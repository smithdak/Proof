//! Integration tests for the serializable Workspace write lane, keyed
//! idempotency, and the savepoint rule (contract §"`PostgreSQL` authoritative
//! unit of work", §"Retry and ambiguous commit").
//!
//! Every test isolates itself in a dedicated schema (`CREATE SCHEMA` +
//! `SET search_path` + `DROP SCHEMA CASCADE`) so parallel agents never collide.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use postgres::{Client, IsolationLevel, NoTls};
use proof_domain::ContentDigest;
use proof_pg::{
    PgConfig, PgError,
    idempotency::{
        IdempotencyOutcome, IdempotencyTupleV1, SavepointGuard, read_stored_in_transaction,
        replay_or_conflict,
    },
    transaction::{
        CausalSequencePolicy, CommitAcknowledgement, RetryPolicy, SqlStateClass, UnitOfWorkHooks,
        UnitOfWorkOutcome, classify_sqlstate, run_unit_of_work, run_unit_of_work_with_retry,
        run_unit_of_work_with_retry_and_sequence_policy_and_acknowledgement,
    },
    wiring::PgRuntime,
};
use proof_remote::RemoteOperationV1;

/// A fixed, valid `UUIDv7` Workspace identity used by every test fixture.
const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
/// A fixed, valid `UUIDv7` requesting Principal.
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
/// A fixed, valid `UUIDv7` operating Principal.
const OPERATOR: &str = "019c0000-0000-7000-8000-000000000003";
/// A fixed, valid `UUIDv7` Delegation identity.
const DELEGATION: &str = "019c0000-0000-7000-8000-000000000004";

/// A valid algorithm-qualified digest with all-zero bytes (for the migration
/// head fixture).
const DIGEST_ZERO: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn connect() -> Client {
    Client::connect(&dsn(), NoTls)
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh to start the local instance")
}

fn set_search_path(client: &mut Client, schema: &str) {
    client
        .batch_execute(&format!("SET search_path TO \"{schema}\""))
        .unwrap();
}

/// A deterministic `blake3:<64 hex digits>` digest derived from one byte so
/// each fixture row can carry a distinct UNIQUE digest.
fn digest(byte: u8) -> String {
    format!("blake3:{}", format!("{byte:02x}").repeat(32))
}

/// Converts a non-negative causal sequence to its `BIGINT` binding form.
fn sequence_bigint(value: u64) -> i64 {
    i64::try_from(value).expect("causal sequence fits in BIGINT")
}

/// Converts a stored non-negative `BIGINT` sequence back to `u64`.
fn sequence_unsigned(value: i64) -> u64 {
    u64::try_from(value).expect("stored sequence is non-negative")
}

fn tx_err(error: &postgres::Error) -> PgError {
    proof_pg::transaction::transaction_error(error)
}

fn candidate() -> IdempotencyTupleV1 {
    IdempotencyTupleV1 {
        workspace_id: WS_ID.parse().expect("valid WorkspaceId"),
        operation: RemoteOperationV1 {
            name: "release.create".to_owned(),
            version: "proof.dev/operation/release.create/v2".to_owned(),
        },
        normalized_input_digest: ContentDigest::blake3([0x22; 32]),
        requesting_principal: REQUESTER.parse().expect("valid PrincipalId"),
        operating_principal: OPERATOR.parse().expect("valid PrincipalId"),
        delegation: Some(DELEGATION.parse().expect("valid DelegationId")),
    }
}

fn persisted_candidate() -> IdempotencyTupleV1 {
    IdempotencyTupleV1 {
        workspace_id: WS_ID.parse().expect("valid WorkspaceId"),
        operation: RemoteOperationV1 {
            name: "release.create".to_owned(),
            version: "v2".to_owned(),
        },
        normalized_input_digest: digest(0x40).parse().unwrap(),
        requesting_principal: REQUESTER.parse().expect("valid PrincipalId"),
        operating_principal: OPERATOR.parse().expect("valid PrincipalId"),
        delegation: Some(DELEGATION.parse().expect("valid DelegationId")),
    }
}

/// One isolated schema with the full table surface plus a seeded
/// `migration_head` (phase `verified`) and `workspace_write_head` singleton.
struct TestDb {
    client: Client,
    schema: String,
}

impl TestDb {
    fn new(name: &str) -> Self {
        let mut client = connect();
        let schema = format!(
            "p0010_{}_{}_{}",
            name,
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .unwrap();
        set_search_path(&mut client, &schema);
        for ddl in proof_pg::schema::ALL_TABLE_DDL {
            client.batch_execute(ddl).unwrap();
        }
        client
            .execute(
                "INSERT INTO migration_head (
                     singleton, version, name, script_digest, phase,
                     actor, tool_version, started_at, verified_at
                 ) VALUES (1, 1, 'bootstrap', $1, 'verified', 'test', 'test', now(), now())",
                &[&DIGEST_ZERO],
            )
            .unwrap();
        client
            .execute(
                "INSERT INTO workspace_write_head (
                     singleton, workspace_id, migration_version,
                     transaction_sequence, authority_sequence, content_sequence, release_sequence,
                     authority_head_digest, authority_head_sequence,
                     content_head_digest, release_head_digest, policy_head_digest,
                     configuration_head_digest
                 ) VALUES (1, $1, 1, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL)",
                &[&WS_ID],
            )
            .unwrap();
        Self { client, schema }
    }

    fn query_head_sequences(&mut self) -> (u64, u64, u64, u64) {
        let row = self
            .client
            .query_one(
                "SELECT transaction_sequence, authority_sequence, content_sequence, release_sequence
                 FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap();
        (
            sequence_unsigned(row.get::<_, i64>(0)),
            sequence_unsigned(row.get::<_, i64>(1)),
            sequence_unsigned(row.get::<_, i64>(2)),
            sequence_unsigned(row.get::<_, i64>(3)),
        )
    }

    fn count(&mut self, table: &str) -> i64 {
        // `table` is always one of the trusted fixture identifiers in this file.
        let query = format!("SELECT COUNT(*) FROM {table}");
        self.client.query_one(&query, &[]).unwrap().get(0)
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// Reads the four advanced causal sequences from inside a transaction.
fn read_head_sequences_tx(
    tx: &mut postgres::Transaction<'_>,
) -> Result<(u64, u64, u64, u64), PgError> {
    let row = tx
        .query_one(
            "SELECT transaction_sequence, authority_sequence, content_sequence, release_sequence
             FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| tx_err(&error))?;
    Ok((
        sequence_unsigned(row.get::<_, i64>(0)),
        sequence_unsigned(row.get::<_, i64>(1)),
        sequence_unsigned(row.get::<_, i64>(2)),
        sequence_unsigned(row.get::<_, i64>(3)),
    ))
}

/// Persists the complete success consequence: decision, consequence, fact,
/// idempotency key, one outbox enqueue, and the new head digests.
fn persist_governed_success(
    tx: &mut postgres::Transaction<'_>,
    application_key: Option<&str>,
) -> Result<(), PgError> {
    let (tx_seq, auth_seq, _content_seq, _release_seq) = read_head_sequences_tx(tx)?;
    let body: Vec<u8> = b"test-body".to_vec();

    tx.execute(
        "INSERT INTO authorization_decisions (
             authority_sequence, workspace_id, decision_digest, operation, body, committed_at
         ) VALUES ($1, $2, $3, $4, $5, now())",
        &[
            &sequence_bigint(auth_seq),
            &WS_ID,
            &digest(0x10),
            &"release.create",
            &body,
        ],
    )
    .map_err(|error| tx_err(&error))?;

    tx.execute(
        "INSERT INTO application_consequences (
             authority_sequence, workspace_id, consequence_digest, operation,
             application_effect_digest, body, committed_at
         ) VALUES ($1, $2, $3, $4, NULL, $5, now())",
        &[
            &sequence_bigint(auth_seq),
            &WS_ID,
            &digest(0x20),
            &"release.create",
            &body,
        ],
    )
    .map_err(|error| tx_err(&error))?;

    tx.execute(
        "INSERT INTO facts (
             fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
         ) VALUES ($1, $2, $3, $4, $5, $6, now())",
        &[
            &"fact-1",
            &WS_ID,
            &"content",
            &sequence_bigint(auth_seq),
            &digest(0x30),
            &body,
        ],
    )
    .map_err(|error| tx_err(&error))?;

    if let Some(application_key) = application_key {
        tx.execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, application_key,
                 key_kind, result_digest, result_body, replay_count, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'required', $9, $10, 0, now())",
            &[
                &WS_ID,
                &"release.create",
                &"v2",
                &digest(0x40),
                &REQUESTER,
                &OPERATOR,
                &DELEGATION,
                &application_key,
                &digest(0x50),
                &body,
            ],
        )
        .map_err(|error| tx_err(&error))?;
    }

    tx.execute(
        "INSERT INTO outbox_events (
             event_id, workspace_id, workspace_transaction_sequence, ordinal,
             event_type, event_version, ordering_key, stream_sequence, effect_digest,
             payload_digest, artifact_kind, artifact_digest,
             destination_configuration_version, destination_configuration_digest,
             correlation_id, causation_id, committed_creation_time
         ) VALUES ($1, $2, $3, 1, 'preview.release', 'v1', 'preview', 1, $4,
                   NULL, NULL, NULL, 1, $5, NULL, NULL, now())",
        &[
            &"event-1",
            &WS_ID,
            &sequence_bigint(tx_seq),
            &digest(0x60),
            &digest(0x70),
        ],
    )
    .map_err(|error| tx_err(&error))?;

    tx.execute(
        "UPDATE workspace_write_head
         SET content_head_digest = $1, authority_head_digest = $2, authority_head_sequence = $3
         WHERE singleton = 1",
        &[&digest(0x80), &digest(0x90), &sequence_bigint(auth_seq)],
    )
    .map_err(|error| tx_err(&error))?;

    Ok(())
}

fn fresh_hooks<'a>(
    consequence: impl FnMut(&mut postgres::Transaction<'_>) -> Result<(), PgError> + 'a,
) -> UnitOfWorkHooks<'a> {
    UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(|_, _| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(consequence),
    }
}

#[test]
fn clean_success_persists_head_facts_consequence_and_one_outbox_enqueue() {
    let mut db = TestDb::new("clean_success");

    let mut hooks = fresh_hooks(|tx| {
        persist_governed_success(tx, Some("019c0000-0000-7000-8000-0000000000f1"))
    });
    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    // The head advanced by exactly one unit of work.
    assert_eq!(db.query_head_sequences(), (1, 1, 1, 1));
    assert_eq!(db.count("authorization_decisions"), 1);
    assert_eq!(db.count("application_consequences"), 1);
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    // Exactly one logical outbox enqueue.
    assert_eq!(db.count("outbox_events"), 1);
}

#[test]
fn replay_discloses_prior_result_without_duplicating_fact_key_or_outbox() {
    let mut db = TestDb::new("replay");

    let prior: Rc<Cell<Option<IdempotencyTupleV1>>> = Rc::new(Cell::new(None));
    let tuple = candidate();

    let prior_for_replay = Rc::clone(&prior);
    let tuple_for_replay = tuple.clone();
    let prior_for_consequence = Rc::clone(&prior);
    let tuple_for_consequence = tuple.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(move |_, _| {
            let stored = prior_for_replay.take();
            Ok(replay_or_conflict(&tuple_for_replay, stored.as_ref()))
        }),
        apply_consequence: Box::new(move |tx| {
            persist_governed_success(tx, Some("019c0000-0000-7000-8000-0000000000f1"))?;
            prior_for_consequence.set(Some(tuple_for_consequence.clone()));
            Ok(())
        }),
    };

    // First attempt is fresh and persists the governed consequence.
    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();
    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("outbox_events"), 1);

    // Second attempt finds the same key + equivalent input and replays.
    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();
    assert_eq!(outcome, UnitOfWorkOutcome::Replayed);
    // No governed fact, key, or outbox event is duplicated.
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("outbox_events"), 1);
    // But the replay consumed a fresh Workspace transaction slot.
    assert_eq!(db.query_head_sequences().0, 2);
}

#[test]
fn changed_input_same_key_commits_conflict_without_governed_effect() {
    let mut db = TestDb::new("conflict");

    let tuple = candidate();
    let mut changed = tuple.clone();
    changed.normalized_input_digest = ContentDigest::blake3([0x77; 32]);

    let consequence_called: Rc<Cell<bool>> = Rc::new(Cell::new(false));
    let flag = Rc::clone(&consequence_called);

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(move |_, _| Ok(replay_or_conflict(&tuple, Some(&changed)))),
        apply_consequence: Box::new(move |_| {
            flag.set(true);
            Ok(())
        }),
    };

    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::ConflictCommitted);
    assert!(
        !consequence_called.get(),
        "the governed consequence must not run for an idempotency conflict"
    );
    // No governed effect.
    assert_eq!(db.count("facts"), 0);
    assert_eq!(db.count("idempotency_keys"), 0);
    assert_eq!(db.count("outbox_events"), 0);
    // The conflict still consumed a transaction + authority slot.
    assert_eq!(db.query_head_sequences(), (1, 1, 1, 1));
}

#[test]
fn application_failure_keeps_decision_and_consequence_without_governed_effect() {
    let mut db = TestDb::new("application_failure");

    let mut hooks = fresh_hooks(|tx| {
        let (tx_seq, auth_seq, _content_seq, _release_seq) = read_head_sequences_tx(tx)?;
        let body: Vec<u8> = b"test-body".to_vec();

        // The decision is persisted outside the governed savepoint and survives.
        tx.execute(
            "INSERT INTO authorization_decisions (
                 authority_sequence, workspace_id, decision_digest, operation, body, committed_at
             ) VALUES ($1, $2, $3, 'release.create', $4, now())",
            &[&sequence_bigint(auth_seq), &WS_ID, &digest(0x11), &body],
        )
        .map_err(|error| tx_err(&error))?;

        // The governed consequence is bounded by a savepoint.
        let mut guard = SavepointGuard::establish(tx)?;
        {
            let savepoint = guard.transaction();
            savepoint
                .execute(
                    "INSERT INTO facts (
                         fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
                     ) VALUES ('fact-1', $1, 'content', $2, $3, $4, now())",
                    &[&WS_ID, &sequence_bigint(auth_seq), &digest(0x33), &body],
                )
                .map_err(|error| tx_err(&error))?;
            savepoint
                .execute(
                    "INSERT INTO idempotency_keys (
                          workspace_id, operation, operation_version, normalized_input_digest,
                          requesting_principal, operating_principal, delegation_id,
                          application_key, key_kind, result_digest, result_body,
                          replay_count, committed_at
                      ) VALUES ($1, 'release.create', 'v2', $2, $3, $4, $5, $6,
                                'required', $7, $8, 0, now())",
                    &[
                        &WS_ID,
                        &digest(0x44),
                        &REQUESTER,
                        &OPERATOR,
                        &DELEGATION,
                        &"019c0000-0000-7000-8000-0000000000f2",
                        &digest(0x55),
                        &body,
                    ],
                )
                .map_err(|error| tx_err(&error))?;
            savepoint
                .execute(
                    "INSERT INTO outbox_events (
                         event_id, workspace_id, workspace_transaction_sequence, ordinal,
                         event_type, event_version, ordering_key, stream_sequence, effect_digest,
                         payload_digest, artifact_kind, artifact_digest,
                         destination_configuration_version, destination_configuration_digest,
                         correlation_id, causation_id, committed_creation_time
                     ) VALUES ('event-1', $1, $2, 1, 'preview.release', 'v1', 'preview', 1, $3,
                               NULL, NULL, NULL, 1, $4, NULL, NULL, now())",
                    &[
                        &WS_ID,
                        &sequence_bigint(tx_seq),
                        &digest(0x66),
                        &digest(0x77),
                    ],
                )
                .map_err(|error| tx_err(&error))?;
        }
        // Ordinary authorized application failure rolls back the governed
        // consequence.
        guard.rollback()?;

        // The failure consequence is persisted outside the savepoint.
        tx.execute(
            "INSERT INTO application_consequences (
                 authority_sequence, workspace_id, consequence_digest, operation,
                 application_effect_digest, body, committed_at
             ) VALUES ($1, $2, $3, 'release.create', NULL, $4, now())",
            &[&sequence_bigint(auth_seq), &WS_ID, &digest(0x22), &body],
        )
        .map_err(|error| tx_err(&error))?;

        Err(PgError::ApplicationFailure(
            "application refused: changeset is not ready".to_owned(),
        ))
    });

    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::ApplicationFailureCommitted);
    assert_eq!(db.count("authorization_decisions"), 1);
    assert_eq!(db.count("application_consequences"), 1);
    assert_eq!(db.count("facts"), 0);
    assert_eq!(db.count("idempotency_keys"), 0);
    assert_eq!(db.count("outbox_events"), 0);
    assert_eq!(db.query_head_sequences().0, 1);
}

#[test]
fn infrastructure_failure_rolls_back_everything() {
    let mut db = TestDb::new("infrastructure_failure");

    let mut hooks = fresh_hooks(|tx| {
        persist_governed_success(tx, Some("019c0000-0000-7000-8000-0000000000f1"))?;
        Err(PgError::Transaction(
            "injected infrastructure failure".to_owned(),
        ))
    });

    let result = run_unit_of_work(&mut db.client, &mut hooks);
    assert!(result.is_err());

    assert_eq!(db.count("authorization_decisions"), 0);
    assert_eq!(db.count("application_consequences"), 0);
    assert_eq!(db.count("facts"), 0);
    assert_eq!(db.count("idempotency_keys"), 0);
    assert_eq!(db.count("outbox_events"), 0);
    // The head write-back from step 3 also rolled back.
    assert_eq!(db.query_head_sequences(), (0, 0, 0, 0));
}

#[test]
fn no_key_rows_execute_fresh_without_consulting_stored_results() {
    let mut db = TestDb::new("no_key");

    let consequence_called: Rc<Cell<bool>> = Rc::new(Cell::new(false));
    let flag = Rc::clone(&consequence_called);
    let tuple = candidate();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        // A no-key row passes `prior == None`; the stored-result lookup is
        // skipped entirely, so the attempt is fresh.
        replay_or_conflict: Box::new(move |_, _| Ok(replay_or_conflict(&tuple, None))),
        apply_consequence: Box::new(move |tx| {
            flag.set(true);
            persist_governed_success(tx, None)
        }),
    };

    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    assert!(consequence_called.get());
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 0);

    // The decision function returns Fresh when there is no stored tuple.
    assert_eq!(
        replay_or_conflict(&candidate(), None),
        IdempotencyOutcome::Fresh
    );
}

#[test]
fn serializable_race_observes_40001_on_commit() {
    let db = TestDb::new("race");

    let mut c1 = connect();
    set_search_path(&mut c1, &db.schema);
    let mut c2 = connect();
    set_search_path(&mut c2, &db.schema);

    let mut t1 = c1
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .unwrap();
    let mut t2 = c2
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .unwrap();

    // Both serializable transactions read the same head snapshot.
    t1.query(
        "SELECT transaction_sequence FROM workspace_write_head WHERE singleton = 1",
        &[],
    )
    .unwrap();
    t2.query(
        "SELECT transaction_sequence FROM workspace_write_head WHERE singleton = 1",
        &[],
    )
    .unwrap();

    // Both advance and commit; exactly one must observe 40001 while the other
    // commits cleanly (SSI may raise it at the UPDATE or at COMMIT, and may
    // pick either victim).
    let attempt = |mut t: postgres::Transaction<'_>| -> Result<(), postgres::Error> {
        t.execute(
            "UPDATE workspace_write_head SET transaction_sequence = transaction_sequence + 1 WHERE singleton = 1",
            &[],
        )?;
        t.commit()
    };
    let r1 = attempt(t1);
    let r2 = attempt(t2);

    let sqlstate = |result: &Result<(), postgres::Error>| {
        result
            .as_ref()
            .err()
            .and_then(|error| error.code().map(postgres::error::SqlState::code))
            .map(str::to_owned)
    };
    let failures = [sqlstate(&r1), sqlstate(&r2)]
        .into_iter()
        .filter(|code| code.as_deref() == Some("40001"))
        .count();
    assert_eq!(
        failures, 1,
        "exactly one serializable transaction must observe 40001"
    );
}

#[test]
fn retry_recovers_from_serialization_failure_with_consistent_sequences() {
    let mut db = TestDb::new("retry");
    db.client
        .batch_execute(
            "CREATE TABLE race_target (id BIGINT PRIMARY KEY, class BIGINT NOT NULL);
             CREATE INDEX race_target_class ON race_target(class)",
        )
        .unwrap();
    db.client
        .execute("INSERT INTO race_target VALUES (1, 1)", &[])
        .unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let (signal_tx, signal_rx) = mpsc::channel();
    let (ack_tx, ack_rx) = mpsc::channel();

    let writer_schema = db.schema.clone();
    let writer = thread::spawn(move || {
        signal_rx.recv().unwrap();
        let mut c = connect();
        set_search_path(&mut c, &writer_schema);
        let mut wt = c
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(false)
            .start()
            .unwrap();
        // Predicate read + insert, mirroring the unit-of-work attempt, so the
        // two transactions form a write-skew cycle that raises 40001 at the
        // unit-of-work COMMIT.
        wt.query("SELECT COUNT(*) FROM race_target WHERE class = 1", &[])
            .unwrap();
        wt.execute("INSERT INTO race_target VALUES (2, 1)", &[])
            .unwrap();
        wt.commit().unwrap();
        ack_tx.send(()).unwrap();
    });

    let attempts_for_hook = Arc::clone(&attempts);
    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(|_, _| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let attempt = attempts_for_hook.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                // First attempt: predicate read, then insert after the writer
                // has committed its own predicate read + insert. The two
                // transactions form a write-skew cycle that raises 40001 at
                // COMMIT.
                let count: i64 = tx
                    .query_one("SELECT COUNT(*) FROM race_target WHERE class = 1", &[])
                    .map_err(|error| tx_err(&error))?
                    .get(0);
                assert_eq!(count, 1);
                signal_tx.send(()).unwrap();
                ack_rx.recv().unwrap();
                tx.execute("INSERT INTO race_target VALUES (3, 1)", &[])
                    .map_err(|error| tx_err(&error))?;
                Ok(())
            } else {
                // Retry: perform the real governed consequence.
                persist_governed_success(tx, Some("019c0000-0000-7000-8000-0000000000f1"))
            }
        }),
    };

    let policy = RetryPolicy::new(3, Duration::from_secs(30), Duration::ZERO);
    let outcome = run_unit_of_work_with_retry(&mut db.client, &mut hooks, policy).unwrap();
    writer.join().unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    // Exactly one failed attempt plus one successful retry.
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    // Only the retried (committed) consequence survives.
    assert_eq!(db.count("facts"), 1);
    // The failed attempt's head write-back rolled back, so the sequences are
    // consistent (no gap).
    assert_eq!(db.query_head_sequences(), (1, 1, 1, 1));
}

#[test]
fn statement_retry_reuses_preallocated_semantics_without_duplicate_effects() {
    let mut db = TestDb::new("statement_retry");
    let attempts = Rc::new(Cell::new(0_u32));
    let observed = Rc::new(RefCell::new(Vec::new()));
    let prepared_id = "019d0000-0000-7000-8000-0000000000f9".to_owned();
    let prepared_time = "2026-08-27T12:00:00Z".to_owned();

    let attempts_for_hook = Rc::clone(&attempts);
    let observed_for_hook = Rc::clone(&observed);
    let prepared_id_for_hook = prepared_id.clone();
    let prepared_time_for_hook = prepared_time.clone();
    let mut hooks = fresh_hooks(move |tx| {
        let attempt = attempts_for_hook.get();
        attempts_for_hook.set(attempt + 1);
        observed_for_hook
            .borrow_mut()
            .push((prepared_id_for_hook.clone(), prepared_time_for_hook.clone()));
        persist_governed_success(tx, Some("019c0000-0000-7000-8000-0000000000f1"))?;
        if attempt == 0 {
            tx.batch_execute(
                "DO $$ BEGIN
                     RAISE EXCEPTION 'injected serialization failure' USING ERRCODE = '40001';
                 END $$",
            )
            .map_err(|error| tx_err(&error))?;
        }
        Ok(())
    });

    let outcome = run_unit_of_work_with_retry(
        &mut db.client,
        &mut hooks,
        RetryPolicy::new(3, Duration::from_secs(30), Duration::ZERO),
    )
    .unwrap();

    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    assert_eq!(attempts.get(), 2);
    assert_eq!(
        observed.borrow().as_slice(),
        [
            (prepared_id.clone(), prepared_time.clone()),
            (prepared_id, prepared_time),
        ]
    );
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("outbox_events"), 1);
    assert_eq!(db.query_head_sequences(), (1, 1, 1, 1));
}

#[test]
fn applied_commit_with_lost_acknowledgement_reconciles_by_key() {
    const APPLICATION_KEY: &str = "019c0000-0000-7000-8000-0000000000f1";

    let mut db = TestDb::new("ambiguous_reconcile");
    let attempts = Rc::new(Cell::new(0_u32));
    let attempts_for_hook = Rc::clone(&attempts);
    let mut hooks = fresh_hooks(move |tx| {
        attempts_for_hook.set(attempts_for_hook.get() + 1);
        persist_governed_success(tx, Some(APPLICATION_KEY))
    });
    let mut acknowledgement = |_| CommitAcknowledgement::Lost;
    let error = run_unit_of_work_with_retry_and_sequence_policy_and_acknowledgement(
        &mut db.client,
        &mut hooks,
        RetryPolicy::new(3, Duration::from_secs(30), Duration::ZERO),
        CausalSequencePolicy::All,
        &mut acknowledgement,
    )
    .unwrap_err();
    assert!(matches!(error, PgError::AmbiguousCommit(_)));
    assert_eq!(attempts.get(), 1, "an applied commit must not be retried");
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("outbox_events"), 1);

    let mut reconciliation = connect();
    set_search_path(&mut reconciliation, &db.schema);
    let candidate = persisted_candidate();
    let consequence_called = Rc::new(Cell::new(false));
    let consequence_called_for_hook = Rc::clone(&consequence_called);
    let mut reconciliation_hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(move |tx, _| {
            let prior = read_stored_in_transaction(tx, candidate.workspace_id, APPLICATION_KEY)?;
            Ok(replay_or_conflict(
                &candidate,
                prior.as_ref().map(|stored| &stored.tuple),
            ))
        }),
        apply_consequence: Box::new(move |_| {
            consequence_called_for_hook.set(true);
            Ok(())
        }),
    };
    let outcome = run_unit_of_work(&mut reconciliation, &mut reconciliation_hooks).unwrap();
    assert_eq!(outcome, UnitOfWorkOutcome::Replayed);
    assert!(!consequence_called.get());
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("outbox_events"), 1);
}

#[test]
fn pg_runtime_reconnects_and_restores_the_authority_search_path() {
    let db = TestDb::new("runtime_reconnect");
    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WS_ID.parse().unwrap(),
        Duration::from_secs(30),
    ))
    .unwrap();
    runtime.set_search_path(&db.schema).unwrap();
    let backend_pid: i32 = runtime
        .client_mut()
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);

    let mut terminator = connect();
    let terminated: bool = terminator
        .query_one("SELECT pg_terminate_backend($1)", &[&backend_pid])
        .unwrap()
        .get(0);
    assert!(terminated);
    assert!(runtime.client_mut().query_one("SELECT 1", &[]).is_err());
    assert!(runtime.client().is_closed());

    runtime.ensure_connected().unwrap();
    let current_schema: String = runtime
        .client_mut()
        .query_one("SELECT current_schema()", &[])
        .unwrap()
        .get(0);
    assert_eq!(current_schema, db.schema);
    let head_count: i64 = runtime
        .client_mut()
        .query_one("SELECT COUNT(*) FROM workspace_write_head", &[])
        .unwrap()
        .get(0);
    assert_eq!(head_count, 1);
}

#[test]
fn retry_deadline_bounds_a_blocked_workspace_head_lock() {
    let mut db = TestDb::new("lock_deadline");
    let mut locker = connect();
    set_search_path(&mut locker, &db.schema);
    let mut lock_transaction = locker.transaction().unwrap();
    lock_transaction
        .query_one(
            "SELECT singleton FROM workspace_write_head WHERE singleton = 1 FOR UPDATE",
            &[],
        )
        .unwrap();

    let mut hooks = fresh_hooks(|_| Ok(()));
    let started = Instant::now();
    let error = run_unit_of_work_with_retry(
        &mut db.client,
        &mut hooks,
        RetryPolicy::new(3, Duration::from_millis(100), Duration::ZERO),
    )
    .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "blocked lock exceeded the bounded retry deadline"
    );
    assert!(
        matches!(&error, PgError::Transaction(message)
            if message.contains("sqlstate=55P03") || message.contains("sqlstate=57014")),
        "expected PostgreSQL lock timeout, got {error}"
    );
    lock_transaction.rollback().unwrap();
    assert_eq!(db.query_head_sequences(), (0, 0, 0, 0));
}

#[test]
fn classify_sqlstate_maps_the_contract_classes() {
    assert_eq!(
        classify_sqlstate("40001"),
        SqlStateClass::SerializationFailure
    );
    assert_eq!(classify_sqlstate("40P01"), SqlStateClass::DeadlockDetected);
    assert_eq!(classify_sqlstate("23505"), SqlStateClass::UniqueViolation);
    assert_eq!(classify_sqlstate("00000"), SqlStateClass::Other);
    assert_eq!(classify_sqlstate(""), SqlStateClass::Other);
    assert_eq!(classify_sqlstate("42P01"), SqlStateClass::Other);
}

#[test]
fn savepoint_guard_rollback_restores_prior_rows() {
    let mut db = TestDb::new("savepoint");
    db.client
        .batch_execute("CREATE TABLE scratch (id BIGINT PRIMARY KEY, note TEXT NOT NULL)")
        .unwrap();

    let mut tx = db.client.transaction().unwrap();
    tx.execute("INSERT INTO scratch VALUES (1, 'prior')", &[])
        .unwrap();

    let mut guard = SavepointGuard::establish(&mut tx).unwrap();
    guard
        .transaction()
        .execute("INSERT INTO scratch VALUES (2, 'inside')", &[])
        .unwrap();
    guard.rollback().unwrap();

    tx.execute("INSERT INTO scratch VALUES (3, 'after')", &[])
        .unwrap();
    tx.commit().unwrap();

    let ids: Vec<i64> = db
        .client
        .query("SELECT id FROM scratch ORDER BY id", &[])
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        ids,
        vec![1, 3],
        "the savepoint rollback removed only rows written inside it"
    );
}
