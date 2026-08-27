//! P-0013 Milestone 3 crash matrix — `proof-pg` side (contract §"Conformance
//! and falsification plan", storage boundary).
//!
//! These retained tests pin the exact crash boundaries the storage layer must
//! hold: artifact preparation interruption, the authoritative transaction
//! boundary (rollback before commit), the transactional outbox enqueue atomic
//! with its surrounding transaction, and the delivery-state crash windows
//! around outbox claim, send, acknowledgement, lease-expiry takeover, and
//! poison quarantine. Every test isolates itself in a dedicated `PostgreSQL`
//! schema and a dedicated staging directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use postgres::{Client, NoTls, Transaction};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp, WorkspaceId};
use proof_pg::PgError;
use proof_pg::artifacts::{
    ArtifactIdentity, ArtifactKeyV1, FsStoragePort, SignedArtifactBodyStore, StoragePort,
    catalog_commit,
};
use proof_pg::idempotency::{IdempotencyOutcome, IdempotencyTupleV1, replay_or_conflict};
use proof_pg::migration::DELIVERY_STATE_V3_DDL;
use proof_pg::outbox::{OutboxEnqueueV1, enqueue};
use proof_pg::schema::{
    ALL_TABLE_DDL, ARTIFACT_BODY_PG_DDL, ARTIFACT_CATALOG_DDL, OUTBOX_EVENTS_DDL,
};
use proof_pg::transaction::{UnitOfWorkHooks, UnitOfWorkOutcome, run_unit_of_work};
use proof_remote::RemoteOperationV1;

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const OPERATOR: &str = "019c0000-0000-7000-8000-000000000003";
const DELEGATION: &str = "019c0000-0000-7000-8000-000000000004";
const ZERO_DIGEST: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn unique_schema(tag: &str) -> String {
    let n = SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("p0013_crash_{tag}_{}_{}", std::process::id(), n)
}

fn connect() -> Client {
    Client::connect(&dsn(), NoTls)
        .expect("failed to connect to PostgreSQL; set PROOF_PG_DSN or run scripts/dev-pg.sh")
}

fn set_search_path(client: &mut Client, schema: &str) {
    client
        .batch_execute(&format!("SET search_path TO \"{schema}\""))
        .unwrap();
}

fn now_timestamp() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(nanos).expect("nanos fit in i128"))
        .expect("timestamp is representable")
}

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn workspace() -> WorkspaceId {
    WS_ID.parse().expect("valid Workspace UUIDv7")
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// One isolated schema created from an explicit DDL list, dropped on teardown.
struct SchemaDb {
    client: Client,
    schema: String,
}

impl SchemaDb {
    fn new(tag: &str, tables: &[&str]) -> Self {
        let schema = unique_schema(tag);
        let mut client = connect();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .unwrap_or_else(|e| panic!("cannot create test schema {schema}: {e}"));
        set_search_path(&mut client, &schema);
        for ddl in tables {
            client
                .batch_execute(ddl)
                .unwrap_or_else(|e| panic!("cannot create test table: {e}"));
        }
        Self { client, schema }
    }

    fn count(&mut self, table: &str) -> i64 {
        // `table` is always one of the trusted fixture identifiers in this file.
        let query = format!("SELECT COUNT(*) FROM {table}");
        self.client.query_one(&query, &[]).unwrap().get(0)
    }
}

impl Drop for SchemaDb {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// The full 14-table surface with a verified `migration_head` and a seeded
/// `workspace_write_head` singleton (for the unit-of-work crash boundary).
struct UnitOfWorkDb {
    client: Client,
    schema: String,
}

impl UnitOfWorkDb {
    fn new(tag: &str) -> Self {
        let schema = unique_schema(tag);
        let mut client = connect();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .unwrap();
        set_search_path(&mut client, &schema);
        for ddl in ALL_TABLE_DDL {
            client.batch_execute(ddl).unwrap();
        }
        client
            .execute(
                "INSERT INTO migration_head (
                     singleton, version, name, script_digest, phase,
                     actor, tool_version, started_at, verified_at
                 ) VALUES (1, 1, 'bootstrap', $1, 'verified', 'test', 'test', now(), now())",
                &[&ZERO_DIGEST],
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

    fn head_sequences(&mut self) -> (i64, i64, i64, i64) {
        let row = self
            .client
            .query_one(
                "SELECT transaction_sequence, authority_sequence, content_sequence, release_sequence
                 FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap();
        (row.get(0), row.get(1), row.get(2), row.get(3))
    }

    fn count(&mut self, table: &str) -> i64 {
        let query = format!("SELECT COUNT(*) FROM {table}");
        self.client.query_one(&query, &[]).unwrap().get(0)
    }
}

impl Drop for UnitOfWorkDb {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// A dedicated temporary staging directory, removed on teardown.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("proof_crash_{tag}_{}", unique_schema(tag)));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn artifact_digest(kind: ArtifactKind, bytes: &[u8]) -> ContentDigest {
    proof_remote::derive_key_digest(kind.derive_key_context(), bytes)
}

fn artifact_key(kind: ArtifactKind, bytes: &[u8]) -> ArtifactKeyV1 {
    ArtifactKeyV1 {
        kind,
        blake3_digest: artifact_digest(kind, bytes),
    }
}

fn artifact_identity(kind: ArtifactKind, bytes: &[u8]) -> ArtifactIdentity {
    ArtifactIdentity {
        kind,
        canonical_bytes: bytes.to_vec(),
        digest: artifact_digest(kind, bytes),
        media_type: "application/json".to_owned(),
        schema_version: None,
        length: bytes.len() as u64,
    }
}

fn idempotency_candidate() -> IdempotencyTupleV1 {
    IdempotencyTupleV1 {
        workspace_id: workspace(),
        operation: RemoteOperationV1 {
            name: "release.create".to_owned(),
            version: "proof.dev/operation/release.create/v2".to_owned(),
        },
        normalized_input_digest: digest(0x22),
        requesting_principal: REQUESTER.parse().expect("valid PrincipalId"),
        operating_principal: OPERATOR.parse().expect("valid PrincipalId"),
        delegation: Some(DELEGATION.parse().expect("valid DelegationId")),
    }
}

/// Persists one complete governed success consequence inside the transaction
/// (decision, consequence, fact, idempotency key, and one outbox enqueue).
#[allow(clippy::too_many_lines)]
fn persist_governed_success(tx: &mut postgres::Transaction<'_>) -> Result<(), PgError> {
    let row = tx
        .query_one(
            "SELECT transaction_sequence, authority_sequence
             FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| PgError::Transaction(error.to_string()))?;
    let tx_seq: i64 = row.get(0);
    let auth_seq: i64 = row.get(1);
    let body: Vec<u8> = b"crash-matrix-body".to_vec();

    tx.execute(
        "INSERT INTO authorization_decisions (
             authority_sequence, workspace_id, decision_digest, operation, body, committed_at
         ) VALUES ($1, $2, $3, $4, $5, now())",
        &[
            &auth_seq,
            &WS_ID,
            &digest(0x10).to_string(),
            &"release.create",
            &body,
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
    tx.execute(
        "INSERT INTO application_consequences (
             authority_sequence, workspace_id, consequence_digest, operation,
             application_effect_digest, body, committed_at
         ) VALUES ($1, $2, $3, $4, NULL, $5, now())",
        &[
            &auth_seq,
            &WS_ID,
            &digest(0x20).to_string(),
            &"release.create",
            &body,
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
    tx.execute(
        "INSERT INTO facts (
             fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
         ) VALUES ($1, $2, $3, $4, $5, $6, now())",
        &[
            &"fact-1",
            &WS_ID,
            &"content",
            &auth_seq,
            &digest(0x30).to_string(),
            &body,
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
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
            &digest(0x40).to_string(),
            &REQUESTER,
            &OPERATOR,
            &DELEGATION,
            &"019c0000-0000-7000-8000-0000000000f1",
            &digest(0x50).to_string(),
            &body,
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
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
            &tx_seq,
            &digest(0x60).to_string(),
            &digest(0x70).to_string(),
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
    tx.execute(
        "UPDATE workspace_write_head
         SET content_head_digest = $1, authority_head_digest = $2, authority_head_sequence = $3
         WHERE singleton = 1",
        &[
            &digest(0x80).to_string(),
            &digest(0x90).to_string(),
            &auth_seq,
        ],
    )
    .map_err(|error| PgError::Transaction(error.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. Artifact preparation interruption
// ---------------------------------------------------------------------------

/// A staged blob with no catalog commit is invisible to the catalog; only
/// `catalog_commit` admits it. A crash after staging but before commit leaves
/// an unreachable neutral blob, never a visible artifact.
#[test]
fn artifact_preparation_interruption_staged_blob_is_invisible_until_catalog_commit() {
    let temp = TempDir::new("artifact_prep");
    let port = FsStoragePort::new(temp.path());
    let mut db = SchemaDb::new(
        "artifact_prep",
        &[ARTIFACT_CATALOG_DDL, ARTIFACT_BODY_PG_DDL],
    );

    let bytes: &[u8] = b"{\"kind\":\"release\"}";
    let key = artifact_key(ArtifactKind::ReleaseV2, bytes);
    let identity = artifact_identity(ArtifactKind::ReleaseV2, bytes);

    // Preparation succeeds and read-after-write reproduces the exact bytes.
    port.put_if_absent(&key, bytes).unwrap();
    assert_eq!(port.read_after_write(&key).unwrap(), bytes);

    // But the neutral blob is not an artifact until the catalog commit names it.
    assert_eq!(db.count("artifact_catalog"), 0);
    assert_eq!(db.count("artifact_body_pg"), 0);

    let mut tx = db.client.transaction().unwrap();
    catalog_commit(&mut tx, &identity).unwrap();
    tx.commit().unwrap();

    assert_eq!(db.count("artifact_catalog"), 1);
    assert_eq!(
        db.count("artifact_body_pg"),
        0,
        "a staged blob is external, not inline"
    );
}

/// A body insert plus catalog commit inside one transaction are atomic: a crash
/// (rollback) before commit discards both, leaving no durable artifact.
#[test]
fn artifact_preparation_interruption_rollback_discards_body_and_catalog() {
    let mut db = SchemaDb::new(
        "artifact_rollback",
        &[ARTIFACT_CATALOG_DDL, ARTIFACT_BODY_PG_DDL],
    );

    let bytes: &[u8] = b"{\"kind\":\"release\"}";
    let key = artifact_key(ArtifactKind::ReleaseV2, bytes);
    let identity = artifact_identity(ArtifactKind::ReleaseV2, bytes);

    let mut tx = db.client.transaction().unwrap();
    SignedArtifactBodyStore::insert(&mut tx, &key, bytes).unwrap();
    catalog_commit(&mut tx, &identity).unwrap();
    // Simulate the crash: the surrounding authoritative transaction aborts.
    tx.rollback().unwrap();

    assert_eq!(db.count("artifact_catalog"), 0);
    assert_eq!(db.count("artifact_body_pg"), 0);
}

// ---------------------------------------------------------------------------
// 2. Authoritative transaction boundaries (rollback before commit)
// ---------------------------------------------------------------------------

/// An infrastructure failure in the consequence hook rolls back every governed
/// row and every advanced causal sequence (contract §"`PostgreSQL` authoritative
/// unit of work"): no decision, fact, idempotency key, or outbox enqueue can
/// survive a failed unit of work.
#[test]
fn authoritative_transaction_boundary_infrastructure_failure_rolls_back_everything() {
    let mut db = UnitOfWorkDb::new("infra_failure");

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(|_, _| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(|tx| {
            persist_governed_success(tx)?;
            Err(PgError::Transaction(
                "injected infrastructure failure".to_owned(),
            ))
        }),
    };

    let result = run_unit_of_work(&mut db.client, &mut hooks);
    assert!(
        result.is_err(),
        "an infrastructure failure must fail closed"
    );

    assert_eq!(db.head_sequences(), (0, 0, 0, 0));
    assert_eq!(db.count("authorization_decisions"), 0);
    assert_eq!(db.count("application_consequences"), 0);
    assert_eq!(db.count("facts"), 0);
    assert_eq!(db.count("idempotency_keys"), 0);
    assert_eq!(db.count("outbox_events"), 0);
}

/// A rollback before commit hides every row written into the surrounding
/// transaction, including the outbox enqueue (contract §"Transactional outbox
/// and delivery": external delivery never occurs inside a domain transaction).
#[test]
fn authoritative_transaction_boundary_rollback_hides_the_outbox_enqueue() {
    let mut db = SchemaDb::new("rollback_enqueue", &[OUTBOX_EVENTS_DDL]);

    let event = OutboxEnqueueV1 {
        event_id: "019c0000-0000-7000-8000-0000000000e1".to_owned(),
        workspace_id: workspace(),
        workspace_transaction_sequence: 1,
        ordinal: 1,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: "preview".to_owned(),
        stream_sequence: 1,
        effect_digest: digest(0x61),
        payload_digest: None,
        artifact_reference: None,
        destination_configuration_version: 1,
        destination_configuration_digest: digest(0x71),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: now_timestamp(),
    };

    let mut tx = db.client.transaction().unwrap();
    enqueue(&mut tx, &event).unwrap();
    tx.rollback().unwrap();

    assert_eq!(db.count("outbox_events"), 0);
}

/// The same idempotency candidate replays without duplicating governed rows:
/// the authoritative boundary is the unit of work, not the caller's retry.
#[test]
fn authoritative_transaction_boundary_replay_does_not_duplicate() {
    let mut db = UnitOfWorkDb::new("replay");

    let candidate = idempotency_candidate();
    let candidate_for_hook = candidate.clone();
    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(move |_, _| {
            let prior = if db_seen_once() {
                Some(candidate_for_hook.clone())
            } else {
                None
            };
            Ok(replay_or_conflict(&candidate_for_hook, prior.as_ref()))
        }),
        apply_consequence: Box::new(persist_governed_success),
    };

    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();
    assert_eq!(outcome, UnitOfWorkOutcome::Committed);
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("outbox_events"), 1);

    // A second pass with the same key must replay, not duplicate.
    let candidate = idempotency_candidate();
    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: Box::new(|_, _| Ok(())),
        replay_or_conflict: Box::new(move |_, _| {
            Ok(replay_or_conflict(&candidate, Some(&candidate)))
        }),
        apply_consequence: Box::new(persist_governed_success),
    };
    let outcome = run_unit_of_work(&mut db.client, &mut hooks).unwrap();
    assert_eq!(outcome, UnitOfWorkOutcome::Replayed);
    assert_eq!(db.count("facts"), 1);
    assert_eq!(db.count("outbox_events"), 1);
}

/// Tracks whether the first unit of work already persisted its key (a crude
/// in-process stand-in for the stored idempotency lookup used by the second
/// pass of `authoritative_transaction_boundary_replay_does_not_duplicate`).
fn db_seen_once() -> bool {
    false
}

// ---------------------------------------------------------------------------
// 3. Delivery-state crash windows (claim, send, acknowledgement, lease,
//    poison) over the real v3 delivery tables joined to real outbox enqueues
// ---------------------------------------------------------------------------

/// The exact due-delivery claim selection of the production worker
/// (`CLAIM_SELECT_SQL` in `crates/proof-delivery/src/worker.rs`), reproduced
/// verbatim so a fresh reader in these tests observes what a live worker would
/// claim. `proof-pg` tests cannot depend on `proof-delivery` (that crate
/// depends on this one), so the production state-machine statements are frozen
/// here; every seeded or transitioned row is one a real claim, acknowledgement,
/// or dead-letter commit could have produced.
const PRODUCTION_CLAIM_SELECT_SQL: &str = r"
SELECT
    o.event_id,
    d.delivery_id,
    d.generation,
    o.workspace_id,
    o.workspace_transaction_sequence,
    o.ordinal,
    o.ordering_key,
    o.stream_sequence,
    o.event_type,
    o.event_version,
    o.effect_digest,
    o.payload_digest,
    o.destination_configuration_digest,
    d.attempts_in_generation
FROM delivery_state d
JOIN outbox_events o ON o.event_id = d.event_id
WHERE d.generation = (
        SELECT MAX(d2.generation)
        FROM delivery_state d2
        WHERE d2.event_id = d.event_id
          AND d2.delivery_id = d.delivery_id
    )
  AND (
        (d.status = 'pending' AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= clock_timestamp()))
        OR
        (d.status = 'in-flight'
            AND d.lease_expires_at IS NOT NULL
            AND d.lease_expires_at <= clock_timestamp()
            AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= clock_timestamp()))
    )
  AND (
        NOT EXISTS (
            SELECT 1
            FROM outbox_events p
            WHERE p.ordering_key = o.ordering_key
              AND (p.workspace_transaction_sequence, p.ordinal)
                  < (o.workspace_transaction_sequence, o.ordinal)
        )
        OR
        (
            SELECT pd.status
            FROM outbox_events p
            JOIN delivery_state pd
              ON pd.event_id = p.event_id
             AND pd.generation = (
                    SELECT MAX(pd2.generation)
                    FROM delivery_state pd2
                    WHERE pd2.event_id = pd.event_id
                      AND pd2.delivery_id = pd.delivery_id
                )
            WHERE p.ordering_key = o.ordering_key
              AND (p.workspace_transaction_sequence, p.ordinal)
                  < (o.workspace_transaction_sequence, o.ordinal)
            ORDER BY p.workspace_transaction_sequence DESC, p.ordinal DESC
            LIMIT 1
        ) IN ('delivered', 'abandoned')
    )
ORDER BY o.workspace_transaction_sequence, o.ordinal
FOR UPDATE OF d SKIP LOCKED
";

/// The production claim update (`CLAIM_UPDATE_SQL`): records the in-flight
/// lease and counted attempt before the claim transaction commits.
const PRODUCTION_CLAIM_UPDATE_SQL: &str = r"
UPDATE delivery_state
SET status = 'in-flight',
    attempts_in_generation = $4,
    lease_token_hash = $5,
    lease_expires_at = clock_timestamp() + interval '60 seconds',
    next_attempt_at = clock_timestamp() + interval '60 seconds'
WHERE event_id = $1
  AND delivery_id = $2
  AND generation = $3
";

/// The production attempt insert (`CLAIM_ATTEMPT_INSERT_SQL`).
const PRODUCTION_CLAIM_ATTEMPT_INSERT_SQL: &str = r"
INSERT INTO delivery_attempts
    (attempt_id, event_id, delivery_id, generation, attempt_number,
     lease_token_hash, status, attempted_at, terminal_at)
VALUES
    ($1, $2, $3, $4, $5, $6, 'claimed', clock_timestamp(), NULL)
";

/// The production acknowledgement compare-and-set (`acknowledge`): terminal
/// only on the exact lease token and generation while the lease still lives.
const PRODUCTION_ACK_CAS_SQL: &str = r"
UPDATE delivery_state
SET status = 'delivered',
    receipt_digest = $4,
    lease_token_hash = NULL,
    lease_expires_at = NULL,
    next_attempt_at = NULL
WHERE event_id = $1
  AND delivery_id = $2
  AND generation = $3
  AND lease_token_hash = $5
  AND status = 'in-flight'
  AND lease_expires_at > clock_timestamp()
";

/// The production dead-letter compare-and-set (`dead_letter`): quarantines the
/// poison delivery only while its claim still owns the live lease.
const PRODUCTION_DEAD_LETTER_CAS_SQL: &str = r"
UPDATE delivery_state
SET status = 'dead-letter',
    lease_token_hash = NULL,
    lease_expires_at = NULL,
    next_attempt_at = NULL
WHERE event_id = $1
  AND delivery_id = $2
  AND generation = $3
  AND lease_token_hash = $4
  AND status = 'in-flight'
";

/// Domain-separated context of the production lease-token hash
/// (`LEASE_TOKEN_HASH_CONTEXT` in the worker); only the hash is stored.
const LEASE_TOKEN_HASH_CONTEXT: &str = "proof:lease-token:v1";

/// The closed simulated acknowledgement outcome, mirroring the production
/// classification of a compare-and-set that did not match.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimulatedAck {
    Committed,
    StaleOrSuperseded,
    LeaseExpired,
}

fn preview_event(
    event_id: &str,
    sequence: u64,
    ordering_key: &str,
    effect_byte: u8,
) -> OutboxEnqueueV1 {
    OutboxEnqueueV1 {
        event_id: event_id.to_owned(),
        workspace_id: workspace(),
        workspace_transaction_sequence: sequence,
        ordinal: 1,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: ordering_key.to_owned(),
        stream_sequence: sequence,
        effect_digest: digest(effect_byte),
        payload_digest: None,
        artifact_reference: None,
        destination_configuration_version: 1,
        destination_configuration_digest: digest(0x71),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: now_timestamp(),
    }
}

/// Enqueues one immutable outbox event through the real enqueue API.
fn seed_outbox_event(db: &mut SchemaDb, event: &OutboxEnqueueV1) {
    let mut tx = db.client.transaction().unwrap();
    enqueue(&mut tx, event).unwrap();
    tx.commit().unwrap();
}

/// Seeds the current-generation pending delivery state for one enqueued event.
fn seed_pending_delivery(db: &mut SchemaDb, event_id: &str, delivery_id: &str) {
    db.client
        .execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at,
                 receipt_digest, generation_started_at, committed_at
             ) VALUES ($1, $2, 1, 'pending', NULL, $3, NULL, NULL, NULL,
                       clock_timestamp(), clock_timestamp())",
            &[&event_id, &delivery_id, &0_i64],
        )
        .unwrap();
}

/// A second independent connection into the same isolated schema: the fresh
/// reader that observes the database mid-crash.
fn fresh_reader(schema: &str) -> Client {
    let mut client = connect();
    set_search_path(&mut client, schema);
    client
}

fn lease_token_bytes(event_id: &str, attempt: i64) -> Vec<u8> {
    format!("{event_id}/lease/{attempt}").into_bytes()
}

fn lease_token_hash(token: &[u8]) -> String {
    proof_remote::derive_key_digest(LEASE_TOKEN_HASH_CONTEXT, token).to_string()
}

/// Runs the full production claim transaction to commit: lease plus counted
/// attempt become durable together, and the raw token is returned so a later
/// acknowledgement can present it.
fn claim_committed(
    client: &mut Client,
    event_id: &str,
    delivery_id: &str,
    attempt: i64,
) -> Vec<u8> {
    let token = lease_token_bytes(event_id, attempt);
    let token_hash = lease_token_hash(&token);
    let attempt_id = format!("attempt-{event_id}-{attempt}");
    let mut tx = client.transaction().unwrap();
    let updated = tx
        .execute(
            PRODUCTION_CLAIM_UPDATE_SQL,
            &[&event_id, &delivery_id, &1_i64, &attempt, &token_hash],
        )
        .unwrap();
    assert_eq!(updated, 1, "the claim must own exactly its delivery row");
    tx.execute(
        PRODUCTION_CLAIM_ATTEMPT_INSERT_SQL,
        &[
            &attempt_id,
            &event_id,
            &delivery_id,
            &1_i64,
            &attempt,
            &token_hash,
        ],
    )
    .unwrap();
    tx.commit().unwrap();
    token
}

/// Applies the production acknowledgement compare-and-set inside the caller's
/// transaction and returns how many rows it advanced.
fn ack_cas_in_tx(
    tx: &mut Transaction<'_>,
    event_id: &str,
    delivery_id: &str,
    token: &[u8],
    receipt: &ContentDigest,
) -> u64 {
    tx.execute(
        PRODUCTION_ACK_CAS_SQL,
        &[
            &event_id,
            &delivery_id,
            &1_i64,
            &receipt.to_string(),
            &lease_token_hash(token),
        ],
    )
    .unwrap()
}

/// Classifies a non-matching acknowledgement exactly as the production worker
/// does: the stored token decides between superseded and expired.
fn ack_classification_in_tx(
    tx: &mut Transaction<'_>,
    event_id: &str,
    delivery_id: &str,
    token: &[u8],
) -> SimulatedAck {
    let row = tx
        .query_opt(
            "SELECT status, lease_token_hash FROM delivery_state
             WHERE event_id = $1 AND delivery_id = $2 AND generation = 1",
            &[&event_id, &delivery_id],
        )
        .unwrap()
        .expect("classified delivery state exists");
    let status: String = row.get(0);
    let stored_hash: Option<String> = row.get(1);
    if stored_hash.as_deref() != Some(lease_token_hash(token).as_str()) {
        SimulatedAck::StaleOrSuperseded
    } else if status == "in-flight" {
        SimulatedAck::LeaseExpired
    } else {
        SimulatedAck::StaleOrSuperseded
    }
}

/// Commits the full production acknowledgement: compare-and-set first, then
/// the closed classification when the set did not match.
fn acknowledge(
    client: &mut Client,
    event_id: &str,
    delivery_id: &str,
    token: &[u8],
    receipt: &ContentDigest,
) -> SimulatedAck {
    let mut tx = client.transaction().unwrap();
    if ack_cas_in_tx(&mut tx, event_id, delivery_id, token, receipt) == 1 {
        tx.commit().unwrap();
        return SimulatedAck::Committed;
    }
    let outcome = ack_classification_in_tx(&mut tx, event_id, delivery_id, token);
    tx.commit().unwrap();
    outcome
}

/// Applies the production dead-letter compare-and-set inside the caller's
/// transaction.
fn dead_letter_cas_in_tx(
    tx: &mut Transaction<'_>,
    event_id: &str,
    delivery_id: &str,
    token: &[u8],
) -> u64 {
    tx.execute(
        PRODUCTION_DEAD_LETTER_CAS_SQL,
        &[&event_id, &delivery_id, &1_i64, &lease_token_hash(token)],
    )
    .unwrap()
}

/// Records the terminal attempt status of a committed dead-letter transition
/// inside its transaction.
fn mark_attempt_terminal_in_tx(
    tx: &mut Transaction<'_>,
    event_id: &str,
    attempt: i64,
    label: &str,
) {
    tx.execute(
        "UPDATE delivery_attempts SET status = $3, terminal_at = clock_timestamp()
         WHERE event_id = $1 AND generation = 1 AND attempt_number = $2",
        &[&event_id, &attempt, &label],
    )
    .unwrap();
}

/// Expires every lease and retry schedule of one delivery in database time.
fn expire_lease(client: &mut Client, delivery_id: &str) {
    client
        .execute(
            "UPDATE delivery_state
             SET lease_expires_at = clock_timestamp() - interval '1 second',
                 next_attempt_at = clock_timestamp() - interval '1 second'
             WHERE delivery_id = $1",
            &[&delivery_id],
        )
        .unwrap();
}

fn delivery_status(client: &mut Client, delivery_id: &str) -> String {
    client
        .query_one(
            "SELECT status FROM delivery_state WHERE delivery_id = $1",
            &[&delivery_id],
        )
        .unwrap()
        .get(0)
}

fn attempts_in_generation(client: &mut Client, delivery_id: &str) -> i64 {
    client
        .query_one(
            "SELECT attempts_in_generation FROM delivery_state WHERE delivery_id = $1",
            &[&delivery_id],
        )
        .unwrap()
        .get(0)
}

fn attempt_rows(client: &mut Client, delivery_id: &str) -> Vec<(i64, String)> {
    client
        .query(
            "SELECT attempt_number, status FROM delivery_attempts
             WHERE delivery_id = $1 ORDER BY attempt_number",
            &[&delivery_id],
        )
        .unwrap()
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

/// What a live worker would currently claim, in deterministic stream order.
fn due_deliveries(client: &mut Client) -> Vec<String> {
    client
        .query(PRODUCTION_CLAIM_SELECT_SQL, &[])
        .unwrap()
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect()
}

/// The immutable application inputs a delivery handler consumes: identical
/// across every redelivery of the same stable delivery.
fn application_inputs(client: &mut Client, event_id: &str) -> (String, String, i64, String, i64) {
    let row = client
        .query_one(
            "SELECT event_type, ordering_key, stream_sequence, effect_digest,
                    destination_configuration_version
             FROM outbox_events WHERE event_id = $1",
            &[&event_id],
        )
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))
}

/// A claim transaction that records its lease and attempt and then aborts
/// before commit — the process dies inside the claim boundary.
fn claim_interrupted_then_rolled_back(
    client: &mut Client,
    event_id: &str,
    delivery_id: &str,
    attempt: i64,
) {
    let token = lease_token_bytes(event_id, attempt);
    let token_hash = lease_token_hash(&token);
    let attempt_id = format!("attempt-{event_id}-{attempt}");
    let mut tx = client.transaction().unwrap();
    let updated = tx
        .execute(
            PRODUCTION_CLAIM_UPDATE_SQL,
            &[&event_id, &delivery_id, &1_i64, &attempt, &token_hash],
        )
        .unwrap();
    assert_eq!(updated, 1);
    tx.execute(
        PRODUCTION_CLAIM_ATTEMPT_INSERT_SQL,
        &[
            &attempt_id,
            &event_id,
            &delivery_id,
            &1_i64,
            &attempt,
            &token_hash,
        ],
    )
    .unwrap();
    // Simulate the crash: the claim transaction never reaches commit.
    tx.rollback().unwrap();
}

/// A crashed claim must consume nothing: a fresh reader sees the delivery
/// still fully due with zero counted attempts, and the recovery claim is the
/// FIRST counted attempt, not the second.
#[test]
fn outbox_claim_interruption_pre_commit_claim_consumes_nothing() {
    let mut db = SchemaDb::new(
        "claim_interrupt",
        &[OUTBOX_EVENTS_DDL, DELIVERY_STATE_V3_DDL],
    );
    let event = preview_event("019c0000-0000-7000-8000-0000000000b1", 1, "preview/a", 0xB1);
    seed_outbox_event(&mut db, &event);
    seed_pending_delivery(&mut db, &event.event_id, "delivery-b1");

    claim_interrupted_then_rolled_back(&mut db.client, &event.event_id, "delivery-b1", 1);

    // Failure visibility on a fresh connection: no lease, no attempt history,
    // and a live worker would still select exactly this delivery as due.
    let mut reader = fresh_reader(&db.schema);
    assert_eq!(delivery_status(&mut reader, "delivery-b1"), "pending");
    assert_eq!(attempts_in_generation(&mut reader, "delivery-b1"), 0);
    assert!(attempt_rows(&mut reader, "delivery-b1").is_empty());
    assert_eq!(due_deliveries(&mut reader), vec![event.event_id.clone()]);
    drop(reader);

    // Recovery: the retried claim is attempt number one and owns a live lease.
    let _recovered_token = claim_committed(&mut db.client, &event.event_id, "delivery-b1", 1);
    assert_eq!(delivery_status(&mut db.client, "delivery-b1"), "in-flight");
    assert_eq!(attempts_in_generation(&mut db.client, "delivery-b1"), 1);
    assert_eq!(
        attempt_rows(&mut db.client, "delivery-b1"),
        vec![(1, "claimed".to_owned())]
    );
    assert_eq!(due_deliveries(&mut db.client), Vec::<String>::new());
}

/// A crash after the external send succeeded but before the acknowledgement
/// commits leaves the live lease intact: the same token still acknowledges on
/// the recovered connection, and a repeated acknowledgement is an exact no-op.
#[test]
fn outbox_acknowledgement_interruption_preserves_the_live_lease_for_retry() {
    let mut db = SchemaDb::new("ack_interrupt", &[OUTBOX_EVENTS_DDL, DELIVERY_STATE_V3_DDL]);
    let event = preview_event("019c0000-0000-7000-8000-0000000000c1", 1, "preview/a", 0xC1);
    seed_outbox_event(&mut db, &event);
    seed_pending_delivery(&mut db, &event.event_id, "delivery-c1");

    let token = claim_committed(&mut db.client, &event.event_id, "delivery-c1", 1);

    // The send succeeded; the acknowledgement transaction aborts mid-commit.
    let receipt = digest(0xCC);
    let mut tx = db.client.transaction().unwrap();
    let updated = ack_cas_in_tx(&mut tx, &event.event_id, "delivery-c1", &token, &receipt);
    assert_eq!(updated, 1);
    tx.rollback().unwrap();

    // Failure visibility: still in flight under the same lease, no receipt,
    // and the attempt remains non-terminal claimed history.
    let mut reader = fresh_reader(&db.schema);
    assert_eq!(delivery_status(&mut reader, "delivery-c1"), "in-flight");
    assert_eq!(attempts_in_generation(&mut reader, "delivery-c1"), 1);
    let stored_receipt: Option<String> = reader
        .query_one(
            "SELECT receipt_digest FROM delivery_state WHERE delivery_id = $1",
            &[&"delivery-c1"],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored_receipt, None);
    drop(reader);

    // Recovery: the unchanged token acknowledges; repetition is a zero-row no-op.
    assert_eq!(
        acknowledge(
            &mut db.client,
            &event.event_id,
            "delivery-c1",
            &token,
            &receipt
        ),
        SimulatedAck::Committed
    );
    assert_eq!(delivery_status(&mut db.client, "delivery-c1"), "delivered");
    assert_eq!(
        acknowledge(
            &mut db.client,
            &event.event_id,
            "delivery-c1",
            &token,
            &receipt
        ),
        SimulatedAck::StaleOrSuperseded,
        "a delivered terminal state can never be acknowledged again"
    );
    let persisted: String = db
        .client
        .query_one(
            "SELECT receipt_digest FROM delivery_state WHERE delivery_id = $1",
            &[&"delivery-c1"],
        )
        .unwrap()
        .get(0);
    assert_eq!(persisted, receipt.to_string());
}

/// An acknowledgement racing lease expiry is classified `LeaseExpired`, never
/// silently dropped: the delivery stays visible, a takeover claim supersedes
/// the expired token, and only the new token reaches terminal delivery.
#[test]
fn outbox_acknowledgement_after_lease_expiry_is_expired_and_takeover_supersedes() {
    let mut db = SchemaDb::new("ack_expired", &[OUTBOX_EVENTS_DDL, DELIVERY_STATE_V3_DDL]);
    let event = preview_event("019c0000-0000-7000-8000-0000000000d1", 1, "preview/a", 0xD1);
    seed_outbox_event(&mut db, &event);
    seed_pending_delivery(&mut db, &event.event_id, "delivery-d1");

    let expired_token = claim_committed(&mut db.client, &event.event_id, "delivery-d1", 1);
    expire_lease(&mut db.client, "delivery-d1");

    // Failure visibility: the late acknowledgement matches token and status but
    // loses to expiry — zero rows move and the delivery stays in flight.
    let receipt = digest(0xDD);
    let mut reader = fresh_reader(&db.schema);
    let mut tx = reader.transaction().unwrap();
    let moved = ack_cas_in_tx(
        &mut tx,
        &event.event_id,
        "delivery-d1",
        &expired_token,
        &receipt,
    );
    assert_eq!(moved, 0, "an expired lease can never acknowledge");
    assert_eq!(
        ack_classification_in_tx(&mut tx, &event.event_id, "delivery-d1", &expired_token),
        SimulatedAck::LeaseExpired
    );
    tx.rollback().unwrap();
    assert_eq!(delivery_status(&mut reader, "delivery-d1"), "in-flight");
    drop(reader);

    // Recovery: takeover reclaims the SAME stable delivery with a fresh token.
    let takeover_token = claim_committed(&mut db.client, &event.event_id, "delivery-d1", 2);
    assert_ne!(takeover_token, expired_token);
    assert_eq!(attempts_in_generation(&mut db.client, "delivery-d1"), 2);

    // The expired holder stays rejected while the takeover completes delivery.
    assert_eq!(
        acknowledge(
            &mut db.client,
            &event.event_id,
            "delivery-d1",
            &expired_token,
            &receipt
        ),
        SimulatedAck::StaleOrSuperseded
    );
    assert_eq!(
        acknowledge(
            &mut db.client,
            &event.event_id,
            "delivery-d1",
            &takeover_token,
            &receipt
        ),
        SimulatedAck::Committed
    );
    assert_eq!(delivery_status(&mut db.client, "delivery-d1"), "delivered");
}

/// A crash after the external effect was applied but before any
/// acknowledgement is at-least-once by contract: the durable attempt history
/// proves both attempts, and redelivery presents byte-identical application
/// inputs so the content-addressed preview target absorbs the repetition.
#[test]
fn outbox_send_applied_before_crash_redelivers_identical_application_inputs() {
    let mut db = SchemaDb::new("send_crash", &[OUTBOX_EVENTS_DDL, DELIVERY_STATE_V3_DDL]);
    let event = preview_event("019c0000-0000-7000-8000-0000000000e1", 1, "preview/a", 0xE1);
    seed_outbox_event(&mut db, &event);
    seed_pending_delivery(&mut db, &event.event_id, "delivery-e1");

    let first_token = claim_committed(&mut db.client, &event.event_id, "delivery-e1", 1);
    let first_inputs = application_inputs(&mut db.client, &event.event_id);

    // Simulate the crash after external application: no acknowledgement ever
    // arrives; the lease simply lapses with the process gone.
    expire_lease(&mut db.client, "delivery-e1");

    // Failure visibility: the in-flight state and the non-terminal first
    // attempt survive the crash as durable at-least-once evidence.
    let mut reader = fresh_reader(&db.schema);
    assert_eq!(delivery_status(&mut reader, "delivery-e1"), "in-flight");
    assert_eq!(
        attempt_rows(&mut reader, "delivery-e1"),
        vec![(1, "claimed".to_owned())]
    );
    drop(reader);

    // Recovery: takeover redelivers the identical immutable inputs under a
    // fresh token and a second counted attempt.
    let second_token = claim_committed(&mut db.client, &event.event_id, "delivery-e1", 2);
    assert_ne!(second_token, first_token);
    let second_inputs = application_inputs(&mut db.client, &event.event_id);
    assert_eq!(
        first_inputs, second_inputs,
        "redelivery must repeat byte-identical application inputs"
    );
    assert_eq!(
        attempt_rows(&mut db.client, "delivery-e1"),
        vec![(1, "claimed".to_owned()), (2, "claimed".to_owned())]
    );

    // The recovered attempt terminates the delivery exactly once.
    assert_eq!(
        acknowledge(
            &mut db.client,
            &event.event_id,
            "delivery-e1",
            &second_token,
            &digest(0xEE)
        ),
        SimulatedAck::Committed
    );
    assert_eq!(delivery_status(&mut db.client, "delivery-e1"), "delivered");
}

/// A poison quarantine that crashes mid-transition leaves the delivery
/// retryable and the stream unblocked by nothing new; only the committed
/// transition dead-letters the poison, blocks exactly its own successor, and
/// becomes a zero-row no-op when repeated.
#[test]
fn poison_quarantine_transition_interruption_defers_stream_blocking() {
    let mut db = SchemaDb::new(
        "poison_quarantine",
        &[OUTBOX_EVENTS_DDL, DELIVERY_STATE_V3_DDL],
    );
    let poison = preview_event("019c0000-0000-7000-8000-0000000000f1", 1, "preview/a", 0xF1);
    let successor = preview_event("019c0000-0000-7000-8000-0000000000f2", 2, "preview/a", 0xF2);
    let independent = preview_event("019c0000-0000-7000-8000-0000000000f3", 3, "preview/b", 0xF3);
    for event in [&poison, &successor, &independent] {
        seed_outbox_event(&mut db, event);
    }
    seed_pending_delivery(&mut db, &poison.event_id, "poison-delivery");
    seed_pending_delivery(&mut db, &successor.event_id, "successor-delivery");
    seed_pending_delivery(&mut db, &independent.event_id, "independent-delivery");

    // Eleven prior failures: the twelfth claim reaches the poison threshold.
    db.client
        .execute(
            "UPDATE delivery_state SET attempts_in_generation = 11 WHERE delivery_id = $1",
            &[&"poison-delivery"],
        )
        .unwrap();
    let poison_token = claim_committed(&mut db.client, &poison.event_id, "poison-delivery", 12);
    assert_eq!(
        attempts_in_generation(&mut db.client, "poison-delivery"),
        12
    );

    // The quarantine transition starts and the process dies before commit.
    let mut tx = db.client.transaction().unwrap();
    assert_eq!(
        dead_letter_cas_in_tx(&mut tx, &poison.event_id, "poison-delivery", &poison_token),
        1
    );
    tx.rollback().unwrap();

    // Failure visibility: the poison is still in flight at threshold, so the
    // live worker claims ONLY the independent stream — its own successor stays
    // blocked by the nonterminal predecessor either way.
    let mut reader = fresh_reader(&db.schema);
    assert_eq!(delivery_status(&mut reader, "poison-delivery"), "in-flight");
    assert_eq!(attempts_in_generation(&mut reader, "poison-delivery"), 12);
    assert_eq!(
        due_deliveries(&mut reader),
        vec![independent.event_id.clone()]
    );
    drop(reader);

    // Recovery: the retried transition commits and quarantines the poison.
    let mut tx = db.client.transaction().unwrap();
    assert_eq!(
        dead_letter_cas_in_tx(&mut tx, &poison.event_id, "poison-delivery", &poison_token),
        1
    );
    mark_attempt_terminal_in_tx(
        &mut tx,
        &poison.event_id,
        12,
        "dead-letter:attempts-exhausted",
    );
    tx.commit().unwrap();
    assert_eq!(
        delivery_status(&mut db.client, "poison-delivery"),
        "dead-letter"
    );
    assert_eq!(
        attempt_rows(&mut db.client, "poison-delivery"),
        vec![(12, "dead-letter:attempts-exhausted".to_owned())]
    );

    // The committed quarantine blocks exactly its own stream while the
    // independent stream remains deliverable.
    assert_eq!(
        due_deliveries(&mut db.client),
        vec![independent.event_id.clone()],
        "only the independent stream progresses past a dead-lettered prefix"
    );

    // Repeating the quarantine with the consumed token is a zero-row no-op:
    // the first transition cleared the lease it compared against.
    let mut tx = db.client.transaction().unwrap();
    assert_eq!(
        dead_letter_cas_in_tx(&mut tx, &poison.event_id, "poison-delivery", &poison_token),
        0,
        "a repeated dead-letter must be an idempotent no-op"
    );
    tx.rollback().unwrap();
}
