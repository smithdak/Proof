//! Integration tests for the generation-scoped outbox worker boundary
//! (P-0012 `worker.rs`).
//!
//! Every test isolates itself in a dedicated `PostgreSQL` schema
//! (`CREATE SCHEMA` + `SET search_path` + `DROP SCHEMA CASCADE` on drop) and
//! exercises the worker against the `DELIVERY_STATE_V3_DDL` tables joined to
//! the P-0010 `outbox_events` enqueue records.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime},
};

use proof_delivery::{
    DeliveryError,
    worker::{
        AcknowledgeOutcome, ClaimedDeliveryV1, DeadLetterReason, OutboxWorker, RetryDelay,
        WorkerConfig,
    },
};
use proof_domain::{ContentDigest, WorkspaceId};
use proof_pg::{PgConfig, postgres_types::ToSql, wiring::PgRuntime};

/// A valid `UUIDv7` Workspace identity for the seeded outbox rows.
const WORKSPACE: &str = "019c0000-0000-7000-8000-000000000010";

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn unique_schema() -> String {
    let n = SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("p0012_worker_{}_{}", std::process::id(), n)
}

/// A runtime connected to a dedicated isolated schema, dropped on teardown.
struct TestDb {
    runtime: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new() -> Self {
        let workspace_id: WorkspaceId = WORKSPACE.parse().expect("valid Workspace UUIDv7");
        let mut runtime =
            PgRuntime::connect(PgConfig::new(dsn(), workspace_id, Duration::from_secs(30)))
                .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        let schema = unique_schema();
        runtime
            .client_mut()
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create schema");
        runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search_path");
        runtime
            .client_mut()
            .batch_execute(proof_pg::schema::OUTBOX_EVENTS_DDL)
            .expect("create outbox_events");
        runtime
            .client_mut()
            .batch_execute(proof_pg::migration::DELIVERY_STATE_V3_DDL)
            .expect("create delivery tables");
        Self { runtime, schema }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// Opens a second runtime connected to the same isolated schema, for the
/// concurrent SKIP LOCKED test.
fn connect_to_schema(schema: &str) -> PgRuntime {
    let workspace_id: WorkspaceId = WORKSPACE.parse().expect("valid Workspace UUIDv7");
    let mut runtime =
        PgRuntime::connect(PgConfig::new(dsn(), workspace_id, Duration::from_secs(30)))
            .expect("connect to PostgreSQL");
    runtime
        .client_mut()
        .batch_execute(&format!("SET search_path TO \"{schema}\""))
        .expect("set search_path");
    runtime
}

fn worker() -> OutboxWorker {
    OutboxWorker::new(WorkerConfig::new(dsn()))
}

/// Seeds one outbox event plus its current-generation delivery state row.
#[allow(clippy::too_many_arguments)]
fn seed_delivery(
    runtime: &mut PgRuntime,
    event_id: &str,
    delivery_id: &str,
    ordering_key: &str,
    sequence: i64,
    ordinal: i64,
    stream_sequence: i64,
    status: &str,
    attempts: i64,
    next_attempt_at: Option<SystemTime>,
    generation_started_at: SystemTime,
    generation: i64,
) {
    let event_id = event_id.to_string();
    let delivery_id = delivery_id.to_string();
    let ordering_key = ordering_key.to_string();
    let status = status.to_string();
    let workspace = WORKSPACE.to_string();
    // Each seeded event is a distinct committed consequence: derive a unique
    // effect digest from its identity so the outbox logical-event uniqueness
    // key does not collide across deliveries.
    let effect =
        proof_remote::derive_key_digest("proof:test-effect:v1", event_id.as_bytes()).to_string();
    let destination = ContentDigest::blake3([0x22; 32]).to_string();

    let event_params: &[&(dyn ToSql + Sync)] = &[
        &event_id,
        &workspace,
        &sequence,
        &ordinal,
        &ordering_key,
        &stream_sequence,
        &effect,
        &destination,
    ];
    runtime
        .client_mut()
        .execute(
            "INSERT INTO outbox_events
                 (event_id, workspace_id, workspace_transaction_sequence, ordinal,
                  event_type, event_version, ordering_key, stream_sequence,
                  effect_digest, payload_digest, destination_configuration_version,
                  destination_configuration_digest, committed_creation_time)
             VALUES ($1, $2, $3, $4, 'preview.release', 'v1', $5, $6, $7, NULL, 1, $8,
                     clock_timestamp())",
            event_params,
        )
        .expect("seed outbox event");

    let state_params: &[&(dyn ToSql + Sync)] = &[
        &event_id,
        &delivery_id,
        &generation,
        &status,
        &next_attempt_at,
        &attempts,
        &generation_started_at,
    ];
    runtime
        .client_mut()
        .execute(
            "INSERT INTO delivery_state
                 (event_id, delivery_id, generation, status, next_attempt_at,
                  attempts_in_generation, lease_token_hash, lease_expires_at,
                  receipt_digest, generation_started_at, committed_at)
             VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7, clock_timestamp())",
            state_params,
        )
        .expect("seed delivery state");
}

fn expire_lease(runtime: &mut PgRuntime, delivery_id: &str) {
    let delivery_id = delivery_id.to_string();
    let params: &[&(dyn ToSql + Sync)] = &[&delivery_id];
    runtime
        .client_mut()
        .execute(
            "UPDATE delivery_state
             SET lease_expires_at = clock_timestamp() - interval '1 second',
                 next_attempt_at = clock_timestamp() - interval '1 second'
             WHERE delivery_id = $1",
            params,
        )
        .expect("expire lease");
}

fn status_of(runtime: &mut PgRuntime, delivery_id: &str) -> String {
    let delivery_id = delivery_id.to_string();
    let params: &[&(dyn ToSql + Sync)] = &[&delivery_id];
    runtime
        .client_mut()
        .query_one(
            "SELECT status FROM delivery_state WHERE delivery_id = $1",
            params,
        )
        .expect("read status")
        .get(0)
}

fn attempts_of(runtime: &mut PgRuntime, delivery_id: &str) -> i64 {
    let delivery_id = delivery_id.to_string();
    let params: &[&(dyn ToSql + Sync)] = &[&delivery_id];
    runtime
        .client_mut()
        .query_one(
            "SELECT attempts_in_generation FROM delivery_state WHERE delivery_id = $1",
            params,
        )
        .expect("read attempts")
        .get(0)
}

/// A handler that always fails transiently, driving the retry/backoff path.
fn failing_handler(_claim: &ClaimedDeliveryV1) -> Result<ContentDigest, DeliveryError> {
    Err(DeliveryError::Integrity(
        "simulated transient delivery failure".to_owned(),
    ))
}

#[test]
fn claim_order_respects_stream_prefixes() {
    let mut db = TestDb::new();
    let worker = worker();

    // One stream with two deliveries in enqueue order.
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );
    seed_delivery(
        &mut db.runtime,
        "e2",
        "d2",
        "stream/a",
        2,
        1,
        2,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    // Only the lowest nonterminal sequence is claimed; the successor is
    // blocked until its prefix is terminally delivered.
    let claims = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1, "only the stream prefix is claimable");
    assert_eq!(claims[0].delivery_id, "d1");

    let receipt = ContentDigest::blake3([0xaa; 32]);
    assert_eq!(
        worker
            .acknowledge(&mut db.runtime, &claims[0], receipt)
            .unwrap(),
        AcknowledgeOutcome::Acknowledged
    );

    // After delivering the prefix, the successor becomes claimable.
    let claims = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].delivery_id, "d2");
}

#[test]
fn skip_locked_parallel_claims_of_distinct_streams() {
    let mut db = TestDb::new();
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );
    seed_delivery(
        &mut db.runtime,
        "e2",
        "d2",
        "stream/b",
        2,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    let schema = db.schema.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();

    // A concurrent transaction locks stream/a's delivery row and holds it.
    let holder = thread::spawn(move || {
        let mut runtime = connect_to_schema(&schema);
        let delivery_id = "d1".to_string();
        let params: &[&(dyn ToSql + Sync)] = &[&delivery_id];
        let mut tx = runtime.client_mut().transaction().expect("begin tx");
        tx.query(
            "SELECT 1 FROM delivery_state WHERE delivery_id = $1 FOR UPDATE",
            params,
        )
        .expect("lock d1");
        locked_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        let _ = tx.commit();
    });

    locked_rx.recv().unwrap();
    // The claim must skip the locked stream/a row and claim stream/b instead.
    let claims = worker().claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1, "SKIP LOCKED must skip the locked row");
    assert_eq!(claims[0].delivery_id, "d2");

    release_tx.send(()).unwrap();
    holder.join().unwrap();
}

#[test]
fn claim_crash_consumes_attempt_and_expiry_redelivers() {
    let mut db = TestDb::new();
    let worker = worker();
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    let first = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].delivery_id, "d1");
    assert_eq!(first[0].attempt_number, 1);
    assert_eq!(attempts_of(&mut db.runtime, "d1"), 1);
    assert_eq!(status_of(&mut db.runtime, "d1"), "in-flight");
    let first_token = first[0].lease_token;

    // Simulate a worker crash: the claim is committed but never acknowledged.
    // After lease expiry the SAME stable delivery identity is eligible again.
    expire_lease(&mut db.runtime, "d1");

    let claims = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].event_id, "e1");
    assert_eq!(claims[0].delivery_id, "d1");
    assert_eq!(claims[0].attempt_number, 2);
    assert_eq!(attempts_of(&mut db.runtime, "d1"), 2);
    assert_ne!(claims[0].lease_token, first_token); // tokens differ across claims
}

#[test]
fn stale_ack_rejection() {
    let mut db = TestDb::new();
    let worker = worker();
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    let first = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(first.len(), 1);
    let stale_claim = first[0].clone();

    // The lease expires and a new claim supersedes the old token.
    expire_lease(&mut db.runtime, "d1");
    let second = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].delivery_id, "d1");
    assert_eq!(second[0].attempt_number, 2);

    let receipt = ContentDigest::blake3([0xaa; 32]);
    assert_eq!(
        worker
            .acknowledge(&mut db.runtime, &stale_claim, receipt)
            .unwrap(),
        AcknowledgeOutcome::StaleOrSuperseded,
        "a superseded lease token must reject"
    );
    assert_eq!(
        worker
            .acknowledge(&mut db.runtime, &second[0], receipt)
            .unwrap(),
        AcknowledgeOutcome::Acknowledged,
        "the current lease token must acknowledge"
    );
    assert_eq!(status_of(&mut db.runtime, "d1"), "delivered");
}

#[test]
fn twelve_attempt_dead_letter() {
    let mut db = TestDb::new();
    let worker = OutboxWorker::with_handler(WorkerConfig::new(dsn()), failing_handler);
    // Eleven prior claims: the next claim is the twelfth.
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        11,
        None,
        SystemTime::now(),
        1,
    );

    worker.run_loop(&mut db.runtime).unwrap();

    assert_eq!(status_of(&mut db.runtime, "d1"), "dead-letter");
    assert_eq!(attempts_of(&mut db.runtime, "d1"), 12);
}

#[test]
fn seven_day_dead_letter() {
    let mut db = TestDb::new();
    let worker = OutboxWorker::with_handler(WorkerConfig::new(dsn()), failing_handler);
    let started = SystemTime::now() - Duration::from_hours(192);
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        1,
        None,
        started,
        1,
    );

    worker.run_loop(&mut db.runtime).unwrap();

    assert_eq!(status_of(&mut db.runtime, "d1"), "dead-letter");
    // Well below the twelve-attempt threshold: age drove the dead-letter.
    assert_eq!(attempts_of(&mut db.runtime, "d1"), 2);
}

#[test]
fn permanent_failure_immediate_dead_letter() {
    let mut db = TestDb::new();
    let worker = worker();
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    let claims = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].attempt_number, 1);

    worker
        .dead_letter(
            &mut db.runtime,
            &claims[0],
            DeadLetterReason::PermanentFailure,
        )
        .unwrap();

    // Immediate: a single attempt, no twelve-attempt or seven-day condition.
    assert_eq!(status_of(&mut db.runtime, "d1"), "dead-letter");
    assert_eq!(attempts_of(&mut db.runtime, "d1"), 1);
}

#[test]
fn poison_stream_blocks_while_other_stream_succeeds() {
    let mut db = TestDb::new();
    let worker = worker();
    // Stream/a: a poison dead-letter followed by a pending successor.
    seed_delivery(
        &mut db.runtime,
        "e1",
        "d1",
        "stream/a",
        1,
        1,
        1,
        "dead-letter",
        0,
        None,
        SystemTime::now(),
        1,
    );
    seed_delivery(
        &mut db.runtime,
        "e2",
        "d2",
        "stream/a",
        2,
        1,
        2,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );
    // Stream/b: an independent pending delivery.
    seed_delivery(
        &mut db.runtime,
        "e3",
        "d3",
        "stream/b",
        3,
        1,
        1,
        "pending",
        0,
        None,
        SystemTime::now(),
        1,
    );

    let claims = worker.claim_due_work(&mut db.runtime).unwrap();
    assert_eq!(claims.len(), 1, "only the independent stream progresses");
    assert_eq!(claims[0].delivery_id, "d3");

    let receipt = ContentDigest::blake3([0xaa; 32]);
    assert_eq!(
        worker
            .acknowledge(&mut db.runtime, &claims[0], receipt)
            .unwrap(),
        AcknowledgeOutcome::Acknowledged
    );

    // Stream/a remains blocked by its poison even after stream/b delivered.
    assert!(worker.claim_due_work(&mut db.runtime).unwrap().is_empty());
}

#[test]
fn retry_delay_bounds_and_distribution() {
    assert_eq!(RetryDelay::window_for_attempt(1), Duration::from_secs(5));
    assert_eq!(RetryDelay::window_for_attempt(2), Duration::from_secs(10));
    assert_eq!(RetryDelay::window_for_attempt(3), Duration::from_secs(20));
    assert_eq!(RetryDelay::window_for_attempt(4), Duration::from_secs(40));
    assert_eq!(RetryDelay::window_for_attempt(5), Duration::from_secs(80));
    assert_eq!(RetryDelay::window_for_attempt(11), Duration::from_hours(1));
    assert_eq!(RetryDelay::window_for_attempt(12), Duration::from_hours(1));
    assert_eq!(RetryDelay::window_for_attempt(0), Duration::ZERO);

    for attempt in [1_u32, 2, 3, 5, 11, 12] {
        let window = RetryDelay::window_for_attempt(attempt);
        let half = window / 2;
        let three_quarters = window * 3 / 4;
        let mut saw_lower = false;
        let mut saw_upper = false;
        let mut min = Duration::MAX;
        let mut max = Duration::ZERO;
        for _ in 0..500 {
            let sample = RetryDelay::sample_upper_half(attempt).unwrap();
            assert!(
                sample >= half,
                "sample {sample:?} below the upper-half floor {half:?}"
            );
            assert!(
                sample < window,
                "sample {sample:?} at or above the window {window:?}"
            );
            if sample < three_quarters {
                saw_lower = true;
            }
            if sample >= three_quarters {
                saw_upper = true;
            }
            min = min.min(sample);
            max = max.max(sample);
        }
        assert!(
            saw_lower,
            "upper-half samples never fell in the lower quarter"
        );
        assert!(
            saw_upper,
            "upper-half samples never fell in the upper quarter"
        );
        assert!(max > min, "samples did not spread across the upper half");
    }
}
