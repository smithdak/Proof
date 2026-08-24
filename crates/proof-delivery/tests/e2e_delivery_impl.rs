//! End-to-end delivery lifecycle test (P-0012).
//!
//! One test drives the complete private-preview delivery state machine against
//! an isolated `PostgreSQL` schema and an isolated preview staging directory:
//!
//! 1. a `preview.release/v1` outbox event is enqueued through the proof-pg
//!    enqueue API and its stable delivery ID is preallocated as `pending`;
//! 2. the worker claims it, the preview adapter materializes the snapshot, the
//!    claim is acknowledged, and `resolve_ready` serves the exact manifest;
//! 3. a second stream is forced into a permanent-failure dead-letter, replay
//!    resets the generation to `pending` with zero attempts, and abandonment
//!    marks the poison terminal — each management action appending one
//!    `DeliveryManagementFactV1` whose digest the test re-verifies.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use proof_delivery::{
    preview::{PreviewAdapter, PreviewBlobV1, PreviewSnapshotV1, ReadyManifestV1},
    worker::{AcknowledgeOutcome, ClaimedDeliveryV1, DeadLetterReason, OutboxWorker, WorkerConfig},
};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp, WorkspaceId};
use proof_pg::{
    PgConfig,
    outbox::{OutboxEnqueueV1, enqueue},
    postgres_types::ToSql,
    wiring::PgRuntime,
};
use proof_remote::{DeliveryManagementAction, DeliveryManagementFactV1, derive_key_digest};

/// A valid `UUIDv7` Workspace identity for the enqueued outbox rows.
const WORKSPACE: &str = "019c0000-0000-7000-8000-000000000010";

/// Fixed valid `UUIDv7` identities for the two delivery-management facts.
const REPLAY_IDEMPOTENCY_KEY: &str = "019d0000-0000-7000-8000-000000000201";
const ABANDON_IDEMPOTENCY_KEY: &str = "019d0000-0000-7000-8000-000000000202";

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);
static PREVIEW_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn unique_schema() -> String {
    let n = SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("p0012_e2e_{}_{}", std::process::id(), n)
}

fn unique_preview_root() -> std::path::PathBuf {
    let n = PREVIEW_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("proof-e2e-preview-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn now_timestamp() -> Timestamp {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(nanos).expect("nanos fit in i128"))
        .expect("timestamp is representable")
}

fn evidence_digest() -> ContentDigest {
    ContentDigest::blake3([0xee; 32])
}

/// A runtime connected to a dedicated isolated schema plus a private preview
/// staging root, both dropped on teardown.
struct TestDb {
    runtime: PgRuntime,
    schema: String,
    preview_root: std::path::PathBuf,
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
        let preview_root = unique_preview_root();
        Self {
            runtime,
            schema,
            preview_root,
        }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
        let _ = std::fs::remove_dir_all(&self.preview_root);
    }
}

/// Enqueues one `preview.release/v1` event through the proof-pg enqueue API and
/// preallocates its stable delivery ID as `pending`, mirroring the
/// authoritative release-commitment transaction (contract §"Transactional
/// outbox and delivery").
#[allow(clippy::too_many_arguments)]
fn enqueue_delivery(
    runtime: &mut PgRuntime,
    event_id: &str,
    delivery_id: &str,
    ordering_key: &str,
    sequence: i64,
    ordinal: i64,
    stream_sequence: i64,
) {
    let workspace_id: WorkspaceId = WORKSPACE.parse().expect("valid Workspace UUIDv7");
    let effect_digest = derive_key_digest("proof:test-effect:v1", event_id.as_bytes());
    let event = OutboxEnqueueV1 {
        event_id: event_id.to_owned(),
        workspace_id,
        workspace_transaction_sequence: u64::try_from(sequence).expect("non-negative sequence"),
        ordinal: u64::try_from(ordinal).expect("non-negative ordinal"),
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: ordering_key.to_owned(),
        stream_sequence: u64::try_from(stream_sequence).expect("non-negative stream sequence"),
        effect_digest,
        payload_digest: Some(ContentDigest::blake3([0x33; 32])),
        artifact_reference: None,
        destination_configuration_version: 1,
        destination_configuration_digest: ContentDigest::blake3([0x44; 32]),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: now_timestamp(),
    };

    let mut transaction = runtime
        .client_mut()
        .transaction()
        .expect("begin enqueue transaction");
    enqueue(&mut transaction, &event).expect("enqueue outbox event");

    let delivery_id_owned = delivery_id.to_owned();
    let params: &[&(dyn ToSql + Sync)] = &[&event.event_id, &delivery_id_owned];
    transaction
        .execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             ) VALUES ($1, $2, 1, 'pending', NULL, 0, NULL, NULL, NULL,
                       clock_timestamp(), clock_timestamp())",
            params,
        )
        .expect("preallocate delivery state");
    transaction.commit().expect("commit enqueue");
}

/// Reads the exact delivery status for one generation.
fn status_of(
    runtime: &mut PgRuntime,
    event_id: &str,
    delivery_id: &str,
    generation: i64,
) -> String {
    let event_id = event_id.to_owned();
    let delivery_id = delivery_id.to_owned();
    let params: &[&(dyn ToSql + Sync)] = &[&event_id, &delivery_id, &generation];
    runtime
        .client_mut()
        .query_one(
            "SELECT status FROM delivery_state
             WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
            params,
        )
        .expect("read delivery status")
        .get(0)
}

/// Reads the counted attempts for one generation.
fn attempts_of(runtime: &mut PgRuntime, event_id: &str, delivery_id: &str, generation: i64) -> i64 {
    let event_id = event_id.to_owned();
    let delivery_id = delivery_id.to_owned();
    let params: &[&(dyn ToSql + Sync)] = &[&event_id, &delivery_id, &generation];
    runtime
        .client_mut()
        .query_one(
            "SELECT attempts_in_generation FROM delivery_state
             WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
            params,
        )
        .expect("read attempts")
        .get(0)
}

/// Materializes the reference `preview.release/v1` snapshot for one claim.
fn materialize(adapter: &PreviewAdapter, claim: &ClaimedDeliveryV1) -> ReadyManifestV1 {
    let kind = ArtifactKind::ReleaseV2;
    let bytes = claim.effect_digest.to_string().into_bytes();
    let digest = derive_key_digest(kind.derive_key_context(), &bytes);
    let hex = digest.to_string().trim_start_matches("blake3:").to_owned();
    let blob = PreviewBlobV1 {
        key: format!("artifacts/{}/blake3/{hex}", kind.wire_name()),
        kind: kind.wire_name().to_owned(),
        length: bytes.len() as u64,
        digest,
        bytes,
    };
    let snapshot = PreviewSnapshotV1 {
        release_id: claim.event_id.clone(),
        release_sequence: claim.stream_sequence,
        release_digest: claim.effect_digest,
        edition_digest: claim
            .payload_digest
            .unwrap_or_else(|| ContentDigest::blake3([0_u8; 32])),
        environment_config_digest: claim.destination_configuration_digest,
        proof_digest: ContentDigest::blake3([0_u8; 32]),
        blobs: vec![blob],
    };
    adapter
        .materialize_snapshot(&snapshot)
        .expect("materialize the preview snapshot")
}

/// Persists one immutable delivery-management fact and its digest.
fn persist_management_fact(runtime: &mut PgRuntime, fact: &DeliveryManagementFactV1) {
    let fact_id = format!("delivery_management_fact/{}", uuid::Uuid::now_v7());
    let digest = fact.digest().expect("fact digest").to_string();
    let payload = serde_json::to_vec(fact).expect("serialize fact");
    let generation = i64::try_from(fact.from_generation).expect("generation fits BIGINT");
    let action = match fact.action {
        DeliveryManagementAction::Replay => "replay",
        DeliveryManagementAction::Abandon => "abandon",
    };
    let recorded_at = SystemTime::now();
    let workspace_id = fact.workspace_id.clone();
    let event_id = fact.event_id.clone();
    let delivery_id = fact.delivery_id.clone();
    let params: &[&(dyn ToSql + Sync)] = &[
        &fact_id,
        &workspace_id,
        &event_id,
        &delivery_id,
        &generation,
        &action,
        &digest,
        &payload,
        &recorded_at,
    ];
    runtime
        .client_mut()
        .execute(
            "INSERT INTO delivery_management_facts (
                 fact_id, workspace_id, event_id, delivery_id, generation, action,
                 fact_digest, payload, recorded_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            params,
        )
        .expect("persist management fact");
}

/// Reads back the appended management facts for one delivery, ordered by
/// generation.
fn management_facts(runtime: &mut PgRuntime, delivery_id: &str) -> Vec<DeliveryManagementFactV1> {
    let delivery_id = delivery_id.to_owned();
    let params: &[&(dyn ToSql + Sync)] = &[&delivery_id];
    runtime
        .client_mut()
        .query(
            "SELECT payload FROM delivery_management_facts
             WHERE delivery_id = $1 ORDER BY generation",
            params,
        )
        .expect("read management facts")
        .iter()
        .map(|row| {
            serde_json::from_slice::<DeliveryManagementFactV1>(&row.get::<_, Vec<u8>>(0))
                .expect("fact payload round-trips")
        })
        .collect()
}

/// Replays a dead-letter generation: appends the immutable replay fact and
/// inserts the successor generation as `pending` with zero attempts.
fn replay(runtime: &mut PgRuntime, event_id: &str, delivery_id: &str, from_generation: i64) {
    let fact = DeliveryManagementFactV1::replay(
        WORKSPACE,
        event_id,
        delivery_id,
        u64::try_from(from_generation).expect("non-negative generation"),
        REPLAY_IDEMPOTENCY_KEY,
        evidence_digest(),
        1,
        now_timestamp(),
    );
    persist_management_fact(runtime, &fact);

    let event_id = event_id.to_owned();
    let delivery_id = delivery_id.to_owned();
    let successor = from_generation + 1;
    let params: &[&(dyn ToSql + Sync)] = &[&event_id, &delivery_id, &successor];
    runtime
        .client_mut()
        .execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             ) VALUES ($1, $2, $3, 'pending', NULL, 0, NULL, NULL, NULL,
                       clock_timestamp(), clock_timestamp())",
            params,
        )
        .expect("insert replayed generation");
}

/// Abandons a dead-letter generation: appends the immutable abandonment fact
/// and marks the generation terminal `abandoned`.
fn abandon(runtime: &mut PgRuntime, event_id: &str, delivery_id: &str, generation: i64) {
    let fact = DeliveryManagementFactV1::abandon(
        WORKSPACE,
        event_id,
        delivery_id,
        u64::try_from(generation).expect("non-negative generation"),
        ABANDON_IDEMPOTENCY_KEY,
        "operator-confirmed-poison-delivery",
        evidence_digest(),
        2,
        now_timestamp(),
    );
    persist_management_fact(runtime, &fact);

    let event_id = event_id.to_owned();
    let delivery_id = delivery_id.to_owned();
    let params: &[&(dyn ToSql + Sync)] = &[&event_id, &delivery_id, &generation];
    runtime
        .client_mut()
        .execute(
            "UPDATE delivery_state
             SET status = 'abandoned',
                 next_attempt_at = NULL,
                 lease_token_hash = NULL,
                 lease_expires_at = NULL,
                 receipt_digest = NULL
             WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
            params,
        )
        .expect("abandon delivery");
}

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_delivery_lifecycle() {
    let mut db = TestDb::new();
    let worker = OutboxWorker::new(WorkerConfig::new(dsn()));
    let adapter = PreviewAdapter::new(&db.preview_root);

    // ----------------------------------------------------------------------
    // Happy path: enqueue -> claim -> materialize -> acknowledge -> resolve.
    // ----------------------------------------------------------------------
    let event_id = "019d0000-0000-7000-8000-000000000100";
    let delivery_id = "019d0000-0000-7000-8000-000000000101";
    enqueue_delivery(
        &mut db.runtime,
        event_id,
        delivery_id,
        "e2e/released",
        1,
        1,
        1,
    );

    let claims = worker
        .claim_due_work(&mut db.runtime)
        .expect("claim due work");
    assert_eq!(claims.len(), 1, "exactly one delivery is due");
    let claim = &claims[0];
    assert_eq!(claim.event_id, event_id);
    assert_eq!(claim.delivery_id, delivery_id);
    assert_eq!(claim.event_type, "preview.release");
    assert_eq!(claim.event_version, "v1");
    assert_eq!(claim.generation, 1);
    assert_eq!(claim.attempt_number, 1);

    let manifest = materialize(&adapter, claim);
    assert_eq!(
        worker
            .acknowledge(&mut db.runtime, claim, manifest.manifest_digest)
            .expect("acknowledge"),
        AcknowledgeOutcome::Acknowledged
    );
    assert_eq!(
        status_of(&mut db.runtime, event_id, delivery_id, 1),
        "delivered"
    );

    // The exact snapshot is now resolvable and byte-identical to the manifest.
    let resolved = adapter
        .resolve_ready(event_id)
        .expect("resolve ready snapshot");
    assert_eq!(resolved, manifest);

    // ----------------------------------------------------------------------
    // Poison path: forced failure -> dead-letter -> replay -> abandon.
    // ----------------------------------------------------------------------
    let poison_event = "019d0000-0000-7000-8000-000000000102";
    let poison_delivery = "019d0000-0000-7000-8000-000000000103";
    enqueue_delivery(
        &mut db.runtime,
        poison_event,
        poison_delivery,
        "e2e/poison",
        2,
        1,
        1,
    );

    let claims = worker
        .claim_due_work(&mut db.runtime)
        .expect("claim poison");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].delivery_id, poison_delivery);

    // A forced permanent failure dead-letters immediately.
    worker
        .dead_letter(
            &mut db.runtime,
            &claims[0],
            DeadLetterReason::PermanentFailure,
        )
        .expect("forced dead-letter");
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 1),
        "dead-letter"
    );

    // Replay resets the generation: the successor is pending with zero attempts
    // while the dead-letter generation remains preserved history.
    replay(&mut db.runtime, poison_event, poison_delivery, 1);
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 1),
        "dead-letter"
    );
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 2),
        "pending"
    );
    assert_eq!(
        attempts_of(&mut db.runtime, poison_event, poison_delivery, 2),
        0
    );

    // The reset generation is claimable; force a second permanent failure so the
    // poison is confirmed before abandonment.
    let claims = worker
        .claim_due_work(&mut db.runtime)
        .expect("claim replayed generation");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].delivery_id, poison_delivery);
    assert_eq!(claims[0].generation, 2);
    worker
        .dead_letter(
            &mut db.runtime,
            &claims[0],
            DeadLetterReason::PermanentFailure,
        )
        .expect("second forced dead-letter");
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 2),
        "dead-letter"
    );

    // Abandonment marks the poison terminal.
    abandon(&mut db.runtime, poison_event, poison_delivery, 2);
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 2),
        "abandoned"
    );
    assert_eq!(
        status_of(&mut db.runtime, poison_event, poison_delivery, 1),
        "dead-letter"
    );

    // Both management actions appended one immutable fact with the exact digest.
    let facts = management_facts(&mut db.runtime, poison_delivery);
    assert_eq!(facts.len(), 2);
    assert_eq!(facts[0].action, DeliveryManagementAction::Replay);
    assert_eq!(facts[0].from_generation, 1);
    assert_eq!(facts[0].to_generation, Some(2));
    assert_eq!(facts[0].reason, "dead-letter-replay");
    assert_eq!(facts[1].action, DeliveryManagementAction::Abandon);
    assert_eq!(facts[1].from_generation, 2);
    assert_eq!(facts[1].to_generation, None);
    assert_eq!(facts[1].reason, "operator-confirmed-poison-delivery");
    for fact in &facts {
        let persisted_digest =
            fact_digest_of(&mut db.runtime, &fact.delivery_id, fact.from_generation);
        assert_eq!(fact.digest().expect("fact digest"), persisted_digest);
    }
}

/// Reads the stored fact digest for one delivery generation.
fn fact_digest_of(runtime: &mut PgRuntime, delivery_id: &str, generation: u64) -> ContentDigest {
    let delivery_id = delivery_id.to_owned();
    let generation = i64::try_from(generation).expect("generation fits BIGINT");
    let params: &[&(dyn ToSql + Sync)] = &[&delivery_id, &generation];
    let encoded: String = runtime
        .client_mut()
        .query_one(
            "SELECT fact_digest FROM delivery_management_facts
             WHERE delivery_id = $1 AND generation = $2",
            params,
        )
        .expect("read fact digest")
        .get(0);
    encoded.parse().expect("fact digest parses")
}
