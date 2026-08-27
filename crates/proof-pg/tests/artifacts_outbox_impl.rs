//! Integration tests for the immutable artifact catalog, the filesystem
//! staging port, and the transactional-outbox enqueue boundary (P-0010).
//!
//! Every test isolates itself in a dedicated `PostgreSQL` schema and a dedicated
//! temporary staging directory, and removes both on teardown.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use postgres::{Client, NoTls};
use proof_domain::{ArtifactKind, ContentDigest, CorrelationId, Timestamp, WorkspaceId};
use proof_pg::PgError;
use proof_pg::artifacts::{
    ArtifactIdentity, ArtifactKeyV1, FsStoragePort, SignedArtifactBodyStore, StoragePort,
    catalog_commit,
};
use proof_pg::outbox::{OutboxEnqueueV1, enqueue, enqueue_initial_delivery};
use proof_pg::schema::{ARTIFACT_BODY_PG_DDL, ARTIFACT_CATALOG_DDL, OUTBOX_EVENTS_DDL};

const WORKSPACE: &str = "019c0000-0000-7000-8000-000000000001";
const CORRELATION: &str = "019c0000-0000-7000-8000-000000000002";
const CAUSATION: &str = "019c0000-0000-7000-8000-000000000003";
const EVENT_ID: &str = "019c0000-0000-7000-8000-0000000000e1";
const EVENT_ID_2: &str = "019c0000-0000-7000-8000-0000000000e2";
const EVENT_ID_3: &str = "019c0000-0000-7000-8000-0000000000e3";
const DELIVERY_ID: &str = "019c0000-0000-7000-8000-0000000000d1";

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn unique_schema() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("p0010_ao_{}_{}", std::process::id(), n)
}

/// A dedicated `PostgreSQL` schema, created and dropped around one test.
struct TestDb {
    client: Client,
    schema: String,
}

impl TestDb {
    fn new(tables: &[&str]) -> Self {
        let schema = unique_schema();
        let mut client = Client::connect(&dsn(), NoTls)
            .expect("failed to connect to PostgreSQL; set PROOF_PG_DSN or run scripts/dev-pg.sh");
        client
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .unwrap_or_else(|e| panic!("cannot create test schema {schema}: {e}"));
        client
            .batch_execute(&format!("SET search_path TO {schema}"))
            .unwrap();
        for ddl in tables {
            client
                .batch_execute(ddl)
                .unwrap_or_else(|e| panic!("cannot create test table: {e}"));
        }
        Self { client, schema }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema));
    }
}

/// A dedicated temporary directory, removed on teardown.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("proof_pg_{tag}_{}", unique_schema()));
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

fn key(kind: ArtifactKind, bytes: &[u8]) -> ArtifactKeyV1 {
    ArtifactKeyV1 {
        kind,
        blake3_digest: artifact_digest(kind, bytes),
    }
}

fn identity(
    kind: ArtifactKind,
    bytes: &[u8],
    media_type: &str,
    schema_version: Option<u32>,
) -> ArtifactIdentity {
    ArtifactIdentity {
        kind,
        canonical_bytes: bytes.to_vec(),
        digest: artifact_digest(kind, bytes),
        media_type: media_type.to_owned(),
        schema_version,
        length: bytes.len() as u64,
    }
}

fn workspace() -> WorkspaceId {
    WORKSPACE.parse().expect("valid Workspace UUIDv7")
}

#[test]
fn put_if_absent_create_replay_noop_and_integrity_failure() {
    let temp = TempDir::new("put_if_absent");
    let port = FsStoragePort::new(temp.path());
    let kind = ArtifactKind::EditionV1;
    let bytes = br#"{"title":"Proof"}"#.to_vec();
    let k = key(kind, &bytes);
    let path = temp.path().join(k.to_path());

    // create: key absent -> staged file exists
    port.put_if_absent(&k, &bytes).expect("first put succeeds");
    assert!(
        path.is_file(),
        "staged file should exist at {}",
        path.display()
    );

    // replay via a fresh port instance: same bytes succeed as a no-op
    let replay = FsStoragePort::new(temp.path());
    replay
        .put_if_absent(&k, &bytes)
        .expect("replay of identical bytes succeeds");
    assert_eq!(fs::read(&path).unwrap(), bytes);

    // read-after-write reproduces exact bytes
    assert_eq!(port.read_after_write(&k).unwrap(), bytes);

    // different bytes at the same key -> integrity failure
    let other = br#"{"title":"Different"}"#.to_vec();
    assert!(matches!(
        port.put_if_absent(&k, &other),
        Err(PgError::Artifact(_))
    ));

    // a corrupted existing file is an integrity failure even for replay bytes
    fs::write(&path, b"tampered").unwrap();
    assert!(matches!(
        port.put_if_absent(&k, &bytes),
        Err(PgError::Artifact(_))
    ));

    // bytes that do not reproduce the key digest are refused up front
    let wrong = ArtifactKeyV1 {
        kind,
        blake3_digest: artifact_digest(kind, b"something else"),
    };
    assert!(matches!(
        port.put_if_absent(&wrong, &bytes),
        Err(PgError::Artifact(_))
    ));
}

#[test]
fn read_after_write_revalidates_and_rejects_truncation() {
    let temp = TempDir::new("read_after_write");
    let port = FsStoragePort::new(temp.path());
    let kind = ArtifactKind::ChangeSetV1;
    let bytes = br#"{"intent":"publish"}"#.to_vec();
    let k = key(kind, &bytes);
    port.put_if_absent(&k, &bytes).unwrap();

    assert_eq!(port.read_after_write(&k).unwrap(), bytes);

    // truncation changes the digest -> revalidation fails closed
    let path = temp.path().join(k.to_path());
    fs::write(&path, &bytes[..6]).unwrap();
    assert!(matches!(
        port.read_after_write(&k),
        Err(PgError::Artifact(_))
    ));

    // an absent key is an error
    let absent = key(kind, b"never staged");
    assert!(matches!(
        port.read_after_write(&absent),
        Err(PgError::Artifact(_))
    ));
}

#[test]
fn staged_neutral_blob_is_invisible_until_catalog_commit() {
    let temp = TempDir::new("staging");
    let port = FsStoragePort::new(temp.path());
    let mut db = TestDb::new(&[ARTIFACT_CATALOG_DDL, ARTIFACT_BODY_PG_DDL]);

    let kind = ArtifactKind::SchemaVersionV1;
    let bytes = br#"{"$schema":"https://json-schema.org/draft/2020-12/schema"}"#.to_vec();
    let k = key(kind, &bytes);

    // stage only: the blob exists in the filesystem but is not yet named
    port.put_if_absent(&k, &bytes).unwrap();
    assert_eq!(port.read_after_write(&k).unwrap(), bytes);

    let kind_str = kind.wire_name();
    let digest_str = k.blake3_digest.to_string();
    let count: i64 = db
        .client
        .query_one(
            "SELECT COUNT(*) FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        count, 0,
        "a staged blob must not be listed before catalog_commit"
    );

    // catalog_commit names it (the staged blob is external, so not inline)
    let id = identity(kind, &bytes, "application/schema+json", Some(1));
    let mut tx = db.client.transaction().unwrap();
    catalog_commit(&mut tx, &id).unwrap();
    tx.commit().unwrap();

    let count: i64 = db
        .client
        .query_one(
            "SELECT COUNT(*) FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        count, 1,
        "catalog_commit must name the previously staged blob"
    );

    // the named reference is external storage, not an inline body
    let stored_inline: bool = db
        .client
        .query_one(
            "SELECT stored_inline FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert!(!stored_inline);
}

#[test]
fn catalog_and_body_are_atomic_with_the_transaction() {
    let mut db = TestDb::new(&[ARTIFACT_CATALOG_DDL, ARTIFACT_BODY_PG_DDL]);
    let kind = ArtifactKind::AuthorityRecordV1;
    let bytes = br#"{"record":true}"#.to_vec();
    let k = key(kind, &bytes);
    let id = identity(kind, &bytes, "application/json", None);

    let kind_str = kind.wire_name();
    let digest_str = k.blake3_digest.to_string();

    let mut tx = db.client.transaction().unwrap();
    SignedArtifactBodyStore::insert(&mut tx, &k, &bytes).unwrap();
    catalog_commit(&mut tx, &id).unwrap();

    // both are visible inside the uncommitted transaction
    let body: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM artifact_body_pg WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(body, 1);
    let catalog: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(catalog, 1);
    let stored_inline: bool = tx
        .query_one(
            "SELECT stored_inline FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert!(stored_inline);

    // rolling back discards the only durable copy of both
    tx.rollback().unwrap();

    let body: i64 = db
        .client
        .query_one(
            "SELECT COUNT(*) FROM artifact_body_pg WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(body, 0, "body must be unreachable after rollback");
    let catalog: i64 = db
        .client
        .query_one(
            "SELECT COUNT(*) FROM artifact_catalog WHERE kind = $1 AND digest = $2",
            &[&kind_str, &digest_str],
        )
        .unwrap()
        .get(0);
    assert_eq!(catalog, 0, "catalog row must be unreachable after rollback");
}

fn base_event(
    workspace: WorkspaceId,
    sequence: u64,
    ordinal: u64,
    effect: ContentDigest,
    event_id: &str,
) -> OutboxEnqueueV1 {
    OutboxEnqueueV1 {
        event_id: event_id.to_owned(),
        workspace_id: workspace,
        workspace_transaction_sequence: sequence,
        ordinal,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: "preview/releases".to_owned(),
        stream_sequence: 7,
        effect_digest: effect,
        payload_digest: None,
        artifact_reference: None,
        destination_configuration_version: 9,
        destination_configuration_digest: ContentDigest::blake3([0x33; 32]),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: "2026-08-03T14:00:00Z".parse().unwrap(),
    }
}

#[test]
fn outbox_enqueue_rejects_both_uniqueness_keys() {
    let mut db = TestDb::new(&[OUTBOX_EVENTS_DDL]);
    let workspace = workspace();
    let effect = ContentDigest::blake3([0x11; 32]);

    // first enqueue succeeds
    let first = base_event(workspace, 1, 1, effect, EVENT_ID);
    let mut tx = db.client.transaction().unwrap();
    enqueue(&mut tx, &first).unwrap();
    tx.commit().unwrap();

    // logical-event key collision: same effect key, different ordinal key
    let second = base_event(workspace, 2, 2, effect, EVENT_ID_2);
    let mut tx = db.client.transaction().unwrap();
    let error = enqueue(&mut tx, &second).unwrap_err();
    assert!(
        matches!(error, PgError::Transaction(_)),
        "logical-event key collision must be a transaction error: {error}"
    );
    assert!(
        error.to_string().contains("event_v_key"),
        "expected the logical-event UNIQUE constraint, got: {error}"
    );
    tx.rollback().unwrap();

    // ordinal key collision: same ordinal key, different effect key
    let third = base_event(
        workspace,
        1,
        1,
        ContentDigest::blake3([0x99; 32]),
        EVENT_ID_3,
    );
    let mut tx = db.client.transaction().unwrap();
    let error = enqueue(&mut tx, &third).unwrap_err();
    assert!(
        matches!(error, PgError::Transaction(_)),
        "ordinal key collision must be a transaction error: {error}"
    );
    assert!(
        error.to_string().contains("sequence_o_key"),
        "expected the ordinal UNIQUE constraint, got: {error}"
    );
    tx.rollback().unwrap();
}

#[test]
fn outbox_enqueue_round_trips_all_fields_exactly() {
    let mut db = TestDb::new(&[OUTBOX_EVENTS_DDL]);
    let workspace = workspace();
    let correlation: CorrelationId = CORRELATION.parse().expect("valid Correlation UUIDv7");
    let artifact_ref = ArtifactKeyV1 {
        kind: ArtifactKind::EditionV1,
        blake3_digest: artifact_digest(ArtifactKind::EditionV1, br#"{"manifest":true}"#),
    };
    let committed = "2026-08-03T14:00:00Z".parse::<Timestamp>().unwrap();

    let event = OutboxEnqueueV1 {
        event_id: EVENT_ID.to_owned(),
        workspace_id: workspace,
        workspace_transaction_sequence: 42,
        ordinal: 3,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: "preview/releases".to_owned(),
        stream_sequence: 7,
        effect_digest: ContentDigest::blake3([0x11; 32]),
        payload_digest: Some(ContentDigest::blake3([0x22; 32])),
        artifact_reference: Some(artifact_ref),
        destination_configuration_version: 9,
        destination_configuration_digest: ContentDigest::blake3([0x33; 32]),
        correlation_id: Some(correlation),
        causation_id: Some(CAUSATION.to_owned()),
        committed_creation_time: committed,
    };

    let mut tx = db.client.transaction().unwrap();
    enqueue(&mut tx, &event).unwrap();
    tx.commit().unwrap();

    let row = db
        .client
        .query_one(
            "SELECT event_id, workspace_id, workspace_transaction_sequence, ordinal,
                    event_type, event_version, ordering_key, stream_sequence,
                    effect_digest, payload_digest, artifact_kind, artifact_digest,
                    destination_configuration_version, destination_configuration_digest,
                    correlation_id, causation_id, committed_creation_time
             FROM outbox_events WHERE event_id = $1",
            &[&event.event_id],
        )
        .unwrap();

    assert_eq!(row.get::<_, String>(0), event.event_id);
    assert_eq!(row.get::<_, String>(1), event.workspace_id.to_string());
    assert_eq!(row.get::<_, i64>(2), 42);
    assert_eq!(row.get::<_, i64>(3), 3);
    assert_eq!(row.get::<_, String>(4), event.event_type);
    assert_eq!(row.get::<_, String>(5), event.event_version);
    assert_eq!(row.get::<_, String>(6), event.ordering_key);
    assert_eq!(row.get::<_, i64>(7), 7);
    assert_eq!(row.get::<_, String>(8), event.effect_digest.to_string());
    assert_eq!(
        row.get::<_, Option<String>>(9),
        event.payload_digest.map(|d| d.to_string())
    );
    assert_eq!(
        row.get::<_, Option<String>>(10),
        event
            .artifact_reference
            .as_ref()
            .map(|k| k.kind.wire_name().to_owned())
    );
    assert_eq!(
        row.get::<_, Option<String>>(11),
        event
            .artifact_reference
            .as_ref()
            .map(|k| k.blake3_digest.to_string())
    );
    assert_eq!(row.get::<_, i64>(12), 9);
    assert_eq!(
        row.get::<_, String>(13),
        event.destination_configuration_digest.to_string()
    );
    assert_eq!(
        row.get::<_, Option<String>>(14),
        event.correlation_id.map(|c| c.to_string())
    );
    assert_eq!(row.get::<_, Option<String>>(15), event.causation_id);

    let stored: SystemTime = row.get(16);
    let stored_nanos = i128::try_from(
        stored
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("stored timestamp is after the Unix epoch")
            .as_nanos(),
    )
    .expect("stored timestamp nanos fit in i128");
    assert_eq!(
        stored_nanos,
        event.committed_creation_time.unix_timestamp_nanos()
    );
}

#[test]
fn initial_delivery_is_atomic_pending_and_database_scheduled() {
    let mut db = TestDb::new(&[
        OUTBOX_EVENTS_DDL,
        proof_pg::migration::DELIVERY_STATE_V3_DDL,
    ]);
    let event = base_event(
        workspace(),
        1,
        0,
        ContentDigest::blake3([0x55; 32]),
        EVENT_ID,
    );

    let mut tx = db.client.transaction().unwrap();
    enqueue_initial_delivery(&mut tx, &event, DELIVERY_ID).unwrap();
    let row = tx
        .query_one(
            "SELECT generation, status, next_attempt_at IS NOT NULL,
                    attempts_in_generation, lease_token_hash, lease_expires_at,
                    receipt_digest, next_attempt_at = generation_started_at,
                    generation_started_at = committed_at
             FROM delivery_state WHERE event_id = $1 AND delivery_id = $2",
            &[&EVENT_ID, &DELIVERY_ID],
        )
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, String>(1), "pending");
    assert!(row.get::<_, bool>(2));
    assert_eq!(row.get::<_, i64>(3), 0);
    assert_eq!(row.get::<_, Option<String>>(4), None);
    assert_eq!(row.get::<_, Option<SystemTime>>(5), None);
    assert_eq!(row.get::<_, Option<String>>(6), None);
    assert!(row.get::<_, bool>(7));
    assert!(row.get::<_, bool>(8));
    tx.rollback().unwrap();

    assert_eq!(
        db.client
            .query_one("SELECT COUNT(*) FROM outbox_events", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        db.client
            .query_one("SELECT COUNT(*) FROM delivery_state", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
}
