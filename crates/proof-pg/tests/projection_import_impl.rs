//! Integration tests for the `PostgreSQL` projection rebuild and the verified
//! SQLite-to-PostgreSQL import.
//!
//! Every test isolates itself in a dedicated `PostgreSQL` schema and drops it at
//! the end so parallel agents never collide.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use proof_application::{
    AddChangeSetEditsCommand, ApprovalName, ApproveChangeSetCommand, ChangeSetEdit, ChangeSetId,
    ChangeSetIntent, CommitChangeSetCommand, CreateChangeSetCommand, CreateEditionCommand,
    CreateEnvironmentCommand, EditId, EnvironmentId, IdempotencyKey, InitializeWorkspaceCommand,
    ObjectCreateEdit, ObjectId, PromoteReleaseCommand, ProofId, ReleaseId, SchemaCreateEdit,
    SchemaId, SchemaVersion, SubmitChangeSetCommand, Timestamp, add_changeset_edits,
    approve_changeset, commit_changeset, create_changeset, create_edition, create_environment,
    initialize_workspace, promote_release, submit_changeset, validate_changeset, workspace_status,
};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_domain::{ArtifactKind, ContentDigest, WorkspaceId};
use proof_local::LocalWorkspace;
use proof_pg::{
    PgConfig,
    import::{ImportReport, SqliteToPostgresImporter},
    projection::{atomic_swap_active_generation, rebuild_into_new_generation},
    wiring::PgRuntime,
};
use serde_json::Value;

const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";
const PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000020";
const CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000030";
const SCHEMA_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000050";
const OBJECT_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000052";
const OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000080";
const EDITION_ID: &str = "019c0000-0000-7000-8000-000000000060";
const RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000c0";
const PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000c4";
const ENVIRONMENT_ID: &str = "preview";
const DRAFT_KEY: &str = "019c0000-0000-7000-8000-000000000040";
const ADD_KEY: &str = "019c0000-0000-7000-8000-000000000041";
const COMMIT_KEY: &str = "019c0000-0000-7000-8000-000000000043";
const EDITION_KEY: &str = "019c0000-0000-7000-8000-000000000070";
const ENVIRONMENT_KEY: &str = "019c0000-0000-7000-8000-0000000000b0";
const RELEASE_KEY: &str = "019c0000-0000-7000-8000-0000000000c8";
const CREATED_AT: &str = "2026-08-03T14:00:00Z";

static NEXT_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_SCHEMA: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(prefix: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("proof-pg-{prefix}-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One isolated `PostgreSQL` test context: a dedicated schema plus the runtime.
struct PgTestCtx {
    runtime: PgRuntime,
    schema: String,
}

impl PgTestCtx {
    fn new(workspace_id: WorkspaceId) -> Self {
        let dsn =
            std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned());
        let runtime = PgRuntime::connect(PgConfig::new(dsn, workspace_id, Duration::from_secs(30)))
            .expect("connect to PostgreSQL");
        let schema = format!(
            "proof_projection_import_{}_{}",
            std::process::id(),
            NEXT_SCHEMA.fetch_add(1, Ordering::Relaxed)
        );
        let mut ctx = Self { runtime, schema };
        ctx.runtime
            .client_mut()
            .batch_execute(&format!("CREATE SCHEMA {}", ctx.schema))
            .expect("create test schema");
        ctx.runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO {}", ctx.schema))
            .expect("set test search path");
        ctx
    }

    fn client(&mut self) -> &mut postgres::Client {
        self.runtime.client_mut()
    }

    fn import(&mut self, source: &LocalWorkspace) -> ImportReport {
        SqliteToPostgresImporter::new()
            .import(source, &mut self.runtime)
            .expect("import")
    }
}

impl Drop for PgTestCtx {
    fn drop(&mut self) {
        let _ = self
            .runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
    }
}

fn initialized_workspace(directory: &TestDir) -> LocalWorkspace {
    let workspace = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &workspace,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap();
    workspace
}

/// Builds a released v1 Workspace: one constrained Schema, one Object, one
/// Edition, one Environment, and one promoted Release.
fn released_workspace(directory: &TestDir) -> LocalWorkspace {
    let workspace = initialized_workspace(directory);

    create_changeset(
        &workspace,
        CreateChangeSetCommand {
            changeset_id: CHANGESET_ID.parse::<ChangeSetId>().unwrap(),
            intent: ChangeSetIntent::new("Define an article and Object").unwrap(),
            requested_base_state: None,
            idempotency_key: DRAFT_KEY.parse::<IdempotencyKey>().unwrap(),
            created_at: CREATED_AT.parse::<Timestamp>().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        &workspace,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                schema_edit(SCHEMA_EDIT_ID, "article"),
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "Projection proof"}),
                ),
            ],
            idempotency_key: ADD_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let validated = validate_changeset(&workspace, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(validated.valid);
    submit_changeset(
        &workspace,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &workspace,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        &workspace,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &workspace,
        CreateEditionCommand {
            edition_id: EDITION_ID.parse().unwrap(),
            idempotency_key: EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        &workspace,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: ENVIRONMENT_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        &workspace,
        PromoteReleaseCommand {
            release_id: RELEASE_ID.parse::<ReleaseId>().unwrap(),
            proof_id: PROOF_ID.parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: EDITION_ID.parse().unwrap(),
            idempotency_key: RELEASE_KEY.parse().unwrap(),
            released_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    workspace
}

fn schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "title": { "type": "string" },
        },
        "required": ["title"],
        "type": "object",
    });
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn object_edit(edit_id: &str, object_id: &str, schema_id: &str, content: &Value) -> ChangeSetEdit {
    let object_id = object_id.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(schema_id).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical = canonicalize(content).unwrap();
    let object_digest =
        object_revision_digest(object_id, &schema_id, schema_version, content).unwrap();
    ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        object_id,
        schema_id,
        schema_version,
        canonical_content: canonical.as_str().to_owned(),
        object_digest,
    })
}

/// Reads the source authority head `(sequence, record_digest)` from `SQLite`.
fn source_authority_head(connection: &rusqlite::Connection) -> (u64, ContentDigest) {
    let (sequence, digest): (i64, String) = connection
        .query_row(
            "SELECT authority_sequence, record_digest FROM authority_records
             ORDER BY authority_sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (u64::try_from(sequence).unwrap(), digest.parse().unwrap())
}

/// Reads the source Known State `(sequence, state_digest)` from `SQLite`.
fn source_known_state(connection: &rusqlite::Connection) -> (u64, ContentDigest) {
    let (sequence, digest): (i64, String) = connection
        .query_row(
            "SELECT authoritative_sequence, state_digest FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    (u64::try_from(sequence).unwrap(), digest.parse().unwrap())
}

fn count(client: &mut postgres::Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .unwrap()
        .get(0)
}

fn active_generation(client: &mut postgres::Client) -> i64 {
    client
        .query_one(
            "SELECT generation FROM projection_generations WHERE active = TRUE",
            &[],
        )
        .unwrap()
        .get(0)
}

fn pg_state_digest(client: &mut postgres::Client) -> ContentDigest {
    let digest: String = client
        .query_one(
            "SELECT state_digest FROM projection_generations WHERE active = TRUE",
            &[],
        )
        .unwrap()
        .get(0);
    digest.parse().unwrap()
}

#[test]
fn import_matches_source_heads_known_state_and_counts() {
    let directory = TestDir::new("import");
    let source = released_workspace(&directory);
    let connection = source.open_database().unwrap();
    let (source_authority_sequence, source_authority_digest) = source_authority_head(&connection);
    let (source_sequence, source_state_digest) = source_known_state(&connection);
    assert_eq!(source_sequence, 2); // one Schema plus one Object

    let mut ctx = PgTestCtx::new(WORKSPACE_ID.parse().unwrap());
    let report = ctx.import(&source);

    assert!(report.authority_heads_match);
    assert!(report.known_state_matches);
    assert!(report.cutover_atomic);
    assert_eq!(report.facts_consumed, 4); // schema + object + release + Known State head
    assert_eq!(report.projections_rebuilt, 1);

    // Authority head matches the source.
    let pg_head_row = ctx
        .client()
        .query_one(
            "SELECT authority_sequence, record_digest FROM authority_records
             ORDER BY authority_sequence DESC LIMIT 1",
            &[],
        )
        .unwrap();
    let pg_head_sequence: i64 = pg_head_row.get(0);
    let pg_head_digest: String = pg_head_row.get(1);
    assert_eq!(
        pg_head_sequence,
        i64::try_from(source_authority_sequence).unwrap()
    );
    assert_eq!(pg_head_digest, source_authority_digest.to_string());

    // Known State digest matches.
    assert_eq!(pg_state_digest(ctx.client()), source_state_digest);

    // Counts match: one schema, one object, zero renditions, one release,
    // plus the Known State head system fact.
    assert_eq!(count(ctx.client(), "facts"), 4);
    let generation = active_generation(ctx.client());
    assert_eq!(
        (
            count_where(ctx.client(), "projection_schemas", generation),
            count_where(ctx.client(), "projection_objects", generation),
            count_where(ctx.client(), "projection_renditions", generation),
            count_where(ctx.client(), "projection_releases", generation),
        ),
        (1, 1, 0, 1)
    );
}

fn count_where(client: &mut postgres::Client, table: &str, generation: i64) -> i64 {
    client
        .query_one(
            &format!("SELECT COUNT(*) FROM {table} WHERE generation = $1"),
            &[&generation],
        )
        .unwrap()
        .get(0)
}

#[test]
fn tampered_sqlite_artifact_fails_closed() {
    let directory = TestDir::new("tamper");
    let source = released_workspace(&directory);

    // Checkpoint the WAL into the main database file so the byte flip below
    // lands in the committed, verified Object content.
    {
        let connection = source.open_database().unwrap();
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // Copy the whole Workspace, then flip one byte in the copied database file
    // inside the verified Object content ("Projection proof" -> "Qrojection proof").
    let copy = TestDir::new("tamper-copy");
    copy_directory(directory.path(), copy.path());
    let db_path = copy.path().join(".proof/state/proof.db");
    let mut bytes = fs::read(&db_path).unwrap();
    let needle = b"Projection proof";
    // The Object revision table is created after the edit table, so its page
    // lands later in the file; flip the last occurrence to hit the committed
    // Object content that the importer re-verifies.
    let offset = bytes
        .windows(needle.len())
        .rposition(|window| window == needle)
        .expect("Object content bytes must be present in the database file");
    bytes[offset] = b'Q';
    fs::write(&db_path, &bytes).unwrap();

    let tampered = LocalWorkspace::new(copy.path()).unwrap();

    // Confirm the flip actually landed in the committed Object content.
    {
        let connection = tampered.open_database().unwrap();
        let content: String = connection
            .query_row(
                "SELECT content_json FROM object_revisions WHERE object_id = ?1",
                [OBJECT_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            content.contains("Qrojection"),
            "the byte flip did not land in the committed Object content: {content}"
        );
    }

    // The tampered Workspace must fail its own verified status read.
    assert!(
        workspace_status(&tampered).is_err(),
        "the tampered Object content must fail source-side verification"
    );

    let mut ctx = PgTestCtx::new(WORKSPACE_ID.parse().unwrap());
    let result = SqliteToPostgresImporter::new().import(&tampered, &mut ctx.runtime);
    assert!(
        result.is_err(),
        "a tampered Object artifact must make the import fail closed"
    );
}

#[test]
fn projection_rebuild_dry_run_then_swap_flips_exactly_one_pointer() {
    let directory = TestDir::new("rebuild");
    let source = released_workspace(&directory);
    let mut ctx = PgTestCtx::new(WORKSPACE_ID.parse().unwrap());
    ctx.import(&source);

    // The import leaves generation one active.
    assert_eq!(active_generation(ctx.client()), 1);

    // A dry-run rebuild commits an inactive next generation without changing
    // the active pointer.
    let dry_run = rebuild_into_new_generation(ctx.client()).unwrap();
    assert_eq!(dry_run.generation, 2);
    assert_eq!(dry_run.counts.objects, 1);
    assert_eq!(dry_run.counts.schemas, 1);
    assert_eq!(dry_run.counts.releases, 1);
    assert_eq!(dry_run.counts.renditions, 0);
    assert_eq!(
        active_generation(ctx.client()),
        1,
        "dry run must not change the active generation"
    );

    // A successful rebuild swaps exactly one pointer.
    let next = rebuild_into_new_generation(ctx.client()).unwrap();
    atomic_swap_active_generation(ctx.client(), &next).unwrap();
    assert_eq!(
        active_generation(ctx.client()),
        i64::try_from(next.generation).unwrap()
    );
    assert_eq!(
        count(ctx.client(), "projection_generations"),
        3,
        "two inactive generations plus one active generation"
    );
}

#[test]
fn rebuild_never_touches_facts_idempotency_or_outbox() {
    let directory = TestDir::new("rebuild-immutability");
    let source = released_workspace(&directory);
    let mut ctx = PgTestCtx::new(WORKSPACE_ID.parse().unwrap());
    ctx.import(&source);

    // Seed one idempotency row and one outbox row to prove rebuild never
    // regenerates or deletes them.
    seed_idempotency_and_outbox(ctx.client());

    let facts_before = count(ctx.client(), "facts");
    let idempotency_before = count(ctx.client(), "idempotency_keys");
    let outbox_before = count(ctx.client(), "outbox_events");

    let generation = rebuild_into_new_generation(ctx.client()).unwrap();
    atomic_swap_active_generation(ctx.client(), &generation).unwrap();

    assert_eq!(count(ctx.client(), "facts"), facts_before);
    assert_eq!(count(ctx.client(), "idempotency_keys"), idempotency_before);
    assert_eq!(count(ctx.client(), "outbox_events"), outbox_before);
    assert_eq!(idempotency_before, 1);
    assert_eq!(outbox_before, 1);
}

fn seed_idempotency_and_outbox(client: &mut postgres::Client) {
    let principal = "019c0000-0000-7000-8000-0000000000e1";
    let digest = format!("blake3:{}", "ab".repeat(32));
    client
        .execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, key_kind,
                 result_digest, replay_count, committed_at
             ) VALUES ($1, 'release.create', 'v1', $2, $3, $4, NULL, 'required_uuid_v7', $5, 0, now())",
            &[
                &WORKSPACE_ID,
                &digest.as_str(),
                &principal,
                &principal,
                &digest.as_str(),
            ],
        )
        .unwrap();
    client
        .execute(
            "INSERT INTO outbox_events (
                 event_id, workspace_id, workspace_transaction_sequence, ordinal, event_type,
                 event_version, ordering_key, stream_sequence, effect_digest, payload_digest,
                 artifact_kind, artifact_digest, destination_configuration_version,
                 destination_configuration_digest, correlation_id, causation_id,
                 committed_creation_time
             ) VALUES (
                 '019c0000-0000-7000-8000-0000000000e2', $1, 1, 1, 'preview.release', 'v1',
                 'preview', 1, $2, NULL, NULL, NULL, 1, $3, NULL, NULL, now()
             )",
            &[&WORKSPACE_ID, &digest.as_str(), &digest.as_str()],
        )
        .unwrap();
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}
