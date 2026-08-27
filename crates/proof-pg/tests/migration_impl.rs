//! Integration tests for the immutable checksummed migration ledger
//! (`proof_pg::migration`) and the logged-table DDL (`proof_pg::schema`).
//!
//! Every test creates its own dedicated schema, applies the base schema inside
//! it, and drops it with `DROP SCHEMA ... CASCADE` on cleanup, so parallel
//! agents never collide. The database itself is never created or dropped.

use std::sync::atomic::{AtomicU64, Ordering};

use postgres::Client;
use proof_pg::PgError;
use proof_pg::migration::{
    MigrationPhase, MigrationScriptV1, application_idempotency_migration_v4, read_head,
    run_expand_backfill_verify_cutover, verify_head, workspace_global_idempotency_migration_v5,
};
use proof_pg::schema::ALL_TABLE_DDL;

/// Resolves the connection string exactly like the crate does.
fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

/// Connects to the local development instance, failing with an actionable
/// message rather than silently skipping.
fn connect() -> Client {
    let dsn = dsn();
    Client::connect(&dsn, postgres::NoTls).unwrap_or_else(|error| {
        panic!(
            "cannot connect to PostgreSQL at {dsn} ({error}); start it with scripts/dev-pg.sh or set {0}",
            proof_pg::DSN_ENV
        )
    })
}

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A dedicated test schema with the base logged tables applied, dropped on
/// scope exit.
struct SchemaGuard {
    name: String,
    client: Client,
}

impl SchemaGuard {
    fn new(label: &str) -> Self {
        let sequence = SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!("p0010_{label}_{}_{sequence}", std::process::id());

        let mut client = connect();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{name}\""))
            .unwrap();
        client
            .batch_execute(&format!("SET search_path TO \"{name}\""))
            .unwrap();
        client.batch_execute(&ALL_TABLE_DDL.join("\n")).unwrap();

        Self { name, client }
    }

    fn client(&mut self) -> &mut Client {
        &mut self.client
    }

    fn schema_name(&self) -> &str {
        &self.name
    }
}

impl Drop for SchemaGuard {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.name));
    }
}

/// Connects a fresh client and points its `search_path` at an existing schema.
fn connect_to_schema(schema: &str) -> Client {
    let mut client = connect();
    client
        .batch_execute(&format!("SET search_path TO \"{schema}\""))
        .unwrap();
    client
}

/// A migration that runs as a fresh, never-applied script.
fn migration_error_message(error: PgError) -> String {
    match error {
        PgError::Migration(message) => message,
        other => panic!("expected PgError::Migration, got {other:?}"),
    }
}

fn prepare_v4_idempotency_schema(schema: &mut SchemaGuard) {
    schema
        .client()
        .batch_execute(
            "DROP TABLE idempotency_keys;
             CREATE TABLE idempotency_keys (
                 workspace_id TEXT NOT NULL,
                 operation TEXT NOT NULL,
                 operation_version TEXT NOT NULL,
                 normalized_input_digest TEXT NOT NULL,
                 requesting_principal TEXT NOT NULL,
                 operating_principal TEXT NOT NULL,
                 delegation_id TEXT,
                 application_key TEXT,
                 key_kind TEXT NOT NULL,
                 result_digest TEXT NOT NULL,
                 replay_count BIGINT NOT NULL DEFAULT 0,
                 committed_at TIMESTAMPTZ NOT NULL,
                 PRIMARY KEY (
                     workspace_id, operation, operation_version, normalized_input_digest,
                     requesting_principal, operating_principal
                 )
             );
             CREATE UNIQUE INDEX idempotency_application_key_unique
                 ON idempotency_keys (
                     workspace_id, operation, operation_version,
                     requesting_principal, operating_principal, application_key
                 );",
        )
        .unwrap();

    let v4 = application_idempotency_migration_v4();
    schema
        .client()
        .execute(
            "INSERT INTO migration_head (
                 singleton, version, name, script_digest, phase,
                 actor, tool_version, started_at, verified_at
             ) VALUES (1, 4, $1, $2, 'verified', 'test', 'test', now(), now())",
            &[&v4.name, &v4.digest.to_string()],
        )
        .unwrap();
    schema
        .client()
        .execute(
            "INSERT INTO workspace_write_head (
                 singleton, workspace_id, migration_version,
                 transaction_sequence, authority_sequence, content_sequence, release_sequence,
                 authority_head_digest, authority_head_sequence,
                 content_head_digest, release_head_digest,
                 policy_head_digest, configuration_head_digest
             ) VALUES (1, $1, 4, 0, 0, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL)",
            &[&"019c0000-0000-7000-8000-000000000001"],
        )
        .unwrap();
}

#[test]
fn clean_run_applies_all_scripts_and_verify_head_passes() {
    let mut schema = SchemaGuard::new("clean_run");

    let v1 = MigrationScriptV1::new(1, "create_first", "CREATE TABLE probe_a (id BIGINT);");
    let v2 = MigrationScriptV1::new(2, "create_second", "CREATE TABLE probe_b (id BIGINT);");

    run_expand_backfill_verify_cutover(schema.client(), &v1).unwrap();
    run_expand_backfill_verify_cutover(schema.client(), &v2).unwrap();

    verify_head(schema.client(), &v2).unwrap();

    let head = read_head(schema.client()).unwrap().expect("head present");
    assert_eq!(head.head_version, 2);
    assert_eq!(head.head_digest, v2.digest);
    assert_eq!(head.phase, MigrationPhase::Verified);

    // Both scripts' DDL actually landed.
    let count: i64 = schema
        .client()
        .query_one("SELECT COUNT(*) FROM probe_a", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    let count: i64 = schema
        .client()
        .query_one("SELECT COUNT(*) FROM probe_b", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
}

#[test]
fn rerun_is_a_no_op() {
    let mut schema = SchemaGuard::new("rerun");

    let script = MigrationScriptV1::new(
        1,
        "seed_probe",
        "CREATE TABLE seeded (n BIGINT NOT NULL); INSERT INTO seeded VALUES (1);",
    );
    run_expand_backfill_verify_cutover(schema.client(), &script).unwrap();

    // Re-running the identical script must not execute its body again.
    run_expand_backfill_verify_cutover(schema.client(), &script).unwrap();

    let count: i64 = schema
        .client()
        .query_one("SELECT COUNT(*) FROM seeded", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "re-run must not execute the script again");

    let head = read_head(schema.client()).unwrap().unwrap();
    assert_eq!(head.head_version, 1);
    assert_eq!(head.phase, MigrationPhase::Verified);
}

#[test]
fn tampered_script_triggers_checksum_mismatch() {
    let mut schema = SchemaGuard::new("tamper");

    let original_sql = "CREATE TABLE stable (id BIGINT);";
    let script = MigrationScriptV1::new(1, "stable", original_sql);
    run_expand_backfill_verify_cutover(schema.client(), &script).unwrap();

    // Flip one byte of an embedded copy of the exact script bytes.
    let mut tampered_bytes = original_sql.as_bytes().to_vec();
    tampered_bytes[0] ^= 1; // 'C' -> 'B'; still ASCII, different digest
    let tampered_sql = String::from_utf8(tampered_bytes).expect("flip keeps ASCII");
    let tampered = MigrationScriptV1::new(1, "stable", tampered_sql);
    assert_ne!(tampered.digest, script.digest);

    let error = run_expand_backfill_verify_cutover(schema.client(), &tampered).unwrap_err();
    let message = migration_error_message(error);
    assert!(
        message.contains("checksum mismatch"),
        "unexpected error: {message}"
    );

    // The tampered body was never executed.
    let head = read_head(schema.client()).unwrap().unwrap();
    assert_eq!(head.head_version, 1);
    assert_eq!(head.head_digest, script.digest);
    assert_eq!(head.phase, MigrationPhase::Verified);
}

#[test]
fn dirty_phase_blocks() {
    let mut schema = SchemaGuard::new("dirty");

    let ok = MigrationScriptV1::new(1, "ok", "CREATE TABLE ok_table (id BIGINT);");
    run_expand_backfill_verify_cutover(schema.client(), &ok).unwrap();

    // A script whose body fails records a dirty (failed) phase.
    let broken = MigrationScriptV1::new(
        2,
        "broken",
        "CREATE TABLE broken_table (id BIGINT); THIS IS NOT VALID SQL;",
    );
    let error = run_expand_backfill_verify_cutover(schema.client(), &broken).unwrap_err();
    let _ = migration_error_message(error);

    let head = read_head(schema.client()).unwrap().unwrap();
    assert_eq!(head.head_version, 2);
    assert_eq!(head.phase, MigrationPhase::Failed);

    // Re-running the same (still-broken) script now blocks on the dirty phase.
    let error = run_expand_backfill_verify_cutover(schema.client(), &broken).unwrap_err();
    let message = migration_error_message(error);
    assert!(message.contains("dirty"), "unexpected error: {message}");
}

#[test]
fn unknown_newer_version_blocks() {
    let mut schema = SchemaGuard::new("newer");

    let v1 = MigrationScriptV1::new(1, "one", "CREATE TABLE t1 (id BIGINT);");
    let v2 = MigrationScriptV1::new(2, "two", "CREATE TABLE t2 (id BIGINT);");
    run_expand_backfill_verify_cutover(schema.client(), &v1).unwrap();
    run_expand_backfill_verify_cutover(schema.client(), &v2).unwrap();

    // The head is newer than the supplied script: refuse rather than downgrade.
    let error = run_expand_backfill_verify_cutover(schema.client(), &v1).unwrap_err();
    let message = migration_error_message(error);
    assert!(message.contains("newer"), "unexpected error: {message}");
}

#[test]
fn concurrent_migrators_exactly_one_wins() {
    let mut schema = SchemaGuard::new("concurrent");

    // The script sleeps while holding the advisory lock so the second migrator
    // is guaranteed to contend, then writes exactly one probe row per execution.
    let script = MigrationScriptV1::new(
        1,
        "concurrent_probe",
        "SELECT pg_sleep(0.2);
         CREATE TABLE migration_probe (n BIGINT NOT NULL);
         INSERT INTO migration_probe VALUES (1);",
    );
    let schema_name = schema.schema_name().to_owned();

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let spawn = |script: MigrationScriptV1,
                 schema_name: String,
                 barrier: std::sync::Arc<std::sync::Barrier>| {
        std::thread::spawn(move || {
            let mut client = connect_to_schema(&schema_name);
            barrier.wait();
            run_expand_backfill_verify_cutover(&mut client, &script)
        })
    };

    let handle_a = spawn(script.clone(), schema_name.clone(), barrier.clone());
    let handle_b = spawn(script.clone(), schema_name, barrier);

    handle_a.join().unwrap().unwrap();
    handle_b.join().unwrap().unwrap();

    // Exactly one migrator executed the script body.
    let count: i64 = schema
        .client()
        .query_one("SELECT COUNT(*) FROM migration_probe", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 1, "the script body must execute exactly once");

    let head = read_head(schema.client()).unwrap().unwrap();
    assert_eq!(head.head_version, 1);
    assert_eq!(head.phase, MigrationPhase::Verified);
}

#[test]
fn script_digest_is_domain_separated_over_exact_bytes() {
    // The already-wired digest helper stays byte-exact and domain-separated.
    let exact = b"CREATE TABLE x (id BIGINT);";
    let digest = proof_pg::migration::migration_script_digest(exact);
    assert_eq!(
        digest,
        proof_remote::derive_key_digest(
            proof_pg::migration::MIGRATION_SCRIPT_DIGEST_CONTEXT,
            exact
        )
    );

    // Leading/trailing whitespace is part of the exact bytes and changes the
    // digest.
    let with_whitespace = b" CREATE TABLE x (id BIGINT);\n";
    assert_ne!(
        digest,
        proof_pg::migration::migration_script_digest(with_whitespace)
    );
}

#[test]
fn workspace_global_idempotency_cutover_advances_workspace_and_drops_scoped_index() {
    let mut schema = SchemaGuard::new("workspace_global_idempotency");
    prepare_v4_idempotency_schema(&mut schema);

    let v5 = workspace_global_idempotency_migration_v5();
    run_expand_backfill_verify_cutover(schema.client(), &v5).unwrap();

    verify_head(schema.client(), &v5).unwrap();
    let workspace_version: i32 = schema
        .client()
        .query_one(
            "SELECT migration_version FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(workspace_version, 5);

    let scoped_index: Option<String> = schema
        .client()
        .query_one(
            "SELECT to_regclass('idempotency_application_key_unique')::text",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(scoped_index, None);

    let primary_key_columns: Vec<String> = schema
        .client()
        .query_one(
            "SELECT array_agg(attribute.attname ORDER BY key.ordinality)
             FROM pg_constraint constraint_row
             CROSS JOIN LATERAL unnest(constraint_row.conkey)
                 WITH ORDINALITY AS key(attribute_number, ordinality)
             JOIN pg_attribute attribute
               ON attribute.attrelid = constraint_row.conrelid
              AND attribute.attnum = key.attribute_number
             WHERE constraint_row.conrelid = 'idempotency_keys'::regclass
               AND constraint_row.contype = 'p'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(primary_key_columns, ["workspace_id", "application_key"]);
}

#[test]
fn workspace_global_idempotency_cutover_retains_only_legacy_rows_without_result_bytes() {
    let mut schema = SchemaGuard::new("workspace_global_legacy_result");
    prepare_v4_idempotency_schema(&mut schema);
    let workspace_id = "019c0000-0000-7000-8000-000000000001";
    let principal_id = "019c0000-0000-7000-8000-000000000002";
    let digest = proof_domain::ContentDigest::blake3([0x45; 32]).to_string();
    schema
        .client()
        .execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, application_key,
                 key_kind, result_digest, replay_count, committed_at
             ) VALUES ($1, 'object.query', 'proof.dev/operation/object.query/v1',
                       $2, $3, $3, NULL, NULL, 'none', $2, 0, now())",
            &[&workspace_id, &digest, &principal_id],
        )
        .unwrap();

    run_expand_backfill_verify_cutover(
        schema.client(),
        &workspace_global_idempotency_migration_v5(),
    )
    .unwrap();

    let row = schema
        .client()
        .query_one(
            "SELECT application_key, result_body FROM idempotency_keys WHERE workspace_id = $1",
            &[&workspace_id],
        )
        .unwrap();
    let application_key: String = row.get(0);
    let result_body: Option<Vec<u8>> = row.get(1);
    assert_eq!(
        application_key,
        format!(
            "legacy:object.query:proof.dev/operation/object.query/v1:{digest}:{principal_id}:{principal_id}:none"
        )
    );
    assert_eq!(result_body, None);

    let error = schema
        .client()
        .execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, application_key,
                 key_kind, result_digest, result_body, replay_count, committed_at
             ) VALUES ($1, 'workspace-role.assign', 'proof.dev/operation/workspace-role.assign/v1',
                       $2, $3, $3, NULL, $4, 'required-uuidv7', $2, NULL, 0, now())",
            &[
                &workspace_id,
                &digest,
                &principal_id,
                &"019d0000-0000-7000-8000-000000000010",
            ],
        )
        .unwrap_err();
    assert_eq!(
        error.as_db_error().map(postgres::error::DbError::code),
        Some(&postgres::error::SqlState::CHECK_VIOLATION)
    );
}

#[test]
fn workspace_global_idempotency_cutover_rejects_unreplayable_v4_key() {
    let mut schema = SchemaGuard::new("workspace_global_unreplayable");
    prepare_v4_idempotency_schema(&mut schema);
    let digest = proof_domain::ContentDigest::blake3([0x44; 32]).to_string();
    schema
        .client()
        .execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, application_key,
                 key_kind, result_digest, replay_count, committed_at
             ) VALUES ($1, 'workspace-role.assign', 'proof.dev/operation/workspace-role.assign/v1',
                       $2, $3, $3, NULL, $4, 'required-uuidv7', $2, 0, now())",
            &[
                &"019c0000-0000-7000-8000-000000000001",
                &digest,
                &"019c0000-0000-7000-8000-000000000002",
                &"019d0000-0000-7000-8000-000000000010",
            ],
        )
        .unwrap();

    let error = run_expand_backfill_verify_cutover(
        schema.client(),
        &workspace_global_idempotency_migration_v5(),
    )
    .unwrap_err();
    let message = migration_error_message(error);
    assert!(
        message.contains("requires retained result bytes"),
        "migration must explain why exact replay cannot be preserved: {message}"
    );

    let workspace_version: i32 = schema
        .client()
        .query_one(
            "SELECT migration_version FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(workspace_version, 4);
    let head = read_head(schema.client()).unwrap().unwrap();
    assert_eq!(head.head_version, 5);
    assert_eq!(head.phase, MigrationPhase::Failed);
}
