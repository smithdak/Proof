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
    MigrationPhase, MigrationScriptV1, read_head, run_expand_backfill_verify_cutover, verify_head,
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
