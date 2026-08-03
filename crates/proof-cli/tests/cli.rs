use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000002";
const IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000040";

#[test]
fn status_emits_the_stable_json_envelope() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args([
            "--output",
            "json",
            "--correlation-id",
            CORRELATION_ID,
            "status",
        ])
        .output()
        .expect("proof executable should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["api_version"], "proof.dev/result/v1");
    assert_eq!(value["operation"], "status");
    assert_eq!(value["correlation_id"], CORRELATION_ID);
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["implementation_stage"], "foundation");
    assert_eq!(value["data"]["workspace_selected"], false);
    assert_eq!(value["data"]["workspace_initialized"], false);
}

#[test]
fn invalid_correlation_id_is_a_structured_input_problem() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args([
            "--output",
            "json",
            "--correlation-id",
            "not-a-uuid",
            "status",
        ])
        .output()
        .expect("proof executable should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["code"], "proof.input.schema_mismatch");
    assert_eq!(value["operation"], "status");
    assert_eq!(value["retryable"], false);
}

#[test]
fn init_creates_a_local_workspace_and_returns_structured_paths() {
    let directory = TestDirectory::new();
    let output = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--correlation-id",
            CORRELATION_ID,
            "init",
        ])
        .output()
        .expect("proof executable should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let workspace_id = value["data"]["workspace_id"].as_str().unwrap();
    let principal_id = value["data"]["principal_id"].as_str().unwrap();

    assert_eq!(value["operation"], "init");
    assert_eq!(value["correlation_id"], CORRELATION_ID);
    assert_eq!(value["meta"]["workspace_id"], workspace_id);
    assert_eq!(value["meta"]["principal_id"], principal_id);
    assert_eq!(
        value["data"]["workspace_root"],
        directory
            .path()
            .canonicalize()
            .unwrap()
            .display()
            .to_string()
    );
    assert_eq!(workspace_id.as_bytes()[14], b'7');
    assert_eq!(principal_id.as_bytes()[14], b'7');
    assert!(directory.path().join("proof.toml").is_file());
    assert!(directory.path().join(".proof/state/proof.db").is_file());
}

#[test]
fn repeated_init_returns_a_structured_conflict_without_overwrite() {
    let directory = TestDirectory::new();
    let first = proof_command(directory.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(first.status.success());
    let config_before = fs::read(directory.path().join("proof.toml")).unwrap();

    let second = proof_command(directory.path())
        .args(["--output", "json", "init"])
        .output()
        .unwrap();

    assert_eq!(second.status.code(), Some(5));
    assert!(second.stderr.is_empty());
    let problem: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(problem["code"], "proof.state.conflict");
    assert_eq!(problem["operation"], "init");
    assert_eq!(
        fs::read(directory.path().join("proof.toml")).unwrap(),
        config_before
    );
}

#[test]
fn status_verifies_an_initialized_workspace_and_known_state() {
    let directory = TestDirectory::new();
    let initialized = proof_command(directory.path())
        .args(["--output", "json", "init"])
        .output()
        .unwrap();
    let initialized: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    let workspace_id = initialized["data"]["workspace_id"].clone();
    let principal_id = initialized["data"]["principal_id"].clone();

    let status = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();

    assert!(status.status.success());
    assert!(status.stderr.is_empty());
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["data"]["workspace_selected"], true);
    assert_eq!(status["data"]["workspace_initialized"], true);
    assert_eq!(status["data"]["workspace_id"], workspace_id);
    assert_eq!(status["data"]["principal_id"], principal_id);
    assert_eq!(status["meta"]["workspace_id"], workspace_id);
    assert_eq!(status["meta"]["principal_id"], principal_id);
    assert_eq!(status["data"]["storage_schema_version"], 3);
    assert_eq!(status["data"]["authoritative_sequence"], 0);
    assert!(
        status["data"]["state_digest"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );
}

#[test]
fn status_returns_an_authentication_problem_for_a_different_local_identity() {
    let directory = TestDirectory::new();
    let initialized = proof_command(directory.path())
        .arg("init")
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let connection =
        rusqlite::Connection::open(directory.path().join(".proof/state/proof.db")).unwrap();
    connection
        .execute(
            "UPDATE principals SET identity_subject = 'uid:identity-mismatch'",
            [],
        )
        .unwrap();

    let status = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();

    assert_eq!(status.status.code(), Some(4));
    assert!(status.stderr.is_empty());
    let problem: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(problem["code"], "proof.auth.unauthenticated");
    assert_eq!(problem["operation"], "status");
    assert_eq!(problem["retryable"], false);
}

#[test]
fn changeset_create_returns_a_draft_bound_to_current_state_and_principal() {
    let directory = TestDirectory::new();
    let initialized = proof_command(directory.path())
        .args(["--output", "json", "init"])
        .output()
        .unwrap();
    let initialized: serde_json::Value = serde_json::from_slice(&initialized.stdout).unwrap();
    let workspace_id = initialized["data"]["workspace_id"].clone();
    let principal_id = initialized["data"]["principal_id"].clone();
    let status = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();

    let created = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "create",
            "--intent",
            "  Publish the launch article  ",
            "--idempotency-key",
            IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();

    assert!(created.status.success());
    assert!(created.stderr.is_empty());
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(created["operation"], "changeset.create");
    assert_eq!(created["data"]["workspace_id"], workspace_id);
    assert_eq!(created["data"]["principal_id"], principal_id);
    assert_eq!(created["meta"]["workspace_id"], workspace_id);
    assert_eq!(created["meta"]["principal_id"], principal_id);
    assert_eq!(created["data"]["intent"], "Publish the launch article");
    assert_eq!(created["data"]["status"], "draft");
    assert_eq!(created["data"]["edit_count"], 0);
    assert_eq!(created["data"]["base_authoritative_sequence"], 0);
    assert_eq!(
        created["data"]["base_state"],
        status["data"]["state_digest"]
    );
    assert_eq!(created["data"]["idempotency_key"], IDEMPOTENCY_KEY);
    assert!(
        created["data"]["created_at"]
            .as_str()
            .unwrap()
            .ends_with('Z')
    );
    assert_eq!(
        created["data"]["changeset_id"].as_str().unwrap().as_bytes()[14],
        b'7'
    );
}

#[test]
fn changeset_create_replays_identical_input_and_rejects_key_reuse() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let create = |intent: &str| {
        proof_command(directory.path())
            .args([
                "--output",
                "json",
                "changeset",
                "create",
                "--intent",
                intent,
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ])
            .output()
            .unwrap()
    };

    let first = create("Publish the launch article");
    let replay = create("Publish the launch article");
    assert!(first.status.success());
    assert!(replay.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["data"], first["data"]);

    let reused = create("Different intent");
    assert_eq!(reused.status.code(), Some(5));
    let problem: serde_json::Value = serde_json::from_slice(&reused.stdout).unwrap();
    assert_eq!(problem["code"], "proof.idempotency.key_reused");
}

#[test]
fn changeset_create_rejects_stale_base_and_empty_intent_without_a_draft() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );

    let stale = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "create",
            "--intent",
            "Publish the launch article",
            "--base-state",
            &format!("blake3:{}", "00".repeat(32)),
        ])
        .output()
        .unwrap();
    assert_eq!(stale.status.code(), Some(5));
    let problem: serde_json::Value = serde_json::from_slice(&stale.stdout).unwrap();
    assert_eq!(problem["code"], "proof.state.conflict");

    let empty = proof_command(directory.path())
        .args(["--output", "json", "changeset", "create", "--intent", "   "])
        .output()
        .unwrap();
    assert_eq!(empty.status.code(), Some(2));
    let problem: serde_json::Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(problem["code"], "proof.input.schema_mismatch");

    let connection =
        rusqlite::Connection::open(directory.path().join(".proof/state/proof.db")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changesets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn changeset_add_appends_ordered_schema_edits_and_replays_identically() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let created = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "create",
            "--intent",
            "Define launch Schemas",
        ])
        .output()
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let changeset_id = created["data"]["changeset_id"].as_str().unwrap();
    let edit_path = directory.path().join("edits.ndjson");
    fs::write(
        &edit_path,
        concat!(
            "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"article\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}}\n",
            "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"cta\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}}\n"
        ),
    )
    .unwrap();
    let run_add = || {
        proof_command(directory.path())
            .args([
                "--output",
                "json",
                "changeset",
                "add",
                changeset_id,
                "--file",
                edit_path.to_str().unwrap(),
                "--idempotency-key",
                IDEMPOTENCY_KEY,
            ])
            .output()
            .unwrap()
    };

    let first = run_add();
    let replay = run_add();
    assert!(first.status.success());
    assert!(replay.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(first["operation"], "changeset.add");
    assert_eq!(first["data"]["first_ordinal"], 1);
    assert_eq!(first["data"]["added_count"], 2);
    assert_eq!(first["data"]["total_edit_count"], 2);
    assert_eq!(first["data"]["idempotency_key"], IDEMPOTENCY_KEY);
    assert_eq!(first["data"]["edit_ids"].as_array().unwrap().len(), 2);
    assert_eq!(replay["data"], first["data"]);

    let connection =
        rusqlite::Connection::open(directory.path().join(".proof/state/proof.db")).unwrap();
    let targets: String = connection
        .query_row(
            "SELECT group_concat(schema_id, ',')
             FROM (SELECT schema_id FROM changeset_edits ORDER BY ordinal)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(targets, "article,cta");
}

#[test]
fn changeset_add_rejects_invalid_typed_input_without_partial_append() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let created = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "create",
            "--intent",
            "Define Schema",
        ])
        .output()
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let changeset_id = created["data"]["changeset_id"].as_str().unwrap();
    let edit_path = directory.path().join("invalid.ndjson");
    fs::write(
        &edit_path,
        concat!(
            "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"article\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}}\n",
            "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"Invalid ID\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\"}}\n"
        ),
    )
    .unwrap();

    let output = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "add",
            changeset_id,
            "--file",
            edit_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.input.schema_mismatch");
    let connection =
        rusqlite::Connection::open(directory.path().join(".proof/state/proof.db")).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_edits", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn status_rejects_partial_workspace_state() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join(".proof")).unwrap();

    let status = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();

    assert_eq!(status.status.code(), Some(8));
    assert!(status.stderr.is_empty());
    let problem: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(problem["code"], "proof.evidence.incomplete");
    assert_eq!(problem["operation"], "status");
}

#[test]
fn status_human_output_is_a_projection_of_status_data() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .arg("status")
        .output()
        .expect("proof executable should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Proof 0.1.0"));
    assert!(stdout.contains("implementation: foundation"));
    assert!(stdout.contains("workspace selected: false"));
}

fn proof_command(current_directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof"));
    command.current_dir(current_directory);
    command
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("proof-cli-test-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
