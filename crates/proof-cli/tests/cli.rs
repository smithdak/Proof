use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use proof_application::{
    DelegatedAction, DelegationConstraints, DelegationScope, GrantDelegationCommand, Timestamp,
    grant_delegation,
};
use proof_attestation::{
    Ed25519SigningProvider, InTotoStatement, InTotoSubject, sign_release_statement,
};
use proof_local::LocalWorkspace;

const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000002";
const IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000040";
const COMMIT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000043";
const EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000070";
const OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000080";
const ENVIRONMENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000081";
const RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000082";
const SECOND_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000083";
const ROLLBACK_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000084";
const AGENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000085";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000086";
const DELEGATION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000087";
const CONTEXT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000088";
const UNKNOWN_CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000099";
const LOCALIZED_COMMIT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000100";
const LOCALIZED_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000101";

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
    assert_eq!(value["data"]["implementation_stage"], "local-proof-loop");
    assert_eq!(value["data"]["workspace_selected"], false);
    assert_eq!(value["data"]["workspace_initialized"], false);
}

#[test]
fn explicit_authority_is_rejected_when_the_operation_cannot_honor_it() {
    let directory = TestDirectory::new();
    let output = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            "019c0000-0000-7000-8000-000000000001",
            "init",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.auth.denied");
    assert_eq!(problem["operation"], "init");
}

#[test]
fn status_rejects_a_partial_delegated_authority_selection() {
    let directory = TestDirectory::new();
    let output = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            "019c0000-0000-7000-8000-000000000001",
            "status",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.input.schema_mismatch");
    assert_eq!(problem["operation"], "status");
}

#[test]
fn delegated_query_and_context_reject_partial_authority_before_storage_access() {
    let directory = TestDirectory::new();
    for arguments in [
        vec![
            "--output",
            "json",
            "--principal",
            "019c0000-0000-7000-8000-000000000001",
            "object",
            "query",
            "--environment",
            "preview",
            "--object-id",
            OBJECT_ID,
        ],
        vec![
            "--output",
            "json",
            "--principal",
            "019c0000-0000-7000-8000-000000000001",
            "context",
            "get",
            "019c0000-0000-7000-8000-000000000090",
        ],
    ] {
        let output = proof_command(directory.path())
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(problem["code"], "proof.input.schema_mismatch");
    }
}

#[test]
fn agent_and_delegation_commands_project_immutable_grant_and_revocation_evidence() {
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
            "principal",
            "create-agent",
            "--display-name",
            "Release reader",
            "--idempotency-key",
            AGENT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(created.status.success());
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let principal_id = created["data"]["principal_id"].as_str().unwrap();
    assert_eq!(created["data"]["principal_type"], "agent");
    assert_eq!(created["data"]["display_name"], "Release reader");

    let not_before = timestamp_after_seconds(60);
    let expires_at = timestamp_after_seconds(120);
    let granted = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "delegation",
            "grant",
            "--recipient",
            principal_id,
            "--action",
            "workspace:status",
            "--max-objects",
            "1",
            "--max-context-bytes",
            "1024",
            "--not-before",
            &not_before,
            "--expires-at",
            &expires_at,
            "--idempotency-key",
            DELEGATION_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(
        granted.status.success(),
        "{}",
        String::from_utf8_lossy(&granted.stderr)
    );
    let granted: serde_json::Value = serde_json::from_slice(&granted.stdout).unwrap();
    let delegation_id = granted["data"]["delegation_id"].as_str().unwrap();
    assert_eq!(granted["data"]["recipient_principal_id"], principal_id);
    assert_eq!(
        granted["data"]["actions"],
        serde_json::json!(["workspace:status"])
    );
    assert_eq!(granted["data"]["constraints"]["allow_subdelegation"], false);

    let pending = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "delegation",
            "verify",
            delegation_id,
            "--operating-principal",
            principal_id,
            "--action",
            "workspace:status",
        ])
        .output()
        .unwrap();
    assert_eq!(pending.status.code(), Some(4));
    let pending: serde_json::Value = serde_json::from_slice(&pending.stdout).unwrap();
    assert_eq!(pending["code"], "proof.delegation.not_yet_valid");

    let revoked = proof_command(directory.path())
        .args(["--output", "json", "delegation", "revoke", delegation_id])
        .output()
        .unwrap();
    assert!(revoked.status.success());
    let revoked: serde_json::Value = serde_json::from_slice(&revoked.stdout).unwrap();
    assert!(revoked["data"]["revoked_at"].is_string());

    let fetched = proof_command(directory.path())
        .args(["--output", "json", "delegation", "get", delegation_id])
        .output()
        .unwrap();
    assert!(fetched.status.success());
    let fetched: serde_json::Value = serde_json::from_slice(&fetched.stdout).unwrap();
    assert_eq!(fetched["data"]["revoked_at"], revoked["data"]["revoked_at"]);
    assert_eq!(
        fetched["data"]["delegation_digest"],
        granted["data"]["delegation_digest"]
    );
}

#[test]
fn offline_verify_requires_explicit_digest_and_key_trust_without_policy_overclaim() {
    let directory = TestDirectory::new();
    let signer = Ed25519SigningProvider::from_secret_bytes(&[7_u8; 32]);
    let statement = InTotoStatement::release(
        vec![InTotoSubject {
            name: "edition/019c0000-0000-7000-8000-000000000070".to_owned(),
            digest: BTreeMap::from([("blake3".to_owned(), "0".repeat(64))]),
        }],
        serde_json::json!({ "release_id": "019c0000-0000-7000-8000-000000000071" }),
    );
    let signed_envelope = sign_release_statement(&statement, &signer).unwrap();
    let envelope = directory.path().join("release.dsse.json");
    fs::write(&envelope, &signed_envelope.envelope_json).unwrap();

    let output = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "verify",
            "--file",
            envelope.to_str().unwrap(),
            "--trusted-key-id",
            &signed_envelope.key_id,
            "--expected-envelope-digest",
            &signed_envelope.envelope_digest.to_string(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["operation"], "proof.verify");
    assert_eq!(value["data"]["signature_valid"], true);
    assert_eq!(value["data"]["digest_valid"], true);
    assert_eq!(value["data"]["canonical_envelope"], true);
    assert_eq!(value["data"]["workspace_evidence_verified"], false);
    assert_eq!(value["data"]["workspace_policy_verified"], false);
    assert_eq!(value["data"]["key_id"], signed_envelope.key_id);

    let digest_mismatch = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "verify",
            "--file",
            envelope.to_str().unwrap(),
            "--trusted-key-id",
            &signed_envelope.key_id,
            "--expected-envelope-digest",
            &format!("blake3:{}", "0".repeat(64)),
        ])
        .output()
        .unwrap();
    assert_eq!(digest_mismatch.status.code(), Some(8));
    let problem: serde_json::Value = serde_json::from_slice(&digest_mismatch.stdout).unwrap();
    assert_eq!(problem["code"], "proof.digest.mismatch");
    assert_eq!(problem["operation"], "proof.verify");

    let invalid_trust = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "verify",
            "--file",
            envelope.to_str().unwrap(),
            "--trusted-key-id",
            "ed25519:not-a-key",
            "--expected-envelope-digest",
            &signed_envelope.envelope_digest.to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(invalid_trust.status.code(), Some(2));
    let problem: serde_json::Value = serde_json::from_slice(&invalid_trust.stdout).unwrap();
    assert_eq!(problem["code"], "proof.input.schema_mismatch");
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
    assert_eq!(status["data"]["storage_schema_version"], 12);
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
#[expect(
    clippy::too_many_lines,
    reason = "the CLI scenario verifies one mixed batch across add, replay, get, diff, and storage projections"
)]
fn changeset_add_appends_mixed_schema_and_object_edits_and_replays_identically() {
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
            "Define an article Schema and Object",
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
            "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"object.create\",\"object_id\":\"019c0000-0000-7000-8000-000000000080\",\"schema_id\":\"article\",\"schema_version\":1,\"content\":{\"title\":\"First article\"}}\n"
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

    let get = proof_command(directory.path())
        .args(["--output", "json", "changeset", "get", changeset_id])
        .output()
        .unwrap();
    assert!(get.status.success());
    let get: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    let object = &get["data"]["edits"][1];
    assert_eq!(object["kind"], "object.create");
    assert_eq!(object["object_id"], OBJECT_ID);
    assert_eq!(object["schema_id"], "article");
    assert_eq!(object["schema_version"], 1);
    assert_eq!(object["revision"], 1);
    assert_eq!(object["lifecycle_state"], "active");
    assert_eq!(object["relationships"], serde_json::json!([]));
    assert_eq!(object["content"]["title"], "First article");
    assert!(
        object["object_digest"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );

    let diff = proof_command(directory.path())
        .args(["--output", "json", "changeset", "diff", changeset_id])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    let object_diff = &diff["data"]["edits"][1];
    assert_eq!(object_diff["operation"], "object.create");
    assert_eq!(object_diff["object_id"], OBJECT_ID);
    assert!(object_diff["before"].is_null());
    assert_eq!(object_diff["after"]["schema_id"], "article");
    assert_eq!(object_diff["after"]["schema_version"], 1);
    assert_eq!(object_diff["after"]["revision"], 1);
    assert_eq!(object_diff["after"]["lifecycle_state"], "active");
    assert_eq!(object_diff["after"]["relationships"], serde_json::json!([]));
    assert_eq!(object_diff["after"]["content"]["title"], "First article");

    let connection =
        rusqlite::Connection::open(directory.path().join(".proof/state/proof.db")).unwrap();
    let targets: Vec<(String, Option<String>)> = {
        let mut statement = connection
            .prepare("SELECT edit_kind, object_id FROM changeset_edits ORDER BY ordinal")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(
        targets,
        vec![
            ("schema.create".to_owned(), None),
            ("object.create".to_owned(), Some(OBJECT_ID.to_owned())),
        ]
    );
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
fn changeset_get_and_diff_reconstruct_verified_ordered_edits() {
    let directory = TestDirectory::new();
    let changeset_id = create_changeset_with_schema_edit(&directory);

    let get = proof_command(directory.path())
        .args(["--output", "json", "changeset", "get", &changeset_id])
        .output()
        .unwrap();
    assert!(get.status.success());
    let get: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(get["operation"], "changeset.get");
    assert_eq!(get["data"]["changeset_id"], changeset_id);
    assert_eq!(get["data"]["status"], "draft");
    assert_eq!(get["data"]["edits"][0]["ordinal"], 1);
    assert_eq!(get["data"]["edits"][0]["kind"], "schema.create");
    assert_eq!(get["data"]["edits"][0]["schema_id"], "article");
    assert_eq!(get["data"]["edits"][0]["document"]["type"], "object");
    assert!(
        get["data"]["edits"][0]["document_digest"]
            .as_str()
            .unwrap()
            .starts_with("blake3:")
    );
    assert_eq!(get["meta"]["workspace_id"], get["data"]["workspace_id"]);
    assert_eq!(get["meta"]["principal_id"], get["data"]["principal_id"]);

    let diff = proof_command(directory.path())
        .args(["--output", "json", "changeset", "diff", &changeset_id])
        .output()
        .unwrap();
    assert!(diff.status.success());
    let diff: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(diff["operation"], "changeset.diff");
    assert_eq!(diff["data"]["edits"][0]["operation"], "schema.create");
    assert!(diff["data"]["edits"][0]["before"].is_null());
    assert_eq!(
        diff["data"]["edits"][0]["after"]["document"]["type"],
        "object"
    );

    let first_text = proof_command(directory.path())
        .args(["changeset", "diff", &changeset_id])
        .output()
        .unwrap();
    let second_text = proof_command(directory.path())
        .args(["changeset", "diff", &changeset_id])
        .output()
        .unwrap();
    assert_eq!(first_text.stdout, second_text.stdout);
    assert!(
        String::from_utf8(first_text.stdout)
            .unwrap()
            .contains("@@ 1 schema.create article@1")
    );
}

#[test]
fn changeset_get_returns_a_structured_not_found_problem() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );

    let output = proof_command(directory.path())
        .args(["--output", "json", "changeset", "get", UNKNOWN_CHANGESET_ID])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.resource.not_found");
    assert_eq!(problem["operation"], "changeset.get");
}

#[test]
fn changeset_validate_returns_digest_bound_success_evidence() {
    let directory = TestDirectory::new();
    let changeset_id = create_changeset_with_schema_edit(&directory);

    let first = proof_command(directory.path())
        .args(["--output", "json", "changeset", "validate", &changeset_id])
        .output()
        .unwrap();
    let second = proof_command(directory.path())
        .args(["--output", "json", "changeset", "validate", &changeset_id])
        .output()
        .unwrap();

    assert!(first.status.success());
    assert!(second.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first["operation"], "changeset.validate");
    assert_eq!(first["data"]["valid"], true);
    assert_eq!(first["data"]["status"], "ready");
    assert_eq!(first["data"]["edit_count"], 1);
    assert_eq!(first["data"]["findings"], serde_json::json!([]));
    assert_eq!(
        first["data"]["changeset_digest"],
        second["data"]["changeset_digest"]
    );
    assert_eq!(
        first["data"]["validation_results_digest"],
        second["data"]["validation_results_digest"]
    );
    let count: i64 = rusqlite::Connection::open(directory.path().join(".proof/state/proof.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_validations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);

    let submitted = proof_command(directory.path())
        .args(["--output", "json", "changeset", "submit", &changeset_id])
        .output()
        .unwrap();
    let replay = proof_command(directory.path())
        .args(["--output", "json", "changeset", "submit", &changeset_id])
        .output()
        .unwrap();
    assert!(submitted.status.success());
    assert!(replay.status.success());
    let submitted: serde_json::Value = serde_json::from_slice(&submitted.stdout).unwrap();
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(submitted["operation"], "changeset.submit");
    assert_eq!(submitted["data"]["status"], "submitted");
    assert_eq!(
        submitted["data"]["changeset_digest"],
        first["data"]["changeset_digest"]
    );
    assert_eq!(
        submitted["data"]["validation_results_digest"],
        first["data"]["validation_results_digest"]
    );
    assert_eq!(
        submitted["data"]["submitted_at"],
        replay["data"]["submitted_at"]
    );

    let approved = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "approve",
            &changeset_id,
            "--approval",
            "editorial",
        ])
        .output()
        .unwrap();
    let approval_replay = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "approve",
            &changeset_id,
            "--approval",
            "editorial",
        ])
        .output()
        .unwrap();
    assert!(approved.status.success());
    assert!(approval_replay.status.success());
    let approved: serde_json::Value = serde_json::from_slice(&approved.stdout).unwrap();
    let approval_replay: serde_json::Value =
        serde_json::from_slice(&approval_replay.stdout).unwrap();
    assert_eq!(approved["operation"], "changeset.approve");
    assert_eq!(approved["data"]["approval"], "editorial");
    assert_eq!(approved["data"]["status"], "approved");
    assert_eq!(
        approved["data"]["changeset_digest"],
        first["data"]["changeset_digest"]
    );
    assert_eq!(
        approved["data"]["approved_at"],
        approval_replay["data"]["approved_at"]
    );
}

#[test]
fn changeset_commit_advances_known_state_and_replays_identically() {
    let directory = TestDirectory::new();
    let changeset_id = create_changeset_with_schema_edit(&directory);
    for action in ["validate", "submit"] {
        assert!(
            proof_command(directory.path())
                .args(["changeset", action, &changeset_id])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "approve",
                &changeset_id,
                "--approval",
                "editorial",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let committed = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "commit",
            &changeset_id,
            "--idempotency-key",
            COMMIT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    let commit_replay = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "changeset",
            "commit",
            &changeset_id,
            "--idempotency-key",
            COMMIT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(committed.status.success());
    assert!(commit_replay.status.success());
    let committed: serde_json::Value = serde_json::from_slice(&committed.stdout).unwrap();
    let commit_replay: serde_json::Value = serde_json::from_slice(&commit_replay.stdout).unwrap();
    assert_eq!(committed["operation"], "changeset.commit");
    assert_eq!(committed["data"]["status"], "committed");
    assert_eq!(committed["data"]["authoritative_sequence"], 1);
    assert_ne!(
        committed["data"]["previous_state"],
        committed["data"]["resulting_state"]
    );
    assert_eq!(
        committed["data"]["committed_at"],
        commit_replay["data"]["committed_at"]
    );
    let status = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["data"]["authoritative_sequence"], 1);
    assert_eq!(
        status["data"]["state_digest"],
        committed["data"]["resulting_state"]
    );
}

#[test]
fn edition_create_returns_a_stable_content_addressed_manifest() {
    let directory = TestDirectory::new();
    let changeset_id = create_changeset_with_schema_edit(&directory);
    for action in ["validate", "submit"] {
        assert!(
            proof_command(directory.path())
                .args(["changeset", action, &changeset_id])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "approve",
                &changeset_id,
                "--approval",
                "editorial"
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "commit",
                &changeset_id,
                "--idempotency-key",
                COMMIT_IDEMPOTENCY_KEY,
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let create = || {
        proof_command(directory.path())
            .args([
                "--output",
                "json",
                "edition",
                "create",
                "--idempotency-key",
                EDITION_IDEMPOTENCY_KEY,
            ])
            .output()
            .unwrap()
    };

    let first = create();
    let replay = create();

    assert!(first.status.success());
    assert!(replay.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let replay: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(first["operation"], "edition.create");
    assert_eq!(first["data"]["authoritative_sequence"], 1);
    assert_eq!(first["data"]["schema_count"], 1);
    assert_eq!(first["data"]["changeset_count"], 1);
    assert_eq!(
        first["data"]["manifest"]["api_version"],
        "proof.dev/edition/v1"
    );
    assert_eq!(first["data"]["edition_id"], replay["data"]["edition_id"]);
    assert_eq!(
        first["data"]["edition_digest"],
        replay["data"]["edition_digest"]
    );
    assert_eq!(first["data"]["created_at"], replay["data"]["created_at"]);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end scenario proves the release, authority, rollback, and rebuild invariants together"
)]
fn local_release_query_proof_rollback_and_projection_rebuild_form_one_verified_loop() {
    let directory = TestDirectory::new();
    let edition_id = create_committed_edition_with_object(&directory);
    let status_before = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();
    let status_before: serde_json::Value = serde_json::from_slice(&status_before.stdout).unwrap();
    let expected_state = status_before["data"]["state_digest"].as_str().unwrap();

    let environment = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "environment",
            "create",
            "preview",
            "--required-approval",
            "editorial",
            "--idempotency-key",
            ENVIRONMENT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(
        environment.status.success(),
        "{}",
        String::from_utf8_lossy(&environment.stderr)
    );
    let environment: serde_json::Value = serde_json::from_slice(&environment.stdout).unwrap();
    assert_eq!(environment["data"]["environment_id"], "preview");
    assert_eq!(
        environment["data"]["target_kind"],
        "proof.local/released-state/v1"
    );
    assert!(environment["data"]["current_release_id"].is_null());

    let first_release = create_release(&directory, &edition_id, RELEASE_IDEMPOTENCY_KEY);
    assert_eq!(first_release["data"]["kind"], "promotion");
    assert_eq!(first_release["data"]["release_sequence"], 1);
    assert!(
        first_release["data"]["key_id"]
            .as_str()
            .unwrap()
            .starts_with("ed25519:")
    );
    assert!(first_release["data"]["proof_envelope_json"].is_string());
    let first_release_id = first_release["data"]["release_id"].as_str().unwrap();

    let fetched = proof_command(directory.path())
        .args(["--output", "json", "release", "get", first_release_id])
        .output()
        .unwrap();
    assert!(fetched.status.success());
    let fetched: serde_json::Value = serde_json::from_slice(&fetched.stdout).unwrap();
    assert_eq!(
        fetched["data"]["proof_envelope_digest"],
        first_release["data"]["proof_envelope_digest"]
    );

    let verified = proof_command(directory.path())
        .args(["--output", "json", "release", "verify", first_release_id])
        .output()
        .unwrap();
    assert!(verified.status.success());
    let verified: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    for check in [
        "signature_valid",
        "subjects_valid",
        "evidence_complete",
        "trusted",
        "valid",
    ] {
        assert_eq!(verified["data"][check], true, "failed check: {check}");
    }

    let envelope_path = directory.path().join("persisted-release.dsse.json");
    fs::write(
        &envelope_path,
        first_release["data"]["proof_envelope_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let offline = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "verify",
            "--file",
            envelope_path.to_str().unwrap(),
            "--trusted-key-id",
            first_release["data"]["key_id"].as_str().unwrap(),
            "--expected-envelope-digest",
            first_release["data"]["proof_envelope_digest"]
                .as_str()
                .unwrap(),
        ])
        .output()
        .unwrap();
    assert!(offline.status.success());

    let queried = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "object",
            "query",
            "--environment",
            "preview",
            "--object-id",
            OBJECT_ID,
        ])
        .output()
        .unwrap();
    assert!(queried.status.success());
    let queried: serde_json::Value = serde_json::from_slice(&queried.stdout).unwrap();
    assert_eq!(queried["data"]["delegation_id"], serde_json::Value::Null);
    assert_eq!(queried["data"]["objects"][0]["object_id"], OBJECT_ID);
    assert_eq!(
        queried["data"]["objects"][0]["canonical_content"],
        "{\"title\":\"First article\"}"
    );

    let agent = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "principal",
            "create-agent",
            "--display-name",
            "Released content agent",
            "--idempotency-key",
            AGENT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(agent.status.success());
    let agent: serde_json::Value = serde_json::from_slice(&agent.stdout).unwrap();
    let agent_id = agent["data"]["principal_id"].as_str().unwrap();
    let issued_at = timestamp_at_offset_seconds(0);
    let delegation_expires = Timestamp::from_unix_timestamp_nanos(
        issued_at.unix_timestamp_nanos() + i128::from(3_600 * 1_000_000_000_u64),
    )
    .unwrap();
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    let delegation = grant_delegation(
        &repository,
        GrantDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            recipient_principal_id: agent_id.parse().unwrap(),
            actions: vec![
                DelegatedAction::WorkspaceStatus,
                DelegatedAction::ObjectQueryReleased,
                DelegatedAction::ContextBuild,
            ],
            scope: DelegationScope {
                workspace_id: status_before["data"]["workspace_id"]
                    .as_str()
                    .unwrap()
                    .parse()
                    .unwrap(),
                environment_ids: vec!["preview".parse().unwrap()],
                object_ids: vec![OBJECT_ID.parse().unwrap()],
            },
            constraints: DelegationConstraints {
                max_objects: 1,
                max_context_bytes: 1_048_576,
                allow_subdelegation: false,
            },
            not_before: issued_at,
            expires_at: delegation_expires,
            idempotency_key: DELEGATION_IDEMPOTENCY_KEY.parse().unwrap(),
            issued_at,
        },
    )
    .unwrap();
    assert_eq!(delegation.delegation_id.to_string(), DELEGATION_ID);

    let delegated_status = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            agent_id,
            "--delegation",
            DELEGATION_ID,
            "status",
        ])
        .output()
        .unwrap();
    assert!(delegated_status.status.success());
    let delegated_status: serde_json::Value =
        serde_json::from_slice(&delegated_status.stdout).unwrap();
    assert_eq!(delegated_status["data"]["principal_id"], agent_id);
    assert_eq!(delegated_status["data"]["delegation_id"], DELEGATION_ID);
    assert!(delegated_status["data"]["authorization_decision_digest"].is_string());

    let delegated_query = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            agent_id,
            "--delegation",
            DELEGATION_ID,
            "object",
            "query",
            "--environment",
            "preview",
            "--object-id",
            OBJECT_ID,
        ])
        .output()
        .unwrap();
    assert!(delegated_query.status.success());
    let delegated_query: serde_json::Value =
        serde_json::from_slice(&delegated_query.stdout).unwrap();
    assert_eq!(delegated_query["data"]["principal_id"], agent_id);
    assert_eq!(delegated_query["data"]["delegation_id"], DELEGATION_ID);

    let context_expires = timestamp_after_seconds(1_800);
    let context = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            agent_id,
            "--delegation",
            DELEGATION_ID,
            "context",
            "build",
            "--task-id",
            "release-read-test",
            "--intent",
            "Read the exact released article",
            "--environment",
            "preview",
            "--object-id",
            OBJECT_ID,
            "--max-objects",
            "1",
            "--max-bytes",
            "1048576",
            "--expires-at",
            &context_expires,
            "--idempotency-key",
            CONTEXT_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(
        context.status.success(),
        "{}",
        String::from_utf8_lossy(&context.stderr)
    );
    let context: serde_json::Value = serde_json::from_slice(&context.stdout).unwrap();
    let context_pack_id = context["data"]["context_pack_id"].as_str().unwrap();
    assert_eq!(context["data"]["delegation_id"], DELEGATION_ID);
    assert_eq!(
        context["data"]["object_ids"],
        serde_json::json!([OBJECT_ID])
    );
    assert!(context["data"]["manifest_json"].is_string());
    for action in ["get", "verify"] {
        let output = proof_command(directory.path())
            .args([
                "--output",
                "json",
                "--principal",
                agent_id,
                "--delegation",
                DELEGATION_ID,
                "context",
                action,
                context_pack_id,
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        if action == "verify" {
            assert_eq!(output["data"]["valid"], true);
        } else {
            assert_eq!(output["data"]["context_pack_id"], context_pack_id);
        }
    }

    let second_release = create_release(&directory, &edition_id, SECOND_RELEASE_IDEMPOTENCY_KEY);
    let second_release_id = second_release["data"]["release_id"].as_str().unwrap();
    let rollback = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "release",
            "rollback",
            "--environment",
            "preview",
            "--to-release",
            first_release_id,
            "--idempotency-key",
            ROLLBACK_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(rollback.status.success());
    let rollback: serde_json::Value = serde_json::from_slice(&rollback.stdout).unwrap();
    assert_eq!(rollback["data"]["kind"], "rollback");
    assert_eq!(rollback["data"]["previous_release_id"], second_release_id);
    assert_eq!(
        rollback["data"]["rollback_target_release_id"],
        first_release_id
    );
    assert_ne!(rollback["data"]["release_id"], first_release_id);

    let clean_dry_run = rebuild(&directory, true);
    assert_eq!(clean_dry_run["data"]["changed"], false);
    assert_eq!(clean_dry_run["data"]["state_digest"], expected_state);

    let database = directory.path().join(".proof/state/proof.db");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute(
            "UPDATE known_state SET state_digest = ?1 WHERE singleton = 1",
            [format!("blake3:{}", "0".repeat(64))],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE object_revisions SET content_json = '{\"title\":\"tampered\"}' WHERE object_id = ?1",
            [OBJECT_ID],
        )
        .unwrap();
    connection
        .execute("DELETE FROM environment_current_releases", [])
        .unwrap();
    drop(connection);

    let drift = rebuild(&directory, true);
    assert_eq!(drift["data"]["changed"], true);
    assert_eq!(drift["data"]["state_digest"], expected_state);
    let connection = rusqlite::Connection::open(&database).unwrap();
    let still_tampered: String = connection
        .query_row(
            "SELECT content_json FROM object_revisions WHERE object_id = ?1",
            [OBJECT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(still_tampered, "{\"title\":\"tampered\"}");
    drop(connection);

    let repaired = rebuild(&directory, false);
    assert_eq!(repaired["data"]["changed"], true);
    assert_eq!(repaired["data"]["state_digest"], expected_state);
    let status_after = proof_command(directory.path())
        .args(["--output", "json", "status"])
        .output()
        .unwrap();
    assert!(status_after.status.success());
    let status_after: serde_json::Value = serde_json::from_slice(&status_after.stdout).unwrap();
    assert_eq!(status_after["data"]["state_digest"], expected_state);
    let connection = rusqlite::Connection::open(&database).unwrap();
    let restored_content: String = connection
        .query_row(
            "SELECT content_json FROM object_revisions WHERE object_id = ?1",
            [OBJECT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(restored_content, "{\"title\":\"First article\"}");
    let pointer_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM environment_current_releases",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pointer_count, 1);
    assert_eq!(rebuild(&directory, true)["data"]["changed"], false);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one CLI oracle proves the complete Human repair, v2 publication, exact query, and verification path"
)]
fn localized_cli_repairs_and_releases_two_exact_locales() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );
    let created = successful_json(
        &directory,
        &[
            "changeset",
            "create",
            "--intent",
            "Create a localizable campaign source",
        ],
    );
    let source_changeset = created["data"]["changeset_id"].as_str().unwrap();
    let source_edits = directory.path().join("localized-source.ndjson");
    fs::write(
        &source_edits,
        format!(
            concat!(
                "{{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",",
                "\"schema_id\":\"campaign\",\"schema_version\":1,\"document\":{{",
                "\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",",
                "\"additionalProperties\":false,\"properties\":{{",
                "\"legal\":{{\"type\":\"string\"}},\"title\":{{\"type\":\"string\"}}}},",
                "\"required\":[\"legal\",\"title\"],\"type\":\"object\",",
                "\"x-proof-localizable\":[\"/legal\",\"/title\"]}}}}\n",
                "{{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"object.create\",",
                "\"object_id\":\"{OBJECT_ID}\",\"schema_id\":\"campaign\",",
                "\"schema_version\":1,\"content\":{{\"legal\":\"Standard terms apply\",",
                "\"title\":\"Summer campaign\"}}}}\n"
            ),
            OBJECT_ID = OBJECT_ID
        ),
    )
    .unwrap();
    successful_json(
        &directory,
        &[
            "changeset",
            "add",
            source_changeset,
            "--file",
            source_edits.to_str().unwrap(),
        ],
    );
    for action in ["validate", "submit"] {
        successful_json(&directory, &["changeset", action, source_changeset]);
    }
    successful_json(
        &directory,
        &[
            "changeset",
            "approve",
            source_changeset,
            "--approval",
            "editorial",
        ],
    );
    successful_json(
        &directory,
        &[
            "changeset",
            "commit",
            source_changeset,
            "--idempotency-key",
            COMMIT_IDEMPOTENCY_KEY,
        ],
    );
    let base_edition = successful_json(
        &directory,
        &[
            "edition",
            "create",
            "--idempotency-key",
            EDITION_IDEMPOTENCY_KEY,
        ],
    );
    let base_edition_id = base_edition["data"]["edition_id"].as_str().unwrap();
    successful_json(
        &directory,
        &[
            "environment",
            "create",
            "preview",
            "--required-approval",
            "editorial",
            "--idempotency-key",
            ENVIRONMENT_IDEMPOTENCY_KEY,
        ],
    );
    let base_release = successful_json(
        &directory,
        &[
            "release",
            "create",
            "--edition",
            base_edition_id,
            "--environment",
            "preview",
            "--idempotency-key",
            RELEASE_IDEMPOTENCY_KEY,
        ],
    );
    let base_release_id = base_release["data"]["release_id"].as_str().unwrap();
    let source_query = successful_json(
        &directory,
        &[
            "object",
            "query",
            "--environment",
            "preview",
            "--object-id",
            OBJECT_ID,
        ],
    );
    let source_digest = source_query["data"]["objects"][0]["object_digest"]
        .as_str()
        .unwrap();

    let intent = successful_json(
        &directory,
        &[
            "localized",
            "intent-issue",
            "--environment",
            "preview",
            "--target",
            &format!("{OBJECT_ID}:campaign:es-ES"),
            "--target",
            &format!("{OBJECT_ID}:campaign:fr-FR"),
        ],
    );
    assert_eq!(
        intent["data"]["api_version"],
        "proof.dev/content-resource-intent/v1"
    );
    let intent_id = intent["data"]["intent_id"].as_str().unwrap();
    let intent_digest = intent["data"]["intent_digest"].as_str().unwrap();
    let context_file = directory.path().join("localized-context.json");
    fs::write(
        &context_file,
        serde_json::to_vec(&serde_json::json!({
            "policy_rules": [{
                "locale": "fr-FR",
                "pointer": "/legal",
                "disallowed_values": ["Garantie absolue"]
            }],
            "limits": {
                "max_objects": 1,
                "max_edits": 3,
                "max_validation_attempts": 3,
                "max_bytes": 1_048_576
            },
            "expires_at": timestamp_after_seconds(600)
        }))
        .unwrap(),
    )
    .unwrap();
    let context = successful_json(
        &directory,
        &[
            "localized",
            "context-build",
            "--resource-intent",
            intent_id,
            "--resource-intent-digest",
            intent_digest,
            "--file",
            context_file.to_str().unwrap(),
        ],
    );
    let context_id = context["data"]["context_pack_id"].as_str().unwrap();
    let context_digest = context["data"]["context_pack_digest"].as_str().unwrap();
    let changeset = successful_json(
        &directory,
        &[
            "localized",
            "changeset-create",
            "--intent",
            "Translate the campaign into Spanish and French",
            "--resource-intent",
            intent_id,
            "--resource-intent-digest",
            intent_digest,
            "--context-pack",
            context_id,
            "--context-pack-digest",
            context_digest,
        ],
    );
    let changeset_id = changeset["data"]["changeset_id"].as_str().unwrap();
    let edits_file = directory.path().join("localized-edits.ndjson");
    fs::write(
        &edits_file,
        format!(
            concat!(
                "{{\"object_id\":\"{OBJECT_ID}\",\"locale\":\"es-ES\",",
                "\"expected_source\":{{\"revision\":1,\"digest\":\"{source_digest}\",",
                "\"schema_id\":\"campaign\",\"schema_version\":1}},\"content\":{{",
                "\"legal\":\"Se aplican términos estándar\",\"title\":\"Campaña de verano\"}}}}\n",
                "{{\"object_id\":\"{OBJECT_ID}\",\"locale\":\"fr-FR\",",
                "\"expected_source\":{{\"revision\":1,\"digest\":\"{source_digest}\",",
                "\"schema_id\":\"campaign\",\"schema_version\":1}},\"content\":{{",
                "\"legal\":\"Garantie absolue\",\"title\":\"Campagne d’été\"}}}}\n"
            ),
            OBJECT_ID = OBJECT_ID,
            source_digest = source_digest
        ),
    )
    .unwrap();
    let added = successful_json(
        &directory,
        &[
            "localized",
            "changeset-add",
            changeset_id,
            "--file",
            edits_file.to_str().unwrap(),
        ],
    );
    let invalid_edit_id = added["data"]["edit_ids"][1].as_str().unwrap();
    let invalid = successful_json(
        &directory,
        &["localized", "changeset-validate", changeset_id],
    );
    assert_eq!(invalid["data"]["valid"], false);
    assert_eq!(
        invalid["data"]["findings"][0]["code"],
        "proof.validation.prohibited_legal_claim"
    );
    let invalid_digest = invalid["data"]["validation_results_digest"]
        .as_str()
        .unwrap();
    let repair_file = directory.path().join("localized-repair.ndjson");
    fs::write(
        &repair_file,
        format!(
            concat!(
                "{{\"object_id\":\"{OBJECT_ID}\",\"locale\":\"fr-FR\",",
                "\"expected_source\":{{\"revision\":1,\"digest\":\"{source_digest}\",",
                "\"schema_id\":\"campaign\",\"schema_version\":1}},\"content\":{{",
                "\"legal\":\"Des conditions standard s’appliquent\",",
                "\"title\":\"Campagne d’été\"}},\"supersedes_edit_id\":\"{invalid_edit_id}\",",
                "\"repair_of_validation_result_digest\":\"{invalid_digest}\"}}\n"
            ),
            OBJECT_ID = OBJECT_ID,
            source_digest = source_digest,
            invalid_edit_id = invalid_edit_id,
            invalid_digest = invalid_digest
        ),
    )
    .unwrap();
    successful_json(
        &directory,
        &[
            "localized",
            "changeset-add",
            changeset_id,
            "--file",
            repair_file.to_str().unwrap(),
        ],
    );
    let valid = successful_json(
        &directory,
        &["localized", "changeset-validate", changeset_id],
    );
    assert_eq!(valid["data"]["valid"], true);
    successful_json(&directory, &["localized", "changeset-submit", changeset_id]);
    successful_json(
        &directory,
        &[
            "localized",
            "changeset-approve",
            changeset_id,
            "--approval",
            "editorial",
        ],
    );
    let committed = successful_json(
        &directory,
        &[
            "localized",
            "changeset-commit",
            changeset_id,
            "--idempotency-key",
            LOCALIZED_COMMIT_IDEMPOTENCY_KEY,
        ],
    );
    let state_digest = committed["data"]["resulting_state"]["digest"]
        .as_str()
        .unwrap();
    let edition = successful_json(
        &directory,
        &[
            "localized",
            "edition-create",
            "--changeset",
            changeset_id,
            "--resulting-state-digest",
            state_digest,
        ],
    );
    let edition_id = edition["data"]["edition_id"].as_str().unwrap();
    let release = successful_json(
        &directory,
        &[
            "localized",
            "release-promote",
            "--environment",
            "preview",
            "--edition",
            edition_id,
            "--expected-base-release",
            base_release_id,
            "--idempotency-key",
            LOCALIZED_RELEASE_IDEMPOTENCY_KEY,
        ],
    );
    let release_id = release["data"]["release_id"].as_str().unwrap();
    let query = successful_json(
        &directory,
        &[
            "localized",
            "query",
            "--environment",
            "preview",
            "--target",
            &format!("{OBJECT_ID}:es-ES"),
            "--target",
            &format!("{OBJECT_ID}:fr-FR"),
        ],
    );
    assert_eq!(query["data"]["renditions"].as_array().unwrap().len(), 2);
    let verified = successful_json(&directory, &["localized", "release-verify", release_id]);
    assert_eq!(verified["data"]["valid"], true);
    assert_eq!(rebuild(&directory, true)["data"]["changed"], false);
}

#[test]
fn edition_create_rejects_an_empty_workspace() {
    let directory = TestDirectory::new();
    assert!(
        proof_command(directory.path())
            .arg("init")
            .output()
            .unwrap()
            .status
            .success()
    );

    let output = proof_command(directory.path())
        .args(["--output", "json", "edition", "create"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["operation"], "edition.create");
    assert_eq!(problem["code"], "proof.validation.empty_state");
}

#[test]
fn changeset_submit_rejects_an_unvalidated_draft() {
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
            "Define article Schema",
        ])
        .output()
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let changeset_id = created["data"]["changeset_id"].as_str().unwrap();

    let output = proof_command(directory.path())
        .args(["--output", "json", "changeset", "submit", changeset_id])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(5));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.changeset.not_ready");
    assert_eq!(problem["operation"], "changeset.submit");
}

#[test]
fn changeset_validate_projects_structured_meta_schema_findings() {
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
            "Define invalid Schema",
        ])
        .output()
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let changeset_id = created["data"]["changeset_id"].as_str().unwrap();
    let edit_path = directory.path().join("invalid-schema.ndjson");
    fs::write(
        &edit_path,
        "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"article\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":42}}\n",
    )
    .unwrap();
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "add",
                changeset_id,
                "--file",
                edit_path.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );

    let output = proof_command(directory.path())
        .args(["--output", "json", "changeset", "validate", changeset_id])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let problem: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["code"], "proof.validation.failed");
    assert_eq!(problem["operation"], "changeset.validate");
    assert_eq!(
        problem["findings"][0]["code"],
        "proof.schema.meta_schema_invalid"
    );
    assert_eq!(problem["findings"][0]["pointer"], "/edits/0/document/type");
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
    assert!(stdout.contains("implementation: local-proof-loop"));
    assert!(stdout.contains("workspace selected: false"));
}

fn proof_command(current_directory: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof"));
    command.current_dir(current_directory);
    command
}

fn successful_json(directory: &TestDirectory, arguments: &[&str]) -> serde_json::Value {
    let output = proof_command(directory.path())
        .arg("--output")
        .arg("json")
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn create_changeset_with_schema_edit(directory: &TestDirectory) -> String {
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
            "Define article Schema",
        ])
        .output()
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let changeset_id = created["data"]["changeset_id"].as_str().unwrap().to_owned();
    let edit_path = directory.path().join("inspect-edits.ndjson");
    fs::write(
        &edit_path,
        "{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"schema.create\",\"schema_id\":\"article\",\"schema_version\":1,\"document\":{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}}\n",
    )
    .unwrap();
    let added = proof_command(directory.path())
        .args([
            "changeset",
            "add",
            &changeset_id,
            "--file",
            edit_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(added.status.success());
    changeset_id
}

fn create_committed_edition_with_object(directory: &TestDirectory) -> String {
    let changeset_id = create_changeset_with_schema_edit(directory);
    let object_edit_path = directory.path().join("object-edit.ndjson");
    fs::write(
        &object_edit_path,
        format!(
            "{{\"api_version\":\"proof.dev/edit/v1\",\"kind\":\"object.create\",\"object_id\":\"{OBJECT_ID}\",\"schema_id\":\"article\",\"schema_version\":1,\"content\":{{\"title\":\"First article\"}}}}\n"
        ),
    )
    .unwrap();
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "add",
                &changeset_id,
                "--file",
                object_edit_path.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    for action in ["validate", "submit"] {
        assert!(
            proof_command(directory.path())
                .args(["changeset", action, &changeset_id])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "approve",
                &changeset_id,
                "--approval",
                "editorial",
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(
        proof_command(directory.path())
            .args([
                "changeset",
                "commit",
                &changeset_id,
                "--idempotency-key",
                COMMIT_IDEMPOTENCY_KEY,
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    let edition = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "edition",
            "create",
            "--idempotency-key",
            EDITION_IDEMPOTENCY_KEY,
        ])
        .output()
        .unwrap();
    assert!(edition.status.success());
    let edition: serde_json::Value = serde_json::from_slice(&edition.stdout).unwrap();
    edition["data"]["edition_id"].as_str().unwrap().to_owned()
}

fn create_release(
    directory: &TestDirectory,
    edition_id: &str,
    idempotency_key: &str,
) -> serde_json::Value {
    let release = proof_command(directory.path())
        .args([
            "--output",
            "json",
            "release",
            "create",
            "--edition",
            edition_id,
            "--environment",
            "preview",
            "--idempotency-key",
            idempotency_key,
        ])
        .output()
        .unwrap();
    assert!(
        release.status.success(),
        "{}",
        String::from_utf8_lossy(&release.stderr)
    );
    serde_json::from_slice(&release.stdout).unwrap()
}

fn rebuild(directory: &TestDirectory, dry_run: bool) -> serde_json::Value {
    let mut command = proof_command(directory.path());
    command.args(["--output", "json", "projection", "rebuild"]);
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn timestamp_at_offset_seconds(seconds: u64) -> Timestamp {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let now_nanos = i128::try_from(elapsed.as_nanos()).unwrap();
    let offset_nanos = i128::from(seconds).checked_mul(1_000_000_000).unwrap();
    Timestamp::from_unix_timestamp_nanos(now_nanos.checked_add(offset_nanos).unwrap()).unwrap()
}

fn timestamp_after_seconds(seconds: u64) -> String {
    timestamp_at_offset_seconds(seconds).to_string()
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
