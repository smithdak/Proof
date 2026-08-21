use std::{fs, path::PathBuf, process::Command};

use serde_json::Value;
use uuid::Uuid;

const RELEASE_ID: &str = "019d2000-0000-7000-8000-000000000057";
const PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-000000000002";

#[test]
fn evidence_export_is_human_only_and_does_not_relabel_legacy_proof_verify() {
    let evidence_help = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args(["evidence", "export", "--help"])
        .output()
        .unwrap();
    assert!(evidence_help.status.success());
    let evidence_help = String::from_utf8(evidence_help.stdout).unwrap();
    assert!(evidence_help.contains("--release-id"));
    assert!(evidence_help.contains("--directory"));
    assert!(evidence_help.contains("--include-subject-opening"));

    let verify_help = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args(["verify", "--help"])
        .output()
        .unwrap();
    assert!(verify_help.status.success());
    let verify_help = String::from_utf8(verify_help.stdout).unwrap();
    assert!(verify_help.contains("--trusted-key-id"));
    assert!(verify_help.contains("--expected-envelope-digest"));
    assert!(!verify_help.contains("--directory"));

    let directory = TestDirectory::new();
    let destination = directory.path().join("bundle");
    let denied = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(directory.path())
        .args([
            "--output",
            "json",
            "--principal",
            PRINCIPAL_ID,
            "evidence",
            "export",
            "--release-id",
            RELEASE_ID,
            "--directory",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(4));
    assert!(denied.stderr.is_empty());
    let problem: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(problem["operation"], "evidence.export");
    assert_eq!(problem["code"], "proof.auth.denied");
    assert!(!destination.exists());
}

#[test]
fn evidence_export_rejects_invalid_release_before_opening_or_writing() {
    let directory = TestDirectory::new();
    let destination = directory.path().join("bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(directory.path())
        .args([
            "--output",
            "json",
            "evidence",
            "export",
            "--release-id",
            "not-a-release",
            "--directory",
        ])
        .arg(&destination)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let problem: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["operation"], "evidence.export");
    assert_eq!(problem["code"], "proof.input.schema_mismatch");
    assert!(!destination.exists());
    assert!(!directory.path().join(".proof").exists());
}

#[test]
#[cfg(unix)]
fn evidence_export_reports_valid_missing_release_without_writing_destination() {
    let directory = TestDirectory::new();
    initialize(&directory);
    let destination = directory.path().join("missing-release-bundle");
    let output = proof_command(&directory)
        .args([
            "--output",
            "json",
            "evidence",
            "export",
            "--release-id",
            RELEASE_ID,
            "--directory",
        ])
        .arg(&destination)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    assert!(output.stderr.is_empty());
    let problem: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(problem["type"], "urn:proof:problem:resource-not-found");
    assert_eq!(
        problem["title"],
        "The requested Release resource was not found"
    );
    assert_eq!(problem["operation"], "evidence.export");
    assert_eq!(problem["code"], "proof.resource.not_found");
    assert_eq!(problem["retryable"], false);
    assert!(problem.get("detail").is_none());
    assert!(!destination.exists());
    assert_no_staging_directory(&directory);
}

#[cfg(unix)]
fn initialize(directory: &TestDirectory) {
    assert_success(
        &proof_command(directory)
            .args(["--output", "json", "init"])
            .output()
            .unwrap(),
    );
}

#[cfg(unix)]
fn proof_command(directory: &TestDirectory) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proof"));
    command.current_dir(directory.path());
    command
}

#[cfg(unix)]
fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
}

#[cfg(unix)]
fn assert_no_staging_directory(directory: &TestDirectory) {
    assert!(fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".proof-evidence-")
    }));
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("proof-p0006-evidence-cli-{}", Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
