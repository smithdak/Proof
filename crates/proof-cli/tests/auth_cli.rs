use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use proof_application::authority::AuthenticatedInvocationV1;
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, verify_authority_envelope},
};
use proof_canonical::{canonicalize, parse_strict};

const STATUS_COMMAND: &str =
    include_str!("../../../conformance/v1/authority/vectors/semantic-command.valid.json");

#[test]
fn capability_list_renders_the_exact_application_registry_in_text_and_json() {
    let text = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args(["capability", "list", "--output", "text"])
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(text.stderr.is_empty());
    let text = String::from_utf8(text.stdout).unwrap();
    for capability in proof_application::capabilities() {
        assert!(
            text.contains(&format!("{} {}", capability.operation, capability.version)),
            "missing exact capability identity for {} {}",
            capability.operation,
            capability.version
        );
        assert!(
            text.contains(&format!("side effect: {}", capability.side_effect)),
            "missing side-effect classification for {} {}",
            capability.operation,
            capability.version
        );
        assert!(
            text.contains(&format!("required action: {}", capability.required_action)),
            "missing required action for {} {}",
            capability.operation,
            capability.version
        );
    }

    let json = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args(["capability", "list", "--output", "json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(json.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        json["data"]["capabilities"],
        serde_json::to_value(proof_application::capabilities()).unwrap()
    );
}

#[test]
fn auth_sources_are_stdin_only_at_the_executable_boundary() {
    for arguments in [
        vec![
            "auth",
            "sign",
            "--command",
            "command.json",
            "--credential",
            "agent-a",
        ],
        vec!["auth", "execute", "--invocation", "invocation.json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_proof"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("authenticated Agent transport is stdin-only")
        );
    }
}

#[test]
fn signer_uses_fixed_credential_directory_and_emits_one_canonical_frame() {
    let directory = TestDirectory::new();
    let credential_directory = platform_credential_directory(directory.path());
    fs::create_dir_all(&credential_directory).unwrap();
    set_directory_permissions(&credential_directory);

    let secret = [42_u8; 32];
    let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
    let key_id = provider.metadata().unwrap().key_id;
    let credential_path = credential_directory.join("agent-a.json");
    fs::write(
        &credential_path,
        serde_json::to_vec(&serde_json::json!({
            "api_version": "proof.dev/local-agent-credential/v1",
            "binding_id": "019c0000-0000-7000-8000-000000000004",
            "key_id": key_id,
            "secret_key_hex": "2a".repeat(32),
        }))
        .unwrap(),
    )
    .unwrap();
    set_file_permissions(&credential_path);

    let mut command = Command::new(env!("CARGO_BIN_EXE_proof"));
    command
        .current_dir(directory.path())
        .args(["auth", "sign", "--command", "-", "--credential", "agent-a"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    set_credential_root_environment(&mut command, directory.path());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(STATUS_COMMAND.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!directory.path().join(".proof").exists());
    assert_ne!(output.stdout.last(), Some(&b'\n'));
    let value = parse_strict(&output.stdout).unwrap();
    let canonical = canonicalize(&value).unwrap();
    assert_eq!(canonical.as_bytes(), output.stdout);
    let invocation: AuthenticatedInvocationV1 = serde_json::from_value(value).unwrap();
    let metadata = provider.metadata().unwrap();
    verify_authority_envelope::<serde_json::Value>(
        invocation.authentication.as_str().as_bytes(),
        AuthorityPayloadProfile::AuthenticatedCommand,
        &[metadata.key_id.as_str()],
    )
    .unwrap();
}

fn platform_credential_directory(root: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        root.join("proof").join("credentials")
    }
    #[cfg(windows)]
    {
        root.join("Proof").join("credentials")
    }
}

fn set_credential_root_environment(command: &mut Command, root: &Path) {
    #[cfg(unix)]
    command.env("XDG_DATA_HOME", root);
    #[cfg(windows)]
    command.env("LOCALAPPDATA", root);
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(not(unix))]
fn set_directory_permissions(_: &Path) {}

#[cfg(unix)]
fn set_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_file_permissions(_: &Path) {}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let suffix = uuid::Uuid::now_v7();
        let path = std::env::temp_dir().join(format!("proof-auth-cli-{suffix}"));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    #[must_use]
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
