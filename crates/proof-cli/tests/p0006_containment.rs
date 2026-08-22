#![cfg(unix)]

mod p0006_support;

use std::{
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    BindingId, CreateAgentPrincipalCommand, DelegationId, EnrollmentChallengeId,
    InitializeWorkspaceCommand, PrincipalId, Timestamp, WorkspaceId,
    authority::{
        AgentPrincipalType, AuthenticatedCommandKeyUsage, AuthenticatedInvocationV1,
        AuthorityAction, AuthorityAdministrator, AuthorityAudience, AuthorityRepository,
        AuthoritySequence, BindingEnrollmentChallengeV1, CommandInputApiVersion, CommandInputV1,
        DelegationActionsV2, DelegationApiVersion, DelegationConstraintsV2,
        DelegationEnvironmentIdsV2, DelegationLocalesV2, DelegationObjectIdsV2,
        DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2, DirectAuthorityProfileV1,
        Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey, EnrollmentChallengeApiVersion,
        LocalEd25519AuthenticatedSubjectV1, MaxContextBytes, MaxEditsPerChangeSet, MaxObjects,
        PrincipalBindingApiVersion, PrincipalBindingV1, PrincipalStatusApiVersion,
        PrincipalStatusV1, SubdelegationDisabled,
    },
    create_agent_principal, initialize_workspace,
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, sign_authority_payload, verify_authority_envelope},
};
use proof_canonical::{canonicalize, parse_strict};
use proof_local::LocalWorkspace;
use serde_json::{Value, json};
use uuid::Uuid;

use p0006_support::{
    BrokerOutcome, canonical_frame, execute_cli_broker, execute_legacy_mcp_broker,
    execute_legacy_mcp_process, execute_legacy_mcp_process_call, execute_modern_mcp_broker,
    execute_modern_mcp_process, execute_modern_mcp_process_call,
};

const AGENT_SELECTED_PATH_CANARY: &str = "p0006-agent-selected-path-must-not-open";

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one retained proof keeps the namespace, signer, and real CLI/MCP process boundaries causally adjacent"
)]
fn distinct_uid_bwrap_signer_feeds_workspace_status_to_cli_and_mcp_process_boundaries() {
    let fixture = AuthorityFixture::new();
    let signer_binary = signer_binary();
    assert!(signer_binary.is_file(), "build proof-agent-signer first");
    assert_bwrap_available();
    assert_bootstrap_uid_is_distinct();
    assert_sandbox_boundary(&signer_binary, fixture.credential_directory());

    let invocations = [0, 1, 2, 3, 4].map(|_| {
        contained_sign(
            &signer_binary,
            fixture.credential_directory(),
            &fixture.command_frame(),
        )
    });
    assert_agent_selected_paths_are_rejected_before_storage(&fixture, &invocations[0]);
    for invocation in &invocations {
        assert_eq!(invocation.command_input, fixture.command_input());
        let verified = verify_authority_envelope::<Value>(
            invocation.authentication.as_str().as_bytes(),
            AuthorityPayloadProfile::AuthenticatedCommand,
            &[fixture.agent_key_id.as_str()],
        )
        .unwrap();
        assert_eq!(
            verified.parsed.payload["binding_id"],
            fixture.binding_id.to_string()
        );
    }
    assert!(
        invocations
            .windows(2)
            .all(|pair| pair[0].authentication != pair[1].authentication),
        "each broker receives a fresh presentation"
    );

    let outcomes = [
        execute_cli_broker(fixture.root(), &invocations[0]),
        execute_modern_mcp_process(fixture.root(), &invocations[1]),
        execute_legacy_mcp_process(fixture.root(), &invocations[2]),
        execute_modern_mcp_broker(fixture.root(), &invocations[3]),
        execute_legacy_mcp_broker(fixture.root(), &invocations[4]),
    ];
    let projections = outcomes.map(|outcome| status_projection(&outcome));
    assert!(
        projections
            .iter()
            .all(|projection| projection == &projections[0])
    );
    assert_eq!(
        projections[0],
        json!({
            "workspace_id": fixture.workspace_id.to_string(),
            "requesting_principal_id": fixture.human_principal_id.to_string(),
            "operating_principal_id": fixture.agent_principal_id.to_string(),
            "delegation_id": fixture.delegation_id.to_string(),
        })
    );

    let database = fixture.repository.open_database().unwrap();
    let decisions: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM authorization_decisions_v2 WHERE operation_name = 'workspace.status'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let consumptions: i64 = database
        .query_row(
            "SELECT COUNT(*) FROM presentation_consumptions_v1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(decisions, 5);
    assert_eq!(consumptions, 5);
}

#[allow(
    clippy::too_many_lines,
    reason = "the retained adversarial proof keeps CLI and both MCP-era rejection boundaries adjacent"
)]
fn assert_agent_selected_paths_are_rejected_before_storage(
    fixture: &AuthorityFixture,
    invocation: &AuthenticatedInvocationV1,
) {
    let selected_workspace_root = fixture
        .directory()
        .join(format!("{AGENT_SELECTED_PATH_CANARY}-workspace"));
    fs::create_dir(&selected_workspace_root).unwrap();
    let selected_workspace = LocalWorkspace::new(&selected_workspace_root).unwrap();
    initialize_workspace(
        &selected_workspace,
        InitializeWorkspaceCommand {
            workspace_id: generated_id(),
            bootstrap_principal_id: generated_id(),
        },
    )
    .unwrap();
    let selected_file = fixture
        .directory()
        .join(format!("{AGENT_SELECTED_PATH_CANARY}-invocation.json"));
    let selected_file_contents = canonical_frame(invocation);
    fs::write(&selected_file, &selected_file_contents).unwrap();

    assert_no_broker_storage(&fixture.repository);
    assert_no_broker_storage(&selected_workspace);

    let file_source = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(fixture.root())
        .args(["--output", "json", "auth", "execute", "--invocation"])
        .arg(&selected_file)
        .output()
        .unwrap();
    assert_eq!(file_source.status.code(), Some(2));
    assert!(file_source.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&file_source.stderr)
            .contains("authenticated Agent transport is stdin-only")
    );

    let selected_workspace_attempt = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(fixture.root())
        .arg("--workspace")
        .arg(&selected_workspace_root)
        .args(["--output", "json", "auth", "execute", "--invocation", "-"])
        .output()
        .unwrap();
    assert!(!selected_workspace_attempt.status.success());
    let selected_workspace_problem = format!(
        "{}{}",
        String::from_utf8_lossy(&selected_workspace_attempt.stdout),
        String::from_utf8_lossy(&selected_workspace_attempt.stderr)
    );
    assert!(selected_workspace_problem.contains("fixed filesystem boundary"));
    assert!(selected_workspace_problem.contains("--workspace is not accepted"));

    let authentication = invocation.authentication.as_str();
    let selected_tool = selected_file.display().to_string();
    for response in [
        execute_modern_mcp_process_call(fixture.root(), &selected_tool, &json!({}), authentication),
        execute_legacy_mcp_process_call(fixture.root(), &selected_tool, &json!({}), authentication),
    ] {
        assert_eq!(response["error"]["code"], -32_602);
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap()
                .contains("Unknown tool")
        );
    }

    let path_shaped_arguments = json!({
        "delegation_id": fixture.delegation_id.to_string(),
        "invocation": selected_file.display().to_string(),
        "operating_principal_id": fixture.agent_principal_id.to_string(),
        "path": selected_file.display().to_string(),
        "tool": selected_tool,
        "workspace": selected_workspace_root.display().to_string(),
    });
    for response in [
        execute_modern_mcp_process_call(
            fixture.root(),
            "proof.workspace.status",
            &path_shaped_arguments,
            authentication,
        ),
        execute_legacy_mcp_process_call(
            fixture.root(),
            "proof.workspace.status",
            &path_shaped_arguments,
            authentication,
        ),
    ] {
        assert_eq!(response["result"]["isError"], true);
        let problem: Value =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(problem["code"], "proof.auth.malformed");
    }

    assert_eq!(
        fs::read_to_string(&selected_file).unwrap(),
        selected_file_contents
    );
    assert_no_broker_storage(&fixture.repository);
    assert_no_broker_storage(&selected_workspace);
}

fn assert_no_broker_storage(repository: &LocalWorkspace) {
    let database = repository.open_database().unwrap();
    for table in ["authorization_decisions_v2", "presentation_consumptions_v1"] {
        let count: i64 = database
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} changed before broker admission");
    }
}

fn assert_bwrap_available() {
    let output = Command::new("bwrap")
        .arg("--version")
        .output()
        .expect("P-0006 qualification requires bubblewrap");
    assert!(output.status.success());
}

fn assert_bootstrap_uid_is_distinct() {
    let output = Command::new("id").arg("-u").output().unwrap();
    assert!(output.status.success());
    let bootstrap_uid = String::from_utf8(output.stdout).unwrap();
    assert_ne!(
        bootstrap_uid.trim(),
        "65534",
        "the retained fixture must bootstrap under a different host UID"
    );
}

fn assert_sandbox_boundary(signer: &Path, credentials: &Path) {
    let mut command = bwrap(signer, credentials);
    command.args([
        "/usr/bin/sh",
        "-ceu",
        concat!(
            "test \"$(id -u)\" = 65534; ",
            "test \"$(id -g)\" = 65534; ",
            "test \"$(stat -c %u /run/proof-agent/credentials)\" = 65534; ",
            "test \"$(stat -c %g /run/proof-agent/credentials)\" = 65534; ",
            "test \"$(stat -c %a /run/proof-agent/credentials)\" = 700; ",
            "test \"$(stat -c %u /run/proof-agent/credentials/agent-a.json)\" = 65534; ",
            "test \"$(stat -c %g /run/proof-agent/credentials/agent-a.json)\" = 65534; ",
            "test \"$(stat -c %a /run/proof-agent/credentials/agent-a.json)\" = 600; ",
            "test -r /run/proof-agent/credentials/agent-a.json; ",
            "test \"$(find /run/proof-agent/credentials -maxdepth 1 -type f | wc -l)\" = 1; ",
            "test ! -e /mnt/d/github/Proof; ",
            "test ! -e /workspace; ",
            "test ! -e /.proof; ",
            "! command -v proof; ",
            "test ! -e /run/proof-agent/credentials/workspace-authority-key.json; ",
            "test ! -e /run/proof-agent/credentials/release-signing-key.json"
        ),
    ]);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn contained_sign(
    signer: &Path,
    credentials: &Path,
    command_frame: &str,
) -> AuthenticatedInvocationV1 {
    let mut command = bwrap(signer, credentials);
    command
        .args([
            "/proof-agent-signer",
            "--command",
            "-",
            "--credential",
            "agent-a",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(command_frame.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_ne!(output.stdout.last(), Some(&b'\n'));
    let value = parse_strict(&output.stdout).unwrap();
    let canonical = canonicalize(&value).unwrap();
    assert_eq!(canonical.as_bytes(), output.stdout);
    serde_json::from_value(value).unwrap()
}

fn bwrap(signer: &Path, credentials: &Path) -> Command {
    let mut command = Command::new("bwrap");
    command
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/run/proof-agent",
            "--ro-bind",
        ])
        .arg(credentials)
        .arg("/run/proof-agent/credentials")
        .arg("--ro-bind")
        .arg(signer)
        .arg("/proof-agent-signer")
        .args(["--chdir", "/"]);
    command
}

fn signer_binary() -> PathBuf {
    let proof = PathBuf::from(env!("CARGO_BIN_EXE_proof"));
    let name = if cfg!(windows) {
        "proof-agent-signer.exe"
    } else {
        "proof-agent-signer"
    };
    proof
        .parent()
        .expect("proof binary has a parent")
        .join(name)
}

fn status_projection(outcome: &BrokerOutcome) -> Value {
    let BrokerOutcome::Success(value) = outcome else {
        panic!("broker returned {outcome:?}");
    };
    json!({
        "workspace_id": value["workspace_id"],
        "requesting_principal_id": value["requesting_principal_id"],
        "operating_principal_id": value["operating_principal_id"],
        "delegation_id": value["delegation_id"],
    })
}

struct AuthorityFixture {
    directory: TestDirectory,
    repository: LocalWorkspace,
    credential_directory: PathBuf,
    agent_key_id: String,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent_principal_id: PrincipalId,
    binding_id: BindingId,
    delegation_id: DelegationId,
}

impl AuthorityFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "the public enrollment and direct Delegation lifecycle establishes the real broker boundary"
    )]
    fn new() -> Self {
        let directory = TestDirectory::new();
        let workspace_root = directory.path().join("workspace");
        fs::create_dir(&workspace_root).unwrap();
        let repository = LocalWorkspace::new(&workspace_root).unwrap();
        let workspace_id = generated_id();
        let human_principal_id = generated_id();
        let agent_principal_id = generated_id();
        let binding_id = generated_id();
        let delegation_id = generated_id();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();

        let setup_at = current_timestamp();
        create_agent_principal(
            &repository,
            CreateAgentPrincipalCommand {
                principal_id: agent_principal_id,
                display_name: "contained-agent".to_owned(),
                idempotency_key: generated_id(),
                created_at: setup_at,
            },
        )
        .unwrap();

        let secret = [42_u8; 32];
        let agent_signer = Ed25519SigningProvider::from_secret_bytes(&secret);
        let metadata = agent_signer.metadata().unwrap();
        let agent_key_id = metadata.key_id.clone();
        let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
        let public_key = Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap();
        let challenge = BindingEnrollmentChallengeV1 {
            api_version: EnrollmentChallengeApiVersion::V1,
            challenge_id: generated_id::<EnrollmentChallengeId>(),
            audience: AuthorityAudience::for_workspace(workspace_id),
            workspace_id,
            binding_id,
            principal_id: agent_principal_id,
            candidate_key_id: key_id.clone(),
            issued_by_principal_id: human_principal_id,
            issued_at: add_seconds(setup_at, -1),
            expires_at: add_seconds(setup_at, 299),
        };
        let recorded_challenge = repository
            .create_binding_enrollment_challenge(challenge.clone())
            .unwrap();
        let enrollment = sign_authority_payload(
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            &challenge,
            &[&agent_signer],
        )
        .unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .issue_principal_binding(
                PrincipalBindingV1 {
                    api_version: PrincipalBindingApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: Some(head.record_digest),
                    workspace_id,
                    binding_id,
                    principal_id: agent_principal_id,
                    principal_type: AgentPrincipalType::Agent,
                    authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
                    algorithm: Ed25519Algorithm::Ed25519,
                    public_key,
                    key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                    audience: AuthorityAudience::for_workspace(workspace_id),
                    enrollment_challenge_digest: recorded_challenge.challenge_digest,
                    enrollment_envelope_digest: enrollment.envelope_digest,
                    issued_by_principal_id: human_principal_id,
                    issued_at: setup_at,
                    not_before: setup_at,
                    expires_at: add_seconds(setup_at, 3_600),
                    supersedes_binding_id: None,
                },
                enrollment.envelope_json,
            )
            .unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .set_principal_status(PrincipalStatusV1 {
                api_version: PrincipalStatusApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                workspace_id,
                principal_id: agent_principal_id,
                principal_type: proof_application::authority::AuthorityPrincipalType::Agent,
                enabled: true,
                recorded_by_principal_id: human_principal_id,
                recorded_at: setup_at,
            })
            .unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .issue_delegation(DelegationV2 {
                api_version: DelegationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                delegation_id,
                workspace_id,
                delegation_profile: DirectAuthorityProfileV1::Direct,
                issuer_principal_id: human_principal_id,
                recipient_principal_id: agent_principal_id,
                actions: DelegationActionsV2::new(vec![AuthorityAction::WorkspaceStatus]).unwrap(),
                scope: DelegationScopeV2 {
                    environment_ids: DelegationEnvironmentIdsV2::new(Vec::new()).unwrap(),
                    object_ids: DelegationObjectIdsV2::new(Vec::new()).unwrap(),
                    schema_ids: DelegationSchemaIdsV2::new(Vec::new()).unwrap(),
                    locales: DelegationLocalesV2::new(Vec::new()).unwrap(),
                },
                constraints: DelegationConstraintsV2 {
                    max_objects: MaxObjects::new(1).unwrap(),
                    max_context_bytes: MaxContextBytes::new(4_096).unwrap(),
                    max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                    allow_subdelegation: SubdelegationDisabled,
                },
                not_before: setup_at,
                expires_at: add_seconds(setup_at, 3_600),
                issued_at: setup_at,
            })
            .unwrap();

        let credential_directory = directory.path().join("credentials");
        fs::create_dir(&credential_directory).unwrap();
        fs::set_permissions(&credential_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let credential_path = credential_directory.join("agent-a.json");
        fs::write(
            &credential_path,
            serde_json::to_vec(&json!({
                "api_version": "proof.dev/local-agent-credential/v1",
                "binding_id": binding_id.to_string(),
                "key_id": agent_key_id,
                "secret_key_hex": "2a".repeat(32),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(credential_path, fs::Permissions::from_mode(0o600)).unwrap();

        Self {
            directory,
            repository,
            credential_directory,
            agent_key_id,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            delegation_id,
        }
    }

    fn root(&self) -> &Path {
        self.repository.root()
    }

    fn directory(&self) -> &Path {
        self.directory.path()
    }

    fn credential_directory(&self) -> &Path {
        &self.credential_directory
    }

    fn command_input(&self) -> CommandInputV1 {
        let mut command = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation: proof_application::authority::AuthorityOperation::WorkspaceStatusV1,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            idempotency_key: None,
            normalized_input: serde_json::Map::new(),
        };
        command.normalize_for_authenticated_execution().unwrap();
        command
    }

    fn command_frame(&self) -> String {
        canonicalize(&serde_json::to_value(self.command_input()).unwrap())
            .unwrap()
            .as_str()
            .to_owned()
    }
}

fn current_timestamp() -> Timestamp {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap()).unwrap()
}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    let nanos = timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000;
    Timestamp::from_unix_timestamp_nanos(nanos).unwrap()
}

fn generated_id<T: std::str::FromStr>() -> T
where
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7().to_string().parse().unwrap()
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("proof-p0006-containment-{}", Uuid::now_v7()));
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
