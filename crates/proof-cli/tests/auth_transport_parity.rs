#![cfg(unix)]

use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    ArtifactKind, BindingId, CreateAgentPrincipalCommand, DelegationId, EnrollmentChallengeId,
    InitializeWorkspaceCommand, PresentationId, PrincipalId, Timestamp, WorkspaceId,
    authority::{
        AgentPrincipalType, AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
        AuthenticatedCommandKeyUsage, AuthenticatedCommandV1, AuthenticatedInvocationApiVersion,
        AuthenticatedInvocationV1, AuthorityAction, AuthorityAdministrator, AuthorityAudience,
        AuthorityExecutionClass, AuthorityOperation, AuthorityRepository, AuthoritySequence,
        AuthorizationDecisionOutcome, AuthorizationDecisionV2, BindingEnrollmentChallengeV1,
        CommandInputApiVersion, CommandInputV1, DelegationActionsV2, DelegationApiVersion,
        DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
        DelegationObjectIdsV2, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
        DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
        EffectiveConstraintsV2, EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1,
        MaxContextBytes, MaxEditsPerChangeSet, MaxObjects, PrincipalBindingApiVersion,
        PrincipalBindingV1, PrincipalStateV2, PrincipalStatusApiVersion, PrincipalStatusV1,
        RequestedResourcesV2, SubdelegationDisabled, WorkspaceStatusInputV1,
        authority_operation_entry,
    },
    create_agent_principal, initialize_workspace,
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, sign_authority_payload},
};
use proof_canonical::{canonicalize, digest};
use proof_local::LocalWorkspace;
use proof_mcp::{LEGACY_PROTOCOL_VERSION, LocalBackend, MODERN_PROTOCOL_VERSION, serve};
use rusqlite::{Connection, types::ValueRef};
use serde_json::{Value, json};
use uuid::Uuid;

const MUTABLE_AUTHORITY_TABLES: [&str; 5] = [
    "authenticated_actor_context_evidence_v1",
    "authenticated_operation_results_v1",
    "authority_records",
    "authorization_decisions_v2",
    "presentation_consumptions_v1",
];

#[test]
fn cli_and_both_mcp_eras_share_real_authenticated_authority_semantics() {
    let fixture = AuthorityFixture::new();
    let governed_before = workspace_snapshot_excluding(
        &fixture.repository.open_database().unwrap(),
        &MUTABLE_AUTHORITY_TABLES,
    );
    let counts_before = authority_execution_counts(&fixture.repository.open_database().unwrap());

    let presentation_ids = [generated_id(), generated_id(), generated_id()];
    let invocations =
        presentation_ids.map(|presentation_id| fixture.status_invocation(presentation_id));

    let cli = execute_cli(fixture.root(), &invocations[0]);
    let modern = execute_modern_mcp(fixture.root(), &invocations[1]);
    let legacy = execute_legacy_mcp(fixture.root(), &invocations[2]);
    let results = [&cli["data"], &modern, &legacy];

    for result in results {
        assert_eq!(result["workspace_id"], fixture.workspace_id.to_string());
        assert_eq!(
            result["requesting_principal_id"],
            fixture.human_principal_id.to_string()
        );
        assert_eq!(
            result["operating_principal_id"],
            fixture.agent_principal_id.to_string()
        );
        assert_eq!(result["delegation_id"], fixture.delegation_id.to_string());
        assert_digest(&result["authorization_decision_digest"]);
    }
    for result in [&modern, &legacy] {
        assert_eq!(
            result["authoritative_sequence"],
            cli["data"]["authoritative_sequence"]
        );
        assert_eq!(result["state_digest"], cli["data"]["state_digest"]);
    }
    assert_eq!(
        cli["data"]["authority"]["requesting_principal_id"],
        fixture.human_principal_id.to_string()
    );
    assert_eq!(
        cli["data"]["authority"]["operating_principal_id"],
        fixture.agent_principal_id.to_string()
    );
    assert_eq!(
        cli["data"]["authority"]["delegation_id"],
        fixture.delegation_id.to_string()
    );
    assert_eq!(
        cli["data"]["authority"]["authorization_decision_digest"],
        cli["data"]["authorization_decision_digest"]
    );

    let connection = fixture.repository.open_database().unwrap();
    let decisions =
        presentation_ids.map(|presentation_id| load_decision(&connection, presentation_id));
    let expected_command_digest = decisions[0].command_digest;
    let expected_projection = SemanticAuthorizationProjection::from(&decisions[0]);
    for (decision, result) in decisions.iter().zip(results) {
        decision.validate().unwrap();
        assert_eq!(decision.command_digest, expected_command_digest);
        assert_eq!(
            SemanticAuthorizationProjection::from(decision),
            expected_projection
        );
        assert_eq!(decision.decision, AuthorizationDecisionOutcome::Allow);
        assert_eq!(
            authority_operation_entry(decision.operation).execution_class,
            AuthorityExecutionClass::EvidenceWrite
        );
        let decision_digest = decision_digest(&connection, decision.presentation_id);
        assert_eq!(
            result["authorization_decision_digest"],
            decision_digest.to_string()
        );
    }

    assert_eq!(
        workspace_snapshot_excluding(&connection, &MUTABLE_AUTHORITY_TABLES),
        governed_before,
        "EvidenceWrite status calls must not mutate governed application state or non-execution authority state"
    );
    assert_eq!(
        authority_execution_counts(&connection),
        counts_before.plus_executions(3)
    );
}

#[test]
fn cli_and_both_mcp_eras_hide_authentication_probe_details_without_writes() {
    let fixture = AuthorityFixture::new();
    let unknown_binding_id = generated_id();
    let wrong_signer = Ed25519SigningProvider::generate().unwrap();
    let full_state_before =
        workspace_snapshot_excluding(&fixture.repository.open_database().unwrap(), &[]);
    let counts_before = authority_execution_counts(&fixture.repository.open_database().unwrap());

    let unknown_binding_invocations =
        [generated_id(), generated_id(), generated_id()].map(|presentation_id| {
            fixture.status_invocation_signed(
                unknown_binding_id,
                &fixture.agent_signer,
                presentation_id,
            )
        });
    let invalid_signature_invocations =
        [generated_id(), generated_id(), generated_id()].map(|presentation_id| {
            fixture.status_invocation_signed(fixture.binding_id, &wrong_signer, presentation_id)
        });

    let cli_unknown = execute_cli_problem(fixture.root(), &unknown_binding_invocations[0]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let cli_invalid = execute_cli_problem(fixture.root(), &invalid_signature_invocations[0]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let modern_unknown =
        execute_modern_mcp_problem(fixture.root(), &unknown_binding_invocations[1]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let modern_invalid =
        execute_modern_mcp_problem(fixture.root(), &invalid_signature_invocations[1]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let legacy_unknown =
        execute_legacy_mcp_problem(fixture.root(), &unknown_binding_invocations[2]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let legacy_invalid =
        execute_legacy_mcp_problem(fixture.root(), &invalid_signature_invocations[2]);
    assert_no_authority_writes(&fixture, counts_before, &full_state_before);
    let problems = [
        [cli_unknown, cli_invalid],
        [modern_unknown, modern_invalid],
        [legacy_unknown, legacy_invalid],
    ];
    let expected = json!({
        "type": "urn:proof:problem:authentication-denied",
        "title": "Agent authentication was denied",
        "code": "proof.auth.denied",
        "detail": null,
    });
    for transport in &problems {
        assert_eq!(
            public_problem_shape(&transport[0]),
            public_problem_shape(&transport[1]),
            "unknown bindings and invalid signatures must be indistinguishable within a transport"
        );
    }
    for problem in problems.iter().flatten() {
        assert_eq!(public_problem_shape(problem), expected);
        assert!(
            problem.get("detail").is_none(),
            "audit-only authentication detail must not cross a public transport"
        );
        assert_eq!(problem["retryable"], false);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticAuthorizationProjection {
    requesting_principal_id: PrincipalId,
    operating_principal_id: PrincipalId,
    delegation_id: DelegationId,
    operation: AuthorityOperation,
    requested_action: AuthorityAction,
    requested_resources: RequestedResourcesV2,
    effective_constraints: EffectiveConstraintsV2,
    principal_state: PrincipalStateV2,
    outcome: AuthorizationDecisionOutcome,
}

impl From<&AuthorizationDecisionV2> for SemanticAuthorizationProjection {
    fn from(decision: &AuthorizationDecisionV2) -> Self {
        Self {
            requesting_principal_id: decision.requesting_principal_id,
            operating_principal_id: decision.operating_principal_id,
            delegation_id: decision.delegation.delegation_id,
            operation: decision.operation,
            requested_action: decision.requested_action,
            requested_resources: decision.requested_resources.clone(),
            effective_constraints: decision.effective_constraints,
            principal_state: decision.principal_state,
            outcome: decision.decision,
        }
    }
}

struct AuthorityFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    agent_signer: Ed25519SigningProvider,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent_principal_id: PrincipalId,
    binding_id: BindingId,
    delegation_id: DelegationId,
    command_issued_at: Timestamp,
    command_expires_at: Timestamp,
}

impl AuthorityFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "the fixture establishes the complete public enrollment and direct-delegation lifecycle"
    )]
    fn new() -> Self {
        let directory = TestDirectory::new();
        let repository = LocalWorkspace::new(directory.path()).unwrap();
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
                display_name: "transport-parity-agent".to_owned(),
                idempotency_key: generated_id(),
                created_at: setup_at,
            },
        )
        .unwrap();

        let agent_signer = Ed25519SigningProvider::generate().unwrap();
        let metadata = agent_signer.metadata().unwrap();
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

        Self {
            _directory: directory,
            repository,
            agent_signer,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            delegation_id,
            command_issued_at: add_seconds(setup_at, -1),
            command_expires_at: add_seconds(setup_at, 299),
        }
    }

    fn root(&self) -> &Path {
        self.repository.root()
    }

    fn status_invocation(&self, presentation_id: PresentationId) -> AuthenticatedInvocationV1 {
        self.status_invocation_signed(self.binding_id, &self.agent_signer, presentation_id)
    }

    fn status_invocation_signed(
        &self,
        binding_id: BindingId,
        signer: &Ed25519SigningProvider,
        presentation_id: PresentationId,
    ) -> AuthenticatedInvocationV1 {
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation: AuthorityOperation::WorkspaceStatusV1,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            idempotency_key: None,
            normalized_input: serde_json::Map::new(),
        };
        assert_eq!(
            command_input
                .normalize_for_authenticated_execution()
                .unwrap(),
            proof_application::authority::EnabledOperationInputV1::WorkspaceStatus(
                WorkspaceStatusInputV1 {},
            )
        );
        let command_json = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command_digest = digest(ArtifactKind::CommandV1, &command_json);
        let command = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation: command_input.operation,
            binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            command_digest,
            idempotency_key: None,
            presentation_id,
            issued_at: self.command_issued_at,
            expires_at: self.command_expires_at,
        };
        let authentication_envelope = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &command,
            &[signer],
        )
        .unwrap();
        AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input,
            authentication: AuthenticatedCommandEnvelopeJson::new(
                authentication_envelope.envelope_json,
            )
            .unwrap(),
        }
    }
}

fn execute_cli(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let output = execute_cli_raw(root, invocation);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn execute_cli_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let output = execute_cli_raw(root, invocation);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn execute_cli_raw(root: &Path, invocation: &AuthenticatedInvocationV1) -> std::process::Output {
    let frame = canonicalize(&serde_json::to_value(invocation).unwrap()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(root)
        .args(["--output", "json", "auth", "execute", "--invocation", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(frame.as_str().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn execute_modern_mcp(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": "modern",
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "dev.proof/authentication": invocation.authentication.as_str(),
            },
            "name": "proof.workspace.status",
            "arguments": status_arguments(invocation),
        }
    });
    let response = serve_real_mcp(root, &[request]);
    assert_eq!(response.len(), 1);
    assert_eq!(response[0]["result"]["resultType"], "complete");
    assert_eq!(response[0]["result"]["isError"], false);
    response[0]["result"]["structuredContent"].clone()
}

fn execute_modern_mcp_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": "modern-denial",
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "dev.proof/authentication": invocation.authentication.as_str(),
            },
            "name": "proof.workspace.status",
            "arguments": status_arguments(invocation),
        }
    });
    let response = serve_real_mcp(root, &[request]);
    assert_eq!(response.len(), 1);
    assert_eq!(response[0]["result"]["resultType"], "complete");
    assert_eq!(response[0]["result"]["isError"], true);
    assert!(response[0]["result"].get("structuredContent").is_none());
    mcp_problem(&response[0])
}

fn execute_legacy_mcp(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "proof-transport-parity", "version": "1" },
            }
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
            "id": "legacy",
            "method": "tools/call",
            "params": {
                "_meta": {
                    "dev.proof/authentication": invocation.authentication.as_str(),
                },
                "name": "proof.workspace.status",
                "arguments": status_arguments(invocation),
            }
        }),
    ];
    let response = serve_real_mcp(root, &requests);
    assert_eq!(
        response.len(),
        2,
        "initialized notifications have no response"
    );
    assert_eq!(
        response[0]["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    assert_eq!(response[1]["result"]["isError"], false);
    assert!(response[1]["result"].get("resultType").is_none());
    response[1]["result"]["structuredContent"].clone()
}

fn execute_legacy_mcp_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let requests = [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize-denial",
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "proof-transport-parity", "version": "1" },
            }
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
            "id": "legacy-denial",
            "method": "tools/call",
            "params": {
                "_meta": {
                    "dev.proof/authentication": invocation.authentication.as_str(),
                },
                "name": "proof.workspace.status",
                "arguments": status_arguments(invocation),
            }
        }),
    ];
    let response = serve_real_mcp(root, &requests);
    assert_eq!(response.len(), 2);
    assert_eq!(
        response[0]["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    assert_eq!(response[1]["result"]["isError"], true);
    assert!(response[1]["result"].get("resultType").is_none());
    assert!(response[1]["result"].get("structuredContent").is_none());
    mcp_problem(&response[1])
}

fn mcp_problem(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn public_problem_shape(problem: &Value) -> Value {
    json!({
        "type": problem["type"],
        "title": problem["title"],
        "code": problem["code"],
        "detail": problem.get("detail").cloned().unwrap_or(Value::Null),
    })
}

fn status_arguments(invocation: &AuthenticatedInvocationV1) -> Value {
    json!({
        "operating_principal_id": invocation.command_input.operating_principal_id.to_string(),
        "delegation_id": invocation.command_input.delegation_id.to_string(),
    })
}

fn serve_real_mcp(root: &Path, requests: &[Value]) -> Vec<Value> {
    let input = requests
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let backend = LocalBackend::new(root).unwrap();
    let mut output = Vec::new();
    serve(Cursor::new(input.as_bytes()), &mut output, &backend).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn load_decision(
    connection: &Connection,
    presentation_id: PresentationId,
) -> AuthorizationDecisionV2 {
    let decision_json: String = connection
        .query_row(
            "SELECT decision_json FROM authorization_decisions_v2 WHERE presentation_id = ?1",
            [presentation_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_str(&decision_json).unwrap()
}

fn decision_digest(
    connection: &Connection,
    presentation_id: PresentationId,
) -> proof_application::ContentDigest {
    connection
        .query_row(
            "SELECT decision_digest FROM authorization_decisions_v2 WHERE presentation_id = ?1",
            [presentation_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
        .parse()
        .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityExecutionCounts {
    authority_records: i64,
    decisions: i64,
    consumptions: i64,
    actor_evidence: i64,
    operation_results: i64,
}

impl AuthorityExecutionCounts {
    fn plus_executions(self, count: i64) -> Self {
        Self {
            authority_records: self.authority_records + count,
            decisions: self.decisions + count,
            consumptions: self.consumptions + count,
            actor_evidence: self.actor_evidence + count,
            operation_results: self.operation_results,
        }
    }
}

fn authority_execution_counts(connection: &Connection) -> AuthorityExecutionCounts {
    connection
        .query_row(
            "SELECT (SELECT COUNT(*) FROM authority_records),
                    (SELECT COUNT(*) FROM authorization_decisions_v2),
                    (SELECT COUNT(*) FROM presentation_consumptions_v1),
                    (SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1),
                    (SELECT COUNT(*) FROM authenticated_operation_results_v1)",
            [],
            |row| {
                Ok(AuthorityExecutionCounts {
                    authority_records: row.get(0)?,
                    decisions: row.get(1)?,
                    consumptions: row.get(2)?,
                    actor_evidence: row.get(3)?,
                    operation_results: row.get(4)?,
                })
            },
        )
        .unwrap()
}

fn assert_no_authority_writes(
    fixture: &AuthorityFixture,
    expected_counts: AuthorityExecutionCounts,
    expected_state: &BTreeMap<String, Vec<Vec<String>>>,
) {
    let connection = fixture.repository.open_database().unwrap();
    assert_eq!(authority_execution_counts(&connection), expected_counts);
    assert_eq!(
        &workspace_snapshot_excluding(&connection, &[]),
        expected_state,
        "pre-consumption authentication denials must leave the full Workspace state unchanged"
    );
}

fn workspace_snapshot_excluding(
    connection: &Connection,
    excluded_tables: &[&str],
) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables.retain(|table| !excluded_tables.contains(&table.as_str()));

    tables
        .into_iter()
        .map(|table| {
            let quoted = table.replace('"', "\"\"");
            let mut statement = connection
                .prepare(&format!("SELECT * FROM \"{quoted}\" ORDER BY rowid"))
                .unwrap();
            let column_count = statement.column_count();
            let rows = statement
                .query_map([], |row| {
                    (0..column_count)
                        .map(|index| row.get_ref(index).map(sqlite_value))
                        .collect::<Result<Vec<_>, _>>()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

fn sqlite_value(value: ValueRef<'_>) -> String {
    match value {
        ValueRef::Null => "null".to_owned(),
        ValueRef::Integer(value) => format!("integer:{value}"),
        ValueRef::Real(value) => format!("real:{:016x}", value.to_bits()),
        ValueRef::Text(value) => format!("text:{}", String::from_utf8_lossy(value)),
        ValueRef::Blob(value) => {
            let mut encoded = String::with_capacity(value.len() * 2 + 5);
            encoded.push_str("blob:");
            for byte in value {
                use std::fmt::Write as _;
                write!(&mut encoded, "{byte:02x}").unwrap();
            }
            encoded
        }
    }
}

fn assert_digest(value: &Value) {
    let value = value.as_str().unwrap();
    assert_eq!(value.len(), 71);
    assert!(value.starts_with("blake3:"));
    assert!(
        value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

fn current_timestamp() -> Timestamp {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap()).unwrap()
}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(
        timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
    )
    .unwrap()
}

fn generated_id<T>() -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7().to_string().parse().unwrap()
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("proof-auth-transport-parity-{}", Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
