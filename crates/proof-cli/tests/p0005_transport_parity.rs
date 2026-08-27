#![cfg(unix)]

use std::{
    fs,
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    AddChangeSetEditsCommand, ApprovalName, ApproveChangeSetCommand, ArtifactKind, BindingId,
    BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetIntent, CommitChangeSetCommand,
    CreateAgentPrincipalCommand, CreateChangeSetCommand, CreateEditionCommand,
    CreateEnvironmentCommand, DelegationId, EditionId, EnrollmentChallengeId, ExitCode,
    IdempotencyKey, InitializeWorkspaceCommand, IssueContentResourceIntentCommand, LocaleId,
    LocalizedContentRepository, LocalizedContentTarget, LocalizedContextLimits,
    LocalizedContextPack, LocalizedPolicyRule, ObjectCreateEdit, ObjectId, PresentationId,
    PrincipalId, PromoteReleaseCommand, ProofId, ReleaseId, SchemaCreateEdit, SchemaId,
    SchemaVersion, SubmitChangeSetCommand, Timestamp, WorkspaceId, add_changeset_edits,
    approve_changeset,
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
        EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1,
        LocalizedOperationSuccessV1, MaxContextBytes, MaxEditsPerChangeSet, MaxObjects,
        PrincipalBindingApiVersion, PrincipalBindingV1, PrincipalStatusApiVersion,
        PrincipalStatusV1, SubdelegationDisabled, authority_operation_entry,
    },
    commit_changeset, create_agent_principal, create_changeset, create_edition, create_environment,
    initialize_workspace, promote_release, submit_changeset, validate_changeset,
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, sign_authority_payload, verify_authority_envelope},
};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::LocalWorkspace;
use proof_mcp::{LEGACY_PROTOCOL_VERSION, LocalBackend, MODERN_PROTOCOL_VERSION, serve};
use rusqlite::{Connection, params};
use serde_json::{Map, Value, json};
use uuid::Uuid;

const ENVIRONMENT_ID: &str = "preview";
const SCHEMA_ID: &str = "transport-page";
const LOCALE: &str = "fr-FR";

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained boundary test keeps all three real transports and their persisted authority cross-links visible"
)]
fn p0005_localized_v2_is_semantically_identical_across_cli_and_both_mcp_eras() {
    let fixture = Fixture::new();
    let success_input = fixture.context_input();
    let success_key = fixture.context_key;
    let success_presentations = [generated_id(), generated_id(), generated_id()];
    let success_invocations = success_presentations.map(|presentation_id| {
        fixture.invocation(success_input.clone(), success_key, presentation_id)
    });
    let before = Counts::load(&fixture.connection());

    let cli = execute_cli_success(fixture.root(), &success_invocations[0]);
    let modern = execute_modern_success(fixture.root(), &success_invocations[1]);
    let legacy = execute_legacy_success(fixture.root(), &success_invocations[2]);
    assert_eq!(cli, modern);
    assert_eq!(modern, legacy);
    let typed_output = LocalizedOperationSuccessV1::ContextBuilt(fixture.context.clone())
        .output_value()
        .unwrap();
    assert_eq!(cli, typed_output);

    let connection = fixture.connection();
    let after_success = Counts::load(&connection);
    assert_eq!(after_success, before.plus_localized_executions(3, 1));
    assert_eq!(count(&connection, "localized_context_packs"), 1);
    assert_eq!(count(&connection, "localized_context_build_operations"), 1);

    let decisions = success_presentations.map(|id| load_decision(&connection, id));
    let consequences = success_presentations.map(|id| load_consequence(&connection, id));
    let first_decision = &decisions[0];
    let first_consequence = &consequences[0];
    let expected_result_json = canonicalize(&cli).unwrap();
    let expected_result_digest = digest(ArtifactKind::OperationEffectV1, &expected_result_json);
    let source_effect_digest = load_context_effect_digest(&connection, &fixture);
    let entry = authority_operation_entry(AuthorityOperation::ContextBuildV2);
    assert_eq!(
        entry.execution_class,
        AuthorityExecutionClass::EvidenceWrite
    );

    for (index, (decision, consequence)) in decisions.iter().zip(&consequences).enumerate() {
        decision.validate().unwrap();
        assert_eq!(decision.decision, AuthorizationDecisionOutcome::Allow);
        assert_eq!(decision.operation, AuthorityOperation::ContextBuildV2);
        assert_eq!(decision.requested_action, AuthorityAction::ContextBuild);
        assert_eq!(decision.command_digest, first_decision.command_digest);
        assert_eq!(
            decision.requested_resources,
            first_decision.requested_resources
        );
        assert_eq!(
            decision.effective_constraints,
            first_decision.effective_constraints
        );
        assert_eq!(decision.requesting_principal_id, fixture.human_principal_id);
        assert_eq!(decision.operating_principal_id, fixture.agent_principal_id);
        assert_eq!(decision.delegation.delegation_id, fixture.delegation_id);
        assert_eq!(decision.presentation_id, success_presentations[index]);

        let commitment = decision
            .localized_consequence_commitment
            .as_ref()
            .expect("localized Allow must sign its exact result and consequence");
        assert_eq!(commitment.result_digest, expected_result_digest);
        assert_eq!(
            commitment.result_digest.to_string(),
            consequence.result_digest
        );
        assert_eq!(
            commitment.application_consequence_digest.to_string(),
            consequence.application_consequence_digest
        );
        assert_eq!(consequence.command_digest, first_consequence.command_digest);
        assert_eq!(consequence.result_json, expected_result_json.as_str());
        assert_eq!(consequence.application_effect_digest, source_effect_digest);
        assert_eq!(
            consequence.requesting_principal_id,
            fixture.human_principal_id.to_string()
        );
        assert_eq!(
            consequence.operating_principal_id,
            fixture.agent_principal_id.to_string()
        );
        assert_eq!(consequence.delegation_id, fixture.delegation_id.to_string());
        assert_eq!(consequence.operation_name, "context.build");
        assert_eq!(
            consequence.operation_version,
            "proof.dev/operation/context.build/v2"
        );
        assert_eq!(consequence.result_kind, "success");
        assert_eq!(
            consequence.result_contract,
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/contextBuildOutput"
        );

        let evidence: Value = serde_json::from_str(&consequence.evidence_json).unwrap();
        assert_eq!(
            evidence["requesting_principal_id"],
            fixture.human_principal_id.to_string()
        );
        assert_eq!(
            evidence["operating_principal_id"],
            fixture.agent_principal_id.to_string()
        );
        assert_eq!(evidence["delegation_id"], fixture.delegation_id.to_string());
        assert_eq!(evidence["command_digest"], first_consequence.command_digest);
        assert_eq!(
            evidence["result"]["digest"],
            expected_result_digest.to_string()
        );
        assert_eq!(evidence["application_effect_digest"], source_effect_digest);
    }
    assert!(consequences.windows(2).all(
        |pair| pair[0].application_consequence_digest == pair[1].application_consequence_digest
    ));

    let failure_key: IdempotencyKey = generated_id();
    let failure_input = fixture.missing_context_input(failure_key);
    let failure_presentations = [generated_id(), generated_id(), generated_id()];
    let failure_invocations = failure_presentations.map(|presentation_id| {
        fixture.invocation(failure_input.clone(), failure_key, presentation_id)
    });
    let cli_problem = execute_cli_problem(fixture.root(), &failure_invocations[0]);
    let modern_problem = execute_modern_problem(fixture.root(), &failure_invocations[1]);
    let legacy_problem = execute_legacy_problem(fixture.root(), &failure_invocations[2]);
    assert_eq!(
        public_problem_shape(&cli_problem),
        public_problem_shape(&modern_problem)
    );
    assert_eq!(
        public_problem_shape(&modern_problem),
        public_problem_shape(&legacy_problem)
    );
    assert_eq!(cli_problem["code"], "proof.resource.not_found");

    let after_failure = Counts::load(&connection);
    assert_eq!(after_failure, after_success.plus_localized_executions(3, 0));
    assert_eq!(count(&connection, "localized_context_packs"), 1);
    assert_eq!(count(&connection, "localized_context_build_operations"), 1);
    for presentation_id in failure_presentations {
        let decision = load_decision(&connection, presentation_id);
        let consequence = load_consequence(&connection, presentation_id);
        let commitment = decision.localized_consequence_commitment.unwrap();
        assert_eq!(decision.decision, AuthorizationDecisionOutcome::Allow);
        assert_eq!(consequence.result_kind, "failure");
        assert_eq!(
            consequence.result_contract,
            "proof.dev/result/localized-operation-problem/v1"
        );
        assert_eq!(
            commitment.result_digest.to_string(),
            consequence.result_digest
        );
        assert_eq!(
            commitment.application_consequence_digest.to_string(),
            consequence.application_consequence_digest
        );
    }
}

struct Fixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent_principal_id: PrincipalId,
    binding_id: BindingId,
    delegation_id: DelegationId,
    signer: Ed25519SigningProvider,
    command_issued_at: Timestamp,
    command_expires_at: Timestamp,
    context: LocalizedContextPack,
    context_key: IdempotencyKey,
}

impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "the fixture uses only public Human and authority APIs to establish one released localized resource"
    )]
    fn new() -> Self {
        let directory = TestDirectory::new();
        let repository = LocalWorkspace::new(directory.path()).unwrap();
        let now = current_timestamp();
        let workspace_id = generated_id();
        let human_principal_id = generated_id();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();

        let object_id: ObjectId = generated_id();
        prepare_release(&repository, object_id, now);
        let intent = repository
            .issue_content_resource_intent(IssueContentResourceIntentCommand {
                creations: Vec::new(),
                intent_id: generated_id(),
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![LocalizedContentTarget {
                    object_id,
                    schema_id: SchemaId::new(SCHEMA_ID).unwrap(),
                    locale: LOCALE.parse::<LocaleId>().unwrap(),
                }],
                idempotency_key: generated_id(),
                issued_at: add_seconds(now, -30),
            })
            .unwrap();
        let context_key = generated_id();
        let context = repository
            .build_localized_context(BuildLocalizedContextCommand {
                context_pack_id: generated_id(),
                resource_intent_id: intent.intent_id,
                resource_intent_digest: intent.intent_digest,
                policy_rules: vec![LocalizedPolicyRule {
                    locale: LOCALE.parse().unwrap(),
                    pointer: "/title".to_owned(),
                    disallowed_values: vec!["forbidden".to_owned()],
                }],
                limits: LocalizedContextLimits {
                    max_objects: 1,
                    max_edits: 1,
                    max_validation_attempts: 1,
                    max_bytes: 65_536,
                },
                idempotency_key: context_key,
                created_at: add_seconds(now, -20),
                expires_at: add_seconds(now, 3_600),
            })
            .unwrap();
        assert_eq!(context.principal_id, human_principal_id);

        let agent_principal_id = generated_id();
        let binding_id = generated_id();
        create_agent_principal(
            &repository,
            CreateAgentPrincipalCommand {
                principal_id: agent_principal_id,
                display_name: "p0005-transport-parity-agent".to_owned(),
                idempotency_key: generated_id(),
                created_at: add_seconds(now, -15),
            },
        )
        .unwrap();
        let signer = Ed25519SigningProvider::generate().unwrap();
        enroll_binding(
            &repository,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            &signer,
            now,
        );

        let delegation_id = generated_id();
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
                actions: DelegationActionsV2::new(vec![AuthorityAction::ContextBuild]).unwrap(),
                scope: DelegationScopeV2 {
                    environment_ids: DelegationEnvironmentIdsV2::new(vec![
                        ENVIRONMENT_ID.parse().unwrap(),
                    ])
                    .unwrap(),
                    object_ids: DelegationObjectIdsV2::new(vec![object_id]).unwrap(),
                    schema_ids: DelegationSchemaIdsV2::new(vec![SchemaId::new(SCHEMA_ID).unwrap()])
                        .unwrap(),
                    locales: DelegationLocalesV2::new(vec![LOCALE.parse().unwrap()]).unwrap(),
                },
                constraints: DelegationConstraintsV2 {
                    max_objects: MaxObjects::new(1).unwrap(),
                    max_context_bytes: MaxContextBytes::new(65_536).unwrap(),
                    max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                    allow_subdelegation: SubdelegationDisabled,
                },
                not_before: add_seconds(now, -10),
                expires_at: add_seconds(now, 3_600),
                issued_at: add_seconds(now, -10),
            })
            .unwrap();

        Self {
            _directory: directory,
            repository,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            delegation_id,
            signer,
            command_issued_at: add_seconds(now, -5),
            command_expires_at: add_seconds(now, 295),
            context,
            context_key,
        }
    }

    fn root(&self) -> &Path {
        self.repository.root()
    }

    fn connection(&self) -> Connection {
        self.repository.open_database().unwrap()
    }

    fn context_input(&self) -> Map<String, Value> {
        object(&json!({
            "api_version": "proof.dev/operation/context.build/v2",
            "context_pack_id": self.context.context_pack_id.to_string(),
            "created_at": self.context.created_at.to_string(),
            "expires_at": self.context.expires_at.to_string(),
            "idempotency_key": self.context_key.to_string(),
            "limits": {
                "max_bytes": self.context.limits.max_bytes,
                "max_edits": self.context.limits.max_edits,
                "max_objects": self.context.limits.max_objects,
                "max_validation_attempts": self.context.limits.max_validation_attempts,
            },
            "policy_rules": [{
                "disallowed_values": ["forbidden"],
                "locale": LOCALE,
                "pointer": "/title",
            }],
            "resource_intent_digest": self.context.resource_intent_digest.to_string(),
            "resource_intent_id": self.context.resource_intent_id.to_string(),
        }))
    }

    fn missing_context_input(&self, idempotency_key: IdempotencyKey) -> Map<String, Value> {
        let mut input = self.context_input();
        input.insert(
            "context_pack_id".to_owned(),
            Value::String(generated_id::<Uuid>().to_string()),
        );
        input.insert(
            "idempotency_key".to_owned(),
            Value::String(idempotency_key.to_string()),
        );
        input
    }

    fn invocation(
        &self,
        normalized_input: Map<String, Value>,
        idempotency_key: IdempotencyKey,
        presentation_id: PresentationId,
    ) -> AuthenticatedInvocationV1 {
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation: AuthorityOperation::ContextBuildV2,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            idempotency_key: Some(idempotency_key),
            normalized_input,
        };
        command_input
            .normalize_for_authenticated_execution()
            .unwrap();
        let command_json = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation: command_input.operation,
            binding_id: self.binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            command_digest: digest(ArtifactKind::CommandV1, &command_json),
            idempotency_key: Some(idempotency_key),
            presentation_id,
            issued_at: self.command_issued_at,
            expires_at: self.command_expires_at,
        };
        let envelope = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &command,
            &[&self.signer],
        )
        .unwrap();
        AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input,
            authentication: AuthenticatedCommandEnvelopeJson::new(envelope.envelope_json).unwrap(),
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the public P7 setup preserves the full source-to-Release integrity chain used by ContextPack replay"
)]
fn prepare_release(repository: &LocalWorkspace, object_id: ObjectId, now: Timestamp) {
    let changeset_id = generated_id();
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Create transport parity source").unwrap(),
            requested_base_state: None,
            idempotency_key: generated_id(),
            created_at: add_seconds(now, -300),
        },
    )
    .unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "slug": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["slug", "title"],
        "type": "object",
        "x-proof-localizable": ["/title"],
    });
    let content = json!({ "slug": "transport-parity", "title": "Transport parity" });
    let canonical_schema = canonicalize(&schema).unwrap();
    let canonical_content = canonicalize(&content).unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id,
            edits: vec![
                ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                    edit_id: generated_id(),
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_document: canonical_schema.as_str().to_owned(),
                    document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical_schema),
                }),
                ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                    edit_id: generated_id(),
                    object_id,
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_content: canonical_content.as_str().to_owned(),
                    object_digest: object_revision_digest(
                        object_id,
                        &schema_id,
                        schema_version,
                        &content,
                    )
                    .unwrap(),
                }),
            ],
            idempotency_key: generated_id(),
        },
    )
    .unwrap();
    assert!(validate_changeset(repository, changeset_id).unwrap().valid);
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id,
            submitted_at: add_seconds(now, -280),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id,
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: add_seconds(now, -270),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id,
            idempotency_key: generated_id(),
            committed_at: add_seconds(now, -260),
        },
    )
    .unwrap();
    let edition_id: EditionId = generated_id();
    create_edition(
        repository,
        CreateEditionCommand {
            edition_id,
            idempotency_key: generated_id(),
            created_at: add_seconds(now, -250),
        },
    )
    .unwrap();
    create_environment(
        repository,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: generated_id(),
            created_at: add_seconds(now, -240),
        },
    )
    .unwrap();
    promote_release(
        repository,
        PromoteReleaseCommand {
            release_id: generated_id::<ReleaseId>(),
            proof_id: generated_id::<ProofId>(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id,
            idempotency_key: generated_id(),
            released_at: add_seconds(now, -230),
        },
    )
    .unwrap();
}

fn enroll_binding(
    repository: &LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent_principal_id: PrincipalId,
    binding_id: BindingId,
    signer: &Ed25519SigningProvider,
    now: Timestamp,
) {
    let metadata = signer.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
    let challenge = BindingEnrollmentChallengeV1 {
        api_version: EnrollmentChallengeApiVersion::V1,
        challenge_id: generated_id::<EnrollmentChallengeId>(),
        audience: AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        binding_id,
        principal_id: agent_principal_id,
        candidate_key_id: key_id.clone(),
        issued_by_principal_id: human_principal_id,
        issued_at: add_seconds(now, -15),
        expires_at: add_seconds(now, 285),
    };
    let recorded = repository
        .create_binding_enrollment_challenge(challenge.clone())
        .unwrap();
    let enrollment = sign_authority_payload(
        AuthorityPayloadProfile::BindingEnrollmentChallenge,
        &challenge,
        &[signer],
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
                public_key: Ed25519PublicKey::new(BASE64.encode(metadata.public_key)).unwrap(),
                key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                audience: AuthorityAudience::for_workspace(workspace_id),
                enrollment_challenge_digest: recorded.challenge_digest,
                enrollment_envelope_digest: enrollment.envelope_digest,
                issued_by_principal_id: human_principal_id,
                issued_at: add_seconds(now, -14),
                not_before: add_seconds(now, -14),
                expires_at: add_seconds(now, 3_600),
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
            recorded_at: add_seconds(now, -13),
        })
        .unwrap();
}

fn execute_cli_success(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let output = execute_cli(root, invocation);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["data"].clone()
}

fn execute_cli_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let output = execute_cli(root, invocation);
    assert_eq!(
        output.status.code(),
        Some(i32::from(ExitCode::NotFound as u8))
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn execute_cli(root: &Path, invocation: &AuthenticatedInvocationV1) -> std::process::Output {
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
        .write_all(frame.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn execute_modern_success(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let response = serve_mcp(root, &[modern_request(invocation, "modern-success")]);
    assert_eq!(response.len(), 1);
    assert_eq!(response[0]["result"]["resultType"], "complete");
    assert_eq!(response[0]["result"]["isError"], false);
    response[0]["result"]["structuredContent"].clone()
}

fn execute_modern_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let response = serve_mcp(root, &[modern_request(invocation, "modern-failure")]);
    assert_eq!(response.len(), 1);
    assert_eq!(response[0]["result"]["isError"], true);
    mcp_problem(&response[0])
}

fn modern_request(invocation: &AuthenticatedInvocationV1, id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "dev.proof/authentication": invocation.authentication.as_str(),
            },
            "name": "proof.context.build.v2",
            "arguments": tool_arguments(invocation),
        },
    })
}

fn execute_legacy_success(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let response = serve_mcp(root, &legacy_requests(invocation, "legacy-success"));
    assert_eq!(response.len(), 2);
    assert_eq!(
        response[0]["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    assert_eq!(response[1]["result"]["isError"], false);
    response[1]["result"]["structuredContent"].clone()
}

fn execute_legacy_problem(root: &Path, invocation: &AuthenticatedInvocationV1) -> Value {
    let response = serve_mcp(root, &legacy_requests(invocation, "legacy-failure"));
    assert_eq!(response.len(), 2);
    assert_eq!(response[1]["result"]["isError"], true);
    mcp_problem(&response[1])
}

fn legacy_requests(invocation: &AuthenticatedInvocationV1, id: &str) -> [Value; 3] {
    [
        json!({
            "jsonrpc": "2.0",
            "id": format!("{id}-initialize"),
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "p0005-transport-parity", "version": "1" },
            },
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "_meta": { "dev.proof/authentication": invocation.authentication.as_str() },
                "name": "proof.context.build.v2",
                "arguments": tool_arguments(invocation),
            },
        }),
    ]
}

fn tool_arguments(invocation: &AuthenticatedInvocationV1) -> Value {
    let mut arguments = invocation.command_input.normalized_input.clone();
    arguments.insert(
        "operating_principal_id".to_owned(),
        Value::String(invocation.command_input.operating_principal_id.to_string()),
    );
    arguments.insert(
        "delegation_id".to_owned(),
        Value::String(invocation.command_input.delegation_id.to_string()),
    );
    Value::Object(arguments)
}

fn serve_mcp(root: &Path, requests: &[Value]) -> Vec<Value> {
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

fn mcp_problem(response: &Value) -> Value {
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

fn public_problem_shape(problem: &Value) -> Value {
    json!({
        "type": problem["type"],
        "title": problem["title"],
        "code": problem["code"],
        "retryable": problem["retryable"],
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counts {
    decisions: i64,
    consumptions: i64,
    actor_evidence: i64,
    localized_consequences: i64,
    global_keys: i64,
}

impl Counts {
    fn load(connection: &Connection) -> Self {
        connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM authorization_decisions_v2),
                        (SELECT COUNT(*) FROM presentation_consumptions_v1),
                        (SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1),
                        (SELECT COUNT(*) FROM authenticated_localized_consequences_v1),
                        (SELECT COUNT(*) FROM authenticated_application_idempotency_v1)",
                [],
                |row| {
                    Ok(Self {
                        decisions: row.get(0)?,
                        consumptions: row.get(1)?,
                        actor_evidence: row.get(2)?,
                        localized_consequences: row.get(3)?,
                        global_keys: row.get(4)?,
                    })
                },
            )
            .unwrap()
    }

    const fn plus_localized_executions(self, executions: i64, global_keys: i64) -> Self {
        Self {
            decisions: self.decisions + executions,
            consumptions: self.consumptions + executions,
            actor_evidence: self.actor_evidence + executions,
            localized_consequences: self.localized_consequences + executions,
            global_keys: self.global_keys + global_keys,
        }
    }
}

#[derive(Debug)]
struct ConsequenceRow {
    requesting_principal_id: String,
    operating_principal_id: String,
    delegation_id: String,
    command_digest: String,
    operation_name: String,
    operation_version: String,
    result_kind: String,
    result_contract: String,
    result_json: String,
    result_digest: String,
    application_effect_digest: String,
    application_consequence_digest: String,
    evidence_json: String,
}

fn load_decision(
    connection: &Connection,
    presentation_id: PresentationId,
) -> AuthorizationDecisionV2 {
    let (decision_json, envelope_json, authority_key_id): (String, String, String) = connection
        .query_row(
            "SELECT decisions.decision_json, records.envelope_json, records.authority_key_id
             FROM authorization_decisions_v2 AS decisions
             JOIN authority_records AS records
               ON records.authority_sequence = decisions.authority_sequence
             WHERE decisions.presentation_id = ?1",
            [presentation_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let verified = verify_authority_envelope::<AuthorizationDecisionV2>(
        envelope_json.as_bytes(),
        AuthorityPayloadProfile::AuthorityRecord,
        &[authority_key_id.as_str()],
    )
    .unwrap();
    assert_eq!(verified.parsed.payload_json, decision_json);
    verified.parsed.payload
}

fn load_consequence(connection: &Connection, presentation_id: PresentationId) -> ConsequenceRow {
    connection
        .query_row(
            "SELECT requesting_principal_id, operating_principal_id, delegation_id,
                    command_digest, operation_name, operation_version, result_kind,
                    result_contract, result_json, result_digest, application_effect_digest,
                    application_consequence_digest, evidence_json
             FROM authenticated_localized_consequences_v1 WHERE presentation_id = ?1",
            [presentation_id.to_string()],
            |row| {
                Ok(ConsequenceRow {
                    requesting_principal_id: row.get(0)?,
                    operating_principal_id: row.get(1)?,
                    delegation_id: row.get(2)?,
                    command_digest: row.get(3)?,
                    operation_name: row.get(4)?,
                    operation_version: row.get(5)?,
                    result_kind: row.get(6)?,
                    result_contract: row.get(7)?,
                    result_json: row.get(8)?,
                    result_digest: row.get(9)?,
                    application_effect_digest: row.get(10)?,
                    application_consequence_digest: row.get(11)?,
                    evidence_json: row.get(12)?,
                })
            },
        )
        .unwrap()
}

fn load_context_effect_digest(connection: &Connection, fixture: &Fixture) -> String {
    connection
        .query_row(
            "SELECT effect_digest FROM localized_context_build_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            params![
                fixture.workspace_id.to_string(),
                fixture.human_principal_id.to_string(),
                fixture.context_key.to_string(),
            ],
            |row| row.get(0),
        )
        .unwrap()
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("proof-p0005-transport-parity-{}", Uuid::now_v7()));
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
