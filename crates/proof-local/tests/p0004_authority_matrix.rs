use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    AddChangeSetEditsCommand, AddLocalizedEditsCommand, ApprovalName, ApproveChangeSetCommand,
    ArtifactKind, BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetIntent,
    CommitChangeSetCommand, CommitLocalizedChangeSetCommand, CreateAgentPrincipalCommand,
    CreateChangeSetCommand, CreateEditionCommand, CreateEnvironmentCommand,
    CreateLocalizedChangeSetCommand, CreateLocalizedEditionCommand, EnvironmentId,
    ExpectedLocalizedSource, InitializeWorkspaceCommand, IssueContentResourceIntentCommand,
    LocaleId, LocalizedContentRepository, LocalizedContentTarget, LocalizedContextLimits,
    LocalizedPolicyRule, ObjectCreateEdit, ObjectId, ObjectLocalePutInput, ObjectRevision,
    PrincipalId, PromoteLocalizedReleaseCommand, PromoteReleaseCommand, ProofId, ReleaseId,
    SchemaCreateEdit, SchemaId, SchemaVersion, SubmitChangeSetCommand, Timestamp, WorkspaceId,
    add_changeset_edits, approve_changeset,
    authority::{
        AgentPrincipalType, AuthenticatedAuthorityExecutor, AuthenticatedCommandApiVersion,
        AuthenticatedCommandEnvelopeJson, AuthenticatedCommandKeyUsage, AuthenticatedCommandV1,
        AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationFailureV1, AuthenticatedOperationResultV1, AuthorityAction,
        AuthorityAdministrator, AuthorityAudience, AuthorityError, AuthorityOperation,
        AuthorityPrincipalType, AuthorityRepository, AuthoritySequence,
        AuthorizationDecisionOutcome, AuthorizationDecisionV2, AuthorizationDenialReason,
        BindingEnrollmentChallengeV1, CommandInputApiVersion, CommandInputV1, DelegationActionsV2,
        DelegationApiVersion, DelegationConstraintsV2, DelegationEnvironmentIdsV2,
        DelegationLocalesV2, DelegationObjectIdsV2, DelegationSchemaIdsV2, DelegationScopeV2,
        DelegationV2, DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
        EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1, MaxContextBytes,
        MaxEditsPerChangeSet, MaxObjects, PrincipalBindingApiVersion,
        PrincipalBindingRevocationApiVersion, PrincipalBindingRevocationReason,
        PrincipalBindingRevocationV1, PrincipalBindingV1, PrincipalStatusApiVersion,
        PrincipalStatusV1, SubdelegationDisabled,
    },
    commit_changeset, create_agent_principal, create_changeset, create_edition, create_environment,
    initialize_workspace, promote_release, submit_changeset, validate_changeset,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use rusqlite::types::ValueRef;
use serde_json::{Map, Value, json};

const WORKSPACE_ID: &str = "019d1000-0000-7000-8000-000000000001";
const HUMAN_PRINCIPAL_ID: &str = "019d1000-0000-7000-8000-000000000002";
const BASE_TIME: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 1_001;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x71; 32];
const ENVIRONMENT_ID: &str = "preview";
const OBJECT_ID: &str = "019d1000-0000-7000-8000-000000000020";
const OTHER_OBJECT_ID: &str = "019d1000-0000-7000-8000-000000000021";

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn pre_consumption_matrix_writes_nothing_and_discloses_no_decision() {
    let fixture = MatrixFixture::new(false);
    let delegation_id = fixture.issue_delegation(
        &fixture.first_agent,
        0x200,
        vec![AuthorityAction::WorkspaceStatus],
        Vec::new(),
        Vec::new(),
        1,
        4_096,
    );
    let baseline = fixture.durable_state();
    let governed = fixture.governed_snapshot();

    let mut malformed = fixture.status_invocation(&fixture.first_agent, delegation_id, 0x300);
    malformed
        .command_input
        .normalized_input
        .insert("unexpected".to_owned(), Value::Bool(true));
    fixture.assert_pre_consumption_failure(
        malformed,
        &AuthorityError::AuthMalformed,
        &baseline,
        &governed,
    );

    let (command_input, mut command) =
        fixture.status_command(&fixture.first_agent, delegation_id, 0x301);
    let other_workspace = matrix_id(0x999).parse::<WorkspaceId>().unwrap();
    command.audience = AuthorityAudience::for_workspace(other_workspace);
    fixture.assert_pre_consumption_failure(
        MatrixFixture::sign_invocation(&fixture.first_agent, command_input, &command),
        &AuthorityError::AuthAudienceMismatch,
        &baseline,
        &governed,
    );

    let (command_input, mut command) =
        fixture.status_command(&fixture.first_agent, delegation_id, 0x302);
    command.requesting_principal_id = matrix_id(0x998).parse().unwrap();
    fixture.assert_pre_consumption_failure(
        MatrixFixture::sign_invocation(&fixture.first_agent, command_input, &command),
        &AuthorityError::AuthActorMismatch,
        &baseline,
        &governed,
    );

    let (command_input, mut command) =
        fixture.status_command(&fixture.first_agent, delegation_id, 0x303);
    command.command_digest = digest(ArtifactKind::CommandV1, &canonicalize(&json!({})).unwrap());
    fixture.assert_pre_consumption_failure(
        MatrixFixture::sign_invocation(&fixture.first_agent, command_input, &command),
        &AuthorityError::AuthActorMismatch,
        &baseline,
        &governed,
    );

    let mut invalid_envelope =
        fixture.status_invocation(&fixture.first_agent, delegation_id, 0x304);
    invalid_envelope.authentication = AuthenticatedCommandEnvelopeJson::new("{").unwrap();
    fixture.assert_pre_consumption_failure(
        invalid_envelope,
        &AuthorityError::AuthMalformed,
        &baseline,
        &governed,
    );
}

#[test]
fn binding_revocation_is_a_committed_non_disclosing_denial() {
    let fixture = MatrixFixture::new(false);
    let delegation_id = fixture.issue_delegation(
        &fixture.first_agent,
        0x210,
        vec![AuthorityAction::WorkspaceStatus],
        Vec::new(),
        Vec::new(),
        1,
        4_096,
    );
    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    let revocation = fixture
        .repository
        .revoke_principal_binding(PrincipalBindingRevocationV1 {
            api_version: PrincipalBindingRevocationApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: head.record_digest,
            workspace_id: fixture.workspace_id,
            revocation_id: matrix_id(0x211).parse().unwrap(),
            binding_id: fixture.first_agent.binding_id,
            revoked_by_principal_id: fixture.human_principal_id,
            revoked_at: fixture.time(130),
            reason: PrincipalBindingRevocationReason::Compromise,
        })
        .unwrap();
    let baseline = fixture.durable_state();
    let governed = fixture.governed_snapshot();
    let presentation_id = matrix_id(0x310).parse().unwrap();
    let error = fixture
        .repository
        .execute_authenticated(
            fixture.status_invocation(&fixture.first_agent, delegation_id, 0x310),
            fixture.time(140),
        )
        .unwrap_err();

    assert_eq!(error, AuthorityError::AuthBindingInactive);
    assert_eq!(error.public_code(), "proof.auth.binding_inactive");
    fixture.assert_one_committed_attempt(&baseline);
    assert_eq!(fixture.governed_snapshot(), governed);
    assert_eq!(fixture.operation_result_count(), baseline.operation_results);
    let decision = fixture.decision(presentation_id);
    assert_eq!(decision.decision, AuthorizationDecisionOutcome::Deny);
    assert_eq!(
        decision.reason_code,
        Some(AuthorizationDenialReason::BindingInactive)
    );
    assert_eq!(
        decision.binding.revocation_record_digest,
        Some(revocation.record_digest)
    );
    assert!(decision.delegation.record_digest.is_some());
    decision.validate().unwrap();
}

#[test]
fn action_resource_and_budget_denials_commit_exact_evidence_without_consequence() {
    let action_fixture = MatrixFixture::new(false);
    let action_delegation = action_fixture.issue_delegation(
        &action_fixture.first_agent,
        0x220,
        vec![AuthorityAction::ObjectQueryReleased],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        4_096,
    );
    action_fixture.assert_committed_denial(
        action_fixture.status_invocation(&action_fixture.first_agent, action_delegation, 0x320),
        0x320,
        &AuthorityError::ScopeExceeded,
        AuthorizationDenialReason::ScopeExceeded,
        &[],
        &[],
        1,
    );

    let resource_fixture = MatrixFixture::new(false);
    let resource_delegation = resource_fixture.issue_delegation(
        &resource_fixture.first_agent,
        0x221,
        vec![AuthorityAction::ObjectQueryReleased],
        Vec::new(),
        Vec::new(),
        2,
        4_096,
    );
    resource_fixture.assert_committed_denial(
        resource_fixture.query_invocation(
            &resource_fixture.first_agent,
            resource_delegation,
            0x321,
            ENVIRONMENT_ID,
            &[OBJECT_ID],
        ),
        0x321,
        &AuthorityError::ScopeExceeded,
        AuthorizationDenialReason::ScopeExceeded,
        &[ENVIRONMENT_ID],
        &[OBJECT_ID],
        1,
    );

    let budget_fixture = MatrixFixture::new(false);
    let budget_delegation = budget_fixture.issue_delegation(
        &budget_fixture.first_agent,
        0x222,
        vec![AuthorityAction::ObjectQueryReleased],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap(), OTHER_OBJECT_ID.parse().unwrap()],
        1,
        4_096,
    );
    budget_fixture.assert_committed_denial(
        budget_fixture.query_invocation(
            &budget_fixture.first_agent,
            budget_delegation,
            0x322,
            ENVIRONMENT_ID,
            &[OBJECT_ID, OTHER_OBJECT_ID],
        ),
        0x322,
        &AuthorityError::BudgetExceeded,
        AuthorizationDenialReason::BudgetExceeded,
        &[ENVIRONMENT_ID],
        &[OBJECT_ID, OTHER_OBJECT_ID],
        2,
    );
}

#[test]
fn chain_and_subdelegation_inputs_are_rejected_before_authority_state() {
    let fixture = MatrixFixture::new(false);
    let direct = fixture.delegation_record(
        &fixture.first_agent,
        0x230,
        vec![AuthorityAction::WorkspaceStatus],
        Vec::new(),
        Vec::new(),
        1,
        4_096,
    );
    let baseline = fixture.durable_state();
    let governed = fixture.governed_snapshot();

    // No chained grant can reach `issue_delegation`: `DelegationV2` has no
    // parent field and its only subdelegation value is the false marker.
    let mut parent = serde_json::to_value(&direct).unwrap();
    parent.as_object_mut().unwrap().insert(
        "parent_delegation_id".to_owned(),
        Value::String(matrix_id(0x231)),
    );
    assert!(serde_json::from_value::<DelegationV2>(parent).is_err());

    let mut subdelegation = serde_json::to_value(&direct).unwrap();
    subdelegation["constraints"]["allow_subdelegation"] = Value::Bool(true);
    assert!(serde_json::from_value::<DelegationV2>(subdelegation).is_err());

    let delegation_id = direct.delegation_id;
    fixture.repository.issue_delegation(direct).unwrap();
    let mut invocation = fixture.status_invocation(&fixture.first_agent, delegation_id, 0x330);
    invocation.command_input.normalized_input.insert(
        "parent_delegation_id".to_owned(),
        Value::String(matrix_id(0x231)),
    );
    let after_issue = fixture.durable_state();
    let governed_after_issue = fixture.governed_snapshot();
    fixture.assert_pre_consumption_failure(
        invocation,
        &AuthorityError::AuthMalformed,
        &after_issue,
        &governed_after_issue,
    );
    assert_eq!(baseline.decisions, after_issue.decisions);
    assert_eq!(baseline.consumptions, after_issue.consumptions);
    assert_eq!(baseline.actor_evidence, after_issue.actor_evidence);
    assert_eq!(fixture.governed_snapshot(), governed);
}

#[test]
fn released_query_success_and_not_found_are_committed_allow_outcomes_without_governed_mutation() {
    let success = MatrixFixture::new(true);
    let success_delegation = success.issue_delegation(
        &success.first_agent,
        0x240,
        vec![AuthorityAction::ObjectQueryReleased],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        4_096,
    );
    let baseline = success.durable_state();
    let governed = success.governed_snapshot();
    let execution = success
        .repository
        .execute_authenticated(
            success.query_invocation(
                &success.first_agent,
                success_delegation,
                0x340,
                ENVIRONMENT_ID,
                &[OBJECT_ID],
            ),
            success.time(140),
        )
        .unwrap();
    success.assert_one_committed_attempt(&baseline);
    assert_eq!(success.governed_snapshot(), governed);
    assert_eq!(success.operation_result_count(), baseline.operation_results);
    assert_eq!(
        execution.decision.decision,
        AuthorizationDecisionOutcome::Allow
    );
    assert_eq!(execution.decision.reason_code, None);
    let AuthenticatedOperationResultV1::ReleasedObjectQuery(query) = execution.result else {
        panic!("authorized v1 query did not disclose its released Object result")
    };
    assert_eq!(query.objects.len(), 1);
    assert_eq!(query.objects[0].object_id, OBJECT_ID.parse().unwrap());
    assert_eq!(
        query.authorization_decision_digest,
        execution.decision_record_digest
    );

    let not_found = MatrixFixture::new(false);
    let not_found_delegation = not_found.issue_delegation(
        &not_found.first_agent,
        0x241,
        vec![AuthorityAction::ObjectQueryReleased],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        4_096,
    );
    let baseline = not_found.durable_state();
    let governed = not_found.governed_snapshot();
    let execution = not_found
        .repository
        .execute_authenticated(
            not_found.query_invocation(
                &not_found.first_agent,
                not_found_delegation,
                0x341,
                ENVIRONMENT_ID,
                &[OBJECT_ID],
            ),
            not_found.time(140),
        )
        .unwrap();
    not_found.assert_one_committed_attempt(&baseline);
    assert_eq!(not_found.governed_snapshot(), governed);
    assert_eq!(
        not_found.operation_result_count(),
        baseline.operation_results
    );
    assert_eq!(
        execution.decision.decision,
        AuthorizationDecisionOutcome::Allow
    );
    assert_eq!(execution.decision.reason_code, None);
    assert_eq!(
        execution.result,
        AuthenticatedOperationResultV1::Failure(
            AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound
        )
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the regression binds one successful owner to both cross-Agent and changed-input conflicts"
)]
fn application_idempotency_key_is_workspace_global_across_agent_and_semantic_input() {
    let fixture = MatrixFixture::new(true);
    let first_delegation = fixture.issue_delegation(
        &fixture.first_agent,
        0x250,
        vec![AuthorityAction::ContextBuild],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        16_384,
    );
    let application_key = matrix_id(0x350).parse().unwrap();
    let baseline = fixture.durable_state();
    let first = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(
                &fixture.first_agent,
                first_delegation,
                0x351,
                application_key,
                "release-summary",
            ),
            fixture.time(140),
        )
        .unwrap();
    fixture.assert_one_committed_attempt(&baseline);
    assert!(matches!(
        first.result,
        AuthenticatedOperationResultV1::ContextPack(_)
    ));
    assert_eq!(fixture.context_result_counts(), (1, 1, 1));
    let first_command_digest = first.decision.command_digest;

    let second_agent = enroll_agent(
        &fixture.repository,
        fixture.workspace_id,
        fixture.human_principal_id,
        fixture.base_time,
        0x110,
        0x43,
    );
    let second_delegation = fixture.issue_delegation(
        &second_agent,
        0x251,
        vec![AuthorityAction::ContextBuild],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        16_384,
    );
    let before_cross_agent = fixture.durable_state();
    let cross_agent_error = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(
                &second_agent,
                second_delegation,
                0x352,
                application_key,
                "release-summary",
            ),
            fixture.time(150),
        )
        .unwrap_err();
    assert_eq!(cross_agent_error, AuthorityError::IdempotencyKeyReused);
    fixture.assert_one_committed_attempt(&before_cross_agent);
    assert_eq!(fixture.context_result_counts(), (1, 1, 1));
    let cross_agent_decision = fixture.decision(matrix_id(0x352).parse().unwrap());
    assert_eq!(
        cross_agent_decision.decision,
        AuthorizationDecisionOutcome::Deny
    );
    assert_eq!(
        cross_agent_decision.reason_code,
        Some(AuthorizationDenialReason::IdempotencyKeyReused)
    );
    assert_eq!(
        cross_agent_decision.operating_principal_id,
        second_agent.principal_id
    );
    assert_ne!(cross_agent_decision.command_digest, first_command_digest);

    let before_changed_input = fixture.durable_state();
    let changed_input_error = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(
                &fixture.first_agent,
                first_delegation,
                0x353,
                application_key,
                "different-semantic-task",
            ),
            fixture.time(160),
        )
        .unwrap_err();
    assert_eq!(changed_input_error, AuthorityError::IdempotencyKeyReused);
    fixture.assert_one_committed_attempt(&before_changed_input);
    assert_eq!(fixture.context_result_counts(), (1, 1, 1));
    let changed_input_decision = fixture.decision(matrix_id(0x353).parse().unwrap());
    assert_eq!(
        changed_input_decision.reason_code,
        Some(AuthorizationDenialReason::IdempotencyKeyReused)
    );
    assert_ne!(changed_input_decision.command_digest, first_command_digest);

    let (owner, stored_digest): (String, String) = fixture
        .repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT operating_principal_id, command_digest
             FROM authenticated_operation_results_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            (
                fixture.workspace_id.to_string(),
                application_key.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(owner, fixture.first_agent.principal_id.to_string());
    assert_eq!(stored_digest, first_command_digest.to_string());
}

#[test]
fn released_query_unsupported_version_is_a_committed_allow_failure_without_projection_movement() {
    let fixture = MatrixFixture::new(true);
    prepare_localized_release(&fixture.repository);
    let delegation_id = fixture.issue_delegation(
        &fixture.first_agent,
        0x260,
        vec![AuthorityAction::ObjectQueryReleased],
        vec![ENVIRONMENT_ID.parse().unwrap()],
        vec![OBJECT_ID.parse().unwrap()],
        1,
        4_096,
    );
    let baseline = fixture.durable_state();
    let governed = fixture.governed_snapshot();
    let execution = fixture
        .repository
        .execute_authenticated(
            fixture.query_invocation(
                &fixture.first_agent,
                delegation_id,
                0x360,
                ENVIRONMENT_ID,
                &[OBJECT_ID],
            ),
            fixture.time(140),
        )
        .unwrap();

    fixture.assert_one_committed_attempt(&baseline);
    assert_eq!(fixture.governed_snapshot(), governed);
    assert_eq!(fixture.operation_result_count(), baseline.operation_results);
    assert_eq!(
        execution.decision.decision,
        AuthorizationDecisionOutcome::Allow
    );
    assert_eq!(execution.decision.reason_code, None);
    assert_eq!(
        execution.result,
        AuthenticatedOperationResultV1::Failure(
            AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion
        )
    );
}

struct MatrixFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    first_agent: AgentCredential,
    base_time: Timestamp,
}

impl MatrixFixture {
    fn new(with_release: bool) -> Self {
        let directory = TestDirectory::new();
        let base_time = BASE_TIME.parse::<Timestamp>().unwrap();
        let repository = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            DeterministicLocalAuthorityAdapter::new(
                DETERMINISTIC_UID,
                add_seconds(base_time, 30),
                DETERMINISTIC_SUBJECT_BLIND,
            ),
        )
        .unwrap();
        let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
        let human_principal_id = HUMAN_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();
        if with_release {
            prepare_v1_release(&repository);
        }
        let first_agent = enroll_agent(
            &repository,
            workspace_id,
            human_principal_id,
            base_time,
            0x100,
            0x42,
        );
        Self {
            _directory: directory,
            repository,
            workspace_id,
            human_principal_id,
            first_agent,
            base_time,
        }
    }

    fn time(&self, seconds: i64) -> Timestamp {
        add_seconds(self.base_time, seconds)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the test helper exposes every independently varied direct-grant axis"
    )]
    fn delegation_record(
        &self,
        agent: &AgentCredential,
        id: u64,
        actions: Vec<AuthorityAction>,
        environment_ids: Vec<EnvironmentId>,
        object_ids: Vec<ObjectId>,
        max_objects: u32,
        max_context_bytes: u32,
    ) -> DelegationV2 {
        let head = self
            .repository
            .authority_head(self.workspace_id)
            .unwrap()
            .unwrap();
        DelegationV2 {
            api_version: DelegationApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            delegation_id: matrix_id(id).parse().unwrap(),
            workspace_id: self.workspace_id,
            delegation_profile: DirectAuthorityProfileV1::Direct,
            issuer_principal_id: self.human_principal_id,
            recipient_principal_id: agent.principal_id,
            actions: DelegationActionsV2::new(actions).unwrap(),
            scope: DelegationScopeV2 {
                environment_ids: DelegationEnvironmentIdsV2::new(environment_ids).unwrap(),
                object_ids: DelegationObjectIdsV2::new(object_ids).unwrap(),
                schema_ids: DelegationSchemaIdsV2::new(Vec::new()).unwrap(),
                locales: DelegationLocalesV2::new(Vec::new()).unwrap(),
            },
            constraints: DelegationConstraintsV2 {
                max_objects: MaxObjects::new(max_objects).unwrap(),
                max_context_bytes: MaxContextBytes::new(max_context_bytes).unwrap(),
                max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                allow_subdelegation: SubdelegationDisabled,
            },
            not_before: self.time(23),
            expires_at: self.time(3_600),
            issued_at: self.time(23),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the test helper exposes every independently varied direct-grant axis"
    )]
    fn issue_delegation(
        &self,
        agent: &AgentCredential,
        id: u64,
        actions: Vec<AuthorityAction>,
        environment_ids: Vec<EnvironmentId>,
        object_ids: Vec<ObjectId>,
        max_objects: u32,
        max_context_bytes: u32,
    ) -> proof_application::DelegationId {
        let delegation = self.delegation_record(
            agent,
            id,
            actions,
            environment_ids,
            object_ids,
            max_objects,
            max_context_bytes,
        );
        let delegation_id = delegation.delegation_id;
        self.repository.issue_delegation(delegation).unwrap();
        delegation_id
    }

    fn status_command(
        &self,
        agent: &AgentCredential,
        delegation_id: proof_application::DelegationId,
        presentation: u64,
    ) -> (CommandInputV1, AuthenticatedCommandV1) {
        self.command(
            agent,
            delegation_id,
            presentation,
            AuthorityOperation::WorkspaceStatusV1,
            Map::new(),
            None,
        )
    }

    fn status_invocation(
        &self,
        agent: &AgentCredential,
        delegation_id: proof_application::DelegationId,
        presentation: u64,
    ) -> AuthenticatedInvocationV1 {
        let (command_input, command) = self.status_command(agent, delegation_id, presentation);
        Self::sign_invocation(agent, command_input, &command)
    }

    fn query_invocation(
        &self,
        agent: &AgentCredential,
        delegation_id: proof_application::DelegationId,
        presentation: u64,
        environment_id: &str,
        object_ids: &[&str],
    ) -> AuthenticatedInvocationV1 {
        let normalized_input = json!({
            "delegation_id": delegation_id.to_string(),
            "environment_id": environment_id,
            "object_ids": object_ids,
            "operating_principal_id": agent.principal_id.to_string(),
        })
        .as_object()
        .unwrap()
        .clone();
        let (command_input, command) = self.command(
            agent,
            delegation_id,
            presentation,
            AuthorityOperation::ObjectQueryReleasedV1,
            normalized_input,
            None,
        );
        Self::sign_invocation(agent, command_input, &command)
    }

    fn context_invocation(
        &self,
        agent: &AgentCredential,
        delegation_id: proof_application::DelegationId,
        presentation: u64,
        idempotency_key: proof_application::IdempotencyKey,
        task_id: &str,
    ) -> AuthenticatedInvocationV1 {
        let normalized_input = json!({
            "delegation_id": delegation_id.to_string(),
            "environment_id": ENVIRONMENT_ID,
            "expires_at": self.time(600).to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "intent": "Summarize the released campaign",
            "max_bytes": 16_384,
            "max_objects": 1,
            "object_ids": [OBJECT_ID],
            "operating_principal_id": agent.principal_id.to_string(),
            "task_id": task_id,
        })
        .as_object()
        .unwrap()
        .clone();
        let (command_input, command) = self.command(
            agent,
            delegation_id,
            presentation,
            AuthorityOperation::ContextBuildV1,
            normalized_input,
            Some(idempotency_key),
        );
        Self::sign_invocation(agent, command_input, &command)
    }

    fn command(
        &self,
        agent: &AgentCredential,
        delegation_id: proof_application::DelegationId,
        presentation: u64,
        operation: AuthorityOperation,
        normalized_input: Map<String, Value>,
        idempotency_key: Option<proof_application::IdempotencyKey>,
    ) -> (CommandInputV1, AuthenticatedCommandV1) {
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: agent.principal_id,
            delegation_id,
            idempotency_key,
            normalized_input,
        };
        command_input
            .normalize_for_authenticated_execution()
            .unwrap();
        let canonical = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation,
            binding_id: agent.binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: agent.principal_id,
            delegation_id,
            command_digest: digest(ArtifactKind::CommandV1, &canonical),
            idempotency_key,
            presentation_id: matrix_id(presentation).parse().unwrap(),
            issued_at: self.time(100),
            expires_at: self.time(300),
        };
        (command_input, command)
    }

    fn sign_invocation(
        agent: &AgentCredential,
        command_input: CommandInputV1,
        command: &AuthenticatedCommandV1,
    ) -> AuthenticatedInvocationV1 {
        let envelope = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            command,
            &[&agent.signer],
        )
        .unwrap();
        AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input,
            authentication: AuthenticatedCommandEnvelopeJson::new(envelope.envelope_json).unwrap(),
        }
    }

    fn assert_pre_consumption_failure(
        &self,
        invocation: AuthenticatedInvocationV1,
        expected: &AuthorityError,
        baseline: &DurableState,
        governed: &TableSnapshot,
    ) {
        let actual = self
            .repository
            .execute_authenticated(invocation, self.time(140))
            .unwrap_err();
        assert_eq!(&actual, expected);
        assert_eq!(&self.durable_state(), baseline);
        assert_eq!(&self.governed_snapshot(), governed);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the assertion binds denial reason, disclosed projection, and exact durable tuple"
    )]
    fn assert_committed_denial(
        &self,
        invocation: AuthenticatedInvocationV1,
        presentation: u64,
        expected_error: &AuthorityError,
        expected_reason: AuthorizationDenialReason,
        expected_environments: &[&str],
        expected_objects: &[&str],
        expected_effective_max_objects: u32,
    ) {
        let baseline = self.durable_state();
        let governed = self.governed_snapshot();
        let error = self
            .repository
            .execute_authenticated(invocation, self.time(140))
            .unwrap_err();
        assert_eq!(&error, expected_error);
        self.assert_one_committed_attempt(&baseline);
        assert_eq!(self.governed_snapshot(), governed);
        assert_eq!(self.operation_result_count(), baseline.operation_results);
        let decision = self.decision(matrix_id(presentation).parse().unwrap());
        assert_eq!(decision.decision, AuthorizationDecisionOutcome::Deny);
        assert_eq!(decision.reason_code, Some(expected_reason));
        assert_eq!(
            decision
                .requested_resources
                .environment_ids
                .as_slice()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            expected_environments
        );
        assert_eq!(
            decision
                .requested_resources
                .object_ids
                .as_slice()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            expected_objects
        );
        assert_eq!(
            decision.effective_constraints.max_objects.get(),
            expected_effective_max_objects
        );
        decision.validate().unwrap();
    }

    fn assert_one_committed_attempt(&self, baseline: &DurableState) {
        let after = self.durable_state();
        assert_eq!(after.head_sequence, baseline.head_sequence + 1);
        assert_eq!(after.authority_records, baseline.authority_records + 1);
        assert_eq!(after.decisions, baseline.decisions + 1);
        assert_eq!(after.consumptions, baseline.consumptions + 1);
        assert_eq!(after.actor_evidence, baseline.actor_evidence + 1);
    }

    fn durable_state(&self) -> DurableState {
        let connection = self.repository.open_database().unwrap();
        let (authority_records, decisions, consumptions, actor_evidence, operation_results) =
            connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM authority_records),
                            (SELECT COUNT(*) FROM authorization_decisions_v2),
                            (SELECT COUNT(*) FROM presentation_consumptions_v1),
                            (SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1),
                            (SELECT COUNT(*) FROM authenticated_operation_results_v1)",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
        DurableState {
            head_sequence: self
                .repository
                .authority_head(self.workspace_id)
                .unwrap()
                .unwrap()
                .sequence
                .get(),
            authority_records,
            decisions,
            consumptions,
            actor_evidence,
            operation_results,
        }
    }

    fn operation_result_count(&self) -> i64 {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM authenticated_operation_results_v1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn context_result_counts(&self) -> (i64, i64, i64) {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM context_packs),
                        (SELECT COUNT(*) FROM context_pack_build_operations),
                        (SELECT COUNT(*) FROM authenticated_operation_results_v1)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap()
    }

    fn decision(
        &self,
        presentation_id: proof_application::PresentationId,
    ) -> AuthorizationDecisionV2 {
        let json: String = self
            .repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT decision_json FROM authorization_decisions_v2
                 WHERE presentation_id = ?1",
                [presentation_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn governed_snapshot(&self) -> TableSnapshot {
        governed_snapshot(&self.repository.open_database().unwrap())
    }
}

struct AgentCredential {
    principal_id: PrincipalId,
    binding_id: proof_application::BindingId,
    signer: Ed25519SigningProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DurableState {
    head_sequence: u64,
    authority_records: i64,
    decisions: i64,
    consumptions: i64,
    actor_evidence: i64,
    operation_results: i64,
}

type TableSnapshot = Vec<(String, Vec<Vec<String>>)>;

fn enroll_agent(
    repository: &LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    base_time: Timestamp,
    id_namespace: u64,
    secret_byte: u8,
) -> AgentCredential {
    let principal_id = matrix_id(id_namespace).parse::<PrincipalId>().unwrap();
    let binding_id = matrix_id(id_namespace + 2).parse().unwrap();
    create_agent_principal(
        repository,
        CreateAgentPrincipalCommand {
            principal_id,
            display_name: format!("matrix-agent-{id_namespace:x}"),
            idempotency_key: matrix_id(id_namespace + 1).parse().unwrap(),
            created_at: base_time,
        },
    )
    .unwrap();
    let signer = Ed25519SigningProvider::from_secret_bytes(&[secret_byte; 32]);
    let metadata = signer.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
    let public_key = Ed25519PublicKey::new(BASE64.encode(metadata.public_key)).unwrap();
    let challenge = BindingEnrollmentChallengeV1 {
        api_version: EnrollmentChallengeApiVersion::V1,
        challenge_id: matrix_id(id_namespace + 3).parse().unwrap(),
        audience: AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        binding_id,
        principal_id,
        candidate_key_id: key_id.clone(),
        issued_by_principal_id: human_principal_id,
        issued_at: add_seconds(base_time, 20),
        expires_at: add_seconds(base_time, 320),
    };
    let recorded = repository
        .create_binding_enrollment_challenge(challenge.clone())
        .unwrap();
    let envelope = sign_authority_payload(
        AuthorityPayloadProfile::BindingEnrollmentChallenge,
        &challenge,
        &[&signer],
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
                principal_id,
                principal_type: AgentPrincipalType::Agent,
                authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
                algorithm: Ed25519Algorithm::Ed25519,
                public_key,
                key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                audience: AuthorityAudience::for_workspace(workspace_id),
                enrollment_challenge_digest: recorded.challenge_digest,
                enrollment_envelope_digest: envelope.envelope_digest,
                issued_by_principal_id: human_principal_id,
                issued_at: add_seconds(base_time, 21),
                not_before: add_seconds(base_time, 21),
                expires_at: add_seconds(base_time, 3_600),
                supersedes_binding_id: None,
            },
            envelope.envelope_json,
        )
        .unwrap();
    let head = repository.authority_head(workspace_id).unwrap().unwrap();
    repository
        .set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            workspace_id,
            principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled: true,
            recorded_by_principal_id: human_principal_id,
            recorded_at: add_seconds(base_time, 22),
        })
        .unwrap();
    AgentCredential {
        principal_id,
        binding_id,
        signer,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the retained fixture constructs the complete public v1 source-to-Release baseline"
)]
fn prepare_v1_release(repository: &LocalWorkspace) {
    let source = json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let changeset_id = matrix_id(0x20).parse().unwrap();
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Create matrix source").unwrap(),
            requested_base_state: None,
            idempotency_key: matrix_id(0x22).parse().unwrap(),
            created_at: "2026-08-20T10:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let schema_id = SchemaId::new("campaign").unwrap();
    let schema_document = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": { "type": "string" },
            "slug": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["legal", "slug", "title"],
        "type": "object",
        "x-proof-localizable": ["/legal", "/title"],
    });
    let canonical_schema = canonicalize(&schema_document).unwrap();
    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical_source = canonicalize(&source).unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id,
            edits: vec![
                ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                    edit_id: matrix_id(0x23).parse().unwrap(),
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_document: canonical_schema.as_str().to_owned(),
                    document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical_schema),
                }),
                ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                    edit_id: matrix_id(0x24).parse().unwrap(),
                    object_id,
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_content: canonical_source.as_str().to_owned(),
                    object_digest: object_revision_digest(
                        object_id,
                        &schema_id,
                        schema_version,
                        &source,
                    )
                    .unwrap(),
                }),
            ],
            idempotency_key: matrix_id(0x25).parse().unwrap(),
        },
    )
    .unwrap();
    assert!(validate_changeset(repository, changeset_id).unwrap().valid);
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id,
            submitted_at: "2026-08-20T10:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id,
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-20T10:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id,
            idempotency_key: matrix_id(0x26).parse().unwrap(),
            committed_at: "2026-08-20T10:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let edition_id = matrix_id(0x27).parse().unwrap();
    create_edition(
        repository,
        CreateEditionCommand {
            edition_id,
            idempotency_key: matrix_id(0x28).parse().unwrap(),
            created_at: "2026-08-20T10:04:00Z".parse().unwrap(),
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
            idempotency_key: matrix_id(0x29).parse().unwrap(),
            created_at: "2026-08-20T10:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        repository,
        PromoteReleaseCommand {
            release_id: matrix_id(0x2a).parse::<ReleaseId>().unwrap(),
            proof_id: matrix_id(0x2b).parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id,
            idempotency_key: matrix_id(0x2c).parse().unwrap(),
            released_at: "2026-08-20T10:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "the retained unsupported-version case constructs the smallest public v1-to-v2 Release transition"
)]
fn prepare_localized_release(repository: &LocalWorkspace) {
    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new("campaign").unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let locale = "fr-FR".parse::<LocaleId>().unwrap();
    let source = json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let expected_source = ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap(),
        schema_id: schema_id.clone(),
        schema_version,
    };
    let intent = repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: matrix_id(0x40).parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id,
                schema_id,
                locale: locale.clone(),
            }],
            idempotency_key: matrix_id(0x41).parse().unwrap(),
            issued_at: "2026-08-20T10:07:00Z".parse().unwrap(),
        })
        .unwrap();
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: matrix_id(0x42).parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: locale.clone(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Forbidden terms".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 1,
                max_validation_attempts: 1,
                max_bytes: 65_536,
            },
            idempotency_key: matrix_id(0x43).parse().unwrap(),
            created_at: "2026-08-20T10:08:00Z".parse().unwrap(),
            expires_at: "2026-08-21T10:08:00Z".parse().unwrap(),
        })
        .unwrap();
    let changeset_id = matrix_id(0x44).parse().unwrap();
    repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Create one localized rendition").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: matrix_id(0x45).parse().unwrap(),
            created_at: "2026-08-20T10:09:00Z".parse().unwrap(),
        })
        .unwrap();
    let localized = canonicalize(&json!({
        "legal": "Les conditions standard s’appliquent",
        "slug": "summer-campaign",
        "title": "Campagne d’été",
    }))
    .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id,
                locale,
                expected_source,
                expected_target: None,
                canonical_content: localized.as_str().to_owned(),
                supersedes_edit_id: None,
                repair_of_validation_result_digest: None,
            }],
            assigned_edit_ids: vec![matrix_id(0x46).parse().unwrap()],
            idempotency_key: matrix_id(0x47).parse().unwrap(),
        })
        .unwrap();
    assert!(
        repository
            .validate_localized_changeset(changeset_id)
            .unwrap()
            .valid
    );
    repository
        .submit_localized_changeset(changeset_id, "2026-08-20T10:10:00Z".parse().unwrap())
        .unwrap();
    repository
        .approve_localized_changeset(
            changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-20T10:11:00Z".parse().unwrap(),
        )
        .unwrap();
    let committed = repository
        .commit_localized_changeset(CommitLocalizedChangeSetCommand {
            changeset_id,
            idempotency_key: matrix_id(0x48).parse().unwrap(),
            committed_at: "2026-08-20T10:12:00Z".parse().unwrap(),
        })
        .unwrap();
    let edition = repository
        .create_localized_edition(CreateLocalizedEditionCommand {
            edition_id: matrix_id(0x49).parse().unwrap(),
            changeset_id,
            resulting_state_digest: committed.resulting_state.digest,
            idempotency_key: matrix_id(0x4a).parse().unwrap(),
            created_at: "2026-08-20T10:13:00Z".parse().unwrap(),
        })
        .unwrap();
    repository
        .promote_localized_release(PromoteLocalizedReleaseCommand {
            release_id: matrix_id(0x4b).parse().unwrap(),
            proof_id: matrix_id(0x4c).parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: edition.edition_id,
            expected_base_release_id: matrix_id(0x2a).parse().unwrap(),
            idempotency_key: matrix_id(0x4d).parse().unwrap(),
            released_at: "2026-08-20T10:14:00Z".parse().unwrap(),
        })
        .unwrap();
}

fn governed_snapshot(connection: &rusqlite::Connection) -> TableSnapshot {
    const AUTHORITY_TABLES: &[&str] = &[
        "authenticated_actor_context_evidence_v1",
        "authenticated_operation_results_v1",
        "authenticated_subject_commitment_openings_v1",
        "authority_records",
        "authorization_decisions_v2",
        "binding_enrollment_challenges",
        "delegation_revocations_v2",
        "delegations_v2",
        "presentation_consumptions_v1",
        "principal_binding_revocations_v1",
        "principal_bindings_v1",
        "principal_status_v1",
        "workspace_authority_roots",
    ];
    let names = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|name| {
            name != "sqlite_sequence"
                && !AUTHORITY_TABLES.contains(&name.as_str())
                && name != "schema_migrations"
                && name != "workspace_metadata"
        })
        .collect::<Vec<_>>();
    names
        .into_iter()
        .map(|name| {
            let quoted = name.replace('"', "\"\"");
            let rows = snapshot_rows(connection, &format!("SELECT * FROM \"{quoted}\""));
            (name, rows)
        })
        .collect()
}

fn snapshot_rows(connection: &rusqlite::Connection, sql: &str) -> Vec<Vec<String>> {
    let mut statement = connection.prepare(sql).unwrap();
    let column_count = statement.column_count();
    let mut rows = statement
        .query_map([], |row| {
            (0..column_count)
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        ValueRef::Null => "null".to_owned(),
                        ValueRef::Integer(value) => format!("integer:{value}"),
                        ValueRef::Real(value) => format!("real:{value:?}"),
                        ValueRef::Text(value) => {
                            format!("text:{}", String::from_utf8_lossy(value))
                        }
                        ValueRef::Blob(value) => format!("blob:{value:?}"),
                    })
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    rows.sort();
    rows
}

fn matrix_id(value: u64) -> String {
    format!("019d1000-0000-7000-8000-{value:012x}")
}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(
        timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
    )
    .unwrap()
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-p0004-authority-matrix-{}-{sequence}",
            std::process::id()
        ));
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
