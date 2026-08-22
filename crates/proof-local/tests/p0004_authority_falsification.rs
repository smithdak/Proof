use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    AddChangeSetEditsCommand, ApprovalName, ApproveChangeSetCommand, ArtifactKind,
    AuthorityRootTransitionId, BindingId, ChangeSetEdit, ChangeSetId, ChangeSetIntent,
    CommitChangeSetCommand, ContentDigest, CreateAgentPrincipalCommand, CreateChangeSetCommand,
    CreateEditionCommand, CreateEnvironmentCommand, EditId, EditionId, EnrollmentChallengeId,
    EnvironmentId, IdempotencyKey, InitializeWorkspaceCommand, ObjectCreateEdit, ObjectId,
    PrincipalId, PromoteReleaseCommand, ProofId, ReleaseId, RevocationId, SchemaCreateEdit,
    SchemaId, SchemaVersion, SubmitChangeSetCommand, Timestamp, WorkspaceId, add_changeset_edits,
    approve_changeset,
    authority::{
        AgentPrincipalType, AuthenticatedAuthorityExecutor, AuthenticatedCommandApiVersion,
        AuthenticatedCommandEnvelopeJson, AuthenticatedCommandKeyUsage, AuthenticatedCommandV1,
        AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationResultV1, AuthorityAction, AuthorityAdministrator, AuthorityAudience,
        AuthorityError, AuthorityOperation, AuthorityPrincipalType, AuthorityRepository,
        AuthoritySequence, AuthorizationDenialReason, BindingEnrollmentChallengeV1,
        CommandInputApiVersion, CommandInputV1, DelegationActionsV2, DelegationApiVersion,
        DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
        DelegationObjectIdsV2, DelegationRevocationApiVersion, DelegationRevocationReasonV1,
        DelegationRevocationV1, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
        DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
        EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1, MaxContextBytes,
        MaxEditsPerChangeSet, MaxObjects, PrincipalBindingApiVersion,
        PrincipalBindingRevocationApiVersion, PrincipalBindingRevocationReason,
        PrincipalBindingRevocationV1, PrincipalBindingV1, PrincipalStatusApiVersion,
        PrincipalStatusV1, SubdelegationDisabled, WorkspaceAuthorityRootTransitionApiVersion,
        WorkspaceAuthorityRootTransitionV1,
    },
    commit_changeset, create_agent_principal, create_changeset, create_edition, create_environment,
    initialize_workspace, promote_release, submit_changeset, validate_changeset,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use rusqlite::types::ValueRef;

const WORKSPACE_ID: &str = "019d2000-0000-7000-8000-000000000001";
const HUMAN_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-000000000002";
const AGENT_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-000000000003";
const AGENT_CREATE_KEY: &str = "019d2000-0000-7000-8000-000000000004";
const BINDING_ID: &str = "019d2000-0000-7000-8000-000000000005";
const CHALLENGE_ID: &str = "019d2000-0000-7000-8000-000000000006";
const DELEGATION_ID: &str = "019d2000-0000-7000-8000-000000000007";
const FIRST_PRESENTATION_ID: &str = "019d2000-0000-7000-8000-000000000008";
const SECOND_PRESENTATION_ID: &str = "019d2000-0000-7000-8000-000000000009";
const FUTURE_BINDING_ID: &str = "019d2000-0000-7000-8000-00000000000a";
const FUTURE_CHALLENGE_ID: &str = "019d2000-0000-7000-8000-00000000000b";
const REUSED_BINDING_ID: &str = "019d2000-0000-7000-8000-00000000000c";
const REUSED_CHALLENGE_ID: &str = "019d2000-0000-7000-8000-00000000000d";
const DISABLED_PRESENTATION_ID: &str = "019d2000-0000-7000-8000-00000000000e";
const OTHER_AGENT_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-00000000000f";
const CHANGESET_ID: &str = "019d2000-0000-7000-8000-000000000010";
const CHANGESET_CREATE_KEY: &str = "019d2000-0000-7000-8000-000000000011";
const SCHEMA_EDIT_ID: &str = "019d2000-0000-7000-8000-000000000012";
const OBJECT_EDIT_ID: &str = "019d2000-0000-7000-8000-000000000013";
const CHANGESET_ADD_KEY: &str = "019d2000-0000-7000-8000-000000000014";
const CHANGESET_COMMIT_KEY: &str = "019d2000-0000-7000-8000-000000000015";
const EDITION_ID: &str = "019d2000-0000-7000-8000-000000000016";
const EDITION_CREATE_KEY: &str = "019d2000-0000-7000-8000-000000000017";
const ENVIRONMENT_CREATE_KEY: &str = "019d2000-0000-7000-8000-000000000018";
const RELEASE_ID: &str = "019d2000-0000-7000-8000-000000000019";
const PROOF_ID: &str = "019d2000-0000-7000-8000-00000000001a";
const RELEASE_PROMOTE_KEY: &str = "019d2000-0000-7000-8000-00000000001b";
const CONTEXT_BUILD_KEY: &str = "019d2000-0000-7000-8000-00000000001c";
const OBJECT_ID: &str = "019d2000-0000-7000-8000-000000000020";
const OTHER_AGENT_CREATE_KEY: &str = "019d2000-0000-7000-8000-000000000021";
const CROSS_PRINCIPAL_BINDING_ID: &str = "019d2000-0000-7000-8000-000000000022";
const CROSS_PRINCIPAL_CHALLENGE_ID: &str = "019d2000-0000-7000-8000-000000000023";
const PENDING_BINDING_ID: &str = "019d2000-0000-7000-8000-000000000024";
const PENDING_CHALLENGE_ID: &str = "019d2000-0000-7000-8000-000000000025";
const EXPIRED_BINDING_ID: &str = "019d2000-0000-7000-8000-000000000026";
const EXPIRED_CHALLENGE_ID: &str = "019d2000-0000-7000-8000-000000000027";
const REVOCATION_ID: &str = "019d2000-0000-7000-8000-000000000028";
const ROOT_TRANSITION_ID: &str = "019d2000-0000-7000-8000-000000000029";
const UNBOUND_AGENT_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-00000000002a";
const UNBOUND_AGENT_CREATE_KEY: &str = "019d2000-0000-7000-8000-00000000002b";
const UNBOUND_DELEGATION_ID: &str = "019d2000-0000-7000-8000-00000000002c";
const DISABLED_AGENT_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-00000000002d";
const DISABLED_AGENT_CREATE_KEY: &str = "019d2000-0000-7000-8000-00000000002e";
const DISABLED_DELEGATION_ID: &str = "019d2000-0000-7000-8000-00000000002f";
const SCHEMA_ID: &str = "article";
const ENVIRONMENT_ID: &str = "production";
const BASE_TIME: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 2_004;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x54; 32];
const AUTHORITY_SIGNING_KEY_RELATIVE_PATH: &str = ".proof/state/authority-signing.ed25519";
const RELEASE_SIGNING_KEY_RELATIVE_PATH: &str = ".proof/state/release-signing.ed25519";
const SUCCESSOR_STAGING_KEY_RELATIVE_PATH: &str = ".proof/state/authority-successor.ed25519";

#[test]
fn fresh_context_presentation_replays_exact_result_and_projection_tamper_fails_closed() {
    let fixture = ContextFixture::new();
    let first = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(FIRST_PRESENTATION_ID, fixture.binding_id, &fixture.signer),
            fixture.time(120),
        )
        .unwrap();
    first.validate().unwrap();
    let AuthenticatedOperationResultV1::ContextPack(first_pack) = &first.result else {
        panic!("authenticated Context build did not return its immutable pack");
    };

    let second = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(SECOND_PRESENTATION_ID, fixture.binding_id, &fixture.signer),
            fixture.time(121),
        )
        .unwrap();
    second.validate().unwrap();
    let AuthenticatedOperationResultV1::ContextPack(second_pack) = &second.result else {
        panic!("fresh Context retry did not return the original immutable pack");
    };

    assert_eq!(second_pack, first_pack);
    assert_eq!(second_pack.built_at, fixture.time(120));
    assert_eq!(second.decision.evaluated_at, fixture.time(121));
    assert_ne!(second.decision_record_digest, first.decision_record_digest);
    assert_eq!(fixture.context_durable_counts(), (1, 1, 1, 2, 2));

    let connection = fixture.repository.open_database().unwrap();
    let original_result_json: String = connection
        .query_row(
            "SELECT result_json FROM authenticated_operation_results_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            (WORKSPACE_ID, CONTEXT_BUILD_KEY),
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        connection
            .execute(
                "UPDATE authenticated_operation_results_v1 SET result_json = '{}'
                 WHERE workspace_id = ?1 AND idempotency_key = ?2",
                (WORKSPACE_ID, CONTEXT_BUILD_KEY),
            )
            .unwrap(),
        1
    );
    drop(connection);
    assert!(matches!(
        fixture.repository.authority_head(fixture.workspace_id),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));

    let connection = fixture.repository.open_database().unwrap();
    connection
        .execute(
            "UPDATE authenticated_operation_results_v1 SET result_json = ?1
             WHERE workspace_id = ?2 AND idempotency_key = ?3",
            (original_result_json, WORKSPACE_ID, CONTEXT_BUILD_KEY),
        )
        .unwrap();
    drop(connection);
    fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap();

    let connection = fixture.repository.open_database().unwrap();
    assert_eq!(
        connection
            .execute(
                "DELETE FROM authenticated_operation_results_v1
                 WHERE workspace_id = ?1 AND idempotency_key = ?2",
                (WORKSPACE_ID, CONTEXT_BUILD_KEY),
            )
            .unwrap(),
        1
    );
    drop(connection);
    assert!(matches!(
        fixture.repository.authority_head(fixture.workspace_id),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
}

#[derive(Clone, Copy, Debug)]
enum CurrentAuthorityInvalidation {
    BindingRotation,
    DelegationRevocation,
    PrincipalDisablement,
}

impl CurrentAuthorityInvalidation {
    const ALL: [Self; 3] = [
        Self::BindingRotation,
        Self::DelegationRevocation,
        Self::PrincipalDisablement,
    ];

    fn apply(self, fixture: &ContextFixture) {
        match self {
            Self::BindingRotation => fixture.enroll_binding(
                FUTURE_CHALLENGE_ID,
                FUTURE_BINDING_ID.parse().unwrap(),
                &Ed25519SigningProvider::from_secret_bytes(&[0x43; 32]),
                Some(fixture.binding_id),
                fixture.time(121),
                fixture.time(1_000),
            ),
            Self::DelegationRevocation => {
                let head = fixture
                    .repository
                    .authority_head(fixture.workspace_id)
                    .unwrap()
                    .unwrap();
                fixture
                    .repository
                    .revoke_delegation(DelegationRevocationV1 {
                        api_version: DelegationRevocationApiVersion::V1,
                        authority_sequence: AuthoritySequence::new(head.sequence.get() + 1)
                            .unwrap(),
                        previous_authority_record_digest: head.record_digest,
                        workspace_id: fixture.workspace_id,
                        revocation_id: REVOCATION_ID.parse().unwrap(),
                        delegation_id: fixture.delegation_id,
                        revoked_by_principal_id: fixture.human_principal_id,
                        revoked_at: fixture.time(121),
                        reason: DelegationRevocationReasonV1::IssuerRequest,
                    })
                    .unwrap();
            }
            Self::PrincipalDisablement => fixture
                .set_agent_enabled(fixture.agent_principal_id, false, fixture.time(121))
                .unwrap(),
        }
    }

    const fn expected_error(self) -> AuthorityError {
        match self {
            Self::BindingRotation => AuthorityError::AuthBindingInactive,
            Self::DelegationRevocation => AuthorityError::DelegationRevoked,
            Self::PrincipalDisablement => AuthorityError::PrincipalDisabled,
        }
    }

    const fn expected_reason(self) -> AuthorizationDenialReason {
        match self {
            Self::BindingRotation => AuthorizationDenialReason::BindingInactive,
            Self::DelegationRevocation => AuthorizationDenialReason::DelegationRevoked,
            Self::PrincipalDisablement => AuthorizationDenialReason::PrincipalDisabled,
        }
    }
}

#[test]
fn current_authority_invalidation_withholds_prior_idempotent_context_result() {
    for invalidation in CurrentAuthorityInvalidation::ALL {
        let fixture = ContextFixture::new();
        let first = fixture
            .repository
            .execute_authenticated(
                fixture.context_invocation(
                    FIRST_PRESENTATION_ID,
                    fixture.binding_id,
                    &fixture.signer,
                ),
                fixture.time(120),
            )
            .unwrap();
        let AuthenticatedOperationResultV1::ContextPack(_) = first.result else {
            panic!("initial authenticated Context build did not return its pack");
        };
        assert_eq!(fixture.context_durable_counts(), (1, 1, 1, 1, 1));
        let consequence_before = context_application_consequence_state(&fixture.repository);

        invalidation.apply(&fixture);
        let denied = fixture
            .repository
            .execute_authenticated(
                fixture.context_invocation(
                    SECOND_PRESENTATION_ID,
                    fixture.binding_id,
                    &fixture.signer,
                ),
                fixture.time(122),
            )
            .unwrap_err();

        assert_eq!(denied, invalidation.expected_error(), "{invalidation:?}");
        assert_eq!(
            context_application_consequence_state(&fixture.repository),
            consequence_before,
            "{invalidation:?}"
        );
        assert_eq!(
            fixture.context_durable_counts(),
            (1, 1, 1, 2, 2),
            "{invalidation:?}"
        );
        assert_eq!(
            persisted_denial(&fixture.repository, SECOND_PRESENTATION_ID),
            (
                "deny".to_owned(),
                Some(serialized_reason(invalidation.expected_reason())),
                1,
            ),
            "{invalidation:?}"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained lifecycle test compares same-Principal rotation and cross-Principal historical reuse before causal disablement"
)]
fn principal_disablement_precedes_future_binding_time_and_old_key_reuse_is_rejected() {
    let fixture = ContextFixture::new();
    let opening_before = fixture.subject_commitment_opening();
    let future_signer = Ed25519SigningProvider::from_secret_bytes(&[0x43; 32]);
    let future_binding_id = FUTURE_BINDING_ID.parse::<BindingId>().unwrap();
    fixture.enroll_binding(
        FUTURE_CHALLENGE_ID,
        future_binding_id,
        &future_signer,
        Some(fixture.binding_id),
        fixture.time(500),
        fixture.time(900),
    );
    assert_eq!(fixture.subject_commitment_opening(), opening_before);

    let head_before_reuse = fixture.authority_head();
    let reuse_error = fixture
        .try_enroll_binding(
            REUSED_CHALLENGE_ID,
            REUSED_BINDING_ID.parse().unwrap(),
            &fixture.signer,
            Some(future_binding_id),
            fixture.time(40),
            fixture.time(900),
        )
        .unwrap_err();
    assert!(matches!(reuse_error, AuthorityError::AuthorityIntegrity(_)));
    assert_eq!(fixture.authority_head(), head_before_reuse);

    create_agent_principal(
        &fixture.repository,
        CreateAgentPrincipalCommand {
            principal_id: OTHER_AGENT_PRINCIPAL_ID.parse().unwrap(),
            display_name: "cross-principal-reuse-agent".to_owned(),
            idempotency_key: OTHER_AGENT_CREATE_KEY.parse().unwrap(),
            created_at: fixture.time(31),
        },
    )
    .unwrap();
    let head_before_cross_principal_reuse = fixture.authority_head();
    let cross_principal_error = fixture
        .try_enroll_binding_for(
            CROSS_PRINCIPAL_CHALLENGE_ID,
            CROSS_PRINCIPAL_BINDING_ID.parse().unwrap(),
            OTHER_AGENT_PRINCIPAL_ID.parse().unwrap(),
            &fixture.signer,
            None,
            fixture.time(40),
            fixture.time(900),
        )
        .unwrap_err();
    assert!(matches!(
        cross_principal_error,
        AuthorityError::AuthorityIntegrity(_)
    ));
    assert_eq!(fixture.authority_head(), head_before_cross_principal_reuse);

    let head = fixture.authority_head();
    fixture
        .repository
        .set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head + 1).unwrap(),
            previous_authority_record_digest: fixture
                .repository
                .authority_head(fixture.workspace_id)
                .unwrap()
                .unwrap()
                .record_digest
                .into(),
            workspace_id: fixture.workspace_id,
            principal_id: fixture.agent_principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled: false,
            recorded_by_principal_id: fixture.human_principal_id,
            recorded_at: fixture.time(40),
        })
        .unwrap();

    let error = fixture
        .repository
        .execute_authenticated(
            fixture.context_invocation(DISABLED_PRESENTATION_ID, future_binding_id, &future_signer),
            fixture.time(120),
        )
        .unwrap_err();
    assert_eq!(error, AuthorityError::PrincipalDisabled);
    let (decision, reason, consumptions): (String, Option<String>, i64) = fixture
        .repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT d.decision, d.reason_code,
                    (SELECT COUNT(*) FROM presentation_consumptions_v1)
             FROM authorization_decisions_v2 d
             WHERE d.presentation_id = ?1",
            [DISABLED_PRESENTATION_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(decision, "deny");
    assert_eq!(
        reason,
        Some(serialized_reason(
            AuthorizationDenialReason::PrincipalDisabled
        ))
    );
    assert_eq!(consumptions, 1);
    assert_eq!(fixture.subject_commitment_opening(), opening_before);
}

#[test]
fn signed_disablement_and_revocation_projection_deletion_fail_integrity() {
    let disabled = ContextFixture::new();
    disabled
        .set_agent_enabled(disabled.agent_principal_id, false, disabled.time(40))
        .unwrap();
    assert_eq!(
        disabled
            .repository
            .open_database()
            .unwrap()
            .execute(
                "DELETE FROM principal_status_v1
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND enabled = 0",
                (WORKSPACE_ID, AGENT_PRINCIPAL_ID),
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        disabled.repository.authority_head(disabled.workspace_id),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));

    let revoked = ContextFixture::new();
    let head = revoked
        .repository
        .authority_head(revoked.workspace_id)
        .unwrap()
        .unwrap();
    revoked
        .repository
        .revoke_delegation(DelegationRevocationV1 {
            api_version: DelegationRevocationApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: head.record_digest,
            workspace_id: revoked.workspace_id,
            revocation_id: REVOCATION_ID.parse::<RevocationId>().unwrap(),
            delegation_id: revoked.delegation_id,
            revoked_by_principal_id: revoked.human_principal_id,
            revoked_at: revoked.time(40),
            reason: DelegationRevocationReasonV1::IssuerRequest,
        })
        .unwrap();
    assert_eq!(
        revoked
            .repository
            .open_database()
            .unwrap()
            .execute(
                "DELETE FROM delegation_revocations_v2
                 WHERE workspace_id = ?1 AND delegation_id = ?2",
                (WORKSPACE_ID, DELEGATION_ID),
            )
            .unwrap(),
        1
    );
    assert!(matches!(
        revoked.repository.authority_head(revoked.workspace_id),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
}

#[derive(Clone, Copy, Debug)]
enum ReconstructedProjectionFalsifier {
    PrincipalBinding,
    Delegation,
    AuthorizationDecision,
    PresentationConsumption,
    ActorEvidence,
    ConsumedEnrollmentChallenge,
    HumanOpening,
}

impl ReconstructedProjectionFalsifier {
    const ALL: [Self; 7] = [
        Self::PrincipalBinding,
        Self::Delegation,
        Self::AuthorizationDecision,
        Self::PresentationConsumption,
        Self::ActorEvidence,
        Self::ConsumedEnrollmentChallenge,
        Self::HumanOpening,
    ];

    const fn requires_authenticated_presentation(self) -> bool {
        matches!(
            self,
            Self::AuthorizationDecision | Self::PresentationConsumption | Self::ActorEvidence
        )
    }

    const fn table_name(self) -> &'static str {
        match self {
            Self::PrincipalBinding => "principal_bindings_v1",
            Self::Delegation => "delegations_v2",
            Self::AuthorizationDecision => "authorization_decisions_v2",
            Self::PresentationConsumption => "presentation_consumptions_v1",
            Self::ActorEvidence => "authenticated_actor_context_evidence_v1",
            Self::ConsumedEnrollmentChallenge => "binding_enrollment_challenges",
            Self::HumanOpening => "authenticated_subject_commitment_openings_v1",
        }
    }

    fn corrupt(self, fixture: &ContextFixture) -> usize {
        let connection = fixture.repository.open_database().unwrap();
        match self {
            Self::PrincipalBinding => connection.execute(
                "DELETE FROM principal_bindings_v1
                 WHERE workspace_id = ?1 AND binding_id = ?2",
                (WORKSPACE_ID, BINDING_ID),
            ),
            Self::Delegation => connection.execute(
                "DELETE FROM delegations_v2
                 WHERE workspace_id = ?1 AND delegation_id = ?2",
                (WORKSPACE_ID, DELEGATION_ID),
            ),
            Self::AuthorizationDecision => connection.execute(
                "UPDATE authorization_decisions_v2 SET decision_json = '{}'
                 WHERE workspace_id = ?1 AND presentation_id = ?2",
                (WORKSPACE_ID, FIRST_PRESENTATION_ID),
            ),
            Self::PresentationConsumption => connection.execute(
                "DELETE FROM presentation_consumptions_v1
                 WHERE workspace_id = ?1 AND presentation_id = ?2",
                (WORKSPACE_ID, FIRST_PRESENTATION_ID),
            ),
            Self::ActorEvidence => connection.execute(
                "DELETE FROM authenticated_actor_context_evidence_v1
                 WHERE workspace_id = ?1 AND presentation_id = ?2",
                (WORKSPACE_ID, FIRST_PRESENTATION_ID),
            ),
            Self::ConsumedEnrollmentChallenge => connection.execute(
                "DELETE FROM binding_enrollment_challenges
                 WHERE workspace_id = ?1 AND challenge_id = ?2",
                (WORKSPACE_ID, CHALLENGE_ID),
            ),
            Self::HumanOpening => connection.execute(
                "DELETE FROM authenticated_subject_commitment_openings_v1
                 WHERE workspace_id = ?1 AND requesting_principal_id = ?2",
                (WORKSPACE_ID, HUMAN_PRINCIPAL_ID),
            ),
        }
        .unwrap()
    }
}

#[test]
fn every_reconstructed_projection_tamper_fails_closed_without_read_side_effects() {
    for falsifier in ReconstructedProjectionFalsifier::ALL {
        let fixture = ContextFixture::new();
        if falsifier.requires_authenticated_presentation() {
            fixture
                .repository
                .execute_authenticated(
                    fixture.context_invocation(
                        FIRST_PRESENTATION_ID,
                        fixture.binding_id,
                        &fixture.signer,
                    ),
                    fixture.time(120),
                )
                .unwrap();
        }

        fixture
            .repository
            .authority_head(fixture.workspace_id)
            .unwrap()
            .unwrap();
        let valid_state = complete_database_state(&fixture.repository);
        assert_eq!(falsifier.corrupt(&fixture), 1, "{falsifier:?}");
        let corrupted_state = complete_database_state(&fixture.repository);
        let changed_tables = changed_tables(&valid_state, &corrupted_state);
        assert_eq!(
            changed_tables,
            vec![falsifier.table_name().to_owned()],
            "{falsifier:?}"
        );

        assert!(
            matches!(
                fixture.repository.authority_head(fixture.workspace_id),
                Err(AuthorityError::AuthorityIntegrity(_))
            ),
            "{falsifier:?}"
        );
        assert_eq!(
            complete_database_state(&fixture.repository),
            corrupted_state,
            "{falsifier:?}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum ClosedAdministratorSurface {
    EnrollmentChallenge,
    PrincipalBinding,
    PrincipalStatus,
    PrincipalBindingRevocation,
    Delegation,
    DelegationRevocation,
    RootTransition,
}

impl ClosedAdministratorSurface {
    const ALL: [Self; 7] = [
        Self::EnrollmentChallenge,
        Self::PrincipalBinding,
        Self::PrincipalStatus,
        Self::PrincipalBindingRevocation,
        Self::Delegation,
        Self::DelegationRevocation,
        Self::RootTransition,
    ];

    #[expect(
        clippy::too_many_lines,
        reason = "the retained table enumerates the complete closed administrator union and changes only each record's actor field"
    )]
    fn arrange_unauthorized_request(self, fixture: &ContextFixture) -> UnauthorizedAdminRequest {
        match self {
            Self::EnrollmentChallenge => {
                let candidate = Ed25519SigningProvider::from_secret_bytes(&[0x74; 32]);
                let candidate_key_id =
                    Ed25519KeyId::new(candidate.metadata().unwrap().key_id).unwrap();
                UnauthorizedAdminRequest::EnrollmentChallenge(BindingEnrollmentChallengeV1 {
                    api_version: EnrollmentChallengeApiVersion::V1,
                    challenge_id: PENDING_CHALLENGE_ID.parse().unwrap(),
                    audience: AuthorityAudience::for_workspace(fixture.workspace_id),
                    workspace_id: fixture.workspace_id,
                    binding_id: PENDING_BINDING_ID.parse().unwrap(),
                    principal_id: fixture.agent_principal_id,
                    candidate_key_id,
                    issued_by_principal_id: fixture.agent_principal_id,
                    issued_at: fixture.time(20),
                    expires_at: fixture.time(320),
                })
            }
            Self::PrincipalBinding => {
                let candidate = Ed25519SigningProvider::from_secret_bytes(&[0x75; 32]);
                let mut prepared = fixture
                    .prepare_enrollment_for(
                        PENDING_CHALLENGE_ID,
                        PENDING_BINDING_ID.parse().unwrap(),
                        fixture.agent_principal_id,
                        &candidate,
                        Some(fixture.binding_id),
                        fixture.time(40),
                        fixture.time(900),
                    )
                    .unwrap();
                prepared.binding.issued_by_principal_id = fixture.agent_principal_id;
                UnauthorizedAdminRequest::PrincipalBinding(prepared)
            }
            Self::PrincipalStatus => {
                let head = fixture
                    .repository
                    .authority_head(fixture.workspace_id)
                    .unwrap()
                    .unwrap();
                UnauthorizedAdminRequest::PrincipalStatus(PrincipalStatusV1 {
                    api_version: PrincipalStatusApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: Some(head.record_digest),
                    workspace_id: fixture.workspace_id,
                    principal_id: fixture.agent_principal_id,
                    principal_type: AuthorityPrincipalType::Agent,
                    enabled: false,
                    recorded_by_principal_id: fixture.agent_principal_id,
                    recorded_at: fixture.time(40),
                })
            }
            Self::PrincipalBindingRevocation => {
                let head = fixture
                    .repository
                    .authority_head(fixture.workspace_id)
                    .unwrap()
                    .unwrap();
                UnauthorizedAdminRequest::PrincipalBindingRevocation(PrincipalBindingRevocationV1 {
                    api_version: PrincipalBindingRevocationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: head.record_digest,
                    workspace_id: fixture.workspace_id,
                    revocation_id: REVOCATION_ID.parse().unwrap(),
                    binding_id: fixture.binding_id,
                    revoked_by_principal_id: fixture.agent_principal_id,
                    revoked_at: fixture.time(40),
                    reason: PrincipalBindingRevocationReason::Administrative,
                })
            }
            Self::Delegation => {
                let mut delegation = fixture.proposed_delegation(
                    UNBOUND_DELEGATION_ID.parse().unwrap(),
                    fixture.agent_principal_id,
                );
                delegation.issuer_principal_id = fixture.agent_principal_id;
                UnauthorizedAdminRequest::Delegation(delegation)
            }
            Self::DelegationRevocation => {
                let head = fixture
                    .repository
                    .authority_head(fixture.workspace_id)
                    .unwrap()
                    .unwrap();
                UnauthorizedAdminRequest::DelegationRevocation(DelegationRevocationV1 {
                    api_version: DelegationRevocationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: head.record_digest,
                    workspace_id: fixture.workspace_id,
                    revocation_id: REVOCATION_ID.parse().unwrap(),
                    delegation_id: fixture.delegation_id,
                    revoked_by_principal_id: fixture.agent_principal_id,
                    revoked_at: fixture.time(40),
                    reason: DelegationRevocationReasonV1::IssuerRequest,
                })
            }
            Self::RootTransition => {
                let successor_secret = [0x76; 32];
                let mut staged = stage_valid_root_transition(fixture, successor_secret);
                staged.transition.activated_by_principal_id = fixture.agent_principal_id;
                let predecessor = signer_from_file(
                    &fixture
                        .repository
                        .root()
                        .join(AUTHORITY_SIGNING_KEY_RELATIVE_PATH),
                );
                let successor = Ed25519SigningProvider::from_secret_bytes(&successor_secret);
                staged.envelope_json = sign_authority_payload(
                    AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                    &staged.transition,
                    &[&predecessor, &successor],
                )
                .unwrap()
                .envelope_json;
                UnauthorizedAdminRequest::RootTransition(staged)
            }
        }
    }
}

enum UnauthorizedAdminRequest {
    EnrollmentChallenge(BindingEnrollmentChallengeV1),
    PrincipalBinding(PreparedEnrollment),
    PrincipalStatus(PrincipalStatusV1),
    PrincipalBindingRevocation(PrincipalBindingRevocationV1),
    Delegation(DelegationV2),
    DelegationRevocation(DelegationRevocationV1),
    RootTransition(StagedRootTransition),
}

impl UnauthorizedAdminRequest {
    fn invoke(self, fixture: &ContextFixture) -> Result<(), AuthorityError> {
        match self {
            Self::EnrollmentChallenge(challenge) => fixture
                .repository
                .create_binding_enrollment_challenge(challenge)
                .map(|_| ()),
            Self::PrincipalBinding(prepared) => fixture
                .repository
                .issue_principal_binding(prepared.binding, prepared.envelope_json)
                .map(|_| ()),
            Self::PrincipalStatus(status) => {
                fixture.repository.set_principal_status(status).map(|_| ())
            }
            Self::PrincipalBindingRevocation(revocation) => fixture
                .repository
                .revoke_principal_binding(revocation)
                .map(|_| ()),
            Self::Delegation(delegation) => {
                fixture.repository.issue_delegation(delegation).map(|_| ())
            }
            Self::DelegationRevocation(revocation) => {
                fixture.repository.revoke_delegation(revocation).map(|_| ())
            }
            Self::RootTransition(staged) => fixture
                .repository
                .transition_workspace_authority_root(staged.transition, staged.envelope_json)
                .map(|_| ()),
        }
    }
}

#[test]
fn agent_actor_cannot_administer_any_closed_authority_surface() {
    for surface in ClosedAdministratorSurface::ALL {
        let fixture = ContextFixture::new();
        let request = surface.arrange_unauthorized_request(&fixture);
        let head_before = fixture.authority_head();
        let record_count_before = authority_record_count(&fixture.repository);
        let challenge_consumptions_before = enrollment_challenge_consumptions(&fixture.repository);
        let database_before = complete_database_state(&fixture.repository);
        let custody_before = authority_key_custody_state(&fixture.repository);

        assert_eq!(
            request.invoke(&fixture).unwrap_err(),
            AuthorityError::AuthDenied
        );
        assert_eq!(fixture.authority_head(), head_before, "{surface:?}");
        assert_eq!(
            authority_record_count(&fixture.repository),
            record_count_before,
            "{surface:?}"
        );
        assert_eq!(
            enrollment_challenge_consumptions(&fixture.repository),
            challenge_consumptions_before,
            "{surface:?}"
        );
        assert_eq!(
            complete_database_state(&fixture.repository),
            database_before,
            "{surface:?}"
        );
        assert_eq!(
            authority_key_custody_state(&fixture.repository),
            custody_before,
            "{surface:?}"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained lifecycle test proves the four no-append issuance boundaries against a shared initialized authority"
)]
fn trusted_challenge_time_and_recipient_liveness_block_invalid_issuance_without_append() {
    let expiry = ContextFixture::new();
    let expired_signer = Ed25519SigningProvider::from_secret_bytes(&[0x61; 32]);
    let expired = expiry
        .prepare_enrollment_for(
            EXPIRED_CHALLENGE_ID,
            EXPIRED_BINDING_ID.parse().unwrap(),
            expiry.agent_principal_id,
            &expired_signer,
            Some(expiry.binding_id),
            expiry.time(40),
            expiry.time(900),
        )
        .unwrap();
    let head_before_expired_issue = expiry.authority_head();
    let late_repository = LocalWorkspace::with_deterministic_authority_adapter(
        expiry.repository.root(),
        DeterministicLocalAuthorityAdapter::new(
            DETERMINISTIC_UID,
            expiry.time(320),
            DETERMINISTIC_SUBJECT_BLIND,
        ),
    )
    .unwrap();
    assert_eq!(
        late_repository
            .issue_principal_binding(expired.binding, expired.envelope_json)
            .unwrap_err(),
        AuthorityError::AuthDenied
    );
    assert_eq!(expiry.authority_head(), head_before_expired_issue);
    assert_eq!(expiry.challenge_consumed(EXPIRED_CHALLENGE_ID), None);

    let disabled = ContextFixture::new();
    let pending_signer = Ed25519SigningProvider::from_secret_bytes(&[0x62; 32]);
    let mut pending = disabled
        .prepare_enrollment_for(
            PENDING_CHALLENGE_ID,
            PENDING_BINDING_ID.parse().unwrap(),
            disabled.agent_principal_id,
            &pending_signer,
            Some(disabled.binding_id),
            disabled.time(40),
            disabled.time(900),
        )
        .unwrap();
    disabled
        .set_agent_enabled(disabled.agent_principal_id, false, disabled.time(40))
        .unwrap();
    let disabled_head = disabled
        .repository
        .authority_head(disabled.workspace_id)
        .unwrap()
        .unwrap();
    pending.binding.authority_sequence =
        AuthoritySequence::new(disabled_head.sequence.get() + 1).unwrap();
    pending.binding.previous_authority_record_digest = Some(disabled_head.record_digest);
    let head_before_disabled_issue = disabled.authority_head();
    assert_eq!(
        disabled
            .repository
            .issue_principal_binding(pending.binding, pending.envelope_json)
            .unwrap_err(),
        AuthorityError::PrincipalDisabled
    );
    assert_eq!(disabled.authority_head(), head_before_disabled_issue);
    assert_eq!(disabled.challenge_consumed(PENDING_CHALLENGE_ID), None);

    let recipients = ContextFixture::new();
    create_agent_principal(
        &recipients.repository,
        CreateAgentPrincipalCommand {
            principal_id: UNBOUND_AGENT_PRINCIPAL_ID.parse().unwrap(),
            display_name: "unbound-recipient".to_owned(),
            idempotency_key: UNBOUND_AGENT_CREATE_KEY.parse().unwrap(),
            created_at: recipients.time(31),
        },
    )
    .unwrap();
    let head_before_unbound_delegation = recipients.authority_head();
    assert_eq!(
        recipients
            .repository
            .issue_delegation(recipients.proposed_delegation(
                UNBOUND_DELEGATION_ID.parse().unwrap(),
                UNBOUND_AGENT_PRINCIPAL_ID.parse().unwrap(),
            ))
            .unwrap_err(),
        AuthorityError::AuthBindingInactive
    );
    assert_eq!(recipients.authority_head(), head_before_unbound_delegation);

    create_agent_principal(
        &recipients.repository,
        CreateAgentPrincipalCommand {
            principal_id: DISABLED_AGENT_PRINCIPAL_ID.parse().unwrap(),
            display_name: "disabled-recipient".to_owned(),
            idempotency_key: DISABLED_AGENT_CREATE_KEY.parse().unwrap(),
            created_at: recipients.time(32),
        },
    )
    .unwrap();
    recipients
        .set_agent_enabled(
            DISABLED_AGENT_PRINCIPAL_ID.parse().unwrap(),
            false,
            recipients.time(40),
        )
        .unwrap();
    let head_before_disabled_delegation = recipients.authority_head();
    assert_eq!(
        recipients
            .repository
            .issue_delegation(recipients.proposed_delegation(
                DISABLED_DELEGATION_ID.parse().unwrap(),
                DISABLED_AGENT_PRINCIPAL_ID.parse().unwrap(),
            ))
            .unwrap_err(),
        AuthorityError::PrincipalDisabled
    );
    assert_eq!(recipients.authority_head(), head_before_disabled_delegation);
}

#[test]
fn invalid_root_transition_signature_preserves_database_and_key_custody() {
    let fixture = ContextFixture::new();
    let root = fixture
        .repository
        .workspace_authority_root(fixture.workspace_id)
        .unwrap();
    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    let predecessor = signer_from_file(
        &fixture
            .repository
            .root()
            .join(AUTHORITY_SIGNING_KEY_RELATIVE_PATH),
    );
    let successor = Ed25519SigningProvider::from_secret_bytes(&[0x71; 32]);
    let successor_metadata = successor.metadata().unwrap();
    let successor_key_id = Ed25519KeyId::new(successor_metadata.key_id).unwrap();
    let transition = WorkspaceAuthorityRootTransitionV1 {
        api_version: WorkspaceAuthorityRootTransitionApiVersion::V1,
        authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
        previous_authority_record_digest: head.record_digest,
        workspace_id: fixture.workspace_id,
        transition_id: ROOT_TRANSITION_ID
            .parse::<AuthorityRootTransitionId>()
            .unwrap(),
        predecessor_authority_key_id: root.authority_key_id,
        successor_authority_key_id: successor_key_id.clone(),
        successor_public_key: Ed25519PublicKey::new(BASE64.encode(successor_metadata.public_key))
            .unwrap(),
        algorithm: Ed25519Algorithm::Ed25519,
        activated_by_principal_id: fixture.human_principal_id,
        activated_at: fixture.time(40),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
        &transition,
        &[&predecessor, &successor],
    )
    .unwrap();
    let mut invalid_envelope =
        serde_json::from_str::<serde_json::Value>(&signed.envelope_json).unwrap();
    invalid_envelope["signatures"][1]["sig"] = serde_json::json!(BASE64.encode([0_u8; 64]));
    let invalid_envelope = canonicalize(&invalid_envelope).unwrap();
    let staging_path = fixture
        .repository
        .root()
        .join(SUCCESSOR_STAGING_KEY_RELATIVE_PATH);
    write_private_key(&staging_path, &successor.secret_bytes());
    let successor_hex = successor_key_id.as_str().strip_prefix("ed25519:").unwrap();
    let published_path = fixture.repository.root().join(format!(
        ".proof/state/authority-roots/{successor_hex}.ed25519"
    ));
    let database_before = authority_root_state(&fixture.repository);

    assert!(matches!(
        fixture
            .repository
            .transition_workspace_authority_root(transition, invalid_envelope.as_str().to_owned(),),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
    assert_eq!(authority_root_state(&fixture.repository), database_before);
    assert!(staging_path.exists());
    assert!(!published_path.exists());
}

#[test]
fn agent_binding_rejects_authority_and_release_signing_keys() {
    for key_path in [
        AUTHORITY_SIGNING_KEY_RELATIVE_PATH,
        RELEASE_SIGNING_KEY_RELATIVE_PATH,
    ] {
        let fixture = ContextFixture::new();
        let signer = signer_from_file(&fixture.repository.root().join(key_path));
        let head_before = fixture.authority_head();
        let error = fixture
            .try_enroll_binding(
                FUTURE_CHALLENGE_ID,
                FUTURE_BINDING_ID.parse().unwrap(),
                &signer,
                Some(fixture.binding_id),
                fixture.time(40),
                fixture.time(900),
            )
            .unwrap_err();

        assert!(matches!(error, AuthorityError::AuthorityIntegrity(_)));
        assert_eq!(fixture.authority_head(), head_before, "{key_path}");
        assert_eq!(
            fixture.challenge_consumed(FUTURE_CHALLENGE_ID),
            None,
            "{key_path}"
        );
    }
}

#[test]
fn authority_successor_rejects_agent_and_release_signing_keys() {
    for role in ["agent", "release"] {
        let fixture = ContextFixture::new();
        let successor_secret = match role {
            "agent" => fixture.signer.secret_bytes(),
            "release" => signer_from_file(
                &fixture
                    .repository
                    .root()
                    .join(RELEASE_SIGNING_KEY_RELATIVE_PATH),
            )
            .secret_bytes(),
            _ => unreachable!(),
        };
        let staged = stage_valid_root_transition(&fixture, successor_secret);
        let database_before = authority_root_state(&fixture.repository);

        assert!(matches!(
            fixture
                .repository
                .transition_workspace_authority_root(staged.transition, staged.envelope_json,),
            Err(AuthorityError::AuthorityIntegrity(_))
        ));
        assert_eq!(authority_root_state(&fixture.repository), database_before);
        assert!(staged.staging_path.exists(), "{role}");
        assert!(!staged.published_path.exists(), "{role}");
    }
}

#[test]
fn root_transition_commit_failure_restores_staging_and_retry_publishes_once() {
    let fixture = ContextFixture::new();
    let staged = stage_valid_root_transition(&fixture, [0x72; 32]);
    let database_before = authority_root_state(&fixture.repository);
    let predecessor_root = fixture
        .repository
        .workspace_authority_root(fixture.workspace_id)
        .unwrap();
    fixture
        .repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TABLE injected_root_parent (
                 id INTEGER PRIMARY KEY
             ) STRICT;
             CREATE TABLE injected_root_child (
                 id INTEGER PRIMARY KEY,
                 parent_id INTEGER NOT NULL,
                 FOREIGN KEY (parent_id) REFERENCES injected_root_parent(id)
                     DEFERRABLE INITIALLY DEFERRED
             ) STRICT;
             CREATE TRIGGER inject_root_commit_failure
             AFTER INSERT ON workspace_authority_roots
             WHEN NEW.predecessor_authority_key_id IS NOT NULL
             BEGIN
                 INSERT INTO injected_root_child (id, parent_id) VALUES (1, 99);
             END;",
        )
        .unwrap();

    assert!(matches!(
        fixture.repository.transition_workspace_authority_root(
            staged.transition.clone(),
            staged.envelope_json.clone(),
        ),
        Err(AuthorityError::Storage(_))
    ));
    assert_eq!(authority_root_state(&fixture.repository), database_before);
    assert!(staged.staging_path.exists());
    assert!(!staged.published_path.exists());
    assert_eq!(
        fixture
            .repository
            .workspace_authority_root(fixture.workspace_id)
            .unwrap(),
        predecessor_root
    );
    fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap();

    fixture
        .repository
        .open_database()
        .unwrap()
        .execute_batch("DROP TRIGGER inject_root_commit_failure;")
        .unwrap();
    let activated = fixture
        .repository
        .transition_workspace_authority_root(staged.transition, staged.envelope_json)
        .unwrap();
    assert_eq!(activated.authority_key_id, staged.successor_key_id);
    assert!(!staged.staging_path.exists());
    assert!(staged.published_path.exists());
}

#[test]
fn published_successor_without_database_transition_rejects_mismatch_then_resumes_exactly() {
    let fixture = ContextFixture::new();
    let staged = stage_valid_root_transition(&fixture, [0x73; 32]);
    let database_before = authority_root_state(&fixture.repository);
    fs::create_dir_all(staged.published_path.parent().unwrap()).unwrap();
    fs::rename(&staged.staging_path, &staged.published_path).unwrap();
    assert!(!staged.staging_path.exists());
    assert!(staged.published_path.exists());

    let mut mismatched_transition = staged.transition.clone();
    mismatched_transition.activated_at = fixture.time(41);
    assert!(matches!(
        fixture.repository.transition_workspace_authority_root(
            mismatched_transition,
            staged.envelope_json.clone(),
        ),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
    assert_eq!(authority_root_state(&fixture.repository), database_before);
    assert!(!staged.staging_path.exists());
    assert!(staged.published_path.exists());

    let activated = fixture
        .repository
        .transition_workspace_authority_root(staged.transition, staged.envelope_json)
        .unwrap();
    assert_eq!(activated.authority_key_id, staged.successor_key_id);
    assert!(staged.published_path.exists());
}

struct ContextFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    signer: Ed25519SigningProvider,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent_principal_id: PrincipalId,
    binding_id: BindingId,
    delegation_id: proof_application::DelegationId,
    base_time: Timestamp,
}

struct PreparedEnrollment {
    binding: PrincipalBindingV1,
    envelope_json: String,
}

impl ContextFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "the fixture creates one complete released resource and authenticated authority chain"
    )]
    fn new() -> Self {
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
        let agent_principal_id = AGENT_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        let binding_id = BINDING_ID.parse::<BindingId>().unwrap();
        let delegation_id = DELEGATION_ID.parse().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();
        prepare_release(&repository, base_time);
        create_agent_principal(
            &repository,
            CreateAgentPrincipalCommand {
                principal_id: agent_principal_id,
                display_name: "falsification-context-agent".to_owned(),
                idempotency_key: AGENT_CREATE_KEY.parse().unwrap(),
                created_at: add_seconds(base_time, 10),
            },
        )
        .unwrap();

        let signer = Ed25519SigningProvider::from_secret_bytes(&[0x42; 32]);
        let fixture = Self {
            _directory: directory,
            repository,
            signer,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            delegation_id,
            base_time,
        };
        fixture.enroll_binding(
            CHALLENGE_ID,
            binding_id,
            &fixture.signer,
            None,
            fixture.time(21),
            fixture.time(1_000),
        );

        let head = fixture
            .repository
            .authority_head(workspace_id)
            .unwrap()
            .unwrap();
        fixture
            .repository
            .set_principal_status(PrincipalStatusV1 {
                api_version: PrincipalStatusApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                workspace_id,
                principal_id: agent_principal_id,
                principal_type: AuthorityPrincipalType::Agent,
                enabled: true,
                recorded_by_principal_id: human_principal_id,
                recorded_at: fixture.time(22),
            })
            .unwrap();

        let head = fixture
            .repository
            .authority_head(workspace_id)
            .unwrap()
            .unwrap();
        fixture
            .repository
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
                    object_ids: DelegationObjectIdsV2::new(vec![OBJECT_ID.parse().unwrap()])
                        .unwrap(),
                    schema_ids: DelegationSchemaIdsV2::new(Vec::new()).unwrap(),
                    locales: DelegationLocalesV2::new(Vec::new()).unwrap(),
                },
                constraints: DelegationConstraintsV2 {
                    max_objects: MaxObjects::new(1).unwrap(),
                    max_context_bytes: MaxContextBytes::new(16_384).unwrap(),
                    max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                    allow_subdelegation: SubdelegationDisabled,
                },
                not_before: fixture.time(23),
                expires_at: fixture.time(1_000),
                issued_at: fixture.time(23),
            })
            .unwrap();
        fixture
    }

    fn time(&self, seconds: i64) -> Timestamp {
        add_seconds(self.base_time, seconds)
    }

    fn authority_head(&self) -> u64 {
        self.repository
            .authority_head(self.workspace_id)
            .unwrap()
            .unwrap()
            .sequence
            .get()
    }

    fn set_agent_enabled(
        &self,
        principal_id: PrincipalId,
        enabled: bool,
        recorded_at: Timestamp,
    ) -> Result<(), AuthorityError> {
        let head = self.repository.authority_head(self.workspace_id)?.unwrap();
        self.repository.set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            workspace_id: self.workspace_id,
            principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled,
            recorded_by_principal_id: self.human_principal_id,
            recorded_at,
        })?;
        Ok(())
    }

    fn proposed_delegation(
        &self,
        delegation_id: proof_application::DelegationId,
        recipient_principal_id: PrincipalId,
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
            delegation_id,
            workspace_id: self.workspace_id,
            delegation_profile: DirectAuthorityProfileV1::Direct,
            issuer_principal_id: self.human_principal_id,
            recipient_principal_id,
            actions: DelegationActionsV2::new(vec![AuthorityAction::ContextBuild]).unwrap(),
            scope: DelegationScopeV2 {
                environment_ids: DelegationEnvironmentIdsV2::new(vec![
                    ENVIRONMENT_ID.parse().unwrap(),
                ])
                .unwrap(),
                object_ids: DelegationObjectIdsV2::new(vec![OBJECT_ID.parse().unwrap()]).unwrap(),
                schema_ids: DelegationSchemaIdsV2::new(Vec::new()).unwrap(),
                locales: DelegationLocalesV2::new(Vec::new()).unwrap(),
            },
            constraints: DelegationConstraintsV2 {
                max_objects: MaxObjects::new(1).unwrap(),
                max_context_bytes: MaxContextBytes::new(16_384).unwrap(),
                max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                allow_subdelegation: SubdelegationDisabled,
            },
            not_before: self.time(23),
            expires_at: self.time(1_000),
            issued_at: self.time(23),
        }
    }

    fn enroll_binding(
        &self,
        challenge_id: &str,
        binding_id: BindingId,
        signer: &Ed25519SigningProvider,
        supersedes_binding_id: Option<BindingId>,
        not_before: Timestamp,
        expires_at: Timestamp,
    ) {
        self.try_enroll_binding(
            challenge_id,
            binding_id,
            signer,
            supersedes_binding_id,
            not_before,
            expires_at,
        )
        .unwrap();
    }

    fn try_enroll_binding(
        &self,
        challenge_id: &str,
        binding_id: BindingId,
        signer: &Ed25519SigningProvider,
        supersedes_binding_id: Option<BindingId>,
        not_before: Timestamp,
        expires_at: Timestamp,
    ) -> Result<(), AuthorityError> {
        self.try_enroll_binding_for(
            challenge_id,
            binding_id,
            self.agent_principal_id,
            signer,
            supersedes_binding_id,
            not_before,
            expires_at,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the helper exposes Principal identity plus every credential-rotation axis varied by the retained regressions"
    )]
    fn try_enroll_binding_for(
        &self,
        challenge_id: &str,
        binding_id: BindingId,
        principal_id: PrincipalId,
        signer: &Ed25519SigningProvider,
        supersedes_binding_id: Option<BindingId>,
        not_before: Timestamp,
        expires_at: Timestamp,
    ) -> Result<(), AuthorityError> {
        let prepared = self.prepare_enrollment_for(
            challenge_id,
            binding_id,
            principal_id,
            signer,
            supersedes_binding_id,
            not_before,
            expires_at,
        )?;
        self.repository
            .issue_principal_binding(prepared.binding, prepared.envelope_json)?;
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the helper exposes Principal identity plus every prepared credential axis used by issuance falsifiers"
    )]
    fn prepare_enrollment_for(
        &self,
        challenge_id: &str,
        binding_id: BindingId,
        principal_id: PrincipalId,
        signer: &Ed25519SigningProvider,
        supersedes_binding_id: Option<BindingId>,
        not_before: Timestamp,
        expires_at: Timestamp,
    ) -> Result<PreparedEnrollment, AuthorityError> {
        let metadata = signer.metadata().unwrap();
        let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
        let challenge = BindingEnrollmentChallengeV1 {
            api_version: EnrollmentChallengeApiVersion::V1,
            challenge_id: challenge_id.parse::<EnrollmentChallengeId>().unwrap(),
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            binding_id,
            principal_id,
            candidate_key_id: key_id.clone(),
            issued_by_principal_id: self.human_principal_id,
            issued_at: self.time(20),
            expires_at: self.time(320),
        };
        let recorded = self
            .repository
            .create_binding_enrollment_challenge(challenge.clone())?;
        let enrollment = sign_authority_payload(
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            &challenge,
            &[signer],
        )
        .unwrap();
        let head = self.repository.authority_head(self.workspace_id)?.unwrap();
        Ok(PreparedEnrollment {
            binding: PrincipalBindingV1 {
                api_version: PrincipalBindingApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                workspace_id: self.workspace_id,
                binding_id,
                principal_id,
                principal_type: AgentPrincipalType::Agent,
                authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
                algorithm: Ed25519Algorithm::Ed25519,
                public_key: Ed25519PublicKey::new(BASE64.encode(metadata.public_key)).unwrap(),
                key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                audience: AuthorityAudience::for_workspace(self.workspace_id),
                enrollment_challenge_digest: recorded.challenge_digest,
                enrollment_envelope_digest: enrollment.envelope_digest,
                issued_by_principal_id: self.human_principal_id,
                issued_at: self.time(21),
                not_before,
                expires_at,
                supersedes_binding_id,
            },
            envelope_json: enrollment.envelope_json,
        })
    }

    fn context_invocation(
        &self,
        presentation_id: &str,
        binding_id: BindingId,
        signer: &Ed25519SigningProvider,
    ) -> AuthenticatedInvocationV1 {
        let idempotency_key = CONTEXT_BUILD_KEY.parse::<IdempotencyKey>().unwrap();
        let normalized_input = serde_json::json!({
            "delegation_id": self.delegation_id.to_string(),
            "environment_id": ENVIRONMENT_ID,
            "expires_at": self.time(600).to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "intent": "Summarize the released article",
            "max_bytes": 16_384,
            "max_objects": 1,
            "object_ids": [OBJECT_ID],
            "operating_principal_id": self.agent_principal_id.to_string(),
            "task_id": "release-summary",
        })
        .as_object()
        .unwrap()
        .clone();
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation: AuthorityOperation::ContextBuildV1,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            idempotency_key: Some(idempotency_key),
            normalized_input,
        };
        let operation_input = command_input
            .normalize_for_authenticated_execution()
            .unwrap();
        command_input.normalized_input = operation_input.normalized_input().unwrap();
        let command_json = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command_digest = digest(ArtifactKind::CommandV1, &command_json);
        let payload = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation: command_input.operation,
            binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id: self.delegation_id,
            command_digest,
            idempotency_key: Some(idempotency_key),
            presentation_id: presentation_id.parse().unwrap(),
            issued_at: self.time(100),
            expires_at: self.time(300),
        };
        let signed_command = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &payload,
            &[signer],
        )
        .unwrap();
        AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input,
            authentication: AuthenticatedCommandEnvelopeJson::new(signed_command.envelope_json)
                .unwrap(),
        }
    }

    fn context_durable_counts(&self) -> (i64, i64, i64, i64, i64) {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM context_packs),
                        (SELECT COUNT(*) FROM context_pack_build_operations),
                        (SELECT COUNT(*) FROM authenticated_operation_results_v1),
                        (SELECT COUNT(*) FROM authorization_decisions_v2),
                        (SELECT COUNT(*) FROM presentation_consumptions_v1)",
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
            .unwrap()
    }

    fn challenge_consumed(&self, challenge_id: &str) -> Option<String> {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT consumed_at FROM binding_enrollment_challenges
                 WHERE challenge_id = ?1",
                [challenge_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn subject_commitment_opening(&self) -> (i64, String, String, ContentDigest) {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM authenticated_subject_commitment_openings_v1),
                        requesting_subject, blind, requesting_subject_commitment
                 FROM authenticated_subject_commitment_openings_v1
                 WHERE workspace_id = ?1 AND requesting_principal_id = ?2",
                (
                    self.workspace_id.to_string(),
                    self.human_principal_id.to_string(),
                ),
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get::<_, String>(3)?.parse().unwrap(),
                    ))
                },
            )
            .unwrap()
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the helper establishes one immutable Release through the ordinary Human lifecycle"
)]
fn prepare_release(repository: &LocalWorkspace, base_time: Timestamp) {
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: CHANGESET_ID.parse::<ChangeSetId>().unwrap(),
            intent: ChangeSetIntent::new("Define a released article").unwrap(),
            requested_base_state: None,
            idempotency_key: CHANGESET_CREATE_KEY.parse().unwrap(),
            created_at: add_seconds(base_time, 40),
        },
    )
    .unwrap();
    let schema_document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {"title": {"type": "string"}},
        "required": ["title"],
        "type": "object",
    });
    let canonical_schema = canonicalize(&schema_document).unwrap();
    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let object = serde_json::json!({"title": "Projection proof"});
    let canonical_object = canonicalize(&object).unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                    edit_id: SCHEMA_EDIT_ID.parse::<EditId>().unwrap(),
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_document: canonical_schema.as_str().to_owned(),
                    document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical_schema),
                }),
                ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                    edit_id: OBJECT_EDIT_ID.parse().unwrap(),
                    object_id,
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_content: canonical_object.as_str().to_owned(),
                    object_digest: object_revision_digest(
                        object_id,
                        &schema_id,
                        schema_version,
                        &object,
                    )
                    .unwrap(),
                }),
            ],
            idempotency_key: CHANGESET_ADD_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: add_seconds(base_time, 50),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: add_seconds(base_time, 60),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: CHANGESET_COMMIT_KEY.parse().unwrap(),
            committed_at: add_seconds(base_time, 70),
        },
    )
    .unwrap();
    create_edition(
        repository,
        CreateEditionCommand {
            edition_id: EDITION_ID.parse::<EditionId>().unwrap(),
            idempotency_key: EDITION_CREATE_KEY.parse().unwrap(),
            created_at: add_seconds(base_time, 80),
        },
    )
    .unwrap();
    create_environment(
        repository,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: ENVIRONMENT_CREATE_KEY.parse().unwrap(),
            created_at: add_seconds(base_time, 81),
        },
    )
    .unwrap();
    promote_release(
        repository,
        PromoteReleaseCommand {
            release_id: RELEASE_ID.parse::<ReleaseId>().unwrap(),
            proof_id: PROOF_ID.parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: EDITION_ID.parse().unwrap(),
            idempotency_key: RELEASE_PROMOTE_KEY.parse().unwrap(),
            released_at: add_seconds(base_time, 90),
        },
    )
    .unwrap();
}

fn serialized_reason(reason: AuthorizationDenialReason) -> String {
    serde_json::to_value(reason)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn context_application_consequence_state(
    repository: &LocalWorkspace,
) -> BTreeMap<&'static str, Vec<Vec<String>>> {
    let connection = repository.open_database().unwrap();
    [
        (
            "context_packs",
            "SELECT * FROM context_packs ORDER BY context_pack_id",
        ),
        (
            "context_pack_build_operations",
            "SELECT * FROM context_pack_build_operations ORDER BY idempotency_key",
        ),
        (
            "authenticated_operation_results_v1",
            "SELECT * FROM authenticated_operation_results_v1
             ORDER BY workspace_id, idempotency_key",
        ),
    ]
    .into_iter()
    .map(|(table_name, query)| (table_name, snapshot_rows(&connection, query)))
    .collect()
}

fn persisted_denial(
    repository: &LocalWorkspace,
    presentation_id: &str,
) -> (String, Option<String>, i64) {
    repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT decision, reason_code,
                    (SELECT COUNT(*) FROM presentation_consumptions_v1 c
                     WHERE c.presentation_id = d.presentation_id
                       AND c.decision_authority_sequence = d.authority_sequence)
             FROM authorization_decisions_v2 d WHERE presentation_id = ?1",
            [presentation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn authority_root_state(repository: &LocalWorkspace) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let connection = repository.open_database().unwrap();
    (
        snapshot_rows(
            &connection,
            "SELECT * FROM authority_records ORDER BY authority_sequence",
        ),
        snapshot_rows(
            &connection,
            "SELECT * FROM workspace_authority_roots ORDER BY authority_key_id",
        ),
    )
}

fn complete_database_state(repository: &LocalWorkspace) -> BTreeMap<String, Vec<Vec<String>>> {
    let connection = repository.open_database().unwrap();
    let table_names = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    table_names
        .into_iter()
        .map(|table_name| {
            let quoted_table_name = table_name.replace('"', "\"\"");
            let mut rows = snapshot_rows(
                &connection,
                &format!("SELECT * FROM \"{quoted_table_name}\""),
            );
            rows.sort();
            (table_name, rows)
        })
        .collect()
}

fn authority_record_count(repository: &LocalWorkspace) -> i64 {
    repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM authority_records", [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn enrollment_challenge_consumptions(repository: &LocalWorkspace) -> Vec<Vec<String>> {
    snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT challenge_id, enrollment_envelope_json,
                enrollment_envelope_digest, consumed_at
         FROM binding_enrollment_challenges ORDER BY challenge_id",
    )
}

fn authority_key_custody_state(repository: &LocalWorkspace) -> Vec<(String, Vec<u8>)> {
    let state_directory = repository.root().join(".proof/state");
    let mut key_paths = vec![
        state_directory.join("authority-signing.ed25519"),
        state_directory.join("authority-successor.ed25519"),
    ];
    let published_directory = state_directory.join("authority-roots");
    if published_directory.exists() {
        key_paths.extend(
            fs::read_dir(&published_directory)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.is_file()),
        );
    }
    let mut custody = key_paths
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| {
            let relative_path = path
                .strip_prefix(repository.root())
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (relative_path, fs::read(path).unwrap())
        })
        .collect::<Vec<_>>();
    custody.sort_by(|left, right| left.0.cmp(&right.0));
    custody
}

fn changed_tables(
    before: &BTreeMap<String, Vec<Vec<String>>>,
    after: &BTreeMap<String, Vec<Vec<String>>>,
) -> Vec<String> {
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    before
        .iter()
        .filter(|(table_name, rows)| after.get(*table_name) != Some(*rows))
        .map(|(table_name, _)| table_name.clone())
        .collect()
}

struct StagedRootTransition {
    transition: WorkspaceAuthorityRootTransitionV1,
    envelope_json: String,
    successor_key_id: Ed25519KeyId,
    staging_path: PathBuf,
    published_path: PathBuf,
}

fn stage_valid_root_transition(
    fixture: &ContextFixture,
    successor_secret: [u8; 32],
) -> StagedRootTransition {
    let root = fixture
        .repository
        .workspace_authority_root(fixture.workspace_id)
        .unwrap();
    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    let predecessor = signer_from_file(
        &fixture
            .repository
            .root()
            .join(AUTHORITY_SIGNING_KEY_RELATIVE_PATH),
    );
    let successor = Ed25519SigningProvider::from_secret_bytes(&successor_secret);
    let successor_metadata = successor.metadata().unwrap();
    let successor_key_id = Ed25519KeyId::new(successor_metadata.key_id).unwrap();
    let transition = WorkspaceAuthorityRootTransitionV1 {
        api_version: WorkspaceAuthorityRootTransitionApiVersion::V1,
        authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
        previous_authority_record_digest: head.record_digest,
        workspace_id: fixture.workspace_id,
        transition_id: ROOT_TRANSITION_ID
            .parse::<AuthorityRootTransitionId>()
            .unwrap(),
        predecessor_authority_key_id: root.authority_key_id,
        successor_authority_key_id: successor_key_id.clone(),
        successor_public_key: Ed25519PublicKey::new(BASE64.encode(successor_metadata.public_key))
            .unwrap(),
        algorithm: Ed25519Algorithm::Ed25519,
        activated_by_principal_id: fixture.human_principal_id,
        activated_at: fixture.time(40),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
        &transition,
        &[&predecessor, &successor],
    )
    .unwrap();
    let staging_path = fixture
        .repository
        .root()
        .join(SUCCESSOR_STAGING_KEY_RELATIVE_PATH);
    write_private_key(&staging_path, &successor.secret_bytes());
    let successor_hex = successor_key_id.as_str().strip_prefix("ed25519:").unwrap();
    let published_path = fixture.repository.root().join(format!(
        ".proof/state/authority-roots/{successor_hex}.ed25519"
    ));
    StagedRootTransition {
        transition,
        envelope_json: signed.envelope_json,
        successor_key_id,
        staging_path,
        published_path,
    }
}

fn snapshot_rows(connection: &rusqlite::Connection, sql: &str) -> Vec<Vec<String>> {
    let mut statement = connection.prepare(sql).unwrap();
    let column_count = statement.column_count();
    statement
        .query_map([], |row| {
            (0..column_count)
                .map(|column| match row.get_ref(column)? {
                    ValueRef::Null => Ok("null".to_owned()),
                    ValueRef::Integer(value) => Ok(format!("integer:{value}")),
                    ValueRef::Real(value) => Ok(format!("real:{value:?}")),
                    ValueRef::Text(value) => Ok(format!("text:{}", String::from_utf8_lossy(value))),
                    ValueRef::Blob(value) => Ok(format!("blob:{}", BASE64.encode(value))),
                })
                .collect::<Result<Vec<_>, rusqlite::Error>>()
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn signer_from_file(path: &Path) -> Ed25519SigningProvider {
    let secret: [u8; 32] = fs::read(path).unwrap().as_slice().try_into().unwrap();
    Ed25519SigningProvider::from_secret_bytes(&secret)
}

fn write_private_key(path: &Path, secret: &[u8; 32]) {
    fs::write(path, secret).unwrap();
    set_private_file_permissions(path);
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) {}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(
        timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
    )
    .unwrap()
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-local-p0004-falsification-{}-{sequence}",
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
