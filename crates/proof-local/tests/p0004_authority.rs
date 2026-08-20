use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD},
};
use proof_application::{
    ArtifactKind, BindingId, ChangeSetId, CreateAgentPrincipalCommand, DelegationId, EditionId,
    EnrollmentChallengeId, EnvironmentId, InitializeWorkspaceCommand, LocaleId, ObjectId,
    PresentationId, PrincipalId, ReleaseId, RevocationId, SchemaId, Timestamp, WorkspaceId,
    authority::{
        AgentPrincipalType, AuthenticatedAuthorityExecutor, AuthenticatedCommandApiVersion,
        AuthenticatedCommandEnvelopeJson, AuthenticatedCommandKeyUsage, AuthenticatedCommandV1,
        AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationResultV1, AuthorityAction, AuthorityAdministrator, AuthorityAudience,
        AuthorityError, AuthorityHeadV1, AuthorityPrincipalType, AuthorityRecordV1,
        AuthorityRepository, AuthoritySequence, AuthorizationDecisionApiVersion,
        AuthorizationDecisionOutcome, AuthorizationDecisionV2, AuthorizationDenialReason,
        BindingDecisionEvidenceV2, BindingEnrollmentChallengeV1, CommandInputApiVersion,
        CommandInputV1, DelegationActionsV2, DelegationApiVersion, DelegationConstraintsV2,
        DelegationDecisionEvidenceV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
        DelegationObjectIdsV2, DelegationResolutionV2, DelegationRevocationApiVersion,
        DelegationRevocationReasonV1, DelegationRevocationV1, DelegationSchemaIdsV2,
        DelegationScopeV2, DelegationV2, DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId,
        Ed25519PublicKey, EffectiveConstraintsV2, EnrollmentChallengeApiVersion,
        LocalEd25519AuthenticatedSubjectV1, MAX_AUTHORITY_ENVELOPE_BYTES,
        MAX_AUTHORITY_RECORD_BYTES, MaxContextBytes, MaxEditsPerChangeSet, MaxObjects,
        PresentationConsumed, PrincipalBindingApiVersion, PrincipalBindingV1, PrincipalStateV2,
        PrincipalStatusApiVersion, PrincipalStatusV1, RequestedChangeSetIdsV2,
        RequestedEditionIdsV2, RequestedEnvironmentIdsV2, RequestedLocalesV2, RequestedObjectIdsV2,
        RequestedReleaseIdsV2, RequestedResourcesV2, RequestedSchemaIdsV2, RequestedWorkspaceIdsV2,
        SubdelegationDisabled, WorkspaceStatusInputV1,
    },
    create_agent_principal, initialize_workspace,
};
use proof_attestation::authority::{
    AuthorityPayloadProfile, sign_authority_payload, verify_authority_envelope,
};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use rusqlite::types::ValueRef;

const WORKSPACE_ID: &str = "019d0000-0000-7000-8000-000000000001";
const HUMAN_PRINCIPAL_ID: &str = "019d0000-0000-7000-8000-000000000002";
const AGENT_PRINCIPAL_ID: &str = "019d0000-0000-7000-8000-000000000003";
const AGENT_CREATE_KEY: &str = "019d0000-0000-7000-8000-000000000004";
const BINDING_ID: &str = "019d0000-0000-7000-8000-000000000005";
const UNKNOWN_BINDING_ID: &str = "019d0000-0000-7000-8000-000000000006";
const ENROLLMENT_CHALLENGE_ID: &str = "019d0000-0000-7000-8000-000000000007";
const DELEGATION_ID: &str = "019d0000-0000-7000-8000-000000000008";
const UNKNOWN_DELEGATION_ID: &str = "019d0000-0000-7000-8000-000000000009";
const PRESENTATION_ID: &str = "019d0000-0000-7000-8000-00000000000a";
const OTHER_PRESENTATION_ID: &str = "019d0000-0000-7000-8000-00000000000b";
const REVOCATION_ID: &str = "019d0000-0000-7000-8000-00000000000c";
const BASE_TIME: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 1_000;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x24; 32];
const MAX_LOGICAL_ID_BYTES: usize = 128;
const MAX_LOCALE_ID_BYTES: usize = 64;

#[test]
fn private_subject_commitment_vector_reproduces_the_public_actor_context_digest() {
    let private_input = include_str!(
        "../../../conformance/v1/authority/vectors/requesting-subject-commitment.input.private-test.json"
    );
    let input = parse_strict(private_input.as_bytes()).unwrap();
    let canonical = canonicalize(&input).unwrap();
    let commitment = digest(ArtifactKind::AuthenticatedSubjectCommitmentV1, &canonical);
    assert_eq!(
        commitment.to_string(),
        "blake3:3d9fef74e8149e34ef4c5a1b97fe4429b9d0ff61b7b801e449b313494e4b3c42"
    );

    let actor_context = parse_strict(
        include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.valid.json"
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        actor_context["requesting_subject_commitment"],
        commitment.to_string()
    );
}

#[test]
fn valid_status_consumes_once_and_replay_is_write_free() {
    let fixture = AuthorityFixture::new();
    let invocation = fixture.status_invocation(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
    );
    let evaluated_at = fixture.time(120);

    assert_eq!(fixture.durable_counts(), DurableCounts::default());
    let head_before = fixture.authority_head_sequence();
    let execution = fixture
        .repository
        .execute_authenticated(invocation.clone(), evaluated_at)
        .unwrap();

    execution.validate().unwrap();
    assert_eq!(
        execution.actor_context.authenticated_at,
        fixture.authenticated_at
    );
    assert_eq!(execution.decision.evaluated_at, evaluated_at);
    assert_ne!(execution.actor_context.authenticated_at, evaluated_at);
    assert_eq!(
        execution.decision.decision,
        AuthorizationDecisionOutcome::Allow
    );
    assert_eq!(execution.decision.reason_code, None);
    assert!(matches!(
        execution.result,
        AuthenticatedOperationResultV1::WorkspaceStatus(_)
    ));
    assert_eq!(
        fixture.durable_counts(),
        DurableCounts {
            decisions: 1,
            consumptions: 1,
            actor_evidence: 1,
        }
    );
    assert_eq!(fixture.authority_head_sequence(), head_before + 1);
    assert!(
        fixture
            .repository
            .consumed_presentation(fixture.workspace_id, PRESENTATION_ID.parse().unwrap())
            .unwrap()
    );

    assert_eq!(
        fixture
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap_err(),
        AuthorityError::AuthReplay
    );
    assert_eq!(
        fixture.durable_counts(),
        DurableCounts {
            decisions: 1,
            consumptions: 1,
            actor_evidence: 1,
        }
    );
    assert_eq!(fixture.authority_head_sequence(), head_before + 1);
}

#[test]
fn unknown_binding_and_invalid_signature_have_public_parity_and_write_nothing() {
    let fixture = AuthorityFixture::new();
    let wrong_signer = Ed25519SigningProvider::from_secret_bytes(&[0x55; 32]);
    let invalid_signature = fixture.status_invocation(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &wrong_signer,
    );
    let unknown_binding = fixture.status_invocation(
        OTHER_PRESENTATION_ID,
        UNKNOWN_BINDING_ID.parse().unwrap(),
        fixture.delegation_id,
        &fixture.agent_signer,
    );
    let evaluated_at = fixture.time(120);
    let head_before = fixture.authority_head_sequence();

    let invalid_error = fixture
        .repository
        .execute_authenticated(invalid_signature, evaluated_at)
        .unwrap_err();
    assert_eq!(invalid_error, AuthorityError::AuthSignatureInvalid);
    assert_eq!(invalid_error.public_code(), "proof.auth.denied");
    assert_eq!(fixture.durable_counts(), DurableCounts::default());
    assert_eq!(fixture.authority_head_sequence(), head_before);

    let unknown_error = fixture
        .repository
        .execute_authenticated(unknown_binding, evaluated_at)
        .unwrap_err();
    assert_eq!(unknown_error, AuthorityError::AuthBindingNotFound);
    assert_eq!(unknown_error.public_code(), "proof.auth.denied");
    assert_eq!(unknown_error.public_code(), invalid_error.public_code());
    assert_eq!(fixture.durable_counts(), DurableCounts::default());
    assert_eq!(fixture.authority_head_sequence(), head_before);
}

#[test]
fn unknown_delegation_is_a_committed_denial_and_replay_adds_no_record() {
    let fixture = AuthorityFixture::new();
    let presentation_id = PRESENTATION_ID.parse::<PresentationId>().unwrap();
    let invocation = fixture.status_invocation(
        PRESENTATION_ID,
        fixture.binding_id,
        UNKNOWN_DELEGATION_ID.parse().unwrap(),
        &fixture.agent_signer,
    );
    let evaluated_at = fixture.time(120);
    let head_before = fixture.authority_head_sequence();

    let error = fixture
        .repository
        .execute_authenticated(invocation.clone(), evaluated_at)
        .unwrap_err();
    assert_eq!(error, AuthorityError::DelegationUnavailable);
    assert_eq!(error.public_code(), "proof.authorization.denied");
    assert_eq!(
        fixture.durable_counts(),
        DurableCounts {
            decisions: 1,
            consumptions: 1,
            actor_evidence: 1,
        }
    );
    assert_eq!(fixture.authority_head_sequence(), head_before + 1);
    assert!(
        fixture
            .repository
            .consumed_presentation(fixture.workspace_id, presentation_id)
            .unwrap()
    );

    let decision = fixture.decision(presentation_id);
    assert_eq!(decision.decision, AuthorizationDecisionOutcome::Deny);
    assert_eq!(
        decision.reason_code,
        Some(AuthorizationDenialReason::DelegationUnavailable)
    );
    assert_eq!(decision.delegation.record_digest, None);
    assert_eq!(decision.delegation.revocation_record_digest, None);
    decision.validate().unwrap();

    assert_eq!(
        fixture
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap_err(),
        AuthorityError::AuthReplay
    );
    assert_eq!(
        fixture.durable_counts(),
        DurableCounts {
            decisions: 1,
            consumptions: 1,
            actor_evidence: 1,
        }
    );
    assert_eq!(fixture.authority_head_sequence(), head_before + 1);
}

#[test]
fn fresh_presentation_after_revocation_is_consumed_but_result_is_withheld() {
    let fixture = AuthorityFixture::new();
    let first = fixture.status_invocation(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
    );
    fixture
        .repository
        .execute_authenticated(first, fixture.time(120))
        .unwrap();

    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    fixture
        .repository
        .revoke_delegation(DelegationRevocationV1 {
            api_version: DelegationRevocationApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: head.record_digest,
            workspace_id: fixture.workspace_id,
            revocation_id: REVOCATION_ID.parse::<RevocationId>().unwrap(),
            delegation_id: fixture.delegation_id,
            revoked_by_principal_id: fixture.human_principal_id,
            revoked_at: fixture.time(130),
            reason: DelegationRevocationReasonV1::IssuerRequest,
        })
        .unwrap();

    let second_presentation_id = OTHER_PRESENTATION_ID.parse::<PresentationId>().unwrap();
    let fresh = fixture.status_invocation(
        OTHER_PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
    );
    assert_eq!(
        fixture
            .repository
            .execute_authenticated(fresh, fixture.time(132))
            .unwrap_err(),
        AuthorityError::DelegationRevoked
    );
    assert_eq!(
        fixture.durable_counts(),
        DurableCounts {
            decisions: 2,
            consumptions: 2,
            actor_evidence: 2,
        }
    );
    assert_eq!(
        fixture.decision(second_presentation_id).reason_code,
        Some(AuthorizationDenialReason::DelegationRevoked)
    );
}

#[test]
fn conformance_authentication_time_boundaries_execute_through_the_public_kernel() {
    let vector = authentication_time_boundaries_vector();
    assert_eq!(
        vector.api_version,
        "proof.dev/conformance/authentication-time-boundaries/v1"
    );
    assert_eq!(vector.max_future_skew_seconds, 30);
    let issued_at = vector.issued_at.parse::<Timestamp>().unwrap();
    let expires_at = vector.expires_at.parse::<Timestamp>().unwrap();
    let base_time = add_seconds(issued_at, -120);

    for evaluated_at in &vector.accepted_evaluated_at {
        let evaluated_at = evaluated_at.parse::<Timestamp>().unwrap();
        let fixture = AuthorityFixture::new_at(base_time);
        let invocation = fixture.status_invocation_at(
            PRESENTATION_ID,
            fixture.binding_id,
            fixture.delegation_id,
            &fixture.agent_signer,
            issued_at,
            expires_at,
        );
        let execution = fixture
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap();
        assert_eq!(
            execution.decision.decision,
            AuthorizationDecisionOutcome::Allow
        );
        assert_eq!(fixture.durable_counts(), DurableCounts::one_execution());
    }

    assert_eq!(
        issued_at.unix_timestamp_nanos()
            - vector.accepted_evaluated_at[0]
                .parse::<Timestamp>()
                .unwrap()
                .unix_timestamp_nanos(),
        i128::from(vector.max_future_skew_seconds) * 1_000_000_000
    );
    for rejected in &vector.rejected {
        let fixture = AuthorityFixture::new_at(base_time);
        let invocation = fixture.status_invocation_at(
            PRESENTATION_ID,
            fixture.binding_id,
            fixture.delegation_id,
            &fixture.agent_signer,
            issued_at,
            expires_at,
        );
        let error = fixture
            .repository
            .execute_authenticated(
                invocation,
                rejected.evaluated_at.parse::<Timestamp>().unwrap(),
            )
            .unwrap_err();
        assert_eq!(error.code(), rejected.expected_code);
        assert_eq!(fixture.durable_counts(), DurableCounts::default());
    }

    let future_issue_rejection = vector
        .rejected
        .iter()
        .find(|case| case.expected_code == "proof.auth.not_yet_valid")
        .unwrap();
    assert_eq!(
        issued_at.unix_timestamp_nanos()
            - future_issue_rejection
                .evaluated_at
                .parse::<Timestamp>()
                .unwrap()
                .unix_timestamp_nanos(),
        i128::from(vector.max_future_skew_seconds + 1) * 1_000_000_000
    );
    let expiry_rejection = vector
        .rejected
        .iter()
        .find(|case| case.expected_code == "proof.auth.expired")
        .unwrap();
    assert_eq!(
        expiry_rejection.evaluated_at.parse::<Timestamp>().unwrap(),
        expires_at
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained test compares all four inclusive and exclusive binding/delegation boundaries"
)]
fn binding_and_delegation_intervals_are_inclusive_start_exclusive_expiry() {
    let base_time = BASE_TIME.parse::<Timestamp>().unwrap();
    let shared_start = TemporalConfiguration {
        binding_not_before: 23,
        delegation_not_before: 23,
        ..TemporalConfiguration::default()
    };
    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, shared_start);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert_eq!(
        fixture
            .repository
            .execute_authenticated(invocation, add_seconds(base_time, 23))
            .unwrap()
            .decision
            .decision,
        AuthorizationDecisionOutcome::Allow
    );
    assert_eq!(fixture.durable_counts(), DurableCounts::one_execution());

    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, shared_start);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_nanos(add_seconds(base_time, 23), -1),
        &AuthorityError::AuthBindingInactive,
        AuthorizationDenialReason::BindingInactive,
    );

    let binding_expiry = TemporalConfiguration {
        binding_expires: 3_600,
        delegation_expires: 4_000,
        ..TemporalConfiguration::default()
    };
    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, binding_expiry);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        add_seconds(base_time, 3_400),
        add_seconds(base_time, 3_700),
    );
    assert!(
        fixture
            .repository
            .execute_authenticated(invocation, add_nanos(add_seconds(base_time, 3_600), -1),)
            .is_ok()
    );

    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, binding_expiry);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        add_seconds(base_time, 3_400),
        add_seconds(base_time, 3_700),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_seconds(base_time, 3_600),
        &AuthorityError::AuthBindingInactive,
        AuthorizationDenialReason::BindingInactive,
    );

    let fixture = AuthorityFixture::new_at(base_time);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_nanos(add_seconds(base_time, 23), -1),
        &AuthorityError::DelegationNotYetValid,
        AuthorizationDenialReason::DelegationNotYetValid,
    );

    let fixture = AuthorityFixture::new_at(base_time);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert!(
        fixture
            .repository
            .execute_authenticated(invocation, add_seconds(base_time, 23))
            .is_ok()
    );

    let delegation_expiry = TemporalConfiguration {
        binding_expires: 4_000,
        delegation_expires: 3_600,
        ..TemporalConfiguration::default()
    };
    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, delegation_expiry);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        add_seconds(base_time, 3_400),
        add_seconds(base_time, 3_700),
    );
    assert!(
        fixture
            .repository
            .execute_authenticated(invocation, add_nanos(add_seconds(base_time, 3_600), -1),)
            .is_ok()
    );

    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, delegation_expiry);
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        add_seconds(base_time, 3_400),
        add_seconds(base_time, 3_700),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_seconds(base_time, 3_600),
        &AuthorityError::DelegationExpired,
        AuthorizationDenialReason::DelegationExpired,
    );
}

#[test]
fn causal_disablement_and_revocation_precede_record_timestamps_and_grant_time() {
    let base_time = BASE_TIME.parse::<Timestamp>().unwrap();
    let future_trusted_time = TemporalConfiguration {
        trusted_time: 30,
        delegation_not_before: 200,
        ..TemporalConfiguration::default()
    };
    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, future_trusted_time);
    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    fixture
        .repository
        .set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            workspace_id: fixture.workspace_id,
            principal_id: fixture.agent_principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled: false,
            recorded_by_principal_id: fixture.human_principal_id,
            recorded_at: add_seconds(base_time, 29),
        })
        .unwrap();
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_seconds(base_time, 25),
        &AuthorityError::PrincipalDisabled,
        AuthorizationDenialReason::PrincipalDisabled,
    );

    let fixture = AuthorityFixture::new_with_temporal_configuration(base_time, future_trusted_time);
    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    fixture
        .repository
        .revoke_delegation(DelegationRevocationV1 {
            api_version: DelegationRevocationApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: head.record_digest,
            workspace_id: fixture.workspace_id,
            revocation_id: REVOCATION_ID.parse().unwrap(),
            delegation_id: fixture.delegation_id,
            revoked_by_principal_id: fixture.human_principal_id,
            revoked_at: add_seconds(base_time, 29),
            reason: DelegationRevocationReasonV1::IssuerRequest,
        })
        .unwrap();
    let invocation = fixture.status_invocation_at(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
        base_time,
        add_seconds(base_time, 300),
    );
    assert_committed_denial(
        &fixture,
        invocation,
        add_seconds(base_time, 25),
        &AuthorityError::DelegationRevoked,
        AuthorizationDenialReason::DelegationRevoked,
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained test proves every collection and byte boundary for both largest authority records"
)]
fn maximum_typed_authority_records_fit_the_signed_profile_and_max_plus_one_rejects() {
    let signer = Ed25519SigningProvider::from_secret_bytes(&[0x63; 32]);
    let signer_metadata = signer.metadata().unwrap();
    let signer_key_id = Ed25519KeyId::new(signer_metadata.key_id.clone()).unwrap();
    let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
    let human_principal_id = HUMAN_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
    let agent_principal_id = AGENT_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
    let canonical_seed = canonicalize(&serde_json::json!({"boundary": "schema-maximum"})).unwrap();
    let boundary_digest = digest(ArtifactKind::AuthorityRecordV1, &canonical_seed);
    let base_time = BASE_TIME.parse::<Timestamp>().unwrap();

    let maximum_delegation = DelegationV2 {
        api_version: DelegationApiVersion::V1,
        authority_sequence: AuthoritySequence::new(AuthoritySequence::MAX).unwrap(),
        previous_authority_record_digest: Some(boundary_digest),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        workspace_id,
        delegation_profile: DirectAuthorityProfileV1::Direct,
        issuer_principal_id: human_principal_id,
        recipient_principal_id: agent_principal_id,
        actions: DelegationActionsV2::new(all_authority_actions()).unwrap(),
        scope: DelegationScopeV2 {
            environment_ids: DelegationEnvironmentIdsV2::new(maximum_environment_ids()).unwrap(),
            object_ids: DelegationObjectIdsV2::new(operational_ids::<ObjectId>(100, 0x10)).unwrap(),
            schema_ids: DelegationSchemaIdsV2::new(maximum_schema_ids()).unwrap(),
            locales: DelegationLocalesV2::new(maximum_locale_ids()).unwrap(),
        },
        constraints: DelegationConstraintsV2 {
            max_objects: MaxObjects::new(MaxObjects::MAX).unwrap(),
            max_context_bytes: MaxContextBytes::new(MaxContextBytes::MAX).unwrap(),
            max_edits_per_changeset: MaxEditsPerChangeSet::new(MaxEditsPerChangeSet::MAX).unwrap(),
            allow_subdelegation: SubdelegationDisabled,
        },
        not_before: base_time,
        expires_at: add_seconds(base_time, 1),
        issued_at: base_time,
    };
    maximum_delegation.validate().unwrap();
    assert_signed_authority_record_fits_and_verifies(
        &AuthorityRecordV1::Delegation(maximum_delegation),
        &signer,
        &signer_metadata.key_id,
    );

    let maximum_decision = AuthorizationDecisionV2 {
        api_version: AuthorizationDecisionApiVersion::V1,
        authority_sequence: AuthoritySequence::new(AuthoritySequence::MAX).unwrap(),
        previous_authority_record_digest: boundary_digest,
        audience: AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: AuthoritySequence::new(AuthoritySequence::MAX - 1).unwrap(),
            record_digest: boundary_digest,
        },
        authority_key_id: signer_key_id,
        operation: proof_application::authority::AuthorityOperation::WorkspaceStatusV1,
        requested_action: AuthorityAction::WorkspaceStatus,
        requested_resources: RequestedResourcesV2 {
            workspace_ids: RequestedWorkspaceIdsV2::new(vec![workspace_id]).unwrap(),
            environment_ids: RequestedEnvironmentIdsV2::new(maximum_environment_ids()).unwrap(),
            object_ids: RequestedObjectIdsV2::new(operational_ids::<ObjectId>(100, 0x20)).unwrap(),
            schema_ids: RequestedSchemaIdsV2::new(maximum_schema_ids()).unwrap(),
            locales: RequestedLocalesV2::new(maximum_locale_ids()).unwrap(),
            changeset_ids: RequestedChangeSetIdsV2::new(operational_ids::<ChangeSetId>(100, 0x30))
                .unwrap(),
            edition_ids: RequestedEditionIdsV2::new(operational_ids::<EditionId>(100, 0x40))
                .unwrap(),
            release_ids: RequestedReleaseIdsV2::new(operational_ids::<ReleaseId>(100, 0x50))
                .unwrap(),
        },
        effective_constraints: EffectiveConstraintsV2 {
            max_objects: MaxObjects::new(MaxObjects::MAX).unwrap(),
            max_context_bytes: MaxContextBytes::new(MaxContextBytes::MAX).unwrap(),
            max_edits_per_changeset: MaxEditsPerChangeSet::new(MaxEditsPerChangeSet::MAX).unwrap(),
        },
        command_digest: boundary_digest,
        command_envelope_digest: boundary_digest,
        presentation_id: PRESENTATION_ID.parse().unwrap(),
        presentation_consumed: PresentationConsumed,
        requesting_subject_commitment: boundary_digest,
        actor_context_digest: boundary_digest,
        requesting_principal_id: human_principal_id,
        operating_principal_id: agent_principal_id,
        principal_state: PrincipalStateV2 {
            requesting_principal_enabled: true,
            operating_principal_enabled: true,
        },
        binding: BindingDecisionEvidenceV2 {
            binding_id: BINDING_ID.parse().unwrap(),
            authority_sequence: AuthoritySequence::new(AuthoritySequence::MAX - 1).unwrap(),
            record_digest: boundary_digest,
            revocation_record_digest: None,
        },
        delegation: DelegationDecisionEvidenceV2 {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            record_digest: Some(boundary_digest),
            revocation_record_digest: None,
            resolution: DelegationResolutionV2::Resolved,
        },
        policy_profile: DirectAuthorityProfileV1::Direct,
        policy_bundle_digest: boundary_digest,
        evaluated_at: base_time,
        decision: AuthorizationDecisionOutcome::Allow,
        reason_code: None,
    };
    maximum_decision.validate().unwrap();
    assert_signed_authority_record_fits_and_verifies(
        &AuthorityRecordV1::AuthorizationDecision(maximum_decision),
        &signer,
        &signer_metadata.key_id,
    );

    let mut too_many_actions = all_authority_actions();
    too_many_actions.push(AuthorityAction::WorkspaceStatus);
    assert!(DelegationActionsV2::new(too_many_actions).is_err());
    assert!(DelegationEnvironmentIdsV2::new(maximum_environment_ids_with_count(33)).is_err());
    assert!(DelegationObjectIdsV2::new(operational_ids::<ObjectId>(101, 0x10)).is_err());
    assert!(DelegationSchemaIdsV2::new(maximum_schema_ids_with_count(101)).is_err());
    assert!(DelegationLocalesV2::new(maximum_locale_ids_with_count(65)).is_err());
    assert!(RequestedWorkspaceIdsV2::new(operational_ids::<WorkspaceId>(2, 0x60)).is_err());
    assert!(RequestedEnvironmentIdsV2::new(maximum_environment_ids_with_count(33)).is_err());
    assert!(RequestedObjectIdsV2::new(operational_ids::<ObjectId>(101, 0x20)).is_err());
    assert!(RequestedSchemaIdsV2::new(maximum_schema_ids_with_count(101)).is_err());
    assert!(RequestedLocalesV2::new(maximum_locale_ids_with_count(65)).is_err());
    assert!(RequestedChangeSetIdsV2::new(operational_ids::<ChangeSetId>(101, 0x30)).is_err());
    assert!(RequestedEditionIdsV2::new(operational_ids::<EditionId>(101, 0x40)).is_err());
    assert!(RequestedReleaseIdsV2::new(operational_ids::<ReleaseId>(101, 0x50)).is_err());
    assert!(MaxObjects::new(MaxObjects::MAX + 1).is_err());
    assert!(MaxContextBytes::new(MaxContextBytes::MAX + 1).is_err());
    assert!(MaxEditsPerChangeSet::new(MaxEditsPerChangeSet::MAX + 1).is_err());
    assert!(AuthoritySequence::new(AuthoritySequence::MAX + 1).is_err());
    assert!(EnvironmentId::new(format!("e{}", "a".repeat(MAX_LOGICAL_ID_BYTES))).is_err());
    assert!(SchemaId::new(format!("s{}", "a".repeat(MAX_LOGICAL_ID_BYTES))).is_err());
    let mut maximum_plus_one_locale = maximum_locale_ids()[0].to_string();
    maximum_plus_one_locale.push('a');
    assert_eq!(maximum_plus_one_locale.len(), MAX_LOCALE_ID_BYTES + 1);
    assert!(LocaleId::new(maximum_plus_one_locale).is_err());
}

#[test]
fn persisted_public_authority_evidence_excludes_the_private_uid_and_blind() {
    let fixture = AuthorityFixture::new();
    let invocation = fixture.status_invocation(
        PRESENTATION_ID,
        fixture.binding_id,
        fixture.delegation_id,
        &fixture.agent_signer,
    );
    let execution = fixture
        .repository
        .execute_authenticated(invocation, fixture.time(120))
        .unwrap();
    let connection = fixture.repository.open_database().unwrap();
    let (raw_subject, blind): (String, String) = connection
        .query_row(
            "SELECT requesting_subject, blind
             FROM authenticated_subject_commitment_openings_v1
             WHERE workspace_id = ?1 AND requesting_principal_id = ?2",
            (
                fixture.workspace_id.to_string(),
                fixture.human_principal_id.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(raw_subject, format!("uid:{DETERMINISTIC_UID}"));
    assert_eq!(
        blind,
        BASE64_URL_SAFE_NO_PAD.encode(DETERMINISTIC_SUBJECT_BLIND)
    );

    let persisted_evidence = ordinary_authority_text(&connection);
    assert!(!persisted_evidence.contains(&raw_subject));
    assert!(!persisted_evidence.contains(&blind));
    let evidence_json = serde_json::to_string(&execution.actor_context_evidence).unwrap();
    assert!(!evidence_json.contains(&raw_subject));
    assert!(!evidence_json.contains(&blind));
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
    base_time: Timestamp,
    authenticated_at: Timestamp,
}

impl AuthorityFixture {
    fn new() -> Self {
        let base_time = BASE_TIME.parse::<Timestamp>().unwrap();
        Self::new_at(base_time)
    }

    fn new_at(base_time: Timestamp) -> Self {
        Self::new_with_temporal_configuration(base_time, TemporalConfiguration::default())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the fixture exercises the complete public enrollment, status, and direct-delegation lifecycle"
    )]
    fn new_with_temporal_configuration(
        base_time: Timestamp,
        temporal: TemporalConfiguration,
    ) -> Self {
        let directory = TestDirectory::new();
        let authenticated_at = add_seconds(base_time, temporal.trusted_time);
        let repository = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            DeterministicLocalAuthorityAdapter::new(
                DETERMINISTIC_UID,
                authenticated_at,
                DETERMINISTIC_SUBJECT_BLIND,
            ),
        )
        .unwrap();
        let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
        let human_principal_id = HUMAN_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        let agent_principal_id = AGENT_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        let binding_id = BINDING_ID.parse::<BindingId>().unwrap();
        let delegation_id = DELEGATION_ID.parse::<DelegationId>().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();
        create_agent_principal(
            &repository,
            CreateAgentPrincipalCommand {
                principal_id: agent_principal_id,
                display_name: "p0004-test-agent".to_owned(),
                idempotency_key: AGENT_CREATE_KEY.parse().unwrap(),
                created_at: base_time,
            },
        )
        .unwrap();

        let agent_signer = Ed25519SigningProvider::from_secret_bytes(&[0x42; 32]);
        let metadata = agent_signer.metadata().unwrap();
        let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
        let public_key = Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap();
        let challenge = BindingEnrollmentChallengeV1 {
            api_version: EnrollmentChallengeApiVersion::V1,
            challenge_id: ENROLLMENT_CHALLENGE_ID
                .parse::<EnrollmentChallengeId>()
                .unwrap(),
            audience: AuthorityAudience::for_workspace(workspace_id),
            workspace_id,
            binding_id,
            principal_id: agent_principal_id,
            candidate_key_id: key_id.clone(),
            issued_by_principal_id: human_principal_id,
            issued_at: add_seconds(base_time, 20),
            expires_at: add_seconds(base_time, 320),
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
                    issued_at: add_seconds(base_time, 21),
                    not_before: add_seconds(base_time, temporal.binding_not_before),
                    expires_at: add_seconds(base_time, temporal.binding_expires),
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
                principal_type: AuthorityPrincipalType::Agent,
                enabled: true,
                recorded_by_principal_id: human_principal_id,
                recorded_at: add_seconds(base_time, 22),
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
                not_before: add_seconds(base_time, temporal.delegation_not_before),
                expires_at: add_seconds(base_time, temporal.delegation_expires),
                issued_at: add_seconds(base_time, 23),
            })
            .unwrap();

        assert_eq!(
            repository
                .principal_binding(workspace_id, binding_id)
                .unwrap()
                .unwrap()
                .principal_id,
            agent_principal_id
        );
        assert!(
            repository
                .principal_status(workspace_id, agent_principal_id)
                .unwrap()
                .unwrap()
                .enabled
        );
        assert_eq!(
            repository
                .delegation_v2(workspace_id, delegation_id)
                .unwrap()
                .unwrap()
                .recipient_principal_id,
            agent_principal_id
        );

        Self {
            _directory: directory,
            repository,
            agent_signer,
            workspace_id,
            human_principal_id,
            agent_principal_id,
            binding_id,
            delegation_id,
            base_time,
            authenticated_at,
        }
    }

    fn time(&self, seconds: i64) -> Timestamp {
        add_seconds(self.base_time, seconds)
    }

    fn status_invocation(
        &self,
        presentation_id: &str,
        binding_id: BindingId,
        delegation_id: DelegationId,
        signer: &Ed25519SigningProvider,
    ) -> AuthenticatedInvocationV1 {
        self.status_invocation_at(
            presentation_id,
            binding_id,
            delegation_id,
            signer,
            self.time(100),
            self.time(300),
        )
    }

    fn status_invocation_at(
        &self,
        presentation_id: &str,
        binding_id: BindingId,
        delegation_id: DelegationId,
        signer: &Ed25519SigningProvider,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> AuthenticatedInvocationV1 {
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation: proof_application::authority::AuthorityOperation::WorkspaceStatusV1,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id,
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
        let payload = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation: command_input.operation,
            binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent_principal_id,
            delegation_id,
            command_digest,
            idempotency_key: None,
            presentation_id: presentation_id.parse().unwrap(),
            issued_at,
            expires_at,
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

    fn authority_head_sequence(&self) -> u64 {
        self.repository
            .authority_head(self.workspace_id)
            .unwrap()
            .unwrap()
            .sequence
            .get()
    }

    fn durable_counts(&self) -> DurableCounts {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM authorization_decisions_v2),
                        (SELECT COUNT(*) FROM presentation_consumptions_v1),
                        (SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1)",
                [],
                |row| {
                    Ok(DurableCounts {
                        decisions: row.get(0)?,
                        consumptions: row.get(1)?,
                        actor_evidence: row.get(2)?,
                    })
                },
            )
            .unwrap()
    }

    fn decision(&self, presentation_id: PresentationId) -> AuthorizationDecisionV2 {
        let decision_json: String = self
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
        serde_json::from_str(&decision_json).unwrap()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DurableCounts {
    decisions: i64,
    consumptions: i64,
    actor_evidence: i64,
}

impl DurableCounts {
    const fn one_execution() -> Self {
        Self {
            decisions: 1,
            consumptions: 1,
            actor_evidence: 1,
        }
    }
}

#[derive(Clone, Copy)]
struct TemporalConfiguration {
    trusted_time: i64,
    binding_not_before: i64,
    binding_expires: i64,
    delegation_not_before: i64,
    delegation_expires: i64,
}

impl Default for TemporalConfiguration {
    fn default() -> Self {
        Self {
            trusted_time: 30,
            binding_not_before: 21,
            binding_expires: 3_600,
            delegation_not_before: 23,
            delegation_expires: 3_600,
        }
    }
}

#[derive(serde::Deserialize)]
struct AuthenticationTimeBoundariesVector {
    api_version: String,
    issued_at: String,
    expires_at: String,
    max_future_skew_seconds: i64,
    accepted_evaluated_at: Vec<String>,
    rejected: Vec<AuthenticationTimeRejectedCase>,
}

#[derive(serde::Deserialize)]
struct AuthenticationTimeRejectedCase {
    evaluated_at: String,
    expected_code: String,
}

fn authentication_time_boundaries_vector() -> AuthenticationTimeBoundariesVector {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/v1/authority/vectors/authentication-time-boundaries.valid.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn assert_committed_denial(
    fixture: &AuthorityFixture,
    invocation: AuthenticatedInvocationV1,
    evaluated_at: Timestamp,
    expected_error: &AuthorityError,
    expected_reason: AuthorizationDenialReason,
) {
    assert_eq!(
        fixture
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap_err(),
        *expected_error
    );
    assert_eq!(fixture.durable_counts(), DurableCounts::one_execution());
    assert_eq!(
        fixture
            .decision(PRESENTATION_ID.parse::<PresentationId>().unwrap())
            .reason_code,
        Some(expected_reason)
    );
}

fn all_authority_actions() -> Vec<AuthorityAction> {
    vec![
        AuthorityAction::ChangesetAdd,
        AuthorityAction::ChangesetCommit,
        AuthorityAction::ChangesetCreate,
        AuthorityAction::ChangesetDiff,
        AuthorityAction::ChangesetGet,
        AuthorityAction::ChangesetSubmit,
        AuthorityAction::ChangesetValidate,
        AuthorityAction::ContextBuild,
        AuthorityAction::EditionCreate,
        AuthorityAction::ObjectQueryReleased,
        AuthorityAction::ReleaseCreate,
        AuthorityAction::WorkspaceStatus,
    ]
}

fn maximum_environment_ids() -> Vec<EnvironmentId> {
    maximum_environment_ids_with_count(32)
}

fn maximum_environment_ids_with_count(count: usize) -> Vec<EnvironmentId> {
    (0..count)
        .map(|index| {
            let value = format!("e{index:03}{}", "a".repeat(MAX_LOGICAL_ID_BYTES - 4));
            assert_eq!(value.len(), MAX_LOGICAL_ID_BYTES);
            EnvironmentId::new(value).unwrap()
        })
        .collect()
}

fn maximum_schema_ids() -> Vec<SchemaId> {
    maximum_schema_ids_with_count(100)
}

fn maximum_schema_ids_with_count(count: usize) -> Vec<SchemaId> {
    (0..count)
        .map(|index| {
            let value = format!("s{index:03}{}", "a".repeat(MAX_LOGICAL_ID_BYTES - 4));
            assert_eq!(value.len(), MAX_LOGICAL_ID_BYTES);
            SchemaId::new(value).unwrap()
        })
        .collect()
}

fn maximum_locale_ids() -> Vec<LocaleId> {
    maximum_locale_ids_with_count(64)
}

fn maximum_locale_ids_with_count(count: usize) -> Vec<LocaleId> {
    (0..count)
        .map(|index| {
            let first = char::from(b'a' + u8::try_from(index / 26).unwrap());
            let second = char::from(b'a' + u8::try_from(index % 26).unwrap());
            let value = format!(
                "{first}{second}-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaaaa-aaaaa"
            );
            assert_eq!(value.len(), MAX_LOCALE_ID_BYTES);
            LocaleId::new(value).unwrap()
        })
        .collect()
}

fn operational_ids<T>(count: usize, namespace: u16) -> Vec<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    (0..count)
        .map(|index| {
            format!("019d{namespace:04x}-0000-7000-8000-{index:012x}")
                .parse::<T>()
                .unwrap()
        })
        .collect()
}

fn assert_signed_authority_record_fits_and_verifies(
    record: &AuthorityRecordV1,
    signer: &Ed25519SigningProvider,
    expected_key_id: &str,
) {
    let canonical = canonicalize(&serde_json::to_value(record).unwrap()).unwrap();
    assert!(canonical.as_bytes().len() <= MAX_AUTHORITY_RECORD_BYTES);
    let signed_record =
        sign_authority_payload(AuthorityPayloadProfile::AuthorityRecord, record, &[signer])
            .unwrap();
    assert_eq!(signed_record.payload_json.as_bytes(), canonical.as_bytes());
    assert!(signed_record.payload_json.len() <= MAX_AUTHORITY_RECORD_BYTES);
    assert!(signed_record.envelope_json.len() <= MAX_AUTHORITY_ENVELOPE_BYTES);
    let verified = verify_authority_envelope::<AuthorityRecordV1>(
        signed_record.envelope_json.as_bytes(),
        AuthorityPayloadProfile::AuthorityRecord,
        &[expected_key_id],
    )
    .unwrap();
    assert_eq!(&verified.parsed.payload, record);
}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(
        timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
    )
    .unwrap()
}

fn add_nanos(timestamp: Timestamp, nanos: i128) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(timestamp.unix_timestamp_nanos() + nanos).unwrap()
}

fn ordinary_authority_text(connection: &rusqlite::Connection) -> String {
    const TABLES: &[&str] = &[
        "workspace_authority_roots",
        "authority_records",
        "binding_enrollment_challenges",
        "principal_bindings_v1",
        "principal_binding_revocations_v1",
        "principal_status_v1",
        "delegations_v2",
        "delegation_revocations_v2",
        "authenticated_actor_context_evidence_v1",
        "authorization_decisions_v2",
        "presentation_consumptions_v1",
        "authenticated_operation_results_v1",
    ];
    let mut persisted = String::new();
    for table in TABLES {
        let mut schema = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        let text_columns = schema
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .filter_map(|(name, column_type)| (column_type == "TEXT").then_some(name))
            .collect::<Vec<_>>();
        if text_columns.is_empty() {
            continue;
        }
        let projection = text_columns
            .iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let mut statement = connection
            .prepare(&format!("SELECT {projection} FROM \"{table}\""))
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                let mut values = Vec::new();
                for index in 0..text_columns.len() {
                    match row.get_ref(index)? {
                        ValueRef::Null => {}
                        ValueRef::Text(value) => {
                            values.push(String::from_utf8(value.to_vec()).unwrap());
                        }
                        _ => unreachable!("TEXT columns yield text or null"),
                    }
                }
                Ok(values)
            })
            .unwrap();
        for row in rows {
            for value in row.unwrap() {
                persisted.push_str(&value);
                persisted.push('\n');
            }
        }
    }
    persisted
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-local-p0004-test-{}-{sequence}",
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
