//! Public-surface smoke test for `proof-remote`.
//!
//! This is the crate-root contract test: it pins that every documented
//! re-export (types, traits, constants, and functions) resolves at
//! `proof_remote::…`, and that the headline public functions actually work
//! end-to-end (digest derivation, blind encode/decode, registry lookup and
//! frozen-hash recomputation, and a complete authority sign → parse → verify
//! round-trip). The deeper per-module conformance coverage lives in the sibling
//! `*_impl` integration binaries.

use std::any::type_name;
use std::mem::size_of;

use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider as _};
use proof_remote::{
    AGENT_AUTHORITY_REGISTRY_SHA256, AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
    AUTHORIZATION_RESOURCE_BINDING_DIGEST_CONTEXT, AgentAuthorizationV1,
    AgentOperationProjectionV1, AgentSubjectV1, ApplicationConsequenceOutcome, ApplicationKeyKind,
    ApprovalDecision, ApprovalPolicyV1, AuthenticatedActorContextEvidenceV2,
    AuthenticatedActorContextV2, AuthenticationProfile, AuthorizationDecisionKind,
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, ChangeSetApprovalV1,
    DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT, DelegationEvaluationV1, DeliveryConfigurationV1,
    ENVIRONMENT_CONFIG_DIGEST_CONTEXT, EffectDigestRule, EffectTimestampField,
    EffectiveConstraintsV1, EnvironmentConfigActivationV1, EnvironmentConfigProposalV1,
    EnvironmentConfigV2, EnvironmentCreationV1, HttpRouteV1, HumanOperationRegistryV1,
    IdentityFixtureV1, MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES, MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES,
    NormalizedEnvironmentConfigurationV1, OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT,
    OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT, OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT,
    OPERATION_EFFECT_DIGEST_CONTEXT, OidcAuthenticatedSubjectV1, OidcEnrollmentChallengeV1,
    OidcIssuerConfigurationV1, OidcPrincipalBindingPrivateV1, OidcPrincipalBindingRevocationV1,
    OidcPrincipalBindingV1, OidcSubjectCommitmentInputV1, OidcSubjectCommitmentOpeningV1,
    OperatingBindingEvaluationV1, OperatingBindingReferenceV1, OracleConsequence, OracleOutcome,
    OracleTraceV1, PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT,
    ParsedRemoteAuthorityRecordEnvelope, PrincipalStateV1,
    REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT, REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
    REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT, REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
    REMOTE_AUTHORITY_SIGNATURE_COUNT, REMOTE_AUTHORIZATION_POLICY_SELECTION_DIGEST_CONTEXT,
    REMOTE_AUTHORIZATION_PROJECTION_SHA256, REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT,
    REQUESTED_AUTHORIZATION_RESOURCES_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthenticationEventV1, RemoteAuthorityRecordEnvelopeV1, RemoteAuthorityRecordV1,
    RemoteAuthorizationDecisionV1, RemoteOperationV1, RemotePrincipalStatusV2, RemotePrincipalType,
    RemoteSemanticOracle, RequestedResourcesV1, SignedRemoteAuthorityRecordEnvelope, StableProblem,
    VerifiedRemoteAuthorityRecord, VerifiedRemoteAuthorityRecordEnvelope, WorkspaceRole,
    WorkspaceRoleAssignmentV1, WorkspaceRoleRevocationV1, application_problem_digest_preimage,
    authorization_resource_binding_digest, canonical_sha256_hex, classify_consequence_outcome,
    cross_check_route_operation, decode_blind, derive_key_digest, effect_timestamp_field,
    encode_blind, generate_subject_commitment_blind, normalized_operation_input_digest,
    oidc_discovery_metadata_digest, operation_effect_digest, operation_major,
    parse_remote_authority_record_envelope, public_operation_input_projection_digest,
    recompute_agent_authority_registry_sha256, recompute_complete_http_operation_registry_sha256,
    recompute_remote_authorization_projection_sha256, remote_authority_pae,
    remote_authorization_policy_selection_digest, requested_authorization_resources_digest,
    sign_remote_authority_record, subject_commitment_digest, validate_chain,
    validate_environment_config_v2, verify_remote_authority_record_envelope,
};

/// References a value (typically a `fn` item) so a surface test can prove a
/// crate-root name resolves without needing a full invocation here.
fn references<T>(_: T) {}

#[test]
#[allow(clippy::too_many_lines)]
fn crate_root_exposes_the_full_documented_surface() {
    // --- authority types ---
    let _ = size_of::<RemoteAuthorityRecordV1>();
    let _ = size_of::<RemoteAuthorityRecordEnvelopeV1>();
    let _ = size_of::<RemotePrincipalStatusV2>();
    let _ = size_of::<RemotePrincipalType>();
    let _ = size_of::<WorkspaceRole>();
    let _ = size_of::<WorkspaceRoleAssignmentV1>();
    let _ = size_of::<WorkspaceRoleRevocationV1>();
    let _ = size_of::<SignedRemoteAuthorityRecordEnvelope>();
    let _ = size_of::<ParsedRemoteAuthorityRecordEnvelope>();
    let _ = size_of::<VerifiedRemoteAuthorityRecordEnvelope>();
    let _ = size_of::<VerifiedRemoteAuthorityRecord>();
    assert!(!type_name::<dyn proof_remote::ActiveAuthorityKeyResolver>().is_empty());

    // --- governance types ---
    let _ = size_of::<ApprovalDecision>();
    let _ = size_of::<ApprovalPolicyV1>();
    let _ = size_of::<ChangeSetApprovalV1>();
    let _ = size_of::<DeliveryConfigurationV1>();
    let _ = size_of::<EnvironmentConfigActivationV1>();
    let _ = size_of::<EnvironmentConfigProposalV1>();
    let _ = size_of::<EnvironmentConfigV2>();
    let _ = size_of::<EnvironmentCreationV1>();
    let _ = size_of::<NormalizedEnvironmentConfigurationV1>();

    // --- identity types ---
    let _ = size_of::<AgentSubjectV1>();
    let _ = size_of::<AuthenticatedActorContextV2>();
    let _ = size_of::<AuthenticatedActorContextEvidenceV2>();
    let _ = size_of::<AuthenticationProfile>();
    let _ = size_of::<OidcAuthenticatedSubjectV1>();
    let _ = size_of::<OidcIssuerConfigurationV1>();
    let _ = size_of::<OidcPrincipalBindingV1>();
    let _ = size_of::<OidcPrincipalBindingPrivateV1>();
    let _ = size_of::<OidcPrincipalBindingRevocationV1>();
    let _ = size_of::<OidcSubjectCommitmentInputV1>();
    let _ = size_of::<OidcSubjectCommitmentOpeningV1>();
    let _ = size_of::<OperatingBindingReferenceV1>();
    let _ = size_of::<RemoteAuthenticationEventV1>();

    // --- oracle types ---
    let _ = size_of::<IdentityFixtureV1>();
    let _ = size_of::<OidcEnrollmentChallengeV1>();
    let _ = size_of::<OracleConsequence>();
    let _ = size_of::<OracleOutcome>();
    let _ = size_of::<OracleTraceV1>();
    let _ = size_of::<RemoteSemanticOracle>();
    let _ = size_of::<StableProblem>();

    // --- registry types ---
    let _ = size_of::<AgentAuthorizationV1>();
    let _ = size_of::<AgentOperationProjectionV1>();
    let _ = size_of::<ApplicationConsequenceOutcome>();
    let _ = size_of::<ApplicationKeyKind>();
    let _ = size_of::<AuthorizationDecisionKind>();
    let _ = size_of::<DelegationEvaluationV1>();
    let _ = size_of::<EffectDigestRule>();
    let _ = size_of::<EffectTimestampField>();
    let _ = size_of::<EffectiveConstraintsV1>();
    let _ = size_of::<HttpRouteV1>();
    let _ = size_of::<HumanOperationRegistryV1>();
    let _ = size_of::<OperatingBindingEvaluationV1>();
    let _ = size_of::<PrincipalStateV1>();
    let _ = size_of::<RemoteApplicationConsequenceV1>();
    let _ = size_of::<RemoteAuthorizationDecisionV1>();
    let _ = size_of::<RequestedResourcesV1>();

    // --- contract-critical constants ---
    assert_eq!(
        AGENT_AUTHORITY_REGISTRY_SHA256,
        "b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7"
    );
    assert_eq!(
        REMOTE_AUTHORIZATION_PROJECTION_SHA256,
        "e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b"
    );
    assert_eq!(
        COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf"
    );
    assert_eq!(
        REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
        "application/vnd.proof.remote-authority-record.v1+json"
    );
    assert_eq!(MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES, 65_536);
    assert_eq!(MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES, 98_304);
    assert_eq!(REMOTE_AUTHORITY_SIGNATURE_COUNT, 1);
    assert_eq!(
        REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
        "proof:remote-authority-record:v1"
    );
    assert_eq!(
        REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT,
        "proof:remote-authority-record-envelope:v1"
    );
    assert_eq!(
        ENVIRONMENT_CONFIG_DIGEST_CONTEXT,
        "proof:environment-config:v2"
    );
    assert_eq!(
        OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT,
        "proof:oidc-authenticated-subject-commitment:v1"
    );
    assert_eq!(
        OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT,
        "proof:oidc-issuer-configuration:v1"
    );
    assert_eq!(
        OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT,
        "proof:oidc-discovery-metadata:v1"
    );
    assert_eq!(
        REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
        "proof:remote-authentication-event:v1"
    );
    assert_eq!(
        REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT,
        "proof:remote-normalized-operation-input:v1"
    );
    assert_eq!(
        PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT,
        "proof:public-operation-input-projection:v1"
    );
    assert_eq!(
        AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
        "proof:authenticated-actor-context-evidence:v2"
    );
    assert_eq!(
        AUTHORIZATION_RESOURCE_BINDING_DIGEST_CONTEXT,
        "proof:authorization-resource-binding:v1"
    );
    assert_eq!(
        REQUESTED_AUTHORIZATION_RESOURCES_DIGEST_CONTEXT,
        "proof:requested-authorization-resources:v1"
    );
    assert_eq!(
        REMOTE_AUTHORIZATION_POLICY_SELECTION_DIGEST_CONTEXT,
        "proof:remote-authorization-policy-selection:v1"
    );
    assert_eq!(OPERATION_EFFECT_DIGEST_CONTEXT, "proof:operation-effect:v1");
    assert_eq!(
        DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT,
        "proof:delivery-management-fact:v1"
    );

    // --- function surface ---
    references(parse_remote_authority_record_envelope);
    references(remote_authority_pae);
    references(sign_remote_authority_record);
    references(validate_chain);
    references(verify_remote_authority_record_envelope);
    references(validate_environment_config_v2);
    references(decode_blind);
    references(encode_blind);
    references(generate_subject_commitment_blind);
    references(normalized_operation_input_digest);
    references(oidc_discovery_metadata_digest);
    references(public_operation_input_projection_digest);
    references(subject_commitment_digest);
    references(application_problem_digest_preimage);
    references(authorization_resource_binding_digest);
    references(canonical_sha256_hex);
    references(classify_consequence_outcome);
    references(cross_check_route_operation);
    references(effect_timestamp_field);
    references(operation_effect_digest);
    references(operation_major);
    references(recompute_agent_authority_registry_sha256);
    references(recompute_complete_http_operation_registry_sha256);
    references(recompute_remote_authorization_projection_sha256);
    references(remote_authorization_policy_selection_digest);
    references(requested_authorization_resources_digest);

    // --- closed route surface ---
    assert_eq!(HttpRouteV1::ALL.len(), 9);
    assert_eq!(HttpRouteV1::HumanOperations.method(), "POST");
    assert_eq!(
        HttpRouteV1::HumanOperations.path(),
        "/api/v1/human/operations/{name}/{major}"
    );
    assert_eq!(HttpRouteV1::AgentOperations.method(), "POST");
    assert_eq!(HttpRouteV1::OidcLogin.method(), "GET");
}

#[test]
fn digest_blind_and_registry_primitives_are_meaningful() {
    // derive_key_digest is deterministic and domain-separated.
    let bytes = b"{\"api_version\":\"proof.dev/smoke/v1\"}";
    let first = derive_key_digest("proof:smoke:v1", bytes);
    let again = derive_key_digest("proof:smoke:v1", bytes);
    let other = derive_key_digest("proof:other:v1", bytes);
    assert_eq!(first, again);
    assert_ne!(first, other);
    assert!(first.to_string().starts_with("blake3:"));

    // 32-byte blind -> exact base64url-no-pad round trip.
    let blind = [0x5a; 32];
    let encoded = encode_blind(&blind);
    assert_eq!(encoded.len(), 43);
    assert!(!encoded.contains('='));
    assert_eq!(decode_blind(&encoded).unwrap(), blind);
    let fresh = generate_subject_commitment_blind().unwrap();
    assert_ne!(fresh, [0u8; 32]);

    // Registry surface: a known Human row resolves, an unknown row fails closed.
    assert!(
        HumanOperationRegistryV1
            .lookup(
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v3"
            )
            .is_some()
    );
    assert!(
        HumanOperationRegistryV1
            .lookup("no.such", "proof.dev/operation/no.such/v1")
            .is_none()
    );
    assert_eq!(
        operation_major("proof.dev/operation/release.create/v2"),
        Some("v2")
    );
    assert_eq!(operation_major("proof.dev/operation/"), None);

    // Route/operation cross-check accepts agreement and rejects a mismatch.
    let op = RemoteOperationV1 {
        name: "changeset.approve".to_owned(),
        version: "proof.dev/operation/changeset.approve/v3".to_owned(),
    };
    cross_check_route_operation(HttpRouteV1::HumanOperations, "changeset.approve", "v3", &op)
        .unwrap();
    assert!(
        cross_check_route_operation(HttpRouteV1::HumanOperations, "changeset.approve", "v2", &op,)
            .is_err()
    );

    // The three frozen registry hashes still recompute from the retained bytes.
    recompute_agent_authority_registry_sha256().unwrap();
    recompute_remote_authorization_projection_sha256().unwrap();
    recompute_complete_http_operation_registry_sha256().unwrap();
}

#[test]
fn authority_sign_parse_verify_round_trip_works() {
    let record: RemoteAuthorityRecordV1 = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/collaboration-server/vectors/workspace-role-assignment.valid.json"
    ))
    .unwrap();

    let provider = Ed25519SigningProvider::from_secret_bytes(&[7u8; 32]);
    let metadata = provider.metadata().unwrap();
    let key_id = metadata.key_id.clone();

    let signed = sign_remote_authority_record(&record, &provider).unwrap();
    assert_eq!(signed.key_id, key_id);
    assert_eq!(signed.payload_digest, record.digest());

    let parsed = parse_remote_authority_record_envelope(signed.envelope_json.as_bytes()).unwrap();
    assert_eq!(parsed.record, record);
    assert_eq!(parsed.envelope_digest, signed.envelope_digest);

    let verified =
        verify_remote_authority_record_envelope(signed.envelope_json.as_bytes(), &key_id).unwrap();
    assert_eq!(verified.key_id, key_id);
    assert_eq!(verified.parsed.record, record);
}
