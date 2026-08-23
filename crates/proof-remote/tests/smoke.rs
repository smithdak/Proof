//! Placeholder integration test asserting that `proof-remote` compiles and
//! exposes the expected public type surface.
//!
//! This constructs nothing and only references the types and functions so that
//! nothing is dead; the follow-up implementation swarm fills in real
//! round-trip, chain, registry, and oracle tests.

use std::mem::size_of;

use proof_remote::{
    AgentAuthorizationV1, AuthenticatedActorContextEvidenceV2, AuthenticatedActorContextV2,
    ChangeSetApprovalV1, EnvironmentConfigActivationV1, EnvironmentConfigProposalV1,
    EnvironmentConfigV2, EnvironmentCreationV1, HttpRouteV1, HumanOperationRegistryV1,
    OidcIssuerConfigurationV1, OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputV1, OracleTraceV1, RemoteApplicationConsequenceV1,
    RemoteAuthenticationEventV1, RemoteAuthorityRecordEnvelopeV1, RemoteAuthorityRecordV1,
    RemoteAuthorizationDecisionV1, RemotePrincipalStatusV2, WorkspaceRoleAssignmentV1,
    WorkspaceRoleRevocationV1,
};

#[test]
fn public_type_surface_is_exposed() {
    let _ = size_of::<RemoteAuthorityRecordV1>();
    let _ = size_of::<RemoteAuthorityRecordEnvelopeV1>();
    let _ = size_of::<RemotePrincipalStatusV2>();
    let _ = size_of::<WorkspaceRoleAssignmentV1>();
    let _ = size_of::<WorkspaceRoleRevocationV1>();
    let _ = size_of::<OidcSubjectCommitmentInputV1>();
    let _ = size_of::<OidcIssuerConfigurationV1>();
    let _ = size_of::<OidcPrincipalBindingV1>();
    let _ = size_of::<OidcPrincipalBindingPrivateV1>();
    let _ = size_of::<RemoteAuthenticationEventV1>();
    let _ = size_of::<AuthenticatedActorContextV2>();
    let _ = size_of::<AuthenticatedActorContextEvidenceV2>();
    let _ = size_of::<ChangeSetApprovalV1>();
    let _ = size_of::<EnvironmentCreationV1>();
    let _ = size_of::<EnvironmentConfigProposalV1>();
    let _ = size_of::<EnvironmentConfigActivationV1>();
    let _ = size_of::<EnvironmentConfigV2>();
    let _ = size_of::<RemoteAuthorizationDecisionV1>();
    let _ = size_of::<RemoteApplicationConsequenceV1>();
    let _ = size_of::<AgentAuthorizationV1>();
    let _ = size_of::<HumanOperationRegistryV1>();
    let _ = size_of::<OracleTraceV1>();

    let _ = HttpRouteV1::ALL;
    let _ = proof_remote::AGENT_AUTHORITY_REGISTRY_SHA256;
    let _ = proof_remote::REMOTE_AUTHORIZATION_PROJECTION_SHA256;
    let _ = proof_remote::COMPLETE_HTTP_OPERATION_REGISTRY_SHA256;
    let _ = proof_remote::REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE;
    let _ = proof_remote::sign_remote_authority_record;
    let _ = proof_remote::parse_remote_authority_record_envelope;
    let _ = proof_remote::verify_remote_authority_record_envelope;
    let _ = proof_remote::validate_chain;
    let _ = proof_remote::validate_environment_config_v2;
}
