#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

//! Remote actor and shared-contract conformance foundation.
//!
//! This crate implements the complete public type/function surface for the
//! Milestone 3 remote authority, identity, governance, registry, and oracle
//! boundary ratified by the accepted
//! [single-Workspace collaboration-server contract] and
//! [ADR-0013]. Its types round-trip the closed JSON Schemas and vectors retained
//! under `conformance/v1/collaboration-server/`, and its construction,
//! canonicalization, signing, verification, digest, and validation functions are
//! fully implemented and exercised by the `tests/` integration binaries.
//!
//! [single-Workspace collaboration-server contract]: https://proof.dev/docs/architecture/collaboration-server
//! [ADR-0013]: https://proof.dev/docs/decisions/0013-single-workspace-collaboration-server

pub mod authority;
pub mod bundle;
pub mod governance;
pub mod identity;
pub mod oracle;
pub mod registry;

mod serde_support;

use proof_domain::ContentDigest;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Closed error taxonomy shared by every remote-actor module.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemoteError {
    /// A remote authority record, envelope, or chain failed validation.
    #[error("remote authority validation failed: {0}")]
    Authority(String),
    /// OIDC identity, commitment, or actor-context validation failed.
    #[error("OIDC identity validation failed: {0}")]
    Identity(String),
    /// Approval or Environment-configuration closure validation failed.
    #[error("governance validation failed: {0}")]
    Governance(String),
    /// An operation registry or digest preimage could not be resolved.
    #[error("registry resolution failed: {0}")]
    Registry(String),
    /// Strict RFC 8785 canonicalization failed.
    #[error("canonicalization failed: {0}")]
    Canonical(String),
    /// The deterministic semantic oracle could not evaluate a trace.
    #[error("oracle evaluation failed: {0}")]
    Oracle(String),
}

/// Exact operation/version pair carried by actor contexts, decisions, and
/// consequences (contract §"Human and control operation registry").
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteOperationV1 {
    /// Stable semantic operation name (for example `release.create`).
    pub name: String,
    /// Exact operation-version identifier (for example
    /// `proof.dev/operation/release.create/v2`).
    pub version: String,
}

/// Exact authority head `{record_digest, sequence}` referenced by every causal
/// remote payload (contract §"Remote identity vocabulary").
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHeadV1 {
    /// The causal sequence of the head record.
    pub sequence: u64,
    /// Domain-separated digest of the exact head record.
    #[serde(with = "crate::serde_support::display_string")]
    pub record_digest: ContentDigest,
}

/// Computes a BLAKE3-256 digest with an explicit domain-separated derive-key
/// context over already-canonical RFC 8785 bytes.
///
/// This is the shared primitive behind every remote digest context; it mirrors
/// [`proof_canonical::digest`] but admits the remote profile's closed context
/// strings that are not part of the historical [`proof_domain::ArtifactKind`]
/// enumeration.
#[must_use]
pub fn derive_key_digest(context: &str, canonical_bytes: &[u8]) -> ContentDigest {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(canonical_bytes);
    ContentDigest::blake3(*hasher.finalize().as_bytes())
}

pub use authority::{
    ActiveAuthorityKeyResolver, MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES,
    MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES, ParsedRemoteAuthorityRecordEnvelope,
    REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT, REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT,
    REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE, REMOTE_AUTHORITY_SIGNATURE_COUNT,
    RemoteAuthorityRecordEnvelopeV1, RemoteAuthorityRecordV1, RemotePrincipalStatusV2,
    RemotePrincipalType, SignedRemoteAuthorityRecordEnvelope, VerifiedRemoteAuthorityRecord,
    VerifiedRemoteAuthorityRecordEnvelope, WorkspaceRole, WorkspaceRoleAssignmentV1,
    WorkspaceRoleRevocationV1, parse_remote_authority_record_envelope, remote_authority_pae,
    sign_remote_authority_record, validate_chain, verify_remote_authority_record_envelope,
};
pub use bundle::{
    AUTHORITY_CHECKPOINT_DIGEST_CONTEXT, AcceptedArtifactAvailabilityV1,
    AcceptedArtifactDescriptorV1, AcceptedArtifactRefV1, AcceptedArtifactRoleBindingV1,
    AcceptedPolicyBundleV1, AcceptedReleasePolicyProfileV1, AuthorityCheckpointApiVersion,
    AuthorityCheckpointV1, AuthorityTrustV2, BUNDLE_DESCRIPTOR_PATH, BundleValidationError,
    CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS, CheckpointRequirement, ConformanceScenario,
    DisclosurePolicyV2, ENVIRONMENT_RELEASE_CHECKPOINT_DIGEST_CONTEXT,
    EVIDENCE_EXPORT_CAPTURE_API_VERSION, EVIDENCE_EXPORT_CAPTURE_DIGEST_CONTEXT,
    EVIDENCE_EXPORT_RESULT_API_VERSION, EVIDENCE_EXPORT_STATUS_API_VERSION,
    EnvironmentReleaseCheckpointApiVersion, EnvironmentReleaseCheckpointV2,
    EvidenceExportCaptureApiVersion, EvidenceExportCaptureType, EvidenceExportCaptureV2,
    EvidenceExportResultApiVersion, EvidenceExportResultV2, EvidenceExportStatusApiVersion,
    EvidenceExportStatusKind, EvidenceExportStatusV1, EvidenceHeadsV1, ExternalArtifactV2,
    MANIFEST_MEMBER_PATH, MAX_ARTIFACT_BYTES, MAX_AUTHORITY_RECORDS, MAX_BUNDLE_DESCRIPTOR_BYTES,
    MAX_EXPORT_ARTIFACT_BODIES, MAX_MANIFEST_BYTES, MAX_NESTED_ARTIFACT_BODIES, MAX_TOTAL_BYTES,
    MAX_VERIFIER_INPUT_BYTES, REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
    REMOTE_EVIDENCE_BUNDLE_API_VERSION, REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
    REMOTE_EVIDENCE_MANIFEST_API_VERSION, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, REMOTE_VERIFICATION_REPORT_API_VERSION,
    REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT, RegistryResolutionFailure, RegistryResolutionV1,
    ReleaseTrustV2, RemoteAttemptCompanionsV1, RemoteAuthorityRecordSetApiVersion,
    RemoteAuthorityRecordSetV1, RemoteEvidenceArtifactClosureBindingV1,
    RemoteEvidenceAttemptCompanionsBindingV1, RemoteEvidenceAuthorityBindingV1,
    RemoteEvidenceBundleApiVersion, RemoteEvidenceBundleType, RemoteEvidenceBundleV2,
    RemoteEvidenceCanonicalization, RemoteEvidenceClosureBindingsApiVersion,
    RemoteEvidenceClosureBindingsV1, RemoteEvidenceComponentBindingV1, RemoteEvidenceCrossLinksV1,
    RemoteEvidenceDelivery, RemoteEvidenceDisclosureKind, RemoteEvidenceDisclosureProfile,
    RemoteEvidenceDisclosureRequirementV1, RemoteEvidenceManifestApiVersion,
    RemoteEvidenceManifestType, RemoteEvidenceManifestV2, RemoteEvidenceMemberMap,
    RemoteEvidenceMemberV1, RemoteEvidencePortablePayloadContractV1, RemoteEvidenceRootKind,
    RemoteIdentityTrustV2, RemoteReleaseArtifactClosureApiVersion,
    RemoteReleaseArtifactClosureEntrypointsV1, RemoteReleaseArtifactClosureV1,
    RemoteVerificationConformanceReportV2, RemoteVerificationReportApiVersion,
    RemoteVerificationReportType, RemoteVerificationReportV2, RemoteVerifierInputApiVersion,
    RemoteVerifierInputType, RemoteVerifierInputV2, RequestingSubjectOpeningPolicy, TrustedKeyV2,
    UntrustedHintsV1, VERIFICATION_TRUST_POLICY_API_VERSION,
    VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, VerificationComponentResult,
    VerificationComponentResultsV2, VerificationLimitsV2, VerificationReasonCode,
    VerificationScenario, VerificationStatus, VerificationTrustPolicyApiVersion,
    VerificationTrustPolicyV2, normalize_member_path, validate_bundle_members,
};
pub use governance::{
    ApprovalDecision, ApprovalPolicyV1, ChangeSetApprovalV1, DeliveryConfigurationV1,
    DeliveryManagementAction, DeliveryManagementFactApiVersion, DeliveryManagementFactV1,
    ENVIRONMENT_CONFIG_DIGEST_CONTEXT, EnvironmentConfigActivationV1, EnvironmentConfigProposalV1,
    EnvironmentConfigV2, EnvironmentCreationV1, NormalizedEnvironmentConfigurationV1,
    validate_environment_config_v2,
};
pub use identity::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AgentSubjectV1,
    AuthenticatedActorContextEvidenceV2, AuthenticatedActorContextV2, AuthenticationProfile,
    OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT, OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT,
    OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT, OidcAuthenticatedSubjectV1, OidcIssuerConfigurationV1,
    OidcPrincipalBindingPrivateV1, OidcPrincipalBindingRevocationV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputV1, OidcSubjectCommitmentOpeningV1, OperatingBindingReferenceV1,
    PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT, REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
    REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT, RemoteAuthenticationEventV1, decode_blind,
    encode_blind, generate_subject_commitment_blind, normalized_operation_input_digest,
    oidc_discovery_metadata_digest, public_operation_input_projection_digest,
    subject_commitment_digest,
};
pub use oracle::{
    IdentityFixtureV1, OidcEnrollmentChallengeV1, OracleConsequence, OracleOutcome, OracleTraceV1,
    RemoteSemanticOracle, SqliteReferenceBackend, StableProblem, StorageBackend,
};
pub use registry::{
    AGENT_AUTHORITY_REGISTRY_SHA256, AUTHORIZATION_RESOURCE_BINDING_DIGEST_CONTEXT,
    AgentAuthorizationV1, AgentOperationProjectionV1, ApplicationConsequenceOutcome,
    ApplicationKeyKind, AuthorizationDecisionKind, COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
    DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT, DelegationEvaluationV1, EffectDigestRule,
    EffectTimestampField, EffectiveConstraintsV1, HttpRouteV1, HumanOperationRegistryV1,
    OPERATION_EFFECT_DIGEST_CONTEXT, OperatingBindingEvaluationV1, PrincipalStateV1,
    REMOTE_AUTHORIZATION_POLICY_SELECTION_DIGEST_CONTEXT, REMOTE_AUTHORIZATION_PROJECTION_SHA256,
    REQUESTED_AUTHORIZATION_RESOURCES_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthorizationDecisionV1, RequestedResourcesV1, application_problem_digest_preimage,
    authorization_resource_binding_digest, canonical_sha256_hex, classify_consequence_outcome,
    cross_check_route_operation, effect_timestamp_field, operation_effect_digest, operation_major,
    recompute_agent_authority_registry_sha256, recompute_complete_http_operation_registry_sha256,
    recompute_remote_authorization_projection_sha256, remote_authorization_policy_selection_digest,
    requested_authorization_resources_digest,
};
