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
//! under `conformance/v1/collaboration-server/`.
//!
//! The bodies of the construction, canonicalization, signing, verification, and
//! validation functions are intentionally stubbed with `todo!()`: this crate is
//! the interface contract for the follow-up implementation swarm, so the type
//! surface is complete and precise while the logic is added later.
//!
//! [single-Workspace collaboration-server contract]: https://proof.dev/docs/architecture/collaboration-server
//! [ADR-0013]: https://proof.dev/docs/decisions/0013-single-workspace-collaboration-server

pub mod authority;
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
    ActiveAuthorityKeyResolver, ParsedRemoteAuthorityRecordEnvelope,
    REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT, REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
    RemoteAuthorityRecordEnvelopeV1, RemoteAuthorityRecordV1, RemotePrincipalStatusV2,
    RemotePrincipalType, SignedRemoteAuthorityRecordEnvelope, VerifiedRemoteAuthorityRecord,
    VerifiedRemoteAuthorityRecordEnvelope, WorkspaceRole, WorkspaceRoleAssignmentV1,
    WorkspaceRoleRevocationV1, parse_remote_authority_record_envelope,
    sign_remote_authority_record, validate_chain, verify_remote_authority_record_envelope,
};
pub use governance::{
    ApprovalPolicyV1, ChangeSetApprovalV1, DeliveryConfigurationV1, EnvironmentConfigActivationV1,
    EnvironmentConfigProposalV1, EnvironmentConfigV2, EnvironmentCreationV1,
    NormalizedEnvironmentConfigurationV1, validate_environment_config_v2,
};
pub use identity::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AgentSubjectV1,
    AuthenticatedActorContextEvidenceV2, AuthenticatedActorContextV2, AuthenticationProfile,
    OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT, OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT,
    OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT, OidcAuthenticatedSubjectV1, OidcIssuerConfigurationV1,
    OidcPrincipalBindingPrivateV1, OidcPrincipalBindingRevocationV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputV1, OidcSubjectCommitmentOpeningV1, OperatingBindingReferenceV1,
    PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT, REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
    REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT, RemoteAuthenticationEventV1,
};
pub use oracle::{
    IdentityFixtureV1, OracleConsequence, OracleOutcome, OracleTraceV1, RemoteSemanticOracle,
    StableProblem,
};
pub use registry::{
    AGENT_AUTHORITY_REGISTRY_SHA256, AgentAuthorizationV1, AgentOperationProjectionV1,
    ApplicationConsequenceOutcome, ApplicationKeyKind, AuthorizationDecisionKind,
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, DelegationEvaluationV1, EffectDigestRule,
    EffectTimestampField, EffectiveConstraintsV1, HttpRouteV1, HumanOperationRegistryV1,
    OperatingBindingEvaluationV1, PrincipalStateV1, REMOTE_AUTHORIZATION_PROJECTION_SHA256,
    RemoteApplicationConsequenceV1, RemoteAuthorizationDecisionV1, RequestedResourcesV1,
    application_problem_digest_preimage, authorization_resource_binding_digest,
    operation_effect_digest, remote_authorization_policy_selection_digest,
    requested_authorization_resources_digest,
};
