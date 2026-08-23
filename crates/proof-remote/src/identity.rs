//! OIDC subject-commitment machinery and versioned remote actor contexts.
//!
//! This module implements the complete type surface for the OIDC issuer
//! configuration, subject commitment/opening/binding, remote authentication
//! event, and the protected [`AuthenticatedActorContextV2`] with its public
//! commitment-only [`AuthenticatedActorContextEvidenceV2`] redaction
//! (contract §"OIDC binding and session boundary",
//! §"Remote identity vocabulary").

use proof_domain::{ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{AuthorityHeadV1, RemoteOperationV1};

/// BLAKE3-256 derive-key context for the OIDC subject commitment.
pub const OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT: &str =
    "proof:oidc-authenticated-subject-commitment:v1";
/// BLAKE3-256 derive-key context for the OIDC issuer configuration.
pub const OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT: &str = "proof:oidc-issuer-configuration:v1";
/// BLAKE3-256 derive-key context for accepted OIDC discovery metadata.
pub const OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT: &str = "proof:oidc-discovery-metadata:v1";
/// BLAKE3-256 derive-key context for the remote authentication event.
pub const REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT: &str = "proof:remote-authentication-event:v1";
/// BLAKE3-256 derive-key context for the protected exact normalized-input
/// digest.
pub const REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT: &str =
    "proof:remote-normalized-operation-input:v1";
/// BLAKE3-256 derive-key context for the public operation-input projection.
pub const PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT: &str =
    "proof:public-operation-input-projection:v1";
/// BLAKE3-256 derive-key context for public actor-context evidence.
pub const AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT: &str =
    "proof:authenticated-actor-context-evidence:v2";

macro_rules! api_version {
    ($name:ident, $wire:literal) => {
        #[doc = concat!("Exact `", $wire, "` schema tag.")]
        #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
        pub enum $name {
            /// The sole supported schema version.
            #[default]
            #[serde(rename = $wire)]
            V1,
        }
    };
}

api_version!(
    OidcAuthenticatedSubjectApiVersion,
    "proof.dev/oidc-authenticated-subject/v1"
);
api_version!(
    OidcSubjectCommitmentInputApiVersion,
    "proof.dev/oidc-subject-commitment-input/v1"
);
api_version!(
    OidcSubjectCommitmentOpeningApiVersion,
    "proof.dev/oidc-subject-commitment-opening/v1"
);
api_version!(
    OidcIssuerConfigurationApiVersion,
    "proof.dev/oidc-issuer-configuration/v1"
);
api_version!(
    OidcPrincipalBindingApiVersion,
    "proof.dev/oidc-principal-binding/v1"
);
api_version!(
    OidcPrincipalBindingPrivateApiVersion,
    "proof.dev/oidc-principal-binding-private/v1"
);
api_version!(
    OidcPrincipalBindingRevocationApiVersion,
    "proof.dev/oidc-principal-binding-revocation/v1"
);
api_version!(
    RemoteAuthenticationEventApiVersion,
    "proof.dev/remote-authentication-event/v1"
);
api_version!(
    AuthenticatedActorContextApiVersion,
    "proof.dev/authenticated-actor-context/v2"
);
api_version!(
    AuthenticatedActorContextEvidenceApiVersion,
    "proof.dev/authenticated-actor-context-evidence/v2"
);
api_version!(AgentSubjectApiVersion, "proof.dev/authenticated-subject/v1");

/// Exact, case-sensitive configured OIDC `{issuer, subject}` tuple
/// (schema `oidcAuthenticatedSubjectV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcAuthenticatedSubjectV1 {
    pub api_version: OidcAuthenticatedSubjectApiVersion,
    /// Exact HTTPS issuer.
    pub issuer: String,
    /// Exact provider label; always `proof/oidc`.
    pub provider: String,
    /// Exact, non-control, case-sensitive subject.
    pub subject: String,
}

/// Private commitment preimage `{api_version, blind, subject, workspace_id}`
/// (schema `oidcSubjectCommitmentInputV1`).
///
/// `blind` is base64url without padding for exactly 32 uniformly random bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSubjectCommitmentInputV1 {
    pub api_version: OidcSubjectCommitmentInputApiVersion,
    /// Base64url-no-pad encoding of exactly 32 random bytes.
    pub blind: String,
    /// The committed OIDC subject.
    pub subject: OidcAuthenticatedSubjectV1,
    /// Owning Workspace identity (UUIDv7).
    pub workspace_id: String,
}

/// Protected audit disclosure carrying the exact commitment preimage and
/// claimed digest (schema `oidcSubjectCommitmentOpeningV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSubjectCommitmentOpeningV1 {
    pub api_version: OidcSubjectCommitmentOpeningApiVersion,
    #[serde(with = "crate::serde_support::display_string")]
    pub commitment: ContentDigest,
    pub input: OidcSubjectCommitmentInputV1,
}

/// Public, secret-free OIDC issuer configuration
/// (schema `oidcIssuerConfigurationV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcIssuerConfigurationV1 {
    pub api_version: OidcIssuerConfigurationApiVersion,
    /// Configuration identity (UUIDv7).
    pub configuration_id: String,
    pub configuration_source: String,
    pub issuer: String,
    pub discovery_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub redirect_uri: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub discovery_metadata_digest: ContentDigest,
    pub endpoint_egress_policy: String,
    pub accepted_id_token_algorithms: Vec<String>,
    pub authorization_code_flow: bool,
    pub pkce_method: String,
    pub response_issuer_parameter_required: bool,
    pub token_endpoint_auth_method: String,
    pub client_credential_reference: String,
    pub tokens_retained: bool,
    pub clock_skew_seconds: u32,
    pub session_cookie_name: String,
    pub session_idle_seconds: u32,
    pub session_absolute_seconds: u32,
}

/// Public commitment-only OIDC Principal binding authority payload
/// (schema `oidcPrincipalBindingV1`).
///
/// Raw issuer/subject and the commitment blind never appear on this public
/// type; they exist only in [`OidcPrincipalBindingPrivateV1`] and the opening.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPrincipalBindingV1 {
    pub api_version: OidcPrincipalBindingApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Binding identity (UUIDv7).
    pub binding_id: String,
    /// Bound Human Principal identity (UUIDv7).
    pub principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub subject_commitment: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    /// Issuing `identity.admin` Principal identity (UUIDv7).
    pub issued_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub issued_at: Timestamp,
    /// Superseded binding identity (UUIDv7) or `null`.
    pub supersedes_binding_id: Option<String>,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Protected adapter lookup carrying the exact issuer/subject and commitment
/// opening (schema `oidcPrincipalBindingPrivateV1`).
///
/// This type is excluded from ordinary logs, Problems, `ContextPack`s, exports,
/// and public evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPrincipalBindingPrivateV1 {
    pub api_version: OidcPrincipalBindingPrivateApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Binding identity (UUIDv7).
    pub binding_id: String,
    /// Bound Human Principal identity (UUIDv7).
    pub principal_id: String,
    pub subject: OidcAuthenticatedSubjectV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub subject_commitment: ContentDigest,
    pub opening: OidcSubjectCommitmentOpeningV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub binding_record_digest: ContentDigest,
}

/// Causal OIDC Principal binding revocation
/// (schema `oidcPrincipalBindingRevocationV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPrincipalBindingRevocationV1 {
    pub api_version: OidcPrincipalBindingRevocationApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Revocation identity (UUIDv7).
    pub revocation_id: String,
    /// Revoked binding identity (UUIDv7).
    pub binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub binding_record_digest: ContentDigest,
    /// Affected Human Principal identity (UUIDv7).
    pub principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub subject_commitment: ContentDigest,
    /// Revoking `identity.admin` Principal identity (UUIDv7).
    pub revoked_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub revoked_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub revoked_at: Timestamp,
    pub reason: String,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Secret-free server authentication event (schema `remoteAuthenticationEventV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAuthenticationEventV1 {
    pub api_version: RemoteAuthenticationEventApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Event identity (UUIDv7).
    pub authentication_event_id: String,
    pub authentication_method: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_at: Timestamp,
    #[serde(with = "crate::serde_support::display_string")]
    pub expires_at: Timestamp,
}

/// The two closed actor-context authentication profiles (contract §"Remote
/// identity vocabulary").
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AuthenticationProfile {
    /// Direct Human OIDC session.
    #[serde(rename = "proof.server/authentication/oidc-human/v1")]
    OidcHuman,
    /// Human OIDC session plus a single-use Agent command presentation.
    #[serde(rename = "proof.server/authentication/oidc-human-agent/v1")]
    OidcHumanAgent,
}

/// Per-struct constant profile tag for the Human context.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum OidcHumanAuthenticationProfile {
    #[default]
    #[serde(rename = "proof.server/authentication/oidc-human/v1")]
    V1,
}

/// Per-struct constant profile tag for the Human-plus-Agent context.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum OidcHumanAgentAuthenticationProfile {
    #[default]
    #[serde(rename = "proof.server/authentication/oidc-human-agent/v1")]
    V1,
}

/// Local Ed25519 operating Agent subject (schema `agentSubject`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSubjectV1 {
    pub api_version: AgentSubjectApiVersion,
    /// Always `proof/local-ed25519`.
    pub provider: String,
    /// Exact `ed25519:<lowercase-hex>` subject.
    pub subject: String,
}

/// Exact historical Agent `PrincipalBindingV1` record reference
/// (schema `operating_binding` within the actor contexts).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingBindingReferenceV1 {
    pub authority_sequence: u64,
    /// Binding identity (UUIDv7).
    pub binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub record_digest: ContentDigest,
}

/// Protected Human actor context (schema `humanContext`).
///
/// This protected type retains the raw requesting subject and the exact
/// normalized-input digest; neither appears on public evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextHumanV2 {
    pub api_version: AuthenticatedActorContextApiVersion,
    /// Exact `proof://workspace/<uuid>` audience.
    pub audience: String,
    pub authentication_profile: OidcHumanAuthenticationProfile,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    pub requesting_subject: OidcAuthenticatedSubjectV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authentication_event_digest: ContentDigest,
    pub operation: RemoteOperationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
}

/// Protected Human-plus-Agent actor context (schema `humanAgentContext`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextHumanAgentV2 {
    pub api_version: AuthenticatedActorContextApiVersion,
    /// Exact `proof://workspace/<uuid>` audience.
    pub audience: String,
    pub authentication_profile: OidcHumanAgentAuthenticationProfile,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    pub requesting_subject: OidcAuthenticatedSubjectV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authentication_event_digest: ContentDigest,
    pub operating_subject: AgentSubjectV1,
    pub operating_binding: OperatingBindingReferenceV1,
    /// Operating Agent Principal identity (UUIDv7).
    pub operating_principal_id: String,
    /// Direct Delegation identity (UUIDv7).
    pub delegation_id: String,
    pub operation: RemoteOperationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub command_envelope_digest: ContentDigest,
    /// Single-use presentation identity (UUIDv7).
    pub presentation_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
}

/// Closed protected actor-context union (schema `authenticatedActorContextV2`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "the human-agent profile legitimately carries more fields than the human profile"
)]
pub enum AuthenticatedActorContextV2 {
    /// Direct Human OIDC context.
    Human(AuthenticatedActorContextHumanV2),
    /// Human-plus-Agent context.
    HumanAgent(AuthenticatedActorContextHumanAgentV2),
}

/// Public commitment-only Human actor-context redaction
/// (schema `humanContextEvidence`).
///
/// This public type never carries a raw issuer/subject, token, opening, or the
/// protected normalized-input digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextHumanEvidenceV2 {
    pub api_version: AuthenticatedActorContextEvidenceApiVersion,
    /// Exact `proof://workspace/<uuid>` audience.
    pub audience: String,
    pub authentication_profile: OidcHumanAuthenticationProfile,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub public_input_projection_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authentication_event_digest: ContentDigest,
    pub operation: RemoteOperationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
}

/// Public commitment-only Human-plus-Agent actor-context redaction
/// (schema `humanAgentContextEvidence`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextHumanAgentEvidenceV2 {
    pub api_version: AuthenticatedActorContextEvidenceApiVersion,
    /// Exact `proof://workspace/<uuid>` audience.
    pub audience: String,
    pub authentication_profile: OidcHumanAgentAuthenticationProfile,
    #[serde(with = "crate::serde_support::display_string")]
    pub oidc_issuer_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub public_input_projection_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authentication_event_digest: ContentDigest,
    pub operating_subject: AgentSubjectV1,
    pub operating_binding: OperatingBindingReferenceV1,
    /// Operating Agent Principal identity (UUIDv7).
    pub operating_principal_id: String,
    /// Direct Delegation identity (UUIDv7).
    pub delegation_id: String,
    pub operation: RemoteOperationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub command_envelope_digest: ContentDigest,
    /// Single-use presentation identity (UUIDv7).
    pub presentation_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
}

/// Closed public actor-context-evidence union
/// (schema `authenticatedActorContextEvidenceV2`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "the human-agent profile legitimately carries more fields than the human profile"
)]
pub enum AuthenticatedActorContextEvidenceV2 {
    /// Direct Human OIDC evidence.
    Human(AuthenticatedActorContextHumanEvidenceV2),
    /// Human-plus-Agent evidence.
    HumanAgent(AuthenticatedActorContextHumanAgentEvidenceV2),
}
