//! OIDC subject-commitment machinery and versioned remote actor contexts.
//!
//! This module implements the complete type surface for the OIDC issuer
//! configuration, subject commitment/opening/binding, remote authentication
//! event, and the protected [`AuthenticatedActorContextV2`] with its public
//! commitment-only [`AuthenticatedActorContextEvidenceV2`] redaction
//! (contract §"OIDC binding and session boundary",
//! §"Remote identity vocabulary").

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use proof_domain::{ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AuthorityHeadV1, RemoteError, RemoteOperationV1};

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

// ---------------------------------------------------------------------------
// Subject-commitment blind and base64url-without-padding encoding.
// ---------------------------------------------------------------------------

/// Canonical base64url-no-pad length for exactly 32 blind bytes.
const BLIND_BASE64URL_LENGTH: usize = 43;

/// Exact BLAKE3 derive-key context for a public `OidcPrincipalBindingV1`
/// persisted as a decoded `RemoteAuthorityRecordV1` payload. This mirrors
/// `crate::authority::REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT`; the public
/// binding itself has no private lookup-specific digest context.
const OIDC_BINDING_RECORD_DIGEST_CONTEXT: &str = "proof:remote-authority-record:v1";

/// Generates a uniformly random 32-byte subject-commitment blind from the
/// operating-system random source.
///
/// # Errors
///
/// Returns [`RemoteError::Identity`] when the OS random source cannot fill a
/// complete blind.
pub fn generate_subject_commitment_blind() -> Result<[u8; 32], RemoteError> {
    proof_attestation::Ed25519SigningProvider::generate()
        .map(|provider| provider.secret_bytes())
        .map_err(|error| {
            RemoteError::Identity(format!(
                "subject-commitment blind randomness is unavailable: {error}"
            ))
        })
}

/// Encodes an exact 32-byte blind as base64url without padding.
#[must_use]
pub fn encode_blind(blind: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(blind)
}

/// Decodes an exact canonical base64url-no-pad 32-byte blind.
///
/// # Errors
///
/// Returns [`RemoteError::Identity`] unless `encoded` is exactly
/// [`BLIND_BASE64URL_LENGTH`] base64url characters, carries only the four
/// trailing data bits, and re-encodes to the identical string.
pub fn decode_blind(encoded: &str) -> Result<[u8; 32], RemoteError> {
    if encoded.len() != BLIND_BASE64URL_LENGTH {
        return Err(RemoteError::Identity(format!(
            "subject-commitment blind must be {BLIND_BASE64URL_LENGTH} base64url-no-pad \
             characters, got {}",
            encoded.len()
        )));
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        RemoteError::Identity(format!(
            "subject-commitment blind is not valid base64url: {error}"
        ))
    })?;
    let blind: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        RemoteError::Identity("subject-commitment blind must decode to exactly 32 bytes".to_owned())
    })?;
    // The final character encodes only four data bits; enforce its canonical
    // form by requiring the exact round-trip.
    if URL_SAFE_NO_PAD.encode(blind) != encoded {
        return Err(RemoteError::Identity(
            "subject-commitment blind is not the canonical base64url-no-pad encoding".to_owned(),
        ));
    }
    Ok(blind)
}

// ---------------------------------------------------------------------------
// Shared canonicalization and digest helpers.
// ---------------------------------------------------------------------------

fn value_digest(context: &str, value: &Value) -> Result<ContentDigest, RemoteError> {
    let canonical = proof_canonical::canonicalize(value)
        .map_err(|error| RemoteError::Canonical(error.to_string()))?;
    Ok(crate::derive_key_digest(context, canonical.as_bytes()))
}

fn typed_digest<T: Serialize>(context: &str, value: &T) -> Result<ContentDigest, RemoteError> {
    let json =
        serde_json::to_value(value).map_err(|error| RemoteError::Canonical(error.to_string()))?;
    value_digest(context, &json)
}

fn validate_audience(audience: &str, workspace_id: &str) -> Result<(), RemoteError> {
    if audience != format!("proof://workspace/{workspace_id}") {
        return Err(RemoteError::Identity(format!(
            "audience must be the exact `proof://workspace/{workspace_id}` URI"
        )));
    }
    Ok(())
}

fn validate_agent_subject(subject: &AgentSubjectV1) -> Result<(), RemoteError> {
    if subject.provider != "proof/local-ed25519" {
        return Err(RemoteError::Identity(
            "operating_subject.provider must be `proof/local-ed25519`".to_owned(),
        ));
    }
    let Some(hex) = subject.subject.strip_prefix("ed25519:") else {
        return Err(RemoteError::Identity(
            "operating_subject.subject must be `ed25519:<lowercase-hex>`".to_owned(),
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RemoteError::Identity(
            "operating_subject.subject must be `ed25519:` followed by 64 lowercase hex digits"
                .to_owned(),
        ));
    }
    Ok(())
}

fn is_https_no_query_or_fragment(value: &str) -> bool {
    (9..=2048).contains(&value.len())
        && value.starts_with("https://")
        && !value.contains(['?', '#'])
}

fn valid_client_credential_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("deployment-secret:") else {
        return false;
    };
    let bytes = rest.as_bytes();
    if !(3..=128).contains(&bytes.len()) || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..].iter().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
    })
}

// ---------------------------------------------------------------------------
// OIDC subject commitment, opening, and authenticated subject.
// ---------------------------------------------------------------------------

impl OidcAuthenticatedSubjectV1 {
    /// Validates the exact pinned OIDC subject profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] for a non-HTTPS issuer, a provider
    /// other than `proof/oidc`, or a non-control-subject violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.provider != "proof/oidc" {
            return Err(RemoteError::Identity(
                "OIDC authenticated subject provider must be `proof/oidc`".to_owned(),
            ));
        }
        if !is_https_no_query_or_fragment(&self.issuer) {
            return Err(RemoteError::Identity(
                "OIDC authenticated subject issuer must be an exact HTTPS URI".to_owned(),
            ));
        }
        if self.subject.is_empty()
            || self.subject.len() > 255
            || self
                .subject
                .chars()
                .any(|character| character == '\u{7f}' || character <= '\u{1f}')
        {
            return Err(RemoteError::Identity(
                "OIDC authenticated subject must be 1..=255 non-control characters".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Computes the `proof:oidc-authenticated-subject-commitment:v1` digest of the
/// exact RFC 8785 commitment preimage
/// `{api_version, blind, subject, workspace_id}`.
///
/// # Errors
///
/// Returns [`RemoteError::Canonical`] if the preimage cannot be canonicalized.
pub fn subject_commitment_digest(
    input: &OidcSubjectCommitmentInputV1,
) -> Result<ContentDigest, RemoteError> {
    typed_digest(OIDC_SUBJECT_COMMITMENT_DIGEST_CONTEXT, input)
}

impl OidcSubjectCommitmentOpeningV1 {
    /// Validates that the carried preimage recomputes to the claimed commitment
    /// and that the blind is a canonical base64url-no-pad 32-byte value.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] for a non-canonical blind or a
    /// commitment/preimage mismatch.
    pub fn validate(&self) -> Result<(), RemoteError> {
        decode_blind(&self.input.blind)?;
        self.input.subject.validate()?;
        let recomputed = subject_commitment_digest(&self.input)?;
        if recomputed != self.commitment {
            return Err(RemoteError::Identity(
                "opening commitment does not match its exact commitment preimage".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OIDC issuer configuration.
// ---------------------------------------------------------------------------

/// Computes the `proof:oidc-discovery-metadata:v1` digest of the exact accepted
/// RFC 8785 discovery document.
///
/// # Errors
///
/// Returns [`RemoteError::Canonical`] if the metadata cannot be canonicalized.
pub fn oidc_discovery_metadata_digest(metadata: &Value) -> Result<ContentDigest, RemoteError> {
    value_digest(OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT, metadata)
}

impl OidcIssuerConfigurationV1 {
    /// Computes the `proof:oidc-issuer-configuration:v1` digest of this exact
    /// RFC 8785 configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the configuration cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<ContentDigest, RemoteError> {
        typed_digest(OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT, self)
    }

    /// Validates the pinned deployment-configuration rules.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on any issuer, endpoint, client-id,
    /// redirect-URI, algorithm-allowlist, or pinned-constant violation.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed Schema pins many exact deployment constants that must each be checked"
    )]
    pub fn validate(&self) -> Result<(), RemoteError> {
        if !is_https_no_query_or_fragment(&self.issuer) {
            return Err(RemoteError::Identity(
                "issuer must be an exact HTTPS URI without query or fragment".to_owned(),
            ));
        }
        if self.client_id.is_empty() || self.client_id.len() > 256 {
            return Err(RemoteError::Identity(
                "client_id must be 1..=256 characters".to_owned(),
            ));
        }
        for (name, endpoint) in [
            ("discovery_uri", self.discovery_uri.as_str()),
            (
                "authorization_endpoint",
                self.authorization_endpoint.as_str(),
            ),
            ("token_endpoint", self.token_endpoint.as_str()),
            ("jwks_uri", self.jwks_uri.as_str()),
        ] {
            if !is_https_no_query_or_fragment(endpoint) {
                return Err(RemoteError::Identity(format!(
                    "{name} must be an exact HTTPS URI without query or fragment"
                )));
            }
        }
        if !self.redirect_uri.starts_with("https://")
            || self.redirect_uri.contains(['?', '#'])
            || !self.redirect_uri.ends_with("/auth/oidc/callback")
        {
            return Err(RemoteError::Identity(
                "redirect_uri must be the exact preregistered `https://<host>/auth/oidc/callback`"
                    .to_owned(),
            ));
        }
        let algorithms = &self.accepted_id_token_algorithms;
        if algorithms.is_empty() || algorithms.len() > 4 {
            return Err(RemoteError::Identity(
                "accepted_id_token_algorithms must contain 1..=4 entries".to_owned(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for algorithm in algorithms {
            if !matches!(algorithm.as_str(), "EdDSA" | "ES256" | "PS256" | "RS256") {
                return Err(RemoteError::Identity(format!(
                    "unsupported ID-token algorithm `{algorithm}`"
                )));
            }
            if !seen.insert(algorithm.as_str()) {
                return Err(RemoteError::Identity(
                    "accepted_id_token_algorithms must not repeat an algorithm".to_owned(),
                ));
            }
        }
        if self.configuration_source != "trusted-deployment-configuration" {
            return Err(RemoteError::Identity(
                "configuration_source must be `trusted-deployment-configuration`".to_owned(),
            ));
        }
        if self.endpoint_egress_policy != "deployment-allowlist-no-redirect" {
            return Err(RemoteError::Identity(
                "endpoint_egress_policy must be `deployment-allowlist-no-redirect`".to_owned(),
            ));
        }
        if !self.authorization_code_flow {
            return Err(RemoteError::Identity(
                "authorization_code_flow must be true".to_owned(),
            ));
        }
        if self.pkce_method != "S256" {
            return Err(RemoteError::Identity(
                "pkce_method must be `S256`".to_owned(),
            ));
        }
        if !self.response_issuer_parameter_required {
            return Err(RemoteError::Identity(
                "response_issuer_parameter_required must be true".to_owned(),
            ));
        }
        if self.token_endpoint_auth_method != "client_secret_basic" {
            return Err(RemoteError::Identity(
                "token_endpoint_auth_method must be `client_secret_basic`".to_owned(),
            ));
        }
        if !valid_client_credential_reference(&self.client_credential_reference) {
            return Err(RemoteError::Identity(
                "client_credential_reference must match `deployment-secret:<name>`".to_owned(),
            ));
        }
        if self.tokens_retained {
            return Err(RemoteError::Identity(
                "tokens_retained must be false".to_owned(),
            ));
        }
        if self.clock_skew_seconds != 30 {
            return Err(RemoteError::Identity(
                "clock_skew_seconds must be exactly 30".to_owned(),
            ));
        }
        if self.session_cookie_name != "__Host-Http-Proof-Session" {
            return Err(RemoteError::Identity(
                "session_cookie_name must be `__Host-Http-Proof-Session`".to_owned(),
            ));
        }
        if self.session_idle_seconds != 900 {
            return Err(RemoteError::Identity(
                "session_idle_seconds must be exactly 900".to_owned(),
            ));
        }
        if self.session_absolute_seconds != 28_800 {
            return Err(RemoteError::Identity(
                "session_absolute_seconds must be exactly 28800".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OIDC principal bindings and revocation.
// ---------------------------------------------------------------------------

impl OidcPrincipalBindingV1 {
    /// Computes the exact `proof:remote-authority-record:v1` digest of this
    /// decoded public binding payload (the private binding's
    /// `binding_record_digest`).
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the payload cannot be canonicalized.
    pub fn binding_record_digest(&self) -> Result<ContentDigest, RemoteError> {
        typed_digest(OIDC_BINDING_RECORD_DIGEST_CONTEXT, self)
    }

    /// Validates the causal authority fields of the public binding payload.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on a sequence/predecessor/identity
    /// violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.authority_sequence < 2 {
            return Err(RemoteError::Identity(
                "authority_sequence must be at least 2".to_owned(),
            ));
        }
        if self.evaluated_authority_head.sequence >= self.authority_sequence {
            return Err(RemoteError::Identity(
                "evaluated_authority_head must precede the binding authority sequence".to_owned(),
            ));
        }
        if self.binding_id == self.principal_id {
            return Err(RemoteError::Identity(
                "a binding cannot bind a Principal to itself".to_owned(),
            ));
        }
        Ok(())
    }
}

impl OidcPrincipalBindingPrivateV1 {
    /// Validates the self-contained protected binding equalities
    /// (`workspace_id`, exact `subject`, `subject_commitment ==
    /// opening.commitment`, and a valid commitment opening).
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on any equality or opening violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.workspace_id != self.opening.input.workspace_id {
            return Err(RemoteError::Identity(
                "private binding workspace_id must equal its opening preimage workspace_id"
                    .to_owned(),
            ));
        }
        if self.subject != self.opening.input.subject {
            return Err(RemoteError::Identity(
                "private binding subject must equal its opening preimage subject".to_owned(),
            ));
        }
        if self.subject_commitment != self.opening.commitment {
            return Err(RemoteError::Identity(
                "private binding subject_commitment must equal its opening commitment".to_owned(),
            ));
        }
        self.opening.validate()
    }

    /// Validates the protected binding against its public commitment-only
    /// record, including the exact public binding-record digest.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on any cross-record or digest mismatch.
    pub fn validate_against(&self, public: &OidcPrincipalBindingV1) -> Result<(), RemoteError> {
        self.validate()?;
        if self.workspace_id != public.workspace_id {
            return Err(RemoteError::Identity(
                "private and public bindings disagree on workspace_id".to_owned(),
            ));
        }
        if self.binding_id != public.binding_id {
            return Err(RemoteError::Identity(
                "private and public bindings disagree on binding_id".to_owned(),
            ));
        }
        if self.principal_id != public.principal_id {
            return Err(RemoteError::Identity(
                "private and public bindings disagree on principal_id".to_owned(),
            ));
        }
        if self.subject_commitment != public.subject_commitment {
            return Err(RemoteError::Identity(
                "private and public bindings disagree on subject_commitment".to_owned(),
            ));
        }
        if self.oidc_issuer_configuration_digest != public.oidc_issuer_configuration_digest {
            return Err(RemoteError::Identity(
                "private and public bindings disagree on the issuer configuration digest"
                    .to_owned(),
            ));
        }
        let record_digest = public.binding_record_digest()?;
        if self.binding_record_digest != record_digest {
            return Err(RemoteError::Identity(
                "private binding_record_digest does not match the public binding payload digest"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

impl OidcPrincipalBindingRevocationV1 {
    /// Validates the causal authority fields and closed reason of the
    /// revocation payload.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on a sequence/reason violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.authority_sequence < 2 {
            return Err(RemoteError::Identity(
                "authority_sequence must be at least 2".to_owned(),
            ));
        }
        if self.evaluated_authority_head.sequence >= self.authority_sequence {
            return Err(RemoteError::Identity(
                "evaluated_authority_head must precede the revocation authority sequence"
                    .to_owned(),
            ));
        }
        if !matches!(
            self.reason.as_str(),
            "administrative" | "compromise" | "disablement" | "recovery"
        ) {
            return Err(RemoteError::Identity(format!(
                "unsupported binding revocation reason `{}`",
                self.reason
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Remote authentication event.
// ---------------------------------------------------------------------------

impl RemoteAuthenticationEventV1 {
    /// Computes the `proof:remote-authentication-event:v1` digest of this exact
    /// RFC 8785 authentication event.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the event cannot be canonicalized.
    pub fn digest(&self) -> Result<ContentDigest, RemoteError> {
        typed_digest(REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT, self)
    }

    /// Validates the authentication method and session-time boundary.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] for an unsupported method or when
    /// `authenticated_at` is not strictly before `expires_at`.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.authentication_method != "oidc-authorization-code-pkce-s256" {
            return Err(RemoteError::Identity(format!(
                "unsupported authentication method `{}`",
                self.authentication_method
            )));
        }
        if self.authenticated_at >= self.expires_at {
            return Err(RemoteError::Identity(
                "authenticated_at must be strictly before expires_at".to_owned(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Actor-context input digests, redaction, and validation.
// ---------------------------------------------------------------------------

fn normalized_input_preimage(input: &Value, operation: &RemoteOperationV1) -> Value {
    serde_json::json!({
        "api_version": "proof.dev/remote-normalized-operation-input/v1",
        "input": input,
        "operation": operation,
    })
}

fn public_input_projection_preimage(input: &Value, operation: &RemoteOperationV1) -> Value {
    serde_json::json!({
        "api_version": "proof.dev/public-operation-input-projection/v1",
        "input": input,
        "operation": operation,
    })
}

/// Computes the protected `proof:remote-normalized-operation-input:v1` digest
/// over `{api_version, input, operation}`.
///
/// # Errors
///
/// Returns [`RemoteError::Canonical`] if the preimage cannot be canonicalized.
pub fn normalized_operation_input_digest(
    input: &Value,
    operation: &RemoteOperationV1,
) -> Result<ContentDigest, RemoteError> {
    value_digest(
        REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT,
        &normalized_input_preimage(input, operation),
    )
}

/// Computes the public `proof:public-operation-input-projection:v1` digest over
/// `{api_version, input, operation}`.
///
/// # Errors
///
/// Returns [`RemoteError::Canonical`] if the preimage cannot be canonicalized.
pub fn public_operation_input_projection_digest(
    input: &Value,
    operation: &RemoteOperationV1,
) -> Result<ContentDigest, RemoteError> {
    value_digest(
        PUBLIC_OPERATION_INPUT_PROJECTION_DIGEST_CONTEXT,
        &public_input_projection_preimage(input, operation),
    )
}

impl AuthenticatedActorContextHumanV2 {
    /// Redacts the protected Human context to its public commitment-only
    /// evidence, dropping the raw requesting subject and the protected
    /// normalized-input digest in favor of the supplied public input-projection
    /// digest.
    #[must_use]
    pub fn redact(
        &self,
        public_input_projection_digest: ContentDigest,
    ) -> AuthenticatedActorContextHumanEvidenceV2 {
        AuthenticatedActorContextHumanEvidenceV2 {
            api_version: AuthenticatedActorContextEvidenceApiVersion::V1,
            audience: self.audience.clone(),
            authentication_profile: self.authentication_profile,
            oidc_issuer_configuration_digest: self.oidc_issuer_configuration_digest,
            public_input_projection_digest,
            requesting_subject_commitment: self.requesting_subject_commitment,
            requesting_binding_id: self.requesting_binding_id.clone(),
            requesting_binding_record_digest: self.requesting_binding_record_digest,
            requesting_principal_id: self.requesting_principal_id.clone(),
            authentication_event_id: self.authentication_event_id.clone(),
            authentication_event_digest: self.authentication_event_digest,
            operation: self.operation.clone(),
            authenticated_at: self.authenticated_at,
            evaluated_authority_head: self.evaluated_authority_head,
            workspace_id: self.workspace_id.clone(),
        }
    }

    /// Validates the Human context audience/Workspace coherence.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience/Workspace mismatch.
    pub fn validate(&self) -> Result<(), RemoteError> {
        validate_audience(&self.audience, &self.workspace_id)
    }
}

impl AuthenticatedActorContextHumanAgentV2 {
    /// Redacts the protected Human-plus-Agent context to its public
    /// commitment-only evidence.
    #[must_use]
    pub fn redact(
        &self,
        public_input_projection_digest: ContentDigest,
    ) -> AuthenticatedActorContextHumanAgentEvidenceV2 {
        AuthenticatedActorContextHumanAgentEvidenceV2 {
            api_version: AuthenticatedActorContextEvidenceApiVersion::V1,
            audience: self.audience.clone(),
            authentication_profile: self.authentication_profile,
            oidc_issuer_configuration_digest: self.oidc_issuer_configuration_digest,
            public_input_projection_digest,
            requesting_subject_commitment: self.requesting_subject_commitment,
            requesting_binding_id: self.requesting_binding_id.clone(),
            requesting_binding_record_digest: self.requesting_binding_record_digest,
            requesting_principal_id: self.requesting_principal_id.clone(),
            authentication_event_id: self.authentication_event_id.clone(),
            authentication_event_digest: self.authentication_event_digest,
            operating_subject: self.operating_subject.clone(),
            operating_binding: self.operating_binding.clone(),
            operating_principal_id: self.operating_principal_id.clone(),
            delegation_id: self.delegation_id.clone(),
            operation: self.operation.clone(),
            command_digest: self.command_digest,
            command_envelope_digest: self.command_envelope_digest,
            presentation_id: self.presentation_id.clone(),
            authenticated_at: self.authenticated_at,
            evaluated_authority_head: self.evaluated_authority_head,
            workspace_id: self.workspace_id.clone(),
        }
    }

    /// Validates the Human-plus-Agent context audience/Workspace coherence and
    /// the operating Agent subject profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience or operating-subject
    /// violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        validate_audience(&self.audience, &self.workspace_id)?;
        validate_agent_subject(&self.operating_subject)
    }
}

impl AuthenticatedActorContextV2 {
    /// Returns the closed authentication profile of this context.
    #[must_use]
    pub fn profile(&self) -> AuthenticationProfile {
        match self {
            Self::Human(_) => AuthenticationProfile::OidcHuman,
            Self::HumanAgent(_) => AuthenticationProfile::OidcHumanAgent,
        }
    }

    /// Redacts either protected profile to its public commitment-only evidence.
    #[must_use]
    pub fn redact(
        &self,
        public_input_projection_digest: ContentDigest,
    ) -> AuthenticatedActorContextEvidenceV2 {
        match self {
            Self::Human(context) => AuthenticatedActorContextEvidenceV2::Human(
                context.redact(public_input_projection_digest),
            ),
            Self::HumanAgent(context) => AuthenticatedActorContextEvidenceV2::HumanAgent(
                context.redact(public_input_projection_digest),
            ),
        }
    }

    /// Validates either protected profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience, subject, or profile
    /// violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        match self {
            Self::Human(context) => context.validate(),
            Self::HumanAgent(context) => context.validate(),
        }
    }
}

impl AuthenticatedActorContextHumanEvidenceV2 {
    /// Computes the `proof:authenticated-actor-context-evidence:v2` digest of
    /// this exact public evidence.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the evidence cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<ContentDigest, RemoteError> {
        typed_digest(AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, self)
    }

    /// Validates the public Human evidence audience/Workspace coherence.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience/Workspace mismatch.
    pub fn validate(&self) -> Result<(), RemoteError> {
        validate_audience(&self.audience, &self.workspace_id)
    }
}

impl AuthenticatedActorContextHumanAgentEvidenceV2 {
    /// Computes the `proof:authenticated-actor-context-evidence:v2` digest of
    /// this exact public evidence.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the evidence cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<ContentDigest, RemoteError> {
        typed_digest(AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, self)
    }

    /// Validates the public Human-plus-Agent evidence audience/Workspace
    /// coherence and operating Agent subject profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience or operating-subject
    /// violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        validate_audience(&self.audience, &self.workspace_id)?;
        validate_agent_subject(&self.operating_subject)
    }
}

impl AuthenticatedActorContextEvidenceV2 {
    /// Returns the closed authentication profile of this evidence.
    #[must_use]
    pub fn profile(&self) -> AuthenticationProfile {
        match self {
            Self::Human(_) => AuthenticationProfile::OidcHuman,
            Self::HumanAgent(_) => AuthenticationProfile::OidcHumanAgent,
        }
    }

    /// Computes the `proof:authenticated-actor-context-evidence:v2` digest of
    /// either public evidence profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Canonical`] if the evidence cannot be
    /// canonicalized.
    pub fn digest(&self) -> Result<ContentDigest, RemoteError> {
        match self {
            Self::Human(evidence) => evidence.digest(),
            Self::HumanAgent(evidence) => evidence.digest(),
        }
    }

    /// Validates either public evidence profile.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Identity`] on an audience, subject, or profile
    /// violation.
    pub fn validate(&self) -> Result<(), RemoteError> {
        match self {
            Self::Human(evidence) => evidence.validate(),
            Self::HumanAgent(evidence) => evidence.validate(),
        }
    }
}
