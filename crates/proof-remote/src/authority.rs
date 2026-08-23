//! Closed `RemoteAuthorityRecordV1` successor payload union and its
//! one-signature Ed25519 DSSE envelope.
//!
//! This module implements the complete type surface for the remote authority
//! payload variants ratified by the accepted single-Workspace
//! collaboration-server contract (§"Remote identity vocabulary",
//! §"Causal approval and release recheck", §"Environment and policy
//! administration", §"HTTP boundary"). The four reused local administrative
//! artifacts (Agent `PrincipalBindingV1`, `PrincipalBindingRevocationV1`,
//! `DelegationV2`, `DelegationRevocationV1`) retain their accepted bytes and
//! are re-exported from `proof-application`.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use proof_application::authority::{
    DelegationRevocationV1, DelegationV2, PrincipalBindingRevocationV1, PrincipalBindingV1,
};
use proof_attestation::{
    DsseEnvelope, DsseSignature, ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES,
    ProofSigningProvider, SignatureAlgorithm, SigningKeyMetadata, ed25519_key_id,
    parse_ed25519_key_id,
};
use proof_canonical::{CanonicalJson, canonicalize, parse_strict};
use proof_domain::{ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityHeadV1, RemoteError,
    governance::{
        ChangeSetApprovalV1, EnvironmentConfigActivationV1, EnvironmentConfigProposalV1,
        EnvironmentCreationV1,
    },
    identity::{OidcPrincipalBindingRevocationV1, OidcPrincipalBindingV1},
    registry::{RemoteApplicationConsequenceV1, RemoteAuthorizationDecisionV1},
};

/// Exact DSSE payload type for a decoded `RemoteAuthorityRecordV1`.
pub const REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE: &str =
    "application/vnd.proof.remote-authority-record.v1+json";
/// BLAKE3-256 derive-key context for a decoded remote authority payload.
pub const REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT: &str = "proof:remote-authority-record:v1";
/// BLAKE3-256 derive-key context for a signed remote authority envelope.
pub const REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT: &str =
    "proof:remote-authority-record-envelope:v1";
/// Maximum canonical remote-authority payload length (bytes).
pub const MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES: usize = 65_536;
/// Maximum canonical remote-authority envelope length (bytes).
pub const MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES: usize = 98_304;
/// Exact signature cardinality for the one-signature remote authority envelope.
pub const REMOTE_AUTHORITY_SIGNATURE_COUNT: usize = 1;

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
    WorkspaceRoleAssignmentApiVersion,
    "proof.dev/workspace-role-assignment/v1"
);
api_version!(
    WorkspaceRoleRevocationApiVersion,
    "proof.dev/workspace-role-revocation/v1"
);
api_version!(
    RemotePrincipalStatusApiVersion,
    "proof.dev/remote-principal-status/v2"
);

/// The exact closed first-profile Human role vocabulary (contract §"Human roles
/// and separation of duties").
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum WorkspaceRole {
    /// `authority.admin` — issue/revoke Agent bindings and emergency Delegation
    /// revocation.
    #[serde(rename = "authority.admin")]
    AuthorityAdmin,
    /// `content.publisher` — read governed closures and create/read exports.
    #[serde(rename = "content.publisher")]
    ContentPublisher,
    /// `content.requester` — issue the intent, first `ContextPack`, and its
    /// Delegation.
    #[serde(rename = "content.requester")]
    ContentRequester,
    /// `content.reviewer` — read the submitted closure and approve.
    #[serde(rename = "content.reviewer")]
    ContentReviewer,
    /// `environment.activator` — activate a proposed configuration or abandon a
    /// poison delivery.
    #[serde(rename = "environment.activator")]
    EnvironmentActivator,
    /// `environment.admin` — propose an Environment configuration.
    #[serde(rename = "environment.admin")]
    EnvironmentAdmin,
    /// `evidence.auditor` — read and export evidence without publication.
    #[serde(rename = "evidence.auditor")]
    EvidenceAuditor,
    /// `identity.admin` — issue/revoke Human bindings and role assignments.
    #[serde(rename = "identity.admin")]
    IdentityAdmin,
}

/// Principal class recorded by a remote authority status fact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemotePrincipalType {
    /// An Ed25519-bound operating Agent Principal.
    Agent,
    /// An OIDC-bound Human Principal.
    Human,
}

/// Append-only assignment of one closed role to an enabled Human Principal
/// (schema `workspaceRoleAssignmentV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRoleAssignmentV1 {
    pub api_version: WorkspaceRoleAssignmentApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Assignment identity (UUIDv7).
    pub assignment_id: String,
    /// Assigned Principal identity (UUIDv7).
    pub principal_id: String,
    pub role: WorkspaceRole,
    /// Assigning `identity.admin` Principal identity (UUIDv7).
    pub assigned_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub assigned_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub assigned_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Append-only revocation of one exact active role assignment
/// (schema `workspaceRoleRevocationV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRoleRevocationV1 {
    pub api_version: WorkspaceRoleRevocationApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Revocation identity (UUIDv7).
    pub revocation_id: String,
    /// Revoked assignment identity (UUIDv7).
    pub assignment_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub assignment_record_digest: ContentDigest,
    /// Affected Principal identity (UUIDv7).
    pub principal_id: String,
    pub role: WorkspaceRole,
    pub reason: String,
    /// Revoking `identity.admin` Principal identity (UUIDv7).
    pub revoked_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub revoked_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub revoked_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Recorded remote Principal status. The first online profile permits only the
/// terminal `disabled` transition (schema `remotePrincipalStatusV2`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePrincipalStatusV2 {
    pub api_version: RemotePrincipalStatusApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Affected Principal identity (UUIDv7).
    pub principal_id: String,
    pub principal_type: RemotePrincipalType,
    pub enabled: bool,
    pub reason: String,
    /// Recording `identity.admin` Principal identity (UUIDv7).
    pub recorded_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub recorded_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub recorded_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Closed discriminated union of all `RemoteAuthorityRecordV1` payloads
/// (schema `remoteAuthorityRecordV1`).
///
/// The four reused local administrative artifacts retain their accepted bytes;
/// every other variant is a versioned remote successor payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would weaken the schema-shaped public record union"
)]
pub enum RemoteAuthorityRecordV1 {
    /// Reused Agent Principal-to-key binding issue (`agent-binding.issue/v1`).
    AgentBindingIssue(PrincipalBindingV1),
    /// Reused Agent Principal-to-key binding revocation
    /// (`agent-binding.revoke/v1`).
    AgentBindingRevocation(PrincipalBindingRevocationV1),
    /// Reused direct Human-to-Agent Delegation issue (`delegation.issue/v2`).
    DelegationIssue(DelegationV2),
    /// Reused direct Delegation revocation (`delegation.revoke/v1`).
    DelegationRevocation(DelegationRevocationV1),
    /// Public OIDC Principal binding issue (`oidc-binding.issue/v1`).
    OidcBindingIssue(OidcPrincipalBindingV1),
    /// Public OIDC Principal binding revocation (`oidc-binding.revoke/v1`).
    OidcBindingRevocation(OidcPrincipalBindingRevocationV1),
    /// Workspace role assignment (`workspace-role.assign/v1`).
    WorkspaceRoleAssignment(WorkspaceRoleAssignmentV1),
    /// Workspace role revocation (`workspace-role.revoke/v1`).
    WorkspaceRoleRevocation(WorkspaceRoleRevocationV1),
    /// Recorded remote Principal status (`principal.status.set/v2`).
    RemotePrincipalStatus(RemotePrincipalStatusV2),
    /// Causal digest-bound `ChangeSet` approval (`changeset.approve/v3`).
    ChangeSetApproval(ChangeSetApprovalV1),
    /// Environment creation chronology fact.
    EnvironmentCreation(EnvironmentCreationV1),
    /// Environment configuration proposal.
    EnvironmentConfigProposal(EnvironmentConfigProposalV1),
    /// Environment configuration activation.
    EnvironmentConfigActivation(EnvironmentConfigActivationV1),
    /// Server-produced current-head authorization decision.
    RemoteAuthorizationDecision(RemoteAuthorizationDecisionV1),
    /// Signed consequence of one committed authorized attempt.
    RemoteApplicationConsequence(RemoteApplicationConsequenceV1),
}

impl RemoteAuthorityRecordV1 {
    /// Wraps a reused Agent binding issue record.
    #[must_use]
    pub const fn agent_binding_issue(payload: PrincipalBindingV1) -> Self {
        Self::AgentBindingIssue(payload)
    }

    /// Wraps a reused Agent binding revocation record.
    #[must_use]
    pub const fn agent_binding_revocation(payload: PrincipalBindingRevocationV1) -> Self {
        Self::AgentBindingRevocation(payload)
    }

    /// Wraps a reused Delegation issue record.
    #[must_use]
    pub const fn delegation_issue(payload: DelegationV2) -> Self {
        Self::DelegationIssue(payload)
    }

    /// Wraps a reused Delegation revocation record.
    #[must_use]
    pub const fn delegation_revocation(payload: DelegationRevocationV1) -> Self {
        Self::DelegationRevocation(payload)
    }

    /// Wraps a public OIDC binding issue record.
    #[must_use]
    pub const fn oidc_binding_issue(payload: OidcPrincipalBindingV1) -> Self {
        Self::OidcBindingIssue(payload)
    }

    /// Wraps a public OIDC binding revocation record.
    #[must_use]
    pub const fn oidc_binding_revocation(payload: OidcPrincipalBindingRevocationV1) -> Self {
        Self::OidcBindingRevocation(payload)
    }

    /// Wraps a Workspace role assignment record.
    #[must_use]
    pub const fn workspace_role_assignment(payload: WorkspaceRoleAssignmentV1) -> Self {
        Self::WorkspaceRoleAssignment(payload)
    }

    /// Wraps a Workspace role revocation record.
    #[must_use]
    pub const fn workspace_role_revocation(payload: WorkspaceRoleRevocationV1) -> Self {
        Self::WorkspaceRoleRevocation(payload)
    }

    /// Wraps a remote Principal status record.
    #[must_use]
    pub const fn principal_status(payload: RemotePrincipalStatusV2) -> Self {
        Self::RemotePrincipalStatus(payload)
    }

    /// Wraps a causal `ChangeSet` approval record.
    #[must_use]
    pub const fn changeset_approval(payload: ChangeSetApprovalV1) -> Self {
        Self::ChangeSetApproval(payload)
    }

    /// Wraps an Environment creation record.
    #[must_use]
    pub const fn environment_creation(payload: EnvironmentCreationV1) -> Self {
        Self::EnvironmentCreation(payload)
    }

    /// Wraps an Environment configuration proposal record.
    #[must_use]
    pub const fn environment_config_proposal(payload: EnvironmentConfigProposalV1) -> Self {
        Self::EnvironmentConfigProposal(payload)
    }

    /// Wraps an Environment configuration activation record.
    #[must_use]
    pub const fn environment_config_activation(payload: EnvironmentConfigActivationV1) -> Self {
        Self::EnvironmentConfigActivation(payload)
    }

    /// Wraps a remote authorization decision record.
    #[must_use]
    pub const fn authorization_decision(payload: RemoteAuthorizationDecisionV1) -> Self {
        Self::RemoteAuthorizationDecision(payload)
    }

    /// Wraps a remote application consequence record.
    #[must_use]
    pub const fn application_consequence(payload: RemoteApplicationConsequenceV1) -> Self {
        Self::RemoteApplicationConsequence(payload)
    }

    /// Computes the exact `proof:remote-authority-record:v1` digest of the
    /// strict RFC 8785 canonical payload.
    ///
    /// # Panics
    ///
    /// Panics only if a closed remote authority record cannot serialize or
    /// canonicalize, which cannot occur for the closed schema-shaped union.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        let value =
            serde_json::to_value(self).expect("a closed remote authority record always serializes");
        let canonical = canonicalize(&value)
            .expect("a closed remote authority record always canonicalizes to RFC 8785 JSON");
        crate::derive_key_digest(REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT, canonical.as_bytes())
    }
}

/// One-signature Ed25519 DSSE envelope for a remote authority record.
///
/// The payload type is exactly [`REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE`]; the
/// envelope is canonical RFC 8785 JSON and carries exactly one signature.
pub type RemoteAuthorityRecordEnvelopeV1 = DsseEnvelope;

/// Complete result of signing one remote authority record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedRemoteAuthorityRecordEnvelope {
    /// Structured DSSE envelope.
    pub envelope: RemoteAuthorityRecordEnvelopeV1,
    /// Exact RFC 8785 canonical envelope JSON.
    pub envelope_json: String,
    /// `proof:remote-authority-record-envelope:v1` envelope digest.
    pub envelope_digest: ContentDigest,
    /// Exact RFC 8785 canonical payload JSON.
    pub payload_json: String,
    /// `proof:remote-authority-record:v1` payload digest.
    pub payload_digest: ContentDigest,
    /// Explicit signing key identifier.
    pub key_id: String,
}

/// Strictly parsed remote authority envelope before trust evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRemoteAuthorityRecordEnvelope {
    /// Structured DSSE envelope.
    pub envelope: RemoteAuthorityRecordEnvelopeV1,
    /// Strictly decoded typed payload.
    pub record: RemoteAuthorityRecordV1,
    /// Exact RFC 8785 canonical envelope JSON.
    pub envelope_json: String,
    /// `proof:remote-authority-record-envelope:v1` envelope digest.
    pub envelope_digest: ContentDigest,
    /// Exact RFC 8785 canonical payload JSON.
    pub payload_json: String,
    /// `proof:remote-authority-record:v1` payload digest.
    pub payload_digest: ContentDigest,
    /// Unsigned key hint carried by the envelope.
    pub key_id: String,
    /// Exact decoded Ed25519 signature bytes.
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

/// Cryptographically verified remote authority envelope plus parsed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRemoteAuthorityRecordEnvelope {
    /// Complete strict parsed representation.
    pub parsed: ParsedRemoteAuthorityRecordEnvelope,
    /// Independently resolved expected key identifier.
    pub key_id: String,
    /// Public key extracted from the expected key identifier.
    pub public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

/// One verified remote authority record suitable for chain validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRemoteAuthorityRecord {
    /// Decoded typed payload.
    pub record: RemoteAuthorityRecordV1,
    /// `proof:remote-authority-record:v1` payload digest.
    pub record_digest: ContentDigest,
    /// `proof:remote-authority-record-envelope:v1` envelope digest.
    pub envelope_digest: ContentDigest,
    /// Signer key identifier resolved by the active authority key.
    pub signer_key_id: String,
    /// Public key used to verify the signature.
    pub public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

/// Resolves the causally active Workspace authority signing key.
///
/// The decoded payload is signed only by the independently resolved active
/// Workspace authority key (contract §"Remote identity vocabulary"); this trait
/// is the object-safe seam that supplies that key without trusting the
/// envelope's self-description.
pub trait ActiveAuthorityKeyResolver {
    /// Resolves the Ed25519 public key authorized to sign for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Authority`] when no active key resolves.
    fn resolve_active_key(
        &self,
        key_id: &str,
    ) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], RemoteError>;
}

/// Produces DSSE pre-authentication encoding for the remote authority profile.
///
/// # Errors
///
/// Returns [`RemoteError::Authority`] when `payload` exceeds
/// [`MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES`].
pub fn remote_authority_pae(payload: &[u8]) -> Result<Vec<u8>, RemoteError> {
    if payload.len() > MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES {
        return Err(RemoteError::Authority(format!(
            "remote authority payload exceeds {MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES} bytes"
        )));
    }
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE.len(),
        REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
        payload.len()
    );
    let mut pae = Vec::with_capacity(prefix.len() + payload.len());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(payload);
    Ok(pae)
}

/// Canonicalizes, PAE-signs, and envelopes one typed remote authority record.
///
/// The payload is strict RFC 8785 canonical JSON under
/// [`REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT`]; the envelope is canonical JSON
/// under [`REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT`] and carries exactly
/// one signature.
///
/// # Errors
///
/// Returns [`RemoteError::Authority`] on any bound, canonicalization, signing,
/// or envelope-profile violation.
pub fn sign_remote_authority_record(
    record: &RemoteAuthorityRecordV1,
    signer: &dyn ProofSigningProvider,
) -> Result<SignedRemoteAuthorityRecordEnvelope, RemoteError> {
    let payload_value = serde_json::to_value(record)
        .map_err(|error| RemoteError::Authority(format!("record serialization failed: {error}")))?;
    if !payload_value.is_object() {
        return Err(RemoteError::Authority(
            "the remote authority record must be a JSON object".to_owned(),
        ));
    }
    let canonical_payload = canonicalize(&payload_value).map_err(|error| {
        RemoteError::Authority(format!("record canonicalization failed: {error}"))
    })?;
    if canonical_payload.as_bytes().len() > MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES {
        return Err(RemoteError::Authority(format!(
            "remote authority payload exceeds {MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES} bytes"
        )));
    }
    let pae = remote_authority_pae(canonical_payload.as_bytes())?;

    let metadata = signer.metadata().map_err(|error| {
        RemoteError::Authority(format!("signing provider unavailable: {error}"))
    })?;
    let public_key = validate_signing_metadata(&metadata)?;
    let signature = signer
        .sign_pae(&pae)
        .map_err(|error| RemoteError::Authority(format!("signing failed: {error}")))?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RemoteError::Authority("signature must be exactly 64 bytes".to_owned()))?;
    verify_ed25519(&public_key, &signature, &pae)?;

    let envelope = DsseEnvelope {
        payload_type: REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE.to_owned(),
        payload: BASE64.encode(canonical_payload.as_bytes()),
        signatures: vec![DsseSignature {
            keyid: metadata.key_id.clone(),
            sig: BASE64.encode(signature),
        }],
    };
    let envelope_value = serde_json::to_value(&envelope).map_err(|error| {
        RemoteError::Authority(format!("envelope serialization failed: {error}"))
    })?;
    let canonical_envelope = canonicalize(&envelope_value).map_err(|error| {
        RemoteError::Authority(format!("envelope canonicalization failed: {error}"))
    })?;
    if canonical_envelope.as_bytes().len() > MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES {
        return Err(RemoteError::Authority(format!(
            "remote authority envelope exceeds {MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES} bytes"
        )));
    }

    let payload_digest = crate::derive_key_digest(
        REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
        canonical_payload.as_bytes(),
    );
    let envelope_digest = crate::derive_key_digest(
        REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT,
        canonical_envelope.as_bytes(),
    );

    Ok(SignedRemoteAuthorityRecordEnvelope {
        envelope,
        envelope_json: canonical_envelope.as_str().to_owned(),
        envelope_digest,
        payload_json: canonical_payload.as_str().to_owned(),
        payload_digest,
        key_id: metadata.key_id,
    })
}

/// Strictly parses one canonical remote authority envelope.
///
/// This validates exact media type, signature cardinality, bounds, canonical
/// JSON, canonical standard base64, and the closed payload union. It does not
/// establish trust or verify the signature.
///
/// # Errors
///
/// Returns [`RemoteError::Authority`] on any structural violation.
pub fn parse_remote_authority_record_envelope(
    input: &[u8],
) -> Result<ParsedRemoteAuthorityRecordEnvelope, RemoteError> {
    if input.len() > MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES {
        return Err(RemoteError::Authority(format!(
            "remote authority envelope exceeds {MAX_REMOTE_AUTHORITY_ENVELOPE_BYTES} bytes"
        )));
    }
    let envelope_value = parse_strict(input)
        .map_err(|error| RemoteError::Authority(format!("invalid envelope JSON: {error}")))?;
    let canonical_envelope = canonicalize(&envelope_value)
        .map_err(|error| RemoteError::Authority(format!("invalid envelope JSON: {error}")))?;
    if canonical_envelope.as_bytes() != input {
        return Err(RemoteError::Authority(
            "the remote authority envelope is not canonical JSON".to_owned(),
        ));
    }
    let envelope: DsseEnvelope = serde_json::from_value(envelope_value)
        .map_err(|error| RemoteError::Authority(format!("invalid DSSE envelope: {error}")))?;
    if envelope.payload_type != REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE {
        return Err(RemoteError::Authority(format!(
            "unsupported DSSE payload type `{}`",
            envelope.payload_type
        )));
    }
    let [signature_entry] = envelope.signatures.as_slice() else {
        return Err(RemoteError::Authority(
            "the remote authority envelope must carry exactly one signature".to_owned(),
        ));
    };
    let key_id = signature_entry.keyid.clone();
    parse_ed25519_key_id(&signature_entry.keyid).map_err(|error| {
        RemoteError::Authority(format!("invalid signing key identifier: {error}"))
    })?;

    let payload_bytes = decode_canonical_base64(&envelope.payload)?;
    if payload_bytes.len() > MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES {
        return Err(RemoteError::Authority(format!(
            "remote authority payload exceeds {MAX_REMOTE_AUTHORITY_PAYLOAD_BYTES} bytes"
        )));
    }
    let payload_value = parse_strict(&payload_bytes)
        .map_err(|error| RemoteError::Authority(format!("invalid payload JSON: {error}")))?;
    if !payload_value.is_object() {
        return Err(RemoteError::Authority(
            "the remote authority payload must be a JSON object".to_owned(),
        ));
    }
    let canonical_payload = canonicalize(&payload_value)
        .map_err(|error| RemoteError::Authority(format!("invalid payload JSON: {error}")))?;
    if canonical_payload.as_bytes() != payload_bytes {
        return Err(RemoteError::Authority(
            "the remote authority payload is not canonical JSON".to_owned(),
        ));
    }
    let record: RemoteAuthorityRecordV1 =
        serde_json::from_value(payload_value).map_err(|error| {
            RemoteError::Authority(format!("unknown remote authority record: {error}"))
        })?;

    let signature = decode_canonical_base64(&signature_entry.sig)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| RemoteError::Authority("signature must be exactly 64 bytes".to_owned()))?;

    let payload_digest = crate::derive_key_digest(
        REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
        canonical_payload.as_bytes(),
    );
    let envelope_digest = crate::derive_key_digest(
        REMOTE_AUTHORITY_RECORD_ENVELOPE_DIGEST_CONTEXT,
        canonical_envelope.as_bytes(),
    );

    Ok(ParsedRemoteAuthorityRecordEnvelope {
        envelope,
        record,
        envelope_json: canonical_envelope.as_str().to_owned(),
        envelope_digest,
        payload_json: canonical_payload.as_str().to_owned(),
        payload_digest,
        key_id,
        signature,
    })
}

/// Verifies one remote authority envelope against an independently resolved
/// active Workspace authority key.
///
/// # Errors
///
/// Returns [`RemoteError::Authority`] unless strict parsing and Ed25519
/// verification over the DSSE PAE both succeed.
pub fn verify_remote_authority_record_envelope(
    input: &[u8],
    expected_key_id: &str,
) -> Result<VerifiedRemoteAuthorityRecordEnvelope, RemoteError> {
    let parsed = parse_remote_authority_record_envelope(input)?;
    // The expected key identifier is supplied by the caller's independently
    // resolved active Workspace authority key; its embedded public bytes are the
    // only key material accepted for verification.
    let public_key = parse_ed25519_key_id(expected_key_id).map_err(|error| {
        RemoteError::Authority(format!("invalid expected key identifier: {error}"))
    })?;
    let pae = remote_authority_pae(parsed.payload_json.as_bytes())?;
    verify_ed25519(&public_key, &parsed.signature, &pae)?;
    // `keyid` is unsigned and cannot select trust; compare it only after the
    // signature has verified against the independently resolved key.
    if parsed.key_id != expected_key_id {
        return Err(RemoteError::Authority(
            "the envelope signing key identifier does not match the expected active key".to_owned(),
        ));
    }
    Ok(VerifiedRemoteAuthorityRecordEnvelope {
        parsed,
        key_id: expected_key_id.to_owned(),
        public_key,
    })
}

/// Validates one contiguous remote authority chain for causal coherence.
///
/// Enforces sequence monotonicity, `previous_authority_record_digest`
/// predecessor linkage, `evaluated_authority_head` coherence, and the
/// single-active-Workspace-key signer rule. `initial_head` is the exact
/// authority head that precedes the first record.
///
/// # Errors
///
/// Returns [`RemoteError::Authority`] on a fork, reorder, predecessor mismatch,
/// head mismatch, or signer-rule violation.
pub fn validate_chain(
    records: &[VerifiedRemoteAuthorityRecord],
    active_key_resolver: &dyn ActiveAuthorityKeyResolver,
    initial_head: AuthorityHeadV1,
) -> Result<AuthorityHeadV1, RemoteError> {
    if records.is_empty() {
        return Ok(initial_head);
    }

    // The whole prefix is signed by exactly one active Workspace authority key.
    let signer_key_id = records[0].signer_key_id.as_str();
    let active_public_key = active_key_resolver.resolve_active_key(signer_key_id)?;
    if active_public_key != records[0].public_key {
        return Err(RemoteError::Authority(
            "the resolved active key disagrees with the verified signer key".to_owned(),
        ));
    }

    let mut expected_sequence = initial_head
        .sequence
        .checked_add(1)
        .ok_or_else(|| RemoteError::Authority("authority sequence overflow".to_owned()))?;
    let mut previous_digest = initial_head.record_digest;
    let mut previous_head = initial_head;

    for record in records {
        if record.signer_key_id != signer_key_id {
            return Err(RemoteError::Authority(
                "the remote authority chain switches signer keys within one prefix".to_owned(),
            ));
        }
        let view = chain_view(&record.record);
        if view.sequence != expected_sequence {
            return Err(RemoteError::Authority(
                "the remote authority chain has a sequence gap or reorder".to_owned(),
            ));
        }
        if view.previous_digest != Some(previous_digest) {
            return Err(RemoteError::Authority(
                "the remote authority predecessor digest does not link to the previous record"
                    .to_owned(),
            ));
        }
        if let Some(evaluated_head) = view.evaluated_head
            && evaluated_head != previous_head
        {
            return Err(RemoteError::Authority(
                "the remote authority evaluated head disagrees with the previous record".to_owned(),
            ));
        }

        previous_digest = record.record_digest;
        previous_head = AuthorityHeadV1 {
            sequence: view.sequence,
            record_digest: record.record_digest,
        };
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| RemoteError::Authority("authority sequence overflow".to_owned()))?;
    }

    Ok(previous_head)
}

/// Decodes standard base64 and requires the canonical (round-trip exact) form.
fn decode_canonical_base64(input: &str) -> Result<Vec<u8>, RemoteError> {
    let decoded = BASE64
        .decode(input)
        .map_err(|_| RemoteError::Authority("the envelope contains invalid base64".to_owned()))?;
    if BASE64.encode(&decoded) != input {
        return Err(RemoteError::Authority(
            "the envelope contains non-canonical base64".to_owned(),
        ));
    }
    Ok(decoded)
}

/// Verifies one Ed25519 signature over exact DSSE PAE bytes.
fn verify_ed25519(
    public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    signature: &[u8; ED25519_SIGNATURE_BYTES],
    pae: &[u8],
) -> Result<(), RemoteError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| RemoteError::Authority("the Ed25519 public key is invalid".to_owned()))?;
    let signature = Ed25519Signature::from_bytes(signature);
    verifying_key
        .verify_strict(pae, &signature)
        .map_err(|_| RemoteError::Authority("the Ed25519 signature is invalid".to_owned()))
}

/// Validates provider metadata and returns the exact 32-byte public key.
fn validate_signing_metadata(
    metadata: &SigningKeyMetadata,
) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], RemoteError> {
    if metadata.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(RemoteError::Authority(
            "the signing provider must use Ed25519".to_owned(),
        ));
    }
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] =
        metadata.public_key.as_slice().try_into().map_err(|_| {
            RemoteError::Authority("the Ed25519 public key must be 32 bytes".to_owned())
        })?;
    if metadata.key_id != ed25519_key_id(&public_key) {
        return Err(RemoteError::Authority(
            "the signing key identifier does not match its public key".to_owned(),
        ));
    }
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| RemoteError::Authority("the Ed25519 public key is invalid".to_owned()))?;
    Ok(public_key)
}

/// Causal fields shared by every `RemoteAuthorityRecordV1` chain entry.
struct RecordChainView {
    sequence: u64,
    previous_digest: Option<ContentDigest>,
    evaluated_head: Option<AuthorityHeadV1>,
}

/// Extracts the sequence, predecessor digest, and evaluated head carried by one
/// record. The four reused local administrative artifacts have no
/// `evaluated_authority_head`, so head coherence is only asserted when present.
fn chain_view(record: &RemoteAuthorityRecordV1) -> RecordChainView {
    match record {
        RemoteAuthorityRecordV1::AgentBindingIssue(value) => RecordChainView {
            sequence: value.authority_sequence.get(),
            previous_digest: value.previous_authority_record_digest,
            evaluated_head: None,
        },
        RemoteAuthorityRecordV1::AgentBindingRevocation(value) => RecordChainView {
            sequence: value.authority_sequence.get(),
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: None,
        },
        RemoteAuthorityRecordV1::DelegationIssue(value) => RecordChainView {
            sequence: value.authority_sequence.get(),
            previous_digest: value.previous_authority_record_digest,
            evaluated_head: None,
        },
        RemoteAuthorityRecordV1::DelegationRevocation(value) => RecordChainView {
            sequence: value.authority_sequence.get(),
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: None,
        },
        RemoteAuthorityRecordV1::OidcBindingIssue(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::OidcBindingRevocation(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::WorkspaceRoleAssignment(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::WorkspaceRoleRevocation(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::RemotePrincipalStatus(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::ChangeSetApproval(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::EnvironmentCreation(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::EnvironmentConfigProposal(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::EnvironmentConfigActivation(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::RemoteAuthorizationDecision(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
        RemoteAuthorityRecordV1::RemoteApplicationConsequence(value) => RecordChainView {
            sequence: value.authority_sequence,
            previous_digest: Some(value.previous_authority_record_digest),
            evaluated_head: Some(value.evaluated_authority_head),
        },
    }
}
