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

use proof_application::authority::{
    DelegationRevocationV1, DelegationV2, PrincipalBindingRevocationV1, PrincipalBindingV1,
};
use proof_attestation::{
    DsseEnvelope, ED25519_PUBLIC_KEY_BYTES, ED25519_SIGNATURE_BYTES, ProofSigningProvider,
};
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
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        todo!()
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
    todo!()
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
    todo!()
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
    todo!()
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
    todo!()
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
    todo!()
}
