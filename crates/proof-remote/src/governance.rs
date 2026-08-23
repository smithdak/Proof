//! Causal approval and Environment-configuration governance facts.
//!
//! This module implements the complete type surface for `ChangeSetApprovalV1`
//! and the Environment creation/proposal/activation records plus the assembled
//! immutable [`EnvironmentConfigV2`] closure (contract §"Causal approval and
//! release recheck", §"Environment and policy administration").

use proof_domain::{ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityHeadV1, RemoteError, authority::REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
    derive_key_digest,
};

/// BLAKE3-256 derive-key context for `environment_config_digest` and
/// `normalized_configuration_digest`.
pub const ENVIRONMENT_CONFIG_DIGEST_CONTEXT: &str = "proof:environment-config:v2";

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
    ChangeSetApprovalApiVersion,
    "proof.dev/changeset-approval/v1"
);
api_version!(
    EnvironmentCreationApiVersion,
    "proof.dev/environment-creation/v1"
);
api_version!(
    EnvironmentConfigProposalApiVersion,
    "proof.dev/environment-config-proposal/v1"
);
api_version!(
    EnvironmentConfigActivationApiVersion,
    "proof.dev/environment-config-activation/v1"
);
api_version!(
    EnvironmentConfigApiVersion,
    "proof.dev/environment-config/v2"
);

/// The sole accepted approval decision (`approved`).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApprovalDecision {
    /// The approval attests to one exact review closure.
    #[default]
    #[serde(rename = "approved")]
    Approved,
}

/// Approval policy fragment of a normalized Environment configuration
/// (schema `approvalPolicy`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the schema-faithful approval policy carries exactly four separation-of-duties flags"
)]
pub struct ApprovalPolicyV1 {
    pub minimum_approvals: u32,
    /// Always `content.reviewer`.
    pub approver_role: String,
    pub approver_distinct_from_requesting_human: bool,
    pub approver_distinct_from_operating_agent: bool,
    pub approver_distinct_from_publisher: bool,
    pub approver_distinct_from_environment_activator: bool,
}

/// Delivery destination fragment of a normalized Environment configuration
/// (schema `deliveryConfiguration`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryConfigurationV1 {
    pub visibility: String,
    pub release_selection: String,
    pub locale_resolution: String,
    pub cache_control: String,
    /// Destination configuration identity (UUIDv7).
    pub destination_configuration_id: String,
    pub destination_configuration_version: u32,
    #[serde(with = "crate::serde_support::display_string")]
    pub destination_configuration_digest: ContentDigest,
}

/// Complete normalized Environment configuration
/// (schema `normalizedEnvironmentConfiguration`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEnvironmentConfigurationV1 {
    pub enabled: bool,
    /// Always `preview` in the first profile.
    pub target_kind: String,
    pub approval_name: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub policy_bundle_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub validation_policy_digest: ContentDigest,
    pub separation_of_duties_profile: String,
    pub approval_policy: ApprovalPolicyV1,
    pub delivery: DeliveryConfigurationV1,
}

/// One causal digest-bound `ChangeSet` approval
/// (schema `changeSetApprovalV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSetApprovalV1 {
    pub api_version: ChangeSetApprovalApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Approval identity (UUIDv7).
    pub approval_id: String,
    pub approval_name: String,
    /// Approved `ChangeSet` identity (UUIDv7).
    pub changeset_id: String,
    pub approval_decision: ApprovalDecision,
    /// ChangeSet requester Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    /// Operating Agent Principal identity (UUIDv7).
    pub operating_principal_id: String,
    /// Approving Human Principal identity (UUIDv7).
    pub approver_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub approver_subject_commitment: ContentDigest,
    /// Approving binding identity (UUIDv7).
    pub approver_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub approver_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub reviewer_role_assignment_digest: ContentDigest,
    /// Publisher Principal identity (UUIDv7).
    pub publisher_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub sealed_changeset_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposal_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub effective_leaves_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub validation_results_digest: ContentDigest,
    /// Submission identity (UUIDv7).
    pub submission_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub submission_digest: ContentDigest,
    /// Resource-intent identity (UUIDv7).
    pub resource_intent_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub resource_intent_digest: ContentDigest,
    /// `ContextPack` identity (UUIDv7).
    pub context_pack_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub context_pack_digest: ContentDigest,
    /// Active Environment identifier.
    pub environment_id: String,
    pub environment_config_version: u32,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    /// Principal that activated the bound configuration (UUIDv7).
    pub environment_activated_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub policy_bundle_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub validation_policy_digest: ContentDigest,
    /// Application idempotency key (UUIDv7).
    pub idempotency_key: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    pub evaluated_authority_head: AuthorityHeadV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub approved_at: Timestamp,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

impl ChangeSetApprovalV1 {
    /// Rejects every prohibited approver (contract §"Causal approval and
    /// release recheck"): an Agent, a disabled or unbound Human, the ChangeSet
    /// requester, a contributing Agent, the active configuration activator, an
    /// incomplete or stale closure, a changed validation head, or a role
    /// assignment not active at the transaction head.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Governance`] on any prohibited-approver or stale
    /// closure violation.
    pub fn validate_prohibited_approvers(&self) -> Result<(), RemoteError> {
        // The approval must extend its exact evaluated authority head: the new
        // sequence is head.sequence + 1 and the immediate predecessor digest is
        // head.record_digest. A mismatch marks an incomplete or stale closure.
        let expected_sequence = self
            .evaluated_authority_head
            .sequence
            .checked_add(1)
            .ok_or_else(|| {
                RemoteError::Governance(
                    "approval authority sequence overflows the causal head".to_owned(),
                )
            })?;
        if self.authority_sequence != expected_sequence {
            return Err(RemoteError::Governance(
                "approval does not extend the evaluated authority head by exactly one sequence"
                    .to_owned(),
            ));
        }
        if self.previous_authority_record_digest != self.evaluated_authority_head.record_digest {
            return Err(RemoteError::Governance(
                "approval does not chain from the exact immediate prior authority head".to_owned(),
            ));
        }

        // The closed separation-of-duties inequalities: the approving Human must
        // be distinct from the requester, the contributing operating Agent, the
        // publisher Agent, and the active configuration activator; and the
        // requesting Human must be distinct from the operating Agent.
        if self.approver_principal_id == self.requesting_principal_id {
            return Err(RemoteError::Governance(
                "approver must not be the ChangeSet requesting Human".to_owned(),
            ));
        }
        if self.approver_principal_id == self.operating_principal_id {
            return Err(RemoteError::Governance(
                "approver must not be a contributing operating Agent".to_owned(),
            ));
        }
        if self.approver_principal_id == self.publisher_principal_id {
            return Err(RemoteError::Governance(
                "approver must not be the publisher Agent".to_owned(),
            ));
        }
        if self.approver_principal_id == self.environment_activated_by_principal_id {
            return Err(RemoteError::Governance(
                "approver must not be the active configuration activator".to_owned(),
            ));
        }
        if self.requesting_principal_id == self.operating_principal_id {
            return Err(RemoteError::Governance(
                "requesting Human must be distinct from the operating Agent".to_owned(),
            ));
        }

        Ok(())
    }
}

/// Immutable Environment creation chronology fact
/// (schema `environmentCreationV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCreationV1 {
    pub api_version: EnvironmentCreationApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Environment identifier.
    pub environment_id: String,
    /// Creating `environment.admin` Principal identity (UUIDv7).
    pub created_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub created_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub created_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Immutable Environment configuration proposal
/// (schema `environmentConfigProposalV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfigProposalV1 {
    pub api_version: EnvironmentConfigProposalApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Environment identifier.
    pub environment_id: String,
    /// Proposal identity (UUIDv7).
    pub proposal_id: String,
    pub expected_predecessor_config_version: Option<u32>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub expected_predecessor_config_digest: Option<ContentDigest>,
    /// Application idempotency key (UUIDv7).
    pub idempotency_key: String,
    pub normalized_configuration: NormalizedEnvironmentConfigurationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    /// Proposing `environment.admin` Principal identity (UUIDv7).
    pub proposed_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposed_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposer_role_assignment_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposed_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Immutable Environment configuration activation
/// (schema `environmentConfigActivationV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfigActivationV1 {
    pub api_version: EnvironmentConfigActivationApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Environment identifier.
    pub environment_id: String,
    /// Activation identity (UUIDv7).
    pub activation_id: String,
    /// Activated proposal identity (UUIDv7).
    pub proposal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposal_digest: ContentDigest,
    pub predecessor_config_version: Option<u32>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub predecessor_config_digest: Option<ContentDigest>,
    pub environment_config_version: u32,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_configuration_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_created_at: Timestamp,
    /// Environment creator Principal identity (UUIDv7).
    pub environment_created_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_created_by_actor_context_digest: ContentDigest,
    pub environment_creation_authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_creation_record_digest: ContentDigest,
    /// Application idempotency key (UUIDv7).
    pub idempotency_key: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    /// Activating `environment.activator` Principal identity (UUIDv7).
    pub activated_by_principal_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub activated_by_actor_context_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub activator_role_assignment_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub activated_at: Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Immutable assembled Environment configuration closure
/// (schema `environmentConfigV2`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentConfigV2 {
    pub api_version: EnvironmentConfigApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Environment identifier.
    pub environment_id: String,
    pub environment_config_version: u32,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    pub predecessor_config_version: Option<u32>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub predecessor_config_digest: Option<ContentDigest>,
    pub normalized_configuration: NormalizedEnvironmentConfigurationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_configuration_digest: ContentDigest,
    pub environment_creation: EnvironmentCreationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_creation_record_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_creation_record_envelope_digest: ContentDigest,
    pub proposal: EnvironmentConfigProposalV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposal_record_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub proposal_record_envelope_digest: ContentDigest,
    pub activation: EnvironmentConfigActivationV1,
    #[serde(with = "crate::serde_support::display_string")]
    pub activation_record_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub activation_record_envelope_digest: ContentDigest,
}

/// Cross-checks an assembled [`EnvironmentConfigV2`] closure.
///
/// Enforces Workspace/Environment agreement across creation, proposal, and
/// activation; positive chronology; exact predecessor version/digest equality;
/// proposal payload-digest equality with the activation's `proposal_digest`;
/// copied creation fields matching the embedded creation record; and distinct
/// proposer and activator.
///
/// # Errors
///
/// Returns [`RemoteError::Governance`] on any cross-check violation.
#[allow(clippy::too_many_lines)]
pub fn validate_environment_config_v2(config: &EnvironmentConfigV2) -> Result<(), RemoteError> {
    let creation = &config.environment_creation;
    let proposal = &config.proposal;
    let activation = &config.activation;

    // Workspace identity must agree across the closure and all three records.
    if config.workspace_id != creation.workspace_id
        || config.workspace_id != proposal.workspace_id
        || config.workspace_id != activation.workspace_id
    {
        return Err(RemoteError::Governance(
            "Workspace identity disagrees across the configuration closure".to_owned(),
        ));
    }

    // Environment identity must agree across the closure and all three records.
    if config.environment_id != creation.environment_id
        || config.environment_id != proposal.environment_id
        || config.environment_id != activation.environment_id
    {
        return Err(RemoteError::Governance(
            "Environment identity disagrees across the configuration closure".to_owned(),
        ));
    }

    // Positive chronology: creation precedes proposal, which precedes
    // activation, both in recorded time and in authority sequence.
    if creation.created_at > proposal.proposed_at || proposal.proposed_at > activation.activated_at
    {
        return Err(RemoteError::Governance(
            "configuration chronology is out of order".to_owned(),
        ));
    }
    if creation.authority_sequence >= proposal.authority_sequence
        || proposal.authority_sequence >= activation.authority_sequence
    {
        return Err(RemoteError::Governance(
            "configuration authority sequences are not chronologically ordered".to_owned(),
        ));
    }

    // The closure's positive configuration version must equal the activation's.
    if config.environment_config_version == 0 {
        return Err(RemoteError::Governance(
            "environment configuration version must be positive".to_owned(),
        ));
    }
    if config.environment_config_version != activation.environment_config_version {
        return Err(RemoteError::Governance(
            "environment configuration version disagrees with the activation".to_owned(),
        ));
    }

    // Exact expected predecessor version/digest equality across the closure,
    // the proposal, and the activation.
    if config.predecessor_config_version != proposal.expected_predecessor_config_version
        || config.predecessor_config_version != activation.predecessor_config_version
    {
        return Err(RemoteError::Governance(
            "predecessor configuration version disagrees across the closure".to_owned(),
        ));
    }
    if config.predecessor_config_digest != proposal.expected_predecessor_config_digest
        || config.predecessor_config_digest != activation.predecessor_config_digest
    {
        return Err(RemoteError::Governance(
            "predecessor configuration digest disagrees across the closure".to_owned(),
        ));
    }

    // The assembled normalized configuration must equal the proposal's and its
    // digest must agree across the proposal and the activation.
    if config.normalized_configuration != proposal.normalized_configuration {
        return Err(RemoteError::Governance(
            "normalized configuration disagrees with the proposal".to_owned(),
        ));
    }
    if config.normalized_configuration_digest != proposal.normalized_configuration_digest
        || config.normalized_configuration_digest != activation.normalized_configuration_digest
    {
        return Err(RemoteError::Governance(
            "normalized configuration digest disagrees across the closure".to_owned(),
        ));
    }

    // Both environment_config_digest and normalized_configuration_digest are the
    // RFC 8785 / BLAKE3-256 digest of the normalized configuration under
    // `proof:environment-config:v2`.
    let computed_config_digest = canonical_derive_key_digest(
        ENVIRONMENT_CONFIG_DIGEST_CONTEXT,
        &config.normalized_configuration,
    )?;
    if config.normalized_configuration_digest != computed_config_digest
        || config.environment_config_digest != computed_config_digest
        || config.environment_config_digest != config.normalized_configuration_digest
    {
        return Err(RemoteError::Governance(
            "environment configuration digest does not match the normalized configuration digest under proof:environment-config:v2"
                .to_owned(),
        ));
    }
    if config.environment_config_digest != activation.environment_config_digest {
        return Err(RemoteError::Governance(
            "environment configuration digest disagrees with the activation".to_owned(),
        ));
    }

    // The activation must reference the exact embedded proposal identity and
    // payload digest.
    if activation.proposal_id != proposal.proposal_id {
        return Err(RemoteError::Governance(
            "activation references a different proposal identity".to_owned(),
        ));
    }
    if config.proposal_record_digest != activation.proposal_digest {
        return Err(RemoteError::Governance(
            "proposal record digest disagrees with the activation proposal digest".to_owned(),
        ));
    }

    // The creation payload digest must equal both the activation's copied
    // creation digest and the recomputed digest of the embedded creation record.
    if config.environment_creation_record_digest != activation.environment_creation_record_digest {
        return Err(RemoteError::Governance(
            "environment creation record digest disagrees with the activation".to_owned(),
        ));
    }
    let computed_creation_digest =
        canonical_derive_key_digest(REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT, creation)?;
    if config.environment_creation_record_digest != computed_creation_digest {
        return Err(RemoteError::Governance(
            "environment creation record digest does not match the decoded creation record"
                .to_owned(),
        ));
    }

    // Every creation field copied into the activation must match the embedded
    // creation record.
    if activation.environment_created_at != creation.created_at
        || activation.environment_created_by_principal_id != creation.created_by_principal_id
        || activation.environment_created_by_actor_context_digest
            != creation.created_by_actor_context_digest
        || activation.environment_creation_authority_sequence != creation.authority_sequence
    {
        return Err(RemoteError::Governance(
            "activation copied creation fields disagree with the creation record".to_owned(),
        ));
    }

    // The proposer and activator must be distinct enabled Humans.
    if proposal.proposed_by_principal_id == activation.activated_by_principal_id {
        return Err(RemoteError::Governance(
            "proposer and activator must be distinct Humans".to_owned(),
        ));
    }

    Ok(())
}

/// Computes a domain-separated BLAKE3-256 digest over the strict RFC 8785
/// canonical bytes of a typed remote payload.
///
/// # Errors
///
/// Returns [`RemoteError::Canonical`] when the value cannot be serialized or
/// canonicalized under the RFC 8785 profile.
fn canonical_derive_key_digest<T: Serialize>(
    context: &str,
    value: &T,
) -> Result<ContentDigest, RemoteError> {
    let json =
        serde_json::to_value(value).map_err(|error| RemoteError::Canonical(error.to_string()))?;
    let canonical = proof_canonical::canonicalize(&json)
        .map_err(|error| RemoteError::Canonical(error.to_string()))?;
    Ok(derive_key_digest(context, canonical.as_bytes()))
}
