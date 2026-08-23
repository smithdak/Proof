//! Causal approval and Environment-configuration governance facts.
//!
//! This module implements the complete type surface for `ChangeSetApprovalV1`
//! and the Environment creation/proposal/activation records plus the assembled
//! immutable [`EnvironmentConfigV2`] closure (contract §"Causal approval and
//! release recheck", §"Environment and policy administration").

use proof_domain::{ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{AuthorityHeadV1, RemoteError};

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
        todo!()
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
pub fn validate_environment_config_v2(config: &EnvironmentConfigV2) -> Result<(), RemoteError> {
    todo!()
}
