//! Closed operation registries, remote authorization decision/consequence
//! types, and the exact digest preimage builders.
//!
//! This module implements the complete type surface for the 23-row Human
//! registry, the 14-pair Agent projection, the nine-route HTTP surface, the
//! `RemoteAuthorizationDecisionV1` and `RemoteApplicationConsequenceV1`
//! authority payloads, and the closed digest preimages under
//! `proof:authorization-resource-binding:v1`,
//! `proof:requested-authorization-resources:v1`,
//! `proof:remote-authorization-policy-selection:v1`, and
//! `proof:operation-effect:v1` (contract §"HTTP boundary",
//! §"Human and control operation registry").

use proof_domain::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{AuthorityHeadV1, RemoteError, RemoteOperationV1, authority::WorkspaceRole};

/// Accepted Agent authority registry SHA-256. Must be recomputed byte-exactly
/// from the retained registry vectors; fail closed on any mismatch.
pub const AGENT_AUTHORITY_REGISTRY_SHA256: &str =
    "b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7";
/// Non-circular remote authorization projection SHA-256. Must be recomputed
/// byte-exactly from the retained registry vectors; fail closed on any mismatch.
pub const REMOTE_AUTHORIZATION_PROJECTION_SHA256: &str =
    "e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b";
/// Complete HTTP operation registry SHA-256. Must be recomputed byte-exactly
/// from the retained registry vectors; fail closed on any mismatch.
pub const COMPLETE_HTTP_OPERATION_REGISTRY_SHA256: &str =
    "e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf";

/// BLAKE3-256 derive-key context for one authorization resource binding.
pub const AUTHORIZATION_RESOURCE_BINDING_DIGEST_CONTEXT: &str =
    "proof:authorization-resource-binding:v1";
/// BLAKE3-256 derive-key context for requested authorization resources.
pub const REQUESTED_AUTHORIZATION_RESOURCES_DIGEST_CONTEXT: &str =
    "proof:requested-authorization-resources:v1";
/// BLAKE3-256 derive-key context for authorization policy selection.
pub const REMOTE_AUTHORIZATION_POLICY_SELECTION_DIGEST_CONTEXT: &str =
    "proof:remote-authorization-policy-selection:v1";
/// BLAKE3-256 derive-key context for operation effects and application problems.
pub const OPERATION_EFFECT_DIGEST_CONTEXT: &str = "proof:operation-effect:v1";
/// BLAKE3-256 derive-key context for an immutable delivery-management fact.
pub const DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT: &str = "proof:delivery-management-fact:v1";

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
    AuthorizationResourceBindingApiVersion,
    "proof.dev/authorization-resource-binding/v1"
);
api_version!(
    RequestedAuthorizationResourcesApiVersion,
    "proof.dev/requested-authorization-resources/v1"
);
api_version!(
    RemoteAuthorizationPolicySelectionApiVersion,
    "proof.dev/remote-authorization-policy-selection/v1"
);
api_version!(
    ApplicationProblemDigestPreimageApiVersion,
    "proof.dev/application-problem-digest-preimage/v1"
);
api_version!(
    RemoteAuthorizationDecisionApiVersion,
    "proof.dev/remote-authorization-decision/v1"
);
api_version!(
    RemoteApplicationConsequenceApiVersion,
    "proof.dev/remote-application-consequence/v1"
);

/// Closed decision outcome (`allow`/`deny`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecisionKind {
    Allow,
    Deny,
}

/// Closed application consequence outcome classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationConsequenceOutcome {
    Success,
    IdempotentReplay,
    IdempotencyConflict,
    PreconditionConflict,
    ApplicationFailure,
}

/// Closed application idempotency key kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationKeyKind {
    DerivedChangeset,
    DerivedProposalPolicyValidator,
    None,
    RequiredUuidV7,
}

/// Closed delegation-resolution result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationResolutionV1 {
    NotFoundOrHidden,
    Resolved,
}

/// Exact operating Agent binding evaluation (schema `operatingBindingEvaluation`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingBindingEvaluationV1 {
    pub active: bool,
    /// Binding identity (UUIDv7).
    pub binding_id: String,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub record_digest: ContentDigest,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub revocation_record_digest: Option<ContentDigest>,
}

/// Exact Delegation resolution at the evaluated head (schema `delegationEvaluation`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEvaluationV1 {
    /// Delegation identity (UUIDv7).
    pub delegation_id: String,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub record_digest: Option<ContentDigest>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub revocation_record_digest: Option<ContentDigest>,
    pub resolution: DelegationResolutionV1,
}

/// Requesting/operating Principal status captured by a decision
/// (schema `principalState`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalStateV1 {
    pub requesting_principal_enabled: bool,
    pub operating_principal_enabled: bool,
}

/// Exact effective CAP numeric constraint closure
/// (schema `effectiveConstraints`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveConstraintsV1 {
    pub max_objects: u32,
    pub max_context_bytes: u32,
    pub max_edits_per_changeset: u32,
}

/// Exact accepted `AuthorizationDecisionV2` requested-resources projection
/// (schema `requestedResources`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedResourcesV1 {
    pub workspace_ids: Vec<String>,
    pub environment_ids: Vec<String>,
    pub object_ids: Vec<String>,
    pub schema_ids: Vec<String>,
    pub locales: Vec<String>,
    pub changeset_ids: Vec<String>,
    pub edition_ids: Vec<String>,
    pub release_ids: Vec<String>,
}

/// Closed Agent-only authorization closure (schema `agentAuthorization`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAuthorizationV1 {
    #[serde(with = "crate::serde_support::display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub command_envelope_digest: ContentDigest,
    /// Single-use presentation identity (UUIDv7).
    pub presentation_id: String,
    pub presentation_consumed: bool,
    /// Operating Agent Principal identity (UUIDv7).
    pub operating_principal_id: String,
    pub principal_state: PrincipalStateV1,
    pub binding: OperatingBindingEvaluationV1,
    pub delegation: DelegationEvaluationV1,
    pub policy_profile: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub policy_bundle_digest: ContentDigest,
    pub requested_resources: RequestedResourcesV1,
    pub effective_constraints: EffectiveConstraintsV1,
}

/// Server-produced current-head authorization decision
/// (schema `remoteAuthorizationDecisionV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAuthorizationDecisionV1 {
    pub api_version: RemoteAuthorizationDecisionApiVersion,
    pub authentication_profile: String,
    pub authorization_registry_sha256: String,
    pub operation_registry_sha256: String,
    pub authorization_rule: String,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Decision identity (UUIDv7).
    pub decision_id: String,
    pub operation: RemoteOperationV1,
    pub requested_action: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub public_input_projection_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub actor_context_digest: ContentDigest,
    /// Requesting Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Requesting binding identity (UUIDv7).
    pub requesting_binding_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_binding_record_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub requesting_subject_commitment: ContentDigest,
    pub agent_authorization: Option<AgentAuthorizationV1>,
    #[serde(with = "crate::serde_support::display_string_vec")]
    pub role_assignment_digests: Vec<ContentDigest>,
    #[serde(with = "crate::serde_support::display_string")]
    pub requested_resources_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub policy_bundle_digest: ContentDigest,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub environment_config_digest: Option<ContentDigest>,
    pub decision: AuthorizationDecisionKind,
    pub public_code: Option<String>,
    pub reason_code: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub evaluated_at: proof_domain::Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Signed consequence of one committed authorized attempt
/// (schema `remoteApplicationConsequenceV1`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApplicationConsequenceV1 {
    pub api_version: RemoteApplicationConsequenceApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Consequence identity (UUIDv7).
    pub consequence_id: String,
    /// Governing decision identity (UUIDv7).
    pub decision_id: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub decision_digest: ContentDigest,
    #[serde(with = "crate::serde_support::display_string")]
    pub public_input_projection_digest: ContentDigest,
    pub operation: RemoteOperationV1,
    pub operation_registry_sha256: String,
    pub outcome: ApplicationConsequenceOutcome,
    pub application_key_kind: ApplicationKeyKind,
    /// UUIDv7 application key, derived digest key, or `null`.
    pub application_key: Option<String>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub result_digest: Option<ContentDigest>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub prior_result_digest: Option<ContentDigest>,
    #[serde(with = "crate::serde_support::optional_display_string")]
    pub application_effect_digest: Option<ContentDigest>,
    pub application_effect_authority_head: Option<AuthorityHeadV1>,
    pub problem_code: Option<String>,
    #[serde(with = "crate::serde_support::display_string")]
    pub recorded_at: proof_domain::Timestamp,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_sequence: u64,
    #[serde(with = "crate::serde_support::display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub authority_key_id: String,
}

/// Closed row-specific effect-digest rule (contract §"Human and control
/// operation registry").
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectDigestRule {
    None,
    RemoteAuthorityRecord,
    ContentResourceIntent,
    EvidenceCapture,
    DeliveryManagementFact,
    LocalizedEffect,
}

/// Closed authority-payload timestamp field selected for effect ordering.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectTimestampField {
    IssuedAt,
    RevokedAt,
    ApprovedAt,
    ProposedAt,
    ActivatedAt,
    RecordedAt,
    AssignedAt,
}

/// One ordered Human operation registry row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanOperationRowV1 {
    pub operation: RemoteOperationV1,
    pub status: String,
    pub authentication: String,
    pub idempotency: String,
    pub concurrency_anchor: String,
    pub authorization_rule: String,
    /// Sorted `roles_any_of` set (contract §"Human and control operation registry").
    pub roles_any_of: Vec<WorkspaceRole>,
    pub effect_digest_rule: EffectDigestRule,
    pub effect_timestamp_field: Option<EffectTimestampField>,
    pub application_problem_codes: Vec<String>,
}

/// The ordered 23-row Human RPC registry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HumanOperationRegistryV1;

impl HumanOperationRegistryV1 {
    /// Returns the exact ordered 23 rows.
    #[must_use]
    pub fn rows(&self) -> &'static [HumanOperationRowV1] {
        todo!()
    }

    /// Route-qualified lookup by exact `(name, version)`.
    #[must_use]
    pub fn lookup(&self, name: &str, version: &str) -> Option<&'static HumanOperationRowV1> {
        todo!()
    }
}

/// One Agent operation-projection pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOperationRowV1 {
    pub operation: RemoteOperationV1,
    pub requested_action: String,
    pub authorization_rule: String,
    pub effect_digest_rule: EffectDigestRule,
    pub effect_timestamp_field: Option<EffectTimestampField>,
    pub application_problem_codes: Vec<String>,
}

/// The accepted 14-pair Agent operation projection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentOperationProjectionV1;

impl AgentOperationProjectionV1 {
    /// Returns the exact accepted 14 pairs.
    #[must_use]
    pub fn rows(&self) -> &'static [AgentOperationRowV1] {
        todo!()
    }

    /// Route-qualified lookup by exact `(name, version)`.
    #[must_use]
    pub fn lookup(&self, name: &str, version: &str) -> Option<&'static AgentOperationRowV1> {
        todo!()
    }
}

/// One of the exact nine first-profile HTTP routes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpRouteV1 {
    OidcLogin,
    OidcCallback,
    Session,
    SessionLogout,
    Capabilities,
    HumanOperations,
    AgentOperations,
    EvidenceArtifact,
    PreviewObject,
}

impl HttpRouteV1 {
    /// The exact nine-route surface.
    pub const ALL: [HttpRouteV1; 9] = [
        HttpRouteV1::OidcLogin,
        HttpRouteV1::OidcCallback,
        HttpRouteV1::Session,
        HttpRouteV1::SessionLogout,
        HttpRouteV1::Capabilities,
        HttpRouteV1::HumanOperations,
        HttpRouteV1::AgentOperations,
        HttpRouteV1::EvidenceArtifact,
        HttpRouteV1::PreviewObject,
    ];

    /// Returns the exact HTTP method for this route.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::OidcLogin
            | Self::OidcCallback
            | Self::Session
            | Self::Capabilities
            | Self::EvidenceArtifact
            | Self::PreviewObject => "GET",
            Self::SessionLogout | Self::HumanOperations | Self::AgentOperations => "POST",
        }
    }

    /// Returns the exact path template for this route.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::OidcLogin => "/auth/oidc/login",
            Self::OidcCallback => "/auth/oidc/callback",
            Self::Session => "/api/v1/session",
            Self::SessionLogout => "/api/v1/session/logout",
            Self::Capabilities => "/api/v1/capabilities",
            Self::HumanOperations => "/api/v1/human/operations/{name}/{major}",
            Self::AgentOperations => "/api/v1/agent/operations/{name}/{major}",
            Self::EvidenceArtifact => {
                "/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}"
            }
            Self::PreviewObject => {
                "/preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}"
            }
        }
    }
}

/// One named resource binding with a structured value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResourceBindingV1 {
    pub api_version: AuthorizationResourceBindingApiVersion,
    pub name: String,
    pub value: Value,
}

/// One name-sorted requested-resource binding `{name, value_digest}`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedAuthorizationResourceBindingV1 {
    pub name: String,
    #[serde(with = "crate::serde_support::display_string")]
    pub value_digest: ContentDigest,
}

/// Computes `proof:authorization-resource-binding:v1` over
/// `{api_version, name, value}`.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the preimage cannot be canonicalized.
pub fn authorization_resource_binding_digest(
    name: &str,
    value: &Value,
) -> Result<ContentDigest, RemoteError> {
    todo!()
}

/// Computes `proof:requested-authorization-resources:v1` over the exact
/// `{api_version, authorization_registry_sha256, authorization_rule, operation,
/// requested_action, bindings}` preimage, where `bindings` is the
/// UTF-8-name-sorted `{name, value_digest}` array.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the preimage cannot be canonicalized.
pub fn requested_authorization_resources_digest(
    authorization_registry_sha256: &str,
    authorization_rule: &str,
    operation: &RemoteOperationV1,
    requested_action: &str,
    bindings: &[RequestedAuthorizationResourceBindingV1],
) -> Result<ContentDigest, RemoteError> {
    todo!()
}

/// Computes `proof:remote-authorization-policy-selection:v1` over
/// `{api_version, authorization_registry_sha256, authorization_rule,
/// environment_config_digest, environment_policy_bundle_digest}`.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the preimage cannot be canonicalized.
pub fn remote_authorization_policy_selection_digest(
    authorization_registry_sha256: &str,
    authorization_rule: &str,
    environment_config_digest: Option<ContentDigest>,
    environment_policy_bundle_digest: Option<ContentDigest>,
) -> Result<ContentDigest, RemoteError> {
    todo!()
}

/// Computes `proof:operation-effect:v1` over the exact row result.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the result cannot be canonicalized.
pub fn operation_effect_digest(result: &Value) -> Result<ContentDigest, RemoteError> {
    todo!()
}

/// Computes the application-problem digest under `proof:operation-effect:v1`
/// over `{api_version, code, operation}`.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the preimage cannot be canonicalized.
pub fn application_problem_digest_preimage(
    code: &str,
    operation: &RemoteOperationV1,
) -> Result<ContentDigest, RemoteError> {
    todo!()
}
