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

use std::sync::LazyLock;

use proof_domain::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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
    /// Wire spelling is `required-uuidv7` (not kebab-case `required-uuid-v7`);
    /// see `collaboration-artifacts-v1.schema.json` §"application key kind".
    #[serde(rename = "required-uuidv7")]
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
        HUMAN_ROWS.as_slice()
    }

    /// Route-qualified lookup by exact `(name, version)`.
    #[must_use]
    pub fn lookup(&self, name: &str, version: &str) -> Option<&'static HumanOperationRowV1> {
        HUMAN_ROWS
            .iter()
            .find(|row| row.operation.name == name && row.operation.version == version)
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
        AGENT_ROWS.as_slice()
    }

    /// Route-qualified lookup by exact `(name, version)`.
    #[must_use]
    pub fn lookup(&self, name: &str, version: &str) -> Option<&'static AgentOperationRowV1> {
        AGENT_ROWS
            .iter()
            .find(|row| row.operation.name == name && row.operation.version == version)
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
    let preimage = json!({
        "api_version": "proof.dev/authorization-resource-binding/v1",
        "name": name,
        "value": value,
    });
    derive_key_digest_of(AUTHORIZATION_RESOURCE_BINDING_DIGEST_CONTEXT, &preimage)
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
    let mut sorted = bindings.to_vec();
    sorted.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    let bindings = sorted
        .iter()
        .map(|binding| {
            json!({
                "name": binding.name,
                "value_digest": binding.value_digest.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let preimage = json!({
        "api_version": "proof.dev/requested-authorization-resources/v1",
        "authorization_registry_sha256": authorization_registry_sha256,
        "authorization_rule": authorization_rule,
        "operation": operation,
        "requested_action": requested_action,
        "bindings": bindings,
    });
    derive_key_digest_of(REQUESTED_AUTHORIZATION_RESOURCES_DIGEST_CONTEXT, &preimage)
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
    let preimage = json!({
        "api_version": "proof.dev/remote-authorization-policy-selection/v1",
        "authorization_registry_sha256": authorization_registry_sha256,
        "authorization_rule": authorization_rule,
        "environment_config_digest": environment_config_digest.map(|digest| digest.to_string()),
        "environment_policy_bundle_digest":
            environment_policy_bundle_digest.map(|digest| digest.to_string()),
    });
    derive_key_digest_of(
        REMOTE_AUTHORIZATION_POLICY_SELECTION_DIGEST_CONTEXT,
        &preimage,
    )
}

/// Computes `proof:operation-effect:v1` over the exact row result.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the result cannot be canonicalized.
pub fn operation_effect_digest(result: &Value) -> Result<ContentDigest, RemoteError> {
    derive_key_digest_of(OPERATION_EFFECT_DIGEST_CONTEXT, result)
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
    let preimage = json!({
        "api_version": "proof.dev/application-problem-digest-preimage/v1",
        "code": code,
        "operation": operation,
    });
    derive_key_digest_of(OPERATION_EFFECT_DIGEST_CONTEXT, &preimage)
}

// ---------------------------------------------------------------------------
// Closed registry data
// ---------------------------------------------------------------------------

const HUMAN_AUTHENTICATION_PROFILE: &str = "proof.server/authentication/oidc-human/v1";
const AGENT_DIRECT_AUTHORIZATION_RULE: &str = "proof.local/authority/direct/v1";

/// The 17 exact post-Allow application Problem codes shared by every localized
/// v2 Agent row (contract §"Agent registry projection").
const LOCALIZED_V2_PROBLEM_CODES: [&str; 17] = [
    "proof.changeset.duplicate_target",
    "proof.changeset.invalid_supersession",
    "proof.changeset.not_approved",
    "proof.changeset.not_draft",
    "proof.changeset.not_ready",
    "proof.changeset.not_submitted",
    "proof.evidence.incomplete",
    "proof.input.intent_mismatch",
    "proof.input.limit_exceeded",
    "proof.input.schema_mismatch",
    "proof.input.unsupported_version",
    "proof.policy.denied",
    "proof.resource.not_found",
    "proof.state.conflict",
    "proof.state.source_conflict",
    "proof.state.target_conflict",
    "proof.validation.repair_evidence_invalid",
];

fn operation(name: &str, version: &str) -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn roles(values: &[WorkspaceRole]) -> Vec<WorkspaceRole> {
    values.to_vec()
}

static HUMAN_ROWS: LazyLock<Vec<HumanOperationRowV1>> = LazyLock::new(|| {
    use WorkspaceRole::{
        AuthorityAdmin, ContentPublisher, ContentRequester, ContentReviewer, EnvironmentActivator,
        EnvironmentAdmin, EvidenceAuditor, IdentityAdmin,
    };

    vec![
        HumanOperationRowV1 {
            operation: operation(
                "agent-binding.issue",
                "proof.dev/operation/agent-binding.issue/v1",
            ),
            status: "Reused artifact, remote decision successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/agent-binding-admin/v1".to_owned(),
            roles_any_of: roles(&[AuthorityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::IssuedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "agent-binding.revoke",
                "proof.dev/operation/agent-binding.revoke/v1",
            ),
            status: "Reused artifact, remote decision successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/agent-binding-admin/v1".to_owned(),
            roles_any_of: roles(&[AuthorityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::RevokedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "content-resource-intent.issue",
                "proof.dev/operation/content-resource-intent.issue/v1",
            ),
            status: "Reused".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/resource-intent-requester/v1"
                .to_owned(),
            roles_any_of: roles(&[ContentRequester]),
            effect_digest_rule: EffectDigestRule::ContentResourceIntent,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("context.build", "proof.dev/operation/context.build/v2"),
            status: "Reused".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-artifact-digest".to_owned(),
            authorization_rule: "proof.server/authorization/initial-context-requester/v1"
                .to_owned(),
            roles_any_of: roles(&[ContentRequester]),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.evidence.incomplete",
                "proof.input.limit_exceeded",
                "proof.input.unsupported_version",
                "proof.policy.denied",
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("changeset.get", "proof.dev/operation/changeset.get/v2"),
            status: "Reused".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "exact-changeset-and-authority".to_owned(),
            authorization_rule: "proof.server/authorization/changeset-closure-reader/v1".to_owned(),
            roles_any_of: roles(&[ContentPublisher, ContentRequester, ContentReviewer]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.input.unsupported_version",
                "proof.resource.not_found",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
            status: "Reused".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "exact-changeset-and-authority".to_owned(),
            authorization_rule: "proof.server/authorization/changeset-closure-reader/v1".to_owned(),
            roles_any_of: roles(&[ContentPublisher, ContentRequester, ContentReviewer]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.input.unsupported_version",
                "proof.resource.not_found",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v3",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-changeset-and-authority".to_owned(),
            authorization_rule: "proof.server/authorization/changeset-distinct-reviewer/v1"
                .to_owned(),
            roles_any_of: roles(&[ContentReviewer]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::ApprovedAt),
            application_problem_codes: strings(&[
                "proof.changeset.not_submitted",
                "proof.evidence.incomplete",
                "proof.policy.denied",
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "delegation.issue",
                "proof.dev/operation/delegation.issue/v2",
            ),
            status: "Reused artifact, remote decision successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/delegation-requester/v1".to_owned(),
            roles_any_of: roles(&[ContentRequester]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::IssuedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "delegation.revoke",
                "proof.dev/operation/delegation.revoke/v1",
            ),
            status: "Reused artifact, remote decision successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule:
                "proof.server/authorization/delegation-issuer-or-authority-admin/v1".to_owned(),
            roles_any_of: roles(&[AuthorityAdmin, ContentRequester]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::RevokedAt),
            application_problem_codes: strings(&[
                "proof.authorization.delegation_revoked",
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("delivery.get", "proof.dev/operation/delivery.get/v1"),
            status: "Successor transport projection".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "exact-delivery-generation".to_owned(),
            authorization_rule: "proof.server/authorization/delivery-reader/v1".to_owned(),
            roles_any_of: roles(&[ContentPublisher, EnvironmentAdmin, EvidenceAuditor]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("delivery.replay", "proof.dev/operation/delivery.replay/v1"),
            status: "Successor immutable application fact".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-delivery-generation".to_owned(),
            authorization_rule: "proof.server/authorization/delivery-dead-letter-replay-admin/v1"
                .to_owned(),
            roles_any_of: roles(&[EnvironmentAdmin]),
            effect_digest_rule: EffectDigestRule::DeliveryManagementFact,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "delivery.abandon",
                "proof.dev/operation/delivery.abandon/v1",
            ),
            status: "Successor immutable application fact".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-delivery-generation".to_owned(),
            authorization_rule: "proof.server/authorization/delivery-poison-abandon-activator/v1"
                .to_owned(),
            roles_any_of: roles(&[EnvironmentActivator]),
            effect_digest_rule: EffectDigestRule::DeliveryManagementFact,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "environment-config.propose",
                "proof.dev/operation/environment-config.propose/v2",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-config-predecessor-and-authority".to_owned(),
            authorization_rule: "proof.server/authorization/environment-config-proposer/v1"
                .to_owned(),
            roles_any_of: roles(&[EnvironmentAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::ProposedAt),
            application_problem_codes: strings(&[
                "proof.state.conflict",
                "proof.validation.failed",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "environment-config.activate",
                "proof.dev/operation/environment-config.activate/v2",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-config-predecessor-and-authority".to_owned(),
            authorization_rule:
                "proof.server/authorization/environment-config-distinct-activator/v1".to_owned(),
            roles_any_of: roles(&[EnvironmentActivator]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::ActivatedAt),
            application_problem_codes: strings(&[
                "proof.policy.denied",
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("evidence.export", "proof.dev/operation/evidence.export/v2"),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-release".to_owned(),
            authorization_rule: "proof.server/authorization/evidence-export-reader/v1".to_owned(),
            roles_any_of: roles(&[ContentPublisher, EvidenceAuditor]),
            effect_digest_rule: EffectDigestRule::EvidenceCapture,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.evidence.incomplete",
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "evidence.export.get",
                "proof.dev/operation/evidence.export.get/v1",
            ),
            status: "Successor lifecycle projection".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "none".to_owned(),
            authorization_rule: "proof.server/authorization/evidence-export-reader/v1".to_owned(),
            roles_any_of: roles(&[ContentPublisher, EvidenceAuditor]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&["proof.resource.not_found"]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "oidc-binding.issue",
                "proof.dev/operation/oidc-binding.issue/v1",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/oidc-binding-admin/v1".to_owned(),
            roles_any_of: roles(&[IdentityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::IssuedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "oidc-binding.revoke",
                "proof.dev/operation/oidc-binding.revoke/v1",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/oidc-binding-admin/v1".to_owned(),
            roles_any_of: roles(&[IdentityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::RevokedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "principal.status.set",
                "proof.dev/operation/principal.status.set/v2",
            ),
            status: "Successor remote authority fact".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/principal-disable-admin/v1".to_owned(),
            roles_any_of: roles(&[IdentityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::RecordedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation("release.get", "proof.dev/operation/release.get/v2"),
            status: "Successor transport projection".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "exact-release".to_owned(),
            authorization_rule: "proof.server/authorization/release-reader/v1".to_owned(),
            roles_any_of: roles(&[
                ContentPublisher,
                ContentRequester,
                ContentReviewer,
                EvidenceAuditor,
            ]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&["proof.resource.not_found"]),
        },
        HumanOperationRowV1 {
            operation: operation("release.verify", "proof.dev/operation/release.verify/v2"),
            status: "Successor remote evidence".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "none".to_owned(),
            concurrency_anchor: "exact-release".to_owned(),
            authorization_rule: "proof.server/authorization/release-reader/v1".to_owned(),
            roles_any_of: roles(&[
                ContentPublisher,
                ContentRequester,
                ContentReviewer,
                EvidenceAuditor,
            ]),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.digest.mismatch",
                "proof.evidence.incomplete",
                "proof.resource.not_found",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "workspace-role.assign",
                "proof.dev/operation/workspace-role.assign/v1",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/workspace-role-admin/v1".to_owned(),
            roles_any_of: roles(&[IdentityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::AssignedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
        HumanOperationRowV1 {
            operation: operation(
                "workspace-role.revoke",
                "proof.dev/operation/workspace-role.revoke/v1",
            ),
            status: "Successor".to_owned(),
            authentication: HUMAN_AUTHENTICATION_PROFILE.to_owned(),
            idempotency: "required-uuidv7".to_owned(),
            concurrency_anchor: "exact-authority-head".to_owned(),
            authorization_rule: "proof.server/authorization/workspace-role-admin/v1".to_owned(),
            roles_any_of: roles(&[IdentityAdmin]),
            effect_digest_rule: EffectDigestRule::RemoteAuthorityRecord,
            effect_timestamp_field: Some(EffectTimestampField::RevokedAt),
            application_problem_codes: strings(&[
                "proof.resource.not_found",
                "proof.state.conflict",
            ]),
        },
    ]
});

static AGENT_ROWS: LazyLock<Vec<AgentOperationRowV1>> = LazyLock::new(|| {
    vec![
        AgentOperationRowV1 {
            operation: operation("changeset.add", "proof.dev/operation/changeset.add/v2"),
            requested_action: "changeset:add".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "changeset.commit",
                "proof.dev/operation/changeset.commit/v2",
            ),
            requested_action: "changeset:commit".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "changeset.create",
                "proof.dev/operation/changeset.create/v2",
            ),
            requested_action: "changeset:create".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
            requested_action: "changeset:diff".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation("changeset.get", "proof.dev/operation/changeset.get/v2"),
            requested_action: "changeset:get".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "changeset.submit",
                "proof.dev/operation/changeset.submit/v2",
            ),
            requested_action: "changeset:submit".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "changeset.validate",
                "proof.dev/operation/changeset.validate/v2",
            ),
            requested_action: "changeset:validate".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation("context.build", "proof.dev/operation/context.build/v1"),
            requested_action: "context:build".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.auth.denied",
                "proof.delegation.expired",
                "proof.input.too_large",
                "proof.resource.not_found",
            ]),
        },
        AgentOperationRowV1 {
            operation: operation("context.build", "proof.dev/operation/context.build/v2"),
            requested_action: "context:build".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation("edition.create", "proof.dev/operation/edition.create/v2"),
            requested_action: "edition:create".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "object.query_released",
                "proof.dev/operation/object.query_released/v1",
            ),
            requested_action: "object:query_released".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&[
                "proof.input.unsupported_version",
                "proof.resource.not_found",
            ]),
        },
        AgentOperationRowV1 {
            operation: operation(
                "object.query_released",
                "proof.dev/operation/object.query_released/v2",
            ),
            requested_action: "object:query_released".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation("release.create", "proof.dev/operation/release.create/v2"),
            requested_action: "release:create".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::LocalizedEffect,
            effect_timestamp_field: None,
            application_problem_codes: strings(&LOCALIZED_V2_PROBLEM_CODES),
        },
        AgentOperationRowV1 {
            operation: operation(
                "workspace.status",
                "proof.dev/operation/workspace.status/v1",
            ),
            requested_action: "workspace:status".to_owned(),
            authorization_rule: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            effect_digest_rule: EffectDigestRule::None,
            effect_timestamp_field: None,
            application_problem_codes: Vec::new(),
        },
    ]
});

// ---------------------------------------------------------------------------
// Digest primitives
// ---------------------------------------------------------------------------

fn derive_key_digest_of(context: &str, value: &Value) -> Result<ContentDigest, RemoteError> {
    let canonical = proof_canonical::canonicalize(value).map_err(|error| {
        RemoteError::Registry(format!(
            "preimage RFC 8785 canonicalization failed: {error}"
        ))
    })?;
    Ok(crate::derive_key_digest(context, canonical.as_bytes()))
}

// ---------------------------------------------------------------------------
// Frozen-hash recomputation (RFC 8785 + SHA-256)
// ---------------------------------------------------------------------------

/// SHA-256 round constants, kept local so the crate needs no third-party hash
/// dependency beyond the workspace-pinned primitives.
#[allow(clippy::unreadable_literal)]
const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[allow(clippy::many_single_char_names, clippy::unreadable_literal)]
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64)
        .checked_mul(8)
        .expect("SHA-256 input length must fit u64 bits");
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(big_s1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = big_s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

/// Canonicalizes a JSON value under RFC 8785 and returns its lowercase SHA-256
/// hex digest. This mirrors the retained P-0008 recomputation harness.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the value cannot be canonicalized.
pub fn canonical_sha256_hex(value: &Value) -> Result<String, RemoteError> {
    let canonical = proof_canonical::canonicalize(value).map_err(|error| {
        RemoteError::Registry(format!("RFC 8785 canonicalization failed: {error}"))
    })?;
    Ok(hex_lower(&sha256(canonical.as_bytes())))
}

fn assert_frozen_sha256(computed: &str, expected: &str, label: &str) -> Result<(), RemoteError> {
    if computed != expected {
        return Err(RemoteError::Registry(format!(
            "{label} SHA-256 mismatch: computed `{computed}`, expected `{expected}`"
        )));
    }
    Ok(())
}

/// Recomputes the accepted Agent authority registry SHA-256 from the retained
/// byte-for-byte registry file and asserts byte-equality with
/// [`AGENT_AUTHORITY_REGISTRY_SHA256`]; fails closed on any mismatch.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the recomputed digest diverges from
/// the frozen commitment.
pub fn recompute_agent_authority_registry_sha256() -> Result<(), RemoteError> {
    let bytes = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/authority/vectors/authority-operation-registry.valid.json"
    ))
    .as_bytes();
    assert_frozen_sha256(
        &hex_lower(&sha256(bytes)),
        AGENT_AUTHORITY_REGISTRY_SHA256,
        "accepted Agent authority registry",
    )
}

/// Recomputes the non-circular remote authorization projection SHA-256 from the
/// retained HTTP registry bytes and asserts byte-equality with
/// [`REMOTE_AUTHORIZATION_PROJECTION_SHA256`]; fails closed on any mismatch.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] on a parse, canonicalization, or digest
/// mismatch.
pub fn recompute_remote_authorization_projection_sha256() -> Result<(), RemoteError> {
    let registry = parse_http_registry()?;
    let projection_fields = registry["authorization_registry_commitment"]["projection_fields"]
        .as_array()
        .ok_or_else(|| {
            RemoteError::Registry(
                "authorization_registry_commitment.projection_fields is not an array".to_owned(),
            )
        })?;
    let mut projection = serde_json::Map::new();
    for field in projection_fields {
        let field = field.as_str().ok_or_else(|| {
            RemoteError::Registry("a projection field is not a string".to_owned())
        })?;
        let value = registry.get(field).ok_or_else(|| {
            RemoteError::Registry(format!(
                "projection field `{field}` is absent from the registry"
            ))
        })?;
        projection.insert(field.to_owned(), value.clone());
    }
    assert_frozen_sha256(
        &canonical_sha256_hex(&Value::Object(projection))?,
        REMOTE_AUTHORIZATION_PROJECTION_SHA256,
        "non-circular remote authorization projection",
    )
}

/// Recomputes the complete HTTP operation registry SHA-256 from the retained
/// registry bytes and asserts byte-equality with
/// [`COMPLETE_HTTP_OPERATION_REGISTRY_SHA256`]; fails closed on any mismatch.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] on a parse, canonicalization, or digest
/// mismatch.
pub fn recompute_complete_http_operation_registry_sha256() -> Result<(), RemoteError> {
    let registry = parse_http_registry()?;
    assert_frozen_sha256(
        &canonical_sha256_hex(&registry)?,
        COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "complete HTTP operation registry",
    )
}

fn parse_http_registry() -> Result<Value, RemoteError> {
    let bytes = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json"
    ));
    proof_canonical::parse_strict(bytes.as_bytes()).map_err(|error| {
        RemoteError::Registry(format!("HTTP operation registry parse failed: {error}"))
    })
}

// ---------------------------------------------------------------------------
// Route cross-check and row selection
// ---------------------------------------------------------------------------

/// Extracts the terminal major-version token from a full operation-version
/// identifier (`proof.dev/operation/release.create/v2` → `v2`).
#[must_use]
pub fn operation_major(version: &str) -> Option<&str> {
    version.rsplit('/').next().filter(|major| !major.is_empty())
}

/// Cross-checks that a Human/Agent route path's `{name}/{major}` tokens, the
/// invocation operation, and the route-qualified registry row all agree.
///
/// Any mismatch — an unsupported pair, a name/major divergence, or an unknown
/// row — fails closed before application execution.
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the path name/major and invocation
/// operation do not agree or the operation is not registered on the route.
pub fn cross_check_route_operation(
    route: HttpRouteV1,
    path_name: &str,
    path_major: &str,
    operation: &RemoteOperationV1,
) -> Result<(), RemoteError> {
    if path_name != operation.name {
        return Err(RemoteError::Registry(format!(
            "path name `{path_name}` does not match operation `{}`",
            operation.name
        )));
    }
    let Some(major) = operation_major(&operation.version) else {
        return Err(RemoteError::Registry(format!(
            "operation version `{}` has no major token",
            operation.version
        )));
    };
    if path_major != major {
        return Err(RemoteError::Registry(format!(
            "path major `{path_major}` does not match operation version major `{major}`"
        )));
    }
    match route {
        HttpRouteV1::HumanOperations => {
            if HumanOperationRegistryV1
                .lookup(&operation.name, &operation.version)
                .is_none()
            {
                return Err(RemoteError::Registry(format!(
                    "`{}`/`{}` is not a registered Human operation",
                    operation.name, operation.version
                )));
            }
        }
        HttpRouteV1::AgentOperations => {
            if AgentOperationProjectionV1
                .lookup(&operation.name, &operation.version)
                .is_none()
            {
                return Err(RemoteError::Registry(format!(
                    "`{}`/`{}` is not a registered Agent operation",
                    operation.name, operation.version
                )));
            }
        }
        _ => {
            return Err(RemoteError::Registry(format!(
                "route `{}` carries no name/major operation rows",
                route.path()
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Decision and consequence construction/validation
// ---------------------------------------------------------------------------

/// The exact Agent authentication profile that requires `agent_authorization`.
pub const AGENT_AUTHENTICATION_PROFILE: &str = "proof.server/authentication/oidc-human-agent/v1";

impl RemoteAuthorizationDecisionV1 {
    /// Binds the two frozen registry commitments onto this decision.
    pub fn bind_registry_hashes(&mut self) {
        REMOTE_AUTHORIZATION_PROJECTION_SHA256.clone_into(&mut self.authorization_registry_sha256);
        COMPLETE_HTTP_OPERATION_REGISTRY_SHA256.clone_into(&mut self.operation_registry_sha256);
    }

    /// Validates that the decision binds the frozen registry commitments and,
    /// for an Agent decision, carries the resolved `agent_authorization`
    /// closure (contract §"Remote authorization decision").
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Registry`] on a mismatched registry hash or a
    /// missing Agent authorization closure.
    pub fn validate(&self) -> Result<(), RemoteError> {
        if self.authorization_registry_sha256 != REMOTE_AUTHORIZATION_PROJECTION_SHA256 {
            return Err(RemoteError::Registry(format!(
                "authorization registry SHA-256 mismatch: expected `{REMOTE_AUTHORIZATION_PROJECTION_SHA256}`, got `{}`",
                self.authorization_registry_sha256
            )));
        }
        if self.operation_registry_sha256 != COMPLETE_HTTP_OPERATION_REGISTRY_SHA256 {
            return Err(RemoteError::Registry(format!(
                "operation registry SHA-256 mismatch: expected `{COMPLETE_HTTP_OPERATION_REGISTRY_SHA256}`, got `{}`",
                self.operation_registry_sha256
            )));
        }
        if self.authentication_profile == AGENT_AUTHENTICATION_PROFILE
            && self.agent_authorization.is_none()
        {
            return Err(RemoteError::Registry(
                "Agent decisions must carry an `agent_authorization` closure".to_owned(),
            ));
        }
        Ok(())
    }
}

impl RemoteApplicationConsequenceV1 {
    /// Copies the decision-bound fields — Workspace, decision identity,
    /// operation, full operation-registry selector, public input-projection
    /// digest, and evaluated head — onto this consequence (contract
    /// §"Application consequence").
    pub fn copy_decision_binding(&mut self, decision: &RemoteAuthorizationDecisionV1) {
        self.workspace_id.clone_from(&decision.workspace_id);
        self.decision_id.clone_from(&decision.decision_id);
        self.operation.clone_from(&decision.operation);
        self.operation_registry_sha256
            .clone_from(&decision.operation_registry_sha256);
        self.public_input_projection_digest = decision.public_input_projection_digest;
        self.evaluated_authority_head = decision.evaluated_authority_head;
    }

    /// Validates that this consequence binds its governing decision exactly.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Registry`] when any copied decision-bound field
    /// diverges from the governing decision.
    pub fn validate_against(
        &self,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<(), RemoteError> {
        if self.workspace_id != decision.workspace_id {
            return Err(RemoteError::Registry(
                "consequence workspace_id does not match its decision".to_owned(),
            ));
        }
        if self.decision_id != decision.decision_id {
            return Err(RemoteError::Registry(
                "consequence decision_id does not match its decision".to_owned(),
            ));
        }
        if self.operation != decision.operation {
            return Err(RemoteError::Registry(
                "consequence operation does not match its decision".to_owned(),
            ));
        }
        if self.operation_registry_sha256 != decision.operation_registry_sha256 {
            return Err(RemoteError::Registry(
                "consequence operation_registry_sha256 does not match its decision".to_owned(),
            ));
        }
        if self.public_input_projection_digest != decision.public_input_projection_digest {
            return Err(RemoteError::Registry(
                "consequence public_input_projection_digest does not match its decision".to_owned(),
            ));
        }
        if self.evaluated_authority_head != decision.evaluated_authority_head {
            return Err(RemoteError::Registry(
                "consequence evaluated_authority_head does not match its decision".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Selects the exact authority-payload timestamp field for one operation from
/// its route-qualified registry row, or `None` when the row has no
/// authority-record effect (contract §"Human and control operation registry").
#[must_use]
pub fn effect_timestamp_field(operation: &RemoteOperationV1) -> Option<EffectTimestampField> {
    HumanOperationRegistryV1
        .lookup(&operation.name, &operation.version)
        .and_then(|row| row.effect_timestamp_field)
        .or_else(|| {
            AgentOperationProjectionV1
                .lookup(&operation.name, &operation.version)
                .and_then(|row| row.effect_timestamp_field)
        })
}

/// Classifies a consequence into its exact outcome class from its field shape.
///
/// The five closed classes are distinguished by `problem_code` and
/// `prior_result_digest`; the field shape is then checked for the required and
/// forbidden members of that class (contract §"Application consequence").
///
/// # Errors
///
/// Returns [`RemoteError::Registry`] when the field shape is inconsistent with
/// the derived outcome class.
pub fn classify_consequence_outcome(
    consequence: &RemoteApplicationConsequenceV1,
) -> Result<ApplicationConsequenceOutcome, RemoteError> {
    let result_present = consequence.result_digest.is_some();
    let prior_present = consequence.prior_result_digest.is_some();
    let effect_absent = consequence.application_effect_digest.is_none()
        && consequence.application_effect_authority_head.is_none();

    let outcome = match consequence.problem_code.as_deref() {
        None => {
            if prior_present {
                ApplicationConsequenceOutcome::IdempotentReplay
            } else {
                ApplicationConsequenceOutcome::Success
            }
        }
        Some("proof.idempotency.key_reused") => ApplicationConsequenceOutcome::IdempotencyConflict,
        Some("proof.state.conflict") => ApplicationConsequenceOutcome::PreconditionConflict,
        Some(_) => ApplicationConsequenceOutcome::ApplicationFailure,
    };

    let shape_ok = match outcome {
        ApplicationConsequenceOutcome::Success => result_present && !prior_present,
        ApplicationConsequenceOutcome::IdempotentReplay
        | ApplicationConsequenceOutcome::IdempotencyConflict => {
            result_present && prior_present && effect_absent
        }
        ApplicationConsequenceOutcome::PreconditionConflict
        | ApplicationConsequenceOutcome::ApplicationFailure => {
            result_present && !prior_present && effect_absent
        }
    };
    if !shape_ok {
        return Err(RemoteError::Registry(format!(
            "consequence field shape is inconsistent with the `{outcome:?}` class"
        )));
    }
    Ok(outcome)
}
