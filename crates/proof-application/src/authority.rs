//! Transport-independent contracts for Proof's ratified local authority profile.

#![allow(
    clippy::missing_errors_doc,
    reason = "schema constructors and validators all return the closed AuthorityContractError"
)]

use std::{fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use proof_canonical::{canonicalize, digest};
use proof_domain::{
    ArtifactKind, AuthorityRootTransitionId, BindingId, ChangeSetId, ChangeSetIntent,
    ChangeSetStatus, ContentDigest, ContentResourceIntentId, ContextPackId, DelegationId, EditId,
    EditionId, EnrollmentChallengeId, EnvironmentId, IdempotencyKey, LocaleId, LocaleRevision,
    ObjectId, ObjectRevision, PresentationId, PrincipalId, ProofId, ReleaseId, ReleaseKind,
    RevocationId, SchemaId, SchemaVersion, Timestamp, WorkspaceId,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};
use thiserror::Error;

use super::{
    AddedLocalizedEdits, BuildLocalizedContextCommand, CommitLocalizedChangeSetCommand,
    CommittedLocalizedChangeSet, ContextPack, CreateLocalizedChangeSetCommand,
    CreateLocalizedEditionCommand, ExpectedLocalizedSource, ExpectedLocalizedTarget,
    LocalizedChangeSet, LocalizedChangeSetDiff, LocalizedContentError, LocalizedContextLimits,
    LocalizedContextPack, LocalizedEdit, LocalizedEditAttempt, LocalizedEdition, LocalizedFinding,
    LocalizedPolicyRule, LocalizedRelease, LocalizedValidation, MAX_CONTEXT_TASK_ID_BYTES,
    MAX_DELEGATION_OBJECTS, MAX_LOCALIZED_CONTEXT_BYTES, MAX_LOCALIZED_EDITS,
    MAX_LOCALIZED_TARGETS, MAX_LOCALIZED_VALIDATION_ATTEMPTS, ObjectCreateInput,
    ObjectLocalePutInput, PromoteLocalizedReleaseCommand, QueryReleasedRenditionsCommand,
    ReleasedLocaleTarget, ReleasedObjectQuery, ReleasedRenditionQuery, SubmittedLocalizedChangeSet,
};

/// Ratified direct Human-to-Agent policy profile.
pub const DIRECT_AUTHORITY_POLICY_PROFILE_V1: &str = "proof.local/authority/direct/v1";
/// Stable result-contract identifier for caller-safe localized operation Problems.
///
/// This is a typed profile identifier, not a claim that a resolvable JSON Schema
/// exists at an invented URL.
pub const LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1: &str =
    "proof.dev/result/localized-operation-problem/v1";
/// Maximum canonical authenticated-command or enrollment payload bytes.
pub const MAX_AUTHENTICATED_PAYLOAD_BYTES: usize = 4_096;
/// Maximum canonical authenticated-command or enrollment envelope bytes.
pub const MAX_AUTHENTICATED_ENVELOPE_BYTES: usize = 16_384;
/// Maximum canonical authority-record payload bytes.
pub const MAX_AUTHORITY_RECORD_BYTES: usize = 65_536;
/// Maximum canonical authority-record or root-transition envelope bytes.
pub const MAX_AUTHORITY_ENVELOPE_BYTES: usize = 98_304;
/// Maximum canonical authenticated broker-frame bytes.
pub const MAX_AUTHENTICATED_INVOCATION_BYTES: usize = 1_048_576;
/// Maximum accepted future clock skew for an authenticated command.
pub const MAX_COMMAND_FUTURE_SKEW_SECONDS: i64 = 30;
/// Maximum authenticated-command lifetime.
pub const MAX_COMMAND_LIFETIME_SECONDS: i64 = 300;

mod display_string {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<T: fmt::Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

mod optional_display_string {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[allow(
        clippy::ref_option,
        reason = "serde with-modules require a shared-reference field signature"
    )]
    pub fn serialize<T: fmt::Display, S: Serializer>(
        value: &Option<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value
            .as_ref()
            .map(ToString::to_string)
            .serialize(serializer)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .transpose()
    }
}

mod display_string_vec {
    use std::{fmt, str::FromStr};

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        T: FromStr,
        T::Err: fmt::Display,
        D: Deserializer<'de>,
    {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}

mod change_set_intent_string {
    use serde::{Deserialize, Deserializer, Serializer};

    use proof_domain::ChangeSetIntent;

    pub fn serialize<S: Serializer>(
        value: &ChangeSetIntent,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ChangeSetIntent, D::Error> {
        ChangeSetIntent::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

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
    AuthenticatedSubjectApiVersion,
    "proof.dev/authenticated-subject/v1"
);
api_version!(
    SubjectCommitmentApiVersion,
    "proof.dev/authenticated-subject-commitment/v1"
);
api_version!(CommandInputApiVersion, "proof.dev/command-input/v1");
api_version!(
    AuthenticatedCommandApiVersion,
    "proof.dev/authenticated-command/v1"
);
api_version!(
    AuthenticatedInvocationApiVersion,
    "proof.dev/authenticated-invocation/v1"
);
api_version!(
    ActorContextApiVersion,
    "proof.dev/authenticated-actor-context/v1"
);
api_version!(
    ActorContextEvidenceApiVersion,
    "proof.dev/authenticated-actor-context-evidence/v1"
);
api_version!(
    EnrollmentChallengeApiVersion,
    "proof.dev/binding-enrollment-challenge/v1"
);
api_version!(PrincipalBindingApiVersion, "proof.dev/principal-binding/v1");
api_version!(PrincipalStatusApiVersion, "proof.dev/principal-status/v1");
api_version!(
    PrincipalBindingRevocationApiVersion,
    "proof.dev/principal-binding-revocation/v1"
);
api_version!(DelegationApiVersion, "proof.dev/delegation/v2");
api_version!(
    DelegationRevocationApiVersion,
    "proof.dev/delegation-revocation/v1"
);
api_version!(
    AuthorizationDecisionApiVersion,
    "proof.dev/authorization-decision/v2"
);
api_version!(
    WorkspaceAuthorityRootApiVersion,
    "proof.dev/workspace-authority-root/v1"
);
api_version!(
    WorkspaceAuthorityRootTransitionApiVersion,
    "proof.dev/workspace-authority-root-transition/v1"
);
api_version!(
    LocalizedContextBuildInputApiVersion,
    "proof.dev/operation/context.build/v2"
);
api_version!(
    LocalizedChangeSetCreateInputApiVersion,
    "proof.dev/operation/changeset.create/v2"
);
api_version!(
    LocalizedChangeSetAddInputApiVersion,
    "proof.dev/operation/changeset.add/v2"
);
api_version!(LocalizedEditInputApiVersion, "proof.dev/edit/v2");
api_version!(
    LocalizedChangeSetGetInputApiVersion,
    "proof.dev/operation/changeset.get/v2"
);
api_version!(
    LocalizedChangeSetDiffInputApiVersion,
    "proof.dev/operation/changeset.diff/v2"
);
api_version!(
    LocalizedChangeSetValidateInputApiVersion,
    "proof.dev/operation/changeset.validate/v2"
);
api_version!(
    LocalizedChangeSetSubmitInputApiVersion,
    "proof.dev/operation/changeset.submit/v2"
);
api_version!(
    LocalizedChangeSetCommitInputApiVersion,
    "proof.dev/operation/changeset.commit/v2"
);
api_version!(
    LocalizedEditionCreateInputApiVersion,
    "proof.dev/operation/edition.create/v2"
);
api_version!(
    LocalizedReleaseCreateInputApiVersion,
    "proof.dev/operation/release.create/v2"
);
api_version!(
    LocalizedObjectQueryReleasedInputApiVersion,
    "proof.dev/operation/object.query_released/v2"
);

/// One of the 14 exact operation/version pairs registered for Milestone 2.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AuthorityOperation {
    ChangesetAddV2,
    ChangesetCommitV2,
    ChangesetCreateV2,
    ChangesetDiffV2,
    ChangesetGetV2,
    ChangesetSubmitV2,
    ChangesetValidateV2,
    ContextBuildV1,
    ContextBuildV2,
    EditionCreateV2,
    ObjectQueryReleasedV1,
    ObjectQueryReleasedV2,
    ReleaseCreateV2,
    WorkspaceStatusV1,
}

impl AuthorityOperation {
    /// Returns the exact semantic operation name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChangesetAddV2 => "changeset.add",
            Self::ChangesetCommitV2 => "changeset.commit",
            Self::ChangesetCreateV2 => "changeset.create",
            Self::ChangesetDiffV2 => "changeset.diff",
            Self::ChangesetGetV2 => "changeset.get",
            Self::ChangesetSubmitV2 => "changeset.submit",
            Self::ChangesetValidateV2 => "changeset.validate",
            Self::ContextBuildV1 | Self::ContextBuildV2 => "context.build",
            Self::EditionCreateV2 => "edition.create",
            Self::ObjectQueryReleasedV1 | Self::ObjectQueryReleasedV2 => "object.query_released",
            Self::ReleaseCreateV2 => "release.create",
            Self::WorkspaceStatusV1 => "workspace.status",
        }
    }

    /// Returns the exact version URI paired with [`Self::name`].
    #[must_use]
    pub const fn version(self) -> &'static str {
        match self {
            Self::ChangesetAddV2 => "proof.dev/operation/changeset.add/v2",
            Self::ChangesetCommitV2 => "proof.dev/operation/changeset.commit/v2",
            Self::ChangesetCreateV2 => "proof.dev/operation/changeset.create/v2",
            Self::ChangesetDiffV2 => "proof.dev/operation/changeset.diff/v2",
            Self::ChangesetGetV2 => "proof.dev/operation/changeset.get/v2",
            Self::ChangesetSubmitV2 => "proof.dev/operation/changeset.submit/v2",
            Self::ChangesetValidateV2 => "proof.dev/operation/changeset.validate/v2",
            Self::ContextBuildV1 => "proof.dev/operation/context.build/v1",
            Self::ContextBuildV2 => "proof.dev/operation/context.build/v2",
            Self::EditionCreateV2 => "proof.dev/operation/edition.create/v2",
            Self::ObjectQueryReleasedV1 => "proof.dev/operation/object.query_released/v1",
            Self::ObjectQueryReleasedV2 => "proof.dev/operation/object.query_released/v2",
            Self::ReleaseCreateV2 => "proof.dev/operation/release.create/v2",
            Self::WorkspaceStatusV1 => "proof.dev/operation/workspace.status/v1",
        }
    }

    /// Resolves only an exact registered name/version pair.
    #[must_use]
    pub fn from_pair(name: &str, version: &str) -> Option<Self> {
        AUTHORITY_OPERATION_REGISTRY_V1
            .iter()
            .find(|entry| entry.operation.name() == name && entry.operation.version() == version)
            .map(|entry| entry.operation)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorityOperationWire {
    name: String,
    version: String,
}

impl Serialize for AuthorityOperation {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        AuthorityOperationWire {
            name: self.name().to_owned(),
            version: self.version().to_owned(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AuthorityOperation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = AuthorityOperationWire::deserialize(deserializer)?;
        Self::from_pair(&wire.name, &wire.version).ok_or_else(|| {
            serde::de::Error::custom("unregistered authority operation/version pair")
        })
    }
}

/// One exact delegated action from the ratified 12-action grammar.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AuthorityAction {
    #[serde(rename = "changeset:add")]
    ChangesetAdd,
    #[serde(rename = "changeset:commit")]
    ChangesetCommit,
    #[serde(rename = "changeset:create")]
    ChangesetCreate,
    #[serde(rename = "changeset:diff")]
    ChangesetDiff,
    #[serde(rename = "changeset:get")]
    ChangesetGet,
    #[serde(rename = "changeset:submit")]
    ChangesetSubmit,
    #[serde(rename = "changeset:validate")]
    ChangesetValidate,
    #[serde(rename = "context:build")]
    ContextBuild,
    #[serde(rename = "edition:create")]
    EditionCreate,
    #[serde(rename = "object:query_released")]
    ObjectQueryReleased,
    #[serde(rename = "release:create")]
    ReleaseCreate,
    #[serde(rename = "workspace:status")]
    WorkspaceStatus,
}

impl fmt::Display for AuthorityAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ChangesetAdd => "changeset:add",
            Self::ChangesetCommit => "changeset:commit",
            Self::ChangesetCreate => "changeset:create",
            Self::ChangesetDiff => "changeset:diff",
            Self::ChangesetGet => "changeset:get",
            Self::ChangesetSubmit => "changeset:submit",
            Self::ChangesetValidate => "changeset:validate",
            Self::ContextBuild => "context:build",
            Self::EditionCreate => "edition:create",
            Self::ObjectQueryReleased => "object:query_released",
            Self::ReleaseCreate => "release:create",
            Self::WorkspaceStatus => "workspace:status",
        })
    }
}

impl FromStr for AuthorityAction {
    type Err = AuthorityContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "changeset:add" => Ok(Self::ChangesetAdd),
            "changeset:commit" => Ok(Self::ChangesetCommit),
            "changeset:create" => Ok(Self::ChangesetCreate),
            "changeset:diff" => Ok(Self::ChangesetDiff),
            "changeset:get" => Ok(Self::ChangesetGet),
            "changeset:submit" => Ok(Self::ChangesetSubmit),
            "changeset:validate" => Ok(Self::ChangesetValidate),
            "context:build" => Ok(Self::ContextBuild),
            "edition:create" => Ok(Self::EditionCreate),
            "object:query_released" => Ok(Self::ObjectQueryReleased),
            "release:create" => Ok(Self::ReleaseCreate),
            "workspace:status" => Ok(Self::WorkspaceStatus),
            _ => Err(AuthorityContractError::InvalidValue("authority action")),
        }
    }
}

/// Authenticated execution side-effect classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityExecutionClass {
    /// Consumes a presentation and appends durable authority evidence.
    EvidenceWrite,
}

/// Rollout provenance for an enabled authenticated operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorityOperationAvailability {
    #[serde(rename = "implemented-v1-read")]
    ImplementedV1Read,
    #[serde(rename = "p0005-delegated-localized")]
    P0005DelegatedLocalized,
}

/// Application idempotency rule frozen by the authority registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ApplicationIdempotency {
    #[serde(rename = "derived-changeset")]
    DerivedChangeset,
    #[serde(rename = "derived-proposal-policy-validator")]
    DerivedProposalPolicyValidator,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "required-uuidv7")]
    RequiredUuidV7,
}

/// Resource-closure anchor frozen by the authority registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClosureAnchor {
    #[serde(rename = "command")]
    Command,
    #[serde(rename = "normalized-input-resource-intent")]
    NormalizedInputResourceIntent,
    #[serde(rename = "resolved-current-release")]
    ResolvedCurrentRelease,
    #[serde(rename = "verified-changeset-resource-intent")]
    VerifiedChangesetResourceIntent,
    #[serde(rename = "verified-committed-changeset-resource-intent")]
    VerifiedCommittedChangesetResourceIntent,
    #[serde(rename = "verified-edition-changeset-resource-intent")]
    VerifiedEditionChangesetResourceIntent,
}

/// Named resource projection profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ResourceProjectionProfileName {
    #[serde(rename = "legacy-object-selection/v1")]
    LegacyObjectSelectionV1,
    #[serde(rename = "localized-intent-closure/v1")]
    LocalizedIntentClosureV1,
    #[serde(rename = "localized-released-selection/v1")]
    LocalizedReleasedSelectionV1,
    #[serde(rename = "workspace-only/v1")]
    WorkspaceOnlyV1,
}

/// Budget source frozen by the authority registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BudgetProjection {
    #[serde(rename = "bound-context-limits")]
    BoundContextLimits,
    #[serde(rename = "delegation-only")]
    DelegationOnly,
    #[serde(rename = "normalized-v1-context-limits")]
    NormalizedV1ContextLimits,
    #[serde(rename = "normalized-v2-context-limits")]
    NormalizedV2ContextLimits,
    #[serde(rename = "requested-object-count")]
    RequestedObjectCount,
}

/// One grant axis evaluated by a resource projection profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantAxis {
    EnvironmentIds,
    Locales,
    ObjectIds,
    SchemaIds,
    WorkspaceIds,
}

/// Whether resource resolution is single-stage or disclosure-safe staged.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProjectionEvaluation {
    #[serde(rename = "single-stage")]
    SingleStage,
    #[serde(rename = "staged-object-locale-then-resolved-schema")]
    StagedObjectLocaleThenResolvedSchema,
}

/// Exact source expression for one resource projection dimension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ProjectionSource {
    #[serde(rename = "command.workspace_id")]
    CommandWorkspaceId,
    #[serde(rename = "none")]
    None,
    #[serde(rename = "normalized_input.environment_id")]
    NormalizedInputEnvironmentId,
    #[serde(rename = "normalized_input.object_ids")]
    NormalizedInputObjectIds,
    #[serde(rename = "normalized_input.targets.locale")]
    NormalizedInputTargetLocales,
    #[serde(rename = "normalized_input.targets.object_id")]
    NormalizedInputTargetObjectIds,
    #[serde(rename = "resolved_current_release.edition.requested_objects.schema_id")]
    ResolvedCurrentReleaseRequestedObjectSchemaIds,
    #[serde(rename = "verified_content_resource_intent.environment_id")]
    VerifiedContentResourceIntentEnvironmentId,
    #[serde(rename = "verified_content_resource_intent.targets.locale")]
    VerifiedContentResourceIntentTargetLocales,
    #[serde(rename = "verified_content_resource_intent.targets.object_id")]
    VerifiedContentResourceIntentTargetObjectIds,
    #[serde(rename = "verified_content_resource_intent.targets.schema_id")]
    VerifiedContentResourceIntentTargetSchemaIds,
}

/// Five complete dimension source mappings for a projection profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSources {
    pub workspace_ids: ProjectionSource,
    pub environment_ids: ProjectionSource,
    pub object_ids: ProjectionSource,
    pub schema_ids: ProjectionSource,
    pub locales: ProjectionSource,
}

/// One of four closed resource-projection profiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceProjectionProfile {
    pub profile: ResourceProjectionProfileName,
    pub grant_axes: &'static [GrantAxis],
    pub evaluation: ProjectionEvaluation,
    pub sources: ProjectionSources,
}

const LEGACY_OBJECT_AXES: &[GrantAxis] = &[
    GrantAxis::EnvironmentIds,
    GrantAxis::ObjectIds,
    GrantAxis::WorkspaceIds,
];
const LOCALIZED_AXES: &[GrantAxis] = &[
    GrantAxis::EnvironmentIds,
    GrantAxis::Locales,
    GrantAxis::ObjectIds,
    GrantAxis::SchemaIds,
    GrantAxis::WorkspaceIds,
];
const WORKSPACE_AXES: &[GrantAxis] = &[GrantAxis::WorkspaceIds];

/// Exact four resource projection profiles from `AuthorityOperationRegistryV1`.
pub const AUTHORITY_RESOURCE_PROJECTION_PROFILES_V1: [ResourceProjectionProfile; 4] = [
    ResourceProjectionProfile {
        profile: ResourceProjectionProfileName::LegacyObjectSelectionV1,
        grant_axes: LEGACY_OBJECT_AXES,
        evaluation: ProjectionEvaluation::SingleStage,
        sources: ProjectionSources {
            workspace_ids: ProjectionSource::CommandWorkspaceId,
            environment_ids: ProjectionSource::NormalizedInputEnvironmentId,
            object_ids: ProjectionSource::NormalizedInputObjectIds,
            schema_ids: ProjectionSource::None,
            locales: ProjectionSource::None,
        },
    },
    ResourceProjectionProfile {
        profile: ResourceProjectionProfileName::LocalizedIntentClosureV1,
        grant_axes: LOCALIZED_AXES,
        evaluation: ProjectionEvaluation::SingleStage,
        sources: ProjectionSources {
            workspace_ids: ProjectionSource::CommandWorkspaceId,
            environment_ids: ProjectionSource::VerifiedContentResourceIntentEnvironmentId,
            object_ids: ProjectionSource::VerifiedContentResourceIntentTargetObjectIds,
            schema_ids: ProjectionSource::VerifiedContentResourceIntentTargetSchemaIds,
            locales: ProjectionSource::VerifiedContentResourceIntentTargetLocales,
        },
    },
    ResourceProjectionProfile {
        profile: ResourceProjectionProfileName::LocalizedReleasedSelectionV1,
        grant_axes: LOCALIZED_AXES,
        evaluation: ProjectionEvaluation::StagedObjectLocaleThenResolvedSchema,
        sources: ProjectionSources {
            workspace_ids: ProjectionSource::CommandWorkspaceId,
            environment_ids: ProjectionSource::NormalizedInputEnvironmentId,
            object_ids: ProjectionSource::NormalizedInputTargetObjectIds,
            schema_ids: ProjectionSource::ResolvedCurrentReleaseRequestedObjectSchemaIds,
            locales: ProjectionSource::NormalizedInputTargetLocales,
        },
    },
    ResourceProjectionProfile {
        profile: ResourceProjectionProfileName::WorkspaceOnlyV1,
        grant_axes: WORKSPACE_AXES,
        evaluation: ProjectionEvaluation::SingleStage,
        sources: ProjectionSources {
            workspace_ids: ProjectionSource::CommandWorkspaceId,
            environment_ids: ProjectionSource::None,
            object_ids: ProjectionSource::None,
            schema_ids: ProjectionSource::None,
            locales: ProjectionSource::None,
        },
    },
];

/// Persisted consequence frozen by the authority registry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorityConsequence {
    #[serde(rename = "authority-evidence-only")]
    AuthorityEvidenceOnly,
    #[serde(rename = "draft-localized-changeset")]
    DraftLocalizedChangeset,
    #[serde(rename = "immutable-context-pack")]
    ImmutableContextPack,
    #[serde(rename = "immutable-localized-edition")]
    ImmutableLocalizedEdition,
    #[serde(rename = "localized-edit-batch")]
    LocalizedEditBatch,
    #[serde(rename = "localized-release-pointer-and-proof")]
    LocalizedReleasePointerAndProof,
    #[serde(rename = "localized-rendition-commit")]
    LocalizedRenditionCommit,
    #[serde(rename = "localized-submission")]
    LocalizedSubmission,
    #[serde(rename = "localized-validation-attempt")]
    LocalizedValidationAttempt,
}

/// Selector mapping for evidence-only resource identifiers.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelectorProjection {
    pub changeset_ids: ChangesetSelectorSource,
    pub edition_ids: EditionSelectorSource,
    pub release_ids: ReleaseSelectorSource,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ChangesetSelectorSource {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "normalized_input.changeset_id")]
    NormalizedInputChangesetId,
    #[serde(rename = "resolved_edition.changeset_id")]
    ResolvedEditionChangesetId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EditionSelectorSource {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "normalized_input.edition_id")]
    NormalizedInputEditionId,
    #[serde(rename = "resolved_current_release.edition_id")]
    ResolvedCurrentReleaseEditionId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReleaseSelectorSource {
    #[serde(rename = "none")]
    None,
    #[serde(
        rename = "canonical-sorted(normalized_input.expected_base_release_id,normalized_input.release_id)"
    )]
    NormalizedExpectedBaseAndReleaseIds,
    #[serde(rename = "resolved_current_release.release_id")]
    ResolvedCurrentReleaseId,
}

/// One immutable row of the ratified runtime authority registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityOperationEntry {
    pub operation: AuthorityOperation,
    pub requested_action: AuthorityAction,
    pub localized_contract: Option<&'static str>,
    pub application_idempotency: ApplicationIdempotency,
    pub closure_anchor: ClosureAnchor,
    pub resource_projection_profile: ResourceProjectionProfileName,
    pub budget_projection: BudgetProjection,
    pub selector_projection: SelectorProjection,
    pub consequence: AuthorityConsequence,
    pub availability: AuthorityOperationAvailability,
    pub execution_class: AuthorityExecutionClass,
}

impl AuthorityOperationEntry {
    /// Whether the completed P-0004/P-0005 profile exposes this operation.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(
            self.availability,
            AuthorityOperationAvailability::ImplementedV1Read
                | AuthorityOperationAvailability::P0005DelegatedLocalized
        )
    }
}

const NONE_SELECTORS: SelectorProjection = SelectorProjection {
    changeset_ids: ChangesetSelectorSource::None,
    edition_ids: EditionSelectorSource::None,
    release_ids: ReleaseSelectorSource::None,
};

#[allow(
    clippy::too_many_arguments,
    reason = "the arguments are the ten exact registry columns"
)]
const fn entry(
    operation: AuthorityOperation,
    requested_action: AuthorityAction,
    localized_contract: Option<&'static str>,
    application_idempotency: ApplicationIdempotency,
    closure_anchor: ClosureAnchor,
    resource_projection_profile: ResourceProjectionProfileName,
    budget_projection: BudgetProjection,
    selector_projection: SelectorProjection,
    consequence: AuthorityConsequence,
    availability: AuthorityOperationAvailability,
) -> AuthorityOperationEntry {
    AuthorityOperationEntry {
        operation,
        requested_action,
        localized_contract,
        application_idempotency,
        closure_anchor,
        resource_projection_profile,
        budget_projection,
        selector_projection,
        consequence,
        availability,
        execution_class: AuthorityExecutionClass::EvidenceWrite,
    }
}

/// Exact 14-row runtime registry ratified by P-0003.
pub const AUTHORITY_OPERATION_REGISTRY_V1: [AuthorityOperationEntry; 14] = [
    entry(
        AuthorityOperation::ChangesetAddV2,
        AuthorityAction::ChangesetAdd,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetAddInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::LocalizedEditBatch,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetCommitV2,
        AuthorityAction::ChangesetCommit,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetCommitInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::LocalizedRenditionCommit,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetCreateV2,
        AuthorityAction::ChangesetCreate,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetCreateInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::NormalizedInputResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::DraftLocalizedChangeset,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetDiffV2,
        AuthorityAction::ChangesetDiff,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetDiffInput",
        ),
        ApplicationIdempotency::None,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::AuthorityEvidenceOnly,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetGetV2,
        AuthorityAction::ChangesetGet,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetGetInput",
        ),
        ApplicationIdempotency::None,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::AuthorityEvidenceOnly,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetSubmitV2,
        AuthorityAction::ChangesetSubmit,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetSubmitInput",
        ),
        ApplicationIdempotency::DerivedChangeset,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::LocalizedSubmission,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ChangesetValidateV2,
        AuthorityAction::ChangesetValidate,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetValidateInput",
        ),
        ApplicationIdempotency::DerivedProposalPolicyValidator,
        ClosureAnchor::VerifiedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::None,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::LocalizedValidationAttempt,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ContextBuildV1,
        AuthorityAction::ContextBuild,
        None,
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::Command,
        ResourceProjectionProfileName::LegacyObjectSelectionV1,
        BudgetProjection::NormalizedV1ContextLimits,
        NONE_SELECTORS,
        AuthorityConsequence::ImmutableContextPack,
        AuthorityOperationAvailability::ImplementedV1Read,
    ),
    entry(
        AuthorityOperation::ContextBuildV2,
        AuthorityAction::ContextBuild,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/contextBuildInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::NormalizedInputResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::NormalizedV2ContextLimits,
        NONE_SELECTORS,
        AuthorityConsequence::ImmutableContextPack,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::EditionCreateV2,
        AuthorityAction::EditionCreate,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/editionCreateInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::VerifiedCommittedChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::NormalizedInputChangesetId,
            edition_ids: EditionSelectorSource::NormalizedInputEditionId,
            release_ids: ReleaseSelectorSource::None,
        },
        AuthorityConsequence::ImmutableLocalizedEdition,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ObjectQueryReleasedV1,
        AuthorityAction::ObjectQueryReleased,
        None,
        ApplicationIdempotency::None,
        ClosureAnchor::Command,
        ResourceProjectionProfileName::LegacyObjectSelectionV1,
        BudgetProjection::RequestedObjectCount,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::None,
            edition_ids: EditionSelectorSource::ResolvedCurrentReleaseEditionId,
            release_ids: ReleaseSelectorSource::ResolvedCurrentReleaseId,
        },
        AuthorityConsequence::AuthorityEvidenceOnly,
        AuthorityOperationAvailability::ImplementedV1Read,
    ),
    entry(
        AuthorityOperation::ObjectQueryReleasedV2,
        AuthorityAction::ObjectQueryReleased,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/objectQueryReleasedInput",
        ),
        ApplicationIdempotency::None,
        ClosureAnchor::ResolvedCurrentRelease,
        ResourceProjectionProfileName::LocalizedReleasedSelectionV1,
        BudgetProjection::RequestedObjectCount,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::None,
            edition_ids: EditionSelectorSource::ResolvedCurrentReleaseEditionId,
            release_ids: ReleaseSelectorSource::ResolvedCurrentReleaseId,
        },
        AuthorityConsequence::AuthorityEvidenceOnly,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::ReleaseCreateV2,
        AuthorityAction::ReleaseCreate,
        Some(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/releaseCreateInput",
        ),
        ApplicationIdempotency::RequiredUuidV7,
        ClosureAnchor::VerifiedEditionChangesetResourceIntent,
        ResourceProjectionProfileName::LocalizedIntentClosureV1,
        BudgetProjection::BoundContextLimits,
        SelectorProjection {
            changeset_ids: ChangesetSelectorSource::ResolvedEditionChangesetId,
            edition_ids: EditionSelectorSource::NormalizedInputEditionId,
            release_ids: ReleaseSelectorSource::NormalizedExpectedBaseAndReleaseIds,
        },
        AuthorityConsequence::LocalizedReleasePointerAndProof,
        AuthorityOperationAvailability::P0005DelegatedLocalized,
    ),
    entry(
        AuthorityOperation::WorkspaceStatusV1,
        AuthorityAction::WorkspaceStatus,
        None,
        ApplicationIdempotency::None,
        ClosureAnchor::Command,
        ResourceProjectionProfileName::WorkspaceOnlyV1,
        BudgetProjection::DelegationOnly,
        NONE_SELECTORS,
        AuthorityConsequence::AuthorityEvidenceOnly,
        AuthorityOperationAvailability::ImplementedV1Read,
    ),
];

/// Runtime view of the ratified authority operation registry.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorityOperationRegistryV1;

impl AuthorityOperationRegistryV1 {
    pub const API_VERSION: &'static str = "proof.dev/authority-operation-registry/v1";

    /// Returns the exact four resource-projection profiles.
    #[must_use]
    pub const fn resource_projection_profiles(self) -> &'static [ResourceProjectionProfile; 4] {
        &AUTHORITY_RESOURCE_PROJECTION_PROFILES_V1
    }

    /// Returns the exact 14 operation rows enabled across P-0004 and P-0005.
    #[must_use]
    pub const fn operations(self) -> &'static [AuthorityOperationEntry; 14] {
        &AUTHORITY_OPERATION_REGISTRY_V1
    }

    /// Looks up a typed registered operation.
    #[must_use]
    pub fn operation(self, operation: AuthorityOperation) -> &'static AuthorityOperationEntry {
        authority_operation_entry(operation)
    }

    /// Iterates all rows exposed by the completed P-0004/P-0005 profile.
    pub fn enabled(self) -> impl Iterator<Item = &'static AuthorityOperationEntry> {
        enabled_authority_operations()
    }
}

/// Looks up an exact registered operation.
///
/// # Panics
///
/// Panics only if this module's closed enum and constant registry diverge.
#[must_use]
pub fn authority_operation_entry(
    operation: AuthorityOperation,
) -> &'static AuthorityOperationEntry {
    AUTHORITY_OPERATION_REGISTRY_V1
        .iter()
        .find(|entry| entry.operation == operation)
        .expect("every AuthorityOperation variant has one registry row")
}

/// Iterates all 14 authenticated operations enabled through P-0004/P-0005.
pub fn enabled_authority_operations() -> impl Iterator<Item = &'static AuthorityOperationEntry> {
    AUTHORITY_OPERATION_REGISTRY_V1
        .iter()
        .filter(|entry| entry.is_enabled())
}

/// A schema-backed authority value violated the ratified closed grammar.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuthorityContractError {
    #[error("invalid {0}")]
    InvalidValue(&'static str),
    #[error("{0} must contain between {1} and {2} sorted unique values")]
    InvalidSet(&'static str, usize, usize),
}

/// A strictly sorted, duplicate-free, bounded JSON string array.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SortedUnique<T, const MIN: usize, const MAX: usize>(Vec<T>);

impl<T, const MIN: usize, const MAX: usize> SortedUnique<T, MIN, MAX>
where
    T: Ord,
{
    /// Constructs a set without reordering signed input.
    pub fn new(values: Vec<T>) -> Result<Self, AuthorityContractError> {
        let valid_len = (MIN..=MAX).contains(&values.len());
        let sorted_unique = values.windows(2).all(|pair| pair[0] < pair[1]);
        if valid_len && sorted_unique {
            Ok(Self(values))
        } else {
            Err(AuthorityContractError::InvalidSet(
                "authority set",
                MIN,
                MAX,
            ))
        }
    }

    /// Sorts a bounded transport array without silently removing duplicates.
    pub fn normalize(mut values: Vec<T>) -> Result<Self, AuthorityContractError> {
        if !(MIN..=MAX).contains(&values.len()) {
            return Err(AuthorityContractError::InvalidSet(
                "authority set",
                MIN,
                MAX,
            ));
        }
        values.sort();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AuthorityContractError::InvalidSet(
                "authority set",
                MIN,
                MAX,
            ));
        }
        Ok(Self(values))
    }

    /// Returns the exact canonical order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Consumes the wrapper without changing order.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MIN: usize, const MAX: usize> Serialize for SortedUnique<T, MIN, MAX>
where
    T: fmt::Display,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
}

impl<'de, T, const MIN: usize, const MAX: usize> Deserialize<'de> for SortedUnique<T, MIN, MAX>
where
    T: FromStr + Ord,
    T::Err: fmt::Display,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let values = Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|value| value.parse().map_err(serde::de::Error::custom))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

macro_rules! ranged_integer {
    ($name:ident, $inner:ty, $min:expr, $max:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name($inner);

        impl $name {
            pub const MIN: $inner = $min;
            pub const MAX: $inner = $max;

            /// Constructs a value inside the schema range.
            pub fn new(value: $inner) -> Result<Self, AuthorityContractError> {
                if (Self::MIN..=Self::MAX).contains(&value) {
                    Ok(Self(value))
                } else {
                    Err(AuthorityContractError::InvalidValue(stringify!($name)))
                }
            }

            /// Returns the primitive integer.
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(<$inner>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

ranged_integer!(
    AuthoritySequence,
    u64,
    1,
    9_007_199_254_740_991,
    "A positive JSON-safe authority-log sequence."
);
ranged_integer!(MaxObjects, u32, 1, 100, "A bounded Object-count grant.");
ranged_integer!(
    MaxContextBytes,
    u32,
    1,
    1_048_576,
    "A bounded canonical `ContextPack` byte grant."
);
ranged_integer!(
    MaxEditsPerChangeSet,
    u32,
    1,
    100,
    "A bounded per-ChangeSet Edit grant."
);

/// Exact Workspace-scoped audience URI.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityAudience(WorkspaceId);

impl AuthorityAudience {
    /// Constructs the only audience valid for a Workspace.
    #[must_use]
    pub const fn for_workspace(workspace_id: WorkspaceId) -> Self {
        Self(workspace_id)
    }

    /// Returns the audience's Workspace.
    #[must_use]
    pub const fn workspace_id(self) -> WorkspaceId {
        self.0
    }
}

impl fmt::Display for AuthorityAudience {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "proof://workspace/{}", self.0)
    }
}

impl FromStr for AuthorityAudience {
    type Err = AuthorityContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .strip_prefix("proof://workspace/")
            .ok_or(AuthorityContractError::InvalidValue("authority audience"))?
            .parse()
            .map(Self)
            .map_err(|_| AuthorityContractError::InvalidValue("authority audience"))
    }
}

impl Serialize for AuthorityAudience {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AuthorityAudience {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Exact `ed25519:<lowercase-hex-public-key>` key identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ed25519KeyId(String);

impl Ed25519KeyId {
    /// Validates the ratified Ed25519 key-ID grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityContractError> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("ed25519:") else {
            return Err(AuthorityContractError::InvalidValue("Ed25519 key id"));
        };
        if hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(AuthorityContractError::InvalidValue("Ed25519 key id"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ed25519KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Ed25519KeyId {
    type Err = AuthorityContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Ed25519KeyId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519KeyId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Canonical standard-base64 Ed25519 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ed25519PublicKey(String);

impl Ed25519PublicKey {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityContractError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let base64 = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/');
        let final_data = |byte: u8| b"AEIMQUYcgkosw048".contains(&byte);
        if bytes.len() == 44
            && bytes[..42].iter().copied().all(base64)
            && final_data(bytes[42])
            && bytes[43] == b'='
            && STANDARD
                .decode(&value)
                .is_ok_and(|decoded| decoded.len() == 32 && STANDARD.encode(decoded) == value)
        {
            Ok(Self(value))
        } else {
            Err(AuthorityContractError::InvalidValue("Ed25519 public key"))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derives the exact lowercase-hex key ID committed by a local subject.
    pub fn key_id(&self) -> Result<Ed25519KeyId, AuthorityContractError> {
        use std::fmt::Write as _;

        let bytes = STANDARD
            .decode(&self.0)
            .map_err(|_| AuthorityContractError::InvalidValue("Ed25519 public key"))?;
        let mut value = String::with_capacity(72);
        value.push_str("ed25519:");
        for byte in bytes {
            write!(&mut value, "{byte:02x}")
                .map_err(|_| AuthorityContractError::InvalidValue("Ed25519 public key"))?;
        }
        Ed25519KeyId::new(value)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = AuthorityContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Provider name from `AuthenticatedSubjectV1`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthenticatedSubjectProvider {
    #[serde(rename = "os/unix")]
    OsUnix,
    #[serde(rename = "proof/local-ed25519")]
    ProofLocalEd25519,
}

/// Provider-qualified subject produced by a trusted authentication adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthenticatedSubjectV1 {
    pub api_version: AuthenticatedSubjectApiVersion,
    pub provider: AuthenticatedSubjectProvider,
    subject: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuthenticatedSubjectV1 {
    #[serde(rename = "api_version")]
    _api_version: AuthenticatedSubjectApiVersion,
    provider: AuthenticatedSubjectProvider,
    subject: String,
}

impl AuthenticatedSubjectV1 {
    /// Constructs a strict Unix subject without normalizing its UID spelling.
    pub fn unix(subject: impl Into<String>) -> Result<Self, AuthorityContractError> {
        Self::new(AuthenticatedSubjectProvider::OsUnix, subject.into())
    }

    /// Constructs a strict local Ed25519 subject from its key ID.
    #[must_use]
    pub fn local_ed25519(key_id: &Ed25519KeyId) -> Self {
        Self {
            api_version: AuthenticatedSubjectApiVersion::V1,
            provider: AuthenticatedSubjectProvider::ProofLocalEd25519,
            subject: key_id.to_string(),
        }
    }

    fn new(
        provider: AuthenticatedSubjectProvider,
        subject: String,
    ) -> Result<Self, AuthorityContractError> {
        let valid = match provider {
            AuthenticatedSubjectProvider::OsUnix => valid_unix_subject(&subject),
            AuthenticatedSubjectProvider::ProofLocalEd25519 => {
                subject.parse::<Ed25519KeyId>().is_ok()
            }
        };
        if valid {
            Ok(Self {
                api_version: AuthenticatedSubjectApiVersion::V1,
                provider,
                subject,
            })
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authenticated subject",
            ))
        }
    }

    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

fn valid_unix_subject(subject: &str) -> bool {
    let Some(uid) = subject.strip_prefix("uid:") else {
        return false;
    };
    !uid.is_empty()
        && uid.len() <= 20
        && uid.bytes().all(|byte| byte.is_ascii_digit())
        && (uid == "0" || !uid.starts_with('0'))
}

impl<'de> Deserialize<'de> for AuthenticatedSubjectV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawAuthenticatedSubjectV1::deserialize(deserializer)?;
        Self::new(raw.provider, raw.subject).map_err(serde::de::Error::custom)
    }
}

/// `AuthenticatedSubjectV1` narrowed to the requester `os/unix` provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnixAuthenticatedSubjectV1(AuthenticatedSubjectV1);

impl UnixAuthenticatedSubjectV1 {
    pub fn new(subject: impl Into<String>) -> Result<Self, AuthorityContractError> {
        AuthenticatedSubjectV1::unix(subject).map(Self)
    }

    #[must_use]
    pub fn as_subject(&self) -> &AuthenticatedSubjectV1 {
        &self.0
    }
}

impl Serialize for UnixAuthenticatedSubjectV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UnixAuthenticatedSubjectV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let subject = AuthenticatedSubjectV1::deserialize(deserializer)?;
        if subject.provider == AuthenticatedSubjectProvider::OsUnix {
            Ok(Self(subject))
        } else {
            Err(serde::de::Error::custom(
                "requesting subject must use os/unix",
            ))
        }
    }
}

/// `AuthenticatedSubjectV1` narrowed to the operator `proof/local-ed25519` provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEd25519AuthenticatedSubjectV1(AuthenticatedSubjectV1);

impl LocalEd25519AuthenticatedSubjectV1 {
    #[must_use]
    pub fn new(key_id: &Ed25519KeyId) -> Self {
        Self(AuthenticatedSubjectV1::local_ed25519(key_id))
    }

    #[must_use]
    pub fn as_subject(&self) -> &AuthenticatedSubjectV1 {
        &self.0
    }
}

impl Serialize for LocalEd25519AuthenticatedSubjectV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LocalEd25519AuthenticatedSubjectV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let subject = AuthenticatedSubjectV1::deserialize(deserializer)?;
        if subject.provider == AuthenticatedSubjectProvider::ProofLocalEd25519 {
            Ok(Self(subject))
        } else {
            Err(serde::de::Error::custom(
                "operating subject must use proof/local-ed25519",
            ))
        }
    }
}

/// Base64url-no-pad encoding of the 32-byte requester-commitment blind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectCommitmentBlind(String);

impl SubjectCommitmentBlind {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityContractError> {
        let value = value.into();
        let bytes = value.as_bytes();
        let base64url = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
        if bytes.len() == 43
            && bytes[..42].iter().copied().all(base64url)
            && b"AEIMQUYcgkosw048".contains(&bytes[42])
        {
            Ok(Self(value))
        } else {
            Err(AuthorityContractError::InvalidValue(
                "subject commitment blind",
            ))
        }
    }
}

impl fmt::Display for SubjectCommitmentBlind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for SubjectCommitmentBlind {
    type Err = AuthorityContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Private canonical requester-commitment preimage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedSubjectCommitmentInputV1 {
    pub api_version: SubjectCommitmentApiVersion,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub authenticated_subject: UnixAuthenticatedSubjectV1,
    #[serde(with = "display_string")]
    pub blind: SubjectCommitmentBlind,
}

/// A bounded exact task identifier in the v1 Context-build input.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextTaskIdV1(String);

impl ContextTaskIdV1 {
    /// Constructs a task identifier without changing its signed bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityContractError> {
        let value = value.into();
        if !value.trim().is_empty() && value.len() <= MAX_CONTEXT_TASK_ID_BYTES {
            Ok(Self(value))
        } else {
            Err(AuthorityContractError::InvalidValue("context task id"))
        }
    }

    /// Returns the exact task-identifier bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContextTaskIdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ContextTaskIdV1 {
    type Err = AuthorityContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ContextTaskIdV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ContextTaskIdV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Canonical empty application input for authenticated Workspace status.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceStatusInputV1 {}

/// Canonical typed input for an authenticated v1 released-Object query.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectQueryReleasedInputV1 {
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "display_string")]
    pub environment_id: EnvironmentId,
    pub object_ids: SortedUnique<ObjectId, 1, MAX_DELEGATION_OBJECTS>,
}

/// Canonical typed input for an authenticated v1 Context build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextBuildInputV1 {
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    pub task_id: ContextTaskIdV1,
    #[serde(with = "change_set_intent_string")]
    pub intent: ChangeSetIntent,
    #[serde(with = "display_string")]
    pub environment_id: EnvironmentId,
    pub object_ids: SortedUnique<ObjectId, 1, MAX_DELEGATION_OBJECTS>,
    pub max_objects: MaxObjects,
    pub max_bytes: MaxContextBytes,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
}

/// Exact bounded localized Context limits carried by `context.build/v2`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedContextLimitsInputV2 {
    pub max_bytes: u64,
    pub max_edits: u32,
    pub max_objects: u32,
    pub max_validation_attempts: u32,
}

impl LocalizedContextLimitsInputV2 {
    fn validate(self) -> Result<(), AuthorityContractError> {
        if (1..=MAX_LOCALIZED_CONTEXT_BYTES).contains(&self.max_bytes)
            && (1..=MAX_LOCALIZED_EDITS).contains(&self.max_edits)
            && (1..=u32::try_from(MAX_LOCALIZED_TARGETS).unwrap_or(u32::MAX))
                .contains(&self.max_objects)
            && (1..=MAX_LOCALIZED_VALIDATION_ATTEMPTS).contains(&self.max_validation_attempts)
        {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "localized Context limits",
            ))
        }
    }

    /// Converts the strict operation contract to P-0007's application value.
    #[must_use]
    pub const fn into_application(self) -> LocalizedContextLimits {
        LocalizedContextLimits {
            max_objects: self.max_objects,
            max_edits: self.max_edits,
            max_validation_attempts: self.max_validation_attempts,
            max_bytes: self.max_bytes,
        }
    }
}

/// One normalized deterministic policy rule carried by `context.build/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedPolicyRuleInputV2 {
    pub disallowed_values: Vec<String>,
    #[serde(with = "display_string")]
    pub locale: LocaleId,
    pub pointer: String,
}

impl Ord for LocalizedPolicyRuleInputV2 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.locale, &self.pointer, &self.disallowed_values).cmp(&(
            &other.locale,
            &other.pointer,
            &other.disallowed_values,
        ))
    }
}

impl PartialOrd for LocalizedPolicyRuleInputV2 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl LocalizedPolicyRuleInputV2 {
    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        if self.disallowed_values.is_empty() || !is_canonical_json_pointer(&self.pointer) {
            return Err(AuthorityContractError::InvalidValue(
                "localized policy rule",
            ));
        }
        self.disallowed_values.sort();
        if self
            .disallowed_values
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(AuthorityContractError::InvalidValue(
                "localized policy rule",
            ));
        }
        Ok(())
    }

    fn into_application(self) -> LocalizedPolicyRule {
        LocalizedPolicyRule {
            locale: self.locale,
            pointer: self.pointer,
            disallowed_values: self.disallowed_values,
        }
    }
}

fn is_canonical_json_pointer(value: &str) -> bool {
    if !value.starts_with('/') {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            let Some(escaped) = bytes.get(index + 1) else {
                return false;
            };
            if !matches!(escaped, b'0' | b'1') {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

/// Strict normalized input for `context.build/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedContextBuildInputV2 {
    pub api_version: LocalizedContextBuildInputApiVersion,
    #[serde(with = "display_string")]
    pub context_pack_id: ContextPackId,
    #[serde(with = "display_string")]
    pub created_at: Timestamp,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
    pub limits: LocalizedContextLimitsInputV2,
    pub policy_rules: Vec<LocalizedPolicyRuleInputV2>,
    #[serde(with = "display_string")]
    pub resource_intent_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub resource_intent_id: ContentResourceIntentId,
}

impl LocalizedContextBuildInputV2 {
    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        self.limits.validate()?;
        if self.expires_at <= self.created_at {
            return Err(AuthorityContractError::InvalidValue(
                "localized Context lifetime",
            ));
        }
        for rule in &mut self.policy_rules {
            rule.normalize()?;
        }
        self.policy_rules.sort();
        if self
            .policy_rules
            .windows(2)
            .any(|pair| pair[0].locale == pair[1].locale && pair[0].pointer == pair[1].pointer)
        {
            return Err(AuthorityContractError::InvalidValue(
                "localized policy rules",
            ));
        }
        Ok(())
    }

    /// Converts exact replay material to P-0007's existing Human-path command shape.
    ///
    /// An authenticated Agent executor must first prove that the Human-path build
    /// operation already exists with this exact input; it must never use this
    /// conversion to originate or replace a `ContextPack`.
    #[must_use]
    pub fn into_application_command(self) -> BuildLocalizedContextCommand {
        BuildLocalizedContextCommand {
            context_pack_id: self.context_pack_id,
            resource_intent_id: self.resource_intent_id,
            resource_intent_digest: self.resource_intent_digest,
            policy_rules: self
                .policy_rules
                .into_iter()
                .map(LocalizedPolicyRuleInputV2::into_application)
                .collect(),
            limits: self.limits.into_application(),
            idempotency_key: self.idempotency_key,
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

/// Strict normalized input for `changeset.create/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedChangeSetCreateInputV2 {
    pub api_version: LocalizedChangeSetCreateInputApiVersion,
    #[serde(with = "display_string")]
    pub changeset_id: ChangeSetId,
    #[serde(with = "display_string")]
    pub context_pack_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub context_pack_id: ContextPackId,
    #[serde(with = "display_string")]
    pub created_at: Timestamp,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
    #[serde(with = "change_set_intent_string")]
    pub intent: ChangeSetIntent,
    #[serde(with = "display_string")]
    pub resource_intent_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub resource_intent_id: ContentResourceIntentId,
}

impl LocalizedChangeSetCreateInputV2 {
    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        if self.intent.as_str().chars().count() <= 500 {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "localized ChangeSet intent",
            ))
        }
    }

    /// Converts the normalized input to the existing P-0007 command.
    #[must_use]
    pub fn into_application_command(self) -> CreateLocalizedChangeSetCommand {
        CreateLocalizedChangeSetCommand {
            changeset_id: self.changeset_id,
            intent: self.intent,
            resource_intent_id: self.resource_intent_id,
            resource_intent_digest: self.resource_intent_digest,
            context_pack_id: self.context_pack_id,
            context_pack_digest: self.context_pack_digest,
            idempotency_key: self.idempotency_key,
            created_at: self.created_at,
        }
    }
}

/// Exact source precondition in one normalized `object.locale.put` input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedExpectedSourceInputV2 {
    #[serde(with = "display_string")]
    pub digest: ContentDigest,
    pub revision: u32,
    #[serde(with = "display_string")]
    pub schema_id: SchemaId,
    pub schema_version: u32,
}

/// Exact target precondition in one normalized `object.locale.put` input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedExpectedTargetInputV2 {
    #[serde(with = "display_string")]
    pub digest: ContentDigest,
    pub revision: u32,
}

/// Semantic Edit kinds admitted by the localized v2 profile.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LocalizedEditKindV2 {
    #[default]
    ObjectLocalePut,
    ObjectCreate,
}

impl LocalizedEditKindV2 {
    /// Returns the stable wire discriminator for this Edit kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObjectLocalePut => "object.locale.put",
            Self::ObjectCreate => "object.create",
        }
    }
}

impl Serialize for LocalizedEditKindV2 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for LocalizedEditKindV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <&'de str>::deserialize(deserializer)?;
        match value {
            "object.locale.put" => Ok(Self::ObjectLocalePut),
            "object.create" => Ok(Self::ObjectCreate),
            _ => Err(serde::de::Error::unknown_variant(
                value,
                &["object.locale.put", "object.create"],
            )),
        }
    }
}

/// One strict `object.locale.put` semantic Edit before Proof assigns its trusted `edit_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedObjectLocalePutEditInputV2 {
    pub api_version: LocalizedEditInputApiVersion,
    pub content: Map<String, Value>,
    pub expected_source: LocalizedExpectedSourceInputV2,
    pub expected_target: Option<LocalizedExpectedTargetInputV2>,
    #[serde(with = "display_string")]
    pub locale: LocaleId,
    #[serde(with = "display_string")]
    pub object_id: ObjectId,
    #[serde(with = "optional_display_string")]
    pub repair_of_validation_result_digest: Option<ContentDigest>,
    #[serde(with = "optional_display_string")]
    pub supersedes_edit_id: Option<EditId>,
}

/// One strict `object.create` semantic Edit before Proof assigns its trusted `edit_id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedObjectCreateEditInputV2 {
    pub api_version: LocalizedEditInputApiVersion,
    pub content: Map<String, Value>,
    #[serde(with = "display_string")]
    pub object_id: ObjectId,
    #[serde(with = "optional_display_string")]
    pub repair_of_validation_result_digest: Option<ContentDigest>,
    #[serde(with = "display_string")]
    pub schema_id: SchemaId,
    pub schema_version: u32,
    #[serde(with = "optional_display_string")]
    pub supersedes_edit_id: Option<EditId>,
}

/// One strict semantic Edit discriminated by its `kind` tag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind")]
pub enum LocalizedSemanticEditInputV2 {
    #[serde(rename = "object.locale.put")]
    ObjectLocalePut(LocalizedObjectLocalePutEditInputV2),
    #[serde(rename = "object.create")]
    ObjectCreate(LocalizedObjectCreateEditInputV2),
}

impl LocalizedSemanticEditInputV2 {
    /// Returns the semantic JSON content that Local canonicalizes through RFC 8785.
    #[must_use]
    pub const fn content(&self) -> &Map<String, Value> {
        match self {
            Self::ObjectLocalePut(input) => &input.content,
            Self::ObjectCreate(input) => &input.content,
        }
    }

    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        match self {
            Self::ObjectLocalePut(input) => {
                if input.expected_source.revision == 0
                    || input.expected_source.schema_version == 0
                    || input
                        .expected_target
                        .as_ref()
                        .is_some_and(|target| target.revision == 0)
                    || input.supersedes_edit_id.is_some()
                        != input.repair_of_validation_result_digest.is_some()
                {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized semantic Edit",
                    ));
                }
                Ok(())
            }
            Self::ObjectCreate(input) => {
                if input.schema_version == 0
                    || input.supersedes_edit_id.is_some()
                        != input.repair_of_validation_result_digest.is_some()
                {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized semantic Edit",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Converts the semantic input after Local supplies its verified RFC 8785 bytes.
    pub fn into_application_input(
        self,
        canonical_content: String,
    ) -> Result<LocalizedEditAttempt, AuthorityContractError> {
        match self {
            Self::ObjectLocalePut(input) => {
                let parsed: Value = serde_json::from_str(&canonical_content)
                    .map_err(|_| AuthorityContractError::InvalidValue("localized Edit content"))?;
                if parsed != Value::Object(input.content) {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized Edit canonical content",
                    ));
                }
                Ok(LocalizedEditAttempt::LocalePut(ObjectLocalePutInput {
                    object_id: input.object_id,
                    locale: input.locale,
                    expected_source: ExpectedLocalizedSource {
                        revision: ObjectRevision::new(input.expected_source.revision)
                            .map_err(|_| AuthorityContractError::InvalidValue("source revision"))?,
                        digest: input.expected_source.digest,
                        schema_id: input.expected_source.schema_id,
                        schema_version: SchemaVersion::new(input.expected_source.schema_version)
                            .map_err(|_| AuthorityContractError::InvalidValue("Schema version"))?,
                    },
                    expected_target: input
                        .expected_target
                        .map(|target| {
                            Ok(ExpectedLocalizedTarget {
                                revision: LocaleRevision::new(target.revision).map_err(|_| {
                                    AuthorityContractError::InvalidValue("target revision")
                                })?,
                                digest: target.digest,
                            })
                        })
                        .transpose()?,
                    canonical_content,
                    supersedes_edit_id: input.supersedes_edit_id,
                    repair_of_validation_result_digest: input.repair_of_validation_result_digest,
                }))
            }
            Self::ObjectCreate(input) => {
                let parsed: Value = serde_json::from_str(&canonical_content)
                    .map_err(|_| AuthorityContractError::InvalidValue("localized Edit content"))?;
                if parsed != Value::Object(input.content) {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized Edit canonical content",
                    ));
                }
                Ok(LocalizedEditAttempt::ObjectCreate(ObjectCreateInput {
                    object_id: input.object_id,
                    schema_id: input.schema_id,
                    schema_version: SchemaVersion::new(input.schema_version)
                        .map_err(|_| AuthorityContractError::InvalidValue("Schema version"))?,
                    canonical_content,
                    supersedes_edit_id: input.supersedes_edit_id,
                    repair_of_validation_result_digest: input.repair_of_validation_result_digest,
                }))
            }
        }
    }
}

/// Strict normalized input for `changeset.add/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedChangeSetAddInputV2 {
    pub api_version: LocalizedChangeSetAddInputApiVersion,
    #[serde(with = "display_string")]
    pub changeset_id: ChangeSetId,
    pub edits: Vec<LocalizedSemanticEditInputV2>,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
}

impl LocalizedChangeSetAddInputV2 {
    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        if self.edits.is_empty()
            || self.edits.len() > usize::try_from(MAX_LOCALIZED_EDITS).unwrap_or(usize::MAX)
        {
            return Err(AuthorityContractError::InvalidValue("localized Edit batch"));
        }
        for edit in &mut self.edits {
            edit.normalize()?;
        }
        Ok(())
    }
}

macro_rules! localized_changeset_selector_input {
    ($name:ident, $api:ty) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub api_version: $api,
            #[serde(with = "display_string")]
            pub changeset_id: ChangeSetId,
        }
    };
}

localized_changeset_selector_input!(
    LocalizedChangeSetGetInputV2,
    LocalizedChangeSetGetInputApiVersion
);
localized_changeset_selector_input!(
    LocalizedChangeSetDiffInputV2,
    LocalizedChangeSetDiffInputApiVersion
);
localized_changeset_selector_input!(
    LocalizedChangeSetValidateInputV2,
    LocalizedChangeSetValidateInputApiVersion
);

/// Strict normalized input for `changeset.submit/v2`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedChangeSetSubmitInputV2 {
    pub api_version: LocalizedChangeSetSubmitInputApiVersion,
    #[serde(with = "display_string")]
    pub changeset_id: ChangeSetId,
    #[serde(with = "display_string")]
    pub submitted_at: Timestamp,
}

/// Strict normalized input for `changeset.commit/v2`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedChangeSetCommitInputV2 {
    pub api_version: LocalizedChangeSetCommitInputApiVersion,
    #[serde(with = "display_string")]
    pub changeset_id: ChangeSetId,
    #[serde(with = "display_string")]
    pub committed_at: Timestamp,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
}

impl LocalizedChangeSetCommitInputV2 {
    /// Converts the normalized input to the existing P-0007 command.
    #[must_use]
    pub const fn into_application_command(self) -> CommitLocalizedChangeSetCommand {
        CommitLocalizedChangeSetCommand {
            changeset_id: self.changeset_id,
            idempotency_key: self.idempotency_key,
            committed_at: self.committed_at,
        }
    }
}

/// Strict normalized input for `edition.create/v2`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedEditionCreateInputV2 {
    pub api_version: LocalizedEditionCreateInputApiVersion,
    #[serde(with = "display_string")]
    pub changeset_id: ChangeSetId,
    #[serde(with = "display_string")]
    pub created_at: Timestamp,
    #[serde(with = "display_string")]
    pub edition_id: EditionId,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
    #[serde(with = "display_string")]
    pub resulting_state_digest: ContentDigest,
}

impl LocalizedEditionCreateInputV2 {
    /// Converts the normalized input to the existing P-0007 command.
    #[must_use]
    pub const fn into_application_command(self) -> CreateLocalizedEditionCommand {
        CreateLocalizedEditionCommand {
            edition_id: self.edition_id,
            changeset_id: self.changeset_id,
            resulting_state_digest: self.resulting_state_digest,
            idempotency_key: self.idempotency_key,
            created_at: self.created_at,
        }
    }
}

/// Strict normalized input for `release.create/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedReleaseCreateInputV2 {
    pub api_version: LocalizedReleaseCreateInputApiVersion,
    #[serde(with = "display_string")]
    pub edition_id: EditionId,
    #[serde(with = "display_string")]
    pub environment_id: EnvironmentId,
    #[serde(with = "display_string")]
    pub expected_base_release_id: ReleaseId,
    #[serde(with = "display_string")]
    pub idempotency_key: IdempotencyKey,
    #[serde(with = "display_string")]
    pub proof_id: ProofId,
    #[serde(with = "display_string")]
    pub release_id: ReleaseId,
    #[serde(with = "display_string")]
    pub released_at: Timestamp,
}

impl LocalizedReleaseCreateInputV2 {
    /// Converts the normalized input to P-0007's promotion command.
    #[must_use]
    pub fn into_application_command(self) -> PromoteLocalizedReleaseCommand {
        PromoteLocalizedReleaseCommand {
            release_id: self.release_id,
            proof_id: self.proof_id,
            environment_id: self.environment_id,
            edition_id: self.edition_id,
            expected_base_release_id: self.expected_base_release_id,
            idempotency_key: self.idempotency_key,
            released_at: self.released_at,
        }
    }
}

/// One strict sorted released-rendition target.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedReleasedTargetInputV2 {
    #[serde(with = "display_string")]
    pub locale: LocaleId,
    #[serde(with = "display_string")]
    pub object_id: ObjectId,
}

impl Ord for LocalizedReleasedTargetInputV2 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (&self.object_id, &self.locale).cmp(&(&other.object_id, &other.locale))
    }
}

impl PartialOrd for LocalizedReleasedTargetInputV2 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Strict normalized input for `object.query_released/v2`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedObjectQueryReleasedInputV2 {
    pub api_version: LocalizedObjectQueryReleasedInputApiVersion,
    #[serde(with = "display_string")]
    pub environment_id: EnvironmentId,
    #[serde(with = "display_string")]
    pub evaluated_at: Timestamp,
    pub targets: Vec<LocalizedReleasedTargetInputV2>,
}

impl LocalizedObjectQueryReleasedInputV2 {
    fn normalize(&mut self) -> Result<(), AuthorityContractError> {
        if self.targets.is_empty() || self.targets.len() > MAX_LOCALIZED_TARGETS {
            return Err(AuthorityContractError::InvalidValue(
                "released-rendition targets",
            ));
        }
        self.targets.sort();
        if self.targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AuthorityContractError::InvalidValue(
                "released-rendition targets",
            ));
        }
        Ok(())
    }

    /// Converts the normalized input to the existing P-0007 query command.
    #[must_use]
    pub fn into_application_command(self) -> QueryReleasedRenditionsCommand {
        QueryReleasedRenditionsCommand {
            environment_id: self.environment_id,
            targets: self
                .targets
                .into_iter()
                .map(|target| ReleasedLocaleTarget {
                    object_id: target.object_id,
                    locale: target.locale,
                })
                .collect(),
            evaluated_at: self.evaluated_at,
        }
    }
}

/// Validated canonical input for one enabled authenticated operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnabledOperationInputV1 {
    WorkspaceStatus(WorkspaceStatusInputV1),
    ObjectQueryReleased(ObjectQueryReleasedInputV1),
    ContextBuild(ContextBuildInputV1),
    LocalizedContextBuild(LocalizedContextBuildInputV2),
    LocalizedChangeSetCreate(LocalizedChangeSetCreateInputV2),
    LocalizedChangeSetAdd(LocalizedChangeSetAddInputV2),
    LocalizedChangeSetGet(LocalizedChangeSetGetInputV2),
    LocalizedChangeSetDiff(LocalizedChangeSetDiffInputV2),
    LocalizedChangeSetValidate(LocalizedChangeSetValidateInputV2),
    LocalizedChangeSetSubmit(LocalizedChangeSetSubmitInputV2),
    LocalizedChangeSetCommit(LocalizedChangeSetCommitInputV2),
    LocalizedEditionCreate(LocalizedEditionCreateInputV2),
    LocalizedReleaseCreate(LocalizedReleaseCreateInputV2),
    LocalizedObjectQueryReleased(LocalizedObjectQueryReleasedInputV2),
}

impl EnabledOperationInputV1 {
    /// Returns the exact operation selected by this typed input.
    #[must_use]
    pub const fn operation(&self) -> AuthorityOperation {
        match self {
            Self::WorkspaceStatus(_) => AuthorityOperation::WorkspaceStatusV1,
            Self::ObjectQueryReleased(_) => AuthorityOperation::ObjectQueryReleasedV1,
            Self::ContextBuild(_) => AuthorityOperation::ContextBuildV1,
            Self::LocalizedContextBuild(_) => AuthorityOperation::ContextBuildV2,
            Self::LocalizedChangeSetCreate(_) => AuthorityOperation::ChangesetCreateV2,
            Self::LocalizedChangeSetAdd(_) => AuthorityOperation::ChangesetAddV2,
            Self::LocalizedChangeSetGet(_) => AuthorityOperation::ChangesetGetV2,
            Self::LocalizedChangeSetDiff(_) => AuthorityOperation::ChangesetDiffV2,
            Self::LocalizedChangeSetValidate(_) => AuthorityOperation::ChangesetValidateV2,
            Self::LocalizedChangeSetSubmit(_) => AuthorityOperation::ChangesetSubmitV2,
            Self::LocalizedChangeSetCommit(_) => AuthorityOperation::ChangesetCommitV2,
            Self::LocalizedEditionCreate(_) => AuthorityOperation::EditionCreateV2,
            Self::LocalizedReleaseCreate(_) => AuthorityOperation::ReleaseCreateV2,
            Self::LocalizedObjectQueryReleased(_) => AuthorityOperation::ObjectQueryReleasedV2,
        }
    }

    /// Returns the caller-visible idempotency key embedded by the operation, if any.
    #[must_use]
    pub const fn application_idempotency_key(&self) -> Option<IdempotencyKey> {
        match self {
            Self::ContextBuild(input) => Some(input.idempotency_key),
            Self::LocalizedContextBuild(input) => Some(input.idempotency_key),
            Self::LocalizedChangeSetCreate(input) => Some(input.idempotency_key),
            Self::LocalizedChangeSetAdd(input) => Some(input.idempotency_key),
            Self::LocalizedChangeSetCommit(input) => Some(input.idempotency_key),
            Self::LocalizedEditionCreate(input) => Some(input.idempotency_key),
            Self::LocalizedReleaseCreate(input) => Some(input.idempotency_key),
            Self::WorkspaceStatus(_)
            | Self::ObjectQueryReleased(_)
            | Self::LocalizedChangeSetGet(_)
            | Self::LocalizedChangeSetDiff(_)
            | Self::LocalizedChangeSetValidate(_)
            | Self::LocalizedChangeSetSubmit(_)
            | Self::LocalizedObjectQueryReleased(_) => None,
        }
    }

    /// Returns the signed semantic operation timestamp as evidence metadata.
    ///
    /// Authority evaluation time is independently injected and is not required to equal it.
    #[must_use]
    pub const fn semantic_timestamp(&self) -> Option<Timestamp> {
        match self {
            Self::LocalizedContextBuild(input) => Some(input.created_at),
            Self::LocalizedChangeSetCreate(input) => Some(input.created_at),
            Self::LocalizedChangeSetSubmit(input) => Some(input.submitted_at),
            Self::LocalizedChangeSetCommit(input) => Some(input.committed_at),
            Self::LocalizedEditionCreate(input) => Some(input.created_at),
            Self::LocalizedReleaseCreate(input) => Some(input.released_at),
            Self::LocalizedObjectQueryReleased(input) => Some(input.evaluated_at),
            Self::WorkspaceStatus(_)
            | Self::ObjectQueryReleased(_)
            | Self::ContextBuild(_)
            | Self::LocalizedChangeSetAdd(_)
            | Self::LocalizedChangeSetGet(_)
            | Self::LocalizedChangeSetDiff(_)
            | Self::LocalizedChangeSetValidate(_) => None,
        }
    }

    /// Serializes the typed input back to the canonical semantic-command object.
    pub fn normalized_input(&self) -> Result<Map<String, Value>, AuthorityContractError> {
        match self {
            Self::WorkspaceStatus(value) => normalized_input_map(value),
            Self::ObjectQueryReleased(value) => normalized_input_map(value),
            Self::ContextBuild(value) => normalized_input_map(value),
            Self::LocalizedContextBuild(value) => normalized_input_map(value),
            Self::LocalizedChangeSetCreate(value) => normalized_input_map(value),
            Self::LocalizedChangeSetAdd(value) => normalized_input_map(value),
            Self::LocalizedChangeSetGet(value) => normalized_input_map(value),
            Self::LocalizedChangeSetDiff(value) => normalized_input_map(value),
            Self::LocalizedChangeSetValidate(value) => normalized_input_map(value),
            Self::LocalizedChangeSetSubmit(value) => normalized_input_map(value),
            Self::LocalizedChangeSetCommit(value) => normalized_input_map(value),
            Self::LocalizedEditionCreate(value) => normalized_input_map(value),
            Self::LocalizedReleaseCreate(value) => normalized_input_map(value),
            Self::LocalizedObjectQueryReleased(value) => normalized_input_map(value),
        }
    }

    fn normalize(command: &CommandInputV1) -> Result<Self, AuthorityContractError> {
        match command.operation {
            AuthorityOperation::WorkspaceStatusV1 => {
                let input = deserialize_normalized_input::<WorkspaceStatusInputV1>(
                    &command.normalized_input,
                )?;
                Ok(Self::WorkspaceStatus(input))
            }
            AuthorityOperation::ObjectQueryReleasedV1 => {
                let raw = deserialize_normalized_input::<RawObjectQueryReleasedInputV1>(
                    &command.normalized_input,
                )?;
                let input = ObjectQueryReleasedInputV1 {
                    operating_principal_id: raw.operating_principal_id,
                    delegation_id: raw.delegation_id,
                    environment_id: raw.environment_id,
                    object_ids: SortedUnique::normalize(raw.object_ids)?,
                };
                input.validate_repeated_fields(command)?;
                Ok(Self::ObjectQueryReleased(input))
            }
            AuthorityOperation::ContextBuildV1 => {
                let raw = deserialize_normalized_input::<RawContextBuildInputV1>(
                    &command.normalized_input,
                )?;
                let input = ContextBuildInputV1 {
                    operating_principal_id: raw.operating_principal_id,
                    delegation_id: raw.delegation_id,
                    task_id: ContextTaskIdV1::new(raw.task_id)?,
                    intent: ChangeSetIntent::new(raw.intent)
                        .map_err(|_| AuthorityContractError::InvalidValue("context intent"))?,
                    environment_id: raw.environment_id,
                    object_ids: SortedUnique::normalize(raw.object_ids)?,
                    max_objects: MaxObjects::new(raw.max_objects)?,
                    max_bytes: MaxContextBytes::new(raw.max_bytes)?,
                    idempotency_key: raw.idempotency_key,
                    expires_at: raw.expires_at,
                };
                input.validate_repeated_fields(command)?;
                Ok(Self::ContextBuild(input))
            }
            AuthorityOperation::ContextBuildV2 => {
                let mut input: LocalizedContextBuildInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Ok(Self::LocalizedContextBuild(input))
            }
            AuthorityOperation::ChangesetCreateV2 => {
                let mut input: LocalizedChangeSetCreateInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Ok(Self::LocalizedChangeSetCreate(input))
            }
            AuthorityOperation::ChangesetAddV2 => {
                let mut input: LocalizedChangeSetAddInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Ok(Self::LocalizedChangeSetAdd(input))
            }
            AuthorityOperation::ChangesetGetV2 => Ok(Self::LocalizedChangeSetGet(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ChangesetDiffV2 => Ok(Self::LocalizedChangeSetDiff(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ChangesetValidateV2 => Ok(Self::LocalizedChangeSetValidate(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ChangesetSubmitV2 => Ok(Self::LocalizedChangeSetSubmit(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ChangesetCommitV2 => Ok(Self::LocalizedChangeSetCommit(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::EditionCreateV2 => Ok(Self::LocalizedEditionCreate(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ReleaseCreateV2 => Ok(Self::LocalizedReleaseCreate(
                deserialize_normalized_input(&command.normalized_input)?,
            )),
            AuthorityOperation::ObjectQueryReleasedV2 => {
                let mut input: LocalizedObjectQueryReleasedInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Ok(Self::LocalizedObjectQueryReleased(input))
            }
        }
    }

    fn from_canonical(command: &CommandInputV1) -> Result<Self, AuthorityContractError> {
        let input = match command.operation {
            AuthorityOperation::WorkspaceStatusV1 => {
                Self::WorkspaceStatus(deserialize_normalized_input(&command.normalized_input)?)
            }
            AuthorityOperation::ObjectQueryReleasedV1 => {
                let input: ObjectQueryReleasedInputV1 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.validate_repeated_fields(command)?;
                Self::ObjectQueryReleased(input)
            }
            AuthorityOperation::ContextBuildV1 => {
                let input: ContextBuildInputV1 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.validate_repeated_fields(command)?;
                Self::ContextBuild(input)
            }
            AuthorityOperation::ContextBuildV2 => {
                let mut input: LocalizedContextBuildInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Self::LocalizedContextBuild(input)
            }
            AuthorityOperation::ChangesetCreateV2 => {
                let mut input: LocalizedChangeSetCreateInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Self::LocalizedChangeSetCreate(input)
            }
            AuthorityOperation::ChangesetAddV2 => {
                let mut input: LocalizedChangeSetAddInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Self::LocalizedChangeSetAdd(input)
            }
            AuthorityOperation::ChangesetGetV2 => Self::LocalizedChangeSetGet(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ChangesetDiffV2 => Self::LocalizedChangeSetDiff(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ChangesetValidateV2 => Self::LocalizedChangeSetValidate(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ChangesetSubmitV2 => Self::LocalizedChangeSetSubmit(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ChangesetCommitV2 => Self::LocalizedChangeSetCommit(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::EditionCreateV2 => Self::LocalizedEditionCreate(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ReleaseCreateV2 => Self::LocalizedReleaseCreate(
                deserialize_normalized_input(&command.normalized_input)?,
            ),
            AuthorityOperation::ObjectQueryReleasedV2 => {
                let mut input: LocalizedObjectQueryReleasedInputV2 =
                    deserialize_normalized_input(&command.normalized_input)?;
                input.normalize()?;
                Self::LocalizedObjectQueryReleased(input)
            }
        };
        if input.normalized_input()? == command.normalized_input {
            Ok(input)
        } else {
            Err(AuthorityContractError::InvalidValue(
                "canonical normalized operation input",
            ))
        }
    }
}

impl ObjectQueryReleasedInputV1 {
    fn validate_repeated_fields(
        &self,
        command: &CommandInputV1,
    ) -> Result<(), AuthorityContractError> {
        if self.operating_principal_id == command.operating_principal_id
            && self.delegation_id == command.delegation_id
        {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "repeated operation authority fields",
            ))
        }
    }
}

impl ContextBuildInputV1 {
    fn validate_repeated_fields(
        &self,
        command: &CommandInputV1,
    ) -> Result<(), AuthorityContractError> {
        if self.operating_principal_id == command.operating_principal_id
            && self.delegation_id == command.delegation_id
            && command.idempotency_key == Some(self.idempotency_key)
            && self.object_ids.as_slice().len() <= self.max_objects.get() as usize
        {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "repeated operation authority fields or Context limits",
            ))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObjectQueryReleasedInputV1 {
    #[serde(with = "display_string")]
    operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    delegation_id: DelegationId,
    #[serde(with = "display_string")]
    environment_id: EnvironmentId,
    #[serde(deserialize_with = "display_string_vec::deserialize")]
    object_ids: Vec<ObjectId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContextBuildInputV1 {
    #[serde(with = "display_string")]
    operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    delegation_id: DelegationId,
    task_id: String,
    intent: String,
    #[serde(with = "display_string")]
    environment_id: EnvironmentId,
    #[serde(deserialize_with = "display_string_vec::deserialize")]
    object_ids: Vec<ObjectId>,
    max_objects: u32,
    max_bytes: u32,
    #[serde(with = "display_string")]
    idempotency_key: IdempotencyKey,
    #[serde(with = "display_string")]
    expires_at: Timestamp,
}

fn deserialize_normalized_input<T: for<'de> Deserialize<'de>>(
    input: &Map<String, Value>,
) -> Result<T, AuthorityContractError> {
    serde_json::from_value(Value::Object(input.clone()))
        .map_err(|_| AuthorityContractError::InvalidValue("normalized operation input"))
}

fn normalized_input_map<T: Serialize>(
    input: &T,
) -> Result<Map<String, Value>, AuthorityContractError> {
    match serde_json::to_value(input)
        .map_err(|_| AuthorityContractError::InvalidValue("normalized operation input"))?
    {
        Value::Object(map) => Ok(map),
        _ => Err(AuthorityContractError::InvalidValue(
            "normalized operation input",
        )),
    }
}

/// Exact semantic command normalized before signing.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandInputV1 {
    pub api_version: CommandInputApiVersion,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub operation: AuthorityOperation,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "optional_display_string")]
    pub idempotency_key: Option<IdempotencyKey>,
    pub normalized_input: Map<String, Value>,
}

impl CommandInputV1 {
    fn validate_registry_and_idempotency(
        &self,
    ) -> Result<&'static AuthorityOperationEntry, AuthorityContractError> {
        let entry = authority_operation_entry(self.operation);
        let idempotency_matches = match entry.application_idempotency {
            ApplicationIdempotency::RequiredUuidV7 => self.idempotency_key.is_some(),
            ApplicationIdempotency::None => self.idempotency_key.is_none(),
            ApplicationIdempotency::DerivedChangeset
            | ApplicationIdempotency::DerivedProposalPolicyValidator => {
                self.idempotency_key.is_none()
            }
        };
        if idempotency_matches {
            Ok(entry)
        } else {
            Err(AuthorityContractError::InvalidValue(
                "operation idempotency field",
            ))
        }
    }

    /// Canonicalizes one freshly constructed transport command.
    ///
    /// Unknown fields, duplicate Objects, invalid bounds, and repeated authority
    /// mismatches fail. Valid unique Objects are sorted before replacement.
    pub fn normalize_for_authenticated_execution(
        &mut self,
    ) -> Result<EnabledOperationInputV1, AuthorityContractError> {
        self.validate_registry_and_idempotency()?;
        let input = EnabledOperationInputV1::normalize(self)?;
        if input.application_idempotency_key() != self.idempotency_key {
            return Err(AuthorityContractError::InvalidValue(
                "operation idempotency cross-check",
            ));
        }
        self.normalized_input = input.normalized_input()?;
        Ok(input)
    }

    /// Decodes an already canonical signed v1 input without changing it.
    pub fn normalized_operation_input(
        &self,
    ) -> Result<EnabledOperationInputV1, AuthorityContractError> {
        self.validate_registry_and_idempotency()?;
        let input = EnabledOperationInputV1::from_canonical(self)?;
        if input.application_idempotency_key() == self.idempotency_key {
            Ok(input)
        } else {
            Err(AuthorityContractError::InvalidValue(
                "operation idempotency cross-check",
            ))
        }
    }

    /// Validates the P-0004 exposure and exact signed application-idempotency shape.
    pub fn validate_for_authenticated_execution(
        &self,
    ) -> Result<&'static AuthorityOperationEntry, AuthorityContractError> {
        let entry = self.validate_registry_and_idempotency()?;
        self.normalized_operation_input()?;
        Ok(entry)
    }
}

/// One single-use signed command assertion payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCommandV1 {
    pub api_version: AuthenticatedCommandApiVersion,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub operation: AuthorityOperation,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "optional_display_string")]
    pub idempotency_key: Option<IdempotencyKey>,
    #[serde(with = "display_string")]
    pub presentation_id: PresentationId,
    #[serde(with = "display_string")]
    pub issued_at: Timestamp,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
}

impl CommandInputV1 {
    /// Validates every signed outer-field duplicate and independently derived actor.
    ///
    /// Signature, binding, and semantic-digest verification remain adapter work;
    /// this method closes the transport-independent equality boundary after those
    /// values have been resolved.
    pub fn validate_authenticated_command(
        &self,
        authenticated_command: &AuthenticatedCommandV1,
        derived_requesting_principal_id: PrincipalId,
        derived_operating_principal_id: PrincipalId,
    ) -> Result<EnabledOperationInputV1, AuthorityContractError> {
        let input = self.normalized_operation_input()?;
        let matches = authenticated_command.audience
            == AuthorityAudience::for_workspace(self.workspace_id)
            && authenticated_command.workspace_id == self.workspace_id
            && authenticated_command.operation == self.operation
            && authenticated_command.requesting_principal_id == self.requesting_principal_id
            && authenticated_command.operating_principal_id == self.operating_principal_id
            && authenticated_command.delegation_id == self.delegation_id
            && authenticated_command.idempotency_key == self.idempotency_key
            && derived_requesting_principal_id == self.requesting_principal_id
            && derived_operating_principal_id == self.operating_principal_id;
        if matches {
            Ok(input)
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authenticated command cross-checks",
            ))
        }
    }
}

/// Exact canonical authenticated-command envelope JSON carried by a broker frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedCommandEnvelopeJson(String);

impl AuthenticatedCommandEnvelopeJson {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorityContractError> {
        let value = value.into();
        if !value.is_empty() && value.len() <= MAX_AUTHENTICATED_ENVELOPE_BYTES {
            Ok(Self(value))
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authenticated command envelope",
            ))
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuthenticatedCommandEnvelopeJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl FromStr for AuthenticatedCommandEnvelopeJson {
    type Err = AuthorityContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// One bounded signer-to-broker frame.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedInvocationV1 {
    pub api_version: AuthenticatedInvocationApiVersion,
    pub command_input: CommandInputV1,
    #[serde(with = "display_string")]
    pub authentication: AuthenticatedCommandEnvelopeJson,
}

/// Ratified adapter-constructed Human/Agent authentication profile.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthenticationProfileV1 {
    #[default]
    #[serde(rename = "proof.local/authentication/human-agent/v1")]
    HumanAgent,
}

/// Private trusted runtime actor context; the raw Unix subject must not persist.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextV1 {
    pub api_version: ActorContextApiVersion,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub authentication_profile: AuthenticationProfileV1,
    pub requesting_subject: UnixAuthenticatedSubjectV1,
    #[serde(with = "display_string")]
    pub requesting_subject_commitment: ContentDigest,
    pub operating_subject: LocalEd25519AuthenticatedSubjectV1,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    pub operation: AuthorityOperation,
    #[serde(with = "display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub command_envelope_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub presentation_id: PresentationId,
    #[serde(with = "display_string")]
    pub authenticated_at: Timestamp,
}

/// Persistable actor context digest preimage that cannot disclose the raw Unix UID.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedActorContextEvidenceV1 {
    pub api_version: ActorContextEvidenceApiVersion,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub authentication_profile: AuthenticationProfileV1,
    #[serde(with = "display_string")]
    pub requesting_subject_commitment: ContentDigest,
    pub operating_subject: LocalEd25519AuthenticatedSubjectV1,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    pub operation: AuthorityOperation,
    #[serde(with = "display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub command_envelope_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub presentation_id: PresentationId,
    #[serde(with = "display_string")]
    pub authenticated_at: Timestamp,
}

impl From<&AuthenticatedActorContextV1> for AuthenticatedActorContextEvidenceV1 {
    fn from(context: &AuthenticatedActorContextV1) -> Self {
        Self {
            api_version: ActorContextEvidenceApiVersion::V1,
            audience: context.audience,
            workspace_id: context.workspace_id,
            authentication_profile: context.authentication_profile,
            requesting_subject_commitment: context.requesting_subject_commitment,
            operating_subject: context.operating_subject.clone(),
            binding_id: context.binding_id,
            requesting_principal_id: context.requesting_principal_id,
            operating_principal_id: context.operating_principal_id,
            delegation_id: context.delegation_id,
            operation: context.operation,
            command_digest: context.command_digest,
            command_envelope_digest: context.command_envelope_digest,
            presentation_id: context.presentation_id,
            authenticated_at: context.authenticated_at,
        }
    }
}

/// Ed25519 algorithm marker required by all v1 local authority keys.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Ed25519Algorithm {
    #[default]
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// Principal class admitted to the v1 authority log.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPrincipalType {
    Agent,
    Human,
}

impl fmt::Display for AuthorityPrincipalType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Agent => "agent",
            Self::Human => "human",
        })
    }
}

impl FromStr for AuthorityPrincipalType {
    type Err = AuthorityContractError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent" => Ok(Self::Agent),
            "human" => Ok(Self::Human),
            _ => Err(AuthorityContractError::InvalidValue(
                "authority principal type",
            )),
        }
    }
}

/// Constant Agent marker used by `PrincipalBindingV1`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum AgentPrincipalType {
    #[default]
    #[serde(rename = "agent")]
    Agent,
}

/// Constant authenticated-command key usage.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthenticatedCommandKeyUsage {
    #[default]
    #[serde(rename = "authenticated-command")]
    AuthenticatedCommand,
}

/// Constant direct authority/delegation policy profile.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum DirectAuthorityProfileV1 {
    #[default]
    #[serde(rename = "proof.local/authority/direct/v1")]
    Direct,
}

/// Schema marker that serializes only as `false`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubdelegationDisabled;

impl Serialize for SubdelegationDisabled {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for SubdelegationDisabled {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Err(serde::de::Error::custom("subdelegation must be false"))
        } else {
            Ok(Self)
        }
    }
}

/// Single-use proof-of-possession challenge for one candidate binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingEnrollmentChallengeV1 {
    pub api_version: EnrollmentChallengeApiVersion,
    #[serde(with = "display_string")]
    pub challenge_id: EnrollmentChallengeId,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub principal_id: PrincipalId,
    pub candidate_key_id: Ed25519KeyId,
    #[serde(with = "display_string")]
    pub issued_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub issued_at: Timestamp,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
}

impl BindingEnrollmentChallengeV1 {
    /// Checks audience equality and the inclusive-start/exclusive-expiry interval.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        if self.audience.workspace_id() != self.workspace_id
            || self.issued_at >= self.expires_at
            || self.expires_at.unix_timestamp_nanos() - self.issued_at.unix_timestamp_nanos()
                > i128::from(MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000
        {
            Err(AuthorityContractError::InvalidValue(
                "binding enrollment challenge",
            ))
        } else {
            Ok(())
        }
    }
}

/// Immutable, authority-signed Agent Principal-to-key binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBindingV1 {
    pub api_version: PrincipalBindingApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "optional_display_string")]
    pub previous_authority_record_digest: Option<ContentDigest>,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub principal_id: PrincipalId,
    pub principal_type: AgentPrincipalType,
    pub authenticated_subject: LocalEd25519AuthenticatedSubjectV1,
    pub algorithm: Ed25519Algorithm,
    pub public_key: Ed25519PublicKey,
    pub key_usage: AuthenticatedCommandKeyUsage,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub enrollment_challenge_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub enrollment_envelope_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub issued_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub issued_at: Timestamp,
    #[serde(with = "display_string")]
    pub not_before: Timestamp,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
    #[serde(with = "optional_display_string")]
    pub supersedes_binding_id: Option<BindingId>,
}

impl PrincipalBindingV1 {
    /// Enforces profile, audience, subject, and temporal invariants independent of storage.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        let public_key_matches_subject = self.public_key.key_id().is_ok_and(|key_id| {
            self.authenticated_subject.as_subject().subject() == key_id.as_str()
        });
        if !public_key_matches_subject
            || self.audience.workspace_id() != self.workspace_id
            || self.issued_at > self.not_before
            || self.not_before >= self.expires_at
            || self.supersedes_binding_id == Some(self.binding_id)
        {
            Err(AuthorityContractError::InvalidValue("principal binding"))
        } else {
            Ok(())
        }
    }

    /// Returns true exactly at `not_before <= evaluated_at < expires_at`.
    #[must_use]
    pub fn is_time_active(&self, evaluated_at: Timestamp) -> bool {
        self.not_before <= evaluated_at && evaluated_at < self.expires_at
    }
}

/// Append-only Principal enablement/terminal-disablement fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalStatusV1 {
    pub api_version: PrincipalStatusApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "optional_display_string")]
    pub previous_authority_record_digest: Option<ContentDigest>,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub principal_id: PrincipalId,
    pub principal_type: AuthorityPrincipalType,
    pub enabled: bool,
    #[serde(with = "display_string")]
    pub recorded_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub recorded_at: Timestamp,
}

/// Why a Principal binding was causally revoked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalBindingRevocationReason {
    Administrative,
    Compromise,
    Disablement,
    Recovery,
    Rotation,
}

/// Immutable causal binding-revocation fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalBindingRevocationV1 {
    pub api_version: PrincipalBindingRevocationApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub previous_authority_record_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub revocation_id: RevocationId,
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    #[serde(with = "display_string")]
    pub revoked_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub revoked_at: Timestamp,
    pub reason: PrincipalBindingRevocationReason,
}

pub type DelegationActionsV2 = SortedUnique<AuthorityAction, 1, 12>;
pub type DelegationEnvironmentIdsV2 = SortedUnique<EnvironmentId, 0, 32>;
pub type DelegationObjectIdsV2 = SortedUnique<ObjectId, 0, 100>;
pub type DelegationSchemaIdsV2 = SortedUnique<SchemaId, 0, 100>;
pub type DelegationLocalesV2 = SortedUnique<LocaleId, 0, 64>;

/// Exact-set resource dimensions for one direct grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationScopeV2 {
    pub environment_ids: DelegationEnvironmentIdsV2,
    pub object_ids: DelegationObjectIdsV2,
    pub schema_ids: DelegationSchemaIdsV2,
    pub locales: DelegationLocalesV2,
}

/// Deterministic direct-grant budgets.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationConstraintsV2 {
    pub max_objects: MaxObjects,
    pub max_context_bytes: MaxContextBytes,
    pub max_edits_per_changeset: MaxEditsPerChangeSet,
    pub allow_subdelegation: SubdelegationDisabled,
}

/// One immutable direct Human-to-Agent grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationV2 {
    pub api_version: DelegationApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "optional_display_string")]
    pub previous_authority_record_digest: Option<ContentDigest>,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub delegation_profile: DirectAuthorityProfileV1,
    #[serde(with = "display_string")]
    pub issuer_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub recipient_principal_id: PrincipalId,
    pub actions: DelegationActionsV2,
    pub scope: DelegationScopeV2,
    pub constraints: DelegationConstraintsV2,
    #[serde(with = "display_string")]
    pub not_before: Timestamp,
    #[serde(with = "display_string")]
    pub expires_at: Timestamp,
    #[serde(with = "display_string")]
    pub issued_at: Timestamp,
}

impl DelegationV2 {
    /// Enforces direct-grant temporal and actor separation invariants.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        if self.issued_at > self.not_before
            || self.not_before >= self.expires_at
            || self.issuer_principal_id == self.recipient_principal_id
        {
            Err(AuthorityContractError::InvalidValue("direct delegation"))
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn is_time_active(&self, evaluated_at: Timestamp) -> bool {
        self.not_before <= evaluated_at && evaluated_at < self.expires_at
    }
}

/// Why a direct Delegation was causally revoked.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationRevocationReasonV1 {
    Administrative,
    Compromise,
    IssuerRequest,
    ScopeChange,
}

/// Immutable causal Delegation-revocation fact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRevocationV1 {
    pub api_version: DelegationRevocationApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub previous_authority_record_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub revocation_id: RevocationId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "display_string")]
    pub revoked_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub revoked_at: Timestamp,
    pub reason: DelegationRevocationReasonV1,
}

pub type RequestedWorkspaceIdsV2 = SortedUnique<WorkspaceId, 1, 1>;
pub type RequestedEnvironmentIdsV2 = SortedUnique<EnvironmentId, 0, 32>;
pub type RequestedObjectIdsV2 = SortedUnique<ObjectId, 0, 100>;
pub type RequestedSchemaIdsV2 = SortedUnique<SchemaId, 0, 100>;
pub type RequestedLocalesV2 = SortedUnique<LocaleId, 0, 64>;
pub type RequestedChangeSetIdsV2 = SortedUnique<ChangeSetId, 0, 100>;
pub type RequestedEditionIdsV2 = SortedUnique<EditionId, 0, 100>;
pub type RequestedReleaseIdsV2 = SortedUnique<ReleaseId, 0, 100>;

/// Complete resource projection recorded in an authorization decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedResourcesV2 {
    pub workspace_ids: RequestedWorkspaceIdsV2,
    pub environment_ids: RequestedEnvironmentIdsV2,
    pub object_ids: RequestedObjectIdsV2,
    pub schema_ids: RequestedSchemaIdsV2,
    pub locales: RequestedLocalesV2,
    pub changeset_ids: RequestedChangeSetIdsV2,
    pub edition_ids: RequestedEditionIdsV2,
    pub release_ids: RequestedReleaseIdsV2,
}

/// Effective budgets recorded after Delegation and operation projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveConstraintsV2 {
    pub max_objects: MaxObjects,
    pub max_context_bytes: MaxContextBytes,
    pub max_edits_per_changeset: MaxEditsPerChangeSet,
}

/// Exact authority head evaluated by one decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHeadV1 {
    pub sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub record_digest: ContentDigest,
}

/// Requesting and operating Principal status captured by one decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalStateV2 {
    pub requesting_principal_enabled: bool,
    pub operating_principal_enabled: bool,
}

/// Binding evidence selected for one authorization decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingDecisionEvidenceV2 {
    #[serde(with = "display_string")]
    pub binding_id: BindingId,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub record_digest: ContentDigest,
    #[serde(with = "optional_display_string")]
    pub revocation_record_digest: Option<ContentDigest>,
}

/// Disclosure-safe Delegation lookup result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationResolutionV2 {
    Resolved,
    NotFoundOrHidden,
}

/// Delegation evidence selected for one authorization decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationDecisionEvidenceV2 {
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    #[serde(with = "optional_display_string")]
    pub record_digest: Option<ContentDigest>,
    #[serde(with = "optional_display_string")]
    pub revocation_record_digest: Option<ContentDigest>,
    pub resolution: DelegationResolutionV2,
}

/// Schema marker that serializes only as `true`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PresentationConsumed;

impl Serialize for PresentationConsumed {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for PresentationConsumed {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "presentation_consumed must be true",
            ))
        }
    }
}

/// Allow/deny result recorded by the authority kernel.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationDecisionOutcome {
    Allow,
    Deny,
}

/// Closed protected denial-reason grammar in `AuthorizationDecisionV2`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthorizationDenialReason {
    #[serde(rename = "proof.auth.binding_inactive")]
    BindingInactive,
    #[serde(rename = "proof.authorization.budget_exceeded")]
    BudgetExceeded,
    #[serde(rename = "proof.authorization.delegation_expired")]
    DelegationExpired,
    #[serde(rename = "proof.authorization.delegation_not_yet_valid")]
    DelegationNotYetValid,
    #[serde(rename = "proof.authorization.delegation_revoked")]
    DelegationRevoked,
    #[serde(rename = "proof.authorization.delegation_unavailable")]
    DelegationUnavailable,
    #[serde(rename = "proof.authorization.policy_denied")]
    PolicyDenied,
    #[serde(rename = "proof.authorization.principal_disabled")]
    PrincipalDisabled,
    #[serde(rename = "proof.authorization.scope_exceeded")]
    ScopeExceeded,
    #[serde(rename = "proof.delegation.chain_unsupported")]
    ChainUnsupported,
    #[serde(rename = "proof.idempotency.key_reused")]
    IdempotencyKeyReused,
}

/// Closed result classification committed by a signed localized Allow decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalizedConsequenceResultKindV1 {
    Success,
    Failure,
}

/// Exact localized application result and effect committed by the signed decision.
///
/// The consequence-evidence digest is deliberately excluded: that evidence
/// includes the authorization-decision digest and would create a circular hash.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedConsequenceCommitmentV1 {
    pub result_kind: LocalizedConsequenceResultKindV1,
    pub result_contract: String,
    #[serde(with = "display_string")]
    pub result_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub application_consequence_digest: ContentDigest,
}

impl LocalizedConsequenceCommitmentV1 {
    /// Constructs the exact contract commitment for one localized v2 result.
    pub fn new(
        operation: AuthorityOperation,
        result_kind: LocalizedConsequenceResultKindV1,
        result_digest: ContentDigest,
        application_consequence_digest: ContentDigest,
    ) -> Result<Self, AuthorityContractError> {
        let result_contract = match result_kind {
            LocalizedConsequenceResultKindV1::Success => localized_operation_output_schema_uri(
                operation,
            )
            .ok_or(AuthorityContractError::InvalidValue(
                "localized consequence commitment operation",
            ))?,
            LocalizedConsequenceResultKindV1::Failure => {
                if authority_operation_entry(operation)
                    .localized_contract
                    .is_none()
                {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized consequence commitment operation",
                    ));
                }
                LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1
            }
        };
        Ok(Self {
            result_kind,
            result_contract: result_contract.to_owned(),
            result_digest,
            application_consequence_digest,
        })
    }

    /// Verifies that the committed result contract belongs to the signed operation.
    pub fn validate_for_operation(
        &self,
        operation: AuthorityOperation,
    ) -> Result<(), AuthorityContractError> {
        let expected = match self.result_kind {
            LocalizedConsequenceResultKindV1::Success => {
                localized_operation_output_schema_uri(operation)
            }
            LocalizedConsequenceResultKindV1::Failure => authority_operation_entry(operation)
                .localized_contract
                .map(|_| LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1),
        };
        if expected == Some(self.result_contract.as_str()) {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "localized consequence commitment",
            ))
        }
    }

    /// Cross-links the committed result classification and contract to a typed result.
    #[must_use]
    pub fn matches_result_kind_and_contract(
        &self,
        result: &AuthenticatedOperationResultV1,
    ) -> bool {
        match result {
            AuthenticatedOperationResultV1::LocalizedSuccess(success) => {
                self.result_kind == LocalizedConsequenceResultKindV1::Success
                    && self.result_contract == success.output_schema_uri()
            }
            AuthenticatedOperationResultV1::LocalizedFailure(_) => {
                self.result_kind == LocalizedConsequenceResultKindV1::Failure
                    && self.result_contract == LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1
            }
            AuthenticatedOperationResultV1::WorkspaceStatus(_)
            | AuthenticatedOperationResultV1::ReleasedObjectQuery(_)
            | AuthenticatedOperationResultV1::ContextPack(_)
            | AuthenticatedOperationResultV1::Failure(_) => false,
        }
    }

    /// Cross-links the classification, contract, and canonical result digest.
    #[must_use]
    pub fn matches_result(&self, result: &AuthenticatedOperationResultV1) -> bool {
        self.matches_result_kind_and_contract(result)
            && result
                .localized_result_digest()
                .is_ok_and(|digest| digest == Some(self.result_digest))
    }
}

/// Signed durable presentation-consumption and authorization record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecisionV2 {
    pub api_version: AuthorizationDecisionApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub previous_authority_record_digest: ContentDigest,
    pub audience: AuthorityAudience,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub evaluated_authority_head: AuthorityHeadV1,
    pub authority_key_id: Ed25519KeyId,
    pub operation: AuthorityOperation,
    pub requested_action: AuthorityAction,
    pub requested_resources: RequestedResourcesV2,
    pub effective_constraints: EffectiveConstraintsV2,
    #[serde(with = "display_string")]
    pub command_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub command_envelope_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub presentation_id: PresentationId,
    pub presentation_consumed: PresentationConsumed,
    #[serde(with = "display_string")]
    pub requesting_subject_commitment: ContentDigest,
    #[serde(with = "display_string")]
    pub actor_context_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    pub principal_state: PrincipalStateV2,
    pub binding: BindingDecisionEvidenceV2,
    pub delegation: DelegationDecisionEvidenceV2,
    pub policy_profile: DirectAuthorityProfileV1,
    #[serde(with = "display_string")]
    pub policy_bundle_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub localized_consequence_commitment: Option<LocalizedConsequenceCommitmentV1>,
    #[serde(with = "display_string")]
    pub evaluated_at: Timestamp,
    pub decision: AuthorizationDecisionOutcome,
    pub reason_code: Option<AuthorizationDenialReason>,
}

impl AuthorizationDecisionV2 {
    /// Enforces schema cross-field rules that serde field types cannot express.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        let registry = authority_operation_entry(self.operation);
        let workspace_matches = self.audience.workspace_id() == self.workspace_id
            && self.requested_resources.workspace_ids.as_slice() == [self.workspace_id];
        let head_matches = self.previous_authority_record_digest
            == self.evaluated_authority_head.record_digest
            && self.authority_sequence.get() == self.evaluated_authority_head.sequence.get() + 1;
        let binding_matches =
            self.binding.authority_sequence <= self.evaluated_authority_head.sequence;
        let decision_matches = match self.decision {
            AuthorizationDecisionOutcome::Allow => {
                self.reason_code.is_none()
                    && self.principal_state.requesting_principal_enabled
                    && self.principal_state.operating_principal_enabled
                    && self.binding.revocation_record_digest.is_none()
                    && self.delegation.resolution == DelegationResolutionV2::Resolved
                    && self.delegation.record_digest.is_some()
                    && self.delegation.revocation_record_digest.is_none()
            }
            AuthorizationDecisionOutcome::Deny => self.reason_code.is_some(),
        };
        let unavailable_matches = if self.delegation.resolution
            == DelegationResolutionV2::NotFoundOrHidden
            || self.reason_code == Some(AuthorizationDenialReason::DelegationUnavailable)
        {
            self.decision == AuthorizationDecisionOutcome::Deny
                && self.reason_code == Some(AuthorizationDenialReason::DelegationUnavailable)
                && self.delegation.resolution == DelegationResolutionV2::NotFoundOrHidden
                && self.delegation.record_digest.is_none()
                && self.delegation.revocation_record_digest.is_none()
        } else {
            true
        };
        let localized_commitment_matches = match (
            self.decision,
            registry.localized_contract,
            self.localized_consequence_commitment.as_ref(),
        ) {
            (AuthorizationDecisionOutcome::Allow, Some(_), Some(commitment)) => {
                commitment.validate_for_operation(self.operation).is_ok()
            }
            (AuthorizationDecisionOutcome::Allow, None, None)
            | (AuthorizationDecisionOutcome::Deny, _, None) => true,
            _ => false,
        };
        if workspace_matches
            && head_matches
            && binding_matches
            && decision_matches
            && unavailable_matches
            && localized_commitment_matches
            && registry.requested_action == self.requested_action
        {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authorization decision",
            ))
        }
    }
}

/// Public metadata for the currently trusted Workspace authority root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceAuthorityRootV1 {
    pub api_version: WorkspaceAuthorityRootApiVersion,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub authority_key_id: Ed25519KeyId,
    pub public_key: Ed25519PublicKey,
    pub algorithm: Ed25519Algorithm,
    #[serde(with = "display_string")]
    pub created_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub created_at: Timestamp,
    pub predecessor_authority_key_id: Option<Ed25519KeyId>,
    #[serde(with = "optional_display_string")]
    pub root_transition_envelope_digest: Option<ContentDigest>,
}

impl WorkspaceAuthorityRootV1 {
    /// Enforces paired predecessor/transition evidence and distinct root IDs.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        let paired = self.predecessor_authority_key_id.is_some()
            == self.root_transition_envelope_digest.is_some();
        let distinct = self
            .predecessor_authority_key_id
            .as_ref()
            .is_none_or(|predecessor| predecessor != &self.authority_key_id);
        let key_matches = self
            .public_key
            .key_id()
            .is_ok_and(|key_id| key_id == self.authority_key_id);
        if paired && distinct && key_matches {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "Workspace authority root",
            ))
        }
    }
}

/// Planned dual-signed successor-root activation record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceAuthorityRootTransitionV1 {
    pub api_version: WorkspaceAuthorityRootTransitionApiVersion,
    pub authority_sequence: AuthoritySequence,
    #[serde(with = "display_string")]
    pub previous_authority_record_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub transition_id: AuthorityRootTransitionId,
    pub predecessor_authority_key_id: Ed25519KeyId,
    pub successor_authority_key_id: Ed25519KeyId,
    pub successor_public_key: Ed25519PublicKey,
    pub algorithm: Ed25519Algorithm,
    #[serde(with = "display_string")]
    pub activated_by_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub activated_at: Timestamp,
}

impl WorkspaceAuthorityRootTransitionV1 {
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        let successor_matches = self
            .successor_public_key
            .key_id()
            .is_ok_and(|key_id| key_id == self.successor_authority_key_id);
        if self.predecessor_authority_key_id == self.successor_authority_key_id
            || !successor_matches
        {
            Err(AuthorityContractError::InvalidValue(
                "authority root transition",
            ))
        } else {
            Ok(())
        }
    }
}

/// Closed discriminated union of all v1 authority-log payloads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing would weaken the schema-shaped public record union"
)]
pub enum AuthorityRecordV1 {
    PrincipalStatus(PrincipalStatusV1),
    PrincipalBinding(PrincipalBindingV1),
    PrincipalBindingRevocation(PrincipalBindingRevocationV1),
    Delegation(DelegationV2),
    DelegationRevocation(DelegationRevocationV1),
    AuthorizationDecision(AuthorizationDecisionV2),
    WorkspaceAuthorityRootTransition(WorkspaceAuthorityRootTransitionV1),
}

impl AuthorityRecordV1 {
    #[must_use]
    pub const fn authority_sequence(&self) -> AuthoritySequence {
        match self {
            Self::PrincipalStatus(value) => value.authority_sequence,
            Self::PrincipalBinding(value) => value.authority_sequence,
            Self::PrincipalBindingRevocation(value) => value.authority_sequence,
            Self::Delegation(value) => value.authority_sequence,
            Self::DelegationRevocation(value) => value.authority_sequence,
            Self::AuthorizationDecision(value) => value.authority_sequence,
            Self::WorkspaceAuthorityRootTransition(value) => value.authority_sequence,
        }
    }

    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        match self {
            Self::PrincipalStatus(value) => value.workspace_id,
            Self::PrincipalBinding(value) => value.workspace_id,
            Self::PrincipalBindingRevocation(value) => value.workspace_id,
            Self::Delegation(value) => value.workspace_id,
            Self::DelegationRevocation(value) => value.workspace_id,
            Self::AuthorizationDecision(value) => value.workspace_id,
            Self::WorkspaceAuthorityRootTransition(value) => value.workspace_id,
        }
    }
}

/// One canonical signed authority record persisted without private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedAuthorityRecordV1 {
    pub record: AuthorityRecordV1,
    pub canonical_record_json: String,
    pub record_digest: ContentDigest,
    pub canonical_envelope_json: String,
    pub envelope_digest: ContentDigest,
    pub signer_key_ids: Vec<Ed25519KeyId>,
}

/// Result of authenticating, authorizing, consuming, and recording one presentation.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedExecutionV1 {
    pub command_input: CommandInputV1,
    pub actor_context: AuthenticatedActorContextV1,
    pub actor_context_evidence: AuthenticatedActorContextEvidenceV1,
    pub actor_context_digest: ContentDigest,
    pub decision: AuthorizationDecisionV2,
    pub decision_record_digest: ContentDigest,
    pub decision_envelope_digest: ContentDigest,
    pub result: AuthenticatedOperationResultV1,
}

impl AuthenticatedExecutionV1 {
    /// Validates the transport-neutral cross-links in a completed execution.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        let operation_input = self.command_input.normalized_operation_input()?;
        self.decision.validate()?;
        let evidence_matches = AuthenticatedActorContextEvidenceV1::from(&self.actor_context)
            == self.actor_context_evidence;
        let common_matches = evidence_matches
            && self.decision.decision == AuthorizationDecisionOutcome::Allow
            && self.command_input.workspace_id == self.actor_context.workspace_id
            && self.command_input.operation == self.actor_context.operation
            && self.command_input.requesting_principal_id
                == self.actor_context.requesting_principal_id
            && self.command_input.operating_principal_id
                == self.actor_context.operating_principal_id
            && self.command_input.delegation_id == self.actor_context.delegation_id
            && self.decision.workspace_id == self.command_input.workspace_id
            && self.decision.operation == self.command_input.operation
            && self.decision.requesting_principal_id == self.command_input.requesting_principal_id
            && self.decision.operating_principal_id == self.command_input.operating_principal_id
            && self.decision.binding.binding_id == self.actor_context.binding_id
            && self.decision.delegation.delegation_id == self.command_input.delegation_id
            && self.decision.command_digest == self.actor_context.command_digest
            && self.decision.command_envelope_digest == self.actor_context.command_envelope_digest
            && self.decision.presentation_id == self.actor_context.presentation_id
            && self.decision.actor_context_digest == self.actor_context_digest;
        let result_matches = match (&operation_input, &self.result) {
            (
                EnabledOperationInputV1::WorkspaceStatus(_),
                AuthenticatedOperationResultV1::WorkspaceStatus(status),
            ) => {
                status.storage_schema_version > 0
                    && status.workspace_id == self.command_input.workspace_id
                    && status.requesting_principal_id == self.command_input.requesting_principal_id
                    && status.operating_principal_id == self.command_input.operating_principal_id
                    && status.delegation_id == self.command_input.delegation_id
                    && status.authorization_decision_digest == self.decision_record_digest
            }
            (
                EnabledOperationInputV1::ObjectQueryReleased(input),
                AuthenticatedOperationResultV1::ReleasedObjectQuery(query),
            ) => {
                query.workspace_id == self.command_input.workspace_id
                    && query.environment_id == input.environment_id
                    && query.principal_id == self.command_input.operating_principal_id
                    && query.delegation_id == Some(self.command_input.delegation_id)
                    && query.authorization_decision_digest == self.decision_record_digest
                    && query.objects.iter().map(|object| object.object_id).eq(input
                        .object_ids
                        .as_slice()
                        .iter()
                        .copied())
            }
            (
                EnabledOperationInputV1::ContextBuild(input),
                AuthenticatedOperationResultV1::ContextPack(pack),
            ) => {
                pack.workspace_id == self.command_input.workspace_id
                    && pack.requesting_principal_id == self.command_input.requesting_principal_id
                    && pack.operating_principal_id == self.command_input.operating_principal_id
                    && pack.delegation_id == self.command_input.delegation_id
                    && pack.task_id == input.task_id.as_str()
                    && pack.intent == input.intent
                    && pack.environment_id == input.environment_id
                    && pack.object_ids.as_slice() == input.object_ids.as_slice()
                    && pack.limits.max_objects == input.max_objects.get()
                    && pack.limits.max_bytes == u64::from(input.max_bytes.get())
                    && pack.built_at <= self.decision.evaluated_at
                    && pack.expires_at == input.expires_at
            }
            (input, AuthenticatedOperationResultV1::Failure(failure)) => {
                failure.operation() == input.operation()
            }
            (input, AuthenticatedOperationResultV1::LocalizedSuccess(success)) => {
                success.matches_input(
                    input,
                    self.command_input.workspace_id,
                    self.command_input.requesting_principal_id,
                ) && success.output_value().is_ok()
            }
            (input, AuthenticatedOperationResultV1::LocalizedFailure(failure)) => {
                failure.operation == input.operation()
            }
            _ => false,
        };
        let commitment_matches = match self.decision.localized_consequence_commitment.as_ref() {
            Some(commitment) => commitment.matches_result(&self.result),
            None => matches!(
                &self.result,
                AuthenticatedOperationResultV1::WorkspaceStatus(_)
                    | AuthenticatedOperationResultV1::ReleasedObjectQuery(_)
                    | AuthenticatedOperationResultV1::ContextPack(_)
                    | AuthenticatedOperationResultV1::Failure(_)
            ),
        };
        if common_matches && result_matches && commitment_matches {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authenticated execution cross-checks",
            ))
        }
    }
}

/// Verified Workspace status with both authenticated actors and decision evidence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedWorkspaceStatusV1 {
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    #[serde(with = "display_string")]
    pub requesting_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub operating_principal_id: PrincipalId,
    #[serde(with = "display_string")]
    pub delegation_id: DelegationId,
    pub storage_schema_version: u32,
    pub authoritative_sequence: u64,
    #[serde(with = "display_string")]
    pub state_digest: ContentDigest,
    #[serde(with = "display_string")]
    pub authorization_decision_digest: ContentDigest,
}

/// Returns the exact checked-in output Schema fragment for a localized v2 operation.
#[must_use]
pub const fn localized_operation_output_schema_uri(
    operation: AuthorityOperation,
) -> Option<&'static str> {
    match operation {
        AuthorityOperation::ContextBuildV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "contextBuildOutput"
        )),
        AuthorityOperation::ChangesetCreateV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetCreateOutput"
        )),
        AuthorityOperation::ChangesetAddV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetAddOutput"
        )),
        AuthorityOperation::ChangesetGetV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetGetOutput"
        )),
        AuthorityOperation::ChangesetDiffV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetDiffOutput"
        )),
        AuthorityOperation::ChangesetValidateV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetValidateOutput"
        )),
        AuthorityOperation::ChangesetSubmitV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetSubmitOutput"
        )),
        AuthorityOperation::ChangesetCommitV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "changeSetCommitOutput"
        )),
        AuthorityOperation::EditionCreateV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "editionCreateOutput"
        )),
        AuthorityOperation::ReleaseCreateV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "releaseCreateOutput"
        )),
        AuthorityOperation::ObjectQueryReleasedV2 => Some(concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
            "objectQueryReleasedOutput"
        )),
        AuthorityOperation::WorkspaceStatusV1
        | AuthorityOperation::ObjectQueryReleasedV1
        | AuthorityOperation::ContextBuildV1 => None,
    }
}

/// Complete P-0007 `ChangeSet` read plus the effective projection digest required by its Schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedChangeSetReadV1 {
    pub changeset: LocalizedChangeSet,
    pub effective_leaf_digest: ContentDigest,
}

/// Closed success union for the 11 authenticated localized v2 operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalizedOperationSuccessV1 {
    ContextBuilt(LocalizedContextPack),
    ChangeSetCreated(LocalizedChangeSet),
    EditsAdded(AddedLocalizedEdits),
    ChangeSetRead(LocalizedChangeSetReadV1),
    ChangeSetDiffed(LocalizedChangeSetDiff),
    ChangeSetValidated(LocalizedValidation),
    ChangeSetSubmitted(SubmittedLocalizedChangeSet),
    ChangeSetCommitted(CommittedLocalizedChangeSet),
    EditionCreated(LocalizedEdition),
    ReleaseCreated(LocalizedRelease),
    ReleasedRenditionsQueried(ReleasedRenditionQuery),
}

impl LocalizedOperationSuccessV1 {
    /// Returns the exact operation whose result this variant can carry.
    #[must_use]
    pub const fn operation(&self) -> AuthorityOperation {
        match self {
            Self::ContextBuilt(_) => AuthorityOperation::ContextBuildV2,
            Self::ChangeSetCreated(_) => AuthorityOperation::ChangesetCreateV2,
            Self::EditsAdded(_) => AuthorityOperation::ChangesetAddV2,
            Self::ChangeSetRead(_) => AuthorityOperation::ChangesetGetV2,
            Self::ChangeSetDiffed(_) => AuthorityOperation::ChangesetDiffV2,
            Self::ChangeSetValidated(_) => AuthorityOperation::ChangesetValidateV2,
            Self::ChangeSetSubmitted(_) => AuthorityOperation::ChangesetSubmitV2,
            Self::ChangeSetCommitted(_) => AuthorityOperation::ChangesetCommitV2,
            Self::EditionCreated(_) => AuthorityOperation::EditionCreateV2,
            Self::ReleaseCreated(_) => AuthorityOperation::ReleaseCreateV2,
            Self::ReleasedRenditionsQueried(_) => AuthorityOperation::ObjectQueryReleasedV2,
        }
    }

    /// Returns the immutable checked-in output-Schema fragment for this exact result.
    #[must_use]
    pub const fn output_schema_uri(&self) -> &'static str {
        match self {
            Self::ContextBuilt(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "contextBuildOutput"
            ),
            Self::ChangeSetCreated(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetCreateOutput"
            ),
            Self::EditsAdded(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetAddOutput"
            ),
            Self::ChangeSetRead(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetGetOutput"
            ),
            Self::ChangeSetDiffed(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetDiffOutput"
            ),
            Self::ChangeSetValidated(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetValidateOutput"
            ),
            Self::ChangeSetSubmitted(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetSubmitOutput"
            ),
            Self::ChangeSetCommitted(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "changeSetCommitOutput"
            ),
            Self::EditionCreated(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "editionCreateOutput"
            ),
            Self::ReleaseCreated(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "releaseCreateOutput"
            ),
            Self::ReleasedRenditionsQueried(_) => concat!(
                "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
                "objectQueryReleasedOutput"
            ),
        }
    }

    /// Builds the exact schema-shaped result value without changing P-0007 domain structs.
    pub fn output_value(&self) -> Result<Value, AuthorityContractError> {
        match self {
            Self::ContextBuilt(result) => Ok(json!({
                "context_pack_digest": result.context_pack_digest.to_string(),
                "context_pack_id": result.context_pack_id.to_string(),
                "manifest": parsed_result_object(&result.manifest_json)?,
                "resource_intent_digest": result.resource_intent_digest.to_string(),
                "resource_intent_id": result.resource_intent_id.to_string(),
            })),
            Self::ChangeSetCreated(result) => Ok(json!({
                "base_state": state_reference_value(&result.base_state),
                "changeset_id": result.changeset_id.to_string(),
                "context_pack_digest": result.context_pack_digest.to_string(),
                "context_pack_id": result.context_pack_id.to_string(),
                "resource_intent_digest": result.resource_intent_digest.to_string(),
                "resource_intent_id": result.resource_intent_id.to_string(),
                "status": result.status.to_string(),
            })),
            Self::EditsAdded(result) => Ok(json!({
                "changeset_id": result.changeset_id.to_string(),
                "edit_ids": result.edit_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "first_ordinal": result.first_ordinal,
                "total_edit_count": result.total_edit_count,
            })),
            Self::ChangeSetRead(result) => localized_changeset_read_value(result),
            Self::ChangeSetDiffed(result) => {
                if result.effective_edits.is_empty() {
                    return Err(AuthorityContractError::InvalidValue(
                        "localized ChangeSet diff output",
                    ));
                }
                Ok(json!({
                    "changeset_id": result.changeset_id.to_string(),
                    "effective_edits": result.effective_edits.iter().map(localized_edit_value).collect::<Result<Vec<_>, _>>()?,
                    "effective_leaf_digest": result.effective_leaf_digest.to_string(),
                    "proposal_digest": result.proposal_digest.to_string(),
                }))
            }
            Self::ChangeSetValidated(result) => Ok(json!({
                "attempt": result.attempt,
                "changeset_id": result.changeset_id.to_string(),
                "effective_leaf_digest": result.effective_leaf_digest.to_string(),
                "findings": result.findings.iter().map(localized_finding_value).collect::<Vec<_>>(),
                "previous_validation_result_digest": result.previous_validation_result_digest.map(|value| value.to_string()),
                "proposal_digest": result.proposal_digest.to_string(),
                "sealed_changeset_digest": result.sealed_changeset_digest.map(|value| value.to_string()),
                "status": result.status.to_string(),
                "valid": result.valid,
                "validation_results_digest": result.validation_results_digest.to_string(),
            })),
            Self::ChangeSetSubmitted(result) => Ok(json!({
                "changeset_id": result.changeset_id.to_string(),
                "sealed_changeset_digest": result.sealed_changeset_digest.to_string(),
                "status": result.status.to_string(),
                "submitted_at": result.submitted_at.to_string(),
                "validation_results_digest": result.validation_results_digest.to_string(),
            })),
            Self::ChangeSetCommitted(result) => Ok(json!({
                "changeset_id": result.changeset_id.to_string(),
                "committed_at": result.committed_at.to_string(),
                "previous_state": state_reference_value(&result.previous_state),
                "renditions": result.renditions.iter().map(|rendition| parsed_result_object(&rendition.manifest_json)).collect::<Result<Vec<_>, _>>()?,
                "resulting_state": state_reference_value(&result.resulting_state),
                "sealed_changeset_digest": result.sealed_changeset_digest.to_string(),
                "status": result.status.to_string(),
                "validation_results_digest": result.validation_results_digest.to_string(),
            })),
            Self::EditionCreated(result) => Ok(json!({
                "edition_digest": result.edition_digest.to_string(),
                "edition_id": result.edition_id.to_string(),
                "manifest": parsed_result_object(&result.manifest_json)?,
                "state": state_reference_value(&result.state),
            })),
            Self::ReleaseCreated(result) => Ok(json!({
                "proof_envelope_digest": result.proof_envelope_digest.to_string(),
                "proof_id": result.proof_id.to_string(),
                "release_digest": result.release_digest.to_string(),
                "release_id": result.release_id.to_string(),
                "release_manifest": parsed_result_object(&result.manifest_json)?,
            })),
            Self::ReleasedRenditionsQueried(result) => Ok(json!({
                "edition": edition_reference_value(&result.edition),
                "environment_id": result.environment_id.to_string(),
                "release_id": result.release_id.to_string(),
                "renditions": result.renditions.iter().map(|rendition| Ok(json!({
                    "content": parsed_result_object(&rendition.canonical_content)?,
                    "locale": rendition.locale.to_string(),
                    "object_id": rendition.object_id.to_string(),
                    "rendition_digest": rendition.rendition_digest.to_string(),
                    "rendition_revision": rendition.rendition_revision.get(),
                    "schema_id": rendition.schema_id.to_string(),
                    "schema_version": rendition.schema_version.get(),
                    "source_digest": rendition.source_digest.to_string(),
                    "source_revision": rendition.source_revision.get(),
                }))).collect::<Result<Vec<_>, AuthorityContractError>>()?,
                "workspace_id": result.workspace_id.to_string(),
            })),
        }
    }

    /// Verifies that this operation-distinct result is the consequence of the normalized input.
    #[must_use]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed match cross-links every localized result without substitutable shared arms"
    )]
    pub fn matches_input(
        &self,
        input: &EnabledOperationInputV1,
        workspace_id: WorkspaceId,
        requesting_principal_id: PrincipalId,
    ) -> bool {
        match (input, self) {
            (EnabledOperationInputV1::LocalizedContextBuild(input), Self::ContextBuilt(result)) => {
                result.context_pack_id == input.context_pack_id
                    && result.workspace_id == workspace_id
                    && result.resource_intent_id == input.resource_intent_id
                    && result.resource_intent_digest == input.resource_intent_digest
                    && result.principal_id == requesting_principal_id
                    && result.limits == input.limits.into_application()
                    && result.created_at == input.created_at
                    && result.expires_at == input.expires_at
                    && localized_context_manifest_matches(
                        result,
                        input,
                        workspace_id,
                        requesting_principal_id,
                    )
            }
            (
                EnabledOperationInputV1::LocalizedChangeSetCreate(input),
                Self::ChangeSetCreated(result),
            ) => {
                result.changeset_id == input.changeset_id
                    && result.workspace_id == workspace_id
                    && result.context_pack_id == input.context_pack_id
                    && result.context_pack_digest == input.context_pack_digest
                    && result.resource_intent_id == input.resource_intent_id
                    && result.resource_intent_digest == input.resource_intent_digest
                    && result.intent == input.intent
                    && result.created_at == input.created_at
                    && result.principal_id == requesting_principal_id
                    && result.status == ChangeSetStatus::Draft
                    && result.edits.is_empty()
                    && result.proposal_digest.is_none()
                    && result.sealed_changeset_digest.is_none()
            }
            (EnabledOperationInputV1::LocalizedChangeSetAdd(input), Self::EditsAdded(result)) => {
                result.changeset_id == input.changeset_id
                    && result.edit_ids.len() == input.edits.len()
                    && result.first_ordinal > 0
                    && result.total_edit_count
                        == result
                            .first_ordinal
                            .saturating_add(
                                u32::try_from(result.edit_ids.len()).unwrap_or(u32::MAX),
                            )
                            .saturating_sub(1)
                    && result
                        .edit_ids
                        .iter()
                        .enumerate()
                        .all(|(index, edit_id)| !result.edit_ids[..index].contains(edit_id))
            }
            (
                EnabledOperationInputV1::LocalizedChangeSetGet(input),
                Self::ChangeSetRead(result),
            ) => {
                result.changeset.changeset_id == input.changeset_id
                    && result.changeset.workspace_id == workspace_id
                    && result.changeset.principal_id == requesting_principal_id
            }
            (
                EnabledOperationInputV1::LocalizedChangeSetDiff(input),
                Self::ChangeSetDiffed(result),
            ) => result.changeset_id == input.changeset_id && !result.effective_edits.is_empty(),
            (
                EnabledOperationInputV1::LocalizedChangeSetValidate(input),
                Self::ChangeSetValidated(result),
            ) => {
                result.changeset_id == input.changeset_id
                    && result.attempt > 0
                    && (result.attempt == 1) == result.previous_validation_result_digest.is_none()
                    && if result.valid {
                        result.status == ChangeSetStatus::Ready
                            && result.sealed_changeset_digest.is_some()
                            && result
                                .findings
                                .iter()
                                .all(|finding| finding.severity != crate::Severity::Error)
                    } else {
                        result.status == ChangeSetStatus::Draft
                            && result.sealed_changeset_digest.is_none()
                            && result
                                .findings
                                .iter()
                                .any(|finding| finding.severity == crate::Severity::Error)
                    }
            }
            (
                EnabledOperationInputV1::LocalizedChangeSetSubmit(input),
                Self::ChangeSetSubmitted(result),
            ) => {
                result.changeset_id == input.changeset_id
                    && result.submitted_at == input.submitted_at
                    && result.status == ChangeSetStatus::Submitted
            }
            (
                EnabledOperationInputV1::LocalizedChangeSetCommit(input),
                Self::ChangeSetCommitted(result),
            ) => {
                result.changeset_id == input.changeset_id
                    && result.committed_at == input.committed_at
                    && result.status == ChangeSetStatus::Committed
                    && !result.renditions.is_empty()
                    && u64::try_from(result.renditions.len())
                        .ok()
                        .and_then(|count| {
                            result
                                .resulting_state
                                .authoritative_sequence
                                .checked_sub(count)
                        })
                        .is_some_and(|rendition_predecessor| {
                            rendition_predecessor >= result.previous_state.authoritative_sequence
                                && result
                                    .renditions
                                    .iter()
                                    .enumerate()
                                    .all(|(index, rendition)| {
                                        let expected_sequence = u64::try_from(index)
                                            .ok()
                                            .and_then(|offset| offset.checked_add(1))
                                            .and_then(|offset| {
                                                rendition_predecessor.checked_add(offset)
                                            });
                                        rendition.workspace_id == workspace_id
                                            && rendition.changeset_id == input.changeset_id
                                            && expected_sequence
                                                == Some(rendition.authoritative_sequence)
                                    })
                        })
            }
            (
                EnabledOperationInputV1::LocalizedEditionCreate(input),
                Self::EditionCreated(result),
            ) => {
                result.edition_id == input.edition_id
                    && result.workspace_id == workspace_id
                    && result.changeset_id == input.changeset_id
                    && result.state.digest == input.resulting_state_digest
                    && result.created_at == input.created_at
                    && result.principal_id == requesting_principal_id
            }
            (
                EnabledOperationInputV1::LocalizedReleaseCreate(input),
                Self::ReleaseCreated(result),
            ) => {
                result.release_id == input.release_id
                    && result.workspace_id == workspace_id
                    && result.proof_id == input.proof_id
                    && result.environment_id == input.environment_id
                    && result.edition.edition_id == input.edition_id
                    && result.previous_release_id == Some(input.expected_base_release_id)
                    && result.released_at == input.released_at
                    && result.kind == ReleaseKind::Promotion
                    && release_manifest_principal(result) == Some(requesting_principal_id)
            }
            (
                EnabledOperationInputV1::LocalizedObjectQueryReleased(input),
                Self::ReleasedRenditionsQueried(result),
            ) => {
                result.environment_id == input.environment_id
                    && result.workspace_id == workspace_id
                    && result
                        .renditions
                        .iter()
                        .map(|rendition| (&rendition.object_id, &rendition.locale))
                        .eq(input
                            .targets
                            .iter()
                            .map(|target| (&target.object_id, &target.locale)))
            }
            _ => false,
        }
    }
}

fn localized_context_manifest_matches(
    result: &LocalizedContextPack,
    input: &LocalizedContextBuildInputV2,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
) -> bool {
    let Ok(manifest) = serde_json::from_str::<Value>(&result.manifest_json) else {
        return false;
    };
    let expected_limits = json!({
        "max_bytes": input.limits.max_bytes,
        "max_edits": input.limits.max_edits,
        "max_objects": input.limits.max_objects,
        "max_validation_attempts": input.limits.max_validation_attempts,
    });
    let expected_policy = json!({
        "api_version": "proof.dev/localized-content-policy/v1",
        "rules": input.policy_rules,
    });
    manifest.get("api_version").and_then(Value::as_str) == Some("proof.dev/context-pack/v2")
        && manifest.get("context_pack_id").and_then(Value::as_str)
            == Some(result.context_pack_id.to_string().as_str())
        && manifest.get("workspace_id").and_then(Value::as_str)
            == Some(workspace_id.to_string().as_str())
        && manifest.get("principal_id").and_then(Value::as_str)
            == Some(requesting_principal_id.to_string().as_str())
        && manifest
            .get("resource_intent_digest")
            .and_then(Value::as_str)
            == Some(input.resource_intent_digest.to_string().as_str())
        && manifest
            .get("resource_intent")
            .and_then(|intent| intent.get("intent_id"))
            .and_then(Value::as_str)
            == Some(input.resource_intent_id.to_string().as_str())
        && manifest.get("created_at").and_then(Value::as_str)
            == Some(input.created_at.to_string().as_str())
        && manifest.get("expires_at").and_then(Value::as_str)
            == Some(input.expires_at.to_string().as_str())
        && manifest.get("limits") == Some(&expected_limits)
        && manifest.get("policy") == Some(&expected_policy)
        && manifest.get("policy_digest").and_then(Value::as_str)
            == Some(result.policy_digest.to_string().as_str())
}

fn parsed_result_object(value: &str) -> Result<Value, AuthorityContractError> {
    let parsed: Value = serde_json::from_str(value)
        .map_err(|_| AuthorityContractError::InvalidValue("localized result JSON"))?;
    if parsed.is_object() {
        Ok(parsed)
    } else {
        Err(AuthorityContractError::InvalidValue(
            "localized result object",
        ))
    }
}

fn state_reference_value(value: &super::KnownStateArtifactReference) -> Value {
    json!({
        "api_version": value.api_version,
        "authoritative_sequence": value.authoritative_sequence,
        "digest": value.digest.to_string(),
    })
}

fn edition_reference_value(value: &super::EditionArtifactReference) -> Value {
    json!({
        "api_version": value.api_version,
        "digest": value.digest.to_string(),
        "edition_id": value.edition_id.to_string(),
    })
}

fn localized_edit_value(edit: &LocalizedEdit) -> Result<Value, AuthorityContractError> {
    let content = parsed_result_object(match &edit.input {
        LocalizedEditAttempt::LocalePut(input) => &input.canonical_content,
        LocalizedEditAttempt::ObjectCreate(input) => &input.canonical_content,
    })?;
    let edit_id = edit.edit_id.to_string();
    let repair = match &edit.input {
        LocalizedEditAttempt::LocalePut(input) => input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
        LocalizedEditAttempt::ObjectCreate(input) => input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
    };
    let supersedes = match &edit.input {
        LocalizedEditAttempt::LocalePut(input) => {
            input.supersedes_edit_id.map(|value| value.to_string())
        }
        LocalizedEditAttempt::ObjectCreate(input) => {
            input.supersedes_edit_id.map(|value| value.to_string())
        }
    };
    Ok(match &edit.input {
        LocalizedEditAttempt::LocalePut(input) => json!({
            "api_version": "proof.dev/edit/v2",
            "content": content,
            "edit_id": edit_id,
            "expected_source": {
                "digest": input.expected_source.digest.to_string(),
                "revision": input.expected_source.revision.get(),
                "schema_id": input.expected_source.schema_id.to_string(),
                "schema_version": input.expected_source.schema_version.get(),
            },
            "expected_target": input.expected_target.as_ref().map(|target| json!({
                "digest": target.digest.to_string(),
                "revision": target.revision.get(),
            })),
            "kind": "object.locale.put",
            "locale": input.locale.to_string(),
            "object_id": input.object_id.to_string(),
            "repair_of_validation_result_digest": repair,
            "supersedes_edit_id": supersedes,
        }),
        LocalizedEditAttempt::ObjectCreate(input) => json!({
            "api_version": "proof.dev/edit/v2",
            "content": content,
            "edit_id": edit_id,
            "kind": "object.create",
            "object_id": input.object_id.to_string(),
            "repair_of_validation_result_digest": repair,
            "schema_id": input.schema_id.to_string(),
            "schema_version": input.schema_version.get(),
            "supersedes_edit_id": supersedes,
        }),
    })
}

fn localized_finding_value(finding: &LocalizedFinding) -> Value {
    let severity = match finding.severity {
        crate::Severity::Info => "info",
        crate::Severity::Warning => "warning",
        crate::Severity::Error => "error",
    };
    json!({
        "code": finding.code,
        "edit_id": finding.edit_id.to_string(),
        "locale": finding.locale.to_string(),
        "object_id": finding.object_id.to_string(),
        "pointer": finding.pointer,
        "policy_digest": finding.policy_digest.to_string(),
        "severity": severity,
        "validator": finding.validator,
    })
}

fn localized_changeset_read_value(
    result: &LocalizedChangeSetReadV1,
) -> Result<Value, AuthorityContractError> {
    let changeset = &result.changeset;
    let effective = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .collect::<Vec<_>>();
    if changeset.edits.is_empty() || effective.is_empty() {
        return Err(AuthorityContractError::InvalidValue(
            "localized ChangeSet read output",
        ));
    }
    Ok(json!({
        "api_version": "proof.dev/changeset/v2",
        "base_state": state_reference_value(&changeset.base_state),
        "changeset_id": changeset.changeset_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "created_at": changeset.created_at.to_string(),
        "edits": changeset.edits.iter().map(localized_edit_value).collect::<Result<Vec<_>, _>>()?,
        "effective_leaf_digest": result.effective_leaf_digest.to_string(),
        "effective_leaves": effective.iter().map(|edit| {
            let mut leaf = serde_json::Map::new();
            leaf.insert("edit_digest".to_owned(), json!(edit.edit_digest.to_string()));
            leaf.insert("edit_id".to_owned(), json!(edit.edit_id.to_string()));
            if let Some(locale) = edit.input.locale() {
                leaf.insert("locale".to_owned(), json!(locale.to_string()));
            }
            leaf.insert(
                "object_id".to_owned(),
                json!(edit.input.object_id().to_string()),
            );
            Value::Object(leaf)
        }).collect::<Vec<_>>(),
        "intent": changeset.intent.to_string(),
        "principal_id": changeset.principal_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "workspace_id": changeset.workspace_id.to_string(),
    }))
}

fn release_manifest_principal(result: &LocalizedRelease) -> Option<PrincipalId> {
    serde_json::from_str::<Value>(&result.manifest_json)
        .ok()?
        .get("principal_id")?
        .as_str()?
        .parse()
        .ok()
}

/// Caller-safe P-0007 application failure kinds admitted after authorization allows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalizedOperationFailureKindV1 {
    NotFound,
    SchemaNotFound,
    UnsupportedVersion,
    InvalidInput,
    IntentMismatch,
    IntentSlotMismatch,
    SourceConflict,
    TargetConflict,
    StateConflict,
    ObjectExists,
    DuplicateActiveTarget,
    InvalidSupersession,
    InvalidRepairEvidence,
    NotDraft,
    NotReady,
    NotSubmitted,
    NotApproved,
    EvidenceMissing,
    LimitExceeded,
    PolicyDenied,
}

impl LocalizedOperationFailureKindV1 {
    /// Maps only caller-safe application failures; integrity/storage/signing abort instead.
    #[must_use]
    pub const fn from_application_error(error: &LocalizedContentError) -> Option<Self> {
        match error {
            LocalizedContentError::NotFound => Some(Self::NotFound),
            LocalizedContentError::SchemaNotFound => Some(Self::SchemaNotFound),
            LocalizedContentError::UnsupportedVersion => Some(Self::UnsupportedVersion),
            LocalizedContentError::InvalidInput => Some(Self::InvalidInput),
            LocalizedContentError::IntentMismatch => Some(Self::IntentMismatch),
            LocalizedContentError::IntentSlotMismatch => Some(Self::IntentSlotMismatch),
            LocalizedContentError::SourceConflict => Some(Self::SourceConflict),
            LocalizedContentError::TargetConflict => Some(Self::TargetConflict),
            LocalizedContentError::StateConflict => Some(Self::StateConflict),
            LocalizedContentError::ObjectExists => Some(Self::ObjectExists),
            LocalizedContentError::DuplicateActiveTarget => Some(Self::DuplicateActiveTarget),
            LocalizedContentError::InvalidSupersession => Some(Self::InvalidSupersession),
            LocalizedContentError::InvalidRepairEvidence => Some(Self::InvalidRepairEvidence),
            LocalizedContentError::NotDraft => Some(Self::NotDraft),
            LocalizedContentError::NotReady => Some(Self::NotReady),
            LocalizedContentError::NotSubmitted => Some(Self::NotSubmitted),
            LocalizedContentError::NotApproved => Some(Self::NotApproved),
            LocalizedContentError::EvidenceMissing => Some(Self::EvidenceMissing),
            LocalizedContentError::LimitExceeded => Some(Self::LimitExceeded),
            LocalizedContentError::PolicyDenied => Some(Self::PolicyDenied),
            LocalizedContentError::Unauthenticated
            | LocalizedContentError::IdempotencyKeyReused
            | LocalizedContentError::Signing(_)
            | LocalizedContentError::Integrity(_)
            | LocalizedContentError::Storage(_) => None,
        }
    }

    /// Stable caller-visible Problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotFound => "proof.resource.not_found",
            Self::SchemaNotFound => "proof.schema.not_found",
            Self::UnsupportedVersion => "proof.input.unsupported_version",
            Self::InvalidInput => "proof.input.schema_mismatch",
            Self::IntentMismatch => "proof.input.intent_mismatch",
            Self::IntentSlotMismatch => "proof.intent.slot_mismatch",
            Self::SourceConflict => "proof.state.source_conflict",
            Self::TargetConflict => "proof.state.target_conflict",
            Self::StateConflict => "proof.state.conflict",
            Self::ObjectExists => "proof.state.object_exists",
            Self::DuplicateActiveTarget => "proof.changeset.duplicate_target",
            Self::InvalidSupersession => "proof.changeset.invalid_supersession",
            Self::InvalidRepairEvidence => "proof.validation.repair_evidence_invalid",
            Self::NotDraft => "proof.changeset.not_draft",
            Self::NotReady => "proof.changeset.not_ready",
            Self::NotSubmitted => "proof.changeset.not_submitted",
            Self::NotApproved => "proof.changeset.not_approved",
            Self::EvidenceMissing => "proof.evidence.incomplete",
            Self::LimitExceeded => "proof.input.limit_exceeded",
            Self::PolicyDenied => "proof.policy.denied",
        }
    }

    /// Central caller-safe Problem projection shared by every adapter.
    #[must_use]
    pub const fn public_problem(self) -> PublicAuthorityProblem {
        let (problem_type, title) = match self {
            Self::NotFound => (
                "urn:proof:problem:resource-not-found",
                "The exact localized-content resource was not found",
            ),
            Self::SchemaNotFound => ("urn:proof:problem:schema-not-found", "Schema not found"),
            Self::UnsupportedVersion => (
                "urn:proof:problem:unsupported-version",
                "The operation is unsupported for the current artifact version",
            ),
            Self::InvalidInput => (
                "urn:proof:problem:input-schema-mismatch",
                "The localized-content input violates its closed contract",
            ),
            Self::IntentMismatch => (
                "urn:proof:problem:intent-mismatch",
                "The operation differs from the immutable resource intent",
            ),
            Self::IntentSlotMismatch => (
                "urn:proof:problem:intent-slot-mismatch",
                "Resource intent creation slot mismatch",
            ),
            Self::SourceConflict => (
                "urn:proof:problem:state-conflict",
                "The locale-neutral source precondition changed",
            ),
            Self::TargetConflict => (
                "urn:proof:problem:state-conflict",
                "The exact target rendition precondition changed",
            ),
            Self::StateConflict => (
                "urn:proof:problem:state-conflict",
                "The localized-content baseline changed concurrently",
            ),
            Self::ObjectExists => ("urn:proof:problem:object-exists", "Object already exists"),
            Self::DuplicateActiveTarget => (
                "urn:proof:problem:state-conflict",
                "The ChangeSet already has an active Edit for this target",
            ),
            Self::InvalidSupersession => (
                "urn:proof:problem:state-conflict",
                "The requested Edit supersession edge is invalid",
            ),
            Self::InvalidRepairEvidence => (
                "urn:proof:problem:repair-evidence-invalid",
                "The repair evidence does not match the latest invalid result",
            ),
            Self::NotDraft => (
                "urn:proof:problem:changeset-lifecycle",
                "Localized Edits require a Draft ChangeSet",
            ),
            Self::NotReady => (
                "urn:proof:problem:changeset-lifecycle",
                "The localized ChangeSet is not Ready",
            ),
            Self::NotSubmitted => (
                "urn:proof:problem:changeset-lifecycle",
                "The localized ChangeSet is not Submitted",
            ),
            Self::NotApproved => (
                "urn:proof:problem:changeset-lifecycle",
                "The localized ChangeSet is not Approved",
            ),
            Self::EvidenceMissing => (
                "urn:proof:problem:evidence-incomplete",
                "Localized-content evidence is incomplete",
            ),
            Self::LimitExceeded => (
                "urn:proof:problem:input-limit-exceeded",
                "The localized-content operation exceeds its committed budget",
            ),
            Self::PolicyDenied => (
                "urn:proof:problem:policy-denied",
                "Policy denied the exact localized-content operation",
            ),
        };
        PublicAuthorityProblem {
            problem_type,
            title,
            code: self.code(),
            detail: None,
            retryable: false,
        }
    }
}

/// One typed caller-safe localized application failure bound to its operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalizedOperationFailureV1 {
    pub operation: AuthorityOperation,
    pub kind: LocalizedOperationFailureKindV1,
}

impl LocalizedOperationFailureV1 {
    /// Constructs a failure only for one of the 11 localized v2 operations.
    pub fn new(
        operation: AuthorityOperation,
        kind: LocalizedOperationFailureKindV1,
    ) -> Result<Self, AuthorityContractError> {
        if authority_operation_entry(operation)
            .localized_contract
            .is_some()
        {
            Ok(Self { operation, kind })
        } else {
            Err(AuthorityContractError::InvalidValue(
                "localized failure operation",
            ))
        }
    }

    /// Stable caller-visible Problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }

    /// Central caller-safe Problem projection shared by every adapter.
    #[must_use]
    pub const fn public_problem(self) -> PublicAuthorityProblem {
        self.kind.public_problem()
    }
}

/// Stable application failure after authentication and authorization succeeded.
///
/// These outcomes consume the presentation with an `allow` decision but do
/// not persist a governed result or successful idempotency record. Integrity,
/// signing, storage, and authentication/authorization failures remain
/// [`AuthorityError`] values and roll back their atomic transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedOperationFailureV1 {
    ReleasedObjectQueryNotFound,
    ReleasedObjectQueryUnsupportedVersion,
    ContextBuildNotFound,
    ContextBuildLimitExceeded,
    ContextBuildExpired,
    ContextBuildDenied,
}

impl AuthenticatedOperationFailureV1 {
    /// Returns the exact operation whose authorized consequence failed.
    #[must_use]
    pub const fn operation(self) -> AuthorityOperation {
        match self {
            Self::ReleasedObjectQueryNotFound | Self::ReleasedObjectQueryUnsupportedVersion => {
                AuthorityOperation::ObjectQueryReleasedV1
            }
            Self::ContextBuildNotFound
            | Self::ContextBuildLimitExceeded
            | Self::ContextBuildExpired
            | Self::ContextBuildDenied => AuthorityOperation::ContextBuildV1,
        }
    }

    /// Returns the ratified legacy public Problem code for this outcome.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReleasedObjectQueryNotFound | Self::ContextBuildNotFound => {
                "proof.resource.not_found"
            }
            Self::ReleasedObjectQueryUnsupportedVersion => "proof.input.unsupported_version",
            Self::ContextBuildLimitExceeded => "proof.input.too_large",
            Self::ContextBuildExpired => "proof.delegation.expired",
            Self::ContextBuildDenied => "proof.auth.denied",
        }
    }
}

/// Closed result union for every authenticated operation enabled by the fixed registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedOperationResultV1 {
    WorkspaceStatus(AuthenticatedWorkspaceStatusV1),
    ReleasedObjectQuery(ReleasedObjectQuery),
    ContextPack(ContextPack),
    Failure(AuthenticatedOperationFailureV1),
    LocalizedSuccess(LocalizedOperationSuccessV1),
    LocalizedFailure(LocalizedOperationFailureV1),
}

impl AuthenticatedOperationResultV1 {
    /// Returns exact schema-shaped localized result data, when this is a localized success.
    pub fn localized_output_value(&self) -> Result<Option<Value>, AuthorityContractError> {
        match self {
            Self::LocalizedSuccess(success) => success.output_value().map(Some),
            Self::WorkspaceStatus(_)
            | Self::ReleasedObjectQuery(_)
            | Self::ContextPack(_)
            | Self::Failure(_)
            | Self::LocalizedFailure(_) => Ok(None),
        }
    }

    /// Returns the exact application-owned value committed by one localized result.
    ///
    /// Successes use the immutable operation output Schema. Failures use the
    /// stable caller-safe Problem profile without transport-only decision detail.
    pub fn localized_result_value(&self) -> Result<Option<Value>, AuthorityContractError> {
        match self {
            Self::LocalizedSuccess(success) => success.output_value().map(Some),
            Self::LocalizedFailure(failure) => {
                let problem = failure.public_problem();
                Ok(Some(json!({
                    "code": problem.code,
                    "detail": problem.detail,
                    "retryable": problem.retryable,
                    "title": problem.title,
                    "type": problem.problem_type,
                })))
            }
            Self::WorkspaceStatus(_)
            | Self::ReleasedObjectQuery(_)
            | Self::ContextPack(_)
            | Self::Failure(_) => Ok(None),
        }
    }

    /// Derives the exact signed localized result digest from the application-owned value.
    pub fn localized_result_digest(&self) -> Result<Option<ContentDigest>, AuthorityContractError> {
        self.localized_result_value()?
            .map(|value| {
                canonicalize(&value)
                    .map(|canonical| digest(ArtifactKind::OperationEffectV1, &canonical))
                    .map_err(|_| AuthorityContractError::InvalidValue("localized result value"))
            })
            .transpose()
    }

    /// Returns the centralized caller-safe Problem for a localized failure.
    #[must_use]
    pub const fn localized_public_problem(&self) -> Option<PublicAuthorityProblem> {
        match self {
            Self::LocalizedFailure(failure) => Some(failure.public_problem()),
            Self::WorkspaceStatus(_)
            | Self::ReleasedObjectQuery(_)
            | Self::ContextPack(_)
            | Self::Failure(_)
            | Self::LocalizedSuccess(_) => None,
        }
    }
}

/// Persisted canonical enrollment challenge and its domain-separated digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedEnrollmentChallengeV1 {
    pub challenge: BindingEnrollmentChallengeV1,
    pub canonical_challenge_json: String,
    pub challenge_digest: ContentDigest,
}

/// Storage boundary for the append-only authenticated authority state.
#[allow(
    clippy::missing_errors_doc,
    reason = "AuthorityError is the closed port contract"
)]
pub trait AuthorityRepository {
    fn workspace_authority_root(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspaceAuthorityRootV1, AuthorityError>;
    fn authority_head(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<AuthorityHeadV1>, AuthorityError>;
    fn principal_status(
        &self,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
    ) -> Result<Option<PrincipalStatusV1>, AuthorityError>;
    fn principal_binding(
        &self,
        workspace_id: WorkspaceId,
        binding_id: BindingId,
    ) -> Result<Option<PrincipalBindingV1>, AuthorityError>;
    fn principal_binding_revocation(
        &self,
        workspace_id: WorkspaceId,
        binding_id: BindingId,
    ) -> Result<Option<PrincipalBindingRevocationV1>, AuthorityError>;
    fn delegation_v2(
        &self,
        workspace_id: WorkspaceId,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationV2>, AuthorityError>;
    fn delegation_revocation(
        &self,
        workspace_id: WorkspaceId,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationRevocationV1>, AuthorityError>;
    fn consumed_presentation(
        &self,
        workspace_id: WorkspaceId,
        presentation_id: PresentationId,
    ) -> Result<bool, AuthorityError>;
    fn append_authority_record(
        &self,
        record: AuthorityRecordV1,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
}

/// Human/admin-only authority lifecycle. Implementations must independently derive the bootstrap Human.
#[allow(
    clippy::missing_errors_doc,
    reason = "AuthorityError is the closed port contract"
)]
pub trait AuthorityAdministrator {
    fn create_binding_enrollment_challenge(
        &self,
        challenge: BindingEnrollmentChallengeV1,
    ) -> Result<RecordedEnrollmentChallengeV1, AuthorityError>;
    fn issue_principal_binding(
        &self,
        binding: PrincipalBindingV1,
        canonical_enrollment_envelope_json: String,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
    fn set_principal_status(
        &self,
        status: PrincipalStatusV1,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
    fn revoke_principal_binding(
        &self,
        revocation: PrincipalBindingRevocationV1,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
    fn issue_delegation(
        &self,
        delegation: DelegationV2,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
    fn revoke_delegation(
        &self,
        revocation: DelegationRevocationV1,
    ) -> Result<RecordedAuthorityRecordV1, AuthorityError>;
    fn transition_workspace_authority_root(
        &self,
        transition: WorkspaceAuthorityRootTransitionV1,
        canonical_transition_envelope_json: String,
    ) -> Result<WorkspaceAuthorityRootV1, AuthorityError>;
}

/// Shared application entry point for CLI and both MCP transports.
#[allow(
    clippy::missing_errors_doc,
    reason = "AuthorityError is the closed port contract"
)]
pub trait AuthenticatedAuthorityExecutor {
    fn execute_authenticated(
        &self,
        invocation: AuthenticatedInvocationV1,
        evaluated_at: Timestamp,
    ) -> Result<AuthenticatedExecutionV1, AuthorityError>;
}

/// Typed input to an Agent-side signer bound to one opaque credential handle.
#[derive(Clone, Debug, PartialEq)]
pub struct SignAuthenticatedCommandV1 {
    pub command_input: CommandInputV1,
    pub binding_id: BindingId,
    pub presentation_id: PresentationId,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
}

impl SignAuthenticatedCommandV1 {
    /// Validates the enabled operation and bounded exclusive command lifetime.
    pub fn validate(&self) -> Result<(), AuthorityContractError> {
        self.command_input.validate_for_authenticated_execution()?;
        let lifetime =
            self.expires_at.unix_timestamp_nanos() - self.issued_at.unix_timestamp_nanos();
        if lifetime > 0 && lifetime <= i128::from(MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000 {
            Ok(())
        } else {
            Err(AuthorityContractError::InvalidValue(
                "authenticated command lifetime",
            ))
        }
    }
}

/// Agent-side signer port. Implementations have no Workspace storage access.
#[allow(
    clippy::missing_errors_doc,
    reason = "AuthorityError is the closed port contract"
)]
pub trait AuthenticatedCommandSigner {
    fn sign_authenticated_command(
        &self,
        command: SignAuthenticatedCommandV1,
    ) -> Result<AuthenticatedInvocationV1, AuthorityError>;
}

/// Closed failure taxonomy for P-0004 authentication, authorization, and authority integrity.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuthorityError {
    #[error("authenticated authority input is malformed")]
    AuthMalformed,
    #[error("authentication was denied")]
    AuthDenied,
    #[error("authenticated command signature is invalid")]
    AuthSignatureInvalid,
    #[error("authenticated command audience does not match")]
    AuthAudienceMismatch,
    #[error("authenticated command binding was not found")]
    AuthBindingNotFound,
    #[error("authenticated command binding is inactive")]
    AuthBindingInactive,
    #[error("authenticated command actor does not match")]
    AuthActorMismatch,
    #[error("authenticated command is not yet valid")]
    AuthNotYetValid,
    #[error("authenticated command has expired")]
    AuthExpired,
    #[error("authenticated command presentation was already consumed")]
    AuthReplay,
    #[error("delegation chaining is unsupported")]
    DelegationChainUnsupported,
    #[error("authorization was denied")]
    AuthorizationDenied,
    #[error("an authority Principal is disabled")]
    PrincipalDisabled,
    #[error("the Delegation is not yet valid")]
    DelegationNotYetValid,
    #[error("the Delegation has expired")]
    DelegationExpired,
    #[error("the Delegation was revoked")]
    DelegationRevoked,
    #[error("the Delegation is unavailable")]
    DelegationUnavailable,
    #[error("the requested resource scope exceeds the Delegation")]
    ScopeExceeded,
    #[error("the requested budget exceeds the Delegation")]
    BudgetExceeded,
    #[error("authority policy denied the operation")]
    PolicyDenied,
    #[error("authority history or signatures failed integrity verification: {0}")]
    AuthorityIntegrity(String),
    #[error("the authority root required to preserve continuity is unavailable")]
    AuthorityRootUnavailable,
    #[error("the idempotency key is already bound to different semantic input")]
    IdempotencyKeyReused,
    #[error("authority persistence is unavailable: {0}")]
    Storage(String),
    #[error("authority signing is unavailable: {0}")]
    Signing(String),
}

/// Caller-safe transport projection for an authenticated-authority failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicAuthorityProblem {
    /// Documentation identifier shared by every transport.
    pub problem_type: &'static str,
    /// Stable caller-safe summary shared by every transport.
    pub title: &'static str,
    /// Disclosure-thresholded machine-readable code.
    pub code: &'static str,
    /// Optional caller-safe detail. Audit-only failure detail is never projected here.
    pub detail: Option<&'static str>,
    /// Whether unchanged input may succeed when retried.
    pub retryable: bool,
}

impl AuthorityError {
    /// Stable internal/audit Problem code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::AuthMalformed => "proof.auth.malformed",
            Self::AuthDenied => "proof.auth.denied",
            Self::AuthSignatureInvalid => "proof.auth.signature_invalid",
            Self::AuthAudienceMismatch => "proof.auth.audience_mismatch",
            Self::AuthBindingNotFound => "proof.auth.binding_not_found",
            Self::AuthBindingInactive => "proof.auth.binding_inactive",
            Self::AuthActorMismatch => "proof.auth.actor_mismatch",
            Self::AuthNotYetValid => "proof.auth.not_yet_valid",
            Self::AuthExpired => "proof.auth.expired",
            Self::AuthReplay => "proof.auth.replay",
            Self::DelegationChainUnsupported => "proof.delegation.chain_unsupported",
            Self::AuthorizationDenied => "proof.authorization.denied",
            Self::PrincipalDisabled => "proof.authorization.principal_disabled",
            Self::DelegationNotYetValid => "proof.authorization.delegation_not_yet_valid",
            Self::DelegationExpired => "proof.authorization.delegation_expired",
            Self::DelegationRevoked => "proof.authorization.delegation_revoked",
            Self::DelegationUnavailable => "proof.authorization.delegation_unavailable",
            Self::ScopeExceeded => "proof.authorization.scope_exceeded",
            Self::BudgetExceeded => "proof.authorization.budget_exceeded",
            Self::PolicyDenied => "proof.authorization.policy_denied",
            Self::AuthorityIntegrity(_) | Self::AuthorityRootUnavailable => {
                "proof.authority.integrity"
            }
            Self::IdempotencyKeyReused => "proof.idempotency.key_reused",
            Self::Storage(_) | Self::Signing(_) => "proof.internal",
        }
    }

    /// Disclosure-thresholded public code.
    #[must_use]
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::AuthSignatureInvalid | Self::AuthBindingNotFound => "proof.auth.denied",
            Self::DelegationUnavailable => "proof.authorization.denied",
            _ => self.code(),
        }
    }

    /// Projects this failure to the caller-safe shape shared by public transports.
    #[must_use]
    pub const fn public_problem(&self) -> PublicAuthorityProblem {
        let code = self.public_code();
        let (problem_type, title, retryable) = match self {
            Self::AuthMalformed => (
                "urn:proof:problem:authenticated-invocation-malformed",
                "The authenticated invocation is malformed",
                false,
            ),
            Self::AuthDenied
            | Self::AuthSignatureInvalid
            | Self::AuthAudienceMismatch
            | Self::AuthBindingNotFound
            | Self::AuthBindingInactive
            | Self::AuthActorMismatch
            | Self::AuthNotYetValid
            | Self::AuthExpired
            | Self::AuthReplay => (
                "urn:proof:problem:authentication-denied",
                "Agent authentication was denied",
                false,
            ),
            Self::DelegationChainUnsupported
            | Self::AuthorizationDenied
            | Self::PrincipalDisabled
            | Self::DelegationNotYetValid
            | Self::DelegationExpired
            | Self::DelegationRevoked
            | Self::DelegationUnavailable
            | Self::ScopeExceeded
            | Self::BudgetExceeded
            | Self::PolicyDenied => (
                "urn:proof:problem:authority-denied",
                "The authenticated operation is outside current authority",
                false,
            ),
            Self::AuthorityIntegrity(_) | Self::AuthorityRootUnavailable => (
                "urn:proof:problem:evidence-incomplete",
                "Workspace authority evidence failed integrity verification",
                false,
            ),
            Self::IdempotencyKeyReused => (
                "urn:proof:problem:idempotency-conflict",
                "The idempotency key is bound to different semantic input",
                false,
            ),
            Self::Storage(_) | Self::Signing(_) => (
                "urn:proof:problem:dependency-unavailable",
                "Authenticated authority execution is unavailable",
                true,
            ),
        };
        PublicAuthorityProblem {
            problem_type,
            title,
            code,
            detail: None,
            retryable,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde::Deserialize;

    #[allow(
        clippy::wildcard_imports,
        reason = "the tests cross-check the complete public contract module"
    )]
    use super::*;

    const REGISTRY_VECTOR: &str = include_str!(
        "../../../conformance/v1/authority/vectors/authority-operation-registry.valid.json"
    );

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RegistryVector {
        api_version: String,
        resource_projection_profiles: Vec<RegistryProjectionProfile>,
        operations: Vec<RegistryOperationEntry>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RegistryProjectionProfile {
        profile: ResourceProjectionProfileName,
        grant_axes: Vec<GrantAxis>,
        evaluation: ProjectionEvaluation,
        sources: ProjectionSources,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RegistryOperationEntry {
        operation: AuthorityOperation,
        requested_action: AuthorityAction,
        localized_contract: Option<String>,
        application_idempotency: ApplicationIdempotency,
        closure_anchor: ClosureAnchor,
        resource_projection_profile: ResourceProjectionProfileName,
        budget_projection: BudgetProjection,
        selector_projection: SelectorProjection,
        consequence: AuthorityConsequence,
        availability: AuthorityOperationAvailability,
    }

    #[test]
    fn runtime_registry_exactly_matches_the_ratified_vector() {
        let vector: RegistryVector = serde_json::from_str(REGISTRY_VECTOR).unwrap();

        assert_eq!(
            vector.api_version,
            "proof.dev/authority-operation-registry/v1"
        );
        assert_eq!(
            vector.operations.len(),
            AUTHORITY_OPERATION_REGISTRY_V1.len()
        );
        for (expected, actual) in vector
            .operations
            .iter()
            .zip(AUTHORITY_OPERATION_REGISTRY_V1.iter())
        {
            assert_eq!(expected.operation, actual.operation);
            assert_eq!(expected.requested_action, actual.requested_action);
            assert_eq!(
                expected.localized_contract.as_deref(),
                actual.localized_contract
            );
            assert_eq!(
                expected.application_idempotency,
                actual.application_idempotency
            );
            assert_eq!(expected.closure_anchor, actual.closure_anchor);
            assert_eq!(
                expected.resource_projection_profile,
                actual.resource_projection_profile
            );
            assert_eq!(expected.budget_projection, actual.budget_projection);
            assert_eq!(expected.selector_projection, actual.selector_projection);
            assert_eq!(expected.consequence, actual.consequence);
            assert_eq!(expected.availability, actual.availability);
            assert_eq!(
                actual.execution_class,
                AuthorityExecutionClass::EvidenceWrite
            );
        }

        assert_eq!(
            vector.resource_projection_profiles.len(),
            AUTHORITY_RESOURCE_PROJECTION_PROFILES_V1.len()
        );
        for (expected, actual) in vector
            .resource_projection_profiles
            .iter()
            .zip(AUTHORITY_RESOURCE_PROJECTION_PROFILES_V1.iter())
        {
            assert_eq!(expected.profile, actual.profile);
            assert_eq!(expected.grant_axes, actual.grant_axes);
            assert_eq!(expected.evaluation, actual.evaluation);
            assert_eq!(expected.sources, actual.sources);
        }
    }

    #[test]
    fn registry_is_closed_to_fourteen_pairs_and_twelve_actions() {
        let pairs = AUTHORITY_OPERATION_REGISTRY_V1
            .iter()
            .map(|entry| (entry.operation.name(), entry.operation.version()))
            .collect::<BTreeSet<_>>();
        let actions = AUTHORITY_OPERATION_REGISTRY_V1
            .iter()
            .map(|entry| entry.requested_action)
            .collect::<BTreeSet<_>>();

        assert_eq!(pairs.len(), 14);
        assert_eq!(actions.len(), 12);
        assert!(
            AuthorityOperation::from_pair(
                "changeset.create",
                "proof.dev/operation/changeset.create/v1"
            )
            .is_none()
        );
        assert!(
            serde_json::from_str::<AuthorityOperation>(
                r#"{"name":"workspace.status","version":"proof.dev/operation/workspace.status/v9"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn all_fourteen_fixed_rows_are_enabled_with_frozen_consequence_classes() {
        let enabled = enabled_authority_operations().collect::<Vec<_>>();

        assert_eq!(enabled.len(), 14);
        assert_eq!(
            enabled
                .iter()
                .map(|entry| entry.operation)
                .collect::<Vec<_>>(),
            AUTHORITY_OPERATION_REGISTRY_V1
                .iter()
                .map(|entry| entry.operation)
                .collect::<Vec<_>>()
        );
        assert!(
            enabled
                .iter()
                .all(|entry| entry.execution_class == AuthorityExecutionClass::EvidenceWrite)
        );
        assert_eq!(
            enabled
                .iter()
                .filter(|entry| entry.consequence == AuthorityConsequence::AuthorityEvidenceOnly)
                .count(),
            5
        );
        assert_eq!(
            enabled
                .iter()
                .filter(|entry| entry.consequence == AuthorityConsequence::ImmutableContextPack)
                .count(),
            2
        );
        for consequence in [
            AuthorityConsequence::DraftLocalizedChangeset,
            AuthorityConsequence::ImmutableLocalizedEdition,
            AuthorityConsequence::LocalizedEditBatch,
            AuthorityConsequence::LocalizedReleasePointerAndProof,
            AuthorityConsequence::LocalizedRenditionCommit,
            AuthorityConsequence::LocalizedSubmission,
            AuthorityConsequence::LocalizedValidationAttempt,
        ] {
            assert_eq!(
                enabled
                    .iter()
                    .filter(|entry| entry.consequence == consequence)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn checked_in_contract_vectors_deserialize_to_typed_values() {
        let command: AuthenticatedCommandV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-command.payload.valid.json"
        ))
        .unwrap();
        let invocation: AuthenticatedInvocationV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-invocation.valid.json"
        ))
        .unwrap();
        let context: AuthenticatedActorContextV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.valid.json"
        ))
        .unwrap();
        let evidence: AuthenticatedActorContextEvidenceV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.digest-input.valid.json"
        ))
        .unwrap();
        let binding: PrincipalBindingV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/principal-binding.valid.json"
        ))
        .unwrap();
        let delegation: DelegationV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/delegation-v2.valid.json"
        ))
        .unwrap();
        let decision: AuthorizationDecisionV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();
        let root: WorkspaceAuthorityRootV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root.valid.json"
        ))
        .unwrap();
        let transition: WorkspaceAuthorityRootTransitionV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root-transition.payload.valid.json"
        ))
        .unwrap();

        assert_eq!(command.operation, AuthorityOperation::WorkspaceStatusV1);
        assert_eq!(invocation.command_input.operation, command.operation);
        assert_eq!(context.operation, command.operation);
        assert_eq!(
            AuthenticatedActorContextEvidenceV1::from(&context),
            evidence
        );
        binding.validate().unwrap();
        delegation.validate().unwrap();
        decision.validate().unwrap();
        root.validate().unwrap();
        transition.validate().unwrap();
        let persisted = serde_json::to_value(evidence).unwrap();
        assert!(persisted.get("requesting_subject").is_none());
        assert!(persisted.to_string().find("uid:").is_none());
    }

    #[test]
    fn localized_consequence_commitment_is_additive_without_changing_p4_payloads() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();
        let legacy: AuthorizationDecisionV2 = serde_json::from_value(vector.clone()).unwrap();
        assert_eq!(legacy.localized_consequence_commitment, None);
        assert_eq!(serde_json::to_value(&legacy).unwrap(), vector);
        legacy.validate().unwrap();

        let result_digest = format!("blake3:{}", "a".repeat(64)).parse().unwrap();
        let application_consequence_digest = format!("blake3:{}", "b".repeat(64)).parse().unwrap();
        assert!(
            LocalizedConsequenceCommitmentV1::new(
                AuthorityOperation::WorkspaceStatusV1,
                LocalizedConsequenceResultKindV1::Success,
                result_digest,
                application_consequence_digest,
            )
            .is_err()
        );

        let mut localized = legacy.clone();
        localized.operation = AuthorityOperation::ContextBuildV2;
        localized.requested_action = AuthorityAction::ContextBuild;
        assert!(localized.validate().is_err());
        localized.localized_consequence_commitment = Some(
            LocalizedConsequenceCommitmentV1::new(
                localized.operation,
                LocalizedConsequenceResultKindV1::Success,
                result_digest,
                application_consequence_digest,
            )
            .unwrap(),
        );
        localized.validate().unwrap();
        let encoded = serde_json::to_value(&localized).unwrap();
        let decoded: AuthorizationDecisionV2 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded, localized);

        let mut wrong_contract = localized.clone();
        wrong_contract
            .localized_consequence_commitment
            .as_mut()
            .unwrap()
            .result_contract = LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1.to_owned();
        assert!(wrong_contract.validate().is_err());

        let mut wrong_operation = localized.clone();
        wrong_operation.operation = AuthorityOperation::ChangesetCreateV2;
        wrong_operation.requested_action = AuthorityAction::ChangesetCreate;
        assert!(wrong_operation.validate().is_err());

        let mut denied = localized;
        denied.decision = AuthorizationDecisionOutcome::Deny;
        denied.reason_code = Some(AuthorizationDenialReason::PolicyDenied);
        assert!(denied.validate().is_err());

        let mut p4_with_commitment = legacy;
        p4_with_commitment.localized_consequence_commitment = Some(
            LocalizedConsequenceCommitmentV1::new(
                AuthorityOperation::ContextBuildV2,
                LocalizedConsequenceResultKindV1::Failure,
                result_digest,
                application_consequence_digest,
            )
            .unwrap(),
        );
        assert!(p4_with_commitment.validate().is_err());

        let mut unknown_commitment = encoded;
        unknown_commitment["localized_consequence_commitment"]["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<AuthorizationDecisionV2>(unknown_commitment).is_err());
    }

    #[test]
    fn deserialization_rejects_unknown_fields_unsorted_sets_and_wrong_constants() {
        let mut command: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/context-build.command-input.valid.json"
        ))
        .unwrap();
        command.as_object_mut().unwrap().insert(
            "requesting_subject".to_owned(),
            Value::String("uid:0".to_owned()),
        );
        assert!(serde_json::from_value::<CommandInputV1>(command).is_err());

        let mut delegation: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/delegation-v2.valid.json"
        ))
        .unwrap();
        delegation["actions"].as_array_mut().unwrap().reverse();
        assert!(serde_json::from_value::<DelegationV2>(delegation).is_err());

        assert!(serde_json::from_str::<AuthenticatedSubjectV1>(
            r#"{"api_version":"proof.dev/authenticated-subject/v2","provider":"os/unix","subject":"uid:1000"}"#
        )
        .is_err());

        let mut context: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.valid.json"
        ))
        .unwrap();
        context["requesting_subject"]["provider"] = Value::String("proof/local-ed25519".into());
        context["requesting_subject"]["subject"] = Value::String(
            "ed25519:707e8ff6e4bd4429a52a5687fd5ddad1023863aeb6ccdd61342295669ad567fc".into(),
        );
        assert!(serde_json::from_value::<AuthenticatedActorContextV1>(context).is_err());
    }

    #[test]
    fn signing_validation_rejects_reserved_rows_and_wrong_retry_shape() {
        let invocation: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-invocation.valid.json"
        ))
        .unwrap();
        let status: CommandInputV1 =
            serde_json::from_value(invocation["command_input"].clone()).unwrap();
        status.validate_for_authenticated_execution().unwrap();

        let context: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/context-build.command-input.valid.json"
        ))
        .unwrap();
        context.validate_for_authenticated_execution().unwrap();

        let mut reserved = context.clone();
        reserved.operation = AuthorityOperation::ContextBuildV2;
        assert!(reserved.validate_for_authenticated_execution().is_err());

        let mut wrong_retry = status;
        wrong_retry.idempotency_key = context.idempotency_key;
        assert!(wrong_retry.validate_for_authenticated_execution().is_err());
    }

    #[test]
    fn v1_normalizer_sorts_unique_objects_and_strict_validation_rejects_drift() {
        let mut query: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        query.operation = AuthorityOperation::ObjectQueryReleasedV1;
        query.normalized_input = serde_json::json!({
            "operating_principal_id": query.operating_principal_id.to_string(),
            "delegation_id": query.delegation_id.to_string(),
            "environment_id": "production",
            "object_ids": [
                "019c0000-0000-7000-8000-000000000020",
                "019c0000-0000-7000-8000-000000000010"
            ]
        })
        .as_object()
        .unwrap()
        .clone();

        assert!(query.validate_for_authenticated_execution().is_err());
        let normalized = query.normalize_for_authenticated_execution().unwrap();
        let EnabledOperationInputV1::ObjectQueryReleased(normalized) = normalized else {
            panic!("query operation must return its typed v1 input");
        };
        assert_eq!(
            normalized
                .object_ids
                .as_slice()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "019c0000-0000-7000-8000-000000000010",
                "019c0000-0000-7000-8000-000000000020",
            ]
        );
        query.validate_for_authenticated_execution().unwrap();

        query.normalized_input["object_ids"] = serde_json::json!([
            "019c0000-0000-7000-8000-000000000010",
            "019c0000-0000-7000-8000-000000000010"
        ]);
        assert!(query.normalize_for_authenticated_execution().is_err());
        query
            .normalized_input
            .insert("unexpected".to_owned(), Value::Bool(true));
        assert!(query.normalize_for_authenticated_execution().is_err());
    }

    #[test]
    fn v1_context_normalization_enforces_bounds_and_repeated_fields() {
        let mut command: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/context-build.command-input.valid.json"
        ))
        .unwrap();
        command.normalized_input["intent"] =
            Value::String("  Build bounded context for retry conformance.  ".to_owned());
        command.normalized_input["max_objects"] = serde_json::json!(2);
        command.normalized_input["object_ids"] = serde_json::json!([
            "019c0000-0000-7000-8000-000000000030",
            "019c0000-0000-7000-8000-000000000020"
        ]);
        assert!(command.validate_for_authenticated_execution().is_err());
        let normalized = command.normalize_for_authenticated_execution().unwrap();
        let EnabledOperationInputV1::ContextBuild(normalized) = normalized else {
            panic!("Context build must return its typed v1 input");
        };
        assert_eq!(
            normalized.intent.as_str(),
            "Build bounded context for retry conformance."
        );
        assert_eq!(normalized.object_ids.as_slice().len(), 2);
        command.validate_for_authenticated_execution().unwrap();

        command.normalized_input["delegation_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
        assert!(command.validate_for_authenticated_execution().is_err());
        command.normalized_input["delegation_id"] =
            Value::String(command.delegation_id.to_string());
        command.normalized_input["max_objects"] = serde_json::json!(1);
        assert!(command.validate_for_authenticated_execution().is_err());
        command.normalized_input["max_objects"] = serde_json::json!(2);
        command.normalized_input["idempotency_key"] =
            Value::String("019c0000-0000-7000-8000-000000000011".to_owned());
        assert!(command.validate_for_authenticated_execution().is_err());
    }

    #[test]
    fn signed_command_cross_checks_include_both_actors_delegation_and_retry_key() {
        let input: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        let mut signed: AuthenticatedCommandV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-command.payload.valid.json"
        ))
        .unwrap();

        input
            .validate_authenticated_command(
                &signed,
                input.requesting_principal_id,
                input.operating_principal_id,
            )
            .unwrap();
        assert!(
            input
                .validate_authenticated_command(
                    &signed,
                    input.operating_principal_id,
                    input.operating_principal_id,
                )
                .is_err()
        );
        signed.delegation_id = "019c0000-0000-7000-8000-000000000099".parse().unwrap();
        assert!(
            input
                .validate_authenticated_command(
                    &signed,
                    input.requesting_principal_id,
                    input.operating_principal_id,
                )
                .is_err()
        );
    }

    #[test]
    fn binding_evidence_carries_its_issuing_authority_sequence() {
        let binding: PrincipalBindingV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/principal-binding.valid.json"
        ))
        .unwrap();
        let decision: AuthorizationDecisionV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();

        assert_eq!(decision.binding.binding_id, binding.binding_id);
        assert_eq!(
            decision.binding.authority_sequence,
            binding.authority_sequence
        );
        assert_eq!(
            serde_json::to_value(AuthorizationDenialReason::IdempotencyKeyReused).unwrap(),
            "proof.idempotency.key_reused"
        );
        let schema: Value = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/schemas/authorization-decision-v2.schema.json"
        ))
        .unwrap();
        assert!(
            schema["$defs"]["denial_code"]["enum"]
                .as_array()
                .unwrap()
                .contains(&Value::String("proof.idempotency.key_reused".to_owned()))
        );
    }

    #[test]
    fn authenticated_status_result_cross_checks_both_actors_and_decision() {
        let command_input: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        let actor_context: AuthenticatedActorContextV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.valid.json"
        ))
        .unwrap();
        let actor_context_evidence = AuthenticatedActorContextEvidenceV1::from(&actor_context);
        let decision: AuthorizationDecisionV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();
        let decision_record_digest = decision.previous_authority_record_digest;
        let status = AuthenticatedWorkspaceStatusV1 {
            workspace_id: command_input.workspace_id,
            requesting_principal_id: command_input.requesting_principal_id,
            operating_principal_id: command_input.operating_principal_id,
            delegation_id: command_input.delegation_id,
            storage_schema_version: 12,
            authoritative_sequence: 4,
            state_digest: decision.policy_bundle_digest,
            authorization_decision_digest: decision_record_digest,
        };
        let mut execution = AuthenticatedExecutionV1 {
            command_input,
            actor_context,
            actor_context_evidence,
            actor_context_digest: decision.actor_context_digest,
            decision,
            decision_record_digest,
            decision_envelope_digest: decision_record_digest,
            result: AuthenticatedOperationResultV1::WorkspaceStatus(status),
        };

        execution.validate().unwrap();
        if let AuthenticatedOperationResultV1::WorkspaceStatus(status) = &mut execution.result {
            status.operating_principal_id = status.requesting_principal_id;
        } else {
            unreachable!();
        }
        assert!(execution.validate().is_err());

        if let AuthenticatedOperationResultV1::WorkspaceStatus(status) = &mut execution.result {
            status.operating_principal_id = execution.command_input.operating_principal_id;
        } else {
            unreachable!();
        }
        execution.decision.decision = AuthorizationDecisionOutcome::Deny;
        execution.decision.reason_code = Some(AuthorizationDenialReason::PolicyDenied);
        execution.decision.validate().unwrap();
        assert!(execution.validate().is_err());

        execution.decision.decision = AuthorizationDecisionOutcome::Allow;
        execution.decision.reason_code = None;
        execution.result = AuthenticatedOperationResultV1::Failure(
            AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
        );
        assert!(execution.validate().is_err());

        execution.command_input.operation = AuthorityOperation::ObjectQueryReleasedV1;
        execution.command_input.normalized_input = serde_json::json!({
            "operating_principal_id": execution.command_input.operating_principal_id.to_string(),
            "delegation_id": execution.command_input.delegation_id.to_string(),
            "environment_id": "production",
            "object_ids": ["019c0000-0000-7000-8000-000000000020"]
        })
        .as_object()
        .unwrap()
        .clone();
        execution.actor_context.operation = AuthorityOperation::ObjectQueryReleasedV1;
        execution.actor_context_evidence =
            AuthenticatedActorContextEvidenceV1::from(&execution.actor_context);
        execution.decision.operation = AuthorityOperation::ObjectQueryReleasedV1;
        execution.decision.requested_action = AuthorityAction::ObjectQueryReleased;
        assert!(execution.validate().is_ok());

        execution.result = AuthenticatedOperationResultV1::Failure(
            AuthenticatedOperationFailureV1::ContextBuildNotFound,
        );
        assert!(execution.validate().is_err());
    }

    #[test]
    fn committed_allow_failures_are_closed_and_keep_legacy_problem_codes() {
        let expected = [
            (
                AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
                AuthorityOperation::ObjectQueryReleasedV1,
                "proof.resource.not_found",
            ),
            (
                AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion,
                AuthorityOperation::ObjectQueryReleasedV1,
                "proof.input.unsupported_version",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildNotFound,
                AuthorityOperation::ContextBuildV1,
                "proof.resource.not_found",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildLimitExceeded,
                AuthorityOperation::ContextBuildV1,
                "proof.input.too_large",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildExpired,
                AuthorityOperation::ContextBuildV1,
                "proof.delegation.expired",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildDenied,
                AuthorityOperation::ContextBuildV1,
                "proof.auth.denied",
            ),
        ];

        for (failure, operation, code) in expected {
            assert_eq!(failure.operation(), operation);
            assert_eq!(failure.code(), code);
        }
    }

    #[test]
    fn cross_field_validators_reject_key_time_and_decision_mismatches() {
        let mut binding: PrincipalBindingV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/principal-binding.valid.json"
        ))
        .unwrap();
        binding.public_key =
            Ed25519PublicKey::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
        assert!(binding.validate().is_err());

        let mut delegation: DelegationV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/delegation-v2.valid.json"
        ))
        .unwrap();
        delegation.not_before = delegation.expires_at;
        assert!(delegation.validate().is_err());

        let mut decision: AuthorizationDecisionV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();
        decision.reason_code = Some(AuthorizationDenialReason::PolicyDenied);
        assert!(decision.validate().is_err());
        decision.reason_code = None;
        decision.binding.authority_sequence = decision.authority_sequence;
        assert!(decision.validate().is_err());
    }

    #[test]
    fn every_authority_record_variant_deserializes_from_its_vector() {
        for json in [
            include_str!(
                "../../../conformance/v1/authority/vectors/principal-status-human-enabled.valid.json"
            ),
            include_str!("../../../conformance/v1/authority/vectors/principal-binding.valid.json"),
            include_str!(
                "../../../conformance/v1/authority/vectors/principal-binding-revocation.valid.json"
            ),
            include_str!("../../../conformance/v1/authority/vectors/delegation-v2.valid.json"),
            include_str!(
                "../../../conformance/v1/authority/vectors/delegation-revocation.valid.json"
            ),
            include_str!(
                "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
            ),
            include_str!(
                "../../../conformance/v1/authority/vectors/workspace-authority-root-transition.payload.valid.json"
            ),
        ] {
            serde_json::from_str::<AuthorityRecordV1>(json).unwrap();
        }
        serde_json::from_str::<BindingEnrollmentChallengeV1>(include_str!(
            "../../../conformance/v1/authority/vectors/binding-enrollment-challenge.payload.valid.json"
        ))
        .unwrap()
        .validate()
        .unwrap();
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the exact normalization regression covers pointer, Edit, and released-target ordering contracts together"
    )]
    fn localized_input_normalization_is_exact_and_rejects_invalid_pointer_escapes() {
        let context_value = |pointer: &str| {
            json!({
                "api_version": "proof.dev/operation/context.build/v2",
                "context_pack_id": "019c0000-0000-7000-8000-000000000010",
                "created_at": "2026-08-21T10:00:00Z",
                "expires_at": "2026-08-21T11:00:00Z",
                "idempotency_key": "019c0000-0000-7000-8000-000000000011",
                "limits": {
                    "max_bytes": 1_048_576,
                    "max_edits": 100,
                    "max_objects": 100,
                    "max_validation_attempts": 100
                },
                "policy_rules": [{
                    "disallowed_values": ["z", "a"],
                    "locale": "fr-FR",
                    "pointer": pointer
                }],
                "resource_intent_digest": format!("blake3:{}", "1".repeat(64)),
                "resource_intent_id": "019c0000-0000-7000-8000-000000000012"
            })
        };
        for pointer in ["/legal", "/~0", "/a~1b"] {
            let mut input: LocalizedContextBuildInputV2 =
                serde_json::from_value(context_value(pointer)).unwrap();
            input.normalize().unwrap();
            assert_eq!(input.policy_rules[0].disallowed_values, ["a", "z"]);
        }
        for pointer in ["/~2", "/a~", ""] {
            let mut input: LocalizedContextBuildInputV2 =
                serde_json::from_value(context_value(pointer)).unwrap();
            assert!(input.normalize().is_err());
        }

        let mut context_command: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        let mut multi_rule_context = context_value("/legal");
        multi_rule_context["policy_rules"] = json!([
            {
                "disallowed_values": ["a"],
                "locale": "fr-FR",
                "pointer": "/legal"
            },
            {
                "disallowed_values": ["z"],
                "locale": "de-DE",
                "pointer": "/legal"
            }
        ]);
        context_command.operation = AuthorityOperation::ContextBuildV2;
        context_command.idempotency_key = Some(
            multi_rule_context["idempotency_key"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        );
        context_command.normalized_input = multi_rule_context.as_object().unwrap().clone();
        assert!(
            context_command
                .validate_for_authenticated_execution()
                .is_err()
        );
        let normalized = context_command
            .normalize_for_authenticated_execution()
            .unwrap();
        let EnabledOperationInputV1::LocalizedContextBuild(normalized) = normalized else {
            panic!("localized Context build must return its typed v2 input")
        };
        assert_eq!(
            normalized
                .policy_rules
                .iter()
                .map(|rule| rule.locale.to_string())
                .collect::<Vec<_>>(),
            ["de-DE", "fr-FR"]
        );
        context_command
            .validate_for_authenticated_execution()
            .unwrap();

        let mut edit_batch: LocalizedChangeSetAddInputV2 = serde_json::from_value(json!({
            "api_version": "proof.dev/operation/changeset.add/v2",
            "changeset_id": "019c0000-0000-7000-8000-000000000013",
            "edits": [{
                "api_version": "proof.dev/edit/v2",
                "content": { "title": "Bonjour" },
                "expected_source": {
                    "digest": format!("blake3:{}", "2".repeat(64)),
                    "revision": 7,
                    "schema_id": "article",
                    "schema_version": 3
                },
                "expected_target": null,
                "kind": "object.locale.put",
                "locale": "fr-FR",
                "object_id": "019c0000-0000-7000-8000-000000000014",
                "repair_of_validation_result_digest": null,
                "supersedes_edit_id": null
            }],
            "idempotency_key": "019c0000-0000-7000-8000-000000000015"
        }))
        .unwrap();
        edit_batch.normalize().unwrap();
        let LocalizedSemanticEditInputV2::ObjectLocalePut(put_edit) = &edit_batch.edits[0] else {
            panic!("locale put batch element must deserialize as its kind variant")
        };
        assert_eq!(put_edit.expected_source.revision, 7);

        let mut create_batch: LocalizedChangeSetAddInputV2 = serde_json::from_value(json!({
            "api_version": "proof.dev/operation/changeset.add/v2",
            "changeset_id": "019c0000-0000-7000-8000-000000000013",
            "edits": [{
                "api_version": "proof.dev/edit/v2",
                "content": { "title": "Bonjour" },
                "kind": "object.create",
                "object_id": "019c0000-0000-7000-8000-000000000014",
                "repair_of_validation_result_digest": null,
                "schema_id": "article",
                "schema_version": 3,
                "supersedes_edit_id": null
            }],
            "idempotency_key": "019c0000-0000-7000-8000-000000000015"
        }))
        .unwrap();
        create_batch.normalize().unwrap();
        let LocalizedSemanticEditInputV2::ObjectCreate(create_edit) = &create_batch.edits[0] else {
            panic!("object.create batch element must deserialize as its kind variant")
        };
        assert_eq!(create_edit.schema_version, 3);
        let mut repaired_create_batch = create_batch.clone();
        let LocalizedSemanticEditInputV2::ObjectCreate(repaired_create) =
            &mut repaired_create_batch.edits[0]
        else {
            unreachable!("the cloned creation batch retains its variant")
        };
        repaired_create.supersedes_edit_id =
            Some("019c0000-0000-7000-8000-000000000016".parse().unwrap());
        repaired_create.repair_of_validation_result_digest =
            Some(format!("blake3:{}", "3".repeat(64)).parse().unwrap());
        repaired_create_batch.normalize().unwrap();
        let mut unpaired_create_batch = repaired_create_batch;
        let LocalizedSemanticEditInputV2::ObjectCreate(unpaired_create) =
            &mut unpaired_create_batch.edits[0]
        else {
            unreachable!("the cloned creation batch retains its variant")
        };
        unpaired_create.repair_of_validation_result_digest = None;
        assert!(unpaired_create_batch.normalize().is_err());
        assert!(
            serde_json::from_value::<LocalizedChangeSetAddInputV2>(json!({
                "api_version": "proof.dev/operation/changeset.add/v2",
                "changeset_id": "019c0000-0000-7000-8000-000000000013",
                "edits": [{
                    "api_version": "proof.dev/edit/v2",
                    "content": { "title": "Bonjour" },
                    "kind": "object.create",
                    "locale": "fr-FR",
                    "object_id": "019c0000-0000-7000-8000-000000000014",
                    "schema_id": "article",
                    "schema_version": 3
                }],
                "idempotency_key": "019c0000-0000-7000-8000-000000000015"
            }))
            .is_err()
        );

        let mut released_query: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        released_query.operation = AuthorityOperation::ObjectQueryReleasedV2;
        released_query.idempotency_key = None;
        released_query.normalized_input = json!({
            "api_version": "proof.dev/operation/object.query_released/v2",
            "environment_id": "preview",
            "evaluated_at": "2026-08-21T10:00:00Z",
            "targets": [
                {
                    "locale": "de-DE",
                    "object_id": "019c0000-0000-7000-8000-000000000032"
                },
                {
                    "locale": "fr-FR",
                    "object_id": "019c0000-0000-7000-8000-000000000031"
                }
            ]
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(
            released_query
                .validate_for_authenticated_execution()
                .is_err()
        );
        let normalized = released_query
            .normalize_for_authenticated_execution()
            .unwrap();
        let EnabledOperationInputV1::LocalizedObjectQueryReleased(normalized) = normalized else {
            panic!("released rendition query must return its typed v2 input")
        };
        assert_eq!(
            normalized
                .targets
                .iter()
                .map(|target| (target.object_id.to_string(), target.locale.to_string()))
                .collect::<Vec<_>>(),
            [
                (
                    "019c0000-0000-7000-8000-000000000031".to_owned(),
                    "fr-FR".to_owned(),
                ),
                (
                    "019c0000-0000-7000-8000-000000000032".to_owned(),
                    "de-DE".to_owned(),
                ),
            ]
        );
        released_query
            .validate_for_authenticated_execution()
            .unwrap();
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the regression cross-links pristine results and signed commitment substitution in one fixture"
    )]
    fn localized_success_cross_links_reject_substituted_and_non_pristine_results() {
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let requesting_principal_id = "019c0000-0000-7000-8000-000000000002"
            .parse::<PrincipalId>()
            .unwrap();
        let operating_principal_id = "019c0000-0000-7000-8000-000000000003"
            .parse::<PrincipalId>()
            .unwrap();
        let mut input: LocalizedChangeSetCreateInputV2 = serde_json::from_value(json!({
            "api_version": "proof.dev/operation/changeset.create/v2",
            "changeset_id": "019c0000-0000-7000-8000-000000000020",
            "context_pack_digest": format!("blake3:{}", "3".repeat(64)),
            "context_pack_id": "019c0000-0000-7000-8000-000000000021",
            "created_at": "2026-08-21T10:00:00Z",
            "idempotency_key": "019c0000-0000-7000-8000-000000000022",
            "intent": "Localize the preview",
            "resource_intent_digest": format!("blake3:{}", "4".repeat(64)),
            "resource_intent_id": "019c0000-0000-7000-8000-000000000023"
        }))
        .unwrap();
        input.normalize().unwrap();
        let enabled_input = EnabledOperationInputV1::LocalizedChangeSetCreate(input.clone());
        let base_state = super::super::KnownStateArtifactReference {
            api_version: "proof.dev/known-state/v2".to_owned(),
            authoritative_sequence: 1,
            digest: format!("blake3:{}", "5".repeat(64)).parse().unwrap(),
        };
        let mut changeset = LocalizedChangeSet {
            changeset_id: input.changeset_id,
            workspace_id,
            principal_id: requesting_principal_id,
            intent: input.intent.clone(),
            resource_intent_id: input.resource_intent_id,
            resource_intent_digest: input.resource_intent_digest,
            context_pack_id: input.context_pack_id,
            context_pack_digest: input.context_pack_digest,
            base_state,
            created_at: input.created_at,
            status: ChangeSetStatus::Draft,
            edits: Vec::new(),
            proposal_digest: None,
            sealed_changeset_digest: None,
        };
        let success = LocalizedOperationSuccessV1::ChangeSetCreated(changeset.clone());
        assert!(success.matches_input(&enabled_input, workspace_id, requesting_principal_id));
        let result_digest = format!("blake3:{}", "6".repeat(64)).parse().unwrap();
        let consequence_digest = format!("blake3:{}", "7".repeat(64)).parse().unwrap();
        let success_commitment = LocalizedConsequenceCommitmentV1::new(
            AuthorityOperation::ChangesetCreateV2,
            LocalizedConsequenceResultKindV1::Success,
            result_digest,
            consequence_digest,
        )
        .unwrap();
        let typed_success = AuthenticatedOperationResultV1::LocalizedSuccess(success.clone());
        assert!(success_commitment.matches_result_kind_and_contract(&typed_success));
        let failure = LocalizedOperationFailureV1::new(
            AuthorityOperation::ChangesetCreateV2,
            LocalizedOperationFailureKindV1::NotFound,
        )
        .unwrap();
        let typed_failure = AuthenticatedOperationResultV1::LocalizedFailure(failure);
        assert!(!success_commitment.matches_result_kind_and_contract(&typed_failure));
        let failure_commitment = LocalizedConsequenceCommitmentV1::new(
            AuthorityOperation::ChangesetCreateV2,
            LocalizedConsequenceResultKindV1::Failure,
            result_digest,
            consequence_digest,
        )
        .unwrap();
        assert!(failure_commitment.matches_result_kind_and_contract(&typed_failure));
        assert!(!failure_commitment.matches_result_kind_and_contract(&typed_success));
        let get_input =
            EnabledOperationInputV1::LocalizedChangeSetGet(LocalizedChangeSetGetInputV2 {
                api_version: LocalizedChangeSetGetInputApiVersion::default(),
                changeset_id: input.changeset_id,
            });
        assert!(!success.matches_input(&get_input, workspace_id, requesting_principal_id));

        changeset.status = ChangeSetStatus::Ready;
        assert!(
            !LocalizedOperationSuccessV1::ChangeSetCreated(changeset.clone()).matches_input(
                &enabled_input,
                workspace_id,
                requesting_principal_id
            )
        );
        changeset.status = ChangeSetStatus::Draft;
        changeset.principal_id = operating_principal_id;
        assert!(
            !LocalizedOperationSuccessV1::ChangeSetCreated(changeset).matches_input(
                &enabled_input,
                workspace_id,
                requesting_principal_id
            )
        );
        assert_eq!(
            LocalizedOperationFailureKindV1::from_application_error(
                &LocalizedContentError::IdempotencyKeyReused
            ),
            None
        );
    }

    #[test]
    fn localized_commit_cross_link_accepts_creation_facts_before_contiguous_renditions() {
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let changeset_id = "019c0000-0000-7000-8000-000000000020"
            .parse::<ChangeSetId>()
            .unwrap();
        let committed_at = "2026-08-21T10:00:00Z".parse().unwrap();
        let input =
            EnabledOperationInputV1::LocalizedChangeSetCommit(LocalizedChangeSetCommitInputV2 {
                api_version: LocalizedChangeSetCommitInputApiVersion::default(),
                changeset_id,
                committed_at,
                idempotency_key: "019c0000-0000-7000-8000-000000000021".parse().unwrap(),
            });
        let state = |sequence, digit: char| super::super::KnownStateArtifactReference {
            api_version: "proof.dev/known-state/v2".to_owned(),
            authoritative_sequence: sequence,
            digest: format!("blake3:{}", digit.to_string().repeat(64))
                .parse()
                .unwrap(),
        };
        let rendition = |object: &str, locale: &str, edit: &str, sequence, digit: char| {
            super::super::ObjectLocaleRevision {
                workspace_id,
                object_id: object.parse().unwrap(),
                locale: locale.parse().unwrap(),
                revision: LocaleRevision::new(1).unwrap(),
                previous_revision_digest: None,
                source_object_revision: ObjectRevision::INITIAL,
                source_object_digest: format!("blake3:{}", digit.to_string().repeat(64))
                    .parse()
                    .unwrap(),
                schema_id: SchemaId::new("campaign").unwrap(),
                schema_version: SchemaVersion::new(1).unwrap(),
                canonical_content: "{}".to_owned(),
                changeset_id,
                edit_id: edit.parse().unwrap(),
                authoritative_sequence: sequence,
                manifest_json: "{}".to_owned(),
                rendition_digest: format!(
                    "blake3:{}",
                    char::from_u32(u32::from(digit) + 2)
                        .unwrap()
                        .to_string()
                        .repeat(64)
                )
                .parse()
                .unwrap(),
            }
        };
        let mut committed = CommittedLocalizedChangeSet {
            changeset_id,
            sealed_changeset_digest: format!("blake3:{}", "1".repeat(64)).parse().unwrap(),
            validation_results_digest: format!("blake3:{}", "2".repeat(64)).parse().unwrap(),
            previous_state: state(10, '3'),
            resulting_state: state(12, '4'),
            renditions: vec![
                rendition(
                    "019c0000-0000-7000-8000-000000000030",
                    "de-DE",
                    "019c0000-0000-7000-8000-000000000040",
                    11,
                    '5',
                ),
                rendition(
                    "019c0000-0000-7000-8000-000000000031",
                    "fr-FR",
                    "019c0000-0000-7000-8000-000000000041",
                    12,
                    '6',
                ),
            ],
            committed_at,
            status: ChangeSetStatus::Committed,
        };
        let matches = |value: &CommittedLocalizedChangeSet| {
            LocalizedOperationSuccessV1::ChangeSetCommitted(value.clone()).matches_input(
                &input,
                workspace_id,
                "019c0000-0000-7000-8000-000000000002".parse().unwrap(),
            )
        };
        assert!(matches(&committed));

        committed.resulting_state.authoritative_sequence = 13;
        committed.renditions[0].authoritative_sequence = 12;
        committed.renditions[1].authoritative_sequence = 13;
        assert!(matches(&committed));

        committed.renditions[0].authoritative_sequence = 11;
        assert!(!matches(&committed));
        committed.renditions[0].authoritative_sequence = 12;
        committed.renditions[1].authoritative_sequence = 12;
        committed.renditions.swap(0, 1);
        assert!(!matches(&committed));
    }

    #[test]
    fn localized_diff_contract_rejects_an_empty_effective_projection() {
        let changeset_id = "019c0000-0000-7000-8000-000000000020"
            .parse::<ChangeSetId>()
            .unwrap();
        let input =
            EnabledOperationInputV1::LocalizedChangeSetDiff(LocalizedChangeSetDiffInputV2 {
                api_version: LocalizedChangeSetDiffInputApiVersion::default(),
                changeset_id,
            });
        let success = LocalizedOperationSuccessV1::ChangeSetDiffed(LocalizedChangeSetDiff {
            changeset_id,
            proposal_digest: format!("blake3:{}", "1".repeat(64)).parse().unwrap(),
            effective_leaf_digest: format!("blake3:{}", "2".repeat(64)).parse().unwrap(),
            effective_edits: Vec::new(),
        });
        assert!(success.output_value().is_err());
        assert!(!success.matches_input(
            &input,
            "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            "019c0000-0000-7000-8000-000000000002".parse().unwrap(),
        ));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the digest substitution regression constructs a complete valid authenticated execution before mutating only result bytes"
    )]
    fn authenticated_execution_rejects_localized_result_digest_substitution() {
        let mut command_input: CommandInputV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/semantic-command.valid.json"
        ))
        .unwrap();
        let changeset_id = "019c0000-0000-7000-8000-000000000020"
            .parse::<ChangeSetId>()
            .unwrap();
        command_input.operation = AuthorityOperation::ChangesetGetV2;
        command_input.idempotency_key = None;
        command_input.normalized_input = json!({
            "api_version": "proof.dev/operation/changeset.get/v2",
            "changeset_id": changeset_id.to_string(),
        })
        .as_object()
        .unwrap()
        .clone();
        command_input
            .validate_for_authenticated_execution()
            .unwrap();

        let mut actor_context: AuthenticatedActorContextV1 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-actor-context.valid.json"
        ))
        .unwrap();
        actor_context.operation = AuthorityOperation::ChangesetGetV2;
        let actor_context_evidence = AuthenticatedActorContextEvidenceV1::from(&actor_context);
        let mut decision: AuthorizationDecisionV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
        ))
        .unwrap();
        decision.operation = AuthorityOperation::ChangesetGetV2;
        decision.requested_action = AuthorityAction::ChangesetGet;

        let edit = LocalizedEdit {
            ordinal: 1,
            edit_id: "019c0000-0000-7000-8000-000000000023".parse().unwrap(),
            input: LocalizedEditAttempt::LocalePut(ObjectLocalePutInput {
                object_id: "019c0000-0000-7000-8000-000000000024".parse().unwrap(),
                locale: "fr-FR".parse().unwrap(),
                expected_source: ExpectedLocalizedSource {
                    revision: ObjectRevision::INITIAL,
                    digest: format!("blake3:{}", "7".repeat(64)).parse().unwrap(),
                    schema_id: SchemaId::new("campaign").unwrap(),
                    schema_version: SchemaVersion::new(1).unwrap(),
                },
                expected_target: None,
                canonical_content: "{}".to_owned(),
                supersedes_edit_id: None,
                repair_of_validation_result_digest: None,
            }),
            effective: true,
            canonical_json: "{}".to_owned(),
            edit_digest: format!("blake3:{}", "8".repeat(64)).parse().unwrap(),
        };
        let changeset = LocalizedChangeSet {
            changeset_id,
            workspace_id: command_input.workspace_id,
            principal_id: command_input.requesting_principal_id,
            intent: ChangeSetIntent::new("Read one localized proposal").unwrap(),
            resource_intent_id: "019c0000-0000-7000-8000-000000000021".parse().unwrap(),
            resource_intent_digest: format!("blake3:{}", "1".repeat(64)).parse().unwrap(),
            context_pack_id: "019c0000-0000-7000-8000-000000000022".parse().unwrap(),
            context_pack_digest: format!("blake3:{}", "2".repeat(64)).parse().unwrap(),
            base_state: super::super::KnownStateArtifactReference {
                api_version: "proof.dev/known-state/v2".to_owned(),
                authoritative_sequence: 10,
                digest: format!("blake3:{}", "3".repeat(64)).parse().unwrap(),
            },
            created_at: "2026-08-21T09:00:00Z".parse().unwrap(),
            status: ChangeSetStatus::Draft,
            edits: vec![edit],
            proposal_digest: Some(format!("blake3:{}", "9".repeat(64)).parse().unwrap()),
            sealed_changeset_digest: None,
        };
        let success = LocalizedOperationSuccessV1::ChangeSetRead(LocalizedChangeSetReadV1 {
            changeset,
            effective_leaf_digest: format!("blake3:{}", "4".repeat(64)).parse().unwrap(),
        });
        let result = AuthenticatedOperationResultV1::LocalizedSuccess(success);
        let result_digest = result.localized_result_digest().unwrap().unwrap();
        decision.localized_consequence_commitment = Some(
            LocalizedConsequenceCommitmentV1::new(
                AuthorityOperation::ChangesetGetV2,
                LocalizedConsequenceResultKindV1::Success,
                result_digest,
                format!("blake3:{}", "5".repeat(64)).parse().unwrap(),
            )
            .unwrap(),
        );
        let decision_record_digest = decision.previous_authority_record_digest;
        let mut execution = AuthenticatedExecutionV1 {
            command_input,
            actor_context,
            actor_context_evidence,
            actor_context_digest: decision.actor_context_digest,
            decision,
            decision_record_digest,
            decision_envelope_digest: decision_record_digest,
            result,
        };
        execution.validate().unwrap();
        let AuthenticatedOperationResultV1::LocalizedSuccess(
            LocalizedOperationSuccessV1::ChangeSetRead(read),
        ) = &mut execution.result
        else {
            unreachable!()
        };
        read.effective_leaf_digest = format!("blake3:{}", "6".repeat(64)).parse().unwrap();
        assert!(execution.validate().is_err());
    }

    #[test]
    fn localized_failure_result_value_is_the_stable_problem_preimage() {
        let failure = LocalizedOperationFailureV1::new(
            AuthorityOperation::ChangesetGetV2,
            LocalizedOperationFailureKindV1::NotFound,
        )
        .unwrap();
        let result = AuthenticatedOperationResultV1::LocalizedFailure(failure);
        assert_eq!(
            result.localized_result_value().unwrap().unwrap(),
            json!({
                "code": "proof.resource.not_found",
                "detail": null,
                "retryable": false,
                "title": "The exact localized-content resource was not found",
                "type": "urn:proof:problem:resource-not-found",
            })
        );
        let commitment = LocalizedConsequenceCommitmentV1::new(
            AuthorityOperation::ChangesetGetV2,
            LocalizedConsequenceResultKindV1::Failure,
            result.localized_result_digest().unwrap().unwrap(),
            format!("blake3:{}", "7".repeat(64)).parse().unwrap(),
        )
        .unwrap();
        assert!(commitment.matches_result(&result));
    }

    #[test]
    fn creation_failures_have_exact_caller_safe_problem_codes() {
        for (error, expected_kind, expected_code) in [
            (
                LocalizedContentError::IntentSlotMismatch,
                LocalizedOperationFailureKindV1::IntentSlotMismatch,
                "proof.intent.slot_mismatch",
            ),
            (
                LocalizedContentError::SchemaNotFound,
                LocalizedOperationFailureKindV1::SchemaNotFound,
                "proof.schema.not_found",
            ),
            (
                LocalizedContentError::ObjectExists,
                LocalizedOperationFailureKindV1::ObjectExists,
                "proof.state.object_exists",
            ),
        ] {
            let kind = LocalizedOperationFailureKindV1::from_application_error(&error).unwrap();
            assert_eq!(kind, expected_kind);
            assert_eq!(kind.code(), expected_code);
            assert_eq!(kind.public_problem().code, expected_code);
        }
    }

    #[test]
    fn authority_errors_apply_the_disclosure_threshold() {
        assert_eq!(
            AuthorityError::AuthBindingNotFound.code(),
            "proof.auth.binding_not_found"
        );
        assert_eq!(
            AuthorityError::AuthBindingNotFound.public_code(),
            "proof.auth.denied"
        );
        assert_eq!(
            AuthorityError::DelegationUnavailable.public_code(),
            "proof.authorization.denied"
        );
        assert_eq!(
            AuthorityError::ScopeExceeded.public_code(),
            "proof.authorization.scope_exceeded"
        );
        let denied = PublicAuthorityProblem {
            problem_type: "urn:proof:problem:authentication-denied",
            title: "Agent authentication was denied",
            code: "proof.auth.denied",
            detail: None,
            retryable: false,
        };
        assert_eq!(AuthorityError::AuthBindingNotFound.public_problem(), denied);
        assert_eq!(
            AuthorityError::AuthSignatureInvalid.public_problem(),
            denied
        );
    }
}
