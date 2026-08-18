//! Human-operated localized-content application contracts.

use thiserror::Error;

use super::{
    ApprovalName, ChangeSetId, ChangeSetIntent, ChangeSetStatus, ContentDigest,
    ContentResourceIntentId, ContextPackId, EditId, EditionId, EnvironmentId, IdempotencyKey,
    LocaleId, LocaleRevision, ObjectId, ObjectRevision, PrincipalId, ProofId, ReleaseId,
    ReleaseKind, SchemaId, SchemaVersion, Severity, Timestamp, WorkspaceId,
};

/// Exact API version for Human-issued localized-content resource intents.
pub const CONTENT_RESOURCE_INTENT_API_VERSION: &str = "proof.dev/content-resource-intent/v1";
/// Exact API version for localized source closures.
pub const LOCALIZED_CONTEXT_API_VERSION: &str = "proof.dev/context-pack/v2";
/// Exact API version for repairable localized-content `ChangeSets`.
pub const LOCALIZED_CHANGESET_API_VERSION: &str = "proof.dev/changeset/v2";
/// Exact API version for localized-content Edits.
pub const LOCALIZED_EDIT_API_VERSION: &str = "proof.dev/edit/v2";
/// Exact API version for rendition-aware Known State.
pub const KNOWN_STATE_V2_API_VERSION: &str = "proof.dev/known-state/v2";
/// Exact v1 Known State API version used by the bridge.
pub const KNOWN_STATE_V1_API_VERSION: &str = "proof.dev/known-state/v1";
/// Exact API version for rendition-aware Editions.
pub const LOCALIZED_EDITION_API_VERSION: &str = "proof.dev/edition/v2";
/// Exact API version for localized-content Releases.
pub const LOCALIZED_RELEASE_API_VERSION: &str = "proof.dev/release/v2";
/// Exact v1 Release API version used by the bridge.
pub const RELEASE_V1_API_VERSION: &str = "proof.dev/release/v1";
/// Exact v1 Edition API version used by the bridge.
pub const EDITION_V1_API_VERSION: &str = "proof.dev/edition/v1";
/// Pinned deterministic localized-content validator.
pub const LOCALIZED_CONTENT_VALIDATOR: &str = "proof/localized-content/1";
/// Stable finding code for an exact prohibited localized legal claim.
pub const PROHIBITED_LEGAL_CLAIM_CODE: &str = "proof.validation.prohibited_legal_claim";
/// Maximum exact target tuples in one Human-issued resource intent.
pub const MAX_LOCALIZED_TARGETS: usize = 100;
/// Maximum total Edit attempts in one localized `ChangeSet`.
pub const MAX_LOCALIZED_EDITS: u32 = 100;
/// Maximum validation attempts retained by one localized `ChangeSet`.
pub const MAX_LOCALIZED_VALIDATION_ATTEMPTS: u32 = 100;
/// Maximum canonical localized `ContextPack` size.
pub const MAX_LOCALIZED_CONTEXT_BYTES: u64 = 1_048_576;

/// Exact versioned reference to one Known State artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownStateArtifactReference {
    /// Artifact API version.
    pub api_version: String,
    /// Monotonic authoritative sequence.
    pub authoritative_sequence: u64,
    /// Digest reproduced under that API version's context.
    pub digest: ContentDigest,
}

/// Exact versioned reference to one immutable Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditionArtifactReference {
    /// Artifact API version.
    pub api_version: String,
    /// Stable Edition identity.
    pub edition_id: EditionId,
    /// Exact Edition digest.
    pub digest: ContentDigest,
}

/// Exact versioned reference to one immutable Release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseArtifactReference {
    /// Artifact API version.
    pub api_version: String,
    /// Stable Release identity.
    pub release_id: ReleaseId,
    /// Exact Release digest.
    pub digest: ContentDigest,
}

/// Clean Environment baseline bound into a content resource intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedContentBaseline {
    /// Current immutable Release.
    pub release: ReleaseArtifactReference,
    /// Edition selected by the Release.
    pub edition: EditionArtifactReference,
    /// Exact Workspace state represented by the Edition.
    pub known_state: KnownStateArtifactReference,
}

/// One exact Object, Schema, and locale tuple.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalizedContentTarget {
    /// Stable source Object identity.
    pub object_id: ObjectId,
    /// Exact governing Schema identity.
    pub schema_id: SchemaId,
    /// Exact target locale.
    pub locale: LocaleId,
}

/// Input for issuing an immutable exact resource intent through the Human path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueContentResourceIntentCommand {
    /// Candidate intent identity used when no idempotent effect exists.
    pub intent_id: ContentResourceIntentId,
    /// Exact Environment whose current Release becomes the baseline.
    pub environment_id: EnvironmentId,
    /// Sorted unique finite target tuples.
    pub targets: Vec<LocalizedContentTarget>,
    /// Caller-visible retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical issuance time.
    pub issued_at: Timestamp,
}

/// One immutable Human-issued localized-content resource intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentResourceIntent {
    /// Stable resource-intent identity.
    pub intent_id: ContentResourceIntentId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Independently authenticated issuing Human.
    pub issued_by_principal_id: PrincipalId,
    /// Canonical issuance time.
    pub issued_at: Timestamp,
    /// Exact target Environment.
    pub environment_id: EnvironmentId,
    /// Clean versioned baseline.
    pub base: LocalizedContentBaseline,
    /// Sorted unique exact target tuples.
    pub targets: Vec<LocalizedContentTarget>,
    /// Exact canonical artifact bytes.
    pub canonical_json: String,
    /// Domain-separated content digest.
    pub intent_digest: ContentDigest,
}

/// One deterministic exact-value policy rule carried by a `ContextPack`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LocalizedPolicyRule {
    /// Exact target locale.
    pub locale: LocaleId,
    /// Canonical RFC 6901 JSON Pointer.
    pub pointer: String,
    /// Sorted unique exact prohibited string values.
    pub disallowed_values: Vec<String>,
}

/// Explicit budgets committed by one localized `ContextPack`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalizedContextLimits {
    /// Maximum distinct Object identities.
    pub max_objects: u32,
    /// Maximum total Edit attempts, including repairs.
    pub max_edits: u32,
    /// Maximum validation attempts.
    pub max_validation_attempts: u32,
    /// Maximum canonical `ContextPack` bytes.
    pub max_bytes: u64,
}

/// Input for building an exact localized source closure from a persisted intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildLocalizedContextCommand {
    /// Candidate `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Exact persisted resource-intent identity.
    pub resource_intent_id: ContentResourceIntentId,
    /// Required verified resource-intent digest.
    pub resource_intent_digest: ContentDigest,
    /// Human-owned deterministic policy rules.
    pub policy_rules: Vec<LocalizedPolicyRule>,
    /// Explicit `ContextPack` budgets.
    pub limits: LocalizedContextLimits,
    /// Caller-visible retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical creation time.
    pub created_at: Timestamp,
    /// Exclusive canonical freshness bound.
    pub expires_at: Timestamp,
}

/// One immutable exact localized-content source closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedContextPack {
    /// Stable `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Authenticated Human that built the pack.
    pub principal_id: PrincipalId,
    /// Bound resource-intent identity.
    pub resource_intent_id: ContentResourceIntentId,
    /// Bound resource-intent digest.
    pub resource_intent_digest: ContentDigest,
    /// Exact baseline copied from the intent.
    pub base: LocalizedContentBaseline,
    /// Domain-separated exact policy-bundle digest.
    pub policy_digest: ContentDigest,
    /// Committed budgets.
    pub limits: LocalizedContextLimits,
    /// Canonical creation time.
    pub created_at: Timestamp,
    /// Exclusive freshness bound.
    pub expires_at: Timestamp,
    /// Exact canonical `ContextPack` bytes.
    pub manifest_json: String,
    /// Domain-separated `ContextPack` digest.
    pub context_pack_digest: ContentDigest,
}

/// Input for creating a repairable localized `ChangeSet` bound to exact evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateLocalizedChangeSetCommand {
    /// Candidate `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Normalized Human-declared reason.
    pub intent: ChangeSetIntent,
    /// Exact resource-intent identity.
    pub resource_intent_id: ContentResourceIntentId,
    /// Exact resource-intent digest.
    pub resource_intent_digest: ContentDigest,
    /// Exact `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Exact `ContextPack` digest.
    pub context_pack_digest: ContentDigest,
    /// Caller-visible retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical creation time.
    pub created_at: Timestamp,
}

/// Exact locale-neutral source precondition for one rendition Edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedLocalizedSource {
    /// Immutable source revision.
    pub revision: ObjectRevision,
    /// Exact source Object digest.
    pub digest: ContentDigest,
    /// Exact governing Schema identity.
    pub schema_id: SchemaId,
    /// Exact governing Schema version.
    pub schema_version: SchemaVersion,
}

/// Exact existing rendition precondition for a replacement Edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedLocalizedTarget {
    /// Exact current rendition revision.
    pub revision: LocaleRevision,
    /// Exact current rendition digest.
    pub digest: ContentDigest,
}

/// Semantic actor input for one complete `object.locale.put` Edit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectLocalePutInput {
    /// Stable source Object identity.
    pub object_id: ObjectId,
    /// Exact target locale.
    pub locale: LocaleId,
    /// Exact immutable source precondition.
    pub expected_source: ExpectedLocalizedSource,
    /// Exact base rendition precondition, or absence assertion.
    pub expected_target: Option<ExpectedLocalizedTarget>,
    /// Complete RFC 8785 canonical localized JSON Object.
    pub canonical_content: String,
    /// Current active Edit being repaired, absent for the first attempt.
    pub supersedes_edit_id: Option<EditId>,
    /// Latest invalid validation result authorizing the repair edge.
    pub repair_of_validation_result_digest: Option<ContentDigest>,
}

/// Input for atomically appending localized Edits with trusted assigned identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddLocalizedEditsCommand {
    /// Target localized `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Non-empty semantic Edit inputs.
    pub edits: Vec<ObjectLocalePutInput>,
    /// Trusted Proof-assigned Edit identities, positionally aligned with inputs.
    pub assigned_edit_ids: Vec<EditId>,
    /// Caller-visible retry key.
    pub idempotency_key: IdempotencyKey,
}

/// One verified persisted localized Edit attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedEdit {
    /// One-based append ordinal.
    pub ordinal: u32,
    /// Proof-assigned stable Edit identity.
    pub edit_id: EditId,
    /// Exact target and preconditions.
    pub input: ObjectLocalePutInput,
    /// Whether this is the current unsuperseded leaf for its target.
    pub effective: bool,
    /// Exact canonical Edit artifact bytes.
    pub canonical_json: String,
    /// Domain-separated Edit artifact digest.
    pub edit_digest: ContentDigest,
}

/// Result of one atomic localized Edit append.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddedLocalizedEdits {
    /// Target `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Persisted Edit identities in order.
    pub edit_ids: Vec<EditId>,
    /// First one-based ordinal assigned by the operation.
    pub first_ordinal: u32,
    /// Total retained attempts after the append.
    pub total_edit_count: u32,
}

/// Complete verified read model for one localized `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedChangeSet {
    /// Stable `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Authenticated initiating Human.
    pub principal_id: PrincipalId,
    /// Declared intent.
    pub intent: ChangeSetIntent,
    /// Exact resource-intent identity and digest.
    pub resource_intent_id: ContentResourceIntentId,
    /// Exact resource-intent digest.
    pub resource_intent_digest: ContentDigest,
    /// Exact `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Exact `ContextPack` digest.
    pub context_pack_digest: ContentDigest,
    /// Exact versioned baseline state.
    pub base_state: KnownStateArtifactReference,
    /// Canonical creation time.
    pub created_at: Timestamp,
    /// Current lifecycle state.
    pub status: ChangeSetStatus,
    /// Complete append-only Edit history.
    pub edits: Vec<LocalizedEdit>,
    /// Current proposal digest, when at least one Edit exists.
    pub proposal_digest: Option<ContentDigest>,
    /// Final sealed `ChangeSet` digest after valid validation.
    pub sealed_changeset_digest: Option<ContentDigest>,
}

/// Effective-only deterministic localized `ChangeSet` projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedChangeSetDiff {
    /// Target `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Digest covering full history plus this effective projection.
    pub proposal_digest: ContentDigest,
    /// Digest of the effective-leaf projection.
    pub effective_leaf_digest: ContentDigest,
    /// Effective Edits sorted by exact target.
    pub effective_edits: Vec<LocalizedEdit>,
}

/// One structured deterministic localized-content validation finding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedFinding {
    /// Stable machine-readable finding code.
    pub code: String,
    /// Finding severity.
    pub severity: Severity,
    /// Exact active Edit that produced the finding.
    pub edit_id: EditId,
    /// Exact source Object.
    pub object_id: ObjectId,
    /// Exact target locale.
    pub locale: LocaleId,
    /// Exact JSON Pointer, when applicable.
    pub pointer: Option<String>,
    /// Pinned validator identity.
    pub validator: String,
    /// Exact policy bundle digest.
    pub policy_digest: ContentDigest,
}

/// One immutable localized-content validation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedValidation {
    /// Target `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Contiguous one-based attempt number.
    pub attempt: u32,
    /// Exact prior attempt digest, absent for attempt one.
    pub previous_validation_result_digest: Option<ContentDigest>,
    /// Exact proposal digest validated.
    pub proposal_digest: ContentDigest,
    /// Exact effective-leaf digest validated.
    pub effective_leaf_digest: ContentDigest,
    /// Whether no blocking findings were produced.
    pub valid: bool,
    /// Deterministically ordered findings.
    pub findings: Vec<LocalizedFinding>,
    /// External digest of the canonical result artifact.
    pub validation_results_digest: ContentDigest,
    /// Final seal when valid.
    pub sealed_changeset_digest: Option<ContentDigest>,
    /// Resulting lifecycle state: `draft` when invalid and `ready` when valid.
    pub status: ChangeSetStatus,
}

/// Result of submitting one exact sealed localized `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmittedLocalizedChangeSet {
    /// Target `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Exact sealed digest.
    pub sealed_changeset_digest: ContentDigest,
    /// Validation-chain head.
    pub validation_results_digest: ContentDigest,
    /// Canonical submission time.
    pub submitted_at: Timestamp,
    /// Resulting status.
    pub status: ChangeSetStatus,
}

/// Result of approving one exact sealed localized `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedLocalizedChangeSet {
    /// Target `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Exact named approval.
    pub approval: ApprovalName,
    /// Exact sealed digest.
    pub sealed_changeset_digest: ContentDigest,
    /// Validation-chain head.
    pub validation_results_digest: ContentDigest,
    /// Canonical approval time.
    pub approved_at: Timestamp,
    /// Resulting status.
    pub status: ChangeSetStatus,
}

/// One immutable accepted locale rendition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectLocaleRevision {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Stable source Object.
    pub object_id: ObjectId,
    /// Exact target locale.
    pub locale: LocaleId,
    /// Immutable rendition revision.
    pub revision: LocaleRevision,
    /// Immediately preceding rendition digest.
    pub previous_revision_digest: Option<ContentDigest>,
    /// Immutable source revision.
    pub source_object_revision: ObjectRevision,
    /// Immutable source digest.
    pub source_object_digest: ContentDigest,
    /// Governing Schema.
    pub schema_id: SchemaId,
    /// Governing Schema version.
    pub schema_version: SchemaVersion,
    /// Complete canonical localized content.
    pub canonical_content: String,
    /// Producing `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Producing effective Edit.
    pub edit_id: EditId,
    /// Fact sequence.
    pub authoritative_sequence: u64,
    /// Exact canonical artifact bytes.
    pub manifest_json: String,
    /// Domain-separated artifact digest.
    pub rendition_digest: ContentDigest,
}

/// Input for committing an approved localized `ChangeSet`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitLocalizedChangeSetCommand {
    /// Target approved `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Consequential retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical commit time.
    pub committed_at: Timestamp,
}

/// Result of one atomic localized-content commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedLocalizedChangeSet {
    /// Target `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Exact sealed `ChangeSet` digest.
    pub sealed_changeset_digest: ContentDigest,
    /// Validation-chain head.
    pub validation_results_digest: ContentDigest,
    /// Exact predecessor state.
    pub previous_state: KnownStateArtifactReference,
    /// Exact resulting rendition-aware state.
    pub resulting_state: KnownStateArtifactReference,
    /// Accepted rendition revisions sorted by exact target.
    pub renditions: Vec<ObjectLocaleRevision>,
    /// Canonical commit time.
    pub committed_at: Timestamp,
    /// Resulting lifecycle state.
    pub status: ChangeSetStatus,
}

/// Input for creating the exact Edition produced by one localized commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateLocalizedEditionCommand {
    /// Candidate Edition identity.
    pub edition_id: EditionId,
    /// Exact committed localized `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Required resulting Known State digest.
    pub resulting_state_digest: ContentDigest,
    /// Caller-visible retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical creation time.
    pub created_at: Timestamp,
}

/// One immutable rendition-aware Edition tied to one localized commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedEdition {
    /// Stable Edition identity.
    pub edition_id: EditionId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Authenticated creating Human.
    pub principal_id: PrincipalId,
    /// Exact committed `ChangeSet`.
    pub changeset_id: ChangeSetId,
    /// Exact previous baseline Edition.
    pub base_edition: EditionArtifactReference,
    /// Exact resulting Known State.
    pub state: KnownStateArtifactReference,
    /// Source Schema-set digest.
    pub schema_set_digest: ContentDigest,
    /// Rendition-aware Object-set digest.
    pub object_set_digest: ContentDigest,
    /// Canonical Edition manifest.
    pub manifest_json: String,
    /// Domain-separated Edition digest.
    pub edition_digest: ContentDigest,
    /// Canonical creation time.
    pub created_at: Timestamp,
}

/// Input for promoting one exact localized Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteLocalizedReleaseCommand {
    /// Candidate Release identity.
    pub release_id: ReleaseId,
    /// Candidate portable Proof identity.
    pub proof_id: ProofId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Exact localized Edition.
    pub edition_id: EditionId,
    /// Exact Release expected to remain current.
    pub expected_base_release_id: ReleaseId,
    /// Consequential retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical release time.
    pub released_at: Timestamp,
}

/// Input for a Human rollback recorded as a v2 Release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackLocalizedReleaseCommand {
    /// Candidate Release identity.
    pub release_id: ReleaseId,
    /// Candidate portable Proof identity.
    pub proof_id: ProofId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Exact Release expected to remain current.
    pub expected_current_release_id: ReleaseId,
    /// Historical Release whose Edition will be selected.
    pub rollback_target_release_id: ReleaseId,
    /// Consequential retry key.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical release time.
    pub released_at: Timestamp,
}

/// One immutable v2 Release and its signed Proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedRelease {
    /// Stable Release identity.
    pub release_id: ReleaseId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Exact versioned selected Edition.
    pub edition: EditionArtifactReference,
    /// Promotion or rollback classification.
    pub kind: ReleaseKind,
    /// Monotonic global Release sequence.
    pub release_sequence: u64,
    /// Exact prior Environment Release.
    pub previous_release_id: Option<ReleaseId>,
    /// Historical rollback target, when applicable.
    pub rollback_target_release_id: Option<ReleaseId>,
    /// Exact localized `ChangeSet` for promotions.
    pub changeset_id: Option<ChangeSetId>,
    /// Exact resource intent for promotions.
    pub resource_intent_id: Option<ContentResourceIntentId>,
    /// Canonical Release manifest.
    pub manifest_json: String,
    /// Domain-separated Release digest.
    pub release_digest: ContentDigest,
    /// Portable Proof identity.
    pub proof_id: ProofId,
    /// Domain-separated canonical envelope digest.
    pub proof_envelope_digest: ContentDigest,
    /// Exact signing key identity.
    pub key_id: String,
    /// Exact canonical DSSE envelope.
    pub proof_envelope_json: String,
    /// Canonical release time.
    pub released_at: Timestamp,
}

/// One exact `(object_id, locale)` released-content request.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReleasedLocaleTarget {
    /// Stable source Object identity.
    pub object_id: ObjectId,
    /// Exact requested locale.
    pub locale: LocaleId,
}

/// Input for an exact Human-path released-rendition query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryReleasedRenditionsCommand {
    /// Exact released Environment.
    pub environment_id: EnvironmentId,
    /// Sorted unique exact targets; never a wildcard.
    pub targets: Vec<ReleasedLocaleTarget>,
    /// Injected evaluation time.
    pub evaluated_at: Timestamp,
}

/// One exact rendition selected from a released v2 Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedRendition {
    /// Stable source Object.
    pub object_id: ObjectId,
    /// Exact target locale.
    pub locale: LocaleId,
    /// Immutable source revision and digest.
    pub source_revision: ObjectRevision,
    /// Exact source digest.
    pub source_digest: ContentDigest,
    /// Exact rendition revision and digest.
    pub rendition_revision: LocaleRevision,
    /// Exact rendition digest.
    pub rendition_digest: ContentDigest,
    /// Governing Schema identity.
    pub schema_id: SchemaId,
    /// Governing Schema version.
    pub schema_version: SchemaVersion,
    /// Complete canonical localized content.
    pub canonical_content: String,
}

/// Result of one exact released-rendition query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedRenditionQuery {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Exact Environment queried.
    pub environment_id: EnvironmentId,
    /// Current v2 Release.
    pub release_id: ReleaseId,
    /// Selected versioned Edition.
    pub edition: EditionArtifactReference,
    /// Returned renditions in request order.
    pub renditions: Vec<ReleasedRendition>,
}

/// Input for verifying one persisted localized Release and Proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyLocalizedReleaseCommand {
    /// Release to verify.
    pub release_id: ReleaseId,
    /// Injected verification time.
    pub verified_at: Timestamp,
}

/// Structured localized Release verification report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalizedReleaseVerification {
    /// Verified Release identity.
    pub release_id: ReleaseId,
    /// Verified Proof identity.
    pub proof_id: ProofId,
    /// Whether the complete exact-delta and signature closure verified.
    pub valid: bool,
    /// Deterministically ordered failure codes.
    pub findings: Vec<String>,
    /// Canonical verification time.
    pub verified_at: Timestamp,
}

/// Human-path persistence boundary for the localized-content foundation.
#[allow(
    clippy::missing_errors_doc,
    reason = "the shared error enum is the complete operation contract"
)]
pub trait LocalizedContentRepository {
    /// Issues or idempotently replays one exact resource intent.
    fn issue_content_resource_intent(
        &self,
        command: IssueContentResourceIntentCommand,
    ) -> Result<ContentResourceIntent, LocalizedContentError>;
    /// Returns one verified resource intent.
    fn get_content_resource_intent(
        &self,
        intent_id: ContentResourceIntentId,
    ) -> Result<ContentResourceIntent, LocalizedContentError>;
    /// Builds or idempotently replays one exact `ContextPack`.
    fn build_localized_context(
        &self,
        command: BuildLocalizedContextCommand,
    ) -> Result<LocalizedContextPack, LocalizedContentError>;
    /// Returns one verified localized `ContextPack`.
    fn get_localized_context(
        &self,
        context_pack_id: ContextPackId,
    ) -> Result<LocalizedContextPack, LocalizedContentError>;
    /// Creates or idempotently replays one repairable localized `ChangeSet`.
    fn create_localized_changeset(
        &self,
        command: CreateLocalizedChangeSetCommand,
    ) -> Result<LocalizedChangeSet, LocalizedContentError>;
    /// Appends one atomic batch of localized Edit attempts.
    fn add_localized_edits(
        &self,
        command: AddLocalizedEditsCommand,
    ) -> Result<AddedLocalizedEdits, LocalizedContentError>;
    /// Returns one complete verified localized `ChangeSet`.
    fn inspect_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<LocalizedChangeSet, LocalizedContentError>;
    /// Returns one effective-only diff while verifying full lineage.
    fn diff_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<LocalizedChangeSetDiff, LocalizedContentError>;
    /// Appends one immutable validation result and transitions Draft or Ready.
    fn validate_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<LocalizedValidation, LocalizedContentError>;
    /// Submits one exact validation-sealed proposal.
    fn submit_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
        submitted_at: Timestamp,
    ) -> Result<SubmittedLocalizedChangeSet, LocalizedContentError>;
    /// Records one exact Human approval.
    fn approve_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
        approval: ApprovalName,
        approved_at: Timestamp,
    ) -> Result<ApprovedLocalizedChangeSet, LocalizedContentError>;
    /// Atomically commits only effective rendition leaves.
    fn commit_localized_changeset(
        &self,
        command: CommitLocalizedChangeSetCommand,
    ) -> Result<CommittedLocalizedChangeSet, LocalizedContentError>;
    /// Creates the exact Edition produced by one localized commit.
    fn create_localized_edition(
        &self,
        command: CreateLocalizedEditionCommand,
    ) -> Result<LocalizedEdition, LocalizedContentError>;
    /// Promotes one exact localized Edition and signs its Proof.
    fn promote_localized_release(
        &self,
        command: PromoteLocalizedReleaseCommand,
    ) -> Result<LocalizedRelease, LocalizedContentError>;
    /// Appends a v2 Human rollback selecting one historical Edition.
    fn rollback_localized_release(
        &self,
        command: RollbackLocalizedReleaseCommand,
    ) -> Result<LocalizedRelease, LocalizedContentError>;
    /// Returns exact released renditions without fallback.
    fn query_released_renditions(
        &self,
        command: QueryReleasedRenditionsCommand,
    ) -> Result<ReleasedRenditionQuery, LocalizedContentError>;
    /// Verifies one localized Release, exact delta, and Proof.
    fn verify_localized_release(
        &self,
        command: VerifyLocalizedReleaseCommand,
    ) -> Result<LocalizedReleaseVerification, LocalizedContentError>;
}

/// A localized-content operation failed without broadening or partially mutating scope.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LocalizedContentError {
    /// The local operating-system identity is not an enabled Human Principal.
    #[error("the current local identity is not authenticated as a Human for this Workspace")]
    Unauthenticated,
    /// A requested exact resource is absent or hidden.
    #[error("the requested localized-content resource was not found")]
    NotFound,
    /// The requested operation/artifact combination is outside the closed version matrix.
    #[error("the requested operation is unsupported for the current artifact version")]
    UnsupportedVersion,
    /// Input structure, ordering, pointer, policy, or cardinality is invalid.
    #[error("the localized-content input violates its closed contract")]
    InvalidInput,
    /// The immutable exact resource intent does not match the requested closure.
    #[error("the operation differs from the immutable localized-content resource intent")]
    IntentMismatch,
    /// Source Object revision, digest, or Schema preconditions are stale.
    #[error("the locale-neutral source precondition does not match")]
    SourceConflict,
    /// Target rendition absence, revision, or digest preconditions are stale.
    #[error("the exact locale rendition precondition does not match")]
    TargetConflict,
    /// Workspace state or Environment pointer changed from the exact baseline.
    #[error("the localized-content baseline changed concurrently")]
    StateConflict,
    /// A target already has an active unsuperseded Edit.
    #[error("the localized ChangeSet already has an active Edit for the target")]
    DuplicateActiveTarget,
    /// The requested supersession is cross-target, forked, cyclic, skipped, or stale.
    #[error("the localized Edit supersession edge is invalid")]
    InvalidSupersession,
    /// Repair evidence is absent, stale, or does not contain the required finding.
    #[error("the localized Edit repair evidence does not match the latest invalid result")]
    InvalidRepairEvidence,
    /// The `ChangeSet` is not currently editable.
    #[error("localized Edits can only be appended to a Draft ChangeSet")]
    NotDraft,
    /// The `ChangeSet` lacks a valid exact validation seal.
    #[error("the localized ChangeSet is not Ready")]
    NotReady,
    /// The `ChangeSet` has not been submitted.
    #[error("the localized ChangeSet is not Submitted")]
    NotSubmitted,
    /// The `ChangeSet` lacks the required exact Human approval.
    #[error("the localized ChangeSet is not Approved")]
    NotApproved,
    /// Required immutable validation, approval, or provenance evidence is missing.
    #[error("localized-content evidence is incomplete")]
    EvidenceMissing,
    /// An explicit Object, Edit, validation, or byte budget was exceeded.
    #[error("the localized-content operation exceeds its committed budget")]
    LimitExceeded,
    /// The retry key is already bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// The Environment policy denied this exact release or approval.
    #[error("localized-content policy denied the requested operation")]
    PolicyDenied,
    /// Signing or key resolution is unavailable.
    #[error("localized Release Proof signing is unavailable: {0}")]
    Signing(String),
    /// Persisted canonical evidence failed deterministic reconstruction.
    #[error("localized-content integrity verification failed: {0}")]
    Integrity(String),
    /// Local persistence could not complete safely.
    #[error("localized-content storage is unavailable: {0}")]
    Storage(String),
}
