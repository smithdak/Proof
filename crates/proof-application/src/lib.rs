#![forbid(unsafe_code)]

//! Transport-independent application contracts for Proof.

pub use proof_domain::{
    ArtifactKind, AuthorityRootTransitionId, BindingId, ChangeSetId, ChangeSetIntent,
    ChangeSetIntentError, ChangeSetStatus, ContentDigest, ContentResourceIntentId, ContextPackId,
    CorrelationId, DelegationId, DigestAlgorithm, EditId, EditionId, EnrollmentChallengeId,
    EnvironmentId, EnvironmentIdError, IdempotencyKey, IdentifierError, LocaleId, LocaleIdError,
    LocaleRevision, LocaleRevisionError, ObjectId, ObjectLifecycleState, ObjectRevision,
    ObjectRevisionError, OperationId, PresentationId, PrincipalId, PrincipalType, ProofId,
    ReleaseId, ReleaseKind, RevocationId, SchemaId, SchemaIdError, SchemaVersion,
    SchemaVersionError, Timestamp, TimestampError, WorkspaceId,
};
use serde::Serialize;
use thiserror::Error;

pub mod authority;
pub mod evidence;
mod localized;
pub use evidence::*;
pub use localized::*;

/// The stable API version for non-streaming command results.
pub const RESULT_API_VERSION: &str = "proof.dev/result/v1";

/// A successful non-streaming application result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResultEnvelope<T> {
    /// The version of this envelope shape.
    pub api_version: &'static str,
    /// The stable operation name.
    pub operation: String,
    /// The identity of this execution.
    pub operation_id: String,
    /// The identity of the surrounding workflow.
    pub correlation_id: String,
    /// Always true for a successful result envelope.
    pub ok: bool,
    /// Operation-specific structured data.
    pub data: T,
    /// Non-blocking structured warnings.
    pub warnings: Vec<Warning>,
    /// Non-authoritative execution metadata.
    pub meta: ResultMeta,
}

impl<T> ResultEnvelope<T> {
    /// Builds a successful application result.
    #[must_use]
    pub fn success(
        operation: impl Into<String>,
        operation_id: OperationId,
        correlation_id: CorrelationId,
        data: T,
    ) -> Self {
        Self {
            api_version: RESULT_API_VERSION,
            operation: operation.into(),
            operation_id: operation_id.to_string(),
            correlation_id: correlation_id.to_string(),
            ok: true,
            data,
            warnings: Vec::new(),
            meta: ResultMeta::current(),
        }
    }
}

/// A non-blocking warning returned with a successful operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Warning {
    /// Stable machine-readable warning code.
    pub code: String,
    /// Human-readable warning text.
    pub message: String,
}

/// Non-authoritative metadata accompanying a command result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResultMeta {
    /// Version of the Proof executable and application contracts.
    pub proof_version: &'static str,
    /// Selected Workspace identity, when one has been resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Operating Principal identity, when one has been resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
}

impl ResultMeta {
    /// Returns metadata for this build before a Workspace or Principal exists.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            proof_version: env!("CARGO_PKG_VERSION"),
            workspace_id: None,
            principal_id: None,
        }
    }
}

/// A transport-independent expected failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Problem {
    /// Documentation identifier for this problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// Stable human summary.
    pub title: String,
    /// Optional HTTP status for HTTP projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Caller-safe detail about this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Stable machine-readable error code.
    pub code: String,
    /// Stable operation name.
    pub operation: String,
    /// Identity of this execution.
    pub operation_id: String,
    /// Identity of the surrounding workflow.
    pub correlation_id: String,
    /// Whether unchanged input may succeed when retried.
    pub retryable: bool,
    /// Structured validation or policy findings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

impl Problem {
    /// Builds a caller-safe problem without transport-specific status.
    #[must_use]
    pub fn new(
        problem_type: impl Into<String>,
        title: impl Into<String>,
        code: impl Into<String>,
        operation: impl Into<String>,
        operation_id: OperationId,
        correlation_id: CorrelationId,
    ) -> Self {
        Self {
            problem_type: problem_type.into(),
            title: title.into(),
            status: None,
            detail: None,
            code: code.into(),
            operation: operation.into(),
            operation_id: operation_id.to_string(),
            correlation_id: correlation_id.to_string(),
            retryable: false,
            findings: Vec::new(),
        }
    }

    /// Maps the precise problem code to its broad CLI exit category.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::for_problem_code(&self.code)
    }
}

/// A structured validation or policy finding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    /// Stable machine-readable finding code.
    pub code: String,
    /// Finding severity.
    pub severity: Severity,
    /// JSON Pointer or domain path locating the finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// Validator identity and version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator: Option<String>,
    /// Caller-safe human description.
    pub message: String,
    /// Typed repair guidance when a safe repair is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repair: Option<Repair>,
}

/// Finding severity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational evidence.
    Info,
    /// Non-blocking issue.
    Warning,
    /// Blocking issue.
    Error,
}

/// Typed, caller-safe repair guidance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Repair {
    /// Stable repair operation kind.
    pub kind: String,
    /// Target JSON Pointer or domain path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// Caller-safe expected value description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
}

/// Broad CLI exit categories from the public CLI contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExitCode {
    /// Successful execution.
    Success = 0,
    /// CLI usage or input syntax error.
    Usage = 2,
    /// Validation or policy precondition failure.
    Validation = 3,
    /// Authentication or authorization failure.
    Authorization = 4,
    /// Concurrency or state conflict.
    Conflict = 5,
    /// Requested resource was not found.
    NotFound = 6,
    /// A dependency or service is unavailable.
    Unavailable = 7,
    /// Integrity or verification failure.
    Integrity = 8,
    /// Operation timed out or was cancelled safely.
    Interrupted = 9,
    /// Unexpected internal failure.
    Internal = 10,
}

impl ExitCode {
    /// Classifies one stable problem code.
    #[must_use]
    pub fn for_problem_code(code: &str) -> Self {
        if code.starts_with("proof.input.") {
            Self::Usage
        } else if code.starts_with("proof.auth.")
            || code.starts_with("proof.delegation.")
            || code == "proof.approval.required"
        {
            Self::Authorization
        } else if code == "proof.schema.not_found" || code == "proof.resource.not_found" {
            Self::NotFound
        } else if code.starts_with("proof.validation.")
            || code.starts_with("proof.policy.")
            || code.starts_with("proof.schema.")
            || code.starts_with("proof.relationship.")
        {
            Self::Validation
        } else if code.starts_with("proof.state.")
            || code.starts_with("proof.changeset.")
            || code.starts_with("proof.idempotency.")
            || code.starts_with("proof.intent.")
        {
            Self::Conflict
        } else if code.starts_with("proof.digest.")
            || code.starts_with("proof.signature.")
            || code.starts_with("proof.evidence.")
            || code.starts_with("proof.artifact.")
        {
            Self::Integrity
        } else if code == "proof.dependency.unavailable" {
            Self::Unavailable
        } else if code == "proof.operation.timeout" || code == "proof.operation.cancelled" {
            Self::Interrupted
        } else {
            Self::Internal
        }
    }
}

/// Input for the Workspace initialization application operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializeWorkspaceCommand {
    /// Identity assigned to the new Workspace.
    pub workspace_id: WorkspaceId,
    /// Human Principal bound to the authenticated local identity.
    pub bootstrap_principal_id: PrincipalId,
}

/// Successful result of initializing one Workspace repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializedWorkspace {
    /// Persisted Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Persisted bootstrap Principal identity.
    pub principal_id: PrincipalId,
}

/// Persistence port used by the Workspace initialization operation.
pub trait WorkspaceRepository {
    /// Atomically initializes empty Workspace storage.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceInitializationError`] if storage already exists or
    /// the adapter cannot safely persist the initial Workspace.
    fn initialize(
        &self,
        command: InitializeWorkspaceCommand,
    ) -> Result<InitializedWorkspace, WorkspaceInitializationError>;
}

/// Workspace initialization failed without committing a usable Workspace.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceInitializationError {
    /// Workspace state or configuration already exists at the selected target.
    #[error("a Workspace is already initialized at the selected location")]
    AlreadyExists,
    /// The selected root is missing, inaccessible, or not a directory.
    #[error("the selected Workspace root is unavailable: {0}")]
    RootUnavailable(String),
    /// The local operating identity could not be authenticated.
    #[error("local identity authentication failed: {0}")]
    IdentityUnavailable(String),
    /// Local storage failed while initializing the Workspace.
    #[error("Workspace storage initialization failed: {0}")]
    Storage(String),
}

/// Initializes a Workspace through the configured persistence port.
///
/// # Errors
///
/// Returns [`WorkspaceInitializationError`] without producing a successful
/// result when the repository rejects or cannot persist the operation.
pub fn initialize_workspace(
    repository: &impl WorkspaceRepository,
    command: InitializeWorkspaceCommand,
) -> Result<InitializedWorkspace, WorkspaceInitializationError> {
    repository.initialize(command)
}

/// Current state of a selected Workspace repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceStatus {
    /// No Workspace configuration or private state exists.
    Uninitialized,
    /// Configuration, storage, and Known State agree.
    Initialized(InitializedWorkspaceStatus),
}

/// Verified status of an initialized Workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializedWorkspaceStatus {
    /// Verified Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated Principal bound to the current local identity.
    pub principal_id: PrincipalId,
    /// Version of the local persistent schema.
    pub storage_schema_version: u32,
    /// Last authoritative fact sequence included in this state.
    pub authoritative_sequence: u64,
    /// Reproducible digest of this Known State.
    pub state_digest: ContentDigest,
}

/// Persistence port used to inspect and verify Workspace state.
pub trait WorkspaceStatusRepository {
    /// Inspects the selected repository without mutating it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceStatusError`] when partial, corrupt, or unavailable
    /// storage prevents a verified status result.
    fn status(&self) -> Result<WorkspaceStatus, WorkspaceStatusError>;
}

/// Workspace state could not be inspected or verified.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkspaceStatusError {
    /// Only part of the required Workspace layout exists.
    #[error("the selected Workspace has incomplete local state")]
    Incomplete,
    /// The current local identity is not an enabled Workspace Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Persisted representations disagree or fail verification.
    #[error("Workspace integrity verification failed: {0}")]
    Integrity(String),
    /// Storage could not be read safely.
    #[error("Workspace storage is unavailable: {0}")]
    Storage(String),
}

/// Inspects a Workspace through the configured persistence port.
///
/// # Errors
///
/// Returns [`WorkspaceStatusError`] when the repository cannot produce a
/// verified status result.
pub fn workspace_status(
    repository: &impl WorkspaceStatusRepository,
) -> Result<WorkspaceStatus, WorkspaceStatusError> {
    repository.status()
}

/// Input for one exact delegated Workspace-status read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegatedWorkspaceStatusCommand {
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Presented Delegation.
    pub delegation_id: DelegationId,
    /// Injected authority-evaluation time.
    pub evaluated_at: Timestamp,
}

/// Verified Workspace status plus exact Delegation-evaluation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegatedWorkspaceStatus {
    /// Verified Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Caller-declared operating Agent Principal evaluated as the Delegation
    /// recipient; it is not an authenticated Agent binding in v1.
    pub principal_id: PrincipalId,
    /// Evaluated Delegation.
    pub delegation_id: DelegationId,
    /// Version of the local persistent schema.
    pub storage_schema_version: u32,
    /// Last authoritative fact sequence included in Known State.
    pub authoritative_sequence: u64,
    /// Reproducible Known State digest.
    pub state_digest: ContentDigest,
    /// Digest of the exact authorization decision.
    pub authorization_decision_digest: ContentDigest,
}

/// Port that evaluates authority and returns Workspace status as one operation.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait DelegatedWorkspaceStatusRepository {
    /// Evaluates the presented Delegation and reads verified status.
    fn delegated_workspace_status(
        &self,
        command: DelegatedWorkspaceStatusCommand,
    ) -> Result<DelegatedWorkspaceStatus, DelegatedWorkspaceStatusError>;
}

/// A delegated Workspace-status read failed without broadening visibility.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DelegatedWorkspaceStatusError {
    /// The requesting identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The Delegation denied this exact read.
    #[error("Workspace status is outside delegated authority")]
    Denied,
    /// Persisted state failed deterministic verification.
    #[error("Workspace integrity verification failed: {0}")]
    Integrity(String),
    /// Workspace state is unavailable.
    #[error("Workspace storage is unavailable: {0}")]
    Storage(String),
}

/// Evaluates delegated authority and reads Workspace status atomically at the
/// application boundary.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn delegated_workspace_status(
    repository: &impl DelegatedWorkspaceStatusRepository,
    command: DelegatedWorkspaceStatusCommand,
) -> Result<DelegatedWorkspaceStatus, DelegatedWorkspaceStatusError> {
    repository.delegated_workspace_status(command)
}

/// The policy profile applied to initial local `ChangeSet`s.
pub const LOCAL_POLICY_PROFILE: &str = "proof.local/policy/default/v1";
/// The validation profile applied to initial local `ChangeSet`s.
pub const LOCAL_VALIDATION_PROFILE: &str = "proof.local/validation/default/v1";

/// Input for creating an empty intent-scoped `ChangeSet` draft.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateChangeSetCommand {
    /// Candidate identity used when no idempotent result already exists.
    pub changeset_id: ChangeSetId,
    /// Normalized reason for the proposed governed mutation.
    pub intent: ChangeSetIntent,
    /// Caller-required base state, or the current state when omitted.
    pub requested_base_state: Option<ContentDigest>,
    /// Caller-visible retry identity for draft creation.
    pub idempotency_key: IdempotencyKey,
    /// Injected creation time used for a newly persisted draft.
    pub created_at: Timestamp,
}

/// A persisted empty `ChangeSet` bound to identity and exact Known State.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DraftChangeSet {
    /// Stable `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated initiating Principal.
    pub principal_id: PrincipalId,
    /// Normalized declared intent.
    pub intent: ChangeSetIntent,
    /// Exact authoritative sequence observed at creation.
    pub base_authoritative_sequence: u64,
    /// Exact Known State digest observed at creation.
    pub base_state: ContentDigest,
    /// Stable retry identity for this creation request.
    pub idempotency_key: IdempotencyKey,
    /// Canonical creation timestamp.
    pub created_at: Timestamp,
    /// Current lifecycle state.
    pub status: ChangeSetStatus,
    /// Versioned policy profile required for this proposal.
    pub policy_profile: String,
    /// Versioned validation profile required for this proposal.
    pub validation_profile: String,
    /// Number of ordered Edits currently in the draft.
    pub edit_count: u32,
}

/// Persistence port for creating local `ChangeSet` drafts.
pub trait ChangeSetRepository {
    /// Creates a draft or returns the prior result for an identical retry.
    ///
    /// # Errors
    ///
    /// Returns [`CreateChangeSetError`] without persisting a partial draft when
    /// authentication, base-state, idempotency, integrity, or storage checks fail.
    fn create_draft(
        &self,
        command: CreateChangeSetCommand,
    ) -> Result<DraftChangeSet, CreateChangeSetError>;
}

/// `ChangeSet` draft creation failed without changing authoritative content.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CreateChangeSetError {
    /// No initialized Workspace was selected.
    #[error("the selected location is not an initialized Workspace")]
    WorkspaceUninitialized,
    /// The operating-system identity is not bound to an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 ChangeSet operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// The requested base digest is no longer the current Known State.
    #[error("the requested base state does not match current Known State")]
    BaseStateConflict,
    /// The idempotency key was previously used with different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted state failed verification.
    #[error("Workspace integrity verification failed: {0}")]
    Integrity(String),
    /// Local persistence could not complete the operation safely.
    #[error("local ChangeSet storage is unavailable: {0}")]
    Storage(String),
}

/// Creates a draft `ChangeSet` through the configured persistence port.
///
/// # Errors
///
/// Returns [`CreateChangeSetError`] when the repository cannot return a safely
/// persisted or idempotently replayed draft.
pub fn create_changeset(
    repository: &impl ChangeSetRepository,
    command: CreateChangeSetCommand,
) -> Result<DraftChangeSet, CreateChangeSetError> {
    repository.create_draft(command)
}

/// Maximum number of Edits accepted in one atomic add operation.
pub const MAX_EDITS_PER_BATCH: usize = 100;

/// A typed proposal to create one immutable JSON Schema version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaCreateEdit {
    /// Candidate identity used when no idempotent result exists.
    pub edit_id: EditId,
    /// Stable logical Schema identity.
    pub schema_id: SchemaId,
    /// Positive immutable version.
    pub schema_version: SchemaVersion,
    /// RFC 8785 canonical JSON Schema document.
    pub canonical_document: String,
    /// Domain-separated digest of the canonical document.
    pub document_digest: ContentDigest,
}

/// A typed proposal to create the first revision of one content Object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectCreateEdit {
    /// Candidate identity used when no idempotent result exists.
    pub edit_id: EditId,
    /// Stable identity assigned to the new Object.
    pub object_id: ObjectId,
    /// Logical Schema governing the Object content.
    pub schema_id: SchemaId,
    /// Immutable Schema version governing the Object content.
    pub schema_version: SchemaVersion,
    /// RFC 8785 canonical JSON Object content.
    pub canonical_content: String,
    /// Domain-separated digest of the canonical Object revision.
    pub object_digest: ContentDigest,
}

/// One typed mutation proposed within an ordered `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeSetEdit {
    /// Create one immutable JSON Schema version.
    SchemaCreate(SchemaCreateEdit),
    /// Create the first accepted revision of one content Object.
    ObjectCreate(ObjectCreateEdit),
}

impl ChangeSetEdit {
    /// Returns the stable identity shared by every Edit kind.
    #[must_use]
    pub const fn edit_id(&self) -> EditId {
        match self {
            Self::SchemaCreate(edit) => edit.edit_id,
            Self::ObjectCreate(edit) => edit.edit_id,
        }
    }
}

/// Input for atomically appending ordered Edits to a draft `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddChangeSetEditsCommand {
    /// Target draft identity.
    pub changeset_id: ChangeSetId,
    /// Non-empty ordered Edit batch.
    pub edits: Vec<ChangeSetEdit>,
    /// Caller-visible retry identity for this exact normalized batch.
    pub idempotency_key: IdempotencyKey,
}

/// Result of atomically appending an ordered Edit batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddedChangeSetEdits {
    /// Target draft identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated Principal that appended the batch.
    pub principal_id: PrincipalId,
    /// First one-based ordinal assigned by this operation.
    pub first_ordinal: u32,
    /// Edit identities in persisted order.
    pub edit_ids: Vec<EditId>,
    /// Total number of Edits now present in the draft.
    pub total_edit_count: u32,
}

/// Persistence port for atomically appending typed Edits.
pub trait ChangeSetEditRepository {
    /// Appends the batch or returns the original result for an identical retry.
    ///
    /// # Errors
    ///
    /// Returns [`AddChangeSetEditsError`] without a partial append.
    fn add_edits(
        &self,
        command: AddChangeSetEditsCommand,
    ) -> Result<AddedChangeSetEdits, AddChangeSetEditsError>;
}

/// Appending Edits to a draft `ChangeSet` failed atomically.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AddChangeSetEditsError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 Edit operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// The target `ChangeSet` does not exist in this Workspace.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// The target is no longer editable.
    #[error("Edits can only be appended to a draft ChangeSet")]
    NotDraft,
    /// The batch was empty or exceeded its contract limit.
    #[error("an Edit batch must contain 1 to {MAX_EDITS_PER_BATCH} records")]
    InvalidBatchSize,
    /// The same Schema target appears more than once in the draft.
    #[error("the draft already contains the requested Schema version target")]
    DuplicateTarget,
    /// The retry key was previously used with different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted or canonical state failed verification.
    #[error("Workspace integrity verification failed: {0}")]
    Integrity(String),
    /// Local persistence could not complete safely.
    #[error("local ChangeSet storage is unavailable: {0}")]
    Storage(String),
}

/// Atomically appends typed Edits through the configured persistence port.
///
/// # Errors
///
/// Returns [`AddChangeSetEditsError`] when the repository cannot append or
/// safely replay the complete batch.
pub fn add_changeset_edits(
    repository: &impl ChangeSetEditRepository,
    command: AddChangeSetEditsCommand,
) -> Result<AddedChangeSetEdits, AddChangeSetEditsError> {
    if command.edits.is_empty() || command.edits.len() > MAX_EDITS_PER_BATCH {
        return Err(AddChangeSetEditsError::InvalidBatchSize);
    }
    repository.add_edits(command)
}

/// A verified persisted Schema-create Edit in deterministic draft order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedSchemaCreateEdit {
    /// One-based position within the `ChangeSet`.
    pub ordinal: u32,
    /// Stable Edit identity.
    pub edit_id: EditId,
    /// Logical Schema target.
    pub schema_id: SchemaId,
    /// Immutable Schema version target.
    pub schema_version: SchemaVersion,
    /// RFC 8785 canonical JSON document.
    pub canonical_document: String,
    /// Verified domain-separated document digest.
    pub document_digest: ContentDigest,
}

/// A verified persisted Object-create Edit in deterministic draft order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedObjectCreateEdit {
    /// One-based position within the `ChangeSet`.
    pub ordinal: u32,
    /// Stable Edit identity.
    pub edit_id: EditId,
    /// Stable identity assigned to the new Object.
    pub object_id: ObjectId,
    /// Logical Schema governing the Object content.
    pub schema_id: SchemaId,
    /// Immutable Schema version governing the Object content.
    pub schema_version: SchemaVersion,
    /// RFC 8785 canonical JSON Object content.
    pub canonical_content: String,
    /// Verified domain-separated Object revision digest.
    pub object_digest: ContentDigest,
}

/// One verified persisted Edit in deterministic `ChangeSet` order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InspectedChangeSetEdit {
    /// A verified Schema-create Edit.
    SchemaCreate(InspectedSchemaCreateEdit),
    /// A verified Object-create Edit.
    ObjectCreate(InspectedObjectCreateEdit),
}

impl InspectedChangeSetEdit {
    /// Returns the one-based position shared by every inspected Edit kind.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        match self {
            Self::SchemaCreate(edit) => edit.ordinal,
            Self::ObjectCreate(edit) => edit.ordinal,
        }
    }

    /// Returns the stable identity shared by every inspected Edit kind.
    #[must_use]
    pub const fn edit_id(&self) -> EditId {
        match self {
            Self::SchemaCreate(edit) => edit.edit_id,
            Self::ObjectCreate(edit) => edit.edit_id,
        }
    }
}

/// Complete verified read model for one persisted `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedChangeSet {
    /// Stable `ChangeSet` identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated initiating Principal.
    pub principal_id: PrincipalId,
    /// Normalized declared intent.
    pub intent: ChangeSetIntent,
    /// Exact authoritative base sequence.
    pub base_authoritative_sequence: u64,
    /// Exact base Known State digest.
    pub base_state: ContentDigest,
    /// Explicit caller-required base, when supplied at creation.
    pub requested_base_state: Option<ContentDigest>,
    /// Creation retry identity.
    pub idempotency_key: IdempotencyKey,
    /// Canonical creation timestamp.
    pub created_at: Timestamp,
    /// Current lifecycle state.
    pub status: ChangeSetStatus,
    /// Versioned policy profile.
    pub policy_profile: String,
    /// Versioned validation profile.
    pub validation_profile: String,
    /// Verified Edits in ordinal order.
    pub edits: Vec<InspectedChangeSetEdit>,
}

/// Read-only port for verified `ChangeSet` reconstruction.
pub trait ChangeSetInspectionRepository {
    /// Reconstructs and verifies a `ChangeSet` without mutating local state.
    ///
    /// # Errors
    ///
    /// Returns [`InspectChangeSetError`] when authentication, lookup,
    /// persistence, or integrity checks fail.
    fn inspect_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<InspectedChangeSet, InspectChangeSetError>;
}

/// A `ChangeSet` could not be reconstructed as a verified read model.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum InspectChangeSetError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// No visible `ChangeSet` has the requested identity.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// Persisted state failed deterministic verification.
    #[error("ChangeSet integrity verification failed: {0}")]
    Integrity(String),
    /// Local state could not be read safely.
    #[error("local ChangeSet storage is unavailable: {0}")]
    Storage(String),
}

/// Reconstructs a verified `ChangeSet` through the configured read port.
///
/// # Errors
///
/// Returns [`InspectChangeSetError`] when no verified visible read model can
/// be produced.
pub fn inspect_changeset(
    repository: &impl ChangeSetInspectionRepository,
    changeset_id: ChangeSetId,
) -> Result<InspectedChangeSet, InspectChangeSetError> {
    repository.inspect_changeset(changeset_id)
}

/// The pinned validator identity recorded in local Schema validation evidence.
pub const DRAFT_2020_12_META_VALIDATOR: &str = "jsonschema/draft-2020-12-meta/0.49.3";

/// Deterministic validation evidence for one exact `ChangeSet` representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedChangeSet {
    /// Stable identity of the validated proposal.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated Principal that requested validation.
    pub principal_id: PrincipalId,
    /// Digest of the exact manifest and ordered Edits that were validated.
    pub changeset_digest: ContentDigest,
    /// Exact Known State against which the proposal was validated.
    pub base_state: ContentDigest,
    /// Versioned validation profile selected by the `ChangeSet`.
    pub validation_profile: String,
    /// Pinned validator implementation recorded in the evidence.
    pub validator: String,
    /// Whether no blocking findings were produced.
    pub valid: bool,
    /// Deterministically ordered structured findings.
    pub findings: Vec<Finding>,
    /// Digest of the canonical validation-results artifact.
    pub validation_results_digest: ContentDigest,
    /// Number of ordered Edits covered by this result.
    pub edit_count: u32,
    /// Resulting lifecycle state (`ready` when valid, otherwise `rejected`).
    pub status: ChangeSetStatus,
}

/// Persistence and validation port for exact local `ChangeSet` proposals.
pub trait ChangeSetValidationRepository {
    /// Validates and persists evidence for the exact current proposal.
    ///
    /// # Errors
    ///
    /// Returns [`ValidateChangeSetError`] when authentication, lookup,
    /// integrity, or persistence prevents a trustworthy result.
    fn validate_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<ValidatedChangeSet, ValidateChangeSetError>;
}

/// Exact `ChangeSet` validation could not produce trustworthy evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidateChangeSetError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 validation operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// No visible `ChangeSet` has the requested identity.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// The proposal has advanced beyond a state that may be validated.
    #[error("the ChangeSet is no longer in a validatable lifecycle state")]
    NotValidatable,
    /// Persisted or canonical state failed deterministic verification.
    #[error("ChangeSet integrity verification failed: {0}")]
    Integrity(String),
    /// Local state or validation evidence could not be persisted safely.
    #[error("local ChangeSet validation storage is unavailable: {0}")]
    Storage(String),
}

/// Validates a `ChangeSet` through the configured validation port.
///
/// # Errors
///
/// Returns [`ValidateChangeSetError`] when no trustworthy validation evidence
/// can be produced and persisted.
pub fn validate_changeset(
    repository: &impl ChangeSetValidationRepository,
    changeset_id: ChangeSetId,
) -> Result<ValidatedChangeSet, ValidateChangeSetError> {
    repository.validate_changeset(changeset_id)
}

/// Input for submitting one validation-sealed `ChangeSet`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmitChangeSetCommand {
    /// Exact proposal to submit for governed review.
    pub changeset_id: ChangeSetId,
    /// Injected canonical time for a newly persisted submission.
    pub submitted_at: Timestamp,
}

/// Persisted submission bound to exact validation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmittedChangeSet {
    /// Stable submitted proposal identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated submitting Principal.
    pub principal_id: PrincipalId,
    /// Exact canonical proposal digest submitted for review.
    pub changeset_digest: ContentDigest,
    /// Exact validation-results artifact authorizing submission.
    pub validation_results_digest: ContentDigest,
    /// Exact Known State on which the proposal is based.
    pub base_state: ContentDigest,
    /// Canonical persisted submission time.
    pub submitted_at: Timestamp,
    /// Resulting lifecycle state.
    pub status: ChangeSetStatus,
    /// Number of ordered Edits sealed by the submission.
    pub edit_count: u32,
}

/// Persistence port for submitting validation-sealed `ChangeSet`s.
pub trait ChangeSetSubmissionRepository {
    /// Submits a ready proposal or replays its original submission result.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitChangeSetError`] without advancing lifecycle state when
    /// exact valid evidence is absent or cannot be verified.
    fn submit_changeset(
        &self,
        command: SubmitChangeSetCommand,
    ) -> Result<SubmittedChangeSet, SubmitChangeSetError>;
}

/// `ChangeSet` submission failed without accepting unvalidated content.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SubmitChangeSetError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 submission operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// No visible `ChangeSet` has the requested identity.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// The proposal has not reached validation-sealed ready state.
    #[error("only a ready ChangeSet can be submitted")]
    NotReady,
    /// No valid result covers the exact current proposal digest and profile.
    #[error("exact valid ChangeSet evidence is required before submission")]
    ValidationEvidenceMissing,
    /// Persisted or canonical state failed deterministic verification.
    #[error("ChangeSet submission integrity verification failed: {0}")]
    Integrity(String),
    /// Local submission state could not be persisted safely.
    #[error("local ChangeSet submission storage is unavailable: {0}")]
    Storage(String),
}

/// Submits a `ChangeSet` through the configured lifecycle port.
///
/// # Errors
///
/// Returns [`SubmitChangeSetError`] unless exact validation evidence is
/// atomically bound to a persisted submission.
pub fn submit_changeset(
    repository: &impl ChangeSetSubmissionRepository,
    command: SubmitChangeSetCommand,
) -> Result<SubmittedChangeSet, SubmitChangeSetError> {
    repository.submit_changeset(command)
}

/// Maximum UTF-8 byte length of a stable approval name.
pub const MAX_APPROVAL_NAME_BYTES: usize = 128;

/// Stable local approval requirement name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalName(String);

impl ApprovalName {
    /// Validates a lowercase machine-readable approval name.
    ///
    /// # Errors
    ///
    /// Returns [`ApprovalNameError`] for an empty, oversized, or unsupported name.
    pub fn new(value: impl Into<String>) -> Result<Self, ApprovalNameError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ApprovalNameError::Empty);
        }
        if value.len() > MAX_APPROVAL_NAME_BYTES {
            return Err(ApprovalNameError::TooLong);
        }
        let mut bytes = value.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(ApprovalNameError::InvalidSyntax);
        }
        Ok(Self(value))
    }

    /// Returns the validated approval name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ApprovalName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An approval name was outside the stable machine-readable profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApprovalNameError {
    /// No name was supplied.
    #[error("approval name must not be empty")]
    Empty,
    /// The name exceeded the bounded profile.
    #[error("approval name must not exceed {MAX_APPROVAL_NAME_BYTES} bytes")]
    TooLong,
    /// The name did not use the lowercase identifier grammar.
    #[error(
        "approval name must begin with a lowercase letter and contain only lowercase letters, digits, `.`, `_`, or `-`"
    )]
    InvalidSyntax,
}

/// Input for explicitly approving one submitted `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveChangeSetCommand {
    /// Exact submitted proposal to approve.
    pub changeset_id: ChangeSetId,
    /// Named approval requirement being satisfied.
    pub approval: ApprovalName,
    /// Injected canonical time for a newly persisted approval.
    pub approved_at: Timestamp,
}

/// Persisted approval bound to exact proposal and validation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedChangeSet {
    /// Stable approved proposal identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated approving Principal.
    pub principal_id: PrincipalId,
    /// Named approval requirement satisfied by this record.
    pub approval: ApprovalName,
    /// Exact canonical proposal digest approved.
    pub changeset_digest: ContentDigest,
    /// Exact validation-results artifact reviewed by the approval transition.
    pub validation_results_digest: ContentDigest,
    /// Canonical persisted approval time.
    pub approved_at: Timestamp,
    /// Resulting lifecycle state.
    pub status: ChangeSetStatus,
}

/// Persistence port for explicit, digest-bound local approval.
pub trait ChangeSetApprovalRepository {
    /// Approves a submitted proposal or replays its original approval record.
    ///
    /// # Errors
    ///
    /// Returns [`ApproveChangeSetError`] without advancing lifecycle state when
    /// submission or validation evidence cannot be verified.
    fn approve_changeset(
        &self,
        command: ApproveChangeSetCommand,
    ) -> Result<ApprovedChangeSet, ApproveChangeSetError>;
}

/// `ChangeSet` approval failed without recording unbound authority evidence.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApproveChangeSetError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 approval operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// No visible `ChangeSet` has the requested identity.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// The proposal has not reached submitted state.
    #[error("only a submitted ChangeSet can be approved")]
    NotSubmitted,
    /// Exact submission or validation evidence is absent.
    #[error("exact submitted ChangeSet evidence is required before approval")]
    EvidenceMissing,
    /// A different named approval was already recorded for this transition.
    #[error("the ChangeSet was already approved under a different approval name")]
    ApprovalConflict,
    /// Persisted or canonical state failed deterministic verification.
    #[error("ChangeSet approval integrity verification failed: {0}")]
    Integrity(String),
    /// Local approval state could not be persisted safely.
    #[error("local ChangeSet approval storage is unavailable: {0}")]
    Storage(String),
}

/// Approves a submitted `ChangeSet` through the configured lifecycle port.
///
/// # Errors
///
/// Returns [`ApproveChangeSetError`] unless exact submission and validation
/// evidence is atomically bound to the approval record.
pub fn approve_changeset(
    repository: &impl ChangeSetApprovalRepository,
    command: ApproveChangeSetCommand,
) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
    repository.approve_changeset(command)
}

/// Input for atomically committing one approved `ChangeSet`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitChangeSetCommand {
    /// Exact approved proposal to apply.
    pub changeset_id: ChangeSetId,
    /// Explicit retry identity for this consequential transition.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical time for a newly persisted commit.
    pub committed_at: Timestamp,
}

/// Result of one atomic authoritative `ChangeSet` commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedChangeSet {
    /// Stable committed proposal identity.
    pub changeset_id: ChangeSetId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Authenticated committing Principal.
    pub principal_id: PrincipalId,
    /// Exact proposal digest applied by the transaction.
    pub changeset_digest: ContentDigest,
    /// Exact validation-results artifact rechecked at commit time.
    pub validation_results_digest: ContentDigest,
    /// Known State required before the transaction began.
    pub previous_state: ContentDigest,
    /// Reproducible Known State produced by the transaction.
    pub resulting_state: ContentDigest,
    /// Last authoritative sequence included in the resulting state.
    pub authoritative_sequence: u64,
    /// Canonical persisted commit time.
    pub committed_at: Timestamp,
    /// Resulting lifecycle state.
    pub status: ChangeSetStatus,
    /// Number of ordered Edits atomically applied.
    pub edit_count: u32,
}

/// Persistence port for atomic authoritative `ChangeSet` commits.
pub trait ChangeSetCommitRepository {
    /// Applies an approved proposal or replays its original commit result.
    ///
    /// # Errors
    ///
    /// Returns [`CommitChangeSetError`] without partial authoritative effects
    /// when evidence, base state, idempotency, or target checks fail.
    fn commit_changeset(
        &self,
        command: CommitChangeSetCommand,
    ) -> Result<CommittedChangeSet, CommitChangeSetError>;
}

/// A `ChangeSet` commit failed without partially changing authoritative state.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CommitChangeSetError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 commit operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// No visible `ChangeSet` has the requested identity.
    #[error("the requested ChangeSet was not found")]
    NotFound,
    /// The proposal has not reached approved state.
    #[error("only an approved ChangeSet can be committed")]
    NotApproved,
    /// Exact validation, submission, or approval evidence is absent.
    #[error("exact approved ChangeSet evidence is required before commit")]
    EvidenceMissing,
    /// Authoritative state advanced beyond the proposal's declared base.
    #[error("the current Known State no longer matches the ChangeSet base")]
    BaseStateConflict,
    /// An immutable Schema-version target already exists.
    #[error("one or more ChangeSet targets already exist in authoritative state")]
    TargetConflict,
    /// The retry key was already bound to different input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted or canonical state failed deterministic verification.
    #[error("ChangeSet commit integrity verification failed: {0}")]
    Integrity(String),
    /// Local commit state could not be persisted safely.
    #[error("local ChangeSet commit storage is unavailable: {0}")]
    Storage(String),
}

/// Commits a `ChangeSet` through the configured authoritative-state port.
///
/// # Errors
///
/// Returns [`CommitChangeSetError`] unless the complete proposal and resulting
/// Known State can be committed atomically.
pub fn commit_changeset(
    repository: &impl ChangeSetCommitRepository,
    command: CommitChangeSetCommand,
) -> Result<CommittedChangeSet, CommitChangeSetError> {
    repository.commit_changeset(command)
}

/// Input for materializing the current verified Known State as an Edition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateEditionCommand {
    /// Operational identity assigned if this state has no Edition yet.
    pub edition_id: EditionId,
    /// Retry identity scoped to the current Known State.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical time for a newly persisted Edition.
    pub created_at: Timestamp,
}

/// One immutable Schema-version reference in an Edition manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditionSchema {
    /// Logical Schema identity.
    pub schema_id: SchemaId,
    /// Immutable Schema version.
    pub schema_version: SchemaVersion,
    /// Digest of the exact canonical Schema document.
    pub document_digest: ContentDigest,
}

/// One immutable accepted Object revision in an Edition manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EditionObject {
    /// Stable governed Object identity.
    pub object_id: ObjectId,
    /// Accepted immutable Object revision.
    pub revision: ObjectRevision,
    /// Logical Schema governing the Object content.
    pub schema_id: SchemaId,
    /// Immutable Schema version governing the Object content.
    pub schema_version: SchemaVersion,
    /// Accepted lifecycle state represented by the Edition.
    pub lifecycle_state: ObjectLifecycleState,
    /// Digest of the exact canonical Object revision.
    pub object_digest: ContentDigest,
}

/// One committed `ChangeSet` reference in an Edition manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditionChangeSet {
    /// Committed proposal identity.
    pub changeset_id: ChangeSetId,
    /// Exact committed proposal digest.
    pub changeset_digest: ContentDigest,
}

/// Immutable content-addressed representation of accepted Workspace state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edition {
    /// Stable operational Edition identity.
    pub edition_id: EditionId,
    /// Owning Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Principal that first materialized the Edition.
    pub principal_id: PrincipalId,
    /// Last authoritative sequence included in the Edition.
    pub authoritative_sequence: u64,
    /// Reproducible Known State represented by this Edition.
    pub state_digest: ContentDigest,
    /// Digest of the ordered Schema-set submanifest.
    pub schema_set_digest: ContentDigest,
    /// Digest of the ordered Object-set submanifest, absent for Schema-only state.
    pub object_set_digest: Option<ContentDigest>,
    /// Digest of the canonical Edition manifest.
    pub edition_digest: ContentDigest,
    /// Exact canonical Edition manifest JSON.
    pub manifest_json: String,
    /// Canonical first-materialization time.
    pub created_at: Timestamp,
    /// Ordered immutable Schema references.
    pub schemas: Vec<EditionSchema>,
    /// Ordered immutable accepted Object revisions.
    pub objects: Vec<EditionObject>,
    /// Authoritative `ChangeSet`s included in sequence order.
    pub changesets: Vec<EditionChangeSet>,
}

/// Persistence port for content-addressed Edition materialization.
pub trait EditionRepository {
    /// Returns the existing Edition for current state or creates it atomically.
    ///
    /// # Errors
    ///
    /// Returns [`CreateEditionError`] without persisting a partial artifact.
    fn create_edition(&self, command: CreateEditionCommand) -> Result<Edition, CreateEditionError>;
}

/// Edition creation failed without publishing a mutable artifact.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CreateEditionError {
    /// The operating-system identity is not an enabled Principal.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative state has activated a newer content contract.
    #[error("the v1 Edition operation is unsupported after KnownStateV2 activation")]
    UnsupportedVersion,
    /// No authoritative state has been committed yet.
    #[error("an Edition requires at least one committed authoritative record")]
    EmptyState,
    /// The retry key was already bound to a different Known State.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted or canonical state failed deterministic verification.
    #[error("Edition integrity verification failed: {0}")]
    Integrity(String),
    /// Local Edition state could not be persisted safely.
    #[error("local Edition storage is unavailable: {0}")]
    Storage(String),
}

/// Materializes current Known State through the configured Edition port.
///
/// # Errors
///
/// Returns [`CreateEditionError`] unless an immutable Edition can be returned.
pub fn create_edition(
    repository: &impl EditionRepository,
    command: CreateEditionCommand,
) -> Result<Edition, CreateEditionError> {
    repository.create_edition(command)
}

/// The initial deterministic local authority-policy profile.
pub const LOCAL_AUTHORITY_POLICY_PROFILE: &str = "proof.local/authority/default/v1";
/// Maximum number of exact Objects one first-slice Delegation may name.
pub const MAX_DELEGATION_OBJECTS: usize = 100;
/// Maximum number of exact Environments one first-slice Delegation may name.
pub const MAX_DELEGATION_ENVIRONMENTS: usize = 32;
/// Maximum canonical `ContextPack` size accepted by the first local profile.
pub const MAX_CONTEXT_PACK_BYTES: u64 = 1_048_576;
/// Maximum UTF-8 byte length of a caller task identifier in a `ContextPack`.
pub const MAX_CONTEXT_TASK_ID_BYTES: usize = 256;

/// One governed action that may be delegated to an Agent Principal.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegatedAction {
    /// Append one exact localized Edit batch to a `ChangeSet`.
    ChangesetAdd,
    /// Commit one approved localized `ChangeSet`.
    ChangesetCommit,
    /// Create one evidence-bound localized `ChangeSet`.
    ChangesetCreate,
    /// Read the effective localized `ChangeSet` projection.
    ChangesetDiff,
    /// Read one complete localized `ChangeSet`.
    ChangesetGet,
    /// Submit one ready localized `ChangeSet`.
    ChangesetSubmit,
    /// Validate one localized `ChangeSet` proposal.
    ChangesetValidate,
    /// Inspect verified Workspace status.
    WorkspaceStatus,
    /// Query exact Objects from one released Environment.
    ObjectQueryReleased,
    /// Build one bounded immutable `ContextPack`.
    ContextBuild,
    /// Materialize one immutable localized Edition.
    EditionCreate,
    /// Promote one exact localized Release.
    ReleaseCreate,
}

impl DelegatedAction {
    /// Returns the stable policy action string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChangesetAdd => "changeset:add",
            Self::ChangesetCommit => "changeset:commit",
            Self::ChangesetCreate => "changeset:create",
            Self::ChangesetDiff => "changeset:diff",
            Self::ChangesetGet => "changeset:get",
            Self::ChangesetSubmit => "changeset:submit",
            Self::ChangesetValidate => "changeset:validate",
            Self::WorkspaceStatus => "workspace:status",
            Self::ObjectQueryReleased => "object:query_released",
            Self::ContextBuild => "context:build",
            Self::EditionCreate => "edition:create",
            Self::ReleaseCreate => "release:create",
        }
    }
}

impl std::fmt::Display for DelegatedAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for DelegatedAction {
    type Err = DelegatedActionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "changeset:add" => Ok(Self::ChangesetAdd),
            "changeset:commit" => Ok(Self::ChangesetCommit),
            "changeset:create" => Ok(Self::ChangesetCreate),
            "changeset:diff" => Ok(Self::ChangesetDiff),
            "changeset:get" => Ok(Self::ChangesetGet),
            "changeset:submit" => Ok(Self::ChangesetSubmit),
            "changeset:validate" => Ok(Self::ChangesetValidate),
            "workspace:status" => Ok(Self::WorkspaceStatus),
            "object:query_released" => Ok(Self::ObjectQueryReleased),
            "context:build" => Ok(Self::ContextBuild),
            "edition:create" => Ok(Self::EditionCreate),
            "release:create" => Ok(Self::ReleaseCreate),
            _ => Err(DelegatedActionParseError),
        }
    }
}

/// A delegated action string is not part of the first stable profile.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("the delegated action is not supported")]
pub struct DelegatedActionParseError;

/// Exact resource scope for one immutable Delegation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationScope {
    /// Exact Workspace in which the Delegation is valid.
    pub workspace_id: WorkspaceId,
    /// Exact delivery Environments visible to the recipient.
    pub environment_ids: Vec<EnvironmentId>,
    /// Exact released Objects visible to the recipient.
    pub object_ids: Vec<ObjectId>,
}

/// Deterministic budgets carried by one Delegation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationConstraints {
    /// Maximum Object count in one query or `ContextPack`.
    pub max_objects: u32,
    /// Maximum canonical `ContextPack` byte length.
    pub max_context_bytes: u64,
    /// Whether the recipient may issue a narrower child Delegation.
    pub allow_subdelegation: bool,
}

/// Input for registering one local Agent Principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAgentPrincipalCommand {
    /// Candidate `UUIDv7` identity.
    pub principal_id: PrincipalId,
    /// Bounded caller-facing label; it is not an authentication subject.
    pub display_name: String,
    /// Retry identity scoped to the authenticated issuer.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical creation time.
    pub created_at: Timestamp,
}

/// One registered Agent Principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPrincipal {
    /// Stable Agent identity.
    pub principal_id: PrincipalId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Stable caller-facing label.
    pub display_name: String,
    /// Authenticated Human Principal that registered the Agent.
    pub created_by_principal_id: PrincipalId,
    /// Canonical registration time.
    pub created_at: Timestamp,
    /// Whether the Principal remains eligible to receive authority.
    pub enabled: bool,
}

/// Principal registry port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait PrincipalRepository {
    /// Registers an Agent or returns the original result for an identical retry.
    fn create_agent_principal(
        &self,
        command: CreateAgentPrincipalCommand,
    ) -> Result<AgentPrincipal, PrincipalError>;

    /// Returns one visible Agent Principal.
    fn get_agent_principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<AgentPrincipal, PrincipalError>;
}

/// A Principal registry operation failed safely.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PrincipalError {
    /// The local requesting identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The requested Principal is absent or not visible.
    #[error("the requested Agent Principal was not found")]
    NotFound,
    /// The requested Principal exists but is disabled.
    #[error("the requested Agent Principal is disabled")]
    Disabled,
    /// The display label violates the bounded contract.
    #[error("the Agent display name must contain 1 to 256 UTF-8 bytes")]
    InvalidDisplayName,
    /// The retry key was bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted registry state failed deterministic verification.
    #[error("Principal registry integrity verification failed: {0}")]
    Integrity(String),
    /// Registry persistence is unavailable.
    #[error("Principal registry storage is unavailable: {0}")]
    Storage(String),
}

/// Registers an Agent Principal through the configured registry port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn create_agent_principal(
    repository: &impl PrincipalRepository,
    command: CreateAgentPrincipalCommand,
) -> Result<AgentPrincipal, PrincipalError> {
    if command.display_name.trim().is_empty() || command.display_name.len() > 256 {
        return Err(PrincipalError::InvalidDisplayName);
    }
    repository.create_agent_principal(command)
}

/// Reads an Agent Principal through the configured registry port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn get_agent_principal(
    repository: &impl PrincipalRepository,
    principal_id: PrincipalId,
) -> Result<AgentPrincipal, PrincipalError> {
    repository.get_agent_principal(principal_id)
}

/// Input for issuing one immutable, scoped, expiring Delegation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantDelegationCommand {
    /// Candidate immutable Delegation identity.
    pub delegation_id: DelegationId,
    /// Agent receiving bounded authority.
    pub recipient_principal_id: PrincipalId,
    /// Non-empty allowlist of actions.
    pub actions: Vec<DelegatedAction>,
    /// Exact Workspace, Environment, and Object scope.
    pub scope: DelegationScope,
    /// Deterministic operation and artifact budgets.
    pub constraints: DelegationConstraints,
    /// Earliest instant at which the grant is valid.
    pub not_before: Timestamp,
    /// Exclusive upper validity bound.
    pub expires_at: Timestamp,
    /// Retry identity scoped to the authenticated issuer.
    pub idempotency_key: IdempotencyKey,
    /// Canonical issue time.
    pub issued_at: Timestamp,
}

/// One immutable Delegation plus an optional append-only revocation fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation {
    /// Stable grant identity.
    pub delegation_id: DelegationId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Authenticated Principal that issued the grant.
    pub issuer_principal_id: PrincipalId,
    /// Agent receiving the grant.
    pub recipient_principal_id: PrincipalId,
    /// Canonically sorted action allowlist.
    pub actions: Vec<DelegatedAction>,
    /// Canonically sorted exact resource scope.
    pub scope: DelegationScope,
    /// Deterministic budgets.
    pub constraints: DelegationConstraints,
    /// Earliest valid instant.
    pub not_before: Timestamp,
    /// Exclusive upper validity bound.
    pub expires_at: Timestamp,
    /// Canonical issue time.
    pub issued_at: Timestamp,
    /// Domain-separated digest of the immutable grant manifest.
    pub delegation_digest: ContentDigest,
    /// Principal that revoked the grant, when revoked.
    pub revoked_by_principal_id: Option<PrincipalId>,
    /// Canonical append-only revocation time, when revoked.
    pub revoked_at: Option<Timestamp>,
}

/// Input for appending one Delegation revocation fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevokeDelegationCommand {
    /// Grant being revoked.
    pub delegation_id: DelegationId,
    /// Retry identity for the revocation operation.
    pub idempotency_key: IdempotencyKey,
    /// Canonical revocation time.
    pub revoked_at: Timestamp,
}

/// Input for evaluating one exact delegated request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifyDelegationCommand {
    /// Presented grant.
    pub delegation_id: DelegationId,
    /// Caller-declared operating Agent Principal; v1 authenticates the local
    /// requesting Human but not a separate Agent binding.
    pub operating_principal_id: PrincipalId,
    /// Exact requested action.
    pub action: DelegatedAction,
    /// Exact Environment target, when the action has one.
    pub environment_id: Option<EnvironmentId>,
    /// Exact Object targets, canonically sorted and unique.
    pub object_ids: Vec<ObjectId>,
    /// Injected evaluation time.
    pub evaluated_at: Timestamp,
}

/// Deterministic result of evaluating one Delegation against one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationVerification {
    /// Evaluated grant.
    pub delegation_id: DelegationId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Requested action.
    pub action: DelegatedAction,
    /// Whether every authority check allowed the request.
    pub authorized: bool,
    /// Stable denial code, absent on allow.
    pub denial_code: Option<String>,
    /// Versioned policy profile used by the evaluator.
    pub policy_profile: String,
    /// Digest of the exact policy inputs and decision.
    pub decision_digest: ContentDigest,
    /// Canonical evaluation time.
    pub evaluated_at: Timestamp,
}

/// Delegation persistence and deterministic evaluation port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait DelegationRepository {
    /// Issues a grant or replays the original result.
    fn grant_delegation(
        &self,
        command: GrantDelegationCommand,
    ) -> Result<Delegation, DelegationError>;
    /// Returns one visible grant and its revocation state.
    fn get_delegation(&self, delegation_id: DelegationId) -> Result<Delegation, DelegationError>;
    /// Appends a revocation fact or replays it.
    fn revoke_delegation(
        &self,
        command: RevokeDelegationCommand,
    ) -> Result<Delegation, DelegationError>;
    /// Evaluates action, resource, time, recipient, and revocation constraints.
    fn verify_delegation(
        &self,
        command: VerifyDelegationCommand,
    ) -> Result<DelegationVerification, DelegationError>;
}

/// A Delegation operation failed without expanding authority.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DelegationError {
    /// The local requesting identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The grant or recipient is absent or not visible.
    #[error("the requested Delegation resource was not found")]
    NotFound,
    /// The recipient is not an enabled Agent Principal.
    #[error("a Delegation recipient must be an enabled Agent Principal")]
    InvalidRecipient,
    /// Actions, scope, constraints, or times violate the bounded profile.
    #[error("the Delegation is empty, over budget, or has invalid validity bounds")]
    InvalidGrant,
    /// The grant is not yet valid.
    #[error("the Delegation is not yet valid")]
    NotYetValid,
    /// The grant has expired.
    #[error("the Delegation has expired")]
    Expired,
    /// A revocation fact prevents use.
    #[error("the Delegation has been revoked")]
    Revoked,
    /// The requested action or resource is outside the grant.
    #[error("the requested action or resource exceeds Delegation scope")]
    ScopeExceeded,
    /// The retry key was bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted or canonical authority state failed verification.
    #[error("Delegation integrity verification failed: {0}")]
    Integrity(String),
    /// Authority persistence is unavailable.
    #[error("Delegation storage is unavailable: {0}")]
    Storage(String),
}

/// Issues a bounded Delegation through the configured authority port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn grant_delegation(
    repository: &impl DelegationRepository,
    command: GrantDelegationCommand,
) -> Result<Delegation, DelegationError> {
    let duplicate_actions = command
        .actions
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != command.actions.len();
    let duplicate_environments = command
        .scope
        .environment_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != command.scope.environment_ids.len();
    let duplicate_objects = command
        .scope
        .object_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != command.scope.object_ids.len();
    let has_resource_action = command.actions.iter().any(|action| {
        matches!(
            action,
            DelegatedAction::ObjectQueryReleased | DelegatedAction::ContextBuild
        )
    });
    let invalid_scope_shape = if has_resource_action {
        command.scope.environment_ids.is_empty() || command.scope.object_ids.is_empty()
    } else {
        !command.scope.environment_ids.is_empty() || !command.scope.object_ids.is_empty()
    };
    let invalid = command.actions.is_empty()
        || duplicate_actions
        || duplicate_environments
        || duplicate_objects
        || invalid_scope_shape
        || command.scope.environment_ids.len() > MAX_DELEGATION_ENVIRONMENTS
        || command.scope.object_ids.len() > MAX_DELEGATION_OBJECTS
        || command.constraints.max_objects == 0
        || usize::try_from(command.constraints.max_objects)
            .map_or(true, |value| value > MAX_DELEGATION_OBJECTS)
        || command.constraints.max_context_bytes == 0
        || command.constraints.max_context_bytes > MAX_CONTEXT_PACK_BYTES
        || command.constraints.allow_subdelegation
        || command.not_before >= command.expires_at;
    if invalid {
        return Err(DelegationError::InvalidGrant);
    }
    repository.grant_delegation(command)
}

/// Reads one Delegation through the configured authority port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn get_delegation(
    repository: &impl DelegationRepository,
    delegation_id: DelegationId,
) -> Result<Delegation, DelegationError> {
    repository.get_delegation(delegation_id)
}

/// Revokes one Delegation through the configured authority port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn revoke_delegation(
    repository: &impl DelegationRepository,
    command: RevokeDelegationCommand,
) -> Result<Delegation, DelegationError> {
    repository.revoke_delegation(command)
}

/// Evaluates one delegated request through the configured authority port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn verify_delegation(
    repository: &impl DelegationRepository,
    command: VerifyDelegationCommand,
) -> Result<DelegationVerification, DelegationError> {
    repository.verify_delegation(command)
}

/// Caller-requested `ContextPack` budgets, further intersected with Delegation budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextPackLimits {
    /// Maximum exact Object count.
    pub max_objects: u32,
    /// Maximum RFC 8785 canonical manifest byte length.
    pub max_bytes: u64,
}

/// Input for building one immutable, content-addressed `ContextPack`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildContextPackCommand {
    /// Candidate `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Presented Delegation authorizing context assembly.
    pub delegation_id: DelegationId,
    /// Stable caller task identity.
    pub task_id: String,
    /// Normalized bounded task intent.
    pub intent: ChangeSetIntent,
    /// Exact released Environment supplying source content.
    pub environment_id: EnvironmentId,
    /// Exact requested Objects, canonically sorted and unique.
    pub object_ids: Vec<ObjectId>,
    /// Requested budgets, intersected with the Delegation.
    pub limits: ContextPackLimits,
    /// Retry identity for exact normalized assembly input.
    pub idempotency_key: IdempotencyKey,
    /// Canonical assembly time.
    pub built_at: Timestamp,
    /// Exclusive freshness bound; it cannot exceed the Delegation expiry.
    pub expires_at: Timestamp,
}

/// One immutable bounded agent-context artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextPack {
    /// Stable `ContextPack` identity.
    pub context_pack_id: ContextPackId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Authenticated requesting Principal.
    pub requesting_principal_id: PrincipalId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Exact Delegation evaluated during assembly.
    pub delegation_id: DelegationId,
    /// Stable task identity.
    pub task_id: String,
    /// Normalized task intent.
    pub intent: ChangeSetIntent,
    /// Exact released Environment represented by the pack.
    pub environment_id: EnvironmentId,
    /// Release from which content was selected.
    pub release_id: ReleaseId,
    /// Immutable Edition from which content was selected.
    pub edition_id: EditionId,
    /// Known State represented by the source Edition.
    pub base_state: ContentDigest,
    /// Canonically sorted exact Object identities.
    pub object_ids: Vec<ObjectId>,
    /// Applied final budgets.
    pub limits: ContextPackLimits,
    /// Canonical assembly time.
    pub built_at: Timestamp,
    /// Exclusive freshness bound.
    pub expires_at: Timestamp,
    /// Exact versioned capability names included in the pack.
    pub capabilities: Vec<String>,
    /// RFC 8785 canonical complete `ContextPack` manifest.
    pub manifest_json: String,
    /// Domain-separated digest of `manifest_json`.
    pub context_pack_digest: ContentDigest,
}

/// Input for an authorization-aware `ContextPack` read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetContextPackCommand {
    /// Requested `ContextPack`.
    pub context_pack_id: ContextPackId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Presented Delegation.
    pub delegation_id: DelegationId,
    /// Injected observation time.
    pub observed_at: Timestamp,
}

/// Input for deterministic `ContextPack` integrity and freshness verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyContextPackCommand {
    /// Requested `ContextPack`.
    pub context_pack_id: ContextPackId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub operating_principal_id: PrincipalId,
    /// Presented Delegation.
    pub delegation_id: DelegationId,
    /// Injected verification time.
    pub verified_at: Timestamp,
}

/// Structured verification result for one `ContextPack`.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the report exposes independent verification checks"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextPackVerification {
    /// Verified artifact identity.
    pub context_pack_id: ContextPackId,
    /// Persisted artifact digest.
    pub context_pack_digest: ContentDigest,
    /// Whether canonical bytes reproduce the persisted digest.
    pub digest_valid: bool,
    /// Whether source references remain internally reproducible.
    pub sources_valid: bool,
    /// Whether the verification instant precedes expiry.
    pub fresh: bool,
    /// Whether every required check succeeded.
    pub valid: bool,
    /// Deterministically ordered stable failure codes.
    pub findings: Vec<String>,
    /// Canonical verification time.
    pub verified_at: Timestamp,
}

/// `ContextPack` persistence and deterministic assembly port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait ContextPackRepository {
    /// Builds an immutable pack or replays identical assembly input.
    fn build_context_pack(
        &self,
        command: BuildContextPackCommand,
    ) -> Result<ContextPack, ContextPackError>;
    /// Returns an authorized visible pack.
    fn get_context_pack(
        &self,
        command: GetContextPackCommand,
    ) -> Result<ContextPack, ContextPackError>;
    /// Verifies canonical bytes, sources, authority binding, and freshness.
    fn verify_context_pack(
        &self,
        command: VerifyContextPackCommand,
    ) -> Result<ContextPackVerification, ContextPackError>;
}

/// A `ContextPack` operation failed without disclosing unauthorized content.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContextPackError {
    /// The requesting identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The Delegation denied the requested assembly or read.
    #[error("the ContextPack operation is outside delegated authority")]
    Denied,
    /// A required Environment, Release, Object, or `ContextPack` is absent or hidden.
    #[error("the requested ContextPack resource was not found")]
    NotFound,
    /// The request exceeds Object-count, byte-size, or time limits.
    #[error("the ContextPack request exceeds its bounded constraints")]
    LimitExceeded,
    /// The artifact is no longer fresh.
    #[error("the ContextPack has expired")]
    Expired,
    /// The retry key was bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Canonical bytes or source references failed verification.
    #[error("ContextPack integrity verification failed: {0}")]
    Integrity(String),
    /// `ContextPack` persistence is unavailable.
    #[error("ContextPack storage is unavailable: {0}")]
    Storage(String),
}

/// Builds one `ContextPack` through the configured assembly port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn build_context_pack(
    repository: &impl ContextPackRepository,
    command: BuildContextPackCommand,
) -> Result<ContextPack, ContextPackError> {
    let max_objects = usize::try_from(command.limits.max_objects).unwrap_or(usize::MAX);
    let unique_objects = command
        .object_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if command.object_ids.is_empty()
        || command.object_ids.len() > max_objects
        || unique_objects != command.object_ids.len()
        || max_objects > MAX_DELEGATION_OBJECTS
        || command.limits.max_bytes == 0
        || command.limits.max_bytes > MAX_CONTEXT_PACK_BYTES
        || command.task_id.trim().is_empty()
        || command.task_id.len() > MAX_CONTEXT_TASK_ID_BYTES
    {
        return Err(ContextPackError::LimitExceeded);
    }
    repository.build_context_pack(command)
}

/// Reads one `ContextPack` through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn get_context_pack(
    repository: &impl ContextPackRepository,
    command: GetContextPackCommand,
) -> Result<ContextPack, ContextPackError> {
    repository.get_context_pack(command)
}

/// Verifies one `ContextPack` through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn verify_context_pack(
    repository: &impl ContextPackRepository,
    command: VerifyContextPackCommand,
) -> Result<ContextPackVerification, ContextPackError> {
    repository.verify_context_pack(command)
}

/// Idempotency contract advertised for one capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityIdempotency {
    /// The operation has no persistent effects.
    NotApplicable,
    /// The operation requires a caller-visible idempotency key.
    Required,
    /// Proof derives the retry identity from the verified immutable closure.
    Derived,
}

/// Side-effect classification advertised to callers and protocol adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySideEffect {
    /// No persistent mutation.
    ReadOnly,
    /// Writes an immutable evidence artifact but not authoritative content.
    EvidenceWrite,
    /// Mutates governed localized content or its release lifecycle.
    GovernedWrite,
}

impl CapabilitySideEffect {
    /// Stable caller-visible classification token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::EvidenceWrite => "evidence_write",
            Self::GovernedWrite => "governed_write",
        }
    }
}

impl std::fmt::Display for CapabilitySideEffect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Static transport-independent description of one agent-visible operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityDescriptor {
    /// Stable application operation name.
    pub operation: &'static str,
    /// Version of this exact operation contract.
    pub version: &'static str,
    /// Human-readable bounded description.
    pub description: &'static str,
    /// JSON Schema Draft 2020-12 input Schema as JSON text.
    pub input_schema_json: &'static str,
    /// JSON Schema Draft 2020-12 result-data Schema as JSON text.
    pub output_schema_json: &'static str,
    /// Required delegated action.
    pub required_action: DelegatedAction,
    /// Retry contract.
    pub idempotency: CapabilityIdempotency,
    /// Side-effect classification.
    pub side_effect: CapabilitySideEffect,
    /// Whether the operation supports a dry run.
    pub dry_run: bool,
    /// Stable expected Problem codes.
    pub error_codes: &'static [&'static str],
    /// Codes reachable through the legacy ambient-Human application path.
    pub ambient_error_codes: &'static [&'static str],
    /// Public codes reachable through authenticated P-0004/P-0005 execution.
    pub authenticated_error_codes: &'static [&'static str],
    /// Maximum accepted Object count, when applicable.
    pub max_objects: Option<u32>,
    /// Maximum accepted payload bytes, when applicable.
    pub max_payload_bytes: Option<u64>,
}

impl CapabilityDescriptor {
    /// Resolves the descriptor to the exact fixed authority-registry row.
    #[must_use]
    pub fn authority_operation(self) -> Option<authority::AuthorityOperation> {
        authority::AuthorityOperation::from_pair(self.operation, self.version)
    }

    /// Parses the complete self-contained input Schema bundle.
    ///
    /// # Errors
    ///
    /// Returns a JSON error only if the statically registered Schema text is corrupt.
    pub fn input_schema(self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_str(self.input_schema_json)
    }

    /// Parses the complete self-contained result-data Schema bundle.
    ///
    /// # Errors
    ///
    /// Returns a JSON error only if the statically registered Schema text is corrupt.
    pub fn output_schema(self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::from_str(self.output_schema_json)
    }

    /// Stable MCP tool identity; v1 names remain unversioned and later versions are explicit.
    #[must_use]
    pub fn mcp_tool_name(self) -> String {
        let suffix = self.version.rsplit('/').next().unwrap_or("unknown");
        if suffix == "v1" {
            format!("proof.{}", self.operation)
        } else {
            format!("proof.{}.{}", self.operation, suffix)
        }
    }
}

const WORKSPACE_STATUS_INPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/workspace.status/input/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"delegation_id":{"format":"uuid","type":"string"},"operating_principal_id":{"format":"uuid","type":"string"}},"required":["operating_principal_id","delegation_id"],"type":"object"}"#;
const WORKSPACE_STATUS_OUTPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/workspace.status/output/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"authoritative_sequence":{"minimum":0,"type":"integer"},"authorization_decision_digest":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"delegation_id":{"format":"uuid","type":"string"},"operating_principal_id":{"format":"uuid","type":"string"},"requesting_principal_id":{"format":"uuid","type":"string"},"state_digest":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"storage_schema_version":{"minimum":1,"type":"integer"},"workspace_id":{"format":"uuid","type":"string"}},"required":["workspace_id","requesting_principal_id","operating_principal_id","delegation_id","storage_schema_version","authoritative_sequence","state_digest","authorization_decision_digest"],"type":"object"}"#;
const RELEASED_OBJECT_QUERY_INPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/object.query_released/input/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"delegation_id":{"format":"uuid","type":"string"},"environment_id":{"maxLength":128,"minLength":1,"type":"string"},"object_ids":{"items":{"format":"uuid","type":"string"},"maxItems":100,"minItems":1,"type":"array","uniqueItems":true},"operating_principal_id":{"format":"uuid","type":"string"}},"required":["operating_principal_id","delegation_id","environment_id","object_ids"],"type":"object"}"#;
const RELEASED_OBJECT_QUERY_OUTPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/object.query_released/output/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"authorization_decision_digest":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"delegation_id":{"format":"uuid","type":"string"},"edition_id":{"format":"uuid","type":"string"},"environment_id":{"type":"string"},"objects":{"items":{"additionalProperties":false,"properties":{"canonical_content":{"type":"string"},"lifecycle_state":{"const":"active"},"object_digest":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"object_id":{"format":"uuid","type":"string"},"revision":{"minimum":1,"type":"integer"},"schema_id":{"type":"string"},"schema_version":{"minimum":1,"type":"integer"}},"required":["object_id","revision","schema_id","schema_version","lifecycle_state","canonical_content","object_digest"],"type":"object"},"maxItems":100,"type":"array"},"principal_id":{"format":"uuid","type":"string"},"release_id":{"format":"uuid","type":"string"},"workspace_id":{"format":"uuid","type":"string"}},"required":["workspace_id","environment_id","release_id","edition_id","principal_id","delegation_id","authorization_decision_digest","objects"],"type":"object"}"#;
const CONTEXT_BUILD_INPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/context.build/input/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"delegation_id":{"format":"uuid","type":"string"},"environment_id":{"maxLength":128,"minLength":1,"type":"string"},"expires_at":{"format":"date-time","type":"string"},"idempotency_key":{"format":"uuid","type":"string"},"intent":{"maxLength":4096,"minLength":1,"type":"string"},"max_bytes":{"maximum":1048576,"minimum":1,"type":"integer"},"max_objects":{"maximum":100,"minimum":1,"type":"integer"},"object_ids":{"items":{"format":"uuid","type":"string"},"maxItems":100,"minItems":1,"type":"array","uniqueItems":true},"operating_principal_id":{"format":"uuid","type":"string"},"task_id":{"maxLength":256,"minLength":1,"type":"string"}},"required":["operating_principal_id","delegation_id","task_id","intent","environment_id","object_ids","max_objects","max_bytes","idempotency_key","expires_at"],"type":"object"}"#;
const CONTEXT_BUILD_OUTPUT_SCHEMA: &str = r#"{"$id":"proof.dev/schema/operation/context.build/output/v1","$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"base_state":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"built_at":{"format":"date-time","type":"string"},"capabilities":{"items":{"type":"string"},"type":"array","uniqueItems":true},"context_pack_digest":{"pattern":"^blake3:[0-9a-f]{64}$","type":"string"},"context_pack_id":{"format":"uuid","type":"string"},"delegation_id":{"format":"uuid","type":"string"},"edition_id":{"format":"uuid","type":"string"},"environment_id":{"type":"string"},"expires_at":{"format":"date-time","type":"string"},"intent":{"type":"string"},"limits":{"additionalProperties":false,"properties":{"max_bytes":{"minimum":1,"type":"integer"},"max_objects":{"minimum":1,"type":"integer"}},"required":["max_objects","max_bytes"],"type":"object"},"manifest_json":{"type":"string"},"object_ids":{"items":{"format":"uuid","type":"string"},"type":"array","uniqueItems":true},"operating_principal_id":{"format":"uuid","type":"string"},"release_id":{"format":"uuid","type":"string"},"requesting_principal_id":{"format":"uuid","type":"string"},"task_id":{"type":"string"},"workspace_id":{"format":"uuid","type":"string"}},"required":["context_pack_id","workspace_id","requesting_principal_id","operating_principal_id","delegation_id","task_id","intent","environment_id","release_id","edition_id","base_state","object_ids","limits","built_at","expires_at","capabilities","manifest_json","context_pack_digest"],"type":"object"}"#;

const LOCALIZED_OPERATIONS_SCHEMA_CATALOG: &str =
    include_str!("../../../conformance/v2/localized-content/schemas/operations.schema.json");
const LOCALIZED_ARTIFACTS_SCHEMA_CATALOG: &str =
    include_str!("../../../conformance/v2/localized-content/schemas/artifacts.schema.json");
const LOCALIZED_ARTIFACT_REF_PREFIX: &str =
    "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/";
const LOCALIZED_ARTIFACT_BUNDLE_PREFIX: &str = "#/$defs/artifact__";

fn rewrite_localized_schema_refs(value: &mut serde_json::Value, artifact_definition: bool) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                rewrite_localized_schema_refs(value, artifact_definition);
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(reference) = object
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            {
                let rewritten = if let Some(definition) =
                    reference.strip_prefix(LOCALIZED_ARTIFACT_REF_PREFIX)
                {
                    Some(format!("{LOCALIZED_ARTIFACT_BUNDLE_PREFIX}{definition}"))
                } else if artifact_definition {
                    reference
                        .strip_prefix("#/$defs/")
                        .map(|definition| format!("{LOCALIZED_ARTIFACT_BUNDLE_PREFIX}{definition}"))
                } else {
                    None
                };
                if let Some(rewritten) = rewritten {
                    object.insert("$ref".to_owned(), serde_json::Value::String(rewritten));
                }
            }
            for child in object.values_mut() {
                rewrite_localized_schema_refs(child, artifact_definition);
            }
        }
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => {}
    }
}

fn bundled_localized_schema_json(definition: &str) -> &'static str {
    let operations: serde_json::Value = serde_json::from_str(LOCALIZED_OPERATIONS_SCHEMA_CATALOG)
        .expect("checked-in localized operation Schema must remain valid JSON");
    let artifacts: serde_json::Value = serde_json::from_str(LOCALIZED_ARTIFACTS_SCHEMA_CATALOG)
        .expect("checked-in localized artifact Schema must remain valid JSON");
    let mut operation_definitions = operations
        .get("$defs")
        .and_then(serde_json::Value::as_object)
        .expect("localized operation Schema must expose $defs")
        .clone();
    let target = operation_definitions
        .get(definition)
        .cloned()
        .expect("capability must name a checked-in localized Schema definition");
    for value in operation_definitions.values_mut() {
        rewrite_localized_schema_refs(value, false);
    }
    for (name, mut value) in artifacts
        .get("$defs")
        .and_then(serde_json::Value::as_object)
        .expect("localized artifact Schema must expose $defs")
        .clone()
    {
        rewrite_localized_schema_refs(&mut value, true);
        operation_definitions.insert(format!("artifact__{name}"), value);
    }
    let mut root = target;
    rewrite_localized_schema_refs(&mut root, false);
    let object = root
        .as_object_mut()
        .expect("localized operation definitions must be object Schemas");
    object.insert(
        "$schema".to_owned(),
        serde_json::Value::String("https://json-schema.org/draft/2020-12/schema".to_owned()),
    );
    object.insert(
        "$id".to_owned(),
        serde_json::Value::String(format!(
            "https://proof.dev/schemas/localized-content/capability-bundle-v2/{definition}"
        )),
    );
    object.insert(
        "$defs".to_owned(),
        serde_json::Value::Object(operation_definitions),
    );
    if definition.ends_with("Input") {
        let properties = object
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .expect("localized input definitions must expose properties");
        for guard in ["delegation_id", "operating_principal_id"] {
            properties.insert(
                guard.to_owned(),
                serde_json::json!({ "$ref": "#/$defs/uuidV7" }),
            );
        }
        let required = object
            .get_mut("required")
            .and_then(serde_json::Value::as_array_mut)
            .expect("localized input definitions must expose required fields");
        required.push(serde_json::Value::String(
            "operating_principal_id".to_owned(),
        ));
        required.push(serde_json::Value::String("delegation_id".to_owned()));
    }
    Box::leak(
        serde_json::to_string(&root)
            .expect("localized capability Schema bundle must serialize")
            .into_boxed_str(),
    )
}

const LOCALIZED_AUTHENTICATED_ERROR_CODES: &[&str] = &[
    "proof.auth.actor_mismatch",
    "proof.auth.audience_mismatch",
    "proof.auth.binding_inactive",
    "proof.auth.denied",
    "proof.auth.expired",
    "proof.auth.malformed",
    "proof.auth.not_yet_valid",
    "proof.auth.replay",
    "proof.authority.integrity",
    "proof.authorization.budget_exceeded",
    "proof.authorization.delegation_expired",
    "proof.authorization.delegation_not_yet_valid",
    "proof.authorization.delegation_revoked",
    "proof.authorization.denied",
    "proof.authorization.principal_disabled",
    "proof.authorization.scope_exceeded",
    "proof.changeset.duplicate_target",
    "proof.changeset.invalid_supersession",
    "proof.changeset.not_approved",
    "proof.changeset.not_draft",
    "proof.changeset.not_ready",
    "proof.changeset.not_submitted",
    "proof.evidence.incomplete",
    "proof.idempotency.key_reused",
    "proof.input.intent_mismatch",
    "proof.input.limit_exceeded",
    "proof.input.schema_mismatch",
    "proof.input.unsupported_version",
    "proof.intent.slot_mismatch",
    "proof.internal",
    "proof.policy.denied",
    "proof.resource.not_found",
    "proof.schema.not_found",
    "proof.state.conflict",
    "proof.state.object_exists",
    "proof.state.source_conflict",
    "proof.state.target_conflict",
    "proof.validation.repair_evidence_invalid",
];

#[allow(
    clippy::too_many_arguments,
    reason = "one row carries the public capability contract"
)]
fn localized_capability(
    operation: &'static str,
    version: &'static str,
    description: &'static str,
    input_definition: &'static str,
    output_definition: &'static str,
    required_action: DelegatedAction,
    idempotency: CapabilityIdempotency,
    side_effect: CapabilitySideEffect,
    max_objects: Option<u32>,
    max_payload_bytes: Option<u64>,
) -> CapabilityDescriptor {
    CapabilityDescriptor {
        operation,
        version,
        description,
        input_schema_json: bundled_localized_schema_json(input_definition),
        output_schema_json: bundled_localized_schema_json(output_definition),
        required_action,
        idempotency,
        side_effect,
        dry_run: false,
        error_codes: LOCALIZED_AUTHENTICATED_ERROR_CODES,
        ambient_error_codes: &[],
        authenticated_error_codes: LOCALIZED_AUTHENTICATED_ERROR_CODES,
        max_objects,
        max_payload_bytes,
    }
}

/// Complete agent-visible capability registry for the fixed 14-operation authority surface.
pub static CAPABILITY_REGISTRY: std::sync::LazyLock<[CapabilityDescriptor; 14]> =
    std::sync::LazyLock::new(|| {
        [
            CapabilityDescriptor {
                operation: "workspace.status",
                version: "proof.dev/operation/workspace.status/v1",
                description: "Return verified Delegation-scoped status for the selected Workspace.",
                input_schema_json: WORKSPACE_STATUS_INPUT_SCHEMA,
                output_schema_json: WORKSPACE_STATUS_OUTPUT_SCHEMA,
                required_action: DelegatedAction::WorkspaceStatus,
                idempotency: CapabilityIdempotency::NotApplicable,
                side_effect: CapabilitySideEffect::EvidenceWrite,
                dry_run: false,
                error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.auth.unauthenticated",
                    "proof.authority.integrity",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.dependency.unavailable",
                    "proof.digest.mismatch",
                    "proof.internal",
                ],
                ambient_error_codes: &[
                    "proof.auth.denied",
                    "proof.auth.unauthenticated",
                    "proof.dependency.unavailable",
                    "proof.digest.mismatch",
                ],
                authenticated_error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.authority.integrity",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.internal",
                ],
                max_objects: None,
                max_payload_bytes: None,
            },
            CapabilityDescriptor {
                operation: "object.query_released",
                version: "proof.dev/operation/object.query_released/v1",
                description: "Return exact Delegation-scoped Objects from one immutable released Edition.",
                input_schema_json: RELEASED_OBJECT_QUERY_INPUT_SCHEMA,
                output_schema_json: RELEASED_OBJECT_QUERY_OUTPUT_SCHEMA,
                required_action: DelegatedAction::ObjectQueryReleased,
                idempotency: CapabilityIdempotency::NotApplicable,
                side_effect: CapabilitySideEffect::EvidenceWrite,
                dry_run: false,
                error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.auth.unauthenticated",
                    "proof.authority.integrity",
                    "proof.authorization.budget_exceeded",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.dependency.unavailable",
                    "proof.digest.mismatch",
                    "proof.input.unsupported_version",
                    "proof.internal",
                    "proof.resource.not_found",
                    "proof.validation.failed",
                ],
                ambient_error_codes: &[
                    "proof.auth.denied",
                    "proof.auth.unauthenticated",
                    "proof.dependency.unavailable",
                    "proof.digest.mismatch",
                    "proof.input.unsupported_version",
                    "proof.resource.not_found",
                    "proof.validation.failed",
                ],
                authenticated_error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.authority.integrity",
                    "proof.authorization.budget_exceeded",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.input.unsupported_version",
                    "proof.internal",
                    "proof.resource.not_found",
                ],
                max_objects: Some(100),
                max_payload_bytes: Some(MAX_CONTEXT_PACK_BYTES),
            },
            CapabilityDescriptor {
                operation: "context.build",
                version: "proof.dev/operation/context.build/v1",
                description: "Build one bounded immutable ContextPack from exact released Objects.",
                input_schema_json: CONTEXT_BUILD_INPUT_SCHEMA,
                output_schema_json: CONTEXT_BUILD_OUTPUT_SCHEMA,
                required_action: DelegatedAction::ContextBuild,
                idempotency: CapabilityIdempotency::Required,
                side_effect: CapabilitySideEffect::EvidenceWrite,
                dry_run: false,
                error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.auth.unauthenticated",
                    "proof.authority.integrity",
                    "proof.authorization.budget_exceeded",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.delegation.expired",
                    "proof.dependency.unavailable",
                    "proof.evidence.incomplete",
                    "proof.idempotency.key_reused",
                    "proof.input.too_large",
                    "proof.internal",
                    "proof.resource.not_found",
                ],
                ambient_error_codes: &[
                    "proof.auth.denied",
                    "proof.auth.unauthenticated",
                    "proof.delegation.expired",
                    "proof.dependency.unavailable",
                    "proof.evidence.incomplete",
                    "proof.idempotency.key_reused",
                    "proof.input.too_large",
                    "proof.resource.not_found",
                ],
                authenticated_error_codes: &[
                    "proof.auth.actor_mismatch",
                    "proof.auth.audience_mismatch",
                    "proof.auth.binding_inactive",
                    "proof.auth.denied",
                    "proof.auth.expired",
                    "proof.auth.malformed",
                    "proof.auth.not_yet_valid",
                    "proof.auth.replay",
                    "proof.authority.integrity",
                    "proof.authorization.budget_exceeded",
                    "proof.authorization.delegation_expired",
                    "proof.authorization.delegation_not_yet_valid",
                    "proof.authorization.delegation_revoked",
                    "proof.authorization.denied",
                    "proof.authorization.principal_disabled",
                    "proof.authorization.scope_exceeded",
                    "proof.delegation.expired",
                    "proof.idempotency.key_reused",
                    "proof.input.too_large",
                    "proof.internal",
                    "proof.resource.not_found",
                ],
                max_objects: Some(100),
                max_payload_bytes: Some(MAX_CONTEXT_PACK_BYTES),
            },
            localized_capability(
                "context.build",
                "proof.dev/operation/context.build/v2",
                "Select and exactly replay one Human-built localized ContextPack.",
                "contextBuildInput",
                "contextBuildOutput",
                DelegatedAction::ContextBuild,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::EvidenceWrite,
                Some(100),
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "changeset.create",
                "proof.dev/operation/changeset.create/v2",
                "Create one Draft localized ChangeSet bound to exact intent and ContextPack evidence.",
                "changeSetCreateInput",
                "changeSetCreateOutput",
                DelegatedAction::ChangesetCreate,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::GovernedWrite,
                None,
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "changeset.add",
                "proof.dev/operation/changeset.add/v2",
                "Append one bounded semantic localized Edit batch to a Draft ChangeSet.",
                "changeSetAddInput",
                "changeSetAddOutput",
                DelegatedAction::ChangesetAdd,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::GovernedWrite,
                Some(MAX_LOCALIZED_EDITS),
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "changeset.get",
                "proof.dev/operation/changeset.get/v2",
                "Return one complete verified localized ChangeSet and effective projection.",
                "changeSetGetInput",
                "changeSetGetOutput",
                DelegatedAction::ChangesetGet,
                CapabilityIdempotency::NotApplicable,
                CapabilitySideEffect::EvidenceWrite,
                None,
                None,
            ),
            localized_capability(
                "changeset.diff",
                "proof.dev/operation/changeset.diff/v2",
                "Return the deterministic effective Edit projection for one localized ChangeSet.",
                "changeSetDiffInput",
                "changeSetDiffOutput",
                DelegatedAction::ChangesetDiff,
                CapabilityIdempotency::NotApplicable,
                CapabilitySideEffect::EvidenceWrite,
                None,
                None,
            ),
            localized_capability(
                "changeset.validate",
                "proof.dev/operation/changeset.validate/v2",
                "Validate the exact localized proposal and append immutable validation evidence.",
                "changeSetValidateInput",
                "changeSetValidateOutput",
                DelegatedAction::ChangesetValidate,
                CapabilityIdempotency::Derived,
                CapabilitySideEffect::EvidenceWrite,
                None,
                None,
            ),
            localized_capability(
                "changeset.submit",
                "proof.dev/operation/changeset.submit/v2",
                "Submit one exact Ready localized ChangeSet for governed approval.",
                "changeSetSubmitInput",
                "changeSetSubmitOutput",
                DelegatedAction::ChangesetSubmit,
                CapabilityIdempotency::Derived,
                CapabilitySideEffect::GovernedWrite,
                None,
                None,
            ),
            localized_capability(
                "changeset.commit",
                "proof.dev/operation/changeset.commit/v2",
                "Atomically commit one approved localized ChangeSet into authoritative renditions.",
                "changeSetCommitInput",
                "changeSetCommitOutput",
                DelegatedAction::ChangesetCommit,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::GovernedWrite,
                None,
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "edition.create",
                "proof.dev/operation/edition.create/v2",
                "Materialize one immutable localized Edition from an exact committed ChangeSet.",
                "editionCreateInput",
                "editionCreateOutput",
                DelegatedAction::EditionCreate,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::GovernedWrite,
                None,
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "release.create",
                "proof.dev/operation/release.create/v2",
                "Promote one exact localized Edition as a signed immutable Release.",
                "releaseCreateInput",
                "releaseCreateOutput",
                DelegatedAction::ReleaseCreate,
                CapabilityIdempotency::Required,
                CapabilitySideEffect::GovernedWrite,
                None,
                Some(MAX_CONTEXT_PACK_BYTES),
            ),
            localized_capability(
                "object.query_released",
                "proof.dev/operation/object.query_released/v2",
                "Return exact localized renditions selected from one immutable released Edition.",
                "objectQueryReleasedInput",
                "objectQueryReleasedOutput",
                DelegatedAction::ObjectQueryReleased,
                CapabilityIdempotency::NotApplicable,
                CapabilitySideEffect::EvidenceWrite,
                Some(u32::try_from(MAX_LOCALIZED_TARGETS).unwrap_or(u32::MAX)),
                None,
            ),
        ]
    });

/// Returns every initial agent-visible capability in stable registry order.
#[must_use]
pub fn capabilities() -> &'static [CapabilityDescriptor] {
    &CAPABILITY_REGISTRY[..]
}

/// Returns one capability by exact stable operation name.
#[must_use]
pub fn capability(operation: &str) -> Option<&'static CapabilityDescriptor> {
    CAPABILITY_REGISTRY
        .iter()
        .find(|capability| capability.operation == operation)
}

/// Returns one capability by its exact registered operation name and version URI.
#[must_use]
pub fn capability_for_operation(
    operation: &str,
    version: &str,
) -> Option<&'static CapabilityDescriptor> {
    CAPABILITY_REGISTRY
        .iter()
        .find(|capability| capability.operation == operation && capability.version == version)
}

/// Input for creating one versioned delivery Environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateEnvironmentCommand {
    /// Stable logical target identity such as `preview`.
    pub environment_id: EnvironmentId,
    /// Versioned adapter target kind, for example `proof.local/directory/v1`.
    pub target_kind: String,
    /// Versioned release policy profile.
    pub policy_profile: String,
    /// Named approval required before a Release can advance this target.
    pub required_approval: ApprovalName,
    /// Retry identity scoped to Workspace, Principal, and operation.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical creation time.
    pub created_at: Timestamp,
}

/// One verified versioned delivery Environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Environment {
    /// Stable logical Environment identity.
    pub environment_id: EnvironmentId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Monotonic immutable configuration version.
    pub config_version: u32,
    /// Versioned adapter target kind.
    pub target_kind: String,
    /// Versioned release policy profile.
    pub policy_profile: String,
    /// Named approval required before Release.
    pub required_approval: ApprovalName,
    /// RFC 8785 canonical Environment configuration manifest.
    pub config_manifest_json: String,
    /// Domain-separated configuration digest.
    pub config_digest: ContentDigest,
    /// Derived pointer to the latest accepted Release.
    pub current_release_id: Option<ReleaseId>,
    /// Authenticated creating Principal.
    pub principal_id: PrincipalId,
    /// Canonical creation time.
    pub created_at: Timestamp,
}

/// Environment configuration persistence port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait EnvironmentRepository {
    /// Creates a version-one Environment or replays the original result.
    fn create_environment(
        &self,
        command: CreateEnvironmentCommand,
    ) -> Result<Environment, EnvironmentError>;
    /// Returns one verified Environment.
    fn get_environment(
        &self,
        environment_id: EnvironmentId,
    ) -> Result<Environment, EnvironmentError>;
}

/// An Environment operation failed without changing a release pointer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EnvironmentError {
    /// The local identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The target is absent or not visible.
    #[error("the requested Environment was not found")]
    NotFound,
    /// The logical target already exists with different configuration.
    #[error("the Environment already exists with different configuration")]
    AlreadyExists,
    /// Target kind or policy profile is empty or unsupported.
    #[error("the Environment configuration is invalid")]
    InvalidConfiguration,
    /// The retry key was bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Persisted or canonical Environment state failed verification.
    #[error("Environment integrity verification failed: {0}")]
    Integrity(String),
    /// Environment persistence is unavailable.
    #[error("Environment storage is unavailable: {0}")]
    Storage(String),
}

/// Creates an Environment through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn create_environment(
    repository: &impl EnvironmentRepository,
    command: CreateEnvironmentCommand,
) -> Result<Environment, EnvironmentError> {
    if command.target_kind.trim().is_empty() || command.policy_profile.trim().is_empty() {
        return Err(EnvironmentError::InvalidConfiguration);
    }
    repository.create_environment(command)
}

/// Reads an Environment through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn get_environment(
    repository: &impl EnvironmentRepository,
    environment_id: EnvironmentId,
) -> Result<Environment, EnvironmentError> {
    repository.get_environment(environment_id)
}

/// Input for promoting one immutable Edition to an Environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromoteReleaseCommand {
    /// Candidate immutable Release identity.
    pub release_id: ReleaseId,
    /// Candidate portable Proof identity.
    pub proof_id: ProofId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Immutable Edition to select.
    pub edition_id: EditionId,
    /// Retry identity for the consequential operation.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical release time.
    pub released_at: Timestamp,
}

/// Input for rolling an Environment back to an earlier Release's Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackReleaseCommand {
    /// Candidate immutable Release identity.
    pub release_id: ReleaseId,
    /// Candidate portable Proof identity.
    pub proof_id: ProofId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Earlier Release whose Edition will be selected.
    pub rollback_target_release_id: ReleaseId,
    /// Retry identity for the consequential operation.
    pub idempotency_key: IdempotencyKey,
    /// Injected canonical release time.
    pub released_at: Timestamp,
}

/// One immutable Environment Release and its portable signed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Release {
    /// Stable Release identity.
    pub release_id: ReleaseId,
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Target Environment.
    pub environment_id: EnvironmentId,
    /// Selected immutable Edition.
    pub edition_id: EditionId,
    /// Promotion or rollback classification.
    pub kind: ReleaseKind,
    /// Monotonic global causal sequence; predecessor links preserve per-Environment order.
    pub release_sequence: u64,
    /// Release current immediately before this fact.
    pub previous_release_id: Option<ReleaseId>,
    /// Earlier Release selected by a rollback, otherwise absent.
    pub rollback_target_release_id: Option<ReleaseId>,
    /// Authenticated operating Principal.
    pub principal_id: PrincipalId,
    /// Evaluated Delegation when the operation was delegated.
    pub delegation_id: Option<DelegationId>,
    /// Canonical release time.
    pub released_at: Timestamp,
    /// Domain-separated digest of the canonical Release manifest.
    pub release_digest: ContentDigest,
    /// Exact immutable Edition digest selected by this Release.
    pub edition_digest: ContentDigest,
    /// Exact Environment configuration digest evaluated by this Release.
    pub environment_config_digest: ContentDigest,
    /// Digest of the exact authority and policy decision.
    pub authorization_decision_digest: ContentDigest,
    /// Portable Proof identity.
    pub proof_id: ProofId,
    /// Domain-separated digest of the exact DSSE envelope bytes.
    pub proof_envelope_digest: ContentDigest,
    /// Explicit Ed25519 signing key identifier.
    pub key_id: String,
    /// Exact strict JSON DSSE envelope.
    pub proof_envelope_json: String,
}

/// Input for verifying one persisted Release and Proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyReleaseCommand {
    /// Release to verify.
    pub release_id: ReleaseId,
    /// Injected verification time.
    pub verified_at: Timestamp,
}

/// Structured verification report for a persisted Release.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the report exposes independent verification checks"
)]
pub struct ReleaseVerification {
    /// Verified Release identity.
    pub release_id: ReleaseId,
    /// Verified Proof identity.
    pub proof_id: ProofId,
    /// Explicit signing key identifier.
    pub key_id: String,
    /// Whether DSSE PAE and Ed25519 verification succeeded.
    pub signature_valid: bool,
    /// Whether Statement subjects match Release and Edition artifacts.
    pub subjects_valid: bool,
    /// Whether required operational evidence is present and internally valid.
    pub evidence_complete: bool,
    /// Whether the key is accepted by the configured trust policy.
    pub trusted: bool,
    /// Whether every required verification check passed.
    pub valid: bool,
    /// Deterministically ordered stable failure codes.
    pub findings: Vec<String>,
    /// Canonical verification time.
    pub verified_at: Timestamp,
}

/// Release transaction and verification port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait ReleaseRepository {
    /// Atomically promotes an Edition, records a Release, and creates its Proof.
    fn promote_release(&self, command: PromoteReleaseCommand) -> Result<Release, ReleaseError>;
    /// Atomically records a rollback Release selecting an earlier Edition.
    fn rollback_release(&self, command: RollbackReleaseCommand) -> Result<Release, ReleaseError>;
    /// Returns one verified persisted Release representation.
    fn get_release(&self, release_id: ReleaseId) -> Result<Release, ReleaseError>;
    /// Verifies Release, Proof, subjects, evidence, and configured trust.
    fn verify_release(
        &self,
        command: VerifyReleaseCommand,
    ) -> Result<ReleaseVerification, ReleaseError>;
}

/// A Release operation failed without moving the Environment pointer.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReleaseError {
    /// The operating identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The requested operation/artifact combination is outside the version matrix.
    #[error("the v1 Release operation is unsupported for this artifact version")]
    UnsupportedVersion,
    /// The requested Environment, Edition, Release, Proof, or key is absent.
    #[error("the requested Release resource was not found")]
    NotFound,
    /// Policy or approval did not authorize the Release.
    #[error("release policy denied the requested operation")]
    PolicyDenied,
    /// A rollback target belongs to another Environment or is otherwise invalid.
    #[error("the rollback target is invalid for this Environment")]
    InvalidRollbackTarget,
    /// The expected Environment pointer changed before commit.
    #[error("the Environment release pointer changed concurrently")]
    StateConflict,
    /// The retry key was bound to different normalized input.
    #[error("the idempotency key was already used with different input")]
    IdempotencyKeyReused,
    /// Signing or key resolution is unavailable.
    #[error("Release Proof signing is unavailable: {0}")]
    Signing(String),
    /// Release, Edition, or Proof evidence failed deterministic verification.
    #[error("Release integrity verification failed: {0}")]
    Integrity(String),
    /// Release persistence is unavailable.
    #[error("Release storage is unavailable: {0}")]
    Storage(String),
}

/// Promotes one Edition through the configured Release port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn promote_release(
    repository: &impl ReleaseRepository,
    command: PromoteReleaseCommand,
) -> Result<Release, ReleaseError> {
    repository.promote_release(command)
}

/// Rolls one Environment back through the configured Release port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn rollback_release(
    repository: &impl ReleaseRepository,
    command: RollbackReleaseCommand,
) -> Result<Release, ReleaseError> {
    repository.rollback_release(command)
}

/// Reads one Release through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn get_release(
    repository: &impl ReleaseRepository,
    release_id: ReleaseId,
) -> Result<Release, ReleaseError> {
    repository.get_release(release_id)
}

/// Verifies one Release through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn verify_release(
    repository: &impl ReleaseRepository,
    command: VerifyReleaseCommand,
) -> Result<ReleaseVerification, ReleaseError> {
    repository.verify_release(command)
}

/// Input for one exact delegated query against a released Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryReleasedObjectsCommand {
    /// Selected operating Agent Principal; absent for authenticated local-Human reads.
    pub operating_principal_id: Option<PrincipalId>,
    /// Presented Delegation; present exactly when an operating Agent is selected.
    pub delegation_id: Option<DelegationId>,
    /// Exact released Environment.
    pub environment_id: EnvironmentId,
    /// Non-empty exact Object identities; an empty list is never a wildcard.
    pub object_ids: Vec<ObjectId>,
    /// Injected authority-evaluation time.
    pub evaluated_at: Timestamp,
}

/// One Object revision selected from an immutable released Edition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedObject {
    /// Stable Object identity.
    pub object_id: ObjectId,
    /// Exact accepted revision.
    pub revision: ObjectRevision,
    /// Governing Schema identity.
    pub schema_id: SchemaId,
    /// Governing immutable Schema version.
    pub schema_version: SchemaVersion,
    /// Accepted lifecycle state.
    pub lifecycle_state: ObjectLifecycleState,
    /// RFC 8785 canonical content.
    pub canonical_content: String,
    /// Domain-separated Object revision digest.
    pub object_digest: ContentDigest,
}

/// Result of one exact authorized released-Object query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedObjectQuery {
    /// Owning Workspace.
    pub workspace_id: WorkspaceId,
    /// Exact Environment queried.
    pub environment_id: EnvironmentId,
    /// Current immutable Release.
    pub release_id: ReleaseId,
    /// Immutable Edition selected by that Release.
    pub edition_id: EditionId,
    /// Caller-declared operating Agent Principal; v1 does not authenticate an
    /// Agent binding independently of the local requesting Human.
    pub principal_id: PrincipalId,
    /// Evaluated Delegation for an Agent query; absent for local-Human reads.
    pub delegation_id: Option<DelegationId>,
    /// Authorization-decision digest for this exact query.
    pub authorization_decision_digest: ContentDigest,
    /// Returned Objects in requested canonical identity order.
    pub objects: Vec<ReleasedObject>,
}

/// Read port for exact authorized released content.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait ReleasedObjectRepository {
    /// Evaluates authority and returns exact immutable released Objects.
    fn query_released_objects(
        &self,
        command: QueryReleasedObjectsCommand,
    ) -> Result<ReleasedObjectQuery, QueryReleasedObjectsError>;
}

/// A released-Object query failed without broadening visibility.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum QueryReleasedObjectsError {
    /// The requesting identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// The current release uses the localized v2 contract.
    #[error("the v1 released-Object query is unsupported for this Release version")]
    UnsupportedVersion,
    /// The Delegation denied the exact query.
    #[error("the released Object query is outside delegated authority")]
    Denied,
    /// The request was empty, duplicated, or exceeded its count budget.
    #[error("the released Object query must contain unique exact Object identities within budget")]
    InvalidQuery,
    /// Environment, current Release, Edition, or one Object is absent or hidden.
    #[error("a requested released Object resource was not found")]
    NotFound,
    /// Released projections or canonical bytes failed verification.
    #[error("released Object integrity verification failed: {0}")]
    Integrity(String),
    /// Released-content storage is unavailable.
    #[error("released Object storage is unavailable: {0}")]
    Storage(String),
}

/// Queries exact released Objects through the configured read port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn query_released_objects(
    repository: &impl ReleasedObjectRepository,
    command: QueryReleasedObjectsCommand,
) -> Result<ReleasedObjectQuery, QueryReleasedObjectsError> {
    let unique = command
        .object_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let authority_pair_valid =
        command.operating_principal_id.is_some() == command.delegation_id.is_some();
    if !authority_pair_valid
        || command.object_ids.is_empty()
        || command.object_ids.len() > MAX_DELEGATION_OBJECTS
        || unique != command.object_ids.len()
    {
        return Err(QueryReleasedObjectsError::InvalidQuery);
    }
    repository.query_released_objects(command)
}

/// Input for rebuilding every derived projection from authoritative records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RebuildProjectionsCommand {
    /// Report drift without writing repaired projections.
    pub dry_run: bool,
}

/// Result of reproducing and optionally repairing derived projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionRebuild {
    /// Whether no derived writes were attempted.
    pub dry_run: bool,
    /// Whether persisted projections differed from reproducible projections.
    pub changed: bool,
    /// Last authoritative sequence included.
    pub authoritative_sequence: u64,
    /// Reproduced Known State digest.
    pub state_digest: ContentDigest,
    /// Reproduced Schema projection count.
    pub schema_count: u32,
    /// Reproduced Object projection count.
    pub object_count: u32,
    /// Reproduced Environment current-pointer count.
    pub environment_pointer_count: u32,
}

/// Projection rebuild port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete port contract"
)]
pub trait ProjectionRepository {
    /// Reproduces every projection and writes only when `dry_run` is false.
    fn rebuild_projections(
        &self,
        command: RebuildProjectionsCommand,
    ) -> Result<ProjectionRebuild, RebuildProjectionsError>;
}

/// Projection reproduction failed without altering authoritative records.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RebuildProjectionsError {
    /// The local identity is not authenticated.
    #[error("the current local identity is not authenticated for this Workspace")]
    Unauthenticated,
    /// Authoritative or derived state failed deterministic verification.
    #[error("projection rebuild integrity verification failed: {0}")]
    Integrity(String),
    /// Projection persistence is unavailable.
    #[error("projection rebuild storage is unavailable: {0}")]
    Storage(String),
}

/// Rebuilds projections through the configured port.
#[allow(
    clippy::missing_errors_doc,
    reason = "the associated error enum is the complete operation contract"
)]
pub fn rebuild_projections(
    repository: &impl ProjectionRepository,
    command: RebuildProjectionsCommand,
) -> Result<ProjectionRebuild, RebuildProjectionsError> {
    repository.rebuild_projections(command)
}

/// Data returned by the initial `status` operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StatusData {
    /// Current implementation milestone.
    pub implementation_stage: &'static str,
    /// Whether an initialized Workspace was selected.
    pub workspace_selected: bool,
    /// Whether configuration and private state form a verified Workspace.
    pub workspace_initialized: bool,
    /// Verified Workspace identity when initialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Authenticated Principal identity when initialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Local persistent schema version when initialized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_schema_version: Option<u32>,
    /// Last authoritative sequence included in Known State.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authoritative_sequence: Option<u64>,
    /// Reproducible Known State digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_digest: Option<String>,
}

impl StatusData {
    /// Returns local-proof-loop status before a Workspace has been selected.
    #[must_use]
    pub const fn local_proof_loop(workspace_selected: bool) -> Self {
        Self {
            implementation_stage: "local-proof-loop",
            workspace_selected,
            workspace_initialized: false,
            workspace_id: None,
            principal_id: None,
            storage_schema_version: None,
            authoritative_sequence: None,
            state_digest: None,
        }
    }

    /// Projects a verified repository status into the stable CLI data shape.
    #[must_use]
    pub fn from_workspace(workspace_selected: bool, status: WorkspaceStatus) -> Self {
        match status {
            WorkspaceStatus::Uninitialized => Self::local_proof_loop(workspace_selected),
            WorkspaceStatus::Initialized(status) => Self {
                implementation_stage: "local-proof-loop",
                workspace_selected,
                workspace_initialized: true,
                workspace_id: Some(status.workspace_id.to_string()),
                principal_id: Some(status.principal_id.to_string()),
                storage_schema_version: Some(status.storage_schema_version),
                authoritative_sequence: Some(status.authoritative_sequence),
                state_digest: Some(status.state_digest.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ApprovalName, CAPABILITY_REGISTRY, CapabilityIdempotency, CapabilitySideEffect,
        ChangeSetEdit, ContentDigest, CorrelationId, EditId, ExitCode, InspectedChangeSetEdit,
        InspectedObjectCreateEdit, ObjectCreateEdit, ObjectId, OperationId, ResultEnvelope,
        SchemaId, SchemaVersion, StatusData, capability_for_operation,
    };

    const OPERATION_ID: &str = "019c0000-0000-7000-8000-000000000001";
    const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000002";

    #[test]
    fn success_envelope_matches_the_stable_json_shape() {
        let result = ResultEnvelope::success(
            "status",
            OPERATION_ID.parse::<OperationId>().unwrap(),
            CORRELATION_ID.parse::<CorrelationId>().unwrap(),
            StatusData::local_proof_loop(false),
        );
        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["api_version"], "proof.dev/result/v1");
        assert_eq!(value["operation"], "status");
        assert_eq!(value["operation_id"], OPERATION_ID);
        assert_eq!(value["correlation_id"], CORRELATION_ID);
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["implementation_stage"], "local-proof-loop");
        assert_eq!(value["warnings"], serde_json::json!([]));
        assert_eq!(value["meta"]["proof_version"], "0.1.0");
        assert!(value["meta"].get("workspace_id").is_none());
    }

    #[test]
    fn agent_capability_registry_exposes_complete_versioned_schemas() {
        assert_eq!(CAPABILITY_REGISTRY.len(), 14);
        assert_eq!(
            CAPABILITY_REGISTRY
                .iter()
                .filter(|capability| capability.side_effect == CapabilitySideEffect::EvidenceWrite)
                .count(),
            8
        );
        assert_eq!(
            CAPABILITY_REGISTRY
                .iter()
                .filter(|capability| capability.side_effect == CapabilitySideEffect::GovernedWrite)
                .count(),
            6
        );
        for capability in CAPABILITY_REGISTRY.iter() {
            assert!(capability.authority_operation().is_some());
            let input = capability.input_schema().unwrap();
            let output = capability.output_schema().unwrap();
            assert!(input["$id"].as_str().is_some());
            assert_eq!(input["additionalProperties"], false);
            assert!(
                input["required"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty())
            );
            assert!(output["$id"].as_str().is_some());
            if output.get("$ref").is_none() {
                assert_eq!(output["additionalProperties"], false);
                assert!(
                    output["required"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty())
                );
            } else {
                assert!(
                    output["$ref"]
                        .as_str()
                        .is_some_and(|reference| { reference.starts_with("#/$defs/") })
                );
            }
            if capability.version.ends_with("/v2") {
                assert!(
                    input["$defs"]
                        .as_object()
                        .is_some_and(|defs| !defs.is_empty())
                );
                assert!(!capability.input_schema_json.contains(
                    "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/"
                ));
                assert!(!capability.output_schema_json.contains(
                    "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/"
                ));
                for guard in ["operating_principal_id", "delegation_id"] {
                    assert!(
                        input["required"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|value| value == guard)
                    );
                    assert!(input["properties"].get(guard).is_some());
                    assert!(output["properties"].get(guard).is_none());
                }
                assert_eq!(capability.mcp_tool_name().rsplit('.').next(), Some("v2"));
            }
        }
        let context =
            capability_for_operation("context.build", "proof.dev/operation/context.build/v1")
                .unwrap();
        let input: serde_json::Value = serde_json::from_str(context.input_schema_json).unwrap();
        let required = input["required"].as_array().unwrap();
        for field in [
            "operating_principal_id",
            "delegation_id",
            "idempotency_key",
            "max_objects",
            "max_bytes",
        ] {
            assert!(required.iter().any(|value| value == field));
        }
        let validate = capability_for_operation(
            "changeset.validate",
            "proof.dev/operation/changeset.validate/v2",
        )
        .unwrap();
        assert_eq!(validate.idempotency, CapabilityIdempotency::Derived);
        assert_eq!(validate.side_effect, CapabilitySideEffect::EvidenceWrite);
    }

    #[test]
    fn capability_error_code_sets_are_sorted_mode_unions() {
        for capability in CAPABILITY_REGISTRY.iter() {
            for codes in [
                capability.error_codes,
                capability.ambient_error_codes,
                capability.authenticated_error_codes,
            ] {
                assert!(codes.windows(2).all(|pair| pair[0] < pair[1]));
            }
            let expected_union = capability
                .ambient_error_codes
                .iter()
                .chain(capability.authenticated_error_codes)
                .copied()
                .collect::<BTreeSet<_>>();
            assert_eq!(
                capability
                    .error_codes
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                expected_union
            );
            for required in [
                "proof.auth.malformed",
                "proof.auth.denied",
                "proof.auth.audience_mismatch",
                "proof.auth.binding_inactive",
                "proof.auth.actor_mismatch",
                "proof.auth.not_yet_valid",
                "proof.auth.expired",
                "proof.auth.replay",
                "proof.authorization.denied",
                "proof.authorization.principal_disabled",
                "proof.authorization.delegation_not_yet_valid",
                "proof.authorization.delegation_expired",
                "proof.authorization.delegation_revoked",
                "proof.authorization.scope_exceeded",
                "proof.authority.integrity",
                "proof.internal",
            ] {
                assert!(capability.authenticated_error_codes.contains(&required));
            }
            for reserved in [
                "proof.authorization.policy_denied",
                "proof.delegation.chain_unsupported",
            ] {
                assert!(!capability.authenticated_error_codes.contains(&reserved));
            }
            assert!(
                !capability
                    .error_codes
                    .contains(&"proof.delegation.scope_exceeded")
            );
        }
    }

    #[test]
    fn capability_error_codes_distinguish_ambient_and_authenticated_paths() {
        let status = CAPABILITY_REGISTRY
            .iter()
            .find(|capability| capability.operation == "workspace.status")
            .unwrap();
        assert_eq!(
            status.ambient_error_codes,
            [
                "proof.auth.denied",
                "proof.auth.unauthenticated",
                "proof.dependency.unavailable",
                "proof.digest.mismatch",
            ]
        );
        let status_output: serde_json::Value =
            serde_json::from_str(status.output_schema_json).unwrap();
        assert!(
            status_output["properties"]
                .get("requesting_principal_id")
                .is_some()
        );
        assert!(
            status_output["properties"]
                .get("operating_principal_id")
                .is_some()
        );
        assert!(status_output["properties"].get("principal_id").is_none());
        let serialized_status = serde_json::to_value(status).unwrap();
        assert_eq!(
            serialized_status["ambient_error_codes"],
            serde_json::json!(status.ambient_error_codes)
        );
        assert_eq!(
            serialized_status["authenticated_error_codes"],
            serde_json::json!(status.authenticated_error_codes)
        );
        assert_eq!(
            serialized_status["error_codes"],
            serde_json::json!(status.error_codes)
        );

        let query = CAPABILITY_REGISTRY
            .iter()
            .find(|capability| capability.operation == "object.query_released")
            .unwrap();
        assert!(
            query
                .authenticated_error_codes
                .contains(&"proof.authorization.budget_exceeded")
        );
        assert!(
            query
                .authenticated_error_codes
                .contains(&"proof.input.unsupported_version")
        );
        assert!(
            query
                .authenticated_error_codes
                .contains(&"proof.resource.not_found")
        );
        let context = CAPABILITY_REGISTRY
            .iter()
            .find(|capability| capability.operation == "context.build")
            .unwrap();
        assert!(
            context
                .authenticated_error_codes
                .contains(&"proof.idempotency.key_reused")
        );
        for code in [
            "proof.auth.denied",
            "proof.delegation.expired",
            "proof.input.too_large",
            "proof.resource.not_found",
        ] {
            assert!(context.authenticated_error_codes.contains(&code));
        }
    }

    #[test]
    fn problem_codes_map_to_documented_exit_categories() {
        assert_eq!(
            ExitCode::for_problem_code("proof.input.invalid_json"),
            ExitCode::Usage
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.validation.failed"),
            ExitCode::Validation
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.auth.denied"),
            ExitCode::Authorization
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.state.conflict"),
            ExitCode::Conflict
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.resource.not_found"),
            ExitCode::NotFound
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.schema.not_found"),
            ExitCode::NotFound
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.intent.slot_mismatch"),
            ExitCode::Conflict
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.state.object_exists"),
            ExitCode::Conflict
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.dependency.unavailable"),
            ExitCode::Unavailable
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.signature.invalid"),
            ExitCode::Integrity
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.operation.timeout"),
            ExitCode::Interrupted
        );
        assert_eq!(
            ExitCode::for_problem_code("proof.internal"),
            ExitCode::Internal
        );
    }

    #[test]
    fn approval_names_use_a_bounded_machine_readable_profile() {
        assert_eq!(
            ApprovalName::new("editorial.review").unwrap().as_str(),
            "editorial.review"
        );
        assert!(ApprovalName::new("").is_err());
        assert!(ApprovalName::new("Editorial").is_err());
        assert!(ApprovalName::new("x".repeat(129)).is_err());
    }

    #[test]
    fn typed_object_edits_expose_shared_identity_and_order() {
        let edit_id = "019c0000-0000-7000-8000-000000000003"
            .parse::<EditId>()
            .unwrap();
        let object_id = "019c0000-0000-7000-8000-000000000004"
            .parse::<ObjectId>()
            .unwrap();
        let schema_id = SchemaId::new("article").unwrap();
        let schema_version = SchemaVersion::new(1).unwrap();
        let object_digest = ContentDigest::blake3([0x42; 32]);
        let proposed = ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
            edit_id,
            object_id,
            schema_id: schema_id.clone(),
            schema_version,
            canonical_content: r#"{"title":"Launch"}"#.to_owned(),
            object_digest,
        });
        let inspected = InspectedChangeSetEdit::ObjectCreate(InspectedObjectCreateEdit {
            ordinal: 2,
            edit_id,
            object_id,
            schema_id,
            schema_version,
            canonical_content: r#"{"title":"Launch"}"#.to_owned(),
            object_digest,
        });

        assert_eq!(proposed.edit_id(), edit_id);
        assert_eq!(inspected.ordinal(), 2);
        assert_eq!(inspected.edit_id(), edit_id);
    }
}
