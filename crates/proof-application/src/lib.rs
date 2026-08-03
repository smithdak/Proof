#![forbid(unsafe_code)]

//! Transport-independent application contracts for Proof.

pub use proof_domain::{
    ArtifactKind, ChangeSetId, ChangeSetIntent, ChangeSetIntentError, ChangeSetStatus,
    ContentDigest, CorrelationId, EditId, IdempotencyKey, IdentifierError, OperationId,
    PrincipalId, PrincipalType, SchemaId, SchemaIdError, SchemaVersion, SchemaVersionError,
    Timestamp, TimestampError, WorkspaceId,
};
use serde::Serialize;
use thiserror::Error;

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
        } else if code.starts_with("proof.validation.")
            || code.starts_with("proof.policy.")
            || code.starts_with("proof.schema.")
            || code.starts_with("proof.relationship.")
        {
            Self::Validation
        } else if code == "proof.resource.not_found" {
            Self::NotFound
        } else if code.starts_with("proof.state.")
            || code.starts_with("proof.changeset.")
            || code.starts_with("proof.idempotency.")
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

/// Input for atomically appending ordered Edits to a draft `ChangeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddChangeSetEditsCommand {
    /// Target draft identity.
    pub changeset_id: ChangeSetId,
    /// Non-empty ordered Edit batch.
    pub edits: Vec<SchemaCreateEdit>,
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
    pub edits: Vec<InspectedSchemaCreateEdit>,
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
    /// Returns the status of the implementation foundation.
    #[must_use]
    pub const fn foundation(workspace_selected: bool) -> Self {
        Self {
            implementation_stage: "foundation",
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
            WorkspaceStatus::Uninitialized => Self::foundation(workspace_selected),
            WorkspaceStatus::Initialized(status) => Self {
                implementation_stage: "foundation",
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
    use super::{CorrelationId, ExitCode, OperationId, ResultEnvelope, StatusData};

    const OPERATION_ID: &str = "019c0000-0000-7000-8000-000000000001";
    const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000002";

    #[test]
    fn success_envelope_matches_the_stable_json_shape() {
        let result = ResultEnvelope::success(
            "status",
            OPERATION_ID.parse::<OperationId>().unwrap(),
            CORRELATION_ID.parse::<CorrelationId>().unwrap(),
            StatusData::foundation(false),
        );
        let value = serde_json::to_value(result).unwrap();

        assert_eq!(value["api_version"], "proof.dev/result/v1");
        assert_eq!(value["operation"], "status");
        assert_eq!(value["operation_id"], OPERATION_ID);
        assert_eq!(value["correlation_id"], CORRELATION_ID);
        assert_eq!(value["ok"], true);
        assert_eq!(value["warnings"], serde_json::json!([]));
        assert_eq!(value["meta"]["proof_version"], "0.1.0");
        assert!(value["meta"].get("workspace_id").is_none());
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
}
