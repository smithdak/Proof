#![forbid(unsafe_code)]

//! Local filesystem and `SQLite` adapters for Proof.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use proof_application::ArtifactKind;
use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, AddedChangeSetEdits, ApproveChangeSetCommand,
    ApproveChangeSetError, ApprovedChangeSet, ChangeSetApprovalRepository,
    ChangeSetCommitRepository, ChangeSetEdit, ChangeSetEditRepository, ChangeSetId,
    ChangeSetInspectionRepository, ChangeSetIntent, ChangeSetRepository, ChangeSetStatus,
    ChangeSetSubmissionRepository, ChangeSetValidationRepository, CommitChangeSetCommand,
    CommitChangeSetError, CommittedChangeSet, ContentDigest, CreateChangeSetCommand,
    CreateChangeSetError, CreateEditionCommand, CreateEditionError, DRAFT_2020_12_META_VALIDATOR,
    DraftChangeSet, EditId, Edition, EditionChangeSet, EditionId, EditionObject, EditionRepository,
    EditionSchema, Finding, IdempotencyKey, InitializeWorkspaceCommand, InitializedWorkspace,
    InitializedWorkspaceStatus, InspectChangeSetError, InspectedChangeSet, InspectedChangeSetEdit,
    InspectedObjectCreateEdit, InspectedSchemaCreateEdit, LOCAL_POLICY_PROFILE,
    LOCAL_VALIDATION_PROFILE, ObjectId, ObjectLifecycleState, ObjectRevision, PrincipalId,
    PrincipalType, SchemaId, SchemaVersion, Severity, SubmitChangeSetCommand, SubmitChangeSetError,
    SubmittedChangeSet, ValidateChangeSetError, ValidatedChangeSet, WorkspaceId,
    WorkspaceInitializationError, WorkspaceRepository, WorkspaceStatus, WorkspaceStatusError,
    WorkspaceStatusRepository,
};
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, initial_known_state_digest,
    known_state_digest_with_objects, object_revision_digest, object_set_digest, parse_strict,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

const CONFIG_API_VERSION: &str = "proof.dev/workspace/v1";
const CONFIG_FILE: &str = "proof.toml";
const RUNTIME_DIRECTORY: &str = ".proof";
const DATABASE_RELATIVE_PATH: &str = ".proof/state/proof.db";
const ARTIFACTS_RELATIVE_PATH: &str = ".proof/artifacts";
const OBJECT_VALIDATOR: &str = "proof/object-create/draft-2020-12/1+jsonschema/0.49.3";
const INITIAL_DATABASE_SCHEMA: &str = "CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (1, 'initialize-local-workspace');
CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL CHECK (
        principal_type IN ('human', 'service', 'agent', 'system_component')
    ),
    identity_provider TEXT NOT NULL,
    identity_subject TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    UNIQUE (identity_provider, identity_subject)
) STRICT;
CREATE TABLE workspace_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    workspace_id TEXT NOT NULL,
    bootstrap_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT;
CREATE TABLE known_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authoritative_sequence INTEGER NOT NULL CHECK (authoritative_sequence >= 0),
    state_digest TEXT NOT NULL
) STRICT;
CREATE TABLE changesets (
    changeset_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    intent TEXT NOT NULL CHECK (length(intent) > 0),
    requested_base_state TEXT,
    base_authoritative_sequence INTEGER NOT NULL CHECK (base_authoritative_sequence >= 0),
    base_state TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status = 'draft'),
    lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (
        lifecycle_status IN (
            'draft', 'validating', 'ready', 'submitted', 'approved',
            'committed', 'rejected', 'superseded', 'expired'
        )
    ),
    policy_profile TEXT NOT NULL,
    validation_profile TEXT NOT NULL,
    UNIQUE (workspace_id, principal_id, idempotency_key)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (2, 'create-draft-changesets');
CREATE TABLE changeset_edits (
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    edit_id TEXT NOT NULL UNIQUE,
    edit_kind TEXT NOT NULL CHECK (edit_kind IN ('schema.create', 'object.create')),
    schema_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    object_id TEXT,
    document_json TEXT NOT NULL,
    document_digest TEXT NOT NULL,
    PRIMARY KEY (changeset_id, ordinal),
    CHECK (
        (edit_kind = 'schema.create' AND object_id IS NULL) OR
        (edit_kind = 'object.create' AND object_id IS NOT NULL)
    )
) STRICT;
CREATE UNIQUE INDEX changeset_schema_targets
    ON changeset_edits(changeset_id, schema_id, schema_version)
    WHERE edit_kind = 'schema.create';
CREATE UNIQUE INDEX changeset_object_targets
    ON changeset_edits(changeset_id, object_id)
    WHERE edit_kind = 'object.create';
CREATE TABLE changeset_add_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    first_ordinal INTEGER NOT NULL CHECK (first_ordinal > 0),
    added_count INTEGER NOT NULL CHECK (added_count > 0),
    total_edit_count INTEGER NOT NULL CHECK (total_edit_count > 0),
    PRIMARY KEY (workspace_id, principal_id, changeset_id, idempotency_key)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (3, 'append-typed-changeset-edits');
CREATE TABLE changeset_validations (
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    changeset_digest TEXT NOT NULL,
    base_state TEXT NOT NULL,
    validation_profile TEXT NOT NULL,
    validator TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
    results_json TEXT NOT NULL,
    results_digest TEXT NOT NULL,
    PRIMARY KEY (changeset_id, changeset_digest, validation_profile, validator)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (4, 'record-changeset-validation');
CREATE TABLE changeset_submissions (
    changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
    changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    submitted_at TEXT NOT NULL
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (5, 'seal-and-submit-changesets');
CREATE TABLE changeset_approvals (
    changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
    approval_name TEXT NOT NULL,
    changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    approved_at TEXT NOT NULL
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (6, 'approve-submitted-changesets');
CREATE TABLE schema_versions (
    schema_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    document_json TEXT NOT NULL,
    document_digest TEXT NOT NULL,
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits(edit_id),
    authoritative_sequence INTEGER NOT NULL UNIQUE CHECK (authoritative_sequence > 0),
    PRIMARY KEY (schema_id, schema_version)
) STRICT;
CREATE TABLE changeset_commits (
    changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    previous_state TEXT NOT NULL,
    resulting_state TEXT NOT NULL,
    authoritative_sequence INTEGER NOT NULL CHECK (authoritative_sequence > 0),
    committed_at TEXT NOT NULL,
    edit_count INTEGER NOT NULL CHECK (edit_count > 0),
    UNIQUE (workspace_id, principal_id, idempotency_key)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (7, 'commit-approved-changesets');
CREATE TABLE editions (
    edition_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    authoritative_sequence INTEGER NOT NULL CHECK (authoritative_sequence > 0),
    state_digest TEXT NOT NULL UNIQUE,
    schema_set_digest TEXT NOT NULL,
    object_set_digest TEXT,
    edition_digest TEXT NOT NULL UNIQUE,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TABLE edition_create_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    requested_state_digest TEXT NOT NULL,
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (8, 'create-immutable-editions');
CREATE TABLE object_revisions (
    object_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision = 1),
    schema_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state = 'active'),
    content_json TEXT NOT NULL,
    object_digest TEXT NOT NULL,
    changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
    edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits(edit_id),
    authoritative_sequence INTEGER NOT NULL UNIQUE CHECK (authoritative_sequence > 0),
    PRIMARY KEY (object_id, revision),
    FOREIGN KEY (schema_id, schema_version)
        REFERENCES schema_versions(schema_id, schema_version)
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (9, 'create-immutable-objects');
PRAGMA user_version = 9;";

struct LocalIdentity {
    provider: &'static str,
    subject: String,
}

/// A selected local Workspace root and its storage adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalWorkspace {
    root: PathBuf,
}

impl LocalWorkspace {
    /// Selects an existing directory as a potential local Workspace root.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceInitializationError::RootUnavailable`] when the path
    /// cannot be resolved or does not identify a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, WorkspaceInitializationError> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| WorkspaceInitializationError::RootUnavailable(error.to_string()))?;
        if !root.is_dir() {
            return Err(WorkspaceInitializationError::RootUnavailable(
                "the selected path is not a directory".to_owned(),
            ));
        }
        Ok(Self { root })
    }

    /// Returns the canonical Workspace root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the version-controlled Workspace configuration path.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.root.join(CONFIG_FILE)
    }

    /// Returns the private runtime-state directory.
    #[must_use]
    pub fn runtime_path(&self) -> PathBuf {
        self.root.join(RUNTIME_DIRECTORY)
    }

    /// Returns the local `SQLite` database path.
    #[must_use]
    pub fn database_path(&self) -> PathBuf {
        self.root.join(DATABASE_RELATIVE_PATH)
    }

    /// Reads and validates the committed Workspace configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceInitializationError::Storage`] when the file cannot
    /// be read or does not match the supported configuration contract.
    pub fn read_config(&self) -> Result<WorkspaceConfig, WorkspaceInitializationError> {
        let content = fs::read_to_string(self.config_path())
            .map_err(|error| storage_error("read Workspace configuration", &error))?;
        let config: WorkspaceConfig = toml::from_str(&content)
            .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
        if config.api_version != CONFIG_API_VERSION {
            return Err(WorkspaceInitializationError::Storage(format!(
                "unsupported Workspace configuration version `{}`",
                config.api_version
            )));
        }
        config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| {
                WorkspaceInitializationError::Storage(format!(
                    "invalid Workspace identity in configuration: {error}"
                ))
            })?;
        if config.storage.mode != "local"
            || config.storage.database != DATABASE_RELATIVE_PATH
            || config.storage.artifacts != ARTIFACTS_RELATIVE_PATH
        {
            return Err(WorkspaceInitializationError::Storage(
                "unsupported or unsafe local storage configuration".to_owned(),
            ));
        }
        Ok(config)
    }

    /// Opens `SQLite` with the required local-mode safety pragmas enabled.
    ///
    /// # Errors
    ///
    /// Returns [`WorkspaceInitializationError::Storage`] when `SQLite` cannot be
    /// opened or configured safely.
    pub fn open_database(&self) -> Result<Connection, WorkspaceInitializationError> {
        open_database_at(&self.database_path())
    }
}

impl WorkspaceRepository for LocalWorkspace {
    fn initialize(
        &self,
        command: InitializeWorkspaceCommand,
    ) -> Result<InitializedWorkspace, WorkspaceInitializationError> {
        let config_path = self.config_path();
        let runtime_path = self.runtime_path();
        if path_exists(&config_path)? || path_exists(&runtime_path)? {
            return Err(WorkspaceInitializationError::AlreadyExists);
        }
        let local_identity = current_local_identity()?;

        fs::create_dir(&runtime_path)
            .map_err(|error| storage_error("create private runtime directory", &error))?;
        set_private_directory_permissions(&runtime_path)?;
        let mut cleanup = InitializationCleanup::new(runtime_path.clone());

        let cache_path = runtime_path.join("cache");
        let state_path = runtime_path.join("state");
        let artifacts_path = runtime_path.join("artifacts");
        for path in [&cache_path, &state_path, &artifacts_path] {
            fs::create_dir(path)
                .map_err(|error| storage_error("create Workspace runtime layout", &error))?;
            set_private_directory_permissions(path)?;
        }

        let database_path = runtime_path.join("state/proof.db");
        let initial_state_digest = initial_known_state_digest(command.workspace_id)
            .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
        let workspace_id = command.workspace_id.to_string();
        let principal_id = command.bootstrap_principal_id.to_string();
        initialize_database(
            &database_path,
            &workspace_id,
            &principal_id,
            &local_identity,
            initial_state_digest.to_string(),
        )?;
        set_private_file_permissions(&database_path)?;

        let config = WorkspaceConfig::new(command.workspace_id.to_string());
        let config_text = toml::to_string_pretty(&config)
            .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
        let temporary_config = self
            .root
            .join(format!(".proof.toml.init-{}", command.workspace_id));
        cleanup.track_temporary_config(temporary_config.clone());
        write_new_file(&temporary_config, config_text.as_bytes())?;
        fs::hard_link(&temporary_config, &config_path)
            .map_err(|error| storage_error("commit Workspace configuration", &error))?;
        cleanup.track_committed_config(config_path);
        fs::remove_file(&temporary_config)
            .map_err(|error| storage_error("remove temporary configuration", &error))?;
        cleanup.clear_temporary_config();
        cleanup.commit();

        Ok(InitializedWorkspace {
            workspace_id: command.workspace_id,
            principal_id: command.bootstrap_principal_id,
        })
    }
}

impl ChangeSetRepository for LocalWorkspace {
    fn create_draft(
        &self,
        command: CreateChangeSetCommand,
    ) -> Result<DraftChangeSet, CreateChangeSetError> {
        let has_config = path_exists(&self.config_path()).map_err(changeset_from_initialization)?;
        let has_runtime =
            path_exists(&self.runtime_path()).map_err(changeset_from_initialization)?;
        if !has_config && !has_runtime {
            return Err(CreateChangeSetError::WorkspaceUninitialized);
        }
        if !has_config || !has_runtime {
            return Err(CreateChangeSetError::Integrity(
                "the selected Workspace has incomplete local state".to_owned(),
            ));
        }

        let config = self.read_config().map_err(changeset_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| CreateChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| CreateChangeSetError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(changeset_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(CreateChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(changeset_from_status)?;
        ensure_changeset_schema(&transaction, schema_version)?;
        let (base_authoritative_sequence, base_state) =
            verified_known_state(&transaction, workspace_id)?;
        let requested_base_state = command.requested_base_state.map(|value| value.to_string());

        if let Some(persisted) = find_idempotent_draft(
            &transaction,
            workspace_id,
            principal_id,
            command.idempotency_key,
        )? {
            if persisted.intent != command.intent.as_str()
                || persisted.requested_base_state != requested_base_state
            {
                return Err(CreateChangeSetError::IdempotencyKeyReused);
            }
            let draft = persisted.into_draft()?;
            transaction
                .commit()
                .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
            return Ok(draft);
        }

        if command
            .requested_base_state
            .is_some_and(|requested| requested != base_state)
        {
            return Err(CreateChangeSetError::BaseStateConflict);
        }
        insert_draft(
            &transaction,
            &command,
            workspace_id,
            principal_id,
            base_authoritative_sequence,
            base_state,
            requested_base_state.as_deref(),
        )?;
        transaction
            .commit()
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;

        Ok(DraftChangeSet {
            changeset_id: command.changeset_id,
            workspace_id,
            principal_id,
            intent: command.intent,
            base_authoritative_sequence,
            base_state,
            idempotency_key: command.idempotency_key,
            created_at: command.created_at,
            status: ChangeSetStatus::Draft,
            policy_profile: LOCAL_POLICY_PROFILE.to_owned(),
            validation_profile: LOCAL_VALIDATION_PROFILE.to_owned(),
            edit_count: 0,
        })
    }
}

impl ChangeSetEditRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "the transaction keeps authentication, migration, replay, and atomic append checks together"
    )]
    fn add_edits(
        &self,
        command: AddChangeSetEditsCommand,
    ) -> Result<AddedChangeSetEdits, AddChangeSetEditsError> {
        let request_digest = verified_edit_batch(&command.edits)?;
        let has_object_edits = command
            .edits
            .iter()
            .any(|edit| matches!(edit, ChangeSetEdit::ObjectCreate(_)));
        let config = self.read_config().map_err(edit_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| AddChangeSetEditsError::Unauthenticated)?;
        let mut connection = self.open_database().map_err(edit_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(AddChangeSetEditsError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(edit_from_status)?;
        ensure_changeset_schema(&transaction, schema_version).map_err(edit_from_create)?;
        let schema_version: u32 = transaction
            .query_row(
                "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        ensure_edit_schema(&transaction, schema_version)?;
        let mut schema_version: u32 = transaction
            .query_row(
                "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        if has_object_edits {
            ensure_object_schema(&transaction, schema_version)?;
            schema_version = 9;
        }
        require_editable_changeset(
            &transaction,
            workspace_id,
            principal_id,
            command.changeset_id,
            schema_version,
        )?;

        if let Some(result) = replay_edit_batch(
            &transaction,
            workspace_id,
            principal_id,
            command.changeset_id,
            command.idempotency_key,
            request_digest,
        )? {
            transaction
                .commit()
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
            return Ok(result);
        }

        reject_duplicate_targets(&transaction, command.changeset_id, &command.edits)?;
        let existing_count = count_changeset_edits(&transaction, command.changeset_id)?;
        let first_ordinal = existing_count
            .checked_add(1)
            .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit ordinal overflow".to_owned()))?;
        append_edit_batch(
            &transaction,
            command.changeset_id,
            first_ordinal,
            schema_version,
            &command.edits,
        )?;
        let added_count = u32::try_from(command.edits.len()).map_err(|_| {
            AddChangeSetEditsError::Integrity("Edit batch count exceeds u32".to_owned())
        })?;
        let total_edit_count = existing_count
            .checked_add(added_count)
            .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit count overflow".to_owned()))?;
        record_edit_batch(
            &transaction,
            workspace_id,
            principal_id,
            &command,
            request_digest,
            first_ordinal,
            added_count,
            total_edit_count,
        )?;
        transaction
            .commit()
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;

        Ok(AddedChangeSetEdits {
            changeset_id: command.changeset_id,
            workspace_id,
            principal_id,
            first_ordinal,
            edit_ids: command
                .edits
                .into_iter()
                .map(|edit| edit.edit_id())
                .collect(),
            total_edit_count,
        })
    }
}

impl ChangeSetInspectionRepository for LocalWorkspace {
    fn inspect_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<InspectedChangeSet, InspectChangeSetError> {
        let config = self.read_config().map_err(inspect_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| InspectChangeSetError::Unauthenticated)?;
        let mut connection =
            open_database_for_status(&self.database_path()).map_err(inspect_from_status)?;
        let transaction = connection
            .transaction()
            .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, metadata_schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(InspectChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(inspect_from_status)?;
        let schema_version = inspect_schema_version(&transaction, metadata_schema_version)?;
        if schema_version < 2 {
            return Err(InspectChangeSetError::NotFound);
        }
        let row = load_inspected_changeset(
            &transaction,
            changeset_id,
            workspace_id,
            principal_id,
            schema_version,
        )?;
        let edits = load_inspected_edits(&transaction, changeset_id, schema_version)?;
        let inspected = row.into_inspected(changeset_id, workspace_id, principal_id, edits)?;
        transaction
            .commit()
            .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
        Ok(inspected)
    }
}

impl ChangeSetValidationRepository for LocalWorkspace {
    fn validate_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<ValidatedChangeSet, ValidateChangeSetError> {
        let config = self.read_config().map_err(validation_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| ValidateChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| ValidateChangeSetError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(validation_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, metadata_schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(ValidateChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(validation_from_status)?;

        ensure_changeset_schema(&transaction, metadata_schema_version)
            .map_err(validation_from_create)?;
        let schema_version = workspace_schema_version(&transaction)?;
        ensure_edit_schema(&transaction, schema_version).map_err(validation_from_edit)?;
        let schema_version = workspace_schema_version(&transaction)?;
        ensure_validation_schema(&transaction, schema_version)?;
        let schema_version = workspace_schema_version(&transaction)?;
        ensure_lifecycle_schema(&transaction, schema_version)?;
        let schema_version = workspace_schema_version(&transaction)?;

        let row = load_inspected_changeset(
            &transaction,
            changeset_id,
            workspace_id,
            principal_id,
            schema_version,
        )
        .map_err(validation_from_inspection)?;
        let edits = load_inspected_edits(&transaction, changeset_id, schema_version)
            .map_err(validation_from_inspection)?;
        let inspected = row
            .into_inspected(changeset_id, workspace_id, principal_id, edits)
            .map_err(validation_from_inspection)?;
        if !matches!(
            inspected.status,
            ChangeSetStatus::Draft | ChangeSetStatus::Ready | ChangeSetStatus::Rejected
        ) {
            return Err(ValidateChangeSetError::NotValidatable);
        }
        let mut validated = validate_inspected_changeset(&transaction, &inspected)?;
        let target_status = if validated.valid {
            ChangeSetStatus::Ready
        } else {
            ChangeSetStatus::Rejected
        };
        if inspected.status != ChangeSetStatus::Draft && inspected.status != target_status {
            return Err(ValidateChangeSetError::NotValidatable);
        }
        validated.status = target_status;
        persist_validation(&transaction, &validated)?;
        transaction
            .execute(
                "UPDATE changesets SET lifecycle_status = ?1 WHERE changeset_id = ?2",
                [target_status.to_string(), changeset_id.to_string()],
            )
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        Ok(validated)
    }
}

impl ChangeSetSubmissionRepository for LocalWorkspace {
    fn submit_changeset(
        &self,
        command: SubmitChangeSetCommand,
    ) -> Result<SubmittedChangeSet, SubmitChangeSetError> {
        let config = self.read_config().map_err(submission_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| SubmitChangeSetError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(submission_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, metadata_schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(SubmitChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(submission_from_status)?;
        ensure_changeset_schema(&transaction, metadata_schema_version)
            .map_err(validation_from_create)
            .map_err(submission_from_validation)?;
        let schema_version =
            workspace_schema_version(&transaction).map_err(submission_from_validation)?;
        ensure_edit_schema(&transaction, schema_version)
            .map_err(validation_from_edit)
            .map_err(submission_from_validation)?;
        let schema_version =
            workspace_schema_version(&transaction).map_err(submission_from_validation)?;
        ensure_validation_schema(&transaction, schema_version)
            .map_err(submission_from_validation)?;
        let schema_version =
            workspace_schema_version(&transaction).map_err(submission_from_validation)?;
        ensure_lifecycle_schema(&transaction, schema_version)
            .map_err(submission_from_validation)?;
        let schema_version =
            workspace_schema_version(&transaction).map_err(submission_from_validation)?;

        let row = load_inspected_changeset(
            &transaction,
            command.changeset_id,
            workspace_id,
            principal_id,
            schema_version,
        )
        .map_err(submission_from_inspection)?;
        let edits = load_inspected_edits(&transaction, command.changeset_id, schema_version)
            .map_err(submission_from_inspection)?;
        let inspected = row
            .into_inspected(command.changeset_id, workspace_id, principal_id, edits)
            .map_err(submission_from_inspection)?;
        if !matches!(
            inspected.status,
            ChangeSetStatus::Ready | ChangeSetStatus::Submitted
        ) {
            return Err(SubmitChangeSetError::NotReady);
        }
        let changeset_digest =
            changeset_digest_for(&inspected).map_err(SubmitChangeSetError::Integrity)?;
        let current_validation = validate_inspected_changeset(&transaction, &inspected)
            .map_err(submission_from_validation)?;
        if !current_validation.valid || current_validation.changeset_digest != changeset_digest {
            return Err(SubmitChangeSetError::ValidationEvidenceMissing);
        }
        let validation_results_digest = exact_valid_evidence(
            &transaction,
            command.changeset_id,
            changeset_digest,
            inspected.base_state,
            &inspected.validation_profile,
            &current_validation.validator,
            current_validation.validation_results_digest,
        )?;
        let edit_count = u32::try_from(inspected.edits.len())
            .map_err(|_| SubmitChangeSetError::Integrity("Edit count exceeds u32".to_owned()))?;

        let submitted = persist_or_replay_submission(
            &transaction,
            &command,
            &inspected,
            changeset_digest,
            validation_results_digest,
            edit_count,
        )?;
        transaction
            .commit()
            .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
        Ok(submitted)
    }
}

impl ChangeSetApprovalRepository for LocalWorkspace {
    fn approve_changeset(
        &self,
        command: ApproveChangeSetCommand,
    ) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
        let config = self.read_config().map_err(approval_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| ApproveChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| ApproveChangeSetError::Unauthenticated)?;
        let mut connection = self.open_database().map_err(approval_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(ApproveChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(approval_from_status)?;
        ensure_approval_schema(&transaction, schema_version)?;
        let schema_version: u32 = transaction
            .query_row(
                "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
        let row = load_inspected_changeset(
            &transaction,
            command.changeset_id,
            workspace_id,
            principal_id,
            schema_version,
        )
        .map_err(approval_from_inspection)?;
        let edits = load_inspected_edits(&transaction, command.changeset_id, schema_version)
            .map_err(approval_from_inspection)?;
        let inspected = row
            .into_inspected(command.changeset_id, workspace_id, principal_id, edits)
            .map_err(approval_from_inspection)?;
        if !matches!(
            inspected.status,
            ChangeSetStatus::Submitted | ChangeSetStatus::Approved
        ) {
            return Err(ApproveChangeSetError::NotSubmitted);
        }
        let current_validation = validate_inspected_changeset(&transaction, &inspected)
            .map_err(approval_from_validation)?;
        if !current_validation.valid {
            return Err(ApproveChangeSetError::EvidenceMissing);
        }
        let validation_results_digest = exact_valid_evidence(
            &transaction,
            command.changeset_id,
            current_validation.changeset_digest,
            inspected.base_state,
            &inspected.validation_profile,
            &current_validation.validator,
            current_validation.validation_results_digest,
        )
        .map_err(approval_from_submission)?;
        replay_submission(
            &transaction,
            &inspected,
            current_validation.changeset_digest,
            validation_results_digest,
            u32::try_from(inspected.edits.len()).map_err(|_| {
                ApproveChangeSetError::Integrity("Edit count exceeds u32".to_owned())
            })?,
        )
        .map_err(approval_from_submission)?;
        let approved = persist_or_replay_approval(
            &transaction,
            &command,
            &inspected,
            current_validation.changeset_digest,
            validation_results_digest,
        )?;
        transaction
            .commit()
            .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
        Ok(approved)
    }
}

impl ChangeSetCommitRepository for LocalWorkspace {
    fn commit_changeset(
        &self,
        command: CommitChangeSetCommand,
    ) -> Result<CommittedChangeSet, CommitChangeSetError> {
        let config = self.read_config().map_err(commit_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| CommitChangeSetError::Unauthenticated)?;
        let mut connection = self.open_database().map_err(commit_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(CommitChangeSetError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(commit_from_status)?;
        ensure_commit_schema(&transaction, schema_version)?;
        let committed =
            commit_verified_transaction(&transaction, workspace_id, principal_id, &command)?;
        transaction
            .commit()
            .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
        Ok(committed)
    }
}

impl EditionRepository for LocalWorkspace {
    fn create_edition(&self, command: CreateEditionCommand) -> Result<Edition, CreateEditionError> {
        let config = self.read_config().map_err(edition_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| CreateEditionError::Unauthenticated)?;
        let mut connection = self.open_database().map_err(edition_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(CreateEditionError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(edition_from_status)?;
        ensure_edition_schema(&transaction, schema_version)?;
        let edition = create_current_edition(&transaction, workspace_id, principal_id, &command)?;
        transaction
            .commit()
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        Ok(edition)
    }
}

impl WorkspaceStatusRepository for LocalWorkspace {
    fn status(&self) -> Result<WorkspaceStatus, WorkspaceStatusError> {
        let has_config = path_exists(&self.config_path()).map_err(status_from_initialization)?;
        let has_runtime = path_exists(&self.runtime_path()).map_err(status_from_initialization)?;
        match (has_config, has_runtime) {
            (false, false) => return Ok(WorkspaceStatus::Uninitialized),
            (true, false) | (false, true) => return Err(WorkspaceStatusError::Incomplete),
            (true, true) => {}
        }

        let config = self.read_config().map_err(status_from_initialization)?;
        let configured_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| WorkspaceStatusError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| WorkspaceStatusError::Unauthenticated)?;
        let connection = open_database_for_status(&self.database_path())?;
        let journal_mode: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
        if journal_mode != "wal" {
            return Err(WorkspaceStatusError::Integrity(
                "local database is not using WAL journal mode".to_owned(),
            ));
        }
        let (database_id, bootstrap_principal_id, metadata_schema_version): (String, String, u32) =
            connection
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                 FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
        let database_id = database_id
            .parse::<WorkspaceId>()
            .map_err(|error| WorkspaceStatusError::Integrity(error.to_string()))?;
        if database_id != configured_id {
            return Err(WorkspaceStatusError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&connection, &bootstrap_principal_id, &local_identity)?;

        let migration_version: u32 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
        let pragma_schema_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
        if metadata_schema_version != migration_version
            || migration_version != pragma_schema_version
        {
            return Err(WorkspaceStatusError::Integrity(
                "persistent schema version records differ".to_owned(),
            ));
        }

        let (authoritative_sequence, persisted_digest) =
            reproducible_known_state(&connection, configured_id)
                .map_err(WorkspaceStatusError::Integrity)?;

        Ok(WorkspaceStatus::Initialized(InitializedWorkspaceStatus {
            workspace_id: configured_id,
            principal_id,
            storage_schema_version: migration_version,
            authoritative_sequence,
            state_digest: persisted_digest,
        }))
    }
}

/// Versioned configuration safe to commit as `proof.toml`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkspaceConfig {
    /// Version of the Workspace configuration contract.
    pub api_version: String,
    /// Stable Workspace `UUIDv7`.
    pub workspace_id: String,
    /// Local storage paths relative to the Workspace root.
    pub storage: StorageConfig,
}

impl WorkspaceConfig {
    fn new(workspace_id: String) -> Self {
        Self {
            api_version: CONFIG_API_VERSION.to_owned(),
            workspace_id,
            storage: StorageConfig {
                mode: "local".to_owned(),
                database: DATABASE_RELATIVE_PATH.to_owned(),
                artifacts: ARTIFACTS_RELATIVE_PATH.to_owned(),
            },
        }
    }
}

/// Local storage configuration persisted in `proof.toml`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageConfig {
    /// Storage adapter mode.
    pub mode: String,
    /// `SQLite` path relative to the Workspace root.
    pub database: String,
    /// Immutable artifact path relative to the Workspace root.
    pub artifacts: String,
}

fn initialize_database(
    path: &Path,
    workspace_id: &str,
    principal_id: &str,
    local_identity: &LocalIdentity,
    initial_state_digest: String,
) -> Result<(), WorkspaceInitializationError> {
    let mut connection = open_database_at(path)?;
    let transaction = connection
        .transaction()
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    transaction
        .execute_batch(INITIAL_DATABASE_SCHEMA)
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO principals (
                 principal_id, principal_type, identity_provider, identity_subject, enabled
             ) VALUES (?1, ?2, ?3, ?4, 1)",
            (
                principal_id,
                PrincipalType::Human.to_string(),
                local_identity.provider,
                &local_identity.subject,
            ),
        )
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO workspace_metadata (
                 singleton, workspace_id, bootstrap_principal_id, schema_version
             ) VALUES (1, ?1, ?2, 9)",
            [workspace_id, principal_id],
        )
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO known_state (singleton, authoritative_sequence, state_digest)
             VALUES (1, 0, ?1)",
            [initial_state_digest],
        )
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    transaction
        .commit()
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    Ok(())
}

fn open_database_at(path: &Path) -> Result<Connection, WorkspaceInitializationError> {
    let connection = Connection::open(path)
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| WorkspaceInitializationError::Storage(error.to_string()))?;
    Ok(connection)
}

fn open_database_for_status(path: &Path) -> Result<Connection, WorkspaceStatusError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
    Ok(connection)
}

fn path_exists(path: &Path) -> Result<bool, WorkspaceInitializationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(storage_error("inspect Workspace target", &error)),
    }
}

fn write_new_file(path: &Path, content: &[u8]) -> Result<(), WorkspaceInitializationError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options
        .open(path)
        .map_err(|error| storage_error("create temporary configuration", &error))?;
    file.write_all(content)
        .and_then(|()| file.sync_all())
        .map_err(|error| storage_error("write Workspace configuration", &error))
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), WorkspaceInitializationError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| storage_error("secure private runtime directory", &error))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), WorkspaceInitializationError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<(), WorkspaceInitializationError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| storage_error("secure private state file", &error))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<(), WorkspaceInitializationError> {
    Ok(())
}

fn storage_error(action: &str, error: &io::Error) -> WorkspaceInitializationError {
    WorkspaceInitializationError::Storage(format!("{action}: {error}"))
}

fn status_from_initialization(error: WorkspaceInitializationError) -> WorkspaceStatusError {
    match error {
        WorkspaceInitializationError::AlreadyExists => WorkspaceStatusError::Integrity(
            "unexpected initialization conflict while reading status".to_owned(),
        ),
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            WorkspaceStatusError::Unauthenticated
        }
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => WorkspaceStatusError::Storage(detail),
    }
}

fn changeset_from_initialization(error: WorkspaceInitializationError) -> CreateChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            CreateChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => CreateChangeSetError::Integrity(
            "unexpected initialization conflict while creating ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => CreateChangeSetError::Storage(detail),
    }
}

fn changeset_from_status(error: WorkspaceStatusError) -> CreateChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => CreateChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => CreateChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => CreateChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => CreateChangeSetError::Storage(detail),
    }
}

fn edit_from_initialization(error: WorkspaceInitializationError) -> AddChangeSetEditsError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            AddChangeSetEditsError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => AddChangeSetEditsError::Integrity(
            "unexpected initialization conflict while appending Edits".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => AddChangeSetEditsError::Storage(detail),
    }
}

fn edit_from_status(error: WorkspaceStatusError) -> AddChangeSetEditsError {
    match error {
        WorkspaceStatusError::Unauthenticated => AddChangeSetEditsError::Unauthenticated,
        WorkspaceStatusError::Incomplete => AddChangeSetEditsError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => AddChangeSetEditsError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => AddChangeSetEditsError::Storage(detail),
    }
}

fn edit_from_create(error: CreateChangeSetError) -> AddChangeSetEditsError {
    match error {
        CreateChangeSetError::Unauthenticated => AddChangeSetEditsError::Unauthenticated,
        CreateChangeSetError::Integrity(detail) => AddChangeSetEditsError::Integrity(detail),
        CreateChangeSetError::Storage(detail) => AddChangeSetEditsError::Storage(detail),
        CreateChangeSetError::WorkspaceUninitialized => AddChangeSetEditsError::NotFound,
        CreateChangeSetError::BaseStateConflict | CreateChangeSetError::IdempotencyKeyReused => {
            AddChangeSetEditsError::Integrity(
                "unexpected draft-creation error while migrating Edit storage".to_owned(),
            )
        }
    }
}

fn inspect_from_initialization(error: WorkspaceInitializationError) -> InspectChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            InspectChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => InspectChangeSetError::Integrity(
            "unexpected initialization conflict while inspecting ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => InspectChangeSetError::Storage(detail),
    }
}

fn inspect_from_status(error: WorkspaceStatusError) -> InspectChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => InspectChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => InspectChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => InspectChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => InspectChangeSetError::Storage(detail),
    }
}

fn validation_from_initialization(error: WorkspaceInitializationError) -> ValidateChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            ValidateChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => ValidateChangeSetError::Integrity(
            "unexpected initialization conflict while validating ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => ValidateChangeSetError::Storage(detail),
    }
}

fn validation_from_status(error: WorkspaceStatusError) -> ValidateChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => ValidateChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => ValidateChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => ValidateChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => ValidateChangeSetError::Storage(detail),
    }
}

fn validation_from_create(error: CreateChangeSetError) -> ValidateChangeSetError {
    match error {
        CreateChangeSetError::Unauthenticated => ValidateChangeSetError::Unauthenticated,
        CreateChangeSetError::Integrity(detail) => ValidateChangeSetError::Integrity(detail),
        CreateChangeSetError::Storage(detail) => ValidateChangeSetError::Storage(detail),
        CreateChangeSetError::WorkspaceUninitialized => ValidateChangeSetError::NotFound,
        CreateChangeSetError::BaseStateConflict | CreateChangeSetError::IdempotencyKeyReused => {
            ValidateChangeSetError::Integrity(
                "unexpected draft-creation error while migrating validation storage".to_owned(),
            )
        }
    }
}

fn validation_from_edit(error: AddChangeSetEditsError) -> ValidateChangeSetError {
    match error {
        AddChangeSetEditsError::Unauthenticated => ValidateChangeSetError::Unauthenticated,
        AddChangeSetEditsError::NotFound => ValidateChangeSetError::NotFound,
        AddChangeSetEditsError::Integrity(detail) => ValidateChangeSetError::Integrity(detail),
        AddChangeSetEditsError::Storage(detail) => ValidateChangeSetError::Storage(detail),
        AddChangeSetEditsError::NotDraft
        | AddChangeSetEditsError::InvalidBatchSize
        | AddChangeSetEditsError::DuplicateTarget
        | AddChangeSetEditsError::IdempotencyKeyReused => ValidateChangeSetError::Integrity(
            "unexpected Edit error while migrating validation storage".to_owned(),
        ),
    }
}

fn validation_from_inspection(error: InspectChangeSetError) -> ValidateChangeSetError {
    match error {
        InspectChangeSetError::Unauthenticated => ValidateChangeSetError::Unauthenticated,
        InspectChangeSetError::NotFound => ValidateChangeSetError::NotFound,
        InspectChangeSetError::Integrity(detail) => ValidateChangeSetError::Integrity(detail),
        InspectChangeSetError::Storage(detail) => ValidateChangeSetError::Storage(detail),
    }
}

fn submission_from_initialization(error: WorkspaceInitializationError) -> SubmitChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            SubmitChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => SubmitChangeSetError::Integrity(
            "unexpected initialization conflict while submitting ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => SubmitChangeSetError::Storage(detail),
    }
}

fn submission_from_status(error: WorkspaceStatusError) -> SubmitChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => SubmitChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => SubmitChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => SubmitChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => SubmitChangeSetError::Storage(detail),
    }
}

fn submission_from_validation(error: ValidateChangeSetError) -> SubmitChangeSetError {
    match error {
        ValidateChangeSetError::Unauthenticated => SubmitChangeSetError::Unauthenticated,
        ValidateChangeSetError::NotFound => SubmitChangeSetError::NotFound,
        ValidateChangeSetError::NotValidatable => SubmitChangeSetError::NotReady,
        ValidateChangeSetError::Integrity(detail) => SubmitChangeSetError::Integrity(detail),
        ValidateChangeSetError::Storage(detail) => SubmitChangeSetError::Storage(detail),
    }
}

fn submission_from_inspection(error: InspectChangeSetError) -> SubmitChangeSetError {
    match error {
        InspectChangeSetError::Unauthenticated => SubmitChangeSetError::Unauthenticated,
        InspectChangeSetError::NotFound => SubmitChangeSetError::NotFound,
        InspectChangeSetError::Integrity(detail) => SubmitChangeSetError::Integrity(detail),
        InspectChangeSetError::Storage(detail) => SubmitChangeSetError::Storage(detail),
    }
}

fn approval_from_initialization(error: WorkspaceInitializationError) -> ApproveChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            ApproveChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => ApproveChangeSetError::Integrity(
            "unexpected initialization conflict while approving ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn approval_from_status(error: WorkspaceStatusError) -> ApproveChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => ApproveChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => ApproveChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => ApproveChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn approval_from_inspection(error: InspectChangeSetError) -> ApproveChangeSetError {
    match error {
        InspectChangeSetError::Unauthenticated => ApproveChangeSetError::Unauthenticated,
        InspectChangeSetError::NotFound => ApproveChangeSetError::NotFound,
        InspectChangeSetError::Integrity(detail) => ApproveChangeSetError::Integrity(detail),
        InspectChangeSetError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn approval_from_validation(error: ValidateChangeSetError) -> ApproveChangeSetError {
    match error {
        ValidateChangeSetError::Unauthenticated => ApproveChangeSetError::Unauthenticated,
        ValidateChangeSetError::NotFound => ApproveChangeSetError::NotFound,
        ValidateChangeSetError::NotValidatable => ApproveChangeSetError::NotSubmitted,
        ValidateChangeSetError::Integrity(detail) => ApproveChangeSetError::Integrity(detail),
        ValidateChangeSetError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn approval_from_submission(error: SubmitChangeSetError) -> ApproveChangeSetError {
    match error {
        SubmitChangeSetError::Unauthenticated => ApproveChangeSetError::Unauthenticated,
        SubmitChangeSetError::NotFound => ApproveChangeSetError::NotFound,
        SubmitChangeSetError::NotReady => ApproveChangeSetError::NotSubmitted,
        SubmitChangeSetError::ValidationEvidenceMissing => ApproveChangeSetError::EvidenceMissing,
        SubmitChangeSetError::Integrity(detail) => ApproveChangeSetError::Integrity(detail),
        SubmitChangeSetError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn commit_from_initialization(error: WorkspaceInitializationError) -> CommitChangeSetError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => {
            CommitChangeSetError::Unauthenticated
        }
        WorkspaceInitializationError::AlreadyExists => CommitChangeSetError::Integrity(
            "unexpected initialization conflict while committing ChangeSet".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn commit_from_status(error: WorkspaceStatusError) -> CommitChangeSetError {
    match error {
        WorkspaceStatusError::Unauthenticated => CommitChangeSetError::Unauthenticated,
        WorkspaceStatusError::Incomplete => CommitChangeSetError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn commit_from_inspection(error: InspectChangeSetError) -> CommitChangeSetError {
    match error {
        InspectChangeSetError::Unauthenticated => CommitChangeSetError::Unauthenticated,
        InspectChangeSetError::NotFound => CommitChangeSetError::NotFound,
        InspectChangeSetError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
        InspectChangeSetError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn commit_from_validation(error: ValidateChangeSetError) -> CommitChangeSetError {
    match error {
        ValidateChangeSetError::Unauthenticated => CommitChangeSetError::Unauthenticated,
        ValidateChangeSetError::NotFound => CommitChangeSetError::NotFound,
        ValidateChangeSetError::NotValidatable => CommitChangeSetError::NotApproved,
        ValidateChangeSetError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
        ValidateChangeSetError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn commit_from_submission(error: SubmitChangeSetError) -> CommitChangeSetError {
    match error {
        SubmitChangeSetError::Unauthenticated => CommitChangeSetError::Unauthenticated,
        SubmitChangeSetError::NotFound => CommitChangeSetError::NotFound,
        SubmitChangeSetError::NotReady | SubmitChangeSetError::ValidationEvidenceMissing => {
            CommitChangeSetError::EvidenceMissing
        }
        SubmitChangeSetError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
        SubmitChangeSetError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn edition_from_initialization(error: WorkspaceInitializationError) -> CreateEditionError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => CreateEditionError::Unauthenticated,
        WorkspaceInitializationError::AlreadyExists => CreateEditionError::Integrity(
            "unexpected initialization conflict while creating Edition".to_owned(),
        ),
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => CreateEditionError::Storage(detail),
    }
}

fn edition_from_status(error: WorkspaceStatusError) -> CreateEditionError {
    match error {
        WorkspaceStatusError::Unauthenticated => CreateEditionError::Unauthenticated,
        WorkspaceStatusError::Incomplete => CreateEditionError::Integrity(
            "the selected Workspace has incomplete local state".to_owned(),
        ),
        WorkspaceStatusError::Integrity(detail) => CreateEditionError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => CreateEditionError::Storage(detail),
    }
}

fn inspect_schema_version(
    connection: &Connection,
    metadata_schema_version: u32,
) -> Result<u32, InspectChangeSetError> {
    let migration_version: u32 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(InspectChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    if !(1..=9).contains(&migration_version) {
        return Err(InspectChangeSetError::Integrity(format!(
            "unsupported local schema version {migration_version}"
        )));
    }
    Ok(migration_version)
}

struct InspectedChangeSetRow {
    intent: String,
    requested_base_state: Option<String>,
    base_authoritative_sequence: i64,
    base_state: String,
    idempotency_key: String,
    created_at: String,
    status: String,
    policy_profile: String,
    validation_profile: String,
}

impl InspectedChangeSetRow {
    fn into_inspected(
        self,
        changeset_id: ChangeSetId,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
        edits: Vec<InspectedChangeSetEdit>,
    ) -> Result<InspectedChangeSet, InspectChangeSetError> {
        let status = parse_changeset_status(&self.status)?;
        if self.policy_profile != LOCAL_POLICY_PROFILE
            || self.validation_profile != LOCAL_VALIDATION_PROFILE
        {
            return Err(InspectChangeSetError::Integrity(
                "persisted ChangeSet profile is unsupported".to_owned(),
            ));
        }
        let base_authoritative_sequence =
            u64::try_from(self.base_authoritative_sequence).map_err(|_| {
                InspectChangeSetError::Integrity(
                    "base authoritative sequence must be non-negative".to_owned(),
                )
            })?;
        let base_state = inspect_parse(&self.base_state, "base state digest")?;
        if base_authoritative_sequence == 0 {
            let expected = initial_known_state_digest(workspace_id)
                .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
            if base_state != expected {
                return Err(InspectChangeSetError::Integrity(
                    "ChangeSet base digest does not match reproducible initial state".to_owned(),
                ));
            }
        }
        Ok(InspectedChangeSet {
            changeset_id,
            workspace_id,
            principal_id,
            intent: ChangeSetIntent::new(self.intent)
                .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?,
            base_authoritative_sequence,
            base_state,
            requested_base_state: self
                .requested_base_state
                .map(|value| inspect_parse(&value, "requested base state digest"))
                .transpose()?,
            idempotency_key: inspect_parse(&self.idempotency_key, "idempotency key")?,
            created_at: inspect_parse(&self.created_at, "creation timestamp")?,
            status,
            policy_profile: self.policy_profile,
            validation_profile: self.validation_profile,
            edits,
        })
    }
}

fn inspect_parse<T>(value: &str, field: &str) -> Result<T, InspectChangeSetError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|error| {
        InspectChangeSetError::Integrity(format!("invalid persisted {field}: {error}"))
    })
}

fn parse_changeset_status(value: &str) -> Result<ChangeSetStatus, InspectChangeSetError> {
    match value {
        "draft" => Ok(ChangeSetStatus::Draft),
        "validating" => Ok(ChangeSetStatus::Validating),
        "ready" => Ok(ChangeSetStatus::Ready),
        "submitted" => Ok(ChangeSetStatus::Submitted),
        "approved" => Ok(ChangeSetStatus::Approved),
        "committed" => Ok(ChangeSetStatus::Committed),
        "rejected" => Ok(ChangeSetStatus::Rejected),
        "superseded" => Ok(ChangeSetStatus::Superseded),
        "expired" => Ok(ChangeSetStatus::Expired),
        _ => Err(InspectChangeSetError::Integrity(
            "persisted ChangeSet lifecycle state is unsupported".to_owned(),
        )),
    }
}

fn load_inspected_changeset(
    connection: &Connection,
    changeset_id: ChangeSetId,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    schema_version: u32,
) -> Result<InspectedChangeSetRow, InspectChangeSetError> {
    let status_column = if schema_version >= 5 {
        "lifecycle_status"
    } else {
        "status"
    };
    connection
        .query_row(
            &format!(
                "SELECT intent, requested_base_state, base_authoritative_sequence,
                        base_state, idempotency_key, created_at, {status_column},
                        policy_profile, validation_profile
                 FROM changesets
                 WHERE changeset_id = ?1 AND workspace_id = ?2 AND principal_id = ?3"
            ),
            [
                changeset_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
            ],
            |row| {
                Ok(InspectedChangeSetRow {
                    intent: row.get(0)?,
                    requested_base_state: row.get(1)?,
                    base_authoritative_sequence: row.get(2)?,
                    base_state: row.get(3)?,
                    idempotency_key: row.get(4)?,
                    created_at: row.get(5)?,
                    status: row.get(6)?,
                    policy_profile: row.get(7)?,
                    validation_profile: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?
        .ok_or(InspectChangeSetError::NotFound)
}

#[expect(
    clippy::too_many_lines,
    reason = "the discriminated-union loader verifies every persisted field before constructing either Edit variant"
)]
fn load_inspected_edits(
    connection: &Connection,
    changeset_id: ChangeSetId,
    schema_version: u32,
) -> Result<Vec<InspectedChangeSetEdit>, InspectChangeSetError> {
    if schema_version < 3 {
        return Ok(Vec::new());
    }
    let object_column = if schema_version >= 9 {
        "object_id"
    } else {
        "NULL AS object_id"
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT ordinal, edit_id, edit_kind, schema_id, schema_version,
                    {object_column}, document_json, document_digest
             FROM changeset_edits WHERE changeset_id = ?1 ORDER BY ordinal"
        ))
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([changeset_id.to_string()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    let mut edits = Vec::new();
    for row in rows {
        let (
            ordinal,
            edit_id,
            edit_kind,
            schema_id,
            schema_version,
            object_id,
            document,
            document_digest,
        ) = row.map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
        let expected_ordinal = u32::try_from(edits.len() + 1).map_err(|_| {
            InspectChangeSetError::Integrity("ChangeSet Edit count exceeds u32".to_owned())
        })?;
        let ordinal = u32::try_from(ordinal).map_err(|_| {
            InspectChangeSetError::Integrity("Edit ordinal must be positive".to_owned())
        })?;
        if ordinal != expected_ordinal {
            return Err(InspectChangeSetError::Integrity(
                "ChangeSet Edit ordering is invalid".to_owned(),
            ));
        }
        let edit_id = inspect_parse(&edit_id, "Edit identity")?;
        let schema_id = SchemaId::new(schema_id)
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let schema_version = SchemaVersion::new(u32::try_from(schema_version).map_err(|_| {
            InspectChangeSetError::Integrity("Schema version must be positive".to_owned())
        })?)
        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let persisted_digest: ContentDigest = inspect_parse(&document_digest, "document digest")?;
        match edit_kind.as_str() {
            "schema.create" => {
                if object_id.is_some() {
                    return Err(InspectChangeSetError::Integrity(
                        "Schema-create Edit contains an Object identity".to_owned(),
                    ));
                }
                let canonical = parse_and_canonical_document(&document)?;
                if digest(ArtifactKind::SchemaVersionV1, &canonical) != persisted_digest {
                    return Err(InspectChangeSetError::Integrity(
                        "Schema document digest does not match canonical content".to_owned(),
                    ));
                }
                edits.push(InspectedChangeSetEdit::SchemaCreate(
                    InspectedSchemaCreateEdit {
                        ordinal,
                        edit_id,
                        schema_id,
                        schema_version,
                        canonical_document: document,
                        document_digest: persisted_digest,
                    },
                ));
            }
            "object.create" => {
                let raw_object_id = object_id.ok_or_else(|| {
                    InspectChangeSetError::Integrity(
                        "Object-create Edit is missing its Object identity".to_owned(),
                    )
                })?;
                let object_id = raw_object_id
                    .parse::<ObjectId>()
                    .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
                if object_id.to_string() != raw_object_id {
                    return Err(InspectChangeSetError::Integrity(
                        "Object identity is not in canonical UUID form".to_owned(),
                    ));
                }
                let (value, canonical) = parse_and_canonical_object(&document)?;
                let expected =
                    object_revision_digest(object_id, &schema_id, schema_version, &value)
                        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
                if expected != persisted_digest {
                    return Err(InspectChangeSetError::Integrity(
                        "Object revision digest does not match canonical content".to_owned(),
                    ));
                }
                edits.push(InspectedChangeSetEdit::ObjectCreate(
                    InspectedObjectCreateEdit {
                        ordinal,
                        edit_id,
                        object_id,
                        schema_id,
                        schema_version,
                        canonical_content: canonical.as_str().to_owned(),
                        object_digest: persisted_digest,
                    },
                ));
            }
            _ => {
                return Err(InspectChangeSetError::Integrity(
                    "ChangeSet Edit kind is unsupported".to_owned(),
                ));
            }
        }
    }
    Ok(edits)
}

fn parse_and_canonical_document(
    document: &str,
) -> Result<proof_canonical::CanonicalJson, InspectChangeSetError> {
    let value = parse_strict(document.as_bytes())
        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
    let canonical = canonicalize(&value)
        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
    if canonical.as_str() != document {
        return Err(InspectChangeSetError::Integrity(
            "Schema document is not canonical JSON".to_owned(),
        ));
    }
    if value
        .as_object()
        .and_then(|object| object.get("$schema"))
        .and_then(serde_json::Value::as_str)
        != Some("https://json-schema.org/draft/2020-12/schema")
    {
        return Err(InspectChangeSetError::Integrity(
            "Schema document dialect is invalid".to_owned(),
        ));
    }
    Ok(canonical)
}

fn ensure_changeset_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), CreateChangeSetError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(CreateChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        1 => transaction
            .execute_batch(
                "CREATE TABLE changesets (
                     changeset_id TEXT PRIMARY KEY,
                     workspace_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     intent TEXT NOT NULL CHECK (length(intent) > 0),
                     requested_base_state TEXT,
                     base_authoritative_sequence INTEGER NOT NULL
                         CHECK (base_authoritative_sequence >= 0),
                     base_state TEXT NOT NULL,
                     idempotency_key TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     status TEXT NOT NULL CHECK (status = 'draft'),
                     policy_profile TEXT NOT NULL,
                     validation_profile TEXT NOT NULL,
                     UNIQUE (workspace_id, principal_id, idempotency_key)
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (2, 'create-draft-changesets');
                 UPDATE workspace_metadata SET schema_version = 2 WHERE singleton = 1;
                 PRAGMA user_version = 2;",
            )
            .map_err(|error| CreateChangeSetError::Storage(error.to_string())),
        2..=9 => Ok(()),
        version => Err(CreateChangeSetError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn ensure_edit_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), AddChangeSetEditsError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(AddChangeSetEditsError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        2 => transaction
            .execute_batch(
                "CREATE TABLE changeset_edits (
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     ordinal INTEGER NOT NULL CHECK (ordinal > 0),
                     edit_id TEXT NOT NULL UNIQUE,
                     edit_kind TEXT NOT NULL CHECK (edit_kind = 'schema.create'),
                     schema_id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                     document_json TEXT NOT NULL,
                     document_digest TEXT NOT NULL,
                     PRIMARY KEY (changeset_id, ordinal),
                     UNIQUE (changeset_id, edit_kind, schema_id, schema_version)
                 ) STRICT;
                 CREATE TABLE changeset_add_operations (
                     workspace_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     idempotency_key TEXT NOT NULL,
                     request_digest TEXT NOT NULL,
                     first_ordinal INTEGER NOT NULL CHECK (first_ordinal > 0),
                     added_count INTEGER NOT NULL CHECK (added_count > 0),
                     total_edit_count INTEGER NOT NULL CHECK (total_edit_count > 0),
                     PRIMARY KEY (workspace_id, principal_id, changeset_id, idempotency_key)
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (3, 'append-typed-changeset-edits');
                 UPDATE workspace_metadata SET schema_version = 3 WHERE singleton = 1;
                 PRAGMA user_version = 3;",
            )
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string())),
        3..=9 => Ok(()),
        version => Err(AddChangeSetEditsError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn workspace_schema_version(connection: &Connection) -> Result<u32, ValidateChangeSetError> {
    connection
        .query_row(
            "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))
}

fn ensure_validation_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), ValidateChangeSetError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(ValidateChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        3 => transaction
            .execute_batch(
                "CREATE TABLE changeset_validations (
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     changeset_digest TEXT NOT NULL,
                     base_state TEXT NOT NULL,
                     validation_profile TEXT NOT NULL,
                     validator TEXT NOT NULL,
                     valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
                     results_json TEXT NOT NULL,
                     results_digest TEXT NOT NULL,
                     PRIMARY KEY (
                         changeset_id, changeset_digest, validation_profile, validator
                     )
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (4, 'record-changeset-validation');
                 UPDATE workspace_metadata SET schema_version = 4 WHERE singleton = 1;
                 PRAGMA user_version = 4;",
            )
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string())),
        4..=9 => Ok(()),
        version => Err(ValidateChangeSetError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn ensure_lifecycle_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), ValidateChangeSetError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(ValidateChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        4 => transaction
            .execute_batch(
                "ALTER TABLE changesets ADD COLUMN lifecycle_status TEXT NOT NULL
                     DEFAULT 'draft' CHECK (
                         lifecycle_status IN (
                             'draft', 'validating', 'ready', 'submitted', 'approved',
                             'committed', 'rejected', 'superseded', 'expired'
                         )
                     );
                 CREATE TABLE changeset_submissions (
                     changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
                     changeset_digest TEXT NOT NULL,
                     validation_results_digest TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     submitted_at TEXT NOT NULL
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (5, 'seal-and-submit-changesets');
                 UPDATE workspace_metadata SET schema_version = 5 WHERE singleton = 1;
                 PRAGMA user_version = 5;",
            )
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string())),
        5..=9 => Ok(()),
        version => Err(ValidateChangeSetError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn ensure_approval_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), ApproveChangeSetError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(ApproveChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        5 => transaction
            .execute_batch(
                "CREATE TABLE changeset_approvals (
                     changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
                     approval_name TEXT NOT NULL,
                     changeset_digest TEXT NOT NULL,
                     validation_results_digest TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     approved_at TEXT NOT NULL
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (6, 'approve-submitted-changesets');
                 UPDATE workspace_metadata SET schema_version = 6 WHERE singleton = 1;
                 PRAGMA user_version = 6;",
            )
            .map_err(|error| ApproveChangeSetError::Storage(error.to_string())),
        6..=9 => Ok(()),
        version => Err(ApproveChangeSetError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn ensure_commit_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), CommitChangeSetError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(CommitChangeSetError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        6 => transaction
            .execute_batch(
                "CREATE TABLE schema_versions (
                     schema_id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                     document_json TEXT NOT NULL,
                     document_digest TEXT NOT NULL,
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits(edit_id),
                     authoritative_sequence INTEGER NOT NULL UNIQUE
                         CHECK (authoritative_sequence > 0),
                     PRIMARY KEY (schema_id, schema_version)
                 ) STRICT;
                 CREATE TABLE changeset_commits (
                     changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
                     workspace_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     idempotency_key TEXT NOT NULL,
                     changeset_digest TEXT NOT NULL,
                     validation_results_digest TEXT NOT NULL,
                     previous_state TEXT NOT NULL,
                     resulting_state TEXT NOT NULL,
                     authoritative_sequence INTEGER NOT NULL
                         CHECK (authoritative_sequence > 0),
                     committed_at TEXT NOT NULL,
                     edit_count INTEGER NOT NULL CHECK (edit_count > 0),
                     UNIQUE (workspace_id, principal_id, idempotency_key)
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (7, 'commit-approved-changesets');
                 UPDATE workspace_metadata SET schema_version = 7 WHERE singleton = 1;
                 PRAGMA user_version = 7;",
            )
            .map_err(|error| CommitChangeSetError::Storage(error.to_string())),
        7..=9 => Ok(()),
        version => Err(CommitChangeSetError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn ensure_edition_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), CreateEditionError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(CreateEditionError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    match migration_version {
        7 => transaction
            .execute_batch(
                "CREATE TABLE editions (
                     edition_id TEXT PRIMARY KEY,
                     workspace_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     authoritative_sequence INTEGER NOT NULL
                         CHECK (authoritative_sequence > 0),
                     state_digest TEXT NOT NULL UNIQUE,
                     schema_set_digest TEXT NOT NULL,
                     edition_digest TEXT NOT NULL UNIQUE,
                     manifest_json TEXT NOT NULL,
                     created_at TEXT NOT NULL
                 ) STRICT;
                 CREATE TABLE edition_create_operations (
                     workspace_id TEXT NOT NULL,
                     principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                     idempotency_key TEXT NOT NULL,
                     requested_state_digest TEXT NOT NULL,
                     edition_id TEXT NOT NULL REFERENCES editions(edition_id),
                     PRIMARY KEY (workspace_id, principal_id, idempotency_key)
                 ) STRICT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (8, 'create-immutable-editions');
                 UPDATE workspace_metadata SET schema_version = 8 WHERE singleton = 1;
                 PRAGMA user_version = 8;",
            )
            .map_err(|error| CreateEditionError::Storage(error.to_string())),
        8 | 9 => Ok(()),
        version => Err(CreateEditionError::Integrity(format!(
            "unsupported local schema version {version}"
        ))),
    }
}

fn parse_and_canonical_object(
    content: &str,
) -> Result<(serde_json::Value, proof_canonical::CanonicalJson), InspectChangeSetError> {
    let value = parse_strict(content.as_bytes())
        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
    if !value.is_object() {
        return Err(InspectChangeSetError::Integrity(
            "Object content root must be a JSON object".to_owned(),
        ));
    }
    let canonical = canonicalize(&value)
        .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
    if canonical.as_str() != content {
        return Err(InspectChangeSetError::Integrity(
            "Object content is not canonical JSON".to_owned(),
        ));
    }
    Ok((value, canonical))
}

#[expect(
    clippy::too_many_lines,
    reason = "the v9 migration is intentionally one auditable transaction including the foreign-key-safe table rebuild"
)]
fn ensure_object_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), AddChangeSetEditsError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(AddChangeSetEditsError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }

    let mut version = migration_version;
    if version == 3 {
        ensure_validation_schema(transaction, version)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 4;
    }
    if version == 4 {
        ensure_lifecycle_schema(transaction, version)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 5;
    }
    if version == 5 {
        ensure_approval_schema(transaction, version)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 6;
    }
    if version == 6 {
        ensure_commit_schema(transaction, version)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 7;
    }
    if version == 7 {
        ensure_edition_schema(transaction, version)
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 8;
    }
    if version == 8 {
        transaction
            .execute_batch(
                "CREATE TABLE changeset_edits_v9 (
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     ordinal INTEGER NOT NULL CHECK (ordinal > 0),
                     edit_id TEXT NOT NULL UNIQUE,
                     edit_kind TEXT NOT NULL
                         CHECK (edit_kind IN ('schema.create', 'object.create')),
                     schema_id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                     object_id TEXT,
                     document_json TEXT NOT NULL,
                     document_digest TEXT NOT NULL,
                     PRIMARY KEY (changeset_id, ordinal),
                     CHECK (
                         (edit_kind = 'schema.create' AND object_id IS NULL) OR
                         (edit_kind = 'object.create' AND object_id IS NOT NULL)
                     )
                 ) STRICT;
                 INSERT INTO changeset_edits_v9 (
                     changeset_id, ordinal, edit_id, edit_kind, schema_id,
                     schema_version, object_id, document_json, document_digest
                 )
                 SELECT changeset_id, ordinal, edit_id, edit_kind, schema_id,
                        schema_version, NULL, document_json, document_digest
                 FROM changeset_edits;
                 CREATE TABLE schema_versions_v9 (
                     schema_id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                     document_json TEXT NOT NULL,
                     document_digest TEXT NOT NULL,
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits_v9(edit_id),
                     authoritative_sequence INTEGER NOT NULL UNIQUE
                         CHECK (authoritative_sequence > 0),
                     PRIMARY KEY (schema_id, schema_version)
                 ) STRICT;
                 INSERT INTO schema_versions_v9 (
                     schema_id, schema_version, document_json, document_digest,
                     changeset_id, edit_id, authoritative_sequence
                 )
                 SELECT schema_id, schema_version, document_json, document_digest,
                        changeset_id, edit_id, authoritative_sequence
                 FROM schema_versions;
                 DROP TABLE schema_versions;
                 DROP TABLE changeset_edits;
                 ALTER TABLE changeset_edits_v9 RENAME TO changeset_edits;
                 ALTER TABLE schema_versions_v9 RENAME TO schema_versions;
                 CREATE UNIQUE INDEX changeset_schema_targets
                     ON changeset_edits(changeset_id, schema_id, schema_version)
                     WHERE edit_kind = 'schema.create';
                 CREATE UNIQUE INDEX changeset_object_targets
                     ON changeset_edits(changeset_id, object_id)
                     WHERE edit_kind = 'object.create';
                 CREATE TABLE object_revisions (
                     object_id TEXT NOT NULL,
                     revision INTEGER NOT NULL CHECK (revision = 1),
                     schema_id TEXT NOT NULL,
                     schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                     lifecycle_state TEXT NOT NULL CHECK (lifecycle_state = 'active'),
                     content_json TEXT NOT NULL,
                     object_digest TEXT NOT NULL,
                     changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                     edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits(edit_id),
                     authoritative_sequence INTEGER NOT NULL UNIQUE
                         CHECK (authoritative_sequence > 0),
                     PRIMARY KEY (object_id, revision),
                     FOREIGN KEY (schema_id, schema_version)
                         REFERENCES schema_versions(schema_id, schema_version)
                 ) STRICT;
                 ALTER TABLE editions ADD COLUMN object_set_digest TEXT;
                 INSERT INTO schema_migrations (version, name)
                 VALUES (9, 'create-immutable-objects');
                 UPDATE workspace_metadata SET schema_version = 9 WHERE singleton = 1;
                 PRAGMA user_version = 9;",
            )
            .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        version = 9;
    }
    if version != 9 {
        return Err(AddChangeSetEditsError::Integrity(format!(
            "unsupported local schema version {version}"
        )));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "ordered Schema visibility and Object validation share one deterministic findings pass"
)]
fn validate_inspected_changeset(
    connection: &Connection,
    changeset: &InspectedChangeSet,
) -> Result<ValidatedChangeSet, ValidateChangeSetError> {
    let changeset_digest =
        changeset_digest_for(changeset).map_err(ValidateChangeSetError::Integrity)?;
    let mut findings = Vec::new();
    if changeset.edits.is_empty() {
        findings.push(Finding {
            code: "proof.changeset.empty".to_owned(),
            severity: Severity::Error,
            pointer: Some("/edits".to_owned()),
            validator: Some(changeset.validation_profile.clone()),
            message: "A ChangeSet must contain at least one Edit before validation".to_owned(),
            repair: None,
        });
    }
    let meta_validator = jsonschema::draft202012::meta::validator();
    let mut proposed_schemas = BTreeMap::new();
    let mut invalid_proposed_schemas = BTreeSet::new();
    for edit in &changeset.edits {
        let index = edit.ordinal().checked_sub(1).ok_or_else(|| {
            ValidateChangeSetError::Integrity("Edit ordinal must be positive".to_owned())
        })?;
        match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => {
                let document = parse_strict(edit.canonical_document.as_bytes())
                    .map_err(|error| ValidateChangeSetError::Integrity(error.to_string()))?;
                let mut schema_invalid = false;
                for error in meta_validator.iter_errors(&document) {
                    schema_invalid = true;
                    findings.push(Finding {
                        code: "proof.schema.meta_schema_invalid".to_owned(),
                        severity: Severity::Error,
                        pointer: Some(format!(
                            "/edits/{index}/document{}",
                            error.instance_path().as_str()
                        )),
                        validator: Some(DRAFT_2020_12_META_VALIDATOR.to_owned()),
                        message: error.to_string(),
                        repair: None,
                    });
                }
                let target = (edit.schema_id.clone(), edit.schema_version);
                if schema_invalid {
                    invalid_proposed_schemas.insert(target.clone());
                }
                proposed_schemas.insert(target, document);
            }
            InspectedChangeSetEdit::ObjectCreate(edit) => {
                let content = parse_strict(edit.canonical_content.as_bytes())
                    .map_err(|error| ValidateChangeSetError::Integrity(error.to_string()))?;
                let target = (edit.schema_id.clone(), edit.schema_version);
                if invalid_proposed_schemas.contains(&target) {
                    continue;
                }
                let schema = if let Some(schema) = proposed_schemas.get(&target) {
                    Some(schema.clone())
                } else {
                    connection
                        .query_row(
                            "SELECT document_json FROM schema_versions
                             WHERE schema_id = ?1 AND schema_version = ?2
                               AND authoritative_sequence <= ?3",
                            (
                                edit.schema_id.as_str(),
                                edit.schema_version.get(),
                                i64::try_from(changeset.base_authoritative_sequence).map_err(
                                    |_| {
                                        ValidateChangeSetError::Integrity(
                                            "base authoritative sequence exceeds local storage range"
                                                .to_owned(),
                                        )
                                    },
                                )?,
                            ),
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?
                        .map(|document| {
                            parse_strict(document.as_bytes()).map_err(|error| {
                                ValidateChangeSetError::Integrity(error.to_string())
                            })
                        })
                        .transpose()?
                };
                let Some(schema) = schema else {
                    findings.push(Finding {
                        code: "proof.schema.not_found".to_owned(),
                        severity: Severity::Error,
                        pointer: Some(format!("/edits/{index}/schema_id")),
                        validator: Some(OBJECT_VALIDATOR.to_owned()),
                        message: format!(
                            "Schema `{}` version {} is not visible at this Edit ordinal",
                            edit.schema_id, edit.schema_version
                        ),
                        repair: None,
                    });
                    continue;
                };
                let validator = match jsonschema::draft202012::new(&schema) {
                    Ok(validator) => validator,
                    Err(error) => {
                        findings.push(Finding {
                            code: "proof.schema.compile_failed".to_owned(),
                            severity: Severity::Error,
                            pointer: Some(format!("/edits/{index}/schema_id")),
                            validator: Some(DRAFT_2020_12_META_VALIDATOR.to_owned()),
                            message: error.to_string(),
                            repair: None,
                        });
                        continue;
                    }
                };
                for error in validator.iter_errors(&content) {
                    let code = match error.kind().keyword() {
                        "required" => "proof.schema.required",
                        "type" => "proof.schema.type_mismatch",
                        _ => "proof.schema.validation_failed",
                    };
                    findings.push(Finding {
                        code: code.to_owned(),
                        severity: Severity::Error,
                        pointer: Some(format!(
                            "/edits/{index}/content{}",
                            error.instance_path().as_str()
                        )),
                        validator: Some(OBJECT_VALIDATOR.to_owned()),
                        message: error.to_string(),
                        repair: None,
                    });
                }
            }
        }
    }
    findings.sort_by(|left, right| {
        (&left.pointer, &left.code, &left.message).cmp(&(
            &right.pointer,
            &right.code,
            &right.message,
        ))
    });
    let valid = findings.is_empty();
    let validator = if changeset
        .edits
        .iter()
        .any(|edit| matches!(edit, InspectedChangeSetEdit::ObjectCreate(_)))
    {
        OBJECT_VALIDATOR
    } else {
        DRAFT_2020_12_META_VALIDATOR
    };
    let results_value = serde_json::json!({
        "api_version": "proof.dev/validation-results/v1",
        "base_state": changeset.base_state.to_string(),
        "changeset_digest": changeset_digest.to_string(),
        "changeset_id": changeset.changeset_id.to_string(),
        "findings": findings,
        "valid": valid,
        "validation_profile": changeset.validation_profile,
        "validator": validator,
    });
    let canonical_results = canonicalize(&results_value)
        .map_err(|error| ValidateChangeSetError::Integrity(error.to_string()))?;
    let validation_results_digest = digest(ArtifactKind::ValidationResultsV1, &canonical_results);
    let edit_count = u32::try_from(changeset.edits.len())
        .map_err(|_| ValidateChangeSetError::Integrity("Edit count exceeds u32".to_owned()))?;
    Ok(ValidatedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        base_state: changeset.base_state,
        validation_profile: changeset.validation_profile.clone(),
        validator: validator.to_owned(),
        valid,
        findings,
        validation_results_digest,
        edit_count,
        status: if valid {
            ChangeSetStatus::Ready
        } else {
            ChangeSetStatus::Rejected
        },
    })
}

fn changeset_digest_for(changeset: &InspectedChangeSet) -> Result<ContentDigest, String> {
    let edits = changeset
        .edits
        .iter()
        .map(|edit| match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => serde_json::json!({
                "document_digest": edit.document_digest.to_string(),
                "edit_id": edit.edit_id.to_string(),
                "kind": "schema.create",
                "ordinal": edit.ordinal,
                "schema_id": edit.schema_id.to_string(),
                "schema_version": edit.schema_version.get(),
            }),
            InspectedChangeSetEdit::ObjectCreate(edit) => serde_json::json!({
                "edit_id": edit.edit_id.to_string(),
                "kind": "object.create",
                "object_digest": edit.object_digest.to_string(),
                "object_id": edit.object_id.to_string(),
                "ordinal": edit.ordinal,
                "schema_id": edit.schema_id.to_string(),
                "schema_version": edit.schema_version.get(),
            }),
        })
        .collect::<Vec<_>>();
    let changeset_manifest = serde_json::json!({
        "api_version": "proof.dev/changeset/v1",
        "base_authoritative_sequence": changeset.base_authoritative_sequence,
        "base_state": changeset.base_state.to_string(),
        "changeset_id": changeset.changeset_id.to_string(),
        "created_at": changeset.created_at.to_string(),
        "edits": edits,
        "idempotency_key": changeset.idempotency_key.to_string(),
        "intent": changeset.intent.to_string(),
        "policy_profile": changeset.policy_profile,
        "principal_id": changeset.principal_id.to_string(),
        "requested_base_state": changeset.requested_base_state.map(|value| value.to_string()),
        "validation_profile": changeset.validation_profile,
        "workspace_id": changeset.workspace_id.to_string(),
    });
    let canonical_changeset =
        canonicalize(&changeset_manifest).map_err(|error| error.to_string())?;
    Ok(digest(ArtifactKind::ChangeSetV1, &canonical_changeset))
}

fn persist_validation(
    transaction: &Transaction<'_>,
    validated: &ValidatedChangeSet,
) -> Result<(), ValidateChangeSetError> {
    let results_value = serde_json::json!({
        "api_version": "proof.dev/validation-results/v1",
        "base_state": validated.base_state.to_string(),
        "changeset_digest": validated.changeset_digest.to_string(),
        "changeset_id": validated.changeset_id.to_string(),
        "findings": validated.findings,
        "valid": validated.valid,
        "validation_profile": validated.validation_profile,
        "validator": validated.validator,
    });
    let results_json = canonicalize(&results_value)
        .map_err(|error| ValidateChangeSetError::Integrity(error.to_string()))?
        .as_str()
        .to_owned();
    transaction
        .execute(
            "INSERT OR IGNORE INTO changeset_validations (
                 changeset_id, changeset_digest, base_state, validation_profile,
                 validator, valid, results_json, results_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                validated.changeset_id.to_string(),
                validated.changeset_digest.to_string(),
                validated.base_state.to_string(),
                &validated.validation_profile,
                &validated.validator,
                i64::from(validated.valid),
                &results_json,
                validated.validation_results_digest.to_string(),
            ),
        )
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    let persisted: (String, i64, String, String) = transaction
        .query_row(
            "SELECT base_state, valid, results_json, results_digest
             FROM changeset_validations
             WHERE changeset_id = ?1 AND changeset_digest = ?2
               AND validation_profile = ?3 AND validator = ?4",
            (
                validated.changeset_id.to_string(),
                validated.changeset_digest.to_string(),
                &validated.validation_profile,
                &validated.validator,
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
    if persisted
        != (
            validated.base_state.to_string(),
            i64::from(validated.valid),
            results_json,
            validated.validation_results_digest.to_string(),
        )
    {
        return Err(ValidateChangeSetError::Integrity(
            "persisted validation evidence does not match deterministic results".to_owned(),
        ));
    }
    Ok(())
}

fn exact_valid_evidence(
    connection: &Connection,
    changeset_id: ChangeSetId,
    changeset_digest: ContentDigest,
    base_state: ContentDigest,
    validation_profile: &str,
    validator: &str,
    expected_results_digest: ContentDigest,
) -> Result<ContentDigest, SubmitChangeSetError> {
    let evidence: Option<(String, String, String)> = connection
        .query_row(
            "SELECT base_state, results_json, results_digest FROM changeset_validations
             WHERE changeset_id = ?1 AND changeset_digest = ?2
               AND validation_profile = ?3 AND validator = ?4 AND valid = 1",
            (
                changeset_id.to_string(),
                changeset_digest.to_string(),
                validation_profile,
                validator,
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    let (persisted_base, results_json, results_digest) =
        evidence.ok_or(SubmitChangeSetError::ValidationEvidenceMissing)?;
    if persisted_base != base_state.to_string() {
        return Err(SubmitChangeSetError::Integrity(
            "validation evidence base state does not match the ChangeSet".to_owned(),
        ));
    }
    let value = parse_strict(results_json.as_bytes())
        .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    if canonical.as_str() != results_json
        || value
            .get("changeset_id")
            .and_then(serde_json::Value::as_str)
            != Some(changeset_id.to_string().as_str())
        || value
            .get("changeset_digest")
            .and_then(serde_json::Value::as_str)
            != Some(changeset_digest.to_string().as_str())
        || value.get("base_state").and_then(serde_json::Value::as_str)
            != Some(base_state.to_string().as_str())
        || value
            .get("validation_profile")
            .and_then(serde_json::Value::as_str)
            != Some(validation_profile)
        || value.get("validator").and_then(serde_json::Value::as_str) != Some(validator)
        || value.get("valid").and_then(serde_json::Value::as_bool) != Some(true)
    {
        return Err(SubmitChangeSetError::Integrity(
            "validation evidence content does not match the exact ChangeSet".to_owned(),
        ));
    }
    let parsed_digest = results_digest
        .parse::<ContentDigest>()
        .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    if digest(ArtifactKind::ValidationResultsV1, &canonical) != parsed_digest
        || parsed_digest != expected_results_digest
    {
        return Err(SubmitChangeSetError::Integrity(
            "validation-results digest does not match canonical evidence".to_owned(),
        ));
    }
    Ok(parsed_digest)
}

fn persist_or_replay_submission(
    transaction: &Transaction<'_>,
    command: &SubmitChangeSetCommand,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
    edit_count: u32,
) -> Result<SubmittedChangeSet, SubmitChangeSetError> {
    if changeset.status == ChangeSetStatus::Submitted {
        return replay_submission(
            transaction,
            changeset,
            changeset_digest,
            validation_results_digest,
            edit_count,
        );
    }
    transaction
        .execute(
            "INSERT INTO changeset_submissions (
                 changeset_id, changeset_digest, validation_results_digest,
                 principal_id, submitted_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                command.changeset_id.to_string(),
                changeset_digest.to_string(),
                validation_results_digest.to_string(),
                changeset.principal_id.to_string(),
                command.submitted_at.to_string(),
            ),
        )
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    let updated = transaction
        .execute(
            "UPDATE changesets SET lifecycle_status = 'submitted'
             WHERE changeset_id = ?1 AND lifecycle_status = 'ready'",
            [command.changeset_id.to_string()],
        )
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    if updated != 1 {
        return Err(SubmitChangeSetError::NotReady);
    }
    Ok(SubmittedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        validation_results_digest,
        base_state: changeset.base_state,
        submitted_at: command.submitted_at,
        status: ChangeSetStatus::Submitted,
        edit_count,
    })
}

fn replay_submission(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
    edit_count: u32,
) -> Result<SubmittedChangeSet, SubmitChangeSetError> {
    let persisted: (String, String, String, String) = connection
        .query_row(
            "SELECT changeset_digest, validation_results_digest, principal_id, submitted_at
             FROM changeset_submissions WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?
        .ok_or(SubmitChangeSetError::ValidationEvidenceMissing)?;
    let persisted_changeset_digest = persisted
        .0
        .parse::<ContentDigest>()
        .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    let persisted_validation_digest = persisted
        .1
        .parse::<ContentDigest>()
        .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    let persisted_principal = persisted
        .2
        .parse::<PrincipalId>()
        .map_err(|error| SubmitChangeSetError::Integrity(error.to_string()))?;
    let submitted_at =
        persisted
            .3
            .parse()
            .map_err(|error: proof_application::TimestampError| {
                SubmitChangeSetError::Integrity(error.to_string())
            })?;
    if persisted_changeset_digest != changeset_digest
        || persisted_validation_digest != validation_results_digest
        || persisted_principal != changeset.principal_id
    {
        return Err(SubmitChangeSetError::Integrity(
            "persisted submission does not match exact validated ChangeSet evidence".to_owned(),
        ));
    }
    Ok(SubmittedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        validation_results_digest,
        base_state: changeset.base_state,
        submitted_at,
        status: ChangeSetStatus::Submitted,
        edit_count,
    })
}

fn persist_or_replay_approval(
    transaction: &Transaction<'_>,
    command: &ApproveChangeSetCommand,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
    if changeset.status == ChangeSetStatus::Approved {
        return replay_approval(
            transaction,
            command,
            changeset,
            changeset_digest,
            validation_results_digest,
        );
    }
    transaction
        .execute(
            "INSERT INTO changeset_approvals (
                 changeset_id, approval_name, changeset_digest,
                 validation_results_digest, principal_id, approved_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                command.changeset_id.to_string(),
                command.approval.as_str(),
                changeset_digest.to_string(),
                validation_results_digest.to_string(),
                changeset.principal_id.to_string(),
                command.approved_at.to_string(),
            ),
        )
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    let updated = transaction
        .execute(
            "UPDATE changesets SET lifecycle_status = 'approved'
             WHERE changeset_id = ?1 AND lifecycle_status = 'submitted'",
            [command.changeset_id.to_string()],
        )
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    if updated != 1 {
        return Err(ApproveChangeSetError::NotSubmitted);
    }
    Ok(ApprovedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        approval: command.approval.clone(),
        changeset_digest,
        validation_results_digest,
        approved_at: command.approved_at,
        status: ChangeSetStatus::Approved,
    })
}

fn replay_approval(
    connection: &Connection,
    command: &ApproveChangeSetCommand,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
    let persisted: (String, String, String, String, String) = connection
        .query_row(
            "SELECT approval_name, changeset_digest, validation_results_digest,
                    principal_id, approved_at
             FROM changeset_approvals WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?
        .ok_or(ApproveChangeSetError::EvidenceMissing)?;
    if persisted.0 != command.approval.as_str() {
        return Err(ApproveChangeSetError::ApprovalConflict);
    }
    let persisted_changeset_digest = persisted
        .1
        .parse::<ContentDigest>()
        .map_err(|error| ApproveChangeSetError::Integrity(error.to_string()))?;
    let persisted_validation_digest = persisted
        .2
        .parse::<ContentDigest>()
        .map_err(|error| ApproveChangeSetError::Integrity(error.to_string()))?;
    let persisted_principal = persisted
        .3
        .parse::<PrincipalId>()
        .map_err(|error| ApproveChangeSetError::Integrity(error.to_string()))?;
    let approved_at = persisted
        .4
        .parse()
        .map_err(|error: proof_application::TimestampError| {
            ApproveChangeSetError::Integrity(error.to_string())
        })?;
    if persisted_changeset_digest != changeset_digest
        || persisted_validation_digest != validation_results_digest
        || persisted_principal != changeset.principal_id
    {
        return Err(ApproveChangeSetError::Integrity(
            "persisted approval does not match exact submitted ChangeSet evidence".to_owned(),
        ));
    }
    Ok(ApprovedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        approval: command.approval.clone(),
        changeset_digest,
        validation_results_digest,
        approved_at,
        status: ChangeSetStatus::Approved,
    })
}

struct VerifiedCommitProposal {
    changeset: InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
}

struct PendingCommitState {
    previous_state: ContentDigest,
    resulting_state: ContentDigest,
    authoritative_sequence: u64,
}

struct PersistedCommitRow {
    idempotency_key: String,
    changeset_digest: String,
    validation_results_digest: String,
    previous_state: String,
    resulting_state: String,
    authoritative_sequence: i64,
    committed_at: String,
    edit_count: i64,
}

fn commit_verified_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    command: &CommitChangeSetCommand,
) -> Result<CommittedChangeSet, CommitChangeSetError> {
    let verified = verified_commit_proposal(transaction, workspace_id, principal_id, command)?;
    if verified.changeset.status == ChangeSetStatus::Committed {
        return replay_commit(transaction, command, &verified);
    }
    reject_reused_commit_key(transaction, workspace_id, principal_id, command)?;
    let (current_sequence, current_state) = reproducible_known_state(transaction, workspace_id)
        .map_err(CommitChangeSetError::Integrity)?;
    if current_sequence != verified.changeset.base_authoritative_sequence
        || current_state != verified.changeset.base_state
    {
        return Err(CommitChangeSetError::BaseStateConflict);
    }
    reject_existing_targets(transaction, &verified.changeset)?;
    let resulting_sequence = apply_edits(transaction, &verified.changeset, current_sequence)?;
    let (_, resulting_state) =
        reproducible_known_state_at(transaction, workspace_id, resulting_sequence)
            .map_err(CommitChangeSetError::Integrity)?;
    let pending = PendingCommitState {
        previous_state: current_state,
        resulting_state,
        authoritative_sequence: resulting_sequence,
    };
    persist_commit(transaction, command, &verified, &pending)?;
    Ok(CommittedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id,
        principal_id,
        changeset_digest: verified.changeset_digest,
        validation_results_digest: verified.validation_results_digest,
        previous_state: pending.previous_state,
        resulting_state: pending.resulting_state,
        authoritative_sequence: pending.authoritative_sequence,
        committed_at: command.committed_at,
        status: ChangeSetStatus::Committed,
        edit_count: u32::try_from(verified.changeset.edits.len())
            .map_err(|_| CommitChangeSetError::Integrity("Edit count exceeds u32".to_owned()))?,
    })
}

fn verified_commit_proposal(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    command: &CommitChangeSetCommand,
) -> Result<VerifiedCommitProposal, CommitChangeSetError> {
    let schema_version: u32 = transaction
        .query_row(
            "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let row = load_inspected_changeset(
        transaction,
        command.changeset_id,
        workspace_id,
        principal_id,
        schema_version,
    )
    .map_err(commit_from_inspection)?;
    let edits = load_inspected_edits(transaction, command.changeset_id, schema_version)
        .map_err(commit_from_inspection)?;
    let changeset = row
        .into_inspected(command.changeset_id, workspace_id, principal_id, edits)
        .map_err(commit_from_inspection)?;
    if !matches!(
        changeset.status,
        ChangeSetStatus::Approved | ChangeSetStatus::Committed
    ) {
        return Err(CommitChangeSetError::NotApproved);
    }
    let validation =
        validate_inspected_changeset(transaction, &changeset).map_err(commit_from_validation)?;
    if !validation.valid {
        return Err(CommitChangeSetError::EvidenceMissing);
    }
    let validation_results_digest = exact_valid_evidence(
        transaction,
        command.changeset_id,
        validation.changeset_digest,
        changeset.base_state,
        &changeset.validation_profile,
        &validation.validator,
        validation.validation_results_digest,
    )
    .map_err(commit_from_submission)?;
    replay_submission(
        transaction,
        &changeset,
        validation.changeset_digest,
        validation_results_digest,
        u32::try_from(changeset.edits.len())
            .map_err(|_| CommitChangeSetError::Integrity("Edit count exceeds u32".to_owned()))?,
    )
    .map_err(commit_from_submission)?;
    verify_approval_evidence(
        transaction,
        &changeset,
        validation.changeset_digest,
        validation_results_digest,
    )?;
    Ok(VerifiedCommitProposal {
        changeset,
        changeset_digest: validation.changeset_digest,
        validation_results_digest,
    })
}

fn verify_approval_evidence(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<(), CommitChangeSetError> {
    let persisted: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT approval_name, changeset_digest, validation_results_digest, principal_id
             FROM changeset_approvals WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let (approval_name, persisted_changeset, persisted_validation, persisted_principal) =
        persisted.ok_or(CommitChangeSetError::EvidenceMissing)?;
    proof_application::ApprovalName::new(approval_name)
        .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
    if persisted_changeset != changeset_digest.to_string()
        || persisted_validation != validation_results_digest.to_string()
        || persisted_principal != changeset.principal_id.to_string()
    {
        return Err(CommitChangeSetError::Integrity(
            "persisted approval does not match exact validated ChangeSet evidence".to_owned(),
        ));
    }
    Ok(())
}

fn reject_reused_commit_key(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    command: &CommitChangeSetCommand,
) -> Result<(), CommitChangeSetError> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT changeset_id FROM changeset_commits
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    if existing.is_some_and(|changeset_id| changeset_id != command.changeset_id.to_string()) {
        return Err(CommitChangeSetError::IdempotencyKeyReused);
    }
    Ok(())
}

fn reject_existing_targets(
    connection: &Connection,
    changeset: &InspectedChangeSet,
) -> Result<(), CommitChangeSetError> {
    for edit in &changeset.edits {
        let exists: bool = match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM schema_versions
                         WHERE schema_id = ?1 AND schema_version = ?2
                     )",
                    (edit.schema_id.as_str(), edit.schema_version.get()),
                    |row| row.get(0),
                )
                .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?,
            InspectedChangeSetEdit::ObjectCreate(edit) => connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM object_revisions WHERE object_id = ?1
                     )",
                    [edit.object_id.to_string()],
                    |row| row.get(0),
                )
                .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?,
        };
        if exists {
            return Err(CommitChangeSetError::TargetConflict);
        }
    }
    Ok(())
}

fn apply_edits(
    transaction: &Transaction<'_>,
    changeset: &InspectedChangeSet,
    current_sequence: u64,
) -> Result<u64, CommitChangeSetError> {
    let mut sequence = current_sequence;
    for edit in &changeset.edits {
        sequence = sequence.checked_add(1).ok_or_else(|| {
            CommitChangeSetError::Integrity("authoritative sequence overflow".to_owned())
        })?;
        let stored_sequence = i64::try_from(sequence).map_err(|_| {
            CommitChangeSetError::Integrity(
                "authoritative sequence exceeds local storage range".to_owned(),
            )
        })?;
        match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => transaction
                .execute(
                    "INSERT INTO schema_versions (
                         schema_id, schema_version, document_json, document_digest,
                         changeset_id, edit_id, authoritative_sequence
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    (
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                        edit.canonical_document.as_str(),
                        edit.document_digest.to_string(),
                        changeset.changeset_id.to_string(),
                        edit.edit_id.to_string(),
                        stored_sequence,
                    ),
                )
                .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?,
            InspectedChangeSetEdit::ObjectCreate(edit) => transaction
                .execute(
                    "INSERT INTO object_revisions (
                         object_id, revision, schema_id, schema_version, lifecycle_state,
                         content_json, object_digest, changeset_id, edit_id,
                         authoritative_sequence
                     ) VALUES (?1, 1, ?2, ?3, 'active', ?4, ?5, ?6, ?7, ?8)",
                    (
                        edit.object_id.to_string(),
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                        edit.canonical_content.as_str(),
                        edit.object_digest.to_string(),
                        changeset.changeset_id.to_string(),
                        edit.edit_id.to_string(),
                        stored_sequence,
                    ),
                )
                .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?,
        };
    }
    Ok(sequence)
}

fn persist_commit(
    transaction: &Transaction<'_>,
    command: &CommitChangeSetCommand,
    verified: &VerifiedCommitProposal,
    pending: &PendingCommitState,
) -> Result<(), CommitChangeSetError> {
    let stored_sequence = i64::try_from(pending.authoritative_sequence).map_err(|_| {
        CommitChangeSetError::Integrity(
            "authoritative sequence exceeds local storage range".to_owned(),
        )
    })?;
    let edit_count = i64::try_from(verified.changeset.edits.len())
        .map_err(|_| CommitChangeSetError::Integrity("Edit count exceeds i64".to_owned()))?;
    transaction
        .execute(
            "INSERT INTO changeset_commits (
                 changeset_id, workspace_id, principal_id, idempotency_key,
                 changeset_digest, validation_results_digest, previous_state,
                 resulting_state, authoritative_sequence, committed_at, edit_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            (
                command.changeset_id.to_string(),
                verified.changeset.workspace_id.to_string(),
                verified.changeset.principal_id.to_string(),
                command.idempotency_key.to_string(),
                verified.changeset_digest.to_string(),
                verified.validation_results_digest.to_string(),
                pending.previous_state.to_string(),
                pending.resulting_state.to_string(),
                stored_sequence,
                command.committed_at.to_string(),
                edit_count,
            ),
        )
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let updated_state = transaction
        .execute(
            "UPDATE known_state
             SET authoritative_sequence = ?1, state_digest = ?2
             WHERE singleton = 1 AND authoritative_sequence = ?3 AND state_digest = ?4",
            (
                stored_sequence,
                pending.resulting_state.to_string(),
                i64::try_from(verified.changeset.base_authoritative_sequence).map_err(|_| {
                    CommitChangeSetError::Integrity(
                        "base authoritative sequence exceeds local storage range".to_owned(),
                    )
                })?,
                pending.previous_state.to_string(),
            ),
        )
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    if updated_state != 1 {
        return Err(CommitChangeSetError::BaseStateConflict);
    }
    let updated_changeset = transaction
        .execute(
            "UPDATE changesets SET lifecycle_status = 'committed'
             WHERE changeset_id = ?1 AND lifecycle_status = 'approved'",
            [command.changeset_id.to_string()],
        )
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    if updated_changeset != 1 {
        return Err(CommitChangeSetError::NotApproved);
    }
    Ok(())
}

fn replay_commit(
    connection: &Connection,
    command: &CommitChangeSetCommand,
    verified: &VerifiedCommitProposal,
) -> Result<CommittedChangeSet, CommitChangeSetError> {
    let persisted: Option<PersistedCommitRow> = connection
        .query_row(
            "SELECT idempotency_key, changeset_digest, validation_results_digest,
                    previous_state, resulting_state, authoritative_sequence,
                    committed_at, edit_count
             FROM changeset_commits WHERE changeset_id = ?1",
            [command.changeset_id.to_string()],
            |row| {
                Ok(PersistedCommitRow {
                    idempotency_key: row.get(0)?,
                    changeset_digest: row.get(1)?,
                    validation_results_digest: row.get(2)?,
                    previous_state: row.get(3)?,
                    resulting_state: row.get(4)?,
                    authoritative_sequence: row.get(5)?,
                    committed_at: row.get(6)?,
                    edit_count: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let persisted = persisted.ok_or(CommitChangeSetError::EvidenceMissing)?;
    if persisted.idempotency_key != command.idempotency_key.to_string() {
        return Err(CommitChangeSetError::IdempotencyKeyReused);
    }
    if persisted.changeset_digest != verified.changeset_digest.to_string()
        || persisted.validation_results_digest != verified.validation_results_digest.to_string()
    {
        return Err(CommitChangeSetError::Integrity(
            "persisted commit does not match exact approved ChangeSet evidence".to_owned(),
        ));
    }
    let previous_state = persisted
        .previous_state
        .parse::<ContentDigest>()
        .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
    let resulting_state = persisted
        .resulting_state
        .parse::<ContentDigest>()
        .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
    let authoritative_sequence = u64::try_from(persisted.authoritative_sequence).map_err(|_| {
        CommitChangeSetError::Integrity("authoritative sequence must be non-negative".to_owned())
    })?;
    let committed_at =
        persisted
            .committed_at
            .parse()
            .map_err(|error: proof_application::TimestampError| {
                CommitChangeSetError::Integrity(error.to_string())
            })?;
    let edit_count = u32::try_from(persisted.edit_count)
        .map_err(|_| CommitChangeSetError::Integrity("Edit count exceeds u32".to_owned()))?;
    if previous_state != verified.changeset.base_state
        || edit_count as usize != verified.changeset.edits.len()
    {
        return Err(CommitChangeSetError::Integrity(
            "persisted commit scope does not match the ChangeSet".to_owned(),
        ));
    }
    let expected_sequence = verified
        .changeset
        .base_authoritative_sequence
        .checked_add(u64::from(edit_count))
        .ok_or_else(|| {
            CommitChangeSetError::Integrity("authoritative sequence overflow".to_owned())
        })?;
    verify_edit_projections(connection, &verified.changeset, expected_sequence)
        .map_err(CommitChangeSetError::Integrity)?;
    let (_, reproduced_state) = reproducible_known_state_at(
        connection,
        verified.changeset.workspace_id,
        expected_sequence,
    )
    .map_err(CommitChangeSetError::Integrity)?;
    if authoritative_sequence != expected_sequence || resulting_state != reproduced_state {
        return Err(CommitChangeSetError::Integrity(
            "persisted commit result does not match reproducible authoritative state".to_owned(),
        ));
    }
    Ok(CommittedChangeSet {
        changeset_id: verified.changeset.changeset_id,
        workspace_id: verified.changeset.workspace_id,
        principal_id: verified.changeset.principal_id,
        changeset_digest: verified.changeset_digest,
        validation_results_digest: verified.validation_results_digest,
        previous_state,
        resulting_state,
        authoritative_sequence,
        committed_at,
        status: ChangeSetStatus::Committed,
        edit_count,
    })
}

struct EditionManifest {
    schema_set_digest: ContentDigest,
    object_set_digest: Option<ContentDigest>,
    manifest_json: String,
    edition_digest: ContentDigest,
}

#[expect(
    clippy::too_many_lines,
    reason = "Edition replay, content addressing, persistence, and result construction form one atomic operation"
)]
fn create_current_edition(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    command: &CreateEditionCommand,
) -> Result<Edition, CreateEditionError> {
    let (authoritative_sequence, state_digest) =
        reproducible_known_state(transaction, workspace_id)
            .map_err(CreateEditionError::Integrity)?;
    if authoritative_sequence == 0 {
        return Err(CreateEditionError::EmptyState);
    }
    if let Some(edition) = replay_edition_operation(
        transaction,
        workspace_id,
        principal_id,
        command.idempotency_key,
        state_digest,
    )? {
        return Ok(edition);
    }
    let existing_id: Option<String> = transaction
        .query_row(
            "SELECT edition_id FROM editions WHERE state_digest = ?1",
            [state_digest.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if let Some(existing_id) = existing_id {
        let edition_id = existing_id
            .parse::<EditionId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        record_edition_operation(
            transaction,
            workspace_id,
            principal_id,
            command.idempotency_key,
            state_digest,
            edition_id,
        )?;
        return load_edition(transaction, edition_id);
    }
    let schemas = load_edition_schemas(transaction, authoritative_sequence)?;
    let objects = load_edition_objects(transaction, authoritative_sequence)?;
    let changesets = load_edition_changesets(transaction, workspace_id, authoritative_sequence)?;
    let manifest = build_edition_manifest(
        workspace_id,
        authoritative_sequence,
        state_digest,
        &schemas,
        &objects,
        &changesets,
    )?;
    let stored_sequence = i64::try_from(authoritative_sequence).map_err(|_| {
        CreateEditionError::Integrity(
            "authoritative sequence exceeds local storage range".to_owned(),
        )
    })?;
    let schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if schema_version >= 9 {
        transaction
            .execute(
                "INSERT INTO editions (
                     edition_id, workspace_id, principal_id, authoritative_sequence,
                     state_digest, schema_set_digest, object_set_digest, edition_digest,
                     manifest_json, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                (
                    command.edition_id.to_string(),
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    stored_sequence,
                    state_digest.to_string(),
                    manifest.schema_set_digest.to_string(),
                    manifest.object_set_digest.map(|digest| digest.to_string()),
                    manifest.edition_digest.to_string(),
                    manifest.manifest_json.as_str(),
                    command.created_at.to_string(),
                ),
            )
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    } else {
        transaction
            .execute(
                "INSERT INTO editions (
                     edition_id, workspace_id, principal_id, authoritative_sequence,
                     state_digest, schema_set_digest, edition_digest, manifest_json, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                (
                    command.edition_id.to_string(),
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    stored_sequence,
                    state_digest.to_string(),
                    manifest.schema_set_digest.to_string(),
                    manifest.edition_digest.to_string(),
                    manifest.manifest_json.as_str(),
                    command.created_at.to_string(),
                ),
            )
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    }
    record_edition_operation(
        transaction,
        workspace_id,
        principal_id,
        command.idempotency_key,
        state_digest,
        command.edition_id,
    )?;
    Ok(Edition {
        edition_id: command.edition_id,
        workspace_id,
        principal_id,
        authoritative_sequence,
        state_digest,
        schema_set_digest: manifest.schema_set_digest,
        object_set_digest: manifest.object_set_digest,
        edition_digest: manifest.edition_digest,
        manifest_json: manifest.manifest_json,
        created_at: command.created_at,
        schemas,
        objects,
        changesets,
    })
}

fn replay_edition_operation(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
    state_digest: ContentDigest,
) -> Result<Option<Edition>, CreateEditionError> {
    let persisted: Option<(String, String)> = connection
        .query_row(
            "SELECT requested_state_digest, edition_id
             FROM edition_create_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                idempotency_key.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let Some((requested_state, edition_id)) = persisted else {
        return Ok(None);
    };
    if requested_state != state_digest.to_string() {
        return Err(CreateEditionError::IdempotencyKeyReused);
    }
    let edition_id = edition_id
        .parse::<EditionId>()
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    load_edition(connection, edition_id).map(Some)
}

fn record_edition_operation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
    state_digest: ContentDigest,
    edition_id: EditionId,
) -> Result<(), CreateEditionError> {
    transaction
        .execute(
            "INSERT INTO edition_create_operations (
                 workspace_id, principal_id, idempotency_key,
                 requested_state_digest, edition_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                idempotency_key.to_string(),
                state_digest.to_string(),
                edition_id.to_string(),
            ),
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "Edition loading reconstructs and verifies the complete immutable aggregate before returning it"
)]
fn load_edition(
    connection: &Connection,
    edition_id: EditionId,
) -> Result<Edition, CreateEditionError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let object_set_column = if schema_version >= 9 {
        "object_set_digest"
    } else {
        "NULL AS object_set_digest"
    };
    let persisted: (
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
    ) = connection
        .query_row(
            &format!(
                "SELECT workspace_id, principal_id, authoritative_sequence, state_digest,
                        schema_set_digest, {object_set_column}, edition_digest,
                        manifest_json, created_at
                 FROM editions WHERE edition_id = ?1"
            ),
            [edition_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let workspace_id = persisted
        .0
        .parse::<WorkspaceId>()
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    let principal_id = persisted
        .1
        .parse::<PrincipalId>()
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    let authoritative_sequence = u64::try_from(persisted.2)
        .map_err(|_| CreateEditionError::Integrity("invalid Edition sequence".to_owned()))?;
    let state_digest = persisted
        .3
        .parse::<ContentDigest>()
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    let schemas = load_edition_schemas(connection, authoritative_sequence)?;
    let objects = load_edition_objects(connection, authoritative_sequence)?;
    let changesets = load_edition_changesets(connection, workspace_id, authoritative_sequence)?;
    let expected = build_edition_manifest(
        workspace_id,
        authoritative_sequence,
        state_digest,
        &schemas,
        &objects,
        &changesets,
    )?;
    if persisted.4 != expected.schema_set_digest.to_string()
        || persisted.5 != expected.object_set_digest.map(|digest| digest.to_string())
        || persisted.6 != expected.edition_digest.to_string()
        || persisted.7 != expected.manifest_json
    {
        return Err(CreateEditionError::Integrity(
            "persisted Edition does not match its canonical manifest".to_owned(),
        ));
    }
    let (_, reproduced_state) =
        reproducible_known_state_at(connection, workspace_id, authoritative_sequence)
            .map_err(CreateEditionError::Integrity)?;
    if reproduced_state != state_digest {
        return Err(CreateEditionError::Integrity(
            "Edition Known State is not reproducible".to_owned(),
        ));
    }
    let created_at = persisted
        .8
        .parse()
        .map_err(|error: proof_application::TimestampError| {
            CreateEditionError::Integrity(error.to_string())
        })?;
    Ok(Edition {
        edition_id,
        workspace_id,
        principal_id,
        authoritative_sequence,
        state_digest,
        schema_set_digest: expected.schema_set_digest,
        object_set_digest: expected.object_set_digest,
        edition_digest: expected.edition_digest,
        manifest_json: expected.manifest_json,
        created_at,
        schemas,
        objects,
        changesets,
    })
}

fn load_edition_schemas(
    connection: &Connection,
    authoritative_sequence: u64,
) -> Result<Vec<EditionSchema>, CreateEditionError> {
    let mut statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_digest
             FROM schema_versions WHERE authoritative_sequence <= ?1
             ORDER BY schema_id, schema_version",
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(authoritative_sequence).map_err(|_| {
                CreateEditionError::Integrity("invalid Edition sequence".to_owned())
            })?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut schemas = Vec::new();
    for row in rows {
        let (schema_id, schema_version, document_digest) =
            row.map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        schemas.push(EditionSchema {
            schema_id: SchemaId::new(schema_id)
                .map_err(|error| CreateEditionError::Integrity(error.to_string()))?,
            schema_version: SchemaVersion::new(
                u32::try_from(schema_version).map_err(|_| {
                    CreateEditionError::Integrity("invalid Schema version".to_owned())
                })?,
            )
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?,
            document_digest: document_digest
                .parse::<ContentDigest>()
                .map_err(|error| CreateEditionError::Integrity(error.to_string()))?,
        });
    }
    Ok(schemas)
}

fn load_edition_objects(
    connection: &Connection,
    authoritative_sequence: u64,
) -> Result<Vec<EditionObject>, CreateEditionError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if schema_version < 9 {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest
             FROM object_revisions WHERE authoritative_sequence <= ?1
             ORDER BY object_id, revision",
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(authoritative_sequence).map_err(|_| {
                CreateEditionError::Integrity("invalid Edition sequence".to_owned())
            })?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut objects = Vec::new();
    for row in rows {
        let (
            raw_object_id,
            revision,
            schema_id,
            schema_version,
            lifecycle_state,
            content,
            persisted_digest,
        ) = row.map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        let object_id = raw_object_id
            .parse::<ObjectId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if object_id.to_string() != raw_object_id {
            return Err(CreateEditionError::Integrity(
                "invalid canonical Object identity".to_owned(),
            ));
        }
        let revision =
            ObjectRevision::new(u32::try_from(revision).map_err(|_| {
                CreateEditionError::Integrity("invalid Object revision".to_owned())
            })?)
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if revision != ObjectRevision::INITIAL || lifecycle_state != "active" {
            return Err(CreateEditionError::Integrity(
                "invalid Object metadata".to_owned(),
            ));
        }
        let schema_id = SchemaId::new(schema_id)
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let schema_version = SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| CreateEditionError::Integrity("invalid Schema version".to_owned()))?,
        )
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let value = parse_strict(content.as_bytes())
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let canonical = canonicalize(&value)
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let object_digest = persisted_digest
            .parse::<ContentDigest>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if !value.is_object()
            || canonical.as_str() != content
            || object_revision_digest(object_id, &schema_id, schema_version, &value)
                .map_err(|error| CreateEditionError::Integrity(error.to_string()))?
                != object_digest
        {
            return Err(CreateEditionError::Integrity(
                "Edition Object content failed digest verification".to_owned(),
            ));
        }
        objects.push(EditionObject {
            object_id,
            revision,
            schema_id,
            schema_version,
            lifecycle_state: ObjectLifecycleState::Active,
            object_digest,
        });
    }
    Ok(objects)
}

#[expect(
    clippy::too_many_lines,
    reason = "Edition ChangeSets are reconstructed with their evidence and authoritative projection links before inclusion"
)]
fn load_edition_changesets(
    connection: &Connection,
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
) -> Result<Vec<EditionChangeSet>, CreateEditionError> {
    let storage_schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, changeset_digest, workspace_id, principal_id,
                    authoritative_sequence, edit_count
             FROM changeset_commits
             WHERE authoritative_sequence <= ?1 ORDER BY authoritative_sequence",
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(authoritative_sequence).map_err(|_| {
                CreateEditionError::Integrity("invalid Edition sequence".to_owned())
            })?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut changesets = Vec::new();
    for row in rows {
        let (
            raw_changeset_id,
            persisted_digest,
            persisted_workspace_id,
            persisted_principal_id,
            commit_sequence,
            edit_count,
        ) = row.map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if changeset_id.to_string() != raw_changeset_id
            || persisted_workspace_id != workspace_id.to_string()
        {
            return Err(CreateEditionError::Integrity(
                "committed ChangeSet scope is not canonical".to_owned(),
            ));
        }
        let principal_id = persisted_principal_id
            .parse::<PrincipalId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if principal_id.to_string() != persisted_principal_id {
            return Err(CreateEditionError::Integrity(
                "committed Principal identity is not canonical".to_owned(),
            ));
        }
        let row = load_inspected_changeset(
            connection,
            changeset_id,
            workspace_id,
            principal_id,
            storage_schema_version,
        )
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let edits = load_inspected_edits(connection, changeset_id, storage_schema_version)
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let inspected = row
            .into_inspected(changeset_id, workspace_id, principal_id, edits)
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if inspected.status != ChangeSetStatus::Committed {
            return Err(CreateEditionError::Integrity(
                "Edition references a ChangeSet that is not committed".to_owned(),
            ));
        }
        let changeset_digest =
            changeset_digest_for(&inspected).map_err(CreateEditionError::Integrity)?;
        if persisted_digest != changeset_digest.to_string()
            || usize::try_from(edit_count).ok() != Some(inspected.edits.len())
        {
            return Err(CreateEditionError::Integrity(
                "committed ChangeSet does not match its canonical proposal".to_owned(),
            ));
        }
        let expected_commit_sequence = inspected
            .base_authoritative_sequence
            .checked_add(u64::try_from(inspected.edits.len()).map_err(|_| {
                CreateEditionError::Integrity("ChangeSet Edit count exceeds u64".to_owned())
            })?)
            .ok_or_else(|| {
                CreateEditionError::Integrity("authoritative sequence overflow".to_owned())
            })?;
        if u64::try_from(commit_sequence).ok() != Some(expected_commit_sequence) {
            return Err(CreateEditionError::Integrity(
                "committed ChangeSet sequence does not match its ordered Edits".to_owned(),
            ));
        }
        verify_edit_projections(connection, &inspected, authoritative_sequence)
            .map_err(CreateEditionError::Integrity)?;
        changesets.push(EditionChangeSet {
            changeset_id,
            changeset_digest,
        });
    }
    Ok(changesets)
}

fn verify_edit_projections(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    edition_sequence: u64,
) -> Result<(), String> {
    for edit in &changeset.edits {
        let expected_sequence = changeset
            .base_authoritative_sequence
            .checked_add(u64::from(edit.ordinal()))
            .ok_or_else(|| "authoritative sequence overflow".to_owned())?;
        if expected_sequence > edition_sequence {
            return Err("ChangeSet exceeds its authoritative boundary".to_owned());
        }
        let matches_projection = match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => connection
                .query_row(
                    "SELECT changeset_id = ?1 AND schema_id = ?2 AND schema_version = ?3
                            AND document_digest = ?4 AND authoritative_sequence = ?5
                     FROM schema_versions WHERE edit_id = ?6",
                    (
                        changeset.changeset_id.to_string(),
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                        edit.document_digest.to_string(),
                        i64::try_from(expected_sequence).map_err(|_| {
                            "authoritative sequence exceeds local storage range".to_owned()
                        })?,
                        edit.edit_id.to_string(),
                    ),
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?,
            InspectedChangeSetEdit::ObjectCreate(edit) => connection
                .query_row(
                    "SELECT changeset_id = ?1 AND object_id = ?2 AND revision = 1
                            AND schema_id = ?3 AND schema_version = ?4
                            AND lifecycle_state = 'active' AND object_digest = ?5
                            AND authoritative_sequence = ?6
                     FROM object_revisions WHERE edit_id = ?7",
                    (
                        changeset.changeset_id.to_string(),
                        edit.object_id.to_string(),
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                        edit.object_digest.to_string(),
                        i64::try_from(expected_sequence).map_err(|_| {
                            "authoritative sequence exceeds local storage range".to_owned()
                        })?,
                        edit.edit_id.to_string(),
                    ),
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|error| error.to_string())?,
        };
        if matches_projection != Some(true) {
            return Err("committed Edit does not match its authoritative projection".to_owned());
        }
    }
    Ok(())
}

fn build_edition_manifest(
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
    state_digest: ContentDigest,
    schemas: &[EditionSchema],
    objects: &[EditionObject],
    changesets: &[EditionChangeSet],
) -> Result<EditionManifest, CreateEditionError> {
    let schema_values: Vec<_> = schemas
        .iter()
        .map(|schema| {
            serde_json::json!({
                "document_digest": schema.document_digest.to_string(),
                "schema_id": schema.schema_id.as_str(),
                "schema_version": schema.schema_version.get(),
            })
        })
        .collect();
    let schema_set = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": schema_values,
    }))
    .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    let schema_set_digest = digest(ArtifactKind::SchemaSetV1, &schema_set);
    let object_references = objects
        .iter()
        .map(|object| ObjectStateReference {
            object_id: object.object_id,
            revision: object.revision,
            schema_id: object.schema_id.clone(),
            schema_version: object.schema_version,
            lifecycle_state: object.lifecycle_state,
            object_digest: object.object_digest,
        })
        .collect::<Vec<_>>();
    let object_values = object_references
        .iter()
        .map(|object| {
            serde_json::json!({
                "lifecycle_state": object.lifecycle_state.to_string(),
                "object_digest": object.object_digest.to_string(),
                "object_id": object.object_id.to_string(),
                "revision": object.revision.get(),
                "schema_id": object.schema_id.as_str(),
                "schema_version": object.schema_version.get(),
            })
        })
        .collect::<Vec<_>>();
    let object_set_digest = if object_references.is_empty() {
        None
    } else {
        Some(
            object_set_digest(&object_references)
                .map_err(|error| CreateEditionError::Integrity(error.to_string()))?,
        )
    };
    let changeset_values: Vec<_> = changesets
        .iter()
        .map(|changeset| {
            serde_json::json!({
                "changeset_digest": changeset.changeset_digest.to_string(),
                "changeset_id": changeset.changeset_id.to_string(),
            })
        })
        .collect();
    let mut manifest_value = serde_json::json!({
        "api_version": "proof.dev/edition/v1",
        "authoritative_sequence": authoritative_sequence,
        "changesets": changeset_values,
        "schema_set_digest": schema_set_digest.to_string(),
        "schemas": schema_values,
        "state_digest": state_digest.to_string(),
        "workspace_id": workspace_id.to_string(),
    });
    if let Some(object_set_digest) = object_set_digest {
        manifest_value["object_set_digest"] =
            serde_json::Value::String(object_set_digest.to_string());
        manifest_value["objects"] = serde_json::Value::Array(object_values);
    }
    let manifest = canonicalize(&manifest_value)
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    Ok(EditionManifest {
        schema_set_digest,
        object_set_digest,
        edition_digest: digest(ArtifactKind::EditionV1, &manifest),
        manifest_json: manifest.as_str().to_owned(),
    })
}

fn verified_edit_batch(edits: &[ChangeSetEdit]) -> Result<ContentDigest, AddChangeSetEditsError> {
    if edits.is_empty() || edits.len() > proof_application::MAX_EDITS_PER_BATCH {
        return Err(AddChangeSetEditsError::InvalidBatchSize);
    }
    let mut schema_targets = BTreeSet::new();
    let mut object_targets = BTreeSet::new();
    let mut manifest = Vec::with_capacity(edits.len());
    for edit in edits {
        match edit {
            ChangeSetEdit::SchemaCreate(edit) => {
                let value = parse_strict(edit.canonical_document.as_bytes())
                    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                let canonical = canonicalize(&value)
                    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                if canonical.as_str() != edit.canonical_document {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Schema document is not RFC 8785 canonical JSON".to_owned(),
                    ));
                }
                let Some(document) = value.as_object() else {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Schema document root must be a JSON object".to_owned(),
                    ));
                };
                if document.get("$schema").and_then(serde_json::Value::as_str)
                    != Some("https://json-schema.org/draft/2020-12/schema")
                {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Schema document must declare JSON Schema Draft 2020-12".to_owned(),
                    ));
                }
                let expected_digest = digest(ArtifactKind::SchemaVersionV1, &canonical);
                if expected_digest != edit.document_digest {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Schema document digest does not match canonical content".to_owned(),
                    ));
                }
                if !schema_targets.insert((edit.schema_id.clone(), edit.schema_version)) {
                    return Err(AddChangeSetEditsError::DuplicateTarget);
                }
                manifest.push(serde_json::json!({
                    "document_digest": edit.document_digest.to_string(),
                    "kind": "schema.create",
                    "schema_id": edit.schema_id.to_string(),
                    "schema_version": edit.schema_version.get(),
                }));
            }
            ChangeSetEdit::ObjectCreate(edit) => {
                let value = parse_strict(edit.canonical_content.as_bytes())
                    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                if !value.is_object() {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Object content root must be a JSON object".to_owned(),
                    ));
                }
                let canonical = canonicalize(&value)
                    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                if canonical.as_str() != edit.canonical_content {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Object content is not RFC 8785 canonical JSON".to_owned(),
                    ));
                }
                let expected_digest = object_revision_digest(
                    edit.object_id,
                    &edit.schema_id,
                    edit.schema_version,
                    &value,
                )
                .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                if expected_digest != edit.object_digest {
                    return Err(AddChangeSetEditsError::Integrity(
                        "Object revision digest does not match canonical content".to_owned(),
                    ));
                }
                if !object_targets.insert(edit.object_id) {
                    return Err(AddChangeSetEditsError::DuplicateTarget);
                }
                manifest.push(serde_json::json!({
                    "kind": "object.create",
                    "object_digest": edit.object_digest.to_string(),
                    "object_id": edit.object_id.to_string(),
                    "schema_id": edit.schema_id.to_string(),
                    "schema_version": edit.schema_version.get(),
                }));
            }
        }
    }
    let canonical = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/edit-batch/v1",
        "edits": manifest,
    }))
    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::EditBatchV1, &canonical))
}

fn require_editable_changeset(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    changeset_id: ChangeSetId,
    schema_version: u32,
) -> Result<(), AddChangeSetEditsError> {
    let status_column = if schema_version >= 5 {
        "lifecycle_status"
    } else {
        "status"
    };
    let status: Option<String> = connection
        .query_row(
            &format!(
                "SELECT {status_column} FROM changesets
                 WHERE changeset_id = ?1 AND workspace_id = ?2 AND principal_id = ?3"
            ),
            [
                changeset_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    match status.as_deref() {
        None => Err(AddChangeSetEditsError::NotFound),
        Some("draft") => Ok(()),
        Some(_) => Err(AddChangeSetEditsError::NotDraft),
    }
}

fn replay_edit_batch(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    changeset_id: ChangeSetId,
    idempotency_key: IdempotencyKey,
    request_digest: ContentDigest,
) -> Result<Option<AddedChangeSetEdits>, AddChangeSetEditsError> {
    let persisted: Option<(String, i64, i64, i64)> = connection
        .query_row(
            "SELECT request_digest, first_ordinal, added_count, total_edit_count
             FROM changeset_add_operations
             WHERE workspace_id = ?1 AND principal_id = ?2
               AND changeset_id = ?3 AND idempotency_key = ?4",
            [
                workspace_id.to_string(),
                principal_id.to_string(),
                changeset_id.to_string(),
                idempotency_key.to_string(),
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let Some((persisted_digest, first_ordinal, added_count, total_edit_count)) = persisted else {
        return Ok(None);
    };
    let persisted_digest = persisted_digest
        .parse::<ContentDigest>()
        .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
    if persisted_digest != request_digest {
        return Err(AddChangeSetEditsError::IdempotencyKeyReused);
    }
    let first_ordinal = positive_u32(first_ordinal, "first Edit ordinal")?;
    let added_count = positive_u32(added_count, "added Edit count")?;
    let total_edit_count = positive_u32(total_edit_count, "total Edit count")?;
    let final_ordinal = first_ordinal
        .checked_add(added_count - 1)
        .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit ordinal overflow".to_owned()))?;
    let mut statement = connection
        .prepare(
            "SELECT edit_id FROM changeset_edits
             WHERE changeset_id = ?1 AND ordinal BETWEEN ?2 AND ?3
             ORDER BY ordinal",
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let edit_ids = statement
        .query_map(
            (
                changeset_id.to_string(),
                i64::from(first_ordinal),
                i64::from(final_ordinal),
            ),
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?
        .map(|result| {
            result
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?
                .parse::<EditId>()
                .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if edit_ids.len() != usize::try_from(added_count).unwrap_or(usize::MAX) {
        return Err(AddChangeSetEditsError::Integrity(
            "idempotent Edit result is incomplete".to_owned(),
        ));
    }
    Ok(Some(AddedChangeSetEdits {
        changeset_id,
        workspace_id,
        principal_id,
        first_ordinal,
        edit_ids,
        total_edit_count,
    }))
}

fn positive_u32(value: i64, field: &str) -> Result<u32, AddChangeSetEditsError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AddChangeSetEditsError::Integrity(format!("{field} must be positive")))
}

fn reject_duplicate_targets(
    connection: &Connection,
    changeset_id: ChangeSetId,
    edits: &[ChangeSetEdit],
) -> Result<(), AddChangeSetEditsError> {
    for edit in edits {
        let exists: bool = match edit {
            ChangeSetEdit::SchemaCreate(edit) => connection
                .query_row(
                    "SELECT EXISTS (
                         SELECT 1 FROM changeset_edits
                         WHERE changeset_id = ?1 AND edit_kind = 'schema.create'
                           AND schema_id = ?2 AND schema_version = ?3
                     )",
                    (
                        changeset_id.to_string(),
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                    ),
                    |row| row.get(0),
                )
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?,
            ChangeSetEdit::ObjectCreate(edit) => connection
                .query_row(
                    "SELECT EXISTS (
                         SELECT 1 FROM changeset_edits
                         WHERE changeset_id = ?1 AND edit_kind = 'object.create'
                           AND object_id = ?2
                     )",
                    (changeset_id.to_string(), edit.object_id.to_string()),
                    |row| row.get(0),
                )
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?,
        };
        if exists {
            return Err(AddChangeSetEditsError::DuplicateTarget);
        }
    }
    Ok(())
}

fn count_changeset_edits(
    connection: &Connection,
    changeset_id: ChangeSetId,
) -> Result<u32, AddChangeSetEditsError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM changeset_edits WHERE changeset_id = ?1",
            [changeset_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    u32::try_from(count)
        .map_err(|_| AddChangeSetEditsError::Integrity("Edit count exceeds u32".to_owned()))
}

fn append_edit_batch(
    transaction: &Transaction<'_>,
    changeset_id: ChangeSetId,
    first_ordinal: u32,
    storage_schema_version: u32,
    edits: &[ChangeSetEdit],
) -> Result<(), AddChangeSetEditsError> {
    for (offset, edit) in edits.iter().enumerate() {
        let offset = u32::try_from(offset)
            .map_err(|_| AddChangeSetEditsError::Integrity("Edit offset exceeds u32".to_owned()))?;
        let ordinal = first_ordinal
            .checked_add(offset)
            .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit ordinal overflow".to_owned()))?;
        match edit {
            ChangeSetEdit::SchemaCreate(edit) => {
                let parameters = (
                    changeset_id.to_string(),
                    ordinal,
                    edit.edit_id.to_string(),
                    edit.schema_id.as_str(),
                    edit.schema_version.get(),
                    &edit.canonical_document,
                    edit.document_digest.to_string(),
                );
                if storage_schema_version >= 9 {
                    transaction.execute(
                        "INSERT INTO changeset_edits (
                             changeset_id, ordinal, edit_id, edit_kind, schema_id,
                             schema_version, object_id, document_json, document_digest
                         ) VALUES (?1, ?2, ?3, 'schema.create', ?4, ?5, NULL, ?6, ?7)",
                        parameters,
                    )
                } else {
                    transaction.execute(
                        "INSERT INTO changeset_edits (
                             changeset_id, ordinal, edit_id, edit_kind, schema_id,
                             schema_version, document_json, document_digest
                         ) VALUES (?1, ?2, ?3, 'schema.create', ?4, ?5, ?6, ?7)",
                        parameters,
                    )
                }
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?
            }
            ChangeSetEdit::ObjectCreate(edit) => transaction
                .execute(
                    "INSERT INTO changeset_edits (
                         changeset_id, ordinal, edit_id, edit_kind, schema_id,
                         schema_version, object_id, document_json, document_digest
                     ) VALUES (?1, ?2, ?3, 'object.create', ?4, ?5, ?6, ?7, ?8)",
                    (
                        changeset_id.to_string(),
                        ordinal,
                        edit.edit_id.to_string(),
                        edit.schema_id.as_str(),
                        edit.schema_version.get(),
                        edit.object_id.to_string(),
                        &edit.canonical_content,
                        edit.object_digest.to_string(),
                    ),
                )
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?,
        };
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the operation record binds its full authentication and result scope"
)]
fn record_edit_batch(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    command: &AddChangeSetEditsCommand,
    request_digest: ContentDigest,
    first_ordinal: u32,
    added_count: u32,
    total_edit_count: u32,
) -> Result<(), AddChangeSetEditsError> {
    transaction
        .execute(
            "INSERT INTO changeset_add_operations (
                 workspace_id, principal_id, changeset_id, idempotency_key,
                 request_digest, first_ordinal, added_count, total_edit_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.changeset_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                first_ordinal,
                added_count,
                total_edit_count,
            ),
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    Ok(())
}

fn verified_known_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(u64, ContentDigest), CreateChangeSetError> {
    reproducible_known_state(connection, workspace_id).map_err(CreateChangeSetError::Integrity)
}

fn reproducible_known_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(u64, ContentDigest), String> {
    let (sequence, persisted_digest): (i64, String) = connection
        .query_row(
            "SELECT authoritative_sequence, state_digest
             FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    let sequence = u64::try_from(sequence)
        .map_err(|_| "authoritative sequence must be non-negative".to_owned())?;
    let persisted_digest = persisted_digest
        .parse::<ContentDigest>()
        .map_err(|error| error.to_string())?;
    let (_, expected_digest) = reproducible_known_state_at(connection, workspace_id, sequence)?;
    if persisted_digest != expected_digest {
        return Err(
            "Known State digest does not match reproducible authoritative state".to_owned(),
        );
    }
    if sequence > 0 {
        load_edition_changesets(connection, workspace_id, sequence)
            .map_err(|error| error.to_string())?;
    }
    Ok((sequence, persisted_digest))
}

#[expect(
    clippy::too_many_lines,
    reason = "Known State reproduction verifies both authoritative projections and their shared sequence in one pass"
)]
fn reproducible_known_state_at(
    connection: &Connection,
    workspace_id: WorkspaceId,
    sequence: u64,
) -> Result<(u64, ContentDigest), String> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if schema_version < 7 {
        if sequence != 0 {
            return Err(
                "authoritative state exists without the required Schema projection".to_owned(),
            );
        }
        return initial_known_state_digest(workspace_id)
            .map(|digest| (sequence, digest))
            .map_err(|error| error.to_string());
    }
    let mut statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_json, document_digest,
                    authoritative_sequence
             FROM schema_versions WHERE authoritative_sequence <= ?1
             ORDER BY schema_id, schema_version",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence)
                .map_err(|_| "authoritative sequence exceeds local storage range".to_owned())?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(|error| error.to_string())?;
    let mut schemas = Vec::new();
    let mut sequences = Vec::new();
    for row in rows {
        let (schema_id, schema_version, document, document_digest, record_sequence) =
            row.map_err(|error| error.to_string())?;
        let schema_id = SchemaId::new(schema_id).map_err(|error| error.to_string())?;
        let schema_version = SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| "Schema version must be positive".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        let document_digest = document_digest
            .parse::<ContentDigest>()
            .map_err(|error| error.to_string())?;
        let canonical = parse_strict(document.as_bytes())
            .and_then(|value| canonicalize(&value))
            .map_err(|error| error.to_string())?;
        if canonical.as_str() != document
            || digest(ArtifactKind::SchemaVersionV1, &canonical) != document_digest
        {
            return Err("authoritative Schema content failed digest verification".to_owned());
        }
        schemas.push((schema_id, schema_version, document_digest));
        sequences.push(
            u64::try_from(record_sequence)
                .map_err(|_| "authoritative sequence must be positive".to_owned())?,
        );
    }
    let mut objects = Vec::new();
    if schema_version >= 9 {
        let mut statement = connection
            .prepare(
                "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                        content_json, object_digest, authoritative_sequence
                 FROM object_revisions WHERE authoritative_sequence <= ?1
                 ORDER BY object_id, revision",
            )
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map(
                [i64::try_from(sequence).map_err(|_| {
                    "authoritative sequence exceeds local storage range".to_owned()
                })?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .map_err(|error| error.to_string())?;
        for row in rows {
            let (
                raw_object_id,
                revision,
                schema_id,
                schema_version,
                lifecycle_state,
                content,
                persisted_digest,
                record_sequence,
            ) = row.map_err(|error| error.to_string())?;
            let object_id = raw_object_id
                .parse::<ObjectId>()
                .map_err(|error| error.to_string())?;
            if object_id.to_string() != raw_object_id {
                return Err("authoritative Object identity is not canonical".to_owned());
            }
            let revision = ObjectRevision::new(
                u32::try_from(revision)
                    .map_err(|_| "Object revision must be positive".to_owned())?,
            )
            .map_err(|error| error.to_string())?;
            if revision != ObjectRevision::INITIAL || lifecycle_state != "active" {
                return Err("authoritative Object metadata is unsupported".to_owned());
            }
            let schema_id = SchemaId::new(schema_id).map_err(|error| error.to_string())?;
            let schema_version = SchemaVersion::new(
                u32::try_from(schema_version)
                    .map_err(|_| "Schema version must be positive".to_owned())?,
            )
            .map_err(|error| error.to_string())?;
            let value = parse_strict(content.as_bytes()).map_err(|error| error.to_string())?;
            if !value.is_object() {
                return Err("authoritative Object content must be a JSON object".to_owned());
            }
            let canonical = canonicalize(&value).map_err(|error| error.to_string())?;
            let persisted_digest = persisted_digest
                .parse::<ContentDigest>()
                .map_err(|error| error.to_string())?;
            if canonical.as_str() != content
                || object_revision_digest(object_id, &schema_id, schema_version, &value)
                    .map_err(|error| error.to_string())?
                    != persisted_digest
            {
                return Err("authoritative Object content failed digest verification".to_owned());
            }
            objects.push(ObjectStateReference {
                object_id,
                revision,
                schema_id,
                schema_version,
                lifecycle_state: ObjectLifecycleState::Active,
                object_digest: persisted_digest,
            });
            sequences.push(
                u64::try_from(record_sequence)
                    .map_err(|_| "authoritative sequence must be positive".to_owned())?,
            );
        }
    }
    sequences.sort_unstable();
    if sequences.len()
        != usize::try_from(sequence)
            .map_err(|_| "authoritative sequence exceeds addressable local state".to_owned())?
        || sequences
            .iter()
            .enumerate()
            .any(|(index, actual)| *actual != u64::try_from(index + 1).unwrap_or(u64::MAX))
    {
        return Err("authoritative sequences are incomplete or non-contiguous".to_owned());
    }
    known_state_digest_with_objects(workspace_id, sequence, &schemas, &objects)
        .map(|digest| (sequence, digest))
        .map_err(|error| error.to_string())
}

fn insert_draft(
    transaction: &Transaction<'_>,
    command: &CreateChangeSetCommand,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    base_authoritative_sequence: u64,
    base_state: ContentDigest,
    requested_base_state: Option<&str>,
) -> Result<(), CreateChangeSetError> {
    let base_authoritative_sequence = i64::try_from(base_authoritative_sequence).map_err(|_| {
        CreateChangeSetError::Integrity(
            "authoritative sequence exceeds local storage range".to_owned(),
        )
    })?;
    transaction
        .execute(
            "INSERT INTO changesets (
                 changeset_id, workspace_id, principal_id, intent,
                 requested_base_state, base_authoritative_sequence, base_state,
                 idempotency_key, created_at, status, policy_profile,
                 validation_profile
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            (
                command.changeset_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                command.intent.as_str(),
                requested_base_state,
                base_authoritative_sequence,
                base_state.to_string(),
                command.idempotency_key.to_string(),
                command.created_at.to_string(),
                ChangeSetStatus::Draft.to_string(),
                LOCAL_POLICY_PROFILE,
                LOCAL_VALIDATION_PROFILE,
            ),
        )
        .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
    Ok(())
}

struct PersistedDraft {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    intent: String,
    requested_base_state: Option<String>,
    base_authoritative_sequence: i64,
    base_state: String,
    idempotency_key: String,
    created_at: String,
    status: String,
    policy_profile: String,
    validation_profile: String,
}

impl PersistedDraft {
    fn into_draft(self) -> Result<DraftChangeSet, CreateChangeSetError> {
        if self.status != ChangeSetStatus::Draft.to_string()
            || self.policy_profile != LOCAL_POLICY_PROFILE
            || self.validation_profile != LOCAL_VALIDATION_PROFILE
        {
            return Err(CreateChangeSetError::Integrity(
                "persisted ChangeSet contract fields are unsupported".to_owned(),
            ));
        }
        Ok(DraftChangeSet {
            changeset_id: parse_changeset_field(&self.changeset_id, "ChangeSet identity")?,
            workspace_id: parse_changeset_field(&self.workspace_id, "Workspace identity")?,
            principal_id: parse_changeset_field(&self.principal_id, "Principal identity")?,
            intent: ChangeSetIntent::new(self.intent)
                .map_err(|error| CreateChangeSetError::Integrity(error.to_string()))?,
            base_authoritative_sequence: u64::try_from(self.base_authoritative_sequence).map_err(
                |_| {
                    CreateChangeSetError::Integrity(
                        "base authoritative sequence must be non-negative".to_owned(),
                    )
                },
            )?,
            base_state: parse_changeset_field(&self.base_state, "base state digest")?,
            idempotency_key: parse_changeset_field(&self.idempotency_key, "idempotency key")?,
            created_at: parse_changeset_field(&self.created_at, "creation timestamp")?,
            status: ChangeSetStatus::Draft,
            policy_profile: self.policy_profile,
            validation_profile: self.validation_profile,
            edit_count: 0,
        })
    }
}

fn parse_changeset_field<T>(value: &str, field: &str) -> Result<T, CreateChangeSetError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse::<T>().map_err(|error| {
        CreateChangeSetError::Integrity(format!("invalid persisted {field}: {error}"))
    })
}

fn find_idempotent_draft(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
) -> Result<Option<PersistedDraft>, CreateChangeSetError> {
    connection
        .query_row(
            "SELECT changeset_id, workspace_id, principal_id, intent,
                    requested_base_state, base_authoritative_sequence, base_state,
                    idempotency_key, created_at, status, policy_profile,
                    validation_profile
             FROM changesets
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            [
                workspace_id.to_string(),
                principal_id.to_string(),
                idempotency_key.to_string(),
            ],
            |row| {
                Ok(PersistedDraft {
                    changeset_id: row.get(0)?,
                    workspace_id: row.get(1)?,
                    principal_id: row.get(2)?,
                    intent: row.get(3)?,
                    requested_base_state: row.get(4)?,
                    base_authoritative_sequence: row.get(5)?,
                    base_state: row.get(6)?,
                    idempotency_key: row.get(7)?,
                    created_at: row.get(8)?,
                    status: row.get(9)?,
                    policy_profile: row.get(10)?,
                    validation_profile: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|error| CreateChangeSetError::Storage(error.to_string()))
}

fn authenticated_principal(
    connection: &Connection,
    principal_id: &str,
    local_identity: &LocalIdentity,
) -> Result<PrincipalId, WorkspaceStatusError> {
    let parsed_principal_id = principal_id
        .parse::<PrincipalId>()
        .map_err(|error| WorkspaceStatusError::Integrity(error.to_string()))?;
    let (principal_type, identity_provider, identity_subject, enabled): (
        String,
        String,
        String,
        i64,
    ) = connection
        .query_row(
            "SELECT principal_type, identity_provider, identity_subject, enabled
             FROM principals WHERE principal_id = ?1",
            [principal_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
    if principal_type != PrincipalType::Human.to_string() {
        return Err(WorkspaceStatusError::Integrity(
            "bootstrap Principal must have type human".to_owned(),
        ));
    }
    if enabled != 1
        || identity_provider != local_identity.provider
        || identity_subject != local_identity.subject
    {
        return Err(WorkspaceStatusError::Unauthenticated);
    }
    Ok(parsed_principal_id)
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "all platform identity adapters share one fallible contract"
)]
fn current_local_identity() -> Result<LocalIdentity, WorkspaceInitializationError> {
    Ok(LocalIdentity {
        provider: "os/unix",
        subject: format!("uid:{}", rustix::process::geteuid().as_raw()),
    })
}

#[cfg(not(unix))]
fn current_local_identity() -> Result<LocalIdentity, WorkspaceInitializationError> {
    Err(WorkspaceInitializationError::IdentityUnavailable(
        "this build does not provide a local identity adapter for the current platform".to_owned(),
    ))
}

struct InitializationCleanup {
    runtime_path: Option<PathBuf>,
    temporary_config: Option<PathBuf>,
    committed_config: Option<PathBuf>,
}

impl InitializationCleanup {
    fn new(runtime_path: PathBuf) -> Self {
        Self {
            runtime_path: Some(runtime_path),
            temporary_config: None,
            committed_config: None,
        }
    }

    fn track_temporary_config(&mut self, path: PathBuf) {
        self.temporary_config = Some(path);
    }

    fn clear_temporary_config(&mut self) {
        self.temporary_config = None;
    }

    fn track_committed_config(&mut self, path: PathBuf) {
        self.committed_config = Some(path);
    }

    fn commit(&mut self) {
        self.runtime_path = None;
        self.temporary_config = None;
        self.committed_config = None;
    }
}

impl Drop for InitializationCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.temporary_config {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = &self.committed_config {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = &self.runtime_path {
            let _ = fs::remove_dir_all(path);
        }
    }
}
