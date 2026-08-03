#![forbid(unsafe_code)]

//! Local filesystem and `SQLite` adapters for Proof.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use proof_application::{
    ContentDigest, InitializeWorkspaceCommand, InitializedWorkspace, InitializedWorkspaceStatus,
    PrincipalId, PrincipalType, WorkspaceId, WorkspaceInitializationError, WorkspaceRepository,
    WorkspaceStatus, WorkspaceStatusError, WorkspaceStatusRepository,
};
use proof_canonical::initial_known_state_digest;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

const CONFIG_API_VERSION: &str = "proof.dev/workspace/v1";
const CONFIG_FILE: &str = "proof.toml";
const RUNTIME_DIRECTORY: &str = ".proof";
const DATABASE_RELATIVE_PATH: &str = ".proof/state/proof.db";
const ARTIFACTS_RELATIVE_PATH: &str = ".proof/artifacts";

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

        let (authoritative_sequence, persisted_digest): (i64, String) = connection
            .query_row(
                "SELECT authoritative_sequence, state_digest
                 FROM known_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| WorkspaceStatusError::Storage(error.to_string()))?;
        let authoritative_sequence = u64::try_from(authoritative_sequence).map_err(|_| {
            WorkspaceStatusError::Integrity(
                "authoritative sequence must be non-negative".to_owned(),
            )
        })?;
        if authoritative_sequence != 0 {
            return Err(WorkspaceStatusError::Integrity(
                "non-empty authoritative state is not supported by this build".to_owned(),
            ));
        }
        let persisted_digest = persisted_digest
            .parse::<ContentDigest>()
            .map_err(|error| WorkspaceStatusError::Integrity(error.to_string()))?;
        let expected_digest = initial_known_state_digest(configured_id)
            .map_err(|error| WorkspaceStatusError::Integrity(error.to_string()))?;
        if persisted_digest != expected_digest {
            return Err(WorkspaceStatusError::Integrity(
                "Known State digest does not match the reproducible initial state".to_owned(),
            ));
        }

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
        .execute_batch(
            "CREATE TABLE schema_migrations (
                 version INTEGER PRIMARY KEY CHECK (version > 0),
                 name TEXT NOT NULL UNIQUE
             ) STRICT;
             INSERT INTO schema_migrations (version, name)
             VALUES (1, 'initialize-local-workspace');
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
             PRAGMA user_version = 1;",
        )
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
             ) VALUES (1, ?1, ?2, 1)",
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
