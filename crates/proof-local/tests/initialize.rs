use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    InitializeWorkspaceCommand, PrincipalId, WorkspaceId, WorkspaceInitializationError,
    WorkspaceStatus, WorkspaceStatusError, initialize_workspace, workspace_status,
};
use proof_canonical::initial_known_state_digest;
use proof_local::LocalWorkspace;

const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";
const OTHER_WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000011";
const PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000020";
const OTHER_PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000021";

#[test]
fn initialization_creates_config_private_layout_and_sqlite_metadata() {
    let directory = TestDirectory::new();
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
    let principal_id = PRINCIPAL_ID.parse::<PrincipalId>().unwrap();

    let initialized = initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id,
            bootstrap_principal_id: principal_id,
        },
    )
    .unwrap();

    assert_eq!(initialized.workspace_id, workspace_id);
    assert_eq!(initialized.principal_id, principal_id);
    assert!(repository.runtime_path().join("cache").is_dir());
    assert!(repository.runtime_path().join("state").is_dir());
    assert!(repository.runtime_path().join("artifacts").is_dir());
    assert!(repository.database_path().is_file());

    let config = repository.read_config().unwrap();
    assert_eq!(config.api_version, "proof.dev/workspace/v1");
    assert_eq!(config.workspace_id, WORKSPACE_ID);
    assert_eq!(config.storage.mode, "local");
    assert_eq!(config.storage.database, ".proof/state/proof.db");
    assert_eq!(config.storage.artifacts, ".proof/artifacts");
    let config_text = fs::read_to_string(repository.config_path()).unwrap();
    assert!(!config_text.contains(PRINCIPAL_ID));
    assert!(!config_text.contains("os/unix"));
    assert!(!config_text.contains("uid:"));

    let connection = repository.open_database().unwrap();
    let (persisted_id, persisted_principal_id): (String, String) = connection
        .query_row(
            "SELECT workspace_id, bootstrap_principal_id
             FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let (principal_type, identity_provider, identity_subject, enabled): (
        String,
        String,
        String,
        i64,
    ) = connection
        .query_row(
            "SELECT principal_type, identity_provider, identity_subject, enabled
             FROM principals WHERE principal_id = ?1",
            [PRINCIPAL_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let schema_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let migration_name: String = connection
        .query_row(
            "SELECT name FROM schema_migrations WHERE version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let (authoritative_sequence, state_digest): (i64, String) = connection
        .query_row(
            "SELECT authoritative_sequence, state_digest FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();

    assert_eq!(persisted_id, WORKSPACE_ID);
    assert_eq!(persisted_principal_id, PRINCIPAL_ID);
    assert_eq!(principal_type, "human");
    assert_eq!(identity_provider, "os/unix");
    assert_eq!(
        identity_subject,
        format!("uid:{}", rustix::process::geteuid().as_raw())
    );
    assert_eq!(enabled, 1);
    assert_eq!(foreign_keys, 1);
    assert_eq!(journal_mode, "wal");
    assert_eq!(schema_version, 1);
    assert_eq!(migration_name, "initialize-local-workspace");
    assert_eq!(authoritative_sequence, 0);
    assert_eq!(
        state_digest,
        initial_known_state_digest(workspace_id)
            .unwrap()
            .to_string()
    );

    #[cfg(unix)]
    assert_private_permissions(&repository);
}

#[test]
fn repeated_initialization_conflicts_without_changing_the_workspace() {
    let directory = TestDirectory::new();
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap();
    let config_before = fs::read(repository.config_path()).unwrap();

    let error = initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: OTHER_WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: OTHER_PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap_err();

    assert_eq!(error, WorkspaceInitializationError::AlreadyExists);
    assert_eq!(fs::read(repository.config_path()).unwrap(), config_before);
    assert_eq!(repository.read_config().unwrap().workspace_id, WORKSPACE_ID);
}

#[test]
fn existing_configuration_is_never_overwritten() {
    let directory = TestDirectory::new();
    let config_path = directory.path().join("proof.toml");
    fs::write(&config_path, b"owned-by-user = true\n").unwrap();
    let repository = LocalWorkspace::new(directory.path()).unwrap();

    let error = initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap_err();

    assert_eq!(error, WorkspaceInitializationError::AlreadyExists);
    assert_eq!(fs::read(&config_path).unwrap(), b"owned-by-user = true\n");
    assert!(!repository.runtime_path().exists());
}

#[test]
fn missing_workspace_root_is_rejected() {
    let directory = TestDirectory::new();
    let missing = directory.path().join("missing");

    assert!(matches!(
        LocalWorkspace::new(missing),
        Err(WorkspaceInitializationError::RootUnavailable(_))
    ));
}

#[test]
fn unsafe_storage_paths_in_configuration_are_rejected() {
    let directory = TestDirectory::new();
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap();
    let config = fs::read_to_string(repository.config_path()).unwrap();
    fs::write(
        repository.config_path(),
        config.replace(".proof/state/proof.db", "../../outside.db"),
    )
    .unwrap();

    assert!(matches!(
        repository.read_config(),
        Err(WorkspaceInitializationError::Storage(_))
    ));
}

#[test]
fn status_distinguishes_uninitialized_and_verified_workspaces() {
    let directory = TestDirectory::new();
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    assert_eq!(
        workspace_status(&repository).unwrap(),
        WorkspaceStatus::Uninitialized
    );
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap();

    let WorkspaceStatus::Initialized(status) = workspace_status(&repository).unwrap() else {
        panic!("initialized Workspace must return verified status");
    };
    assert_eq!(status.workspace_id.to_string(), WORKSPACE_ID);
    assert_eq!(status.principal_id.to_string(), PRINCIPAL_ID);
    assert_eq!(status.storage_schema_version, 1);
    assert_eq!(status.authoritative_sequence, 0);
    assert_eq!(
        status.state_digest,
        initial_known_state_digest(status.workspace_id).unwrap()
    );
}

#[test]
fn partial_workspace_layout_fails_closed() {
    let directory = TestDirectory::new();
    fs::create_dir(directory.path().join(".proof")).unwrap();
    let repository = LocalWorkspace::new(directory.path()).unwrap();

    assert_eq!(
        workspace_status(&repository).unwrap_err(),
        WorkspaceStatusError::Incomplete
    );
}

#[test]
fn mismatched_workspace_identities_fail_integrity_verification() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE workspace_metadata SET workspace_id = ?1 WHERE singleton = 1",
            [OTHER_WORKSPACE_ID],
        )
        .unwrap();

    assert!(matches!(
        workspace_status(&repository),
        Err(WorkspaceStatusError::Integrity(_))
    ));
}

#[test]
fn altered_known_state_digest_fails_integrity_verification() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE known_state SET state_digest = ?1 WHERE singleton = 1",
            [format!("blake3:{}", "00".repeat(32))],
        )
        .unwrap();

    assert!(matches!(
        workspace_status(&repository),
        Err(WorkspaceStatusError::Integrity(_))
    ));
}

#[test]
fn mismatched_local_identity_fails_authentication() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE principals SET identity_subject = 'uid:identity-mismatch'",
            [],
        )
        .unwrap();

    assert_eq!(
        workspace_status(&repository).unwrap_err(),
        WorkspaceStatusError::Unauthenticated
    );
}

#[test]
fn disabled_bootstrap_principal_fails_authentication() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    repository
        .open_database()
        .unwrap()
        .execute("UPDATE principals SET enabled = 0", [])
        .unwrap();

    assert_eq!(
        workspace_status(&repository).unwrap_err(),
        WorkspaceStatusError::Unauthenticated
    );
}

#[test]
fn altered_journal_mode_is_detected_without_repairing_it() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let connection = repository.open_database().unwrap();
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .unwrap();
    drop(connection);

    assert!(matches!(
        workspace_status(&repository),
        Err(WorkspaceStatusError::Integrity(_))
    ));
    let connection = rusqlite::Connection::open(repository.database_path()).unwrap();
    let journal_mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode, "delete");
}

fn initialized_repository(directory: &TestDirectory) -> LocalWorkspace {
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse().unwrap(),
        },
    )
    .unwrap();
    repository
}

#[cfg(unix)]
fn assert_private_permissions(repository: &LocalWorkspace) {
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        fs::metadata(repository.runtime_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(repository.database_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-local-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
