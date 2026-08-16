use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, ApprovalName, ApproveChangeSetCommand,
    ApproveChangeSetError, ArtifactKind, ChangeSetEdit, ChangeSetId, ChangeSetIntent,
    CommitChangeSetCommand, CommitChangeSetError, ContentDigest, CreateChangeSetCommand,
    CreateChangeSetError, CreateEditionCommand, CreateEditionError, EditId, EditionId,
    IdempotencyKey, InitializeWorkspaceCommand, InspectChangeSetError, InspectedChangeSetEdit,
    ObjectCreateEdit, ObjectId, PrincipalId, SchemaCreateEdit, SchemaId, SchemaVersion, Severity,
    SubmitChangeSetCommand, SubmitChangeSetError, Timestamp, WorkspaceId,
    WorkspaceInitializationError, WorkspaceStatus, WorkspaceStatusError, add_changeset_edits,
    approve_changeset, commit_changeset, create_changeset, create_edition, initialize_workspace,
    inspect_changeset, submit_changeset, validate_changeset, workspace_status,
};
use proof_canonical::{canonicalize, digest, initial_known_state_digest, object_revision_digest};
use proof_local::LocalWorkspace;

const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";
const OTHER_WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000011";
const PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000020";
const OTHER_PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000021";
const CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000030";
const OTHER_CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000031";
const IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000040";
const ADD_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000041";
const OTHER_ADD_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000042";
const COMMIT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000043";
const OTHER_COMMIT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000044";
const EDIT_ID: &str = "019c0000-0000-7000-8000-000000000050";
const OTHER_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000051";
const OBJECT_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000052";
const OTHER_OBJECT_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000053";
const OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000080";
const EDITION_ID: &str = "019c0000-0000-7000-8000-000000000060";
const OTHER_EDITION_ID: &str = "019c0000-0000-7000-8000-000000000061";
const EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000070";
const OTHER_EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000071";
const CREATED_AT: &str = "2026-08-03T14:00:00Z";

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
    #[cfg(unix)]
    assert_eq!(identity_provider, "os/unix");
    #[cfg(unix)]
    assert_eq!(
        identity_subject,
        format!("uid:{}", rustix::process::geteuid().as_raw())
    );
    #[cfg(not(unix))]
    let _ = (identity_provider, identity_subject);
    assert_eq!(enabled, 1);
    assert_eq!(foreign_keys, 1);
    assert_eq!(journal_mode, "wal");
    assert_eq!(schema_version, 9);
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
    assert_eq!(status.storage_schema_version, 9);
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
fn draft_changeset_is_bound_to_principal_intent_and_known_state() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let expected_state = initial_known_state_digest(WORKSPACE_ID.parse().unwrap()).unwrap();

    let draft = create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "  Publish the launch article  ", None),
    )
    .unwrap();

    assert_eq!(draft.changeset_id.to_string(), CHANGESET_ID);
    assert_eq!(draft.workspace_id.to_string(), WORKSPACE_ID);
    assert_eq!(draft.principal_id.to_string(), PRINCIPAL_ID);
    assert_eq!(draft.intent.as_str(), "Publish the launch article");
    assert_eq!(draft.base_authoritative_sequence, 0);
    assert_eq!(draft.base_state, expected_state);
    assert_eq!(draft.idempotency_key.to_string(), IDEMPOTENCY_KEY);
    assert_eq!(draft.created_at.to_string(), CREATED_AT);
    assert_eq!(draft.status.to_string(), "draft");
    assert_eq!(draft.policy_profile, "proof.local/policy/default/v1");
    assert_eq!(
        draft.validation_profile,
        "proof.local/validation/default/v1"
    );
    assert_eq!(draft.edit_count, 0);

    let connection = repository.open_database().unwrap();
    let persisted: (String, String, String, i64, String) = connection
        .query_row(
            "SELECT workspace_id, principal_id, intent,
                    base_authoritative_sequence, base_state
             FROM changesets WHERE changeset_id = ?1",
            [CHANGESET_ID],
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
        .unwrap();
    assert_eq!(persisted.0, WORKSPACE_ID);
    assert_eq!(persisted.1, PRINCIPAL_ID);
    assert_eq!(persisted.2, "Publish the launch article");
    assert_eq!(persisted.3, 0);
    assert_eq!(persisted.4, expected_state.to_string());
}

#[test]
fn stale_requested_base_state_rejects_without_persisting_a_draft() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let stale = format!("blake3:{}", "00".repeat(32))
        .parse::<ContentDigest>()
        .unwrap();

    let error = create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Publish the launch article", Some(stale)),
    )
    .unwrap_err();

    assert_eq!(error, CreateChangeSetError::BaseStateConflict);
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changesets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn changeset_creation_is_idempotent_and_rejects_key_reuse() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let first = create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Publish the launch article", None),
    )
    .unwrap();
    let replay = create_changeset(
        &repository,
        draft_command(OTHER_CHANGESET_ID, "Publish the launch article", None),
    )
    .unwrap();

    assert_eq!(replay, first);
    let error = create_changeset(
        &repository,
        draft_command(OTHER_CHANGESET_ID, "Different intent", None),
    )
    .unwrap_err();
    assert_eq!(error, CreateChangeSetError::IdempotencyKeyReused);
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changesets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn draft_creation_migrates_a_verified_version_one_workspace_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DROP TABLE changeset_submissions;
             DROP TABLE changeset_validations;
             DROP TABLE changeset_add_operations;
             DROP TABLE changeset_edits;
             DROP TABLE changesets;
             DELETE FROM schema_migrations WHERE version >= 2;
             UPDATE workspace_metadata SET schema_version = 1 WHERE singleton = 1;
             PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(connection);

    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Publish the launch article", None),
    )
    .unwrap();

    let connection = repository.open_database().unwrap();
    let metadata_version: u32 = connection
        .query_row(
            "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let pragma_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(metadata_version, 2);
    assert_eq!(pragma_version, 2);
}

#[test]
fn schema_create_edits_append_atomically_in_declared_order() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let edits = vec![
        schema_edit(EDIT_ID, "article", 1, "Article"),
        schema_edit(OTHER_EDIT_ID, "cta", 1, "Call to action"),
    ];

    let added = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits,
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(added.first_ordinal, 1);
    assert_eq!(added.total_edit_count, 2);
    assert_eq!(added.edit_ids[0].to_string(), EDIT_ID);
    assert_eq!(added.edit_ids[1].to_string(), OTHER_EDIT_ID);
    let connection = repository.open_database().unwrap();
    let rows: Vec<(i64, String, String)> = {
        let mut statement = connection
            .prepare(
                "SELECT ordinal, schema_id, document_json FROM changeset_edits ORDER BY ordinal",
            )
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    assert_eq!(rows[0].0, 1);
    assert_eq!(rows[0].1, "article");
    assert!(rows[0].2.starts_with("{\"$schema\":"));
    assert_eq!(rows[1].0, 2);
    assert_eq!(rows[1].1, "cta");
}

#[test]
fn edit_batch_retries_return_original_ids_and_reject_changed_input() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let add = |edit: ChangeSetEdit| {
        add_changeset_edits(
            &repository,
            AddChangeSetEditsCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                edits: vec![edit],
                idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
            },
        )
    };
    let first = add(schema_edit(EDIT_ID, "article", 1, "Article")).unwrap();
    let replay = add(schema_edit(OTHER_EDIT_ID, "article", 1, "Article")).unwrap();
    assert_eq!(replay, first);

    let error = add(schema_edit(OTHER_EDIT_ID, "cta", 1, "CTA")).unwrap_err();
    assert_eq!(error, AddChangeSetEditsError::IdempotencyKeyReused);
}

#[test]
fn duplicate_schema_targets_reject_the_complete_batch() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let error = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                schema_edit(EDIT_ID, "article", 1, "Article"),
                schema_edit(OTHER_EDIT_ID, "article", 1, "Article duplicate"),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(error, AddChangeSetEditsError::DuplicateTarget);
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_edits", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn duplicate_object_targets_reject_the_complete_batch() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Reject duplicate Objects", None),
    )
    .unwrap();
    let error = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "First"}),
                ),
                object_edit(
                    OTHER_OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "Duplicate"}),
                ),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap_err();

    assert_eq!(error, AddChangeSetEditsError::DuplicateTarget);
    let connection = repository.open_database().unwrap();
    let edit_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_edits", [], |row| row.get(0))
        .unwrap();
    let operation_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_add_operations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!((edit_count, operation_count), (0, 0));
}

#[test]
fn adding_edits_migrates_schema_version_two_in_the_same_transaction() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DROP TABLE changeset_submissions;
             DROP TABLE changeset_validations;
             DROP TABLE changeset_add_operations;
             DROP TABLE changeset_edits;
             DELETE FROM schema_migrations WHERE version >= 3;
             UPDATE workspace_metadata SET schema_version = 2 WHERE singleton = 1;
             PRAGMA user_version = 2;",
        )
        .unwrap();
    drop(connection);

    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: OTHER_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    let connection = repository.open_database().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, 3);
}

#[test]
fn object_add_migrates_an_exact_version_three_workspace_to_nine_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define an article and Object", None),
    )
    .unwrap();
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DROP TABLE changeset_submissions;
             DROP TABLE changeset_validations;
             CREATE TABLE changeset_edits_v3 (
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
             DROP TABLE changeset_edits;
             ALTER TABLE changeset_edits_v3 RENAME TO changeset_edits;
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 4;
             UPDATE workspace_metadata SET schema_version = 3 WHERE singleton = 1;
             PRAGMA user_version = 3;",
        )
        .unwrap();
    let legacy_edit_sql: String = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'changeset_edits'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!legacy_edit_sql.contains("object_id"));
    assert!(legacy_edit_sql.contains("CHECK (edit_kind = 'schema.create')"));
    drop(connection);

    let added = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                constrained_schema_edit(EDIT_ID, "article"),
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "Migration proof"}),
                ),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(added.total_edit_count, 2);
    let connection = repository.open_database().unwrap();
    let metadata_version: u32 = connection
        .query_row(
            "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let migration_version: u32 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .unwrap();
    let pragma_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(
        (metadata_version, migration_version, pragma_version),
        (9, 9, 9)
    );
    let persisted_kinds: String = connection
        .query_row(
            "SELECT group_concat(edit_kind, ',')
             FROM (SELECT edit_kind FROM changeset_edits ORDER BY ordinal)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(persisted_kinds, "schema.create,object.create");
}

#[test]
fn inspection_reconstructs_complete_changeset_and_ordered_edits() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                schema_edit(EDIT_ID, "article", 1, "Article"),
                schema_edit(OTHER_EDIT_ID, "cta", 1, "Call to action"),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    let inspected = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();

    assert_eq!(inspected.workspace_id.to_string(), WORKSPACE_ID);
    assert_eq!(inspected.principal_id.to_string(), PRINCIPAL_ID);
    assert_eq!(inspected.intent.as_str(), "Define launch Schemas");
    assert_eq!(inspected.status.to_string(), "draft");
    assert_eq!(inspected.edits.len(), 2);
    let InspectedChangeSetEdit::SchemaCreate(first) = &inspected.edits[0] else {
        panic!("first Edit should be schema.create");
    };
    let InspectedChangeSetEdit::SchemaCreate(second) = &inspected.edits[1] else {
        panic!("second Edit should be schema.create");
    };
    assert_eq!(first.ordinal, 1);
    assert_eq!(first.schema_id.as_str(), "article");
    assert_eq!(second.ordinal, 2);
    assert_eq!(second.schema_id.as_str(), "cta");
    assert!(first.canonical_document.starts_with("{\"$schema\":"));
}

#[test]
fn inspection_returns_not_found_without_revealing_an_unknown_changeset() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);

    assert_eq!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap_err(),
        InspectChangeSetError::NotFound
    );
}

#[test]
fn inspection_rejects_tampered_canonical_edit_evidence() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_edits SET document_digest = ?1",
            [format!("blake3:{}", "00".repeat(32))],
        )
        .unwrap();

    assert!(matches!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(InspectChangeSetError::Integrity(_))
    ));
}

#[test]
fn validation_evidence_is_deterministic_and_seals_exact_edits() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    let first = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    let replay = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();

    assert!(first.valid);
    assert!(first.findings.is_empty());
    assert_eq!(first.edit_count, 1);
    assert_eq!(first.status, proof_application::ChangeSetStatus::Ready);
    assert_eq!(first, replay);
    let connection = repository.open_database().unwrap();
    let persisted: (String, String, i64, String) = connection
        .query_row(
            "SELECT changeset_digest, base_state, valid, results_digest
             FROM changeset_validations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(persisted.0, first.changeset_digest.to_string());
    assert_eq!(persisted.1, first.base_state.to_string());
    assert_eq!(persisted.2, 1);
    assert_eq!(persisted.3, first.validation_results_digest.to_string());
    drop(connection);

    let error = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(OTHER_EDIT_ID, "cta", 1, "Call to action")],
            idempotency_key: OTHER_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap_err();
    assert_eq!(error, AddChangeSetEditsError::NotDraft);
    let inspected = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert_eq!(inspected.status, proof_application::ChangeSetStatus::Ready);
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_validations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn validation_reports_empty_and_meta_schema_findings_at_stable_pointers() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();

    let empty = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(!empty.valid);
    assert_eq!(empty.status, proof_application::ChangeSetStatus::Rejected);
    assert_eq!(empty.findings[0].code, "proof.changeset.empty");
    assert_eq!(empty.findings[0].pointer.as_deref(), Some("/edits"));

    let invalid_directory = TestDirectory::new();
    let repository = initialized_repository(&invalid_directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define invalid Schema", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![invalid_schema_edit()],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let invalid = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(!invalid.valid);
    assert_eq!(invalid.findings.len(), 1);
    assert_eq!(invalid.findings[0].code, "proof.schema.meta_schema_invalid");
    assert_eq!(
        invalid.findings[0].pointer.as_deref(),
        Some("/edits/0/document/type")
    );
    assert_eq!(
        invalid.findings[0].validator.as_deref(),
        Some(proof_application::DRAFT_2020_12_META_VALIDATOR)
    );
}

#[test]
fn object_validation_reports_schema_content_and_visibility_findings() {
    let invalid_directory = TestDirectory::new();
    let invalid_repository = initialized_repository(&invalid_directory);
    create_changeset(
        &invalid_repository,
        draft_command(CHANGESET_ID, "Reject invalid Object content", None),
    )
    .unwrap();
    add_changeset_edits(
        &invalid_repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                constrained_schema_edit(EDIT_ID, "article"),
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": 42}),
                ),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    let invalid = validate_changeset(&invalid_repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(!invalid.valid);
    assert_eq!(invalid.status, proof_application::ChangeSetStatus::Rejected);
    assert!(invalid.findings.iter().any(|finding| {
        finding.code == "proof.schema.type_mismatch"
            && finding.severity == Severity::Error
            && finding.pointer.as_deref() == Some("/edits/1/content/title")
            && finding.validator.as_deref()
                == Some("proof/object-create/draft-2020-12/1+jsonschema/0.49.3")
    }));

    for (case, edits) in [
        (
            "missing",
            vec![object_edit(
                OBJECT_EDIT_ID,
                OBJECT_ID,
                "article",
                &serde_json::json!({"title": "Unbound"}),
            )],
        ),
        (
            "later ordinal",
            vec![
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "Premature"}),
                ),
                constrained_schema_edit(EDIT_ID, "article"),
            ],
        ),
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        create_changeset(
            &repository,
            draft_command(
                CHANGESET_ID,
                &format!("Reject {case} Schema reference"),
                None,
            ),
        )
        .unwrap();
        add_changeset_edits(
            &repository,
            AddChangeSetEditsCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                edits,
                idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
            },
        )
        .unwrap();

        let result = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
        assert!(!result.valid, "{case} Schema reference must be rejected");
        assert!(result.findings.iter().any(|finding| {
            finding.code == "proof.schema.not_found"
                && finding.severity == Severity::Error
                && finding.pointer.as_deref() == Some("/edits/0/schema_id")
        }));
        let object_count: i64 = repository
            .open_database()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM object_revisions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(object_count, 0);
    }
}

#[test]
fn altered_validation_evidence_is_rejected_on_deterministic_replay() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_validations SET results_digest = ?1",
            [format!("blake3:{}", "00".repeat(32))],
        )
        .unwrap();

    assert!(matches!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(proof_application::ValidateChangeSetError::Integrity(_))
    ));
}

#[test]
fn submission_requires_ready_state_and_replays_exact_sealed_evidence() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let submit = |submitted_at: &str| {
        submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: submitted_at.parse().unwrap(),
            },
        )
    };
    assert_eq!(
        submit("2026-08-03T15:00:00Z").unwrap_err(),
        SubmitChangeSetError::NotReady
    );
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let validated = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();

    let first = submit("2026-08-03T15:00:00Z").unwrap();
    let replay = submit("2026-08-03T16:00:00Z").unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.status, proof_application::ChangeSetStatus::Submitted);
    assert_eq!(first.changeset_digest, validated.changeset_digest);
    assert_eq!(
        first.validation_results_digest,
        validated.validation_results_digest
    );
    assert_eq!(first.submitted_at.to_string(), "2026-08-03T15:00:00Z");
    let inspected = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert_eq!(
        inspected.status,
        proof_application::ChangeSetStatus::Submitted
    );
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_submissions", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn submission_rejects_tampered_validation_evidence() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_validations SET results_digest = ?1",
            [format!("blake3:{}", "00".repeat(32))],
        )
        .unwrap();

    assert!(matches!(
        submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
            }
        ),
        Err(SubmitChangeSetError::Integrity(_))
    ));
    let status = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap())
        .unwrap()
        .status;
    assert_eq!(status, proof_application::ChangeSetStatus::Ready);
}

#[test]
fn approval_requires_submission_and_replays_exact_digest_bound_evidence() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let validated = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    let approve = |name: &str, approved_at: &str| {
        approve_changeset(
            &repository,
            ApproveChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                approval: ApprovalName::new(name).unwrap(),
                approved_at: approved_at.parse().unwrap(),
            },
        )
    };
    assert_eq!(
        approve("editorial", "2026-08-03T16:00:00Z").unwrap_err(),
        ApproveChangeSetError::NotSubmitted
    );
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DELETE FROM schema_migrations WHERE version >= 6;
             UPDATE workspace_metadata SET schema_version = 5 WHERE singleton = 1;
             PRAGMA user_version = 5;",
        )
        .unwrap();
    drop(connection);

    let first = approve("editorial", "2026-08-03T16:00:00Z").unwrap();
    let replay = approve("editorial", "2026-08-03T17:00:00Z").unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.changeset_digest, validated.changeset_digest);
    assert_eq!(
        first.validation_results_digest,
        validated.validation_results_digest
    );
    assert_eq!(first.approved_at.to_string(), "2026-08-03T16:00:00Z");
    assert_eq!(first.status, proof_application::ChangeSetStatus::Approved);
    assert_eq!(
        approve("legal", "2026-08-03T17:00:00Z").unwrap_err(),
        ApproveChangeSetError::ApprovalConflict
    );
    let inspected = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert_eq!(
        inspected.status,
        proof_application::ChangeSetStatus::Approved
    );
    let schema_version: u32 = repository
        .open_database()
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(schema_version, 6);
}

#[test]
fn approved_changeset_commits_atomically_and_replays_the_original_result() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    let commit = |committed_at: &str| {
        commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: committed_at.parse().unwrap(),
            },
        )
    };

    let first = commit("2026-08-03T17:00:00Z").unwrap();
    let replay = commit("2026-08-03T18:00:00Z").unwrap();

    assert_eq!(first, replay);
    assert_eq!(first.status, proof_application::ChangeSetStatus::Committed);
    assert_eq!(first.authoritative_sequence, 1);
    assert_ne!(first.previous_state, first.resulting_state);
    assert_eq!(first.committed_at.to_string(), "2026-08-03T17:00:00Z");
    let status = workspace_status(&repository).unwrap();
    let WorkspaceStatus::Initialized(status) = status else {
        panic!("Workspace should remain initialized");
    };
    assert_eq!(status.authoritative_sequence, 1);
    assert_eq!(status.state_digest, first.resulting_state);
    let next = create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Define another Schema").unwrap(),
            requested_base_state: None,
            idempotency_key: OTHER_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: CREATED_AT.parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(next.base_authoritative_sequence, 1);
    assert_eq!(next.base_state, first.resulting_state);
}

#[test]
fn commit_replay_rejects_syntactically_valid_result_and_sequence_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    let command = CommitChangeSetCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
        committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
    };
    let committed = commit_changeset(&repository, command).unwrap();
    let connection = repository.open_database().unwrap();
    connection
        .execute(
            "UPDATE changeset_commits SET resulting_state = ?1 WHERE changeset_id = ?2",
            (
                initial_known_state_digest(WORKSPACE_ID.parse().unwrap())
                    .unwrap()
                    .to_string(),
                CHANGESET_ID,
            ),
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        commit_changeset(&repository, command),
        Err(CommitChangeSetError::Integrity(_))
    ));

    let connection = repository.open_database().unwrap();
    connection
        .execute(
            "UPDATE changeset_commits
             SET resulting_state = ?1, authoritative_sequence = 2
             WHERE changeset_id = ?2",
            (committed.resulting_state.to_string(), CHANGESET_ID),
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        commit_changeset(&repository, command),
        Err(CommitChangeSetError::Integrity(_))
    ));
}

#[test]
fn mixed_commit_replay_rejects_swapped_projection_sequences() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    let command = CommitChangeSetCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
        committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
    };
    let committed = commit_changeset(&repository, command).unwrap();
    assert_eq!(committed.authoritative_sequence, 2);
    let connection = repository.open_database().unwrap();
    connection
        .execute(
            "UPDATE schema_versions SET authoritative_sequence = 2
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE object_revisions SET authoritative_sequence = 1
             WHERE object_id = ?1 AND revision = 1",
            [OBJECT_ID],
        )
        .unwrap();
    let sequences: Vec<i64> = {
        let mut statement = connection
            .prepare(
                "SELECT authoritative_sequence FROM schema_versions
                 UNION ALL
                 SELECT authoritative_sequence FROM object_revisions
                 ORDER BY authoritative_sequence",
            )
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert_eq!(sequences, vec![1, 2]);
    drop(connection);

    assert!(matches!(
        workspace_status(&repository),
        Err(WorkspaceStatusError::Integrity(_))
    ));
    assert!(matches!(
        commit_changeset(&repository, command),
        Err(CommitChangeSetError::Integrity(_))
    ));
}

#[test]
fn commit_rejects_a_stale_base_without_partial_authoritative_effects() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    prepare_approved_changeset(
        &repository,
        OTHER_CHANGESET_ID,
        OTHER_EDIT_ID,
        "cta",
        OTHER_ADD_IDEMPOTENCY_KEY,
        OTHER_COMMIT_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let error = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: OTHER_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T18:00:00Z".parse().unwrap(),
        },
    )
    .unwrap_err();

    assert_eq!(error, CommitChangeSetError::BaseStateConflict);
    let connection = repository.open_database().unwrap();
    let schema_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_versions", [], |row| row.get(0))
        .unwrap();
    let commit_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_commits", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(schema_count, 1);
    assert_eq!(commit_count, 1);
    assert_eq!(
        inspect_changeset(&repository, OTHER_CHANGESET_ID.parse().unwrap())
            .unwrap()
            .status,
        proof_application::ChangeSetStatus::Approved
    );
}

#[test]
fn commit_migrates_an_approved_version_six_workspace_in_its_transaction() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DELETE FROM schema_migrations WHERE version >= 7;
             UPDATE workspace_metadata SET schema_version = 6 WHERE singleton = 1;
             PRAGMA user_version = 6;",
        )
        .unwrap();

    let committed = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(committed.authoritative_sequence, 1);
    let connection = repository.open_database().unwrap();
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(schema_version, 7);
}

#[test]
fn commit_storage_failure_rolls_back_every_authoritative_write() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define related Schemas", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                schema_edit(EDIT_ID, "article", 1, "Article"),
                schema_edit(OTHER_EDIT_ID, "cta", 1, "CTA"),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_cta_schema
             BEFORE INSERT ON schema_versions
             WHEN NEW.schema_id = 'cta'
             BEGIN
                 SELECT RAISE(ABORT, 'injected storage failure');
             END;",
        )
        .unwrap();

    assert!(matches!(
        commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
            },
        ),
        Err(CommitChangeSetError::Storage(_))
    ));
    let connection = repository.open_database().unwrap();
    let schema_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM schema_versions", [], |row| row.get(0))
        .unwrap();
    let commit_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_commits", [], |row| {
            row.get(0)
        })
        .unwrap();
    let (sequence, state): (i64, String) = connection
        .query_row(
            "SELECT authoritative_sequence, state_digest FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(schema_count, 0);
    assert_eq!(commit_count, 0);
    assert_eq!(sequence, 0);
    assert_eq!(
        state,
        initial_known_state_digest(WORKSPACE_ID.parse().unwrap())
            .unwrap()
            .to_string()
    );
    assert_eq!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .status,
        proof_application::ChangeSetStatus::Approved
    );
}

#[test]
fn edition_requires_committed_state_without_persisting_an_empty_artifact() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);

    let error = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap_err();

    assert_eq!(error, CreateEditionError::EmptyState);
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM editions", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn edition_is_content_addressed_immutable_and_replayed_for_the_same_state() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    let committed = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let first = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    let replay = create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();
    let same_state = create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            OTHER_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();

    assert_eq!(first, replay);
    assert_eq!(first, same_state);
    assert_eq!(first.state_digest, committed.resulting_state);
    assert_eq!(first.authoritative_sequence, 1);
    assert_eq!(first.schemas.len(), 1);
    assert_eq!(first.changesets.len(), 1);
    assert_eq!(first.created_at.to_string(), "2026-08-03T18:00:00Z");
    let manifest = proof_canonical::parse_strict(first.manifest_json.as_bytes()).unwrap();
    assert_eq!(manifest["api_version"], "proof.dev/edition/v1");
    assert_eq!(manifest["state_digest"], first.state_digest.to_string());
    let connection = repository.open_database().unwrap();
    let edition_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM editions", [], |row| row.get(0))
        .unwrap();
    let operation_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM edition_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(edition_count, 1);
    assert_eq!(operation_count, 2);
    connection
        .execute("UPDATE editions SET manifest_json = '{}'", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        create_edition(
            &repository,
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T20:00:00Z",),
        ),
        Err(CreateEditionError::Integrity(_))
    ));
}

#[test]
fn edition_replay_rejects_consistently_redigested_committed_edit_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let command = edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z");
    create_edition(&repository, command).unwrap();
    let tampered_document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Tampered but internally consistent",
        "type": "object",
    });
    let tampered_canonical = canonicalize(&tampered_document).unwrap();
    let tampered_digest = digest(ArtifactKind::SchemaVersionV1, &tampered_canonical);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_edits
             SET document_json = ?1, document_digest = ?2
             WHERE changeset_id = ?3 AND edit_id = ?4",
            (
                tampered_canonical.as_str(),
                tampered_digest.to_string(),
                CHANGESET_ID,
                EDIT_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        create_edition(&repository, command),
        Err(CreateEditionError::Integrity(_))
    ));
}

#[test]
fn edition_key_reuse_rejects_a_later_known_state() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    prepare_approved_changeset(
        &repository,
        OTHER_CHANGESET_ID,
        OTHER_EDIT_ID,
        "cta",
        OTHER_ADD_IDEMPOTENCY_KEY,
        OTHER_COMMIT_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: OTHER_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(
        create_edition(
            &repository,
            edition_command(
                OTHER_EDITION_ID,
                EDITION_IDEMPOTENCY_KEY,
                "2026-08-03T20:00:00Z",
            ),
        )
        .unwrap_err(),
        CreateEditionError::IdempotencyKeyReused
    );
}

#[test]
fn edition_creation_migrates_version_seven_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DELETE FROM schema_migrations WHERE version >= 8;
             UPDATE workspace_metadata SET schema_version = 7 WHERE singleton = 1;
             PRAGMA user_version = 7;",
        )
        .unwrap();

    create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();

    let schema_version: u32 = repository
        .open_database()
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(schema_version, 8);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the migration scenario keeps fixture construction and compatibility assertions together"
)]
fn object_migration_retains_schema_only_state_and_canonical_digests() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_changeset(
        &repository,
        CHANGESET_ID,
        EDIT_ID,
        "article",
        IDEMPOTENCY_KEY,
        ADD_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let schema_only_edition = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    let WorkspaceStatus::Initialized(before) = workspace_status(&repository).unwrap() else {
        panic!("Workspace should remain initialized");
    };
    let connection = repository.open_database().unwrap();
    let schema_digest_before: String = connection
        .query_row(
            "SELECT document_digest FROM schema_versions
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             CREATE TABLE changeset_edits_v8 (
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
             INSERT INTO changeset_edits_v8 (
                 changeset_id, ordinal, edit_id, edit_kind, schema_id,
                 schema_version, document_json, document_digest
             )
             SELECT changeset_id, ordinal, edit_id, edit_kind, schema_id,
                    schema_version, document_json, document_digest
             FROM changeset_edits;
             CREATE TABLE schema_versions_v8 (
                 schema_id TEXT NOT NULL,
                 schema_version INTEGER NOT NULL CHECK (schema_version > 0),
                 document_json TEXT NOT NULL,
                 document_digest TEXT NOT NULL,
                 changeset_id TEXT NOT NULL REFERENCES changesets(changeset_id),
                 edit_id TEXT NOT NULL UNIQUE REFERENCES changeset_edits_v8(edit_id),
                 authoritative_sequence INTEGER NOT NULL UNIQUE CHECK (authoritative_sequence > 0),
                 PRIMARY KEY (schema_id, schema_version)
             ) STRICT;
             INSERT INTO schema_versions_v8 (
                 schema_id, schema_version, document_json, document_digest,
                 changeset_id, edit_id, authoritative_sequence
             )
             SELECT schema_id, schema_version, document_json, document_digest,
                    changeset_id, edit_id, authoritative_sequence
             FROM schema_versions;
             DROP TABLE schema_versions;
             DROP TABLE changeset_edits;
             ALTER TABLE changeset_edits_v8 RENAME TO changeset_edits;
             ALTER TABLE schema_versions_v8 RENAME TO schema_versions;
             CREATE TABLE editions_v8 (
                 edition_id TEXT PRIMARY KEY,
                 workspace_id TEXT NOT NULL,
                 principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                 authoritative_sequence INTEGER NOT NULL CHECK (authoritative_sequence > 0),
                 state_digest TEXT NOT NULL UNIQUE,
                 schema_set_digest TEXT NOT NULL,
                 edition_digest TEXT NOT NULL UNIQUE,
                 manifest_json TEXT NOT NULL,
                 created_at TEXT NOT NULL
             ) STRICT;
             INSERT INTO editions_v8 (
                 edition_id, workspace_id, principal_id, authoritative_sequence,
                 state_digest, schema_set_digest, edition_digest, manifest_json, created_at
             )
             SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, edition_digest, manifest_json, created_at
             FROM editions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             ALTER TABLE editions_v8 RENAME TO editions;
             CREATE TABLE edition_create_operations (
                 workspace_id TEXT NOT NULL,
                 principal_id TEXT NOT NULL REFERENCES principals(principal_id),
                 idempotency_key TEXT NOT NULL,
                 requested_state_digest TEXT NOT NULL,
                 edition_id TEXT NOT NULL REFERENCES editions(edition_id),
                 PRIMARY KEY (workspace_id, principal_id, idempotency_key)
             ) STRICT;
             DELETE FROM schema_migrations WHERE version = 9;
             UPDATE workspace_metadata SET schema_version = 8 WHERE singleton = 1;
             PRAGMA user_version = 8;",
        )
        .unwrap();
    drop(connection);

    create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Exercise the Object migration").unwrap(),
            requested_base_state: None,
            idempotency_key: OTHER_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: CREATED_AT.parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![object_edit(
                OBJECT_EDIT_ID,
                OBJECT_ID,
                "article",
                &serde_json::json!({"title": "Migration probe"}),
            )],
            idempotency_key: OTHER_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();

    let WorkspaceStatus::Initialized(after) = workspace_status(&repository).unwrap() else {
        panic!("Workspace should remain initialized");
    };
    assert_eq!(after.storage_schema_version, 9);
    assert_eq!(after.authoritative_sequence, before.authoritative_sequence);
    assert_eq!(after.state_digest, before.state_digest);
    let connection = repository.open_database().unwrap();
    let schema_digest_after: String = connection
        .query_row(
            "SELECT document_digest FROM schema_versions
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema_digest_after, schema_digest_before);
    let foreign_key_violations = {
        let mut statement = connection.prepare("PRAGMA foreign_key_check").unwrap();
        statement
            .query_map([], |_| Ok(()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(foreign_key_violations.is_empty());
    let schema_foreign_keys: Vec<(String, String, String)> = {
        let mut statement = connection
            .prepare("PRAGMA foreign_key_list(schema_versions)")
            .unwrap();
        statement
            .query_map([], |row| Ok((row.get(2)?, row.get(3)?, row.get(4)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(schema_foreign_keys.contains(&(
        "changeset_edits".to_owned(),
        "edit_id".to_owned(),
        "edit_id".to_owned(),
    )));
    assert!(
        schema_foreign_keys
            .iter()
            .all(|(table, _, _)| table != "changeset_edits_v9")
    );
    drop(connection);
    let replayed = create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            OTHER_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(replayed.edition_digest, schema_only_edition.edition_digest);
    assert_eq!(replayed.manifest_json, schema_only_edition.manifest_json);
}

#[test]
fn validation_migrates_schema_version_three_in_the_same_transaction() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DROP TABLE changeset_submissions;
             DROP TABLE changeset_validations;
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 4;
             UPDATE workspace_metadata SET schema_version = 3 WHERE singleton = 1;
             PRAGMA user_version = 3;",
        )
        .unwrap();
    drop(connection);

    let result = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();

    assert!(!result.valid);
    let connection = repository.open_database().unwrap();
    let metadata_version: u32 = connection
        .query_row(
            "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let pragma_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let evidence_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM changeset_validations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(metadata_version, 5);
    assert_eq!(pragma_version, 5);
    assert_eq!(evidence_count, 1);
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

fn prepare_approved_changeset(
    repository: &LocalWorkspace,
    changeset_id: &str,
    edit_id: &str,
    schema_id: &str,
    draft_key: &str,
    add_key: &str,
) {
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            intent: ChangeSetIntent::new(format!("Define {schema_id} Schema")).unwrap(),
            requested_base_state: None,
            idempotency_key: draft_key.parse().unwrap(),
            created_at: CREATED_AT.parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: changeset_id.parse().unwrap(),
            edits: vec![schema_edit(edit_id, schema_id, 1, schema_id)],
            idempotency_key: add_key.parse().unwrap(),
        },
    )
    .unwrap();
    validate_changeset(repository, changeset_id.parse().unwrap()).unwrap();
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
}

fn prepare_approved_mixed_changeset(repository: &LocalWorkspace) {
    create_changeset(
        repository,
        draft_command(CHANGESET_ID, "Define an article and Object", None),
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                constrained_schema_edit(EDIT_ID, "article"),
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "Projection proof"}),
                ),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let validated = validate_changeset(repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(validated.valid);
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
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

fn draft_command(
    changeset_id: &str,
    intent: &str,
    requested_base_state: Option<ContentDigest>,
) -> CreateChangeSetCommand {
    CreateChangeSetCommand {
        changeset_id: changeset_id.parse::<ChangeSetId>().unwrap(),
        intent: ChangeSetIntent::new(intent).unwrap(),
        requested_base_state,
        idempotency_key: IDEMPOTENCY_KEY.parse::<IdempotencyKey>().unwrap(),
        created_at: CREATED_AT.parse::<Timestamp>().unwrap(),
    }
}

fn edition_command(
    edition_id: &str,
    idempotency_key: &str,
    created_at: &str,
) -> CreateEditionCommand {
    CreateEditionCommand {
        edition_id: edition_id.parse::<EditionId>().unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        created_at: created_at.parse().unwrap(),
    }
}

fn schema_edit(edit_id: &str, schema_id: &str, schema_version: u32, title: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
    });
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(schema_version).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the lifecycle scenario proves one atomic path from mixed input through Edition output"
)]
fn mixed_schema_and_object_changeset_replays_and_commits_as_one_authoritative_unit() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define an article and its first Object", None),
    )
    .unwrap();
    let edits = vec![
        constrained_schema_edit(EDIT_ID, "article"),
        object_edit(
            OBJECT_EDIT_ID,
            OBJECT_ID,
            "article",
            &serde_json::json!({"title": "First article"}),
        ),
    ];
    let first = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits,
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let replay = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                constrained_schema_edit(OTHER_EDIT_ID, "article"),
                object_edit(
                    OTHER_OBJECT_EDIT_ID,
                    OBJECT_ID,
                    "article",
                    &serde_json::json!({"title": "First article"}),
                ),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(replay, first);
    assert_eq!(first.first_ordinal, 1);
    assert_eq!(first.total_edit_count, 2);

    let inspected = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(matches!(
        inspected.edits.as_slice(),
        [
            InspectedChangeSetEdit::SchemaCreate(_),
            InspectedChangeSetEdit::ObjectCreate(_)
        ]
    ));
    let validated = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(validated.valid);
    assert_eq!(validated.edit_count, 2);
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let committed = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(committed.edit_count, 2);
    assert_eq!(committed.authoritative_sequence, 2);
    assert_ne!(committed.previous_state, committed.resulting_state);
    let WorkspaceStatus::Initialized(status) = workspace_status(&repository).unwrap() else {
        panic!("Workspace should remain initialized");
    };
    assert_eq!(status.authoritative_sequence, 2);
    assert_eq!(status.state_digest, committed.resulting_state);
    let connection = repository.open_database().unwrap();
    let schema_sequence: i64 = connection
        .query_row(
            "SELECT authoritative_sequence FROM schema_versions WHERE schema_id = 'article'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let object_sequence: i64 = connection
        .query_row(
            "SELECT authoritative_sequence FROM object_revisions WHERE object_id = ?1",
            [OBJECT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((schema_sequence, object_sequence), (1, 2));
    drop(connection);

    let edition = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    assert_eq!(edition.authoritative_sequence, 2);
    assert_eq!(edition.schemas.len(), 1);
    assert_eq!(edition.objects.len(), 1);
    assert!(edition.object_set_digest.is_some());
    let manifest = proof_canonical::parse_strict(edition.manifest_json.as_bytes()).unwrap();
    assert_eq!(manifest["objects"].as_array().unwrap().len(), 1);
    assert_eq!(
        manifest["object_set_digest"],
        edition.object_set_digest.unwrap().to_string()
    );
}

fn invalid_schema_edit() -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": 42,
    });
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: EDIT_ID.parse().unwrap(),
        schema_id: SchemaId::new("article").unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn constrained_schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "title": { "type": "string" },
        },
        "required": ["title"],
        "type": "object",
    });
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: edit_id.parse().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn object_edit(
    edit_id: &str,
    object_id: &str,
    schema_id: &str,
    content: &serde_json::Value,
) -> ChangeSetEdit {
    let object_id = object_id.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(schema_id).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical = canonicalize(content).unwrap();
    let object_digest =
        object_revision_digest(object_id, &schema_id, schema_version, content).unwrap();
    ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
        edit_id: edit_id.parse().unwrap(),
        object_id,
        schema_id,
        schema_version,
        canonical_content: canonical.as_str().to_owned(),
        object_digest,
    })
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
