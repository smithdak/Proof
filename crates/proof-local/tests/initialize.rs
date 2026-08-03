use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, ArtifactKind, ChangeSetId, ChangeSetIntent,
    ContentDigest, CreateChangeSetCommand, CreateChangeSetError, EditId, IdempotencyKey,
    InitializeWorkspaceCommand, InspectChangeSetError, PrincipalId, SchemaCreateEdit, SchemaId,
    SchemaVersion, Timestamp, WorkspaceId, WorkspaceInitializationError, WorkspaceStatus,
    WorkspaceStatusError, add_changeset_edits, create_changeset, initialize_workspace,
    inspect_changeset, validate_changeset, workspace_status,
};
use proof_canonical::{canonicalize, digest, initial_known_state_digest};
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
const EDIT_ID: &str = "019c0000-0000-7000-8000-000000000050";
const OTHER_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000051";
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
    assert_eq!(identity_provider, "os/unix");
    assert_eq!(
        identity_subject,
        format!("uid:{}", rustix::process::geteuid().as_raw())
    );
    assert_eq!(enabled, 1);
    assert_eq!(foreign_keys, 1);
    assert_eq!(journal_mode, "wal");
    assert_eq!(schema_version, 4);
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
    assert_eq!(status.storage_schema_version, 4);
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
            "DROP TABLE changeset_validations;
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
    let add = |edit: SchemaCreateEdit| {
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
            "DROP TABLE changeset_validations;
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
    assert_eq!(inspected.edits[0].ordinal, 1);
    assert_eq!(inspected.edits[0].schema_id.as_str(), "article");
    assert_eq!(inspected.edits[1].ordinal, 2);
    assert_eq!(inspected.edits[1].schema_id.as_str(), "cta");
    assert!(
        inspected.edits[0]
            .canonical_document
            .starts_with("{\"$schema\":")
    );
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
fn validation_evidence_is_deterministic_and_bound_to_exact_edits() {
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

    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(OTHER_EDIT_ID, "cta", 1, "Call to action")],
            idempotency_key: OTHER_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    let updated = validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    assert!(updated.valid);
    assert_eq!(updated.edit_count, 2);
    assert_ne!(updated.changeset_digest, first.changeset_digest);
    assert_ne!(
        updated.validation_results_digest,
        first.validation_results_digest
    );
    let count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_validations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 2);
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
    assert_eq!(empty.findings[0].code, "proof.changeset.empty");
    assert_eq!(empty.findings[0].pointer.as_deref(), Some("/edits"));

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
            "DROP TABLE changeset_validations;
             DELETE FROM schema_migrations WHERE version = 4;
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
    assert_eq!(metadata_version, 4);
    assert_eq!(pragma_version, 4);
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

fn schema_edit(
    edit_id: &str,
    schema_id: &str,
    schema_version: u32,
    title: &str,
) -> SchemaCreateEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": title,
        "type": "object",
    });
    let canonical = canonicalize(&document).unwrap();
    SchemaCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(schema_version).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    }
}

fn invalid_schema_edit() -> SchemaCreateEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": 42,
    });
    let canonical = canonicalize(&document).unwrap();
    SchemaCreateEdit {
        edit_id: EDIT_ID.parse().unwrap(),
        schema_id: SchemaId::new("article").unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    }
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
