use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, ApprovalName, ApproveChangeSetCommand,
    ApproveChangeSetError, ArtifactKind, BuildContextPackCommand, ChangeSetEdit, ChangeSetId,
    ChangeSetIntent, CommitChangeSetCommand, CommitChangeSetError, ContentDigest, ContextPackError,
    ContextPackId, ContextPackLimits, CreateAgentPrincipalCommand, CreateChangeSetCommand,
    CreateChangeSetError, CreateEditionCommand, CreateEditionError, CreateEnvironmentCommand,
    DelegatedAction, DelegatedWorkspaceStatusCommand, DelegatedWorkspaceStatusError,
    DelegationConstraints, DelegationError, DelegationId, DelegationScope, EditId, EditionId,
    EnvironmentError, EnvironmentId, GetContextPackCommand, GrantDelegationCommand, IdempotencyKey,
    InitializeWorkspaceCommand, InspectChangeSetError, InspectedChangeSet, InspectedChangeSetEdit,
    ObjectCreateEdit, ObjectId, ObjectLifecycleState, ObjectRevision, PrincipalError, PrincipalId,
    PromoteReleaseCommand, ProofId, QueryReleasedObjectsCommand, QueryReleasedObjectsError,
    RebuildProjectionsCommand, RebuildProjectionsError, ReleaseError, ReleaseId, ReleaseKind,
    RevokeDelegationCommand, RollbackReleaseCommand, SchemaCreateEdit, SchemaId, SchemaVersion,
    Severity, SubmitChangeSetCommand, SubmitChangeSetError, Timestamp, VerifyContextPackCommand,
    VerifyDelegationCommand, VerifyReleaseCommand, WorkspaceId, WorkspaceInitializationError,
    WorkspaceStatus, WorkspaceStatusError, add_changeset_edits, approve_changeset,
    build_context_pack, commit_changeset, create_agent_principal, create_changeset, create_edition,
    create_environment, delegated_workspace_status, get_agent_principal, get_context_pack,
    get_delegation, get_environment, get_release, grant_delegation, initialize_workspace,
    inspect_changeset, promote_release, query_released_objects, rebuild_projections,
    revoke_delegation, rollback_release, submit_changeset, validate_changeset, verify_context_pack,
    verify_delegation, verify_release, workspace_status,
};
use proof_application::{
    AddLocalizedEditsCommand, BuildLocalizedContextCommand, CommitLocalizedChangeSetCommand,
    ContentResourceIntentId, CreateLocalizedChangeSetCommand, CreateLocalizedEditionCommand,
    ExpectedLocalizedSource, ExpectedLocalizedTarget, IssueContentResourceIntentCommand, LocaleId,
    LocaleRevision, LocalizedContentError, LocalizedContentRepository, LocalizedContentTarget,
    LocalizedContextLimits, LocalizedPolicyRule, ObjectLocalePutInput,
    PromoteLocalizedReleaseCommand, QueryReleasedRenditionsCommand, ReleasedLocaleTarget,
    RollbackLocalizedReleaseCommand, VerifyLocalizedReleaseCommand,
};
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, initial_known_state_digest,
    known_state_digest_with_objects, object_revision_digest,
};
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
const OTHER_OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000081";
const EDITION_ID: &str = "019c0000-0000-7000-8000-000000000060";
const OTHER_EDITION_ID: &str = "019c0000-0000-7000-8000-000000000061";
const EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000070";
const OTHER_EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000071";
const AGENT_PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000090";
const OTHER_AGENT_PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000091";
const AGENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000092";
const OTHER_AGENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000093";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-0000000000a0";
const OTHER_DELEGATION_ID: &str = "019c0000-0000-7000-8000-0000000000a1";
const DELEGATION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000a2";
const DELEGATION_REVOKE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000a3";
const STATUS_SCOPE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000a4";
const RESOURCE_SCOPE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000a5";
const EARLY_REVOKE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000a6";
const ENVIRONMENT_ID: &str = "preview";
const OTHER_ENVIRONMENT_ID: &str = "production";
const ENVIRONMENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000b0";
const OTHER_ENVIRONMENT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000b1";
const FIRST_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000c0";
const SECOND_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000c1";
const ROLLBACK_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000c2";
const REPLAY_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000c3";
const SUPERSEDING_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000cb";
const OTHER_ENVIRONMENT_RELEASE_ID: &str = "019c0000-0000-7000-8000-0000000000ce";
const FIRST_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000c4";
const SECOND_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000c5";
const ROLLBACK_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000c6";
const REPLAY_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000c7";
const SUPERSEDING_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000cc";
const OTHER_ENVIRONMENT_PROOF_ID: &str = "019c0000-0000-7000-8000-0000000000cf";
const FIRST_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000c8";
const SECOND_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000c9";
const ROLLBACK_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000ca";
const SUPERSEDING_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000cd";
const OTHER_ENVIRONMENT_RELEASE_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000d3";
const RELEASE_SWAP_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000d6";
const CONTEXT_PACK_ID: &str = "019c0000-0000-7000-8000-0000000000d0";
const OTHER_CONTEXT_PACK_ID: &str = "019c0000-0000-7000-8000-0000000000d1";
const CONTEXT_PACK_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000d2";
const OTHER_CONTEXT_PACK_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000d4";
const CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000d5";
const SECOND_DRAFT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e0";
const SECOND_ADD_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e1";
const SECOND_COMMIT_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e2";
const SECOND_EDITION_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e3";
const EDITION_SWAP_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e4";
const COMMIT_SWAP_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e5";
const DRAFT_SWAP_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-0000000000e6";
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
    assert_eq!(schema_version, 11);
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
fn fresh_version_eleven_schema_requires_operation_effect_commitments() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);

    assert_operation_effect_columns(&repository);
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
    assert_eq!(status.storage_schema_version, 11);
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
fn changeset_consumers_reject_output_tamper_without_effect_commitment_update() {
    for (column, tampered_value) in [
        ("created_at", "2026-08-03T14:01:00Z"),
        ("intent", "Tampered draft intent"),
        ("idempotency_key", DRAFT_SWAP_IDEMPOTENCY_KEY),
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        let command = draft_command(CHANGESET_ID, "Publish the launch article", None);
        create_changeset(&repository, command.clone()).unwrap();
        let effect_before: String = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT effect_digest FROM changesets WHERE changeset_id = ?1",
                [CHANGESET_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            repository
                .open_database()
                .unwrap()
                .execute(
                    &format!("UPDATE changesets SET {column} = ?1 WHERE changeset_id = ?2"),
                    (tampered_value, CHANGESET_ID),
                )
                .unwrap(),
            1
        );

        let replay_command = if column == "idempotency_key" {
            CreateChangeSetCommand {
                changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
                intent: ChangeSetIntent::new("Publish the launch article").unwrap(),
                requested_base_state: None,
                idempotency_key: IDEMPOTENCY_KEY.parse().unwrap(),
                created_at: "2026-08-03T14:02:00Z".parse().unwrap(),
            }
        } else {
            command
        };
        let replay = create_changeset(&repository, replay_command);
        assert!(
            matches!(replay, Err(CreateChangeSetError::Integrity(_))),
            "{column} tamper replay returned {replay:?}"
        );
        assert!(matches!(
            inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
            Err(InspectChangeSetError::Integrity(_))
        ));
        assert!(matches!(
            validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
            Err(proof_application::ValidateChangeSetError::Integrity(_))
        ));
        let connection = repository.open_database().unwrap();
        let (total_count, effect_after): (i64, String) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM changesets), effect_digest
                 FROM changesets WHERE changeset_id = ?1",
                [CHANGESET_ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(total_count, 1);
        assert_eq!(effect_after, effect_before);
    }
}

#[test]
fn changeset_consumers_reject_noncanonical_stored_key_and_intent_aliases() {
    let uppercase_key = DRAFT_SWAP_IDEMPOTENCY_KEY.to_ascii_uppercase();
    assert_ne!(uppercase_key, DRAFT_SWAP_IDEMPOTENCY_KEY);
    for (name, column, replacement) in [
        (
            "uppercase idempotency key",
            "idempotency_key",
            uppercase_key.as_str(),
        ),
        (
            "whitespace-normalized intent",
            "intent",
            "  Publish the canonical-key article  ",
        ),
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        create_changeset(
            &repository,
            CreateChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                intent: ChangeSetIntent::new("Publish the canonical-key article").unwrap(),
                requested_base_state: None,
                idempotency_key: DRAFT_SWAP_IDEMPOTENCY_KEY.parse().unwrap(),
                created_at: CREATED_AT.parse().unwrap(),
            },
        )
        .unwrap();
        let effect_before: String = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT effect_digest FROM changesets WHERE changeset_id = ?1",
                [CHANGESET_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            repository
                .open_database()
                .unwrap()
                .execute(
                    &format!("UPDATE changesets SET {column} = ?1 WHERE changeset_id = ?2"),
                    (replacement, CHANGESET_ID),
                )
                .unwrap(),
            1
        );
        let tampered = snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, workspace_id, principal_id, intent, idempotency_key,
                    created_at, lifecycle_status, effect_digest
             FROM changesets ORDER BY changeset_id",
        );

        assert!(matches!(
            inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
            Err(InspectChangeSetError::Integrity(_))
        ));
        assert!(matches!(
            validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
            Err(proof_application::ValidateChangeSetError::Integrity(_))
        ));
        let retry = create_changeset(
            &repository,
            CreateChangeSetCommand {
                changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
                intent: ChangeSetIntent::new("Publish the canonical-key article").unwrap(),
                requested_base_state: None,
                idempotency_key: DRAFT_SWAP_IDEMPOTENCY_KEY.parse().unwrap(),
                created_at: "2026-08-03T14:01:00Z".parse().unwrap(),
            },
        );
        assert!(
            matches!(retry, Err(CreateChangeSetError::Integrity(_))),
            "canonical retry of {name} alias returned {retry:?}"
        );
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT changeset_id, workspace_id, principal_id, intent, idempotency_key,
                        created_at, lifecycle_status, effect_digest
                 FROM changesets ORDER BY changeset_id",
            ),
            tampered
        );
        let (count, effect_after): (i64, String) = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT COUNT(*), effect_digest FROM changesets",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(effect_after, effect_before, "{name} changed the effect");
    }
}

#[test]
fn changeset_consumers_reject_two_row_idempotency_key_swap() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let first = draft_command(CHANGESET_ID, "Publish the launch article", None);
    let second = CreateChangeSetCommand {
        changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
        intent: ChangeSetIntent::new("Publish the launch article").unwrap(),
        requested_base_state: None,
        idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
        created_at: "2026-08-03T14:01:00Z".parse().unwrap(),
    };
    create_changeset(&repository, first.clone()).unwrap();
    create_changeset(&repository, second.clone()).unwrap();
    let immutable_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT changeset_id, workspace_id, principal_id, intent,
                base_authoritative_sequence, base_state, created_at, status,
                policy_profile, validation_profile, lifecycle_status, effect_digest
         FROM changesets ORDER BY changeset_id",
    );
    swap_idempotency_keys(
        &repository,
        "changesets",
        IDEMPOTENCY_KEY,
        SECOND_DRAFT_IDEMPOTENCY_KEY,
        DRAFT_SWAP_IDEMPOTENCY_KEY,
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, workspace_id, principal_id, intent,
                    base_authoritative_sequence, base_state, created_at, status,
                    policy_profile, validation_profile, lifecycle_status, effect_digest
             FROM changesets ORDER BY changeset_id",
        ),
        immutable_before
    );
    let swapped_evidence = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT changeset_id, idempotency_key, effect_digest
         FROM changesets ORDER BY changeset_id",
    );

    for command in [first, second] {
        assert!(matches!(
            create_changeset(&repository, command),
            Err(CreateChangeSetError::Integrity(_))
        ));
    }
    for changeset_id in [CHANGESET_ID, OTHER_CHANGESET_ID] {
        assert!(matches!(
            inspect_changeset(&repository, changeset_id.parse().unwrap()),
            Err(InspectChangeSetError::Integrity(_))
        ));
        assert!(matches!(
            validate_changeset(&repository, changeset_id.parse().unwrap()),
            Err(proof_application::ValidateChangeSetError::Integrity(_))
        ));
    }
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, idempotency_key, effect_digest
             FROM changesets ORDER BY changeset_id",
        ),
        swapped_evidence
    );
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
fn edit_batch_replay_rejects_self_consistent_persisted_effect_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let command = AddChangeSetEditsCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
        idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
    };
    add_changeset_edits(&repository, command.clone()).unwrap();
    let ChangeSetEdit::SchemaCreate(forged) = schema_edit(EDIT_ID, "article", 1, "Forged article")
    else {
        unreachable!();
    };
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_edits SET document_json = ?1, document_digest = ?2
             WHERE changeset_id = ?3 AND edit_id = ?4",
            (
                forged.canonical_document,
                forged.document_digest.to_string(),
                CHANGESET_ID,
                EDIT_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        add_changeset_edits(&repository, command),
        Err(AddChangeSetEditsError::Integrity(_))
    ));
    assert!(matches!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(InspectChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(proof_application::ValidateChangeSetError::Integrity(_))
    ));
}

#[test]
fn edit_consumers_reject_output_identity_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define launch Schemas", None),
    )
    .unwrap();
    let command = AddChangeSetEditsCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
        idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
    };
    add_changeset_edits(&repository, command.clone()).unwrap();
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_add_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_edits SET edit_id = ?1
             WHERE changeset_id = ?2 AND edit_id = ?3",
            (OTHER_EDIT_ID, CHANGESET_ID, EDIT_ID),
        )
        .unwrap();

    assert!(matches!(
        add_changeset_edits(&repository, command),
        Err(AddChangeSetEditsError::Integrity(_))
    ));
    assert!(matches!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(InspectChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(proof_application::ValidateChangeSetError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_add_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn edit_idempotency_key_cannot_alias_a_different_changeset() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define the first Schema", None),
    )
    .unwrap();
    create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Define the second Schema").unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T14:01:00Z".parse().unwrap(),
        },
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

    assert_eq!(
        add_changeset_edits(
            &repository,
            AddChangeSetEditsCommand {
                changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
                edits: vec![schema_edit(OTHER_EDIT_ID, "cta", 1, "CTA")],
                idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
            },
        )
        .unwrap_err(),
        AddChangeSetEditsError::IdempotencyKeyReused
    );
    let untouched = inspect_changeset(&repository, OTHER_CHANGESET_ID.parse().unwrap()).unwrap();
    assert_eq!(untouched.status, proof_application::ChangeSetStatus::Draft);
    assert!(untouched.edits.is_empty());
    let operation_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM changeset_add_operations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(operation_count, 1);

    repository
        .open_database()
        .unwrap()
        .execute(
            "INSERT INTO changeset_add_operations (
                 workspace_id, principal_id, changeset_id, idempotency_key,
                 request_digest, effect_digest, first_ordinal, added_count,
                 total_edit_count
             )
             SELECT workspace_id, principal_id, ?1, idempotency_key,
                    request_digest, effect_digest, first_ordinal, added_count,
                    total_edit_count
             FROM changeset_add_operations WHERE changeset_id = ?2",
            (OTHER_CHANGESET_ID, CHANGESET_ID),
        )
        .unwrap();
    assert!(matches!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(InspectChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        inspect_changeset(&repository, OTHER_CHANGESET_ID.parse().unwrap()),
        Err(InspectChangeSetError::Integrity(_))
    ));
}

#[test]
fn add_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Define an article Schema", None),
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
    create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Define a CTA Schema").unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T14:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE changeset_add_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY, ADD_IDEMPOTENCY_KEY),
            )
            .unwrap(),
        1
    );
    let evidence_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT 'operation', changeset_id, idempotency_key, request_digest, effect_digest,
                first_ordinal, added_count, total_edit_count
         FROM changeset_add_operations
         UNION ALL
         SELECT 'edit', changeset_id, edit_id, edit_kind, document_digest,
                ordinal, schema_version, 0
         FROM changeset_edits
         ORDER BY 1, 2, 3",
    );

    let retry = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![schema_edit(OTHER_EDIT_ID, "cta", 1, "CTA")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    );
    assert!(
        matches!(retry, Err(AddChangeSetEditsError::Integrity(_))),
        "missing-key Add retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT 'operation', changeset_id, idempotency_key, request_digest, effect_digest,
                    first_ordinal, added_count, total_edit_count
             FROM changeset_add_operations
             UNION ALL
             SELECT 'edit', changeset_id, edit_id, edit_kind, document_digest,
                    ordinal, schema_version, 0
             FROM changeset_edits
             ORDER BY 1, 2, 3",
        ),
        evidence_before
    );
    let second_edit_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM changeset_edits WHERE changeset_id = ?1",
            [OTHER_CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(second_edit_count, 0);
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
              ALTER TABLE changeset_add_operations DROP COLUMN effect_digest;
              ALTER TABLE changesets DROP COLUMN effect_digest;
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
fn submission_consumers_reject_submitted_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_release(&repository);
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_submissions WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE changeset_submissions SET submitted_at = '2026-08-03T15:01:00Z'
                 WHERE changeset_id = ?1",
                [CHANGESET_ID],
            )
            .unwrap(),
        1
    );

    assert!(matches!(
        submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
            },
        ),
        Err(SubmitChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
            },
        ),
        Err(CommitChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        create_edition(
            &repository,
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        ),
        Err(CreateEditionError::Integrity(_))
    ));
    assert_release_read_surfaces_reject_integrity(
        &repository,
        FIRST_RELEASE_ID.parse().unwrap(),
        "2026-08-03T19:30:00Z",
    );
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_submissions WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
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
fn approval_consumers_reject_approved_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_release(&repository);
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_approvals WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE changeset_approvals SET approved_at = '2026-08-03T16:01:00Z'
                 WHERE changeset_id = ?1",
                [CHANGESET_ID],
            )
            .unwrap(),
        1
    );

    assert!(matches!(
        approve_changeset(
            &repository,
            ApproveChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                approval: ApprovalName::new("editorial").unwrap(),
                approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
            },
        ),
        Err(ApproveChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
            },
        ),
        Err(CommitChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        create_edition(
            &repository,
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        ),
        Err(CreateEditionError::Integrity(_))
    ));
    assert_release_read_surfaces_reject_integrity(
        &repository,
        FIRST_RELEASE_ID.parse().unwrap(),
        "2026-08-03T19:30:00Z",
    );
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_approvals WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn delayed_changeset_retries_return_original_results_after_commit() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let draft_command = draft_command(CHANGESET_ID, "Define a durable article Schema", None);
    let original_draft = create_changeset(&repository, draft_command.clone()).unwrap();
    let add_command = AddChangeSetEditsCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        edits: vec![schema_edit(EDIT_ID, "article", 1, "Article")],
        idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
    };
    let original_add = add_changeset_edits(&repository, add_command.clone()).unwrap();
    let original_validation =
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    let submit_command = SubmitChangeSetCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
    };
    let original_submission = submit_changeset(&repository, submit_command).unwrap();
    let approval_command = ApproveChangeSetCommand {
        changeset_id: CHANGESET_ID.parse().unwrap(),
        approval: ApprovalName::new("editorial").unwrap(),
        approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
    };
    let original_approval = approve_changeset(&repository, approval_command.clone()).unwrap();
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(
        create_changeset(&repository, draft_command).unwrap(),
        original_draft
    );
    assert_eq!(
        add_changeset_edits(&repository, add_command).unwrap(),
        original_add
    );
    assert_eq!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap(),
        original_validation
    );
    assert_eq!(
        submit_changeset(&repository, submit_command).unwrap(),
        original_submission
    );
    assert_eq!(
        approve_changeset(&repository, approval_command).unwrap(),
        original_approval
    );
    assert_eq!(
        inspect_changeset(&repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .status,
        proof_application::ChangeSetStatus::Committed
    );
    let counts: (i64, i64, i64, i64, i64, i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM changesets),
                 (SELECT COUNT(*) FROM changeset_edits),
                 (SELECT COUNT(*) FROM changeset_add_operations),
                 (SELECT COUNT(*) FROM changeset_validations),
                 (SELECT COUNT(*) FROM changeset_submissions),
                 (SELECT COUNT(*) FROM changeset_approvals),
                 (SELECT COUNT(*) FROM changeset_commits)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(counts, (1, 1, 1, 1, 1, 1, 1));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the same exact lifecycle proves first-write chronology and replay ordering across supported v9, v10, and v11 storage"
)]
fn lifecycle_chronology_rejects_invalid_first_writes_but_replays_original_results() {
    for schema_version in [9, 10, 11] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        match schema_version {
            9 => downgrade_database_to_v9(&repository),
            10 => downgrade_database_to_v10(&repository),
            11 => {}
            _ => unreachable!(),
        }
        assert_storage_version(&repository, schema_version);
        create_changeset(
            &repository,
            draft_command(CHANGESET_ID, "Define a chronology-bound article", None),
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
        assert!(
            validate_changeset(&repository, CHANGESET_ID.parse().unwrap())
                .unwrap()
                .valid
        );

        let before_invalid_submit = lifecycle_write_snapshot(&repository, schema_version);
        let invalid_submit = submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: "2026-08-03T13:59:00Z".parse().unwrap(),
            },
        );
        assert!(
            matches!(
                invalid_submit,
                Err(SubmitChangeSetError::Integrity(ref detail))
                    if detail == "submission timestamp predates ChangeSet creation"
            ),
            "v{schema_version} invalid first submission returned {invalid_submit:?}"
        );
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            before_invalid_submit
        );
        let submitted = submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        let after_submission = lifecycle_write_snapshot(&repository, schema_version);
        let replayed_submission = submit_changeset(
            &repository,
            SubmitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                submitted_at: "2026-08-03T13:58:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(replayed_submission, submitted);
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            after_submission
        );

        let before_invalid_approval = lifecycle_write_snapshot(&repository, schema_version);
        let invalid_approval = approve_changeset(
            &repository,
            ApproveChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                approval: ApprovalName::new("editorial").unwrap(),
                approved_at: "2026-08-03T14:59:00Z".parse().unwrap(),
            },
        );
        assert!(
            matches!(
                invalid_approval,
                Err(ApproveChangeSetError::Integrity(ref detail))
                    if detail == "approval timestamp predates submission"
            ),
            "v{schema_version} invalid first approval returned {invalid_approval:?}"
        );
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            before_invalid_approval
        );
        let approved = approve_changeset(
            &repository,
            ApproveChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                approval: ApprovalName::new("editorial").unwrap(),
                approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        let after_approval = lifecycle_write_snapshot(&repository, schema_version);
        let replayed_approval = approve_changeset(
            &repository,
            ApproveChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                approval: ApprovalName::new("editorial").unwrap(),
                approved_at: "2026-08-03T14:58:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(replayed_approval, approved);
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            after_approval
        );

        let before_invalid_commit = lifecycle_write_snapshot(&repository, schema_version);
        let invalid_commit = commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T15:59:00Z".parse().unwrap(),
            },
        );
        assert!(
            matches!(
                invalid_commit,
                Err(CommitChangeSetError::Integrity(ref detail))
                    if detail == "commit timestamp predates approval"
            ),
            "v{schema_version} invalid first commit returned {invalid_commit:?}"
        );
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            before_invalid_commit
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
        let after_commit = lifecycle_write_snapshot(&repository, schema_version);
        let replayed_commit = commit_changeset(
            &repository,
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T15:58:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        assert_eq!(replayed_commit, committed);
        assert_eq!(
            lifecycle_write_snapshot(&repository, schema_version),
            after_commit
        );
        assert_storage_version(&repository, schema_version);
    }
}

#[test]
fn delayed_validation_replay_rejects_tampered_submission_evidence() {
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
        .execute(
            "UPDATE changeset_submissions SET validation_results_digest = ?1
             WHERE changeset_id = ?2",
            (format!("blake3:{}", "00".repeat(32)), CHANGESET_ID),
        )
        .unwrap();

    assert!(matches!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap()),
        Err(proof_application::ValidateChangeSetError::Integrity(_))
    ));
    let lifecycle: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT lifecycle_status FROM changesets WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(lifecycle, "committed");
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
fn commit_consumers_reject_committed_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_commits WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_commits SET committed_at = '2026-08-03T17:01:00Z'
             WHERE changeset_id = ?1",
            [CHANGESET_ID],
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
        Err(CommitChangeSetError::Integrity(_))
    ));
    assert!(matches!(
        create_edition(
            &repository,
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        ),
        Err(CreateEditionError::Integrity(_))
    ));
    assert!(matches!(
        promote_release(
            &repository,
            promotion_command(
                FIRST_RELEASE_ID,
                FIRST_PROOF_ID,
                EDITION_ID,
                FIRST_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T19:00:00Z",
            ),
        ),
        Err(ReleaseError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM changeset_commits WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn commit_consumers_reject_two_row_idempotency_key_swap() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    let immutable_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT changeset_id, workspace_id, principal_id, effect_digest,
                changeset_digest, validation_results_digest, previous_state,
                resulting_state, authoritative_sequence, committed_at, edit_count
         FROM changeset_commits ORDER BY changeset_id",
    );
    swap_idempotency_keys(
        &repository,
        "changeset_commits",
        COMMIT_IDEMPOTENCY_KEY,
        SECOND_COMMIT_IDEMPOTENCY_KEY,
        COMMIT_SWAP_IDEMPOTENCY_KEY,
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, workspace_id, principal_id, effect_digest,
                    changeset_digest, validation_results_digest, previous_state,
                    resulting_state, authoritative_sequence, committed_at, edit_count
             FROM changeset_commits ORDER BY changeset_id",
        ),
        immutable_before
    );
    let swapped_evidence = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT changeset_id, idempotency_key, effect_digest
         FROM changeset_commits ORDER BY changeset_id",
    );

    for (label, command) in [
        (
            "first",
            CommitChangeSetCommand {
                changeset_id: CHANGESET_ID.parse().unwrap(),
                idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
            },
        ),
        (
            "second",
            CommitChangeSetCommand {
                changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
                idempotency_key: SECOND_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
                committed_at: "2026-08-03T20:00:00Z".parse().unwrap(),
            },
        ),
    ] {
        let replay = commit_changeset(&repository, command);
        assert!(
            matches!(replay, Err(CommitChangeSetError::Integrity(_))),
            "{label} swapped Commit replay returned {replay:?}"
        );
    }
    for command in [
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        edition_command(
            OTHER_EDITION_ID,
            SECOND_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T20:10:00Z",
        ),
    ] {
        assert!(matches!(
            create_edition(&repository, command),
            Err(CreateEditionError::Integrity(_))
        ));
    }
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    assert!(matches!(
        promote_release(
            &repository,
            promotion_command(
                FIRST_RELEASE_ID,
                FIRST_PROOF_ID,
                EDITION_ID,
                FIRST_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T21:00:00Z",
            ),
        ),
        Err(ReleaseError::Integrity(_))
    ));
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, idempotency_key, effect_digest
             FROM changeset_commits ORDER BY changeset_id",
        ),
        swapped_evidence
    );
}

#[test]
fn commit_missing_key_retry_rejects_scope_corruption_without_writes() {
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
    prepare_approved_changeset(
        &repository,
        OTHER_CHANGESET_ID,
        OTHER_EDIT_ID,
        "cta",
        SECOND_DRAFT_IDEMPOTENCY_KEY,
        SECOND_ADD_IDEMPOTENCY_KEY,
    );
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE changeset_commits SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (COMMIT_SWAP_IDEMPOTENCY_KEY, COMMIT_IDEMPOTENCY_KEY),
            )
            .unwrap(),
        1
    );
    let commits_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                changeset_digest, validation_results_digest, previous_state,
                resulting_state, authoritative_sequence, committed_at, edit_count,
                effect_digest
         FROM changeset_commits ORDER BY changeset_id",
    );
    let state_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT authoritative_sequence, state_digest FROM known_state",
    );
    let projections_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT schema_id, schema_version, document_digest, changeset_id,
                edit_id, authoritative_sequence
         FROM schema_versions ORDER BY authoritative_sequence",
    );

    let retry = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    );
    assert!(
        matches!(retry, Err(CommitChangeSetError::Integrity(_))),
        "missing-key Commit retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                    changeset_digest, validation_results_digest, previous_state,
                    resulting_state, authoritative_sequence, committed_at, edit_count,
                    effect_digest
             FROM changeset_commits ORDER BY changeset_id",
        ),
        commits_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT authoritative_sequence, state_digest FROM known_state",
        ),
        state_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT schema_id, schema_version, document_digest, changeset_id,
                    edit_id, authoritative_sequence
             FROM schema_versions ORDER BY authoritative_sequence",
        ),
        projections_before
    );
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
fn edition_chronology_rejects_invalid_first_write_but_replays_the_original_result() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let before_invalid = edition_write_snapshot(&repository);
    let invalid_first = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T16:59:00Z"),
    );
    assert!(
        matches!(invalid_first, Err(CreateEditionError::Integrity(_))),
        "Edition created before its latest commit returned {invalid_first:?}"
    );
    assert_eq!(edition_write_snapshot(&repository), before_invalid);

    let original = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    let after_original = edition_write_snapshot(&repository);
    let replayed = create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T16:58:00Z",
        ),
    )
    .unwrap();
    assert_eq!(replayed, original);
    assert_eq!(edition_write_snapshot(&repository), after_original);
}

#[test]
fn edition_consumers_reject_output_metadata_tamper_without_effect_commitment_update() {
    for tamper_principal in [false, true] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        prepare_first_mixed_release(&repository);
        let operation_effect_before: String = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT effect_digest FROM edition_create_operations
                 WHERE idempotency_key = ?1",
                [EDITION_IDEMPOTENCY_KEY],
                |row| row.get(0),
            )
            .unwrap();
        let immutable_before = snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT manifest_json, edition_digest, state_digest, schema_set_digest,
                    object_set_digest FROM editions WHERE edition_id =
                    '019c0000-0000-7000-8000-000000000060'",
        );
        let connection = repository.open_database().unwrap();
        if tamper_principal {
            connection
                .execute(
                    "INSERT INTO principals (
                         principal_id, principal_type, identity_provider, identity_subject, enabled
                     ) VALUES (?1, 'human', 'proof/test', 'edition-tamper', 1)",
                    [OTHER_PRINCIPAL_ID],
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE editions SET principal_id = ?1 WHERE edition_id = ?2",
                    (OTHER_PRINCIPAL_ID, EDITION_ID),
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE editions SET created_at = '2026-08-03T18:01:00Z'
                     WHERE edition_id = ?1",
                    [EDITION_ID],
                )
                .unwrap();
        }
        drop(connection);

        for command in [
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
            edition_command(
                OTHER_EDITION_ID,
                OTHER_EDITION_IDEMPOTENCY_KEY,
                "2026-08-03T18:02:00Z",
            ),
        ] {
            assert!(matches!(
                create_edition(&repository, command),
                Err(CreateEditionError::Integrity(_))
            ));
        }
        assert_release_read_surfaces_reject_integrity(
            &repository,
            FIRST_RELEASE_ID.parse().unwrap(),
            "2026-08-03T19:30:00Z",
        );
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT manifest_json, edition_digest, state_digest, schema_set_digest,
                        object_set_digest FROM editions WHERE edition_id =
                        '019c0000-0000-7000-8000-000000000060'",
            ),
            immutable_before
        );
        let connection = repository.open_database().unwrap();
        let (operation_count, operation_effect_after): (i64, String) = connection
            .query_row(
                "SELECT COUNT(*), effect_digest FROM edition_create_operations
                 WHERE idempotency_key = ?1",
                [EDITION_IDEMPOTENCY_KEY],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(operation_count, 1);
        assert_eq!(operation_effect_after, operation_effect_before);
    }
}

#[test]
fn edition_consumers_reject_two_alias_idempotency_key_swap() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            OTHER_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T18:01:00Z",
        ),
    )
    .unwrap();
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();
    let immutable_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, requested_state_digest, edition_id, effect_digest
         FROM edition_create_operations ORDER BY effect_digest",
    );
    swap_idempotency_keys(
        &repository,
        "edition_create_operations",
        EDITION_IDEMPOTENCY_KEY,
        OTHER_EDITION_IDEMPOTENCY_KEY,
        EDITION_SWAP_IDEMPOTENCY_KEY,
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, requested_state_digest, edition_id, effect_digest
             FROM edition_create_operations ORDER BY effect_digest",
        ),
        immutable_before
    );
    let swapped_evidence = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT idempotency_key, effect_digest, edition_id
         FROM edition_create_operations ORDER BY idempotency_key",
    );

    for command in [
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        edition_command(
            OTHER_EDITION_ID,
            OTHER_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T18:01:00Z",
        ),
    ] {
        assert!(matches!(
            create_edition(&repository, command),
            Err(CreateEditionError::Integrity(_))
        ));
    }
    assert_release_read_surfaces_reject_integrity(
        &repository,
        FIRST_RELEASE_ID.parse().unwrap(),
        "2026-08-03T19:30:00Z",
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT idempotency_key, effect_digest, edition_id
             FROM edition_create_operations ORDER BY idempotency_key",
        ),
        swapped_evidence
    );
}

#[test]
fn edition_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE edition_create_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (EDITION_SWAP_IDEMPOTENCY_KEY, EDITION_IDEMPOTENCY_KEY),
            )
            .unwrap(),
        1
    );
    prepare_approved_changeset(
        &repository,
        OTHER_CHANGESET_ID,
        OTHER_EDIT_ID,
        "cta",
        SECOND_DRAFT_IDEMPOTENCY_KEY,
        SECOND_ADD_IDEMPOTENCY_KEY,
    );
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: SECOND_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T20:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let editions_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                state_digest, schema_set_digest, object_set_digest, edition_digest,
                manifest_json, created_at
         FROM editions ORDER BY edition_id",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, idempotency_key, requested_state_digest,
                edition_id, effect_digest
         FROM edition_create_operations ORDER BY idempotency_key",
    );

    let retry = create_edition(
        &repository,
        edition_command(
            OTHER_EDITION_ID,
            EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T20:10:00Z",
        ),
    );
    assert!(
        matches!(retry, Err(CreateEditionError::Integrity(_))),
        "missing-key Edition retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, object_set_digest, edition_digest,
                    manifest_json, created_at
             FROM editions ORDER BY edition_id",
        ),
        editions_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, idempotency_key, requested_state_digest,
                    edition_id, effect_digest
             FROM edition_create_operations ORDER BY idempotency_key",
        ),
        operations_before
    );
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
             CREATE TABLE edition_create_operations_v8_snapshot (
                 workspace_id TEXT NOT NULL,
                 principal_id TEXT NOT NULL,
                 idempotency_key TEXT NOT NULL,
                 requested_state_digest TEXT NOT NULL,
                 edition_id TEXT NOT NULL,
                 PRIMARY KEY (workspace_id, principal_id, idempotency_key)
             ) STRICT;
             INSERT INTO edition_create_operations_v8_snapshot (
                 workspace_id, principal_id, idempotency_key,
                 requested_state_digest, edition_id
             )
             SELECT workspace_id, principal_id, idempotency_key,
                    requested_state_digest, edition_id
             FROM edition_create_operations;
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
             INSERT INTO edition_create_operations (
                 workspace_id, principal_id, idempotency_key,
                 requested_state_digest, edition_id
             )
             SELECT workspace_id, principal_id, idempotency_key,
                    requested_state_digest, edition_id
             FROM edition_create_operations_v8_snapshot;
             DROP TABLE edition_create_operations_v8_snapshot;
             ALTER TABLE changesets DROP COLUMN effect_digest;
             ALTER TABLE changeset_add_operations DROP COLUMN effect_digest;
             ALTER TABLE changeset_submissions DROP COLUMN effect_digest;
             ALTER TABLE changeset_approvals DROP COLUMN effect_digest;
             ALTER TABLE changeset_commits DROP COLUMN effect_digest;
             DELETE FROM schema_migrations WHERE version >= 9;
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

#[test]
fn environment_creation_is_canonical_and_idempotent_without_pointer_side_effects() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let command = environment_command(
        ENVIRONMENT_ID,
        ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T14:10:00Z",
    );

    let created = create_environment(&repository, command.clone()).unwrap();

    assert_eq!(created.environment_id.as_str(), ENVIRONMENT_ID);
    assert_eq!(created.workspace_id.to_string(), WORKSPACE_ID);
    assert_eq!(created.config_version, 1);
    assert_eq!(created.target_kind, "proof.local/released-state/v1");
    assert_eq!(created.policy_profile, "proof.local/release-policy/v1");
    assert_eq!(created.required_approval.as_str(), "editorial");
    assert_eq!(created.current_release_id, None);
    assert_eq!(created.principal_id.to_string(), PRINCIPAL_ID);
    let policy = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release-policy/v1",
        "profile": "proof.local/release-policy/v1",
        "require_approved_changesets": true,
        "require_signed_proof": true,
        "required_approval": "editorial",
    }))
    .unwrap();
    let expected_manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/environment/v1",
        "config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "policy_digest": digest(ArtifactKind::PolicyBundleV1, &policy).to_string(),
        "policy_profile": "proof.local/release-policy/v1",
        "required_approval": "editorial",
        "target_kind": "proof.local/released-state/v1",
        "workspace_id": WORKSPACE_ID,
    }))
    .unwrap();
    assert_eq!(created.config_manifest_json, expected_manifest.as_str());
    assert_eq!(
        created.config_digest,
        digest(ArtifactKind::EnvironmentConfigV1, &expected_manifest)
    );
    assert_eq!(create_environment(&repository, command).unwrap(), created);
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap()).unwrap(),
        created
    );

    let different_target = environment_command(
        OTHER_ENVIRONMENT_ID,
        ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T14:20:00Z",
    );
    assert_eq!(
        create_environment(&repository, different_target).unwrap_err(),
        EnvironmentError::IdempotencyKeyReused
    );
    let changed_config = environment_command(
        ENVIRONMENT_ID,
        OTHER_ENVIRONMENT_IDEMPOTENCY_KEY,
        "security",
        "2026-08-03T14:20:00Z",
    );
    assert_eq!(
        create_environment(&repository, changed_config).unwrap_err(),
        EnvironmentError::AlreadyExists
    );
    let operation_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM environment_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(operation_count, 1);
}

#[test]
fn environment_replay_rejects_self_consistent_configuration_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    let command = environment_command(
        ENVIRONMENT_ID,
        ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T14:10:00Z",
    );
    create_environment(&repository, command.clone()).unwrap();
    let operation_before: (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT request_digest, environment_id FROM environment_create_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let policy = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release-policy/v1",
        "profile": "proof.local/release-policy/v1",
        "require_approved_changesets": true,
        "require_signed_proof": true,
        "required_approval": "security",
    }))
    .unwrap();
    let policy_digest = digest(ArtifactKind::PolicyBundleV1, &policy);
    let manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/environment/v1",
        "config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "policy_digest": policy_digest.to_string(),
        "policy_profile": "proof.local/release-policy/v1",
        "required_approval": "security",
        "target_kind": "proof.local/released-state/v1",
        "workspace_id": WORKSPACE_ID,
    }))
    .unwrap();
    let config_digest = digest(ArtifactKind::EnvironmentConfigV1, &manifest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE environment_versions SET required_approval = 'security',
                    policy_json = ?1, policy_digest = ?2, manifest_json = ?3,
                    config_digest = ?4
             WHERE environment_id = ?5 AND config_version = 1",
            (
                policy.as_str(),
                policy_digest.to_string(),
                manifest.as_str(),
                config_digest.to_string(),
                ENVIRONMENT_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        create_environment(&repository, command),
        Err(EnvironmentError::Integrity(_))
    ));
    assert!(matches!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap()),
        Err(EnvironmentError::Integrity(_))
    ));
    assert!(matches!(
        promote_release(
            &repository,
            promotion_command(
                FIRST_RELEASE_ID,
                FIRST_PROOF_ID,
                EDITION_ID,
                FIRST_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T19:00:00Z",
            ),
        ),
        Err(ReleaseError::Integrity(_))
    ));
    let operation_after: (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT request_digest, environment_id FROM environment_create_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(operation_after, operation_before);
}

#[test]
fn environment_consumers_reject_created_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    let command = environment_command(
        ENVIRONMENT_ID,
        ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T18:10:00Z",
    );
    create_environment(&repository, command.clone()).unwrap();
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM environment_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "UPDATE environments SET created_at = '2026-08-03T18:11:00Z'
             WHERE environment_id = 'preview';
             UPDATE environment_versions SET created_at = '2026-08-03T18:11:00Z'
             WHERE environment_id = 'preview' AND config_version = 1;",
        )
        .unwrap();

    assert!(matches!(
        create_environment(&repository, command),
        Err(EnvironmentError::Integrity(_))
    ));
    assert!(matches!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap()),
        Err(EnvironmentError::Integrity(_))
    ));
    assert!(matches!(
        promote_release(
            &repository,
            promotion_command(
                FIRST_RELEASE_ID,
                FIRST_PROOF_ID,
                EDITION_ID,
                FIRST_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T19:00:00Z",
            ),
        ),
        Err(ReleaseError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM environment_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn environment_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE environment_create_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
                    ENVIRONMENT_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    let environments_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT e.environment_id, e.workspace_id, e.created_by_principal_id, e.created_at,
                v.config_version, v.target_kind, v.policy_profile, v.required_approval,
                v.policy_digest, v.config_digest, v.created_by_principal_id, v.created_at
         FROM environments e
         JOIN environment_versions v ON v.environment_id = e.environment_id
         ORDER BY e.environment_id, v.config_version",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                effect_digest, environment_id
         FROM environment_create_operations ORDER BY environment_id",
    );

    let retry = create_environment(
        &repository,
        environment_command(
            OTHER_ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "security",
            "2026-08-03T18:20:00Z",
        ),
    );
    assert!(
        matches!(retry, Err(EnvironmentError::Integrity(_))),
        "missing-key Environment retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT e.environment_id, e.workspace_id, e.created_by_principal_id, e.created_at,
                    v.config_version, v.target_kind, v.policy_profile, v.required_approval,
                    v.policy_digest, v.config_digest, v.created_by_principal_id, v.created_at
             FROM environments e
             JOIN environment_versions v ON v.environment_id = e.environment_id
             ORDER BY e.environment_id, v.config_version",
        ),
        environments_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                    effect_digest, environment_id
             FROM environment_create_operations ORDER BY environment_id",
        ),
        operations_before
    );
}

#[test]
fn delegation_grant_rejects_environment_operation_key_tamper_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM environment_create_operations
             WHERE environment_id = ?1",
            [ENVIRONMENT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE environment_create_operations SET idempotency_key = ?1
                 WHERE environment_id = ?2",
                (CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY, ENVIRONMENT_ID),
            )
            .unwrap(),
        1
    );
    let before_grant = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT d.delegation_id, d.workspace_id, d.issuer_principal_id,
                d.recipient_principal_id, d.delegation_digest,
                o.idempotency_key, o.request_digest, o.effect_digest
         FROM delegations d
         JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
         ORDER BY d.delegation_id",
    );

    let granted = grant_delegation(
        &repository,
        delegation_command(
            DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:15:00Z",
        ),
    );
    assert!(
        matches!(granted, Err(DelegationError::Integrity(_))),
        "grant scoped to an Environment with corrupt operation evidence returned {granted:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT d.delegation_id, d.workspace_id, d.issuer_principal_id,
                    d.recipient_principal_id, d.delegation_digest,
                    o.idempotency_key, o.request_digest, o.effect_digest
             FROM delegations d
             JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
             ORDER BY d.delegation_id",
        ),
        before_grant
    );
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM environment_create_operations
             WHERE environment_id = ?1",
            [ENVIRONMENT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn delegation_grant_rejects_object_provenance_operation_key_tamper_without_writes() {
    for (name, table, replacement) in [
        (
            "Add",
            "changeset_add_operations",
            CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
        ),
        ("Commit", "changeset_commits", COMMIT_SWAP_IDEMPOTENCY_KEY),
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        prepare_delegation_dependencies(&repository);
        let effect_query = format!("SELECT effect_digest FROM {table} WHERE changeset_id = ?1");
        let effect_before: String = repository
            .open_database()
            .unwrap()
            .query_row(&effect_query, [CHANGESET_ID], |row| row.get(0))
            .unwrap();
        assert_eq!(
            repository
                .open_database()
                .unwrap()
                .execute(
                    &format!("UPDATE {table} SET idempotency_key = ?1 WHERE changeset_id = ?2"),
                    (replacement, CHANGESET_ID),
                )
                .unwrap(),
            1
        );
        let before_grant = snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT d.delegation_id, d.workspace_id, d.issuer_principal_id,
                    d.recipient_principal_id, d.delegation_digest,
                    o.idempotency_key, o.request_digest, o.effect_digest
             FROM delegations d
             JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
             ORDER BY d.delegation_id",
        );

        let granted = grant_delegation(
            &repository,
            delegation_command(
                DELEGATION_ID,
                DELEGATION_IDEMPOTENCY_KEY,
                "2026-08-03T17:15:00Z",
            ),
        );
        assert!(
            matches!(granted, Err(DelegationError::Integrity(_))),
            "Object-scoped grant with corrupt {name} operation evidence returned {granted:?}"
        );
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT d.delegation_id, d.workspace_id, d.issuer_principal_id,
                        d.recipient_principal_id, d.delegation_digest,
                        o.idempotency_key, o.request_digest, o.effect_digest
                 FROM delegations d
                 JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
                 ORDER BY d.delegation_id",
            ),
            before_grant
        );
        let effect_after: String = repository
            .open_database()
            .unwrap()
            .query_row(&effect_query, [CHANGESET_ID], |row| row.get(0))
            .unwrap();
        assert_eq!(effect_after, effect_before, "{name} effect changed");
    }
}

#[test]
fn environment_read_rejects_current_release_operation_key_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_release(&repository);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE release_operations SET idempotency_key = ?1
                 WHERE release_id = ?2",
                (RELEASE_SWAP_IDEMPOTENCY_KEY, FIRST_RELEASE_ID),
            )
            .unwrap(),
        1
    );
    let operation_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                request_digest, release_id, proof_id
         FROM release_operations ORDER BY release_id",
    );
    let pointer_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT environment_id, release_id, release_sequence, projection_version
         FROM environment_current_releases ORDER BY environment_id",
    );

    let environment = get_environment(&repository, ENVIRONMENT_ID.parse().unwrap());
    assert!(
        matches!(environment, Err(EnvironmentError::Integrity(_))),
        "Environment read with corrupt current Release operation evidence returned {environment:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                    request_digest, release_id, proof_id
             FROM release_operations ORDER BY release_id",
        ),
        operation_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT environment_id, release_id, release_sequence, projection_version
             FROM environment_current_releases ORDER BY environment_id",
        ),
        pointer_before
    );
}

#[test]
fn same_environment_config_with_fresh_key_replays_version_without_live_pointer() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    let original = create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    let release = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();
    let alias = environment_command(
        ENVIRONMENT_ID,
        OTHER_ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T19:10:00Z",
    );

    let first_alias = create_environment(&repository, alias.clone()).unwrap();
    let replayed_alias = create_environment(&repository, alias).unwrap();
    assert_eq!(first_alias, original);
    assert_eq!(replayed_alias, original);
    assert_eq!(first_alias.current_release_id, None);
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(release.release_id)
    );
    let operation_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM environment_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(operation_count, 2);
}

#[test]
fn environment_retry_returns_original_result_after_release_advances_pointer() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    let command = environment_command(
        ENVIRONMENT_ID,
        ENVIRONMENT_IDEMPOTENCY_KEY,
        "editorial",
        "2026-08-03T18:10:00Z",
    );
    let original = create_environment(&repository, command.clone()).unwrap();
    let release = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();

    assert_eq!(original.current_release_id, None);
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(release.release_id)
    );
    assert_eq!(create_environment(&repository, command).unwrap(), original);
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(release.release_id)
    );
}

#[test]
fn every_pre_localization_version_migrates_without_changing_v1_evidence() {
    for source_version in 1..=10 {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        prepare_exact_pre_v11_fixture(&repository, source_version);
        assert_storage_version(&repository, source_version);
        assert_legacy_effect_columns(&repository, source_version, source_version >= 10);
        let before = legacy_evidence_snapshot(&repository, source_version);

        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();

        assert_latest_schema_and_foreign_keys(&repository);
        assert_operation_effect_columns(&repository);
        assert_legacy_effect_digests(&repository, source_version);
        assert_migrated_legacy_effects_replay(&repository, source_version);
        assert_eq!(
            legacy_evidence_snapshot(&repository, source_version),
            before,
            "v{source_version} legacy evidence changed during migration"
        );
        assert_no_v10_authority_or_release_rows(&repository);
        assert_no_v11_localized_rows(&repository);
    }
}

#[test]
fn version_ten_migration_rolls_back_atomically_after_a_mid_script_failure() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    assert_legacy_effect_columns(&repository, 9, false);
    let before = legacy_evidence_snapshot(&repository, 9);
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_v10_migration
             BEFORE INSERT ON schema_migrations
             WHEN NEW.version = 10
             BEGIN
                 SELECT RAISE(ABORT, 'injected v10 migration failure');
             END;",
        )
        .unwrap();
    let schema_before = storage_schema_snapshot(&repository);

    assert!(matches!(
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }),
        Err(RebuildProjectionsError::Storage(_))
    ));

    let connection = repository.open_database().unwrap();
    let (metadata_version, migration_version): (u32, u32) = connection
        .query_row(
            "SELECT schema_version, (SELECT MAX(version) FROM schema_migrations)
             FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let pragma_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    let v10_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN (
                 'environments', 'environment_versions', 'environment_create_operations',
                 'signing_keys', 'signing_key_revocations', 'release_policy_decisions',
                 'releases', 'environment_current_releases', 'release_proofs',
                 'release_operations', 'release_proof_export_outbox',
                 'principal_registrations',
                 'principal_create_operations', 'delegations',
                 'delegation_grant_operations', 'delegation_revocations',
                 'delegation_revoke_operations', 'context_packs',
                 'context_pack_build_operations'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        (metadata_version, migration_version, pragma_version),
        (9, 9, 9)
    );
    assert_eq!(v10_table_count, 0);
    assert_legacy_effect_columns(&repository, 9, false);
    assert_eq!(storage_schema_snapshot(&repository), schema_before);
    assert_eq!(legacy_evidence_snapshot(&repository, 9), before);
    assert_foreign_keys_clean(&connection);
    connection
        .execute("DROP TRIGGER reject_v10_migration", [])
        .unwrap();
    drop(connection);

    rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert_latest_schema_and_foreign_keys(&repository);
    assert_operation_effect_columns(&repository);
    assert_legacy_effect_digests(&repository, 9);
    inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    inspect_changeset(&repository, OTHER_CHANGESET_ID.parse().unwrap()).unwrap();
    assert_eq!(legacy_evidence_snapshot(&repository, 9), before);
    assert_no_v10_authority_or_release_rows(&repository);
}

#[test]
fn version_eleven_migration_rolls_back_atomically_after_an_injected_failure() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_pre_v11_fixture(&repository, 10);
    assert_storage_version(&repository, 10);
    let before = legacy_evidence_snapshot(&repository, 10);
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_v11_migration
             BEFORE INSERT ON schema_migrations
             WHEN NEW.version = 11
             BEGIN
                 SELECT RAISE(ABORT, 'injected v11 migration failure');
             END;",
        )
        .unwrap();
    let schema_before = storage_schema_snapshot(&repository);

    assert!(matches!(
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }),
        Err(RebuildProjectionsError::Storage(_))
    ));
    assert_storage_version(&repository, 10);
    assert_eq!(storage_schema_snapshot(&repository), schema_before);
    assert_eq!(legacy_evidence_snapshot(&repository, 10), before);
    assert_foreign_keys_clean(&repository.open_database().unwrap());

    let connection = repository.open_database().unwrap();
    let localized_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN (
                 'known_state_artifacts', 'content_resource_intents',
                 'localized_context_packs', 'localized_changesets',
                 'localized_edits', 'object_locale_revisions',
                 'localized_commits', 'localized_edition_metadata',
                 'localized_release_metadata'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(localized_table_count, 0);
    connection
        .execute("DROP TRIGGER reject_v11_migration", [])
        .unwrap();
    drop(connection);

    rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert_latest_schema_and_foreign_keys(&repository);
    assert_eq!(legacy_evidence_snapshot(&repository, 10), before);
    assert_no_v11_localized_rows(&repository);
}

#[test]
fn version_ten_migration_rejects_noncanonical_legacy_operation_key_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_add_operations SET idempotency_key = 'not-a-uuid'
             WHERE changeset_id = ?1",
            [CHANGESET_ID],
        )
        .unwrap();

    assert_v9_migration_rejected_atomically(&repository);
}

#[test]
fn legacy_changeset_aliases_fail_live_replay_and_version_ten_migration_atomically() {
    let uppercase_key = SECOND_DRAFT_IDEMPOTENCY_KEY.to_ascii_uppercase();
    assert_ne!(uppercase_key, SECOND_DRAFT_IDEMPOTENCY_KEY);
    for (name, column, replacement) in [
        (
            "uppercase idempotency key",
            "idempotency_key",
            uppercase_key.as_str(),
        ),
        (
            "whitespace-normalized intent",
            "intent",
            "  Create the legacy article Object  ",
        ),
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        prepare_exact_legacy_fixture(&repository, 9);
        assert_eq!(
            repository
                .open_database()
                .unwrap()
                .execute(
                    &format!("UPDATE changesets SET {column} = ?1 WHERE changeset_id = ?2"),
                    (replacement, OTHER_CHANGESET_ID),
                )
                .unwrap(),
            1
        );
        let schema_before = storage_schema_snapshot(&repository);
        let evidence_before = legacy_evidence_snapshot(&repository, 9);

        let live_retry = create_changeset(
            &repository,
            CreateChangeSetCommand {
                changeset_id: "019c0000-0000-7000-8000-000000000032".parse().unwrap(),
                intent: ChangeSetIntent::new("Create the legacy article Object").unwrap(),
                requested_base_state: None,
                idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
                created_at: "2026-08-03T20:20:00Z".parse().unwrap(),
            },
        );
        assert!(
            matches!(live_retry, Err(CreateChangeSetError::Integrity(_))),
            "v9 live retry of {name} alias returned {live_retry:?}"
        );
        assert_storage_version(&repository, 9);
        assert_legacy_effect_columns(&repository, 9, false);
        assert_eq!(storage_schema_snapshot(&repository), schema_before);
        assert_eq!(legacy_evidence_snapshot(&repository, 9), evidence_before);

        assert_v9_migration_rejected_atomically(&repository);
    }
}

#[test]
fn legacy_add_key_alias_fails_live_replay_and_version_ten_migration_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    let uppercase_key = SECOND_ADD_IDEMPOTENCY_KEY.to_ascii_uppercase();
    assert_ne!(uppercase_key, SECOND_ADD_IDEMPOTENCY_KEY);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE changeset_add_operations SET idempotency_key = ?1
                 WHERE changeset_id = ?2",
                (uppercase_key.as_str(), OTHER_CHANGESET_ID),
            )
            .unwrap(),
        1
    );
    let schema_before = storage_schema_snapshot(&repository);
    let evidence_before = legacy_evidence_snapshot(&repository, 9);

    let live_retry = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![object_edit(
                OBJECT_EDIT_ID,
                OBJECT_ID,
                "article",
                &serde_json::json!({"title": "Legacy migration"}),
            )],
            idempotency_key: SECOND_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    );
    assert!(
        matches!(live_retry, Err(AddChangeSetEditsError::Integrity(_))),
        "v9 live Add retry of uppercase key alias returned {live_retry:?}"
    );
    assert_storage_version(&repository, 9);
    assert_legacy_effect_columns(&repository, 9, false);
    assert_eq!(storage_schema_snapshot(&repository), schema_before);
    assert_eq!(legacy_evidence_snapshot(&repository, 9), evidence_before);

    assert_v9_migration_rejected_atomically(&repository);
}

#[test]
fn legacy_edition_operation_aliases_fail_live_replay_and_migration_atomically() {
    for source_version in [8, 9] {
        let (edition_id, idempotency_key, created_at) = if source_version == 8 {
            (EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z")
        } else {
            (
                OTHER_EDITION_ID,
                SECOND_EDITION_IDEMPOTENCY_KEY,
                "2026-08-03T20:10:00Z",
            )
        };
        let uppercase_key = idempotency_key.to_ascii_uppercase();
        let uppercase_edition_id = edition_id.to_ascii_uppercase();
        assert_ne!(uppercase_key, idempotency_key);
        assert_ne!(uppercase_edition_id, edition_id);

        for alias in ["key", "identity"] {
            let directory = TestDirectory::new();
            let repository = initialized_repository(&directory);
            prepare_exact_legacy_fixture(&repository, source_version);
            let connection = repository.open_database().unwrap();
            if alias == "key" {
                assert_eq!(
                    connection
                        .execute(
                            "UPDATE edition_create_operations SET idempotency_key = ?1
                             WHERE edition_id = ?2",
                            (uppercase_key.as_str(), edition_id),
                        )
                        .unwrap(),
                    1
                );
            } else {
                connection
                    .pragma_update(None, "foreign_keys", false)
                    .unwrap();
                assert_eq!(
                    connection
                        .execute(
                            "UPDATE editions SET edition_id = ?1 WHERE edition_id = ?2",
                            (uppercase_edition_id.as_str(), edition_id),
                        )
                        .unwrap(),
                    1
                );
                assert_eq!(
                    connection
                        .execute(
                            "UPDATE edition_create_operations SET edition_id = ?1
                             WHERE edition_id = ?2",
                            (uppercase_edition_id.as_str(), edition_id),
                        )
                        .unwrap(),
                    1
                );
                connection
                    .pragma_update(None, "foreign_keys", true)
                    .unwrap();
            }
            assert_foreign_keys_clean(&connection);
            drop(connection);
            let schema_before = storage_schema_snapshot(&repository);
            let evidence_before = legacy_evidence_snapshot(&repository, source_version);

            let live_replay = create_edition(
                &repository,
                edition_command(edition_id, idempotency_key, created_at),
            );
            assert!(
                matches!(live_replay, Err(CreateEditionError::Integrity(_))),
                "v{source_version} live Edition replay of uppercase {alias} alias returned {live_replay:?}"
            );
            assert_storage_version(&repository, source_version);
            assert_legacy_effect_columns(&repository, source_version, false);
            assert_eq!(storage_schema_snapshot(&repository), schema_before);
            assert_eq!(
                legacy_evidence_snapshot(&repository, source_version),
                evidence_before
            );

            assert_legacy_migration_rejected_atomically(&repository, source_version);
        }
    }
}

#[test]
fn version_ten_migration_rejects_orphan_legacy_edits_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "DELETE FROM changeset_add_operations WHERE changeset_id = ?1",
                [OTHER_CHANGESET_ID],
            )
            .unwrap(),
        1
    );

    assert_v9_migration_rejected_atomically(&repository);
}

#[test]
fn version_ten_migration_rejects_committed_lifecycle_without_commit_provenance() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "DELETE FROM changeset_commits WHERE changeset_id = ?1",
                [OTHER_CHANGESET_ID],
            )
            .unwrap(),
        1
    );
    let persisted_state: (String, i64, i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT lifecycle_status,
                    (SELECT authoritative_sequence FROM known_state WHERE singleton = 1),
                    (SELECT COUNT(*) FROM schema_versions),
                    (SELECT COUNT(*) FROM object_revisions)
             FROM changesets WHERE changeset_id = ?1",
            [OTHER_CHANGESET_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(persisted_state, ("committed".to_owned(), 2, 1, 1));

    assert_v9_migration_rejected_atomically(&repository);
    let schema_before_edition = storage_schema_snapshot(&repository);
    let evidence_before_edition = legacy_evidence_snapshot(&repository, 9);
    let attempted_edition = create_edition(
        &repository,
        edition_command(
            "019c0000-0000-7000-8000-000000000062",
            "019c0000-0000-7000-8000-000000000072",
            "2026-08-03T20:20:00Z",
        ),
    );
    assert!(
        matches!(attempted_edition, Err(CreateEditionError::Integrity(_))),
        "missing legacy commit provenance returned {attempted_edition:?}"
    );
    assert_storage_version(&repository, 9);
    assert_legacy_effect_columns(&repository, 9, false);
    assert_eq!(storage_schema_snapshot(&repository), schema_before_edition);
    assert_eq!(
        legacy_evidence_snapshot(&repository, 9),
        evidence_before_edition
    );
    assert_foreign_keys_clean(&repository.open_database().unwrap());
}

#[test]
fn version_ten_migration_rejects_legacy_edition_created_before_its_latest_commit() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE editions SET created_at = '2026-08-03T19:59:59Z'
                 WHERE edition_id = ?1",
                [OTHER_EDITION_ID],
            )
            .unwrap(),
        1
    );

    assert_v9_migration_rejected_atomically(&repository);
}

#[test]
fn failed_pre_v10_reads_do_not_persist_reachable_migration_side_effects() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    let schema_before = storage_schema_snapshot(&repository);
    let evidence_before = legacy_evidence_snapshot(&repository, 9);

    assert_eq!(
        delegated_workspace_status(
            &repository,
            DelegatedWorkspaceStatusCommand {
                operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                delegation_id: DELEGATION_ID.parse().unwrap(),
                evaluated_at: "2026-08-03T20:20:00Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        DelegatedWorkspaceStatusError::Denied
    );
    assert_storage_version(&repository, 9);
    assert_eq!(storage_schema_snapshot(&repository), schema_before);
    assert_eq!(legacy_evidence_snapshot(&repository, 9), evidence_before);

    assert_eq!(
        query_released_objects(
            &repository,
            QueryReleasedObjectsCommand {
                operating_principal_id: None,
                delegation_id: None,
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                evaluated_at: "2026-08-03T20:20:00Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        QueryReleasedObjectsError::NotFound
    );
    assert_storage_version(&repository, 9);
    assert_eq!(storage_schema_snapshot(&repository), schema_before);
    assert_eq!(legacy_evidence_snapshot(&repository, 9), evidence_before);
}

#[test]
fn projection_rebuild_reports_dry_run_drift_and_repairs_malformed_derived_rows() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    let committed = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let valid_schema_digest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT document_digest FROM schema_versions
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let malformed_digest = format!("blake3:{}", "f".repeat(64));
    assert_ne!(malformed_digest, valid_schema_digest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE schema_versions SET document_digest = ?1
             WHERE schema_id = 'article' AND schema_version = 1",
            [malformed_digest.as_str()],
        )
        .unwrap();

    let dry_run =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(dry_run.dry_run);
    assert!(dry_run.changed);
    assert_eq!(dry_run.authoritative_sequence, 2);
    assert_eq!(dry_run.state_digest, committed.resulting_state);
    assert_eq!(dry_run.schema_count, 1);
    assert_eq!(dry_run.object_count, 1);
    assert_eq!(dry_run.environment_pointer_count, 0);
    let after_dry_run: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT document_digest FROM schema_versions
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(after_dry_run, malformed_digest);

    let repaired =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(!repaired.dry_run);
    assert!(repaired.changed);
    assert_eq!(repaired.state_digest, committed.resulting_state);
    let connection = repository.open_database().unwrap();
    let repaired_schema_digest: String = connection
        .query_row(
            "SELECT document_digest FROM schema_versions
             WHERE schema_id = 'article' AND schema_version = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(repaired_schema_digest, valid_schema_digest);
    drop(connection);
    let clean =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(!clean.changed);
}

#[test]
fn legacy_projection_rebuild_migrates_v8_then_repairs_schema_and_known_state() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 8);
    let pristine = legacy_evidence_snapshot(&repository, 8);
    let expected_state: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT resulting_state FROM changeset_commits
             ORDER BY authoritative_sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let drifted_schema = canonicalize(&serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Drifted legacy projection",
        "type": "object",
    }))
    .unwrap();
    let drifted_schema_digest = digest(ArtifactKind::SchemaVersionV1, &drifted_schema);
    let drifted_state = format!("blake3:{}", "f".repeat(64));
    assert_ne!(drifted_state, expected_state);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE schema_versions
             SET document_json = ?1, document_digest = ?2, authoritative_sequence = 77
             WHERE schema_id = 'article' AND schema_version = 1",
            (drifted_schema.as_str(), drifted_schema_digest.to_string()),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE known_state
             SET authoritative_sequence = 77, state_digest = ?1
             WHERE singleton = 1",
            [drifted_state.as_str()],
        )
        .unwrap();
    let drifted = legacy_evidence_snapshot(&repository, 8);
    assert_legacy_authority_unchanged(&pristine, &drifted);

    let dry_run =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(dry_run.dry_run);
    assert!(dry_run.changed);
    assert_eq!(dry_run.authoritative_sequence, 1);
    assert_eq!(dry_run.state_digest.to_string(), expected_state);
    assert_eq!(dry_run.schema_count, 1);
    assert_eq!(dry_run.object_count, 0);
    assert_eq!(dry_run.environment_pointer_count, 0);
    assert_storage_version(&repository, 11);
    assert_operation_effect_columns(&repository);
    assert_legacy_effect_digests(&repository, 8);
    let after_dry_run = legacy_evidence_snapshot(&repository, 8);
    assert_eq!(after_dry_run, drifted);
    assert_legacy_authority_unchanged(&pristine, &after_dry_run);
    assert_foreign_keys_clean(&repository.open_database().unwrap());

    let repaired =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(!repaired.dry_run);
    assert!(repaired.changed);
    assert_eq!(repaired.authoritative_sequence, 1);
    assert_eq!(repaired.state_digest.to_string(), expected_state);
    assert_eq!(repaired.schema_count, 1);
    assert_eq!(repaired.object_count, 0);
    assert_eq!(legacy_evidence_snapshot(&repository, 8), pristine);
    assert_latest_schema_and_foreign_keys(&repository);
    assert_migrated_legacy_effects_replay(&repository, 8);
    assert_no_v10_authority_or_release_rows(&repository);
    assert!(
        !rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
}

#[test]
fn legacy_projection_rebuild_migrates_v9_then_repairs_object_and_known_state() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_exact_legacy_fixture(&repository, 9);
    let pristine = legacy_evidence_snapshot(&repository, 9);
    let expected_state: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT resulting_state FROM changeset_commits
             ORDER BY authoritative_sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let drifted_content = canonicalize(&serde_json::json!({
        "title": "Drifted legacy Object projection",
    }))
    .unwrap();
    let drifted_object_digest = object_revision_digest(
        OBJECT_ID.parse().unwrap(),
        &SchemaId::new("article").unwrap(),
        SchemaVersion::new(1).unwrap(),
        &serde_json::json!({"title": "Drifted legacy Object projection"}),
    )
    .unwrap();
    let drifted_state = format!("blake3:{}", "f".repeat(64));
    assert_ne!(drifted_state, expected_state);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE object_revisions
             SET content_json = ?1, object_digest = ?2, authoritative_sequence = 77
             WHERE object_id = ?3 AND revision = 1",
            (
                drifted_content.as_str(),
                drifted_object_digest.to_string(),
                OBJECT_ID,
            ),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE known_state
             SET authoritative_sequence = 77, state_digest = ?1
             WHERE singleton = 1",
            [drifted_state.as_str()],
        )
        .unwrap();
    let drifted = legacy_evidence_snapshot(&repository, 9);
    assert_legacy_authority_unchanged(&pristine, &drifted);

    let dry_run =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(dry_run.dry_run);
    assert!(dry_run.changed);
    assert_eq!(dry_run.authoritative_sequence, 2);
    assert_eq!(dry_run.state_digest.to_string(), expected_state);
    assert_eq!(dry_run.schema_count, 1);
    assert_eq!(dry_run.object_count, 1);
    assert_eq!(dry_run.environment_pointer_count, 0);
    assert_storage_version(&repository, 11);
    assert_operation_effect_columns(&repository);
    assert_legacy_effect_digests(&repository, 9);
    let after_dry_run = legacy_evidence_snapshot(&repository, 9);
    assert_eq!(after_dry_run, drifted);
    assert_legacy_authority_unchanged(&pristine, &after_dry_run);
    assert_foreign_keys_clean(&repository.open_database().unwrap());

    let repaired =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(!repaired.dry_run);
    assert!(repaired.changed);
    assert_eq!(repaired.authoritative_sequence, 2);
    assert_eq!(repaired.state_digest.to_string(), expected_state);
    assert_eq!(repaired.schema_count, 1);
    assert_eq!(repaired.object_count, 1);
    assert_eq!(legacy_evidence_snapshot(&repository, 9), pristine);
    assert_latest_schema_and_foreign_keys(&repository);
    assert_migrated_legacy_effects_replay(&repository, 9);
    assert_no_v10_authority_or_release_rows(&repository);
    assert!(
        !rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
}

#[test]
fn projection_rebuild_rejects_lifecycle_effect_tamper_without_repairing_projections() {
    struct TamperCase {
        name: &'static str,
        table: &'static str,
        column: &'static str,
        replacement: &'static str,
    }

    for case in [
        TamperCase {
            name: "submission timestamp",
            table: "changeset_submissions",
            column: "submitted_at",
            replacement: "2026-08-03T15:00:01Z",
        },
        TamperCase {
            name: "approval timestamp",
            table: "changeset_approvals",
            column: "approved_at",
            replacement: "2026-08-03T16:00:01Z",
        },
        TamperCase {
            name: "commit idempotency key",
            table: "changeset_commits",
            column: "idempotency_key",
            replacement: COMMIT_SWAP_IDEMPOTENCY_KEY,
        },
        TamperCase {
            name: "commit timestamp",
            table: "changeset_commits",
            column: "committed_at",
            replacement: "2026-08-03T17:00:01Z",
        },
    ] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        prepare_first_mixed_release(&repository);
        assert_storage_version(&repository, 11);

        let connection = repository.open_database().unwrap();
        let effect_query = format!(
            "SELECT effect_digest FROM {} WHERE changeset_id = ?1",
            case.table
        );
        let value_query = format!(
            "SELECT {} FROM {} WHERE changeset_id = ?1",
            case.column, case.table
        );
        let effect_before: String = connection
            .query_row(&effect_query, [CHANGESET_ID], |row| row.get(0))
            .unwrap();
        let value_before: String = connection
            .query_row(&value_query, [CHANGESET_ID], |row| row.get(0))
            .unwrap();
        assert_ne!(value_before, case.replacement, "{} fixture", case.name);
        assert_eq!(
            connection
                .execute(
                    &format!(
                        "UPDATE {} SET {} = ?1 WHERE changeset_id = ?2",
                        case.table, case.column
                    ),
                    (case.replacement, CHANGESET_ID),
                )
                .unwrap(),
            1
        );
        let effect_after: String = connection
            .query_row(&effect_query, [CHANGESET_ID], |row| row.get(0))
            .unwrap();
        assert_eq!(effect_after, effect_before, "{} effect changed", case.name);
        drop(connection);

        let before_rebuild = rebuild_lifecycle_guard_snapshot(&repository);
        for dry_run in [true, false] {
            let rebuilt = rebuild_projections(&repository, RebuildProjectionsCommand { dry_run });
            assert!(
                matches!(rebuilt, Err(RebuildProjectionsError::Integrity(_))),
                "{} rebuild dry_run={dry_run} returned {rebuilt:?}",
                case.name
            );
            assert_eq!(
                rebuild_lifecycle_guard_snapshot(&repository),
                before_rebuild,
                "{} rebuild dry_run={dry_run} changed authoritative evidence or projections",
                case.name
            );
        }
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the single missing-commit fixture proves every required local, delegated, Edition, and rebuild fan-in without duplicating setup"
)]
fn committed_state_consumers_reject_missing_commit_evidence_without_repairing_projections() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_agent_principal(
        &repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "status-reader",
            "2026-08-03T17:10:00Z",
        ),
    )
    .unwrap();
    grant_delegation(
        &repository,
        GrantDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            recipient_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
            actions: vec![DelegatedAction::WorkspaceStatus],
            scope: DelegationScope {
                workspace_id: WORKSPACE_ID.parse().unwrap(),
                environment_ids: Vec::new(),
                object_ids: Vec::new(),
            },
            constraints: DelegationConstraints {
                max_objects: 1,
                max_context_bytes: 4_096,
                allow_subdelegation: false,
            },
            not_before: "2026-08-03T18:00:00Z".parse().unwrap(),
            expires_at: "2026-08-03T20:00:00Z".parse().unwrap(),
            idempotency_key: DELEGATION_IDEMPOTENCY_KEY.parse().unwrap(),
            issued_at: "2026-08-03T17:15:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "DELETE FROM changeset_commits WHERE changeset_id = ?1",
                [CHANGESET_ID],
            )
            .unwrap(),
        1
    );
    let persisted_state: (String, i64, i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT lifecycle_status,
                    (SELECT authoritative_sequence FROM known_state WHERE singleton = 1),
                    (SELECT COUNT(*) FROM schema_versions),
                    (SELECT COUNT(*) FROM object_revisions)
             FROM changesets WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(persisted_state, ("committed".to_owned(), 2, 1, 1));
    let state_before = rebuild_lifecycle_guard_snapshot(&repository);
    let editions_before = edition_write_snapshot(&repository);
    let delegation_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT d.delegation_id, d.delegation_digest,
                o.idempotency_key, o.request_digest, o.effect_digest
         FROM delegations d
         JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
         ORDER BY d.delegation_id",
    );

    assert!(matches!(
        workspace_status(&repository),
        Err(WorkspaceStatusError::Integrity(_))
    ));
    assert_eq!(rebuild_lifecycle_guard_snapshot(&repository), state_before);
    assert_eq!(edition_write_snapshot(&repository), editions_before);

    let attempted_draft = create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Must not extend state with missing commit provenance")
                .unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:20:00Z".parse().unwrap(),
        },
    );
    assert!(
        matches!(attempted_draft, Err(CreateChangeSetError::Integrity(_))),
        "draft creation without the current commit chain returned {attempted_draft:?}"
    );
    assert_eq!(rebuild_lifecycle_guard_snapshot(&repository), state_before);
    assert_eq!(edition_write_snapshot(&repository), editions_before);

    let delegated_status = delegated_workspace_status(
        &repository,
        DelegatedWorkspaceStatusCommand {
            operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
            delegation_id: DELEGATION_ID.parse().unwrap(),
            evaluated_at: "2026-08-03T18:30:00Z".parse().unwrap(),
        },
    );
    assert!(
        matches!(
            delegated_status,
            Err(DelegatedWorkspaceStatusError::Integrity(_))
        ),
        "delegated status without commit provenance returned {delegated_status:?}"
    );
    assert_eq!(rebuild_lifecycle_guard_snapshot(&repository), state_before);
    assert_eq!(edition_write_snapshot(&repository), editions_before);
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT d.delegation_id, d.delegation_digest,
                    o.idempotency_key, o.request_digest, o.effect_digest
             FROM delegations d
             JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
             ORDER BY d.delegation_id",
        ),
        delegation_before
    );

    let attempted_edition = create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    );
    assert!(
        matches!(attempted_edition, Err(CreateEditionError::Integrity(_))),
        "Edition creation without commit provenance returned {attempted_edition:?}"
    );
    assert_eq!(rebuild_lifecycle_guard_snapshot(&repository), state_before);
    assert_eq!(edition_write_snapshot(&repository), editions_before);

    for dry_run in [true, false] {
        let rebuilt = rebuild_projections(&repository, RebuildProjectionsCommand { dry_run });
        assert!(
            matches!(rebuilt, Err(RebuildProjectionsError::Integrity(_))),
            "missing commit rebuild dry_run={dry_run} returned {rebuilt:?}"
        );
        assert_eq!(rebuild_lifecycle_guard_snapshot(&repository), state_before);
        assert_eq!(edition_write_snapshot(&repository), editions_before);
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT d.delegation_id, d.delegation_digest,
                        o.idempotency_key, o.request_digest, o.effect_digest
                 FROM delegations d
                 JOIN delegation_grant_operations o ON o.delegation_id = d.delegation_id
                 ORDER BY d.delegation_id",
            ),
            delegation_before
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the forged evidence chain is intentionally explicit so semantic revalidation, not a broken digest link, is the tested failure"
)]
fn projection_rebuild_rejects_consistently_redigested_invalid_authoritative_content_atomically() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let mut tampered = inspect_changeset(&repository, CHANGESET_ID.parse().unwrap()).unwrap();
    let invalid_content = serde_json::json!({"title": 42});
    let invalid_canonical = canonicalize(&invalid_content).unwrap();
    let invalid_object_digest = object_revision_digest(
        OBJECT_ID.parse().unwrap(),
        &SchemaId::new("article").unwrap(),
        SchemaVersion::new(1).unwrap(),
        &invalid_content,
    )
    .unwrap();
    for edit in &mut tampered.edits {
        if let InspectedChangeSetEdit::ObjectCreate(edit) = edit {
            edit.canonical_content = invalid_canonical.as_str().to_owned();
            edit.object_digest = invalid_object_digest;
        }
    }
    let changeset_digest = test_changeset_digest(&tampered);
    let edit_batch_digest = test_edit_batch_digest(&tampered);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE changeset_edits SET document_json = ?1, document_digest = ?2
             WHERE changeset_id = ?3 AND edit_id = ?4",
            (
                invalid_canonical.as_str(),
                invalid_object_digest.to_string(),
                CHANGESET_ID,
                OBJECT_EDIT_ID,
            ),
        )
        .unwrap();
    let validator: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT validator FROM changeset_validations WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| row.get(0),
        )
        .unwrap();
    let forged_validation = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/validation-results/v1",
        "base_state": tampered.base_state.to_string(),
        "changeset_digest": changeset_digest.to_string(),
        "changeset_id": CHANGESET_ID,
        "findings": [],
        "valid": true,
        "validation_profile": tampered.validation_profile,
        "validator": validator,
    }))
    .unwrap();
    let validation_digest = digest(ArtifactKind::ValidationResultsV1, &forged_validation);
    let schema_digest = tampered
        .edits
        .iter()
        .find_map(|edit| match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => Some(edit.document_digest),
            InspectedChangeSetEdit::ObjectCreate(_) => None,
        })
        .unwrap();
    let forged_state = known_state_digest_with_objects(
        WORKSPACE_ID.parse().unwrap(),
        2,
        &[(
            SchemaId::new("article").unwrap(),
            SchemaVersion::new(1).unwrap(),
            schema_digest,
        )],
        &[ObjectStateReference {
            object_id: OBJECT_ID.parse().unwrap(),
            revision: ObjectRevision::new(1).unwrap(),
            schema_id: SchemaId::new("article").unwrap(),
            schema_version: SchemaVersion::new(1).unwrap(),
            lifecycle_state: ObjectLifecycleState::Active,
            object_digest: invalid_object_digest,
        }],
    )
    .unwrap();
    let malformed_projection_digest = format!("blake3:{}", "e".repeat(64));
    let mut connection = repository.open_database().unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute(
            "UPDATE changeset_add_operations SET request_digest = ?1
             WHERE changeset_id = ?2",
            (edit_batch_digest.to_string(), CHANGESET_ID),
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE changeset_validations
             SET changeset_digest = ?1, valid = 1, results_json = ?2, results_digest = ?3
             WHERE changeset_id = ?4",
            (
                changeset_digest.to_string(),
                forged_validation.as_str(),
                validation_digest.to_string(),
                CHANGESET_ID,
            ),
        )
        .unwrap();
    for table in ["changeset_submissions", "changeset_approvals"] {
        transaction
            .execute(
                &format!(
                    "UPDATE {table} SET changeset_digest = ?1, validation_results_digest = ?2
                     WHERE changeset_id = ?3"
                ),
                (
                    changeset_digest.to_string(),
                    validation_digest.to_string(),
                    CHANGESET_ID,
                ),
            )
            .unwrap();
    }
    transaction
        .execute(
            "UPDATE changeset_commits
             SET changeset_digest = ?1, validation_results_digest = ?2, resulting_state = ?3
             WHERE changeset_id = ?4",
            (
                changeset_digest.to_string(),
                validation_digest.to_string(),
                forged_state.to_string(),
                CHANGESET_ID,
            ),
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE known_state SET authoritative_sequence = 2, state_digest = ?1
             WHERE singleton = 1",
            [forged_state.to_string()],
        )
        .unwrap();
    transaction
        .execute(
            "UPDATE schema_versions SET document_digest = ?1
             WHERE schema_id = 'article' AND schema_version = 1",
            [malformed_projection_digest.as_str()],
        )
        .unwrap();
    transaction.commit().unwrap();
    drop(connection);

    assert!(matches!(
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false },),
        Err(RebuildProjectionsError::Integrity(_))
    ));
    let connection = repository.open_database().unwrap();
    let (persisted_schema_digest, persisted_object_content, persisted_state): (
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT
                 (SELECT document_digest FROM schema_versions
                  WHERE schema_id = 'article' AND schema_version = 1),
                 (SELECT content_json FROM object_revisions WHERE object_id = ?1),
                 (SELECT state_digest FROM known_state WHERE singleton = 1)",
            [OBJECT_ID],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(persisted_schema_digest, malformed_projection_digest);
    assert_eq!(persisted_object_content, r#"{"title":"Projection proof"}"#);
    assert_eq!(persisted_state, forged_state.to_string());
}

#[test]
fn agent_replay_rejects_self_consistent_registration_provenance_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let command = agent_command(
        AGENT_PRINCIPAL_ID,
        AGENT_IDEMPOTENCY_KEY,
        "release-reader",
        "2026-08-03T17:10:00Z",
    );
    create_agent_principal(&repository, command.clone()).unwrap();
    let operation_before: (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT request_digest, created_principal_id FROM principal_create_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let registration = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/principal-registration/v1",
        "created_at": "2026-08-03T17:11:00Z",
        "created_by_principal_id": AGENT_PRINCIPAL_ID,
        "display_name": "forged-reader",
        "principal_id": AGENT_PRINCIPAL_ID,
        "principal_type": "agent",
        "workspace_id": WORKSPACE_ID,
    }))
    .unwrap();
    let registration_digest = digest(ArtifactKind::PrincipalRegistrationV1, &registration);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE principal_registrations
             SET registered_by_principal_id = ?1, display_name = 'forged-reader',
                 registration_json = ?2, registration_digest = ?3,
                 created_at = '2026-08-03T17:11:00Z'
             WHERE principal_id = ?1",
            (
                AGENT_PRINCIPAL_ID,
                registration.as_str(),
                registration_digest.to_string(),
            ),
        )
        .unwrap();

    assert!(matches!(
        create_agent_principal(&repository, command),
        Err(PrincipalError::Integrity(_))
    ));
    assert!(matches!(
        get_agent_principal(&repository, AGENT_PRINCIPAL_ID.parse().unwrap()),
        Err(PrincipalError::Integrity(_))
    ));
    assert!(matches!(
        grant_delegation(
            &repository,
            GrantDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                recipient_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                actions: vec![DelegatedAction::WorkspaceStatus],
                scope: DelegationScope {
                    workspace_id: WORKSPACE_ID.parse().unwrap(),
                    environment_ids: Vec::new(),
                    object_ids: Vec::new(),
                },
                constraints: DelegationConstraints {
                    max_objects: 1,
                    max_context_bytes: 4_096,
                    allow_subdelegation: false,
                },
                not_before: "2026-08-03T18:00:00Z".parse().unwrap(),
                expires_at: "2026-08-03T20:00:00Z".parse().unwrap(),
                idempotency_key: DELEGATION_IDEMPOTENCY_KEY.parse().unwrap(),
                issued_at: "2026-08-03T17:15:00Z".parse().unwrap(),
            },
        ),
        Err(DelegationError::Integrity(_))
    ));
    let operation_after: (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT request_digest, created_principal_id FROM principal_create_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(operation_after, operation_before);
}

#[test]
fn agent_consumers_reject_created_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let command = agent_command(
        AGENT_PRINCIPAL_ID,
        AGENT_IDEMPOTENCY_KEY,
        "release-reader",
        "2026-08-03T17:10:00Z",
    );
    create_agent_principal(&repository, command.clone()).unwrap();
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM principal_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let registration = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/principal-registration/v1",
        "created_at": "2026-08-03T17:11:00Z",
        "created_by_principal_id": PRINCIPAL_ID,
        "display_name": "release-reader",
        "principal_id": AGENT_PRINCIPAL_ID,
        "principal_type": "agent",
        "workspace_id": WORKSPACE_ID,
    }))
    .unwrap();
    let registration_digest = digest(ArtifactKind::PrincipalRegistrationV1, &registration);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE principal_registrations
             SET registration_json = ?1, registration_digest = ?2,
                 created_at = '2026-08-03T17:11:00Z'
             WHERE principal_id = ?3",
            (
                registration.as_str(),
                registration_digest.to_string(),
                AGENT_PRINCIPAL_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        create_agent_principal(&repository, command),
        Err(PrincipalError::Integrity(_))
    ));
    assert!(matches!(
        get_agent_principal(&repository, AGENT_PRINCIPAL_ID.parse().unwrap()),
        Err(PrincipalError::Integrity(_))
    ));
    assert!(matches!(
        grant_delegation(
            &repository,
            GrantDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                recipient_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                actions: vec![DelegatedAction::WorkspaceStatus],
                scope: DelegationScope {
                    workspace_id: WORKSPACE_ID.parse().unwrap(),
                    environment_ids: Vec::new(),
                    object_ids: Vec::new(),
                },
                constraints: DelegationConstraints {
                    max_objects: 1,
                    max_context_bytes: 4_096,
                    allow_subdelegation: false,
                },
                not_before: "2026-08-03T18:00:00Z".parse().unwrap(),
                expires_at: "2026-08-03T20:00:00Z".parse().unwrap(),
                idempotency_key: DELEGATION_IDEMPOTENCY_KEY.parse().unwrap(),
                issued_at: "2026-08-03T17:15:00Z".parse().unwrap(),
            },
        ),
        Err(DelegationError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM principal_create_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn principal_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    create_agent_principal(
        &repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "release-agent",
            "2026-08-03T17:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE principal_create_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY, AGENT_IDEMPOTENCY_KEY),
            )
            .unwrap(),
        1
    );
    let registrations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT p.principal_id, p.principal_type, p.identity_provider, p.identity_subject,
                p.enabled, r.workspace_id, r.registered_by_principal_id, r.display_name,
                r.registration_json, r.registration_digest, r.created_at
         FROM principals p
         LEFT JOIN principal_registrations r ON r.principal_id = p.principal_id
         ORDER BY p.principal_id",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                effect_digest, created_principal_id
         FROM principal_create_operations ORDER BY created_principal_id",
    );

    let retry = create_agent_principal(
        &repository,
        agent_command(
            OTHER_AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "release-agent",
            "2026-08-03T17:01:00Z",
        ),
    );
    assert!(
        matches!(retry, Err(PrincipalError::Integrity(_))),
        "missing-key Principal retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT p.principal_id, p.principal_type, p.identity_provider, p.identity_subject,
                    p.enabled, r.workspace_id, r.registered_by_principal_id, r.display_name,
                    r.registration_json, r.registration_digest, r.created_at
             FROM principals p
             LEFT JOIN principal_registrations r ON r.principal_id = p.principal_id
             ORDER BY p.principal_id",
        ),
        registrations_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                    effect_digest, created_principal_id
             FROM principal_create_operations ORDER BY created_principal_id",
        ),
        operations_before
    );
}

#[test]
fn delegation_replay_and_authorization_reject_self_consistent_scope_widening() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    let command = delegation_command(
        DELEGATION_ID,
        DELEGATION_IDEMPOTENCY_KEY,
        "2026-08-03T17:15:00Z",
    );
    grant_delegation(&repository, command.clone()).unwrap();
    let action_values = vec![
        DelegatedAction::WorkspaceStatus.to_string(),
        DelegatedAction::ObjectQueryReleased.to_string(),
        DelegatedAction::ContextBuild.to_string(),
    ];
    let actions_json = canonicalize(&serde_json::json!(action_values.clone())).unwrap();
    let manifest = canonicalize(&serde_json::json!({
        "actions": action_values,
        "api_version": "proof.dev/delegation/v1",
        "constraints": {
            "allow_subdelegation": false,
            "max_context_bytes": 4_096,
            "max_objects": 1,
        },
        "delegation_id": DELEGATION_ID,
        "expires_at": "2026-08-03T20:00:00Z",
        "issued_at": "2026-08-03T17:15:00Z",
        "issuer_principal_id": PRINCIPAL_ID,
        "not_before": "2026-08-03T18:00:00Z",
        "recipient_principal_id": AGENT_PRINCIPAL_ID,
        "scope": {
            "environment_ids": [ENVIRONMENT_ID],
            "object_ids": [OBJECT_ID],
            "workspace_id": WORKSPACE_ID,
        },
    }))
    .unwrap();
    let delegation_digest = digest(ArtifactKind::DelegationV1, &manifest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE delegations SET actions_json = ?1, manifest_json = ?2,
                    delegation_digest = ?3
             WHERE delegation_id = ?4",
            (
                actions_json.as_str(),
                manifest.as_str(),
                delegation_digest.to_string(),
                DELEGATION_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        grant_delegation(&repository, command),
        Err(DelegationError::Integrity(_))
    ));
    assert!(matches!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                action: DelegatedAction::ContextBuild,
                environment_id: Some(ENVIRONMENT_ID.parse().unwrap()),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                evaluated_at: "2026-08-03T18:30:00Z".parse().unwrap(),
            },
        ),
        Err(DelegationError::Integrity(_))
    ));
}

#[test]
fn delegation_consumers_reject_issued_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    let command = delegation_command(
        DELEGATION_ID,
        DELEGATION_IDEMPOTENCY_KEY,
        "2026-08-03T17:15:00Z",
    );
    grant_delegation(&repository, command.clone()).unwrap();
    let connection = repository.open_database().unwrap();
    let (effect_before, manifest_json): (String, String) = connection
        .query_row(
            "SELECT o.effect_digest, d.manifest_json
             FROM delegation_grant_operations o
             JOIN delegations d ON d.delegation_id = o.delegation_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut manifest = serde_json::from_str::<serde_json::Value>(&manifest_json).unwrap();
    manifest["issued_at"] = serde_json::json!("2026-08-03T17:16:00Z");
    let manifest = canonicalize(&manifest).unwrap();
    let delegation_digest = digest(ArtifactKind::DelegationV1, &manifest);
    connection
        .execute(
            "UPDATE delegations SET issued_at = '2026-08-03T17:16:00Z',
                    manifest_json = ?1, delegation_digest = ?2
             WHERE delegation_id = ?3",
            (
                manifest.as_str(),
                delegation_digest.to_string(),
                DELEGATION_ID,
            ),
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        grant_delegation(&repository, command),
        Err(DelegationError::Integrity(_))
    ));
    assert!(matches!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                action: DelegatedAction::WorkspaceStatus,
                environment_id: None,
                object_ids: Vec::new(),
                evaluated_at: "2026-08-03T18:30:00Z".parse().unwrap(),
            },
        ),
        Err(DelegationError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM delegation_grant_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn delegation_grant_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    grant_delegation(
        &repository,
        delegation_command(
            DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:15:00Z",
        ),
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE delegation_grant_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
                    DELEGATION_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    let delegations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT delegation_id, workspace_id, issuer_principal_id, recipient_principal_id,
                actions_json, environment_ids_json, object_ids_json, max_objects,
                max_context_bytes, allow_subdelegation, not_before, expires_at,
                manifest_json, delegation_digest, issued_at
         FROM delegations ORDER BY delegation_id",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                effect_digest, delegation_id
         FROM delegation_grant_operations ORDER BY delegation_id",
    );

    let retry = grant_delegation(
        &repository,
        delegation_command(
            OTHER_DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:16:00Z",
        ),
    );
    assert!(
        matches!(retry, Err(DelegationError::Integrity(_))),
        "missing-key Delegation grant retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT delegation_id, workspace_id, issuer_principal_id, recipient_principal_id,
                    actions_json, environment_ids_json, object_ids_json, max_objects,
                    max_context_bytes, allow_subdelegation, not_before, expires_at,
                    manifest_json, delegation_digest, issued_at
             FROM delegations ORDER BY delegation_id",
        ),
        delegations_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                    effect_digest, delegation_id
             FROM delegation_grant_operations ORDER BY delegation_id",
        ),
        operations_before
    );
}

#[test]
fn revocation_consumers_reject_revoked_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    grant_delegation(
        &repository,
        delegation_command(
            DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:15:00Z",
        ),
    )
    .unwrap();
    let command = RevokeDelegationCommand {
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
        revoked_at: "2026-08-03T18:45:00Z".parse().unwrap(),
    };
    revoke_delegation(&repository, command).unwrap();
    let connection = repository.open_database().unwrap();
    let (effect_before, revocation_json): (String, String) = connection
        .query_row(
            "SELECT o.effect_digest, r.revocation_json
             FROM delegation_revoke_operations o
             JOIN delegation_revocations r ON r.delegation_id = o.delegation_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut revocation = serde_json::from_str::<serde_json::Value>(&revocation_json).unwrap();
    revocation["revoked_at"] = serde_json::json!("2026-08-03T18:30:00Z");
    let revocation = canonicalize(&revocation).unwrap();
    let revocation_digest = digest(ArtifactKind::DelegationV1, &revocation);
    connection
        .execute(
            "UPDATE delegation_revocations
             SET revoked_at = '2026-08-03T18:30:00Z', revocation_json = ?1,
                 revocation_digest = ?2
             WHERE delegation_id = ?3",
            (
                revocation.as_str(),
                revocation_digest.to_string(),
                DELEGATION_ID,
            ),
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        revoke_delegation(&repository, command),
        Err(DelegationError::Integrity(_))
    ));
    assert!(matches!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                action: DelegatedAction::WorkspaceStatus,
                environment_id: None,
                object_ids: Vec::new(),
                evaluated_at: "2026-08-03T18:40:00Z".parse().unwrap(),
            },
        ),
        Err(DelegationError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM delegation_revoke_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn revocation_replay_returns_original_before_revalidating_candidate_time() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    grant_delegation(
        &repository,
        delegation_command(
            DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:15:00Z",
        ),
    )
    .unwrap();
    let original = revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T18:45:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let evidence_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT r.revoked_at, r.revocation_json, r.revocation_digest,
                    o.request_digest, o.effect_digest,
                    (SELECT COUNT(*) FROM delegation_revoke_operations)
             FROM delegation_revocations r
             JOIN delegation_revoke_operations o
               ON o.delegation_id = r.delegation_id
             ORDER BY r.delegation_id, o.principal_id, o.idempotency_key",
    );

    let replay = revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T17:14:59Z".parse().unwrap(),
        },
    )
    .unwrap();

    assert_eq!(replay, original);
    let evidence_after = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT r.revoked_at, r.revocation_json, r.revocation_digest,
                    o.request_digest, o.effect_digest,
                    (SELECT COUNT(*) FROM delegation_revoke_operations)
             FROM delegation_revocations r
             JOIN delegation_revoke_operations o
               ON o.delegation_id = r.delegation_id
             ORDER BY r.delegation_id, o.principal_id, o.idempotency_key",
    );
    assert_eq!(evidence_after, evidence_before);
}

#[test]
fn delegation_revoke_missing_key_retry_rejects_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    grant_delegation(
        &repository,
        delegation_command(
            DELEGATION_ID,
            DELEGATION_IDEMPOTENCY_KEY,
            "2026-08-03T17:15:00Z",
        ),
    )
    .unwrap();
    let mut other_grant = delegation_command(
        OTHER_DELEGATION_ID,
        RESOURCE_SCOPE_IDEMPOTENCY_KEY,
        "2026-08-03T17:16:00Z",
    );
    other_grant.constraints.max_context_bytes = 8_192;
    grant_delegation(&repository, other_grant).unwrap();
    revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T18:45:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE delegation_revoke_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
                    DELEGATION_REVOKE_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    let revocations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT delegation_id, revoked_by_principal_id, revoked_at, reason,
                revocation_json, revocation_digest
         FROM delegation_revocations ORDER BY delegation_id",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                effect_digest, delegation_id
         FROM delegation_revoke_operations ORDER BY delegation_id",
    );

    let retry = revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: OTHER_DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T18:46:00Z".parse().unwrap(),
        },
    );
    assert!(
        matches!(retry, Err(DelegationError::Integrity(_))),
        "missing-key Delegation revoke retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT delegation_id, revoked_by_principal_id, revoked_at, reason,
                    revocation_json, revocation_digest
             FROM delegation_revocations ORDER BY delegation_id",
        ),
        revocations_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, idempotency_key, request_digest,
                    effect_digest, delegation_id
             FROM delegation_revoke_operations ORDER BY delegation_id",
        ),
        operations_before
    );
}

#[test]
fn delegation_semantic_retry_ignores_regenerated_issued_at_after_not_before() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_delegation_dependencies(&repository);
    let command = delegation_command(
        DELEGATION_ID,
        DELEGATION_IDEMPOTENCY_KEY,
        "2026-08-03T17:15:00Z",
    );
    let original = grant_delegation(&repository, command.clone()).unwrap();

    let replay = grant_delegation(
        &repository,
        GrantDelegationCommand {
            delegation_id: OTHER_DELEGATION_ID.parse().unwrap(),
            issued_at: "2026-08-03T18:30:00Z".parse().unwrap(),
            ..command
        },
    )
    .unwrap();
    assert_eq!(replay, original);
    let counts: (i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM delegations),
                    (SELECT COUNT(*) FROM delegation_grant_operations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (1, 1));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one authority scenario keeps retry, scope, time, status, and revocation assertions causally adjacent"
)]
fn agent_and_delegation_authority_is_exact_expiring_and_revocable() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_approved_mixed_changeset(&repository);
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T17:05:00Z",
        ),
    )
    .unwrap();

    let created_agent = create_agent_principal(
        &repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "release-reader",
            "2026-08-03T17:10:00Z",
        ),
    )
    .unwrap();
    let replayed_agent = create_agent_principal(
        &repository,
        agent_command(
            OTHER_AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "release-reader",
            "2026-08-03T17:11:00Z",
        ),
    )
    .unwrap();
    assert_eq!(replayed_agent, created_agent);
    assert_eq!(created_agent.principal_id.to_string(), AGENT_PRINCIPAL_ID);
    assert_eq!(
        get_agent_principal(&repository, AGENT_PRINCIPAL_ID.parse().unwrap()).unwrap(),
        created_agent
    );
    assert_eq!(
        create_agent_principal(
            &repository,
            agent_command(
                OTHER_AGENT_PRINCIPAL_ID,
                AGENT_IDEMPOTENCY_KEY,
                "different-reader",
                "2026-08-03T17:12:00Z",
            ),
        )
        .unwrap_err(),
        PrincipalError::IdempotencyKeyReused
    );
    let other_agent = create_agent_principal(
        &repository,
        agent_command(
            OTHER_AGENT_PRINCIPAL_ID,
            OTHER_AGENT_IDEMPOTENCY_KEY,
            "untrusted-reader",
            "2026-08-03T17:13:00Z",
        ),
    )
    .unwrap();

    assert_eq!(
        grant_delegation(
            &repository,
            delegation_command(
                OTHER_DELEGATION_ID,
                DELEGATION_IDEMPOTENCY_KEY,
                "2026-08-03T18:00:01Z",
            ),
        )
        .unwrap_err(),
        DelegationError::InvalidGrant
    );
    assert_eq!(
        grant_delegation(
            &repository,
            GrantDelegationCommand {
                actions: vec![DelegatedAction::WorkspaceStatus],
                idempotency_key: STATUS_SCOPE_IDEMPOTENCY_KEY.parse().unwrap(),
                ..delegation_command(
                    OTHER_DELEGATION_ID,
                    STATUS_SCOPE_IDEMPOTENCY_KEY,
                    "2026-08-03T17:15:00Z",
                )
            },
        )
        .unwrap_err(),
        DelegationError::InvalidGrant
    );
    assert_eq!(
        grant_delegation(
            &repository,
            GrantDelegationCommand {
                actions: vec![DelegatedAction::ObjectQueryReleased],
                scope: DelegationScope {
                    workspace_id: WORKSPACE_ID.parse().unwrap(),
                    environment_ids: Vec::new(),
                    object_ids: Vec::new(),
                },
                idempotency_key: RESOURCE_SCOPE_IDEMPOTENCY_KEY.parse().unwrap(),
                ..delegation_command(
                    OTHER_DELEGATION_ID,
                    RESOURCE_SCOPE_IDEMPOTENCY_KEY,
                    "2026-08-03T17:15:00Z",
                )
            },
        )
        .unwrap_err(),
        DelegationError::InvalidGrant
    );

    let grant = delegation_command(
        DELEGATION_ID,
        DELEGATION_IDEMPOTENCY_KEY,
        "2026-08-03T17:15:00Z",
    );
    let created_grant = grant_delegation(&repository, grant.clone()).unwrap();
    let replayed_grant = grant_delegation(
        &repository,
        GrantDelegationCommand {
            delegation_id: OTHER_DELEGATION_ID.parse().unwrap(),
            issued_at: "2026-08-03T17:16:00Z".parse().unwrap(),
            ..grant.clone()
        },
    )
    .unwrap();
    assert_eq!(replayed_grant, created_grant);
    assert_eq!(created_grant.delegation_id.to_string(), DELEGATION_ID);
    assert_eq!(
        get_delegation(&repository, DELEGATION_ID.parse().unwrap()).unwrap(),
        created_grant
    );

    let valid_status = VerifyDelegationCommand {
        delegation_id: DELEGATION_ID.parse().unwrap(),
        operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
        action: DelegatedAction::WorkspaceStatus,
        environment_id: None,
        object_ids: Vec::new(),
        evaluated_at: "2026-08-03T18:30:00Z".parse().unwrap(),
    };
    assert!(
        verify_delegation(&repository, valid_status.clone())
            .unwrap()
            .authorized
    );
    let status = delegated_workspace_status(
        &repository,
        DelegatedWorkspaceStatusCommand {
            operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
            delegation_id: DELEGATION_ID.parse().unwrap(),
            evaluated_at: "2026-08-03T18:30:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(status.principal_id.to_string(), AGENT_PRINCIPAL_ID);
    assert_eq!(status.delegation_id.to_string(), DELEGATION_ID);
    assert_eq!(status.storage_schema_version, 11);
    assert_eq!(
        status.authorization_decision_digest,
        verify_delegation(&repository, valid_status.clone())
            .unwrap()
            .decision_digest
    );

    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                operating_principal_id: other_agent.principal_id,
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::ScopeExceeded
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                action: DelegatedAction::ContextBuild,
                environment_id: Some(ENVIRONMENT_ID.parse().unwrap()),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::ScopeExceeded
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                action: DelegatedAction::ObjectQueryReleased,
                environment_id: Some(OTHER_ENVIRONMENT_ID.parse().unwrap()),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::ScopeExceeded
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                action: DelegatedAction::ObjectQueryReleased,
                environment_id: Some(ENVIRONMENT_ID.parse().unwrap()),
                object_ids: vec!["019c0000-0000-7000-8000-000000000081".parse().unwrap(),],
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::ScopeExceeded
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                evaluated_at: "2026-08-03T17:59:59Z".parse().unwrap(),
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::NotYetValid
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                evaluated_at: "2026-08-03T20:00:00Z".parse().unwrap(),
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::Expired
    );
    assert!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                action: DelegatedAction::ObjectQueryReleased,
                environment_id: Some(ENVIRONMENT_ID.parse().unwrap()),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                ..valid_status.clone()
            },
        )
        .unwrap()
        .authorized
    );

    assert_eq!(
        revoke_delegation(
            &repository,
            RevokeDelegationCommand {
                delegation_id: DELEGATION_ID.parse().unwrap(),
                idempotency_key: EARLY_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
                revoked_at: "2026-08-03T17:14:59Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        DelegationError::InvalidGrant
    );

    let revoked = revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T18:45:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let replayed_revocation = revoke_delegation(
        &repository,
        RevokeDelegationCommand {
            delegation_id: DELEGATION_ID.parse().unwrap(),
            idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
            revoked_at: "2026-08-03T18:46:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(replayed_revocation, revoked);
    assert_eq!(
        revoked.revoked_at.unwrap().to_string(),
        "2026-08-03T18:45:00Z"
    );
    let replayed_grant_after_revocation = grant_delegation(
        &repository,
        GrantDelegationCommand {
            delegation_id: OTHER_DELEGATION_ID.parse().unwrap(),
            issued_at: "2026-08-03T17:16:00Z".parse().unwrap(),
            ..grant
        },
    )
    .unwrap();
    assert_eq!(replayed_grant_after_revocation, created_grant);
    assert_eq!(
        get_delegation(&repository, DELEGATION_ID.parse().unwrap()).unwrap(),
        revoked
    );
    assert!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                evaluated_at: "2026-08-03T18:44:59Z".parse().unwrap(),
                ..valid_status.clone()
            },
        )
        .unwrap()
        .authorized
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                evaluated_at: "2026-08-03T18:45:00Z".parse().unwrap(),
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::Revoked
    );
    assert_eq!(
        verify_delegation(
            &repository,
            VerifyDelegationCommand {
                evaluated_at: "2026-08-03T18:50:00Z".parse().unwrap(),
                ..valid_status.clone()
            },
        )
        .unwrap_err(),
        DelegationError::Revoked
    );
    assert_eq!(
        delegated_workspace_status(
            &repository,
            DelegatedWorkspaceStatusCommand {
                operating_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
                delegation_id: DELEGATION_ID.parse().unwrap(),
                evaluated_at: "2026-08-03T18:50:00Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        DelegatedWorkspaceStatusError::Denied
    );
}

#[test]
fn context_pack_consumers_reject_built_at_tamper_without_effect_commitment_update() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let (command, context) = prepare_released_context_pack(&repository);
    let delegation = get_delegation(&repository, command.delegation_id).unwrap();
    let effect_before: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM context_pack_build_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let decision = canonicalize(&serde_json::json!({
        "action": DelegatedAction::ContextBuild.to_string(),
        "api_version": "proof.dev/authorization-decision/v1",
        "authorized": true,
        "delegation_digest": delegation.delegation_digest.to_string(),
        "delegation_id": delegation.delegation_id.to_string(),
        "environment_id": ENVIRONMENT_ID,
        "evaluated_at": "2026-08-03T23:21:00Z",
        "object_ids": [OBJECT_ID],
        "operating_principal_id": command.operating_principal_id.to_string(),
        "policy_profile": "proof.local/authority/default/v1",
        "workspace_id": WORKSPACE_ID,
    }))
    .unwrap();
    let authorization_digest = digest(ArtifactKind::AuthorizationDecisionV1, &decision);
    let mut manifest = serde_json::from_str::<serde_json::Value>(&context.manifest_json).unwrap();
    manifest["built_at"] = serde_json::json!("2026-08-03T23:21:00Z");
    manifest["authorization_decision_digest"] = serde_json::json!(authorization_digest.to_string());
    let manifest = canonicalize(&manifest).unwrap();
    let context_digest = digest(ArtifactKind::ContextPackV1, &manifest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE context_packs SET created_at = '2026-08-03T23:21:00Z',
                    manifest_json = ?1, context_pack_digest = ?2
             WHERE context_pack_id = ?3",
            (
                manifest.as_str(),
                context_digest.to_string(),
                CONTEXT_PACK_ID,
            ),
        )
        .unwrap();

    assert!(matches!(
        get_context_pack(
            &repository,
            GetContextPackCommand {
                context_pack_id: context.context_pack_id,
                operating_principal_id: command.operating_principal_id,
                delegation_id: delegation.delegation_id,
                observed_at: "2026-08-03T23:30:00Z".parse().unwrap(),
            },
        ),
        Err(ContextPackError::Integrity(_))
    ));
    assert!(matches!(
        verify_context_pack(
            &repository,
            VerifyContextPackCommand {
                context_pack_id: context.context_pack_id,
                operating_principal_id: command.operating_principal_id,
                delegation_id: delegation.delegation_id,
                verified_at: "2026-08-03T23:30:00Z".parse().unwrap(),
            },
        ),
        Err(ContextPackError::Integrity(_))
    ));
    assert!(matches!(
        build_context_pack(&repository, command),
        Err(ContextPackError::Integrity(_))
    ));
    let effect_after: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT effect_digest FROM context_pack_build_operations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(effect_after, effect_before);
}

#[test]
fn context_pack_replay_returns_original_before_revalidating_candidate_built_at() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let (command, original) = prepare_released_context_pack(&repository);
    let evidence_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT p.created_at, p.expires_at, p.manifest_json, p.context_pack_digest,
                    o.request_digest, o.effect_digest,
                    (SELECT COUNT(*) FROM context_packs),
                    (SELECT COUNT(*) FROM context_pack_build_operations)
             FROM context_packs p
             JOIN context_pack_build_operations o
               ON o.context_pack_id = p.context_pack_id
             ORDER BY p.context_pack_id, o.requesting_principal_id,
                      o.operating_principal_id, o.idempotency_key",
    );

    for built_at in ["2026-08-03T22:59:59Z", "2026-08-03T23:50:00Z"] {
        let replay = build_context_pack(
            &repository,
            BuildContextPackCommand {
                context_pack_id: OTHER_CONTEXT_PACK_ID.parse().unwrap(),
                built_at: built_at.parse().unwrap(),
                ..command.clone()
            },
        )
        .unwrap();
        assert_eq!(replay, original);
    }

    let evidence_after = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT p.created_at, p.expires_at, p.manifest_json, p.context_pack_digest,
                    o.request_digest, o.effect_digest,
                    (SELECT COUNT(*) FROM context_packs),
                    (SELECT COUNT(*) FROM context_pack_build_operations)
             FROM context_packs p
             JOIN context_pack_build_operations o
               ON o.context_pack_id = p.context_pack_id
             ORDER BY p.context_pack_id, o.requesting_principal_id,
                      o.operating_principal_id, o.idempotency_key",
    );
    assert_eq!(evidence_after, evidence_before);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the two-output fixture proves swapped operation identities fail replay, get, and verify without changing committed results"
)]
fn context_pack_consumers_reject_two_row_idempotency_key_swap() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let (first_command, first) = prepare_released_context_pack(&repository);
    let second_command = BuildContextPackCommand {
        context_pack_id: OTHER_CONTEXT_PACK_ID.parse().unwrap(),
        idempotency_key: OTHER_CONTEXT_PACK_IDEMPOTENCY_KEY.parse().unwrap(),
        built_at: "2026-08-03T23:21:00Z".parse().unwrap(),
        ..first_command.clone()
    };
    let second = build_context_pack(&repository, second_command.clone()).unwrap();
    assert_ne!(second.context_pack_id, first.context_pack_id);
    assert_ne!(second.context_pack_digest, first.context_pack_digest);
    let immutable_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT request_digest, effect_digest, context_pack_id
         FROM context_pack_build_operations ORDER BY context_pack_id",
    );

    let mut connection = repository.open_database().unwrap();
    let transaction = connection.transaction().unwrap();
    assert_eq!(
        transaction
            .execute(
                "UPDATE context_pack_build_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
                    CONTEXT_PACK_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE context_pack_build_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    CONTEXT_PACK_IDEMPOTENCY_KEY,
                    OTHER_CONTEXT_PACK_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE context_pack_build_operations SET idempotency_key = ?1
                 WHERE idempotency_key = ?2",
                (
                    OTHER_CONTEXT_PACK_IDEMPOTENCY_KEY,
                    CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    transaction.commit().unwrap();
    drop(connection);
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT request_digest, effect_digest, context_pack_id
             FROM context_pack_build_operations ORDER BY context_pack_id",
        ),
        immutable_before
    );
    let swapped_evidence = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT idempotency_key, request_digest, effect_digest, context_pack_id
         FROM context_pack_build_operations ORDER BY context_pack_id",
    );

    for command in [first_command.clone(), second_command] {
        assert!(matches!(
            build_context_pack(&repository, command),
            Err(ContextPackError::Integrity(_))
        ));
    }
    for context in [&first, &second] {
        assert!(matches!(
            get_context_pack(
                &repository,
                GetContextPackCommand {
                    context_pack_id: context.context_pack_id,
                    operating_principal_id: first_command.operating_principal_id,
                    delegation_id: first_command.delegation_id,
                    observed_at: "2026-08-03T23:30:00Z".parse().unwrap(),
                },
            ),
            Err(ContextPackError::Integrity(_))
        ));
        assert!(matches!(
            verify_context_pack(
                &repository,
                VerifyContextPackCommand {
                    context_pack_id: context.context_pack_id,
                    operating_principal_id: first_command.operating_principal_id,
                    delegation_id: first_command.delegation_id,
                    verified_at: "2026-08-03T23:30:00Z".parse().unwrap(),
                },
            ),
            Err(ContextPackError::Integrity(_))
        ));
    }
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT idempotency_key, request_digest, effect_digest, context_pack_id
             FROM context_pack_build_operations ORDER BY context_pack_id",
        ),
        swapped_evidence
    );
}

#[test]
fn context_pack_missing_key_retry_and_moved_scope_reject_without_writes() {
    for mutation in ["idempotency_key", "operating_principal_id"] {
        let directory = TestDirectory::new();
        let repository = initialized_repository(&directory);
        let (mut command, _) = prepare_released_context_pack(&repository);
        if mutation == "operating_principal_id" {
            create_agent_principal(
                &repository,
                agent_command(
                    OTHER_AGENT_PRINCIPAL_ID,
                    OTHER_AGENT_IDEMPOTENCY_KEY,
                    "other-context-reader",
                    "2026-08-03T23:00:00Z",
                ),
            )
            .unwrap();
        }
        let replacement = if mutation == "idempotency_key" {
            CONTEXT_PACK_SWAP_IDEMPOTENCY_KEY
        } else {
            OTHER_AGENT_PRINCIPAL_ID
        };
        assert_eq!(
            repository
                .open_database()
                .unwrap()
                .execute(
                    &format!(
                        "UPDATE context_pack_build_operations SET {mutation} = ?1
                         WHERE context_pack_id = ?2"
                    ),
                    (replacement, CONTEXT_PACK_ID),
                )
                .unwrap(),
            1
        );
        let packs_before = snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT context_pack_id, workspace_id, requesting_principal_id,
                    operating_principal_id, delegation_id, environment_id, release_id,
                    edition_id, object_ids_json, manifest_json, context_pack_digest,
                    created_at, expires_at
             FROM context_packs ORDER BY context_pack_id",
        );
        let operations_before = snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                    idempotency_key, request_digest, effect_digest, context_pack_id
             FROM context_pack_build_operations ORDER BY context_pack_id",
        );
        command.context_pack_id = OTHER_CONTEXT_PACK_ID.parse().unwrap();
        command.built_at = "2026-08-03T23:21:00Z".parse().unwrap();

        let retry = build_context_pack(&repository, command);
        assert!(
            matches!(retry, Err(ContextPackError::Integrity(_))),
            "{mutation} moved-scope ContextPack retry returned {retry:?}"
        );
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT context_pack_id, workspace_id, requesting_principal_id,
                        operating_principal_id, delegation_id, environment_id, release_id,
                        edition_id, object_ids_json, manifest_json, context_pack_digest,
                        created_at, expires_at
                 FROM context_packs ORDER BY context_pack_id",
            ),
            packs_before
        );
        assert_eq!(
            snapshot_rows(
                &repository.open_database().unwrap(),
                "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                        idempotency_key, request_digest, effect_digest, context_pack_id
                 FROM context_pack_build_operations ORDER BY context_pack_id",
            ),
            operations_before
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one causal scenario proves signed Release history, rollback, released reads, ContextPack replay, supersession, and pointer repair"
)]
fn releases_queries_and_context_packs_preserve_immutable_history_and_exact_authority() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();

    let first_command = promotion_command(
        FIRST_RELEASE_ID,
        FIRST_PROOF_ID,
        EDITION_ID,
        FIRST_RELEASE_IDEMPOTENCY_KEY,
        "2026-08-03T21:00:00Z",
    );
    let first = promote_release(&repository, first_command.clone()).unwrap();
    assert_eq!(first.kind, ReleaseKind::Promotion);
    assert_eq!(first.release_sequence, 1);
    assert_eq!(first.previous_release_id, None);
    assert_eq!(first.rollback_target_release_id, None);
    assert_eq!(first.edition_id.to_string(), EDITION_ID);
    assert_eq!(first.principal_id.to_string(), PRINCIPAL_ID);
    assert_eq!(first.delegation_id, None);
    let encoded_public_key = first.key_id.strip_prefix("ed25519:").unwrap();
    assert_eq!(encoded_public_key.len(), 64);
    assert!(
        encoded_public_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let canonical_envelope = canonicalize(
        &serde_json::from_str::<serde_json::Value>(&first.proof_envelope_json).unwrap(),
    )
    .unwrap();
    assert_eq!(canonical_envelope.as_str(), first.proof_envelope_json);
    assert_eq!(
        first.proof_envelope_digest,
        digest(ArtifactKind::ProofEnvelopeV1, &canonical_envelope)
    );
    let first_verification = verify_release(
        &repository,
        VerifyReleaseCommand {
            release_id: first.release_id,
            verified_at: "2026-08-03T21:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert!(first_verification.signature_valid);
    assert!(first_verification.subjects_valid);
    assert!(first_verification.evidence_complete);
    assert!(first_verification.trusted);
    assert!(first_verification.valid);
    assert!(first_verification.findings.is_empty());

    let replayed_first = promote_release(
        &repository,
        PromoteReleaseCommand {
            release_id: REPLAY_RELEASE_ID.parse().unwrap(),
            proof_id: REPLAY_PROOF_ID.parse().unwrap(),
            released_at: "2026-08-03T21:30:00Z".parse().unwrap(),
            ..first_command.clone()
        },
    )
    .unwrap();
    assert_eq!(replayed_first, first);
    assert_eq!(
        promote_release(
            &repository,
            PromoteReleaseCommand {
                release_id: REPLAY_RELEASE_ID.parse().unwrap(),
                proof_id: REPLAY_PROOF_ID.parse().unwrap(),
                edition_id: OTHER_EDITION_ID.parse().unwrap(),
                released_at: "2026-08-03T21:31:00Z".parse().unwrap(),
                ..first_command
            },
        )
        .unwrap_err(),
        ReleaseError::IdempotencyKeyReused
    );

    let second = promote_release(
        &repository,
        promotion_command(
            SECOND_RELEASE_ID,
            SECOND_PROOF_ID,
            OTHER_EDITION_ID,
            SECOND_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T22:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(second.release_sequence, 2);
    assert_eq!(second.previous_release_id, Some(first.release_id));
    assert_eq!(second.edition_id.to_string(), OTHER_EDITION_ID);
    assert_eq!(
        promote_release(
            &repository,
            promotion_command(
                ROLLBACK_RELEASE_ID,
                ROLLBACK_PROOF_ID,
                EDITION_ID,
                ROLLBACK_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T22:30:00Z",
            ),
        )
        .unwrap_err(),
        ReleaseError::PolicyDenied
    );
    let rollback = rollback_release(
        &repository,
        RollbackReleaseCommand {
            release_id: ROLLBACK_RELEASE_ID.parse().unwrap(),
            proof_id: ROLLBACK_PROOF_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            rollback_target_release_id: first.release_id,
            idempotency_key: ROLLBACK_RELEASE_IDEMPOTENCY_KEY.parse().unwrap(),
            released_at: "2026-08-03T23:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(rollback.kind, ReleaseKind::Rollback);
    assert_eq!(rollback.release_sequence, 3);
    assert_eq!(rollback.previous_release_id, Some(second.release_id));
    assert_eq!(rollback.rollback_target_release_id, Some(first.release_id));
    assert_eq!(rollback.edition_id, first.edition_id);
    assert_eq!(get_release(&repository, first.release_id).unwrap(), first);
    assert_eq!(get_release(&repository, second.release_id).unwrap(), second);
    assert_eq!(
        get_release(&repository, rollback.release_id).unwrap(),
        rollback
    );
    let release_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM releases", [], |row| row.get(0))
        .unwrap();
    assert_eq!(release_count, 3);

    let human_query = query_released_objects(
        &repository,
        QueryReleasedObjectsCommand {
            operating_principal_id: None,
            delegation_id: None,
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            object_ids: vec![OBJECT_ID.parse().unwrap()],
            evaluated_at: "2026-08-03T23:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(human_query.release_id, rollback.release_id);
    assert_eq!(human_query.edition_id, first.edition_id);
    assert_eq!(human_query.principal_id.to_string(), PRINCIPAL_ID);
    assert_eq!(human_query.delegation_id, None);
    assert_eq!(human_query.objects.len(), 1);
    assert_eq!(human_query.objects[0].object_id.to_string(), OBJECT_ID);
    assert_eq!(
        human_query.objects[0].canonical_content,
        r#"{"title":"Projection proof"}"#
    );

    let agent = create_agent_principal(
        &repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "context-reader",
            "2026-08-03T22:45:00Z",
        ),
    )
    .unwrap();
    let delegation = grant_delegation(
        &repository,
        context_delegation_command(DELEGATION_ID, DELEGATION_IDEMPOTENCY_KEY),
    )
    .unwrap();
    let agent_query = query_released_objects(
        &repository,
        QueryReleasedObjectsCommand {
            operating_principal_id: Some(agent.principal_id),
            delegation_id: Some(delegation.delegation_id),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            object_ids: vec![OBJECT_ID.parse().unwrap()],
            evaluated_at: "2026-08-03T23:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(agent_query.release_id, rollback.release_id);
    assert_eq!(agent_query.principal_id, agent.principal_id);
    assert_eq!(agent_query.delegation_id, Some(delegation.delegation_id));
    assert_ne!(
        agent_query.authorization_decision_digest,
        human_query.authorization_decision_digest
    );

    let context_command = BuildContextPackCommand {
        context_pack_id: CONTEXT_PACK_ID.parse::<ContextPackId>().unwrap(),
        operating_principal_id: agent.principal_id,
        delegation_id: delegation.delegation_id,
        task_id: "release-summary-1".to_owned(),
        intent: ChangeSetIntent::new("Summarize the released article").unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        object_ids: vec![OBJECT_ID.parse().unwrap()],
        limits: ContextPackLimits {
            max_objects: 10,
            max_bytes: 1_048_576,
        },
        idempotency_key: CONTEXT_PACK_IDEMPOTENCY_KEY.parse().unwrap(),
        built_at: "2026-08-03T23:20:00Z".parse().unwrap(),
        expires_at: "2026-08-03T23:50:00Z".parse().unwrap(),
    };
    let context = build_context_pack(&repository, context_command.clone()).unwrap();
    assert_eq!(context.release_id, rollback.release_id);
    assert_eq!(context.edition_id, first.edition_id);
    assert_eq!(context.object_ids, vec![OBJECT_ID.parse().unwrap()]);
    assert_eq!(
        context.limits,
        ContextPackLimits {
            max_objects: 1,
            max_bytes: 16_384,
        }
    );
    assert!(context.manifest_json.len() <= 16_384);
    let context_manifest =
        serde_json::from_str::<serde_json::Value>(&context.manifest_json).unwrap();
    let selected_objects = context_manifest["objects"].as_array().unwrap();
    assert_eq!(selected_objects.len(), 1);
    assert_eq!(selected_objects[0]["object_id"], OBJECT_ID);
    assert_eq!(
        selected_objects[0]["canonical_content"],
        r#"{"title":"Projection proof"}"#
    );
    assert_eq!(
        selected_objects[0]["object_digest"],
        human_query.objects[0].object_digest.to_string()
    );
    let expected_schema_document = canonicalize(&serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "title": { "type": "string" },
        },
        "required": ["title"],
        "type": "object",
    }))
    .unwrap();
    let selected_schemas = context_manifest["schemas"].as_array().unwrap();
    assert_eq!(selected_schemas.len(), 1);
    assert_eq!(selected_schemas[0]["schema_id"], "article");
    assert_eq!(selected_schemas[0]["schema_version"], 1);
    assert_eq!(
        selected_schemas[0]["canonical_document"],
        expected_schema_document.as_str()
    );
    assert_eq!(
        selected_schemas[0]["document_digest"],
        digest(ArtifactKind::SchemaVersionV1, &expected_schema_document).to_string()
    );
    assert_eq!(
        context.context_pack_digest,
        digest(
            ArtifactKind::ContextPackV1,
            &canonicalize(
                &serde_json::from_str::<serde_json::Value>(&context.manifest_json).unwrap()
            )
            .unwrap()
        )
    );
    let replayed_context = build_context_pack(
        &repository,
        BuildContextPackCommand {
            context_pack_id: OTHER_CONTEXT_PACK_ID.parse().unwrap(),
            built_at: "2026-08-03T23:21:00Z".parse().unwrap(),
            limits: ContextPackLimits {
                max_objects: 2,
                max_bytes: 32_768,
            },
            ..context_command.clone()
        },
    )
    .unwrap();
    assert_eq!(replayed_context, context);
    assert_eq!(
        build_context_pack(
            &repository,
            BuildContextPackCommand {
                context_pack_id: OTHER_CONTEXT_PACK_ID.parse().unwrap(),
                built_at: "2026-08-03T23:22:00Z".parse().unwrap(),
                limits: ContextPackLimits {
                    max_objects: 1,
                    max_bytes: 8_192,
                },
                ..context_command
            },
        )
        .unwrap_err(),
        ContextPackError::IdempotencyKeyReused
    );

    let superseding = promote_release(
        &repository,
        promotion_command(
            SUPERSEDING_RELEASE_ID,
            SUPERSEDING_PROOF_ID,
            OTHER_EDITION_ID,
            SUPERSEDING_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T23:30:00Z",
        ),
    )
    .unwrap();
    assert_eq!(superseding.release_sequence, 4);
    assert_eq!(superseding.previous_release_id, Some(rollback.release_id));
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE environment_current_releases
             SET release_id = ?1, release_sequence = 1
             WHERE environment_id = ?2",
            (FIRST_RELEASE_ID, ENVIRONMENT_ID),
        )
        .unwrap();
    let pointer_drift =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(pointer_drift.changed);
    assert_eq!(pointer_drift.environment_pointer_count, 1);
    let still_drifted: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT release_id FROM environment_current_releases WHERE environment_id = ?1",
            [ENVIRONMENT_ID],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(still_drifted, FIRST_RELEASE_ID);
    let repaired =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(repaired.changed);
    assert_eq!(repaired.environment_pointer_count, 1);

    let current_query = query_released_objects(
        &repository,
        QueryReleasedObjectsCommand {
            operating_principal_id: None,
            delegation_id: None,
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            object_ids: vec![OBJECT_ID.parse().unwrap()],
            evaluated_at: "2026-08-03T23:35:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(current_query.release_id, superseding.release_id);
    let historical_context = get_context_pack(
        &repository,
        GetContextPackCommand {
            context_pack_id: context.context_pack_id,
            operating_principal_id: agent.principal_id,
            delegation_id: delegation.delegation_id,
            observed_at: "2026-08-03T23:35:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(historical_context, context);
    let context_verification = verify_context_pack(
        &repository,
        VerifyContextPackCommand {
            context_pack_id: context.context_pack_id,
            operating_principal_id: agent.principal_id,
            delegation_id: delegation.delegation_id,
            verified_at: "2026-08-03T23:40:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert!(context_verification.digest_valid);
    assert!(context_verification.sources_valid);
    assert!(context_verification.fresh);
    assert!(context_verification.valid);
    assert!(context_verification.findings.is_empty());
    assert_eq!(
        verify_context_pack(
            &repository,
            VerifyContextPackCommand {
                context_pack_id: context.context_pack_id,
                operating_principal_id: agent.principal_id,
                delegation_id: delegation.delegation_id,
                verified_at: context.expires_at,
            },
        )
        .unwrap_err(),
        ContextPackError::Expired
    );

    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE context_packs SET manifest_json = '{}' WHERE context_pack_id = ?1",
            [CONTEXT_PACK_ID],
        )
        .unwrap();
    assert!(matches!(
        get_context_pack(
            &repository,
            GetContextPackCommand {
                context_pack_id: context.context_pack_id,
                operating_principal_id: agent.principal_id,
                delegation_id: delegation.delegation_id,
                observed_at: "2026-08-03T23:45:00Z".parse().unwrap(),
            },
        ),
        Err(ContextPackError::Integrity(_))
    ));

    create_environment(
        &repository,
        environment_command(
            OTHER_ENVIRONMENT_ID,
            OTHER_ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T23:46:00Z",
        ),
    )
    .unwrap();
    let other_environment_release = promote_release(
        &repository,
        PromoteReleaseCommand {
            release_id: OTHER_ENVIRONMENT_RELEASE_ID.parse().unwrap(),
            proof_id: OTHER_ENVIRONMENT_PROOF_ID.parse().unwrap(),
            environment_id: OTHER_ENVIRONMENT_ID.parse().unwrap(),
            edition_id: OTHER_EDITION_ID.parse().unwrap(),
            idempotency_key: OTHER_ENVIRONMENT_RELEASE_IDEMPOTENCY_KEY.parse().unwrap(),
            released_at: "2026-08-03T23:47:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    assert_eq!(other_environment_release.release_sequence, 5);
    assert_eq!(
        rollback_release(
            &repository,
            RollbackReleaseCommand {
                release_id: REPLAY_RELEASE_ID.parse().unwrap(),
                proof_id: REPLAY_PROOF_ID.parse().unwrap(),
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                rollback_target_release_id: other_environment_release.release_id,
                idempotency_key: DELEGATION_REVOKE_IDEMPOTENCY_KEY.parse().unwrap(),
                released_at: "2026-08-03T23:48:00Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        ReleaseError::InvalidRollbackTarget
    );
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(superseding.release_id)
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the two signed Releases prove swapped operation identities fail replay, get, and verify without changing committed evidence"
)]
fn release_consumers_reject_two_row_idempotency_key_swap() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    let first_command = promotion_command(
        FIRST_RELEASE_ID,
        FIRST_PROOF_ID,
        EDITION_ID,
        FIRST_RELEASE_IDEMPOTENCY_KEY,
        "2026-08-03T21:00:00Z",
    );
    let first = promote_release(&repository, first_command.clone()).unwrap();
    let second_command = promotion_command(
        SECOND_RELEASE_ID,
        SECOND_PROOF_ID,
        OTHER_EDITION_ID,
        SECOND_RELEASE_IDEMPOTENCY_KEY,
        "2026-08-03T22:00:00Z",
    );
    let second = promote_release(&repository, second_command.clone()).unwrap();
    let immutable_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, operation_kind, request_digest,
                release_id, proof_id
         FROM release_operations ORDER BY release_id",
    );

    let mut connection = repository.open_database().unwrap();
    let transaction = connection.transaction().unwrap();
    assert_eq!(
        transaction
            .execute(
                "UPDATE release_operations SET idempotency_key = ?1
                 WHERE operation_kind = 'release.promote' AND idempotency_key = ?2",
                (RELEASE_SWAP_IDEMPOTENCY_KEY, FIRST_RELEASE_IDEMPOTENCY_KEY,),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE release_operations SET idempotency_key = ?1
                 WHERE operation_kind = 'release.promote' AND idempotency_key = ?2",
                (
                    FIRST_RELEASE_IDEMPOTENCY_KEY,
                    SECOND_RELEASE_IDEMPOTENCY_KEY,
                ),
            )
            .unwrap(),
        1
    );
    assert_eq!(
        transaction
            .execute(
                "UPDATE release_operations SET idempotency_key = ?1
                 WHERE operation_kind = 'release.promote' AND idempotency_key = ?2",
                (SECOND_RELEASE_IDEMPOTENCY_KEY, RELEASE_SWAP_IDEMPOTENCY_KEY,),
            )
            .unwrap(),
        1
    );
    transaction.commit().unwrap();
    drop(connection);
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, operation_kind, request_digest,
                    release_id, proof_id
             FROM release_operations ORDER BY release_id",
        ),
        immutable_before
    );
    let swapped_evidence = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                request_digest, release_id, proof_id
         FROM release_operations ORDER BY release_id",
    );

    for (label, command) in [("first", first_command), ("second", second_command)] {
        let replay = promote_release(&repository, command);
        assert!(
            matches!(replay, Err(ReleaseError::Integrity(_))),
            "{label} swapped Release replay returned {replay:?}"
        );
    }
    for release in [&first, &second] {
        assert!(matches!(
            get_release(&repository, release.release_id),
            Err(ReleaseError::Integrity(_))
        ));
        assert!(matches!(
            verify_release(
                &repository,
                VerifyReleaseCommand {
                    release_id: release.release_id,
                    verified_at: "2026-08-03T22:10:00Z".parse().unwrap(),
                },
            ),
            Err(ReleaseError::Integrity(_))
        ));
    }
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                    request_digest, release_id, proof_id
             FROM release_operations ORDER BY release_id",
        ),
        swapped_evidence
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the noncurrent signed Release fixture keeps the corrupted operation and all no-write evidence snapshots causally adjacent"
)]
fn release_missing_key_retry_rejects_noncurrent_scope_corruption_without_writes() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T21:00:00Z",
        ),
    )
    .unwrap();
    promote_release(
        &repository,
        promotion_command(
            SECOND_RELEASE_ID,
            SECOND_PROOF_ID,
            OTHER_EDITION_ID,
            SECOND_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T22:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE release_operations SET idempotency_key = ?1
                 WHERE operation_kind = 'release.promote' AND idempotency_key = ?2",
                (RELEASE_SWAP_IDEMPOTENCY_KEY, FIRST_RELEASE_IDEMPOTENCY_KEY,),
            )
            .unwrap(),
        1
    );
    let releases_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT release_id, release_sequence, workspace_id, environment_id,
                environment_config_version, edition_id, edition_digest, release_kind,
                rollback_target_release_id, previous_release_id, principal_id, delegation_id,
                policy_decision_digest, manifest_json, release_digest, released_at
         FROM releases ORDER BY release_id",
    );
    let proofs_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT proof_id, release_id, key_id, payload_type, statement_json,
                envelope_json, proof_digest, created_at
         FROM release_proofs ORDER BY proof_id",
    );
    let operations_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                request_digest, release_id, proof_id
         FROM release_operations ORDER BY release_id",
    );
    let pointer_before = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT environment_id, release_id, release_sequence, projection_version
         FROM environment_current_releases ORDER BY environment_id",
    );

    let retry = promote_release(
        &repository,
        promotion_command(
            REPLAY_RELEASE_ID,
            REPLAY_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T22:10:00Z",
        ),
    );
    assert!(
        matches!(retry, Err(ReleaseError::Integrity(_))),
        "missing-key noncurrent Release retry returned {retry:?}"
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT release_id, release_sequence, workspace_id, environment_id,
                    environment_config_version, edition_id, edition_digest, release_kind,
                    rollback_target_release_id, previous_release_id, principal_id, delegation_id,
                    policy_decision_digest, manifest_json, release_digest, released_at
             FROM releases ORDER BY release_id",
        ),
        releases_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT proof_id, release_id, key_id, payload_type, statement_json,
                    envelope_json, proof_digest, created_at
             FROM release_proofs ORDER BY proof_id",
        ),
        proofs_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                    request_digest, release_id, proof_id
             FROM release_operations ORDER BY release_id",
        ),
        operations_before
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT environment_id, release_id, release_sequence, projection_version
             FROM environment_current_releases ORDER BY environment_id",
        ),
        pointer_before
    );
}

#[test]
fn release_reads_reject_independent_approval_digest_tamper() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    let release = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T21:00:00Z",
        ),
    )
    .unwrap();
    let (approval_changeset_digest, approval_validation_digest): (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT changeset_digest, validation_results_digest
             FROM changeset_approvals WHERE changeset_id = ?1",
            [CHANGESET_ID],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let wrong_digest = format!("blake3:{}", "f".repeat(64));
    assert_ne!(wrong_digest, approval_changeset_digest);
    assert_ne!(wrong_digest, approval_validation_digest);

    for (mutation, original) in [
        (
            "UPDATE changeset_approvals SET changeset_digest = ?1 WHERE changeset_id = ?2",
            approval_changeset_digest.as_str(),
        ),
        (
            "UPDATE changeset_approvals SET validation_results_digest = ?1
             WHERE changeset_id = ?2",
            approval_validation_digest.as_str(),
        ),
    ] {
        repository
            .open_database()
            .unwrap()
            .execute(mutation, (wrong_digest.as_str(), CHANGESET_ID))
            .unwrap();
        assert_release_read_surfaces_reject_integrity(
            &repository,
            release.release_id,
            "2026-08-03T21:10:00Z",
        );
        repository
            .open_database()
            .unwrap()
            .execute(mutation, (original, CHANGESET_ID))
            .unwrap();
        assert_eq!(
            get_release(&repository, release.release_id).unwrap(),
            release
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one Release chain proves equal-Edition validity before independently falsifying predecessor time and Edition monotonicity"
)]
fn release_verifier_enforces_predecessor_time_and_non_regressing_editions() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    let first = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            OTHER_EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T21:00:00Z",
        ),
    )
    .unwrap();
    let equal_edition_successor = promote_release(
        &repository,
        promotion_command(
            SECOND_RELEASE_ID,
            SECOND_PROOF_ID,
            OTHER_EDITION_ID,
            SECOND_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T22:00:00Z",
        ),
    )
    .unwrap();
    assert_eq!(first.edition_id, equal_edition_successor.edition_id);
    assert_eq!(
        equal_edition_successor.previous_release_id,
        Some(first.release_id)
    );
    assert!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: equal_edition_successor.release_id,
                verified_at: "2026-08-03T22:01:00Z".parse().unwrap(),
            },
        )
        .unwrap()
        .valid
    );

    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE releases SET released_at = '2026-08-03T20:59:59Z'
             WHERE release_id = ?1",
            [SECOND_RELEASE_ID],
        )
        .unwrap();
    assert_release_history_violation(
        &repository,
        equal_edition_successor.release_id,
        "Release timestamp precedes its Environment predecessor",
    );
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE releases SET released_at = ?1 WHERE release_id = ?2",
            (
                equal_edition_successor.released_at.to_string(),
                SECOND_RELEASE_ID,
            ),
        )
        .unwrap();
    assert_eq!(
        get_release(&repository, equal_edition_successor.release_id).unwrap(),
        equal_edition_successor
    );

    let older_edition_digest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT edition_digest FROM editions WHERE edition_id = ?1",
            [EDITION_ID],
            |row| row.get(0),
        )
        .unwrap();
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE releases SET edition_id = ?1, edition_digest = ?2
             WHERE release_id = ?3",
            (EDITION_ID, older_edition_digest.as_str(), SECOND_RELEASE_ID),
        )
        .unwrap();
    assert_release_history_violation(
        &repository,
        equal_edition_successor.release_id,
        "Promotion Edition predates its Environment predecessor Edition",
    );
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE releases SET edition_id = ?1, edition_digest = ?2
             WHERE release_id = ?3",
            (
                OTHER_EDITION_ID,
                equal_edition_successor.edition_digest.to_string(),
                SECOND_RELEASE_ID,
            ),
        )
        .unwrap();
    assert_eq!(
        get_release(&repository, equal_edition_successor.release_id).unwrap(),
        equal_edition_successor
    );
}

#[cfg(unix)]
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the scenario proves commit, pending export, idempotent replay, and derived artifact repair as one crash-boundary contract"
)]
fn release_commit_survives_proof_export_failure_and_replay_repairs_artifact() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    let proof_directory = directory
        .path()
        .join(".proof")
        .join("artifacts")
        .join("release-proofs");
    fs::create_dir(&proof_directory).unwrap();
    fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let command = promotion_command(
        FIRST_RELEASE_ID,
        FIRST_PROOF_ID,
        EDITION_ID,
        FIRST_RELEASE_IDEMPOTENCY_KEY,
        "2026-08-03T19:00:00Z",
    );

    let release = promote_release(&repository, command.clone()).unwrap();
    let proof_path = proof_directory.join(format!("{}.dsse.json", release.proof_id));
    assert!(!proof_path.exists());
    let persisted: (String, String, String, i64, i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT
                 (SELECT release_id FROM releases WHERE release_id = ?1),
                 (SELECT release_id FROM release_proof_export_outbox WHERE proof_id = ?2),
                 (SELECT release_id FROM environment_current_releases
                  WHERE environment_id = ?3),
                 (SELECT COUNT(*) FROM releases),
                 (SELECT COUNT(*) FROM release_proofs),
                 (SELECT COUNT(*) FROM release_operations)",
            (FIRST_RELEASE_ID, FIRST_PROOF_ID, ENVIRONMENT_ID),
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        persisted,
        (
            FIRST_RELEASE_ID.to_owned(),
            FIRST_RELEASE_ID.to_owned(),
            FIRST_RELEASE_ID.to_owned(),
            1,
            1,
            1,
        )
    );

    assert_eq!(
        promote_release(&repository, command.clone()).unwrap(),
        release
    );
    let pending_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM release_proof_export_outbox",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending_count, 1);

    fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(promote_release(&repository, command).unwrap(), release);
    assert_eq!(
        fs::read_to_string(&proof_path).unwrap(),
        release.proof_envelope_json
    );
    let final_counts: (i64, i64, i64, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT
                 (SELECT COUNT(*) FROM releases),
                 (SELECT COUNT(*) FROM release_proofs),
                 (SELECT COUNT(*) FROM release_operations),
                 (SELECT COUNT(*) FROM release_proof_export_outbox)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(final_counts, (1, 1, 1, 0));
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one portable-Proof scenario keeps artifact repair, operation provenance, atomic projection refusal, keyless verification, and trust tamper causally adjacent"
)]
fn release_proof_artifacts_repair_and_verified_history_needs_no_private_key() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_first_mixed_edition(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    let command = promotion_command(
        FIRST_RELEASE_ID,
        FIRST_PROOF_ID,
        EDITION_ID,
        FIRST_RELEASE_IDEMPOTENCY_KEY,
        "2026-08-03T21:00:00Z",
    );
    let release = promote_release(&repository, command.clone()).unwrap();
    let proof_path = directory
        .path()
        .join(".proof")
        .join("artifacts")
        .join("release-proofs")
        .join(format!("{}.dsse.json", release.proof_id));
    let signing_key_path = directory
        .path()
        .join(".proof")
        .join("state")
        .join("release-signing.ed25519");
    assert_eq!(
        fs::read_to_string(&proof_path).unwrap(),
        release.proof_envelope_json
    );

    fs::remove_file(&proof_path).unwrap();
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );
    assert_eq!(
        fs::read_to_string(&proof_path).unwrap(),
        release.proof_envelope_json
    );
    fs::write(&proof_path, "{").unwrap();
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );
    assert_eq!(
        fs::read_to_string(&proof_path).unwrap(),
        release.proof_envelope_json
    );

    assert!(signing_key_path.is_file());
    fs::remove_file(&signing_key_path).unwrap();
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );
    assert!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: release.release_id,
                verified_at: "2026-08-03T21:10:00Z".parse().unwrap(),
            },
        )
        .unwrap()
        .valid
    );
    assert_eq!(
        promote_release(
            &repository,
            PromoteReleaseCommand {
                release_id: REPLAY_RELEASE_ID.parse().unwrap(),
                proof_id: REPLAY_PROOF_ID.parse().unwrap(),
                released_at: "2026-08-03T21:30:00Z".parse().unwrap(),
                ..command
            },
        )
        .unwrap(),
        release
    );
    assert!(!signing_key_path.exists());

    let operation_digest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT request_digest FROM release_operations WHERE release_id = ?1",
            [FIRST_RELEASE_ID],
            |row| row.get(0),
        )
        .unwrap();
    let wrong_operation_digest = format!("blake3:{}", "f".repeat(64));
    assert_ne!(wrong_operation_digest, operation_digest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE release_operations SET request_digest = ?1 WHERE release_id = ?2",
            (wrong_operation_digest.as_str(), FIRST_RELEASE_ID),
        )
        .unwrap();
    assert!(matches!(
        get_release(&repository, release.release_id),
        Err(ReleaseError::Integrity(_))
    ));
    assert!(matches!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: release.release_id,
                verified_at: "2026-08-03T21:35:00Z".parse().unwrap(),
            },
        ),
        Err(ReleaseError::Integrity(_))
    ));
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE release_operations SET request_digest = ?1 WHERE release_id = ?2",
            (operation_digest.as_str(), FIRST_RELEASE_ID),
        )
        .unwrap();
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );

    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE release_proofs SET envelope_json = '{}' WHERE proof_id = ?1",
            [FIRST_PROOF_ID],
        )
        .unwrap();
    assert!(matches!(
        get_release(&repository, release.release_id),
        Err(ReleaseError::Integrity(_))
    ));
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE environment_current_releases SET release_sequence = 999
             WHERE environment_id = ?1",
            [ENVIRONMENT_ID],
        )
        .unwrap();
    for dry_run in [true, false] {
        assert!(matches!(
            rebuild_projections(&repository, RebuildProjectionsCommand { dry_run }),
            Err(RebuildProjectionsError::Integrity(_))
        ));
        let persisted_pointer: (String, i64) = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT release_id, release_sequence FROM environment_current_releases
                 WHERE environment_id = ?1",
                [ENVIRONMENT_ID],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted_pointer, (FIRST_RELEASE_ID.to_owned(), 999));
    }
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE release_proofs SET envelope_json = ?1 WHERE proof_id = ?2",
            (release.proof_envelope_json.as_str(), FIRST_PROOF_ID),
        )
        .unwrap();
    let repaired_pointer =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(repaired_pointer.changed);
    assert_eq!(repaired_pointer.environment_pointer_count, 1);
    assert_eq!(
        get_release(&repository, release.release_id).unwrap(),
        release
    );

    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE signing_keys SET public_key = ?1 WHERE key_id = ?2",
            ("0".repeat(64), release.key_id.as_str()),
        )
        .unwrap();
    assert!(matches!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: release.release_id,
                verified_at: "2026-08-03T21:40:00Z".parse().unwrap(),
            },
        ),
        Err(ReleaseError::Integrity(_))
    ));
}

#[test]
fn release_trust_uses_signing_time_and_revoked_keys_cannot_sign_again() {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    prepare_two_mixed_editions(&repository);
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T20:15:00Z",
        ),
    )
    .unwrap();
    let first = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T21:00:00Z",
        ),
    )
    .unwrap();

    persist_signing_key_revocation(&repository, &first.key_id, "2026-08-03T21:30:00Z");
    assert!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: first.release_id,
                verified_at: "2026-08-03T21:31:00Z".parse().unwrap(),
            },
        )
        .unwrap()
        .valid
    );
    assert!(matches!(
        promote_release(
            &repository,
            promotion_command(
                SECOND_RELEASE_ID,
                SECOND_PROOF_ID,
                OTHER_EDITION_ID,
                SECOND_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-03T22:00:00Z",
            ),
        ),
        Err(ReleaseError::Signing(_))
    ));
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(first.release_id)
    );
    let release_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM releases", [], |row| row.get(0))
        .unwrap();
    assert_eq!(release_count, 1);

    persist_signing_key_revocation(&repository, &first.key_id, "2026-08-03T21:00:00Z");
    assert!(matches!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: first.release_id,
                verified_at: "2026-08-03T22:01:00Z".parse().unwrap(),
            },
        ),
        Err(ReleaseError::Integrity(_))
    ));
}

fn assert_release_read_surfaces_reject_integrity(
    repository: &LocalWorkspace,
    release_id: ReleaseId,
    evaluated_at: &str,
) {
    assert!(matches!(
        get_release(repository, release_id),
        Err(ReleaseError::Integrity(_))
    ));
    assert!(matches!(
        verify_release(
            repository,
            VerifyReleaseCommand {
                release_id,
                verified_at: evaluated_at.parse().unwrap(),
            },
        ),
        Err(ReleaseError::Integrity(_))
    ));
    assert!(matches!(
        query_released_objects(
            repository,
            QueryReleasedObjectsCommand {
                operating_principal_id: None,
                delegation_id: None,
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                evaluated_at: evaluated_at.parse().unwrap(),
            },
        ),
        Err(QueryReleasedObjectsError::Integrity(_))
    ));
}

fn assert_release_history_violation(
    repository: &LocalWorkspace,
    release_id: ReleaseId,
    expected_detail: &str,
) {
    assert!(matches!(
        get_release(repository, release_id),
        Err(ReleaseError::Integrity(detail)) if detail == expected_detail
    ));
    assert!(matches!(
        verify_release(
            repository,
            VerifyReleaseCommand {
                release_id,
                verified_at: "2026-08-03T22:10:00Z".parse().unwrap(),
            },
        ),
        Err(ReleaseError::Integrity(detail)) if detail == expected_detail
    ));
    assert!(matches!(
        query_released_objects(
            repository,
            QueryReleasedObjectsCommand {
                operating_principal_id: None,
                delegation_id: None,
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                object_ids: vec![OBJECT_ID.parse().unwrap()],
                evaluated_at: "2026-08-03T22:10:00Z".parse().unwrap(),
            },
        ),
        Err(QueryReleasedObjectsError::Integrity(detail)) if detail == expected_detail
    ));
    for dry_run in [true, false] {
        assert!(matches!(
            rebuild_projections(repository, RebuildProjectionsCommand { dry_run }),
            Err(RebuildProjectionsError::Integrity(detail)) if detail == expected_detail
        ));
        let current_release_id: String = repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT release_id FROM environment_current_releases
                 WHERE environment_id = ?1",
                [ENVIRONMENT_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(current_release_id, SECOND_RELEASE_ID);
    }
}

fn promotion_command(
    release_id: &str,
    proof_id: &str,
    edition_id: &str,
    idempotency_key: &str,
    released_at: &str,
) -> PromoteReleaseCommand {
    PromoteReleaseCommand {
        release_id: release_id.parse::<ReleaseId>().unwrap(),
        proof_id: proof_id.parse::<ProofId>().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        edition_id: edition_id.parse().unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        released_at: released_at.parse().unwrap(),
    }
}

fn context_delegation_command(
    delegation_id: &str,
    idempotency_key: &str,
) -> GrantDelegationCommand {
    GrantDelegationCommand {
        delegation_id: delegation_id.parse().unwrap(),
        recipient_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
        actions: vec![
            DelegatedAction::ContextBuild,
            DelegatedAction::ObjectQueryReleased,
        ],
        scope: DelegationScope {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            environment_ids: vec![ENVIRONMENT_ID.parse().unwrap()],
            object_ids: vec![OBJECT_ID.parse().unwrap()],
        },
        constraints: DelegationConstraints {
            max_objects: 1,
            max_context_bytes: 16_384,
            allow_subdelegation: false,
        },
        not_before: "2026-08-03T23:00:00Z".parse().unwrap(),
        expires_at: "2026-08-04T00:00:00Z".parse().unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        issued_at: "2026-08-03T22:55:00Z".parse().unwrap(),
    }
}

fn prepare_released_context_pack(
    repository: &LocalWorkspace,
) -> (BuildContextPackCommand, proof_application::ContextPack) {
    prepare_first_mixed_edition(repository);
    create_environment(
        repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    promote_release(
        repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T21:00:00Z",
        ),
    )
    .unwrap();
    let agent = create_agent_principal(
        repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "context-reader",
            "2026-08-03T22:45:00Z",
        ),
    )
    .unwrap();
    let delegation = grant_delegation(
        repository,
        context_delegation_command(DELEGATION_ID, DELEGATION_IDEMPOTENCY_KEY),
    )
    .unwrap();
    let command = BuildContextPackCommand {
        context_pack_id: CONTEXT_PACK_ID.parse().unwrap(),
        operating_principal_id: agent.principal_id,
        delegation_id: delegation.delegation_id,
        task_id: "release-summary-1".to_owned(),
        intent: ChangeSetIntent::new("Summarize the released article").unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        object_ids: vec![OBJECT_ID.parse().unwrap()],
        limits: ContextPackLimits {
            max_objects: 10,
            max_bytes: 1_048_576,
        },
        idempotency_key: CONTEXT_PACK_IDEMPOTENCY_KEY.parse().unwrap(),
        built_at: "2026-08-03T23:20:00Z".parse().unwrap(),
        expires_at: "2026-08-03T23:50:00Z".parse().unwrap(),
    };
    let context = build_context_pack(repository, command.clone()).unwrap();
    (command, context)
}

fn prepare_delegation_dependencies(repository: &LocalWorkspace) {
    prepare_approved_mixed_changeset(repository);
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T17:05:00Z",
        ),
    )
    .unwrap();
    create_agent_principal(
        repository,
        agent_command(
            AGENT_PRINCIPAL_ID,
            AGENT_IDEMPOTENCY_KEY,
            "release-reader",
            "2026-08-03T17:10:00Z",
        ),
    )
    .unwrap();
}

fn environment_command(
    environment_id: &str,
    idempotency_key: &str,
    required_approval: &str,
    created_at: &str,
) -> CreateEnvironmentCommand {
    CreateEnvironmentCommand {
        environment_id: environment_id.parse::<EnvironmentId>().unwrap(),
        target_kind: "proof.local/released-state/v1".to_owned(),
        policy_profile: "proof.local/release-policy/v1".to_owned(),
        required_approval: ApprovalName::new(required_approval).unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        created_at: created_at.parse().unwrap(),
    }
}

fn agent_command(
    principal_id: &str,
    idempotency_key: &str,
    display_name: &str,
    created_at: &str,
) -> CreateAgentPrincipalCommand {
    CreateAgentPrincipalCommand {
        principal_id: principal_id.parse().unwrap(),
        display_name: display_name.to_owned(),
        idempotency_key: idempotency_key.parse().unwrap(),
        created_at: created_at.parse().unwrap(),
    }
}

fn delegation_command(
    delegation_id: &str,
    idempotency_key: &str,
    issued_at: &str,
) -> GrantDelegationCommand {
    GrantDelegationCommand {
        delegation_id: delegation_id.parse::<DelegationId>().unwrap(),
        recipient_principal_id: AGENT_PRINCIPAL_ID.parse().unwrap(),
        actions: vec![
            DelegatedAction::ObjectQueryReleased,
            DelegatedAction::WorkspaceStatus,
        ],
        scope: DelegationScope {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            environment_ids: vec![ENVIRONMENT_ID.parse().unwrap()],
            object_ids: vec![OBJECT_ID.parse().unwrap()],
        },
        constraints: DelegationConstraints {
            max_objects: 1,
            max_context_bytes: 4_096,
            allow_subdelegation: false,
        },
        not_before: "2026-08-03T18:00:00Z".parse().unwrap(),
        expires_at: "2026-08-03T20:00:00Z".parse().unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        issued_at: issued_at.parse().unwrap(),
    }
}

fn downgrade_database_to_v10(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    if version == 10 {
        return;
    }
    assert_eq!(version, 11);
    connection
        .execute_batch(
            "DROP TABLE localized_release_operations;
             DROP TABLE localized_release_metadata;
             DROP TABLE localized_edition_operations;
             DROP TABLE localized_edition_metadata;
             DROP TABLE localized_commits;
             DROP TABLE object_locale_revisions;
             DROP TABLE localized_approvals;
             DROP TABLE localized_submissions;
             DROP TABLE localized_validations;
             DROP TABLE localized_add_operations;
             DROP TABLE localized_edits;
             DROP TABLE localized_changesets;
             DROP TABLE localized_context_build_operations;
             DROP TABLE localized_context_packs;
             DROP TABLE content_resource_intent_operations;
             DROP TABLE content_resource_intents;
             DROP TABLE known_state_artifacts;
             ALTER TABLE known_state DROP COLUMN manifest_json;
             ALTER TABLE known_state DROP COLUMN api_version;
             ALTER TABLE editions DROP COLUMN api_version;
             ALTER TABLE releases DROP COLUMN api_version;
             ALTER TABLE release_proofs DROP COLUMN predicate_type;
             DELETE FROM schema_migrations WHERE version = 11;
             UPDATE workspace_metadata SET schema_version = 10 WHERE singleton = 1;
             PRAGMA user_version = 10;",
        )
        .unwrap();
}

fn downgrade_database_to_v9(repository: &LocalWorkspace) {
    downgrade_database_to_v10(repository);
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE context_pack_build_operations;
             DROP TABLE context_packs;
             DROP TABLE release_proof_export_outbox;
             DROP TABLE release_operations;
             DROP TABLE release_proofs;
             DROP TABLE environment_current_releases;
             DROP TABLE releases;
             DROP TABLE release_policy_decisions;
             DROP TABLE signing_key_revocations;
             DROP TABLE signing_keys;
             DROP TABLE delegation_revoke_operations;
             DROP TABLE delegation_revocations;
             DROP TABLE delegation_grant_operations;
             DROP TABLE delegations;
             DROP TABLE principal_create_operations;
             DROP TABLE principal_registrations;
             DROP TABLE environment_create_operations;
             DROP TABLE environment_versions;
             DROP TABLE environments;",
        )
        .unwrap();
    for table in [
        "changesets",
        "changeset_add_operations",
        "changeset_submissions",
        "changeset_approvals",
        "changeset_commits",
        "edition_create_operations",
    ] {
        drop_effect_column_if_present(&connection, table);
    }
    connection
        .execute_batch(
            "DELETE FROM schema_migrations WHERE version = 10;
             UPDATE workspace_metadata SET schema_version = 9 WHERE singleton = 1;
             PRAGMA user_version = 9;",
        )
        .unwrap();
}

fn downgrade_database_to_v2(repository: &LocalWorkspace) {
    downgrade_database_to_v9(repository);
    repository
        .open_database()
        .unwrap()
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
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 3;
             UPDATE workspace_metadata SET schema_version = 2 WHERE singleton = 1;
             PRAGMA user_version = 2;",
        )
        .unwrap();
}

fn downgrade_database_to_v1(repository: &LocalWorkspace) {
    downgrade_database_to_v2(repository);
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE changesets;
             DELETE FROM schema_migrations WHERE version >= 2;
             UPDATE workspace_metadata SET schema_version = 1 WHERE singleton = 1;
             PRAGMA user_version = 1;",
        )
        .unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "the staged fixture follows the exact operation that introduced each historical schema version"
)]
fn prepare_exact_legacy_fixture(repository: &LocalWorkspace, target_version: u32) {
    assert!((1..=9).contains(&target_version));
    downgrade_database_to_v1(repository);
    if target_version == 1 {
        return;
    }

    create_changeset(
        repository,
        draft_command(CHANGESET_ID, "Define the legacy article Schema", None),
    )
    .unwrap();
    if target_version == 2 {
        return;
    }

    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![constrained_schema_edit(EDIT_ID, "article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 3 {
        return;
    }

    assert!(
        validate_changeset(repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    if target_version == 4 {
        downgrade_validated_database_to_v4(repository);
        return;
    }

    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 5 {
        return;
    }

    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 6 {
        return;
    }

    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 7 {
        return;
    }

    create_edition(
        repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
    if target_version == 8 {
        return;
    }

    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Create the legacy article Object").unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![object_edit(
                OBJECT_EDIT_ID,
                OBJECT_ID,
                "article",
                &serde_json::json!({"title": "Legacy migration"}),
            )],
            idempotency_key: SECOND_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, OTHER_CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T19:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: SECOND_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T20:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        edition_command(
            OTHER_EDITION_ID,
            SECOND_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T20:10:00Z",
        ),
    )
    .unwrap();
}

fn prepare_exact_pre_v11_fixture(repository: &LocalWorkspace, target_version: u32) {
    assert!((1..=10).contains(&target_version));
    if target_version <= 9 {
        prepare_exact_legacy_fixture(repository, target_version);
        return;
    }
    prepare_exact_legacy_fixture(repository, 9);
    rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    downgrade_database_to_v10(repository);
}

fn downgrade_validated_database_to_v4(repository: &LocalWorkspace) {
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE changeset_submissions;
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 5;
             UPDATE workspace_metadata SET schema_version = 4 WHERE singleton = 1;
             PRAGMA user_version = 4;",
        )
        .unwrap();
}

#[derive(Debug, Eq, PartialEq)]
struct LegacyEvidenceSnapshot {
    principals: Vec<Vec<String>>,
    workspace: Vec<Vec<String>>,
    known_state: Vec<Vec<String>>,
    changesets: Vec<Vec<String>>,
    edits: Vec<Vec<String>>,
    add_operations: Vec<Vec<String>>,
    validations: Vec<Vec<String>>,
    submissions: Vec<Vec<String>>,
    approvals: Vec<Vec<String>>,
    schema_versions: Vec<Vec<String>>,
    commits: Vec<Vec<String>>,
    editions: Vec<Vec<String>>,
    edition_operations: Vec<Vec<String>>,
    object_revisions: Vec<Vec<String>>,
}

#[derive(Debug, Eq, PartialEq)]
struct LifecycleWriteSnapshot {
    evidence: LegacyEvidenceSnapshot,
    effect_digests: Vec<Vec<String>>,
}

fn assert_legacy_authority_unchanged(
    before: &LegacyEvidenceSnapshot,
    after: &LegacyEvidenceSnapshot,
) {
    assert_eq!(after.principals, before.principals);
    assert_eq!(after.workspace, before.workspace);
    assert_eq!(after.changesets, before.changesets);
    assert_eq!(after.edits, before.edits);
    assert_eq!(after.add_operations, before.add_operations);
    assert_eq!(after.validations, before.validations);
    assert_eq!(after.submissions, before.submissions);
    assert_eq!(after.approvals, before.approvals);
    assert_eq!(after.commits, before.commits);
    assert_eq!(after.editions, before.editions);
    assert_eq!(after.edition_operations, before.edition_operations);
}

fn lifecycle_write_snapshot(
    repository: &LocalWorkspace,
    schema_version: u32,
) -> LifecycleWriteSnapshot {
    let effect_digests = if schema_version >= 10 {
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT 'changeset', changeset_id, effect_digest FROM changesets
             UNION ALL
             SELECT 'add', changeset_id, effect_digest FROM changeset_add_operations
             UNION ALL
             SELECT 'submission', changeset_id, effect_digest FROM changeset_submissions
             UNION ALL
             SELECT 'approval', changeset_id, effect_digest FROM changeset_approvals
             UNION ALL
             SELECT 'commit', changeset_id, effect_digest FROM changeset_commits
             ORDER BY 1, 2",
        )
    } else {
        Vec::new()
    };
    LifecycleWriteSnapshot {
        evidence: legacy_evidence_snapshot(repository, 9),
        effect_digests,
    }
}

#[derive(Debug, Eq, PartialEq)]
struct RebuildLifecycleGuardSnapshot {
    submissions: Vec<Vec<String>>,
    approvals: Vec<Vec<String>>,
    commits: Vec<Vec<String>>,
    known_state: Vec<Vec<String>>,
    schema_versions: Vec<Vec<String>>,
    object_revisions: Vec<Vec<String>>,
    environment_pointers: Vec<Vec<String>>,
}

fn rebuild_lifecycle_guard_snapshot(repository: &LocalWorkspace) -> RebuildLifecycleGuardSnapshot {
    let connection = repository.open_database().unwrap();
    RebuildLifecycleGuardSnapshot {
        submissions: snapshot_rows(
            &connection,
            "SELECT changeset_id, changeset_digest, validation_results_digest,
                    principal_id, submitted_at, effect_digest
             FROM changeset_submissions ORDER BY changeset_id",
        ),
        approvals: snapshot_rows(
            &connection,
            "SELECT changeset_id, approval_name, changeset_digest,
                    validation_results_digest, principal_id, approved_at, effect_digest
             FROM changeset_approvals ORDER BY changeset_id",
        ),
        commits: snapshot_rows(
            &connection,
            "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                    changeset_digest, validation_results_digest, previous_state,
                    resulting_state, authoritative_sequence, committed_at, edit_count,
                    effect_digest
             FROM changeset_commits ORDER BY changeset_id",
        ),
        known_state: snapshot_rows(
            &connection,
            "SELECT singleton, authoritative_sequence, state_digest
             FROM known_state ORDER BY singleton",
        ),
        schema_versions: snapshot_rows(
            &connection,
            "SELECT schema_id, schema_version, document_json, document_digest,
                    changeset_id, edit_id, authoritative_sequence
             FROM schema_versions ORDER BY schema_id, schema_version",
        ),
        object_revisions: snapshot_rows(
            &connection,
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest, changeset_id, edit_id,
                    authoritative_sequence
             FROM object_revisions ORDER BY object_id, revision",
        ),
        environment_pointers: snapshot_rows(
            &connection,
            "SELECT environment_id, release_id, release_sequence, projection_version
             FROM environment_current_releases ORDER BY environment_id",
        ),
    }
}

fn edition_write_snapshot(repository: &LocalWorkspace) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let connection = repository.open_database().unwrap();
    (
        snapshot_rows(
            &connection,
            "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, object_set_digest, edition_digest,
                    manifest_json, created_at
             FROM editions ORDER BY edition_id",
        ),
        snapshot_rows(
            &connection,
            "SELECT workspace_id, principal_id, idempotency_key, requested_state_digest,
                    edition_id, effect_digest
             FROM edition_create_operations ORDER BY workspace_id, principal_id,
                    idempotency_key",
        ),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "the snapshot explicitly binds every historical fact column that survives migration"
)]
fn legacy_evidence_snapshot(
    repository: &LocalWorkspace,
    source_version: u32,
) -> LegacyEvidenceSnapshot {
    let connection = repository.open_database().unwrap();
    let changesets = if source_version >= 5 {
        snapshot_rows(
            &connection,
            "SELECT changeset_id, workspace_id, principal_id, intent,
                    requested_base_state, base_authoritative_sequence, base_state,
                    idempotency_key, created_at, status, lifecycle_status,
                    policy_profile, validation_profile
             FROM changesets ORDER BY changeset_id",
        )
    } else if source_version >= 2 {
        snapshot_rows(
            &connection,
            "SELECT changeset_id, workspace_id, principal_id, intent,
                    requested_base_state, base_authoritative_sequence, base_state,
                    idempotency_key, created_at, status, policy_profile,
                    validation_profile
             FROM changesets ORDER BY changeset_id",
        )
    } else {
        Vec::new()
    };
    let edits = if source_version >= 9 {
        snapshot_rows(
            &connection,
            "SELECT changeset_id, ordinal, edit_id, edit_kind, schema_id,
                    schema_version, object_id, document_json, document_digest
             FROM changeset_edits ORDER BY changeset_id, ordinal",
        )
    } else if source_version >= 3 {
        snapshot_rows(
            &connection,
            "SELECT changeset_id, ordinal, edit_id, edit_kind, schema_id,
                    schema_version, document_json, document_digest
             FROM changeset_edits ORDER BY changeset_id, ordinal",
        )
    } else {
        Vec::new()
    };
    let editions = if source_version >= 9 {
        snapshot_rows(
            &connection,
            "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, object_set_digest,
                    edition_digest, manifest_json, created_at
             FROM editions ORDER BY edition_id",
        )
    } else if source_version >= 8 {
        snapshot_rows(
            &connection,
            "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, edition_digest, manifest_json,
                    created_at
             FROM editions ORDER BY edition_id",
        )
    } else {
        Vec::new()
    };

    LegacyEvidenceSnapshot {
        principals: snapshot_rows(
            &connection,
            "SELECT principal_id, principal_type, identity_provider, identity_subject,
                    enabled FROM principals ORDER BY principal_id",
        ),
        workspace: snapshot_rows(
            &connection,
            "SELECT singleton, workspace_id, bootstrap_principal_id
             FROM workspace_metadata ORDER BY singleton",
        ),
        known_state: snapshot_rows(
            &connection,
            "SELECT singleton, authoritative_sequence, state_digest
             FROM known_state ORDER BY singleton",
        ),
        changesets,
        edits,
        add_operations: if source_version >= 3 {
            snapshot_rows(
                &connection,
                "SELECT workspace_id, principal_id, changeset_id, idempotency_key,
                        request_digest, first_ordinal, added_count, total_edit_count
                 FROM changeset_add_operations
                 ORDER BY workspace_id, principal_id, changeset_id, idempotency_key",
            )
        } else {
            Vec::new()
        },
        validations: if source_version >= 4 {
            snapshot_rows(
                &connection,
                "SELECT changeset_id, changeset_digest, base_state,
                        validation_profile, validator, valid, results_json,
                        results_digest
                 FROM changeset_validations
                 ORDER BY changeset_id, changeset_digest, validation_profile, validator",
            )
        } else {
            Vec::new()
        },
        submissions: if source_version >= 5 {
            snapshot_rows(
                &connection,
                "SELECT changeset_id, changeset_digest, validation_results_digest,
                        principal_id, submitted_at
                 FROM changeset_submissions ORDER BY changeset_id",
            )
        } else {
            Vec::new()
        },
        approvals: if source_version >= 6 {
            snapshot_rows(
                &connection,
                "SELECT changeset_id, approval_name, changeset_digest,
                        validation_results_digest, principal_id, approved_at
                 FROM changeset_approvals ORDER BY changeset_id",
            )
        } else {
            Vec::new()
        },
        schema_versions: if source_version >= 7 {
            snapshot_rows(
                &connection,
                "SELECT schema_id, schema_version, document_json, document_digest,
                        changeset_id, edit_id, authoritative_sequence
                 FROM schema_versions ORDER BY schema_id, schema_version",
            )
        } else {
            Vec::new()
        },
        commits: if source_version >= 7 {
            snapshot_rows(
                &connection,
                "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                        changeset_digest, validation_results_digest, previous_state,
                        resulting_state, authoritative_sequence, committed_at, edit_count
                 FROM changeset_commits ORDER BY changeset_id",
            )
        } else {
            Vec::new()
        },
        editions,
        edition_operations: if source_version >= 8 {
            snapshot_rows(
                &connection,
                "SELECT workspace_id, principal_id, idempotency_key,
                        requested_state_digest, edition_id
                 FROM edition_create_operations
                 ORDER BY workspace_id, principal_id, idempotency_key",
            )
        } else {
            Vec::new()
        },
        object_revisions: if source_version >= 9 {
            snapshot_rows(
                &connection,
                "SELECT object_id, revision, schema_id, schema_version,
                        lifecycle_state, content_json, object_digest, changeset_id,
                        edit_id, authoritative_sequence
                 FROM object_revisions ORDER BY object_id, revision",
            )
        } else {
            Vec::new()
        },
    }
}

fn snapshot_rows(connection: &rusqlite::Connection, query: &str) -> Vec<Vec<String>> {
    let mut statement = connection.prepare(query).unwrap();
    let column_count = statement.column_count();
    statement
        .query_map([], |row| {
            (0..column_count)
                .map(|index| {
                    let value = row.get_ref(index)?;
                    Ok(match value {
                        rusqlite::types::ValueRef::Null => "null".to_owned(),
                        rusqlite::types::ValueRef::Integer(value) => format!("integer:{value}"),
                        rusqlite::types::ValueRef::Real(value) => {
                            format!("real:{}", value.to_bits())
                        }
                        rusqlite::types::ValueRef::Text(value) => {
                            format!("text:{}", String::from_utf8_lossy(value))
                        }
                        rusqlite::types::ValueRef::Blob(value) => format!("blob:{value:?}"),
                    })
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn swap_idempotency_keys(
    repository: &LocalWorkspace,
    table: &str,
    first: &str,
    second: &str,
    temporary: &str,
) {
    let mut connection = repository.open_database().unwrap();
    let transaction = connection.transaction().unwrap();
    for (from, to) in [(first, temporary), (second, first), (temporary, second)] {
        assert_eq!(
            transaction
                .execute(
                    &format!("UPDATE {table} SET idempotency_key = ?1 WHERE idempotency_key = ?2"),
                    (to, from),
                )
                .unwrap(),
            1,
            "expected exactly one {table} row for idempotency key {from}"
        );
    }
    transaction.commit().unwrap();
}

fn storage_schema_snapshot(repository: &LocalWorkspace) -> Vec<Vec<String>> {
    snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT type, name, tbl_name, rootpage, sql
         FROM sqlite_schema ORDER BY type, name",
    )
}

fn drop_effect_column_if_present(connection: &rusqlite::Connection, table: &str) {
    let exists: bool = connection
        .query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('{table}')
                     WHERE name = 'effect_digest'
                 )"
            ),
            [],
            |row| row.get(0),
        )
        .unwrap();
    if exists {
        connection
            .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN effect_digest;"))
            .unwrap();
    }
}

fn assert_storage_version(repository: &LocalWorkspace, expected: u32) {
    let connection = repository.open_database().unwrap();
    let versions: (u32, u32, u32) = connection
        .query_row(
            "SELECT schema_version, (SELECT MAX(version) FROM schema_migrations),
                    (SELECT user_version FROM pragma_user_version)
             FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(versions, (expected, expected, expected));
}

fn assert_foreign_keys_clean(connection: &rusqlite::Connection) {
    let violations = {
        let mut statement = connection.prepare("PRAGMA foreign_key_check").unwrap();
        statement
            .query_map([], |_| Ok(()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(violations.is_empty());
}

fn assert_v9_migration_rejected_atomically(repository: &LocalWorkspace) {
    assert_legacy_migration_rejected_atomically(repository, 9);
}

fn assert_legacy_migration_rejected_atomically(repository: &LocalWorkspace, source_version: u32) {
    assert_storage_version(repository, source_version);
    assert_legacy_effect_columns(repository, source_version, false);
    let schema_before = storage_schema_snapshot(repository);
    let evidence_before = legacy_evidence_snapshot(repository, source_version);

    assert!(matches!(
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }),
        Err(RebuildProjectionsError::Integrity(_))
    ));

    assert_storage_version(repository, source_version);
    assert_legacy_effect_columns(repository, source_version, false);
    assert_eq!(storage_schema_snapshot(repository), schema_before);
    assert_eq!(
        legacy_evidence_snapshot(repository, source_version),
        evidence_before
    );
    assert_foreign_keys_clean(&repository.open_database().unwrap());
}

fn assert_effect_column(repository: &LocalWorkspace, table: &str, expected: bool) {
    let connection = repository.open_database().unwrap();
    let column_count: i64 = connection
        .query_row(
            &format!(
                "SELECT COUNT(*) FROM pragma_table_info('{table}')
                 WHERE name = 'effect_digest'"
            ),
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        column_count,
        i64::from(expected),
        "unexpected {table}.effect_digest presence"
    );
}

fn assert_legacy_effect_columns(repository: &LocalWorkspace, source_version: u32, expected: bool) {
    for (introduced_in, table) in [
        (2, "changesets"),
        (3, "changeset_add_operations"),
        (5, "changeset_submissions"),
        (6, "changeset_approvals"),
        (7, "changeset_commits"),
        (8, "edition_create_operations"),
    ] {
        if source_version >= introduced_in {
            assert_effect_column(repository, table, expected);
        }
    }
}

fn assert_operation_effect_columns(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    for table in [
        "changesets",
        "changeset_add_operations",
        "changeset_submissions",
        "changeset_approvals",
        "changeset_commits",
        "edition_create_operations",
        "environment_create_operations",
        "principal_create_operations",
        "delegation_grant_operations",
        "delegation_revoke_operations",
        "context_pack_build_operations",
    ] {
        let (column_count, not_null_count): (i64, i64) = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*), COALESCE(SUM(\"notnull\"), 0)
                     FROM pragma_table_info('{table}') WHERE name = 'effect_digest'"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(column_count, 1, "{table} has no effect_digest column");
        assert_eq!(not_null_count, 1, "{table}.effect_digest is nullable");
    }
}

fn assert_legacy_effect_digests(repository: &LocalWorkspace, source_version: u32) {
    let connection = repository.open_database().unwrap();
    for (introduced_in, table) in [
        (2, "changesets"),
        (3, "changeset_add_operations"),
        (5, "changeset_submissions"),
        (6, "changeset_approvals"),
        (7, "changeset_commits"),
        (8, "edition_create_operations"),
    ] {
        let expected_count = if source_version >= 9 {
            2
        } else {
            usize::from(source_version >= introduced_in)
        };
        let mut statement = connection
            .prepare(&format!("SELECT effect_digest FROM {table} ORDER BY rowid"))
            .unwrap();
        let digests = statement
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            digests.len(),
            expected_count,
            "unexpected migrated row count in {table}"
        );
        let placeholder = format!("blake3:{}", "0".repeat(64));
        for persisted in digests {
            persisted.parse::<ContentDigest>().unwrap();
            assert_ne!(persisted, placeholder, "placeholder effect in {table}");
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "each historical operation is replayed with its exact original command so every backfilled effect is consumer-verifiable"
)]
fn assert_migrated_legacy_effects_replay(repository: &LocalWorkspace, source_version: u32) {
    if source_version < 2 {
        return;
    }
    create_changeset(
        repository,
        draft_command(CHANGESET_ID, "Define the legacy article Schema", None),
    )
    .unwrap();
    inspect_changeset(repository, CHANGESET_ID.parse().unwrap()).unwrap();
    if source_version < 3 {
        return;
    }
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![constrained_schema_edit(EDIT_ID, "article")],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    if source_version < 5 {
        return;
    }
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if source_version < 6 {
        return;
    }
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if source_version < 7 {
        return;
    }
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if source_version < 8 {
        return;
    }
    if source_version == 8 {
        create_edition(
            repository,
            edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
        )
        .unwrap();
        return;
    }

    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Create the legacy article Object").unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![object_edit(
                OBJECT_EDIT_ID,
                OBJECT_ID,
                "article",
                &serde_json::json!({"title": "Legacy migration"}),
            )],
            idempotency_key: SECOND_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T19:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: SECOND_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T20:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        edition_command(
            OTHER_EDITION_ID,
            SECOND_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T20:10:00Z",
        ),
    )
    .unwrap();
}

fn assert_no_v10_authority_or_release_rows(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    for table in [
        "environments",
        "environment_versions",
        "environment_create_operations",
        "signing_keys",
        "signing_key_revocations",
        "release_policy_decisions",
        "releases",
        "environment_current_releases",
        "release_proofs",
        "release_operations",
        "release_proof_export_outbox",
        "principal_registrations",
        "principal_create_operations",
        "delegations",
        "delegation_grant_operations",
        "delegation_revocations",
        "delegation_revoke_operations",
        "context_packs",
        "context_pack_build_operations",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "migration fabricated rows in {table}");
    }
}

fn assert_latest_schema_and_foreign_keys(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    let (metadata_version, migration_version): (u32, u32) = connection
        .query_row(
            "SELECT schema_version, (SELECT MAX(version) FROM schema_migrations)
             FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let pragma_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(
        (metadata_version, migration_version, pragma_version),
        (11, 11, 11)
    );
    let v10_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN (
                 'environments', 'environment_versions', 'environment_create_operations',
                 'signing_keys', 'signing_key_revocations', 'release_policy_decisions',
                 'releases', 'environment_current_releases', 'release_proofs',
                 'release_operations', 'release_proof_export_outbox',
                 'principal_registrations',
                 'principal_create_operations', 'delegations',
                 'delegation_grant_operations', 'delegation_revocations',
                 'delegation_revoke_operations', 'context_packs',
                 'context_pack_build_operations'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(v10_table_count, 19);
    let v11_table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN (
                 'known_state_artifacts', 'content_resource_intents',
                 'content_resource_intent_operations', 'localized_context_packs',
                 'localized_context_build_operations', 'localized_changesets',
                 'localized_edits', 'localized_add_operations',
                 'localized_validations', 'localized_submissions',
                 'localized_approvals', 'object_locale_revisions',
                 'localized_commits', 'localized_edition_metadata',
                 'localized_edition_operations', 'localized_release_metadata',
                 'localized_release_operations'
             )",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(v11_table_count, 17);
    let foreign_key_violations = {
        let mut statement = connection.prepare("PRAGMA foreign_key_check").unwrap();
        statement
            .query_map([], |_| Ok(()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(foreign_key_violations.is_empty());
}

fn assert_no_v11_localized_rows(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    for table in [
        "content_resource_intents",
        "content_resource_intent_operations",
        "localized_context_packs",
        "localized_context_build_operations",
        "localized_changesets",
        "localized_edits",
        "localized_add_operations",
        "localized_validations",
        "localized_submissions",
        "localized_approvals",
        "object_locale_revisions",
        "localized_commits",
        "localized_edition_metadata",
        "localized_edition_operations",
        "localized_release_metadata",
        "localized_release_operations",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "migration fabricated rows in {table}");
    }
    let artifacts: Vec<Vec<String>> = snapshot_rows(
        &connection,
        "SELECT api_version, authoritative_sequence, state_digest, manifest_json,
                changeset_id FROM known_state_artifacts ORDER BY authoritative_sequence",
    );
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0][0], "text:proof.dev/known-state/v1");
    assert_eq!(artifacts[0][3], "null");
    assert_eq!(artifacts[0][4], "null");
}

fn test_changeset_digest(changeset: &InspectedChangeSet) -> ContentDigest {
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
    let manifest = canonicalize(&serde_json::json!({
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
    }))
    .unwrap();
    digest(ArtifactKind::ChangeSetV1, &manifest)
}

fn test_edit_batch_digest(changeset: &InspectedChangeSet) -> ContentDigest {
    let edits = changeset
        .edits
        .iter()
        .map(|edit| match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => serde_json::json!({
                "document_digest": edit.document_digest.to_string(),
                "kind": "schema.create",
                "schema_id": edit.schema_id.to_string(),
                "schema_version": edit.schema_version.get(),
            }),
            InspectedChangeSetEdit::ObjectCreate(edit) => serde_json::json!({
                "kind": "object.create",
                "object_digest": edit.object_digest.to_string(),
                "object_id": edit.object_id.to_string(),
                "schema_id": edit.schema_id.to_string(),
                "schema_version": edit.schema_version.get(),
            }),
        })
        .collect::<Vec<_>>();
    let manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/edit-batch/v1",
        "edits": edits,
    }))
    .unwrap();
    digest(ArtifactKind::EditBatchV1, &manifest)
}

fn prepare_two_mixed_editions(repository: &LocalWorkspace) {
    prepare_first_mixed_edition(repository);

    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Add a second released Object").unwrap(),
            requested_base_state: None,
            idempotency_key: SECOND_DRAFT_IDEMPOTENCY_KEY.parse().unwrap(),
            created_at: "2026-08-03T18:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            edits: vec![
                constrained_schema_edit(OTHER_EDIT_ID, "cta"),
                object_edit(
                    OTHER_OBJECT_EDIT_ID,
                    OTHER_OBJECT_ID,
                    "cta",
                    &serde_json::json!({"title": "Second release"}),
                ),
            ],
            idempotency_key: SECOND_ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, OTHER_CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-03T19:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-03T19:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET_ID.parse().unwrap(),
            idempotency_key: SECOND_COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T20:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        edition_command(
            OTHER_EDITION_ID,
            SECOND_EDITION_IDEMPOTENCY_KEY,
            "2026-08-03T20:10:00Z",
        ),
    )
    .unwrap();
}

fn prepare_first_mixed_edition(repository: &LocalWorkspace) {
    prepare_approved_mixed_changeset(repository);
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-03T17:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-03T18:00:00Z"),
    )
    .unwrap();
}

fn prepare_first_mixed_release(repository: &LocalWorkspace) {
    prepare_first_mixed_edition(repository);
    create_environment(
        repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-03T18:10:00Z",
        ),
    )
    .unwrap();
    promote_release(
        repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-03T19:00:00Z",
        ),
    )
    .unwrap();
}

fn persist_signing_key_revocation(repository: &LocalWorkspace, key_id: &str, revoked_at: &str) {
    let revocation = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/signing-key-revocation/v1",
        "key_id": key_id,
        "reason": "compromised",
        "revoked_at": revoked_at,
    }))
    .unwrap();
    let revocation_digest = digest(ArtifactKind::PolicyBundleV1, &revocation);
    repository
        .open_database()
        .unwrap()
        .execute(
            "INSERT INTO signing_key_revocations (
                 key_id, revoked_at, reason, revocation_json, revocation_digest
             ) VALUES (?1, ?2, 'compromised', ?3, ?4)
             ON CONFLICT(key_id) DO UPDATE SET
                 revoked_at = excluded.revoked_at,
                 reason = excluded.reason,
                 revocation_json = excluded.revocation_json,
                 revocation_digest = excluded.revocation_digest",
            (
                key_id,
                revoked_at,
                revocation.as_str(),
                revocation_digest.to_string(),
            ),
        )
        .unwrap();
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

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the localized foundation oracle covers the complete Human repair and Release path"
)]
fn localized_human_path_repairs_and_releases_two_exact_locales() {
    const INTENT_ID: &str = "019c0000-0000-7000-8000-000000000100";
    const CONTEXT_ID: &str = "019c0000-0000-7000-8000-000000000101";
    const LOCALIZED_CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000102";
    const ES_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000103";
    const FR_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000104";
    const FR_REPAIR_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000105";
    const INTENT_KEY: &str = "019c0000-0000-7000-8000-000000000106";
    const CONTEXT_KEY: &str = "019c0000-0000-7000-8000-000000000107";
    const CHANGESET_KEY: &str = "019c0000-0000-7000-8000-000000000108";
    const ADD_KEY: &str = "019c0000-0000-7000-8000-000000000109";
    const REPAIR_KEY: &str = "019c0000-0000-7000-8000-00000000010a";
    const LOCALIZED_COMMIT_KEY: &str = "019c0000-0000-7000-8000-00000000010b";
    const LOCALIZED_EDITION_KEY: &str = "019c0000-0000-7000-8000-00000000010c";
    const LOCALIZED_EDITION_ID: &str = "019c0000-0000-7000-8000-00000000010d";
    const LOCALIZED_RELEASE_ID: &str = "019c0000-0000-7000-8000-00000000010e";
    const LOCALIZED_PROOF_ID: &str = "019c0000-0000-7000-8000-00000000010f";
    const LOCALIZED_RELEASE_KEY: &str = "019c0000-0000-7000-8000-000000000110";
    const REPLACEMENT_INTENT_ID: &str = "019c0000-0000-7000-8000-000000000111";
    const REPLACEMENT_CONTEXT_ID: &str = "019c0000-0000-7000-8000-000000000112";
    const REPLACEMENT_CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000113";
    const REPLACEMENT_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000114";
    const REPLACEMENT_INTENT_KEY: &str = "019c0000-0000-7000-8000-000000000115";
    const REPLACEMENT_CONTEXT_KEY: &str = "019c0000-0000-7000-8000-000000000116";
    const REPLACEMENT_CHANGESET_KEY: &str = "019c0000-0000-7000-8000-000000000117";
    const REPLACEMENT_ADD_KEY: &str = "019c0000-0000-7000-8000-000000000118";
    const REPLACEMENT_COMMIT_KEY: &str = "019c0000-0000-7000-8000-000000000119";
    const REPLACEMENT_EDITION_KEY: &str = "019c0000-0000-7000-8000-00000000011a";
    const REPLACEMENT_EDITION_ID: &str = "019c0000-0000-7000-8000-00000000011b";
    const REPLACEMENT_RELEASE_ID: &str = "019c0000-0000-7000-8000-00000000011c";
    const REPLACEMENT_PROOF_ID: &str = "019c0000-0000-7000-8000-00000000011d";
    const REPLACEMENT_RELEASE_KEY: &str = "019c0000-0000-7000-8000-00000000011e";

    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "title": "Summer campaign",
    });
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Create a localizable campaign source", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                localizable_schema_edit(EDIT_ID, "campaign"),
                object_edit(OBJECT_EDIT_ID, OBJECT_ID, "campaign", &source),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-17T15:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-17T15:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-17T15:10:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-17T15:15:00Z"),
    )
    .unwrap();
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-17T15:20:00Z",
        ),
    )
    .unwrap();
    let baseline_release = promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-17T15:25:00Z",
        ),
    )
    .unwrap();

    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new("campaign").unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source_digest =
        object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
    let es = LocaleId::new("es-ES").unwrap();
    let fr = LocaleId::new("fr-FR").unwrap();
    assert_eq!(
        repository
            .query_released_renditions(QueryReleasedRenditionsCommand {
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![ReleasedLocaleTarget {
                    object_id,
                    locale: fr.clone(),
                }],
                evaluated_at: "2026-08-17T15:29:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotFound
    );
    let targets = vec![
        LocalizedContentTarget {
            object_id,
            schema_id: schema_id.clone(),
            locale: es.clone(),
        },
        LocalizedContentTarget {
            object_id,
            schema_id: schema_id.clone(),
            locale: fr.clone(),
        },
    ];
    let intent = repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: INTENT_ID.parse::<ContentResourceIntentId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets,
            idempotency_key: INTENT_KEY.parse().unwrap(),
            issued_at: "2026-08-17T15:30:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(intent.base.release.release_id, baseline_release.release_id);
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: CONTEXT_ID.parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: fr.clone(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Garantie absolue".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 3,
                max_validation_attempts: 3,
                max_bytes: 1_048_576,
            },
            idempotency_key: CONTEXT_KEY.parse().unwrap(),
            created_at: "2026-08-17T15:31:00Z".parse().unwrap(),
            expires_at: "2026-08-18T15:31:00Z".parse().unwrap(),
        })
        .unwrap();
    let changeset = repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: LOCALIZED_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign into Spanish and French").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: CHANGESET_KEY.parse().unwrap(),
            created_at: "2026-08-17T15:32:00Z".parse().unwrap(),
        })
        .unwrap();
    let expected_source = ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: source_digest,
        schema_id: schema_id.clone(),
        schema_version,
    };
    let es_content = canonicalize(&serde_json::json!({
        "legal": "Se aplican términos estándar",
        "title": "Campaña de verano",
    }))
    .unwrap();
    let invalid_fr_content = canonicalize(&serde_json::json!({
        "legal": "Garantie absolue",
        "title": "Campagne d’été",
    }))
    .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: changeset.changeset_id,
            edits: vec![
                ObjectLocalePutInput {
                    object_id,
                    locale: es.clone(),
                    expected_source: expected_source.clone(),
                    expected_target: None,
                    canonical_content: es_content.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                },
                ObjectLocalePutInput {
                    object_id,
                    locale: fr.clone(),
                    expected_source: expected_source.clone(),
                    expected_target: None,
                    canonical_content: invalid_fr_content.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                },
            ],
            assigned_edit_ids: vec![ES_EDIT_ID.parse().unwrap(), FR_EDIT_ID.parse().unwrap()],
            idempotency_key: ADD_KEY.parse().unwrap(),
        })
        .unwrap();
    let invalid = repository
        .validate_localized_changeset(changeset.changeset_id)
        .unwrap();
    assert!(!invalid.valid);
    assert_eq!(invalid.findings.len(), 1);
    assert_eq!(
        invalid.findings[0].code,
        proof_application::PROHIBITED_LEGAL_CLAIM_CODE
    );
    let repaired_fr_content = canonicalize(&serde_json::json!({
        "legal": "Des conditions standard s’appliquent",
        "title": "Campagne d’été",
    }))
    .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: changeset.changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id,
                locale: fr.clone(),
                expected_source,
                expected_target: None,
                canonical_content: repaired_fr_content.as_str().to_owned(),
                supersedes_edit_id: Some(FR_EDIT_ID.parse().unwrap()),
                repair_of_validation_result_digest: Some(invalid.validation_results_digest),
            }],
            assigned_edit_ids: vec![FR_REPAIR_EDIT_ID.parse().unwrap()],
            idempotency_key: REPAIR_KEY.parse().unwrap(),
        })
        .unwrap();
    let valid = repository
        .validate_localized_changeset(changeset.changeset_id)
        .unwrap();
    assert!(valid.valid);
    assert_eq!(valid.attempt, 2);
    repository
        .submit_localized_changeset(
            changeset.changeset_id,
            "2026-08-17T15:35:00Z".parse().unwrap(),
        )
        .unwrap();
    repository
        .approve_localized_changeset(
            changeset.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-17T15:36:00Z".parse().unwrap(),
        )
        .unwrap();
    let committed = repository
        .commit_localized_changeset(CommitLocalizedChangeSetCommand {
            changeset_id: changeset.changeset_id,
            idempotency_key: LOCALIZED_COMMIT_KEY.parse().unwrap(),
            committed_at: "2026-08-17T15:37:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(committed.renditions.len(), 2);
    assert_eq!(
        committed.previous_state.api_version,
        "proof.dev/known-state/v1"
    );
    assert_eq!(
        committed.resulting_state.api_version,
        "proof.dev/known-state/v2"
    );
    let edition = repository
        .create_localized_edition(CreateLocalizedEditionCommand {
            edition_id: LOCALIZED_EDITION_ID.parse().unwrap(),
            changeset_id: changeset.changeset_id,
            resulting_state_digest: committed.resulting_state.digest,
            idempotency_key: LOCALIZED_EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-17T15:38:00Z".parse().unwrap(),
        })
        .unwrap();
    let release = repository
        .promote_localized_release(PromoteLocalizedReleaseCommand {
            release_id: LOCALIZED_RELEASE_ID.parse().unwrap(),
            proof_id: LOCALIZED_PROOF_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: edition.edition_id,
            expected_base_release_id: baseline_release.release_id,
            idempotency_key: LOCALIZED_RELEASE_KEY.parse().unwrap(),
            released_at: "2026-08-17T15:39:00Z".parse().unwrap(),
        })
        .unwrap();
    let queried = repository
        .query_released_renditions(QueryReleasedRenditionsCommand {
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![
                ReleasedLocaleTarget {
                    object_id,
                    locale: es.clone(),
                },
                ReleasedLocaleTarget {
                    object_id,
                    locale: fr.clone(),
                },
            ],
            evaluated_at: "2026-08-17T15:40:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(queried.release_id, release.release_id);
    assert_eq!(queried.renditions.len(), 2);
    assert!(
        repository
            .verify_localized_release(VerifyLocalizedReleaseCommand {
                release_id: release.release_id,
                verified_at: "2026-08-17T15:41:00Z".parse().unwrap(),
            })
            .unwrap()
            .valid
    );
    assert_eq!(
        repository
            .query_released_renditions(QueryReleasedRenditionsCommand {
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![ReleasedLocaleTarget {
                    object_id,
                    locale: LocaleId::new("de-DE").unwrap(),
                }],
                evaluated_at: "2026-08-17T15:41:30Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotFound
    );

    let first_fr = committed
        .renditions
        .iter()
        .find(|rendition| rendition.locale == fr)
        .unwrap()
        .clone();
    let replacement_intent = repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: REPLACEMENT_INTENT_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id,
                schema_id: schema_id.clone(),
                locale: fr.clone(),
            }],
            idempotency_key: REPLACEMENT_INTENT_KEY.parse().unwrap(),
            issued_at: "2026-08-17T16:00:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(
        replacement_intent.base.release.release_id,
        release.release_id
    );
    assert_eq!(
        replacement_intent.base.known_state,
        committed.resulting_state
    );
    let replacement_context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: REPLACEMENT_CONTEXT_ID.parse().unwrap(),
            resource_intent_id: replacement_intent.intent_id,
            resource_intent_digest: replacement_intent.intent_digest,
            policy_rules: Vec::new(),
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 1,
                max_validation_attempts: 1,
                max_bytes: 1_048_576,
            },
            idempotency_key: REPLACEMENT_CONTEXT_KEY.parse().unwrap(),
            created_at: "2026-08-17T16:01:00Z".parse().unwrap(),
            expires_at: "2026-08-18T16:01:00Z".parse().unwrap(),
        })
        .unwrap();
    let replacement_changeset = repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: REPLACEMENT_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Revise the exact French rendition").unwrap(),
            resource_intent_id: replacement_intent.intent_id,
            resource_intent_digest: replacement_intent.intent_digest,
            context_pack_id: replacement_context.context_pack_id,
            context_pack_digest: replacement_context.context_pack_digest,
            idempotency_key: REPLACEMENT_CHANGESET_KEY.parse().unwrap(),
            created_at: "2026-08-17T16:02:00Z".parse().unwrap(),
        })
        .unwrap();
    let replacement_content = canonicalize(&serde_json::json!({
        "legal": "Des conditions standard s’appliquent",
        "title": "Campagne estivale révisée",
    }))
    .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: replacement_changeset.changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id,
                locale: fr.clone(),
                expected_source: ExpectedLocalizedSource {
                    revision: ObjectRevision::INITIAL,
                    digest: source_digest,
                    schema_id: schema_id.clone(),
                    schema_version,
                },
                expected_target: Some(ExpectedLocalizedTarget {
                    revision: first_fr.revision,
                    digest: first_fr.rendition_digest,
                }),
                canonical_content: replacement_content.as_str().to_owned(),
                supersedes_edit_id: None,
                repair_of_validation_result_digest: None,
            }],
            assigned_edit_ids: vec![REPLACEMENT_EDIT_ID.parse().unwrap()],
            idempotency_key: REPLACEMENT_ADD_KEY.parse().unwrap(),
        })
        .unwrap();
    assert!(
        repository
            .validate_localized_changeset(replacement_changeset.changeset_id)
            .unwrap()
            .valid
    );
    repository
        .submit_localized_changeset(
            replacement_changeset.changeset_id,
            "2026-08-17T16:05:00Z".parse().unwrap(),
        )
        .unwrap();
    repository
        .approve_localized_changeset(
            replacement_changeset.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-17T16:06:00Z".parse().unwrap(),
        )
        .unwrap();
    let replacement_commit = repository
        .commit_localized_changeset(CommitLocalizedChangeSetCommand {
            changeset_id: replacement_changeset.changeset_id,
            idempotency_key: REPLACEMENT_COMMIT_KEY.parse().unwrap(),
            committed_at: "2026-08-17T16:07:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(replacement_commit.previous_state, committed.resulting_state);
    assert_eq!(replacement_commit.renditions.len(), 1);
    assert_eq!(replacement_commit.renditions[0].revision.get(), 2);
    assert_eq!(
        replacement_commit.renditions[0].previous_revision_digest,
        Some(first_fr.rendition_digest)
    );
    assert_eq!(
        repository
            .create_localized_edition(CreateLocalizedEditionCommand {
                edition_id: "019c0000-0000-7000-8000-00000000011f".parse().unwrap(),
                changeset_id: changeset.changeset_id,
                resulting_state_digest: committed.resulting_state.digest,
                idempotency_key: "019c0000-0000-7000-8000-000000000120".parse().unwrap(),
                created_at: "2026-08-17T16:07:30Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::StateConflict
    );
    let replacement_edition = repository
        .create_localized_edition(CreateLocalizedEditionCommand {
            edition_id: REPLACEMENT_EDITION_ID.parse().unwrap(),
            changeset_id: replacement_changeset.changeset_id,
            resulting_state_digest: replacement_commit.resulting_state.digest,
            idempotency_key: REPLACEMENT_EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-17T16:08:00Z".parse().unwrap(),
        })
        .unwrap();
    let replacement_release = repository
        .promote_localized_release(PromoteLocalizedReleaseCommand {
            release_id: REPLACEMENT_RELEASE_ID.parse().unwrap(),
            proof_id: REPLACEMENT_PROOF_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: replacement_edition.edition_id,
            expected_base_release_id: release.release_id,
            idempotency_key: REPLACEMENT_RELEASE_KEY.parse().unwrap(),
            released_at: "2026-08-17T16:09:00Z".parse().unwrap(),
        })
        .unwrap();
    let replacement_query = repository
        .query_released_renditions(QueryReleasedRenditionsCommand {
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![
                ReleasedLocaleTarget {
                    object_id,
                    locale: es.clone(),
                },
                ReleasedLocaleTarget {
                    object_id,
                    locale: fr.clone(),
                },
            ],
            evaluated_at: "2026-08-17T16:09:30Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(replacement_query.release_id, replacement_release.release_id);
    assert_eq!(replacement_query.renditions[0].rendition_revision.get(), 1);
    assert_eq!(replacement_query.renditions[1].rendition_revision.get(), 2);
    assert_eq!(
        replacement_query.renditions[1].canonical_content,
        replacement_content.as_str()
    );

    let rollback_to_v1_command = RollbackLocalizedReleaseCommand {
        release_id: "019c0000-0000-7000-8000-000000000130".parse().unwrap(),
        proof_id: "019c0000-0000-7000-8000-000000000131".parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        expected_current_release_id: replacement_release.release_id,
        rollback_target_release_id: baseline_release.release_id,
        idempotency_key: "019c0000-0000-7000-8000-000000000132".parse().unwrap(),
        released_at: "2026-08-17T16:10:00Z".parse().unwrap(),
    };
    let rollback_to_v1 = repository
        .rollback_localized_release(rollback_to_v1_command.clone())
        .unwrap();
    assert_eq!(rollback_to_v1.kind, ReleaseKind::Rollback);
    assert_eq!(rollback_to_v1.edition.api_version, "proof.dev/edition/v1");
    assert_eq!(
        repository
            .rollback_localized_release(rollback_to_v1_command)
            .unwrap(),
        rollback_to_v1
    );
    assert!(
        repository
            .verify_localized_release(VerifyLocalizedReleaseCommand {
                release_id: rollback_to_v1.release_id,
                verified_at: "2026-08-17T16:11:00Z".parse().unwrap(),
            })
            .unwrap()
            .valid
    );
    assert_eq!(
        repository
            .query_released_renditions(QueryReleasedRenditionsCommand {
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![ReleasedLocaleTarget {
                    object_id,
                    locale: fr.clone(),
                }],
                evaluated_at: "2026-08-17T16:11:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotFound
    );

    let restore_v2 = repository
        .rollback_localized_release(RollbackLocalizedReleaseCommand {
            release_id: "019c0000-0000-7000-8000-000000000133".parse().unwrap(),
            proof_id: "019c0000-0000-7000-8000-000000000134".parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            expected_current_release_id: rollback_to_v1.release_id,
            rollback_target_release_id: replacement_release.release_id,
            idempotency_key: "019c0000-0000-7000-8000-000000000135".parse().unwrap(),
            released_at: "2026-08-17T16:12:00Z".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(restore_v2.edition.api_version, "proof.dev/edition/v2");
    assert_eq!(
        repository
            .query_released_renditions(QueryReleasedRenditionsCommand {
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![
                    ReleasedLocaleTarget {
                        object_id,
                        locale: es,
                    },
                    ReleasedLocaleTarget {
                        object_id,
                        locale: fr,
                    },
                ],
                evaluated_at: "2026-08-17T16:13:00Z".parse().unwrap(),
            })
            .unwrap()
            .renditions
            .len(),
        2
    );
    assert!(
        repository
            .verify_localized_release(VerifyLocalizedReleaseCommand {
                release_id: restore_v2.release_id,
                verified_at: "2026-08-17T16:13:00Z".parse().unwrap(),
            })
            .unwrap()
            .valid
    );
    assert_eq!(
        repository
            .promote_localized_release(PromoteLocalizedReleaseCommand {
                release_id: "019c0000-0000-7000-8000-000000000136".parse().unwrap(),
                proof_id: "019c0000-0000-7000-8000-000000000137".parse().unwrap(),
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                edition_id: edition.edition_id,
                expected_base_release_id: baseline_release.release_id,
                idempotency_key: "019c0000-0000-7000-8000-000000000138".parse().unwrap(),
                released_at: "2026-08-17T16:14:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::StateConflict
    );
    assert_eq!(
        get_environment(&repository, ENVIRONMENT_ID.parse().unwrap())
            .unwrap()
            .current_release_id,
        Some(restore_v2.release_id)
    );
    assert!(
        verify_release(
            &repository,
            VerifyReleaseCommand {
                release_id: baseline_release.release_id,
                verified_at: "2026-08-17T15:42:00Z".parse().unwrap(),
            },
        )
        .unwrap()
        .valid
    );
    let WorkspaceStatus::Initialized(status) = workspace_status(&repository).unwrap() else {
        panic!("localized Workspace must remain initialized");
    };
    assert_eq!(
        status.authoritative_sequence,
        replacement_commit.resulting_state.authoritative_sequence
    );
    assert_eq!(
        status.state_digest,
        replacement_commit.resulting_state.digest
    );
    let expected_rendition = replacement_commit.renditions.first().unwrap();
    let expected_state_manifest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT resulting_state_json FROM localized_commits WHERE changeset_id = ?1",
            [replacement_commit.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let tampered_state_digest = format!("blake3:{}", "f".repeat(64));
    let connection = repository.open_database().unwrap();
    connection
        .execute(
            "UPDATE object_locale_revisions SET content_json = '{}'
             WHERE edit_id = ?1",
            [expected_rendition.edit_id.to_string()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE known_state SET state_digest = ?1, manifest_json = '{}' WHERE singleton = 1",
            [tampered_state_digest.as_str()],
        )
        .unwrap();
    drop(connection);
    let dry_run =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(dry_run.changed);
    assert_eq!(
        dry_run.authoritative_sequence,
        replacement_commit.resulting_state.authoritative_sequence
    );
    assert_eq!(
        dry_run.state_digest,
        replacement_commit.resulting_state.digest
    );
    let still_tampered: (String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT (SELECT content_json FROM object_locale_revisions WHERE edit_id = ?1),
                    state_digest FROM known_state WHERE singleton = 1",
            [expected_rendition.edit_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(still_tampered, ("{}".to_owned(), tampered_state_digest));
    let repaired =
        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(repaired.changed);
    let repaired_projection: (String, String, String) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT (SELECT content_json FROM object_locale_revisions WHERE edit_id = ?1),
                    state_digest, manifest_json FROM known_state WHERE singleton = 1",
            [expected_rendition.edit_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        repaired_projection,
        (
            expected_rendition.canonical_content.clone(),
            replacement_commit.resulting_state.digest.to_string(),
            expected_state_manifest,
        )
    );
    assert!(
        !rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
    assert_eq!(
        create_changeset(
            &repository,
            draft_command(
                OTHER_CHANGESET_ID,
                "v1 authoring is closed after localization",
                None,
            ),
        )
        .unwrap_err(),
        CreateChangeSetError::UnsupportedVersion
    );
    assert_eq!(
        create_edition(
            &repository,
            edition_command(
                OTHER_EDITION_ID,
                OTHER_EDITION_IDEMPOTENCY_KEY,
                "2026-08-17T15:43:00Z",
            ),
        )
        .unwrap_err(),
        CreateEditionError::UnsupportedVersion
    );
    assert_eq!(
        query_released_objects(
            &repository,
            QueryReleasedObjectsCommand {
                operating_principal_id: None,
                delegation_id: None,
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                object_ids: vec![object_id],
                evaluated_at: "2026-08-17T15:44:00Z".parse().unwrap(),
            },
        )
        .unwrap_err(),
        QueryReleasedObjectsError::UnsupportedVersion
    );
    assert_eq!(
        promote_release(
            &repository,
            promotion_command(
                SECOND_RELEASE_ID,
                SECOND_PROOF_ID,
                EDITION_ID,
                SECOND_RELEASE_IDEMPOTENCY_KEY,
                "2026-08-17T15:45:00Z",
            ),
        )
        .unwrap_err(),
        ReleaseError::UnsupportedVersion
    );
}

struct LocalizedDraftFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    changeset_id: ChangeSetId,
    object_id: ObjectId,
    locale: LocaleId,
    expected_source: ExpectedLocalizedSource,
}

fn localized_draft_fixture() -> LocalizedDraftFixture {
    let directory = TestDirectory::new();
    let repository = initialized_repository(&directory);
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    create_changeset(
        &repository,
        draft_command(CHANGESET_ID, "Create a partially localizable source", None),
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                partially_localizable_schema_edit(EDIT_ID, "campaign"),
                object_edit(OBJECT_EDIT_ID, OBJECT_ID, "campaign", &source),
            ],
            idempotency_key: ADD_IDEMPOTENCY_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(&repository, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-17T16:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-17T16:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_IDEMPOTENCY_KEY.parse().unwrap(),
            committed_at: "2026-08-17T16:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &repository,
        edition_command(EDITION_ID, EDITION_IDEMPOTENCY_KEY, "2026-08-17T16:03:00Z"),
    )
    .unwrap();
    create_environment(
        &repository,
        environment_command(
            ENVIRONMENT_ID,
            ENVIRONMENT_IDEMPOTENCY_KEY,
            "editorial",
            "2026-08-17T16:04:00Z",
        ),
    )
    .unwrap();
    promote_release(
        &repository,
        promotion_command(
            FIRST_RELEASE_ID,
            FIRST_PROOF_ID,
            EDITION_ID,
            FIRST_RELEASE_IDEMPOTENCY_KEY,
            "2026-08-17T16:05:00Z",
        ),
    )
    .unwrap();

    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let locale = LocaleId::new("fr-FR").unwrap();
    let schema_id = SchemaId::new("campaign").unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let expected_source = ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap(),
        schema_id: schema_id.clone(),
        schema_version,
    };
    let intent = repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: "019c0000-0000-7000-8000-000000000200".parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id,
                schema_id,
                locale: locale.clone(),
            }],
            idempotency_key: "019c0000-0000-7000-8000-000000000201".parse().unwrap(),
            issued_at: "2026-08-17T16:06:00Z".parse().unwrap(),
        })
        .unwrap();
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: "019c0000-0000-7000-8000-000000000202".parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: locale.clone(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Garantie absolue".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 10,
                max_validation_attempts: 5,
                max_bytes: 1_048_576,
            },
            idempotency_key: "019c0000-0000-7000-8000-000000000203".parse().unwrap(),
            created_at: "2026-08-17T16:07:00Z".parse().unwrap(),
            expires_at: "2026-08-18T16:07:00Z".parse().unwrap(),
        })
        .unwrap();
    let changeset = repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: "019c0000-0000-7000-8000-000000000204".parse().unwrap(),
            intent: ChangeSetIntent::new("Translate one exact campaign rendition").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: "019c0000-0000-7000-8000-000000000205".parse().unwrap(),
            created_at: "2026-08-17T16:08:00Z".parse().unwrap(),
        })
        .unwrap();

    LocalizedDraftFixture {
        _directory: directory,
        repository,
        changeset_id: changeset.changeset_id,
        object_id,
        locale,
        expected_source,
    }
}

fn localized_edit_count(repository: &LocalWorkspace, changeset_id: ChangeSetId) -> i64 {
    repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM localized_edits WHERE changeset_id = ?1",
            [changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap()
}

fn test_digest(hex: char) -> ContentDigest {
    format!("blake3:{}", hex.to_string().repeat(64))
        .parse()
        .unwrap()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one transaction-level denial matrix proves stable Problems and zero partial Edit persistence"
)]
fn localized_edit_denials_are_specific_and_atomic() {
    let fixture = localized_draft_fixture();
    let repository = &fixture.repository;
    let translated = canonicalize(&serde_json::json!({
        "legal": "Garantie absolue",
        "slug": "summer-campaign",
        "title": "Campagne d’été",
    }))
    .unwrap();

    assert_eq!(
        repository
            .submit_localized_changeset(
                fixture.changeset_id,
                "2026-08-17T16:09:00Z".parse().unwrap(),
            )
            .unwrap_err(),
        LocalizedContentError::NotReady
    );
    assert_eq!(
        repository
            .approve_localized_changeset(
                fixture.changeset_id,
                ApprovalName::new("editorial").unwrap(),
                "2026-08-17T16:09:00Z".parse().unwrap(),
            )
            .unwrap_err(),
        LocalizedContentError::NotSubmitted
    );
    assert_eq!(
        repository
            .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                changeset_id: fixture.changeset_id,
                idempotency_key: "019c0000-0000-7000-8000-000000000206".parse().unwrap(),
                committed_at: "2026-08-17T16:09:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotApproved
    );

    let wrong_target = ObjectLocalePutInput {
        object_id: fixture.object_id,
        locale: LocaleId::new("de-DE").unwrap(),
        expected_source: fixture.expected_source.clone(),
        expected_target: None,
        canonical_content: translated.as_str().to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    };
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![wrong_target],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000210".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000220".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::IntentMismatch
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 0);

    let mut stale_source = fixture.expected_source.clone();
    stale_source.digest = test_digest('a');
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: stale_source,
                    expected_target: None,
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000211".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000221".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::SourceConflict
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 0);

    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: Some(ExpectedLocalizedTarget {
                        revision: LocaleRevision::new(1).unwrap(),
                        digest: test_digest('b'),
                    }),
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000212".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000222".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::TargetConflict
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 0);

    let non_localizable_change = canonicalize(&serde_json::json!({
        "legal": "Garantie absolue",
        "slug": "campagne-ete",
        "title": "Campagne d’été",
    }))
    .unwrap();
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: non_localizable_change.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000213".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000223".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidInput
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 0);

    let first_edit_id = "019c0000-0000-7000-8000-000000000214"
        .parse::<EditId>()
        .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: fixture.changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id: fixture.object_id,
                locale: fixture.locale.clone(),
                expected_source: fixture.expected_source.clone(),
                expected_target: None,
                canonical_content: translated.as_str().to_owned(),
                supersedes_edit_id: None,
                repair_of_validation_result_digest: None,
            }],
            assigned_edit_ids: vec![first_edit_id],
            idempotency_key: "019c0000-0000-7000-8000-000000000224".parse().unwrap(),
        })
        .unwrap();

    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000215".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000225".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::DuplicateActiveTarget
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 1);

    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: Some(OTHER_EDIT_ID.parse().unwrap()),
                    repair_of_validation_result_digest: Some(test_digest('c')),
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000216".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000226".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidSupersession
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 1);

    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: Some(first_edit_id),
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000217".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000227".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidRepairEvidence
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 1);

    let invalid = repository
        .validate_localized_changeset(fixture.changeset_id)
        .unwrap();
    assert!(!invalid.valid);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: translated.as_str().to_owned(),
                    supersedes_edit_id: Some(first_edit_id),
                    repair_of_validation_result_digest: Some(test_digest('d')),
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-000000000218".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-000000000228".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidRepairEvidence
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 1);

    let repaired = canonicalize(&serde_json::json!({
        "legal": "Des conditions standard s’appliquent",
        "slug": "summer-campaign",
        "title": "Campagne d’été",
    }))
    .unwrap();
    let repair_edit_id = "019c0000-0000-7000-8000-000000000219"
        .parse::<EditId>()
        .unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: fixture.changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id: fixture.object_id,
                locale: fixture.locale.clone(),
                expected_source: fixture.expected_source.clone(),
                expected_target: None,
                canonical_content: repaired.as_str().to_owned(),
                supersedes_edit_id: Some(first_edit_id),
                repair_of_validation_result_digest: Some(invalid.validation_results_digest),
            }],
            assigned_edit_ids: vec![repair_edit_id],
            idempotency_key: "019c0000-0000-7000-8000-000000000229".parse().unwrap(),
        })
        .unwrap();
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 2);

    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale.clone(),
                    expected_source: fixture.expected_source.clone(),
                    expected_target: None,
                    canonical_content: repaired.as_str().to_owned(),
                    supersedes_edit_id: Some(first_edit_id),
                    repair_of_validation_result_digest: Some(invalid.validation_results_digest),
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-00000000021a".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-00000000022a".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidSupersession
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 2);

    assert!(
        repository
            .validate_localized_changeset(fixture.changeset_id)
            .unwrap()
            .valid
    );
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: fixture.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id: fixture.object_id,
                    locale: fixture.locale,
                    expected_source: fixture.expected_source,
                    expected_target: None,
                    canonical_content: repaired.as_str().to_owned(),
                    supersedes_edit_id: Some(repair_edit_id),
                    repair_of_validation_result_digest: Some(invalid.validation_results_digest),
                }],
                assigned_edit_ids: vec!["019c0000-0000-7000-8000-00000000021b".parse().unwrap()],
                idempotency_key: "019c0000-0000-7000-8000-00000000022b".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotDraft
    );
    assert_eq!(localized_edit_count(repository, fixture.changeset_id), 2);

    repository
        .submit_localized_changeset(
            fixture.changeset_id,
            "2026-08-17T16:10:00Z".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(
        repository
            .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                changeset_id: fixture.changeset_id,
                idempotency_key: "019c0000-0000-7000-8000-00000000022c".parse().unwrap(),
                committed_at: "2026-08-17T16:11:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::NotApproved
    );
}

#[test]
fn localized_conformance_schemas_and_golden_artifacts_are_closed() {
    let artifact_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/schemas/artifacts.schema.json"
    ))
    .unwrap();
    let operation_schema: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/schemas/operations.schema.json"
    ))
    .unwrap();
    let meta = jsonschema::draft202012::meta::validator();
    assert!(
        meta.is_valid(&artifact_schema),
        "localized artifact Schema must satisfy the Draft 2020-12 meta-Schema"
    );
    assert!(
        meta.is_valid(&operation_schema),
        "localized operation Schema catalog must satisfy the Draft 2020-12 meta-Schema"
    );

    let validator = jsonschema::draft202012::new(&artifact_schema).unwrap();
    let corpus: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/artifact-digests.valid.json"
    ))
    .unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let artifact = &case["artifact"];
        let errors = validator
            .iter_errors(artifact)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(
            errors.is_empty(),
            "{} failed its artifact Schema: {errors:?}",
            case["artifact_kind"].as_str().unwrap()
        );
    }

    let mut wrong_locale = cases[0]["artifact"].clone();
    wrong_locale["targets"][0]["locale"] = serde_json::json!("fr-fr");
    assert!(!validator.is_valid(&wrong_locale));
    let mut widened = cases[3]["artifact"].clone();
    widened["relationships"] = serde_json::json!([]);
    assert!(!validator.is_valid(&widened));

    let registry: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/operation-registry.valid.json"
    ))
    .unwrap();
    let contracts = registry["contracts"].as_array().unwrap();
    let expected = [
        ("proof.dev/operation/context.build/v2", "context:build"),
        (
            "proof.dev/operation/changeset.create/v2",
            "changeset:create",
        ),
        ("proof.dev/operation/changeset.add/v2", "changeset:add"),
        ("proof.dev/operation/changeset.get/v2", "changeset:get"),
        ("proof.dev/operation/changeset.diff/v2", "changeset:diff"),
        (
            "proof.dev/operation/changeset.validate/v2",
            "changeset:validate",
        ),
        (
            "proof.dev/operation/changeset.submit/v2",
            "changeset:submit",
        ),
        (
            "proof.dev/operation/changeset.commit/v2",
            "changeset:commit",
        ),
        ("proof.dev/operation/edition.create/v2", "edition:create"),
        ("proof.dev/operation/release.create/v2", "release:create"),
        (
            "proof.dev/operation/object.query_released/v2",
            "object:query_released",
        ),
    ];
    assert_eq!(contracts.len(), expected.len());
    for (contract, (operation_id, action)) in contracts.iter().zip(expected) {
        assert_eq!(contract["operation_id"], operation_id);
        assert_eq!(contract["action"], action);
        for selector in ["input_schema", "output_schema"] {
            let pointer = contract[selector]
                .as_str()
                .unwrap()
                .strip_prefix('#')
                .unwrap();
            assert!(
                operation_schema.pointer(pointer).is_some(),
                "{operation_id} {selector} does not resolve"
            );
        }
        let input_pointer = contract["input_schema"]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        assert_eq!(
            operation_schema.pointer(input_pointer).unwrap()["properties"]["api_version"]["const"],
            operation_id
        );
    }
}

fn localizable_schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["legal", "title"],
        "type": "object",
        "x-proof-localizable": ["/legal", "/title"],
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

fn partially_localizable_schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": { "type": "string" },
            "slug": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["legal", "slug", "title"],
        "type": "object",
        "x-proof-localizable": ["/legal", "/title"],
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
