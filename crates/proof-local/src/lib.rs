#![forbid(unsafe_code)]

//! Local filesystem and `SQLite` adapters for Proof.

mod localized;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
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
    LOCAL_VALIDATION_PROFILE, ObjectCreateEdit, ObjectId, ObjectLifecycleState, ObjectRevision,
    PrincipalId, PrincipalType, SchemaCreateEdit, SchemaId, SchemaVersion, Severity,
    SubmitChangeSetCommand, SubmitChangeSetError, SubmittedChangeSet, ValidateChangeSetError,
    ValidatedChangeSet, WorkspaceId, WorkspaceInitializationError, WorkspaceRepository,
    WorkspaceStatus, WorkspaceStatusError, WorkspaceStatusRepository,
};
use proof_application::{
    AgentPrincipal, ApprovalName, BuildContextPackCommand, ContextPack, ContextPackError,
    ContextPackId, ContextPackLimits, ContextPackRepository, ContextPackVerification,
    CreateAgentPrincipalCommand, CreateEnvironmentCommand, DelegatedAction,
    DelegatedWorkspaceStatus, DelegatedWorkspaceStatusCommand, DelegatedWorkspaceStatusError,
    DelegatedWorkspaceStatusRepository, Delegation, DelegationConstraints, DelegationError,
    DelegationId, DelegationRepository, DelegationScope, DelegationVerification, Environment,
    EnvironmentError, EnvironmentId, EnvironmentRepository, GetContextPackCommand,
    GrantDelegationCommand, KNOWN_STATE_V1_API_VERSION, KNOWN_STATE_V2_API_VERSION,
    LOCAL_AUTHORITY_POLICY_PROFILE, LOCALIZED_RELEASE_API_VERSION, MAX_CONTEXT_PACK_BYTES,
    MAX_DELEGATION_ENVIRONMENTS, MAX_DELEGATION_OBJECTS, PrincipalError, PrincipalRepository,
    ProjectionRebuild, ProjectionRepository, PromoteReleaseCommand, ProofId,
    QueryReleasedObjectsCommand, QueryReleasedObjectsError, RebuildProjectionsCommand,
    RebuildProjectionsError, Release, ReleaseError, ReleaseId, ReleaseKind, ReleaseRepository,
    ReleaseVerification, ReleasedObject, ReleasedObjectQuery, ReleasedObjectRepository,
    RevokeDelegationCommand, RollbackReleaseCommand, Timestamp, VerifyContextPackCommand,
    VerifyDelegationCommand, VerifyReleaseCommand,
};
use proof_attestation::{
    DSSE_PAYLOAD_TYPE, Ed25519SigningProvider, InTotoStatement, InTotoSubject,
    ProofSigningProvider, sign_release_statement, verify_release_envelope,
};
use proof_canonical::{
    ObjectStateReference, canonicalize, digest, initial_known_state_digest,
    known_state_digest_with_objects, object_revision_digest, object_set_digest, parse_strict,
};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

const CONFIG_API_VERSION: &str = "proof.dev/workspace/v1";
const CONFIG_FILE: &str = "proof.toml";
const RUNTIME_DIRECTORY: &str = ".proof";
const DATABASE_RELATIVE_PATH: &str = ".proof/state/proof.db";
const ARTIFACTS_RELATIVE_PATH: &str = ".proof/artifacts";
const RELEASE_SIGNING_KEY_RELATIVE_PATH: &str = ".proof/state/release-signing.ed25519";
const LATEST_DATABASE_SCHEMA_VERSION: u32 = 11;
const OBJECT_VALIDATOR: &str = "proof/object-create/draft-2020-12/1+jsonschema/0.49.3";
const LOCAL_RELEASE_TARGET: &str = "proof.local/released-state/v1";
const LOCAL_RELEASE_POLICY: &str = "proof.local/release-policy/v1";

macro_rules! require_v1_profile {
    ($connection:expr, $unsupported:path, $storage:path, $integrity:path) => {
        match require_v1_authoring_profile($connection) {
            Ok(()) => {}
            Err(LocalPortError::UnsupportedVersion) => return Err($unsupported),
            Err(LocalPortError::Storage(detail)) => return Err($storage(detail)),
            Err(LocalPortError::Integrity(detail)) => return Err($integrity(detail)),
            Err(error) => {
                return Err($integrity(format!(
                    "unexpected v1 profile guard outcome: {error:?}"
                )))
            }
        }
    };
}

fn operation_effect_digest(
    operation_kind: &str,
    request_digest: ContentDigest,
    result: &serde_json::Value,
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": operation_kind,
        "request_digest": request_digest.to_string(),
        "result": result,
    }))
    .map_err(|error| error.to_string())?;
    Ok(digest(ArtifactKind::OperationEffectV1, &effect))
}

fn operation_request_digest(
    operation_kind: &str,
    request: &serde_json::Value,
) -> Result<ContentDigest, String> {
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-request/v1",
        "operation_kind": operation_kind,
        "request": request,
    }))
    .map_err(|error| error.to_string())?;
    Ok(digest(ArtifactKind::OperationEffectV1, &request))
}

fn changeset_creation_effect_digest(
    requested_base_state: Option<ContentDigest>,
    draft: &DraftChangeSet,
) -> Result<ContentDigest, String> {
    let request_digest = operation_request_digest(
        "changeset.create",
        &serde_json::json!({
            "idempotency_key": draft.idempotency_key.to_string(),
            "intent": draft.intent.as_str(),
            "principal_id": draft.principal_id.to_string(),
            "requested_base_state": requested_base_state.map(|value| value.to_string()),
            "workspace_id": draft.workspace_id.to_string(),
        }),
    )?;
    operation_effect_digest(
        "changeset.create",
        request_digest,
        &serde_json::json!({
            "base_authoritative_sequence": draft.base_authoritative_sequence,
            "base_state": draft.base_state.to_string(),
            "changeset_id": draft.changeset_id.to_string(),
            "created_at": draft.created_at.to_string(),
            "edit_count": 0,
            "idempotency_key": draft.idempotency_key.to_string(),
            "intent": draft.intent.as_str(),
            "policy_profile": draft.policy_profile,
            "principal_id": draft.principal_id.to_string(),
            "requested_base_state": requested_base_state.map(|value| value.to_string()),
            "status": ChangeSetStatus::Draft.to_string(),
            "validation_profile": draft.validation_profile,
            "workspace_id": draft.workspace_id.to_string(),
        }),
    )
}

fn changeset_submission_effect_digest(
    submitted: &SubmittedChangeSet,
) -> Result<ContentDigest, String> {
    let request_digest = operation_request_digest(
        "changeset.submit",
        &serde_json::json!({
            "changeset_digest": submitted.changeset_digest.to_string(),
            "changeset_id": submitted.changeset_id.to_string(),
            "principal_id": submitted.principal_id.to_string(),
            "validation_results_digest": submitted.validation_results_digest.to_string(),
            "workspace_id": submitted.workspace_id.to_string(),
        }),
    )?;
    operation_effect_digest(
        "changeset.submit",
        request_digest,
        &serde_json::json!({
            "base_state": submitted.base_state.to_string(),
            "changeset_digest": submitted.changeset_digest.to_string(),
            "changeset_id": submitted.changeset_id.to_string(),
            "edit_count": submitted.edit_count,
            "principal_id": submitted.principal_id.to_string(),
            "status": submitted.status.to_string(),
            "submitted_at": submitted.submitted_at.to_string(),
            "validation_results_digest": submitted.validation_results_digest.to_string(),
            "workspace_id": submitted.workspace_id.to_string(),
        }),
    )
}

fn changeset_approval_effect_digest(approved: &ApprovedChangeSet) -> Result<ContentDigest, String> {
    let request_digest = operation_request_digest(
        "changeset.approve",
        &serde_json::json!({
            "approval": approved.approval.as_str(),
            "changeset_digest": approved.changeset_digest.to_string(),
            "changeset_id": approved.changeset_id.to_string(),
            "principal_id": approved.principal_id.to_string(),
            "validation_results_digest": approved.validation_results_digest.to_string(),
            "workspace_id": approved.workspace_id.to_string(),
        }),
    )?;
    operation_effect_digest(
        "changeset.approve",
        request_digest,
        &serde_json::json!({
            "approval": approved.approval.as_str(),
            "approved_at": approved.approved_at.to_string(),
            "changeset_digest": approved.changeset_digest.to_string(),
            "changeset_id": approved.changeset_id.to_string(),
            "principal_id": approved.principal_id.to_string(),
            "status": approved.status.to_string(),
            "validation_results_digest": approved.validation_results_digest.to_string(),
            "workspace_id": approved.workspace_id.to_string(),
        }),
    )
}

fn changeset_commit_effect_digest(
    idempotency_key: IdempotencyKey,
    committed: &CommittedChangeSet,
) -> Result<ContentDigest, String> {
    let request_digest = operation_request_digest(
        "changeset.commit",
        &serde_json::json!({
            "changeset_digest": committed.changeset_digest.to_string(),
            "changeset_id": committed.changeset_id.to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "principal_id": committed.principal_id.to_string(),
            "validation_results_digest": committed.validation_results_digest.to_string(),
            "workspace_id": committed.workspace_id.to_string(),
        }),
    )?;
    operation_effect_digest(
        "changeset.commit",
        request_digest,
        &serde_json::json!({
            "authoritative_sequence": committed.authoritative_sequence,
            "changeset_digest": committed.changeset_digest.to_string(),
            "changeset_id": committed.changeset_id.to_string(),
            "committed_at": committed.committed_at.to_string(),
            "edit_count": committed.edit_count,
            "idempotency_key": idempotency_key.to_string(),
            "previous_state": committed.previous_state.to_string(),
            "principal_id": committed.principal_id.to_string(),
            "resulting_state": committed.resulting_state.to_string(),
            "status": committed.status.to_string(),
            "validation_results_digest": committed.validation_results_digest.to_string(),
            "workspace_id": committed.workspace_id.to_string(),
        }),
    )
}

fn edition_create_operation_effect_digest(
    idempotency_key: IdempotencyKey,
    requested_state_digest: ContentDigest,
    edition: &Edition,
) -> Result<ContentDigest, String> {
    let request_digest = operation_request_digest(
        "edition.create",
        &serde_json::json!({
            "idempotency_key": idempotency_key.to_string(),
            "principal_id": edition.principal_id.to_string(),
            "requested_state_digest": requested_state_digest.to_string(),
            "workspace_id": edition.workspace_id.to_string(),
        }),
    )?;
    operation_effect_digest(
        "edition.create",
        request_digest,
        &serde_json::json!({
            "authoritative_sequence": edition.authoritative_sequence,
            "created_at": edition.created_at.to_string(),
            "edition_digest": edition.edition_digest.to_string(),
            "edition_id": edition.edition_id.to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "manifest_json": edition.manifest_json,
            "object_set_digest": edition.object_set_digest.map(|value| value.to_string()),
            "principal_id": edition.principal_id.to_string(),
            "requested_state_digest": requested_state_digest.to_string(),
            "schema_set_digest": edition.schema_set_digest.to_string(),
            "state_digest": edition.state_digest.to_string(),
            "workspace_id": edition.workspace_id.to_string(),
        }),
    )
}
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
    effect_digest TEXT NOT NULL,
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
    effect_digest TEXT NOT NULL,
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
    submitted_at TEXT NOT NULL,
    effect_digest TEXT NOT NULL
) STRICT;
INSERT INTO schema_migrations (version, name) VALUES (5, 'seal-and-submit-changesets');
CREATE TABLE changeset_approvals (
    changeset_id TEXT PRIMARY KEY REFERENCES changesets(changeset_id),
    approval_name TEXT NOT NULL,
    changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    approved_at TEXT NOT NULL,
    effect_digest TEXT NOT NULL
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
    effect_digest TEXT NOT NULL,
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
    effect_digest TEXT NOT NULL,
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
const V10_DATABASE_MIGRATION: &str = "CREATE TABLE environments (
    environment_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    created_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    created_at TEXT NOT NULL,
    UNIQUE (workspace_id, environment_id)
) STRICT;
CREATE TABLE environment_versions (
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    config_version INTEGER NOT NULL CHECK (config_version > 0),
    target_kind TEXT NOT NULL,
    policy_profile TEXT NOT NULL,
    required_approval TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    config_digest TEXT NOT NULL UNIQUE,
    created_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (environment_id, config_version)
) STRICT;
CREATE TABLE environment_create_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;
CREATE TABLE signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    public_key TEXT NOT NULL,
    trust_profile TEXT NOT NULL,
    not_before TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    metadata_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE signing_key_revocations (
    key_id TEXT PRIMARY KEY REFERENCES signing_keys(key_id),
    revoked_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    revocation_json TEXT NOT NULL,
    revocation_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE release_policy_decisions (
    decision_digest TEXT PRIMARY KEY,
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    environment_config_version INTEGER NOT NULL,
    environment_config_digest TEXT NOT NULL,
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    edition_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    decision_json TEXT NOT NULL,
    FOREIGN KEY (environment_id, environment_config_version)
        REFERENCES environment_versions(environment_id, config_version)
) STRICT;
CREATE TABLE releases (
    release_id TEXT PRIMARY KEY,
    release_sequence INTEGER NOT NULL UNIQUE CHECK (release_sequence > 0),
    workspace_id TEXT NOT NULL,
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    environment_config_version INTEGER NOT NULL,
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    edition_digest TEXT NOT NULL,
    release_kind TEXT NOT NULL CHECK (release_kind IN ('promotion', 'rollback')),
    rollback_target_release_id TEXT REFERENCES releases(release_id),
    previous_release_id TEXT REFERENCES releases(release_id),
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    delegation_id TEXT REFERENCES delegations(delegation_id),
    policy_decision_digest TEXT NOT NULL REFERENCES release_policy_decisions(decision_digest),
    manifest_json TEXT NOT NULL,
    release_digest TEXT NOT NULL UNIQUE,
    released_at TEXT NOT NULL,
    FOREIGN KEY (environment_id, environment_config_version)
        REFERENCES environment_versions(environment_id, config_version)
) STRICT;
CREATE TABLE environment_current_releases (
    environment_id TEXT PRIMARY KEY REFERENCES environments(environment_id),
    release_id TEXT NOT NULL UNIQUE REFERENCES releases(release_id),
    release_sequence INTEGER NOT NULL UNIQUE CHECK (release_sequence > 0),
    projection_version INTEGER NOT NULL CHECK (projection_version = 1)
) STRICT;
CREATE TABLE release_proofs (
    proof_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL UNIQUE REFERENCES releases(release_id),
    key_id TEXT NOT NULL REFERENCES signing_keys(key_id),
    payload_type TEXT NOT NULL,
    statement_json TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    proof_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
) STRICT;
CREATE TABLE release_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN ('release.promote', 'release.rollback')
    ),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    proof_id TEXT NOT NULL REFERENCES release_proofs(proof_id),
    PRIMARY KEY (workspace_id, principal_id, operation_kind, idempotency_key)
) STRICT;
CREATE TABLE release_proof_export_outbox (
    proof_id TEXT PRIMARY KEY REFERENCES release_proofs(proof_id),
    release_id TEXT NOT NULL UNIQUE REFERENCES releases(release_id),
    created_at TEXT NOT NULL
) STRICT;
CREATE TABLE principal_registrations (
    principal_id TEXT PRIMARY KEY REFERENCES principals(principal_id),
    workspace_id TEXT NOT NULL,
    registered_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    display_name TEXT NOT NULL,
    registration_json TEXT NOT NULL,
    registration_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
) STRICT;
CREATE TABLE principal_create_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    created_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;
CREATE TABLE delegations (
    delegation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    issuer_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    recipient_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    actions_json TEXT NOT NULL,
    environment_ids_json TEXT NOT NULL,
    object_ids_json TEXT NOT NULL,
    max_objects INTEGER NOT NULL CHECK (max_objects BETWEEN 1 AND 100),
    max_context_bytes INTEGER NOT NULL CHECK (max_context_bytes > 0),
    allow_subdelegation INTEGER NOT NULL CHECK (allow_subdelegation = 0),
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    delegation_digest TEXT NOT NULL UNIQUE,
    issued_at TEXT NOT NULL
) STRICT;
CREATE TABLE delegation_grant_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    delegation_id TEXT NOT NULL REFERENCES delegations(delegation_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;
CREATE TABLE delegation_revocations (
    delegation_id TEXT PRIMARY KEY REFERENCES delegations(delegation_id),
    revoked_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    revoked_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    revocation_json TEXT NOT NULL,
    revocation_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE delegation_revoke_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    delegation_id TEXT NOT NULL REFERENCES delegations(delegation_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;
CREATE TABLE context_packs (
    context_pack_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operating_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    delegation_id TEXT NOT NULL REFERENCES delegations(delegation_id),
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    object_ids_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    context_pack_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
CREATE TABLE context_pack_build_operations (
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operating_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    context_pack_id TEXT NOT NULL REFERENCES context_packs(context_pack_id),
    PRIMARY KEY (
        workspace_id, requesting_principal_id, operating_principal_id, idempotency_key
    )
) STRICT;
INSERT INTO schema_migrations (version, name)
VALUES (10, 'local-release-authority-foundation');
UPDATE workspace_metadata SET schema_version = 10 WHERE singleton = 1;
PRAGMA user_version = 10;";

struct LocalIdentity {
    provider: &'static str,
    subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LatestSchemaError {
    Integrity(String),
    Storage(String),
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
    #[expect(
        clippy::too_many_lines,
        reason = "draft creation keeps migration, replay, and atomic effect commitment together"
    )]
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
        require_v1_profile!(
            &transaction,
            CreateChangeSetError::UnsupportedVersion,
            CreateChangeSetError::Storage,
            CreateChangeSetError::Integrity
        );
        let schema_version: u32 = transaction
            .query_row(
                "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
        let (base_authoritative_sequence, base_state) =
            verified_known_state(&transaction, workspace_id)?;
        let requested_base_state = command.requested_base_state.map(|value| value.to_string());
        verify_changeset_creation_effects_for_scope(&transaction, schema_version)?;

        if let Some(persisted) = find_idempotent_draft(
            &transaction,
            workspace_id,
            principal_id,
            command.idempotency_key,
            schema_version,
        )? {
            let persisted_requested_base_state = persisted.requested_base_state.clone();
            let draft = persisted.into_draft(schema_version)?;
            if draft.intent.as_str() != command.intent.as_str()
                || persisted_requested_base_state != requested_base_state
            {
                return Err(CreateChangeSetError::IdempotencyKeyReused);
            }
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
            schema_version,
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
            schema_version = transaction
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        }
        require_v1_profile!(
            &transaction,
            AddChangeSetEditsError::UnsupportedVersion,
            AddChangeSetEditsError::Storage,
            AddChangeSetEditsError::Integrity
        );
        verify_edit_operation_scope(&transaction, schema_version).map_err(|error| match error {
            LocalPortError::Storage(detail) => AddChangeSetEditsError::Storage(detail),
            LocalPortError::Integrity(detail) => AddChangeSetEditsError::Integrity(detail),
            other => AddChangeSetEditsError::Integrity(format!(
                "Edit operation scope verification failed: {other:?}"
            )),
        })?;
        if let Some(result) = replay_edit_batch(
            &transaction,
            workspace_id,
            principal_id,
            command.changeset_id,
            command.idempotency_key,
            request_digest,
            schema_version,
        )? {
            transaction
                .commit()
                .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
            return Ok(result);
        }

        require_editable_changeset(
            &transaction,
            workspace_id,
            principal_id,
            command.changeset_id,
            schema_version,
        )?;

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
            schema_version,
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
    #[expect(
        clippy::too_many_lines,
        reason = "validation keeps deterministic replay evidence and lifecycle transition checks in one transaction"
    )]
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
        require_v1_profile!(
            &transaction,
            ValidateChangeSetError::UnsupportedVersion,
            ValidateChangeSetError::Storage,
            ValidateChangeSetError::Integrity
        );

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
            ChangeSetStatus::Draft
                | ChangeSetStatus::Ready
                | ChangeSetStatus::Submitted
                | ChangeSetStatus::Approved
                | ChangeSetStatus::Committed
                | ChangeSetStatus::Rejected
        ) {
            return Err(ValidateChangeSetError::NotValidatable);
        }
        let mut validated = validate_inspected_changeset(&transaction, &inspected)?;
        let target_status = if validated.valid {
            ChangeSetStatus::Ready
        } else {
            ChangeSetStatus::Rejected
        };
        let advanced_replay = matches!(
            inspected.status,
            ChangeSetStatus::Submitted | ChangeSetStatus::Approved | ChangeSetStatus::Committed
        );
        if inspected.status != ChangeSetStatus::Draft
            && inspected.status != target_status
            && !(advanced_replay && target_status == ChangeSetStatus::Ready)
        {
            return Err(ValidateChangeSetError::NotValidatable);
        }
        validated.status = target_status;
        persist_validation(
            &transaction,
            &validated,
            inspected.status == ChangeSetStatus::Draft,
        )?;
        if advanced_replay {
            replay_submission(
                &transaction,
                &inspected,
                validated.changeset_digest,
                validated.validation_results_digest,
                validated.edit_count,
            )
            .map_err(validation_from_submission)?;
        } else if inspected.status == ChangeSetStatus::Draft {
            transaction
                .execute(
                    "UPDATE changesets SET lifecycle_status = ?1 WHERE changeset_id = ?2",
                    [target_status.to_string(), changeset_id.to_string()],
                )
                .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        }
        transaction
            .commit()
            .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?;
        Ok(validated)
    }
}

impl ChangeSetSubmissionRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "submission verifies and binds exact validation evidence in one transaction"
    )]
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
        require_v1_profile!(
            &transaction,
            SubmitChangeSetError::UnsupportedVersion,
            SubmitChangeSetError::Storage,
            SubmitChangeSetError::Integrity
        );

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
            ChangeSetStatus::Ready
                | ChangeSetStatus::Submitted
                | ChangeSetStatus::Approved
                | ChangeSetStatus::Committed
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
        require_v1_profile!(
            &transaction,
            ApproveChangeSetError::UnsupportedVersion,
            ApproveChangeSetError::Storage,
            ApproveChangeSetError::Integrity
        );
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
            ChangeSetStatus::Submitted | ChangeSetStatus::Approved | ChangeSetStatus::Committed
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
        require_v1_profile!(
            &transaction,
            CommitChangeSetError::UnsupportedVersion,
            CommitChangeSetError::Storage,
            CommitChangeSetError::Integrity
        );
        verify_commit_operation_scope(&transaction, workspace_id).map_err(|error| match error {
            LocalPortError::Storage(detail) => CommitChangeSetError::Storage(detail),
            LocalPortError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
            other => CommitChangeSetError::Integrity(format!(
                "commit operation scope verification failed: {other:?}"
            )),
        })?;
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
        require_v1_profile!(
            &transaction,
            CreateEditionError::UnsupportedVersion,
            CreateEditionError::Storage,
            CreateEditionError::Integrity
        );
        verify_commit_operation_scope(&transaction, workspace_id).map_err(|error| match error {
            LocalPortError::Storage(detail) => CreateEditionError::Storage(detail),
            LocalPortError::Integrity(detail) => CreateEditionError::Integrity(detail),
            other => CreateEditionError::Integrity(format!(
                "commit-chain verification failed: {other:?}"
            )),
        })?;
        verify_edition_operation_scope(&transaction, workspace_id).map_err(
            |error| match error {
                LocalPortError::Storage(detail) => CreateEditionError::Storage(detail),
                LocalPortError::Integrity(detail) => CreateEditionError::Integrity(detail),
                other => CreateEditionError::Integrity(format!(
                    "Edition operation scope verification failed: {other:?}"
                )),
            },
        )?;
        let edition = create_current_edition(&transaction, workspace_id, principal_id, &command)?;
        transaction
            .commit()
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        Ok(edition)
    }
}

impl EnvironmentRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "Environment creation authenticates, migrates, canonicalizes policy, and records idempotency atomically"
    )]
    fn create_environment(
        &self,
        command: CreateEnvironmentCommand,
    ) -> Result<Environment, EnvironmentError> {
        if command.target_kind != LOCAL_RELEASE_TARGET
            || command.policy_profile != LOCAL_RELEASE_POLICY
        {
            return Err(EnvironmentError::InvalidConfiguration);
        }
        let config = self
            .read_config()
            .map_err(environment_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| EnvironmentError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(environment_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(EnvironmentError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(environment_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(environment_from_latest)?;
        verify_environment_operation_scope(&transaction, workspace_id).map_err(
            |error| match error {
                LocalPortError::Storage(detail) => EnvironmentError::Storage(detail),
                LocalPortError::Integrity(detail) => EnvironmentError::Integrity(detail),
                other => EnvironmentError::Integrity(format!(
                    "Environment operation scope verification failed: {other:?}"
                )),
            },
        )?;

        let policy = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/release-policy/v1",
            "profile": command.policy_profile,
            "require_approved_changesets": true,
            "require_signed_proof": true,
            "required_approval": command.required_approval.as_str(),
        }))
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
        let policy_digest = digest(ArtifactKind::PolicyBundleV1, &policy);
        let manifest = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/environment/v1",
            "config_version": 1,
            "environment_id": command.environment_id.as_str(),
            "policy_digest": policy_digest.to_string(),
            "policy_profile": command.policy_profile,
            "required_approval": command.required_approval.as_str(),
            "target_kind": command.target_kind,
            "workspace_id": workspace_id.to_string(),
        }))
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
        let request_digest = digest(ArtifactKind::EnvironmentConfigV1, &manifest);
        if let Some((persisted_request, environment_id)) = transaction
            .query_row(
                "SELECT request_digest, environment_id
                 FROM environment_create_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    command.idempotency_key.to_string(),
                ),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?
        {
            let persisted_request = persisted_request
                .parse::<ContentDigest>()
                .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
            let environment_id = environment_id
                .parse::<EnvironmentId>()
                .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
            let environment =
                load_environment_version(&transaction, workspace_id, environment_id, 1)?;
            if environment.config_digest != persisted_request {
                return Err(EnvironmentError::Integrity(
                    "Environment create operation does not bind its immutable configuration"
                        .to_owned(),
                ));
            }
            if persisted_request != request_digest {
                return Err(EnvironmentError::IdempotencyKeyReused);
            }
            return Ok(environment);
        }
        let operation_environment = if let Some(existing_digest) = transaction
            .query_row(
                "SELECT config_digest FROM environment_versions
                 WHERE environment_id = ?1 AND config_version = 1",
                [command.environment_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?
        {
            if existing_digest != request_digest.to_string() {
                return Err(EnvironmentError::AlreadyExists);
            }
            load_environment_version(
                &transaction,
                workspace_id,
                command.environment_id.clone(),
                1,
            )?
        } else {
            transaction
                .execute(
                    "INSERT INTO environments (
                         environment_id, workspace_id, created_by_principal_id, created_at
                     ) VALUES (?1, ?2, ?3, ?4)",
                    (
                        command.environment_id.as_str(),
                        workspace_id.to_string(),
                        principal_id.to_string(),
                        command.created_at.to_string(),
                    ),
                )
                .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
            transaction
                .execute(
                    "INSERT INTO environment_versions (
                         environment_id, config_version, target_kind, policy_profile,
                         required_approval, policy_json, policy_digest, manifest_json,
                         config_digest, created_by_principal_id, created_at
                     ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    (
                        command.environment_id.as_str(),
                        command.target_kind.as_str(),
                        command.policy_profile.as_str(),
                        command.required_approval.as_str(),
                        policy.as_str(),
                        policy_digest.to_string(),
                        manifest.as_str(),
                        request_digest.to_string(),
                        principal_id.to_string(),
                        command.created_at.to_string(),
                    ),
                )
                .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
            Environment {
                environment_id: command.environment_id.clone(),
                workspace_id,
                config_version: 1,
                target_kind: command.target_kind.clone(),
                policy_profile: command.policy_profile.clone(),
                required_approval: command.required_approval.clone(),
                config_manifest_json: manifest.as_str().to_owned(),
                config_digest: request_digest,
                current_release_id: None,
                principal_id,
                created_at: command.created_at,
            }
        };
        let effect_digest = environment_create_operation_effect_digest(
            request_digest,
            command.idempotency_key,
            &operation_environment,
            policy_digest,
        )
        .map_err(EnvironmentError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO environment_create_operations (
                     workspace_id, principal_id, idempotency_key, request_digest,
                     effect_digest, environment_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    command.idempotency_key.to_string(),
                    request_digest.to_string(),
                    effect_digest.to_string(),
                    command.environment_id.as_str(),
                ),
            )
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        let environment =
            load_environment_version(&transaction, workspace_id, command.environment_id, 1)?;
        transaction
            .commit()
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        Ok(environment)
    }

    fn get_environment(
        &self,
        environment_id: EnvironmentId,
    ) -> Result<Environment, EnvironmentError> {
        let config = self
            .read_config()
            .map_err(environment_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| EnvironmentError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(environment_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(EnvironmentError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
            .map_err(environment_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(environment_from_latest)?;
        let environment = load_environment(&transaction, workspace_id, environment_id)?;
        transaction
            .commit()
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        Ok(environment)
    }
}

impl PrincipalRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "agent registration authenticates, canonicalizes evidence, and records idempotency atomically"
    )]
    fn create_agent_principal(
        &self,
        command: CreateAgentPrincipalCommand,
    ) -> Result<AgentPrincipal, PrincipalError> {
        let display_name = command.display_name.trim().to_owned();
        if display_name.is_empty() || display_name.len() > 256 {
            return Err(PrincipalError::InvalidDisplayName);
        }
        let config = self.read_config().map_err(principal_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| PrincipalError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(principal_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(PrincipalError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let issuer =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(principal_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(principal_from_latest)?;
        verify_principal_operation_scope(&transaction, workspace_id).map_err(
            |error| match error {
                LocalPortError::Storage(detail) => PrincipalError::Storage(detail),
                LocalPortError::Integrity(detail) => PrincipalError::Integrity(detail),
                other => PrincipalError::Integrity(format!(
                    "Principal operation scope verification failed: {other:?}"
                )),
            },
        )?;
        let request_digest =
            principal_registration_request_digest(workspace_id, issuer, display_name.as_str())?;
        let registration = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/principal-registration/v1",
            "created_at": command.created_at.to_string(),
            "created_by_principal_id": issuer.to_string(),
            "display_name": display_name,
            "principal_id": command.principal_id.to_string(),
            "principal_type": "agent",
            "workspace_id": workspace_id.to_string(),
        }))
        .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
        let registration_digest = digest(ArtifactKind::PrincipalRegistrationV1, &registration);
        if let Some((persisted_request, principal_id)) = transaction
            .query_row(
                "SELECT request_digest, created_principal_id
                 FROM principal_create_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    workspace_id.to_string(),
                    issuer.to_string(),
                    command.idempotency_key.to_string(),
                ),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| PrincipalError::Storage(error.to_string()))?
        {
            let persisted_request = persisted_request
                .parse::<ContentDigest>()
                .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
            let principal = load_agent_principal(
                &transaction,
                workspace_id,
                principal_id
                    .parse::<PrincipalId>()
                    .map_err(|error| PrincipalError::Integrity(error.to_string()))?,
            )?;
            let effect_digest = principal_registration_request_digest(
                principal.workspace_id,
                principal.created_by_principal_id,
                &principal.display_name,
            )?;
            if effect_digest != persisted_request {
                return Err(PrincipalError::Integrity(
                    "Principal create operation does not bind its registration effect".to_owned(),
                ));
            }
            if persisted_request != request_digest {
                return Err(PrincipalError::IdempotencyKeyReused);
            }
            return Ok(principal);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM principals WHERE principal_id = ?1",
                [command.principal_id.to_string()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| PrincipalError::Storage(error.to_string()))?
            .is_some()
        {
            return Err(PrincipalError::Integrity(
                "the candidate Principal identity already exists".to_owned(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO principals (
                     principal_id, principal_type, identity_provider, identity_subject, enabled
                 ) VALUES (?1, 'agent', 'proof/local-agent', ?2, 1)",
                (
                    command.principal_id.to_string(),
                    format!("principal:{}", command.principal_id),
                ),
            )
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO principal_registrations (
                     principal_id, workspace_id, registered_by_principal_id, display_name,
                     registration_json, registration_digest, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    command.principal_id.to_string(),
                    workspace_id.to_string(),
                    issuer.to_string(),
                    display_name.as_str(),
                    registration.as_str(),
                    registration_digest.to_string(),
                    command.created_at.to_string(),
                ),
            )
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        let operation_principal = AgentPrincipal {
            principal_id: command.principal_id,
            workspace_id,
            display_name: display_name.clone(),
            created_by_principal_id: issuer,
            created_at: command.created_at,
            enabled: true,
        };
        let effect_digest = principal_create_operation_effect_digest(
            request_digest,
            command.idempotency_key,
            &operation_principal,
            registration_digest,
        )
        .map_err(PrincipalError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO principal_create_operations (
                     workspace_id, principal_id, idempotency_key, request_digest, effect_digest,
                     created_principal_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    workspace_id.to_string(),
                    issuer.to_string(),
                    command.idempotency_key.to_string(),
                    request_digest.to_string(),
                    effect_digest.to_string(),
                    command.principal_id.to_string(),
                ),
            )
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        let principal = load_agent_principal(&transaction, workspace_id, command.principal_id)?;
        transaction
            .commit()
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        Ok(principal)
    }

    fn get_agent_principal(
        &self,
        principal_id: PrincipalId,
    ) -> Result<AgentPrincipal, PrincipalError> {
        let config = self.read_config().map_err(principal_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| PrincipalError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(principal_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        let (bootstrap_principal_id, schema_version): (String, u32) = transaction
            .query_row(
                "SELECT bootstrap_principal_id, schema_version
                 FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
            .map_err(principal_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(principal_from_latest)?;
        let principal = load_agent_principal(&transaction, workspace_id, principal_id)?;
        transaction
            .commit()
            .map_err(|error| PrincipalError::Storage(error.to_string()))?;
        Ok(principal)
    }
}

impl DelegationRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "Delegation grant enforces the complete authority boundary and persists canonical evidence atomically"
    )]
    fn grant_delegation(
        &self,
        command: GrantDelegationCommand,
    ) -> Result<Delegation, DelegationError> {
        let config = self.read_config().map_err(delegation_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let duplicate_actions =
            command.actions.iter().collect::<BTreeSet<_>>().len() != command.actions.len();
        let duplicate_environments = command
            .scope
            .environment_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != command.scope.environment_ids.len();
        let duplicate_objects = command
            .scope
            .object_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != command.scope.object_ids.len();
        if command.scope.workspace_id != workspace_id
            || command.actions.is_empty()
            || duplicate_actions
            || duplicate_environments
            || duplicate_objects
            || command.scope.environment_ids.len() > MAX_DELEGATION_ENVIRONMENTS
            || command.scope.object_ids.len() > MAX_DELEGATION_OBJECTS
            || command.constraints.max_objects == 0
            || usize::try_from(command.constraints.max_objects)
                .map_or(true, |value| value > MAX_DELEGATION_OBJECTS)
            || command.constraints.max_context_bytes == 0
            || command.constraints.max_context_bytes > MAX_CONTEXT_PACK_BYTES
            || command.constraints.allow_subdelegation
            || command.not_before >= command.expires_at
        {
            return Err(DelegationError::InvalidGrant);
        }
        let local_identity =
            current_local_identity().map_err(|_| DelegationError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(delegation_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(DelegationError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let issuer =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(delegation_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(delegation_from_latest)?;
        verify_delegation_operation_scope(&transaction, workspace_id).map_err(
            |error| match error {
                LocalPortError::Storage(detail) => DelegationError::Storage(detail),
                LocalPortError::Integrity(detail) => DelegationError::Integrity(detail),
                other => DelegationError::Integrity(format!(
                    "Delegation operation scope verification failed: {other:?}"
                )),
            },
        )?;
        load_agent_principal(&transaction, workspace_id, command.recipient_principal_id).map_err(
            |error| match error {
                PrincipalError::NotFound | PrincipalError::Disabled => {
                    DelegationError::InvalidRecipient
                }
                PrincipalError::Integrity(detail) => DelegationError::Integrity(detail),
                PrincipalError::Storage(detail) => DelegationError::Storage(detail),
                _ => DelegationError::InvalidRecipient,
            },
        )?;

        let mut actions = command.actions.clone();
        actions.sort_unstable();
        let mut environment_ids = command.scope.environment_ids.clone();
        environment_ids.sort();
        let mut object_ids = command.scope.object_ids.clone();
        object_ids.sort_unstable();
        let has_resource_action = actions.iter().any(|action| {
            matches!(
                action,
                DelegatedAction::ObjectQueryReleased | DelegatedAction::ContextBuild
            )
        });
        if (has_resource_action && (environment_ids.is_empty() || object_ids.is_empty()))
            || (!has_resource_action && (!environment_ids.is_empty() || !object_ids.is_empty()))
        {
            return Err(DelegationError::InvalidGrant);
        }
        if !object_ids.is_empty() {
            reproducible_known_state(&transaction, workspace_id)
                .map_err(DelegationError::Integrity)?;
        }
        for environment_id in &environment_ids {
            load_environment(&transaction, workspace_id, environment_id.clone()).map_err(
                |error| match error {
                    EnvironmentError::NotFound => DelegationError::InvalidGrant,
                    EnvironmentError::Storage(detail) => DelegationError::Storage(detail),
                    EnvironmentError::Integrity(detail) => DelegationError::Integrity(detail),
                    other => DelegationError::Integrity(format!(
                        "delegated Environment failed verification: {other:?}"
                    )),
                },
            )?;
        }
        for object_id in &object_ids {
            let exists = transaction
                .query_row(
                    "SELECT 1 FROM object_revisions WHERE object_id = ?1",
                    [object_id.to_string()],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
            if exists.is_none() {
                return Err(DelegationError::InvalidGrant);
            }
        }
        let action_values = actions.iter().map(ToString::to_string).collect::<Vec<_>>();
        let environment_values = environment_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let object_values = object_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let request_digest = delegation_grant_request_digest(
            workspace_id,
            issuer,
            command.recipient_principal_id,
            &actions,
            &environment_ids,
            &object_ids,
            &command.constraints,
            command.not_before,
            command.expires_at,
        )?;
        let manifest_value = serde_json::json!({
            "actions": action_values,
            "api_version": "proof.dev/delegation/v1",
            "constraints": {
                "allow_subdelegation": false,
                "max_context_bytes": command.constraints.max_context_bytes,
                "max_objects": command.constraints.max_objects,
            },
            "delegation_id": command.delegation_id.to_string(),
            "expires_at": command.expires_at.to_string(),
            "issued_at": command.issued_at.to_string(),
            "issuer_principal_id": issuer.to_string(),
            "not_before": command.not_before.to_string(),
            "recipient_principal_id": command.recipient_principal_id.to_string(),
            "scope": {
                "environment_ids": environment_values,
                "object_ids": object_values,
                "workspace_id": workspace_id.to_string(),
            },
        });
        let manifest = canonicalize(&manifest_value)
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let delegation_digest = digest(ArtifactKind::DelegationV1, &manifest);
        if let Some((persisted_request, delegation_id)) = transaction
            .query_row(
                "SELECT request_digest, delegation_id
                 FROM delegation_grant_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    workspace_id.to_string(),
                    issuer.to_string(),
                    command.idempotency_key.to_string(),
                ),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|error| DelegationError::Storage(error.to_string()))?
        {
            let persisted_request = persisted_request
                .parse::<ContentDigest>()
                .map_err(|error| DelegationError::Integrity(error.to_string()))?;
            let delegation = load_original_delegation_grant(
                &transaction,
                workspace_id,
                delegation_id
                    .parse()
                    .map_err(|error: proof_application::IdentifierError| {
                        DelegationError::Integrity(error.to_string())
                    })?,
            )?;
            let effect_digest = delegation_grant_request_digest(
                delegation.workspace_id,
                delegation.issuer_principal_id,
                delegation.recipient_principal_id,
                &delegation.actions,
                &delegation.scope.environment_ids,
                &delegation.scope.object_ids,
                &delegation.constraints,
                delegation.not_before,
                delegation.expires_at,
            )?;
            if effect_digest != persisted_request {
                return Err(DelegationError::Integrity(
                    "Delegation grant operation does not bind its canonical grant effect"
                        .to_owned(),
                ));
            }
            if persisted_request != request_digest {
                return Err(DelegationError::IdempotencyKeyReused);
            }
            return Ok(delegation);
        }
        if command.issued_at > command.not_before || command.issued_at >= command.expires_at {
            return Err(DelegationError::InvalidGrant);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM delegations WHERE delegation_id = ?1",
                [command.delegation_id.to_string()],
                |_| Ok(()),
            )
            .optional()
            .map_err(|error| DelegationError::Storage(error.to_string()))?
            .is_some()
        {
            return Err(DelegationError::Integrity(
                "the candidate Delegation identity already exists".to_owned(),
            ));
        }
        let actions_json = canonicalize(&serde_json::json!(action_values))
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let environments_json = canonicalize(&serde_json::json!(environment_values))
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let objects_json = canonicalize(&serde_json::json!(object_values))
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO delegations (
                     delegation_id, workspace_id, issuer_principal_id, recipient_principal_id,
                     actions_json, environment_ids_json, object_ids_json, max_objects,
                     max_context_bytes, allow_subdelegation, not_before, expires_at,
                     manifest_json, delegation_digest, issued_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    command.delegation_id.to_string(),
                    workspace_id.to_string(),
                    issuer.to_string(),
                    command.recipient_principal_id.to_string(),
                    actions_json.as_str(),
                    environments_json.as_str(),
                    objects_json.as_str(),
                    command.constraints.max_objects,
                    i64::try_from(command.constraints.max_context_bytes)
                        .map_err(|_| { DelegationError::InvalidGrant })?,
                    command.not_before.to_string(),
                    command.expires_at.to_string(),
                    manifest.as_str(),
                    delegation_digest.to_string(),
                    command.issued_at.to_string(),
                ],
            )
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        let operation_delegation = Delegation {
            delegation_id: command.delegation_id,
            workspace_id,
            issuer_principal_id: issuer,
            recipient_principal_id: command.recipient_principal_id,
            actions: actions.clone(),
            scope: DelegationScope {
                workspace_id,
                environment_ids: environment_ids.clone(),
                object_ids: object_ids.clone(),
            },
            constraints: command.constraints,
            not_before: command.not_before,
            expires_at: command.expires_at,
            issued_at: command.issued_at,
            delegation_digest,
            revoked_by_principal_id: None,
            revoked_at: None,
        };
        let effect_digest = delegation_grant_operation_effect_digest(
            request_digest,
            command.idempotency_key,
            &operation_delegation,
        )
        .map_err(DelegationError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO delegation_grant_operations (
                     workspace_id, principal_id, idempotency_key, request_digest,
                     effect_digest, delegation_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    workspace_id.to_string(),
                    issuer.to_string(),
                    command.idempotency_key.to_string(),
                    request_digest.to_string(),
                    effect_digest.to_string(),
                    command.delegation_id.to_string(),
                ),
            )
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        let delegation = load_delegation(&transaction, workspace_id, command.delegation_id)?;
        transaction
            .commit()
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        Ok(delegation)
    }

    fn get_delegation(
        &self,
        delegation_id: proof_application::DelegationId,
    ) -> Result<Delegation, DelegationError> {
        self.with_delegation_transaction(|transaction, workspace_id, _| {
            load_delegation(transaction, workspace_id, delegation_id)
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "revocation keeps normalized replay and persisted-effect authorization in one transaction"
    )]
    fn revoke_delegation(
        &self,
        command: RevokeDelegationCommand,
    ) -> Result<Delegation, DelegationError> {
        self.with_delegation_transaction(|transaction, workspace_id, principal_id| {
            verify_delegation_operation_scope(transaction, workspace_id).map_err(|error| {
                match error {
                    LocalPortError::Storage(detail) => DelegationError::Storage(detail),
                    LocalPortError::Integrity(detail) => DelegationError::Integrity(detail),
                    other => DelegationError::Integrity(format!(
                        "Delegation operation scope verification failed: {other:?}"
                    )),
                }
            })?;
            let delegation = load_delegation(transaction, workspace_id, command.delegation_id)?;
            let request_digest =
                delegation_revoke_request_digest(workspace_id, command.delegation_id)?;
            if let Some((persisted_request, persisted_id)) = transaction
                .query_row(
                    "SELECT request_digest, delegation_id
                     FROM delegation_revoke_operations
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                    (
                        workspace_id.to_string(),
                        principal_id.to_string(),
                        command.idempotency_key.to_string(),
                    ),
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| DelegationError::Storage(error.to_string()))?
            {
                if persisted_request != request_digest.to_string()
                    || persisted_id != command.delegation_id.to_string()
                {
                    return Err(DelegationError::IdempotencyKeyReused);
                }
                return load_delegation(transaction, workspace_id, command.delegation_id);
            }
            let revocation = canonicalize(&serde_json::json!({
                "api_version": "proof.dev/delegation-revocation/v1",
                "delegation_id": command.delegation_id.to_string(),
                "reason": "revoked",
                "revoked_at": command.revoked_at.to_string(),
                "revoked_by_principal_id": principal_id.to_string(),
                "workspace_id": workspace_id.to_string(),
            }))
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
            let revocation_digest = digest(ArtifactKind::DelegationV1, &revocation);
            let existing: Option<(String, String)> = transaction
                .query_row(
                    "SELECT revocation_json, revocation_digest FROM delegation_revocations
                     WHERE delegation_id = ?1",
                    [command.delegation_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
            let (operation_delegation, operation_revocation_digest) =
                if let Some((_, digest)) = existing {
                    let persisted_digest = digest
                        .parse::<ContentDigest>()
                        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                    (delegation.clone(), persisted_digest)
                } else {
                    if command.revoked_at < delegation.issued_at {
                        return Err(DelegationError::InvalidGrant);
                    }
                    transaction
                        .execute(
                            "INSERT INTO delegation_revocations (
                             delegation_id, revoked_by_principal_id, revoked_at, reason,
                             revocation_json, revocation_digest
                         ) VALUES (?1, ?2, ?3, 'revoked', ?4, ?5)",
                            (
                                command.delegation_id.to_string(),
                                principal_id.to_string(),
                                command.revoked_at.to_string(),
                                revocation.as_str(),
                                revocation_digest.to_string(),
                            ),
                        )
                        .map_err(|error| DelegationError::Storage(error.to_string()))?;
                    let mut revoked_delegation = delegation.clone();
                    revoked_delegation.revoked_by_principal_id = Some(principal_id);
                    revoked_delegation.revoked_at = Some(command.revoked_at);
                    (revoked_delegation, revocation_digest)
                };
            let effect_digest = delegation_revoke_operation_effect_digest(
                request_digest,
                command.idempotency_key,
                principal_id,
                &operation_delegation,
                operation_revocation_digest,
            )
            .map_err(DelegationError::Integrity)?;
            transaction
                .execute(
                    "INSERT INTO delegation_revoke_operations (
                         workspace_id, principal_id, idempotency_key, request_digest,
                         effect_digest, delegation_id
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    (
                        workspace_id.to_string(),
                        principal_id.to_string(),
                        command.idempotency_key.to_string(),
                        request_digest.to_string(),
                        effect_digest.to_string(),
                        command.delegation_id.to_string(),
                    ),
                )
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
            load_delegation(transaction, workspace_id, command.delegation_id)
        })
    }

    fn verify_delegation(
        &self,
        command: VerifyDelegationCommand,
    ) -> Result<DelegationVerification, DelegationError> {
        self.with_delegation_transaction(|transaction, workspace_id, _| {
            verify_delegation_record(transaction, workspace_id, &command)
        })
    }
}

impl DelegatedWorkspaceStatusRepository for LocalWorkspace {
    fn delegated_workspace_status(
        &self,
        command: DelegatedWorkspaceStatusCommand,
    ) -> Result<DelegatedWorkspaceStatus, DelegatedWorkspaceStatusError> {
        self.with_delegation_transaction(|transaction, workspace_id, _| {
            let authorization = verify_delegation_record(
                transaction,
                workspace_id,
                &VerifyDelegationCommand {
                    delegation_id: command.delegation_id,
                    operating_principal_id: command.operating_principal_id,
                    action: DelegatedAction::WorkspaceStatus,
                    environment_id: None,
                    object_ids: Vec::new(),
                    evaluated_at: command.evaluated_at,
                },
            )?;
            let schema_version: u32 = transaction
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
            let (authoritative_sequence, state_digest) =
                reproducible_known_state(transaction, workspace_id)
                    .map_err(DelegationError::Integrity)?;
            Ok(DelegatedWorkspaceStatus {
                workspace_id,
                principal_id: command.operating_principal_id,
                delegation_id: command.delegation_id,
                storage_schema_version: schema_version,
                authoritative_sequence,
                state_digest,
                authorization_decision_digest: authorization.decision_digest,
            })
        })
        .map_err(|error| match error {
            DelegationError::Unauthenticated => DelegatedWorkspaceStatusError::Unauthenticated,
            DelegationError::Storage(detail) => DelegatedWorkspaceStatusError::Storage(detail),
            DelegationError::Integrity(detail) => DelegatedWorkspaceStatusError::Integrity(detail),
            _ => DelegatedWorkspaceStatusError::Denied,
        })
    }
}

impl ReleasedObjectRepository for LocalWorkspace {
    fn query_released_objects(
        &self,
        mut command: QueryReleasedObjectsCommand,
    ) -> Result<ReleasedObjectQuery, QueryReleasedObjectsError> {
        let unique_count = command.object_ids.iter().collect::<BTreeSet<_>>().len();
        if command.operating_principal_id.is_some() != command.delegation_id.is_some()
            || command.object_ids.is_empty()
            || command.object_ids.len() > MAX_DELEGATION_OBJECTS
            || unique_count != command.object_ids.len()
        {
            return Err(QueryReleasedObjectsError::InvalidQuery);
        }
        command.object_ids.sort();
        self.with_latest_transaction(|transaction, workspace_id, requesting_principal_id| {
            require_v1_authoring_profile(transaction)?;
            query_released_objects_transaction(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
        })
        .map_err(query_from_local_port)
    }
}

impl ContextPackRepository for LocalWorkspace {
    fn build_context_pack(
        &self,
        mut command: BuildContextPackCommand,
    ) -> Result<ContextPack, ContextPackError> {
        let unique_count = command.object_ids.iter().collect::<BTreeSet<_>>().len();
        let requested_max_objects =
            usize::try_from(command.limits.max_objects).unwrap_or(usize::MAX);
        if command.object_ids.is_empty()
            || unique_count != command.object_ids.len()
            || command.object_ids.len() > requested_max_objects
            || requested_max_objects > MAX_DELEGATION_OBJECTS
            || command.limits.max_bytes == 0
            || command.limits.max_bytes > MAX_CONTEXT_PACK_BYTES
            || command.task_id.trim().is_empty()
            || command.task_id.len() > proof_application::MAX_CONTEXT_TASK_ID_BYTES
        {
            return Err(ContextPackError::LimitExceeded);
        }
        command.object_ids.sort();
        self.with_latest_transaction(|transaction, workspace_id, requesting_principal_id| {
            build_context_pack_transaction(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
        })
        .map_err(context_from_local_port)
    }

    fn get_context_pack(
        &self,
        command: GetContextPackCommand,
    ) -> Result<ContextPack, ContextPackError> {
        self.with_latest_transaction(|transaction, workspace_id, requesting_principal_id| {
            authorize_context_pack_access(
                transaction,
                workspace_id,
                requesting_principal_id,
                command.context_pack_id,
                command.operating_principal_id,
                command.delegation_id,
                command.observed_at,
            )?;
            load_context_pack_record(transaction, workspace_id, command.context_pack_id)
        })
        .map_err(context_from_local_port)
    }

    fn verify_context_pack(
        &self,
        command: VerifyContextPackCommand,
    ) -> Result<ContextPackVerification, ContextPackError> {
        self.with_latest_transaction(|transaction, workspace_id, requesting_principal_id| {
            authorize_context_pack_access(
                transaction,
                workspace_id,
                requesting_principal_id,
                command.context_pack_id,
                command.operating_principal_id,
                command.delegation_id,
                command.verified_at,
            )?;
            let pack =
                load_context_pack_record(transaction, workspace_id, command.context_pack_id)?;
            Ok(ContextPackVerification {
                context_pack_id: pack.context_pack_id,
                context_pack_digest: pack.context_pack_digest,
                digest_valid: true,
                sources_valid: true,
                fresh: command.verified_at < pack.expires_at,
                valid: command.verified_at < pack.expires_at,
                findings: Vec::new(),
                verified_at: command.verified_at,
            })
        })
        .map_err(context_from_local_port)
    }
}

impl ReleaseRepository for LocalWorkspace {
    fn promote_release(&self, command: PromoteReleaseCommand) -> Result<Release, ReleaseError> {
        let release = self
            .with_latest_transaction(|transaction, workspace_id, principal_id| {
                require_v1_authoring_profile(transaction)?;
                create_release_transaction(
                    transaction,
                    workspace_id,
                    principal_id,
                    ReleaseRequest::Promotion(&command),
                    || self.preflight_release_proof_export(command.proof_id),
                    || self.load_or_create_release_signer(command.release_id),
                )
            })
            .map_err(release_from_local_port)?;
        let _ = self.materialize_release_proof(&release);
        Ok(release)
    }

    fn rollback_release(&self, command: RollbackReleaseCommand) -> Result<Release, ReleaseError> {
        let release = self
            .with_latest_transaction(|transaction, workspace_id, principal_id| {
                require_v1_authoring_profile(transaction)?;
                create_release_transaction(
                    transaction,
                    workspace_id,
                    principal_id,
                    ReleaseRequest::Rollback(&command),
                    || self.preflight_release_proof_export(command.proof_id),
                    || self.load_or_create_release_signer(command.release_id),
                )
            })
            .map_err(release_from_local_port)?;
        let _ = self.materialize_release_proof(&release);
        Ok(release)
    }

    fn get_release(&self, release_id: ReleaseId) -> Result<Release, ReleaseError> {
        let release = self
            .with_latest_transaction(|transaction, workspace_id, _| {
                load_release_record(transaction, workspace_id, release_id)
            })
            .map_err(release_from_local_port)?;
        self.materialize_release_proof(&release)
            .map_err(release_from_local_port)?;
        Ok(release)
    }

    fn verify_release(
        &self,
        command: VerifyReleaseCommand,
    ) -> Result<ReleaseVerification, ReleaseError> {
        self.with_latest_transaction(|transaction, workspace_id, _| {
            let release = load_release_record(transaction, workspace_id, command.release_id)?;
            Ok(ReleaseVerification {
                release_id: release.release_id,
                proof_id: release.proof_id,
                key_id: release.key_id,
                signature_valid: true,
                subjects_valid: true,
                evidence_complete: true,
                trusted: true,
                valid: true,
                findings: Vec::new(),
                verified_at: command.verified_at,
            })
        })
        .map_err(release_from_local_port)
    }
}

impl ProjectionRepository for LocalWorkspace {
    fn rebuild_projections(
        &self,
        command: RebuildProjectionsCommand,
    ) -> Result<ProjectionRebuild, RebuildProjectionsError> {
        self.with_latest_transaction(|transaction, workspace_id, _| {
            rebuild_projections_transaction(transaction, workspace_id, command.dry_run)
        })
        .map_err(rebuild_from_local_port)
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

        if migration_version >= 7 {
            verify_commit_operation_scope(&connection, configured_id).map_err(
                |error| match error {
                    LocalPortError::Storage(detail) => WorkspaceStatusError::Storage(detail),
                    LocalPortError::Integrity(detail) => WorkspaceStatusError::Integrity(detail),
                    other => WorkspaceStatusError::Integrity(format!(
                        "commit-chain verification failed: {other:?}"
                    )),
                },
            )?;
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
        .execute_batch(V10_DATABASE_MIGRATION)
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
             ) VALUES (1, ?1, ?2, 10)",
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
    localized::migrate_schema_v11(&transaction).map_err(WorkspaceInitializationError::Storage)?;
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
#[expect(
    clippy::unnecessary_wraps,
    reason = "platform-neutral caller requires a fallible permission-hardening interface"
)]
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
#[expect(
    clippy::unnecessary_wraps,
    reason = "platform-neutral caller requires a fallible permission-hardening interface"
)]
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
        CreateChangeSetError::UnsupportedVersion => AddChangeSetEditsError::UnsupportedVersion,
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
        CreateChangeSetError::UnsupportedVersion => ValidateChangeSetError::UnsupportedVersion,
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
        AddChangeSetEditsError::UnsupportedVersion => ValidateChangeSetError::UnsupportedVersion,
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

fn validation_from_submission(error: SubmitChangeSetError) -> ValidateChangeSetError {
    match error {
        SubmitChangeSetError::Unauthenticated => ValidateChangeSetError::Unauthenticated,
        SubmitChangeSetError::UnsupportedVersion => ValidateChangeSetError::UnsupportedVersion,
        SubmitChangeSetError::NotFound => ValidateChangeSetError::NotFound,
        SubmitChangeSetError::NotReady => ValidateChangeSetError::NotValidatable,
        SubmitChangeSetError::ValidationEvidenceMissing => ValidateChangeSetError::Integrity(
            "persisted submission evidence is missing for an advanced ChangeSet".to_owned(),
        ),
        SubmitChangeSetError::Integrity(detail) => ValidateChangeSetError::Integrity(detail),
        SubmitChangeSetError::Storage(detail) => ValidateChangeSetError::Storage(detail),
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
        ValidateChangeSetError::UnsupportedVersion => SubmitChangeSetError::UnsupportedVersion,
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
        ValidateChangeSetError::UnsupportedVersion => ApproveChangeSetError::UnsupportedVersion,
        ValidateChangeSetError::NotFound => ApproveChangeSetError::NotFound,
        ValidateChangeSetError::NotValidatable => ApproveChangeSetError::NotSubmitted,
        ValidateChangeSetError::Integrity(detail) => ApproveChangeSetError::Integrity(detail),
        ValidateChangeSetError::Storage(detail) => ApproveChangeSetError::Storage(detail),
    }
}

fn approval_from_submission(error: SubmitChangeSetError) -> ApproveChangeSetError {
    match error {
        SubmitChangeSetError::Unauthenticated => ApproveChangeSetError::Unauthenticated,
        SubmitChangeSetError::UnsupportedVersion => ApproveChangeSetError::UnsupportedVersion,
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
        ValidateChangeSetError::UnsupportedVersion => CommitChangeSetError::UnsupportedVersion,
        ValidateChangeSetError::NotFound => CommitChangeSetError::NotFound,
        ValidateChangeSetError::NotValidatable => CommitChangeSetError::NotApproved,
        ValidateChangeSetError::Integrity(detail) => CommitChangeSetError::Integrity(detail),
        ValidateChangeSetError::Storage(detail) => CommitChangeSetError::Storage(detail),
    }
}

fn commit_from_submission(error: SubmitChangeSetError) -> CommitChangeSetError {
    match error {
        SubmitChangeSetError::Unauthenticated => CommitChangeSetError::Unauthenticated,
        SubmitChangeSetError::UnsupportedVersion => CommitChangeSetError::UnsupportedVersion,
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
    if !(1..=LATEST_DATABASE_SCHEMA_VERSION).contains(&migration_version) {
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
    immutable_status: String,
    status: String,
    policy_profile: String,
    validation_profile: String,
    effect_digest: Option<String>,
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
        if self.immutable_status != ChangeSetStatus::Draft.to_string() {
            return Err(InspectChangeSetError::Integrity(
                "persisted ChangeSet creation status is invalid".to_owned(),
            ));
        }
        let intent = ChangeSetIntent::new(self.intent.clone())
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        if intent.as_str() != self.intent {
            return Err(InspectChangeSetError::Integrity(
                "persisted ChangeSet intent is not canonical".to_owned(),
            ));
        }
        let inspected = InspectedChangeSet {
            changeset_id,
            workspace_id,
            principal_id,
            intent,
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
        };
        if let Some(persisted_effect) = self.effect_digest {
            let draft = DraftChangeSet {
                changeset_id: inspected.changeset_id,
                workspace_id: inspected.workspace_id,
                principal_id: inspected.principal_id,
                intent: inspected.intent.clone(),
                base_authoritative_sequence: inspected.base_authoritative_sequence,
                base_state: inspected.base_state,
                idempotency_key: inspected.idempotency_key,
                created_at: inspected.created_at,
                status: ChangeSetStatus::Draft,
                policy_profile: inspected.policy_profile.clone(),
                validation_profile: inspected.validation_profile.clone(),
                edit_count: 0,
            };
            let expected = changeset_creation_effect_digest(inspected.requested_base_state, &draft)
                .map_err(InspectChangeSetError::Integrity)?;
            if persisted_effect != expected.to_string() {
                return Err(InspectChangeSetError::Integrity(
                    "ChangeSet creation effect does not reproduce".to_owned(),
                ));
            }
        }
        Ok(inspected)
    }
}

fn inspect_parse<T>(value: &str, field: &str) -> Result<T, InspectChangeSetError>
where
    T: std::str::FromStr + ToString,
    T::Err: std::fmt::Display,
{
    let parsed = value.parse::<T>().map_err(|error| {
        InspectChangeSetError::Integrity(format!("invalid persisted {field}: {error}"))
    })?;
    if parsed.to_string() != value {
        return Err(InspectChangeSetError::Integrity(format!(
            "persisted {field} is not canonical"
        )));
    }
    Ok(parsed)
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
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    connection
        .query_row(
            &format!(
                "SELECT intent, requested_base_state, base_authoritative_sequence,
                        base_state, idempotency_key, created_at, status, {status_column},
                        policy_profile, validation_profile, {effect_column}
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
                    immutable_status: row.get(6)?,
                    status: row.get(7)?,
                    policy_profile: row.get(8)?,
                    validation_profile: row.get(9)?,
                    effect_digest: row.get(10)?,
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
    verify_inspected_edit_operation_bindings(
        connection,
        changeset_id,
        schema_version,
        edits.len(),
    )?;
    Ok(edits)
}

#[expect(
    clippy::too_many_lines,
    reason = "the verifier binds every persisted Edit batch and its contiguous operation coverage"
)]
fn verify_inspected_edit_operation_bindings(
    connection: &Connection,
    changeset_id: ChangeSetId,
    storage_schema_version: u32,
    edit_count: usize,
) -> Result<(), InspectChangeSetError> {
    type EditOperationRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        i64,
        i64,
        String,
        String,
        i64,
    );
    if storage_schema_version < 3 {
        return if edit_count == 0 {
            Ok(())
        } else {
            Err(InspectChangeSetError::Integrity(
                "ChangeSet Edits exist before Edit operation provenance was introduced".to_owned(),
            ))
        };
    }
    let effect_column = if storage_schema_version >= 10 {
        "o.effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT o.workspace_id, o.principal_id, o.idempotency_key,
                    o.request_digest, {effect_column},
                    o.first_ordinal, o.added_count, o.total_edit_count,
                    c.workspace_id, c.principal_id,
                    (SELECT COUNT(*) FROM changeset_add_operations duplicate
                     WHERE duplicate.workspace_id = o.workspace_id
                       AND duplicate.principal_id = o.principal_id
                       AND duplicate.idempotency_key = o.idempotency_key)
             FROM changeset_add_operations o
             JOIN changesets c ON c.changeset_id = o.changeset_id
             WHERE o.changeset_id = ?1
             ORDER BY o.first_ordinal, o.workspace_id, o.principal_id, o.idempotency_key"
        ))
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([changeset_id.to_string()], |row| {
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
                row.get(9)?,
                row.get(10)?,
            ))
        })
        .map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
    let mut covered_edit_count = 0_u32;
    for row in rows {
        let (
            operation_workspace,
            operation_principal,
            raw_idempotency_key,
            request_digest,
            persisted_effect_digest,
            first_ordinal,
            added_count,
            total_edit_count,
            changeset_workspace,
            changeset_principal,
            global_key_binding_count,
        ): EditOperationRow =
            row.map_err(|error| InspectChangeSetError::Storage(error.to_string()))?;
        let operation_workspace_id = operation_workspace
            .parse::<WorkspaceId>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let operation_principal_id = operation_principal
            .parse::<PrincipalId>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let changeset_workspace_id = changeset_workspace
            .parse::<WorkspaceId>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let changeset_principal_id = changeset_principal
            .parse::<PrincipalId>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        let operation_idempotency_key = raw_idempotency_key
            .parse::<IdempotencyKey>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        if operation_workspace_id.to_string() != operation_workspace
            || operation_principal_id.to_string() != operation_principal
            || changeset_workspace_id.to_string() != changeset_workspace
            || changeset_principal_id.to_string() != changeset_principal
            || operation_idempotency_key.to_string() != raw_idempotency_key
        {
            return Err(InspectChangeSetError::Integrity(
                "ChangeSet Edit operation identity is not canonical".to_owned(),
            ));
        }
        if operation_workspace_id != changeset_workspace_id
            || operation_principal_id != changeset_principal_id
        {
            return Err(InspectChangeSetError::Integrity(
                "ChangeSet Edit operation scope does not match its ChangeSet".to_owned(),
            ));
        }
        if global_key_binding_count != 1 {
            return Err(InspectChangeSetError::Integrity(
                "the Edit idempotency key is bound to multiple ChangeSets".to_owned(),
            ));
        }
        let positive = |value: i64, field: &str| {
            u32::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| {
                    InspectChangeSetError::Integrity(format!("{field} must be positive"))
                })
        };
        let first_ordinal = positive(first_ordinal, "first Edit ordinal")?;
        let added_count = positive(added_count, "added Edit count")?;
        let total_edit_count = positive(total_edit_count, "total Edit count")?;
        let expected_first_ordinal = covered_edit_count.checked_add(1).ok_or_else(|| {
            InspectChangeSetError::Integrity("ChangeSet Edit ordinal overflow".to_owned())
        })?;
        let final_ordinal = first_ordinal.checked_add(added_count - 1).ok_or_else(|| {
            InspectChangeSetError::Integrity("ChangeSet Edit ordinal overflow".to_owned())
        })?;
        if first_ordinal != expected_first_ordinal || total_edit_count != final_ordinal {
            return Err(InspectChangeSetError::Integrity(
                "ChangeSet Edit operations do not reproduce the persisted Edit sequence".to_owned(),
            ));
        }
        let batch = load_persisted_edit_batch(
            connection,
            changeset_id,
            first_ordinal,
            final_ordinal,
            storage_schema_version,
        )
        .map_err(inspect_from_persisted_edit)?;
        if batch.len() != usize::try_from(added_count).unwrap_or(usize::MAX) {
            return Err(InspectChangeSetError::Integrity(
                "persisted Edit batch is incomplete".to_owned(),
            ));
        }
        let reproduced_request_digest =
            verified_edit_batch(&batch).map_err(inspect_from_persisted_edit)?;
        let operation_digest = request_digest
            .parse::<ContentDigest>()
            .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
        if operation_digest.to_string() != request_digest
            || reproduced_request_digest != operation_digest
        {
            return Err(InspectChangeSetError::Integrity(
                "persisted Edit batch does not match its operation digest".to_owned(),
            ));
        }
        if storage_schema_version >= 10 {
            let persisted_effect_digest = persisted_effect_digest
                .ok_or_else(|| {
                    InspectChangeSetError::Integrity(
                        "persisted Edit operation effect commitment is missing".to_owned(),
                    )
                })?
                .parse::<ContentDigest>()
                .map_err(|error| InspectChangeSetError::Integrity(error.to_string()))?;
            let expected_effect_digest = edit_batch_operation_effect_digest(
                operation_digest,
                operation_idempotency_key,
                operation_workspace_id,
                operation_principal_id,
                changeset_id,
                first_ordinal,
                added_count,
                total_edit_count,
                &batch,
            )
            .map_err(InspectChangeSetError::Integrity)?;
            if persisted_effect_digest != expected_effect_digest {
                return Err(InspectChangeSetError::Integrity(
                    "persisted Edit batch does not match its operation effect digest".to_owned(),
                ));
            }
        }
        covered_edit_count = final_ordinal;
    }
    let actual_edit_count = u32::try_from(edit_count).map_err(|_| {
        InspectChangeSetError::Integrity("ChangeSet Edit count exceeds u32".to_owned())
    })?;
    if covered_edit_count != actual_edit_count {
        return Err(InspectChangeSetError::Integrity(
            "ChangeSet Edit operations do not cover the persisted Edits".to_owned(),
        ));
    }
    Ok(())
}

fn inspect_from_persisted_edit(error: AddChangeSetEditsError) -> InspectChangeSetError {
    match error {
        AddChangeSetEditsError::Integrity(detail) => InspectChangeSetError::Integrity(detail),
        AddChangeSetEditsError::Storage(detail) => InspectChangeSetError::Storage(detail),
        other => {
            InspectChangeSetError::Integrity(format!("persisted Edit batch is invalid: {other}"))
        }
    }
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

fn ensure_latest_schema(
    transaction: &Transaction<'_>,
    metadata_schema_version: u32,
) -> Result<(), LatestSchemaError> {
    let migration_version: u32 = transaction
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    let pragma_schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if metadata_schema_version != migration_version || migration_version != pragma_schema_version {
        return Err(LatestSchemaError::Integrity(
            "persistent schema version records differ".to_owned(),
        ));
    }
    let mut version = migration_version;
    if version == 1 {
        ensure_changeset_schema(transaction, version)
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        version = 2;
    }
    if version == 2 {
        ensure_edit_schema(transaction, version)
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        version = 3;
    }
    if (3..9).contains(&version) {
        ensure_object_schema(transaction, version)
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        version = 9;
    }
    if version == 9 {
        backfill_changeset_add_effect_digests(transaction)?;
        backfill_lifecycle_effect_digests(transaction)?;
        transaction
            .execute_batch(V10_DATABASE_MIGRATION)
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        version = 10;
    }
    if version == 10 {
        localized::migrate_schema_v11(transaction).map_err(LatestSchemaError::Storage)?;
        version = 11;
    }
    if version == LATEST_DATABASE_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(LatestSchemaError::Integrity(format!(
            "unsupported local schema version {version}"
        )))
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the v10 migration must reconstruct and commit every legacy Edit operation effect atomically"
)]
fn backfill_changeset_add_effect_digests(
    transaction: &Transaction<'_>,
) -> Result<(), LatestSchemaError> {
    type LegacyEditOperation = (String, String, String, String, String, i64, i64, i64);
    let has_effect_digest: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info('changeset_add_operations')
                 WHERE name = 'effect_digest'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if !has_effect_digest {
        transaction
            .execute_batch(
                "ALTER TABLE changeset_add_operations
                 ADD COLUMN effect_digest TEXT NOT NULL DEFAULT '';",
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    }
    let duplicate_key_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM changeset_add_operations
                 GROUP BY workspace_id, principal_id, idempotency_key
                 HAVING COUNT(*) > 1
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if duplicate_key_exists {
        return Err(LatestSchemaError::Integrity(
            "the Edit idempotency key is bound to multiple ChangeSets".to_owned(),
        ));
    }
    let operations = {
        let mut statement = transaction
            .prepare(
                "SELECT workspace_id, principal_id, changeset_id, idempotency_key,
                        request_digest, first_ordinal, added_count, total_edit_count
                 FROM changeset_add_operations
                 ORDER BY workspace_id, principal_id, changeset_id, first_ordinal,
                          idempotency_key",
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            .collect::<Result<Vec<LegacyEditOperation>, _>>()
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
    };
    let changeset_ids = {
        let mut statement = transaction
            .prepare(
                "SELECT changeset_id FROM changeset_add_operations
                 UNION
                 SELECT changeset_id FROM changeset_edits
                 ORDER BY changeset_id",
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
    };
    for raw_changeset_id in changeset_ids {
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let edit_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM changeset_edits WHERE changeset_id = ?1",
                [&raw_changeset_id],
                |row| row.get(0),
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        let edit_count = usize::try_from(edit_count).map_err(|_| {
            LatestSchemaError::Integrity("ChangeSet Edit count exceeds usize".to_owned())
        })?;
        verify_inspected_edit_operation_bindings(transaction, changeset_id, 9, edit_count)
            .map_err(|error| match error {
                InspectChangeSetError::Storage(detail) => LatestSchemaError::Storage(detail),
                other => LatestSchemaError::Integrity(other.to_string()),
            })?;
    }
    for (
        raw_workspace_id,
        raw_principal_id,
        raw_changeset_id,
        raw_idempotency_key,
        raw_request_digest,
        first_ordinal,
        added_count,
        total_edit_count,
    ) in operations
    {
        let workspace_id = raw_workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let principal_id = raw_principal_id
            .parse::<PrincipalId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let request_digest = raw_request_digest
            .parse::<ContentDigest>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let idempotency_key = raw_idempotency_key
            .parse::<IdempotencyKey>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        if workspace_id.to_string() != raw_workspace_id
            || principal_id.to_string() != raw_principal_id
            || changeset_id.to_string() != raw_changeset_id
            || request_digest.to_string() != raw_request_digest
            || idempotency_key.to_string() != raw_idempotency_key
        {
            return Err(LatestSchemaError::Integrity(
                "legacy Edit operation identity or digest is not canonical".to_owned(),
            ));
        }
        let positive = |value: i64, field: &str| {
            u32::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| LatestSchemaError::Integrity(format!("{field} must be positive")))
        };
        let first_ordinal = positive(first_ordinal, "first Edit ordinal")?;
        let added_count = positive(added_count, "added Edit count")?;
        let total_edit_count = positive(total_edit_count, "total Edit count")?;
        let final_ordinal = first_ordinal.checked_add(added_count - 1).ok_or_else(|| {
            LatestSchemaError::Integrity("ChangeSet Edit ordinal overflow".to_owned())
        })?;
        if total_edit_count != final_ordinal {
            return Err(LatestSchemaError::Integrity(
                "legacy Edit operation result ordinals are inconsistent".to_owned(),
            ));
        }
        let edits =
            load_persisted_edit_batch(transaction, changeset_id, first_ordinal, final_ordinal, 9)
                .map_err(|error| match error {
                AddChangeSetEditsError::Storage(detail) => LatestSchemaError::Storage(detail),
                other => LatestSchemaError::Integrity(other.to_string()),
            })?;
        if verified_edit_batch(&edits)
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?
            != request_digest
        {
            return Err(LatestSchemaError::Integrity(
                "legacy Edit batch does not match its operation digest".to_owned(),
            ));
        }
        let effect_digest = edit_batch_operation_effect_digest(
            request_digest,
            idempotency_key,
            workspace_id,
            principal_id,
            changeset_id,
            first_ordinal,
            added_count,
            total_edit_count,
            &edits,
        )
        .map_err(LatestSchemaError::Integrity)?;
        let updated = transaction
            .execute(
                "UPDATE changeset_add_operations SET effect_digest = ?1
                 WHERE workspace_id = ?2 AND principal_id = ?3 AND changeset_id = ?4
                       AND idempotency_key = ?5",
                (
                    effect_digest.to_string(),
                    raw_workspace_id,
                    raw_principal_id,
                    raw_changeset_id,
                    raw_idempotency_key,
                ),
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        if updated != 1 {
            return Err(LatestSchemaError::Integrity(
                "legacy Edit operation effect backfill was ambiguous".to_owned(),
            ));
        }
    }
    let placeholder_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM changeset_add_operations WHERE effect_digest = ''",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if placeholder_count != 0 {
        return Err(LatestSchemaError::Integrity(
            "legacy Edit operation effect backfill is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_migration_effect_column(
    transaction: &Transaction<'_>,
    table: &str,
) -> Result<(), LatestSchemaError> {
    let exists: bool = transaction
        .query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('{table}') WHERE name = 'effect_digest'
                 )"
            ),
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if !exists {
        transaction
            .execute_batch(&format!(
                "ALTER TABLE {table}
                 ADD COLUMN effect_digest TEXT NOT NULL DEFAULT '';"
            ))
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn verify_changeset_lifecycle_cardinality(connection: &Connection) -> Result<(), LocalPortError> {
    type LifecycleRow = (String, String, i64, i64, i64);

    let orphan_evidence_exists: bool = connection
        .query_row(
            "SELECT
                 EXISTS(
                     SELECT 1 FROM changeset_submissions s
                     WHERE NOT EXISTS (
                         SELECT 1 FROM changesets c WHERE c.changeset_id = s.changeset_id
                     )
                 ) OR EXISTS(
                     SELECT 1 FROM changeset_approvals a
                     WHERE NOT EXISTS (
                         SELECT 1 FROM changesets c WHERE c.changeset_id = a.changeset_id
                     )
                 ) OR EXISTS(
                     SELECT 1 FROM changeset_commits m
                     WHERE NOT EXISTS (
                         SELECT 1 FROM changesets c WHERE c.changeset_id = m.changeset_id
                     )
                 )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if orphan_evidence_exists {
        return Err(LocalPortError::Integrity(
            "ChangeSet lifecycle evidence has no owning ChangeSet".to_owned(),
        ));
    }

    let rows = {
        let mut statement = connection
            .prepare(
                "SELECT c.changeset_id, c.lifecycle_status,
                        (SELECT COUNT(*) FROM changeset_submissions s
                         WHERE s.changeset_id = c.changeset_id),
                        (SELECT COUNT(*) FROM changeset_approvals a
                         WHERE a.changeset_id = c.changeset_id),
                        (SELECT COUNT(*) FROM changeset_commits m
                         WHERE m.changeset_id = c.changeset_id)
                 FROM changesets c ORDER BY c.changeset_id",
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
            .collect::<Result<Vec<LifecycleRow>, _>>()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    };
    for (raw_changeset_id, raw_status, submissions, approvals, commits) in rows {
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if changeset_id.to_string() != raw_changeset_id {
            return Err(LocalPortError::Integrity(
                "ChangeSet lifecycle identity is not canonical".to_owned(),
            ));
        }
        let status = parse_changeset_status(&raw_status).map_err(local_port_from_inspection)?;
        let expected = match status {
            ChangeSetStatus::Submitted => (1, 0, 0),
            ChangeSetStatus::Approved => (1, 1, 0),
            ChangeSetStatus::Committed => (1, 1, 1),
            ChangeSetStatus::Draft
            | ChangeSetStatus::Validating
            | ChangeSetStatus::Ready
            | ChangeSetStatus::Rejected
            | ChangeSetStatus::Superseded
            | ChangeSetStatus::Expired => (0, 0, 0),
        };
        if (submissions, approvals, commits) != expected {
            return Err(LocalPortError::Integrity(format!(
                "ChangeSet {changeset_id} lifecycle evidence cardinality does not match {status}"
            )));
        }
    }
    Ok(())
}

fn load_legacy_inspected_changeset(
    connection: &Connection,
    changeset_id: ChangeSetId,
) -> Result<InspectedChangeSet, LatestSchemaError> {
    let (raw_workspace, raw_principal): (String, String) = connection
        .query_row(
            "SELECT workspace_id, principal_id FROM changesets WHERE changeset_id = ?1",
            [changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    let workspace_id = raw_workspace
        .parse::<WorkspaceId>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let principal_id = raw_principal
        .parse::<PrincipalId>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    if workspace_id.to_string() != raw_workspace || principal_id.to_string() != raw_principal {
        return Err(LatestSchemaError::Integrity(
            "legacy ChangeSet scope is not canonical".to_owned(),
        ));
    }
    let row = load_inspected_changeset(connection, changeset_id, workspace_id, principal_id, 9)
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let edits = load_inspected_edits(connection, changeset_id, 9)
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    row.into_inspected(changeset_id, workspace_id, principal_id, edits)
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))
}

fn latest_schema_from_local_port(error: LocalPortError) -> LatestSchemaError {
    match error {
        LocalPortError::Storage(detail) => LatestSchemaError::Storage(detail),
        LocalPortError::Integrity(detail) => LatestSchemaError::Integrity(detail),
        _ => LatestSchemaError::Integrity(
            "legacy immutable fact verification returned an invalid outcome".to_owned(),
        ),
    }
}

fn load_verified_legacy_submission(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    reproduced: &ReproducedCommitFacts,
) -> Result<SubmittedChangeSet, LatestSchemaError> {
    if !matches!(
        changeset.status,
        ChangeSetStatus::Submitted | ChangeSetStatus::Approved | ChangeSetStatus::Committed
    ) {
        return Err(LatestSchemaError::Integrity(
            "legacy submission has an invalid lifecycle state".to_owned(),
        ));
    }
    let changeset_digest = changeset_digest_for(changeset).map_err(LatestSchemaError::Integrity)?;
    let preceding_schemas = reproduced_schemas_at(
        reproduced,
        changeset.workspace_id,
        changeset.base_authoritative_sequence,
    )?;
    let validation = validate_rebuild_changeset(changeset, changeset_digest, &preceding_schemas)
        .map_err(latest_schema_from_local_port)?;
    if !validation.valid {
        return Err(LatestSchemaError::Integrity(
            "legacy submission lacks valid deterministic evidence".to_owned(),
        ));
    }
    let validation_results_digest = exact_valid_evidence(
        connection,
        changeset.changeset_id,
        changeset_digest,
        changeset.base_state,
        &changeset.validation_profile,
        &validation.validator,
        validation.results_digest,
    )
    .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let submitted = replay_submission(
        connection,
        changeset,
        changeset_digest,
        validation_results_digest,
        u32::try_from(changeset.edits.len()).map_err(|_| {
            LatestSchemaError::Integrity("legacy ChangeSet Edit count exceeds u32".to_owned())
        })?,
    )
    .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    if submitted.submitted_at < changeset.created_at {
        return Err(LatestSchemaError::Integrity(
            "legacy submission predates ChangeSet creation".to_owned(),
        ));
    }
    Ok(submitted)
}

fn load_verified_legacy_approval(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    submitted: &SubmittedChangeSet,
) -> Result<ApprovedChangeSet, LatestSchemaError> {
    if !matches!(
        changeset.status,
        ChangeSetStatus::Approved | ChangeSetStatus::Committed
    ) {
        return Err(LatestSchemaError::Integrity(
            "legacy approval has an invalid lifecycle state".to_owned(),
        ));
    }
    let (raw_approval, raw_approved_at): (String, String) = connection
        .query_row(
            "SELECT approval_name, approved_at FROM changeset_approvals
             WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    let approval = ApprovalName::new(raw_approval)
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let approved_at = raw_approved_at
        .parse::<Timestamp>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    if approved_at.to_string() != raw_approved_at {
        return Err(LatestSchemaError::Integrity(
            "legacy approval timestamp is not canonical".to_owned(),
        ));
    }
    let approved = replay_approval(
        connection,
        &ApproveChangeSetCommand {
            changeset_id: changeset.changeset_id,
            approval,
            approved_at,
        },
        changeset,
        submitted.changeset_digest,
        submitted.validation_results_digest,
    )
    .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    if approved.approved_at < submitted.submitted_at {
        return Err(LatestSchemaError::Integrity(
            "legacy approval predates submission".to_owned(),
        ));
    }
    Ok(approved)
}

#[expect(
    clippy::too_many_lines,
    reason = "legacy migration reconstructs and verifies every persisted commit result field without consulting projections"
)]
fn load_verified_legacy_commit(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    submitted: &SubmittedChangeSet,
    approved: &ApprovedChangeSet,
    reproduced: &ReproducedCommitFacts,
) -> Result<(IdempotencyKey, CommittedChangeSet), LatestSchemaError> {
    type LegacyCommitRow = (String, String, String, String, String, i64, String, i64);
    if changeset.status != ChangeSetStatus::Committed {
        return Err(LatestSchemaError::Integrity(
            "legacy commit has an invalid lifecycle state".to_owned(),
        ));
    }
    let (
        raw_key,
        raw_changeset_digest,
        raw_validation_digest,
        raw_previous_state,
        raw_resulting_state,
        raw_sequence,
        raw_committed_at,
        raw_edit_count,
    ): LegacyCommitRow = connection
        .query_row(
            "SELECT idempotency_key, changeset_digest, validation_results_digest,
                    previous_state, resulting_state, authoritative_sequence,
                    committed_at, edit_count
             FROM changeset_commits
             WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
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
                ))
            },
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    let idempotency_key = raw_key
        .parse::<IdempotencyKey>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let committed_at = raw_committed_at
        .parse::<Timestamp>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let changeset_digest = raw_changeset_digest
        .parse::<ContentDigest>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let validation_results_digest = raw_validation_digest
        .parse::<ContentDigest>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let previous_state = raw_previous_state
        .parse::<ContentDigest>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let resulting_state = raw_resulting_state
        .parse::<ContentDigest>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    let authoritative_sequence = u64::try_from(raw_sequence).map_err(|_| {
        LatestSchemaError::Integrity("legacy commit sequence must be non-negative".to_owned())
    })?;
    let edit_count = u32::try_from(raw_edit_count).map_err(|_| {
        LatestSchemaError::Integrity("legacy commit Edit count exceeds u32".to_owned())
    })?;
    if idempotency_key.to_string() != raw_key
        || committed_at.to_string() != raw_committed_at
        || changeset_digest.to_string() != raw_changeset_digest
        || validation_results_digest.to_string() != raw_validation_digest
        || previous_state.to_string() != raw_previous_state
        || resulting_state.to_string() != raw_resulting_state
    {
        return Err(LatestSchemaError::Integrity(
            "legacy commit identity or result is not canonical".to_owned(),
        ));
    }
    let expected_sequence = changeset
        .base_authoritative_sequence
        .checked_add(u64::from(edit_count))
        .ok_or_else(|| {
            LatestSchemaError::Integrity("legacy commit sequence overflow".to_owned())
        })?;
    let reproduced_result =
        reproduced_state_at(reproduced, changeset.workspace_id, authoritative_sequence)?;
    if changeset_digest != submitted.changeset_digest
        || validation_results_digest != submitted.validation_results_digest
        || previous_state != changeset.base_state
        || usize::try_from(edit_count).ok() != Some(changeset.edits.len())
        || authoritative_sequence != expected_sequence
        || resulting_state != reproduced_result
    {
        return Err(LatestSchemaError::Integrity(
            "legacy commit does not match its immutable ChangeSet result".to_owned(),
        ));
    }
    let committed = CommittedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        validation_results_digest,
        previous_state,
        resulting_state,
        authoritative_sequence,
        committed_at,
        status: ChangeSetStatus::Committed,
        edit_count,
    };
    if committed.committed_at < approved.approved_at {
        return Err(LatestSchemaError::Integrity(
            "legacy commit predates approval".to_owned(),
        ));
    }
    Ok((idempotency_key, committed))
}

#[expect(
    clippy::too_many_lines,
    reason = "the v10 migration verifies and binds the full legacy lifecycle in dependency order"
)]
fn backfill_lifecycle_effect_digests(
    transaction: &Transaction<'_>,
) -> Result<(), LatestSchemaError> {
    type LegacyDraftRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    const TABLES: [&str; 5] = [
        "changesets",
        "changeset_submissions",
        "changeset_approvals",
        "changeset_commits",
        "edition_create_operations",
    ];
    for table in TABLES {
        ensure_migration_effect_column(transaction, table)?;
    }
    verify_changeset_lifecycle_cardinality(transaction).map_err(|error| match error {
        LocalPortError::Storage(detail) => LatestSchemaError::Storage(detail),
        LocalPortError::Integrity(detail) => LatestSchemaError::Integrity(detail),
        other => LatestSchemaError::Integrity(format!(
            "legacy ChangeSet lifecycle verification failed: {other:?}"
        )),
    })?;
    let raw_workspace_id: String = transaction
        .query_row(
            "SELECT workspace_id FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    let workspace_id = raw_workspace_id
        .parse::<WorkspaceId>()
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
    if workspace_id.to_string() != raw_workspace_id {
        return Err(LatestSchemaError::Integrity(
            "legacy Workspace identity is not canonical".to_owned(),
        ));
    }
    let reproduced = reproduce_commit_facts(transaction, workspace_id, 9)
        .map_err(latest_schema_from_local_port)?;

    let changeset_ids = {
        let mut statement = transaction
            .prepare("SELECT changeset_id FROM changesets ORDER BY changeset_id")
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
    };
    for raw_changeset_id in &changeset_ids {
        let raw: LegacyDraftRow = transaction
            .query_row(
                "SELECT changeset_id, workspace_id, principal_id, intent,
                        requested_base_state, base_authoritative_sequence, base_state,
                        idempotency_key, created_at, status, policy_profile,
                        validation_profile
                 FROM changesets WHERE changeset_id = ?1",
                [raw_changeset_id],
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
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                    ))
                },
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        let requested_base_state = raw
            .4
            .as_deref()
            .map(str::parse::<ContentDigest>)
            .transpose()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let draft = PersistedDraft {
            changeset_id: raw.0.clone(),
            workspace_id: raw.1,
            principal_id: raw.2,
            intent: raw.3,
            requested_base_state: raw.4,
            base_authoritative_sequence: raw.5,
            base_state: raw.6,
            idempotency_key: raw.7,
            created_at: raw.8,
            status: raw.9,
            policy_profile: raw.10,
            validation_profile: raw.11,
            effect_digest: None,
        }
        .into_draft(9)
        .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let reproduced_base = reproduced_state_at(
            &reproduced,
            draft.workspace_id,
            draft.base_authoritative_sequence,
        )?;
        if reproduced_base != draft.base_state
            || requested_base_state.is_some_and(|value| value != draft.base_state)
        {
            return Err(LatestSchemaError::Integrity(
                "legacy ChangeSet base state does not reproduce".to_owned(),
            ));
        }
        let effect = changeset_creation_effect_digest(requested_base_state, &draft)
            .map_err(LatestSchemaError::Integrity)?;
        if transaction
            .execute(
                "UPDATE changesets SET effect_digest = ?1 WHERE changeset_id = ?2",
                (effect.to_string(), raw_changeset_id),
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            != 1
        {
            return Err(LatestSchemaError::Integrity(
                "legacy ChangeSet creation effect backfill was ambiguous".to_owned(),
            ));
        }
    }

    let submission_ids = migration_record_ids(transaction, "changeset_submissions")?;
    for raw_changeset_id in submission_ids {
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let changeset = load_legacy_inspected_changeset(transaction, changeset_id)?;
        let submitted = load_verified_legacy_submission(transaction, &changeset, &reproduced)?;
        let effect =
            changeset_submission_effect_digest(&submitted).map_err(LatestSchemaError::Integrity)?;
        update_migration_effect(
            transaction,
            "changeset_submissions",
            &raw_changeset_id,
            effect,
        )?;
    }

    let approval_ids = migration_record_ids(transaction, "changeset_approvals")?;
    for raw_changeset_id in approval_ids {
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let changeset = load_legacy_inspected_changeset(transaction, changeset_id)?;
        let submitted = load_verified_legacy_submission(transaction, &changeset, &reproduced)?;
        let approved = load_verified_legacy_approval(transaction, &changeset, &submitted)?;
        let effect =
            changeset_approval_effect_digest(&approved).map_err(LatestSchemaError::Integrity)?;
        update_migration_effect(
            transaction,
            "changeset_approvals",
            &raw_changeset_id,
            effect,
        )?;
    }

    let commit_ids = migration_record_ids(transaction, "changeset_commits")?;
    for raw_changeset_id in commit_ids {
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let changeset = load_legacy_inspected_changeset(transaction, changeset_id)?;
        let submitted = load_verified_legacy_submission(transaction, &changeset, &reproduced)?;
        let approved = load_verified_legacy_approval(transaction, &changeset, &submitted)?;
        let (idempotency_key, committed) = load_verified_legacy_commit(
            transaction,
            &changeset,
            &submitted,
            &approved,
            &reproduced,
        )?;
        let effect = changeset_commit_effect_digest(idempotency_key, &committed)
            .map_err(LatestSchemaError::Integrity)?;
        update_migration_effect(transaction, "changeset_commits", &raw_changeset_id, effect)?;
    }

    let edition_operations = {
        let mut statement = transaction
            .prepare(
                "SELECT workspace_id, principal_id, idempotency_key,
                        requested_state_digest, edition_id
                 FROM edition_create_operations
                 ORDER BY workspace_id, principal_id, idempotency_key",
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
    };
    for (raw_workspace, raw_principal, raw_key, raw_state, raw_edition_id) in edition_operations {
        let workspace_id = raw_workspace
            .parse::<WorkspaceId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let principal_id = raw_principal
            .parse::<PrincipalId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let idempotency_key = raw_key
            .parse::<IdempotencyKey>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let requested_state = raw_state
            .parse::<ContentDigest>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        let edition_id = raw_edition_id
            .parse::<EditionId>()
            .map_err(|error| LatestSchemaError::Integrity(error.to_string()))?;
        if workspace_id.to_string() != raw_workspace
            || principal_id.to_string() != raw_principal
            || idempotency_key.to_string() != raw_key
            || requested_state.to_string() != raw_state
            || edition_id.to_string() != raw_edition_id
        {
            return Err(LatestSchemaError::Integrity(
                "legacy Edition operation identity is not canonical".to_owned(),
            ));
        }
        let edition = load_edition_from_reproduced(
            transaction,
            edition_id,
            workspace_id,
            ReproducedEditionData {
                schemas: &reproduced.schemas,
                objects: &reproduced.objects,
                changesets: &reproduced.changesets,
            },
        )
        .map_err(latest_schema_from_local_port)?;
        if edition.workspace_id != workspace_id
            || edition.principal_id != principal_id
            || edition.state_digest != requested_state
        {
            return Err(LatestSchemaError::Integrity(
                "legacy Edition operation does not match its result".to_owned(),
            ));
        }
        let effect =
            edition_create_operation_effect_digest(idempotency_key, requested_state, &edition)
                .map_err(LatestSchemaError::Integrity)?;
        if transaction
            .execute(
                "UPDATE edition_create_operations SET effect_digest = ?1
                 WHERE workspace_id = ?2 AND principal_id = ?3 AND idempotency_key = ?4",
                (effect.to_string(), raw_workspace, raw_principal, raw_key),
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
            != 1
        {
            return Err(LatestSchemaError::Integrity(
                "legacy Edition effect backfill was ambiguous".to_owned(),
            ));
        }
    }
    let orphan_edition_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM editions e
                 LEFT JOIN edition_create_operations o ON o.edition_id = e.edition_id
                 WHERE o.edition_id IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    if orphan_edition_exists {
        return Err(LatestSchemaError::Integrity(
            "legacy Edition is missing its creation operation".to_owned(),
        ));
    }
    for table in TABLES {
        let placeholders: i64 = transaction
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE effect_digest = ''"),
                [],
                |row| row.get(0),
            )
            .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
        if placeholders != 0 {
            return Err(LatestSchemaError::Integrity(format!(
                "legacy {table} effect backfill is incomplete"
            )));
        }
    }
    Ok(())
}

fn migration_record_ids(
    transaction: &Transaction<'_>,
    table: &str,
) -> Result<Vec<String>, LatestSchemaError> {
    let mut statement = transaction
        .prepare(&format!(
            "SELECT changeset_id FROM {table} ORDER BY changeset_id"
        ))
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?;
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))
}

fn update_migration_effect(
    transaction: &Transaction<'_>,
    table: &str,
    changeset_id: &str,
    effect_digest: ContentDigest,
) -> Result<(), LatestSchemaError> {
    if transaction
        .execute(
            &format!("UPDATE {table} SET effect_digest = ?1 WHERE changeset_id = ?2"),
            (effect_digest.to_string(), changeset_id),
        )
        .map_err(|error| LatestSchemaError::Storage(error.to_string()))?
        != 1
    {
        return Err(LatestSchemaError::Integrity(format!(
            "legacy {table} effect backfill was ambiguous"
        )));
    }
    Ok(())
}

fn operation_target_ids(
    connection: &Connection,
    table: &str,
    target_column: &str,
) -> Result<Vec<String>, LocalPortError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT DISTINCT {target_column} FROM {table} ORDER BY {target_column}"
        ))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| LocalPortError::Storage(error.to_string()))
}

fn verify_edit_operation_scope(
    connection: &Connection,
    schema_version: u32,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(connection, "changeset_add_operations", "changeset_id")? {
        let changeset_id = raw_id
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if changeset_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "Edit operation ChangeSet identity is not canonical".to_owned(),
            ));
        }
        let target_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM changesets WHERE changeset_id = ?1)",
                [&raw_id],
                |row| row.get(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if !target_exists {
            return Err(LocalPortError::Integrity(
                "Edit operation target ChangeSet is missing".to_owned(),
            ));
        }
        load_inspected_edits(connection, changeset_id, schema_version)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    }
    Ok(())
}

fn verify_environment_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(
        connection,
        "environment_create_operations",
        "environment_id",
    )? {
        let environment_id = raw_id
            .parse::<EnvironmentId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if environment_id.as_str() != raw_id {
            return Err(LocalPortError::Integrity(
                "Environment operation target is not canonical".to_owned(),
            ));
        }
        load_environment_version(connection, workspace_id, environment_id, 1)
            .map_err(local_port_from_environment)?;
    }
    Ok(())
}

fn verify_principal_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(
        connection,
        "principal_create_operations",
        "created_principal_id",
    )? {
        let principal_id = raw_id
            .parse::<PrincipalId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if principal_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "Principal operation target is not canonical".to_owned(),
            ));
        }
        load_agent_principal(connection, workspace_id, principal_id).map_err(
            |error| match error {
                PrincipalError::Storage(detail) => LocalPortError::Storage(detail),
                other => LocalPortError::Integrity(other.to_string()),
            },
        )?;
    }
    Ok(())
}

fn verify_delegation_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    let mut target_ids = BTreeSet::new();
    for table in [
        "delegation_grant_operations",
        "delegation_revoke_operations",
    ] {
        target_ids.extend(operation_target_ids(connection, table, "delegation_id")?);
    }
    for raw_id in target_ids {
        let delegation_id = raw_id
            .parse::<DelegationId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if delegation_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "Delegation operation target is not canonical".to_owned(),
            ));
        }
        load_delegation(connection, workspace_id, delegation_id)
            .map_err(local_port_from_delegation)?;
    }
    Ok(())
}

fn verify_context_pack_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(
        connection,
        "context_pack_build_operations",
        "context_pack_id",
    )? {
        let context_pack_id = raw_id
            .parse::<ContextPackId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if context_pack_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "ContextPack operation target is not canonical".to_owned(),
            ));
        }
        load_context_pack_record(connection, workspace_id, context_pack_id)?;
    }
    Ok(())
}

fn verify_edition_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(connection, "edition_create_operations", "edition_id")? {
        let edition_id = raw_id
            .parse::<EditionId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if edition_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "Edition operation target is not canonical".to_owned(),
            ));
        }
        let edition = load_edition(connection, edition_id).map_err(local_port_from_edition)?;
        if edition.workspace_id != workspace_id {
            return Err(LocalPortError::Integrity(
                "Edition operation target belongs to another Workspace".to_owned(),
            ));
        }
    }
    Ok(())
}

fn parse_canonical_scope_value<T>(raw: &str, field: &str) -> Result<T, LocalPortError>
where
    T: std::str::FromStr + ToString,
    T::Err: std::fmt::Display,
{
    let parsed = raw
        .parse::<T>()
        .map_err(|error| LocalPortError::Integrity(format!("invalid {field}: {error}")))?;
    if parsed.to_string() != raw {
        return Err(LocalPortError::Integrity(format!(
            "{field} is not canonical"
        )));
    }
    Ok(parsed)
}

fn local_port_from_submission_evidence(error: SubmitChangeSetError) -> LocalPortError {
    match error {
        SubmitChangeSetError::Storage(detail) => LocalPortError::Storage(detail),
        SubmitChangeSetError::Integrity(detail) => LocalPortError::Integrity(detail),
        other => LocalPortError::Integrity(format!(
            "committed submission evidence failed verification: {other}"
        )),
    }
}

fn local_port_from_approval_evidence(error: ApproveChangeSetError) -> LocalPortError {
    match error {
        ApproveChangeSetError::Storage(detail) => LocalPortError::Storage(detail),
        ApproveChangeSetError::Integrity(detail) => LocalPortError::Integrity(detail),
        other => LocalPortError::Integrity(format!(
            "committed approval evidence failed verification: {other}"
        )),
    }
}

fn verify_committed_validation_evidence(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<(), LocalPortError> {
    let validators = {
        let mut statement = connection
            .prepare(
                "SELECT validator FROM changeset_validations
                 WHERE changeset_id = ?1 AND changeset_digest = ?2
                       AND base_state = ?3 AND validation_profile = ?4
                       AND valid = 1 AND results_digest = ?5
                 ORDER BY validator",
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        statement
            .query_map(
                (
                    changeset.changeset_id.to_string(),
                    changeset_digest.to_string(),
                    changeset.base_state.to_string(),
                    changeset.validation_profile.as_str(),
                    validation_results_digest.to_string(),
                ),
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    };
    if validators.len() != 1 {
        return Err(LocalPortError::Integrity(
            "committed ChangeSet does not have one exact valid evidence record".to_owned(),
        ));
    }
    exact_valid_evidence(
        connection,
        changeset.changeset_id,
        changeset_digest,
        changeset.base_state,
        &changeset.validation_profile,
        &validators[0],
        validation_results_digest,
    )
    .map_err(local_port_from_submission_evidence)?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "commit scope verification reconstructs the complete projection-independent lifecycle and authoritative chain"
)]
fn verify_commit_operation_chain(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(u64, ContentDigest), LocalPortError> {
    type CommitScopeRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        Option<String>,
    );

    verify_changeset_lifecycle_cardinality(connection)?;
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let rows = {
        let mut statement = connection
            .prepare(&format!(
                "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                        changeset_digest, validation_results_digest, previous_state,
                        resulting_state, authoritative_sequence, committed_at,
                        edit_count, {effect_column}
                 FROM changeset_commits
                 ORDER BY authoritative_sequence, changeset_id"
            ))
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| {
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            })
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
            .collect::<Result<Vec<CommitScopeRow>, _>>()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    };
    let mut previous_sequence = 0_u64;
    let mut previous_state = initial_known_state_digest(workspace_id)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    for row in rows {
        let changeset_id =
            parse_canonical_scope_value::<ChangeSetId>(&row.0, "commit ChangeSet identity")?;
        let persisted_workspace =
            parse_canonical_scope_value::<WorkspaceId>(&row.1, "commit Workspace identity")?;
        let principal_id =
            parse_canonical_scope_value::<PrincipalId>(&row.2, "commit Principal identity")?;
        let idempotency_key =
            parse_canonical_scope_value::<IdempotencyKey>(&row.3, "commit idempotency key")?;
        let changeset_digest =
            parse_canonical_scope_value::<ContentDigest>(&row.4, "commit ChangeSet digest")?;
        let validation_results_digest = parse_canonical_scope_value::<ContentDigest>(
            &row.5,
            "commit validation-results digest",
        )?;
        let persisted_previous_state =
            parse_canonical_scope_value::<ContentDigest>(&row.6, "commit previous state")?;
        let resulting_state =
            parse_canonical_scope_value::<ContentDigest>(&row.7, "commit resulting state")?;
        let authoritative_sequence = u64::try_from(row.8).map_err(|_| {
            LocalPortError::Integrity("commit sequence must be positive".to_owned())
        })?;
        let committed_at = parse_canonical_scope_value::<Timestamp>(&row.9, "commit timestamp")?;
        let edit_count = u32::try_from(row.10)
            .map_err(|_| LocalPortError::Integrity("commit Edit count exceeds u32".to_owned()))?;
        if persisted_workspace != workspace_id {
            return Err(LocalPortError::Integrity(
                "commit belongs to another Workspace".to_owned(),
            ));
        }

        let inspected_row = load_inspected_changeset(
            connection,
            changeset_id,
            workspace_id,
            principal_id,
            schema_version,
        )
        .map_err(local_port_from_inspection)?;
        let edits = load_inspected_edits(connection, changeset_id, schema_version)
            .map_err(local_port_from_inspection)?;
        let changeset = inspected_row
            .into_inspected(changeset_id, workspace_id, principal_id, edits)
            .map_err(local_port_from_inspection)?;
        if changeset.status != ChangeSetStatus::Committed
            || changeset_digest_for(&changeset).map_err(LocalPortError::Integrity)?
                != changeset_digest
            || u32::try_from(changeset.edits.len()).ok() != Some(edit_count)
            || changeset.base_state != persisted_previous_state
        {
            return Err(LocalPortError::Integrity(
                "commit does not match its immutable ChangeSet proposal".to_owned(),
            ));
        }
        let expected_sequence = changeset
            .base_authoritative_sequence
            .checked_add(u64::from(edit_count))
            .ok_or_else(|| {
                LocalPortError::Integrity("authoritative sequence overflow".to_owned())
            })?;
        if authoritative_sequence != expected_sequence
            || changeset.base_authoritative_sequence != previous_sequence
            || persisted_previous_state != previous_state
        {
            return Err(LocalPortError::Integrity(
                "commit authoritative chain is not contiguous".to_owned(),
            ));
        }

        verify_committed_validation_evidence(
            connection,
            &changeset,
            changeset_digest,
            validation_results_digest,
        )?;
        let submitted = replay_submission(
            connection,
            &changeset,
            changeset_digest,
            validation_results_digest,
            edit_count,
        )
        .map_err(local_port_from_submission_evidence)?;
        if submitted.submitted_at < changeset.created_at {
            return Err(LocalPortError::Integrity(
                "submission timestamp predates ChangeSet creation".to_owned(),
            ));
        }
        let (raw_approval, raw_approved_at): (String, String) = connection
            .query_row(
                "SELECT approval_name, approved_at FROM changeset_approvals
                 WHERE changeset_id = ?1",
                [changeset_id.to_string()],
                |approval_row| Ok((approval_row.get(0)?, approval_row.get(1)?)),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let approval = ApprovalName::new(raw_approval)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let approved_at =
            parse_canonical_scope_value::<Timestamp>(&raw_approved_at, "approval timestamp")?;
        let approved = replay_approval(
            connection,
            &ApproveChangeSetCommand {
                changeset_id,
                approval,
                approved_at,
            },
            &changeset,
            changeset_digest,
            validation_results_digest,
        )
        .map_err(local_port_from_approval_evidence)?;
        if approved.approved_at < submitted.submitted_at {
            return Err(LocalPortError::Integrity(
                "approval timestamp predates submission".to_owned(),
            ));
        }
        let committed = CommittedChangeSet {
            changeset_id,
            workspace_id,
            principal_id,
            changeset_digest,
            validation_results_digest,
            previous_state: persisted_previous_state,
            resulting_state,
            authoritative_sequence,
            committed_at,
            status: ChangeSetStatus::Committed,
            edit_count,
        };
        if committed.committed_at < approved.approved_at {
            return Err(LocalPortError::Integrity(
                "commit timestamp predates approval".to_owned(),
            ));
        }
        if schema_version >= 10 {
            let persisted_effect = row
                .11
                .ok_or_else(|| LocalPortError::Integrity("commit effect is missing".to_owned()))?;
            let expected = changeset_commit_effect_digest(idempotency_key, &committed)
                .map_err(LocalPortError::Integrity)?;
            if persisted_effect != expected.to_string() {
                return Err(LocalPortError::Integrity(
                    "commit effect does not reproduce".to_owned(),
                ));
            }
        }
        previous_sequence = authoritative_sequence;
        previous_state = resulting_state;
    }
    Ok((previous_sequence, previous_state))
}

fn verify_commit_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    let (previous_sequence, previous_state) =
        verify_commit_operation_chain(connection, workspace_id)?;
    let (raw_known_sequence, raw_known_state): (i64, String) = connection
        .query_row(
            "SELECT authoritative_sequence, state_digest FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let known_sequence = u64::try_from(raw_known_sequence).map_err(|_| {
        LocalPortError::Integrity("Known State sequence must be non-negative".to_owned())
    })?;
    let known_state =
        parse_canonical_scope_value::<ContentDigest>(&raw_known_state, "Known State digest")?;
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let api_version = if schema_version >= 11 {
        connection
            .query_row(
                "SELECT api_version FROM known_state WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    } else {
        KNOWN_STATE_V1_API_VERSION.to_owned()
    };
    match api_version.as_str() {
        KNOWN_STATE_V1_API_VERSION => {
            if known_sequence != previous_sequence || known_state != previous_state {
                return Err(LocalPortError::Integrity(
                    "Known State is not covered by the complete commit chain".to_owned(),
                ));
            }
        }
        KNOWN_STATE_V2_API_VERSION => {
            let (predecessor_api, predecessor_sequence, predecessor_digest): (String, i64, String) =
                connection
                    .query_row(
                        "SELECT previous_state_api_version, previous_authoritative_sequence,
                            previous_state_digest
                     FROM localized_commits ORDER BY resulting_authoritative_sequence LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(|error| LocalPortError::Storage(error.to_string()))?;
            let predecessor_sequence = u64::try_from(predecessor_sequence).map_err(|_| {
                LocalPortError::Integrity("localized predecessor sequence is invalid".to_owned())
            })?;
            let predecessor_digest = parse_canonical_scope_value::<ContentDigest>(
                &predecessor_digest,
                "localized predecessor state digest",
            )?;
            if predecessor_api != KNOWN_STATE_V1_API_VERSION
                || predecessor_sequence != previous_sequence
                || predecessor_digest != previous_state
                || known_sequence <= previous_sequence
            {
                return Err(LocalPortError::Integrity(
                    "localized state does not extend the complete v1 commit chain".to_owned(),
                ));
            }
        }
        _ => return Err(LocalPortError::UnsupportedVersion),
    }
    Ok(())
}

fn verify_release_operation_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), LocalPortError> {
    for raw_id in operation_target_ids(connection, "release_operations", "release_id")? {
        let release_id = raw_id
            .parse::<ReleaseId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if release_id.to_string() != raw_id {
            return Err(LocalPortError::Integrity(
                "Release operation target is not canonical".to_owned(),
            ));
        }
        load_release_record(connection, workspace_id, release_id).map_err(|error| match error {
            LocalPortError::Storage(detail) => LocalPortError::Storage(detail),
            LocalPortError::Integrity(detail) => LocalPortError::Integrity(detail),
            other => LocalPortError::Integrity(format!(
                "Release operation target failed verification: {other:?}"
            )),
        })?;
    }
    Ok(())
}

fn environment_create_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    environment: &Environment,
    policy_digest: ContentDigest,
) -> Result<ContentDigest, String> {
    operation_effect_digest(
        "environment.create",
        request_digest,
        &serde_json::json!({
            "config_digest": environment.config_digest.to_string(),
            "config_manifest_json": environment.config_manifest_json,
            "config_version": environment.config_version,
            "created_at": environment.created_at.to_string(),
            "created_by_principal_id": environment.principal_id.to_string(),
            "environment_id": environment.environment_id.as_str(),
            "idempotency_key": idempotency_key.to_string(),
            "policy_digest": policy_digest.to_string(),
            "policy_profile": environment.policy_profile,
            "required_approval": environment.required_approval.as_str(),
            "target_kind": environment.target_kind,
            "workspace_id": environment.workspace_id.to_string(),
        }),
    )
}

fn load_environment(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    environment_id: EnvironmentId,
) -> Result<Environment, EnvironmentError> {
    let config_version: Option<i64> = transaction
        .query_row(
            "SELECT MAX(config_version) FROM environment_versions WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?
        .flatten();
    let config_version = config_version.ok_or(EnvironmentError::NotFound)?;
    let config_version = u32::try_from(config_version).map_err(|_| {
        EnvironmentError::Integrity("invalid Environment configuration version".to_owned())
    })?;
    let mut environment = load_environment_version(
        transaction,
        workspace_id,
        environment_id.clone(),
        config_version,
    )?;
    let projected: Option<String> = transaction
        .query_row(
            "SELECT release_id FROM environment_current_releases WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
    let expected_current: Option<String> = transaction
        .query_row(
            "SELECT release_id FROM releases WHERE environment_id = ?1
             ORDER BY release_sequence DESC LIMIT 1",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
    if projected != expected_current {
        return Err(EnvironmentError::Integrity(
            "Environment current Release projection is not reproducible".to_owned(),
        ));
    }
    let current_release_id = projected
        .map(|value| value.parse::<ReleaseId>())
        .transpose()
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    if let Some(release_id) = current_release_id {
        let api_version: String = transaction
            .query_row(
                "SELECT api_version FROM releases WHERE release_id = ?1",
                [release_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
        let verified_environment = match api_version.as_str() {
            proof_application::RELEASE_V1_API_VERSION => {
                load_release_record(transaction, workspace_id, release_id)
                    .map(|release| release.environment_id)
            }
            LOCALIZED_RELEASE_API_VERSION => {
                localized::load_localized_release_chain_node(transaction, workspace_id, release_id)
                    .map(|(_, release_environment, _)| release_environment)
            }
            _ => Err(LocalPortError::UnsupportedVersion),
        }
        .map_err(|error| match error {
            LocalPortError::Storage(detail) => EnvironmentError::Storage(detail),
            LocalPortError::Integrity(detail) => EnvironmentError::Integrity(detail),
            LocalPortError::NotFound => EnvironmentError::Integrity(
                "Environment current Release record is missing".to_owned(),
            ),
            other => EnvironmentError::Integrity(format!(
                "Environment current Release failed verification: {other:?}"
            )),
        })?;
        if verified_environment != environment_id {
            return Err(EnvironmentError::Integrity(
                "Environment current Release belongs to another Environment".to_owned(),
            ));
        }
    }
    environment.current_release_id = current_release_id;
    Ok(environment)
}

#[expect(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "Environment loading reconstructs canonical policy evidence"
)]
fn load_environment_version(
    connection: &Connection,
    workspace_id: WorkspaceId,
    environment_id: EnvironmentId,
    requested_config_version: u32,
) -> Result<Environment, EnvironmentError> {
    let persisted: Option<(
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = connection
        .query_row(
            "SELECT e.workspace_id, e.created_by_principal_id, e.created_at,
                    v.config_version, v.target_kind, v.policy_profile, v.required_approval,
                    v.policy_json, v.policy_digest, v.manifest_json, v.config_digest,
                    v.created_by_principal_id, v.created_at
             FROM environments e
             JOIN environment_versions v ON v.environment_id = e.environment_id
             WHERE e.environment_id = ?1 AND v.config_version = ?2",
            (environment_id.as_str(), requested_config_version),
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                ))
            },
        )
        .optional()
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
    let Some((
        persisted_workspace,
        parent_principal_id,
        parent_created_at,
        config_version,
        target_kind,
        policy_profile,
        required_approval,
        policy_json,
        policy_digest,
        manifest_json,
        config_digest,
        principal_id,
        created_at,
    )) = persisted
    else {
        return Err(EnvironmentError::NotFound);
    };
    if persisted_workspace != workspace_id.to_string()
        || u32::try_from(config_version).ok() != Some(requested_config_version)
        || parent_principal_id != principal_id
        || parent_created_at != created_at
    {
        return Err(EnvironmentError::Integrity(
            "Environment identity, Workspace, version, or creation provenance is invalid"
                .to_owned(),
        ));
    }
    let required_approval = ApprovalName::new(required_approval)
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let policy_value = parse_strict(policy_json.as_bytes())
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let policy = canonicalize(&policy_value)
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let expected_policy = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release-policy/v1",
        "profile": policy_profile,
        "require_approved_changesets": true,
        "require_signed_proof": true,
        "required_approval": required_approval.as_str(),
    }))
    .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let expected_policy_digest = digest(ArtifactKind::PolicyBundleV1, &expected_policy);
    let manifest_value = parse_strict(manifest_json.as_bytes())
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let manifest = canonicalize(&manifest_value)
        .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let expected_manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/environment/v1",
        "config_version": requested_config_version,
        "environment_id": environment_id.as_str(),
        "policy_digest": expected_policy_digest.to_string(),
        "policy_profile": policy_profile,
        "required_approval": required_approval.as_str(),
        "target_kind": target_kind,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
    let expected_config_digest = digest(ArtifactKind::EnvironmentConfigV1, &expected_manifest);
    if policy.as_str() != policy_json
        || policy != expected_policy
        || policy_digest != expected_policy_digest.to_string()
        || manifest.as_str() != manifest_json
        || manifest != expected_manifest
        || config_digest != expected_config_digest.to_string()
    {
        return Err(EnvironmentError::Integrity(
            "persisted Environment does not match its canonical configuration".to_owned(),
        ));
    }
    let environment = Environment {
        environment_id,
        workspace_id,
        config_version: requested_config_version,
        target_kind,
        policy_profile,
        required_approval,
        config_manifest_json: manifest_json,
        config_digest: expected_config_digest,
        current_release_id: None,
        principal_id: principal_id
            .parse::<PrincipalId>()
            .map_err(|error| EnvironmentError::Integrity(error.to_string()))?,
        created_at: created_at
            .parse()
            .map_err(|error: proof_application::TimestampError| {
                EnvironmentError::Integrity(error.to_string())
            })?,
    };
    verify_environment_create_operations(connection, &environment, expected_policy_digest)?;
    Ok(environment)
}

fn verify_environment_create_operations(
    connection: &Connection,
    environment: &Environment,
    policy_digest: ContentDigest,
) -> Result<(), EnvironmentError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, principal_id, idempotency_key, request_digest, effect_digest
             FROM environment_create_operations
             WHERE environment_id = ?1
             ORDER BY workspace_id, principal_id, idempotency_key",
        )
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([environment.environment_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| EnvironmentError::Storage(error.to_string()))?;
    if rows.is_empty() {
        return Err(EnvironmentError::Integrity(
            "Environment create operation does not bind its immutable configuration".to_owned(),
        ));
    }
    for (workspace_id, principal_id, raw_key, request_digest, effect_digest) in rows {
        let idempotency_key = raw_key
            .parse::<IdempotencyKey>()
            .map_err(|error| EnvironmentError::Integrity(error.to_string()))?;
        let expected_effect_digest = environment_create_operation_effect_digest(
            environment.config_digest,
            idempotency_key,
            environment,
            policy_digest,
        )
        .map_err(EnvironmentError::Integrity)?;
        if idempotency_key.to_string() != raw_key
            || workspace_id != environment.workspace_id.to_string()
            || principal_id != environment.principal_id.to_string()
            || request_digest != environment.config_digest.to_string()
            || effect_digest != expected_effect_digest.to_string()
        {
            return Err(EnvironmentError::Integrity(
                "Environment create operation does not bind its immutable configuration".to_owned(),
            ));
        }
    }
    Ok(())
}

fn environment_from_latest(error: LatestSchemaError) -> EnvironmentError {
    match error {
        LatestSchemaError::Integrity(detail) => EnvironmentError::Integrity(detail),
        LatestSchemaError::Storage(detail) => EnvironmentError::Storage(detail),
    }
}

fn environment_from_initialization(error: WorkspaceInitializationError) -> EnvironmentError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => EnvironmentError::Unauthenticated,
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => EnvironmentError::Storage(detail),
        WorkspaceInitializationError::AlreadyExists => {
            EnvironmentError::Integrity("unexpected Workspace initialization conflict".to_owned())
        }
    }
}

fn environment_from_status(error: WorkspaceStatusError) -> EnvironmentError {
    match error {
        WorkspaceStatusError::Unauthenticated => EnvironmentError::Unauthenticated,
        WorkspaceStatusError::Integrity(detail) => EnvironmentError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => EnvironmentError::Storage(detail),
        WorkspaceStatusError::Incomplete => {
            EnvironmentError::Integrity("the selected Workspace has incomplete state".to_owned())
        }
    }
}

fn principal_registration_request_digest(
    workspace_id: WorkspaceId,
    created_by_principal_id: PrincipalId,
    display_name: &str,
) -> Result<ContentDigest, PrincipalError> {
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/principal-registration-request/v1",
        "created_by_principal_id": created_by_principal_id.to_string(),
        "display_name": display_name,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::PrincipalRegistrationV1, &request))
}

fn principal_create_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    principal: &AgentPrincipal,
    registration_digest: ContentDigest,
) -> Result<ContentDigest, String> {
    operation_effect_digest(
        "principal.create",
        request_digest,
        &serde_json::json!({
            "created_at": principal.created_at.to_string(),
            "created_by_principal_id": principal.created_by_principal_id.to_string(),
            "display_name": principal.display_name,
            "enabled": principal.enabled,
            "idempotency_key": idempotency_key.to_string(),
            "principal_id": principal.principal_id.to_string(),
            "principal_type": "agent",
            "registration_digest": registration_digest.to_string(),
            "workspace_id": principal.workspace_id.to_string(),
        }),
    )
}

#[expect(
    clippy::type_complexity,
    reason = "the row mirrors the complete immutable Principal registration evidence"
)]
fn load_agent_principal(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
) -> Result<AgentPrincipal, PrincipalError> {
    let row: Option<(
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
    )> = connection
        .query_row(
            "SELECT p.principal_type, p.identity_subject, p.enabled,
                    r.workspace_id, r.registered_by_principal_id, r.display_name,
                    r.registration_json, r.registration_digest, r.created_at
             FROM principals p
             JOIN principal_registrations r ON r.principal_id = p.principal_id
             WHERE p.principal_id = ?1",
            [principal_id.to_string()],
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
        .optional()
        .map_err(|error| PrincipalError::Storage(error.to_string()))?;
    let Some((
        principal_type,
        identity_subject,
        enabled,
        persisted_workspace,
        created_by,
        display_name,
        registration_json,
        registration_digest,
        created_at,
    )) = row
    else {
        return Err(PrincipalError::NotFound);
    };
    if principal_type != "agent"
        || identity_subject != format!("principal:{principal_id}")
        || persisted_workspace != workspace_id.to_string()
        || !matches!(enabled, 0 | 1)
    {
        return Err(PrincipalError::Integrity(
            "persisted Agent Principal identity is invalid".to_owned(),
        ));
    }
    if enabled == 0 {
        return Err(PrincipalError::Disabled);
    }
    let registration_value = parse_strict(registration_json.as_bytes())
        .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
    let registration = canonicalize(&registration_value)
        .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
    let expected = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/principal-registration/v1",
        "created_at": created_at,
        "created_by_principal_id": created_by,
        "display_name": display_name,
        "principal_id": principal_id.to_string(),
        "principal_type": "agent",
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
    let expected_digest = digest(ArtifactKind::PrincipalRegistrationV1, &expected);
    if registration.as_str() != registration_json
        || registration != expected
        || registration_digest != expected_digest.to_string()
    {
        return Err(PrincipalError::Integrity(
            "Agent Principal registration evidence does not reproduce".to_owned(),
        ));
    }
    let principal = AgentPrincipal {
        principal_id,
        workspace_id,
        display_name,
        created_by_principal_id: created_by
            .parse::<PrincipalId>()
            .map_err(|error| PrincipalError::Integrity(error.to_string()))?,
        created_at: created_at
            .parse()
            .map_err(|error: proof_application::TimestampError| {
                PrincipalError::Integrity(error.to_string())
            })?,
        enabled: true,
    };
    verify_principal_create_operation(connection, &principal, expected_digest)?;
    Ok(principal)
}

fn verify_principal_create_operation(
    connection: &Connection,
    principal: &AgentPrincipal,
    registration_digest: ContentDigest,
) -> Result<(), PrincipalError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, principal_id, idempotency_key, request_digest, effect_digest
             FROM principal_create_operations
             WHERE created_principal_id = ?1
             ORDER BY workspace_id, principal_id, idempotency_key",
        )
        .map_err(|error| PrincipalError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([principal.principal_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| PrincipalError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PrincipalError::Storage(error.to_string()))?;
    let expected_digest = principal_registration_request_digest(
        principal.workspace_id,
        principal.created_by_principal_id,
        &principal.display_name,
    )?;
    if rows.len() != 1 {
        return Err(PrincipalError::Integrity(
            "Principal create operation does not bind its registration effect".to_owned(),
        ));
    }
    let (workspace_id, creator_id, raw_key, request_digest, effect_digest) = &rows[0];
    let idempotency_key = raw_key
        .parse::<IdempotencyKey>()
        .map_err(|error| PrincipalError::Integrity(error.to_string()))?;
    let expected_effect_digest = principal_create_operation_effect_digest(
        expected_digest,
        idempotency_key,
        principal,
        registration_digest,
    )
    .map_err(PrincipalError::Integrity)?;
    if idempotency_key.to_string() != *raw_key
        || workspace_id != &principal.workspace_id.to_string()
        || creator_id != &principal.created_by_principal_id.to_string()
        || request_digest != &expected_digest.to_string()
        || effect_digest != &expected_effect_digest.to_string()
    {
        return Err(PrincipalError::Integrity(
            "Principal create operation does not bind its registration effect".to_owned(),
        ));
    }
    Ok(())
}

fn principal_from_latest(error: LatestSchemaError) -> PrincipalError {
    match error {
        LatestSchemaError::Integrity(detail) => PrincipalError::Integrity(detail),
        LatestSchemaError::Storage(detail) => PrincipalError::Storage(detail),
    }
}

fn principal_from_initialization(error: WorkspaceInitializationError) -> PrincipalError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => PrincipalError::Unauthenticated,
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => PrincipalError::Storage(detail),
        WorkspaceInitializationError::AlreadyExists => {
            PrincipalError::Integrity("unexpected Workspace initialization conflict".to_owned())
        }
    }
}

fn principal_from_status(error: WorkspaceStatusError) -> PrincipalError {
    match error {
        WorkspaceStatusError::Unauthenticated => PrincipalError::Unauthenticated,
        WorkspaceStatusError::Integrity(detail) => PrincipalError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => PrincipalError::Storage(detail),
        WorkspaceStatusError::Incomplete => {
            PrincipalError::Integrity("the selected Workspace has incomplete state".to_owned())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LocalPortError {
    Unauthenticated,
    UnsupportedVersion,
    Denied,
    NotFound,
    Invalid,
    IntentMismatch,
    SourceConflict,
    TargetConflict,
    DuplicateActiveTarget,
    InvalidSupersession,
    InvalidRepairEvidence,
    NotDraft,
    NotReady,
    NotSubmitted,
    NotApproved,
    EvidenceMissing,
    LimitExceeded,
    Expired,
    IdempotencyKeyReused,
    PolicyDenied,
    InvalidRollbackTarget,
    StateConflict,
    Signing(String),
    Integrity(String),
    Storage(String),
}

fn require_v1_authoring_profile(connection: &Connection) -> Result<(), LocalPortError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if schema_version < 11 {
        return Ok(());
    }
    let api_version: String = connection
        .query_row(
            "SELECT api_version FROM known_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    match api_version.as_str() {
        KNOWN_STATE_V1_API_VERSION => Ok(()),
        KNOWN_STATE_V2_API_VERSION => Err(LocalPortError::UnsupportedVersion),
        _ => Err(LocalPortError::Integrity(
            "Known State has an unsupported API version".to_owned(),
        )),
    }
}

impl LocalWorkspace {
    fn with_latest_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>, WorkspaceId, PrincipalId) -> Result<T, LocalPortError>,
    ) -> Result<T, LocalPortError> {
        let config = self.read_config().map_err(local_port_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| LocalPortError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(local_port_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(LocalPortError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(local_port_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(local_port_from_latest)?;
        let result = operation(&transaction, workspace_id, principal_id)?;
        transaction
            .commit()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        Ok(result)
    }

    fn load_or_create_release_signer(
        &self,
        candidate_release_id: ReleaseId,
    ) -> Result<Ed25519SigningProvider, LocalPortError> {
        let path = self.root.join(RELEASE_SIGNING_KEY_RELATIVE_PATH);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => read_release_signer(&path, &metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let provider = Ed25519SigningProvider::generate()
                    .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                let mut secret = provider.secret_bytes();
                let temporary =
                    path.with_file_name(format!(".release-signing-{candidate_release_id}.tmp"));
                remove_stale_regular_file(&temporary, "Release signing-key temporary file")?;
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = match options.open(&temporary) {
                    Ok(file) => file,
                    Err(error) => {
                        secret.zeroize();
                        return Err(LocalPortError::Signing(error.to_string()));
                    }
                };
                let write_result = file.write_all(&secret).and_then(|()| file.sync_all());
                secret.zeroize();
                if let Err(error) = write_result {
                    drop(file);
                    let _ = fs::remove_file(&temporary);
                    return Err(LocalPortError::Signing(error.to_string()));
                }
                drop(file);
                match fs::hard_link(&temporary, &path) {
                    Ok(()) => {
                        fs::remove_file(&temporary)
                            .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                        sync_parent_directory(&path)
                            .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        fs::remove_file(&temporary)
                            .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                        let metadata = fs::symlink_metadata(&path)
                            .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                        return read_release_signer(&path, &metadata);
                    }
                    Err(error) => {
                        let _ = fs::remove_file(&temporary);
                        return Err(LocalPortError::Signing(error.to_string()));
                    }
                }
                let metadata = fs::symlink_metadata(&path)
                    .map_err(|error| LocalPortError::Signing(error.to_string()))?;
                validate_private_key_metadata(&metadata)?;
                Ok(provider)
            }
            Err(error) => Err(LocalPortError::Signing(error.to_string())),
        }
    }

    fn preflight_release_proof_export(&self, proof_id: ProofId) -> Result<(), LocalPortError> {
        let proofs = self.release_proof_directory()?;
        validate_optional_regular_file(
            &proofs.join(format!("{proof_id}.dsse.json")),
            "Release Proof artifact",
        )?;
        remove_stale_regular_file(
            &proofs.join(format!(".{proof_id}.dsse.tmp")),
            "Release Proof temporary artifact",
        )
    }

    fn materialize_release_proof(&self, release: &Release) -> Result<(), LocalPortError> {
        self.export_release_proof(release)?;
        let _ = self.acknowledge_release_proof_export(release.proof_id);
        Ok(())
    }

    fn acknowledge_release_proof_export(&self, proof_id: ProofId) -> Result<(), LocalPortError> {
        self.with_latest_transaction(|transaction, _, _| {
            transaction
                .execute(
                    "DELETE FROM release_proof_export_outbox WHERE proof_id = ?1",
                    [proof_id.to_string()],
                )
                .map_err(|error| LocalPortError::Storage(error.to_string()))?;
            Ok(())
        })
    }

    fn release_proof_directory(&self) -> Result<PathBuf, LocalPortError> {
        let artifacts = self.root.join(ARTIFACTS_RELATIVE_PATH);
        let metadata = fs::symlink_metadata(&artifacts)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(LocalPortError::Integrity(
                "Workspace artifacts path is not a regular directory".to_owned(),
            ));
        }
        let proofs = artifacts.join("release-proofs");
        match fs::symlink_metadata(&proofs) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(LocalPortError::Integrity(
                        "Release Proof artifact path is not a regular directory".to_owned(),
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&proofs)
                    .map_err(|error| LocalPortError::Storage(error.to_string()))?;
                set_private_directory_permissions(&proofs)
                    .map_err(local_port_from_initialization)?;
            }
            Err(error) => return Err(LocalPortError::Storage(error.to_string())),
        }
        Ok(proofs)
    }

    fn export_release_proof(&self, release: &Release) -> Result<(), LocalPortError> {
        let proofs = self.release_proof_directory()?;
        let path = proofs.join(format!("{}.dsse.json", release.proof_id));
        let needs_write = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(LocalPortError::Integrity(
                        "Release Proof artifact is not a regular file".to_owned(),
                    ));
                }
                let persisted = fs::read_to_string(&path)
                    .map_err(|error| LocalPortError::Storage(error.to_string()))?;
                persisted != release.proof_envelope_json
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(LocalPortError::Storage(error.to_string())),
        };
        if !needs_write {
            return Ok(());
        }
        let temporary = proofs.join(format!(".{}.dsse.tmp", release.proof_id));
        remove_stale_regular_file(&temporary, "Release Proof temporary artifact")?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if let Err(error) = file
            .write_all(release.proof_envelope_json.as_bytes())
            .and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = fs::remove_file(&temporary);
            return Err(LocalPortError::Storage(error.to_string()));
        }
        drop(file);
        replace_derived_file(&temporary, &path)?;
        sync_parent_directory(&path).map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let persisted = fs::read_to_string(&path)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if persisted != release.proof_envelope_json {
            return Err(LocalPortError::Integrity(
                "repaired Release Proof artifact differs from verified storage".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_optional_regular_file(path: &Path, label: &str) -> Result<(), LocalPortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LocalPortError::Integrity(format!(
                    "{label} is not a regular file"
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalPortError::Storage(error.to_string())),
    }
}

fn remove_stale_regular_file(path: &Path, label: &str) -> Result<(), LocalPortError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LocalPortError::Integrity(format!(
                    "{label} is not a regular file"
                )));
            }
            fs::remove_file(path).map_err(|error| LocalPortError::Storage(error.to_string()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(LocalPortError::Storage(error.to_string())),
    }
}

#[cfg(unix)]
fn replace_derived_file(temporary: &Path, destination: &Path) -> Result<(), LocalPortError> {
    fs::rename(temporary, destination).map_err(|error| LocalPortError::Storage(error.to_string()))
}

#[cfg(not(unix))]
fn replace_derived_file(temporary: &Path, destination: &Path) -> Result<(), LocalPortError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LocalPortError::Integrity(
                    "Release Proof destination is not a regular file".to_owned(),
                ));
            }
            fs::remove_file(destination)
                .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(LocalPortError::Storage(error.to_string())),
    }
    fs::rename(temporary, destination).map_err(|error| LocalPortError::Storage(error.to_string()))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "platform-neutral atomic publication calls a fallible directory sync interface"
)]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn read_release_signer(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Ed25519SigningProvider, LocalPortError> {
    validate_private_key_metadata(metadata)?;
    let mut bytes = fs::read(path).map_err(|error| LocalPortError::Signing(error.to_string()))?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(LocalPortError::Signing(
            "local Release signing key must contain exactly 32 bytes".to_owned(),
        ));
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
    secret.zeroize();
    Ok(provider)
}

fn validate_private_key_metadata(metadata: &fs::Metadata) -> Result<(), LocalPortError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LocalPortError::Signing(
            "local Release signing key is not a regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(LocalPortError::Signing(
                "local Release signing key permissions must be 0600 or stricter".to_owned(),
            ));
        }
    }
    Ok(())
}

fn local_port_from_initialization(error: WorkspaceInitializationError) -> LocalPortError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => LocalPortError::Unauthenticated,
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => LocalPortError::Storage(detail),
        WorkspaceInitializationError::AlreadyExists => {
            LocalPortError::Integrity("unexpected Workspace initialization conflict".to_owned())
        }
    }
}

fn local_port_from_status(error: WorkspaceStatusError) -> LocalPortError {
    match error {
        WorkspaceStatusError::Unauthenticated => LocalPortError::Unauthenticated,
        WorkspaceStatusError::Integrity(detail) => LocalPortError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => LocalPortError::Storage(detail),
        WorkspaceStatusError::Incomplete => {
            LocalPortError::Integrity("the selected Workspace has incomplete state".to_owned())
        }
    }
}

fn local_port_from_latest(error: LatestSchemaError) -> LocalPortError {
    match error {
        LatestSchemaError::Integrity(detail) => LocalPortError::Integrity(detail),
        LatestSchemaError::Storage(detail) => LocalPortError::Storage(detail),
    }
}

impl LocalWorkspace {
    fn with_delegation_transaction<T>(
        &self,
        operation: impl FnOnce(&Transaction<'_>, WorkspaceId, PrincipalId) -> Result<T, DelegationError>,
    ) -> Result<T, DelegationError> {
        let config = self.read_config().map_err(delegation_from_initialization)?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let local_identity =
            current_local_identity().map_err(|_| DelegationError::Unauthenticated)?;
        let mut connection = self
            .open_database()
            .map_err(delegation_from_initialization)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        let (database_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| DelegationError::Storage(error.to_string()))?;
        if database_id != workspace_id.to_string() {
            return Err(DelegationError::Integrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(delegation_from_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(delegation_from_latest)?;
        let result = operation(&transaction, workspace_id, principal_id)?;
        transaction
            .commit()
            .map_err(|error| DelegationError::Storage(error.to_string()))?;
        Ok(result)
    }
}

fn load_original_delegation_grant(
    connection: &Connection,
    workspace_id: WorkspaceId,
    delegation_id: DelegationId,
) -> Result<Delegation, DelegationError> {
    let mut delegation = load_delegation(connection, workspace_id, delegation_id)?;
    delegation.revoked_by_principal_id = None;
    delegation.revoked_at = None;
    Ok(delegation)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the digest binds every normalized semantic grant field while intentionally excluding candidate identity and issuance time"
)]
fn delegation_grant_request_digest(
    workspace_id: WorkspaceId,
    issuer_principal_id: PrincipalId,
    recipient_principal_id: PrincipalId,
    actions: &[DelegatedAction],
    environment_ids: &[EnvironmentId],
    object_ids: &[ObjectId],
    constraints: &DelegationConstraints,
    not_before: Timestamp,
    expires_at: Timestamp,
) -> Result<ContentDigest, DelegationError> {
    let action_values = actions.iter().map(ToString::to_string).collect::<Vec<_>>();
    let environment_values = environment_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let object_values = object_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let request = canonicalize(&serde_json::json!({
        "actions": action_values,
        "api_version": "proof.dev/delegation-request/v1",
        "constraints": {
            "allow_subdelegation": constraints.allow_subdelegation,
            "max_context_bytes": constraints.max_context_bytes,
            "max_objects": constraints.max_objects,
        },
        "expires_at": expires_at.to_string(),
        "issuer_principal_id": issuer_principal_id.to_string(),
        "not_before": not_before.to_string(),
        "recipient_principal_id": recipient_principal_id.to_string(),
        "scope": {
            "environment_ids": environment_values,
            "object_ids": object_values,
            "workspace_id": workspace_id.to_string(),
        },
    }))
    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::DelegationV1, &request))
}

fn delegation_grant_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    delegation: &Delegation,
) -> Result<ContentDigest, String> {
    operation_effect_digest(
        "delegation.grant",
        request_digest,
        &serde_json::json!({
            "actions": delegation.actions.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "constraints": {
                "allow_subdelegation": delegation.constraints.allow_subdelegation,
                "max_context_bytes": delegation.constraints.max_context_bytes,
                "max_objects": delegation.constraints.max_objects,
            },
            "delegation_digest": delegation.delegation_digest.to_string(),
            "delegation_id": delegation.delegation_id.to_string(),
            "expires_at": delegation.expires_at.to_string(),
            "issued_at": delegation.issued_at.to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "issuer_principal_id": delegation.issuer_principal_id.to_string(),
            "not_before": delegation.not_before.to_string(),
            "recipient_principal_id": delegation.recipient_principal_id.to_string(),
            "revoked_at": serde_json::Value::Null,
            "revoked_by_principal_id": serde_json::Value::Null,
            "scope": {
                "environment_ids": delegation.scope.environment_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "object_ids": delegation.scope.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "workspace_id": delegation.scope.workspace_id.to_string(),
            },
            "workspace_id": delegation.workspace_id.to_string(),
        }),
    )
}

fn delegation_revoke_request_digest(
    workspace_id: WorkspaceId,
    delegation_id: DelegationId,
) -> Result<ContentDigest, DelegationError> {
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/delegation-revocation-request/v1",
        "delegation_id": delegation_id.to_string(),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::DelegationV1, &request))
}

fn delegation_revoke_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    operation_principal_id: PrincipalId,
    delegation: &Delegation,
    revocation_digest: ContentDigest,
) -> Result<ContentDigest, String> {
    let revoked_by_principal_id = delegation
        .revoked_by_principal_id
        .ok_or_else(|| "Delegation revocation Principal is missing".to_owned())?;
    let revoked_at = delegation
        .revoked_at
        .ok_or_else(|| "Delegation revocation time is missing".to_owned())?;
    operation_effect_digest(
        "delegation.revoke",
        request_digest,
        &serde_json::json!({
            "delegation_digest": delegation.delegation_digest.to_string(),
            "delegation_id": delegation.delegation_id.to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "principal_id": operation_principal_id.to_string(),
            "reason": "revoked",
            "revocation_digest": revocation_digest.to_string(),
            "revoked_at": revoked_at.to_string(),
            "revoked_by_principal_id": revoked_by_principal_id.to_string(),
            "workspace_id": delegation.workspace_id.to_string(),
        }),
    )
}

fn verify_delegation_grant_operation(
    connection: &Connection,
    delegation: &Delegation,
) -> Result<(), DelegationError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, principal_id, idempotency_key, request_digest, effect_digest
             FROM delegation_grant_operations
             WHERE delegation_id = ?1
             ORDER BY workspace_id, principal_id, idempotency_key",
        )
        .map_err(|error| DelegationError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([delegation.delegation_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| DelegationError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DelegationError::Storage(error.to_string()))?;
    let expected_digest = delegation_grant_request_digest(
        delegation.workspace_id,
        delegation.issuer_principal_id,
        delegation.recipient_principal_id,
        &delegation.actions,
        &delegation.scope.environment_ids,
        &delegation.scope.object_ids,
        &delegation.constraints,
        delegation.not_before,
        delegation.expires_at,
    )?;
    if rows.len() != 1 {
        return Err(DelegationError::Integrity(
            "Delegation grant operation does not bind its canonical grant effect".to_owned(),
        ));
    }
    let (workspace_id, issuer_id, raw_key, request_digest, effect_digest) = &rows[0];
    let idempotency_key = raw_key
        .parse::<IdempotencyKey>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let expected_effect_digest =
        delegation_grant_operation_effect_digest(expected_digest, idempotency_key, delegation)
            .map_err(DelegationError::Integrity)?;
    if idempotency_key.to_string() != *raw_key
        || workspace_id != &delegation.workspace_id.to_string()
        || issuer_id != &delegation.issuer_principal_id.to_string()
        || request_digest != &expected_digest.to_string()
        || effect_digest != &expected_effect_digest.to_string()
    {
        return Err(DelegationError::Integrity(
            "Delegation grant operation does not bind its canonical grant effect".to_owned(),
        ));
    }
    Ok(())
}

fn verify_delegation_revoke_operations(
    connection: &Connection,
    delegation: &Delegation,
    revocation_digest: Option<ContentDigest>,
) -> Result<(), DelegationError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, principal_id, idempotency_key, request_digest, effect_digest
             FROM delegation_revoke_operations
             WHERE delegation_id = ?1
             ORDER BY workspace_id, principal_id, idempotency_key",
        )
        .map_err(|error| DelegationError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([delegation.delegation_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| DelegationError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| DelegationError::Storage(error.to_string()))?;
    let Some(revocation_digest) = revocation_digest else {
        return if rows.is_empty() {
            Ok(())
        } else {
            Err(DelegationError::Integrity(
                "unrevoked Delegation has revoke operation evidence".to_owned(),
            ))
        };
    };
    if rows.is_empty() {
        return Err(DelegationError::Integrity(
            "revoked Delegation is missing revoke operation evidence".to_owned(),
        ));
    }
    let expected_request =
        delegation_revoke_request_digest(delegation.workspace_id, delegation.delegation_id)?;
    for (workspace_id, principal_id, raw_key, request_digest, effect_digest) in rows {
        let idempotency_key = raw_key
            .parse::<IdempotencyKey>()
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let operation_principal_id = principal_id
            .parse::<PrincipalId>()
            .map_err(|error| DelegationError::Integrity(error.to_string()))?;
        let expected_effect = delegation_revoke_operation_effect_digest(
            expected_request,
            idempotency_key,
            operation_principal_id,
            delegation,
            revocation_digest,
        )
        .map_err(DelegationError::Integrity)?;
        if idempotency_key.to_string() != raw_key
            || workspace_id != delegation.workspace_id.to_string()
            || principal_id != operation_principal_id.to_string()
            || request_digest != expected_request.to_string()
            || effect_digest != expected_effect.to_string()
        {
            return Err(DelegationError::Integrity(
                "Delegation revoke operation does not bind its canonical revocation effect"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "Delegation loading verifies every persisted constraint and its canonical evidence"
)]
fn load_delegation(
    connection: &Connection,
    workspace_id: WorkspaceId,
    delegation_id: DelegationId,
) -> Result<Delegation, DelegationError> {
    type DelegationRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<DelegationRow> = connection
        .query_row(
            "SELECT d.workspace_id, d.issuer_principal_id, d.recipient_principal_id,
                    d.actions_json, d.environment_ids_json, d.object_ids_json,
                    d.max_objects, d.max_context_bytes, d.allow_subdelegation,
                    d.not_before, d.expires_at, d.manifest_json, d.delegation_digest,
                    d.issued_at, r.revoked_by_principal_id, r.revoked_at,
                    r.revocation_json, r.revocation_digest
             FROM delegations d
             LEFT JOIN delegation_revocations r ON r.delegation_id = d.delegation_id
             WHERE d.delegation_id = ?1",
            [delegation_id.to_string()],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                ))
            },
        )
        .optional()
        .map_err(|error| DelegationError::Storage(error.to_string()))?;
    let Some((
        persisted_workspace,
        issuer,
        recipient,
        actions_json,
        environments_json,
        objects_json,
        max_objects,
        max_context_bytes,
        allow_subdelegation,
        not_before,
        expires_at,
        manifest_json,
        persisted_digest,
        issued_at,
        revoked_by,
        revoked_at,
        revocation_json,
        revocation_digest,
    )) = row
    else {
        return Err(DelegationError::NotFound);
    };
    if persisted_workspace != workspace_id.to_string() || allow_subdelegation != 0 {
        return Err(DelegationError::Integrity(
            "Delegation Workspace or subdelegation constraint is invalid".to_owned(),
        ));
    }
    let issuer_principal_id = issuer
        .parse::<PrincipalId>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let recipient_principal_id = recipient
        .parse::<PrincipalId>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    load_agent_principal(connection, workspace_id, recipient_principal_id).map_err(|error| {
        match error {
            PrincipalError::Storage(detail) => DelegationError::Storage(detail),
            PrincipalError::Integrity(detail) => DelegationError::Integrity(detail),
            _ => DelegationError::InvalidRecipient,
        }
    })?;
    let actions_value = parse_strict(actions_json.as_bytes())
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let environments_value = parse_strict(environments_json.as_bytes())
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let objects_value = parse_strict(objects_json.as_bytes())
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    if canonicalize(&actions_value)
        .map_err(|error| DelegationError::Integrity(error.to_string()))?
        .as_str()
        != actions_json
        || canonicalize(&environments_value)
            .map_err(|error| DelegationError::Integrity(error.to_string()))?
            .as_str()
            != environments_json
        || canonicalize(&objects_value)
            .map_err(|error| DelegationError::Integrity(error.to_string()))?
            .as_str()
            != objects_json
    {
        return Err(DelegationError::Integrity(
            "Delegation scopes are not canonical JSON".to_owned(),
        ));
    }
    let actions = actions_value
        .as_array()
        .ok_or_else(|| {
            DelegationError::Integrity("Delegation actions are not an array".to_owned())
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| {
                    DelegationError::Integrity("Delegation action is not a string".to_owned())
                })?
                .parse::<DelegatedAction>()
                .map_err(|error| DelegationError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment_ids = environments_value
        .as_array()
        .ok_or_else(|| {
            DelegationError::Integrity("Delegation Environments are not an array".to_owned())
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| {
                    DelegationError::Integrity("Environment identity is not a string".to_owned())
                })?
                .parse::<EnvironmentId>()
                .map_err(|error| DelegationError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let object_ids = objects_value
        .as_array()
        .ok_or_else(|| {
            DelegationError::Integrity("Delegation Objects are not an array".to_owned())
        })?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| {
                    DelegationError::Integrity("Object identity is not a string".to_owned())
                })?
                .parse::<ObjectId>()
                .map_err(|error| DelegationError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if actions.windows(2).any(|pair| pair[0] >= pair[1])
        || environment_ids.windows(2).any(|pair| pair[0] >= pair[1])
        || object_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(DelegationError::Integrity(
            "Delegation scopes are not sorted and unique".to_owned(),
        ));
    }
    let has_resource_action = actions.iter().any(|action| {
        matches!(
            action,
            DelegatedAction::ObjectQueryReleased | DelegatedAction::ContextBuild
        )
    });
    if (has_resource_action && (environment_ids.is_empty() || object_ids.is_empty()))
        || (!has_resource_action && (!environment_ids.is_empty() || !object_ids.is_empty()))
    {
        return Err(DelegationError::Integrity(
            "Delegation action and resource scope shape is invalid".to_owned(),
        ));
    }
    let max_objects = u32::try_from(max_objects)
        .map_err(|_| DelegationError::Integrity("invalid max_objects".to_owned()))?;
    let max_context_bytes = u64::try_from(max_context_bytes)
        .map_err(|_| DelegationError::Integrity("invalid max_context_bytes".to_owned()))?;
    let not_before = not_before
        .parse::<proof_application::Timestamp>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let expires_at = expires_at
        .parse::<proof_application::Timestamp>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let issued_at = issued_at
        .parse::<proof_application::Timestamp>()
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    if issued_at > not_before || not_before >= expires_at {
        return Err(DelegationError::Integrity(
            "Delegation time bounds are invalid".to_owned(),
        ));
    }
    let action_values = actions.iter().map(ToString::to_string).collect::<Vec<_>>();
    let environment_values = environment_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let object_values = object_ids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let expected = canonicalize(&serde_json::json!({
        "actions": action_values,
        "api_version": "proof.dev/delegation/v1",
        "constraints": {
            "allow_subdelegation": false,
            "max_context_bytes": max_context_bytes,
            "max_objects": max_objects,
        },
        "delegation_id": delegation_id.to_string(),
        "expires_at": expires_at.to_string(),
        "issued_at": issued_at.to_string(),
        "issuer_principal_id": issuer_principal_id.to_string(),
        "not_before": not_before.to_string(),
        "recipient_principal_id": recipient_principal_id.to_string(),
        "scope": {
            "environment_ids": environment_values,
            "object_ids": object_values,
            "workspace_id": workspace_id.to_string(),
        },
    }))
    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let manifest_value = parse_strict(manifest_json.as_bytes())
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let manifest = canonicalize(&manifest_value)
        .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    let expected_digest = digest(ArtifactKind::DelegationV1, &expected);
    if manifest.as_str() != manifest_json
        || manifest != expected
        || persisted_digest != expected_digest.to_string()
    {
        return Err(DelegationError::Integrity(
            "Delegation manifest or digest does not reproduce".to_owned(),
        ));
    }
    let (revoked_by_principal_id, revoked_at, verified_revocation_digest) =
        match (revoked_by, revoked_at, revocation_json, revocation_digest) {
            (None, None, None, None) => (None, None, None),
            (
                Some(revoked_by),
                Some(revoked_at),
                Some(revocation_json),
                Some(revocation_digest),
            ) => {
                let revoked_by_principal_id = revoked_by
                    .parse::<PrincipalId>()
                    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                let revoked_at = revoked_at
                    .parse::<proof_application::Timestamp>()
                    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                if revoked_at < issued_at {
                    return Err(DelegationError::Integrity(
                        "Delegation revocation predates issuance".to_owned(),
                    ));
                }
                let expected_revocation = canonicalize(&serde_json::json!({
                    "api_version": "proof.dev/delegation-revocation/v1",
                    "delegation_id": delegation_id.to_string(),
                    "reason": "revoked",
                    "revoked_at": revoked_at.to_string(),
                    "revoked_by_principal_id": revoked_by_principal_id.to_string(),
                    "workspace_id": workspace_id.to_string(),
                }))
                .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                let value = parse_strict(revocation_json.as_bytes())
                    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                let canonical = canonicalize(&value)
                    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
                let expected_revocation_digest =
                    digest(ArtifactKind::DelegationV1, &expected_revocation);
                if canonical.as_str() != revocation_json
                    || canonical != expected_revocation
                    || revocation_digest != expected_revocation_digest.to_string()
                {
                    return Err(DelegationError::Integrity(
                        "Delegation revocation evidence does not reproduce".to_owned(),
                    ));
                }
                (
                    Some(revoked_by_principal_id),
                    Some(revoked_at),
                    Some(expected_revocation_digest),
                )
            }
            _ => {
                return Err(DelegationError::Integrity(
                    "Delegation revocation evidence is incomplete".to_owned(),
                ));
            }
        };
    let delegation = Delegation {
        delegation_id,
        workspace_id,
        issuer_principal_id,
        recipient_principal_id,
        actions,
        scope: DelegationScope {
            workspace_id,
            environment_ids,
            object_ids,
        },
        constraints: DelegationConstraints {
            max_objects,
            max_context_bytes,
            allow_subdelegation: false,
        },
        not_before,
        expires_at,
        issued_at,
        delegation_digest: expected_digest,
        revoked_by_principal_id,
        revoked_at,
    };
    verify_delegation_grant_operation(connection, &delegation)?;
    verify_delegation_revoke_operations(connection, &delegation, verified_revocation_digest)?;
    Ok(delegation)
}

fn verify_delegation_record(
    connection: &Connection,
    workspace_id: WorkspaceId,
    command: &VerifyDelegationCommand,
) -> Result<DelegationVerification, DelegationError> {
    let delegation = load_delegation(connection, workspace_id, command.delegation_id)?;
    let resource_shape_valid = match command.action {
        DelegatedAction::WorkspaceStatus => {
            command.environment_id.is_none() && command.object_ids.is_empty()
        }
        DelegatedAction::ObjectQueryReleased | DelegatedAction::ContextBuild => {
            command.environment_id.is_some()
                && !command.object_ids.is_empty()
                && !command.object_ids.windows(2).any(|pair| pair[0] >= pair[1])
        }
    };
    if !resource_shape_valid {
        return Err(DelegationError::ScopeExceeded);
    }
    if delegation.recipient_principal_id != command.operating_principal_id {
        return Err(DelegationError::ScopeExceeded);
    }
    if command.evaluated_at < delegation.not_before {
        return Err(DelegationError::NotYetValid);
    }
    if command.evaluated_at >= delegation.expires_at {
        return Err(DelegationError::Expired);
    }
    if delegation
        .revoked_at
        .is_some_and(|revoked_at| revoked_at <= command.evaluated_at)
    {
        return Err(DelegationError::Revoked);
    }
    if !delegation.actions.contains(&command.action)
        || command
            .environment_id
            .as_ref()
            .is_some_and(|environment_id| {
                delegation
                    .scope
                    .environment_ids
                    .binary_search(environment_id)
                    .is_err()
            })
        || command.object_ids.iter().any(|object_id| {
            delegation
                .scope
                .object_ids
                .binary_search(object_id)
                .is_err()
        })
        || u32::try_from(command.object_ids.len())
            .map_or(true, |count| count > delegation.constraints.max_objects)
    {
        return Err(DelegationError::ScopeExceeded);
    }
    let decision = canonicalize(&serde_json::json!({
        "action": command.action.to_string(),
        "api_version": "proof.dev/authorization-decision/v1",
        "authorized": true,
        "delegation_digest": delegation.delegation_digest.to_string(),
        "delegation_id": delegation.delegation_id.to_string(),
        "environment_id": command.environment_id.as_ref().map(ToString::to_string),
        "evaluated_at": command.evaluated_at.to_string(),
        "object_ids": command.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "operating_principal_id": command.operating_principal_id.to_string(),
        "policy_profile": LOCAL_AUTHORITY_POLICY_PROFILE,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| DelegationError::Integrity(error.to_string()))?;
    Ok(DelegationVerification {
        delegation_id: delegation.delegation_id,
        operating_principal_id: command.operating_principal_id,
        action: command.action,
        authorized: true,
        denial_code: None,
        policy_profile: LOCAL_AUTHORITY_POLICY_PROFILE.to_owned(),
        decision_digest: digest(ArtifactKind::AuthorizationDecisionV1, &decision),
        evaluated_at: command.evaluated_at,
    })
}

struct ReleasedSource {
    release_id: ReleaseId,
    released_at: Timestamp,
    edition: Edition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReleasedSchema {
    schema_id: SchemaId,
    schema_version: SchemaVersion,
    canonical_document: String,
    document_digest: ContentDigest,
}

fn query_released_objects_transaction(
    connection: &Connection,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    command: &QueryReleasedObjectsCommand,
) -> Result<ReleasedObjectQuery, LocalPortError> {
    let mut normalized = command.clone();
    let unique_count = normalized.object_ids.iter().collect::<BTreeSet<_>>().len();
    if command.operating_principal_id.is_some() != command.delegation_id.is_some()
        || command.object_ids.is_empty()
        || command.object_ids.len() > MAX_DELEGATION_OBJECTS
        || unique_count != command.object_ids.len()
    {
        return Err(LocalPortError::Invalid);
    }
    normalized.object_ids.sort();
    let command = &normalized;
    let (principal_id, delegation_id, authorization_decision_digest) = match (
        command.operating_principal_id,
        command.delegation_id,
    ) {
        (Some(operating_principal_id), Some(delegation_id)) => {
            let verification = verify_delegation_record(
                connection,
                workspace_id,
                &VerifyDelegationCommand {
                    delegation_id,
                    operating_principal_id,
                    action: DelegatedAction::ObjectQueryReleased,
                    environment_id: Some(command.environment_id.clone()),
                    object_ids: command.object_ids.clone(),
                    evaluated_at: command.evaluated_at,
                },
            )
            .map_err(local_port_from_delegation)?;
            (
                operating_principal_id,
                Some(delegation_id),
                verification.decision_digest,
            )
        }
        (None, None) => {
            let decision = canonicalize(&serde_json::json!({
                    "action": DelegatedAction::ObjectQueryReleased.to_string(),
                    "api_version": "proof.dev/authorization-decision/v1",
                    "authorized": true,
                    "delegation_id": serde_json::Value::Null,
                    "environment_id": command.environment_id.as_str(),
                    "evaluated_at": command.evaluated_at.to_string(),
                    "object_ids": command.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "operating_principal_id": requesting_principal_id.to_string(),
                    "policy_profile": "proof.local/bootstrap-human/v1",
                    "workspace_id": workspace_id.to_string(),
                }))
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            (
                requesting_principal_id,
                None,
                digest(ArtifactKind::AuthorizationDecisionV1, &decision),
            )
        }
        _ => return Err(LocalPortError::Invalid),
    };
    let source = load_released_source(connection, workspace_id, &command.environment_id)?;
    if command.evaluated_at < source.released_at {
        return Err(LocalPortError::Denied);
    }
    let objects = load_exact_released_objects(connection, &source.edition, &command.object_ids)?;
    Ok(ReleasedObjectQuery {
        workspace_id,
        environment_id: command.environment_id.clone(),
        release_id: source.release_id,
        edition_id: source.edition.edition_id,
        principal_id,
        delegation_id,
        authorization_decision_digest,
        objects,
    })
}

fn load_released_source(
    connection: &Connection,
    workspace_id: WorkspaceId,
    environment_id: &EnvironmentId,
) -> Result<ReleasedSource, LocalPortError> {
    let pointer: Option<(String, i64)> = connection
        .query_row(
            "SELECT release_id, release_sequence FROM environment_current_releases
             WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((raw_release_id, pointer_sequence)) = pointer else {
        return Err(LocalPortError::NotFound);
    };
    let release_id = raw_release_id
        .parse::<ReleaseId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if release_id.to_string() != raw_release_id {
        return Err(LocalPortError::Integrity(
            "Environment pointer contains a non-canonical Release identity".to_owned(),
        ));
    }
    let latest: Option<(String, i64)> = connection
        .query_row(
            "SELECT release_id, release_sequence FROM releases
             WHERE environment_id = ?1 ORDER BY release_sequence DESC LIMIT 1",
            [environment_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if latest.as_ref() != Some(&(raw_release_id.clone(), pointer_sequence)) {
        return Err(LocalPortError::Integrity(
            "Environment current Release projection does not match immutable history".to_owned(),
        ));
    }
    let release = load_release_record(connection, workspace_id, release_id)?;
    if release.environment_id != *environment_id
        || i64::try_from(release.release_sequence).ok() != Some(pointer_sequence)
    {
        return Err(LocalPortError::Integrity(
            "released source scope differs from the verified current Release".to_owned(),
        ));
    }
    let edition = load_edition(connection, release.edition_id).map_err(local_port_from_edition)?;
    Ok(ReleasedSource {
        release_id,
        released_at: release.released_at,
        edition,
    })
}

fn load_exact_released_objects(
    connection: &Connection,
    edition: &Edition,
    object_ids: &[ObjectId],
) -> Result<Vec<ReleasedObject>, LocalPortError> {
    let mut objects = Vec::with_capacity(object_ids.len());
    for object_id in object_ids {
        let Some(reference) = edition
            .objects
            .iter()
            .find(|candidate| candidate.object_id == *object_id)
        else {
            return Err(LocalPortError::NotFound);
        };
        let row: Option<(i64, String, i64, String, String, String)> = connection
            .query_row(
                "SELECT revision, schema_id, schema_version, lifecycle_state,
                        content_json, object_digest
                 FROM object_revisions
                 WHERE object_id = ?1 AND revision = ?2 AND authoritative_sequence <= ?3",
                (
                    object_id.to_string(),
                    reference.revision.get(),
                    i64::try_from(edition.authoritative_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "Edition authoritative sequence exceeds local storage range".to_owned(),
                        )
                    })?,
                ),
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
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let Some((
            revision,
            schema_id,
            schema_version,
            lifecycle_state,
            content_json,
            stored_digest,
        )) = row
        else {
            return Err(LocalPortError::NotFound);
        };
        let revision = ObjectRevision::new(u32::try_from(revision).map_err(|_| {
            LocalPortError::Integrity("invalid released Object revision".to_owned())
        })?)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_id = SchemaId::new(schema_id)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_version = SchemaVersion::new(u32::try_from(schema_version).map_err(|_| {
            LocalPortError::Integrity("invalid released Object Schema version".to_owned())
        })?)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if lifecycle_state != "active" {
            return Err(LocalPortError::Integrity(
                "released Object has an unsupported lifecycle state".to_owned(),
            ));
        }
        let value = parse_strict(content_json.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let canonical_content =
            canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let object_digest = stored_digest
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let reproduced =
            object_revision_digest(object_id.to_owned(), &schema_id, schema_version, &value)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if canonical_content.as_str() != content_json
            || object_digest != reproduced
            || reference.revision != revision
            || reference.schema_id != schema_id
            || reference.schema_version != schema_version
            || reference.lifecycle_state != ObjectLifecycleState::Active
            || reference.object_digest != object_digest
        {
            return Err(LocalPortError::Integrity(
                "released Object does not match its immutable Edition reference".to_owned(),
            ));
        }
        objects.push(ReleasedObject {
            object_id: object_id.to_owned(),
            revision,
            schema_id,
            schema_version,
            lifecycle_state: ObjectLifecycleState::Active,
            canonical_content: canonical_content.as_str().to_owned(),
            object_digest,
        });
    }
    Ok(objects)
}

fn load_exact_released_schemas(
    connection: &Connection,
    edition: &Edition,
    objects: &[ReleasedObject],
) -> Result<Vec<ReleasedSchema>, LocalPortError> {
    let keys = objects
        .iter()
        .map(|object| {
            (
                object.schema_id.as_str().to_owned(),
                object.schema_version.get(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut schemas = Vec::with_capacity(keys.len());
    for (raw_schema_id, raw_schema_version) in keys {
        let schema_id = SchemaId::new(raw_schema_id.clone())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_version = SchemaVersion::new(raw_schema_version)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let Some(reference) = edition.schemas.iter().find(|candidate| {
            candidate.schema_id == schema_id && candidate.schema_version == schema_version
        }) else {
            return Err(LocalPortError::Integrity(
                "released Object Schema is absent from its Edition".to_owned(),
            ));
        };
        let row: Option<(String, String, i64)> = connection
            .query_row(
                "SELECT document_json, document_digest, authoritative_sequence
                 FROM schema_versions WHERE schema_id = ?1 AND schema_version = ?2",
                (raw_schema_id, raw_schema_version),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let Some((document_json, persisted_digest, sequence)) = row else {
            return Err(LocalPortError::NotFound);
        };
        if u64::try_from(sequence)
            .map_or(true, |sequence| sequence > edition.authoritative_sequence)
        {
            return Err(LocalPortError::Integrity(
                "released Schema lies beyond its Edition boundary".to_owned(),
            ));
        }
        let value = parse_strict(document_json.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let canonical =
            canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let document_digest = persisted_digest
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if canonical.as_str() != document_json
            || digest(ArtifactKind::SchemaVersionV1, &canonical) != document_digest
            || reference.document_digest != document_digest
        {
            return Err(LocalPortError::Integrity(
                "released Schema does not match its immutable Edition reference".to_owned(),
            ));
        }
        schemas.push(ReleasedSchema {
            schema_id,
            schema_version,
            canonical_document: document_json,
            document_digest,
        });
    }
    Ok(schemas)
}

fn local_port_from_delegation(error: DelegationError) -> LocalPortError {
    match error {
        DelegationError::Unauthenticated => LocalPortError::Unauthenticated,
        DelegationError::NotFound => LocalPortError::NotFound,
        DelegationError::Storage(detail) => LocalPortError::Storage(detail),
        DelegationError::Integrity(detail) => LocalPortError::Integrity(detail),
        DelegationError::Expired => LocalPortError::Expired,
        _ => LocalPortError::Denied,
    }
}

fn local_port_from_edition(error: CreateEditionError) -> LocalPortError {
    match error {
        CreateEditionError::Unauthenticated => LocalPortError::Unauthenticated,
        CreateEditionError::UnsupportedVersion => LocalPortError::UnsupportedVersion,
        CreateEditionError::Storage(detail) => LocalPortError::Storage(detail),
        CreateEditionError::Integrity(detail) => LocalPortError::Integrity(detail),
        CreateEditionError::EmptyState => LocalPortError::NotFound,
        CreateEditionError::IdempotencyKeyReused => LocalPortError::Integrity(
            "unexpected Edition idempotency conflict while loading released state".to_owned(),
        ),
    }
}

fn query_from_local_port(error: LocalPortError) -> QueryReleasedObjectsError {
    match error {
        LocalPortError::Unauthenticated => QueryReleasedObjectsError::Unauthenticated,
        LocalPortError::UnsupportedVersion => QueryReleasedObjectsError::UnsupportedVersion,
        LocalPortError::Denied | LocalPortError::Expired => QueryReleasedObjectsError::Denied,
        LocalPortError::Invalid | LocalPortError::LimitExceeded => {
            QueryReleasedObjectsError::InvalidQuery
        }
        LocalPortError::NotFound => QueryReleasedObjectsError::NotFound,
        LocalPortError::Storage(detail) => QueryReleasedObjectsError::Storage(detail),
        LocalPortError::Integrity(detail) => QueryReleasedObjectsError::Integrity(detail),
        other => QueryReleasedObjectsError::Integrity(format!(
            "unexpected released-query adapter state: {other:?}"
        )),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContextPackLimits {
    max_bytes: u64,
    max_objects: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredContextPackManifest {
    api_version: String,
    authorization_decision_digest: String,
    base_state: String,
    built_at: String,
    capabilities: Vec<String>,
    context_pack_id: String,
    delegation_id: String,
    edition_id: String,
    environment_id: String,
    expires_at: String,
    intent: String,
    limits: StoredContextPackLimits,
    objects: Vec<serde_json::Value>,
    operating_principal_id: String,
    release_id: String,
    requesting_principal_id: String,
    schemas: Vec<serde_json::Value>,
    task_id: String,
    workspace_id: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "ContextPack construction intersects authority, loads exact Release content, budgets, and persists evidence atomically"
)]
fn build_context_pack_transaction(
    connection: &Connection,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    command: &BuildContextPackCommand,
) -> Result<ContextPack, LocalPortError> {
    verify_context_pack_operation_scope(connection, workspace_id)?;
    let delegation = load_delegation(connection, workspace_id, command.delegation_id)
        .map_err(local_port_from_delegation)?;
    if command.expires_at > delegation.expires_at {
        return Err(LocalPortError::LimitExceeded);
    }
    let limits = ContextPackLimits {
        max_objects: command
            .limits
            .max_objects
            .min(delegation.constraints.max_objects),
        max_bytes: command
            .limits
            .max_bytes
            .min(delegation.constraints.max_context_bytes),
    };
    if u32::try_from(command.object_ids.len()).map_or(true, |count| count > limits.max_objects) {
        return Err(LocalPortError::LimitExceeded);
    }
    let request_digest = context_pack_request_digest(
        workspace_id,
        requesting_principal_id,
        command.operating_principal_id,
        command.delegation_id,
        &command.task_id,
        &command.intent,
        &command.environment_id,
        &command.object_ids,
        limits,
        command.expires_at,
    )?;
    let replay: Option<(String, String)> = connection
        .query_row(
            "SELECT request_digest, context_pack_id
             FROM context_pack_build_operations
             WHERE workspace_id = ?1 AND requesting_principal_id = ?2
                   AND operating_principal_id = ?3 AND idempotency_key = ?4",
            (
                workspace_id.to_string(),
                requesting_principal_id.to_string(),
                command.operating_principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if let Some((persisted_request, context_pack_id)) = replay {
        let context_pack_id = context_pack_id
            .parse::<ContextPackId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let context_pack = load_context_pack_record(connection, workspace_id, context_pack_id)?;
        if persisted_request != request_digest.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(context_pack);
    }
    if command.built_at >= command.expires_at {
        return Err(LocalPortError::LimitExceeded);
    }
    let authorization = verify_delegation_record(
        connection,
        workspace_id,
        &VerifyDelegationCommand {
            delegation_id: command.delegation_id,
            operating_principal_id: command.operating_principal_id,
            action: DelegatedAction::ContextBuild,
            environment_id: Some(command.environment_id.clone()),
            object_ids: command.object_ids.clone(),
            evaluated_at: command.built_at,
        },
    )
    .map_err(local_port_from_delegation)?;
    let candidate_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM context_packs WHERE context_pack_id = ?1)",
            [command.context_pack_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if candidate_exists {
        return Err(LocalPortError::Integrity(
            "candidate ContextPack identity already exists".to_owned(),
        ));
    }
    let source = load_released_source(connection, workspace_id, &command.environment_id)?;
    if command.built_at < source.released_at {
        return Err(LocalPortError::Denied);
    }
    let objects = load_exact_released_objects(connection, &source.edition, &command.object_ids)?;
    let schemas = load_exact_released_schemas(connection, &source.edition, &objects)?;
    let capabilities = delegated_capability_versions(&delegation);
    let manifest = context_pack_manifest(
        command.context_pack_id,
        workspace_id,
        requesting_principal_id,
        command.operating_principal_id,
        command.delegation_id,
        &command.task_id,
        &command.intent,
        &command.environment_id,
        source.release_id,
        source.edition.edition_id,
        source.edition.state_digest,
        &schemas,
        &objects,
        limits,
        command.built_at,
        command.expires_at,
        &capabilities,
        authorization.decision_digest,
    )?;
    if u64::try_from(manifest.as_str().len()).map_or(true, |length| length > limits.max_bytes) {
        return Err(LocalPortError::LimitExceeded);
    }
    let context_pack_digest = digest(ArtifactKind::ContextPackV1, &manifest);
    let object_ids_json = canonicalize(&serde_json::json!(
        command
            .object_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    ))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    connection
        .execute(
            "INSERT INTO context_packs (
                 context_pack_id, workspace_id, requesting_principal_id,
                 operating_principal_id, delegation_id, environment_id, release_id,
                 edition_id, object_ids_json, manifest_json, context_pack_digest,
                 created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            (
                command.context_pack_id.to_string(),
                workspace_id.to_string(),
                requesting_principal_id.to_string(),
                command.operating_principal_id.to_string(),
                command.delegation_id.to_string(),
                command.environment_id.as_str(),
                source.release_id.to_string(),
                source.edition.edition_id.to_string(),
                object_ids_json.as_str(),
                manifest.as_str(),
                context_pack_digest.to_string(),
                command.built_at.to_string(),
                command.expires_at.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let context_pack = ContextPack {
        context_pack_id: command.context_pack_id,
        workspace_id,
        requesting_principal_id,
        operating_principal_id: command.operating_principal_id,
        delegation_id: command.delegation_id,
        task_id: command.task_id.clone(),
        intent: command.intent.clone(),
        environment_id: command.environment_id.clone(),
        release_id: source.release_id,
        edition_id: source.edition.edition_id,
        base_state: source.edition.state_digest,
        object_ids: command.object_ids.clone(),
        limits,
        built_at: command.built_at,
        expires_at: command.expires_at,
        capabilities,
        manifest_json: manifest.as_str().to_owned(),
        context_pack_digest,
    };
    let effect_digest = context_pack_build_operation_effect_digest(
        request_digest,
        command.idempotency_key,
        &context_pack,
    )
    .map_err(LocalPortError::Integrity)?;
    connection
        .execute(
            "INSERT INTO context_pack_build_operations (
                 workspace_id, requesting_principal_id, operating_principal_id,
                 idempotency_key, request_digest, effect_digest, context_pack_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                workspace_id.to_string(),
                requesting_principal_id.to_string(),
                command.operating_principal_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                command.context_pack_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    Ok(context_pack)
}

#[expect(
    clippy::too_many_arguments,
    reason = "the canonical request digest names every semantic idempotency input explicitly"
)]
fn context_pack_request_digest(
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    operating_principal_id: PrincipalId,
    delegation_id: DelegationId,
    task_id: &str,
    intent: &ChangeSetIntent,
    environment_id: &EnvironmentId,
    object_ids: &[ObjectId],
    limits: ContextPackLimits,
    expires_at: Timestamp,
) -> Result<ContentDigest, LocalPortError> {
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/context-pack-request/v1",
        "delegation_id": delegation_id.to_string(),
        "environment_id": environment_id.as_str(),
        "expires_at": expires_at.to_string(),
        "intent": intent.as_str(),
        "limits": {
            "max_bytes": limits.max_bytes,
            "max_objects": limits.max_objects,
        },
        "object_ids": object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "operating_principal_id": operating_principal_id.to_string(),
        "requesting_principal_id": requesting_principal_id.to_string(),
        "task_id": task_id,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::ContextPackV1, &request))
}

fn context_pack_build_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    context_pack: &ContextPack,
) -> Result<ContentDigest, String> {
    operation_effect_digest(
        "context-pack.build",
        request_digest,
        &serde_json::json!({
            "base_state": context_pack.base_state.to_string(),
            "built_at": context_pack.built_at.to_string(),
            "capabilities": context_pack.capabilities,
            "context_pack_digest": context_pack.context_pack_digest.to_string(),
            "context_pack_id": context_pack.context_pack_id.to_string(),
            "delegation_id": context_pack.delegation_id.to_string(),
            "edition_id": context_pack.edition_id.to_string(),
            "environment_id": context_pack.environment_id.as_str(),
            "expires_at": context_pack.expires_at.to_string(),
            "idempotency_key": idempotency_key.to_string(),
            "intent": context_pack.intent.as_str(),
            "limits": {
                "max_bytes": context_pack.limits.max_bytes,
                "max_objects": context_pack.limits.max_objects,
            },
            "object_ids": context_pack.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "operating_principal_id": context_pack.operating_principal_id.to_string(),
            "release_id": context_pack.release_id.to_string(),
            "requesting_principal_id": context_pack.requesting_principal_id.to_string(),
            "task_id": context_pack.task_id,
            "workspace_id": context_pack.workspace_id.to_string(),
        }),
    )
}

fn verify_context_pack_build_operation(
    connection: &Connection,
    context_pack: &ContextPack,
    request_digest: ContentDigest,
) -> Result<(), LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                    idempotency_key, request_digest, effect_digest
             FROM context_pack_build_operations
             WHERE context_pack_id = ?1
             ORDER BY workspace_id, requesting_principal_id, operating_principal_id,
                      idempotency_key",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([context_pack.context_pack_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if rows.len() != 1 {
        return Err(LocalPortError::Integrity(
            "ContextPack operation evidence does not reproduce".to_owned(),
        ));
    }
    let (workspace_id, requesting_id, operating_id, raw_key, persisted_request, persisted_effect) =
        &rows[0];
    let idempotency_key = raw_key
        .parse::<IdempotencyKey>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expected_effect =
        context_pack_build_operation_effect_digest(request_digest, idempotency_key, context_pack)
            .map_err(LocalPortError::Integrity)?;
    if idempotency_key.to_string() != *raw_key
        || workspace_id != &context_pack.workspace_id.to_string()
        || requesting_id != &context_pack.requesting_principal_id.to_string()
        || operating_id != &context_pack.operating_principal_id.to_string()
        || persisted_request != &request_digest.to_string()
        || persisted_effect != &expected_effect.to_string()
    {
        return Err(LocalPortError::Integrity(
            "ContextPack operation evidence does not reproduce".to_owned(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the ContextPack manifest binds every source, authority, and freshness field"
)]
fn context_pack_manifest(
    context_pack_id: ContextPackId,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    operating_principal_id: PrincipalId,
    delegation_id: DelegationId,
    task_id: &str,
    intent: &ChangeSetIntent,
    environment_id: &EnvironmentId,
    release_id: ReleaseId,
    edition_id: EditionId,
    base_state: ContentDigest,
    schemas: &[ReleasedSchema],
    objects: &[ReleasedObject],
    limits: ContextPackLimits,
    built_at: Timestamp,
    expires_at: Timestamp,
    capabilities: &[String],
    authorization_decision_digest: ContentDigest,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    let schema_values = schemas
        .iter()
        .map(|schema| {
            serde_json::json!({
                "canonical_document": schema.canonical_document,
                "document_digest": schema.document_digest.to_string(),
                "schema_id": schema.schema_id.as_str(),
                "schema_version": schema.schema_version.get(),
            })
        })
        .collect::<Vec<_>>();
    let object_values = objects
        .iter()
        .map(|object| {
            serde_json::json!({
                "canonical_content": object.canonical_content,
                "lifecycle_state": object.lifecycle_state.to_string(),
                "object_digest": object.object_digest.to_string(),
                "object_id": object.object_id.to_string(),
                "revision": object.revision.get(),
                "schema_id": object.schema_id.as_str(),
                "schema_version": object.schema_version.get(),
            })
        })
        .collect::<Vec<_>>();
    canonicalize(&serde_json::json!({
        "api_version": "proof.dev/context-pack/v1",
        "authorization_decision_digest": authorization_decision_digest.to_string(),
        "base_state": base_state.to_string(),
        "built_at": built_at.to_string(),
        "capabilities": capabilities,
        "context_pack_id": context_pack_id.to_string(),
        "delegation_id": delegation_id.to_string(),
        "edition_id": edition_id.to_string(),
        "environment_id": environment_id.as_str(),
        "expires_at": expires_at.to_string(),
        "intent": intent.as_str(),
        "limits": {
            "max_bytes": limits.max_bytes,
            "max_objects": limits.max_objects,
        },
        "objects": object_values,
        "operating_principal_id": operating_principal_id.to_string(),
        "release_id": release_id.to_string(),
        "requesting_principal_id": requesting_principal_id.to_string(),
        "schemas": schema_values,
        "task_id": task_id,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn delegated_capability_versions(delegation: &Delegation) -> Vec<String> {
    let mut versions = proof_application::capabilities()
        .iter()
        .filter(|capability| delegation.actions.contains(&capability.required_action))
        .map(|capability| capability.version.to_owned())
        .collect::<Vec<_>>();
    versions.sort();
    versions
}

fn authorize_context_pack_access(
    connection: &Connection,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    context_pack_id: ContextPackId,
    operating_principal_id: PrincipalId,
    delegation_id: DelegationId,
    observed_at: Timestamp,
) -> Result<(), LocalPortError> {
    let row: Option<(String, String, String, String, String, String)> = connection
        .query_row(
            "SELECT requesting_principal_id, operating_principal_id, delegation_id,
                    environment_id, object_ids_json, expires_at
             FROM context_packs WHERE context_pack_id = ?1 AND workspace_id = ?2",
            (context_pack_id.to_string(), workspace_id.to_string()),
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
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((requesting, operating, persisted_delegation, environment, object_ids, expires_at)) =
        row
    else {
        return Err(LocalPortError::NotFound);
    };
    if requesting != requesting_principal_id.to_string()
        || operating != operating_principal_id.to_string()
        || persisted_delegation != delegation_id.to_string()
    {
        return Err(LocalPortError::Denied);
    }
    let expires_at = expires_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if observed_at >= expires_at {
        return Err(LocalPortError::Expired);
    }
    let environment_id = environment
        .parse::<EnvironmentId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let object_ids = parse_object_id_array(&object_ids)?;
    verify_delegation_record(
        connection,
        workspace_id,
        &VerifyDelegationCommand {
            delegation_id,
            operating_principal_id,
            action: DelegatedAction::ContextBuild,
            environment_id: Some(environment_id),
            object_ids,
            evaluated_at: observed_at,
        },
    )
    .map_err(local_port_from_delegation)?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "ContextPack loading reconstructs canonical content, sources, authority, and operation evidence"
)]
fn load_context_pack_record(
    connection: &Connection,
    workspace_id: WorkspaceId,
    context_pack_id: ContextPackId,
) -> Result<ContextPack, LocalPortError> {
    type ContextPackRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let row: Option<ContextPackRow> = connection
        .query_row(
            "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                    delegation_id, environment_id, release_id, edition_id,
                    object_ids_json, manifest_json, context_pack_digest, created_at, expires_at
             FROM context_packs WHERE context_pack_id = ?1",
            [context_pack_id.to_string()],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((
        persisted_workspace,
        requesting,
        operating,
        raw_delegation,
        raw_environment,
        raw_release,
        raw_edition,
        object_ids_json,
        manifest_json,
        persisted_digest,
        created_at,
        expires_at,
    )) = row
    else {
        return Err(LocalPortError::NotFound);
    };
    if persisted_workspace != workspace_id.to_string() {
        return Err(LocalPortError::NotFound);
    }
    let requesting_principal_id = requesting
        .parse::<PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let operating_principal_id = operating
        .parse::<PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let delegation_id = raw_delegation
        .parse::<DelegationId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let environment_id = raw_environment
        .parse::<EnvironmentId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let release_id = raw_release
        .parse::<ReleaseId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let edition_id = raw_edition
        .parse::<EditionId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let built_at = created_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expires_at = expires_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let object_ids = parse_object_id_array(&object_ids_json)?;
    let manifest_value = parse_strict(manifest_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical_manifest = canonicalize(&manifest_value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical_manifest.as_str() != manifest_json {
        return Err(LocalPortError::Integrity(
            "ContextPack manifest is not canonical JSON".to_owned(),
        ));
    }
    let stored: StoredContextPackManifest = serde_json::from_value(manifest_value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let intent = ChangeSetIntent::new(stored.intent.clone())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let limits = ContextPackLimits {
        max_objects: stored.limits.max_objects,
        max_bytes: stored.limits.max_bytes,
    };
    let authorization_decision_digest = stored
        .authorization_decision_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if stored.api_version != "proof.dev/context-pack/v1"
        || stored.context_pack_id != context_pack_id.to_string()
        || stored.workspace_id != workspace_id.to_string()
        || stored.requesting_principal_id != requesting
        || stored.operating_principal_id != operating
        || stored.delegation_id != raw_delegation
        || stored.environment_id != raw_environment
        || stored.release_id != raw_release
        || stored.edition_id != raw_edition
        || stored.built_at != built_at.to_string()
        || stored.expires_at != expires_at.to_string()
        || stored.objects.len() != object_ids.len()
    {
        return Err(LocalPortError::Integrity(
            "ContextPack manifest differs from its indexed identity and source fields".to_owned(),
        ));
    }
    let delegation = load_delegation(connection, workspace_id, delegation_id)
        .map_err(local_port_from_delegation)?;
    if operating_principal_id != delegation.recipient_principal_id
        || !delegation.actions.contains(&DelegatedAction::ContextBuild)
        || built_at < delegation.not_before
        || built_at >= delegation.expires_at
        || expires_at > delegation.expires_at
        || delegation
            .scope
            .environment_ids
            .binary_search(&environment_id)
            .is_err()
        || object_ids
            .iter()
            .any(|id| delegation.scope.object_ids.binary_search(id).is_err())
        || u32::try_from(object_ids.len()).map_or(true, |count| {
            count > delegation.constraints.max_objects || count > limits.max_objects
        })
        || limits.max_objects > delegation.constraints.max_objects
        || limits.max_bytes > delegation.constraints.max_context_bytes
        || limits.max_bytes > MAX_CONTEXT_PACK_BYTES
    {
        return Err(LocalPortError::Integrity(
            "ContextPack exceeds its recorded Delegation or bounded limits".to_owned(),
        ));
    }
    let expected_decision = delegation_decision_digest(
        workspace_id,
        &delegation,
        operating_principal_id,
        DelegatedAction::ContextBuild,
        Some(&environment_id),
        &object_ids,
        built_at,
    )?;
    if expected_decision != authorization_decision_digest {
        return Err(LocalPortError::Integrity(
            "ContextPack authorization decision does not reproduce".to_owned(),
        ));
    }
    let source = load_release_source_by_id(connection, workspace_id, release_id)?;
    if built_at < source.released_at {
        return Err(LocalPortError::Integrity(
            "ContextPack predates its immutable Release source".to_owned(),
        ));
    }
    if source.edition.edition_id != edition_id
        || stored.base_state != source.edition.state_digest.to_string()
    {
        return Err(LocalPortError::Integrity(
            "ContextPack source Edition does not reproduce".to_owned(),
        ));
    }
    let objects = load_exact_released_objects(connection, &source.edition, &object_ids)?;
    let schemas = load_exact_released_schemas(connection, &source.edition, &objects)?;
    if stored.schemas.len() != schemas.len() {
        return Err(LocalPortError::Integrity(
            "ContextPack Schema set does not reproduce".to_owned(),
        ));
    }
    let capabilities = delegated_capability_versions(&delegation);
    if capabilities != stored.capabilities {
        return Err(LocalPortError::Integrity(
            "ContextPack capability boundary does not reproduce".to_owned(),
        ));
    }
    let expected = context_pack_manifest(
        context_pack_id,
        workspace_id,
        requesting_principal_id,
        operating_principal_id,
        delegation_id,
        &stored.task_id,
        &intent,
        &environment_id,
        release_id,
        edition_id,
        source.edition.state_digest,
        &schemas,
        &objects,
        limits,
        built_at,
        expires_at,
        &capabilities,
        authorization_decision_digest,
    )?;
    let context_pack_digest = digest(ArtifactKind::ContextPackV1, &expected);
    if expected.as_str() != manifest_json
        || context_pack_digest.to_string() != persisted_digest
        || u64::try_from(expected.as_str().len()).map_or(true, |length| length > limits.max_bytes)
    {
        return Err(LocalPortError::Integrity(
            "ContextPack canonical bytes or digest do not reproduce".to_owned(),
        ));
    }
    let expected_request = context_pack_request_digest(
        workspace_id,
        requesting_principal_id,
        operating_principal_id,
        delegation_id,
        &stored.task_id,
        &intent,
        &environment_id,
        &object_ids,
        limits,
        expires_at,
    )?;
    let context_pack = ContextPack {
        context_pack_id,
        workspace_id,
        requesting_principal_id,
        operating_principal_id,
        delegation_id,
        task_id: stored.task_id,
        intent,
        environment_id,
        release_id,
        edition_id,
        base_state: source.edition.state_digest,
        object_ids,
        limits,
        built_at,
        expires_at,
        capabilities,
        manifest_json,
        context_pack_digest,
    };
    verify_context_pack_build_operation(connection, &context_pack, expected_request)?;
    Ok(context_pack)
}

fn parse_object_id_array(json: &str) -> Result<Vec<ObjectId>, LocalPortError> {
    let value = parse_strict(json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical.as_str() != json {
        return Err(LocalPortError::Integrity(
            "Object scope is not canonical JSON".to_owned(),
        ));
    }
    let object_ids = value
        .as_array()
        .ok_or_else(|| LocalPortError::Integrity("Object scope is not an array".to_owned()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| LocalPortError::Integrity("Object identity is not text".to_owned()))?
                .parse::<ObjectId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if object_ids.is_empty()
        || object_ids.len() > MAX_DELEGATION_OBJECTS
        || object_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(LocalPortError::Integrity(
            "Object scope is empty, duplicated, unsorted, or over budget".to_owned(),
        ));
    }
    Ok(object_ids)
}

fn delegation_decision_digest(
    workspace_id: WorkspaceId,
    delegation: &Delegation,
    operating_principal_id: PrincipalId,
    action: DelegatedAction,
    environment_id: Option<&EnvironmentId>,
    object_ids: &[ObjectId],
    evaluated_at: Timestamp,
) -> Result<ContentDigest, LocalPortError> {
    let decision = canonicalize(&serde_json::json!({
        "action": action.to_string(),
        "api_version": "proof.dev/authorization-decision/v1",
        "authorized": true,
        "delegation_digest": delegation.delegation_digest.to_string(),
        "delegation_id": delegation.delegation_id.to_string(),
        "environment_id": environment_id.map(ToString::to_string),
        "evaluated_at": evaluated_at.to_string(),
        "object_ids": object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "operating_principal_id": operating_principal_id.to_string(),
        "policy_profile": LOCAL_AUTHORITY_POLICY_PROFILE,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::AuthorizationDecisionV1, &decision))
}

fn load_release_source_by_id(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: ReleaseId,
) -> Result<ReleasedSource, LocalPortError> {
    let release = load_release_record(connection, workspace_id, release_id)?;
    let edition = load_edition(connection, release.edition_id).map_err(local_port_from_edition)?;
    Ok(ReleasedSource {
        release_id,
        released_at: release.released_at,
        edition,
    })
}

fn context_from_local_port(error: LocalPortError) -> ContextPackError {
    match error {
        LocalPortError::Unauthenticated => ContextPackError::Unauthenticated,
        LocalPortError::Denied => ContextPackError::Denied,
        LocalPortError::NotFound => ContextPackError::NotFound,
        LocalPortError::Invalid | LocalPortError::LimitExceeded => ContextPackError::LimitExceeded,
        LocalPortError::Expired => ContextPackError::Expired,
        LocalPortError::IdempotencyKeyReused => ContextPackError::IdempotencyKeyReused,
        LocalPortError::Storage(detail) => ContextPackError::Storage(detail),
        LocalPortError::Integrity(detail) => ContextPackError::Integrity(detail),
        other => {
            ContextPackError::Integrity(format!("unexpected ContextPack adapter state: {other:?}"))
        }
    }
}

#[derive(Clone, Copy)]
enum ReleaseRequest<'a> {
    Promotion(&'a PromoteReleaseCommand),
    Rollback(&'a RollbackReleaseCommand),
}

impl ReleaseRequest<'_> {
    fn release_id(&self) -> ReleaseId {
        match self {
            Self::Promotion(command) => command.release_id,
            Self::Rollback(command) => command.release_id,
        }
    }

    fn proof_id(&self) -> ProofId {
        match self {
            Self::Promotion(command) => command.proof_id,
            Self::Rollback(command) => command.proof_id,
        }
    }

    fn environment_id(&self) -> &EnvironmentId {
        match self {
            Self::Promotion(command) => &command.environment_id,
            Self::Rollback(command) => &command.environment_id,
        }
    }

    fn idempotency_key(&self) -> IdempotencyKey {
        match self {
            Self::Promotion(command) => command.idempotency_key,
            Self::Rollback(command) => command.idempotency_key,
        }
    }

    fn released_at(&self) -> Timestamp {
        match self {
            Self::Promotion(command) => command.released_at,
            Self::Rollback(command) => command.released_at,
        }
    }

    const fn kind(&self) -> ReleaseKind {
        match self {
            Self::Promotion(_) => ReleaseKind::Promotion,
            Self::Rollback(_) => ReleaseKind::Rollback,
        }
    }

    const fn operation_kind(&self) -> &'static str {
        match self {
            Self::Promotion(_) => "release.promote",
            Self::Rollback(_) => "release.rollback",
        }
    }
}

struct ReleaseEvidence {
    origin_base_state: ContentDigest,
    changesets: Vec<serde_json::Value>,
    max_evidence_at: Timestamp,
}

#[expect(
    clippy::too_many_lines,
    reason = "Release creation binds policy, evidence, immutable history, signing, and pointer movement in one transaction"
)]
fn create_release_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    request: ReleaseRequest<'_>,
    artifact_preflight: impl FnOnce() -> Result<(), LocalPortError>,
    signer_factory: impl FnOnce() -> Result<Ed25519SigningProvider, LocalPortError>,
) -> Result<Release, LocalPortError> {
    let environment = load_environment(transaction, workspace_id, request.environment_id().clone())
        .map_err(local_port_from_environment)?;
    let request_digest = release_request_digest(workspace_id, principal_id, &request)?;
    verify_release_operation_scope(transaction, workspace_id)?;
    let replay: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT request_digest, release_id, proof_id FROM release_operations
             WHERE workspace_id = ?1 AND principal_id = ?2
                   AND operation_kind = ?3 AND idempotency_key = ?4",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                request.operation_kind(),
                request.idempotency_key().to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if let Some((persisted_request, release_id, proof_id)) = replay {
        let release_id = release_id
            .parse::<ReleaseId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let proof_id = proof_id
            .parse::<ProofId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let release = load_release_record(transaction, workspace_id, release_id)?;
        if release.proof_id != proof_id {
            return Err(LocalPortError::Integrity(
                "Release operation does not bind the persisted Proof".to_owned(),
            ));
        }
        if persisted_request != request_digest.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(release);
    }
    artifact_preflight()?;
    let candidate_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM releases WHERE release_id = ?1
                 UNION ALL SELECT 1 FROM release_proofs WHERE proof_id = ?2
             )",
            (
                request.release_id().to_string(),
                request.proof_id().to_string(),
            ),
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if candidate_exists {
        return Err(LocalPortError::Integrity(
            "candidate Release or Proof identity already exists".to_owned(),
        ));
    }

    let previous: Option<(String, i64, String)> = transaction
        .query_row(
            "SELECT release_id, release_sequence, released_at FROM releases
             WHERE environment_id = ?1 ORDER BY release_sequence DESC LIMIT 1",
            [request.environment_id().as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let previous_release = previous
        .as_ref()
        .map(|(release_id, _, _)| {
            release_id
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()?;
    if let Some((_, _, previous_released_at)) = &previous {
        let previous_released_at = previous_released_at
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if request.released_at() < previous_released_at {
            return Err(LocalPortError::PolicyDenied);
        }
    }
    if environment.current_release_id != previous_release {
        return Err(LocalPortError::StateConflict);
    }
    let (edition, rollback_target_release_id) = match &request {
        ReleaseRequest::Promotion(command) => {
            let edition =
                load_edition(transaction, command.edition_id).map_err(local_port_from_edition)?;
            if edition.workspace_id != workspace_id {
                return Err(LocalPortError::NotFound);
            }
            if let Some(previous_release_id) = previous_release {
                let current = load_release_record(transaction, workspace_id, previous_release_id)?;
                let current_edition = load_edition(transaction, current.edition_id)
                    .map_err(local_port_from_edition)?;
                if edition.authoritative_sequence < current_edition.authoritative_sequence {
                    return Err(LocalPortError::PolicyDenied);
                }
            }
            (edition, None)
        }
        ReleaseRequest::Rollback(command) => {
            let Some((_, current_sequence, _)) = previous else {
                return Err(LocalPortError::InvalidRollbackTarget);
            };
            let target = load_release_record(
                transaction,
                workspace_id,
                command.rollback_target_release_id,
            )?;
            if target.environment_id != command.environment_id
                || i64::try_from(target.release_sequence)
                    .map_or(true, |sequence| sequence >= current_sequence)
            {
                return Err(LocalPortError::InvalidRollbackTarget);
            }
            let edition =
                load_edition(transaction, target.edition_id).map_err(local_port_from_edition)?;
            (edition, Some(command.rollback_target_release_id))
        }
    };
    reproduce_projections_from_facts(transaction, workspace_id)?;
    let evidence =
        collect_release_evidence(transaction, &edition, &environment.required_approval, None)?;
    if !release_time_valid(request.released_at(), &environment, &edition, &evidence) {
        return Err(LocalPortError::PolicyDenied);
    }
    let signer = signer_factory()?;
    let metadata = signer
        .metadata()
        .map_err(|error| LocalPortError::Signing(error.to_string()))?;
    persist_signing_key(transaction, &metadata, request.released_at())?;
    let release_sequence: u64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(release_sequence), 0) + 1 FROM releases",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .try_into()
        .map_err(|_| LocalPortError::Integrity("invalid next Release sequence".to_owned()))?;
    let policy_decision = release_policy_decision(
        workspace_id,
        principal_id,
        &environment,
        &edition,
        request.kind(),
        previous_release,
        rollback_target_release_id,
        request.released_at(),
        &evidence,
    )?;
    let authorization_decision_digest =
        digest(ArtifactKind::AuthorizationDecisionV1, &policy_decision);
    let manifest = release_manifest(
        request.release_id(),
        request.proof_id(),
        workspace_id,
        principal_id,
        &environment,
        &edition,
        request.kind(),
        release_sequence,
        previous_release,
        rollback_target_release_id,
        request.released_at(),
        authorization_decision_digest,
        &metadata.key_id,
    )?;
    let release_digest = digest(ArtifactKind::ReleaseV1, &manifest);
    let statement = release_statement(
        request.release_id(),
        workspace_id,
        principal_id,
        &environment,
        &edition,
        request.kind(),
        release_sequence,
        previous_release,
        rollback_target_release_id,
        request.released_at(),
        release_digest,
        authorization_decision_digest,
        &metadata.key_id,
        &evidence,
    );
    let signed_proof = sign_release_statement(&statement, &signer)
        .map_err(|error| LocalPortError::Signing(error.to_string()))?;
    if signed_proof.key_id != metadata.key_id {
        return Err(LocalPortError::Signing(
            "signing provider changed key identity during Release creation".to_owned(),
        ));
    }

    transaction
        .execute(
            "INSERT OR IGNORE INTO release_policy_decisions (
                 decision_digest, environment_id, environment_config_version,
                 environment_config_digest, edition_id, edition_digest,
                 principal_id, allowed, decision_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            (
                authorization_decision_digest.to_string(),
                environment.environment_id.as_str(),
                environment.config_version,
                environment.config_digest.to_string(),
                edition.edition_id.to_string(),
                edition.edition_digest.to_string(),
                principal_id.to_string(),
                policy_decision.as_str(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let persisted_policy: (String, i64, String, String, String, String, i64, String) = transaction
        .query_row(
            "SELECT environment_id, environment_config_version,
                    environment_config_digest, edition_id, edition_digest,
                    principal_id, allowed, decision_json
             FROM release_policy_decisions WHERE decision_digest = ?1",
            [authorization_decision_digest.to_string()],
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
                ))
            },
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if persisted_policy
        != (
            environment.environment_id.as_str().to_owned(),
            i64::from(environment.config_version),
            environment.config_digest.to_string(),
            edition.edition_id.to_string(),
            edition.edition_digest.to_string(),
            principal_id.to_string(),
            1,
            policy_decision.as_str().to_owned(),
        )
    {
        return Err(LocalPortError::Integrity(
            "persisted Release policy decision conflicts with exact evaluated evidence".to_owned(),
        ));
    }
    transaction
        .execute(
            "INSERT INTO releases (
                 release_id, release_sequence, workspace_id, environment_id,
                 environment_config_version, edition_id, edition_digest, release_kind,
                 rollback_target_release_id, previous_release_id, principal_id,
                 delegation_id, policy_decision_digest, manifest_json, release_digest,
                 released_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, ?14, ?15)",
            (
                request.release_id().to_string(),
                i64::try_from(release_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "Release sequence exceeds local storage range".to_owned(),
                    )
                })?,
                workspace_id.to_string(),
                environment.environment_id.as_str(),
                environment.config_version,
                edition.edition_id.to_string(),
                edition.edition_digest.to_string(),
                request.kind().to_string(),
                rollback_target_release_id.map(|id| id.to_string()),
                previous_release.map(|id| id.to_string()),
                principal_id.to_string(),
                authorization_decision_digest.to_string(),
                manifest.as_str(),
                release_digest.to_string(),
                request.released_at().to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO release_proofs (
                 proof_id, release_id, key_id, payload_type, statement_json,
                 envelope_json, proof_digest, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                request.proof_id().to_string(),
                request.release_id().to_string(),
                metadata.key_id.as_str(),
                DSSE_PAYLOAD_TYPE,
                signed_proof.payload_json.as_str(),
                signed_proof.envelope_json.as_str(),
                signed_proof.envelope_digest.to_string(),
                request.released_at().to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO release_operations (
                 workspace_id, principal_id, operation_kind, idempotency_key,
                 request_digest, release_id, proof_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                request.operation_kind(),
                request.idempotency_key().to_string(),
                request_digest.to_string(),
                request.release_id().to_string(),
                request.proof_id().to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO release_proof_export_outbox (proof_id, release_id, created_at)
             VALUES (?1, ?2, ?3)",
            (
                request.proof_id().to_string(),
                request.release_id().to_string(),
                request.released_at().to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let pointer_changed = if let Some((previous_id, previous_sequence, _)) = previous {
        transaction
            .execute(
                "UPDATE environment_current_releases
                 SET release_id = ?1, release_sequence = ?2, projection_version = 1
                 WHERE environment_id = ?3 AND release_id = ?4 AND release_sequence = ?5",
                (
                    request.release_id().to_string(),
                    i64::try_from(release_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "Release sequence exceeds local storage range".to_owned(),
                        )
                    })?,
                    environment.environment_id.as_str(),
                    previous_id,
                    previous_sequence,
                ),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    } else {
        transaction
            .execute(
                "INSERT INTO environment_current_releases (
                     environment_id, release_id, release_sequence, projection_version
                 ) VALUES (?1, ?2, ?3, 1)",
                (
                    environment.environment_id.as_str(),
                    request.release_id().to_string(),
                    i64::try_from(release_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "Release sequence exceeds local storage range".to_owned(),
                        )
                    })?,
                ),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    };
    if pointer_changed != 1 {
        return Err(LocalPortError::StateConflict);
    }
    Ok(Release {
        release_id: request.release_id(),
        workspace_id,
        environment_id: environment.environment_id,
        edition_id: edition.edition_id,
        kind: request.kind(),
        release_sequence,
        previous_release_id: previous_release,
        rollback_target_release_id,
        principal_id,
        delegation_id: None,
        released_at: request.released_at(),
        release_digest,
        edition_digest: edition.edition_digest,
        environment_config_digest: environment.config_digest,
        authorization_decision_digest,
        proof_id: request.proof_id(),
        proof_envelope_digest: signed_proof.envelope_digest,
        key_id: signed_proof.key_id,
        proof_envelope_json: signed_proof.envelope_json,
    })
}

fn release_request_digest(
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    request: &ReleaseRequest<'_>,
) -> Result<ContentDigest, LocalPortError> {
    let (edition_id, rollback_target_release_id) = match request {
        ReleaseRequest::Promotion(command) => (Some(command.edition_id.to_string()), None),
        ReleaseRequest::Rollback(command) => {
            (None, Some(command.rollback_target_release_id.to_string()))
        }
    };
    release_request_digest_values(
        workspace_id,
        principal_id,
        request.kind(),
        request.environment_id(),
        request.idempotency_key(),
        edition_id.as_deref(),
        rollback_target_release_id.as_deref(),
    )
}

fn release_request_digest_values(
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    kind: ReleaseKind,
    environment_id: &EnvironmentId,
    idempotency_key: IdempotencyKey,
    edition_id: Option<&str>,
    rollback_target_release_id: Option<&str>,
) -> Result<ContentDigest, LocalPortError> {
    let canonical = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release-request/v1",
        "edition_id": edition_id,
        "environment_id": environment_id.as_str(),
        "idempotency_key": idempotency_key.to_string(),
        "kind": kind.to_string(),
        "principal_id": principal_id.to_string(),
        "rollback_target_release_id": rollback_target_release_id,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::ReleaseV1, &canonical))
}

#[expect(
    clippy::too_many_lines,
    reason = "Release evidence loading verifies every ChangeSet lifecycle binding selected by the Edition"
)]
fn collect_release_evidence(
    connection: &Connection,
    edition: &Edition,
    required_approval: &ApprovalName,
    reproduced: Option<ReproducedEditionData<'_>>,
) -> Result<ReleaseEvidence, LocalPortError> {
    type EvidenceRow = (
        String,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let verified_changesets = if let Some(reproduced) = reproduced {
        reproduced
            .changesets
            .iter()
            .filter(|changeset| changeset.authoritative_sequence <= edition.authoritative_sequence)
            .map(|changeset| changeset.reference)
            .collect::<Vec<_>>()
    } else {
        load_edition_changesets(
            connection,
            edition.workspace_id,
            edition.authoritative_sequence,
        )
        .map_err(local_port_from_edition)?
    };
    if verified_changesets != edition.changesets {
        return Err(LocalPortError::Integrity(
            "Release Edition ChangeSet evidence does not reproduce".to_owned(),
        ));
    }
    let mut entries = Vec::with_capacity(edition.changesets.len());
    let mut origin_base_state = None;
    let mut max_evidence_at = edition.created_at;
    for changeset in &edition.changesets {
        let row: Option<EvidenceRow> = connection
            .query_row(
                "SELECT c.base_state, c.created_at,
                        cc.authoritative_sequence, cc.committed_at,
                        cc.changeset_digest, cc.validation_results_digest,
                        v.validation_profile, v.validator, v.results_json,
                        s.changeset_digest, s.validation_results_digest, s.submitted_at,
                        a.changeset_digest, a.validation_results_digest,
                        a.approval_name, a.approved_at, a.principal_id
                 FROM changesets c
                 JOIN changeset_commits cc ON cc.changeset_id = c.changeset_id
                 JOIN changeset_validations v
                   ON v.changeset_id = c.changeset_id
                  AND v.changeset_digest = cc.changeset_digest
                  AND v.results_digest = cc.validation_results_digest
                  AND v.valid = 1
                 JOIN changeset_submissions s ON s.changeset_id = c.changeset_id
                 JOIN changeset_approvals a ON a.changeset_id = c.changeset_id
                 WHERE c.changeset_id = ?1",
                [changeset.changeset_id.to_string()],
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
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                        row.get(14)?,
                        row.get(15)?,
                        row.get(16)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let Some((
            base_state,
            changeset_created_at,
            authoritative_sequence,
            committed_at,
            committed_changeset_digest,
            validation_results_digest,
            validation_profile,
            validator,
            results_json,
            submitted_changeset_digest,
            submitted_validation_digest,
            submitted_at,
            approved_changeset_digest,
            approved_validation_digest,
            approval_name,
            approved_at,
            approval_principal_id,
        )) = row
        else {
            return Err(LocalPortError::PolicyDenied);
        };
        if origin_base_state.is_none() {
            origin_base_state = Some(
                base_state
                    .parse::<ContentDigest>()
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            );
        }
        let canonical_results = parse_strict(results_json.as_bytes())
            .and_then(|value| canonicalize(&value))
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let reproduced_validation_digest =
            digest(ArtifactKind::ValidationResultsV1, &canonical_results);
        if approved_changeset_digest != committed_changeset_digest
            || approved_changeset_digest != submitted_changeset_digest
            || approved_validation_digest != validation_results_digest
            || approved_validation_digest != submitted_validation_digest
            || approved_validation_digest != reproduced_validation_digest.to_string()
        {
            return Err(LocalPortError::Integrity(
                "ChangeSet approval digests do not reproduce the submitted validation evidence"
                    .to_owned(),
            ));
        }
        if canonical_results.as_str() != results_json
            || committed_changeset_digest != changeset.changeset_digest.to_string()
            || submitted_changeset_digest != changeset.changeset_digest.to_string()
            || validation_results_digest != reproduced_validation_digest.to_string()
            || submitted_validation_digest != validation_results_digest
            || approval_name != required_approval.as_str()
            || u64::try_from(authoritative_sequence)
                .map_or(true, |sequence| sequence > edition.authoritative_sequence)
        {
            return Err(LocalPortError::PolicyDenied);
        }
        ApprovalName::new(approval_name.clone())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let changeset_created_timestamp = changeset_created_at
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let committed_timestamp = committed_at
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let submitted_timestamp = submitted_at
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let approved_timestamp = approved_at
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if changeset_created_timestamp > submitted_timestamp
            || submitted_timestamp > approved_timestamp
            || approved_timestamp > committed_timestamp
            || committed_timestamp > edition.created_at
        {
            return Err(LocalPortError::Integrity(
                "Release evidence timestamps violate the ChangeSet lifecycle order".to_owned(),
            ));
        }
        max_evidence_at = max_evidence_at
            .max(changeset_created_timestamp)
            .max(committed_timestamp)
            .max(submitted_timestamp)
            .max(approved_timestamp);
        let approval_principal_id = approval_principal_id
            .parse::<PrincipalId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        entries.push(serde_json::json!({
            "approval": {
                "approved_at": approved_at,
                "approval_name": approval_name,
                "principal_id": approval_principal_id.to_string(),
            },
            "authoritative_sequence": authoritative_sequence,
            "changeset_digest": changeset.changeset_digest.to_string(),
            "changeset_id": changeset.changeset_id.to_string(),
            "created_at": changeset_created_at,
            "committed_at": committed_at,
            "submission": {
                "submitted_at": submitted_at,
            },
            "validation": {
                "results_digest": reproduced_validation_digest.to_string(),
                "validation_profile": validation_profile,
                "validator": validator,
            },
        }));
    }
    Ok(ReleaseEvidence {
        origin_base_state: origin_base_state.ok_or(LocalPortError::PolicyDenied)?,
        changesets: entries,
        max_evidence_at,
    })
}

fn release_time_valid(
    released_at: Timestamp,
    environment: &Environment,
    edition: &Edition,
    evidence: &ReleaseEvidence,
) -> bool {
    released_at >= environment.created_at
        && released_at >= edition.created_at
        && released_at >= evidence.max_evidence_at
}

#[expect(
    clippy::too_many_arguments,
    reason = "the policy decision explicitly binds the complete Release request and evaluated evidence"
)]
fn release_policy_decision(
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    environment: &Environment,
    edition: &Edition,
    kind: ReleaseKind,
    previous_release_id: Option<ReleaseId>,
    rollback_target_release_id: Option<ReleaseId>,
    released_at: Timestamp,
    evidence: &ReleaseEvidence,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&serde_json::json!({
        "action": match kind {
            ReleaseKind::Promotion => "release.promote",
            ReleaseKind::Rollback => "release.rollback",
        },
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v1",
        "delegation_chain": [],
        "edition_digest": edition.edition_digest.to_string(),
        "edition_id": edition.edition_id.to_string(),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": environment.environment_id.as_str(),
        "evaluated_at": released_at.to_string(),
        "evidence": evidence.changesets,
        "operating_principal_id": principal_id.to_string(),
        "policy_profile": environment.policy_profile,
        "previous_release_id": previous_release_id.map(|id| id.to_string()),
        "required_approval": environment.required_approval.as_str(),
        "rollback_target_release_id": rollback_target_release_id.map(|id| id.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the immutable Release manifest explicitly binds every identity, digest, and causal field"
)]
fn release_manifest(
    release_id: ReleaseId,
    proof_id: ProofId,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    environment: &Environment,
    edition: &Edition,
    kind: ReleaseKind,
    release_sequence: u64,
    previous_release_id: Option<ReleaseId>,
    rollback_target_release_id: Option<ReleaseId>,
    released_at: Timestamp,
    authorization_decision_digest: ContentDigest,
    key_id: &str,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release/v1",
        "authorization_decision_digest": authorization_decision_digest.to_string(),
        "delegation_id": serde_json::Value::Null,
        "edition_digest": edition.edition_digest.to_string(),
        "edition_id": edition.edition_id.to_string(),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": environment.environment_id.as_str(),
        "key_id": key_id,
        "kind": kind.to_string(),
        "previous_release_id": previous_release_id.map(|id| id.to_string()),
        "principal_id": principal_id.to_string(),
        "proof_id": proof_id.to_string(),
        "release_id": release_id.to_string(),
        "release_sequence": release_sequence,
        "released_at": released_at.to_string(),
        "rollback_target_release_id": rollback_target_release_id.map(|id| id.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

#[expect(
    clippy::too_many_arguments,
    reason = "the portable Statement binds immutable subjects plus full operational evidence"
)]
fn release_statement(
    release_id: ReleaseId,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    environment: &Environment,
    edition: &Edition,
    kind: ReleaseKind,
    release_sequence: u64,
    previous_release_id: Option<ReleaseId>,
    rollback_target_release_id: Option<ReleaseId>,
    released_at: Timestamp,
    release_digest: ContentDigest,
    authorization_decision_digest: ContentDigest,
    key_id: &str,
    evidence: &ReleaseEvidence,
) -> InTotoStatement {
    InTotoStatement::release(
        vec![
            InTotoSubject {
                name: format!("proof:edition:{}", edition.edition_id),
                digest: BTreeMap::from([("blake3".to_owned(), digest_hex(edition.edition_digest))]),
            },
            InTotoSubject {
                name: format!("proof:release:{release_id}"),
                digest: BTreeMap::from([("blake3".to_owned(), digest_hex(release_digest))]),
            },
        ],
        serde_json::json!({
            "api_version": "proof.dev/release-proof-predicate/v1",
            "authority": {
                "authorization_decision_digest": authorization_decision_digest.to_string(),
                "delegation_chain": [],
                "human_principal_id": principal_id.to_string(),
                "policy_profile": environment.policy_profile,
            },
            "evidence": evidence.changesets,
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": "proof.dev/known-state/v1",
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "origin": {
                "authoritative_sequence": edition.authoritative_sequence,
                "base_state": evidence.origin_base_state.to_string(),
                "changesets": edition.changesets.iter().map(|changeset| serde_json::json!({
                    "changeset_digest": changeset.changeset_digest.to_string(),
                    "changeset_id": changeset.changeset_id.to_string(),
                })).collect::<Vec<_>>(),
                "edition_state": edition.state_digest.to_string(),
                "workspace_id": workspace_id.to_string(),
            },
            "policy": {
                "decision": "allow",
                "environment_config_digest": environment.config_digest.to_string(),
                "environment_config_version": environment.config_version,
                "required_approval": environment.required_approval.as_str(),
            },
            "release": {
                "edition_digest": edition.edition_digest.to_string(),
                "edition_id": edition.edition_id.to_string(),
                "environment_id": environment.environment_id.as_str(),
                "key_id": key_id,
                "kind": kind.to_string(),
                "previous_release_id": previous_release_id.map(|id| id.to_string()),
                "release_digest": release_digest.to_string(),
                "release_id": release_id.to_string(),
                "release_sequence": release_sequence,
                "released_at": released_at.to_string(),
                "rollback_target_release_id": rollback_target_release_id.map(|id| id.to_string()),
            },
        }),
    )
}

fn digest_hex(value: ContentDigest) -> String {
    value
        .to_string()
        .strip_prefix("blake3:")
        .expect("ContentDigest only supports BLAKE3")
        .to_owned()
}

fn persist_signing_key(
    connection: &Connection,
    metadata: &proof_attestation::SigningKeyMetadata,
    not_before: Timestamp,
) -> Result<(), LocalPortError> {
    if metadata.public_key.len() != 32
        || !metadata.key_id.starts_with("ed25519:")
        || metadata.key_id.len() != 72
    {
        return Err(LocalPortError::Signing(
            "local signing provider returned invalid public metadata".to_owned(),
        ));
    }
    let public_key = metadata.public_key.iter().fold(
        String::with_capacity(metadata.public_key.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing hexadecimal bytes to String");
            output
        },
    );
    if metadata.key_id != format!("ed25519:{public_key}") {
        return Err(LocalPortError::Signing(
            "local signing key identity does not match public bytes".to_owned(),
        ));
    }
    let manifest = canonicalize(&serde_json::json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/signing-key-metadata/v1",
        "key_id": metadata.key_id,
        "not_before": not_before.to_string(),
        "public_key": public_key,
        "trust_profile": "proof.local/release-proof/v1",
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let metadata_digest = digest(ArtifactKind::PolicyBundleV1, &manifest);
    let existing: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM signing_keys WHERE key_id = ?1)",
            [metadata.key_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if existing {
        if load_signing_key_revocation(connection, &metadata.key_id)?.is_some() {
            return Err(LocalPortError::Signing(
                "local Release signing key is revoked".to_owned(),
            ));
        }
        verify_signing_key_trust(connection, &metadata.key_id, not_before)?;
        return Ok(());
    }
    connection
        .execute(
            "INSERT INTO signing_keys (
                 key_id, algorithm, public_key, trust_profile, not_before,
                 metadata_json, metadata_digest
             ) VALUES (?1, 'ed25519', ?2, ?3, ?4, ?5, ?6)",
            (
                metadata.key_id.as_str(),
                public_key,
                "proof.local/release-proof/v1",
                not_before.to_string(),
                manifest.as_str(),
                metadata_digest.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    Ok(())
}

fn load_release_record(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: ReleaseId,
) -> Result<Release, LocalPortError> {
    load_release_record_with_reproduced_editions(connection, workspace_id, release_id, None)
}

fn load_release_record_from_reproduced(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: ReleaseId,
    reproduced: ReproducedEditionData<'_>,
) -> Result<Release, LocalPortError> {
    load_release_record_with_reproduced_editions(
        connection,
        workspace_id,
        release_id,
        Some(reproduced),
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "Release loading reconstructs and verifies policy, causal history, Statement subjects, trust, and signature"
)]
fn load_release_record_with_reproduced_editions(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: ReleaseId,
    reproduced: Option<ReproducedEditionData<'_>>,
) -> Result<Release, LocalPortError> {
    type ReleaseRow = (
        String,
        i64,
        String,
        String,
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
    );
    type OperationRow = (String, String, String, String, String, String);
    let row: Option<ReleaseRow> = connection
        .query_row(
            "SELECT api_version, release_sequence, workspace_id, environment_id,
                    environment_config_version, edition_id, edition_digest, release_kind,
                    rollback_target_release_id, previous_release_id, principal_id,
                    delegation_id, policy_decision_digest, manifest_json, release_digest,
                    released_at
             FROM releases WHERE release_id = ?1",
            [release_id.to_string()],
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
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((
        api_version,
        raw_sequence,
        persisted_workspace,
        raw_environment,
        raw_config_version,
        raw_edition,
        persisted_edition_digest,
        raw_kind,
        raw_rollback_target,
        raw_previous,
        raw_principal,
        raw_delegation,
        persisted_decision_digest,
        manifest_json,
        persisted_release_digest,
        raw_released_at,
    )) = row
    else {
        return Err(LocalPortError::NotFound);
    };
    if api_version != "proof.dev/release/v1" {
        return Err(LocalPortError::UnsupportedVersion);
    }
    if persisted_workspace != workspace_id.to_string() || raw_delegation.is_some() {
        return Err(LocalPortError::Integrity(
            "Release Workspace or unsupported delegated authority field is invalid".to_owned(),
        ));
    }
    let release_sequence = u64::try_from(raw_sequence)
        .map_err(|_| LocalPortError::Integrity("invalid Release sequence".to_owned()))?;
    let environment_id = raw_environment
        .parse::<EnvironmentId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let config_version = u32::try_from(raw_config_version)
        .map_err(|_| LocalPortError::Integrity("invalid Environment config version".to_owned()))?;
    let edition_id = raw_edition
        .parse::<EditionId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let principal_id = raw_principal
        .parse::<PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let previous_release_id = raw_previous
        .map(|value| {
            value
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()?;
    let rollback_target_release_id = raw_rollback_target
        .map(|value| {
            value
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()?;
    let kind = match raw_kind.as_str() {
        "promotion" => ReleaseKind::Promotion,
        "rollback" => ReleaseKind::Rollback,
        _ => {
            return Err(LocalPortError::Integrity(
                "unsupported Release kind".to_owned(),
            ));
        }
    };
    if (kind == ReleaseKind::Promotion && rollback_target_release_id.is_some())
        || (kind == ReleaseKind::Rollback && rollback_target_release_id.is_none())
    {
        return Err(LocalPortError::Integrity(
            "Release kind and rollback target are inconsistent".to_owned(),
        ));
    }
    let released_at = raw_released_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let count_before: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM releases WHERE release_sequence <= ?1",
            [raw_sequence],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .try_into()
        .map_err(|_| LocalPortError::Integrity("invalid Release history count".to_owned()))?;
    if count_before != release_sequence {
        return Err(LocalPortError::Integrity(
            "global Release sequence is not contiguous".to_owned(),
        ));
    }
    let expected_previous: Option<(String, String, String)> = connection
        .query_row(
            "SELECT release_id, released_at, edition_id FROM releases
             WHERE environment_id = ?1 AND release_sequence < ?2
             ORDER BY release_sequence DESC LIMIT 1",
            (environment_id.as_str(), raw_sequence),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let expected_previous_id = expected_previous
        .as_ref()
        .map(|(raw_release_id, _, _)| {
            raw_release_id
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()?;
    if expected_previous_id != previous_release_id {
        return Err(LocalPortError::Integrity(
            "Release predecessor does not match immutable Environment history".to_owned(),
        ));
    }
    let predecessor_edition_id = expected_previous
        .as_ref()
        .map(|(raw_release_id, raw_released_at, raw_edition_id)| {
            if expected_previous_id.map(|id| id.to_string()).as_deref()
                != Some(raw_release_id.as_str())
            {
                return Err(LocalPortError::Integrity(
                    "Release predecessor identity is not canonical".to_owned(),
                ));
            }
            let previous_released_at = raw_released_at
                .parse::<Timestamp>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            if released_at < previous_released_at {
                return Err(LocalPortError::Integrity(
                    "Release timestamp precedes its Environment predecessor".to_owned(),
                ));
            }
            let predecessor_edition_id = raw_edition_id
                .parse::<EditionId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            if predecessor_edition_id.to_string() != *raw_edition_id {
                return Err(LocalPortError::Integrity(
                    "Release predecessor Edition identity is not canonical".to_owned(),
                ));
            }
            Ok(predecessor_edition_id)
        })
        .transpose()?;
    if let Some(target) = rollback_target_release_id {
        let target_scope: Option<(String, i64)> = connection
            .query_row(
                "SELECT environment_id, release_sequence FROM releases WHERE release_id = ?1",
                [target.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if !matches!(target_scope, Some((ref target_environment, target_sequence))
            if target_environment == environment_id.as_str() && target_sequence < raw_sequence)
        {
            return Err(LocalPortError::Integrity(
                "rollback target is not an earlier Release in the same Environment".to_owned(),
            ));
        }
    }
    let environment = load_environment_version(
        connection,
        workspace_id,
        environment_id.clone(),
        config_version,
    )
    .map_err(local_port_from_environment)?;
    let edition = if let Some(reproduced) = reproduced {
        load_edition_from_reproduced(connection, edition_id, workspace_id, reproduced)?
    } else {
        load_edition(connection, edition_id).map_err(local_port_from_edition)?
    };
    if edition.workspace_id != workspace_id
        || persisted_edition_digest != edition.edition_digest.to_string()
    {
        return Err(LocalPortError::Integrity(
            "Release Edition binding does not reproduce".to_owned(),
        ));
    }
    if kind == ReleaseKind::Promotion
        && let Some(predecessor_edition_id) = predecessor_edition_id
    {
        let predecessor_edition = if let Some(reproduced) = reproduced {
            load_edition_from_reproduced(
                connection,
                predecessor_edition_id,
                workspace_id,
                reproduced,
            )?
        } else {
            load_edition(connection, predecessor_edition_id).map_err(local_port_from_edition)?
        };
        if edition.authoritative_sequence < predecessor_edition.authoritative_sequence {
            return Err(LocalPortError::Integrity(
                "Promotion Edition predates its Environment predecessor Edition".to_owned(),
            ));
        }
    }
    let evidence = collect_release_evidence(
        connection,
        &edition,
        &environment.required_approval,
        reproduced,
    )?;
    if !release_time_valid(released_at, &environment, &edition, &evidence) {
        return Err(LocalPortError::Integrity(
            "Release predates its Environment, Edition, or bound evidence".to_owned(),
        ));
    }
    let expected_decision = release_policy_decision(
        workspace_id,
        principal_id,
        &environment,
        &edition,
        kind,
        previous_release_id,
        rollback_target_release_id,
        released_at,
        &evidence,
    )?;
    let authorization_decision_digest =
        digest(ArtifactKind::AuthorizationDecisionV1, &expected_decision);
    let decision_row: Option<(String, String, String, String, i64)> = connection
        .query_row(
            "SELECT decision_json, environment_config_digest, edition_digest,
                    principal_id, allowed
             FROM release_policy_decisions WHERE decision_digest = ?1",
            [persisted_decision_digest.as_str()],
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((decision_json, config_digest, decision_edition_digest, decision_principal, allowed)) =
        decision_row
    else {
        return Err(LocalPortError::Integrity(
            "Release policy decision evidence is missing".to_owned(),
        ));
    };
    if persisted_decision_digest != authorization_decision_digest.to_string()
        || decision_json != expected_decision.as_str()
        || config_digest != environment.config_digest.to_string()
        || decision_edition_digest != edition.edition_digest.to_string()
        || decision_principal != principal_id.to_string()
        || allowed != 1
    {
        return Err(LocalPortError::Integrity(
            "Release policy decision does not reproduce".to_owned(),
        ));
    }
    let proof_row: Option<(String, String, String, String, String, String, String)> = connection
        .query_row(
            "SELECT proof_id, key_id, payload_type, statement_json,
                    envelope_json, proof_digest, created_at
             FROM release_proofs WHERE release_id = ?1",
            [release_id.to_string()],
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
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((
        raw_proof_id,
        key_id,
        payload_type,
        statement_json,
        envelope_json,
        proof_digest,
        proof_created_at,
    )) = proof_row
    else {
        return Err(LocalPortError::Integrity(
            "Release Proof evidence is missing".to_owned(),
        ));
    };
    let proof_id = raw_proof_id
        .parse::<ProofId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if payload_type != DSSE_PAYLOAD_TYPE || proof_created_at != released_at.to_string() {
        return Err(LocalPortError::Integrity(
            "Release Proof media type or creation time is invalid".to_owned(),
        ));
    }
    let mut operation_statement = connection
        .prepare(
            "SELECT workspace_id, principal_id, operation_kind, idempotency_key,
                    request_digest, proof_id
             FROM release_operations WHERE release_id = ?1",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let operation_rows = operation_statement
        .query_map([release_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut operations = Vec::<OperationRow>::new();
    for row in operation_rows {
        operations.push(row.map_err(|error| LocalPortError::Storage(error.to_string()))?);
    }
    if operations.len() != 1 {
        return Err(LocalPortError::Integrity(
            "Release must have exactly one authoritative operation record".to_owned(),
        ));
    }
    let (
        operation_workspace,
        operation_principal,
        operation_kind,
        raw_operation_key,
        operation_digest,
        operation_proof,
    ) = operations.pop().expect("length checked");
    let operation_key = raw_operation_key
        .parse::<IdempotencyKey>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if operation_key.to_string() != raw_operation_key {
        return Err(LocalPortError::Integrity(
            "Release operation idempotency key is not canonical".to_owned(),
        ));
    }
    let expected_operation_kind = match kind {
        ReleaseKind::Promotion => "release.promote",
        ReleaseKind::Rollback => "release.rollback",
    };
    let expected_request_digest = release_request_digest_values(
        workspace_id,
        principal_id,
        kind,
        &environment_id,
        operation_key,
        (kind == ReleaseKind::Promotion)
            .then_some(edition_id.to_string())
            .as_deref(),
        rollback_target_release_id
            .map(|id| id.to_string())
            .as_deref(),
    )?;
    if operation_workspace != workspace_id.to_string()
        || operation_principal != principal_id.to_string()
        || operation_kind != expected_operation_kind
        || operation_digest != expected_request_digest.to_string()
        || operation_proof != proof_id.to_string()
    {
        return Err(LocalPortError::Integrity(
            "Release operation provenance does not reproduce".to_owned(),
        ));
    }
    let expected_manifest = release_manifest(
        release_id,
        proof_id,
        workspace_id,
        principal_id,
        &environment,
        &edition,
        kind,
        release_sequence,
        previous_release_id,
        rollback_target_release_id,
        released_at,
        authorization_decision_digest,
        &key_id,
    )?;
    let release_digest = digest(ArtifactKind::ReleaseV1, &expected_manifest);
    if manifest_json != expected_manifest.as_str()
        || persisted_release_digest != release_digest.to_string()
    {
        return Err(LocalPortError::Integrity(
            "Release canonical manifest or digest does not reproduce".to_owned(),
        ));
    }
    verify_signing_key_trust(connection, &key_id, released_at)?;
    let proof_envelope_digest = proof_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let verified =
        verify_release_envelope(envelope_json.as_bytes(), proof_envelope_digest, &key_id)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expected_statement = release_statement(
        release_id,
        workspace_id,
        principal_id,
        &environment,
        &edition,
        kind,
        release_sequence,
        previous_release_id,
        rollback_target_release_id,
        released_at,
        release_digest,
        authorization_decision_digest,
        &key_id,
        &evidence,
    );
    let expected_statement_json = canonicalize(
        &serde_json::to_value(&expected_statement)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if verified.parsed.statement != expected_statement
        || verified.parsed.payload_json != statement_json
        || statement_json != expected_statement_json.as_str()
    {
        return Err(LocalPortError::Integrity(
            "Release Proof Statement does not match reconstructed operational evidence".to_owned(),
        ));
    }
    Ok(Release {
        release_id,
        workspace_id,
        environment_id,
        edition_id,
        kind,
        release_sequence,
        previous_release_id,
        rollback_target_release_id,
        principal_id,
        delegation_id: None,
        released_at,
        release_digest,
        edition_digest: edition.edition_digest,
        environment_config_digest: environment.config_digest,
        authorization_decision_digest,
        proof_id,
        proof_envelope_digest,
        key_id,
        proof_envelope_json: envelope_json,
    })
}

fn verify_signing_key_trust(
    connection: &Connection,
    key_id: &str,
    signed_at: Timestamp,
) -> Result<(), LocalPortError> {
    let row: Option<(String, String, String, String, String, String)> = connection
        .query_row(
            "SELECT algorithm, public_key, trust_profile, not_before,
                    metadata_json, metadata_digest
             FROM signing_keys WHERE key_id = ?1",
            [key_id],
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
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((
        algorithm,
        public_key,
        trust_profile,
        raw_not_before,
        metadata_json,
        metadata_digest,
    )) = row
    else {
        return Err(LocalPortError::Integrity(
            "Release signing key is not trusted by local configuration".to_owned(),
        ));
    };
    let not_before = raw_not_before
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expected = canonicalize(&serde_json::json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/signing-key-metadata/v1",
        "key_id": key_id,
        "not_before": not_before.to_string(),
        "public_key": public_key,
        "trust_profile": "proof.local/release-proof/v1",
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if algorithm != "ed25519"
        || trust_profile != "proof.local/release-proof/v1"
        || key_id != format!("ed25519:{public_key}")
        || metadata_json != expected.as_str()
        || metadata_digest != digest(ArtifactKind::PolicyBundleV1, &expected).to_string()
        || signed_at < not_before
    {
        return Err(LocalPortError::Integrity(
            "Release signing-key trust metadata does not reproduce at signing time".to_owned(),
        ));
    }
    if let Some(revoked_at) = load_signing_key_revocation(connection, key_id)?
        && revoked_at <= signed_at
    {
        return Err(LocalPortError::Integrity(
            "Release was signed after its trusted key was revoked".to_owned(),
        ));
    }
    Ok(())
}

fn load_signing_key_revocation(
    connection: &Connection,
    key_id: &str,
) -> Result<Option<Timestamp>, LocalPortError> {
    let row: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT revoked_at, reason, revocation_json, revocation_digest
             FROM signing_key_revocations WHERE key_id = ?1",
            [key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((raw_revoked_at, reason, revocation_json, revocation_digest)) = row else {
        return Ok(None);
    };
    let revoked_at = raw_revoked_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if reason.trim().is_empty() {
        return Err(LocalPortError::Integrity(
            "signing-key revocation reason is empty".to_owned(),
        ));
    }
    let expected = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/signing-key-revocation/v1",
        "key_id": key_id,
        "reason": reason,
        "revoked_at": revoked_at.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if revocation_json != expected.as_str()
        || revocation_digest != digest(ArtifactKind::PolicyBundleV1, &expected).to_string()
    {
        return Err(LocalPortError::Integrity(
            "signing-key revocation evidence does not reproduce".to_owned(),
        ));
    }
    Ok(Some(revoked_at))
}

fn local_port_from_environment(error: EnvironmentError) -> LocalPortError {
    match error {
        EnvironmentError::Unauthenticated => LocalPortError::Unauthenticated,
        EnvironmentError::NotFound => LocalPortError::NotFound,
        EnvironmentError::Storage(detail) => LocalPortError::Storage(detail),
        EnvironmentError::Integrity(detail) => LocalPortError::Integrity(detail),
        EnvironmentError::IdempotencyKeyReused => LocalPortError::IdempotencyKeyReused,
        EnvironmentError::InvalidConfiguration | EnvironmentError::AlreadyExists => {
            LocalPortError::Integrity("invalid persisted Environment configuration".to_owned())
        }
    }
}

fn release_from_local_port(error: LocalPortError) -> ReleaseError {
    match error {
        LocalPortError::Unauthenticated => ReleaseError::Unauthenticated,
        LocalPortError::UnsupportedVersion => ReleaseError::UnsupportedVersion,
        LocalPortError::NotFound => ReleaseError::NotFound,
        LocalPortError::PolicyDenied | LocalPortError::Denied | LocalPortError::Expired => {
            ReleaseError::PolicyDenied
        }
        LocalPortError::InvalidRollbackTarget => ReleaseError::InvalidRollbackTarget,
        LocalPortError::StateConflict => ReleaseError::StateConflict,
        LocalPortError::IdempotencyKeyReused => ReleaseError::IdempotencyKeyReused,
        LocalPortError::Signing(detail) => ReleaseError::Signing(detail),
        LocalPortError::Integrity(detail) => ReleaseError::Integrity(detail),
        LocalPortError::Storage(detail) => ReleaseError::Storage(detail),
        LocalPortError::Invalid
        | LocalPortError::IntentMismatch
        | LocalPortError::SourceConflict
        | LocalPortError::TargetConflict
        | LocalPortError::DuplicateActiveTarget
        | LocalPortError::InvalidSupersession
        | LocalPortError::InvalidRepairEvidence
        | LocalPortError::NotDraft
        | LocalPortError::NotReady
        | LocalPortError::NotSubmitted
        | LocalPortError::NotApproved
        | LocalPortError::EvidenceMissing
        | LocalPortError::LimitExceeded => {
            ReleaseError::Integrity("invalid Release adapter request".to_owned())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedSchemaProjection {
    schema_id: SchemaId,
    schema_version: SchemaVersion,
    document_json: String,
    document_digest: ContentDigest,
    changeset_id: ChangeSetId,
    edit_id: EditId,
    authoritative_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedObjectProjection {
    object_id: ObjectId,
    revision: ObjectRevision,
    schema_id: SchemaId,
    schema_version: SchemaVersion,
    content_json: String,
    object_digest: ContentDigest,
    changeset_id: ChangeSetId,
    edit_id: EditId,
    authoritative_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedEnvironmentPointer {
    environment_id: EnvironmentId,
    release_id: ReleaseId,
    release_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedEditionChangeSet {
    authoritative_sequence: u64,
    reference: EditionChangeSet,
}

#[derive(Clone, Copy)]
struct ReproducedEditionData<'a> {
    schemas: &'a [ExpectedSchemaProjection],
    objects: &'a [ExpectedObjectProjection],
    changesets: &'a [ExpectedEditionChangeSet],
}

struct ReproducedCommitFacts {
    workspace_id: WorkspaceId,
    schemas: Vec<ExpectedSchemaProjection>,
    objects: Vec<ExpectedObjectProjection>,
    changesets: Vec<ExpectedEditionChangeSet>,
    authoritative_sequence: u64,
    state_digest: ContentDigest,
}

type ReproducedSchemaMap = BTreeMap<(String, u32), ExpectedSchemaProjection>;
type ReproducedObjectMap = BTreeMap<ObjectId, ExpectedObjectProjection>;

fn reproduced_maps_at(
    reproduced: &ReproducedCommitFacts,
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
) -> Result<(ReproducedSchemaMap, ReproducedObjectMap), LatestSchemaError> {
    if reproduced.workspace_id != workspace_id
        || authoritative_sequence > reproduced.authoritative_sequence
        || (authoritative_sequence != 0
            && !reproduced
                .changesets
                .iter()
                .any(|changeset| changeset.authoritative_sequence == authoritative_sequence))
    {
        return Err(LatestSchemaError::Integrity(
            "legacy ChangeSet base is not an authoritative commit boundary".to_owned(),
        ));
    }
    let schemas = reproduced
        .schemas
        .iter()
        .filter(|schema| schema.authoritative_sequence <= authoritative_sequence)
        .map(|schema| {
            (
                (
                    schema.schema_id.as_str().to_owned(),
                    schema.schema_version.get(),
                ),
                schema.clone(),
            )
        })
        .collect();
    let objects = reproduced
        .objects
        .iter()
        .filter(|object| object.authoritative_sequence <= authoritative_sequence)
        .map(|object| (object.object_id, object.clone()))
        .collect();
    Ok((schemas, objects))
}

fn reproduced_schemas_at(
    reproduced: &ReproducedCommitFacts,
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
) -> Result<ReproducedSchemaMap, LatestSchemaError> {
    reproduced_maps_at(reproduced, workspace_id, authoritative_sequence).map(|(schemas, _)| schemas)
}

fn reproduced_state_at(
    reproduced: &ReproducedCommitFacts,
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
) -> Result<ContentDigest, LatestSchemaError> {
    let (schemas, objects) = reproduced_maps_at(reproduced, workspace_id, authoritative_sequence)?;
    reproduced_state_digest(workspace_id, authoritative_sequence, &schemas, &objects)
        .map_err(latest_schema_from_local_port)
}

struct ReproducedProjections {
    schemas: Vec<ExpectedSchemaProjection>,
    objects: Vec<ExpectedObjectProjection>,
    changesets: Vec<ExpectedEditionChangeSet>,
    localized_renditions: Vec<proof_application::ObjectLocaleRevision>,
    known_state_api_version: String,
    known_state_manifest_json: Option<String>,
    authoritative_sequence: u64,
    state_digest: ContentDigest,
}

#[expect(
    clippy::too_many_lines,
    reason = "projection rebuild compares and atomically replaces three derived projection families"
)]
fn rebuild_projections_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    dry_run: bool,
) -> Result<ProjectionRebuild, LocalPortError> {
    let verified_commit_tip = verify_commit_operation_chain(transaction, workspace_id)?;
    let expected = reproduce_projections_from_facts(transaction, workspace_id)?;
    match expected.known_state_api_version.as_str() {
        KNOWN_STATE_V1_API_VERSION => {
            if verified_commit_tip != (expected.authoritative_sequence, expected.state_digest) {
                return Err(LocalPortError::Integrity(
                    "reproduced projections do not match the verified commit chain".to_owned(),
                ));
            }
        }
        KNOWN_STATE_V2_API_VERSION => {
            if verified_commit_tip.0 >= expected.authoritative_sequence {
                return Err(LocalPortError::Integrity(
                    "localized state does not advance beyond its verified v1 predecessor"
                        .to_owned(),
                ));
            }
        }
        _ => return Err(LocalPortError::UnsupportedVersion),
    }
    let schemas_match =
        projection_rows_match(persisted_schema_projections(transaction), &expected.schemas)?;
    let objects_match =
        projection_rows_match(persisted_object_projections(transaction), &expected.objects)?;
    let localized_renditions_match = projection_rows_match(
        localized::persisted_locale_projections(transaction),
        &expected.localized_renditions,
    )?;
    let known_state_match: bool = transaction
        .query_row(
            "SELECT authoritative_sequence = ?1 AND state_digest = ?2 AND api_version = ?3
                    AND manifest_json IS ?4
             FROM known_state WHERE singleton = 1",
            params![
                i64::try_from(expected.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "authoritative sequence exceeds local storage range".to_owned(),
                    )
                })?,
                expected.state_digest.to_string(),
                expected.known_state_api_version.as_str(),
                expected.known_state_manifest_json.as_deref(),
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .unwrap_or(false);
    let core_changed =
        !schemas_match || !objects_match || !localized_renditions_match || !known_state_match;
    if dry_run && core_changed {
        transaction
            .execute_batch("SAVEPOINT proof_projection_rebuild_dry_run")
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    if core_changed {
        materialize_core_projections(transaction, &expected)?;
    }
    let expected_environment_pointers = reproduce_environment_pointers(
        transaction,
        workspace_id,
        ReproducedEditionData {
            schemas: &expected.schemas,
            objects: &expected.objects,
            changesets: &expected.changesets,
        },
    )?;
    let pointers_match = projection_rows_match(
        persisted_environment_pointers(transaction),
        &expected_environment_pointers,
    )?;
    let changed = core_changed || !pointers_match;
    if !dry_run && !pointers_match {
        transaction
            .execute("DELETE FROM environment_current_releases", [])
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        for pointer in &expected_environment_pointers {
            transaction
                .execute(
                    "INSERT INTO environment_current_releases (
                         environment_id, release_id, release_sequence, projection_version
                     ) VALUES (?1, ?2, ?3, 1)",
                    (
                        pointer.environment_id.as_str(),
                        pointer.release_id.to_string(),
                        i64::try_from(pointer.release_sequence).map_err(|_| {
                            LocalPortError::Integrity(
                                "Release sequence exceeds local storage range".to_owned(),
                            )
                        })?,
                    ),
                )
                .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        }
    }
    if core_changed || (!dry_run && !pointers_match) {
        let foreign_key_violation: Option<(String, i64, String, i64)> = transaction
            .query_row("PRAGMA foreign_key_check", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if foreign_key_violation.is_some() {
            return Err(LocalPortError::Integrity(
                "projection rebuild would leave foreign-key violations".to_owned(),
            ));
        }
    }
    if dry_run && core_changed {
        transaction
            .execute_batch(
                "ROLLBACK TO proof_projection_rebuild_dry_run;
                 RELEASE proof_projection_rebuild_dry_run;",
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    Ok(ProjectionRebuild {
        dry_run,
        changed,
        authoritative_sequence: expected.authoritative_sequence,
        state_digest: expected.state_digest,
        schema_count: u32::try_from(expected.schemas.len())
            .map_err(|_| LocalPortError::Integrity("Schema count exceeds u32".to_owned()))?,
        object_count: u32::try_from(expected.objects.len())
            .map_err(|_| LocalPortError::Integrity("Object count exceeds u32".to_owned()))?,
        environment_pointer_count: u32::try_from(expected_environment_pointers.len())
            .map_err(|_| LocalPortError::Integrity("Environment count exceeds u32".to_owned()))?,
    })
}

fn materialize_core_projections(
    transaction: &Transaction<'_>,
    expected: &ReproducedProjections,
) -> Result<(), LocalPortError> {
    transaction
        .execute("DELETE FROM object_locale_revisions", [])
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute("DELETE FROM object_revisions", [])
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute("DELETE FROM schema_versions", [])
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    for schema in &expected.schemas {
        transaction
            .execute(
                "INSERT INTO schema_versions (
                     schema_id, schema_version, document_json, document_digest,
                     changeset_id, edit_id, authoritative_sequence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    schema.schema_id.as_str(),
                    schema.schema_version.get(),
                    schema.document_json.as_str(),
                    schema.document_digest.to_string(),
                    schema.changeset_id.to_string(),
                    schema.edit_id.to_string(),
                    i64::try_from(schema.authoritative_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "Schema sequence exceeds local storage range".to_owned(),
                        )
                    })?,
                ),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    for object in &expected.objects {
        transaction
            .execute(
                "INSERT INTO object_revisions (
                     object_id, revision, schema_id, schema_version, lifecycle_state,
                     content_json, object_digest, changeset_id, edit_id,
                     authoritative_sequence
                 ) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?8, ?9)",
                (
                    object.object_id.to_string(),
                    object.revision.get(),
                    object.schema_id.as_str(),
                    object.schema_version.get(),
                    object.content_json.as_str(),
                    object.object_digest.to_string(),
                    object.changeset_id.to_string(),
                    object.edit_id.to_string(),
                    i64::try_from(object.authoritative_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "Object sequence exceeds local storage range".to_owned(),
                        )
                    })?,
                ),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    localized::insert_locale_projections(transaction, &expected.localized_renditions)?;
    let updated = transaction
        .execute(
            "UPDATE known_state
             SET api_version = ?1, authoritative_sequence = ?2,
                 state_digest = ?3, manifest_json = ?4
             WHERE singleton = 1",
            params![
                expected.known_state_api_version.as_str(),
                i64::try_from(expected.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "authoritative sequence exceeds local storage range".to_owned(),
                    )
                })?,
                expected.state_digest.to_string(),
                expected.known_state_manifest_json.as_deref(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if updated != 1 {
        return Err(LocalPortError::Integrity(
            "Known State projection singleton is missing".to_owned(),
        ));
    }
    Ok(())
}

fn projection_rows_match<T: Eq>(
    persisted: Result<Vec<T>, LocalPortError>,
    expected: &[T],
) -> Result<bool, LocalPortError> {
    match persisted {
        Ok(persisted) => Ok(persisted == expected),
        Err(LocalPortError::Integrity(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "projection reproduction verifies the complete committed fact chain before deriving any row"
)]
fn reproduce_commit_facts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    storage_schema_version: u32,
) -> Result<ReproducedCommitFacts, LocalPortError> {
    type CommitRow = (String, String, String, String, String, String, i64, i64);
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, workspace_id, principal_id, changeset_digest,
                    validation_results_digest, previous_state,
                    authoritative_sequence, edit_count
             FROM changeset_commits ORDER BY authoritative_sequence",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, i64>(7)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut commits = Vec::<CommitRow>::new();
    for row in rows {
        commits.push(row.map_err(|error| LocalPortError::Storage(error.to_string()))?);
    }
    drop(statement);

    let mut schema_map = BTreeMap::<(String, u32), ExpectedSchemaProjection>::new();
    let mut object_map = BTreeMap::<ObjectId, ExpectedObjectProjection>::new();
    let mut edition_changesets = Vec::<ExpectedEditionChangeSet>::new();
    let mut authoritative_sequence = 0_u64;
    let mut state_digest = initial_known_state_digest(workspace_id)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;

    for (
        raw_changeset_id,
        persisted_workspace,
        raw_principal_id,
        persisted_changeset_digest,
        persisted_validation_digest,
        previous_state,
        commit_sequence,
        edit_count,
    ) in commits
    {
        if persisted_workspace != workspace_id.to_string() {
            return Err(LocalPortError::Integrity(
                "committed ChangeSet belongs to a different Workspace".to_owned(),
            ));
        }
        let changeset_id = raw_changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let principal_id = raw_principal_id
            .parse::<PrincipalId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if changeset_id.to_string() != raw_changeset_id
            || principal_id.to_string() != raw_principal_id
        {
            return Err(LocalPortError::Integrity(
                "committed identity is not canonical".to_owned(),
            ));
        }
        let row = load_inspected_changeset(
            connection,
            changeset_id,
            workspace_id,
            principal_id,
            storage_schema_version,
        )
        .map_err(local_port_from_inspection)?;
        let edits = load_inspected_edits(connection, changeset_id, storage_schema_version)
            .map_err(local_port_from_inspection)?;
        let changeset = row
            .into_inspected(changeset_id, workspace_id, principal_id, edits)
            .map_err(local_port_from_inspection)?;
        if changeset.status != ChangeSetStatus::Committed
            || changeset.base_authoritative_sequence != authoritative_sequence
            || changeset.base_state != state_digest
            || previous_state != state_digest.to_string()
            || usize::try_from(edit_count).ok() != Some(changeset.edits.len())
        {
            return Err(LocalPortError::Integrity(
                "committed ChangeSet does not continue the authoritative fact chain".to_owned(),
            ));
        }
        let changeset_digest =
            changeset_digest_for(&changeset).map_err(LocalPortError::Integrity)?;
        if persisted_changeset_digest != changeset_digest.to_string() {
            return Err(LocalPortError::Integrity(
                "committed ChangeSet digest does not reproduce".to_owned(),
            ));
        }
        let deterministic_validation =
            validate_rebuild_changeset(&changeset, changeset_digest, &schema_map)?;
        if !deterministic_validation.valid {
            return Err(LocalPortError::Integrity(
                "committed ChangeSet fails deterministic revalidation".to_owned(),
            ));
        }
        let validation_digest = verify_rebuild_evidence(
            connection,
            &changeset,
            changeset_digest,
            &persisted_validation_digest,
            &deterministic_validation,
        )?;
        for edit in &changeset.edits {
            authoritative_sequence = authoritative_sequence.checked_add(1).ok_or_else(|| {
                LocalPortError::Integrity("authoritative sequence overflow".to_owned())
            })?;
            match edit {
                InspectedChangeSetEdit::SchemaCreate(edit) => {
                    let key = (
                        edit.schema_id.as_str().to_owned(),
                        edit.schema_version.get(),
                    );
                    if schema_map.contains_key(&key) {
                        return Err(LocalPortError::Integrity(
                            "authoritative facts contain a duplicate immutable Schema target"
                                .to_owned(),
                        ));
                    }
                    schema_map.insert(
                        key,
                        ExpectedSchemaProjection {
                            schema_id: edit.schema_id.clone(),
                            schema_version: edit.schema_version,
                            document_json: edit.canonical_document.clone(),
                            document_digest: edit.document_digest,
                            changeset_id,
                            edit_id: edit.edit_id,
                            authoritative_sequence,
                        },
                    );
                }
                InspectedChangeSetEdit::ObjectCreate(edit) => {
                    let schema_key = (
                        edit.schema_id.as_str().to_owned(),
                        edit.schema_version.get(),
                    );
                    if !schema_map.contains_key(&schema_key) {
                        return Err(LocalPortError::Integrity(
                            "authoritative Object fact references no preceding Schema version"
                                .to_owned(),
                        ));
                    }
                    if object_map.contains_key(&edit.object_id) {
                        return Err(LocalPortError::Integrity(
                            "authoritative facts contain a duplicate immutable Object target"
                                .to_owned(),
                        ));
                    }
                    object_map.insert(
                        edit.object_id,
                        ExpectedObjectProjection {
                            object_id: edit.object_id,
                            revision: ObjectRevision::INITIAL,
                            schema_id: edit.schema_id.clone(),
                            schema_version: edit.schema_version,
                            content_json: edit.canonical_content.clone(),
                            object_digest: edit.object_digest,
                            changeset_id,
                            edit_id: edit.edit_id,
                            authoritative_sequence,
                        },
                    );
                }
            }
        }
        let expected_commit_sequence = u64::try_from(commit_sequence).map_err(|_| {
            LocalPortError::Integrity("commit sequence must be positive".to_owned())
        })?;
        if expected_commit_sequence != authoritative_sequence {
            return Err(LocalPortError::Integrity(
                "commit sequence does not equal its ordered Edit boundary".to_owned(),
            ));
        }
        state_digest = reproduced_state_digest(
            workspace_id,
            authoritative_sequence,
            &schema_map,
            &object_map,
        )?;
        let resulting_state: String = connection
            .query_row(
                "SELECT resulting_state FROM changeset_commits WHERE changeset_id = ?1",
                [changeset_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if resulting_state != state_digest.to_string()
            || validation_digest.to_string() != persisted_validation_digest
        {
            return Err(LocalPortError::Integrity(
                "commit result or validation binding does not reproduce".to_owned(),
            ));
        }
        edition_changesets.push(ExpectedEditionChangeSet {
            authoritative_sequence,
            reference: EditionChangeSet {
                changeset_id,
                changeset_digest,
            },
        });
    }
    let schemas = schema_map.into_values().collect::<Vec<_>>();
    let objects = object_map.into_values().collect::<Vec<_>>();
    Ok(ReproducedCommitFacts {
        workspace_id,
        schemas,
        objects,
        changesets: edition_changesets,
        authoritative_sequence,
        state_digest,
    })
}

fn reproduce_projections_from_facts(
    connection: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<ReproducedProjections, LocalPortError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let facts = reproduce_commit_facts(connection, workspace_id, schema_version)?;
    let localized = if schema_version >= 11 {
        localized::reproduce_localized_projections(
            connection,
            workspace_id,
            facts.authoritative_sequence,
            facts.state_digest,
            &facts.schemas,
            &facts.objects,
        )?
    } else {
        None
    };
    let (
        localized_renditions,
        known_state_api_version,
        known_state_manifest_json,
        authoritative_sequence,
        state_digest,
    ) = localized.map_or_else(
        || {
            (
                Vec::new(),
                KNOWN_STATE_V1_API_VERSION.to_owned(),
                None,
                facts.authoritative_sequence,
                facts.state_digest,
            )
        },
        |localized| {
            (
                localized.renditions,
                KNOWN_STATE_V2_API_VERSION.to_owned(),
                Some(localized.state_manifest_json),
                localized.authoritative_sequence,
                localized.state_digest,
            )
        },
    );
    Ok(ReproducedProjections {
        schemas: facts.schemas,
        objects: facts.objects,
        changesets: facts.changesets,
        localized_renditions,
        known_state_api_version,
        known_state_manifest_json,
        authoritative_sequence,
        state_digest,
    })
}

struct RebuildValidation {
    valid: bool,
    validator: String,
    results_json: String,
    results_digest: ContentDigest,
}

#[expect(
    clippy::too_many_lines,
    reason = "rebuild validation deliberately mirrors normal validation while resolving Schemas from reconstructed facts"
)]
fn validate_rebuild_changeset(
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    preceding_schemas: &BTreeMap<(String, u32), ExpectedSchemaProjection>,
) -> Result<RebuildValidation, LocalPortError> {
    let mut schemas = BTreeMap::<(String, u32), serde_json::Value>::new();
    for (key, schema) in preceding_schemas {
        let document = parse_strict(schema.document_json.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        schemas.insert(key.clone(), document);
    }
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
    let mut invalid_proposed_schemas = BTreeSet::<(String, u32)>::new();
    for edit in &changeset.edits {
        let index = edit
            .ordinal()
            .checked_sub(1)
            .ok_or_else(|| LocalPortError::Integrity("Edit ordinal must be positive".to_owned()))?;
        match edit {
            InspectedChangeSetEdit::SchemaCreate(edit) => {
                let document = parse_strict(edit.canonical_document.as_bytes())
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
                let target = (
                    edit.schema_id.as_str().to_owned(),
                    edit.schema_version.get(),
                );
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
                if schema_invalid {
                    invalid_proposed_schemas.insert(target.clone());
                }
                schemas.insert(target, document);
            }
            InspectedChangeSetEdit::ObjectCreate(edit) => {
                let content = parse_strict(edit.canonical_content.as_bytes())
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
                let target = (
                    edit.schema_id.as_str().to_owned(),
                    edit.schema_version.get(),
                );
                if invalid_proposed_schemas.contains(&target) {
                    continue;
                }
                let Some(schema) = schemas.get(&target) else {
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
                let validator = match jsonschema::draft202012::new(schema) {
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
    }
    .to_owned();
    let results = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/validation-results/v1",
        "base_state": changeset.base_state.to_string(),
        "changeset_digest": changeset_digest.to_string(),
        "changeset_id": changeset.changeset_id.to_string(),
        "findings": findings,
        "valid": valid,
        "validation_profile": changeset.validation_profile,
        "validator": validator,
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(RebuildValidation {
        valid,
        validator,
        results_json: results.as_str().to_owned(),
        results_digest: digest(ArtifactKind::ValidationResultsV1, &results),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "authoritative ChangeSet lifecycle evidence is fully reconstructed and cross-bound"
)]
fn verify_rebuild_evidence(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    persisted_commit_validation_digest: &str,
    deterministic: &RebuildValidation,
) -> Result<ContentDigest, LocalPortError> {
    type ValidationRow = (String, String, String, i64, String, String);
    let mut statement = connection
        .prepare(
            "SELECT base_state, validation_profile, validator, valid,
                    results_json, results_digest
             FROM changeset_validations
             WHERE changeset_id = ?1 AND changeset_digest = ?2",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            (
                changeset.changeset_id.to_string(),
                changeset_digest.to_string(),
            ),
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut validations = Vec::<ValidationRow>::new();
    for row in rows {
        validations.push(row.map_err(|error| LocalPortError::Storage(error.to_string()))?);
    }
    if validations.len() != 1 {
        return Err(LocalPortError::Integrity(
            "committed ChangeSet must bind exactly one validation result".to_owned(),
        ));
    }
    let (base_state, validation_profile, validator, valid, results_json, results_digest) =
        validations.pop().expect("length checked");
    let value = parse_strict(results_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let reproduced_digest = digest(ArtifactKind::ValidationResultsV1, &canonical);
    let object = value.as_object().ok_or_else(|| {
        LocalPortError::Integrity("validation result is not an object".to_owned())
    })?;
    let field = |name: &str| object.get(name).and_then(serde_json::Value::as_str);
    if canonical.as_str() != results_json
        || valid != 1
        || base_state != changeset.base_state.to_string()
        || validation_profile != changeset.validation_profile
        || validator != deterministic.validator
        || field("api_version") != Some("proof.dev/validation-results/v1")
        || field("base_state") != Some(changeset.base_state.to_string().as_str())
        || field("changeset_digest") != Some(changeset_digest.to_string().as_str())
        || field("changeset_id") != Some(changeset.changeset_id.to_string().as_str())
        || field("validation_profile") != Some(validation_profile.as_str())
        || field("validator") != Some(validator.as_str())
        || object.get("valid").and_then(serde_json::Value::as_bool) != Some(true)
        || results_digest != reproduced_digest.to_string()
        || results_json != deterministic.results_json
        || reproduced_digest != deterministic.results_digest
        || persisted_commit_validation_digest != results_digest
    {
        return Err(LocalPortError::Integrity(
            "validation evidence does not reproduce the committed ChangeSet".to_owned(),
        ));
    }
    let submission: Option<(String, String, String)> = connection
        .query_row(
            "SELECT changeset_digest, validation_results_digest, principal_id
             FROM changeset_submissions WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let approval: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT approval_name, changeset_digest, validation_results_digest, principal_id
             FROM changeset_approvals WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((submitted_changeset, submitted_validation, submitted_principal)) = submission else {
        return Err(LocalPortError::Integrity(
            "committed ChangeSet is missing submission evidence".to_owned(),
        ));
    };
    let Some((approval_name, approved_changeset, approved_validation, approved_principal)) =
        approval
    else {
        return Err(LocalPortError::Integrity(
            "committed ChangeSet is missing approval evidence".to_owned(),
        ));
    };
    ApprovalName::new(approval_name)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if submitted_changeset != changeset_digest.to_string()
        || submitted_validation != reproduced_digest.to_string()
        || submitted_principal != changeset.principal_id.to_string()
        || approved_changeset != changeset_digest.to_string()
        || approved_validation != reproduced_digest.to_string()
        || approved_principal != changeset.principal_id.to_string()
    {
        return Err(LocalPortError::Integrity(
            "submission or approval evidence is not bound to the committed ChangeSet".to_owned(),
        ));
    }
    Ok(reproduced_digest)
}

fn reproduced_state_digest(
    workspace_id: WorkspaceId,
    authoritative_sequence: u64,
    schemas: &BTreeMap<(String, u32), ExpectedSchemaProjection>,
    objects: &BTreeMap<ObjectId, ExpectedObjectProjection>,
) -> Result<ContentDigest, LocalPortError> {
    let schema_references = schemas
        .values()
        .map(|schema| {
            (
                schema.schema_id.clone(),
                schema.schema_version,
                schema.document_digest,
            )
        })
        .collect::<Vec<_>>();
    let object_references = objects
        .values()
        .map(|object| ObjectStateReference {
            object_id: object.object_id,
            revision: object.revision,
            schema_id: object.schema_id.clone(),
            schema_version: object.schema_version,
            lifecycle_state: ObjectLifecycleState::Active,
            object_digest: object.object_digest,
        })
        .collect::<Vec<_>>();
    known_state_digest_with_objects(
        workspace_id,
        authoritative_sequence,
        &schema_references,
        &object_references,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

#[expect(
    clippy::too_many_lines,
    reason = "projection rebuild must reconstruct an Edition from authoritative facts without consulting repairable projections"
)]
fn load_edition_from_reproduced(
    connection: &Connection,
    edition_id: EditionId,
    workspace_id: WorkspaceId,
    reproduced: ReproducedEditionData<'_>,
) -> Result<Edition, LocalPortError> {
    type EditionRow = (
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
    );
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let persisted: Option<EditionRow> = connection
        .query_row(
            "SELECT workspace_id, principal_id, authoritative_sequence, state_digest,
                    schema_set_digest, object_set_digest, edition_digest,
                    manifest_json, created_at
             FROM editions WHERE edition_id = ?1",
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
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((
        persisted_workspace,
        raw_principal,
        raw_sequence,
        raw_state_digest,
        persisted_schema_set_digest,
        persisted_object_set_digest,
        persisted_edition_digest,
        persisted_manifest,
        raw_created_at,
    )) = persisted
    else {
        return Err(LocalPortError::NotFound);
    };
    if persisted_workspace != workspace_id.to_string() {
        return Err(LocalPortError::Integrity(
            "Release Edition belongs to a different Workspace".to_owned(),
        ));
    }
    let principal_id = raw_principal
        .parse::<PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if principal_id.to_string() != raw_principal {
        return Err(LocalPortError::Integrity(
            "Release Edition Principal identity is not canonical".to_owned(),
        ));
    }
    let authoritative_sequence = u64::try_from(raw_sequence)
        .map_err(|_| LocalPortError::Integrity("invalid Edition sequence".to_owned()))?;
    let state_digest = raw_state_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if state_digest.to_string() != raw_state_digest {
        return Err(LocalPortError::Integrity(
            "Release Edition state digest is not canonical".to_owned(),
        ));
    }
    let schemas = reproduced
        .schemas
        .iter()
        .filter(|schema| schema.authoritative_sequence <= authoritative_sequence)
        .map(|schema| EditionSchema {
            schema_id: schema.schema_id.clone(),
            schema_version: schema.schema_version,
            document_digest: schema.document_digest,
        })
        .collect::<Vec<_>>();
    let objects = reproduced
        .objects
        .iter()
        .filter(|object| object.authoritative_sequence <= authoritative_sequence)
        .map(|object| EditionObject {
            object_id: object.object_id,
            revision: object.revision,
            schema_id: object.schema_id.clone(),
            schema_version: object.schema_version,
            lifecycle_state: ObjectLifecycleState::Active,
            object_digest: object.object_digest,
        })
        .collect::<Vec<_>>();
    let changesets = reproduced
        .changesets
        .iter()
        .filter(|changeset| changeset.authoritative_sequence <= authoritative_sequence)
        .map(|changeset| changeset.reference)
        .collect::<Vec<_>>();
    let boundary = reproduced
        .changesets
        .iter()
        .rfind(|changeset| changeset.authoritative_sequence <= authoritative_sequence)
        .map(|changeset| changeset.authoritative_sequence);
    if (authoritative_sequence == 0 && boundary.is_some())
        || (authoritative_sequence != 0 && boundary != Some(authoritative_sequence))
    {
        return Err(LocalPortError::Integrity(
            "Release Edition is not at an authoritative ChangeSet boundary".to_owned(),
        ));
    }
    let schema_references = schemas
        .iter()
        .map(|schema| {
            (
                schema.schema_id.clone(),
                schema.schema_version,
                schema.document_digest,
            )
        })
        .collect::<Vec<_>>();
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
    let expected_state = known_state_digest_with_objects(
        workspace_id,
        authoritative_sequence,
        &schema_references,
        &object_references,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if state_digest != expected_state {
        return Err(LocalPortError::Integrity(
            "Release Edition Known State does not reproduce from authoritative facts".to_owned(),
        ));
    }
    let expected = build_edition_manifest(
        workspace_id,
        authoritative_sequence,
        state_digest,
        &schemas,
        &objects,
        &changesets,
    )
    .map_err(local_port_from_edition)?;
    if persisted_schema_set_digest != expected.schema_set_digest.to_string()
        || persisted_object_set_digest != expected.object_set_digest.map(|value| value.to_string())
        || persisted_edition_digest != expected.edition_digest.to_string()
        || persisted_manifest != expected.manifest_json.as_str()
    {
        return Err(LocalPortError::Integrity(
            "Release Edition immutable manifest does not reproduce from authoritative facts"
                .to_owned(),
        ));
    }
    let created_at = raw_created_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if created_at.to_string() != raw_created_at {
        return Err(LocalPortError::Integrity(
            "Release Edition creation timestamp is not canonical".to_owned(),
        ));
    }
    let latest_commit = latest_included_commit_timestamp(connection, authoritative_sequence)
        .map_err(local_port_from_edition)?;
    if created_at < latest_commit {
        return Err(LocalPortError::Integrity(
            "Edition creation timestamp predates latest included commit".to_owned(),
        ));
    }
    let edition = Edition {
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
    };
    verify_edition_operation_effects(connection, schema_version, &edition)
        .map_err(local_port_from_edition)?;
    Ok(edition)
}

fn reproduce_environment_pointers(
    connection: &Transaction<'_>,
    workspace_id: WorkspaceId,
    reproduced: ReproducedEditionData<'_>,
) -> Result<Vec<ExpectedEnvironmentPointer>, LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT release_id, release_sequence, api_version
             FROM releases ORDER BY release_sequence",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut heads = BTreeMap::<EnvironmentId, ExpectedEnvironmentPointer>::new();
    let mut expected_global_sequence = 0_u64;
    for row in rows {
        let (raw_release, sequence, api_version) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        expected_global_sequence = expected_global_sequence.checked_add(1).ok_or_else(|| {
            LocalPortError::Integrity("global Release sequence overflow".to_owned())
        })?;
        if u64::try_from(sequence).ok() != Some(expected_global_sequence) {
            return Err(LocalPortError::Integrity(
                "immutable Release history has a non-contiguous sequence".to_owned(),
            ));
        }
        let release_id = raw_release
            .parse::<ReleaseId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if release_id.to_string() != raw_release {
            return Err(LocalPortError::Integrity(
                "immutable Release identity is not canonical".to_owned(),
            ));
        }
        let (verified_sequence, environment_id, previous_release_id) = match api_version.as_str() {
            "proof.dev/release/v1" => {
                let release = load_release_record_from_reproduced(
                    connection,
                    workspace_id,
                    release_id,
                    reproduced,
                )?;
                (
                    release.release_sequence,
                    release.environment_id,
                    release.previous_release_id,
                )
            }
            LOCALIZED_RELEASE_API_VERSION => {
                localized::load_localized_release_chain_node(connection, workspace_id, release_id)?
            }
            _ => return Err(LocalPortError::UnsupportedVersion),
        };
        if verified_sequence != expected_global_sequence {
            return Err(LocalPortError::Integrity(
                "verified Release sequence differs from immutable history".to_owned(),
            ));
        }
        let expected_previous = heads.get(&environment_id).map(|pointer| pointer.release_id);
        if previous_release_id != expected_previous {
            return Err(LocalPortError::Integrity(
                "immutable Release history has a broken Environment predecessor chain".to_owned(),
            ));
        }
        heads.insert(
            environment_id.clone(),
            ExpectedEnvironmentPointer {
                environment_id,
                release_id,
                release_sequence: expected_global_sequence,
            },
        );
    }
    Ok(heads.into_values().collect())
}

fn persisted_schema_projections(
    connection: &Connection,
) -> Result<Vec<ExpectedSchemaProjection>, LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_json, document_digest,
                    changeset_id, edit_id, authoritative_sequence
             FROM schema_versions ORDER BY schema_id, schema_version",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut projections = Vec::new();
    for row in rows {
        let (
            schema_id,
            schema_version,
            document_json,
            document_digest,
            changeset_id,
            edit_id,
            sequence,
        ) = row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        projections.push(ExpectedSchemaProjection {
            schema_id: SchemaId::new(schema_id)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            schema_version: SchemaVersion::new(u32::try_from(schema_version).map_err(|_| {
                LocalPortError::Integrity("invalid projected Schema version".to_owned())
            })?)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            document_json,
            document_digest: document_digest
                .parse::<ContentDigest>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            changeset_id: changeset_id
                .parse::<ChangeSetId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            edit_id: edit_id
                .parse::<EditId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            authoritative_sequence: u64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("invalid projected Schema sequence".to_owned())
            })?,
        });
    }
    Ok(projections)
}

fn persisted_object_projections(
    connection: &Connection,
) -> Result<Vec<ExpectedObjectProjection>, LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest, changeset_id, edit_id, authoritative_sequence
             FROM object_revisions ORDER BY object_id, revision",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut projections = Vec::new();
    for row in rows {
        let (
            object_id,
            revision,
            schema_id,
            schema_version,
            lifecycle,
            content_json,
            object_digest,
            changeset_id,
            edit_id,
            sequence,
        ) = row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if lifecycle != "active" {
            return Err(LocalPortError::Integrity(
                "projected Object lifecycle is unsupported".to_owned(),
            ));
        }
        projections.push(ExpectedObjectProjection {
            object_id: object_id
                .parse::<ObjectId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            revision: ObjectRevision::new(u32::try_from(revision).map_err(|_| {
                LocalPortError::Integrity("invalid projected Object revision".to_owned())
            })?)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            schema_id: SchemaId::new(schema_id)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            schema_version: SchemaVersion::new(u32::try_from(schema_version).map_err(|_| {
                LocalPortError::Integrity("invalid projected Object Schema version".to_owned())
            })?)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            content_json,
            object_digest: object_digest
                .parse::<ContentDigest>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            changeset_id: changeset_id
                .parse::<ChangeSetId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            edit_id: edit_id
                .parse::<EditId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            authoritative_sequence: u64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("invalid projected Object sequence".to_owned())
            })?,
        });
    }
    Ok(projections)
}

fn persisted_environment_pointers(
    connection: &Connection,
) -> Result<Vec<ExpectedEnvironmentPointer>, LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT environment_id, release_id, release_sequence, projection_version
             FROM environment_current_releases ORDER BY environment_id",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut pointers = Vec::new();
    for row in rows {
        let (environment_id, release_id, sequence, projection_version) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if projection_version != 1 {
            return Err(LocalPortError::Integrity(
                "Environment pointer projection version is unsupported".to_owned(),
            ));
        }
        pointers.push(ExpectedEnvironmentPointer {
            environment_id: environment_id
                .parse::<EnvironmentId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            release_id: release_id
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            release_sequence: u64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("invalid Environment pointer sequence".to_owned())
            })?,
        });
    }
    Ok(pointers)
}

fn local_port_from_inspection(error: InspectChangeSetError) -> LocalPortError {
    match error {
        InspectChangeSetError::Unauthenticated => LocalPortError::Unauthenticated,
        InspectChangeSetError::NotFound => LocalPortError::NotFound,
        InspectChangeSetError::Storage(detail) => LocalPortError::Storage(detail),
        InspectChangeSetError::Integrity(detail) => LocalPortError::Integrity(detail),
    }
}

fn rebuild_from_local_port(error: LocalPortError) -> RebuildProjectionsError {
    match error {
        LocalPortError::Unauthenticated => RebuildProjectionsError::Unauthenticated,
        LocalPortError::Storage(detail) => RebuildProjectionsError::Storage(detail),
        LocalPortError::Integrity(detail) => RebuildProjectionsError::Integrity(detail),
        other => RebuildProjectionsError::Integrity(format!(
            "unexpected projection-rebuild adapter state: {other:?}"
        )),
    }
}

fn delegation_from_latest(error: LatestSchemaError) -> DelegationError {
    match error {
        LatestSchemaError::Integrity(detail) => DelegationError::Integrity(detail),
        LatestSchemaError::Storage(detail) => DelegationError::Storage(detail),
    }
}

fn delegation_from_initialization(error: WorkspaceInitializationError) -> DelegationError {
    match error {
        WorkspaceInitializationError::IdentityUnavailable(_) => DelegationError::Unauthenticated,
        WorkspaceInitializationError::RootUnavailable(detail)
        | WorkspaceInitializationError::Storage(detail) => DelegationError::Storage(detail),
        WorkspaceInitializationError::AlreadyExists => {
            DelegationError::Integrity("unexpected Workspace initialization conflict".to_owned())
        }
    }
}

fn delegation_from_status(error: WorkspaceStatusError) -> DelegationError {
    match error {
        WorkspaceStatusError::Unauthenticated => DelegationError::Unauthenticated,
        WorkspaceStatusError::Integrity(detail) => DelegationError::Integrity(detail),
        WorkspaceStatusError::Storage(detail) => DelegationError::Storage(detail),
        WorkspaceStatusError::Incomplete => {
            DelegationError::Integrity("the selected Workspace has incomplete state".to_owned())
        }
    }
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
        2..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        3..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        4..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        5..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        6..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        7..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
        8..=LATEST_DATABASE_SCHEMA_VERSION => Ok(()),
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
    if !(9..=LATEST_DATABASE_SCHEMA_VERSION).contains(&version) {
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
    insert_if_missing: bool,
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
    if insert_if_missing {
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
    }
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
        .optional()
        .map_err(|error| ValidateChangeSetError::Storage(error.to_string()))?
        .ok_or_else(|| {
            ValidateChangeSetError::Integrity(
                "persisted validation evidence is missing for a completed validation".to_owned(),
            )
        })?;
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
    if matches!(
        changeset.status,
        ChangeSetStatus::Submitted | ChangeSetStatus::Approved | ChangeSetStatus::Committed
    ) {
        return replay_submission(
            transaction,
            changeset,
            changeset_digest,
            validation_results_digest,
            edit_count,
        );
    }
    if command.submitted_at < changeset.created_at {
        return Err(SubmitChangeSetError::Integrity(
            "submission timestamp predates ChangeSet creation".to_owned(),
        ));
    }
    let submitted = SubmittedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        validation_results_digest,
        base_state: changeset.base_state,
        submitted_at: command.submitted_at,
        status: ChangeSetStatus::Submitted,
        edit_count,
    };
    let schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    if schema_version >= 10 {
        let effect_digest = changeset_submission_effect_digest(&submitted)
            .map_err(SubmitChangeSetError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO changeset_submissions (
                     changeset_id, changeset_digest, validation_results_digest,
                     principal_id, submitted_at, effect_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    command.changeset_id.to_string(),
                    changeset_digest.to_string(),
                    validation_results_digest.to_string(),
                    changeset.principal_id.to_string(),
                    command.submitted_at.to_string(),
                    effect_digest.to_string(),
                ),
            )
            .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    } else {
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
    }
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
    Ok(submitted)
}

fn replay_submission(
    connection: &Connection,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
    edit_count: u32,
) -> Result<SubmittedChangeSet, SubmitChangeSetError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| SubmitChangeSetError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let persisted: (String, String, String, String, Option<String>) = connection
        .query_row(
            &format!(
                "SELECT changeset_digest, validation_results_digest, principal_id,
                        submitted_at, {effect_column}
                 FROM changeset_submissions WHERE changeset_id = ?1"
            ),
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
    let submitted = SubmittedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        changeset_digest,
        validation_results_digest,
        base_state: changeset.base_state,
        submitted_at,
        status: ChangeSetStatus::Submitted,
        edit_count,
    };
    if schema_version >= 10 {
        let persisted_effect = persisted.4.ok_or_else(|| {
            SubmitChangeSetError::Integrity("submission effect is missing".to_owned())
        })?;
        let expected = changeset_submission_effect_digest(&submitted)
            .map_err(SubmitChangeSetError::Integrity)?;
        if persisted_effect != expected.to_string() {
            return Err(SubmitChangeSetError::Integrity(
                "submission effect does not reproduce".to_owned(),
            ));
        }
    }
    Ok(submitted)
}

fn persist_or_replay_approval(
    transaction: &Transaction<'_>,
    command: &ApproveChangeSetCommand,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
    if matches!(
        changeset.status,
        ChangeSetStatus::Approved | ChangeSetStatus::Committed
    ) {
        return replay_approval(
            transaction,
            command,
            changeset,
            changeset_digest,
            validation_results_digest,
        );
    }
    let submitted_at = transaction
        .query_row(
            "SELECT submitted_at FROM changeset_submissions WHERE changeset_id = ?1",
            [changeset.changeset_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?
        .parse::<Timestamp>()
        .map_err(|error| ApproveChangeSetError::Integrity(error.to_string()))?;
    if command.approved_at < submitted_at {
        return Err(ApproveChangeSetError::Integrity(
            "approval timestamp predates submission".to_owned(),
        ));
    }
    let approved = ApprovedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        approval: command.approval.clone(),
        changeset_digest,
        validation_results_digest,
        approved_at: command.approved_at,
        status: ChangeSetStatus::Approved,
    };
    let schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    if schema_version >= 10 {
        let effect_digest = changeset_approval_effect_digest(&approved)
            .map_err(ApproveChangeSetError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO changeset_approvals (
                     changeset_id, approval_name, changeset_digest,
                     validation_results_digest, principal_id, approved_at, effect_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    command.changeset_id.to_string(),
                    command.approval.as_str(),
                    changeset_digest.to_string(),
                    validation_results_digest.to_string(),
                    changeset.principal_id.to_string(),
                    command.approved_at.to_string(),
                    effect_digest.to_string(),
                ),
            )
            .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    } else {
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
    }
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
    Ok(approved)
}

fn replay_approval(
    connection: &Connection,
    command: &ApproveChangeSetCommand,
    changeset: &InspectedChangeSet,
    changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ApprovedChangeSet, ApproveChangeSetError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| ApproveChangeSetError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let persisted: (String, String, String, String, String, Option<String>) = connection
        .query_row(
            &format!(
                "SELECT approval_name, changeset_digest, validation_results_digest,
                        principal_id, approved_at, {effect_column}
                 FROM changeset_approvals WHERE changeset_id = ?1"
            ),
            [changeset.changeset_id.to_string()],
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
    let approved = ApprovedChangeSet {
        changeset_id: changeset.changeset_id,
        workspace_id: changeset.workspace_id,
        principal_id: changeset.principal_id,
        approval: command.approval.clone(),
        changeset_digest,
        validation_results_digest,
        approved_at,
        status: ChangeSetStatus::Approved,
    };
    if schema_version >= 10 {
        let persisted_effect = persisted.5.ok_or_else(|| {
            ApproveChangeSetError::Integrity("approval effect is missing".to_owned())
        })?;
        let expected = changeset_approval_effect_digest(&approved)
            .map_err(ApproveChangeSetError::Integrity)?;
        if persisted_effect != expected.to_string() {
            return Err(ApproveChangeSetError::Integrity(
                "approval effect does not reproduce".to_owned(),
            ));
        }
    }
    Ok(approved)
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
    effect_digest: Option<String>,
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
    let approved_at = transaction
        .query_row(
            "SELECT approved_at FROM changeset_approvals WHERE changeset_id = ?1",
            [verified.changeset.changeset_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?
        .parse::<Timestamp>()
        .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
    if command.committed_at < approved_at {
        return Err(CommitChangeSetError::Integrity(
            "commit timestamp predates approval".to_owned(),
        ));
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
    let committed = CommittedChangeSet {
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
    };
    persist_commit(transaction, command, &verified, &pending, &committed)?;
    Ok(committed)
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
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let persisted: Option<(String, String, String, String, String, Option<String>)> = connection
        .query_row(
            &format!(
                "SELECT approval_name, changeset_digest, validation_results_digest,
                        principal_id, approved_at, {effect_column}
                 FROM changeset_approvals WHERE changeset_id = ?1"
            ),
            [changeset.changeset_id.to_string()],
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
        .optional()
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let (
        approval_name,
        persisted_changeset,
        persisted_validation,
        persisted_principal,
        raw_approved_at,
        persisted_effect,
    ) = persisted.ok_or(CommitChangeSetError::EvidenceMissing)?;
    let approval = proof_application::ApprovalName::new(approval_name)
        .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
    if persisted_changeset != changeset_digest.to_string()
        || persisted_validation != validation_results_digest.to_string()
        || persisted_principal != changeset.principal_id.to_string()
    {
        return Err(CommitChangeSetError::Integrity(
            "persisted approval does not match exact validated ChangeSet evidence".to_owned(),
        ));
    }
    if schema_version >= 10 {
        let approved_at = raw_approved_at
            .parse::<Timestamp>()
            .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
        let approved = ApprovedChangeSet {
            changeset_id: changeset.changeset_id,
            workspace_id: changeset.workspace_id,
            principal_id: changeset.principal_id,
            approval,
            changeset_digest,
            validation_results_digest,
            approved_at,
            status: ChangeSetStatus::Approved,
        };
        let expected =
            changeset_approval_effect_digest(&approved).map_err(CommitChangeSetError::Integrity)?;
        if persisted_effect.as_deref() != Some(expected.to_string().as_str()) {
            return Err(CommitChangeSetError::Integrity(
                "approval effect does not reproduce".to_owned(),
            ));
        }
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
    committed: &CommittedChangeSet,
) -> Result<(), CommitChangeSetError> {
    let stored_sequence = i64::try_from(pending.authoritative_sequence).map_err(|_| {
        CommitChangeSetError::Integrity(
            "authoritative sequence exceeds local storage range".to_owned(),
        )
    })?;
    let edit_count = i64::try_from(verified.changeset.edits.len())
        .map_err(|_| CommitChangeSetError::Integrity("Edit count exceeds i64".to_owned()))?;
    let schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    if schema_version >= 10 {
        let effect_digest = changeset_commit_effect_digest(command.idempotency_key, committed)
            .map_err(CommitChangeSetError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO changeset_commits (
                     changeset_id, workspace_id, principal_id, idempotency_key,
                     changeset_digest, validation_results_digest, previous_state,
                     resulting_state, authoritative_sequence, committed_at, edit_count,
                     effect_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
                    effect_digest.to_string(),
                ),
            )
            .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    } else {
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
    }
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

#[expect(
    clippy::too_many_lines,
    reason = "commit replay reconstructs and verifies the complete persisted effect"
)]
fn replay_commit(
    connection: &Connection,
    command: &CommitChangeSetCommand,
    verified: &VerifiedCommitProposal,
) -> Result<CommittedChangeSet, CommitChangeSetError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let persisted: Option<PersistedCommitRow> = connection
        .query_row(
            &format!(
                "SELECT idempotency_key, changeset_digest, validation_results_digest,
                        previous_state, resulting_state, authoritative_sequence,
                        committed_at, edit_count, {effect_column}
                 FROM changeset_commits WHERE changeset_id = ?1"
            ),
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
                    effect_digest: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(|error| CommitChangeSetError::Storage(error.to_string()))?;
    let persisted = persisted.ok_or(CommitChangeSetError::EvidenceMissing)?;
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
    let committed = CommittedChangeSet {
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
    };
    if schema_version >= 10 {
        let effect_digest = persisted.effect_digest.ok_or_else(|| {
            CommitChangeSetError::Integrity("commit effect is missing".to_owned())
        })?;
        let idempotency_key = persisted
            .idempotency_key
            .parse::<IdempotencyKey>()
            .map_err(|error| CommitChangeSetError::Integrity(error.to_string()))?;
        if idempotency_key.to_string() != persisted.idempotency_key {
            return Err(CommitChangeSetError::Integrity(
                "commit idempotency key is not canonical".to_owned(),
            ));
        }
        let expected = changeset_commit_effect_digest(idempotency_key, &committed)
            .map_err(CommitChangeSetError::Integrity)?;
        if effect_digest != expected.to_string() {
            return Err(CommitChangeSetError::Integrity(
                "commit effect does not reproduce".to_owned(),
            ));
        }
    }
    if persisted.idempotency_key != command.idempotency_key.to_string() {
        return Err(CommitChangeSetError::IdempotencyKeyReused);
    }
    Ok(committed)
}

struct EditionManifest {
    schema_set_digest: ContentDigest,
    object_set_digest: Option<ContentDigest>,
    manifest_json: String,
    edition_digest: ContentDigest,
}

fn latest_included_commit_timestamp(
    connection: &Connection,
    authoritative_sequence: u64,
) -> Result<Timestamp, CreateEditionError> {
    let mut statement = connection
        .prepare(
            "SELECT committed_at FROM changeset_commits
             WHERE authoritative_sequence <= ?1 ORDER BY authoritative_sequence",
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(authoritative_sequence).map_err(|_| {
                CreateEditionError::Integrity("invalid Edition sequence".to_owned())
            })?],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut latest = None;
    for row in rows {
        let raw_timestamp = row.map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        let timestamp = raw_timestamp
            .parse::<Timestamp>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if timestamp.to_string() != raw_timestamp {
            return Err(CreateEditionError::Integrity(
                "commit timestamp is not canonical".to_owned(),
            ));
        }
        latest = Some(match latest {
            Some(current) => std::cmp::max(current, timestamp),
            None => timestamp,
        });
    }
    latest.ok_or_else(|| {
        CreateEditionError::Integrity(
            "Edition authoritative range has no committed ChangeSet".to_owned(),
        )
    })
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
        let edition = load_edition(transaction, edition_id)?;
        record_edition_operation(
            transaction,
            workspace_id,
            principal_id,
            command.idempotency_key,
            state_digest,
            &edition,
        )?;
        return Ok(edition);
    }
    let latest_commit = latest_included_commit_timestamp(transaction, authoritative_sequence)?;
    if command.created_at < latest_commit {
        return Err(CreateEditionError::Integrity(
            "Edition creation timestamp predates latest included commit".to_owned(),
        ));
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
    let edition = Edition {
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
    };
    record_edition_operation(
        transaction,
        workspace_id,
        principal_id,
        command.idempotency_key,
        state_digest,
        &edition,
    )?;
    Ok(edition)
}

fn replay_edition_operation(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
    state_digest: ContentDigest,
) -> Result<Option<Edition>, CreateEditionError> {
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let persisted: Option<(String, String, Option<String>)> = connection
        .query_row(
            &format!(
                "SELECT requested_state_digest, edition_id, {effect_column}
                 FROM edition_create_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3"
            ),
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                idempotency_key.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let Some((requested_state, edition_id, persisted_effect)) = persisted else {
        return Ok(None);
    };
    if requested_state != state_digest.to_string() {
        return Err(CreateEditionError::IdempotencyKeyReused);
    }
    let edition_id = edition_id
        .parse::<EditionId>()
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
    let edition = load_edition(connection, edition_id)?;
    if schema_version >= 10 {
        let persisted_effect = persisted_effect.ok_or_else(|| {
            CreateEditionError::Integrity("Edition creation effect is missing".to_owned())
        })?;
        let expected =
            edition_create_operation_effect_digest(idempotency_key, state_digest, &edition)
                .map_err(CreateEditionError::Integrity)?;
        if persisted_effect != expected.to_string() {
            return Err(CreateEditionError::Integrity(
                "Edition creation effect does not reproduce".to_owned(),
            ));
        }
    }
    Ok(Some(edition))
}

fn record_edition_operation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
    state_digest: ContentDigest,
    edition: &Edition,
) -> Result<(), CreateEditionError> {
    let schema_version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if schema_version >= 10 {
        let effect_digest =
            edition_create_operation_effect_digest(idempotency_key, state_digest, edition)
                .map_err(CreateEditionError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO edition_create_operations (
                     workspace_id, principal_id, idempotency_key,
                     requested_state_digest, edition_id, effect_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                (
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    idempotency_key.to_string(),
                    state_digest.to_string(),
                    edition.edition_id.to_string(),
                    effect_digest.to_string(),
                ),
            )
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    } else {
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
                    edition.edition_id.to_string(),
                ),
            )
            .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    }
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
    let api_version_column = if schema_version >= 11 {
        "api_version"
    } else {
        "'proof.dev/edition/v1' AS api_version"
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
        String,
    ) = connection
        .query_row(
            &format!(
                "SELECT workspace_id, principal_id, authoritative_sequence, state_digest,
                        schema_set_digest, {object_set_column}, edition_digest,
                        manifest_json, created_at, {api_version_column}
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
                    row.get(9)?,
                ))
            },
        )
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    if persisted.9 != proof_application::EDITION_V1_API_VERSION {
        return Err(CreateEditionError::Integrity(
            "v1 Edition reader cannot interpret a non-v1 Edition".to_owned(),
        ));
    }
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
    let latest_commit = latest_included_commit_timestamp(connection, authoritative_sequence)?;
    if created_at < latest_commit {
        return Err(CreateEditionError::Integrity(
            "Edition creation timestamp predates latest included commit".to_owned(),
        ));
    }
    let edition = Edition {
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
    };
    verify_edition_operation_effects(connection, schema_version, &edition)?;
    Ok(edition)
}

fn verify_edition_operation_effects(
    connection: &Connection,
    schema_version: u32,
    edition: &Edition,
) -> Result<(), CreateEditionError> {
    if schema_version < 8 {
        return Ok(());
    }
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT workspace_id, principal_id, idempotency_key,
                    requested_state_digest, {effect_column}
             FROM edition_create_operations WHERE edition_id = ?1
             ORDER BY workspace_id, principal_id, idempotency_key"
        ))
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([edition.edition_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|error| CreateEditionError::Storage(error.to_string()))?;
    let mut count = 0_usize;
    for row in rows {
        let (raw_workspace, raw_principal, raw_key, raw_state, persisted_effect) =
            row.map_err(|error| CreateEditionError::Storage(error.to_string()))?;
        let operation_workspace = raw_workspace
            .parse::<WorkspaceId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let operation_principal = raw_principal
            .parse::<PrincipalId>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let operation_key = raw_key
            .parse::<IdempotencyKey>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let requested_state = raw_state
            .parse::<ContentDigest>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if operation_workspace.to_string() != raw_workspace
            || operation_principal.to_string() != raw_principal
            || operation_key.to_string() != raw_key
            || requested_state.to_string() != raw_state
            || operation_workspace != edition.workspace_id
            || operation_principal != edition.principal_id
            || requested_state != edition.state_digest
        {
            return Err(CreateEditionError::Integrity(
                "Edition creation operation identity is invalid".to_owned(),
            ));
        }
        if schema_version >= 10 {
            let persisted_effect = persisted_effect.ok_or_else(|| {
                CreateEditionError::Integrity("Edition creation effect is missing".to_owned())
            })?;
            let expected =
                edition_create_operation_effect_digest(operation_key, requested_state, edition)
                    .map_err(CreateEditionError::Integrity)?;
            if persisted_effect != expected.to_string() {
                return Err(CreateEditionError::Integrity(
                    "Edition creation effect does not reproduce".to_owned(),
                ));
            }
        }
        count += 1;
    }
    if count == 0 {
        return Err(CreateEditionError::Integrity(
            "Edition creation operation is missing".to_owned(),
        ));
    }
    Ok(())
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
                    authoritative_sequence, edit_count, validation_results_digest,
                    idempotency_key, committed_at
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
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
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
            raw_validation_digest,
            raw_commit_key,
            raw_committed_at,
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
        let validation_results_digest = raw_validation_digest
            .parse::<ContentDigest>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if validation_results_digest.to_string() != raw_validation_digest {
            return Err(CreateEditionError::Integrity(
                "committed validation-results digest is not canonical".to_owned(),
            ));
        }
        replay_submission(
            connection,
            &inspected,
            changeset_digest,
            validation_results_digest,
            u32::try_from(inspected.edits.len()).map_err(|_| {
                CreateEditionError::Integrity("ChangeSet Edit count exceeds u32".to_owned())
            })?,
        )
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        verify_approval_evidence(
            connection,
            &inspected,
            changeset_digest,
            validation_results_digest,
        )
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let commit_key = raw_commit_key
            .parse::<IdempotencyKey>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        let committed_at = raw_committed_at
            .parse::<Timestamp>()
            .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
        if commit_key.to_string() != raw_commit_key || committed_at.to_string() != raw_committed_at
        {
            return Err(CreateEditionError::Integrity(
                "commit operation identity is not canonical".to_owned(),
            ));
        }
        replay_commit(
            connection,
            &CommitChangeSetCommand {
                changeset_id,
                idempotency_key: commit_key,
                committed_at,
            },
            &VerifiedCommitProposal {
                changeset: inspected.clone(),
                changeset_digest,
                validation_results_digest,
            },
        )
        .map_err(|error| CreateEditionError::Integrity(error.to_string()))?;
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

#[expect(
    clippy::too_many_arguments,
    reason = "the effect commitment binds the complete persisted append result"
)]
fn edit_batch_operation_effect_digest(
    request_digest: ContentDigest,
    idempotency_key: IdempotencyKey,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    changeset_id: ChangeSetId,
    first_ordinal: u32,
    added_count: u32,
    total_edit_count: u32,
    edits: &[ChangeSetEdit],
) -> Result<ContentDigest, String> {
    operation_effect_digest(
        "changeset.edits.add",
        request_digest,
        &serde_json::json!({
            "added_count": added_count,
            "changeset_id": changeset_id.to_string(),
            "edit_ids": edits
                .iter()
                .map(|edit| edit.edit_id().to_string())
                .collect::<Vec<_>>(),
            "first_ordinal": first_ordinal,
            "idempotency_key": idempotency_key.to_string(),
            "principal_id": principal_id.to_string(),
            "total_edit_count": total_edit_count,
            "workspace_id": workspace_id.to_string(),
        }),
    )
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

#[expect(
    clippy::too_many_lines,
    reason = "replay verifies legacy and v10 semantic plus exact-effect commitments before returning"
)]
fn replay_edit_batch(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    changeset_id: ChangeSetId,
    idempotency_key: IdempotencyKey,
    request_digest: ContentDigest,
    storage_schema_version: u32,
) -> Result<Option<AddedChangeSetEdits>, AddChangeSetEditsError> {
    let effect_column = if storage_schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let mut operation_statement = connection
        .prepare(&format!(
            "SELECT changeset_id, idempotency_key, request_digest, {effect_column},
                    first_ordinal, added_count, total_edit_count
             FROM changeset_add_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3
             ORDER BY changeset_id"
        ))
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let persisted = operation_statement
        .query_map(
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                idempotency_key.to_string(),
            ),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    if persisted.len() > 1 {
        return Err(AddChangeSetEditsError::Integrity(
            "the Edit idempotency key is bound to multiple ChangeSets".to_owned(),
        ));
    }
    let Some((
        persisted_changeset_id,
        persisted_idempotency_key,
        persisted_digest,
        persisted_effect_digest,
        first_ordinal,
        added_count,
        total_edit_count,
    )) = persisted.into_iter().next()
    else {
        return Ok(None);
    };
    let raw_persisted_changeset_id = persisted_changeset_id;
    let persisted_changeset_id = raw_persisted_changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
    if persisted_changeset_id.to_string() != raw_persisted_changeset_id {
        return Err(AddChangeSetEditsError::Integrity(
            "persisted Edit operation ChangeSet identity is not canonical".to_owned(),
        ));
    }
    let parsed_idempotency_key = persisted_idempotency_key
        .parse::<IdempotencyKey>()
        .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
    if parsed_idempotency_key.to_string() != persisted_idempotency_key {
        return Err(AddChangeSetEditsError::Integrity(
            "persisted Edit operation idempotency key is not canonical".to_owned(),
        ));
    }
    let raw_persisted_digest = persisted_digest;
    let persisted_digest = raw_persisted_digest
        .parse::<ContentDigest>()
        .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
    if persisted_digest.to_string() != raw_persisted_digest {
        return Err(AddChangeSetEditsError::Integrity(
            "persisted Edit operation request digest is not canonical".to_owned(),
        ));
    }
    let first_ordinal = positive_u32(first_ordinal, "first Edit ordinal")?;
    let added_count = positive_u32(added_count, "added Edit count")?;
    let total_edit_count = positive_u32(total_edit_count, "total Edit count")?;
    let final_ordinal = first_ordinal
        .checked_add(added_count - 1)
        .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit ordinal overflow".to_owned()))?;
    if total_edit_count != final_ordinal {
        return Err(AddChangeSetEditsError::Integrity(
            "idempotent Edit result ordinals are inconsistent".to_owned(),
        ));
    }
    let persisted_edits = load_persisted_edit_batch(
        connection,
        persisted_changeset_id,
        first_ordinal,
        final_ordinal,
        storage_schema_version,
    )?;
    if persisted_edits.len() != usize::try_from(added_count).unwrap_or(usize::MAX) {
        return Err(AddChangeSetEditsError::Integrity(
            "idempotent Edit result is incomplete".to_owned(),
        ));
    }
    let reproduced_request_digest =
        verified_edit_batch(&persisted_edits).map_err(|error| match error {
            AddChangeSetEditsError::Integrity(detail) => AddChangeSetEditsError::Integrity(detail),
            AddChangeSetEditsError::Storage(detail) => AddChangeSetEditsError::Storage(detail),
            other => AddChangeSetEditsError::Integrity(format!(
                "persisted Edit batch is invalid: {other}"
            )),
        })?;
    if reproduced_request_digest != persisted_digest {
        return Err(AddChangeSetEditsError::Integrity(
            "persisted Edit batch does not match its operation digest".to_owned(),
        ));
    }
    if storage_schema_version >= 10 {
        let persisted_effect_digest = persisted_effect_digest
            .ok_or_else(|| {
                AddChangeSetEditsError::Integrity(
                    "persisted Edit operation effect commitment is missing".to_owned(),
                )
            })?
            .parse::<ContentDigest>()
            .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let expected_effect_digest = edit_batch_operation_effect_digest(
            persisted_digest,
            parsed_idempotency_key,
            workspace_id,
            principal_id,
            persisted_changeset_id,
            first_ordinal,
            added_count,
            total_edit_count,
            &persisted_edits,
        )
        .map_err(AddChangeSetEditsError::Integrity)?;
        if persisted_effect_digest != expected_effect_digest {
            return Err(AddChangeSetEditsError::Integrity(
                "persisted Edit batch does not match its operation effect digest".to_owned(),
            ));
        }
    }
    if persisted_changeset_id != changeset_id {
        return Err(AddChangeSetEditsError::IdempotencyKeyReused);
    }
    if reproduced_request_digest != request_digest {
        return Err(AddChangeSetEditsError::IdempotencyKeyReused);
    }
    let edit_ids = persisted_edits.iter().map(ChangeSetEdit::edit_id).collect();
    Ok(Some(AddedChangeSetEdits {
        changeset_id: persisted_changeset_id,
        workspace_id,
        principal_id,
        first_ordinal,
        edit_ids,
        total_edit_count,
    }))
}

#[expect(
    clippy::too_many_lines,
    reason = "persisted replay reconstruction verifies both legacy Schema-only and current discriminated Edit rows"
)]
fn load_persisted_edit_batch(
    connection: &Connection,
    changeset_id: ChangeSetId,
    first_ordinal: u32,
    final_ordinal: u32,
    storage_schema_version: u32,
) -> Result<Vec<ChangeSetEdit>, AddChangeSetEditsError> {
    type PersistedEditRow = (
        i64,
        String,
        String,
        String,
        i64,
        Option<String>,
        String,
        String,
    );
    let object_column = if storage_schema_version >= 9 {
        "object_id"
    } else {
        "NULL AS object_id"
    };
    let mut statement = connection
        .prepare(&format!(
            "SELECT ordinal, edit_id, edit_kind, schema_id, schema_version,
                    {object_column}, document_json, document_digest
             FROM changeset_edits
             WHERE changeset_id = ?1 AND ordinal BETWEEN ?2 AND ?3
             ORDER BY ordinal"
        ))
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            (
                changeset_id.to_string(),
                i64::from(first_ordinal),
                i64::from(final_ordinal),
            ),
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
                ))
            },
        )
        .map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
    let mut edits = Vec::new();
    for row in rows {
        let (
            ordinal,
            edit_id,
            edit_kind,
            schema_id,
            schema_version,
            object_id,
            document_json,
            document_digest,
        ): PersistedEditRow =
            row.map_err(|error| AddChangeSetEditsError::Storage(error.to_string()))?;
        let ordinal = positive_u32(ordinal, "persisted Edit ordinal")?;
        let expected_ordinal = first_ordinal
            .checked_add(u32::try_from(edits.len()).map_err(|_| {
                AddChangeSetEditsError::Integrity("persisted Edit count exceeds u32".to_owned())
            })?)
            .ok_or_else(|| AddChangeSetEditsError::Integrity("Edit ordinal overflow".to_owned()))?;
        if ordinal != expected_ordinal {
            return Err(AddChangeSetEditsError::Integrity(
                "persisted Edit batch ordinals are not contiguous".to_owned(),
            ));
        }
        let edit_id = edit_id
            .parse::<EditId>()
            .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let schema_id = SchemaId::new(schema_id)
            .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let schema_version = SchemaVersion::new(u32::try_from(schema_version).map_err(|_| {
            AddChangeSetEditsError::Integrity("persisted Schema version is invalid".to_owned())
        })?)
        .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let persisted_digest = document_digest
            .parse::<ContentDigest>()
            .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
        let edit = match edit_kind.as_str() {
            "schema.create" if object_id.is_none() => {
                ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                    edit_id,
                    schema_id,
                    schema_version,
                    canonical_document: document_json,
                    document_digest: persisted_digest,
                })
            }
            "object.create" if storage_schema_version >= 9 => {
                let object_id = object_id
                    .ok_or_else(|| {
                        AddChangeSetEditsError::Integrity(
                            "persisted Object Edit target is missing".to_owned(),
                        )
                    })?
                    .parse::<ObjectId>()
                    .map_err(|error| AddChangeSetEditsError::Integrity(error.to_string()))?;
                ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                    edit_id,
                    object_id,
                    schema_id,
                    schema_version,
                    canonical_content: document_json,
                    object_digest: persisted_digest,
                })
            }
            _ => {
                return Err(AddChangeSetEditsError::Integrity(
                    "persisted Edit variant is invalid for the storage schema".to_owned(),
                ));
            }
        };
        edits.push(edit);
    }
    Ok(edits)
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
    storage_schema_version: u32,
) -> Result<(), AddChangeSetEditsError> {
    if storage_schema_version >= 10 {
        let effect_digest = edit_batch_operation_effect_digest(
            request_digest,
            command.idempotency_key,
            workspace_id,
            principal_id,
            command.changeset_id,
            first_ordinal,
            added_count,
            total_edit_count,
            &command.edits,
        )
        .map_err(AddChangeSetEditsError::Integrity)?;
        transaction.execute(
            "INSERT INTO changeset_add_operations (
                 workspace_id, principal_id, changeset_id, idempotency_key,
                 request_digest, effect_digest, first_ordinal, added_count, total_edit_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.changeset_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                first_ordinal,
                added_count,
                total_edit_count,
            ),
        )
    } else {
        transaction.execute(
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
    }
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
    let schema_version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if schema_version >= 7 {
        verify_commit_operation_scope(connection, workspace_id).map_err(|error| match error {
            LocalPortError::Storage(detail) | LocalPortError::Integrity(detail) => detail,
            other => format!("commit-chain verification failed: {other:?}"),
        })?;
    }
    if schema_version >= 11 {
        let api_version: String = connection
            .query_row(
                "SELECT api_version FROM known_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        match api_version.as_str() {
            KNOWN_STATE_V1_API_VERSION => {}
            KNOWN_STATE_V2_API_VERSION => {
                return localized::reproducible_localized_known_state(connection, workspace_id)
                    .map_err(|error| match error {
                        LocalPortError::Storage(detail) | LocalPortError::Integrity(detail) => {
                            detail
                        }
                        other => format!("localized state verification failed: {other:?}"),
                    });
            }
            _ => return Err("Known State has an unsupported API version".to_owned()),
        }
    }
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

#[expect(
    clippy::too_many_arguments,
    reason = "draft insertion binds the authenticated scope and exact observed base atomically"
)]
fn insert_draft(
    transaction: &Transaction<'_>,
    command: &CreateChangeSetCommand,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    base_authoritative_sequence: u64,
    base_state: ContentDigest,
    requested_base_state: Option<&str>,
    schema_version: u32,
) -> Result<(), CreateChangeSetError> {
    let base_authoritative_sequence = i64::try_from(base_authoritative_sequence).map_err(|_| {
        CreateChangeSetError::Integrity(
            "authoritative sequence exceeds local storage range".to_owned(),
        )
    })?;
    let draft = DraftChangeSet {
        changeset_id: command.changeset_id,
        workspace_id,
        principal_id,
        intent: command.intent.clone(),
        base_authoritative_sequence: u64::try_from(base_authoritative_sequence).map_err(|_| {
            CreateChangeSetError::Integrity(
                "authoritative sequence must be non-negative".to_owned(),
            )
        })?,
        base_state,
        idempotency_key: command.idempotency_key,
        created_at: command.created_at,
        status: ChangeSetStatus::Draft,
        policy_profile: LOCAL_POLICY_PROFILE.to_owned(),
        validation_profile: LOCAL_VALIDATION_PROFILE.to_owned(),
        edit_count: 0,
    };
    if schema_version >= 10 {
        let requested_base_state = requested_base_state
            .map(|value| parse_changeset_field(value, "requested base state digest"))
            .transpose()?;
        let effect_digest = changeset_creation_effect_digest(requested_base_state, &draft)
            .map_err(CreateChangeSetError::Integrity)?;
        transaction
            .execute(
                "INSERT INTO changesets (
                     changeset_id, workspace_id, principal_id, intent,
                     requested_base_state, base_authoritative_sequence, base_state,
                     idempotency_key, created_at, status, policy_profile,
                     validation_profile, effect_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                (
                    command.changeset_id.to_string(),
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    command.intent.as_str(),
                    requested_base_state.map(|value| value.to_string()),
                    base_authoritative_sequence,
                    base_state.to_string(),
                    command.idempotency_key.to_string(),
                    command.created_at.to_string(),
                    ChangeSetStatus::Draft.to_string(),
                    LOCAL_POLICY_PROFILE,
                    LOCAL_VALIDATION_PROFILE,
                    effect_digest.to_string(),
                ),
            )
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
    } else {
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
    }
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
    effect_digest: Option<String>,
}

impl PersistedDraft {
    fn into_draft(self, schema_version: u32) -> Result<DraftChangeSet, CreateChangeSetError> {
        if self.status != ChangeSetStatus::Draft.to_string()
            || self.policy_profile != LOCAL_POLICY_PROFILE
            || self.validation_profile != LOCAL_VALIDATION_PROFILE
        {
            return Err(CreateChangeSetError::Integrity(
                "persisted ChangeSet contract fields are unsupported".to_owned(),
            ));
        }
        let requested_base_state = self
            .requested_base_state
            .as_deref()
            .map(|value| parse_changeset_field(value, "requested base state digest"))
            .transpose()?;
        let intent = ChangeSetIntent::new(self.intent.clone())
            .map_err(|error| CreateChangeSetError::Integrity(error.to_string()))?;
        if intent.as_str() != self.intent {
            return Err(CreateChangeSetError::Integrity(
                "persisted ChangeSet intent is not canonical".to_owned(),
            ));
        }
        let draft = DraftChangeSet {
            changeset_id: parse_changeset_field(&self.changeset_id, "ChangeSet identity")?,
            workspace_id: parse_changeset_field(&self.workspace_id, "Workspace identity")?,
            principal_id: parse_changeset_field(&self.principal_id, "Principal identity")?,
            intent,
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
        };
        if schema_version >= 10 {
            let persisted_effect = self.effect_digest.ok_or_else(|| {
                CreateChangeSetError::Integrity("ChangeSet creation effect is missing".to_owned())
            })?;
            let expected = changeset_creation_effect_digest(requested_base_state, &draft)
                .map_err(CreateChangeSetError::Integrity)?;
            if persisted_effect != expected.to_string() {
                return Err(CreateChangeSetError::Integrity(
                    "ChangeSet creation effect does not reproduce".to_owned(),
                ));
            }
        }
        Ok(draft)
    }
}

fn parse_changeset_field<T>(value: &str, field: &str) -> Result<T, CreateChangeSetError>
where
    T: std::str::FromStr + ToString,
    T::Err: std::fmt::Display,
{
    let parsed = value.parse::<T>().map_err(|error| {
        CreateChangeSetError::Integrity(format!("invalid persisted {field}: {error}"))
    })?;
    if parsed.to_string() != value {
        return Err(CreateChangeSetError::Integrity(format!(
            "persisted {field} is not canonical"
        )));
    }
    Ok(parsed)
}

fn verify_changeset_creation_effects_for_scope(
    connection: &Connection,
    schema_version: u32,
) -> Result<(), CreateChangeSetError> {
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    let rows = {
        let mut statement = connection
            .prepare(&format!(
                "SELECT changeset_id, workspace_id, principal_id, intent,
                        requested_base_state, base_authoritative_sequence, base_state,
                        idempotency_key, created_at, status, policy_profile,
                        validation_profile, {effect_column}
                 FROM changesets
                 ORDER BY changeset_id"
            ))
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?;
        statement
            .query_map([], |row| {
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
                    effect_digest: row.get(12)?,
                })
            })
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CreateChangeSetError::Storage(error.to_string()))?
    };
    for persisted in rows {
        persisted.into_draft(schema_version)?;
    }
    Ok(())
}

fn find_idempotent_draft(
    connection: &Connection,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    idempotency_key: IdempotencyKey,
    schema_version: u32,
) -> Result<Option<PersistedDraft>, CreateChangeSetError> {
    let effect_column = if schema_version >= 10 {
        "effect_digest"
    } else {
        "NULL AS effect_digest"
    };
    connection
        .query_row(
            &format!(
                "SELECT changeset_id, workspace_id, principal_id, intent,
                    requested_base_state, base_authoritative_sequence, base_state,
                    idempotency_key, created_at, status, policy_profile,
                    validation_profile, {effect_column}
             FROM changesets
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3"
            ),
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
                    effect_digest: row.get(12)?,
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
