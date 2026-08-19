//! `SQLite` implementation of the Human-operated localized-content profile.

use std::collections::{BTreeMap, BTreeSet};

use proof_application::{
    AddLocalizedEditsCommand, AddedLocalizedEdits, ApprovalName, ApprovedLocalizedChangeSet,
    BuildLocalizedContextCommand, ChangeSetId, ChangeSetStatus, CommitLocalizedChangeSetCommand,
    CommittedLocalizedChangeSet, ContentDigest, ContentResourceIntent, ContentResourceIntentId,
    ContextPackId, CreateLocalizedChangeSetCommand, CreateLocalizedEditionCommand,
    EditionArtifactReference, EditionId, IssueContentResourceIntentCommand,
    KNOWN_STATE_V1_API_VERSION, KNOWN_STATE_V2_API_VERSION, KnownStateArtifactReference,
    LOCALIZED_CONTEXT_API_VERSION, LOCALIZED_EDITION_API_VERSION, LOCALIZED_RELEASE_API_VERSION,
    LocalizedChangeSet, LocalizedChangeSetDiff, LocalizedContentBaseline, LocalizedContentError,
    LocalizedContentRepository, LocalizedContextLimits, LocalizedContextPack, LocalizedEdition,
    LocalizedPolicyRule, LocalizedRelease, LocalizedReleaseVerification,
    MAX_LOCALIZED_CONTEXT_BYTES, MAX_LOCALIZED_EDITS, MAX_LOCALIZED_TARGETS,
    MAX_LOCALIZED_VALIDATION_ATTEMPTS, ObjectId, ObjectLocalePutInput, ObjectLocaleRevision,
    PromoteLocalizedReleaseCommand, QueryReleasedRenditionsCommand, RELEASE_V1_API_VERSION,
    ReleaseArtifactReference, ReleaseId, ReleasedRendition, ReleasedRenditionQuery,
    RollbackLocalizedReleaseCommand, SchemaId, SubmittedLocalizedChangeSet, Timestamp,
    VerifyLocalizedReleaseCommand,
};
use proof_canonical::{canonicalize, digest, object_revision_digest, parse_strict};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::{Value, json};

use super::{LocalPortError, LocalWorkspace};

const V11_DATABASE_MIGRATION: &str = r"
ALTER TABLE known_state
    ADD COLUMN api_version TEXT NOT NULL DEFAULT 'proof.dev/known-state/v1';
ALTER TABLE known_state ADD COLUMN manifest_json TEXT;
ALTER TABLE editions
    ADD COLUMN api_version TEXT NOT NULL DEFAULT 'proof.dev/edition/v1';
ALTER TABLE releases
    ADD COLUMN api_version TEXT NOT NULL DEFAULT 'proof.dev/release/v1';
ALTER TABLE release_proofs
    ADD COLUMN predicate_type TEXT NOT NULL DEFAULT 'urn:proof:attestation:release:v1';

CREATE TABLE known_state_artifacts (
    api_version TEXT NOT NULL,
    authoritative_sequence INTEGER NOT NULL CHECK (authoritative_sequence >= 0),
    state_digest TEXT NOT NULL,
    manifest_json TEXT,
    changeset_id TEXT,
    PRIMARY KEY (api_version, state_digest),
    UNIQUE (authoritative_sequence, state_digest)
) STRICT;

CREATE TABLE content_resource_intents (
    intent_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    issued_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    issued_at TEXT NOT NULL,
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    base_release_api_version TEXT NOT NULL,
    base_release_id TEXT NOT NULL REFERENCES releases(release_id),
    base_release_digest TEXT NOT NULL,
    base_edition_api_version TEXT NOT NULL,
    base_edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    base_edition_digest TEXT NOT NULL,
    base_state_api_version TEXT NOT NULL,
    base_authoritative_sequence INTEGER NOT NULL CHECK (base_authoritative_sequence >= 0),
    base_state_digest TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    intent_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE content_resource_intent_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    intent_id TEXT NOT NULL REFERENCES content_resource_intents(intent_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_context_packs (
    context_pack_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    resource_intent_id TEXT NOT NULL REFERENCES content_resource_intents(intent_id),
    resource_intent_digest TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    max_objects INTEGER NOT NULL CHECK (max_objects > 0),
    max_edits INTEGER NOT NULL CHECK (max_edits > 0),
    max_validation_attempts INTEGER NOT NULL CHECK (max_validation_attempts > 0),
    max_bytes INTEGER NOT NULL CHECK (max_bytes > 0),
    manifest_json TEXT NOT NULL,
    context_pack_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
CREATE TABLE localized_context_build_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    context_pack_id TEXT NOT NULL REFERENCES localized_context_packs(context_pack_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_changesets (
    changeset_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    intent TEXT NOT NULL CHECK (length(intent) > 0),
    resource_intent_id TEXT NOT NULL REFERENCES content_resource_intents(intent_id),
    resource_intent_digest TEXT NOT NULL,
    context_pack_id TEXT NOT NULL REFERENCES localized_context_packs(context_pack_id),
    context_pack_digest TEXT NOT NULL,
    base_state_api_version TEXT NOT NULL,
    base_authoritative_sequence INTEGER NOT NULL CHECK (base_authoritative_sequence >= 0),
    base_state_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL CHECK (
        lifecycle_status IN ('draft', 'ready', 'submitted', 'approved', 'committed')
    ),
    proposal_digest TEXT,
    effective_leaf_digest TEXT,
    sealed_changeset_digest TEXT,
    effect_digest TEXT NOT NULL,
    UNIQUE (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_edits (
    changeset_id TEXT NOT NULL REFERENCES localized_changesets(changeset_id),
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    edit_id TEXT NOT NULL UNIQUE,
    object_id TEXT NOT NULL,
    locale TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    source_digest TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    expected_target_revision INTEGER CHECK (expected_target_revision > 0),
    expected_target_digest TEXT,
    content_json TEXT NOT NULL,
    supersedes_edit_id TEXT REFERENCES localized_edits(edit_id),
    repair_validation_digest TEXT,
    edit_json TEXT NOT NULL,
    edit_digest TEXT NOT NULL UNIQUE,
    PRIMARY KEY (changeset_id, ordinal),
    CHECK (
        (expected_target_revision IS NULL AND expected_target_digest IS NULL) OR
        (expected_target_revision IS NOT NULL AND expected_target_digest IS NOT NULL)
    ),
    CHECK (
        (supersedes_edit_id IS NULL AND repair_validation_digest IS NULL) OR
        (supersedes_edit_id IS NOT NULL AND repair_validation_digest IS NOT NULL)
    )
) STRICT;
CREATE INDEX localized_edit_targets
    ON localized_edits(changeset_id, object_id, locale, ordinal);
CREATE TABLE localized_add_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    changeset_id TEXT NOT NULL REFERENCES localized_changesets(changeset_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    first_ordinal INTEGER NOT NULL CHECK (first_ordinal > 0),
    added_count INTEGER NOT NULL CHECK (added_count > 0),
    total_edit_count INTEGER NOT NULL CHECK (total_edit_count > 0),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_validations (
    changeset_id TEXT NOT NULL REFERENCES localized_changesets(changeset_id),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    previous_result_digest TEXT,
    proposal_digest TEXT NOT NULL,
    effective_leaf_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    validator TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
    findings_json TEXT NOT NULL,
    results_json TEXT NOT NULL,
    results_digest TEXT NOT NULL UNIQUE,
    sealed_changeset_digest TEXT,
    PRIMARY KEY (changeset_id, attempt)
) STRICT;
CREATE TABLE localized_submissions (
    changeset_id TEXT PRIMARY KEY REFERENCES localized_changesets(changeset_id),
    sealed_changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    submitted_at TEXT NOT NULL,
    effect_digest TEXT NOT NULL
) STRICT;
CREATE TABLE localized_approvals (
    changeset_id TEXT PRIMARY KEY REFERENCES localized_changesets(changeset_id),
    approval_name TEXT NOT NULL,
    sealed_changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    approved_at TEXT NOT NULL,
    effect_digest TEXT NOT NULL
) STRICT;

CREATE TABLE object_locale_revisions (
    workspace_id TEXT NOT NULL,
    object_id TEXT NOT NULL,
    locale TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    previous_revision_digest TEXT,
    source_object_revision INTEGER NOT NULL CHECK (source_object_revision = 1),
    source_object_digest TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    content_json TEXT NOT NULL,
    changeset_id TEXT NOT NULL REFERENCES localized_changesets(changeset_id),
    edit_id TEXT NOT NULL UNIQUE REFERENCES localized_edits(edit_id),
    authoritative_sequence INTEGER NOT NULL UNIQUE CHECK (authoritative_sequence > 0),
    manifest_json TEXT NOT NULL,
    rendition_digest TEXT NOT NULL UNIQUE,
    PRIMARY KEY (object_id, locale, revision),
    FOREIGN KEY (object_id, source_object_revision)
        REFERENCES object_revisions(object_id, revision),
    FOREIGN KEY (schema_id, schema_version)
        REFERENCES schema_versions(schema_id, schema_version)
) STRICT;
CREATE INDEX object_locale_heads
    ON object_locale_revisions(object_id, locale, revision DESC);

CREATE TABLE localized_commits (
    changeset_id TEXT PRIMARY KEY REFERENCES localized_changesets(changeset_id),
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    sealed_changeset_digest TEXT NOT NULL,
    validation_results_digest TEXT NOT NULL,
    previous_state_api_version TEXT NOT NULL,
    previous_authoritative_sequence INTEGER NOT NULL CHECK (previous_authoritative_sequence >= 0),
    previous_state_digest TEXT NOT NULL,
    resulting_authoritative_sequence INTEGER NOT NULL CHECK (resulting_authoritative_sequence > 0),
    resulting_state_digest TEXT NOT NULL UNIQUE,
    resulting_state_json TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    UNIQUE (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_edition_metadata (
    edition_id TEXT PRIMARY KEY REFERENCES editions(edition_id),
    changeset_id TEXT NOT NULL UNIQUE REFERENCES localized_commits(changeset_id),
    base_edition_api_version TEXT NOT NULL,
    base_edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    base_edition_digest TEXT NOT NULL,
    state_api_version TEXT NOT NULL,
    state_digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    metadata_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE localized_edition_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    effect_digest TEXT NOT NULL,
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    PRIMARY KEY (workspace_id, principal_id, idempotency_key)
) STRICT;

CREATE TABLE localized_release_metadata (
    release_id TEXT PRIMARY KEY REFERENCES releases(release_id),
    base_release_id TEXT REFERENCES releases(release_id),
    changeset_id TEXT REFERENCES localized_commits(changeset_id),
    resource_intent_id TEXT REFERENCES content_resource_intents(intent_id),
    exact_delta_json TEXT NOT NULL,
    exact_delta_digest TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    metadata_digest TEXT NOT NULL UNIQUE
) STRICT;
CREATE TABLE localized_release_operations (
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN ('release.promote.v2', 'release.rollback.v2')
    ),
    idempotency_key TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    proof_id TEXT NOT NULL REFERENCES release_proofs(proof_id),
    PRIMARY KEY (workspace_id, principal_id, operation_kind, idempotency_key)
) STRICT;

INSERT INTO schema_migrations (version, name)
VALUES (11, 'localized-content-foundation');
UPDATE workspace_metadata SET schema_version = 11 WHERE singleton = 1;
PRAGMA user_version = 11;
";

pub(super) fn migrate_schema_v11(transaction: &Transaction<'_>) -> Result<(), String> {
    transaction
        .execute_batch(V11_DATABASE_MIGRATION)
        .map_err(|error| error.to_string())?;
    let (authoritative_sequence, state_digest): (i64, String) = transaction
        .query_row(
            "SELECT authoritative_sequence, state_digest FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO known_state_artifacts (
                 api_version, authoritative_sequence, state_digest, manifest_json, changeset_id
             ) VALUES ('proof.dev/known-state/v1', ?1, ?2, NULL, NULL)",
            (authoritative_sequence, state_digest),
        )
        .map_err(|error| error.to_string())?;
    Ok(())
}

impl LocalizedContentRepository for LocalWorkspace {
    fn issue_content_resource_intent(
        &self,
        command: IssueContentResourceIntentCommand,
    ) -> Result<ContentResourceIntent, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            issue_resource_intent(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn get_content_resource_intent(
        &self,
        intent_id: ContentResourceIntentId,
    ) -> Result<ContentResourceIntent, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            load_resource_intent(transaction, workspace_id, intent_id)
        })
        .map_err(localized_from_local_port)
    }

    fn build_localized_context(
        &self,
        command: BuildLocalizedContextCommand,
    ) -> Result<LocalizedContextPack, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            build_context(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn get_localized_context(
        &self,
        context_pack_id: ContextPackId,
    ) -> Result<LocalizedContextPack, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            load_context(transaction, workspace_id, context_pack_id)
        })
        .map_err(localized_from_local_port)
    }

    fn create_localized_changeset(
        &self,
        command: CreateLocalizedChangeSetCommand,
    ) -> Result<LocalizedChangeSet, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            create_changeset(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn add_localized_edits(
        &self,
        command: AddLocalizedEditsCommand,
    ) -> Result<AddedLocalizedEdits, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            add_edits(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn inspect_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<LocalizedChangeSet, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            load_changeset(transaction, workspace_id, changeset_id)
        })
        .map_err(localized_from_local_port)
    }

    fn diff_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<LocalizedChangeSetDiff, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
            changeset_diff(&changeset)
        })
        .map_err(localized_from_local_port)
    }

    fn validate_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
    ) -> Result<proof_application::LocalizedValidation, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            validate_changeset(transaction, workspace_id, principal_id, changeset_id)
        })
        .map_err(localized_from_local_port)
    }

    fn submit_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
        submitted_at: Timestamp,
    ) -> Result<proof_application::SubmittedLocalizedChangeSet, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            submit_changeset(
                transaction,
                workspace_id,
                principal_id,
                changeset_id,
                submitted_at,
            )
        })
        .map_err(localized_from_local_port)
    }

    fn approve_localized_changeset(
        &self,
        changeset_id: ChangeSetId,
        approval: ApprovalName,
        approved_at: Timestamp,
    ) -> Result<ApprovedLocalizedChangeSet, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            approve_changeset(
                transaction,
                workspace_id,
                principal_id,
                changeset_id,
                approval,
                approved_at,
            )
        })
        .map_err(localized_from_local_port)
    }

    fn commit_localized_changeset(
        &self,
        command: CommitLocalizedChangeSetCommand,
    ) -> Result<CommittedLocalizedChangeSet, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            commit_changeset(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn create_localized_edition(
        &self,
        command: CreateLocalizedEditionCommand,
    ) -> Result<LocalizedEdition, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            create_localized_edition(transaction, workspace_id, principal_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn promote_localized_release(
        &self,
        command: PromoteLocalizedReleaseCommand,
    ) -> Result<LocalizedRelease, LocalizedContentError> {
        let release = self
            .with_latest_transaction(|transaction, workspace_id, principal_id| {
                require_human_principal(transaction, principal_id)?;
                create_localized_release(
                    transaction,
                    workspace_id,
                    principal_id,
                    LocalizedReleaseRequest::Promotion(&command),
                    || self.preflight_release_proof_export(command.proof_id),
                    || self.load_or_create_release_signer(command.release_id),
                )
            })
            .map_err(localized_from_local_port)?;
        let _ = materialize_localized_release_proof(self, &release);
        Ok(release)
    }

    fn rollback_localized_release(
        &self,
        command: RollbackLocalizedReleaseCommand,
    ) -> Result<LocalizedRelease, LocalizedContentError> {
        let release = self
            .with_latest_transaction(|transaction, workspace_id, principal_id| {
                require_human_principal(transaction, principal_id)?;
                create_localized_release(
                    transaction,
                    workspace_id,
                    principal_id,
                    LocalizedReleaseRequest::Rollback(&command),
                    || self.preflight_release_proof_export(command.proof_id),
                    || self.load_or_create_release_signer(command.release_id),
                )
            })
            .map_err(localized_from_local_port)?;
        let _ = materialize_localized_release_proof(self, &release);
        Ok(release)
    }

    fn query_released_renditions(
        &self,
        command: QueryReleasedRenditionsCommand,
    ) -> Result<ReleasedRenditionQuery, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            query_released_renditions(transaction, workspace_id, &command)
        })
        .map_err(localized_from_local_port)
    }

    fn verify_localized_release(
        &self,
        command: VerifyLocalizedReleaseCommand,
    ) -> Result<LocalizedReleaseVerification, LocalizedContentError> {
        self.with_latest_transaction(|transaction, workspace_id, principal_id| {
            require_human_principal(transaction, principal_id)?;
            let release = load_localized_release(transaction, workspace_id, command.release_id)?;
            if command.verified_at < release.released_at {
                return Err(LocalPortError::Invalid);
            }
            Ok(LocalizedReleaseVerification {
                release_id: release.release_id,
                proof_id: release.proof_id,
                valid: true,
                findings: Vec::new(),
                verified_at: command.verified_at,
            })
        })
        .map_err(localized_from_local_port)
    }
}

fn require_human_principal(
    transaction: &Transaction<'_>,
    principal_id: proof_application::PrincipalId,
) -> Result<(), LocalPortError> {
    let principal_type: String = transaction
        .query_row(
            "SELECT principal_type FROM principals WHERE principal_id = ?1 AND enabled = 1",
            [principal_id.to_string()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::Unauthenticated)?;
    if principal_type != "human" {
        return Err(LocalPortError::Unauthenticated);
    }
    Ok(())
}

fn load_localized_environment(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    environment_id: proof_application::EnvironmentId,
) -> Result<proof_application::Environment, LocalPortError> {
    let config_version: i64 = transaction
        .query_row(
            "SELECT MAX(config_version) FROM environment_versions WHERE environment_id = ?1",
            [environment_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    let config_version = u32::try_from(config_version)
        .map_err(|_| LocalPortError::Integrity("invalid Environment version".to_owned()))?;
    let mut environment =
        super::load_environment_version(transaction, workspace_id, environment_id, config_version)
            .map_err(super::local_port_from_environment)?;
    environment.current_release_id = transaction
        .query_row(
            "SELECT release_id FROM environment_current_releases WHERE environment_id = ?1",
            [environment.environment_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .map(|value| {
            value
                .parse::<ReleaseId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()?;
    Ok(environment)
}

fn localized_from_local_port(error: LocalPortError) -> LocalizedContentError {
    match error {
        LocalPortError::Unauthenticated => LocalizedContentError::Unauthenticated,
        LocalPortError::UnsupportedVersion => LocalizedContentError::UnsupportedVersion,
        LocalPortError::NotFound => LocalizedContentError::NotFound,
        LocalPortError::Invalid | LocalPortError::InvalidRollbackTarget => {
            LocalizedContentError::InvalidInput
        }
        LocalPortError::IntentMismatch => LocalizedContentError::IntentMismatch,
        LocalPortError::SourceConflict => LocalizedContentError::SourceConflict,
        LocalPortError::TargetConflict => LocalizedContentError::TargetConflict,
        LocalPortError::DuplicateActiveTarget => LocalizedContentError::DuplicateActiveTarget,
        LocalPortError::InvalidSupersession => LocalizedContentError::InvalidSupersession,
        LocalPortError::InvalidRepairEvidence => LocalizedContentError::InvalidRepairEvidence,
        LocalPortError::NotDraft => LocalizedContentError::NotDraft,
        LocalPortError::NotReady => LocalizedContentError::NotReady,
        LocalPortError::NotSubmitted => LocalizedContentError::NotSubmitted,
        LocalPortError::NotApproved => LocalizedContentError::NotApproved,
        LocalPortError::EvidenceMissing => LocalizedContentError::EvidenceMissing,
        LocalPortError::LimitExceeded => LocalizedContentError::LimitExceeded,
        LocalPortError::IdempotencyKeyReused => LocalizedContentError::IdempotencyKeyReused,
        LocalPortError::StateConflict => LocalizedContentError::StateConflict,
        LocalPortError::PolicyDenied | LocalPortError::Denied | LocalPortError::Expired => {
            LocalizedContentError::PolicyDenied
        }
        LocalPortError::Signing(detail) => LocalizedContentError::Signing(detail),
        LocalPortError::Integrity(detail) => LocalizedContentError::Integrity(detail),
        LocalPortError::Storage(detail) => LocalizedContentError::Storage(detail),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "intent issuance verifies and persists one complete effect-bound resource closure"
)]
fn issue_resource_intent(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &IssueContentResourceIntentCommand,
) -> Result<ContentResourceIntent, LocalPortError> {
    let targets = normalized_targets(&command.targets)?;
    let (baseline, released_at) =
        current_baseline(transaction, workspace_id, &command.environment_id)?;
    if command.issued_at < released_at {
        return Err(LocalPortError::Invalid);
    }
    verify_targets_at_baseline(transaction, &baseline, &targets)?;
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/content-intent.issue/v1",
        "environment_id": command.environment_id.as_str(),
        "idempotency_key": command.idempotency_key.to_string(),
        "intent_id": command.intent_id.to_string(),
        "issued_at": command.issued_at.to_string(),
        "targets": targets_value(&targets),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((persisted_request, intent_id)) = transaction
        .query_row(
            "SELECT request_digest, intent_id FROM content_resource_intent_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        if persisted_request != request_digest.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        let intent_id = intent_id
            .parse::<ContentResourceIntentId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        return load_resource_intent(transaction, workspace_id, intent_id);
    }
    let candidate_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM content_resource_intents WHERE intent_id = ?1)",
            [command.intent_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if candidate_exists {
        return Err(LocalPortError::Integrity(
            "candidate resource-intent identity already exists".to_owned(),
        ));
    }
    let manifest = content_intent_manifest(
        command.intent_id,
        workspace_id,
        principal_id,
        command.issued_at,
        &command.environment_id,
        &baseline,
        &targets,
    )?;
    let intent_digest = digest(
        proof_application::ArtifactKind::ContentResourceIntentV1,
        &manifest,
    );
    let targets_json = canonicalize(&Value::Array(targets_value(&targets)))
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO content_resource_intents (
                 intent_id, workspace_id, issued_by_principal_id, issued_at, environment_id,
                 base_release_api_version, base_release_id, base_release_digest,
                 base_edition_api_version, base_edition_id, base_edition_digest,
                 base_state_api_version, base_authoritative_sequence, base_state_digest,
                 targets_json, manifest_json, intent_digest
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             )",
            params![
                command.intent_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                command.issued_at.to_string(),
                command.environment_id.as_str(),
                baseline.release.api_version,
                baseline.release.release_id.to_string(),
                baseline.release.digest.to_string(),
                baseline.edition.api_version,
                baseline.edition.edition_id.to_string(),
                baseline.edition.digest.to_string(),
                baseline.known_state.api_version,
                i64::try_from(baseline.known_state.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                baseline.known_state.digest.to_string(),
                targets_json.as_str(),
                manifest.as_str(),
                intent_digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "content-intent.issue/v1",
        "request_digest": request_digest.to_string(),
        "result": {
            "intent_digest": intent_digest.to_string(),
            "intent_id": command.intent_id.to_string(),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let effect_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &effect);
    transaction
        .execute(
            "INSERT INTO content_resource_intent_operations (
                 workspace_id, principal_id, idempotency_key, request_digest,
                 effect_digest, intent_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                command.intent_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    load_resource_intent(transaction, workspace_id, command.intent_id)
}

fn content_intent_manifest(
    intent_id: ContentResourceIntentId,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    issued_at: Timestamp,
    environment_id: &proof_application::EnvironmentId,
    baseline: &LocalizedContentBaseline,
    targets: &[proof_application::LocalizedContentTarget],
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": proof_application::CONTENT_RESOURCE_INTENT_API_VERSION,
        "base": baseline_value(baseline),
        "environment_id": environment_id.as_str(),
        "intent_id": intent_id.to_string(),
        "issued_at": issued_at.to_string(),
        "issued_by_principal_id": principal_id.to_string(),
        "targets": targets_value(targets),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn normalized_targets(
    targets: &[proof_application::LocalizedContentTarget],
) -> Result<Vec<proof_application::LocalizedContentTarget>, LocalPortError> {
    if targets.is_empty() || targets.len() > MAX_LOCALIZED_TARGETS {
        return Err(LocalPortError::LimitExceeded);
    }
    let mut normalized = targets.to_vec();
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LocalPortError::Invalid);
    }
    Ok(normalized)
}

fn targets_value(targets: &[proof_application::LocalizedContentTarget]) -> Vec<Value> {
    targets
        .iter()
        .map(|target| {
            json!({
                "locale": target.locale.as_str(),
                "object_id": target.object_id.to_string(),
                "schema_id": target.schema_id.as_str(),
            })
        })
        .collect()
}

fn baseline_value(baseline: &LocalizedContentBaseline) -> Value {
    json!({
        "edition": {
            "api_version": baseline.edition.api_version,
            "digest": baseline.edition.digest.to_string(),
            "edition_id": baseline.edition.edition_id.to_string(),
        },
        "known_state": {
            "api_version": baseline.known_state.api_version,
            "authoritative_sequence": baseline.known_state.authoritative_sequence,
            "digest": baseline.known_state.digest.to_string(),
        },
        "release": {
            "api_version": baseline.release.api_version,
            "digest": baseline.release.digest.to_string(),
            "release_id": baseline.release.release_id.to_string(),
        },
    })
}

fn current_baseline(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    environment_id: &proof_application::EnvironmentId,
) -> Result<(LocalizedContentBaseline, Timestamp), LocalPortError> {
    let (release_id, release_api_version): (String, String) = transaction
        .query_row(
            "SELECT current.release_id, releases.api_version
             FROM environment_current_releases AS current
             JOIN releases ON releases.release_id = current.release_id
             WHERE current.environment_id = ?1 AND releases.workspace_id = ?2",
            (environment_id.as_str(), workspace_id.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    let release_id = release_id
        .parse::<ReleaseId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let (edition_id, edition_digest, release_digest, released_at): (
        String,
        String,
        String,
        String,
    ) = transaction
        .query_row(
            "SELECT edition_id, edition_digest, release_digest, released_at
                 FROM releases WHERE release_id = ?1",
            [release_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let edition_id = edition_id
        .parse::<EditionId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let edition_digest = edition_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let release_digest = release_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let released_at = released_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let (edition_api_version, persisted_edition_digest, state_digest, state_sequence): (
        String,
        String,
        String,
        i64,
    ) = transaction
        .query_row(
            "SELECT api_version, edition_digest, state_digest, authoritative_sequence
             FROM editions WHERE edition_id = ?1 AND workspace_id = ?2",
            (edition_id.to_string(), workspace_id.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if persisted_edition_digest != edition_digest.to_string() {
        return Err(LocalPortError::Integrity(
            "Release and Edition digests differ".to_owned(),
        ));
    }
    let state = current_state_reference(transaction, workspace_id)?;
    if state.digest.to_string() != state_digest
        || state.authoritative_sequence
            != u64::try_from(state_sequence).map_err(|_| {
                LocalPortError::Integrity("invalid Edition state sequence".to_owned())
            })?
    {
        return Err(LocalPortError::StateConflict);
    }
    verify_version_pair(&release_api_version, &edition_api_version)?;
    verify_release_and_edition_artifacts(
        transaction,
        workspace_id,
        release_id,
        &release_api_version,
        edition_id,
        &edition_api_version,
    )?;
    Ok((
        LocalizedContentBaseline {
            release: ReleaseArtifactReference {
                api_version: release_api_version,
                release_id,
                digest: release_digest,
            },
            edition: EditionArtifactReference {
                api_version: edition_api_version,
                edition_id,
                digest: edition_digest,
            },
            known_state: state,
        },
        released_at,
    ))
}

fn verify_version_pair(release_version: &str, edition_version: &str) -> Result<(), LocalPortError> {
    match (release_version, edition_version) {
        (
            RELEASE_V1_API_VERSION | LOCALIZED_RELEASE_API_VERSION,
            proof_application::EDITION_V1_API_VERSION,
        )
        | (LOCALIZED_RELEASE_API_VERSION, LOCALIZED_EDITION_API_VERSION) => Ok(()),
        _ => Err(LocalPortError::Integrity(
            "Release and Edition API versions form an unsupported pair".to_owned(),
        )),
    }
}

fn current_state_reference(
    transaction: &Connection,
    workspace_id: proof_application::WorkspaceId,
) -> Result<KnownStateArtifactReference, LocalPortError> {
    let (api_version, sequence, raw_digest, manifest_json): (String, i64, String, Option<String>) =
        transaction
            .query_row(
                "SELECT api_version, authoritative_sequence, state_digest, manifest_json
                 FROM known_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let sequence = u64::try_from(sequence)
        .map_err(|_| LocalPortError::Integrity("invalid Known State sequence".to_owned()))?;
    let state_digest = raw_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    match api_version.as_str() {
        KNOWN_STATE_V1_API_VERSION => {
            let (_, reproduced) =
                super::reproducible_known_state_at(transaction, workspace_id, sequence)
                    .map_err(LocalPortError::Integrity)?;
            if reproduced != state_digest {
                return Err(LocalPortError::Integrity(
                    "v1 Known State digest does not reproduce".to_owned(),
                ));
            }
        }
        KNOWN_STATE_V2_API_VERSION => {
            let manifest_json = manifest_json.ok_or_else(|| {
                LocalPortError::Integrity("v2 Known State manifest is missing".to_owned())
            })?;
            let canonical = strict_canonical(&manifest_json, "v2 Known State")?;
            if digest(proof_application::ArtifactKind::KnownStateV2, &canonical) != state_digest {
                return Err(LocalPortError::Integrity(
                    "v2 Known State digest does not reproduce".to_owned(),
                ));
            }
            verify_v2_state_semantics(
                transaction,
                workspace_id,
                sequence,
                state_digest,
                &canonical,
            )?;
        }
        _ => {
            return Err(LocalPortError::Integrity(
                "current Known State API version is unsupported".to_owned(),
            ));
        }
    }
    Ok(KnownStateArtifactReference {
        api_version,
        authoritative_sequence: sequence,
        digest: state_digest,
    })
}

pub(super) fn reproducible_localized_known_state(
    connection: &Connection,
    workspace_id: proof_application::WorkspaceId,
) -> Result<(u64, ContentDigest), LocalPortError> {
    let state = current_state_reference(connection, workspace_id)?;
    if state.api_version != KNOWN_STATE_V2_API_VERSION {
        return Err(LocalPortError::UnsupportedVersion);
    }
    Ok((state.authoritative_sequence, state.digest))
}

fn verify_release_and_edition_artifacts(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    release_id: ReleaseId,
    release_api_version: &str,
    edition_id: EditionId,
    edition_api_version: &str,
) -> Result<(), LocalPortError> {
    if release_api_version == RELEASE_V1_API_VERSION {
        super::load_release_record(transaction, workspace_id, release_id)?;
    } else {
        verify_v2_release_record(transaction, workspace_id, release_id)?;
    }
    if edition_api_version == proof_application::EDITION_V1_API_VERSION {
        super::load_edition(transaction, edition_id).map_err(super::local_port_from_edition)?;
    } else {
        verify_v2_edition_record(transaction, workspace_id, edition_id)?;
    }
    Ok(())
}

fn verify_targets_at_baseline(
    transaction: &Transaction<'_>,
    baseline: &LocalizedContentBaseline,
    targets: &[proof_application::LocalizedContentTarget],
) -> Result<(), LocalPortError> {
    let edition_objects = edition_object_ids(transaction, &baseline.edition)?;
    for target in targets {
        let source = load_source_object(transaction, target.object_id)?;
        if source.schema_id != target.schema_id || !edition_objects.contains(&target.object_id) {
            return Err(LocalPortError::Invalid);
        }
    }
    Ok(())
}

#[derive(Clone)]
struct SourceObject {
    schema_id: SchemaId,
    schema_version: proof_application::SchemaVersion,
    canonical_content: String,
    object_digest: ContentDigest,
}

fn load_source_object(
    transaction: &Connection,
    object_id: ObjectId,
) -> Result<SourceObject, LocalPortError> {
    let (revision, raw_schema_id, schema_version, lifecycle, content, raw_digest): (
        i64,
        String,
        i64,
        String,
        String,
        String,
    ) = transaction
        .query_row(
            "SELECT revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest
             FROM object_revisions WHERE object_id = ?1",
            [object_id.to_string()],
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if revision != 1 || lifecycle != "active" {
        return Err(LocalPortError::Integrity(
            "source Object metadata is unsupported".to_owned(),
        ));
    }
    let schema_id = SchemaId::new(raw_schema_id)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let schema_version = proof_application::SchemaVersion::new(
        u32::try_from(schema_version)
            .map_err(|_| LocalPortError::Integrity("invalid source Schema version".to_owned()))?,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let object_digest = raw_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical = strict_canonical(&content, "source Object")?;
    let value = parse_strict(canonical.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if object_revision_digest(object_id, &schema_id, schema_version, &value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?
        != object_digest
    {
        return Err(LocalPortError::Integrity(
            "source Object digest does not reproduce".to_owned(),
        ));
    }
    Ok(SourceObject {
        schema_id,
        schema_version,
        canonical_content: content,
        object_digest,
    })
}

fn strict_canonical(
    text: &str,
    artifact: &str,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    let value = parse_strict(text.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical.as_str() != text {
        return Err(LocalPortError::Integrity(format!(
            "{artifact} bytes are not canonical JSON"
        )));
    }
    Ok(canonical)
}

fn edition_object_ids(
    transaction: &Transaction<'_>,
    edition: &EditionArtifactReference,
) -> Result<BTreeSet<ObjectId>, LocalPortError> {
    let sequence: i64 = transaction
        .query_row(
            "SELECT authoritative_sequence FROM editions WHERE edition_id = ?1",
            [edition.edition_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut statement = transaction
        .prepare(
            "SELECT object_id FROM object_revisions
             WHERE authoritative_sequence <= ?1 ORDER BY object_id",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    statement
        .query_map([sequence], |row| row.get::<_, String>(0))
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .map(|row| {
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?
                .parse::<ObjectId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn load_resource_intent(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    intent_id: ContentResourceIntentId,
) -> Result<ContentResourceIntent, LocalPortError> {
    type IntentRow = (
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
        i64,
        String,
        String,
        String,
        String,
    );
    let row: IntentRow = transaction
        .query_row(
            "SELECT issued_by_principal_id, issued_at, environment_id,
                    base_release_api_version, base_release_id, base_release_digest,
                    base_edition_api_version, base_edition_id, base_edition_digest,
                    base_state_api_version, workspace_id, base_authoritative_sequence,
                    base_state_digest, targets_json, manifest_json, intent_digest
             FROM content_resource_intents WHERE intent_id = ?1",
            [intent_id.to_string()],
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.10 != workspace_id.to_string() {
        return Err(LocalPortError::NotFound);
    }
    let principal_id = row
        .0
        .parse()
        .map_err(|error: proof_application::IdentifierError| {
            LocalPortError::Integrity(error.to_string())
        })?;
    let issued_at = row
        .1
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let environment_id = proof_application::EnvironmentId::new(row.2)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let baseline =
        LocalizedContentBaseline {
            release: ReleaseArtifactReference {
                api_version: row.3,
                release_id: row.4.parse().map_err(
                    |error: proof_application::IdentifierError| {
                        LocalPortError::Integrity(error.to_string())
                    },
                )?,
                digest: row
                    .5
                    .parse::<ContentDigest>()
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            },
            edition: EditionArtifactReference {
                api_version: row.6,
                edition_id: row.7.parse().map_err(
                    |error: proof_application::IdentifierError| {
                        LocalPortError::Integrity(error.to_string())
                    },
                )?,
                digest: row
                    .8
                    .parse::<ContentDigest>()
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            },
            known_state: KnownStateArtifactReference {
                api_version: row.9,
                authoritative_sequence: u64::try_from(row.11).map_err(|_| {
                    LocalPortError::Integrity("invalid intent state sequence".to_owned())
                })?,
                digest: row
                    .12
                    .parse::<ContentDigest>()
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            },
        };
    let targets = parse_targets(&row.13)?;
    let manifest = content_intent_manifest(
        intent_id,
        workspace_id,
        principal_id,
        issued_at,
        &environment_id,
        &baseline,
        &targets,
    )?;
    let intent_digest = row
        .15
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if manifest.as_str() != row.14
        || digest(
            proof_application::ArtifactKind::ContentResourceIntentV1,
            &manifest,
        ) != intent_digest
    {
        return Err(LocalPortError::Integrity(
            "resource-intent artifact does not reproduce".to_owned(),
        ));
    }
    Ok(ContentResourceIntent {
        intent_id,
        workspace_id,
        issued_by_principal_id: principal_id,
        issued_at,
        environment_id,
        base: baseline,
        targets,
        canonical_json: row.14,
        intent_digest,
    })
}

fn parse_targets(
    text: &str,
) -> Result<Vec<proof_application::LocalizedContentTarget>, LocalPortError> {
    let value = parse_strict(text.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical.as_str() != text {
        return Err(LocalPortError::Integrity(
            "resource-intent targets are not canonical".to_owned(),
        ));
    }
    let array = value.as_array().ok_or_else(|| {
        LocalPortError::Integrity("resource-intent targets are not an array".to_owned())
    })?;
    let mut targets = Vec::with_capacity(array.len());
    for item in array {
        let object = item.as_object().ok_or_else(|| {
            LocalPortError::Integrity("resource-intent target is not an object".to_owned())
        })?;
        if object.len() != 3 {
            return Err(LocalPortError::Integrity(
                "resource-intent target has unknown members".to_owned(),
            ));
        }
        targets.push(proof_application::LocalizedContentTarget {
            object_id: required_string(object, "object_id")?.parse().map_err(
                |error: proof_application::IdentifierError| {
                    LocalPortError::Integrity(error.to_string())
                },
            )?,
            schema_id: SchemaId::new(required_string(object, "schema_id")?)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            locale: proof_application::LocaleId::new(required_string(object, "locale")?)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        });
    }
    let normalized = normalized_targets(&targets)?;
    if normalized != targets {
        return Err(LocalPortError::Integrity(
            "resource-intent targets are not in canonical order".to_owned(),
        ));
    }
    Ok(targets)
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, LocalPortError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| LocalPortError::Integrity(format!("missing string field `{field}`")))
}

#[expect(
    clippy::too_many_lines,
    reason = "ContextPack construction binds and persists the complete exact source closure"
)]
fn build_context(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &BuildLocalizedContextCommand,
) -> Result<LocalizedContextPack, LocalPortError> {
    let intent = load_resource_intent(transaction, workspace_id, command.resource_intent_id)?;
    if intent.intent_digest != command.resource_intent_digest {
        return Err(LocalPortError::Invalid);
    }
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let rules = normalized_policy_rules(&command.policy_rules)?;
    validate_context_limits(&command.limits, &intent)?;
    if command.expires_at <= command.created_at {
        return Err(LocalPortError::Invalid);
    }
    let policy = policy_manifest(&rules)?;
    let policy_digest = digest(proof_application::ArtifactKind::PolicyBundleV1, &policy);
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/context.build/v2",
        "context_pack_id": command.context_pack_id.to_string(),
        "created_at": command.created_at.to_string(),
        "expires_at": command.expires_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "limits": limits_value(command.limits),
        "policy_digest": policy_digest.to_string(),
        "resource_intent_digest": command.resource_intent_digest.to_string(),
        "resource_intent_id": command.resource_intent_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((persisted_request, context_pack_id)) = transaction
        .query_row(
            "SELECT request_digest, context_pack_id FROM localized_context_build_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        if persisted_request != request_digest.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        let context_pack_id = context_pack_id
            .parse::<ContextPackId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        return load_context(transaction, workspace_id, context_pack_id);
    }
    let candidate_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM localized_context_packs WHERE context_pack_id = ?1)",
            [command.context_pack_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if candidate_exists {
        return Err(LocalPortError::Integrity(
            "candidate localized ContextPack identity already exists".to_owned(),
        ));
    }
    let resources = context_resources(transaction, &intent, &rules)?;
    let intent_value = parse_strict(intent.canonical_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let manifest = canonicalize(&json!({
        "allowed_operations": [
            "proof.dev/operation/changeset.create/v2",
            "proof.dev/operation/changeset.add/v2",
            "proof.dev/operation/changeset.get/v2",
            "proof.dev/operation/changeset.diff/v2",
            "proof.dev/operation/changeset.validate/v2",
            "proof.dev/operation/changeset.submit/v2",
            "proof.dev/operation/changeset.commit/v2",
            "proof.dev/operation/edition.create/v2",
            "proof.dev/operation/release.create/v2",
            "proof.dev/operation/object.query_released/v2"
        ],
        "api_version": LOCALIZED_CONTEXT_API_VERSION,
        "context_pack_id": command.context_pack_id.to_string(),
        "created_at": command.created_at.to_string(),
        "explicit_exclusions": [
            "agent-authority",
            "campaign-expansion",
            "deletion",
            "fallback",
            "generic-object-replacement",
            "relationship-mutation",
            "schema-mutation"
        ],
        "expires_at": command.expires_at.to_string(),
        "limits": limits_value(command.limits),
        "policy": parse_strict(policy.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        "policy_digest": policy_digest.to_string(),
        "principal_id": principal_id.to_string(),
        "resource_intent": intent_value,
        "resource_intent_digest": intent.intent_digest.to_string(),
        "resources": resources,
        "target_ordering": "object_id,schema_id,locale:utf8-ascending",
        "validator": proof_application::LOCALIZED_CONTENT_VALIDATOR,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let manifest_len =
        u64::try_from(manifest.as_bytes().len()).map_err(|_| LocalPortError::LimitExceeded)?;
    if manifest_len > command.limits.max_bytes || manifest_len > MAX_LOCALIZED_CONTEXT_BYTES {
        return Err(LocalPortError::LimitExceeded);
    }
    let context_pack_digest = digest(proof_application::ArtifactKind::ContextPackV2, &manifest);
    transaction
        .execute(
            "INSERT INTO localized_context_packs (
                 context_pack_id, workspace_id, principal_id, resource_intent_id,
                 resource_intent_digest, policy_json, policy_digest, max_objects,
                 max_edits, max_validation_attempts, max_bytes, manifest_json,
                 context_pack_digest, created_at, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                command.context_pack_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                intent.intent_id.to_string(),
                intent.intent_digest.to_string(),
                policy.as_str(),
                policy_digest.to_string(),
                i64::from(command.limits.max_objects),
                i64::from(command.limits.max_edits),
                i64::from(command.limits.max_validation_attempts),
                i64::try_from(command.limits.max_bytes)
                    .map_err(|_| LocalPortError::LimitExceeded)?,
                manifest.as_str(),
                context_pack_digest.to_string(),
                command.created_at.to_string(),
                command.expires_at.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "context.build/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "context_pack_digest": context_pack_digest.to_string(),
            "context_pack_id": command.context_pack_id.to_string(),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let effect_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &effect);
    transaction
        .execute(
            "INSERT INTO localized_context_build_operations (
                 workspace_id, principal_id, idempotency_key, request_digest,
                 effect_digest, context_pack_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                command.context_pack_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    load_context(transaction, workspace_id, command.context_pack_id)
}

fn verify_baseline_is_current(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    intent: &ContentResourceIntent,
) -> Result<(), LocalPortError> {
    let (current, _) = current_baseline(transaction, workspace_id, &intent.environment_id)?;
    if current != intent.base {
        return Err(LocalPortError::StateConflict);
    }
    Ok(())
}

fn normalized_policy_rules(
    rules: &[LocalizedPolicyRule],
) -> Result<Vec<LocalizedPolicyRule>, LocalPortError> {
    let mut normalized = Vec::with_capacity(rules.len());
    for rule in rules {
        let _ = parse_pointer(&rule.pointer)?;
        if rule.disallowed_values.is_empty() {
            return Err(LocalPortError::Invalid);
        }
        let mut values = rule.disallowed_values.clone();
        values.sort();
        if values.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(LocalPortError::Invalid);
        }
        normalized.push(LocalizedPolicyRule {
            locale: rule.locale.clone(),
            pointer: rule.pointer.clone(),
            disallowed_values: values,
        });
    }
    normalized.sort();
    if normalized
        .windows(2)
        .any(|pair| pair[0].locale == pair[1].locale && pair[0].pointer == pair[1].pointer)
    {
        return Err(LocalPortError::Invalid);
    }
    Ok(normalized)
}

fn policy_manifest(
    rules: &[LocalizedPolicyRule],
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": "proof.dev/localized-content-policy/v1",
        "rules": rules.iter().map(|rule| json!({
            "disallowed_values": rule.disallowed_values,
            "locale": rule.locale.as_str(),
            "pointer": rule.pointer,
        })).collect::<Vec<_>>(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn validate_context_limits(
    limits: &LocalizedContextLimits,
    intent: &ContentResourceIntent,
) -> Result<(), LocalPortError> {
    let object_count = intent
        .targets
        .iter()
        .map(|target| target.object_id)
        .collect::<BTreeSet<_>>()
        .len();
    let object_count = u32::try_from(object_count).map_err(|_| LocalPortError::LimitExceeded)?;
    let target_count =
        u32::try_from(intent.targets.len()).map_err(|_| LocalPortError::LimitExceeded)?;
    if limits.max_objects < object_count
        || limits.max_objects == 0
        || limits.max_objects > u32::try_from(MAX_LOCALIZED_TARGETS).unwrap_or(u32::MAX)
        || limits.max_edits < target_count
        || limits.max_edits > MAX_LOCALIZED_EDITS
        || limits.max_validation_attempts == 0
        || limits.max_validation_attempts > MAX_LOCALIZED_VALIDATION_ATTEMPTS
        || limits.max_bytes == 0
        || limits.max_bytes > MAX_LOCALIZED_CONTEXT_BYTES
    {
        return Err(LocalPortError::LimitExceeded);
    }
    Ok(())
}

fn limits_value(limits: LocalizedContextLimits) -> Value {
    json!({
        "max_bytes": limits.max_bytes,
        "max_edits": limits.max_edits,
        "max_objects": limits.max_objects,
        "max_validation_attempts": limits.max_validation_attempts,
    })
}

fn context_resources(
    transaction: &Transaction<'_>,
    intent: &ContentResourceIntent,
    rules: &[LocalizedPolicyRule],
) -> Result<Vec<Value>, LocalPortError> {
    let mut resources = Vec::with_capacity(intent.targets.len());
    for target in &intent.targets {
        let source = load_source_object(transaction, target.object_id)?;
        if source.schema_id != target.schema_id {
            return Err(LocalPortError::Invalid);
        }
        let schema =
            load_localizable_schema(transaction, &source.schema_id, source.schema_version)?;
        for rule in rules.iter().filter(|rule| rule.locale == target.locale) {
            if !schema.localizable_pointers.contains(&rule.pointer) {
                return Err(LocalPortError::Invalid);
            }
        }
        let target_state = load_rendition_at(
            transaction,
            target.object_id,
            &target.locale,
            intent.base.known_state.authoritative_sequence,
        )?;
        resources.push(json!({
            "locale": target.locale.as_str(),
            "object_id": target.object_id.to_string(),
            "schema": {
                "document": parse_strict(schema.canonical_document.as_bytes())
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
                "document_digest": schema.document_digest.to_string(),
                "localizable_pointers": schema.localizable_pointers,
                "schema_id": schema.schema_id.as_str(),
                "schema_version": schema.schema_version.get(),
            },
            "source": {
                "api_version": "proof.dev/object-revision/v1",
                "content": parse_strict(source.canonical_content.as_bytes())
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
                "digest": source.object_digest.to_string(),
                "revision": 1,
            },
            "target": target_state.map_or_else(
                || json!({
                    "absent": true,
                    "api_version": "proof.dev/object-locale-absence/v1",
                    "authoritative_sequence": intent.base.known_state.authoritative_sequence,
                }),
                |rendition| json!({
                    "absent": false,
                    "api_version": "proof.dev/object-locale-revision/v1",
                    "digest": rendition.digest.to_string(),
                    "manifest": rendition.manifest,
                    "revision": rendition.revision,
                }),
            ),
        }));
    }
    let target_locales = intent
        .targets
        .iter()
        .map(|target| &target.locale)
        .collect::<BTreeSet<_>>();
    if rules
        .iter()
        .any(|rule| !target_locales.contains(&rule.locale))
    {
        return Err(LocalPortError::Invalid);
    }
    Ok(resources)
}

struct LocalizableSchema {
    schema_id: SchemaId,
    schema_version: proof_application::SchemaVersion,
    canonical_document: String,
    document_digest: ContentDigest,
    localizable_pointers: Vec<String>,
}

fn load_localizable_schema(
    transaction: &Transaction<'_>,
    schema_id: &SchemaId,
    schema_version: proof_application::SchemaVersion,
) -> Result<LocalizableSchema, LocalPortError> {
    let (document, raw_digest): (String, String) = transaction
        .query_row(
            "SELECT document_json, document_digest FROM schema_versions
             WHERE schema_id = ?1 AND schema_version = ?2",
            (schema_id.as_str(), schema_version.get()),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    let canonical = strict_canonical(&document, "Schema")?;
    let document_digest = raw_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if digest(proof_application::ArtifactKind::SchemaVersionV1, &canonical) != document_digest {
        return Err(LocalPortError::Integrity(
            "Schema digest does not reproduce".to_owned(),
        ));
    }
    let value = parse_strict(document.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let pointers = value
        .as_object()
        .and_then(|object| object.get("x-proof-localizable"))
        .and_then(Value::as_array)
        .ok_or(LocalPortError::Invalid)?;
    if pointers.is_empty() {
        return Err(LocalPortError::Invalid);
    }
    let mut localizable_pointers = Vec::with_capacity(pointers.len());
    let mut parsed = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let pointer = pointer.as_str().ok_or(LocalPortError::Invalid)?.to_owned();
        let segments = parse_pointer(&pointer)?;
        localizable_pointers.push(pointer);
        parsed.push(segments);
    }
    if !localizable_pointers.is_sorted()
        || localizable_pointers
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(LocalPortError::Invalid);
    }
    for (index, left) in parsed.iter().enumerate() {
        for right in parsed.iter().skip(index + 1) {
            if is_prefix(left, right) || is_prefix(right, left) {
                return Err(LocalPortError::Invalid);
            }
        }
    }
    Ok(LocalizableSchema {
        schema_id: schema_id.clone(),
        schema_version,
        canonical_document: document,
        document_digest,
        localizable_pointers,
    })
}

fn parse_pointer(pointer: &str) -> Result<Vec<String>, LocalPortError> {
    if pointer.is_empty() || !pointer.starts_with('/') {
        return Err(LocalPortError::Invalid);
    }
    let mut segments = Vec::new();
    for raw in pointer[1..].split('/') {
        let mut decoded = String::new();
        let mut chars = raw.chars();
        while let Some(character) = chars.next() {
            if character == '~' {
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err(LocalPortError::Invalid),
                }
            } else {
                decoded.push(character);
            }
        }
        let encoded = decoded.replace('~', "~0").replace('/', "~1");
        if encoded != raw {
            return Err(LocalPortError::Invalid);
        }
        segments.push(decoded);
    }
    Ok(segments)
}

fn is_prefix(left: &[String], right: &[String]) -> bool {
    left.len() < right.len() && left.iter().zip(right).all(|(left, right)| left == right)
}

struct RenditionAtState {
    revision: u32,
    digest: ContentDigest,
    manifest: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReproducedLocalizedProjections {
    pub(super) renditions: Vec<ObjectLocaleRevision>,
    pub(super) authoritative_sequence: u64,
    pub(super) state_digest: ContentDigest,
    pub(super) state_manifest_json: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "localized projection reproduction verifies every immutable commit and rebuilds its rendition facts"
)]
pub(super) fn reproduce_localized_projections(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    predecessor_sequence: u64,
    predecessor_digest: ContentDigest,
    schemas: &[super::ExpectedSchemaProjection],
    objects: &[super::ExpectedObjectProjection],
) -> Result<Option<ReproducedLocalizedProjections>, LocalPortError> {
    type CommitRow = (
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
        String,
        String,
        String,
        String,
    );
    let mut statement = transaction
        .prepare(
            "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                    sealed_changeset_digest, validation_results_digest,
                    previous_state_api_version, previous_authoritative_sequence,
                    previous_state_digest, resulting_authoritative_sequence,
                    resulting_state_digest, resulting_state_json, committed_at, effect_digest
             FROM localized_commits ORDER BY resulting_authoritative_sequence",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
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
                row.get(12)?,
                row.get(13)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let commits = rows
        .map(|row| row.map_err(|error| LocalPortError::Storage(error.to_string())))
        .collect::<Result<Vec<CommitRow>, _>>()?;
    drop(statement);
    if commits.is_empty() {
        return Ok(None);
    }

    let predecessor_artifact: Option<(i64, Option<String>, Option<String>)> = transaction
        .query_row(
            "SELECT authoritative_sequence, manifest_json, changeset_id
             FROM known_state_artifacts WHERE api_version = ?1 AND state_digest = ?2",
            (KNOWN_STATE_V1_API_VERSION, predecessor_digest.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if !matches!(predecessor_artifact, Some((sequence, None, None))
        if u64::try_from(sequence).ok() == Some(predecessor_sequence))
    {
        return Err(LocalPortError::Integrity(
            "localized commit chain lacks its exact v1 predecessor artifact".to_owned(),
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
        .map(|object| proof_canonical::ObjectStateReference {
            object_id: object.object_id,
            revision: object.revision,
            schema_id: object.schema_id.clone(),
            schema_version: object.schema_version,
            lifecycle_state: proof_application::ObjectLifecycleState::Active,
            object_digest: object.object_digest,
        })
        .collect::<Vec<_>>();
    let mut current_state = KnownStateArtifactReference {
        api_version: KNOWN_STATE_V1_API_VERSION.to_owned(),
        authoritative_sequence: predecessor_sequence,
        digest: predecessor_digest,
    };
    let mut heads =
        BTreeMap::<(ObjectId, proof_application::LocaleId), ObjectLocaleRevision>::new();
    let mut renditions = Vec::new();
    let mut final_manifest = None;

    for row in commits {
        if row.1 != workspace_id.to_string() {
            return Err(LocalPortError::Integrity(
                "localized commit belongs to another Workspace".to_owned(),
            ));
        }
        let changeset_id = row
            .0
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let principal_id = row
            .2
            .parse::<proof_application::PrincipalId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let idempotency_key = row
            .3
            .parse::<proof_application::IdempotencyKey>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let sealed_changeset_digest = row
            .4
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let validation_results_digest = row
            .5
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let previous_state = KnownStateArtifactReference {
            api_version: row.6,
            authoritative_sequence: u64::try_from(row.7).map_err(|_| {
                LocalPortError::Integrity("invalid localized predecessor sequence".to_owned())
            })?,
            digest: row
                .8
                .parse::<ContentDigest>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        };
        let resulting_sequence = u64::try_from(row.9).map_err(|_| {
            LocalPortError::Integrity("invalid localized result sequence".to_owned())
        })?;
        let resulting_digest = row
            .10
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let committed_at = row
            .12
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if previous_state != current_state {
            return Err(LocalPortError::Integrity(
                "localized commit predecessor chain is broken".to_owned(),
            ));
        }

        let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
        if changeset.status != ChangeSetStatus::Committed
            || changeset.principal_id != principal_id
            || changeset.base_state != current_state
        {
            return Err(LocalPortError::Integrity(
                "localized commit lifecycle or base does not reproduce".to_owned(),
            ));
        }
        let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
        let validation = sealed_validation_head(transaction, &changeset)?;
        let approval = load_localized_approval(transaction, &changeset)?.ok_or_else(|| {
            LocalPortError::Integrity("localized commit lacks approval".to_owned())
        })?;
        if sealed_changeset_digest
            != validation.sealed_changeset_digest.ok_or_else(|| {
                LocalPortError::Integrity("localized commit validation lacks seal".to_owned())
            })?
            || validation_results_digest != validation.validation_results_digest
            || committed_at < approval.approved_at
        {
            return Err(LocalPortError::Integrity(
                "localized commit evidence does not reproduce".to_owned(),
            ));
        }
        let (_, _, effective_edits) = proposal(&changeset)?;
        if effective_edits.is_empty() {
            return Err(LocalPortError::Integrity(
                "localized commit has no effective Edits".to_owned(),
            ));
        }
        let mut commit_renditions = Vec::with_capacity(effective_edits.len());
        let mut next_sequence = current_state.authoritative_sequence;
        for edit in &effective_edits {
            let head = heads.get(&(edit.input.object_id, edit.input.locale.clone()));
            verify_reproduced_edit_input(&edit.input, &intent, objects, schemas, head)?;
            next_sequence = next_sequence.checked_add(1).ok_or_else(|| {
                LocalPortError::Integrity("authoritative sequence overflow".to_owned())
            })?;
            let revision = proof_application::LocaleRevision::new(
                head.map_or(1, |rendition| rendition.revision.get().saturating_add(1)),
            )
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            let previous_revision_digest = head.map(|rendition| rendition.rendition_digest);
            let content = parse_strict(edit.input.canonical_content.as_bytes())
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            let (manifest, rendition_digest) = proof_canonical::object_locale_revision(
                &proof_canonical::ObjectLocaleRevisionInput {
                    workspace_id,
                    object_id: edit.input.object_id,
                    locale: &edit.input.locale,
                    revision,
                    previous_revision_digest,
                    source_object_revision: edit.input.expected_source.revision,
                    source_object_digest: edit.input.expected_source.digest,
                    schema_id: &edit.input.expected_source.schema_id,
                    schema_version: edit.input.expected_source.schema_version,
                    content: &content,
                    changeset_id,
                    edit_id: edit.edit_id,
                    authoritative_sequence: next_sequence,
                },
            )
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
            let rendition = ObjectLocaleRevision {
                workspace_id,
                object_id: edit.input.object_id,
                locale: edit.input.locale.clone(),
                revision,
                previous_revision_digest,
                source_object_revision: edit.input.expected_source.revision,
                source_object_digest: edit.input.expected_source.digest,
                schema_id: edit.input.expected_source.schema_id.clone(),
                schema_version: edit.input.expected_source.schema_version,
                canonical_content: edit.input.canonical_content.clone(),
                changeset_id,
                edit_id: edit.edit_id,
                authoritative_sequence: next_sequence,
                manifest_json: manifest.as_str().to_owned(),
                rendition_digest,
            };
            heads.insert(
                (rendition.object_id, rendition.locale.clone()),
                rendition.clone(),
            );
            renditions.push(rendition.clone());
            commit_renditions.push(rendition);
        }
        if next_sequence != resulting_sequence {
            return Err(LocalPortError::Integrity(
                "localized commit sequence does not match its effective Edit count".to_owned(),
            ));
        }
        let locale_references = heads
            .values()
            .map(|rendition| proof_canonical::LocaleStateReference {
                object_id: rendition.object_id,
                locale: rendition.locale.clone(),
                revision: rendition.revision,
                rendition_digest: rendition.rendition_digest,
                source_object_digest: rendition.source_object_digest,
                schema_id: rendition.schema_id.clone(),
                schema_version: rendition.schema_version,
            })
            .collect::<Vec<_>>();
        let previous_reference = proof_canonical::PreviousKnownStateReference {
            api_version: current_state.api_version.clone(),
            authoritative_sequence: current_state.authoritative_sequence,
            digest: current_state.digest,
        };
        let state_manifest = proof_canonical::known_state_v2_manifest(
            workspace_id,
            next_sequence,
            &schema_references,
            &object_references,
            &locale_references,
            &previous_reference,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let expected_state_digest = digest(
            proof_application::ArtifactKind::KnownStateV2,
            &state_manifest,
        );
        if row.11 != state_manifest.as_str() || resulting_digest != expected_state_digest {
            return Err(LocalPortError::Integrity(
                "localized commit resulting state does not reproduce from Edit facts".to_owned(),
            ));
        }
        let state_artifact: Option<(i64, String, Option<String>)> = transaction
            .query_row(
                "SELECT authoritative_sequence, manifest_json, changeset_id
                 FROM known_state_artifacts WHERE api_version = ?1 AND state_digest = ?2",
                (
                    KNOWN_STATE_V2_API_VERSION,
                    expected_state_digest.to_string(),
                ),
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let changeset_id_text = changeset_id.to_string();
        if !matches!(state_artifact, Some((sequence, ref manifest, Some(ref producer)))
            if u64::try_from(sequence).ok() == Some(next_sequence)
                && manifest == state_manifest.as_str()
                && producer == &changeset_id_text)
        {
            return Err(LocalPortError::Integrity(
                "localized Known State artifact does not reproduce".to_owned(),
            ));
        }
        let resulting_state = KnownStateArtifactReference {
            api_version: KNOWN_STATE_V2_API_VERSION.to_owned(),
            authoritative_sequence: next_sequence,
            digest: expected_state_digest,
        };
        let result = CommittedLocalizedChangeSet {
            changeset_id,
            sealed_changeset_digest,
            validation_results_digest,
            previous_state: current_state,
            resulting_state: resulting_state.clone(),
            renditions: commit_renditions,
            committed_at,
            status: ChangeSetStatus::Committed,
        };
        let request = canonicalize(&json!({
            "api_version": "proof.dev/operation/changeset.commit/v2",
            "changeset_id": changeset_id.to_string(),
            "committed_at": committed_at.to_string(),
            "idempotency_key": idempotency_key.to_string(),
        }))
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
        if row.13 != localized_commit_effect(request_digest, &result)?.to_string() {
            return Err(LocalPortError::Integrity(
                "localized commit operation effect does not reproduce".to_owned(),
            ));
        }
        current_state = resulting_state;
        final_manifest = Some(state_manifest.as_str().to_owned());
    }

    let artifact_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM known_state_artifacts WHERE api_version = ?1",
            [KNOWN_STATE_V2_API_VERSION],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if usize::try_from(artifact_count).ok()
        != Some(
            renditions
                .iter()
                .map(|rendition| rendition.changeset_id)
                .collect::<BTreeSet<_>>()
                .len(),
        )
    {
        return Err(LocalPortError::Integrity(
            "localized Known State artifact history has orphan or missing entries".to_owned(),
        ));
    }
    Ok(Some(ReproducedLocalizedProjections {
        renditions,
        authoritative_sequence: current_state.authoritative_sequence,
        state_digest: current_state.digest,
        state_manifest_json: final_manifest.ok_or_else(|| {
            LocalPortError::Integrity("localized commit chain lacks a final state".to_owned())
        })?,
    }))
}

fn verify_reproduced_edit_input(
    input: &ObjectLocalePutInput,
    intent: &ContentResourceIntent,
    objects: &[super::ExpectedObjectProjection],
    schemas: &[super::ExpectedSchemaProjection],
    head: Option<&ObjectLocaleRevision>,
) -> Result<(), LocalPortError> {
    let source = reproduced_edit_source(input, intent, objects, head)?;
    let schema = schemas
        .iter()
        .find(|schema| {
            schema.schema_id == source.schema_id && schema.schema_version == source.schema_version
        })
        .ok_or_else(|| {
            LocalPortError::Integrity("committed localized Edit Schema is missing".to_owned())
        })?;
    let (schema_value, parsed_pointers) = reproduced_localizable_pointers(schema)?;
    verify_reproduced_localized_content(input, source, &schema_value, &parsed_pointers)
}

fn reproduced_edit_source<'a>(
    input: &ObjectLocalePutInput,
    intent: &ContentResourceIntent,
    objects: &'a [super::ExpectedObjectProjection],
    head: Option<&ObjectLocaleRevision>,
) -> Result<&'a super::ExpectedObjectProjection, LocalPortError> {
    let target = proof_application::LocalizedContentTarget {
        object_id: input.object_id,
        schema_id: input.expected_source.schema_id.clone(),
        locale: input.locale.clone(),
    };
    if intent.targets.binary_search(&target).is_err() {
        return Err(LocalPortError::Integrity(
            "committed localized Edit lies outside its resource intent".to_owned(),
        ));
    }
    let source = objects
        .iter()
        .find(|object| object.object_id == input.object_id)
        .ok_or_else(|| {
            LocalPortError::Integrity("committed localized Edit source is missing".to_owned())
        })?;
    if input.expected_source.revision != source.revision
        || input.expected_source.digest != source.object_digest
        || input.expected_source.schema_id != source.schema_id
        || input.expected_source.schema_version != source.schema_version
    {
        return Err(LocalPortError::Integrity(
            "committed localized Edit source precondition does not reproduce".to_owned(),
        ));
    }
    match (&input.expected_target, head) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if expected.revision == actual.revision
                && expected.digest == actual.rendition_digest => {}
        _ => {
            return Err(LocalPortError::Integrity(
                "committed localized Edit target precondition does not reproduce".to_owned(),
            ));
        }
    }
    Ok(source)
}

fn reproduced_localizable_pointers(
    schema: &super::ExpectedSchemaProjection,
) -> Result<(Value, Vec<Vec<String>>), LocalPortError> {
    let schema_value = parse_strict(schema.document_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let pointers = schema_value
        .as_object()
        .and_then(|object| object.get("x-proof-localizable"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LocalPortError::Integrity(
                "committed localized Schema lacks localizable paths".to_owned(),
            )
        })?;
    let mut localizable_pointers = Vec::with_capacity(pointers.len());
    let mut parsed_pointers = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let pointer = pointer.as_str().ok_or_else(|| {
            LocalPortError::Integrity("committed localizable path is not a string".to_owned())
        })?;
        let parsed = parse_pointer(pointer).map_err(|_| {
            LocalPortError::Integrity("committed localizable path is invalid".to_owned())
        })?;
        localizable_pointers.push(pointer.to_owned());
        parsed_pointers.push(parsed);
    }
    if localizable_pointers.is_empty()
        || !localizable_pointers.is_sorted()
        || localizable_pointers
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        || parsed_pointers.iter().enumerate().any(|(index, left)| {
            parsed_pointers
                .iter()
                .skip(index + 1)
                .any(|right| is_prefix(left, right) || is_prefix(right, left))
        })
    {
        return Err(LocalPortError::Integrity(
            "committed localizable path set is not canonical".to_owned(),
        ));
    }
    Ok((schema_value, parsed_pointers))
}

fn verify_reproduced_localized_content(
    input: &ObjectLocalePutInput,
    source: &super::ExpectedObjectProjection,
    schema_value: &Value,
    parsed_pointers: &[Vec<String>],
) -> Result<(), LocalPortError> {
    let source_value = parse_strict(source.content_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let target_value = parse_strict(input.canonical_content.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let target_canonical = canonicalize(&target_value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if target_canonical.as_str() != input.canonical_content || !target_value.is_object() {
        return Err(LocalPortError::Integrity(
            "committed localized content is not a canonical Object".to_owned(),
        ));
    }
    let validator = jsonschema::draft202012::new(schema_value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if validator.iter_errors(&target_value).next().is_some() {
        return Err(LocalPortError::Integrity(
            "committed localized content fails its Schema".to_owned(),
        ));
    }
    let mut reconstructed = source_value.clone();
    for segments in parsed_pointers {
        let replacement = string_at_pointer(&target_value, segments).map_err(|_| {
            LocalPortError::Integrity("committed localized value is not a string".to_owned())
        })?;
        string_at_pointer(&source_value, segments).map_err(|_| {
            LocalPortError::Integrity("committed source localizable value is invalid".to_owned())
        })?;
        set_string_at_pointer(&mut reconstructed, segments, replacement.to_owned()).map_err(
            |_| {
                LocalPortError::Integrity("committed localizable path cannot be applied".to_owned())
            },
        )?;
    }
    let reconstructed = canonicalize(&reconstructed)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if reconstructed.as_str() != input.canonical_content {
        return Err(LocalPortError::Integrity(
            "committed localized Edit changes a non-localizable field".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn persisted_locale_projections(
    connection: &Connection,
) -> Result<Vec<ObjectLocaleRevision>, LocalPortError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, locale, revision FROM object_locale_revisions
             ORDER BY object_id, locale, revision",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut renditions = Vec::new();
    for row in rows {
        let (raw_object_id, raw_locale, raw_revision) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let object_id = raw_object_id
            .parse::<ObjectId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let locale = proof_application::LocaleId::new(raw_locale)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let revision = proof_application::LocaleRevision::new(
            u32::try_from(raw_revision)
                .map_err(|_| LocalPortError::Integrity("invalid locale revision".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        renditions.push(load_object_locale_revision(
            connection, object_id, &locale, revision,
        )?);
    }
    Ok(renditions)
}

pub(super) fn insert_locale_projections(
    transaction: &Transaction<'_>,
    renditions: &[ObjectLocaleRevision],
) -> Result<(), LocalPortError> {
    for rendition in renditions {
        transaction
            .execute(
                "INSERT INTO object_locale_revisions (
                     workspace_id, object_id, locale, revision, previous_revision_digest,
                     source_object_revision, source_object_digest, schema_id, schema_version,
                     content_json, changeset_id, edit_id, authoritative_sequence,
                     manifest_json, rendition_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    rendition.workspace_id.to_string(),
                    rendition.object_id.to_string(),
                    rendition.locale.as_str(),
                    i64::from(rendition.revision.get()),
                    rendition
                        .previous_revision_digest
                        .map(|value| value.to_string()),
                    i64::from(rendition.source_object_revision.get()),
                    rendition.source_object_digest.to_string(),
                    rendition.schema_id.as_str(),
                    i64::from(rendition.schema_version.get()),
                    rendition.canonical_content.as_str(),
                    rendition.changeset_id.to_string(),
                    rendition.edit_id.to_string(),
                    i64::try_from(rendition.authoritative_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "rendition sequence exceeds SQLite range".to_owned(),
                        )
                    })?,
                    rendition.manifest_json.as_str(),
                    rendition.rendition_digest.to_string(),
                ],
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn load_rendition_at(
    transaction: &Transaction<'_>,
    object_id: ObjectId,
    locale: &proof_application::LocaleId,
    sequence: u64,
) -> Result<Option<RenditionAtState>, LocalPortError> {
    let row: Option<(i64, String, String)> = transaction
        .query_row(
            "SELECT revision, rendition_digest, manifest_json
             FROM object_locale_revisions
             WHERE object_id = ?1 AND locale = ?2 AND authoritative_sequence <= ?3
             ORDER BY revision DESC LIMIT 1",
            (
                object_id.to_string(),
                locale.as_str(),
                i64::try_from(sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    row.map(|(revision, raw_digest, manifest)| {
        let canonical = strict_canonical(&manifest, "locale rendition")?;
        let rendition_digest = raw_digest
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if digest(
            proof_application::ArtifactKind::ObjectLocaleRevisionV1,
            &canonical,
        ) != rendition_digest
        {
            return Err(LocalPortError::Integrity(
                "locale rendition digest does not reproduce".to_owned(),
            ));
        }
        Ok(RenditionAtState {
            revision: u32::try_from(revision)
                .map_err(|_| LocalPortError::Integrity("invalid rendition revision".to_owned()))?,
            digest: rendition_digest,
            manifest: parse_strict(manifest.as_bytes())
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        })
    })
    .transpose()
}

#[allow(clippy::too_many_lines)]
fn load_context(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    context_pack_id: ContextPackId,
) -> Result<LocalizedContextPack, LocalPortError> {
    type ContextRow = (
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
        String,
        String,
        String,
        String,
        String,
    );
    let row: ContextRow = transaction
        .query_row(
            "SELECT workspace_id, principal_id, resource_intent_id,
                    resource_intent_digest, policy_digest, max_objects, max_edits,
                    max_validation_attempts, max_bytes, manifest_json,
                    context_pack_digest, created_at, expires_at, policy_json
             FROM localized_context_packs WHERE context_pack_id = ?1",
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
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.0 != workspace_id.to_string() {
        return Err(LocalPortError::NotFound);
    }
    let principal_id = row
        .1
        .parse()
        .map_err(|error: proof_application::IdentifierError| {
            LocalPortError::Integrity(error.to_string())
        })?;
    let resource_intent_id = row
        .2
        .parse::<ContentResourceIntentId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let intent = load_resource_intent(transaction, workspace_id, resource_intent_id)?;
    let resource_intent_digest = row
        .3
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if resource_intent_digest != intent.intent_digest {
        return Err(LocalPortError::Integrity(
            "ContextPack resource-intent digest differs".to_owned(),
        ));
    }
    let policy = strict_canonical(&row.13, "localized policy")?;
    let policy_digest = row
        .4
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if digest(proof_application::ArtifactKind::PolicyBundleV1, &policy) != policy_digest {
        return Err(LocalPortError::Integrity(
            "ContextPack policy digest does not reproduce".to_owned(),
        ));
    }
    let limits = LocalizedContextLimits {
        max_objects: u32::try_from(row.5)
            .map_err(|_| LocalPortError::Integrity("invalid Object budget".to_owned()))?,
        max_edits: u32::try_from(row.6)
            .map_err(|_| LocalPortError::Integrity("invalid Edit budget".to_owned()))?,
        max_validation_attempts: u32::try_from(row.7)
            .map_err(|_| LocalPortError::Integrity("invalid validation budget".to_owned()))?,
        max_bytes: u64::try_from(row.8)
            .map_err(|_| LocalPortError::Integrity("invalid byte budget".to_owned()))?,
    };
    validate_context_limits(&limits, &intent)?;
    let manifest = strict_canonical(&row.9, "localized ContextPack")?;
    let context_pack_digest = row
        .10
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if digest(proof_application::ArtifactKind::ContextPackV2, &manifest) != context_pack_digest {
        return Err(LocalPortError::Integrity(
            "ContextPack digest does not reproduce".to_owned(),
        ));
    }
    let manifest_value = parse_strict(row.9.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let embedded_intent = manifest_value
        .as_object()
        .and_then(|object| object.get("resource_intent"))
        .ok_or_else(|| LocalPortError::Integrity("ContextPack intent is missing".to_owned()))?;
    let embedded = canonicalize(embedded_intent)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if embedded.as_str() != intent.canonical_json {
        return Err(LocalPortError::Integrity(
            "ContextPack does not embed the exact resource intent".to_owned(),
        ));
    }
    let created_at = row
        .11
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expires_at = row
        .12
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if expires_at <= created_at {
        return Err(LocalPortError::Integrity(
            "ContextPack freshness window is invalid".to_owned(),
        ));
    }
    Ok(LocalizedContextPack {
        context_pack_id,
        workspace_id,
        principal_id,
        resource_intent_id,
        resource_intent_digest,
        base: intent.base,
        policy_digest,
        limits,
        created_at,
        expires_at,
        manifest_json: row.9,
        context_pack_digest,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "state verification reconstructs every versioned fact family and predecessor edge"
)]
fn verify_v2_state_semantics(
    transaction: &Connection,
    workspace_id: proof_application::WorkspaceId,
    sequence: u64,
    state_digest: ContentDigest,
    canonical: &proof_canonical::CanonicalJson,
) -> Result<(), LocalPortError> {
    type StateRow = (String, i64, String, String, Option<String>);
    let row: StateRow = transaction
        .query_row(
            "SELECT commits.previous_state_api_version,
                    commits.previous_authoritative_sequence,
                    commits.previous_state_digest, artifacts.manifest_json,
                    artifacts.changeset_id
             FROM known_state_artifacts AS artifacts
             JOIN localized_commits AS commits
               ON commits.changeset_id = artifacts.changeset_id
             WHERE artifacts.api_version = ?1
                   AND artifacts.authoritative_sequence = ?2
                   AND artifacts.state_digest = ?3",
            (
                KNOWN_STATE_V2_API_VERSION,
                i64::try_from(sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                state_digest.to_string(),
            ),
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("v2 Known State lacks its producing commit".to_owned())
        })?;
    if row.3 != canonical.as_str() || row.4.is_none() {
        return Err(LocalPortError::Integrity(
            "v2 Known State artifact bytes or producer differ".to_owned(),
        ));
    }
    let previous_sequence = u64::try_from(row.1)
        .map_err(|_| LocalPortError::Integrity("invalid predecessor state sequence".to_owned()))?;
    let previous_digest = row
        .2
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let previous = proof_canonical::PreviousKnownStateReference {
        api_version: row.0,
        authoritative_sequence: previous_sequence,
        digest: previous_digest,
    };
    verify_state_artifact_reference(transaction, workspace_id, &previous)?;
    let schemas = schema_state_references(transaction, sequence)?;
    let objects = object_state_references(transaction, sequence)?;
    let renditions = locale_state_references(transaction, sequence)?;
    let expected = proof_canonical::known_state_v2_manifest(
        workspace_id,
        sequence,
        &schemas,
        &objects,
        &renditions,
        &previous,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if expected.as_str() != canonical.as_str()
        || digest(proof_application::ArtifactKind::KnownStateV2, &expected) != state_digest
    {
        return Err(LocalPortError::Integrity(
            "v2 Known State semantic projection does not reproduce".to_owned(),
        ));
    }
    let mut statement = transaction
        .prepare(
            "SELECT authoritative_sequence FROM schema_versions
             WHERE authoritative_sequence <= ?1
             UNION ALL
             SELECT authoritative_sequence FROM object_revisions
             WHERE authoritative_sequence <= ?1
             UNION ALL
             SELECT authoritative_sequence FROM object_locale_revisions
             WHERE authoritative_sequence <= ?1
             ORDER BY authoritative_sequence",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
            })?],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    for (index, row) in rows.enumerate() {
        let fact_sequence =
            u64::try_from(row.map_err(|error| LocalPortError::Storage(error.to_string()))?)
                .map_err(|_| LocalPortError::Integrity("invalid fact sequence".to_owned()))?;
        if fact_sequence != u64::try_from(index + 1).unwrap_or(u64::MAX) {
            return Err(LocalPortError::Integrity(
                "authoritative fact sequence is not contiguous".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_state_artifact_reference(
    transaction: &Connection,
    workspace_id: proof_application::WorkspaceId,
    reference: &proof_canonical::PreviousKnownStateReference,
) -> Result<(), LocalPortError> {
    let manifest: Option<Option<String>> = transaction
        .query_row(
            "SELECT manifest_json FROM known_state_artifacts
             WHERE api_version = ?1 AND authoritative_sequence = ?2 AND state_digest = ?3",
            (
                reference.api_version.as_str(),
                i64::try_from(reference.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                reference.digest.to_string(),
            ),
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let manifest = manifest.ok_or_else(|| {
        LocalPortError::Integrity("Known State predecessor artifact is missing".to_owned())
    })?;
    match reference.api_version.as_str() {
        KNOWN_STATE_V1_API_VERSION => {
            if manifest.is_some() {
                return Err(LocalPortError::Integrity(
                    "v1 Known State artifact unexpectedly carries v2 bytes".to_owned(),
                ));
            }
            let (_, reproduced) = super::reproducible_known_state_at(
                transaction,
                workspace_id,
                reference.authoritative_sequence,
            )
            .map_err(LocalPortError::Integrity)?;
            if reproduced != reference.digest {
                return Err(LocalPortError::Integrity(
                    "v1 predecessor state does not reproduce".to_owned(),
                ));
            }
        }
        KNOWN_STATE_V2_API_VERSION => {
            let manifest = manifest.ok_or_else(|| {
                LocalPortError::Integrity("v2 predecessor state bytes are missing".to_owned())
            })?;
            let canonical = strict_canonical(&manifest, "v2 predecessor state")?;
            if digest(proof_application::ArtifactKind::KnownStateV2, &canonical) != reference.digest
            {
                return Err(LocalPortError::Integrity(
                    "v2 predecessor state digest does not reproduce".to_owned(),
                ));
            }
            verify_v2_state_semantics(
                transaction,
                workspace_id,
                reference.authoritative_sequence,
                reference.digest,
                &canonical,
            )?;
        }
        _ => {
            return Err(LocalPortError::Integrity(
                "Known State predecessor API version is unsupported".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_v2_release_record(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    release_id: ReleaseId,
) -> Result<(), LocalPortError> {
    let _ = load_localized_release(transaction, workspace_id, release_id)?;
    Ok(())
}

fn verify_v2_edition_record(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    edition_id: EditionId,
) -> Result<(), LocalPortError> {
    let _ = load_localized_edition(transaction, workspace_id, edition_id)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn create_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &CreateLocalizedChangeSetCommand,
) -> Result<LocalizedChangeSet, LocalPortError> {
    let intent = load_resource_intent(transaction, workspace_id, command.resource_intent_id)?;
    let context = load_context(transaction, workspace_id, command.context_pack_id)?;
    if intent.intent_digest != command.resource_intent_digest
        || context.resource_intent_id != intent.intent_id
        || context.resource_intent_digest != intent.intent_digest
        || context.context_pack_digest != command.context_pack_digest
    {
        return Err(LocalPortError::IntentMismatch);
    }
    if intent.issued_by_principal_id != principal_id {
        return Err(LocalPortError::NotFound);
    }
    if command.created_at < context.created_at || command.created_at >= context.expires_at {
        return Err(LocalPortError::PolicyDenied);
    }
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/changeset.create/v2",
        "changeset_id": command.changeset_id.to_string(),
        "context_pack_digest": command.context_pack_digest.to_string(),
        "context_pack_id": command.context_pack_id.to_string(),
        "created_at": command.created_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "intent": command.intent.as_str(),
        "resource_intent_digest": command.resource_intent_digest.to_string(),
        "resource_intent_id": command.resource_intent_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((persisted_request, changeset_id)) = transaction
        .query_row(
            "SELECT effect_digest, changeset_id FROM localized_changesets
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        let changeset_id = changeset_id
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
        let expected_effect = changeset_creation_effect(request_digest, &changeset)?;
        if persisted_request != expected_effect.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(changeset);
    }
    let candidate_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM localized_changesets WHERE changeset_id = ?1
                 UNION ALL SELECT 1 FROM changesets WHERE changeset_id = ?1
             )",
            [command.changeset_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if candidate_exists {
        return Err(LocalPortError::Integrity(
            "candidate ChangeSet identity already exists".to_owned(),
        ));
    }
    let draft = LocalizedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id,
        principal_id,
        intent: command.intent.clone(),
        resource_intent_id: intent.intent_id,
        resource_intent_digest: intent.intent_digest,
        context_pack_id: context.context_pack_id,
        context_pack_digest: context.context_pack_digest,
        base_state: intent.base.known_state,
        created_at: command.created_at,
        status: ChangeSetStatus::Draft,
        edits: Vec::new(),
        proposal_digest: None,
        sealed_changeset_digest: None,
    };
    let effect_digest = changeset_creation_effect(request_digest, &draft)?;
    transaction
        .execute(
            "INSERT INTO localized_changesets (
                 changeset_id, workspace_id, principal_id, intent, resource_intent_id,
                 resource_intent_digest, context_pack_id, context_pack_digest,
                 base_state_api_version, base_authoritative_sequence, base_state_digest,
                 idempotency_key, created_at, lifecycle_status, proposal_digest,
                 effective_leaf_digest, sealed_changeset_digest, effect_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       'draft', NULL, NULL, NULL, ?14)",
            params![
                command.changeset_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                command.intent.as_str(),
                intent.intent_id.to_string(),
                intent.intent_digest.to_string(),
                context.context_pack_id.to_string(),
                context.context_pack_digest.to_string(),
                draft.base_state.api_version,
                i64::try_from(draft.base_state.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity("base sequence exceeds SQLite range".to_owned())
                })?,
                draft.base_state.digest.to_string(),
                command.idempotency_key.to_string(),
                command.created_at.to_string(),
                effect_digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    load_changeset(transaction, workspace_id, command.changeset_id)
}

fn changeset_creation_effect(
    request_digest: ContentDigest,
    changeset: &LocalizedChangeSet,
) -> Result<ContentDigest, LocalPortError> {
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.create/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "base_state": state_reference_value(&changeset.base_state),
            "changeset_id": changeset.changeset_id.to_string(),
            "context_pack_digest": changeset.context_pack_digest.to_string(),
            "context_pack_id": changeset.context_pack_id.to_string(),
            "resource_intent_digest": changeset.resource_intent_digest.to_string(),
            "resource_intent_id": changeset.resource_intent_id.to_string(),
            "status": "draft",
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

fn state_reference_value(state: &KnownStateArtifactReference) -> Value {
    json!({
        "api_version": state.api_version,
        "authoritative_sequence": state.authoritative_sequence,
        "digest": state.digest.to_string(),
    })
}

#[allow(clippy::too_many_lines)]
fn load_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    changeset_id: ChangeSetId,
) -> Result<LocalizedChangeSet, LocalPortError> {
    type ChangeSetRow = (
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
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: ChangeSetRow = transaction
        .query_row(
            "SELECT workspace_id, principal_id, intent, resource_intent_id,
                    resource_intent_digest, context_pack_id, context_pack_digest,
                    base_state_api_version, base_authoritative_sequence, base_state_digest,
                    created_at, lifecycle_status, proposal_digest, effective_leaf_digest,
                    sealed_changeset_digest
             FROM localized_changesets WHERE changeset_id = ?1",
            [changeset_id.to_string()],
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
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.0 != workspace_id.to_string() {
        return Err(LocalPortError::NotFound);
    }
    let principal_id = row
        .1
        .parse()
        .map_err(|error: proof_application::IdentifierError| {
            LocalPortError::Integrity(error.to_string())
        })?;
    let intent = proof_application::ChangeSetIntent::new(row.2)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let resource_intent_id = row
        .3
        .parse::<ContentResourceIntentId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let resource_intent_digest = row
        .4
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let context_pack_id = row
        .5
        .parse::<ContextPackId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let context_pack_digest = row
        .6
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let persisted_intent = load_resource_intent(transaction, workspace_id, resource_intent_id)?;
    let persisted_context = load_context(transaction, workspace_id, context_pack_id)?;
    if persisted_intent.intent_digest != resource_intent_digest
        || persisted_context.context_pack_digest != context_pack_digest
        || persisted_context.resource_intent_id != resource_intent_id
    {
        return Err(LocalPortError::Integrity(
            "localized ChangeSet evidence references do not reproduce".to_owned(),
        ));
    }
    let base_state = KnownStateArtifactReference {
        api_version: row.7,
        authoritative_sequence: u64::try_from(row.8)
            .map_err(|_| LocalPortError::Integrity("invalid base state sequence".to_owned()))?,
        digest: row
            .9
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    };
    if base_state != persisted_intent.base.known_state {
        return Err(LocalPortError::Integrity(
            "localized ChangeSet base differs from resource intent".to_owned(),
        ));
    }
    let created_at = row
        .10
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let status = parse_localized_status(&row.11)?;
    let edits = load_edits(transaction, changeset_id)?;
    let mut changeset = LocalizedChangeSet {
        changeset_id,
        workspace_id,
        principal_id,
        intent,
        resource_intent_id,
        resource_intent_digest,
        context_pack_id,
        context_pack_digest,
        base_state,
        created_at,
        status,
        edits,
        proposal_digest: parse_optional_digest(row.12.as_deref())?,
        sealed_changeset_digest: parse_optional_digest(row.14.as_deref())?,
    };
    if changeset.edits.is_empty() {
        if changeset.proposal_digest.is_some()
            || row.13.is_some()
            || changeset.sealed_changeset_digest.is_some()
        {
            return Err(LocalPortError::Integrity(
                "empty localized ChangeSet has proposal evidence".to_owned(),
            ));
        }
    } else {
        let (proposal_digest, effective_digest, _) = proposal(&changeset)?;
        let persisted_effective = row
            .13
            .as_deref()
            .ok_or_else(|| {
                LocalPortError::Integrity("effective-leaf digest is missing".to_owned())
            })?
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if changeset.proposal_digest != Some(proposal_digest)
            || persisted_effective != effective_digest
        {
            return Err(LocalPortError::Integrity(
                "localized ChangeSet proposal does not reproduce".to_owned(),
            ));
        }
        if let Some(sealed) = changeset.sealed_changeset_digest {
            let latest = load_validation_chain(transaction, &changeset)?
                .last()
                .cloned()
                .ok_or_else(|| {
                    LocalPortError::Integrity("ChangeSet seal lacks validation".to_owned())
                })?;
            if !latest.valid || latest.sealed_changeset_digest != Some(sealed) {
                return Err(LocalPortError::Integrity(
                    "localized ChangeSet seal does not match validation head".to_owned(),
                ));
            }
        }
    }
    mark_effective_edits(&mut changeset.edits)?;
    verify_all_repair_edges(transaction, &changeset)?;
    Ok(changeset)
}

fn parse_localized_status(value: &str) -> Result<ChangeSetStatus, LocalPortError> {
    match value {
        "draft" => Ok(ChangeSetStatus::Draft),
        "ready" => Ok(ChangeSetStatus::Ready),
        "submitted" => Ok(ChangeSetStatus::Submitted),
        "approved" => Ok(ChangeSetStatus::Approved),
        "committed" => Ok(ChangeSetStatus::Committed),
        _ => Err(LocalPortError::Integrity(
            "localized ChangeSet status is invalid".to_owned(),
        )),
    }
}

fn parse_optional_digest(value: Option<&str>) -> Result<Option<ContentDigest>, LocalPortError> {
    value
        .map(|value| {
            value
                .parse::<ContentDigest>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .transpose()
}

#[allow(clippy::too_many_lines)]
fn load_edits(
    transaction: &Transaction<'_>,
    changeset_id: ChangeSetId,
) -> Result<Vec<proof_application::LocalizedEdit>, LocalPortError> {
    type EditRow = (
        i64,
        String,
        String,
        String,
        i64,
        String,
        String,
        i64,
        Option<i64>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
    );
    let mut statement = transaction
        .prepare(
            "SELECT ordinal, edit_id, object_id, locale, source_revision, source_digest,
                    schema_id, schema_version, expected_target_revision,
                    expected_target_digest, content_json, supersedes_edit_id,
                    repair_validation_digest, edit_json, edit_digest
             FROM localized_edits WHERE changeset_id = ?1 ORDER BY ordinal",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
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
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut edits = Vec::new();
    for (index, row) in rows.enumerate() {
        let row: EditRow = row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let ordinal = u32::try_from(row.0)
            .map_err(|_| LocalPortError::Integrity("invalid localized Edit ordinal".to_owned()))?;
        if ordinal != u32::try_from(index + 1).unwrap_or(u32::MAX) {
            return Err(LocalPortError::Integrity(
                "localized Edit ordinals are not contiguous".to_owned(),
            ));
        }
        let edit_id = row
            .1
            .parse::<proof_application::EditId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let object_id = row
            .2
            .parse::<ObjectId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let locale = proof_application::LocaleId::new(row.3)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let source_revision = proof_application::ObjectRevision::new(
            u32::try_from(row.4)
                .map_err(|_| LocalPortError::Integrity("invalid source revision".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let source_digest = row
            .5
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_id =
            SchemaId::new(row.6).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_version = proof_application::SchemaVersion::new(
            u32::try_from(row.7)
                .map_err(|_| LocalPortError::Integrity("invalid Schema version".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let expected_target = match (row.8, row.9) {
            (None, None) => None,
            (Some(revision), Some(raw_digest)) => {
                Some(proof_application::ExpectedLocalizedTarget {
                    revision: proof_application::LocaleRevision::new(
                        u32::try_from(revision).map_err(|_| {
                            LocalPortError::Integrity("invalid target revision".to_owned())
                        })?,
                    )
                    .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
                    digest: raw_digest
                        .parse::<ContentDigest>()
                        .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
                })
            }
            _ => {
                return Err(LocalPortError::Integrity(
                    "localized Edit target precondition is partial".to_owned(),
                ));
            }
        };
        strict_canonical(&row.10, "localized Edit content")?;
        let input = ObjectLocalePutInput {
            object_id,
            locale,
            expected_source: proof_application::ExpectedLocalizedSource {
                revision: source_revision,
                digest: source_digest,
                schema_id,
                schema_version,
            },
            expected_target,
            canonical_content: row.10,
            supersedes_edit_id: row
                .11
                .map(|value| value.parse::<proof_application::EditId>())
                .transpose()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            repair_of_validation_result_digest: parse_optional_digest(row.12.as_deref())?,
        };
        let manifest = edit_manifest(edit_id, &input)?;
        let edit_digest = row
            .14
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if manifest.as_str() != row.13
            || digest(proof_application::ArtifactKind::EditV2, &manifest) != edit_digest
        {
            return Err(LocalPortError::Integrity(
                "localized Edit artifact does not reproduce".to_owned(),
            ));
        }
        edits.push(proof_application::LocalizedEdit {
            ordinal,
            edit_id,
            input,
            effective: false,
            canonical_json: row.13,
            edit_digest,
        });
    }
    mark_effective_edits(&mut edits)?;
    Ok(edits)
}

fn edit_manifest(
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    let content =
        parse_strict(input.canonical_content.as_bytes()).map_err(|_| LocalPortError::Invalid)?;
    canonicalize(&json!({
        "api_version": proof_application::LOCALIZED_EDIT_API_VERSION,
        "content": content,
        "edit_id": edit_id.to_string(),
        "expected_source": {
            "digest": input.expected_source.digest.to_string(),
            "revision": input.expected_source.revision.get(),
            "schema_id": input.expected_source.schema_id.as_str(),
            "schema_version": input.expected_source.schema_version.get(),
        },
        "expected_target": input.expected_target.as_ref().map(|target| json!({
            "digest": target.digest.to_string(),
            "revision": target.revision.get(),
        })),
        "kind": "object.locale.put",
        "locale": input.locale.as_str(),
        "object_id": input.object_id.to_string(),
        "repair_of_validation_result_digest": input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
        "supersedes_edit_id": input.supersedes_edit_id.map(|value| value.to_string()),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn mark_effective_edits(
    edits: &mut [proof_application::LocalizedEdit],
) -> Result<(), LocalPortError> {
    let mut active =
        BTreeMap::<(ObjectId, proof_application::LocaleId), proof_application::EditId>::new();
    let mut seen_ids = BTreeSet::new();
    for edit in edits.iter() {
        if !seen_ids.insert(edit.edit_id) {
            return Err(LocalPortError::Integrity(
                "localized Edit identity is duplicated".to_owned(),
            ));
        }
        let target = (edit.input.object_id, edit.input.locale.clone());
        match active.get(&target).copied() {
            None => {
                if edit.input.supersedes_edit_id.is_some()
                    || edit.input.repair_of_validation_result_digest.is_some()
                {
                    return Err(LocalPortError::Integrity(
                        "first localized Edit has a supersession edge".to_owned(),
                    ));
                }
            }
            Some(active_edit_id) => {
                if edit.input.supersedes_edit_id != Some(active_edit_id)
                    || edit.input.repair_of_validation_result_digest.is_none()
                {
                    return Err(LocalPortError::Integrity(
                        "localized Edit lineage forks or skips its active leaf".to_owned(),
                    ));
                }
            }
        }
        active.insert(target, edit.edit_id);
    }
    for edit in edits {
        edit.effective = active
            .get(&(edit.input.object_id, edit.input.locale.clone()))
            .is_some_and(|edit_id| *edit_id == edit.edit_id);
    }
    Ok(())
}

fn proposal(
    changeset: &LocalizedChangeSet,
) -> Result<
    (
        ContentDigest,
        ContentDigest,
        Vec<proof_application::LocalizedEdit>,
    ),
    LocalPortError,
> {
    let mut effective = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .cloned()
        .collect::<Vec<_>>();
    effective.sort_by(|left, right| {
        (left.input.object_id, &left.input.locale)
            .cmp(&(right.input.object_id, &right.input.locale))
    });
    let effective_values = effective
        .iter()
        .map(|edit| {
            parse_strict(edit.canonical_json.as_bytes())
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let effective_manifest = canonicalize(&json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": effective_values,
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let effective_digest = digest(
        proof_application::ArtifactKind::EditBatchV2,
        &effective_manifest,
    );
    let all_values = changeset
        .edits
        .iter()
        .map(|edit| {
            parse_strict(edit.canonical_json.as_bytes())
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = canonicalize(&json!({
        "api_version": proof_application::LOCALIZED_CHANGESET_API_VERSION,
        "base_state": state_reference_value(&changeset.base_state),
        "changeset_id": changeset.changeset_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "created_at": changeset.created_at.to_string(),
        "edits": all_values,
        "effective_leaf_digest": effective_digest.to_string(),
        "effective_leaves": effective.iter().map(|edit| json!({
            "edit_digest": edit.edit_digest.to_string(),
            "edit_id": edit.edit_id.to_string(),
            "locale": edit.input.locale.as_str(),
            "object_id": edit.input.object_id.to_string(),
        })).collect::<Vec<_>>(),
        "intent": changeset.intent.as_str(),
        "principal_id": changeset.principal_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "workspace_id": changeset.workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok((
        digest(proof_application::ArtifactKind::ChangeSetV2, &manifest),
        effective_digest,
        effective,
    ))
}

fn changeset_diff(
    changeset: &LocalizedChangeSet,
) -> Result<LocalizedChangeSetDiff, LocalPortError> {
    let (proposal_digest, effective_leaf_digest, effective_edits) = proposal(changeset)?;
    Ok(LocalizedChangeSetDiff {
        changeset_id: changeset.changeset_id,
        proposal_digest,
        effective_leaf_digest,
        effective_edits,
    })
}

#[allow(clippy::too_many_lines)]
fn add_edits(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &AddLocalizedEditsCommand,
) -> Result<AddedLocalizedEdits, LocalPortError> {
    if command.edits.is_empty()
        || command.edits.len() != command.assigned_edit_ids.len()
        || command.edits.len() > usize::try_from(MAX_LOCALIZED_EDITS).unwrap_or(usize::MAX)
        || command
            .assigned_edit_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != command.assigned_edit_ids.len()
    {
        return Err(LocalPortError::Invalid);
    }
    let semantic_values = command
        .edits
        .iter()
        .map(semantic_edit_value)
        .collect::<Result<Vec<_>, _>>()?;
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": command.changeset_id.to_string(),
        "edits": semantic_values,
        "idempotency_key": command.idempotency_key.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((persisted_request, first_ordinal, added_count, total_count, effect_digest)) =
        transaction
            .query_row(
                "SELECT request_digest, first_ordinal, added_count, total_edit_count, effect_digest
                 FROM localized_add_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    workspace_id.to_string(),
                    principal_id.to_string(),
                    command.idempotency_key.to_string(),
                ),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        if persisted_request != request_digest.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        let first_ordinal = u32::try_from(first_ordinal)
            .map_err(|_| LocalPortError::Integrity("invalid replay ordinal".to_owned()))?;
        let added_count = u32::try_from(added_count)
            .map_err(|_| LocalPortError::Integrity("invalid replay count".to_owned()))?;
        let total_edit_count = u32::try_from(total_count)
            .map_err(|_| LocalPortError::Integrity("invalid replay total".to_owned()))?;
        let edit_ids = operation_edit_ids(
            transaction,
            command.changeset_id,
            first_ordinal,
            added_count,
        )?;
        let expected_effect = add_effect(
            request_digest,
            command.changeset_id,
            first_ordinal,
            total_edit_count,
            &edit_ids,
        )?;
        if effect_digest != expected_effect.to_string() {
            return Err(LocalPortError::Integrity(
                "localized Edit operation effect does not reproduce".to_owned(),
            ));
        }
        return Ok(AddedLocalizedEdits {
            changeset_id: command.changeset_id,
            edit_ids,
            first_ordinal,
            total_edit_count,
        });
    }
    let mut changeset = load_changeset(transaction, workspace_id, command.changeset_id)?;
    if changeset.principal_id != principal_id {
        return Err(LocalPortError::NotFound);
    }
    if changeset.status != ChangeSetStatus::Draft {
        return Err(LocalPortError::NotDraft);
    }
    let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
    let context = load_context(transaction, workspace_id, changeset.context_pack_id)?;
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let added_count =
        u32::try_from(command.edits.len()).map_err(|_| LocalPortError::LimitExceeded)?;
    let existing_count =
        u32::try_from(changeset.edits.len()).map_err(|_| LocalPortError::LimitExceeded)?;
    let total_edit_count = existing_count
        .checked_add(added_count)
        .ok_or(LocalPortError::LimitExceeded)?;
    if total_edit_count > context.limits.max_edits {
        return Err(LocalPortError::LimitExceeded);
    }
    let first_ordinal = existing_count
        .checked_add(1)
        .ok_or(LocalPortError::LimitExceeded)?;
    let batch_targets = command
        .edits
        .iter()
        .map(|edit| (edit.object_id, &edit.locale))
        .collect::<BTreeSet<_>>();
    if batch_targets.len() != command.edits.len() {
        return Err(LocalPortError::DuplicateActiveTarget);
    }
    let active = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .map(|edit| {
            (
                (edit.input.object_id, edit.input.locale.clone()),
                edit.edit_id,
            )
        })
        .collect::<BTreeMap<_, _>>();
    for (index, (input, edit_id)) in command
        .edits
        .iter()
        .zip(&command.assigned_edit_ids)
        .enumerate()
    {
        let candidate_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM localized_edits WHERE edit_id = ?1
                     UNION ALL SELECT 1 FROM changeset_edits WHERE edit_id = ?1
                 )",
                [edit_id.to_string()],
                |row| row.get(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        if candidate_exists {
            return Err(LocalPortError::Integrity(
                "Proof-assigned Edit identity already exists".to_owned(),
            ));
        }
        verify_edit_input(transaction, &intent, input)?;
        let target = (input.object_id, input.locale.clone());
        match active.get(&target).copied() {
            None => {
                if input.supersedes_edit_id.is_some()
                    || input.repair_of_validation_result_digest.is_some()
                {
                    return Err(LocalPortError::InvalidSupersession);
                }
            }
            Some(active_edit_id) => {
                if input.supersedes_edit_id.is_none() {
                    return Err(LocalPortError::DuplicateActiveTarget);
                }
                if input.supersedes_edit_id != Some(active_edit_id) {
                    return Err(LocalPortError::InvalidSupersession);
                }
                let Some(result_digest) = input.repair_of_validation_result_digest else {
                    return Err(LocalPortError::InvalidRepairEvidence);
                };
                verify_repair_evidence(
                    transaction,
                    command.changeset_id,
                    active_edit_id,
                    input.object_id,
                    &input.locale,
                    result_digest,
                    changeset.proposal_digest.ok_or_else(|| {
                        LocalPortError::Integrity(
                            "repair target ChangeSet has no current proposal digest".to_owned(),
                        )
                    })?,
                )?;
            }
        }
        let ordinal = first_ordinal
            .checked_add(u32::try_from(index).map_err(|_| LocalPortError::LimitExceeded)?)
            .ok_or(LocalPortError::LimitExceeded)?;
        persist_edit(transaction, command.changeset_id, ordinal, *edit_id, input)?;
        let manifest = edit_manifest(*edit_id, input)?;
        changeset.edits.push(proof_application::LocalizedEdit {
            ordinal,
            edit_id: *edit_id,
            input: input.clone(),
            effective: false,
            canonical_json: manifest.as_str().to_owned(),
            edit_digest: digest(proof_application::ArtifactKind::EditV2, &manifest),
        });
    }
    mark_effective_edits(&mut changeset.edits)?;
    let (proposal_digest, effective_digest, _) = proposal(&changeset)?;
    transaction
        .execute(
            "UPDATE localized_changesets
             SET proposal_digest = ?1, effective_leaf_digest = ?2,
                 sealed_changeset_digest = NULL
             WHERE changeset_id = ?3 AND lifecycle_status = 'draft'",
            (
                proposal_digest.to_string(),
                effective_digest.to_string(),
                command.changeset_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let edit_ids = command.assigned_edit_ids.clone();
    let effect_digest = add_effect(
        request_digest,
        command.changeset_id,
        first_ordinal,
        total_edit_count,
        &edit_ids,
    )?;
    transaction
        .execute(
            "INSERT INTO localized_add_operations (
                 workspace_id, principal_id, changeset_id, idempotency_key,
                 request_digest, effect_digest, first_ordinal, added_count, total_edit_count
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                workspace_id.to_string(),
                principal_id.to_string(),
                command.changeset_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                i64::from(first_ordinal),
                i64::from(added_count),
                i64::from(total_edit_count),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    Ok(AddedLocalizedEdits {
        changeset_id: command.changeset_id,
        edit_ids,
        first_ordinal,
        total_edit_count,
    })
}

fn semantic_edit_value(input: &ObjectLocalePutInput) -> Result<Value, LocalPortError> {
    let content =
        parse_strict(input.canonical_content.as_bytes()).map_err(|_| LocalPortError::Invalid)?;
    let canonical = canonicalize(&content).map_err(|_| LocalPortError::Invalid)?;
    if canonical.as_str() != input.canonical_content {
        return Err(LocalPortError::Invalid);
    }
    Ok(json!({
        "api_version": proof_application::LOCALIZED_EDIT_API_VERSION,
        "content": content,
        "expected_source": {
            "digest": input.expected_source.digest.to_string(),
            "revision": input.expected_source.revision.get(),
            "schema_id": input.expected_source.schema_id.as_str(),
            "schema_version": input.expected_source.schema_version.get(),
        },
        "expected_target": input.expected_target.as_ref().map(|target| json!({
            "digest": target.digest.to_string(),
            "revision": target.revision.get(),
        })),
        "kind": "object.locale.put",
        "locale": input.locale.as_str(),
        "object_id": input.object_id.to_string(),
        "repair_of_validation_result_digest": input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
        "supersedes_edit_id": input.supersedes_edit_id.map(|value| value.to_string()),
    }))
}

fn add_effect(
    request_digest: ContentDigest,
    changeset_id: ChangeSetId,
    first_ordinal: u32,
    total_edit_count: u32,
    edit_ids: &[proof_application::EditId],
) -> Result<ContentDigest, LocalPortError> {
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.add/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": changeset_id.to_string(),
            "edit_ids": edit_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "first_ordinal": first_ordinal,
            "total_edit_count": total_edit_count,
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

fn operation_edit_ids(
    transaction: &Transaction<'_>,
    changeset_id: ChangeSetId,
    first_ordinal: u32,
    added_count: u32,
) -> Result<Vec<proof_application::EditId>, LocalPortError> {
    let final_ordinal = first_ordinal
        .checked_add(added_count)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| LocalPortError::Integrity("invalid Edit operation range".to_owned()))?;
    let mut statement = transaction
        .prepare(
            "SELECT edit_id FROM localized_edits
             WHERE changeset_id = ?1 AND ordinal BETWEEN ?2 AND ?3 ORDER BY ordinal",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let values = statement
        .query_map(
            (
                changeset_id.to_string(),
                i64::from(first_ordinal),
                i64::from(final_ordinal),
            ),
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .map(|row| {
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?
                .parse::<proof_application::EditId>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() != usize::try_from(added_count).unwrap_or(usize::MAX) {
        return Err(LocalPortError::Integrity(
            "localized Edit operation range is incomplete".to_owned(),
        ));
    }
    Ok(values)
}

fn persist_edit(
    transaction: &Transaction<'_>,
    changeset_id: ChangeSetId,
    ordinal: u32,
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) -> Result<(), LocalPortError> {
    let manifest = edit_manifest(edit_id, input)?;
    let edit_digest = digest(proof_application::ArtifactKind::EditV2, &manifest);
    transaction
        .execute(
            "INSERT INTO localized_edits (
                 changeset_id, ordinal, edit_id, object_id, locale, source_revision,
                 source_digest, schema_id, schema_version, expected_target_revision,
                 expected_target_digest, content_json, supersedes_edit_id,
                 repair_validation_digest, edit_json, edit_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                changeset_id.to_string(),
                i64::from(ordinal),
                edit_id.to_string(),
                input.object_id.to_string(),
                input.locale.as_str(),
                i64::from(input.expected_source.revision.get()),
                input.expected_source.digest.to_string(),
                input.expected_source.schema_id.as_str(),
                i64::from(input.expected_source.schema_version.get()),
                input
                    .expected_target
                    .as_ref()
                    .map(|target| i64::from(target.revision.get())),
                input
                    .expected_target
                    .as_ref()
                    .map(|target| target.digest.to_string()),
                input.canonical_content.as_str(),
                input.supersedes_edit_id.map(|value| value.to_string()),
                input
                    .repair_of_validation_result_digest
                    .map(|value| value.to_string()),
                manifest.as_str(),
                edit_digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    Ok(())
}

fn verify_edit_input(
    transaction: &Transaction<'_>,
    intent: &ContentResourceIntent,
    input: &ObjectLocalePutInput,
) -> Result<(), LocalPortError> {
    let target = proof_application::LocalizedContentTarget {
        object_id: input.object_id,
        schema_id: input.expected_source.schema_id.clone(),
        locale: input.locale.clone(),
    };
    if intent.targets.binary_search(&target).is_err() {
        return Err(LocalPortError::IntentMismatch);
    }
    let source = load_source_object(transaction, input.object_id)?;
    if input.expected_source.revision != proof_application::ObjectRevision::INITIAL
        || input.expected_source.digest != source.object_digest
        || input.expected_source.schema_id != source.schema_id
        || input.expected_source.schema_version != source.schema_version
    {
        return Err(LocalPortError::SourceConflict);
    }
    let persisted_target = load_rendition_at(
        transaction,
        input.object_id,
        &input.locale,
        intent.base.known_state.authoritative_sequence,
    )?;
    match (&input.expected_target, persisted_target) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if expected.revision.get() == actual.revision && expected.digest == actual.digest => {}
        _ => return Err(LocalPortError::TargetConflict),
    }
    let schema = load_localizable_schema(transaction, &source.schema_id, source.schema_version)?;
    let source_value = parse_strict(source.canonical_content.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let target_value =
        parse_strict(input.canonical_content.as_bytes()).map_err(|_| LocalPortError::Invalid)?;
    let target_canonical = canonicalize(&target_value).map_err(|_| LocalPortError::Invalid)?;
    if target_canonical.as_str() != input.canonical_content || !target_value.is_object() {
        return Err(LocalPortError::Invalid);
    }
    let schema_value = parse_strict(schema.canonical_document.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let validator = jsonschema::draft202012::new(&schema_value)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if validator.iter_errors(&target_value).next().is_some() {
        return Err(LocalPortError::Invalid);
    }
    let mut reconstructed = source_value.clone();
    for pointer in &schema.localizable_pointers {
        let segments = parse_pointer(pointer)?;
        let source_string = string_at_pointer(&source_value, &segments)?;
        let target_string = string_at_pointer(&target_value, &segments)?;
        if source_string.is_empty() && target_string.is_empty() {
            // Empty strings are valid; this branch deliberately proves both reads.
        }
        set_string_at_pointer(&mut reconstructed, &segments, target_string.to_owned())?;
    }
    let reconstructed = canonicalize(&reconstructed).map_err(|_| LocalPortError::Invalid)?;
    if reconstructed.as_str() != input.canonical_content {
        return Err(LocalPortError::Invalid);
    }
    Ok(())
}

fn string_at_pointer<'a>(value: &'a Value, segments: &[String]) -> Result<&'a str, LocalPortError> {
    let mut current = value;
    for segment in segments {
        current = current
            .as_object()
            .and_then(|object| object.get(segment))
            .ok_or(LocalPortError::Invalid)?;
    }
    current.as_str().ok_or(LocalPortError::Invalid)
}

fn set_string_at_pointer(
    value: &mut Value,
    segments: &[String],
    replacement: String,
) -> Result<(), LocalPortError> {
    let Some((last, parents)) = segments.split_last() else {
        return Err(LocalPortError::Invalid);
    };
    let mut current = value;
    for segment in parents {
        current = current
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .ok_or(LocalPortError::Invalid)?;
    }
    let slot = current
        .as_object_mut()
        .and_then(|object| object.get_mut(last))
        .ok_or(LocalPortError::Invalid)?;
    if !slot.is_string() {
        return Err(LocalPortError::Invalid);
    }
    *slot = Value::String(replacement);
    Ok(())
}

fn verify_repair_evidence(
    transaction: &Transaction<'_>,
    changeset_id: ChangeSetId,
    superseded_edit_id: proof_application::EditId,
    object_id: ObjectId,
    locale: &proof_application::LocaleId,
    expected_result_digest: ContentDigest,
    expected_proposal_digest: ContentDigest,
) -> Result<(), LocalPortError> {
    let row: Option<(i64, i64, String, String, String, String)> = transaction
        .query_row(
            "SELECT attempt, valid, findings_json, results_json, results_digest,
                    proposal_digest
             FROM localized_validations
             WHERE changeset_id = ?1 AND results_digest = ?2",
            (changeset_id.to_string(), expected_result_digest.to_string()),
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
    let Some((attempt, valid, findings_json, results_json, raw_digest, raw_proposal)) = row else {
        return Err(LocalPortError::InvalidRepairEvidence);
    };
    let result_digest = raw_digest
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let result = strict_canonical(&results_json, "localized validation result")?;
    if valid != 0
        || result_digest != expected_result_digest
        || raw_proposal != expected_proposal_digest.to_string()
        || digest(
            proof_application::ArtifactKind::ValidationResultsV2,
            &result,
        ) != result_digest
    {
        return Err(LocalPortError::InvalidRepairEvidence);
    }
    let latest_attempt: i64 = transaction
        .query_row(
            "SELECT MAX(attempt) FROM localized_validations
             WHERE changeset_id = ?1 AND proposal_digest = ?2",
            (
                changeset_id.to_string(),
                expected_proposal_digest.to_string(),
            ),
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if latest_attempt != attempt {
        return Err(LocalPortError::InvalidRepairEvidence);
    }
    let findings = parse_strict(findings_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let findings = findings.as_array().ok_or_else(|| {
        LocalPortError::Integrity("localized findings are not an array".to_owned())
    })?;
    let superseded_edit_id = superseded_edit_id.to_string();
    let object_id = object_id.to_string();
    let matches = findings.iter().any(|finding| {
        let Some(finding) = finding.as_object() else {
            return false;
        };
        finding.get("edit_id").and_then(Value::as_str) == Some(superseded_edit_id.as_str())
            && finding.get("object_id").and_then(Value::as_str) == Some(object_id.as_str())
            && finding.get("locale").and_then(Value::as_str) == Some(locale.as_str())
            && finding.get("severity").and_then(Value::as_str) == Some("error")
    });
    if !matches {
        return Err(LocalPortError::InvalidRepairEvidence);
    }
    Ok(())
}

fn verify_all_repair_edges(
    transaction: &Transaction<'_>,
    changeset: &LocalizedChangeSet,
) -> Result<(), LocalPortError> {
    for (index, edit) in changeset.edits.iter().enumerate() {
        let (Some(superseded), Some(result_digest)) = (
            edit.input.supersedes_edit_id,
            edit.input.repair_of_validation_result_digest,
        ) else {
            continue;
        };
        let mut prefix = changeset.clone();
        prefix.edits.truncate(index);
        prefix.proposal_digest = None;
        prefix.sealed_changeset_digest = None;
        mark_effective_edits(&mut prefix.edits)?;
        let (proposal_digest, _, _) = proposal(&prefix)?;
        verify_repair_evidence(
            transaction,
            changeset.changeset_id,
            superseded,
            edit.input.object_id,
            &edit.input.locale,
            result_digest,
            proposal_digest,
        )?;
    }
    Ok(())
}

fn submit_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    changeset_id: ChangeSetId,
    submitted_at: Timestamp,
) -> Result<SubmittedLocalizedChangeSet, LocalPortError> {
    let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
    if changeset.principal_id != principal_id {
        return Err(LocalPortError::NotFound);
    }
    if let Some(existing) = load_localized_submission(transaction, &changeset)? {
        if existing.submitted_at != submitted_at {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(existing);
    }
    if changeset.status != ChangeSetStatus::Ready {
        return Err(LocalPortError::NotReady);
    }
    if submitted_at < changeset.created_at {
        return Err(LocalPortError::Invalid);
    }
    let validation = sealed_validation_head(transaction, &changeset)?;
    let sealed = validation.sealed_changeset_digest.ok_or_else(|| {
        LocalPortError::Integrity("valid localized validation lacks a seal".to_owned())
    })?;
    let effect = localized_lifecycle_effect(
        "changeset.submit/v2",
        changeset_id,
        sealed,
        validation.validation_results_digest,
        Some(submitted_at),
        None,
        principal_id,
    )?;
    transaction
        .execute(
            "INSERT INTO localized_submissions (
                 changeset_id, sealed_changeset_digest, validation_results_digest,
                 principal_id, submitted_at, effect_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                changeset_id.to_string(),
                sealed.to_string(),
                validation.validation_results_digest.to_string(),
                principal_id.to_string(),
                submitted_at.to_string(),
                effect.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let changed = transaction
        .execute(
            "UPDATE localized_changesets SET lifecycle_status = 'submitted'
             WHERE changeset_id = ?1 AND lifecycle_status = 'ready'",
            [changeset_id.to_string()],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(LocalPortError::StateConflict);
    }
    Ok(SubmittedLocalizedChangeSet {
        changeset_id,
        sealed_changeset_digest: sealed,
        validation_results_digest: validation.validation_results_digest,
        submitted_at,
        status: ChangeSetStatus::Submitted,
    })
}

fn approve_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    changeset_id: ChangeSetId,
    approval: ApprovalName,
    approved_at: Timestamp,
) -> Result<ApprovedLocalizedChangeSet, LocalPortError> {
    let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
    if let Some(existing) = load_localized_approval(transaction, &changeset)? {
        if existing.approval != approval || existing.approved_at != approved_at {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(existing);
    }
    if changeset.status != ChangeSetStatus::Submitted {
        return Err(LocalPortError::NotSubmitted);
    }
    let submission = load_localized_submission(transaction, &changeset)?.ok_or_else(|| {
        LocalPortError::Integrity(
            "submitted localized ChangeSet lacks submission evidence".to_owned(),
        )
    })?;
    if approved_at < submission.submitted_at {
        return Err(LocalPortError::Invalid);
    }
    let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let environment = load_localized_environment(transaction, workspace_id, intent.environment_id)?;
    if environment.required_approval != approval {
        return Err(LocalPortError::PolicyDenied);
    }
    let effect = localized_lifecycle_effect(
        "changeset.approve/v2",
        changeset_id,
        submission.sealed_changeset_digest,
        submission.validation_results_digest,
        Some(approved_at),
        Some(approval.as_str()),
        principal_id,
    )?;
    transaction
        .execute(
            "INSERT INTO localized_approvals (
                 changeset_id, approval_name, sealed_changeset_digest,
                 validation_results_digest, principal_id, approved_at, effect_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                changeset_id.to_string(),
                approval.as_str(),
                submission.sealed_changeset_digest.to_string(),
                submission.validation_results_digest.to_string(),
                principal_id.to_string(),
                approved_at.to_string(),
                effect.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let changed = transaction
        .execute(
            "UPDATE localized_changesets SET lifecycle_status = 'approved'
             WHERE changeset_id = ?1 AND lifecycle_status = 'submitted'",
            [changeset_id.to_string()],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(LocalPortError::StateConflict);
    }
    Ok(ApprovedLocalizedChangeSet {
        changeset_id,
        approval,
        sealed_changeset_digest: submission.sealed_changeset_digest,
        validation_results_digest: submission.validation_results_digest,
        approved_at,
        status: ChangeSetStatus::Approved,
    })
}

fn localized_lifecycle_effect(
    operation_kind: &str,
    changeset_id: ChangeSetId,
    sealed_changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
    occurred_at: Option<Timestamp>,
    approval: Option<&str>,
    principal_id: proof_application::PrincipalId,
) -> Result<ContentDigest, LocalPortError> {
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": operation_kind,
        "result": {
            "approval": approval,
            "changeset_id": changeset_id.to_string(),
            "occurred_at": occurred_at.map(|value| value.to_string()),
            "principal_id": principal_id.to_string(),
            "sealed_changeset_digest": sealed_changeset_digest.to_string(),
            "validation_results_digest": validation_results_digest.to_string(),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

fn sealed_validation_head(
    transaction: &Transaction<'_>,
    changeset: &LocalizedChangeSet,
) -> Result<proof_application::LocalizedValidation, LocalPortError> {
    let validation = load_validation_chain(transaction, changeset)?
        .last()
        .cloned()
        .ok_or_else(|| {
            LocalPortError::Integrity("localized ChangeSet has no validation evidence".to_owned())
        })?;
    if !validation.valid
        || validation.sealed_changeset_digest != changeset.sealed_changeset_digest
        || validation.proposal_digest
            != changeset.proposal_digest.ok_or_else(|| {
                LocalPortError::Integrity(
                    "sealed localized ChangeSet lacks proposal digest".to_owned(),
                )
            })?
    {
        return Err(LocalPortError::Integrity(
            "localized ChangeSet seal is not the valid validation head".to_owned(),
        ));
    }
    Ok(validation)
}

fn load_localized_submission(
    transaction: &Transaction<'_>,
    changeset: &LocalizedChangeSet,
) -> Result<Option<SubmittedLocalizedChangeSet>, LocalPortError> {
    type SubmissionRow = (String, String, String, String, String);
    let row: Option<SubmissionRow> = transaction
        .query_row(
            "SELECT sealed_changeset_digest, validation_results_digest,
                    principal_id, submitted_at, effect_digest
             FROM localized_submissions WHERE changeset_id = ?1",
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((raw_sealed, raw_validation, raw_principal, raw_at, raw_effect)) = row else {
        return Ok(None);
    };
    let sealed = raw_sealed
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let validation = raw_validation
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let principal_id = raw_principal
        .parse::<proof_application::PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let submitted_at = raw_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let effect = localized_lifecycle_effect(
        "changeset.submit/v2",
        changeset.changeset_id,
        sealed,
        validation,
        Some(submitted_at),
        None,
        principal_id,
    )?;
    if raw_principal != principal_id.to_string()
        || raw_at != submitted_at.to_string()
        || raw_effect != effect.to_string()
        || changeset.sealed_changeset_digest != Some(sealed)
        || sealed_validation_head(transaction, changeset)?.validation_results_digest != validation
    {
        return Err(LocalPortError::Integrity(
            "localized submission evidence does not reproduce".to_owned(),
        ));
    }
    Ok(Some(SubmittedLocalizedChangeSet {
        changeset_id: changeset.changeset_id,
        sealed_changeset_digest: sealed,
        validation_results_digest: validation,
        submitted_at,
        status: ChangeSetStatus::Submitted,
    }))
}

fn load_localized_approval(
    transaction: &Transaction<'_>,
    changeset: &LocalizedChangeSet,
) -> Result<Option<ApprovedLocalizedChangeSet>, LocalPortError> {
    type ApprovalRow = (String, String, String, String, String, String);
    let row: Option<ApprovalRow> = transaction
        .query_row(
            "SELECT approval_name, sealed_changeset_digest, validation_results_digest,
                    principal_id, approved_at, effect_digest
             FROM localized_approvals WHERE changeset_id = ?1",
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((raw_approval, raw_sealed, raw_validation, raw_principal, raw_at, raw_effect)) = row
    else {
        return Ok(None);
    };
    let approval = ApprovalName::new(raw_approval.clone())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let sealed = raw_sealed
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let validation = raw_validation
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let principal_id = raw_principal
        .parse::<proof_application::PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let approved_at = raw_at
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let effect = localized_lifecycle_effect(
        "changeset.approve/v2",
        changeset.changeset_id,
        sealed,
        validation,
        Some(approved_at),
        Some(approval.as_str()),
        principal_id,
    )?;
    let submission = load_localized_submission(transaction, changeset)?.ok_or_else(|| {
        LocalPortError::Integrity("localized approval lacks submission".to_owned())
    })?;
    if raw_approval != approval.as_str()
        || raw_principal != principal_id.to_string()
        || raw_at != approved_at.to_string()
        || raw_effect != effect.to_string()
        || submission.sealed_changeset_digest != sealed
        || submission.validation_results_digest != validation
        || approved_at < submission.submitted_at
    {
        return Err(LocalPortError::Integrity(
            "localized approval evidence does not reproduce".to_owned(),
        ));
    }
    Ok(Some(ApprovedLocalizedChangeSet {
        changeset_id: changeset.changeset_id,
        approval,
        sealed_changeset_digest: sealed,
        validation_results_digest: validation,
        approved_at,
        status: ChangeSetStatus::Approved,
    }))
}

#[allow(clippy::too_many_lines)]
fn commit_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &CommitLocalizedChangeSetCommand,
) -> Result<CommittedLocalizedChangeSet, LocalPortError> {
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": command.changeset_id.to_string(),
        "committed_at": command.committed_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((raw_request, raw_changeset)) = transaction
        .query_row(
            "SELECT effect_digest, changeset_id FROM localized_commits
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        let persisted_id = raw_changeset
            .parse::<ChangeSetId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let result = load_localized_commit(transaction, workspace_id, persisted_id)?;
        let expected_effect = localized_commit_effect(request_digest, &result)?;
        if persisted_id != command.changeset_id || raw_request != expected_effect.to_string() {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(result);
    }
    let changeset = load_changeset(transaction, workspace_id, command.changeset_id)?;
    if changeset.principal_id != principal_id {
        return Err(LocalPortError::NotFound);
    }
    if changeset.status != ChangeSetStatus::Approved {
        return Err(LocalPortError::NotApproved);
    }
    let validation = sealed_validation_head(transaction, &changeset)?;
    let approval =
        load_localized_approval(transaction, &changeset)?.ok_or(LocalPortError::EvidenceMissing)?;
    if command.committed_at < approval.approved_at {
        return Err(LocalPortError::Invalid);
    }
    let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let previous_state = current_state_reference(transaction, workspace_id)?;
    if previous_state != changeset.base_state {
        return Err(LocalPortError::StateConflict);
    }
    ensure_known_state_artifact(transaction, &previous_state)?;
    let (_, _, effective_edits) = proposal(&changeset)?;
    if effective_edits.is_empty() {
        return Err(LocalPortError::Invalid);
    }
    let mut renditions = Vec::with_capacity(effective_edits.len());
    let mut next_sequence = previous_state.authoritative_sequence;
    for edit in &effective_edits {
        verify_edit_input(transaction, &intent, &edit.input)?;
        next_sequence = next_sequence.checked_add(1).ok_or_else(|| {
            LocalPortError::Integrity("authoritative sequence overflow".to_owned())
        })?;
        let previous = load_rendition_at(
            transaction,
            edit.input.object_id,
            &edit.input.locale,
            previous_state.authoritative_sequence,
        )?;
        let revision = proof_application::LocaleRevision::new(
            previous
                .as_ref()
                .map_or(1, |value| value.revision.saturating_add(1)),
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let previous_revision_digest = previous.as_ref().map(|value| value.digest);
        let content = parse_strict(edit.input.canonical_content.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let (manifest, rendition_digest) =
            proof_canonical::object_locale_revision(&proof_canonical::ObjectLocaleRevisionInput {
                workspace_id,
                object_id: edit.input.object_id,
                locale: &edit.input.locale,
                revision,
                previous_revision_digest,
                source_object_revision: edit.input.expected_source.revision,
                source_object_digest: edit.input.expected_source.digest,
                schema_id: &edit.input.expected_source.schema_id,
                schema_version: edit.input.expected_source.schema_version,
                content: &content,
                changeset_id: changeset.changeset_id,
                edit_id: edit.edit_id,
                authoritative_sequence: next_sequence,
            })
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        transaction
            .execute(
                "INSERT INTO object_locale_revisions (
                     workspace_id, object_id, locale, revision, previous_revision_digest,
                     source_object_revision, source_object_digest, schema_id, schema_version,
                     content_json, changeset_id, edit_id, authoritative_sequence,
                     manifest_json, rendition_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    workspace_id.to_string(),
                    edit.input.object_id.to_string(),
                    edit.input.locale.as_str(),
                    i64::from(revision.get()),
                    previous_revision_digest.map(|value| value.to_string()),
                    i64::from(edit.input.expected_source.revision.get()),
                    edit.input.expected_source.digest.to_string(),
                    edit.input.expected_source.schema_id.as_str(),
                    i64::from(edit.input.expected_source.schema_version.get()),
                    edit.input.canonical_content.as_str(),
                    changeset.changeset_id.to_string(),
                    edit.edit_id.to_string(),
                    i64::try_from(next_sequence).map_err(|_| {
                        LocalPortError::Integrity(
                            "authoritative sequence exceeds SQLite range".to_owned(),
                        )
                    })?,
                    manifest.as_str(),
                    rendition_digest.to_string(),
                ],
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        renditions.push(ObjectLocaleRevision {
            workspace_id,
            object_id: edit.input.object_id,
            locale: edit.input.locale.clone(),
            revision,
            previous_revision_digest,
            source_object_revision: edit.input.expected_source.revision,
            source_object_digest: edit.input.expected_source.digest,
            schema_id: edit.input.expected_source.schema_id.clone(),
            schema_version: edit.input.expected_source.schema_version,
            canonical_content: edit.input.canonical_content.clone(),
            changeset_id: changeset.changeset_id,
            edit_id: edit.edit_id,
            authoritative_sequence: next_sequence,
            manifest_json: manifest.as_str().to_owned(),
            rendition_digest,
        });
    }
    let schemas = schema_state_references(transaction, next_sequence)?;
    let objects = object_state_references(transaction, next_sequence)?;
    let locale_references = locale_state_references(transaction, next_sequence)?;
    let previous_reference = proof_canonical::PreviousKnownStateReference {
        api_version: previous_state.api_version.clone(),
        authoritative_sequence: previous_state.authoritative_sequence,
        digest: previous_state.digest,
    };
    let state_manifest = proof_canonical::known_state_v2_manifest(
        workspace_id,
        next_sequence,
        &schemas,
        &objects,
        &locale_references,
        &previous_reference,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let state_digest = digest(
        proof_application::ArtifactKind::KnownStateV2,
        &state_manifest,
    );
    let resulting_state = KnownStateArtifactReference {
        api_version: KNOWN_STATE_V2_API_VERSION.to_owned(),
        authoritative_sequence: next_sequence,
        digest: state_digest,
    };
    let result = CommittedLocalizedChangeSet {
        changeset_id: changeset.changeset_id,
        sealed_changeset_digest: validation.sealed_changeset_digest.ok_or_else(|| {
            LocalPortError::Integrity("valid localized validation lacks seal".to_owned())
        })?,
        validation_results_digest: validation.validation_results_digest,
        previous_state: previous_state.clone(),
        resulting_state: resulting_state.clone(),
        renditions,
        committed_at: command.committed_at,
        status: ChangeSetStatus::Committed,
    };
    let effect_digest = localized_commit_effect(request_digest, &result)?;
    transaction
        .execute(
            "INSERT INTO known_state_artifacts (
                 api_version, authoritative_sequence, state_digest, manifest_json, changeset_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                KNOWN_STATE_V2_API_VERSION,
                i64::try_from(next_sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                state_digest.to_string(),
                state_manifest.as_str(),
                changeset.changeset_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_commits (
                 changeset_id, workspace_id, principal_id, idempotency_key,
                 sealed_changeset_digest, validation_results_digest,
                 previous_state_api_version, previous_authoritative_sequence,
                 previous_state_digest, resulting_authoritative_sequence,
                 resulting_state_digest, resulting_state_json, committed_at, effect_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                changeset.changeset_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
                result.sealed_changeset_digest.to_string(),
                result.validation_results_digest.to_string(),
                previous_state.api_version,
                i64::try_from(previous_state.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "previous state sequence exceeds SQLite range".to_owned(),
                    )
                })?,
                previous_state.digest.to_string(),
                i64::try_from(next_sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                state_digest.to_string(),
                state_manifest.as_str(),
                command.committed_at.to_string(),
                effect_digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let changed = transaction
        .execute(
            "UPDATE known_state
             SET api_version = ?1, authoritative_sequence = ?2,
                 state_digest = ?3, manifest_json = ?4
             WHERE singleton = 1 AND api_version = ?5
                   AND authoritative_sequence = ?6 AND state_digest = ?7",
            params![
                KNOWN_STATE_V2_API_VERSION,
                i64::try_from(next_sequence).map_err(|_| {
                    LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                })?,
                state_digest.to_string(),
                state_manifest.as_str(),
                previous_state.api_version,
                i64::try_from(previous_state.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "previous state sequence exceeds SQLite range".to_owned(),
                    )
                })?,
                previous_state.digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(LocalPortError::StateConflict);
    }
    transaction
        .execute(
            "UPDATE localized_changesets SET lifecycle_status = 'committed'
             WHERE changeset_id = ?1 AND lifecycle_status = 'approved'",
            [changeset.changeset_id.to_string()],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    Ok(result)
}

fn localized_commit_effect(
    request_digest: ContentDigest,
    result: &CommittedLocalizedChangeSet,
) -> Result<ContentDigest, LocalPortError> {
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.commit/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": result.changeset_id.to_string(),
            "committed_at": result.committed_at.to_string(),
            "previous_state": state_reference_value(&result.previous_state),
            "renditions": result.renditions.iter().map(|rendition| json!({
                "digest": rendition.rendition_digest.to_string(),
                "edit_id": rendition.edit_id.to_string(),
                "locale": rendition.locale.as_str(),
                "object_id": rendition.object_id.to_string(),
                "revision": rendition.revision.get(),
            })).collect::<Vec<_>>(),
            "resulting_state": state_reference_value(&result.resulting_state),
            "sealed_changeset_digest": result.sealed_changeset_digest.to_string(),
            "validation_results_digest": result.validation_results_digest.to_string(),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

fn ensure_known_state_artifact(
    transaction: &Transaction<'_>,
    state: &KnownStateArtifactReference,
) -> Result<(), LocalPortError> {
    if state.api_version == KNOWN_STATE_V1_API_VERSION {
        transaction
            .execute(
                "INSERT OR IGNORE INTO known_state_artifacts (
                     api_version, authoritative_sequence, state_digest, manifest_json, changeset_id
                 ) VALUES (?1, ?2, ?3, NULL, NULL)",
                (
                    state.api_version.as_str(),
                    i64::try_from(state.authoritative_sequence).map_err(|_| {
                        LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
                    })?,
                    state.digest.to_string(),
                ),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    let persisted: Option<(i64, Option<String>, Option<String>)> = transaction
        .query_row(
            "SELECT authoritative_sequence, manifest_json, changeset_id
             FROM known_state_artifacts WHERE api_version = ?1 AND state_digest = ?2",
            (state.api_version.as_str(), state.digest.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let Some((sequence, manifest, changeset_id)) = persisted else {
        return Err(LocalPortError::Integrity(
            "Known State artifact is missing".to_owned(),
        ));
    };
    if u64::try_from(sequence).ok() != Some(state.authoritative_sequence)
        || (state.api_version == KNOWN_STATE_V1_API_VERSION
            && (manifest.is_some() || changeset_id.is_some()))
    {
        return Err(LocalPortError::Integrity(
            "Known State artifact identity differs".to_owned(),
        ));
    }
    Ok(())
}

fn schema_state_references(
    transaction: &Connection,
    sequence: u64,
) -> Result<Vec<(SchemaId, proof_application::SchemaVersion, ContentDigest)>, LocalPortError> {
    let mut statement = transaction
        .prepare(
            "SELECT schema_id, schema_version, document_json, document_digest
             FROM schema_versions WHERE authoritative_sequence <= ?1
             ORDER BY schema_id, schema_version",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
            })?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut schemas = Vec::new();
    for row in rows {
        let (raw_id, raw_version, document, raw_digest) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let schema_id = SchemaId::new(raw_id.clone())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_version = proof_application::SchemaVersion::new(
            u32::try_from(raw_version)
                .map_err(|_| LocalPortError::Integrity("invalid Schema version".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let document_digest = raw_digest
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let canonical = strict_canonical(&document, "Schema")?;
        if raw_id != schema_id.as_str()
            || digest(proof_application::ArtifactKind::SchemaVersionV1, &canonical)
                != document_digest
        {
            return Err(LocalPortError::Integrity(
                "Schema state reference does not reproduce".to_owned(),
            ));
        }
        schemas.push((schema_id, schema_version, document_digest));
    }
    Ok(schemas)
}

fn object_state_references(
    transaction: &Connection,
    sequence: u64,
) -> Result<Vec<proof_canonical::ObjectStateReference>, LocalPortError> {
    type ObjectRow = (String, i64, String, i64, String, String, String);
    let mut statement = transaction
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version,
                    lifecycle_state, content_json, object_digest
             FROM object_revisions WHERE authoritative_sequence <= ?1
             ORDER BY object_id, revision",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
            })?],
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut objects = Vec::new();
    for row in rows {
        let row: ObjectRow = row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let object_id = row
            .0
            .parse::<ObjectId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let revision = proof_application::ObjectRevision::new(
            u32::try_from(row.1)
                .map_err(|_| LocalPortError::Integrity("invalid Object revision".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_id =
            SchemaId::new(row.2).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let schema_version = proof_application::SchemaVersion::new(
            u32::try_from(row.3)
                .map_err(|_| LocalPortError::Integrity("invalid Schema version".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if row.4 != "active" || revision != proof_application::ObjectRevision::INITIAL {
            return Err(LocalPortError::Integrity(
                "Object state reference uses an unsupported lifecycle or revision".to_owned(),
            ));
        }
        let object_digest = row
            .6
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let canonical = strict_canonical(&row.5, "source Object")?;
        let content = parse_strict(canonical.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if object_revision_digest(object_id, &schema_id, schema_version, &content)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?
            != object_digest
        {
            return Err(LocalPortError::Integrity(
                "Object state reference digest does not reproduce".to_owned(),
            ));
        }
        objects.push(proof_canonical::ObjectStateReference {
            object_id,
            revision,
            schema_id,
            schema_version,
            lifecycle_state: proof_application::ObjectLifecycleState::Active,
            object_digest,
        });
    }
    Ok(objects)
}

fn locale_state_references(
    transaction: &Connection,
    sequence: u64,
) -> Result<Vec<proof_canonical::LocaleStateReference>, LocalPortError> {
    let mut statement = transaction
        .prepare(
            "SELECT object_id, locale, revision FROM object_locale_revisions
             WHERE authoritative_sequence <= ?1 ORDER BY object_id, locale, revision",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence).map_err(|_| {
                LocalPortError::Integrity("state sequence exceeds SQLite range".to_owned())
            })?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut heads = BTreeMap::new();
    for row in rows {
        let (raw_object_id, raw_locale, raw_revision) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let object_id = raw_object_id
            .parse::<ObjectId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let locale = proof_application::LocaleId::new(raw_locale)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let revision = proof_application::LocaleRevision::new(
            u32::try_from(raw_revision)
                .map_err(|_| LocalPortError::Integrity("invalid locale revision".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let rendition = load_object_locale_revision(transaction, object_id, &locale, revision)?;
        heads.insert(
            (object_id, locale.clone()),
            proof_canonical::LocaleStateReference {
                object_id,
                locale,
                revision,
                rendition_digest: rendition.rendition_digest,
                source_object_digest: rendition.source_object_digest,
                schema_id: rendition.schema_id,
                schema_version: rendition.schema_version,
            },
        );
    }
    Ok(heads.into_values().collect())
}

#[allow(clippy::too_many_lines)]
fn load_object_locale_revision(
    transaction: &Connection,
    object_id: ObjectId,
    locale: &proof_application::LocaleId,
    revision: proof_application::LocaleRevision,
) -> Result<ObjectLocaleRevision, LocalPortError> {
    type RenditionRow = (
        String,
        Option<String>,
        i64,
        String,
        String,
        i64,
        String,
        String,
        String,
        i64,
        String,
        String,
    );
    let row: RenditionRow = transaction
        .query_row(
            "SELECT workspace_id, previous_revision_digest, source_object_revision,
                    source_object_digest, schema_id, schema_version, content_json,
                    changeset_id, edit_id, authoritative_sequence, manifest_json,
                    rendition_digest
             FROM object_locale_revisions
             WHERE object_id = ?1 AND locale = ?2 AND revision = ?3",
            (
                object_id.to_string(),
                locale.as_str(),
                i64::from(revision.get()),
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    let workspace_id = row
        .0
        .parse::<proof_application::WorkspaceId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let previous_revision_digest = parse_optional_digest(row.1.as_deref())?;
    let source_object_revision = proof_application::ObjectRevision::new(
        u32::try_from(row.2)
            .map_err(|_| LocalPortError::Integrity("invalid source Object revision".to_owned()))?,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let source_object_digest = row
        .3
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let schema_id =
        SchemaId::new(row.4).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let schema_version =
        proof_application::SchemaVersion::new(u32::try_from(row.5).map_err(|_| {
            LocalPortError::Integrity("invalid rendition Schema version".to_owned())
        })?)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let changeset_id = row
        .7
        .parse::<ChangeSetId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let edit_id = row
        .8
        .parse::<proof_application::EditId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let authoritative_sequence = u64::try_from(row.9)
        .map_err(|_| LocalPortError::Integrity("invalid rendition sequence".to_owned()))?;
    let rendition_digest = row
        .11
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let content = parse_strict(row.6.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical_content =
        canonicalize(&content).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical_content.as_str() != row.6 {
        return Err(LocalPortError::Integrity(
            "rendition content is not canonical".to_owned(),
        ));
    }
    let (manifest, expected_digest) =
        proof_canonical::object_locale_revision(&proof_canonical::ObjectLocaleRevisionInput {
            workspace_id,
            object_id,
            locale,
            revision,
            previous_revision_digest,
            source_object_revision,
            source_object_digest,
            schema_id: &schema_id,
            schema_version,
            content: &content,
            changeset_id,
            edit_id,
            authoritative_sequence,
        })
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if manifest.as_str() != row.10 || expected_digest != rendition_digest {
        return Err(LocalPortError::Integrity(
            "locale rendition artifact does not reproduce".to_owned(),
        ));
    }
    let expected_previous = if revision == proof_application::LocaleRevision::INITIAL {
        None
    } else {
        let prior_revision = proof_application::LocaleRevision::new(revision.get() - 1)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        Some(
            load_object_locale_revision(transaction, object_id, locale, prior_revision)?
                .rendition_digest,
        )
    };
    if previous_revision_digest != expected_previous {
        return Err(LocalPortError::Integrity(
            "locale rendition predecessor chain is broken".to_owned(),
        ));
    }
    let source = load_source_object(transaction, object_id)?;
    if source_object_revision != proof_application::ObjectRevision::INITIAL
        || source_object_digest != source.object_digest
        || schema_id != source.schema_id
        || schema_version != source.schema_version
    {
        return Err(LocalPortError::Integrity(
            "locale rendition source reference does not reproduce".to_owned(),
        ));
    }
    Ok(ObjectLocaleRevision {
        workspace_id,
        object_id,
        locale: locale.clone(),
        revision,
        previous_revision_digest,
        source_object_revision,
        source_object_digest,
        schema_id,
        schema_version,
        canonical_content: row.6,
        changeset_id,
        edit_id,
        authoritative_sequence,
        manifest_json: row.10,
        rendition_digest,
    })
}

#[allow(clippy::too_many_lines)]
fn load_localized_commit(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    changeset_id: ChangeSetId,
) -> Result<CommittedLocalizedChangeSet, LocalPortError> {
    type CommitRow = (
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        i64,
        String,
        String,
        String,
        String,
    );
    let row: CommitRow = transaction
        .query_row(
            "SELECT principal_id, idempotency_key, sealed_changeset_digest,
                    validation_results_digest, previous_state_api_version,
                    previous_authoritative_sequence, previous_state_digest,
                    resulting_authoritative_sequence, resulting_state_digest,
                    resulting_state_json, committed_at, effect_digest
             FROM localized_commits WHERE changeset_id = ?1 AND workspace_id = ?2",
            (changeset_id.to_string(), workspace_id.to_string()),
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    let principal_id = row
        .0
        .parse::<proof_application::PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let idempotency_key = row
        .1
        .parse::<proof_application::IdempotencyKey>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let sealed_changeset_digest = row
        .2
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let validation_results_digest = row
        .3
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let previous_state = KnownStateArtifactReference {
        api_version: row.4,
        authoritative_sequence: u64::try_from(row.5)
            .map_err(|_| LocalPortError::Integrity("invalid previous state sequence".to_owned()))?,
        digest: row
            .6
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    };
    let resulting_sequence = u64::try_from(row.7)
        .map_err(|_| LocalPortError::Integrity("invalid resulting state sequence".to_owned()))?;
    let resulting_digest = row
        .8
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let state_manifest = strict_canonical(&row.9, "localized commit state")?;
    if digest(
        proof_application::ArtifactKind::KnownStateV2,
        &state_manifest,
    ) != resulting_digest
    {
        return Err(LocalPortError::Integrity(
            "localized commit state digest does not reproduce".to_owned(),
        ));
    }
    verify_v2_state_semantics(
        transaction,
        workspace_id,
        resulting_sequence,
        resulting_digest,
        &state_manifest,
    )?;
    let committed_at = row
        .10
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
    if changeset.status != ChangeSetStatus::Committed || changeset.principal_id != principal_id {
        return Err(LocalPortError::Integrity(
            "localized commit lifecycle identity differs".to_owned(),
        ));
    }
    let validation = sealed_validation_head(transaction, &changeset)?;
    let approval = load_localized_approval(transaction, &changeset)?
        .ok_or_else(|| LocalPortError::Integrity("localized commit lacks approval".to_owned()))?;
    if sealed_changeset_digest
        != validation.sealed_changeset_digest.ok_or_else(|| {
            LocalPortError::Integrity("localized commit validation lacks seal".to_owned())
        })?
        || validation_results_digest != validation.validation_results_digest
        || committed_at < approval.approved_at
    {
        return Err(LocalPortError::Integrity(
            "localized commit evidence does not reproduce".to_owned(),
        ));
    }
    let mut statement = transaction
        .prepare(
            "SELECT object_id, locale, revision FROM object_locale_revisions
             WHERE changeset_id = ?1 ORDER BY object_id, locale",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([changeset_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut renditions = Vec::new();
    for row in rows {
        let (raw_object_id, raw_locale, raw_revision) =
            row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let object_id = raw_object_id
            .parse::<ObjectId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let locale = proof_application::LocaleId::new(raw_locale)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let revision = proof_application::LocaleRevision::new(
            u32::try_from(raw_revision)
                .map_err(|_| LocalPortError::Integrity("invalid locale revision".to_owned()))?,
        )
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        renditions.push(load_object_locale_revision(
            transaction,
            object_id,
            &locale,
            revision,
        )?);
    }
    if renditions.is_empty()
        || previous_state.authoritative_sequence.checked_add(
            u64::try_from(renditions.len()).map_err(|_| {
                LocalPortError::Integrity("rendition count exceeds state sequence range".to_owned())
            })?,
        ) != Some(resulting_sequence)
        || renditions.iter().enumerate().any(|(index, rendition)| {
            rendition.authoritative_sequence
                != previous_state.authoritative_sequence
                    + u64::try_from(index).unwrap_or(u64::MAX)
                    + 1
        })
    {
        return Err(LocalPortError::Integrity(
            "localized commit authoritative sequence is not contiguous".to_owned(),
        ));
    }
    let resulting_state = KnownStateArtifactReference {
        api_version: KNOWN_STATE_V2_API_VERSION.to_owned(),
        authoritative_sequence: resulting_sequence,
        digest: resulting_digest,
    };
    let result = CommittedLocalizedChangeSet {
        changeset_id,
        sealed_changeset_digest,
        validation_results_digest,
        previous_state,
        resulting_state,
        renditions,
        committed_at,
        status: ChangeSetStatus::Committed,
    };
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": changeset_id.to_string(),
        "committed_at": committed_at.to_string(),
        "idempotency_key": idempotency_key.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if row.11 != localized_commit_effect(request_digest, &result)?.to_string() {
        return Err(LocalPortError::Integrity(
            "localized commit operation effect does not reproduce".to_owned(),
        ));
    }
    Ok(result)
}

#[allow(clippy::too_many_lines)]
fn create_localized_edition(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    command: &CreateLocalizedEditionCommand,
) -> Result<LocalizedEdition, LocalPortError> {
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/edition.create/v2",
        "changeset_id": command.changeset_id.to_string(),
        "created_at": command.created_at.to_string(),
        "edition_id": command.edition_id.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "resulting_state_digest": command.resulting_state_digest.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
    if let Some((persisted_request, raw_edition_id, persisted_effect)) = transaction
        .query_row(
            "SELECT request_digest, edition_id, effect_digest
             FROM localized_edition_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
            ),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        let edition_id = raw_edition_id
            .parse::<EditionId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let edition = load_localized_edition(transaction, workspace_id, edition_id)?;
        if persisted_request != request_digest.to_string()
            || edition_id != command.edition_id
            || persisted_effect != localized_edition_effect(request_digest, &edition)?.to_string()
        {
            return Err(LocalPortError::IdempotencyKeyReused);
        }
        return Ok(edition);
    }
    if transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM editions WHERE edition_id = ?1)",
            [command.edition_id.to_string()],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        return Err(LocalPortError::Integrity(
            "candidate Edition identity already exists".to_owned(),
        ));
    }
    let commit = load_localized_commit(transaction, workspace_id, command.changeset_id)?;
    if commit.resulting_state.digest != command.resulting_state_digest
        || commit.committed_at > command.created_at
    {
        return Err(LocalPortError::Invalid);
    }
    let current_state = current_state_reference(transaction, workspace_id)?;
    if current_state != commit.resulting_state {
        return Err(LocalPortError::StateConflict);
    }
    let changeset = load_changeset(transaction, workspace_id, command.changeset_id)?;
    let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
    let schemas =
        schema_state_references(transaction, commit.resulting_state.authoritative_sequence)?;
    let objects =
        object_state_references(transaction, commit.resulting_state.authoritative_sequence)?;
    let renditions =
        locale_state_references(transaction, commit.resulting_state.authoritative_sequence)?;
    let schema_set_digest = localized_schema_set_digest(&schemas)?;
    let object_set_digest = proof_canonical::object_set_v2_digest(&objects, &renditions)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let manifest = localized_edition_manifest(
        command.edition_id,
        workspace_id,
        principal_id,
        command.created_at,
        &intent.base.edition,
        &commit,
        &changeset,
        &schemas,
        &objects,
        &renditions,
        schema_set_digest,
        object_set_digest,
    )?;
    let edition_digest = digest(proof_application::ArtifactKind::EditionV2, &manifest);
    let metadata = localized_edition_metadata(
        command.edition_id,
        &intent.base.edition,
        &commit.resulting_state,
        command.changeset_id,
    )?;
    let metadata_digest = digest(proof_application::ArtifactKind::EditionV2, &metadata);
    let edition = LocalizedEdition {
        edition_id: command.edition_id,
        workspace_id,
        principal_id,
        changeset_id: command.changeset_id,
        base_edition: intent.base.edition,
        state: commit.resulting_state,
        schema_set_digest,
        object_set_digest,
        manifest_json: manifest.as_str().to_owned(),
        edition_digest,
        created_at: command.created_at,
    };
    let effect_digest = localized_edition_effect(request_digest, &edition)?;
    transaction
        .execute(
            "INSERT INTO editions (
                 edition_id, workspace_id, principal_id, authoritative_sequence,
                 state_digest, schema_set_digest, object_set_digest, edition_digest,
                 manifest_json, created_at, api_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                edition.edition_id.to_string(),
                workspace_id.to_string(),
                principal_id.to_string(),
                i64::try_from(edition.state.authoritative_sequence).map_err(|_| {
                    LocalPortError::Integrity("Edition sequence exceeds SQLite range".to_owned())
                })?,
                edition.state.digest.to_string(),
                schema_set_digest.to_string(),
                object_set_digest.to_string(),
                edition_digest.to_string(),
                edition.manifest_json.as_str(),
                edition.created_at.to_string(),
                LOCALIZED_EDITION_API_VERSION,
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_edition_metadata (
                 edition_id, changeset_id, base_edition_api_version,
                 base_edition_id, base_edition_digest, state_api_version,
                 state_digest, metadata_json, metadata_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                edition.edition_id.to_string(),
                edition.changeset_id.to_string(),
                edition.base_edition.api_version.as_str(),
                edition.base_edition.edition_id.to_string(),
                edition.base_edition.digest.to_string(),
                edition.state.api_version.as_str(),
                edition.state.digest.to_string(),
                metadata.as_str(),
                metadata_digest.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_edition_operations (
                 workspace_id, principal_id, idempotency_key, request_digest,
                 effect_digest, edition_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                command.idempotency_key.to_string(),
                request_digest.to_string(),
                effect_digest.to_string(),
                edition.edition_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    load_localized_edition(transaction, workspace_id, edition.edition_id)
}

fn localized_schema_set_digest(
    schemas: &[(SchemaId, proof_application::SchemaVersion, ContentDigest)],
) -> Result<ContentDigest, LocalPortError> {
    let manifest = canonicalize(&json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": schemas.iter().map(|(schema_id, schema_version, document_digest)| json!({
            "document_digest": document_digest.to_string(),
            "schema_id": schema_id.as_str(),
            "schema_version": schema_version.get(),
        })).collect::<Vec<_>>(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::SchemaSetV1,
        &manifest,
    ))
}

#[allow(clippy::too_many_arguments)]
fn localized_edition_manifest(
    edition_id: EditionId,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    created_at: Timestamp,
    base_edition: &EditionArtifactReference,
    commit: &CommittedLocalizedChangeSet,
    changeset: &LocalizedChangeSet,
    schemas: &[(SchemaId, proof_application::SchemaVersion, ContentDigest)],
    objects: &[proof_canonical::ObjectStateReference],
    renditions: &[proof_canonical::LocaleStateReference],
    schema_set_digest: ContentDigest,
    object_set_digest: ContentDigest,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    let diff = changeset_diff(changeset)?;
    canonicalize(&json!({
        "api_version": LOCALIZED_EDITION_API_VERSION,
        "authoritative_sequence": commit.resulting_state.authoritative_sequence,
        "base_edition": edition_reference_value(base_edition),
        "changeset": {
            "changeset_id": changeset.changeset_id.to_string(),
            "context_pack_digest": changeset.context_pack_digest.to_string(),
            "effective_leaf_digest": diff.effective_leaf_digest.to_string(),
            "proposal_digest": diff.proposal_digest.to_string(),
            "resource_intent_digest": changeset.resource_intent_digest.to_string(),
            "sealed_changeset_digest": commit.sealed_changeset_digest.to_string(),
            "validation_results_digest": commit.validation_results_digest.to_string(),
        },
        "created_at": created_at.to_string(),
        "edition_id": edition_id.to_string(),
        "object_set_digest": object_set_digest.to_string(),
        "objects": objects.iter().map(object_reference_value).collect::<Vec<_>>(),
        "principal_id": principal_id.to_string(),
        "renditions": renditions.iter().map(locale_reference_value).collect::<Vec<_>>(),
        "schema_set_digest": schema_set_digest.to_string(),
        "schemas": schemas.iter().map(|(schema_id, schema_version, document_digest)| json!({
            "document_digest": document_digest.to_string(),
            "schema_id": schema_id.as_str(),
            "schema_version": schema_version.get(),
        })).collect::<Vec<_>>(),
        "state": state_reference_value(&commit.resulting_state),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn object_reference_value(reference: &proof_canonical::ObjectStateReference) -> Value {
    json!({
        "lifecycle_state": reference.lifecycle_state.to_string(),
        "object_digest": reference.object_digest.to_string(),
        "object_id": reference.object_id.to_string(),
        "revision": reference.revision.get(),
        "schema_id": reference.schema_id.as_str(),
        "schema_version": reference.schema_version.get(),
    })
}

fn locale_reference_value(reference: &proof_canonical::LocaleStateReference) -> Value {
    json!({
        "locale": reference.locale.as_str(),
        "object_id": reference.object_id.to_string(),
        "rendition_digest": reference.rendition_digest.to_string(),
        "revision": reference.revision.get(),
        "schema_id": reference.schema_id.as_str(),
        "schema_version": reference.schema_version.get(),
        "source_object_digest": reference.source_object_digest.to_string(),
    })
}

fn edition_reference_value(reference: &EditionArtifactReference) -> Value {
    json!({
        "api_version": reference.api_version,
        "digest": reference.digest.to_string(),
        "edition_id": reference.edition_id.to_string(),
    })
}

fn localized_edition_metadata(
    edition_id: EditionId,
    base_edition: &EditionArtifactReference,
    state: &KnownStateArtifactReference,
    changeset_id: ChangeSetId,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": "proof.dev/localized-edition-metadata/v1",
        "base_edition": edition_reference_value(base_edition),
        "changeset_id": changeset_id.to_string(),
        "edition_id": edition_id.to_string(),
        "state": state_reference_value(state),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn localized_edition_effect(
    request_digest: ContentDigest,
    edition: &LocalizedEdition,
) -> Result<ContentDigest, LocalPortError> {
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "edition.create/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": edition.changeset_id.to_string(),
            "edition_digest": edition.edition_digest.to_string(),
            "edition_id": edition.edition_id.to_string(),
            "state": state_reference_value(&edition.state),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

#[allow(clippy::too_many_lines)]
fn load_localized_edition(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    edition_id: EditionId,
) -> Result<LocalizedEdition, LocalPortError> {
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
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let row: EditionRow = transaction
        .query_row(
            "SELECT editions.workspace_id, editions.principal_id,
                    editions.authoritative_sequence, editions.state_digest,
                    editions.schema_set_digest, editions.object_set_digest,
                    editions.edition_digest, editions.manifest_json, editions.created_at,
                    editions.api_version, metadata.changeset_id,
                    metadata.base_edition_api_version, metadata.base_edition_id,
                    metadata.base_edition_digest, metadata.state_api_version,
                    metadata.metadata_json
             FROM editions
             JOIN localized_edition_metadata AS metadata
               ON metadata.edition_id = editions.edition_id
             WHERE editions.edition_id = ?1",
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.0 != workspace_id.to_string() || row.9 != LOCALIZED_EDITION_API_VERSION {
        return Err(LocalPortError::NotFound);
    }
    let principal_id = row
        .1
        .parse::<proof_application::PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let sequence = u64::try_from(row.2)
        .map_err(|_| LocalPortError::Integrity("invalid Edition sequence".to_owned()))?;
    let state_digest = row
        .3
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let schema_set_digest = row
        .4
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let object_set_digest = row
        .5
        .ok_or_else(|| LocalPortError::Integrity("v2 Edition lacks Object-set digest".to_owned()))?
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let edition_digest = row
        .6
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let created_at = row
        .8
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let changeset_id = row
        .10
        .parse::<ChangeSetId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let base_edition = EditionArtifactReference {
        api_version: row.11,
        edition_id: row
            .12
            .parse::<EditionId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        digest: row
            .13
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    };
    verify_edition_artifact_reference(transaction, workspace_id, &base_edition)?;
    let state = KnownStateArtifactReference {
        api_version: row.14,
        authoritative_sequence: sequence,
        digest: state_digest,
    };
    if state.api_version != KNOWN_STATE_V2_API_VERSION {
        return Err(LocalPortError::Integrity(
            "v2 Edition state version is invalid".to_owned(),
        ));
    }
    let commit = load_localized_commit(transaction, workspace_id, changeset_id)?;
    if commit.resulting_state != state || created_at < commit.committed_at {
        return Err(LocalPortError::Integrity(
            "v2 Edition does not bind its exact localized commit".to_owned(),
        ));
    }
    let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
    let schemas = schema_state_references(transaction, sequence)?;
    let objects = object_state_references(transaction, sequence)?;
    let renditions = locale_state_references(transaction, sequence)?;
    let expected_schema_set = localized_schema_set_digest(&schemas)?;
    let expected_object_set = proof_canonical::object_set_v2_digest(&objects, &renditions)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let manifest = localized_edition_manifest(
        edition_id,
        workspace_id,
        principal_id,
        created_at,
        &base_edition,
        &commit,
        &changeset,
        &schemas,
        &objects,
        &renditions,
        expected_schema_set,
        expected_object_set,
    )?;
    let metadata = localized_edition_metadata(edition_id, &base_edition, &state, changeset_id)?;
    let persisted_metadata_digest: String = transaction
        .query_row(
            "SELECT metadata_digest FROM localized_edition_metadata WHERE edition_id = ?1",
            [edition_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if schema_set_digest != expected_schema_set
        || object_set_digest != expected_object_set
        || row.7 != manifest.as_str()
        || edition_digest != digest(proof_application::ArtifactKind::EditionV2, &manifest)
        || row.15 != metadata.as_str()
        || persisted_metadata_digest
            != digest(proof_application::ArtifactKind::EditionV2, &metadata).to_string()
    {
        return Err(LocalPortError::Integrity(
            "v2 Edition artifact does not reproduce".to_owned(),
        ));
    }
    let edition = LocalizedEdition {
        edition_id,
        workspace_id,
        principal_id,
        changeset_id,
        base_edition,
        state,
        schema_set_digest,
        object_set_digest,
        manifest_json: row.7,
        edition_digest,
        created_at,
    };
    let mut statement = transaction
        .prepare(
            "SELECT idempotency_key, request_digest, effect_digest
             FROM localized_edition_operations WHERE edition_id = ?1",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let operations = statement
        .query_map([edition_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut operation_count = 0_u32;
    for operation in operations {
        let (raw_key, raw_request, raw_effect) =
            operation.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let key = raw_key
            .parse::<proof_application::IdempotencyKey>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let request = canonicalize(&json!({
            "api_version": "proof.dev/operation/edition.create/v2",
            "changeset_id": edition.changeset_id.to_string(),
            "created_at": edition.created_at.to_string(),
            "edition_id": edition.edition_id.to_string(),
            "idempotency_key": key.to_string(),
            "resulting_state_digest": edition.state.digest.to_string(),
        }))
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let request_digest = digest(proof_application::ArtifactKind::OperationEffectV1, &request);
        if raw_request != request_digest.to_string()
            || raw_effect != localized_edition_effect(request_digest, &edition)?.to_string()
        {
            return Err(LocalPortError::Integrity(
                "v2 Edition operation effect does not reproduce".to_owned(),
            ));
        }
        operation_count = operation_count.saturating_add(1);
    }
    if operation_count != 1 {
        return Err(LocalPortError::Integrity(
            "v2 Edition must have exactly one creation operation".to_owned(),
        ));
    }
    Ok(edition)
}

fn verify_edition_artifact_reference(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    reference: &EditionArtifactReference,
) -> Result<(), LocalPortError> {
    match reference.api_version.as_str() {
        proof_application::EDITION_V1_API_VERSION => {
            let edition = super::load_edition(transaction, reference.edition_id)
                .map_err(super::local_port_from_edition)?;
            if edition.workspace_id != workspace_id || edition.edition_digest != reference.digest {
                return Err(LocalPortError::Integrity(
                    "v1 Edition reference does not reproduce".to_owned(),
                ));
            }
        }
        LOCALIZED_EDITION_API_VERSION => {
            let edition = load_localized_edition(transaction, workspace_id, reference.edition_id)?;
            if edition.edition_digest != reference.digest {
                return Err(LocalPortError::Integrity(
                    "v2 Edition reference does not reproduce".to_owned(),
                ));
            }
        }
        _ => {
            return Err(LocalPortError::Integrity(
                "Edition reference API version is unsupported".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum LocalizedReleaseRequest<'a> {
    Promotion(&'a PromoteLocalizedReleaseCommand),
    Rollback(&'a RollbackLocalizedReleaseCommand),
}

impl LocalizedReleaseRequest<'_> {
    const fn release_id(self) -> ReleaseId {
        match self {
            Self::Promotion(command) => command.release_id,
            Self::Rollback(command) => command.release_id,
        }
    }

    const fn proof_id(self) -> proof_application::ProofId {
        match self {
            Self::Promotion(command) => command.proof_id,
            Self::Rollback(command) => command.proof_id,
        }
    }

    fn environment_id(self) -> proof_application::EnvironmentId {
        match self {
            Self::Promotion(command) => command.environment_id.clone(),
            Self::Rollback(command) => command.environment_id.clone(),
        }
    }

    const fn idempotency_key(self) -> proof_application::IdempotencyKey {
        match self {
            Self::Promotion(command) => command.idempotency_key,
            Self::Rollback(command) => command.idempotency_key,
        }
    }

    const fn released_at(self) -> Timestamp {
        match self {
            Self::Promotion(command) => command.released_at,
            Self::Rollback(command) => command.released_at,
        }
    }

    const fn kind(self) -> proof_application::ReleaseKind {
        match self {
            Self::Promotion(_) => proof_application::ReleaseKind::Promotion,
            Self::Rollback(_) => proof_application::ReleaseKind::Rollback,
        }
    }

    const fn operation_kind(self) -> &'static str {
        match self {
            Self::Promotion(_) => "release.promote.v2",
            Self::Rollback(_) => "release.rollback.v2",
        }
    }

    const fn expected_current_release_id(self) -> ReleaseId {
        match self {
            Self::Promotion(command) => command.expected_base_release_id,
            Self::Rollback(command) => command.expected_current_release_id,
        }
    }
}

#[derive(Clone)]
struct VersionedEditionView {
    reference: EditionArtifactReference,
    state: KnownStateArtifactReference,
    schemas: Vec<(SchemaId, proof_application::SchemaVersion, ContentDigest)>,
    objects: Vec<proof_canonical::ObjectStateReference>,
    renditions: Vec<proof_canonical::LocaleStateReference>,
    created_at: Timestamp,
}

fn load_versioned_edition_view(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    edition_id: EditionId,
) -> Result<VersionedEditionView, LocalPortError> {
    let api_version: String = transaction
        .query_row(
            "SELECT api_version FROM editions WHERE edition_id = ?1 AND workspace_id = ?2",
            (edition_id.to_string(), workspace_id.to_string()),
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    match api_version.as_str() {
        proof_application::EDITION_V1_API_VERSION => {
            let edition = super::load_edition(transaction, edition_id)
                .map_err(super::local_port_from_edition)?;
            if edition.workspace_id != workspace_id {
                return Err(LocalPortError::NotFound);
            }
            Ok(VersionedEditionView {
                reference: EditionArtifactReference {
                    api_version,
                    edition_id,
                    digest: edition.edition_digest,
                },
                state: KnownStateArtifactReference {
                    api_version: KNOWN_STATE_V1_API_VERSION.to_owned(),
                    authoritative_sequence: edition.authoritative_sequence,
                    digest: edition.state_digest,
                },
                schemas: edition
                    .schemas
                    .iter()
                    .map(|schema| {
                        (
                            schema.schema_id.clone(),
                            schema.schema_version,
                            schema.document_digest,
                        )
                    })
                    .collect(),
                objects: edition
                    .objects
                    .iter()
                    .map(|object| proof_canonical::ObjectStateReference {
                        object_id: object.object_id,
                        revision: object.revision,
                        schema_id: object.schema_id.clone(),
                        schema_version: object.schema_version,
                        lifecycle_state: object.lifecycle_state,
                        object_digest: object.object_digest,
                    })
                    .collect(),
                renditions: Vec::new(),
                created_at: edition.created_at,
            })
        }
        LOCALIZED_EDITION_API_VERSION => {
            let edition = load_localized_edition(transaction, workspace_id, edition_id)?;
            Ok(VersionedEditionView {
                reference: EditionArtifactReference {
                    api_version,
                    edition_id,
                    digest: edition.edition_digest,
                },
                schemas: schema_state_references(
                    transaction,
                    edition.state.authoritative_sequence,
                )?,
                objects: object_state_references(
                    transaction,
                    edition.state.authoritative_sequence,
                )?,
                renditions: locale_state_references(
                    transaction,
                    edition.state.authoritative_sequence,
                )?,
                state: edition.state,
                created_at: edition.created_at,
            })
        }
        _ => Err(LocalPortError::Integrity(
            "Edition API version is unsupported".to_owned(),
        )),
    }
}

type RenditionChange = (
    (ObjectId, proof_application::LocaleId),
    Option<proof_canonical::LocaleStateReference>,
    Option<proof_canonical::LocaleStateReference>,
);

struct ExactEditionDelta {
    canonical: proof_canonical::CanonicalJson,
    digest: ContentDigest,
    schema_changed: bool,
    object_changed: bool,
    rendition_changes: Vec<RenditionChange>,
}

#[expect(
    clippy::too_many_lines,
    reason = "the exact delta compares all versioned Schema, Object, and rendition dimensions"
)]
fn exact_edition_delta(
    base: &VersionedEditionView,
    target: &VersionedEditionView,
) -> Result<ExactEditionDelta, LocalPortError> {
    let base_schemas = base
        .schemas
        .iter()
        .map(|(id, version, digest)| ((id.clone(), *version), *digest))
        .collect::<BTreeMap<_, _>>();
    let target_schemas = target
        .schemas
        .iter()
        .map(|(id, version, digest)| ((id.clone(), *version), *digest))
        .collect::<BTreeMap<_, _>>();
    let base_objects = base
        .objects
        .iter()
        .map(|object| (object.object_id, object.clone()))
        .collect::<BTreeMap<_, _>>();
    let target_objects = target
        .objects
        .iter()
        .map(|object| (object.object_id, object.clone()))
        .collect::<BTreeMap<_, _>>();
    let base_renditions = base
        .renditions
        .iter()
        .map(|rendition| {
            (
                (rendition.object_id, rendition.locale.clone()),
                rendition.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target_renditions = target
        .renditions
        .iter()
        .map(|rendition| {
            (
                (rendition.object_id, rendition.locale.clone()),
                rendition.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let schema_keys = base_schemas
        .keys()
        .chain(target_schemas.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let object_keys = base_objects
        .keys()
        .chain(target_objects.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let rendition_keys = base_renditions
        .keys()
        .chain(target_renditions.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let schema_changes = schema_keys
        .iter()
        .filter_map(|key| {
            let before = base_schemas.get(key).copied();
            let after = target_schemas.get(key).copied();
            (before != after).then(|| {
                json!({
                    "after": after.map(|value| value.to_string()),
                    "before": before.map(|value| value.to_string()),
                    "schema_id": key.0.as_str(),
                    "schema_version": key.1.get(),
                })
            })
        })
        .collect::<Vec<_>>();
    let object_changes = object_keys
        .iter()
        .filter_map(|key| {
            let before = base_objects.get(key);
            let after = target_objects.get(key);
            (before != after).then(|| {
                json!({
                    "after": after.map(object_reference_value),
                    "before": before.map(object_reference_value),
                    "object_id": key.to_string(),
                })
            })
        })
        .collect::<Vec<_>>();
    let rendition_changes = rendition_keys
        .iter()
        .filter_map(|key| {
            let before = base_renditions.get(key).cloned();
            let after = target_renditions.get(key).cloned();
            (before != after).then(|| (key.clone(), before, after))
        })
        .collect::<Vec<_>>();
    let canonical = canonicalize(&json!({
        "api_version": "proof.dev/edition-delta/v2",
        "base": {
            "edition": edition_reference_value(&base.reference),
            "state": state_reference_value(&base.state),
        },
        "objects": object_changes,
        "renditions": rendition_changes.iter().map(|(key, before, after)| json!({
            "after": after.as_ref().map(locale_reference_value),
            "before": before.as_ref().map(locale_reference_value),
            "locale": key.1.as_str(),
            "object_id": key.0.to_string(),
        })).collect::<Vec<_>>(),
        "schemas": schema_changes,
        "target": {
            "edition": edition_reference_value(&target.reference),
            "state": state_reference_value(&target.state),
        },
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(ExactEditionDelta {
        digest: digest(proof_application::ArtifactKind::ReleaseV2, &canonical),
        canonical,
        schema_changed: base_schemas != target_schemas,
        object_changed: base_objects != target_objects,
        rendition_changes,
    })
}

fn verify_promotion_delta(
    delta: &ExactEditionDelta,
    commit: &CommittedLocalizedChangeSet,
    changeset: &LocalizedChangeSet,
) -> Result<(), LocalPortError> {
    if delta.schema_changed || delta.object_changed {
        return Err(LocalPortError::PolicyDenied);
    }
    let (_, _, effective_edits) = proposal(changeset)?;
    if delta.rendition_changes.len() != commit.renditions.len()
        || commit.renditions.len() != effective_edits.len()
    {
        return Err(LocalPortError::PolicyDenied);
    }
    for ((key, before, after), (rendition, edit)) in delta
        .rendition_changes
        .iter()
        .zip(commit.renditions.iter().zip(effective_edits.iter()))
    {
        let Some(after) = after else {
            return Err(LocalPortError::PolicyDenied);
        };
        let expected_before = edit.input.expected_target.as_ref();
        if key != &(rendition.object_id, rendition.locale.clone())
            || key != &(edit.input.object_id, edit.input.locale.clone())
            || after.rendition_digest != rendition.rendition_digest
            || after.revision != rendition.revision
            || after.source_object_digest != rendition.source_object_digest
            || before
                .as_ref()
                .map(|value| (value.revision, value.rendition_digest))
                != expected_before.map(|value| (value.revision, value.digest))
        {
            return Err(LocalPortError::PolicyDenied);
        }
    }
    Ok(())
}

#[derive(Clone)]
struct VersionedReleaseSelection {
    reference: ReleaseArtifactReference,
    environment_id: proof_application::EnvironmentId,
    edition: EditionArtifactReference,
    release_sequence: u64,
    released_at: Timestamp,
}

fn load_release_selection(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    release_id: ReleaseId,
) -> Result<VersionedReleaseSelection, LocalPortError> {
    type SelectionRow = (String, String, String, String, String, i64, String);
    let row: SelectionRow = transaction
        .query_row(
            "SELECT workspace_id, environment_id, edition_id, edition_digest,
                    api_version, release_sequence, released_at
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
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.0 != workspace_id.to_string() {
        return Err(LocalPortError::NotFound);
    }
    let release_digest: String = transaction
        .query_row(
            "SELECT release_digest FROM releases WHERE release_id = ?1",
            [release_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let reference = ReleaseArtifactReference {
        api_version: row.4.clone(),
        release_id,
        digest: release_digest
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    };
    match row.4.as_str() {
        RELEASE_V1_API_VERSION => {
            let release = super::load_release_record(transaction, workspace_id, release_id)?;
            if release.release_digest != reference.digest {
                return Err(LocalPortError::Integrity(
                    "v1 Release reference does not reproduce".to_owned(),
                ));
            }
        }
        LOCALIZED_RELEASE_API_VERSION => {
            verify_v2_release_record(transaction, workspace_id, release_id)?;
        }
        _ => {
            return Err(LocalPortError::Integrity(
                "Release API version is unsupported".to_owned(),
            ));
        }
    }
    let edition_id = row
        .2
        .parse::<EditionId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let view = load_versioned_edition_view(transaction, workspace_id, edition_id)?;
    if row.3 != view.reference.digest.to_string() {
        return Err(LocalPortError::Integrity(
            "Release Edition digest does not reproduce".to_owned(),
        ));
    }
    Ok(VersionedReleaseSelection {
        reference,
        environment_id: proof_application::EnvironmentId::new(row.1)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        edition: view.reference,
        release_sequence: u64::try_from(row.5)
            .map_err(|_| LocalPortError::Integrity("invalid Release sequence".to_owned()))?,
        released_at: row
            .6
            .parse::<Timestamp>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    })
}

fn localized_release_request_digest(
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    request: LocalizedReleaseRequest<'_>,
) -> Result<ContentDigest, LocalPortError> {
    let (edition_id, rollback_target_release_id) = match request {
        LocalizedReleaseRequest::Promotion(command) => (Some(command.edition_id.to_string()), None),
        LocalizedReleaseRequest::Rollback(command) => {
            (None, Some(command.rollback_target_release_id.to_string()))
        }
    };
    let canonical = canonicalize(&json!({
        "api_version": "proof.dev/operation/release.create/v2",
        "edition_id": edition_id,
        "environment_id": request.environment_id().as_str(),
        "expected_current_release_id": request.expected_current_release_id().to_string(),
        "idempotency_key": request.idempotency_key().to_string(),
        "kind": request.kind().to_string(),
        "principal_id": principal_id.to_string(),
        "proof_id": request.proof_id().to_string(),
        "release_id": request.release_id().to_string(),
        "released_at": request.released_at().to_string(),
        "rollback_target_release_id": rollback_target_release_id,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(
        proof_application::ArtifactKind::OperationEffectV1,
        &canonical,
    ))
}

#[allow(clippy::too_many_lines)]
fn create_localized_release(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    request: LocalizedReleaseRequest<'_>,
    artifact_preflight: impl FnOnce() -> Result<(), LocalPortError>,
    signer_factory: impl FnOnce() -> Result<super::Ed25519SigningProvider, LocalPortError>,
) -> Result<LocalizedRelease, LocalPortError> {
    let request_digest = localized_release_request_digest(workspace_id, principal_id, request)?;
    if let Some((persisted_request, raw_release_id, raw_proof_id)) = transaction
        .query_row(
            "SELECT request_digest, release_id, proof_id
             FROM localized_release_operations
             WHERE workspace_id = ?1 AND principal_id = ?2
                   AND operation_kind = ?3 AND idempotency_key = ?4",
            (
                workspace_id.to_string(),
                principal_id.to_string(),
                request.operation_kind(),
                request.idempotency_key().to_string(),
            ),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
    {
        let release_id = raw_release_id
            .parse::<ReleaseId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let proof_id = raw_proof_id
            .parse::<proof_application::ProofId>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let release = load_localized_release(transaction, workspace_id, release_id)?;
        if persisted_request != request_digest.to_string()
            || release_id != request.release_id()
            || proof_id != request.proof_id()
            || release.proof_id != proof_id
        {
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
    let environment =
        load_localized_environment(transaction, workspace_id, request.environment_id())?;
    if environment.current_release_id != Some(request.expected_current_release_id()) {
        return Err(LocalPortError::StateConflict);
    }
    let base_release = load_release_selection(
        transaction,
        workspace_id,
        request.expected_current_release_id(),
    )?;
    if base_release.environment_id != environment.environment_id
        || request.released_at() < base_release.released_at
        || request.released_at() < environment.created_at
    {
        return Err(LocalPortError::PolicyDenied);
    }
    let base_view =
        load_versioned_edition_view(transaction, workspace_id, base_release.edition.edition_id)?;
    let (
        target_view,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        content_evidence,
    ) = match request {
        LocalizedReleaseRequest::Promotion(command) => {
            let target_view =
                load_versioned_edition_view(transaction, workspace_id, command.edition_id)?;
            if target_view.reference.api_version != LOCALIZED_EDITION_API_VERSION {
                return Err(LocalPortError::Invalid);
            }
            let edition = load_localized_edition(transaction, workspace_id, command.edition_id)?;
            let commit = load_localized_commit(transaction, workspace_id, edition.changeset_id)?;
            let changeset = load_changeset(transaction, workspace_id, edition.changeset_id)?;
            let intent =
                load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
            if intent.base.release != base_release.reference
                || intent.base.edition != base_release.edition
                || intent.base.known_state != base_view.state
                || edition.base_edition != base_release.edition
                || edition.state != commit.resulting_state
                || current_state_reference(transaction, workspace_id)? != edition.state
            {
                return Err(LocalPortError::StateConflict);
            }
            let approval = load_localized_approval(transaction, &changeset)?.ok_or_else(|| {
                LocalPortError::Integrity("Release lacks localized approval".to_owned())
            })?;
            if approval.approval != environment.required_approval
                || request.released_at() < approval.approved_at
                || request.released_at() < commit.committed_at
                || request.released_at() < edition.created_at
            {
                return Err(LocalPortError::PolicyDenied);
            }
            let delta = exact_edition_delta(&base_view, &target_view)?;
            verify_promotion_delta(&delta, &commit, &changeset)?;
            let evidence =
                localized_release_content_evidence(transaction, &intent, &changeset, &commit)?;
            (
                target_view,
                None,
                Some(changeset.changeset_id),
                Some(intent.intent_id),
                (delta, evidence),
            )
        }
        LocalizedReleaseRequest::Rollback(command) => {
            let target_release = load_release_selection(
                transaction,
                workspace_id,
                command.rollback_target_release_id,
            )?;
            if target_release.environment_id != environment.environment_id
                || target_release.release_sequence >= base_release.release_sequence
            {
                return Err(LocalPortError::InvalidRollbackTarget);
            }
            let target_view = load_versioned_edition_view(
                transaction,
                workspace_id,
                target_release.edition.edition_id,
            )?;
            let delta = exact_edition_delta(&base_view, &target_view)?;
            (
                target_view,
                Some(command.rollback_target_release_id),
                None,
                None,
                (delta, Value::Null),
            )
        }
    };
    let (delta, content_evidence) = content_evidence;
    let signer = signer_factory()?;
    let metadata = super::ProofSigningProvider::metadata(&signer)
        .map_err(|error| LocalPortError::Signing(error.to_string()))?;
    super::persist_signing_key(transaction, &metadata, request.released_at())?;
    let release_sequence = u64::try_from(
        transaction
            .query_row(
                "SELECT COALESCE(MAX(release_sequence), 0) + 1 FROM releases",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|error| LocalPortError::Storage(error.to_string()))?,
    )
    .map_err(|_| LocalPortError::Integrity("invalid next Release sequence".to_owned()))?;
    let policy_decision = localized_release_policy_decision(
        workspace_id,
        principal_id,
        &environment,
        request.kind(),
        &base_release.reference,
        &target_view.reference,
        rollback_target_release_id,
        delta.digest,
        changeset_id,
        resource_intent_id,
        request.released_at(),
    )?;
    let policy_decision_digest = digest(
        proof_application::ArtifactKind::AuthorizationDecisionV1,
        &policy_decision,
    );
    let manifest = localized_release_manifest(
        request.release_id(),
        request.proof_id(),
        workspace_id,
        principal_id,
        &environment,
        request.kind(),
        release_sequence,
        &base_release.reference,
        &target_view.reference,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        delta.digest,
        policy_decision_digest,
        &metadata.key_id,
        request.released_at(),
    )?;
    let release_digest = digest(proof_application::ArtifactKind::ReleaseV2, &manifest);
    let statement = localized_release_statement(
        request.release_id(),
        workspace_id,
        principal_id,
        &environment,
        request.kind(),
        release_sequence,
        &base_release.reference,
        &target_view,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        release_digest,
        policy_decision_digest,
        &metadata.key_id,
        request.released_at(),
        &delta,
        &content_evidence,
    );
    let signed_proof = super::sign_release_statement(&statement, &signer)
        .map_err(|error| LocalPortError::Signing(error.to_string()))?;
    if signed_proof.key_id != metadata.key_id {
        return Err(LocalPortError::Signing(
            "signer changed key identity during localized Release creation".to_owned(),
        ));
    }
    let metadata_manifest = localized_release_metadata(
        request.release_id(),
        &base_release.reference,
        &target_view.reference,
        request.kind(),
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        delta.digest,
    )?;
    let metadata_digest = digest(
        proof_application::ArtifactKind::ReleaseV2,
        &metadata_manifest,
    );
    transaction
        .execute(
            "INSERT OR IGNORE INTO release_policy_decisions (
                 decision_digest, environment_id, environment_config_version,
                 environment_config_digest, edition_id, edition_digest,
                 principal_id, allowed, decision_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8)",
            (
                policy_decision_digest.to_string(),
                environment.environment_id.as_str(),
                environment.config_version,
                environment.config_digest.to_string(),
                target_view.reference.edition_id.to_string(),
                target_view.reference.digest.to_string(),
                principal_id.to_string(),
                policy_decision.as_str(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO releases (
                 release_id, release_sequence, workspace_id, environment_id,
                 environment_config_version, edition_id, edition_digest, release_kind,
                 rollback_target_release_id, previous_release_id, principal_id,
                 delegation_id, policy_decision_digest, manifest_json, release_digest,
                 released_at, api_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                       NULL, ?12, ?13, ?14, ?15, ?16)",
            params![
                request.release_id().to_string(),
                i64::try_from(release_sequence).map_err(|_| {
                    LocalPortError::Integrity("Release sequence exceeds SQLite range".to_owned())
                })?,
                workspace_id.to_string(),
                environment.environment_id.as_str(),
                i64::from(environment.config_version),
                target_view.reference.edition_id.to_string(),
                target_view.reference.digest.to_string(),
                request.kind().to_string(),
                rollback_target_release_id.map(|value| value.to_string()),
                base_release.reference.release_id.to_string(),
                principal_id.to_string(),
                policy_decision_digest.to_string(),
                manifest.as_str(),
                release_digest.to_string(),
                request.released_at().to_string(),
                LOCALIZED_RELEASE_API_VERSION,
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_release_metadata (
                 release_id, base_release_id, changeset_id, resource_intent_id,
                 exact_delta_json, exact_delta_digest, metadata_json, metadata_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                request.release_id().to_string(),
                base_release.reference.release_id.to_string(),
                changeset_id.map(|value| value.to_string()),
                resource_intent_id.map(|value| value.to_string()),
                delta.canonical.as_str(),
                delta.digest.to_string(),
                metadata_manifest.as_str(),
                metadata_digest.to_string(),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO release_proofs (
                 proof_id, release_id, key_id, payload_type, statement_json,
                 envelope_json, proof_digest, created_at, predicate_type
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                request.proof_id().to_string(),
                request.release_id().to_string(),
                metadata.key_id.as_str(),
                super::DSSE_PAYLOAD_TYPE,
                signed_proof.payload_json.as_str(),
                signed_proof.envelope_json.as_str(),
                signed_proof.envelope_digest.to_string(),
                request.released_at().to_string(),
                proof_attestation::RELEASE_PREDICATE_TYPE_V2,
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_release_operations (
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
    let changed = transaction
        .execute(
            "UPDATE environment_current_releases
             SET release_id = ?1, release_sequence = ?2, projection_version = 1
             WHERE environment_id = ?3 AND release_id = ?4 AND release_sequence = ?5",
            params![
                request.release_id().to_string(),
                i64::try_from(release_sequence).map_err(|_| {
                    LocalPortError::Integrity("Release sequence exceeds SQLite range".to_owned())
                })?,
                environment.environment_id.as_str(),
                base_release.reference.release_id.to_string(),
                i64::try_from(base_release.release_sequence).map_err(|_| {
                    LocalPortError::Integrity(
                        "base Release sequence exceeds SQLite range".to_owned(),
                    )
                })?,
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(LocalPortError::StateConflict);
    }
    Ok(LocalizedRelease {
        release_id: request.release_id(),
        workspace_id,
        environment_id: environment.environment_id,
        edition: target_view.reference,
        kind: request.kind(),
        release_sequence,
        previous_release_id: Some(base_release.reference.release_id),
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        manifest_json: manifest.as_str().to_owned(),
        release_digest,
        proof_id: request.proof_id(),
        proof_envelope_digest: signed_proof.envelope_digest,
        key_id: signed_proof.key_id,
        proof_envelope_json: signed_proof.envelope_json,
        released_at: request.released_at(),
    })
}

#[allow(clippy::too_many_arguments)]
fn localized_release_policy_decision(
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    environment: &proof_application::Environment,
    kind: proof_application::ReleaseKind,
    base_release: &ReleaseArtifactReference,
    edition: &EditionArtifactReference,
    rollback_target_release_id: Option<ReleaseId>,
    exact_delta_digest: ContentDigest,
    changeset_id: Option<ChangeSetId>,
    resource_intent_id: Option<ContentResourceIntentId>,
    released_at: Timestamp,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": release_reference_value(base_release),
        "changeset_id": changeset_id.map(|value| value.to_string()),
        "edition": edition_reference_value(edition),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": environment.environment_id.as_str(),
        "evaluated_at": released_at.to_string(),
        "exact_delta_digest": exact_delta_digest.to_string(),
        "kind": kind.to_string(),
        "operating_principal_id": principal_id.to_string(),
        "policy_profile": environment.policy_profile,
        "required_approval": environment.required_approval.as_str(),
        "resource_intent_id": resource_intent_id.map(|value| value.to_string()),
        "rollback_target_release_id": rollback_target_release_id.map(|value| value.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn release_reference_value(reference: &ReleaseArtifactReference) -> Value {
    json!({
        "api_version": reference.api_version,
        "digest": reference.digest.to_string(),
        "release_id": reference.release_id.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
fn localized_release_manifest(
    release_id: ReleaseId,
    proof_id: proof_application::ProofId,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    environment: &proof_application::Environment,
    kind: proof_application::ReleaseKind,
    release_sequence: u64,
    base_release: &ReleaseArtifactReference,
    edition: &EditionArtifactReference,
    rollback_target_release_id: Option<ReleaseId>,
    changeset_id: Option<ChangeSetId>,
    resource_intent_id: Option<ContentResourceIntentId>,
    exact_delta_digest: ContentDigest,
    policy_decision_digest: ContentDigest,
    key_id: &str,
    released_at: Timestamp,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": LOCALIZED_RELEASE_API_VERSION,
        "authorization_decision_digest": policy_decision_digest.to_string(),
        "base_release": release_reference_value(base_release),
        "changeset_id": changeset_id.map(|value| value.to_string()),
        "edition": edition_reference_value(edition),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": environment.environment_id.as_str(),
        "exact_delta_digest": exact_delta_digest.to_string(),
        "key_id": key_id,
        "kind": kind.to_string(),
        "principal_id": principal_id.to_string(),
        "proof_id": proof_id.to_string(),
        "release_id": release_id.to_string(),
        "release_sequence": release_sequence,
        "released_at": released_at.to_string(),
        "resource_intent_id": resource_intent_id.map(|value| value.to_string()),
        "rollback_target_release_id": rollback_target_release_id.map(|value| value.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn localized_release_statement(
    release_id: ReleaseId,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    environment: &proof_application::Environment,
    kind: proof_application::ReleaseKind,
    release_sequence: u64,
    base_release: &ReleaseArtifactReference,
    edition: &VersionedEditionView,
    rollback_target_release_id: Option<ReleaseId>,
    changeset_id: Option<ChangeSetId>,
    resource_intent_id: Option<ContentResourceIntentId>,
    release_digest: ContentDigest,
    policy_decision_digest: ContentDigest,
    key_id: &str,
    released_at: Timestamp,
    delta: &ExactEditionDelta,
    content_evidence: &Value,
) -> super::InTotoStatement {
    super::InTotoStatement::release_v2(
        vec![
            super::InTotoSubject {
                name: format!("proof:edition:{}", edition.reference.edition_id),
                digest: BTreeMap::from([(
                    "blake3".to_owned(),
                    localized_digest_hex(edition.reference.digest),
                )]),
            },
            super::InTotoSubject {
                name: format!("proof:release:{release_id}"),
                digest: BTreeMap::from([(
                    "blake3".to_owned(),
                    localized_digest_hex(release_digest),
                )]),
            },
        ],
        json!({
            "api_version": "proof.dev/release-proof-predicate/v2",
            "authority": {
                "authorization_decision_digest": policy_decision_digest.to_string(),
                "human_principal_id": principal_id.to_string(),
                "policy_profile": environment.policy_profile,
            },
            "content_evidence": content_evidence,
            "exact_delta": parse_strict(delta.canonical.as_bytes()).expect("canonical delta parses"),
            "exact_delta_digest": delta.digest.to_string(),
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": edition.state.api_version,
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "release": {
                "base_release": release_reference_value(base_release),
                "changeset_id": changeset_id.map(|value| value.to_string()),
                "edition": edition_reference_value(&edition.reference),
                "environment_id": environment.environment_id.as_str(),
                "key_id": key_id,
                "kind": kind.to_string(),
                "release_digest": release_digest.to_string(),
                "release_id": release_id.to_string(),
                "release_sequence": release_sequence,
                "released_at": released_at.to_string(),
                "resource_intent_id": resource_intent_id.map(|value| value.to_string()),
                "rollback_target_release_id": rollback_target_release_id.map(|value| value.to_string()),
            },
            "state": state_reference_value(&edition.state),
            "workspace_id": workspace_id.to_string(),
        }),
    )
}

fn localized_digest_hex(digest: ContentDigest) -> String {
    digest
        .to_string()
        .strip_prefix("blake3:")
        .expect("ContentDigest only supports BLAKE3")
        .to_owned()
}

#[allow(clippy::too_many_arguments)]
fn localized_release_metadata(
    release_id: ReleaseId,
    base_release: &ReleaseArtifactReference,
    edition: &EditionArtifactReference,
    kind: proof_application::ReleaseKind,
    rollback_target_release_id: Option<ReleaseId>,
    changeset_id: Option<ChangeSetId>,
    resource_intent_id: Option<ContentResourceIntentId>,
    exact_delta_digest: ContentDigest,
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": "proof.dev/localized-release-metadata/v1",
        "base_release": release_reference_value(base_release),
        "changeset_id": changeset_id.map(|value| value.to_string()),
        "edition": edition_reference_value(edition),
        "exact_delta_digest": exact_delta_digest.to_string(),
        "kind": kind.to_string(),
        "release_id": release_id.to_string(),
        "resource_intent_id": resource_intent_id.map(|value| value.to_string()),
        "rollback_target_release_id": rollback_target_release_id.map(|value| value.to_string()),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn localized_release_content_evidence(
    transaction: &Transaction<'_>,
    intent: &ContentResourceIntent,
    changeset: &LocalizedChangeSet,
    commit: &CommittedLocalizedChangeSet,
) -> Result<Value, LocalPortError> {
    let context = load_context(
        transaction,
        changeset.workspace_id,
        changeset.context_pack_id,
    )?;
    let validations = load_validation_chain(transaction, changeset)?;
    let diff = changeset_diff(changeset)?;
    Ok(json!({
        "base": baseline_value(&intent.base),
        "changeset": {
            "changeset_id": changeset.changeset_id.to_string(),
            "effective_leaf_digest": diff.effective_leaf_digest.to_string(),
            "proposal_digest": diff.proposal_digest.to_string(),
            "sealed_changeset_digest": commit.sealed_changeset_digest.to_string(),
        },
        "context_pack_digest": context.context_pack_digest.to_string(),
        "renditions": commit.renditions.iter().map(|rendition| json!({
            "edit_id": rendition.edit_id.to_string(),
            "locale": rendition.locale.as_str(),
            "object_id": rendition.object_id.to_string(),
            "rendition_digest": rendition.rendition_digest.to_string(),
            "schema_id": rendition.schema_id.as_str(),
            "schema_version": rendition.schema_version.get(),
            "source_object_digest": rendition.source_object_digest.to_string(),
        })).collect::<Vec<_>>(),
        "resource_intent": {
            "digest": intent.intent_digest.to_string(),
            "intent_id": intent.intent_id.to_string(),
            "targets": targets_value(&intent.targets),
        },
        "resulting_state": state_reference_value(&commit.resulting_state),
        "validations": validations.iter().map(|validation| json!({
            "attempt": validation.attempt,
            "previous_validation_result_digest": validation.previous_validation_result_digest.map(|value| value.to_string()),
            "proposal_digest": validation.proposal_digest.to_string(),
            "results_digest": validation.validation_results_digest.to_string(),
            "valid": validation.valid,
        })).collect::<Vec<_>>(),
    }))
}

#[allow(clippy::too_many_lines)]
fn load_localized_release(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    release_id: ReleaseId,
) -> Result<LocalizedRelease, LocalPortError> {
    type ReleaseRow = (
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
        String,
        String,
        String,
        String,
        String,
    );
    type MetadataRow = (
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
    );
    type ProofRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let row: ReleaseRow = transaction
        .query_row(
            "SELECT release_sequence, workspace_id, environment_id,
                    environment_config_version, edition_id, edition_digest,
                    release_kind, rollback_target_release_id, previous_release_id,
                    principal_id, policy_decision_digest, manifest_json,
                    release_digest, released_at, api_version
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
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or(LocalPortError::NotFound)?;
    if row.1 != workspace_id.to_string() || row.14 != LOCALIZED_RELEASE_API_VERSION {
        return Err(LocalPortError::NotFound);
    }
    let release_sequence = u64::try_from(row.0)
        .map_err(|_| LocalPortError::Integrity("invalid Release sequence".to_owned()))?;
    let environment_id = proof_application::EnvironmentId::new(row.2.clone())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let environment_config_version = u32::try_from(row.3)
        .map_err(|_| LocalPortError::Integrity("invalid Environment version".to_owned()))?;
    let edition_id = row
        .4
        .parse::<EditionId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let edition = load_versioned_edition_view(transaction, workspace_id, edition_id)?;
    if row.5 != edition.reference.digest.to_string() {
        return Err(LocalPortError::Integrity(
            "localized Release Edition binding does not reproduce".to_owned(),
        ));
    }
    let kind = match row.6.as_str() {
        "promotion" => proof_application::ReleaseKind::Promotion,
        "rollback" => proof_application::ReleaseKind::Rollback,
        _ => return Err(LocalPortError::Integrity("invalid Release kind".to_owned())),
    };
    let rollback_target_release_id = row
        .7
        .map(|value| value.parse::<ReleaseId>())
        .transpose()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let previous_release_id = row
        .8
        .map(|value| value.parse::<ReleaseId>())
        .transpose()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("v2 Release lacks a predecessor Release".to_owned())
        })?;
    let principal_id = row
        .9
        .parse::<proof_application::PrincipalId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let policy_decision_digest = row
        .10
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let release_digest = row
        .12
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let released_at = row
        .13
        .parse::<Timestamp>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let metadata: MetadataRow = transaction
        .query_row(
            "SELECT base_release_id, changeset_id, resource_intent_id,
                    exact_delta_json, exact_delta_digest, metadata_json, metadata_digest
             FROM localized_release_metadata WHERE release_id = ?1",
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("localized Release metadata is missing".to_owned())
        })?;
    let metadata_base = metadata
        .0
        .ok_or_else(|| LocalPortError::Integrity("localized Release base is missing".to_owned()))?
        .parse::<ReleaseId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if metadata_base != previous_release_id {
        return Err(LocalPortError::Integrity(
            "localized Release predecessor references differ".to_owned(),
        ));
    }
    let changeset_id = metadata
        .1
        .map(|value| value.parse::<ChangeSetId>())
        .transpose()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let resource_intent_id = metadata
        .2
        .map(|value| value.parse::<ContentResourceIntentId>())
        .transpose()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let exact_delta_digest = metadata
        .4
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let base_release = load_release_selection(transaction, workspace_id, previous_release_id)?;
    if base_release.environment_id != environment_id
        || base_release.release_sequence >= release_sequence
        || released_at < base_release.released_at
    {
        return Err(LocalPortError::Integrity(
            "localized Release predecessor is not earlier in the same Environment".to_owned(),
        ));
    }
    let expected_predecessor: Option<String> = transaction
        .query_row(
            "SELECT release_id FROM releases
             WHERE environment_id = ?1 AND release_sequence < ?2
             ORDER BY release_sequence DESC LIMIT 1",
            (
                environment_id.as_str(),
                i64::try_from(release_sequence).map_err(|_| {
                    LocalPortError::Integrity("Release sequence exceeds SQLite range".to_owned())
                })?,
            ),
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let previous_release_id_text = previous_release_id.to_string();
    if expected_predecessor.as_deref() != Some(previous_release_id_text.as_str()) {
        return Err(LocalPortError::Integrity(
            "localized Release predecessor chain is not contiguous for its Environment".to_owned(),
        ));
    }
    let base_view =
        load_versioned_edition_view(transaction, workspace_id, base_release.edition.edition_id)?;
    let delta = exact_edition_delta(&base_view, &edition)?;
    if delta.canonical.as_str() != metadata.3 || delta.digest != exact_delta_digest {
        return Err(LocalPortError::Integrity(
            "localized Release exact delta does not reproduce".to_owned(),
        ));
    }
    let content_evidence = match kind {
        proof_application::ReleaseKind::Promotion => {
            let (Some(changeset_id), Some(resource_intent_id), None) =
                (changeset_id, resource_intent_id, rollback_target_release_id)
            else {
                return Err(LocalPortError::Integrity(
                    "localized promotion evidence shape is invalid".to_owned(),
                ));
            };
            let localized_edition = load_localized_edition(transaction, workspace_id, edition_id)?;
            if localized_edition.changeset_id != changeset_id {
                return Err(LocalPortError::Integrity(
                    "localized promotion Edition and ChangeSet differ".to_owned(),
                ));
            }
            let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
            let intent = load_resource_intent(transaction, workspace_id, resource_intent_id)?;
            let commit = load_localized_commit(transaction, workspace_id, changeset_id)?;
            if changeset.resource_intent_id != resource_intent_id
                || intent.base.release != base_release.reference
                || intent.base.edition != base_release.edition
                || intent.base.known_state != base_view.state
                || localized_edition.base_edition != base_release.edition
                || localized_edition.state != commit.resulting_state
            {
                return Err(LocalPortError::Integrity(
                    "localized promotion causal closure differs".to_owned(),
                ));
            }
            verify_promotion_delta(&delta, &commit, &changeset)?;
            localized_release_content_evidence(transaction, &intent, &changeset, &commit)?
        }
        proof_application::ReleaseKind::Rollback => {
            let (None, None, Some(target_release_id)) =
                (changeset_id, resource_intent_id, rollback_target_release_id)
            else {
                return Err(LocalPortError::Integrity(
                    "localized rollback evidence shape is invalid".to_owned(),
                ));
            };
            let target = load_release_selection(transaction, workspace_id, target_release_id)?;
            if target.environment_id != environment_id
                || target.release_sequence >= base_release.release_sequence
                || target.edition != edition.reference
            {
                return Err(LocalPortError::Integrity(
                    "localized rollback target does not reproduce".to_owned(),
                ));
            }
            Value::Null
        }
    };
    let environment = super::load_environment_version(
        transaction,
        workspace_id,
        environment_id.clone(),
        environment_config_version,
    )
    .map_err(super::local_port_from_environment)?;
    if released_at < environment.created_at || released_at < edition.created_at {
        return Err(LocalPortError::Integrity(
            "localized Release timestamp predates bound evidence".to_owned(),
        ));
    }
    let policy = localized_release_policy_decision(
        workspace_id,
        principal_id,
        &environment,
        kind,
        &base_release.reference,
        &edition.reference,
        rollback_target_release_id,
        exact_delta_digest,
        changeset_id,
        resource_intent_id,
        released_at,
    )?;
    if digest(
        proof_application::ArtifactKind::AuthorizationDecisionV1,
        &policy,
    ) != policy_decision_digest
    {
        return Err(LocalPortError::Integrity(
            "localized Release policy digest does not reproduce".to_owned(),
        ));
    }
    let policy_row: (String, String, String, String, i64) = transaction
        .query_row(
            "SELECT decision_json, environment_config_digest, edition_digest,
                    principal_id, allowed
             FROM release_policy_decisions WHERE decision_digest = ?1",
            [policy_decision_digest.to_string()],
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("localized Release policy is missing".to_owned())
        })?;
    if policy_row
        != (
            policy.as_str().to_owned(),
            environment.config_digest.to_string(),
            edition.reference.digest.to_string(),
            principal_id.to_string(),
            1,
        )
    {
        return Err(LocalPortError::Integrity(
            "localized Release policy evidence differs".to_owned(),
        ));
    }
    let proof: ProofRow = transaction
        .query_row(
            "SELECT proof_id, key_id, payload_type, statement_json,
                    envelope_json, proof_digest, created_at, predicate_type
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
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("localized Release Proof is missing".to_owned())
        })?;
    let proof_id = proof
        .0
        .parse::<proof_application::ProofId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let proof_digest = proof
        .5
        .parse::<ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if proof.2 != super::DSSE_PAYLOAD_TYPE
        || proof.6 != released_at.to_string()
        || proof.7 != proof_attestation::RELEASE_PREDICATE_TYPE_V2
    {
        return Err(LocalPortError::Integrity(
            "localized Release Proof profile differs".to_owned(),
        ));
    }
    super::verify_signing_key_trust(transaction, &proof.1, released_at)?;
    let verified = super::verify_release_envelope(proof.4.as_bytes(), proof_digest, &proof.1)
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let expected_statement = localized_release_statement(
        release_id,
        workspace_id,
        principal_id,
        &environment,
        kind,
        release_sequence,
        &base_release.reference,
        &edition,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        release_digest,
        policy_decision_digest,
        &proof.1,
        released_at,
        &delta,
        &content_evidence,
    );
    let expected_statement_json = canonicalize(
        &serde_json::to_value(&expected_statement)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
    )
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if proof.3 != expected_statement_json.as_str()
        || verified.parsed.payload_json != proof.3
        || verified.parsed.statement != expected_statement
        || verified.parsed.envelope_json != proof.4
    {
        return Err(LocalPortError::Integrity(
            "localized Release Statement does not reproduce".to_owned(),
        ));
    }
    let manifest = localized_release_manifest(
        release_id,
        proof_id,
        workspace_id,
        principal_id,
        &environment,
        kind,
        release_sequence,
        &base_release.reference,
        &edition.reference,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        exact_delta_digest,
        policy_decision_digest,
        &proof.1,
        released_at,
    )?;
    if row.11 != manifest.as_str()
        || digest(proof_application::ArtifactKind::ReleaseV2, &manifest) != release_digest
    {
        return Err(LocalPortError::Integrity(
            "localized Release manifest does not reproduce".to_owned(),
        ));
    }
    let expected_metadata = localized_release_metadata(
        release_id,
        &base_release.reference,
        &edition.reference,
        kind,
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        exact_delta_digest,
    )?;
    if metadata.5 != expected_metadata.as_str()
        || metadata.6
            != digest(
                proof_application::ArtifactKind::ReleaseV2,
                &expected_metadata,
            )
            .to_string()
    {
        return Err(LocalPortError::Integrity(
            "localized Release metadata does not reproduce".to_owned(),
        ));
    }
    let output = LocalizedRelease {
        release_id,
        workspace_id,
        environment_id,
        edition: edition.reference,
        kind,
        release_sequence,
        previous_release_id: Some(previous_release_id),
        rollback_target_release_id,
        changeset_id,
        resource_intent_id,
        manifest_json: row.11,
        release_digest,
        proof_id,
        proof_envelope_digest: proof_digest,
        key_id: proof.1,
        proof_envelope_json: proof.4,
        released_at,
    };
    verify_localized_release_operation(transaction, principal_id, &output)?;
    Ok(output)
}

pub(super) fn load_localized_release_chain_node(
    connection: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    release_id: ReleaseId,
) -> Result<(u64, proof_application::EnvironmentId, Option<ReleaseId>), LocalPortError> {
    let release = load_localized_release(connection, workspace_id, release_id)?;
    Ok((
        release.release_sequence,
        release.environment_id,
        release.previous_release_id,
    ))
}

fn verify_localized_release_operation(
    transaction: &Transaction<'_>,
    principal_id: proof_application::PrincipalId,
    release: &LocalizedRelease,
) -> Result<(), LocalPortError> {
    let row: (String, String, String) = transaction
        .query_row(
            "SELECT operation_kind, idempotency_key, request_digest
             FROM localized_release_operations WHERE release_id = ?1",
            [release.release_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity("localized Release operation is missing".to_owned())
        })?;
    let key = row
        .1
        .parse::<proof_application::IdempotencyKey>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let request = match release.kind {
        proof_application::ReleaseKind::Promotion => {
            if row.0 != "release.promote.v2" {
                return Err(LocalPortError::Integrity(
                    "localized promotion operation kind differs".to_owned(),
                ));
            }
            LocalizedReleaseRequest::Promotion(&PromoteLocalizedReleaseCommand {
                release_id: release.release_id,
                proof_id: release.proof_id,
                environment_id: release.environment_id.clone(),
                edition_id: release.edition.edition_id,
                expected_base_release_id: release.previous_release_id.ok_or_else(|| {
                    LocalPortError::Integrity("localized promotion base is missing".to_owned())
                })?,
                idempotency_key: key,
                released_at: release.released_at,
            })
        }
        proof_application::ReleaseKind::Rollback => {
            if row.0 != "release.rollback.v2" {
                return Err(LocalPortError::Integrity(
                    "localized rollback operation kind differs".to_owned(),
                ));
            }
            LocalizedReleaseRequest::Rollback(&RollbackLocalizedReleaseCommand {
                release_id: release.release_id,
                proof_id: release.proof_id,
                environment_id: release.environment_id.clone(),
                expected_current_release_id: release.previous_release_id.ok_or_else(|| {
                    LocalPortError::Integrity("localized rollback base is missing".to_owned())
                })?,
                rollback_target_release_id: release.rollback_target_release_id.ok_or_else(
                    || LocalPortError::Integrity("localized rollback target is missing".to_owned()),
                )?,
                idempotency_key: key,
                released_at: release.released_at,
            })
        }
    };
    if row.2
        != localized_release_request_digest(release.workspace_id, principal_id, request)?
            .to_string()
    {
        return Err(LocalPortError::Integrity(
            "localized Release operation request does not reproduce".to_owned(),
        ));
    }
    Ok(())
}

fn materialize_localized_release_proof(
    workspace: &LocalWorkspace,
    release: &LocalizedRelease,
) -> Result<(), LocalPortError> {
    use std::io::Write as _;

    let proofs = workspace.release_proof_directory()?;
    let path = proofs.join(format!("{}.dsse.json", release.proof_id));
    let needs_write = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(LocalPortError::Integrity(
                    "Release Proof artifact is not a regular file".to_owned(),
                ));
            }
            std::fs::read_to_string(&path)
                .map_err(|error| LocalPortError::Storage(error.to_string()))?
                != release.proof_envelope_json
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(LocalPortError::Storage(error.to_string())),
    };
    if needs_write {
        let temporary = proofs.join(format!(".{}.dsse.tmp", release.proof_id));
        super::remove_stale_regular_file(&temporary, "Release Proof temporary artifact")?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        file.write_all(release.proof_envelope_json.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
        drop(file);
        super::replace_derived_file(&temporary, &path)?;
        super::sync_parent_directory(&path)
            .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    }
    let persisted = std::fs::read_to_string(&path)
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if persisted != release.proof_envelope_json {
        return Err(LocalPortError::Integrity(
            "localized Release Proof export differs from verified storage".to_owned(),
        ));
    }
    workspace.acknowledge_release_proof_export(release.proof_id)
}

fn query_released_renditions(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    command: &QueryReleasedRenditionsCommand,
) -> Result<ReleasedRenditionQuery, LocalPortError> {
    if command.targets.is_empty()
        || command.targets.len() > MAX_LOCALIZED_TARGETS
        || !command.targets.is_sorted()
        || command.targets.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(LocalPortError::Invalid);
    }
    let environment =
        load_localized_environment(transaction, workspace_id, command.environment_id.clone())?;
    let release_id = environment
        .current_release_id
        .ok_or(LocalPortError::NotFound)?;
    let api_version: String = transaction
        .query_row(
            "SELECT api_version FROM releases WHERE release_id = ?1",
            [release_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    if api_version != LOCALIZED_RELEASE_API_VERSION {
        return Err(LocalPortError::NotFound);
    }
    let release = load_localized_release(transaction, workspace_id, release_id)?;
    if command.evaluated_at < release.released_at
        || release.edition.api_version != LOCALIZED_EDITION_API_VERSION
    {
        return if command.evaluated_at < release.released_at {
            Err(LocalPortError::Invalid)
        } else {
            Err(LocalPortError::NotFound)
        };
    }
    let edition = load_localized_edition(transaction, workspace_id, release.edition.edition_id)?;
    let mut renditions = Vec::with_capacity(command.targets.len());
    for target in &command.targets {
        let selected = load_rendition_at(
            transaction,
            target.object_id,
            &target.locale,
            edition.state.authoritative_sequence,
        )?
        .ok_or(LocalPortError::NotFound)?;
        let revision = proof_application::LocaleRevision::new(selected.revision)
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let rendition =
            load_object_locale_revision(transaction, target.object_id, &target.locale, revision)?;
        renditions.push(ReleasedRendition {
            object_id: rendition.object_id,
            locale: rendition.locale,
            source_revision: rendition.source_object_revision,
            source_digest: rendition.source_object_digest,
            rendition_revision: rendition.revision,
            rendition_digest: rendition.rendition_digest,
            schema_id: rendition.schema_id,
            schema_version: rendition.schema_version,
            canonical_content: rendition.canonical_content,
        });
    }
    Ok(ReleasedRenditionQuery {
        workspace_id,
        environment_id: command.environment_id.clone(),
        release_id,
        edition: release.edition,
        renditions,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "validation persists a complete deterministic attempt and exact lineage transition"
)]
fn validate_changeset(
    transaction: &Transaction<'_>,
    workspace_id: proof_application::WorkspaceId,
    principal_id: proof_application::PrincipalId,
    changeset_id: ChangeSetId,
) -> Result<proof_application::LocalizedValidation, LocalPortError> {
    let changeset = load_changeset(transaction, workspace_id, changeset_id)?;
    if changeset.principal_id != principal_id {
        return Err(LocalPortError::NotFound);
    }
    if changeset.status == ChangeSetStatus::Ready {
        return load_validation_chain(transaction, &changeset)?
            .last()
            .cloned()
            .ok_or_else(|| {
                LocalPortError::Integrity("Ready ChangeSet lacks validation".to_owned())
            });
    }
    if changeset.status != ChangeSetStatus::Draft || changeset.edits.is_empty() {
        return Err(LocalPortError::Invalid);
    }
    let intent = load_resource_intent(transaction, workspace_id, changeset.resource_intent_id)?;
    verify_baseline_is_current(transaction, workspace_id, &intent)?;
    let (_, _, effective_edits) = proposal(&changeset)?;
    let effective_targets = effective_edits
        .iter()
        .map(|edit| proof_application::LocalizedContentTarget {
            object_id: edit.input.object_id,
            schema_id: edit.input.expected_source.schema_id.clone(),
            locale: edit.input.locale.clone(),
        })
        .collect::<Vec<_>>();
    if effective_targets != intent.targets {
        return Err(LocalPortError::Invalid);
    }
    let context_pack = load_context(transaction, workspace_id, changeset.context_pack_id)?;
    let mut chain = load_validation_chain(transaction, &changeset)?;
    let attempt = u32::try_from(chain.len())
        .map_err(|_| LocalPortError::LimitExceeded)?
        .checked_add(1)
        .ok_or(LocalPortError::LimitExceeded)?;
    if attempt > context_pack.limits.max_validation_attempts {
        return Err(LocalPortError::LimitExceeded);
    }
    let previous = chain.last().map(|result| result.validation_results_digest);
    let rules = load_policy_rules(transaction, context_pack.context_pack_id)?;
    let (proposal_digest, effective_leaf_digest, effective_edits) = proposal(&changeset)?;
    let mut findings = Vec::new();
    for edit in &effective_edits {
        let localized_value = parse_strict(edit.input.canonical_content.as_bytes())
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        for rule in rules.iter().filter(|rule| rule.locale == edit.input.locale) {
            let segments = parse_pointer(&rule.pointer)?;
            let value = string_at_pointer(&localized_value, &segments)?;
            if rule
                .disallowed_values
                .binary_search_by(|candidate| candidate.as_str().cmp(value))
                .is_ok()
            {
                findings.push(proof_application::LocalizedFinding {
                    code: proof_application::PROHIBITED_LEGAL_CLAIM_CODE.to_owned(),
                    severity: proof_application::Severity::Error,
                    edit_id: edit.edit_id,
                    object_id: edit.input.object_id,
                    locale: edit.input.locale.clone(),
                    pointer: Some(rule.pointer.clone()),
                    validator: proof_application::LOCALIZED_CONTENT_VALIDATOR.to_owned(),
                    policy_digest: context_pack.policy_digest,
                });
            }
        }
    }
    findings.sort_by(|left, right| {
        (
            left.object_id,
            &left.locale,
            left.pointer.as_deref().unwrap_or_default(),
            left.edit_id,
        )
            .cmp(&(
                right.object_id,
                &right.locale,
                right.pointer.as_deref().unwrap_or_default(),
                right.edit_id,
            ))
    });
    let valid = findings.is_empty();
    let schema_digests = context_schema_digests(&context_pack)?;
    let manifest = validation_manifest(
        changeset_id,
        attempt,
        previous,
        proposal_digest,
        effective_leaf_digest,
        context_pack.context_pack_digest,
        context_pack.policy_digest,
        &schema_digests,
        &findings,
    )?;
    let validation_results_digest = digest(
        proof_application::ArtifactKind::ValidationResultsV2,
        &manifest,
    );
    let sealed_changeset_digest = valid
        .then(|| seal_digest(proposal_digest, validation_results_digest))
        .transpose()?;
    let findings_json = canonicalize(&Value::Array(findings_value(&findings)))
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO localized_validations (
                 changeset_id, attempt, previous_result_digest, proposal_digest,
                 effective_leaf_digest, policy_digest, validator, valid,
                 findings_json, results_json, results_digest, sealed_changeset_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                changeset_id.to_string(),
                i64::from(attempt),
                previous.map(|value| value.to_string()),
                proposal_digest.to_string(),
                effective_leaf_digest.to_string(),
                context_pack.policy_digest.to_string(),
                proof_application::LOCALIZED_CONTENT_VALIDATOR,
                i64::from(valid),
                findings_json.as_str(),
                manifest.as_str(),
                validation_results_digest.to_string(),
                sealed_changeset_digest.map(|value| value.to_string()),
            ],
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    transaction
        .execute(
            "UPDATE localized_changesets
             SET lifecycle_status = ?1, sealed_changeset_digest = ?2
             WHERE changeset_id = ?3 AND lifecycle_status = 'draft'",
            (
                if valid { "ready" } else { "draft" },
                sealed_changeset_digest.map(|value| value.to_string()),
                changeset_id.to_string(),
            ),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let result = proof_application::LocalizedValidation {
        changeset_id,
        attempt,
        previous_validation_result_digest: previous,
        proposal_digest,
        effective_leaf_digest,
        valid,
        findings,
        validation_results_digest,
        sealed_changeset_digest,
        status: if valid {
            ChangeSetStatus::Ready
        } else {
            ChangeSetStatus::Draft
        },
    };
    chain.push(result.clone());
    Ok(result)
}

fn load_policy_rules(
    transaction: &Transaction<'_>,
    context_pack_id: ContextPackId,
) -> Result<Vec<LocalizedPolicyRule>, LocalPortError> {
    let policy_json: String = transaction
        .query_row(
            "SELECT policy_json FROM localized_context_packs WHERE context_pack_id = ?1",
            [context_pack_id.to_string()],
            |row| row.get(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let value = parse_strict(policy_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| LocalPortError::Integrity("localized policy is not an object".to_owned()))?;
    if object.get("api_version").and_then(Value::as_str)
        != Some("proof.dev/localized-content-policy/v1")
    {
        return Err(LocalPortError::Integrity(
            "localized policy API version is invalid".to_owned(),
        ));
    }
    let rules = object
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            LocalPortError::Integrity("localized policy rules are missing".to_owned())
        })?;
    let mut parsed = Vec::with_capacity(rules.len());
    for rule in rules {
        let rule = rule.as_object().ok_or_else(|| {
            LocalPortError::Integrity("localized policy rule is invalid".to_owned())
        })?;
        let values = rule
            .get("disallowed_values")
            .and_then(Value::as_array)
            .ok_or_else(|| LocalPortError::Integrity("policy values are missing".to_owned()))?
            .iter()
            .map(|value| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    LocalPortError::Integrity("policy value is not a string".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        parsed.push(LocalizedPolicyRule {
            locale: proof_application::LocaleId::new(required_string(rule, "locale")?)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            pointer: required_string(rule, "pointer")?,
            disallowed_values: values,
        });
    }
    let normalized = normalized_policy_rules(&parsed)?;
    if normalized != parsed {
        return Err(LocalPortError::Integrity(
            "localized policy rules are not canonical".to_owned(),
        ));
    }
    Ok(parsed)
}

fn context_schema_digests(context: &LocalizedContextPack) -> Result<Vec<Value>, LocalPortError> {
    let manifest = parse_strict(context.manifest_json.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let resources = manifest
        .as_object()
        .and_then(|object| object.get("resources"))
        .and_then(Value::as_array)
        .ok_or_else(|| LocalPortError::Integrity("ContextPack resources are missing".to_owned()))?;
    let mut schemas = BTreeMap::<(String, u32), String>::new();
    for resource in resources {
        let schema = resource
            .as_object()
            .and_then(|object| object.get("schema"))
            .and_then(Value::as_object)
            .ok_or_else(|| LocalPortError::Integrity("ContextPack Schema is missing".to_owned()))?;
        let schema_id = required_string(schema, "schema_id")?;
        let version = schema
            .get("schema_version")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                LocalPortError::Integrity("ContextPack Schema version is invalid".to_owned())
            })?;
        let digest = required_string(schema, "document_digest")?;
        if let Some(existing) = schemas.insert((schema_id, version), digest.clone())
            && existing != digest
        {
            return Err(LocalPortError::Integrity(
                "ContextPack repeats one Schema identity with different bytes".to_owned(),
            ));
        }
    }
    Ok(schemas
        .into_iter()
        .map(|((schema_id, schema_version), document_digest)| {
            json!({
                "document_digest": document_digest,
                "schema_id": schema_id,
                "schema_version": schema_version,
            })
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn validation_manifest(
    changeset_id: ChangeSetId,
    attempt: u32,
    previous: Option<ContentDigest>,
    proposal_digest: ContentDigest,
    effective_leaf_digest: ContentDigest,
    context_pack_digest: ContentDigest,
    policy_digest: ContentDigest,
    schema_digests: &[Value],
    findings: &[proof_application::LocalizedFinding],
) -> Result<proof_canonical::CanonicalJson, LocalPortError> {
    canonicalize(&json!({
        "api_version": "proof.dev/validation-results/v2",
        "attempt": attempt,
        "changeset_id": changeset_id.to_string(),
        "context_pack_digest": context_pack_digest.to_string(),
        "effective_leaf_digest": effective_leaf_digest.to_string(),
        "findings": findings_value(findings),
        "policy_digest": policy_digest.to_string(),
        "previous_validation_result_digest": previous.map(|value| value.to_string()),
        "proposal_digest": proposal_digest.to_string(),
        "schema_digests": schema_digests,
        "valid": findings.is_empty(),
        "validator": proof_application::LOCALIZED_CONTENT_VALIDATOR,
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

fn findings_value(findings: &[proof_application::LocalizedFinding]) -> Vec<Value> {
    findings
        .iter()
        .map(|finding| {
            json!({
                "code": finding.code,
                "edit_id": finding.edit_id.to_string(),
                "locale": finding.locale.as_str(),
                "object_id": finding.object_id.to_string(),
                "pointer": finding.pointer,
                "policy_digest": finding.policy_digest.to_string(),
                "severity": match finding.severity {
                    proof_application::Severity::Info => "info",
                    proof_application::Severity::Warning => "warning",
                    proof_application::Severity::Error => "error",
                },
                "validator": finding.validator,
            })
        })
        .collect()
}

fn seal_digest(
    proposal_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ContentDigest, LocalPortError> {
    let seal = canonicalize(&json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": proposal_digest.to_string(),
        "validation_results_digest": validation_results_digest.to_string(),
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    Ok(digest(proof_application::ArtifactKind::ChangeSetV2, &seal))
}

#[allow(clippy::too_many_lines)]
fn load_validation_chain(
    transaction: &Transaction<'_>,
    changeset: &LocalizedChangeSet,
) -> Result<Vec<proof_application::LocalizedValidation>, LocalPortError> {
    type ValidationRow = (
        i64,
        Option<String>,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        String,
        Option<String>,
    );
    let context = load_context(
        transaction,
        changeset.workspace_id,
        changeset.context_pack_id,
    )?;
    let schema_digests = context_schema_digests(&context)?;
    let mut statement = transaction
        .prepare(
            "SELECT attempt, previous_result_digest, proposal_digest,
                    effective_leaf_digest, policy_digest, validator, valid,
                    findings_json, results_json, results_digest, sealed_changeset_digest
             FROM localized_validations WHERE changeset_id = ?1 ORDER BY attempt",
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([changeset.changeset_id.to_string()], |row| {
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
        .map_err(|error| LocalPortError::Storage(error.to_string()))?;
    let mut chain = Vec::new();
    for (index, row) in rows.enumerate() {
        let row: ValidationRow = row.map_err(|error| LocalPortError::Storage(error.to_string()))?;
        let attempt = u32::try_from(row.0)
            .map_err(|_| LocalPortError::Integrity("invalid validation attempt".to_owned()))?;
        if attempt != u32::try_from(index + 1).unwrap_or(u32::MAX) {
            return Err(LocalPortError::Integrity(
                "validation attempts are not contiguous".to_owned(),
            ));
        }
        let previous = parse_optional_digest(row.1.as_deref())?;
        if previous
            != chain
                .last()
                .map(|prior: &proof_application::LocalizedValidation| {
                    prior.validation_results_digest
                })
        {
            return Err(LocalPortError::Integrity(
                "validation result predecessor chain is broken".to_owned(),
            ));
        }
        let proposal_digest = row
            .2
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let effective_leaf_digest = row
            .3
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        let policy_digest = row
            .4
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if policy_digest != context.policy_digest
            || row.5 != proof_application::LOCALIZED_CONTENT_VALIDATOR
        {
            return Err(LocalPortError::Integrity(
                "validation policy or validator differs from ContextPack".to_owned(),
            ));
        }
        let valid = match row.6 {
            0 => false,
            1 => true,
            _ => {
                return Err(LocalPortError::Integrity(
                    "invalid validation result".to_owned(),
                ));
            }
        };
        let findings = parse_findings(&row.7)?;
        if valid != findings.is_empty() {
            return Err(LocalPortError::Integrity(
                "validation validity differs from findings".to_owned(),
            ));
        }
        let expected_manifest = validation_manifest(
            changeset.changeset_id,
            attempt,
            previous,
            proposal_digest,
            effective_leaf_digest,
            context.context_pack_digest,
            context.policy_digest,
            &schema_digests,
            &findings,
        )?;
        let result_digest = row
            .9
            .parse::<ContentDigest>()
            .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
        if expected_manifest.as_str() != row.8
            || digest(
                proof_application::ArtifactKind::ValidationResultsV2,
                &expected_manifest,
            ) != result_digest
        {
            return Err(LocalPortError::Integrity(
                "validation result artifact does not reproduce".to_owned(),
            ));
        }
        let sealed = parse_optional_digest(row.10.as_deref())?;
        let expected_seal = valid
            .then(|| seal_digest(proposal_digest, result_digest))
            .transpose()?;
        if sealed != expected_seal {
            return Err(LocalPortError::Integrity(
                "validation seal does not reproduce".to_owned(),
            ));
        }
        chain.push(proof_application::LocalizedValidation {
            changeset_id: changeset.changeset_id,
            attempt,
            previous_validation_result_digest: previous,
            proposal_digest,
            effective_leaf_digest,
            valid,
            findings,
            validation_results_digest: result_digest,
            sealed_changeset_digest: sealed,
            status: if valid {
                ChangeSetStatus::Ready
            } else {
                ChangeSetStatus::Draft
            },
        });
    }
    Ok(chain)
}

fn parse_findings(text: &str) -> Result<Vec<proof_application::LocalizedFinding>, LocalPortError> {
    let value = parse_strict(text.as_bytes())
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let canonical =
        canonicalize(&value).map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    if canonical.as_str() != text {
        return Err(LocalPortError::Integrity(
            "validation findings are not canonical".to_owned(),
        ));
    }
    let array = value.as_array().ok_or_else(|| {
        LocalPortError::Integrity("validation findings are not an array".to_owned())
    })?;
    let mut findings = Vec::with_capacity(array.len());
    for finding in array {
        let finding = finding
            .as_object()
            .ok_or_else(|| LocalPortError::Integrity("validation finding is invalid".to_owned()))?;
        let severity = match required_string(finding, "severity")?.as_str() {
            "info" => proof_application::Severity::Info,
            "warning" => proof_application::Severity::Warning,
            "error" => proof_application::Severity::Error,
            _ => {
                return Err(LocalPortError::Integrity(
                    "finding severity is invalid".to_owned(),
                ));
            }
        };
        findings.push(proof_application::LocalizedFinding {
            code: required_string(finding, "code")?,
            severity,
            edit_id: required_string(finding, "edit_id")?.parse().map_err(
                |error: proof_application::IdentifierError| {
                    LocalPortError::Integrity(error.to_string())
                },
            )?,
            object_id: required_string(finding, "object_id")?.parse().map_err(
                |error: proof_application::IdentifierError| {
                    LocalPortError::Integrity(error.to_string())
                },
            )?,
            locale: proof_application::LocaleId::new(required_string(finding, "locale")?)
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
            pointer: finding
                .get("pointer")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            validator: required_string(finding, "validator")?,
            policy_digest: required_string(finding, "policy_digest")?
                .parse::<ContentDigest>()
                .map_err(|error| LocalPortError::Integrity(error.to_string()))?,
        });
    }
    Ok(findings)
}
