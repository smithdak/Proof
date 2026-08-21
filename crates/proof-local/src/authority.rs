//! Local key and `SQLite` support for the ratified authenticated-authority profile.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD},
};
use proof_application::authority as contract;
use proof_application::{
    ArtifactKind, BuildContextPackCommand, ContentResourceIntent, ContextPackId, ContextPackLimits,
    DelegatedAction, EnvironmentId, LocaleId, ObjectId, PrincipalId, ReleasedLocaleTarget,
    ReleasedObjectQuery, SchemaId, Timestamp, WorkspaceId,
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{
        AuthorityPayloadProfile, parse_authority_envelope, sign_authority_payload,
        verify_authority_envelope,
    },
};
use proof_canonical::{canonicalize, digest, parse_strict};
use rusqlite::{Connection, OptionalExtension as _, Transaction, TransactionBehavior};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use zeroize::Zeroize as _;

use super::{
    LocalIdentity, LocalPortError, LocalWorkspace, authenticated_principal,
    build_context_pack_authorized_transaction, ensure_latest_schema, load_exact_released_objects,
    load_released_source, localized, reproducible_known_state, verify_commit_operation_scope,
};

pub(super) const AUTHORITY_SIGNING_KEY_RELATIVE_PATH: &str =
    ".proof/state/authority-signing.ed25519";
const AUTHORITY_SUCCESSOR_STAGING_KEY_RELATIVE_PATH: &str =
    ".proof/state/authority-successor.ed25519";
const UNKNOWN_BINDING_DUMMY_RECORD_JSON: &str = r#"{"algorithm":"ed25519","api_version":"proof.dev/principal-binding/v1","audience":"proof://workspace/019c0000-0000-7000-8000-000000000001","authenticated_subject":{"api_version":"proof.dev/authenticated-subject/v1","provider":"proof/local-ed25519","subject":"ed25519:707e8ff6e4bd4429a52a5687fd5ddad1023863aeb6ccdd61342295669ad567fc"},"authority_sequence":3,"binding_id":"019c0000-0000-7000-8000-000000000004","enrollment_challenge_digest":"blake3:67be6641b6f8838fb41158946c80ecb685445252d05b63dd88b04d280f3545e1","enrollment_envelope_digest":"blake3:9e14e11582aa0f9b94b1060832b6a09b52b81192fb215df5d0a590dfe0304653","expires_at":"2026-11-15T20:00:00Z","issued_at":"2026-08-17T20:00:00Z","issued_by_principal_id":"019c0000-0000-7000-8000-000000000002","key_usage":"authenticated-command","not_before":"2026-08-17T20:00:00Z","previous_authority_record_digest":"blake3:7d716637e7d7fda06b5c50965e7e3087dcbb16b50365b818c8b8a55f4bf39dd4","principal_id":"019c0000-0000-7000-8000-000000000003","principal_type":"agent","public_key":"cH6P9uS9RCmlKlaH/V3a0QI4Y662zN1hNCKVZprVZ/w=","supersedes_binding_id":null,"workspace_id":"019c0000-0000-7000-8000-000000000001"}"#;
const UNKNOWN_BINDING_DUMMY_RECORD_DIGEST: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

const V12_DATABASE_MIGRATION: &str = r"
CREATE TABLE workspace_authority_roots (
    authority_key_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ed25519'),
    key_file_relative_path TEXT NOT NULL,
    created_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    created_at TEXT NOT NULL,
    predecessor_authority_key_id TEXT REFERENCES workspace_authority_roots(authority_key_id),
    root_transition_envelope_digest TEXT,
    root_json TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    UNIQUE (workspace_id, public_key)
) STRICT;
CREATE UNIQUE INDEX workspace_active_authority_root
    ON workspace_authority_roots(workspace_id) WHERE active = 1;

CREATE TABLE authority_records (
    authority_sequence INTEGER PRIMARY KEY CHECK (authority_sequence > 0),
    workspace_id TEXT NOT NULL,
    previous_authority_record_digest TEXT,
    record_kind TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    envelope_json TEXT NOT NULL,
    envelope_digest TEXT NOT NULL UNIQUE,
    authority_key_id TEXT NOT NULL REFERENCES workspace_authority_roots(authority_key_id),
    recorded_at TEXT NOT NULL,
    CHECK (
        (authority_sequence = 1 AND previous_authority_record_digest IS NULL) OR
        (authority_sequence > 1 AND previous_authority_record_digest IS NOT NULL)
    )
) STRICT;

CREATE TABLE binding_enrollment_challenges (
    challenge_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    binding_id TEXT NOT NULL UNIQUE,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    candidate_key_id TEXT NOT NULL,
    issued_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    challenge_json TEXT NOT NULL,
    challenge_digest TEXT NOT NULL UNIQUE,
    enrollment_envelope_json TEXT,
    enrollment_envelope_digest TEXT UNIQUE,
    consumed_at TEXT
) STRICT;

CREATE TABLE principal_bindings_v1 (
    binding_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    authenticated_subject TEXT NOT NULL,
    public_key TEXT NOT NULL,
    audience TEXT NOT NULL,
    enrollment_challenge_digest TEXT NOT NULL,
    enrollment_envelope_digest TEXT NOT NULL,
    issued_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    issued_at TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    supersedes_binding_id TEXT REFERENCES principal_bindings_v1(binding_id),
    authority_sequence INTEGER NOT NULL UNIQUE REFERENCES authority_records(authority_sequence),
    record_digest TEXT NOT NULL UNIQUE,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    UNIQUE (workspace_id, binding_id)
) STRICT;
CREATE UNIQUE INDEX principal_binding_active_principal
    ON principal_bindings_v1(workspace_id, principal_id) WHERE active = 1;
CREATE UNIQUE INDEX principal_binding_historical_subject
    ON principal_bindings_v1(workspace_id, authenticated_subject);
CREATE UNIQUE INDEX principal_binding_historical_public_key
    ON principal_bindings_v1(workspace_id, public_key);

CREATE TABLE authenticated_subject_commitment_openings_v1 (
    workspace_id TEXT PRIMARY KEY,
    requesting_principal_id TEXT NOT NULL UNIQUE REFERENCES principals(principal_id),
    requesting_subject_provider TEXT NOT NULL CHECK (requesting_subject_provider = 'os/unix'),
    requesting_subject TEXT NOT NULL,
    blind TEXT NOT NULL,
    commitment_input_json TEXT NOT NULL,
    requesting_subject_commitment TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE principal_binding_revocations_v1 (
    revocation_id TEXT PRIMARY KEY,
    binding_id TEXT NOT NULL UNIQUE REFERENCES principal_bindings_v1(binding_id),
    workspace_id TEXT NOT NULL,
    revoked_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    revoked_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    authority_sequence INTEGER NOT NULL UNIQUE REFERENCES authority_records(authority_sequence),
    record_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE principal_status_v1 (
    principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    authority_sequence INTEGER PRIMARY KEY REFERENCES authority_records(authority_sequence),
    workspace_id TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('human', 'agent')),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    recorded_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    recorded_at TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    UNIQUE (principal_id, authority_sequence)
) STRICT;
CREATE INDEX principal_status_latest
    ON principal_status_v1(principal_id, authority_sequence DESC);

CREATE TABLE delegations_v2 (
    delegation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    issuer_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    recipient_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    delegation_profile TEXT NOT NULL CHECK (
        delegation_profile = 'proof.local/authority/direct/v1'
    ),
    actions_json TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    constraints_json TEXT NOT NULL,
    not_before TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    authority_sequence INTEGER NOT NULL UNIQUE REFERENCES authority_records(authority_sequence),
    record_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE delegation_revocations_v2 (
    revocation_id TEXT PRIMARY KEY,
    delegation_id TEXT NOT NULL UNIQUE REFERENCES delegations_v2(delegation_id),
    workspace_id TEXT NOT NULL,
    revoked_by_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    revoked_at TEXT NOT NULL,
    reason TEXT NOT NULL,
    authority_sequence INTEGER NOT NULL UNIQUE REFERENCES authority_records(authority_sequence),
    record_digest TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE authenticated_actor_context_evidence_v1 (
    presentation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    actor_context_digest TEXT NOT NULL UNIQUE,
    authenticated_at TEXT NOT NULL
) STRICT;

CREATE TABLE authorization_decisions_v2 (
    authority_sequence INTEGER PRIMARY KEY REFERENCES authority_records(authority_sequence),
    presentation_id TEXT NOT NULL UNIQUE,
    workspace_id TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    command_envelope_digest TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operating_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    binding_id TEXT NOT NULL REFERENCES principal_bindings_v1(binding_id),
    delegation_id TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    requested_action TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason_code TEXT,
    evaluated_at TEXT NOT NULL,
    decision_json TEXT NOT NULL,
    decision_digest TEXT NOT NULL UNIQUE,
    CHECK (
        (decision = 'allow' AND reason_code IS NULL) OR
        (decision = 'deny' AND reason_code IS NOT NULL)
    )
) STRICT;

CREATE TABLE presentation_consumptions_v1 (
    presentation_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    command_envelope_digest TEXT NOT NULL,
    decision_authority_sequence INTEGER NOT NULL UNIQUE
        REFERENCES authorization_decisions_v2(authority_sequence),
    consumed_at TEXT NOT NULL
) STRICT;

CREATE TABLE authenticated_operation_results_v1 (
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL,
    operating_principal_id TEXT NOT NULL,
    delegation_id TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    PRIMARY KEY (workspace_id, idempotency_key)
) STRICT;

INSERT INTO schema_migrations (version, name)
VALUES (12, 'authenticated-authorization-kernel');
UPDATE workspace_metadata SET schema_version = 12 WHERE singleton = 1;
PRAGMA user_version = 12;
";

const V13_DATABASE_MIGRATION: &str = r"
CREATE TABLE authenticated_localized_consequences_v1 (
    decision_authority_sequence INTEGER PRIMARY KEY
        REFERENCES authorization_decisions_v2(authority_sequence),
    presentation_id TEXT NOT NULL UNIQUE
        REFERENCES presentation_consumptions_v1(presentation_id),
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operating_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    delegation_id TEXT NOT NULL REFERENCES delegations_v2(delegation_id),
    command_digest TEXT NOT NULL,
    authorization_decision_digest TEXT NOT NULL UNIQUE
        REFERENCES authorization_decisions_v2(decision_digest),
    operation_name TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    application_idempotency_kind TEXT NOT NULL CHECK (
        application_idempotency_kind IN ('none', 'required', 'derived')
    ),
    application_idempotency_key TEXT,
    result_kind TEXT NOT NULL CHECK (result_kind IN ('success', 'failure')),
    result_contract TEXT NOT NULL,
    result_json TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    application_effect_digest TEXT NOT NULL,
    application_consequence_digest TEXT NOT NULL,
    selectors_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evidence_digest TEXT NOT NULL UNIQUE,
    CHECK (
        (application_idempotency_kind = 'none' AND application_idempotency_key IS NULL) OR
        (application_idempotency_kind = 'required' AND
         application_idempotency_key IS NOT NULL) OR
        (application_idempotency_kind = 'derived' AND
         (result_kind = 'failure' OR application_idempotency_key IS NOT NULL))
    )
) STRICT;

CREATE TABLE authenticated_application_idempotency_v1 (
    workspace_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    idempotency_kind TEXT NOT NULL CHECK (idempotency_kind IN ('required', 'derived')),
    operation_name TEXT NOT NULL,
    operation_version TEXT NOT NULL,
    command_digest TEXT NOT NULL,
    result_digest TEXT NOT NULL,
    application_effect_digest TEXT NOT NULL,
    application_consequence_digest TEXT NOT NULL,
    first_decision_authority_sequence INTEGER NOT NULL UNIQUE
        REFERENCES authorization_decisions_v2(authority_sequence),
    PRIMARY KEY (workspace_id, idempotency_key)
) STRICT;

INSERT INTO schema_migrations (version, name)
VALUES (13, 'authenticated-localized-consequences');
UPDATE workspace_metadata SET schema_version = 13 WHERE singleton = 1;
PRAGMA user_version = 13;
";

const V12_CONTEXT_PACK_DELEGATION_MIGRATION: &str = r"
ALTER TABLE context_pack_build_operations
    RENAME TO context_pack_build_operations_v11;
ALTER TABLE context_packs RENAME TO context_packs_v11;

CREATE TABLE context_packs (
    context_pack_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    operating_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    delegation_id TEXT NOT NULL,
    environment_id TEXT NOT NULL REFERENCES environments(environment_id),
    release_id TEXT NOT NULL REFERENCES releases(release_id),
    edition_id TEXT NOT NULL REFERENCES editions(edition_id),
    object_ids_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    context_pack_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;
INSERT INTO context_packs
SELECT * FROM context_packs_v11;

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
INSERT INTO context_pack_build_operations
SELECT * FROM context_pack_build_operations_v11;

DROP TABLE context_pack_build_operations_v11;
DROP TABLE context_packs_v11;
";

pub(super) fn migrate_schema_v12(transaction: &Transaction<'_>) -> Result<(), String> {
    migrate_context_pack_delegation_reference(transaction)?;
    transaction
        .execute_batch(V12_DATABASE_MIGRATION)
        .map_err(|error| error.to_string())
}

pub(super) fn migrate_schema_v13(transaction: &Transaction<'_>) -> Result<(), String> {
    transaction
        .execute_batch(V13_DATABASE_MIGRATION)
        .map_err(|error| error.to_string())
}

fn migrate_context_pack_delegation_reference(transaction: &Transaction<'_>) -> Result<(), String> {
    let context_pack_exists = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'context_packs'
             )",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| error.to_string())?;
    if !context_pack_exists {
        return Ok(());
    }
    let mut foreign_keys = transaction
        .prepare("PRAGMA foreign_key_list(context_packs)")
        .map_err(|error| error.to_string())?;
    let legacy_delegation_reference = foreign_keys
        .query_map([], |row| {
            Ok((row.get::<_, String>(2)?, row.get::<_, String>(3)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
        .into_iter()
        .any(|(table, column)| table == "delegations" && column == "delegation_id");
    drop(foreign_keys);
    if legacy_delegation_reference {
        transaction
            .execute_batch(V12_CONTEXT_PACK_DELEGATION_MIGRATION)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "bootstrap atomically creates the root, first signed status, its exact projections, and the one private Human opening"
)]
pub(super) fn bootstrap_authority(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    created_at: Timestamp,
    signer: &Ed25519SigningProvider,
    local_identity: &LocalIdentity,
    subject_commitment_blind: [u8; 32],
) -> Result<(), String> {
    let root_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM workspace_authority_roots WHERE workspace_id = ?1",
            [workspace_id.to_string()],
            |row| row.get::<_, u32>(0),
        )
        .map_err(|error| error.to_string())?;
    if root_count != 0 {
        verify_bootstrapped_authority(transaction, workspace_id, bootstrap_principal_id, signer)?;
        return verify_subject_commitment_opening(
            transaction,
            workspace_id,
            bootstrap_principal_id,
            local_identity,
        )
        .map(|_| ())
        .map_err(|error| error.to_string());
    }

    let metadata = signer.metadata().map_err(|error| error.to_string())?;
    let root = json!({
        "api_version": "proof.dev/workspace-authority-root/v1",
        "workspace_id": workspace_id.to_string(),
        "authority_key_id": metadata.key_id.clone(),
        "public_key": BASE64.encode(&metadata.public_key),
        "algorithm": "ed25519",
        "created_by_principal_id": bootstrap_principal_id.to_string(),
        "created_at": created_at.to_string(),
        "predecessor_authority_key_id": null,
        "root_transition_envelope_digest": null,
    });
    let root_json = canonicalize(&root).map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO workspace_authority_roots (
                 authority_key_id, workspace_id, public_key, algorithm,
                 key_file_relative_path, created_by_principal_id, created_at,
                 predecessor_authority_key_id, root_transition_envelope_digest,
                 root_json, active
             ) VALUES (?1, ?2, ?3, 'ed25519', ?4, ?5, ?6, NULL, NULL, ?7, 1)",
            (
                &metadata.key_id,
                workspace_id.to_string(),
                BASE64.encode(&metadata.public_key),
                AUTHORITY_SIGNING_KEY_RELATIVE_PATH,
                bootstrap_principal_id.to_string(),
                created_at.to_string(),
                root_json.as_str(),
            ),
        )
        .map_err(|error| error.to_string())?;

    let status = json!({
        "api_version": "proof.dev/principal-status/v1",
        "authority_sequence": 1,
        "previous_authority_record_digest": null,
        "workspace_id": workspace_id.to_string(),
        "principal_id": bootstrap_principal_id.to_string(),
        "principal_type": "human",
        "enabled": true,
        "recorded_by_principal_id": bootstrap_principal_id.to_string(),
        "recorded_at": created_at.to_string(),
    });
    let signed_record =
        sign_authority_payload(AuthorityPayloadProfile::AuthorityRecord, &status, &[signer])
            .map_err(|error| error.to_string())?;
    let record_json = canonicalize(&status).map_err(|error| error.to_string())?;
    let record_digest = digest(ArtifactKind::AuthorityRecordV1, &record_json);
    transaction
        .execute(
            "INSERT INTO authority_records (
                 authority_sequence, workspace_id, previous_authority_record_digest,
                 record_kind, record_json, record_digest, envelope_json,
                 envelope_digest, authority_key_id, recorded_at
             ) VALUES (1, ?1, NULL, 'principal_status', ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                workspace_id.to_string(),
                signed_record.payload_json,
                record_digest.to_string(),
                signed_record.envelope_json,
                signed_record.envelope_digest.to_string(),
                &metadata.key_id,
                created_at.to_string(),
            ),
        )
        .map_err(|error| error.to_string())?;
    transaction
        .execute(
            "INSERT INTO principal_status_v1 (
                 principal_id, authority_sequence, workspace_id, principal_type,
                 enabled, recorded_by_principal_id, recorded_at, record_digest
             ) VALUES (?1, 1, ?2, 'human', 1, ?1, ?3, ?4)",
            (
                bootstrap_principal_id.to_string(),
                workspace_id.to_string(),
                created_at.to_string(),
                record_digest.to_string(),
            ),
        )
        .map_err(|error| error.to_string())?;
    insert_subject_commitment_opening(
        transaction,
        workspace_id,
        bootstrap_principal_id,
        local_identity,
        subject_commitment_blind,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn verify_bootstrapped_authority(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    signer: &Ed25519SigningProvider,
) -> Result<(), String> {
    let metadata = signer.metadata().map_err(|error| error.to_string())?;
    let (stored_workspace, stored_public_key, stored_creator, active): (
        String,
        String,
        String,
        i64,
    ) = transaction
        .query_row(
            "SELECT workspace_id, public_key, created_by_principal_id, active
             FROM workspace_authority_roots WHERE authority_key_id = ?1",
            [&metadata.key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|error| error.to_string())?;
    if stored_workspace != workspace_id.to_string()
        || stored_public_key != BASE64.encode(&metadata.public_key)
        || stored_creator != bootstrap_principal_id.to_string()
        || active != 1
    {
        return Err("local authority root and signing key disagree".to_owned());
    }
    let status_count = transaction
        .query_row(
            "SELECT COUNT(*) FROM principal_status_v1
             WHERE workspace_id = ?1 AND principal_id = ?2
               AND principal_type = 'human' AND enabled = 1",
            (workspace_id.to_string(), bootstrap_principal_id.to_string()),
            |row| row.get::<_, u32>(0),
        )
        .map_err(|error| error.to_string())?;
    if status_count != 1 {
        return Err("bootstrap Human authority status is missing or ambiguous".to_owned());
    }
    Ok(())
}

pub(super) fn load_or_create_authority_signer(
    workspace_root: &Path,
    temporary_token: &str,
) -> Result<Ed25519SigningProvider, String> {
    let path = workspace_root.join(AUTHORITY_SIGNING_KEY_RELATIVE_PATH);
    match fs::symlink_metadata(&path) {
        Ok(metadata) => read_authority_signer(&path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let provider = Ed25519SigningProvider::generate().map_err(|error| error.to_string())?;
            let mut secret = provider.secret_bytes();
            let temporary =
                path.with_file_name(format!(".authority-signing-{temporary_token}.tmp"));
            match fs::symlink_metadata(&temporary) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    secret.zeroize();
                    return Err(
                        "authority signing-key temporary path is not a regular file".to_owned()
                    );
                }
                Ok(_) => {
                    if let Err(error) = fs::remove_file(&temporary) {
                        secret.zeroize();
                        return Err(error.to_string());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    secret.zeroize();
                    return Err(error.to_string());
                }
            }

            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = match options.open(&temporary) {
                Ok(file) => file,
                Err(error) => {
                    secret.zeroize();
                    return Err(error.to_string());
                }
            };
            let write_result = file.write_all(&secret).and_then(|()| file.sync_all());
            secret.zeroize();
            if let Err(error) = write_result {
                drop(file);
                let _ = fs::remove_file(&temporary);
                return Err(error.to_string());
            }
            drop(file);
            match fs::hard_link(&temporary, &path) {
                Ok(()) => {
                    fs::remove_file(&temporary).map_err(|error| error.to_string())?;
                    sync_parent_directory(&path).map_err(|error| error.to_string())?;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    fs::remove_file(&temporary).map_err(|error| error.to_string())?;
                    let metadata =
                        fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
                    return read_authority_signer(&path, &metadata);
                }
                Err(error) => {
                    let _ = fs::remove_file(&temporary);
                    return Err(error.to_string());
                }
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            validate_authority_key_metadata(&metadata)?;
            Ok(provider)
        }
        Err(error) => Err(error.to_string()),
    }
}

fn load_existing_authority_signer(
    workspace_root: &Path,
    relative_path: &str,
) -> Result<Ed25519SigningProvider, contract::AuthorityError> {
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authority key path escapes the Workspace".to_owned(),
        ));
    }
    let path = workspace_root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)?;
    read_authority_signer(&path, &metadata)
        .map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)
}

fn read_authority_signer(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Ed25519SigningProvider, String> {
    validate_authority_key_metadata(metadata)?;
    let mut bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err("local authority signing key must contain exactly 32 bytes".to_owned());
    }
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&bytes);
    bytes.zeroize();
    let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
    secret.zeroize();
    Ok(provider)
}

fn validate_authority_key_metadata(metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("local authority signing key is not a regular file".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "local authority signing key permissions must be 0600 or stricter".to_owned(),
            );
        }
    }
    Ok(())
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

impl LocalWorkspace {
    fn with_authority_transaction<T>(
        &self,
        operation: impl FnOnce(
            &Transaction<'_>,
            WorkspaceId,
            PrincipalId,
            &LocalIdentity,
            &Ed25519SigningProvider,
            Timestamp,
        ) -> Result<T, contract::AuthorityError>,
    ) -> Result<T, contract::AuthorityError> {
        let config = self
            .read_config()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let local_identity = self
            .resolved_local_identity()
            .map_err(|_| contract::AuthorityError::AuthDenied)?;
        let trusted_at = self
            .resolved_local_timestamp()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let mut connection = self
            .open_database()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let (database_workspace_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                 FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if database_workspace_id != workspace_id.to_string() {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let bootstrap_principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(authority_from_workspace_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(|error| match error {
            super::LatestSchemaError::Integrity(detail) => {
                contract::AuthorityError::AuthorityIntegrity(detail)
            }
            super::LatestSchemaError::Storage(detail) => contract::AuthorityError::Storage(detail),
        })?;
        let signer = self.authority_signer_for_transaction(
            &transaction,
            workspace_id,
            bootstrap_principal_id,
        )?;
        verify_authority_log(&transaction, workspace_id)?;
        let result = operation(
            &transaction,
            workspace_id,
            bootstrap_principal_id,
            &local_identity,
            &signer,
            trusted_at,
        )?;
        transaction
            .commit()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        Ok(result)
    }

    fn authority_signer_for_transaction(
        &self,
        transaction: &Transaction<'_>,
        workspace_id: WorkspaceId,
        bootstrap_principal_id: PrincipalId,
    ) -> Result<Ed25519SigningProvider, contract::AuthorityError> {
        let root_count = transaction
            .query_row(
                "SELECT COUNT(*) FROM workspace_authority_roots WHERE workspace_id = ?1",
                [workspace_id.to_string()],
                |row| row.get::<_, u32>(0),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if root_count == 0 {
            let signer = load_or_create_authority_signer(&self.root, &workspace_id.to_string())
                .map_err(contract::AuthorityError::Signing)?;
            let created_at = self
                .resolved_local_timestamp()
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            let local_identity = self
                .resolved_local_identity()
                .map_err(|_| contract::AuthorityError::AuthDenied)?;
            let subject_commitment_blind = self
                .resolved_subject_commitment_blind()
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            bootstrap_authority(
                transaction,
                workspace_id,
                bootstrap_principal_id,
                created_at,
                &signer,
                &local_identity,
                subject_commitment_blind,
            )
            .map_err(contract::AuthorityError::AuthorityIntegrity)?;
            return Ok(signer);
        }
        let (active_key_id, key_path): (String, String) = transaction
            .query_row(
                "SELECT authority_key_id, key_file_relative_path
                 FROM workspace_authority_roots
                 WHERE workspace_id = ?1 AND active = 1",
                [workspace_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)?;
        let signer = load_existing_authority_signer(&self.root, &key_path)?;
        let signer_key_id = signer
            .metadata()
            .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?
            .key_id;
        if signer_key_id != active_key_id {
            return Err(contract::AuthorityError::AuthorityRootUnavailable);
        }
        Ok(signer)
    }

    fn with_authority_consumption_transaction<T>(
        &self,
        operation: impl FnOnce(
            &Transaction<'_>,
            WorkspaceId,
            PrincipalId,
            &LocalIdentity,
            &Ed25519SigningProvider,
        )
            -> Result<Result<T, contract::AuthorityError>, contract::AuthorityError>,
    ) -> Result<T, contract::AuthorityError> {
        let config = self
            .read_config()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let local_identity = self
            .resolved_local_identity()
            .map_err(|_| contract::AuthorityError::AuthDenied)?;
        let mut connection = self
            .open_database()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let (database_workspace_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                 FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if database_workspace_id != workspace_id.to_string() {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let bootstrap_principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(authority_from_workspace_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(|error| match error {
            super::LatestSchemaError::Integrity(detail) => {
                contract::AuthorityError::AuthorityIntegrity(detail)
            }
            super::LatestSchemaError::Storage(detail) => contract::AuthorityError::Storage(detail),
        })?;
        let signer = self.authority_signer_for_transaction(
            &transaction,
            workspace_id,
            bootstrap_principal_id,
        )?;
        verify_authority_log(&transaction, workspace_id)?;
        let outcome = operation(
            &transaction,
            workspace_id,
            bootstrap_principal_id,
            &local_identity,
            &signer,
        )?;
        transaction
            .commit()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        outcome
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the atomic executor keeps authentication, current authorization, consequence, and durable decision ordering visible"
    )]
    fn execute_authenticated_at(
        &self,
        invocation: contract::AuthenticatedInvocationV1,
        evaluated_at: Timestamp,
        authenticated_at: Timestamp,
    ) -> Result<contract::AuthenticatedExecutionV1, contract::AuthorityError> {
        invocation
            .command_input
            .validate_for_authenticated_execution()
            .map_err(|_| contract::AuthorityError::AuthMalformed)?;
        let command_value = serde_json::to_value(&invocation.command_input)
            .map_err(|_| contract::AuthorityError::AuthMalformed)?;
        let canonical_command =
            canonicalize(&command_value).map_err(|_| contract::AuthorityError::AuthMalformed)?;
        let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);
        let parsed = parse_authority_envelope::<contract::AuthenticatedCommandV1>(
            invocation.authentication.as_str().as_bytes(),
            AuthorityPayloadProfile::AuthenticatedCommand,
        )
        .map_err(|_| contract::AuthorityError::AuthMalformed)?;
        let command_input = invocation.command_input;

        let execution = self.with_authority_consumption_transaction(
            move |transaction, workspace_id, bootstrap_principal_id, local_identity, signer| {
                let presentation = verify_authenticated_presentation(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    local_identity,
                    &command_input,
                    &parsed,
                    command_digest,
                    evaluated_at,
                    authenticated_at,
                )?;
                let mut assessment = assess_authorization(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    &presentation,
                    evaluated_at,
                )?;
                if assessment.denial.is_none() {
                    apply_application_idempotency_denial(
                        transaction,
                        workspace_id,
                        &presentation,
                        &mut assessment,
                    )?;
                }

                if let Some((_, denial)) = assessment.denial.clone() {
                    let prepared = prepare_authorization_decision(
                        transaction,
                        workspace_id,
                        signer,
                        &presentation,
                        &assessment,
                        evaluated_at,
                        None,
                    )?;
                    persist_authorization_decision(
                        transaction,
                        workspace_id,
                        &presentation,
                        &prepared,
                    )?;
                    verify_authority_log(transaction, workspace_id)?;
                    return Ok(Err(denial));
                }

                let localized_operation =
                    contract::authority_operation_entry(presentation.command.operation)
                        .localized_contract
                        .is_some();
                let mut prepared = if localized_operation {
                    None
                } else {
                    Some(prepare_authorization_decision(
                        transaction,
                        workspace_id,
                        signer,
                        &presentation,
                        &assessment,
                        evaluated_at,
                        None,
                    )?)
                };
                transaction
                    .execute_batch("SAVEPOINT authenticated_authorized_consequence")
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                let consequence = if localized_operation {
                    execute_localized_consequence(
                        self,
                        transaction,
                        workspace_id,
                        &presentation,
                        &assessment,
                    )
                } else {
                    execute_authorized_consequence(
                        self,
                        transaction,
                        workspace_id,
                        &presentation,
                        &assessment,
                        prepared
                            .as_ref()
                            .ok_or_else(|| {
                                contract::AuthorityError::AuthorityIntegrity(
                                    "legacy consequence has no prepared decision".to_owned(),
                                )
                            })?
                            .record_digest,
                        evaluated_at,
                    )
                };
                let result = match consequence {
                    Ok(result) => {
                        if matches!(
                            &result,
                            contract::AuthenticatedOperationResultV1::Failure(_)
                                | contract::AuthenticatedOperationResultV1::LocalizedFailure(_)
                        ) {
                            transaction
                                .execute_batch(
                                    "ROLLBACK TO authenticated_authorized_consequence;
                                     RELEASE authenticated_authorized_consequence",
                                )
                                .map_err(|error| {
                                    contract::AuthorityError::Storage(error.to_string())
                                })?;
                        } else {
                            transaction
                                .execute_batch("RELEASE authenticated_authorized_consequence")
                                .map_err(|error| {
                                    contract::AuthorityError::Storage(error.to_string())
                                })?;
                        }
                        result
                    }
                    Err(error @ contract::AuthorityError::IdempotencyKeyReused) => {
                        transaction
                            .execute_batch(
                                "ROLLBACK TO authenticated_authorized_consequence;
                                 RELEASE authenticated_authorized_consequence",
                            )
                            .map_err(|rollback_error| {
                                contract::AuthorityError::Storage(rollback_error.to_string())
                            })?;
                        assessment.denial = Some((
                            contract::AuthorizationDenialReason::IdempotencyKeyReused,
                            error.clone(),
                        ));
                        let denial = prepare_authorization_decision(
                            transaction,
                            workspace_id,
                            signer,
                            &presentation,
                            &assessment,
                            evaluated_at,
                            None,
                        )?;
                        persist_authorization_decision(
                            transaction,
                            workspace_id,
                            &presentation,
                            &denial,
                        )?;
                        verify_authority_log(transaction, workspace_id)?;
                        return Ok(Err(error));
                    }
                    Err(error) => {
                        transaction
                            .execute_batch(
                                "ROLLBACK TO authenticated_authorized_consequence;
                                 RELEASE authenticated_authorized_consequence",
                            )
                            .map_err(|rollback_error| {
                                contract::AuthorityError::Storage(rollback_error.to_string())
                            })?;
                        return Err(error);
                    }
                };
                let localized_result_evidence = localized_operation
                    .then(|| {
                        localized_result_evidence(
                            transaction,
                            workspace_id,
                            &presentation,
                            &assessment,
                            &result,
                        )
                    })
                    .transpose()?;
                if prepared.is_none() {
                    let commitment = localized_result_evidence
                        .as_ref()
                        .ok_or_else(|| {
                            contract::AuthorityError::AuthorityIntegrity(
                                "localized consequence lost its result evidence".to_owned(),
                            )
                        })?
                        .commitment(presentation.command.operation)?;
                    prepared = Some(prepare_authorization_decision(
                        transaction,
                        workspace_id,
                        signer,
                        &presentation,
                        &assessment,
                        evaluated_at,
                        Some(commitment),
                    )?);
                }
                let prepared = prepared.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "authorized consequence has no signed decision".to_owned(),
                    )
                })?;
                let execution = contract::AuthenticatedExecutionV1 {
                    command_input,
                    actor_context: presentation.actor_context.clone(),
                    actor_context_evidence: presentation.actor_context_evidence.clone(),
                    actor_context_digest: presentation.actor_context_digest,
                    decision: prepared.decision.clone(),
                    decision_record_digest: prepared.record_digest,
                    decision_envelope_digest: prepared.envelope_digest,
                    result,
                };
                execution.validate().map_err(contract_integrity)?;
                persist_authorization_decision(
                    transaction,
                    workspace_id,
                    &presentation,
                    &prepared,
                )?;
                if matches!(
                    &execution.result,
                    contract::AuthenticatedOperationResultV1::LocalizedSuccess(_)
                        | contract::AuthenticatedOperationResultV1::LocalizedFailure(_)
                ) {
                    persist_authenticated_localized_consequence(
                        transaction,
                        workspace_id,
                        &presentation,
                        &assessment,
                        &prepared,
                        localized_result_evidence.as_ref().ok_or_else(|| {
                            contract::AuthorityError::AuthorityIntegrity(
                                "localized consequence lost its signed result evidence".to_owned(),
                            )
                        })?,
                    )?;
                }
                verify_authority_log(transaction, workspace_id)?;
                Ok(Ok(execution))
            },
        )?;
        if let contract::AuthenticatedOperationResultV1::LocalizedSuccess(
            contract::LocalizedOperationSuccessV1::ReleaseCreated(release),
        ) = &execution.result
        {
            let _ = localized::materialize_localized_release_proof(self, release);
        }
        Ok(execution)
    }
}

impl contract::AuthenticatedAuthorityExecutor for LocalWorkspace {
    fn execute_authenticated(
        &self,
        invocation: contract::AuthenticatedInvocationV1,
        evaluated_at: Timestamp,
    ) -> Result<contract::AuthenticatedExecutionV1, contract::AuthorityError> {
        let authenticated_at = self
            .resolved_local_timestamp()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        self.execute_authenticated_at(invocation, evaluated_at, authenticated_at)
    }
}

fn authority_from_workspace_status(
    error: proof_application::WorkspaceStatusError,
) -> contract::AuthorityError {
    match error {
        proof_application::WorkspaceStatusError::Unauthenticated => {
            contract::AuthorityError::AuthDenied
        }
        proof_application::WorkspaceStatusError::Integrity(detail) => {
            contract::AuthorityError::AuthorityIntegrity(detail)
        }
        proof_application::WorkspaceStatusError::Storage(detail) => {
            contract::AuthorityError::Storage(detail)
        }
        proof_application::WorkspaceStatusError::Incomplete => {
            contract::AuthorityError::AuthorityIntegrity(
                "the selected Workspace has incomplete state".to_owned(),
            )
        }
    }
}

fn decode_canonical<T: DeserializeOwned>(
    input: &str,
    label: &str,
) -> Result<T, contract::AuthorityError> {
    let value = parse_strict(input.as_bytes()).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
    })?;
    let canonical = canonicalize(&value).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
    })?;
    if canonical.as_str() != input {
        return Err(contract::AuthorityError::AuthorityIntegrity(format!(
            "stored {label} is not canonical"
        )));
    }
    serde_json::from_value(value).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
    })
}

#[expect(
    clippy::explicit_counter_loop,
    clippy::single_match_else,
    clippy::too_many_lines,
    reason = "one linear verifier keeps the explicit causal counter and root-transition branch visible"
)]
fn verify_authority_log(
    transaction: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), contract::AuthorityError> {
    let initial_key_id = transaction
        .query_row(
            "SELECT authority_key_id FROM workspace_authority_roots
             WHERE workspace_id = ?1 AND predecessor_authority_key_id IS NULL",
            [workspace_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let initial_key_id_for_projection = initial_key_id.clone();
    let mut current_key_id = initial_key_id;
    let mut expected_sequence = 1_u64;
    let mut previous_digest: Option<String> = None;
    let mut verified_records = Vec::new();
    let mut statement = transaction
        .prepare(
            "SELECT authority_sequence, previous_authority_record_digest, record_json,
                    record_digest, envelope_json, envelope_digest, authority_key_id,
                    record_kind, recorded_at
             FROM authority_records WHERE workspace_id = ?1
             ORDER BY authority_sequence",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([workspace_id.to_string()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    drop(statement);

    for (
        sequence,
        stored_previous,
        record_json,
        stored_digest,
        envelope_json,
        envelope_digest,
        signer_key_id,
        stored_record_kind,
        stored_recorded_at,
    ) in rows
    {
        let sequence = u64::try_from(sequence).map_err(|_| {
            contract::AuthorityError::AuthorityIntegrity(
                "authority sequence is negative or out of range".to_owned(),
            )
        })?;
        if sequence != expected_sequence || stored_previous != previous_digest {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authority record sequence or predecessor digest is discontinuous".to_owned(),
            ));
        }
        let record: contract::AuthorityRecordV1 =
            decode_canonical(&record_json, "authority record")?;
        if record.authority_sequence().get() != sequence || record.workspace_id() != workspace_id {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authority record typed identity disagrees with storage".to_owned(),
            ));
        }
        if stored_record_kind != authority_record_kind(&record)
            || stored_recorded_at != record_time(&record).to_string()
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authority record kind or timestamp disagrees with its signed payload".to_owned(),
            ));
        }
        let record_value = parse_strict(record_json.as_bytes())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let canonical_record = canonicalize(&record_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let computed_digest = digest(ArtifactKind::AuthorityRecordV1, &canonical_record);
        if computed_digest.to_string() != stored_digest {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authority record digest disagrees with canonical bytes".to_owned(),
            ));
        }

        match &record {
            contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(transition) => {
                transition.validate().map_err(|error| {
                    contract::AuthorityError::AuthorityIntegrity(error.to_string())
                })?;
                if transition.predecessor_authority_key_id.as_str() != current_key_id
                    || signer_key_id != current_key_id
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority root transition predecessor disagrees with causal state"
                            .to_owned(),
                    ));
                }
                let verified = verify_authority_envelope::<
                    contract::WorkspaceAuthorityRootTransitionV1,
                >(
                    envelope_json.as_bytes(),
                    AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                    &[
                        current_key_id.as_str(),
                        transition.successor_authority_key_id.as_str(),
                    ],
                )
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
                if verified.parsed.payload != *transition
                    || verified.parsed.payload_json != record_json
                    || verified.parsed.envelope_digest.to_string() != envelope_digest
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority root transition envelope disagrees with stored record"
                            .to_owned(),
                    ));
                }
                let successor_count = transaction
                    .query_row(
                        "SELECT COUNT(*) FROM workspace_authority_roots
                         WHERE workspace_id = ?1 AND authority_key_id = ?2
                           AND predecessor_authority_key_id = ?3
                           AND root_transition_envelope_digest = ?4",
                        (
                            workspace_id.to_string(),
                            transition.successor_authority_key_id.as_str(),
                            current_key_id.as_str(),
                            envelope_digest.as_str(),
                        ),
                        |row| row.get::<_, u32>(0),
                    )
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                if successor_count != 1 {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority successor root metadata is missing or ambiguous".to_owned(),
                    ));
                }
                current_key_id = transition.successor_authority_key_id.to_string();
            }
            _ => {
                if signer_key_id != current_key_id {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority record signer disagrees with causal root".to_owned(),
                    ));
                }
                let verified = verify_authority_envelope::<contract::AuthorityRecordV1>(
                    envelope_json.as_bytes(),
                    AuthorityPayloadProfile::AuthorityRecord,
                    &[current_key_id.as_str()],
                )
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
                if verified.parsed.payload != record
                    || verified.parsed.payload_json != record_json
                    || verified.parsed.envelope_digest.to_string() != envelope_digest
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority envelope disagrees with stored record".to_owned(),
                    ));
                }
            }
        }
        verified_records.push(VerifiedAuthorityProjectionRecord {
            record,
            record_digest: stored_digest.clone(),
            envelope_digest,
        });
        previous_digest = Some(stored_digest);
        expected_sequence += 1;
    }
    if previous_digest.is_none() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authority log has no bootstrap record".to_owned(),
        ));
    }
    let active_key_id = transaction
        .query_row(
            "SELECT authority_key_id FROM workspace_authority_roots
             WHERE workspace_id = ?1 AND active = 1",
            [workspace_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if active_key_id != current_key_id {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "active authority root does not match the verified log head".to_owned(),
        ));
    }
    verify_authority_projections(
        transaction,
        workspace_id,
        &initial_key_id_for_projection,
        &current_key_id,
        &verified_records,
    )
}

struct VerifiedAuthorityProjectionRecord {
    record: contract::AuthorityRecordV1,
    record_digest: String,
    envelope_digest: String,
}

#[derive(Clone)]
struct BindingProjectionExpectation {
    binding: contract::PrincipalBindingV1,
    record_digest: String,
    active: bool,
}

fn projection_row_key(value: &serde_json::Value) -> Result<String, contract::AuthorityError> {
    canonicalize(value)
        .map(|canonical| canonical.as_str().to_owned())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
}

fn verify_projection_row_set(
    label: &str,
    expected: &[serde_json::Value],
    actual: &[serde_json::Value],
) -> Result<(), contract::AuthorityError> {
    let mut expected = expected
        .iter()
        .map(projection_row_key)
        .collect::<Result<Vec<_>, _>>()?;
    let mut actual = actual
        .iter()
        .map(projection_row_key)
        .collect::<Result<Vec<_>, _>>()?;
    expected.sort();
    actual.sort();
    if expected == actual {
        Ok(())
    } else {
        Err(contract::AuthorityError::AuthorityIntegrity(format!(
            "{label} does not exactly reproduce the signed authority log"
        )))
    }
}

fn query_projection_rows(
    connection: &Connection,
    sql: &str,
    mut project: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<serde_json::Value>,
) -> Result<Vec<serde_json::Value>, contract::AuthorityError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    statement
        .query_map([], |row| project(row))
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))
}

#[expect(
    clippy::too_many_lines,
    reason = "the signed authority union is reconstructed field-by-field before any projection may influence authorization"
)]
fn verify_authority_projections(
    connection: &Connection,
    workspace_id: WorkspaceId,
    initial_key_id: &str,
    active_key_id: &str,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let bootstrap_principal_id = connection
        .query_row(
            "SELECT bootstrap_principal_id FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let bootstrap_principal_id = bootstrap_principal_id
        .parse::<PrincipalId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;

    let mut statuses = Vec::new();
    let mut latest_statuses = BTreeMap::<String, (String, bool)>::new();
    let mut bindings = BTreeMap::<String, BindingProjectionExpectation>::new();
    let mut active_bindings = BTreeMap::<String, String>::new();
    let mut historical_subjects = BTreeSet::new();
    let mut historical_public_keys = BTreeSet::new();
    let mut binding_revocations = Vec::new();
    let mut revoked_bindings = BTreeSet::new();
    let mut delegations = Vec::new();
    let mut delegation_ids = BTreeSet::new();
    let mut delegation_revocations = Vec::new();
    let mut revoked_delegations = BTreeSet::new();
    let mut decisions = Vec::new();
    let mut consumptions = Vec::new();

    for verified in records {
        match &verified.record {
            contract::AuthorityRecordV1::PrincipalStatus(status) => {
                if status.recorded_by_principal_id != bootstrap_principal_id {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "Principal status was not recorded by the bootstrap Human".to_owned(),
                    ));
                }
                if latest_statuses
                    .get(&status.principal_id.to_string())
                    .is_some_and(|(_, enabled)| !enabled && status.enabled)
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "Principal disablement is not terminal in the signed log".to_owned(),
                    ));
                }
                statuses.push(json!({
                    "authority_sequence": status.authority_sequence.get(),
                    "enabled": status.enabled,
                    "principal_id": status.principal_id.to_string(),
                    "principal_type": status.principal_type.to_string(),
                    "record_digest": verified.record_digest,
                    "recorded_at": status.recorded_at.to_string(),
                    "recorded_by_principal_id": status.recorded_by_principal_id.to_string(),
                    "workspace_id": workspace_id.to_string(),
                }));
                latest_statuses.insert(
                    status.principal_id.to_string(),
                    (status.principal_type.to_string(), status.enabled),
                );
            }
            contract::AuthorityRecordV1::PrincipalBinding(binding) => {
                binding.validate().map_err(contract_integrity)?;
                validate_binding_key_identity(binding)?;
                if binding.issued_by_principal_id != bootstrap_principal_id
                    || !historical_subjects.insert(
                        binding
                            .authenticated_subject
                            .as_subject()
                            .subject()
                            .to_owned(),
                    )
                    || !historical_public_keys.insert(binding.public_key.to_string())
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "signed binding history reuses Agent credential authority".to_owned(),
                    ));
                }
                let principal_id = binding.principal_id.to_string();
                match active_bindings.get(&principal_id).cloned() {
                    Some(predecessor_id)
                        if binding.supersedes_binding_id.map(|id| id.to_string())
                            == Some(predecessor_id.clone()) =>
                    {
                        let predecessor = bindings.get_mut(&predecessor_id).ok_or_else(|| {
                            contract::AuthorityError::AuthorityIntegrity(
                                "binding predecessor is absent from signed history".to_owned(),
                            )
                        })?;
                        predecessor.active = false;
                    }
                    Some(_) => {
                        return Err(contract::AuthorityError::AuthorityIntegrity(
                            "binding rotation does not supersede the active predecessor".to_owned(),
                        ));
                    }
                    None if binding.supersedes_binding_id.is_some() => {
                        return Err(contract::AuthorityError::AuthorityIntegrity(
                            "binding rotation has no active predecessor".to_owned(),
                        ));
                    }
                    None => {}
                }
                active_bindings.insert(principal_id, binding.binding_id.to_string());
                if bindings
                    .insert(
                        binding.binding_id.to_string(),
                        BindingProjectionExpectation {
                            binding: binding.clone(),
                            record_digest: verified.record_digest.clone(),
                            active: true,
                        },
                    )
                    .is_some()
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "signed binding identity is duplicated".to_owned(),
                    ));
                }
            }
            contract::AuthorityRecordV1::PrincipalBindingRevocation(revocation) => {
                if revocation.revoked_by_principal_id != bootstrap_principal_id
                    || !revoked_bindings.insert(revocation.binding_id.to_string())
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "binding revocation actor or target history is invalid".to_owned(),
                    ));
                }
                let binding = bindings
                    .get_mut(&revocation.binding_id.to_string())
                    .ok_or_else(|| {
                        contract::AuthorityError::AuthorityIntegrity(
                            "binding revocation target is absent from signed history".to_owned(),
                        )
                    })?;
                binding.active = false;
                if active_bindings.get(&binding.binding.principal_id.to_string())
                    == Some(&revocation.binding_id.to_string())
                {
                    active_bindings.remove(&binding.binding.principal_id.to_string());
                }
                binding_revocations.push(json!({
                    "authority_sequence": revocation.authority_sequence.get(),
                    "binding_id": revocation.binding_id.to_string(),
                    "reason": serialized_enum_name(&revocation.reason, "binding revocation reason")?,
                    "record_digest": verified.record_digest,
                    "revocation_id": revocation.revocation_id.to_string(),
                    "revoked_at": revocation.revoked_at.to_string(),
                    "revoked_by_principal_id": revocation.revoked_by_principal_id.to_string(),
                    "workspace_id": workspace_id.to_string(),
                }));
            }
            contract::AuthorityRecordV1::Delegation(delegation) => {
                delegation.validate().map_err(contract_integrity)?;
                if delegation.issuer_principal_id != bootstrap_principal_id
                    || !delegation_ids.insert(delegation.delegation_id.to_string())
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "Delegation issuer or identity is invalid in signed history".to_owned(),
                    ));
                }
                delegations.push(json!({
                    "actions_json": canonical_json(&delegation.actions, "Delegation actions")?,
                    "authority_sequence": delegation.authority_sequence.get(),
                    "constraints_json": canonical_json(&delegation.constraints, "Delegation constraints")?,
                    "delegation_id": delegation.delegation_id.to_string(),
                    "delegation_profile": contract::DIRECT_AUTHORITY_POLICY_PROFILE_V1,
                    "expires_at": delegation.expires_at.to_string(),
                    "issued_at": delegation.issued_at.to_string(),
                    "issuer_principal_id": delegation.issuer_principal_id.to_string(),
                    "not_before": delegation.not_before.to_string(),
                    "recipient_principal_id": delegation.recipient_principal_id.to_string(),
                    "record_digest": verified.record_digest,
                    "scope_json": canonical_json(&delegation.scope, "Delegation scope")?,
                    "workspace_id": workspace_id.to_string(),
                }));
            }
            contract::AuthorityRecordV1::DelegationRevocation(revocation) => {
                if revocation.revoked_by_principal_id != bootstrap_principal_id
                    || !delegation_ids.contains(&revocation.delegation_id.to_string())
                    || !revoked_delegations.insert(revocation.delegation_id.to_string())
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "Delegation revocation actor or target history is invalid".to_owned(),
                    ));
                }
                delegation_revocations.push(json!({
                    "authority_sequence": revocation.authority_sequence.get(),
                    "delegation_id": revocation.delegation_id.to_string(),
                    "reason": serialized_enum_name(&revocation.reason, "Delegation revocation reason")?,
                    "record_digest": verified.record_digest,
                    "revocation_id": revocation.revocation_id.to_string(),
                    "revoked_at": revocation.revoked_at.to_string(),
                    "revoked_by_principal_id": revocation.revoked_by_principal_id.to_string(),
                    "workspace_id": workspace_id.to_string(),
                }));
            }
            contract::AuthorityRecordV1::AuthorizationDecision(decision) => {
                decision.validate().map_err(contract_integrity)?;
                decisions.push(expected_decision_projection(
                    decision,
                    &verified.record_digest,
                )?);
                consumptions.push(json!({
                    "command_digest": decision.command_digest.to_string(),
                    "command_envelope_digest": decision.command_envelope_digest.to_string(),
                    "consumed_at": decision.evaluated_at.to_string(),
                    "decision_authority_sequence": decision.authority_sequence.get(),
                    "presentation_id": decision.presentation_id.to_string(),
                    "workspace_id": workspace_id.to_string(),
                }));
            }
            contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(transition) => {
                if transition.activated_by_principal_id != bootstrap_principal_id {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "authority root transition actor is not the bootstrap Human".to_owned(),
                    ));
                }
            }
        }
    }

    verify_root_projection(
        connection,
        workspace_id,
        bootstrap_principal_id,
        initial_key_id,
        active_key_id,
        records,
    )?;
    verify_status_projection(connection, &statuses, &latest_statuses)?;
    verify_binding_projection(connection, workspace_id, &bindings)?;
    verify_simple_authority_projections(
        connection,
        &binding_revocations,
        &delegations,
        &delegation_revocations,
        &decisions,
        &consumptions,
    )?;
    verify_actor_evidence_projection(connection, workspace_id, bootstrap_principal_id, records)?;
    verify_enrollment_challenge_projections(
        connection,
        workspace_id,
        bootstrap_principal_id,
        records,
    )?;
    verify_authenticated_operation_result_projection(connection, workspace_id, records)?;
    verify_authenticated_localized_consequence_projection(connection, workspace_id, records)?;

    let total_authority_records = connection
        .query_row("SELECT COUNT(*) FROM authority_records", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if total_authority_records != i64::try_from(records.len()).unwrap_or(i64::MAX) {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authority log contains a record outside the selected Workspace".to_owned(),
        ));
    }
    Ok(())
}

fn expected_decision_projection(
    decision: &contract::AuthorizationDecisionV2,
    record_digest: &str,
) -> Result<serde_json::Value, contract::AuthorityError> {
    Ok(json!({
        "authority_sequence": decision.authority_sequence.get(),
        "binding_id": decision.binding.binding_id.to_string(),
        "command_digest": decision.command_digest.to_string(),
        "command_envelope_digest": decision.command_envelope_digest.to_string(),
        "decision": serialized_enum_name(&decision.decision, "decision outcome")?,
        "decision_digest": record_digest,
        "decision_json": canonical_json(decision, "authorization decision")?,
        "delegation_id": decision.delegation.delegation_id.to_string(),
        "evaluated_at": decision.evaluated_at.to_string(),
        "operating_principal_id": decision.operating_principal_id.to_string(),
        "operation_name": decision.operation.name(),
        "operation_version": decision.operation.version(),
        "presentation_id": decision.presentation_id.to_string(),
        "reason_code": decision.reason_code
            .map(|reason| serialized_enum_name(&reason, "decision reason"))
            .transpose()?,
        "requested_action": serialized_enum_name(&decision.requested_action, "requested action")?,
        "requesting_principal_id": decision.requesting_principal_id.to_string(),
        "workspace_id": decision.workspace_id.to_string(),
    }))
}

fn verify_status_projection(
    connection: &Connection,
    expected: &[serde_json::Value],
    latest_statuses: &BTreeMap<String, (String, bool)>,
) -> Result<(), contract::AuthorityError> {
    let actual = query_projection_rows(
        connection,
        "SELECT principal_id, authority_sequence, workspace_id, principal_type,
                enabled, recorded_by_principal_id, recorded_at, record_digest
         FROM principal_status_v1",
        |row| {
            Ok(json!({
                "authority_sequence": row.get::<_, i64>(1)?,
                "enabled": row.get::<_, bool>(4)?,
                "principal_id": row.get::<_, String>(0)?,
                "principal_type": row.get::<_, String>(3)?,
                "record_digest": row.get::<_, String>(7)?,
                "recorded_at": row.get::<_, String>(6)?,
                "recorded_by_principal_id": row.get::<_, String>(5)?,
                "workspace_id": row.get::<_, String>(2)?,
            }))
        },
    )?;
    verify_projection_row_set("Principal-status projection", expected, &actual)?;
    for (principal_id, (expected_type, expected_enabled)) in latest_statuses {
        let (actual_type, actual_enabled): (String, bool) = connection
            .query_row(
                "SELECT principal_type, enabled FROM principals WHERE principal_id = ?1",
                [principal_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        if actual_type != *expected_type || actual_enabled != *expected_enabled {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "Principal projection disagrees with latest signed status".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_binding_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    bindings: &BTreeMap<String, BindingProjectionExpectation>,
) -> Result<(), contract::AuthorityError> {
    let expected = bindings
        .values()
        .map(|expected| {
            let binding = &expected.binding;
            json!({
                "active": expected.active,
                "audience": binding.audience.to_string(),
                "authenticated_subject": binding.authenticated_subject.as_subject().subject(),
                "authority_sequence": binding.authority_sequence.get(),
                "binding_id": binding.binding_id.to_string(),
                "enrollment_challenge_digest": binding.enrollment_challenge_digest.to_string(),
                "enrollment_envelope_digest": binding.enrollment_envelope_digest.to_string(),
                "expires_at": binding.expires_at.to_string(),
                "issued_at": binding.issued_at.to_string(),
                "issued_by_principal_id": binding.issued_by_principal_id.to_string(),
                "not_before": binding.not_before.to_string(),
                "principal_id": binding.principal_id.to_string(),
                "public_key": binding.public_key.to_string(),
                "record_digest": expected.record_digest,
                "supersedes_binding_id": binding.supersedes_binding_id.map(|id| id.to_string()),
                "workspace_id": workspace_id.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let actual = query_projection_rows(
        connection,
        "SELECT binding_id, workspace_id, principal_id, authenticated_subject,
                public_key, audience, enrollment_challenge_digest,
                enrollment_envelope_digest, issued_by_principal_id, issued_at,
                not_before, expires_at, supersedes_binding_id, authority_sequence,
                record_digest, active
         FROM principal_bindings_v1",
        |row| {
            Ok(json!({
                "active": row.get::<_, bool>(15)?,
                "audience": row.get::<_, String>(5)?,
                "authenticated_subject": row.get::<_, String>(3)?,
                "authority_sequence": row.get::<_, i64>(13)?,
                "binding_id": row.get::<_, String>(0)?,
                "enrollment_challenge_digest": row.get::<_, String>(6)?,
                "enrollment_envelope_digest": row.get::<_, String>(7)?,
                "expires_at": row.get::<_, String>(11)?,
                "issued_at": row.get::<_, String>(9)?,
                "issued_by_principal_id": row.get::<_, String>(8)?,
                "not_before": row.get::<_, String>(10)?,
                "principal_id": row.get::<_, String>(2)?,
                "public_key": row.get::<_, String>(4)?,
                "record_digest": row.get::<_, String>(14)?,
                "supersedes_binding_id": row.get::<_, Option<String>>(12)?,
                "workspace_id": row.get::<_, String>(1)?,
            }))
        },
    )?;
    verify_projection_row_set("Principal-binding projection", &expected, &actual)
}

#[expect(
    clippy::too_many_lines,
    reason = "the five small signed projection tables are compared as one exact set before authorization"
)]
fn verify_simple_authority_projections(
    connection: &Connection,
    binding_revocations: &[serde_json::Value],
    delegations: &[serde_json::Value],
    delegation_revocations: &[serde_json::Value],
    decisions: &[serde_json::Value],
    consumptions: &[serde_json::Value],
) -> Result<(), contract::AuthorityError> {
    let actual_binding_revocations = query_projection_rows(
        connection,
        "SELECT revocation_id, binding_id, workspace_id, revoked_by_principal_id,
                revoked_at, reason, authority_sequence, record_digest
         FROM principal_binding_revocations_v1",
        |row| {
            Ok(json!({
                "authority_sequence": row.get::<_, i64>(6)?,
                "binding_id": row.get::<_, String>(1)?,
                "reason": row.get::<_, String>(5)?,
                "record_digest": row.get::<_, String>(7)?,
                "revocation_id": row.get::<_, String>(0)?,
                "revoked_at": row.get::<_, String>(4)?,
                "revoked_by_principal_id": row.get::<_, String>(3)?,
                "workspace_id": row.get::<_, String>(2)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "binding-revocation projection",
        binding_revocations,
        &actual_binding_revocations,
    )?;

    let actual_delegations = query_projection_rows(
        connection,
        "SELECT delegation_id, workspace_id, issuer_principal_id,
                recipient_principal_id, delegation_profile, actions_json, scope_json,
                constraints_json, not_before, expires_at, issued_at,
                authority_sequence, record_digest
         FROM delegations_v2",
        |row| {
            Ok(json!({
                "actions_json": row.get::<_, String>(5)?,
                "authority_sequence": row.get::<_, i64>(11)?,
                "constraints_json": row.get::<_, String>(7)?,
                "delegation_id": row.get::<_, String>(0)?,
                "delegation_profile": row.get::<_, String>(4)?,
                "expires_at": row.get::<_, String>(9)?,
                "issued_at": row.get::<_, String>(10)?,
                "issuer_principal_id": row.get::<_, String>(2)?,
                "not_before": row.get::<_, String>(8)?,
                "recipient_principal_id": row.get::<_, String>(3)?,
                "record_digest": row.get::<_, String>(12)?,
                "scope_json": row.get::<_, String>(6)?,
                "workspace_id": row.get::<_, String>(1)?,
            }))
        },
    )?;
    verify_projection_row_set("Delegation projection", delegations, &actual_delegations)?;

    let actual_delegation_revocations = query_projection_rows(
        connection,
        "SELECT revocation_id, delegation_id, workspace_id, revoked_by_principal_id,
                revoked_at, reason, authority_sequence, record_digest
         FROM delegation_revocations_v2",
        |row| {
            Ok(json!({
                "authority_sequence": row.get::<_, i64>(6)?,
                "delegation_id": row.get::<_, String>(1)?,
                "reason": row.get::<_, String>(5)?,
                "record_digest": row.get::<_, String>(7)?,
                "revocation_id": row.get::<_, String>(0)?,
                "revoked_at": row.get::<_, String>(4)?,
                "revoked_by_principal_id": row.get::<_, String>(3)?,
                "workspace_id": row.get::<_, String>(2)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "Delegation-revocation projection",
        delegation_revocations,
        &actual_delegation_revocations,
    )?;

    let actual_decisions = query_projection_rows(
        connection,
        "SELECT authority_sequence, presentation_id, workspace_id, command_digest,
                command_envelope_digest, requesting_principal_id,
                operating_principal_id, binding_id, delegation_id,
                operation_name, operation_version, requested_action,
                decision, reason_code, evaluated_at, decision_json, decision_digest
         FROM authorization_decisions_v2",
        |row| {
            Ok(json!({
                "authority_sequence": row.get::<_, i64>(0)?,
                "binding_id": row.get::<_, String>(7)?,
                "command_digest": row.get::<_, String>(3)?,
                "command_envelope_digest": row.get::<_, String>(4)?,
                "decision": row.get::<_, String>(12)?,
                "decision_digest": row.get::<_, String>(16)?,
                "decision_json": row.get::<_, String>(15)?,
                "delegation_id": row.get::<_, String>(8)?,
                "evaluated_at": row.get::<_, String>(14)?,
                "operating_principal_id": row.get::<_, String>(6)?,
                "operation_name": row.get::<_, String>(9)?,
                "operation_version": row.get::<_, String>(10)?,
                "presentation_id": row.get::<_, String>(1)?,
                "reason_code": row.get::<_, Option<String>>(13)?,
                "requested_action": row.get::<_, String>(11)?,
                "requesting_principal_id": row.get::<_, String>(5)?,
                "workspace_id": row.get::<_, String>(2)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "authorization-decision projection",
        decisions,
        &actual_decisions,
    )?;

    let actual_consumptions = query_projection_rows(
        connection,
        "SELECT presentation_id, workspace_id, command_digest,
                command_envelope_digest, decision_authority_sequence, consumed_at
         FROM presentation_consumptions_v1",
        |row| {
            Ok(json!({
                "command_digest": row.get::<_, String>(2)?,
                "command_envelope_digest": row.get::<_, String>(3)?,
                "consumed_at": row.get::<_, String>(5)?,
                "decision_authority_sequence": row.get::<_, i64>(4)?,
                "presentation_id": row.get::<_, String>(0)?,
                "workspace_id": row.get::<_, String>(1)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "presentation-consumption projection",
        consumptions,
        &actual_consumptions,
    )
}

struct RootProjectionRow {
    authority_key_id: String,
    workspace_id: String,
    public_key: String,
    algorithm: String,
    key_file_relative_path: String,
    created_by_principal_id: String,
    created_at: String,
    predecessor_authority_key_id: Option<String>,
    root_transition_envelope_digest: Option<String>,
    root_json: String,
    active: bool,
}

#[expect(
    clippy::too_many_lines,
    reason = "every root column and transition cross-link is reconciled together against the signed rotation chain"
)]
fn verify_root_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    initial_key_id: &str,
    active_key_id: &str,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let mut statement = connection
        .prepare(
            "SELECT authority_key_id, workspace_id, public_key, algorithm,
                    key_file_relative_path, created_by_principal_id, created_at,
                    predecessor_authority_key_id, root_transition_envelope_digest,
                    root_json, active
             FROM workspace_authority_roots",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let roots = statement
        .query_map([], |row| {
            Ok(RootProjectionRow {
                authority_key_id: row.get(0)?,
                workspace_id: row.get(1)?,
                public_key: row.get(2)?,
                algorithm: row.get(3)?,
                key_file_relative_path: row.get(4)?,
                created_by_principal_id: row.get(5)?,
                created_at: row.get(6)?,
                predecessor_authority_key_id: row.get(7)?,
                root_transition_envelope_digest: row.get(8)?,
                root_json: row.get(9)?,
                active: row.get(10)?,
            })
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let transitions = records
        .iter()
        .filter_map(|record| match &record.record {
            contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(transition) => Some((
                transition.successor_authority_key_id.to_string(),
                (transition, record),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    if roots.len() != transitions.len() + 1 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "Workspace root projection count disagrees with signed transitions".to_owned(),
        ));
    }
    for row in roots {
        let root: contract::WorkspaceAuthorityRootV1 =
            decode_canonical(&row.root_json, "Workspace authority root")?;
        root.validate().map_err(contract_integrity)?;
        if row.workspace_id != workspace_id.to_string()
            || row.authority_key_id != root.authority_key_id.as_str()
            || row.public_key != root.public_key.as_str()
            || row.algorithm != "ed25519"
            || row.created_by_principal_id != root.created_by_principal_id.to_string()
            || row.created_at != root.created_at.to_string()
            || row.predecessor_authority_key_id
                != root
                    .predecessor_authority_key_id
                    .as_ref()
                    .map(ToString::to_string)
            || row.root_transition_envelope_digest
                != root
                    .root_transition_envelope_digest
                    .as_ref()
                    .map(ToString::to_string)
            || row.active != (row.authority_key_id == active_key_id)
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "Workspace authority root columns disagree with canonical root metadata".to_owned(),
            ));
        }
        if row.authority_key_id == initial_key_id {
            if row.key_file_relative_path != AUTHORITY_SIGNING_KEY_RELATIVE_PATH
                || root.created_by_principal_id != bootstrap_principal_id
                || root.predecessor_authority_key_id.is_some()
                || root.root_transition_envelope_digest.is_some()
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "initial Workspace authority root metadata is invalid".to_owned(),
                ));
            }
        } else {
            let Some((transition, verified)) = transitions.get(&row.authority_key_id) else {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Workspace authority successor has no signed transition".to_owned(),
                ));
            };
            let expected_relative_path =
                successor_authority_key_relative_path(&transition.successor_authority_key_id)?;
            if row.key_file_relative_path != expected_relative_path
                || root.workspace_id != transition.workspace_id
                || root.authority_key_id != transition.successor_authority_key_id
                || root.public_key != transition.successor_public_key
                || root.created_by_principal_id != transition.activated_by_principal_id
                || root.created_at != transition.activated_at
                || root.predecessor_authority_key_id
                    != Some(transition.predecessor_authority_key_id.clone())
                || root
                    .root_transition_envelope_digest
                    .as_ref()
                    .map(ToString::to_string)
                    != Some(verified.envelope_digest.clone())
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Workspace authority successor does not reproduce its transition".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn stable_subject_commitment_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
) -> Result<(PrincipalId, proof_application::ContentDigest), contract::AuthorityError> {
    let rows = query_projection_rows(
        connection,
        "SELECT workspace_id, requesting_principal_id, requesting_subject_provider,
                requesting_subject, blind, commitment_input_json,
                requesting_subject_commitment
         FROM authenticated_subject_commitment_openings_v1",
        |row| {
            Ok(json!({
                "blind": row.get::<_, String>(4)?,
                "commitment_input_json": row.get::<_, String>(5)?,
                "requesting_principal_id": row.get::<_, String>(1)?,
                "requesting_subject": row.get::<_, String>(3)?,
                "requesting_subject_commitment": row.get::<_, String>(6)?,
                "requesting_subject_provider": row.get::<_, String>(2)?,
                "workspace_id": row.get::<_, String>(0)?,
            }))
        },
    )?;
    if rows.len() != 1 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "Workspace must have exactly one private requesting-Human commitment opening"
                .to_owned(),
        ));
    }
    let row = &rows[0];
    let row_workspace = row["workspace_id"].as_str().ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "subject commitment Workspace is malformed".to_owned(),
        )
    })?;
    let principal = row["requesting_principal_id"]
        .as_str()
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "subject commitment Principal is malformed".to_owned(),
            )
        })?
        .parse::<PrincipalId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let input_json = row["commitment_input_json"].as_str().ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "subject commitment input is malformed".to_owned(),
        )
    })?;
    let input: contract::AuthenticatedSubjectCommitmentInputV1 =
        decode_canonical(input_json, "authenticated subject commitment opening")?;
    let input_value = parse_strict(input_json.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let input_canonical = canonicalize(&input_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let commitment = digest(
        ArtifactKind::AuthenticatedSubjectCommitmentV1,
        &input_canonical,
    );
    let (principal_provider, principal_subject): (String, String) = connection
        .query_row(
            "SELECT identity_provider, identity_subject FROM principals
             WHERE principal_id = ?1 AND principal_type = 'human'",
            [bootstrap_principal_id.to_string()],
            |principal_row| Ok((principal_row.get(0)?, principal_row.get(1)?)),
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if row_workspace != workspace_id.to_string()
        || principal != bootstrap_principal_id
        || input.workspace_id != workspace_id
        || principal_provider != "os/unix"
        || row["requesting_subject_provider"] != principal_provider
        || row["requesting_subject"] != principal_subject
        || row["requesting_subject"] != input.authenticated_subject.as_subject().subject()
        || row["blind"] != input.blind.to_string()
        || row["requesting_subject_commitment"] != commitment.to_string()
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "private requesting-Human commitment opening does not reproduce".to_owned(),
        ));
    }
    Ok((principal, commitment))
}

fn verify_actor_evidence_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let (opening_principal_id, opening_commitment) =
        stable_subject_commitment_projection(connection, workspace_id, bootstrap_principal_id)?;
    let decisions = records
        .iter()
        .filter_map(|record| match &record.record {
            contract::AuthorityRecordV1::AuthorizationDecision(decision) => Some(decision),
            _ => None,
        })
        .collect::<Vec<_>>();
    let evidence_count = connection
        .query_row(
            "SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if evidence_count != i64::try_from(decisions.len()).unwrap_or(i64::MAX) {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "actor-context evidence is not one-to-one with signed decisions".to_owned(),
        ));
    }
    for decision in decisions {
        let (stored_workspace, evidence_json, stored_digest, authenticated_at): (
            String,
            String,
            String,
            String,
        ) = connection
            .query_row(
                "SELECT workspace_id, evidence_json, actor_context_digest, authenticated_at
                 FROM authenticated_actor_context_evidence_v1
                 WHERE presentation_id = ?1",
                [decision.presentation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let evidence: contract::AuthenticatedActorContextEvidenceV1 =
            decode_canonical(&evidence_json, "authenticated actor context evidence")?;
        let canonical =
            canonicalize(&parse_strict(evidence_json.as_bytes()).map_err(|error| {
                contract::AuthorityError::AuthorityIntegrity(error.to_string())
            })?)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let computed_digest = digest(ArtifactKind::AuthenticatedActorContextV1, &canonical);
        let binding = records.iter().find_map(|record| match &record.record {
            contract::AuthorityRecordV1::PrincipalBinding(binding)
                if binding.binding_id == decision.binding.binding_id =>
            {
                Some(binding)
            }
            _ => None,
        });
        let Some(binding) = binding else {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "decision actor evidence names an absent binding".to_owned(),
            ));
        };
        if stored_workspace != workspace_id.to_string()
            || authenticated_at != evidence.authenticated_at.to_string()
            || stored_digest != computed_digest.to_string()
            || computed_digest != decision.actor_context_digest
            || evidence.workspace_id != workspace_id
            || evidence.audience != contract::AuthorityAudience::for_workspace(workspace_id)
            || evidence.requesting_principal_id != opening_principal_id
            || evidence.requesting_principal_id != decision.requesting_principal_id
            || evidence.requesting_subject_commitment != opening_commitment
            || evidence.requesting_subject_commitment != decision.requesting_subject_commitment
            || evidence.operating_subject != binding.authenticated_subject
            || evidence.binding_id != decision.binding.binding_id
            || evidence.operating_principal_id != decision.operating_principal_id
            || evidence.delegation_id != decision.delegation.delegation_id
            || evidence.operation != decision.operation
            || evidence.command_digest != decision.command_digest
            || evidence.command_envelope_digest != decision.command_envelope_digest
            || evidence.presentation_id != decision.presentation_id
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "actor-context evidence does not reproduce its signed decision".to_owned(),
            ));
        }
    }
    Ok(())
}

struct EnrollmentChallengeProjectionRow {
    challenge_id: String,
    workspace_id: String,
    binding_id: String,
    principal_id: String,
    candidate_key_id: String,
    issued_by_principal_id: String,
    issued_at: String,
    expires_at: String,
    challenge_json: String,
    challenge_digest: String,
    enrollment_envelope_json: Option<String>,
    enrollment_envelope_digest: Option<String>,
    consumed_at: Option<String>,
}

#[expect(
    clippy::too_many_lines,
    reason = "preparatory challenges and consumed Agent proof envelopes are reconciled as one lifecycle projection"
)]
fn verify_enrollment_challenge_projections(
    connection: &Connection,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let mut signed_bindings = records
        .iter()
        .filter_map(|record| match &record.record {
            contract::AuthorityRecordV1::PrincipalBinding(binding) => {
                Some((binding.binding_id.to_string(), binding))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut statement = connection
        .prepare(
            "SELECT challenge_id, workspace_id, binding_id, principal_id,
                    candidate_key_id, issued_by_principal_id, issued_at, expires_at,
                    challenge_json, challenge_digest, enrollment_envelope_json,
                    enrollment_envelope_digest, consumed_at
             FROM binding_enrollment_challenges ORDER BY challenge_id",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok(EnrollmentChallengeProjectionRow {
                challenge_id: row.get(0)?,
                workspace_id: row.get(1)?,
                binding_id: row.get(2)?,
                principal_id: row.get(3)?,
                candidate_key_id: row.get(4)?,
                issued_by_principal_id: row.get(5)?,
                issued_at: row.get(6)?,
                expires_at: row.get(7)?,
                challenge_json: row.get(8)?,
                challenge_digest: row.get(9)?,
                enrollment_envelope_json: row.get(10)?,
                enrollment_envelope_digest: row.get(11)?,
                consumed_at: row.get(12)?,
            })
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;

    for row in rows {
        let challenge: contract::BindingEnrollmentChallengeV1 =
            decode_canonical(&row.challenge_json, "binding enrollment challenge")?;
        challenge.validate().map_err(contract_integrity)?;
        let challenge_canonical = canonicalize(
            &parse_strict(row.challenge_json.as_bytes())
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?,
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let challenge_digest = digest(
            ArtifactKind::BindingEnrollmentChallengeV1,
            &challenge_canonical,
        );
        if row.workspace_id != workspace_id.to_string()
            || challenge.workspace_id != workspace_id
            || challenge.audience != contract::AuthorityAudience::for_workspace(workspace_id)
            || row.challenge_id != challenge.challenge_id.to_string()
            || row.binding_id != challenge.binding_id.to_string()
            || row.principal_id != challenge.principal_id.to_string()
            || row.candidate_key_id != challenge.candidate_key_id.as_str()
            || row.issued_by_principal_id != bootstrap_principal_id.to_string()
            || challenge.issued_by_principal_id != bootstrap_principal_id
            || row.issued_at != challenge.issued_at.to_string()
            || row.expires_at != challenge.expires_at.to_string()
            || row.challenge_digest != challenge_digest.to_string()
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "binding-enrollment challenge projection does not reproduce".to_owned(),
            ));
        }

        let (envelope_json, envelope_digest, consumed_at) = match (
            row.enrollment_envelope_json,
            row.enrollment_envelope_digest,
            row.consumed_at,
        ) {
            (None, None, None) => continue,
            (Some(envelope_json), Some(envelope_digest), Some(consumed_at)) => {
                (envelope_json, envelope_digest, consumed_at)
            }
            _ => {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "binding-enrollment challenge has an ambiguous partial consumption".to_owned(),
                ));
            }
        };
        let binding = signed_bindings.remove(&row.binding_id).ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "consumed enrollment challenge is orphaned from signed binding history".to_owned(),
            )
        })?;
        let consumed_at = consumed_at
            .parse::<Timestamp>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let verified = verify_authority_envelope::<contract::BindingEnrollmentChallengeV1>(
            envelope_json.as_bytes(),
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            &[challenge.candidate_key_id.as_str()],
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        if binding.workspace_id != workspace_id
            || binding.binding_id != challenge.binding_id
            || binding.principal_id != challenge.principal_id
            || binding.issued_by_principal_id != bootstrap_principal_id
            || binding.audience != challenge.audience
            || binding.authenticated_subject.as_subject().subject()
                != challenge.candidate_key_id.as_str()
            || binding.enrollment_challenge_digest != challenge_digest
            || binding.enrollment_envelope_digest.to_string() != envelope_digest
            || verified.parsed.envelope_digest.to_string() != envelope_digest
            || verified.parsed.payload != challenge
            || verified.parsed.payload_json != row.challenge_json
            || binding.issued_at < challenge.issued_at
            || binding.issued_at >= challenge.expires_at
            || consumed_at < challenge.issued_at
            || consumed_at >= challenge.expires_at
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "consumed enrollment projection does not reproduce its signed binding".to_owned(),
            ));
        }
    }
    if signed_bindings.is_empty() {
        Ok(())
    } else {
        Err(contract::AuthorityError::AuthorityIntegrity(
            "signed binding history lacks a consumed enrollment projection".to_owned(),
        ))
    }
}

struct ContextResultAnchorRow {
    context_pack_id: String,
    workspace_id: String,
    requesting_principal_id: String,
    operating_principal_id: String,
    delegation_id: String,
    environment_id: String,
    release_id: String,
    edition_id: String,
    object_ids_json: String,
    manifest_json: String,
    context_pack_digest: String,
    created_at: String,
    expires_at: String,
    operation_workspace_id: Option<String>,
    operation_requesting_principal_id: Option<String>,
    operation_operating_principal_id: Option<String>,
    idempotency_key: Option<String>,
}

fn required_json_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a str, contract::AuthorityError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "{label} has no valid `{field}` field"
            ))
        })
}

fn required_json_u64(
    value: &serde_json::Value,
    field: &str,
    label: &str,
) -> Result<u64, contract::AuthorityError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "{label} has no valid `{field}` field"
            ))
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "C4 result ownership is reconstructed from the immutable ContextPack, its operation key, and signed Allow decision before disclosure"
)]
fn verify_authenticated_operation_result_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let signed_decisions = records
        .iter()
        .filter_map(|record| match &record.record {
            contract::AuthorityRecordV1::AuthorizationDecision(decision) => {
                Some((record.record_digest.as_str(), decision))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut statement = connection
        .prepare(
            "SELECT pack.context_pack_id, pack.workspace_id,
                    pack.requesting_principal_id, pack.operating_principal_id,
                    pack.delegation_id, pack.environment_id, pack.release_id,
                    pack.edition_id, pack.object_ids_json, pack.manifest_json,
                    pack.context_pack_digest, pack.created_at, pack.expires_at,
                    operation.workspace_id, operation.requesting_principal_id,
                    operation.operating_principal_id, operation.idempotency_key
             FROM context_packs AS pack
             LEFT JOIN context_pack_build_operations AS operation
               ON operation.context_pack_id = pack.context_pack_id
             ORDER BY pack.context_pack_id, operation.idempotency_key",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let anchors = statement
        .query_map([], |row| {
            Ok(ContextResultAnchorRow {
                context_pack_id: row.get(0)?,
                workspace_id: row.get(1)?,
                requesting_principal_id: row.get(2)?,
                operating_principal_id: row.get(3)?,
                delegation_id: row.get(4)?,
                environment_id: row.get(5)?,
                release_id: row.get(6)?,
                edition_id: row.get(7)?,
                object_ids_json: row.get(8)?,
                manifest_json: row.get(9)?,
                context_pack_digest: row.get(10)?,
                created_at: row.get(11)?,
                expires_at: row.get(12)?,
                operation_workspace_id: row.get(13)?,
                operation_requesting_principal_id: row.get(14)?,
                operation_operating_principal_id: row.get(15)?,
                idempotency_key: row.get(16)?,
            })
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;

    let mut expected_results = Vec::new();
    for anchor in anchors {
        let manifest_value = parse_strict(anchor.manifest_json.as_bytes())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let manifest = canonicalize(&manifest_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let object_ids_value = parse_strict(anchor.object_ids_json.as_bytes())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let object_ids_canonical = canonicalize(&object_ids_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let object_ids = object_ids_value
            .as_array()
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "ContextPack Object identity projection is malformed".to_owned(),
                )
            })?;
        let manifest_object_ids = manifest_value
            .get("objects")
            .and_then(serde_json::Value::as_array)
            .and_then(|objects| {
                objects
                    .iter()
                    .map(|object| {
                        object
                            .get("object_id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "ContextPack manifest Object closure is malformed".to_owned(),
                )
            })?;
        let authorization_decision_digest = required_json_string(
            &manifest_value,
            "authorization_decision_digest",
            "ContextPack manifest",
        )?;
        let anchored_decision = signed_decisions.get(authorization_decision_digest).copied();
        let Some(idempotency_key) = anchor.idempotency_key.as_deref() else {
            if anchored_decision.is_some() {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "authenticated ContextPack lacks its application operation key".to_owned(),
                ));
            }
            continue;
        };
        let limits = manifest_value.get("limits").ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "ContextPack manifest has no limits".to_owned(),
            )
        })?;
        let max_objects = required_json_u64(limits, "max_objects", "ContextPack limits")?;
        let max_bytes = required_json_u64(limits, "max_bytes", "ContextPack limits")?;
        let semantic_command = canonicalize(&json!({
            "api_version": "proof.dev/command-input/v1",
            "delegation_id": anchor.delegation_id,
            "idempotency_key": idempotency_key,
            "normalized_input": {
                "delegation_id": anchor.delegation_id,
                "environment_id": anchor.environment_id,
                "expires_at": anchor.expires_at,
                "idempotency_key": idempotency_key,
                "intent": required_json_string(&manifest_value, "intent", "ContextPack manifest")?,
                "max_bytes": max_bytes,
                "max_objects": max_objects,
                "object_ids": object_ids,
                "operating_principal_id": anchor.operating_principal_id,
                "task_id": required_json_string(&manifest_value, "task_id", "ContextPack manifest")?,
            },
            "operating_principal_id": anchor.operating_principal_id,
            "operation": {
                "name": contract::AuthorityOperation::ContextBuildV1.name(),
                "version": contract::AuthorityOperation::ContextBuildV1.version(),
            },
            "requesting_principal_id": anchor.requesting_principal_id,
            "workspace_id": anchor.workspace_id,
        }))
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let command_digest = digest(ArtifactKind::CommandV1, &semantic_command);
        let command_has_signed_allow = signed_decisions.values().any(|decision| {
            decision.workspace_id == workspace_id
                && decision.operation == contract::AuthorityOperation::ContextBuildV1
                && decision.decision == contract::AuthorizationDecisionOutcome::Allow
                && decision.requesting_principal_id.to_string() == anchor.requesting_principal_id
                && decision.operating_principal_id.to_string() == anchor.operating_principal_id
                && decision.delegation.delegation_id.to_string() == anchor.delegation_id
                && decision.command_digest == command_digest
        });
        if anchored_decision.is_none() && !command_has_signed_allow {
            continue;
        }
        let decision = anchored_decision.ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "authenticated ContextPack substituted its signed decision anchor".to_owned(),
            )
        })?;
        let context_pack_digest = digest(ArtifactKind::ContextPackV1, &manifest);
        if anchor.workspace_id != workspace_id.to_string()
            || anchor.manifest_json != manifest.as_str()
            || anchor.object_ids_json != object_ids_canonical.as_str()
            || manifest_object_ids != object_ids
            || anchor.context_pack_digest != context_pack_digest.to_string()
            || required_json_string(&manifest_value, "api_version", "ContextPack manifest")?
                != "proof.dev/context-pack/v1"
            || required_json_string(&manifest_value, "context_pack_id", "ContextPack manifest")?
                != anchor.context_pack_id
            || required_json_string(&manifest_value, "workspace_id", "ContextPack manifest")?
                != anchor.workspace_id
            || required_json_string(
                &manifest_value,
                "requesting_principal_id",
                "ContextPack manifest",
            )? != anchor.requesting_principal_id
            || required_json_string(
                &manifest_value,
                "operating_principal_id",
                "ContextPack manifest",
            )? != anchor.operating_principal_id
            || required_json_string(&manifest_value, "delegation_id", "ContextPack manifest")?
                != anchor.delegation_id
            || required_json_string(&manifest_value, "environment_id", "ContextPack manifest")?
                != anchor.environment_id
            || required_json_string(&manifest_value, "release_id", "ContextPack manifest")?
                != anchor.release_id
            || required_json_string(&manifest_value, "edition_id", "ContextPack manifest")?
                != anchor.edition_id
            || required_json_string(&manifest_value, "built_at", "ContextPack manifest")?
                != anchor.created_at
            || required_json_string(&manifest_value, "expires_at", "ContextPack manifest")?
                != anchor.expires_at
            || decision.operation != contract::AuthorityOperation::ContextBuildV1
            || decision.decision != contract::AuthorizationDecisionOutcome::Allow
            || decision.command_digest != command_digest
            || decision.requesting_principal_id.to_string() != anchor.requesting_principal_id
            || decision.operating_principal_id.to_string() != anchor.operating_principal_id
            || decision.delegation.delegation_id.to_string() != anchor.delegation_id
            || decision.evaluated_at.to_string() != anchor.created_at
            || anchor.operation_workspace_id.as_deref() != Some(anchor.workspace_id.as_str())
            || anchor.operation_requesting_principal_id.as_deref()
                != Some(anchor.requesting_principal_id.as_str())
            || anchor.operation_operating_principal_id.as_deref()
                != Some(anchor.operating_principal_id.as_str())
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authenticated ContextPack result anchor does not reproduce".to_owned(),
            ));
        }
        expected_results.push(json!({
            "command_digest": command_digest.to_string(),
            "delegation_id": anchor.delegation_id,
            "idempotency_key": idempotency_key,
            "operating_principal_id": anchor.operating_principal_id,
            "operation_name": contract::AuthorityOperation::ContextBuildV1.name(),
            "operation_version": contract::AuthorityOperation::ContextBuildV1.version(),
            "requesting_principal_id": anchor.requesting_principal_id,
            "result_digest": context_pack_digest.to_string(),
            "result_json": anchor.manifest_json,
            "workspace_id": anchor.workspace_id,
        }));
    }

    let actual_results = query_projection_rows(
        connection,
        "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                delegation_id, operation_name, operation_version, idempotency_key,
                command_digest, result_json, result_digest
         FROM authenticated_operation_results_v1",
        |row| {
            Ok(json!({
                "command_digest": row.get::<_, String>(7)?,
                "delegation_id": row.get::<_, String>(3)?,
                "idempotency_key": row.get::<_, String>(6)?,
                "operating_principal_id": row.get::<_, String>(2)?,
                "operation_name": row.get::<_, String>(4)?,
                "operation_version": row.get::<_, String>(5)?,
                "requesting_principal_id": row.get::<_, String>(1)?,
                "result_digest": row.get::<_, String>(9)?,
                "result_json": row.get::<_, String>(8)?,
                "workspace_id": row.get::<_, String>(0)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "authenticated-operation result projection",
        &expected_results,
        &actual_results,
    )
}

#[derive(Clone, Debug)]
struct AuthenticatedLocalizedConsequenceRow {
    decision_authority_sequence: i64,
    presentation_id: String,
    workspace_id: String,
    requesting_principal_id: String,
    operating_principal_id: String,
    delegation_id: String,
    command_digest: String,
    authorization_decision_digest: String,
    operation_name: String,
    operation_version: String,
    application_idempotency_kind: String,
    application_idempotency_key: Option<String>,
    result_kind: String,
    result_contract: String,
    result_json: String,
    result_digest: String,
    application_effect_digest: String,
    application_consequence_digest: String,
    selectors_json: String,
    evidence_json: String,
    evidence_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedApplicationLedgerRow {
    workspace_id: String,
    idempotency_key: String,
    idempotency_kind: String,
    operation_name: String,
    operation_version: String,
    command_digest: String,
    result_digest: String,
    application_effect_digest: String,
    application_consequence_digest: String,
    first_decision_authority_sequence: i64,
}

fn canonical_projection_value(
    input: &str,
    label: &str,
) -> Result<serde_json::Value, contract::AuthorityError> {
    let value = parse_strict(input.as_bytes()).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
    })?;
    let canonical = canonicalize(&value).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
    })?;
    if canonical.as_str() != input {
        return Err(contract::AuthorityError::AuthorityIntegrity(format!(
            "stored {label} is not canonical"
        )));
    }
    Ok(value)
}

const fn localized_result_kind_name(
    kind: contract::LocalizedConsequenceResultKindV1,
) -> &'static str {
    match kind {
        contract::LocalizedConsequenceResultKindV1::Success => "success",
        contract::LocalizedConsequenceResultKindV1::Failure => "failure",
    }
}

fn load_authenticated_localized_consequence_rows(
    connection: &Connection,
) -> Result<Vec<AuthenticatedLocalizedConsequenceRow>, contract::AuthorityError> {
    let mut statement = connection
        .prepare(
            "SELECT decision_authority_sequence, presentation_id, workspace_id,
                    requesting_principal_id, operating_principal_id, delegation_id,
                    command_digest, authorization_decision_digest, operation_name,
                    operation_version, application_idempotency_kind,
                    application_idempotency_key, result_kind, result_contract,
                    result_json, result_digest, application_effect_digest,
                    application_consequence_digest, selectors_json, evidence_json,
                    evidence_digest
             FROM authenticated_localized_consequences_v1
             ORDER BY decision_authority_sequence",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    statement
        .query_map([], |row| {
            Ok(AuthenticatedLocalizedConsequenceRow {
                decision_authority_sequence: row.get(0)?,
                presentation_id: row.get(1)?,
                workspace_id: row.get(2)?,
                requesting_principal_id: row.get(3)?,
                operating_principal_id: row.get(4)?,
                delegation_id: row.get(5)?,
                command_digest: row.get(6)?,
                authorization_decision_digest: row.get(7)?,
                operation_name: row.get(8)?,
                operation_version: row.get(9)?,
                application_idempotency_kind: row.get(10)?,
                application_idempotency_key: row.get(11)?,
                result_kind: row.get(12)?,
                result_contract: row.get(13)?,
                result_json: row.get(14)?,
                result_digest: row.get(15)?,
                application_effect_digest: row.get(16)?,
                application_consequence_digest: row.get(17)?,
                selectors_json: row.get(18)?,
                evidence_json: row.get(19)?,
                evidence_digest: row.get(20)?,
            })
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))
}

#[expect(
    clippy::too_many_lines,
    reason = "P5 verification reconstructs the signed result, immutable application anchors, and global idempotency ledger as one closed projection"
)]
fn verify_authenticated_localized_consequence_projection(
    connection: &Connection,
    workspace_id: WorkspaceId,
    records: &[VerifiedAuthorityProjectionRecord],
) -> Result<(), contract::AuthorityError> {
    let signed_decisions = records
        .iter()
        .filter_map(|record| match &record.record {
            contract::AuthorityRecordV1::AuthorizationDecision(decision)
                if decision.decision == contract::AuthorizationDecisionOutcome::Allow
                    && contract::localized_operation_output_schema_uri(decision.operation)
                        .is_some() =>
            {
                Some((
                    decision.authority_sequence.get(),
                    (decision, record.record_digest.as_str()),
                ))
            }
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let rows = load_authenticated_localized_consequence_rows(connection)?;
    if rows.len() != signed_decisions.len() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authenticated localized consequences do not exactly cover signed localized Allow decisions"
                .to_owned(),
        ));
    }

    let mut seen_sequences = BTreeSet::new();
    let mut expected_ledger = BTreeMap::<(String, String), ExpectedApplicationLedgerRow>::new();
    for row in &rows {
        let sequence = u64::try_from(row.decision_authority_sequence).map_err(|_| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized consequence authority sequence is out of range".to_owned(),
            )
        })?;
        if !seen_sequences.insert(sequence) {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized consequence authority sequence is duplicated".to_owned(),
            ));
        }
        let (decision, decision_digest) =
            signed_decisions.get(&sequence).copied().ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized consequence has no matching signed Allow decision".to_owned(),
                )
            })?;
        let commitment = decision
            .localized_consequence_commitment
            .as_ref()
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized Allow decision lacks its signed consequence commitment".to_owned(),
                )
            })?;
        let expected_result_kind = localized_result_kind_name(commitment.result_kind);
        let operation_output_schema = contract::localized_operation_output_schema_uri(
            decision.operation,
        )
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "signed localized operation has no output Schema".to_owned(),
            )
        })?;
        let expected_selectors_value = json!({
            "changeset_ids": decision.requested_resources.changeset_ids,
            "edition_ids": decision.requested_resources.edition_ids,
            "release_ids": decision.requested_resources.release_ids,
        });
        let selectors_value =
            canonical_projection_value(&row.selectors_json, "localized selectors")?;
        let result_value = canonical_projection_value(&row.result_json, "localized result")?;
        let result_canonical = canonicalize(&result_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let computed_result_digest = digest(ArtifactKind::OperationEffectV1, &result_canonical);
        let evidence_value =
            canonical_projection_value(&row.evidence_json, "localized consequence evidence")?;
        let closure = evidence_value.get("closure").cloned().ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized consequence evidence has no closure".to_owned(),
            )
        })?;
        let semantic_timestamp = evidence_value
            .get("semantic_timestamp")
            .cloned()
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized consequence evidence has no semantic timestamp".to_owned(),
                )
            })?;
        if !(semantic_timestamp.is_null() || semantic_timestamp.is_string()) {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized consequence semantic timestamp is malformed".to_owned(),
            ));
        }
        let expected_idempotency = expected_localized_idempotency_projection(
            decision.operation,
            expected_result_kind,
            row.application_idempotency_kind.as_str(),
            row.application_idempotency_key.as_deref(),
        );
        if row.workspace_id != workspace_id.to_string()
            || row.workspace_id != decision.workspace_id.to_string()
            || row.presentation_id != decision.presentation_id.to_string()
            || row.requesting_principal_id != decision.requesting_principal_id.to_string()
            || row.operating_principal_id != decision.operating_principal_id.to_string()
            || row.delegation_id != decision.delegation.delegation_id.to_string()
            || row.command_digest != decision.command_digest.to_string()
            || row.authorization_decision_digest != decision_digest
            || row.operation_name != decision.operation.name()
            || row.operation_version != decision.operation.version()
            || row.result_kind != expected_result_kind
            || row.result_contract != commitment.result_contract
            || row.result_digest != commitment.result_digest.to_string()
            || computed_result_digest != commitment.result_digest
            || row.application_consequence_digest
                != commitment.application_consequence_digest.to_string()
            || selectors_value != expected_selectors_value
            || !expected_idempotency
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authenticated localized consequence differs from its signed decision".to_owned(),
            ));
        }

        verify_localized_immutable_closure(connection, decision, &closure)?;
        verify_localized_application_effect_projection(
            connection,
            decision.operation,
            row,
            &result_value,
            &closure,
        )?;

        let composite = canonicalize(&json!({
            "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
            "application_effect_digest": row.application_effect_digest,
            "application_idempotency": {
                "key": row.application_idempotency_key,
                "kind": row.application_idempotency_kind,
            },
            "closure": closure,
            "command_digest": decision.command_digest.to_string(),
            "delegation_id": decision.delegation.delegation_id.to_string(),
            "operating_principal_id": decision.operating_principal_id.to_string(),
            "operation": {
                "name": decision.operation.name(),
                "version": decision.operation.version(),
            },
            "requesting_principal_id": decision.requesting_principal_id.to_string(),
            "result": {
                "contract": row.result_contract,
                "digest": row.result_digest,
                "kind": row.result_kind,
            },
            "selectors": selectors_value,
            "semantic_timestamp": semantic_timestamp,
            "workspace_id": decision.workspace_id.to_string(),
        }))
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let computed_consequence_digest = digest(ArtifactKind::OperationEffectV1, &composite);
        if computed_consequence_digest != commitment.application_consequence_digest {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized application consequence does not reproduce its signed composite"
                    .to_owned(),
            ));
        }

        let expected_evidence = canonicalize(&json!({
            "api_version": "proof.dev/authenticated-localized-consequence/v1",
            "application_consequence_digest": row.application_consequence_digest,
            "application_idempotency": {
                "key": row.application_idempotency_key,
                "kind": row.application_idempotency_kind,
            },
            "authorization_decision_digest": decision_digest,
            "closure": evidence_value.get("closure"),
            "command_digest": decision.command_digest.to_string(),
            "delegation_id": decision.delegation.delegation_id.to_string(),
            "operating_principal_id": decision.operating_principal_id.to_string(),
            "operation": {
                "name": decision.operation.name(),
                "version": decision.operation.version(),
            },
            "operation_output_schema": operation_output_schema,
            "presentation_id": decision.presentation_id.to_string(),
            "requesting_principal_id": decision.requesting_principal_id.to_string(),
            "result": {
                "contract": row.result_contract,
                "digest": row.result_digest,
                "kind": row.result_kind,
            },
            "application_effect_digest": row.application_effect_digest,
            "selectors": evidence_value.get("selectors"),
            "semantic_timestamp": evidence_value.get("semantic_timestamp"),
            "workspace_id": decision.workspace_id.to_string(),
        }))
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let evidence_canonical = canonicalize(&evidence_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let computed_evidence_digest = digest(ArtifactKind::OperationEffectV1, &evidence_canonical);
        if expected_evidence.as_str() != row.evidence_json
            || computed_evidence_digest.to_string() != row.evidence_digest
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized consequence evidence does not exactly reproduce".to_owned(),
            ));
        }

        if row.result_kind == "success"
            && let Some(key) = row.application_idempotency_key.as_ref()
        {
            register_expected_application_ledger_row(&mut expected_ledger, row, key)?;
        }
    }
    if seen_sequences != signed_decisions.keys().copied().collect() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "signed localized Allow decision lacks consequence evidence".to_owned(),
        ));
    }
    verify_authenticated_application_ledger_projection(connection, &expected_ledger)
}

fn expected_localized_idempotency_projection(
    operation: contract::AuthorityOperation,
    result_kind: &str,
    actual_kind: &str,
    actual_key: Option<&str>,
) -> bool {
    match contract::authority_operation_entry(operation).application_idempotency {
        contract::ApplicationIdempotency::None => actual_kind == "none" && actual_key.is_none(),
        contract::ApplicationIdempotency::RequiredUuidV7 => {
            actual_kind == "required" && actual_key.is_some()
        }
        contract::ApplicationIdempotency::DerivedChangeset
        | contract::ApplicationIdempotency::DerivedProposalPolicyValidator => {
            actual_kind == "derived" && (result_kind == "failure" || actual_key.is_some())
        }
    }
}

fn register_expected_application_ledger_row(
    expected: &mut BTreeMap<(String, String), ExpectedApplicationLedgerRow>,
    row: &AuthenticatedLocalizedConsequenceRow,
    key: &str,
) -> Result<(), contract::AuthorityError> {
    let map_key = (row.workspace_id.clone(), key.to_owned());
    let candidate = ExpectedApplicationLedgerRow {
        workspace_id: row.workspace_id.clone(),
        idempotency_key: key.to_owned(),
        idempotency_kind: row.application_idempotency_kind.clone(),
        operation_name: row.operation_name.clone(),
        operation_version: row.operation_version.clone(),
        command_digest: row.command_digest.clone(),
        result_digest: row.result_digest.clone(),
        application_effect_digest: row.application_effect_digest.clone(),
        application_consequence_digest: row.application_consequence_digest.clone(),
        first_decision_authority_sequence: row.decision_authority_sequence,
    };
    if let Some(first) = expected.get(&map_key) {
        if first.idempotency_kind != candidate.idempotency_kind
            || first.operation_name != candidate.operation_name
            || first.operation_version != candidate.operation_version
            || first.command_digest != candidate.command_digest
            || first.result_digest != candidate.result_digest
            || first.application_effect_digest != candidate.application_effect_digest
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authenticated application key has divergent successful consequences".to_owned(),
            ));
        }
        return Ok(());
    }
    expected.insert(map_key, candidate);
    Ok(())
}

fn verify_authenticated_application_ledger_projection(
    connection: &Connection,
    expected: &BTreeMap<(String, String), ExpectedApplicationLedgerRow>,
) -> Result<(), contract::AuthorityError> {
    let expected_rows = expected
        .values()
        .map(|row| {
            json!({
                "application_consequence_digest": row.application_consequence_digest,
                "application_effect_digest": row.application_effect_digest,
                "command_digest": row.command_digest,
                "first_decision_authority_sequence": row.first_decision_authority_sequence,
                "idempotency_key": row.idempotency_key,
                "idempotency_kind": row.idempotency_kind,
                "operation_name": row.operation_name,
                "operation_version": row.operation_version,
                "result_digest": row.result_digest,
                "workspace_id": row.workspace_id,
            })
        })
        .collect::<Vec<_>>();
    let actual_rows = query_projection_rows(
        connection,
        "SELECT workspace_id, idempotency_key, idempotency_kind, operation_name,
                operation_version, command_digest, result_digest,
                application_effect_digest, application_consequence_digest,
                first_decision_authority_sequence
         FROM authenticated_application_idempotency_v1",
        |row| {
            Ok(json!({
                "application_consequence_digest": row.get::<_, String>(8)?,
                "application_effect_digest": row.get::<_, String>(7)?,
                "command_digest": row.get::<_, String>(5)?,
                "first_decision_authority_sequence": row.get::<_, i64>(9)?,
                "idempotency_key": row.get::<_, String>(1)?,
                "idempotency_kind": row.get::<_, String>(2)?,
                "operation_name": row.get::<_, String>(3)?,
                "operation_version": row.get::<_, String>(4)?,
                "result_digest": row.get::<_, String>(6)?,
                "workspace_id": row.get::<_, String>(0)?,
            }))
        },
    )?;
    verify_projection_row_set(
        "authenticated application idempotency projection",
        &expected_rows,
        &actual_rows,
    )?;
    let overlap = connection
        .query_row(
            "SELECT COUNT(*)
             FROM authenticated_application_idempotency_v1 AS localized
             JOIN authenticated_operation_results_v1 AS legacy
               ON legacy.workspace_id = localized.workspace_id
              AND legacy.idempotency_key = localized.idempotency_key",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if overlap != 0 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "an application idempotency key is owned by both legacy and localized ledgers"
                .to_owned(),
        ));
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "localized closure verification keeps historical monotonicity and immutable P7 artifact checks adjacent"
)]
fn verify_localized_immutable_closure(
    connection: &Connection,
    decision: &contract::AuthorizationDecisionV2,
    closure: &serde_json::Value,
) -> Result<(), contract::AuthorityError> {
    let closure_object = closure.as_object().ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "localized application closure is not an object".to_owned(),
        )
    })?;
    if !closure_object.contains_key("resource_intent") {
        let edition_ids = decision
            .requested_resources
            .edition_ids
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let release_ids = decision
            .requested_resources
            .release_ids
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if edition_ids.len() > 1 || release_ids.len() > 1 {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized released closure has multiple resolved artifacts".to_owned(),
            ));
        }
        let expected = json!({
            "edition_id": edition_ids.first(),
            "release_id": release_ids.first(),
            "schema_ids": decision
                .requested_resources
                .schema_ids
                .as_slice()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        });
        if &expected != closure {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized released closure differs from signed selectors".to_owned(),
            ));
        }
        return verify_released_closure_artifacts(connection, decision.workspace_id, closure);
    }

    let intent = closure_object
        .get("resource_intent")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized intent closure has no resource intent".to_owned(),
            )
        })?;
    let intent_id = required_json_string(
        closure_object
            .get("resource_intent")
            .unwrap_or(&serde_json::Value::Null),
        "intent_id",
        "localized intent closure",
    )?;
    let intent_digest = required_json_string(
        closure_object
            .get("resource_intent")
            .unwrap_or(&serde_json::Value::Null),
        "intent_digest",
        "localized intent closure",
    )?;
    let intent_issuer = required_json_string(
        closure_object
            .get("resource_intent")
            .unwrap_or(&serde_json::Value::Null),
        "issued_by_principal_id",
        "localized intent closure",
    )?;
    if intent.len() != 3
        || closure_object
            .get("validator")
            .and_then(serde_json::Value::as_str)
            != Some(proof_application::LOCALIZED_CONTENT_VALIDATOR)
        || !closure_object
            .get("context_fresh")
            .is_some_and(serde_json::Value::is_boolean)
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized intent closure shape is malformed".to_owned(),
        ));
    }
    verify_localized_intent_artifact(
        connection,
        decision.workspace_id,
        intent_id,
        intent_digest,
        intent_issuer,
    )?;

    if let Some(context) = closure_object
        .get("context")
        .filter(|value| !value.is_null())
    {
        verify_localized_context_artifact(
            connection,
            decision.workspace_id,
            intent_id,
            intent_digest,
            context,
        )?;
    }
    let changeset_id = if let Some(changeset) = closure_object
        .get("changeset")
        .filter(|value| !value.is_null())
    {
        Some(verify_localized_changeset_artifact(
            connection,
            decision.workspace_id,
            intent_id,
            intent_digest,
            changeset,
        )?)
    } else {
        None
    };
    if let Some(approval) = closure_object
        .get("approval")
        .filter(|value| !value.is_null())
    {
        let changeset_id = changeset_id.as_deref().ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized approval closure has no ChangeSet anchor".to_owned(),
            )
        })?;
        verify_localized_approval_artifact(connection, changeset_id, approval)?;
    }
    let exact = json!({
        "approval": closure_object.get("approval"),
        "changeset": closure_object.get("changeset"),
        "context": closure_object.get("context"),
        "context_fresh": closure_object.get("context_fresh"),
        "resource_intent": closure_object.get("resource_intent"),
        "validator": closure_object.get("validator"),
    });
    if &exact != closure {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized intent closure has unknown or missing fields".to_owned(),
        ));
    }
    Ok(())
}

fn verify_released_closure_artifacts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    closure: &serde_json::Value,
) -> Result<(), contract::AuthorityError> {
    if let Some(release_id) = closure
        .get("release_id")
        .and_then(serde_json::Value::as_str)
    {
        let stored_workspace = connection
            .query_row(
                "SELECT workspace_id FROM releases WHERE release_id = ?1",
                [release_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        if stored_workspace != workspace_id.to_string() {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized released closure references another Workspace".to_owned(),
            ));
        }
        let release_id = release_id
            .parse::<proof_application::ReleaseId>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        localized::load_localized_release(connection, workspace_id, release_id).map_err(
            |error| {
                contract::AuthorityError::AuthorityIntegrity(format!(
                    "localized released-selection verification failed: {error:?}"
                ))
            },
        )?;
    }
    if let Some(edition_id) = closure
        .get("edition_id")
        .and_then(serde_json::Value::as_str)
    {
        let exists = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM editions WHERE edition_id = ?1)",
                [edition_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if !exists {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized released closure Edition is absent".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_localized_intent_artifact(
    connection: &Connection,
    workspace_id: WorkspaceId,
    intent_id: &str,
    signed_digest: &str,
    signed_issuer: &str,
) -> Result<(), contract::AuthorityError> {
    let parsed_intent_id = intent_id
        .parse::<proof_application::ContentResourceIntentId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let loaded = localized::load_resource_intent(connection, workspace_id, parsed_intent_id)
        .map_err(|error| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "localized resource-intent verification failed: {error:?}"
            ))
        })?;
    let (stored_workspace, issuer, manifest_json, stored_digest): (String, String, String, String) =
        connection
            .query_row(
                "SELECT workspace_id, issued_by_principal_id, manifest_json, intent_digest
                 FROM content_resource_intents WHERE intent_id = ?1",
                [intent_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let manifest = canonical_projection_value(&manifest_json, "localized resource intent")?;
    let manifest = canonicalize(&manifest)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let computed = digest(ArtifactKind::ContentResourceIntentV1, &manifest);
    if stored_workspace != workspace_id.to_string()
        || issuer != signed_issuer
        || stored_digest != signed_digest
        || computed.to_string() != stored_digest
        || loaded.intent_digest.to_string() != signed_digest
        || loaded.issued_by_principal_id.to_string() != signed_issuer
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized resource-intent artifact does not reproduce".to_owned(),
        ));
    }
    Ok(())
}

fn verify_localized_context_artifact(
    connection: &Connection,
    workspace_id: WorkspaceId,
    intent_id: &str,
    intent_digest: &str,
    context: &serde_json::Value,
) -> Result<(), contract::AuthorityError> {
    let context_id = required_json_string(context, "context_pack_id", "localized ContextPack")?;
    let context_digest =
        required_json_string(context, "context_pack_digest", "localized ContextPack")?;
    let policy_digest = required_json_string(context, "policy_digest", "localized ContextPack")?;
    let parsed_context_id = context_id
        .parse::<ContextPackId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let loaded =
        localized::load_context(connection, workspace_id, parsed_context_id).map_err(|error| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "localized ContextPack verification failed: {error:?}"
            ))
        })?;
    let limits = context.get("limits").ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "localized ContextPack closure has no limits".to_owned(),
        )
    })?;
    let row: (
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
    ) = connection
        .query_row(
            "SELECT workspace_id, resource_intent_id, resource_intent_digest,
                        policy_digest, context_pack_digest, max_objects, max_edits,
                        max_validation_attempts, max_bytes, policy_json, manifest_json,
                        principal_id
                 FROM localized_context_packs WHERE context_pack_id = ?1",
            [context_id],
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
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let policy_value = canonical_projection_value(&row.9, "localized policy")?;
    let policy_canonical = canonicalize(&policy_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let manifest_value = canonical_projection_value(&row.10, "localized ContextPack")?;
    let manifest_canonical = canonicalize(&manifest_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let exact_context = json!({
        "context_pack_digest": context_digest,
        "context_pack_id": context_id,
        "limits": {
            "max_bytes": row.8,
            "max_edits": row.6,
            "max_objects": row.5,
            "max_validation_attempts": row.7,
        },
        "policy_digest": policy_digest,
    });
    if row.0 != workspace_id.to_string()
        || row.1 != intent_id
        || row.2 != intent_digest
        || row.3 != policy_digest
        || row.4 != context_digest
        || loaded.resource_intent_id.to_string() != intent_id
        || loaded.resource_intent_digest.to_string() != intent_digest
        || loaded.context_pack_digest.to_string() != context_digest
        || loaded.policy_digest.to_string() != policy_digest
        || limits
            != exact_context
                .get("limits")
                .unwrap_or(&serde_json::Value::Null)
        || digest(ArtifactKind::PolicyBundleV1, &policy_canonical).to_string() != row.3
        || digest(ArtifactKind::ContextPackV2, &manifest_canonical).to_string() != row.4
        || &exact_context != context
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized ContextPack artifact does not reproduce".to_owned(),
        ));
    }
    Ok(())
}

fn verify_localized_changeset_artifact(
    connection: &Connection,
    workspace_id: WorkspaceId,
    intent_id: &str,
    intent_digest: &str,
    changeset: &serde_json::Value,
) -> Result<String, contract::AuthorityError> {
    let changeset_id = required_json_string(changeset, "changeset_id", "localized ChangeSet")?;
    let parsed_changeset_id = changeset_id
        .parse::<proof_application::ChangeSetId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let loaded = localized::load_changeset(connection, workspace_id, parsed_changeset_id).map_err(
        |error| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "localized ChangeSet verification failed: {error:?}"
            ))
        },
    )?;
    let context_pack_id =
        required_json_string(changeset, "context_pack_id", "localized ChangeSet")?;
    let context_pack_digest =
        required_json_string(changeset, "context_pack_digest", "localized ChangeSet")?;
    let row: (String, String, String, String, String) = connection
        .query_row(
            "SELECT workspace_id, resource_intent_id, resource_intent_digest,
                    context_pack_id, context_pack_digest
             FROM localized_changesets WHERE changeset_id = ?1",
            [changeset_id],
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
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let exact = json!({
        "changeset_id": changeset_id,
        "context_pack_digest": context_pack_digest,
        "context_pack_id": context_pack_id,
        "resource_intent_digest": intent_digest,
        "resource_intent_id": intent_id,
    });
    if row.0 != workspace_id.to_string()
        || row.1 != intent_id
        || row.2 != intent_digest
        || row.3 != context_pack_id
        || row.4 != context_pack_digest
        || loaded.resource_intent_id.to_string() != intent_id
        || loaded.resource_intent_digest.to_string() != intent_digest
        || loaded.context_pack_id.to_string() != context_pack_id
        || loaded.context_pack_digest.to_string() != context_pack_digest
        || &exact != changeset
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized ChangeSet closure does not reproduce".to_owned(),
        ));
    }
    Ok(changeset_id.to_owned())
}

fn verify_localized_approval_artifact(
    connection: &Connection,
    changeset_id: &str,
    approval: &serde_json::Value,
) -> Result<(), contract::AuthorityError> {
    let row: (String, String, String, String, String, String, String) = connection
        .query_row(
            "SELECT approval.approval_name, approval.sealed_changeset_digest,
                    approval.validation_results_digest, approval.principal_id,
                    approval.approved_at, approval.effect_digest,
                    principal.principal_type
             FROM localized_approvals AS approval
             JOIN principals AS principal
               ON principal.principal_id = approval.principal_id
             WHERE approval.changeset_id = ?1",
            [changeset_id],
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
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.approve/v2",
        "result": {
            "approval": row.0,
            "changeset_id": changeset_id,
            "occurred_at": row.4,
            "principal_id": row.3,
            "sealed_changeset_digest": row.1,
            "validation_results_digest": row.2,
        },
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let exact = json!({
        "approval_name": row.0,
        "approved_at": row.4,
        "effect_digest": row.5,
        "principal_id": row.3,
    });
    if row.6 != "human" {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized approval principal is not a Human".to_owned(),
        ));
    }
    if digest(ArtifactKind::OperationEffectV1, &effect).to_string() != row.5 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized approval effect does not reproduce".to_owned(),
        ));
    }
    if &exact != approval {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized signed approval closure differs from immutable evidence".to_owned(),
        ));
    }
    Ok(())
}

fn query_localized_projection_digest<P: rusqlite::Params>(
    connection: &Connection,
    statement: &str,
    params: P,
) -> Result<String, contract::AuthorityError> {
    connection
        .query_row(statement, params, |row| row.get::<_, String>(0))
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
}

fn localized_result_string<'a>(
    result: &'a serde_json::Value,
    field: &str,
) -> Result<&'a str, contract::AuthorityError> {
    required_json_string(result, field, "localized operation result")
}

fn row_workspace_id(
    row: &AuthenticatedLocalizedConsequenceRow,
) -> Result<WorkspaceId, contract::AuthorityError> {
    row.workspace_id
        .parse::<WorkspaceId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
}

fn verify_loaded_changeset_projection(
    connection: &Connection,
    row: &AuthenticatedLocalizedConsequenceRow,
    result: &serde_json::Value,
) -> Result<proof_application::LocalizedChangeSet, contract::AuthorityError> {
    let changeset_id = localized_result_string(result, "changeset_id")?
        .parse::<proof_application::ChangeSetId>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    localized::load_changeset(connection, row_workspace_id(row)?, changeset_id).map_err(|error| {
        contract::AuthorityError::AuthorityIntegrity(format!(
            "localized ChangeSet verification failed: {error:?}"
        ))
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed 11-operation effect verifier makes every P7 reconstruction branch explicit and exhaustive"
)]
fn verify_localized_application_effect_projection(
    connection: &Connection,
    operation: contract::AuthorityOperation,
    row: &AuthenticatedLocalizedConsequenceRow,
    result: &serde_json::Value,
    closure: &serde_json::Value,
) -> Result<(), contract::AuthorityError> {
    if row.result_kind == "failure"
        || matches!(
            operation,
            contract::AuthorityOperation::ChangesetGetV2
                | contract::AuthorityOperation::ChangesetDiffV2
                | contract::AuthorityOperation::ObjectQueryReleasedV2
        )
    {
        if row.application_effect_digest != row.result_digest {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "read or failed localized consequence has a mutable application effect".to_owned(),
            ));
        }
        return Ok(());
    }

    let key = row.application_idempotency_key.as_deref();
    if matches!(
        operation,
        contract::AuthorityOperation::ChangesetCreateV2
            | contract::AuthorityOperation::ChangesetAddV2
    ) {
        verify_loaded_changeset_projection(connection, row, result)?;
    }
    let stored_effect = match operation {
        contract::AuthorityOperation::ContextBuildV2 => query_localized_projection_digest(
            connection,
            "SELECT effect_digest FROM localized_context_build_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                row.workspace_id.as_str(),
                row.requesting_principal_id.as_str(),
                key.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized Context consequence has no application key".to_owned(),
                    )
                })?,
            ),
        )?,
        contract::AuthorityOperation::ChangesetCreateV2 => {
            let changeset_id = localized_result_string(result, "changeset_id")?
                .parse::<proof_application::ChangeSetId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            if key.is_none() {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized ChangeSet create consequence has no application key".to_owned(),
                ));
            }
            localized::verify_changeset_creation_effect(
                connection,
                row_workspace_id(row)?,
                changeset_id,
            )
            .map_err(|error| {
                contract::AuthorityError::AuthorityIntegrity(format!(
                    "localized ChangeSet creation verification failed: {error:?}"
                ))
            })?
            .to_string()
        }
        contract::AuthorityOperation::ChangesetAddV2 => {
            let principal_id = row
                .requesting_principal_id
                .parse::<PrincipalId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            localized::verify_add_effect(
                connection,
                row_workspace_id(row)?,
                principal_id,
                key.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized Add consequence has no application key".to_owned(),
                    )
                })?,
            )
            .map_err(|error| {
                contract::AuthorityError::AuthorityIntegrity(format!(
                    "localized Add verification failed: {error:?}"
                ))
            })?
            .to_string()
        }
        contract::AuthorityOperation::ChangesetValidateV2 => {
            let validation_digest = localized_result_string(result, "validation_results_digest")?;
            verify_loaded_changeset_projection(connection, row, result)?;
            let stored = query_localized_projection_digest(
                connection,
                "SELECT results_digest FROM localized_validations
                 WHERE results_digest = ?1",
                [validation_digest],
            )?;
            if key.is_none() {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "successful localized validation has no derived application key".to_owned(),
                ));
            }
            stored
        }
        contract::AuthorityOperation::ChangesetSubmitV2 => {
            let changeset_id = localized_result_string(result, "changeset_id")?;
            if key.is_none() {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "successful localized submit has no derived application key".to_owned(),
                ));
            }
            let changeset = verify_loaded_changeset_projection(connection, row, result)?;
            localized::load_localized_submission(connection, &changeset)
                .map_err(|error| {
                    contract::AuthorityError::AuthorityIntegrity(format!(
                        "localized submission verification failed: {error:?}"
                    ))
                })?
                .ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized submission evidence is absent".to_owned(),
                    )
                })?;
            query_localized_projection_digest(
                connection,
                "SELECT effect_digest FROM localized_submissions WHERE changeset_id = ?1",
                [changeset_id],
            )?
        }
        contract::AuthorityOperation::ChangesetCommitV2 => {
            let changeset_id = localized_result_string(result, "changeset_id")?
                .parse::<proof_application::ChangeSetId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            localized::load_localized_commit(connection, row_workspace_id(row)?, changeset_id)
                .map_err(|error| {
                    contract::AuthorityError::AuthorityIntegrity(format!(
                        "localized commit verification failed: {error:?}"
                    ))
                })?;
            query_localized_projection_digest(
                connection,
                "SELECT effect_digest FROM localized_commits
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    row.workspace_id.as_str(),
                    row.requesting_principal_id.as_str(),
                    key.ok_or_else(|| {
                        contract::AuthorityError::AuthorityIntegrity(
                            "localized Commit consequence has no application key".to_owned(),
                        )
                    })?,
                ),
            )?
        }
        contract::AuthorityOperation::EditionCreateV2 => {
            let edition_id = localized_result_string(result, "edition_id")?
                .parse::<proof_application::EditionId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            localized::load_localized_edition(connection, row_workspace_id(row)?, edition_id)
                .map_err(|error| {
                    contract::AuthorityError::AuthorityIntegrity(format!(
                        "localized Edition verification failed: {error:?}"
                    ))
                })?;
            query_localized_projection_digest(
                connection,
                "SELECT effect_digest FROM localized_edition_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    row.workspace_id.as_str(),
                    row.requesting_principal_id.as_str(),
                    key.ok_or_else(|| {
                        contract::AuthorityError::AuthorityIntegrity(
                            "localized Edition consequence has no application key".to_owned(),
                        )
                    })?,
                ),
            )?
        }
        contract::AuthorityOperation::ReleaseCreateV2 => {
            let release_id = localized_result_string(result, "release_id")?;
            let release_digest = localized_result_string(result, "release_digest")?;
            let parsed_release_id = release_id
                .parse::<proof_application::ReleaseId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            localized::load_localized_release(
                connection,
                row_workspace_id(row)?,
                parsed_release_id,
            )
            .map_err(|error| {
                contract::AuthorityError::AuthorityIntegrity(format!(
                    "localized Release verification failed: {error:?}"
                ))
            })?;
            let stored = query_localized_projection_digest(
                connection,
                "SELECT release_digest FROM releases
                 WHERE workspace_id = ?1 AND release_id = ?2",
                (row.workspace_id.as_str(), release_id),
            )?;
            let operation_exists = connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM localized_release_operations
                         WHERE workspace_id = ?1 AND principal_id = ?2
                           AND idempotency_key = ?3 AND release_id = ?4
                     )",
                    (
                        row.workspace_id.as_str(),
                        row.requesting_principal_id.as_str(),
                        key.ok_or_else(|| {
                            contract::AuthorityError::AuthorityIntegrity(
                                "localized Release consequence has no application key".to_owned(),
                            )
                        })?,
                        release_id,
                    ),
                    |query_row| query_row.get::<_, bool>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if !operation_exists || stored != release_digest {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized Release effect does not reproduce".to_owned(),
                ));
            }
            stored
        }
        contract::AuthorityOperation::ChangesetGetV2
        | contract::AuthorityOperation::ChangesetDiffV2
        | contract::AuthorityOperation::ObjectQueryReleasedV2 => {
            unreachable!("read operations returned before effect lookup")
        }
        contract::AuthorityOperation::ContextBuildV1
        | contract::AuthorityOperation::ObjectQueryReleasedV1
        | contract::AuthorityOperation::WorkspaceStatusV1 => {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "legacy operation reached localized application-effect verification".to_owned(),
            ));
        }
    };
    if stored_effect != row.application_effect_digest {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized application effect differs from immutable P7 evidence".to_owned(),
        ));
    }
    if closure.is_null() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized success has no application closure".to_owned(),
        ));
    }
    Ok(())
}

fn load_workspace_authority_root(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<contract::WorkspaceAuthorityRootV1, contract::AuthorityError> {
    let root_json = transaction
        .query_row(
            "SELECT root_json FROM workspace_authority_roots
             WHERE workspace_id = ?1 AND active = 1",
            [workspace_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let root: contract::WorkspaceAuthorityRootV1 =
        decode_canonical(&root_json, "Workspace authority root")?;
    root.validate()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if root.workspace_id != workspace_id {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "Workspace authority root has the wrong Workspace".to_owned(),
        ));
    }
    let public_key = BASE64.decode(root.public_key.as_str()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "Workspace authority root public key is malformed".to_owned(),
        )
    })?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "Workspace authority root public key has the wrong length".to_owned(),
        )
    })?;
    if BASE64.encode(public_key) != root.public_key.as_str()
        || proof_attestation::ed25519_key_id(&public_key) != root.authority_key_id.as_str()
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "Workspace authority root key identity disagrees with public bytes".to_owned(),
        ));
    }
    Ok(root)
}

fn load_authority_head(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
) -> Result<Option<contract::AuthorityHeadV1>, contract::AuthorityError> {
    let row = transaction
        .query_row(
            "SELECT authority_sequence, record_digest FROM authority_records
             WHERE workspace_id = ?1 ORDER BY authority_sequence DESC LIMIT 1",
            [workspace_id.to_string()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    row.map(|(sequence, digest)| {
        let sequence = u64::try_from(sequence).map_err(|_| {
            contract::AuthorityError::AuthorityIntegrity(
                "authority sequence is negative or out of range".to_owned(),
            )
        })?;
        Ok(contract::AuthorityHeadV1 {
            sequence: contract::AuthoritySequence::new(sequence)
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?,
            record_digest: digest
                .parse::<proof_application::ContentDigest>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?,
        })
    })
    .transpose()
}

fn load_principal_status(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
) -> Result<Option<contract::PrincipalStatusV1>, contract::AuthorityError> {
    let json = transaction
        .query_row(
            "SELECT records.record_json
             FROM principal_status_v1 status
             JOIN authority_records records
               ON records.authority_sequence = status.authority_sequence
             WHERE status.workspace_id = ?1 AND status.principal_id = ?2
             ORDER BY status.authority_sequence DESC LIMIT 1",
            (workspace_id.to_string(), principal_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    json.map(|value| decode_canonical(&value, "Principal status"))
        .transpose()
}

fn load_principal_binding(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    binding_id: proof_application::BindingId,
) -> Result<Option<contract::PrincipalBindingV1>, contract::AuthorityError> {
    let json = transaction
        .query_row(
            "SELECT records.record_json
             FROM principal_bindings_v1 binding
             JOIN authority_records records
               ON records.authority_sequence = binding.authority_sequence
             WHERE binding.workspace_id = ?1 AND binding.binding_id = ?2",
            (workspace_id.to_string(), binding_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    json.map(|value| decode_canonical(&value, "Principal binding"))
        .transpose()
}

fn load_principal_binding_revocation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    binding_id: proof_application::BindingId,
) -> Result<Option<contract::PrincipalBindingRevocationV1>, contract::AuthorityError> {
    let json = transaction
        .query_row(
            "SELECT records.record_json
             FROM principal_binding_revocations_v1 revocation
             JOIN authority_records records
               ON records.authority_sequence = revocation.authority_sequence
             WHERE revocation.workspace_id = ?1 AND revocation.binding_id = ?2",
            (workspace_id.to_string(), binding_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    json.map(|value| decode_canonical(&value, "Principal binding revocation"))
        .transpose()
}

fn load_delegation_v2(
    transaction: &Connection,
    workspace_id: WorkspaceId,
    delegation_id: proof_application::DelegationId,
) -> Result<Option<contract::DelegationV2>, contract::AuthorityError> {
    let json = transaction
        .query_row(
            "SELECT records.record_json
             FROM delegations_v2 delegation
             JOIN authority_records records
               ON records.authority_sequence = delegation.authority_sequence
             WHERE delegation.workspace_id = ?1 AND delegation.delegation_id = ?2",
            (workspace_id.to_string(), delegation_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    json.map(|value| decode_canonical(&value, "Delegation v2"))
        .transpose()
}

fn load_delegation_revocation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    delegation_id: proof_application::DelegationId,
) -> Result<Option<contract::DelegationRevocationV1>, contract::AuthorityError> {
    let json = transaction
        .query_row(
            "SELECT records.record_json
             FROM delegation_revocations_v2 revocation
             JOIN authority_records records
               ON records.authority_sequence = revocation.authority_sequence
             WHERE revocation.workspace_id = ?1 AND revocation.delegation_id = ?2",
            (workspace_id.to_string(), delegation_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    json.map(|value| decode_canonical(&value, "Delegation revocation"))
        .transpose()
}

impl contract::AuthorityRepository for LocalWorkspace {
    fn workspace_authority_root(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<contract::WorkspaceAuthorityRootV1, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_workspace_authority_root(transaction, workspace_id)
        })
    }

    fn authority_head(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Option<contract::AuthorityHeadV1>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_authority_head(transaction, workspace_id)
        })
    }

    fn principal_status(
        &self,
        workspace_id: WorkspaceId,
        principal_id: PrincipalId,
    ) -> Result<Option<contract::PrincipalStatusV1>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_principal_status(transaction, workspace_id, principal_id)
        })
    }

    fn principal_binding(
        &self,
        workspace_id: WorkspaceId,
        binding_id: proof_application::BindingId,
    ) -> Result<Option<contract::PrincipalBindingV1>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_principal_binding(transaction, workspace_id, binding_id)
        })
    }

    fn principal_binding_revocation(
        &self,
        workspace_id: WorkspaceId,
        binding_id: proof_application::BindingId,
    ) -> Result<Option<contract::PrincipalBindingRevocationV1>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_principal_binding_revocation(transaction, workspace_id, binding_id)
        })
    }

    fn delegation_v2(
        &self,
        workspace_id: WorkspaceId,
        delegation_id: proof_application::DelegationId,
    ) -> Result<Option<contract::DelegationV2>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_delegation_v2(transaction, workspace_id, delegation_id)
        })
    }

    fn delegation_revocation(
        &self,
        workspace_id: WorkspaceId,
        delegation_id: proof_application::DelegationId,
    ) -> Result<Option<contract::DelegationRevocationV1>, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            load_delegation_revocation(transaction, workspace_id, delegation_id)
        })
    }

    fn consumed_presentation(
        &self,
        workspace_id: WorkspaceId,
        presentation_id: proof_application::PresentationId,
    ) -> Result<bool, contract::AuthorityError> {
        self.with_authority_transaction(|transaction, actual_workspace_id, _, _, _, _| {
            if actual_workspace_id != workspace_id {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "requested Workspace does not match selected Workspace".to_owned(),
                ));
            }
            transaction
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM presentation_consumptions_v1
                         WHERE workspace_id = ?1 AND presentation_id = ?2
                     )",
                    (workspace_id.to_string(), presentation_id.to_string()),
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))
        })
    }

    fn append_authority_record(
        &self,
        record: contract::AuthorityRecordV1,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    record,
                )
            },
        )
    }
}

impl contract::AuthorityAdministrator for LocalWorkspace {
    fn create_binding_enrollment_challenge(
        &self,
        challenge: contract::BindingEnrollmentChallengeV1,
    ) -> Result<contract::RecordedEnrollmentChallengeV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, _, trusted_at| {
                challenge
                    .validate()
                    .map_err(|_| contract::AuthorityError::AuthMalformed)?;
                if challenge.workspace_id != workspace_id
                    || challenge.audience
                        != contract::AuthorityAudience::for_workspace(workspace_id)
                    || challenge.issued_by_principal_id != bootstrap_principal_id
                    || trusted_at < challenge.issued_at
                    || trusted_at >= challenge.expires_at
                {
                    return Err(contract::AuthorityError::AuthDenied);
                }
                let (principal_type, enabled): (String, bool) = transaction
                    .query_row(
                        "SELECT principal_type, enabled FROM principals WHERE principal_id = ?1",
                        [challenge.principal_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                if principal_type != "agent" || !enabled {
                    return Err(contract::AuthorityError::PrincipalDisabled);
                }
                let canonical_challenge_json =
                    canonical_json(&challenge, "binding enrollment challenge")?;
                let value = parse_strict(canonical_challenge_json.as_bytes())
                    .map_err(|_| contract::AuthorityError::AuthMalformed)?;
                let canonical =
                    canonicalize(&value).map_err(|_| contract::AuthorityError::AuthMalformed)?;
                let challenge_digest =
                    digest(ArtifactKind::BindingEnrollmentChallengeV1, &canonical);
                transaction
                    .execute(
                        "INSERT INTO binding_enrollment_challenges (
                             challenge_id, workspace_id, binding_id, principal_id,
                             candidate_key_id, issued_by_principal_id, issued_at,
                             expires_at, challenge_json, challenge_digest
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        (
                            challenge.challenge_id.to_string(),
                            workspace_id.to_string(),
                            challenge.binding_id.to_string(),
                            challenge.principal_id.to_string(),
                            challenge.candidate_key_id.as_str(),
                            bootstrap_principal_id.to_string(),
                            challenge.issued_at.to_string(),
                            challenge.expires_at.to_string(),
                            canonical_challenge_json.as_str(),
                            challenge_digest.to_string(),
                        ),
                    )
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                Ok(contract::RecordedEnrollmentChallengeV1 {
                    challenge: challenge.clone(),
                    canonical_challenge_json,
                    challenge_digest,
                })
            },
        )
    }

    fn issue_principal_binding(
        &self,
        binding: contract::PrincipalBindingV1,
        canonical_enrollment_envelope_json: String,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                let row: (String, String, Option<String>, String) = transaction
                    .query_row(
                        "SELECT challenge_json, challenge_digest, consumed_at, candidate_key_id
                         FROM binding_enrollment_challenges
                         WHERE workspace_id = ?1 AND binding_id = ?2",
                        (workspace_id.to_string(), binding.binding_id.to_string()),
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                let challenge: contract::BindingEnrollmentChallengeV1 =
                    decode_canonical(&row.0, "binding enrollment challenge")?;
                if row.2.is_some()
                    || binding.workspace_id != workspace_id
                    || binding.issued_by_principal_id != bootstrap_principal_id
                    || challenge.binding_id != binding.binding_id
                    || challenge.principal_id != binding.principal_id
                    || challenge.candidate_key_id.as_str() != row.3
                    || challenge.candidate_key_id
                        != binding.public_key.key_id().map_err(|error| {
                            contract::AuthorityError::AuthorityIntegrity(error.to_string())
                        })?
                    || row.1 != binding.enrollment_challenge_digest.to_string()
                    || trusted_at < challenge.issued_at
                    || trusted_at >= challenge.expires_at
                    || binding.issued_at < challenge.issued_at
                    || binding.issued_at >= challenge.expires_at
                {
                    return Err(contract::AuthorityError::AuthDenied);
                }
                let verified = verify_authority_envelope::<contract::BindingEnrollmentChallengeV1>(
                    canonical_enrollment_envelope_json.as_bytes(),
                    AuthorityPayloadProfile::BindingEnrollmentChallenge,
                    &[challenge.candidate_key_id.as_str()],
                )
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
                if verified.parsed.payload != challenge
                    || verified.parsed.payload_json != row.0
                    || verified.parsed.envelope_digest != binding.enrollment_envelope_digest
                {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "binding enrollment proof does not match its challenge".to_owned(),
                    ));
                }
                transaction
                    .execute(
                        "UPDATE binding_enrollment_challenges
                         SET enrollment_envelope_json = ?1,
                             enrollment_envelope_digest = ?2,
                             consumed_at = ?3
                         WHERE challenge_id = ?4 AND consumed_at IS NULL",
                        (
                            verified.parsed.envelope_json.as_str(),
                            verified.parsed.envelope_digest.to_string(),
                            trusted_at.to_string(),
                            challenge.challenge_id.to_string(),
                        ),
                    )
                    .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    contract::AuthorityRecordV1::PrincipalBinding(binding.clone()),
                )
            },
        )
    }

    fn set_principal_status(
        &self,
        status: contract::PrincipalStatusV1,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    contract::AuthorityRecordV1::PrincipalStatus(status.clone()),
                )
            },
        )
    }

    fn revoke_principal_binding(
        &self,
        revocation: contract::PrincipalBindingRevocationV1,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    contract::AuthorityRecordV1::PrincipalBindingRevocation(revocation.clone()),
                )
            },
        )
    }

    fn issue_delegation(
        &self,
        delegation: contract::DelegationV2,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    contract::AuthorityRecordV1::Delegation(delegation.clone()),
                )
            },
        )
    }

    fn revoke_delegation(
        &self,
        revocation: contract::DelegationRevocationV1,
    ) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
        self.with_authority_transaction(
            |transaction, workspace_id, bootstrap_principal_id, _, signer, trusted_at| {
                append_administrative_record(
                    transaction,
                    workspace_id,
                    bootstrap_principal_id,
                    signer,
                    trusted_at,
                    contract::AuthorityRecordV1::DelegationRevocation(revocation.clone()),
                )
            },
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "root transition keeps dual-signature verification, causal storage checks, and resumable cross-store publication visible"
    )]
    fn transition_workspace_authority_root(
        &self,
        transition: contract::WorkspaceAuthorityRootTransitionV1,
        canonical_transition_envelope_json: String,
    ) -> Result<contract::WorkspaceAuthorityRootV1, contract::AuthorityError> {
        let config = self
            .read_config()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let local_identity = self
            .resolved_local_identity()
            .map_err(|_| contract::AuthorityError::AuthDenied)?;
        let mut connection = self
            .open_database()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let (database_workspace_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                     FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if database_workspace_id != workspace_id.to_string() {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "configuration and database Workspace identities differ".to_owned(),
            ));
        }
        let bootstrap_principal_id =
            authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
                .map_err(authority_from_workspace_status)?;
        ensure_latest_schema(&transaction, schema_version).map_err(|error| match error {
            super::LatestSchemaError::Integrity(detail) => {
                contract::AuthorityError::AuthorityIntegrity(detail)
            }
            super::LatestSchemaError::Storage(detail) => contract::AuthorityError::Storage(detail),
        })?;
        let predecessor_signer = self.authority_signer_for_transaction(
            &transaction,
            workspace_id,
            bootstrap_principal_id,
        )?;
        verify_authority_log(&transaction, workspace_id)?;
        transition
            .validate()
            .map_err(|_| contract::AuthorityError::AuthMalformed)?;
        let head = load_authority_head(&transaction, workspace_id)?.ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity("authority log has no head".to_owned())
        })?;
        let predecessor_key_id = predecessor_signer
            .metadata()
            .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?
            .key_id;
        if transition.workspace_id != workspace_id
            || transition.activated_by_principal_id != bootstrap_principal_id
            || transition.predecessor_authority_key_id.as_str() != predecessor_key_id
            || transition.authority_sequence.get() != head.sequence.get() + 1
            || transition.previous_authority_record_digest != head.record_digest
        {
            return Err(contract::AuthorityError::AuthDenied);
        }
        let successor_relative_path =
            successor_authority_key_relative_path(&transition.successor_authority_key_id)?;
        let staging_path = self
            .root
            .join(AUTHORITY_SUCCESSOR_STAGING_KEY_RELATIVE_PATH);
        let successor_path = self.root.join(&successor_relative_path);
        let successor_was_published = successor_path.exists();
        let successor_signer = if successor_was_published {
            if staging_path.exists() {
                return Err(contract::AuthorityError::AuthorityRootUnavailable);
            }
            load_existing_authority_signer(&self.root, &successor_relative_path)?
        } else {
            load_existing_authority_signer(
                &self.root,
                AUTHORITY_SUCCESSOR_STAGING_KEY_RELATIVE_PATH,
            )?
        };
        let successor_metadata = successor_signer
            .metadata()
            .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?;
        if successor_metadata.key_id != transition.successor_authority_key_id.as_str()
            || BASE64.encode(successor_metadata.public_key)
                != transition.successor_public_key.as_str()
        {
            return Err(contract::AuthorityError::AuthorityRootUnavailable);
        }
        let verified = verify_authority_envelope::<contract::WorkspaceAuthorityRootTransitionV1>(
            canonical_transition_envelope_json.as_bytes(),
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            &[
                transition.predecessor_authority_key_id.as_str(),
                transition.successor_authority_key_id.as_str(),
            ],
        )
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        if verified.parsed.payload != transition {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "root-transition envelope payload differs from the requested transition".to_owned(),
            ));
        }
        let record_json = verified.parsed.payload_json;
        let record_value = parse_strict(record_json.as_bytes())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let canonical_record = canonicalize(&record_value)
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        let record_digest = digest(ArtifactKind::AuthorityRecordV1, &canonical_record);
        let sequence = i64::try_from(transition.authority_sequence.get()).map_err(|_| {
            contract::AuthorityError::AuthorityIntegrity(
                "authority sequence is out of range".to_owned(),
            )
        })?;
        transaction
            .execute(
                "INSERT INTO authority_records (
                             authority_sequence, workspace_id,
                             previous_authority_record_digest, record_kind, record_json,
                             record_digest, envelope_json, envelope_digest,
                             authority_key_id, recorded_at
                         ) VALUES (?1, ?2, ?3, 'root_transition', ?4, ?5, ?6, ?7, ?8, ?9)",
                (
                    sequence,
                    workspace_id.to_string(),
                    head.record_digest.to_string(),
                    record_json.as_str(),
                    record_digest.to_string(),
                    verified.parsed.envelope_json.as_str(),
                    verified.parsed.envelope_digest.to_string(),
                    predecessor_key_id.as_str(),
                    transition.activated_at.to_string(),
                ),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        transaction
            .execute(
                "UPDATE workspace_authority_roots SET active = 0
                         WHERE workspace_id = ?1 AND authority_key_id = ?2 AND active = 1",
                (workspace_id.to_string(), predecessor_key_id.as_str()),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        let root = contract::WorkspaceAuthorityRootV1 {
            api_version: contract::WorkspaceAuthorityRootApiVersion::V1,
            workspace_id,
            authority_key_id: transition.successor_authority_key_id.clone(),
            public_key: transition.successor_public_key.clone(),
            algorithm: transition.algorithm,
            created_by_principal_id: bootstrap_principal_id,
            created_at: transition.activated_at,
            predecessor_authority_key_id: Some(transition.predecessor_authority_key_id.clone()),
            root_transition_envelope_digest: Some(verified.parsed.envelope_digest),
        };
        let root_json = canonical_json(&root, "successor authority root")?;
        transaction
            .execute(
                "INSERT INTO workspace_authority_roots (
                             authority_key_id, workspace_id, public_key, algorithm,
                             key_file_relative_path, created_by_principal_id, created_at,
                             predecessor_authority_key_id,
                             root_transition_envelope_digest, root_json, active
                         ) VALUES (?1, ?2, ?3, 'ed25519', ?4, ?5, ?6, ?7, ?8, ?9, 1)",
                (
                    root.authority_key_id.as_str(),
                    workspace_id.to_string(),
                    root.public_key.as_str(),
                    successor_relative_path.as_str(),
                    bootstrap_principal_id.to_string(),
                    root.created_at.to_string(),
                    transition.predecessor_authority_key_id.as_str(),
                    verified.parsed.envelope_digest.to_string(),
                    root_json,
                ),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        verify_authority_log(&transaction, workspace_id)?;
        let publication = if successor_was_published {
            None
        } else {
            Some(publish_successor_authority_key(
                &staging_path,
                &successor_path,
            )?)
        };
        if let Err(error) = transaction.commit() {
            if let Some(publication) = publication
                && publication.rollback().is_err()
            {
                return Err(contract::AuthorityError::AuthorityRootUnavailable);
            }
            return Err(contract::AuthorityError::Storage(error.to_string()));
        }
        Ok(root)
    }
}

struct PendingSuccessorAuthorityKeyPublication {
    staging_path: std::path::PathBuf,
    successor_path: std::path::PathBuf,
    remove_successor_parent_on_rollback: bool,
}

impl PendingSuccessorAuthorityKeyPublication {
    fn rollback(self) -> io::Result<()> {
        fs::rename(&self.successor_path, &self.staging_path)?;
        sync_parent_directory(&self.staging_path)?;
        if self.remove_successor_parent_on_rollback {
            let successor_parent = self.successor_path.parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "successor path has no parent")
            })?;
            fs::remove_dir(successor_parent)?;
            sync_parent_directory(successor_parent)?;
        } else {
            sync_parent_directory(&self.successor_path)?;
        }
        Ok(())
    }
}

fn publish_successor_authority_key(
    staging_path: &Path,
    successor_path: &Path,
) -> Result<PendingSuccessorAuthorityKeyPublication, contract::AuthorityError> {
    let parent = successor_path
        .parent()
        .ok_or(contract::AuthorityError::AuthorityRootUnavailable)?;
    let remove_successor_parent_on_rollback = !parent.exists();
    fs::create_dir_all(parent).map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)?;
    fs::rename(staging_path, successor_path)
        .map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)?;
    let publication = PendingSuccessorAuthorityKeyPublication {
        staging_path: staging_path.to_path_buf(),
        successor_path: successor_path.to_path_buf(),
        remove_successor_parent_on_rollback,
    };
    if sync_parent_directory(successor_path).is_err() {
        publication
            .rollback()
            .map_err(|_| contract::AuthorityError::AuthorityRootUnavailable)?;
        return Err(contract::AuthorityError::AuthorityRootUnavailable);
    }
    Ok(publication)
}

fn successor_authority_key_relative_path(
    key_id: &contract::Ed25519KeyId,
) -> Result<String, contract::AuthorityError> {
    let hex = key_id.as_str().strip_prefix("ed25519:").ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "successor authority key identity is malformed".to_owned(),
        )
    })?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "successor authority key identity is malformed".to_owned(),
        ));
    }
    Ok(format!(".proof/state/authority-roots/{hex}.ed25519"))
}

fn record_previous_digest(
    record: &contract::AuthorityRecordV1,
) -> Option<proof_application::ContentDigest> {
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(value) => {
            value.previous_authority_record_digest
        }
        contract::AuthorityRecordV1::PrincipalBinding(value) => {
            value.previous_authority_record_digest
        }
        contract::AuthorityRecordV1::PrincipalBindingRevocation(value) => {
            Some(value.previous_authority_record_digest)
        }
        contract::AuthorityRecordV1::Delegation(value) => value.previous_authority_record_digest,
        contract::AuthorityRecordV1::DelegationRevocation(value) => {
            Some(value.previous_authority_record_digest)
        }
        contract::AuthorityRecordV1::AuthorizationDecision(value) => {
            Some(value.previous_authority_record_digest)
        }
        contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(value) => {
            Some(value.previous_authority_record_digest)
        }
    }
}

fn record_time(record: &contract::AuthorityRecordV1) -> Timestamp {
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(value) => value.recorded_at,
        contract::AuthorityRecordV1::PrincipalBinding(value) => value.issued_at,
        contract::AuthorityRecordV1::PrincipalBindingRevocation(value) => value.revoked_at,
        contract::AuthorityRecordV1::Delegation(value) => value.issued_at,
        contract::AuthorityRecordV1::DelegationRevocation(value) => value.revoked_at,
        contract::AuthorityRecordV1::AuthorizationDecision(value) => value.evaluated_at,
        contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(value) => value.activated_at,
    }
}

fn authority_record_kind(record: &contract::AuthorityRecordV1) -> &'static str {
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(_) => "principal_status",
        contract::AuthorityRecordV1::PrincipalBinding(_) => "principal_binding",
        contract::AuthorityRecordV1::PrincipalBindingRevocation(_) => {
            "principal_binding_revocation"
        }
        contract::AuthorityRecordV1::Delegation(_) => "delegation_v2",
        contract::AuthorityRecordV1::DelegationRevocation(_) => "delegation_revocation",
        contract::AuthorityRecordV1::AuthorizationDecision(_) => "authorization_decision_v2",
        contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(_) => "root_transition",
    }
}

fn administrative_actor(
    record: &contract::AuthorityRecordV1,
) -> Result<PrincipalId, contract::AuthorityError> {
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(value) => Ok(value.recorded_by_principal_id),
        contract::AuthorityRecordV1::PrincipalBinding(value) => Ok(value.issued_by_principal_id),
        contract::AuthorityRecordV1::PrincipalBindingRevocation(value) => {
            Ok(value.revoked_by_principal_id)
        }
        contract::AuthorityRecordV1::Delegation(value) => Ok(value.issuer_principal_id),
        contract::AuthorityRecordV1::DelegationRevocation(value) => {
            Ok(value.revoked_by_principal_id)
        }
        contract::AuthorityRecordV1::AuthorizationDecision(_) => {
            Err(contract::AuthorityError::AuthorityIntegrity(
                "authorization decisions are kernel-produced".to_owned(),
            ))
        }
        contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(_) => {
            Err(contract::AuthorityError::AuthorityIntegrity(
                "root transitions require the dual-signed transition operation".to_owned(),
            ))
        }
    }
}

fn append_administrative_record(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    signer: &Ed25519SigningProvider,
    trusted_at: Timestamp,
    record: contract::AuthorityRecordV1,
) -> Result<contract::RecordedAuthorityRecordV1, contract::AuthorityError> {
    if record.workspace_id() != workspace_id
        || administrative_actor(&record)? != bootstrap_principal_id
    {
        return Err(contract::AuthorityError::AuthDenied);
    }
    let head = load_authority_head(transaction, workspace_id)?.ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity("authority log has no head".to_owned())
    })?;
    if record.authority_sequence().get() != head.sequence.get() + 1
        || record_previous_digest(&record) != Some(head.record_digest)
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "administrative record does not extend the exact authority head".to_owned(),
        ));
    }
    validate_administrative_record(
        transaction,
        workspace_id,
        bootstrap_principal_id,
        trusted_at,
        &record,
    )?;
    let signed_record =
        sign_authority_payload(AuthorityPayloadProfile::AuthorityRecord, &record, &[signer])
            .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?;
    let record_value = serde_json::to_value(&record)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let canonical_record = canonicalize(&record_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if signed_record.payload_json != canonical_record.as_str() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "signed authority payload differs from canonical record".to_owned(),
        ));
    }
    let record_digest = digest(ArtifactKind::AuthorityRecordV1, &canonical_record);
    let signer_key_id = signer
        .metadata()
        .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?
        .key_id;
    let sequence = i64::try_from(record.authority_sequence().get()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "authority sequence is out of range".to_owned(),
        )
    })?;
    let record_kind = authority_record_kind(&record);
    transaction
        .execute(
            "INSERT INTO authority_records (
                 authority_sequence, workspace_id, previous_authority_record_digest,
                 record_kind, record_json, record_digest, envelope_json,
                 envelope_digest, authority_key_id, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                sequence,
                workspace_id.to_string(),
                head.record_digest.to_string(),
                record_kind,
                canonical_record.as_str(),
                record_digest.to_string(),
                signed_record.envelope_json.as_str(),
                signed_record.envelope_digest.to_string(),
                signer_key_id.as_str(),
                record_time(&record).to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    insert_administrative_projection(transaction, workspace_id, &record, record_digest)?;
    verify_authority_log(transaction, workspace_id)?;
    Ok(contract::RecordedAuthorityRecordV1 {
        record,
        canonical_record_json: canonical_record.as_str().to_owned(),
        record_digest,
        canonical_envelope_json: signed_record.envelope_json,
        envelope_digest: signed_record.envelope_digest,
        signer_key_ids: vec![signer_key_id.parse().map_err(
            |error: contract::AuthorityContractError| {
                contract::AuthorityError::AuthorityIntegrity(error.to_string())
            },
        )?],
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed administrative union is validated field-by-field without a permissive fallback"
)]
fn validate_administrative_record(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    trusted_at: Timestamp,
    record: &contract::AuthorityRecordV1,
) -> Result<(), contract::AuthorityError> {
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(status) => {
            let expected_type = transaction
                .query_row(
                    "SELECT principal_type FROM principals WHERE principal_id = ?1",
                    [status.principal_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if expected_type != status.principal_type.to_string()
                || (status.principal_type == contract::AuthorityPrincipalType::Human
                    && status.principal_id != bootstrap_principal_id)
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Principal status does not match the registered Principal".to_owned(),
                ));
            }
            if let Some(previous) =
                load_principal_status(transaction, workspace_id, status.principal_id)?
                && !previous.enabled
                && status.enabled
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Principal disablement is terminal in v1".to_owned(),
                ));
            }
        }
        contract::AuthorityRecordV1::PrincipalBinding(binding) => {
            binding
                .validate()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            let (principal_type, recipient_enabled): (String, bool) = transaction
                .query_row(
                    "SELECT principal_type, enabled FROM principals WHERE principal_id = ?1",
                    [binding.principal_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if principal_type != "agent" {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Principal binding recipient is not an Agent".to_owned(),
                ));
            }
            if !recipient_enabled {
                return Err(contract::AuthorityError::PrincipalDisabled);
            }
            validate_binding_key_identity(binding)?;
            let conflicting_historical_credential = transaction
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM principal_bindings_v1
                         WHERE workspace_id = ?1
                           AND (authenticated_subject = ?2 OR public_key = ?3)
                     )",
                    (
                        workspace_id.to_string(),
                        binding.authenticated_subject.as_subject().subject(),
                        binding.public_key.as_str(),
                    ),
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if conflicting_historical_credential {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "an Agent credential cannot reuse historical Workspace authority".to_owned(),
                ));
            }
            let challenge_count = transaction
                .query_row(
                    "SELECT COUNT(*) FROM binding_enrollment_challenges
                     WHERE workspace_id = ?1 AND binding_id = ?2 AND principal_id = ?3
                       AND candidate_key_id = ?4 AND challenge_digest = ?5
                       AND enrollment_envelope_digest = ?6 AND consumed_at IS NOT NULL",
                    (
                        workspace_id.to_string(),
                        binding.binding_id.to_string(),
                        binding.principal_id.to_string(),
                        binding.authenticated_subject.as_subject().subject(),
                        binding.enrollment_challenge_digest.to_string(),
                        binding.enrollment_envelope_digest.to_string(),
                    ),
                    |row| row.get::<_, u32>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if challenge_count != 1 {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Principal binding lacks a consumed proof-of-possession challenge".to_owned(),
                ));
            }
        }
        contract::AuthorityRecordV1::PrincipalBindingRevocation(revocation) => {
            if load_principal_binding(transaction, workspace_id, revocation.binding_id)?.is_none()
                || load_principal_binding_revocation(
                    transaction,
                    workspace_id,
                    revocation.binding_id,
                )?
                .is_some()
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Principal binding revocation target is missing or already revoked".to_owned(),
                ));
            }
        }
        contract::AuthorityRecordV1::Delegation(delegation) => {
            delegation
                .validate()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            if delegation.issuer_principal_id != bootstrap_principal_id {
                return Err(contract::AuthorityError::AuthDenied);
            }
            let (recipient_type, recipient_enabled): (String, bool) = transaction
                .query_row(
                    "SELECT principal_type, enabled FROM principals WHERE principal_id = ?1",
                    [delegation.recipient_principal_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            if recipient_type != "agent" {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Delegation recipient is not an Agent".to_owned(),
                ));
            }
            if !recipient_enabled {
                return Err(contract::AuthorityError::PrincipalDisabled);
            }
            let active_binding_id = transaction
                .query_row(
                    "SELECT binding_id FROM principal_bindings_v1
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND active = 1",
                    (
                        workspace_id.to_string(),
                        delegation.recipient_principal_id.to_string(),
                    ),
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            let Some(active_binding_id) = active_binding_id else {
                return Err(contract::AuthorityError::AuthBindingInactive);
            };
            let active_binding_id = active_binding_id
                .parse::<proof_application::BindingId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            let active_binding =
                load_principal_binding(transaction, workspace_id, active_binding_id)?.ok_or_else(
                    || {
                        contract::AuthorityError::AuthorityIntegrity(
                            "active Agent binding projection is missing".to_owned(),
                        )
                    },
                )?;
            if !active_binding.is_time_active(trusted_at)
                || load_principal_binding_revocation(
                    transaction,
                    workspace_id,
                    active_binding.binding_id,
                )?
                .is_some()
            {
                return Err(contract::AuthorityError::AuthBindingInactive);
            }
        }
        contract::AuthorityRecordV1::DelegationRevocation(revocation) => {
            if load_delegation_v2(transaction, workspace_id, revocation.delegation_id)?.is_none()
                || load_delegation_revocation(transaction, workspace_id, revocation.delegation_id)?
                    .is_some()
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "Delegation revocation target is missing or already revoked".to_owned(),
                ));
            }
        }
        contract::AuthorityRecordV1::AuthorizationDecision(_)
        | contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(_) => {
            return Err(contract::AuthorityError::AuthDenied);
        }
    }
    Ok(())
}

fn validate_binding_key_identity(
    binding: &contract::PrincipalBindingV1,
) -> Result<(), contract::AuthorityError> {
    let public_key = BASE64.decode(binding.public_key.as_str()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "Principal binding public key is malformed".to_owned(),
        )
    })?;
    let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "Principal binding public key has the wrong length".to_owned(),
        )
    })?;
    let key_id = proof_attestation::ed25519_key_id(&public_key);
    if binding.authenticated_subject.as_subject().subject() != key_id {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "Principal binding subject and public key differ".to_owned(),
        ));
    }
    Ok(())
}

fn canonical_json<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<String, contract::AuthorityError> {
    let value = serde_json::to_value(value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    canonicalize(&value)
        .map(|canonical| canonical.as_str().to_owned())
        .map_err(|error| {
            contract::AuthorityError::AuthorityIntegrity(format!("invalid {label}: {error}"))
        })
}

fn serialized_enum_name<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<String, contract::AuthorityError> {
    serde_json::to_value(value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(format!(
                "{label} did not serialize as a string"
            ))
        })
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed administrative union projects each signed record into its typed lookup table"
)]
fn insert_administrative_projection(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    record: &contract::AuthorityRecordV1,
    record_digest: proof_application::ContentDigest,
) -> Result<(), contract::AuthorityError> {
    let sequence = i64::try_from(record.authority_sequence().get()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "authority sequence is out of range".to_owned(),
        )
    })?;
    match record {
        contract::AuthorityRecordV1::PrincipalStatus(status) => {
            transaction
                .execute(
                    "INSERT INTO principal_status_v1 (
                         principal_id, authority_sequence, workspace_id, principal_type,
                         enabled, recorded_by_principal_id, recorded_at, record_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    (
                        status.principal_id.to_string(),
                        sequence,
                        workspace_id.to_string(),
                        status.principal_type.to_string(),
                        i64::from(status.enabled),
                        status.recorded_by_principal_id.to_string(),
                        status.recorded_at.to_string(),
                        record_digest.to_string(),
                    ),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            transaction
                .execute(
                    "UPDATE principals SET enabled = ?1 WHERE principal_id = ?2",
                    (i64::from(status.enabled), status.principal_id.to_string()),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        }
        contract::AuthorityRecordV1::PrincipalBinding(binding) => {
            let active = transaction
                .query_row(
                    "SELECT binding_id, public_key FROM principal_bindings_v1
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND active = 1",
                    (workspace_id.to_string(), binding.principal_id.to_string()),
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            match active {
                Some((active_binding_id, active_public_key)) => {
                    if binding.supersedes_binding_id.map(|id| id.to_string())
                        != Some(active_binding_id.clone())
                        || binding.public_key.as_str() == active_public_key
                    {
                        return Err(contract::AuthorityError::AuthorityIntegrity(
                            "binding rotation must supersede the active binding with a distinct key"
                                .to_owned(),
                        ));
                    }
                    transaction
                        .execute(
                            "UPDATE principal_bindings_v1 SET active = 0
                             WHERE workspace_id = ?1 AND binding_id = ?2",
                            (workspace_id.to_string(), active_binding_id),
                        )
                        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
                }
                None if binding.supersedes_binding_id.is_some() => {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "binding rotation has no active predecessor".to_owned(),
                    ));
                }
                None => {}
            }
            transaction
                .execute(
                    "INSERT INTO principal_bindings_v1 (
                         binding_id, workspace_id, principal_id, authenticated_subject,
                         public_key, audience, enrollment_challenge_digest,
                         enrollment_envelope_digest, issued_by_principal_id, issued_at,
                         not_before, expires_at, supersedes_binding_id, authority_sequence,
                         record_digest, active
                      ) VALUES (
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                         ?14, ?15, 1
                     )",
                    (
                        binding.binding_id.to_string(),
                        workspace_id.to_string(),
                        binding.principal_id.to_string(),
                        binding
                            .authenticated_subject
                            .as_subject()
                            .subject()
                            .to_owned(),
                        binding.public_key.as_str(),
                        binding.audience.to_string(),
                        binding.enrollment_challenge_digest.to_string(),
                        binding.enrollment_envelope_digest.to_string(),
                        binding.issued_by_principal_id.to_string(),
                        binding.issued_at.to_string(),
                        binding.not_before.to_string(),
                        binding.expires_at.to_string(),
                        binding.supersedes_binding_id.map(|id| id.to_string()),
                        sequence,
                        record_digest.to_string(),
                    ),
                )
                .map_err(|error| match &error {
                    rusqlite::Error::SqliteFailure(code, _)
                        if code.code == rusqlite::ErrorCode::ConstraintViolation =>
                    {
                        contract::AuthorityError::AuthorityIntegrity(
                            "Principal binding violates historical credential or active-binding uniqueness"
                                .to_owned(),
                        )
                    }
                    _ => contract::AuthorityError::Storage(error.to_string()),
                })?;
        }
        contract::AuthorityRecordV1::PrincipalBindingRevocation(revocation) => {
            transaction
                .execute(
                    "INSERT INTO principal_binding_revocations_v1 (
                         revocation_id, binding_id, workspace_id, revoked_by_principal_id,
                         revoked_at, reason, authority_sequence, record_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    (
                        revocation.revocation_id.to_string(),
                        revocation.binding_id.to_string(),
                        workspace_id.to_string(),
                        revocation.revoked_by_principal_id.to_string(),
                        revocation.revoked_at.to_string(),
                        serialized_enum_name(&revocation.reason, "binding revocation reason")?,
                        sequence,
                        record_digest.to_string(),
                    ),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            transaction
                .execute(
                    "UPDATE principal_bindings_v1 SET active = 0
                     WHERE workspace_id = ?1 AND binding_id = ?2",
                    (workspace_id.to_string(), revocation.binding_id.to_string()),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        }
        contract::AuthorityRecordV1::Delegation(delegation) => {
            let actions_json = canonical_json(&delegation.actions, "Delegation actions")?;
            let scope_json = canonical_json(&delegation.scope, "Delegation scope")?;
            let constraints_json =
                canonical_json(&delegation.constraints, "Delegation constraints")?;
            transaction
                .execute(
                    "INSERT INTO delegations_v2 (
                         delegation_id, workspace_id, issuer_principal_id,
                         recipient_principal_id, delegation_profile, actions_json, scope_json,
                         constraints_json, not_before, expires_at, issued_at,
                         authority_sequence, record_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    (
                        delegation.delegation_id.to_string(),
                        workspace_id.to_string(),
                        delegation.issuer_principal_id.to_string(),
                        delegation.recipient_principal_id.to_string(),
                        contract::DIRECT_AUTHORITY_POLICY_PROFILE_V1,
                        actions_json,
                        scope_json,
                        constraints_json,
                        delegation.not_before.to_string(),
                        delegation.expires_at.to_string(),
                        delegation.issued_at.to_string(),
                        sequence,
                        record_digest.to_string(),
                    ),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        }
        contract::AuthorityRecordV1::DelegationRevocation(revocation) => {
            transaction
                .execute(
                    "INSERT INTO delegation_revocations_v2 (
                         revocation_id, delegation_id, workspace_id, revoked_by_principal_id,
                         revoked_at, reason, authority_sequence, record_digest
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    (
                        revocation.revocation_id.to_string(),
                        revocation.delegation_id.to_string(),
                        workspace_id.to_string(),
                        revocation.revoked_by_principal_id.to_string(),
                        revocation.revoked_at.to_string(),
                        serialized_enum_name(&revocation.reason, "Delegation revocation reason")?,
                        sequence,
                        record_digest.to_string(),
                    ),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        }
        contract::AuthorityRecordV1::AuthorizationDecision(_)
        | contract::AuthorityRecordV1::WorkspaceAuthorityRootTransition(_) => {
            return Err(contract::AuthorityError::AuthDenied);
        }
    }
    Ok(())
}

fn insert_subject_commitment_opening(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    local_identity: &LocalIdentity,
    mut blind_bytes: [u8; 32],
) -> Result<(), contract::AuthorityError> {
    if local_identity.provider != "os/unix" {
        return Err(contract::AuthorityError::AuthDenied);
    }
    let requesting_subject =
        contract::UnixAuthenticatedSubjectV1::new(local_identity.subject.clone())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let blind_text = BASE64_URL_SAFE_NO_PAD.encode(blind_bytes);
    blind_bytes.zeroize();
    let blind = blind_text
        .parse::<contract::SubjectCommitmentBlind>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let input = contract::AuthenticatedSubjectCommitmentInputV1 {
        api_version: contract::SubjectCommitmentApiVersion::V1,
        workspace_id,
        authenticated_subject: requesting_subject,
        blind,
    };
    let input_json = canonical_json(&input, "requesting subject commitment input")?;
    let input_value = parse_strict(input_json.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let canonical = canonicalize(&input_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let commitment = digest(ArtifactKind::AuthenticatedSubjectCommitmentV1, &canonical);
    transaction
        .execute(
            "INSERT INTO authenticated_subject_commitment_openings_v1 (
                 workspace_id, requesting_principal_id, requesting_subject_provider,
                 requesting_subject, blind, commitment_input_json,
                 requesting_subject_commitment
             ) VALUES (?1, ?2, 'os/unix', ?3, ?4, ?5, ?6)",
            (
                workspace_id.to_string(),
                requesting_principal_id.to_string(),
                local_identity.subject.as_str(),
                blind_text,
                input_json,
                commitment.to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    Ok(())
}

struct VerifiedSubjectCommitmentOpening {
    input: contract::AuthenticatedSubjectCommitmentInputV1,
    commitment: proof_application::ContentDigest,
    blind: String,
}

fn verify_subject_commitment_opening(
    connection: &Connection,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    local_identity: &LocalIdentity,
) -> Result<VerifiedSubjectCommitmentOpening, contract::AuthorityError> {
    let opening: (String, String, String, String, String, String) = connection
        .query_row(
            "SELECT requesting_principal_id, requesting_subject_provider,
                    requesting_subject, blind, commitment_input_json,
                    requesting_subject_commitment
             FROM authenticated_subject_commitment_openings_v1
             WHERE workspace_id = ?1",
            [workspace_id.to_string()],
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
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if opening.0 != requesting_principal_id.to_string()
        || opening.1 != local_identity.provider
        || opening.2 != local_identity.subject
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "requesting Human subject commitment opening is inconsistent".to_owned(),
        ));
    }
    let input: contract::AuthenticatedSubjectCommitmentInputV1 =
        decode_canonical(&opening.4, "authenticated subject commitment opening")?;
    if input.workspace_id != workspace_id
        || input.authenticated_subject.as_subject().provider
            != contract::AuthenticatedSubjectProvider::OsUnix
        || input.authenticated_subject.as_subject().subject() != local_identity.subject
        || input.blind.to_string() != opening.3
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authenticated subject commitment opening is inconsistent".to_owned(),
        ));
    }
    let input_value = parse_strict(opening.4.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let canonical = canonicalize(&input_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let commitment = digest(ArtifactKind::AuthenticatedSubjectCommitmentV1, &canonical);
    if commitment.to_string() != opening.5 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "authenticated subject commitment does not reproduce".to_owned(),
        ));
    }
    Ok(VerifiedSubjectCommitmentOpening {
        input,
        commitment,
        blind: opening.3,
    })
}

struct VerifiedPresentation {
    operation_input: contract::EnabledOperationInputV1,
    command: contract::AuthenticatedCommandV1,
    command_digest: proof_application::ContentDigest,
    command_envelope_digest: proof_application::ContentDigest,
    binding: contract::PrincipalBindingV1,
    binding_record_digest: proof_application::ContentDigest,
    binding_active: bool,
    binding_revocation_record_digest: Option<proof_application::ContentDigest>,
    actor_context: contract::AuthenticatedActorContextV1,
    actor_context_evidence: contract::AuthenticatedActorContextEvidenceV1,
    actor_context_digest: proof_application::ContentDigest,
}

struct LocalizedIntentAuthorizationClosure {
    intent: ContentResourceIntent,
    context: Option<proof_application::LocalizedContextPack>,
    changeset: Option<proof_application::LocalizedChangeSet>,
    context_fresh: bool,
}

#[expect(
    clippy::large_enum_variant,
    reason = "the transaction-scoped closure is short lived and direct ownership keeps frozen P7 evidence explicit"
)]
enum AuthorizationApplicationClosure {
    Legacy,
    LocalizedIntent(LocalizedIntentAuthorizationClosure),
    LocalizedReleased(localized::ReleasedAuthorizationProjectionV1),
}

#[expect(
    clippy::large_enum_variant,
    reason = "the verified closure is transaction scoped and boxing would obscure fail-closed resolution ownership"
)]
enum LocalizedIntentClosureResolution {
    Verified(LocalizedIntentAuthorizationClosure),
    Hidden,
}

struct AuthorizationAssessment {
    requested_resources: contract::RequestedResourcesV2,
    effective_constraints: contract::EffectiveConstraintsV2,
    principal_state: contract::PrincipalStateV2,
    binding: contract::BindingDecisionEvidenceV2,
    delegation: contract::DelegationDecisionEvidenceV2,
    resolved_delegation: Option<contract::DelegationV2>,
    application_closure: AuthorizationApplicationClosure,
    application_idempotency: Option<ApplicationIdempotencyAssessment>,
    denial: Option<(
        contract::AuthorizationDenialReason,
        contract::AuthorityError,
    )>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationIdempotencyKind {
    Required,
    Derived,
}

struct ApplicationIdempotencyAssessment {
    kind: ApplicationIdempotencyKind,
    key: Option<String>,
    replay_application_effect_digest: Option<proof_application::ContentDigest>,
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the owned signature is required for direct use as a Result::map_err function"
)]
fn contract_integrity(error: contract::AuthorityContractError) -> contract::AuthorityError {
    contract::AuthorityError::AuthorityIntegrity(error.to_string())
}

fn projected_resources(
    workspace_id: WorkspaceId,
    environment_ids: Vec<EnvironmentId>,
    object_ids: Vec<ObjectId>,
    schema_ids: Vec<SchemaId>,
    locales: Vec<LocaleId>,
) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
    Ok(contract::RequestedResourcesV2 {
        workspace_ids: contract::RequestedWorkspaceIdsV2::new(vec![workspace_id])
            .map_err(contract_integrity)?,
        environment_ids: contract::RequestedEnvironmentIdsV2::new(environment_ids)
            .map_err(contract_integrity)?,
        object_ids: contract::RequestedObjectIdsV2::new(object_ids).map_err(contract_integrity)?,
        schema_ids: contract::RequestedSchemaIdsV2::new(schema_ids).map_err(contract_integrity)?,
        locales: contract::RequestedLocalesV2::new(locales).map_err(contract_integrity)?,
        changeset_ids: contract::RequestedChangeSetIdsV2::new(Vec::new())
            .map_err(contract_integrity)?,
        edition_ids: contract::RequestedEditionIdsV2::new(Vec::new())
            .map_err(contract_integrity)?,
        release_ids: contract::RequestedReleaseIdsV2::new(Vec::new())
            .map_err(contract_integrity)?,
    })
}

#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
fn sorted_unique_values<T: Clone + Ord>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Stage-one disclosure-safe projection for a localized released-rendition query.
#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
pub(super) struct StagedLocalizedReleasedProjectionV1 {
    requested: contract::RequestedResourcesV2,
}

#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
impl StagedLocalizedReleasedProjectionV1 {
    /// Signed axes that must pass before resolving the current Release or Edition.
    #[must_use]
    pub(super) const fn requested_axes(&self) -> &contract::RequestedResourcesV2 {
        &self.requested
    }

    /// Adds only internally resolved Schema identities after stage one succeeds.
    pub(super) fn resolve_schemas(
        mut self,
        schema_ids: impl IntoIterator<Item = SchemaId>,
    ) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
        self.requested.schema_ids =
            contract::RequestedSchemaIdsV2::new(sorted_unique_values(schema_ids))
                .map_err(contract_integrity)?;
        Ok(self.requested)
    }
}

pub(super) fn project_workspace_only_v1(
    workspace_id: WorkspaceId,
) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
    projected_resources(workspace_id, Vec::new(), Vec::new(), Vec::new(), Vec::new())
}

pub(super) fn project_legacy_object_selection_v1(
    workspace_id: WorkspaceId,
    environment_id: EnvironmentId,
    object_ids: &[ObjectId],
) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
    projected_resources(
        workspace_id,
        vec![environment_id],
        object_ids.to_vec(),
        Vec::new(),
        Vec::new(),
    )
}

#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
pub(super) fn project_localized_intent_closure_v1(
    workspace_id: WorkspaceId,
    intent: &ContentResourceIntent,
) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
    let manifest_value = parse_strict(intent.canonical_json.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let manifest = canonicalize(&manifest_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let expected_targets = intent
        .targets
        .iter()
        .map(|target| {
            json!({
                "locale": target.locale.as_str(),
                "object_id": target.object_id.to_string(),
                "schema_id": target.schema_id.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let expected_manifest = canonicalize(&json!({
        "api_version": proof_application::CONTENT_RESOURCE_INTENT_API_VERSION,
        "base": {
            "edition": {
                "api_version": intent.base.edition.api_version,
                "digest": intent.base.edition.digest.to_string(),
                "edition_id": intent.base.edition.edition_id.to_string(),
            },
            "known_state": {
                "api_version": intent.base.known_state.api_version,
                "authoritative_sequence": intent.base.known_state.authoritative_sequence,
                "digest": intent.base.known_state.digest.to_string(),
            },
            "release": {
                "api_version": intent.base.release.api_version,
                "digest": intent.base.release.digest.to_string(),
                "release_id": intent.base.release.release_id.to_string(),
            },
        },
        "environment_id": intent.environment_id.as_str(),
        "intent_id": intent.intent_id.to_string(),
        "issued_at": intent.issued_at.to_string(),
        "issued_by_principal_id": intent.issued_by_principal_id.to_string(),
        "targets": expected_targets,
        "workspace_id": intent.workspace_id.to_string(),
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if intent.workspace_id != workspace_id
        || manifest.as_str() != intent.canonical_json
        || manifest != expected_manifest
        || digest(ArtifactKind::ContentResourceIntentV1, &manifest) != intent.intent_digest
        || intent.targets.is_empty()
        || !intent.targets.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized resource-intent closure does not reproduce".to_owned(),
        ));
    }
    projected_resources(
        workspace_id,
        vec![intent.environment_id.clone()],
        sorted_unique_values(intent.targets.iter().map(|target| target.object_id)),
        sorted_unique_values(intent.targets.iter().map(|target| target.schema_id.clone())),
        sorted_unique_values(intent.targets.iter().map(|target| target.locale.clone())),
    )
}

#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
pub(super) fn project_localized_released_selection_stage_one_v1(
    workspace_id: WorkspaceId,
    environment_id: EnvironmentId,
    targets: &[ReleasedLocaleTarget],
) -> Result<StagedLocalizedReleasedProjectionV1, contract::AuthorityError> {
    if targets.is_empty() || !targets.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized released selection is not a nonempty sorted unique target set".to_owned(),
        ));
    }
    Ok(StagedLocalizedReleasedProjectionV1 {
        requested: projected_resources(
            workspace_id,
            vec![environment_id],
            sorted_unique_values(targets.iter().map(|target| target.object_id)),
            Vec::new(),
            sorted_unique_values(targets.iter().map(|target| target.locale.clone())),
        )?,
    })
}

/// Evaluates all five grant axes for a complete projection. Staged released
/// selection sets `require_nonempty_schema_grant` before resolving Schemas so
/// a not-found path cannot disclose whether an ungranted target exists.
#[must_use]
#[allow(
    dead_code,
    reason = "the P-0004 kernel freezes P-0005 projection semantics without exposing localized operations"
)]
pub(super) fn delegation_covers_projected_resources_v1(
    delegation: &contract::DelegationV2,
    requested: &contract::RequestedResourcesV2,
    require_nonempty_schema_grant: bool,
) -> bool {
    requested.workspace_ids.as_slice() == [delegation.workspace_id]
        && requested.environment_ids.as_slice().iter().all(|value| {
            delegation
                .scope
                .environment_ids
                .as_slice()
                .binary_search(value)
                .is_ok()
        })
        && requested.object_ids.as_slice().iter().all(|value| {
            delegation
                .scope
                .object_ids
                .as_slice()
                .binary_search(value)
                .is_ok()
        })
        && requested.schema_ids.as_slice().iter().all(|value| {
            delegation
                .scope
                .schema_ids
                .as_slice()
                .binary_search(value)
                .is_ok()
        })
        && requested.locales.as_slice().iter().all(|value| {
            delegation
                .scope
                .locales
                .as_slice()
                .binary_search(value)
                .is_ok()
        })
        && (!require_nonempty_schema_grant || !delegation.scope.schema_ids.as_slice().is_empty())
}

fn initial_requested_resources(
    workspace_id: WorkspaceId,
    input: &contract::EnabledOperationInputV1,
) -> Result<contract::RequestedResourcesV2, contract::AuthorityError> {
    let profile =
        contract::authority_operation_entry(input.operation()).resource_projection_profile;
    match (profile, input) {
        (
            contract::ResourceProjectionProfileName::WorkspaceOnlyV1,
            contract::EnabledOperationInputV1::WorkspaceStatus(_),
        )
        | (
            contract::ResourceProjectionProfileName::LocalizedIntentClosureV1,
            contract::EnabledOperationInputV1::LocalizedContextBuild(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetCreate(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetAdd(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetGet(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetDiff(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetValidate(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(_)
            | contract::EnabledOperationInputV1::LocalizedChangeSetCommit(_)
            | contract::EnabledOperationInputV1::LocalizedEditionCreate(_)
            | contract::EnabledOperationInputV1::LocalizedReleaseCreate(_),
        ) => project_workspace_only_v1(workspace_id),
        (
            contract::ResourceProjectionProfileName::LegacyObjectSelectionV1,
            contract::EnabledOperationInputV1::ObjectQueryReleased(value),
        ) => project_legacy_object_selection_v1(
            workspace_id,
            value.environment_id.clone(),
            value.object_ids.as_slice(),
        ),
        (
            contract::ResourceProjectionProfileName::LegacyObjectSelectionV1,
            contract::EnabledOperationInputV1::ContextBuild(value),
        ) => project_legacy_object_selection_v1(
            workspace_id,
            value.environment_id.clone(),
            value.object_ids.as_slice(),
        ),
        (
            contract::ResourceProjectionProfileName::LocalizedReleasedSelectionV1,
            contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(value),
        ) => {
            let targets = value
                .targets
                .iter()
                .map(|target| ReleasedLocaleTarget {
                    object_id: target.object_id,
                    locale: target.locale.clone(),
                })
                .collect::<Vec<_>>();
            Ok(project_localized_released_selection_stage_one_v1(
                workspace_id,
                value.environment_id.clone(),
                &targets,
            )?
            .requested)
        }
        _ => Err(contract::AuthorityError::AuthorityIntegrity(
            "enabled operation disagrees with its frozen resource projection profile".to_owned(),
        )),
    }
}

fn closure_load<T>(
    result: Result<T, LocalPortError>,
) -> Result<Option<T>, contract::AuthorityError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(LocalPortError::Storage(detail)) => Err(contract::AuthorityError::Storage(detail)),
        Err(LocalPortError::Integrity(detail)) => {
            Err(contract::AuthorityError::AuthorityIntegrity(detail))
        }
        Err(_) => Ok(None),
    }
}

fn context_is_fresh(
    transaction: &Connection,
    context: &proof_application::LocalizedContextPack,
    lifecycle_changeset_id: Option<proof_application::ChangeSetId>,
    replay_release_id: Option<proof_application::ReleaseId>,
    evaluated_at: Timestamp,
) -> Result<bool, contract::AuthorityError> {
    if context.created_at > evaluated_at || evaluated_at >= context.expires_at {
        return Ok(false);
    }
    localized::context_resource_closure_is_current(
        transaction,
        context,
        lifecycle_changeset_id,
        replay_release_id,
    )
    .map_err(authority_from_local_port)
}

fn resolve_changeset_intent_closure(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    changeset_id: proof_application::ChangeSetId,
    replay_release_id: Option<proof_application::ReleaseId>,
    evaluated_at: Timestamp,
) -> Result<LocalizedIntentClosureResolution, contract::AuthorityError> {
    let Some(changeset) = closure_load(localized::load_changeset(
        transaction,
        workspace_id,
        changeset_id,
    ))?
    else {
        return Ok(LocalizedIntentClosureResolution::Hidden);
    };
    let Some(intent) = closure_load(localized::load_resource_intent(
        transaction,
        workspace_id,
        changeset.resource_intent_id,
    ))?
    else {
        return Ok(LocalizedIntentClosureResolution::Hidden);
    };
    let Some(context) = closure_load(localized::load_context(
        transaction,
        workspace_id,
        changeset.context_pack_id,
    ))?
    else {
        return Ok(LocalizedIntentClosureResolution::Hidden);
    };
    if changeset.principal_id != requesting_principal_id
        || intent.issued_by_principal_id != requesting_principal_id
        || context.principal_id != requesting_principal_id
        || changeset.resource_intent_digest != intent.intent_digest
        || changeset.context_pack_digest != context.context_pack_digest
        || context.resource_intent_id != intent.intent_id
        || context.resource_intent_digest != intent.intent_digest
    {
        return Ok(LocalizedIntentClosureResolution::Hidden);
    }
    let context_fresh = context_is_fresh(
        transaction,
        &context,
        Some(changeset.changeset_id),
        replay_release_id,
        evaluated_at,
    )?;
    Ok(LocalizedIntentClosureResolution::Verified(
        LocalizedIntentAuthorizationClosure {
            intent,
            context: Some(context),
            changeset: Some(changeset),
            context_fresh,
        },
    ))
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed localized registry requires explicit disclosure-neutral resolution for every resource anchor"
)]
fn resolve_localized_intent_closure(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    input: &contract::EnabledOperationInputV1,
    evaluated_at: Timestamp,
) -> Result<LocalizedIntentClosureResolution, contract::AuthorityError> {
    match input {
        contract::EnabledOperationInputV1::LocalizedContextBuild(value) => {
            let Some(intent) = closure_load(localized::load_resource_intent(
                transaction,
                workspace_id,
                value.resource_intent_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            if intent.intent_digest != value.resource_intent_digest
                || intent.issued_by_principal_id != requesting_principal_id
            {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            }
            let command = value.clone().into_application_command();
            let context = match localized::load_exact_context_replay(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            ) {
                Ok(context) => Some(context),
                Err(LocalPortError::Storage(detail)) => {
                    return Err(contract::AuthorityError::Storage(detail));
                }
                Err(LocalPortError::Integrity(detail)) => {
                    return Err(contract::AuthorityError::AuthorityIntegrity(detail));
                }
                Err(_) => None,
            };
            let context_fresh = if let Some(context) = context.as_ref() {
                context_is_fresh(transaction, context, None, None, evaluated_at)?
            } else {
                value.created_at <= evaluated_at && evaluated_at < value.expires_at
            };
            Ok(LocalizedIntentClosureResolution::Verified(
                LocalizedIntentAuthorizationClosure {
                    intent,
                    context,
                    changeset: None,
                    context_fresh,
                },
            ))
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCreate(value) => {
            let Some(intent) = closure_load(localized::load_resource_intent(
                transaction,
                workspace_id,
                value.resource_intent_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            let Some(context) = closure_load(localized::load_context(
                transaction,
                workspace_id,
                value.context_pack_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            if intent.intent_digest != value.resource_intent_digest
                || intent.issued_by_principal_id != requesting_principal_id
                || context.principal_id != requesting_principal_id
                || context.context_pack_digest != value.context_pack_digest
                || context.resource_intent_id != intent.intent_id
                || context.resource_intent_digest != intent.intent_digest
            {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            }
            let context_fresh = context_is_fresh(transaction, &context, None, None, evaluated_at)?;
            Ok(LocalizedIntentClosureResolution::Verified(
                LocalizedIntentAuthorizationClosure {
                    intent,
                    context: Some(context),
                    changeset: None,
                    context_fresh,
                },
            ))
        }
        contract::EnabledOperationInputV1::LocalizedEditionCreate(value) => {
            let Some(commit) = closure_load(localized::load_localized_commit(
                transaction,
                workspace_id,
                value.changeset_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            if commit.changeset_id != value.changeset_id {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            }
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedReleaseCreate(value) => {
            let Some(edition) = closure_load(localized::load_localized_edition(
                transaction,
                workspace_id,
                value.edition_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            let Some(commit) = closure_load(localized::load_localized_commit(
                transaction,
                workspace_id,
                edition.changeset_id,
            ))?
            else {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            };
            if edition.principal_id != requesting_principal_id
                || commit.changeset_id != edition.changeset_id
            {
                return Ok(LocalizedIntentClosureResolution::Hidden);
            }
            let command = value.clone().into_application_command();
            let replay_release_id = localized::load_exact_localized_release_replay(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
            .map_err(authority_from_local_port)?
            .map(|release| release.release_id);
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                edition.changeset_id,
                replay_release_id,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetAdd(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetGet(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetDiff(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetValidate(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCommit(value) => {
            resolve_changeset_intent_closure(
                transaction,
                workspace_id,
                requesting_principal_id,
                value.changeset_id,
                None,
                evaluated_at,
            )
        }
        _ => Err(contract::AuthorityError::AuthorityIntegrity(
            "localized intent closure disagrees with its operation profile".to_owned(),
        )),
    }
}

fn apply_frozen_selectors(
    requested: &mut contract::RequestedResourcesV2,
    input: &contract::EnabledOperationInputV1,
    closure: &AuthorizationApplicationClosure,
) -> Result<(), contract::AuthorityError> {
    let mut changeset_ids = Vec::new();
    let mut edition_ids = Vec::new();
    let mut release_ids = Vec::new();
    match input {
        contract::EnabledOperationInputV1::LocalizedChangeSetCreate(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetAdd(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetGet(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetDiff(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetValidate(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCommit(value) => {
            changeset_ids.push(value.changeset_id);
        }
        contract::EnabledOperationInputV1::LocalizedEditionCreate(value) => {
            changeset_ids.push(value.changeset_id);
            edition_ids.push(value.edition_id);
        }
        contract::EnabledOperationInputV1::LocalizedReleaseCreate(value) => {
            let AuthorizationApplicationClosure::LocalizedIntent(intent_closure) = closure else {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized Release has no verified intent closure".to_owned(),
                ));
            };
            let changeset = intent_closure.changeset.as_ref().ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized Release closure has no ChangeSet".to_owned(),
                )
            })?;
            changeset_ids.push(changeset.changeset_id);
            edition_ids.push(value.edition_id);
            release_ids.extend([value.expected_base_release_id, value.release_id]);
        }
        contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(_) => {
            let AuthorizationApplicationClosure::LocalizedReleased(projection) = closure else {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized released query has no staged projection".to_owned(),
                ));
            };
            edition_ids.extend(projection.edition_id);
            release_ids.extend(projection.release_id);
        }
        contract::EnabledOperationInputV1::WorkspaceStatus(_)
        | contract::EnabledOperationInputV1::ObjectQueryReleased(_)
        | contract::EnabledOperationInputV1::ContextBuild(_)
        | contract::EnabledOperationInputV1::LocalizedContextBuild(_) => {}
    }
    requested.changeset_ids =
        contract::RequestedChangeSetIdsV2::new(changeset_ids).map_err(contract_integrity)?;
    requested.edition_ids =
        contract::RequestedEditionIdsV2::new(edition_ids).map_err(contract_integrity)?;
    requested.release_ids =
        contract::RequestedReleaseIdsV2::new(release_ids).map_err(contract_integrity)?;
    Ok(())
}

fn requested_effective_constraints(
    input: &contract::EnabledOperationInputV1,
    closure: &AuthorizationApplicationClosure,
) -> Result<contract::EffectiveConstraintsV2, contract::AuthorityError> {
    let (max_objects, max_context_bytes, max_edits) = match input {
        contract::EnabledOperationInputV1::WorkspaceStatus(_) => (1, 1, 1),
        contract::EnabledOperationInputV1::ObjectQueryReleased(value) => (
            u32::try_from(value.object_ids.as_slice().len()).map_err(|_| {
                contract::AuthorityError::AuthorityIntegrity(
                    "requested Object count is out of range".to_owned(),
                )
            })?,
            1,
            1,
        ),
        contract::EnabledOperationInputV1::ContextBuild(value) => {
            (value.max_objects.get(), value.max_bytes.get(), 1)
        }
        contract::EnabledOperationInputV1::LocalizedContextBuild(value) => (
            value.limits.max_objects,
            u32::try_from(value.limits.max_bytes).map_err(|_| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized Context byte limit is out of range".to_owned(),
                )
            })?,
            value.limits.max_edits,
        ),
        contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(value) => {
            let object_count = value
                .targets
                .iter()
                .map(|target| target.object_id)
                .collect::<BTreeSet<_>>()
                .len();
            (
                u32::try_from(object_count).map_err(|_| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "requested Object count is out of range".to_owned(),
                    )
                })?,
                1,
                1,
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCreate(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetAdd(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetGet(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetDiff(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetValidate(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetCommit(_)
        | contract::EnabledOperationInputV1::LocalizedEditionCreate(_)
        | contract::EnabledOperationInputV1::LocalizedReleaseCreate(_) => {
            let context = match closure {
                AuthorizationApplicationClosure::LocalizedIntent(value) => value.context.as_ref(),
                _ => None,
            };
            context.map_or((1, 1, 1), |value| {
                (
                    value.limits.max_objects,
                    u32::try_from(value.limits.max_bytes).unwrap_or(u32::MAX),
                    value.limits.max_edits,
                )
            })
        }
    };
    Ok(contract::EffectiveConstraintsV2 {
        max_objects: contract::MaxObjects::new(max_objects).map_err(contract_integrity)?,
        max_context_bytes: contract::MaxContextBytes::new(max_context_bytes)
            .map_err(contract_integrity)?,
        max_edits_per_changeset: contract::MaxEditsPerChangeSet::new(max_edits)
            .map_err(contract_integrity)?,
    })
}

fn effective_constraints_for_delegation(
    input: &contract::EnabledOperationInputV1,
    delegation: &contract::DelegationV2,
    closure: &AuthorizationApplicationClosure,
) -> Result<contract::EffectiveConstraintsV2, contract::AuthorityError> {
    let entry = contract::authority_operation_entry(input.operation());
    let requested = requested_effective_constraints(input, closure)?;
    let constraints = match entry.budget_projection {
        contract::BudgetProjection::DelegationOnly => contract::EffectiveConstraintsV2 {
            max_objects: delegation.constraints.max_objects,
            max_context_bytes: delegation.constraints.max_context_bytes,
            max_edits_per_changeset: delegation.constraints.max_edits_per_changeset,
        },
        contract::BudgetProjection::RequestedObjectCount => contract::EffectiveConstraintsV2 {
            max_objects: requested.max_objects,
            max_context_bytes: delegation.constraints.max_context_bytes,
            max_edits_per_changeset: delegation.constraints.max_edits_per_changeset,
        },
        contract::BudgetProjection::NormalizedV1ContextLimits
        | contract::BudgetProjection::NormalizedV2ContextLimits
        | contract::BudgetProjection::BoundContextLimits => requested,
    };
    Ok(constraints)
}

fn record_digest_from_projection(
    transaction: &Transaction<'_>,
    table: &str,
    workspace_id: WorkspaceId,
    selector_column: &str,
    selector: &str,
) -> Result<Option<proof_application::ContentDigest>, contract::AuthorityError> {
    let allowed = matches!(
        (table, selector_column),
        (
            "delegations_v2" | "delegation_revocations_v2",
            "delegation_id"
        )
    );
    if !allowed {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "invalid authority projection selector".to_owned(),
        ));
    }
    let sql = format!(
        "SELECT record_digest FROM {table} WHERE workspace_id = ?1 AND {selector_column} = ?2"
    );
    transaction
        .query_row(&sql, (workspace_id.to_string(), selector), |row| {
            row.get::<_, String>(0)
        })
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .map(|value| {
            value
                .parse::<proof_application::ContentDigest>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
        })
        .transpose()
}

fn scope_and_budget_denial(
    delegation: &contract::DelegationV2,
    requested_action: contract::AuthorityAction,
    requested_resources: &contract::RequestedResourcesV2,
    effective_constraints: contract::EffectiveConstraintsV2,
    input: &contract::EnabledOperationInputV1,
) -> Option<(
    contract::AuthorizationDenialReason,
    contract::AuthorityError,
)> {
    if !delegation.actions.as_slice().contains(&requested_action) {
        return Some((
            contract::AuthorizationDenialReason::ScopeExceeded,
            contract::AuthorityError::ScopeExceeded,
        ));
    }
    if !delegation_covers_projected_resources_v1(delegation, requested_resources, false) {
        return Some((
            contract::AuthorizationDenialReason::ScopeExceeded,
            contract::AuthorityError::ScopeExceeded,
        ));
    }
    let budget_exceeded = effective_constraints.max_objects > delegation.constraints.max_objects
        || effective_constraints.max_context_bytes > delegation.constraints.max_context_bytes
        || effective_constraints.max_edits_per_changeset
            > delegation.constraints.max_edits_per_changeset
        || match input {
            contract::EnabledOperationInputV1::ContextBuild(value) => {
                value.expires_at > delegation.expires_at
            }
            contract::EnabledOperationInputV1::LocalizedContextBuild(value) => {
                value.expires_at > delegation.expires_at
            }
            _ => false,
        };
    budget_exceeded.then_some((
        contract::AuthorizationDenialReason::BudgetExceeded,
        contract::AuthorityError::BudgetExceeded,
    ))
}

#[expect(
    clippy::too_many_lines,
    clippy::if_not_else,
    reason = "the evaluator makes the complete current C6 ordering and denial precedence explicit"
)]
fn assess_authorization(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    presentation: &VerifiedPresentation,
    evaluated_at: Timestamp,
) -> Result<AuthorizationAssessment, contract::AuthorityError> {
    let mut requested_resources =
        initial_requested_resources(workspace_id, &presentation.operation_input)?;
    let mut application_closure = AuthorizationApplicationClosure::Legacy;
    let requesting_status =
        load_principal_status(transaction, workspace_id, bootstrap_principal_id)?;
    let operating_status =
        load_principal_status(transaction, workspace_id, presentation.binding.principal_id)?;
    let principal_state = contract::PrincipalStateV2 {
        requesting_principal_enabled: requesting_status.is_some_and(|status| status.enabled),
        operating_principal_enabled: operating_status.is_some_and(|status| status.enabled),
    };
    let binding = contract::BindingDecisionEvidenceV2 {
        binding_id: presentation.binding.binding_id,
        authority_sequence: presentation.binding.authority_sequence,
        record_digest: presentation.binding_record_digest,
        revocation_record_digest: presentation.binding_revocation_record_digest,
    };
    let delegation = load_delegation_v2(
        transaction,
        workspace_id,
        presentation.command.delegation_id,
    )?;
    let delegation_record_digest = record_digest_from_projection(
        transaction,
        "delegations_v2",
        workspace_id,
        "delegation_id",
        &presentation.command.delegation_id.to_string(),
    )?;
    let delegation_revocation_record_digest = record_digest_from_projection(
        transaction,
        "delegation_revocations_v2",
        workspace_id,
        "delegation_id",
        &presentation.command.delegation_id.to_string(),
    )?;
    let delegation_evidence = contract::DelegationDecisionEvidenceV2 {
        delegation_id: presentation.command.delegation_id,
        record_digest: delegation_record_digest,
        revocation_record_digest: delegation_revocation_record_digest,
        resolution: if delegation.is_some() {
            contract::DelegationResolutionV2::Resolved
        } else {
            contract::DelegationResolutionV2::NotFoundOrHidden
        },
    };
    let mut effective_constraints =
        requested_effective_constraints(&presentation.operation_input, &application_closure)?;
    let requested_action =
        contract::authority_operation_entry(presentation.command.operation).requested_action;
    let mut denial = if !principal_state.requesting_principal_enabled
        || !principal_state.operating_principal_enabled
    {
        Some((
            contract::AuthorizationDenialReason::PrincipalDisabled,
            contract::AuthorityError::PrincipalDisabled,
        ))
    } else if !presentation.binding_active
        || presentation.binding_revocation_record_digest.is_some()
        || !presentation.binding.is_time_active(evaluated_at)
    {
        Some((
            contract::AuthorizationDenialReason::BindingInactive,
            contract::AuthorityError::AuthBindingInactive,
        ))
    } else if let Some(value) = delegation.as_ref() {
        if value.issuer_principal_id != bootstrap_principal_id
            || value.recipient_principal_id != presentation.binding.principal_id
        {
            Some((
                contract::AuthorizationDenialReason::ScopeExceeded,
                contract::AuthorityError::ScopeExceeded,
            ))
        } else if delegation_revocation_record_digest.is_some() {
            Some((
                contract::AuthorizationDenialReason::DelegationRevoked,
                contract::AuthorityError::DelegationRevoked,
            ))
        } else if evaluated_at < value.not_before {
            Some((
                contract::AuthorizationDenialReason::DelegationNotYetValid,
                contract::AuthorityError::DelegationNotYetValid,
            ))
        } else if evaluated_at >= value.expires_at {
            Some((
                contract::AuthorizationDenialReason::DelegationExpired,
                contract::AuthorityError::DelegationExpired,
            ))
        } else if !value.actions.as_slice().contains(&requested_action) {
            Some((
                contract::AuthorizationDenialReason::ScopeExceeded,
                contract::AuthorityError::ScopeExceeded,
            ))
        } else {
            None
        }
    } else {
        Some((
            contract::AuthorizationDenialReason::DelegationUnavailable,
            contract::AuthorityError::DelegationUnavailable,
        ))
    };

    if denial.is_none() {
        let resolved_delegation = delegation.as_ref().ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "allowed authorization assessment has no Delegation".to_owned(),
            )
        })?;
        let profile = contract::authority_operation_entry(presentation.command.operation)
            .resource_projection_profile;
        match profile {
            contract::ResourceProjectionProfileName::WorkspaceOnlyV1
            | contract::ResourceProjectionProfileName::LegacyObjectSelectionV1 => {
                effective_constraints = effective_constraints_for_delegation(
                    &presentation.operation_input,
                    resolved_delegation,
                    &application_closure,
                )?;
                denial = scope_and_budget_denial(
                    resolved_delegation,
                    requested_action,
                    &requested_resources,
                    effective_constraints,
                    &presentation.operation_input,
                );
            }
            contract::ResourceProjectionProfileName::LocalizedIntentClosureV1 => {
                match resolve_localized_intent_closure(
                    transaction,
                    workspace_id,
                    presentation.command.requesting_principal_id,
                    &presentation.operation_input,
                    evaluated_at,
                )? {
                    LocalizedIntentClosureResolution::Hidden => {
                        denial = Some((
                            contract::AuthorizationDenialReason::ScopeExceeded,
                            contract::AuthorityError::ScopeExceeded,
                        ));
                    }
                    LocalizedIntentClosureResolution::Verified(closure) => {
                        requested_resources =
                            project_localized_intent_closure_v1(workspace_id, &closure.intent)?;
                        application_closure =
                            AuthorizationApplicationClosure::LocalizedIntent(closure);
                        apply_frozen_selectors(
                            &mut requested_resources,
                            &presentation.operation_input,
                            &application_closure,
                        )?;
                        effective_constraints = effective_constraints_for_delegation(
                            &presentation.operation_input,
                            resolved_delegation,
                            &application_closure,
                        )?;
                        denial = scope_and_budget_denial(
                            resolved_delegation,
                            requested_action,
                            &requested_resources,
                            effective_constraints,
                            &presentation.operation_input,
                        );
                    }
                }
            }
            contract::ResourceProjectionProfileName::LocalizedReleasedSelectionV1 => {
                if !delegation_covers_projected_resources_v1(
                    resolved_delegation,
                    &requested_resources,
                    true,
                ) {
                    denial = Some((
                        contract::AuthorizationDenialReason::ScopeExceeded,
                        contract::AuthorityError::ScopeExceeded,
                    ));
                } else {
                    let contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(value) =
                        &presentation.operation_input
                    else {
                        return Err(contract::AuthorityError::AuthorityIntegrity(
                            "localized released projection has the wrong input".to_owned(),
                        ));
                    };
                    let command = value.clone().into_application_command();
                    let projection = localized::resolve_released_authorization_projection(
                        transaction,
                        workspace_id,
                        &command,
                    )
                    .map_err(authority_from_local_port)?;
                    requested_resources.schema_ids =
                        contract::RequestedSchemaIdsV2::new(projection.schema_ids.clone())
                            .map_err(contract_integrity)?;
                    application_closure =
                        AuthorizationApplicationClosure::LocalizedReleased(projection);
                    apply_frozen_selectors(
                        &mut requested_resources,
                        &presentation.operation_input,
                        &application_closure,
                    )?;
                    effective_constraints = effective_constraints_for_delegation(
                        &presentation.operation_input,
                        resolved_delegation,
                        &application_closure,
                    )?;
                    denial = scope_and_budget_denial(
                        resolved_delegation,
                        requested_action,
                        &requested_resources,
                        effective_constraints,
                        &presentation.operation_input,
                    );
                }
            }
        }
    }
    Ok(AuthorizationAssessment {
        requested_resources,
        effective_constraints,
        principal_state,
        binding,
        delegation: delegation_evidence,
        resolved_delegation: delegation,
        application_closure,
        application_idempotency: None,
        denial,
    })
}

struct PreparedDecision {
    decision: contract::AuthorizationDecisionV2,
    record_json: String,
    record_digest: proof_application::ContentDigest,
    envelope_json: String,
    envelope_digest: proof_application::ContentDigest,
    authority_key_id: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "global application-key preflight checks legacy, v13, and P7 ownership before any consequence is attempted"
)]
fn apply_application_idempotency_denial(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &mut AuthorizationAssessment,
) -> Result<(), contract::AuthorityError> {
    type LedgerRow = (String, String, String, String);

    let registry = contract::authority_operation_entry(presentation.command.operation);
    let application_idempotency = match registry.application_idempotency {
        contract::ApplicationIdempotency::None => return Ok(()),
        contract::ApplicationIdempotency::RequiredUuidV7 => {
            let key = presentation
                .operation_input
                .application_idempotency_key()
                .ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "required application key is absent after contract validation".to_owned(),
                    )
                })?;
            ApplicationIdempotencyAssessment {
                kind: ApplicationIdempotencyKind::Required,
                key: Some(key.to_string()),
                replay_application_effect_digest: None,
            }
        }
        contract::ApplicationIdempotency::DerivedChangeset => ApplicationIdempotencyAssessment {
            kind: ApplicationIdempotencyKind::Derived,
            key: Some(derived_changeset_application_key(
                workspace_id,
                &presentation.operation_input,
            )?),
            replay_application_effect_digest: None,
        },
        contract::ApplicationIdempotency::DerivedProposalPolicyValidator => {
            ApplicationIdempotencyAssessment {
                kind: ApplicationIdempotencyKind::Derived,
                key: derived_validation_application_key(workspace_id, assessment)?,
                replay_application_effect_digest: None,
            }
        }
    };
    assessment.application_idempotency = Some(application_idempotency);
    let Some(key) = assessment
        .application_idempotency
        .as_ref()
        .and_then(|value| value.key.as_deref())
    else {
        return Ok(());
    };

    let legacy_rows = transaction
        .prepare(
            "SELECT operation_name, operation_version, command_digest
             FROM authenticated_operation_results_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2
             ORDER BY operation_name, operation_version, command_digest",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .query_map((workspace_id.to_string(), key), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if legacy_rows.len() > 1 {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "an authenticated operation key has multiple recorded results".to_owned(),
        ));
    }
    if let Some((operation_name, operation_version, command_digest)) = legacy_rows.first() {
        let exact_legacy_replay = presentation.command.operation
            == contract::AuthorityOperation::ContextBuildV1
            && operation_name == presentation.command.operation.name()
            && operation_version == presentation.command.operation.version()
            && command_digest == &presentation.command_digest.to_string();
        if exact_legacy_replay {
            return Ok(());
        }
        set_idempotency_denial(assessment);
        return Ok(());
    }

    let ledger: Option<LedgerRow> = transaction
        .query_row(
            "SELECT operation_name, operation_version, command_digest,
                    application_effect_digest
             FROM authenticated_application_idempotency_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            (workspace_id.to_string(), key),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if let Some((operation_name, operation_version, command_digest, consequence_digest)) = ledger {
        if operation_name != presentation.command.operation.name()
            || operation_version != presentation.command.operation.version()
            || command_digest != presentation.command_digest.to_string()
        {
            set_idempotency_denial(assessment);
            return Ok(());
        }
        let consequence_digest = consequence_digest
            .parse::<proof_application::ContentDigest>()
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
        assessment
            .application_idempotency
            .as_mut()
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "application replay lost its derived key".to_owned(),
                )
            })?
            .replay_application_effect_digest = Some(consequence_digest);
        return Ok(());
    }

    let prior_sources = prior_application_key_sources(transaction, workspace_id, key)?;
    if prior_sources.is_empty() {
        return Ok(());
    }
    let exact_context_selection = presentation.command.operation
        == contract::AuthorityOperation::ContextBuildV2
        && prior_sources.as_slice() == ["localized_context_build_operations"]
        && transaction
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM localized_context_build_operations
                     WHERE workspace_id = ?1 AND principal_id = ?2
                       AND idempotency_key = ?3 AND context_pack_id = ?4
                 )",
                (
                    workspace_id.to_string(),
                    presentation.command.requesting_principal_id.to_string(),
                    key,
                    match &presentation.operation_input {
                        contract::EnabledOperationInputV1::LocalizedContextBuild(input) => {
                            input.context_pack_id.to_string()
                        }
                        _ => String::new(),
                    },
                ),
                |row| row.get::<_, bool>(0),
            )
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if !exact_context_selection {
        set_idempotency_denial(assessment);
    }
    Ok(())
}

fn prior_application_key_sources(
    connection: &Connection,
    workspace_id: WorkspaceId,
    key: &str,
) -> Result<Vec<String>, contract::AuthorityError> {
    let table_names = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let mut sources = Vec::new();
    for table_name in table_names {
        let quoted_table = format!("\"{}\"", table_name.replace('"', "\"\""));
        let columns = connection
            .prepare(&format!("PRAGMA table_info({quoted_table})"))
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        if !columns.iter().any(|column| column == "idempotency_key") {
            continue;
        }
        let workspace_scoped = columns.iter().any(|column| column == "workspace_id");
        let exists = if workspace_scoped {
            connection
                .query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM {quoted_table}
                         WHERE workspace_id = ?1 AND idempotency_key = ?2)"
                    ),
                    (workspace_id.to_string(), key),
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        } else {
            connection
                .query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM {quoted_table} WHERE idempotency_key = ?1)"
                    ),
                    [key],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        };
        if exists {
            sources.push(table_name);
        }
    }
    Ok(sources)
}

fn set_idempotency_denial(assessment: &mut AuthorizationAssessment) {
    assessment.denial = Some((
        contract::AuthorizationDenialReason::IdempotencyKeyReused,
        contract::AuthorityError::IdempotencyKeyReused,
    ));
}

fn derived_changeset_application_key(
    workspace_id: WorkspaceId,
    input: &contract::EnabledOperationInputV1,
) -> Result<String, contract::AuthorityError> {
    let contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(input) = input else {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "derived ChangeSet key selected for the wrong operation".to_owned(),
        ));
    };
    let value = canonicalize(&json!({
        "api_version": "proof.dev/application-idempotency-key/v1",
        "changeset_id": input.changeset_id.to_string(),
        "operation": "changeset.submit/v2",
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    Ok(digest(ArtifactKind::OperationEffectV1, &value).to_string())
}

fn derived_validation_application_key(
    workspace_id: WorkspaceId,
    assessment: &AuthorizationAssessment,
) -> Result<Option<String>, contract::AuthorityError> {
    let AuthorizationApplicationClosure::LocalizedIntent(closure) = &assessment.application_closure
    else {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "derived validation key has no verified intent closure".to_owned(),
        ));
    };
    let (Some(changeset), Some(context)) = (&closure.changeset, &closure.context) else {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "derived validation key has incomplete ChangeSet evidence".to_owned(),
        ));
    };
    let diff = match localized::changeset_diff(changeset) {
        Ok(diff) => diff,
        Err(LocalPortError::Storage(detail)) => {
            return Err(contract::AuthorityError::Storage(detail));
        }
        Err(LocalPortError::Integrity(detail)) => {
            return Err(contract::AuthorityError::AuthorityIntegrity(detail));
        }
        Err(_) => return Ok(None),
    };
    let value = canonicalize(&json!({
        "api_version": "proof.dev/application-idempotency-key/v1",
        "changeset_id": changeset.changeset_id.to_string(),
        "operation": "changeset.validate/v2",
        "policy_digest": context.policy_digest.to_string(),
        "proposal_digest": diff.proposal_digest.to_string(),
        "validator": proof_application::LOCALIZED_CONTENT_VALIDATOR,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    Ok(Some(
        digest(ArtifactKind::OperationEffectV1, &value).to_string(),
    ))
}

fn authority_policy_bundle_digest()
-> Result<proof_application::ContentDigest, contract::AuthorityError> {
    let policy = canonicalize(&json!({
        "api_version": "proof.dev/policy-bundle/v1",
        "profile": contract::DIRECT_AUTHORITY_POLICY_PROFILE_V1,
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    Ok(digest(ArtifactKind::PolicyBundleV1, &policy))
}

fn prepare_authorization_decision(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    signer: &Ed25519SigningProvider,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    evaluated_at: Timestamp,
    localized_consequence_commitment: Option<contract::LocalizedConsequenceCommitmentV1>,
) -> Result<PreparedDecision, contract::AuthorityError> {
    let head = load_authority_head(transaction, workspace_id)?.ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity("authority log has no head".to_owned())
    })?;
    let root = load_workspace_authority_root(transaction, workspace_id)?;
    let signer_key_id = signer
        .metadata()
        .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?
        .key_id;
    if signer_key_id != root.authority_key_id.as_str() {
        return Err(contract::AuthorityError::AuthorityRootUnavailable);
    }
    let requested_action =
        contract::authority_operation_entry(presentation.command.operation).requested_action;
    let (outcome, reason_code) = assessment.denial.as_ref().map_or(
        (contract::AuthorizationDecisionOutcome::Allow, None),
        |(reason, _)| (contract::AuthorizationDecisionOutcome::Deny, Some(*reason)),
    );
    let decision = contract::AuthorizationDecisionV2 {
        api_version: contract::AuthorizationDecisionApiVersion::V1,
        authority_sequence: contract::AuthoritySequence::new(head.sequence.get() + 1)
            .map_err(contract_integrity)?,
        previous_authority_record_digest: head.record_digest,
        audience: contract::AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        evaluated_authority_head: head,
        authority_key_id: root.authority_key_id,
        operation: presentation.command.operation,
        requested_action,
        requested_resources: assessment.requested_resources.clone(),
        effective_constraints: assessment.effective_constraints,
        command_digest: presentation.command_digest,
        command_envelope_digest: presentation.command_envelope_digest,
        presentation_id: presentation.command.presentation_id,
        presentation_consumed: contract::PresentationConsumed,
        requesting_subject_commitment: presentation.actor_context.requesting_subject_commitment,
        actor_context_digest: presentation.actor_context_digest,
        requesting_principal_id: presentation.command.requesting_principal_id,
        operating_principal_id: presentation.command.operating_principal_id,
        principal_state: assessment.principal_state,
        binding: assessment.binding,
        delegation: assessment.delegation,
        policy_profile: contract::DirectAuthorityProfileV1::Direct,
        policy_bundle_digest: authority_policy_bundle_digest()?,
        localized_consequence_commitment,
        evaluated_at,
        decision: outcome,
        reason_code,
    };
    decision.validate().map_err(contract_integrity)?;
    let signed_decision = sign_authority_payload(
        AuthorityPayloadProfile::AuthorityRecord,
        &decision,
        &[signer],
    )
    .map_err(|error| contract::AuthorityError::Signing(error.to_string()))?;
    let record_value = parse_strict(signed_decision.payload_json.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let canonical_record = canonicalize(&record_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let record_digest = digest(ArtifactKind::AuthorityRecordV1, &canonical_record);
    Ok(PreparedDecision {
        decision,
        record_json: signed_decision.payload_json,
        record_digest,
        envelope_json: signed_decision.envelope_json,
        envelope_digest: signed_decision.envelope_digest,
        authority_key_id: signer_key_id,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one transaction persists the signed decision, redacted actor evidence, and single-use presentation cross-links"
)]
fn persist_authorization_decision(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    prepared: &PreparedDecision,
) -> Result<(), contract::AuthorityError> {
    let sequence = i64::try_from(prepared.decision.authority_sequence.get()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "authority sequence is out of range".to_owned(),
        )
    })?;
    transaction
        .execute(
            "INSERT INTO authority_records (
                 authority_sequence, workspace_id, previous_authority_record_digest,
                 record_kind, record_json, record_digest, envelope_json,
                 envelope_digest, authority_key_id, recorded_at
             ) VALUES (?1, ?2, ?3, 'authorization_decision_v2', ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                sequence,
                workspace_id.to_string(),
                prepared
                    .decision
                    .previous_authority_record_digest
                    .to_string(),
                prepared.record_json.as_str(),
                prepared.record_digest.to_string(),
                prepared.envelope_json.as_str(),
                prepared.envelope_digest.to_string(),
                prepared.authority_key_id.as_str(),
                prepared.decision.evaluated_at.to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let evidence_json = canonical_json(
        &presentation.actor_context_evidence,
        "authenticated actor context evidence",
    )?;
    transaction
        .execute(
            "INSERT INTO authenticated_actor_context_evidence_v1 (
                 presentation_id, workspace_id, evidence_json,
                 actor_context_digest, authenticated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                presentation.command.presentation_id.to_string(),
                workspace_id.to_string(),
                evidence_json,
                presentation.actor_context_digest.to_string(),
                presentation.actor_context.authenticated_at.to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let decision_name = serialized_enum_name(&prepared.decision.decision, "decision outcome")?;
    let reason_code = prepared
        .decision
        .reason_code
        .map(|reason| serialized_enum_name(&reason, "decision reason"))
        .transpose()?;
    let requested_action = serialized_enum_name(
        &prepared.decision.requested_action,
        "requested authority action",
    )?;
    transaction
        .execute(
            "INSERT INTO authorization_decisions_v2 (
                 authority_sequence, presentation_id, workspace_id, command_digest,
                 command_envelope_digest, requesting_principal_id,
                 operating_principal_id, binding_id, delegation_id,
                 operation_name, operation_version, requested_action,
                 decision, reason_code, evaluated_at, decision_json,
                 decision_digest
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                 ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
             )",
            rusqlite::params![
                sequence,
                prepared.decision.presentation_id.to_string(),
                workspace_id.to_string(),
                prepared.decision.command_digest.to_string(),
                prepared.decision.command_envelope_digest.to_string(),
                prepared.decision.requesting_principal_id.to_string(),
                prepared.decision.operating_principal_id.to_string(),
                prepared.decision.binding.binding_id.to_string(),
                prepared.decision.delegation.delegation_id.to_string(),
                prepared.decision.operation.name(),
                prepared.decision.operation.version(),
                requested_action,
                decision_name,
                reason_code,
                prepared.decision.evaluated_at.to_string(),
                prepared.record_json.as_str(),
                prepared.record_digest.to_string(),
            ],
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    transaction
        .execute(
            "INSERT INTO presentation_consumptions_v1 (
                 presentation_id, workspace_id, command_digest,
                 command_envelope_digest, decision_authority_sequence, consumed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                prepared.decision.presentation_id.to_string(),
                workspace_id.to_string(),
                prepared.decision.command_digest.to_string(),
                prepared.decision.command_envelope_digest.to_string(),
                sequence,
                prepared.decision.evaluated_at.to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    Ok(())
}

struct LocalizedResultEvidence {
    result_kind: &'static str,
    operation_output_schema: &'static str,
    result_contract: &'static str,
    result_json: String,
    result_digest: proof_application::ContentDigest,
    application_effect_digest: proof_application::ContentDigest,
    application_consequence_digest: proof_application::ContentDigest,
    selectors_json: String,
    closure: serde_json::Value,
}

impl LocalizedResultEvidence {
    fn commitment(
        &self,
        operation: contract::AuthorityOperation,
    ) -> Result<contract::LocalizedConsequenceCommitmentV1, contract::AuthorityError> {
        let result_kind = match self.result_kind {
            "success" => contract::LocalizedConsequenceResultKindV1::Success,
            "failure" => contract::LocalizedConsequenceResultKindV1::Failure,
            _ => {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized result evidence has an unknown kind".to_owned(),
                ));
            }
        };
        let commitment = contract::LocalizedConsequenceCommitmentV1::new(
            operation,
            result_kind,
            self.result_digest,
            self.application_consequence_digest,
        )
        .map_err(contract_integrity)?;
        if commitment.result_contract != self.result_contract {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized result contract differs from the signed commitment".to_owned(),
            ));
        }
        Ok(commitment)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "localized consequence persistence atomically cross-links the signed decision, canonical result, ledger, and P7 effect"
)]
fn persist_authenticated_localized_consequence(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    prepared: &PreparedDecision,
    evidence: &LocalizedResultEvidence,
) -> Result<(), contract::AuthorityError> {
    if prepared.decision.decision != contract::AuthorizationDecisionOutcome::Allow {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized consequence is not anchored to an Allow decision".to_owned(),
        ));
    }
    let expected_commitment = evidence.commitment(presentation.command.operation)?;
    if prepared.decision.localized_consequence_commitment.as_ref() != Some(&expected_commitment) {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized consequence differs from its signed decision commitment".to_owned(),
        ));
    }
    let (idempotency_kind, idempotency_key) = localized_idempotency_evidence(
        presentation.command.operation,
        assessment,
        evidence.result_kind,
    )?;
    let selectors = canonicalize(
        &parse_strict(evidence.selectors_json.as_bytes())
            .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?,
    )
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if selectors.as_str() != evidence.selectors_json {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized consequence selectors are not canonical".to_owned(),
        ));
    }
    let signed_selectors = canonicalize(&json!({
        "changeset_ids": prepared.decision.requested_resources.changeset_ids,
        "edition_ids": prepared.decision.requested_resources.edition_ids,
        "release_ids": prepared.decision.requested_resources.release_ids,
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    if selectors.as_str() != signed_selectors.as_str() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized consequence selectors differ from the signed decision".to_owned(),
        ));
    }
    let consequence = canonicalize(&json!({
        "api_version": "proof.dev/authenticated-localized-consequence/v1",
        "application_consequence_digest": evidence.application_consequence_digest.to_string(),
        "application_idempotency": {
            "key": idempotency_key,
            "kind": idempotency_kind,
        },
        "authorization_decision_digest": prepared.record_digest.to_string(),
        "closure": evidence.closure,
        "command_digest": presentation.command_digest.to_string(),
        "delegation_id": presentation.command.delegation_id.to_string(),
        "operating_principal_id": presentation.command.operating_principal_id.to_string(),
        "operation": {
            "name": presentation.command.operation.name(),
            "version": presentation.command.operation.version(),
        },
        "operation_output_schema": evidence.operation_output_schema,
        "presentation_id": presentation.command.presentation_id.to_string(),
        "requesting_principal_id": presentation.command.requesting_principal_id.to_string(),
        "result": {
            "contract": evidence.result_contract,
            "digest": evidence.result_digest.to_string(),
            "kind": evidence.result_kind,
        },
        "application_effect_digest": evidence.application_effect_digest.to_string(),
        "selectors": parse_strict(selectors.as_bytes()).map_err(|error| {
            contract::AuthorityError::AuthorityIntegrity(error.to_string())
        })?,
        "semantic_timestamp": presentation
            .operation_input
            .semantic_timestamp()
            .map(|value| value.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let evidence_digest = digest(ArtifactKind::OperationEffectV1, &consequence);
    let sequence = i64::try_from(prepared.decision.authority_sequence.get()).map_err(|_| {
        contract::AuthorityError::AuthorityIntegrity(
            "localized consequence authority sequence is out of range".to_owned(),
        )
    })?;

    if evidence.result_kind == "success"
        && let Some(key) = idempotency_key
    {
        persist_authenticated_application_key(
            transaction,
            workspace_id,
            key,
            idempotency_kind,
            presentation,
            assessment,
            evidence,
            sequence,
        )?;
    }

    transaction
        .execute(
            "INSERT INTO authenticated_localized_consequences_v1 (
                 decision_authority_sequence, presentation_id, workspace_id,
                 requesting_principal_id, operating_principal_id, delegation_id,
                 command_digest, authorization_decision_digest, operation_name,
                 operation_version, application_idempotency_kind,
                 application_idempotency_key, result_kind, result_contract,
                 result_json, result_digest, application_effect_digest,
                 application_consequence_digest, selectors_json, evidence_json,
                 evidence_digest
             ) VALUES (
                 ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                 ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21
             )",
            rusqlite::params![
                sequence,
                presentation.command.presentation_id.to_string(),
                workspace_id.to_string(),
                presentation.command.requesting_principal_id.to_string(),
                presentation.command.operating_principal_id.to_string(),
                presentation.command.delegation_id.to_string(),
                presentation.command_digest.to_string(),
                prepared.record_digest.to_string(),
                presentation.command.operation.name(),
                presentation.command.operation.version(),
                idempotency_kind,
                idempotency_key,
                evidence.result_kind,
                evidence.result_contract,
                evidence.result_json,
                evidence.result_digest.to_string(),
                evidence.application_effect_digest.to_string(),
                evidence.application_consequence_digest.to_string(),
                selectors.as_str(),
                consequence.as_str(),
                evidence_digest.to_string(),
            ],
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "localized result evidence builds one canonical signed composite across the closed result union"
)]
fn localized_result_evidence(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    result: &contract::AuthenticatedOperationResultV1,
) -> Result<LocalizedResultEvidence, contract::AuthorityError> {
    let operation_output_schema =
        contract::localized_operation_output_schema_uri(presentation.command.operation)
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized operation has no output Schema".to_owned(),
                )
            })?;
    let (result_kind, result_contract) = match result {
        contract::AuthenticatedOperationResultV1::LocalizedSuccess(success) => {
            if success.operation() != presentation.command.operation {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized success operation differs from its signed command".to_owned(),
                ));
            }
            ("success", operation_output_schema)
        }
        contract::AuthenticatedOperationResultV1::LocalizedFailure(failure) => {
            if failure.operation != presentation.command.operation {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "localized failure operation differs from its signed command".to_owned(),
                ));
            }
            (
                "failure",
                contract::LOCALIZED_PUBLIC_PROBLEM_RESULT_CONTRACT_V1,
            )
        }
        _ => {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "non-localized result reached localized consequence persistence".to_owned(),
            ));
        }
    };
    let result_value = result
        .localized_result_value()
        .map_err(contract_integrity)?
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized result has no application-owned canonical value".to_owned(),
            )
        })?;
    let canonical_result = canonicalize(&result_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let result_digest = result
        .localized_result_digest()
        .map_err(contract_integrity)?
        .ok_or_else(|| {
            contract::AuthorityError::AuthorityIntegrity(
                "localized result has no application-owned digest".to_owned(),
            )
        })?;
    let application_effect_digest = match result {
        contract::AuthenticatedOperationResultV1::LocalizedSuccess(success) => {
            localized_success_effect_digest(
                transaction,
                workspace_id,
                presentation,
                assessment,
                success,
                result_digest,
            )?
        }
        contract::AuthenticatedOperationResultV1::LocalizedFailure(_) => result_digest,
        _ => unreachable!("localized result union was checked above"),
    };
    let (idempotency_kind, idempotency_key) =
        localized_idempotency_evidence(presentation.command.operation, assessment, result_kind)?;
    let selectors = canonicalize(&json!({
        "changeset_ids": assessment.requested_resources.changeset_ids,
        "edition_ids": assessment.requested_resources.edition_ids,
        "release_ids": assessment.requested_resources.release_ids,
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let closure = localized_closure_evidence(transaction, assessment, result)?;
    let composite = canonicalize(&json!({
        "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
        "application_effect_digest": application_effect_digest.to_string(),
        "application_idempotency": {
            "key": idempotency_key,
            "kind": idempotency_kind,
        },
        "closure": closure,
        "command_digest": presentation.command_digest.to_string(),
        "delegation_id": presentation.command.delegation_id.to_string(),
        "operating_principal_id": presentation.command.operating_principal_id.to_string(),
        "operation": {
            "name": presentation.command.operation.name(),
            "version": presentation.command.operation.version(),
        },
        "requesting_principal_id": presentation.command.requesting_principal_id.to_string(),
        "result": {
            "contract": result_contract,
            "digest": result_digest.to_string(),
            "kind": result_kind,
        },
        "selectors": parse_strict(selectors.as_bytes()).map_err(|error| {
            contract::AuthorityError::AuthorityIntegrity(error.to_string())
        })?,
        "semantic_timestamp": presentation
            .operation_input
            .semantic_timestamp()
            .map(|value| value.to_string()),
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let application_consequence_digest = digest(ArtifactKind::OperationEffectV1, &composite);
    Ok(LocalizedResultEvidence {
        result_kind,
        operation_output_schema,
        result_contract,
        result_json: canonical_result.as_str().to_owned(),
        result_digest,
        application_effect_digest,
        application_consequence_digest,
        selectors_json: selectors.as_str().to_owned(),
        closure,
    })
}

fn localized_success_effect_digest(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    success: &contract::LocalizedOperationSuccessV1,
    result_digest: proof_application::ContentDigest,
) -> Result<proof_application::ContentDigest, contract::AuthorityError> {
    let principal_id = presentation.command.requesting_principal_id.to_string();
    let required_key = assessment
        .application_idempotency
        .as_ref()
        .and_then(|value| value.key.as_deref());
    let raw = match success {
        contract::LocalizedOperationSuccessV1::ContextBuilt(_) => Some(localized_digest_row(
            transaction,
            "SELECT effect_digest FROM localized_context_build_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.as_str(),
                required_key.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized Context replay has no application key".to_owned(),
                    )
                })?,
            ),
        )?),
        contract::LocalizedOperationSuccessV1::ChangeSetCreated(value) => {
            Some(localized_digest_row(
                transaction,
                "SELECT effect_digest FROM localized_changesets WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )?)
        }
        contract::LocalizedOperationSuccessV1::EditsAdded(_) => Some(localized_digest_row(
            transaction,
            "SELECT effect_digest FROM localized_add_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.as_str(),
                required_key.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized Add has no application key".to_owned(),
                    )
                })?,
            ),
        )?),
        contract::LocalizedOperationSuccessV1::ChangeSetRead(_)
        | contract::LocalizedOperationSuccessV1::ChangeSetDiffed(_)
        | contract::LocalizedOperationSuccessV1::ReleasedRenditionsQueried(_) => None,
        contract::LocalizedOperationSuccessV1::ChangeSetValidated(value) => {
            Some(value.validation_results_digest)
        }
        contract::LocalizedOperationSuccessV1::ChangeSetSubmitted(value) => {
            Some(localized_digest_row(
                transaction,
                "SELECT effect_digest FROM localized_submissions WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )?)
        }
        contract::LocalizedOperationSuccessV1::ChangeSetCommitted(value) => {
            Some(localized_digest_row(
                transaction,
                "SELECT effect_digest FROM localized_commits WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )?)
        }
        contract::LocalizedOperationSuccessV1::EditionCreated(_) => Some(localized_digest_row(
            transaction,
            "SELECT effect_digest FROM localized_edition_operations
             WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
            (
                workspace_id.to_string(),
                principal_id.as_str(),
                required_key.ok_or_else(|| {
                    contract::AuthorityError::AuthorityIntegrity(
                        "localized Edition has no application key".to_owned(),
                    )
                })?,
            ),
        )?),
        contract::LocalizedOperationSuccessV1::ReleaseCreated(value) => Some(value.release_digest),
    };
    Ok(raw.unwrap_or(result_digest))
}

fn localized_digest_row<P: rusqlite::Params>(
    transaction: &Transaction<'_>,
    statement: &str,
    params: P,
) -> Result<proof_application::ContentDigest, contract::AuthorityError> {
    let raw = transaction
        .query_row(statement, params, |row| row.get::<_, String>(0))
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    raw.parse::<proof_application::ContentDigest>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
}

fn localized_idempotency_evidence<'a>(
    operation: contract::AuthorityOperation,
    assessment: &'a AuthorizationAssessment,
    result_kind: &str,
) -> Result<(&'static str, Option<&'a str>), contract::AuthorityError> {
    match contract::authority_operation_entry(operation).application_idempotency {
        contract::ApplicationIdempotency::None => Ok(("none", None)),
        contract::ApplicationIdempotency::RequiredUuidV7 => {
            let value = assessment.application_idempotency.as_ref().ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "required application key was not assessed".to_owned(),
                )
            })?;
            if value.kind != ApplicationIdempotencyKind::Required || value.key.is_none() {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "required application key has the wrong evidence kind".to_owned(),
                ));
            }
            Ok(("required", value.key.as_deref()))
        }
        contract::ApplicationIdempotency::DerivedChangeset
        | contract::ApplicationIdempotency::DerivedProposalPolicyValidator => {
            let value = assessment.application_idempotency.as_ref().ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "derived application key was not assessed".to_owned(),
                )
            })?;
            if value.kind != ApplicationIdempotencyKind::Derived
                || (result_kind == "success" && value.key.is_none())
            {
                return Err(contract::AuthorityError::AuthorityIntegrity(
                    "derived application key has the wrong evidence kind".to_owned(),
                ));
            }
            Ok(("derived", value.key.as_deref()))
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the global ledger insertion binds its transaction, actors, stable key identity, result, effect, and first sequence"
)]
fn persist_authenticated_application_key(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    key: &str,
    idempotency_kind: &str,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    evidence: &LocalizedResultEvidence,
    sequence: i64,
) -> Result<(), contract::AuthorityError> {
    type ExistingKey = (String, String, String, String, String, String);
    let existing: Option<ExistingKey> = transaction
        .query_row(
            "SELECT idempotency_kind, operation_name, operation_version,
                    command_digest, result_digest, application_effect_digest
             FROM authenticated_application_idempotency_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            (workspace_id.to_string(), key),
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
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if let Some(existing) = existing {
        let replay_expected = assessment
            .application_idempotency
            .as_ref()
            .is_some_and(|value| value.replay_application_effect_digest.is_some());
        if !replay_expected
            || existing.0 != idempotency_kind
            || existing.1 != presentation.command.operation.name()
            || existing.2 != presentation.command.operation.version()
            || existing.3 != presentation.command_digest.to_string()
            || existing.4 != evidence.result_digest.to_string()
            || existing.5 != evidence.application_effect_digest.to_string()
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authenticated application replay ledger does not reproduce".to_owned(),
            ));
        }
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO authenticated_application_idempotency_v1 (
                 workspace_id, idempotency_key, idempotency_kind, operation_name,
                 operation_version, command_digest, result_digest,
                 application_effect_digest, application_consequence_digest,
                 first_decision_authority_sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                workspace_id.to_string(),
                key,
                idempotency_kind,
                presentation.command.operation.name(),
                presentation.command.operation.version(),
                presentation.command_digest.to_string(),
                evidence.result_digest.to_string(),
                evidence.application_effect_digest.to_string(),
                evidence.application_consequence_digest.to_string(),
                sequence,
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "closure evidence explicitly binds every optional immutable P7 artifact and Human approval field"
)]
fn localized_closure_evidence(
    transaction: &Transaction<'_>,
    assessment: &AuthorizationAssessment,
    result: &contract::AuthenticatedOperationResultV1,
) -> Result<serde_json::Value, contract::AuthorityError> {
    let AuthorizationApplicationClosure::LocalizedIntent(closure) = &assessment.application_closure
    else {
        if let AuthorizationApplicationClosure::LocalizedReleased(projection) =
            &assessment.application_closure
        {
            return Ok(json!({
                "edition_id": projection.edition_id.map(|value| value.to_string()),
                "release_id": projection.release_id.map(|value| value.to_string()),
                "schema_ids": projection
                    .schema_ids
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            }));
        }
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "localized consequence has no localized closure".to_owned(),
        ));
    };
    let context = closure.context.as_ref().or(match result {
        contract::AuthenticatedOperationResultV1::LocalizedSuccess(
            contract::LocalizedOperationSuccessV1::ContextBuilt(context),
        ) => Some(context),
        _ => None,
    });
    let approval = if let Some(changeset) = &closure.changeset {
        let row = transaction
            .query_row(
                "SELECT approval.approval_name, approval.principal_id,
                        approval.approved_at, approval.effect_digest,
                        principal.principal_type, principal.enabled
                 FROM localized_approvals AS approval
                 JOIN principals AS principal
                   ON principal.principal_id = approval.principal_id
                 WHERE approval.changeset_id = ?1",
                [changeset.changeset_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
        row.map(
            |(approval_name, principal_id, approved_at, effect_digest, kind, enabled)| {
                if kind != "human" || !enabled {
                    return Err(contract::AuthorityError::AuthorityIntegrity(
                        "localized approval principal is not an enabled Human".to_owned(),
                    ));
                }
                Ok(json!({
                    "approval_name": approval_name,
                    "approved_at": approved_at,
                    "effect_digest": effect_digest,
                    "principal_id": principal_id,
                }))
            },
        )
        .transpose()?
    } else {
        None
    };
    let successful_approval_required = matches!(
        result,
        contract::AuthenticatedOperationResultV1::LocalizedSuccess(
            contract::LocalizedOperationSuccessV1::ChangeSetCommitted(_)
                | contract::LocalizedOperationSuccessV1::EditionCreated(_)
                | contract::LocalizedOperationSuccessV1::ReleaseCreated(_)
        )
    );
    if successful_approval_required && approval.is_none() {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "consequential localized success lacks enabled Human approval".to_owned(),
        ));
    }
    Ok(json!({
        "approval": approval,
        "changeset": closure.changeset.as_ref().map(|value| json!({
            "changeset_id": value.changeset_id.to_string(),
            "context_pack_digest": value.context_pack_digest.to_string(),
            "context_pack_id": value.context_pack_id.to_string(),
            "resource_intent_digest": value.resource_intent_digest.to_string(),
            "resource_intent_id": value.resource_intent_id.to_string(),
        })),
        "context": context.map(|value| json!({
            "context_pack_digest": value.context_pack_digest.to_string(),
            "context_pack_id": value.context_pack_id.to_string(),
            "limits": {
                "max_bytes": value.limits.max_bytes,
                "max_edits": value.limits.max_edits,
                "max_objects": value.limits.max_objects,
                "max_validation_attempts": value.limits.max_validation_attempts,
            },
            "policy_digest": value.policy_digest.to_string(),
        })),
        "context_fresh": closure.context_fresh,
        "resource_intent": {
            "intent_digest": closure.intent.intent_digest.to_string(),
            "intent_id": closure.intent.intent_id.to_string(),
            "issued_by_principal_id": closure.intent.issued_by_principal_id.to_string(),
        },
        "validator": proof_application::LOCALIZED_CONTENT_VALIDATOR,
    }))
}

fn authority_from_local_port(error: LocalPortError) -> contract::AuthorityError {
    match error {
        LocalPortError::Unauthenticated => contract::AuthorityError::AuthDenied,
        LocalPortError::IdempotencyKeyReused => contract::AuthorityError::IdempotencyKeyReused,
        LocalPortError::LimitExceeded => contract::AuthorityError::BudgetExceeded,
        LocalPortError::Expired => contract::AuthorityError::AuthExpired,
        LocalPortError::PolicyDenied => contract::AuthorityError::PolicyDenied,
        LocalPortError::Signing(detail) => contract::AuthorityError::Signing(detail),
        LocalPortError::Storage(detail) => contract::AuthorityError::Storage(detail),
        LocalPortError::Integrity(detail) => contract::AuthorityError::AuthorityIntegrity(detail),
        LocalPortError::Denied
        | LocalPortError::NotFound
        | LocalPortError::UnsupportedVersion
        | LocalPortError::Invalid
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
        | LocalPortError::InvalidRollbackTarget
        | LocalPortError::StateConflict => contract::AuthorityError::AuthorizationDenied,
    }
}

fn delegated_capability_versions_v2(delegation: &contract::DelegationV2) -> Vec<String> {
    let mut versions = proof_application::capabilities()
        .iter()
        .filter(|capability| {
            let action = match capability.required_action {
                DelegatedAction::ChangesetAdd => contract::AuthorityAction::ChangesetAdd,
                DelegatedAction::ChangesetCommit => contract::AuthorityAction::ChangesetCommit,
                DelegatedAction::ChangesetCreate => contract::AuthorityAction::ChangesetCreate,
                DelegatedAction::ChangesetDiff => contract::AuthorityAction::ChangesetDiff,
                DelegatedAction::ChangesetGet => contract::AuthorityAction::ChangesetGet,
                DelegatedAction::ChangesetSubmit => contract::AuthorityAction::ChangesetSubmit,
                DelegatedAction::ChangesetValidate => contract::AuthorityAction::ChangesetValidate,
                DelegatedAction::WorkspaceStatus => contract::AuthorityAction::WorkspaceStatus,
                DelegatedAction::ObjectQueryReleased => {
                    contract::AuthorityAction::ObjectQueryReleased
                }
                DelegatedAction::ContextBuild => contract::AuthorityAction::ContextBuild,
                DelegatedAction::EditionCreate => contract::AuthorityAction::EditionCreate,
                DelegatedAction::ReleaseCreate => contract::AuthorityAction::ReleaseCreate,
            };
            delegation.actions.as_slice().contains(&action)
        })
        .map(|capability| capability.version.to_owned())
        .collect::<Vec<_>>();
    versions.sort();
    versions
}

#[expect(
    clippy::too_many_arguments,
    reason = "ContextPack verification cross-checks every actor, resource, budget, time, and decision identity committed by its manifest"
)]
pub(super) fn verify_authenticated_context_pack_authority(
    connection: &Connection,
    workspace_id: WorkspaceId,
    requesting_principal_id: PrincipalId,
    operating_principal_id: PrincipalId,
    delegation_id: proof_application::DelegationId,
    environment_id: &EnvironmentId,
    object_ids: &[ObjectId],
    limits: ContextPackLimits,
    built_at: Timestamp,
    expires_at: Timestamp,
    authorization_decision_digest: proof_application::ContentDigest,
) -> Result<Vec<String>, LocalPortError> {
    verify_authority_log(connection, workspace_id).map_err(authority_to_local_port)?;
    let decision_json = connection
        .query_row(
            "SELECT decision_json FROM authorization_decisions_v2
             WHERE workspace_id = ?1 AND decision_digest = ?2",
            (
                workspace_id.to_string(),
                authorization_decision_digest.to_string(),
            ),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .ok_or_else(|| {
            LocalPortError::Integrity(
                "ContextPack authorization decision is absent from the authority log".to_owned(),
            )
        })?;
    let decision: contract::AuthorizationDecisionV2 =
        decode_canonical(&decision_json, "ContextPack authorization decision")
            .map_err(authority_to_local_port)?;
    decision.validate().map_err(|error| {
        LocalPortError::Integrity(format!(
            "ContextPack authorization decision is invalid: {error}"
        ))
    })?;
    let delegation = load_delegation_v2(connection, workspace_id, delegation_id)
        .map_err(authority_to_local_port)?
        .ok_or_else(|| {
            LocalPortError::Integrity(
                "ContextPack Delegation is absent from the authority log".to_owned(),
            )
        })?;
    let delegation_record_digest = connection
        .query_row(
            "SELECT record_digest FROM delegations_v2
             WHERE workspace_id = ?1 AND delegation_id = ?2",
            (workspace_id.to_string(), delegation_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| LocalPortError::Storage(error.to_string()))?
        .parse::<proof_application::ContentDigest>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let requested = &decision.requested_resources;
    let empty_dimensions = requested.schema_ids.as_slice().is_empty()
        && requested.locales.as_slice().is_empty()
        && requested.changeset_ids.as_slice().is_empty()
        && requested.edition_ids.as_slice().is_empty()
        && requested.release_ids.as_slice().is_empty();
    let decision_matches = decision.workspace_id == workspace_id
        && decision.operation == contract::AuthorityOperation::ContextBuildV1
        && decision.requested_action == contract::AuthorityAction::ContextBuild
        && decision.requesting_principal_id == requesting_principal_id
        && decision.operating_principal_id == operating_principal_id
        && decision.evaluated_at >= built_at
        && decision.decision == contract::AuthorizationDecisionOutcome::Allow
        && decision.reason_code.is_none()
        && decision.delegation.delegation_id == delegation_id
        && decision.delegation.resolution == contract::DelegationResolutionV2::Resolved
        && decision.delegation.record_digest == Some(delegation_record_digest)
        && decision.delegation.revocation_record_digest.is_none()
        && requested.workspace_ids.as_slice() == [workspace_id]
        && requested.environment_ids.as_slice() == [environment_id.clone()]
        && requested.object_ids.as_slice() == object_ids
        && empty_dimensions
        && decision.effective_constraints.max_objects.get() >= limits.max_objects
        && u64::from(decision.effective_constraints.max_context_bytes.get()) >= limits.max_bytes;
    let delegation_matches = delegation.workspace_id == workspace_id
        && delegation.delegation_id == delegation_id
        && delegation.issuer_principal_id == requesting_principal_id
        && delegation.recipient_principal_id == operating_principal_id
        && delegation
            .actions
            .as_slice()
            .contains(&contract::AuthorityAction::ContextBuild)
        && delegation
            .scope
            .environment_ids
            .as_slice()
            .binary_search(environment_id)
            .is_ok()
        && object_ids.iter().all(|object_id| {
            delegation
                .scope
                .object_ids
                .as_slice()
                .binary_search(object_id)
                .is_ok()
        })
        && delegation.is_time_active(built_at)
        && expires_at <= delegation.expires_at
        && limits.max_objects <= delegation.constraints.max_objects.get()
        && limits.max_bytes <= u64::from(delegation.constraints.max_context_bytes.get());
    if !decision_matches || !delegation_matches {
        return Err(LocalPortError::Integrity(
            "ContextPack authenticated authority does not reproduce".to_owned(),
        ));
    }
    Ok(delegated_capability_versions_v2(&delegation))
}

fn authority_to_local_port(error: contract::AuthorityError) -> LocalPortError {
    match error {
        contract::AuthorityError::Storage(detail) => LocalPortError::Storage(detail),
        contract::AuthorityError::AuthorityIntegrity(detail)
        | contract::AuthorityError::Signing(detail) => LocalPortError::Integrity(detail),
        other => LocalPortError::Integrity(other.to_string()),
    }
}

fn persist_context_result(
    transaction: &Transaction<'_>,
    presentation: &VerifiedPresentation,
    context_pack: &proof_application::ContextPack,
) -> Result<(), contract::AuthorityError> {
    let idempotency_key = presentation.command.idempotency_key.ok_or_else(|| {
        contract::AuthorityError::AuthorityIntegrity(
            "Context build lacks its required idempotency key".to_owned(),
        )
    })?;
    let existing: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT command_digest, result_json, result_digest
             FROM authenticated_operation_results_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2",
            (
                presentation.command.workspace_id.to_string(),
                idempotency_key.to_string(),
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if let Some((command_digest, result_json, result_digest)) = existing {
        if command_digest != presentation.command_digest.to_string()
            || result_json != context_pack.manifest_json
            || result_digest != context_pack.context_pack_digest.to_string()
        {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "authenticated Context result does not reproduce".to_owned(),
            ));
        }
        return Ok(());
    }
    transaction
        .execute(
            "INSERT INTO authenticated_operation_results_v1 (
                 workspace_id, requesting_principal_id, operating_principal_id,
                 delegation_id, operation_name, operation_version,
                 idempotency_key, command_digest, result_json, result_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            (
                presentation.command.workspace_id.to_string(),
                presentation.command.requesting_principal_id.to_string(),
                presentation.command.operating_principal_id.to_string(),
                presentation.command.delegation_id.to_string(),
                presentation.command.operation.name(),
                presentation.command.operation.version(),
                idempotency_key.to_string(),
                presentation.command_digest.to_string(),
                context_pack.manifest_json.as_str(),
                context_pack.context_pack_digest.to_string(),
            ),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    Ok(())
}

fn localized_application_result(
    operation: contract::AuthorityOperation,
    result: Result<contract::LocalizedOperationSuccessV1, LocalPortError>,
) -> Result<contract::AuthenticatedOperationResultV1, contract::AuthorityError> {
    match result {
        Ok(success) => Ok(contract::AuthenticatedOperationResultV1::LocalizedSuccess(
            success,
        )),
        Err(LocalPortError::IdempotencyKeyReused) => {
            Err(contract::AuthorityError::IdempotencyKeyReused)
        }
        Err(LocalPortError::Storage(detail)) => Err(contract::AuthorityError::Storage(detail)),
        Err(LocalPortError::Integrity(detail)) => {
            Err(contract::AuthorityError::AuthorityIntegrity(detail))
        }
        Err(LocalPortError::Signing(detail)) => Err(contract::AuthorityError::Signing(detail)),
        Err(LocalPortError::Unauthenticated) => Err(contract::AuthorityError::AuthorityIntegrity(
            "authority-owned localized consequence re-authenticated its Human".to_owned(),
        )),
        Err(error) => {
            let application_error = localized::localized_from_local_port(error);
            let kind = contract::LocalizedOperationFailureKindV1::from_application_error(
                &application_error,
            )
            .ok_or_else(|| {
                contract::AuthorityError::AuthorityIntegrity(
                    "localized application failure has no caller-safe mapping".to_owned(),
                )
            })?;
            let failure = contract::LocalizedOperationFailureV1::new(operation, kind)
                .map_err(contract_integrity)?;
            Ok(contract::AuthenticatedOperationResultV1::LocalizedFailure(
                failure,
            ))
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixed 11-row registry maps explicitly to existing P-0007 transaction helpers"
)]
fn execute_localized_consequence(
    repository: &LocalWorkspace,
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
) -> Result<contract::AuthenticatedOperationResultV1, contract::AuthorityError> {
    if let AuthorizationApplicationClosure::LocalizedIntent(closure) =
        &assessment.application_closure
        && !closure.context_fresh
    {
        return localized_application_result(
            presentation.command.operation,
            Err(LocalPortError::PolicyDenied),
        );
    }
    let requesting_principal_id = presentation.command.requesting_principal_id;
    let operation = presentation.command.operation;
    let result = match &presentation.operation_input {
        contract::EnabledOperationInputV1::LocalizedContextBuild(input) => {
            let command = input.clone().into_application_command();
            localized::replay_existing_context(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
            .map(contract::LocalizedOperationSuccessV1::ContextBuilt)
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCreate(input) => {
            let command = input.clone().into_application_command();
            localized::create_changeset(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
            .map(contract::LocalizedOperationSuccessV1::ChangeSetCreated)
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetAdd(input) => (|| {
            let edits = input
                .edits
                .iter()
                .cloned()
                .map(|edit| {
                    let content = canonicalize(&serde_json::Value::Object(edit.content().clone()))
                        .map_err(|_| LocalPortError::Invalid)?
                        .as_str()
                        .to_owned();
                    edit.into_application_input(content)
                        .map_err(|_| LocalPortError::Invalid)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let assigned_edit_ids = (0..edits.len())
                .map(|index| {
                    proof_assigned_edit_id(
                        presentation.command.presentation_id.to_string().as_str(),
                        index,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            let command = proof_application::AddLocalizedEditsCommand {
                changeset_id: input.changeset_id,
                edits,
                assigned_edit_ids,
                idempotency_key: input.idempotency_key,
            };
            localized::add_edits(transaction, workspace_id, requesting_principal_id, &command)
                .map(contract::LocalizedOperationSuccessV1::EditsAdded)
        })(),
        contract::EnabledOperationInputV1::LocalizedChangeSetGet(input) => {
            localized::load_changeset(transaction, workspace_id, input.changeset_id).and_then(
                |changeset| {
                    let diff = localized::changeset_diff(&changeset)?;
                    Ok(contract::LocalizedOperationSuccessV1::ChangeSetRead(
                        contract::LocalizedChangeSetReadV1 {
                            changeset,
                            effective_leaf_digest: diff.effective_leaf_digest,
                        },
                    ))
                },
            )
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetDiff(input) => {
            localized::load_changeset(transaction, workspace_id, input.changeset_id)
                .and_then(|changeset| localized::changeset_diff(&changeset))
                .map(contract::LocalizedOperationSuccessV1::ChangeSetDiffed)
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetValidate(input) => {
            let replay = assessment
                .application_idempotency
                .as_ref()
                .and_then(|value| value.replay_application_effect_digest);
            replay
                .map_or_else(
                    || {
                        localized::validate_changeset(
                            transaction,
                            workspace_id,
                            requesting_principal_id,
                            input.changeset_id,
                        )
                    },
                    |validation_results_digest| {
                        localized::replay_validation_for_authenticated_operation(
                            transaction,
                            workspace_id,
                            requesting_principal_id,
                            input.changeset_id,
                            validation_results_digest,
                        )
                    },
                )
                .map(contract::LocalizedOperationSuccessV1::ChangeSetValidated)
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(input) => {
            localized::submit_changeset(
                transaction,
                workspace_id,
                requesting_principal_id,
                input.changeset_id,
                input.submitted_at,
            )
            .map(contract::LocalizedOperationSuccessV1::ChangeSetSubmitted)
        }
        contract::EnabledOperationInputV1::LocalizedChangeSetCommit(input) => {
            let command = input.into_application_command();
            localized::commit_changeset(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
            .map(contract::LocalizedOperationSuccessV1::ChangeSetCommitted)
        }
        contract::EnabledOperationInputV1::LocalizedEditionCreate(input) => {
            let command = input.into_application_command();
            localized::create_localized_edition(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
            )
            .map(contract::LocalizedOperationSuccessV1::EditionCreated)
        }
        contract::EnabledOperationInputV1::LocalizedReleaseCreate(input) => {
            let command = input.clone().into_application_command();
            localized::promote_localized_release_transaction(
                transaction,
                workspace_id,
                requesting_principal_id,
                &command,
                || repository.preflight_release_proof_export(command.proof_id),
                || repository.load_or_create_release_signer(command.release_id),
            )
            .map(contract::LocalizedOperationSuccessV1::ReleaseCreated)
        }
        contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(input) => {
            let command = input.clone().into_application_command();
            localized::query_released_renditions(transaction, workspace_id, &command)
                .map(contract::LocalizedOperationSuccessV1::ReleasedRenditionsQueried)
        }
        _ => {
            return Err(contract::AuthorityError::AuthorityIntegrity(
                "localized consequence received a legacy operation".to_owned(),
            ));
        }
    };
    localized_application_result(operation, result)
}

fn proof_assigned_edit_id(
    presentation_id: &str,
    edit_index: usize,
) -> Result<proof_application::EditId, LocalPortError> {
    let entropy = canonicalize(&json!({
        "api_version": "proof.dev/proof-assigned-edit-id/v1",
        "edit_index": edit_index,
        "presentation_id": presentation_id,
    }))
    .map_err(|error| LocalPortError::Integrity(error.to_string()))?;
    let entropy_digest = digest(ArtifactKind::OperationEffectV1, &entropy).to_string();
    let entropy_hex = entropy_digest.strip_prefix("blake3:").ok_or_else(|| {
        LocalPortError::Integrity("Edit identity entropy digest is malformed".to_owned())
    })?;
    if presentation_id.len() != 36 || entropy_hex.len() < 18 {
        return Err(LocalPortError::Integrity(
            "Edit identity source is malformed".to_owned(),
        ));
    }
    let candidate = format!(
        "{}-{}-7{}-8{}-{}",
        &presentation_id[..8],
        &presentation_id[9..13],
        &entropy_hex[..3],
        &entropy_hex[3..6],
        &entropy_hex[6..18],
    );
    candidate
        .parse::<proof_application::EditId>()
        .map_err(|error| LocalPortError::Integrity(error.to_string()))
}

#[expect(
    clippy::too_many_lines,
    reason = "the three-operation closed union keeps success and committed-Allow failure mappings explicit"
)]
fn execute_authorized_consequence(
    repository: &LocalWorkspace,
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    presentation: &VerifiedPresentation,
    assessment: &AuthorizationAssessment,
    decision_record_digest: proof_application::ContentDigest,
    evaluated_at: Timestamp,
) -> Result<contract::AuthenticatedOperationResultV1, contract::AuthorityError> {
    match &presentation.operation_input {
        contract::EnabledOperationInputV1::WorkspaceStatus(_) => {
            verify_commit_operation_scope(transaction, workspace_id)
                .map_err(authority_from_local_port)?;
            let storage_schema_version = transaction
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
            let (authoritative_sequence, state_digest) =
                reproducible_known_state(transaction, workspace_id)
                    .map_err(contract::AuthorityError::AuthorityIntegrity)?;
            Ok(contract::AuthenticatedOperationResultV1::WorkspaceStatus(
                contract::AuthenticatedWorkspaceStatusV1 {
                    workspace_id,
                    requesting_principal_id: presentation.command.requesting_principal_id,
                    operating_principal_id: presentation.command.operating_principal_id,
                    delegation_id: presentation.command.delegation_id,
                    storage_schema_version,
                    authoritative_sequence,
                    state_digest,
                    authorization_decision_digest: decision_record_digest,
                },
            ))
        }
        contract::EnabledOperationInputV1::ObjectQueryReleased(input) => {
            let source = match load_released_source(
                transaction,
                workspace_id,
                &input.environment_id,
            ) {
                Ok(source) => source,
                Err(LocalPortError::NotFound) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
                    ));
                }
                Err(LocalPortError::UnsupportedVersion) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion,
                    ));
                }
                Err(error) => return Err(authority_from_local_port(error)),
            };
            if evaluated_at < source.released_at {
                return Ok(contract::AuthenticatedOperationResultV1::Failure(
                    contract::AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
                ));
            }
            let objects = match load_exact_released_objects(
                transaction,
                &source.edition,
                input.object_ids.as_slice(),
            ) {
                Ok(objects) => objects,
                Err(LocalPortError::NotFound) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
                    ));
                }
                Err(LocalPortError::UnsupportedVersion) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion,
                    ));
                }
                Err(error) => return Err(authority_from_local_port(error)),
            };
            Ok(
                contract::AuthenticatedOperationResultV1::ReleasedObjectQuery(
                    ReleasedObjectQuery {
                        workspace_id,
                        environment_id: input.environment_id.clone(),
                        release_id: source.release_id,
                        edition_id: source.edition.edition_id,
                        principal_id: presentation.command.operating_principal_id,
                        delegation_id: Some(presentation.command.delegation_id),
                        authorization_decision_digest: decision_record_digest,
                        objects,
                    },
                ),
            )
        }
        contract::EnabledOperationInputV1::ContextBuild(input) => {
            let delegation = assessment
                .resolved_delegation
                .as_ref()
                .ok_or(contract::AuthorityError::DelegationUnavailable)?;
            let context_pack_id = presentation
                .command
                .presentation_id
                .to_string()
                .parse::<ContextPackId>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
            let command = BuildContextPackCommand {
                context_pack_id,
                operating_principal_id: presentation.command.operating_principal_id,
                delegation_id: presentation.command.delegation_id,
                task_id: input.task_id.as_str().to_owned(),
                intent: input.intent.clone(),
                environment_id: input.environment_id.clone(),
                object_ids: input.object_ids.as_slice().to_vec(),
                limits: ContextPackLimits {
                    max_objects: input.max_objects.get(),
                    max_bytes: u64::from(input.max_bytes.get()),
                },
                idempotency_key: input.idempotency_key,
                built_at: evaluated_at,
                expires_at: input.expires_at,
            };
            let context_pack = match build_context_pack_authorized_transaction(
                transaction,
                workspace_id,
                presentation.command.requesting_principal_id,
                &command,
                ContextPackLimits {
                    max_objects: assessment.effective_constraints.max_objects.get(),
                    max_bytes: u64::from(assessment.effective_constraints.max_context_bytes.get()),
                },
                delegated_capability_versions_v2(delegation),
                decision_record_digest,
            ) {
                Ok(context_pack) => context_pack,
                Err(LocalPortError::NotFound) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ContextBuildNotFound,
                    ));
                }
                Err(LocalPortError::LimitExceeded) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ContextBuildLimitExceeded,
                    ));
                }
                Err(LocalPortError::Expired) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ContextBuildExpired,
                    ));
                }
                Err(
                    LocalPortError::Denied
                    | LocalPortError::PolicyDenied
                    | LocalPortError::StateConflict,
                ) => {
                    return Ok(contract::AuthenticatedOperationResultV1::Failure(
                        contract::AuthenticatedOperationFailureV1::ContextBuildDenied,
                    ));
                }
                Err(error) => return Err(authority_from_local_port(error)),
            };
            persist_context_result(transaction, presentation, &context_pack)?;
            Ok(contract::AuthenticatedOperationResultV1::ContextPack(
                context_pack,
            ))
        }
        contract::EnabledOperationInputV1::LocalizedContextBuild(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetCreate(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetAdd(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetGet(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetDiff(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetValidate(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetSubmit(_)
        | contract::EnabledOperationInputV1::LocalizedChangeSetCommit(_)
        | contract::EnabledOperationInputV1::LocalizedEditionCreate(_)
        | contract::EnabledOperationInputV1::LocalizedReleaseCreate(_)
        | contract::EnabledOperationInputV1::LocalizedObjectQueryReleased(_) => {
            execute_localized_consequence(
                repository,
                transaction,
                workspace_id,
                presentation,
                assessment,
            )
        }
    }
}

type BindingLookupRow = (String, bool, String);

struct PresentationBindingVerification {
    binding_found: bool,
    binding_record_digest: String,
    binding_active: bool,
    binding: contract::PrincipalBindingV1,
    signature_valid: bool,
}

fn verify_presentation_binding_candidate(
    binding_row: Option<BindingLookupRow>,
    parsed: &proof_attestation::authority::ParsedAuthorityEnvelope<
        contract::AuthenticatedCommandV1,
    >,
) -> Result<PresentationBindingVerification, contract::AuthorityError> {
    let (binding_found, binding_record_digest, binding_active, binding_json) = binding_row
        .map_or_else(
            || {
                (
                    false,
                    UNKNOWN_BINDING_DUMMY_RECORD_DIGEST.to_owned(),
                    false,
                    UNKNOWN_BINDING_DUMMY_RECORD_JSON.to_owned(),
                )
            },
            |(record_digest, active, record_json)| (true, record_digest, active, record_json),
        );
    let binding: contract::PrincipalBindingV1 =
        decode_canonical(&binding_json, "Principal binding")?;
    let signature_valid = verify_authority_envelope::<contract::AuthenticatedCommandV1>(
        parsed.envelope_json.as_bytes(),
        AuthorityPayloadProfile::AuthenticatedCommand,
        &[binding.authenticated_subject.as_subject().subject()],
    )
    .is_ok();
    Ok(PresentationBindingVerification {
        binding_found,
        binding_record_digest,
        binding_active,
        binding,
        signature_valid,
    })
}

#[expect(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the authentication phase keeps signature proof, actor derivation, time, replay, and private commitment opening in one no-write sequence"
)]
fn verify_authenticated_presentation(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    bootstrap_principal_id: PrincipalId,
    local_identity: &LocalIdentity,
    command_input: &contract::CommandInputV1,
    parsed: &proof_attestation::authority::ParsedAuthorityEnvelope<
        contract::AuthenticatedCommandV1,
    >,
    command_digest: proof_application::ContentDigest,
    evaluated_at: Timestamp,
    authenticated_at: Timestamp,
) -> Result<VerifiedPresentation, contract::AuthorityError> {
    let command = &parsed.payload;
    let binding_row: Option<BindingLookupRow> = transaction
        .query_row(
            "SELECT binding.record_digest, binding.active, records.record_json
             FROM principal_bindings_v1 binding
             JOIN authority_records records
               ON records.authority_sequence = binding.authority_sequence
             WHERE binding.workspace_id = ?1 AND binding.binding_id = ?2",
            (workspace_id.to_string(), command.binding_id.to_string()),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    let verified_binding = verify_presentation_binding_candidate(binding_row, parsed)?;
    if !verified_binding.binding_found {
        return Err(contract::AuthorityError::AuthBindingNotFound);
    }
    if !verified_binding.signature_valid {
        return Err(contract::AuthorityError::AuthSignatureInvalid);
    }
    let PresentationBindingVerification {
        binding_record_digest,
        binding_active,
        binding,
        ..
    } = verified_binding;

    if command.audience != contract::AuthorityAudience::for_workspace(workspace_id)
        || command.workspace_id != workspace_id
        || command_input.workspace_id != workspace_id
    {
        return Err(contract::AuthorityError::AuthAudienceMismatch);
    }
    if command.command_digest != command_digest {
        return Err(contract::AuthorityError::AuthActorMismatch);
    }
    let operation_input = command_input
        .normalized_operation_input()
        .map_err(|_| contract::AuthorityError::AuthMalformed)?;
    let checked_input = command_input
        .validate_authenticated_command(command, bootstrap_principal_id, binding.principal_id)
        .map_err(|_| contract::AuthorityError::AuthActorMismatch)?;
    if checked_input != operation_input {
        return Err(contract::AuthorityError::AuthActorMismatch);
    }
    if binding.workspace_id != workspace_id
        || binding.principal_id != command.operating_principal_id
        || command.requesting_principal_id != bootstrap_principal_id
    {
        return Err(contract::AuthorityError::AuthActorMismatch);
    }

    let issued_at = command.issued_at.unix_timestamp_nanos();
    let expires_at = command.expires_at.unix_timestamp_nanos();
    let evaluated = evaluated_at.unix_timestamp_nanos();
    let lifetime = expires_at - issued_at;
    if lifetime <= 0
        || lifetime > i128::from(contract::MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000
    {
        return Err(contract::AuthorityError::AuthMalformed);
    }
    if issued_at - evaluated > i128::from(contract::MAX_COMMAND_FUTURE_SKEW_SECONDS) * 1_000_000_000
    {
        return Err(contract::AuthorityError::AuthNotYetValid);
    }
    if evaluated >= expires_at {
        return Err(contract::AuthorityError::AuthExpired);
    }
    let consumed = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM presentation_consumptions_v1
                 WHERE workspace_id = ?1 AND presentation_id = ?2
             )",
            (
                workspace_id.to_string(),
                command.presentation_id.to_string(),
            ),
            |row| row.get::<_, bool>(0),
        )
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?;
    if consumed {
        return Err(contract::AuthorityError::AuthReplay);
    }

    let opening = verify_subject_commitment_opening(
        transaction,
        workspace_id,
        bootstrap_principal_id,
        local_identity,
    )?;
    let actor_context = contract::AuthenticatedActorContextV1 {
        api_version: contract::ActorContextApiVersion::V1,
        audience: contract::AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        authentication_profile: contract::AuthenticationProfileV1::HumanAgent,
        requesting_subject: opening.input.authenticated_subject,
        requesting_subject_commitment: opening.commitment,
        operating_subject: binding.authenticated_subject.clone(),
        binding_id: binding.binding_id,
        requesting_principal_id: bootstrap_principal_id,
        operating_principal_id: binding.principal_id,
        delegation_id: command.delegation_id,
        operation: command.operation,
        command_digest,
        command_envelope_digest: parsed.envelope_digest,
        presentation_id: command.presentation_id,
        authenticated_at,
    };
    let actor_context_evidence =
        contract::AuthenticatedActorContextEvidenceV1::from(&actor_context);
    let evidence_json = canonical_json(&actor_context_evidence, "actor context evidence")?;
    if evidence_json.contains(local_identity.subject.as_str())
        || evidence_json.contains(opening.blind.as_str())
    {
        return Err(contract::AuthorityError::AuthorityIntegrity(
            "persistable actor evidence contains a private commitment opening".to_owned(),
        ));
    }
    let evidence_value = parse_strict(evidence_json.as_bytes())
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let evidence_canonical = canonicalize(&evidence_value)
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let actor_context_digest = digest(
        ArtifactKind::AuthenticatedActorContextV1,
        &evidence_canonical,
    );
    let binding_record_digest = binding_record_digest
        .parse::<proof_application::ContentDigest>()
        .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))?;
    let binding_revocation_record_digest = transaction
        .query_row(
            "SELECT record_digest FROM principal_binding_revocations_v1
             WHERE workspace_id = ?1 AND binding_id = ?2",
            (workspace_id.to_string(), binding.binding_id.to_string()),
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|error| contract::AuthorityError::Storage(error.to_string()))?
        .map(|value| {
            value
                .parse::<proof_application::ContentDigest>()
                .map_err(|error| contract::AuthorityError::AuthorityIntegrity(error.to_string()))
        })
        .transpose()?;
    Ok(VerifiedPresentation {
        operation_input,
        command: command.clone(),
        command_digest,
        command_envelope_digest: parsed.envelope_digest,
        binding,
        binding_record_digest,
        binding_active,
        binding_revocation_record_digest,
        actor_context,
        actor_context_evidence,
        actor_context_digest,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use base64::Engine as _;
    use rusqlite::Connection;

    use proof_application::{
        ArtifactKind, ContentResourceIntent, ContentResourceIntentId, EditionArtifactReference,
        EditionId, EnvironmentId, KnownStateArtifactReference, LocaleId, LocalizedContentBaseline,
        LocalizedContentTarget, ObjectId, PrincipalId, ReleaseArtifactReference, ReleaseId,
        ReleasedLocaleTarget, SchemaId, Timestamp, WorkspaceId,
    };
    use proof_attestation::Ed25519SigningProvider;
    use proof_canonical::{canonicalize, digest};

    use super::{
        AuthenticatedLocalizedConsequenceRow, AuthorityPayloadProfile, BASE64,
        ExpectedApplicationLedgerRow, LocalIdentity, UNKNOWN_BINDING_DUMMY_RECORD_DIGEST,
        UNKNOWN_BINDING_DUMMY_RECORD_JSON, bootstrap_authority, contract,
        delegation_covers_projected_resources_v1, migrate_schema_v12, migrate_schema_v13,
        parse_authority_envelope, prior_application_key_sources,
        project_legacy_object_selection_v1, project_localized_intent_closure_v1,
        project_localized_released_selection_stage_one_v1, project_workspace_only_v1,
        projected_resources, register_expected_application_ledger_row,
        verify_presentation_binding_candidate,
    };

    const V11_PREREQUISITES: &str = r"
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    name TEXT NOT NULL UNIQUE
) STRICT;
INSERT INTO schema_migrations (version, name)
VALUES (11, 'localized-content-foundation');
CREATE TABLE principals (
    principal_id TEXT PRIMARY KEY,
    principal_type TEXT NOT NULL,
    identity_provider TEXT NOT NULL,
    identity_subject TEXT NOT NULL,
    enabled INTEGER NOT NULL
) STRICT;
CREATE TABLE workspace_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    workspace_id TEXT NOT NULL,
    bootstrap_principal_id TEXT NOT NULL REFERENCES principals(principal_id),
    schema_version INTEGER NOT NULL CHECK (schema_version > 0)
) STRICT;
INSERT INTO principals VALUES (
    '019c0000-0000-7000-8000-000000000002',
    'human',
    'os/unix',
    'uid:1000',
    1
);
INSERT INTO workspace_metadata VALUES (
    1,
    '019c0000-0000-7000-8000-000000000001',
    '019c0000-0000-7000-8000-000000000002',
    11
);
PRAGMA user_version = 11;
";

    fn v11_connection() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        connection.execute_batch(V11_PREREQUISITES).unwrap();
        connection
    }

    fn v12_connection() -> Connection {
        let mut connection = v11_connection();
        let transaction = connection.transaction().unwrap();
        migrate_schema_v12(&transaction).unwrap();
        transaction.commit().unwrap();
        connection
    }

    fn localized_consequence_row(
        sequence: i64,
        composite_suffix: char,
    ) -> AuthenticatedLocalizedConsequenceRow {
        AuthenticatedLocalizedConsequenceRow {
            decision_authority_sequence: sequence,
            presentation_id: format!("presentation-{sequence}"),
            workspace_id: "019c0000-0000-7000-8000-000000000001".to_owned(),
            requesting_principal_id: "019c0000-0000-7000-8000-000000000002".to_owned(),
            operating_principal_id: "019c0000-0000-7000-8000-000000000003".to_owned(),
            delegation_id: "019c0000-0000-7000-8000-000000000004".to_owned(),
            command_digest: format!("blake3:{}", "1".repeat(64)),
            authorization_decision_digest: format!("blake3:{}", "2".repeat(64)),
            operation_name: "changeset.submit".to_owned(),
            operation_version: "proof.dev/operation/changeset.submit/v2".to_owned(),
            application_idempotency_kind: "derived".to_owned(),
            application_idempotency_key: Some("derived-submit-key".to_owned()),
            result_kind: "success".to_owned(),
            result_contract: "submit-result".to_owned(),
            result_json: "{}".to_owned(),
            result_digest: format!("blake3:{}", "3".repeat(64)),
            application_effect_digest: format!("blake3:{}", "4".repeat(64)),
            application_consequence_digest: format!(
                "blake3:{}",
                composite_suffix.to_string().repeat(64)
            ),
            selectors_json: "{}".to_owned(),
            evidence_json: "{}".to_owned(),
            evidence_digest: format!("blake3:{}", "6".repeat(64)),
        }
    }

    #[test]
    fn mutable_current_closure_does_not_change_global_replay_identity() {
        let mut expected =
            std::collections::BTreeMap::<(String, String), ExpectedApplicationLedgerRow>::new();
        let first = localized_consequence_row(11, '5');
        let replay_after_approval = localized_consequence_row(12, '7');

        register_expected_application_ledger_row(
            &mut expected,
            &first,
            first.application_idempotency_key.as_deref().unwrap(),
        )
        .unwrap();
        register_expected_application_ledger_row(
            &mut expected,
            &replay_after_approval,
            replay_after_approval
                .application_idempotency_key
                .as_deref()
                .unwrap(),
        )
        .unwrap();

        let row = expected.values().next().unwrap();
        assert_eq!(row.first_decision_authority_sequence, 11);
        assert_eq!(
            row.application_consequence_digest,
            first.application_consequence_digest
        );
        assert_eq!(
            row.application_effect_digest,
            first.application_effect_digest
        );
    }

    #[test]
    fn global_replay_identity_rejects_raw_effect_substitution() {
        let mut expected =
            std::collections::BTreeMap::<(String, String), ExpectedApplicationLedgerRow>::new();
        let first = localized_consequence_row(11, '5');
        let mut substituted = localized_consequence_row(12, '7');
        substituted.application_effect_digest = format!("blake3:{}", "8".repeat(64));
        let key = first.application_idempotency_key.as_deref().unwrap();
        register_expected_application_ledger_row(&mut expected, &first, key).unwrap();

        assert!(
            register_expected_application_ledger_row(&mut expected, &substituted, key).is_err()
        );
    }

    #[test]
    fn application_key_inventory_discovers_future_key_bearing_tables() {
        let connection = v11_connection();
        connection
            .execute_batch(
                "CREATE TABLE future_workspace_operation (
                     workspace_id TEXT NOT NULL,
                     idempotency_key TEXT NOT NULL,
                     PRIMARY KEY (workspace_id, idempotency_key)
                 ) STRICT;
                 CREATE TABLE future_single_workspace_operation (
                     idempotency_key TEXT PRIMARY KEY
                 ) STRICT;
                 INSERT INTO future_workspace_operation VALUES (
                     '019c0000-0000-7000-8000-000000000001',
                     '019c0000-0000-7000-8000-000000000099'
                 );
                 INSERT INTO future_single_workspace_operation VALUES (
                     '019c0000-0000-7000-8000-000000000099'
                 );",
            )
            .unwrap();
        let sources = prior_application_key_sources(
            &connection,
            "019c0000-0000-7000-8000-000000000001".parse().unwrap(),
            "019c0000-0000-7000-8000-000000000099",
        )
        .unwrap();
        assert_eq!(
            sources,
            [
                "future_single_workspace_operation".to_owned(),
                "future_workspace_operation".to_owned(),
            ]
        );
    }

    #[test]
    fn migration_creates_the_strict_v12_authority_schema() {
        let mut connection = v11_connection();
        let transaction = connection.transaction().unwrap();
        migrate_schema_v12(&transaction).unwrap();
        transaction.commit().unwrap();

        let versions = (
            connection
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
        );
        assert_eq!(versions, (12, 12, 12));

        let expected = BTreeSet::from([
            "authenticated_actor_context_evidence_v1",
            "authenticated_operation_results_v1",
            "authenticated_subject_commitment_openings_v1",
            "authority_records",
            "authorization_decisions_v2",
            "binding_enrollment_challenges",
            "delegation_revocations_v2",
            "delegations_v2",
            "presentation_consumptions_v1",
            "principal_binding_revocations_v1",
            "principal_bindings_v1",
            "principal_status_v1",
            "workspace_authority_roots",
        ]);
        let mut statement = connection
            .prepare("SELECT name, strict FROM pragma_table_list WHERE schema = 'main'")
            .unwrap();
        let actual = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .unwrap()
            .filter_map(Result::ok)
            .filter(|(name, _)| expected.contains(name.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual.len(), expected.len());
        assert!(actual.iter().all(|(_, strict)| *strict == 1));
    }

    #[test]
    fn migration_failure_rolls_back_every_v12_table_and_version_marker() {
        let mut connection = v11_connection();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_v12_migration
                 BEFORE INSERT ON schema_migrations
                 WHEN NEW.version = 12
                 BEGIN
                     SELECT RAISE(ABORT, 'injected v12 migration failure');
                 END;",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        assert!(migrate_schema_v12(&transaction).is_err());
        transaction.rollback().unwrap();

        let versions = (
            connection
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
        );
        assert_eq!(versions, (11, 11, 11));
        let table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name = 'authority_records'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap();
        assert_eq!(table_count, 0);
    }

    #[test]
    fn migration_creates_strict_v13_consequence_and_global_key_tables() {
        let mut connection = v12_connection();
        let transaction = connection.transaction().unwrap();
        migrate_schema_v13(&transaction).unwrap();
        transaction.commit().unwrap();

        let versions = (
            connection
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
        );
        assert_eq!(versions, (13, 13, 13));

        for table in [
            "authenticated_application_idempotency_v1",
            "authenticated_localized_consequences_v1",
        ] {
            let strict = connection
                .query_row(
                    "SELECT strict FROM pragma_table_list WHERE schema = 'main' AND name = ?1",
                    [table],
                    |row| row.get::<_, bool>(0),
                )
                .unwrap();
            assert!(strict, "{table} must remain STRICT");
        }
        connection.execute("PRAGMA foreign_key_check", []).unwrap();
    }

    #[test]
    fn migration_failure_rolls_back_and_v13_retry_is_exact() {
        let mut connection = v12_connection();
        connection
            .execute_batch(
                "CREATE TRIGGER reject_v13_migration
                 BEFORE INSERT ON schema_migrations
                 WHEN NEW.version = 13
                 BEGIN
                     SELECT RAISE(ABORT, 'injected v13 migration failure');
                 END;",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        assert!(migrate_schema_v13(&transaction).is_err());
        transaction.rollback().unwrap();

        let table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type = 'table' AND name IN (
                     'authenticated_application_idempotency_v1',
                     'authenticated_localized_consequences_v1'
                 )",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap();
        assert_eq!(table_count, 0);
        let versions = (
            connection
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
        );
        assert_eq!(versions, (12, 12, 12));

        connection
            .execute("DROP TRIGGER reject_v13_migration", [])
            .unwrap();
        let transaction = connection.transaction().unwrap();
        migrate_schema_v13(&transaction).unwrap();
        transaction.commit().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM schema_migrations WHERE version = 13",
                    [],
                    |row| { row.get::<_, u32>(0) }
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn unknown_binding_and_known_invalid_signature_share_decode_and_crypto_helper() {
        let envelope = include_str!(
            "../../../conformance/v1/authority/vectors/authenticated-command.envelope.valid.json"
        );
        let mut value = serde_json::from_str::<serde_json::Value>(envelope).unwrap();
        let mut signature = BASE64
            .decode(value["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        signature[0] ^= 1;
        value["signatures"][0]["sig"] = serde_json::json!(BASE64.encode(signature));
        let invalid_envelope = canonicalize(&value).unwrap();
        let parsed = parse_authority_envelope::<contract::AuthenticatedCommandV1>(
            invalid_envelope.as_bytes(),
            AuthorityPayloadProfile::AuthenticatedCommand,
        )
        .unwrap();

        let unknown = verify_presentation_binding_candidate(None, &parsed).unwrap();
        let known_invalid = verify_presentation_binding_candidate(
            Some((
                UNKNOWN_BINDING_DUMMY_RECORD_DIGEST.to_owned(),
                true,
                UNKNOWN_BINDING_DUMMY_RECORD_JSON.to_owned(),
            )),
            &parsed,
        )
        .unwrap();

        assert!(!unknown.binding_found);
        assert!(known_invalid.binding_found);
        assert!(!unknown.signature_valid);
        assert!(!known_invalid.signature_valid);
        assert_eq!(unknown.binding, known_invalid.binding);
        assert_eq!(
            unknown.binding_record_digest,
            known_invalid.binding_record_digest
        );
    }

    #[test]
    fn bootstrap_creates_one_separate_root_and_signed_human_status() {
        let mut connection = v11_connection();
        let signer = Ed25519SigningProvider::from_secret_bytes(&[41_u8; 32]);
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let principal_id = "019c0000-0000-7000-8000-000000000002"
            .parse::<PrincipalId>()
            .unwrap();
        let created_at = "2026-08-20T20:00:00Z".parse::<Timestamp>().unwrap();
        let local_identity = LocalIdentity {
            provider: "os/unix",
            subject: "uid:1000".to_owned(),
        };
        let transaction = connection.transaction().unwrap();
        migrate_schema_v12(&transaction).unwrap();
        bootstrap_authority(
            &transaction,
            workspace_id,
            principal_id,
            created_at,
            &signer,
            &local_identity,
            [0x24; 32],
        )
        .unwrap();
        bootstrap_authority(
            &transaction,
            workspace_id,
            principal_id,
            created_at,
            &signer,
            &local_identity,
            [0x24; 32],
        )
        .unwrap();
        transaction.commit().unwrap();

        for table in [
            "workspace_authority_roots",
            "authority_records",
            "principal_status_v1",
            "authenticated_subject_commitment_openings_v1",
        ] {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap();
            assert_eq!(count, 1, "{table} bootstrap was not idempotent");
        }
        let (kind, root_path, root_json, record_json): (String, String, String, String) =
            connection
                .query_row(
                    "SELECT r.record_kind, w.key_file_relative_path, w.root_json, r.record_json
                 FROM authority_records r CROSS JOIN workspace_authority_roots w
                 WHERE r.authority_sequence = 1 AND w.active = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
        assert_eq!(kind, "principal_status");
        assert_eq!(root_path, ".proof/state/authority-signing.ed25519");
        assert!(!root_json.contains("uid:"));
        assert!(!record_json.contains("uid:"));
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one registry-freeze test exercises all four projection profiles and every populated resource axis"
    )]
    fn all_four_resource_projection_profiles_enforce_their_exact_runtime_axes() {
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let environment_id = EnvironmentId::new("production").unwrap();
        let object_a = "019c0000-0000-7000-8000-000000000010"
            .parse::<ObjectId>()
            .unwrap();
        let object_b = "019c0000-0000-7000-8000-000000000011"
            .parse::<ObjectId>()
            .unwrap();
        let schema_a = SchemaId::new("campaign").unwrap();
        let schema_b = SchemaId::new("legal").unwrap();
        let locale_a = "en-US".parse::<LocaleId>().unwrap();
        let locale_b = "fr-FR".parse::<LocaleId>().unwrap();

        let workspace_only = project_workspace_only_v1(workspace_id).unwrap();
        assert_eq!(workspace_only.workspace_ids.as_slice(), [workspace_id]);
        assert!(workspace_only.environment_ids.as_slice().is_empty());
        assert!(workspace_only.object_ids.as_slice().is_empty());
        assert!(workspace_only.schema_ids.as_slice().is_empty());
        assert!(workspace_only.locales.as_slice().is_empty());

        let legacy = project_legacy_object_selection_v1(
            workspace_id,
            environment_id.clone(),
            &[object_a, object_b],
        )
        .unwrap();
        assert_eq!(legacy.workspace_ids.as_slice(), [workspace_id]);
        assert_eq!(
            legacy.environment_ids.as_slice(),
            std::slice::from_ref(&environment_id)
        );
        assert_eq!(legacy.object_ids.as_slice(), [object_a, object_b]);
        assert!(legacy.schema_ids.as_slice().is_empty());
        assert!(legacy.locales.as_slice().is_empty());

        let marker = canonicalize(&serde_json::json!({"marker": "projection"})).unwrap();
        let marker_digest = digest(ArtifactKind::KnownStateV2, &marker);
        let principal_id = "019c0000-0000-7000-8000-000000000002"
            .parse::<PrincipalId>()
            .unwrap();
        let intent_id = "019c0000-0000-7000-8000-000000000020"
            .parse::<ContentResourceIntentId>()
            .unwrap();
        let issued_at = "2026-08-20T20:00:00Z".parse::<Timestamp>().unwrap();
        let base = LocalizedContentBaseline {
            release: ReleaseArtifactReference {
                api_version: "proof.dev/release/v2".to_owned(),
                release_id: "019c0000-0000-7000-8000-000000000021"
                    .parse::<ReleaseId>()
                    .unwrap(),
                digest: marker_digest,
            },
            edition: EditionArtifactReference {
                api_version: "proof.dev/edition/v2".to_owned(),
                edition_id: "019c0000-0000-7000-8000-000000000022"
                    .parse::<EditionId>()
                    .unwrap(),
                digest: marker_digest,
            },
            known_state: KnownStateArtifactReference {
                api_version: "proof.dev/known-state/v2".to_owned(),
                authoritative_sequence: 7,
                digest: marker_digest,
            },
        };
        let targets = vec![
            LocalizedContentTarget {
                object_id: object_a,
                schema_id: schema_a.clone(),
                locale: locale_a.clone(),
            },
            LocalizedContentTarget {
                object_id: object_b,
                schema_id: schema_b.clone(),
                locale: locale_b.clone(),
            },
        ];
        let manifest = canonicalize(&serde_json::json!({
            "api_version": proof_application::CONTENT_RESOURCE_INTENT_API_VERSION,
            "base": {
                "edition": {
                    "api_version": base.edition.api_version,
                    "digest": base.edition.digest.to_string(),
                    "edition_id": base.edition.edition_id.to_string(),
                },
                "known_state": {
                    "api_version": base.known_state.api_version,
                    "authoritative_sequence": base.known_state.authoritative_sequence,
                    "digest": base.known_state.digest.to_string(),
                },
                "release": {
                    "api_version": base.release.api_version,
                    "digest": base.release.digest.to_string(),
                    "release_id": base.release.release_id.to_string(),
                },
            },
            "environment_id": environment_id.as_str(),
            "intent_id": intent_id.to_string(),
            "issued_at": issued_at.to_string(),
            "issued_by_principal_id": principal_id.to_string(),
            "targets": [
                {"locale": locale_a.as_str(), "object_id": object_a.to_string(), "schema_id": schema_a.as_str()},
                {"locale": locale_b.as_str(), "object_id": object_b.to_string(), "schema_id": schema_b.as_str()},
            ],
            "workspace_id": workspace_id.to_string(),
        }))
        .unwrap();
        let mut intent = ContentResourceIntent {
            intent_id,
            workspace_id,
            issued_by_principal_id: principal_id,
            issued_at,
            environment_id: environment_id.clone(),
            base,
            targets,
            canonical_json: manifest.as_str().to_owned(),
            intent_digest: digest(ArtifactKind::ContentResourceIntentV1, &manifest),
        };
        let complete = project_localized_intent_closure_v1(workspace_id, &intent).unwrap();
        assert_eq!(complete.workspace_ids.as_slice(), [workspace_id]);
        assert_eq!(
            complete.environment_ids.as_slice(),
            std::slice::from_ref(&environment_id)
        );
        assert_eq!(complete.object_ids.as_slice(), [object_a, object_b]);
        assert_eq!(
            complete.schema_ids.as_slice(),
            [schema_a.clone(), schema_b.clone()]
        );
        assert_eq!(
            complete.locales.as_slice(),
            [locale_a.clone(), locale_b.clone()]
        );
        intent.base.known_state.authoritative_sequence += 1;
        assert!(project_localized_intent_closure_v1(workspace_id, &intent).is_err());

        let released_targets = vec![
            ReleasedLocaleTarget {
                object_id: object_a,
                locale: locale_a.clone(),
            },
            ReleasedLocaleTarget {
                object_id: object_b,
                locale: locale_b.clone(),
            },
        ];
        let staged = project_localized_released_selection_stage_one_v1(
            workspace_id,
            environment_id.clone(),
            &released_targets,
        )
        .unwrap();
        assert_eq!(
            staged.requested_axes().workspace_ids.as_slice(),
            [workspace_id]
        );
        assert_eq!(
            staged.requested_axes().environment_ids.as_slice(),
            [environment_id]
        );
        assert_eq!(
            staged.requested_axes().object_ids.as_slice(),
            [object_a, object_b]
        );
        assert_eq!(
            staged.requested_axes().locales.as_slice(),
            [locale_a, locale_b]
        );
        assert!(staged.requested_axes().schema_ids.as_slice().is_empty());
        let resolved = staged
            .resolve_schemas([schema_a.clone(), schema_b.clone()])
            .unwrap();
        assert_eq!(resolved.schema_ids.as_slice(), [schema_a, schema_b]);
        assert!(
            project_localized_released_selection_stage_one_v1(
                workspace_id,
                EnvironmentId::new("production").unwrap(),
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn localized_projection_evaluator_denies_each_missing_axis_without_filtering() {
        let delegation: contract::DelegationV2 = serde_json::from_str(include_str!(
            "../../../conformance/v1/authority/vectors/delegation-v2.localized-scope.valid.json"
        ))
        .unwrap();
        let object_id = "019c0000-0000-7000-8000-000000000080"
            .parse::<ObjectId>()
            .unwrap();
        let requested = projected_resources(
            delegation.workspace_id,
            vec![EnvironmentId::new("preview").unwrap()],
            vec![object_id],
            vec![SchemaId::new("campaign").unwrap()],
            vec!["iw".parse::<LocaleId>().unwrap()],
        )
        .unwrap();
        let original = requested.clone();
        assert!(delegation_covers_projected_resources_v1(
            &delegation,
            &requested,
            false
        ));

        let mut missing_environment = delegation.clone();
        missing_environment.scope.environment_ids =
            contract::DelegationEnvironmentIdsV2::new(Vec::new()).unwrap();
        let mut missing_object = delegation.clone();
        missing_object.scope.object_ids = contract::DelegationObjectIdsV2::new(Vec::new()).unwrap();
        let mut missing_schema = delegation.clone();
        missing_schema.scope.schema_ids = contract::DelegationSchemaIdsV2::new(Vec::new()).unwrap();
        let mut missing_locale = delegation.clone();
        missing_locale.scope.locales = contract::DelegationLocalesV2::new(Vec::new()).unwrap();
        for narrowed in [
            missing_environment,
            missing_object,
            missing_schema.clone(),
            missing_locale,
        ] {
            assert!(!delegation_covers_projected_resources_v1(
                &narrowed, &requested, false
            ));
            assert_eq!(requested, original, "denial must not filter the projection");
        }

        let stage_one = projected_resources(
            delegation.workspace_id,
            vec![EnvironmentId::new("preview").unwrap()],
            vec![object_id],
            Vec::new(),
            vec!["sl-rozaj".parse::<LocaleId>().unwrap()],
        )
        .unwrap();
        assert!(delegation_covers_projected_resources_v1(
            &delegation,
            &stage_one,
            true
        ));
        assert!(!delegation_covers_projected_resources_v1(
            &missing_schema,
            &stage_one,
            true
        ));
        assert!("sl-ROZAJ".parse::<LocaleId>().is_err());

        let normalized_alias = projected_resources(
            delegation.workspace_id,
            vec![EnvironmentId::new("preview").unwrap()],
            vec![object_id],
            vec![SchemaId::new("campaign").unwrap()],
            vec!["he".parse::<LocaleId>().unwrap()],
        )
        .unwrap();
        assert!(!delegation_covers_projected_resources_v1(
            &delegation,
            &normalized_alias,
            false
        ));

        let other_workspace = projected_resources(
            "019c0000-0000-7000-8000-000000000099"
                .parse::<WorkspaceId>()
                .unwrap(),
            vec![EnvironmentId::new("preview").unwrap()],
            vec![object_id],
            vec![SchemaId::new("campaign").unwrap()],
            vec!["iw".parse::<LocaleId>().unwrap()],
        )
        .unwrap();
        assert!(!delegation_covers_projected_resources_v1(
            &delegation,
            &other_workspace,
            false
        ));
    }
}
