use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    AuthorityRootTransitionId, InitializeWorkspaceCommand, PrincipalId, Timestamp, WorkspaceId,
    authority::{
        AuthorityAdministrator, AuthorityError, AuthorityHeadV1, AuthorityRepository,
        AuthoritySequence, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
        WorkspaceAuthorityRootTransitionApiVersion, WorkspaceAuthorityRootTransitionV1,
    },
    initialize_workspace,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, params};

const WORKSPACE_ID: &str = "019d1000-0000-7000-8000-000000000001";
const HUMAN_PRINCIPAL_ID: &str = "019d1000-0000-7000-8000-000000000002";
const TRANSITION_ID: &str = "019d1000-0000-7000-8000-000000000003";
const BASE_TIME: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 1_004;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x44; 32];
const ATTACKER_SUCCESSOR_SECRET: [u8; 32] = [0xa7; 32];
const PREDECESSOR_KEY_RELATIVE_PATH: &str = ".proof/state/authority-signing.ed25519";
const SUCCESSOR_STAGING_KEY_RELATIVE_PATH: &str = ".proof/state/authority-successor.ed25519";

#[test]
fn predecessor_key_loss_aborts_transition_without_history_change() {
    let fixture = ContinuityFixture::new();
    let signed = fixture.stage_attacker_transition();
    let fingerprint_before = logical_database_fingerprint(&fixture.repository);
    let predecessor_path = fixture
        .repository
        .root()
        .join(PREDECESSOR_KEY_RELATIVE_PATH);

    // The target is an isolated disposable test Workspace.
    fs::remove_file(&predecessor_path).unwrap();

    assert_eq!(
        fixture
            .repository
            .transition_workspace_authority_root(signed.transition, signed.envelope_json)
            .unwrap_err(),
        AuthorityError::AuthorityRootUnavailable
    );
    assert_eq!(
        logical_database_fingerprint(&fixture.repository),
        fingerprint_before
    );
    assert!(signed.staging_path.exists());
    assert!(!signed.published_path.exists());
}

#[test]
fn compromised_predecessor_can_authorize_attacker_successor_but_not_match_the_pin() {
    let fixture = ContinuityFixture::new();
    let pinned_pre_transition_head = fixture.verified_head();
    let signed = fixture.stage_attacker_transition();
    assert_eq!(
        signed.transition.previous_authority_record_digest,
        pinned_pre_transition_head.record_digest
    );

    // Possession of the predecessor secret is sufficient for ordinary rotation:
    // dual signing is continuity, not recovery from predecessor compromise.
    let activated_root = fixture
        .repository
        .transition_workspace_authority_root(signed.transition.clone(), signed.envelope_json)
        .unwrap();
    let verified_post_transition_head = fixture.verified_head();

    assert_eq!(
        activated_root.authority_key_id,
        signed.transition.successor_authority_key_id
    );
    assert_eq!(
        activated_root.predecessor_authority_key_id,
        Some(signed.transition.predecessor_authority_key_id)
    );
    assert!(signed.published_path.exists());
    assert!(!signed.staging_path.exists());
    assert_eq!(
        verified_post_transition_head.sequence.get(),
        pinned_pre_transition_head.sequence.get() + 1
    );
    assert_ne!(verified_post_transition_head, pinned_pre_transition_head);
    assert!(
        !verified_head_matches_pin(
            &fixture.repository,
            fixture.workspace_id,
            pinned_pre_transition_head,
        )
        .unwrap()
    );
}

#[test]
fn signed_record_mutation_fails_verified_head_before_pin_comparison() {
    let fixture = ContinuityFixture::new();
    let pinned_head = fixture.verified_head();
    let connection = fixture.repository.open_database().unwrap();
    let original: String = connection
        .query_row(
            "SELECT record_json FROM authority_records WHERE authority_sequence = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mutated = original.replace("\"enabled\":true", "\"enabled\":false");
    assert_ne!(mutated, original);
    connection
        .execute(
            "UPDATE authority_records SET record_json = ?1 WHERE authority_sequence = 1",
            [mutated],
        )
        .unwrap();
    drop(connection);

    assert!(matches!(
        verified_head_matches_pin(&fixture.repository, fixture.workspace_id, pinned_head),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
}

#[test]
fn signed_record_reordering_fails_verified_head_before_pin_comparison() {
    let fixture = ContinuityFixture::new();
    let signed = fixture.stage_attacker_transition();
    fixture
        .repository
        .transition_workspace_authority_root(signed.transition, signed.envelope_json)
        .unwrap();
    let pinned_head = fixture.verified_head();
    let mut connection = fixture.repository.open_database().unwrap();

    swap_signed_record_positions(&mut connection);
    drop(connection);

    assert!(matches!(
        verified_head_matches_pin(&fixture.repository, fixture.workspace_id, pinned_head),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
}

#[test]
fn valid_older_signed_snapshot_is_internal_validity_not_freshness() {
    let fixture = ContinuityFixture::new();
    let pre_transition_head = fixture.verified_head();
    checkpoint_database(&fixture.repository);

    let older_directory = TestDirectory::new("older-snapshot");
    copy_directory_contents(fixture.repository.root(), older_directory.path());
    let older_snapshot = LocalWorkspace::with_deterministic_authority_adapter(
        older_directory.path(),
        deterministic_adapter(),
    )
    .unwrap();

    let signed = fixture.stage_attacker_transition();
    fixture
        .repository
        .transition_workspace_authority_root(signed.transition, signed.envelope_json)
        .unwrap();
    let independently_pinned_later_head = fixture.verified_head();

    // Every record and signature in the copied prefix is valid; only an
    // independent later pin distinguishes it from the current history.
    let internally_verified_older_head = older_snapshot
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    assert_eq!(internally_verified_older_head, pre_transition_head);
    assert_ne!(
        internally_verified_older_head,
        independently_pinned_later_head
    );
    assert!(
        !verified_head_matches_pin(
            &older_snapshot,
            fixture.workspace_id,
            independently_pinned_later_head,
        )
        .unwrap()
    );
}

struct ContinuityFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    activated_at: Timestamp,
}

impl ContinuityFixture {
    fn new() -> Self {
        let directory = TestDirectory::new("fixture");
        let repository = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            deterministic_adapter(),
        )
        .unwrap();
        let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
        let human_principal_id = HUMAN_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();

        Self {
            _directory: directory,
            repository,
            workspace_id,
            human_principal_id,
            activated_at: BASE_TIME.parse().unwrap(),
        }
    }

    fn verified_head(&self) -> AuthorityHeadV1 {
        self.repository
            .authority_head(self.workspace_id)
            .unwrap()
            .unwrap()
    }

    fn stage_attacker_transition(&self) -> SignedTransition {
        let root = self
            .repository
            .workspace_authority_root(self.workspace_id)
            .unwrap();
        let head = self.verified_head();
        let predecessor =
            signer_from_file(&self.repository.root().join(PREDECESSOR_KEY_RELATIVE_PATH));
        assert_eq!(
            predecessor.metadata().unwrap().key_id,
            root.authority_key_id.as_str()
        );

        let successor = Ed25519SigningProvider::from_secret_bytes(&ATTACKER_SUCCESSOR_SECRET);
        let successor_metadata = successor.metadata().unwrap();
        let successor_key_id = Ed25519KeyId::new(successor_metadata.key_id).unwrap();
        let transition = WorkspaceAuthorityRootTransitionV1 {
            api_version: WorkspaceAuthorityRootTransitionApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: head.record_digest,
            workspace_id: self.workspace_id,
            transition_id: TRANSITION_ID.parse::<AuthorityRootTransitionId>().unwrap(),
            predecessor_authority_key_id: root.authority_key_id,
            successor_authority_key_id: successor_key_id.clone(),
            successor_public_key: Ed25519PublicKey::new(
                BASE64.encode(successor_metadata.public_key),
            )
            .unwrap(),
            algorithm: Ed25519Algorithm::Ed25519,
            activated_by_principal_id: self.human_principal_id,
            activated_at: self.activated_at,
        };
        let signed = sign_authority_payload(
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            &transition,
            &[&predecessor, &successor],
        )
        .unwrap();
        let staging_path = self
            .repository
            .root()
            .join(SUCCESSOR_STAGING_KEY_RELATIVE_PATH);
        write_private_key(&staging_path, &successor.secret_bytes());
        let successor_hex = successor_key_id.as_str().strip_prefix("ed25519:").unwrap();
        let published_path = self.repository.root().join(format!(
            ".proof/state/authority-roots/{successor_hex}.ed25519"
        ));

        SignedTransition {
            transition,
            envelope_json: signed.envelope_json,
            staging_path,
            published_path,
        }
    }
}

struct SignedTransition {
    transition: WorkspaceAuthorityRootTransitionV1,
    envelope_json: String,
    staging_path: PathBuf,
    published_path: PathBuf,
}

fn deterministic_adapter() -> DeterministicLocalAuthorityAdapter {
    DeterministicLocalAuthorityAdapter::new(
        DETERMINISTIC_UID,
        BASE_TIME.parse().unwrap(),
        DETERMINISTIC_SUBJECT_BLIND,
    )
}

fn signer_from_file(path: &Path) -> Ed25519SigningProvider {
    let mut bytes = fs::read(path).unwrap();
    let mut secret: [u8; 32] = bytes.as_slice().try_into().unwrap();
    bytes.fill(0);
    let signer = Ed25519SigningProvider::from_secret_bytes(&secret);
    secret.fill(0);
    signer
}

fn write_private_key(path: &Path, secret: &[u8; 32]) {
    fs::write(path, secret).unwrap();
    set_private_file_permissions(path);
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) {}

fn verified_head_matches_pin(
    repository: &LocalWorkspace,
    workspace_id: WorkspaceId,
    pinned: AuthorityHeadV1,
) -> Result<bool, AuthorityError> {
    Ok(repository.authority_head(workspace_id)? == Some(pinned))
}

fn logical_database_fingerprint(repository: &LocalWorkspace) -> String {
    let connection = repository.open_database().unwrap();
    let schema_entries = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '')
             FROM sqlite_schema
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let table_names = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut hasher = blake3::Hasher::new();
    for (kind, name, table_name, sql) in schema_entries {
        fingerprint_atom(&mut hasher, b"schema-kind", kind.as_bytes());
        fingerprint_atom(&mut hasher, b"schema-name", name.as_bytes());
        fingerprint_atom(&mut hasher, b"schema-table", table_name.as_bytes());
        fingerprint_atom(&mut hasher, b"schema-sql", sql.as_bytes());
    }
    for table_name in table_names {
        fingerprint_table(&connection, &mut hasher, &table_name);
    }
    hasher.finalize().to_hex().to_string()
}

fn fingerprint_table(connection: &Connection, hasher: &mut blake3::Hasher, table_name: &str) {
    fingerprint_atom(hasher, b"table", table_name.as_bytes());
    let identifier = format!("\"{}\"", table_name.replace('"', "\"\""));
    let mut statement = connection
        .prepare(&format!("SELECT rowid, * FROM {identifier} ORDER BY rowid"))
        .unwrap();
    let column_count = statement.column_count();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        fingerprint_atom(hasher, b"row", table_name.as_bytes());
        for column in 0..column_count {
            match row.get_ref(column).unwrap() {
                ValueRef::Null => fingerprint_atom(hasher, b"null", &[]),
                ValueRef::Integer(value) => {
                    fingerprint_atom(hasher, b"integer", &value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    fingerprint_atom(hasher, b"real", &value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => fingerprint_atom(hasher, b"text", value),
                ValueRef::Blob(value) => fingerprint_atom(hasher, b"blob", value),
            }
        }
    }
}

fn fingerprint_atom(hasher: &mut blake3::Hasher, kind: &[u8], value: &[u8]) {
    let kind_length = u64::try_from(kind.len()).unwrap();
    let value_length = u64::try_from(value.len()).unwrap();
    hasher.update(&kind_length.to_le_bytes());
    hasher.update(kind);
    hasher.update(&value_length.to_le_bytes());
    hasher.update(value);
}

struct StoredSignedRecord {
    record_kind: String,
    record_json: String,
    record_digest: String,
    envelope_json: String,
    envelope_digest: String,
    authority_key_id: String,
    recorded_at: String,
}

fn swap_signed_record_positions(connection: &mut Connection) {
    let first = stored_signed_record(connection, 1);
    let second = stored_signed_record(connection, 2);
    let transaction = connection.transaction().unwrap();
    transaction
        .execute(
            "UPDATE authority_records
             SET record_digest = 'temporary-record-digest',
                 envelope_digest = 'temporary-envelope-digest'
             WHERE authority_sequence = 1",
            [],
        )
        .unwrap();
    replace_signed_record(&transaction, 2, &first);
    replace_signed_record(&transaction, 1, &second);
    transaction.commit().unwrap();
}

fn stored_signed_record(connection: &Connection, sequence: i64) -> StoredSignedRecord {
    connection
        .query_row(
            "SELECT record_kind, record_json, record_digest, envelope_json,
                    envelope_digest, authority_key_id, recorded_at
             FROM authority_records WHERE authority_sequence = ?1",
            [sequence],
            |row| {
                Ok(StoredSignedRecord {
                    record_kind: row.get(0)?,
                    record_json: row.get(1)?,
                    record_digest: row.get(2)?,
                    envelope_json: row.get(3)?,
                    envelope_digest: row.get(4)?,
                    authority_key_id: row.get(5)?,
                    recorded_at: row.get(6)?,
                })
            },
        )
        .unwrap()
}

fn replace_signed_record(
    transaction: &rusqlite::Transaction<'_>,
    sequence: i64,
    record: &StoredSignedRecord,
) {
    transaction
        .execute(
            "UPDATE authority_records
             SET record_kind = ?1, record_json = ?2, record_digest = ?3,
                 envelope_json = ?4, envelope_digest = ?5,
                 authority_key_id = ?6, recorded_at = ?7
             WHERE authority_sequence = ?8",
            params![
                record.record_kind,
                record.record_json,
                record.record_digest,
                record.envelope_json,
                record.envelope_digest,
                record.authority_key_id,
                record.recorded_at,
                sequence,
            ],
        )
        .unwrap();
}

fn checkpoint_database(repository: &LocalWorkspace) {
    repository
        .open_database()
        .unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
}

fn copy_directory_contents(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().unwrap();
        if file_type.is_dir() {
            fs::create_dir(&destination_path).unwrap();
            fs::set_permissions(&destination_path, entry.metadata().unwrap().permissions())
                .unwrap();
            copy_directory_contents(&source_path, &destination_path);
        } else {
            assert!(file_type.is_file(), "test snapshot rejects symbolic links");
            fs::copy(&source_path, &destination_path).unwrap();
        }
    }
}

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-local-p0004-continuity-{label}-{}-{sequence}",
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
