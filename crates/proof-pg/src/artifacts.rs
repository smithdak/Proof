//! Immutable artifact catalog and durability boundary (contract §"Immutable
//! artifact boundary").

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use postgres::Transaction;
use proof_domain::{ArtifactKind, ContentDigest};
use proof_remote::derive_key_digest;

use crate::PgError;

/// A canonical content-addressed artifact key `artifacts/{kind}/blake3/{digest}`
/// (contract §"Immutable artifact boundary").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactKeyV1 {
    /// Exact artifact kind.
    pub kind: ArtifactKind,
    /// Domain-separated BLAKE3-256 digest of the exact canonical bytes.
    pub blake3_digest: ContentDigest,
}

impl ArtifactKeyV1 {
    /// Formats the canonical private content-addressed key.
    #[must_use]
    pub fn to_path(&self) -> String {
        let encoded = self.blake3_digest.to_string();
        let hex = encoded.strip_prefix("blake3:").unwrap_or(encoded.as_str());
        format!("artifacts/{}/blake3/{hex}", self.kind.wire_name())
    }
}

/// Complete artifact identity: kind, canonical bytes, digest, media type,
/// Schema version, and byte length (contract §"Immutable artifact boundary").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactIdentity {
    /// Exact artifact kind.
    pub kind: ArtifactKind,
    /// Exact canonical bytes.
    pub canonical_bytes: Vec<u8>,
    /// Domain-separated digest of the exact canonical bytes.
    pub digest: ContentDigest,
    /// Exact media type.
    pub media_type: String,
    /// Optional Schema version.
    pub schema_version: Option<u32>,
    /// Exact byte length.
    pub length: u64,
}

/// The external storage port: private `put_if_absent` plus verified
/// read-after-write (contract §"Immutable artifact boundary").
pub trait StoragePort {
    /// Inserts bytes only when the key is absent; an existing key with
    /// different bytes is an integrity failure.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Artifact`] on storage failure or a length/digest
    /// mismatch at an existing key.
    fn put_if_absent(&self, key: &ArtifactKeyV1, bytes: &[u8]) -> Result<(), PgError>;

    /// Reads bytes back and verifies length and digest.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Artifact`] when the key is absent or read-back
    /// verification fails.
    fn read_after_write(&self, key: &ArtifactKeyV1) -> Result<Vec<u8>, PgError>;
}

/// Filesystem-backed reference [`StoragePort`] over an unreachable neutral
/// staging namespace (contract §"Immutable artifact boundary").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsStoragePort {
    /// Private staging root (authority-neutral namespace only).
    pub root: PathBuf,
}

impl FsStoragePort {
    /// Selects a private staging root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolves the staging file path for a key inside the private root.
    fn file_path(&self, key: &ArtifactKeyV1) -> PathBuf {
        self.root.join(key.to_path())
    }
}

impl StoragePort for FsStoragePort {
    fn put_if_absent(&self, key: &ArtifactKeyV1, bytes: &[u8]) -> Result<(), PgError> {
        let actual_digest = artifact_digest(key.kind, bytes);
        if actual_digest != key.blake3_digest {
            return Err(PgError::Artifact(format!(
                "staged bytes digest {actual_digest} does not reproduce key digest {}",
                key.blake3_digest
            )));
        }

        let path = self.file_path(key);
        let parent = path.parent().ok_or_else(|| {
            PgError::Artifact(format!(
                "artifact key path {} has no parent directory",
                path.display()
            ))
        })?;
        fs::create_dir_all(parent).map_err(|error| {
            PgError::Artifact(format!(
                "cannot create staging directory {}: {error}",
                parent.display()
            ))
        })?;

        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                file.write_all(bytes).map_err(|error| {
                    let _ = fs::remove_file(&path);
                    PgError::Artifact(format!(
                        "cannot write staged artifact {}: {error}",
                        path.display()
                    ))
                })?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&path).map_err(|error| {
                    PgError::Artifact(format!(
                        "cannot read existing staged artifact {}: {error}",
                        path.display()
                    ))
                })?;
                if existing == bytes {
                    // Exact bytes already staged: replay is a successful no-op.
                    Ok(())
                } else {
                    Err(PgError::Artifact(format!(
                        "different bytes already staged at key {}",
                        path.display()
                    )))
                }
            }
            Err(error) => Err(PgError::Artifact(format!(
                "cannot stage artifact {}: {error}",
                path.display()
            ))),
        }
    }

    fn read_after_write(&self, key: &ArtifactKeyV1) -> Result<Vec<u8>, PgError> {
        let path = self.file_path(key);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                PgError::Artifact(format!("staged artifact {} is absent", path.display()))
            } else {
                PgError::Artifact(format!(
                    "cannot read staged artifact {}: {error}",
                    path.display()
                ))
            }
        })?;

        let actual_digest = artifact_digest(key.kind, &bytes);
        if actual_digest != key.blake3_digest {
            return Err(PgError::Artifact(format!(
                "staged artifact {} digest {actual_digest} does not reproduce key digest {}",
                path.display(),
                key.blake3_digest
            )));
        }
        Ok(bytes)
    }
}

/// In-transaction insertion of fork-capable signed bytes into the logged
/// `artifact_body_pg` table (contract §"Immutable artifact boundary").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SignedArtifactBodyStore;

impl SignedArtifactBodyStore {
    /// Inserts exact signed bytes into `artifact_body_pg` in the same
    /// transaction as their catalog row and state transition.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Artifact`] on insertion failure.
    pub fn insert(
        transaction: &mut Transaction,
        key: &ArtifactKeyV1,
        bytes: &[u8],
    ) -> Result<(), PgError> {
        let actual_digest = artifact_digest(key.kind, bytes);
        if actual_digest != key.blake3_digest {
            return Err(PgError::Artifact(format!(
                "signed bytes digest {actual_digest} does not reproduce key digest {}",
                key.blake3_digest
            )));
        }

        let params: &[&(dyn postgres::types::ToSql + Sync)] = &[
            &key.kind.wire_name(),
            &key.blake3_digest.to_string(),
            &bytes,
        ];
        transaction
            .execute(
                "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
                 VALUES ($1, $2, $3, clock_timestamp())",
                params,
            )
            .map_err(|error| {
                PgError::Artifact(format!(
                    "cannot insert artifact body: {}",
                    pg_db_error_message(&error)
                ))
            })?;
        Ok(())
    }
}

/// Commits one artifact catalog row.
///
/// # Errors
///
/// Returns [`PgError::Artifact`] when the catalog row cannot be committed.
pub fn catalog_commit(
    transaction: &mut Transaction,
    identity: &ArtifactIdentity,
) -> Result<(), PgError> {
    let actual_digest = artifact_digest(identity.kind, &identity.canonical_bytes);
    if actual_digest != identity.digest {
        return Err(PgError::Artifact(format!(
            "artifact identity digest {actual_digest} does not reproduce declared digest {}",
            identity.digest
        )));
    }
    if identity.canonical_bytes.len() as u64 != identity.length {
        return Err(PgError::Artifact(format!(
            "artifact identity length {} does not match {} canonical bytes",
            identity.length,
            identity.canonical_bytes.len()
        )));
    }
    let length = i64::try_from(identity.length).map_err(|_| {
        PgError::Artifact(format!(
            "artifact byte length {} exceeds PostgreSQL BIGINT range",
            identity.length
        ))
    })?;
    let schema_version = identity
        .schema_version
        .map(i32::try_from)
        .transpose()
        .map_err(|_| {
            PgError::Artifact("artifact Schema version exceeds INTEGER range".to_owned())
        })?;

    // The storage location is "inline" exactly when the body was inserted into
    // `artifact_body_pg` in this same transaction; otherwise the reference is
    // a verified pre-staged neutral blob.
    let stored_inline: bool = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM artifact_body_pg WHERE kind = $1 AND digest = $2)",
            &[&identity.kind.wire_name(), &identity.digest.to_string()],
        )
        .map_err(|error| {
            PgError::Artifact(format!(
                "cannot resolve artifact storage location: {}",
                pg_db_error_message(&error)
            ))
        })?
        .get(0);

    let params: &[&(dyn postgres::types::ToSql + Sync)] = &[
        &identity.kind.wire_name(),
        &identity.digest.to_string(),
        &identity.media_type,
        &schema_version,
        &length,
        &stored_inline,
    ];
    transaction
        .execute(
            "INSERT INTO artifact_catalog
                 (kind, digest, media_type, schema_version, length, stored_inline, committed_at)
             VALUES ($1, $2, $3, $4, $5, $6, clock_timestamp())",
            params,
        )
        .map_err(|error| {
            PgError::Artifact(format!(
                "cannot commit artifact catalog row: {}",
                pg_db_error_message(&error)
            ))
        })?;
    Ok(())
}

/// Renders the most specific available PostgreSQL error detail: the
/// server-supplied severity and message when present, otherwise the
/// driver-level description.
fn pg_db_error_message(error: &postgres::Error) -> String {
    match error.as_db_error() {
        Some(db_error) => db_error.to_string(),
        None => error.to_string(),
    }
}

/// Computes the domain-separated BLAKE3-256 digest of exact canonical bytes
/// under the artifact kind's derive-key context (contract §"Immutable artifact
/// boundary"; mirrors [`proof_canonical::digest`]).
#[must_use]
fn artifact_digest(kind: ArtifactKind, bytes: &[u8]) -> ContentDigest {
    derive_key_digest(kind.derive_key_context(), bytes)
}
