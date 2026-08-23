//! Immutable artifact catalog and durability boundary (contract §"Immutable
//! artifact boundary").

use std::path::PathBuf;

use postgres::Transaction;
use proof_domain::{ArtifactKind, ContentDigest};

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
        todo!()
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
}

impl StoragePort for FsStoragePort {
    fn put_if_absent(&self, key: &ArtifactKeyV1, bytes: &[u8]) -> Result<(), PgError> {
        todo!()
    }

    fn read_after_write(&self, key: &ArtifactKeyV1) -> Result<Vec<u8>, PgError> {
        todo!()
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
        todo!()
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
    todo!()
}
