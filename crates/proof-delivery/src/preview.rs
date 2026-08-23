//! Private preview delivery adapter (contract §"Preview delivery", §"Evidence
//! and private preview").
//!
//! The filesystem-backed reference adapter materializes every blob under an
//! unreachable content-addressed key, verifies kind/length/digest, and writes
//! one content-addressed complete-snapshot manifest and a ready marker last;
//! reads and the mutable alias resolve only ready manifests so a crash cannot
//! expose a partial snapshot. Alias compare-and-set outcomes are exact: a
//! higher Release sequence advances; the same sequence plus the same
//! Release/manifest digest is a no-op; the same sequence plus different bytes
//! is an integrity failure; a lower sequence is recorded superseded without
//! regressing the alias (contract §"Evidence and private preview").

use std::path::PathBuf;

use proof_domain::ContentDigest;

use crate::DeliveryError;

/// The exact `Cache-Control` value for private preview responses (contract
/// §"Preview delivery").
pub const PREVIEW_CACHE_CONTROL: &str = "private, no-store";

/// Renders a strong HTTP ETag from the immutable manifest digest (contract
/// §"Preview delivery"). A strong ETag accompanies immutable representations.
#[must_use]
pub fn strong_etag(manifest_digest: &ContentDigest) -> String {
    format!("\"{manifest_digest}\"")
}

/// One content-addressed preview blob (contract §"Preview delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewBlobV1 {
    /// The unreachable content-addressed key.
    pub key: String,
    /// Exact artifact kind.
    pub kind: String,
    /// Exact byte length.
    pub length: u64,
    /// Domain-separated digest of the exact bytes.
    pub digest: ContentDigest,
    /// Exact bytes, verified before materialization.
    pub bytes: Vec<u8>,
}

/// The exact Release snapshot a `preview.release/v1` event names (contract
/// §"Preview delivery"). It never resolves an ambient "current" Release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewSnapshotV1 {
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// Exact Release sequence.
    pub release_sequence: u64,
    /// Exact Release digest.
    pub release_digest: ContentDigest,
    /// Exact Edition digest.
    pub edition_digest: ContentDigest,
    /// Exact Environment configuration digest.
    pub environment_config_digest: ContentDigest,
    /// Exact Proof digest.
    pub proof_digest: ContentDigest,
    /// The complete blob closure.
    pub blobs: Vec<PreviewBlobV1>,
}

/// The content-addressed complete-snapshot manifest, written before the ready
/// marker (contract §"Preview delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyManifestV1 {
    /// Digest of the complete-snapshot manifest bytes.
    pub manifest_digest: ContentDigest,
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// Exact Release sequence.
    pub release_sequence: u64,
    /// Exact Release digest.
    pub release_digest: ContentDigest,
    /// Exact Edition digest.
    pub edition_digest: ContentDigest,
    /// Content-addressed blob keys in the complete snapshot.
    pub blob_keys: Vec<String>,
}

/// The closed alias compare-and-set outcome (contract §"Preview delivery").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AliasOutcome {
    /// A higher Release sequence advanced the alias.
    Advanced,
    /// The same sequence plus the same Release/manifest digest; a no-op.
    NoOp,
    /// The same sequence plus different bytes; an integrity failure.
    IntegrityFailure,
    /// A lower sequence was recorded superseded without regressing the alias.
    Superseded,
}

/// Filesystem-backed private preview adapter (reference implementation,
/// contract §"Preview delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewAdapter {
    root: PathBuf,
}

impl PreviewAdapter {
    /// Selects the private preview root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the private preview root.
    #[must_use]
    pub const fn root(&self) -> &PathBuf {
        &self.root
    }

    /// Materializes one blob under its unreachable content-addressed key.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Integrity`] when kind, length, or digest
    /// verification fails, or [`DeliveryError::Preview`] on storage failure.
    pub fn put_blob(&self, blob: &PreviewBlobV1) -> Result<(), DeliveryError> {
        let _ = (self, blob);
        todo!(
            "materialize the blob under its unreachable content-addressed key, verifying kind/length/digest"
        )
    }

    /// Writes the complete-snapshot manifest and ready marker last.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Preview`] when the snapshot cannot be
    /// materialized atomically.
    pub fn materialize_snapshot(
        &self,
        snapshot: &PreviewSnapshotV1,
    ) -> Result<ReadyManifestV1, DeliveryError> {
        let _ = (self, snapshot);
        todo!(
            "write the complete-snapshot manifest and ready marker LAST so a crash cannot expose a partial snapshot"
        )
    }

    /// Compares-and-sets the mutable alias with the four exact outcomes by
    /// Release sequence (contract §"Preview delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Preview`] on storage failure. An integrity
    /// failure is reported as [`AliasOutcome::IntegrityFailure`].
    pub fn alias_cas(
        &self,
        release_sequence: u64,
        release_digest: &ContentDigest,
        manifest_digest: &ContentDigest,
    ) -> Result<AliasOutcome, DeliveryError> {
        let _ = (self, release_sequence, release_digest, manifest_digest);
        todo!("compare-and-set the mutable alias with the four exact outcomes by Release sequence")
    }

    /// Resolves only ready manifests; a pending or partial snapshot is never
    /// visible (contract §"Preview delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Preview`] when no ready manifest exists for the
    /// exact Release.
    pub fn resolve_ready(&self, release_id: &str) -> Result<ReadyManifestV1, DeliveryError> {
        let _ = (self, release_id);
        todo!("resolve only ready manifests; a pending or partial snapshot is never visible")
    }
}
