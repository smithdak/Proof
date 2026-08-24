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

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use proof_domain::{ArtifactKind, ContentDigest};
use proof_remote::derive_key_digest;
use serde_json::{Value, json};

use crate::DeliveryError;

/// The exact `Cache-Control` value for private preview responses (contract
/// §"Preview delivery").
pub const PREVIEW_CACHE_CONTROL: &str = "private, no-store";

/// Canonical `api_version` of the complete-snapshot manifest.
const MANIFEST_API_VERSION: &str = "proof.dev/preview-manifest/v1";

/// Domain-separated BLAKE3-256 derive-key context for the complete-snapshot
/// manifest digest. The manifest is an unauthenticated producer projection, not
/// a remote-authority payload, so it owns a closed context distinct from every
/// [`proof_remote`] authority or management-fact context.
const PREVIEW_MANIFEST_DIGEST_CONTEXT: &str = "proof:preview-manifest:v1";

/// Canonical `api_version` of the mutable alias record.
const ALIAS_API_VERSION: &str = "proof.dev/preview-alias/v1";

/// Canonical `api_version` of a superseded-candidate record.
const SUPERSEDED_API_VERSION: &str = "proof.dev/preview-superseded/v1";

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
    /// The key must reproduce the exact `artifacts/{kind}/blake3/{digest}`
    /// form; the declared length must equal the byte count; and the
    /// domain-separated digest must reproduce over the exact bytes. After
    /// writing, the bytes are read back and re-verified, so a staged blob that
    /// cannot reproduce its identity fails closed.
    ///
    /// An existing key succeeds only when its bytes are byte-identical;
    /// different bytes at one key are an integrity incident (contract
    /// §"Immutable artifact boundary").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Integrity`] when kind, length, or digest
    /// verification fails, or [`DeliveryError::Preview`] on storage failure.
    pub fn put_blob(&self, blob: &PreviewBlobV1) -> Result<(), DeliveryError> {
        let expected_key = blob_key(&blob.kind, &blob.digest);
        if blob.key != expected_key {
            return Err(DeliveryError::Integrity(format!(
                "blob key `{}` does not reproduce the content-addressed key `{}`",
                blob.key, expected_key
            )));
        }
        if blob.bytes.len() as u64 != blob.length {
            return Err(DeliveryError::Integrity(format!(
                "blob length {} does not match {} exact bytes",
                blob.length,
                blob.bytes.len()
            )));
        }
        let actual_digest = blob_digest(&blob.kind, &blob.bytes)?;
        if actual_digest != blob.digest {
            return Err(DeliveryError::Integrity(format!(
                "blob digest {actual_digest} does not reproduce declared digest {}",
                blob.digest
            )));
        }

        let path = self.root.join(&blob.key);
        write_blob_file(&path, &blob.bytes)?;

        // Read-after-write: revalidate kind (from the key), length, and digest.
        let read_back = fs::read(&path).map_err(|error| {
            DeliveryError::Preview(format!(
                "cannot read back staged blob {}: {error}",
                path.display()
            ))
        })?;
        if read_back.len() as u64 != blob.length {
            return Err(DeliveryError::Integrity(format!(
                "read-back blob length {} does not match declared length {}",
                read_back.len(),
                blob.length
            )));
        }
        let read_back_digest = blob_digest(&blob.kind, &read_back)?;
        if read_back_digest != blob.digest {
            return Err(DeliveryError::Integrity(format!(
                "read-back blob digest {read_back_digest} does not reproduce declared digest {}",
                blob.digest
            )));
        }
        Ok(())
    }

    /// Writes the complete-snapshot manifest and ready marker last.
    ///
    /// Every blob is materialized and verified first; then one content-addressed
    /// complete-snapshot manifest is written; then the per-Release ready marker
    /// is written last. A crash before the marker leaves only unreachable blobs
    /// and an unreferenced manifest, so a partial snapshot is never visible.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Preview`] when the snapshot cannot be
    /// materialized atomically, or [`DeliveryError::Integrity`] when a blob or
    /// the manifest fails verification.
    pub fn materialize_snapshot(
        &self,
        snapshot: &PreviewSnapshotV1,
    ) -> Result<ReadyManifestV1, DeliveryError> {
        for blob in &snapshot.blobs {
            self.put_blob(blob)?;
        }

        let blob_keys = snapshot
            .blobs
            .iter()
            .map(|blob| blob.key.clone())
            .collect::<Vec<_>>();
        let mut manifest = ReadyManifestV1 {
            manifest_digest: ContentDigest::blake3([0_u8; 32]),
            release_id: snapshot.release_id.clone(),
            release_sequence: snapshot.release_sequence,
            release_digest: snapshot.release_digest,
            edition_digest: snapshot.edition_digest,
            blob_keys,
        };
        let manifest_digest = manifest_digest_of(&manifest)?;
        manifest.manifest_digest = manifest_digest;

        let manifest_bytes = encode_manifest(&manifest)?;
        write_file_atomic(&self.manifest_path(&manifest_digest), &manifest_bytes)?;

        // The ready marker is the visibility gate and is written last.
        write_file_atomic(
            &self.ready_marker_path(&snapshot.release_id),
            &manifest_bytes,
        )?;
        Ok(manifest)
    }

    /// Compares-and-sets the mutable alias with the four exact outcomes by
    /// Release sequence (contract §"Preview delivery").
    ///
    /// A higher Release sequence (or an absent alias) advances the alias; the
    /// same sequence plus the same Release/manifest digest is a no-op; the same
    /// sequence plus a different Release or manifest digest is an integrity
    /// failure; a lower sequence is recorded superseded without regressing the
    /// alias. Delivery failure never rewrites Release history.
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
        let candidate = AliasRecordV1 {
            release_sequence,
            release_digest: *release_digest,
            manifest_digest: *manifest_digest,
        };
        let alias_path = self.alias_path();
        let current = read_alias(&alias_path)?;
        match current {
            None => {
                write_file_atomic(&alias_path, &encode_alias(&candidate)?)?;
                Ok(AliasOutcome::Advanced)
            }
            Some(current) => match release_sequence.cmp(&current.release_sequence) {
                std::cmp::Ordering::Greater => {
                    write_file_atomic(&alias_path, &encode_alias(&candidate)?)?;
                    Ok(AliasOutcome::Advanced)
                }
                std::cmp::Ordering::Equal => {
                    if release_digest == &current.release_digest
                        && manifest_digest == &current.manifest_digest
                    {
                        Ok(AliasOutcome::NoOp)
                    } else {
                        Ok(AliasOutcome::IntegrityFailure)
                    }
                }
                std::cmp::Ordering::Less => {
                    write_file_atomic(
                        &self.superseded_path(release_sequence),
                        &encode_superseded(&candidate)?,
                    )?;
                    Ok(AliasOutcome::Superseded)
                }
            },
        }
    }

    /// Resolves only ready manifests; a pending or partial snapshot is never
    /// visible (contract §"Preview delivery").
    ///
    /// The per-Release ready marker is read, its manifest digest and identity
    /// are re-verified, the content-addressed manifest must match byte-for-byte,
    /// and every referenced blob key must still reproduce its digest.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Preview`] when no ready manifest exists for the
    /// exact Release, or [`DeliveryError::Integrity`] when the manifest or a
    /// referenced blob fails verification.
    pub fn resolve_ready(&self, release_id: &str) -> Result<ReadyManifestV1, DeliveryError> {
        let marker_path = self.ready_marker_path(release_id);
        let manifest_bytes = fs::read(&marker_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DeliveryError::Preview(format!("no ready manifest for release `{release_id}`"))
            } else {
                DeliveryError::Preview(format!(
                    "cannot read ready marker {}: {error}",
                    marker_path.display()
                ))
            }
        })?;
        let manifest = decode_manifest(&manifest_bytes)?;
        if manifest.release_id != release_id {
            return Err(DeliveryError::Integrity(format!(
                "ready marker for release `{release_id}` names release `{}`",
                manifest.release_id
            )));
        }

        // The content-addressed manifest must exist and reproduce the exact
        // bytes so a ready marker can only ever resolve a complete manifest.
        let content_addressed =
            fs::read(self.manifest_path(&manifest.manifest_digest)).map_err(|error| {
                DeliveryError::Preview(format!(
                    "content-addressed manifest {} is absent or unreadable: {error}",
                    self.manifest_path(&manifest.manifest_digest).display()
                ))
            })?;
        if content_addressed != manifest_bytes {
            return Err(DeliveryError::Integrity(format!(
                "content-addressed manifest {} does not match the ready marker",
                manifest.manifest_digest
            )));
        }

        // A ready manifest must resolve only a complete snapshot: every
        // referenced blob key must be present and reproduce its digest.
        for key in &manifest.blob_keys {
            self.verify_blob_key(key)?;
        }
        Ok(manifest)
    }

    /// Resolves the per-Release ready-marker path.
    fn ready_marker_path(&self, release_id: &str) -> PathBuf {
        self.root.join("releases").join(release_id).join("ready")
    }

    /// Resolves the content-addressed manifest path.
    fn manifest_path(&self, digest: &ContentDigest) -> PathBuf {
        self.root
            .join("manifests")
            .join("blake3")
            .join(digest_hex(digest))
    }

    /// Resolves the mutable alias path.
    fn alias_path(&self) -> PathBuf {
        self.root.join("alias")
    }

    /// Resolves the superseded-candidate record path for a Release sequence.
    fn superseded_path(&self, release_sequence: u64) -> PathBuf {
        self.root
            .join("superseded")
            .join(release_sequence.to_string())
    }

    /// Verifies that a content-addressed blob key exists and reproduces its
    /// kind/digest identity (length is revalidated at materialization time).
    fn verify_blob_key(&self, key: &str) -> Result<(), DeliveryError> {
        let (kind, digest) = parse_blob_key(key)?;
        let path = self.root.join(key);
        let bytes = fs::read(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                DeliveryError::Integrity(format!("referenced blob `{key}` is absent"))
            } else {
                DeliveryError::Preview(format!("cannot read referenced blob {key}: {error}"))
            }
        })?;
        let actual = blob_digest(kind, &bytes)?;
        if actual != digest {
            return Err(DeliveryError::Integrity(format!(
                "referenced blob `{key}` digest {actual} does not reproduce key digest {digest}"
            )));
        }
        Ok(())
    }
}

/// The mutable alias record: the highest-sequence ready manifest that has
/// advanced the alias (contract §"Preview delivery").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AliasRecordV1 {
    release_sequence: u64,
    release_digest: ContentDigest,
    manifest_digest: ContentDigest,
}

/// Returns the 64-character lowercase hexadecimal digest component.
fn digest_hex(digest: &ContentDigest) -> String {
    let encoded = digest.to_string();
    encoded
        .strip_prefix("blake3:")
        .unwrap_or(encoded.as_str())
        .to_owned()
}

/// Formats the canonical private content-addressed blob key.
fn blob_key(kind: &str, digest: &ContentDigest) -> String {
    format!("artifacts/{kind}/blake3/{}", digest_hex(digest))
}

/// Computes the domain-separated BLAKE3-256 digest of exact blob bytes under
/// the artifact kind's derive-key context (contract §"Immutable artifact
/// boundary"; mirrors [`proof_pg::artifacts::artifact_digest`]).
fn blob_digest(kind: &str, bytes: &[u8]) -> Result<ContentDigest, DeliveryError> {
    let artifact_kind = ArtifactKind::from_wire_name(kind).ok_or_else(|| {
        DeliveryError::Integrity(format!("unknown artifact kind wire name `{kind}`"))
    })?;
    Ok(derive_key_digest(artifact_kind.derive_key_context(), bytes))
}

/// Parses a content-addressed blob key `artifacts/{kind}/blake3/{digest}`.
fn parse_blob_key(key: &str) -> Result<(&str, ContentDigest), DeliveryError> {
    let rest = key.strip_prefix("artifacts/").ok_or_else(|| {
        DeliveryError::Integrity(format!("blob key `{key}` lacks the `artifacts/` prefix"))
    })?;
    let (kind, hex) = rest.split_once("/blake3/").ok_or_else(|| {
        DeliveryError::Integrity(format!("blob key `{key}` lacks the `/blake3/` component"))
    })?;
    if kind.is_empty() || hex.len() != 64 {
        return Err(DeliveryError::Integrity(format!(
            "blob key `{key}` has an invalid kind or digest component"
        )));
    }
    let digest = format!("blake3:{hex}")
        .parse::<ContentDigest>()
        .map_err(|error| {
            DeliveryError::Integrity(format!("blob key `{key}` has an invalid digest: {error}"))
        })?;
    Ok((kind, digest))
}

/// Renders the canonical manifest preimage: every field except
/// `manifest_digest`. The digest is over this preimage so the manifest is
/// content-addressed without a self-referential digest member.
fn manifest_preimage_json(manifest: &ReadyManifestV1) -> Value {
    json!({
        "api_version": MANIFEST_API_VERSION,
        "release_id": manifest.release_id,
        "release_sequence": manifest.release_sequence,
        "release_digest": manifest.release_digest.to_string(),
        "edition_digest": manifest.edition_digest.to_string(),
        "blob_keys": manifest.blob_keys,
    })
}

/// Renders the canonical manifest document (including `manifest_digest`).
fn manifest_json(manifest: &ReadyManifestV1) -> Value {
    json!({
        "api_version": MANIFEST_API_VERSION,
        "manifest_digest": manifest.manifest_digest.to_string(),
        "release_id": manifest.release_id,
        "release_sequence": manifest.release_sequence,
        "release_digest": manifest.release_digest.to_string(),
        "edition_digest": manifest.edition_digest.to_string(),
        "blob_keys": manifest.blob_keys,
    })
}

/// Computes the domain-separated digest of the manifest preimage.
fn manifest_digest_of(manifest: &ReadyManifestV1) -> Result<ContentDigest, DeliveryError> {
    let canonical = canonicalize(&manifest_preimage_json(manifest))?;
    Ok(derive_key_digest(
        PREVIEW_MANIFEST_DIGEST_CONTEXT,
        canonical.as_bytes(),
    ))
}

/// Canonicalizes a [`ReadyManifestV1`] into its exact manifest bytes.
fn encode_manifest(manifest: &ReadyManifestV1) -> Result<Vec<u8>, DeliveryError> {
    canonicalize(&manifest_json(manifest)).map(|canonical| canonical.as_bytes().to_vec())
}

/// Parses exact manifest bytes back into a [`ReadyManifestV1`], re-verifying
/// the content-addressed manifest digest.
fn decode_manifest(bytes: &[u8]) -> Result<ReadyManifestV1, DeliveryError> {
    let value = parse_strict(bytes)?;
    if value.get("api_version").and_then(Value::as_str) != Some(MANIFEST_API_VERSION) {
        return Err(DeliveryError::Integrity(
            "manifest `api_version` is missing or unsupported".to_owned(),
        ));
    }
    let manifest = ReadyManifestV1 {
        manifest_digest: field_digest(&value, "manifest_digest")?,
        release_id: field_string(&value, "release_id")?,
        release_sequence: field_u64(&value, "release_sequence")?,
        release_digest: field_digest(&value, "release_digest")?,
        edition_digest: field_digest(&value, "edition_digest")?,
        blob_keys: field_string_array(&value, "blob_keys")?,
    };
    let recomputed = manifest_digest_of(&manifest)?;
    if recomputed != manifest.manifest_digest {
        return Err(DeliveryError::Integrity(format!(
            "manifest digest {recomputed} does not reproduce declared digest {}",
            manifest.manifest_digest
        )));
    }
    Ok(manifest)
}

/// Canonicalizes the mutable alias record.
fn encode_alias(alias: &AliasRecordV1) -> Result<Vec<u8>, DeliveryError> {
    let value = json!({
        "api_version": ALIAS_API_VERSION,
        "release_sequence": alias.release_sequence,
        "release_digest": alias.release_digest.to_string(),
        "manifest_digest": alias.manifest_digest.to_string(),
    });
    canonicalize(&value).map(|canonical| canonical.as_bytes().to_vec())
}

/// Parses the mutable alias record bytes.
fn decode_alias(bytes: &[u8]) -> Result<AliasRecordV1, DeliveryError> {
    let value = parse_strict(bytes)?;
    if value.get("api_version").and_then(Value::as_str) != Some(ALIAS_API_VERSION) {
        return Err(DeliveryError::Integrity(
            "alias `api_version` is missing or unsupported".to_owned(),
        ));
    }
    Ok(AliasRecordV1 {
        release_sequence: field_u64(&value, "release_sequence")?,
        release_digest: field_digest(&value, "release_digest")?,
        manifest_digest: field_digest(&value, "manifest_digest")?,
    })
}

/// Reads the current alias, or `None` when no alias has been recorded yet.
fn read_alias(path: &Path) -> Result<Option<AliasRecordV1>, DeliveryError> {
    match fs::read(path) {
        Ok(bytes) => decode_alias(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(DeliveryError::Preview(format!(
            "cannot read alias {}: {error}",
            path.display()
        ))),
    }
}

/// Canonicalizes a superseded-candidate record.
fn encode_superseded(candidate: &AliasRecordV1) -> Result<Vec<u8>, DeliveryError> {
    let value = json!({
        "api_version": SUPERSEDED_API_VERSION,
        "release_sequence": candidate.release_sequence,
        "release_digest": candidate.release_digest.to_string(),
        "manifest_digest": candidate.manifest_digest.to_string(),
    });
    canonicalize(&value).map(|canonical| canonical.as_bytes().to_vec())
}

/// Writes a blob under put-if-absent semantics: an existing key succeeds only
/// when its bytes are byte-identical (contract §"Immutable artifact boundary").
fn write_blob_file(path: &Path, bytes: &[u8]) -> Result<(), DeliveryError> {
    let parent = path.parent().ok_or_else(|| {
        DeliveryError::Preview(format!(
            "blob key path {} has no parent directory",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        DeliveryError::Preview(format!(
            "cannot create staging directory {}: {error}",
            parent.display()
        ))
    })?;

    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(bytes).map_err(|error| {
                let _ = fs::remove_file(path);
                DeliveryError::Preview(format!(
                    "cannot write staged blob {}: {error}",
                    path.display()
                ))
            })?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path).map_err(|error| {
                DeliveryError::Preview(format!(
                    "cannot read existing staged blob {}: {error}",
                    path.display()
                ))
            })?;
            if existing.as_slice() == bytes {
                Ok(())
            } else {
                Err(DeliveryError::Integrity(format!(
                    "different bytes already staged at key {}",
                    path.display()
                )))
            }
        }
        Err(error) => Err(DeliveryError::Preview(format!(
            "cannot stage blob {}: {error}",
            path.display()
        ))),
    }
}

/// Atomically writes exact bytes by writing a sibling temporary file and then
/// renaming it into place (contract §"Preview delivery": the ready marker is
/// the last write and is never observable in a partial state).
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), DeliveryError> {
    let parent = path.parent().ok_or_else(|| {
        DeliveryError::Preview(format!("path {} has no parent directory", path.display()))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        DeliveryError::Preview(format!(
            "cannot create directory {}: {error}",
            parent.display()
        ))
    })?;

    let mut temp_os = path.as_os_str().to_os_string();
    temp_os.push(".tmp");
    let temp_path = PathBuf::from(temp_os);
    if let Err(error) = fs::write(&temp_path, bytes) {
        return Err(DeliveryError::Preview(format!(
            "cannot write {}: {error}",
            temp_path.display()
        )));
    }
    fs::rename(&temp_path, path).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        DeliveryError::Preview(format!(
            "cannot rename {} to {}: {error}",
            temp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Strictly parses canonical JSON bytes and maps failures to integrity errors.
fn parse_strict(bytes: &[u8]) -> Result<Value, DeliveryError> {
    proof_canonical::parse_strict(bytes)
        .map_err(|error| DeliveryError::Integrity(format!("invalid canonical JSON bytes: {error}")))
}

/// Canonicalizes a JSON value to exact RFC 8785 bytes.
fn canonicalize(value: &Value) -> Result<proof_canonical::CanonicalJson, DeliveryError> {
    proof_canonical::canonicalize(value)
        .map_err(|error| DeliveryError::Integrity(format!("cannot canonicalize manifest: {error}")))
}

/// Extracts a required string member.
fn field_string(value: &Value, name: &str) -> Result<String, DeliveryError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| DeliveryError::Integrity(format!("manifest member `{name}` is missing")))
}

/// Extracts a required [`ContentDigest`] member.
fn field_digest(value: &Value, name: &str) -> Result<ContentDigest, DeliveryError> {
    let encoded = value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| DeliveryError::Integrity(format!("manifest member `{name}` is missing")))?;
    encoded.parse::<ContentDigest>().map_err(|error| {
        DeliveryError::Integrity(format!("manifest member `{name}` is invalid: {error}"))
    })
}

/// Extracts a required unsigned integer member.
fn field_u64(value: &Value, name: &str) -> Result<u64, DeliveryError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| DeliveryError::Integrity(format!("manifest member `{name}` is missing")))
}

/// Extracts a required array of string members.
fn field_string_array(value: &Value, name: &str) -> Result<Vec<String>, DeliveryError> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| DeliveryError::Integrity(format!("manifest member `{name}` is missing")))?
        .iter()
        .map(|entry| {
            entry.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                DeliveryError::Integrity(format!("manifest member `{name}` is not a string array"))
            })
        })
        .collect()
}
