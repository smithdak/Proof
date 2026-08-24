//! Filesystem private-preview adapter implementation tests (contract §"Preview
//! delivery", §"Evidence and private preview").
//!
//! These tests exercise the reference [`PreviewAdapter`] against isolated
//! temporary directories: materialization resolves only ready manifests, a
//! crash before the ready marker exposes nothing, the four alias compare-and-set
//! outcomes are exact, tampered blobs fail closed, and the ETag/cache-control
//! constants are pinned.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use proof_delivery::DeliveryError;
use proof_delivery::preview::{
    AliasOutcome, PREVIEW_CACHE_CONTROL, PreviewAdapter, PreviewBlobV1, PreviewSnapshotV1,
    ReadyManifestV1, strong_etag,
};
use proof_delivery::proof_domain::{ArtifactKind, ContentDigest};
use proof_delivery::proof_remote::derive_key_digest;

static COUNTER: AtomicU64 = AtomicU64::new(0);

const RELEASE_ID: &str = "018f0000-0000-7000-8000-000000000023";
const OTHER_RELEASE_ID: &str = "018f0000-0000-7000-8000-000000000024";

/// Allocates a unique, empty temporary directory per test.
fn temp_root() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("proof-preview-impl-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Computes the domain-separated digest exactly as the adapter does.
fn digest(kind: &str, bytes: &[u8]) -> ContentDigest {
    let kind = ArtifactKind::from_wire_name(kind).expect("fixture kind must be a wire name");
    derive_key_digest(kind.derive_key_context(), bytes)
}

/// Renders the 64-character hexadecimal digest component.
fn hex(digest: &ContentDigest) -> String {
    digest.to_string().trim_start_matches("blake3:").to_owned()
}

/// Builds a valid content-addressed preview blob fixture.
fn blob(kind: &str, bytes: &[u8]) -> PreviewBlobV1 {
    let digest = digest(kind, bytes);
    PreviewBlobV1 {
        key: format!("artifacts/{kind}/blake3/{}", hex(&digest)),
        kind: kind.to_owned(),
        length: bytes.len() as u64,
        digest,
        bytes: bytes.to_vec(),
    }
}

/// Builds a fixed four-blob snapshot fixture for a Release.
fn snapshot(release_sequence: u64, release_id: &str) -> PreviewSnapshotV1 {
    PreviewSnapshotV1 {
        release_id: release_id.to_owned(),
        release_sequence,
        release_digest: ContentDigest::blake3([0x77; 32]),
        edition_digest: ContentDigest::blake3([0x88; 32]),
        environment_config_digest: ContentDigest::blake3([0x99; 32]),
        proof_digest: ContentDigest::blake3([0x22; 32]),
        blobs: vec![
            blob("release_v2", br#"{"release":"v2"}"#),
            blob("edition_v2", br#"{"edition":"v2"}"#),
            blob("proof_envelope_v1", br#"{"proof":"envelope"}"#),
            blob("object_locale_revision_v1", br#"{"locale":"en-US"}"#),
        ],
    }
}

#[test]
fn materialize_then_resolve_returns_the_exact_ready_manifest() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let snap = snapshot(31, RELEASE_ID);

    let manifest = adapter.materialize_snapshot(&snap).unwrap();
    assert_eq!(manifest.release_id, snap.release_id);
    assert_eq!(manifest.release_sequence, snap.release_sequence);
    assert_eq!(manifest.release_digest, snap.release_digest);
    assert_eq!(manifest.edition_digest, snap.edition_digest);
    assert_eq!(
        manifest.blob_keys,
        snap.blobs
            .iter()
            .map(|blob| blob.key.clone())
            .collect::<Vec<_>>()
    );

    let resolved = adapter.resolve_ready(RELEASE_ID).unwrap();
    assert_eq!(resolved, manifest);

    // The manifest bytes are canonical and content-addressed: materializing the
    // exact snapshot again reproduces the identical manifest and digest.
    let again = adapter.materialize_snapshot(&snap).unwrap();
    assert_eq!(again, manifest);
    assert_eq!(again.manifest_digest, manifest.manifest_digest);
}

#[test]
fn deleting_the_ready_marker_hides_a_complete_snapshot() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let snap = snapshot(31, RELEASE_ID);
    let manifest = adapter.materialize_snapshot(&snap).unwrap();
    assert_eq!(adapter.resolve_ready(RELEASE_ID).unwrap(), manifest);

    // Simulate a crash before the ready marker write: the blobs and the
    // content-addressed manifest remain on disk, but the snapshot is invisible.
    let marker = root.join("releases").join(RELEASE_ID).join("ready");
    assert!(marker.exists());
    fs::remove_file(&marker).unwrap();
    assert!(root.join("manifests").exists());

    let error = adapter.resolve_ready(RELEASE_ID).unwrap_err();
    assert!(matches!(error, DeliveryError::Preview(_)));
}

#[test]
fn staged_blobs_without_a_ready_marker_are_invisible() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let snap = snapshot(31, RELEASE_ID);
    for blob in &snap.blobs {
        adapter.put_blob(blob).unwrap();
    }

    let error = adapter.resolve_ready(RELEASE_ID).unwrap_err();
    assert!(matches!(error, DeliveryError::Preview(_)));
}

#[test]
fn alias_cas_yields_the_four_exact_outcomes_by_sequence() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);

    let rel_a = ContentDigest::blake3([0xa0; 32]);
    let rel_b = ContentDigest::blake3([0xb0; 32]);
    let rel_c = ContentDigest::blake3([0xc0; 32]);
    let rel_d = ContentDigest::blake3([0xd0; 32]);
    let man_a = ContentDigest::blake3([0x1a; 32]);
    let man_b = ContentDigest::blake3([0x1b; 32]);
    let man_c = ContentDigest::blake3([0x1c; 32]);
    let man_d = ContentDigest::blake3([0x1d; 32]);

    // An absent alias advances on the first candidate.
    assert_eq!(
        adapter.alias_cas(31, &rel_b, &man_b).unwrap(),
        AliasOutcome::Advanced
    );
    assert!(root.join("alias").exists());

    // A higher Release sequence advances.
    assert_eq!(
        adapter.alias_cas(32, &rel_d, &man_d).unwrap(),
        AliasOutcome::Advanced
    );

    // Same sequence plus the same Release/manifest digest is a no-op.
    assert_eq!(
        adapter.alias_cas(32, &rel_d, &man_d).unwrap(),
        AliasOutcome::NoOp
    );

    // Same sequence plus a different manifest digest is an integrity failure.
    assert_eq!(
        adapter.alias_cas(32, &rel_d, &man_c).unwrap(),
        AliasOutcome::IntegrityFailure
    );
    // Same sequence plus a different Release digest is also an integrity failure.
    assert_eq!(
        adapter.alias_cas(32, &rel_c, &man_d).unwrap(),
        AliasOutcome::IntegrityFailure
    );

    // A lower sequence is recorded superseded without regressing the alias.
    assert_eq!(
        adapter.alias_cas(31, &rel_b, &man_b).unwrap(),
        AliasOutcome::Superseded
    );
    assert!(root.join("superseded").join("31").exists());

    // The alias still resolves to sequence 32 with (rel_d, man_d).
    assert_eq!(
        adapter.alias_cas(32, &rel_d, &man_d).unwrap(),
        AliasOutcome::NoOp
    );
    // A lower candidate remains superseded; the alias never regresses.
    assert_eq!(
        adapter.alias_cas(31, &rel_b, &man_b).unwrap(),
        AliasOutcome::Superseded
    );
    assert_eq!(
        adapter.alias_cas(30, &rel_a, &man_a).unwrap(),
        AliasOutcome::Superseded
    );
}

#[test]
fn a_blob_with_a_wrong_digest_fails_materialization_closed() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let mut snap = snapshot(31, RELEASE_ID);

    // Replace the first blob's digest and key with a wrong, self-consistent
    // value so the digest verification — not the key check — fails closed.
    snap.blobs[0].digest = ContentDigest::blake3([0xee; 32]);
    snap.blobs[0].key = format!("artifacts/release_v2/blake3/{}", hex(&snap.blobs[0].digest));

    let error = adapter.materialize_snapshot(&snap).unwrap_err();
    assert!(matches!(error, DeliveryError::Integrity(_)));

    // No ready marker was written, so the partial snapshot is invisible.
    assert!(
        !root
            .join("releases")
            .join(RELEASE_ID)
            .join("ready")
            .exists()
    );
}

#[test]
fn blob_read_revalidates_kind_length_and_digest() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let b = blob("object_locale_revision_v1", b"hello rendition");

    // A declared length that does not match the byte count fails closed.
    let mut wrong_length = b.clone();
    wrong_length.length = 999;
    assert!(matches!(
        adapter.put_blob(&wrong_length),
        Err(DeliveryError::Integrity(_))
    ));

    // A key whose kind component disagrees with the declared kind fails closed.
    let mut wrong_kind = b.clone();
    wrong_kind.key = format!("artifacts/other_kind/blake3/{}", hex(&b.digest));
    assert!(matches!(
        adapter.put_blob(&wrong_kind),
        Err(DeliveryError::Integrity(_))
    ));

    // The correct blob stages and verifies read-back.
    adapter.put_blob(&b).unwrap();

    // Tampering the on-disk bytes is detected as an integrity incident on the
    // next stage of the same key.
    let path = root.join(&b.key);
    fs::write(&path, b"tampered bytes with a different content").unwrap();
    let error = adapter.put_blob(&b).unwrap_err();
    assert!(matches!(error, DeliveryError::Integrity(_)));
}

#[test]
fn resolve_revalidates_the_complete_blob_closure() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let snap = snapshot(31, RELEASE_ID);
    adapter.materialize_snapshot(&snap).unwrap();

    // Substitute the first blob's bytes on disk: the ready manifest now names a
    // blob whose digest no longer reproduces, so resolution fails closed.
    let path = root.join(&snap.blobs[0].key);
    fs::write(&path, b"substituted bytes").unwrap();

    let error = adapter.resolve_ready(RELEASE_ID).unwrap_err();
    assert!(matches!(error, DeliveryError::Integrity(_)));
}

#[test]
fn each_release_resolves_only_its_own_ready_manifest() {
    let root = temp_root();
    let adapter = PreviewAdapter::new(&root);
    let first = snapshot(31, RELEASE_ID);
    let second = snapshot(32, OTHER_RELEASE_ID);

    let first_manifest = adapter.materialize_snapshot(&first).unwrap();
    let second_manifest = adapter.materialize_snapshot(&second).unwrap();

    assert_ne!(first_manifest, second_manifest);
    assert_eq!(adapter.resolve_ready(RELEASE_ID).unwrap(), first_manifest);
    assert_eq!(
        adapter.resolve_ready(OTHER_RELEASE_ID).unwrap(),
        second_manifest
    );

    // An unknown Release has no ready marker.
    let error = adapter
        .resolve_ready("018f0000-0000-7000-8000-000000000099")
        .unwrap_err();
    assert!(matches!(error, DeliveryError::Preview(_)));
}

#[test]
fn etag_and_cache_control_constants_are_exact() {
    assert_eq!(PREVIEW_CACHE_CONTROL, "private, no-store");
    let digest = ContentDigest::blake3([0xab; 32]);
    assert_eq!(strong_etag(&digest), format!("\"{digest}\""));
    // A strong ETag accompanies an immutable representation: it is the manifest
    // digest, not a mutable sequence or timestamp.
    let manifest = ReadyManifestV1 {
        manifest_digest: digest,
        release_id: RELEASE_ID.to_owned(),
        release_sequence: 31,
        release_digest: ContentDigest::blake3([0x77; 32]),
        edition_digest: ContentDigest::blake3([0x88; 32]),
        blob_keys: vec![],
    };
    assert_eq!(
        strong_etag(&manifest.manifest_digest),
        format!("\"{digest}\"")
    );
}
