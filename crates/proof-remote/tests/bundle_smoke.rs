//! Public-surface smoke test for the remote evidence bundle boundary.
//!
//! These are surface assertions only: the closed types resolve, the frozen
//! constants are exact, and the validation entrypoints exist. No bytes are
//! validated here; the deeper conformance coverage lives in later
//! implementation items.

use std::mem::size_of;

use proof_remote::{
    CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS, EvidenceExportCaptureV2,
    EvidenceExportResultV2, EvidenceExportStatusV1, MAX_ARTIFACT_BYTES, MAX_AUTHORITY_RECORDS,
    MAX_EXPORT_ARTIFACT_BODIES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES, RemoteAuthorityRecordSetV1,
    RemoteEvidenceBundleV2, RemoteEvidenceManifestV2, RemoteReleaseArtifactClosureV1,
    RemoteVerificationConformanceReportV2, RemoteVerificationReportV2, UntrustedHintsV1,
    VerificationLimitsV2, VerificationTrustPolicyV2, normalize_member_path,
    validate_bundle_members,
};

/// References a `fn` item so a surface test can prove a crate-root name
/// resolves without a full invocation here.
fn references<T>(_: T) {}

#[test]
fn bundle_type_surface_resolves() {
    let _ = size_of::<RemoteEvidenceBundleV2>();
    let _ = size_of::<RemoteEvidenceManifestV2>();
    let _ = size_of::<RemoteReleaseArtifactClosureV1>();
    let _ = size_of::<RemoteAuthorityRecordSetV1>();
    let _ = size_of::<EvidenceExportCaptureV2>();
    let _ = size_of::<EvidenceExportResultV2>();
    let _ = size_of::<EvidenceExportStatusV1>();
    let _ = size_of::<VerificationTrustPolicyV2>();
    let _ = size_of::<RemoteVerificationReportV2>();
    let _ = size_of::<RemoteVerificationConformanceReportV2>();

    references(normalize_member_path);
    references(validate_bundle_members);
}

#[test]
fn bundle_constants_are_exact() {
    assert_eq!(
        CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS,
        "pre-export-attempt-locked-heads"
    );
    assert_eq!(MAX_EXPORT_ARTIFACT_BODIES, 4_096);
    assert_eq!(MAX_MANIFEST_BYTES, 4_194_304);
    assert_eq!(MAX_ARTIFACT_BYTES, 4_194_304);
    assert_eq!(MAX_TOTAL_BYTES, 268_435_456);
    assert_eq!(MAX_AUTHORITY_RECORDS, 512);
}

#[test]
fn inert_hints_and_contract_limits_are_frozen() {
    let hints = UntrustedHintsV1::inert();
    assert!(hints.authority_root_ids.is_empty());
    assert!(hints.release_root_ids.is_empty());
    assert!(hints.checkpoint_ids.is_empty());
    assert!(hints.resolver_urls.is_empty());
    assert!(!hints.trusted);
    assert!(!hints.auto_fetch);

    let limits = VerificationLimitsV2::contract();
    assert_eq!(limits.max_verifier_input_bytes, 268_435_456);
    assert_eq!(limits.max_manifest_bytes, 4_194_304);
    assert_eq!(limits.max_artifacts, 4_096);
    assert_eq!(limits.max_authority_records, 512);
    assert_eq!(limits.max_artifact_bytes, 4_194_304);
    assert_eq!(limits.max_total_bytes, 268_435_456);
    assert_eq!(limits.max_json_depth, 128);
}
