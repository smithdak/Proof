//! Public-surface assertions only (no I/O, no bundle bytes, no trust inputs).
//!
//! These tests pin the closed remote-authority and remote-evidence verifier
//! surface so a later implementation cannot silently reshape the P-0013
//! verifier extension.

use std::mem::size_of;

use proof_remote::{
    RemoteEvidenceMemberMap, RemoteVerificationReportV2, RemoteVerifierInputV2,
    VerificationTrustPolicyV2,
};
use proof_verifier::{
    RemoteAuthoritySuffixInput, RemoteAuthoritySuffixOutput, RemoteVerifierError,
    verify_remote_authority_suffix, verify_remote_evidence_v2,
};

/// References a `fn` item so a surface test can prove a crate-root name
/// resolves without a full invocation here.
fn references<T>(_: T) {}

#[test]
fn remote_verifier_surface_resolves() {
    let _ = size_of::<RemoteAuthoritySuffixInput<'static>>();
    let _ = size_of::<RemoteAuthoritySuffixOutput>();
    let _ = size_of::<RemoteVerifierError>();
    let _ = size_of::<VerificationTrustPolicyV2>();
    let _ = size_of::<RemoteVerifierInputV2>();
    let _ = size_of::<RemoteVerificationReportV2>();
    let _ = size_of::<RemoteEvidenceMemberMap>();

    references(verify_remote_authority_suffix);
    references(verify_remote_evidence_v2);
}
