//! `proof-verifier/remote-evidence-v2`: the composed verifier that validates
//! the release-artifact closure, the caller-anchored P8 remote authority, and
//! the exact attempt companions, then enforces every frozen cross-link
//! (contract §"Evidence export and independent verification").
//!
//! The report is classified Complete, Incomplete, or Invalid with exactly one
//! first-applicable primary reason. This module is a skeleton: the error
//! taxonomy and entrypoint signature are final, and the body is `todo!()`.

use proof_remote::{RemoteEvidenceMemberMap, RemoteVerificationReportV2, RemoteVerifierInputV2};
use thiserror::Error;

/// Closed remote-verifier error taxonomy.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemoteVerifierError {
    /// The remote authority suffix failed verification.
    #[error("remote authority suffix verification failed: {0}")]
    Authority(String),
    /// The remote evidence closure or cross-links failed verification.
    #[error("remote evidence verification failed: {0}")]
    Evidence(String),
    /// Remote verification input exceeds a v2 bound.
    #[error("remote verification input exceeds a v2 bound")]
    Limit,
    /// Remote verification input is not canonical v2 JSON.
    #[error("remote verification input is not canonical v2 JSON")]
    InvalidInput,
}

/// Verifies one exact logical member map under caller-controlled trust
/// (contract §"Evidence export and independent verification").
///
/// This validates the accepted Release/artifact closure, the caller-anchored
/// remote authority record set, and every attempt companion independently,
/// then enforces the Workspace, identity, command, policy, application-key,
/// Release, Proof, result, effect, decision, consequence, and authority-head
/// links before selecting one Complete, Incomplete, or Invalid classification
/// with its first-applicable primary reason.
#[must_use]
pub fn verify_remote_evidence_v2(
    members: &RemoteEvidenceMemberMap,
    verifier_input: &RemoteVerifierInputV2,
) -> RemoteVerificationReportV2 {
    let _ = (members, verifier_input);
    todo!("verify closure + Release/artifact closure + companions, then enforce cross-links")
}
