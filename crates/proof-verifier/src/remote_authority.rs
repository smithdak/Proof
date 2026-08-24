//! `proof-verifier/remote-authority/v1`: validates a canonical contiguous P8
//! DSSE suffix from a caller-pinned initial head (contract §"Evidence export
//! and independent verification").
//!
//! The verifier has no producer database, network, or authenticated base-state
//! snapshot; every OIDC/Agent binding, Delegation, revocation, Principal/role,
//! Environment, approval, decision, and consequence fact consumed for the
//! selected attempt must be present in the supplied suffix after the initial
//! head. This module is a skeleton: the input/output shapes and the entrypoint
//! signature are final, and the body is `todo!()`.

use proof_remote::{AuthorityHeadV1, VerifiedRemoteAuthorityRecord};

use crate::remote_evidence::RemoteVerifierError;

/// Caller-supplied bounded authority suffix to verify.
#[derive(Clone, Debug)]
pub struct RemoteAuthoritySuffixInput<'a> {
    /// Exact canonical P8 DSSE envelope bytes, in ascending authority sequence.
    pub envelopes: &'a [Vec<u8>],
    /// Independently resolved active Workspace authority key identifier
    /// (`ed25519:<64 lowercase hex>`).
    pub initial_root_key_id: &'a str,
    /// Caller-pinned initial head that strictly precedes the first record.
    pub initial_head: AuthorityHeadV1,
}

/// Verified contiguous authority suffix.
#[derive(Clone, Debug)]
pub struct RemoteAuthoritySuffixOutput {
    /// The included head: the last verified record's head, or the initial head
    /// when the suffix is empty.
    pub included_head: AuthorityHeadV1,
    /// Every cryptographically verified and chain-validated record.
    pub verified_records: Vec<VerifiedRemoteAuthorityRecord>,
}

/// Validates one canonical contiguous P8 DSSE suffix from a caller-pinned
/// initial head (contract §"Evidence export and independent verification").
///
/// # Errors
///
/// Returns [`RemoteVerifierError::Authority`] on any signature, signer-key,
/// sequence, predecessor, or head-coherence violation.
pub fn verify_remote_authority_suffix(
    input: &RemoteAuthoritySuffixInput<'_>,
) -> Result<RemoteAuthoritySuffixOutput, RemoteVerifierError> {
    let _ = input;
    todo!("verify the contiguous P8 DSSE suffix from the caller-pinned initial head")
}
