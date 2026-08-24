//! `proof-verifier/remote-authority/v1`: validates a canonical contiguous P8
//! DSSE suffix from a caller-pinned initial head (contract §"Evidence export
//! and independent verification").
//!
//! The verifier has no producer database, network, or authenticated base-state
//! snapshot; every OIDC/Agent binding, Delegation, revocation, Principal/role,
//! Environment, approval, decision, and consequence fact consumed for the
//! selected attempt must be present in the supplied suffix after the initial
//! head.

use proof_remote::{
    ActiveAuthorityKeyResolver, AuthorityHeadV1, RemoteError, VerifiedRemoteAuthorityRecord,
    validate_chain, verify_remote_authority_record_envelope,
};

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

/// Resolves exactly one pinned active Workspace authority key for the whole
/// prefix (contract §"Remote identity vocabulary"). The remote profile has no
/// key-transition payload, so a single independently resolved key is the only
/// accepted signer.
struct SingleActiveKeyResolver {
    key_id: String,
    public_key: [u8; 32],
}

impl ActiveAuthorityKeyResolver for SingleActiveKeyResolver {
    fn resolve_active_key(&self, key_id: &str) -> Result<[u8; 32], RemoteError> {
        if key_id == self.key_id {
            Ok(self.public_key)
        } else {
            Err(RemoteError::Authority(format!(
                "unexpected active authority key `{key_id}`; expected `{}`",
                self.key_id
            )))
        }
    }
}

/// Parses the `ed25519:<64 lowercase hex>` key identifier into its exact
/// decoded 32-byte public key.
fn parse_authority_key_id(key_id: &str) -> Result<[u8; 32], RemoteVerifierError> {
    let hex = key_id.strip_prefix("ed25519:").ok_or_else(|| {
        RemoteVerifierError::Authority(
            "authority key identifier must be `ed25519:<hex>`".to_owned(),
        )
    })?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RemoteVerifierError::Authority(
            "authority key identifier must carry 64 lowercase hex digits".to_owned(),
        ));
    }
    let mut public_key = [0_u8; 32];
    for (index, byte) in public_key.iter_mut().enumerate() {
        let pair = &hex[index * 2..index * 2 + 2];
        *byte = u8::from_str_radix(pair, 16).map_err(|_| {
            RemoteVerifierError::Authority("authority key identifier hex is invalid".to_owned())
        })?;
    }
    Ok(public_key)
}

fn authority_error(error: &RemoteError) -> RemoteVerifierError {
    RemoteVerifierError::Authority(error.to_string())
}

/// Validates one canonical contiguous P8 DSSE suffix from a caller-pinned
/// initial head (contract §"Evidence export and independent verification").
///
/// Every envelope is verified against the independently resolved active
/// Workspace authority key, and the decoded records are then chain-validated
/// for sequence contiguity, predecessor linkage, and head coherence using
/// [`validate_chain`] semantics.
///
/// # Errors
///
/// Returns [`RemoteVerifierError::Authority`] on any signature, signer-key,
/// sequence, predecessor, or head-coherence violation.
pub fn verify_remote_authority_suffix(
    input: &RemoteAuthoritySuffixInput<'_>,
) -> Result<RemoteAuthoritySuffixOutput, RemoteVerifierError> {
    let public_key = parse_authority_key_id(input.initial_root_key_id)?;
    let resolver = SingleActiveKeyResolver {
        key_id: input.initial_root_key_id.to_owned(),
        public_key,
    };

    let mut verified_records = Vec::with_capacity(input.envelopes.len());
    for envelope in input.envelopes {
        let verified = verify_remote_authority_record_envelope(envelope, input.initial_root_key_id)
            .map_err(|error| authority_error(&error))?;
        verified_records.push(VerifiedRemoteAuthorityRecord {
            record: verified.parsed.record,
            record_digest: verified.parsed.payload_digest,
            envelope_digest: verified.parsed.envelope_digest,
            signer_key_id: verified.key_id,
            public_key: verified.public_key,
        });
    }

    let included_head = validate_chain(&verified_records, &resolver, input.initial_head)
        .map_err(|error| authority_error(&error))?;

    Ok(RemoteAuthoritySuffixOutput {
        included_head,
        verified_records,
    })
}
