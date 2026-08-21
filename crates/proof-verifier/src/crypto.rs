use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    model::{ArtifactKind, Digest},
    strict_json::parse_canonical,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseSignature {
    keyid: String,
    sig: String,
}

#[derive(Clone, Debug)]
pub struct PublicSigner {
    pub key_id: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct VerifiedEnvelope {
    pub payload_bytes: Vec<u8>,
    pub payload: Value,
}

#[derive(Clone, Debug)]
pub struct UnverifiedEnvelope {
    pub payload: Value,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum CryptoError {
    #[error("invalid canonical DSSE envelope")]
    InvalidEnvelope,
    #[error("unsupported DSSE payload type")]
    PayloadType,
    #[error("invalid DSSE signature count")]
    SignatureCount,
    #[error("DSSE signer differs from caller trust")]
    SignerMismatch,
    #[error("invalid canonical base64")]
    Base64,
    #[error("invalid Ed25519 public key")]
    PublicKey,
    #[error("invalid Ed25519 signature")]
    Signature,
    #[error("invalid canonical DSSE payload")]
    InvalidPayload,
}

#[must_use]
pub fn domain_digest(kind: ArtifactKind, canonical: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(kind.context());
    hasher.update(canonical);
    Digest(*hasher.finalize().as_bytes())
}

pub fn parse_public_signer(key_id: &str, public_key: &str) -> Result<PublicSigner, CryptoError> {
    let key_hex = key_id
        .strip_prefix("ed25519:")
        .ok_or(CryptoError::PublicKey)?;
    if key_hex.len() != 64
        || !key_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CryptoError::PublicKey);
    }
    let decoded = BASE64.decode(public_key).map_err(|_| CryptoError::Base64)?;
    if BASE64.encode(&decoded) != public_key {
        return Err(CryptoError::Base64);
    }
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| CryptoError::PublicKey)?;
    let mut expected = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(expected, "{byte:02x}");
    }
    if expected != key_hex || VerifyingKey::from_bytes(&bytes).is_err() {
        return Err(CryptoError::PublicKey);
    }
    Ok(PublicSigner {
        key_id: key_id.to_owned(),
        public_key: bytes,
    })
}

pub fn verify_dsse(
    envelope_bytes: &[u8],
    _envelope_kind: ArtifactKind,
    allowed_payload_types: &[&str],
    expected_signers: &[PublicSigner],
    max_json_depth: usize,
    max_envelope_bytes: usize,
    max_payload_bytes: usize,
) -> Result<VerifiedEnvelope, CryptoError> {
    if envelope_bytes.len() > max_envelope_bytes {
        return Err(CryptoError::InvalidEnvelope);
    }
    let envelope_value = parse_canonical(envelope_bytes, max_json_depth)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let envelope: DsseEnvelope =
        serde_json::from_value(envelope_value).map_err(|_| CryptoError::InvalidEnvelope)?;
    if !allowed_payload_types.contains(&envelope.payload_type.as_str()) {
        return Err(CryptoError::PayloadType);
    }
    if envelope.signatures.len() != expected_signers.len() || expected_signers.is_empty() {
        return Err(CryptoError::SignatureCount);
    }
    validate_envelope_scalars(&envelope, max_payload_bytes)?;
    let payload = BASE64
        .decode(&envelope.payload)
        .map_err(|_| CryptoError::Base64)?;
    if BASE64.encode(&payload) != envelope.payload {
        return Err(CryptoError::Base64);
    }
    if payload.len() > max_payload_bytes {
        return Err(CryptoError::InvalidPayload);
    }
    let payload_value =
        parse_canonical(&payload, max_json_depth).map_err(|_| CryptoError::InvalidPayload)?;
    let pae = dsse_pae(&envelope.payload_type, &payload);
    for (signature, expected) in envelope.signatures.iter().zip(expected_signers) {
        if signature.keyid != expected.key_id {
            return Err(CryptoError::SignerMismatch);
        }
        let signature_bytes = BASE64
            .decode(&signature.sig)
            .map_err(|_| CryptoError::Base64)?;
        if BASE64.encode(&signature_bytes) != signature.sig {
            return Err(CryptoError::Base64);
        }
        let signature_bytes: [u8; 64] = signature_bytes
            .try_into()
            .map_err(|_| CryptoError::Signature)?;
        let key =
            VerifyingKey::from_bytes(&expected.public_key).map_err(|_| CryptoError::PublicKey)?;
        key.verify_strict(&pae, &Signature::from_bytes(&signature_bytes))
            .map_err(|_| CryptoError::Signature)?;
    }
    Ok(VerifiedEnvelope {
        payload_bytes: payload,
        payload: payload_value,
    })
}

pub fn parse_dsse_unverified(
    envelope_bytes: &[u8],
    max_json_depth: usize,
    max_envelope_bytes: usize,
    max_payload_bytes: usize,
) -> Result<UnverifiedEnvelope, CryptoError> {
    if envelope_bytes.len() > max_envelope_bytes {
        return Err(CryptoError::InvalidEnvelope);
    }
    let envelope_value = parse_canonical(envelope_bytes, max_json_depth)
        .map_err(|_| CryptoError::InvalidEnvelope)?;
    let envelope: DsseEnvelope =
        serde_json::from_value(envelope_value).map_err(|_| CryptoError::InvalidEnvelope)?;
    validate_envelope_scalars(&envelope, max_payload_bytes)?;
    let payload = BASE64
        .decode(&envelope.payload)
        .map_err(|_| CryptoError::Base64)?;
    if BASE64.encode(&payload) != envelope.payload {
        return Err(CryptoError::Base64);
    }
    if payload.len() > max_payload_bytes {
        return Err(CryptoError::InvalidPayload);
    }
    let payload =
        parse_canonical(&payload, max_json_depth).map_err(|_| CryptoError::InvalidPayload)?;
    Ok(UnverifiedEnvelope { payload })
}

fn validate_envelope_scalars(
    envelope: &DsseEnvelope,
    max_payload_bytes: usize,
) -> Result<(), CryptoError> {
    let encoded_payload_limit = max_payload_bytes
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(CryptoError::InvalidEnvelope)?;
    if envelope.payload_type.is_empty()
        || envelope.payload_type.len() > 128
        || envelope.payload.len() > encoded_payload_limit
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > 2
        || envelope.signatures.iter().any(|signature| {
            signature.keyid.is_empty()
                || signature.keyid.len() > 256
                || signature.sig.is_empty()
                || signature.sig.len() > 128
        })
    {
        return Err(CryptoError::InvalidEnvelope);
    }
    for signature in &envelope.signatures {
        let bytes = BASE64
            .decode(&signature.sig)
            .map_err(|_| CryptoError::Base64)?;
        if bytes.len() != 64 || BASE64.encode(bytes) != signature.sig {
            return Err(CryptoError::Base64);
        }
    }
    Ok(())
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(prefix.len() + payload.len());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(payload);
    pae
}
