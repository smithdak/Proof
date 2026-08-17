#![forbid(unsafe_code)]

//! Strict DSSE and in-toto Release Proof production and verification.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_domain::{ArtifactKind, ContentDigest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroize;

/// DSSE payload type required by the Proof v1 profile.
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
/// in-toto Statement type required by the Proof v1 profile.
pub const IN_TOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// Proof Release predicate type required by the Proof v1 profile.
pub const RELEASE_PREDICATE_TYPE: &str = "urn:proof:attestation:release:v1";

/// Maximum complete canonical DSSE envelope length.
pub const MAX_ENVELOPE_BYTES: usize = 4 * 1_048_576;
/// Maximum decoded canonical Statement payload length.
pub const MAX_PAYLOAD_BYTES: usize = 2 * 1_048_576;
/// Maximum number of in-toto subjects in the first profile.
pub const MAX_SUBJECTS: usize = 1_024;
/// Maximum UTF-8 bytes in an in-toto subject name.
pub const MAX_SUBJECT_NAME_BYTES: usize = 1_024;
/// Exact Ed25519 signature byte length.
pub const ED25519_SIGNATURE_BYTES: usize = 64;
/// Exact Ed25519 public-key byte length.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Signature algorithm supported by the first Proof envelope profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// RFC 8032 Ed25519.
    Ed25519,
}

/// Public, non-secret metadata exposed by a signing-key provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyMetadata {
    /// Explicit stable key identifier.
    pub key_id: String,
    /// Signature algorithm implemented by this key.
    pub algorithm: SignatureAlgorithm,
    /// Raw public-key bytes.
    pub public_key: Vec<u8>,
}

/// Object-safe signing boundary; implementations retain all private key material.
pub trait ProofSigningProvider {
    /// Returns public key metadata without exposing a private key.
    ///
    /// # Errors
    ///
    /// Returns [`SigningProviderError`] when key metadata is unavailable.
    fn metadata(&self) -> Result<SigningKeyMetadata, SigningProviderError>;

    /// Signs exact DSSE PAE bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SigningProviderError`] when the key provider cannot sign.
    fn sign_pae(&self, pae: &[u8]) -> Result<Vec<u8>, SigningProviderError>;
}

/// A signing provider could not return public metadata or a signature.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SigningProviderError {
    /// Key material or a remote provider is unavailable.
    #[error("signing provider unavailable: {0}")]
    Unavailable(String),
    /// Provider-specific signing failed without exposing secret state.
    #[error("signing provider failed: {0}")]
    Failed(String),
}

/// In-memory Ed25519 provider suitable for a local key-storage adapter.
pub struct Ed25519SigningProvider {
    signing_key: SigningKey,
    key_id: String,
}

impl Ed25519SigningProvider {
    /// Constructs a provider from exact secret seed bytes.
    ///
    /// The caller remains responsible for protected persistence and zeroization
    /// of its source buffer.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        let key_id = ed25519_key_id(&signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            key_id,
        }
    }

    /// Generates a provider from the operating system random source.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::RandomUnavailable`] when the OS random source
    /// cannot fill a complete Ed25519 seed.
    pub fn generate() -> Result<Self, AttestationError> {
        let mut secret = [0_u8; 32];
        if let Err(error) = getrandom::fill(&mut secret) {
            secret.zeroize();
            return Err(AttestationError::RandomUnavailable(error.to_string()));
        }
        let provider = Self::from_secret_bytes(&secret);
        secret.zeroize();
        Ok(provider)
    }

    /// Returns the secret seed for a protected local key-store adapter.
    ///
    /// This value must never enter domain/application results, content, logs,
    /// `ContextPacks`, or Proof payloads.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl ProofSigningProvider for Ed25519SigningProvider {
    fn metadata(&self) -> Result<SigningKeyMetadata, SigningProviderError> {
        Ok(SigningKeyMetadata {
            key_id: self.key_id.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: self.signing_key.verifying_key().to_bytes().to_vec(),
        })
    }

    fn sign_pae(&self, pae: &[u8]) -> Result<Vec<u8>, SigningProviderError> {
        Ok(self.signing_key.sign(pae).to_bytes().to_vec())
    }
}

/// One digest-addressed in-toto subject.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoSubject {
    /// Stable subject name.
    pub name: String,
    /// Explicit algorithm-to-lowercase-hex digest map.
    pub digest: BTreeMap<String, String>,
}

/// Strict in-toto Statement v1 carrying a Proof Release predicate.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InTotoStatement {
    /// Exact in-toto Statement type.
    #[serde(rename = "_type")]
    pub statement_type: String,
    /// Non-empty immutable subjects.
    pub subject: Vec<InTotoSubject>,
    /// Exact Proof Release predicate type.
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    /// Versioned Proof-specific operational evidence.
    pub predicate: Value,
}

impl InTotoStatement {
    /// Constructs the required v1 types around supplied subjects and predicate.
    #[must_use]
    pub fn release(subject: Vec<InTotoSubject>, predicate: Value) -> Self {
        Self {
            statement_type: IN_TOTO_STATEMENT_TYPE.to_owned(),
            subject,
            predicate_type: RELEASE_PREDICATE_TYPE.to_owned(),
            predicate,
        }
    }
}

/// One DSSE signature entry.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseSignature {
    /// Explicit key identifier.
    pub keyid: String,
    /// Standard-base64 encoded signature bytes.
    pub sig: String,
}

/// Strict single-signature DSSE envelope.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DsseEnvelope {
    /// Exact payload media type.
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Standard-base64 encoded exact Statement payload bytes.
    pub payload: String,
    /// Exactly one Ed25519 signature in v1.
    pub signatures: Vec<DsseSignature>,
}

/// Complete result of producing one canonical signed Proof envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedReleaseEnvelope {
    /// Structured envelope.
    pub envelope: DsseEnvelope,
    /// Exact RFC 8785 canonical envelope JSON.
    pub envelope_json: String,
    /// Domain-separated digest of the canonical envelope.
    pub envelope_digest: ContentDigest,
    /// Exact RFC 8785 canonical Statement payload JSON.
    pub payload_json: String,
    /// Explicit signing key identifier.
    pub key_id: String,
}

/// Strictly parsed envelope and Statement before trust evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReleaseEnvelope {
    /// Structured DSSE envelope.
    pub envelope: DsseEnvelope,
    /// Parsed typed Statement.
    pub statement: InTotoStatement,
    /// Exact canonical envelope JSON.
    pub envelope_json: String,
    /// Exact canonical payload bytes as UTF-8 JSON.
    pub payload_json: String,
    /// Domain-separated canonical envelope digest.
    pub envelope_digest: ContentDigest,
    /// Decoded exact signature bytes.
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

/// Cryptographically verified envelope plus the complete parsed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedReleaseEnvelope {
    /// Complete strict parsed representation.
    pub parsed: ParsedReleaseEnvelope,
    /// Expected/trusted key identifier used for this verification.
    pub key_id: String,
    /// Public key extracted from and matched to the expected key identifier.
    pub public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
}

/// Produces DSSE pre-authentication encoding using raw byte lengths.
///
/// # Errors
///
/// Returns [`AttestationError::UnsupportedPayloadType`] for a payload type
/// outside the Proof Release profile, or [`AttestationError::PayloadTooLarge`]
/// when the payload exceeds the bounded profile.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if payload_type != DSSE_PAYLOAD_TYPE {
        return Err(AttestationError::UnsupportedPayloadType);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AttestationError::PayloadTooLarge);
    }
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(prefix.len() + payload.len());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(payload);
    Ok(pae)
}

/// Returns the ratified self-describing local Ed25519 key identifier.
#[must_use]
pub fn ed25519_key_id(public_key: &[u8; ED25519_PUBLIC_KEY_BYTES]) -> String {
    let mut key_id = String::with_capacity(9 + ED25519_PUBLIC_KEY_BYTES * 2);
    key_id.push_str("ed25519:");
    for byte in public_key {
        use std::fmt::Write as _;
        let _ = write!(key_id, "{byte:02x}");
    }
    key_id
}

/// Parses and validates the ratified local Ed25519 key identifier.
///
/// # Errors
///
/// Returns [`AttestationError::InvalidKeyId`] unless the value is exactly
/// `ed25519:` followed by 64 lowercase hexadecimal characters.
pub fn parse_ed25519_key_id(
    value: &str,
) -> Result<[u8; ED25519_PUBLIC_KEY_BYTES], AttestationError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or(AttestationError::InvalidKeyId)?;
    if encoded.len() != ED25519_PUBLIC_KEY_BYTES * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AttestationError::InvalidKeyId);
    }
    let mut bytes = [0_u8; ED25519_PUBLIC_KEY_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .map_err(|_| AttestationError::InvalidKeyId)?;
    }
    Ok(bytes)
}

/// Canonicalizes, PAE-signs, and envelopes one typed Release Statement.
///
/// # Errors
///
/// Returns [`AttestationError`] unless the Statement, provider metadata,
/// signature, and resulting envelope satisfy the complete v1 profile.
pub fn sign_release_statement(
    statement: &InTotoStatement,
    signer: &dyn ProofSigningProvider,
) -> Result<SignedReleaseEnvelope, AttestationError> {
    validate_statement(statement)?;
    let payload_value = serde_json::to_value(statement)
        .map_err(|error| AttestationError::InvalidStatement(error.to_string()))?;
    let payload = canonicalize(&payload_value)
        .map_err(|error| AttestationError::InvalidStatement(error.to_string()))?;
    if payload.as_str().len() > MAX_PAYLOAD_BYTES {
        return Err(AttestationError::PayloadTooLarge);
    }
    let metadata = signer
        .metadata()
        .map_err(|error| AttestationError::Signing(error.to_string()))?;
    validate_signing_metadata(&metadata)?;
    let pae = dsse_pae(DSSE_PAYLOAD_TYPE, payload.as_str().as_bytes())?;
    let signature = signer
        .sign_pae(&pae)
        .map_err(|error| AttestationError::Signing(error.to_string()))?;
    if signature.len() != ED25519_SIGNATURE_BYTES {
        return Err(AttestationError::InvalidSignatureLength);
    }
    verify_signature(&metadata.public_key, &signature, &pae)?;

    let envelope = DsseEnvelope {
        payload_type: DSSE_PAYLOAD_TYPE.to_owned(),
        payload: BASE64.encode(payload.as_str().as_bytes()),
        signatures: vec![DsseSignature {
            keyid: metadata.key_id.clone(),
            sig: BASE64.encode(signature),
        }],
    };
    let envelope_value = serde_json::to_value(&envelope)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    let canonical_envelope = canonicalize(&envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if canonical_envelope.as_str().len() > MAX_ENVELOPE_BYTES {
        return Err(AttestationError::EnvelopeTooLarge);
    }
    Ok(SignedReleaseEnvelope {
        envelope,
        envelope_digest: digest(ArtifactKind::ProofEnvelopeV1, &canonical_envelope),
        envelope_json: canonical_envelope.as_str().to_owned(),
        payload_json: payload.as_str().to_owned(),
        key_id: metadata.key_id,
    })
}

/// Strictly parses and validates one canonical Proof Release envelope.
///
/// This does not evaluate trust or verify the Ed25519 signature.
///
/// # Errors
///
/// Returns [`AttestationError`] on any bound, canonicalization, type, Schema,
/// base64, signature-length, or Statement-profile violation.
pub fn parse_release_envelope(input: &[u8]) -> Result<ParsedReleaseEnvelope, AttestationError> {
    if input.len() > MAX_ENVELOPE_BYTES {
        return Err(AttestationError::EnvelopeTooLarge);
    }
    let envelope_value = parse_strict(input)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    let canonical_envelope = canonicalize(&envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if canonical_envelope.as_str().as_bytes() != input {
        return Err(AttestationError::NonCanonicalEnvelope);
    }
    let envelope: DsseEnvelope = serde_json::from_value(envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if envelope.payload_type != DSSE_PAYLOAD_TYPE {
        return Err(AttestationError::UnsupportedPayloadType);
    }
    let [signature_entry] = envelope.signatures.as_slice() else {
        return Err(AttestationError::InvalidSignatureCount);
    };
    parse_ed25519_key_id(&signature_entry.keyid)?;

    let payload = BASE64
        .decode(&envelope.payload)
        .map_err(|_| AttestationError::InvalidBase64)?;
    if BASE64.encode(&payload) != envelope.payload {
        return Err(AttestationError::InvalidBase64);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(AttestationError::PayloadTooLarge);
    }
    let payload_value = parse_strict(&payload)
        .map_err(|error| AttestationError::InvalidStatement(error.to_string()))?;
    let canonical_payload = canonicalize(&payload_value)
        .map_err(|error| AttestationError::InvalidStatement(error.to_string()))?;
    if canonical_payload.as_str().as_bytes() != payload {
        return Err(AttestationError::NonCanonicalPayload);
    }
    let statement: InTotoStatement = serde_json::from_value(payload_value)
        .map_err(|error| AttestationError::InvalidStatement(error.to_string()))?;
    validate_statement(&statement)?;

    let signature = BASE64
        .decode(&signature_entry.sig)
        .map_err(|_| AttestationError::InvalidBase64)?;
    if BASE64.encode(&signature) != signature_entry.sig {
        return Err(AttestationError::InvalidBase64);
    }
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| AttestationError::InvalidSignatureLength)?;
    let envelope_digest = digest(ArtifactKind::ProofEnvelopeV1, &canonical_envelope);
    Ok(ParsedReleaseEnvelope {
        envelope,
        statement,
        envelope_json: canonical_envelope.as_str().to_owned(),
        payload_json: canonical_payload.as_str().to_owned(),
        envelope_digest,
        signature,
    })
}

/// Verifies envelope digest, trusted key identity, DSSE PAE, and Ed25519 signature.
///
/// The expected key ID is supplied by trust policy. Although the key ID embeds
/// public bytes for portability, the envelope's self-description never grants
/// trust by itself.
///
/// # Errors
///
/// Returns [`AttestationError`] unless every structural and cryptographic check
/// succeeds against the caller-supplied expected digest and key ID.
pub fn verify_release_envelope(
    input: &[u8],
    expected_envelope_digest: ContentDigest,
    expected_key_id: &str,
) -> Result<VerifiedReleaseEnvelope, AttestationError> {
    let parsed = parse_release_envelope(input)?;
    if parsed.envelope_digest != expected_envelope_digest {
        return Err(AttestationError::EnvelopeDigestMismatch);
    }
    let [signature_entry] = parsed.envelope.signatures.as_slice() else {
        return Err(AttestationError::InvalidSignatureCount);
    };
    if signature_entry.keyid != expected_key_id {
        return Err(AttestationError::KeyIdMismatch);
    }
    let public_key = parse_ed25519_key_id(expected_key_id)?;
    let pae = dsse_pae(
        &parsed.envelope.payload_type,
        parsed.payload_json.as_bytes(),
    )?;
    verify_signature(&public_key, &parsed.signature, &pae)?;
    Ok(VerifiedReleaseEnvelope {
        parsed,
        key_id: expected_key_id.to_owned(),
        public_key,
    })
}

fn validate_signing_metadata(metadata: &SigningKeyMetadata) -> Result<(), AttestationError> {
    if metadata.algorithm != SignatureAlgorithm::Ed25519 {
        return Err(AttestationError::UnsupportedSignatureAlgorithm);
    }
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = metadata
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::InvalidPublicKeyLength)?;
    if metadata.key_id != ed25519_key_id(&public_key) {
        return Err(AttestationError::InvalidKeyId);
    }
    VerifyingKey::from_bytes(&public_key).map_err(|_| AttestationError::InvalidPublicKey)?;
    Ok(())
}

fn validate_statement(statement: &InTotoStatement) -> Result<(), AttestationError> {
    if statement.statement_type != IN_TOTO_STATEMENT_TYPE {
        return Err(AttestationError::UnsupportedStatementType);
    }
    if statement.predicate_type != RELEASE_PREDICATE_TYPE {
        return Err(AttestationError::UnsupportedPredicateType);
    }
    if statement.subject.is_empty() || statement.subject.len() > MAX_SUBJECTS {
        return Err(AttestationError::InvalidSubjects);
    }
    for subject in &statement.subject {
        if subject.name.is_empty()
            || subject.name.len() > MAX_SUBJECT_NAME_BYTES
            || subject.digest.is_empty()
            || subject.digest.len() > 8
        {
            return Err(AttestationError::InvalidSubjects);
        }
        for (algorithm, encoded) in &subject.digest {
            if algorithm.is_empty()
                || algorithm.len() > 64
                || !algorithm.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
                || encoded.is_empty()
                || encoded.len() > 256
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(AttestationError::InvalidSubjects);
            }
        }
    }
    if !statement.predicate.is_object() {
        return Err(AttestationError::InvalidPredicate);
    }
    Ok(())
}

fn verify_signature(
    public_key: &[u8],
    signature: &[u8],
    pae: &[u8],
) -> Result<(), AttestationError> {
    let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = public_key
        .try_into()
        .map_err(|_| AttestationError::InvalidPublicKeyLength)?;
    let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
        .try_into()
        .map_err(|_| AttestationError::InvalidSignatureLength)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AttestationError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&signature);
    verifying_key
        .verify_strict(pae, &signature)
        .map_err(|_| AttestationError::SignatureInvalid)
}

/// Strict envelope, Statement, key, and cryptographic failure taxonomy.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AttestationError {
    /// Complete envelope exceeds the bounded profile.
    #[error("the DSSE envelope exceeds the maximum byte length")]
    EnvelopeTooLarge,
    /// Decoded Statement payload exceeds the bounded profile.
    #[error("the DSSE payload exceeds the maximum byte length")]
    PayloadTooLarge,
    /// Envelope JSON is malformed or violates the strict Schema.
    #[error("the DSSE envelope is invalid: {0}")]
    InvalidEnvelope(String),
    /// Proof envelopes must use RFC 8785 canonical JSON bytes.
    #[error("the DSSE envelope is not canonical JSON")]
    NonCanonicalEnvelope,
    /// Payload type does not identify an in-toto JSON Statement.
    #[error("the DSSE payload type is unsupported")]
    UnsupportedPayloadType,
    /// The v1 profile requires exactly one signature.
    #[error("the DSSE envelope must contain exactly one signature")]
    InvalidSignatureCount,
    /// Base64 payload or signature data is malformed.
    #[error("the DSSE envelope contains invalid base64")]
    InvalidBase64,
    /// Statement payload must be exact RFC 8785 canonical JSON bytes.
    #[error("the in-toto Statement payload is not canonical JSON")]
    NonCanonicalPayload,
    /// Typed Statement JSON is malformed or unsupported.
    #[error("the in-toto Statement is invalid: {0}")]
    InvalidStatement(String),
    /// Statement `_type` is not in-toto Statement v1.
    #[error("the in-toto Statement type is unsupported")]
    UnsupportedStatementType,
    /// Statement `predicateType` is not the Proof Release v1 predicate.
    #[error("the Proof predicate type is unsupported")]
    UnsupportedPredicateType,
    /// Subject count, name, algorithms, or digests violate the bounded profile.
    #[error("the in-toto Statement subjects are invalid")]
    InvalidSubjects,
    /// Release predicate must be a JSON object.
    #[error("the Proof Release predicate is invalid")]
    InvalidPredicate,
    /// Key identifier is not the ratified self-describing Ed25519 form.
    #[error("the Ed25519 key identifier is invalid")]
    InvalidKeyId,
    /// Caller-selected trust key differs from the envelope signature key.
    #[error("the DSSE signature key identifier does not match the expected trusted key")]
    KeyIdMismatch,
    /// Public key is not exactly 32 bytes.
    #[error("the Ed25519 public key must contain exactly 32 bytes")]
    InvalidPublicKeyLength,
    /// Public bytes do not encode an Ed25519 verification key.
    #[error("the Ed25519 public key is invalid")]
    InvalidPublicKey,
    /// Signature is not exactly 64 bytes.
    #[error("the Ed25519 signature must contain exactly 64 bytes")]
    InvalidSignatureLength,
    /// Provider reported an unsupported signature algorithm.
    #[error("the signature algorithm is unsupported")]
    UnsupportedSignatureAlgorithm,
    /// Ed25519 verification failed over exact DSSE PAE bytes.
    #[error("the Ed25519 signature is invalid")]
    SignatureInvalid,
    /// Persisted expected digest differs from canonical envelope bytes.
    #[error("the Proof envelope digest does not match")]
    EnvelopeDigestMismatch,
    /// Signing provider failed without returning a valid signature.
    #[error("Proof signing failed: {0}")]
    Signing(String),
    /// Operating-system randomness failed during local key generation.
    #[error("operating-system random generation is unavailable: {0}")]
    RandomUnavailable(String),
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use proof_domain::{ArtifactKind, ContentDigest};
    use serde_json::json;

    use super::{
        AttestationError, DSSE_PAYLOAD_TYPE, Ed25519SigningProvider, InTotoStatement,
        InTotoSubject, dsse_pae, parse_ed25519_key_id, parse_release_envelope,
        sign_release_statement, verify_release_envelope,
    };

    fn statement() -> InTotoStatement {
        InTotoStatement::release(
            vec![InTotoSubject {
                name: "urn:proof:release:019c0000-0000-7000-8000-000000000001".to_owned(),
                digest: BTreeMap::from([("blake3".to_owned(), "ab".repeat(32))]),
            }],
            json!({
                "implementation": {"predicate_version": "1"},
                "release": {"release_id": "019c0000-0000-7000-8000-000000000001"}
            }),
        )
    }

    #[test]
    fn pae_uses_raw_byte_lengths() {
        assert_eq!(
            dsse_pae(DSSE_PAYLOAD_TYPE, b"abc").unwrap(),
            b"DSSEv1 28 application/vnd.in-toto+json 3 abc"
        );
    }

    #[test]
    fn canonical_statement_round_trips_through_signed_envelope() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[7_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let verified = verify_release_envelope(
            signed.envelope_json.as_bytes(),
            signed.envelope_digest,
            &signed.key_id,
        )
        .unwrap();

        assert_eq!(verified.parsed.statement, statement());
        assert_eq!(verified.parsed.envelope_digest, signed.envelope_digest);
        assert_eq!(verified.key_id, signed.key_id);
        assert_eq!(
            parse_release_envelope(signed.envelope_json.as_bytes())
                .unwrap()
                .payload_json,
            signed.payload_json
        );
    }

    #[test]
    fn verification_rejects_a_different_expected_digest() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[9_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();

        assert_eq!(
            verify_release_envelope(
                signed.envelope_json.as_bytes(),
                ContentDigest::blake3([0_u8; 32]),
                &signed.key_id,
            )
            .unwrap_err(),
            AttestationError::EnvelopeDigestMismatch
        );
    }

    #[test]
    fn verification_rejects_an_untrusted_key_id() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[11_u8; 32]);
        let other = Ed25519SigningProvider::from_secret_bytes(&[12_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let other_signed = sign_release_statement(&statement(), &other).unwrap();

        assert_eq!(
            verify_release_envelope(
                signed.envelope_json.as_bytes(),
                signed.envelope_digest,
                &other_signed.key_id,
            )
            .unwrap_err(),
            AttestationError::KeyIdMismatch
        );
    }

    #[test]
    fn parser_rejects_noncanonical_envelope_bytes() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[13_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let formatted = serde_json::to_string_pretty(&signed.envelope).unwrap();

        assert_eq!(
            parse_release_envelope(formatted.as_bytes()).unwrap_err(),
            AttestationError::NonCanonicalEnvelope
        );
    }

    #[test]
    fn verification_rejects_one_byte_signature_tamper() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[14_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let mut envelope = signed.envelope;
        let mut signature = BASE64.decode(&envelope.signatures[0].sig).unwrap();
        signature[0] ^= 1;
        envelope.signatures[0].sig = BASE64.encode(signature);
        let canonical =
            proof_canonical::canonicalize(&serde_json::to_value(&envelope).unwrap()).unwrap();
        let envelope_digest = proof_canonical::digest(ArtifactKind::ProofEnvelopeV1, &canonical);

        assert_eq!(
            verify_release_envelope(
                canonical.as_str().as_bytes(),
                envelope_digest,
                &signed.key_id
            )
            .unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }

    #[test]
    fn verification_rejects_one_byte_payload_tamper() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[15_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let mut envelope = signed.envelope;
        let payload = BASE64.decode(&envelope.payload).unwrap();
        let payload = String::from_utf8(payload)
            .unwrap()
            .replace("\"predicate_version\":\"1\"", "\"predicate_version\":\"2\"");
        envelope.payload = BASE64.encode(payload.as_bytes());
        let canonical =
            proof_canonical::canonicalize(&serde_json::to_value(&envelope).unwrap()).unwrap();
        let envelope_digest = proof_canonical::digest(ArtifactKind::ProofEnvelopeV1, &canonical);

        assert_eq!(
            verify_release_envelope(
                canonical.as_str().as_bytes(),
                envelope_digest,
                &signed.key_id
            )
            .unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }

    #[test]
    fn wrong_dsse_and_statement_types_are_rejected() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[16_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let mut envelope = signed.envelope;
        envelope.payload_type = "application/json".to_owned();
        let canonical =
            proof_canonical::canonicalize(&serde_json::to_value(&envelope).unwrap()).unwrap();
        assert_eq!(
            parse_release_envelope(canonical.as_str().as_bytes()).unwrap_err(),
            AttestationError::UnsupportedPayloadType
        );

        let mut wrong_statement = statement();
        wrong_statement.statement_type = "https://in-toto.io/Statement/v0.1".to_owned();
        assert_eq!(
            sign_release_statement(&wrong_statement, &signer).unwrap_err(),
            AttestationError::UnsupportedStatementType
        );
        let mut wrong_predicate = statement();
        wrong_predicate.predicate_type = "urn:proof:attestation:release:v2".to_owned();
        assert_eq!(
            sign_release_statement(&wrong_predicate, &signer).unwrap_err(),
            AttestationError::UnsupportedPredicateType
        );
    }

    #[test]
    fn local_key_id_parser_rejects_uppercase_and_wrong_length() {
        assert_eq!(
            parse_ed25519_key_id(&format!("ed25519:{}", "AB".repeat(32))).unwrap_err(),
            AttestationError::InvalidKeyId
        );
        assert_eq!(
            parse_ed25519_key_id("ed25519:00").unwrap_err(),
            AttestationError::InvalidKeyId
        );
    }

    #[test]
    fn proof_envelope_uses_its_own_digest_domain() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[17_u8; 32]);
        let signed = sign_release_statement(&statement(), &signer).unwrap();
        let canonical =
            proof_canonical::parse_and_canonicalize(signed.envelope_json.as_bytes()).unwrap();

        assert_eq!(
            signed.envelope_digest,
            proof_canonical::digest(ArtifactKind::ProofEnvelopeV1, &canonical)
        );
    }
}
