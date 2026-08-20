//! Bounded generic DSSE production and verification for authority artifacts.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_domain::{ArtifactKind, ContentDigest};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    AttestationError, DsseEnvelope, DsseSignature, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SIGNATURE_BYTES, ProofSigningProvider, dsse_pae_bounded, parse_ed25519_key_id,
    validate_signing_metadata, verify_signature,
};

/// Exact DSSE payload type for `AuthenticatedCommandV1`.
pub const AUTHENTICATED_COMMAND_PAYLOAD_TYPE: &str =
    "application/vnd.proof.authenticated-command.v1+json";
/// Exact DSSE payload type for `BindingEnrollmentChallengeV1`.
pub const BINDING_ENROLLMENT_CHALLENGE_PAYLOAD_TYPE: &str =
    "application/vnd.proof.binding-enrollment-challenge.v1+json";
/// Exact DSSE payload type for an ordinary `AuthorityRecordV1`.
pub const AUTHORITY_RECORD_PAYLOAD_TYPE: &str = "application/vnd.proof.authority-record.v1+json";
/// Exact DSSE payload type for `WorkspaceAuthorityRootTransitionV1`.
pub const WORKSPACE_AUTHORITY_ROOT_TRANSITION_PAYLOAD_TYPE: &str =
    "application/vnd.proof.workspace-authority-root-transition.v1+json";

/// Maximum canonical command or enrollment payload length.
pub const MAX_AUTHENTICATION_PAYLOAD_BYTES: usize = 4_096;
/// Maximum complete canonical command or enrollment envelope length.
pub const MAX_AUTHENTICATION_ENVELOPE_BYTES: usize = 16_384;
/// Maximum canonical ordinary-record or root-transition payload length.
pub const MAX_AUTHORITY_PAYLOAD_BYTES: usize = 65_536;
/// Maximum complete canonical ordinary-record or root-transition envelope length.
pub const MAX_AUTHORITY_ENVELOPE_BYTES: usize = 98_304;

/// One of the four exact P-0003 authority DSSE profiles.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorityPayloadProfile {
    /// One Agent-authenticated command presentation.
    AuthenticatedCommand,
    /// One candidate-key proof-of-possession challenge.
    BindingEnrollmentChallenge,
    /// One ordinary authority-log record.
    AuthorityRecord,
    /// One predecessor-and-successor signed authority-root transition.
    WorkspaceAuthorityRootTransition,
}

impl AuthorityPayloadProfile {
    /// Returns the profile's exact DSSE payload media type.
    #[must_use]
    pub const fn payload_type(self) -> &'static str {
        match self {
            Self::AuthenticatedCommand => AUTHENTICATED_COMMAND_PAYLOAD_TYPE,
            Self::BindingEnrollmentChallenge => BINDING_ENROLLMENT_CHALLENGE_PAYLOAD_TYPE,
            Self::AuthorityRecord => AUTHORITY_RECORD_PAYLOAD_TYPE,
            Self::WorkspaceAuthorityRootTransition => {
                WORKSPACE_AUTHORITY_ROOT_TRANSITION_PAYLOAD_TYPE
            }
        }
    }

    /// Returns the profile's maximum canonical payload length.
    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            Self::AuthenticatedCommand | Self::BindingEnrollmentChallenge => {
                MAX_AUTHENTICATION_PAYLOAD_BYTES
            }
            Self::AuthorityRecord | Self::WorkspaceAuthorityRootTransition => {
                MAX_AUTHORITY_PAYLOAD_BYTES
            }
        }
    }

    /// Returns the profile's maximum complete canonical envelope length.
    #[must_use]
    pub const fn max_envelope_bytes(self) -> usize {
        match self {
            Self::AuthenticatedCommand | Self::BindingEnrollmentChallenge => {
                MAX_AUTHENTICATION_ENVELOPE_BYTES
            }
            Self::AuthorityRecord | Self::WorkspaceAuthorityRootTransition => {
                MAX_AUTHORITY_ENVELOPE_BYTES
            }
        }
    }

    /// Returns the exact ordered signature count for this profile.
    #[must_use]
    pub const fn signature_count(self) -> usize {
        match self {
            Self::AuthenticatedCommand
            | Self::BindingEnrollmentChallenge
            | Self::AuthorityRecord => 1,
            Self::WorkspaceAuthorityRootTransition => 2,
        }
    }

    /// Returns the artifact domain for the complete canonical envelope.
    #[must_use]
    pub const fn envelope_artifact_kind(self) -> ArtifactKind {
        match self {
            Self::AuthenticatedCommand => ArtifactKind::AuthenticatedCommandEnvelopeV1,
            Self::BindingEnrollmentChallenge => ArtifactKind::BindingEnrollmentEnvelopeV1,
            Self::AuthorityRecord | Self::WorkspaceAuthorityRootTransition => {
                ArtifactKind::AuthorityRecordEnvelopeV1
            }
        }
    }
}

/// Exact decoded signature material retained from a parsed authority envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedAuthoritySignature {
    /// Unsigned key identifier carried by the envelope.
    pub key_id: String,
    /// Exact decoded Ed25519 signature bytes.
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

/// A signer proven against an independently resolved expected key identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthoritySigner {
    /// Independently resolved expected key identifier.
    pub key_id: String,
    /// Public key encoded by and checked against the expected key identifier.
    pub public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    /// Exact signature bytes verified over the DSSE PAE.
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

/// Complete result of signing one typed authority payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAuthorityEnvelope {
    /// Exact bounded authority profile used to produce the envelope.
    pub profile: AuthorityPayloadProfile,
    /// Structured DSSE envelope.
    pub envelope: DsseEnvelope,
    /// Exact RFC 8785 canonical envelope JSON.
    pub envelope_json: String,
    /// Domain-separated digest of the canonical envelope.
    pub envelope_digest: ContentDigest,
    /// Exact RFC 8785 canonical typed payload JSON.
    pub payload_json: String,
    /// Ordered signer identities, public keys, and exact signatures.
    pub signers: Vec<VerifiedAuthoritySigner>,
}

/// Strictly parsed typed authority envelope before trust evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedAuthorityEnvelope<T> {
    /// Exact bounded authority profile required by the caller.
    pub profile: AuthorityPayloadProfile,
    /// Structured DSSE envelope.
    pub envelope: DsseEnvelope,
    /// Strictly deserialized typed payload.
    pub payload: T,
    /// Exact RFC 8785 canonical envelope JSON.
    pub envelope_json: String,
    /// Domain-separated digest of the canonical envelope.
    pub envelope_digest: ContentDigest,
    /// Exact RFC 8785 canonical typed payload JSON.
    pub payload_json: String,
    /// Ordered unsigned key hints and exact decoded signatures.
    pub signatures: Vec<ParsedAuthoritySignature>,
}

/// Cryptographically verified authority envelope plus parsed evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthorityEnvelope<T> {
    /// Complete strict parsed representation.
    pub parsed: ParsedAuthorityEnvelope<T>,
    /// Ordered independently resolved keys and verified signatures.
    pub verified_signers: Vec<VerifiedAuthoritySigner>,
}

/// Produces DSSE pre-authentication encoding for one exact authority profile.
///
/// # Errors
///
/// Returns [`AttestationError::PayloadTooLarge`] when `payload` exceeds the
/// selected profile's canonical payload bound.
pub fn authority_dsse_pae(
    profile: AuthorityPayloadProfile,
    payload: &[u8],
) -> Result<Vec<u8>, AttestationError> {
    dsse_pae_bounded(profile.payload_type(), payload, profile.max_payload_bytes())
}

/// Canonicalizes, PAE-signs, and envelopes one typed authority payload.
///
/// `signers` is ordered. The command, enrollment, and ordinary-record profiles
/// require exactly one signer. A root transition requires exactly two distinct
/// signers in predecessor-then-successor order.
///
/// # Errors
///
/// Returns [`AttestationError`] unless the typed payload, provider metadata,
/// signature cardinality, signatures, and resulting envelope satisfy the
/// selected P-0003 profile.
pub fn sign_authority_payload<T: Serialize>(
    profile: AuthorityPayloadProfile,
    payload: &T,
    signers: &[&dyn ProofSigningProvider],
) -> Result<SignedAuthorityEnvelope, AttestationError> {
    if signers.len() != profile.signature_count() {
        return Err(AttestationError::InvalidAuthoritySignatureCount);
    }

    let payload_value = serde_json::to_value(payload)
        .map_err(|error| AttestationError::InvalidAuthorityPayload(error.to_string()))?;
    if !payload_value.is_object() {
        return Err(AttestationError::InvalidAuthorityPayload(
            "the typed payload must be a JSON object".to_owned(),
        ));
    }
    let canonical_payload = canonicalize(&payload_value)
        .map_err(|error| AttestationError::InvalidAuthorityPayload(error.to_string()))?;
    let pae = authority_dsse_pae(profile, canonical_payload.as_bytes())?;

    let mut signer_metadata = Vec::with_capacity(signers.len());
    for signer in signers {
        let metadata = signer
            .metadata()
            .map_err(|error| AttestationError::Signing(error.to_string()))?;
        validate_signing_metadata(&metadata)?;
        signer_metadata.push(metadata);
    }
    validate_distinct_root_key_ids(
        profile,
        signer_metadata.iter().map(|item| item.key_id.as_str()),
    )?;

    let mut envelope_signatures = Vec::with_capacity(signers.len());
    let mut verified_signers = Vec::with_capacity(signers.len());
    for (signer, metadata) in signers.iter().zip(&signer_metadata) {
        let signature = signer
            .sign_pae(&pae)
            .map_err(|error| AttestationError::Signing(error.to_string()))?;
        let signature: [u8; ED25519_SIGNATURE_BYTES] = signature
            .try_into()
            .map_err(|_| AttestationError::InvalidSignatureLength)?;
        verify_signature(&metadata.public_key, &signature, &pae)?;
        let public_key: [u8; ED25519_PUBLIC_KEY_BYTES] = metadata
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidPublicKeyLength)?;
        envelope_signatures.push(DsseSignature {
            keyid: metadata.key_id.clone(),
            sig: BASE64.encode(signature),
        });
        verified_signers.push(VerifiedAuthoritySigner {
            key_id: metadata.key_id.clone(),
            public_key,
            signature,
        });
    }
    validate_distinct_root_signatures(
        profile,
        verified_signers.iter().map(|item| &item.signature),
    )?;

    let envelope = DsseEnvelope {
        payload_type: profile.payload_type().to_owned(),
        payload: BASE64.encode(canonical_payload.as_bytes()),
        signatures: envelope_signatures,
    };
    let envelope_value = serde_json::to_value(&envelope)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    let canonical_envelope = canonicalize(&envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if canonical_envelope.as_bytes().len() > profile.max_envelope_bytes() {
        return Err(AttestationError::EnvelopeTooLarge);
    }
    let envelope_digest = digest(profile.envelope_artifact_kind(), &canonical_envelope);

    Ok(SignedAuthorityEnvelope {
        profile,
        envelope,
        envelope_json: canonical_envelope.as_str().to_owned(),
        envelope_digest,
        payload_json: canonical_payload.as_str().to_owned(),
        signers: verified_signers,
    })
}

/// Strictly parses one canonical typed authority envelope.
///
/// This validates exact media type, signature cardinality and distinctness,
/// bounds, canonical JSON, canonical standard base64, and the caller-selected
/// payload type. It does not establish trust or verify signatures.
///
/// # Errors
///
/// Returns [`AttestationError`] on any bound, canonicalization, media-type,
/// base64, signature-profile, or typed-payload violation.
pub fn parse_authority_envelope<T: DeserializeOwned>(
    input: &[u8],
    profile: AuthorityPayloadProfile,
) -> Result<ParsedAuthorityEnvelope<T>, AttestationError> {
    if input.len() > profile.max_envelope_bytes() {
        return Err(AttestationError::EnvelopeTooLarge);
    }
    let envelope_value = parse_strict(input)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    let canonical_envelope = canonicalize(&envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if canonical_envelope.as_bytes() != input {
        return Err(AttestationError::NonCanonicalEnvelope);
    }
    let envelope: DsseEnvelope = serde_json::from_value(envelope_value)
        .map_err(|error| AttestationError::InvalidEnvelope(error.to_string()))?;
    if envelope.payload_type != profile.payload_type() {
        return Err(AttestationError::UnsupportedPayloadType);
    }
    if envelope.signatures.len() != profile.signature_count() {
        return Err(AttestationError::InvalidAuthoritySignatureCount);
    }

    let payload_bytes = decode_canonical_base64(&envelope.payload)?;
    if payload_bytes.len() > profile.max_payload_bytes() {
        return Err(AttestationError::PayloadTooLarge);
    }
    let payload_value = parse_strict(&payload_bytes)
        .map_err(|error| AttestationError::InvalidAuthorityPayload(error.to_string()))?;
    if !payload_value.is_object() {
        return Err(AttestationError::InvalidAuthorityPayload(
            "the typed payload must be a JSON object".to_owned(),
        ));
    }
    let canonical_payload = canonicalize(&payload_value)
        .map_err(|error| AttestationError::InvalidAuthorityPayload(error.to_string()))?;
    if canonical_payload.as_bytes() != payload_bytes {
        return Err(AttestationError::NonCanonicalPayload);
    }
    let payload = serde_json::from_value(payload_value)
        .map_err(|error| AttestationError::InvalidAuthorityPayload(error.to_string()))?;

    let mut signatures = Vec::with_capacity(envelope.signatures.len());
    for entry in &envelope.signatures {
        parse_ed25519_key_id(&entry.keyid)?;
        let signature: [u8; ED25519_SIGNATURE_BYTES] = decode_canonical_base64(&entry.sig)?
            .try_into()
            .map_err(|_| AttestationError::InvalidSignatureLength)?;
        signatures.push(ParsedAuthoritySignature {
            key_id: entry.keyid.clone(),
            signature,
        });
    }
    validate_distinct_root_key_ids(profile, signatures.iter().map(|item| item.key_id.as_str()))?;
    validate_distinct_root_signatures(profile, signatures.iter().map(|item| &item.signature))?;

    let envelope_digest = digest(profile.envelope_artifact_kind(), &canonical_envelope);
    Ok(ParsedAuthorityEnvelope {
        profile,
        envelope,
        payload,
        envelope_json: canonical_envelope.as_str().to_owned(),
        envelope_digest,
        payload_json: canonical_payload.as_str().to_owned(),
        signatures,
    })
}

/// Verifies one typed authority envelope against independently resolved keys.
///
/// `expected_key_ids` is ordered and must contain one identity for command,
/// enrollment, or ordinary records, or two distinct identities in predecessor-
/// then-successor order for a root transition. Each signature is verified with
/// the independently resolved expected key before the corresponding unsigned
/// envelope `keyid` is required to equal it.
///
/// # Errors
///
/// Returns [`AttestationError`] unless strict parsing, signature cardinality,
/// expected-key validity, Ed25519 verification, and post-verification key-ID
/// equality all succeed.
pub fn verify_authority_envelope<T: DeserializeOwned>(
    input: &[u8],
    profile: AuthorityPayloadProfile,
    expected_key_ids: &[&str],
) -> Result<VerifiedAuthorityEnvelope<T>, AttestationError> {
    if expected_key_ids.len() != profile.signature_count() {
        return Err(AttestationError::InvalidAuthoritySignatureCount);
    }
    validate_distinct_root_key_ids(profile, expected_key_ids.iter().copied())?;

    let parsed = parse_authority_envelope(input, profile)?;
    let pae = authority_dsse_pae(profile, parsed.payload_json.as_bytes())?;
    let mut verified_signers = Vec::with_capacity(expected_key_ids.len());
    for (expected_key_id, parsed_signature) in expected_key_ids.iter().zip(&parsed.signatures) {
        let public_key = parse_ed25519_key_id(expected_key_id)?;
        verify_signature(&public_key, &parsed_signature.signature, &pae)?;
        verified_signers.push(VerifiedAuthoritySigner {
            key_id: (*expected_key_id).to_owned(),
            public_key,
            signature: parsed_signature.signature,
        });
    }

    // `keyid` is unsigned and cannot select trust. Compare it only after every
    // signature has verified against the independently resolved ordered keys.
    for (parsed_signature, expected_key_id) in parsed.signatures.iter().zip(expected_key_ids) {
        if parsed_signature.key_id != *expected_key_id {
            return Err(AttestationError::KeyIdMismatch);
        }
    }

    Ok(VerifiedAuthorityEnvelope {
        parsed,
        verified_signers,
    })
}

fn decode_canonical_base64(input: &str) -> Result<Vec<u8>, AttestationError> {
    let decoded = BASE64
        .decode(input)
        .map_err(|_| AttestationError::InvalidBase64)?;
    if BASE64.encode(&decoded) != input {
        return Err(AttestationError::InvalidBase64);
    }
    Ok(decoded)
}

fn validate_distinct_root_key_ids<'a>(
    profile: AuthorityPayloadProfile,
    key_ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), AttestationError> {
    if profile != AuthorityPayloadProfile::WorkspaceAuthorityRootTransition {
        return Ok(());
    }
    let mut key_ids = key_ids.into_iter();
    let predecessor = key_ids
        .next()
        .ok_or(AttestationError::InvalidAuthoritySignatureCount)?;
    let successor = key_ids
        .next()
        .ok_or(AttestationError::InvalidAuthoritySignatureCount)?;
    if key_ids.next().is_some() {
        return Err(AttestationError::InvalidAuthoritySignatureCount);
    }
    if predecessor == successor {
        return Err(AttestationError::DuplicateAuthorityKeyId);
    }
    Ok(())
}

fn validate_distinct_root_signatures<'a>(
    profile: AuthorityPayloadProfile,
    signatures: impl IntoIterator<Item = &'a [u8; ED25519_SIGNATURE_BYTES]>,
) -> Result<(), AttestationError> {
    if profile != AuthorityPayloadProfile::WorkspaceAuthorityRootTransition {
        return Ok(());
    }
    let mut signatures = signatures.into_iter();
    let predecessor = signatures
        .next()
        .ok_or(AttestationError::InvalidAuthoritySignatureCount)?;
    let successor = signatures
        .next()
        .ok_or(AttestationError::InvalidAuthoritySignatureCount)?;
    if signatures.next().is_some() {
        return Err(AttestationError::InvalidAuthoritySignatureCount);
    }
    if predecessor == successor {
        return Err(AttestationError::DuplicateAuthoritySignature);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use proof_canonical::{canonicalize, digest, parse_strict};
    use proof_domain::ArtifactKind;
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::{
        AUTHENTICATED_COMMAND_PAYLOAD_TYPE, AUTHORITY_RECORD_PAYLOAD_TYPE, AuthorityPayloadProfile,
        BINDING_ENROLLMENT_CHALLENGE_PAYLOAD_TYPE, MAX_AUTHENTICATION_ENVELOPE_BYTES,
        MAX_AUTHENTICATION_PAYLOAD_BYTES, MAX_AUTHORITY_ENVELOPE_BYTES,
        MAX_AUTHORITY_PAYLOAD_BYTES, WORKSPACE_AUTHORITY_ROOT_TRANSITION_PAYLOAD_TYPE,
        authority_dsse_pae, parse_authority_envelope, sign_authority_payload,
        verify_authority_envelope,
    };
    use crate::{AttestationError, DsseEnvelope, Ed25519SigningProvider, ed25519_key_id};

    const COMMAND_MANIFEST: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/authenticated-command.dsse-bytes.valid.json"
    );
    const COMMAND_PAYLOAD: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/authenticated-command.payload.valid.json"
    );
    const COMMAND_ENVELOPE: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/authenticated-command.envelope.valid.json"
    );
    const ENROLLMENT_MANIFEST: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/binding-enrollment-challenge.dsse-bytes.valid.json"
    );
    const ENROLLMENT_PAYLOAD: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/binding-enrollment-challenge.payload.valid.json"
    );
    const ENROLLMENT_ENVELOPE: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/binding-enrollment-challenge.envelope.valid.json"
    );
    const AUTHORITY_MANIFEST: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/principal-binding-authority.dsse-bytes.valid.json"
    );
    const AUTHORITY_PAYLOAD: &[u8] =
        include_bytes!("../../../conformance/v1/authority/vectors/principal-binding.valid.json");
    const AUTHORITY_ENVELOPE: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/principal-binding.authority-envelope.valid.json"
    );
    const DECISION_PAYLOAD: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
    );
    const DECISION_ENVELOPE: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/authorization-decision-v2.authority-envelope.valid.json"
    );
    const ROOT_TRANSITION_MANIFEST: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/workspace-authority-root-transition.dsse-bytes.valid.json"
    );
    const ROOT_TRANSITION_PAYLOAD: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/workspace-authority-root-transition.payload.valid.json"
    );
    const ROOT_TRANSITION_ENVELOPE: &[u8] = include_bytes!(
        "../../../conformance/v1/authority/vectors/workspace-authority-root-transition.envelope.valid.json"
    );
    const AUTHORITY_CHAIN_FIXTURES: [(&[u8], u64); 9] = [
        (
            include_bytes!(
                "../../../conformance/v1/authority/vectors/principal-status-human-enabled.valid.json"
            ),
            1,
        ),
        (
            include_bytes!(
                "../../../conformance/v1/authority/vectors/principal-status-agent-enabled.valid.json"
            ),
            2,
        ),
        (AUTHORITY_PAYLOAD, 3),
        (
            include_bytes!("../../../conformance/v1/authority/vectors/delegation-v2.valid.json"),
            4,
        ),
        (DECISION_PAYLOAD, 5),
        (
            include_bytes!(
                "../../../conformance/v1/authority/vectors/principal-status-agent-disabled.valid.json"
            ),
            6,
        ),
        (
            include_bytes!(
                "../../../conformance/v1/authority/vectors/delegation-revocation.valid.json"
            ),
            7,
        ),
        (
            include_bytes!(
                "../../../conformance/v1/authority/vectors/principal-binding-revocation.valid.json"
            ),
            8,
        ),
        (ROOT_TRANSITION_PAYLOAD, 9),
    ];

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VectorManifest {
        api_version: String,
        status: String,
        payload_file: String,
        envelope_file: String,
        payload_type: String,
        payload_utf8_base64: String,
        pae_utf8_base64: String,
        envelope_digest: String,
        envelope_digest_context: String,
        signers: Vec<VectorSigner>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VectorSigner {
        key_id: String,
        public_key_hex: String,
        public_key_base64: String,
        signature_hex: String,
        signature_base64: String,
    }

    #[test]
    fn authenticated_command_vector_matches_exact_bytes() {
        assert_vector(
            COMMAND_MANIFEST,
            COMMAND_PAYLOAD,
            COMMAND_ENVELOPE,
            "authenticated-command.payload.valid.json",
            "authenticated-command.envelope.valid.json",
            AuthorityPayloadProfile::AuthenticatedCommand,
        );
    }

    #[test]
    fn enrollment_challenge_vector_matches_exact_bytes() {
        assert_vector(
            ENROLLMENT_MANIFEST,
            ENROLLMENT_PAYLOAD,
            ENROLLMENT_ENVELOPE,
            "binding-enrollment-challenge.payload.valid.json",
            "binding-enrollment-challenge.envelope.valid.json",
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
        );
    }

    #[test]
    fn ordinary_authority_record_vector_matches_exact_bytes() {
        assert_vector(
            AUTHORITY_MANIFEST,
            AUTHORITY_PAYLOAD,
            AUTHORITY_ENVELOPE,
            "principal-binding.valid.json",
            "principal-binding.authority-envelope.valid.json",
            AuthorityPayloadProfile::AuthorityRecord,
        );
    }

    #[test]
    fn root_transition_vector_matches_exact_ordered_bytes() {
        assert_vector(
            ROOT_TRANSITION_MANIFEST,
            ROOT_TRANSITION_PAYLOAD,
            ROOT_TRANSITION_ENVELOPE,
            "workspace-authority-root-transition.payload.valid.json",
            "workspace-authority-root-transition.envelope.valid.json",
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
        );
    }

    #[test]
    fn authority_fixture_graph_verifies_from_public_material() {
        let initial_root = fixture_value(include_bytes!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root.valid.json"
        ));
        let successor_root = fixture_value(include_bytes!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root-successor.valid.json"
        ));
        let predecessor_key_id = initial_root["authority_key_id"].as_str().unwrap();
        let successor_key_id = successor_root["authority_key_id"].as_str().unwrap();
        assert_key_id_matches_public_key(
            predecessor_key_id,
            initial_root["public_key"].as_str().unwrap(),
        );
        assert_key_id_matches_public_key(
            successor_key_id,
            successor_root["public_key"].as_str().unwrap(),
        );

        let mut records = Vec::with_capacity(AUTHORITY_CHAIN_FIXTURES.len());
        let mut record_digests: Vec<String> = Vec::with_capacity(AUTHORITY_CHAIN_FIXTURES.len());
        for (bytes, sequence) in AUTHORITY_CHAIN_FIXTURES {
            let record = fixture_value(bytes);
            assert_eq!(record["authority_sequence"], json!(sequence));
            assert_eq!(record["workspace_id"], initial_root["workspace_id"]);
            if let Some(predecessor_digest) = record_digests.last() {
                assert_eq!(
                    record["previous_authority_record_digest"].as_str(),
                    Some(predecessor_digest.as_str())
                );
            } else {
                assert!(record["previous_authority_record_digest"].is_null());
            }
            record_digests.push(authority_record_digest(&record));
            records.push(record);
        }

        let binding_envelope =
            canonical_envelope_bytes(&canonical_fixture_envelope(AUTHORITY_ENVELOPE));
        let verified_binding = verify_authority_envelope::<Value>(
            &binding_envelope,
            AuthorityPayloadProfile::AuthorityRecord,
            &[predecessor_key_id],
        )
        .unwrap();
        assert_eq!(verified_binding.parsed.payload, records[2]);

        let decision_envelope =
            canonical_envelope_bytes(&canonical_fixture_envelope(DECISION_ENVELOPE));
        let verified_decision = verify_authority_envelope::<Value>(
            &decision_envelope,
            AuthorityPayloadProfile::AuthorityRecord,
            &[predecessor_key_id],
        )
        .unwrap();
        assert_eq!(verified_decision.parsed.payload, records[4]);
        assert_eq!(
            records[4]["authority_key_id"].as_str(),
            Some(predecessor_key_id)
        );
        assert_eq!(records[4]["binding"]["authority_sequence"], json!(3));
        assert_eq!(records[4]["binding"]["record_digest"], record_digests[2]);
        assert_eq!(records[4]["delegation"]["record_digest"], record_digests[3]);
        assert_eq!(
            records[4]["evaluated_authority_head"]["record_digest"],
            record_digests[3]
        );

        let transition_envelope =
            canonical_envelope_bytes(&canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE));
        let verified_transition = verify_authority_envelope::<Value>(
            &transition_envelope,
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            &[predecessor_key_id, successor_key_id],
        )
        .unwrap();
        assert_eq!(verified_transition.parsed.payload, records[8]);
        assert_eq!(
            records[8]["predecessor_authority_key_id"].as_str(),
            Some(predecessor_key_id)
        );
        assert_eq!(
            records[8]["successor_authority_key_id"].as_str(),
            Some(successor_key_id)
        );
        assert_eq!(
            successor_root["predecessor_authority_key_id"].as_str(),
            Some(predecessor_key_id)
        );
        assert_eq!(
            successor_root["root_transition_envelope_digest"].as_str(),
            Some(
                verified_transition
                    .parsed
                    .envelope_digest
                    .to_string()
                    .as_str()
            )
        );
        assert_eq!(
            records[8]["successor_public_key"],
            successor_root["public_key"]
        );
    }

    #[test]
    fn rejection_fixture_key_substitutions_follow_regenerated_roots() {
        let root = fixture_value(include_bytes!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root.valid.json"
        ));
        let successor = fixture_value(include_bytes!(
            "../../../conformance/v1/authority/vectors/workspace-authority-root-successor.valid.json"
        ));
        let predecessor_key_id = root["authority_key_id"].as_str().unwrap();
        let successor_key_id = successor["authority_key_id"].as_str().unwrap();
        let authority_cases = include_bytes!(
            "../../../conformance/v1/authority/vectors/rejected-authority-cases.json"
        );

        assert_eq!(
            rejected_mutation_value(authority_cases, "root-transition-duplicate-keyid"),
            predecessor_key_id
        );
        assert_eq!(
            rejected_mutation_value(authority_cases, "authority-envelope-keyid-substitution"),
            successor_key_id
        );
        assert_eq!(
            rejected_mutation_value(authority_cases, "enrollment-envelope-keyid-substitution"),
            predecessor_key_id
        );
        assert_eq!(
            rejected_mutation_value(
                include_bytes!(
                    "../../../conformance/v1/authority/vectors/rejected-authentication-cases.json"
                ),
                "command-keyid-substitution",
            ),
            predecessor_key_id
        );
        assert_eq!(
            rejected_mutation_value(
                include_bytes!(
                    "../../../conformance/v1/authority/vectors/rejected-authorization-cases.json"
                ),
                "binding-subject-public-key-mismatch",
            ),
            predecessor_key_id
        );
    }

    #[test]
    fn generic_signing_round_trips_single_and_dual_signature_profiles() {
        let predecessor = Ed25519SigningProvider::from_secret_bytes(&[31_u8; 32]);
        let successor = Ed25519SigningProvider::from_secret_bytes(&[32_u8; 32]);
        let payload = json!({
            "api_version": "proof.dev/test/v1",
            "value": "canonical"
        });

        for profile in [
            AuthorityPayloadProfile::AuthenticatedCommand,
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            AuthorityPayloadProfile::AuthorityRecord,
        ] {
            let signed = sign_authority_payload(profile, &payload, &[&predecessor]).unwrap();
            let expected = signed.signers[0].key_id.as_str();
            let verified = verify_authority_envelope::<Value>(
                signed.envelope_json.as_bytes(),
                profile,
                &[expected],
            )
            .unwrap();
            assert_eq!(verified.parsed.payload, payload);
            assert_eq!(verified.parsed.payload_json, signed.payload_json);
            assert_eq!(verified.parsed.envelope_json, signed.envelope_json);
            assert_eq!(verified.parsed.envelope_digest, signed.envelope_digest);
            assert_eq!(verified.verified_signers, signed.signers);
        }

        let profile = AuthorityPayloadProfile::WorkspaceAuthorityRootTransition;
        let signed =
            sign_authority_payload(profile, &payload, &[&predecessor, &successor]).unwrap();
        let expected = [
            signed.signers[0].key_id.as_str(),
            signed.signers[1].key_id.as_str(),
        ];
        let verified =
            verify_authority_envelope::<Value>(signed.envelope_json.as_bytes(), profile, &expected)
                .unwrap();
        assert_eq!(verified.verified_signers, signed.signers);
    }

    #[test]
    fn signature_cardinality_is_exact_for_every_profile() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[33_u8; 32]);
        let payload = json!({"api_version": "proof.dev/test/v1"});

        assert_eq!(
            sign_authority_payload(AuthorityPayloadProfile::AuthenticatedCommand, &payload, &[])
                .unwrap_err(),
            AttestationError::InvalidAuthoritySignatureCount
        );
        assert_eq!(
            sign_authority_payload(
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                &payload,
                &[&signer]
            )
            .unwrap_err(),
            AttestationError::InvalidAuthoritySignatureCount
        );

        let mut command = canonical_fixture_envelope(COMMAND_ENVELOPE);
        command
            .signatures
            .push(command.signatures.first().unwrap().clone());
        assert_eq!(
            parse_authority_envelope::<Value>(
                &canonical_envelope_bytes(&command),
                AuthorityPayloadProfile::AuthenticatedCommand,
            )
            .unwrap_err(),
            AttestationError::InvalidAuthoritySignatureCount
        );
    }

    #[test]
    fn root_transition_rejects_duplicate_key_ids_and_signatures() {
        let mut duplicate_id = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        duplicate_id.signatures[1].keyid = duplicate_id.signatures[0].keyid.clone();
        assert_eq!(
            parse_authority_envelope::<Value>(
                &canonical_envelope_bytes(&duplicate_id),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            )
            .unwrap_err(),
            AttestationError::DuplicateAuthorityKeyId
        );

        let mut duplicate_signature = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        duplicate_signature.signatures[1].sig = duplicate_signature.signatures[0].sig.clone();
        assert_eq!(
            parse_authority_envelope::<Value>(
                &canonical_envelope_bytes(&duplicate_signature),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            )
            .unwrap_err(),
            AttestationError::DuplicateAuthoritySignature
        );
    }

    #[test]
    fn root_transition_rejects_permuted_ids_and_signature_entries() {
        let manifest = vector_manifest(ROOT_TRANSITION_MANIFEST);
        let expected = manifest
            .signers
            .iter()
            .map(|signer| signer.key_id.as_str())
            .collect::<Vec<_>>();

        let mut permuted_ids = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        let first_id = permuted_ids.signatures[0].keyid.clone();
        permuted_ids.signatures[0].keyid = permuted_ids.signatures[1].keyid.clone();
        permuted_ids.signatures[1].keyid = first_id;
        assert_eq!(
            verify_authority_envelope::<Value>(
                &canonical_envelope_bytes(&permuted_ids),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                &expected,
            )
            .unwrap_err(),
            AttestationError::KeyIdMismatch
        );

        let mut permuted_entries = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        permuted_entries.signatures.swap(0, 1);
        assert_eq!(
            verify_authority_envelope::<Value>(
                &canonical_envelope_bytes(&permuted_entries),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                &expected,
            )
            .unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }

    #[test]
    fn root_transition_rejects_substituted_id_and_signature() {
        let manifest = vector_manifest(ROOT_TRANSITION_MANIFEST);
        let expected = manifest
            .signers
            .iter()
            .map(|signer| signer.key_id.as_str())
            .collect::<Vec<_>>();
        let command_manifest = vector_manifest(COMMAND_MANIFEST);

        let mut substituted_id = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        substituted_id.signatures[0].keyid = command_manifest.signers[0].key_id.clone();
        assert_eq!(
            verify_authority_envelope::<Value>(
                &canonical_envelope_bytes(&substituted_id),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                &expected,
            )
            .unwrap_err(),
            AttestationError::KeyIdMismatch
        );

        let mut substituted_signature = canonical_fixture_envelope(ROOT_TRANSITION_ENVELOPE);
        substituted_signature.signatures[0].sig =
            command_manifest.signers[0].signature_base64.clone();
        assert_eq!(
            verify_authority_envelope::<Value>(
                &canonical_envelope_bytes(&substituted_signature),
                AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
                &expected,
            )
            .unwrap_err(),
            AttestationError::SignatureInvalid
        );
    }

    #[test]
    fn standard_base64_must_round_trip_exactly() {
        let manifest = vector_manifest(COMMAND_MANIFEST);
        let mut envelope = canonical_fixture_envelope(COMMAND_ENVELOPE);
        let canonical_signature = manifest.signers[0].signature_base64.as_bytes();
        assert_eq!(canonical_signature[canonical_signature.len() - 2], b'=');
        let final_data_index = envelope.signatures[0].sig.len() - 3;
        envelope.signatures[0]
            .sig
            .replace_range(final_data_index..=final_data_index, "h");

        assert_eq!(
            parse_authority_envelope::<Value>(
                &canonical_envelope_bytes(&envelope),
                AuthorityPayloadProfile::AuthenticatedCommand,
            )
            .unwrap_err(),
            AttestationError::InvalidBase64
        );
    }

    #[test]
    fn profile_bounds_enforce_4096_16384_and_65536_98304() {
        let signer = Ed25519SigningProvider::from_secret_bytes(&[34_u8; 32]);
        let successor = Ed25519SigningProvider::from_secret_bytes(&[35_u8; 32]);
        let authentication_max = object_with_canonical_size(MAX_AUTHENTICATION_PAYLOAD_BYTES);
        let authority_max = object_with_canonical_size(MAX_AUTHORITY_PAYLOAD_BYTES);

        let command = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &authentication_max,
            &[&signer],
        )
        .unwrap();
        assert!(command.envelope_json.len() <= MAX_AUTHENTICATION_ENVELOPE_BYTES);

        let transition = sign_authority_payload(
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition,
            &authority_max,
            &[&signer, &successor],
        )
        .unwrap();
        assert!(transition.envelope_json.len() <= MAX_AUTHORITY_ENVELOPE_BYTES);

        assert_eq!(
            authority_dsse_pae(
                AuthorityPayloadProfile::BindingEnrollmentChallenge,
                &vec![b'a'; MAX_AUTHENTICATION_PAYLOAD_BYTES + 1],
            )
            .unwrap_err(),
            AttestationError::PayloadTooLarge
        );
        assert_eq!(
            authority_dsse_pae(
                AuthorityPayloadProfile::AuthorityRecord,
                &vec![b'a'; MAX_AUTHORITY_PAYLOAD_BYTES + 1],
            )
            .unwrap_err(),
            AttestationError::PayloadTooLarge
        );
        assert_eq!(
            parse_authority_envelope::<Value>(
                &vec![b' '; MAX_AUTHENTICATION_ENVELOPE_BYTES + 1],
                AuthorityPayloadProfile::AuthenticatedCommand,
            )
            .unwrap_err(),
            AttestationError::EnvelopeTooLarge
        );
        assert_eq!(
            parse_authority_envelope::<Value>(
                &vec![b' '; MAX_AUTHORITY_ENVELOPE_BYTES + 1],
                AuthorityPayloadProfile::AuthorityRecord,
            )
            .unwrap_err(),
            AttestationError::EnvelopeTooLarge
        );
    }

    fn assert_vector(
        manifest_bytes: &[u8],
        payload_fixture: &[u8],
        envelope_fixture: &[u8],
        payload_file: &str,
        envelope_file: &str,
        profile: AuthorityPayloadProfile,
    ) {
        let manifest = vector_manifest(manifest_bytes);
        assert_eq!(
            manifest.api_version,
            "proof.dev/conformance/ed25519-dsse-vector/v1"
        );
        assert_eq!(manifest.status, "proposed");
        assert_eq!(manifest.payload_file, payload_file);
        assert_eq!(manifest.envelope_file, envelope_file);
        assert_eq!(manifest.payload_type, profile.payload_type());
        assert_eq!(
            manifest.envelope_digest_context,
            profile.envelope_artifact_kind().derive_key_context()
        );

        let payload_value = parse_strict(payload_fixture).unwrap();
        let canonical_payload = canonicalize(&payload_value).unwrap();
        assert_eq!(
            canonical_base64_decode(&manifest.payload_utf8_base64),
            canonical_payload.as_bytes()
        );
        assert_eq!(
            canonical_base64_decode(&manifest.pae_utf8_base64),
            authority_dsse_pae(profile, canonical_payload.as_bytes()).unwrap()
        );

        let envelope = canonical_fixture_envelope(envelope_fixture);
        let canonical_envelope = canonical_envelope_bytes(&envelope);
        let expected_key_ids = manifest
            .signers
            .iter()
            .map(|signer| signer.key_id.as_str())
            .collect::<Vec<_>>();
        let verified =
            verify_authority_envelope::<Value>(&canonical_envelope, profile, &expected_key_ids)
                .unwrap();

        assert_eq!(verified.parsed.profile, profile);
        assert_eq!(verified.parsed.payload, payload_value);
        assert_eq!(verified.parsed.payload_json, canonical_payload.as_str());
        assert_eq!(verified.parsed.envelope, envelope);
        assert_eq!(verified.parsed.envelope_json.as_bytes(), canonical_envelope);
        assert_eq!(
            verified.parsed.envelope_digest.to_string(),
            manifest.envelope_digest
        );
        assert_eq!(
            verified.parsed.envelope_digest,
            digest(
                profile.envelope_artifact_kind(),
                &canonicalize(&serde_json::to_value(&envelope).unwrap()).unwrap(),
            )
        );
        assert_eq!(verified.verified_signers.len(), manifest.signers.len());

        for ((vector_signer, parsed_signature), verified_signer) in manifest
            .signers
            .iter()
            .zip(&verified.parsed.signatures)
            .zip(&verified.verified_signers)
        {
            let public_key = canonical_base64_decode(&vector_signer.public_key_base64);
            let public_key: [u8; 32] = public_key.try_into().unwrap();
            let signature = canonical_base64_decode(&vector_signer.signature_base64);
            let signature: [u8; 64] = signature.try_into().unwrap();
            assert_eq!(decode_lower_hex(&vector_signer.public_key_hex), public_key);
            assert_eq!(decode_lower_hex(&vector_signer.signature_hex), signature);
            assert_eq!(ed25519_key_id(&public_key), vector_signer.key_id);
            assert_eq!(parsed_signature.key_id, vector_signer.key_id);
            assert_eq!(parsed_signature.signature, signature);
            assert_eq!(verified_signer.key_id, vector_signer.key_id);
            assert_eq!(verified_signer.public_key, public_key);
            assert_eq!(verified_signer.signature, signature);
        }
    }

    fn vector_manifest(bytes: &[u8]) -> VectorManifest {
        let value = parse_strict(bytes).unwrap();
        serde_json::from_value(value).unwrap()
    }

    fn fixture_value(bytes: &[u8]) -> Value {
        parse_strict(bytes).unwrap()
    }

    fn authority_record_digest(value: &Value) -> String {
        digest(
            ArtifactKind::AuthorityRecordV1,
            &canonicalize(value).unwrap(),
        )
        .to_string()
    }

    fn assert_key_id_matches_public_key(key_id: &str, public_key: &str) {
        let public_key: [u8; 32] = canonical_base64_decode(public_key).try_into().unwrap();
        assert_eq!(ed25519_key_id(&public_key), key_id);
    }

    fn rejected_mutation_value(bytes: &[u8], id: &str) -> String {
        fixture_value(bytes)["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["id"] == id)
            .unwrap()["mutation"]["value"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn canonical_fixture_envelope(bytes: &[u8]) -> DsseEnvelope {
        serde_json::from_value(parse_strict(bytes).unwrap()).unwrap()
    }

    fn canonical_envelope_bytes(envelope: &DsseEnvelope) -> Vec<u8> {
        canonicalize(&serde_json::to_value(envelope).unwrap())
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn canonical_base64_decode(value: &str) -> Vec<u8> {
        let decoded = BASE64.decode(value).unwrap();
        assert_eq!(BASE64.encode(&decoded), value);
        decoded
    }

    fn decode_lower_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
            .collect()
    }

    fn object_with_canonical_size(size: usize) -> Value {
        let value = json!({"x": "a".repeat(size - 8)});
        assert_eq!(canonicalize(&value).unwrap().as_bytes().len(), size);
        value
    }

    #[test]
    fn profile_media_types_are_exact() {
        assert_eq!(
            AuthorityPayloadProfile::AuthenticatedCommand.payload_type(),
            AUTHENTICATED_COMMAND_PAYLOAD_TYPE
        );
        assert_eq!(
            AuthorityPayloadProfile::BindingEnrollmentChallenge.payload_type(),
            BINDING_ENROLLMENT_CHALLENGE_PAYLOAD_TYPE
        );
        assert_eq!(
            AuthorityPayloadProfile::AuthorityRecord.payload_type(),
            AUTHORITY_RECORD_PAYLOAD_TYPE
        );
        assert_eq!(
            AuthorityPayloadProfile::WorkspaceAuthorityRootTransition.payload_type(),
            WORKSPACE_AUTHORITY_ROOT_TRANSITION_PAYLOAD_TYPE
        );
    }
}
