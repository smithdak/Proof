//! Deterministic in-process OIDC issuer (contract §"OIDC binding and session
//! boundary").
//!
//! The issuer fixes one issuer URL, a discovery document, an Ed25519 JWKS,
//! in-process authorization/token endpoints, one-use code issuance, and JWT
//! signing. It performs **no network I/O**: it is retained test
//! infrastructure, never a live provider.

use std::collections::HashMap;
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use proof_attestation::ed25519_key_id;
use proof_remote::identity::OidcIssuerConfigurationV1;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::ServerError;

/// BLAKE3/Ed25519 domain tag used to derive the deterministic signing key.
const ISSUER_KEY_DERIVATION_DOMAIN: &[u8] = b"proof:deterministic-issuer-ed25519:v1";

/// The only accepted JWT signing algorithm (never `none`, never a symmetric
/// algorithm) (contract §"OIDC binding and session boundary").
pub const ID_TOKEN_ALGORITHM: &str = "EdDSA";

/// One issued one-use authorization code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedAuthorizationCode {
    /// One-use authorization code value.
    pub code: String,
    /// Exact preregistered redirect URI it was issued for.
    pub redirect_uri: String,
    /// PKCE `S256` code verifier used to mint the challenge.
    pub code_verifier: String,
    /// One-use OIDC `nonce`.
    pub nonce: String,
    /// Exact authenticated subject carried by the eventual ID token.
    pub subject: String,
}

/// The token response returned by the in-process token endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerTokenSet {
    /// Signed Ed25519 ID token (JWS compact serialization).
    pub id_token: String,
    /// Token type (always `Bearer`).
    pub token_type: String,
    /// `expires_in` seconds (never exceeding the session absolute bound).
    pub expires_in: u64,
}

/// Deterministic in-process OIDC issuer (contract §"OIDC binding and session
/// boundary"). It is test infrastructure; no live provider is contacted.
pub struct DeterministicIssuer {
    config: OidcIssuerConfigurationV1,
    signing_key: SigningKey,
    key_id: String,
    issued_codes: Mutex<HashMap<String, IssuedAuthorizationCode>>,
}

impl DeterministicIssuer {
    /// Constructs the deterministic issuer from the pinned configuration. The
    /// Ed25519 signing key is derived deterministically from the issuer URL so
    /// retained fixtures reproduce byte-for-byte across runs.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Config`] when the configuration fails validation.
    pub fn new(config: OidcIssuerConfigurationV1) -> Result<Self, ServerError> {
        config
            .validate()
            .map_err(|error| ServerError::Config(error.to_string()))?;
        let signing_key = Self::derive_signing_key(&config.issuer);
        let key_id = ed25519_key_id(&signing_key.verifying_key().to_bytes());
        Ok(Self {
            config,
            signing_key,
            key_id,
            issued_codes: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the exact pinned issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Returns the pinned public issuer configuration.
    #[must_use]
    pub fn config(&self) -> &OidcIssuerConfigurationV1 {
        &self.config
    }

    /// Returns the Ed25519 JWKS signing key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the exact accepted discovery document (contract §"OIDC binding
    /// and session boundary").
    #[must_use]
    pub fn discovery_document(&self) -> Value {
        json!({
            "issuer": self.config.issuer,
            "authorization_endpoint": self.config.authorization_endpoint,
            "token_endpoint": self.config.token_endpoint,
            "jwks_uri": self.config.jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [ID_TOKEN_ALGORITHM],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "authorization_response_iss_parameter_supported": true,
        })
    }

    /// Returns the Ed25519 JWKS (contract §"OIDC binding and session boundary").
    #[must_use]
    pub fn jwks(&self) -> Value {
        let public = self.signing_key.verifying_key().to_bytes();
        json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.key_id,
                "x": URL_SAFE_NO_PAD.encode(public),
                "alg": ID_TOKEN_ALGORITHM,
                "use": "sig",
            }]
        })
    }

    /// Mints a one-use authorization code for one PKCE `S256` challenge
    /// (contract §"OIDC binding and session boundary"). No network is used.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the code cannot be minted.
    pub fn issue_code(
        &self,
        redirect_uri: &str,
        code_verifier: &str,
        nonce: &str,
        subject: &str,
    ) -> Result<IssuedAuthorizationCode, ServerError> {
        todo!("mint a one-use code and record the transaction")
    }

    /// Exchanges one one-use authorization code for an ID token
    /// (`client_secret_basic` only) (contract §"OIDC binding and session
    /// boundary"). No network is used.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the code is unknown, already used, or
    /// the redirect/PKCE/nonce does not match.
    pub fn exchange_code(&self, code: &str) -> Result<IssuerTokenSet, ServerError> {
        todo!("consume the one-use code and sign the ID token")
    }

    /// Signs an Ed25519 ID token with the configured issuer/key (contract
    /// §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the claims cannot be serialized.
    pub fn sign_id_token(&self, claims: &Value) -> Result<String, ServerError> {
        todo!("compact-serialize header/payload and Ed25519-sign")
    }

    /// Verifies one compact Ed25519 JWS and returns the decoded payload JSON,
    /// used by the BFF's ID-token validation (contract §"OIDC binding and
    /// session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] on malformed segments, a wrong algorithm,
    /// a wrong key, or an invalid signature.
    pub fn verify_id_token(&self, token: &str) -> Result<Value, ServerError> {
        todo!("base64url-decode, enforce alg=kid=EdDSA, verify_strict, return payload")
    }

    /// Derives the deterministic Ed25519 signing key from the issuer URL.
    fn derive_signing_key(issuer: &str) -> SigningKey {
        let mut hasher = Sha256::new();
        hasher.update(ISSUER_KEY_DERIVATION_DOMAIN);
        hasher.update(issuer.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        SigningKey::from_bytes(&digest)
    }
}

/// Base64url-no-pad encodes one byte slice (JWS compact serialization).
#[must_use]
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64url-no-pad decodes one byte slice, rejecting non-canonical input.
///
/// # Errors
///
/// Returns [`ServerError::Oidc`] on invalid or non-canonical base64url.
pub(crate) fn b64url_decode(text: &str) -> Result<Vec<u8>, ServerError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|error| ServerError::Oidc(format!("invalid base64url segment: {error}")))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != text {
        return Err(ServerError::Oidc(
            "non-canonical base64url segment".to_owned(),
        ));
    }
    Ok(decoded)
}

/// Verifies one Ed25519 signature over exact message bytes (shared by the
/// issuer and the BFF).
///
/// # Errors
///
/// Returns [`ServerError::Oidc`] on an invalid public key or signature.
pub(crate) fn verify_ed25519(
    public_key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> Result<(), ServerError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| ServerError::Oidc("invalid Ed25519 public key".to_owned()))?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| ServerError::Oidc("invalid Ed25519 signature".to_owned()))
}
