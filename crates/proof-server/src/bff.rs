//! Same-origin confidential OIDC Backend-for-Frontend: Authorization Code plus
//! PKCE `S256` state machine and ID-token validation (contract §"OIDC binding
//! and session boundary").

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use proof_remote::identity::{
    OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT, OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT,
    OidcAuthenticatedSubjectV1, OidcIssuerConfigurationV1, OidcPrincipalBindingPrivateV1,
    OidcPrincipalBindingV1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ServerError, issuer::DeterministicIssuer};

/// PKCE method: `S256` only (contract §"OIDC binding and session boundary").
pub const PKCE_METHOD: &str = "S256";

/// Frozen maximum clock skew: 30 seconds (contract §"OIDC binding and session
/// boundary").
pub const CLOCK_SKEW_SECONDS: u32 = 30;

/// One-use login transaction state (contract §"OIDC binding and session
/// boundary").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginTransaction {
    /// One-use `state`.
    pub state: String,
    /// One-use OpenID Connect `nonce`.
    pub nonce: String,
    /// PKCE code verifier.
    pub code_verifier: String,
    /// PKCE `S256` code challenge.
    pub code_challenge: String,
    /// Exact preregistered redirect URI.
    pub redirect_uri: String,
    /// Creation time.
    pub created_at: SystemTime,
}

/// The callback validation result: an authenticated OIDC subject ready for
/// protected binding resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackResult {
    /// Exact, case-sensitive `{issuer, subject}` tuple.
    pub subject: OidcAuthenticatedSubjectV1,
    /// One-use `nonce` from the validated ID token.
    pub nonce: String,
}

/// The BFF state machine over the deterministic in-process issuer (contract
/// §"OIDC binding and session boundary"). No live provider is contacted.
pub struct Bff {
    config: OidcIssuerConfigurationV1,
    issuer: Arc<DeterministicIssuer>,
    transactions: Mutex<HashMap<String, LoginTransaction>>,
}

impl Bff {
    /// Constructs the BFF over a deterministic issuer.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Config`] when the issuer configuration is
    /// invalid.
    pub fn new(
        config: OidcIssuerConfigurationV1,
        issuer: Arc<DeterministicIssuer>,
    ) -> Result<Self, ServerError> {
        config
            .validate()
            .map_err(|error| ServerError::Config(error.to_string()))?;
        Ok(Self {
            config,
            issuer,
            transactions: Mutex::new(HashMap::new()),
        })
    }

    /// Pins the issuer-configuration and discovery-metadata digests
    /// (`proof:oidc-issuer-configuration:v1` and
    /// `proof:oidc-discovery-metadata:v1`) (contract §"OIDC binding and session
    /// boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when a digest cannot be recomputed.
    pub fn pin_issuer_digests(
        &self,
    ) -> Result<(proof_domain::ContentDigest, proof_domain::ContentDigest), ServerError> {
        todo!("recompute configuration and discovery digests")
    }

    /// Starts a fresh login: mints a one-use `state`, `nonce`, and PKCE
    /// verifier/challenge, and returns the authorization URL (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the transaction cannot be minted.
    pub fn begin_login(&self) -> Result<(LoginTransaction, String), ServerError> {
        todo!("mint state/nonce/verifier, record transaction, build authorize URL")
    }

    /// Validates the authorization-response `code`/`state`/`iss` and consumes
    /// the one-use transaction, then exchanges the code (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] on state/nonce/PKCE/iss mismatch or code
    /// exchange failure.
    pub fn handle_callback(
        &self,
        code: &str,
        state: &str,
        iss: &str,
    ) -> Result<CallbackResult, ServerError> {
        todo!("consume transaction, exact-check iss/state, exchange, validate ID token")
    }

    /// Exchanges one code via `client_secret_basic` against the deterministic
    /// issuer (contract §"OIDC binding and session boundary"). No network.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the exchange fails.
    pub fn exchange_code(&self, code: &str) -> Result<crate::issuer::IssuerTokenSet, ServerError> {
        self.issuer.exchange_code(code)
    }

    /// Validates an Ed25519 ID token: signature/algorithm allowlist (never
    /// `none`), exact `iss`/nonempty `sub`/`aud`/`azp`, and `exp`/`iat`/`nbf`
    /// with a frozen 30-second skew (contract §"OIDC binding and session
    /// boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] on any claim, time, or signature failure.
    pub fn validate_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
    ) -> Result<CallbackResult, ServerError> {
        todo!("verify signature, enforce claims and skew, return exact subject")
    }

    /// Resolves one protected binding to its public commitment-only record
    /// (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Authorization`] when the binding is unknown,
    /// revoked, or disabled.
    pub fn resolve_binding(
        &self,
        _private: &OidcPrincipalBindingPrivateV1,
    ) -> Result<OidcPrincipalBindingV1, ServerError> {
        todo!("re-resolve the pre-existing public binding through proof-pg")
    }
}

/// Computes the PKCE `S256` code challenge from a code verifier
/// (`BASE64URL(SHA256(verifier))`) (contract §"OIDC binding and session
/// boundary").
#[must_use]
pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

/// Generates a fresh uniformly random 256-bit base64url value for `state` or
/// `nonce`.
///
/// # Errors
///
/// Returns [`ServerError::Oidc`] when the random source is unavailable.
pub fn random_opaque_value() -> Result<String, ServerError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| ServerError::Oidc(format!("random opaque value: {error}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Validates the exact decoded JSON-string subject without case folding or
/// Unicode normalization (contract §"Remote identity vocabulary").
///
/// # Errors
///
/// Returns [`ServerError::Oidc`] on a nonempty/control violation.
pub fn validate_subject(subject: &str) -> Result<(), ServerError> {
    let value = OidcAuthenticatedSubjectV1 {
        api_version: proof_remote::identity::OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: subject.to_owned(),
    };
    value
        .validate()
        .map_err(|error| ServerError::Oidc(error.to_string()))
}

/// Re-exported discovery-metadata digest context for the issuer fixture
/// (contract §"OIDC binding and session boundary").
#[must_use]
pub const fn issuer_configuration_digest_context() -> &'static str {
    OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT
}

/// Re-exported issuer-configuration digest context for the issuer fixture.
#[must_use]
pub const fn discovery_metadata_digest_context() -> &'static str {
    OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT
}

/// Validates that the accepted discovery document is pinned to the configured
/// issuer (contract §"OIDC binding and session boundary").
///
/// # Errors
///
/// Returns [`ServerError::Oidc`] when the discovery issuer diverges.
pub fn validate_discovery_issuer(
    metadata: &Value,
    expected_issuer: &str,
) -> Result<(), ServerError> {
    let actual = metadata
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Oidc("discovery document is missing `issuer`".to_owned()))?;
    if actual != expected_issuer {
        return Err(ServerError::Oidc(format!(
            "discovery issuer `{actual}` does not match the configured issuer `{expected_issuer}`"
        )));
    }
    Ok(())
}
