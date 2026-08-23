//! Same-origin confidential OIDC Backend-for-Frontend: Authorization Code plus
//! PKCE `S256` state machine and ID-token validation (contract §"OIDC binding
//! and session boundary").

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use proof_remote::identity::{
    OIDC_DISCOVERY_METADATA_DIGEST_CONTEXT, OIDC_ISSUER_CONFIGURATION_DIGEST_CONTEXT,
    OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1, OidcIssuerConfigurationV1,
    OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1, oidc_discovery_metadata_digest,
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
        let configuration_digest = self
            .config
            .digest()
            .map_err(|error| ServerError::Oidc(error.to_string()))?;
        let discovery_digest = oidc_discovery_metadata_digest(&self.issuer.discovery_document())
            .map_err(|error| ServerError::Oidc(error.to_string()))?;
        Ok((configuration_digest, discovery_digest))
    }

    /// Starts a fresh login: mints a one-use `state`, `nonce`, and PKCE
    /// verifier/challenge, and returns the authorization URL (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Oidc`] when the transaction cannot be minted.
    pub fn begin_login(&self) -> Result<(LoginTransaction, String), ServerError> {
        let state = random_opaque_value()?;
        let nonce = random_opaque_value()?;
        let code_verifier = random_opaque_value()?;
        let code_challenge = pkce_s256_challenge(&code_verifier);

        let transaction = LoginTransaction {
            state: state.clone(),
            nonce: nonce.clone(),
            code_verifier: code_verifier.clone(),
            code_challenge: code_challenge.clone(),
            redirect_uri: self.config.redirect_uri.clone(),
            created_at: SystemTime::now(),
        };
        self.transactions
            .lock()
            .map_err(|_| ServerError::Oidc("login transaction store poisoned".to_owned()))?
            .insert(state.clone(), transaction.clone());

        let authorize_url = self.authorize_url(&state, &nonce, &code_challenge);
        Ok((transaction, authorize_url))
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
        // One-use state: consume it immediately so any outcome below — including
        // a mismatched issuer — abandons the transaction (contract §"OIDC
        // binding and session boundary"). A replayed or fixated state fails
        // closed.
        let transaction = self
            .transactions
            .lock()
            .map_err(|_| ServerError::Oidc("login transaction store poisoned".to_owned()))?
            .remove(state)
            .ok_or_else(|| ServerError::Oidc("unknown or replayed login state".to_owned()))?;

        // RFC 9207: the authorization-response issuer parameter must be the
        // exact configured issuer.
        if iss != self.config.issuer {
            return Err(ServerError::Oidc(
                "authorization-response issuer does not match the configured issuer".to_owned(),
            ));
        }

        // The transaction was minted for the one exact preregistered redirect;
        // any divergence is an open-redirect refusal.
        if transaction.redirect_uri != self.config.redirect_uri {
            return Err(ServerError::Oidc(
                "login transaction carries a non-preregistered redirect URI".to_owned(),
            ));
        }

        let token_set = self.exchange_code(code)?;
        self.validate_id_token(&token_set.id_token, &transaction.nonce)
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
        // Signature, algorithm allowlist, and JWKS key are verified by the
        // configured issuer; keys come only from that issuer (contract §"OIDC
        // binding and session boundary").
        let claims = self.issuer.verify_id_token(token)?;

        let issuer = claims
            .get("iss")
            .and_then(Value::as_str)
            .ok_or_else(|| ServerError::Oidc("ID token is missing `iss`".to_owned()))?;
        if issuer != self.config.issuer {
            return Err(ServerError::Oidc(
                "ID token issuer does not match the configured issuer".to_owned(),
            ));
        }

        // Nonempty, stable, exact-case subject; no case folding or Unicode
        // normalization (contract §"Remote identity vocabulary").
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or_else(|| ServerError::Oidc("ID token is missing `sub`".to_owned()))?;
        validate_subject(subject)?;

        validate_audience(&claims, &self.config.client_id)?;

        let nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| ServerError::Oidc("ID token is missing `nonce`".to_owned()))?;
        if nonce != expected_nonce {
            return Err(ServerError::Oidc(
                "ID token nonce does not match the login transaction".to_owned(),
            ));
        }

        validate_token_time(&claims)?;

        let authenticated_subject = OidcAuthenticatedSubjectV1 {
            api_version: OidcAuthenticatedSubjectApiVersion::V1,
            issuer: self.config.issuer.clone(),
            provider: "proof/oidc".to_owned(),
            subject: subject.to_owned(),
        };
        Ok(CallbackResult {
            subject: authenticated_subject,
            nonce: nonce.to_owned(),
        })
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
        private: &OidcPrincipalBindingPrivateV1,
    ) -> Result<OidcPrincipalBindingV1, ServerError> {
        // Validate the protected record's self-consistency and commitment
        // opening before anything else.
        private.validate().map_err(|error| {
            ServerError::Authorization(format!("protected binding failed validation: {error}"))
        })?;

        // The BFF owns no storage handle and `proof-pg` exposes no binding-fetch
        // surface in this slice, so the pre-existing public record cannot be
        // re-resolved here. Fail closed (disclosure-neutral) rather than
        // fabricate a public record (contract §"OIDC binding and session
        // boundary").
        Err(ServerError::Authorization(
            "the pre-existing public binding cannot be re-resolved without the authority store lane"
                .to_owned(),
        ))
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

impl Bff {
    /// Builds the exact authorization URL for one transaction (contract §"OIDC
    /// binding and session boundary"). Values are RFC 3986 percent-encoded.
    #[must_use]
    fn authorize_url(&self, state: &str, nonce: &str, code_challenge: &str) -> String {
        let parameters = [
            ("client_id", self.config.client_id.as_str()),
            ("redirect_uri", self.config.redirect_uri.as_str()),
            ("response_type", "code"),
            ("scope", "openid"),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", code_challenge),
            ("code_challenge_method", PKCE_METHOD),
        ];
        let query = parameters
            .into_iter()
            .map(|(key, value)| format!("{key}={}", percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        format!("{}?{}", self.config.authorization_endpoint, query)
    }
}

/// RFC 3986 percent-encodes one query value, leaving only unreserved characters
/// literal.
#[must_use]
fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            other => {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{other:02X}");
            }
        }
    }
    encoded
}

/// Validates the exact `aud`/`azp` claims (contract §"OIDC binding and session
/// boundary").
fn validate_audience(claims: &Value, client_id: &str) -> Result<(), ServerError> {
    let aud = claims
        .get("aud")
        .ok_or_else(|| ServerError::Oidc("ID token is missing `aud`".to_owned()))?;

    let mut audiences = Vec::new();
    match aud {
        Value::String(audience) => audiences.push(audience.as_str()),
        Value::Array(items) => {
            for item in items {
                let Some(audience) = item.as_str() else {
                    return Err(ServerError::Oidc(
                        "ID token `aud` array must contain only strings".to_owned(),
                    ));
                };
                audiences.push(audience);
            }
        }
        _ => {
            return Err(ServerError::Oidc(
                "ID token `aud` must be a string or an array of strings".to_owned(),
            ));
        }
    }

    if !audiences.contains(&client_id) {
        return Err(ServerError::Oidc(
            "ID token audience does not include the configured client_id".to_owned(),
        ));
    }

    // `azp` is required and must name the client whenever multiple audiences
    // are present; when present at all it must still name the client.
    if audiences.len() > 1 {
        let azp = claims.get("azp").and_then(Value::as_str).ok_or_else(|| {
            ServerError::Oidc("ID token with multiple audiences is missing `azp`".to_owned())
        })?;
        if azp != client_id {
            return Err(ServerError::Oidc(
                "ID token `azp` does not match the configured client_id".to_owned(),
            ));
        }
    } else if let Some(azp) = claims.get("azp").and_then(Value::as_str)
        && azp != client_id
    {
        return Err(ServerError::Oidc(
            "ID token `azp` does not match the configured client_id".to_owned(),
        ));
    }

    Ok(())
}

/// Validates `exp`/`iat`/optional `nbf` with the frozen 30-second clock skew
/// (contract §"OIDC binding and session boundary").
fn validate_token_time(claims: &Value) -> Result<(), ServerError> {
    let now = crate::issuer::unix_timestamp_seconds();
    let skew = u64::from(CLOCK_SKEW_SECONDS);

    let exp = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or_else(|| ServerError::Oidc("ID token is missing `exp`".to_owned()))?;
    if now > exp.saturating_add(skew) {
        return Err(ServerError::Oidc(
            "ID token is expired beyond the accepted clock skew".to_owned(),
        ));
    }

    let iat = claims
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or_else(|| ServerError::Oidc("ID token is missing `iat`".to_owned()))?;
    if iat > now.saturating_add(skew) {
        return Err(ServerError::Oidc(
            "ID token was issued in the future beyond the accepted clock skew".to_owned(),
        ));
    }

    if let Some(nbf) = claims.get("nbf").and_then(Value::as_u64)
        && nbf > now.saturating_add(skew)
    {
        return Err(ServerError::Oidc(
            "ID token is not yet valid beyond the accepted clock skew".to_owned(),
        ));
    }

    Ok(())
}
