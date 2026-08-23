//! Integration tests for the `proof-server` deterministic-issuer OIDC BFF
//! (Authorization Code plus PKCE `S256`) state machine and ID-token validation.
//!
//! These tests exercise the retained abuse matrix without any network, socket,
//! or database access: the full happy-path code exchange, every retained claim/
//! signature/time abuse, one-use state/nonce/PKCE enforcement, exact-redirect
//! and RFC 9207 issuer checks, and disclosure-neutral error surfaces.

#![allow(clippy::similar_names)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use proof_server::{
    bff::{Bff, pkce_s256_challenge, validate_discovery_issuer, validate_subject},
    issuer::DeterministicIssuer,
    proof_remote::{identity::oidc_discovery_metadata_digest, oracle::IdentityFixtureV1},
};

/// Builds the BFF plus its deterministic issuer from the retained fixture.
fn fixture() -> (Bff, Arc<DeterministicIssuer>) {
    let config = IdentityFixtureV1::deterministic().issuer_configuration;
    let issuer = Arc::new(DeterministicIssuer::new(config.clone()).expect("issuer constructs"));
    let bff = Bff::new(config, issuer.clone()).expect("bff constructs");
    (bff, issuer)
}

/// Current wall-clock seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the Unix epoch")
        .as_secs()
}

/// Base64url-no-pad helper for hand-built ("none") tokens.
fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A well-formed base claim set bound to the issuer.
fn base_claims(issuer: &DeterministicIssuer) -> Value {
    let now = now();
    json!({
        "iss": issuer.issuer(),
        "sub": "human-alice",
        "aud": issuer.config().client_id.as_str(),
        "nonce": "test-nonce",
        "iat": now,
        "exp": now + 28_800,
    })
}

// ---------------------------------------------------------------------------
// PKCE, discovery-issuer, and subject primitives.
// ---------------------------------------------------------------------------

#[test]
fn pkce_s256_challenge_matches_rfc7636_frozen_vector() {
    // RFC 7636 Appendix B `S256` example vector.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        pkce_s256_challenge(verifier),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    // The challenge is base64url without padding.
    assert!(!pkce_s256_challenge(verifier).contains('='));
}

#[test]
fn validate_discovery_issuer_requires_exact_equality() {
    let expected = "https://identity.example.test";
    assert!(
        validate_discovery_issuer(
            &json!({ "issuer": "https://identity.example.test" }),
            expected
        )
        .is_ok()
    );
    // Wrong issuer value is refused (no trailing-slash folding, no case folding).
    assert!(
        validate_discovery_issuer(
            &json!({ "issuer": "https://identity.example.test/" }),
            expected
        )
        .is_err()
    );
    assert!(
        validate_discovery_issuer(
            &json!({ "issuer": "https://identity.example.test".to_ascii_uppercase() }),
            expected
        )
        .is_err()
    );
    // A missing issuer is refused.
    assert!(validate_discovery_issuer(&json!({ "no_issuer": 1 }), expected).is_err());
}

#[test]
fn validate_subject_rejects_empty_and_control_characters() {
    assert!(validate_subject("human-alice").is_ok());
    assert!(validate_subject("").is_err());
    assert!(validate_subject("with\u{1f}control").is_err());
    assert!(validate_subject("with\u{7f}control").is_err());
}

// ---------------------------------------------------------------------------
// Happy path: Authorization Code plus PKCE code exchange -> ID-token validation.
// ---------------------------------------------------------------------------

#[test]
fn happy_path_code_exchange_round_trips() {
    let (bff, issuer) = fixture();

    let (transaction, authorize_url) = bff.begin_login().expect("begin login");
    assert!(authorize_url.starts_with(&issuer.config().authorization_endpoint));
    assert!(authorize_url.contains("response_type=code"));
    assert!(authorize_url.contains("code_challenge_method=S256"));
    assert!(authorize_url.contains("state="));
    assert!(authorize_url.contains("nonce="));
    // The redirect URI is percent-encoded in the query string.
    assert!(
        authorize_url
            .contains("redirect_uri=https%3A%2F%2Fproof.example.test%2Fauth%2Foidc%2Fcallback")
    );

    // The "provider" issues a one-use code bound to the exact transaction.
    let issued = issuer
        .issue_code(
            &transaction.redirect_uri,
            &transaction.code_verifier,
            &transaction.nonce,
            "human-alice",
        )
        .expect("issue code");

    let result = bff
        .handle_callback(&issued.code, &transaction.state, issuer.issuer())
        .expect("callback succeeds");

    assert_eq!(result.subject.issuer, issuer.issuer());
    assert_eq!(result.subject.provider, "proof/oidc");
    assert_eq!(result.subject.subject, "human-alice");
    assert_eq!(result.nonce, transaction.nonce);
}

#[test]
fn issued_code_is_single_use() {
    let (bff, issuer) = fixture();
    let (transaction, _) = bff.begin_login().expect("begin login");
    let issued = issuer
        .issue_code(
            &transaction.redirect_uri,
            &transaction.code_verifier,
            &transaction.nonce,
            "human-alice",
        )
        .expect("issue code");

    bff.handle_callback(&issued.code, &transaction.state, issuer.issuer())
        .expect("first exchange");

    // The code was consumed: a second exchange fails closed.
    assert!(
        bff.handle_callback(&issued.code, &transaction.state, issuer.issuer())
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Retained abuse matrix.
// ---------------------------------------------------------------------------

#[test]
fn wrong_issuer_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["iss"] = json!("https://evil.example.test");
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn wrong_audience_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["aud"] = json!("some-other-client");
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn multiple_audiences_require_exact_azp() {
    let (bff, issuer) = fixture();

    // Multiple audiences without azp: refused.
    let mut claims = base_claims(&issuer);
    claims["aud"] = json!([issuer.config().client_id.as_str(), "other-client"]);
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());

    // Multiple audiences with the exact azp: accepted.
    let mut claims = base_claims(&issuer);
    claims["aud"] = json!([issuer.config().client_id.as_str(), "other-client"]);
    claims["azp"] = json!(issuer.config().client_id.as_str());
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_ok());

    // Multiple audiences with a wrong azp: refused.
    let mut claims = base_claims(&issuer);
    claims["aud"] = json!([issuer.config().client_id.as_str(), "other-client"]);
    claims["azp"] = json!("other-client");
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn wrong_algorithm_none_is_rejected() {
    let (bff, issuer) = fixture();
    let header = b64url(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64url(&serde_json::to_vec(&base_claims(&issuer)).expect("serialize"));
    let signature = b64url(b"not-a-real-signature");
    let token = format!("{header}.{payload}.{signature}");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());

    // The same claims signed with a symmetric algorithm are also refused.
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let token = format!("{header}.{payload}.{signature}");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn wrong_key_is_rejected() {
    let (bff, issuer) = fixture();
    // A distinct issuer URL derives a distinct Ed25519 key.
    let mut other_config = IdentityFixtureV1::deterministic().issuer_configuration;
    other_config.issuer = "https://other.example.test".to_owned();
    let other_issuer = DeterministicIssuer::new(other_config).expect("other issuer");
    assert_ne!(other_issuer.key_id(), issuer.key_id());

    // Correct iss claim, but signed by the wrong key.
    let token = other_issuer
        .sign_id_token(&base_claims(&issuer))
        .expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn expired_token_beyond_skew_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["iat"] = json!(now() - 10_000);
    claims["exp"] = json!(now() - 100);
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn future_token_beyond_skew_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["iat"] = json!(now() + 100);
    claims["exp"] = json!(now() + 200);
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn not_before_beyond_skew_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["nbf"] = json!(now() + 100);
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

#[test]
fn nonce_mismatch_is_rejected() {
    let (bff, issuer) = fixture();
    let token = issuer.sign_id_token(&base_claims(&issuer)).expect("sign");
    assert!(bff.validate_id_token(&token, "some-other-nonce").is_err());
    assert!(bff.validate_id_token(&token, "test-nonce").is_ok());
}

#[test]
fn replayed_state_is_rejected() {
    let (bff, issuer) = fixture();
    let (transaction, _) = bff.begin_login().expect("begin login");
    let issued = issuer
        .issue_code(
            &transaction.redirect_uri,
            &transaction.code_verifier,
            &transaction.nonce,
            "human-alice",
        )
        .expect("issue code");
    bff.handle_callback(&issued.code, &transaction.state, issuer.issuer())
        .expect("first callback consumes state");

    // Reusing the same state with a fresh code fails closed.
    let second = issuer
        .issue_code(
            &transaction.redirect_uri,
            &transaction.code_verifier,
            &transaction.nonce,
            "human-alice",
        )
        .expect("second code");
    assert!(
        bff.handle_callback(&second.code, &transaction.state, issuer.issuer())
            .is_err()
    );
}

#[test]
fn unknown_state_is_rejected() {
    let (bff, issuer) = fixture();
    assert!(
        bff.handle_callback("any-code", "unknown-state", issuer.issuer())
            .is_err()
    );
}

#[test]
fn missing_pkce_verifier_is_rejected() {
    let (bff, issuer) = fixture();
    let (transaction, _) = bff.begin_login().expect("begin login");
    // An empty verifier is refused at issuance.
    assert!(
        issuer
            .issue_code(
                &transaction.redirect_uri,
                "",
                &transaction.nonce,
                "human-alice"
            )
            .is_err()
    );
    // An under-length verifier is refused.
    assert!(
        issuer
            .issue_code(
                &transaction.redirect_uri,
                "too-short",
                &transaction.nonce,
                "human-alice"
            )
            .is_err()
    );
    // A verifier with reserved characters is refused.
    assert!(
        issuer
            .issue_code(
                &transaction.redirect_uri,
                "invalid=verifier!with?reserved+chars-000000000000000000000000",
                &transaction.nonce,
                "human-alice"
            )
            .is_err()
    );
}

#[test]
fn wrong_redirect_is_rejected() {
    let (bff, issuer) = fixture();
    let (transaction, _) = bff.begin_login().expect("begin login");
    assert!(
        issuer
            .issue_code(
                "https://evil.example.test/auth/oidc/callback",
                &transaction.code_verifier,
                &transaction.nonce,
                "human-alice"
            )
            .is_err()
    );
}

#[test]
fn host_mismatched_callback_iss_is_rejected() {
    let (bff, issuer) = fixture();
    let (transaction, _) = bff.begin_login().expect("begin login");
    let issued = issuer
        .issue_code(
            &transaction.redirect_uri,
            &transaction.code_verifier,
            &transaction.nonce,
            "human-alice",
        )
        .expect("issue code");

    // RFC 9207: the authorization-response issuer must be the exact issuer.
    assert!(
        bff.handle_callback(
            &issued.code,
            &transaction.state,
            "https://evil.example.test"
        )
        .is_err()
    );
    // The mismatched callback abandons the one-use transaction, so a retry with
    // the correct issuer also fails closed.
    assert!(
        bff.handle_callback(&issued.code, &transaction.state, issuer.issuer())
            .is_err()
    );
}

#[test]
fn missing_claims_are_rejected() {
    let (bff, issuer) = fixture();
    // Drop each required claim in turn and confirm refusal.
    for key in ["iss", "sub", "aud", "nonce", "exp", "iat"] {
        let mut claims = base_claims(&issuer);
        claims.as_object_mut().expect("object").remove(key);
        let token = issuer.sign_id_token(&claims).expect("sign");
        assert!(
            bff.validate_id_token(&token, "test-nonce").is_err(),
            "missing {key} must be rejected"
        );
    }
}

#[test]
fn non_string_or_empty_subject_is_rejected() {
    let (bff, issuer) = fixture();
    let mut claims = base_claims(&issuer);
    claims["sub"] = json!("");
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());

    let mut claims = base_claims(&issuer);
    claims["sub"] = json!(42);
    let token = issuer.sign_id_token(&claims).expect("sign");
    assert!(bff.validate_id_token(&token, "test-nonce").is_err());
}

// ---------------------------------------------------------------------------
// Disclosure-neutral failure surfaces: no raw claim, token, or subject leaks.
// ---------------------------------------------------------------------------

#[test]
fn public_errors_do_not_leak_raw_claims_or_tokens() {
    let (bff, issuer) = fixture();

    let secret_subject = "SENSITIVE-SUBJECT-LEAK-CHECK";
    let secret_nonce = "SENSITIVE-NONCE-LEAK-CHECK";

    // A token whose claims embed distinct secret material, signed under the
    // correct key but failing validation at the issuer check.
    let mut claims = base_claims(&issuer);
    claims["sub"] = json!(secret_subject);
    claims["nonce"] = json!(secret_nonce);
    claims["iss"] = json!("https://evil.example.test");
    let token = issuer.sign_id_token(&claims).expect("sign");

    let error = bff
        .validate_id_token(&token, secret_nonce)
        .expect_err("wrong issuer must fail");
    let message = error.to_string();
    assert!(!message.contains(secret_subject));
    assert!(!message.contains(secret_nonce));
    assert!(!message.contains(&token));

    // A "none"-algorithm token must not disclose its payload either.
    let header = b64url(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = b64url(&serde_json::to_vec(&claims).expect("serialize"));
    let token = format!("{header}.{payload}.{}", b64url(b"sig"));
    let error = bff
        .validate_id_token(&token, secret_nonce)
        .expect_err("none algorithm must fail");
    let message = error.to_string();
    assert!(!message.contains(secret_subject));
    assert!(!message.contains(secret_nonce));
    assert!(!message.contains(&token));
}

#[test]
fn callback_errors_do_not_leak_state_code_or_iss() {
    let (bff, _issuer) = fixture();
    let secret_code = "SECRET-CODE-LEAK-CHECK";
    let secret_state = "SECRET-STATE-LEAK-CHECK";
    let secret_iss = "https://secret-issuer.example.test";

    let error = bff
        .handle_callback(secret_code, secret_state, secret_iss)
        .expect_err("mismatched callback must fail");
    let message = error.to_string();
    assert!(!message.contains(secret_code));
    assert!(!message.contains(secret_state));
    assert!(!message.contains(secret_iss));
}

// ---------------------------------------------------------------------------
// Digest pinning.
// ---------------------------------------------------------------------------

#[test]
fn pin_issuer_digests_matches_frozen_configuration_vector() {
    let (bff, issuer) = fixture();
    let (configuration_digest, discovery_digest) = bff.pin_issuer_digests().expect("pin");

    // The issuer-configuration digest reproduces the frozen P-0008 vector.
    assert_eq!(
        configuration_digest.to_string(),
        "blake3:64cab46b9d5925076a726b80206f365d2e913768a90e0954487cb30b010a9cc7"
    );

    // The discovery-metadata digest reproduces the issuer's accepted document.
    let expected = oidc_discovery_metadata_digest(&issuer.discovery_document()).expect("digest");
    assert_eq!(discovery_digest, expected);
    assert_ne!(configuration_digest, discovery_digest);
}
