//! Public-surface assertions only (no I/O, no database, no network).
//!
//! These tests pin the exact contract constants and type surface so a later
//! implementation cannot silently reshape the P-0011 boundary.

use cookie::SameSite;
use proof_server::{
    Limits,
    dispatch::{PROBLEM_REGISTRY, SuccessEnvelope, problem_tuple},
    issuer::DeterministicIssuer,
    proof_remote::{
        HttpRouteV1,
        oracle::IdentityFixtureV1,
        registry::{AgentOperationProjectionV1, HumanOperationRegistryV1},
    },
    routes::route_problem_profile,
    session::{OIDC_TX_COOKIE_NAME, SESSION_COOKIE_NAME, oidc_tx_cookie, session_cookie},
};

#[test]
fn problem_registry_is_exactly_44_tuples() {
    assert_eq!(PROBLEM_REGISTRY.len(), 44);
    let unknown = problem_tuple("proof.operation.unknown_outcome").expect("504 tuple");
    assert!(unknown.retryable);
    assert_eq!(unknown.status, 504);
    let denied = problem_tuple("proof.auth.denied").expect("401 tuple");
    assert!(!denied.retryable);
    assert_eq!(denied.status, 401);
}

#[test]
fn contract_limits_are_exact() {
    let limits = Limits::contract();
    assert_eq!(limits.raw_body_bytes, 1_048_576);
    assert_eq!(limits.canonical_request_bytes, 1_048_576);
    assert_eq!(limits.response_bytes, 4_194_304);
    assert_eq!(limits.agent_authentication_payload_bytes, 4_096);
    assert_eq!(limits.agent_dsse_envelope_bytes, 16_384);
}

#[test]
fn every_route_has_a_closed_problem_profile() {
    for route in HttpRouteV1::ALL {
        assert!(!route_problem_profile(route).codes.is_empty());
    }
    assert_eq!(HttpRouteV1::ALL.len(), 9);
}

#[test]
fn session_cookies_have_exact_flags() {
    let session = session_cookie("opaque-value");
    assert_eq!(session.name(), SESSION_COOKIE_NAME);
    assert_eq!(session.secure(), Some(true));
    assert_eq!(session.http_only(), Some(true));
    assert_eq!(session.same_site(), Some(SameSite::Strict));
    assert_eq!(session.path(), Some("/"));
    assert!(session.domain().is_none());

    let tx = oidc_tx_cookie("opaque-value");
    assert_eq!(tx.name(), OIDC_TX_COOKIE_NAME);
    assert_eq!(tx.secure(), Some(true));
    assert_eq!(tx.http_only(), Some(true));
    assert_eq!(tx.same_site(), Some(SameSite::Lax));
    assert_eq!(tx.path(), Some("/auth/oidc/callback"));
}

#[test]
fn deterministic_issuer_constructs_and_reports() {
    let config = IdentityFixtureV1::deterministic().issuer_configuration;
    let issuer = DeterministicIssuer::new(config.clone()).expect("issuer constructs");
    assert_eq!(issuer.issuer(), config.issuer);
    assert_eq!(
        issuer.jwks()["keys"].as_array().expect("keys array").len(),
        1
    );
    assert!(issuer.discovery_document()["issuer"].as_str().is_some());
    assert!(!issuer.key_id().is_empty());
}

#[test]
fn registries_have_exact_row_counts() {
    assert_eq!(HumanOperationRegistryV1.rows().len(), 26);
    assert_eq!(AgentOperationProjectionV1.rows().len(), 14);
}

#[test]
fn success_envelope_serializes_operation_and_ids() {
    let envelope = SuccessEnvelope::new(
        proof_server::proof_remote::RemoteOperationV1 {
            name: "workspace.status".to_owned(),
            version: "proof.dev/operation/workspace.status/v1".to_owned(),
        },
        "019e0000-0000-7000-8000-000000000024".to_owned(),
        None,
        serde_json::json!({ "authority_head": null }),
        serde_json::json!({ "status": "initialized" }),
    );
    let json = serde_json::to_value(&envelope).expect("envelope serializes");
    assert_eq!(json["api_version"], "proof.dev/http-operation-result/v1");
    assert_eq!(json["operation"]["name"], "workspace.status");
    assert!(json["result"].is_object());
}
