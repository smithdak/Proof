//! Implementation tests for the P-0011 HTTP transport boundary in
//! `crates/proof-server/src/routes.rs`.
//!
//! These tests exercise only the transport-level surface owned by `routes.rs`:
//! the nine-route router and its 404 fallback, the raw-body limit layer, the
//! canonical-request guard (strict I-JSON, duplicate names, canonical
//! size), the `Content-Type` guard, the same-origin `Origin` guard, and the
//! `Proof-CSRF` synchronizer guard. No database, network, or sibling-module
//! runtime is exercised.

#![allow(clippy::doc_markdown)]

use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use proof_server::{
    AppState, RAW_BODY_LIMIT_BYTES, ServerConfig,
    dispatch::ProblemResponse,
    proof_remote::oracle::IdentityFixtureV1,
    routes::{CanonicalRequestGuard, ContentTypeGuard, CsrfGuard, OriginGuard, router},
};
use serde_json::Value;
use tower::ServiceExt;

/// Builds a shared [`AppState`] with no database connection (PostgreSQL is
/// lazily connected and never opened by these tests).
fn app_state() -> AppState {
    let fixture = IdentityFixtureV1::deterministic();
    let config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("loopback address parses"),
        "019e0000-0000-7000-8000-000000000001"
            .parse()
            .expect("workspace id parses"),
        fixture.issuer_configuration,
        "deployment-secret:test",
        [7_u8; 32],
        "postgres://postgres@127.0.0.1:55432/prooftest",
    );
    AppState::new(config)
}

/// Reads the `code` member of a JSON Problem response body.
async fn response_code(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body is readable");
    let value: Value = serde_json::from_slice(&bytes).expect("response body is JSON");
    value["code"]
        .as_str()
        .expect("Problem carries a string code")
        .to_owned()
}

/// Runs the canonical-request guard directly against raw request bytes.
async fn canonical_guard(bytes: Vec<u8>) -> Result<CanonicalRequestGuard, ProblemResponse> {
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .expect("request constructs");
    CanonicalRequestGuard::from_request(request, &()).await
}

#[tokio::test]
async fn router_rejects_unknown_routes_and_versions() {
    let app = router(app_state());

    for path in [
        "/api/v1/capabilities/extra",
        "/api/v2/capabilities",
        "/api/v1/human/operations",
        "/definitely/not/a/route",
    ] {
        let request = Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("request constructs");
        let response = app.clone().oneshot(request).await.expect("router serves");
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {path}");
        assert_eq!(response_code(response).await, "proof.resource.not_found");
    }
}

#[tokio::test]
async fn raw_body_over_limit_rejects_413_before_parsing() {
    let app = router(app_state());

    // Malformed (non-JSON) body over the raw limit must still be rejected with
    // 413 — the raw-body limit fires before strict parsing.
    let garbage: Vec<u8> = vec![b'x'; RAW_BODY_LIMIT_BYTES + 1];
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/human/operations/changeset.approve/v3")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://proof.example.test")
        .header("proof-csrf", "some-csrf-value")
        .header(header::CONTENT_LENGTH, garbage.len().to_string())
        .body(Body::from(garbage))
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response_code(response).await, "proof.input.too_large");

    // A valid-JSON spelling over the limit is rejected identically.
    let valid = format!("{{\"input\":\"{}\"}}", "a".repeat(RAW_BODY_LIMIT_BYTES + 1));
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/human/operations/changeset.approve/v3")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://proof.example.test")
        .header("proof-csrf", "some-csrf-value")
        .header(header::CONTENT_LENGTH, valid.len().to_string())
        .body(Body::from(valid))
        .expect("request constructs");
    let response = app.oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response_code(response).await, "proof.input.too_large");
}

#[tokio::test]
async fn duplicate_json_names_reject_with_400() {
    let body = br#"{"operation":{"name":"changeset.approve","version":"proof.dev/operation/changeset.approve/v3"},"operation":{"name":"release.get","version":"proof.dev/operation/release.get/v2"}}"#;
    let rejection = canonical_guard(body.to_vec())
        .await
        .err()
        .expect("duplicate names reject");
    assert_eq!(rejection.tuple.code, "proof.input.invalid_json");
    assert_eq!(rejection.tuple.status, 400);
}

#[tokio::test]
async fn unknown_members_are_deferred_to_the_route_schema() {
    let body = br#"{"api_version":"proof.dev/http-human-operation-request/v1","operation":{"name":"changeset.approve","version":"proof.dev/operation/changeset.approve/v3"},"bogus_member":true}"#;
    canonical_guard(body.to_vec())
        .await
        .expect("strict JSON parsing precedes the route-specific closed Schema");
}

#[tokio::test]
async fn malformed_json_rejects_with_400() {
    let rejection = canonical_guard(b"{not valid json".to_vec())
        .await
        .err()
        .expect("malformed JSON rejects");
    assert_eq!(rejection.tuple.code, "proof.input.invalid_json");
    assert_eq!(rejection.tuple.status, 400);
}

#[tokio::test]
async fn non_json_content_type_rejects_415() {
    async fn handler(_guard: ContentTypeGuard) -> StatusCode {
        StatusCode::OK
    }
    let app = axum::Router::new().route("/test", axum::routing::post(handler));

    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("{}"))
        .expect("request constructs");
    let response = app.oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response_code(response).await,
        "proof.input.unsupported_media_type"
    );
}

#[tokio::test]
async fn origin_guard_accepts_same_origin_and_rejects_hostile() {
    async fn handler(_guard: OriginGuard) -> StatusCode {
        StatusCode::OK
    }
    let app = axum::Router::new().route("/test", axum::routing::post(handler));

    // Exact same-origin origin passes.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://proof.example.test")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::OK);

    // Hostile origin fails closed with 403 CSRF denial.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://evil.example.test")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_code(response).await, "proof.auth.csrf_denied");

    // Missing origin fails closed.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header(header::HOST, "proof.example.test")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_code(response).await, "proof.auth.csrf_denied");

    // A `null` origin fails closed.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "null")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_code(response).await, "proof.auth.csrf_denied");
}

#[tokio::test]
async fn csrf_guard_accepts_present_and_rejects_missing() {
    async fn handler(_guard: CsrfGuard) -> StatusCode {
        StatusCode::OK
    }
    let app = axum::Router::new().route("/test", axum::routing::post(handler));

    // A present, non-empty synchronizer passes the presence check.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header("proof-csrf", "some-synchronizer-value")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::OK);

    // A missing synchronizer fails closed with 403 CSRF denial.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.clone().oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_code(response).await, "proof.auth.csrf_denied");

    // An empty synchronizer fails closed.
    let request = Request::builder()
        .method("POST")
        .uri("/test")
        .header("proof-csrf", "")
        .body(Body::empty())
        .expect("request constructs");
    let response = app.oneshot(request).await.expect("router serves");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_code(response).await, "proof.auth.csrf_denied");
}

#[tokio::test]
async fn canonical_size_rejects_when_body_expands_past_1mib() {
    // `1e20` is four raw bytes but canonicalizes to the fixed 21-byte
    // `100000000000000000000`, so this body is small raw (~250 KiB) yet expands
    // past the 1 MiB canonical bound. This proves the canonical limit is
    // enforced independently of the raw-body limit.
    let mut numbers = String::new();
    for _ in 0..50_000 {
        numbers.push_str("1e20,");
    }
    numbers.pop(); // drop the trailing comma
    let body = format!("{{\"input\":[{numbers}]}}");

    assert!(
        body.len() < RAW_BODY_LIMIT_BYTES,
        "the raw body must stay under the raw limit"
    );

    let rejection = canonical_guard(body.into_bytes())
        .await
        .err()
        .expect("canonical expansion past the bound rejects");
    assert_eq!(rejection.tuple.code, "proof.input.too_large");
    assert_eq!(rejection.tuple.status, 413);
}
