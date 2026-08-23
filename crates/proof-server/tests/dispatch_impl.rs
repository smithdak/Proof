//! Integration tests for the route-qualified dispatch surface: the exact
//! 41-tuple Problem registry, the RFC 9457 Problem projection, the success
//! envelope, cross-check disagreement, status mapping, and the token-bucket
//! rate limiter (contract §"Envelopes, Problems, and HTTP semantics",
//! §"HTTP boundary").
//!
//! No database, network, or socket binding is required.

#![allow(clippy::too_many_lines)]

use axum::http::StatusCode;
use axum::response::IntoResponse;
use proof_server::dispatch::{
    DispatchRequest, PROBLEM_REGISTRY, ProblemResponse, RateLimiter, SuccessEnvelope,
    committed_anchor, cross_check_dispatch_request, dispatch, map_server_error, new_operation_id,
    problem_tuple, validate_correlation_id,
};
use proof_server::proof_domain::{ContentDigest, Timestamp, WorkspaceId};
use proof_server::proof_remote::{
    AuthorityHeadV1, HttpRouteV1, RemoteOperationV1,
    identity::{
        AuthenticatedActorContextApiVersion, AuthenticatedActorContextHumanV2,
        OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1,
        OidcHumanAuthenticationProfile,
    },
    oracle::IdentityFixtureV1,
};
use proof_server::{AppState, RateLimitBudget, ServerConfig, ServerError};
use serde_json::{Value, json};

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const BINDING_ID: &str = "019c0000-0000-7000-8000-000000000002";
const PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000003";
const AUTH_EVENT_ID: &str = "019c0000-0000-7000-8000-000000000004";
const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000005";
const OP_ID: &str = "019c0000-0000-7000-8000-000000000006";
const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";
const HUMAN_OP: &str = "proof.dev/operation/changeset.get/v2";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn digest() -> ContentDigest {
    ContentDigest::blake3([0x5a; 32])
}

fn timestamp() -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(1_700_000_000_000_000_000).expect("valid timestamp")
}

fn operation(name: &str, version: &str) -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn human_context(
    op: &RemoteOperationV1,
) -> proof_server::proof_remote::AuthenticatedActorContextV2 {
    proof_server::proof_remote::AuthenticatedActorContextV2::Human(
        AuthenticatedActorContextHumanV2 {
            api_version: AuthenticatedActorContextApiVersion::V1,
            audience: format!("proof://workspace/{WS_ID}"),
            authentication_profile: OidcHumanAuthenticationProfile::V1,
            oidc_issuer_configuration_digest: digest(),
            normalized_input_digest: digest(),
            requesting_subject: OidcAuthenticatedSubjectV1 {
                api_version: OidcAuthenticatedSubjectApiVersion::V1,
                issuer: "https://issuer.example".to_owned(),
                provider: "proof/oidc".to_owned(),
                subject: "subject-1".to_owned(),
            },
            requesting_subject_commitment: digest(),
            requesting_binding_id: BINDING_ID.to_owned(),
            requesting_binding_record_digest: digest(),
            requesting_principal_id: PRINCIPAL_ID.to_owned(),
            authentication_event_id: AUTH_EVENT_ID.to_owned(),
            authentication_event_digest: digest(),
            operation: op.clone(),
            authenticated_at: timestamp(),
            evaluated_authority_head: AuthorityHeadV1 {
                sequence: 1,
                record_digest: digest(),
            },
            workspace_id: WS_ID.to_owned(),
        },
    )
}

/// A route-consistent Human dispatch request for `changeset.get/v2`.
fn valid_request(correlation_id: Option<String>) -> DispatchRequest {
    let op = operation("changeset.get", HUMAN_OP);
    DispatchRequest {
        route: HttpRouteV1::HumanOperations,
        path_name: "changeset.get".to_owned(),
        path_major: "v2".to_owned(),
        operation: op.clone(),
        normalized_input: json!({}),
        actor_context: human_context(&op),
        correlation_id,
    }
}

/// An `AppState` built without opening a database connection.
fn app_state() -> AppState {
    let config = ServerConfig::new(
        "127.0.0.1:0".parse().expect("listen address"),
        WS_ID.parse::<WorkspaceId>().expect("workspace id"),
        IdentityFixtureV1::deterministic().issuer_configuration,
        "deployment-secret:test",
        [0x11; 32],
        "postgres://postgres@127.0.0.1:55432/prooftest".to_owned(),
    );
    AppState::new(config)
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1_048_576)
        .await
        .expect("collect response body");
    serde_json::from_slice(&bytes).expect("response body is valid JSON")
}

async fn problem_body_json(problem: ProblemResponse) -> (StatusCode, Value) {
    let response = problem.into_response();
    let status = response.status();
    let body = body_json(response).await;
    (status, body)
}

// ---------------------------------------------------------------------------
// 1. The exact 41-tuple Problem registry
// ---------------------------------------------------------------------------

#[test]
fn problem_registry_is_exactly_41_frozen_tuples() {
    let expected: [(&str, u16, &str, &str, bool); 41] = [
        (
            "proof.auth.csrf_denied",
            403,
            "urn:proof:problem:csrf-denied",
            "CSRF validation denied",
            false,
        ),
        (
            "proof.auth.denied",
            401,
            "urn:proof:problem:authentication-denied",
            "Authentication denied",
            false,
        ),
        (
            "proof.auth.replay",
            401,
            "urn:proof:problem:authentication-replay",
            "Authentication replay denied",
            false,
        ),
        (
            "proof.authority.integrity",
            500,
            "urn:proof:problem:authority-integrity",
            "Authority integrity failure",
            false,
        ),
        (
            "proof.authorization.budget_exceeded",
            403,
            "urn:proof:problem:authorization-budget-exceeded",
            "Authorization budget exceeded",
            false,
        ),
        (
            "proof.authorization.delegation_expired",
            403,
            "urn:proof:problem:authorization-delegation-expired",
            "Authorization delegation expired",
            false,
        ),
        (
            "proof.authorization.delegation_not_yet_valid",
            403,
            "urn:proof:problem:authorization-delegation-not-yet-valid",
            "Authorization delegation not yet valid",
            false,
        ),
        (
            "proof.authorization.delegation_revoked",
            403,
            "urn:proof:problem:authorization-delegation-revoked",
            "Authorization delegation revoked",
            false,
        ),
        (
            "proof.authorization.denied",
            403,
            "urn:proof:problem:authorization-denied",
            "Authorization denied",
            false,
        ),
        (
            "proof.authorization.scope_exceeded",
            403,
            "urn:proof:problem:authorization-scope-exceeded",
            "Authorization scope exceeded",
            false,
        ),
        (
            "proof.changeset.duplicate_target",
            409,
            "urn:proof:problem:changeset-duplicate-target",
            "ChangeSet duplicate target",
            false,
        ),
        (
            "proof.changeset.invalid_supersession",
            409,
            "urn:proof:problem:changeset-invalid-supersession",
            "ChangeSet invalid supersession",
            false,
        ),
        (
            "proof.changeset.not_approved",
            409,
            "urn:proof:problem:changeset-not-approved",
            "ChangeSet not approved",
            false,
        ),
        (
            "proof.changeset.not_draft",
            409,
            "urn:proof:problem:changeset-not-draft",
            "ChangeSet not draft",
            false,
        ),
        (
            "proof.changeset.not_ready",
            409,
            "urn:proof:problem:changeset-not-ready",
            "ChangeSet not ready",
            false,
        ),
        (
            "proof.changeset.not_submitted",
            409,
            "urn:proof:problem:changeset-not-submitted",
            "ChangeSet not submitted",
            false,
        ),
        (
            "proof.delegation.expired",
            403,
            "urn:proof:problem:delegation-expired",
            "Delegation expired",
            false,
        ),
        (
            "proof.dependency.unavailable",
            503,
            "urn:proof:problem:dependency-unavailable",
            "Dependency unavailable",
            true,
        ),
        (
            "proof.digest.mismatch",
            500,
            "urn:proof:problem:digest-mismatch",
            "Digest mismatch",
            false,
        ),
        (
            "proof.evidence.incomplete",
            409,
            "urn:proof:problem:evidence-incomplete",
            "Evidence incomplete",
            false,
        ),
        (
            "proof.idempotency.key_reused",
            409,
            "urn:proof:problem:idempotency-key-reused",
            "Idempotency key reused",
            false,
        ),
        (
            "proof.input.invalid_json",
            400,
            "urn:proof:problem:invalid-json",
            "Invalid JSON",
            false,
        ),
        (
            "proof.input.intent_mismatch",
            409,
            "urn:proof:problem:intent-mismatch",
            "Input intent mismatch",
            false,
        ),
        (
            "proof.input.limit_exceeded",
            413,
            "urn:proof:problem:input-limit-exceeded",
            "Input limit exceeded",
            false,
        ),
        (
            "proof.input.schema_mismatch",
            400,
            "urn:proof:problem:schema-mismatch",
            "Schema mismatch",
            false,
        ),
        (
            "proof.input.too_large",
            413,
            "urn:proof:problem:input-too-large",
            "Input too large",
            false,
        ),
        (
            "proof.input.unsupported_media_type",
            415,
            "urn:proof:problem:unsupported-media-type",
            "Unsupported media type",
            false,
        ),
        (
            "proof.input.unsupported_version",
            400,
            "urn:proof:problem:unsupported-version",
            "Unsupported version",
            false,
        ),
        (
            "proof.integrity.failure",
            500,
            "urn:proof:problem:integrity-failure",
            "Integrity failure",
            false,
        ),
        (
            "proof.internal",
            500,
            "urn:proof:problem:internal",
            "Internal error",
            false,
        ),
        (
            "proof.operation.timeout",
            504,
            "urn:proof:problem:operation-timeout",
            "Operation timed out",
            true,
        ),
        (
            "proof.operation.unknown_outcome",
            504,
            "urn:proof:problem:unknown-outcome",
            "Operation outcome unknown",
            true,
        ),
        (
            "proof.policy.denied",
            403,
            "urn:proof:problem:policy-denied",
            "Policy denied",
            false,
        ),
        (
            "proof.rate_limit.exceeded",
            429,
            "urn:proof:problem:rate-limit-exceeded",
            "Rate limit exceeded",
            true,
        ),
        (
            "proof.resource.not_found",
            404,
            "urn:proof:problem:resource-not-found",
            "Resource not found",
            false,
        ),
        (
            "proof.state.conflict",
            409,
            "urn:proof:problem:state-conflict",
            "State conflict",
            false,
        ),
        (
            "proof.state.source_conflict",
            409,
            "urn:proof:problem:source-state-conflict",
            "Source state conflict",
            false,
        ),
        (
            "proof.state.target_conflict",
            409,
            "urn:proof:problem:target-state-conflict",
            "Target state conflict",
            false,
        ),
        (
            "proof.storage.conflict",
            503,
            "urn:proof:problem:storage-conflict",
            "Storage conflict",
            true,
        ),
        (
            "proof.validation.failed",
            422,
            "urn:proof:problem:validation-failed",
            "Validation failed",
            false,
        ),
        (
            "proof.validation.repair_evidence_invalid",
            422,
            "urn:proof:problem:repair-evidence-invalid",
            "Repair evidence invalid",
            false,
        ),
    ];

    assert_eq!(PROBLEM_REGISTRY.len(), 41);
    for (index, tuple) in PROBLEM_REGISTRY.iter().enumerate() {
        let (code, status, type_uri, title, retryable) = expected[index];
        assert_eq!(tuple.code, code, "tuple {index} code");
        assert_eq!(tuple.status, status, "tuple {index} status");
        assert_eq!(tuple.type_uri, type_uri, "tuple {index} type");
        assert_eq!(tuple.title, title, "tuple {index} title");
        assert_eq!(tuple.retryable, retryable, "tuple {index} retryable");
    }

    // Codes are unique and the lookup round-trips every tuple exactly.
    let mut codes: Vec<&str> = PROBLEM_REGISTRY.iter().map(|t| t.code).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), 41, "registry codes must be unique");
    for tuple in &PROBLEM_REGISTRY {
        assert_eq!(problem_tuple(tuple.code), Some(*tuple));
    }
    assert!(problem_tuple("proof.does.not.exist").is_none());
}

// ---------------------------------------------------------------------------
// 2. Problem serialization carries only the allowed members
// ---------------------------------------------------------------------------

#[tokio::test]
async fn problem_response_serializes_exactly_the_allowed_members() {
    let tuple = problem_tuple("proof.validation.failed").expect("frozen tuple");
    let op = operation(
        "changeset.validate",
        "proof.dev/operation/changeset.validate/v2",
    );
    let problem = ProblemResponse::new(
        tuple,
        Some(op),
        OP_ID.to_owned(),
        Some(CORRELATION_ID.to_owned()),
    );

    let response = problem.into_response();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json"
    );

    let body = body_json(response).await;
    let object = body.as_object().expect("problem body is an object");

    // RFC 9457 base members plus the exact allowed extension members.
    let allowed: &[&str] = &[
        "api_version",
        "type",
        "title",
        "status",
        "detail",
        "instance",
        "code",
        "operation",
        "operation_id",
        "correlation_id",
        "retryable",
        "retry_after_ms",
        "current_digest",
        "findings",
    ];
    for key in object.keys() {
        assert!(allowed.contains(&key.as_str()), "unexpected member `{key}`");
    }

    let required = [
        "api_version",
        "type",
        "title",
        "status",
        "code",
        "operation",
        "operation_id",
        "correlation_id",
        "retryable",
        "instance",
    ];
    for member in required {
        assert!(
            object.contains_key(member),
            "missing required member `{member}`"
        );
    }

    assert_eq!(body["api_version"], "proof.dev/http-problem/v1");
    assert_eq!(body["type"], tuple.type_uri);
    assert_eq!(body["title"], tuple.title);
    assert_eq!(body["status"].as_u64(), Some(u64::from(tuple.status)));
    assert_eq!(body["code"], tuple.code);
    assert_eq!(body["retryable"].as_bool(), Some(tuple.retryable));
    assert_eq!(body["operation_id"], OP_ID);
    assert_eq!(body["correlation_id"], CORRELATION_ID);
    assert_eq!(body["operation"]["name"], "changeset.validate");
    assert_eq!(
        body["operation"]["version"],
        "proof.dev/operation/changeset.validate/v2"
    );
    assert_eq!(body["instance"], format!("urn:proof:operation:{OP_ID}"));

    // Optional members are absent when not authorized.
    assert!(object.get("retry_after_ms").is_none());
    assert!(object.get("current_digest").is_none());
    assert!(object.get("findings").is_none());
    assert!(object.get("detail").is_none());
}

#[tokio::test]
async fn rate_limited_problem_carries_retry_after() {
    let problem = ProblemResponse::rate_limited(OP_ID.to_owned(), 1500);
    let response = problem.into_response();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap(),
        "2"
    );
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/problem+json"
    );

    let body = body_json(response).await;
    assert_eq!(body["code"], "proof.rate_limit.exceeded");
    assert_eq!(body["status"].as_u64(), Some(429));
    assert_eq!(body["retryable"].as_bool(), Some(true));
    assert_eq!(body["retry_after_ms"].as_u64(), Some(1500));
}

// ---------------------------------------------------------------------------
// 3. Envelope construction and identifier validation
// ---------------------------------------------------------------------------

#[test]
fn new_operation_id_is_a_uuid_v7() {
    let id = new_operation_id();
    let parsed = uuid::Uuid::parse_str(&id).expect("operation id is a UUID");
    assert_eq!(parsed.get_version(), Some(uuid::Version::SortRand));
}

#[test]
fn correlation_id_validation_accepts_only_uuid_v7() {
    assert!(validate_correlation_id(None).is_ok());
    assert!(validate_correlation_id(Some(CORRELATION_ID)).is_ok());
    assert!(validate_correlation_id(Some("not-a-uuid")).is_err());
    assert!(validate_correlation_id(Some(UUID_V4)).is_err());
    assert!(validate_correlation_id(Some("")).is_err());
}

#[test]
fn success_envelope_binds_operation_and_identifiers() {
    let operation_id = new_operation_id();
    let envelope = SuccessEnvelope::new(
        operation(
            "workspace.status",
            "proof.dev/operation/workspace.status/v1",
        ),
        operation_id.clone(),
        Some(CORRELATION_ID.to_owned()),
        json!({ "authority_head": null }),
        json!({ "status": "initialized" }),
    );

    let value = serde_json::to_value(&envelope).expect("envelope serializes");
    assert_eq!(value["api_version"], "proof.dev/http-operation-result/v1");
    assert_eq!(value["operation"]["name"], "workspace.status");
    assert_eq!(
        value["operation"]["version"],
        "proof.dev/operation/workspace.status/v1"
    );
    assert_eq!(value["operation_id"], operation_id);
    assert_eq!(value["correlation_id"], CORRELATION_ID);
    assert!(value["result"].is_object());
    assert!(value["committed_anchor"].is_object());
}

#[test]
fn committed_anchor_binds_head_and_optional_result_digest() {
    let head = AuthorityHeadV1 {
        sequence: 7,
        record_digest: digest(),
    };
    let anchored = committed_anchor(
        &head,
        Some("blake3:0000000000000000000000000000000000000000000000000000000000000000"),
    );
    assert_eq!(anchored["authority_head"]["sequence"].as_u64(), Some(7));
    assert_eq!(
        anchored["authority_head"]["record_digest"],
        digest().to_string()
    );
    assert_eq!(
        anchored["result_digest"],
        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
    );

    let unanchored = committed_anchor(&head, None);
    assert!(unanchored["result_digest"].is_null());
}

#[test]
fn dispatch_rejects_invalid_correlation_before_execution() {
    let state = app_state();
    let request = valid_request(Some("not-a-uuid".to_owned()));
    let problem = dispatch(&state, request).expect_err("invalid correlation must be rejected");
    assert_eq!(problem.tuple.code, "proof.input.schema_mismatch");
    assert_eq!(problem.tuple.status, 400);
}

#[test]
fn dispatch_rejects_cross_check_mismatch_before_execution() {
    let state = app_state();
    let mut request = valid_request(None);
    request.path_major = "v3".to_owned();
    let problem = dispatch(&state, request).expect_err("path major mismatch must be rejected");
    assert_eq!(problem.tuple.code, "proof.input.schema_mismatch");
    assert_eq!(problem.tuple.status, 400);
}

// ---------------------------------------------------------------------------
// 4. Cross-check disagreement matrix
// ---------------------------------------------------------------------------

#[test]
fn cross_check_matrix_rejects_every_disagreement() {
    // Baseline passes.
    assert!(cross_check_dispatch_request(&valid_request(None)).is_ok());

    // Path name diverges from the body operation name.
    let mut req = valid_request(None);
    req.path_name = "changeset.diff".to_owned();
    assert!(cross_check_dispatch_request(&req).is_err());

    // Path major token diverges from the body operation version major.
    let mut req = valid_request(None);
    req.path_major = "v9".to_owned();
    assert!(cross_check_dispatch_request(&req).is_err());

    // Body operation name diverges from the path name.
    let mut req = valid_request(None);
    req.operation.name = "changeset.diff".to_owned();
    assert!(cross_check_dispatch_request(&req).is_err());

    // Body operation version has a different major token.
    let mut req = valid_request(None);
    req.operation.version = "proof.dev/operation/changeset.get/v3".to_owned();
    assert!(cross_check_dispatch_request(&req).is_err());

    // Unknown operation/version is not registered on the route.
    let mut req = valid_request(None);
    req.path_name = "does.not.exist".to_owned();
    req.path_major = "v1".to_owned();
    req.operation = operation("does.not.exist", "proof.dev/operation/does.not.exist/v1");
    assert!(cross_check_dispatch_request(&req).is_err());

    // A route that carries no name/major operation rows fails closed.
    let mut req = valid_request(None);
    req.route = HttpRouteV1::Capabilities;
    assert!(cross_check_dispatch_request(&req).is_err());

    // The adapter-derived actor context (signed invocation) must name the same
    // operation as the request.
    let mut req = valid_request(None);
    req.actor_context = human_context(&operation("other.op", "proof.dev/operation/other.op/v1"));
    assert!(cross_check_dispatch_request(&req).is_err());
}

// ---------------------------------------------------------------------------
// 5. Status mapping table
// ---------------------------------------------------------------------------

#[test]
fn map_server_error_projects_the_contract_table() {
    let op = Some(operation("changeset.get", HUMAN_OP));
    let cases: Vec<(ServerError, &str, u16, bool)> = vec![
        (
            ServerError::RateLimited,
            "proof.rate_limit.exceeded",
            429,
            true,
        ),
        (
            ServerError::DeadlineExceeded,
            "proof.operation.unknown_outcome",
            504,
            true,
        ),
        (
            ServerError::Storage(proof_pg::PgError::Transaction("x".to_owned())),
            "proof.storage.conflict",
            503,
            true,
        ),
        (
            ServerError::Config("x".to_owned()),
            "proof.internal",
            500,
            false,
        ),
        (
            ServerError::Internal("x".to_owned()),
            "proof.internal",
            500,
            false,
        ),
        (
            ServerError::Oidc("x".to_owned()),
            "proof.auth.denied",
            401,
            false,
        ),
        (
            ServerError::Session("x".to_owned()),
            "proof.auth.denied",
            401,
            false,
        ),
        (
            ServerError::Csrf("x".to_owned()),
            "proof.auth.csrf_denied",
            403,
            false,
        ),
        (
            ServerError::Authorization("x".to_owned()),
            "proof.authorization.denied",
            403,
            false,
        ),
        (
            ServerError::Dispatch("x".to_owned()),
            "proof.input.schema_mismatch",
            400,
            false,
        ),
    ];

    for (error, code, status, retryable) in cases {
        let problem = map_server_error(&error, op.clone(), OP_ID.to_owned());
        assert_eq!(problem.tuple.code, code, "code for {error:?}");
        assert_eq!(problem.tuple.status, status, "status for {code}");
        assert_eq!(problem.tuple.retryable, retryable, "retryable for {code}");
    }
}

// ---------------------------------------------------------------------------
// 6. Rate limiter exhausts and recovers
// ---------------------------------------------------------------------------

#[test]
fn rate_limiter_exhausts_and_recovers() {
    let budget = RateLimitBudget {
        capacity: 2,
        refill_per_second: 100,
    };
    let limiter = RateLimiter::new(budget);

    assert!(limiter.try_acquire().is_ok());
    assert!(limiter.try_acquire().is_ok());
    assert!(matches!(
        limiter.try_acquire(),
        Err(ServerError::RateLimited)
    ));

    // The authorized retry delay is the time to refill one token.
    assert_eq!(limiter.retry_after_ms(), 10);

    // After the refill interval, one token becomes available again.
    std::thread::sleep(std::time::Duration::from_millis(30));
    assert!(limiter.try_acquire().is_ok());
}

#[test]
fn dispatch_returns_429_with_retry_after_when_exhausted() {
    let mut state = app_state();
    state.rate_limiter = std::sync::Arc::new(RateLimiter::new(RateLimitBudget {
        capacity: 0,
        refill_per_second: 50,
    }));

    let problem = dispatch(&state, valid_request(None)).expect_err("exhausted bucket must deny");
    assert_eq!(problem.tuple.code, "proof.rate_limit.exceeded");
    assert_eq!(problem.tuple.status, 429);
    assert_eq!(problem.retry_after_ms, Some(20));
}

// ---------------------------------------------------------------------------
// 7. No raw diagnostic strings in any public response body
// ---------------------------------------------------------------------------

#[tokio::test]
async fn problem_bodies_never_leak_raw_diagnostics() {
    let op = Some(operation("changeset.get", HUMAN_OP));
    let cases: Vec<(ServerError, &str)> = vec![
        (
            ServerError::Internal(
                "SELECT secret FROM principals; backtrace: proof_server::dispatch::dispatch"
                    .to_owned(),
            ),
            "proof.internal",
        ),
        (
            ServerError::Oidc("subject=alice@example.com token=eyJhbGciOiJub25lIn0.raw".to_owned()),
            "proof.auth.denied",
        ),
        (
            ServerError::Storage(proof_pg::PgError::Transaction(
                "INSERT INTO secrets (value) VALUES ('x')".to_owned(),
            )),
            "proof.storage.conflict",
        ),
    ];

    for (error, code) in cases {
        let problem = map_server_error(&error, op.clone(), OP_ID.to_owned());
        let (status, body) = problem_body_json(problem).await;
        let text = body.to_string().to_lowercase();

        assert_eq!(body["code"], code);
        assert!(status.is_client_error() || status.is_server_error());

        for needle in [
            "select",
            "insert",
            "secret",
            "backtrace",
            "token",
            "eyj",
            "alice",
        ] {
            assert!(
                !text.contains(needle),
                "leaked `{needle}` in problem body `{text}`"
            );
        }
    }
}
