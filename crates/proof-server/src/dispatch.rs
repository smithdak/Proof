//! Route-qualified registry dispatch, the success/Problem envelopes, and the
//! adapter rate limiter (contract §"HTTP boundary", §"Envelopes, Problems, and
//! HTTP semantics").

use std::sync::Mutex;
use std::time::Instant;

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue};
use proof_remote::{
    AuthorityHeadV1, HttpRouteV1, RemoteOperationV1, cross_check_route_operation,
    identity::AuthenticatedActorContextV2,
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{AppState, PROBLEM_CONTENT_TYPE, ServerError, issuer::b64url_encode};

/// Success envelope `api_version` (contract §"Envelopes, Problems, and HTTP
/// semantics").
pub const SUCCESS_ENVELOPE_API_VERSION: &str = "proof.dev/http-operation-result/v1";

/// Problem envelope `api_version` (contract §"Envelopes, Problems, and HTTP
/// semantics").
pub const PROBLEM_API_VERSION: &str = "proof.dev/http-problem/v1";

/// One frozen RFC 9457 Problem registry tuple `(code, status, type, title,
/// retryable)` (contract §"Envelopes, Problems, and HTTP semantics").
///
/// The exact 41-tuple set mirrors the normative
/// `http-operation-registry.valid.json` machine vector; no adapter may
/// substitute a different title, status, type, or retry flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemTuple {
    /// Stable machine-readable Proof code.
    pub code: &'static str,
    /// Exact HTTP status.
    pub status: u16,
    /// Controlled problem type URI.
    pub type_uri: &'static str,
    /// Stable human summary.
    pub title: &'static str,
    /// Whether retry may succeed without changing input.
    pub retryable: bool,
}

impl ProblemTuple {
    /// Binds one exact registry tuple.
    #[must_use]
    pub const fn new(
        code: &'static str,
        status: u16,
        type_uri: &'static str,
        title: &'static str,
        retryable: bool,
    ) -> Self {
        Self {
            code,
            status,
            type_uri,
            title,
            retryable,
        }
    }
}

/// The exact 41-tuple HTTP Problem registry (contract §"Envelopes, Problems,
/// and HTTP semantics").
pub const PROBLEM_REGISTRY: [ProblemTuple; 41] = [
    ProblemTuple::new(
        "proof.auth.csrf_denied",
        403,
        "urn:proof:problem:csrf-denied",
        "CSRF validation denied",
        false,
    ),
    ProblemTuple::new(
        "proof.auth.denied",
        401,
        "urn:proof:problem:authentication-denied",
        "Authentication denied",
        false,
    ),
    ProblemTuple::new(
        "proof.auth.replay",
        401,
        "urn:proof:problem:authentication-replay",
        "Authentication replay denied",
        false,
    ),
    ProblemTuple::new(
        "proof.authority.integrity",
        500,
        "urn:proof:problem:authority-integrity",
        "Authority integrity failure",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.budget_exceeded",
        403,
        "urn:proof:problem:authorization-budget-exceeded",
        "Authorization budget exceeded",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.delegation_expired",
        403,
        "urn:proof:problem:authorization-delegation-expired",
        "Authorization delegation expired",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.delegation_not_yet_valid",
        403,
        "urn:proof:problem:authorization-delegation-not-yet-valid",
        "Authorization delegation not yet valid",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.delegation_revoked",
        403,
        "urn:proof:problem:authorization-delegation-revoked",
        "Authorization delegation revoked",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.denied",
        403,
        "urn:proof:problem:authorization-denied",
        "Authorization denied",
        false,
    ),
    ProblemTuple::new(
        "proof.authorization.scope_exceeded",
        403,
        "urn:proof:problem:authorization-scope-exceeded",
        "Authorization scope exceeded",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.duplicate_target",
        409,
        "urn:proof:problem:changeset-duplicate-target",
        "ChangeSet duplicate target",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.invalid_supersession",
        409,
        "urn:proof:problem:changeset-invalid-supersession",
        "ChangeSet invalid supersession",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.not_approved",
        409,
        "urn:proof:problem:changeset-not-approved",
        "ChangeSet not approved",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.not_draft",
        409,
        "urn:proof:problem:changeset-not-draft",
        "ChangeSet not draft",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.not_ready",
        409,
        "urn:proof:problem:changeset-not-ready",
        "ChangeSet not ready",
        false,
    ),
    ProblemTuple::new(
        "proof.changeset.not_submitted",
        409,
        "urn:proof:problem:changeset-not-submitted",
        "ChangeSet not submitted",
        false,
    ),
    ProblemTuple::new(
        "proof.delegation.expired",
        403,
        "urn:proof:problem:delegation-expired",
        "Delegation expired",
        false,
    ),
    ProblemTuple::new(
        "proof.dependency.unavailable",
        503,
        "urn:proof:problem:dependency-unavailable",
        "Dependency unavailable",
        true,
    ),
    ProblemTuple::new(
        "proof.digest.mismatch",
        500,
        "urn:proof:problem:digest-mismatch",
        "Digest mismatch",
        false,
    ),
    ProblemTuple::new(
        "proof.evidence.incomplete",
        409,
        "urn:proof:problem:evidence-incomplete",
        "Evidence incomplete",
        false,
    ),
    ProblemTuple::new(
        "proof.idempotency.key_reused",
        409,
        "urn:proof:problem:idempotency-key-reused",
        "Idempotency key reused",
        false,
    ),
    ProblemTuple::new(
        "proof.input.invalid_json",
        400,
        "urn:proof:problem:invalid-json",
        "Invalid JSON",
        false,
    ),
    ProblemTuple::new(
        "proof.input.intent_mismatch",
        409,
        "urn:proof:problem:intent-mismatch",
        "Input intent mismatch",
        false,
    ),
    ProblemTuple::new(
        "proof.input.limit_exceeded",
        413,
        "urn:proof:problem:input-limit-exceeded",
        "Input limit exceeded",
        false,
    ),
    ProblemTuple::new(
        "proof.input.schema_mismatch",
        400,
        "urn:proof:problem:schema-mismatch",
        "Schema mismatch",
        false,
    ),
    ProblemTuple::new(
        "proof.input.too_large",
        413,
        "urn:proof:problem:input-too-large",
        "Input too large",
        false,
    ),
    ProblemTuple::new(
        "proof.input.unsupported_media_type",
        415,
        "urn:proof:problem:unsupported-media-type",
        "Unsupported media type",
        false,
    ),
    ProblemTuple::new(
        "proof.input.unsupported_version",
        400,
        "urn:proof:problem:unsupported-version",
        "Unsupported version",
        false,
    ),
    ProblemTuple::new(
        "proof.integrity.failure",
        500,
        "urn:proof:problem:integrity-failure",
        "Integrity failure",
        false,
    ),
    ProblemTuple::new(
        "proof.internal",
        500,
        "urn:proof:problem:internal",
        "Internal error",
        false,
    ),
    ProblemTuple::new(
        "proof.operation.timeout",
        504,
        "urn:proof:problem:operation-timeout",
        "Operation timed out",
        true,
    ),
    ProblemTuple::new(
        "proof.operation.unknown_outcome",
        504,
        "urn:proof:problem:unknown-outcome",
        "Operation outcome unknown",
        true,
    ),
    ProblemTuple::new(
        "proof.policy.denied",
        403,
        "urn:proof:problem:policy-denied",
        "Policy denied",
        false,
    ),
    ProblemTuple::new(
        "proof.rate_limit.exceeded",
        429,
        "urn:proof:problem:rate-limit-exceeded",
        "Rate limit exceeded",
        true,
    ),
    ProblemTuple::new(
        "proof.resource.not_found",
        404,
        "urn:proof:problem:resource-not-found",
        "Resource not found",
        false,
    ),
    ProblemTuple::new(
        "proof.state.conflict",
        409,
        "urn:proof:problem:state-conflict",
        "State conflict",
        false,
    ),
    ProblemTuple::new(
        "proof.state.source_conflict",
        409,
        "urn:proof:problem:source-state-conflict",
        "Source state conflict",
        false,
    ),
    ProblemTuple::new(
        "proof.state.target_conflict",
        409,
        "urn:proof:problem:target-state-conflict",
        "Target state conflict",
        false,
    ),
    ProblemTuple::new(
        "proof.storage.conflict",
        503,
        "urn:proof:problem:storage-conflict",
        "Storage conflict",
        true,
    ),
    ProblemTuple::new(
        "proof.validation.failed",
        422,
        "urn:proof:problem:validation-failed",
        "Validation failed",
        false,
    ),
    ProblemTuple::new(
        "proof.validation.repair_evidence_invalid",
        422,
        "urn:proof:problem:repair-evidence-invalid",
        "Repair evidence invalid",
        false,
    ),
];

/// Looks up one exact registry tuple by stable code.
#[must_use]
pub fn problem_tuple(code: &str) -> Option<ProblemTuple> {
    PROBLEM_REGISTRY
        .iter()
        .copied()
        .find(|tuple| tuple.code == code)
}

/// The exact structured success envelope (contract §"Envelopes, Problems, and
/// HTTP semantics").
#[derive(Clone, Debug, Serialize)]
pub struct SuccessEnvelope {
    /// Exact `proof.dev/http-operation-result/v1` tag.
    pub api_version: String,
    /// Exact operation name/version pair.
    pub operation: RemoteOperationV1,
    /// Server-generated UUIDv7 operation identifier.
    pub operation_id: String,
    /// Optional validated caller UUIDv7 correlation identifier.
    pub correlation_id: Option<String>,
    /// Committed snapshot or immutable-result anchor.
    pub committed_anchor: Value,
    /// Unchanged typed application result.
    pub result: Value,
}

impl SuccessEnvelope {
    /// Binds the exact operation/version, identifiers, anchor, and result.
    #[must_use]
    pub fn new(
        operation: RemoteOperationV1,
        operation_id: String,
        correlation_id: Option<String>,
        committed_anchor: Value,
        result: Value,
    ) -> Self {
        Self {
            api_version: SUCCESS_ENVELOPE_API_VERSION.to_owned(),
            operation,
            operation_id,
            correlation_id,
            committed_anchor,
            result,
        }
    }
}

/// A disclosure-neutral RFC 9457 `application/problem+json` response (contract
/// §"Envelopes, Problems, and HTTP semantics").
#[derive(Clone, Debug)]
pub struct ProblemResponse {
    /// The exact registry tuple.
    pub tuple: ProblemTuple,
    /// Exact operation name/version pair, when the problem is operation-scoped.
    pub operation: Option<RemoteOperationV1>,
    /// Server-generated UUIDv7 operation identifier.
    pub operation_id: String,
    /// Optional validated caller UUIDv7 correlation identifier.
    pub correlation_id: Option<String>,
    /// Authorized retry delay in milliseconds (429 only).
    pub retry_after_ms: Option<u64>,
}

impl ProblemResponse {
    /// Builds a disclosure-neutral Problem from a registry tuple.
    #[must_use]
    pub fn new(
        tuple: ProblemTuple,
        operation: Option<RemoteOperationV1>,
        operation_id: String,
        correlation_id: Option<String>,
    ) -> Self {
        Self {
            tuple,
            operation,
            operation_id,
            correlation_id,
            retry_after_ms: None,
        }
    }

    /// Builds a 429 with the authorized `Retry-After` delay.
    #[must_use]
    pub fn rate_limited(operation_id: String, retry_after_ms: u64) -> Self {
        Self {
            tuple: problem_tuple("proof.rate_limit.exceeded")
                .expect("proof.rate_limit.exceeded is a frozen registry tuple"),
            operation: None,
            operation_id,
            correlation_id: None,
            retry_after_ms: Some(retry_after_ms),
        }
    }
}

impl IntoResponse for ProblemResponse {
    fn into_response(self) -> Response {
        let mut body = json!({
            "api_version": PROBLEM_API_VERSION,
            "type": self.tuple.type_uri,
            "title": self.tuple.title,
            "status": self.tuple.status,
            "code": self.tuple.code,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "correlation_id": self.correlation_id,
            "retryable": self.tuple.retryable,
            "instance": format!("urn:proof:operation:{}", self.operation_id),
        });
        if let Some(retry_after_ms) = self.retry_after_ms {
            body["retry_after_ms"] = json!(retry_after_ms);
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
        );
        if let Some(retry_after_ms) = self.retry_after_ms {
            let seconds = retry_after_ms.div_ceil(1_000);
            headers.insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&seconds.to_string())
                    .unwrap_or_else(|_| HeaderValue::from_static("1")),
            );
        }

        (
            StatusCode::from_u16(self.tuple.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            headers,
            Json(body),
        )
            .into_response()
    }
}

/// Token-bucket rate limiter (contract §"HTTP boundary"). This is an adapter
/// denial control, never authority.
pub struct RateLimiter {
    budget: crate::RateLimitBudget,
    state: Mutex<TokenBucket>,
}

/// Token-bucket state.
#[derive(Clone, Copy, Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Constructs a token-bucket limiter from a budget.
    #[must_use]
    pub fn new(budget: crate::RateLimitBudget) -> Self {
        Self {
            budget,
            state: Mutex::new(TokenBucket {
                tokens: budget.capacity as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    /// Consumes one token if available, refilling at the configured rate.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::RateLimited`] when the bucket is empty.
    pub fn try_acquire(&self) -> Result<(), ServerError> {
        todo!("refill token bucket and consume one token or deny")
    }
}

/// One route-qualified dispatch request, assembled after strict parsing,
/// session/CSRF authentication, and dual Agent presentation proof (contract
/// §"HTTP boundary").
#[derive(Clone, Debug)]
pub struct DispatchRequest {
    /// Exact route.
    pub route: HttpRouteV1,
    /// Path terminal `{name}` token.
    pub path_name: String,
    /// Path terminal `{major}` token (`v1`, `v2`, ...).
    pub path_major: String,
    /// Exact body operation name/version pair.
    pub operation: RemoteOperationV1,
    /// Normalized application input.
    pub normalized_input: Value,
    /// Adapter-derived protected actor context.
    pub actor_context: AuthenticatedActorContextV2,
    /// Optional validated caller UUIDv7 correlation identifier.
    pub correlation_id: Option<String>,
}

/// Dispatches one route-qualified operation against the P-0009 registries and
/// the P-0010 unit of work (contract §"HTTP boundary").
///
/// # Errors
///
/// Returns a disclosure-neutral [`ProblemResponse`] on any cross-check,
/// authentication, authorization, storage, deadline, or limit failure.
pub fn dispatch(
    _state: &AppState,
    request: DispatchRequest,
) -> Result<SuccessEnvelope, ProblemResponse> {
    todo!("route-qualified cross-check, rate limit, deadline, unit of work")
}

/// Cross-checks the path name/major, invocation operation, and route-qualified
/// registry row; a mismatch fails before application execution (contract §"HTTP
/// boundary").
///
/// # Errors
///
/// Returns [`ServerError::Dispatch`] on any cross-check mismatch.
pub fn cross_check_dispatch_request(request: &DispatchRequest) -> Result<(), ServerError> {
    cross_check_route_operation(
        request.route,
        &request.path_name,
        &request.path_major,
        &request.operation,
    )
    .map_err(|error| ServerError::Dispatch(error.to_string()))
}

/// Maps an internal [`ServerError`] onto the disclosure-neutral Problem
/// projection for a route (contract §"Envelopes, Problems, and HTTP
/// semantics").
#[must_use]
pub fn map_server_error(
    error: &ServerError,
    operation: Option<RemoteOperationV1>,
    operation_id: String,
) -> ProblemResponse {
    let code = match error {
        ServerError::RateLimited => "proof.rate_limit.exceeded",
        ServerError::DeadlineExceeded => "proof.operation.timeout",
        ServerError::Storage(_) => "proof.storage.conflict",
        ServerError::Config(_) | ServerError::Internal(_) => "proof.internal",
        ServerError::Oidc(_)
        | ServerError::Authorization(_)
        | ServerError::Session(_)
        | ServerError::Csrf(_) => "proof.auth.denied",
        ServerError::Dispatch(_) => "proof.input.schema_mismatch",
    };
    let tuple = problem_tuple(code).expect("mapped code is a frozen registry tuple");
    ProblemResponse::new(tuple, operation, operation_id, None)
}

/// Derives a UUIDv7 operation identifier for an execution (contract §"HTTP
/// boundary").
#[must_use]
pub fn new_operation_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Computes the committed result anchor for a success envelope (contract
/// §"Envelopes, Problems, and HTTP semantics").
#[must_use]
pub fn committed_anchor(authority_head: &AuthorityHeadV1, result_digest: Option<&str>) -> Value {
    json!({
        "authority_head": {
            "sequence": authority_head.sequence,
            "record_digest": authority_head.record_digest.to_string(),
        },
        "result_digest": result_digest,
    })
}

/// Base64url-no-pad helper re-exported for the BFF's PKCE challenge.
#[must_use]
pub fn base64url_no_pad(bytes: &[u8]) -> String {
    b64url_encode(bytes)
}
