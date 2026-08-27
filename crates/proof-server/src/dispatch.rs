//! Route-qualified registry dispatch, the success/Problem envelopes, and the
//! adapter rate limiter (contract §"HTTP boundary", §"Envelopes, Problems, and
//! HTTP semantics").

use std::sync::Mutex;
use std::time::Instant;

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, HeaderValue};
use proof_domain::CorrelationId;
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
/// The exact 44-tuple set mirrors the normative
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

/// The exact 44-tuple HTTP Problem registry (contract §"Envelopes, Problems,
/// and HTTP semantics").
pub const PROBLEM_REGISTRY: [ProblemTuple; 44] = [
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
        "proof.intent.slot_mismatch",
        409,
        "urn:proof:problem:intent-slot-mismatch",
        "Resource intent creation slot mismatch",
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
        "proof.schema.not_found",
        404,
        "urn:proof:problem:schema-not-found",
        "Schema not found",
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
        "proof.state.object_exists",
        409,
        "urn:proof:problem:object-exists",
        "Object already exists",
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

        // Serialize to bytes directly so the explicit RFC 9457 media type stays
        // the single primary Content-Type (axum's `Json` would inject
        // `application/json` and downgrade the header to a duplicate value).
        let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
        (
            StatusCode::from_u16(self.tuple.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            headers,
            axum::body::Body::from(bytes),
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
    /// Returns [`ServerError::RateLimited`] when the bucket is empty, or
    /// [`ServerError::Internal`] if the bucket lock is poisoned.
    pub fn try_acquire(&self) -> Result<(), ServerError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ServerError::Internal("rate limiter state is poisoned".to_owned()))?;
        let now = Instant::now();
        let elapsed = now.duration_since(state.last_refill).as_secs_f64();
        let refill = elapsed * self.budget.refill_per_second as f64;
        state.tokens = (state.tokens + refill).min(self.budget.capacity as f64);
        state.last_refill = now;
        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            Err(ServerError::RateLimited)
        }
    }

    /// Returns the authorized retry delay in milliseconds for an exhausted
    /// bucket: the time to refill one token at the configured rate, bounded to
    /// the contract's `1..=300_000` `retry_after_ms` interval.
    #[must_use]
    pub fn retry_after_ms(&self) -> u64 {
        let refill = self.budget.refill_per_second;
        if refill == 0 {
            return 300_000;
        }
        // `ceil(1_000 / refill)` without float-to-int truncation.
        1_000_u64.div_ceil(refill).clamp(1, 300_000)
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
    /// Verified Agent evidence awaiting atomic persistence. Human requests do
    /// not carry this field.
    pub agent_attempt: Option<crate::authz::PreparedAgentAttempt>,
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
    state: &AppState,
    request: DispatchRequest,
) -> Result<SuccessEnvelope, ProblemResponse> {
    let operation_id = new_operation_id();
    let operation = request.operation.clone();

    // 1. Bounded adapter rate limit (denial control, never authority).
    match state.rate_limiter.try_acquire() {
        Ok(()) => {}
        Err(ServerError::RateLimited) => {
            return Err(ProblemResponse::rate_limited(
                operation_id,
                state.rate_limiter.retry_after_ms(),
            ));
        }
        Err(error) => return Err(map_server_error(&error, Some(operation), operation_id)),
    }

    // 2. The caller-supplied correlation identifier must be an exact UUIDv7.
    if let Err(error) = validate_correlation_id(request.correlation_id.as_deref()) {
        return Err(map_server_error(&error, Some(operation), operation_id));
    }
    let correlation_id = request.correlation_id.clone();

    // 3. Path/body/invocation/capability cross-check before any application
    // execution; a mismatch fails closed.
    if let Err(error) = cross_check_dispatch_request(&request) {
        return Err(map_server_error_with_correlation(
            &error,
            Some(operation),
            operation_id,
            correlation_id,
        ));
    }

    // 4. Evaluate authorization at the exact locked authority head.
    let decision = crate::authz::evaluate_authorization(
        state,
        &request.actor_context,
        &request.normalized_input,
    )
    .map_err(|error| {
        map_server_error_with_correlation(
            &error,
            Some(operation.clone()),
            operation_id.clone(),
            correlation_id.clone(),
        )
    })?;

    // 5. Execute the operation through the P-0010 unit of work.
    let execution = match request.route {
        HttpRouteV1::HumanOperations => {
            crate::operations::HumanOperationExecutor::execute_for_dispatch(
                state,
                &operation,
                &request.normalized_input,
                &request.actor_context,
                &decision,
            )
        }
        HttpRouteV1::AgentOperations => {
            crate::operations::AgentOperationExecutor::execute_for_dispatch_with_attempt_and_correlation(
                state,
                &operation,
                &request.normalized_input,
                &request.actor_context,
                &decision,
                request.agent_attempt.as_ref(),
                request.correlation_id.as_deref(),
            )
        }
        route => {
            return Err(map_server_error_with_correlation(
                &ServerError::Dispatch(format!(
                    "route `{}` carries no operation executor",
                    route.path()
                )),
                Some(operation),
                operation_id,
                correlation_id,
            ));
        }
    }
    .map_err(|error| {
        map_server_error_with_correlation(
            &error,
            Some(operation.clone()),
            operation_id.clone(),
            correlation_id.clone(),
        )
    })?;

    // 6. Bind the committed head/result-digest anchor and the unchanged typed
    // application result.
    let result_digest = execution
        .consequence
        .result_digest
        .as_ref()
        .map(ToString::to_string);
    let anchor = committed_anchor(
        &execution.consequence.evaluated_authority_head,
        result_digest.as_deref(),
    );

    Ok(SuccessEnvelope::new(
        operation,
        operation_id,
        request.correlation_id,
        anchor,
        execution.result,
    ))
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
    .map_err(|error| ServerError::Dispatch(error.to_string()))?;

    // The adapter-derived actor context (bound to the signed invocation) must
    // name the exact operation being dispatched; a divergence fails closed
    // before any application execution.
    let actor_operation = match &request.actor_context {
        AuthenticatedActorContextV2::Human(context) => &context.operation,
        AuthenticatedActorContextV2::HumanAgent(context) => &context.operation,
    };
    if actor_operation != &request.operation {
        return Err(ServerError::Dispatch(
            "actor-context operation does not match the request operation".to_owned(),
        ));
    }

    Ok(())
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
    map_server_error_with_correlation(error, operation, operation_id, None)
}

fn map_server_error_with_correlation(
    error: &ServerError,
    operation: Option<RemoteOperationV1>,
    operation_id: String,
    correlation_id: Option<String>,
) -> ProblemResponse {
    let code = match error {
        ServerError::RateLimited => "proof.rate_limit.exceeded",
        ServerError::DeadlineExceeded
        | ServerError::Storage(proof_pg::PgError::AmbiguousCommit(_)) => {
            "proof.operation.unknown_outcome"
        }
        ServerError::Storage(
            proof_pg::PgError::Integrity(_) | proof_pg::PgError::Projection(_),
        ) => "proof.integrity.failure",
        ServerError::Storage(_) => "proof.storage.conflict",
        ServerError::Config(_) | ServerError::Internal(_) => "proof.internal",
        ServerError::Oidc(_) | ServerError::Session(_) | ServerError::Authentication(_) => {
            "proof.auth.denied"
        }
        ServerError::Csrf(_) => "proof.auth.csrf_denied",
        ServerError::Authorization(_) => "proof.authorization.denied",
        ServerError::Dispatch(_) => "proof.input.schema_mismatch",
        ServerError::ApplicationProblem(code) => {
            if problem_tuple(code).is_some() {
                code
            } else {
                "proof.internal"
            }
        }
    };
    let tuple = problem_tuple(code).expect("mapped code is a frozen registry tuple");
    ProblemResponse::new(tuple, operation, operation_id, correlation_id)
}

/// Derives a UUIDv7 operation identifier for an execution (contract §"HTTP
/// boundary").
#[must_use]
pub fn new_operation_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// Validates a caller-supplied correlation identifier as an exact UUIDv7
/// value (contract §"Envelopes, Problems, and HTTP semantics").
///
/// A `None` correlation is always valid. A `Some` value must be a canonical
/// UUIDv7 string; anything else fails closed as a schema mismatch before any
/// application execution.
///
/// # Errors
///
/// Returns [`ServerError::Dispatch`] when the supplied value is not a UUIDv7.
pub fn validate_correlation_id(correlation_id: Option<&str>) -> Result<(), ServerError> {
    if let Some(value) = correlation_id {
        value.parse::<CorrelationId>().map_err(|_| {
            ServerError::Dispatch("correlation_id is not a UUIDv7 value".to_owned())
        })?;
    }
    Ok(())
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
