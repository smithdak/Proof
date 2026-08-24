//! The exact nine-route HTTP surface, per-route Problem profiles, and the
//! request-guard signatures (contract §"HTTP boundary", §"Envelopes, Problems,
//! and HTTP semantics").

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

use axum::Json;
use axum::Router;
use axum::body::to_bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::http::{StatusCode, uri::Authority};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::{HeaderMap, HeaderValue, Uri};
use http_body_util::Limited;
use proof_application::authority::AuthenticatedInvocationV1;
use proof_remote::{
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, HttpRouteV1, RemoteOperationV1,
    cross_check_route_operation,
    identity::{AuthenticatedActorContextV2, normalized_operation_input_digest},
};
use serde_json::{Value, json};

use crate::{
    AppState, CANONICAL_REQUEST_LIMIT_BYTES, RAW_BODY_LIMIT_BYTES, ServerError,
    authz::{
        authenticate_agent_presentation, authenticate_human_session,
        guard_request_carried_identity, resolve_oidc_binding_by_subject,
    },
    dispatch::{
        DispatchRequest, ProblemResponse, dispatch, map_server_error, new_operation_id,
        problem_tuple,
    },
    session::{
        OIDC_TX_COOKIE_NAME, OIDC_TX_COOKIE_PATH, SESSION_ABSOLUTE_SECONDS, SESSION_COOKIE_NAME,
        SESSION_IDLE_SECONDS, SessionId, oidc_tx_cookie, session_cookie,
    },
};

/// The exact `application/json` media-type essence required on operation
/// requests (contract §"HTTP boundary").
const JSON_MEDIA_TYPE: &str = "application/json";

/// `Proof-CSRF` synchronizer request header name (contract §"OIDC binding and
/// session boundary"). Header names are matched case-insensitively by HTTP.
const PROOF_CSRF_HEADER: &str = "proof-csrf";

/// The closed top-level member names of both operation request envelopes. A
/// member outside this set is rejected before dispatch; the route-specific
/// `additionalProperties: false` Schemas are enforced later by the registry.
const ENVELOPE_MEMBERS: [&str; 7] = [
    "api_version",
    "workspace_id",
    "operation",
    "correlation_id",
    "idempotency_key",
    "input",
    "invocation",
];

/// The exact committed HTTP operation registry value (contract §"HTTP
/// boundary", `capabilities.discover/v1`). It is byte-for-byte the retained
/// conformance vector; the response is canonicalized and committed separately.
const HTTP_OPERATION_REGISTRY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json"
));

/// A closed route-specific Problem profile (contract §"Envelopes, Problems, and
/// HTTP semantics"). The full route-and-row union is computed at dispatch time;
/// these constants freeze the exact transport-level subset each route emits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProblemProfile {
    /// Stable code subset for this route.
    pub codes: &'static [&'static str],
}

/// `GET /auth/oidc/login` transport-session profile.
pub const OIDC_LOGIN_PROFILE: ProblemProfile = ProblemProfile {
    codes: &["proof.internal", "proof.rate_limit.exceeded"],
};

/// `GET /auth/oidc/callback` transport-session profile.
pub const OIDC_CALLBACK_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.auth.replay",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `GET /api/v1/session` transport-session profile.
pub const SESSION_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `POST /api/v1/session/logout` transport-session profile.
pub const SESSION_LOGOUT_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.auth.csrf_denied",
        "proof.input.invalid_json",
        "proof.input.too_large",
        "proof.input.unsupported_media_type",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `GET /api/v1/capabilities` application-data profile.
pub const CAPABILITIES_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.integrity.failure",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `POST /api/v1/human/operations/{name}/{major}` application-data profile.
pub const HUMAN_OPERATIONS_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.auth.csrf_denied",
        "proof.input.invalid_json",
        "proof.input.schema_mismatch",
        "proof.input.too_large",
        "proof.input.unsupported_media_type",
        "proof.input.unsupported_version",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `POST /api/v1/agent/operations/{name}/{major}` application-data profile.
pub const AGENT_OPERATIONS_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.auth.replay",
        "proof.auth.csrf_denied",
        "proof.input.invalid_json",
        "proof.input.schema_mismatch",
        "proof.input.too_large",
        "proof.input.unsupported_media_type",
        "proof.input.unsupported_version",
        "proof.internal",
        "proof.rate_limit.exceeded",
    ],
};

/// `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}`
/// application-data profile.
pub const EVIDENCE_ARTIFACT_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.dependency.unavailable",
        "proof.internal",
        "proof.rate_limit.exceeded",
        "proof.resource.not_found",
    ],
};

/// `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}`
/// application-data profile.
pub const PREVIEW_OBJECT_PROFILE: ProblemProfile = ProblemProfile {
    codes: &[
        "proof.auth.denied",
        "proof.dependency.unavailable",
        "proof.internal",
        "proof.rate_limit.exceeded",
        "proof.resource.not_found",
    ],
};

/// Returns the exact closed route-specific Problem profile (contract
/// §"Envelopes, Problems, and HTTP semantics").
#[must_use]
pub const fn route_problem_profile(route: HttpRouteV1) -> ProblemProfile {
    match route {
        HttpRouteV1::OidcLogin => OIDC_LOGIN_PROFILE,
        HttpRouteV1::OidcCallback => OIDC_CALLBACK_PROFILE,
        HttpRouteV1::Session => SESSION_PROFILE,
        HttpRouteV1::SessionLogout => SESSION_LOGOUT_PROFILE,
        HttpRouteV1::Capabilities => CAPABILITIES_PROFILE,
        HttpRouteV1::HumanOperations => HUMAN_OPERATIONS_PROFILE,
        HttpRouteV1::AgentOperations => AGENT_OPERATIONS_PROFILE,
        HttpRouteV1::EvidenceArtifact => EVIDENCE_ARTIFACT_PROFILE,
        HttpRouteV1::PreviewObject => PREVIEW_OBJECT_PROFILE,
    }
}

/// The boxed middleware future for [`raw_body_limit_layer`].
type RawBodyLimitFuture = Pin<Box<dyn Future<Output = Response> + Send + 'static>>;

/// The middleware function pointer for [`raw_body_limit_layer`].
type RawBodyLimitMiddleware = fn(Request, Next) -> RawBodyLimitFuture;

/// Raw HTTP request body limit layer (1 MiB) (contract §"HTTP boundary"). The
/// canonical-request limit is enforced independently by
/// [`CanonicalRequestGuard`].
///
/// It reads `Content-Length` and rejects an oversized declaration with
/// `413 proof.input.too_large` *before* parsing, and caps the body stream with
/// [`http_body_util::Limited`] so a chunked or undeclared-length body cannot
/// exceed the same bound.
pub fn raw_body_limit_layer()
-> axum::middleware::FromFnLayer<RawBodyLimitMiddleware, (), (Request,)> {
    from_fn(raw_body_limit_middleware)
}

/// The raw-body-limit middleware itself (contract §"HTTP boundary").
fn raw_body_limit_middleware(request: Request, next: Next) -> RawBodyLimitFuture {
    Box::pin(async move {
        if let Some(length) = content_length(&request)
            && length > RAW_BODY_LIMIT_BYTES
        {
            return transport_problem("proof.input.too_large").into_response();
        }
        let (parts, body) = request.into_parts();
        let limited = Limited::new(body, RAW_BODY_LIMIT_BYTES);
        let request = Request::from_parts(parts, axum::body::Body::new(limited));
        next.run(request).await
    })
}

/// Reads the declared `Content-Length` header as a byte count, if present and
/// well-formed.
fn content_length(request: &Request) -> Option<usize> {
    request
        .headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Builds the exact nine-route router with shared [`AppState`] (contract §"HTTP
/// boundary"). Unknown routes, versions, and members fail closed with the
/// route-specific Problem profile.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        .route("/api/v1/session", get(session_get))
        .route("/api/v1/session/logout", post(session_logout))
        .route("/api/v1/capabilities", get(capabilities))
        .route(
            "/api/v1/human/operations/{name}/{major}",
            post(human_operations).layer(raw_body_limit_layer()),
        )
        .route(
            "/api/v1/agent/operations/{name}/{major}",
            post(agent_operations).layer(raw_body_limit_layer()),
        )
        .route(
            "/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}",
            get(evidence_artifact),
        )
        .route(
            "/preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}",
            get(preview_object),
        )
        .fallback(route_not_found)
        .with_state(state)
}

/// The disclosure-neutral 404 for an unknown route/version (contract §"HTTP
/// boundary"). Unknown members are rejected earlier by
/// [`CanonicalRequestGuard`].
async fn route_not_found() -> ProblemResponse {
    transport_problem("proof.resource.not_found")
}

/// `GET /auth/oidc/login` — starts the Authorization Code + PKCE flow; succeeds
/// only by 303 redirect (contract §"HTTP boundary").
pub async fn oidc_login(State(state): State<AppState>) -> Result<Response, ProblemResponse> {
    let (transaction, authorize_url) = state
        .bff
        .begin_login()
        .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
    let tx_cookie = oidc_tx_cookie(&transaction.state).to_string();
    Ok(redirect_with_cookie(&authorize_url, &tx_cookie))
}

/// `GET /auth/oidc/callback` — validates state/nonce/PKCE/iss and completes the
/// flow; succeeds only by 303 redirect (contract §"HTTP boundary").
pub async fn oidc_callback(
    State(state): State<AppState>,
    query: Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ProblemResponse> {
    let code = query
        .get("code")
        .cloned()
        .ok_or_else(|| transport_problem("proof.auth.denied"))?;
    let state_param = query
        .get("state")
        .cloned()
        .ok_or_else(|| transport_problem("proof.auth.denied"))?;
    let iss = query
        .get("iss")
        .cloned()
        .ok_or_else(|| transport_problem("proof.auth.denied"))?;

    run_blocking(move || {
        let result = state
            .bff
            .handle_callback(&code, &state_param, &iss)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;

        // Resolve the protected binding for the authenticated subject, then mint
        // the opaque session (rotation on re-login is the caller's later concern).
        let binding = resolve_oidc_binding_by_subject(&state, &result.subject)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
        let authentication_event_id = uuid::Uuid::now_v7().to_string();
        let session_id = state
            .sessions
            .create(
                &binding.workspace_id,
                &binding.principal_id,
                &binding.binding_id,
                &authentication_event_id,
            )
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;

        // 303 + the strict application session cookie; also expire the one-use
        // transaction cookie.
        let mut response = (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, HeaderValue::from_static("/"))],
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&session_cookie(session_id.as_str()).to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        if let Ok(value) = HeaderValue::from_str(&expired_cookie(
            OIDC_TX_COOKIE_NAME,
            OIDC_TX_COOKIE_PATH,
            "Lax",
        )) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        Ok(response)
    })
    .await
}

/// `GET /api/v1/session` — authenticated `private, no-store` 200 projection and
/// the CSRF acquisition route (contract §"OIDC binding and session boundary").
pub async fn session_get(
    State(state): State<AppState>,
    session_cookie: SessionCookieGuard,
) -> Result<Response, ProblemResponse> {
    let session_id = session_cookie.session_id;
    run_blocking(move || {
        // The acquisition route rotates the session-bound CSRF synchronizer
        // before disclosing its fresh value (stored only as a digest).
        let csrf = state
            .sessions
            .issue_csrf(&session_id)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
        let record = state
            .sessions
            .resolve(&session_id)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;

        let authenticated_at = system_time_to_timestamp(record.created_at)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
        let idle_expiry = record
            .last_seen
            .checked_add(Duration::from_secs(SESSION_IDLE_SECONDS))
            .ok_or_else(|| transport_problem("proof.internal"))?;
        let idle_expires_at = system_time_to_timestamp(idle_expiry)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
        let expires_at = system_time_to_timestamp(record.absolute_expiry)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;

        let body = json!({
            "api_version": "proof.dev/session-get-result/v1",
            "cache_control": "private, no-store",
            "csrf_token": csrf.value,
            "principal_id": record.principal_id,
            "authenticated_at": authenticated_at.to_string(),
            "idle_expires_at": idle_expires_at.to_string(),
            "expires_at": expires_at.to_string(),
        });

        Ok((StatusCode::OK, private_no_store_headers(), Json(body)).into_response())
    })
    .await
}

/// `POST /api/v1/session/logout` — JSON POST requiring Origin and CSRF;
/// converges to `logged_out: true` (contract §"OIDC binding and session
/// boundary").
pub async fn session_logout(
    State(state): State<AppState>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    csrf: CsrfGuard,
    session_cookie: SessionCookieGuard,
) -> Result<Response, ProblemResponse> {
    let session_id = session_cookie.session_id;
    let csrf_value = csrf.csrf;
    run_blocking(move || {
        state
            .sessions
            .validate_csrf(&session_id, &csrf_value)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;
        state
            .sessions
            .logout_converge(&session_id)
            .map_err(|error| map_server_error(&error, None, new_operation_id()))?;

        let body = json!({
            "api_version": "proof.dev/session-logout-result/v1",
            "logged_out": true,
        });
        let mut response = (StatusCode::OK, Json(body)).into_response();
        if let Ok(value) =
            HeaderValue::from_str(&expired_cookie(SESSION_COOKIE_NAME, "/", "Strict"))
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        Ok(response)
    })
    .await
}

/// `GET /api/v1/capabilities` — public `capabilities.discover/v1` (contract
/// §"HTTP boundary").
pub async fn capabilities(State(_state): State<AppState>) -> Result<Response, ProblemResponse> {
    let registry: Value = proof_canonical::parse_strict(HTTP_OPERATION_REGISTRY.as_bytes())
        .map_err(|_| transport_problem("proof.internal"))?;
    let result = json!({
        "api_version": "proof.dev/capabilities-discover-result/v1",
        "profile": "proof.server/single-workspace/v1",
        "registry": registry,
        "registry_canonicalization": "RFC8785",
        "registry_digest_algorithm": "sha-256",
        "registry_schema": "https://proof.dev/schema/collaboration-server/http-operation-registry/v1",
        "registry_sha256": COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "route_count": 9,
        "human_operation_count": 23,
        "agent_operation_count": 14,
    });
    Ok((StatusCode::OK, Json(result)).into_response())
}

/// `POST /api/v1/human/operations/{name}/{major}` — exactly one registered
/// direct-Human operation (contract §"HTTP boundary").
pub async fn human_operations(
    State(state): State<AppState>,
    Path((name, major)): Path<(String, String)>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    csrf: CsrfGuard,
    session_cookie: SessionCookieGuard,
    canonical: CanonicalRequestGuard,
) -> Result<Response, ProblemResponse> {
    let value = proof_canonical::parse_strict(&canonical.canonical_bytes)
        .map_err(|_| transport_problem("proof.input.invalid_json"))?;
    let operation = parse_envelope_operation(&value)?;
    cross_check_route_operation(HttpRouteV1::HumanOperations, &name, &major, &operation)
        .map_err(|_| transport_problem("proof.input.schema_mismatch"))?;

    let normalized_input = value.get("input").cloned().unwrap_or(Value::Null);
    let correlation_id = value
        .get("correlation_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let supplied_workspace = value
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let session_id = session_cookie.session_id;
    let csrf_value = csrf.csrf;

    run_blocking(move || {
        let session = state.sessions.resolve(&session_id).map_err(|error| {
            map_server_error(&error, Some(operation.clone()), new_operation_id())
        })?;
        state
            .sessions
            .validate_csrf(&session_id, &csrf_value)
            .map_err(|error| {
                map_server_error(&error, Some(operation.clone()), new_operation_id())
            })?;

        // The request-carried Workspace identifier is an expected-value
        // cross-check only; it never selects the Workspace.
        guard_request_carried_identity(
            &session.workspace_id,
            supplied_workspace.as_deref(),
            "workspace",
        )
        .map_err(|error| map_server_error(&error, Some(operation.clone()), new_operation_id()))?;

        let mut actor_context = authenticate_human_session(&state, &session).map_err(|error| {
            map_server_error(&error, Some(operation.clone()), new_operation_id())
        })?;
        let input_digest = normalized_operation_input_digest(&normalized_input, &operation)
            .map_err(|error| {
                map_server_error(
                    &ServerError::Internal(error.to_string()),
                    Some(operation.clone()),
                    new_operation_id(),
                )
            })?;
        if let AuthenticatedActorContextV2::Human(human) = &mut actor_context {
            human.operation = operation.clone();
            human.normalized_input_digest = input_digest;
        }

        let envelope = dispatch(
            &state,
            DispatchRequest {
                route: HttpRouteV1::HumanOperations,
                path_name: name,
                path_major: major,
                operation,
                normalized_input,
                actor_context,
                correlation_id,
            },
        )?;
        Ok((StatusCode::OK, Json(envelope)).into_response())
    })
    .await
}

/// `POST /api/v1/agent/operations/{name}/{major}` — exactly one registered
/// Agent pair plus a fresh single-use Agent presentation (contract §"HTTP
/// boundary").
pub async fn agent_operations(
    State(state): State<AppState>,
    Path((name, major)): Path<(String, String)>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    csrf: CsrfGuard,
    session_cookie: SessionCookieGuard,
    canonical: CanonicalRequestGuard,
) -> Result<Response, ProblemResponse> {
    let value = proof_canonical::parse_strict(&canonical.canonical_bytes)
        .map_err(|_| transport_problem("proof.input.invalid_json"))?;
    let operation = parse_envelope_operation(&value)?;
    cross_check_route_operation(HttpRouteV1::AgentOperations, &name, &major, &operation)
        .map_err(|_| transport_problem("proof.input.schema_mismatch"))?;

    let invocation: AuthenticatedInvocationV1 = value
        .get("invocation")
        .cloned()
        .ok_or_else(|| transport_problem("proof.input.schema_mismatch"))
        .and_then(|invocation| {
            serde_json::from_value(invocation)
                .map_err(|_| transport_problem("proof.input.schema_mismatch"))
        })?;
    let normalized_input = Value::Object(invocation.command_input.normalized_input.clone());
    let correlation_id = value
        .get("correlation_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let session_id = session_cookie.session_id;
    let csrf_value = csrf.csrf;

    run_blocking(move || {
        let session = state.sessions.resolve(&session_id).map_err(|error| {
            map_server_error(&error, Some(operation.clone()), new_operation_id())
        })?;
        state
            .sessions
            .validate_csrf(&session_id, &csrf_value)
            .map_err(|error| {
                map_server_error(&error, Some(operation.clone()), new_operation_id())
            })?;

        let actor_context = authenticate_agent_presentation(&state, &session, &invocation)
            .map_err(|error| {
                map_server_error(&error, Some(operation.clone()), new_operation_id())
            })?;

        let envelope = dispatch(
            &state,
            DispatchRequest {
                route: HttpRouteV1::AgentOperations,
                path_name: name,
                path_major: major,
                operation,
                normalized_input,
                actor_context,
                correlation_id,
            },
        )?;
        Ok((StatusCode::OK, Json(envelope)).into_response())
    })
    .await
}

/// `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}`
/// — re-authorized evidence artifact read; returns the stable
/// `proof.dependency.unavailable` until S4/S5 (contract §"HTTP boundary").
pub async fn evidence_artifact(
    State(_state): State<AppState>,
    Path((_export_id, _artifact_kind, _digest)): Path<(String, String, String)>,
) -> Result<Response, ProblemResponse> {
    Err(transport_problem("proof.dependency.unavailable"))
}

/// `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}`
/// — private preview object read (contract §"HTTP boundary", §"Preview
/// delivery").
///
/// The exact requested Release's ready snapshot is served with a strong ETag
/// and `Cache-Control: private, no-store`; a Release without a ready marker
/// returns the stable `proof.dependency.unavailable` pending Problem and never
/// falls back to another Release, and a ready Release lacking the exact
/// object/locale is a `proof.resource.not_found`.
pub async fn preview_object(
    State(state): State<AppState>,
    Path((environment, release_id, object_id, locale)): Path<(String, String, String, String)>,
) -> Result<Response, ProblemResponse> {
    run_blocking(move || {
        match crate::operations::serve_preview_object(
            &state,
            &environment,
            &release_id,
            &object_id,
            &locale,
        ) {
            Ok(result) => {
                let mut response = (
                    StatusCode::OK,
                    private_no_store_headers(),
                    Json(result.body),
                )
                    .into_response();
                if let Ok(etag) = HeaderValue::from_str(&result.etag) {
                    response.headers_mut().insert(header::ETAG, etag);
                }
                Ok(response)
            }
            Err(ServerError::Internal(message))
                if message.starts_with(crate::operations::DEPENDENCY_UNAVAILABLE_CODE) =>
            {
                Err(transport_problem("proof.dependency.unavailable"))
            }
            Err(ServerError::Dispatch(_)) => Err(transport_problem("proof.resource.not_found")),
            Err(_) => Err(transport_problem("proof.internal")),
        }
    })
    .await
}

/// Strict-parsed RFC 8785 canonical request guard (contract §"HTTP boundary").
///
/// It enforces the 1 MiB canonical-request bound independently of the raw-body
/// bound, rejects non-I-JSON values and duplicate/unknown JSON names, and
/// exposes the canonical bytes to the operation handlers.
pub struct CanonicalRequestGuard {
    /// Exact RFC 8785 canonical request bytes.
    pub canonical_bytes: Vec<u8>,
}

impl<S> FromRequest<S> for CanonicalRequestGuard
where
    S: Send + Sync,
{
    type Rejection = ProblemResponse;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let bytes = to_bytes(req.into_body(), RAW_BODY_LIMIT_BYTES)
            .await
            .map_err(|error| {
                if is_length_limit(&error) {
                    transport_problem("proof.input.too_large")
                } else {
                    transport_problem("proof.internal")
                }
            })?;

        let value = proof_canonical::parse_strict(&bytes)
            .map_err(|_| transport_problem("proof.input.invalid_json"))?;
        reject_unknown_members(&value)?;

        let canonical = proof_canonical::canonicalize(&value)
            .map_err(|_| transport_problem("proof.input.invalid_json"))?;
        if canonical.as_bytes().len() > CANONICAL_REQUEST_LIMIT_BYTES {
            return Err(transport_problem("proof.input.too_large"));
        }

        Ok(CanonicalRequestGuard {
            canonical_bytes: canonical.as_bytes().to_vec(),
        })
    }
}

/// `Content-Type: application/json` enforcement extractor (contract §"HTTP
/// boundary"). Unsupported media fails with 415.
pub struct ContentTypeGuard;

impl<S> FromRequestParts<S> for ContentTypeGuard
where
    S: Send + Sync,
{
    type Rejection = ProblemResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let essence = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim)
            .map(str::to_ascii_lowercase);
        match essence.as_deref() {
            Some(JSON_MEDIA_TYPE) => Ok(ContentTypeGuard),
            _ => Err(transport_problem("proof.input.unsupported_media_type")),
        }
    }
}

/// Exact same-origin `Origin` enforcement extractor (contract §"OIDC binding
/// and session boundary"). Hostile, missing, or `null` origins fail closed.
pub struct OriginGuard {
    /// The validated same-origin value.
    pub origin: String,
}

impl<S> FromRequestParts<S> for OriginGuard
where
    S: Send + Sync,
{
    type Rejection = ProblemResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let origin = parts
            .headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| transport_problem("proof.auth.csrf_denied"))?;
        let host = parts
            .headers
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| transport_problem("proof.auth.csrf_denied"))?;

        if !same_origin(origin, host) {
            return Err(transport_problem("proof.auth.csrf_denied"));
        }

        Ok(OriginGuard {
            origin: origin.to_owned(),
        })
    }
}

/// Session-bound `Proof-CSRF` synchronizer enforcement extractor (contract
/// §"OIDC binding and session boundary").
///
/// The extractor enforces presence and header well-formedness of the
/// synchronizer value. The session-bound digest match is performed by the
/// operation handlers, which hold the [`AppState`] session store.
pub struct CsrfGuard {
    /// The supplied synchronizer value (validated against the session digest).
    pub csrf: String,
}

impl<S> FromRequestParts<S> for CsrfGuard
where
    S: Send + Sync,
{
    type Rejection = ProblemResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let csrf = parts
            .headers
            .get(PROOF_CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| transport_problem("proof.auth.csrf_denied"))?;
        Ok(CsrfGuard {
            csrf: csrf.to_owned(),
        })
    }
}

/// Strict application-session cookie extractor (contract §"OIDC binding and
/// session boundary"). A missing, malformed, or non-canonical cookie fails
/// closed as a disclosure-neutral 401.
pub struct SessionCookieGuard {
    /// The reconstructed opaque session identifier.
    pub session_id: SessionId,
}

impl<S> FromRequestParts<S> for SessionCookieGuard
where
    S: Send + Sync,
{
    type Rejection = ProblemResponse;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = session_cookie_value(&parts.headers)?;
        let session_id =
            SessionId::from_wire(&value).map_err(|_| transport_problem("proof.auth.denied"))?;
        Ok(Self { session_id })
    }
}

/// Reads the strict application-session cookie value from the `Cookie` header.
fn session_cookie_value(headers: &HeaderMap) -> Result<String, ProblemResponse> {
    let header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| transport_problem("proof.auth.denied"))?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            let name = name.trim();
            let value = value.trim();
            if name == SESSION_COOKIE_NAME && !value.is_empty() {
                return Ok(value.to_owned());
            }
        }
    }
    Err(transport_problem("proof.auth.denied"))
}

/// Builds an expired `Max-Age=0` cookie for one transport/session cookie name.
fn expired_cookie(name: &str, path: &str, same_site: &str) -> String {
    format!("{name}=; Path={path}; Secure; HttpOnly; SameSite={same_site}; Max-Age=0")
}

/// Converts a wall-clock instant to the RFC 3339 domain timestamp.
fn system_time_to_timestamp(
    value: SystemTime,
) -> Result<crate::proof_domain::Timestamp, ServerError> {
    let duration = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_| {
        ServerError::Internal("system clock exceeds the timestamp range".to_owned())
    })?;
    crate::proof_domain::Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| ServerError::Internal(error.to_string()))
}

/// Sets `Cache-Control: private, no-store` on session/projection responses
/// (contract §"OIDC binding and session boundary").
#[must_use]
pub fn private_no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers
}

/// Builds a disclosure-neutral transport/session Problem from a frozen registry
/// code (contract §"Envelopes, Problems, and HTTP semantics").
fn transport_problem(code: &'static str) -> ProblemResponse {
    let tuple = problem_tuple(code).expect("the code is a frozen registry tuple");
    ProblemResponse::new(tuple, None, new_operation_id(), None)
}

/// Runs one blocking storage/authority operation off the async runtime
/// (contract §"PostgreSQL authoritative unit of work": the async runtime never
/// blocks on storage; the synchronous `postgres` driver runs on a blocking
/// executor thread).
async fn run_blocking<F>(operation: F) -> Result<Response, ProblemResponse>
where
    F: FnOnce() -> Result<Response, ProblemResponse> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| transport_problem("proof.internal"))?
}

/// Reports whether a body-collection error was a size-limit violation.
fn is_length_limit(error: &axum::Error) -> bool {
    std::error::Error::source(error)
        .is_some_and(<dyn std::error::Error>::is::<http_body_util::LengthLimitError>)
}

/// Rejects top-level JSON members that are unknown to both operation request
/// envelopes (contract §"HTTP boundary").
fn reject_unknown_members(value: &Value) -> Result<(), ProblemResponse> {
    let Value::Object(map) = value else {
        return Ok(());
    };
    for key in map.keys() {
        if !ENVELOPE_MEMBERS.contains(&key.as_str()) {
            return Err(transport_problem("proof.input.invalid_json"));
        }
    }
    Ok(())
}

/// Extracts the exact envelope `operation` pair from a strict-parsed request
/// body (contract §"HTTP boundary").
fn parse_envelope_operation(value: &Value) -> Result<RemoteOperationV1, ProblemResponse> {
    value
        .get("operation")
        .cloned()
        .ok_or_else(|| transport_problem("proof.input.schema_mismatch"))
        .and_then(|operation| {
            serde_json::from_value(operation)
                .map_err(|_| transport_problem("proof.input.schema_mismatch"))
        })
}

/// Returns `true` when the `Origin` header denotes the exact same origin as the
/// request's `Host` authority (contract §"OIDC binding and session boundary").
///
/// TLS termination is a deployment prerequisite, so the effective scheme is
/// `https` and the default port is 443. `null`, relative, cross-origin, and
/// mismatched-port origins fail closed.
fn same_origin(origin: &str, host: &str) -> bool {
    let Ok(uri) = origin.parse::<Uri>() else {
        return false;
    };
    if uri.scheme_str() != Some("https") {
        return false;
    }
    if uri.path() != "" && uri.path() != "/" {
        return false;
    }
    if uri.query().is_some() {
        return false;
    }
    let Some(origin_authority) = uri.authority() else {
        return false;
    };

    let Ok(host_authority) = host.parse::<Authority>() else {
        return false;
    };

    if !origin_authority
        .host()
        .eq_ignore_ascii_case(host_authority.host())
    {
        return false;
    }
    let origin_port = origin_authority.port_u16().unwrap_or(443);
    let host_port = host_authority.port_u16().unwrap_or(443);
    origin_port == host_port
}

/// Builds a 303 redirect response carrying one `Set-Cookie` header.
fn redirect_with_cookie(location: &str, set_cookie: &str) -> Response {
    let mut response = (
        StatusCode::SEE_OTHER,
        [(
            header::LOCATION,
            HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/")),
        )],
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(set_cookie) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}
