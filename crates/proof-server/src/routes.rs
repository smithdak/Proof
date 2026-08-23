//! The exact nine-route HTTP surface, per-route Problem profiles, and the
//! request-guard signatures (contract §"HTTP boundary", §"Envelopes, Problems,
//! and HTTP semantics").

use axum::Router;
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::http::header;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use http::{HeaderMap, HeaderValue};
use proof_remote::HttpRouteV1;

use crate::{AppState, RAW_BODY_LIMIT_BYTES, dispatch::ProblemResponse};

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

/// Raw HTTP request body limit layer (1 MiB) (contract §"HTTP boundary"). The
/// canonical-request limit is enforced independently by
/// [`CanonicalRequestGuard`].
#[must_use]
pub fn raw_body_limit_layer() -> tower_http::limit::RequestBodyLimitLayer {
    tower_http::limit::RequestBodyLimitLayer::new(RAW_BODY_LIMIT_BYTES)
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
        .with_state(state)
}

/// `GET /auth/oidc/login` — starts the Authorization Code + PKCE flow; succeeds
/// only by 303 redirect (contract §"HTTP boundary").
pub async fn oidc_login(State(_state): State<AppState>) -> Result<Response, ProblemResponse> {
    todo!("mint one-use login transaction and 303 to the authorization endpoint")
}

/// `GET /auth/oidc/callback` — validates state/nonce/PKCE/iss and completes the
/// flow; succeeds only by 303 redirect (contract §"HTTP boundary").
pub async fn oidc_callback(
    State(_state): State<AppState>,
    _query: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, ProblemResponse> {
    todo!("validate the authorization response and exchange the code")
}

/// `GET /api/v1/session` — authenticated `private, no-store` 200 projection and
/// the CSRF acquisition route (contract §"OIDC binding and session boundary").
pub async fn session_get(State(_state): State<AppState>) -> Result<Response, ProblemResponse> {
    todo!("resolve session, return Principal/timestamps and a fresh CSRF value")
}

/// `POST /api/v1/session/logout` — JSON POST requiring Origin and CSRF;
/// converges to `logged_out: true` (contract §"OIDC binding and session
/// boundary").
pub async fn session_logout(
    State(_state): State<AppState>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    _csrf: CsrfGuard,
) -> Result<Response, ProblemResponse> {
    todo!("revoke session/tombstone, expire cookie, return logged_out:true")
}

/// `GET /api/v1/capabilities` — public `capabilities.discover/v1` (contract
/// §"HTTP boundary").
pub async fn capabilities(State(_state): State<AppState>) -> Result<Response, ProblemResponse> {
    todo!("return the committed registry plus its RFC 8785/SHA-256 commitment")
}

/// `POST /api/v1/human/operations/{name}/{major}` — exactly one registered
/// direct-Human operation (contract §"HTTP boundary").
pub async fn human_operations(
    State(_state): State<AppState>,
    Path((_name, _major)): Path<(String, String)>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    _csrf: CsrfGuard,
    _canonical: CanonicalRequestGuard,
) -> Result<Response, ProblemResponse> {
    todo!("strict-parse, derive Human actor, route-qualified dispatch")
}

/// `POST /api/v1/agent/operations/{name}/{major}` — exactly one registered
/// Agent pair plus a fresh single-use Agent presentation (contract §"HTTP
/// boundary").
pub async fn agent_operations(
    State(_state): State<AppState>,
    Path((_name, _major)): Path<(String, String)>,
    _content_type: ContentTypeGuard,
    _origin: OriginGuard,
    _csrf: CsrfGuard,
    _canonical: CanonicalRequestGuard,
) -> Result<Response, ProblemResponse> {
    todo!("strict-parse, derive Human+Agent actor, route-qualified dispatch")
}

/// `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}`
/// — re-authorized evidence artifact read; returns the stable
/// `proof.dependency.unavailable` until S4/S5 (contract §"HTTP boundary").
pub async fn evidence_artifact(
    State(_state): State<AppState>,
    Path((_export_id, _artifact_kind, _digest)): Path<(String, String, String)>,
) -> Result<Response, ProblemResponse> {
    todo!("re-authorize Human, return proof.dependency.unavailable until S4/S5")
}

/// `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}`
/// — private preview object read; returns the stable
/// `proof.dependency.unavailable` until S4/S5 (contract §"HTTP boundary").
pub async fn preview_object(
    State(_state): State<AppState>,
    Path((_environment, _release_id, _object_id, _locale)): Path<(String, String, String, String)>,
) -> Result<Response, ProblemResponse> {
    todo!("authenticate Human, return proof.dependency.unavailable until S4/S5")
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
        let _ = req;
        todo!("collect, strict-parse, canonicalize, enforce the 1 MiB canonical bound")
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
        let _ = parts;
        todo!("require Content-Type: application/json else 415")
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
        let _ = parts;
        todo!("require exact same-origin Origin else 401/403")
    }
}

/// Session-bound `Proof-CSRF` synchronizer enforcement extractor (contract
/// §"OIDC binding and session boundary").
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
        let _ = parts;
        todo!("require and validate Proof-CSRF against the session-bound digest")
    }
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
