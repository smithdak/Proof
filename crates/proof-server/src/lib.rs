#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::implicit_hasher,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::struct_field_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

//! HTTP and OIDC server boundary skeleton for Proof (work item P-0011).
//!
//! This crate is the third dependency-ordered successor of the accepted
//! [single-Workspace collaboration-server contract]: the exact nine-route HTTP
//! boundary, the same-origin confidential OIDC Backend-for-Frontend with
//! Authorization Code plus PKCE against a deterministic in-process issuer,
//! opaque server-side sessions with bounded idle/absolute lifetimes, the
//! session-bound CSRF synchronizer, dual Human-session plus
//! `AuthenticatedCommandV1` Agent authentication, exact envelope/Problem/status
//! mapping, and the identity/role/approval/configuration Human operations over
//! the P-0010 PostgreSQL unit of work.
//!
//! This is a compiling **skeleton**: every public type and function is declared
//! here as the contract surface for the parallel implementation successors, and
//! function bodies are [`todo!()`] stubs. It depends only on
//! [`proof_remote`] (P-0009 registries/identity/authority/oracle) and
//! [`proof_pg`] (P-0010 persistence); never the reverse.
//!
//! [single-Workspace collaboration-server contract]: https://proof.dev/docs/architecture/collaboration-server
//! [`proof_remote`]: ../proof_remote/index.html
//! [`proof_pg`]: ../proof_pg/index.html

pub mod authz;
pub mod bff;
pub mod dispatch;
pub mod issuer;
pub mod operations;
pub mod routes;
pub mod session;

/// The exact `application/json` MIME type required on operation requests
/// (contract §"HTTP boundary").
#[must_use]
pub fn json_media_type() -> mime::Mime {
    mime::APPLICATION_JSON
}

/// Serves the assembled router on an already-bound tokio listener (contract
/// §"Topology and trust boundaries"). TLS termination and trusted-proxy
/// configuration are deployment prerequisites outside this adapter.
///
/// # Errors
///
/// Returns [`ServerError::Internal`] when the server cannot run.
pub async fn serve(
    app: axum::Router<AppState>,
    listener: tokio::net::TcpListener,
) -> Result<(), ServerError> {
    let _ = (app, listener);
    todo!("run axum::serve(listener, app) behind the tokio runtime")
}

/// Re-exported shared domain vocabulary (Workspace/Principal identities,
/// digests, timestamps) so server consumers need only one dependency edge.
pub use proof_domain;

/// Re-exported P-0009 remote registries, identity, authority, and oracle types
/// that the server boundary dispatches over.
pub use proof_remote;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use proof_domain::WorkspaceId;
use proof_remote::identity::OidcIssuerConfigurationV1;
use thiserror::Error;

use crate::{dispatch::RateLimiter, issuer::DeterministicIssuer, session::SessionStore};

/// Exact first-profile HTTP API version path token (contract §"HTTP boundary").
pub const HTTP_API_VERSION: &str = "v1";

/// Required JSON request media type (contract §"Envelopes, Problems, and HTTP
/// semantics").
pub const JSON_CONTENT_TYPE: &str = "application/json";

/// RFC 9457 problem media type (contract §"Envelopes, Problems, and HTTP
/// semantics").
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// Raw HTTP request body bound: 1,048,576 bytes (contract §"HTTP boundary",
/// limits table).
pub const RAW_BODY_LIMIT_BYTES: usize = 1_048_576;

/// RFC 8785 canonical operation request bound: 1,048,576 bytes (contract
/// §"HTTP boundary", limits table).
pub const CANONICAL_REQUEST_LIMIT_BYTES: usize = 1_048_576;

/// Ordinary structured response bound: 4,194,304 bytes (contract §"HTTP
/// boundary", limits table).
pub const RESPONSE_LIMIT_BYTES: usize = 4_194_304;

/// Canonical Agent authentication payload bound: 4,096 bytes (contract §"HTTP
/// boundary", limits table).
pub const AGENT_AUTHENTICATION_PAYLOAD_LIMIT_BYTES: usize = 4_096;

/// Agent DSSE envelope bound: 16,384 bytes (contract §"HTTP boundary", limits
/// table).
pub const AGENT_DSSE_ENVELOPE_LIMIT_BYTES: usize = 16_384;

/// Frozen 30-second application deadline (contract §"HTTP boundary", limits
/// table).
pub const APPLICATION_DEADLINE: Duration = Duration::from_secs(30);

/// The nine exact first-profile routes and the four transport-session routes
/// are the complete HTTP surface; no other route exists (contract §"HTTP
/// boundary").
pub const ROUTE_COUNT: usize = 9;

/// Bounded request/response/artifact limits (contract §"HTTP boundary", limits
/// table). The raw-body and canonical-request bounds are enforced
/// independently; neither can be bypassed by alternate JSON spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Raw HTTP request body maximum bytes.
    pub raw_body_bytes: usize,
    /// RFC 8785 canonical operation request maximum bytes.
    pub canonical_request_bytes: usize,
    /// Canonical Agent authentication payload maximum bytes.
    pub agent_authentication_payload_bytes: usize,
    /// Agent DSSE envelope maximum bytes.
    pub agent_dsse_envelope_bytes: usize,
    /// Ordinary structured response maximum bytes.
    pub response_bytes: usize,
}

impl Limits {
    /// The exact contract limits table (contract §"HTTP boundary").
    #[must_use]
    pub const fn contract() -> Self {
        Self {
            raw_body_bytes: RAW_BODY_LIMIT_BYTES,
            canonical_request_bytes: CANONICAL_REQUEST_LIMIT_BYTES,
            agent_authentication_payload_bytes: AGENT_AUTHENTICATION_PAYLOAD_LIMIT_BYTES,
            agent_dsse_envelope_bytes: AGENT_DSSE_ENVELOPE_LIMIT_BYTES,
            response_bytes: RESPONSE_LIMIT_BYTES,
        }
    }
}

/// Token-bucket rate-limit budget (contract §"HTTP boundary"). Rate limiting is
/// an adapter denial control, never authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimitBudget {
    /// Bucket capacity in tokens (requests).
    pub capacity: u64,
    /// Token refill rate per second.
    pub refill_per_second: u64,
}

impl RateLimitBudget {
    /// A bounded development default (capacity 120, refill 40/s). The exact
    /// deployment value is a configuration concern, not a portable contract.
    #[must_use]
    pub const fn development_default() -> Self {
        Self {
            capacity: 120,
            refill_per_second: 40,
        }
    }
}

/// Deployment-scoped server configuration (contract §"OIDC binding and session
/// boundary", §"HTTP boundary").
///
/// The configuration fixes the one Workspace before the server accepts traffic;
/// no request-carried value can select another Workspace, issuer, or redirect.
#[derive(Clone)]
pub struct ServerConfig {
    /// Listen address for the HTTP endpoint.
    pub listen_addr: SocketAddr,
    /// The single Workspace identity fixed by deployment configuration.
    pub workspace_id: WorkspaceId,
    /// Pinned public, secret-free issuer configuration from trusted deployment
    /// configuration.
    pub issuer: OidcIssuerConfigurationV1,
    /// `deployment-secret:...` client-credential reference; never the secret.
    pub client_credential_reference: String,
    /// Keyed-hash secret for opaque session and CSRF material at rest.
    pub session_secret: [u8; 32],
    /// Bounded request/response/artifact limits.
    pub limits: Limits,
    /// Application deadline.
    pub deadline: Duration,
    /// Token-bucket rate-limit budget.
    pub rate_limit_budget: RateLimitBudget,
    /// PostgreSQL connection string (DSN) for the authority store.
    pub dsn: String,
}

impl ServerConfig {
    /// Binds the deployment constants into one configuration. Callers supply
    /// the trusted issuer configuration and a 32-byte session secret.
    #[must_use]
    pub fn new(
        listen_addr: SocketAddr,
        workspace_id: WorkspaceId,
        issuer: OidcIssuerConfigurationV1,
        client_credential_reference: impl Into<String>,
        session_secret: [u8; 32],
        dsn: impl Into<String>,
    ) -> Self {
        Self {
            listen_addr,
            workspace_id,
            issuer,
            client_credential_reference: client_credential_reference.into(),
            session_secret,
            limits: Limits::contract(),
            deadline: APPLICATION_DEADLINE,
            rate_limit_budget: RateLimitBudget::development_default(),
            dsn: dsn.into(),
        }
    }

    /// The exact workspace audience URI for actor contexts
    /// (`proof://workspace/<uuid>`) (contract §"Remote identity vocabulary").
    #[must_use]
    pub fn workspace_audience(&self) -> String {
        format!("proof://workspace/{}", self.workspace_id)
    }
}

/// Shared application state behind the router. It is cheaply clonable; the
/// synchronous PostgreSQL client is wrapped in a mutex and driven behind
/// `tokio::task::spawn_blocking` so the async runtime never blocks on storage.
#[derive(Clone)]
pub struct AppState {
    /// Fixed deployment configuration.
    pub config: Arc<ServerConfig>,
    /// Lazily-connected PostgreSQL runtime; `None` until [`AppState::connect_pg`].
    pub pg: Arc<std::sync::Mutex<Option<proof_pg::wiring::PgRuntime>>>,
    /// Opaque session and CSRF store.
    pub sessions: Arc<SessionStore>,
    /// Token-bucket rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
    /// Deterministic in-process OIDC issuer.
    pub issuer: Arc<DeterministicIssuer>,
}

impl AppState {
    /// Constructs the shared state without opening a database connection
    /// (contract §"PostgreSQL authoritative unit of work").
    ///
    /// # Panics
    ///
    /// Panics if the deterministic issuer cannot be constructed, which cannot
    /// happen for a valid configuration.
    #[must_use]
    pub fn new(config: ServerConfig) -> Self {
        let session_secret = config.session_secret;
        let rate_limit_budget = config.rate_limit_budget;
        let issuer = DeterministicIssuer::new(config.issuer.clone())
            .expect("the deterministic issuer always constructs from a valid configuration");
        Self {
            config: Arc::new(config),
            pg: Arc::new(std::sync::Mutex::new(None)),
            sessions: Arc::new(SessionStore::new(session_secret)),
            rate_limiter: Arc::new(RateLimiter::new(rate_limit_budget)),
            issuer: Arc::new(issuer),
        }
    }

    /// Opens the PostgreSQL runtime and applies the immutable migration ledger
    /// to the session-boundary version (contract §"Migration and projection
    /// rebuild").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Storage`] when connect or migrate fails.
    pub fn connect_pg(&self) -> Result<(), ServerError> {
        todo!("connect, migrate to session-boundary v2, and store the PgRuntime")
    }
}

/// Closed server-boundary error taxonomy (contract §"Envelopes, Problems, and
/// HTTP semantics").
#[derive(Debug, Error)]
pub enum ServerError {
    /// Deployment configuration failed validation.
    #[error("configuration failed: {0}")]
    Config(String),
    /// OIDC login/callback/token validation failed.
    #[error("OIDC failed: {0}")]
    Oidc(String),
    /// Opaque session resolution or mutation failed.
    #[error("session failed: {0}")]
    Session(String),
    /// CSRF synchronizer validation failed.
    #[error("CSRF failed: {0}")]
    Csrf(String),
    /// Authentication or authorization failed.
    #[error("authorization failed: {0}")]
    Authorization(String),
    /// Route-qualified registry dispatch failed.
    #[error("dispatch failed: {0}")]
    Dispatch(String),
    /// The PostgreSQL authority store failed.
    #[error("storage failed: {0}")]
    Storage(#[from] proof_pg::PgError),
    /// Bounded rate limit exceeded (adapter denial control).
    #[error("rate limit exceeded")]
    RateLimited,
    /// The 30-second application deadline was exhausted.
    #[error("application deadline exceeded")]
    DeadlineExceeded,
    /// Disclosure-neutral internal integrity or invariant failure.
    #[error("internal failure: {0}")]
    Internal(String),
}
