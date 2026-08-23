//! Opaque server-side session store and session-bound CSRF synchronizer
//! (contract §"OIDC binding and session boundary", §"Human roles and
//! separation of duties").

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cookie::{Cookie, CookieBuilder, SameSite};

use crate::ServerError;

/// Exact application session cookie name (contract §"OIDC binding and session
/// boundary").
pub const SESSION_COOKIE_NAME: &str = "__Host-Http-Proof-Session";

/// Exact OIDC callback one-use transaction-handle cookie name (contract
/// §"OIDC binding and session boundary").
pub const OIDC_TX_COOKIE_NAME: &str = "__Host-Oidc-Tx";

/// Session idle bound: 900 seconds (contract §"OIDC binding and session
/// boundary").
pub const SESSION_IDLE_SECONDS: u64 = 900;

/// Session absolute bound: 28,800 seconds (contract §"OIDC binding and session
/// boundary").
pub const SESSION_ABSOLUTE_SECONDS: u64 = 28_800;

/// Opaque identifier length: 256 bits (contract §"OIDC binding and session
/// boundary").
pub const SESSION_ID_BYTES: usize = 32;

/// CSRF synchronizer length: 256 bits (contract §"OIDC binding and session
/// boundary").
pub const CSRF_VALUE_BYTES: usize = 32;

/// Exact OIDC callback cookie path.
pub const OIDC_TX_COOKIE_PATH: &str = "/auth/oidc/callback";

/// A random 256-bit opaque session identifier, base64url-no-pad on the wire
/// and never stored (only its keyed hash is stored) (contract §"OIDC binding
/// and session boundary").
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    /// Generates a fresh 256-bit session identifier from the OS random source.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the random source is unavailable.
    pub fn generate() -> Result<Self, ServerError> {
        let mut bytes = [0_u8; SESSION_ID_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|error| ServerError::Session(format!("random session id: {error}")))?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// Returns the wire base64url representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The uniform random 256-bit CSRF synchronizer value, returned base64url-no-pad
/// to the browser and stored only as a digest (contract §"OIDC binding and
/// session boundary").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsrfSynchronizer {
    /// Wire base64url value (returned once to the browser).
    pub value: String,
    /// Keyed digest actually stored, bound to one session.
    pub digest: [u8; 32],
}

impl CsrfSynchronizer {
    /// Generates a fresh 256-bit synchronizer and its keyed digest.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] when the random source is unavailable.
    pub fn generate(secret: &[u8; 32]) -> Result<Self, ServerError> {
        let mut bytes = [0_u8; CSRF_VALUE_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|error| ServerError::Csrf(format!("random CSRF: {error}")))?;
        let value = URL_SAFE_NO_PAD.encode(bytes);
        let digest = keyed_digest(secret, value.as_bytes());
        Ok(Self { value, digest })
    }
}

/// Server-side session record: only the keyed hash of the opaque identifier is
/// stored, never the identifier itself (contract §"OIDC binding and session
/// boundary").
#[derive(Clone, Debug)]
pub struct SessionRecord {
    /// Keyed hash of the opaque 256-bit identifier.
    pub session_id_hash: [u8; 32],
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Bound requesting Principal identity (UUIDv7).
    pub principal_id: String,
    /// Bound requesting OIDC binding identity (UUIDv7).
    pub binding_id: String,
    /// Remote authentication event identity (UUIDv7).
    pub authentication_event_id: String,
    /// Keyed digest of the current session-bound CSRF synchronizer.
    pub csrf_digest: [u8; 32],
    /// Creation time.
    pub created_at: SystemTime,
    /// Last observed activity time.
    pub last_seen: SystemTime,
    /// Absolute expiry time.
    pub absolute_expiry: SystemTime,
}

/// Bounded revocation tombstone for an opaque handle and its session-bound CSRF
/// digest (contract §"OIDC binding and session boundary").
#[derive(Clone, Debug)]
pub struct RevocationTombstone {
    /// Keyed hash of the revoked opaque identifier.
    pub session_id_hash: [u8; 32],
    /// Keyed digest of the exact session-bound CSRF value at revocation.
    pub csrf_digest: [u8; 32],
    /// Revocation time.
    pub revoked_at: SystemTime,
}

/// Authenticated same-origin `GET /api/v1/session` projection (contract §"OIDC
/// binding and session boundary"). It is `private, no-store` and carries no raw
/// OIDC claims or provider tokens.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionProjection {
    /// Requesting Principal identity (UUIDv7).
    pub principal_id: String,
    /// Session creation time.
    pub authenticated_at: SystemTime,
    /// Session idle bound in seconds.
    pub idle_seconds: u64,
    /// Session absolute bound in seconds.
    pub absolute_seconds: u64,
    /// Fresh uniform random 256-bit base64url CSRF synchronizer.
    pub csrf: String,
}

/// In-memory opaque session store plus revocation tombstones (contract §"OIDC
/// binding and session boundary"). The PostgreSQL persistence adapter mirrors
/// this state into the proof-pg session-boundary migration.
pub struct SessionStore {
    secret: [u8; 32],
    sessions: Mutex<HashMap<[u8; 32], SessionRecord>>,
    tombstones: Mutex<HashMap<[u8; 32], RevocationTombstone>>,
}

impl SessionStore {
    /// Constructs a session store keyed by a 32-byte session secret.
    #[must_use]
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            sessions: Mutex::new(HashMap::new()),
            tombstones: Mutex::new(HashMap::new()),
        }
    }

    /// Creates one fresh session bound to a Principal/binding/authentication
    /// event (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the identifier cannot be minted.
    pub fn create(
        &self,
        workspace_id: &str,
        principal_id: &str,
        binding_id: &str,
        authentication_event_id: &str,
    ) -> Result<SessionId, ServerError> {
        todo!("mint id, store keyed hash + csrf digest, return wire id")
    }

    /// Re-resolves the immutable binding and session record for one wire
    /// identifier, enforcing the idle and absolute bounds (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] for an unknown, expired, idle-exceeded,
    /// or tombstoned handle.
    pub fn resolve(&self, session_id: &SessionId) -> Result<SessionRecord, ServerError> {
        todo!("keyed-hash lookup, enforce bounds, touch last_seen")
    }

    /// Rotates one session to a fresh identifier, carrying the same binding
    /// (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when rotation fails.
    pub fn rotate(&self, session_id: &SessionId) -> Result<SessionId, ServerError> {
        todo!("mint replacement id, move record, drop old handle")
    }

    /// Revokes one session and retains a bounded tombstone (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when revocation fails.
    pub fn revoke(&self, session_id: &SessionId) -> Result<(), ServerError> {
        todo!("remove record and write a bounded revocation tombstone")
    }

    /// Converges logout for an exact replay or an already-revoked handle to
    /// `logged_out: true` (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the tombstone write fails.
    pub fn logout_converge(&self, session_id: &SessionId) -> Result<bool, ServerError> {
        todo!("validate active-or-tombstone handle and return logged_out:true")
    }

    /// Issues a fresh session-bound CSRF synchronizer and stores its digest
    /// (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] when the synchronizer cannot be minted.
    pub fn issue_csrf(&self, session_id: &SessionId) -> Result<CsrfSynchronizer, ServerError> {
        todo!("generate synchronizer and store its digest on the session")
    }

    /// Validates an exact session-bound `Proof-CSRF` value against its stored
    /// digest (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] on a missing or mismatched synchronizer.
    pub fn validate_csrf(&self, session_id: &SessionId, value: &str) -> Result<(), ServerError> {
        todo!("recompute keyed digest and compare to the stored session digest")
    }

    /// Invalidates the current synchronizer with the session (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] when invalidation fails.
    pub fn invalidate_csrf(&self, session_id: &SessionId) -> Result<(), ServerError> {
        todo!("clear the stored digest")
    }
}

/// Builds the strict application session cookie: `Secure`, `HttpOnly`,
/// `SameSite=Strict`, `Path=/`, no `Domain` (contract §"OIDC binding and
/// session boundary").
#[must_use]
pub fn session_cookie(value: &str) -> Cookie<'static> {
    CookieBuilder::new(SESSION_COOKIE_NAME, value.to_owned())
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}

/// Builds the short-lived one-use OIDC callback transaction cookie: `Secure`,
/// `HttpOnly`, `SameSite=Lax`, `Path=/auth/oidc/callback` (contract §"OIDC
/// binding and session boundary").
#[must_use]
pub fn oidc_tx_cookie(value: &str) -> Cookie<'static> {
    CookieBuilder::new(OIDC_TX_COOKIE_NAME, value.to_owned())
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .path(OIDC_TX_COOKIE_PATH)
        .build()
}

/// Computes the keyed at-rest digest used for session handles and CSRF values.
#[must_use]
fn keyed_digest(secret: &[u8; 32], value: &[u8]) -> [u8; 32] {
    *blake3::keyed_hash(secret, value).as_bytes()
}
