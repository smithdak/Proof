//! Opaque server-side session store and session-bound CSRF synchronizer
//! (contract §"OIDC binding and session boundary", §"Human roles and
//! separation of duties").
//!
//! The store is PostgreSQL-backed and persists only keyed hashes of opaque
//! material into the additive v2 session-boundary migration
//! ([`proof_pg::migration::SESSION_BOUNDARY_V2_DDL`]). The synchronous client
//! is guarded by a mutex and driven by the caller behind the async runtime, so
//! the runtime never blocks on storage.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

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

    /// Reconstructs a session identifier from its wire base64url representation
    /// (a request cookie value), validating the canonical 256-bit form.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the wire value is not a canonical
    /// base64url-no-pad encoding of exactly 32 bytes.
    pub fn from_wire(value: &str) -> Result<Self, ServerError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|error| ServerError::Session(format!("invalid session id: {error}")))?;
        if bytes.len() != SESSION_ID_BYTES {
            return Err(ServerError::Session(
                "session id is not 256 bits".to_owned(),
            ));
        }
        if URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(ServerError::Session("non-canonical session id".to_owned()));
        }
        Ok(Self(value.to_owned()))
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

/// An injectable wall-clock source so session lifetime tests can drive time
/// deterministically (contract §"OIDC binding and session boundary").
pub trait Clock: Send + Sync {
    /// Returns the current wall-clock instant.
    fn now(&self) -> SystemTime;
}

/// The production wall clock (contract §"OIDC binding and session boundary").
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// PostgreSQL-backed opaque session store plus revocation tombstones (contract
/// §"OIDC binding and session boundary"). Only keyed hashes of the opaque
/// identifier and CSRF material are persisted, into the proof-pg
/// session-boundary migration.
///
/// The synchronous [`proof_pg::wiring::PgRuntime`] is attached after connect
/// (and after the caller has pointed its `search_path` at an isolated schema in
/// tests); every operation runs behind a single mutex, matching the
/// single-writer storage contract.
pub struct SessionStore {
    secret: [u8; 32],
    clock: Arc<dyn Clock + Send + Sync>,
    runtime: Mutex<Option<proof_pg::wiring::PgRuntime>>,
}

impl SessionStore {
    /// Constructs a session store keyed by a 32-byte session secret, using the
    /// system wall clock and no attached PostgreSQL runtime yet (the caller
    /// attaches one with [`SessionStore::attach`] after connect).
    #[must_use]
    pub fn new(secret: [u8; 32]) -> Self {
        Self::with_clock(secret, Arc::new(SystemClock))
    }

    /// Constructs a session store keyed by a 32-byte session secret with an
    /// injected time source, and no attached PostgreSQL runtime yet.
    #[must_use]
    pub fn with_clock(secret: [u8; 32], clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self {
            secret,
            clock,
            runtime: Mutex::new(None),
        }
    }

    /// Attaches an already-connected PostgreSQL runtime (whose `search_path`
    /// already points at the session-boundary schema).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Internal`] when the store lock is poisoned.
    pub fn attach(&self, runtime: proof_pg::wiring::PgRuntime) -> Result<(), ServerError> {
        let mut guard = self.lock()?;
        *guard = Some(runtime);
        Ok(())
    }

    /// Creates one fresh session bound to a Principal/binding/authentication
    /// event (contract §"OIDC binding and session boundary"). It also mints the
    /// initial session-bound CSRF synchronizer (its value is never revealed;
    /// the acquisition route rotates it again before disclosure).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the identifier cannot be minted or
    /// the row cannot be written, or [`ServerError::Csrf`] when the initial
    /// synchronizer cannot be minted.
    pub fn create(
        &self,
        workspace_id: &str,
        principal_id: &str,
        binding_id: &str,
        authentication_event_id: &str,
    ) -> Result<SessionId, ServerError> {
        let id = SessionId::generate()?;
        let hash = session_hash(&self.secret, &id);
        let hash_hex = hex(&hash);
        let now = self.clock.now();
        let absolute_expiry = now
            .checked_add(Duration::from_secs(SESSION_ABSOLUTE_SECONDS))
            .ok_or_else(|| ServerError::Session("absolute expiry overflow".to_owned()))?;
        let csrf = CsrfSynchronizer::generate(&self.secret)?;
        let csrf_hex = hex(&csrf.digest);

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();
            let mut tx = client.transaction().map_err(storage_err)?;
            tx.execute(
                "INSERT INTO proof_sessions \
                 (session_id_hash, workspace_id, requesting_principal_id, \
                  requesting_binding_id, authentication_event_id, created_at, \
                  last_seen_at, absolute_expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &hash_hex,
                    &workspace_id,
                    &principal_id,
                    &binding_id,
                    &authentication_event_id,
                    &now,
                    &now,
                    &absolute_expiry,
                ],
            )
            .map_err(storage_err)?;
            tx.execute(
                "INSERT INTO proof_csrf_synchronizers \
                 (session_id_hash, csrf_digest, issued_at) \
                 VALUES ($1, $2, $3)",
                &[&hash_hex, &csrf_hex, &now],
            )
            .map_err(storage_err)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })?;

        Ok(id)
    }

    /// Re-resolves the immutable binding and session record for one wire
    /// identifier, enforcing the idle and absolute bounds (contract §"OIDC
    /// binding and session boundary"). A live resolution touches `last_seen`; an
    /// expired or idle-exceeded resolution invalidates the session and writes a
    /// bounded tombstone before returning.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] for an unknown, expired, idle-exceeded,
    /// or tombstoned handle, or [`ServerError::Storage`] on persistence failure.
    pub fn resolve(&self, session_id: &SessionId) -> Result<SessionRecord, ServerError> {
        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);
        let now = self.clock.now();

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();

            if client
                .query_opt(
                    "SELECT 1 FROM proof_session_revocations WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .is_some()
            {
                return Err(ServerError::Session("session revoked".to_owned()));
            }

            let row = client
                .query_opt(
                    "SELECT workspace_id, requesting_principal_id, requesting_binding_id, \
                     authentication_event_id, created_at, last_seen_at, absolute_expires_at \
                     FROM proof_sessions WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .ok_or_else(|| ServerError::Session("unknown session".to_owned()))?;

            let workspace_id: String = row.get(0);
            let principal_id: String = row.get(1);
            let binding_id: String = row.get(2);
            let authentication_event_id: String = row.get(3);
            let created_at: SystemTime = row.get(4);
            let last_seen: SystemTime = row.get(5);
            let absolute_expiry: SystemTime = row.get(6);

            let idle_exceeded = now
                .duration_since(last_seen)
                .is_ok_and(|idle| idle >= Duration::from_secs(SESSION_IDLE_SECONDS));
            if now >= absolute_expiry || idle_exceeded {
                let csrf_hex =
                    Self::current_csrf_hex(runtime, &hash_hex)?.unwrap_or_else(|| hex(&[0_u8; 32]));
                invalidate_session(runtime, &hash_hex, &csrf_hex, now)?;
                return Err(ServerError::Session("session expired".to_owned()));
            }

            client
                .execute(
                    "UPDATE proof_sessions SET last_seen_at = $1 WHERE session_id_hash = $2",
                    &[&now, &hash_hex],
                )
                .map_err(storage_err)?;

            let csrf_digest = match Self::current_csrf_hex(runtime, &hash_hex)? {
                Some(encoded) => decode_hex(&encoded)?,
                None => [0_u8; 32],
            };

            Ok(SessionRecord {
                session_id_hash: hash,
                workspace_id,
                principal_id,
                binding_id,
                authentication_event_id,
                csrf_digest,
                created_at,
                last_seen: now,
                absolute_expiry,
            })
        })
    }

    /// Rotates one session to a fresh identifier, carrying the same binding and
    /// issuing a fresh session-bound CSRF synchronizer (contract §"OIDC binding
    /// and session boundary"). The old handle is dropped; it is not tombstoned.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] for an unknown or tombstoned handle, or
    /// when the replacement identifier cannot be minted.
    pub fn rotate(&self, session_id: &SessionId) -> Result<SessionId, ServerError> {
        let old_hash = session_hash(&self.secret, session_id);
        let old_hex = hex(&old_hash);

        let replacement = SessionId::generate()?;
        let new_hash = session_hash(&self.secret, &replacement);
        let new_hex = hex(&new_hash);
        let now = self.clock.now();
        let absolute_expiry = now
            .checked_add(Duration::from_secs(SESSION_ABSOLUTE_SECONDS))
            .ok_or_else(|| ServerError::Session("absolute expiry overflow".to_owned()))?;
        let csrf = CsrfSynchronizer::generate(&self.secret)?;
        let csrf_hex = hex(&csrf.digest);

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();

            if client
                .query_opt(
                    "SELECT 1 FROM proof_session_revocations WHERE session_id_hash = $1",
                    &[&old_hex],
                )
                .map_err(storage_err)?
                .is_some()
            {
                return Err(ServerError::Session("session revoked".to_owned()));
            }

            let row = client
                .query_opt(
                    "SELECT workspace_id, requesting_principal_id, requesting_binding_id, \
                     authentication_event_id FROM proof_sessions WHERE session_id_hash = $1",
                    &[&old_hex],
                )
                .map_err(storage_err)?
                .ok_or_else(|| ServerError::Session("unknown session".to_owned()))?;
            let workspace_id: String = row.get(0);
            let principal_id: String = row.get(1);
            let binding_id: String = row.get(2);
            let authentication_event_id: String = row.get(3);

            let mut tx = client.transaction().map_err(storage_err)?;
            tx.execute(
                "DELETE FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
                &[&old_hex],
            )
            .map_err(storage_err)?;
            tx.execute(
                "DELETE FROM proof_sessions WHERE session_id_hash = $1",
                &[&old_hex],
            )
            .map_err(storage_err)?;
            tx.execute(
                "INSERT INTO proof_sessions \
                 (session_id_hash, workspace_id, requesting_principal_id, \
                  requesting_binding_id, authentication_event_id, created_at, \
                  last_seen_at, absolute_expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &new_hex,
                    &workspace_id,
                    &principal_id,
                    &binding_id,
                    &authentication_event_id,
                    &now,
                    &now,
                    &absolute_expiry,
                ],
            )
            .map_err(storage_err)?;
            tx.execute(
                "INSERT INTO proof_csrf_synchronizers \
                 (session_id_hash, csrf_digest, issued_at) \
                 VALUES ($1, $2, $3)",
                &[&new_hex, &csrf_hex, &now],
            )
            .map_err(storage_err)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })?;

        Ok(replacement)
    }

    /// Revokes one session and retains a bounded tombstone (contract §"OIDC
    /// binding and session boundary"). Revoking an already-revoked handle is an
    /// idempotent no-op.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] for an unknown handle, or when
    /// revocation fails.
    pub fn revoke(&self, session_id: &SessionId) -> Result<(), ServerError> {
        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);
        let now = self.clock.now();

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();

            if client
                .query_opt(
                    "SELECT 1 FROM proof_session_revocations WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .is_some()
            {
                return Ok(());
            }

            let exists = client
                .query_opt(
                    "SELECT 1 FROM proof_sessions WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .is_some();
            if !exists {
                return Err(ServerError::Session("unknown session".to_owned()));
            }

            let csrf_hex =
                Self::current_csrf_hex(runtime, &hash_hex)?.unwrap_or_else(|| hex(&[0_u8; 32]));
            invalidate_session(runtime, &hash_hex, &csrf_hex, now)
        })
    }

    /// Converges logout for an exact replay or an already-revoked handle to
    /// `logged_out: true` (contract §"OIDC binding and session boundary"). It
    /// uses no application idempotency key and discloses no prior result.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] for an unknown handle, or when the
    /// tombstone write fails.
    pub fn logout_converge(&self, session_id: &SessionId) -> Result<bool, ServerError> {
        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);
        let now = self.clock.now();

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();

            if client
                .query_opt(
                    "SELECT 1 FROM proof_session_revocations WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .is_some()
            {
                return Ok(true);
            }

            let exists = client
                .query_opt(
                    "SELECT 1 FROM proof_sessions WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .is_some();
            if !exists {
                return Err(ServerError::Session("unknown session".to_owned()));
            }

            let csrf_hex =
                Self::current_csrf_hex(runtime, &hash_hex)?.unwrap_or_else(|| hex(&[0_u8; 32]));
            invalidate_session(runtime, &hash_hex, &csrf_hex, now)?;
            Ok(true)
        })
    }

    /// Issues a fresh session-bound CSRF synchronizer and stores its digest
    /// (contract §"OIDC binding and session boundary"). The prior synchronizer,
    /// if any, is invalidated.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Session`] when the session is not live, or
    /// [`ServerError::Csrf`] when the synchronizer cannot be minted.
    pub fn issue_csrf(&self, session_id: &SessionId) -> Result<CsrfSynchronizer, ServerError> {
        // Re-resolves the session: enforces bounds, touches last_seen, and
        // refuses tombstoned/unknown handles before rotating the synchronizer.
        self.resolve(session_id)?;

        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);
        let csrf = CsrfSynchronizer::generate(&self.secret)?;
        let csrf_hex = hex(&csrf.digest);
        let now = self.clock.now();

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();
            let mut tx = client.transaction().map_err(storage_err)?;
            tx.execute(
                "DELETE FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
                &[&hash_hex],
            )
            .map_err(storage_err)?;
            tx.execute(
                "INSERT INTO proof_csrf_synchronizers \
                 (session_id_hash, csrf_digest, issued_at) \
                 VALUES ($1, $2, $3)",
                &[&hash_hex, &csrf_hex, &now],
            )
            .map_err(storage_err)?;
            tx.commit().map_err(storage_err)?;
            Ok(())
        })?;

        Ok(csrf)
    }

    /// Validates an exact session-bound `Proof-CSRF` value against its stored
    /// digest (contract §"OIDC binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] on a missing or mismatched synchronizer.
    pub fn validate_csrf(&self, session_id: &SessionId, value: &str) -> Result<(), ServerError> {
        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);
        let expected = hex(&keyed_digest(&self.secret, value.as_bytes()));

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();
            let stored: Option<String> = client
                .query_opt(
                    "SELECT csrf_digest FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(storage_err)?
                .map(|row| row.get(0));

            match stored {
                Some(digest) if digest == expected => Ok(()),
                Some(_) => Err(ServerError::Csrf("CSRF synchronizer mismatch".to_owned())),
                None => Err(ServerError::Csrf("missing CSRF synchronizer".to_owned())),
            }
        })
    }

    /// Invalidates the current synchronizer with the session (contract §"OIDC
    /// binding and session boundary").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError::Csrf`] when invalidation fails.
    pub fn invalidate_csrf(&self, session_id: &SessionId) -> Result<(), ServerError> {
        let hash = session_hash(&self.secret, session_id);
        let hash_hex = hex(&hash);

        self.with_runtime(|runtime| {
            let client = runtime.client_mut();
            client
                .execute(
                    "DELETE FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
                    &[&hash_hex],
                )
                .map_err(|error| ServerError::Csrf(format!("invalidate CSRF: {error}")))?;
            Ok(())
        })
    }

    /// Locks the runtime guard, mapping a poisoned lock to an internal failure.
    fn lock(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<proof_pg::wiring::PgRuntime>>, ServerError> {
        self.runtime
            .lock()
            .map_err(|_| ServerError::Internal("session store lock poisoned".to_owned()))
    }

    /// Runs one storage operation against the attached PostgreSQL runtime.
    fn with_runtime<T>(
        &self,
        operation: impl FnOnce(&mut proof_pg::wiring::PgRuntime) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        let mut guard = self.lock()?;
        let runtime = guard.as_mut().ok_or_else(|| {
            ServerError::Internal("session store has no attached PostgreSQL runtime".to_owned())
        })?;
        operation(runtime)
    }

    /// Reads the current CSRF digest (hex) for one session, if any.
    fn current_csrf_hex(
        runtime: &mut proof_pg::wiring::PgRuntime,
        hash_hex: &str,
    ) -> Result<Option<String>, ServerError> {
        let row = runtime
            .client_mut()
            .query_opt(
                "SELECT csrf_digest FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
                &[&hash_hex],
            )
            .map_err(storage_err)?;
        Ok(row.map(|row| row.get(0)))
    }
}

/// Removes one session and its synchronizer, then writes a bounded revocation
/// tombstone referencing the exact synchronizer digest at revocation.
fn invalidate_session(
    runtime: &mut proof_pg::wiring::PgRuntime,
    hash_hex: &str,
    csrf_hex: &str,
    revoked_at: SystemTime,
) -> Result<(), ServerError> {
    let client = runtime.client_mut();
    let mut tx = client.transaction().map_err(storage_err)?;
    tx.execute(
        "DELETE FROM proof_csrf_synchronizers WHERE session_id_hash = $1",
        &[&hash_hex],
    )
    .map_err(storage_err)?;
    tx.execute(
        "DELETE FROM proof_sessions WHERE session_id_hash = $1",
        &[&hash_hex],
    )
    .map_err(storage_err)?;
    tx.execute(
        "INSERT INTO proof_session_revocations (session_id_hash, csrf_digest, revoked_at) \
         VALUES ($1, $2, $3) ON CONFLICT (session_id_hash) DO NOTHING",
        &[&hash_hex, &csrf_hex, &revoked_at],
    )
    .map_err(storage_err)?;
    tx.commit().map_err(storage_err)?;
    Ok(())
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

/// Computes the keyed hash of one opaque session identifier's wire form.
#[must_use]
fn session_hash(secret: &[u8; 32], id: &SessionId) -> [u8; 32] {
    keyed_digest(secret, id.as_str().as_bytes())
}

/// Maps a storage-layer failure onto the closed storage error variant without
/// naming the `postgres` error type (which is not a direct dependency).
fn storage_err(error: impl std::fmt::Display) -> ServerError {
    ServerError::Storage(proof_pg::PgError::Transaction(format!(
        "session store: {error}"
    )))
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex encoding of a 32-byte digest.
#[must_use]
fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX_CHARS[usize::from(byte >> 4)] as char);
        out.push(HEX_CHARS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// Decodes a 64-character lowercase hex digest back into 32 bytes.
fn decode_hex(encoded: &str) -> Result<[u8; 32], ServerError> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 64 {
        return Err(ServerError::Internal(format!(
            "corrupt stored digest length {}",
            bytes.len()
        )));
    }
    let mut out = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, ServerError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(ServerError::Internal(format!(
            "corrupt stored digest nibble {other:#04x}"
        ))),
    }
}
