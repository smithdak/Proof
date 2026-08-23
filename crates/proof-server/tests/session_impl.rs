//! Integration tests for the PostgreSQL-backed opaque session store, the
//! session-bound CSRF synchronizer, and the exact cookie shapes
//! (`proof_server::session`).
//!
//! Every test creates its own dedicated schema (`CREATE SCHEMA` +
//! `SET search_path` + the additive v2 session-boundary DDL) and drops it with
//! `DROP SCHEMA ... CASCADE` on teardown, so parallel agents never collide. The
//! database itself is never created or dropped.

#![allow(clippy::duration_suboptimal_units)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use cookie::SameSite;
use proof_domain::WorkspaceId;
use proof_pg::PgConfig;
use proof_pg::wiring::PgRuntime;
use proof_server::ServerError;
use proof_server::session::{
    Clock, OIDC_TX_COOKIE_NAME, SESSION_COOKIE_NAME, SessionId, SessionProjection, SessionStore,
    oidc_tx_cookie, session_cookie,
};

/// A fixed 32-byte session secret for every test.
const SECRET: [u8; 32] = [0x5a; 32];

/// A fixed whole-second epoch offset so stored timestamps round-trip exactly
/// through `TIMESTAMPTZ` (microsecond precision).
const EPOCH_SECONDS: u64 = 1_700_000_000;

static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

/// A deterministic, manually advanced wall clock.
struct TestClock(Mutex<u64>);

impl TestClock {
    fn new(epoch_secs: u64) -> Self {
        Self(Mutex::new(epoch_secs))
    }

    fn advance(&self, seconds: u64) {
        *self.0.lock().unwrap() += seconds;
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(*self.0.lock().unwrap())
    }
}

/// A store attached to an isolated schema plus a second connection used for
/// direct assertions and schema teardown.
struct TestContext {
    store: SessionStore,
    clock: Arc<TestClock>,
    admin: PgRuntime,
    schema: String,
}

impl TestContext {
    fn new() -> Self {
        let sequence = SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed);
        let schema = format!("p0011_session_{}_{}", std::process::id(), sequence);

        let workspace_id =
            WorkspaceId::from_uuid(uuid::Uuid::now_v7()).expect("UUIDv7 WorkspaceId");
        let config = PgConfig::new(dsn(), workspace_id, Duration::from_secs(30));

        let mut runtime = PgRuntime::connect(config.clone())
            .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        runtime
            .client_mut()
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create schema");
        runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search_path");
        runtime
            .client_mut()
            .batch_execute(proof_pg::migration::SESSION_BOUNDARY_V2_DDL)
            .expect("apply v2 session-boundary DDL");

        let mut admin = PgRuntime::connect(config).expect("connect admin client");
        admin
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set admin search_path");

        let clock = Arc::new(TestClock::new(EPOCH_SECONDS));
        let clock_source: Arc<dyn Clock + Send + Sync> = clock.clone();
        let store = SessionStore::with_clock(SECRET, clock_source);
        store.attach(runtime).expect("attach runtime");

        Self {
            store,
            clock,
            admin,
            schema,
        }
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        let _ = self
            .admin
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// Lowercase hex of a 32-byte digest, mirroring the store's at-rest encoding.
fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[test]
fn cookies_have_exact_flags() {
    let session = session_cookie("opaque-value");
    assert_eq!(session.name(), SESSION_COOKIE_NAME);
    assert_eq!(session.value(), "opaque-value");
    assert_eq!(session.secure(), Some(true));
    assert_eq!(session.http_only(), Some(true));
    assert_eq!(session.same_site(), Some(SameSite::Strict));
    assert_eq!(session.path(), Some("/"));
    assert!(session.domain().is_none());

    let tx = oidc_tx_cookie("tx-value");
    assert_eq!(tx.name(), OIDC_TX_COOKIE_NAME);
    assert_eq!(tx.secure(), Some(true));
    assert_eq!(tx.http_only(), Some(true));
    assert_eq!(tx.same_site(), Some(SameSite::Lax));
    assert_eq!(tx.path(), Some("/auth/oidc/callback"));
    assert!(tx.domain().is_none());
}

#[test]
fn session_id_is_256_bit_opaque_and_unique() {
    let first = SessionId::generate().unwrap();
    let second = SessionId::generate().unwrap();
    assert_eq!(first.as_str().len(), 43, "base64url-no-pad of 32 bytes");
    assert_ne!(first, second);
}

#[test]
fn create_and_resolve_roundtrip() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "authentication-event")
        .unwrap();
    assert_eq!(id.as_str().len(), 43);

    let record = ctx.store.resolve(&id).unwrap();
    assert_eq!(record.workspace_id, "workspace");
    assert_eq!(record.principal_id, "principal");
    assert_eq!(record.binding_id, "binding");
    assert_eq!(record.authentication_event_id, "authentication-event");
    assert_eq!(record.session_id_hash.len(), 32);
    assert_ne!(record.csrf_digest, [0_u8; 32], "a synchronizer is minted");

    let now = ctx.clock.now();
    assert_eq!(record.created_at, now);
    assert_eq!(record.last_seen, now);
    assert_eq!(record.absolute_expiry, now + Duration::from_secs(28_800));

    // Re-resolution touches last_seen.
    ctx.clock.advance(10);
    let touched = ctx.store.resolve(&id).unwrap();
    assert_eq!(touched.last_seen, ctx.clock.now());
}

#[test]
fn rotate_changes_handle_and_preserves_binding() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "authentication-event")
        .unwrap();

    let rotated = ctx.store.rotate(&id).unwrap();
    assert_ne!(rotated, id);

    let record = ctx.store.resolve(&rotated).unwrap();
    assert_eq!(record.workspace_id, "workspace");
    assert_eq!(record.principal_id, "principal");
    assert_eq!(record.binding_id, "binding");
    assert_eq!(record.authentication_event_id, "authentication-event");
    assert_ne!(record.csrf_digest, [0_u8; 32]);

    // The old handle is gone.
    assert!(matches!(
        ctx.store.resolve(&id),
        Err(ServerError::Session(_))
    ));
}

#[test]
fn idle_expiry_invalidates_and_tombstones() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    // Still within the 900-second idle bound.
    ctx.clock.advance(899);
    ctx.store.resolve(&id).unwrap();

    // Exceed idle: last_seen was 899s ago, now 1800s ago.
    ctx.clock.advance(901);
    assert!(matches!(
        ctx.store.resolve(&id),
        Err(ServerError::Session(_))
    ));

    // Expiry invalidated the session, so logout still converges.
    assert!(ctx.store.logout_converge(&id).unwrap());
}

#[test]
fn absolute_expiry_invalidates_even_when_idle_is_kept_alive() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    // Keep the idle window alive while advancing toward the 8-hour absolute
    // bound (47 x 10 minutes = 7h50m).
    for _ in 0..47 {
        ctx.clock.advance(600);
        ctx.store.resolve(&id).unwrap();
    }

    // 8h1m: idle is only 11 minutes but the absolute bound is exceeded.
    ctx.clock.advance(660);
    assert!(matches!(
        ctx.store.resolve(&id),
        Err(ServerError::Session(_))
    ));
}

#[test]
fn revoke_then_replay_converges() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    ctx.store.revoke(&id).unwrap();

    // The revoked handle no longer resolves.
    assert!(matches!(
        ctx.store.resolve(&id),
        Err(ServerError::Session(_))
    ));

    // Logout converges on the already-revoked handle.
    assert!(ctx.store.logout_converge(&id).unwrap());

    // Revoking again is idempotent.
    ctx.store.revoke(&id).unwrap();
}

#[test]
fn logout_converges_for_exact_replay_and_unknown_handle_fails() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    // First logout revokes and converges.
    assert!(ctx.store.logout_converge(&id).unwrap());
    // Exact replay converges without an idempotency key or prior-result leak.
    assert!(ctx.store.logout_converge(&id).unwrap());

    // A handle that never existed does not converge.
    let unknown = SessionId::generate().unwrap();
    assert!(matches!(
        ctx.store.logout_converge(&unknown),
        Err(ServerError::Session(_))
    ));
}

#[test]
fn csrf_digest_is_stored_not_raw_value() {
    let mut ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    let csrf = ctx.store.issue_csrf(&id).unwrap();
    assert_eq!(csrf.value.len(), 43);

    // The session record carries the keyed digest, not the raw value.
    let record = ctx.store.resolve(&id).unwrap();
    assert_eq!(record.csrf_digest, csrf.digest);

    // The database column holds exactly the hex digest, never the raw value.
    let stored: String = ctx
        .admin
        .client_mut()
        .query_one("SELECT csrf_digest FROM proof_csrf_synchronizers", &[])
        .unwrap()
        .get(0);
    assert_eq!(stored, hex(&csrf.digest));
    assert_ne!(stored, csrf.value);
}

#[test]
fn csrf_rotation_invalidates_prior_value_and_invalidation_clears() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    let first = ctx.store.issue_csrf(&id).unwrap();
    ctx.store.validate_csrf(&id, &first.value).unwrap();

    let second = ctx.store.issue_csrf(&id).unwrap();
    assert_ne!(first.digest, second.digest);
    ctx.store.validate_csrf(&id, &second.value).unwrap();

    // The rotated-out value no longer validates.
    assert!(matches!(
        ctx.store.validate_csrf(&id, &first.value),
        Err(ServerError::Csrf(_))
    ));

    // Invalidation clears the synchronizer entirely.
    ctx.store.invalidate_csrf(&id).unwrap();
    assert!(matches!(
        ctx.store.validate_csrf(&id, &second.value),
        Err(ServerError::Csrf(_))
    ));
}

#[test]
fn logout_invalidates_the_synchronizer() {
    let ctx = TestContext::new();
    let id = ctx
        .store
        .create("workspace", "principal", "binding", "auth")
        .unwrap();

    let csrf = ctx.store.issue_csrf(&id).unwrap();
    ctx.store.validate_csrf(&id, &csrf.value).unwrap();

    ctx.store.logout_converge(&id).unwrap();
    assert!(matches!(
        ctx.store.validate_csrf(&id, &csrf.value),
        Err(ServerError::Csrf(_))
    ));
}

#[test]
fn projection_contains_no_raw_claims() {
    let projection = SessionProjection {
        principal_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        authenticated_at: SystemTime::UNIX_EPOCH + Duration::from_secs(EPOCH_SECONDS),
        idle_seconds: 900,
        absolute_seconds: 28_800,
        csrf: "opaque-csrf-value".to_owned(),
    };

    let value = serde_json::to_value(&projection).unwrap();
    let object = value.as_object().expect("projection is an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "absolute_seconds",
            "authenticated_at",
            "csrf",
            "idle_seconds",
            "principal_id",
        ]
    );

    let serialized = serde_json::to_string(&projection).unwrap();
    for banned in [
        "sub",
        "issuer",
        "iss",
        "aud",
        "claims",
        "token",
        "access_token",
        "id_token",
        "email",
        "name",
        "picture",
    ] {
        assert!(
            !serialized.contains(banned),
            "projection leaked a raw OIDC claim fragment `{banned}`: {serialized}"
        );
    }
}
