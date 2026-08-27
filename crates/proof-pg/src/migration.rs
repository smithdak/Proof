//! Immutable checksummed migration ledger (contract §"Migration and projection
//! rebuild").

use postgres::Client;
use proof_domain::ContentDigest;
use proof_remote::derive_key_digest;
use serde::{Deserialize, Serialize};

use crate::PgError;

/// Domain-separated BLAKE3-256 derive-key context over exact migration script
/// bytes (contract §"Migration and projection rebuild").
pub const MIGRATION_SCRIPT_DIGEST_CONTEXT: &str = "proof:migration-script:v1";

/// Computes the domain-separated BLAKE3-256 digest of exact script bytes.
#[must_use]
pub fn migration_script_digest(exact_script_bytes: &[u8]) -> ContentDigest {
    derive_key_digest(MIGRATION_SCRIPT_DIGEST_CONTEXT, exact_script_bytes)
}

/// One immutable migration script with a monotonic version, name, and
/// domain-separated digest of its exact bytes (contract §"Migration and
/// projection rebuild").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationScriptV1 {
    /// Monotonic positive migration version.
    pub version: u32,
    /// Stable migration name.
    pub name: String,
    /// Domain-separated BLAKE3-256 digest of the exact `sql` bytes.
    pub digest: ContentDigest,
    /// Exact, never-rewritten migration script bytes.
    pub sql: String,
}

impl MigrationScriptV1 {
    /// Binds a version, name, and exact script bytes together with their
    /// domain-separated digest.
    #[must_use]
    pub fn new(version: u32, name: impl Into<String>, sql: impl Into<String>) -> Self {
        let sql = sql.into();
        let digest = migration_script_digest(sql.as_bytes());
        Self {
            version,
            name: name.into(),
            digest,
            sql,
        }
    }
}

/// Per-phase ledger status (contract §"Migration and projection rebuild").
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    /// Migration work began.
    Started,
    /// Migration was verified and the Schema version advanced.
    Verified,
    /// Migration failed and left a dirty phase.
    Failed,
}

/// Fail-closed refusal reasons (contract §"Migration and projection rebuild").
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRefusal {
    /// The stored script digest does not match the exact bytes.
    ChecksumMismatch,
    /// The ledger is in a dirty or failed phase.
    DirtyPhase,
    /// The ledger head is a newer unknown version.
    UnknownNewer,
    /// The write is outside the declared compatibility interval.
    OutsideInterval,
}

/// The durable singleton migration-head ledger (contract §"Migration and
/// projection rebuild").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationLedger {
    /// Current committed head version.
    pub head_version: u32,
    /// Digest of the exact head script bytes.
    pub head_digest: ContentDigest,
    /// Current phase.
    pub phase: MigrationPhase,
}

/// The actor recorded in the migration ledger by this crate's migrator.
///
/// The ledger is written only by the singleton migrator below, so a fixed
/// stable actor string is sufficient for the first profile.
const MIGRATOR_ACTOR: &str = "proof-pg-migrator";

/// The tool version recorded in the migration ledger by this crate's migrator.
const MIGRATOR_TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

impl MigrationLedger {
    /// Fixed PostgreSQL advisory-lock key that admits exactly one migrator
    /// across transactional and nontransactional phases.
    pub const ADVISORY_LOCK_KEY: i64 = 0x5072_6F6F_6650_4731;
    /// The single durable head row key.
    pub const SINGLETON_HEAD_ROW: i32 = 1;

    /// Verifies the singleton head snapshot is present and coherent.
    ///
    /// A coherent head carries a positive version and a non-dirty phase. A
    /// `failed` phase is a recorded dirty state that blocks every write until a
    /// forward repair is selected; a `started` phase is a valid resumable state
    /// for the (later) nontransactional phases.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Migration`] when the version is not positive or the
    /// phase is dirty.
    pub fn verify_head(&self) -> Result<(), PgError> {
        if self.head_version == 0 {
            return Err(PgError::Migration(
                "migration head is not a valid singleton: version must be positive".to_owned(),
            ));
        }
        if self.phase == MigrationPhase::Failed {
            return self.refuse_on(MigrationRefusal::DirtyPhase);
        }
        Ok(())
    }

    /// Fails closed on the supplied refusal reason.
    ///
    /// # Errors
    ///
    /// Always returns [`PgError::Migration`] describing `reason`.
    pub fn refuse_on(&self, reason: MigrationRefusal) -> Result<(), PgError> {
        let message = match reason {
            MigrationRefusal::ChecksumMismatch => format!(
                "migration checksum mismatch: head version {} digest {} does not match the supplied script bytes",
                self.head_version, self.head_digest,
            ),
            MigrationRefusal::DirtyPhase => format!(
                "migration head version {} is in a dirty {:?} phase",
                self.head_version, self.phase,
            ),
            MigrationRefusal::UnknownNewer => format!(
                "migration head version {} is newer than the supplied script version; forward repair required",
                self.head_version,
            ),
            MigrationRefusal::OutsideInterval => format!(
                "migration head version {} is outside the declared compatibility interval",
                self.head_version,
            ),
        };
        Err(PgError::Migration(message))
    }
}

/// Reads the current singleton head snapshot, when a migration has been
/// committed.
///
/// The returned [`MigrationLedger`] is the in-memory mirror of the single
/// durable `migration_head` row; it is `None` only before the first migration.
///
/// # Errors
///
/// Returns [`PgError::Migration`] when the row cannot be read or carries an
/// unparsable digest or phase.
pub fn read_head(client: &mut Client) -> Result<Option<MigrationLedger>, PgError> {
    let row = client
        .query_opt(
            "SELECT version, script_digest, phase FROM migration_head WHERE singleton = $1",
            &[&MigrationLedger::SINGLETON_HEAD_ROW],
        )
        .map_err(|error| PgError::Migration(format!("cannot read migration head: {error}")))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let version: i32 = row.get(0);
    let digest_text: String = row.get(1);
    let phase_text: String = row.get(2);

    let head_version = u32::try_from(version)
        .map_err(|_| PgError::Migration(format!("invalid migration head version {version}")))?;
    let head_digest = digest_text.parse::<ContentDigest>().map_err(|error| {
        PgError::Migration(format!(
            "invalid migration head digest {digest_text:?}: {error}"
        ))
    })?;
    let phase = match phase_text.as_str() {
        "started" => MigrationPhase::Started,
        "verified" => MigrationPhase::Verified,
        "failed" => MigrationPhase::Failed,
        other => {
            return Err(PgError::Migration(format!(
                "unknown migration head phase {other:?}"
            )));
        }
    };

    Ok(Some(MigrationLedger {
        head_version,
        head_digest,
        phase,
    }))
}

/// Runs the expand/backfill/verify/cutover migration contract for one script.
///
/// The fixed advisory lock is taken for the whole read-decide-apply window so
/// exactly one migrator proceeds; concurrent migrators serialize and observe
/// the already-advanced head as a no-op. Transactional phases (DDL, backfill,
/// verification, and version advancement) run in one transaction and record the
/// `started` then `verified` phase state; a failure records `failed` in a fresh
/// transaction after the primary transaction rolls back.
///
/// # Errors
///
/// Returns [`PgError::Migration`] on checksum mismatch, dirty phase, unknown
/// newer version, or a write outside the compatibility interval.
pub fn run_expand_backfill_verify_cutover(
    client: &mut Client,
    script: &MigrationScriptV1,
) -> Result<(), PgError> {
    if script.version == 0 {
        return Err(PgError::Migration(
            "migration version must be positive".to_owned(),
        ));
    }

    client
        .execute(
            "SELECT pg_advisory_lock($1)",
            &[&MigrationLedger::ADVISORY_LOCK_KEY],
        )
        .map_err(|error| {
            PgError::Migration(format!("cannot acquire migration advisory lock: {error}"))
        })?;

    let result = run_expand_backfill_verify_cutover_locked(client, script);

    if let Err(error) = client.execute(
        "SELECT pg_advisory_unlock($1)",
        &[&MigrationLedger::ADVISORY_LOCK_KEY],
    ) {
        return Err(PgError::Migration(format!(
            "cannot release migration advisory lock: {error}"
        )));
    }

    result
}

/// The lock-holding body of [`run_expand_backfill_verify_cutover`].
fn run_expand_backfill_verify_cutover_locked(
    client: &mut Client,
    script: &MigrationScriptV1,
) -> Result<(), PgError> {
    let head = read_head(client)?;
    match head {
        None => apply_script(client, script),
        Some(head) if head.head_version < script.version => apply_script(client, script),
        Some(head) if head.head_version > script.version => {
            head.refuse_on(MigrationRefusal::UnknownNewer)
        }
        Some(head) if head.head_digest != script.digest => {
            head.refuse_on(MigrationRefusal::ChecksumMismatch)
        }
        Some(head) => match head.phase {
            MigrationPhase::Verified => Ok(()),
            MigrationPhase::Failed => head.refuse_on(MigrationRefusal::DirtyPhase),
            MigrationPhase::Started => Err(PgError::Migration(
                "migration head is in a resumable 'started' phase; this transactional migrator cannot resume it"
                    .to_owned(),
            )),
        },
    }
}

/// Applies one pending script transactionally and records the phase state.
fn apply_script(client: &mut Client, script: &MigrationScriptV1) -> Result<(), PgError> {
    let version = i32::try_from(script.version).map_err(|_| {
        PgError::Migration(format!(
            "migration version {} exceeds the ledger range",
            script.version
        ))
    })?;
    let digest = script.digest.to_string();

    let applied = (|| -> Result<(), PgError> {
        let mut tx = client.transaction().map_err(|error| {
            PgError::Migration(format!("cannot begin migration transaction: {error}"))
        })?;

        tx.execute(
            "INSERT INTO migration_head
                 (singleton, version, name, script_digest, phase, actor, tool_version, started_at)
             VALUES ($1, $2, $3, $4, 'started', $5, $6, now())
             ON CONFLICT (singleton) DO UPDATE SET
                 version = EXCLUDED.version,
                 name = EXCLUDED.name,
                 script_digest = EXCLUDED.script_digest,
                 phase = 'started',
                 actor = EXCLUDED.actor,
                 tool_version = EXCLUDED.tool_version,
                 started_at = now(),
                 verified_at = NULL",
            &[
                &MigrationLedger::SINGLETON_HEAD_ROW,
                &version,
                &script.name,
                &digest,
                &MIGRATOR_ACTOR,
                &MIGRATOR_TOOL_VERSION,
            ],
        )
        .map_err(|error| PgError::Migration(format!("cannot record migration start: {error}")))?;

        tx.batch_execute(&script.sql).map_err(|error| {
            let detail = error.as_db_error().map_or_else(
                || error.to_string(),
                |database| database.message().to_owned(),
            );
            PgError::Migration(format!(
                "migration script for version {} failed: {detail}",
                script.version
            ))
        })?;

        tx.execute(
            "UPDATE workspace_write_head
             SET migration_version = $1
             WHERE migration_version < $1",
            &[&version],
        )
        .map_err(|error| {
            PgError::Migration(format!(
                "cannot advance the Workspace migration version to {}: {error}",
                script.version
            ))
        })?;

        tx.execute(
            "UPDATE migration_head
             SET phase = 'verified', verified_at = now()
             WHERE singleton = $1",
            &[&MigrationLedger::SINGLETON_HEAD_ROW],
        )
        .map_err(|error| {
            PgError::Migration(format!("cannot record migration verification: {error}"))
        })?;

        tx.commit()
            .map_err(|error| PgError::Migration(format!("cannot commit migration: {error}")))
    })();

    match applied {
        Ok(()) => Ok(()),
        Err(error) => {
            // The primary transaction rolled back; record the dirty phase in a
            // fresh transaction so future migrators fail closed.
            if let Err(record_error) = record_failed_phase(client, script, version, &digest) {
                return Err(PgError::Migration(format!(
                    "{error}; additionally failed to record the failed phase: {record_error}"
                )));
            }
            Err(error)
        }
    }
}

/// Records the dirty `failed` phase after a migration transaction rolled back.
fn record_failed_phase(
    client: &mut Client,
    script: &MigrationScriptV1,
    version: i32,
    digest: &str,
) -> Result<(), PgError> {
    let mut tx = client.transaction().map_err(|error| {
        PgError::Migration(format!("cannot begin failure-record transaction: {error}"))
    })?;

    tx.execute(
        "INSERT INTO migration_head
             (singleton, version, name, script_digest, phase, actor, tool_version, started_at)
         VALUES ($1, $2, $3, $4, 'failed', $5, $6, now())
         ON CONFLICT (singleton) DO UPDATE SET
             version = EXCLUDED.version,
             name = EXCLUDED.name,
             script_digest = EXCLUDED.script_digest,
             phase = 'failed',
             actor = EXCLUDED.actor,
             tool_version = EXCLUDED.tool_version,
             started_at = now(),
             verified_at = NULL",
        &[
            &MigrationLedger::SINGLETON_HEAD_ROW,
            &version,
            &script.name,
            &digest,
            &MIGRATOR_ACTOR,
            &MIGRATOR_TOOL_VERSION,
        ],
    )
    .map_err(|error| PgError::Migration(format!("cannot record failed phase: {error}")))?;

    tx.commit()
        .map_err(|error| PgError::Migration(format!("cannot commit failed phase: {error}")))
}

/// Verifies that the committed head matches an exact expected script.
///
/// # Errors
///
/// Returns [`PgError::Migration`] when the head is absent, or its version,
/// digest, or phase disagrees with `expected`.
pub fn verify_head(client: &mut Client, expected: &MigrationScriptV1) -> Result<(), PgError> {
    let head = read_head(client)?.ok_or_else(|| {
        PgError::Migration("migration head is absent; no migration has been applied".to_owned())
    })?;

    if head.head_version != expected.version {
        return Err(PgError::Migration(format!(
            "migration head version {} does not match expected version {}",
            head.head_version, expected.version,
        )));
    }
    if head.head_digest != expected.digest {
        return head.refuse_on(MigrationRefusal::ChecksumMismatch);
    }
    if head.phase != MigrationPhase::Verified {
        return head.refuse_on(MigrationRefusal::DirtyPhase);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Additive v2 session-boundary migration (declared for `proof-server`).
// ---------------------------------------------------------------------------

/// The additive session-boundary migration version (contract §"Migration and
/// projection rebuild").
///
/// The P-0010 base schema (see [`crate::schema::ALL_TABLE_DDL`]) is migration
/// version 1. The `proof-server` crate owns this minimal additive migration
/// constant and version bump: it advances the immutable ledger to version 2
/// with the session, authentication-event, CSRF-digest, and
/// revocation-tombstone tables its HTTP/OIDC boundary requires. The integrator
/// drives it through
/// [`run_expand_backfill_verify_cutover`]; this crate only declares it.
pub const SESSION_BOUNDARY_MIGRATION_VERSION: u32 = 2;

/// Stable migration name for the additive v2 session boundary.
pub const SESSION_BOUNDARY_MIGRATION_NAME: &str = "session-authentication-csrf-tombstone";

/// Exact additive v2 DDL: opaque server-side sessions (keyed-hash only),
/// remote authentication events, session-bound CSRF digests, and bounded
/// revocation tombstones (contract §"OIDC binding and session boundary").
///
/// All four tables are ordinary LOGGED storage; none is `UNLOGGED`. The
/// session table stores only a keyed hash of the opaque 256-bit identifier,
/// never the identifier itself.
pub const SESSION_BOUNDARY_V2_DDL: &str = r"CREATE TABLE proof_sessions (
    session_id_hash TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL,
    requesting_binding_id TEXT NOT NULL,
    authentication_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE proof_authentication_events (
    authentication_event_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    authentication_method TEXT NOT NULL,
    oidc_issuer_configuration_digest TEXT NOT NULL,
    requesting_subject_commitment TEXT NOT NULL,
    requesting_binding_id TEXT NOT NULL,
    requesting_binding_record_digest TEXT NOT NULL,
    requesting_principal_id TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE proof_csrf_synchronizers (
    session_id_hash TEXT NOT NULL REFERENCES proof_sessions(session_id_hash),
    csrf_digest TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (session_id_hash, csrf_digest)
);

CREATE TABLE proof_session_revocations (
    session_id_hash TEXT PRIMARY KEY,
    csrf_digest TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL
);";

/// Constructs the additive v2 session-boundary migration script.
///
/// This binds [`SESSION_BOUNDARY_MIGRATION_VERSION`],
/// [`SESSION_BOUNDARY_MIGRATION_NAME`], and [`SESSION_BOUNDARY_V2_DDL`] into
/// an immutable, checksummed [`MigrationScriptV1`] whose exact-bytes digest is
/// domain-separated under
/// [`MIGRATION_SCRIPT_DIGEST_CONTEXT`](crate::migration::MIGRATION_SCRIPT_DIGEST_CONTEXT).
#[must_use]
pub fn session_boundary_migration_v2() -> MigrationScriptV1 {
    MigrationScriptV1::new(
        SESSION_BOUNDARY_MIGRATION_VERSION,
        SESSION_BOUNDARY_MIGRATION_NAME,
        SESSION_BOUNDARY_V2_DDL,
    )
}

// ---------------------------------------------------------------------------
// Additive v3 delivery-state migration (declared for `proof-delivery`).
// ---------------------------------------------------------------------------

/// The additive delivery-state migration version (contract §"Migration and
/// projection rebuild", §"Transactional outbox and delivery").
///
/// The P-0010 base schema (see [`crate::schema::ALL_TABLE_DDL`]) is migration
/// version 1 and the `proof-server` session boundary is version 2. The
/// `proof-delivery` crate owns this minimal additive migration constant and
/// version bump: it advances the immutable ledger to version 3 with the
/// mutable per-generation delivery state, append-only delivery attempts, and
/// immutable delivery-management facts its worker and preview boundary
/// require. The integrator drives it through
/// [`run_expand_backfill_verify_cutover`]; this crate only declares it.
pub const DELIVERY_STATE_MIGRATION_VERSION: u32 = 3;

/// Stable migration name for the additive v3 delivery state.
pub const DELIVERY_STATE_MIGRATION_NAME: &str = "delivery-state-attempts-management-facts";

/// Exact additive v3 DDL: mutable per-generation delivery state, append-only
/// delivery attempts, and immutable delivery-management facts (contract
/// §"Transactional outbox and delivery", §"Preview delivery").
///
/// All three tables are ordinary LOGGED storage; none is `UNLOGGED`. The
/// delivery state stores only a hash of the random lease token, never the raw
/// token. The mutable alias and the preview filesystem live in the
/// `proof-delivery` crate, not in this migration.
pub const DELIVERY_STATE_V3_DDL: &str = r"CREATE TABLE delivery_state (
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (status IN ('pending', 'in-flight', 'delivered', 'dead-letter', 'abandoned')),
    next_attempt_at TIMESTAMPTZ,
    attempts_in_generation BIGINT NOT NULL DEFAULT 0 CHECK (attempts_in_generation >= 0),
    lease_token_hash TEXT,
    lease_expires_at TIMESTAMPTZ,
    receipt_digest TEXT,
    generation_started_at TIMESTAMPTZ NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (event_id, delivery_id, generation)
);

CREATE TABLE delivery_attempts (
    attempt_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    attempt_number BIGINT NOT NULL CHECK (attempt_number > 0),
    lease_token_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL,
    terminal_at TIMESTAMPTZ,
    UNIQUE (event_id, delivery_id, generation, attempt_number)
);

CREATE TABLE delivery_management_facts (
    fact_id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    action TEXT NOT NULL CHECK (action IN ('replay', 'abandon')),
    fact_digest TEXT NOT NULL UNIQUE,
    payload BYTEA NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);";

/// Constructs the additive v3 delivery-state migration script.
///
/// This binds [`DELIVERY_STATE_MIGRATION_VERSION`],
/// [`DELIVERY_STATE_MIGRATION_NAME`], and [`DELIVERY_STATE_V3_DDL`] into an
/// immutable, checksummed [`MigrationScriptV1`] whose exact-bytes digest is
/// domain-separated under
/// [`MIGRATION_SCRIPT_DIGEST_CONTEXT`](crate::migration::MIGRATION_SCRIPT_DIGEST_CONTEXT).
#[must_use]
pub fn delivery_state_migration_v3() -> MigrationScriptV1 {
    MigrationScriptV1::new(
        DELIVERY_STATE_MIGRATION_VERSION,
        DELIVERY_STATE_MIGRATION_NAME,
        DELIVERY_STATE_V3_DDL,
    )
}

/// The additive migration that keys idempotency lookup by the exact
/// application-provided UUIDv7 key.
pub const APPLICATION_IDEMPOTENCY_MIGRATION_VERSION: u32 = 4;

/// Stable migration name for application-key idempotency.
pub const APPLICATION_IDEMPOTENCY_MIGRATION_NAME: &str = "application-key-idempotency";

/// Adds the nullable key used only by keyed operations and its scoped
/// uniqueness boundary. PostgreSQL permits multiple `NULL` values, so no-key
/// operations remain outside stored-result lookup.
pub const APPLICATION_IDEMPOTENCY_V4_DDL: &str = r"ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS application_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idempotency_application_key_unique
    ON idempotency_keys (
        workspace_id,
        operation,
        operation_version,
        requesting_principal,
        operating_principal,
        application_key
    );";

/// Constructs the additive v4 application-key idempotency migration.
#[must_use]
pub fn application_idempotency_migration_v4() -> MigrationScriptV1 {
    MigrationScriptV1::new(
        APPLICATION_IDEMPOTENCY_MIGRATION_VERSION,
        APPLICATION_IDEMPOTENCY_MIGRATION_NAME,
        APPLICATION_IDEMPOTENCY_V4_DDL,
    )
}

/// The cutover that makes an application key immutable across the complete
/// Workspace rather than within one operation/actor tuple.
pub const WORKSPACE_GLOBAL_IDEMPOTENCY_MIGRATION_VERSION: u32 = 5;

/// Stable migration name for Workspace-global application keys.
pub const WORKSPACE_GLOBAL_IDEMPOTENCY_MIGRATION_NAME: &str =
    "workspace-global-application-idempotency";

/// Adds retained result bytes and cuts identity over to
/// `(workspace_id, application_key)`. Pre-v4 rows had no application key, so
/// the backfill assigns a reserved, unreachable `legacy:` key while retaining
/// their immutable semantic tuple and digest.
pub const WORKSPACE_GLOBAL_IDEMPOTENCY_V5_DDL: &str = r"ALTER TABLE idempotency_keys
    ADD COLUMN IF NOT EXISTS result_body BYTEA;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM idempotency_keys
        WHERE application_key IS NOT NULL AND result_body IS NULL
    ) THEN
        RAISE EXCEPTION 'Workspace-global idempotency cutover requires retained result bytes for every existing application key';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM idempotency_keys
        WHERE application_key IS NOT NULL
        GROUP BY workspace_id, application_key
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'Workspace-global idempotency cutover found duplicate application keys';
    END IF;
END $$;

UPDATE idempotency_keys
SET application_key = 'legacy:' || operation || ':' || operation_version || ':' ||
    normalized_input_digest || ':' || requesting_principal || ':' || operating_principal || ':' ||
    COALESCE(delegation_id, 'none')
WHERE application_key IS NULL;

ALTER TABLE idempotency_keys
    ADD CONSTRAINT idempotency_result_body_present
    CHECK (result_body IS NOT NULL OR application_key LIKE 'legacy:%');

ALTER TABLE idempotency_keys
    ALTER COLUMN application_key SET NOT NULL;

DROP INDEX IF EXISTS idempotency_application_key_unique;

ALTER TABLE idempotency_keys
    DROP CONSTRAINT IF EXISTS idempotency_keys_pkey;

ALTER TABLE idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (workspace_id, application_key);";

/// Constructs the immutable v5 Workspace-global idempotency migration.
#[must_use]
pub fn workspace_global_idempotency_migration_v5() -> MigrationScriptV1 {
    MigrationScriptV1::new(
        WORKSPACE_GLOBAL_IDEMPOTENCY_MIGRATION_VERSION,
        WORKSPACE_GLOBAL_IDEMPOTENCY_MIGRATION_NAME,
        WORKSPACE_GLOBAL_IDEMPOTENCY_V5_DDL,
    )
}
