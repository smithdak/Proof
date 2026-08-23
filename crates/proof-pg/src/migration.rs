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

impl MigrationLedger {
    /// Fixed PostgreSQL advisory-lock key that admits exactly one migrator
    /// across transactional and nontransactional phases.
    pub const ADVISORY_LOCK_KEY: i64 = 0x5072_6F6F_6650_4731;
    /// The single durable head row key.
    pub const SINGLETON_HEAD_ROW: i32 = 1;

    /// Verifies the singleton head row is present and coherent.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Migration`] when the ledger cannot be read or is not
    /// a valid singleton.
    pub fn verify_head(&self) -> Result<(), PgError> {
        todo!()
    }

    /// Fails closed on the supplied refusal reason.
    ///
    /// # Errors
    ///
    /// Always returns [`PgError::Migration`] describing `reason`.
    pub fn refuse_on(&self, reason: MigrationRefusal) -> Result<(), PgError> {
        todo!()
    }
}

/// Runs the expand/backfill/verify/cutover migration contract for one script.
///
/// # Errors
///
/// Returns [`PgError::Migration`] on checksum mismatch, dirty phase, unknown
/// newer version, or a write outside the compatibility interval.
pub fn run_expand_backfill_verify_cutover(
    client: &mut Client,
    script: &MigrationScriptV1,
) -> Result<(), PgError> {
    todo!()
}

/// Verifies that the committed head matches an exact expected script.
///
/// # Errors
///
/// Returns [`PgError::Migration`] when the head version or digest disagrees
/// with `expected`.
pub fn verify_head(client: &mut Client, expected: &MigrationScriptV1) -> Result<(), PgError> {
    todo!()
}
