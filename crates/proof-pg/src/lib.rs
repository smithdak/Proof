#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_variables,
    unused_imports,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::unused_self
)]

//! PostgreSQL parity foundation for Proof.
//!
//! This crate is the compiling skeleton for the second dependency-ordered
//! successor of the accepted [single-Workspace collaboration-server contract].
//! It declares the complete public type and function surface of the durable
//! PostgreSQL adapter — the immutable checksummed migration ledger, the
//! serializable Workspace write lane with the twelve-step unit of work, keyed
//! idempotency and the savepoint rule, the immutable artifact catalog and
//! durability boundary, transactional outbox enqueue, projection rebuild, the
//! verified SQLite-to-PostgreSQL import, and the shared storage-backend
//! boundary — with `todo!()` bodies for later parallel implementation. The
//! retained SQLite reference semantics live in [`proof_local`]; the shared
//! conformance oracle lives in [`proof_remote`].
//!
//! The synchronous [rust-postgres] driver is the selected baseline: blocking
//! semantics match the single-writer contract and no async runtime is
//! introduced by this crate.
//!
//! [single-Workspace collaboration-server contract]: https://proof.dev/docs/architecture/collaboration-server
//! [rust-postgres]: https://crates.io/crates/postgres
//! [`proof_local`]: ../proof_local/index.html
//! [`proof_remote`]: ../proof_remote/index.html

pub mod artifacts;
pub mod idempotency;
pub mod import;
pub mod migration;
pub mod outbox;
pub mod parity;
pub mod projection;
pub mod schema;
pub mod transaction;
pub mod wiring;

use std::time::Duration;

use proof_domain::WorkspaceId;
use thiserror::Error;

/// Re-exported PostgreSQL type traits so the crate's data-type surface stays
/// explicit. These are the same traits [`postgres::types`] re-exports.
pub use postgres_types;

/// The `PROOF_PG_DSN` environment variable used to override the default
/// development connection string (contract §"PostgreSQL authoritative unit of
/// work").
pub const DSN_ENV: &str = "PROOF_PG_DSN";

/// Default connection string for the local development instance
/// (`scripts/dev-pg.sh`) and the Linux CI gate (contract §"PostgreSQL
/// authoritative unit of work").
pub const DEFAULT_DSN: &str = "postgres://postgres@127.0.0.1:55432/prooftest";

/// Closed error taxonomy for the PostgreSQL parity foundation (contract
/// §"PostgreSQL authoritative unit of work", §"Retry and ambiguous commit").
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PgError {
    /// Connection or configuration of the PostgreSQL authority store failed.
    #[error("PostgreSQL connection failed: {0}")]
    Connect(String),
    /// The immutable migration ledger refused or failed a migration.
    #[error("migration failed: {0}")]
    Migration(String),
    /// A serializable Workspace transaction failed or exhausted retries.
    #[error("transaction failed: {0}")]
    Transaction(String),
    /// Keyed idempotency replay/conflict evaluation failed.
    #[error("idempotency failed: {0}")]
    Idempotency(String),
    /// The immutable artifact boundary failed a put/read/verify step.
    #[error("artifact failed: {0}")]
    Artifact(String),
    /// Transactional outbox enqueue failed.
    #[error("outbox failed: {0}")]
    Outbox(String),
    /// Projection rebuild or generation swap failed.
    #[error("projection failed: {0}")]
    Projection(String),
    /// SQLite-to-PostgreSQL import failed.
    #[error("import failed: {0}")]
    Import(String),
    /// A durability, digest, or invariant check failed closed.
    #[error("integrity failed: {0}")]
    Integrity(String),
}

/// Deployment-scoped configuration for one PostgreSQL-backed Workspace
/// (contract §"PostgreSQL authoritative unit of work").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PgConfig {
    /// Exact connection string for the authority store. Resolved from
    /// [`DSN_ENV`] or [`DEFAULT_DSN`].
    pub dsn: String,
    /// The single Workspace identity fixed by deployment configuration; a
    /// request-selected Workspace is never accepted.
    pub workspace_id: WorkspaceId,
    /// Duration of the migration compatibility interval.
    pub compatibility_interval: Duration,
}

impl PgConfig {
    /// Constructs a fixed single-Workspace configuration.
    #[must_use]
    pub fn new(
        dsn: impl Into<String>,
        workspace_id: WorkspaceId,
        compatibility_interval: Duration,
    ) -> Self {
        Self {
            dsn: dsn.into(),
            workspace_id,
            compatibility_interval,
        }
    }

    /// Resolves the DSN from [`DSN_ENV`], falling back to [`DEFAULT_DSN`].
    #[must_use]
    pub fn from_env(workspace_id: WorkspaceId, compatibility_interval: Duration) -> Self {
        let dsn = std::env::var(DSN_ENV).unwrap_or_else(|_| DEFAULT_DSN.to_owned());
        Self::new(dsn, workspace_id, compatibility_interval)
    }
}
