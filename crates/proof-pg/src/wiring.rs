//! Dependency wiring: connect, migrate, verify durability, and open the
//! Workspace write lane.

use crate::{
    PgConfig, PgError,
    schema::{
        ALL_TABLE_DDL, FSYNC_REQUIRED, FULL_PAGE_WRITES_REQUIRED, SYNCHRONOUS_COMMIT_REQUIRED,
    },
    transaction::WorkspaceTransaction,
};

/// The wired PostgreSQL runtime: one configured synchronous client plus the
/// fixed single-Workspace identity.
pub struct PgRuntime {
    config: PgConfig,
    client: postgres::Client,
}

impl PgRuntime {
    /// Connects to the authority store with no TLS.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Connect`] when the client cannot connect.
    pub fn connect(config: PgConfig) -> Result<Self, PgError> {
        let client = postgres::Client::connect(&config.dsn, postgres::NoTls)
            .map_err(|error| PgError::Connect(error.to_string()))?;
        Ok(Self { config, client })
    }

    /// Returns the fixed single-Workspace configuration.
    #[must_use]
    pub const fn config(&self) -> &PgConfig {
        &self.config
    }

    /// Returns the underlying synchronous client.
    #[must_use]
    pub const fn client(&self) -> &postgres::Client {
        &self.client
    }

    /// Returns the underlying synchronous client mutably.
    #[must_use]
    pub const fn client_mut(&mut self) -> &mut postgres::Client {
        &mut self.client
    }

    /// Runs the immutable migration ledger to the required head.
    ///
    /// This first verifies the durability preconditions, then bootstraps the
    /// base logged schema when it is absent. The crate itself declares no
    /// additional migration scripts beyond that bootstrap schema, so a caller
    /// with deployment-specific scripts drives them through
    /// [`crate::migration::run_expand_backfill_verify_cutover`] afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Migration`] on any ledger refusal or failure, or
    /// [`PgError::Integrity`] when a durability precondition is not met.
    pub fn migrate(&mut self) -> Result<(), PgError> {
        self.verify_durability_preconditions()?;

        let has_schema: Option<String> = self
            .client
            .query_opt("SELECT to_regclass('migration_head')::text", &[])
            .map_err(|error| PgError::Migration(error.to_string()))?
            .and_then(|row| row.get(0));

        if has_schema.is_none() {
            let ddl = ALL_TABLE_DDL.join("\n");
            self.client
                .batch_execute(&ddl)
                .map_err(|error| PgError::Migration(error.to_string()))?;
        }
        Ok(())
    }

    /// Verifies the durability preconditions
    /// (`synchronous_commit=on`, `fsync=on`, `full_page_writes=on`).
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a precondition is not `on`.
    pub fn verify_durability_preconditions(&mut self) -> Result<(), PgError> {
        for (setting, required) in [
            ("synchronous_commit", SYNCHRONOUS_COMMIT_REQUIRED),
            ("fsync", FSYNC_REQUIRED),
            ("full_page_writes", FULL_PAGE_WRITES_REQUIRED),
        ] {
            let row = self
                .client
                .query_one(&format!("SHOW {setting}"), &[])
                .map_err(|error| PgError::Integrity(error.to_string()))?;
            let value: String = row.get(0);
            if value != required {
                return Err(PgError::Integrity(format!(
                    "durability precondition {setting} is {value:?}, required {required:?}"
                )));
            }
        }
        Ok(())
    }

    /// Begins a serializable Workspace write transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the transaction cannot start.
    pub fn begin_workspace_transaction(&mut self) -> Result<WorkspaceTransaction<'_>, PgError> {
        WorkspaceTransaction::begin(&mut self.client)
    }

    /// Applies the additive v3 delivery-state migration on top of the
    /// bootstrapped base schema (contract §"Migration and projection rebuild",
    /// §"Transactional outbox and delivery").
    ///
    /// This first runs [`Self::migrate`] (idempotent), then advances the
    /// immutable ledger with [`crate::migration::delivery_state_migration_v3`].
    /// A deployment that also owns the P-0011 session boundary must have
    /// already applied
    /// [`crate::migration::session_boundary_migration_v2`]; the monotonic ledger
    /// accepts the v3 advance from either a fresh head or a head already at
    /// version 2.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Migration`] on any ledger refusal or failure, or
    /// [`PgError::Integrity`] when a durability precondition is not met.
    pub fn migrate_delivery_state(&mut self) -> Result<(), PgError> {
        self.migrate()?;
        crate::migration::run_expand_backfill_verify_cutover(
            self.client_mut(),
            &crate::migration::delivery_state_migration_v3(),
        )
    }
}
