//! Dependency wiring: connect, migrate, verify durability, and open the
//! Workspace write lane.

use crate::{PgConfig, PgError, transaction::WorkspaceTransaction};

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
    /// # Errors
    ///
    /// Returns [`PgError::Migration`] on any ledger refusal or failure.
    pub fn migrate(&mut self) -> Result<(), PgError> {
        todo!()
    }

    /// Verifies the durability preconditions
    /// (`synchronous_commit=on`, `fsync=on`, `full_page_writes=on`).
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a precondition is not `on`.
    pub fn verify_durability_preconditions(&mut self) -> Result<(), PgError> {
        todo!()
    }

    /// Begins a serializable Workspace write transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the transaction cannot start.
    pub fn begin_workspace_transaction(&mut self) -> Result<WorkspaceTransaction<'_>, PgError> {
        WorkspaceTransaction::begin(&mut self.client)
    }
}
