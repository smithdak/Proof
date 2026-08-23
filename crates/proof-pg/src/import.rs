//! Verified SQLite-to-PostgreSQL import (contract §"Migration and projection
//! rebuild").

use serde::{Deserialize, Serialize};

use crate::{PgError, wiring::PgRuntime};

/// Consumes verified canonical facts via the [`proof_local`] read API,
/// reconstructs chains, rebuilds projections, compares authority heads and
/// Known State, and cuts over atomically (contract §"Migration and projection
/// rebuild").
///
/// Copying unverified SQLite rows is never sufficient.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SqliteToPostgresImporter;

impl SqliteToPostgresImporter {
    /// Constructs the importer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Imports the source Workspace into the target PostgreSQL runtime.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Import`] when chain reconstruction, projection
    /// rebuild, or head/Known-State comparison fails.
    pub fn import(
        &self,
        source: &proof_local::LocalWorkspace,
        target: &mut PgRuntime,
    ) -> Result<ImportReport, PgError> {
        todo!()
    }
}

/// The closed import result (contract §"Migration and projection rebuild").
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImportReport {
    /// Verified canonical facts consumed from the SQLite source.
    pub facts_consumed: u64,
    /// Causal chains reconstructed from those facts.
    pub chains_reconstructed: u64,
    /// Projection generations rebuilt.
    pub projections_rebuilt: u64,
    /// Whether the reconstructed authority head matches the source.
    pub authority_heads_match: bool,
    /// Whether the reconstructed Known State digest matches the source.
    pub known_state_matches: bool,
    /// Whether the network-facing cutover was atomic.
    pub cutover_atomic: bool,
}
