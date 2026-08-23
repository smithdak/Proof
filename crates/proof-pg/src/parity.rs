//! Shared storage-backend boundary and the parity runner (contract
//! §"Conformance and falsification plan").
//!
//! NOTE: this [`StorageBackend`] trait is declared here for the P-0010
//! skeleton. Wave 2 relocates it to `proof_remote::oracle` so the shared
//! conformance oracle consumes it directly (P-0010 brief, cross-crate note).

use proof_domain::ContentDigest;
use proof_remote::{AuthenticatedActorContextV2, OracleTraceV1, RemoteSemanticOracle};
use serde_json::Value;

use crate::{PgError, wiring::PgRuntime};

/// The shared oracle boundary between the retained SQLite reference path and
/// the new PostgreSQL path (contract §"Conformance and falsification plan").
pub trait StorageBackend {
    /// Evaluates one shared operation and returns a deterministic trace.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when the operation cannot be evaluated
    /// deterministically.
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, PgError>;
}

/// The retained SQLite reference backend, delegating to [`proof_local`] through
/// [`RemoteSemanticOracle`] (contract §"Conformance and falsification plan").
pub struct SqliteReferenceBackend<'a> {
    workspace: &'a proof_local::LocalWorkspace,
}

impl<'a> SqliteReferenceBackend<'a> {
    /// Binds the reference backend to a local Workspace.
    #[must_use]
    pub const fn new(workspace: &'a proof_local::LocalWorkspace) -> Self {
        Self { workspace }
    }
}

impl StorageBackend for SqliteReferenceBackend<'_> {
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, PgError> {
        RemoteSemanticOracle::new()
            .run(self.workspace, normalized_input, actor_context)
            .map_err(|error| PgError::Integrity(error.to_string()))
    }
}

/// The PostgreSQL backend (skeleton; implemented in wave 2).
pub struct PostgresBackend<'a> {
    runtime: &'a mut PgRuntime,
}

impl<'a> PostgresBackend<'a> {
    /// Binds the PostgreSQL backend to a runtime.
    #[must_use]
    pub fn new(runtime: &'a mut PgRuntime) -> Self {
        Self { runtime }
    }
}

impl StorageBackend for PostgresBackend<'_> {
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, PgError> {
        todo!()
    }
}

/// One parity scenario: a name, its shared operations, and the expected
/// byte-identical trace digests (contract §"Conformance and falsification
/// plan").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParityScenario {
    /// Stable scenario name.
    pub name: String,
    /// Normalized shared-operation inputs, in execution order.
    pub operations: Vec<Value>,
    /// Expected [`OracleTraceV1`] digests in the same order.
    pub expected_trace_digests: Vec<ContentDigest>,
}

/// Runs one scenario against both backends and asserts byte-identical traces
/// (contract §"Conformance and falsification plan").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParityRunner;

impl ParityRunner {
    /// Constructs the runner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Runs the scenario against the SQLite reference backend.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a trace cannot be produced.
    pub fn run_sqlite(
        &self,
        scenario: &ParityScenario,
        backend: &mut SqliteReferenceBackend<'_>,
    ) -> Result<Vec<OracleTraceV1>, PgError> {
        todo!()
    }

    /// Runs the scenario against the PostgreSQL backend.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a trace cannot be produced.
    pub fn run_postgres(
        &self,
        scenario: &ParityScenario,
        backend: &mut PostgresBackend<'_>,
    ) -> Result<Vec<OracleTraceV1>, PgError> {
        todo!()
    }

    /// Asserts that the two backends produced byte-identical traces.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] on any trace mismatch.
    pub fn assert_identical(
        sqlite: &[OracleTraceV1],
        postgres: &[OracleTraceV1],
    ) -> Result<(), PgError> {
        todo!()
    }
}
