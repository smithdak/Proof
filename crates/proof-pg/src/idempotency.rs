//! Keyed idempotency and the savepoint rule (contract §"PostgreSQL
//! authoritative unit of work", steps 6, 8, 10, and 11).

use postgres::Transaction;
use proof_domain::{ContentDigest, DelegationId, PrincipalId, WorkspaceId};
use proof_remote::RemoteOperationV1;
use serde::{Deserialize, Serialize};

use crate::PgError;

/// The complete keyed idempotency tuple compared at step 6 (contract
/// §"PostgreSQL authoritative unit of work").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyTupleV1 {
    /// The fixed Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Exact operation name/version.
    pub operation: RemoteOperationV1,
    /// Protected exact normalized-input digest.
    pub normalized_input_digest: ContentDigest,
    /// The requesting Principal, derived from the Human session.
    pub requesting_principal: PrincipalId,
    /// The operating Principal, derived from the Agent presentation.
    pub operating_principal: PrincipalId,
    /// The Delegation granting authority, when present.
    pub delegation: Option<DelegationId>,
}

/// Key kinds that select stored-result lookup behavior (contract §"PostgreSQL
/// authoritative unit of work", step 6).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyKeyKind {
    /// Required UUIDv7 application key.
    RequiredUuidV7,
    /// Derived key (the `derived-*` family over normalized input or
    /// correlation).
    Derived,
    /// No key: skip stored-result lookup and execute as a fresh attempt.
    None,
}

/// The idempotency decision selected before the governed consequence (contract
/// §"PostgreSQL authoritative unit of work", step 6).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyOutcome {
    /// Same key plus equivalent input: disclose the prior committed result
    /// without duplicating the governed fact, key, or outbox event.
    Replayed,
    /// Same key plus changed input: commit a signed idempotency-conflict
    /// consequence without a governed effect.
    Conflict,
    /// No key or fresh attempt: execute the governed consequence.
    Fresh,
}

/// Compares a candidate tuple against a prior stored tuple and returns the
/// replay/conflict/fresh decision.
#[must_use]
pub fn replay_or_conflict(
    candidate: &IdempotencyTupleV1,
    prior: Option<&IdempotencyTupleV1>,
) -> IdempotencyOutcome {
    todo!()
}

/// A savepoint bounding the governed application consequence (contract
/// §"PostgreSQL authoritative unit of work", steps 8–11).
pub struct SavepointGuard<'tx> {
    savepoint: postgres::Transaction<'tx>,
}

impl<'tx> SavepointGuard<'tx> {
    /// The fixed savepoint name for the governed consequence.
    pub const SAVEPOINT_NAME: &'static str = "proof_governed_consequence";

    /// Establishes the savepoint around the governed consequence.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the savepoint cannot be created.
    pub fn establish(transaction: &'tx mut Transaction) -> Result<Self, PgError> {
        let savepoint = transaction
            .savepoint(Self::SAVEPOINT_NAME)
            .map_err(|error| PgError::Transaction(error.to_string()))?;
        Ok(Self { savepoint })
    }

    /// Releases (commits) the savepoint — the authorized success path
    /// (step 9).
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the savepoint cannot be released.
    pub fn release(self) -> Result<(), PgError> {
        self.savepoint
            .commit()
            .map_err(|error| PgError::Transaction(error.to_string()))
    }

    /// Rolls back to the savepoint — the authorized application-failure path
    /// (step 10) commits only presentation consumption, decision, and
    /// failure-consequence bodies.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the rollback fails.
    pub fn rollback(self) -> Result<(), PgError> {
        self.savepoint
            .rollback()
            .map_err(|error| PgError::Transaction(error.to_string()))
    }
}
