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

/// One successful keyed result retained under a Workspace-global application
/// key. The semantic tuple is compared only after current authentication and
/// authorization; `result_body` is the exact canonical JSON returned on replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredIdempotencyV1 {
    /// Semantic tuple committed by the successful application.
    pub tuple: IdempotencyTupleV1,
    /// Digest of the exact typed result.
    pub result_digest: ContentDigest,
    /// Canonical typed-result bytes, absent only on a pre-v5 legacy row.
    pub result_body: Option<Vec<u8>>,
}

/// Reads one Workspace-global application key inside the locked transaction.
///
/// # Errors
///
/// Returns [`PgError::Idempotency`] for a database lookup failure and
/// [`PgError::Integrity`] for malformed retained identities or digests.
pub fn read_stored_in_transaction(
    transaction: &mut Transaction<'_>,
    workspace_id: WorkspaceId,
    application_key: &str,
) -> Result<Option<StoredIdempotencyV1>, PgError> {
    let row = transaction
        .query_opt(
            "SELECT operation, operation_version, normalized_input_digest,
                    requesting_principal, operating_principal, delegation_id,
                    result_digest, result_body
             FROM idempotency_keys
             WHERE workspace_id = $1 AND application_key = $2",
            &[&workspace_id.to_string(), &application_key],
        )
        .map_err(|error| crate::transaction::transaction_error(&error))?;
    let Some(row) = row else {
        return Ok(None);
    };

    let operation = RemoteOperationV1 {
        name: row.get(0),
        version: row.get(1),
    };
    let normalized_input_digest: String = row.get(2);
    let requesting_principal: String = row.get(3);
    let operating_principal: String = row.get(4);
    let delegation: Option<String> = row.get(5);
    let result_digest: String = row.get(6);

    Ok(Some(StoredIdempotencyV1 {
        tuple: IdempotencyTupleV1 {
            workspace_id,
            operation,
            normalized_input_digest: normalized_input_digest.parse().map_err(|error| {
                PgError::Integrity(format!("invalid stored input digest: {error}"))
            })?,
            requesting_principal: requesting_principal.parse().map_err(|_| {
                PgError::Integrity("invalid stored requesting Principal".to_owned())
            })?,
            operating_principal: operating_principal
                .parse()
                .map_err(|_| PgError::Integrity("invalid stored operating Principal".to_owned()))?,
            delegation: delegation
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|_| PgError::Integrity("invalid stored Delegation identity".to_owned()))?,
        },
        result_digest: result_digest.parse().map_err(|error| {
            PgError::Integrity(format!("invalid stored result digest: {error}"))
        })?,
        result_body: row.get(7),
    }))
}

/// Persists one successful application key and exact typed result inside the
/// governed-success savepoint.
///
/// # Errors
///
/// Returns a transaction error when the immutable global key cannot be stored.
#[allow(clippy::too_many_arguments)]
pub fn persist_success_in_transaction(
    transaction: &mut Transaction<'_>,
    candidate: &IdempotencyTupleV1,
    application_key: &str,
    key_kind: &str,
    result_digest: ContentDigest,
    result_body: &[u8],
) -> Result<(), PgError> {
    transaction
        .execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, application_key,
                 key_kind, result_digest, result_body, replay_count, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0, now())",
            &[
                &candidate.workspace_id.to_string(),
                &candidate.operation.name,
                &candidate.operation.version,
                &candidate.normalized_input_digest.to_string(),
                &candidate.requesting_principal.to_string(),
                &candidate.operating_principal.to_string(),
                &candidate.delegation.map(|value| value.to_string()),
                &application_key,
                &key_kind,
                &result_digest.to_string(),
                &result_body,
            ],
        )
        .map_err(|error| crate::transaction::transaction_error(&error))?;
    Ok(())
}

/// Increments the diagnostic replay count without changing the retained tuple
/// or result.
///
/// # Errors
///
/// Returns a transaction error if the retained row cannot be updated.
pub fn record_replay_in_transaction(
    transaction: &mut Transaction<'_>,
    workspace_id: WorkspaceId,
    application_key: &str,
) -> Result<(), PgError> {
    let updated = transaction
        .execute(
            "UPDATE idempotency_keys
             SET replay_count = replay_count + 1
             WHERE workspace_id = $1 AND application_key = $2",
            &[&workspace_id.to_string(), &application_key],
        )
        .map_err(|error| crate::transaction::transaction_error(&error))?;
    if updated == 1 {
        Ok(())
    } else {
        Err(PgError::Integrity(
            "idempotency replay row disappeared while locked".to_owned(),
        ))
    }
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
///
/// The "key" is the exact semantic tuple (Workspace, operation/version,
/// normalized-input digest, requesting and operating Principals, and
/// Delegation). A missing prior tuple means there is no stored result (a
/// no-key row skips the lookup entirely and lands here with `prior == None`),
/// so the attempt is fresh. A present prior tuple that equals the candidate
/// is the same key plus equivalent input and replays the prior result; a
/// present prior tuple that differs is the same key plus changed input and is
/// an idempotency conflict. Presentation identity, signature, time, and
/// binding instance are not members of the tuple and therefore never
/// participate in the comparison (contract §"PostgreSQL authoritative unit of
/// work", step 6).
#[must_use]
pub fn replay_or_conflict(
    candidate: &IdempotencyTupleV1,
    prior: Option<&IdempotencyTupleV1>,
) -> IdempotencyOutcome {
    match prior {
        None => IdempotencyOutcome::Fresh,
        Some(stored) if stored == candidate => IdempotencyOutcome::Replayed,
        Some(_) => IdempotencyOutcome::Conflict,
    }
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
            .map_err(|error| crate::transaction::transaction_error(&error))?;
        Ok(Self { savepoint })
    }

    /// Returns the savepoint transaction for in-savepoint execution.
    ///
    /// Writes made through the returned transaction land after the savepoint
    /// marker and are undone by [`Self::rollback`] or made permanent by
    /// [`Self::release`].
    #[must_use]
    pub fn transaction(&mut self) -> &mut postgres::Transaction<'tx> {
        &mut self.savepoint
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
            .map_err(|error| crate::transaction::transaction_error(&error))
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
            .map_err(|error| crate::transaction::transaction_error(&error))
    }
}
