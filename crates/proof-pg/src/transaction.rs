//! Serializable Workspace write lane plus the bounded-retry and
//! ambiguous-commit contracts (contract §"PostgreSQL authoritative unit of
//! work", §"Retry and ambiguous commit").

use std::time::Duration;

use postgres::{Client, IsolationLevel};
use proof_domain::ContentDigest;
use proof_remote::AuthorityHeadV1;

use crate::{PgError, idempotency::IdempotencyOutcome};

/// A `SERIALIZABLE READ WRITE` transaction over the single Workspace write
/// lane (contract §"PostgreSQL authoritative unit of work").
pub struct WorkspaceTransaction<'a> {
    transaction: postgres::Transaction<'a>,
}

impl<'a> WorkspaceTransaction<'a> {
    /// Begins a serializable read-write transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the transaction cannot start.
    pub fn begin(client: &'a mut Client) -> Result<Self, PgError> {
        let transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .read_only(false)
            .start()
            .map_err(|error| PgError::Transaction(error.to_string()))?;
        Ok(Self { transaction })
    }

    /// Locks the single durable `workspace_write_head` row with
    /// `SELECT ... FOR UPDATE` and returns its snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when the head row is absent or cannot
    /// be locked.
    pub fn lock_workspace_head(&mut self) -> Result<WorkspaceHeadSnapshot, PgError> {
        todo!()
    }

    /// Commits the transaction; nothing returns before this succeeds
    /// (contract step 12).
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when commit fails, possibly with
    /// unknown outcome.
    pub fn commit(self) -> Result<(), PgError> {
        self.transaction
            .commit()
            .map_err(|error| PgError::Transaction(error.to_string()))
    }

    /// Rolls the entire transaction back (infrastructure-failure path,
    /// contract step 11).
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Transaction`] when rollback reports an error.
    pub fn rollback(self) -> Result<(), PgError> {
        self.transaction
            .rollback()
            .map_err(|error| PgError::Transaction(error.to_string()))
    }
}

/// The locked Workspace head plus row-derived causal sequences (contract
/// §"PostgreSQL authoritative unit of work", steps 2–3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceHeadSnapshot {
    /// Current Workspace transaction sequence.
    pub transaction_sequence: u64,
    /// Current authority sequence.
    pub authority_sequence: u64,
    /// Current content sequence.
    pub content_sequence: u64,
    /// Current Release sequence.
    pub release_sequence: u64,
    /// Exact authority head `{record_digest, sequence}`, when present.
    pub authority_head: Option<AuthorityHeadV1>,
    /// Exact content head digest, when present.
    pub content_head: Option<ContentDigest>,
    /// Exact Release head digest, when present.
    pub release_head: Option<ContentDigest>,
    /// Exact policy head digest, when present.
    pub policy_head: Option<ContentDigest>,
    /// Exact configuration head digest, when present.
    pub configuration_head: Option<ContentDigest>,
}

/// The next transaction/authority/content/Release sequences derived from the
/// locked head row only (contract §"PostgreSQL authoritative unit of work",
/// step 3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocatedSequences {
    /// Next Workspace transaction sequence.
    pub transaction: u64,
    /// Next authority sequence.
    pub authority: u64,
    /// Next content sequence.
    pub content: u64,
    /// Next Release sequence.
    pub release: u64,
}

/// Allocates the next sequences from the locked head row only. PostgreSQL
/// sequences, `SERIAL`, and `BIGSERIAL` are forbidden for causal order because
/// their increments do not roll back (contract §"PostgreSQL authoritative unit
/// of work", step 3).
#[must_use]
pub fn allocate_sequences_from_head(head: &WorkspaceHeadSnapshot) -> AllocatedSequences {
    todo!()
}

/// Bounded full-transaction retry policy (contract §"Retry and ambiguous
/// commit").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Maximum attempts before exhaustion (three).
    pub max_attempts: u32,
    /// Original application deadline (30 seconds).
    pub deadline: Duration,
    /// Bounded jitter added between attempts.
    pub jitter: Duration,
}

impl RetryPolicy {
    /// Contract maximum attempt count.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
    /// Contract 30-second application deadline.
    pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);

    /// Constructs a bounded retry policy.
    #[must_use]
    pub const fn new(max_attempts: u32, deadline: Duration, jitter: Duration) -> Self {
        Self {
            max_attempts,
            deadline,
            jitter,
        }
    }

    /// The contract default: three attempts within 30 seconds with no jitter
    /// (callers may add bounded jitter).
    #[must_use]
    pub const fn default() -> Self {
        Self::new(
            Self::DEFAULT_MAX_ATTEMPTS,
            Self::DEFAULT_DEADLINE,
            Duration::ZERO,
        )
    }
}

/// Retry classification for a PostgreSQL SQLSTATE (contract §"Retry and
/// ambiguous commit").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlStateClass {
    /// `40001` serialization_failure — retry the complete transaction.
    SerializationFailure,
    /// `40P01` deadlock_detected — retry from the beginning only.
    DeadlockDetected,
    /// `23505` unique_violation — retryable only for a named internal
    /// allocation constraint.
    UniqueViolation,
    /// Any other SQLSTATE — not a retryable class.
    Other,
}

/// Classifies one SQLSTATE string into the contract's retry decision.
#[must_use]
pub fn classify_sqlstate(state: &str) -> SqlStateClass {
    match state {
        "40001" => SqlStateClass::SerializationFailure,
        "40P01" => SqlStateClass::DeadlockDetected,
        "23505" => SqlStateClass::UniqueViolation,
        _ => SqlStateClass::Other,
    }
}

/// The unknown-outcome descriptor for a connection loss during commit
/// (contract §"Retry and ambiguous commit").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownOutcome {
    /// Retryable HTTP status (`504`).
    pub http_status: u16,
    /// Stable problem code.
    pub problem_code: &'static str,
    /// Always retryable.
    pub retryable: bool,
}

impl UnknownOutcome {
    /// HTTP 504 Gateway Timeout status.
    pub const HTTP_STATUS: u16 = 504;
    /// Stable retryable problem code for an unknown commit outcome.
    pub const PROBLEM_CODE: &'static str = "proof.operation.unknown_outcome";

    /// The contract unknown-outcome descriptor.
    #[must_use]
    pub const fn contract() -> Self {
        Self {
            http_status: Self::HTTP_STATUS,
            problem_code: Self::PROBLEM_CODE,
            retryable: true,
        }
    }
}

/// An ambiguous commit with unknown outcome (contract §"Retry and ambiguous
/// commit").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AmbiguousCommit {
    /// The `504 proof.operation.unknown_outcome` descriptor.
    pub unknown_outcome: UnknownOutcome,
}

impl AmbiguousCommit {
    /// Constructs the contract ambiguous-commit descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            unknown_outcome: UnknownOutcome::contract(),
        }
    }
}

impl Default for AmbiguousCommit {
    fn default() -> Self {
        Self::new()
    }
}

/// The closed outcome of one twelve-step unit of work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnitOfWorkOutcome {
    /// Committed a fresh governed consequence.
    Committed,
    /// Committed a replay that disclosed a prior result.
    Replayed,
    /// Committed an idempotency-conflict consequence without a governed
    /// effect.
    ConflictCommitted,
    /// Committed an authorized application failure (savepoint rule, step 10).
    ApplicationFailureCommitted,
}

/// Step 5 hook: evaluates current authorization at the locked head.
pub type AuthorizationHook<'a> = Box<dyn FnMut(&WorkspaceHeadSnapshot) -> Result<(), PgError> + 'a>;
/// Step 6 hook: keyed replay/conflict evaluation returning the
/// [`IdempotencyOutcome`].
pub type ReplayOrConflictHook<'a> =
    Box<dyn FnMut(&WorkspaceHeadSnapshot) -> Result<IdempotencyOutcome, PgError> + 'a>;
/// Step 9 hook: the governed application consequence, bounded by a savepoint.
pub type ConsequenceHook<'a> =
    Box<dyn FnMut(&mut postgres::Transaction<'_>) -> Result<(), PgError> + 'a>;

/// Hook closures injected into [`run_unit_of_work`] (contract §"PostgreSQL
/// authoritative unit of work").
pub struct UnitOfWorkHooks<'a> {
    /// Step 4: verify authentication before idempotency lookup or prior-result
    /// disclosure.
    pub verify_authentication: Box<dyn FnMut() -> Result<(), PgError> + 'a>,
    /// Step 5: evaluate current authorization at the locked head.
    pub evaluate_authorization: AuthorizationHook<'a>,
    /// Step 6: keyed replay/conflict evaluation, returning the
    /// [`IdempotencyOutcome`].
    pub replay_or_conflict: ReplayOrConflictHook<'a>,
    /// Step 9: the governed application consequence, bounded by a savepoint.
    pub apply_consequence: ConsequenceHook<'a>,
}

/// Runs the exact twelve-step authoritative unit of work with injected hooks
/// (contract §"PostgreSQL authoritative unit of work"):
///
/// 1. select the deployment Workspace and verify the compatible migration
///    version;
/// 2. lock the Workspace write head and read the exact heads;
/// 3. derive the next transaction/authority/content/Release sequences from the
///    locked row;
/// 4. verify authentication before idempotency lookup or disclosure;
/// 5. evaluate current authorization at the locked head;
/// 6. keyed replay/conflict or fresh attempt via [`IdempotencyOutcome`];
/// 7. compare base state, approval, configuration, and concurrency
///    preconditions;
/// 8. establish a savepoint around the governed consequence;
/// 9. on success persist every governed record and the new heads;
/// 10. on an authorized application failure roll back to the savepoint and
///     commit only presentation consumption, decision, and failure-consequence
///     bodies;
/// 11. on infrastructure failure roll back the entire transaction;
/// 12. return nothing until commit success.
///
/// # Errors
///
/// Returns [`PgError::Transaction`] on infrastructure, signing, artifact,
/// storage, or integrity failure (step 11).
pub fn run_unit_of_work(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
) -> Result<UnitOfWorkOutcome, PgError> {
    todo!()
}

/// Runs one unit of work under the bounded retry policy (contract §"Retry and
/// ambiguous commit").
///
/// # Errors
///
/// Returns [`PgError::Transaction`] when the retry budget or deadline is
/// exhausted, or the commit outcome is unknown.
pub fn run_unit_of_work_with_retry(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    policy: RetryPolicy,
) -> Result<UnitOfWorkOutcome, PgError> {
    todo!()
}
