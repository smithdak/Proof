//! Serializable Workspace write lane plus the bounded-retry and
//! ambiguous-commit contracts (contract §"PostgreSQL authoritative unit of
//! work", §"Retry and ambiguous commit").

use std::{
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

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
            .map_err(|error| transaction_error(&error))?;
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
        lock_head_for_update(&mut self.transaction)
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

/// Selects which causal streams one authoritative transaction advances.
/// Authority-only reads and control evidence must not create gaps in the
/// independently verified content and Release chains.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CausalSequencePolicy {
    /// Advance every causal stream for legacy governed mutations.
    #[default]
    All,
    /// Advance only the Workspace transaction and authority streams.
    AuthorityOnly,
}

/// Allocates the next sequences from the locked head row only. PostgreSQL
/// sequences, `SERIAL`, and `BIGSERIAL` are forbidden for causal order because
/// their increments do not roll back (contract §"PostgreSQL authoritative unit
/// of work", step 3).
#[must_use]
pub fn allocate_sequences_from_head(head: &WorkspaceHeadSnapshot) -> AllocatedSequences {
    allocate_sequences_with_policy(head, CausalSequencePolicy::All)
}

/// Allocates causal sequences according to an explicit operation policy.
#[must_use]
pub fn allocate_sequences_with_policy(
    head: &WorkspaceHeadSnapshot,
    policy: CausalSequencePolicy,
) -> AllocatedSequences {
    AllocatedSequences {
        transaction: head.transaction_sequence + 1,
        authority: head.authority_sequence + 1,
        content: head.content_sequence + u64::from(matches!(policy, CausalSequencePolicy::All)),
        release: head.release_sequence + u64::from(matches!(policy, CausalSequencePolicy::All)),
    }
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

/// Testable observation of whether the caller received acknowledgement after
/// PostgreSQL committed an authoritative attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitAcknowledgement {
    /// The successful commit acknowledgement reached the caller.
    Received,
    /// The commit applied, but its acknowledgement was lost; the outcome must
    /// be reported as unknown and must never be retried internally.
    Lost,
}

/// Step 5 hook: evaluates current authorization at the locked head.
pub type AuthorizationHook<'a> = Box<
    dyn FnMut(&mut postgres::Transaction<'_>, &WorkspaceHeadSnapshot) -> Result<(), PgError> + 'a,
>;
/// Step 6 hook: keyed replay/conflict evaluation returning the
/// [`IdempotencyOutcome`].
pub type ReplayOrConflictHook<'a> = Box<
    dyn FnMut(
            &mut postgres::Transaction<'_>,
            &WorkspaceHeadSnapshot,
        ) -> Result<IdempotencyOutcome, PgError>
        + 'a,
>;
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
    run_unit_of_work_with_sequence_policy(client, hooks, CausalSequencePolicy::All)
}

/// Runs one authoritative unit of work under an explicit causal-stream
/// allocation policy.
///
/// # Errors
///
/// Returns the terminal transaction error or a commit-outcome error from the
/// authoritative attempt.
pub fn run_unit_of_work_with_sequence_policy(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    sequence_policy: CausalSequencePolicy,
) -> Result<UnitOfWorkOutcome, PgError> {
    let mut acknowledgement = |_| CommitAcknowledgement::Received;
    match run_unit_of_work_attempt(client, hooks, sequence_policy, None, &mut acknowledgement) {
        Ok(outcome) => Ok(outcome),
        Err(AttemptFailure::Terminal(error)) => Err(error),
        Err(failure) => Err(failure.into_pg_error()),
    }
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
    run_unit_of_work_with_retry_and_sequence_policy(
        client,
        hooks,
        policy,
        CausalSequencePolicy::All,
    )
}

/// Runs one authoritative unit of work under both an explicit causal-stream
/// policy and the bounded full-transaction retry policy.
///
/// # Errors
///
/// Returns the terminal body error, [`PgError::AmbiguousCommit`] when commit
/// acknowledgement is lost, or [`PgError::Transaction`] when retryable
/// conflicts exhaust the attempt/deadline budget.
pub fn run_unit_of_work_with_retry_and_sequence_policy(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    policy: RetryPolicy,
    sequence_policy: CausalSequencePolicy,
) -> Result<UnitOfWorkOutcome, PgError> {
    let mut acknowledgement = |_| CommitAcknowledgement::Received;
    run_unit_of_work_with_retry_and_sequence_policy_impl(
        client,
        hooks,
        policy,
        sequence_policy,
        &mut acknowledgement,
    )
}

/// Runs the bounded authoritative transaction while exposing a deterministic
/// post-commit acknowledgement seam. This is used to qualify the otherwise
/// nondeterministic case where PostgreSQL commits but the response is lost.
/// Returning [`CommitAcknowledgement::Lost`] reports
/// [`PgError::AmbiguousCommit`] after the real commit and never retries it.
///
/// # Errors
///
/// Returns the same failures as
/// [`run_unit_of_work_with_retry_and_sequence_policy`], plus the injected
/// unknown outcome when `acknowledgement` reports loss.
pub fn run_unit_of_work_with_retry_and_sequence_policy_and_acknowledgement<F>(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    policy: RetryPolicy,
    sequence_policy: CausalSequencePolicy,
    acknowledgement: &mut F,
) -> Result<UnitOfWorkOutcome, PgError>
where
    F: FnMut(UnitOfWorkOutcome) -> CommitAcknowledgement,
{
    run_unit_of_work_with_retry_and_sequence_policy_impl(
        client,
        hooks,
        policy,
        sequence_policy,
        acknowledgement,
    )
}

fn run_unit_of_work_with_retry_and_sequence_policy_impl<F>(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    policy: RetryPolicy,
    sequence_policy: CausalSequencePolicy,
    acknowledgement: &mut F,
) -> Result<UnitOfWorkOutcome, PgError>
where
    F: FnMut(UnitOfWorkOutcome) -> CommitAcknowledgement,
{
    let started = Instant::now();
    let mut last_error = None;

    for attempt in 1..=policy.max_attempts {
        if started.elapsed() >= policy.deadline {
            return Err(PgError::Transaction(
                "retry deadline exhausted: retryable storage conflict".to_owned(),
            ));
        }

        let remaining = policy.deadline.saturating_sub(started.elapsed());
        match run_unit_of_work_attempt(
            client,
            hooks,
            sequence_policy,
            Some(remaining),
            acknowledgement,
        ) {
            Ok(outcome) => return Ok(outcome),
            Err(failure) => {
                let retryable = failure.is_retryable();
                last_error = Some(failure.into_pg_error());
                if attempt < policy.max_attempts && retryable {
                    thread::sleep(policy.jitter);
                    continue;
                }
                return Err(last_error.expect("assigned immediately above"));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| PgError::Transaction("retry budget exhausted".to_owned())))
}

/// Maps a database error to [`PgError::Transaction`], embedding its SQLSTATE
/// when present so [`run_unit_of_work_with_retry`] can classify `40001` and
/// `40P01` as retryable transients (contract §"Retry and ambiguous commit").
/// Hooks should use this helper when mapping `postgres::Error` so a
/// serialization failure or deadlock observed inside the governed consequence
/// is retried rather than treated as an infrastructure failure.
#[must_use]
pub fn transaction_error(error: &postgres::Error) -> PgError {
    let detail = error
        .as_db_error()
        .map_or_else(|| error.to_string(), ToString::to_string);
    match error.code().map(postgres::error::SqlState::code) {
        Some(state) => {
            PgError::Transaction(format!("proof.pg.transient sqlstate={state}: {detail}"))
        }
        None => PgError::Transaction(detail),
    }
}

/// The internal attempt failure that preserves the PostgreSQL error so the
/// retry wrapper can classify its SQLSTATE before stringifying.
enum AttemptFailure {
    /// A non-retryable failure before commit (hook refusal or a database
    /// operation that failed inside the transaction body).
    Terminal(PgError),
    /// Commit failed; the [`postgres::Error`] is retained so its SQLSTATE can
    /// drive the retry decision (contract §"Retry and ambiguous commit").
    CommitFailed(postgres::Error),
}

impl AttemptFailure {
    /// Returns `true` when this failure is a retryable transient SQLSTATE.
    fn is_retryable(&self) -> bool {
        match self {
            Self::Terminal(error) => is_retryable_transient(error),
            Self::CommitFailed(error) => is_retryable_commit_error(error),
        }
    }

    /// Collapses this failure into the public [`PgError`] taxonomy.
    fn into_pg_error(self) -> PgError {
        match self {
            Self::Terminal(error) => error,
            Self::CommitFailed(error) if error.code().is_none() => {
                PgError::AmbiguousCommit(error.to_string())
            }
            Self::CommitFailed(error) => PgError::Transaction(error.to_string()),
        }
    }
}

/// Runs one full twelve-step attempt, returning the raw commit error so the
/// caller can classify retryable SQLSTATEs.
fn run_unit_of_work_attempt<F>(
    client: &mut Client,
    hooks: &mut UnitOfWorkHooks<'_>,
    sequence_policy: CausalSequencePolicy,
    attempt_timeout: Option<Duration>,
    acknowledgement: &mut F,
) -> Result<UnitOfWorkOutcome, AttemptFailure>
where
    F: FnMut(UnitOfWorkOutcome) -> CommitAcknowledgement,
{
    let mut transaction = client
        .build_transaction()
        .isolation_level(IsolationLevel::Serializable)
        .read_only(false)
        .start()
        .map_err(|error| AttemptFailure::Terminal(transaction_error(&error)))?;

    if let Some(timeout) = attempt_timeout {
        configure_attempt_timeout(&mut transaction, timeout).map_err(AttemptFailure::Terminal)?;
    }

    // Step 1: select the deployment Workspace and verify the compatible
    // migration version.
    verify_migration_compatible(&mut transaction).map_err(AttemptFailure::Terminal)?;

    // Step 2: lock the Workspace write head and read the exact heads.
    let head = lock_head_for_update(&mut transaction).map_err(AttemptFailure::Terminal)?;

    // Step 3: derive and advance the causal sequences from the locked row only.
    // The write-back is an ordinary logged UPDATE, so it rolls back with the
    // transaction on infrastructure failure; no PostgreSQL sequence is used.
    let allocated = allocate_sequences_with_policy(&head, sequence_policy);
    write_back_advanced_head(&mut transaction, &allocated).map_err(AttemptFailure::Terminal)?;

    // Step 4: verify authentication before idempotency lookup or disclosure.
    if let Err(error) = (hooks.verify_authentication)() {
        let _ = transaction.rollback();
        return Err(AttemptFailure::Terminal(error));
    }

    // Step 5: evaluate current authorization at the locked head.
    if let Err(error) = (hooks.evaluate_authorization)(&mut transaction, &head) {
        let _ = transaction.rollback();
        return Err(AttemptFailure::Terminal(error));
    }

    // Step 6: keyed replay/conflict or a fresh attempt.
    match (hooks.replay_or_conflict)(&mut transaction, &head) {
        Ok(IdempotencyOutcome::Replayed) => {
            return commit_transaction(transaction, UnitOfWorkOutcome::Replayed, acknowledgement);
        }
        Ok(IdempotencyOutcome::Conflict) => {
            return commit_transaction(
                transaction,
                UnitOfWorkOutcome::ConflictCommitted,
                acknowledgement,
            );
        }
        Ok(IdempotencyOutcome::Fresh) => {}
        Err(error) => {
            let _ = transaction.rollback();
            return Err(AttemptFailure::Terminal(error));
        }
    }

    // Step 7: base state, approval, configuration, and concurrency precondition
    // conflicts are resolved inside the consequence hook, which returns an
    // application-failure signal (see step 10) without a governed effect.

    // Step 8 + 9: the governed application consequence. The hook bounds the
    // governed mutation with a savepoint (see [`crate::idempotency::SavepointGuard`])
    // so the decision and failure-consequence bodies can be committed outside
    // it (reproducing the SQLite savepoint rule).
    match (hooks.apply_consequence)(&mut transaction) {
        Ok(()) => {}
        Err(error) => {
            if is_infrastructure_failure(&error) {
                // Step 11: infrastructure/signing/artifact/storage/integrity
                // failure rolls back the entire transaction.
                let _ = transaction.rollback();
                return Err(AttemptFailure::Terminal(error));
            }
            // Step 10: an ordinary authorized application failure commits only
            // presentation consumption, decision, and failure-consequence
            // bodies (persisted by the hook outside its savepoint).
            return commit_transaction(
                transaction,
                UnitOfWorkOutcome::ApplicationFailureCommitted,
                acknowledgement,
            );
        }
    }

    // Step 12: nothing returns before commit success.
    commit_transaction(transaction, UnitOfWorkOutcome::Committed, acknowledgement)
}

fn configure_attempt_timeout(
    transaction: &mut postgres::Transaction<'_>,
    timeout: Duration,
) -> Result<(), PgError> {
    let milliseconds = timeout.as_millis().clamp(1, i32::MAX as u128);
    let value = format!("{milliseconds}ms");
    transaction
        .query_one(
            "SELECT set_config('statement_timeout', $1, true),
                    set_config('lock_timeout', $1, true)",
            &[&value],
        )
        .map_err(|error| transaction_error(&error))?;
    Ok(())
}

/// Commits one attempt, preserving the raw commit error for SQLSTATE
/// classification.
fn commit_transaction<F>(
    transaction: postgres::Transaction<'_>,
    outcome: UnitOfWorkOutcome,
    acknowledgement: &mut F,
) -> Result<UnitOfWorkOutcome, AttemptFailure>
where
    F: FnMut(UnitOfWorkOutcome) -> CommitAcknowledgement,
{
    transaction.commit().map_err(AttemptFailure::CommitFailed)?;
    if acknowledgement(outcome) == CommitAcknowledgement::Lost {
        Err(AttemptFailure::Terminal(PgError::AmbiguousCommit(
            "commit applied but its acknowledgement was lost".to_owned(),
        )))
    } else {
        Ok(outcome)
    }
}

/// Returns `true` when a commit failure is a transient SQLSTATE that the
/// adapter may retry: `40001` (serialization failure) or `40P01` (deadlock,
/// retried from the beginning only). `23505` (unique violation) is never
/// retried here because this foundation defines no named internal allocation
/// constraint; business uniqueness and idempotency conflicts remain stable
/// application results (contract §"Retry and ambiguous commit").
fn is_retryable_commit_error(error: &postgres::Error) -> bool {
    match error.code().map(postgres::error::SqlState::code) {
        Some(code) => matches!(
            classify_sqlstate(code),
            SqlStateClass::SerializationFailure | SqlStateClass::DeadlockDetected
        ),
        None => false,
    }
}

/// Returns `true` when a transaction-body error carries a retryable transient
/// SQLSTATE embedded by [`transaction_error`]. A serialization failure or
/// deadlock observed by a hook is retried exactly like one observed at commit
/// (contract §"Retry and ambiguous commit").
fn is_retryable_transient(error: &PgError) -> bool {
    let PgError::Transaction(message) = error else {
        return false;
    };
    let Some(rest) = message.strip_prefix("proof.pg.transient sqlstate=") else {
        return false;
    };
    let state = rest.split(':').next().unwrap_or_default();
    matches!(
        classify_sqlstate(state),
        SqlStateClass::SerializationFailure | SqlStateClass::DeadlockDetected
    )
}

/// Returns `true` when the error is an infrastructure/signing/artifact/storage/
/// integrity failure (contract step 11). Only
/// [`PgError::ApplicationFailure`] signals an ordinary authorized application
/// failure (step 10); every other variant fails closed and rolls back the
/// entire transaction.
fn is_infrastructure_failure(error: &PgError) -> bool {
    !matches!(error, PgError::ApplicationFailure(_))
}

/// Verifies the singleton migration head is present and in the `verified`
/// phase, and that the Workspace write head names the same migration version
/// (contract step 1).
fn verify_migration_compatible(transaction: &mut postgres::Transaction<'_>) -> Result<(), PgError> {
    let migration = transaction
        .query_opt(
            "SELECT version, phase FROM migration_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| transaction_error(&error))?;
    let Some(migration) = migration else {
        return Err(PgError::Migration(
            "the migration head singleton is absent".to_owned(),
        ));
    };
    let version: i32 = migration.get(0);
    let phase: String = migration.get(1);
    if phase != "verified" {
        return Err(PgError::Migration(format!(
            "migration head is in phase `{phase}`, not `verified`"
        )));
    }

    let head = transaction
        .query_opt(
            "SELECT migration_version FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| transaction_error(&error))?;
    let Some(head) = head else {
        return Err(PgError::Transaction(
            "the Workspace write head singleton is absent".to_owned(),
        ));
    };
    let migration_version: i32 = head.get(0);
    if migration_version != version {
        return Err(PgError::Migration(format!(
            "Workspace write head names migration version {migration_version}, ledger head is {version}"
        )));
    }
    Ok(())
}

/// Locks the singleton `workspace_write_head` row with `SELECT ... FOR UPDATE`
/// and decodes the exact heads (contract step 2).
fn lock_head_for_update(
    transaction: &mut postgres::Transaction<'_>,
) -> Result<WorkspaceHeadSnapshot, PgError> {
    let row = transaction
        .query_opt(
            "SELECT transaction_sequence, authority_sequence, content_sequence, release_sequence,
                    authority_head_digest, authority_head_sequence,
                    content_head_digest, release_head_digest, policy_head_digest,
                    configuration_head_digest
             FROM workspace_write_head
             WHERE singleton = 1
             FOR UPDATE",
            &[],
        )
        .map_err(|error| transaction_error(&error))?;
    let Some(row) = row else {
        return Err(PgError::Transaction(
            "the Workspace write head singleton is absent".to_owned(),
        ));
    };

    let authority_head_digest: Option<String> = row.get(4);
    let authority_head_sequence: Option<i64> = row.get(5);
    let authority_head = match (authority_head_digest, authority_head_sequence) {
        (Some(digest), Some(sequence)) => Some(AuthorityHeadV1 {
            sequence: to_u64(sequence)?,
            record_digest: parse_digest(&digest)?,
        }),
        (None, None) => None,
        _ => {
            return Err(PgError::Integrity(
                "authority head digest and sequence are not both present".to_owned(),
            ));
        }
    };

    Ok(WorkspaceHeadSnapshot {
        transaction_sequence: to_u64(row.get(0))?,
        authority_sequence: to_u64(row.get(1))?,
        content_sequence: to_u64(row.get(2))?,
        release_sequence: to_u64(row.get(3))?,
        authority_head,
        content_head: parse_optional_digest(row.get::<_, Option<String>>(6).as_deref())?,
        release_head: parse_optional_digest(row.get::<_, Option<String>>(7).as_deref())?,
        policy_head: parse_optional_digest(row.get::<_, Option<String>>(8).as_deref())?,
        configuration_head: parse_optional_digest(row.get::<_, Option<String>>(9).as_deref())?,
    })
}

/// Writes the advanced row-derived sequences back to the locked head row
/// (contract step 3). Head digests are updated by the governed consequence
/// hook, which owns the new authority/content/Release digests.
fn write_back_advanced_head(
    transaction: &mut postgres::Transaction<'_>,
    allocated: &AllocatedSequences,
) -> Result<(), PgError> {
    let transaction_sequence = i64::try_from(allocated.transaction).map_err(|_| {
        PgError::Transaction("transaction sequence exceeds BIGINT range".to_owned())
    })?;
    let authority_sequence = i64::try_from(allocated.authority)
        .map_err(|_| PgError::Transaction("authority sequence exceeds BIGINT range".to_owned()))?;
    let content_sequence = i64::try_from(allocated.content)
        .map_err(|_| PgError::Transaction("content sequence exceeds BIGINT range".to_owned()))?;
    let release_sequence = i64::try_from(allocated.release)
        .map_err(|_| PgError::Transaction("release sequence exceeds BIGINT range".to_owned()))?;
    transaction
        .execute(
            "UPDATE workspace_write_head
             SET transaction_sequence = $1,
                 authority_sequence = $2,
                 content_sequence = $3,
                 release_sequence = $4
             WHERE singleton = 1",
            &[
                &transaction_sequence,
                &authority_sequence,
                &content_sequence,
                &release_sequence,
            ],
        )
        .map_err(|error| transaction_error(&error))?;
    Ok(())
}

/// Decodes a non-negative `BIGINT` causal sequence into a `u64`.
fn to_u64(value: i64) -> Result<u64, PgError> {
    u64::try_from(value)
        .map_err(|_| PgError::Integrity("causal sequence in the head row is negative".to_owned()))
}

/// Decodes one optional head digest string into an optional [`ContentDigest`].
fn parse_optional_digest(value: Option<&str>) -> Result<Option<ContentDigest>, PgError> {
    value.map(parse_digest).transpose()
}

/// Decodes one algorithm-qualified digest string.
fn parse_digest(value: &str) -> Result<ContentDigest, PgError> {
    ContentDigest::from_str(value)
        .map_err(|error| PgError::Integrity(format!("invalid head digest: {error}")))
}
