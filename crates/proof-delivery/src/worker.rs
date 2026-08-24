//! Transactional outbox worker boundary (contract §"Transactional outbox and
//! delivery").
//!
//! The worker claims only the lowest nonterminal sequence of a stream whose
//! prior sequence is terminally delivered or explicitly abandoned; claims due
//! work in deterministic order in a short `READ COMMITTED` transaction using
//! `FOR UPDATE SKIP LOCKED`; records a random lease token, a 60-second lease
//! using PostgreSQL `clock_timestamp()`, and the counted attempt before
//! committing the claim; performs external I/O only after that commit with a
//! 30-second attempt deadline and no lease renewal; acknowledges in a new
//! transaction by compare-and-set on the exact lease token and generation;
//! rejects stale or superseded acknowledgements; and makes the same stable
//! delivery eligible again after lease expiry (contract §"Immutable artifacts
//! and delivery", §"Transactional outbox and delivery").

use std::time::Duration;

use proof_domain::{ContentDigest, WorkspaceId};
use proof_pg::{postgres_types::ToSql, wiring::PgRuntime};

use crate::DeliveryError;

/// The exact 60-second worker lease, measured by PostgreSQL
/// `clock_timestamp()` (contract §"Transactional outbox and delivery").
pub const LEASE_DURATION_SECONDS: u64 = 60;

/// The frozen 30-second external-attempt deadline; external I/O happens only
/// after claim commit with no lease renewal (contract §"Transactional outbox
/// and delivery").
pub const ATTEMPT_DEADLINE_SECONDS: u64 = 30;

/// The exact dead-letter threshold of twelve counted attempts in one
/// generation (contract §"Transactional outbox and delivery").
pub const MAX_ATTEMPTS_PER_GENERATION: u32 = 12;

/// The exact seven-day generation-age dead-letter threshold (contract
/// §"Transactional outbox and delivery").
pub const DEAD_LETTER_MAX_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Backoff base: five seconds (contract §"Transactional outbox and delivery").
pub const RETRY_BASE_SECONDS: u64 = 5;

/// Backoff cap: one hour (contract §"Transactional outbox and delivery").
pub const RETRY_CAP_SECONDS: u64 = 60 * 60;

/// Domain-separated BLAKE3-256 derive-key context for hashing a lease token.
/// The delivery state stores only this hash, never the raw token (contract
/// §"Transactional outbox and delivery").
const LEASE_TOKEN_HASH_CONTEXT: &str = "proof:lease-token:v1";

/// Bounded poll count for one [`OutboxWorker::run_loop`] invocation (contract
/// §"Transactional outbox and delivery"). Each poll consumes every currently
/// due delivery, so transient failures leave the loop when no work is due.
const RUN_LOOP_MAX_POLLS: usize = 64;

/// The closed mutable delivery state (contract §"Transactional outbox and
/// delivery").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatus {
    /// The delivery is eligible but not yet claimed.
    Pending,
    /// A live lease currently owns the delivery.
    InFlight,
    /// The effect was applied and acknowledged.
    Delivered,
    /// The poison delivery was dead-lettered and blocks only its stream.
    DeadLetter,
    /// An authenticated activator explicitly abandoned the poison delivery.
    Abandoned,
}

impl DeliveryStatus {
    /// Returns the exact lowercase wire spelling persisted in `delivery_state`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::InFlight => "in-flight",
            Self::Delivered => "delivered",
            Self::DeadLetter => "dead-letter",
            Self::Abandoned => "abandoned",
        }
    }
}

/// A uniformly random 32-byte lease token (contract §"Transactional outbox and
/// delivery"). The token is generated from the OS random source via
/// [`getrandom`]; no `rand` dependency exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseToken([u8; 32]);

impl LeaseToken {
    /// The exact lease-token length in bytes.
    pub const LENGTH: usize = 32;

    /// Generates a fresh random 32-byte lease token.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Lease`] when the OS random source is
    /// unavailable.
    pub fn generate() -> Result<Self, DeliveryError> {
        let mut bytes = [0_u8; Self::LENGTH];
        getrandom::fill(&mut bytes)
            .map_err(|error| DeliveryError::Lease(format!("random lease token: {error}")))?;
        Ok(Self(bytes))
    }

    /// Returns the raw 32-byte token.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the base64url-without-padding wire representation.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
}

/// One delivery claimed by the worker: the immutable event identity plus the
/// mutable per-generation claim state (contract §"Transactional outbox and
/// delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimedDeliveryV1 {
    /// Stable outbox event identity.
    pub event_id: String,
    /// Stable delivery identity.
    pub delivery_id: String,
    /// The current delivery generation (incremented by replay).
    pub generation: u64,
    /// Fixed Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Workspace transaction sequence (enqueue order, never time).
    pub workspace_transaction_sequence: u64,
    /// Per-transaction ordinal within the stream.
    pub ordinal: u64,
    /// Stable ordering key selecting the destination stream.
    pub ordering_key: String,
    /// Stream-local monotonic sequence.
    pub stream_sequence: u64,
    /// Event type (for example `preview.release`).
    pub event_type: String,
    /// Event version (for example `v1`).
    pub event_version: String,
    /// Exact effect identity (the committed consequence digest).
    pub effect_digest: ContentDigest,
    /// Canonical payload digest, when content-addressed.
    pub payload_digest: Option<ContentDigest>,
    /// Destination configuration digest.
    pub destination_configuration_digest: ContentDigest,
    /// The counted attempt number in the current generation.
    pub attempt_number: u32,
    /// The recorded random lease token for this claim.
    pub lease_token: LeaseToken,
}

/// The closed compare-and-set acknowledgement outcome (contract §"Transactional
/// outbox and delivery").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgeOutcome {
    /// The exact lease token and generation matched; the delivery is terminal.
    Acknowledged,
    /// The lease token or generation was superseded; the acknowledgement is
    /// rejected.
    StaleOrSuperseded,
    /// The lease already expired; the acknowledgement is rejected and the
    /// delivery becomes eligible again.
    LeaseExpired,
}

/// The closed dead-letter trigger (contract §"Transactional outbox and
/// delivery").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadLetterReason {
    /// Twelve counted attempts in one generation.
    AttemptsExhausted,
    /// Seven days from the generation start.
    GenerationAgeExceeded,
    /// An explicit permanent delivery failure.
    PermanentFailure,
}

/// Injected delivery handler: performs the external effect only after claim
/// commit and returns the terminal receipt digest (contract §"Transactional
/// outbox and delivery").
///
/// The handler is a plain function pointer so [`OutboxWorker`] remains
/// `Clone`, `Debug`, `Eq`, and `PartialEq`; the delivery boundary needs no
/// captured state because the complete [`ClaimedDeliveryV1`] is passed in.
pub type DeliveryHandler = fn(&ClaimedDeliveryV1) -> Result<ContentDigest, DeliveryError>;

/// Backoff delay uniformly sampled from the upper half of
/// `min(5s * 2^(attempt - 1), 1h)`, added to database time (contract
/// §"Transactional outbox and delivery").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryDelay;

impl RetryDelay {
    /// Computes the full backoff window `min(5s * 2^(attempt - 1), 1h)` for a
    /// 1-based generation attempt.
    #[must_use]
    pub fn window_for_attempt(attempt: u32) -> Duration {
        if attempt == 0 {
            // The contract defines the window only for a 1-based attempt; a
            // zero attempt has no backoff window.
            return Duration::ZERO;
        }
        let exponent = attempt.saturating_sub(1);
        // Saturate the power so a pathological attempt number cannot overflow a
        // `u64`; the one-hour cap makes the exact saturation point unobservable.
        let factor = if exponent >= 63 {
            u64::MAX
        } else {
            1_u64 << exponent
        };
        let seconds = RETRY_BASE_SECONDS
            .saturating_mul(factor)
            .min(RETRY_CAP_SECONDS);
        Duration::from_secs(seconds)
    }

    /// Uniformly samples the upper half of [`RetryDelay::window_for_attempt`].
    ///
    /// The returned delay is added to database time (`clock_timestamp()`) by
    /// the caller to schedule the next eligibility.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Deadline`] when the sample cannot be drawn.
    pub fn sample_upper_half(attempt: u32) -> Result<Duration, DeliveryError> {
        let window = Self::window_for_attempt(attempt);
        // The one-hour cap keeps the window far below `u64` nanoseconds, so the
        // truncating conversion below cannot lose magnitude.
        let half_nanos = window.as_nanos() / 2;
        if half_nanos == 0 {
            return Ok(Duration::ZERO);
        }
        let half_nanos = u64::try_from(half_nanos).map_err(|_| {
            DeliveryError::Deadline("retry window exceeds u64 nanoseconds".to_owned())
        })?;

        let mut bytes = [0_u8; 8];
        getrandom::fill(&mut bytes).map_err(|error| {
            DeliveryError::Deadline(format!("uniform retry-delay sample: {error}"))
        })?;
        let value = u64::from_le_bytes(bytes);
        // `half_nanos` is at most half an hour in nanoseconds, far below
        // `u64::MAX`, so the modulo bias is below any observable threshold for
        // this boundary.
        let offset = value % half_nanos;
        let delay_nanos = half_nanos + offset;
        Ok(Duration::from_nanos(delay_nanos))
    }
}

/// Deployment-scoped worker configuration (contract §"Transactional outbox and
/// delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerConfig {
    /// Exact connection string for the authority store.
    pub dsn: String,
}

impl WorkerConfig {
    /// Constructs a fixed worker configuration.
    #[must_use]
    pub fn new(dsn: impl Into<String>) -> Self {
        Self { dsn: dsn.into() }
    }

    /// Resolves the worker DSN from the environment or the development default.
    #[must_use]
    pub fn from_env() -> Self {
        let dsn =
            std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned());
        Self::new(dsn)
    }
}

/// The generation-scoped transactional outbox worker (contract §"Transactional
/// outbox and delivery"). Delivery is explicitly at least once: a target may
/// apply an effect before acknowledgement, so a retry can repeat delivery. No
/// exactly-once or at-most-once claim exists anywhere in this boundary.
#[derive(Clone, Debug)]
pub struct OutboxWorker {
    config: WorkerConfig,
    handler: Option<DeliveryHandler>,
}

impl PartialEq for OutboxWorker {
    /// Worker equality compares deployment configuration only: the injected
    /// handler is code, not state, so two workers with the same configuration
    /// are equal regardless of which handler function was injected.
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for OutboxWorker {}

impl OutboxWorker {
    /// Constructs a worker from the fixed configuration.
    ///
    /// The worker has no delivery handler until [`OutboxWorker::with_handler`]
    /// injects one; [`OutboxWorker::run_loop`] refuses to run without a
    /// handler.
    #[must_use]
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config,
            handler: None,
        }
    }

    /// Constructs a worker with an injected delivery handler.
    #[must_use]
    pub fn with_handler(config: WorkerConfig, handler: DeliveryHandler) -> Self {
        Self {
            config,
            handler: Some(handler),
        }
    }

    /// Returns the fixed worker configuration.
    #[must_use]
    pub const fn config(&self) -> &WorkerConfig {
        &self.config
    }

    /// Claims all currently due deliveries in deterministic stream order.
    ///
    /// The claim runs in a short `READ COMMITTED` transaction using
    /// `FOR UPDATE SKIP LOCKED`, selecting the lowest nonterminal sequence of
    /// each stream whose prior sequence is terminally delivered or explicitly
    /// abandoned. Each claim records a random [`LeaseToken`], a
    /// [`LEASE_DURATION_SECONDS`] lease via `clock_timestamp()`, and the
    /// counted attempt before the transaction commits.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Claim`] when a claim cannot be taken or
    /// committed.
    #[allow(clippy::cast_precision_loss)]
    pub fn claim_due_work(
        &self,
        runtime: &mut PgRuntime,
    ) -> Result<Vec<ClaimedDeliveryV1>, DeliveryError> {
        let mut transaction = runtime
            .client_mut()
            .transaction()
            .map_err(|error| DeliveryError::Claim(format!("begin claim transaction: {error}")))?;
        // PostgreSQL's default isolation is READ COMMITTED; make it explicit so
        // the contract's "short READ COMMITTED transaction" is enforced even if
        // a deployment changes `default_transaction_isolation`. `SET
        // TRANSACTION` is legal here because it is the first statement after
        // `BEGIN`.
        transaction
            .batch_execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE")
            .map_err(|error| {
                DeliveryError::Claim(format!("set claim transaction isolation: {error}"))
            })?;

        let rows = transaction
            .query(CLAIM_SELECT_SQL, &[])
            .map_err(|error| DeliveryError::Claim(format!("select due deliveries: {error}")))?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in &rows {
            let event_id: String = row.get(0);
            let delivery_id: String = row.get(1);
            let generation_i64: i64 = row.get(2);
            let generation = to_u64(generation_i64, "generation")?;
            let workspace_id = parse_workspace(row.get(3))?;
            let workspace_transaction_sequence =
                to_u64(row.get(4), "workspace_transaction_sequence")?;
            let ordinal = to_u64(row.get(5), "ordinal")?;
            let ordering_key: String = row.get(6);
            let stream_sequence = to_u64(row.get(7), "stream_sequence")?;
            let event_type: String = row.get(8);
            let event_version: String = row.get(9);
            let effect_digest = parse_digest(row.get(10), "effect_digest")?;
            let payload_digest = parse_optional_digest(row.get(11), "payload_digest")?;
            let destination_configuration_digest =
                parse_digest(row.get(12), "destination_configuration_digest")?;
            let attempts_in_generation = to_u64(row.get(13), "attempts_in_generation")?;

            // The counted attempt in the current generation: one more than the
            // committed claim count read from the locked row.
            let attempt_number = u32::try_from(attempts_in_generation.saturating_add(1))
                .map_err(|_| DeliveryError::Claim("attempt number exceeds u32".to_owned()))?;

            let lease_token = LeaseToken::generate()?;
            let lease_token_hash = lease_token_hash(&lease_token);
            // Backoff for the attempt that follows this consumed claim.
            let retry_delay = RetryDelay::sample_upper_half(attempt_number)?;
            let attempt_id = uuid::Uuid::now_v7().to_string();

            let update_params: &[&(dyn ToSql + Sync)] = &[
                &event_id,
                &delivery_id,
                &generation_i64,
                &i64::from(attempt_number),
                &lease_token_hash,
                // The lease and retry delays are multiplied by `interval` in
                // SQL, which infers `double precision`; the integer constants
                // are exact in `f64`.
                &(LEASE_DURATION_SECONDS as f64),
                &retry_delay.as_secs_f64(),
            ];
            transaction
                .execute(CLAIM_UPDATE_SQL, update_params)
                .map_err(|error| DeliveryError::Claim(format!("record claim: {error}")))?;

            let attempt_params: &[&(dyn ToSql + Sync)] = &[
                &attempt_id,
                &event_id,
                &delivery_id,
                &generation_i64,
                &i64::from(attempt_number),
                &lease_token_hash,
            ];
            transaction
                .execute(CLAIM_ATTEMPT_INSERT_SQL, attempt_params)
                .map_err(|error| DeliveryError::Claim(format!("record attempt: {error}")))?;

            claims.push(ClaimedDeliveryV1 {
                event_id,
                delivery_id,
                generation,
                workspace_id,
                workspace_transaction_sequence,
                ordinal,
                ordering_key,
                stream_sequence,
                event_type,
                event_version,
                effect_digest,
                payload_digest,
                destination_configuration_digest,
                attempt_number,
                lease_token,
            });
        }

        // Nothing returns before the claim commit: external I/O happens only
        // after this transaction durably owns the lease.
        transaction
            .commit()
            .map_err(|error| DeliveryError::Claim(format!("commit claim: {error}")))?;
        Ok(claims)
    }

    /// Acknowledges a claimed delivery by compare-and-set on the exact lease
    /// token and generation (contract §"Transactional outbox and delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Acknowledge`] when the acknowledgement cannot
    /// be committed.
    pub fn acknowledge(
        &self,
        runtime: &mut PgRuntime,
        claim: &ClaimedDeliveryV1,
        receipt_digest: ContentDigest,
    ) -> Result<AcknowledgeOutcome, DeliveryError> {
        let lease_token_hash = lease_token_hash(&claim.lease_token);
        let receipt = receipt_digest.to_string();
        let generation_i64 = i64::try_from(claim.generation).map_err(|_| {
            DeliveryError::Acknowledge("generation exceeds BIGINT range".to_owned())
        })?;

        let mut transaction = runtime.client_mut().transaction().map_err(|error| {
            DeliveryError::Acknowledge(format!("begin ack transaction: {error}"))
        })?;

        let updated = transaction
            .execute(
                "UPDATE delivery_state
                 SET status = 'delivered',
                     receipt_digest = $4,
                     lease_token_hash = NULL,
                     lease_expires_at = NULL,
                     next_attempt_at = NULL
                 WHERE event_id = $1
                   AND delivery_id = $2
                   AND generation = $3
                   AND lease_token_hash = $5
                   AND status = 'in-flight'
                   AND lease_expires_at > clock_timestamp()",
                &[
                    &claim.event_id,
                    &claim.delivery_id,
                    &generation_i64,
                    &receipt,
                    &lease_token_hash,
                ],
            )
            .map_err(|error| {
                DeliveryError::Acknowledge(format!("compare-and-set acknowledgement: {error}"))
            })?;

        if updated == 1 {
            transaction
                .execute(
                    "UPDATE delivery_attempts
                     SET status = 'delivered', terminal_at = clock_timestamp()
                     WHERE event_id = $1
                       AND delivery_id = $2
                       AND generation = $3
                       AND attempt_number = $4
                       AND lease_token_hash = $5",
                    &[
                        &claim.event_id,
                        &claim.delivery_id,
                        &generation_i64,
                        &i64::from(claim.attempt_number),
                        &lease_token_hash,
                    ],
                )
                .map_err(|error| {
                    DeliveryError::Acknowledge(format!("record terminal attempt: {error}"))
                })?;
            transaction
                .commit()
                .map_err(|error| DeliveryError::Acknowledge(format!("commit ack: {error}")))?;
            return Ok(AcknowledgeOutcome::Acknowledged);
        }

        // The compare-and-set did not match. Classify why so the caller can
        // observe a stale/superseded acknowledgement or a lease expiry.
        let outcome = match transaction
            .query_opt(
                "SELECT status, lease_token_hash
                 FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
                &[&claim.event_id, &claim.delivery_id, &generation_i64],
            )
            .map_err(|error| {
                DeliveryError::Acknowledge(format!("classify acknowledgement: {error}"))
            })? {
            None => AcknowledgeOutcome::StaleOrSuperseded,
            Some(row) => {
                let status: String = row.get(0);
                let stored_hash: Option<String> = row.get(1);
                if stored_hash.as_deref() != Some(lease_token_hash.as_str()) {
                    AcknowledgeOutcome::StaleOrSuperseded
                } else if status == "in-flight" {
                    // Token and generation match, but the lease already expired.
                    AcknowledgeOutcome::LeaseExpired
                } else {
                    AcknowledgeOutcome::StaleOrSuperseded
                }
            }
        };
        transaction.commit().map_err(|error| {
            DeliveryError::Acknowledge(format!("commit ack classification: {error}"))
        })?;
        Ok(outcome)
    }

    /// Dead-letters a poison delivery, blocking only its stream (contract
    /// §"Transactional outbox and delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::DeadLetter`] when the transition cannot be
    /// committed or the claim no longer owns the delivery (a stale lease).
    pub fn dead_letter(
        &self,
        runtime: &mut PgRuntime,
        claim: &ClaimedDeliveryV1,
        reason: DeadLetterReason,
    ) -> Result<(), DeliveryError> {
        let attempt_status = dead_letter_attempt_status(reason);
        let lease_token_hash = lease_token_hash(&claim.lease_token);
        let generation_i64 = i64::try_from(claim.generation)
            .map_err(|_| DeliveryError::DeadLetter("generation exceeds BIGINT range".to_owned()))?;

        let mut transaction = runtime.client_mut().transaction().map_err(|error| {
            DeliveryError::DeadLetter(format!("begin dead-letter transaction: {error}"))
        })?;

        let updated = transaction
            .execute(
                "UPDATE delivery_state
                 SET status = 'dead-letter',
                     lease_token_hash = NULL,
                     lease_expires_at = NULL,
                     next_attempt_at = NULL
                 WHERE event_id = $1
                   AND delivery_id = $2
                   AND generation = $3
                   AND lease_token_hash = $4
                   AND status = 'in-flight'",
                &[
                    &claim.event_id,
                    &claim.delivery_id,
                    &generation_i64,
                    &lease_token_hash,
                ],
            )
            .map_err(|error| {
                DeliveryError::DeadLetter(format!("dead-letter transition: {error}"))
            })?;

        if updated != 1 {
            let _ = transaction.rollback();
            return Err(DeliveryError::DeadLetter(
                "delivery is not owned by this claim (stale or superseded lease)".to_owned(),
            ));
        }

        transaction
            .execute(
                "UPDATE delivery_attempts
                 SET status = $6, terminal_at = clock_timestamp()
                 WHERE event_id = $1
                   AND delivery_id = $2
                   AND generation = $3
                   AND attempt_number = $4
                   AND lease_token_hash = $5",
                &[
                    &claim.event_id,
                    &claim.delivery_id,
                    &generation_i64,
                    &i64::from(claim.attempt_number),
                    &lease_token_hash,
                    &attempt_status,
                ],
            )
            .map_err(|error| {
                DeliveryError::DeadLetter(format!("record terminal attempt: {error}"))
            })?;

        transaction
            .commit()
            .map_err(|error| DeliveryError::DeadLetter(format!("commit dead-letter: {error}")))?;
        Ok(())
    }

    /// Runs the worker loop: claim, external I/O after commit within the
    /// 30-second attempt deadline with no renewal, then acknowledge (contract
    /// §"Transactional outbox and delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] on any claim or acknowledgement failure that
    /// the loop does not absorb as a per-stream retry.
    pub fn run_loop(&self, runtime: &mut PgRuntime) -> Result<(), DeliveryError> {
        let handler = self.handler.ok_or_else(|| {
            DeliveryError::Claim(
                "no delivery handler injected; construct with `OutboxWorker::with_handler`"
                    .to_owned(),
            )
        })?;

        for _ in 0..RUN_LOOP_MAX_POLLS {
            let claims = self.claim_due_work(runtime)?;
            if claims.is_empty() {
                return Ok(());
            }
            for claim in &claims {
                self.deliver_one(runtime, handler, claim)?;
            }
        }
        Ok(())
    }

    /// Applies one claimed delivery: external I/O after claim commit, then
    /// acknowledge or dead-letter. A handler failure is a transient retry
    /// unless the attempt window or generation age is exhausted.
    fn deliver_one(
        &self,
        runtime: &mut PgRuntime,
        handler: DeliveryHandler,
        claim: &ClaimedDeliveryV1,
    ) -> Result<(), DeliveryError> {
        match invoke_with_deadline(handler, claim) {
            Ok(receipt_digest) => {
                // The acknowledgement outcome (stale/superseded/expired) is a
                // per-stream observation, not a loop failure.
                let _ = self.acknowledge(runtime, claim, receipt_digest)?;
            }
            Err(_) => {
                if let Some(reason) = Self::dead_letter_reason(runtime, claim)? {
                    self.dead_letter(runtime, claim, reason)?;
                }
                // Otherwise the lease expires and the same stable delivery
                // becomes eligible again (at-least-once).
            }
        }
        Ok(())
    }

    /// Selects the dead-letter trigger for a failed attempt: twelve counted
    /// attempts in the generation, or seven days from the generation start,
    /// whichever comes first; otherwise the delivery retries.
    #[allow(clippy::cast_precision_loss)]
    fn dead_letter_reason(
        runtime: &mut PgRuntime,
        claim: &ClaimedDeliveryV1,
    ) -> Result<Option<DeadLetterReason>, DeliveryError> {
        let generation_i64 = i64::try_from(claim.generation)
            .map_err(|_| DeliveryError::DeadLetter("generation exceeds BIGINT range".to_owned()))?;
        let row = runtime
            .client_mut()
            .query_opt(
                "SELECT CASE
                     WHEN attempts_in_generation >= $4 THEN 'attempts'
                     WHEN generation_started_at <= clock_timestamp() - ($5 * interval '1 second')
                         THEN 'age'
                     ELSE 'retry'
                 END
                 FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
                &[
                    &claim.event_id,
                    &claim.delivery_id,
                    &generation_i64,
                    &i64::from(MAX_ATTEMPTS_PER_GENERATION),
                    // Multiplied by `interval` in SQL (inferred `double
                    // precision`); the constant is exact in `f64`.
                    &(DEAD_LETTER_MAX_AGE_SECONDS as f64),
                ],
            )
            .map_err(|error| {
                DeliveryError::DeadLetter(format!("read dead-letter state: {error}"))
            })?;

        Ok(match row {
            None => None,
            Some(row) => match row.get::<_, String>(0).as_str() {
                "attempts" => Some(DeadLetterReason::AttemptsExhausted),
                "age" => Some(DeadLetterReason::GenerationAgeExceeded),
                _ => None,
            },
        })
    }
}

/// The deterministic due-delivery claim query (contract §"Transactional outbox
/// and delivery").
///
/// It locks only the latest-generation `delivery_state` row of each candidate
/// with `FOR UPDATE ... SKIP LOCKED`, ordered by the Workspace transaction
/// sequence plus ordinal — never by time. A candidate must be the lowest
/// nonterminal delivery of its stream (no earlier nonterminal delivery exists)
/// and its immediate predecessor in the stream must be terminally `delivered`
/// or explicitly `abandoned`; a `dead-letter` predecessor blocks the stream.
const CLAIM_SELECT_SQL: &str = r"
SELECT
    o.event_id,
    d.delivery_id,
    d.generation,
    o.workspace_id,
    o.workspace_transaction_sequence,
    o.ordinal,
    o.ordering_key,
    o.stream_sequence,
    o.event_type,
    o.event_version,
    o.effect_digest,
    o.payload_digest,
    o.destination_configuration_digest,
    d.attempts_in_generation
FROM delivery_state d
JOIN outbox_events o ON o.event_id = d.event_id
WHERE d.generation = (
        SELECT MAX(d2.generation)
        FROM delivery_state d2
        WHERE d2.event_id = d.event_id
          AND d2.delivery_id = d.delivery_id
    )
  AND (
        (d.status = 'pending' AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= clock_timestamp()))
        OR
        (d.status = 'in-flight'
            AND d.lease_expires_at IS NOT NULL
            AND d.lease_expires_at <= clock_timestamp()
            AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= clock_timestamp()))
    )
  AND (
        NOT EXISTS (
            SELECT 1
            FROM outbox_events p
            WHERE p.ordering_key = o.ordering_key
              AND (p.workspace_transaction_sequence, p.ordinal)
                  < (o.workspace_transaction_sequence, o.ordinal)
        )
        OR
        (
            SELECT pd.status
            FROM outbox_events p
            JOIN delivery_state pd
              ON pd.event_id = p.event_id
             AND pd.generation = (
                    SELECT MAX(pd2.generation)
                    FROM delivery_state pd2
                    WHERE pd2.event_id = pd.event_id
                      AND pd2.delivery_id = pd.delivery_id
                )
            WHERE p.ordering_key = o.ordering_key
              AND (p.workspace_transaction_sequence, p.ordinal)
                  < (o.workspace_transaction_sequence, o.ordinal)
            ORDER BY p.workspace_transaction_sequence DESC, p.ordinal DESC
            LIMIT 1
        ) IN ('delivered', 'abandoned')
    )
ORDER BY o.workspace_transaction_sequence, o.ordinal
FOR UPDATE OF d SKIP LOCKED
";

/// Records the in-flight lease and the counted attempt at claim commit
/// (contract §"Transactional outbox and delivery"). The lease and the retry
/// delay are both added to `clock_timestamp()`, never to wall-clock time.
const CLAIM_UPDATE_SQL: &str = r"
UPDATE delivery_state
SET status = 'in-flight',
    attempts_in_generation = $4,
    lease_token_hash = $5,
    lease_expires_at = clock_timestamp() + ($6 * interval '1 second'),
    next_attempt_at = clock_timestamp() + ($7 * interval '1 second')
WHERE event_id = $1
  AND delivery_id = $2
  AND generation = $3
";

/// Appends the immutable attempt record at claim commit (contract
/// §"Transactional outbox and delivery"). Older generations' attempts remain
/// untouched as global history.
const CLAIM_ATTEMPT_INSERT_SQL: &str = r"
INSERT INTO delivery_attempts
    (attempt_id, event_id, delivery_id, generation, attempt_number,
     lease_token_hash, status, attempted_at, terminal_at)
VALUES
    ($1, $2, $3, $4, $5, $6, 'claimed', clock_timestamp(), NULL)
";

/// Invokes the delivery handler after claim commit, enforcing the frozen
/// 30-second attempt deadline with no lease renewal (contract §"Transactional
/// outbox and delivery"). A handler that exceeds the deadline is abandoned by
/// the worker; the delivery retries after lease expiry.
fn invoke_with_deadline(
    handler: DeliveryHandler,
    claim: &ClaimedDeliveryV1,
) -> Result<ContentDigest, DeliveryError> {
    let claim = claim.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = handler(&claim);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(Duration::from_secs(ATTEMPT_DEADLINE_SECONDS)) {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(error)) => Err(error),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(DeliveryError::Deadline(format!(
            "attempt deadline of {ATTEMPT_DEADLINE_SECONDS}s exceeded"
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(DeliveryError::Deadline(
            "delivery handler panicked before returning".to_owned(),
        )),
    }
}

/// Domain-separated hash of the random lease token; only this hash is
/// persisted (contract §"Transactional outbox and delivery").
fn lease_token_hash(token: &LeaseToken) -> String {
    proof_remote::derive_key_digest(LEASE_TOKEN_HASH_CONTEXT, token.as_bytes()).to_string()
}

/// The append-only `delivery_attempts` terminal status for a dead-letter
/// transition. The trigger reason is recorded here for observability;
/// `delivery_state.status` is uniformly `dead-letter` (contract
/// §"Transactional outbox and delivery").
fn dead_letter_attempt_status(reason: DeadLetterReason) -> &'static str {
    match reason {
        DeadLetterReason::AttemptsExhausted => "dead-letter:attempts-exhausted",
        DeadLetterReason::GenerationAgeExceeded => "dead-letter:generation-age",
        DeadLetterReason::PermanentFailure => "dead-letter:permanent",
    }
}

/// Decodes a non-negative `BIGINT` causal value into a `u64`.
fn to_u64(value: i64, field: &str) -> Result<u64, DeliveryError> {
    u64::try_from(value)
        .map_err(|_| DeliveryError::Claim(format!("{field} is negative or out of range: {value}")))
}

/// Decodes one algorithm-qualified digest string.
fn parse_digest(value: String, field: &str) -> Result<ContentDigest, DeliveryError> {
    value
        .parse::<ContentDigest>()
        .map_err(|error| DeliveryError::Claim(format!("invalid {field}: {error}")))
}

/// Decodes one optional algorithm-qualified digest string.
fn parse_optional_digest(
    value: Option<String>,
    field: &str,
) -> Result<Option<ContentDigest>, DeliveryError> {
    value.map(|digest| parse_digest(digest, field)).transpose()
}

/// Decodes one Workspace identity string.
fn parse_workspace(value: String) -> Result<WorkspaceId, DeliveryError> {
    value
        .parse::<WorkspaceId>()
        .map_err(|error| DeliveryError::Claim(format!("invalid workspace_id: {error}")))
}
