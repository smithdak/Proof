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
use proof_pg::wiring::PgRuntime;

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
        let _ = attempt;
        todo!("compute min(5s * 2^(attempt - 1), 1h) from the database-time base")
    }

    /// Uniformly samples the upper half of [`RetryDelay::window_for_attempt`].
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Deadline`] when the sample cannot be drawn.
    pub fn sample_upper_half(attempt: u32) -> Result<Duration, DeliveryError> {
        let _ = attempt;
        todo!("uniformly sample the upper half of window_for_attempt and add it to database time")
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
        todo!("resolve PROOF_PG_DSN or the development default DSN")
    }
}

/// The generation-scoped transactional outbox worker (contract §"Transactional
/// outbox and delivery"). Delivery is explicitly at least once: a target may
/// apply an effect before acknowledgement, so a retry can repeat delivery. No
/// exactly-once or at-most-once claim exists anywhere in this boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxWorker {
    config: WorkerConfig,
}

impl OutboxWorker {
    /// Constructs a worker from the fixed configuration.
    #[must_use]
    pub fn new(config: WorkerConfig) -> Self {
        Self { config }
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
    pub fn claim_due_work(
        &self,
        runtime: &mut PgRuntime,
    ) -> Result<Vec<ClaimedDeliveryV1>, DeliveryError> {
        let _ = (self, runtime);
        todo!(
            "claim due work under READ COMMITTED with FOR UPDATE SKIP LOCKED in deterministic order"
        )
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
        let _ = (self, runtime, claim, receipt_digest);
        todo!(
            "compare-and-set on the exact lease token and generation; reject stale or superseded acknowledgements"
        )
    }

    /// Dead-letters a poison delivery, blocking only its stream (contract
    /// §"Transactional outbox and delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::DeadLetter`] when the transition cannot be
    /// committed.
    pub fn dead_letter(
        &self,
        runtime: &mut PgRuntime,
        claim: &ClaimedDeliveryV1,
        reason: DeadLetterReason,
    ) -> Result<(), DeliveryError> {
        let _ = (self, runtime, claim, reason);
        todo!("mark the poison delivery dead-lettered; a poison blocks only its stream")
    }

    /// Runs the worker loop: claim, external I/O after commit within the
    /// 30-second attempt deadline with no renewal, then acknowledge (contract
    /// §"Transactional outbox and delivery").
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] on any claim, deadline, or acknowledgement
    /// failure that the loop does not absorb as a per-stream retry.
    pub fn run_loop(&self, runtime: &mut PgRuntime) -> Result<(), DeliveryError> {
        let _ = (self, runtime);
        todo!(
            "claim due work, perform external I/O after commit within the attempt deadline, then acknowledge"
        )
    }
}
