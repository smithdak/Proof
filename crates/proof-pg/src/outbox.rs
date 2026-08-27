//! Transactional outbox enqueue and initial delivery state (contract
//! §"Transactional outbox and delivery").

use std::time::{Duration, SystemTime};

use postgres::Transaction;
use proof_domain::{ContentDigest, CorrelationId, Timestamp, WorkspaceId};

use crate::PgError;
use crate::artifacts::ArtifactKeyV1;

/// One immutable outbox enqueue record (contract §"Transactional outbox and
/// delivery").
///
/// The logical-event uniqueness key is
/// `{workspace_id, effect_digest, event_type, event_version,
/// destination_configuration_digest}`; the ordinal uniqueness key is
/// `{workspace_id, workspace_transaction_sequence, ordinal}`. These constraints
/// permit exactly one enqueue for that committed consequence and destination,
/// and say nothing about delivery count.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxEnqueueV1 {
    /// Stable UUIDv7 event identity.
    pub event_id: String,
    /// Fixed Workspace identity.
    pub workspace_id: WorkspaceId,
    /// Workspace transaction sequence (enqueue order, never time).
    pub workspace_transaction_sequence: u64,
    /// Per-transaction ordinal within the stream.
    pub ordinal: u64,
    /// Event type (for example `preview.release`).
    pub event_type: String,
    /// Event version (for example `v1`).
    pub event_version: String,
    /// Stable ordering key selecting the destination stream.
    pub ordering_key: String,
    /// Stream-local monotonic sequence.
    pub stream_sequence: u64,
    /// Exact effect identity (the committed consequence digest).
    pub effect_digest: ContentDigest,
    /// Canonical payload digest, when the payload is content-addressed.
    pub payload_digest: Option<ContentDigest>,
    /// Artifact reference, when the payload is an immutable artifact.
    pub artifact_reference: Option<ArtifactKeyV1>,
    /// Destination configuration version.
    pub destination_configuration_version: u64,
    /// Destination configuration digest.
    pub destination_configuration_digest: ContentDigest,
    /// Correlation identity, when present.
    pub correlation_id: Option<CorrelationId>,
    /// Causation identity (the prior effect that caused this one), when
    /// present.
    pub causation_id: Option<String>,
    /// Database-recorded committed creation time.
    pub committed_creation_time: Timestamp,
}

impl OutboxEnqueueV1 {
    /// Returns the logical-event uniqueness key
    /// `{workspace_id, effect_digest, event_type, event_version,
    /// destination_configuration_digest}`.
    #[must_use]
    pub fn effect_uniqueness_key(
        &self,
    ) -> (WorkspaceId, ContentDigest, String, String, ContentDigest) {
        (
            self.workspace_id,
            self.effect_digest,
            self.event_type.clone(),
            self.event_version.clone(),
            self.destination_configuration_digest,
        )
    }

    /// Returns the ordinal uniqueness key
    /// `{workspace_id, workspace_transaction_sequence, ordinal}`.
    #[must_use]
    pub fn ordinal_uniqueness_key(&self) -> (WorkspaceId, u64, u64) {
        (
            self.workspace_id,
            self.workspace_transaction_sequence,
            self.ordinal,
        )
    }
}

/// Enqueues exactly one immutable outbox event in the caller's transaction
/// (contract §"Transactional outbox and delivery").
///
/// This is the enqueue-only boundary: both uniqueness keys are enforced by the
/// database's `UNIQUE` constraints, and no worker, lease, claim,
/// acknowledgement, backoff, dead-letter, replay, or delivery state is
/// introduced by this item.
///
/// # Errors
///
/// Returns [`PgError::Outbox`] for invalid numeric bounds and
/// [`PgError::Transaction`] for a database insertion failure.
pub fn enqueue(transaction: &mut Transaction, event: &OutboxEnqueueV1) -> Result<(), PgError> {
    let workspace_transaction_sequence = i64::try_from(event.workspace_transaction_sequence)
        .map_err(|_| {
            PgError::Outbox("workspace_transaction_sequence exceeds BIGINT range".to_owned())
        })?;
    let ordinal = i64::try_from(event.ordinal)
        .map_err(|_| PgError::Outbox("ordinal exceeds BIGINT range".to_owned()))?;
    let stream_sequence = i64::try_from(event.stream_sequence)
        .map_err(|_| PgError::Outbox("stream_sequence exceeds BIGINT range".to_owned()))?;
    let destination_configuration_version = i64::try_from(event.destination_configuration_version)
        .map_err(|_| {
            PgError::Outbox("destination_configuration_version exceeds BIGINT range".to_owned())
        })?;

    let workspace_id = event.workspace_id.to_string();
    let effect_digest = event.effect_digest.to_string();
    let payload_digest = event.payload_digest.map(|value| value.to_string());
    let artifact_kind = event
        .artifact_reference
        .as_ref()
        .map(|key| key.kind.wire_name());
    let artifact_digest = event
        .artifact_reference
        .as_ref()
        .map(|key| key.blake3_digest.to_string());
    let destination_configuration_digest = event.destination_configuration_digest.to_string();
    let correlation_id = event.correlation_id.map(|value| value.to_string());
    let causation_id = event.causation_id.clone();
    let committed_creation_time = timestamp_to_system_time(event.committed_creation_time);

    let params: &[&(dyn postgres::types::ToSql + Sync)] = &[
        &event.event_id,
        &workspace_id,
        &workspace_transaction_sequence,
        &ordinal,
        &event.event_type,
        &event.event_version,
        &event.ordering_key,
        &stream_sequence,
        &effect_digest,
        &payload_digest,
        &artifact_kind,
        &artifact_digest,
        &destination_configuration_version,
        &destination_configuration_digest,
        &correlation_id,
        &causation_id,
        &committed_creation_time,
    ];
    transaction
        .execute(
            "INSERT INTO outbox_events (
                 event_id, workspace_id, workspace_transaction_sequence, ordinal,
                 event_type, event_version, ordering_key, stream_sequence,
                 effect_digest, payload_digest, artifact_kind, artifact_digest,
                 destination_configuration_version, destination_configuration_digest,
                 correlation_id, causation_id, committed_creation_time
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                 $15, $16, $17
             )",
            params,
        )
        .map_err(|error| crate::transaction::transaction_error(&error))?;
    Ok(())
}

/// Enqueues one immutable event and creates its stable generation-1 delivery
/// as immediately pending in the caller's transaction.
///
/// The event and delivery identities are supplied by the caller so a complete
/// transaction retry reuses them. One database timestamp initializes
/// `next_attempt_at`, `generation_started_at`, and `committed_at`; a failure in
/// either insert leaves the caller to roll back the complete transaction.
///
/// # Errors
///
/// Returns [`PgError::Outbox`] for invalid event bounds and
/// [`PgError::Transaction`] when either insertion fails.
pub fn enqueue_initial_delivery(
    transaction: &mut Transaction,
    event: &OutboxEnqueueV1,
    delivery_id: &str,
) -> Result<(), PgError> {
    enqueue(transaction, event)?;
    transaction
        .execute(
            "WITH initial_clock AS (
                 SELECT clock_timestamp() AS recorded_at
             )
             INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             )
             SELECT $1, $2, 1, 'pending', recorded_at,
                    0, NULL, NULL, NULL, recorded_at, recorded_at
             FROM initial_clock",
            &[&event.event_id, &delivery_id],
        )
        .map_err(|error| crate::transaction::transaction_error(&error))?;
    Ok(())
}

/// Converts a domain [`Timestamp`] into a [`SystemTime`] for `TIMESTAMPTZ`
/// binding. Microsecond truncation matches PostgreSQL `timestamptz` storage.
fn timestamp_to_system_time(timestamp: Timestamp) -> SystemTime {
    let nanos = timestamp.unix_timestamp_nanos();
    if nanos >= 0 {
        let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
        SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos)
    } else {
        let nanos = u64::try_from(nanos.unsigned_abs()).unwrap_or(u64::MAX);
        SystemTime::UNIX_EPOCH - Duration::from_nanos(nanos)
    }
}
