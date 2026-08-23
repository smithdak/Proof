//! Transactional outbox enqueue only (contract §"Transactional outbox and
//! delivery"). No worker, lease, claim, acknowledgement, or delivery state is
//! introduced by this item.

use proof_domain::{ContentDigest, CorrelationId, Timestamp, WorkspaceId};

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
