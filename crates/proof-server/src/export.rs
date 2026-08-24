//! Immutable keyed evidence-export capture, no-key lifecycle status read,
//! kind-and-digest artifact acquisition, and the out-of-transaction assembly
//! worker (contract §"Evidence export and independent verification").
//!
//! This module is a skeleton: the public function and [`ExportWorker`]
//! signatures are final while every body is `todo!()`. `evidence.export/v2`
//! commits one immutable [`EvidenceExportCaptureV2`] and always returns the
//! keyed pending [`EvidenceExportResultV2`]; the worker builds the logical
//! member map outside the transaction and performs a separate pending-to-ready
//! transaction; `evidence.export.get/v1` reads the mutable
//! [`EvidenceExportStatusV1`]; `evidence.artifact.get/v2` acquires one body by
//! its exact `(export_id, artifact_kind, digest)` triple.

use proof_domain::ContentDigest;
use proof_remote::{
    AuthenticatedActorContextV2, EvidenceExportCaptureV2, EvidenceExportResultV2,
    EvidenceExportStatusV1, RemoteAuthorityRecordSetV1, RemoteAuthorizationDecisionV1,
    RemoteEvidenceBundleV2, RemoteEvidenceManifestV2, RemoteEvidenceMemberMap, RemoteOperationV1,
    RemoteReleaseArtifactClosureV1,
};
use serde_json::Value;

use crate::{AppState, ServerError};

/// The exact `(export_id, artifact_kind, digest)` triple that addresses and
/// authorizes one artifact acquisition (contract §"Evidence export and
/// independent verification").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceArtifactSelector {
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// Exact artifact kind; a digest under another kind is not an alias.
    pub artifact_kind: String,
    /// Domain-separated digest of the exact canonical bytes.
    pub digest: ContentDigest,
}

/// `evidence.export/v2`: commits one immutable [`EvidenceExportCaptureV2`] in a
/// short serializable transaction with the `pre-export-attempt-locked-heads`
/// capture boundary and always returns the keyed pending result (contract
/// §"Evidence export and independent verification").
///
/// Every same-key equivalent replay returns the same create-result bytes, even
/// after assembly finishes.
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// consequence failure.
pub fn evidence_export_v2(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<EvidenceExportResultV2, ServerError> {
    let _ = (state, operation, normalized_input, actor_context, decision);
    todo!("commit the immutable capture and return the keyed pending result")
}

/// `evidence.export.get/v1`: the no-key fresh authentication/authorization
/// lifecycle read returning the mutable [`EvidenceExportStatusV1`] (contract
/// §"Evidence export and independent verification").
///
/// It cannot replace the capture or the keyed result; it publishes null
/// descriptor/manifest digests and zero counts while pending and the exact
/// reserved digests/counts/bytes when ready.
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, or storage
/// failure.
pub fn evidence_export_get_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<EvidenceExportStatusV1, ServerError> {
    let _ = (state, operation, actor_context, decision);
    todo!("read the mutable readiness projection without an application key")
}

/// `evidence.artifact.get/v2`: acquires one artifact body addressed and
/// authorized by its exact `(export_id, artifact_kind, digest)` triple, with
/// kind, length, and digest revalidated (contract §"Evidence export and
/// independent verification").
///
/// # Errors
///
/// Returns [`ServerError`] when the triple does not resolve, the kind does not
/// match, or length/digest revalidation fails.
pub fn evidence_artifact_get_v2(
    state: &AppState,
    selector: &EvidenceArtifactSelector,
) -> Result<Vec<u8>, ServerError> {
    let _ = (state, selector);
    todo!("acquire and revalidate the exact kind-and-digest artifact bytes")
}

/// Builds the exact uncompressed logical member map from one immutable capture,
/// outside any transaction (contract §"Evidence export and independent
/// verification").
///
/// # Errors
///
/// Returns [`ServerError`] when the capture's closure bytes are absent,
/// malformed, or fail kind/length/digest revalidation.
pub fn build_logical_member_map(
    capture: &EvidenceExportCaptureV2,
    closure: &RemoteReleaseArtifactClosureV1,
    record_set: &RemoteAuthorityRecordSetV1,
) -> Result<RemoteEvidenceMemberMap, ServerError> {
    let _ = (capture, closure, record_set);
    todo!("build the deterministic uncompressed logical member map")
}

/// Builds the reserved `bundle.json` descriptor from one immutable capture.
///
/// # Errors
///
/// Returns [`ServerError`] on any projection failure.
pub fn build_bundle_descriptor(
    capture: &EvidenceExportCaptureV2,
) -> Result<RemoteEvidenceBundleV2, ServerError> {
    let _ = capture;
    todo!("project the canonical bundle descriptor from the capture")
}

/// Builds the reserved `manifest.json` value from one immutable capture.
///
/// # Errors
///
/// Returns [`ServerError`] on any projection failure.
pub fn build_manifest(
    capture: &EvidenceExportCaptureV2,
) -> Result<RemoteEvidenceManifestV2, ServerError> {
    let _ = capture;
    todo!("project the canonical manifest from the capture")
}

/// `assemble_export`: the worker entrypoint that builds the logical member map
/// from the capture outside the transaction, verifies the bytes, and performs
/// the separate pending-to-ready transaction (contract §"Evidence export and
/// independent verification").
///
/// # Errors
///
/// Returns [`ServerError`] when verification fails or the ready transition
/// cannot commit.
pub fn assemble_export(
    state: &AppState,
    capture: &EvidenceExportCaptureV2,
) -> Result<EvidenceExportStatusV1, ServerError> {
    let _ = (state, capture);
    todo!("assemble, verify, and transition the export to ready")
}

/// The bounded assembly worker that materializes captured exports into their
/// ready logical member maps (contract §"Evidence export and independent
/// verification").
#[derive(Clone, Debug, Default)]
pub struct ExportWorker;

impl ExportWorker {
    /// Constructs the assembly worker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Assembles one captured export and transitions it pending-to-ready.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any build, verification, or transition
    /// failure.
    pub fn assemble(
        &self,
        state: &AppState,
        capture: &EvidenceExportCaptureV2,
    ) -> Result<EvidenceExportStatusV1, ServerError> {
        let _ = (state, capture);
        todo!("assemble one captured export outside the transaction")
    }

    /// Claims and assembles one due pending export; returns the number of
    /// exports advanced (0 or 1).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on storage or assembly failure.
    pub fn run_once(&self, state: &AppState) -> Result<usize, ServerError> {
        let _ = state;
        todo!("claim one pending export, assemble it, and transition it to ready")
    }
}
