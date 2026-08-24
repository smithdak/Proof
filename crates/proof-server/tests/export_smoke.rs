//! Public-surface assertions only (no I/O, no database, no network).
//!
//! These tests pin the closed evidence-export function and worker surface so a
//! later implementation cannot silently reshape the P-0013 export boundary.

use std::mem::size_of;

use proof_server::export::{
    EvidenceArtifactSelector, ExportWorker, assemble_export, build_bundle_descriptor,
    build_logical_member_map, build_manifest, evidence_artifact_get_v2, evidence_export_get_v1,
    evidence_export_v2,
};

/// References a `fn` item so a surface test can prove a module name resolves
/// without a full invocation here.
fn references<T>(_: T) {}

#[test]
fn export_function_and_worker_surface_resolves() {
    let _ = size_of::<EvidenceArtifactSelector>();
    let _ = size_of::<ExportWorker>();
    let worker = ExportWorker::new();
    let _ = &worker;

    references(evidence_export_v2);
    references(evidence_export_get_v1);
    references(evidence_artifact_get_v2);
    references(build_logical_member_map);
    references(build_bundle_descriptor);
    references(build_manifest);
    references(assemble_export);
}
