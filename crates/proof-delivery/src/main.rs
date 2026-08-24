//! `proof-worker` binary entry point (contract §"Transactional outbox and
//! delivery").
//!
//! The binary resolves the worker configuration from the environment, connects
//! the `PostgreSQL` authority store, advances the migration ledger through the
//! v3 delivery-state schema, injects the reference `preview.release/v1`
//! delivery handler, and drains the outbox through the bounded
//! [`OutboxWorker::run_loop`] loop (at most 64 polls). It is a single bounded
//! pass, suitable for a cron-scheduled worker.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use proof_delivery::{
    DeliveryError,
    preview::{PreviewAdapter, PreviewBlobV1, PreviewSnapshotV1},
    proof_domain::{ArtifactKind, ContentDigest, WorkspaceId},
    proof_pg::{PgConfig, wiring::PgRuntime},
    proof_remote::derive_key_digest,
    worker::{ClaimedDeliveryV1, OutboxWorker, WorkerConfig},
};

/// Environment variable selecting the private preview staging root for the
/// reference worker. Defaults to `<temp>/proof-preview/worker`.
const PREVIEW_ROOT_ENV: &str = "PROOF_PREVIEW_ROOT";

/// Environment variable selecting the single Workspace identity. Defaults to a
/// fixed development Workspace `UUIDv7`.
const WORKSPACE_ID_ENV: &str = "PROOF_WORKSPACE_ID";

/// Fixed development Workspace identity when [`WORKSPACE_ID_ENV`] is unset.
const DEFAULT_WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000010";

/// The frozen 30-second application deadline reused for the worker runtime
/// configuration (contract §"Transactional outbox and delivery").
const WORKER_COMPATIBILITY_INTERVAL: Duration = Duration::from_secs(30);

/// The only event type/version the reference worker materializes.
const PREVIEW_RELEASE_EVENT_TYPE: &str = "preview.release";
const PREVIEW_RELEASE_EVENT_VERSION: &str = "v1";

fn main() -> ExitCode {
    let config = WorkerConfig::from_env();
    let workspace_id = workspace_id();
    let mut runtime = match PgRuntime::connect(PgConfig::new(
        config.dsn.clone(),
        workspace_id,
        WORKER_COMPATIBILITY_INTERVAL,
    )) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("proof-worker: cannot connect the authority store: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = runtime.migrate_delivery_state() {
        eprintln!("proof-worker: cannot apply the delivery-state migration: {error}");
        return ExitCode::FAILURE;
    }

    let worker = OutboxWorker::with_handler(config, preview_delivery_handler);
    match worker.run_loop(&mut runtime) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("proof-worker: worker loop failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves the single Workspace identity from [`WORKSPACE_ID_ENV`] or the
/// fixed development default.
fn workspace_id() -> WorkspaceId {
    std::env::var(WORKSPACE_ID_ENV)
        .unwrap_or_else(|_| DEFAULT_WORKSPACE_ID.to_owned())
        .parse()
        .unwrap_or_else(|_| {
            DEFAULT_WORKSPACE_ID
                .parse()
                .expect("valid default Workspace UUIDv7")
        })
}

/// Resolves the private preview staging root from [`PREVIEW_ROOT_ENV`] or the
/// system temporary directory.
fn preview_root() -> PathBuf {
    std::env::var(PREVIEW_ROOT_ENV).map_or_else(
        |_| std::env::temp_dir().join("proof-preview").join("worker"),
        PathBuf::from,
    )
}

/// The reference `preview.release/v1` delivery handler.
///
/// It materializes a single-blob reference snapshot whose Release identity is
/// the stable event identity and whose digest binds the committed effect
/// digest, then returns the content-addressed manifest digest as the terminal
/// receipt. A real deployment fetches the exact artifact closure by digest and
/// substitutes it here; the delivery boundary is identical either way.
fn preview_delivery_handler(claim: &ClaimedDeliveryV1) -> Result<ContentDigest, DeliveryError> {
    if claim.event_type != PREVIEW_RELEASE_EVENT_TYPE
        || claim.event_version != PREVIEW_RELEASE_EVENT_VERSION
    {
        return Err(DeliveryError::Integrity(format!(
            "unsupported event type `{}` at version `{}`",
            claim.event_type, claim.event_version
        )));
    }

    let adapter = PreviewAdapter::new(preview_root());
    let blob = reference_blob(claim);
    let snapshot = PreviewSnapshotV1 {
        release_id: claim.event_id.clone(),
        release_sequence: claim.stream_sequence,
        release_digest: claim.effect_digest,
        edition_digest: claim
            .payload_digest
            .unwrap_or_else(|| ContentDigest::blake3([0_u8; 32])),
        environment_config_digest: claim.destination_configuration_digest,
        proof_digest: ContentDigest::blake3([0_u8; 32]),
        blobs: vec![blob],
    };

    let manifest = adapter.materialize_snapshot(&snapshot)?;
    Ok(manifest.manifest_digest)
}

/// Builds the single reference Release blob for a claimed delivery.
fn reference_blob(claim: &ClaimedDeliveryV1) -> PreviewBlobV1 {
    let kind = ArtifactKind::ReleaseV2;
    let bytes = claim.effect_digest.to_string().into_bytes();
    let digest = derive_key_digest(kind.derive_key_context(), &bytes);
    let hex = digest.to_string().trim_start_matches("blake3:").to_owned();
    PreviewBlobV1 {
        key: format!("artifacts/{}/blake3/{hex}", kind.wire_name()),
        kind: kind.wire_name().to_owned(),
        length: bytes.len() as u64,
        digest,
        bytes,
    }
}
