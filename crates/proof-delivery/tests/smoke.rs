//! Public-surface assertions only (no I/O, no database, no network).
//!
//! These tests pin the exact contract constants and type surface so a later
//! implementation cannot silently reshape the P-0012 delivery boundary.

use proof_delivery::{
    preview::{AliasOutcome, PREVIEW_CACHE_CONTROL, PreviewAdapter, ReadyManifestV1, strong_etag},
    proof_domain::ContentDigest,
    proof_pg::migration::{
        DELIVERY_STATE_MIGRATION_NAME, DELIVERY_STATE_MIGRATION_VERSION,
        delivery_state_migration_v3,
    },
    proof_remote::{
        authority::REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT,
        registry::DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT,
    },
    worker::{
        ATTEMPT_DEADLINE_SECONDS, AcknowledgeOutcome, DEAD_LETTER_MAX_AGE_SECONDS,
        DeadLetterReason, DeliveryStatus, LEASE_DURATION_SECONDS, LeaseToken,
        MAX_ATTEMPTS_PER_GENERATION, RETRY_BASE_SECONDS, RETRY_CAP_SECONDS, RetryDelay,
        WorkerConfig,
    },
};

#[test]
fn worker_lease_and_deadline_constants_are_exact() {
    assert_eq!(LEASE_DURATION_SECONDS, 60);
    assert_eq!(ATTEMPT_DEADLINE_SECONDS, 30);
    assert_eq!(LeaseToken::LENGTH, 32);
}

#[test]
fn retry_and_dead_letter_bounds_are_exact() {
    assert_eq!(MAX_ATTEMPTS_PER_GENERATION, 12);
    assert_eq!(DEAD_LETTER_MAX_AGE_SECONDS, 7 * 24 * 60 * 60);
    assert_eq!(RETRY_BASE_SECONDS, 5);
    assert_eq!(RETRY_CAP_SECONDS, 60 * 60);
}

#[test]
fn delivery_status_wire_spellings_are_exact() {
    assert_eq!(DeliveryStatus::Pending.as_str(), "pending");
    assert_eq!(DeliveryStatus::InFlight.as_str(), "in-flight");
    assert_eq!(DeliveryStatus::Delivered.as_str(), "delivered");
    assert_eq!(DeliveryStatus::DeadLetter.as_str(), "dead-letter");
    assert_eq!(DeliveryStatus::Abandoned.as_str(), "abandoned");
}

#[test]
fn closed_outcome_enums_have_the_contract_variants() {
    let _ = AcknowledgeOutcome::Acknowledged;
    let _ = AcknowledgeOutcome::StaleOrSuperseded;
    let _ = AcknowledgeOutcome::LeaseExpired;
    let _ = DeadLetterReason::AttemptsExhausted;
    let _ = DeadLetterReason::GenerationAgeExceeded;
    let _ = DeadLetterReason::PermanentFailure;
    let _ = AliasOutcome::Advanced;
    let _ = AliasOutcome::NoOp;
    let _ = AliasOutcome::IntegrityFailure;
    let _ = AliasOutcome::Superseded;
}

#[test]
fn preview_constants_and_strong_etag_are_exact() {
    assert_eq!(PREVIEW_CACHE_CONTROL, "private, no-store");
    let digest = ContentDigest::blake3([0xab; 32]);
    assert_eq!(strong_etag(&digest), format!("\"{digest}\""));
}

#[test]
fn preview_adapter_surface_constructs() {
    let adapter = PreviewAdapter::new("/tmp/proof-preview");
    assert_eq!(
        adapter.root().as_path(),
        std::path::Path::new("/tmp/proof-preview")
    );
}

#[test]
fn worker_config_surface_constructs() {
    let config = WorkerConfig::new("postgres://postgres@127.0.0.1:55432/prooftest");
    assert_eq!(config.dsn, "postgres://postgres@127.0.0.1:55432/prooftest");
}

#[test]
fn delivery_state_migration_is_version_three() {
    assert_eq!(DELIVERY_STATE_MIGRATION_VERSION, 3);
    assert!(!DELIVERY_STATE_MIGRATION_NAME.is_empty());
    let script = delivery_state_migration_v3();
    assert_eq!(script.version, 3);
    assert_eq!(script.name, DELIVERY_STATE_MIGRATION_NAME);
    assert!(script.sql.contains("delivery_state"));
    assert!(script.sql.contains("delivery_attempts"));
    assert!(script.sql.contains("delivery_management_facts"));
}

#[test]
fn delivery_management_fact_is_not_a_remote_authority_record_payload() {
    // The delivery-management fact is deliberately NOT a
    // RemoteAuthorityRecordV1 payload: its digest context must differ from the
    // remote authority payload digest context.
    assert_eq!(
        DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT,
        "proof:delivery-management-fact:v1"
    );
    assert_ne!(
        DELIVERY_MANAGEMENT_FACT_DIGEST_CONTEXT,
        REMOTE_AUTHORITY_RECORD_DIGEST_CONTEXT
    );
}

#[test]
fn ready_manifest_and_retry_delay_types_are_named() {
    // The types exist as part of the public surface even though their
    // construction methods are `todo!()` stubs.
    let _: Option<ReadyManifestV1> = None;
    let _ = RetryDelay;
}
