//! Implementation conformance tests for `proof-remote` governance.
//!
//! These tests prove that the retained collaboration-server vectors assemble
//! and validate against the two implemented governance functions, that every
//! `EnvironmentConfigV2` cross-check rejects exactly its own mutation, and
//! that `ChangeSetApprovalV1::validate_prohibited_approvers` rejects the full
//! prohibited-approver and stale-closure matrix.

#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use proof_domain::{ContentDigest, Timestamp};
use proof_remote::{
    ChangeSetApprovalV1, EnvironmentConfigV2, RemoteError, validate_environment_config_v2,
};
use serde::de::DeserializeOwned;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vector_path(name: &str) -> PathBuf {
    repository_root()
        .join("conformance/v1/collaboration-server/vectors")
        .join(name)
}

fn load<T: DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn digest_of(context: &str, value: &serde_json::Value) -> ContentDigest {
    let canonical =
        proof_canonical::canonicalize(value).expect("retained vector must canonicalize");
    proof_remote::derive_key_digest(context, canonical.as_bytes())
}

fn assert_governance(result: Result<(), RemoteError>, needle: &str) {
    match result {
        Err(RemoteError::Governance(message)) => {
            assert!(
                message.contains(needle),
                "expected Governance error containing {needle:?}, got {message:?}"
            );
        }
        other => panic!("expected Governance error containing {needle:?}, got {other:?}"),
    }
}

#[test]
fn environment_config_v2_digests_match_the_retained_vector() {
    let raw: serde_json::Value = load(&vector_path("environment-config-v2.valid.json"));

    let expected_config_digest = raw["normalized_configuration_digest"]
        .as_str()
        .expect("vector carries a normalized_configuration_digest");
    assert_eq!(
        raw["environment_config_digest"].as_str().unwrap(),
        expected_config_digest,
        "the retained closure binds one config digest for both fields"
    );

    let computed_config_digest = digest_of(
        "proof:environment-config:v2",
        &raw["normalized_configuration"],
    )
    .to_string();
    assert_eq!(
        computed_config_digest, expected_config_digest,
        "normalized_configuration_digest must be the proof:environment-config:v2 RFC 8785 digest"
    );

    let expected_creation_digest = raw["environment_creation_record_digest"]
        .as_str()
        .expect("vector carries an environment_creation_record_digest");
    let computed_creation_digest = digest_of(
        "proof:remote-authority-record:v1",
        &raw["environment_creation"],
    )
    .to_string();
    assert_eq!(
        computed_creation_digest, expected_creation_digest,
        "environment_creation_record_digest must be the remote-authority-record digest"
    );
}

#[test]
fn assembled_environment_config_v2_validates() {
    let config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    validate_environment_config_v2(&config).expect("the retained assembled closure must validate");
}

#[test]
fn environment_config_v2_rejects_wrong_workspace() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.workspace_id = "019e0000-0000-7000-8000-0000000000aa".to_owned();
    assert_governance(validate_environment_config_v2(&config), "Workspace");
}

#[test]
fn environment_config_v2_rejects_chronology_gap() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.activation.activated_at = "2026-08-23T00:00:00Z".parse::<Timestamp>().unwrap();
    assert_governance(validate_environment_config_v2(&config), "chronology");
}

#[test]
fn environment_config_v2_rejects_predecessor_mismatch() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.predecessor_config_version = Some(999);
    assert_governance(validate_environment_config_v2(&config), "predecessor");
}

#[test]
fn environment_config_v2_rejects_proposal_digest_swap() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.proposal_record_digest =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .parse::<ContentDigest>()
            .unwrap();
    assert_governance(
        validate_environment_config_v2(&config),
        "proposal record digest",
    );
}

#[test]
fn environment_config_v2_rejects_creation_digest_swap() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.environment_creation_record_digest =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .parse::<ContentDigest>()
            .unwrap();
    assert_governance(
        validate_environment_config_v2(&config),
        "creation record digest",
    );
}

#[test]
fn environment_config_v2_rejects_copied_creation_field_mutation() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.activation.environment_created_at = "2026-08-23T00:00:00Z".parse::<Timestamp>().unwrap();
    assert_governance(
        validate_environment_config_v2(&config),
        "copied creation fields",
    );
}

#[test]
fn environment_config_v2_rejects_self_activation() {
    let mut config: EnvironmentConfigV2 = load(&vector_path("environment-config-v2.valid.json"));
    config.proposal.proposed_by_principal_id = config.activation.activated_by_principal_id.clone();
    assert_governance(validate_environment_config_v2(&config), "distinct");
}

#[test]
fn retained_changeset_approval_passes_prohibited_approvers() {
    let approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval
        .validate_prohibited_approvers()
        .expect("the retained approval must satisfy every prohibited-approver gate");
}

#[test]
fn prohibited_approver_rejects_the_changeset_requester() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.approver_principal_id = approval.requesting_principal_id.clone();
    assert_governance(
        approval.validate_prohibited_approvers(),
        "ChangeSet requesting Human",
    );
}

#[test]
fn prohibited_approver_rejects_a_contributing_operating_agent() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.approver_principal_id = approval.operating_principal_id.clone();
    assert_governance(
        approval.validate_prohibited_approvers(),
        "contributing operating Agent",
    );
}

#[test]
fn prohibited_approver_rejects_the_publisher_agent() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.publisher_principal_id = approval.approver_principal_id.clone();
    assert_governance(approval.validate_prohibited_approvers(), "publisher Agent");
}

#[test]
fn prohibited_approver_rejects_the_active_configuration_activator() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.approver_principal_id = approval.environment_activated_by_principal_id.clone();
    assert_governance(approval.validate_prohibited_approvers(), "activator");
}

#[test]
fn prohibited_approver_rejects_requesting_and_operating_identity_collapse() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.requesting_principal_id = approval.operating_principal_id.clone();
    assert_governance(approval.validate_prohibited_approvers(), "must be distinct");
}

#[test]
fn prohibited_approver_rejects_a_stale_authority_sequence() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.authority_sequence = approval.evaluated_authority_head.sequence;
    assert_governance(
        approval.validate_prohibited_approvers(),
        "exactly one sequence",
    );
}

#[test]
fn prohibited_approver_rejects_a_stale_prior_authority_head() {
    let mut approval: ChangeSetApprovalV1 = load(&vector_path("changeset-approval.valid.json"));
    approval.previous_authority_record_digest =
        "blake3:0000000000000000000000000000000000000000000000000000000000000000"
            .parse::<ContentDigest>()
            .unwrap();
    assert_governance(
        approval.validate_prohibited_approvers(),
        "immediate prior authority head",
    );
}
