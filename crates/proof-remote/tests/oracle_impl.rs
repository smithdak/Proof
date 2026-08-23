//! Deterministic oracle implementation tests.
//!
//! These tests initialize an ephemeral SQLite-backed `proof-local` Workspace
//! through the deterministic authority adapter, replay shared operations
//! through [`RemoteSemanticOracle`], and assert byte-identical traces across
//! repeated runs, a typed success trace, a stable-problem trace for rejected
//! input, and the closed deterministic identity fixtures.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{InitializeWorkspaceCommand, Timestamp, initialize_workspace};
use proof_domain::ContentDigest;
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use proof_remote::identity::{
    AuthenticatedActorContextApiVersion, AuthenticatedActorContextHumanV2,
    OidcAuthenticatedSubjectApiVersion, OidcHumanAuthenticationProfile,
};
use proof_remote::oracle::OidcEnrollmentChallengeV1;
use proof_remote::{
    AuthenticatedActorContextV2, AuthorityHeadV1, IdentityFixtureV1, OidcAuthenticatedSubjectV1,
    OracleConsequence, OracleOutcome, RemoteOperationV1, RemoteSemanticOracle,
};
use serde_json::{Value, json};

const WORKSPACE_ID: &str = "019d0000-0000-7000-8000-000000000001";
const PRINCIPAL_ID: &str = "019d0000-0000-7000-8000-000000000002";
const AUTHENTICATED_AT: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 1_000;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x24; 32];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Creates a fresh, unique temporary directory for one Workspace root.
fn fresh_dir() -> PathBuf {
    let ordinal = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("proof-oracle-{}-{ordinal}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).expect("stale oracle tempdir must be removable");
    }
    fs::create_dir_all(&path).expect("oracle tempdir must be creatable");
    path
}

/// Initializes a deterministic SQLite-backed Workspace with fixed identity data.
fn initialize_workspace_at(root: &Path) -> LocalWorkspace {
    let workspace = LocalWorkspace::with_deterministic_authority_adapter(
        root,
        DeterministicLocalAuthorityAdapter::new(
            DETERMINISTIC_UID,
            AUTHENTICATED_AT
                .parse::<Timestamp>()
                .expect("fixed timestamp"),
            DETERMINISTIC_SUBJECT_BLIND,
        ),
    )
    .expect("the deterministic Workspace must select the fresh root");

    initialize_workspace(
        &workspace,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse().expect("fixed workspace identity"),
            bootstrap_principal_id: PRINCIPAL_ID.parse().expect("fixed principal identity"),
        },
    )
    .expect("the deterministic Workspace must initialize");

    workspace
}

fn digest(value: &str) -> ContentDigest {
    value.parse::<ContentDigest>().expect("fixed digest value")
}

/// Builds a closed Human actor context carrying the exact operation pair.
fn actor_context(name: &str, version: &str) -> AuthenticatedActorContextV2 {
    AuthenticatedActorContextV2::Human(AuthenticatedActorContextHumanV2 {
        api_version: AuthenticatedActorContextApiVersion::V1,
        audience: "proof://workspace/019e0000-0000-7000-8000-000000000001".to_owned(),
        authentication_profile: OidcHumanAuthenticationProfile::V1,
        oidc_issuer_configuration_digest: digest(
            "blake3:64cab46b9d5925076a726b80206f365d2e913768a90e0954487cb30b010a9cc7",
        ),
        normalized_input_digest: digest(
            "blake3:b92fec1b2c910e4c3e59bf1ca9c077d7eff73c20e4bcaeb903da8225fc78a73c",
        ),
        requesting_subject: OidcAuthenticatedSubjectV1 {
            api_version: OidcAuthenticatedSubjectApiVersion::V1,
            issuer: "https://identity.example.test".to_owned(),
            provider: "proof/oidc".to_owned(),
            subject: "human-alice".to_owned(),
        },
        requesting_subject_commitment: digest(
            "blake3:d527780fd72191afe371293b1f2224af4196fb0f7e5ea281831ee2c793e7c3f2",
        ),
        requesting_binding_id: "019e0000-0000-7000-8000-000000000011".to_owned(),
        requesting_binding_record_digest: digest(
            "blake3:07c47a343c09eb7a58fc86a1c0ec07d5e54dbf0b23ce5a1eb3aee946dff6ce39",
        ),
        requesting_principal_id: "019e0000-0000-7000-8000-000000000002".to_owned(),
        authentication_event_id: "019e0000-0000-7000-8000-000000000012".to_owned(),
        authentication_event_digest: digest(
            "blake3:8d9e13564123e941ec953411f221b77088566e2421a757edf4895b627b83ee94",
        ),
        operation: RemoteOperationV1 {
            name: name.to_owned(),
            version: version.to_owned(),
        },
        authenticated_at: "2026-08-23T02:00:00Z"
            .parse::<Timestamp>()
            .expect("fixed actor-context timestamp"),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 41,
            record_digest: digest(
                "blake3:1111111111111111111111111111111111111111111111111111111111111111",
            ),
        },
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
    })
}

#[test]
fn repeated_execution_produces_byte_identical_traces() {
    let oracle = RemoteSemanticOracle::new();
    let context = actor_context(
        "workspace.status",
        "proof.dev/operation/workspace.status/v1",
    );
    let input = json!({});

    let first_root = fresh_dir();
    let first_workspace = initialize_workspace_at(&first_root);
    let first = oracle
        .run(&first_workspace, &input, &context)
        .expect("first trace");
    let replay = oracle
        .run(&first_workspace, &input, &context)
        .expect("replayed trace");
    assert_eq!(first, replay, "replaying the same scenario must not drift");

    let second_root = fresh_dir();
    let second_workspace = initialize_workspace_at(&second_root);
    let second = oracle
        .run(&second_workspace, &input, &context)
        .expect("second trace");
    assert_eq!(
        first, second,
        "an independently initialized Workspace with identical fixture data must reproduce the trace"
    );

    fs::remove_dir_all(&first_root).ok();
    fs::remove_dir_all(&second_root).ok();
}

#[test]
fn workspace_status_produces_a_typed_success_trace() {
    let oracle = RemoteSemanticOracle::new();
    let context = actor_context(
        "workspace.status",
        "proof.dev/operation/workspace.status/v1",
    );

    let root = fresh_dir();
    let workspace = initialize_workspace_at(&root);
    let trace = oracle
        .run(&workspace, &json!({}), &context)
        .expect("workspace status must evaluate");

    assert!(
        trace
            .normalized_input_digest
            .to_string()
            .starts_with("blake3:"),
        "the trace must bind a real normalized-input digest"
    );
    assert_eq!(trace.evaluated_authority_head.sequence, 41);
    assert!(
        matches!(trace.consequence, OracleConsequence::Null),
        "workspace.status/v1 has a `none` effect rule, so no signed consequence is produced"
    );

    match &trace.outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["status"], "initialized");
            assert_eq!(result["workspace_id"], WORKSPACE_ID);
            assert_eq!(result["principal_id"], PRINCIPAL_ID);
        }
        OracleOutcome::StableProblem(problem) => {
            panic!(
                "workspace status must succeed, not produce `{}`",
                problem.code
            );
        }
    }

    fs::remove_dir_all(&root).ok();
}

#[test]
fn rejected_input_produces_a_stable_problem_trace() {
    let oracle = RemoteSemanticOracle::new();
    let context = actor_context("changeset.get", "proof.dev/operation/changeset.get/v2");
    let malformed = json!({
        "api_version": "proof.dev/operation/changeset.get/v2",
        "changeset_id": "not-a-uuid"
    });

    let root = fresh_dir();
    let workspace = initialize_workspace_at(&root);
    let trace = oracle
        .run(&workspace, &malformed, &context)
        .expect("a rejected input must still evaluate into a stable trace");

    match &trace.outcome {
        OracleOutcome::StableProblem(problem) => {
            assert_eq!(problem.code, "proof.input.schema_mismatch");
            assert_eq!(problem.operation.name, "changeset.get");
            assert_eq!(
                problem.operation.version,
                "proof.dev/operation/changeset.get/v2"
            );
        }
        OracleOutcome::TypedResult(_) => {
            panic!("a malformed `changeset_id` must not produce a typed result");
        }
    }
    assert!(
        matches!(trace.consequence, OracleConsequence::ConsequenceDigest(_)),
        "a stable problem must bind its domain-separated consequence digest"
    );

    fs::remove_dir_all(&root).ok();
}

#[test]
fn deterministic_identity_fixture_mirrors_the_retained_issuer_vector() {
    let fixture = IdentityFixtureV1::deterministic();
    let serialized: Value = serde_json::to_value(&fixture.issuer_configuration)
        .expect("the issuer configuration must serialize");

    let retained: Value = serde_json::from_str(include_str!(
        "../../../conformance/v1/collaboration-server/vectors/oidc-issuer-configuration.valid.json"
    ))
    .expect("the retained issuer vector must parse");

    assert_eq!(
        serialized, retained,
        "the deterministic issuer configuration must mirror the retained vector"
    );
    assert!(fixture.oidc_bindings.is_empty());
    assert!(fixture.oidc_bindings_private.is_empty());
}

#[test]
fn deterministic_enrollment_challenge_has_fixed_values() {
    let challenge = OidcEnrollmentChallengeV1::deterministic();
    assert_eq!(
        challenge.api_version,
        "proof.dev/oidc-enrollment-challenge/v1"
    );
    assert_eq!(challenge.state, "019e0000-0000-7000-8000-0000000000a1");
    assert_eq!(challenge.nonce, "019e0000-0000-7000-8000-0000000000a2");
    assert!(!challenge.code_verifier.is_empty());

    let again = OidcEnrollmentChallengeV1::deterministic();
    assert_eq!(
        challenge, again,
        "the enrollment challenge must be reproducible"
    );
}
