//! The complete remote north-star qualification scenario (P-0013 Milestone 3
//! acceptance criterion): two Humans (`H1` requester/initiator and `H2`
//! approver/publisher) plus one Agent (`G` operator) exercised end to end
//! through the in-process axum HTTP server and an isolated PostgreSQL schema.
//!
//! Step order follows the accepted contract §"Exact remote north star":
//! capabilities discovery, deterministic-issuer OIDC sessions for both Humans,
//! role assignment, Delegation and ContextPack issue, the Agent's localized
//! ChangeSet lifecycle under fresh single-use presentations, Human approval
//! with separation-of-duties rejections, idempotent Agent commit, Edition and
//! Environment progression plus Release creation, outbox delivery to private
//! preview with a ready-gated alias, keyed `evidence.export/v2` capture with
//! byte-identical replay, worker assembly to ready, reserved-digest lifecycle
//! reads, exact kind-and-digest artifact acquisition without cross-kind
//! aliases, and the offline `proof-verifier` leg over the fetched logical
//! member map under explicit caller trust.

#![allow(
    clippy::doc_markdown,
    clippy::duration_suboptimal_units,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::authority::{
    AgentPrincipalType, AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
    AuthenticatedCommandKeyUsage, AuthenticatedCommandV1, AuthenticatedInvocationApiVersion,
    AuthenticatedInvocationV1, AuthorityAudience, AuthorityOperation, AuthoritySequence,
    CommandInputApiVersion, CommandInputV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
    LocalEd25519AuthenticatedSubjectV1, PrincipalBindingApiVersion, PrincipalBindingV1,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest};
use proof_delivery::preview::{PreviewAdapter, PreviewBlobV1, PreviewSnapshotV1};
use proof_delivery::worker::{AcknowledgeOutcome, OutboxWorker, WorkerConfig};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::outbox::{OutboxEnqueueV1, enqueue};
use proof_pg::{PgConfig, schema::ALL_TABLE_DDL, wiring::PgRuntime};
use proof_remote::authority::WorkspaceRole as Role;
use proof_remote::identity::{
    AgentSubjectApiVersion, AgentSubjectV1, AuthenticatedActorContextEvidenceApiVersion,
    AuthenticatedActorContextHumanAgentEvidenceV2, AuthenticatedActorContextV2,
    OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1,
    OidcHumanAgentAuthenticationProfile, OidcPrincipalBindingApiVersion,
    OidcPrincipalBindingPrivateApiVersion, OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputApiVersion, OidcSubjectCommitmentInputV1,
    OidcSubjectCommitmentOpeningApiVersion, OidcSubjectCommitmentOpeningV1,
    OperatingBindingReferenceV1, RemoteAuthenticationEventApiVersion, encode_blind,
    public_operation_input_projection_digest, subject_commitment_digest,
};
use proof_remote::oracle::IdentityFixtureV1;
use proof_remote::registry::{
    AgentAuthorizationV1, DelegationEvaluationV1, DelegationResolutionV1, EffectiveConstraintsV1,
    OperatingBindingEvaluationV1, PrincipalStateV1, RemoteApplicationConsequenceApiVersion,
    RemoteAuthorizationDecisionApiVersion, RemoteAuthorizationDecisionV1, RequestedResourcesV1,
};
use proof_remote::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AcceptedArtifactAvailabilityV1,
    AcceptedArtifactDescriptorV1, AcceptedArtifactRefV1, AcceptedArtifactRoleBindingV1,
    ApplicationConsequenceOutcome, ApplicationKeyKind, AuthorityHeadV1, AuthorizationDecisionKind,
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, EvidenceExportResultV2, EvidenceExportStatusKind,
    EvidenceExportStatusV1, REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
    REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT, REMOTE_AUTHORIZATION_PROJECTION_SHA256,
    REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthenticationEventV1, RemoteAuthorityRecordSetApiVersion, RemoteAuthorityRecordSetV1,
    RemoteAuthorityRecordV1, RemoteOperationV1, RemoteReleaseArtifactClosureApiVersion,
    RemoteReleaseArtifactClosureEntrypointsV1, RemoteReleaseArtifactClosureV1,
    VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, VerificationReasonCode, VerificationStatus,
    derive_key_digest,
};
use proof_server::export::{
    ExportWorker, build_bundle_descriptor, build_manifest, evidence_export_get_v1,
    evidence_export_v2,
};
use proof_server::routes::router;
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig};
use proof_verifier::{
    RemoteAuthoritySuffixInput, verify_remote_authority_suffix, verify_remote_evidence_v2,
};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const H1_REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const H2_APPROVER: &str = "019c0000-0000-7000-8000-000000000003";
const G_OPERATOR: &str = "019c0000-0000-7000-8000-000000000004";
const H1_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000005";
const H2_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000006";
const AGENT_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000007";
const H1_SUBJECT: &str = "north-star-h1-requester";
const H2_SUBJECT: &str = "north-star-h2-approver";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000008";
const PRESENTATION_ID: &str = "019c0000-0000-7000-8000-000000000009";
const CHANGES_ET_ID: &str = "019d0000-0000-7000-8000-000000000010";
const EDITION_ID: &str = "019d0000-0000-7000-8000-000000000011";
const RELEASE_ID: &str = "019d0000-0000-7000-8000-000000000020";
const EXPORT_APPLICATION_KEY: &str = "019d0000-0000-7000-8000-000000000041";

const ZERO_DIGEST_STR: &str =
    "blake3:0000000000000000000000000000000000000000000000000000000000000000";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn zero_digest() -> ContentDigest {
    ZERO_DIGEST_STR.parse().unwrap()
}

fn fixed_digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap()).unwrap()
}

fn timestamp_offset(seconds: i64) -> Timestamp {
    let nanos = now_timestamp().unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000;
    Timestamp::from_unix_timestamp_nanos(nanos).unwrap()
}

fn byte_len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    canonicalize(value).unwrap().as_bytes().to_vec()
}

fn domain_digest(context: &str, bytes: &[u8]) -> ContentDigest {
    derive_key_digest(context, bytes)
}

// ---------------------------------------------------------------------------
// Isolated PostgreSQL schema harness.
// ---------------------------------------------------------------------------

struct TestDb {
    state: AppState,
    cleanup: std::sync::Mutex<PgRuntime>,
    schema: String,
}

impl TestDb {
    fn new() -> Self {
        let schema = format!(
            "p0013_north_star_{}_{}",
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        let issuer = IdentityFixtureV1::deterministic().issuer_configuration;
        let config = ServerConfig::new(
            "127.0.0.1:0".parse().unwrap(),
            WS_ID.parse().unwrap(),
            issuer,
            "deployment-secret:proof-oidc-client",
            [0x5a; 32],
            dsn(),
        );
        let state = AppState::new(config);

        let mut runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        {
            let client = runtime.client_mut();
            client
                .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
                .unwrap();
            client
                .batch_execute(&format!("SET search_path TO \"{schema}\""))
                .unwrap();
            for ddl in ALL_TABLE_DDL {
                client.batch_execute(ddl).unwrap();
            }
            client
                .batch_execute(proof_pg::migration::SESSION_BOUNDARY_V2_DDL)
                .unwrap();
            client
                .batch_execute(proof_pg::migration::DELIVERY_STATE_V3_DDL)
                .unwrap();
            client
                .execute(
                    "INSERT INTO migration_head (
                         singleton, version, name, script_digest, phase,
                         actor, tool_version, started_at, verified_at
                     ) VALUES (1, 3, 'delivery-state', $1, 'verified', 'test', 'test', now(), now())",
                    &[&fixed_digest(0x10).to_string()],
                )
                .unwrap();
            client
                .execute(
                    "INSERT INTO workspace_write_head (
                         singleton, workspace_id, migration_version,
                         transaction_sequence, authority_sequence, content_sequence, release_sequence,
                         authority_head_digest, authority_head_sequence,
                         content_head_digest, release_head_digest, policy_head_digest,
                         configuration_head_digest
                     ) VALUES (1, $1, 3, 0, 10, 0, 0, $2, 10, NULL, NULL, NULL, NULL)",
                    &[&WS_ID, &fixed_digest(0xaa).to_string()],
                )
                .unwrap();
        }
        *state.pg.lock().unwrap() = Some(runtime);

        let mut session_runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect session runtime");
        session_runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .unwrap();
        state.sessions.attach(session_runtime).unwrap();

        let mut cleanup = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect cleanup connection");
        cleanup
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .unwrap();

        Self {
            state,
            cleanup: std::sync::Mutex::new(cleanup),
            schema,
        }
    }

    fn seed_fact(
        &self,
        fact_id: &str,
        fact_kind: &str,
        fact_digest: &ContentDigest,
        body: &[u8],
        auth_seq: i64,
    ) {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .execute(
                "INSERT INTO facts (fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at)
                 VALUES ($1, $2, $3, $4, $5, $6, now())",
                &[
                    &fact_id,
                    &WS_ID,
                    &fact_kind,
                    &auth_seq,
                    &fact_digest.to_string(),
                    &body,
                ],
            )
            .unwrap();
    }

    fn seed_artifact(&self, kind: &str, digest_value: &ContentDigest, bytes: &[u8]) {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .execute(
                "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
                 VALUES ($1, $2, $3, clock_timestamp())",
                &[&kind, &digest_value.to_string(), &bytes],
            )
            .unwrap();
    }

    fn seed_authority_root(&self, key_id: &str) {
        let body = canonicalize(&json!({
            "api_version": "proof.dev/workspace-authority-root/v1",
            "workspace_id": WS_ID,
            "authority_key_id": key_id,
        }))
        .unwrap();
        self.seed_fact(
            "workspace_authority_root",
            "workspace_authority_root",
            &fixed_digest(0x20),
            body.as_bytes(),
            0,
        );
    }

    fn delivery_status(&self, event_id: &str, delivery_id: &str, generation: i64) -> String {
        let mut guard = self.cleanup.lock().unwrap();
        guard
            .client_mut()
            .query_one(
                "SELECT status FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
                &[&event_id, &delivery_id, &generation],
            )
            .unwrap()
            .get(0)
    }

    fn read_export_capture_bytes(&self, export_id: &str) -> Vec<u8> {
        let row = self
            .cleanup
            .lock()
            .unwrap()
            .client_mut()
            .query_one(
                "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'evidence_export_capture'",
                &[&format!("evidence_export_capture/{export_id}")],
            )
            .unwrap();
        row.get(0)
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.cleanup.lock() {
            let _ = guard
                .client_mut()
                .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap identity seeding (verified pre-existing Workspace inputs).
// ---------------------------------------------------------------------------

struct HumanIdentity {
    subject_commitment: ContentDigest,
    binding_record_digest: ContentDigest,
}

fn seed_human_identity(
    db: &TestDb,
    principal_id: &'static str,
    binding_id: &'static str,
    subject_label: &'static str,
    auth_seq: i64,
) -> HumanIdentity {
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: subject_label.to_owned(),
    };
    let blind = [0x42_u8; 32];
    let commitment_input = OidcSubjectCommitmentInputV1 {
        api_version: OidcSubjectCommitmentInputApiVersion::V1,
        blind: encode_blind(&blind),
        subject: subject.clone(),
        workspace_id: WS_ID.to_owned(),
    };
    let subject_commitment = subject_commitment_digest(&commitment_input).unwrap();
    let opening = OidcSubjectCommitmentOpeningV1 {
        api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
        commitment: subject_commitment,
        input: commitment_input,
    };

    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();

    let public = OidcPrincipalBindingV1 {
        api_version: OidcPrincipalBindingApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: binding_id.to_owned(),
        principal_id: principal_id.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        issued_by_principal_id: H1_REQUESTER.to_owned(),
        issued_at: now_timestamp(),
        supersedes_binding_id: None,
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: u64::try_from(auth_seq).unwrap(),
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };

    let binding_record_digest = public.binding_record_digest().unwrap();
    let private = OidcPrincipalBindingPrivateV1 {
        api_version: OidcPrincipalBindingPrivateApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: binding_id.to_owned(),
        principal_id: principal_id.to_owned(),
        subject,
        subject_commitment,
        opening,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        binding_record_digest,
    };

    let public_body = canonicalize(&serde_json::to_value(&public).unwrap()).unwrap();
    db.seed_fact(
        &format!("oidc_binding/{binding_id}"),
        "oidc_public_binding",
        &binding_record_digest,
        public_body.as_bytes(),
        auth_seq,
    );
    let private_body = canonicalize(&serde_json::to_value(&private).unwrap()).unwrap();
    let private_digest = ContentDigest::blake3(*blake3::hash(private_body.as_bytes()).as_bytes());
    db.seed_fact(
        &format!("oidc_private_binding/{binding_id}"),
        "oidc_private_binding",
        &private_digest,
        private_body.as_bytes(),
        auth_seq,
    );

    HumanIdentity {
        subject_commitment,
        binding_record_digest,
    }
}

fn seed_principal_status(db: &TestDb, principal_id: &str, agent: bool, auth_seq: i64) {
    let status = proof_remote::authority::RemotePrincipalStatusV2 {
        api_version: proof_remote::authority::RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: principal_id.to_owned(),
        principal_type: if agent {
            proof_remote::authority::RemotePrincipalType::Agent
        } else {
            proof_remote::authority::RemotePrincipalType::Human
        },
        enabled: true,
        reason: "north-star bootstrap".to_owned(),
        recorded_by_principal_id: H1_REQUESTER.to_owned(),
        recorded_by_actor_context_digest: fixed_digest(0x30),
        recorded_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: u64::try_from(auth_seq).unwrap(),
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };
    let body = canonicalize(&serde_json::to_value(&status).unwrap()).unwrap();
    db.seed_fact(
        &format!("principal_status/{principal_id}"),
        "principal_status",
        &RemoteAuthorityRecordV1::principal_status(status).digest(),
        body.as_bytes(),
        auth_seq,
    );
}

fn seed_role_assignment(
    db: &TestDb,
    principal_id: &str,
    role: proof_remote::authority::WorkspaceRole,
    assignment_suffix: u8,
) {
    use proof_remote::authority::{WorkspaceRoleAssignmentApiVersion, WorkspaceRoleAssignmentV1};
    let assignment_id = format!("019c0000-0000-7000-8000-0000000007{assignment_suffix:02}");
    let assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: assignment_id.clone(),
        principal_id: principal_id.to_owned(),
        role,
        assigned_by_principal_id: H1_REQUESTER.to_owned(),
        assigned_by_actor_context_digest: fixed_digest(0x32),
        assigned_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: fixed_digest(0x01),
        },
        authority_sequence: 4,
        previous_authority_record_digest: fixed_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };
    let body = canonicalize(&serde_json::to_value(&assignment).unwrap()).unwrap();
    db.seed_fact(
        &format!("workspace_role_assignment/{assignment_id}"),
        "workspace_role_assignment",
        &RemoteAuthorityRecordV1::workspace_role_assignment(assignment).digest(),
        body.as_bytes(),
        4,
    );
}

fn seed_live_agent_binding(db: &TestDb, agent_provider: &Ed25519SigningProvider) {
    let metadata = agent_provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
    let public_key = Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap();

    let binding = PrincipalBindingV1 {
        api_version: PrincipalBindingApiVersion::V1,
        authority_sequence: AuthoritySequence::new(5).unwrap(),
        previous_authority_record_digest: Some(fixed_digest(0x01)),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        principal_id: G_OPERATOR.parse().unwrap(),
        principal_type: AgentPrincipalType::Agent,
        authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
        algorithm: Ed25519Algorithm::Ed25519,
        public_key,
        key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        enrollment_challenge_digest: fixed_digest(0x33),
        enrollment_envelope_digest: fixed_digest(0x34),
        issued_by_principal_id: H1_REQUESTER.parse().unwrap(),
        issued_at: timestamp_offset(-60),
        not_before: timestamp_offset(-60),
        expires_at: timestamp_offset(86_400),
        supersedes_binding_id: None,
    };
    let body = canonicalize(&serde_json::to_value(&binding).unwrap()).unwrap();
    db.seed_fact(
        &format!("agent_binding/{AGENT_BINDING_ID}"),
        "agent_binding",
        &RemoteAuthorityRecordV1::agent_binding_issue(binding).digest(),
        body.as_bytes(),
        5,
    );
}

// ---------------------------------------------------------------------------
// The retained remote attempt fixture: six roots + nested artifacts.
// ---------------------------------------------------------------------------

#[allow(clippy::type_complexity)]
struct AttemptFixture {
    release_v2_digest: ContentDigest,
    release_v2_bytes: Vec<u8>,
    nested: Vec<(String, ContentDigest)>,
    closure_digest: ContentDigest,
    record_set_digest: ContentDigest,
    actor_evidence_digest: ContentDigest,
    authentication_event_digest: ContentDigest,
    command_input_digest: ContentDigest,
    command_envelope_digest: ContentDigest,
    target_decision_digest: ContentDigest,
    target_consequence_digest: ContentDigest,
    result_digest: ContentDigest,
    release_policy_decision_digest: ContentDigest,
    authority_key_id: String,
    authority_public_b64: String,
    release_key_id: String,
    release_public_b64: String,
}

fn operation(name: &str, version: &str) -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

#[allow(clippy::too_many_lines)]
fn seed_attempt_fixture(db: &TestDb, h1: &HumanIdentity) -> AttemptFixture {
    let authority_provider = Ed25519SigningProvider::from_secret_bytes(&[0x11_u8; 32]);
    let agent_provider = Ed25519SigningProvider::from_secret_bytes(&[0x33_u8; 32]);
    let release_provider = Ed25519SigningProvider::from_secret_bytes(&[0x22_u8; 32]);

    let authority_metadata = authority_provider.metadata().unwrap();
    let authority_public = authority_metadata.public_key;
    let authority_key_id = authority_metadata.key_id.clone();
    let agent_metadata = agent_provider.metadata().unwrap();
    let agent_key_id = agent_metadata.key_id.clone();
    let agent_public_b64 = BASE64.encode(agent_metadata.public_key);
    let release_metadata = release_provider.metadata().unwrap();
    let release_key_id = release_metadata.key_id.clone();
    let release_public_b64 = BASE64.encode(release_metadata.public_key);

    let release_create_op = operation("release.create", "proof.dev/operation/release.create/v2");
    let normalized_input: Map<String, Value> = json!({ "release_name": "preview" })
        .as_object()
        .unwrap()
        .clone();
    let projection_digest = public_operation_input_projection_digest(
        &Value::Object(normalized_input.clone()),
        &release_create_op,
    )
    .unwrap();

    // Nested accepted-artifact bodies.
    let release_v2_value = json!({
        "api_version": "proof.dev/release/v2",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "edition_digest": fixed_digest(0x50).to_string(),
        "kind": "release-v2-north-star",
    });
    let release_v2_bytes = canonical_bytes(&release_v2_value);
    let release_v2_digest = domain_digest(
        ArtifactKind::ReleaseV2.derive_key_context(),
        &release_v2_bytes,
    );

    let proof_value = json!({
        "api_version": "proof.dev/proof-envelope/v1",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "predicate": "release-attestation-north-star",
    });
    let proof_bytes = canonical_bytes(&proof_value);
    let proof_digest = domain_digest(
        ArtifactKind::ProofEnvelopeV1.derive_key_context(),
        &proof_bytes,
    );

    let environment_value = json!({
        "api_version": "proof.dev/environment-config-projection/v2",
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "version": 2,
    });
    let environment_bytes = canonical_bytes(&environment_value);
    let environment_digest = domain_digest("proof:environment-config:v2", &environment_bytes);

    let locale_value = json!({
        "api_version": "proof.dev/object-locale-revision/v1",
        "workspace_id": WS_ID,
        "object_id": "019d0000-0000-7000-8000-000000000025",
        "locale": "en-US",
        "title": "North star snapshot",
    });
    let locale_bytes = canonical_bytes(&locale_value);
    let locale_digest = domain_digest(
        ArtifactKind::ObjectLocaleRevisionV1.derive_key_context(),
        &locale_bytes,
    );

    // Attempt companions: CommandInputV1 and its signed Agent command envelope.
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::ReleaseCreateV2,
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: Some(EXPORT_APPLICATION_KEY.parse().unwrap()),
        normalized_input: normalized_input.clone(),
    };
    let command_input_value = serde_json::to_value(&command_input).unwrap();
    let command_input_canonical = canonicalize(&command_input_value).unwrap();
    let command_input_bytes = command_input_canonical.as_bytes().to_vec();
    let command_input_digest = domain_digest(
        ArtifactKind::CommandV1.derive_key_context(),
        &command_input_bytes,
    );

    let command = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::ReleaseCreateV2,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest: digest(ArtifactKind::CommandV1, &command_input_canonical),
        idempotency_key: Some(EXPORT_APPLICATION_KEY.parse().unwrap()),
        presentation_id: PRESENTATION_ID.parse().unwrap(),
        issued_at: timestamp_offset(-10),
        expires_at: timestamp_offset(120),
    };
    let signed_command = sign_authority_payload(
        AuthorityPayloadProfile::AuthenticatedCommand,
        &command,
        &[&agent_provider],
    )
    .unwrap();
    let envelope_bytes = signed_command.envelope_json.as_bytes().to_vec();
    let command_envelope_digest = signed_command.envelope_digest;

    // Authentication event and actor-context evidence for H1.
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let authentication_event = RemoteAuthenticationEventV1 {
        api_version: RemoteAuthenticationEventApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        authentication_event_id: "019c0000-0000-7000-8000-0000000000ce".to_owned(),
        authentication_method: "oidc-authorization-code-pkce-s256".to_owned(),
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        requesting_subject_commitment: h1.subject_commitment,
        requesting_binding_id: H1_BINDING_ID.to_owned(),
        requesting_binding_record_digest: h1.binding_record_digest,
        requesting_principal_id: H1_REQUESTER.to_owned(),
        authenticated_at: timestamp_offset(-30),
        expires_at: timestamp_offset(3_600),
    };
    let event_bytes = canonical_bytes(&serde_json::to_value(&authentication_event).unwrap());
    let authentication_event_digest =
        domain_digest(REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT, &event_bytes);

    let actor_evidence = AuthenticatedActorContextHumanAgentEvidenceV2 {
        api_version: AuthenticatedActorContextEvidenceApiVersion::V1,
        audience: format!("proof://workspace/{WS_ID}"),
        authentication_profile: OidcHumanAgentAuthenticationProfile::V1,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        public_input_projection_digest: projection_digest,
        requesting_subject_commitment: h1.subject_commitment,
        requesting_binding_id: H1_BINDING_ID.to_owned(),
        requesting_binding_record_digest: h1.binding_record_digest,
        requesting_principal_id: H1_REQUESTER.to_owned(),
        authentication_event_id: authentication_event.authentication_event_id.clone(),
        authentication_event_digest,
        operating_subject: AgentSubjectV1 {
            api_version: AgentSubjectApiVersion::V1,
            provider: "proof/local-ed25519".to_owned(),
            subject: agent_key_id.clone(),
        },
        operating_binding: OperatingBindingReferenceV1 {
            authority_sequence: 2,
            binding_id: AGENT_BINDING_ID.to_owned(),
            record_digest: zero_digest(),
        },
        operating_principal_id: G_OPERATOR.to_owned(),
        delegation_id: DELEGATION_ID.to_owned(),
        operation: release_create_op.clone(),
        command_digest: command_input_digest,
        command_envelope_digest,
        presentation_id: PRESENTATION_ID.to_owned(),
        authenticated_at: timestamp_offset(-5),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 2,
            record_digest: zero_digest(),
        },
        workspace_id: WS_ID.to_owned(),
    };
    let actor_bytes = canonical_bytes(&serde_json::to_value(&actor_evidence).unwrap());
    let actor_evidence_digest = domain_digest(
        AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
        &actor_bytes,
    );

    // Release-artifact closure over the four nested artifacts.
    let ref_of = |kind: &str, digest_value: ContentDigest| AcceptedArtifactRefV1 {
        artifact_kind: kind.to_owned(),
        digest: digest_value,
    };
    let descriptor_of =
        |kind: &str, digest_value: ContentDigest, bytes: &[u8]| AcceptedArtifactDescriptorV1 {
            artifact: ref_of(kind, digest_value),
            availability: AcceptedArtifactAvailabilityV1 {
                state: "included".to_owned(),
                byte_length: byte_len(bytes),
            },
        };
    let closure = RemoteReleaseArtifactClosureV1 {
        api_version: RemoteReleaseArtifactClosureApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        artifact_order: "artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        artifacts: vec![
            descriptor_of(
                "environment_config_v2_projection",
                environment_digest,
                &environment_bytes,
            ),
            descriptor_of("object_locale_revision_v1", locale_digest, &locale_bytes),
            descriptor_of("proof_envelope_v1", proof_digest, &proof_bytes),
            descriptor_of("release_v2", release_v2_digest, &release_v2_bytes),
        ],
        role_binding_order: "role, artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        role_bindings: vec![
            AcceptedArtifactRoleBindingV1 {
                artifact: ref_of("release_v2", release_v2_digest),
                role: "application_effect".to_owned(),
            },
            AcceptedArtifactRoleBindingV1 {
                artifact: ref_of("environment_config_v2_projection", environment_digest),
                role: "environment_config".to_owned(),
            },
            AcceptedArtifactRoleBindingV1 {
                artifact: ref_of("release_v2", release_v2_digest),
                role: "release_manifest".to_owned(),
            },
            AcceptedArtifactRoleBindingV1 {
                artifact: ref_of("proof_envelope_v1", proof_digest),
                role: "release_proof_envelope".to_owned(),
            },
        ],
        entrypoints: RemoteReleaseArtifactClosureEntrypointsV1 {
            target_release_manifest: ref_of("release_v2", release_v2_digest),
            target_release_proof_envelope: ref_of("proof_envelope_v1", proof_digest),
            target_environment_config: ref_of(
                "environment_config_v2_projection",
                environment_digest,
            ),
            application_effect: ref_of("release_v2", release_v2_digest),
            result_derivation:
                "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest"
                    .to_owned(),
        },
    };
    let closure_bytes = canonical_bytes(&serde_json::to_value(&closure).unwrap());
    let closure_digest = domain_digest(
        REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT,
        &closure_bytes,
    );

    // The three-record authority suffix: Agent binding, decision, consequence.
    let suffix_binding = PrincipalBindingV1 {
        api_version: PrincipalBindingApiVersion::V1,
        authority_sequence: AuthoritySequence::new(2).unwrap(),
        previous_authority_record_digest: Some(zero_digest()),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        principal_id: G_OPERATOR.parse().unwrap(),
        principal_type: AgentPrincipalType::Agent,
        authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(
            &Ed25519KeyId::new(agent_key_id.clone()).unwrap(),
        ),
        algorithm: Ed25519Algorithm::Ed25519,
        public_key: Ed25519PublicKey::new(agent_public_b64.clone()).unwrap(),
        key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        enrollment_challenge_digest: fixed_digest(0x35),
        enrollment_envelope_digest: fixed_digest(0x36),
        issued_by_principal_id: H1_REQUESTER.parse().unwrap(),
        issued_at: timestamp_offset(-120),
        not_before: timestamp_offset(-120),
        expires_at: timestamp_offset(86_400),
        supersedes_binding_id: None,
    };
    let signed_binding = proof_remote::sign_remote_authority_record(
        &RemoteAuthorityRecordV1::agent_binding_issue(suffix_binding.clone()),
        &authority_provider,
    )
    .unwrap();
    let binding_record_digest = signed_binding.payload_digest;

    let decision = RemoteAuthorizationDecisionV1 {
        api_version: RemoteAuthorizationDecisionApiVersion::V1,
        authentication_profile: "proof.server/authentication/oidc-human-agent/v1".to_owned(),
        authorization_registry_sha256: REMOTE_AUTHORIZATION_PROJECTION_SHA256.to_owned(),
        operation_registry_sha256: COMPLETE_HTTP_OPERATION_REGISTRY_SHA256.to_owned(),
        authorization_rule: "proof.local/authority/direct/v1".to_owned(),
        workspace_id: WS_ID.to_owned(),
        decision_id: "019e0000-0000-7000-8000-000000000021".to_owned(),
        operation: release_create_op.clone(),
        requested_action: "release:create".to_owned(),
        public_input_projection_digest: projection_digest,
        actor_context_digest: fixed_digest(0x22),
        requesting_principal_id: H1_REQUESTER.to_owned(),
        requesting_binding_id: H1_BINDING_ID.to_owned(),
        requesting_binding_record_digest: h1.binding_record_digest,
        requesting_subject_commitment: h1.subject_commitment,
        agent_authorization: Some(AgentAuthorizationV1 {
            command_digest: command_input_digest,
            command_envelope_digest,
            presentation_id: PRESENTATION_ID.to_owned(),
            presentation_consumed: false,
            operating_principal_id: G_OPERATOR.to_owned(),
            principal_state: PrincipalStateV1 {
                requesting_principal_enabled: true,
                operating_principal_enabled: true,
            },
            binding: OperatingBindingEvaluationV1 {
                active: true,
                binding_id: AGENT_BINDING_ID.to_owned(),
                authority_sequence: 2,
                record_digest: binding_record_digest,
                revocation_record_digest: None,
            },
            delegation: DelegationEvaluationV1 {
                delegation_id: DELEGATION_ID.to_owned(),
                record_digest: None,
                revocation_record_digest: None,
                resolution: DelegationResolutionV1::Resolved,
            },
            policy_profile: "proof.local/authority/direct/v1".to_owned(),
            policy_bundle_digest: fixed_digest(0x23),
            requested_resources: RequestedResourcesV1 {
                workspace_ids: vec![],
                environment_ids: vec![],
                object_ids: vec![],
                schema_ids: vec![],
                locales: vec![],
                changeset_ids: vec![],
                edition_ids: vec![],
                release_ids: vec![RELEASE_ID.to_owned()],
            },
            effective_constraints: EffectiveConstraintsV1 {
                max_objects: 100,
                max_context_bytes: 1_048_576,
                max_edits_per_changeset: 100,
            },
        }),
        role_assignment_digests: vec![],
        requested_resources_digest: zero_digest(),
        policy_bundle_digest: zero_digest(),
        environment_config_digest: None,
        decision: AuthorizationDecisionKind::Allow,
        public_code: None,
        reason_code: "proof.authorization.allowed".to_owned(),
        evaluated_at: timestamp_offset(-5),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 2,
            record_digest: binding_record_digest,
        },
        authority_sequence: 3,
        previous_authority_record_digest: binding_record_digest,
        authority_key_id: authority_key_id.clone(),
    };
    let signed_decision = proof_remote::sign_remote_authority_record(
        &RemoteAuthorityRecordV1::authorization_decision(decision.clone()),
        &authority_provider,
    )
    .unwrap();
    let decision_record_digest = signed_decision.payload_digest;

    let result_digest = fixed_digest(0x82);
    let consequence = RemoteApplicationConsequenceV1 {
        api_version: RemoteApplicationConsequenceApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        consequence_id: "019e0000-0000-7000-8000-000000000022".to_owned(),
        decision_id: decision.decision_id.clone(),
        decision_digest: decision_record_digest,
        public_input_projection_digest: projection_digest,
        operation: release_create_op.clone(),
        operation_registry_sha256: COMPLETE_HTTP_OPERATION_REGISTRY_SHA256.to_owned(),
        outcome: ApplicationConsequenceOutcome::Success,
        application_key_kind: ApplicationKeyKind::RequiredUuidV7,
        application_key: Some(EXPORT_APPLICATION_KEY.to_owned()),
        result_digest: Some(result_digest),
        prior_result_digest: None,
        application_effect_digest: Some(release_v2_digest),
        application_effect_authority_head: None,
        problem_code: None,
        recorded_at: timestamp_offset(-4),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 3,
            record_digest: decision_record_digest,
        },
        authority_sequence: 4,
        previous_authority_record_digest: decision_record_digest,
        authority_key_id: authority_key_id.clone(),
    };
    let signed_consequence = proof_remote::sign_remote_authority_record(
        &RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
        &authority_provider,
    )
    .unwrap();
    let consequence_record_digest = signed_consequence.payload_digest;

    let record_set = RemoteAuthorityRecordSetV1 {
        api_version: RemoteAuthorityRecordSetApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        base_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: zero_digest(),
        },
        record_order: "decoded authority_sequence ascending and contiguous".to_owned(),
        records: vec![
            signed_binding.envelope,
            signed_decision.envelope,
            signed_consequence.envelope,
        ],
        included_head: AuthorityHeadV1 {
            sequence: 4,
            record_digest: consequence_record_digest,
        },
    };
    let record_set_bytes = canonical_bytes(&serde_json::to_value(&record_set).unwrap());
    let record_set_digest = domain_digest(
        REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
        &record_set_bytes,
    );

    // Persist the six roots, the four nested artifacts, and the material fact.
    db.seed_artifact("release-artifact-closure", &closure_digest, &closure_bytes);
    db.seed_artifact("authority-fact", &record_set_digest, &record_set_bytes);
    db.seed_artifact(
        "remote-actor-evidence",
        &actor_evidence_digest,
        &actor_bytes,
    );
    db.seed_artifact(
        "remote-authentication-event",
        &authentication_event_digest,
        &event_bytes,
    );
    db.seed_artifact(
        "remote-command-input",
        &command_input_digest,
        &command_input_bytes,
    );
    db.seed_artifact(
        "remote-authenticated-command-envelope",
        &command_envelope_digest,
        &envelope_bytes,
    );
    db.seed_artifact("release_v2", &release_v2_digest, &release_v2_bytes);
    db.seed_artifact("proof_envelope_v1", &proof_digest, &proof_bytes);
    db.seed_artifact(
        "environment_config_v2_projection",
        &environment_digest,
        &environment_bytes,
    );
    db.seed_artifact("object_locale_revision_v1", &locale_digest, &locale_bytes);

    let release_policy_decision_digest = fixed_digest(0x83);
    let material = json!({
        "api_version": "proof.dev/release-export-material/v1",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "release_digest": release_v2_digest.to_string(),
        "release_artifact_closure_digest": closure_digest.to_string(),
        "authority_record_set_digest": record_set_digest.to_string(),
        "actor_context_evidence_digest": actor_evidence_digest.to_string(),
        "authentication_event_digest": authentication_event_digest.to_string(),
        "command_input_digest": command_input_digest.to_string(),
        "authenticated_command_envelope_digest": command_envelope_digest.to_string(),
        "target_decision_digest": decision_record_digest.to_string(),
        "target_consequence_digest": consequence_record_digest.to_string(),
        "result_digest": result_digest.to_string(),
        "release_policy_decision_digest": release_policy_decision_digest.to_string(),
    });
    let material_bytes = canonical_bytes(&material);
    db.seed_fact(
        &format!("release_export_material/{RELEASE_ID}"),
        "release_export_material",
        &fixed_digest(0x90),
        &material_bytes,
        1,
    );

    AttemptFixture {
        release_v2_digest,
        release_v2_bytes,
        nested: vec![
            (
                "environment_config_v2_projection".to_owned(),
                environment_digest,
            ),
            ("object_locale_revision_v1".to_owned(), locale_digest),
            ("proof_envelope_v1".to_owned(), proof_digest),
            ("release_v2".to_owned(), release_v2_digest),
        ],
        closure_digest,
        record_set_digest,
        actor_evidence_digest,
        authentication_event_digest,
        command_input_digest,
        command_envelope_digest,
        target_decision_digest: decision_record_digest,
        target_consequence_digest: consequence_record_digest,
        result_digest,
        release_policy_decision_digest,
        authority_key_id,
        authority_public_b64: BASE64.encode(authority_public),
        release_key_id,
        release_public_b64,
    }
}

// ---------------------------------------------------------------------------
// In-process HTTP harness.
// ---------------------------------------------------------------------------

fn query_param(url: &str, key: &str) -> String {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return v.to_owned();
        }
    }
    panic!("missing query parameter {key} in {url}");
}

fn set_cookie_value(resp: &axum::response::Response, name: &str) -> String {
    let values: Vec<_> = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    for value in values {
        let pair = value.split(';').next().unwrap_or("");
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return v.to_owned();
        }
    }
    panic!("missing set-cookie {name}");
}

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body is readable");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

async fn response_bytes(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body is readable")
        .to_vec()
}

struct HumanSession {
    cookie: String,
    csrf: String,
}

const PKCE_VERIFIER: &str = "deterministic-pkce-verifier-0000000000000000000000000000000000000000";

/// Acquires one live OIDC session through the deterministic-issuer BFF path:
/// login redirect, provider-issued one-use code, callback exchange, and the
/// `GET /api/v1/session` CSRF acquisition route.
async fn login_human(
    app: &axum::Router,
    issuer: &proof_server::issuer::DeterministicIssuer,
    subject: &str,
    expected_principal: &str,
) -> HumanSession {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/oidc/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let authorize_url = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("login carries a Location header")
        .to_owned();
    let state = query_param(&authorize_url, "state");
    let nonce = query_param(&authorize_url, "nonce");

    let redirect_uri = issuer.config().redirect_uri.clone();
    let code = issuer
        .issue_code(&redirect_uri, PKCE_VERIFIER, &nonce, subject)
        .expect("issuer mints the code")
        .code;
    let issuer_uri = issuer.issuer().to_owned();

    let callback_uri = format!("/auth/oidc/callback?code={code}&state={state}&iss={issuer_uri}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(callback_uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let session_id = set_cookie_value(&resp, "__Host-Http-Proof-Session");
    let cookie = format!("__Host-Http-Proof-Session={session_id}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/session")
                .header(header::COOKIE, cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let projection = response_json(resp).await;
    assert_eq!(projection["principal_id"], expected_principal);
    let csrf = projection["csrf_token"]
        .as_str()
        .expect("session projection carries a CSRF token")
        .to_owned();
    HumanSession { cookie, csrf }
}

fn operation_request_body(operation: &RemoteOperationV1, input: &Value) -> Value {
    json!({
        "api_version": "proof.dev/http-human-operation-request/v1",
        "workspace_id": WS_ID,
        "operation": operation,
        "input": input,
    })
}

async fn post_operation(
    app: &axum::Router,
    route_prefix: &str,
    name: &str,
    major: &str,
    session: Option<&HumanSession>,
    body: &Value,
) -> axum::response::Response {
    let uri = format!("/api/v1/{route_prefix}/operations/{name}/{major}");
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "proof.example.test")
        .header(header::ORIGIN, "https://proof.example.test");
    if let Some(session) = session {
        builder = builder
            .header("proof-csrf", session.csrf.clone())
            .header(header::COOKIE, session.cookie.clone());
    }
    app.clone()
        .oneshot(
            builder
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Asserts one successful dispatch envelope and returns the whole envelope.
async fn expect_success(resp: axum::response::Response, label: &str) -> Value {
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{label} must succeed over HTTP"
    );
    let envelope = response_json(resp).await;
    assert_eq!(
        envelope["api_version"],
        "proof.dev/http-operation-result/v1"
    );
    assert!(envelope["committed_anchor"].is_object());
    envelope
}

/// Asserts one RFC 9457 Problem rejection with the exact frozen Problem code.
async fn expect_problem(resp: axum::response::Response, expected_code: &str, label: &str) -> Value {
    let status = resp.status();
    let problem = response_json(resp).await;
    assert_eq!(
        problem["code"], expected_code,
        "{label} must fail with {expected_code}"
    );
    assert_eq!(
        u16::try_from(problem["status"].as_u64().unwrap()).unwrap(),
        status.as_u16(),
        "{label} Problem status must match the HTTP status"
    );
    problem
}

// ---------------------------------------------------------------------------
// Dual-auth Agent invocation builder (fresh single-use presentation each call).
// ---------------------------------------------------------------------------

fn build_agent_invocation(
    agent_provider: &Ed25519SigningProvider,
    authority_operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
) -> AuthenticatedInvocationV1 {
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: authority_operation,
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: normalized_input
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(|key| key.parse().unwrap()),
        normalized_input,
    };
    let command_input_value = serde_json::to_value(&command_input).unwrap();
    let canonical_command = canonicalize(&command_input_value).unwrap();
    let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);

    let payload = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: authority_operation,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: H1_REQUESTER.parse().unwrap(),
        operating_principal_id: G_OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest,
        idempotency_key: command_input.idempotency_key,
        presentation_id: uuid::Uuid::now_v7().to_string().parse().unwrap(),
        issued_at: timestamp_offset(-10),
        expires_at: timestamp_offset(120),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::AuthenticatedCommand,
        &payload,
        &[agent_provider],
    )
    .unwrap();
    AuthenticatedInvocationV1 {
        api_version: AuthenticatedInvocationApiVersion::V1,
        command_input,
        authentication: AuthenticatedCommandEnvelopeJson::new(signed.envelope_json).unwrap(),
    }
}

async fn run_agent_operation(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
    authority_operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
    label: &str,
) -> Value {
    let invocation = build_agent_invocation(agent_provider, authority_operation, normalized_input);
    let body = json!({
        "api_version": "proof.dev/http-agent-operation-request/v1",
        "operation": {
            "name": authority_operation.name(),
            "version": authority_operation.version()
        },
        "invocation": serde_json::to_value(&invocation).unwrap()
    });
    let resp = post_operation(
        app,
        "agent",
        authority_operation.name(),
        authority_operation.version().rsplit('/').next().unwrap(),
        Some(h1),
        &body,
    )
    .await;
    expect_success(resp, label).await
}

fn input_object(value: &Value) -> Map<String, Value> {
    value.as_object().expect("input object").clone()
}

// ---------------------------------------------------------------------------
// Typed export-surface helpers (the HTTP envelope carries only the effect
// digest; the typed public entrypoints expose the exact result/status bytes).
// ---------------------------------------------------------------------------

fn h2_session_record() -> SessionRecord {
    SessionRecord {
        session_id_hash: [0_u8; 32],
        workspace_id: WS_ID.to_owned(),
        principal_id: H2_APPROVER.to_owned(),
        binding_id: H2_BINDING_ID.to_owned(),
        authentication_event_id: "019c0000-0000-7000-8000-0000000000c2".to_owned(),
        csrf_digest: [0_u8; 32],
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        absolute_expiry: SystemTime::now() + Duration::from_secs(3_600),
    }
}

fn h2_export_context(
    db: &TestDb,
    operation: &RemoteOperationV1,
    input: &Value,
) -> AuthenticatedActorContextV2 {
    let mut context =
        proof_server::authz::authenticate_human_session(&db.state, &h2_session_record())
            .expect("H2 export context authenticates");
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(input, operation).unwrap();
    if let AuthenticatedActorContextV2::Human(human) = &mut context {
        human.operation = operation.clone();
        human.normalized_input_digest = normalized_input_digest;
    }
    context
}

fn evidence_export_operation() -> RemoteOperationV1 {
    operation("evidence.export", "proof.dev/operation/evidence.export/v2")
}

fn evidence_export_get_operation() -> RemoteOperationV1 {
    operation(
        "evidence.export.get",
        "proof.dev/operation/evidence.export.get/v1",
    )
}

fn export_input(release_digest: &ContentDigest) -> Value {
    json!({
        "idempotency_key": EXPORT_APPLICATION_KEY,
        "release_id": RELEASE_ID,
        "release_digest": release_digest.to_string(),
    })
}

fn typed_export_create(db: &TestDb, input: &Value) -> EvidenceExportResultV2 {
    let op = evidence_export_operation();
    let context = h2_export_context(db, &op, input);
    let decision = proof_server::authz::evaluate_authorization(&db.state, &context, input)
        .expect("export create decision");
    evidence_export_v2(&db.state, &op, input, &context, &decision).expect("typed export create")
}

fn typed_export_status(db: &TestDb, export_id: &str) -> EvidenceExportStatusV1 {
    let op = evidence_export_get_operation();
    let input = json!({ "export_id": export_id });
    let context = h2_export_context(db, &op, &input);
    let decision = proof_server::authz::evaluate_authorization(&db.state, &context, &input)
        .expect("export get decision");
    evidence_export_get_v1(&db.state, &op, &input, &context, &decision)
        .expect("typed export status")
}

// ---------------------------------------------------------------------------
// Caller trust policy and verifier input (remote_impl.rs fixture style).
// ---------------------------------------------------------------------------

struct TrustInputs {
    input: proof_remote::RemoteVerifierInputV2,
}

fn trusted_key(key_id: &str, public_b64: &str) -> Value {
    json!({
        "key_id": key_id,
        "public_key": public_b64,
        "not_before": "2026-08-01T00:00:00Z",
        "not_after": null,
        "revoked_at": null,
    })
}

fn head_value(sequence: u64, digest_str: &str) -> Value {
    json!({ "sequence": sequence, "record_digest": digest_str })
}

fn build_trust_inputs(fixture: &AttemptFixture) -> TrustInputs {
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let policy_value = json!({
        "api_version": "proof.dev/verification-trust-policy/v2",
        "workspace_id": WS_ID,
        "registry_resolution": {
            "profile": "proof.verifier/collaboration-registry/v1",
            "source": "verifier-built-in-closed-hash-to-rfc8785-document-table",
            "unknown_hash_result": "Invalid",
            "hash_mismatch_result": "Invalid"
        },
        "authority": {
            "initial_root": trusted_key(&fixture.authority_key_id, &fixture.authority_public_b64),
            "initial_head": head_value(1, ZERO_DIGEST_STR),
            "accepted_authorization_registry_hashes": [REMOTE_AUTHORIZATION_PROJECTION_SHA256],
            "accepted_operation_registry_hashes": [COMPLETE_HTTP_OPERATION_REGISTRY_SHA256],
            "accepted_policy_bundles": [
                {"policy_profile": "proof.local/authority/direct/v1", "policy_bundle_digest": fixed_digest(0x23).to_string()}
            ],
            "checkpoint_requirement": "internal_prefix_only",
            "compromise_cutoff": null
        },
        "release": {
            "trusted_signers": [trusted_key(&fixture.release_key_id, &fixture.release_public_b64)],
            "accepted_predicate_types": ["urn:proof:attestation:release:v2"],
            "accepted_policy_profiles": [
                {"policy_profile": "proof.local/release-policy/v1", "environment_config_digest": ZERO_DIGEST_STR}
            ]
        },
        "remote_identity": {
            "accepted_oidc_issuer_configuration_digests": [issuer_configuration_digest.to_string()]
        },
        "disclosure": { "requesting_subject_opening": "optional" },
        "limits": {
            "max_verifier_input_bytes": 268_435_456,
            "max_manifest_bytes": 4_194_304,
            "max_artifacts": 4096,
            "max_authority_records": 512,
            "max_artifact_bytes": 4_194_304,
            "max_total_bytes": 268_435_456,
            "max_json_depth": 128
        }
    });
    let policy_canonical = canonical_bytes(&policy_value);
    let trust_policy_digest =
        domain_digest(VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, &policy_canonical);

    let input_json = json!({
        "type": "RemoteVerifierInputV2",
        "api_version": "proof.dev/remote-verifier-input/v2",
        "verification_trust_policy": policy_value,
        "trust_policy_digest": trust_policy_digest.to_string(),
        "subject_openings": [],
        "authority_checkpoint": null,
        "environment_release_checkpoint": null,
        "external_artifacts": [],
        "bundle_hints_are_authority": false,
        "network_access": false,
        "database_access": false,
        "session_access": false,
        "private_key_count": 0,
        "credential_count": 0
    });
    let input: proof_remote::RemoteVerifierInputV2 =
        serde_json::from_value(input_json).expect("verifier input builds");
    TrustInputs { input }
}

// ---------------------------------------------------------------------------
// Step 1: capabilities discovery is a public read.
// ---------------------------------------------------------------------------

async fn step_01_capabilities(app: &axum::Router) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let capabilities = response_json(resp).await;
    assert_eq!(capabilities["route_count"], 9);
    assert_eq!(capabilities["human_operation_count"], 23);
    assert_eq!(capabilities["agent_operation_count"], 14);
}

// ---------------------------------------------------------------------------
// Step 3: workspace init and role assignment through the live route.
// ---------------------------------------------------------------------------

async fn step_03_workspace_init_and_role_assignment(app: &axum::Router, h1: &HumanSession) {
    let op = human_operation(
        "workspace-role.assign",
        "proof.dev/operation/workspace-role.assign/v1",
    );
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": H2_APPROVER,
        "role": "content.publisher",
        "assignment_id": "019d0000-0000-7000-8000-0000000000aa",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000ab",
    });
    let resp = post_operation(
        app,
        "human",
        op.name.as_str(),
        "v1",
        Some(h1),
        &operation_request_body(&op, &input),
    )
    .await;
    let envelope = expect_success(resp, "H1 assigns content.publisher to H2").await;
    assert_eq!(envelope["result"]["outcome"], "success");
    assert!(envelope["result"]["application_effect_digest"].is_string());
}

// ---------------------------------------------------------------------------
// Step 4: Delegation H1->G and the ContextPack.
// ---------------------------------------------------------------------------

async fn step_04_delegation_and_context_pack(app: &axum::Router, h1: &HumanSession) {
    let delegation_op = human_operation(
        "delegation.issue",
        "proof.dev/operation/delegation.issue/v2",
    );
    let delegation_input = json!({
        "workspace_id": WS_ID,
        "delegation_id": DELEGATION_ID,
        "principal_id": G_OPERATOR,
        "idempotency_key": "019d0000-0000-7000-8000-0000000000b1",
    });
    let resp = post_operation(
        app,
        "human",
        delegation_op.name.as_str(),
        "v2",
        Some(h1),
        &operation_request_body(&delegation_op, &delegation_input),
    )
    .await;
    let envelope = expect_success(resp, "H1 issues Delegation H1->G").await;
    assert_eq!(envelope["result"]["outcome"], "success");

    let context_op = human_operation("context.build", "proof.dev/operation/context.build/v2");
    let context_input = json!({
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000b2",
    });
    let resp = post_operation(
        app,
        "human",
        context_op.name.as_str(),
        "v2",
        Some(h1),
        &operation_request_body(&context_op, &context_input),
    )
    .await;
    let envelope = expect_success(resp, "H1 builds the ContextPack").await;
    assert_eq!(envelope["result"]["outcome"], "success");
}

// ---------------------------------------------------------------------------
// Step 5: G proposes edits, validates, and submits over dual authentication.
// ---------------------------------------------------------------------------

async fn step_05_agent_changeset_lifecycle(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
) {
    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCreateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.create/v2",
            "changeset_id": CHANGES_ET_ID,
            "context_pack_digest": fixed_digest(0x60).to_string(),
            "context_pack_id": "019d0000-0000-7000-8000-000000000061",
            "created_at": timestamp_offset(0).to_string(),
            "idempotency_key": "019d0000-0000-7000-8000-000000000062",
            "intent": "localized north-star ChangeSet",
            "resource_intent_digest": fixed_digest(0x63).to_string(),
            "resource_intent_id": "019d0000-0000-7000-8000-000000000064",
        })),
        "G creates the localized ChangeSet",
    )
    .await;
    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetAddV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.add/v2",
            "changeset_id": CHANGES_ET_ID,
            "edits": [{
                "api_version": "proof.dev/edit/v2",
                "content": {"title": "North star snapshot"},
                "expected_source": {
                    "digest": fixed_digest(0x65).to_string(),
                    "revision": 1,
                    "schema_id": "localized-object-v2",
                    "schema_version": 2,
                },
                "expected_target": null,
                "kind": "object.locale.put",
                "locale": PREVIEW_LOCALE,
                "object_id": PREVIEW_OBJECT_ID,
                "repair_of_validation_result_digest": null,
                "supersedes_edit_id": null,
            }],
            "idempotency_key": "019d0000-0000-7000-8000-000000000066",
        })),
        "G appends the localized object edit",
    )
    .await;
    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetValidateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.validate/v2",
            "changeset_id": CHANGES_ET_ID,
        })),
        "G validates successfully",
    )
    .await;
    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetSubmitV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.submit/v2",
            "changeset_id": CHANGES_ET_ID,
            "submitted_at": timestamp_offset(0).to_string(),
        })),
        "G submits the sealed lineage",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Step 6: separation-of-duties rejections for the Human-only approval.
// ---------------------------------------------------------------------------

async fn step_06_separation_of_duties_rejections(
    app: &axum::Router,
    h1: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
) {
    let approve_name = "changeset.approve";
    let approve_major = "v3";

    // G cannot approve: the approval row does not exist on the Agent
    // projection, so the route cross-check rejects before execution.
    let invocation = build_agent_invocation(
        agent_provider,
        AuthorityOperation::ChangesetGetV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/changeset.get/v2",
            "changeset_id": CHANGES_ET_ID,
        })),
    );
    let agent_body = json!({
        "api_version": "proof.dev/http-agent-operation-request/v1",
        "operation": {"name": approve_name, "version": "proof.dev/operation/changeset.approve/v3"},
        "invocation": serde_json::to_value(&invocation).unwrap()
    });
    let resp = post_operation(
        app,
        "agent",
        approve_name,
        approve_major,
        Some(h1),
        &agent_body,
    )
    .await;
    expect_problem(
        resp,
        "proof.input.schema_mismatch",
        "G attempts Human-only approval",
    )
    .await;

    // The initiating Human cannot approve either: H1 lacks content.reviewer,
    // so the decision denies and commits the signed denial alone.
    let op = human_operation(approve_name, "proof.dev/operation/changeset.approve/v3");
    let input = json!({
        "workspace_id": WS_ID,
        "changeset_id": CHANGES_ET_ID,
        "approval_id": "019d0000-0000-7000-8000-0000000000c9",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000ca",
    });
    let resp = post_operation(
        app,
        "human",
        approve_name,
        approve_major,
        Some(h1),
        &operation_request_body(&op, &input),
    )
    .await;
    expect_problem(
        resp,
        "proof.authorization.denied",
        "initiator H1 cannot approve",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Step 7: H2 approves; G commits idempotently; Edition, Environment, Release.
// ---------------------------------------------------------------------------

async fn step_07_approval_idempotent_commit_edition_environment_release(
    app: &axum::Router,
    h1: &HumanSession,
    h2: &HumanSession,
    agent_provider: &Ed25519SigningProvider,
) {
    let approve_op = human_operation(
        "changeset.approve",
        "proof.dev/operation/changeset.approve/v3",
    );
    let approve_input = json!({
        "workspace_id": WS_ID,
        "changeset_id": CHANGES_ET_ID,
        "approval_id": "019d0000-0000-7000-8000-0000000000d1",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d2",
    });
    let resp = post_operation(
        app,
        "human",
        approve_op.name.as_str(),
        "v3",
        Some(h2),
        &operation_request_body(&approve_op, &approve_input),
    )
    .await;
    let envelope = expect_success(resp, "H2 records the causal approval").await;
    assert_eq!(envelope["result"]["outcome"], "success");

    let commit_input = json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": CHANGES_ET_ID,
        "committed_at": timestamp_offset(0).to_string(),
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d3",
    });
    let first_commit = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCommitV2,
        input_object(&commit_input),
        "G commits the approved ChangeSet",
    )
    .await;
    assert_eq!(first_commit["result"]["outcome"], "success");
    let committed_digest = first_commit["result"]["result_digest"].clone();

    let replay_commit = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ChangesetCommitV2,
        input_object(&commit_input),
        "replayed commit returns identical bytes",
    )
    .await;
    assert_eq!(replay_commit["result"]["outcome"], "idempotent-replay");
    assert_eq!(replay_commit["result"]["result_digest"], committed_digest);
    assert_eq!(
        replay_commit["result"]["prior_result_digest"],
        committed_digest
    );

    run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::EditionCreateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/edition.create/v2",
            "changeset_id": CHANGES_ET_ID,
            "created_at": timestamp_offset(0).to_string(),
            "edition_id": EDITION_ID,
            "idempotency_key": "019d0000-0000-7000-8000-0000000000d4",
            "resulting_state_digest": fixed_digest(0x67).to_string(),
        })),
        "G creates the exact Edition",
    )
    .await;

    let propose_op = human_operation(
        "environment-config.propose",
        "proof.dev/operation/environment-config.propose/v2",
    );
    let propose_input = json!({
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "configuration_version": 2,
        "proposal_id": "019d0000-0000-7000-8000-0000000000d5",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d6",
    });
    let resp = post_operation(
        app,
        "human",
        propose_op.name.as_str(),
        "v2",
        Some(h1),
        &operation_request_body(&propose_op, &propose_input),
    )
    .await;
    expect_success(resp, "H1 proposes the preview Environment configuration").await;

    let activate_op = human_operation(
        "environment-config.activate",
        "proof.dev/operation/environment-config.activate/v2",
    );
    let activate_input = json!({
        "workspace_id": WS_ID,
        "environment_id": "preview",
        "activation_id": "019d0000-0000-7000-8000-0000000000d7",
        "proposal_id": "019d0000-0000-7000-8000-0000000000d5",
        "idempotency_key": "019d0000-0000-7000-8000-0000000000d8",
    });
    let resp = post_operation(
        app,
        "human",
        activate_op.name.as_str(),
        "v2",
        Some(h2),
        &operation_request_body(&activate_op, &activate_input),
    )
    .await;
    expect_success(resp, "distinct H2 activates the proposal").await;

    let release_create = run_agent_operation(
        app,
        h1,
        agent_provider,
        AuthorityOperation::ReleaseCreateV2,
        input_object(&json!({
            "api_version": "proof.dev/operation/release.create/v2",
            "edition_id": EDITION_ID,
            "environment_id": "preview",
            "expected_base_release_id": "019d0000-0000-7000-8000-0000000000da",
            "idempotency_key": "019d0000-0000-7000-8000-0000000000d9",
            "proof_id": "019d0000-0000-7000-8000-0000000000db",
            "release_id": RELEASE_ID,
            "released_at": timestamp_offset(0).to_string(),
        })),
        "G invokes release.create/v2 with an idempotency key",
    )
    .await;
    assert_eq!(release_create["result"]["outcome"], "success");
    assert!(release_create["result"]["result_digest"].is_string());

    let release_get_op = human_operation("release.get", "proof.dev/operation/release.get/v2");
    let release_get_input = json!({ "workspace_id": WS_ID, "release_id": RELEASE_ID });
    let resp = post_operation(
        app,
        "human",
        release_get_op.name.as_str(),
        "v2",
        Some(h2),
        &operation_request_body(&release_get_op, &release_get_input),
    )
    .await;
    let envelope = expect_success(resp, "H2 reads back the Release").await;
    assert_eq!(envelope["result"]["outcome"], "success");
}

// ---------------------------------------------------------------------------
// Step 8: outbox advance to delivered preview plus the ready-gated alias.
//
// The synchronous PostgreSQL driver cannot run inside the tokio runtime, so
// the scenario alternates small async route segments with synchronous
// storage/worker phases on the outer thread.
// ---------------------------------------------------------------------------

const OUTBOX_EVENT_ID: &str = "019d0000-0000-7000-8000-0000000000e1";
const OUTBOX_DELIVERY_ID: &str = "019d0000-0000-7000-8000-0000000000e2";
const PREVIEW_OBJECT_ID: &str = "019d0000-0000-7000-8000-000000000025";
const PREVIEW_LOCALE: &str = "en-US";

fn human_operation(name: &str, version: &str) -> RemoteOperationV1 {
    operation(name, version)
}

fn enqueue_preview_release_event(db: &TestDb) {
    let event = OutboxEnqueueV1 {
        event_id: OUTBOX_EVENT_ID.to_owned(),
        workspace_id: WS_ID.parse().unwrap(),
        workspace_transaction_sequence: 1,
        ordinal: 0,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: format!("preview:{RELEASE_ID}"),
        stream_sequence: 1,
        effect_digest: fixture_release_effect_digest(),
        payload_digest: Some(fixed_digest(0x33)),
        artifact_reference: None,
        destination_configuration_version: 1,
        destination_configuration_digest: fixed_digest(0x44),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: now_timestamp(),
    };
    let mut cleanup = db.cleanup.lock().unwrap();
    let mut transaction = cleanup.client_mut().transaction().unwrap();
    enqueue(&mut transaction, &event).expect("enqueue preview.release/v1 outbox event");
    transaction
        .execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             ) VALUES ($1, $2, 1, 'pending', NULL, 0, NULL, NULL, NULL,
                       clock_timestamp(), clock_timestamp())",
            &[&OUTBOX_EVENT_ID, &OUTBOX_DELIVERY_ID],
        )
        .unwrap();
    transaction.commit().unwrap();
}

fn fixture_release_effect_digest() -> ContentDigest {
    derive_key_digest("proof:test-effect:v1", RELEASE_ID.as_bytes())
}

struct PreviewFiles {
    environment: String,
    root: std::path::PathBuf,
    rendition_digest: ContentDigest,
    body_value: Value,
}

/// Materializes the exact Release snapshot projection without its ready
/// marker; the marker is written last so the alias resolves only after ready.
fn stage_preview_files(release_digest: &ContentDigest) -> PreviewFiles {
    let environment = format!("ns_preview_{}", std::process::id());
    let root = std::env::temp_dir()
        .join("proof-preview")
        .join(&environment);
    let release_root = root.join(RELEASE_ID);
    std::fs::create_dir_all(release_root.join("objects").join(PREVIEW_OBJECT_ID)).unwrap();

    let body_value = json!({ "title": "North star preview snapshot", "value": 7 });
    let body_bytes = serde_json::to_vec(&body_value).unwrap();
    let rendition_digest = ContentDigest::blake3(*blake3::hash(&body_bytes).as_bytes());
    let relative_path = format!("objects/{PREVIEW_OBJECT_ID}/{PREVIEW_LOCALE}.json");
    std::fs::write(release_root.join(&relative_path), &body_bytes).unwrap();

    let manifest = json!({
        "release_id": RELEASE_ID,
        "release_digest": release_digest.to_string(),
        "edition_digest": fixed_digest(0x88).to_string(),
        "objects": [{
            "object_id": PREVIEW_OBJECT_ID,
            "locale": PREVIEW_LOCALE,
            "rendition_digest": rendition_digest.to_string(),
            "path": relative_path,
        }],
    });
    std::fs::write(
        release_root.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();

    PreviewFiles {
        environment,
        root,
        rendition_digest,
        body_value,
    }
}

async fn preview_route_get(app: &axum::Router, environment: &str) -> axum::response::Response {
    let uri = format!(
        "/preview/{environment}/releases/{RELEASE_ID}/objects/{PREVIEW_OBJECT_ID}/locales/{PREVIEW_LOCALE}"
    );
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn hex_of(digest_value: &ContentDigest) -> String {
    digest_value
        .to_string()
        .strip_prefix("blake3:")
        .unwrap_or(&digest_value.to_string())
        .to_owned()
}

// ---------------------------------------------------------------------------
// Step 10 helpers: exact kind-and-digest artifact acquisition over HTTP.
// ---------------------------------------------------------------------------

async fn fetch_artifact(
    app: &axum::Router,
    export_id: &str,
    artifact_kind: &str,
    digest_value: &ContentDigest,
) -> axum::response::Response {
    let uri =
        format!("/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest_value}");
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn fetch_ok_artifact(
    app: &axum::Router,
    export_id: &str,
    artifact_kind: &str,
    digest_value: &ContentDigest,
) -> Vec<u8> {
    let resp = fetch_artifact(app, export_id, artifact_kind, digest_value).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "artifact {artifact_kind} must resolve by its exact triple"
    );
    response_bytes(resp).await
}

fn root_member_path(kind: &str) -> &'static str {
    match kind {
        "release-artifact-closure" => "content/release-closure.json",
        "authority-fact" => "authority/facts.json",
        "remote-actor-evidence" => "actor/context-evidence.json",
        "remote-authentication-event" => "authentication/event.json",
        "remote-command-input" => "attempt/command-input.json",
        "remote-authenticated-command-envelope" => "attempt/authenticated-command-envelope.json",
        other => panic!("unknown root kind {other}"),
    }
}

fn nested_member_path(kind: &str, digest_value: &ContentDigest) -> String {
    format!(
        "content/artifacts/{kind}/blake3/{}.json",
        hex_of(digest_value)
    )
}

// ---------------------------------------------------------------------------
// The complete remote north star: alternating async/sync phases.
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn north_star_two_humans_and_one_agent_end_to_end_over_http_and_postgresql() {
    let started = Instant::now();

    // All PostgreSQL setup happens synchronously before any tokio runtime
    // exists because the synchronous driver cannot connect or transact inside
    // `block_on`.
    let db = TestDb::new();
    let h1_identity = seed_human_identity(&db, H1_REQUESTER, H1_BINDING_ID, H1_SUBJECT, 2);
    let h2_identity = seed_human_identity(&db, H2_APPROVER, H2_BINDING_ID, H2_SUBJECT, 2);
    seed_principal_status(&db, H1_REQUESTER, false, 3);
    seed_principal_status(&db, H2_APPROVER, false, 3);
    seed_principal_status(&db, G_OPERATOR, true, 3);
    seed_role_assignment(&db, H1_REQUESTER, Role::ContentRequester, 0x11);
    seed_role_assignment(&db, H1_REQUESTER, Role::IdentityAdmin, 0x12);
    seed_role_assignment(&db, H1_REQUESTER, Role::EnvironmentAdmin, 0x13);
    seed_role_assignment(&db, H2_APPROVER, Role::ContentReviewer, 0x21);
    seed_role_assignment(&db, H2_APPROVER, Role::EvidenceAuditor, 0x22);
    seed_role_assignment(&db, H2_APPROVER, Role::EnvironmentActivator, 0x23);
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );
    let agent_provider = Ed25519SigningProvider::from_secret_bytes(&[0x33_u8; 32]);
    seed_live_agent_binding(&db, &agent_provider);
    let fixture = seed_attempt_fixture(&db, &h1_identity);

    // A dedicated worker connection is opened outside the async runtime.
    let mut worker_runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WS_ID.parse().unwrap(),
        Duration::from_secs(60),
    ))
    .expect("connect worker runtime");
    worker_runtime
        .client_mut()
        .batch_execute(&format!("SET search_path TO \"{}\"", db.schema))
        .unwrap();

    let issuer = db.state.issuer.clone();
    let app = router(db.state.clone());

    // Segment 1: sessions, workspace init, delegation/context, the Agent
    // lifecycle under separation of duties, approval, commit, Edition,
    // Environment progression, and Release creation.
    {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            step_01_capabilities(&app).await;
            let h1 = login_human(&app, &issuer, H1_SUBJECT, H1_REQUESTER).await;
            let h2 = login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER).await;
            step_03_workspace_init_and_role_assignment(&app, &h1).await;
            step_04_delegation_and_context_pack(&app, &h1).await;
            step_05_agent_changeset_lifecycle(&app, &h1, &agent_provider).await;
            step_06_separation_of_duties_rejections(&app, &h1, &agent_provider).await;
            step_07_approval_idempotent_commit_edition_environment_release(
                &app,
                &h1,
                &h2,
                &agent_provider,
            )
            .await;
        });
    }

    // Synchronous phase: queue the Release delivery and stage the projection.
    enqueue_preview_release_event(&db);
    let staged = stage_preview_files(&fixture.release_v2_digest);

    // Segment 2: the alias stays pending before the ready gate.
    {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let resp = preview_route_get(&app, &staged.environment).await;
            expect_problem(
                resp,
                "proof.dependency.unavailable",
                "preview alias stays pending before ready",
            )
            .await;
        });
    }

    // Synchronous phase: claim, materialize, acknowledge, and confirm the
    // delivered generation plus the drained queue.
    let worker = OutboxWorker::new(WorkerConfig::new(dsn()));
    let claims = worker
        .claim_due_work(&mut worker_runtime)
        .expect("claim the preview delivery");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].event_id, OUTBOX_EVENT_ID);
    assert_eq!(claims[0].delivery_id, OUTBOX_DELIVERY_ID);
    assert_eq!(claims[0].event_type, "preview.release");
    assert_eq!(claims[0].generation, 1);

    let adapter_root = std::env::temp_dir().join(format!(
        "proof-north-star-preview-worker-{}",
        std::process::id()
    ));
    let adapter = PreviewAdapter::new(&adapter_root);
    let blob_bytes = fixture.release_v2_bytes.clone();
    let blob = PreviewBlobV1 {
        key: format!(
            "artifacts/release_v2/blake3/{}",
            hex_of(&fixture.release_v2_digest)
        ),
        kind: "release_v2".to_owned(),
        length: byte_len(&blob_bytes),
        digest: fixture.release_v2_digest,
        bytes: blob_bytes,
    };
    let snapshot = PreviewSnapshotV1 {
        release_id: OUTBOX_EVENT_ID.to_owned(),
        release_sequence: 1,
        release_digest: fixture_release_effect_digest(),
        edition_digest: fixed_digest(0x88),
        environment_config_digest: fixed_digest(0x44),
        proof_digest: fixed_digest(0x89),
        blobs: vec![blob],
    };
    let worker_manifest = adapter
        .materialize_snapshot(&snapshot)
        .expect("materialize");
    assert_eq!(
        worker
            .acknowledge(
                &mut worker_runtime,
                &claims[0],
                worker_manifest.manifest_digest
            )
            .expect("acknowledge"),
        AcknowledgeOutcome::Acknowledged
    );
    assert_eq!(
        db.delivery_status(OUTBOX_EVENT_ID, OUTBOX_DELIVERY_ID, 1),
        "delivered"
    );
    assert!(
        worker
            .claim_due_work(&mut worker_runtime)
            .expect("second claim is empty")
            .is_empty()
    );
    let resolved = adapter
        .resolve_ready(OUTBOX_EVENT_ID)
        .expect("ready resolves");
    assert_eq!(resolved, worker_manifest);
    let _ = std::fs::remove_dir_all(&adapter_root);

    // Write the ready marker last; the exact snapshot becomes visible only now.
    std::fs::write(staged.root.join(RELEASE_ID).join("ready"), b"").unwrap();

    // Segment 3: the alias resolves over HTTP with the exact snapshot.
    {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let resp = preview_route_get(&app, &staged.environment).await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                resp.headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("private, no-store")
            );
            assert_eq!(
                resp.headers()
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok()),
                Some(format!("\"{}\"", staged.rendition_digest).as_str())
            );
            let served = response_json(resp).await;
            assert_eq!(served, staged.body_value);
        });
    }

    // Segment 4: keyed evidence.export/v2 capture through the live route.
    let route_result_digest = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let input = export_input(&fixture.release_v2_digest);
        let op = evidence_export_operation();
        let h2_session = {
            let login_runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            login_runtime.block_on(login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER))
        };
        runtime.block_on(async {
            let resp = post_operation(
                &app,
                "human",
                op.name.as_str(),
                "v2",
                Some(&h2_session),
                &operation_request_body(&op, &input),
            )
            .await;
            let envelope = expect_success(resp, "H2 captures evidence.export/v2").await;
            assert_eq!(envelope["result"]["outcome"], "success");
            assert_eq!(
                envelope["result"]["application_key_kind"],
                "required-uuidv7"
            );
            envelope["result"]["result_digest"].clone()
        })
    };

    // Synchronous phase: same-key typed replay, pending projection, assembly
    // worker, ready projection, and capture-to-fixture binding checks.
    let input = export_input(&fixture.release_v2_digest);
    let first_result = typed_export_create(&db, &input);
    assert_eq!(first_result.status, EvidenceExportStatusKind::Pending);
    let first_bytes = canonical_bytes(&serde_json::to_value(&first_result).unwrap());
    let export_id = first_result.export_id.clone();

    let pending = typed_export_status(&db, &export_id);
    assert_eq!(pending.status, EvidenceExportStatusKind::Pending);
    assert!(pending.bundle_descriptor_digest.is_none());
    assert!(pending.manifest_digest.is_none());
    assert_eq!(pending.artifact_count, 0);

    let capture_bytes = db.read_export_capture_bytes(&export_id);
    let capture: proof_remote::EvidenceExportCaptureV2 =
        serde_json::from_slice(&capture_bytes).unwrap();
    assert_eq!(
        capture
            .closure_bindings
            .remote_authority
            .target_decision_digest,
        fixture.target_decision_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .remote_authority
            .target_consequence_digest,
        fixture.target_consequence_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.result_digest,
        fixture.result_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .cross_links
            .release_policy_decision_digest,
        fixture.release_policy_decision_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.application_key,
        EXPORT_APPLICATION_KEY
    );
    // The disclosure binds the Human export caller's subject commitment (H2),
    // not the selected attempt's requester (H1): capture metadata is
    // pre-attempt and unauthenticated by contract.
    assert_eq!(
        capture.disclosures[0].commitment_digest,
        h2_identity.subject_commitment
    );

    // The exported cross-links bind the retained Agent attempt material, not
    // the Human export caller (H2): command/envelope digests match the stored
    // companions, identities match the signed decision's agent authorization,
    // and the environment-config link matches the closure entrypoint.
    assert_eq!(
        capture.closure_bindings.cross_links.command_digest,
        fixture.command_input_digest
    );
    assert_eq!(
        capture
            .closure_bindings
            .cross_links
            .authenticated_command_envelope_digest,
        fixture.command_envelope_digest
    );
    assert_eq!(
        capture.closure_bindings.cross_links.requesting_principal_id,
        H1_REQUESTER
    );
    assert_eq!(
        capture.closure_bindings.cross_links.operating_principal_id,
        G_OPERATOR
    );
    assert_eq!(
        capture.closure_bindings.cross_links.delegation_id,
        DELEGATION_ID
    );
    assert_eq!(
        capture.closure_bindings.cross_links.presentation_id,
        PRESENTATION_ID
    );

    let worker = ExportWorker::new();
    assert_eq!(worker.run_once(&db.state).expect("worker run_once"), 1);
    assert_eq!(worker.run_once(&db.state).expect("second run_once"), 0);

    let ready = typed_export_status(&db, &export_id);
    assert_eq!(ready.status, EvidenceExportStatusKind::Ready);
    let bundle_digest = ready.bundle_descriptor_digest.expect("ready bundle digest");
    let ready_manifest_digest = ready.manifest_digest.expect("ready manifest digest");
    assert_eq!(ready.artifact_count, 10);
    assert!(ready.total_included_bytes > 0);

    let bundle_descriptor = build_bundle_descriptor(&capture).unwrap();
    let manifest_value = serde_json::to_value(build_manifest(&capture).unwrap()).unwrap();
    let expected_bundle = domain_digest(
        REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
        &canonical_bytes(&serde_json::to_value(&bundle_descriptor).unwrap()),
    );
    let expected_manifest = domain_digest(
        REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
        &canonical_bytes(&manifest_value),
    );
    assert_eq!(bundle_digest, expected_bundle);
    assert_eq!(ready_manifest_digest, expected_manifest);

    // Segment 5: byte-bound route-level replay, exact-triple artifact
    // acquisition without cross-kind aliases, and the unknown-export profile.
    let fetched_members = {
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        runtime.block_on(async {
            let op = evidence_export_operation();
            let h2_session = login_human(&app, &issuer, H2_SUBJECT, H2_APPROVER).await;

            let resp = post_operation(
                &app,
                "human",
                op.name.as_str(),
                "v2",
                Some(&h2_session),
                &operation_request_body(&op, &input),
            )
            .await;
            let replay_envelope = expect_success(resp, "route-level export replay").await;
            assert_eq!(replay_envelope["result"]["outcome"], "idempotent-replay");
            assert_eq!(
                replay_envelope["result"]["result_digest"],
                route_result_digest
            );
            assert_eq!(
                replay_envelope["result"]["prior_result_digest"],
                route_result_digest
            );

            // Reserved descriptors stay hidden while pending was asserted
            // above; once ready both acquire by their exact reserved digests.
            let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
            let bundle_bytes = fetch_ok_artifact(&app, &export_id, "bundle", &bundle_digest).await;
            members.insert("bundle.json".to_owned(), bundle_bytes);
            let manifest_bytes =
                fetch_ok_artifact(&app, &export_id, "manifest", &ready_manifest_digest).await;
            members.insert("manifest.json".to_owned(), manifest_bytes.clone());

            let roots: Vec<(String, ContentDigest)> = vec![
                (
                    "release-artifact-closure".to_owned(),
                    fixture.closure_digest,
                ),
                ("authority-fact".to_owned(), fixture.record_set_digest),
                (
                    "remote-actor-evidence".to_owned(),
                    fixture.actor_evidence_digest,
                ),
                (
                    "remote-authentication-event".to_owned(),
                    fixture.authentication_event_digest,
                ),
                (
                    "remote-command-input".to_owned(),
                    fixture.command_input_digest,
                ),
                (
                    "remote-authenticated-command-envelope".to_owned(),
                    fixture.command_envelope_digest,
                ),
            ];
            for (kind, digest_value) in &roots {
                let bytes = fetch_ok_artifact(&app, &export_id, kind, digest_value).await;
                members.insert(root_member_path(kind).to_owned(), bytes);
            }
            for (kind, digest_value) in &fixture.nested {
                let bytes = fetch_ok_artifact(&app, &export_id, kind, digest_value).await;
                members.insert(nested_member_path(kind, digest_value), bytes);
            }

            // A digest under another kind is not an alias.
            let release_digest = fixture
                .nested
                .iter()
                .find(|(kind, _)| kind == "release_v2")
                .map(|(_, digest_value)| *digest_value)
                .unwrap();
            let resp = fetch_artifact(&app, &export_id, "proof_envelope_v1", &release_digest).await;
            expect_problem(
                resp,
                "proof.resource.not_found",
                "wrong-kind digest alias is rejected",
            )
            .await;

            let resp = fetch_artifact(
                &app,
                "019d0000-0000-7000-8000-0000000000ff",
                "release_v2",
                &release_digest,
            )
            .await;
            expect_problem(
                resp,
                "proof.resource.not_found",
                "unknown export is rejected",
            )
            .await;

            // Every declared membership entry matches its fetched bytes exactly.
            let manifest: Value = serde_json::from_slice(&manifest_bytes).unwrap();
            for member in manifest["membership"].as_array().expect("membership") {
                let path = member["member_path"].as_str().unwrap();
                let expected_length = member["byte_length"].as_u64().unwrap();
                let bytes = members
                    .get(path)
                    .unwrap_or_else(|| panic!("member {path} fetched"));
                assert_eq!(byte_len(bytes), expected_length, "member {path} length");
            }
            members
        })
    };

    // The same-key typed replay after assembly returns byte-identical
    // create-result bytes.
    let replayed_result = typed_export_create(&db, &input);
    let replayed_bytes = canonical_bytes(&serde_json::to_value(&replayed_result).unwrap());
    assert_eq!(
        first_bytes, replayed_bytes,
        "same-key replay must return byte-identical create-result bytes even post-assembly"
    );

    // Final phase: offline verification of the fetched logical member map.
    // This consumes no producer state, network, session, or private key.
    let trust = build_trust_inputs(&fixture);

    // The P8 authority suffix verifies independently under explicit trust:
    // signature, signer key, sequence contiguity, predecessor linkage, and
    // head coherence all reproduce from the fetched envelopes alone.
    let record_set_value: Value =
        serde_json::from_slice(&fetched_members["authority/facts.json"]).unwrap();
    let envelopes: Vec<Vec<u8>> = record_set_value["records"]
        .as_array()
        .expect("record envelopes")
        .iter()
        .map(canonical_bytes)
        .collect();
    let suffix = verify_remote_authority_suffix(&RemoteAuthoritySuffixInput {
        envelopes: &envelopes,
        initial_root_key_id: &fixture.authority_key_id,
        initial_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: zero_digest(),
        },
    })
    .expect("fetched authority suffix verifies under caller-pinned trust");
    assert_eq!(suffix.included_head.sequence, 4);
    assert_eq!(suffix.verified_records.len(), 3);

    // The composed remote-evidence verifier consumes only the fetched member
    // map and the caller-supplied policy input.
    let report = verify_remote_evidence_v2(&fetched_members, &trust.input);
    println!(
        "offline verification report: status={:?} scenario={:?} reasons={:?}",
        report.status, report.scenario, report.reason_codes
    );

    // The producer binds every attempt link from the captured attempt material
    // (command/envelope digests, Agent authorization identities, closure
    // entrypoint environment config, recomputed public input projection), so
    // the composed offline leg classifies the export Complete.
    assert_eq!(report.status, VerificationStatus::Complete);
    assert_eq!(report.reason_codes, vec![VerificationReasonCode::Verified]);

    let _ = std::fs::remove_dir_all(&staged.root);
    println!(
        "north-star remote duration: {} ms",
        started.elapsed().as_millis()
    );
}
