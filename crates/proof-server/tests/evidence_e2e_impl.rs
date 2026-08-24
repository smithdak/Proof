//! End-to-end evidence-export scenario: create a Release-bearing workspace,
//! request `evidence.export/v2`, assemble through the export worker, read the
//! status to ready, acquire one artifact by its exact triple, and assert the
//! reserved bundle/manifest digests.
//!
//! Every database test isolates itself in a dedicated schema (`CREATE SCHEMA` +
//! `SET search_path` + `DROP SCHEMA CASCADE` at the end), so parallel agents and
//! test runs never collide.

#![allow(clippy::similar_names)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proof_application::authority::{
    AuthenticatedCommandApiVersion, AuthenticatedCommandV1, AuthorityAudience, AuthorityOperation,
    CommandInputApiVersion, CommandInputV1,
};
use proof_attestation::Ed25519SigningProvider;
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{PgConfig, schema::ALL_TABLE_DDL, wiring::PgRuntime};
use proof_remote::authority::{
    RemoteAuthorityRecordV1, RemotePrincipalStatusApiVersion, RemotePrincipalStatusV2,
    RemotePrincipalType, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
    WorkspaceRoleAssignmentV1,
};
use proof_remote::identity::AuthenticatedActorContextV2;
use proof_remote::identity::{
    OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1, OidcPrincipalBindingApiVersion,
    OidcPrincipalBindingPrivateApiVersion, OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputApiVersion, OidcSubjectCommitmentInputV1,
    OidcSubjectCommitmentOpeningApiVersion, OidcSubjectCommitmentOpeningV1, encode_blind,
    subject_commitment_digest,
};
use proof_remote::oracle::IdentityFixtureV1;
use proof_remote::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AcceptedArtifactAvailabilityV1,
    AcceptedArtifactDescriptorV1, AcceptedArtifactRefV1, AuthorityHeadV1, EvidenceExportCaptureV2,
    EvidenceExportStatusKind, REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
    REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT, REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
    REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT, REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT,
    RemoteAuthorityRecordSetApiVersion, RemoteAuthorityRecordSetV1, RemoteOperationV1,
    RemoteReleaseArtifactClosureApiVersion, RemoteReleaseArtifactClosureEntrypointsV1,
    RemoteReleaseArtifactClosureV1, derive_key_digest,
};
use proof_server::authz::{authenticate_human_session, evaluate_authorization};
use proof_server::export::{
    EvidenceArtifactSelector, ExportWorker, build_bundle_descriptor, build_manifest,
    evidence_artifact_get_v2, evidence_export_get_v1, evidence_export_v2,
};
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig};
use serde_json::{Value, json};

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const OPERATOR: &str = "019c0000-0000-7000-8000-000000000003";
const HUMAN_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const AGENT_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000005";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000006";
const PRESENTATION_ID: &str = "019c0000-0000-7000-8000-000000000007";
const APPLICATION_KEY: &str = "019d0000-0000-7000-8000-000000000031";
const AUTH_EVENT_ID: &str = "019c0000-0000-7000-8000-000000000007";
const RELEASE_ID: &str = "019d0000-0000-7000-8000-000000000020";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn deterministic_digest(byte: u8) -> ContentDigest {
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

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn evidence_export_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "evidence.export".to_owned(),
        version: "proof.dev/operation/evidence.export/v2".to_owned(),
    }
}

fn evidence_export_get_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "evidence.export.get".to_owned(),
        version: "proof.dev/operation/evidence.export.get/v1".to_owned(),
    }
}

fn domain_digest(context: &str, value: &Value) -> ContentDigest {
    let canonical = canonicalize(value).unwrap();
    derive_key_digest(context, canonical.as_bytes())
}

// ---------------------------------------------------------------------------
// Test database harness (schema-isolated, mirrors the P-0012 delivery harness).
// ---------------------------------------------------------------------------

struct TestDb {
    state: AppState,
    cleanup: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new(name: &str) -> Self {
        let schema = format!(
            "p0013_e2e_{}_{}_{}",
            name,
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
            Duration::from_mins(1),
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
                .execute(
                    "INSERT INTO migration_head (
                         singleton, version, name, script_digest, phase,
                         actor, tool_version, started_at, verified_at
                     ) VALUES (1, 3, 'delivery-state', $1, 'verified', 'test', 'test', now(), now())",
                    &[&deterministic_digest(0x10).to_string()],
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
                    &[&WS_ID, &deterministic_digest(0xaa).to_string()],
                )
                .unwrap();
        }
        *state.pg.lock().unwrap() = Some(runtime);

        let cleanup = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_mins(1),
        ))
        .expect("connect cleanup connection");

        Self {
            state,
            cleanup,
            schema,
        }
    }

    fn runtime(&self) -> std::sync::MutexGuard<'_, Option<PgRuntime>> {
        self.state.pg.lock().unwrap()
    }

    fn seed_fact(
        &self,
        fact_id: &str,
        fact_kind: &str,
        fact_digest: &ContentDigest,
        body: &[u8],
        auth_seq: i64,
    ) {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
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

    fn seed_artifact(&self, kind: &str, digest: &ContentDigest, bytes: &[u8]) {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
                 VALUES ($1, $2, $3, clock_timestamp())",
                &[&kind, &digest.to_string(), &bytes],
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
            &deterministic_digest(0x20),
            body.as_bytes(),
            0,
        );
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .cleanup
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

// ---------------------------------------------------------------------------
// Actor context and authorization seeding (mirrors P-0012).
// ---------------------------------------------------------------------------

fn session(binding_id: &str, principal_id: &str, workspace_id: &str) -> SessionRecord {
    SessionRecord {
        session_id_hash: [0_u8; 32],
        workspace_id: workspace_id.to_owned(),
        principal_id: principal_id.to_owned(),
        binding_id: binding_id.to_owned(),
        authentication_event_id: AUTH_EVENT_ID.to_owned(),
        csrf_digest: [0_u8; 32],
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        absolute_expiry: SystemTime::now() + Duration::from_hours(1),
    }
}

fn build_human_binding_pair() -> (OidcPrincipalBindingV1, OidcPrincipalBindingPrivateV1) {
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-requester".to_owned(),
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
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: REQUESTER.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        issued_by_principal_id: REQUESTER.to_owned(),
        issued_at: now_timestamp(),
        supersedes_binding_id: None,
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: deterministic_digest(0x01),
        },
        authority_sequence: 2,
        previous_authority_record_digest: deterministic_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };

    let binding_record_digest = public.binding_record_digest().unwrap();
    let private = OidcPrincipalBindingPrivateV1 {
        api_version: OidcPrincipalBindingPrivateApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: REQUESTER.to_owned(),
        subject,
        subject_commitment,
        opening,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        binding_record_digest,
    };
    (public, private)
}

fn seed_human_binding(db: &TestDb) {
    let (public, private) = build_human_binding_pair();
    let public_body = canonicalize(&serde_json::to_value(&public).unwrap()).unwrap();
    db.seed_fact(
        &format!("oidc_binding/{HUMAN_BINDING_ID}"),
        "oidc_public_binding",
        &public.binding_record_digest().unwrap(),
        public_body.as_bytes(),
        2,
    );
    let private_body = canonicalize(&serde_json::to_value(&private).unwrap()).unwrap();
    db.seed_fact(
        &format!("oidc_private_binding/{HUMAN_BINDING_ID}"),
        "oidc_private_binding",
        &deterministic_digest(0x12),
        private_body.as_bytes(),
        2,
    );
}

fn seed_principal_status(db: &TestDb) {
    let status = RemotePrincipalStatusV2 {
        api_version: RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: REQUESTER.to_owned(),
        principal_type: RemotePrincipalType::Human,
        enabled: true,
        reason: "test".to_owned(),
        recorded_by_principal_id: REQUESTER.to_owned(),
        recorded_by_actor_context_digest: deterministic_digest(0x30),
        recorded_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: deterministic_digest(0x01),
        },
        authority_sequence: 3,
        previous_authority_record_digest: deterministic_digest(0x01),
        authority_key_id:
            "ed25519:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    };
    let body = canonicalize(&serde_json::to_value(&status).unwrap()).unwrap();
    let digest = RemoteAuthorityRecordV1::principal_status(status).digest();
    db.seed_fact(
        &format!("principal_status/{REQUESTER}"),
        "principal_status",
        &digest,
        body.as_bytes(),
        3,
    );
}

fn seed_role_assignment(db: &TestDb, role: WorkspaceRole, assignment_id: &str) {
    let assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: assignment_id.to_owned(),
        principal_id: REQUESTER.to_owned(),
        role,
        assigned_by_principal_id: REQUESTER.to_owned(),
        assigned_by_actor_context_digest: deterministic_digest(0x32),
        assigned_at: now_timestamp(),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: deterministic_digest(0x01),
        },
        authority_sequence: 4,
        previous_authority_record_digest: deterministic_digest(0x01),
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

fn seed_human_actor(db: &TestDb, role: WorkspaceRole, assignment_id: &str) {
    seed_human_binding(db);
    seed_principal_status(db);
    seed_role_assignment(db, role, assignment_id);
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );
}

fn human_context_for(
    db: &TestDb,
    operation: &RemoteOperationV1,
    input: &Value,
) -> AuthenticatedActorContextV2 {
    let mut context =
        authenticate_human_session(&db.state, &session(HUMAN_BINDING_ID, REQUESTER, WS_ID))
            .expect("human session authenticates");
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(input, operation).unwrap();
    if let AuthenticatedActorContextV2::Human(human) = &mut context {
        human.operation = operation.clone();
        human.normalized_input_digest = normalized_input_digest;
    }
    context
}

fn read_capture(db: &TestDb, export_id: &str) -> EvidenceExportCaptureV2 {
    let mut guard = db.runtime();
    let runtime = guard.as_mut().unwrap();
    let row = runtime
        .client_mut()
        .query_one(
            "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'evidence_export_capture'",
            &[&format!("evidence_export_capture/{export_id}")],
        )
        .unwrap();
    let bytes: Vec<u8> = row.get(0);
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Deterministic Release-bearing workspace fixture (reuses P-0011 fixtures).
// ---------------------------------------------------------------------------

#[allow(clippy::struct_field_names)]
struct SeededExport {
    release_digest: ContentDigest,
    release_v2_digest: ContentDigest,
    release_v2_bytes: Vec<u8>,
    command_input_digest: ContentDigest,
    envelope_digest: ContentDigest,
}

#[allow(clippy::too_many_lines)]
fn seed_export(db: &TestDb) -> SeededExport {
    // Nested accepted-artifact bodies (canonical JSON bytes).
    let release_v2_value = json!({
        "api_version": "proof.dev/release/v2",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "edition_digest": deterministic_digest(0x50).to_string(),
        "kind": "release-v2-test",
    });
    let release_v2_bytes = canonicalize(&release_v2_value).unwrap();
    let release_v2_digest = derive_key_digest("proof:release:v2", release_v2_bytes.as_bytes());

    let proof_value = json!({
        "api_version": "proof.dev/proof-envelope/v1",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "predicate": "release-attestation-test",
    });
    let proof_bytes = canonicalize(&proof_value).unwrap();
    let proof_digest = derive_key_digest("proof:proof-envelope:v1", proof_bytes.as_bytes());

    let environment_value = json!({
        "api_version": "proof.dev/environment-config-projection/v2",
        "workspace_id": WS_ID,
        "environment_id": "test",
        "version": 2,
    });
    let environment_bytes = canonicalize(&environment_value).unwrap();
    let environment_digest =
        derive_key_digest("proof:environment-config:v2", environment_bytes.as_bytes());

    let artifacts = vec![
        AcceptedArtifactDescriptorV1 {
            artifact: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: release_v2_digest,
            },
            availability: AcceptedArtifactAvailabilityV1 {
                state: "included".to_owned(),
                byte_length: release_v2_bytes.as_bytes().len() as u64,
            },
        },
        AcceptedArtifactDescriptorV1 {
            artifact: AcceptedArtifactRefV1 {
                artifact_kind: "proof_envelope_v1".to_owned(),
                digest: proof_digest,
            },
            availability: AcceptedArtifactAvailabilityV1 {
                state: "included".to_owned(),
                byte_length: proof_bytes.as_bytes().len() as u64,
            },
        },
        AcceptedArtifactDescriptorV1 {
            artifact: AcceptedArtifactRefV1 {
                artifact_kind: "environment_config_v2_projection".to_owned(),
                digest: environment_digest,
            },
            availability: AcceptedArtifactAvailabilityV1 {
                state: "included".to_owned(),
                byte_length: environment_bytes.as_bytes().len() as u64,
            },
        },
    ];

    let closure = RemoteReleaseArtifactClosureV1 {
        api_version: RemoteReleaseArtifactClosureApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        artifact_order: "artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        artifacts,
        role_binding_order: "role, artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        role_bindings: Vec::new(),
        entrypoints: RemoteReleaseArtifactClosureEntrypointsV1 {
            target_release_manifest: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: release_v2_digest,
            },
            target_release_proof_envelope: AcceptedArtifactRefV1 {
                artifact_kind: "proof_envelope_v1".to_owned(),
                digest: proof_digest,
            },
            target_environment_config: AcceptedArtifactRefV1 {
                artifact_kind: "environment_config_v2_projection".to_owned(),
                digest: environment_digest,
            },
            application_effect: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: release_v2_digest,
            },
            result_derivation:
                "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest"
                    .to_owned(),
        },
    };
    let closure_value = serde_json::to_value(&closure).unwrap();
    let closure_bytes = canonicalize(&closure_value).unwrap();
    let closure_digest = derive_key_digest(
        REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT,
        closure_bytes.as_bytes(),
    );

    let record_set = RemoteAuthorityRecordSetV1 {
        api_version: RemoteAuthorityRecordSetApiVersion::Tag,
        workspace_id: WS_ID.to_owned(),
        base_head: AuthorityHeadV1 {
            sequence: 1,
            record_digest: deterministic_digest(0x61),
        },
        record_order: "decoded authority_sequence ascending and contiguous".to_owned(),
        records: Vec::new(),
        included_head: AuthorityHeadV1 {
            sequence: 2,
            record_digest: deterministic_digest(0x62),
        },
    };
    let record_set_value = serde_json::to_value(&record_set).unwrap();
    let record_set_bytes = canonicalize(&record_set_value).unwrap();
    let record_set_digest = derive_key_digest(
        REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
        record_set_bytes.as_bytes(),
    );

    // Attempt-companion root bytes.
    let actor_value = json!({
        "api_version": "proof.authenticated-actor-context-evidence/v2",
        "workspace_id": WS_ID,
        "requesting_principal_id": REQUESTER,
        "subject_commitment": deterministic_digest(0x70).to_string(),
    });
    let actor_bytes = canonicalize(&actor_value).unwrap();
    let actor_digest = derive_key_digest(
        AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
        actor_bytes.as_bytes(),
    );

    let auth_value = json!({
        "api_version": "proof.remote-authentication-event/v1",
        "workspace_id": WS_ID,
        "authentication_event_id": AUTH_EVENT_ID,
    });
    let auth_bytes = canonicalize(&auth_value).unwrap();
    let auth_digest = derive_key_digest(
        REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
        auth_bytes.as_bytes(),
    );

    // Attempt companions: a real CommandInputV1 and its signed Agent DSSE
    // envelope, so the capture can bind attempt identities from stored bytes.
    let normalized_input: serde_json::Map<String, Value> = json!({ "release_name": "test" })
        .as_object()
        .unwrap()
        .clone();
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::ReleaseCreateV2,
        requesting_principal_id: REQUESTER.parse().unwrap(),
        operating_principal_id: OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: Some(APPLICATION_KEY.parse().unwrap()),
        normalized_input: normalized_input.clone(),
    };
    let canonical_command = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
    let command_bytes = canonical_command.as_bytes().to_vec();
    let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);

    let agent_provider = Ed25519SigningProvider::from_secret_bytes(&[0x33_u8; 32]);
    let command = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::ReleaseCreateV2,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: REQUESTER.parse().unwrap(),
        operating_principal_id: OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest,
        idempotency_key: Some(APPLICATION_KEY.parse().unwrap()),
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
    let envelope_digest = signed_command.envelope_digest;

    // Persist the six roots + nested bodies and the pre-materialized selection.
    db.seed_artifact(
        "release-artifact-closure",
        &closure_digest,
        closure_bytes.as_bytes(),
    );
    db.seed_artifact(
        "authority-fact",
        &record_set_digest,
        record_set_bytes.as_bytes(),
    );
    db.seed_artifact(
        "remote-actor-evidence",
        &actor_digest,
        actor_bytes.as_bytes(),
    );
    db.seed_artifact(
        "remote-authentication-event",
        &auth_digest,
        auth_bytes.as_bytes(),
    );
    db.seed_artifact("remote-command-input", &command_digest, &command_bytes);
    db.seed_artifact(
        "remote-authenticated-command-envelope",
        &envelope_digest,
        &envelope_bytes,
    );
    db.seed_artifact(
        "release_v2",
        &release_v2_digest,
        release_v2_bytes.as_bytes(),
    );
    db.seed_artifact("proof_envelope_v1", &proof_digest, proof_bytes.as_bytes());
    db.seed_artifact(
        "environment_config_v2_projection",
        &environment_digest,
        environment_bytes.as_bytes(),
    );

    let material = json!({
        "api_version": "proof.dev/release-export-material/v1",
        "workspace_id": WS_ID,
        "release_id": RELEASE_ID,
        "release_digest": release_v2_digest.to_string(),
        "release_artifact_closure_digest": closure_digest.to_string(),
        "authority_record_set_digest": record_set_digest.to_string(),
        "actor_context_evidence_digest": actor_digest.to_string(),
        "authentication_event_digest": auth_digest.to_string(),
        "command_input_digest": command_digest.to_string(),
        "authenticated_command_envelope_digest": envelope_digest.to_string(),
        "target_decision_digest": deterministic_digest(0x80).to_string(),
        "target_consequence_digest": deterministic_digest(0x81).to_string(),
        "result_digest": deterministic_digest(0x82).to_string(),
        "release_policy_decision_digest": deterministic_digest(0x83).to_string(),
    });
    let material_bytes = canonicalize(&material).unwrap();
    db.seed_fact(
        &format!("release_export_material/{RELEASE_ID}"),
        "release_export_material",
        &deterministic_digest(0x90),
        material_bytes.as_bytes(),
        1,
    );

    SeededExport {
        release_digest: release_v2_digest,
        release_v2_digest,
        release_v2_bytes: release_v2_bytes.as_bytes().to_vec(),
        command_input_digest: command_digest,
        envelope_digest,
    }
}

fn export_input_with_digest(release_digest: &ContentDigest) -> Value {
    json!({
        "idempotency_key": "019d0000-0000-7000-8000-000000000030",
        "release_id": RELEASE_ID,
        "release_digest": release_digest.to_string(),
    })
}

// ---------------------------------------------------------------------------
// End-to-end scenario.
// ---------------------------------------------------------------------------

#[test]
fn export_worker_end_to_end_reads_ready_and_serves_an_artifact() {
    let db = TestDb::new("scenario");
    seed_human_actor(
        &db,
        WorkspaceRole::ContentPublisher,
        "019c0000-0000-7000-8000-0000000000e1",
    );
    let seeded = seed_export(&db);

    // 1. Request `evidence.export/v2` (typed server-side entrypoint) and observe
    //    the pending keyed result.
    let operation = evidence_export_operation();
    let input = export_input_with_digest(&seeded.release_digest);
    let context = human_context_for(&db, &operation, &input);
    let decision = evaluate_authorization(&db.state, &context, &input).expect("allow decision");
    let result =
        evidence_export_v2(&db.state, &operation, &input, &context, &decision).expect("create");
    assert_eq!(result.status, EvidenceExportStatusKind::Pending);

    // 2. Assemble the bundle through the export worker (claims the pending
    //    capture and transitions it pending-to-ready).
    let worker = ExportWorker::new();
    let advanced = worker.run_once(&db.state).expect("worker run_once");
    assert_eq!(
        advanced, 1,
        "the worker must assemble exactly one pending export"
    );

    // 3. Read the lifecycle status to ready and assert the reserved
    //    bundle/manifest digests.
    let get_operation = evidence_export_get_operation();
    let get_input = json!({ "export_id": result.export_id });
    let get_context = human_context_for(&db, &get_operation, &get_input);
    let get_decision =
        evaluate_authorization(&db.state, &get_context, &get_input).expect("get decision");
    let ready = evidence_export_get_v1(
        &db.state,
        &get_operation,
        &get_input,
        &get_context,
        &get_decision,
    )
    .expect("ready status");
    assert_eq!(ready.status, EvidenceExportStatusKind::Ready);
    assert!(ready.bundle_descriptor_digest.is_some());
    assert!(ready.manifest_digest.is_some());

    let capture = read_capture(&db, &result.export_id);

    // The exported cross-links bind the retained attempt companions, not the
    // Human export caller (the attempt's application key differs from the
    // export input's idempotency key).
    let links = &capture.closure_bindings.cross_links;
    assert_eq!(links.command_digest, seeded.command_input_digest);
    assert_eq!(
        links.authenticated_command_envelope_digest,
        seeded.envelope_digest
    );
    assert_eq!(links.requesting_principal_id, REQUESTER);
    assert_eq!(links.operating_principal_id, OPERATOR);
    assert_eq!(links.delegation_id, DELEGATION_ID);
    assert_eq!(links.presentation_id, PRESENTATION_ID);
    assert_eq!(links.application_key, APPLICATION_KEY);

    let bundle = build_bundle_descriptor(&capture).expect("bundle descriptor");
    let manifest = build_manifest(&capture).expect("manifest");
    let expected_bundle = domain_digest(
        REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
        &serde_json::to_value(&bundle).unwrap(),
    );
    let expected_manifest = domain_digest(
        REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
        &serde_json::to_value(&manifest).unwrap(),
    );
    assert_eq!(ready.bundle_descriptor_digest, Some(expected_bundle));
    assert_eq!(ready.manifest_digest, Some(expected_manifest));

    // 4. Fetch one nested artifact by its exact (export_id, kind, digest) triple.
    let selector = EvidenceArtifactSelector {
        export_id: result.export_id.clone(),
        artifact_kind: "release_v2".to_owned(),
        digest: seeded.release_v2_digest,
    };
    let bytes = evidence_artifact_get_v2(&db.state, &selector).expect("acquire release_v2");
    assert_eq!(bytes, seeded.release_v2_bytes);

    // A second worker run is a no-op: the export is already ready.
    let advanced_again = worker.run_once(&db.state).expect("second run_once");
    assert_eq!(advanced_again, 0);
}
