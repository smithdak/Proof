//! Integration tests for the P-0012 delivery executors and the private preview
//! object projection.
//!
//! Every database test isolates itself in a dedicated schema (`CREATE SCHEMA` +
//! `SET search_path` + `DROP SCHEMA CASCADE` at the end) and every preview test
//! uses a uniquely-scoped environment directory under the system temp dir, so
//! parallel agents and test runs never collide.

#![allow(
    clippy::duration_suboptimal_units,
    clippy::match_wildcard_for_single_variants,
    clippy::similar_names
)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proof_canonical::canonicalize;
use proof_domain::{ContentDigest, Timestamp};
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
use proof_remote::registry::ApplicationConsequenceOutcome;
use proof_remote::{AuthorityHeadV1, DeliveryManagementFactV1, RemoteOperationV1};
use proof_server::authz::{authenticate_human_session, evaluate_authorization};
use proof_server::operations::{
    DEPENDENCY_UNAVAILABLE_CODE, HumanOperationExecutor, PreviewObjectResultV1, delivery_get_v1,
    serve_preview_object,
};
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig, ServerError};
use serde_json::{Value, json};

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const HUMAN_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const AUTH_EVENT_ID: &str = "019c0000-0000-7000-8000-000000000007";

const EVENT_ID: &str = "019d0000-0000-7000-8000-000000000010";
const DELIVERY_ID: &str = "019d0000-0000-7000-8000-000000000011";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn delivery_get_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "delivery.get".to_owned(),
        version: "proof.dev/operation/delivery.get/v1".to_owned(),
    }
}

fn delivery_replay_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "delivery.replay".to_owned(),
        version: "proof.dev/operation/delivery.replay/v1".to_owned(),
    }
}

fn delivery_abandon_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "delivery.abandon".to_owned(),
        version: "proof.dev/operation/delivery.abandon/v1".to_owned(),
    }
}

fn deterministic_digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn now_timestamp() -> Timestamp {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap()).unwrap()
}

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

/// One isolated schema with the full v3 table surface, a verified migration
/// head, and a seeded Workspace write head.
struct TestDb {
    state: AppState,
    cleanup: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new(name: &str) -> Self {
        let schema = format!(
            "p0012_{}_{}_{}",
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
                .batch_execute(proof_pg::migration::DELIVERY_STATE_V3_DDL)
                .unwrap();
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
            Duration::from_secs(60),
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

    fn count(&self, table: &str) -> i64 {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
            .unwrap()
            .get(0)
    }

    fn seed_delivery_state(
        &self,
        event_id: &str,
        delivery_id: &str,
        generation: i64,
        status: &str,
        attempts_in_generation: i64,
        receipt_digest: Option<&str>,
    ) {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO delivery_state (
                     event_id, delivery_id, generation, status, next_attempt_at,
                     attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                     generation_started_at, committed_at
                 ) VALUES ($1, $2, $3, $4, NULL, $5, NULL, NULL, $6, now(), now())",
                &[
                    &event_id,
                    &delivery_id,
                    &generation,
                    &status,
                    &attempts_in_generation,
                    &receipt_digest,
                ],
            )
            .unwrap();
    }

    fn seed_delivery_attempt(
        &self,
        attempt_id: &str,
        event_id: &str,
        delivery_id: &str,
        generation: i64,
        attempt_number: i64,
    ) {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO delivery_attempts (
                     attempt_id, event_id, delivery_id, generation, attempt_number,
                     lease_token_hash, status, attempted_at, terminal_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, 'failed', now(), now())",
                &[
                    &attempt_id,
                    &event_id,
                    &delivery_id,
                    &generation,
                    &attempt_number,
                    &deterministic_digest(0x50).to_string(),
                ],
            )
            .unwrap();
    }

    fn seed_outbox_event(&self, event_id: &str, payload_digest: &ContentDigest) {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO outbox_events (
                     event_id, workspace_id, workspace_transaction_sequence, ordinal,
                     event_type, event_version, ordering_key, stream_sequence,
                     effect_digest, payload_digest, artifact_kind, artifact_digest,
                     destination_configuration_version, destination_configuration_digest,
                     correlation_id, causation_id, committed_creation_time
                 ) VALUES ($1, $2, 1, 0, 'preview.release', 'v1', 'preview:key', 1,
                           $3, $4, NULL, NULL, 1, $3, NULL, NULL, now())",
                &[
                    &event_id,
                    &WS_ID,
                    &deterministic_digest(0x60).to_string(),
                    &payload_digest.to_string(),
                ],
            )
            .unwrap();
    }

    fn delivery_state_rows(&self, event_id: &str, delivery_id: &str) -> Vec<(i64, String, i64)> {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query(
                "SELECT generation, status, attempts_in_generation FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 ORDER BY generation",
                &[&event_id, &delivery_id],
            )
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row.get::<_, i64>(0),
                    row.get::<_, String>(1),
                    row.get::<_, i64>(2),
                )
            })
            .collect()
    }

    fn outbox_payload_digest(&self, event_id: &str) -> String {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query_one(
                "SELECT payload_digest FROM outbox_events WHERE event_id = $1",
                &[&event_id],
            )
            .unwrap()
            .get(0)
    }

    fn management_fact_payloads(&self, delivery_id: &str) -> Vec<DeliveryManagementFactV1> {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query(
                "SELECT payload FROM delivery_management_facts WHERE delivery_id = $1",
                &[&delivery_id],
            )
            .unwrap()
            .iter()
            .map(|row| {
                serde_json::from_slice::<DeliveryManagementFactV1>(&row.get::<_, Vec<u8>>(0))
                    .unwrap()
            })
            .collect()
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
        absolute_expiry: SystemTime::now() + Duration::from_secs(3600),
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

/// A unique preview environment directory, cleaned up on drop.
struct PreviewEnv {
    environment: String,
    root: PathBuf,
}

impl PreviewEnv {
    fn new(name: &str) -> Self {
        let environment = format!(
            "p0012_{}_{}_{}",
            name,
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let root = std::env::temp_dir()
            .join("proof-preview")
            .join(&environment);
        Self { environment, root }
    }

    fn write_manifest(
        &self,
        release_id: &str,
        release_digest: &ContentDigest,
        edition_digest: &ContentDigest,
    ) {
        let manifest = json!({
            "release_id": release_id,
            "release_digest": release_digest.to_string(),
            "edition_digest": edition_digest.to_string(),
            "objects": [],
        });
        std::fs::create_dir_all(self.root.join(release_id)).unwrap();
        std::fs::write(
            self.root.join(release_id).join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn write_object(
        &self,
        release_id: &str,
        object_id: &str,
        locale: &str,
        body: &Value,
    ) -> ContentDigest {
        let bytes = serde_json::to_vec(body).unwrap();
        let digest = ContentDigest::blake3(*blake3::hash(&bytes).as_bytes());
        let path = format!("objects/{object_id}/{locale}.json");
        std::fs::create_dir_all(self.root.join(release_id).join("objects").join(object_id))
            .unwrap();
        std::fs::write(self.root.join(release_id).join(&path), &bytes).unwrap();

        let manifest_path = self.root.join(release_id).join("manifest.json");
        let bytes = std::fs::read(&manifest_path).unwrap();
        let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
        let objects = manifest.get_mut("objects").unwrap().as_array_mut().unwrap();
        objects.push(json!({
            "object_id": object_id,
            "locale": locale,
            "rendition_digest": digest.to_string(),
            "path": path,
        }));
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        digest
    }

    fn mark_ready(&self, release_id: &str) {
        std::fs::write(self.root.join(release_id).join("ready"), b"").unwrap();
    }
}

impl Drop for PreviewEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn preview_root_path(environment: &str) -> PathBuf {
    std::env::temp_dir().join("proof-preview").join(environment)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn delivery_management_fact_digest_matches_conformance_vectors() {
    let recorded_at: Timestamp = "2026-08-23T14:05:00Z".parse().unwrap();
    let replay = DeliveryManagementFactV1::replay(
        "019e0000-0000-7000-8000-000000000001",
        "018f0000-0000-7000-8000-000000000011",
        "018f0000-0000-7000-8000-000000000014",
        1,
        "018f0000-0000-7000-8000-000000000015",
        "blake3:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .parse()
            .unwrap(),
        92,
        recorded_at,
    );
    assert_eq!(
        replay.digest().unwrap().to_string(),
        "blake3:d6589f50e56b6002f75cec029e3d890ef4f391b32a5e172e86136ae9d448259c"
    );

    let recorded_at: Timestamp = "2026-08-23T14:10:00Z".parse().unwrap();
    let abandon = DeliveryManagementFactV1::abandon(
        "019e0000-0000-7000-8000-000000000001",
        "018f0000-0000-7000-8000-000000000011",
        "018f0000-0000-7000-8000-000000000014",
        2,
        "018f0000-0000-7000-8000-000000000016",
        "operator-confirmed-poison-delivery",
        "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            .parse()
            .unwrap(),
        93,
        recorded_at,
    );
    assert_eq!(
        abandon.digest().unwrap().to_string(),
        "blake3:ff532321728ed84553f69c4a2b1d822b019db9ef87514953d5f884ecf4a81035"
    );
}

#[test]
fn replay_returns_pending_with_new_generation_and_preserved_identities() {
    let db = TestDb::new("replay");
    seed_human_actor(
        &db,
        WorkspaceRole::EnvironmentAdmin,
        "019c0000-0000-7000-8000-0000000000d1",
    );

    let payload_digest = deterministic_digest(0x71);
    db.seed_outbox_event(EVENT_ID, &payload_digest);
    db.seed_delivery_state(EVENT_ID, DELIVERY_ID, 1, "dead-letter", 12, None);
    db.seed_delivery_attempt("attempt-1", EVENT_ID, DELIVERY_ID, 1, 1);
    db.seed_delivery_attempt("attempt-2", EVENT_ID, DELIVERY_ID, 1, 2);

    let operation = delivery_replay_operation();
    let input = json!({
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "expected_generation": 1,
        "idempotency_key": "019d0000-0000-7000-8000-000000000012",
    });
    let context = human_context_for(&db, &operation, &input);
    let decision = evaluate_authorization(&db.state, &context, &input).expect("allow decision");

    let consequence =
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision)
            .expect("replay commits");

    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);

    // The successor generation is pending with reset attempts; the original
    // generation row is preserved.
    let rows = db.delivery_state_rows(EVENT_ID, DELIVERY_ID);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], (1, "dead-letter".to_owned(), 12));
    assert_eq!(rows[1], (2, "pending".to_owned(), 0));

    // Immutable identities and the payload are preserved.
    assert_eq!(db.count("delivery_attempts"), 2);
    assert_eq!(
        db.outbox_payload_digest(EVENT_ID),
        payload_digest.to_string()
    );

    // One immutable management fact binds the consequence effect digest.
    assert_eq!(db.count("delivery_management_facts"), 1);
    let facts = db.management_fact_payloads(DELIVERY_ID);
    assert_eq!(facts.len(), 1);
    assert_eq!(
        facts[0].action,
        proof_remote::DeliveryManagementAction::Replay
    );
    assert_eq!(facts[0].from_generation, 1);
    assert_eq!(facts[0].to_generation, Some(2));
    assert_eq!(facts[0].reason, "dead-letter-replay");
    assert_eq!(facts[0].event_id, EVENT_ID);
    assert_eq!(facts[0].delivery_id, DELIVERY_ID);
    assert_eq!(
        consequence.application_effect_digest,
        Some(facts[0].digest().unwrap())
    );
}

#[test]
fn abandon_is_terminal_with_null_to_generation_and_preserved_generation() {
    let db = TestDb::new("abandon");
    seed_human_actor(
        &db,
        WorkspaceRole::EnvironmentActivator,
        "019c0000-0000-7000-8000-0000000000d2",
    );

    db.seed_delivery_state(EVENT_ID, DELIVERY_ID, 1, "dead-letter", 3, None);

    let operation = delivery_abandon_operation();
    let input = json!({
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "expected_generation": 1,
        "reason": "operator-confirmed-poison-delivery",
        "idempotency_key": "019d0000-0000-7000-8000-000000000013",
    });
    let context = human_context_for(&db, &operation, &input);
    let decision = evaluate_authorization(&db.state, &context, &input).expect("allow decision");

    let consequence =
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision)
            .expect("abandon commits");

    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);

    let rows = db.delivery_state_rows(EVENT_ID, DELIVERY_ID);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], (1, "abandoned".to_owned(), 3));

    let facts = db.management_fact_payloads(DELIVERY_ID);
    assert_eq!(facts.len(), 1);
    assert_eq!(
        facts[0].action,
        proof_remote::DeliveryManagementAction::Abandon
    );
    assert_eq!(facts[0].from_generation, 1);
    assert_eq!(facts[0].to_generation, None);
    assert_eq!(facts[0].reason, "operator-confirmed-poison-delivery");
    assert_eq!(
        consequence.application_effect_digest,
        Some(facts[0].digest().unwrap())
    );
}

#[test]
fn non_dead_letter_replay_and_non_poison_abandon_reject() {
    let db = TestDb::new("reject");
    seed_human_actor(
        &db,
        WorkspaceRole::EnvironmentAdmin,
        "019c0000-0000-7000-8000-0000000000d3",
    );

    // A pending delivery is neither dead-letter (replay) nor a confirmed poison
    // (abandon); both fail closed with proof.state.conflict.
    db.seed_delivery_state(EVENT_ID, DELIVERY_ID, 1, "pending", 0, None);

    let replay = delivery_replay_operation();
    let replay_input = json!({
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "expected_generation": 1,
        "idempotency_key": "019d0000-0000-7000-8000-000000000014",
    });
    let context = human_context_for(&db, &replay, &replay_input);
    let decision = evaluate_authorization(&db.state, &context, &replay_input).expect("decision");
    let replay_consequence =
        HumanOperationExecutor::execute(&db.state, &replay, &replay_input, &context, &decision)
            .expect("replay commits a failure consequence");
    assert_eq!(
        replay_consequence.outcome,
        ApplicationConsequenceOutcome::ApplicationFailure
    );
    assert_eq!(
        replay_consequence.problem_code.as_deref(),
        Some("proof.state.conflict")
    );
    assert_eq!(db.count("delivery_management_facts"), 0);

    // The activator role is also required for the abandon reject case; assign it
    // in addition to the admin role already present.
    seed_role_assignment(
        &db,
        WorkspaceRole::EnvironmentActivator,
        "019c0000-0000-7000-8000-0000000000d4",
    );
    let abandon = delivery_abandon_operation();
    let abandon_input = json!({
        "event_id": EVENT_ID,
        "delivery_id": DELIVERY_ID,
        "expected_generation": 1,
        "reason": "operator-confirmed-poison-delivery",
        "idempotency_key": "019d0000-0000-7000-8000-000000000015",
    });
    let context = human_context_for(&db, &abandon, &abandon_input);
    let decision = evaluate_authorization(&db.state, &context, &abandon_input).expect("decision");
    let abandon_consequence =
        HumanOperationExecutor::execute(&db.state, &abandon, &abandon_input, &context, &decision)
            .expect("abandon commits a failure consequence");
    assert_eq!(
        abandon_consequence.outcome,
        ApplicationConsequenceOutcome::ApplicationFailure
    );
    assert_eq!(
        abandon_consequence.problem_code.as_deref(),
        Some("proof.state.conflict")
    );
    assert_eq!(db.count("delivery_management_facts"), 0);

    // The delivery remains pending; neither reject mutated state.
    let rows = db.delivery_state_rows(EVENT_ID, DELIVERY_ID);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], (1, "pending".to_owned(), 0));
}

#[test]
fn delivery_get_projects_each_status() {
    let db = TestDb::new("get");
    seed_human_actor(
        &db,
        WorkspaceRole::ContentPublisher,
        "019c0000-0000-7000-8000-0000000000d5",
    );

    let cases = [
        ("pending", 0, None),
        ("in-flight", 2, None),
        (
            "delivered",
            5,
            Some("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ),
        ("dead-letter", 12, None),
        ("abandoned", 3, None),
    ];

    let mut ordinal = 0_i64;
    for (status, attempts, receipt) in cases {
        ordinal += 1;
        let delivery_id = format!("019d0000-0000-7000-8000-00000000002{ordinal}");
        let event_id = format!("019d0000-0000-7000-8000-00000000003{ordinal}");
        db.seed_delivery_state(&event_id, &delivery_id, 1, status, attempts, receipt);

        let operation = delivery_get_operation();
        let input = json!({
            "event_id": event_id,
            "delivery_id": delivery_id,
            "expected_generation": 1,
        });
        let context = human_context_for(&db, &operation, &input);
        let decision = evaluate_authorization(&db.state, &context, &input).expect("decision");
        let consequence = delivery_get_v1(&db.state, &operation, &input, &context, &decision)
            .expect("projection commits");

        assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);
        assert_eq!(consequence.application_effect_digest, None);

        let expected = json!({
            "api_version": "proof.dev/delivery-get-result/v1",
            "event_id": event_id,
            "delivery_id": delivery_id,
            "generation": 1,
            "status": status,
            "attempts_in_generation": attempts,
            "next_attempt_at": null,
            "receipt_digest": receipt,
        });
        let expected_digest = proof_remote::registry::operation_effect_digest(&expected).unwrap();
        assert_eq!(consequence.result_digest, Some(expected_digest));
    }
}

#[test]
fn serve_preview_object_returns_snapshot_after_ready_and_pending_before() {
    let env = PreviewEnv::new("preview");
    let release_id = "018f0000-0000-7000-8000-000000000023";
    let release_digest = deterministic_digest(0x77);
    let edition_digest = deterministic_digest(0x88);
    let object_id = "018f0000-0000-7000-8000-000000000025";
    let locale = "en-US";
    let body = json!({ "title": "exact snapshot", "value": 7 });

    env.write_manifest(release_id, &release_digest, &edition_digest);
    let rendition_digest = env.write_object(release_id, object_id, locale, &body);

    let state = preview_state();

    // Before the ready marker exists the object is pending, never another
    // Release's snapshot.
    let pending = serve_preview_object(&state, &env.environment, release_id, object_id, locale);
    assert!(matches!(
        pending,
        Err(ServerError::Internal(ref message)) if message.starts_with(DEPENDENCY_UNAVAILABLE_CODE)
    ));

    // Materialize the ready marker last; now the exact snapshot resolves.
    env.mark_ready(release_id);
    let served = serve_preview_object(&state, &env.environment, release_id, object_id, locale)
        .expect("ready snapshot resolves");
    assert_eq!(served.release_id, release_id);
    assert_eq!(served.release_digest, release_digest);
    assert_eq!(served.edition_digest, edition_digest);
    assert_eq!(served.rendition_digest, rendition_digest);
    assert_eq!(served.etag, format!("\"{rendition_digest}\""));
    assert_eq!(served.cache_control, "private, no-store");
    assert_eq!(served.body, body);
}

#[test]
fn serve_preview_object_never_falls_back_to_another_release() {
    let env = PreviewEnv::new("fallback");
    let ready_release = "018f0000-0000-7000-8000-000000000023";
    let other_release = "018f0000-0000-7000-8000-000000000024";
    let release_digest = deterministic_digest(0x77);
    let edition_digest = deterministic_digest(0x88);
    let object_id = "018f0000-0000-7000-8000-000000000025";
    let locale = "en-US";

    env.write_manifest(ready_release, &release_digest, &edition_digest);
    env.write_object(
        ready_release,
        object_id,
        locale,
        &json!({ "which": "ready" }),
    );
    env.mark_ready(ready_release);

    let state = preview_state();

    // A different, not-ready Release returns the pending Problem, never the
    // ready Release's snapshot.
    let result = serve_preview_object(&state, &env.environment, other_release, object_id, locale);
    assert!(matches!(
        result,
        Err(ServerError::Internal(ref message)) if message.starts_with(DEPENDENCY_UNAVAILABLE_CODE)
    ));

    // A ready Release that lacks the exact object/locale is a not-found, never a
    // fallback to a different object.
    let result = serve_preview_object(
        &state,
        &env.environment,
        ready_release,
        "different-object",
        locale,
    );
    assert!(matches!(result, Err(ServerError::Dispatch(_))));
}

fn preview_state() -> AppState {
    let issuer = IdentityFixtureV1::deterministic().issuer_configuration;
    let config = ServerConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        WS_ID.parse().unwrap(),
        issuer,
        "deployment-secret:proof-oidc-client",
        [0x5a; 32],
        dsn(),
    );
    AppState::new(config)
}

#[test]
fn preview_object_projection_type_surface_is_stable() {
    // Pin the public projection shape so a later implementation cannot silently
    // reshape the preview boundary.
    let _ = PreviewObjectResultV1 {
        release_id: String::new(),
        release_digest: deterministic_digest(0xaa),
        edition_digest: deterministic_digest(0xbb),
        rendition_digest: deterministic_digest(0xcc),
        etag: String::new(),
        cache_control: "private, no-store",
        body: Value::Null,
    };
    let _ = preview_root_path("preview");
    assert!(Path::new("/").exists());
}
