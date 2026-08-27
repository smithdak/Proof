//! Integration tests for the Human/Agent authentication boundary and the
//! owned Human/Agent operation executors over the P-0010 unit of work.
//!
//! Every test isolates itself in a dedicated schema (`CREATE SCHEMA` +
//! `SET search_path` + `DROP SCHEMA CASCADE` at the end) so parallel agents
//! never collide.

#![allow(
    clippy::duration_suboptimal_units,
    clippy::match_wildcard_for_single_variants
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{
    PgConfig, projection::DERIVED_TABLES_DDL, schema::ALL_TABLE_DDL, wiring::PgRuntime,
};
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
use proof_remote::registry::{ApplicationConsequenceOutcome, RemoteApplicationConsequenceV1};
use proof_remote::{AuthorityHeadV1, HttpRouteV1, RemoteOperationV1, derive_key_digest};
use proof_server::authz::{
    authenticate_agent_presentation, authenticate_human_session, evaluate_authorization,
};
use proof_server::dispatch::{DispatchRequest, dispatch};
use proof_server::operations::HumanOperationExecutor;
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig, ServerError};
use serde_json::{Map, Value, json};

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const OPERATOR: &str = "019c0000-0000-7000-8000-000000000003";
const HUMAN_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const AGENT_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000005";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000006";
const AUTH_EVENT_ID: &str = "019c0000-0000-7000-8000-000000000007";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn workspace_role_assign_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "workspace-role.assign".to_owned(),
        version: "proof.dev/operation/workspace-role.assign/v1".to_owned(),
    }
}

fn evidence_export_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "evidence.export".to_owned(),
        version: "proof.dev/operation/evidence.export/v2".to_owned(),
    }
}

fn content_read_operation(name: &str) -> RemoteOperationV1 {
    let version = match name {
        "schema.get" => "proof.dev/operation/schema.get/v1",
        "schema.list" => "proof.dev/operation/schema.list/v1",
        "object.list" => "proof.dev/operation/object.list/v1",
        _ => panic!("unsupported content read"),
    };
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

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

/// One isolated schema with the full table surface, a verified migration head,
/// and a seeded Workspace write head.
struct TestDb {
    state: AppState,
    cleanup: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new(name: &str) -> Self {
        let schema = format!(
            "p0011_{}_{}_{}",
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
                .execute(
                    "INSERT INTO migration_head (
                         singleton, version, name, script_digest, phase,
                         actor, tool_version, started_at, verified_at
                     ) VALUES (1, 1, 'bootstrap', $1, 'verified', 'test', 'test', now(), now())",
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
                     ) VALUES (1, $1, 1, 0, 10, 0, 0, $2, 10, NULL, NULL, NULL, NULL)",
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
                &[&fact_id, &WS_ID, &fact_kind, &auth_seq, &fact_digest.to_string(), &body],
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

    fn fact_count(&self, fact_id: &str) -> i64 {
        let mut guard = self.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query_one("SELECT COUNT(*) FROM facts WHERE fact_id = $1", &[&fact_id])
            .unwrap()
            .get(0)
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

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
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

/// Builds a consistent public/private OIDC Principal binding pair for the
/// requesting Human Principal.
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

fn seed_principal_status(db: &TestDb, principal_id: &str, enabled: bool) {
    let status = RemotePrincipalStatusV2 {
        api_version: RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: principal_id.to_owned(),
        principal_type: RemotePrincipalType::Human,
        enabled,
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
        &format!("principal_status/{principal_id}"),
        "principal_status",
        &digest,
        body.as_bytes(),
        3,
    );
}

fn seed_role_assignment(db: &TestDb, principal_id: &str, role: WorkspaceRole, assignment_id: &str) {
    let assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: assignment_id.to_owned(),
        principal_id: principal_id.to_owned(),
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

/// Builds and stores the operating Agent binding, returning its signing
/// provider so callers can sign an `AuthenticatedCommandV1` with the same key.
fn seed_agent_binding(db: &TestDb) -> Ed25519SigningProvider {
    let secret = [0x33_u8; 32];
    let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
    let metadata = provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
    let public_key = Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap();

    let binding = PrincipalBindingV1 {
        api_version: PrincipalBindingApiVersion::V1,
        authority_sequence: AuthoritySequence::new(5).unwrap(),
        previous_authority_record_digest: Some(deterministic_digest(0x01)),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        principal_id: OPERATOR.parse().unwrap(),
        principal_type: AgentPrincipalType::Agent,
        authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
        algorithm: Ed25519Algorithm::Ed25519,
        public_key,
        key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        enrollment_challenge_digest: deterministic_digest(0x33),
        enrollment_envelope_digest: deterministic_digest(0x34),
        issued_by_principal_id: REQUESTER.parse().unwrap(),
        issued_at: timestamp_offset(-60),
        not_before: timestamp_offset(-60),
        expires_at: timestamp_offset(3600),
        supersedes_binding_id: None,
    };
    let body = canonicalize(&serde_json::to_value(&binding).unwrap()).unwrap();
    let digest = RemoteAuthorityRecordV1::agent_binding_issue(binding).digest();
    db.seed_fact(
        &format!("agent_binding/{AGENT_BINDING_ID}"),
        "agent_binding",
        &digest,
        body.as_bytes(),
        5,
    );
    provider
}

/// Signs a valid `AuthenticatedInvocationV1` for `workspace.status/v1`.
fn build_invocation(provider: &Ed25519SigningProvider) -> AuthenticatedInvocationV1 {
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::WorkspaceStatusV1,
        requesting_principal_id: REQUESTER.parse().unwrap(),
        operating_principal_id: OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: None,
        normalized_input: Map::new(),
    };
    let command_input_value = serde_json::to_value(&command_input).unwrap();
    let canonical_command = canonicalize(&command_input_value).unwrap();
    let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);

    let issued_at = timestamp_offset(-10);
    let expires_at = timestamp_offset(120);
    let payload = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::WorkspaceStatusV1,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: REQUESTER.parse().unwrap(),
        operating_principal_id: OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest,
        idempotency_key: None,
        presentation_id: "019c0000-0000-7000-8000-0000000000aa".parse().unwrap(),
        issued_at,
        expires_at,
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::AuthenticatedCommand,
        &payload,
        &[provider],
    )
    .unwrap();
    AuthenticatedInvocationV1 {
        api_version: AuthenticatedInvocationApiVersion::V1,
        command_input,
        authentication: AuthenticatedCommandEnvelopeJson::new(signed.envelope_json).unwrap(),
    }
}

/// Builds a Human actor context whose `operation`/`normalized_input_digest`
/// fields are bound to the supplied operation and input (the dispatch layer's
/// overwrite of `authenticate_human_session` placeholders).
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

// ---------------------------------------------------------------------------

#[test]
fn human_session_binding_resolution_succeeds_and_unknown_binding_denies() {
    let db = TestDb::new("human_session");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);

    let context =
        authenticate_human_session(&db.state, &session(HUMAN_BINDING_ID, REQUESTER, WS_ID))
            .expect("binding resolution succeeds");
    match &context {
        AuthenticatedActorContextV2::Human(human) => {
            assert_eq!(human.requesting_principal_id, REQUESTER);
            assert_eq!(human.requesting_binding_id, HUMAN_BINDING_ID);
            assert_eq!(human.workspace_id, WS_ID);
            assert_eq!(human.evaluated_authority_head.sequence, 10);
            assert_eq!(
                human.authentication_profile,
                proof_remote::identity::OidcHumanAuthenticationProfile::V1
            );
        }
        _ => panic!("expected a Human context"),
    }

    // Unknown binding is a disclosure-neutral 401 with no existence oracle.
    let unknown = authenticate_human_session(
        &db.state,
        &session("019c0000-0000-7000-8000-000000000099", REQUESTER, WS_ID),
    );
    assert!(matches!(unknown, Err(ServerError::Authentication(_))));
}

#[test]
fn agent_dual_authentication_accepts_and_single_credential_rejects() {
    let db = TestDb::new("agent_dual");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    seed_principal_status(&db, OPERATOR, true);
    let provider = seed_agent_binding(&db);

    let invocation = build_invocation(&provider);
    let context = authenticate_agent_presentation(
        &db.state,
        &session(HUMAN_BINDING_ID, REQUESTER, WS_ID),
        &invocation,
    )
    .expect("dual authentication succeeds");
    match &context {
        AuthenticatedActorContextV2::HumanAgent(agent) => {
            assert_eq!(agent.requesting_principal_id, REQUESTER);
            assert_eq!(agent.operating_principal_id, OPERATOR);
            assert_eq!(agent.delegation_id, DELEGATION_ID);
        }
        _ => panic!("expected a HumanAgent context"),
    }

    // Session-only: a valid session with an invalid (wrong-key) presentation
    // is rejected — the Agent credential cannot be omitted.
    let wrong_key = Ed25519SigningProvider::from_secret_bytes(&[0x44_u8; 32]);
    let bad_invocation = build_invocation(&wrong_key);
    let session_only = authenticate_agent_presentation(
        &db.state,
        &session(HUMAN_BINDING_ID, REQUESTER, WS_ID),
        &bad_invocation,
    );
    assert!(matches!(session_only, Err(ServerError::Authentication(_))));

    // Agent-only: a valid presentation with an unknown binding session is
    // rejected — the Human credential cannot be omitted.
    let agent_only = authenticate_agent_presentation(
        &db.state,
        &session("019c0000-0000-7000-8000-000000000099", REQUESTER, WS_ID),
        &invocation,
    );
    assert!(matches!(agent_only, Err(ServerError::Authentication(_))));
}

#[test]
fn per_row_role_requirement_is_enforced() {
    let db = TestDb::new("role_requirement");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let operation = workspace_role_assign_operation();
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": OPERATOR,
        "role": "content.requester",
        "assignment_id": "019c0000-0000-7000-8000-0000000000bb",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000cc",
    });
    let context = human_context_for(&db, &operation, &input);

    // Without the required identity.admin role the decision is a denial.
    let decision = evaluate_authorization(&db.state, &context, &input).expect("decision evaluates");
    assert_eq!(
        decision.decision,
        proof_remote::registry::AuthorizationDecisionKind::Deny
    );

    // Assign the required role; the decision now allows.
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::IdentityAdmin,
        "019c0000-0000-7000-8000-0000000000dd",
    );
    let decision = evaluate_authorization(&db.state, &context, &input).expect("decision evaluates");
    assert_eq!(
        decision.decision,
        proof_remote::registry::AuthorizationDecisionKind::Allow
    );
}

#[test]
fn content_register_reads_share_release_reader_role_authorization() {
    let allowed = TestDb::new("content_reads_allowed");
    seed_human_binding(&allowed);
    seed_principal_status(&allowed, REQUESTER, true);
    seed_role_assignment(
        &allowed,
        REQUESTER,
        WorkspaceRole::ContentReviewer,
        "019c0000-0000-7000-8000-0000000000de",
    );
    allowed.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    for (operation, input) in [
        (
            content_read_operation("schema.get"),
            json!({
                "api_version": "proof.dev/operation/schema.get/v1",
                "schema_id": "article",
                "schema_version": 1,
            }),
        ),
        (
            content_read_operation("schema.list"),
            json!({"api_version": "proof.dev/operation/schema.list/v1"}),
        ),
        (
            content_read_operation("object.list"),
            json!({
                "api_version": "proof.dev/operation/object.list/v1",
                "environment_id": "preview",
                "object_ids": ["019c0000-0000-7000-8000-000000000080"],
            }),
        ),
    ] {
        let context = human_context_for(&allowed, &operation, &input);
        let decision = evaluate_authorization(&allowed.state, &context, &input).unwrap();
        assert_eq!(
            decision.decision,
            proof_remote::registry::AuthorizationDecisionKind::Allow,
            "{} should admit a release-reader role",
            operation.name
        );
        let binding_names: &[&str] = match operation.name.as_str() {
            "schema.get" => &["schema_id", "schema_version"],
            "schema.list" => &["schema_id"],
            "object.list" => &["object_ids", "schema_id"],
            _ => unreachable!(),
        };
        let bindings = binding_names
            .iter()
            .map(
                |name| proof_remote::registry::RequestedAuthorizationResourceBindingV1 {
                    name: (*name).to_owned(),
                    value_digest: proof_remote::authorization_resource_binding_digest(
                        name,
                        input.get(name).unwrap_or(&Value::Null),
                    )
                    .unwrap(),
                },
            )
            .collect::<Vec<_>>();
        let expected = proof_remote::registry::requested_authorization_resources_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            "proof.server/authorization/schema-reader/v1",
            &operation,
            match operation.name.as_str() {
                "schema.get" => "schema:get",
                "schema.list" => "schema:list",
                "object.list" => "object:list",
                _ => unreachable!(),
            },
            &bindings,
        )
        .unwrap();
        assert_eq!(decision.requested_resources_digest, expected);
    }

    let denied = TestDb::new("content_reads_denied");
    seed_human_binding(&denied);
    seed_principal_status(&denied, REQUESTER, true);
    denied.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );
    for operation in [
        content_read_operation("schema.get"),
        content_read_operation("schema.list"),
        content_read_operation("object.list"),
    ] {
        let input = json!({"api_version": operation.version.clone()});
        let context = human_context_for(&denied, &operation, &input);
        let decision = evaluate_authorization(&denied.state, &context, &input).unwrap();
        assert_eq!(
            decision.decision,
            proof_remote::registry::AuthorizationDecisionKind::Deny,
            "{} should deny an actor without a release-reader role",
            operation.name
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn schema_get_exposes_typed_result_and_commits_only_authority_evidence() {
    let db = TestDb::new("schema_get_result");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::ContentRequester,
        "019c0000-0000-7000-8000-0000000000df",
    );
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let document = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
    });
    let canonical = canonicalize(&document).unwrap();
    let document_digest = digest(ArtifactKind::SchemaVersionV1, &canonical);
    let sidecar = canonicalize(&json!({
        "api_version": "proof.dev/parity/localizable-schema/v1",
        "authoritative_sequence": 1,
        "changeset_id": "019c0000-0000-7000-8000-000000000030",
        "document": document,
        "document_digest": document_digest.to_string(),
        "edit_id": "019c0000-0000-7000-8000-000000000031",
        "schema_id": "article",
        "schema_version": 1,
    }))
    .unwrap();
    let sidecar_digest =
        derive_key_digest("proof:parity:localizable-schema:v1", sidecar.as_bytes());
    {
        let mut guard = db.runtime();
        let runtime = guard.as_mut().unwrap();
        for ddl in DERIVED_TABLES_DDL {
            runtime.client_mut().batch_execute(ddl).unwrap();
        }
        runtime
            .client_mut()
            .execute(
                "INSERT INTO projection_generations (generation, state_digest, active, rebuilt_at)
                 VALUES (1, $1, TRUE, now())",
                &[&deterministic_digest(0x72).to_string()],
            )
            .unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO projection_schemas (
                     generation, schema_id, schema_version, document_digest, authority_sequence
                 ) VALUES (1, 'article', 1, $1, 1)",
                &[&document_digest.to_string()],
            )
            .unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest,
                     body, committed_at
                 ) VALUES ('schema/article/1', $1, 'schema', 1, $2, $3, now())",
                &[&WS_ID, &document_digest.to_string(), &canonical.as_bytes()],
            )
            .unwrap();
        runtime
            .client_mut()
            .execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest,
                     body, committed_at
                 ) VALUES (
                     'localizable_schema/article/1', $1, 'localizable_schema', 0, $2, $3, now()
                 )",
                &[&WS_ID, &sidecar_digest.to_string(), &sidecar.as_bytes()],
            )
            .unwrap();
    }

    let head_before: (i64, i64, i64) = {
        let mut guard = db.runtime();
        let row = guard
            .as_mut()
            .unwrap()
            .client_mut()
            .query_one(
                "SELECT transaction_sequence, content_sequence, release_sequence
                 FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    let operation = content_read_operation("schema.get");
    let input = json!({
        "api_version": "proof.dev/operation/schema.get/v1",
        "schema_id": "article",
        "schema_version": 1,
    });
    let context = human_context_for(&db, &operation, &input);
    let envelope = dispatch(
        &db.state,
        DispatchRequest {
            route: HttpRouteV1::HumanOperations,
            path_name: "schema.get".to_owned(),
            path_major: "v1".to_owned(),
            operation,
            normalized_input: input,
            actor_context: context,
            correlation_id: None,
            agent_attempt: None,
        },
    )
    .unwrap();

    assert_eq!(envelope.data["schema_id"], "article");
    assert_eq!(envelope.data["schema_version"], 1);
    assert_eq!(envelope.data["document"]["type"], "object");
    assert_eq!(envelope.data["provenance"]["authoritative_sequence"], 1);
    assert_eq!(envelope.result_anchor["kind"], "committed-transaction");
    assert!(envelope.result_anchor["digest"].is_string());
    assert!(envelope.result_anchor["transaction_sequence"].is_u64());
    let consequence = {
        let mut guard = db.runtime();
        let body: Vec<u8> = guard
            .as_mut()
            .unwrap()
            .client_mut()
            .query_one("SELECT body FROM application_consequences", &[])
            .unwrap()
            .get(0);
        serde_json::from_slice::<RemoteApplicationConsequenceV1>(&body).unwrap()
    };
    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);
    assert!(consequence.application_effect_digest.is_none());
    assert_eq!(db.fact_count("governed_effect/schema.get"), 0);

    let missing_operation = content_read_operation("schema.get");
    let missing_input = json!({
        "api_version": "proof.dev/operation/schema.get/v1",
        "schema_id": "missing",
        "schema_version": 1,
    });
    let missing_context = human_context_for(&db, &missing_operation, &missing_input);
    let problem = dispatch(
        &db.state,
        DispatchRequest {
            route: HttpRouteV1::HumanOperations,
            path_name: "schema.get".to_owned(),
            path_major: "v1".to_owned(),
            operation: missing_operation,
            normalized_input: missing_input,
            actor_context: missing_context,
            correlation_id: None,
            agent_attempt: None,
        },
    )
    .unwrap_err();
    assert_eq!(problem.tuple.code, "proof.schema.not_found");
    assert_eq!(db.fact_count("governed_effect/schema.get"), 0);
    assert_eq!(db.count("authorization_decisions"), 2);
    assert_eq!(db.count("application_consequences"), 2);
    let head_after: (i64, i64, i64) = {
        let mut guard = db.runtime();
        let row = guard
            .as_mut()
            .unwrap()
            .client_mut()
            .query_one(
                "SELECT transaction_sequence, content_sequence, release_sequence
                 FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .unwrap();
        (row.get(0), row.get(1), row.get(2))
    };
    assert_eq!(head_after.0, head_before.0 + 2);
    assert_eq!(head_after.1, head_before.1);
    assert_eq!(head_after.2, head_before.2);
}

#[test]
fn owned_mutation_commits_decision_fact_and_consequence_with_effect_digest() {
    let db = TestDb::new("owned_mutation");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    seed_principal_status(&db, OPERATOR, true);
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::IdentityAdmin,
        "019c0000-0000-7000-8000-0000000000dd",
    );
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let operation = workspace_role_assign_operation();
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": OPERATOR,
        "role": "content.requester",
        "assignment_id": "019c0000-0000-7000-8000-0000000000ee",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000ff",
    });
    let context = human_context_for(&db, &operation, &input);
    let decision = evaluate_authorization(&db.state, &context, &input).expect("allow decision");

    let consequence =
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision)
            .expect("mutation commits");

    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);
    assert_eq!(db.count("authorization_decisions"), 1);
    assert_eq!(
        db.fact_count("workspace_role_assignment/019c0000-0000-7000-8000-0000000000ee"),
        1
    );
    assert_eq!(db.count("application_consequences"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);

    // The consequence's application_effect_digest equals the governed fact
    // digest, which is the exact remote-authority-record digest of the
    // persisted WorkspaceRoleAssignmentV1.
    let (effect_digest, fact_digest, fact_body) = {
        let mut guard = db.runtime();
        let runtime = guard.as_mut().unwrap();
        let effect: Option<String> = runtime
            .client_mut()
            .query_one(
                "SELECT application_effect_digest FROM application_consequences",
                &[],
            )
            .unwrap()
            .get(0);
        let fact_row = runtime
            .client_mut()
            .query_one(
                "SELECT fact_digest, body FROM facts WHERE fact_id = 'workspace_role_assignment/019c0000-0000-7000-8000-0000000000ee'",
                &[],
            )
            .unwrap();
        let fact_digest: String = fact_row.get(0);
        let fact_body: Vec<u8> = fact_row.get(1);
        (effect, fact_digest, fact_body)
    };
    assert_eq!(effect_digest.as_deref(), Some(fact_digest.as_str()));

    let assignment: WorkspaceRoleAssignmentV1 = serde_json::from_slice(&fact_body).unwrap();
    assert_eq!(assignment.principal_id, OPERATOR);
    assert_eq!(assignment.role, WorkspaceRole::ContentRequester);
    let recomputed = RemoteAuthorityRecordV1::workspace_role_assignment(assignment)
        .digest()
        .to_string();
    assert_eq!(recomputed, fact_digest);
}

#[test]
fn idempotent_replay_returns_prior_result_without_duplicating_fact() {
    let db = TestDb::new("replay");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    seed_principal_status(&db, OPERATOR, true);
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::IdentityAdmin,
        "019c0000-0000-7000-8000-0000000000dd",
    );
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let operation = workspace_role_assign_operation();
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": OPERATOR,
        "role": "content.requester",
        "assignment_id": "019c0000-0000-7000-8000-0000000000ee",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000ff",
    });
    let context = human_context_for(&db, &operation, &input);

    let first = {
        let decision = evaluate_authorization(&db.state, &context, &input).expect("allow");
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision)
            .expect("first commit")
    };
    assert_eq!(first.outcome, ApplicationConsequenceOutcome::Success);
    assert_eq!(
        db.fact_count("workspace_role_assignment/019c0000-0000-7000-8000-0000000000ee"),
        1
    );

    // Same key + equivalent input replays the prior result.
    let second_decision = evaluate_authorization(&db.state, &context, &input).expect("allow");
    let replay =
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &second_decision)
            .expect("replay succeeds");
    assert_eq!(
        replay.outcome,
        ApplicationConsequenceOutcome::IdempotentReplay
    );
    assert!(replay.prior_result_digest.is_some());
    // No governed fact is duplicated.
    assert_eq!(
        db.fact_count("workspace_role_assignment/019c0000-0000-7000-8000-0000000000ee"),
        1
    );
    assert_eq!(db.count("idempotency_keys"), 1);
}

#[test]
fn evidence_export_requires_the_full_capture_input() {
    let db = TestDb::new("export_requires_input");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::ContentPublisher,
        "019c0000-0000-7000-8000-0000000000dd",
    );
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let operation = evidence_export_operation();
    // The obsolete `{"workspace_id": ...}` stub input is no longer accepted:
    // `evidence.export/v2` requires `idempotency_key`, `release_id`, and
    // `release_digest`. A missing field fails closed as an input schema
    // mismatch rather than returning a dependency-unavailable consequence.
    let input = json!({ "workspace_id": WS_ID });
    let context = human_context_for(&db, &operation, &input);
    let decision = evaluate_authorization(&db.state, &context, &input).expect("decision");

    let error = HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision)
        .expect_err("evidence.export is no longer a dependency-unavailable stub");
    assert!(matches!(error, ServerError::Dispatch(_)));
}

#[test]
fn denial_appends_signed_decision_without_governed_effect() {
    let db = TestDb::new("denial");
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, true);
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );

    let operation = workspace_role_assign_operation();
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": OPERATOR,
        "role": "content.requester",
        "assignment_id": "019c0000-0000-7000-8000-0000000000ee",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000ff",
    });
    let context = human_context_for(&db, &operation, &input);

    let decision = evaluate_authorization(&db.state, &context, &input).expect("decision");
    assert_eq!(
        decision.decision,
        proof_remote::registry::AuthorizationDecisionKind::Deny
    );

    let result =
        HumanOperationExecutor::execute(&db.state, &operation, &input, &context, &decision);
    assert!(matches!(result, Err(ServerError::Authorization(_))));
    // The denial decision is committed, but no governed fact or consequence.
    assert_eq!(db.count("authorization_decisions"), 1);
    assert_eq!(db.count("application_consequences"), 0);
    assert_eq!(
        db.fact_count("workspace_role_assignment/019c0000-0000-7000-8000-0000000000ee"),
        0
    );
}
