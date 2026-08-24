//! Integration tests for P-0014 route-complete enrollment: the
//! `agent-binding.issue/v1` and `oidc-binding.issue/v1` executors over the
//! P-0010 unit of work, and the usability of their issued credentials through
//! the existing dual authentication boundary.

#![allow(
    clippy::duration_suboptimal_units,
    clippy::match_wildcard_for_single_variants,
    clippy::too_many_lines
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::authority::{
    AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson, AuthenticatedCommandV1,
    AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1, AuthorityAudience,
    AuthorityOperation, BindingEnrollmentChallengeV1, CommandInputApiVersion, CommandInputV1,
    Ed25519KeyId, EnrollmentChallengeApiVersion, MAX_COMMAND_LIFETIME_SECONDS,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{PgConfig, schema::ALL_TABLE_DDL, wiring::PgRuntime};
use proof_remote::authority::{
    RemoteAuthorityRecordV1, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
    WorkspaceRoleAssignmentV1,
};
use proof_remote::identity::{OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1};
use proof_remote::oracle::IdentityFixtureV1;
use proof_remote::registry::ApplicationConsequenceOutcome;
use proof_remote::{AuthorityHeadV1, RemoteOperationV1};
use proof_server::authz::{
    authenticate_agent_presentation, evaluate_authorization, resolve_oidc_binding_by_subject,
};
use proof_server::operations::{AgentOperationExecutor, HumanOperationExecutor};
use proof_server::session::SessionRecord;
use proof_server::{AppState, ServerConfig, ServerError};
use serde_json::{Map, Value, json};

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const ADMIN: &str = "019c0000-0000-7000-8000-000000000002";
const AGENT_PRINCIPAL: &str = "019c0000-0000-7000-8000-000000000003";
const HUMAN_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const NEW_AGENT_BINDING: &str = "019c0000-0000-7000-8000-000000000005";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000006";
const AUTH_EVENT_ID: &str = "019c0000-0000-7000-8000-000000000007";
const TARGET_HUMAN: &str = "019c0000-0000-7000-8000-000000000008";

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

struct TestDb {
    state: AppState,
    cleanup: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new(name: &str) -> Self {
        let schema = format!(
            "p0014_{name}_{}_{}",
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

    fn seed_authority_root(&self) {
        let body = canonicalize(&json!({
            "api_version": "proof.dev/workspace-authority-root/v1",
            "workspace_id": WS_ID,
            "authority_key_id":
                "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
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

fn session() -> SessionRecord {
    SessionRecord {
        session_id_hash: [0_u8; 32],
        workspace_id: WS_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        authentication_event_id: AUTH_EVENT_ID.to_owned(),
        csrf_digest: [0_u8; 32],
        created_at: SystemTime::now(),
        last_seen: SystemTime::now(),
        absolute_expiry: SystemTime::now() + Duration::from_secs(3600),
    }
}

/// Seeds the enrolling identity.admin's Human binding pair and enabled status.
fn seed_admin(db: &TestDb) {
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-admin".to_owned(),
    };
    let blind = [0x42_u8; 32];
    let commitment_input = proof_remote::identity::OidcSubjectCommitmentInputV1 {
        api_version: proof_remote::identity::OidcSubjectCommitmentInputApiVersion::V1,
        blind: proof_remote::identity::encode_blind(&blind),
        subject: subject.clone(),
        workspace_id: WS_ID.to_owned(),
    };
    let subject_commitment =
        proof_remote::identity::subject_commitment_digest(&commitment_input).unwrap();
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let public = proof_remote::identity::OidcPrincipalBindingV1 {
        api_version: proof_remote::identity::OidcPrincipalBindingApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        issued_by_principal_id: ADMIN.to_owned(),
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
    let private = proof_remote::identity::OidcPrincipalBindingPrivateV1 {
        api_version: proof_remote::identity::OidcPrincipalBindingPrivateApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        subject,
        subject_commitment,
        opening: proof_remote::identity::OidcSubjectCommitmentOpeningV1 {
            api_version: proof_remote::identity::OidcSubjectCommitmentOpeningApiVersion::V1,
            commitment: subject_commitment,
            input: commitment_input,
        },
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        binding_record_digest: public.binding_record_digest().unwrap(),
    };
    db.seed_fact(
        &format!("oidc_binding/{HUMAN_BINDING_ID}"),
        "oidc_public_binding",
        &public.binding_record_digest().unwrap(),
        canonicalize(&serde_json::to_value(&public).unwrap())
            .unwrap()
            .as_bytes(),
        2,
    );
    db.seed_fact(
        &format!("oidc_private_binding/{HUMAN_BINDING_ID}"),
        "oidc_private_binding",
        &deterministic_digest(0x12),
        canonicalize(&serde_json::to_value(&private).unwrap())
            .unwrap()
            .as_bytes(),
        2,
    );
    seed_principal_status(db);
    let assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: "019c0000-0000-7000-8000-0000000000dd".to_owned(),
        principal_id: ADMIN.to_owned(),
        role: WorkspaceRole::AuthorityAdmin,
        assigned_by_principal_id: ADMIN.to_owned(),
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
    db.seed_fact(
        &format!("workspace_role_assignment/{}", assignment.assignment_id),
        "workspace_role_assignment",
        &RemoteAuthorityRecordV1::workspace_role_assignment(assignment.clone()).digest(),
        canonicalize(&serde_json::to_value(&assignment).unwrap())
            .unwrap()
            .as_bytes(),
        4,
    );
    // The same Principal holds identity.admin for OIDC issuance tests.
    let identity_assignment = WorkspaceRoleAssignmentV1 {
        api_version: WorkspaceRoleAssignmentApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        assignment_id: "019c0000-0000-7000-8000-0000000000de".to_owned(),
        principal_id: ADMIN.to_owned(),
        role: WorkspaceRole::IdentityAdmin,
        assigned_by_principal_id: ADMIN.to_owned(),
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
    db.seed_fact(
        &format!(
            "workspace_role_assignment/{}",
            identity_assignment.assignment_id
        ),
        "workspace_role_assignment",
        &RemoteAuthorityRecordV1::workspace_role_assignment(identity_assignment.clone()).digest(),
        canonicalize(&serde_json::to_value(&identity_assignment).unwrap())
            .unwrap()
            .as_bytes(),
        4,
    );
}

fn seed_principal_status(db: &TestDb) {
    let status = proof_remote::authority::RemotePrincipalStatusV2 {
        api_version: proof_remote::authority::RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        principal_type: proof_remote::authority::RemotePrincipalType::Human,
        enabled: true,
        reason: "test".to_owned(),
        recorded_by_principal_id: ADMIN.to_owned(),
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
    db.seed_fact(
        &format!("principal_status/{ADMIN}"),
        "principal_status",
        &RemoteAuthorityRecordV1::principal_status(status).digest(),
        body.as_bytes(),
        3,
    );
}

fn human_context_for(
    db: &TestDb,
    operation: &RemoteOperationV1,
    input: &Value,
) -> proof_remote::identity::AuthenticatedActorContextV2 {
    let mut context = proof_server::authz::authenticate_human_session(&db.state, &session())
        .expect("human session authenticates");
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(input, operation).unwrap();
    if let proof_remote::identity::AuthenticatedActorContextV2::Human(human) = &mut context {
        human.operation = operation.clone();
        human.normalized_input_digest = normalized_input_digest;
    }
    context
}

fn agent_binding_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "agent-binding.issue".to_owned(),
        version: "proof.dev/operation/agent-binding.issue/v1".to_owned(),
    }
}

fn oidc_binding_operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "oidc-binding.issue".to_owned(),
        version: "proof.dev/operation/oidc-binding.issue/v1".to_owned(),
    }
}

/// Builds the full enrollment closure for one candidate Agent key.
fn build_enrollment_closure(provider: &Ed25519SigningProvider) -> (Value, String, String) {
    let metadata = provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
    let public_key_b64 = BASE64.encode(&metadata.public_key);
    let challenge = BindingEnrollmentChallengeV1 {
        api_version: EnrollmentChallengeApiVersion::V1,
        challenge_id: "019c0000-0000-7000-8000-0000000000c1".parse().unwrap(),
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: NEW_AGENT_BINDING.parse().unwrap(),
        principal_id: AGENT_PRINCIPAL.parse().unwrap(),
        candidate_key_id: key_id,
        issued_by_principal_id: ADMIN.parse().unwrap(),
        issued_at: timestamp_offset(-60),
        expires_at: timestamp_offset((MAX_COMMAND_LIFETIME_SECONDS - 60).min(240)),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::BindingEnrollmentChallenge,
        &challenge,
        &[provider],
    )
    .unwrap();
    let challenge_value = serde_json::to_value(&challenge).unwrap();
    (challenge_value, signed.envelope_json, public_key_b64)
}

fn agent_binding_input(
    challenge_value: &Value,
    envelope_json: &str,
    public_key_b64: &str,
) -> Value {
    json!({
        "workspace_id": WS_ID,
        "principal_id": AGENT_PRINCIPAL,
        "public_key": public_key_b64,
        "challenge": challenge_value,
        "enrollment_envelope": envelope_json,
        "idempotency_key": "019c0000-0000-7000-8000-0000000000ff",
    })
}

fn execute_human(
    db: &TestDb,
    operation: &RemoteOperationV1,
    input: &Value,
) -> Result<proof_remote::registry::RemoteApplicationConsequenceV1, ServerError> {
    let context = human_context_for(db, operation, input);
    let decision = evaluate_authorization(&db.state, &context, input).expect("decision evaluates");
    HumanOperationExecutor::execute(&db.state, operation, input, &context, &decision)
}

#[test]
fn agent_binding_issue_commits_and_issued_credentials_authenticate() {
    let db = TestDb::new("agent_issue_use");
    seed_admin(&db);
    db.seed_authority_root();

    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x71_u8; 32]);
    let (challenge_value, envelope_json, public_key_b64) = build_enrollment_closure(&provider);
    let input = agent_binding_input(&challenge_value, &envelope_json, &public_key_b64);
    let operation = agent_binding_operation();

    let consequence = execute_human(&db, &operation, &input).expect("enrollment commits");
    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);
    assert!(consequence.problem_code.is_none());
    assert_eq!(
        db.fact_count(&format!("agent_binding/{NEW_AGENT_BINDING}")),
        1
    );
    assert_eq!(db.count("application_consequences"), 1);
    assert_eq!(db.count("idempotency_keys"), 1);
    assert_eq!(db.count("authorization_decisions"), 1);

    // The governed effect is the exact remote-authority-record digest.
    let stored: Vec<u8> = {
        let mut guard = db.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query_one(
                "SELECT body FROM facts WHERE fact_id = $1",
                &[&format!("agent_binding/{NEW_AGENT_BINDING}")],
            )
            .unwrap()
            .get(0)
    };
    let binding: proof_application::authority::PrincipalBindingV1 =
        serde_json::from_slice(&stored).unwrap();
    let recomputed = RemoteAuthorityRecordV1::agent_binding_issue(binding.clone())
        .digest()
        .to_string();
    assert_eq!(
        consequence.application_effect_digest.map(|d| d.to_string()),
        Some(recomputed)
    );

    // Single-use consumption marker exists.
    let challenge_canonical = canonicalize(&challenge_value).unwrap();
    let challenge_digest = digest(
        ArtifactKind::BindingEnrollmentChallengeV1,
        &challenge_canonical,
    );
    assert_eq!(
        db.fact_count(&format!(
            "enrollment_challenge_consumption/{challenge_digest}"
        )),
        1
    );

    // The issued credential authenticates end to end through the dual
    // boundary and completes an authenticated governed read.
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::WorkspaceStatusV1,
        requesting_principal_id: ADMIN.parse().unwrap(),
        operating_principal_id: AGENT_PRINCIPAL.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        idempotency_key: None,
        normalized_input: Map::new(),
    };
    let command_input_value = serde_json::to_value(&command_input).unwrap();
    let command_digest = digest(
        ArtifactKind::CommandV1,
        &canonicalize(&command_input_value).unwrap(),
    );
    let payload = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::WorkspaceStatusV1,
        binding_id: NEW_AGENT_BINDING.parse().unwrap(),
        requesting_principal_id: ADMIN.parse().unwrap(),
        operating_principal_id: AGENT_PRINCIPAL.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest,
        idempotency_key: None,
        presentation_id: "019c0000-0000-7000-8000-0000000000aa".parse().unwrap(),
        issued_at: timestamp_offset(-10),
        expires_at: timestamp_offset(120),
    };
    let signed_command = sign_authority_payload(
        AuthorityPayloadProfile::AuthenticatedCommand,
        &payload,
        &[&provider],
    )
    .unwrap();
    let invocation = AuthenticatedInvocationV1 {
        api_version: AuthenticatedInvocationApiVersion::V1,
        command_input,
        authentication: AuthenticatedCommandEnvelopeJson::new(signed_command.envelope_json)
            .unwrap(),
    };
    let context = authenticate_agent_presentation(&db.state, &session(), &invocation)
        .expect("issued credentials authenticate");
    let decision =
        evaluate_authorization(&db.state, &context, &input).expect("agent decision evaluates");
    let status_consequence = AgentOperationExecutor::execute(
        &db.state,
        &decision.operation,
        &json!({}),
        &context,
        &decision,
    )
    .expect("authenticated governed operation commits");
    assert_eq!(
        status_consequence.outcome,
        ApplicationConsequenceOutcome::Success
    );
}

#[test]
fn agent_binding_issue_replays_then_conflicts_on_challenge_reuse() {
    let db = TestDb::new("agent_replay_conflict");
    seed_admin(&db);
    db.seed_authority_root();

    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x72_u8; 32]);
    let (challenge_value, envelope_json, public_key_b64) = build_enrollment_closure(&provider);
    let operation = agent_binding_operation();

    let first = execute_human(
        &db,
        &operation,
        &agent_binding_input(&challenge_value, &envelope_json, &public_key_b64),
    )
    .expect("first commit");
    assert_eq!(first.outcome, ApplicationConsequenceOutcome::Success);

    // Same key + equivalent input replays without a duplicate fact.
    let replay = execute_human(
        &db,
        &operation,
        &agent_binding_input(&challenge_value, &envelope_json, &public_key_b64),
    )
    .expect("replay succeeds");
    assert_eq!(
        replay.outcome,
        ApplicationConsequenceOutcome::IdempotentReplay
    );
    assert_eq!(
        db.fact_count(&format!("agent_binding/{NEW_AGENT_BINDING}")),
        1
    );

    // A fresh idempotency key re-presenting the same ceremony for the same
    // principals hits the Workspace-global successful-application key rule
    // before any enrollment precondition.
    let mut reused = agent_binding_input(&challenge_value, &envelope_json, &public_key_b64);
    reused["idempotency_key"] = json!("019c0000-0000-7000-8000-0000000000fe");
    let conflict = execute_human(&db, &operation, &reused).expect("conflict commits");
    assert_eq!(
        conflict.outcome,
        ApplicationConsequenceOutcome::IdempotencyConflict
    );
    assert_eq!(
        db.fact_count(&format!("agent_binding/{NEW_AGENT_BINDING}")),
        1
    );
}

#[test]
fn agent_binding_issue_fails_with_state_conflict_for_expired_challenge() {
    let db = TestDb::new("agent_expired");
    seed_admin(&db);
    db.seed_authority_root();

    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x75_u8; 32]);
    let metadata = provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
    let public_key_b64 = BASE64.encode(&metadata.public_key);
    let challenge = BindingEnrollmentChallengeV1 {
        api_version: EnrollmentChallengeApiVersion::V1,
        challenge_id: "019c0000-0000-7000-8000-0000000000c2".parse().unwrap(),
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        binding_id: NEW_AGENT_BINDING.parse().unwrap(),
        principal_id: AGENT_PRINCIPAL.parse().unwrap(),
        candidate_key_id: key_id,
        issued_by_principal_id: ADMIN.parse().unwrap(),
        issued_at: timestamp_offset(-600),
        expires_at: timestamp_offset(-300),
    };
    let signed = sign_authority_payload(
        AuthorityPayloadProfile::BindingEnrollmentChallenge,
        &challenge,
        &[&provider],
    )
    .unwrap();
    let challenge_value = serde_json::to_value(&challenge).unwrap();
    let input = agent_binding_input(&challenge_value, &signed.envelope_json, &public_key_b64);

    let consequence = execute_human(&db, &agent_binding_operation(), &input)
        .expect("failure consequence commits");
    assert_eq!(
        consequence.outcome,
        ApplicationConsequenceOutcome::ApplicationFailure
    );
    assert_eq!(
        consequence.problem_code.as_deref(),
        Some("proof.state.conflict")
    );
    assert_eq!(
        db.fact_count(&format!("agent_binding/{NEW_AGENT_BINDING}")),
        0
    );
    assert_eq!(
        db.count("authorization_decisions"),
        1,
        "an authorized application failure retains its signed decision"
    );
}

#[test]
fn agent_binding_issue_rejects_malformed_closure_without_state_change() {
    let db = TestDb::new("agent_malformed");
    seed_admin(&db);
    db.seed_authority_root();

    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x73_u8; 32]);
    let (challenge_value, _envelope_json, public_key_b64) = build_enrollment_closure(&provider);
    // An envelope signed by a different key does not verify: its embedded
    // challenge carries a different candidate key identity than ours.
    let impostor = Ed25519SigningProvider::from_secret_bytes(&[0x74_u8; 32]);
    let (_, wrong_envelope, _) = build_enrollment_closure(&impostor);
    let input = agent_binding_input(&challenge_value, &wrong_envelope, &public_key_b64);
    let error = execute_human(&db, &agent_binding_operation(), &input)
        .expect_err("foreign envelope must not verify");
    assert!(matches!(error, ServerError::Dispatch(_)));
    assert_eq!(
        db.fact_count(&format!("agent_binding/{NEW_AGENT_BINDING}")),
        0
    );

    // Missing closure fields fail closed before any transaction.
    let incomplete = json!({
        "workspace_id": WS_ID,
        "principal_id": AGENT_PRINCIPAL,
        "public_key": public_key_b64,
        "idempotency_key": "019c0000-0000-7000-8000-0000000000ff",
    });
    let error = execute_human(&db, &agent_binding_operation(), &incomplete)
        .expect_err("missing closure fields are a schema mismatch");
    assert!(matches!(error, ServerError::Dispatch(_)));

    // Without the required role the decision denies and only the decision
    // commits.
    let unassigned = TestDb::new("agent_unassigned");
    seed_admin_roles_absent(&unassigned);
    unassigned.seed_authority_root();
    let (challenge_value_c, envelope_c, key_c) = build_enrollment_closure(&provider);
    let input = agent_binding_input(&challenge_value_c, &envelope_c, &key_c);
    let error = execute_human(&unassigned, &agent_binding_operation(), &input)
        .expect_err("missing authority.admin role denies");
    assert!(matches!(error, ServerError::Authorization(_)));
    assert_eq!(
        unassigned.count("authorization_decisions"),
        1,
        "a proven denial commits its signed decision"
    );
    assert_eq!(unassigned.count("application_consequences"), 0);
}

fn seed_admin_roles_absent(db: &TestDb) {
    // Same as `seed_admin` minus both role assignments.
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-admin".to_owned(),
    };
    let blind = [0x42_u8; 32];
    let commitment_input = proof_remote::identity::OidcSubjectCommitmentInputV1 {
        api_version: proof_remote::identity::OidcSubjectCommitmentInputApiVersion::V1,
        blind: proof_remote::identity::encode_blind(&blind),
        subject: subject.clone(),
        workspace_id: WS_ID.to_owned(),
    };
    let subject_commitment =
        proof_remote::identity::subject_commitment_digest(&commitment_input).unwrap();
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let public = proof_remote::identity::OidcPrincipalBindingV1 {
        api_version: proof_remote::identity::OidcPrincipalBindingApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        issued_by_principal_id: ADMIN.to_owned(),
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
    let private = proof_remote::identity::OidcPrincipalBindingPrivateV1 {
        api_version: proof_remote::identity::OidcPrincipalBindingPrivateApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: ADMIN.to_owned(),
        subject,
        subject_commitment,
        opening: proof_remote::identity::OidcSubjectCommitmentOpeningV1 {
            api_version: proof_remote::identity::OidcSubjectCommitmentOpeningApiVersion::V1,
            commitment: subject_commitment,
            input: commitment_input,
        },
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        binding_record_digest: public.binding_record_digest().unwrap(),
    };
    db.seed_fact(
        &format!("oidc_binding/{HUMAN_BINDING_ID}"),
        "oidc_public_binding",
        &public.binding_record_digest().unwrap(),
        canonicalize(&serde_json::to_value(&public).unwrap())
            .unwrap()
            .as_bytes(),
        2,
    );
    db.seed_fact(
        &format!("oidc_private_binding/{HUMAN_BINDING_ID}"),
        "oidc_private_binding",
        &deterministic_digest(0x12),
        canonicalize(&serde_json::to_value(&private).unwrap())
            .unwrap()
            .as_bytes(),
        2,
    );
    seed_principal_status(db);
}

#[test]
fn oidc_binding_issue_commits_pair_resolves_subject_and_conflicts_on_duplicate() {
    let db = TestDb::new("oidc_issue_resolve");
    seed_admin(&db);
    db.seed_authority_root();

    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-new-editor".to_owned(),
    };
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": TARGET_HUMAN,
        "subject": subject,
        "issuer_configuration_digest": issuer_configuration_digest.to_string(),
        "binding_id": "019c0000-0000-7000-8000-0000000000e1",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000fd",
    });
    let operation = oidc_binding_operation();

    let consequence = execute_human(&db, &operation, &input).expect("issuance commits");
    assert_eq!(consequence.outcome, ApplicationConsequenceOutcome::Success);
    assert_eq!(
        db.fact_count("oidc_binding/019c0000-0000-7000-8000-0000000000e1"),
        1
    );
    assert_eq!(
        db.fact_count("oidc_private_binding/019c0000-0000-7000-8000-0000000000e1"),
        1
    );

    // The issued pair resolves the authenticated subject to the bound Human.
    let resolved = resolve_oidc_binding_by_subject(&db.state, &subject)
        .expect("issued binding resolves the subject");
    assert_eq!(resolved.principal_id, TARGET_HUMAN);
    assert_eq!(resolved.binding_id, "019c0000-0000-7000-8000-0000000000e1");

    // Re-issuing the same subject with a fresh binding identifier hits the
    // Workspace-global successful-application key rule before the duplicate
    // scan; the original binding survives and no new private row appears.
    let mut duplicate = input.clone();
    duplicate["binding_id"] = json!("019c0000-0000-7000-8000-0000000000e2");
    duplicate["idempotency_key"] = json!("019c0000-0000-7000-8000-0000000000fc");
    let conflict = execute_human(&db, &operation, &duplicate).expect("conflict commits");
    assert_eq!(
        conflict.outcome,
        ApplicationConsequenceOutcome::IdempotencyConflict
    );
    assert_eq!(
        db.fact_count("oidc_private_binding/019c0000-0000-7000-8000-0000000000e2"),
        0
    );

    // Replay returns the prior result without duplicating rows.
    let replay = execute_human(&db, &operation, &input).expect("replay succeeds");
    assert_eq!(
        replay.outcome,
        ApplicationConsequenceOutcome::IdempotentReplay
    );
    assert_eq!(
        db.fact_count("oidc_binding/019c0000-0000-7000-8000-0000000000e1"),
        1
    );
}

#[test]
fn oidc_binding_issue_rejects_unpinned_issuer_digest() {
    let db = TestDb::new("oidc_unpinned");
    seed_admin(&db);
    db.seed_authority_root();

    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-anyone".to_owned(),
    };
    let input = json!({
        "workspace_id": WS_ID,
        "principal_id": TARGET_HUMAN,
        "subject": subject,
        "issuer_configuration_digest": deterministic_digest(0x99).to_string(),
        "idempotency_key": "019c0000-0000-7000-8000-0000000000fb",
    });
    let error = execute_human(&db, &oidc_binding_operation(), &input)
        .expect_err("an unpinned issuer configuration must not issue");
    assert!(matches!(error, ServerError::Dispatch(_)));
    assert_eq!(db.count("application_consequences"), 0);
}

#[test]
fn enrollment_conformance_vectors_match_produced_artifacts() {
    let repository_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let agent_vector: Value = serde_json::from_slice(
        &std::fs::read(repository_root.join(
            "conformance/v1/collaboration-server/vectors/enrollment-agent-binding.valid.json",
        ))
        .unwrap(),
    )
    .unwrap();
    let oidc_vector: Value = serde_json::from_slice(
        &std::fs::read(repository_root.join(
            "conformance/v1/collaboration-server/vectors/enrollment-oidc-binding.valid.json",
        ))
        .unwrap(),
    )
    .unwrap();

    let db = TestDb::new("vector_pinning");
    seed_admin(&db);
    db.seed_authority_root();

    // The produced Agent binding carries exactly the pinned field set.
    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x76_u8; 32]);
    let (challenge_value, envelope_json, public_key_b64) = build_enrollment_closure(&provider);
    let input = agent_binding_input(&challenge_value, &envelope_json, &public_key_b64);
    let _ = execute_human(&db, &agent_binding_operation(), &input).expect("enrollment commits");
    let stored: Vec<u8> = {
        let mut guard = db.runtime();
        let runtime = guard.as_mut().unwrap();
        runtime
            .client_mut()
            .query_one(
                "SELECT body FROM facts WHERE fact_id = $1",
                &[&format!("agent_binding/{NEW_AGENT_BINDING}")],
            )
            .unwrap()
            .get(0)
    };
    let binding: Value = serde_json::from_slice(&stored).unwrap();
    let mut produced_fields: Vec<String> = binding.as_object().unwrap().keys().cloned().collect();
    produced_fields.sort();
    let mut pinned_fields: Vec<String> = agent_vector["issued_binding_shape"]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    pinned_fields.sort();
    assert_eq!(produced_fields, pinned_fields);

    // The issued OIDC pair carries exactly the pinned public/protected sets.
    let issuer_configuration_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: "subject-vector".to_owned(),
    };
    let oidc_input = json!({
        "workspace_id": WS_ID,
        "principal_id": TARGET_HUMAN,
        "subject": subject,
        "issuer_configuration_digest": issuer_configuration_digest.to_string(),
        "binding_id": "019c0000-0000-7000-8000-0000000000f1",
        "idempotency_key": "019c0000-0000-7000-8000-0000000000fa",
    });
    let _ = execute_human(&db, &oidc_binding_operation(), &oidc_input).expect("issuance commits");
    let load_fact = |fact_id: &str| -> Value {
        let mut guard = db.runtime();
        let runtime = guard.as_mut().unwrap();
        let body: Vec<u8> = runtime
            .client_mut()
            .query_one("SELECT body FROM facts WHERE fact_id = $1", &[&fact_id])
            .unwrap()
            .get(0);
        serde_json::from_slice(&body).unwrap()
    };
    let public = load_fact("oidc_binding/019c0000-0000-7000-8000-0000000000f1");
    let private = load_fact("oidc_private_binding/019c0000-0000-7000-8000-0000000000f1");
    let sorted_keys = |value: &Value| -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        sorted_keys(&public),
        sorted_field_list(&oidc_vector["public_binding_shape"]["fields"])
    );
    assert_eq!(
        sorted_keys(&private),
        sorted_field_list(&oidc_vector["protected_opening_shape"]["fields"])
    );
}

fn sorted_field_list(value: &Value) -> Vec<String> {
    let mut fields: Vec<String> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap().to_owned())
        .collect();
    fields.sort();
    fields
}
