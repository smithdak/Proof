//! End-to-end HTTP oneshot test for the P-0011 server boundary.
//!
//! It drives the complete public-to-authenticated surface against an isolated
//! `PostgreSQL` schema (never the shared database): capabilities discovery,
//! deterministic-issuer login plus callback, the `GET /api/v1/session` CSRF
//! acquisition route, a direct-Human read with `Origin` + `Proof-CSRF`, a
//! dual-auth Agent operation, and the disclosure-neutral 401 path for an
//! unknown subject.

#![allow(clippy::duration_suboptimal_units, clippy::too_many_lines)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::authority::{
    AgentPrincipalType, AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
    AuthenticatedCommandKeyUsage, AuthenticatedCommandV1, AuthenticatedInvocationApiVersion,
    AuthenticatedInvocationV1, AuthorityAction, AuthorityAudience, AuthorityOperation,
    AuthoritySequence, CommandInputApiVersion, CommandInputV1, DelegationActionsV2,
    DelegationApiVersion, DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
    DelegationObjectIdsV2, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
    DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
    LocalEd25519AuthenticatedSubjectV1, MaxContextBytes, MaxEditsPerChangeSet, MaxObjects,
    PrincipalBindingApiVersion, PrincipalBindingV1, SubdelegationDisabled,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{PgConfig, schema::ALL_TABLE_DDL, wiring::PgRuntime};
use proof_remote::AuthorityHeadV1;
use proof_remote::authority::{
    RemoteAuthorityRecordV1, RemotePrincipalStatusApiVersion, RemotePrincipalStatusV2,
    RemotePrincipalType, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
    WorkspaceRoleAssignmentV1,
};
use proof_remote::identity::{
    OidcAuthenticatedSubjectApiVersion, OidcAuthenticatedSubjectV1, OidcPrincipalBindingApiVersion,
    OidcPrincipalBindingPrivateApiVersion, OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
    OidcSubjectCommitmentInputApiVersion, OidcSubjectCommitmentInputV1,
    OidcSubjectCommitmentOpeningApiVersion, OidcSubjectCommitmentOpeningV1, encode_blind,
    subject_commitment_digest,
};
use proof_remote::oracle::IdentityFixtureV1;
use proof_server::routes::router;
use proof_server::{AppState, ServerConfig};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const WS_ID: &str = "019c0000-0000-7000-8000-000000000001";
const REQUESTER: &str = "019c0000-0000-7000-8000-000000000002";
const OPERATOR: &str = "019c0000-0000-7000-8000-000000000003";
const HUMAN_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const AGENT_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000005";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000006";
const SUBJECT: &str = "human-alice";

static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn dsn() -> String {
    std::env::var("PROOF_PG_DSN").unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
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
/// a seeded Workspace write head, and both the authority and session runtimes
/// attached to the same schema.
struct TestDb {
    state: AppState,
    cleanup: PgRuntime,
    schema: String,
}

impl TestDb {
    fn new() -> Self {
        let schema = format!(
            "p0011_e2e_{}_{}",
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

        let mut authority = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
        {
            let client = authority.client_mut();
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
        *state.pg.lock().unwrap() = Some(authority);

        // A distinct runtime for the session store, pointed at the same schema.
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

    fn seed_fact(
        &self,
        fact_id: &str,
        fact_kind: &str,
        fact_digest: &ContentDigest,
        body: &[u8],
        auth_seq: i64,
    ) {
        let mut guard = self.state.pg.lock().unwrap();
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
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = self
            .cleanup
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

fn build_human_binding_pair() -> (OidcPrincipalBindingV1, OidcPrincipalBindingPrivateV1) {
    let subject = OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: SUBJECT.to_owned(),
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

fn seed_principal_status(
    db: &TestDb,
    principal_id: &str,
    principal_type: RemotePrincipalType,
    enabled: bool,
) {
    let status = RemotePrincipalStatusV2 {
        api_version: RemotePrincipalStatusApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        principal_id: principal_id.to_owned(),
        principal_type,
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

fn seed_delegation(db: &TestDb) {
    let issued_at = timestamp_offset(-60);
    let delegation = DelegationV2 {
        api_version: DelegationApiVersion::V1,
        authority_sequence: AuthoritySequence::new(6).unwrap(),
        previous_authority_record_digest: Some(deterministic_digest(0x01)),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        workspace_id: WS_ID.parse().unwrap(),
        delegation_profile: DirectAuthorityProfileV1::Direct,
        issuer_principal_id: REQUESTER.parse().unwrap(),
        recipient_principal_id: OPERATOR.parse().unwrap(),
        actions: DelegationActionsV2::new(vec![AuthorityAction::WorkspaceStatus]).unwrap(),
        scope: DelegationScopeV2 {
            environment_ids: DelegationEnvironmentIdsV2::new(Vec::new()).unwrap(),
            object_ids: DelegationObjectIdsV2::new(Vec::new()).unwrap(),
            schema_ids: DelegationSchemaIdsV2::new(Vec::new()).unwrap(),
            locales: DelegationLocalesV2::new(Vec::new()).unwrap(),
        },
        constraints: DelegationConstraintsV2 {
            max_objects: MaxObjects::new(1).unwrap(),
            max_context_bytes: MaxContextBytes::new(1).unwrap(),
            max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
            allow_subdelegation: SubdelegationDisabled,
        },
        not_before: issued_at,
        expires_at: timestamp_offset(3600),
        issued_at,
    };
    let body = canonicalize(&serde_json::to_value(&delegation).unwrap()).unwrap();
    db.seed_fact(
        &format!("delegation/{DELEGATION_ID}"),
        "delegation",
        &RemoteAuthorityRecordV1::delegation_issue(delegation).digest(),
        body.as_bytes(),
        6,
    );
}

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

/// Extracts one percent-unencoded query parameter from a URL.
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

/// Reads one cookie value by name from a response's `Set-Cookie` headers.
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

#[test]
fn end_to_end_capabilities_login_session_human_agent_and_unknown_subject() {
    // All PostgreSQL setup happens synchronously here, before the tokio runtime
    // exists, because the synchronous `postgres` driver cannot connect from
    // within an async runtime.
    let db = TestDb::new();
    seed_human_binding(&db);
    seed_principal_status(&db, REQUESTER, RemotePrincipalType::Human, true);
    seed_principal_status(&db, OPERATOR, RemotePrincipalType::Agent, true);
    seed_role_assignment(
        &db,
        REQUESTER,
        WorkspaceRole::ContentRequester,
        "019c0000-0000-7000-8000-0000000000dd",
    );
    db.seed_authority_root(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    );
    let provider = seed_agent_binding(&db);
    seed_delegation(&db);

    let app = router(db.state.clone());
    // Capture the in-process issuer and a signed Agent invocation now so the
    // async block below never borrows (or drops) the `TestDb` inside the
    // runtime — its `Drop` runs a synchronous PostgreSQL `DROP SCHEMA`.
    let issuer = db.state.issuer.clone();
    let invocation = build_invocation(&provider);

    // Pre-create the unknown-subject session + CSRF synchronously (its later
    // HTTP request must fail with a disclosure-neutral 401).
    let unknown_binding = "019c0000-0000-7000-8000-0000000000ff";
    let unknown_session = db
        .state
        .sessions
        .create(
            WS_ID,
            REQUESTER,
            unknown_binding,
            "019c0000-0000-7000-8000-0000000000ee",
        )
        .expect("unknown-subject session is created");
    let unknown_csrf = db
        .state
        .sessions
        .issue_csrf(&unknown_session)
        .expect("unknown-subject CSRF issued");
    let unknown_cookie = format!("__Host-Http-Proof-Session={}", unknown_session.as_str());

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async move {
        // 1. Capabilities discovery is a public read.
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
        assert!(capabilities["registry_sha256"].is_string());

        // 2. Deterministic-issuer login: 303 + authorize URL.
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

        // The in-process "provider" issues the one-use code for the seeded
        // subject (this is pure CPU/random, no storage).
        let redirect_uri = issuer.config().redirect_uri.clone();
        let code_verifier =
            "deterministic-pkce-verifier-0000000000000000000000000000000000000000".to_owned();
        let code = issuer
            .issue_code(&redirect_uri, &code_verifier, &nonce, SUBJECT)
            .expect("issuer mints the code")
            .code;
        let issuer_uri = issuer.issuer().to_owned();

        // 3. Callback completes the flow: 303 + strict application session cookie.
        let callback_uri =
            format!("/auth/oidc/callback?code={code}&state={state}&iss={issuer_uri}");
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

        // 4. Session GET returns a fresh CSRF synchronizer.
        let session_cookie = format!("__Host-Http-Proof-Session={session_id}");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/session")
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("private, no-store")
        );
        let projection = response_json(resp).await;
        let csrf = projection["csrf_token"]
            .as_str()
            .expect("session projection carries a CSRF token")
            .to_owned();
        assert_eq!(csrf.len(), 43);
        assert_eq!(projection["principal_id"], REQUESTER);

        // 5. A direct-Human read operation with Origin + Proof-CSRF.
        let human_body = json!({
            "api_version": "proof.dev/http-human-operation-request/v1",
            "workspace_id": WS_ID,
            "operation": {
                "name": "changeset.get",
                "version": "proof.dev/operation/changeset.get/v2"
            },
            "input": { "changeset_id": "019c0000-0000-7000-8000-0000000000ee" }
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/human/operations/changeset.get/v2")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::HOST, "proof.example.test")
                    .header(header::ORIGIN, "https://proof.example.test")
                    .header("proof-csrf", csrf.clone())
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&human_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let human_result = response_json(resp).await;
        assert_eq!(human_result["operation"]["name"], "changeset.get");

        // 6. A dual-auth Agent operation (session + fresh AuthenticatedCommandV1).
        let agent_body = json!({
            "api_version": "proof.dev/http-agent-operation-request/v1",
            "operation": {
                "name": "workspace.status",
                "version": "proof.dev/operation/workspace.status/v1"
            },
            "invocation": serde_json::to_value(&invocation).unwrap()
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/agent/operations/workspace.status/v1")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::HOST, "proof.example.test")
                    .header(header::ORIGIN, "https://proof.example.test")
                    .header("proof-csrf", csrf.clone())
                    .header(header::COOKIE, session_cookie.clone())
                    .body(Body::from(serde_json::to_vec(&agent_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let agent_result = response_json(resp).await;
        assert_eq!(agent_result["operation"]["name"], "workspace.status");

        // 7. Disclosure-neutral 401 for an unknown subject: a session bound to a
        // binding that does not exist must fail exactly like any other identity
        // failure, with no binding-existence oracle in the response body.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/human/operations/changeset.get/v2")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::HOST, "proof.example.test")
                    .header(header::ORIGIN, "https://proof.example.test")
                    .header("proof-csrf", unknown_csrf.value)
                    .header(header::COOKIE, unknown_cookie)
                    .body(Body::from(serde_json::to_vec(&human_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let denied = response_json(resp).await;
        assert_eq!(denied["code"], "proof.auth.denied");
        let serialized = denied.to_string();
        assert!(
            !serialized.contains(unknown_binding),
            "the 401 must not disclose the unknown binding identity: {serialized}"
        );
    });
}
