//! Milestone-3 local/server conformance report (P-0013 acceptance criterion:
//! "The local/server conformance report proves byte-identical shared oracle
//! traces in both modes").
//!
//! One representative five-step operation sequence is executed by three
//! runners and classified per step and per runner into one canonical JSON
//! report (RFC 8785 bytes, BLAKE3-256 digest):
//!
//! 1. `sqlite-oracle` — the shared semantic oracle over the `SQLite` reference
//!    backend (`proof_remote::SqliteReferenceBackend`, local mode);
//! 2. `postgres-parity` — the same oracle boundary over the P-0010 verified
//!    import plus parity mirror (`proof_pg::parity::PostgresBackend`);
//! 3. `http-server` — server mode driven through the real HTTP router.
//!
//! The report proves byte-identical oracle traces where mirrored, records the
//! ratified stable not-mirrored error as an exact observable, and precisely
//! bounds every other divergence with an explicit classification plus named
//! field exclusions. Nothing is silently normalized.

#![allow(clippy::duration_suboptimal_units, clippy::too_many_lines)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
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
use proof_application::{
    AddChangeSetEditsCommand, ApprovalName, ApproveChangeSetCommand, BuildLocalizedContextCommand,
    ChangeSetEdit, ChangeSetId, ChangeSetIntent, CommitChangeSetCommand, CreateChangeSetCommand,
    CreateEditionCommand, CreateEnvironmentCommand, EditId, EnvironmentId, IdempotencyKey,
    InitializeWorkspaceCommand, IssueContentResourceIntentCommand, LocaleId,
    LocalizedContentRepository, LocalizedContentTarget, LocalizedContextLimits,
    LocalizedPolicyRule, ObjectCreateEdit, ObjectId, PromoteReleaseCommand, ProofId, ReleaseId,
    SchemaCreateEdit, SchemaId, SchemaVersion, SubmitChangeSetCommand, Timestamp,
    add_changeset_edits, approve_changeset, commit_changeset, create_changeset, create_edition,
    create_environment, initialize_workspace, promote_release, submit_changeset,
    validate_changeset,
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider,
    authority::{AuthorityPayloadProfile, sign_authority_payload},
};
use proof_canonical::{canonicalize, digest as artifact_digest, object_revision_digest};
use proof_domain::{ArtifactKind, ContentDigest, WorkspaceId};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use proof_pg::{
    DEFAULT_DSN, DSN_ENV, PgConfig,
    migration::SESSION_BOUNDARY_V2_DDL,
    parity::{PostgresBackend, prepare_parity_backend},
    schema::ALL_TABLE_DDL,
    wiring::PgRuntime,
};
use proof_remote::{
    AuthorityHeadV1, OracleTraceV1, RemoteOperationV1, SqliteReferenceBackend, StorageBackend,
    authority::{
        RemoteAuthorityRecordV1, RemotePrincipalStatusApiVersion, RemotePrincipalStatusV2,
        RemotePrincipalType, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
        WorkspaceRoleAssignmentV1, WorkspaceRoleRevocationV1,
    },
    derive_key_digest,
    identity::{
        AuthenticatedActorContextApiVersion, AuthenticatedActorContextHumanV2,
        AuthenticatedActorContextV2, OidcAuthenticatedSubjectApiVersion,
        OidcHumanAuthenticationProfile,
    },
    oracle::IdentityFixtureV1,
    registry::{RemoteApplicationConsequenceV1, operation_effect_digest},
};
use proof_server::{AppState, ServerConfig, routes::router};
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const WS_ID: &str = "019d1000-0000-7000-8000-000000000101";
const REQUESTER: &str = "019d1000-0000-7000-8000-000000000102";
const OPERATOR: &str = "019d1000-0000-7000-8000-000000000103";
const HUMAN_BINDING_ID: &str = "019d1000-0000-7000-8000-000000000104";
const AGENT_BINDING_ID: &str = "019d1000-0000-7000-8000-000000000105";
const DELEGATION_ID: &str = "019d1000-0000-7000-8000-000000000106";
const AUTH_EVENT_ID: &str = "019d1000-0000-7000-8000-000000000107";
const SUBJECT: &str = "human-conformance";

const CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000110";
const SOURCE_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000133";
const SCHEMA_EDIT_ID: &str = "019d1000-0000-7000-8000-000000000111";
const OBJECT_EDIT_ID: &str = "019d1000-0000-7000-8000-000000000112";
const OBJECT_ID: &str = "019d1000-0000-7000-8000-000000000113";
const EDITION_ID: &str = "019d1000-0000-7000-8000-000000000114";
const RELEASE_ID: &str = "019d1000-0000-7000-8000-000000000115";
const PROOF_ID: &str = "019d1000-0000-7000-8000-000000000116";
const INTENT_ID: &str = "019d1000-0000-7000-8000-000000000117";
const CONTEXT_PACK_ID: &str = "019d1000-0000-7000-8000-000000000118";
const ASSIGNMENT_ID: &str = "019d1000-0000-7000-8000-000000000119";
const ENVIRONMENT_ID: &str = "preview";
const SCHEMA_ID: &str = "campaign";
const LOCALE: &str = "fr-FR";

const DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000120";
const ADD_KEY: &str = "019d1000-0000-7000-8000-000000000121";
const COMMIT_KEY: &str = "019d1000-0000-7000-8000-000000000122";
const EDITION_KEY: &str = "019d1000-0000-7000-8000-000000000123";
const ENVIRONMENT_KEY: &str = "019d1000-0000-7000-8000-000000000124";
const RELEASE_KEY: &str = "019d1000-0000-7000-8000-000000000125";
const INTENT_KEY: &str = "019d1000-0000-7000-8000-000000000126";
const CONTEXT_KEY: &str = "019d1000-0000-7000-8000-000000000127";
const ASSIGN_KEY: &str = "019d1000-0000-7000-8000-000000000128";
const REVOKE_KEY: &str = "019d1000-0000-7000-8000-000000000129";
const CREATE_KEY: &str = "019d1000-0000-7000-8000-000000000132";
const SOURCE_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000134";

const AUTHENTICATED_AT: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 4_001;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x31; 32];

/// Derive-key context for the report digest (closed report namespace).
const REPORT_DIGEST_CONTEXT: &str = "proof:milestone3-conformance-report:v1";
/// Canonical trace-digest context, mirroring the P-0010 parity runner.
const TRACE_DIGEST_CONTEXT: &str = "proof:oracle-trace:v1";

// The closed classification set recorded in the report legend.
const CLASS_BYTE_IDENTICAL: &str = "byte_identical";
const CLASS_NOT_MIRRORED: &str = "not_mirrored_stable_error";
const CLASS_UNREGISTERED: &str = "oracle_unregistered_operation";
const CLASS_GOVERNED_PROJECTION_ONLY: &str = "server_governed_projection_only";
const CLASS_ADAPTER_PROJECTED: &str = "adapter_projected";
const CLASS_HTTP_NATIVE: &str = "http_adapter_native";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static SCHEMA_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn dsn() -> String {
    std::env::var(DSN_ENV).unwrap_or_else(|_| DEFAULT_DSN.to_owned())
}

fn fresh_dir() -> PathBuf {
    let ordinal = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("proof-conf-local-{}-{ordinal}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).expect("stale temp dir must be removable");
    }
    fs::create_dir_all(&path).expect("temp dir must be creatable");
    path
}

fn deterministic_digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn now_timestamp() -> Timestamp {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is past the epoch");
    Timestamp::from_unix_timestamp_nanos(i128::try_from(duration.as_nanos()).unwrap())
        .expect("nanos are in range")
}

fn timestamp_offset(seconds: i64) -> Timestamp {
    let nanos = now_timestamp().unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000;
    Timestamp::from_unix_timestamp_nanos(nanos).expect("offset nanos are in range")
}

/// Builds a closed Human actor context for one shared operation pair (the
/// fixed fixture values mirror the retained P-0010 parity harness).
fn actor_context(name: &str, version: &str) -> AuthenticatedActorContextV2 {
    AuthenticatedActorContextV2::Human(AuthenticatedActorContextHumanV2 {
        api_version: AuthenticatedActorContextApiVersion::V1,
        audience: format!("proof://workspace/{WS_ID}"),
        authentication_profile: OidcHumanAuthenticationProfile::V1,
        oidc_issuer_configuration_digest: deterministic_digest(0xa1),
        normalized_input_digest: deterministic_digest(0xa2),
        requesting_subject: proof_remote::OidcAuthenticatedSubjectV1 {
            api_version: OidcAuthenticatedSubjectApiVersion::V1,
            issuer: "https://identity.example.test".to_owned(),
            provider: "proof/oidc".to_owned(),
            subject: SUBJECT.to_owned(),
        },
        requesting_subject_commitment: deterministic_digest(0xa3),
        requesting_binding_id: HUMAN_BINDING_ID.to_owned(),
        requesting_binding_record_digest: deterministic_digest(0xa4),
        requesting_principal_id: REQUESTER.to_owned(),
        authentication_event_id: AUTH_EVENT_ID.to_owned(),
        authentication_event_digest: deterministic_digest(0xa5),
        operation: RemoteOperationV1 {
            name: name.to_owned(),
            version: version.to_owned(),
        },
        authenticated_at: AUTHENTICATED_AT.parse::<Timestamp>().expect("fixed stamp"),
        evaluated_authority_head: AuthorityHeadV1 {
            sequence: 41,
            record_digest: deterministic_digest(0x11),
        },
        workspace_id: WS_ID.to_owned(),
    })
}

fn shared_operation(name: &str) -> AuthenticatedActorContextV2 {
    // The registered version of each row: content ChangeSet rows are v2.
    let version = match name {
        "changeset.add" | "changeset.create" | "changeset.get" => {
            format!("proof.dev/operation/{name}/v2")
        }
        _ => format!("proof.dev/operation/{name}/v1"),
    };
    actor_context(name, &version)
}

fn schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties": false,
        "properties": {
            "legal": { "type": "string" },
            "slug": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["legal", "slug", "title"],
        "type": "object",
        "x-proof-localizable": ["/legal", "/title"],
    });
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: artifact_digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn object_edit(edit_id: &str, object_id: &str, content: &Value) -> ChangeSetEdit {
    let object_id = object_id.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical = canonicalize(content).unwrap();
    let object_digest =
        object_revision_digest(object_id, &schema_id, schema_version, content).unwrap();
    ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
        edit_id: edit_id.parse::<EditId>().unwrap(),
        object_id,
        schema_id,
        schema_version,
        canonical_content: canonical.as_str().to_owned(),
        object_digest,
    })
}

/// Builds the released localized baseline, a localized `ContextPack`, and one
/// draft localized `ChangeSet` created through the shared oracle itself, so
/// `changeset.get/v2` has typed state to read on the reference path.
fn conformance_workspace(root: &Path) -> LocalWorkspace {
    let workspace = LocalWorkspace::with_deterministic_authority_adapter(
        root,
        DeterministicLocalAuthorityAdapter::new(
            DETERMINISTIC_UID,
            AUTHENTICATED_AT.parse::<Timestamp>().expect("fixed stamp"),
            DETERMINISTIC_SUBJECT_BLIND,
        ),
    )
    .expect("the deterministic Workspace must select the fresh root");

    initialize_workspace(
        &workspace,
        InitializeWorkspaceCommand {
            workspace_id: WS_ID.parse().expect("fixed workspace identity"),
            bootstrap_principal_id: REQUESTER.parse().expect("fixed principal identity"),
        },
    )
    .expect("the deterministic Workspace must initialize");

    create_changeset(
        &workspace,
        CreateChangeSetCommand {
            changeset_id: CHANGESET_ID.parse::<ChangeSetId>().unwrap(),
            intent: ChangeSetIntent::new("Create the conformance baseline").unwrap(),
            requested_base_state: None,
            idempotency_key: DRAFT_KEY.parse::<IdempotencyKey>().unwrap(),
            created_at: "2026-08-21T10:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        &workspace,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            edits: vec![
                schema_edit(SCHEMA_EDIT_ID, SCHEMA_ID),
                object_edit(
                    OBJECT_EDIT_ID,
                    OBJECT_ID,
                    &json!({
                        "legal": "Standard terms apply",
                        "slug": "summer-campaign",
                        "title": "Summer campaign",
                    }),
                ),
            ],
            idempotency_key: ADD_KEY.parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(&workspace, CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        &workspace,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-21T10:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &workspace,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-21T10:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        &workspace,
        CommitChangeSetCommand {
            changeset_id: CHANGESET_ID.parse().unwrap(),
            idempotency_key: COMMIT_KEY.parse().unwrap(),
            committed_at: "2026-08-21T10:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &workspace,
        CreateEditionCommand {
            edition_id: EDITION_ID.parse().unwrap(),
            idempotency_key: EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-21T10:04:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        &workspace,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: ENVIRONMENT_KEY.parse().unwrap(),
            created_at: "2026-08-21T10:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        &workspace,
        PromoteReleaseCommand {
            release_id: RELEASE_ID.parse::<ReleaseId>().unwrap(),
            proof_id: PROOF_ID.parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: EDITION_ID.parse().unwrap(),
            idempotency_key: RELEASE_KEY.parse().unwrap(),
            released_at: "2026-08-21T10:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let intent = workspace
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: INTENT_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id: OBJECT_ID.parse::<ObjectId>().unwrap(),
                schema_id: SchemaId::new(SCHEMA_ID).unwrap(),
                locale: LOCALE.parse::<LocaleId>().unwrap(),
            }],
            creations: Vec::new(),
            idempotency_key: INTENT_KEY.parse().unwrap(),
            issued_at: "2026-08-21T12:00:08Z".parse().unwrap(),
        })
        .unwrap();

    let pack = workspace
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: CONTEXT_PACK_ID.parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: LOCALE.parse().unwrap(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Forbidden terms".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 2,
                max_validation_attempts: 2,
                max_bytes: 65_536,
            },
            idempotency_key: CONTEXT_KEY.parse().unwrap(),
            created_at: "2026-08-21T12:00:10Z".parse().unwrap(),
            expires_at: "2026-08-21T13:00:10Z".parse().unwrap(),
        })
        .unwrap();

    // The draft source ChangeSet for `changeset.get/v2` is created through the
    // shared oracle itself (setup trace; not part of the compared sequence).
    let mut backend = SqliteReferenceBackend::new(&workspace);
    let create_input = json!({
        "api_version": "proof.dev/operation/changeset.create/v2",
        "changeset_id": SOURCE_CHANGESET_ID,
        "context_pack_digest": pack.context_pack_digest.to_string(),
        "context_pack_id": CONTEXT_PACK_ID,
        "created_at": "2026-08-21T12:30:00Z",
        "idempotency_key": CREATE_KEY,
        "intent": "Conformance report source ChangeSet",
        "resource_intent_digest": intent.intent_digest.to_string(),
        "resource_intent_id": INTENT_ID,
    });
    let setup_trace = backend
        .run(&create_input, &shared_operation("changeset.create"))
        .expect("fixture changeset.create must dispatch over the reference path");
    if let proof_remote::OracleOutcome::StableProblem(problem) = &setup_trace.outcome {
        panic!(
            "fixture changeset.create produced stable problem {} for operation {:?}",
            problem.code,
            serde_json::to_value(&setup_trace).unwrap()
        );
    }
    let source_content = json!({
        "legal": "Des conditions standard s’appliquent",
        "slug": "summer-campaign",
        "title": "Campagne d’été",
    });
    let baseline_content = json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest = object_revision_digest(
        OBJECT_ID.parse().unwrap(),
        &SchemaId::new(SCHEMA_ID).unwrap(),
        SchemaVersion::new(1).unwrap(),
        &baseline_content,
    )
    .unwrap();
    let add_input = json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": SOURCE_CHANGESET_ID,
        "edits": [{
            "api_version": "proof.dev/edit/v2",
            "content": source_content,
            "expected_source": {
                "digest": source_digest.to_string(),
                "revision": 1,
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            "expected_target": null,
            "kind": "object.locale.put",
            "locale": LOCALE,
            "object_id": OBJECT_ID,
            "repair_of_validation_result_digest": null,
            "supersedes_edit_id": null,
        }],
        "idempotency_key": SOURCE_ADD_KEY,
    });
    let add_trace = backend
        .run(&add_input, &shared_operation("changeset.add"))
        .expect("fixture changeset.add must dispatch over the reference path");
    if let proof_remote::OracleOutcome::StableProblem(problem) = &add_trace.outcome {
        panic!(
            "fixture changeset.add produced stable problem {}",
            problem.code
        );
    }

    workspace
}

/// Computes the canonical JSON digest of one trace under the exact P-0010
/// parity context so digests are comparable across runners and runs.
fn trace_digest(trace: &OracleTraceV1) -> ContentDigest {
    let value = serde_json::to_value(trace).expect("trace serialization");
    let canonical = canonicalize(&value).expect("trace canonicalization");
    derive_key_digest(TRACE_DIGEST_CONTEXT, canonical.as_bytes())
}

/// One oracle-runner observation: a produced trace or the exact error text.
enum OracleRun {
    Trace(OracleTraceV1),
    Error(String),
}

fn run_oracle_step(
    backend: &mut dyn StorageBackend,
    input: &Value,
    context: &AuthenticatedActorContextV2,
) -> OracleRun {
    match backend.run(input, context) {
        Ok(trace) => OracleRun::Trace(trace),
        Err(error) => OracleRun::Error(error.to_string()),
    }
}

fn expect_trace<'a>(run: &'a OracleRun, label: &'a str) -> &'a OracleTraceV1 {
    match run {
        OracleRun::Trace(trace) => trace,
        OracleRun::Error(message) => panic!("{label} must produce a trace, got: {message}"),
    }
}

fn expect_error<'a>(run: &'a OracleRun, label: &'a str) -> &'a str {
    match run {
        OracleRun::Trace(_) => panic!("{label} must fail closed, found a trace"),
        OracleRun::Error(message) => message,
    }
}

/// The isolated `PostgreSQL` parity fixture: a dedicated schema populated by
/// the verified SQLite-to-PostgreSQL import plus parity facts.
struct ParityFixture {
    runtime: PgRuntime,
    schema: String,
}

impl ParityFixture {
    fn new(source: &LocalWorkspace) -> Self {
        let runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse::<WorkspaceId>().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
        let schema = format!(
            "p0013_conf_parity_{}_{}",
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        let mut fixture = Self { runtime, schema };
        fixture
            .runtime
            .client_mut()
            .batch_execute(&format!("CREATE SCHEMA \"{}\"", fixture.schema))
            .expect("create isolated parity schema");
        fixture
            .runtime
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{}\"", fixture.schema))
            .expect("set parity search path");
        prepare_parity_backend(source, &mut fixture.runtime)
            .expect("verified SQLite-to-PostgreSQL parity import");
        fixture
    }
}

impl Drop for ParityFixture {
    fn drop(&mut self) {
        let _ = self
            .runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

/// One isolated server-mode fixture: full table surface in a dedicated
/// schema, seeded authority facts, a live session with CSRF synchronizer,
/// the operating Agent binding signer, and an isolated verification handle.
struct ServerFixture {
    state: AppState,
    query: PgRuntime,
    schema: String,
    session_cookie: String,
    csrf: String,
    agent_provider: Ed25519SigningProvider,
}

impl ServerFixture {
    fn new() -> Self {
        let schema = format!(
            "p0013_conf_server_{}_{}",
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
            client.batch_execute(SESSION_BOUNDARY_V2_DDL).unwrap();
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
                     ) VALUES (1, $1, 1, 0, 10, 0, 0, $2, 10, $3, NULL, NULL, NULL)",
                    &[
                        &WS_ID,
                        &deterministic_digest(0xaa).to_string(),
                        &deterministic_digest(0x73).to_string(),
                    ],
                )
                .unwrap();
            let metadata = canonicalize(&json!({
                "principal_id": REQUESTER,
                "storage_schema_version": 1,
            }))
            .unwrap();
            client
                .execute(
                    "INSERT INTO facts
                         (fact_id, workspace_id, fact_kind, authority_sequence,
                          fact_digest, body, committed_at)
                     VALUES ('workspace/metadata', $1, 'workspace_metadata', 0, $2, $3, now())",
                    &[
                        &WS_ID,
                        &deterministic_digest(0x74).to_string(),
                        &metadata.as_bytes(),
                    ],
                )
                .unwrap();
        }
        *state.pg.lock().unwrap() = Some(runtime);

        // A distinct session-store runtime attached to the same schema.
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

        let mut query = PgRuntime::connect(PgConfig::new(
            dsn(),
            WS_ID.parse().unwrap(),
            Duration::from_secs(60),
        ))
        .expect("connect verification connection");
        query
            .client_mut()
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("verification search path");

        seed_human_binding(&state);
        seed_principal_status(&state, REQUESTER, RemotePrincipalType::Human, true);
        seed_principal_status(&state, OPERATOR, RemotePrincipalType::Agent, true);
        seed_role_assignment(
            &state,
            REQUESTER,
            WorkspaceRole::IdentityAdmin,
            "019d1000-0000-7000-8000-000000000130",
        );
        seed_role_assignment(
            &state,
            REQUESTER,
            WorkspaceRole::ContentRequester,
            "019d1000-0000-7000-8000-000000000131",
        );
        seed_authority_root(&state);
        let agent_provider = seed_agent_binding(&state);
        seed_delegation(&state);

        let session = state
            .sessions
            .create(WS_ID, REQUESTER, HUMAN_BINDING_ID, AUTH_EVENT_ID)
            .expect("session is created");
        let csrf = state
            .sessions
            .issue_csrf(&session)
            .expect("CSRF synchronizer issued");

        Self {
            state,
            query,
            schema,
            session_cookie: format!("__Host-Http-Proof-Session={}", session.as_str()),
            csrf: csrf.value,
            agent_provider,
        }
    }

    fn row(&mut self, sql: &str) -> (String, Vec<u8>) {
        let row = self
            .query
            .client_mut()
            .query_one(sql, &[])
            .expect("server verification row");
        (row.get(0), row.get(1))
    }

    fn scalar(&mut self, sql: &str) -> String {
        self.query
            .client_mut()
            .query_one(sql, &[])
            .expect("server verification scalar")
            .get(0)
    }

    fn import_content_from(&mut self, source_schema: &str) {
        self.query
            .client_mut()
            .batch_execute(&format!(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence,
                     fact_digest, body, committed_at
                 )
                 SELECT fact_id, workspace_id, fact_kind, authority_sequence,
                        fact_digest, body, committed_at
                 FROM \"{source_schema}\".facts
                 WHERE fact_kind IN (
                     'context_pack', 'localized_changeset', 'localized_edit',
                     'resource_intent'
                 )
                 ON CONFLICT (fact_id) DO NOTHING;
                 UPDATE workspace_write_head AS target
                 SET content_sequence = source.content_sequence,
                     content_head_digest = source.content_head_digest
                 FROM \"{source_schema}\".workspace_write_head AS source
                 WHERE target.singleton = 1 AND source.singleton = 1;"
            ))
            .expect("import the exact content facts exercised by server mode");
    }
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        let _ = self
            .query
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.schema));
    }
}

fn insert_fact(
    state: &AppState,
    fact_id: &str,
    fact_kind: &str,
    fact_digest: ContentDigest,
    body: &Value,
) {
    let mut guard = state.pg.lock().unwrap();
    let runtime = guard.as_mut().unwrap();
    runtime
        .client_mut()
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, $3, 0, $4, $5, now())",
            &[
                &fact_id,
                &WS_ID,
                &fact_kind,
                &fact_digest.to_string(),
                &canonicalize(body).unwrap().as_bytes(),
            ],
        )
        .unwrap();
}

fn seed_human_binding(state: &AppState) {
    use proof_remote::identity::{
        OidcPrincipalBindingApiVersion, OidcPrincipalBindingPrivateApiVersion,
        OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
        OidcSubjectCommitmentInputApiVersion, OidcSubjectCommitmentInputV1,
        OidcSubjectCommitmentOpeningApiVersion, OidcSubjectCommitmentOpeningV1, encode_blind,
        subject_commitment_digest,
    };

    let subject = proof_remote::OidcAuthenticatedSubjectV1 {
        api_version: OidcAuthenticatedSubjectApiVersion::V1,
        issuer: "https://identity.example.test".to_owned(),
        provider: "proof/oidc".to_owned(),
        subject: SUBJECT.to_owned(),
    };
    let commitment_input = OidcSubjectCommitmentInputV1 {
        api_version: OidcSubjectCommitmentInputApiVersion::V1,
        blind: encode_blind(&[0x42_u8; 32]),
        subject: subject.clone(),
        workspace_id: WS_ID.to_owned(),
    };
    let subject_commitment = subject_commitment_digest(&commitment_input).unwrap();
    let issuer_digest = IdentityFixtureV1::deterministic()
        .issuer_configuration
        .digest()
        .unwrap();
    let public = OidcPrincipalBindingV1 {
        api_version: OidcPrincipalBindingApiVersion::V1,
        workspace_id: WS_ID.to_owned(),
        binding_id: HUMAN_BINDING_ID.to_owned(),
        principal_id: REQUESTER.to_owned(),
        subject_commitment,
        oidc_issuer_configuration_digest: issuer_digest,
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
        opening: OidcSubjectCommitmentOpeningV1 {
            api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
            commitment: subject_commitment,
            input: commitment_input,
        },
        oidc_issuer_configuration_digest: issuer_digest,
        binding_record_digest,
    };
    insert_fact(
        state,
        &format!("oidc_binding/{HUMAN_BINDING_ID}"),
        "oidc_public_binding",
        public.binding_record_digest().unwrap(),
        &serde_json::to_value(&public).unwrap(),
    );
    insert_fact(
        state,
        &format!("oidc_private_binding/{HUMAN_BINDING_ID}"),
        "oidc_private_binding",
        deterministic_digest(0x12),
        &serde_json::to_value(&private).unwrap(),
    );
}

fn seed_principal_status(
    state: &AppState,
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
        reason: "conformance-report-fixture".to_owned(),
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
    insert_fact(
        state,
        &format!("principal_status/{principal_id}"),
        "principal_status",
        RemoteAuthorityRecordV1::principal_status(status.clone()).digest(),
        &serde_json::to_value(&status).unwrap(),
    );
}

fn seed_role_assignment(
    state: &AppState,
    principal_id: &str,
    role: WorkspaceRole,
    assignment_id: &str,
) {
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
    let assignment_body = serde_json::to_value(&assignment).unwrap();
    insert_fact(
        state,
        &format!("workspace_role_assignment/{assignment_id}"),
        "workspace_role_assignment",
        RemoteAuthorityRecordV1::workspace_role_assignment(assignment).digest(),
        &assignment_body,
    );
}

fn seed_authority_root(state: &AppState) {
    insert_fact(
        state,
        "workspace_authority_root",
        "workspace_authority_root",
        deterministic_digest(0x20),
        &json!({
            "api_version": "proof.dev/workspace-authority-root/v1",
            "workspace_id": WS_ID,
            "authority_key_id":
                "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
        }),
    );
}

fn seed_agent_binding(state: &AppState) -> Ed25519SigningProvider {
    let provider = Ed25519SigningProvider::from_secret_bytes(&[0x33_u8; 32]);
    let metadata = provider.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id.clone()).unwrap();
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
        public_key: Ed25519PublicKey::new(BASE64.encode(&metadata.public_key)).unwrap(),
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
    let binding_body = serde_json::to_value(&binding).unwrap();
    insert_fact(
        state,
        &format!("agent_binding/{AGENT_BINDING_ID}"),
        "agent_binding",
        RemoteAuthorityRecordV1::agent_binding_issue(binding).digest(),
        &binding_body,
    );
    provider
}

fn seed_delegation(state: &AppState) {
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
    insert_fact(
        state,
        &format!("delegation/{DELEGATION_ID}"),
        "delegation",
        RemoteAuthorityRecordV1::delegation_issue(delegation.clone()).digest(),
        &serde_json::to_value(delegation).unwrap(),
    );
}

/// Signs a fresh dual-auth Agent invocation for `workspace.status/v1`.
fn build_agent_invocation(provider: &Ed25519SigningProvider) -> AuthenticatedInvocationV1 {
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
    let canonical_command = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
    let payload = AuthenticatedCommandV1 {
        api_version: AuthenticatedCommandApiVersion::V1,
        audience: AuthorityAudience::for_workspace(WS_ID.parse().unwrap()),
        workspace_id: WS_ID.parse().unwrap(),
        operation: AuthorityOperation::WorkspaceStatusV1,
        binding_id: AGENT_BINDING_ID.parse().unwrap(),
        requesting_principal_id: REQUESTER.parse().unwrap(),
        operating_principal_id: OPERATOR.parse().unwrap(),
        delegation_id: DELEGATION_ID.parse().unwrap(),
        command_digest: artifact_digest(ArtifactKind::CommandV1, &canonical_command),
        idempotency_key: None,
        presentation_id: "019d1000-0000-7000-8000-000000000140".parse().unwrap(),
        issued_at: timestamp_offset(-10),
        expires_at: timestamp_offset(120),
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

async fn response_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body is readable");
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

/// Drives one authenticated operation POST through the real HTTP router.
async fn post_operation(
    app: axum::Router,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Value,
) -> (StatusCode, Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::HOST, "proof.example.test")
                .header(header::ORIGIN, "https://proof.example.test")
                .header("proof-csrf", csrf)
                .header(header::COOKIE, cookie)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, response_json(resp).await)
}

fn human_body(operation: (&str, &str), input: &Value) -> Value {
    let idempotency_key = input.get("idempotency_key").cloned().unwrap_or(Value::Null);
    json!({
        "api_version": "proof.dev/http-human-operation-request/v1",
        "workspace_id": WS_ID,
        "operation": { "name": operation.0, "version": operation.1 },
        "correlation_id": null,
        "idempotency_key": idempotency_key,
        "input": input,
    })
}

fn entry(step: usize, runner: &str, outcome: &Value) -> Value {
    let mut object = json!({ "step": step, "runner": runner });
    let map = object.as_object_mut().unwrap();
    for (key, value) in outcome.as_object().expect("outcome object") {
        map.insert(key.clone(), value.clone());
    }
    object
}

fn comparison(pair: [&str; 2], step: usize, verdict: &Value) -> Value {
    let mut object = json!({ "pair": [pair[0], pair[1]], "step": step });
    let map = object.as_object_mut().unwrap();
    for (key, value) in verdict.as_object().expect("verdict object") {
        map.insert(key.clone(), value.clone());
    }
    object
}

/// Exclusion record: one named field that differs between compared bytes,
/// with its contract justification.
fn exclusion(step: usize, field: &str, justification: &str) -> Value {
    json!({
        "step": step,
        "field": field,
        "justification": justification,
    })
}

/// Verifies the committed typed role-assignment record against the committed
/// decision row and the success envelope, returning its exact record digest.
#[allow(clippy::too_many_lines)]
fn verify_assignment_record(server: &mut ServerFixture, envelope: &Value) -> ContentDigest {
    let assignment_fact_id = format!("workspace_role_assignment/{ASSIGNMENT_ID}");
    let (fact_digest_text, fact_body) = server.row(&format!(
        "SELECT fact_digest, body FROM facts WHERE fact_id = '{assignment_fact_id}'"
    ));
    let (decision_digest_text, decision_body) = server.row(
        "SELECT decision_digest, body FROM authorization_decisions \
         WHERE operation = 'workspace-role.assign' \
         ORDER BY authority_sequence DESC LIMIT 1",
    );
    let decision: Value = serde_json::from_slice(&decision_body).unwrap();
    let record: WorkspaceRoleAssignmentV1 = serde_json::from_slice(&fact_body).unwrap();

    assert_eq!(
        serde_json::to_value(&record).unwrap()["api_version"],
        "proof.dev/workspace-role-assignment/v1"
    );
    assert_eq!(record.workspace_id, WS_ID);
    assert_eq!(record.assignment_id, ASSIGNMENT_ID);
    assert_eq!(record.principal_id, OPERATOR);
    assert_eq!(record.role, WorkspaceRole::ContentRequester);
    assert_eq!(record.assigned_by_principal_id, REQUESTER);
    assert_eq!(
        record.assigned_by_actor_context_digest.to_string(),
        decision["actor_context_digest"].as_str().unwrap(),
        "the actor-context binding must equal the committed signed decision"
    );
    assert_eq!(
        record.evaluated_authority_head.sequence.to_string(),
        decision["authority_sequence"].to_string()
    );
    assert_eq!(
        record.evaluated_authority_head.record_digest.to_string(),
        decision_digest_text
    );
    assert_eq!(
        record.authority_key_id,
        decision["authority_key_id"].as_str().unwrap()
    );
    assert_eq!(
        record.previous_authority_record_digest.to_string(),
        decision_digest_text,
        "the previous-record binding must equal the committed decision digest"
    );

    // The single excluded volatile field is a well-formed wall-clock stamp.
    let raw = serde_json::to_value(&record).unwrap();
    raw["assigned_at"]
        .as_str()
        .expect("assigned_at carries the effect timestamp")
        .parse::<Timestamp>()
        .expect("assigned_at is an RFC 3339 timestamp");

    // The exact remote-authority-record digest reproduces from the stored
    // canonical bytes, and both consequence bindings point at it.
    let recomputed = RemoteAuthorityRecordV1::workspace_role_assignment(record).digest();
    assert_eq!(recomputed.to_string(), fact_digest_text);
    let (_, consequence_body) = server.row(
        "SELECT consequence_digest, body FROM application_consequences \
         WHERE operation = 'workspace-role.assign' \
         ORDER BY authority_sequence DESC LIMIT 1",
    );
    let consequence: RemoteApplicationConsequenceV1 =
        serde_json::from_slice(&consequence_body).unwrap();
    assert_eq!(
        consequence.application_effect_digest,
        Some(recomputed),
        "the success consequence binds the governed fact exactly"
    );
    assert_eq!(
        envelope["result_anchor"]["digest"].as_str(),
        consequence
            .result_digest
            .map(|value| value.to_string())
            .as_deref()
    );
    let record_value: Value = serde_json::from_slice(&fact_body).unwrap();
    assert_eq!(
        consequence.result_digest,
        operation_effect_digest(&record_value).ok(),
        "the result digest is the exact operation-effect digest of the typed record"
    );
    recomputed
}

/// Verifies the committed typed role-revocation record against the committed
/// decision row and the success envelope.
#[allow(clippy::too_many_lines)]
fn verify_revocation_record(server: &mut ServerFixture, envelope: &Value) {
    let (fact_digest_text, fact_body) = server.row(
        "SELECT fact_digest, body FROM facts \
         WHERE fact_kind = 'workspace_role_revocation' LIMIT 1",
    );
    let (decision_digest_text, decision_body) = server.row(
        "SELECT decision_digest, body FROM authorization_decisions \
         WHERE operation = 'workspace-role.revoke' \
         ORDER BY authority_sequence DESC LIMIT 1",
    );
    let decision: Value = serde_json::from_slice(&decision_body).unwrap();
    let revocation: WorkspaceRoleRevocationV1 = serde_json::from_slice(&fact_body).unwrap();

    assert_eq!(
        revocation.workspace_id, WS_ID,
        "revocation stays inside the dispatched Workspace"
    );
    assert_eq!(revocation.assignment_id, ASSIGNMENT_ID);
    assert_eq!(revocation.principal_id, OPERATOR);
    assert_eq!(revocation.role, WorkspaceRole::ContentRequester);
    assert_eq!(revocation.revoked_by_principal_id, REQUESTER);
    let assignment_digest = server.scalar(&format!(
        "SELECT fact_digest FROM facts \
         WHERE fact_id = 'workspace_role_assignment/{ASSIGNMENT_ID}'"
    ));
    assert_eq!(
        revocation.assignment_record_digest.to_string(),
        assignment_digest,
        "the revocation binds the exact target role-assignment fact"
    );
    assert_eq!(
        revocation.revoked_by_actor_context_digest.to_string(),
        decision["actor_context_digest"].as_str().unwrap()
    );
    assert_eq!(
        revocation
            .evaluated_authority_head
            .record_digest
            .to_string(),
        decision_digest_text
    );
    assert_eq!(
        revocation.evaluated_authority_head.sequence.to_string(),
        decision["authority_sequence"].to_string()
    );
    assert_eq!(
        revocation.authority_key_id,
        decision["authority_key_id"].as_str().unwrap()
    );
    assert_eq!(
        revocation.previous_authority_record_digest.to_string(),
        decision_digest_text
    );

    // The excluded volatile fields are well-formed wall-clock/identity mints.
    let raw = serde_json::to_value(&revocation).unwrap();
    raw["revoked_at"]
        .as_str()
        .expect("revoked_at carries the effect timestamp")
        .parse::<Timestamp>()
        .expect("revoked_at is an RFC 3339 timestamp");
    let revocation_id = raw["revocation_id"]
        .as_str()
        .and_then(|text| text.parse::<uuid::Uuid>().ok())
        .expect("revocation_id is a UUID minted by the server");
    assert_eq!(
        revocation_id.get_version_num(),
        7,
        "revocation_id is a UUIDv7"
    );

    let recomputed = RemoteAuthorityRecordV1::workspace_role_revocation(revocation).digest();
    assert_eq!(recomputed.to_string(), fact_digest_text);
    let (_, consequence_body) = server.row(
        "SELECT consequence_digest, body FROM application_consequences \
         WHERE operation = 'workspace-role.revoke' \
         ORDER BY authority_sequence DESC LIMIT 1",
    );
    let consequence: RemoteApplicationConsequenceV1 =
        serde_json::from_slice(&consequence_body).unwrap();
    assert_eq!(consequence.application_effect_digest, Some(recomputed));
    assert_eq!(
        envelope["result_anchor"]["digest"].as_str(),
        consequence
            .result_digest
            .map(|value| value.to_string())
            .as_deref()
    );
}

/// The Milestone-3 local/server conformance report: three runners, one
/// representative sequence, honest per-step classification, one canonical
/// report object whose BLAKE3 digest is printed to the test log.
#[test]
#[allow(clippy::too_many_lines)]
fn milestone3_conformance_report_three_runner_classification() {
    // ---------------------------------------------------------------
    // Phase 0: local-mode fixture (SQLite reference path).
    // ---------------------------------------------------------------
    let root = fresh_dir();
    let workspace = conformance_workspace(&root);

    // ---------------------------------------------------------------
    // Phase 1: PostgreSQL parity fixture via the P-0010 verified import.
    // ---------------------------------------------------------------
    let mut parity = ParityFixture::new(&workspace);

    // ---------------------------------------------------------------
    // Phase 2: shared-oracle steps on both storage backends.
    // ---------------------------------------------------------------
    let status_input = json!({});
    let status_context = shared_operation("workspace.status");
    let get_input = json!({
        "api_version": "proof.dev/operation/changeset.get/v2",
        "changeset_id": SOURCE_CHANGESET_ID,
    });
    let get_context = shared_operation("changeset.get");

    let mut sqlite = SqliteReferenceBackend::new(&workspace);
    let sqlite_status = run_oracle_step(&mut sqlite, &status_input, &status_context);
    let sqlite_get = run_oracle_step(&mut sqlite, &get_input, &get_context);
    let sqlite_unregistered: Vec<OracleRun> = [
        "workspace-role.assign",
        "workspace-role.revoke",
        "capabilities.discover",
    ]
    .iter()
    .map(|name| run_oracle_step(&mut sqlite, &json!({}), &shared_operation(name)))
    .collect();

    let mut postgres = PostgresBackend::new(&mut parity.runtime);
    let postgres_status = run_oracle_step(&mut postgres, &status_input, &status_context);
    let postgres_get = run_oracle_step(&mut postgres, &get_input, &get_context);
    let postgres_unregistered: Vec<OracleRun> = [
        "workspace-role.assign",
        "workspace-role.revoke",
        "capabilities.discover",
    ]
    .iter()
    .map(|name| run_oracle_step(&mut postgres, &json!({}), &shared_operation(name)))
    .collect();

    let sqlite_status_trace = expect_trace(&sqlite_status, "local workspace.status/v1");
    let postgres_status_trace = expect_trace(&postgres_status, "parity workspace.status/v1");
    assert!(matches!(
        sqlite_status_trace.outcome,
        proof_remote::OracleOutcome::TypedResult(_)
    ));
    assert_eq!(
        sqlite_status_trace, postgres_status_trace,
        "mirrored rows must be field-identical across backends"
    );
    assert_eq!(
        trace_digest(sqlite_status_trace),
        trace_digest(postgres_status_trace),
        "mirrored rows must have identical canonical trace digests"
    );

    // Keyed replay stability for the mirrored read (cheap, no re-import).
    let mut sqlite_replay = SqliteReferenceBackend::new(&workspace);
    let sqlite_replay_run = run_oracle_step(&mut sqlite_replay, &status_input, &status_context);
    let replay_a = expect_trace(&sqlite_replay_run, "SQLite replay");
    let mut postgres_replay = PostgresBackend::new(&mut parity.runtime);
    let postgres_replay_run = run_oracle_step(&mut postgres_replay, &status_input, &status_context);
    let replay_b = expect_trace(&postgres_replay_run, "PostgreSQL replay");
    assert_eq!(
        replay_a, sqlite_status_trace,
        "SQLite replay must not drift"
    );
    assert_eq!(
        replay_b, postgres_status_trace,
        "PostgreSQL replay must not drift"
    );

    // The changeset read is typed on both backends and byte-identical since
    // the P-0015 executor mirrored it onto the PostgreSQL parity path.
    let sqlite_get_trace = expect_trace(&sqlite_get, "local changeset.get/v2");
    let postgres_get_trace = expect_trace(&postgres_get, "parity changeset.get/v2");
    assert!(matches!(
        sqlite_get_trace.outcome,
        proof_remote::OracleOutcome::TypedResult(_)
    ));
    assert_eq!(
        sqlite_get_trace, postgres_get_trace,
        "the mirrored changeset read must be field-identical across backends"
    );
    assert_eq!(
        trace_digest(sqlite_get_trace),
        trace_digest(postgres_get_trace),
        "the mirrored changeset read must have an identical canonical digest"
    );
    for run in sqlite_unregistered
        .iter()
        .chain(postgres_unregistered.iter())
    {
        let message = expect_error(run, "rows outside the shared application registry");
        assert!(
            message.contains("unregistered remote operation"),
            "unexpected failure outside the ratified classification: {message}"
        );
    }

    // ---------------------------------------------------------------
    // Phase 3: server mode over the real HTTP router.
    // ---------------------------------------------------------------
    let mut server = ServerFixture::new();
    server.import_content_from(&parity.schema);
    let invocation_value =
        serde_json::to_value(build_agent_invocation(&server.agent_provider)).unwrap();
    let assign_input = json!({
        "principal_id": OPERATOR,
        "role": "content.requester",
        "assignment_id": ASSIGNMENT_ID,
        "idempotency_key": ASSIGN_KEY,
    });
    let revoke_input = json!({
        "assignment_id": ASSIGNMENT_ID,
        "reason": "conformance report cleanup",
        "idempotency_key": REVOKE_KEY,
    });

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let http_observations = runtime.block_on(async {
        let app = router(server.state.clone());

        // Step 5: capabilities discovery — public HTTP-native read.
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

        // Step 1 through the dual-auth Agent surface.
        let (status_code, status_envelope) = post_operation(
            app.clone(),
            "/api/v1/agent/operations/workspace.status/v1",
            &server.session_cookie,
            &server.csrf,
            json!({
                "api_version": "proof.dev/http-agent-operation-request/v1",
                "operation": {
                    "name": "workspace.status",
                    "version": "proof.dev/operation/workspace.status/v1"
                },
                "correlation_id": null,
                "invocation": invocation_value,
            }),
        )
        .await;
        assert_eq!(
            status_code,
            StatusCode::OK,
            "agent status must succeed: {status_envelope}"
        );

        // Step 2 through the direct-Human surface.
        let (get_code, get_envelope) = post_operation(
            app.clone(),
            "/api/v1/human/operations/changeset.get/v2",
            &server.session_cookie,
            &server.csrf,
            human_body(
                ("changeset.get", "proof.dev/operation/changeset.get/v2"),
                &get_input,
            ),
        )
        .await;
        assert_eq!(get_code, StatusCode::OK, "human changeset.get must succeed");

        // Step 3: typed role-assignment mutation.
        let (assign_code, assign_envelope) = post_operation(
            app.clone(),
            "/api/v1/human/operations/workspace-role.assign/v1",
            &server.session_cookie,
            &server.csrf,
            human_body(
                (
                    "workspace-role.assign",
                    "proof.dev/operation/workspace-role.assign/v1",
                ),
                &assign_input,
            ),
        )
        .await;
        assert_eq!(assign_code, StatusCode::OK, "role assignment must succeed");

        // Step 4: typed role-revocation mutation.
        let (revoke_code, revoke_envelope) = post_operation(
            app,
            "/api/v1/human/operations/workspace-role.revoke/v1",
            &server.session_cookie,
            &server.csrf,
            human_body(
                (
                    "workspace-role.revoke",
                    "proof.dev/operation/workspace-role.revoke/v1",
                ),
                &revoke_input,
            ),
        )
        .await;
        assert_eq!(revoke_code, StatusCode::OK, "role revocation must succeed");

        json!({
            "capabilities": capabilities,
            "status_envelope": status_envelope,
            "get_envelope": get_envelope,
            "assign_envelope": assign_envelope,
            "revoke_envelope": revoke_envelope,
        })
    });

    // Effect-free registry rows retain their decision and consequence without
    // manufacturing an application fact.
    let mut governed_count = |suffix: &str| {
        server.scalar(&format!(
            "SELECT COUNT(*)::text FROM facts WHERE fact_kind = 'governed_effect' \
             AND fact_id LIKE 'governed_effect/{suffix}/%'"
        ))
    };
    assert_eq!(governed_count("workspace.status"), "0");
    assert_eq!(governed_count("changeset.get"), "0");
    let mut consequence_count = |operation: &str| {
        server.scalar(&format!(
            "SELECT COUNT(*)::text FROM application_consequences \
             WHERE operation = '{operation}'"
        ))
    };
    assert_eq!(consequence_count("workspace.status"), "1");
    assert_eq!(consequence_count("changeset.get"), "1");

    let assignment_effect =
        verify_assignment_record(&mut server, &http_observations["assign_envelope"]);
    verify_revocation_record(&mut server, &http_observations["revoke_envelope"]);

    // ---------------------------------------------------------------
    // Phase 4: assemble the canonical report object.
    // ---------------------------------------------------------------
    let entries = vec![
        entry(
            1,
            "sqlite-oracle",
            &json!({ "outcome": "trace", "trace_digest_hex": trace_digest(sqlite_status_trace).to_string() }),
        ),
        entry(
            1,
            "postgres-parity",
            &json!({ "outcome": "trace", "trace_digest_hex": trace_digest(postgres_status_trace).to_string() }),
        ),
        entry(
            1,
            "http-server",
            &json!({
                "outcome": "classified",
                "classification": CLASS_GOVERNED_PROJECTION_ONLY,
                "observed": { "governed_effect_count": 0, "consequence_count": 1 },
                "note": "the server returns the opaque governed projection and retains decision/consequence evidence; EffectDigestRule::None forbids an application fact",
            }),
        ),
        entry(
            2,
            "sqlite-oracle",
            &json!({ "outcome": "trace", "trace_digest_hex": trace_digest(sqlite_get_trace).to_string() }),
        ),
        entry(
            2,
            "postgres-parity",
            &json!({ "outcome": "trace", "trace_digest_hex": trace_digest(postgres_get_trace).to_string() }),
        ),
        entry(
            2,
            "http-server",
            &json!({
                "outcome": "classified",
                "classification": CLASS_GOVERNED_PROJECTION_ONLY,
                "observed": { "governed_effect_count": 0, "consequence_count": 1 },
                "note": "the server wraps the read in the opaque governed projection; no content state is consulted and EffectDigestRule::None forbids an application fact",
            }),
        ),
        entry(
            3,
            "sqlite-oracle",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&sqlite_unregistered[0], "assign on sqlite"),
            }),
        ),
        entry(
            3,
            "postgres-parity",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&postgres_unregistered[0], "assign on postgres"),
            }),
        ),
        entry(
            3,
            "http-server",
            &json!({
                "outcome": "typed_record",
                "classification": CLASS_ADAPTER_PROJECTED,
                "record_api_version": "proof.dev/workspace-role-assignment/v1",
                "record_digest_hex": assignment_effect.to_string(),
                "verified_bindings": [
                    "assignment_id/principal_id/role equal the normalized input",
                    "assigned_by_principal_id equals the session principal",
                    "assigned_by_actor_context_digest equals the committed decision row",
                    "evaluated_authority_head equals the committed decision row",
                    "authority_key_id equals the committed decision row",
                    "previous_authority_record_digest equals the committed decision_digest column",
                    "RemoteAuthorityRecordV1 digest recomputes exactly from stored canonical bytes",
                    "consequence application_effect_digest equals the fact digest",
                ],
                "note": "runner A defines no semantics for this authority row; the server-side typed record was verified against the shared record vocabulary and the committed decision instead",
            }),
        ),
        entry(
            4,
            "sqlite-oracle",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&sqlite_unregistered[1], "revoke on sqlite"),
            }),
        ),
        entry(
            4,
            "postgres-parity",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&postgres_unregistered[1], "revoke on postgres"),
            }),
        ),
        entry(
            4,
            "http-server",
            &json!({
                "outcome": "typed_record",
                "classification": CLASS_ADAPTER_PROJECTED,
                "record_api_version": "proof.dev/workspace-role-revocation/v1",
                "note": "exact typed WorkspaceRoleRevocationV1 committed; volatile fields listed in exclusions; all authority bindings verified against the committed decision row",
            }),
        ),
        entry(
            5,
            "sqlite-oracle",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&sqlite_unregistered[2], "capabilities on sqlite"),
            }),
        ),
        entry(
            5,
            "postgres-parity",
            &json!({
                "outcome": "classified",
                "classification": CLASS_UNREGISTERED,
                "error": expect_error(&postgres_unregistered[2], "capabilities on postgres"),
            }),
        ),
        entry(
            5,
            "http-server",
            &json!({
                "outcome": "classified",
                "classification": CLASS_HTTP_NATIVE,
                "observed": {
                    "route_count": http_observations["capabilities"]["route_count"],
                    "registry_sha256_present": true,
                },
                "note": "served directly by the HTTP adapter from the frozen registry; adapter-specific case per the conformance plan",
            }),
        ),
    ];

    let comparisons = vec![
        comparison(
            ["sqlite-oracle", "postgres-parity"],
            1,
            &json!({
                "verdict": CLASS_BYTE_IDENTICAL,
                "replay": "stable",
                "basis": "field equality plus equal canonical trace digests on both backends including keyed replay",
            }),
        ),
        comparison(
            ["sqlite-oracle", "postgres-parity"],
            2,
            &json!({
                "verdict": CLASS_BYTE_IDENTICAL,
                "basis": "P-0015 mirrored the changeset read; field equality plus equal canonical trace digests on both backends",
            }),
        ),
        comparison(
            ["sqlite-oracle", "postgres-parity"],
            3,
            &json!({ "verdict": CLASS_UNREGISTERED }),
        ),
        comparison(
            ["sqlite-oracle", "postgres-parity"],
            4,
            &json!({ "verdict": CLASS_UNREGISTERED }),
        ),
        comparison(
            ["sqlite-oracle", "postgres-parity"],
            5,
            &json!({ "verdict": CLASS_UNREGISTERED }),
        ),
        comparison(
            ["sqlite-oracle", "http-server"],
            1,
            &json!({ "verdict": CLASS_GOVERNED_PROJECTION_ONLY }),
        ),
        comparison(
            ["sqlite-oracle", "http-server"],
            2,
            &json!({ "verdict": CLASS_GOVERNED_PROJECTION_ONLY }),
        ),
        comparison(
            ["sqlite-oracle", "http-server"],
            3,
            &json!({ "verdict": CLASS_ADAPTER_PROJECTED }),
        ),
        comparison(
            ["sqlite-oracle", "http-server"],
            4,
            &json!({ "verdict": CLASS_ADAPTER_PROJECTED }),
        ),
        comparison(
            ["sqlite-oracle", "http-server"],
            5,
            &json!({ "verdict": CLASS_HTTP_NATIVE }),
        ),
    ];

    let report = json!({
        "api_version": "proof.dev/conformance-report/milestone3-local-server/v1",
        "acceptance_criterion":
            "P-0013: the local/server conformance report proves byte-identical shared oracle traces in both modes",
        "contract_basis":
            "docs/architecture/collaboration-server.md §Conformance and falsification plan: a shared semantic oracle plus adapter-specific cases",
        "classification_legend": {
            CLASS_BYTE_IDENTICAL:
                "both runners produced byte-identical observables (field equality plus equal canonical RFC 8785 BLAKE3 digests)",
            CLASS_NOT_MIRRORED:
                "the PostgreSQL parity mirror fails closed with its ratified stable not-mirrored integrity error; the exact error text is the recorded observable",
            CLASS_UNREGISTERED:
                "the operation/version pair is outside the closed 14-row shared application authority registry, so no oracle trace can exist in either storage mode",
            CLASS_GOVERNED_PROJECTION_ONLY:
                "server mode returned the opaque proof.dev/governed-effect/v1 projection and retained decision/consequence evidence without an application fact, as required by EffectDigestRule::None",
            CLASS_ADAPTER_PROJECTED:
                "server mode emitted the exact contracted typed authority record; all non-volatile fields were verified against observable bindings, and remaining differences are named exclusions",
            CLASS_HTTP_NATIVE:
                "adapter-specific case served directly by the HTTP adapter; no shared-oracle semantics exist by contract",
        },
        "sequence": [
            { "index": 1, "class": "read", "operation": { "name": "workspace.status", "version": "proof.dev/operation/workspace.status/v1" } },
            { "index": 2, "class": "read", "operation": { "name": "changeset.get", "version": "proof.dev/operation/changeset.get/v2" } },
            { "index": 3, "class": "mutation", "operation": { "name": "workspace-role.assign", "version": "proof.dev/operation/workspace-role.assign/v1" } },
            { "index": 4, "class": "mutation", "operation": { "name": "workspace-role.revoke", "version": "proof.dev/operation/workspace-role.revoke/v1" } },
            { "index": 5, "class": "public-read", "operation": { "name": "capabilities.discover", "version": "proof.dev/operation/capabilities.discover/v1" } },
        ],
        "entries": entries,
        "comparisons": comparisons,
        "exclusions": [
            exclusion(3, "assigned_at", "wall-clock effect timestamp minted by the server (registry EffectDigestRule::RemoteAuthorityRecord with EffectTimestampField::AssignedAt); excluded from byte comparison, covered indirectly by exact remote-authority-record digest re-verification over the stored canonical bytes"),
            exclusion(4, "revoked_at", "wall-clock effect timestamp (EffectTimestampField::RevokedAt); same coverage as assigned_at"),
            exclusion(4, "revocation_id", "server-minted UUIDv7 identity; shape-verified but not reproducible outside the adapter"),
        ],
        "residual_boundary":
            "PG-backed semantic execution of mutation rows (a PostgreSQL implementation of the shared application operations beyond the two mirrored read rows) remains deferred; server mode currently commits decisions, consequences, and typed authority effects where the registry requires them without executing the shared domain state machines.",
        "execution_binding":
            "the report binds one execution. Within the run, the mirrored A<->B oracle traces are byte-identical (field equality plus equal canonical digests, including keyed replay), which is exactly what the acceptance criterion claims. Across executions, content-typed traces embed the local Workspace's per-instance Release signing-key identity (proof-local generates a fresh Ed25519 release signer per root) and server typed records embed wall-clock stamps and server-minted UUIDv7 identifiers, so cross-run byte-reproducibility of this artifact is bounded by those documented identities.",
    });

    // Internal consistency: every sequence step appears exactly once per
    // runner, every non-trace outcome carries a closed classification, and
    // the mirrored row pair is byte-identical by construction above.
    let runners = ["sqlite-oracle", "postgres-parity", "http-server"];
    for step_index in 1..=5_usize {
        for runner in runners {
            let count = entries
                .iter()
                .filter(|item| item["step"] == step_index && item["runner"] == runner)
                .count();
            assert_eq!(
                count, 1,
                "step {step_index} runner {runner} must appear exactly once"
            );
        }
    }
    assert_eq!(entries.len(), 15);
    assert_eq!(comparisons.len(), 10);
    for item in &comparisons {
        let verdict = item["verdict"].as_str().expect("verdict string");
        assert!(
            [
                CLASS_BYTE_IDENTICAL,
                CLASS_NOT_MIRRORED,
                CLASS_UNREGISTERED,
                CLASS_GOVERNED_PROJECTION_ONLY,
                CLASS_ADAPTER_PROJECTED,
                CLASS_HTTP_NATIVE,
            ]
            .contains(&verdict),
            "verdict {verdict} must come from the closed classification set"
        );
    }
    let identical = comparisons
        .iter()
        .find(|item| {
            item["pair"][0] == "sqlite-oracle"
                && item["pair"][1] == "postgres-parity"
                && item["step"] == 1
        })
        .expect("mirrored comparison exists");
    assert_eq!(identical["verdict"], CLASS_BYTE_IDENTICAL);

    // Canonicalize (RFC 8785), digest (BLAKE3-256 derive-key), persist, print.
    let canonical = canonicalize(&report).expect("report canonicalization");
    let report_digest = derive_key_digest(REPORT_DIGEST_CONTEXT, canonical.as_bytes());
    let report_path = std::env::temp_dir().join(format!(
        "p0013-conformance-report-{}.json",
        std::process::id()
    ));
    fs::write(
        &report_path,
        serde_json::to_string_pretty(&report).expect("pretty serialization"),
    )
    .expect("report file write");

    println!("milestone3 conformance report digest: {report_digest}");
    println!(
        "milestone3 conformance report path: {}",
        report_path.display()
    );
    println!("report canonical byte length: {}", canonical.as_str().len());
    println!(
        "per-step verdicts: s1 {CLASS_BYTE_IDENTICAL}(A-B)/{CLASS_GOVERNED_PROJECTION_ONLY}(A-C); \
         s2 {CLASS_NOT_MIRRORED}(A-B)/{CLASS_GOVERNED_PROJECTION_ONLY}(A-C); \
         s3+s4 {CLASS_UNREGISTERED}(A-B)/{CLASS_ADAPTER_PROJECTED}(A-C); \
         s5 {CLASS_UNREGISTERED}(A-B)/{CLASS_HTTP_NATIVE}(A-C)"
    );
}
