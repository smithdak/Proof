//! Parity implementation tests: the shared oracle runner produces
//! byte-identical traces on the `SQLite` reference path and the `PostgreSQL` path
//! for accepted, rejected, replay, and tampered-consequence scenarios.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
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
use proof_canonical::{canonicalize, digest as digest_canonical, object_revision_digest};
use proof_domain::{ArtifactKind, ContentDigest, WorkspaceId};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use proof_pg::{
    PgConfig,
    parity::{
        ParityOperation, ParityRunner, ParityScenario, PostgresBackend, prepare_parity_backend,
    },
    wiring::PgRuntime,
};
use proof_remote::identity::{
    AuthenticatedActorContextApiVersion, AuthenticatedActorContextHumanV2,
    OidcAuthenticatedSubjectApiVersion, OidcHumanAuthenticationProfile,
};
use proof_remote::{
    AuthenticatedActorContextV2, AuthorityHeadV1, RemoteOperationV1, SqliteReferenceBackend,
};
use serde_json::{Value, json};

const WORKSPACE_ID: &str = "019d1000-0000-7000-8000-000000000001";
const PRINCIPAL_ID: &str = "019d1000-0000-7000-8000-000000000002";
const CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000010";
const SCHEMA_EDIT_ID: &str = "019d1000-0000-7000-8000-000000000011";
const OBJECT_EDIT_ID: &str = "019d1000-0000-7000-8000-000000000012";
const OBJECT_ID: &str = "019d1000-0000-7000-8000-000000000013";
const EDITION_ID: &str = "019d1000-0000-7000-8000-000000000014";
const RELEASE_ID: &str = "019d1000-0000-7000-8000-000000000015";
const PROOF_ID: &str = "019d1000-0000-7000-8000-000000000016";
const INTENT_ID: &str = "019d1000-0000-7000-8000-000000000017";
const CONTEXT_PACK_ID: &str = "019d1000-0000-7000-8000-000000000018";
const ENVIRONMENT_ID: &str = "preview";
const SCHEMA_ID: &str = "campaign";
const LOCALE: &str = "fr-FR";
const DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000020";
const ADD_KEY: &str = "019d1000-0000-7000-8000-000000000021";
const COMMIT_KEY: &str = "019d1000-0000-7000-8000-000000000022";
const EDITION_KEY: &str = "019d1000-0000-7000-8000-000000000023";
const ENVIRONMENT_KEY: &str = "019d1000-0000-7000-8000-000000000024";
const RELEASE_KEY: &str = "019d1000-0000-7000-8000-000000000025";
const INTENT_KEY: &str = "019d1000-0000-7000-8000-000000000026";
const CONTEXT_KEY: &str = "019d1000-0000-7000-8000-000000000027";
const AUTHENTICATED_AT: &str = "2026-08-20T12:00:00Z";
const DETERMINISTIC_UID: u64 = 1_001;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x24; 32];

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static SCHEMA_COUNTER: AtomicU64 = AtomicU64::new(0);

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn fresh_dir() -> PathBuf {
    let ordinal = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("proof-parity-{}-{ordinal}", std::process::id()));
    if path.exists() {
        fs::remove_dir_all(&path).expect("stale parity tempdir must be removable");
    }
    fs::create_dir_all(&path).expect("parity tempdir must be creatable");
    path
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
        requesting_subject: proof_remote::OidcAuthenticatedSubjectV1 {
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

fn schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
    let document = serde_json::json!({
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
        document_digest: digest_canonical(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn object_edit(edit_id: &str, object_id: &str, schema_id: &str, content: &Value) -> ChangeSetEdit {
    let object_id = object_id.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(schema_id).unwrap();
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

/// A released v1 baseline plus a built localized `ContextPack`, so the
/// deterministic oracle can reproduce both `workspace.status/v1` and a keyed
/// `context.build/v2` replay.
#[expect(
    clippy::too_many_lines,
    reason = "the fixture makes the released baseline, resource intent, and ContextPack explicit"
)]
fn north_star_workspace(root: &Path) -> (LocalWorkspace, ContentDigest) {
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

    create_changeset(
        &workspace,
        CreateChangeSetCommand {
            changeset_id: CHANGESET_ID.parse::<ChangeSetId>().unwrap(),
            intent: ChangeSetIntent::new("Create the parity source").unwrap(),
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
                    SCHEMA_ID,
                    &serde_json::json!({
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

    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let intent = workspace
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: INTENT_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id,
                schema_id: schema_id.clone(),
                locale: LOCALE.parse::<LocaleId>().unwrap(),
            }],
            idempotency_key: INTENT_KEY.parse().unwrap(),
            issued_at: "2026-08-21T12:00:08Z".parse().unwrap(),
        })
        .unwrap();

    let _context = workspace
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

    (workspace, intent.intent_digest)
}

fn context_build_input(intent_digest: ContentDigest) -> Value {
    json!({
        "api_version": "proof.dev/operation/context.build/v2",
        "context_pack_id": CONTEXT_PACK_ID,
        "created_at": "2026-08-21T12:00:10Z",
        "expires_at": "2026-08-21T13:00:10Z",
        "idempotency_key": CONTEXT_KEY,
        "limits": {
            "max_bytes": 65_536,
            "max_edits": 2,
            "max_objects": 1,
            "max_validation_attempts": 2,
        },
        "policy_rules": [{
            "disallowed_values": ["Forbidden terms"],
            "locale": LOCALE,
            "pointer": "/legal",
        }],
        "resource_intent_digest": intent_digest.to_string(),
        "resource_intent_id": INTENT_ID,
    })
}

/// An isolated parity fixture: a deterministic `SQLite` Workspace plus a
/// dedicated `PostgreSQL` schema populated by the verified parity import.
struct ParityFixture {
    workspace: LocalWorkspace,
    intent_digest: ContentDigest,
    runtime: PgRuntime,
    schema: String,
    root: PathBuf,
}

impl ParityFixture {
    fn new() -> Self {
        let root = fresh_dir();
        let (workspace, intent_digest) = north_star_workspace(&root);

        let runtime = PgRuntime::connect(PgConfig::new(
            dsn(),
            WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            Duration::from_secs(30),
        ))
        .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");

        let schema = format!(
            "p0010_parity_{}_{}",
            std::process::id(),
            SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        let mut fixture = Self {
            workspace,
            intent_digest,
            runtime,
            schema,
            root,
        };
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

        prepare_parity_backend(&fixture.workspace, &mut fixture.runtime)
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
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn workspace_status_scenario() -> ParityScenario {
    ParityScenario {
        name: "workspace.status/v1 accepted".to_owned(),
        operations: vec![ParityOperation {
            normalized_input: json!({}),
            actor_context: actor_context(
                "workspace.status",
                "proof.dev/operation/workspace.status/v1",
            ),
        }],
        expected_trace_digests: Vec::new(),
    }
}

fn context_build_scenario(intent_digest: ContentDigest) -> ParityScenario {
    ParityScenario {
        name: "context.build/v2 keyed replay".to_owned(),
        operations: vec![ParityOperation {
            normalized_input: context_build_input(intent_digest),
            actor_context: actor_context("context.build", "proof.dev/operation/context.build/v2"),
        }],
        expected_trace_digests: Vec::new(),
    }
}

fn rejected_input_scenario() -> ParityScenario {
    ParityScenario {
        name: "changeset.get/v2 rejected input".to_owned(),
        operations: vec![ParityOperation {
            normalized_input: json!({
                "api_version": "proof.dev/operation/changeset.get/v2",
                "changeset_id": "not-a-uuid",
            }),
            actor_context: actor_context("changeset.get", "proof.dev/operation/changeset.get/v2"),
        }],
        expected_trace_digests: Vec::new(),
    }
}

#[test]
fn workspace_status_trace_is_byte_identical() {
    let mut fixture = ParityFixture::new();
    let runner = ParityRunner::new();
    let scenario = workspace_status_scenario();

    let mut sqlite = SqliteReferenceBackend::new(&fixture.workspace);
    let sqlite_traces = runner.run_sqlite(&scenario, &mut sqlite).unwrap();

    let mut postgres = PostgresBackend::new(&mut fixture.runtime);
    let postgres_traces = runner.run_postgres(&scenario, &mut postgres).unwrap();

    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .unwrap();
}

#[test]
fn localized_context_build_replay_trace_is_byte_identical() {
    let mut fixture = ParityFixture::new();
    let runner = ParityRunner::new();
    let scenario = context_build_scenario(fixture.intent_digest);

    let mut sqlite = SqliteReferenceBackend::new(&fixture.workspace);
    let sqlite_traces = runner.run_sqlite(&scenario, &mut sqlite).unwrap();
    // A keyed operation replays the prior committed result without drift.
    let sqlite_replay = runner.run_sqlite(&scenario, &mut sqlite).unwrap();
    assert_eq!(sqlite_traces, sqlite_replay, "SQLite replay must not drift");

    let mut postgres = PostgresBackend::new(&mut fixture.runtime);
    let postgres_traces = runner.run_postgres(&scenario, &mut postgres).unwrap();
    let postgres_replay = runner.run_postgres(&scenario, &mut postgres).unwrap();
    assert_eq!(
        postgres_traces, postgres_replay,
        "PostgreSQL replay must not drift"
    );

    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .unwrap();
}

#[test]
fn rejected_input_trace_is_byte_identical() {
    let mut fixture = ParityFixture::new();
    let runner = ParityRunner::new();
    let scenario = rejected_input_scenario();

    let mut sqlite = SqliteReferenceBackend::new(&fixture.workspace);
    let sqlite_traces = runner.run_sqlite(&scenario, &mut sqlite).unwrap();

    let mut postgres = PostgresBackend::new(&mut fixture.runtime);
    let postgres_traces = runner.run_postgres(&scenario, &mut postgres).unwrap();

    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .unwrap();
}

#[test]
fn tampered_postgres_consequence_diverges() {
    let mut fixture = ParityFixture::new();
    let runner = ParityRunner::new();
    let scenario = context_build_scenario(fixture.intent_digest);

    let mut sqlite = SqliteReferenceBackend::new(&fixture.workspace);
    let sqlite_traces = runner.run_sqlite(&scenario, &mut sqlite).unwrap();

    let mut postgres = PostgresBackend::new(&mut fixture.runtime);
    let postgres_traces = runner.run_postgres(&scenario, &mut postgres).unwrap();
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .unwrap();

    // Tamper the PG consequence: drop the imported build-operation fact so the
    // replay can no longer reproduce the reference consequence.
    fixture
        .runtime
        .client_mut()
        .execute(
            "DELETE FROM facts WHERE fact_kind = 'context_build_operation'",
            &[],
        )
        .unwrap();

    let mut postgres = PostgresBackend::new(&mut fixture.runtime);
    let tampered_traces = runner.run_postgres(&scenario, &mut postgres).unwrap();

    assert!(
        runner
            .assert_identical(&sqlite_traces, &tampered_traces)
            .is_err(),
        "a tampered PostgreSQL consequence must produce a divergent trace"
    );
}

/// Seeds only the localized intent and `ContextPack` prerequisites, returning
/// `(intent_id, intent_digest, context_pack_id, context_pack_digest)` so
/// executor tests can drive the `ChangeSet` lifecycle through both backends.
fn seed_localized_intent_and_context(
    workspace: &LocalWorkspace,
) -> (
    proof_application::ContentResourceIntentId,
    ContentDigest,
    proof_application::ContextPackId,
    ContentDigest,
) {
    use proof_application::{
        BuildLocalizedContextCommand, ContentResourceIntentId, ContextPackId,
        IssueContentResourceIntentCommand, LocaleId, LocalizedContentRepository,
        LocalizedContentTarget, LocalizedPolicyRule,
    };
    const L_INTENT_ID: &str = "019d1000-0000-7000-8000-000000000031";
    const L_CONTEXT_ID: &str = "019d1000-0000-7000-8000-000000000032";
    const L_INTENT_KEY: &str = "019d1000-0000-7000-8000-000000000041";
    const L_CONTEXT_KEY: &str = "019d1000-0000-7000-8000-000000000042";

    let repository: &dyn LocalizedContentRepository = workspace;
    let object_id = OBJECT_ID.parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let es = LocaleId::new("es-ES").unwrap();
    let fr = LocaleId::new("fr-FR").unwrap();
    let intent = repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: L_INTENT_ID.parse::<ContentResourceIntentId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![
                LocalizedContentTarget {
                    object_id,
                    schema_id: schema_id.clone(),
                    locale: es.clone(),
                },
                LocalizedContentTarget {
                    object_id,
                    schema_id,
                    locale: fr,
                },
            ],
            idempotency_key: L_INTENT_KEY.parse().unwrap(),
            issued_at: "2026-08-21T11:00:00Z".parse().unwrap(),
        })
        .expect("localized resource intent issues");
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: L_CONTEXT_ID.parse::<ContextPackId>().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: LocaleId::new("fr-FR").unwrap(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Garantie absolue".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 3,
                max_validation_attempts: 3,
                max_bytes: 1_048_576,
            },
            idempotency_key: L_CONTEXT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:01:00Z".parse().unwrap(),
            expires_at: "2026-08-22T11:01:00Z".parse().unwrap(),
        })
        .expect("localized ContextPack builds");
    (
        intent.intent_id,
        intent.intent_digest,
        context.context_pack_id,
        context.context_pack_digest,
    )
}

/// Seeds one complete localized flow (intent, `ContextPack`, `ChangeSet`,
/// two Edits across locales, one failing validation) and returns its
/// `ChangeSet` identity. Only `/legal` and `/title` vary from the source
/// Object because non-localizable fields must be inherited verbatim.
#[allow(clippy::too_many_lines)]
fn seed_localized_flow(workspace: &LocalWorkspace) -> proof_application::ChangeSetId {
    use proof_application::{
        AddLocalizedEditsCommand, CreateLocalizedChangeSetCommand, EditId, ExpectedLocalizedSource,
        LocaleId, LocalizedContentRepository, ObjectLocalePutInput, ObjectRevision,
    };
    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_ES_EDIT: &str = "019d1000-0000-7000-8000-000000000034";
    const L_FR_EDIT: &str = "019d1000-0000-7000-8000-000000000035";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";

    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(workspace);
    let repository: &dyn LocalizedContentRepository = workspace;
    let object_id = OBJECT_ID.parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest =
        object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
    let es = LocaleId::new("es-ES").unwrap();

    let changeset = repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");
    let expected_source = ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: source_digest,
        schema_id,
        schema_version,
    };
    let localized = |legal: &str, title: &str| -> ObjectLocalePutInput {
        let rendition = canonicalize(&serde_json::json!({
            "legal": legal,
            "slug": "summer-campaign",
            "title": title,
        }))
        .unwrap();
        ObjectLocalePutInput {
            object_id,
            locale: LocaleId::new("fr-FR").unwrap(),
            expected_source: expected_source.clone(),
            expected_target: None,
            canonical_content: rendition.as_str().to_owned(),
            supersedes_edit_id: None,
            repair_of_validation_result_digest: None,
        }
    };
    // The Spanish edit targets es-ES; build it separately for its locale.
    let mut es_edit = localized("Se aplican términos estándar", "Campaña de verano");
    es_edit.locale = es;
    let fr_edit = localized("Garantie absolue", "Campagne d’été");
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: changeset.changeset_id,
            edits: vec![es_edit, fr_edit],
            assigned_edit_ids: vec![
                L_ES_EDIT.parse::<EditId>().unwrap(),
                L_FR_EDIT.parse().unwrap(),
            ],
            idempotency_key: L_ADD_KEY.parse().unwrap(),
        })
        .expect("localized Edits append");
    let invalid = repository
        .validate_localized_changeset(changeset.changeset_id)
        .expect("validation runs");
    assert!(!invalid.valid, "the policy violation must fail validation");
    changeset.changeset_id
}

#[test]
#[allow(clippy::too_many_lines)]
fn localized_change_set_artifacts_import_with_verified_digests() {
    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let _changeset_id = seed_localized_flow(&workspace);

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_csfacts_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");
    // Import and verify.
    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_csfacts_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let connection = workspace.open_database().expect("open reference db");
    let source_changesets: i64 = connection
        .query_row("SELECT COUNT(*) FROM localized_changesets", [], |r| {
            r.get(0)
        })
        .expect("count source changesets");
    let source_edits: i64 = connection
        .query_row("SELECT COUNT(*) FROM localized_edits", [], |r| r.get(0))
        .expect("count source edits");
    let source_validations: i64 = connection
        .query_row("SELECT COUNT(*) FROM localized_validations", [], |r| {
            r.get(0)
        })
        .expect("count source validations");
    drop(connection);
    assert_eq!(source_changesets, 1);
    assert_eq!(source_edits, 2);
    assert_eq!(source_validations, 1);

    let counts = |runtime: &mut PgRuntime, kind: &str| -> i64 {
        runtime
            .client_mut()
            .query_one("SELECT COUNT(*) FROM facts WHERE fact_kind = $1", &[&kind])
            .expect("count parity facts")
            .get(0)
    };
    assert_eq!(
        counts(&mut runtime, "localized_changeset"),
        source_changesets
    );
    assert_eq!(counts(&mut runtime, "localized_edit"), source_edits);
    assert_eq!(
        counts(&mut runtime, "localized_validation"),
        source_validations
    );

    // Every imported Edit fact reproduces its recorded digest exactly.
    let rows = runtime
        .client_mut()
        .query(
            "SELECT fact_digest, body FROM facts WHERE fact_kind = 'localized_edit' ORDER BY fact_id",
            &[],
        )
        .expect("read imported edits");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let stored_digest: String = row.get(0);
        let body: Vec<u8> = row.get(1);
        let value: Value = serde_json::from_slice(&body).expect("edit bytes are JSON");
        let canonical = canonicalize(&value).expect("edit bytes canonicalize");
        assert_eq!(canonical.as_bytes(), body.as_slice());
        assert_eq!(
            digest_canonical(ArtifactKind::EditV2, &canonical).to_string(),
            stored_digest
        );
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn changeset_get_traces_are_byte_identical() {
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let changeset_id = seed_localized_flow(&workspace);

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_cget_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let scenario = ParityScenario {
        name: "changeset.get/v2 accepted plus not-found".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: json!({
                    "api_version": "proof.dev/operation/changeset.get/v2",
                    "changeset_id": changeset_id.to_string(),
                }),
                actor_context: actor_context(
                    "changeset.get",
                    "proof.dev/operation/changeset.get/v2",
                ),
            },
            ParityOperation {
                normalized_input: json!({
                    "api_version": "proof.dev/operation/changeset.get/v2",
                    "changeset_id": "019d1000-0000-7000-8000-000000000039",
                }),
                actor_context: actor_context(
                    "changeset.get",
                    "proof.dev/operation/changeset.get/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    // Semantic spot checks beyond byte equality.
    match &postgres_traces[0].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["status"], "draft");
            assert_eq!(result["edits"].as_array().map(Vec::len), Some(2));
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected a typed result, got {other:?}")
        }
    }
    match &postgres_traces[1].outcome {
        OracleOutcome::StableProblem(problem) => {
            assert_eq!(problem.code, "proof.resource.not_found");
        }
        other @ OracleOutcome::TypedResult(_) => {
            panic!("expected a stable problem, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn changeset_create_traces_are_byte_identical() {
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_create_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let create_input = json!({
        "api_version": "proof.dev/operation/changeset.create/v2",
        "changeset_id": "019d1000-0000-7000-8000-000000000036",
        "context_pack_digest": context_pack_digest.to_string(),
        "context_pack_id": context_pack_id.to_string(),
        "created_at": "2026-08-21T11:05:00Z",
        "idempotency_key": "019d1000-0000-7000-8000-000000000045",
        "intent": "Translate the campaign into two locales",
        "resource_intent_digest": intent_digest.to_string(),
        "resource_intent_id": intent_id.to_string(),
    });
    let scenario = ParityScenario {
        name: "changeset.create/v2 accepted plus keyed replay".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: create_input.clone(),
                actor_context: actor_context(
                    "changeset.create",
                    "proof.dev/operation/changeset.create/v2",
                ),
            },
            ParityOperation {
                normalized_input: create_input,
                actor_context: actor_context(
                    "changeset.create",
                    "proof.dev/operation/changeset.create/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    for trace in &postgres_traces {
        match &trace.outcome {
            OracleOutcome::TypedResult(result) => {
                assert_eq!(result["status"], "draft");
                assert_eq!(
                    result["edits"].as_array().map(Vec::len),
                    Some(0),
                    "a fresh draft carries no edits"
                );
            }
            other @ OracleOutcome::StableProblem(_) => {
                panic!("expected typed results on both steps, got {other:?}")
            }
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn changeset_add_traces_are_byte_identical() {
    use proof_application::{ChangeSetIntent, CreateLocalizedChangeSetCommand};
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_add_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let object_id = OBJECT_ID;
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest = object_revision_digest(
        object_id.parse().unwrap(),
        &schema_id,
        schema_version,
        &source,
    )
    .unwrap()
    .to_string();
    let edit_input = |locale: &str, legal: &str, title: &str| {
        serde_json::json!({
            "api_version": "proof.dev/edit/v2",
            "content": {"legal": legal, "slug": "summer-campaign", "title": title},
            "expected_source": {
                "digest": source_digest,
                "revision": 1,
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            "expected_target": Value::Null,
            "kind": "object.locale.put",
            "locale": locale,
            "object_id": object_id,
            "repair_of_validation_result_digest": Value::Null,
            "supersedes_edit_id": Value::Null,
        })
    };
    let add_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": L_CHANGESET_ID,
        "edits": [
            edit_input("es-ES", "Se aplican términos estándar", "Campaña de verano"),
            edit_input("fr-FR", "Garantie absolue", "Campagne d’été"),
        ],
        "idempotency_key": L_ADD_KEY,
    });
    let scenario = ParityScenario {
        name: "changeset.add/v2 accepted plus keyed replay".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: add_input.clone(),
                actor_context: actor_context(
                    "changeset.add",
                    "proof.dev/operation/changeset.add/v2",
                ),
            },
            ParityOperation {
                normalized_input: add_input,
                actor_context: actor_context(
                    "changeset.add",
                    "proof.dev/operation/changeset.add/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    let outcome = &postgres_traces[0].outcome;
    match outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["first_ordinal"], 1);
            assert_eq!(result["total_edit_count"], 2);
            assert_eq!(result["edit_ids"].as_array().map(Vec::len), Some(2));
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected a typed add result, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn changeset_validate_traces_are_byte_identical() {
    use proof_application::{ChangeSetIntent, CreateLocalizedChangeSetCommand};
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_validate_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let object_id = OBJECT_ID;
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest = object_revision_digest(
        object_id.parse().unwrap(),
        &schema_id,
        schema_version,
        &source,
    )
    .unwrap()
    .to_string();
    let edit_input = |locale: &str, legal: &str, title: &str| {
        serde_json::json!({
            "api_version": "proof.dev/edit/v2",
            "content": {"legal": legal, "slug": "summer-campaign", "title": title},
            "expected_source": {
                "digest": source_digest,
                "revision": 1,
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            "expected_target": Value::Null,
            "kind": "object.locale.put",
            "locale": locale,
            "object_id": object_id,
            "repair_of_validation_result_digest": Value::Null,
            "supersedes_edit_id": Value::Null,
        })
    };
    let add_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": L_CHANGESET_ID,
        "edits": [
            edit_input("es-ES", "Se aplican términos estándar", "Campaña de verano"),
            edit_input("fr-FR", "Garantie absolue", "Campagne d’été"),
        ],
        "idempotency_key": L_ADD_KEY,
    });
    let validate_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.validate/v2",
        "changeset_id": L_CHANGESET_ID,
    });
    let scenario = ParityScenario {
        name: "changeset.add then changeset.validate".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: add_input,
                actor_context: actor_context(
                    "changeset.add",
                    "proof.dev/operation/changeset.add/v2",
                ),
            },
            ParityOperation {
                normalized_input: validate_input,
                actor_context: actor_context(
                    "changeset.validate",
                    "proof.dev/operation/changeset.validate/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[1].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["valid"], false);
            assert_eq!(result["status"], "draft");
            assert_eq!(result["findings"].as_array().map(Vec::len), Some(1));
            assert_eq!(result["findings"][0]["severity"], "error");
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected a typed validation result, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn changeset_submit_traces_are_byte_identical() {
    use proof_application::{ChangeSetIntent, CreateLocalizedChangeSetCommand};
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_submit_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let object_id = OBJECT_ID;
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest = object_revision_digest(
        object_id.parse().unwrap(),
        &schema_id,
        schema_version,
        &source,
    )
    .unwrap()
    .to_string();
    let edit_input = |locale: &str, legal: &str, title: &str| {
        serde_json::json!({
            "api_version": "proof.dev/edit/v2",
            "content": {"legal": legal, "slug": "summer-campaign", "title": title},
            "expected_source": {
                "digest": source_digest,
                "revision": 1,
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            "expected_target": Value::Null,
            "kind": "object.locale.put",
            "locale": locale,
            "object_id": object_id,
            "repair_of_validation_result_digest": Value::Null,
            "supersedes_edit_id": Value::Null,
        })
    };
    // The policy disallows some legal claims; both edits stay clean so the
    // ChangeSet validates ready and can be submitted.
    let add_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": L_CHANGESET_ID,
        "edits": [
            edit_input("es-ES", "Se aplican condiciones estándar", "Campaña de verano"),
            edit_input("fr-FR", "Conditions standards", "Campagne d’été"),
        ],
        "idempotency_key": L_ADD_KEY,
    });
    let validate_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.validate/v2",
        "changeset_id": L_CHANGESET_ID,
    });
    let submit_input = |at: &str| {
        serde_json::json!({
            "api_version": "proof.dev/operation/changeset.submit/v2",
            "changeset_id": L_CHANGESET_ID,
            "submitted_at": at,
        })
    };
    let scenario = ParityScenario {
        name: "validate then submit accepted, replayed, and time-conflicted".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: add_input,
                actor_context: actor_context(
                    "changeset.add",
                    "proof.dev/operation/changeset.add/v2",
                ),
            },
            ParityOperation {
                normalized_input: validate_input,
                actor_context: actor_context(
                    "changeset.validate",
                    "proof.dev/operation/changeset.validate/v2",
                ),
            },
            ParityOperation {
                normalized_input: submit_input("2026-08-21T12:00:00Z"),
                actor_context: actor_context(
                    "changeset.submit",
                    "proof.dev/operation/changeset.submit/v2",
                ),
            },
            ParityOperation {
                normalized_input: submit_input("2026-08-21T12:00:00Z"),
                actor_context: actor_context(
                    "changeset.submit",
                    "proof.dev/operation/changeset.submit/v2",
                ),
            },
            ParityOperation {
                normalized_input: submit_input("2026-08-21T13:00:00Z"),
                actor_context: actor_context(
                    "changeset.submit",
                    "proof.dev/operation/changeset.submit/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[1].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["status"], "ready");
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected the validation to pass, got {other:?}")
        }
    }
    match &postgres_traces[2].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["status"], "submitted");
            assert_eq!(result["submitted_at"], "2026-08-21T12:00:00Z");
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected an accepted submission, got {other:?}")
        }
    }
    match (&postgres_traces[3].outcome, &postgres_traces[4].outcome) {
        (OracleOutcome::TypedResult(replay), OracleOutcome::StableProblem(conflict)) => {
            assert_eq!(replay["status"], "submitted");
            assert_eq!(conflict.code, "proof.idempotency.key_reused");
        }
        _ => panic!("expected replay success plus time-conflict rejection"),
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn changeset_commit_traces_are_byte_identical() {
    use proof_application::{
        AddLocalizedEditsCommand, ApprovalName, ChangeSetIntent, CreateLocalizedChangeSetCommand,
        EditId, ExpectedLocalizedSource, LocaleId, ObjectLocalePutInput, ObjectRevision,
    };
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";
    const L_COMMIT_KEY: &str = "019d1000-0000-7000-8000-000000000045";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let object_id = OBJECT_ID.parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest =
        object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");
    let edit_input = |locale: LocaleId, legal: &str, title: &str| ObjectLocalePutInput {
        object_id,
        locale,
        expected_source: ExpectedLocalizedSource {
            revision: ObjectRevision::INITIAL,
            digest: source_digest,
            schema_id: schema_id.clone(),
            schema_version,
        },
        expected_target: None,
        canonical_content: canonicalize(&serde_json::json!({
            "legal": legal,
            "slug": "summer-campaign",
            "title": title,
        }))
        .unwrap()
        .as_str()
        .to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    };
    workspace
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            edits: vec![
                edit_input(
                    LocaleId::new("es-ES").unwrap(),
                    "Condiciones estándar",
                    "Campaña de verano",
                ),
                edit_input(
                    LocaleId::new("fr-FR").unwrap(),
                    "Conditions standards",
                    "Campagne d’été",
                ),
            ],
            assigned_edit_ids: vec![
                "019d1000-0000-7000-8000-000000000051"
                    .parse::<EditId>()
                    .unwrap(),
                "019d1000-0000-7000-8000-000000000052".parse().unwrap(),
            ],
            idempotency_key: L_ADD_KEY.parse().unwrap(),
        })
        .expect("localized Edits append");
    workspace
        .validate_localized_changeset(L_CHANGESET_ID.parse().unwrap())
        .expect("validation runs");
    workspace
        .submit_localized_changeset(
            L_CHANGESET_ID.parse().unwrap(),
            "2026-08-21T12:00:00Z".parse().unwrap(),
        )
        .expect("submission recorded");
    workspace
        .approve_localized_changeset(
            L_CHANGESET_ID.parse().unwrap(),
            ApprovalName::new("editorial").unwrap(),
            "2026-08-21T12:30:00Z".parse().unwrap(),
        )
        .expect("approval recorded");

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_commit_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let commit_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": L_CHANGESET_ID,
        "committed_at": "2026-08-21T13:00:00Z",
        "idempotency_key": L_COMMIT_KEY,
    });
    let scenario = ParityScenario {
        name: "changeset.commit/v2 accepted plus keyed replay".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: commit_input.clone(),
                actor_context: actor_context(
                    "changeset.commit",
                    "proof.dev/operation/changeset.commit/v2",
                ),
            },
            ParityOperation {
                normalized_input: commit_input,
                actor_context: actor_context(
                    "changeset.commit",
                    "proof.dev/operation/changeset.commit/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[0].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["status"], "committed");
            assert_eq!(result["renditions"].as_array().map(Vec::len), Some(2));
            assert_eq!(result["resulting_state"]["authoritative_sequence"], 4);
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected an accepted commit, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn edition_create_traces_are_byte_identical() {
    use proof_application::{
        AddLocalizedEditsCommand, ApprovalName, ChangeSetIntent, CommitLocalizedChangeSetCommand,
        CreateLocalizedChangeSetCommand, EditId, ExpectedLocalizedSource, LocaleId,
        ObjectLocalePutInput, ObjectRevision,
    };
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";
    const L_COMMIT_KEY: &str = "019d1000-0000-7000-8000-000000000045";
    const L_EDITION_ID: &str = "019d1000-0000-7000-8000-000000000034";
    const L_EDITION_KEY: &str = "019d1000-0000-7000-8000-000000000046";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let object_id = OBJECT_ID.parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest =
        object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");
    let edit_input = |locale: LocaleId, legal: &str, title: &str| ObjectLocalePutInput {
        object_id,
        locale,
        expected_source: ExpectedLocalizedSource {
            revision: ObjectRevision::INITIAL,
            digest: source_digest,
            schema_id: schema_id.clone(),
            schema_version,
        },
        expected_target: None,
        canonical_content: canonicalize(&serde_json::json!({
            "legal": legal,
            "slug": "summer-campaign",
            "title": title,
        }))
        .unwrap()
        .as_str()
        .to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    };
    workspace
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            edits: vec![
                edit_input(
                    LocaleId::new("es-ES").unwrap(),
                    "Condiciones estándar",
                    "Campaña de verano",
                ),
                edit_input(
                    LocaleId::new("fr-FR").unwrap(),
                    "Conditions standards",
                    "Campagne d’été",
                ),
            ],
            assigned_edit_ids: vec![
                "019d1000-0000-7000-8000-000000000051"
                    .parse::<EditId>()
                    .unwrap(),
                "019d1000-0000-7000-8000-000000000052".parse().unwrap(),
            ],
            idempotency_key: L_ADD_KEY.parse().unwrap(),
        })
        .expect("localized Edits append");
    workspace
        .validate_localized_changeset(L_CHANGESET_ID.parse().unwrap())
        .expect("validation runs");
    workspace
        .submit_localized_changeset(
            L_CHANGESET_ID.parse().unwrap(),
            "2026-08-21T12:00:00Z".parse().unwrap(),
        )
        .expect("submission recorded");
    workspace
        .approve_localized_changeset(
            L_CHANGESET_ID.parse().unwrap(),
            ApprovalName::new("editorial").unwrap(),
            "2026-08-21T12:30:00Z".parse().unwrap(),
        )
        .expect("approval recorded");
    let committed = workspace
        .commit_localized_changeset(CommitLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            committed_at: "2026-08-21T13:00:00Z".parse().unwrap(),
            idempotency_key: L_COMMIT_KEY.parse().unwrap(),
        })
        .expect("commit recorded");
    let resulting_state_digest = committed.resulting_state.digest;

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_edition_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let edition_input = serde_json::json!({
        "api_version": "proof.dev/operation/edition.create/v2",
        "changeset_id": L_CHANGESET_ID,
        "created_at": "2026-08-21T14:00:00Z",
        "edition_id": L_EDITION_ID,
        "idempotency_key": L_EDITION_KEY,
        "resulting_state_digest": resulting_state_digest.to_string(),
    });
    let scenario = ParityScenario {
        name: "edition.create/v2 accepted plus keyed replay".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: edition_input.clone(),
                actor_context: actor_context(
                    "edition.create",
                    "proof.dev/operation/edition.create/v2",
                ),
            },
            ParityOperation {
                normalized_input: edition_input,
                actor_context: actor_context(
                    "edition.create",
                    "proof.dev/operation/edition.create/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[0].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["state"]["authoritative_sequence"], 4);
            assert!(result["edition_digest"].as_str().is_some());
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected an accepted edition creation, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn changeset_diff_traces_are_byte_identical() {
    use proof_application::{
        AddLocalizedEditsCommand, ChangeSetIntent, CreateLocalizedChangeSetCommand, EditId,
        ExpectedLocalizedSource, LocaleId, ObjectLocalePutInput, ObjectRevision,
    };
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_CHANGESET_ID: &str = "019d1000-0000-7000-8000-000000000033";
    const L_DRAFT_KEY: &str = "019d1000-0000-7000-8000-000000000043";
    const L_ADD_KEY: &str = "019d1000-0000-7000-8000-000000000044";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, context_pack_id, context_pack_digest) =
        seed_localized_intent_and_context(&workspace);
    let object_id = OBJECT_ID.parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID.to_owned()).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let source = serde_json::json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let source_digest =
        object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
    let _changeset = workspace
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Translate the campaign").unwrap(),
            resource_intent_id: intent_id,
            resource_intent_digest: intent_digest,
            context_pack_id,
            context_pack_digest,
            idempotency_key: L_DRAFT_KEY.parse().unwrap(),
            created_at: "2026-08-21T11:02:00Z".parse().unwrap(),
        })
        .expect("localized ChangeSet creates");
    let edit_input = |locale: LocaleId, legal: &str, title: &str| ObjectLocalePutInput {
        object_id,
        locale,
        expected_source: ExpectedLocalizedSource {
            revision: ObjectRevision::INITIAL,
            digest: source_digest,
            schema_id: schema_id.clone(),
            schema_version,
        },
        expected_target: None,
        canonical_content: canonicalize(&serde_json::json!({
            "legal": legal,
            "slug": "summer-campaign",
            "title": title,
        }))
        .unwrap()
        .as_str()
        .to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    };
    workspace
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: L_CHANGESET_ID.parse().unwrap(),
            edits: vec![
                edit_input(
                    LocaleId::new("es-ES").unwrap(),
                    "Condiciones estándar",
                    "Campaña de verano",
                ),
                edit_input(
                    LocaleId::new("fr-FR").unwrap(),
                    "Conditions standards",
                    "Campagne d’été",
                ),
            ],
            assigned_edit_ids: vec![
                "019d1000-0000-7000-8000-000000000051"
                    .parse::<EditId>()
                    .unwrap(),
                "019d1000-0000-7000-8000-000000000052".parse().unwrap(),
            ],
            idempotency_key: L_ADD_KEY.parse().unwrap(),
        })
        .expect("localized Edits append");

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_diff_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let diff_input = serde_json::json!({
        "api_version": "proof.dev/operation/changeset.diff/v2",
        "changeset_id": L_CHANGESET_ID,
    });
    let scenario = ParityScenario {
        name: "changeset.diff/v2 accepted".to_owned(),
        operations: vec![ParityOperation {
            normalized_input: diff_input,
            actor_context: actor_context("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
        }],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[0].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["effective_edits"].as_array().map(Vec::len), Some(2));
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected a typed diff result, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn query_released_rejection_traces_are_byte_identical() {
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_query_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    // The north-star baseline is a v1 Release; a v2 released-rendition query
    // must reject identically on both backends.
    let input = serde_json::json!({
        "api_version": "proof.dev/operation/object.query_released/v2",
        "environment_id": ENVIRONMENT_ID,
        "evaluated_at": "2026-08-21T15:00:00Z",
        "targets": [
            {"locale": "es-ES", "object_id": OBJECT_ID},
        ],
    });
    let scenario = ParityScenario {
        name: "object.query_released/v2 rejects v1 releases".to_owned(),
        operations: vec![ParityOperation {
            normalized_input: input,
            actor_context: actor_context(
                "object.query_released",
                "proof.dev/operation/object.query_released/v2",
            ),
        }],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    assert!(matches!(
        &postgres_traces[0].outcome,
        OracleOutcome::StableProblem(problem) if problem.code == "proof.resource.not_found"
    ));

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
#[allow(clippy::too_many_lines)]
fn context_build_traces_are_byte_identical() {
    use proof_pg::parity::PostgresBackend as PgBackendAlias;
    use proof_remote::OracleOutcome;

    const L_BUILD_KEY: &str = "019d1000-0000-7000-8000-000000000047";

    let root = fresh_dir();
    let (workspace, _intent_digest) = north_star_workspace(&root);
    let (intent_id, intent_digest, _pack_id, _pack_digest) =
        seed_localized_intent_and_context(&workspace);

    let mut runtime = PgRuntime::connect(PgConfig::new(
        dsn(),
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh or set PROOF_PG_DSN");
    let schema = format!(
        "p0015_build_{}_{}",
        std::process::id(),
        SCHEMA_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    {
        let client = runtime.client_mut();
        client
            .batch_execute(&format!("CREATE SCHEMA \"{schema}\""))
            .expect("create isolated schema");
        client
            .batch_execute(&format!("SET search_path TO \"{schema}\""))
            .expect("set search path");
    }
    prepare_parity_backend(&workspace, &mut runtime).expect("parity import");

    let build_input = serde_json::json!({
        "api_version": "proof.dev/operation/context.build/v2",
        "context_pack_id": "019d1000-0000-7000-8000-000000000053",
        "created_at": "2026-08-21T10:30:00Z",
        "expires_at": "2026-08-22T10:30:00Z",
        "idempotency_key": L_BUILD_KEY,
        "limits": {
            "max_bytes": 262_144,
            "max_edits": 16,
            "max_objects": 8,
            "max_validation_attempts": 3,
        },
        "policy_rules": [
            {
                "disallowed_values": [
                    "absolute guarantee",
                    "best in class",
                    "guaranteed returns"
                ],
                "locale": "es-ES",
                "pointer": "/legal",
            },
            {
                "disallowed_values": ["absolute guarantee", "garantie absolue"],
                "locale": "fr-FR",
                "pointer": "/legal",
            },
        ],
        "resource_intent_digest": intent_digest.to_string(),
        "resource_intent_id": intent_id.to_string(),
    });
    let scenario = ParityScenario {
        name: "context.build/v2 accepted plus keyed replay".to_owned(),
        operations: vec![
            ParityOperation {
                normalized_input: build_input.clone(),
                actor_context: actor_context(
                    "context.build",
                    "proof.dev/operation/context.build/v2",
                ),
            },
            ParityOperation {
                normalized_input: build_input,
                actor_context: actor_context(
                    "context.build",
                    "proof.dev/operation/context.build/v2",
                ),
            },
        ],
        expected_trace_digests: Vec::new(),
    };

    let mut sqlite_backend = SqliteReferenceBackend::new(&workspace);
    let mut postgres_backend = PgBackendAlias::new(&mut runtime);
    let runner = ParityRunner::new();
    let sqlite_traces = runner
        .run_sqlite(&scenario, &mut sqlite_backend)
        .expect("SQLite reference traces");
    let postgres_traces = runner
        .run_postgres(&scenario, &mut postgres_backend)
        .expect("PostgreSQL traces");
    runner
        .assert_identical(&sqlite_traces, &postgres_traces)
        .expect("byte-identical traces");

    match &postgres_traces[0].outcome {
        OracleOutcome::TypedResult(result) => {
            assert_eq!(result["manifest"]["limits"]["max_edits"], 16);
            assert_eq!(
                result["manifest"]["resources"].as_array().map(Vec::len),
                Some(2)
            );
        }
        other @ OracleOutcome::StableProblem(_) => {
            panic!("expected an accepted ContextPack build, got {other:?}")
        }
    }

    let _ = runtime
        .client_mut()
        .batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE"));
    let _ = fs::remove_dir_all(&root);
}
