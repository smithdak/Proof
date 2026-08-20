use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    AddChangeSetEditsCommand, AddLocalizedEditsCommand, ApprovalName, ApproveChangeSetCommand,
    ArtifactKind, BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetId, ChangeSetIntent,
    CommitChangeSetCommand, ContentDigest, CreateChangeSetCommand, CreateEditionCommand,
    CreateEnvironmentCommand, CreateLocalizedChangeSetCommand, EnvironmentId,
    ExpectedLocalizedSource, IdempotencyKey, InitializeWorkspaceCommand,
    IssueContentResourceIntentCommand, LocalizedContentError, LocalizedContentRepository,
    LocalizedContentTarget, LocalizedContextLimits, LocalizedPolicyRule, ObjectCreateEdit,
    ObjectId, ObjectLocalePutInput, ObjectRevision, PrincipalId, PromoteReleaseCommand, ProofId,
    RebuildProjectionsCommand, RebuildProjectionsError, ReleaseId, SchemaCreateEdit, SchemaId,
    SchemaVersion, SubmitChangeSetCommand, Timestamp, WorkspaceId, add_changeset_edits,
    approve_changeset, commit_changeset, create_changeset, create_edition, create_environment,
    initialize_workspace, promote_release, rebuild_projections, submit_changeset,
    validate_changeset,
};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::LocalWorkspace;
use rusqlite::{Connection, types::ValueRef};
use serde_json::json;

const WORKSPACE_ID: &str = "019d0000-0000-7000-8000-000000000001";
const PRINCIPAL_ID: &str = "019d0000-0000-7000-8000-000000000002";
const SOURCE_CHANGESET_ID: &str = "019d0000-0000-7000-8000-000000000010";
const SOURCE_SCHEMA_EDIT_ID: &str = "019d0000-0000-7000-8000-000000000011";
const SOURCE_OBJECT_EDIT_ID: &str = "019d0000-0000-7000-8000-000000000012";
const OBJECT_ID: &str = "019d0000-0000-7000-8000-000000000013";
const BASE_EDITION_ID: &str = "019d0000-0000-7000-8000-000000000014";
const BASE_RELEASE_ID: &str = "019d0000-0000-7000-8000-000000000015";
const BASE_PROOF_ID: &str = "019d0000-0000-7000-8000-000000000016";
const ENVIRONMENT_ID: &str = "preview";

const LOCALIZED_TABLES: &[&str] = &[
    "content_resource_intents",
    "content_resource_intent_operations",
    "localized_context_packs",
    "localized_context_build_operations",
    "localized_changesets",
    "localized_edits",
    "localized_add_operations",
    "localized_validations",
    "localized_submissions",
    "localized_approvals",
    "localized_commits",
    "object_locale_revisions",
    "known_state",
];

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-p0007-assurance-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assurance_id(value: u64) -> String {
    format!("019d0000-0000-7000-8000-{value:012x}")
}

fn initialized_repository(directory: &TestDirectory) -> LocalWorkspace {
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse::<PrincipalId>().unwrap(),
        },
    )
    .unwrap();
    repository
}

fn localizable_schema_edit(edit_id: &str, schema_id: &str) -> ChangeSetEdit {
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
        edit_id: edit_id.parse().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(1).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn object_edit(
    edit_id: &str,
    object_id: &str,
    schema_id: &str,
    content: &serde_json::Value,
) -> ChangeSetEdit {
    let object_id = object_id.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new(schema_id).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical = canonicalize(content).unwrap();
    ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
        edit_id: edit_id.parse().unwrap(),
        object_id,
        schema_id: schema_id.clone(),
        schema_version,
        canonical_content: canonical.as_str().to_owned(),
        object_digest: object_revision_digest(object_id, &schema_id, schema_version, content)
            .unwrap(),
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "the assurance fixture retains the complete v1 source-to-Release baseline"
)]
fn create_source_baseline(repository: &LocalWorkspace) -> ExpectedLocalizedSource {
    let source = json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: SOURCE_CHANGESET_ID.parse().unwrap(),
            intent: ChangeSetIntent::new("Create the exact localizable source").unwrap(),
            requested_base_state: None,
            idempotency_key: assurance_id(0x20).parse().unwrap(),
            created_at: "2026-08-20T12:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: SOURCE_CHANGESET_ID.parse().unwrap(),
            edits: vec![
                localizable_schema_edit(SOURCE_SCHEMA_EDIT_ID, "campaign"),
                object_edit(SOURCE_OBJECT_EDIT_ID, OBJECT_ID, "campaign", &source),
            ],
            idempotency_key: assurance_id(0x21).parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, SOURCE_CHANGESET_ID.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: SOURCE_CHANGESET_ID.parse().unwrap(),
            submitted_at: "2026-08-20T12:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: SOURCE_CHANGESET_ID.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-20T12:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: SOURCE_CHANGESET_ID.parse().unwrap(),
            idempotency_key: assurance_id(0x22).parse().unwrap(),
            committed_at: "2026-08-20T12:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        CreateEditionCommand {
            edition_id: BASE_EDITION_ID.parse().unwrap(),
            idempotency_key: assurance_id(0x23).parse().unwrap(),
            created_at: "2026-08-20T12:04:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        repository,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: assurance_id(0x24).parse().unwrap(),
            created_at: "2026-08-20T12:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        repository,
        PromoteReleaseCommand {
            release_id: BASE_RELEASE_ID.parse::<ReleaseId>().unwrap(),
            proof_id: BASE_PROOF_ID.parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: BASE_EDITION_ID.parse().unwrap(),
            idempotency_key: assurance_id(0x25).parse().unwrap(),
            released_at: "2026-08-20T12:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_id = SchemaId::new("campaign").unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap(),
        schema_id,
        schema_version,
    }
}

struct DraftFixture {
    directory: TestDirectory,
    repository: LocalWorkspace,
    changeset_id: ChangeSetId,
    expected_source: ExpectedLocalizedSource,
}

fn create_intent(
    repository: &LocalWorkspace,
    sequence: u64,
) -> proof_application::ContentResourceIntent {
    repository
        .issue_content_resource_intent(IssueContentResourceIntentCommand {
            intent_id: assurance_id(sequence).parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            targets: vec![LocalizedContentTarget {
                object_id: OBJECT_ID.parse().unwrap(),
                schema_id: SchemaId::new("campaign").unwrap(),
                locale: "fr-FR".parse().unwrap(),
            }],
            idempotency_key: assurance_id(sequence + 1).parse().unwrap(),
            issued_at: "2026-08-20T13:00:00Z".parse().unwrap(),
        })
        .unwrap()
}

fn build_draft(
    repository: &LocalWorkspace,
    sequence: u64,
    limits: LocalizedContextLimits,
) -> ChangeSetId {
    let intent = create_intent(repository, sequence);
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: assurance_id(sequence + 2).parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![LocalizedPolicyRule {
                locale: "fr-FR".parse().unwrap(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Garantie absolue".to_owned()],
            }],
            limits,
            idempotency_key: assurance_id(sequence + 3).parse().unwrap(),
            created_at: "2026-08-20T13:01:00Z".parse().unwrap(),
            expires_at: "2026-08-21T13:01:00Z".parse().unwrap(),
        })
        .unwrap();
    repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id: assurance_id(sequence + 4).parse().unwrap(),
            intent: ChangeSetIntent::new("Exercise exact localized assurance bounds").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: assurance_id(sequence + 5).parse().unwrap(),
            created_at: "2026-08-20T13:02:00Z".parse().unwrap(),
        })
        .unwrap()
        .changeset_id
}

fn draft_fixture(label: &str, sequence: u64, limits: LocalizedContextLimits) -> DraftFixture {
    let directory = TestDirectory::new(label);
    let repository = initialized_repository(&directory);
    let expected_source = create_source_baseline(&repository);
    let changeset_id = build_draft(&repository, sequence, limits);
    DraftFixture {
        directory,
        repository,
        changeset_id,
        expected_source,
    }
}

fn localized_input(
    expected_source: &ExpectedLocalizedSource,
    legal: &str,
    title: &str,
) -> ObjectLocalePutInput {
    let canonical = canonicalize(&json!({
        "legal": legal,
        "slug": "summer-campaign",
        "title": title,
    }))
    .unwrap();
    ObjectLocalePutInput {
        object_id: OBJECT_ID.parse().unwrap(),
        locale: "fr-FR".parse().unwrap(),
        expected_source: expected_source.clone(),
        expected_target: None,
        canonical_content: canonical.as_str().to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    }
}

fn hash_feed(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
    hash.update(bytes);
}

fn query_fingerprint(connection: &Connection, sql: &str, hash: &mut blake3::Hasher) {
    hash_feed(hash, sql.as_bytes());
    let mut statement = connection.prepare(sql).unwrap();
    let columns = statement.column_count();
    let mut rows = statement.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        for column in 0..columns {
            match row.get_ref(column).unwrap() {
                ValueRef::Null => hash_feed(hash, &[0]),
                ValueRef::Integer(value) => {
                    hash_feed(hash, &[1]);
                    hash_feed(hash, &value.to_le_bytes());
                }
                ValueRef::Real(value) => {
                    hash_feed(hash, &[2]);
                    hash_feed(hash, &value.to_bits().to_le_bytes());
                }
                ValueRef::Text(value) => {
                    hash_feed(hash, &[3]);
                    hash_feed(hash, value);
                }
                ValueRef::Blob(value) => {
                    hash_feed(hash, &[4]);
                    hash_feed(hash, value);
                }
            }
        }
    }
}

fn table_fingerprint(repository: &LocalWorkspace, tables: &[&str]) -> blake3::Hash {
    let connection = repository.open_database().unwrap();
    let mut hash = blake3::Hasher::new_derive_key("proof:p0007:assurance-state:v1");
    for table in tables {
        query_fingerprint(
            &connection,
            &format!("SELECT * FROM {table} ORDER BY rowid"),
            &mut hash,
        );
    }
    hash.finalize()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one retained test reports each independently exhausted G7 budget"
)]
fn p0007_g7_separate_context_edit_and_validation_budgets_are_atomic() {
    let directory = TestDirectory::new("g7-context-budgets");
    let repository = initialized_repository(&directory);
    create_source_baseline(&repository);
    let intent = create_intent(&repository, 0x100);

    for (label, limits, sequence) in [
        (
            "object",
            LocalizedContextLimits {
                max_objects: 0,
                max_edits: 1,
                max_validation_attempts: 1,
                max_bytes: 1_048_576,
            },
            0x110,
        ),
        (
            "byte",
            LocalizedContextLimits {
                max_objects: 1,
                max_edits: 1,
                max_validation_attempts: 1,
                max_bytes: 1,
            },
            0x120,
        ),
    ] {
        let before = table_fingerprint(&repository, LOCALIZED_TABLES);
        let result = repository.build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: assurance_id(sequence).parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: Vec::new(),
            limits,
            idempotency_key: assurance_id(sequence + 1).parse().unwrap(),
            created_at: "2026-08-20T13:01:00Z".parse().unwrap(),
            expires_at: "2026-08-21T13:01:00Z".parse().unwrap(),
        });
        assert_eq!(result.unwrap_err(), LocalizedContentError::LimitExceeded);
        let after = table_fingerprint(&repository, LOCALIZED_TABLES);
        assert_eq!(after, before, "{label} Context budget denial mutated state");
        eprintln!("G7 {label}-context-budget before={before} after={after}");
    }

    let edit_fixture = draft_fixture(
        "g7-edit-budget",
        0x200,
        LocalizedContextLimits {
            max_objects: 1,
            max_edits: 1,
            max_validation_attempts: 2,
            max_bytes: 1_048_576,
        },
    );
    let first_edit_id = assurance_id(0x210).parse().unwrap();
    edit_fixture
        .repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: edit_fixture.changeset_id,
            edits: vec![localized_input(
                &edit_fixture.expected_source,
                "Garantie absolue",
                "Campagne d’été",
            )],
            assigned_edit_ids: vec![first_edit_id],
            idempotency_key: assurance_id(0x211).parse().unwrap(),
        })
        .unwrap();
    let invalid = edit_fixture
        .repository
        .validate_localized_changeset(edit_fixture.changeset_id)
        .unwrap();
    assert!(!invalid.valid);
    let mut repair = localized_input(
        &edit_fixture.expected_source,
        "Des conditions standard s’appliquent",
        "Campagne d’été",
    );
    repair.supersedes_edit_id = Some(first_edit_id);
    repair.repair_of_validation_result_digest = Some(invalid.validation_results_digest);
    let before = table_fingerprint(&edit_fixture.repository, LOCALIZED_TABLES);
    assert_eq!(
        edit_fixture
            .repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: edit_fixture.changeset_id,
                edits: vec![repair],
                assigned_edit_ids: vec![assurance_id(0x212).parse().unwrap()],
                idempotency_key: assurance_id(0x213).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::LimitExceeded
    );
    let after = table_fingerprint(&edit_fixture.repository, LOCALIZED_TABLES);
    assert_eq!(after, before, "Edit budget denial mutated state");
    eprintln!("G7 edit-budget before={before} after={after}");

    let validation_fixture = draft_fixture(
        "g7-validation-budget",
        0x300,
        LocalizedContextLimits {
            max_objects: 1,
            max_edits: 1,
            max_validation_attempts: 1,
            max_bytes: 1_048_576,
        },
    );
    validation_fixture
        .repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: validation_fixture.changeset_id,
            edits: vec![localized_input(
                &validation_fixture.expected_source,
                "Garantie absolue",
                "Campagne d’été",
            )],
            assigned_edit_ids: vec![assurance_id(0x310).parse().unwrap()],
            idempotency_key: assurance_id(0x311).parse().unwrap(),
        })
        .unwrap();
    assert!(
        !validation_fixture
            .repository
            .validate_localized_changeset(validation_fixture.changeset_id)
            .unwrap()
            .valid
    );
    let before = table_fingerprint(&validation_fixture.repository, LOCALIZED_TABLES);
    assert_eq!(
        validation_fixture
            .repository
            .validate_localized_changeset(validation_fixture.changeset_id)
            .unwrap_err(),
        LocalizedContentError::LimitExceeded
    );
    let after = table_fingerprint(&validation_fixture.repository, LOCALIZED_TABLES);
    assert_eq!(after, before, "validation budget denial mutated state");
    eprintln!("G7 validation-budget before={before} after={after}");
}

struct LineageFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    changeset_id: ChangeSetId,
    first_edit_id: proof_application::EditId,
    repair_edit_id: proof_application::EditId,
    invalid_digest: ContentDigest,
    first_input: ObjectLocalePutInput,
    repair_input: ObjectLocalePutInput,
}

fn lineage_fixture(label: &str, sequence: u64) -> LineageFixture {
    let fixture = draft_fixture(
        label,
        sequence,
        LocalizedContextLimits {
            max_objects: 1,
            max_edits: 2,
            max_validation_attempts: 2,
            max_bytes: 1_048_576,
        },
    );
    let first_edit_id = assurance_id(sequence + 0x10).parse().unwrap();
    let repair_edit_id = assurance_id(sequence + 0x11).parse().unwrap();
    let first_input = localized_input(
        &fixture.expected_source,
        "Garantie absolue",
        "Campagne d’été",
    );
    fixture
        .repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: fixture.changeset_id,
            edits: vec![first_input.clone()],
            assigned_edit_ids: vec![first_edit_id],
            idempotency_key: assurance_id(sequence + 0x12).parse().unwrap(),
        })
        .unwrap();
    let invalid = fixture
        .repository
        .validate_localized_changeset(fixture.changeset_id)
        .unwrap();
    assert!(!invalid.valid);
    let mut repair_input = localized_input(
        &fixture.expected_source,
        "Des conditions standard s’appliquent",
        "Campagne d’été",
    );
    repair_input.supersedes_edit_id = Some(first_edit_id);
    repair_input.repair_of_validation_result_digest = Some(invalid.validation_results_digest);
    fixture
        .repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: fixture.changeset_id,
            edits: vec![repair_input.clone()],
            assigned_edit_ids: vec![repair_edit_id],
            idempotency_key: assurance_id(sequence + 0x13).parse().unwrap(),
        })
        .unwrap();
    LineageFixture {
        _directory: fixture.directory,
        repository: fixture.repository,
        changeset_id: fixture.changeset_id,
        first_edit_id,
        repair_edit_id,
        invalid_digest: invalid.validation_results_digest,
        first_input,
        repair_input,
    }
}

fn edit_manifest(
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) -> proof_canonical::CanonicalJson {
    let content: serde_json::Value = serde_json::from_str(&input.canonical_content).unwrap();
    canonicalize(&json!({
        "api_version": proof_application::LOCALIZED_EDIT_API_VERSION,
        "content": content,
        "edit_id": edit_id.to_string(),
        "expected_source": {
            "digest": input.expected_source.digest.to_string(),
            "revision": input.expected_source.revision.get(),
            "schema_id": input.expected_source.schema_id.as_str(),
            "schema_version": input.expected_source.schema_version.get(),
        },
        "expected_target": input.expected_target.as_ref().map(|target| json!({
            "digest": target.digest.to_string(),
            "revision": target.revision.get(),
        })),
        "kind": "object.locale.put",
        "locale": input.locale.as_str(),
        "object_id": input.object_id.to_string(),
        "repair_of_validation_result_digest": input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
        "supersedes_edit_id": input.supersedes_edit_id.map(|value| value.to_string()),
    }))
    .unwrap()
}

fn replace_edit_artifact(
    repository: &LocalWorkspace,
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) {
    let manifest = edit_manifest(edit_id, input);
    let edit_digest = digest(ArtifactKind::EditV2, &manifest);
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE localized_edits
             SET content_json = ?1, supersedes_edit_id = ?2,
                 repair_validation_digest = ?3, edit_json = ?4, edit_digest = ?5
             WHERE edit_id = ?6",
            rusqlite::params![
                input.canonical_content,
                input.supersedes_edit_id.map(|value| value.to_string()),
                input
                    .repair_of_validation_result_digest
                    .map(|value| value.to_string()),
                manifest.as_str(),
                edit_digest.to_string(),
                edit_id.to_string(),
            ],
        )
        .unwrap();
}

#[test]
fn p0007_g7_raw_lineage_deletion_reorder_substitution_and_cycle_are_detected_read_only() {
    for (label, sequence) in [
        ("deletion", 0x400),
        ("reorder", 0x500),
        ("substitution", 0x600),
        ("cycle", 0x700),
    ] {
        let fixture = lineage_fixture(label, sequence);
        let valid_before_injection = table_fingerprint(&fixture.repository, LOCALIZED_TABLES);
        match label {
            "deletion" => {
                fixture
                    .repository
                    .open_database()
                    .unwrap()
                    .execute(
                        "DELETE FROM localized_edits WHERE edit_id = ?1",
                        [fixture.repair_edit_id.to_string()],
                    )
                    .unwrap();
            }
            "reorder" => {
                fixture
                    .repository
                    .open_database()
                    .unwrap()
                    .execute_batch(
                        "UPDATE localized_edits SET ordinal = ordinal + 100;
                         UPDATE localized_edits
                         SET ordinal = CASE ordinal WHEN 101 THEN 2 WHEN 102 THEN 1 ELSE ordinal END;",
                    )
                    .unwrap();
            }
            "substitution" => {
                let mut substituted = fixture.repair_input.clone();
                substituted.canonical_content = canonicalize(&json!({
                    "legal": "Des conditions standard s’appliquent",
                    "slug": "summer-campaign",
                    "title": "Substituted after validation",
                }))
                .unwrap()
                .as_str()
                .to_owned();
                replace_edit_artifact(&fixture.repository, fixture.repair_edit_id, &substituted);
            }
            "cycle" => {
                let mut cyclic = fixture.first_input.clone();
                cyclic.supersedes_edit_id = Some(fixture.repair_edit_id);
                cyclic.repair_of_validation_result_digest = Some(fixture.invalid_digest);
                replace_edit_artifact(&fixture.repository, fixture.first_edit_id, &cyclic);
            }
            _ => unreachable!(),
        }
        let injected = table_fingerprint(&fixture.repository, LOCALIZED_TABLES);
        assert_ne!(
            injected, valid_before_injection,
            "{label} injection was inert"
        );
        assert!(matches!(
            fixture
                .repository
                .inspect_localized_changeset(fixture.changeset_id),
            Err(LocalizedContentError::Integrity(_))
        ));
        let after_read = table_fingerprint(&fixture.repository, LOCALIZED_TABLES);
        assert_eq!(after_read, injected, "{label} rejection mutated evidence");
        eprintln!(
            "G7 {label} valid={valid_before_injection} injected={injected} after={after_read}"
        );
    }
}

fn legacy_draft_command(
    changeset_id: &str,
    idempotency_key: &str,
    intent: &str,
) -> CreateChangeSetCommand {
    CreateChangeSetCommand {
        changeset_id: changeset_id.parse::<ChangeSetId>().unwrap(),
        intent: ChangeSetIntent::new(intent).unwrap(),
        requested_base_state: None,
        idempotency_key: idempotency_key.parse::<IdempotencyKey>().unwrap(),
        created_at: "2026-08-20T14:00:00Z".parse::<Timestamp>().unwrap(),
    }
}

fn legacy_edition_command(
    edition_id: &str,
    idempotency_key: &str,
    created_at: &str,
) -> CreateEditionCommand {
    CreateEditionCommand {
        edition_id: edition_id.parse().unwrap(),
        idempotency_key: idempotency_key.parse().unwrap(),
        created_at: created_at.parse().unwrap(),
    }
}

fn downgrade_database_to_v10(repository: &LocalWorkspace) {
    let connection = repository.open_database().unwrap();
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    if version == 10 {
        return;
    }
    assert_eq!(version, 11);
    connection
        .execute_batch(
            "DROP TABLE localized_release_operations;
             DROP TABLE localized_release_metadata;
             DROP TABLE localized_edition_operations;
             DROP TABLE localized_edition_metadata;
             DROP TABLE localized_commits;
             DROP TABLE object_locale_revisions;
             DROP TABLE localized_approvals;
             DROP TABLE localized_submissions;
             DROP TABLE localized_validations;
             DROP TABLE localized_add_operations;
             DROP TABLE localized_edits;
             DROP TABLE localized_changesets;
             DROP TABLE localized_context_build_operations;
             DROP TABLE localized_context_packs;
             DROP TABLE content_resource_intent_operations;
             DROP TABLE content_resource_intents;
             DROP TABLE known_state_artifacts;
             ALTER TABLE known_state DROP COLUMN manifest_json;
             ALTER TABLE known_state DROP COLUMN api_version;
             ALTER TABLE editions DROP COLUMN api_version;
             ALTER TABLE releases DROP COLUMN api_version;
             ALTER TABLE release_proofs DROP COLUMN predicate_type;
             DELETE FROM schema_migrations WHERE version = 11;
             UPDATE workspace_metadata SET schema_version = 10 WHERE singleton = 1;
             PRAGMA user_version = 10;",
        )
        .unwrap();
}

fn drop_effect_column_if_present(connection: &Connection, table: &str) {
    let exists: bool = connection
        .query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM pragma_table_info('{table}')
                     WHERE name = 'effect_digest'
                 )"
            ),
            [],
            |row| row.get(0),
        )
        .unwrap();
    if exists {
        connection
            .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN effect_digest;"))
            .unwrap();
    }
}

fn downgrade_database_to_v9(repository: &LocalWorkspace) {
    downgrade_database_to_v10(repository);
    let connection = repository.open_database().unwrap();
    connection
        .execute_batch(
            "DROP TABLE context_pack_build_operations;
             DROP TABLE context_packs;
             DROP TABLE release_proof_export_outbox;
             DROP TABLE release_operations;
             DROP TABLE release_proofs;
             DROP TABLE environment_current_releases;
             DROP TABLE releases;
             DROP TABLE release_policy_decisions;
             DROP TABLE signing_key_revocations;
             DROP TABLE signing_keys;
             DROP TABLE delegation_revoke_operations;
             DROP TABLE delegation_revocations;
             DROP TABLE delegation_grant_operations;
             DROP TABLE delegations;
             DROP TABLE principal_create_operations;
             DROP TABLE principal_registrations;
             DROP TABLE environment_create_operations;
             DROP TABLE environment_versions;
             DROP TABLE environments;",
        )
        .unwrap();
    for table in [
        "changesets",
        "changeset_add_operations",
        "changeset_submissions",
        "changeset_approvals",
        "changeset_commits",
        "edition_create_operations",
    ] {
        drop_effect_column_if_present(&connection, table);
    }
    connection
        .execute_batch(
            "DELETE FROM schema_migrations WHERE version = 10;
             UPDATE workspace_metadata SET schema_version = 9 WHERE singleton = 1;
             PRAGMA user_version = 9;",
        )
        .unwrap();
}

fn downgrade_database_to_v2(repository: &LocalWorkspace) {
    downgrade_database_to_v9(repository);
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE object_revisions;
             DROP TABLE edition_create_operations;
             DROP TABLE editions;
             DROP TABLE changeset_commits;
             DROP TABLE schema_versions;
             DROP TABLE changeset_approvals;
             DROP TABLE changeset_submissions;
             DROP TABLE changeset_validations;
             DROP TABLE changeset_add_operations;
             DROP TABLE changeset_edits;
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 3;
             UPDATE workspace_metadata SET schema_version = 2 WHERE singleton = 1;
             PRAGMA user_version = 2;",
        )
        .unwrap();
}

fn downgrade_database_to_v1(repository: &LocalWorkspace) {
    downgrade_database_to_v2(repository);
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE changesets;
             DELETE FROM schema_migrations WHERE version >= 2;
             UPDATE workspace_metadata SET schema_version = 1 WHERE singleton = 1;
             PRAGMA user_version = 1;",
        )
        .unwrap();
}

fn downgrade_validated_database_to_v4(repository: &LocalWorkspace) {
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "DROP TABLE changeset_submissions;
             ALTER TABLE changesets DROP COLUMN lifecycle_status;
             DELETE FROM schema_migrations WHERE version >= 5;
             UPDATE workspace_metadata SET schema_version = 4 WHERE singleton = 1;
             PRAGMA user_version = 4;",
        )
        .unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixture performs the exact operation that introduced each legacy version"
)]
fn prepare_exact_legacy_fixture(repository: &LocalWorkspace, target_version: u32) {
    const CHANGESET: &str = "019d0000-0000-7000-8000-000000000810";
    const OTHER_CHANGESET: &str = "019d0000-0000-7000-8000-000000000811";
    const SCHEMA_EDIT: &str = "019d0000-0000-7000-8000-000000000812";
    const OBJECT_EDIT: &str = "019d0000-0000-7000-8000-000000000813";
    const LEGACY_OBJECT: &str = "019d0000-0000-7000-8000-000000000814";
    const EDITION: &str = "019d0000-0000-7000-8000-000000000815";
    const OTHER_EDITION: &str = "019d0000-0000-7000-8000-000000000816";

    assert!((1..=9).contains(&target_version));

    downgrade_database_to_v1(repository);
    if target_version == 1 {
        return;
    }
    create_changeset(
        repository,
        legacy_draft_command(
            CHANGESET,
            "019d0000-0000-7000-8000-000000000820",
            "Define the legacy campaign Schema",
        ),
    )
    .unwrap();
    if target_version == 2 {
        return;
    }
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: CHANGESET.parse().unwrap(),
            edits: vec![localizable_schema_edit(SCHEMA_EDIT, "campaign")],
            idempotency_key: "019d0000-0000-7000-8000-000000000821".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 3 {
        return;
    }
    assert!(
        validate_changeset(repository, CHANGESET.parse().unwrap())
            .unwrap()
            .valid
    );
    if target_version == 4 {
        downgrade_validated_database_to_v4(repository);
        return;
    }
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: CHANGESET.parse().unwrap(),
            submitted_at: "2026-08-20T14:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 5 {
        return;
    }
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: CHANGESET.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-20T14:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 6 {
        return;
    }
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: CHANGESET.parse().unwrap(),
            idempotency_key: "019d0000-0000-7000-8000-000000000822".parse().unwrap(),
            committed_at: "2026-08-20T14:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    if target_version == 7 {
        return;
    }
    create_edition(
        repository,
        legacy_edition_command(
            EDITION,
            "019d0000-0000-7000-8000-000000000823",
            "2026-08-20T14:04:00Z",
        ),
    )
    .unwrap();
    if target_version == 8 {
        return;
    }
    create_changeset(
        repository,
        legacy_draft_command(
            OTHER_CHANGESET,
            "019d0000-0000-7000-8000-000000000824",
            "Create the legacy campaign Object",
        ),
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: OTHER_CHANGESET.parse().unwrap(),
            edits: vec![object_edit(
                OBJECT_EDIT,
                LEGACY_OBJECT,
                "campaign",
                &json!({
                    "legal": "Legacy terms",
                    "slug": "legacy-campaign",
                    "title": "Legacy migration",
                }),
            )],
            idempotency_key: "019d0000-0000-7000-8000-000000000825".parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, OTHER_CHANGESET.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: OTHER_CHANGESET.parse().unwrap(),
            submitted_at: "2026-08-20T14:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: OTHER_CHANGESET.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-20T14:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: OTHER_CHANGESET.parse().unwrap(),
            idempotency_key: "019d0000-0000-7000-8000-000000000826".parse().unwrap(),
            committed_at: "2026-08-20T14:07:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        repository,
        legacy_edition_command(
            OTHER_EDITION,
            "019d0000-0000-7000-8000-000000000827",
            "2026-08-20T14:08:00Z",
        ),
    )
    .unwrap();
}

fn prepare_exact_pre_v11_fixture(repository: &LocalWorkspace, target_version: u32) {
    assert!((1..=10).contains(&target_version));
    if target_version <= 9 {
        prepare_exact_legacy_fixture(repository, target_version);
    } else {
        prepare_exact_legacy_fixture(repository, 9);
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
        downgrade_database_to_v10(repository);
    }
}

fn storage_version(repository: &LocalWorkspace) -> (u32, u32, u32) {
    let connection = repository.open_database().unwrap();
    connection
        .query_row(
            "SELECT schema_version, (SELECT MAX(version) FROM schema_migrations),
                    (SELECT user_version FROM pragma_user_version)
             FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap()
}

fn legacy_fingerprint(repository: &LocalWorkspace, source_version: u32) -> blake3::Hash {
    let connection = repository.open_database().unwrap();
    let mut hash = blake3::Hasher::new_derive_key("proof:p0007:assurance-legacy:v1");
    for sql in [
        "SELECT principal_id, principal_type, identity_provider, identity_subject, enabled FROM principals ORDER BY principal_id",
        "SELECT singleton, workspace_id, bootstrap_principal_id FROM workspace_metadata ORDER BY singleton",
        "SELECT singleton, authoritative_sequence, state_digest FROM known_state ORDER BY singleton",
    ] {
        query_fingerprint(&connection, sql, &mut hash);
    }
    if source_version >= 2 {
        query_fingerprint(
            &connection,
            "SELECT changeset_id, workspace_id, principal_id, intent, requested_base_state,
                    base_authoritative_sequence, base_state, idempotency_key, created_at,
                    status, policy_profile, validation_profile
             FROM changesets ORDER BY changeset_id",
            &mut hash,
        );
    }
    if source_version >= 3 {
        for sql in [
            "SELECT changeset_id, ordinal, edit_id, edit_kind, schema_id, schema_version,
                    document_json, document_digest FROM changeset_edits ORDER BY changeset_id, ordinal",
            "SELECT workspace_id, principal_id, changeset_id, idempotency_key, request_digest,
                    first_ordinal, added_count, total_edit_count
             FROM changeset_add_operations ORDER BY workspace_id, principal_id, changeset_id, idempotency_key",
        ] {
            query_fingerprint(&connection, sql, &mut hash);
        }
    }
    if source_version >= 4 {
        query_fingerprint(
            &connection,
            "SELECT changeset_id, changeset_digest, base_state, validation_profile,
                    validator, valid, results_json, results_digest
             FROM changeset_validations ORDER BY changeset_id",
            &mut hash,
        );
    }
    if source_version >= 5 {
        query_fingerprint(
            &connection,
            "SELECT changeset_id, changeset_digest, validation_results_digest,
                    principal_id, submitted_at FROM changeset_submissions ORDER BY changeset_id",
            &mut hash,
        );
    }
    if source_version >= 6 {
        query_fingerprint(
            &connection,
            "SELECT changeset_id, approval_name, changeset_digest,
                    validation_results_digest, principal_id, approved_at
             FROM changeset_approvals ORDER BY changeset_id, approval_name",
            &mut hash,
        );
    }
    if source_version >= 7 {
        for sql in [
            "SELECT schema_id, schema_version, document_json, document_digest,
                    changeset_id, edit_id, authoritative_sequence
             FROM schema_versions ORDER BY schema_id, schema_version",
            "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                    changeset_digest, validation_results_digest, previous_state,
                    resulting_state, authoritative_sequence, committed_at, edit_count
             FROM changeset_commits ORDER BY changeset_id",
        ] {
            query_fingerprint(&connection, sql, &mut hash);
        }
    }
    if source_version >= 8 {
        query_fingerprint(
            &connection,
            "SELECT edition_id, workspace_id, principal_id, authoritative_sequence,
                    state_digest, schema_set_digest, edition_digest, manifest_json, created_at
             FROM editions ORDER BY edition_id",
            &mut hash,
        );
    }
    if source_version >= 9 {
        query_fingerprint(
            &connection,
            "SELECT object_id, revision, schema_id, schema_version, lifecycle_state,
                    content_json, object_digest, changeset_id, edit_id, authoritative_sequence
             FROM object_revisions ORDER BY object_id, revision",
            &mut hash,
        );
    }
    hash.finalize()
}

fn schema_fingerprint(repository: &LocalWorkspace) -> blake3::Hash {
    let connection = repository.open_database().unwrap();
    let mut hash = blake3::Hasher::new_derive_key("proof:p0007:assurance-schema:v1");
    query_fingerprint(
        &connection,
        "SELECT type, name, tbl_name, sql FROM sqlite_schema
         WHERE name <> 'reject_p0007_v11_migration' ORDER BY type, name",
        &mut hash,
    );
    hash.finalize()
}

fn localized_table_count(repository: &LocalWorkspace) -> i64 {
    let connection = repository.open_database().unwrap();
    [
        "content_resource_intents",
        "content_resource_intent_operations",
        "localized_context_packs",
        "localized_context_build_operations",
        "localized_changesets",
        "localized_edits",
        "localized_add_operations",
        "localized_validations",
        "localized_submissions",
        "localized_approvals",
        "object_locale_revisions",
        "localized_commits",
        "localized_edition_metadata",
        "localized_edition_operations",
        "localized_release_metadata",
        "localized_release_operations",
    ]
    .into_iter()
    .map(|table| {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    })
    .sum()
}

fn assert_zero_localized_migration_facts(repository: &LocalWorkspace) {
    assert_eq!(localized_table_count(repository), 0);
    let connection = repository.open_database().unwrap();
    let artifact: (i64, String, Option<String>, Option<String>) = connection
        .query_row(
            "SELECT COUNT(*), MIN(api_version), MIN(manifest_json), MIN(changeset_id)
             FROM known_state_artifacts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        artifact,
        (1, "proof.dev/known-state/v1".to_owned(), None, None)
    );
}

#[test]
fn p0007_g9_each_v1_to_v10_failure_rolls_back_retries_and_preserves_legacy_hash() {
    for source_version in 1..=10 {
        let directory = TestDirectory::new(&format!("g9-v{source_version}"));
        let repository = initialized_repository(&directory);
        prepare_exact_pre_v11_fixture(&repository, source_version);
        assert_eq!(
            storage_version(&repository),
            (source_version, source_version, source_version)
        );
        let legacy_before = legacy_fingerprint(&repository, source_version);
        let schema_before = schema_fingerprint(&repository);
        repository
            .open_database()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER reject_p0007_v11_migration
                 BEFORE INSERT ON schema_migrations
                 WHEN NEW.version = 11
                 BEGIN
                     SELECT RAISE(ABORT, 'injected P-0007 v11 migration failure');
                 END;",
            )
            .unwrap();

        assert!(matches!(
            rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }),
            Err(RebuildProjectionsError::Storage(_))
        ));
        assert_eq!(
            storage_version(&repository),
            (source_version, source_version, source_version),
            "v{source_version} failure advanced a storage version"
        );
        let legacy_after_failure = legacy_fingerprint(&repository, source_version);
        assert_eq!(
            legacy_after_failure, legacy_before,
            "v{source_version} failure changed legacy evidence"
        );
        assert_eq!(
            schema_fingerprint(&repository),
            schema_before,
            "v{source_version} failure left partial Schema effects"
        );
        repository
            .open_database()
            .unwrap()
            .execute("DROP TRIGGER reject_p0007_v11_migration", [])
            .unwrap();

        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
        assert_eq!(storage_version(&repository), (11, 11, 11));
        let legacy_after_retry = legacy_fingerprint(&repository, source_version);
        assert_eq!(
            legacy_after_retry, legacy_before,
            "v{source_version} retry changed legacy evidence"
        );
        assert_zero_localized_migration_facts(&repository);
        let migration_history = table_fingerprint(&repository, &["schema_migrations"]);

        rebuild_projections(&repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
        assert_eq!(storage_version(&repository), (11, 11, 11));
        assert_eq!(
            legacy_fingerprint(&repository, source_version),
            legacy_before
        );
        assert_eq!(
            table_fingerprint(&repository, &["schema_migrations"]),
            migration_history,
            "v{source_version} retry was not stable"
        );
        assert_zero_localized_migration_facts(&repository);
        eprintln!(
            "G9 v{source_version}->v11 rollback={legacy_after_failure} retry={legacy_after_retry} migration-history={migration_history} versions=11/11/11 localized_rows=0"
        );
    }
}
