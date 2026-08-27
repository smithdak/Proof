use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use proof_application::{
    AddChangeSetEditsCommand, AddLocalizedEditsCommand, ApprovalName, ApproveChangeSetCommand,
    ArtifactKind, BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetIntent,
    CommitChangeSetCommand, CommitLocalizedChangeSetCommand, ContentResourceIntent,
    CreateChangeSetCommand, CreateEditionCommand, CreateEnvironmentCommand,
    CreateLocalizedChangeSetCommand, EnvironmentId, ExpectedLocalizedSource,
    InitializeWorkspaceCommand, IssueContentResourceIntentCommand, LocalizedContentError,
    LocalizedContentRepository, LocalizedContentTarget, LocalizedContextLimits,
    LocalizedContextPack, LocalizedCreationSlot, LocalizedEditAttempt, LocalizedPolicyRule,
    ObjectCreateEdit, ObjectCreateInput, ObjectId, ObjectLocalePutInput, ObjectRevision,
    PrincipalId, RebuildProjectionsCommand, ReleaseId, SchemaCreateEdit, SchemaId, SchemaVersion,
    SubmitChangeSetCommand, WorkspaceId, add_changeset_edits, approve_changeset, commit_changeset,
    create_changeset, create_edition, create_environment, initialize_workspace, promote_release,
    rebuild_projections, submit_changeset, validate_changeset,
};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::LocalWorkspace;
use serde_json::{Value, json};

const WORKSPACE_ID: &str = "019d2000-0000-7000-8000-000000000001";
const PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-000000000002";
const ENVIRONMENT_ID: &str = "preview";
const SCHEMA_ID: &str = "campaign";

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-p0021-authoring-{label}-{}-{sequence}",
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

fn test_id(value: u64) -> String {
    format!("019d2000-0000-7000-8000-{value:012x}")
}

fn schema_document_version(version: u32) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$comment": format!("campaign schema v{version}"),
        "additionalProperties": false,
        "properties": {
            "legal": { "type": "string" },
            "slug": { "type": "string" },
            "title": { "type": "string" },
        },
        "required": ["legal", "slug", "title"],
        "type": "object",
        "x-proof-localizable": if version == 1 { json!(["/legal", "/title"]) } else { json!(["/title"]) },
    })
}

fn source_content(slug: &str, title: &str) -> Value {
    json!({
        "legal": "Standard terms apply",
        "slug": slug,
        "title": title,
    })
}

fn localized_content(slug: &str, title: &str) -> Value {
    json!({
        "legal": "Les conditions standard s'appliquent",
        "slug": slug,
        "title": title,
    })
}

fn schema_edit(edit_id: &str) -> ChangeSetEdit {
    schema_edit_version(edit_id, 1)
}

fn schema_edit_version(edit_id: &str, version: u32) -> ChangeSetEdit {
    named_schema_edit_version(edit_id, SCHEMA_ID, version)
}

fn named_schema_edit_version(edit_id: &str, schema_id: &str, version: u32) -> ChangeSetEdit {
    let document = schema_document_version(version);
    let canonical = canonicalize(&document).unwrap();
    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
        edit_id: edit_id.parse().unwrap(),
        schema_id: SchemaId::new(schema_id).unwrap(),
        schema_version: SchemaVersion::new(version).unwrap(),
        canonical_document: canonical.as_str().to_owned(),
        document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical),
    })
}

fn legacy_object_edit(edit_id: &str, object_id: ObjectId, content: &Value) -> ChangeSetEdit {
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
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

struct BaselineFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    anchor_object_id: ObjectId,
    anchor_source: ExpectedLocalizedSource,
}

#[expect(
    clippy::too_many_lines,
    reason = "the retained fixture establishes one complete released localized-content baseline"
)]
fn baseline_fixture(label: &str) -> BaselineFixture {
    let directory = TestDirectory::new(label);
    let repository = LocalWorkspace::new(directory.path()).unwrap();
    initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
            bootstrap_principal_id: PRINCIPAL_ID.parse::<PrincipalId>().unwrap(),
        },
    )
    .unwrap();

    let changeset_id = test_id(0x10);
    let schema_edit_id = test_id(0x11);
    let object_edit_id = test_id(0x12);
    let second_schema_edit_id = test_id(0x1d);
    let anchor_object_id = test_id(0x13).parse::<ObjectId>().unwrap();
    let anchor_content = source_content("anchor", "Anchor");
    create_changeset(
        &repository,
        CreateChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            intent: ChangeSetIntent::new("Create the authoring baseline").unwrap(),
            requested_base_state: None,
            idempotency_key: test_id(0x14).parse().unwrap(),
            created_at: "2026-08-26T00:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id: changeset_id.parse().unwrap(),
            edits: vec![
                schema_edit(&schema_edit_id),
                schema_edit_version(&second_schema_edit_id, 2),
                legacy_object_edit(&object_edit_id, anchor_object_id, &anchor_content),
            ],
            idempotency_key: test_id(0x15).parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(&repository, changeset_id.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            submitted_at: "2026-08-26T00:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-26T00:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            idempotency_key: test_id(0x16).parse().unwrap(),
            committed_at: "2026-08-26T00:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_edition(
        &repository,
        CreateEditionCommand {
            edition_id: test_id(0x17).parse().unwrap(),
            idempotency_key: test_id(0x18).parse().unwrap(),
            created_at: "2026-08-26T00:04:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        &repository,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse::<EnvironmentId>().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: test_id(0x19).parse().unwrap(),
            created_at: "2026-08-26T00:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        &repository,
        proof_application::PromoteReleaseCommand {
            release_id: test_id(0x1a).parse::<ReleaseId>().unwrap(),
            proof_id: test_id(0x1b).parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: test_id(0x17).parse().unwrap(),
            idempotency_key: test_id(0x1c).parse().unwrap(),
            released_at: "2026-08-26T00:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();

    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    BaselineFixture {
        _directory: directory,
        repository,
        anchor_object_id,
        anchor_source: ExpectedLocalizedSource {
            revision: ObjectRevision::INITIAL,
            digest: object_revision_digest(
                anchor_object_id,
                &schema_id,
                schema_version,
                &anchor_content,
            )
            .unwrap(),
            schema_id,
            schema_version,
        },
    }
}

fn creation_intent_command(
    sequence: u64,
    object_id: ObjectId,
) -> IssueContentResourceIntentCommand {
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    IssueContentResourceIntentCommand {
        intent_id: test_id(sequence).parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        targets: vec![LocalizedContentTarget {
            object_id,
            schema_id: schema_id.clone(),
            locale: "fr-FR".parse().unwrap(),
        }],
        creations: vec![LocalizedCreationSlot {
            object_id,
            schema_id,
            locales: vec!["fr-FR".parse().unwrap()],
        }],
        idempotency_key: test_id(sequence + 1).parse().unwrap(),
        issued_at: "2026-08-26T01:00:00Z".parse().unwrap(),
    }
}

struct DraftFixture {
    intent_command: IssueContentResourceIntentCommand,
    intent: ContentResourceIntent,
    context: LocalizedContextPack,
    changeset_id: proof_application::ChangeSetId,
}

fn build_draft(
    repository: &LocalWorkspace,
    intent_command: IssueContentResourceIntentCommand,
    sequence: u64,
    max_objects: u32,
) -> DraftFixture {
    build_draft_with_policy(
        repository,
        intent_command,
        sequence,
        max_objects,
        Vec::new(),
    )
}

fn build_draft_with_policy(
    repository: &LocalWorkspace,
    intent_command: IssueContentResourceIntentCommand,
    sequence: u64,
    max_objects: u32,
    policy_rules: Vec<LocalizedPolicyRule>,
) -> DraftFixture {
    let intent = repository
        .issue_content_resource_intent(intent_command.clone())
        .unwrap();
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: test_id(sequence + 2).parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules,
            limits: LocalizedContextLimits {
                max_objects,
                max_edits: 10,
                max_validation_attempts: 5,
                max_bytes: 1_048_576,
            },
            idempotency_key: test_id(sequence + 3).parse().unwrap(),
            created_at: "2026-08-26T01:01:00Z".parse().unwrap(),
            expires_at: "2026-08-27T01:01:00Z".parse().unwrap(),
        })
        .unwrap();
    let changeset_id = test_id(sequence + 4).parse().unwrap();
    repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Create and localize an Object").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: test_id(sequence + 5).parse().unwrap(),
            created_at: "2026-08-26T01:02:00Z".parse().unwrap(),
        })
        .unwrap();
    DraftFixture {
        intent_command,
        intent,
        context,
        changeset_id,
    }
}

fn create_input(object_id: ObjectId, schema_version: u32, content: &Value) -> ObjectCreateInput {
    ObjectCreateInput {
        object_id,
        schema_id: SchemaId::new(SCHEMA_ID).unwrap(),
        schema_version: SchemaVersion::new(schema_version).unwrap(),
        canonical_content: canonicalize(content).unwrap().as_str().to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    }
}

fn put_input(
    object_id: ObjectId,
    locale: &str,
    expected_source: ExpectedLocalizedSource,
    content: &Value,
) -> ObjectLocalePutInput {
    ObjectLocalePutInput {
        object_id,
        locale: locale.parse().unwrap(),
        expected_source,
        expected_target: None,
        canonical_content: canonicalize(content).unwrap().as_str().to_owned(),
        supersedes_edit_id: None,
        repair_of_validation_result_digest: None,
    }
}

fn expected_created_source(object_id: ObjectId, content: &Value) -> ExpectedLocalizedSource {
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    ExpectedLocalizedSource {
        revision: ObjectRevision::INITIAL,
        digest: object_revision_digest(object_id, &schema_id, schema_version, content).unwrap(),
        schema_id,
        schema_version,
    }
}

fn commit_legacy_object(
    repository: &LocalWorkspace,
    sequence: u64,
    object_id: ObjectId,
    content: &Value,
) {
    let changeset_id = test_id(sequence);
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            intent: ChangeSetIntent::new("Win the creation race").unwrap(),
            requested_base_state: None,
            idempotency_key: test_id(sequence + 1).parse().unwrap(),
            created_at: "2026-08-26T02:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: changeset_id.parse().unwrap(),
            edits: vec![legacy_object_edit(
                &test_id(sequence + 2),
                object_id,
                content,
            )],
            idempotency_key: test_id(sequence + 3).parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, changeset_id.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            submitted_at: "2026-08-26T02:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-26T02:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            idempotency_key: test_id(sequence + 4).parse().unwrap(),
            committed_at: "2026-08-26T02:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
}

fn commit_schema(repository: &LocalWorkspace, sequence: u64, schema_id: &str) {
    let changeset_id = test_id(sequence);
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            intent: ChangeSetIntent::new("Commit a post-Release Schema").unwrap(),
            requested_base_state: None,
            idempotency_key: test_id(sequence + 1).parse().unwrap(),
            created_at: "2026-08-26T03:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id: changeset_id.parse().unwrap(),
            edits: vec![named_schema_edit_version(
                &test_id(sequence + 2),
                schema_id,
                1,
            )],
            idempotency_key: test_id(sequence + 3).parse().unwrap(),
        },
    )
    .unwrap();
    assert!(
        validate_changeset(repository, changeset_id.parse().unwrap())
            .unwrap()
            .valid
    );
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            submitted_at: "2026-08-26T03:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-26T03:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id: changeset_id.parse().unwrap(),
            idempotency_key: test_id(sequence + 4).parse().unwrap(),
            committed_at: "2026-08-26T03:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
}

fn target_values(targets: &[LocalizedContentTarget]) -> Vec<Value> {
    targets
        .iter()
        .map(|target| {
            json!({
                "locale": target.locale.as_str(),
                "object_id": target.object_id.to_string(),
                "schema_id": target.schema_id.as_str(),
            })
        })
        .collect()
}

fn creation_values(creations: &[LocalizedCreationSlot]) -> Vec<Value> {
    creations
        .iter()
        .map(|slot| {
            json!({
                "locales": slot.locales.iter().map(proof_application::LocaleId::as_str).collect::<Vec<_>>(),
                "object_id": slot.object_id.to_string(),
                "schema_id": slot.schema_id.as_str(),
            })
        })
        .collect()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained intent closure test includes the post-Release Schema boundary"
)]
fn creation_slot_issuance_is_precise_and_closed() {
    let fixture = baseline_fixture("intent-closure");
    let repository = &fixture.repository;
    let object_id = test_id(0x100).parse().unwrap();
    let issued = repository
        .issue_content_resource_intent(creation_intent_command(0x110, object_id))
        .unwrap();
    let manifest: Value = serde_json::from_str(&issued.canonical_json).unwrap();
    assert_eq!(
        manifest["api_version"],
        "proof.dev/content-resource-intent/v2"
    );
    assert_eq!(issued.creations.len(), 1);

    let existing = repository
        .issue_content_resource_intent(creation_intent_command(0x120, fixture.anchor_object_id))
        .unwrap_err();
    assert_eq!(existing, LocalizedContentError::ObjectExists);

    let missing_object_id = test_id(0x130).parse().unwrap();
    let mut missing_schema = creation_intent_command(0x131, missing_object_id);
    missing_schema.targets[0].schema_id = SchemaId::new("missing-schema").unwrap();
    missing_schema.creations[0].schema_id = SchemaId::new("missing-schema").unwrap();
    assert_eq!(
        repository
            .issue_content_resource_intent(missing_schema)
            .unwrap_err(),
        LocalizedContentError::SchemaNotFound
    );

    let post_release_schema = "post-release-campaign";
    commit_schema(repository, 0x180, post_release_schema);
    let connection = repository.open_database().unwrap();
    let released_state: (i64, String) = connection
        .query_row(
            "SELECT edition.authoritative_sequence, edition.state_digest
             FROM environment_current_releases AS current
             JOIN releases AS release ON release.release_id = current.release_id
             JOIN editions AS edition ON edition.edition_id = release.edition_id
             WHERE current.environment_id = ?1",
            [ENVIRONMENT_ID],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    // Isolate the Release-bounded lookup while retaining a later committed Schema fact.
    connection
        .execute(
            "UPDATE known_state
             SET authoritative_sequence = ?1, state_digest = ?2,
                 api_version = 'proof.dev/known-state/v1', manifest_json = NULL
             WHERE singleton = 1",
            (&released_state.0, &released_state.1),
        )
        .unwrap();
    drop(connection);
    let post_release_object_id = test_id(0x190).parse().unwrap();
    let mut post_release = creation_intent_command(0x191, post_release_object_id);
    post_release.targets[0].schema_id = SchemaId::new(post_release_schema).unwrap();
    post_release.creations[0].schema_id = SchemaId::new(post_release_schema).unwrap();
    assert_eq!(
        repository
            .issue_content_resource_intent(post_release)
            .unwrap_err(),
        LocalizedContentError::SchemaNotFound
    );

    let duplicate_object_id = test_id(0x140).parse().unwrap();
    let mut duplicate = creation_intent_command(0x141, duplicate_object_id);
    duplicate.creations.push(duplicate.creations[0].clone());
    assert_eq!(
        repository
            .issue_content_resource_intent(duplicate)
            .unwrap_err(),
        LocalizedContentError::InvalidInput
    );

    for (sequence, mutate) in [(0x150, "locale"), (0x160, "schema")] {
        let mismatch_object_id = test_id(sequence + 10).parse().unwrap();
        let mut mismatch = creation_intent_command(sequence, mismatch_object_id);
        if mutate == "locale" {
            mismatch.targets[0].locale = "de-DE".parse().unwrap();
        } else {
            mismatch.targets[0].schema_id = SchemaId::new("other-schema").unwrap();
        }
        assert_eq!(
            repository
                .issue_content_resource_intent(mismatch)
                .unwrap_err(),
            LocalizedContentError::InvalidInput,
            "{mutate} mismatch"
        );
    }

    let mut oversized = creation_intent_command(0x170, test_id(0x1_000).parse().unwrap());
    for offset in 1..=50 {
        let object_id = test_id(0x1_000 + offset).parse().unwrap();
        let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
        oversized.targets.push(LocalizedContentTarget {
            object_id,
            schema_id: schema_id.clone(),
            locale: "fr-FR".parse().unwrap(),
        });
        oversized.creations.push(LocalizedCreationSlot {
            object_id,
            schema_id,
            locales: vec!["fr-FR".parse().unwrap()],
        });
    }
    assert_eq!(
        repository
            .issue_content_resource_intent(oversized)
            .unwrap_err(),
        LocalizedContentError::LimitExceeded
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained creation-repair matrix proves precise edges, validation causality, and effective-only commit"
)]
fn creation_repairs_follow_same_object_linear_validation_bound_lineage() {
    let fixture = baseline_fixture("creation-repair");
    let repository = &fixture.repository;
    let object_id = test_id(0x800).parse().unwrap();
    let draft = build_draft_with_policy(
        repository,
        creation_intent_command(0x810, object_id),
        0x810,
        1,
        vec![LocalizedPolicyRule {
            locale: "fr-FR".parse().unwrap(),
            pointer: "/title".to_owned(),
            disallowed_values: vec!["Initial title".to_owned()],
        }],
    );
    let initial_source = source_content("repair-item", "Initial title");
    let repaired_source = source_content("repair-item", "Repaired title");
    let initial_create_id = test_id(0x816).parse().unwrap();
    let initial_put_id = test_id(0x817).parse().unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![
                LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &initial_source)),
                LocalizedEditAttempt::LocalePut(put_input(
                    object_id,
                    "fr-FR",
                    expected_created_source(object_id, &initial_source),
                    &localized_content("repair-item", "Titre initial"),
                )),
            ],
            assigned_edit_ids: vec![initial_create_id, initial_put_id],
            idempotency_key: test_id(0x818).parse().unwrap(),
        })
        .unwrap();
    let initial_validation = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert!(!initial_validation.valid);
    assert_eq!(initial_validation.findings.len(), 1);
    let creation_finding = &initial_validation.findings[0];
    assert_eq!(
        creation_finding.code,
        proof_application::PROHIBITED_LEGAL_CLAIM_CODE
    );
    assert_eq!(creation_finding.edit_id, initial_create_id);
    assert_eq!(creation_finding.object_id, object_id);
    assert_eq!(creation_finding.locale.as_str(), "fr-FR");
    assert_eq!(creation_finding.pointer.as_deref(), Some("/title"));
    let creation_invalid_digest = initial_validation.validation_results_digest;

    let mut malformed = create_input(object_id, 1, &repaired_source);
    malformed.supersedes_edit_id = Some(initial_create_id);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(malformed)],
                assigned_edit_ids: vec![test_id(0x819).parse().unwrap()],
                idempotency_key: test_id(0x81a).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidRepairEvidence
    );
    let mut malformed = create_input(object_id, 1, &repaired_source);
    malformed.repair_of_validation_result_digest = Some(creation_invalid_digest);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(malformed)],
                assigned_edit_ids: vec![test_id(0x81b).parse().unwrap()],
                idempotency_key: test_id(0x81c).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::DuplicateActiveTarget
    );
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                    object_id,
                    1,
                    &repaired_source,
                ))],
                assigned_edit_ids: vec![test_id(0x81d).parse().unwrap()],
                idempotency_key: test_id(0x81e).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::DuplicateActiveTarget
    );
    let mut wrong_object = create_input(test_id(0x820).parse().unwrap(), 1, &repaired_source);
    wrong_object.supersedes_edit_id = Some(initial_create_id);
    wrong_object.repair_of_validation_result_digest = Some(creation_invalid_digest);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(wrong_object)],
                assigned_edit_ids: vec![test_id(0x821).parse().unwrap()],
                idempotency_key: test_id(0x822).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidSupersession
    );

    let repaired_create_id = test_id(0x823).parse().unwrap();
    let mut repaired_create = create_input(object_id, 1, &repaired_source);
    repaired_create.supersedes_edit_id = Some(initial_create_id);
    repaired_create.repair_of_validation_result_digest = Some(creation_invalid_digest);
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![LocalizedEditAttempt::ObjectCreate(repaired_create.clone())],
            assigned_edit_ids: vec![repaired_create_id],
            idempotency_key: test_id(0x824).parse().unwrap(),
        })
        .unwrap();
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(repaired_create)],
                assigned_edit_ids: vec![test_id(0x825).parse().unwrap()],
                idempotency_key: test_id(0x826).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidSupersession
    );

    let source_validation = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert!(!source_validation.valid);
    assert_eq!(source_validation.findings.len(), 1);
    let source_finding = &source_validation.findings[0];
    assert_eq!(
        source_finding.code,
        proof_application::LOCALIZED_SOURCE_CONFLICT_CODE
    );
    assert_eq!(source_finding.edit_id, initial_put_id);
    assert_eq!(source_finding.object_id, object_id);
    assert_eq!(source_finding.locale.as_str(), "fr-FR");
    assert_eq!(source_finding.pointer, None);
    let put_invalid_digest = source_validation.validation_results_digest;
    let mut stale_put = put_input(
        object_id,
        "fr-FR",
        expected_created_source(object_id, &repaired_source),
        &localized_content("repair-item", "Titre réparé"),
    );
    stale_put.supersedes_edit_id = Some(initial_put_id);
    stale_put.repair_of_validation_result_digest = Some(creation_invalid_digest);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::LocalePut(stale_put)],
                assigned_edit_ids: vec![test_id(0x82a).parse().unwrap()],
                idempotency_key: test_id(0x82b).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidRepairEvidence
    );
    let repaired_put_id = test_id(0x827).parse().unwrap();
    let mut repaired_put = put_input(
        object_id,
        "fr-FR",
        expected_created_source(object_id, &repaired_source),
        &localized_content("repair-item", "Titre réparé"),
    );
    repaired_put.supersedes_edit_id = Some(initial_put_id);
    repaired_put.repair_of_validation_result_digest = Some(put_invalid_digest);
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![LocalizedEditAttempt::LocalePut(repaired_put)],
            assigned_edit_ids: vec![repaired_put_id],
            idempotency_key: test_id(0x828).parse().unwrap(),
        })
        .unwrap();
    assert!(
        repository
            .validate_localized_changeset(draft.changeset_id)
            .unwrap()
            .valid
    );
    repository
        .submit_localized_changeset(draft.changeset_id, "2026-08-26T04:00:00Z".parse().unwrap())
        .unwrap();
    repository
        .approve_localized_changeset(
            draft.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-26T04:01:00Z".parse().unwrap(),
        )
        .unwrap();
    repository
        .commit_localized_changeset(CommitLocalizedChangeSetCommand {
            changeset_id: draft.changeset_id,
            idempotency_key: test_id(0x829).parse().unwrap(),
            committed_at: "2026-08-26T04:02:00Z".parse().unwrap(),
        })
        .unwrap();
    let connection = repository.open_database().unwrap();
    let committed: (String, String) = connection
        .query_row(
            "SELECT content_json, edit_id FROM object_revisions WHERE object_id = ?1",
            [object_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        committed.0,
        canonicalize(&repaired_source).unwrap().as_str()
    );
    assert_eq!(committed.1, repaired_create_id.to_string());
    assert_eq!(
        connection
            .query_row(
                "SELECT edit_id FROM object_locale_revisions
                 WHERE object_id = ?1 AND locale = 'fr-FR'",
                [object_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        repaired_put_id.to_string()
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained version test reproduces both v2 and persisted v1 operation evidence"
)]
fn intent_operation_versions_follow_the_stored_artifact_version() {
    let fixture = baseline_fixture("intent-version");
    let repository = &fixture.repository;
    let command = IssueContentResourceIntentCommand {
        intent_id: test_id(0x200).parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        targets: vec![LocalizedContentTarget {
            object_id: fixture.anchor_object_id,
            schema_id: SchemaId::new(SCHEMA_ID).unwrap(),
            locale: "fr-FR".parse().unwrap(),
        }],
        creations: Vec::new(),
        idempotency_key: test_id(0x201).parse().unwrap(),
        issued_at: "2026-08-26T01:00:00Z".parse().unwrap(),
    };
    let intent = repository
        .issue_content_resource_intent(command.clone())
        .unwrap();
    let manifest: Value = serde_json::from_str(&intent.canonical_json).unwrap();
    assert_eq!(
        manifest["api_version"],
        "proof.dev/content-resource-intent/v2"
    );
    assert_eq!(manifest["creations"], json!([]));

    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/content-intent.issue/v2",
        "creations": creation_values(&intent.creations),
        "environment_id": intent.environment_id.as_str(),
        "idempotency_key": command.idempotency_key.to_string(),
        "intent_id": intent.intent_id.to_string(),
        "issued_at": intent.issued_at.to_string(),
        "targets": target_values(&intent.targets),
    }))
    .unwrap();
    let request_digest = digest(ArtifactKind::OperationEffectV1, &request);
    let effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "content-intent.issue/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "intent_digest": intent.intent_digest.to_string(),
            "intent_id": intent.intent_id.to_string(),
        },
    }))
    .unwrap();
    let effect_digest = digest(ArtifactKind::OperationEffectV1, &effect);
    let connection = repository.open_database().unwrap();
    let persisted: (String, String) = connection
        .query_row(
            "SELECT request_digest, effect_digest FROM content_resource_intent_operations
             WHERE intent_id = ?1",
            [intent.intent_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        persisted,
        (request_digest.to_string(), effect_digest.to_string())
    );

    let legacy_manifest = canonicalize(&json!({
        "api_version": "proof.dev/content-resource-intent/v1",
        "base": {
            "edition": {
                "api_version": intent.base.edition.api_version,
                "digest": intent.base.edition.digest.to_string(),
                "edition_id": intent.base.edition.edition_id.to_string(),
            },
            "known_state": {
                "api_version": intent.base.known_state.api_version,
                "authoritative_sequence": intent.base.known_state.authoritative_sequence,
                "digest": intent.base.known_state.digest.to_string(),
            },
            "release": {
                "api_version": intent.base.release.api_version,
                "digest": intent.base.release.digest.to_string(),
                "release_id": intent.base.release.release_id.to_string(),
            },
        },
        "environment_id": intent.environment_id.as_str(),
        "intent_id": intent.intent_id.to_string(),
        "issued_at": intent.issued_at.to_string(),
        "issued_by_principal_id": intent.issued_by_principal_id.to_string(),
        "targets": target_values(&intent.targets),
        "workspace_id": intent.workspace_id.to_string(),
    }))
    .unwrap();
    let legacy_intent_digest = digest(ArtifactKind::ContentResourceIntentV1, &legacy_manifest);
    let legacy_request = canonicalize(&json!({
        "api_version": "proof.dev/operation/content-intent.issue/v1",
        "environment_id": intent.environment_id.as_str(),
        "idempotency_key": command.idempotency_key.to_string(),
        "intent_id": intent.intent_id.to_string(),
        "issued_at": intent.issued_at.to_string(),
        "targets": target_values(&intent.targets),
    }))
    .unwrap();
    let legacy_request_digest = digest(ArtifactKind::OperationEffectV1, &legacy_request);
    let legacy_effect = canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "content-intent.issue/v1",
        "request_digest": legacy_request_digest.to_string(),
        "result": {
            "intent_digest": legacy_intent_digest.to_string(),
            "intent_id": intent.intent_id.to_string(),
        },
    }))
    .unwrap();
    let legacy_effect_digest = digest(ArtifactKind::OperationEffectV1, &legacy_effect);
    connection
        .execute(
            "UPDATE content_resource_intents SET manifest_json = ?1, intent_digest = ?2
             WHERE intent_id = ?3",
            (
                legacy_manifest.as_str(),
                legacy_intent_digest.to_string(),
                intent.intent_id.to_string(),
            ),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE content_resource_intent_operations
             SET request_digest = ?1, effect_digest = ?2 WHERE intent_id = ?3",
            (
                legacy_request_digest.to_string(),
                legacy_effect_digest.to_string(),
                intent.intent_id.to_string(),
            ),
        )
        .unwrap();
    drop(connection);

    let loaded = repository
        .get_content_resource_intent(intent.intent_id)
        .unwrap();
    assert_eq!(loaded.canonical_json, legacy_manifest.as_str());
    assert_eq!(
        repository
            .issue_content_resource_intent(command.clone())
            .unwrap(),
        loaded
    );

    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE content_resource_intent_operations SET effect_digest = ?1
             WHERE intent_id = ?2",
            (
                format!("blake3:{}", "f".repeat(64)),
                intent.intent_id.to_string(),
            ),
        )
        .unwrap();
    assert!(matches!(
        repository.get_content_resource_intent(intent.intent_id),
        Err(LocalizedContentError::Integrity(_))
    ));
}

#[test]
fn creation_policy_is_checked_against_only_the_selected_schema_candidate() {
    let fixture = baseline_fixture("selected-candidate-policy");
    let repository = &fixture.repository;
    let object_id = test_id(0x280).parse().unwrap();
    let intent = repository
        .issue_content_resource_intent(creation_intent_command(0x281, object_id))
        .unwrap();
    let context = repository
        .build_localized_context(BuildLocalizedContextCommand {
            context_pack_id: test_id(0x283).parse().unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            policy_rules: vec![proof_application::LocalizedPolicyRule {
                locale: "fr-FR".parse().unwrap(),
                pointer: "/legal".to_owned(),
                disallowed_values: vec!["Forbidden".to_owned()],
            }],
            limits: LocalizedContextLimits {
                max_objects: 1,
                max_edits: 4,
                max_validation_attempts: 2,
                max_bytes: 1_048_576,
            },
            idempotency_key: test_id(0x284).parse().unwrap(),
            created_at: "2026-08-26T01:01:00Z".parse().unwrap(),
            expires_at: "2026-08-27T01:01:00Z".parse().unwrap(),
        })
        .unwrap();
    let changeset_id = test_id(0x285).parse().unwrap();
    repository
        .create_localized_changeset(CreateLocalizedChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Select the creation Schema").unwrap(),
            resource_intent_id: intent.intent_id,
            resource_intent_digest: intent.intent_digest,
            context_pack_id: context.context_pack_id,
            context_pack_digest: context.context_pack_digest,
            idempotency_key: test_id(0x286).parse().unwrap(),
            created_at: "2026-08-26T01:02:00Z".parse().unwrap(),
        })
        .unwrap();
    let source = source_content("selected", "Selected");
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                    object_id, 2, &source,
                ))],
                assigned_edit_ids: vec![test_id(0x287).parse().unwrap()],
                idempotency_key: test_id(0x288).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::InvalidInput
    );
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id,
            edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                object_id, 1, &source,
            ))],
            assigned_edit_ids: vec![test_id(0x289).parse().unwrap()],
            idempotency_key: test_id(0x28a).parse().unwrap(),
        })
        .unwrap();
}

#[test]
fn creation_policy_findings_cover_each_reserved_locale_once() {
    let fixture = baseline_fixture("creation-policy-locales");
    let repository = &fixture.repository;
    let object_id = test_id(0x2a0).parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let locales = vec!["de-DE".parse().unwrap(), "fr-FR".parse().unwrap()];
    let intent = IssueContentResourceIntentCommand {
        intent_id: test_id(0x2a1).parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        targets: locales
            .iter()
            .cloned()
            .map(|locale| LocalizedContentTarget {
                object_id,
                schema_id: schema_id.clone(),
                locale,
            })
            .collect(),
        creations: vec![LocalizedCreationSlot {
            object_id,
            schema_id,
            locales: locales.clone(),
        }],
        idempotency_key: test_id(0x2a2).parse().unwrap(),
        issued_at: "2026-08-26T01:00:00Z".parse().unwrap(),
    };
    let rules = locales
        .iter()
        .cloned()
        .map(|locale| LocalizedPolicyRule {
            locale,
            pointer: "/title".to_owned(),
            disallowed_values: vec!["Blocked title".to_owned()],
        })
        .collect();
    let draft = build_draft_with_policy(repository, intent, 0x2b0, 1, rules);
    let source = source_content("policy-locales", "Blocked title");
    let source_precondition = expected_created_source(object_id, &source);
    let create_id = test_id(0x2b6).parse().unwrap();
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![
                LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &source)),
                LocalizedEditAttempt::LocalePut(put_input(
                    object_id,
                    "de-DE",
                    source_precondition.clone(),
                    &localized_content("policy-locales", "Deutscher Titel"),
                )),
                LocalizedEditAttempt::LocalePut(put_input(
                    object_id,
                    "fr-FR",
                    source_precondition,
                    &localized_content("policy-locales", "Titre français"),
                )),
            ],
            assigned_edit_ids: vec![
                create_id,
                test_id(0x2b7).parse().unwrap(),
                test_id(0x2b8).parse().unwrap(),
            ],
            idempotency_key: test_id(0x2b9).parse().unwrap(),
        })
        .unwrap();
    let validation = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert!(!validation.valid);
    assert_eq!(validation.findings.len(), 2);
    assert_eq!(
        validation
            .findings
            .iter()
            .map(|finding| finding.locale.as_str())
            .collect::<Vec<_>>(),
        ["de-DE", "fr-FR"]
    );
    assert!(validation.findings.iter().all(|finding| {
        finding.code == proof_application::PROHIBITED_LEGAL_CLAIM_CODE
            && finding.edit_id == create_id
            && finding.pointer.as_deref() == Some("/title")
    }));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained happy path verifies commit, provenance, replay, and projection rebuild"
)]
fn create_before_put_commits_revision_one_with_causal_provenance() {
    let fixture = baseline_fixture("happy");
    let repository = &fixture.repository;
    let object_id = test_id(0x300).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x310, object_id),
        0x310,
        1,
    );
    let context_manifest: Value = serde_json::from_str(&draft.context.manifest_json).unwrap();
    let resources = context_manifest["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    let resource = &resources[0];
    assert_eq!(resource["object_id"], object_id.to_string());
    assert_eq!(resource["locale"], "fr-FR");
    assert_eq!(
        resource["source"],
        json!({
            "absent": true,
            "api_version": "proof.dev/object-revision-absence/v1",
            "authoritative_sequence": draft.intent.base.known_state.authoritative_sequence,
        })
    );
    assert_eq!(
        resource["target"],
        json!({
            "absent": true,
            "api_version": "proof.dev/object-locale-absence/v1",
            "authoritative_sequence": draft.intent.base.known_state.authoritative_sequence,
        })
    );
    assert_eq!(
        resource["schema_candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["schema_version"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let artifacts_schema: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../conformance/v2/localized-content/schemas/artifacts.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let artifacts_validator = jsonschema::draft202012::new(&artifacts_schema).unwrap();
    assert!(
        artifacts_validator.is_valid(&context_manifest),
        "creation ContextPack must satisfy the frozen artifact schema"
    );
    let source = source_content("new-item", "New item");
    let localized = localized_content("new-item", "Nouvel article");
    let create_edit_id = test_id(0x316);
    let put_edit_id = test_id(0x317);
    let add_command = AddLocalizedEditsCommand {
        changeset_id: draft.changeset_id,
        edits: vec![
            LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &source)),
            LocalizedEditAttempt::LocalePut(put_input(
                object_id,
                "fr-FR",
                expected_created_source(object_id, &source),
                &localized,
            )),
        ],
        assigned_edit_ids: vec![
            create_edit_id.parse().unwrap(),
            put_edit_id.parse().unwrap(),
        ],
        idempotency_key: test_id(0x318).parse().unwrap(),
    };
    let added = repository.add_localized_edits(add_command.clone()).unwrap();
    assert_eq!(
        repository.add_localized_edits(add_command.clone()).unwrap(),
        added
    );
    let validation = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert!(validation.valid);
    let validation_manifest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT results_json FROM localized_validations
             WHERE changeset_id = ?1 AND attempt = 1",
            [draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let validation_manifest: Value = serde_json::from_str(&validation_manifest).unwrap();
    assert_eq!(
        validation_manifest["schema_digests"],
        json!([
            {
                "document_digest": digest(
                    ArtifactKind::SchemaVersionV1,
                    &canonicalize(&schema_document_version(1)).unwrap(),
                ).to_string(),
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            {
                "document_digest": digest(
                    ArtifactKind::SchemaVersionV1,
                    &canonicalize(&schema_document_version(2)).unwrap(),
                ).to_string(),
                "schema_id": SCHEMA_ID,
                "schema_version": 2,
            },
        ])
    );
    assert_eq!(
        repository
            .validate_localized_changeset(draft.changeset_id)
            .unwrap(),
        validation
    );
    repository
        .submit_localized_changeset(draft.changeset_id, "2026-08-26T01:03:00Z".parse().unwrap())
        .unwrap();
    repository
        .approve_localized_changeset(
            draft.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-26T01:04:00Z".parse().unwrap(),
        )
        .unwrap();
    let commit_command = CommitLocalizedChangeSetCommand {
        changeset_id: draft.changeset_id,
        idempotency_key: test_id(0x319).parse().unwrap(),
        committed_at: "2026-08-26T01:05:00Z".parse().unwrap(),
    };
    let committed = repository
        .commit_localized_changeset(commit_command)
        .unwrap();
    assert_eq!(
        repository
            .commit_localized_changeset(commit_command)
            .unwrap(),
        committed
    );
    assert_eq!(committed.renditions.len(), 1);
    assert_eq!(
        committed.resulting_state.authoritative_sequence,
        committed.previous_state.authoritative_sequence + 2
    );
    assert_eq!(
        committed.renditions[0].authoritative_sequence,
        committed.previous_state.authoritative_sequence + 2
    );
    assert_eq!(committed.renditions[0].source_object_revision.get(), 1);
    assert_eq!(
        committed.renditions[0].source_object_digest,
        expected_created_source(object_id, &source).digest
    );

    let connection = repository.open_database().unwrap();
    let object_row: (
        i64,
        String,
        i64,
        String,
        String,
        String,
        String,
        String,
        i64,
    ) = connection
        .query_row(
            "SELECT revision, schema_id, schema_version, lifecycle_state, content_json,
                    object_digest, changeset_id, edit_id, authoritative_sequence
             FROM object_revisions WHERE object_id = ?1",
            [object_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(object_row.0, 1);
    assert_eq!(object_row.1, SCHEMA_ID);
    assert_eq!(object_row.2, 1);
    assert_eq!(object_row.3, "active");
    assert_eq!(object_row.4, canonicalize(&source).unwrap().as_str());
    assert_eq!(
        object_row.5,
        expected_created_source(object_id, &source)
            .digest
            .to_string()
    );
    assert_eq!(object_row.6, draft.changeset_id.to_string());
    assert_eq!(object_row.7, create_edit_id);
    assert_eq!(
        u64::try_from(object_row.8).unwrap(),
        committed.previous_state.authoritative_sequence + 1
    );
    let rendition_provenance: (String, String, i64) = connection
        .query_row(
            "SELECT changeset_id, edit_id, authoritative_sequence
             FROM object_locale_revisions WHERE object_id = ?1 AND locale = 'fr-FR'",
            [object_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(rendition_provenance.0, draft.changeset_id.to_string());
    assert_eq!(rendition_provenance.1, put_edit_id);
    assert_eq!(
        u64::try_from(rendition_provenance.2).unwrap(),
        committed.previous_state.authoritative_sequence + 2
    );
    drop(connection);

    assert_eq!(
        repository
            .issue_content_resource_intent(draft.intent_command)
            .unwrap(),
        draft.intent
    );
    let rebuilt =
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    assert!(!rebuilt.changed);
    assert_eq!(
        rebuilt.authoritative_sequence,
        committed.resulting_state.authoritative_sequence
    );
}

#[test]
fn put_before_create_is_a_deterministic_validation_finding_without_commit() {
    let fixture = baseline_fixture("put-before-create");
    let repository = &fixture.repository;
    let object_id = test_id(0x400).parse().unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let intent_command = IssueContentResourceIntentCommand {
        intent_id: test_id(0x410).parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        targets: vec![
            LocalizedContentTarget {
                object_id: fixture.anchor_object_id,
                schema_id: schema_id.clone(),
                locale: "fr-FR".parse().unwrap(),
            },
            LocalizedContentTarget {
                object_id,
                schema_id: schema_id.clone(),
                locale: "fr-FR".parse().unwrap(),
            },
        ],
        creations: vec![LocalizedCreationSlot {
            object_id,
            schema_id,
            locales: vec!["fr-FR".parse().unwrap()],
        }],
        idempotency_key: test_id(0x411).parse().unwrap(),
        issued_at: "2026-08-26T01:00:00Z".parse().unwrap(),
    };
    let draft = build_draft(repository, intent_command, 0x410, 2);
    let source = source_content("causal-item", "Causal item");
    let added = repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![
                LocalizedEditAttempt::LocalePut(put_input(
                    fixture.anchor_object_id,
                    "fr-FR",
                    fixture.anchor_source.clone(),
                    &localized_content("anchor", "Ancre"),
                )),
                LocalizedEditAttempt::LocalePut(put_input(
                    object_id,
                    "fr-FR",
                    expected_created_source(object_id, &source),
                    &localized_content("causal-item", "Article causal"),
                )),
                LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &source)),
            ],
            assigned_edit_ids: vec![
                test_id(0x416).parse().unwrap(),
                test_id(0x417).parse().unwrap(),
                test_id(0x418).parse().unwrap(),
            ],
            idempotency_key: test_id(0x419).parse().unwrap(),
        })
        .unwrap();
    assert_eq!(added.total_edit_count, 3);
    let validation = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert!(!validation.valid);
    assert_eq!(validation.findings.len(), 1);
    let finding = &validation.findings[0];
    assert_eq!(
        finding.code,
        proof_application::LOCALIZED_SOURCE_CONFLICT_CODE
    );
    assert_eq!(finding.edit_id, test_id(0x417).parse().unwrap());
    assert_eq!(finding.object_id, object_id);
    assert_eq!(finding.locale.as_str(), "fr-FR");
    assert_eq!(finding.pointer, None);
    assert_eq!(finding.policy_digest, draft.context.policy_digest);
    let replayed = repository
        .validate_localized_changeset(draft.changeset_id)
        .unwrap();
    assert_eq!(replayed.findings, validation.findings);
    let connection = repository.open_database().unwrap();
    let edit_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM localized_edits WHERE changeset_id = ?1",
            [draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let add_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM localized_add_operations WHERE changeset_id = ?1",
            [draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM object_revisions WHERE object_id = ?1",
            [object_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((edit_count, add_count, object_count), (3, 1, 0));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained rejection matrix verifies precise failures and transaction atomicity"
)]
fn creation_add_failures_are_precise_and_atomic() {
    let fixture = baseline_fixture("double-slot");
    let repository = &fixture.repository;
    let object_id = test_id(0x500).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x510, object_id),
        0x510,
        1,
    );
    let source = source_content("double", "Double");
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                object_id, 1, &source,
            ))],
            assigned_edit_ids: vec![test_id(0x516).parse().unwrap()],
            idempotency_key: test_id(0x517).parse().unwrap(),
        })
        .unwrap();
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                    object_id, 1, &source,
                ))],
                assigned_edit_ids: vec![test_id(0x518).parse().unwrap()],
                idempotency_key: test_id(0x519).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::DuplicateActiveTarget
    );
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM localized_edits WHERE changeset_id = ?1",
                [draft.changeset_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );

    let fixture = baseline_fixture("unknown-schema-version");
    let repository = &fixture.repository;
    let object_id = test_id(0x520).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x530, object_id),
        0x530,
        1,
    );
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                    object_id,
                    3,
                    &source_content("unknown-version", "Unknown version"),
                ))],
                assigned_edit_ids: vec![test_id(0x536).parse().unwrap()],
                idempotency_key: test_id(0x537).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::SchemaNotFound
    );

    let fixture = baseline_fixture("edit-slot-mismatch");
    let repository = &fixture.repository;
    let object_id = test_id(0x540).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x550, object_id),
        0x550,
        1,
    );
    let mut mismatched = create_input(object_id, 1, &source_content("mismatch", "Mismatch"));
    mismatched.schema_id = SchemaId::new("another-schema").unwrap();
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(mismatched)],
                assigned_edit_ids: vec![test_id(0x556).parse().unwrap()],
                idempotency_key: test_id(0x557).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::IntentSlotMismatch
    );

    let fixture = baseline_fixture("locale-intent-mismatch");
    let repository = &fixture.repository;
    let object_id = test_id(0x560).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x570, object_id),
        0x570,
        1,
    );
    let source = source_content("locale-mismatch", "Locale mismatch");
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![
                    LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &source)),
                    LocalizedEditAttempt::LocalePut(put_input(
                        object_id,
                        "de-DE",
                        expected_created_source(object_id, &source),
                        &localized_content("locale-mismatch", "Gebietsschema stimmt nicht"),
                    )),
                ],
                assigned_edit_ids: vec![
                    test_id(0x576).parse().unwrap(),
                    test_id(0x577).parse().unwrap(),
                ],
                idempotency_key: test_id(0x578).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::IntentMismatch
    );
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM localized_edits WHERE changeset_id = ?1",
                [draft.changeset_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained race matrix verifies both add-time and commit-time rollback boundaries"
)]
fn committed_object_races_fail_at_add_and_commit_without_partial_writes() {
    let fixture = baseline_fixture("object-exists-add");
    let repository = &fixture.repository;
    let object_id = test_id(0x600).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x610, object_id),
        0x610,
        1,
    );
    let source = source_content("add-race", "Add race");
    commit_legacy_object(repository, 0x620, object_id, &source);
    assert_eq!(
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: draft.changeset_id,
                edits: vec![LocalizedEditAttempt::ObjectCreate(create_input(
                    object_id, 1, &source,
                ))],
                assigned_edit_ids: vec![test_id(0x626).parse().unwrap()],
                idempotency_key: test_id(0x627).parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::ObjectExists
    );
    assert_eq!(
        repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM localized_edits WHERE changeset_id = ?1",
                [draft.changeset_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );

    let fixture = baseline_fixture("object-exists-commit");
    let repository = &fixture.repository;
    let object_id = test_id(0x630).parse().unwrap();
    let draft = build_draft(
        repository,
        creation_intent_command(0x640, object_id),
        0x640,
        1,
    );
    let source = source_content("commit-race", "Commit race");
    repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: draft.changeset_id,
            edits: vec![
                LocalizedEditAttempt::ObjectCreate(create_input(object_id, 1, &source)),
                LocalizedEditAttempt::LocalePut(put_input(
                    object_id,
                    "fr-FR",
                    expected_created_source(object_id, &source),
                    &localized_content("commit-race", "Course de validation"),
                )),
            ],
            assigned_edit_ids: vec![
                test_id(0x646).parse().unwrap(),
                test_id(0x647).parse().unwrap(),
            ],
            idempotency_key: test_id(0x648).parse().unwrap(),
        })
        .unwrap();
    assert!(
        repository
            .validate_localized_changeset(draft.changeset_id)
            .unwrap()
            .valid
    );
    repository
        .submit_localized_changeset(draft.changeset_id, "2026-08-26T01:03:00Z".parse().unwrap())
        .unwrap();
    repository
        .approve_localized_changeset(
            draft.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-26T01:04:00Z".parse().unwrap(),
        )
        .unwrap();
    commit_legacy_object(repository, 0x650, object_id, &source);
    let sequence_before: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT authoritative_sequence FROM known_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        repository
            .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                changeset_id: draft.changeset_id,
                idempotency_key: test_id(0x656).parse().unwrap(),
                committed_at: "2026-08-26T03:00:00Z".parse().unwrap(),
            })
            .unwrap_err(),
        LocalizedContentError::ObjectExists
    );
    let connection = repository.open_database().unwrap();
    let sequence_after: i64 = connection
        .query_row(
            "SELECT authoritative_sequence FROM known_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let localized_commit_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM localized_commits WHERE changeset_id = ?1",
            [draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let rendition_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM object_locale_revisions WHERE changeset_id = ?1",
            [draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let object_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM object_revisions WHERE object_id = ?1",
            [object_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(sequence_after, sequence_before);
    assert_eq!(
        (localized_commit_count, rendition_count, object_count),
        (0, 0, 1)
    );
}
