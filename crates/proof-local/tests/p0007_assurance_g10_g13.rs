#![allow(
    clippy::too_many_lines,
    reason = "the included shared fixture currently contains one separately owned long test"
)]
include!("initialize.rs");

use proof_application::{CommittedLocalizedChangeSet, ProjectionRebuild};

const ASSURANCE_EDIT_ID: &str = "019c0000-0000-7000-8000-000000000250";
const ASSURANCE_ADD_KEY: &str = "019c0000-0000-7000-8000-000000000251";
const ASSURANCE_COMMIT_KEY: &str = "019c0000-0000-7000-8000-000000000252";
const ASSURANCE_EDITION_ID: &str = "019c0000-0000-7000-8000-000000000253";
const ASSURANCE_EDITION_KEY: &str = "019c0000-0000-7000-8000-000000000254";
const ASSURANCE_RELEASE_ID: &str = "019c0000-0000-7000-8000-000000000255";
const ASSURANCE_PROOF_ID: &str = "019c0000-0000-7000-8000-000000000256";
const ASSURANCE_RELEASE_KEY: &str = "019c0000-0000-7000-8000-000000000257";

type AssuranceSnapshot = Vec<Vec<Vec<String>>>;

struct AssuranceCommittedFixture {
    draft: LocalizedDraftFixture,
    canonical_content: String,
    committed: CommittedLocalizedChangeSet,
}

fn assurance_approved_fixture() -> (LocalizedDraftFixture, String) {
    let fixture = localized_draft_fixture();
    let canonical_content = canonicalize(&serde_json::json!({
        "legal": "Des conditions standard s’appliquent",
        "slug": "summer-campaign",
        "title": "Campagne d’été",
    }))
    .unwrap()
    .as_str()
    .to_owned();
    fixture
        .repository
        .add_localized_edits(AddLocalizedEditsCommand {
            changeset_id: fixture.changeset_id,
            edits: vec![ObjectLocalePutInput {
                object_id: fixture.object_id,
                locale: fixture.locale.clone(),
                expected_source: fixture.expected_source.clone(),
                expected_target: None,
                canonical_content: canonical_content.clone(),
                supersedes_edit_id: None,
                repair_of_validation_result_digest: None,
            }],
            assigned_edit_ids: vec![ASSURANCE_EDIT_ID.parse().unwrap()],
            idempotency_key: ASSURANCE_ADD_KEY.parse().unwrap(),
        })
        .unwrap();
    assert!(
        fixture
            .repository
            .validate_localized_changeset(fixture.changeset_id)
            .unwrap()
            .valid
    );
    fixture
        .repository
        .submit_localized_changeset(
            fixture.changeset_id,
            "2026-08-17T16:10:00Z".parse().unwrap(),
        )
        .unwrap();
    fixture
        .repository
        .approve_localized_changeset(
            fixture.changeset_id,
            ApprovalName::new("editorial").unwrap(),
            "2026-08-17T16:11:00Z".parse().unwrap(),
        )
        .unwrap();
    (fixture, canonical_content)
}

fn assurance_commit_command(changeset_id: ChangeSetId) -> CommitLocalizedChangeSetCommand {
    CommitLocalizedChangeSetCommand {
        changeset_id,
        idempotency_key: ASSURANCE_COMMIT_KEY.parse().unwrap(),
        committed_at: "2026-08-17T16:12:00Z".parse().unwrap(),
    }
}

fn assurance_committed_fixture() -> AssuranceCommittedFixture {
    let (draft, canonical_content) = assurance_approved_fixture();
    let committed = draft
        .repository
        .commit_localized_changeset(assurance_commit_command(draft.changeset_id))
        .unwrap();
    AssuranceCommittedFixture {
        draft,
        canonical_content,
        committed,
    }
}

fn assurance_projection_snapshot(repository: &LocalWorkspace) -> AssuranceSnapshot {
    let connection = repository.open_database().unwrap();
    [
        "SELECT schema_id, schema_version, document_json, document_digest, changeset_id, edit_id,
                authoritative_sequence FROM schema_versions ORDER BY schema_id, schema_version",
        "SELECT object_id, revision, schema_id, schema_version, lifecycle_state, content_json,
                object_digest, changeset_id, edit_id, authoritative_sequence
         FROM object_revisions ORDER BY object_id, revision",
        "SELECT workspace_id, object_id, locale, revision, previous_revision_digest,
                source_object_revision, source_object_digest, schema_id, schema_version,
                content_json, changeset_id, edit_id, authoritative_sequence, manifest_json,
                rendition_digest
         FROM object_locale_revisions ORDER BY object_id, locale, revision",
        "SELECT api_version, authoritative_sequence, state_digest, manifest_json
         FROM known_state WHERE singleton = 1",
        "SELECT environment_id, release_id, release_sequence, projection_version
         FROM environment_current_releases ORDER BY environment_id",
    ]
    .iter()
    .map(|query| snapshot_rows(&connection, query))
    .collect()
}

fn assurance_authority_snapshot(repository: &LocalWorkspace) -> AssuranceSnapshot {
    let connection = repository.open_database().unwrap();
    [
        "SELECT changeset_id, ordinal, edit_id, object_id, locale, source_revision, source_digest,
                schema_id, schema_version, expected_target_revision, expected_target_digest,
                content_json, supersedes_edit_id, repair_validation_digest, edit_json, edit_digest
         FROM localized_edits ORDER BY changeset_id, ordinal",
        "SELECT changeset_id, workspace_id, principal_id, idempotency_key,
                sealed_changeset_digest, validation_results_digest, previous_state_api_version,
                previous_authoritative_sequence, previous_state_digest,
                resulting_authoritative_sequence, resulting_state_digest, resulting_state_json,
                committed_at, effect_digest
         FROM localized_commits ORDER BY resulting_authoritative_sequence",
        "SELECT release_id, release_sequence, workspace_id, environment_id, edition_id,
                release_kind, previous_release_id, release_digest, released_at
         FROM releases ORDER BY release_sequence",
        "SELECT release_id, base_release_id, changeset_id, resource_intent_id, exact_delta_json,
                exact_delta_digest, metadata_json, metadata_digest
         FROM localized_release_metadata ORDER BY release_id",
    ]
    .iter()
    .map(|query| snapshot_rows(&connection, query))
    .collect()
}

fn assurance_commit_snapshot(repository: &LocalWorkspace) -> AssuranceSnapshot {
    let connection = repository.open_database().unwrap();
    [
        "SELECT changeset_id, lifecycle_status, proposal_digest, effective_leaf_digest,
                sealed_changeset_digest, effect_digest
         FROM localized_changesets ORDER BY changeset_id",
        "SELECT object_id, locale, revision, content_json, changeset_id, edit_id,
                authoritative_sequence, manifest_json, rendition_digest
         FROM object_locale_revisions ORDER BY object_id, locale, revision",
        "SELECT api_version, authoritative_sequence, state_digest, manifest_json, changeset_id
         FROM known_state_artifacts ORDER BY authoritative_sequence, state_digest",
        "SELECT changeset_id, idempotency_key, resulting_authoritative_sequence,
                resulting_state_digest, resulting_state_json, committed_at, effect_digest
         FROM localized_commits ORDER BY resulting_authoritative_sequence",
        "SELECT api_version, authoritative_sequence, state_digest, manifest_json
         FROM known_state WHERE singleton = 1",
    ]
    .iter()
    .map(|query| snapshot_rows(&connection, query))
    .collect()
}

#[cfg(unix)]
fn assurance_release_snapshot(repository: &LocalWorkspace) -> AssuranceSnapshot {
    let connection = repository.open_database().unwrap();
    [
        "SELECT release_id, release_sequence, environment_id, edition_id, release_kind,
                previous_release_id, release_digest, released_at
         FROM releases ORDER BY release_sequence",
        "SELECT proof_id, release_id, key_id, statement_json, envelope_json, proof_digest
         FROM release_proofs ORDER BY proof_id",
        "SELECT release_id, base_release_id, changeset_id, resource_intent_id,
                exact_delta_json, exact_delta_digest, metadata_json, metadata_digest
         FROM localized_release_metadata ORDER BY release_id",
        "SELECT operation_kind, idempotency_key, request_digest, release_id, proof_id
         FROM localized_release_operations ORDER BY operation_kind, idempotency_key",
        "SELECT environment_id, release_id, release_sequence, projection_version
         FROM environment_current_releases ORDER BY environment_id",
        "SELECT proof_id, release_id, created_at FROM release_proof_export_outbox
         ORDER BY proof_id",
    ]
    .iter()
    .map(|query| snapshot_rows(&connection, query))
    .collect()
}

fn assurance_snapshot_hash(snapshot: &AssuranceSnapshot) -> String {
    let canonical = canonicalize(&serde_json::to_value(snapshot).unwrap()).unwrap();
    digest(ArtifactKind::OperationEffectV1, &canonical).to_string()
}

fn assurance_rebuild_hash(result: ProjectionRebuild) -> String {
    let canonical = canonicalize(&serde_json::json!({
        "authoritative_sequence": result.authoritative_sequence,
        "changed": result.changed,
        "dry_run": result.dry_run,
        "environment_pointer_count": result.environment_pointer_count,
        "object_count": result.object_count,
        "schema_count": result.schema_count,
        "state_digest": result.state_digest.to_string(),
    }))
    .unwrap();
    digest(ArtifactKind::OperationEffectV1, &canonical).to_string()
}

fn assurance_repeated_dry_run(
    repository: &LocalWorkspace,
    family: &str,
) -> (ProjectionRebuild, AssuranceSnapshot) {
    let before = assurance_projection_snapshot(repository);
    let first =
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    let after_first = assurance_projection_snapshot(repository);
    let second =
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true }).unwrap();
    let after_second = assurance_projection_snapshot(repository);
    assert!(first.dry_run && first.changed);
    assert_eq!(second, first);
    assert_eq!(after_first, before, "{family} dry-run wrote data");
    assert_eq!(after_second, before, "{family} repeated dry-run wrote data");
    assert_eq!(
        assurance_rebuild_hash(first),
        assurance_rebuild_hash(second)
    );
    println!(
        "G10 family={family} projection_snapshot={} dry_run={}",
        assurance_snapshot_hash(&before),
        assurance_rebuild_hash(first)
    );
    (first, before)
}

#[test]
fn p0007_assurance_g10_locale_projection_reconstructs_repairs_and_converges() {
    let fixture = assurance_committed_fixture();
    let repository = &fixture.draft.repository;
    let rendition = fixture.committed.renditions.first().unwrap();
    let content = proof_canonical::parse_strict(fixture.canonical_content.as_bytes()).unwrap();
    let (independent_manifest, independent_digest) =
        proof_canonical::object_locale_revision(&proof_canonical::ObjectLocaleRevisionInput {
            workspace_id: WORKSPACE_ID.parse().unwrap(),
            object_id: fixture.draft.object_id,
            locale: &fixture.draft.locale,
            revision: LocaleRevision::new(1).unwrap(),
            previous_revision_digest: None,
            source_object_revision: fixture.draft.expected_source.revision,
            source_object_digest: fixture.draft.expected_source.digest,
            schema_id: &fixture.draft.expected_source.schema_id,
            schema_version: fixture.draft.expected_source.schema_version,
            content: &content,
            changeset_id: fixture.draft.changeset_id,
            edit_id: ASSURANCE_EDIT_ID.parse().unwrap(),
            authoritative_sequence: fixture
                .committed
                .previous_state
                .authoritative_sequence
                .checked_add(1)
                .unwrap(),
        })
        .unwrap();
    assert_eq!(rendition.manifest_json, independent_manifest.as_str());
    assert_eq!(rendition.rendition_digest, independent_digest);
    let expected = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT workspace_id, object_id, locale, revision, previous_revision_digest,
                source_object_revision, source_object_digest, schema_id, schema_version,
                content_json, changeset_id, edit_id, authoritative_sequence, manifest_json,
                rendition_digest FROM object_locale_revisions",
    );
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE object_locale_revisions SET content_json = '{}' WHERE edit_id = ?1",
            [ASSURANCE_EDIT_ID],
        )
        .unwrap();
    let authority_before = assurance_authority_snapshot(repository);
    assurance_repeated_dry_run(repository, "object_locale_revisions");
    let repaired =
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: false }).unwrap();
    assert!(repaired.changed);
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT workspace_id, object_id, locale, revision, previous_revision_digest,
                    source_object_revision, source_object_digest, schema_id, schema_version,
                    content_json, changeset_id, edit_id, authoritative_sequence, manifest_json,
                    rendition_digest FROM object_locale_revisions",
        ),
        expected
    );
    assert_eq!(assurance_authority_snapshot(repository), authority_before);
    assert!(
        !rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
}

#[test]
fn p0007_assurance_g10_known_state_projection_reconstructs_repairs_and_converges() {
    let fixture = assurance_committed_fixture();
    let repository = &fixture.draft.repository;
    let state_manifest: String = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT resulting_state_json FROM localized_commits WHERE changeset_id = ?1",
            [fixture.draft.changeset_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let independently_parsed = proof_canonical::parse_strict(state_manifest.as_bytes()).unwrap();
    let independently_canonical = canonicalize(&independently_parsed).unwrap();
    assert_eq!(
        digest(ArtifactKind::KnownStateV2, &independently_canonical),
        fixture.committed.resulting_state.digest
    );
    let expected = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT api_version, authoritative_sequence, state_digest, manifest_json
         FROM known_state WHERE singleton = 1",
    );
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE known_state SET state_digest = ?1, manifest_json = '{}' WHERE singleton = 1",
            [format!("blake3:{}", "f".repeat(64))],
        )
        .unwrap();
    let authority_before = assurance_authority_snapshot(repository);
    assurance_repeated_dry_run(repository, "known_state");
    assert!(
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: false })
            .unwrap()
            .changed
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT api_version, authoritative_sequence, state_digest, manifest_json
             FROM known_state WHERE singleton = 1",
        ),
        expected
    );
    assert_eq!(assurance_authority_snapshot(repository), authority_before);
    assert!(
        !rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
}

#[test]
fn p0007_assurance_g10_environment_pointer_reconstructs_repairs_and_converges() {
    let fixture = assurance_committed_fixture();
    let repository = &fixture.draft.repository;
    let edition = repository
        .create_localized_edition(CreateLocalizedEditionCommand {
            edition_id: ASSURANCE_EDITION_ID.parse().unwrap(),
            changeset_id: fixture.draft.changeset_id,
            resulting_state_digest: fixture.committed.resulting_state.digest,
            idempotency_key: ASSURANCE_EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-17T16:13:00Z".parse().unwrap(),
        })
        .unwrap();
    let release = repository
        .promote_localized_release(PromoteLocalizedReleaseCommand {
            release_id: ASSURANCE_RELEASE_ID.parse().unwrap(),
            proof_id: ASSURANCE_PROOF_ID.parse().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id: edition.edition_id,
            expected_base_release_id: FIRST_RELEASE_ID.parse().unwrap(),
            idempotency_key: ASSURANCE_RELEASE_KEY.parse().unwrap(),
            released_at: "2026-08-17T16:14:00Z".parse().unwrap(),
        })
        .unwrap();
    let authoritative_release: (String, i64) = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT release_id, release_sequence FROM releases WHERE release_id = ?1",
            [release.release_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(authoritative_release.0, release.release_id.to_string());
    assert_eq!(
        authoritative_release.1,
        i64::try_from(release.release_sequence).unwrap()
    );
    let expected = snapshot_rows(
        &repository.open_database().unwrap(),
        "SELECT environment_id, release_id, release_sequence, projection_version
         FROM environment_current_releases ORDER BY environment_id",
    );
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE environment_current_releases
             SET release_id = ?1,
                 release_sequence = (SELECT release_sequence FROM releases WHERE release_id = ?1)
             WHERE environment_id = ?2",
            (FIRST_RELEASE_ID, ENVIRONMENT_ID),
        )
        .unwrap();
    let authority_before = assurance_authority_snapshot(repository);
    assurance_repeated_dry_run(repository, "environment_current_releases");
    assert!(
        rebuild_projections(repository, RebuildProjectionsCommand { dry_run: false })
            .unwrap()
            .changed
    );
    assert_eq!(
        snapshot_rows(
            &repository.open_database().unwrap(),
            "SELECT environment_id, release_id, release_sequence, projection_version
             FROM environment_current_releases ORDER BY environment_id",
        ),
        expected
    );
    assert_eq!(assurance_authority_snapshot(repository), authority_before);
    assert!(
        !rebuild_projections(repository, RebuildProjectionsCommand { dry_run: true })
            .unwrap()
            .changed
    );
}

#[test]
fn p0007_assurance_g10_authoritative_tamper_fails_closed_in_both_modes() {
    let fixture = assurance_committed_fixture();
    let repository = &fixture.draft.repository;
    repository
        .open_database()
        .unwrap()
        .execute(
            "UPDATE localized_commits SET committed_at = '2026-08-17T16:12:01Z'
             WHERE changeset_id = ?1",
            [fixture.draft.changeset_id.to_string()],
        )
        .unwrap();
    let authority_before = assurance_authority_snapshot(repository);
    let projections_before = assurance_projection_snapshot(repository);
    for dry_run in [true, false] {
        let result = rebuild_projections(repository, RebuildProjectionsCommand { dry_run });
        assert!(
            matches!(result, Err(RebuildProjectionsError::Integrity(_))),
            "authoritative tamper with dry_run={dry_run} returned {result:?}"
        );
        assert_eq!(assurance_authority_snapshot(repository), authority_before);
        assert_eq!(
            assurance_projection_snapshot(repository),
            projections_before
        );
    }
    println!(
        "G10 authoritative_tamper authority={} projections={}",
        assurance_snapshot_hash(&authority_before),
        assurance_snapshot_hash(&projections_before)
    );
}

#[test]
fn p0007_assurance_g13_pre_write_storage_failure_rolls_back_and_retries_once() {
    let (fixture, _) = assurance_approved_fixture();
    let repository = &fixture.repository;
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER assurance_pre_write_failure
             BEFORE INSERT ON object_locale_revisions
             BEGIN SELECT RAISE(ABORT, 'assurance pre-write failure'); END;",
        )
        .unwrap();
    let before = assurance_commit_snapshot(repository);
    let command = assurance_commit_command(fixture.changeset_id);
    let failed = repository.commit_localized_changeset(command);
    assert!(matches!(failed, Err(LocalizedContentError::Storage(_))));
    assert_eq!(assurance_commit_snapshot(repository), before);
    repository
        .open_database()
        .unwrap()
        .execute_batch("DROP TRIGGER assurance_pre_write_failure")
        .unwrap();
    let committed = repository.commit_localized_changeset(command).unwrap();
    assert_eq!(committed.changeset_id, fixture.changeset_id);
    let committed_count: i64 = repository
        .open_database()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM localized_commits", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(committed_count, 1);
    println!(
        "G13 pre_write before={} converged={}",
        assurance_snapshot_hash(&before),
        assurance_snapshot_hash(&assurance_commit_snapshot(repository))
    );
}

#[test]
fn p0007_assurance_g13_mid_transaction_storage_failure_rolls_back_and_retries_once() {
    let (fixture, _) = assurance_approved_fixture();
    let repository = &fixture.repository;
    repository
        .open_database()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER assurance_mid_transaction_failure
             BEFORE INSERT ON localized_commits
             BEGIN SELECT RAISE(ABORT, 'assurance mid-transaction failure'); END;",
        )
        .unwrap();
    let before = assurance_commit_snapshot(repository);
    let command = assurance_commit_command(fixture.changeset_id);
    let failed = repository.commit_localized_changeset(command);
    assert!(matches!(failed, Err(LocalizedContentError::Storage(_))));
    assert_eq!(assurance_commit_snapshot(repository), before);
    repository
        .open_database()
        .unwrap()
        .execute_batch("DROP TRIGGER assurance_mid_transaction_failure")
        .unwrap();
    let committed = repository.commit_localized_changeset(command).unwrap();
    assert_eq!(committed.changeset_id, fixture.changeset_id);
    assert_eq!(committed.renditions.len(), 1);
    println!(
        "G13 mid_transaction before={} converged={}",
        assurance_snapshot_hash(&before),
        assurance_snapshot_hash(&assurance_commit_snapshot(repository))
    );
}

#[cfg(unix)]
#[test]
fn p0007_assurance_g13_post_commit_export_and_replay_failure_converges_once() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = assurance_committed_fixture();
    let repository = &fixture.draft.repository;
    let edition = repository
        .create_localized_edition(CreateLocalizedEditionCommand {
            edition_id: ASSURANCE_EDITION_ID.parse().unwrap(),
            changeset_id: fixture.draft.changeset_id,
            resulting_state_digest: fixture.committed.resulting_state.digest,
            idempotency_key: ASSURANCE_EDITION_KEY.parse().unwrap(),
            created_at: "2026-08-17T16:13:00Z".parse().unwrap(),
        })
        .unwrap();
    let proof_directory = repository
        .runtime_path()
        .join("artifacts")
        .join("release-proofs");
    assert!(proof_directory.is_dir());
    fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o500)).unwrap();
    let command = PromoteLocalizedReleaseCommand {
        release_id: ASSURANCE_RELEASE_ID.parse().unwrap(),
        proof_id: ASSURANCE_PROOF_ID.parse().unwrap(),
        environment_id: ENVIRONMENT_ID.parse().unwrap(),
        edition_id: edition.edition_id,
        expected_base_release_id: FIRST_RELEASE_ID.parse().unwrap(),
        idempotency_key: ASSURANCE_RELEASE_KEY.parse().unwrap(),
        released_at: "2026-08-17T16:14:00Z".parse().unwrap(),
    };
    let release = repository
        .promote_localized_release(command.clone())
        .unwrap();
    let proof_path = proof_directory.join(format!("{}.dsse.json", release.proof_id));
    assert!(!proof_path.exists());
    let durable = assurance_release_snapshot(repository);
    assert_eq!(
        repository
            .promote_localized_release(command.clone())
            .unwrap(),
        release
    );
    assert_eq!(assurance_release_snapshot(repository), durable);
    assert!(!proof_path.exists());

    fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        repository
            .promote_localized_release(command.clone())
            .unwrap(),
        release
    );
    assert_eq!(
        fs::read_to_string(&proof_path).unwrap(),
        release.proof_envelope_json
    );
    let pending: i64 = repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM release_proof_export_outbox",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
    let converged = assurance_release_snapshot(repository);
    assert_eq!(
        repository.promote_localized_release(command).unwrap(),
        release
    );
    assert_eq!(assurance_release_snapshot(repository), converged);
    println!(
        "G13 post_commit_pending={} converged={}",
        assurance_snapshot_hash(&durable),
        assurance_snapshot_hash(&converged)
    );
}
