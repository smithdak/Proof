use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use proof_application::{
    AddChangeSetEditsCommand, ApprovalName, ApproveChangeSetCommand, ArtifactKind,
    BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetIntent, CommitChangeSetCommand,
    ContentDigest, ContentResourceIntent, CreateAgentPrincipalCommand, CreateChangeSetCommand,
    CreateEditionCommand, CreateEnvironmentCommand, IdempotencyKey, InitializeWorkspaceCommand,
    IssueContentResourceIntentCommand, LocaleId, LocalizedContentRepository,
    LocalizedContentTarget, LocalizedContextLimits, LocalizedContextPack, LocalizedPolicyRule,
    ObjectCreateEdit, ObjectId, PresentationId, PrincipalId, PromoteReleaseCommand, ProofId,
    ReleaseId, SchemaCreateEdit, SchemaId, SchemaVersion, SubmitChangeSetCommand, Timestamp,
    VerifyLocalizedReleaseCommand, WorkspaceId, add_changeset_edits, approve_changeset,
    authority::{
        AgentPrincipalType, ApplicationIdempotency, AuthenticatedAuthorityExecutor,
        AuthenticatedCommandApiVersion, AuthenticatedCommandEnvelopeJson,
        AuthenticatedCommandKeyUsage, AuthenticatedCommandV1, AuthenticatedExecutionV1,
        AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationResultV1, AuthorityAction, AuthorityAdministrator, AuthorityAudience,
        AuthorityError, AuthorityOperation, AuthorityPrincipalType, AuthorityRepository,
        AuthoritySequence, AuthorizationDecisionOutcome, BindingEnrollmentChallengeV1,
        CommandInputApiVersion, CommandInputV1, DelegationActionsV2, DelegationApiVersion,
        DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
        DelegationObjectIdsV2, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
        DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
        EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1,
        LocalizedOperationSuccessV1, MaxContextBytes, MaxEditsPerChangeSet, MaxObjects,
        PrincipalBindingApiVersion, PrincipalBindingV1, PrincipalStatusApiVersion,
        PrincipalStatusV1, SubdelegationDisabled, authority_operation_entry,
        localized_operation_output_schema_uri,
    },
    capability_for_operation, commit_changeset, create_agent_principal, create_changeset,
    create_edition, create_environment, initialize_workspace, promote_release, submit_changeset,
    validate_changeset,
};
use proof_attestation::authority::{AuthorityPayloadProfile, sign_authority_payload};
use proof_attestation::{Ed25519SigningProvider, ProofSigningProvider};
use proof_canonical::{canonicalize, digest, object_revision_digest};
use proof_local::{DeterministicLocalAuthorityAdapter, LocalWorkspace};
use rusqlite::{Connection, types::ValueRef};
use serde_json::{Map, Value, json};

const WORKSPACE_ID: &str = "019d2000-0000-7000-8000-000000000001";
const HUMAN_PRINCIPAL_ID: &str = "019d2000-0000-7000-8000-000000000002";
const BASE_TIME: &str = "2026-08-21T12:00:00Z";
const DETERMINISTIC_UID: u64 = 2_005;
const DETERMINISTIC_SUBJECT_BLIND: [u8; 32] = [0x75; 32];
const ENVIRONMENT_ID: &str = "preview";
const OBJECT_ID: &str = "019d2000-0000-7000-8000-000000000020";
const SCHEMA_ID: &str = "campaign";
const LOCALE: &str = "fr-FR";

static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the retained acceptance target keeps the complete 11-operation lifecycle and both approval falsifiers visible"
)]
fn p0005_agent_executes_the_complete_human_owned_localized_lifecycle() {
    let mut fixture = LifecycleFixture::new();
    fixture.assert_agent_approval_absent();

    let context_input = object(&json!({
        "api_version": "proof.dev/operation/context.build/v2",
        "context_pack_id": fixture.context.context_pack_id.to_string(),
        "created_at": fixture.context.created_at.to_string(),
        "expires_at": fixture.context.expires_at.to_string(),
        "idempotency_key": lifecycle_id(0x43),
        "limits": {
            "max_bytes": fixture.context.limits.max_bytes,
            "max_edits": fixture.context.limits.max_edits,
            "max_objects": fixture.context.limits.max_objects,
            "max_validation_attempts": fixture.context.limits.max_validation_attempts
        },
        "policy_rules": [{
            "disallowed_values": ["Forbidden terms"],
            "locale": LOCALE,
            "pointer": "/legal"
        }],
        "resource_intent_digest": fixture.intent.intent_digest.to_string(),
        "resource_intent_id": fixture.intent.intent_id.to_string()
    }));
    let context_execution = fixture.execute_replayed(
        AuthorityOperation::ContextBuildV2,
        context_input,
        Some(key(0x43)),
        false,
    );
    let LocalizedOperationSuccessV1::ContextBuilt(replayed_context) =
        localized_success(&context_execution)
    else {
        panic!("context.build/v2 returned the wrong typed success")
    };
    assert_eq!(replayed_context, &fixture.context);
    assert_eq!(replayed_context.principal_id, fixture.human_principal_id);
    assert_eq!(fixture.count("localized_context_packs"), 1);
    assert_eq!(fixture.count("localized_context_build_operations"), 1);

    let changeset_id = lifecycle_id(0x50)
        .parse::<proof_application::ChangeSetId>()
        .unwrap();
    let create_input = object(&json!({
        "api_version": "proof.dev/operation/changeset.create/v2",
        "changeset_id": changeset_id.to_string(),
        "context_pack_digest": fixture.context.context_pack_digest.to_string(),
        "context_pack_id": fixture.context.context_pack_id.to_string(),
        "created_at": fixture.time(40).to_string(),
        "idempotency_key": lifecycle_id(0x51),
        "intent": "Create and repair one French rendition",
        "resource_intent_digest": fixture.intent.intent_digest.to_string(),
        "resource_intent_id": fixture.intent.intent_id.to_string()
    }));
    let created = fixture.execute_replayed(
        AuthorityOperation::ChangesetCreateV2,
        create_input,
        Some(key(0x51)),
        true,
    );
    let LocalizedOperationSuccessV1::ChangeSetCreated(created_changeset) =
        localized_success(&created)
    else {
        panic!("changeset.create/v2 returned the wrong typed success")
    };
    assert_eq!(created_changeset.principal_id, fixture.human_principal_id);
    assert!(created_changeset.edits.is_empty());

    let invalid_add_input = fixture.add_input(changeset_id, 0x52, "Forbidden terms", None, None);
    let invalid_add = fixture.execute_replayed(
        AuthorityOperation::ChangesetAddV2,
        invalid_add_input,
        Some(key(0x52)),
        true,
    );
    let LocalizedOperationSuccessV1::EditsAdded(invalid_added) = localized_success(&invalid_add)
    else {
        panic!("changeset.add/v2 returned the wrong typed success")
    };
    let invalid_edit_id = invalid_added.edit_ids[0];

    let selector = |api_version: &str| {
        object(&json!({
            "api_version": api_version,
            "changeset_id": changeset_id.to_string()
        }))
    };
    let read = fixture.execute_once(
        AuthorityOperation::ChangesetGetV2,
        selector("proof.dev/operation/changeset.get/v2"),
        None,
    );
    let LocalizedOperationSuccessV1::ChangeSetRead(read_changeset) = localized_success(&read)
    else {
        panic!("changeset.get/v2 returned the wrong typed success")
    };
    assert_eq!(
        read_changeset.changeset.principal_id,
        fixture.human_principal_id
    );
    assert_eq!(read_changeset.changeset.edits.len(), 1);
    fixture.assert_evidence_only(&read);

    let diff = fixture.execute_once(
        AuthorityOperation::ChangesetDiffV2,
        selector("proof.dev/operation/changeset.diff/v2"),
        None,
    );
    let LocalizedOperationSuccessV1::ChangeSetDiffed(diff_result) = localized_success(&diff) else {
        panic!("changeset.diff/v2 returned the wrong typed success")
    };
    assert_eq!(diff_result.effective_edits[0].edit_id, invalid_edit_id);
    fixture.assert_evidence_only(&diff);

    let invalid_validation = fixture.execute_replayed(
        AuthorityOperation::ChangesetValidateV2,
        selector("proof.dev/operation/changeset.validate/v2"),
        None,
        true,
    );
    let LocalizedOperationSuccessV1::ChangeSetValidated(invalid_validation_result) =
        localized_success(&invalid_validation)
    else {
        panic!("changeset.validate/v2 returned the wrong typed success")
    };
    assert!(!invalid_validation_result.valid);
    assert!(
        invalid_validation_result
            .findings
            .iter()
            .any(|finding| finding.edit_id == invalid_edit_id)
    );
    let invalid_validation_digest = invalid_validation_result.validation_results_digest;

    let repair_add_input = fixture.add_input(
        changeset_id,
        0x53,
        "Les conditions standard s’appliquent",
        Some(invalid_edit_id),
        Some(invalid_validation_digest),
    );
    let repair_add = fixture.execute_replayed(
        AuthorityOperation::ChangesetAddV2,
        repair_add_input,
        Some(key(0x53)),
        true,
    );
    let LocalizedOperationSuccessV1::EditsAdded(repair_added) = localized_success(&repair_add)
    else {
        panic!("repair changeset.add/v2 returned the wrong typed success")
    };
    assert_ne!(repair_added.edit_ids[0], invalid_edit_id);
    assert_eq!(repair_added.total_edit_count, 2);

    let ready_validation = fixture.execute_replayed(
        AuthorityOperation::ChangesetValidateV2,
        selector("proof.dev/operation/changeset.validate/v2"),
        None,
        true,
    );
    let LocalizedOperationSuccessV1::ChangeSetValidated(ready_validation_result) =
        localized_success(&ready_validation)
    else {
        panic!("ready changeset.validate/v2 returned the wrong typed success")
    };
    assert!(ready_validation_result.valid);
    assert_eq!(
        ready_validation_result.previous_validation_result_digest,
        Some(invalid_validation_digest)
    );

    let submit_input = object(&json!({
        "api_version": "proof.dev/operation/changeset.submit/v2",
        "changeset_id": changeset_id.to_string(),
        "submitted_at": fixture.time(60).to_string()
    }));
    let submitted = fixture.execute_replayed(
        AuthorityOperation::ChangesetSubmitV2,
        submit_input.clone(),
        None,
        true,
    );
    assert!(matches!(
        localized_success(&submitted),
        LocalizedOperationSuccessV1::ChangeSetSubmitted(_)
    ));

    fixture.assert_agent_approval_absent();
    let authority_before_approval = fixture.authority_state();
    let approved = fixture
        .repository
        .approve_localized_changeset(
            changeset_id,
            ApprovalName::new("editorial").unwrap(),
            fixture.time(70),
        )
        .unwrap();
    assert_eq!(fixture.authority_state(), authority_before_approval);
    assert_eq!(
        fixture.approval_principal(changeset_id),
        fixture.human_principal_id
    );

    let original_submission_evidence =
        fixture.consequence_row(submitted.actor_context.presentation_id);
    let application_after_approval = fixture.application_snapshot();
    let ledger_after_approval = fixture.count("authenticated_application_idempotency_v1");
    let post_approval_submit =
        fixture.execute_once(AuthorityOperation::ChangesetSubmitV2, submit_input, None);
    let post_approval_submission_evidence =
        fixture.consequence_row(post_approval_submit.actor_context.presentation_id);
    assert_eq!(post_approval_submit.result, submitted.result);
    assert_eq!(fixture.application_snapshot(), application_after_approval);
    assert_eq!(
        fixture.count("authenticated_application_idempotency_v1"),
        ledger_after_approval
    );
    assert_eq!(
        post_approval_submission_evidence.result_digest,
        original_submission_evidence.result_digest
    );
    assert_eq!(
        post_approval_submission_evidence.application_effect_digest,
        original_submission_evidence.application_effect_digest
    );
    assert_ne!(
        post_approval_submission_evidence.application_consequence_digest,
        original_submission_evidence.application_consequence_digest
    );

    let commit_input = object(&json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": changeset_id.to_string(),
        "committed_at": fixture.time(80).to_string(),
        "idempotency_key": lifecycle_id(0x54)
    }));
    let before_forged_commit = fixture.authority_state();
    fixture.rewrite_approval_principal(
        changeset_id,
        fixture.agent.principal_id,
        approved.sealed_changeset_digest,
        approved.validation_results_digest,
        approved.approved_at,
    );
    let error = fixture.execute_integrity_error_with_unverified_head(
        AuthorityOperation::ChangesetCommitV2,
        commit_input.clone(),
        Some(key(0x54)),
    );
    assert!(matches!(error, AuthorityError::AuthorityIntegrity(_)));
    fixture.rewrite_approval_principal(
        changeset_id,
        fixture.human_principal_id,
        approved.sealed_changeset_digest,
        approved.validation_results_digest,
        approved.approved_at,
    );
    assert_eq!(fixture.authority_state(), before_forged_commit);

    let committed = fixture.execute_replayed(
        AuthorityOperation::ChangesetCommitV2,
        commit_input,
        Some(key(0x54)),
        true,
    );
    let LocalizedOperationSuccessV1::ChangeSetCommitted(committed_changeset) =
        localized_success(&committed)
    else {
        panic!("changeset.commit/v2 returned the wrong typed success")
    };
    let resulting_state_digest = committed_changeset.resulting_state.digest;

    fixture.rewrite_approval_principal(
        changeset_id,
        fixture.agent.principal_id,
        approved.sealed_changeset_digest,
        approved.validation_results_digest,
        approved.approved_at,
    );
    assert!(matches!(
        fixture.repository.authority_head(fixture.workspace_id),
        Err(AuthorityError::AuthorityIntegrity(_))
    ));
    fixture.rewrite_approval_principal(
        changeset_id,
        fixture.human_principal_id,
        approved.sealed_changeset_digest,
        approved.validation_results_digest,
        approved.approved_at,
    );
    fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();

    let edition_id = lifecycle_id(0x55)
        .parse::<proof_application::EditionId>()
        .unwrap();
    let edition_input = object(&json!({
        "api_version": "proof.dev/operation/edition.create/v2",
        "changeset_id": changeset_id.to_string(),
        "created_at": fixture.time(90).to_string(),
        "edition_id": edition_id.to_string(),
        "idempotency_key": lifecycle_id(0x56),
        "resulting_state_digest": resulting_state_digest.to_string()
    }));
    let edition_execution = fixture.execute_replayed(
        AuthorityOperation::EditionCreateV2,
        edition_input,
        Some(key(0x56)),
        true,
    );
    let LocalizedOperationSuccessV1::EditionCreated(edition) =
        localized_success(&edition_execution)
    else {
        panic!("edition.create/v2 returned the wrong typed success")
    };
    assert_eq!(edition.principal_id, fixture.human_principal_id);

    let release_id = lifecycle_id(0x57).parse::<ReleaseId>().unwrap();
    let proof_id = lifecycle_id(0x58).parse::<ProofId>().unwrap();
    let release_input = object(&json!({
        "api_version": "proof.dev/operation/release.create/v2",
        "edition_id": edition_id.to_string(),
        "environment_id": ENVIRONMENT_ID,
        "expected_base_release_id": lifecycle_id(0x2a),
        "idempotency_key": lifecycle_id(0x59),
        "proof_id": proof_id.to_string(),
        "release_id": release_id.to_string(),
        "released_at": fixture.time(100).to_string()
    }));
    let export_blocker = ReleaseProofExportBlocker::install(&fixture.repository, proof_id);
    let ledger_before_release = fixture.count("authenticated_application_idempotency_v1");
    let release_execution = fixture.execute_once(
        AuthorityOperation::ReleaseCreateV2,
        release_input.clone(),
        Some(key(0x59)),
    );
    let LocalizedOperationSuccessV1::ReleaseCreated(release) =
        localized_success(&release_execution)
    else {
        panic!("release.create/v2 returned the wrong typed success")
    };
    let release = release.clone();
    fixture.assert_release_policy_authority_is_distinct(&release, &release_execution);
    assert!(!export_blocker.is_materialized(&release));
    assert_eq!(fixture.count("release_proof_export_outbox"), 1);
    assert_eq!(
        fixture.count("authenticated_application_idempotency_v1"),
        ledger_before_release + 1
    );
    let release_rows_after_first = (
        fixture.count("releases"),
        fixture.count("release_proofs"),
        fixture.count("localized_release_operations"),
    );
    let first_release_evidence =
        fixture.consequence_row(release_execution.actor_context.presentation_id);

    export_blocker.recover();
    let release_replay = fixture.execute_once(
        AuthorityOperation::ReleaseCreateV2,
        release_input.clone(),
        Some(key(0x59)),
    );
    assert_eq!(release_replay.result, release_execution.result);
    assert_eq!(
        (
            fixture.count("releases"),
            fixture.count("release_proofs"),
            fixture.count("localized_release_operations"),
        ),
        release_rows_after_first
    );
    assert_eq!(
        fixture.count("authenticated_application_idempotency_v1"),
        ledger_before_release + 1
    );
    assert_eq!(fixture.count("release_proof_export_outbox"), 0);
    assert_eq!(
        fs::read_to_string(
            fixture
                .repository
                .runtime_path()
                .join("artifacts")
                .join("release-proofs")
                .join(format!("{}.dsse.json", release.proof_id)),
        )
        .unwrap(),
        release.proof_envelope_json
    );
    let replay_release_evidence =
        fixture.consequence_row(release_replay.actor_context.presentation_id);
    assert_eq!(
        replay_release_evidence.result_digest,
        first_release_evidence.result_digest
    );
    assert_eq!(
        replay_release_evidence.application_effect_digest,
        first_release_evidence.application_effect_digest
    );

    let query_input = object(&json!({
        "api_version": "proof.dev/operation/object.query_released/v2",
        "environment_id": ENVIRONMENT_ID,
        "evaluated_at": fixture.time(110).to_string(),
        "targets": [{ "locale": LOCALE, "object_id": OBJECT_ID }]
    }));
    let query_execution =
        fixture.execute_once(AuthorityOperation::ObjectQueryReleasedV2, query_input, None);
    let LocalizedOperationSuccessV1::ReleasedRenditionsQueried(query) =
        localized_success(&query_execution)
    else {
        panic!("object.query_released/v2 returned the wrong typed success")
    };
    assert_eq!(query.release_id, release_id);
    assert_eq!(query.renditions.len(), 1);
    assert_eq!(
        serde_json::from_str::<Value>(&query.renditions[0].canonical_content).unwrap(),
        json!({
            "legal": "Les conditions standard s’appliquent",
            "slug": "summer-campaign",
            "title": "Campagne d’été"
        })
    );
    fixture.assert_evidence_only(&query_execution);

    let verification = fixture
        .repository
        .verify_localized_release(VerifyLocalizedReleaseCommand {
            release_id,
            verified_at: fixture.time(200),
        })
        .unwrap();
    assert!(verification.valid, "{:?}", verification.findings);
    assert!(verification.findings.is_empty());
    assert_eq!(verification.proof_id, proof_id);

    fixture.assert_final_evidence_and_principals(changeset_id);

    let head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    fixture
        .repository
        .set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            workspace_id: fixture.workspace_id,
            principal_id: fixture.agent.principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled: false,
            recorded_by_principal_id: fixture.human_principal_id,
            recorded_at: fixture.time(fixture.next_evaluation_seconds - 1),
        })
        .unwrap();
    let authority_before_disabled_replay = fixture.authority_state();
    let application_before_disabled_replay = fixture.application_snapshot();
    let ledger_before_disabled_replay = fixture.count("authenticated_application_idempotency_v1");
    let presentation = fixture.next_presentation;
    let (invocation, evaluated_at) = fixture.next_invocation(
        AuthorityOperation::ReleaseCreateV2,
        release_input,
        Some(key(0x59)),
    );
    assert_eq!(
        fixture
            .repository
            .execute_authenticated(invocation, evaluated_at),
        Err(AuthorityError::PrincipalDisabled)
    );
    let authority_after_disabled_replay = fixture.authority_state();
    assert_eq!(
        authority_after_disabled_replay.head_sequence,
        authority_before_disabled_replay.head_sequence + 1
    );
    assert_eq!(
        authority_after_disabled_replay.localized_consequences,
        authority_before_disabled_replay.localized_consequences
    );
    assert_eq!(
        fixture.application_snapshot(),
        application_before_disabled_replay
    );
    assert_eq!(
        fixture.count("authenticated_application_idempotency_v1"),
        ledger_before_disabled_replay
    );
    let disabled_decision: (String, String) = fixture
        .repository
        .open_database()
        .unwrap()
        .query_row(
            "SELECT decision, reason_code FROM authorization_decisions_v2
             WHERE presentation_id = ?1",
            [lifecycle_id(presentation)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        disabled_decision,
        (
            "deny".to_owned(),
            "proof.authorization.principal_disabled".to_owned()
        )
    );

    let final_authority = fixture.authority_state();
    let final_head = fixture
        .repository
        .authority_head(fixture.workspace_id)
        .unwrap()
        .unwrap();
    let transcript = canonicalize(&json!({
        "api_version": "proof.dev/qualification/p0005-lifecycle/v1",
        "application": {
            "global_application_keys": fixture.count("authenticated_application_idempotency_v1"),
            "localized_changesets": fixture.count("localized_changesets"),
            "localized_edits": fixture.count("localized_edits"),
            "localized_releases": fixture.count("localized_release_operations"),
            "successful_presentations": fixture.successful_executions,
            "validation_attempts": fixture.count("localized_validations")
        },
        "artifacts": {
            "changeset_id": changeset_id.to_string(),
            "context_pack_digest": fixture.context.context_pack_digest.to_string(),
            "context_pack_id": fixture.context.context_pack_id.to_string(),
            "edition_digest": edition.edition_digest.to_string(),
            "edition_id": edition_id.to_string(),
            "proof_envelope_digest": release.proof_envelope_digest.to_string(),
            "proof_id": proof_id.to_string(),
            "release_digest": release.release_digest.to_string(),
            "release_id": release_id.to_string(),
            "resource_intent_digest": fixture.intent.intent_digest.to_string(),
            "resource_intent_id": fixture.intent.intent_id.to_string(),
            "resulting_state_digest": resulting_state_digest.to_string()
        },
        "authority": {
            "actor_evidence": final_authority.actor_evidence,
            "consumptions": final_authority.consumptions,
            "decisions": final_authority.decisions,
            "final_head_digest": final_head.record_digest.to_string(),
            "final_head_sequence": final_head.sequence.get(),
            "localized_consequences": final_authority.localized_consequences,
            "release_decision_digest": release_execution.decision_record_digest.to_string()
        },
        "denial": {
            "operation": "release.create/v2",
            "presentation_id": lifecycle_id(presentation),
            "reason_code": disabled_decision.1
        },
        "identity": {
            "delegation_id": fixture.delegation_id.to_string(),
            "operating_principal_id": fixture.agent.principal_id.to_string(),
            "requesting_principal_id": fixture.human_principal_id.to_string(),
            "workspace_id": fixture.workspace_id.to_string()
        },
        "operation_calls": {
            "changeset.add/v2": 4,
            "changeset.commit/v2": 2,
            "changeset.create/v2": 2,
            "changeset.diff/v2": 1,
            "changeset.get/v2": 1,
            "changeset.submit/v2": 3,
            "changeset.validate/v2": 4,
            "context.build/v2": 2,
            "edition.create/v2": 2,
            "object.query_released/v2": 1,
            "release.create/v2": 3
        }
    }))
    .unwrap();
    eprintln!("P0005_QUALIFICATION_TRANSCRIPT={}", transcript.as_str());
}

struct LifecycleFixture {
    _directory: TestDirectory,
    repository: LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    agent: AgentCredential,
    delegation_id: proof_application::DelegationId,
    base_time: Timestamp,
    intent: ContentResourceIntent,
    context: LocalizedContextPack,
    source_digest: ContentDigest,
    next_presentation: u64,
    next_evaluation_seconds: i64,
    successful_executions: usize,
}

impl LifecycleFixture {
    #[expect(
        clippy::too_many_lines,
        reason = "the retained fixture makes the Human baseline, intent, ContextPack, and direct grant explicit"
    )]
    fn new() -> Self {
        let directory = TestDirectory::new();
        let base_time = BASE_TIME.parse::<Timestamp>().unwrap();
        let repository = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            DeterministicLocalAuthorityAdapter::new(
                DETERMINISTIC_UID,
                add_seconds(base_time, 30),
                DETERMINISTIC_SUBJECT_BLIND,
            ),
        )
        .unwrap();
        let workspace_id = WORKSPACE_ID.parse::<WorkspaceId>().unwrap();
        let human_principal_id = HUMAN_PRINCIPAL_ID.parse::<PrincipalId>().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();
        prepare_v1_release(&repository);

        let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
        let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
        let schema_version = SchemaVersion::new(1).unwrap();
        let source = json!({
            "legal": "Standard terms apply",
            "slug": "summer-campaign",
            "title": "Summer campaign",
        });
        let source_digest =
            object_revision_digest(object_id, &schema_id, schema_version, &source).unwrap();
        let intent = repository
            .issue_content_resource_intent(IssueContentResourceIntentCommand {
                intent_id: lifecycle_id(0x40).parse().unwrap(),
                environment_id: ENVIRONMENT_ID.parse().unwrap(),
                targets: vec![LocalizedContentTarget {
                    object_id,
                    schema_id: schema_id.clone(),
                    locale: LOCALE.parse::<LocaleId>().unwrap(),
                }],
                idempotency_key: key(0x41),
                issued_at: add_seconds(base_time, 8),
            })
            .unwrap();
        let context = repository
            .build_localized_context(BuildLocalizedContextCommand {
                context_pack_id: lifecycle_id(0x42).parse().unwrap(),
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
                idempotency_key: key(0x43),
                created_at: add_seconds(base_time, 10),
                expires_at: add_seconds(base_time, 3_600),
            })
            .unwrap();
        assert_eq!(intent.issued_by_principal_id, human_principal_id);
        assert_eq!(context.principal_id, human_principal_id);

        let agent = enroll_agent(
            &repository,
            workspace_id,
            human_principal_id,
            base_time,
            0x100,
            0x42,
        );
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        let delegation_id = lifecycle_id(0x200).parse().unwrap();
        repository
            .issue_delegation(DelegationV2 {
                api_version: DelegationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                delegation_id,
                workspace_id,
                delegation_profile: DirectAuthorityProfileV1::Direct,
                issuer_principal_id: human_principal_id,
                recipient_principal_id: agent.principal_id,
                actions: DelegationActionsV2::new(vec![
                    AuthorityAction::ChangesetAdd,
                    AuthorityAction::ChangesetCommit,
                    AuthorityAction::ChangesetCreate,
                    AuthorityAction::ChangesetDiff,
                    AuthorityAction::ChangesetGet,
                    AuthorityAction::ChangesetSubmit,
                    AuthorityAction::ChangesetValidate,
                    AuthorityAction::ContextBuild,
                    AuthorityAction::EditionCreate,
                    AuthorityAction::ObjectQueryReleased,
                    AuthorityAction::ReleaseCreate,
                ])
                .unwrap(),
                scope: DelegationScopeV2 {
                    environment_ids: DelegationEnvironmentIdsV2::new(vec![
                        ENVIRONMENT_ID.parse().unwrap(),
                    ])
                    .unwrap(),
                    object_ids: DelegationObjectIdsV2::new(vec![object_id]).unwrap(),
                    schema_ids: DelegationSchemaIdsV2::new(vec![schema_id]).unwrap(),
                    locales: DelegationLocalesV2::new(vec![LOCALE.parse().unwrap()]).unwrap(),
                },
                constraints: DelegationConstraintsV2 {
                    max_objects: MaxObjects::new(1).unwrap(),
                    max_context_bytes: MaxContextBytes::new(65_536).unwrap(),
                    max_edits_per_changeset: MaxEditsPerChangeSet::new(2).unwrap(),
                    allow_subdelegation: SubdelegationDisabled,
                },
                not_before: add_seconds(base_time, 23),
                expires_at: add_seconds(base_time, 3_600),
                issued_at: add_seconds(base_time, 23),
            })
            .unwrap();

        Self {
            _directory: directory,
            repository,
            workspace_id,
            human_principal_id,
            agent,
            delegation_id,
            base_time,
            intent,
            context,
            source_digest,
            next_presentation: 0x300,
            next_evaluation_seconds: 120,
            successful_executions: 0,
        }
    }

    fn time(&self, seconds: i64) -> Timestamp {
        add_seconds(self.base_time, seconds)
    }

    fn add_input(
        &self,
        changeset_id: proof_application::ChangeSetId,
        key_value: u64,
        legal_value: &str,
        supersedes_edit_id: Option<proof_application::EditId>,
        repair_digest: Option<ContentDigest>,
    ) -> Map<String, Value> {
        object(&json!({
            "api_version": "proof.dev/operation/changeset.add/v2",
            "changeset_id": changeset_id.to_string(),
            "edits": [{
                "api_version": "proof.dev/edit/v2",
                "content": {
                    "legal": legal_value,
                    "slug": "summer-campaign",
                    "title": "Campagne d’été"
                },
                "expected_source": {
                    "digest": self.source_digest.to_string(),
                    "revision": 1,
                    "schema_id": SCHEMA_ID,
                    "schema_version": 1
                },
                "expected_target": null,
                "kind": "object.locale.put",
                "locale": LOCALE,
                "object_id": OBJECT_ID,
                "repair_of_validation_result_digest": repair_digest.map(|value| value.to_string()),
                "supersedes_edit_id": supersedes_edit_id.map(|value| value.to_string())
            }],
            "idempotency_key": lifecycle_id(key_value)
        }))
    }

    fn assert_agent_approval_absent(&self) {
        assert!(
            AuthorityOperation::from_pair(
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v2"
            )
            .is_none()
        );
        assert!(
            capability_for_operation(
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v2"
            )
            .is_none()
        );
        assert!(
            serde_json::from_value::<CommandInputV1>(json!({
                "api_version": "proof.dev/command-input/v1",
                "delegation_id": self.delegation_id.to_string(),
                "idempotency_key": null,
                "normalized_input": {},
                "operating_principal_id": self.agent.principal_id.to_string(),
                "operation": {
                    "name": "changeset.approve",
                    "version": "proof.dev/operation/changeset.approve/v2"
                },
                "requesting_principal_id": self.human_principal_id.to_string(),
                "workspace_id": self.workspace_id.to_string()
            }))
            .is_err()
        );
    }

    fn count(&self, table: &str) -> i64 {
        self.repository
            .open_database()
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn next_invocation(
        &mut self,
        operation: AuthorityOperation,
        normalized_input: Map<String, Value>,
        idempotency_key: Option<IdempotencyKey>,
    ) -> (AuthenticatedInvocationV1, Timestamp) {
        let evaluated_at = self.time(self.next_evaluation_seconds);
        self.next_evaluation_seconds += 2;
        let presentation_id = lifecycle_id(self.next_presentation)
            .parse::<PresentationId>()
            .unwrap();
        self.next_presentation += 1;
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id: self.workspace_id,
            operation,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent.principal_id,
            delegation_id: self.delegation_id,
            idempotency_key,
            normalized_input,
        };
        command_input
            .normalize_for_authenticated_execution()
            .unwrap();
        let canonical_command =
            canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(self.workspace_id),
            workspace_id: self.workspace_id,
            operation,
            binding_id: self.agent.binding_id,
            requesting_principal_id: self.human_principal_id,
            operating_principal_id: self.agent.principal_id,
            delegation_id: self.delegation_id,
            command_digest: digest(ArtifactKind::CommandV1, &canonical_command),
            idempotency_key,
            presentation_id,
            issued_at: add_seconds(evaluated_at, -5),
            expires_at: add_seconds(evaluated_at, 120),
        };
        let envelope = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &command,
            &[&self.agent.signer],
        )
        .unwrap();
        (
            AuthenticatedInvocationV1 {
                api_version: AuthenticatedInvocationApiVersion::V1,
                command_input,
                authentication: AuthenticatedCommandEnvelopeJson::new(envelope.envelope_json)
                    .unwrap(),
            },
            evaluated_at,
        )
    }

    fn execute_once(
        &mut self,
        operation: AuthorityOperation,
        normalized_input: Map<String, Value>,
        idempotency_key: Option<IdempotencyKey>,
    ) -> AuthenticatedExecutionV1 {
        let authority_before = self.authority_state();
        let application_before = self.application_snapshot();
        let ledger_before = self.count("authenticated_application_idempotency_v1");
        let (invocation, evaluated_at) =
            self.next_invocation(operation, normalized_input, idempotency_key);
        let execution = self
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap();
        execution.validate().unwrap();
        assert_eq!(
            execution.decision.decision,
            AuthorizationDecisionOutcome::Allow
        );
        assert_eq!(execution.decision.reason_code, None);
        assert_eq!(execution.decision.operation, operation);
        assert_eq!(
            execution.decision.requested_action,
            authority_operation_entry(operation).requested_action
        );
        assert_eq!(
            execution.decision.requesting_principal_id,
            self.human_principal_id
        );
        assert_eq!(
            execution.decision.operating_principal_id,
            self.agent.principal_id
        );
        assert_eq!(
            execution.decision.delegation.delegation_id,
            self.delegation_id
        );
        assert!(matches!(
            execution.result,
            AuthenticatedOperationResultV1::LocalizedSuccess(_)
        ));
        self.assert_one_authority_effect(&authority_before);
        if authority_operation_entry(operation).application_idempotency
            == ApplicationIdempotency::None
        {
            assert_eq!(self.application_snapshot(), application_before);
            assert_eq!(
                self.count("authenticated_application_idempotency_v1"),
                ledger_before
            );
        }
        self.assert_execution_evidence(&execution);
        self.successful_executions += 1;
        execution
    }

    fn execute_replayed(
        &mut self,
        operation: AuthorityOperation,
        normalized_input: Map<String, Value>,
        idempotency_key: Option<IdempotencyKey>,
        first_call_changes_application: bool,
    ) -> AuthenticatedExecutionV1 {
        assert_ne!(
            authority_operation_entry(operation).application_idempotency,
            ApplicationIdempotency::None
        );
        let application_before = self.application_snapshot();
        let ledger_before = self.count("authenticated_application_idempotency_v1");
        let first = self.execute_once(operation, normalized_input.clone(), idempotency_key);
        let application_after_first = self.application_snapshot();
        if first_call_changes_application {
            assert_ne!(application_after_first, application_before);
        } else {
            assert_eq!(application_after_first, application_before);
        }
        assert_eq!(
            self.count("authenticated_application_idempotency_v1"),
            ledger_before + 1
        );
        let first_evidence = self.consequence_row(first.actor_context.presentation_id);

        let replay = self.execute_once(operation, normalized_input, idempotency_key);
        let replay_evidence = self.consequence_row(replay.actor_context.presentation_id);
        assert_eq!(self.application_snapshot(), application_after_first);
        assert_eq!(
            self.count("authenticated_application_idempotency_v1"),
            ledger_before + 1
        );
        assert_eq!(first.command_input, replay.command_input);
        assert_eq!(first.result, replay.result);
        assert_eq!(first_evidence.result_digest, replay_evidence.result_digest);
        assert_eq!(
            first_evidence.application_effect_digest,
            replay_evidence.application_effect_digest
        );
        assert_eq!(
            first_evidence.application_consequence_digest,
            replay_evidence.application_consequence_digest
        );
        assert_eq!(
            first_evidence.application_idempotency_key,
            replay_evidence.application_idempotency_key
        );
        assert_ne!(
            first_evidence.evidence_digest,
            replay_evidence.evidence_digest
        );
        first
    }

    fn execute_integrity_error_with_unverified_head(
        &mut self,
        operation: AuthorityOperation,
        normalized_input: Map<String, Value>,
        idempotency_key: Option<IdempotencyKey>,
    ) -> AuthorityError {
        let database_before = database_snapshot(&self.repository.open_database().unwrap());
        let (invocation, evaluated_at) =
            self.next_invocation(operation, normalized_input, idempotency_key);
        let error = self
            .repository
            .execute_authenticated(invocation, evaluated_at)
            .unwrap_err();
        assert_eq!(
            database_snapshot(&self.repository.open_database().unwrap()),
            database_before
        );
        error
    }

    fn assert_one_authority_effect(&self, before: &AuthorityState) {
        let after = self.authority_state();
        assert_eq!(after.head_sequence, before.head_sequence + 1);
        assert_eq!(after.authority_records, before.authority_records + 1);
        assert_eq!(after.decisions, before.decisions + 1);
        assert_eq!(after.consumptions, before.consumptions + 1);
        assert_eq!(after.actor_evidence, before.actor_evidence + 1);
        assert_eq!(
            after.localized_consequences,
            before.localized_consequences + 1
        );
    }

    fn authority_state(&self) -> AuthorityState {
        let connection = self.repository.open_database().unwrap();
        let (authority_records, decisions, consumptions, actor_evidence, localized_consequences) =
            connection
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM authority_records),
                            (SELECT COUNT(*) FROM authorization_decisions_v2),
                            (SELECT COUNT(*) FROM presentation_consumptions_v1),
                            (SELECT COUNT(*) FROM authenticated_actor_context_evidence_v1),
                            (SELECT COUNT(*) FROM authenticated_localized_consequences_v1)",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
        AuthorityState {
            head_sequence: self
                .repository
                .authority_head(self.workspace_id)
                .unwrap()
                .unwrap()
                .sequence
                .get(),
            authority_records,
            decisions,
            consumptions,
            actor_evidence,
            localized_consequences,
        }
    }

    fn application_snapshot(&self) -> TableSnapshot {
        governed_snapshot(&self.repository.open_database().unwrap())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the assertion independently reconstructs every signed and persisted localized consequence cross-link"
    )]
    fn assert_execution_evidence(&self, execution: &AuthenticatedExecutionV1) {
        let success = localized_success(execution);
        let operation = success.operation();
        let row = self.consequence_row(execution.actor_context.presentation_id);
        let expected_schema = localized_operation_output_schema_uri(operation).unwrap();
        assert_eq!(row.workspace_id, self.workspace_id.to_string());
        assert_eq!(
            row.requesting_principal_id,
            self.human_principal_id.to_string()
        );
        assert_eq!(
            row.operating_principal_id,
            self.agent.principal_id.to_string()
        );
        assert_eq!(row.delegation_id, self.delegation_id.to_string());
        assert_eq!(row.operation_name, operation.name());
        assert_eq!(row.operation_version, operation.version());
        assert_eq!(row.result_kind, "success");
        assert_eq!(row.result_contract, expected_schema);
        assert_eq!(
            row.authorization_decision_digest,
            execution.decision_record_digest.to_string()
        );

        let canonical_command =
            canonicalize(&serde_json::to_value(&execution.command_input).unwrap()).unwrap();
        assert_eq!(
            row.command_digest,
            digest(ArtifactKind::CommandV1, &canonical_command).to_string()
        );
        let result_value = success.output_value().unwrap();
        let canonical_result = canonicalize(&result_value).unwrap();
        let result_digest = digest(ArtifactKind::OperationEffectV1, &canonical_result);
        assert_eq!(row.result_json, canonical_result.as_str());
        assert_eq!(row.result_digest, result_digest.to_string());
        assert_eq!(
            row.application_effect_digest,
            self.expected_application_effect_digest(execution, result_digest)
                .to_string()
        );

        let expected_idempotency_kind =
            match authority_operation_entry(operation).application_idempotency {
                ApplicationIdempotency::None => "none",
                ApplicationIdempotency::RequiredUuidV7 => "required",
                ApplicationIdempotency::DerivedChangeset
                | ApplicationIdempotency::DerivedProposalPolicyValidator => "derived",
            };
        assert_eq!(row.application_idempotency_kind, expected_idempotency_kind);
        match authority_operation_entry(operation).application_idempotency {
            ApplicationIdempotency::None => {
                assert_eq!(row.application_idempotency_key, None);
            }
            ApplicationIdempotency::RequiredUuidV7 => {
                assert_eq!(
                    row.application_idempotency_key,
                    execution
                        .command_input
                        .idempotency_key
                        .map(|value| value.to_string())
                );
            }
            ApplicationIdempotency::DerivedChangeset
            | ApplicationIdempotency::DerivedProposalPolicyValidator => {
                assert!(execution.command_input.idempotency_key.is_none());
                assert!(row.application_idempotency_key.is_some());
            }
        }

        let evidence_value: Value = serde_json::from_str(&row.evidence_json).unwrap();
        let canonical_evidence = canonicalize(&evidence_value).unwrap();
        assert_eq!(canonical_evidence.as_str(), row.evidence_json);
        assert_eq!(
            digest(ArtifactKind::OperationEffectV1, &canonical_evidence).to_string(),
            row.evidence_digest
        );
        assert_eq!(
            evidence_value["authorization_decision_digest"],
            execution.decision_record_digest.to_string()
        );
        assert_eq!(evidence_value["operation_output_schema"], expected_schema);
        assert_eq!(
            evidence_value["presentation_id"],
            execution.actor_context.presentation_id.to_string()
        );
        assert_eq!(
            evidence_value["requesting_principal_id"],
            self.human_principal_id.to_string()
        );
        assert_eq!(
            evidence_value["operating_principal_id"],
            self.agent.principal_id.to_string()
        );
        assert_eq!(
            evidence_value["result"]["digest"],
            result_digest.to_string()
        );
        assert_eq!(evidence_value["result"]["contract"], expected_schema);
        assert_eq!(
            evidence_value["application_effect_digest"],
            row.application_effect_digest
        );

        let expected_selectors = canonicalize(&json!({
            "changeset_ids": execution.decision.requested_resources.changeset_ids,
            "edition_ids": execution.decision.requested_resources.edition_ids,
            "release_ids": execution.decision.requested_resources.release_ids,
        }))
        .unwrap();
        assert_eq!(
            canonicalize(&evidence_value["selectors"]).unwrap().as_str(),
            expected_selectors.as_str()
        );

        let consequence_commitment = canonicalize(&json!({
            "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
            "application_effect_digest": evidence_value["application_effect_digest"],
            "application_idempotency": evidence_value["application_idempotency"],
            "closure": evidence_value["closure"],
            "command_digest": evidence_value["command_digest"],
            "delegation_id": evidence_value["delegation_id"],
            "operating_principal_id": evidence_value["operating_principal_id"],
            "operation": evidence_value["operation"],
            "requesting_principal_id": evidence_value["requesting_principal_id"],
            "result": evidence_value["result"],
            "selectors": evidence_value["selectors"],
            "semantic_timestamp": evidence_value["semantic_timestamp"],
            "workspace_id": evidence_value["workspace_id"],
        }))
        .unwrap();
        assert_eq!(
            digest(ArtifactKind::OperationEffectV1, &consequence_commitment).to_string(),
            row.application_consequence_digest
        );
        let signed_commitment = execution
            .decision
            .localized_consequence_commitment
            .as_ref()
            .unwrap();
        assert_eq!(signed_commitment.result_contract, expected_schema);
        assert_eq!(
            signed_commitment.result_digest.to_string(),
            row.result_digest
        );
        assert_eq!(
            signed_commitment.application_consequence_digest.to_string(),
            row.application_consequence_digest
        );

        if let Some(intent) = evidence_value["closure"].get("resource_intent") {
            assert_eq!(
                intent["issued_by_principal_id"],
                self.human_principal_id.to_string()
            );
            assert_eq!(intent["intent_id"], self.intent.intent_id.to_string());
            assert_eq!(
                intent["intent_digest"],
                self.intent.intent_digest.to_string()
            );
        }
        if matches!(
            success,
            LocalizedOperationSuccessV1::ChangeSetCommitted(_)
                | LocalizedOperationSuccessV1::EditionCreated(_)
                | LocalizedOperationSuccessV1::ReleaseCreated(_)
        ) {
            assert_eq!(
                evidence_value["closure"]["approval"]["principal_id"],
                self.human_principal_id.to_string()
            );
        }
    }

    fn expected_application_effect_digest(
        &self,
        execution: &AuthenticatedExecutionV1,
        result_digest: ContentDigest,
    ) -> ContentDigest {
        let success = localized_success(execution);
        let required_key = execution
            .command_input
            .idempotency_key
            .map(|value| value.to_string());
        let raw = match success {
            LocalizedOperationSuccessV1::ContextBuilt(_) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_context_build_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    self.workspace_id.to_string(),
                    self.human_principal_id.to_string(),
                    required_key.unwrap(),
                ),
            )),
            LocalizedOperationSuccessV1::ChangeSetCreated(value) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_changesets WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )),
            LocalizedOperationSuccessV1::EditsAdded(_) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_add_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    self.workspace_id.to_string(),
                    self.human_principal_id.to_string(),
                    required_key.unwrap(),
                ),
            )),
            LocalizedOperationSuccessV1::ChangeSetRead(_)
            | LocalizedOperationSuccessV1::ChangeSetDiffed(_)
            | LocalizedOperationSuccessV1::ReleasedRenditionsQueried(_) => None,
            LocalizedOperationSuccessV1::ChangeSetValidated(value) => {
                Some(value.validation_results_digest)
            }
            LocalizedOperationSuccessV1::ChangeSetSubmitted(value) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_submissions WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )),
            LocalizedOperationSuccessV1::ChangeSetCommitted(value) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_commits WHERE changeset_id = ?1",
                [value.changeset_id.to_string()],
            )),
            LocalizedOperationSuccessV1::EditionCreated(_) => Some(self.digest_row(
                "SELECT effect_digest FROM localized_edition_operations
                 WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                (
                    self.workspace_id.to_string(),
                    self.human_principal_id.to_string(),
                    required_key.unwrap(),
                ),
            )),
            LocalizedOperationSuccessV1::ReleaseCreated(value) => Some(value.release_digest),
        };
        raw.unwrap_or(result_digest)
    }

    fn digest_row<P: rusqlite::Params>(&self, statement: &str, params: P) -> ContentDigest {
        self.repository
            .open_database()
            .unwrap()
            .query_row(statement, params, |row| row.get::<_, String>(0))
            .unwrap()
            .parse()
            .unwrap()
    }

    fn consequence_row(&self, presentation_id: PresentationId) -> ConsequenceRow {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT workspace_id, requesting_principal_id, operating_principal_id,
                        delegation_id, command_digest, authorization_decision_digest,
                        operation_name, operation_version, application_idempotency_kind,
                        application_idempotency_key, result_kind, result_contract,
                        result_json, result_digest, application_effect_digest,
                        application_consequence_digest, evidence_json, evidence_digest
                 FROM authenticated_localized_consequences_v1
                 WHERE presentation_id = ?1",
                [presentation_id.to_string()],
                |row| {
                    Ok(ConsequenceRow {
                        workspace_id: row.get(0)?,
                        requesting_principal_id: row.get(1)?,
                        operating_principal_id: row.get(2)?,
                        delegation_id: row.get(3)?,
                        command_digest: row.get(4)?,
                        authorization_decision_digest: row.get(5)?,
                        operation_name: row.get(6)?,
                        operation_version: row.get(7)?,
                        application_idempotency_kind: row.get(8)?,
                        application_idempotency_key: row.get(9)?,
                        result_kind: row.get(10)?,
                        result_contract: row.get(11)?,
                        result_json: row.get(12)?,
                        result_digest: row.get(13)?,
                        application_effect_digest: row.get(14)?,
                        application_consequence_digest: row.get(15)?,
                        evidence_json: row.get(16)?,
                        evidence_digest: row.get(17)?,
                    })
                },
            )
            .unwrap()
    }

    fn assert_evidence_only(&self, execution: &AuthenticatedExecutionV1) {
        let row = self.consequence_row(execution.actor_context.presentation_id);
        assert_eq!(row.application_idempotency_kind, "none");
        assert_eq!(row.application_idempotency_key, None);
        assert_eq!(row.application_effect_digest, row.result_digest);
    }

    fn approval_principal(&self, changeset_id: proof_application::ChangeSetId) -> PrincipalId {
        self.repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT principal_id FROM localized_approvals WHERE changeset_id = ?1",
                [changeset_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .unwrap()
            .parse()
            .unwrap()
    }

    fn rewrite_approval_principal(
        &self,
        changeset_id: proof_application::ChangeSetId,
        principal_id: PrincipalId,
        sealed_changeset_digest: ContentDigest,
        validation_results_digest: ContentDigest,
        approved_at: Timestamp,
    ) {
        let effect = canonicalize(&json!({
            "api_version": "proof.dev/operation-effect/v1",
            "operation_kind": "changeset.approve/v2",
            "result": {
                "approval": "editorial",
                "changeset_id": changeset_id.to_string(),
                "occurred_at": approved_at.to_string(),
                "principal_id": principal_id.to_string(),
                "sealed_changeset_digest": sealed_changeset_digest.to_string(),
                "validation_results_digest": validation_results_digest.to_string(),
            }
        }))
        .unwrap();
        let effect_digest = digest(ArtifactKind::OperationEffectV1, &effect);
        let changed = self
            .repository
            .open_database()
            .unwrap()
            .execute(
                "UPDATE localized_approvals SET principal_id = ?1, effect_digest = ?2
                 WHERE changeset_id = ?3",
                (
                    principal_id.to_string(),
                    effect_digest.to_string(),
                    changeset_id.to_string(),
                ),
            )
            .unwrap();
        assert_eq!(changed, 1);
        assert_eq!(self.approval_principal(changeset_id), principal_id);
    }

    fn assert_release_policy_authority_is_distinct(
        &self,
        release: &proof_application::LocalizedRelease,
        execution: &AuthenticatedExecutionV1,
    ) {
        let (policy_digest, policy_json): (String, String) = self
            .repository
            .open_database()
            .unwrap()
            .query_row(
                "SELECT release.policy_decision_digest, decision.decision_json
                 FROM releases AS release
                 JOIN release_policy_decisions AS decision
                   ON decision.decision_digest = release.policy_decision_digest
                 WHERE release.release_id = ?1",
                [release.release_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let manifest: Value = serde_json::from_str(&release.manifest_json).unwrap();
        assert_eq!(manifest["authorization_decision_digest"], policy_digest);
        assert_ne!(policy_digest, execution.decision_record_digest.to_string());
        let policy: Value = serde_json::from_str(&policy_json).unwrap();
        assert_eq!(
            policy["operating_principal_id"],
            self.human_principal_id.to_string()
        );
        assert_eq!(
            execution.decision.operating_principal_id,
            self.agent.principal_id
        );
        assert_eq!(
            self.repository
                .open_database()
                .unwrap()
                .query_row(
                    "SELECT principal_id FROM releases WHERE release_id = ?1",
                    [release.release_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            self.human_principal_id.to_string()
        );
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the final retained assertion proves all 11 rows and the complete Human-owned P7 artifact chain"
    )]
    fn assert_final_evidence_and_principals(&self, changeset_id: proof_application::ChangeSetId) {
        assert_eq!(self.successful_executions, 24);
        let state = self.authority_state();
        assert_eq!(state.decisions, 24);
        assert_eq!(state.consumptions, 24);
        assert_eq!(state.actor_evidence, 24);
        assert_eq!(state.localized_consequences, 24);
        assert_eq!(self.count("authenticated_application_idempotency_v1"), 10);
        let connection = self.repository.open_database().unwrap();
        let (required_keys, derived_keys): (i64, i64) = connection
            .query_row(
                "SELECT SUM(idempotency_kind = 'required'),
                        SUM(idempotency_kind = 'derived')
                 FROM authenticated_application_idempotency_v1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((required_keys, derived_keys), (7, 3));
        let exact_actor_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authenticated_localized_consequences_v1
                 WHERE requesting_principal_id = ?1 AND operating_principal_id = ?2
                   AND delegation_id = ?3 AND result_kind = 'success'",
                (
                    self.human_principal_id.to_string(),
                    self.agent.principal_id.to_string(),
                    self.delegation_id.to_string(),
                ),
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exact_actor_rows, 24);

        let operation_counts = connection
            .prepare(
                "SELECT operation_name, operation_version, COUNT(*)
                 FROM authenticated_localized_consequences_v1
                 GROUP BY operation_name, operation_version",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((
                    (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                    row.get::<_, i64>(2)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect::<BTreeMap<_, _>>();
        let expected_counts = [
            (AuthorityOperation::ContextBuildV2, 2),
            (AuthorityOperation::ChangesetCreateV2, 2),
            (AuthorityOperation::ChangesetAddV2, 4),
            (AuthorityOperation::ChangesetGetV2, 1),
            (AuthorityOperation::ChangesetDiffV2, 1),
            (AuthorityOperation::ChangesetValidateV2, 4),
            (AuthorityOperation::ChangesetSubmitV2, 3),
            (AuthorityOperation::ChangesetCommitV2, 2),
            (AuthorityOperation::EditionCreateV2, 2),
            (AuthorityOperation::ReleaseCreateV2, 2),
            (AuthorityOperation::ObjectQueryReleasedV2, 1),
        ]
        .into_iter()
        .map(|(operation, count)| {
            (
                (operation.name().to_owned(), operation.version().to_owned()),
                count,
            )
        })
        .collect::<BTreeMap<_, _>>();
        assert_eq!(operation_counts, expected_counts);

        for (table, expected) in [
            ("content_resource_intents", 1),
            ("localized_context_packs", 1),
            ("localized_context_build_operations", 1),
            ("localized_changesets", 1),
            ("localized_edits", 2),
            ("localized_add_operations", 2),
            ("localized_validations", 2),
            ("localized_submissions", 1),
            ("localized_approvals", 1),
            ("localized_commits", 1),
            ("object_locale_revisions", 1),
            ("localized_edition_metadata", 1),
            ("localized_edition_operations", 1),
            ("localized_release_metadata", 1),
            ("localized_release_operations", 1),
        ] {
            assert_eq!(self.count(table), expected, "unexpected {table} count");
        }
        assert_eq!(self.count("editions"), 2);
        assert_eq!(self.count("releases"), 2);
        assert_eq!(
            self.approval_principal(changeset_id),
            self.human_principal_id
        );

        let agent_owned_rows: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM (
                     SELECT issued_by_principal_id AS principal_id FROM content_resource_intents
                     UNION ALL SELECT principal_id FROM localized_context_packs
                     UNION ALL SELECT principal_id FROM localized_context_build_operations
                     UNION ALL SELECT principal_id FROM localized_changesets
                     UNION ALL SELECT principal_id FROM localized_add_operations
                     UNION ALL SELECT principal_id FROM localized_submissions
                     UNION ALL SELECT principal_id FROM localized_approvals
                     UNION ALL SELECT principal_id FROM localized_commits
                     UNION ALL SELECT principal_id FROM localized_edition_operations
                     UNION ALL SELECT principal_id FROM localized_release_operations
                     UNION ALL SELECT principal_id FROM editions
                     UNION ALL SELECT principal_id FROM releases
                 ) WHERE principal_id = ?1",
                [self.agent.principal_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(agent_owned_rows, 0);
    }
}

struct AgentCredential {
    principal_id: PrincipalId,
    binding_id: proof_application::BindingId,
    signer: Ed25519SigningProvider,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityState {
    head_sequence: u64,
    authority_records: i64,
    decisions: i64,
    consumptions: i64,
    actor_evidence: i64,
    localized_consequences: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsequenceRow {
    workspace_id: String,
    requesting_principal_id: String,
    operating_principal_id: String,
    delegation_id: String,
    command_digest: String,
    authorization_decision_digest: String,
    operation_name: String,
    operation_version: String,
    application_idempotency_kind: String,
    application_idempotency_key: Option<String>,
    result_kind: String,
    result_contract: String,
    result_json: String,
    result_digest: String,
    application_effect_digest: String,
    application_consequence_digest: String,
    evidence_json: String,
    evidence_digest: String,
}

type TableSnapshot = Vec<(String, Vec<Vec<String>>)>;

fn governed_snapshot(connection: &Connection) -> TableSnapshot {
    const AUTHORITY_TABLES: &[&str] = &[
        "authenticated_actor_context_evidence_v1",
        "authenticated_application_idempotency_v1",
        "authenticated_localized_consequences_v1",
        "authenticated_operation_results_v1",
        "authenticated_subject_commitment_openings_v1",
        "authority_records",
        "authorization_decisions_v2",
        "binding_enrollment_challenges",
        "delegation_revocations_v2",
        "delegations_v2",
        "presentation_consumptions_v1",
        "principal_binding_revocations_v1",
        "principal_bindings_v1",
        "principal_status_v1",
        "workspace_authority_roots",
    ];
    connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|name| {
            name != "sqlite_sequence"
                && name != "schema_migrations"
                && name != "workspace_metadata"
                && !AUTHORITY_TABLES.contains(&name.as_str())
        })
        .map(|name| {
            let quoted = name.replace('"', "\"\"");
            let rows = snapshot_rows(connection, &format!("SELECT * FROM \"{quoted}\""));
            (name, rows)
        })
        .collect()
}

fn database_snapshot(connection: &Connection) -> TableSnapshot {
    connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .filter(|name| name != "sqlite_sequence")
        .map(|name| {
            let quoted = name.replace('"', "\"\"");
            let rows = snapshot_rows(connection, &format!("SELECT * FROM \"{quoted}\""));
            (name, rows)
        })
        .collect()
}

fn snapshot_rows(connection: &Connection, sql: &str) -> Vec<Vec<String>> {
    let mut statement = connection.prepare(sql).unwrap();
    let column_count = statement.column_count();
    let mut rows = statement
        .query_map([], |row| {
            (0..column_count)
                .map(|index| {
                    Ok(match row.get_ref(index)? {
                        ValueRef::Null => "null".to_owned(),
                        ValueRef::Integer(value) => format!("integer:{value}"),
                        ValueRef::Real(value) => format!("real:{value:?}"),
                        ValueRef::Text(value) => {
                            format!("text:{}", String::from_utf8_lossy(value))
                        }
                        ValueRef::Blob(value) => format!("blob:{value:?}"),
                    })
                })
                .collect::<rusqlite::Result<Vec<_>>>()
        })
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    rows.sort();
    rows
}

fn enroll_agent(
    repository: &LocalWorkspace,
    workspace_id: WorkspaceId,
    human_principal_id: PrincipalId,
    base_time: Timestamp,
    id_namespace: u64,
    secret_byte: u8,
) -> AgentCredential {
    let principal_id = lifecycle_id(id_namespace).parse::<PrincipalId>().unwrap();
    let binding_id = lifecycle_id(id_namespace + 2).parse().unwrap();
    create_agent_principal(
        repository,
        CreateAgentPrincipalCommand {
            principal_id,
            display_name: "p0005-lifecycle-agent".to_owned(),
            idempotency_key: key(id_namespace + 1),
            created_at: base_time,
        },
    )
    .unwrap();
    let signer = Ed25519SigningProvider::from_secret_bytes(&[secret_byte; 32]);
    let metadata = signer.metadata().unwrap();
    let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
    let public_key = Ed25519PublicKey::new(BASE64.encode(metadata.public_key)).unwrap();
    let challenge = BindingEnrollmentChallengeV1 {
        api_version: EnrollmentChallengeApiVersion::V1,
        challenge_id: lifecycle_id(id_namespace + 3).parse().unwrap(),
        audience: AuthorityAudience::for_workspace(workspace_id),
        workspace_id,
        binding_id,
        principal_id,
        candidate_key_id: key_id.clone(),
        issued_by_principal_id: human_principal_id,
        issued_at: add_seconds(base_time, 20),
        expires_at: add_seconds(base_time, 320),
    };
    let recorded = repository
        .create_binding_enrollment_challenge(challenge.clone())
        .unwrap();
    let envelope = sign_authority_payload(
        AuthorityPayloadProfile::BindingEnrollmentChallenge,
        &challenge,
        &[&signer],
    )
    .unwrap();
    let head = repository.authority_head(workspace_id).unwrap().unwrap();
    repository
        .issue_principal_binding(
            PrincipalBindingV1 {
                api_version: PrincipalBindingApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                workspace_id,
                binding_id,
                principal_id,
                principal_type: AgentPrincipalType::Agent,
                authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
                algorithm: Ed25519Algorithm::Ed25519,
                public_key,
                key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                audience: AuthorityAudience::for_workspace(workspace_id),
                enrollment_challenge_digest: recorded.challenge_digest,
                enrollment_envelope_digest: envelope.envelope_digest,
                issued_by_principal_id: human_principal_id,
                issued_at: add_seconds(base_time, 21),
                not_before: add_seconds(base_time, 21),
                expires_at: add_seconds(base_time, 3_600),
                supersedes_binding_id: None,
            },
            envelope.envelope_json,
        )
        .unwrap();
    let head = repository.authority_head(workspace_id).unwrap().unwrap();
    repository
        .set_principal_status(PrincipalStatusV1 {
            api_version: PrincipalStatusApiVersion::V1,
            authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
            previous_authority_record_digest: Some(head.record_digest),
            workspace_id,
            principal_id,
            principal_type: AuthorityPrincipalType::Agent,
            enabled: true,
            recorded_by_principal_id: human_principal_id,
            recorded_at: add_seconds(base_time, 22),
        })
        .unwrap();
    AgentCredential {
        principal_id,
        binding_id,
        signer,
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the retained fixture constructs the complete public v1 source-to-Release baseline"
)]
fn prepare_v1_release(repository: &LocalWorkspace) {
    let source = json!({
        "legal": "Standard terms apply",
        "slug": "summer-campaign",
        "title": "Summer campaign",
    });
    let changeset_id = lifecycle_id(0x20).parse().unwrap();
    create_changeset(
        repository,
        CreateChangeSetCommand {
            changeset_id,
            intent: ChangeSetIntent::new("Create P-0005 source").unwrap(),
            requested_base_state: None,
            idempotency_key: key(0x22),
            created_at: "2026-08-20T10:00:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
    let schema_document = json!({
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
    let canonical_schema = canonicalize(&schema_document).unwrap();
    let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
    let schema_version = SchemaVersion::new(1).unwrap();
    let canonical_source = canonicalize(&source).unwrap();
    add_changeset_edits(
        repository,
        AddChangeSetEditsCommand {
            changeset_id,
            edits: vec![
                ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                    edit_id: lifecycle_id(0x23).parse().unwrap(),
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_document: canonical_schema.as_str().to_owned(),
                    document_digest: digest(ArtifactKind::SchemaVersionV1, &canonical_schema),
                }),
                ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                    edit_id: lifecycle_id(0x24).parse().unwrap(),
                    object_id,
                    schema_id: schema_id.clone(),
                    schema_version,
                    canonical_content: canonical_source.as_str().to_owned(),
                    object_digest: object_revision_digest(
                        object_id,
                        &schema_id,
                        schema_version,
                        &source,
                    )
                    .unwrap(),
                }),
            ],
            idempotency_key: key(0x25),
        },
    )
    .unwrap();
    assert!(validate_changeset(repository, changeset_id).unwrap().valid);
    submit_changeset(
        repository,
        SubmitChangeSetCommand {
            changeset_id,
            submitted_at: "2026-08-20T10:01:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    approve_changeset(
        repository,
        ApproveChangeSetCommand {
            changeset_id,
            approval: ApprovalName::new("editorial").unwrap(),
            approved_at: "2026-08-20T10:02:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    commit_changeset(
        repository,
        CommitChangeSetCommand {
            changeset_id,
            idempotency_key: key(0x26),
            committed_at: "2026-08-20T10:03:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    let edition_id = lifecycle_id(0x27).parse().unwrap();
    create_edition(
        repository,
        CreateEditionCommand {
            edition_id,
            idempotency_key: key(0x28),
            created_at: "2026-08-20T10:04:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    create_environment(
        repository,
        CreateEnvironmentCommand {
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            target_kind: "proof.local/released-state/v1".to_owned(),
            policy_profile: "proof.local/release-policy/v1".to_owned(),
            required_approval: ApprovalName::new("editorial").unwrap(),
            idempotency_key: key(0x29),
            created_at: "2026-08-20T10:05:00Z".parse().unwrap(),
        },
    )
    .unwrap();
    promote_release(
        repository,
        PromoteReleaseCommand {
            release_id: lifecycle_id(0x2a).parse::<ReleaseId>().unwrap(),
            proof_id: lifecycle_id(0x2b).parse::<ProofId>().unwrap(),
            environment_id: ENVIRONMENT_ID.parse().unwrap(),
            edition_id,
            idempotency_key: key(0x2c),
            released_at: "2026-08-20T10:06:00Z".parse().unwrap(),
        },
    )
    .unwrap();
}

fn localized_success(execution: &AuthenticatedExecutionV1) -> &LocalizedOperationSuccessV1 {
    let AuthenticatedOperationResultV1::LocalizedSuccess(success) = &execution.result else {
        panic!("authenticated localized operation did not return success")
    };
    success
}

fn object(value: &Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn lifecycle_id(value: u64) -> String {
    format!("019d2000-0000-7000-8000-{value:012x}")
}

fn key(value: u64) -> IdempotencyKey {
    lifecycle_id(value).parse().unwrap()
}

fn add_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(
        timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
    )
    .unwrap()
}

struct ReleaseProofExportBlocker {
    proof_path: PathBuf,
    #[cfg(unix)]
    proof_directory: PathBuf,
    #[cfg(windows)]
    locked_file: Option<fs::File>,
}

impl ReleaseProofExportBlocker {
    fn install(repository: &LocalWorkspace, proof_id: ProofId) -> Self {
        let proof_directory = repository
            .runtime_path()
            .join("artifacts")
            .join("release-proofs");
        fs::create_dir_all(&proof_directory).unwrap();
        let proof_path = proof_directory.join(format!("{proof_id}.dsse.json"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&proof_directory, fs::Permissions::from_mode(0o500)).unwrap();
            Self {
                proof_path,
                proof_directory,
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;

            fs::write(&proof_path, "{}").unwrap();
            let locked_file = fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&proof_path)
                .unwrap();
            Self {
                proof_path,
                locked_file: Some(locked_file),
            }
        }
    }

    fn is_materialized(&self, release: &proof_application::LocalizedRelease) -> bool {
        fs::read_to_string(&self.proof_path)
            .is_ok_and(|persisted| persisted == release.proof_envelope_json)
    }

    fn recover(mut self) {
        self.restore();
    }

    fn restore(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&self.proof_directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(windows)]
        {
            drop(self.locked_file.take());
            if self.proof_path.exists() {
                fs::remove_file(&self.proof_path).unwrap();
            }
        }
    }
}

impl Drop for ReleaseProofExportBlocker {
    fn drop(&mut self) {
        self.restore();
    }
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-p0005-delegated-lifecycle-{}-{sequence}",
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
