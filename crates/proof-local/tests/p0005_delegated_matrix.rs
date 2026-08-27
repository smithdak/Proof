mod retained {
    include!("p0005_delegated_lifecycle.rs");

    mod matrix {
        use std::sync::{Arc, Barrier, mpsc};

        use super::*;
        use proof_application::authority::{
            AuthorizationDenialReason, DelegationRevocationApiVersion,
            DelegationRevocationReasonV1, DelegationRevocationV1, LocalizedOperationFailureKindV1,
            PrincipalBindingRevocationApiVersion, PrincipalBindingRevocationReason,
            PrincipalBindingRevocationV1,
        };
        use proof_application::{
            AddLocalizedEditsCommand, ChangeSetId, CommitLocalizedChangeSetCommand,
            CreateLocalizedChangeSetCommand, ExpectedLocalizedSource, ObjectLocalePutInput,
            ObjectRevision,
        };

        #[derive(Clone)]
        struct GrantScope {
            recipient: PrincipalId,
            actions: Vec<AuthorityAction>,
            environments: Vec<proof_application::EnvironmentId>,
            objects: Vec<ObjectId>,
            schemas: Vec<SchemaId>,
            locales: Vec<LocaleId>,
            max_objects: u32,
            max_context_bytes: u32,
            max_edits: u32,
            not_before: Timestamp,
            expires_at: Timestamp,
        }

        type GrantMutation = fn(&mut LifecycleFixture, &mut GrantScope);
        type DenialCase = (
            &'static str,
            GrantMutation,
            AuthorityError,
            AuthorizationDenialReason,
        );

        impl GrantScope {
            fn covering(fixture: &LifecycleFixture) -> Self {
                Self {
                    recipient: fixture.agent.principal_id,
                    actions: vec![AuthorityAction::ContextBuild],
                    environments: vec![ENVIRONMENT_ID.parse().unwrap()],
                    objects: vec![OBJECT_ID.parse().unwrap()],
                    schemas: vec![SchemaId::new(SCHEMA_ID).unwrap()],
                    locales: vec![LOCALE.parse().unwrap()],
                    max_objects: 1,
                    max_context_bytes: 65_536,
                    max_edits: 2,
                    not_before: fixture.time(23),
                    expires_at: fixture.time(3_600),
                }
            }
        }

        #[test]
        fn malformed_and_actor_mismatched_presentations_leave_zero_durable_writes() {
            let mut fixture = LifecycleFixture::new();
            let input = context_input(&fixture);
            let (mut actor_mismatch, evaluated_at) = fixture.next_invocation(
                AuthorityOperation::ContextBuildV2,
                input.clone(),
                Some(key(0x610)),
            );
            actor_mismatch.command_input.operating_principal_id = fixture.human_principal_id;
            assert_pre_authority_failure(
                &fixture,
                actor_mismatch,
                evaluated_at,
                AuthorityError::AuthActorMismatch,
            );

            let (mut malformed, evaluated_at) = fixture.next_invocation(
                AuthorityOperation::ContextBuildV2,
                input,
                Some(key(0x610)),
            );
            malformed
                .command_input
                .normalized_input
                .insert("unexpected".to_owned(), Value::String("field".to_owned()));
            // Unknown normalized fields fail closed before any durable authority write.
            assert_pre_authority_failure(
                &fixture,
                malformed,
                evaluated_at,
                AuthorityError::AuthMalformed,
            );
        }

        #[test]
        #[expect(
            clippy::too_many_lines,
            reason = "the retained table makes every P-0005 Delegation dimension and denial effect explicit"
        )]
        fn delegation_scope_budget_lifetime_recipient_and_revocation_denials_are_evidence_only() {
            let cases: [DenialCase; 8] = [
                (
                    "action",
                    |_, grant| grant.actions = vec![AuthorityAction::ChangesetAdd],
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
                (
                    "environment",
                    |_, grant| grant.environments = vec!["production".parse().unwrap()],
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
                (
                    "object",
                    |_, grant| {
                        grant.objects = vec![lifecycle_id(0xdead).parse().unwrap()];
                    },
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
                (
                    "schema",
                    |_, grant| grant.schemas = vec![SchemaId::new("other").unwrap()],
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
                (
                    "locale",
                    |_, grant| grant.locales = vec!["de-DE".parse().unwrap()],
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
                (
                    "budget",
                    |_, grant| grant.max_context_bytes = 1_024,
                    AuthorityError::BudgetExceeded,
                    AuthorizationDenialReason::BudgetExceeded,
                ),
                (
                    "expired",
                    |fixture, grant| grant.expires_at = fixture.time(100),
                    AuthorityError::DelegationExpired,
                    AuthorizationDenialReason::DelegationExpired,
                ),
                (
                    "recipient",
                    |fixture, grant| {
                        grant.recipient = enroll_agent(
                            &fixture.repository,
                            fixture.workspace_id,
                            fixture.human_principal_id,
                            fixture.base_time,
                            0x620,
                            0x62,
                        )
                        .principal_id;
                    },
                    AuthorityError::ScopeExceeded,
                    AuthorizationDenialReason::ScopeExceeded,
                ),
            ];

            for (offset, (label, mutate, expected_error, expected_reason)) in
                cases.into_iter().enumerate()
            {
                let mut fixture = LifecycleFixture::new();
                let mut grant = GrantScope::covering(&fixture);
                mutate(&mut fixture, &mut grant);
                let delegation_id = issue_grant(&fixture, 0x630 + offset as u64, grant);
                fixture.delegation_id = delegation_id;
                let input = context_input(&fixture);
                assert_authorization_denial(
                    &mut fixture,
                    input,
                    expected_error,
                    expected_reason,
                    label,
                );
            }

            let mut revoked = LifecycleFixture::new();
            let delegation_id = issue_grant(&revoked, 0x640, GrantScope::covering(&revoked));
            let head = revoked
                .repository
                .authority_head(revoked.workspace_id)
                .unwrap()
                .unwrap();
            revoked
                .repository
                .revoke_delegation(DelegationRevocationV1 {
                    api_version: DelegationRevocationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: head.record_digest,
                    revocation_id: lifecycle_id(0x641).parse().unwrap(),
                    workspace_id: revoked.workspace_id,
                    delegation_id,
                    revoked_by_principal_id: revoked.human_principal_id,
                    reason: DelegationRevocationReasonV1::IssuerRequest,
                    revoked_at: revoked.time(100),
                })
                .unwrap();
            revoked.delegation_id = delegation_id;
            let input = context_input(&revoked);
            assert_authorization_denial(
                &mut revoked,
                input,
                AuthorityError::DelegationRevoked,
                AuthorizationDenialReason::DelegationRevoked,
                "revoked",
            );
        }

        #[test]
        fn localized_failure_does_not_reserve_global_key_and_corrected_input_succeeds() {
            let mut fixture = LifecycleFixture::new();
            let existing_id: ChangeSetId = lifecycle_id(0x650).parse().unwrap();
            let create_key = key(0x651);
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                changeset_create_input(&fixture, existing_id, create_key),
                Some(create_key),
            );
            let application_key = key(0x652);
            let mut failed_input = fixture.add_input(
                existing_id,
                0x652,
                "Les conditions standard s’appliquent",
                None,
                None,
            );
            failed_input["edits"].as_array_mut().unwrap()[0]["expected_source"]["digest"] =
                Value::String(fixture.context.context_pack_digest.to_string());
            let application_before = fixture.application_snapshot();
            let ledger_before = fixture.count("authenticated_application_idempotency_v1");
            let failure = execute_allow_failure(
                &mut fixture,
                AuthorityOperation::ChangesetAddV2,
                failed_input,
                Some(application_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(problem) = &failure.result else {
                panic!("duplicate ChangeSet identity did not become a signed localized failure")
            };
            assert_eq!(
                problem.kind,
                LocalizedOperationFailureKindV1::SourceConflict
            );
            assert_eq!(fixture.application_snapshot(), application_before);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before
            );

            let corrected = fixture.execute_once(
                AuthorityOperation::ChangesetAddV2,
                fixture.add_input(
                    existing_id,
                    0x652,
                    "Les conditions standard s’appliquent",
                    None,
                    None,
                ),
                Some(application_key),
            );
            assert!(matches!(
                corrected.result,
                AuthenticatedOperationResultV1::LocalizedSuccess(
                    LocalizedOperationSuccessV1::EditsAdded(_)
                )
            ));
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before + 1
            );
        }

        #[test]
        fn exact_replay_is_stable_but_stale_context_withholds_the_prior_result() {
            let mut fixture = LifecycleFixture::new();
            fixture.context = fixture
                .repository
                .build_localized_context(BuildLocalizedContextCommand {
                    context_pack_id: lifecycle_id(0x65f).parse().unwrap(),
                    resource_intent_id: fixture.intent.intent_id,
                    resource_intent_digest: fixture.intent.intent_digest,
                    policy_rules: vec![LocalizedPolicyRule {
                        locale: LOCALE.parse().unwrap(),
                        pointer: "/legal".to_owned(),
                        disallowed_values: vec!["Forbidden terms".to_owned()],
                    }],
                    limits: fixture.context.limits,
                    idempotency_key: key(0x65f),
                    created_at: fixture.time(30),
                    expires_at: fixture.time(200),
                })
                .unwrap();
            let application_key = key(0x660);
            let changeset_id = lifecycle_id(0x661).parse().unwrap();
            let input = changeset_create_input(&fixture, changeset_id, application_key);
            let first = fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                input.clone(),
                Some(application_key),
            );
            let effects = fixture.count("localized_changesets");
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            let replay = fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                input.clone(),
                Some(application_key),
            );
            assert_eq!(first.result, replay.result);
            assert_eq!(fixture.count("localized_changesets"), effects);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );

            fixture.next_evaluation_seconds = 201;
            let stale = execute_allow_failure(
                &mut fixture,
                AuthorityOperation::ChangesetCreateV2,
                input,
                Some(application_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(problem) = stale.result else {
                panic!("expired ContextPack disclosed a prior success")
            };
            assert_eq!(problem.kind, LocalizedOperationFailureKindV1::PolicyDenied);
            assert_eq!(fixture.count("localized_changesets"), effects);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        #[test]
        fn required_application_key_is_workspace_global_across_agent_operation_and_input() {
            let mut fixture = LifecycleFixture::new();
            let global_key = key(0x43);
            let mut context = context_input(&fixture);
            context.insert(
                "idempotency_key".to_owned(),
                Value::String(global_key.to_string()),
            );
            let first = fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                context.clone(),
                Some(global_key),
            );
            assert!(matches!(
                first.result,
                AuthenticatedOperationResultV1::LocalizedSuccess(
                    LocalizedOperationSuccessV1::ContextBuilt(_)
                )
            ));
            let ledger = fixture.count("authenticated_application_idempotency_v1");

            let second_agent = enroll_agent(
                &fixture.repository,
                fixture.workspace_id,
                fixture.human_principal_id,
                fixture.base_time,
                0x680,
                0x68,
            );
            let mut second_scope = GrantScope::covering(&fixture);
            second_scope.recipient = second_agent.principal_id;
            second_scope.actions = vec![
                AuthorityAction::ChangesetCreate,
                AuthorityAction::ContextBuild,
            ];
            let second_grant = issue_grant(&fixture, 0x681, second_scope);
            fixture.agent = second_agent;
            fixture.delegation_id = second_grant;
            assert_key_reuse_denial(
                &mut fixture,
                AuthorityOperation::ContextBuildV2,
                context,
                global_key,
                "different Agent",
            );

            let changed_operation =
                changeset_create_input(&fixture, lifecycle_id(0x682).parse().unwrap(), global_key);
            assert_key_reuse_denial(
                &mut fixture,
                AuthorityOperation::ChangesetCreateV2,
                changed_operation,
                global_key,
                "different operation",
            );
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );

            let input_key = key(0x683);
            let first_id = lifecycle_id(0x684).parse().unwrap();
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                changeset_create_input(&fixture, first_id, input_key),
                Some(input_key),
            );
            let changed_input =
                changeset_create_input(&fixture, lifecycle_id(0x685).parse().unwrap(), input_key);
            assert_key_reuse_denial(
                &mut fixture,
                AuthorityOperation::ChangesetCreateV2,
                changed_input,
                input_key,
                "different semantic input",
            );
        }

        #[test]
        fn invalid_validation_exact_replay_does_not_append_an_attempt() {
            let mut fixture = LifecycleFixture::new();
            let changeset_id = lifecycle_id(0x690).parse().unwrap();
            let create_key = key(0x691);
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                changeset_create_input(&fixture, changeset_id, create_key),
                Some(create_key),
            );
            fixture.execute_once(
                AuthorityOperation::ChangesetAddV2,
                fixture.add_input(changeset_id, 0x692, "Forbidden terms", None, None),
                Some(key(0x692)),
            );
            let selector = object(&json!({
                "api_version": "proof.dev/operation/changeset.validate/v2",
                "changeset_id": changeset_id.to_string()
            }));
            let before = fixture.count("localized_validations");
            let first = fixture.execute_once(
                AuthorityOperation::ChangesetValidateV2,
                selector.clone(),
                None,
            );
            let LocalizedOperationSuccessV1::ChangeSetValidated(first_result) =
                localized_success(&first)
            else {
                panic!("validation returned the wrong result")
            };
            assert!(!first_result.valid);
            assert_eq!(fixture.count("localized_validations"), before + 1);
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            let replay =
                fixture.execute_once(AuthorityOperation::ChangesetValidateV2, selector, None);
            assert_eq!(first.result, replay.result);
            assert_eq!(fixture.count("localized_validations"), before + 1);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        #[test]
        fn stale_known_state_withholds_a_previously_committed_result() {
            let mut fixture = LifecycleFixture::new();
            let application_key = key(0x6a0);
            let changeset_id = lifecycle_id(0x6a1).parse().unwrap();
            let input = changeset_create_input(&fixture, changeset_id, application_key);
            let first = fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                input.clone(),
                Some(application_key),
            );
            assert!(matches!(
                first.result,
                AuthenticatedOperationResultV1::LocalizedSuccess(_)
            ));
            let ledger = fixture.count("authenticated_application_idempotency_v1");

            advance_localized_target(&fixture);
            let localized_count = fixture.count("localized_changesets");
            let stale = execute_allow_failure(
                &mut fixture,
                AuthorityOperation::ChangesetCreateV2,
                input,
                Some(application_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(problem) = stale.result else {
                panic!("stale known state disclosed a prior localized result")
            };
            assert_eq!(problem.kind, LocalizedOperationFailureKindV1::PolicyDenied);
            assert_eq!(fixture.count("localized_changesets"), localized_count);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        #[test]
        fn stale_target_withholds_exact_context_build_replay_without_projection_movement() {
            let mut fixture = LifecycleFixture::new();
            let global_key = key(0x43);
            let mut input = context_input(&fixture);
            input.insert(
                "idempotency_key".to_owned(),
                Value::String(global_key.to_string()),
            );
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                input.clone(),
                Some(global_key),
            );
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            advance_localized_target(&fixture);
            let application = fixture.application_snapshot();
            let context_operations = fixture.count("localized_context_build_operations");
            let stale = execute_allow_failure(
                &mut fixture,
                AuthorityOperation::ContextBuildV2,
                input,
                Some(global_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(problem) = stale.result else {
                panic!("stale target disclosed the exact prior ContextBuild result")
            };
            assert_eq!(problem.kind, LocalizedOperationFailureKindV1::PolicyDenied);
            assert_eq!(fixture.application_snapshot(), application);
            assert_eq!(
                fixture.count("localized_context_build_operations"),
                context_operations
            );
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        #[test]
        fn multi_locale_intent_counts_one_distinct_object_against_budget() {
            let mut fixture = LifecycleFixture::new();
            let object_id = OBJECT_ID.parse::<ObjectId>().unwrap();
            let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
            let intent = fixture
                .repository
                .issue_content_resource_intent(IssueContentResourceIntentCommand {
                    creations: Vec::new(),
                    intent_id: lifecycle_id(0x6b0).parse().unwrap(),
                    environment_id: ENVIRONMENT_ID.parse().unwrap(),
                    targets: vec![
                        LocalizedContentTarget {
                            object_id,
                            schema_id: schema_id.clone(),
                            locale: "de-DE".parse().unwrap(),
                        },
                        LocalizedContentTarget {
                            object_id,
                            schema_id,
                            locale: LOCALE.parse().unwrap(),
                        },
                    ],
                    idempotency_key: key(0x6b1),
                    issued_at: fixture.time(30),
                })
                .unwrap();
            let context_key = key(0x6b2);
            let context = fixture
                .repository
                .build_localized_context(BuildLocalizedContextCommand {
                    context_pack_id: lifecycle_id(0x6b3).parse().unwrap(),
                    resource_intent_id: intent.intent_id,
                    resource_intent_digest: intent.intent_digest,
                    policy_rules: vec![
                        LocalizedPolicyRule {
                            locale: "de-DE".parse().unwrap(),
                            pointer: "/legal".to_owned(),
                            disallowed_values: vec!["Verboten".to_owned()],
                        },
                        LocalizedPolicyRule {
                            locale: LOCALE.parse().unwrap(),
                            pointer: "/legal".to_owned(),
                            disallowed_values: vec!["Interdit".to_owned()],
                        },
                    ],
                    limits: LocalizedContextLimits {
                        max_objects: 1,
                        max_edits: 2,
                        max_validation_attempts: 2,
                        max_bytes: 65_536,
                    },
                    idempotency_key: context_key,
                    created_at: fixture.time(32),
                    expires_at: fixture.time(3_500),
                })
                .unwrap();
            let mut grant = GrantScope::covering(&fixture);
            grant.locales = vec!["de-DE".parse().unwrap(), LOCALE.parse().unwrap()];
            fixture.delegation_id = issue_grant(&fixture, 0x6b4, grant);
            let input = context_replay_input(&intent, &context, context_key);
            fixture.intent = intent;
            fixture.context = context;
            let execution =
                fixture.execute_once(AuthorityOperation::ContextBuildV2, input, Some(context_key));
            assert!(matches!(
                execution.result,
                AuthenticatedOperationResultV1::LocalizedSuccess(
                    LocalizedOperationSuccessV1::ContextBuilt(_)
                )
            ));
            assert_eq!(
                execution.decision.effective_constraints.max_objects.get(),
                1
            );
            assert_eq!(
                execution.decision.requested_resources.object_ids.as_slice(),
                &[object_id]
            );
            assert_eq!(
                execution
                    .decision
                    .requested_resources
                    .locales
                    .as_slice()
                    .len(),
                2
            );
        }

        #[test]
        #[expect(
            clippy::too_many_lines,
            reason = "both SQLite writer orders retain their exact authority and application effects"
        )]
        fn revocation_and_localized_consequence_are_serialized_in_both_writer_orders() {
            let mut revoke_first = LifecycleFixture::new();
            let global_key = key(0x6d2);
            let changeset_id = lifecycle_id(0x6d3).parse().unwrap();
            let input = changeset_create_input(&revoke_first, changeset_id, global_key);
            let (invocation, evaluated_at) = revoke_first.next_invocation(
                AuthorityOperation::ChangesetCreateV2,
                input,
                Some(global_key),
            );
            let authority_before = revoke_first.authority_state();
            let application_before = revoke_first.application_snapshot();
            let ledger_before = revoke_first.count("authenticated_application_idempotency_v1");
            let gate = revoke_first.repository.open_database().unwrap();
            gate.execute_batch("BEGIN IMMEDIATE").unwrap();
            let barrier = Arc::new(Barrier::new(3));
            let (revoked_tx, revoked_rx) = mpsc::sync_channel(0);
            let revocation_repository = revoke_first.repository.clone();
            let workspace_id = revoke_first.workspace_id;
            let human_principal_id = revoke_first.human_principal_id;
            let delegation_id = revoke_first.delegation_id;
            let revocation_barrier = Arc::clone(&barrier);
            let revocation = std::thread::spawn(move || {
                revocation_barrier.wait();
                revoke_delegation(
                    &revocation_repository,
                    workspace_id,
                    human_principal_id,
                    delegation_id,
                    lifecycle_id(0x6d0).parse().unwrap(),
                    add_seconds(BASE_TIME.parse().unwrap(), 100),
                )
                .unwrap();
                revoked_tx.send(()).unwrap();
            });
            let consequence_repository = revoke_first.repository.clone();
            let consequence_barrier = Arc::clone(&barrier);
            let consequence = std::thread::spawn(move || {
                consequence_barrier.wait();
                revoked_rx.recv().unwrap();
                consequence_repository.execute_authenticated(invocation, evaluated_at)
            });
            barrier.wait();
            gate.execute_batch("COMMIT").unwrap();
            revocation.join().unwrap();
            assert_eq!(
                consequence.join().unwrap(),
                Err(AuthorityError::DelegationRevoked)
            );
            let after = revoke_first.authority_state();
            assert_eq!(after.head_sequence, authority_before.head_sequence + 2);
            assert_eq!(
                after.authority_records,
                authority_before.authority_records + 2
            );
            assert_eq!(after.decisions, authority_before.decisions + 1);
            assert_eq!(after.consumptions, authority_before.consumptions + 1);
            assert_eq!(
                after.command_presentations,
                authority_before.command_presentations + 1
            );
            assert_eq!(after.actor_evidence, authority_before.actor_evidence + 1);
            assert_eq!(
                after.localized_consequences,
                authority_before.localized_consequences
            );
            assert_eq!(revoke_first.application_snapshot(), application_before);
            assert_eq!(revoke_first.count("localized_changesets"), 0);
            assert_eq!(
                revoke_first.count("authenticated_application_idempotency_v1"),
                ledger_before
            );

            let mut consequence_first = LifecycleFixture::new();
            let input = changeset_create_input(&consequence_first, changeset_id, global_key);
            let replay_input = input.clone();
            let (invocation, evaluated_at) = consequence_first.next_invocation(
                AuthorityOperation::ChangesetCreateV2,
                input,
                Some(global_key),
            );
            let authority_before = consequence_first.authority_state();
            let application_before = consequence_first.application_snapshot();
            let ledger_before = consequence_first.count("authenticated_application_idempotency_v1");
            let gate = consequence_first.repository.open_database().unwrap();
            gate.execute_batch("BEGIN IMMEDIATE").unwrap();
            let barrier = Arc::new(Barrier::new(3));
            let (committed_tx, committed_rx) = mpsc::sync_channel(0);
            let consequence_repository = consequence_first.repository.clone();
            let consequence_barrier = Arc::clone(&barrier);
            let consequence = std::thread::spawn(move || {
                consequence_barrier.wait();
                let result = consequence_repository.execute_authenticated(invocation, evaluated_at);
                committed_tx.send(()).unwrap();
                result
            });
            let revocation_repository = consequence_first.repository.clone();
            let workspace_id = consequence_first.workspace_id;
            let human_principal_id = consequence_first.human_principal_id;
            let delegation_id = consequence_first.delegation_id;
            let revocation_barrier = Arc::clone(&barrier);
            let revocation = std::thread::spawn(move || {
                revocation_barrier.wait();
                committed_rx.recv().unwrap();
                revoke_delegation(
                    &revocation_repository,
                    workspace_id,
                    human_principal_id,
                    delegation_id,
                    lifecycle_id(0x6d1).parse().unwrap(),
                    add_seconds(BASE_TIME.parse().unwrap(), 130),
                )
            });
            barrier.wait();
            gate.execute_batch("COMMIT").unwrap();
            let execution = consequence.join().unwrap().unwrap();
            execution.validate().unwrap();
            assert!(matches!(
                execution.result,
                AuthenticatedOperationResultV1::LocalizedSuccess(
                    LocalizedOperationSuccessV1::ChangeSetCreated(_)
                )
            ));
            revocation.join().unwrap().unwrap();
            let after = consequence_first.authority_state();
            assert_eq!(after.head_sequence, authority_before.head_sequence + 2);
            assert_eq!(
                after.authority_records,
                authority_before.authority_records + 2
            );
            assert_eq!(after.decisions, authority_before.decisions + 1);
            assert_eq!(after.consumptions, authority_before.consumptions + 1);
            assert_eq!(
                after.command_presentations,
                authority_before.command_presentations + 1
            );
            assert_eq!(after.actor_evidence, authority_before.actor_evidence + 1);
            assert_eq!(
                after.localized_consequences,
                authority_before.localized_consequences + 1
            );
            let application_after_consequence = consequence_first.application_snapshot();
            assert_ne!(application_after_consequence, application_before);
            assert_eq!(consequence_first.count("localized_changesets"), 1);
            assert_eq!(
                consequence_first.count("authenticated_application_idempotency_v1"),
                ledger_before + 1
            );

            let authority_before_denial = consequence_first.authority_state();
            let (fresh, evaluated_at) = consequence_first.next_invocation(
                AuthorityOperation::ChangesetCreateV2,
                replay_input,
                Some(global_key),
            );
            assert_eq!(
                consequence_first
                    .repository
                    .execute_authenticated(fresh, evaluated_at),
                Err(AuthorityError::DelegationRevoked)
            );
            let after_denial = consequence_first.authority_state();
            assert_eq!(
                after_denial.head_sequence,
                authority_before_denial.head_sequence + 1
            );
            assert_eq!(
                after_denial.decisions,
                authority_before_denial.decisions + 1
            );
            assert_eq!(
                after_denial.command_presentations,
                authority_before_denial.command_presentations + 1
            );
            assert_eq!(
                after_denial.localized_consequences,
                authority_before_denial.localized_consequences
            );
            assert_eq!(
                consequence_first.application_snapshot(),
                application_after_consequence
            );
            assert_eq!(consequence_first.count("localized_changesets"), 1);
            assert_eq!(
                consequence_first.count("authenticated_application_idempotency_v1"),
                ledger_before + 1
            );
        }

        #[test]
        fn current_binding_revocation_withholds_result_without_application_writes() {
            let mut fixture = LifecycleFixture::new();
            let global_key = key(0x43);
            let mut input = context_input(&fixture);
            input.insert(
                "idempotency_key".to_owned(),
                Value::String(global_key.to_string()),
            );
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                input.clone(),
                Some(global_key),
            );
            let head = fixture
                .repository
                .authority_head(fixture.workspace_id)
                .unwrap()
                .unwrap();
            fixture
                .repository
                .revoke_principal_binding(PrincipalBindingRevocationV1 {
                    api_version: PrincipalBindingRevocationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: head.record_digest,
                    workspace_id: fixture.workspace_id,
                    revocation_id: lifecycle_id(0x6e0).parse().unwrap(),
                    binding_id: fixture.agent.binding_id,
                    revoked_by_principal_id: fixture.human_principal_id,
                    revoked_at: fixture.time(130),
                    reason: PrincipalBindingRevocationReason::Disablement,
                })
                .unwrap();
            let authority = fixture.authority_state();
            let application = fixture.application_snapshot();
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            let (fresh, evaluated_at) = fixture.next_invocation(
                AuthorityOperation::ContextBuildV2,
                input,
                Some(global_key),
            );
            assert_eq!(
                fixture
                    .repository
                    .execute_authenticated(fresh, evaluated_at),
                Err(AuthorityError::AuthBindingInactive)
            );
            let after = fixture.authority_state();
            assert_eq!(after.head_sequence, authority.head_sequence + 1);
            assert_eq!(after.authority_records, authority.authority_records + 1);
            assert_eq!(after.decisions, authority.decisions + 1);
            assert_eq!(after.consumptions, authority.consumptions + 1);
            assert_eq!(
                after.command_presentations,
                authority.command_presentations + 1
            );
            assert_eq!(after.actor_evidence, authority.actor_evidence + 1);
            assert_eq!(
                after.localized_consequences,
                authority.localized_consequences
            );
            assert_eq!(fixture.application_snapshot(), application);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        fn context_input(fixture: &LifecycleFixture) -> Map<String, Value> {
            object(&json!({
                "api_version": "proof.dev/operation/context.build/v2",
                "context_pack_id": fixture.context.context_pack_id.to_string(),
                "created_at": fixture.context.created_at.to_string(),
                "expires_at": fixture.context.expires_at.to_string(),
                "idempotency_key": lifecycle_id(0x610),
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
            }))
        }

        fn changeset_create_input(
            fixture: &LifecycleFixture,
            changeset_id: ChangeSetId,
            idempotency_key: IdempotencyKey,
        ) -> Map<String, Value> {
            object(&json!({
                "api_version": "proof.dev/operation/changeset.create/v2",
                "changeset_id": changeset_id.to_string(),
                "context_pack_digest": fixture.context.context_pack_digest.to_string(),
                "context_pack_id": fixture.context.context_pack_id.to_string(),
                "created_at": fixture.time(40).to_string(),
                "idempotency_key": idempotency_key.to_string(),
                "intent": "Create one localized rendition",
                "resource_intent_digest": fixture.intent.intent_digest.to_string(),
                "resource_intent_id": fixture.intent.intent_id.to_string()
            }))
        }

        fn context_replay_input(
            intent: &ContentResourceIntent,
            context: &LocalizedContextPack,
            idempotency_key: IdempotencyKey,
        ) -> Map<String, Value> {
            object(&json!({
                "api_version": "proof.dev/operation/context.build/v2",
                "context_pack_id": context.context_pack_id.to_string(),
                "created_at": context.created_at.to_string(),
                "expires_at": context.expires_at.to_string(),
                "idempotency_key": idempotency_key.to_string(),
                "limits": {
                    "max_bytes": context.limits.max_bytes,
                    "max_edits": context.limits.max_edits,
                    "max_objects": context.limits.max_objects,
                    "max_validation_attempts": context.limits.max_validation_attempts
                },
                "policy_rules": [
                    {
                        "disallowed_values": ["Verboten"],
                        "locale": "de-DE",
                        "pointer": "/legal"
                    },
                    {
                        "disallowed_values": ["Interdit"],
                        "locale": LOCALE,
                        "pointer": "/legal"
                    }
                ],
                "resource_intent_digest": intent.intent_digest.to_string(),
                "resource_intent_id": intent.intent_id.to_string()
            }))
        }

        fn advance_localized_target(fixture: &LifecycleFixture) {
            let changeset_id = lifecycle_id(0x6c0).parse().unwrap();
            fixture
                .repository
                .create_localized_changeset(CreateLocalizedChangeSetCommand {
                    changeset_id,
                    intent: ChangeSetIntent::new("Advance the localized target base").unwrap(),
                    resource_intent_id: fixture.intent.intent_id,
                    resource_intent_digest: fixture.intent.intent_digest,
                    context_pack_id: fixture.context.context_pack_id,
                    context_pack_digest: fixture.context.context_pack_digest,
                    idempotency_key: key(0x6c1),
                    created_at: fixture.time(50),
                })
                .unwrap();
            let object_id = OBJECT_ID.parse().unwrap();
            let schema_id = SchemaId::new(SCHEMA_ID).unwrap();
            let schema_version = SchemaVersion::new(1).unwrap();
            let content = json!({
                "legal": "Les conditions standard s’appliquent",
                "slug": "summer-campaign",
                "title": "Campagne d’été"
            });
            let canonical = canonicalize(&content).unwrap();
            fixture
                .repository
                .add_localized_edits(AddLocalizedEditsCommand {
                    changeset_id,
                    edits: vec![proof_application::LocalizedEditAttempt::LocalePut(
                        ObjectLocalePutInput {
                            object_id,
                            locale: LOCALE.parse().unwrap(),
                            expected_source: ExpectedLocalizedSource {
                                revision: ObjectRevision::new(1).unwrap(),
                                digest: fixture.source_digest,
                                schema_id,
                                schema_version,
                            },
                            expected_target: None,
                            canonical_content: canonical.as_str().to_owned(),
                            supersedes_edit_id: None,
                            repair_of_validation_result_digest: None,
                        },
                    )],
                    assigned_edit_ids: vec![lifecycle_id(0x6c3).parse().unwrap()],
                    idempotency_key: key(0x6c4),
                })
                .unwrap();
            assert!(
                fixture
                    .repository
                    .validate_localized_changeset(changeset_id)
                    .unwrap()
                    .valid
            );
            fixture
                .repository
                .submit_localized_changeset(changeset_id, fixture.time(52))
                .unwrap();
            fixture
                .repository
                .approve_localized_changeset(
                    changeset_id,
                    ApprovalName::new("editorial").unwrap(),
                    fixture.time(54),
                )
                .unwrap();
            fixture
                .repository
                .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                    changeset_id,
                    idempotency_key: key(0x6c5),
                    committed_at: fixture.time(56),
                })
                .unwrap();
        }

        fn issue_grant(
            fixture: &LifecycleFixture,
            id: u64,
            scope: GrantScope,
        ) -> proof_application::DelegationId {
            let head = fixture
                .repository
                .authority_head(fixture.workspace_id)
                .unwrap()
                .unwrap();
            let delegation_id = lifecycle_id(id).parse().unwrap();
            fixture
                .repository
                .issue_delegation(DelegationV2 {
                    api_version: DelegationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: Some(head.record_digest),
                    delegation_id,
                    workspace_id: fixture.workspace_id,
                    delegation_profile: DirectAuthorityProfileV1::Direct,
                    issuer_principal_id: fixture.human_principal_id,
                    recipient_principal_id: scope.recipient,
                    actions: DelegationActionsV2::new(scope.actions).unwrap(),
                    scope: DelegationScopeV2 {
                        environment_ids: DelegationEnvironmentIdsV2::new(scope.environments)
                            .unwrap(),
                        object_ids: DelegationObjectIdsV2::new(scope.objects).unwrap(),
                        schema_ids: DelegationSchemaIdsV2::new(scope.schemas).unwrap(),
                        locales: DelegationLocalesV2::new(scope.locales).unwrap(),
                    },
                    constraints: DelegationConstraintsV2 {
                        max_objects: MaxObjects::new(scope.max_objects).unwrap(),
                        max_context_bytes: MaxContextBytes::new(scope.max_context_bytes).unwrap(),
                        max_edits_per_changeset: MaxEditsPerChangeSet::new(scope.max_edits)
                            .unwrap(),
                        allow_subdelegation: SubdelegationDisabled,
                    },
                    not_before: scope.not_before,
                    expires_at: scope.expires_at,
                    issued_at: fixture.time(23),
                })
                .unwrap();
            delegation_id
        }

        fn revoke_delegation(
            repository: &LocalWorkspace,
            workspace_id: WorkspaceId,
            human_principal_id: PrincipalId,
            delegation_id: proof_application::DelegationId,
            revocation_id: proof_application::RevocationId,
            revoked_at: Timestamp,
        ) -> Result<(), AuthorityError> {
            let head = repository.authority_head(workspace_id)?.ok_or_else(|| {
                AuthorityError::AuthorityIntegrity("authority head is absent".to_owned())
            })?;
            repository
                .revoke_delegation(DelegationRevocationV1 {
                    api_version: DelegationRevocationApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1)
                        .map_err(|error| AuthorityError::AuthorityIntegrity(error.to_string()))?,
                    previous_authority_record_digest: head.record_digest,
                    workspace_id,
                    revocation_id,
                    delegation_id,
                    revoked_by_principal_id: human_principal_id,
                    revoked_at,
                    reason: DelegationRevocationReasonV1::IssuerRequest,
                })
                .map(|_| ())
        }

        fn assert_pre_authority_failure(
            fixture: &LifecycleFixture,
            invocation: AuthenticatedInvocationV1,
            evaluated_at: Timestamp,
            expected: AuthorityError,
        ) {
            let authority = fixture.authority_state();
            let application = fixture.application_snapshot();
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            assert_eq!(
                fixture
                    .repository
                    .execute_authenticated(invocation, evaluated_at),
                Err(expected)
            );
            assert_eq!(fixture.authority_state(), authority);
            assert_eq!(fixture.application_snapshot(), application);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger
            );
        }

        fn execute_allow_failure(
            fixture: &mut LifecycleFixture,
            operation: AuthorityOperation,
            input: Map<String, Value>,
            idempotency_key: Option<IdempotencyKey>,
        ) -> AuthenticatedExecutionV1 {
            let authority = fixture.authority_state();
            let (invocation, evaluated_at) =
                fixture.next_invocation(operation, input, idempotency_key);
            let execution = fixture
                .repository
                .execute_authenticated(invocation, evaluated_at)
                .unwrap();
            execution.validate().unwrap();
            assert_eq!(
                execution.decision.decision,
                AuthorizationDecisionOutcome::Allow
            );
            assert!(matches!(
                execution.result,
                AuthenticatedOperationResultV1::LocalizedFailure(_)
            ));
            fixture.assert_one_authority_effect(&authority);
            execution
        }

        fn assert_key_reuse_denial(
            fixture: &mut LifecycleFixture,
            operation: AuthorityOperation,
            input: Map<String, Value>,
            idempotency_key: IdempotencyKey,
            label: &str,
        ) {
            let authority = fixture.authority_state();
            let application = fixture.application_snapshot();
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            let (invocation, evaluated_at) =
                fixture.next_invocation(operation, input, Some(idempotency_key));
            assert_eq!(
                fixture
                    .repository
                    .execute_authenticated(invocation, evaluated_at),
                Err(AuthorityError::IdempotencyKeyReused),
                "wrong result for {label}"
            );
            let after = fixture.authority_state();
            assert_eq!(after.head_sequence, authority.head_sequence + 1, "{label}");
            assert_eq!(after.decisions, authority.decisions + 1, "{label}");
            assert_eq!(after.consumptions, authority.consumptions + 1, "{label}");
            assert_eq!(
                after.command_presentations,
                authority.command_presentations + 1,
                "{label}"
            );
            assert_eq!(
                after.actor_evidence,
                authority.actor_evidence + 1,
                "{label}"
            );
            assert_eq!(
                after.localized_consequences, authority.localized_consequences,
                "{label}"
            );
            assert_eq!(fixture.application_snapshot(), application, "{label}");
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger,
                "{label}"
            );
        }

        fn assert_authorization_denial(
            fixture: &mut LifecycleFixture,
            input: Map<String, Value>,
            expected_error: AuthorityError,
            expected_reason: AuthorizationDenialReason,
            label: &str,
        ) {
            let authority = fixture.authority_state();
            let application = fixture.application_snapshot();
            let ledger = fixture.count("authenticated_application_idempotency_v1");
            let presentation = fixture.next_presentation;
            let (invocation, evaluated_at) = fixture.next_invocation(
                AuthorityOperation::ContextBuildV2,
                input,
                Some(key(0x610)),
            );
            assert_eq!(
                fixture
                    .repository
                    .execute_authenticated(invocation, evaluated_at),
                Err(expected_error),
                "wrong denial for {label}"
            );
            let after = fixture.authority_state();
            assert_eq!(after.head_sequence, authority.head_sequence + 1, "{label}");
            assert_eq!(
                after.authority_records,
                authority.authority_records + 1,
                "{label}"
            );
            assert_eq!(after.decisions, authority.decisions + 1, "{label}");
            assert_eq!(after.consumptions, authority.consumptions + 1, "{label}");
            assert_eq!(
                after.command_presentations,
                authority.command_presentations + 1,
                "{label}"
            );
            assert_eq!(
                after.actor_evidence,
                authority.actor_evidence + 1,
                "{label}"
            );
            assert_eq!(
                after.localized_consequences, authority.localized_consequences,
                "{label}"
            );
            assert_eq!(fixture.application_snapshot(), application, "{label}");
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger,
                "{label}"
            );
            let reason: String = fixture
                .repository
                .open_database()
                .unwrap()
                .query_row(
                    "SELECT reason_code FROM authorization_decisions_v2 WHERE presentation_id = ?1",
                    [lifecycle_id(presentation)],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(reason, expected_reason_code(expected_reason), "{label}");
        }

        fn expected_reason_code(reason: AuthorizationDenialReason) -> &'static str {
            match reason {
                AuthorizationDenialReason::BudgetExceeded => "proof.authorization.budget_exceeded",
                AuthorizationDenialReason::DelegationExpired => {
                    "proof.authorization.delegation_expired"
                }
                AuthorizationDenialReason::DelegationRevoked => {
                    "proof.authorization.delegation_revoked"
                }
                AuthorizationDenialReason::DelegationUnavailable => {
                    "proof.authorization.delegation_unavailable"
                }
                AuthorizationDenialReason::ScopeExceeded => "proof.authorization.scope_exceeded",
                _ => panic!("unexpected matrix denial reason"),
            }
        }
    }
}
