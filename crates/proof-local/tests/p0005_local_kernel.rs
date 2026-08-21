mod retained {
    include!("p0005_delegated_lifecycle.rs");

    mod local_kernel {
        use super::*;

        #[test]
        fn human_application_key_collision_is_a_signed_deny_without_application_effect() {
            let mut fixture = LifecycleFixture::new();
            let reused_key = key(0x29);
            let input = context_input(&fixture, reused_key);
            let authority_before = fixture.authority_state();
            let application_before = fixture.application_snapshot();
            let ledger_before = fixture.count("authenticated_application_idempotency_v1");
            let presentation = fixture.next_presentation;
            let (invocation, evaluated_at) = fixture.next_invocation(
                AuthorityOperation::ContextBuildV2,
                input,
                Some(reused_key),
            );

            assert_eq!(
                fixture
                    .repository
                    .execute_authenticated(invocation, evaluated_at),
                Err(AuthorityError::IdempotencyKeyReused)
            );
            let authority_after = fixture.authority_state();
            assert_eq!(
                authority_after.head_sequence,
                authority_before.head_sequence + 1
            );
            assert_eq!(authority_after.decisions, authority_before.decisions + 1);
            assert_eq!(
                authority_after.consumptions,
                authority_before.consumptions + 1
            );
            assert_eq!(
                authority_after.actor_evidence,
                authority_before.actor_evidence + 1
            );
            assert_eq!(
                authority_after.localized_consequences,
                authority_before.localized_consequences
            );
            assert_eq!(fixture.application_snapshot(), application_before);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before
            );
            let decision: (String, String) = fixture
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
                decision,
                ("deny".to_owned(), "proof.idempotency.key_reused".to_owned())
            );
        }

        #[test]
        fn unapproved_commit_failure_does_not_own_its_key_and_human_approval_unblocks_retry() {
            use proof_application::authority::LocalizedOperationFailureKindV1;

            let mut fixture = LifecycleFixture::new();
            let changeset_id = prepare_submitted_changeset(&mut fixture, 0x760);
            let commit_key = key(0x769);
            let commit_input = object(&json!({
                "api_version": "proof.dev/operation/changeset.commit/v2",
                "changeset_id": changeset_id.to_string(),
                "committed_at": fixture.time(80).to_string(),
                "idempotency_key": commit_key.to_string()
            }));
            let ledger_before = fixture.count("authenticated_application_idempotency_v1");
            let failure = execute_localized_failure(
                &mut fixture,
                AuthorityOperation::ChangesetCommitV2,
                commit_input.clone(),
                Some(commit_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(failure) = failure.result else {
                panic!("unapproved commit did not return a localized failure")
            };
            assert_eq!(failure.kind, LocalizedOperationFailureKindV1::NotApproved);
            assert_eq!(fixture.count("localized_commits"), 0);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before
            );

            fixture
                .repository
                .approve_localized_changeset(
                    changeset_id,
                    ApprovalName::new("editorial").unwrap(),
                    fixture.time(70),
                )
                .unwrap();
            let committed = fixture.execute_once(
                AuthorityOperation::ChangesetCommitV2,
                commit_input,
                Some(commit_key),
            );
            assert!(matches!(
                localized_success(&committed),
                LocalizedOperationSuccessV1::ChangeSetCommitted(_)
            ));
            assert_eq!(fixture.count("localized_commits"), 1);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before + 1
            );
        }

        #[test]
        fn exact_context_replay_is_withheld_after_its_selected_target_head_changes() {
            use proof_application::authority::LocalizedOperationFailureKindV1;

            let mut fixture = LifecycleFixture::new();
            let context_input = context_input(&fixture, key(0x43));
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                context_input.clone(),
                Some(key(0x43)),
            );
            let changeset_id = prepare_submitted_changeset(&mut fixture, 0x76a);
            fixture
                .repository
                .approve_localized_changeset(
                    changeset_id,
                    ApprovalName::new("editorial").unwrap(),
                    fixture.time(70),
                )
                .unwrap();
            fixture
                .repository
                .commit_localized_changeset(proof_application::CommitLocalizedChangeSetCommand {
                    changeset_id,
                    idempotency_key: key(0x76f),
                    committed_at: fixture.time(80),
                })
                .unwrap();
            let failure = execute_localized_failure(
                &mut fixture,
                AuthorityOperation::ContextBuildV2,
                context_input,
                Some(key(0x43)),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(failure) = failure.result else {
                panic!("stale Context replay did not return a localized failure")
            };
            assert_eq!(failure.kind, LocalizedOperationFailureKindV1::PolicyDenied);
        }

        #[test]
        fn late_second_edit_failure_rolls_back_the_entire_authenticated_add_batch() {
            use proof_application::authority::LocalizedOperationFailureKindV1;

            let mut fixture = LifecycleFixture::new();
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                context_input(&fixture, key(0x43)),
                Some(key(0x43)),
            );
            let changeset_id = lifecycle_id(0x770);
            let create_key = key(0x771);
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                object(&json!({
                    "api_version": "proof.dev/operation/changeset.create/v2",
                    "changeset_id": changeset_id,
                    "context_pack_digest": fixture.context.context_pack_digest.to_string(),
                    "context_pack_id": fixture.context.context_pack_id.to_string(),
                    "created_at": fixture.time(40).to_string(),
                    "idempotency_key": create_key.to_string(),
                    "intent": "Rollback a partially applied authenticated Add",
                    "resource_intent_digest": fixture.intent.intent_digest.to_string(),
                    "resource_intent_id": fixture.intent.intent_id.to_string()
                })),
                Some(create_key),
            );
            let add_key = key(0x772);
            let valid_content = json!({
                "legal": "Les conditions standard s’appliquent",
                "slug": "summer-campaign",
                "title": "Campagne d’été"
            });
            let source_digest = fixture.source_digest.to_string();
            let add_input = object(&json!({
                "api_version": "proof.dev/operation/changeset.add/v2",
                "changeset_id": changeset_id,
                    "edits": [
                        {
                            "api_version": "proof.dev/edit/v2",
                            "content": valid_content,
                        "expected_source": {
                            "digest": source_digest,
                            "revision": 1,
                            "schema_id": SCHEMA_ID,
                            "schema_version": 1
                        },
                        "expected_target": null,
                        "kind": "object.locale.put",
                        "locale": LOCALE,
                        "object_id": OBJECT_ID,
                        "repair_of_validation_result_digest": null,
                        "supersedes_edit_id": null
                        },
                        {
                            "api_version": "proof.dev/edit/v2",
                            "content": valid_content,
                        "expected_source": {
                            "digest": source_digest,
                            "revision": 1,
                            "schema_id": SCHEMA_ID,
                            "schema_version": 1
                        },
                        "expected_target": null,
                        "kind": "object.locale.put",
                        "locale": LOCALE,
                        "object_id": lifecycle_id(0x21),
                        "repair_of_validation_result_digest": null,
                        "supersedes_edit_id": null
                    }
                ],
                "idempotency_key": add_key.to_string()
            }));
            let failure = execute_localized_failure(
                &mut fixture,
                AuthorityOperation::ChangesetAddV2,
                add_input,
                Some(add_key),
            );
            let AuthenticatedOperationResultV1::LocalizedFailure(failure) = failure.result else {
                panic!("late invalid Edit did not return a localized failure")
            };
            assert_eq!(
                failure.kind,
                LocalizedOperationFailureKindV1::IntentMismatch
            );
            assert_eq!(fixture.count("localized_edits"), 0);
            assert_eq!(fixture.count("localized_add_operations"), 0);
        }

        #[derive(Clone, Copy, Debug)]
        enum ProjectionTamper {
            ConsequenceDelete,
            ConsequenceSubstitute,
            ConsequenceSwap,
            LedgerDelete,
            LedgerSubstitute,
            LedgerSwap,
            ContextSubstitute,
            ApplicationEffectSubstitute,
        }

        #[test]
        fn public_authority_verifier_rejects_localized_projection_tampering_without_reads_writing()
        {
            for tamper in [
                ProjectionTamper::ConsequenceDelete,
                ProjectionTamper::ConsequenceSubstitute,
                ProjectionTamper::ConsequenceSwap,
                ProjectionTamper::LedgerDelete,
                ProjectionTamper::LedgerSubstitute,
                ProjectionTamper::LedgerSwap,
                ProjectionTamper::ContextSubstitute,
                ProjectionTamper::ApplicationEffectSubstitute,
            ] {
                let mut fixture = LifecycleFixture::new();
                seed_two_localized_allows(&mut fixture);
                apply_projection_tamper(&fixture, tamper);
                let tampered = database_snapshot(&fixture.repository.open_database().unwrap());

                assert!(
                    matches!(
                        fixture.repository.authority_head(fixture.workspace_id),
                        Err(AuthorityError::AuthorityIntegrity(_))
                    ),
                    "public verification accepted {tamper:?}"
                );
                assert_eq!(
                    database_snapshot(&fixture.repository.open_database().unwrap()),
                    tampered,
                    "public verification wrote while rejecting {tamper:?}"
                );
            }
        }

        fn seed_two_localized_allows(fixture: &mut LifecycleFixture) {
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                context_input(fixture, key(0x43)),
                Some(key(0x43)),
            );
            let changeset_id = lifecycle_id(0x750);
            let create_key = key(0x751);
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                object(&json!({
                    "api_version": "proof.dev/operation/changeset.create/v2",
                    "changeset_id": changeset_id,
                    "context_pack_digest": fixture.context.context_pack_digest.to_string(),
                    "context_pack_id": fixture.context.context_pack_id.to_string(),
                    "created_at": fixture.time(40).to_string(),
                    "idempotency_key": create_key.to_string(),
                    "intent": "Seed a second signed localized consequence",
                    "resource_intent_digest": fixture.intent.intent_digest.to_string(),
                    "resource_intent_id": fixture.intent.intent_id.to_string()
                })),
                Some(create_key),
            );
        }

        fn prepare_submitted_changeset(
            fixture: &mut LifecycleFixture,
            id_base: u64,
        ) -> proof_application::ChangeSetId {
            fixture.execute_once(
                AuthorityOperation::ContextBuildV2,
                context_input(fixture, key(0x43)),
                Some(key(0x43)),
            );
            let changeset_id = lifecycle_id(id_base)
                .parse::<proof_application::ChangeSetId>()
                .unwrap();
            let create_key = key(id_base + 1);
            fixture.execute_once(
                AuthorityOperation::ChangesetCreateV2,
                object(&json!({
                    "api_version": "proof.dev/operation/changeset.create/v2",
                    "changeset_id": changeset_id.to_string(),
                    "context_pack_digest": fixture.context.context_pack_digest.to_string(),
                    "context_pack_id": fixture.context.context_pack_id.to_string(),
                    "created_at": fixture.time(40).to_string(),
                    "idempotency_key": create_key.to_string(),
                    "intent": "Prepare an unapproved delegated commit",
                    "resource_intent_digest": fixture.intent.intent_digest.to_string(),
                    "resource_intent_id": fixture.intent.intent_id.to_string()
                })),
                Some(create_key),
            );
            let add_key = key(id_base + 2);
            let add_input = fixture.add_input(
                changeset_id,
                id_base + 2,
                "Les conditions standard s’appliquent",
                None,
                None,
            );
            fixture.execute_once(AuthorityOperation::ChangesetAddV2, add_input, Some(add_key));
            let selector = object(&json!({
                "api_version": "proof.dev/operation/changeset.validate/v2",
                "changeset_id": changeset_id.to_string()
            }));
            let validation =
                fixture.execute_once(AuthorityOperation::ChangesetValidateV2, selector, None);
            let LocalizedOperationSuccessV1::ChangeSetValidated(validation) =
                localized_success(&validation)
            else {
                panic!("submitted fixture validation returned the wrong result")
            };
            assert!(validation.valid);
            fixture.execute_once(
                AuthorityOperation::ChangesetSubmitV2,
                object(&json!({
                    "api_version": "proof.dev/operation/changeset.submit/v2",
                    "changeset_id": changeset_id.to_string(),
                    "submitted_at": fixture.time(60).to_string()
                })),
                None,
            );
            changeset_id
        }

        fn execute_localized_failure(
            fixture: &mut LifecycleFixture,
            operation: AuthorityOperation,
            input: Map<String, Value>,
            idempotency_key: Option<IdempotencyKey>,
        ) -> AuthenticatedExecutionV1 {
            let authority_before = fixture.authority_state();
            let application_before = fixture.application_snapshot();
            let ledger_before = fixture.count("authenticated_application_idempotency_v1");
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
            let authority_after = fixture.authority_state();
            assert_eq!(
                authority_after.head_sequence,
                authority_before.head_sequence + 1
            );
            assert_eq!(authority_after.decisions, authority_before.decisions + 1);
            assert_eq!(
                authority_after.localized_consequences,
                authority_before.localized_consequences + 1
            );
            assert_eq!(fixture.application_snapshot(), application_before);
            assert_eq!(
                fixture.count("authenticated_application_idempotency_v1"),
                ledger_before
            );
            execution
        }

        #[expect(
            clippy::too_many_lines,
            reason = "the retained table keeps every delete, substitute, and swap mutation explicit"
        )]
        fn apply_projection_tamper(fixture: &LifecycleFixture, tamper: ProjectionTamper) {
            let connection = fixture.repository.open_database().unwrap();
            connection
                .pragma_update(None, "foreign_keys", "OFF")
                .unwrap();
            match tamper {
                ProjectionTamper::ConsequenceDelete => {
                    connection
                        .execute(
                            "DELETE FROM authenticated_localized_consequences_v1
                             WHERE decision_authority_sequence = (
                                 SELECT MIN(decision_authority_sequence)
                                 FROM authenticated_localized_consequences_v1
                             )",
                            [],
                        )
                        .unwrap();
                }
                ProjectionTamper::ConsequenceSubstitute => {
                    connection
                        .execute(
                            "UPDATE authenticated_localized_consequences_v1
                             SET result_digest = ?1
                             WHERE decision_authority_sequence = (
                                 SELECT MIN(decision_authority_sequence)
                                 FROM authenticated_localized_consequences_v1
                             )",
                            [format!("blake3:{}", "f".repeat(64))],
                        )
                        .unwrap();
                }
                ProjectionTamper::ConsequenceSwap => {
                    let (first, second) = first_two_consequence_sequences(&connection);
                    connection
                        .execute(
                            "UPDATE authenticated_localized_consequences_v1
                             SET decision_authority_sequence = ?1
                             WHERE decision_authority_sequence = ?2",
                            (first + 100_000, first),
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE authenticated_localized_consequences_v1
                             SET decision_authority_sequence = ?1
                             WHERE decision_authority_sequence = ?2",
                            (first, second),
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE authenticated_localized_consequences_v1
                             SET decision_authority_sequence = ?1
                             WHERE decision_authority_sequence = ?2",
                            (second, first + 100_000),
                        )
                        .unwrap();
                }
                ProjectionTamper::LedgerDelete => {
                    connection
                        .execute(
                            "DELETE FROM authenticated_application_idempotency_v1
                             WHERE idempotency_key = (
                                 SELECT MIN(idempotency_key)
                                 FROM authenticated_application_idempotency_v1
                             )",
                            [],
                        )
                        .unwrap();
                }
                ProjectionTamper::LedgerSubstitute => {
                    connection
                        .execute(
                            "UPDATE authenticated_application_idempotency_v1
                             SET application_effect_digest = ?1
                             WHERE idempotency_key = (
                                 SELECT MIN(idempotency_key)
                                 FROM authenticated_application_idempotency_v1
                             )",
                            [format!("blake3:{}", "e".repeat(64))],
                        )
                        .unwrap();
                }
                ProjectionTamper::LedgerSwap => {
                    let (first, second) = first_two_ledger_keys(&connection);
                    let temporary = lifecycle_id(0x7ff);
                    connection
                        .execute(
                            "UPDATE authenticated_application_idempotency_v1
                             SET idempotency_key = ?1 WHERE idempotency_key = ?2",
                            (&temporary, &first),
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE authenticated_application_idempotency_v1
                             SET idempotency_key = ?1 WHERE idempotency_key = ?2",
                            (&first, &second),
                        )
                        .unwrap();
                    connection
                        .execute(
                            "UPDATE authenticated_application_idempotency_v1
                             SET idempotency_key = ?1 WHERE idempotency_key = ?2",
                            (&second, &temporary),
                        )
                        .unwrap();
                }
                ProjectionTamper::ContextSubstitute => {
                    connection
                        .execute(
                            "UPDATE localized_context_packs SET policy_digest = ?1",
                            [format!("blake3:{}", "d".repeat(64))],
                        )
                        .unwrap();
                }
                ProjectionTamper::ApplicationEffectSubstitute => {
                    connection
                        .execute(
                            "UPDATE localized_changesets SET effect_digest = ?1",
                            [format!("blake3:{}", "c".repeat(64))],
                        )
                        .unwrap();
                }
            }
        }

        fn first_two_consequence_sequences(connection: &Connection) -> (i64, i64) {
            let values = connection
                .prepare(
                    "SELECT decision_authority_sequence
                     FROM authenticated_localized_consequences_v1
                     ORDER BY decision_authority_sequence LIMIT 2",
                )
                .unwrap()
                .query_map([], |row| row.get::<_, i64>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>();
            (values[0], values[1])
        }

        fn first_two_ledger_keys(connection: &Connection) -> (String, String) {
            let values = connection
                .prepare(
                    "SELECT idempotency_key FROM authenticated_application_idempotency_v1
                     ORDER BY idempotency_key LIMIT 2",
                )
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>();
            (values[0].clone(), values[1].clone())
        }

        fn context_input(
            fixture: &LifecycleFixture,
            idempotency_key: IdempotencyKey,
        ) -> Map<String, Value> {
            object(&json!({
                "api_version": "proof.dev/operation/context.build/v2",
                "context_pack_id": fixture.context.context_pack_id.to_string(),
                "created_at": fixture.context.created_at.to_string(),
                "expires_at": fixture.context.expires_at.to_string(),
                "idempotency_key": idempotency_key.to_string(),
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
    }
}
