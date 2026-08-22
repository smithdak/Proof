# P-0006 C1-C24 traceability

## Binding and result

This matrix applies only to immutable candidate
`ea35e093daed50017684f7da53373cbb70af753a`. Its controlling complete gate is
`rtk cargo test --locked --workspace --all-targets --all-features`: 604 tests
passed across 36 suites with no failure. The commands below identify smaller
retained targets for criterion-level reproduction; their tests are included in
that exact-candidate aggregate.

Every C1-C24 row is supported for the bounded local Linux profile. This is an
Engineering result, not project-owner acceptance or a Milestone 2 completion
record.

## Command legend

| ID | Retained command |
| --- | --- |
| PV | `rtk cargo test --locked -p proof-verifier --test portable_matrix` |
| PS | `rtk cargo test --locked -p proof-verifier --test security_matrix` |
| PR | `rtk cargo test --locked -p proof-verifier --test finding_code_registry` |
| PC | `rtk cargo test --locked -p proof-verifier --test public_cli` |
| NS | `rtk cargo test --locked -p proof-cli --test p0006_north_star -- --nocapture` |
| CT | `rtk cargo test --locked -p proof-cli --test p0006_containment -- --nocapture` |
| TP | `rtk cargo test --locked -p proof-cli --test auth_transport_parity --test p0005_transport_parity` |
| ARCH | `rtk cargo test --locked -p proof-cli --test architecture` |
| A4 | `rtk cargo test --locked -p proof-local --test p0004_authority --test p0004_authority_continuity --test p0004_authority_falsification --test p0004_authority_matrix` |
| A5 | `rtk cargo test --locked -p proof-local --test p0005_delegated_lifecycle --test p0005_delegated_matrix --test p0005_local_kernel` |
| P7 | `rtk cargo test --locked -p proof-local --test initialize --test p0007_assurance_g6_g9 --test p0007_assurance_g10_g13` |
| CLI | `rtk cargo test --locked -p proof-cli --test cli` |

NS and CT require Linux namespace capability so their bubblewrap boundaries
execute. No test in this matrix is treated as skipped evidence.

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Accepted and rejected coverage | Result |
| --- | --- | --- | --- | --- |
| C1 | Every governed mutation belongs to exactly one ChangeSet. | NS; P7 `localized_human_path_repairs_and_releases_two_exact_locales`; PV `historical_policy_key_time_and_signed_v2_delta_tampering_are_invalid` | Exactly three localized Edits produce two authorized renditions while the source remains unchanged. The prohibited French claim first fails validation and requires a linked repair. Signed delta substitution and hitchhiking state are rejected. | Supported |
| C2 | A ChangeSet commits atomically or leaves no partial authoritative mutation. | P7 `mixed_schema_and_object_changeset_replays_and_commits_as_one_authoritative_unit`, `approved_changeset_commits_atomically_and_replays_the_original_result`, `commit_storage_failure_rolls_back_every_authoritative_write`; A5 `late_second_edit_failure_rolls_back_the_entire_authenticated_add_batch` | Mixed and localized batches commit together and replay exactly. Injected storage failure and late second-Edit failure roll back every authoritative write. | Supported |
| C3 | Intent and expected base state are explicit; stale work conflicts. | P7 `draft_changeset_is_bound_to_principal_intent_and_known_state`, `stale_requested_base_state_rejects_without_persisting_a_draft`; A5 `stale_known_state_withholds_a_previously_committed_result` | Draft and localized intent bind Principal, ContextPack, and base digest. A stale base creates no draft; stale current state withholds an old result without another effect. | Supported |
| C4 | Retry disclosure requires equivalent input, fresh authentication, and current authority; effects are not duplicated. | A4 `valid_status_consumes_once_and_replay_is_write_free`, `fresh_context_presentation_replays_exact_result_and_projection_tamper_fails_closed`, `current_authority_invalidation_withholds_prior_idempotent_context_result`; A5 `exact_replay_is_stable_but_stale_context_withholds_the_prior_result` | Fresh equivalent presentations disclose the retained result with one effect. Key/input mismatch, stale Context, Principal/Binding disablement, or revocation denies disclosure without duplicating governed state. | Supported |
| C5 | Consequential actions bind authenticated requesting and operating Principals. | NS; A5 `malformed_and_actor_mismatched_presentations_leave_zero_durable_writes`; PV `signed_actor_presentation_substitution_fails_the_command_cross_link` | The scenario binds Human, Agent, Binding, Delegation, command, decision, and consequence. Malformed/actor-mismatched input writes nothing; signed actor substitution fails the command cross-link. | Supported |
| C6 | Authority is evaluated at the action's causal position immediately before consequence. | A4 `causal_disablement_and_revocation_precede_record_timestamps_and_grant_time`, `current_authority_invalidation_withholds_prior_idempotent_context_result`; PV `causally_exact_checkpoint_accepts_an_earlier_observer_clock`, `causal_prefix_position_wins_over_status_and_revocation_clock_skew` | Valid causal state survives later revocation and observer-clock differences. Disablement or revocation effective before the action invalidates authority and blocks fresh or replay disclosure. | Supported |
| C7 | Delegation is direct, scoped, time- and budget-bounded, and non-expanding. | A5 `delegation_scope_budget_lifetime_recipient_and_revocation_denials_are_evidence_only`; A4 `chain_and_subdelegation_inputs_are_rejected_before_authority_state`; PV `signed_subdelegation_record_is_rejected_by_the_closed_authority_contract`, `wrong_delegation_issuer_and_recipient_are_rejected` | A matching direct Human-to-Agent grant succeeds. Scope, budget, time, recipient, issuer, revocation, chain, and subdelegation violations reject without an application consequence. | Supported |
| C8 | Agents use governed operations and cannot bypass administration, validation, approval, or Release policy. | NS; TP; A4 `agent_actor_cannot_administer_any_closed_authority_surface` | Application, CLI, and both MCP eras share the governed Agent workflow. Agent administration and approval/policy bypass are rejected. | Supported |
| C9 | Deterministic code decides authorization, validation, commit, Release, and verification. | PV `complete_report_bytes_and_digest_are_deterministic`, `generated_outcomes_match_frozen_conformance_hashes`, `generated_inputs_and_reports_match_canonical_wire_fixtures`; ARCH `inward_dependency_boundaries_are_enforced` | Repeated independent verification produces identical canonical reports and frozen digests. Canonical-byte, digest, signature, semantic, and dependency-boundary substitutions fail. | Supported |
| C10 | Validation binds the exact ChangeSet, base, policy, validator, and input. | P7 `validation_evidence_is_deterministic_and_seals_exact_edits`, `altered_validation_evidence_is_rejected_on_deterministic_replay`; PV `v1_edition_shape_and_independent_validation_are_enforced` | Exact inputs reproduce validation and state. Altered validation, invalid schema/object content, malformed Edition, and re-signed delta mismatch fail independently. | Supported |
| C11 | Expected failures expose stable machine-readable codes and repair data. | PR `public_finding_code_registry_matches_every_emitted_literal`; PC `public_cli_freezes_complete_incomplete_and_invalid_results`, `public_cli_freezes_usage_and_input_failures`; CLI structured Problem tests | Complete, Incomplete, Invalid, usage, input, and repair findings are frozen. Registry/source drift, stale overrides, and prose-only diagnostic changes fail conformance. | Supported |
| C12 | Editions are immutable and content-addressed; correction creates another Edition. | P7 `edition_is_content_addressed_immutable_and_replayed_for_the_same_state`, `edition_consumers_reject_output_metadata_tamper_without_effect_commitment_update`, `edition_key_reuse_rejects_a_later_known_state`; CLI Edition projection test | Identical state replays the same Edition. Metadata/effect tamper and key reuse for later state reject without rewriting an Edition. | Supported |
| C13 | Availability changes only through explicit Releases bound to Edition, Environment, authority, policy, time, and target. | NS; P7 `releases_queries_and_context_packs_preserve_immutable_history_and_exact_authority`; PV `release_entrypoint_splice_and_revoked_signer_are_invalid` | The scenario promotes an explicit v2 Release and verifies its closure. Entrypoint splice, revoked key, subject substitution, or missing policy evidence cannot yield Complete. | Supported |
| C14 | Rollback appends a Release and never rewrites prior Releases or Editions. | CLI `local_release_query_proof_rollback_and_projection_rebuild_form_one_verified_loop`; PV `complete_rollback_bundle_requires_an_unbroken_predecessor_chain`, `signed_release_kind_and_rollback_target_shape_tampering_is_invalid`, `duplicate_and_orphan_historical_proof_mappings_are_invalid` | A new rollback Release may select an exact ancestor Edition through intact history. Broken ancestry, cycles, target/kind mismatch, duplicate mappings, and orphan Proofs fail. | Supported |
| C15 | Proof claims bind immutable subjects and fail closed on invalid or unavailable required evidence. | PV include/withhold equivalence, supplied-artifact tamper, historical Proof substitution, and missing-historical-Proof tests | Exact signed statements, subjects, keys, and closure verify. Supplied tamper is Invalid; unavailable required evidence is Incomplete and never overclaimed. | Supported |
| C16 | Authoritative facts are append-only; snapshots and projections are derived. | A4 older-snapshot, signed-record mutation, and reordering tests; P7 `p0007_assurance_g10_authoritative_tamper_fails_closed_in_both_modes` | An older intact prefix has internal validity but no freshness claim. Signed mutation/reordering and authoritative tamper fail before repair or checkpoint comparison. | Supported |
| C17 | Known State is reproducible from authoritative facts and canonicalization. | P7 projection dry-run/repair/convergence and authoritative-tamper tests | Rebuild deterministically reconstructs Known State and converges. Authoritative tamper fails closed and is never rewritten as projection repair. | Supported |
| C18 | Timestamps are evidence; causal order comes from sequence, parent, and state identifiers. | PV causal-checkpoint, clock-skew, Release-key time, command-time nanosecond, and predecessor-time tests; P7 Release chronology tests | Signing-time validity and causal prefix decide historical validity; later revocation is non-retroactive. Invalid key time, command skew/lifetime, predecessor chronology, or causal state fails. | Supported |
| C19 | Application, CLI, and protocol adapters use one operation path; none is privileged. | NS; TP; ARCH; CT | Equivalent application, CLI, modern MCP, and legacy MCP calls return equal semantic projections. Distinct-UID path, argv, raw CLI, file, unknown-tool, and path-shaped MCP attacks reject before storage access. | Supported |
| C20 | Human-readable output is a projection of stable structured output. | NS `assert_text_receipt_projection`; CLI status projection; PC frozen report/CLI assertions | Evidence and status text are compared field-for-field with structured JSON. Text/JSON divergence or unstable diagnostics fail. | Supported |
| C21 | Protocol adapters remain replaceable and outside the domain core. | TP; ARCH `inward_dependency_boundaries_are_enforced` | CLI and both MCP eras execute the same application contract. Forbidden adapter/domain/storage/verifier dependency direction fails architecture checks. | Supported |
| C22 | Secrets, credentials, private keys, raw UIDs, and blinds never enter content or Proof payloads. | NS `assert_bundle_contains_no_private_material`; PS `withheld_bundle_excludes_private_keys_credentials_uid_and_blind`; PV withheld-bundle canaries | Public commitments and keys remain available. Every bundle path and byte stream is checked against raw UID, blind, credential, host path, and private-key encodings. | Supported |
| C23 | Untrusted content remains inert and cannot become command, path, policy, or executable input. | NS inert prompt content; CT broker-boundary attacks; PS symlink substitution | Prompt-like content survives only as rendition data. Agent-selected path/argv, unknown tools, path-shaped inputs, and artifact symlinks reject at typed/container boundaries. | Supported |
| C24 | Redaction retains commitments and chain integrity; unavailable evidence is explicit. | PV `independently_generated_complete_include_and_withhold_are_equivalent`, `external_root_restores_the_exact_committed_subject_opening`, `required_withheld_opening_and_missing_checkpoint_are_incomplete`, `included_opening_rejects_a_noncanonical_32_byte_blind_substitution` | Include and Withhold modes prove one commitment; a trusted external opening restores the exact preimage. Required withholding/checkpoint absence is Incomplete; a malformed supplied opening is Invalid. | Supported |

## Public error coverage

`conformance/v1/verifier-finding-codes.json` registers exactly 158 public
verifier codes: 156 structured report findings and two CLI diagnostics, all in
the `proof.verify.` namespace. Thirty codes are classified
`direct_behavioral`; every override names an existing retained test whose body
asserts that exact code. The remaining 128 codes use the conservative
`structural_guard` default.

`finding_code_registry::public_finding_code_registry_matches_every_emitted_literal`
proves exact set equality between the registry and emitted report/CLI literals,
rejects stale, duplicate, or nonexistent overrides, and requires one coverage
classification per code. It does not convert the 128 structural guards into a
claim of 128 independent branch-level tests.

## Boundary carried to owner review

C1-C24 support the disclosed local Linux profile. They do not establish a
globally latest same-Environment Release, hostile same-UID isolation, Windows
identity/runtime containment, a collaboration server, HTTP/PostgreSQL parity,
or any live remote, publication, deployment, or production claim. The full
residual list is bound in `receipt.md` and `manifest.json` and requires explicit
project-owner disposition.
