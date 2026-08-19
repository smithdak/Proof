# P-0007 Engineering traceability

## Decision boundary

This table maps the nine P-0007 acceptance criteria and Assurance rows G1-G14
to the exact candidate `fede487547c3e2bb27f5cb8fb168f5b5312a5f23`.
Engineering evidence is not an Assurance verdict. `partial` means the retained
candidate suite supplies supporting evidence but the independent adversarial
execution required by the gate has not occurred. `blocked` means the directive
prohibits the publication needed to obtain the required result.

## Acceptance criteria

| AC | Requirement | Candidate evidence | Engineering state |
| --- | --- | --- | --- |
| AC1 | Two-locale Human repair-to-Release scenario | `localized_human_path_repairs_and_releases_two_exact_locales`; `localized_cli_repairs_and_releases_two_exact_locales` | supported locally |
| AC2 | Human-authenticated immutable, idempotent, effect-bound intent and acyclic digest graph | `LocalizedContentRepository::issue_content_resource_intent`; the application scenario; operation-effect verification in `crates/proof-local/src/localized.rs` | partial; independent mutation run pending |
| AC3 | Deterministic create/replace and atomic stable denials | `localized_edit_denials_are_specific_and_atomic`; replacement phase of the application scenario | supported locally; independent falsification pending |
| AC4 | Immutable attempts, effective heads, complete approval/evidence lineage | application scenario and denial matrix; sealed validation/approval/commit reconstruction in `crates/proof-local/src/localized.rs` | partial; deletion/substitution mutation run pending |
| AC5 | Exact commit/Edition/Release causality | application scenario; `release_reads_reject_independent_approval_digest_tamper`; `release_verifier_enforces_predecessor_time_and_non_regressing_editions` | partial; localized pointer/delta mutation run pending |
| AC6 | Exact ContextPack and query closure without fallback/traversal | application scenario exact-locale and absent-locale assertions; `releases_queries_and_context_packs_preserve_immutable_history_and_exact_authority` | partial; independent disclosure matrix pending |
| AC7 | Atomic migration of every supported pre-v11 version with v1 reproduction | `every_pre_localization_version_migrates_without_changing_v1_evidence`; `version_eleven_migration_rolls_back_atomically_after_an_injected_failure` | supported locally; independent fixture hashing pending |
| AC8 | Exact first v1-to-v2 transition and closed compatibility matrix | application scenario assertions for KnownState v1/v2, v1/v2 rollback, and unsupported legacy operations | supported locally; independent reconstruction pending |
| AC9 | Canonical, migration, rebuild, replay, denial, and Linux gates | canonical localized tests; migration/rebuild/denial tests; exact-SHA Ubuntu run in `receipt.md` | partial; exact-SHA GitHub CI and Assurance remain pending |

## G1-G14 plan and retained evidence

| Gate | AC | Exact public entry point | Source | Retained test or command | Engineering result / Assurance action |
| --- | --- | --- | --- | --- | --- |
| G1 | AC9 | Repository Linux quality gate | `.github/workflows/ci.yml`; `rust-toolchain.toml` | Exact commands and 208-test result in `receipt.md` | local Ubuntu supported; GitHub exact-SHA CI blocked by no-push directive |
| G2 | AC9 | `object_locale_revision`; `known_state_v2_manifest`; `known_state_v2`; versioned Schemas | `crates/proof-canonical/src/lib.rs`; `conformance/v2/localized-content/` | `localized_artifact_golden_digests_are_stable`; public builder vector tests; `localized_conformance_schemas_and_golden_artifacts_are_closed` | positive vectors and selected mutations supported; Assurance must independently reconstruct and complete mutation corpus |
| G3 | AC2-AC5 | `get_content_resource_intent`; `get_localized_context`; `inspect_localized_changeset`; `query_released_renditions` | `crates/proof-application/src/localized.rs`; `crates/proof-local/src/localized.rs` | operation-effect integrity tests in `initialize.rs`; application scenario direct reads | partial; Assurance must tamper each localized authoritative family and prove unchanged state |
| G4 | AC5, AC8 | `verify_localized_release`; CLI `localized release-verify` | `crates/proof-local/src/localized.rs`; `crates/proof-cli/src/localized_cli.rs` | application/CLI scenarios; generic Release tamper, chronology, trust, and proof-repair tests | partial; Assurance must run localized wrong-bytes/ancestry/version matrix |
| G5 | AC6 | `build_localized_context`; `get_localized_context`; `query_released_renditions` | application trait and local adapter localized modules | application exact/absent locale assertions; immutable-history/exact-authority test | partial; Assurance independently derives closure and disclosure denials |
| G6 | AC1, AC2 | Complete `LocalizedContentRepository`; CLI `run_localized` | application trait, local adapter, and CLI localized modules | application and CLI two-locale repair-to-Release scenarios | supported locally; Assurance compares normalized envelopes and digest graph |
| G7 | AC3, AC4 | `add_localized_edits`; inspect/diff/validate methods | `crates/proof-local/src/localized.rs` | `localized_edit_denials_are_specific_and_atomic`; application repair lineage | retained atomic denial matrix supported; Assurance expands fork/cycle/budget mutations |
| G8 | AC5 | commit, Edition, promote, rollback methods | `crates/proof-local/src/localized.rs` | application replacement, stale Edition, moved pointer, rollback, and Release verification assertions | partial; Assurance independently reconstructs exact delta and pointer snapshots |
| G9 | AC7, AC8 | workspace initialization/migration and latest-schema preflight | `crates/proof-local/src/lib.rs`; localized migration in `localized.rs` | every-pre-localization-version migration; injected v11 rollback; application legacy/v2 matrix | supported locally; Assurance independently hashes fixtures and retries injected failures |
| G10 | AC9 | `rebuild_projections`; CLI `projection rebuild` | `crates/proof-local/src/lib.rs`; `crates/proof-local/src/localized.rs` | application localized corruption/dry-run/repair/no-drift assertions; authoritative-tamper rejection tests | supported locally; Assurance repeats with independent expected state |
| G11 | AC2, AC9 | consequential localized repository methods | `crates/proof-local/src/localized.rs` | exact replay in application rollback; operation-effect replay/tamper tests across shared local adapter | partial; Assurance executes per-operation identical and changed-input matrix |
| G12 | AC2 | Human identity preflight on every localized method | `require_human_principal` in `crates/proof-local/src/localized.rs` | Human application/CLI scenarios; local identity authentication denial tests; no Agent entry point exists | partial; Assurance invokes each mutation without Human identity and confirms Agent boundary absent |
| G13 | AC3, AC5, AC7, AC9 | commit, promote, rollback transaction/recovery boundaries | local adapter transaction and proof-export helpers | commit rollback; Release post-commit proof repair; migration rollback; rebuild recovery tests | partial; Assurance runs localized fault points and convergence snapshots |
| G14 | all | Git/work-control provenance | `scripts/check-work-items.mjs`; this evidence packet | `candidate-paths.sha256`; ancestry checks; normalized diff; credential-shape scan | local inventory supported; evidence-only diff and independent secret scan repeat after evidence commit |

## Scope reconciliation

The candidate adds only the ratified localized-content foundation, its Human
CLI, v11 storage/migration, conformance material, tests, quality workflow, and
work-control enforcement. No dependency changed. No Agent credential,
DelegationV2, MCP mutation surface, server, PostgreSQL, HTTP API, UI, model
provider, translation service, locale fallback, rendition deletion, or generic
variant behavior was added.

The strongest counterargument is that the 208-test exact-SHA run plus two
end-to-end scenarios should be sufficient. It is rejected for claim
reactivation: direct reads, verifiers, queries, rebuilds, and recovery paths can
share a faulty helper or trusted projection. Only the independent G1-G14 run
can close that residual uncertainty.
