# P-0007 Engineering traceability

## Decision boundary

This table maps every P-0007 acceptance criterion and Assurance row G1-G14 to
candidate `c4b312d6f493936e15c2cc658277953ea18777f7`. `supported by Engineering`
means the exact-candidate implementation and retained evidence passed; it is
not an Assurance verdict. Only `assurance-verdict.md` can transition the
bounded claim from `indeterminate` to `supported`.

## Acceptance criteria

| AC | Requirement | Exact-candidate evidence | Engineering state |
| --- | --- | --- | --- |
| AC1 | Two-locale Human repair-to-Release lifecycle | `localized_human_path_repairs_and_releases_two_exact_locales`; `localized_cli_repairs_and_releases_two_exact_locales` | supported by Engineering |
| AC2 | Human-authenticated immutable, idempotent, effect-bound intent and acyclic immutable closure | `localized_resource_intent_operations_are_unique_and_effect_bound`; `localized_context_build_operations_are_unique_and_effect_bound`; `localized_control_replays_survive_environment_pointer_movement` | supported by Engineering |
| AC3 | Deterministic create/replace and atomic stable denials | `localized_edit_denials_are_specific_and_atomic`; lifecycle replacement phase; G7 retained matrix | supported by Engineering |
| AC4 | Immutable attempts, effective heads, complete evidence lineage, and budgets | lifecycle scenario; G7 raw-lineage and separate-budget tests | supported by Engineering |
| AC5 | Exact commit/Edition/Release causality | lifecycle scenario; Release integrity/chronology tests; moved-pointer and pre-promotion denials | supported by Engineering |
| AC6 | Exact ContextPack/query closure without fallback or traversal | `localized_context_reads_reconstruct_policy_resources_and_metadata`; `releases_queries_and_context_packs_preserve_immutable_history_and_exact_authority`; exact/absent-locale lifecycle assertions | supported by Engineering |
| AC7 | Atomic v1-v10 migration to v11 without fabricated locale facts | G9 every-version injected-failure/rollback/retry matrix; existing v10/v11 fault cases | supported by Engineering |
| AC8 | Exact v1-to-v2 transition and closed compatibility matrix | lifecycle v1/v2 rollback/restore assertions; G9 legacy fingerprint equality | supported by Engineering |
| AC9 | Canonical, migration, rebuild, replay, denial, and Linux gates | exact local 345-test gate; GitHub run `32380862459`; focused G2-G14 retained cases | supported by Engineering; Assurance pending |

## G1-G14 mapping

| Gate | Ratified requirement and public surface | Source | Retained test or exact command | Engineering result / independent action |
| --- | --- | --- | --- | --- |
| G1 | Repository quality through `.github/workflows/ci.yml` | workflow, `rust-toolchain.toml`, repository scripts | pinned local gate and GitHub run `32380862459`, job `96463454459` | exact local and CI gates supported; evidence-only checks rerun before commit |
| G2 | Canonical builders, Schemas, vectors, and independent reconstruction | `crates/proof-canonical/src/lib.rs`; `conformance/v2/localized-content/` | canonical unit corpus; `localized_conformance_schemas_and_golden_artifacts_are_closed`; `localized_portable_artifacts_and_operation_instances_are_closed` | all artifact/operation fixtures, independent RFC 8785+BLAKE3 recomputation, and mutation rejection retained; Assurance independently recomputes |
| G3 | Integrity-equivalent direct reads: `get_content_resource_intent`, `get_localized_context`, `inspect_localized_changeset`, `query_released_renditions` | `crates/proof-local/src/localized.rs` | resource-intent/Context operation-uniqueness tests; Context reconstruction; operation/effect tamper and key-swap matrices; existing Edit-through-Release integrity cases | missing, duplicate, substituted, tampered, and cross-linked evidence fails closed with no read repair; Assurance expands table snapshots |
| G4 | Historical/current `verify_localized_release` and CLI verifier | local adapter and CLI localized modules | lifecycle verification; `release_reads_reject_independent_approval_digest_tamper`; chronology/trust/predecessor tests | valid and wrong ancestry/reference/version/time cases retained; Assurance independently challenges artifacts |
| G5 | Exact `build_localized_context`, `get_localized_context`, and released query closure | application trait and local adapter localized modules | exact closure reconstruction test; immutable history/exact authority; application/CLI exact and absent locale probes | target closure, casing, stale/source/scope changes, and budget constraints retained; Assurance derives expected closure independently |
| G6 | Complete Human lifecycle and application/CLI parity | application trait, local adapter, Human CLI | application and CLI two-locale repair-to-Release scenarios | complete lifecycle supported; Assurance compares identifiers, digests, transitions, Problems, and normalized envelopes |
| G7 | Target preconditions, immutable attempts, repair lineage, and budgets | `crates/proof-local/src/localized.rs` | `localized_edit_denials_are_specific_and_atomic`; `p0007_g7_separate_context_edit_and_validation_budgets_are_atomic`; `p0007_g7_raw_lineage_deletion_reorder_substitution_and_cycle_are_detected_read_only` | deterministic denials, budgets, lineage integrity, and unchanged snapshots retained |
| G8 | Exact commit, Edition, Release, delta, and pointer causality | local adapter commit/Edition/Release paths | lifecycle replacement and moved-pointer phases; Release evidence/pointer tests | stale/missing/extra/wrong/ambient cases reject before Release attribution or pointer movement; Assurance independently reconstructs delta |
| G9 | Atomic v1-v11 migration and closed compatibility | local initialization and `migrate_schema_v11` | `p0007_g9_each_v1_to_v10_failure_rolls_back_retries_and_preserves_legacy_hash`; every-pre-version and lifecycle compatibility tests | all ten source versions roll back exactly and converge once without locale fabrication; Assurance independently hashes legacy fixtures |
| G10 | Deterministic dry-run and derived-only repair through `rebuild_projections` | local rebuild implementation and CLI | four `p0007_assurance_g10_*` cases | each localized derived family independently repaired; repeated dry-runs stable/no-write; authoritative tamper rejected |
| G11 | Replay/idempotency for seven consequential localized operations | local adapter operation/effect implementation | `localized_control_replays_survive_environment_pointer_movement`; changed-input/key/effect matrices; lifecycle replay cases | identical replay precedes mutable preconditions; changed valid/invalid input, target, key, and lifecycle reuse fail without writes |
| G12 | Human authentication and explicit absence of delegated Agent authority | `require_human_principal` and every localized repository method | Human lifecycle; `mismatched_local_identity_fails_authentication`; `disabled_bootstrap_principal_fails_authentication`; source-surface enumeration | Human boundary supported; Assurance independently invokes all 17 surfaces through Agent/disabled identities; no delegated authority claim |
| G13 | Atomic failure recovery and one-step convergence | commit transaction and Release proof-export/replay helpers | three `p0007_assurance_g13_*` cases; existing storage/migration/release-export failures | pre-write and mid-transaction abort rollback; post-commit export and replay converge once; no power-loss claim |
| G14 | Exact provenance, scope, inventory, and secret exclusion | work-control validator, Git objects, evidence packet | 34-path Git-blob inventory; candidate-parent 10-path diff; clean status; diff/links/work-items/Markdown/credential scans | portable inventory and explicit non-goals retained; Assurance verifies evidence-only diff and exclusions |

## Scope reconciliation

The 34-path original-base inventory is entirely attributable to the ratified
localized-content foundation, its Human application/CLI path, storage v11,
canonical/conformance material, retained verification, quality workflow, and
work-control gate. The candidate-parent repair is limited to ten listed paths.
Its only dependency change exposes two already workspace-pinned libraries to
`proof-local` tests; production dependencies are unchanged.

The implementation does not add an Agent credential, DelegationV2,
authorization-decision surface, MCP mutation path, server, HTTP API,
PostgreSQL adapter, UI, model/translation provider, locale fallback, rendition
deletion, relationship localization, or generic variants.

## Falsification posture

The strongest counterargument is that a green end-to-end test and CI already
exercise the same code, making independent G2-G14 checks redundant. It is
rejected: direct reads, verifiers, query, rebuild, recovery, and migration can
share an incorrect helper or trust one corrupted projection while remaining
jointly green. Integrity parity across all reachable paths is the crux.

Any exact-candidate digest mismatch, returned success after authoritative
tamper, partial denial write, pointer movement, changed legacy fingerprint,
fabricated locale row, replay divergence, evidence provenance conflict, or
required quality-step failure changes Engineering's recommendation to
`REVISE`. Until Assurance completes that falsification pass, the bounded claim
remains `indeterminate`.
