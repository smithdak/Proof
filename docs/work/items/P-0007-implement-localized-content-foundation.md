---
id: P-0007
title: Implement the localized content foundation
status: claimed
wave: now
kind: implementation
blocked_by: [P-0002]
claimed_by: buzz:proof-engineering:4fba209ea00d5d985d87873f17915f6ed117ca6e0272a81c100ca3166586f846
claimed_at: 2026-08-19T17:39:58Z
base_sha: a95ee484b7038358c0d4e30167862dbed85728c0
review_gate: proof-assurance
accepted_by: null
accepted_at: null
---

# Implement the localized content foundation

[Back to the work map](../map.md)

## Outcome

The Human application and CLI path can create and revise exact-locale
renditions of existing Objects, repair an invalid proposal inside one
ChangeSet, approve and commit the final effective proposal, create the bound
Edition, release it to a preview Environment, and reproduce every v2 artifact
without delegated Agent authority.

## Promotion condition

P-0002 must be project-owner accepted and `done`. Re-read the accepted
[delegated content contract](../../architecture/delegated-content.md) and ADR-0012
before moving this item to `ready`; do not infer implementation details from the
candidate while P-0002 remains in review.

## Authorized scope

- Add the versioned `ObjectLocaleRevisionV1` projection and
  `proof.dev/edit/v2` `object.locale.put` contract selected by P-0002.
- Add immutable resource intent, exact ContextPack source closure, repairable
  ChangeSet v2 lineage, deterministic validation, diff, approval, commit, and
  exact-locale released query semantics.
- Add the idempotent authenticated-Human issuance path for
  `ContentResourceIntentV1`; ContextPack and ChangeSet creation accept only its
  stored identifier/digest and the Agent integration cannot replace its target
  arrays.
- Add Edition v2 and Release v2 creation bound to the exact committed
  ChangeSet, resulting state, and unchanged baseline Environment Release.
- Add the storage successor and atomic migrations required for the new content
  facts, operation effects, resource-intent control artifacts, projections,
  and artifact versions.
- Preserve the Human authorization boundary and expose the same application
  contracts through the Human CLI. The authenticated Agent adapter remains
  P-0004/P-0005 work.
- Add independent canonicalization/reconstruction tests and small golden
  fixtures for every new authoritative or portable format.
- Own the exact content operation input/output and artifact Schemas. Reopened
  P-0003 owns the operation/action/resource-projection registry against
  P-0002's normative identifiers and fields; P-0007 registers the final Schema
  identifiers/digests without duplicating authority decisions.

## Explicit non-goals

- No Agent credential, DelegationV2, authorization-decision, MCP, or broker
  implementation.
- No JSON Patch, base-Object replacement, relationship or lifecycle mutation,
  rendition deletion, locale fallback, generic variants, campaign entity, or
  subtree/path-prefix authority.
- No collaboration server, PostgreSQL, HTTP API, visual UI, model provider, or
  translation service.

## Acceptance criteria

- [x] One Human-path scenario creates two target-locale renditions from an
      existing source Object, persists a prohibited-claim finding, appends a
      valid superseding Edit, and completes approval, commit, Edition, Release,
      exact-locale query, and verification.
- [x] Resource-intent issuance is Human-authenticated, immutable, idempotent,
      and effect-bound; the digest graph from intent to ContextPack to ChangeSet
      is acyclic, and no later command can narrow or widen the exact tuples.
- [x] Missing-target creation and exact revision/digest replacement are
      deterministic; stale source, stale target, duplicate active target,
      supersession fork/cycle, wrong target, and non-localizable-field changes
      fail atomically with stable Problems.
- [x] Every attempted Edit remains immutable and counts toward the budget;
      effective heads alone drive diff/validation/commit, while approval and
      evidence bind the complete attempt lineage and final effective digest.
- [x] Edition and Release reject ambient or intervening state, a moved
      Environment pointer, an unrelated same-resource commit, or any delta
      outside the immutable exact resource intent.
- [x] ContextPack v2 and released-query v2 expose only the exact requested
      Object/Schema/locale closure and perform no fallback or relationship
      traversal.
- [x] Every supported pre-P-0007 storage version migrates atomically; all v1
      bytes and digests reproduce exactly, no locale facts are fabricated, and
      injected failures roll back cleanly.
- [x] The first v1-to-v2 content transition reproduces exact versioned base
      references and the cross-version delta; the closed legacy/v2 command,
      query, rollback, and historical-verification matrix fails unsupported
      combinations without losing rendition state.
- [x] Canonical format, migration, rebuild, replay, denial atomicity, and Linux
      quality gates pass an adversarial falsification review.

## Required evidence

Create `docs/work/evidence/P-0007/receipt.md` and `manifest.json` when
executing. Include exact schema/storage versions, artifact digests, migration
matrix, source-to-rendition fixtures, denial matrix, replay results, and test
commands. Do not include prompts, provider credentials, private keys, runtime
databases, or generated translation text that cannot be checked in safely.

The project-owner stale-claim decision on 2026-08-19 added the mandatory
[P-0007 independent verification gate](../gates/P-0007-independent-verification.md).
Engineering produces the candidate receipt and manifest; Proof Assurance must
independently execute the gate and add `assurance-verdict.md`. Only a
`supported` exact-candidate verdict can satisfy this review gate. Assurance
does not authorize release.

## Engineering revalidation plan

The candidate revision follows this control-plane commit. Engineering first
closes the known strict-Clippy failure, then adds only tests or implementation
repairs required by the gaps below. Any architecture, dependency, migration
shape, or authorized-scope change stops for project-owner review. The final
traceability table in the evidence packet replaces `gap` with exact retained
evidence from one immutable candidate.

| Gate | Ratified requirement | Exact public entry point | Current source and retained test/command | Current state |
| --- | --- | --- | --- | --- |
| G1 | Acceptance criterion 9; repository quality gate | `.github/workflows/ci.yml` | `cargo fmt --all --check`; strict workspace Clippy; full workspace/all-target/all-feature tests; doc tests; `scripts/check-doc-links.mjs`; `scripts/check-work-items.mjs` | `gap`: `a95ee48` failed Clippy and skipped later CI steps. |
| G2 | Canonical formats, Schemas, vectors, and independent reconstruction | `proof_canonical::object_locale_revision`, `known_state_v2_manifest`, and `known_state_v2` | `crates/proof-canonical/src/lib.rs`; `conformance/v2/localized-content/`; `localized_artifact_golden_digests_are_stable`; `localized_public_rendition_builder_matches_the_portable_vector`; `localized_public_state_builders_match_the_portable_vectors` | Partial positive vectors exist; independent mutation/rejection corpus is missing. |
| G3 | Integrity-equivalent authoritative reads | `LocalizedContentRepository::{get_content_resource_intent,get_localized_context,inspect_localized_changeset,query_released_renditions}` | `crates/proof-application/src/localized.rs`; `crates/proof-local/src/localized.rs`; new retained direct-read tamper matrix required | `gap`: no retained per-artifact tamper/omission/cross-link matrix. |
| G4 | Historical and current verifiers fail closed | `LocalizedContentRepository::verify_localized_release`; CLI `localized release-verify` | `crates/proof-local/src/localized.rs`; `crates/proof-cli/src/localized_cli.rs`; `localized_cli_repairs_and_releases_two_exact_locales` | Valid-path proof exists; adversarial artifact/ancestry/version cases are missing. |
| G5 | Exact ContextPack and query closure; no fallback or traversal | `build_localized_context`, `get_localized_context`, `query_released_renditions` | Application trait and SQLite implementation in `crates/proof-application/src/localized.rs` and `crates/proof-local/src/localized.rs`; CLI localized scenario | Two-locale positive path exists; scope/disclosure denial matrix is missing. |
| G6 | Complete Human lifecycle and application/CLI parity | Complete `LocalizedContentRepository`; CLI `run_localized` | `crates/proof-application/src/localized.rs`; `crates/proof-cli/src/localized_cli.rs`; `localized_cli_repairs_and_releases_two_exact_locales` | CLI end-to-end path exists; direct application parity evidence is missing. |
| G7 | Deterministic target preconditions, immutable attempts, repair, and budgets | `add_localized_edits`, `inspect_localized_changeset`, `diff_localized_changeset`, `validate_localized_changeset` | `crates/proof-local/src/localized.rs`; localized CLI repair scenario | One prohibited-claim repair exists; fork/cycle/stale/budget/atomicity matrix is missing. |
| G8 | Exact commit, Edition, Release, and pointer causality | `commit_localized_changeset`, `create_localized_edition`, `promote_localized_release`, `rollback_localized_release` | `crates/proof-local/src/localized.rs`; localized CLI scenario | Positive promotion exists; ambient/intervening-state and pointer-denial matrix is missing. |
| G9 | Atomic v1-v11 migration and closed compatibility matrix | `proof_application::initialize_workspace` and every localized operation's latest-schema preflight | `crates/proof-local/src/lib.rs`; `crates/proof-local/src/localized.rs::migrate_schema_v11`; new every-version/failure matrix required | First v1-to-v2 path is exercised indirectly; every-version, injected rollback, and closed version matrix evidence is missing. |
| G10 | Deterministic dry-run rebuild and derived-only repair | `proof_application::rebuild_projections`; CLI `projection rebuild` | `crates/proof-application/src/lib.rs`; `crates/proof-local/src/lib.rs::rebuild_projections_transaction`; localized CLI clean dry-run | Localized projection corruption/repair and authoritative-tamper rejection are missing. |
| G11 | Replay and idempotency for every consequential operation | `issue_content_resource_intent`, `build_localized_context`, `create_localized_changeset`, `add_localized_edits`, `commit_localized_changeset`, `promote_localized_release`, and `rollback_localized_release` | `crates/proof-local/src/localized.rs`; new retained identical-replay/changed-input matrix required | Keys are persisted; complete identical-replay and changed-input reuse matrix is missing. |
| G12 | Human authentication; no delegated Agent authority | `require_human_principal` and every `LocalizedContentRepository` method | `crates/proof-local/src/localized.rs`; CLI localized commands | Human positive path exists; unauthenticated and Agent-boundary denial evidence is missing. |
| G13 | Atomic failure recovery and one-step convergence | `commit_localized_changeset`, `promote_localized_release`, and `rollback_localized_release` | `crates/proof-local/src/localized.rs`; Release proof preflight/materialization helpers; new retained fault-injection matrix required | `gap`: no retained pre-write/mid-transaction/post-commit/interruption fault matrix. |
| G14 | Exact candidate provenance, scope inventory, and secret exclusion | `node scripts/check-work-items.mjs` and the receipt/manifest contract | `scripts/check-work-items.mjs`; full Git path inventory; `git diff --check`; credential-shaped-content scan | Validator ancestry enforcement is implemented in the revalidation control plane; candidate inventory remains pending. |

Disposition is mechanical: restore only when every row and acceptance criterion
is supported at one candidate and Proof Assurance records `supported`; revise
only through an approved contract/work-item change followed by a complete new
run; retire as `superseded` when a required invariant cannot be supported
without unauthorized expansion. No disposition implies release.

## Completion record

Ready after project owner `smithdak` accepted P-0002 at
`2026-08-18T12:44:20.977Z`. Claimed by `codex:/root:p-0007` at
`2026-08-18T12:52:10.931Z` from
`a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566`. The accepted contract and
ADR-0012 are the implementation authority.

The project owner declared the prior P-0007 capability claim stale and
authorized transfer of operating ownership to Proof Engineering in Buzz event
`4fba209ea00d5d985d87873f17915f6ed117ca6e0272a81c100ca3166586f846` at
`2026-08-19T17:39:58Z`. Proof Engineering claimed revalidation from
`a95ee484b7038358c0d4e30167862dbed85728c0`.

Engineering qualified exact candidate
`c4b312d6f493936e15c2cc658277953ea18777f7` in a clean fresh Ubuntu checkout
and GitHub Actions run `32380862459` completed every required step successfully
at the same SHA. The receipt, manifest, portable Git-blob inventory, and
traceability table bind that candidate and move the item to `review`.

Proof Assurance reviewed that exact candidate at
`2026-08-20T15:24:51.377Z` and recorded an `unsupported` verdict. G4 reproduced
a v2 Release predecessor cycle that stack-aborted the public verifier before
its chronology guard, and G11 reproduced an exact ChangeSet-create replay that
returned the later committed aggregate instead of the original empty draft.
The item therefore returned to `claimed` for Engineering repair; the c4
qualification and its evidence remain historical records and are not relabeled.

The item is not accepted or done until `proof-assurance` records a supported
independent G1-G14 verdict. An unsupported or indeterminate row returns the
item to Engineering or requires an authorized revision; it must not silently
narrow the claim. Review status does not assert release, production, delegated
Agent authority, or customer proof.

## Residual risks and next-wave update

On completion, reshape only P-0005's authenticated integration boundary.
Fallback, rendition removal, relationship-localization, general variants,
dynamic campaign/subtree selection, and higher-cardinality scale stay in map
fog until a demonstrated outcome requires them.
