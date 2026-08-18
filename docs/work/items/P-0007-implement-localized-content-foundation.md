---
id: P-0007
title: Implement the localized content foundation
status: claimed
wave: now
kind: implementation
blocked_by: [P-0002]
claimed_by: codex:/root:p-0007
claimed_at: 2026-08-18T12:52:10.931Z
base_sha: a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566
review_gate: none
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

- [ ] One Human-path scenario creates two target-locale renditions from an
      existing source Object, persists a prohibited-claim finding, appends a
      valid superseding Edit, and completes approval, commit, Edition, Release,
      exact-locale query, and verification.
- [ ] Resource-intent issuance is Human-authenticated, immutable, idempotent,
      and effect-bound; the digest graph from intent to ContextPack to ChangeSet
      is acyclic, and no later command can narrow or widen the exact tuples.
- [ ] Missing-target creation and exact revision/digest replacement are
      deterministic; stale source, stale target, duplicate active target,
      supersession fork/cycle, wrong target, and non-localizable-field changes
      fail atomically with stable Problems.
- [ ] Every attempted Edit remains immutable and counts toward the budget;
      effective heads alone drive diff/validation/commit, while approval and
      evidence bind the complete attempt lineage and final effective digest.
- [ ] Edition and Release reject ambient or intervening state, a moved
      Environment pointer, an unrelated same-resource commit, or any delta
      outside the immutable exact resource intent.
- [ ] ContextPack v2 and released-query v2 expose only the exact requested
      Object/Schema/locale closure and perform no fallback or relationship
      traversal.
- [ ] Every supported pre-P-0007 storage version migrates atomically; all v1
      bytes and digests reproduce exactly, no locale facts are fabricated, and
      injected failures roll back cleanly.
- [ ] The first v1-to-v2 content transition reproduces exact versioned base
      references and the cross-version delta; the closed legacy/v2 command,
      query, rollback, and historical-verification matrix fails unsupported
      combinations without losing rendition state.
- [ ] Canonical format, migration, rebuild, replay, denial atomicity, and Linux
      quality gates pass an adversarial falsification review.

## Required evidence

Create `docs/work/evidence/P-0007/receipt.md` and `manifest.json` when
executing. Include exact schema/storage versions, artifact digests, migration
matrix, source-to-rendition fixtures, denial matrix, replay results, and test
commands. Do not include prompts, provider credentials, private keys, runtime
databases, or generated translation text that cannot be checked in safely.

## Completion record

Ready after project owner `smithdak` accepted P-0002 at
`2026-08-18T12:44:20.977Z`. Claimed by `codex:/root:p-0007` at
`2026-08-18T12:52:10.931Z` from
`a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566`. The accepted contract and
ADR-0012 are the implementation authority.

## Residual risks and next-wave update

On completion, reshape only P-0005's authenticated integration boundary.
Fallback, rendition removal, relationship-localization, general variants,
dynamic campaign/subtree selection, and higher-cardinality scale stay in map
fog until a demonstrated outcome requires them.
