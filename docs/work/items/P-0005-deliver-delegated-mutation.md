---
id: P-0005
title: Deliver delegated mutation through a verified Release
status: ready
wave: now
kind: implementation
blocked_by: [P-0004, P-0007]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Deliver delegated mutation through a verified Release

[Back to the work map](../map.md)

## Outcome

An authenticated Agent Principal can use a bounded ContextPack to propose the
content behavior ratified by P-0002, repair and submit a ChangeSet, pause for a
separate Human approval, then resume through execution-time authorization,
commit, Edition, Environment Release, and persisted verification.

## Promotion condition — satisfied

P-0007 candidate `47153144b4b834cfffab61b328e4551f09fe50cb`, bound through
Engineering evidence `8308ebfb9090270982fcfb06c8247ab423fcb51d` and Assurance
record `29ad9d95c100c9ecfad5080c998915c23a2a5f93`, closed the Human-path
localized content foundation. P-0004 candidate
`87888475829cf6f197f6b1ed4b0c0e1a9863ccf7`, bound through Engineering
evidence `e6843ada5be3ad48d669dc1c1ae23cb4e997220d`, closed the bounded local
authenticated read kernel. Both dependencies are `done`; this item is ready
and unclaimed.

## Authorized scope

- Enable and wire the 11 already-registered localized v2 operation rows through
  P-0007's ChangeSet, Edition, and Release consequences. P-0005 must not add or
  reinterpret their actions, resource projections, budgets, retry classes,
  closure anchors, selectors, or registry rows.
- Integrate the P-0007 application and storage contracts; do not reimplement or
  fork localized-content, repair, Edition, Release, or migration semantics in
  an Agent adapter.
- Keep approval a distinct Principal action; an Agent cannot implicitly approve
  its own proposal.
- Re-evaluate current authority and the applicable state/policy inputs
  immediately before every consequential transaction, including commit,
  Edition creation, and Release, and bind that operation's fresh authorization
  decision to its result.
- Bind requesting and operating Principals, the versioned
  authenticated-subject/Principal-binding commitment selected by P-0003,
  Delegation, ContextPack, policy/validator versions, approval, and capability
  version into authoritative evidence.
- Expose the same operation contracts through CLI and both MCP eras. If the
  ratified application capability contract remains the Schema source,
  generate tool Schemas from it rather than duplicating transport contracts.
- Treat P-0007's registered content Schema identifiers/digests and
  P-0003/P-0004's authority registry as immutable inputs. P-0005 wires them
  together and cannot add an adapter-local operation, resource projection, or
  content normalization rule.

## Explicit non-goals

- No autonomous approval bypass.
- No collaboration server, HTTP API, PostgreSQL, model provider, or visual UI.
- No ambient repository, filesystem, command, or network access for an Agent.

## Acceptance criteria

- [ ] One real local scenario completes ContextPack → proposed content change →
      validation/repair → submission → Human approval → delegated commit →
      Edition → delegated Release → verification.
- [ ] The Agent may add only `object.locale.put` v2 Edits for the immutable
      exact target set. Base Objects, Schemas, relationships, lifecycle,
      fallback, and unrelated locale renditions remain structurally
      unavailable through this profile.
- [ ] The requesting Human issues the exact resource intent and equals the
      direct Delegation issuer; the Agent can select the persisted intent and
      bound ContextPack but cannot create or replace either resource closure.
- [ ] Wrong recipient, action, resource, locale, Environment, budget, expired or
      revoked Delegation, stale ContextPack/base state, replay mismatch, and
      approval bypass all fail structurally and atomically.
- [ ] Under the ratified P-0003 profile, revocation, Principal/binding
      disablement, direct-Delegation invalidation, or applicable
      policy/configuration change between submission and consequence is detected
      by re-authorization; parent or subdelegation input is rejected as
      unsupported.
- [ ] A controlled concurrency test proves that whichever of revocation and
      consequence commits first determines the result; no check-then-act window
      permits a post-revocation commit.
- [ ] Every denial leaves governed content facts, committed
      ChangeSet/Edition/Release history, content projections, and Environment
      pointers unchanged; only ratified denial/audit evidence may append.
- [ ] Application, CLI, modern MCP, and legacy MCP assert equivalent behavior.
- [ ] Every storage version supported before P-0005 migrates atomically and
      remains foreign-key clean; pre-existing authoritative facts, Known State,
      Editions, Releases, and Proof bytes/digests reproduce exactly; injected
      failures roll back and retry without partial semantic conversion.
- [ ] The Linux quality gate and an adversarial falsification review pass.

## Required evidence

Create `docs/work/evidence/P-0005/receipt.md` and `manifest.json` when
executing. Include the exact end-to-end transcript in structured form,
authority and state digests, denial matrix, migration results, adapter parity,
and test commands. Do not include credentials, prompts, hidden reasoning, or
private key material.

## Completion record

Ready and unclaimed after P-0007 and P-0004 completion. Delegated mutation is
still unimplemented; claiming P-0005 is the next authorized execution step.

## Residual risks and next-wave update

Record incomplete repair/security cases for P-0006 and keep server concerns in
map fog rather than widening this item.
