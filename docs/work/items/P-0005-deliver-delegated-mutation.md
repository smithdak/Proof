---
id: P-0005
title: Deliver delegated mutation through a verified Release
status: blocked
wave: next
kind: implementation
blocked_by: [P-0002, P-0004]
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

## Promotion condition

Re-shape this item after P-0002 and P-0004 close. It is not claimable while
content or authenticated-authority semantics remain provisional.

## Authorized scope

- Add the ratified delegated actions, resources, budgets, and ContextPack
  requirements for ChangeSet proposal/edit/validation/submission, commit,
  Edition creation, and Release promotion.
- Add the content Edit kinds and persistence/migrations selected by P-0002.
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

## Explicit non-goals

- No autonomous approval bypass.
- No collaboration server, HTTP API, PostgreSQL, model provider, or visual UI.
- No ambient repository, filesystem, command, or network access for an Agent.

## Acceptance criteria

- [ ] One real local scenario completes ContextPack → proposed content change →
      validation/repair → submission → Human approval → delegated commit →
      Edition → delegated Release → verification.
- [ ] Wrong recipient, action, resource, locale, Environment, budget, expired or
      revoked Delegation, stale ContextPack/base state, replay mismatch, and
      approval bypass all fail structurally and atomically.
- [ ] Revocation, Principal/binding disablement, parent-chain invalidation, or
      applicable policy/configuration change between submission and consequence
      is detected by re-authorization.
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

Blocked by P-0002 and P-0004.

## Residual risks and next-wave update

Record incomplete repair/security cases for P-0006 and keep server concerns in
map fog rather than widening this item.
