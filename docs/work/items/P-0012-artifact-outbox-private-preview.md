---
id: P-0012
title: Implement the artifact outbox and private preview delivery
status: claimed
wave: now
kind: implementation
blocked_by: [P-0011]
claimed_by: deepseek:proof:p-0012
claimed_at: 2026-08-23T23:21:15.788Z
base_sha: 5e1810e89571d87840fb9af6b56eb44f728f351c
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the artifact outbox and private preview delivery

[Back to the work map](../map.md)

## Outcome

Proof has the transactional-outbox worker and the private preview delivery
boundary from the accepted contract: ordered generation-scoped stream claims
with bounded leases and counted attempts, at-least-once delivery without an
exactly-once claim, dead-letter and poison management with authorized replay
and abandonment, immutable `DeliveryManagementFactV1` facts, and a private
content-addressed preview materialization whose ready manifest is written
last and whose alias advances monotonically by Release sequence. The preview
route serves exact immutable Release snapshots per object and locale with no
fallback, and the delivery projection and management operations are
implemented through the P-0010 unit of work.

## Why now

P-0009 fixed the contracts, P-0010 fixed the durable PostgreSQL foundation
including outbox enqueue, and P-0011 fixed the HTTP/OIDC boundary with the
preview and delivery routes returning the stable pending Problem. The
accepted contract names this item as the fourth dependency-ordered
successor. Remote evidence and Milestone 3 qualification consume this
delivery boundary.

## Promotion condition

Satisfied by completed P-0011 candidate
`ed6a06eb9710ab98792e11f5b7a42d56d2832e65`, bound by Engineering evidence
commit `cddb5355abc3ec5d228bbc511da26e8ed45be6c3`, per the accepted
[collaboration-server
contract](../../architecture/collaboration-server.md) successor order.
ADR-0013 remains the implementation authority.

## Authorized scope

- Implement the outbox worker over the P-0010 enqueue records: a worker
  claims only the lowest nonterminal sequence of a stream whose prior
  sequence is terminally delivered or explicitly abandoned; claims due work
  in deterministic order in a short `READ COMMITTED` transaction using
  `FOR UPDATE SKIP LOCKED`; records a random lease token, a 60-second lease
  using PostgreSQL `clock_timestamp()`, and the counted attempt before
  committing the claim; performs external I/O only after that commit with a
  30-second attempt deadline and no lease renewal; acknowledges in a new
  transaction by compare-and-set on the exact lease token and generation;
  rejects stale or superseded acknowledgements; makes the same stable
  delivery eligible again after lease expiry.
- Implement retry and poison semantics exactly: retry delay uniformly
  sampled from the upper half of `min(5 seconds * 2^(generation_attempt -
  1), 1 hour)` added to database time; twelve counted attempts in one
  generation or seven days from that generation's start, whichever comes
  first, produces a dead-letter record; an explicit permanent failure does
  so immediately; a poison message blocks its strict
  destination/Environment stream until successful replay or authenticated
  administrative abandonment while other independent streams progress;
  Workspace transaction sequence plus ordinal, never time, defines enqueue
  order; `attempts_in_generation` counts claims consumed in only the current
  generation while older attempts remain immutable global history.
- Implement `delivery.replay/v1` (`environment.admin`) and
  `delivery.abandon/v1` (`environment.activator`): each appends one
  `DeliveryManagementFactV1` digested under
  `proof:delivery-management-fact:v1` — deliberately not a
  `RemoteAuthorityRecordV1` payload — with the signed
  `RemoteAuthorizationDecisionV1` and the signed
  `RemoteApplicationConsequenceV1` whose `application_effect_digest` binds
  the fact. Replay increments the generation, resets
  `attempts_in_generation`, and returns `pending` while preserving event,
  delivery, and payload identities and the append-only attempt history;
  abandonment keeps the current generation, records null `to_generation`,
  and sets terminal `abandoned` so only the stream-management cursor may
  advance. Implement `delivery.get/v1` as the typed transport projection.
- Implement the private preview adapter (filesystem-backed reference
  implementation): materialize every blob under unreachable
  content-addressed keys, verify kind/length/digest, and write one
  content-addressed complete-snapshot manifest and ready marker last; reads
  and the mutable alias resolve only ready manifests so a crash cannot
  expose a partial snapshot. Alias compare-and-set outcomes are exact: a
  higher Release sequence advances; the same sequence plus the same
  Release/manifest digest is a no-op; the same sequence plus different bytes
  is an integrity failure; a lower sequence is recorded superseded without
  regressing the alias. Delivery failure never rewrites Release history;
  recovery is retry, authenticated abandonment, or a new forward rollback
  Release.
- Implement `preview.release/v1` event handling naming the exact Release
  sequence/digest, Edition, Environment configuration, Proof, and artifact
  references — never an ambient “current” lookup.
- Implement the preview route result: exact JSON only after that Release's
  ready marker exists, identifying Release ID/digest, Edition digest, and
  rendition digest, with a strong ETag and `Cache-Control: private,
  no-store`, no locale fallback, no renderer, no template engine, no
  arbitrary fetch; while pending it returns the stable
  `proof.dependency.unavailable` Problem and never falls back to another
  Release.
- Deliver the worker and preview state changes as recorded facts with exact
  crash boundaries (claim crash consumes the attempt; send-before-ack crash
  may repeat the effect) and explicit at-least-once semantics; no
  exactly-once or at-most-once claim.
- Retained tests: lease claim/ack/expiry/redelivery, stale-ack rejection,
  poison dead-letter plus replay and abandonment, alias monotonicity and
  integrity failure, partial-snapshot invisibility, delivery/Release state
  divergence, and the two delivery-management operations through the unit of
  work.

## Explicit non-goals

- No evidence export capture/assembly or remote bundle v2 (successor
  scope); the evidence artifact route remains pending until export records
  exist.
- No general webhooks, public preview, bearer links, or presentation
  framework.
- No SDK, console, deployment, TLS infrastructure, or provider selection.
- No high availability, multi-region ordering, backup/restore, or
  garbage-collection claim.
- No successor promotion: remote evidence and Milestone 3 qualification
  stay fog until this item closes.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md):
  transactional outbox and delivery, preview delivery, immutable artifact
  boundary (read side), and the delivery operation rows.
- [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
- [Core invariants](../../architecture/constitution.md)
- [P-0011 evidence](../evidence/P-0011/receipt.md)

## Acceptance criteria

- [ ] The worker claims in deterministic stream order under
      `FOR UPDATE SKIP LOCKED` with a random 60-second lease and counts the
      attempt at claim commit; external I/O happens only after claim commit.
- [ ] Acknowledgement is compare-and-set on lease token and generation;
      stale acks reject; expiry makes the same stable delivery eligible
      again.
- [ ] Backoff, the twelve-attempt/seven-day dead-letter rule, immediate
      permanent-failure dead-letter, and per-stream poison blocking all
      behave exactly; other streams progress independently.
- [ ] Replay and abandonment append `DeliveryManagementFactV1` with the
      signed decision and consequence binding; replay resets the generation
      to `pending`; abandonment is terminal `abandoned`.
- [ ] The preview adapter materializes blobs under unreachable keys, writes
      the ready manifest last, and enforces the four alias outcomes
      (advance, no-op, integrity failure, superseded) by Release sequence.
- [ ] The preview route serves exact immutable Release snapshots with the
      strong ETag and private no-store cache control, returns the stable
      pending Problem until ready, and performs no fallback.
- [ ] Release commitment and preview delivery remain observably separate
      facts; delivery failure never rewrites Release history.
- [ ] At-least-once semantics are explicit in code and tests; no
      exactly-once or at-most-once claim exists anywhere.
- [ ] `delivery.get/v1` projects the exact mutable delivery state.
- [ ] The full Linux quality gate passes and durable Engineering evidence
      (receipt, manifest, traceability) binds the item-work commit.

## Evidence contract

Record the qualified implementation candidate, crate/module inventory, the
delivery-state machine matrix, alias outcome matrix, crash-boundary tests,
gate command results, and residual boundaries in
`docs/work/evidence/P-0012/`. Produce `receipt.md`, `manifest.json`, and a
criterion-level traceability matrix.

## Completion record

Ready at `2026-08-23T23:20:07.742Z` after P-0011 candidate
`ed6a06eb9710ab98792e11f5b7a42d56d2832e65` closed with Engineering evidence
commit `cddb5355abc3ec5d228bbc511da26e8ed45be6c3`.

Claimed by `deepseek:proof:p-0012` at `2026-08-23T23:21:15.788Z` from
P-0011 completion commit `5e1810e89571d87840fb9af6b56eb44f728f351c`
on `proof-architecture/p-0008-collaboration-server-contract`. No SDK,
console, provider, or deployment work is claimed by this item.
