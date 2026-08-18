---
id: P-0004
title: Implement the authenticated authorization kernel
status: blocked
wave: next
kind: implementation
blocked_by: [P-0003]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the authenticated authorization kernel

[Back to the work map](../map.md)

## Outcome

Every authority-bearing local operation receives an adapter-authenticated actor
context, binds it to the correct Principal, evaluates the ratified Delegation
contract, and emits a canonical authorization decision. Request data and MCP
session state cannot manufacture authority.

## Promotion condition

This outcome is durable, but its implementation details are provisional until
P-0003 closes. Re-shape this item against the ratified identity and Delegation
contracts before setting it to `ready`.

## Proposed P-0003 profile reshape

The following reshape is pending project-owner acceptance of P-0003. It does
not make this item `ready` and does not claim any authenticated Agent path is
implemented. The controlling proposal is the
[authenticated actor contract](../../architecture/authenticated-actor.md).
P-0002 must first settle the write-resource closure before P-0003 can enter
owner review; this candidate reshape remains blocked and exposes no write path.

## Authorized scope

- Implement the identity port, Unix local Human adapter, local per-Agent
  Ed25519 proof-of-possession adapter, deterministic fake adapter, and
  `PrincipalBindingV1` issuance, rotation, disablement, and recovery lifecycle
  selected by the **Proposed P-0003 profile**.
- Make Principal disablement terminal for v1. Recovery creates a new Principal,
  binding, and `DelegationV2`; it cannot reactivate old authority.
- Verify one bounded, single-use `AuthenticatedCommandV1` DSSE presentation per
  Agent operation and construct `AuthenticatedActorContextV1` only inside the
  trusted adapter. Request Principal identifiers remain expected-value
  cross-checks.
- Persist `requesting_subject_commitment` as a hiding commitment formed with a
  32-byte blind, not a raw UID checksum. Build `actor_context_digest` from that
  public commitment, never the raw requesting `os/unix` subject or blind. Keep
  private subject-plus-blind disclosure behind audit policy and conform exactly
  to the authenticated-actor vectors.
- Persist strict raw-UID-free `AuthenticatedActorContextEvidenceV1` as the
  canonical actor-context digest preimage. Record `authenticated_at` as
  authentication completion time without assuming it equals authorization
  `evaluated_at`. Store the semantic `CommandInputV1` digest and
  authenticated-command envelope digest; do not invent a payload digest.
- Enforce one active Agent key/subject to one Principal per Workspace. Rotation
  for the same Principal uses a distinct new key; authenticated-subject key hex,
  binding `public_key`, enrollment candidate, and signer key are byte-identical.
- Enforce `issued_at <= not_before < expires_at` for bindings and Delegations,
  with activity exactly `not_before <= evaluated_at < expires_at`. Causal
  disable/revoke takes effect at its authority-record sequence regardless of
  timestamp. Empty v2 scope arrays grant none, never wildcard; unused dimensions
  are ignored and any required empty dimension denies.
- Treat DSSE `keyid` as an unsigned lookup hint. After verification it must equal
  the expected key resolved from the validly issued immutable historical
  binding, enrollment candidate, or
  Workspace authority state. Root transitions accept exactly two distinct,
  verified signatures in predecessor-then-successor order; reject duplicate,
  permuted, or substituted key IDs per conformance.
- Implement the Agent-side signer and Human-owned broker split. The signer has
  no Workspace access and emits exact normalized input plus
  `AuthenticatedCommandV1`. The broker alone opens the private Workspace and
  authority keys. Keep `proof-mcp` stdio as one broker and implement CLI parity
  as `proof auth execute --invocation -`, reading one bounded framed stdin or
  already-open-FD invocation of at most 1,048,576 bytes plus the operation cap.
  No Agent-controlled path, argv, signed field, or MCP value may make the broker
  open a file; path modes and ambient direct CLI remain Human-only. Add no
  network/collaboration server.
- Permit only the enabled ADR-0009 bootstrap Human derived in that broker to
  issue challenges; enable or terminally disable Principals; issue, revoke, or
  rotate bindings; issue or revoke Delegations; or activate root transitions.
  Every administration actor field and `DelegationV2` issuer equals the derived
  bootstrap Principal. No Agent or Delegation can administer authority.
- Append `AuthorityRecordV1` entries to a causally ordered authority log with a
  trust root separate from governed content facts and the Release-signing root.
  Implement enrollment challenges and dual-signed Workspace authority-root
  transitions. Enforce `presentation_id` consumption, authorization decision,
  idempotency outcome, and governed consequence in one transaction before a
  result can be disclosed. Fresh C5 authentication and current C6 authorization
  must precede C4 idempotent-result disclosure.
  Treat hash-chain integrity as relative to a trusted later authority head;
  do not claim that local SQLite plus a file-backed signer detects restoration
  of a valid older prefix or fork.
  If the predecessor root is lost before a dual-signed transition, fail fatally
  as root-unavailable/integrity and preserve history. V1 does not recover
  continuity; a new epoch or re-anchor needs a future ADR, Schema, and explicit
  caller trust.
  Treat dual-signed rotation as planned rotation only. A compromised predecessor
  can sign an attacker successor/fork; trust stops at the last independently
  pinned pre-compromise checkpoint, and recovery needs a future trust
  epoch/re-anchor rather than ordinary rotation.
- Implement `DelegationV2` as exactly one Human issuer to one authenticated
  Agent recipient. Evaluate action, resource, budget, time, binding,
  revocation, and policy; reject parent references, subdelegation, chains, and
  cycles rather than partially evaluating them.
- Reserve the exact canonical tokens `changeset:create`, `changeset:add`, `changeset:get`,
  `changeset:diff`, `changeset:validate`, `changeset:submit`,
  `changeset:commit`, `edition:create`, and `release:create`; implement the
  generic exact-set evaluator and all 12 normative operation/version-to-action
  mappings, rejecting unknown pairs. Expose only current status/query/context
  operations. P-0002/P-0005 own write-resource closure and enablement; if they
  require absent scope dimensions, P-0003 must reopen/version before acceptance.
- Enforce payload limits: 4,096-byte command/enrollment canonical payload and
  16,384-byte complete envelopes; 65,536-byte canonical authority record and
  98,304-byte complete authority/root-transition envelope. Generate and verify
  Schema-maximum `AuthorizationDecisionV2` and `DelegationV2` conformance cases.
- Persist canonical `AuthorizationDecisionV2` allow/deny evidence without
  secrets. Preserve legacy `AuthorizationDecisionV1` semantics and historical
  bytes.
- Separate authentication from consumption. Canonical form, known historical
  binding/key, valid signature, audience, actor, command time, and unseen
  presentation all succeed before any write. Failure writes no decision or
  consumption. Current binding time/revocation and Principal-enabled status are
  authorization checks; their denial consumes and appends a decision, as do
  Delegation, scope, budget, and policy denial. Replay adds no second record.
- Migrate existing workspaces atomically and preserve historical read/Release
  verification.
- Keep CLI and both MCP eras on the same application contracts.
- Under the **Proposed P-0003 profile**, classify authenticated Agent status and
  query operations as `evidence_write` because they consume a presentation and
  append `AuthorizationDecisionV2`; remove MCP `readOnlyHint: true` from those
  tools while preserving nonmutation of governed content. Human ambient reads
  may remain read-only when they append no authority evidence.
- Keep authenticated status/released-query `idempotency_key` null. Each fresh
  presentation is a distinct attempt that appends one consumption and decision
  and returns a newly authorized current read. Classify it `evidence_write` but
  do not mutate governed content/projections; the proposed C4 carve-out excludes
  this bounded security evidence from duplicate governed effects. Keep
  ContextPack build idempotent.

## Explicit non-goals

- No delegated content mutation; that is P-0005.
- No OIDC, HTTP/network/collaboration server, enterprise workload provider, or
  Windows support claim.
- No session-scoped ambient authority.
- Under the **Proposed P-0003 profile**, no chained Delegation,
  `AuthorityEvidenceBundleV1`, enterprise authority service, or portable-bundle
  verification; P-0006 owns the bundle contract and qualification.
- No isolation of mutually hostile same-UID processes and no container/sandbox
  infrastructure. A process with the bootstrap Unix UID or private Workspace
  access is inside Human/admin trust and may use the direct-Human path. P-0004
  provides Agent attribution and authorization contracts; deployment containment
  is qualified by P-0006 through a Human-owned broker/adapter boundary.

## Acceptance criteria

- [ ] A request cannot substitute its authenticated subject, requesting
      Principal, or operating Principal. It may present an explicit Delegation,
      but only a grant cryptographically or adapter-verifiably bound to that
      operating Principal may authorize the request.
- [ ] `requesting_subject_commitment` uses the canonical 32-byte-blind hiding
      commitment vectors; persisted actor-context evidence never contains the
      raw requesting `os/unix` subject or blind, and private opening disclosure
      is audit-policy controlled.
- [ ] `AuthenticatedActorContextEvidenceV1` persists the exact raw-UID-free
      canonical preimage and P-0006 can consume it; `authenticated_at` is proven
      as authentication completion time independent of `evaluated_at`.
- [ ] Binding tests enforce the one-Workspace one-active-key/subject-to-Principal
      invariant, distinct-key rotation for the same Principal, and equality of
      subject hex, `public_key`, enrollment candidate, and verified signer.
- [ ] Binding/Delegation boundary vectors prove
      `issued_at <= not_before < expires_at` and
      `not_before <= evaluated_at < expires_at`; causal disable/revoke wins at
      record sequence irrespective of timestamp.
- [ ] Scope tests prove empty arrays grant none, unused dimensions are ignored,
      required empty dimensions deny, and no empty array becomes wildcard.
- [ ] Under the **Proposed P-0003 profile**, invalid signature, missing or
      inactive binding, actor mismatch, wrong
      Workspace/audience/operation/request digest, not-yet-valid or expired
      presentation, and
      reused `presentation_id` fail before a stored result is disclosed.
- [ ] Excessive future `issued_at` returns `proof.auth.not_yet_valid`;
      `proof.auth.expired` is reserved for `evaluated_at >= expires_at`. Exact
      boundary vectors reproduce the authenticated-actor/conformance contract.
- [ ] Malformed structure may return `proof.auth.malformed`. A well-formed
      unknown binding/key and an invalid signature before proof both return the
      same public `proof.auth.denied`; detailed lookup/signature reasons are
      trusted audit/offline only. Random-unknown and invalid-signature cases
      have parity in public code, shape, persistence, and observable lookup
      behavior. Detailed public post-proof failures require a valid signature
      under a known historical key.
- [ ] Malformed command, signature failure, audience mismatch, binding failure,
      actor mismatch, replay, expiry, revocation, wrong action/resource, and any
      parent/subdelegation/chain input fail closed with
      structured errors. Denial produces no governed content mutation,
      successful idempotency result, projection movement, or external effect. A
      canonical denial/audit record may append only if P-0003 ratifies it, and
      must commit atomically without granting authority.
- [ ] Pre-consumption failures across canonical form, unknown historical
      binding/key, invalid signature, audience, actor, command time, and unseen
      presentation write no decision or consumption. A known historical binding
      plus valid signature authenticates credential control; current
      binding/Principal-state, scope/budget/policy/Delegation denial atomically
      consumes and persists one denial. Replay adds no second record.
- [ ] Audience/actor mismatch remains a pre-consumption authentication failure
      and never appears in `AuthorizationDecisionV2`. A validly signed unknown
      or hidden Delegation selector consumes and persists protected reason
      `proof.authorization.delegation_unavailable`, the bound selector,
      `resolution: not_found_or_hidden`, and null record digest; the public
      Problem is `proof.authorization.denied`.
- [ ] The Unix local Human path remains supported through the same port.
- [ ] A deterministic adapter and portable vectors prove behavior without OS or
      wall-clock dependence.
- [ ] All 12 normative operation/version-to-action mappings reproduce the
      authenticated-actor/conformance table and unknown pairs fail. Only the
      current status/query/context operations are exposed; no P-0004 write is
      enabled.
- [ ] Command, enrollment, authority, and root-transition vectors prove `keyid`
      matches the resolved expected key after verification and reject duplicate,
      permuted, or substituted root-transition identities/signatures.
- [ ] Authority-admin tests derive the enabled ADR-0009 bootstrap Human in the
      broker, require every actor and Delegation issuer to equal it, and reject
      all Agent- or Delegation-authorized administration.
- [ ] Broker tests cover exact normalized-input/envelope pairing through MCP
      stdio and `proof auth execute --invocation -`, enforce the 1,048,576-byte
      frame plus operation cap, and reject path/argv substitution without
      opening an Agent-selected file. Ambient Human CLI is never an Agent path.
- [ ] Maximum-size Decision/Delegation fixtures prove the 65,536-byte authority
      payload and 98,304-byte envelope bounds; command/enrollment remain at
      4,096/16,384 bytes.
- [ ] Predecessor-root loss before transition is fatal and preserves history;
      no P-0004 repair claims recovered continuity or silently establishes a
      new authority epoch.
- [ ] Compromised-root tests prove ordinary dual-sign rotation cannot establish
      recovery: an attacker successor/fork is valid from the compromised key,
      and trust is bounded by the independently pinned pre-compromise checkpoint.
- [ ] A logical retry uses a fresh `AuthenticatedCommandV1` with the same
      idempotency key and equivalent normalized request. The authority log
      proves single consumption; a changed request under the key still fails.
      Fresh C5 authentication and current C6 authorization precede C4 result
      disclosure, so current revocation, disablement, or policy denial withholds
      the earlier result.
- [ ] Hash-chain tests detect mutation and reordering relative to a pinned
      trusted head. They also prove that a valid signed older prefix or fork is
      only internally valid without an independent checkpoint and is not a
      P-0004 rollback-resistance guarantee.
- [ ] Documentation and conformance distinguish same-UID attribution from
      containment: bootstrap-UID/private-Workspace access is Human/admin trust,
      and no P-0004 result alone claims the Milestone 2 bounded-authority exit.
- [ ] `AuthorityRecordV1`, `DelegationV2`, and `AuthorizationDecisionV2`
      canonical bytes and golden vectors are portable inputs for P-0006, but no
      P-0004 evidence claims a complete `AuthorityEvidenceBundleV1`.
- [ ] Every storage version supported immediately before this item, enumerated
      in the receipt, migrates atomically and historical Releases reproduce
      exactly.
- [ ] CLI and modern/legacy MCP conformance prove no transport-specific
      authorization semantics.
- [ ] Capability discovery, CLI explanation, and both MCP eras report
      authenticated Agent reads as `evidence_write` and never advertise
      `readOnlyHint: true`; tests separately prove the governed content read is
      nonmutating.
- [ ] Authenticated status/query keeps `idempotency_key` null; every fresh
      presentation appends exactly one consumption and decision and returns the
      current authorized read. Tests prove `evidence_write` without governed
      content/projection movement. ContextPack build remains idempotent.
- [ ] The full Linux quality gate and a focused falsification review pass.

## Required evidence

Create `docs/work/evidence/P-0004/receipt.md` and `manifest.json` when
executing. Record migration fixtures, authentication/authorization vectors,
denial atomicity, adapter parity, test commands, and residual trust boundaries.

## Completion record

Blocked by P-0003; implementation scope must be reshaped after that decision.

## Residual risks and next-wave update

Record provider-specific concerns deferred to Milestone 3/4 and any constraint
P-0005 must enforce immediately before commit or Release.
