---
id: P-0003
title: Ratify authenticated actor and Delegation semantics
status: done
wave: now
kind: decision
blocked_by: [P-0001, P-0002]
claimed_by: codex:/root:p-0003
claimed_at: 2026-08-20T18:58:18Z
base_sha: 8aede43c1e4ec7f24bc0fd4761aa117a5173bfa8
review_gate: project-owner
accepted_by: smithdak
accepted_at: 2026-08-20T19:52:12.756Z
---

# Ratify authenticated actor and Delegation semantics

[Back to the work map](../map.md)

## Outcome

Proof has a versioned local authentication and delegated-authorization contract
that binds an authenticated Agent credential subject to an Agent Principal without
collapsing requesting human, operating Agent, runtime metadata, or transport
session into one identity.

## Why now

Current delegated reads accept request-supplied Principal and Delegation IDs,
while the local repository authenticates only the bootstrap Unix user. Exposing
mutations on that boundary would let a caller select its asserted operating
identity instead of proving control of it.

## Decision questions

- What credential proves control of a local Agent Principal?
- What adapter-authenticated actor context reaches application operations, and
  which identity fields are forbidden in untrusted request bodies?
- How are credentials issued, stored, rotated, disabled, and recovered without
  moving secrets into content, ContextPacks, logs, or Proof predicates?
- How do canonical command authentication, anti-replay, time bounds, and
  idempotency compose?
- What bounded chain representation and evaluation rules implement
  complete-chain intersection for Milestone 2? A direct-only profile is
  admissible only if subdelegation is explicitly unsupported and the ratified
  agent-authority contract is reconciled by ADR.
- Which authority records and revocations must be portable outside SQLite for
  independent verification?

## Proposed resolution

The complete ratified contract is
[Authenticated actor](../../architecture/authenticated-actor.md), recorded by
accepted [ADR-0011](../../decisions/0011-local-agent-command-authentication.md)
and the machine-readable
[authority conformance profile](../../../conformance/v1/authority/README.md).

The recommendation is:

- retain the authenticated Unix Human as requesting Principal and local
  recovery/issuance root;
- authenticate the operating Agent with per-command Ed25519 proof of possession
  under an immutable `PrincipalBindingV1`;
- derive `AuthenticatedActorContextV1` behind an application authentication
  port; caller-supplied identifiers are signed mismatch guards or selectors,
  never identity proof;
- sign binding, direct Delegation, and revocation facts in an append-only
  Workspace authority sequence with a key distinct from Agent and Release keys;
- support exactly one direct Human-to-Agent `DelegationV2` for Milestone 2 and
  reject Agent issuers, parents, chains, and subdelegation explicitly;
- make every authenticated presentation single-use, with a five-minute maximum
  validity and 30-second future-skew allowance; and
- retry consequential work with a fresh presentation and the same semantic
  application idempotency key.

The bounded claim is credential control, not workload or model attestation.
Same-UID key theft remains a ratified local residual. OIDC, SPIFFE, protected
platform credentials, Windows identity, KMS/HSM, and a final portable evidence
bundle remain adapter or successor work.

## Decisive tradeoff

The strongest alternative is SPIFFE/mTLS with short-lived workload credentials.
It is stronger against process substitution, but it requires a daemon or secure
channel, an issuance/rotation plane, workload selectors, and historical trust
material before it solves exact command binding. No Milestone 2 outcome requires
that deployment boundary.

Direct-only Delegation deliberately replaces the current full-chain direction
for Milestone 2. Full chains add adjacency, parent-digest, intersection,
cycle/depth, revocation-closure, and issuer-authentication obligations without a
demonstrated scenario. A future chain requires `DelegationV3` and a new ADR;
v2 meaning will not drift.

The decision must be reopened if Milestone 2 must isolate mutually hostile
same-UID processes, attest a binary/model/runtime, avoid every callable local
Agent secret, or support Agent-to-Agent delegation.

## Authorized scope

- Compare local per-Agent signing credentials, OS/process subject bindings, and
  other viable local adapters.
- Define an application identity port and deterministic conformance adapter.
- Define versioned Principal binding, Delegation, authorization-decision, and
  command-authentication Schemas.
- Update the threat model, agent-authority contract, ADRs, and downstream item
  shapes.
- Keep OIDC, SPIFFE, cloud workload identity, and KMS implementations deferred;
  their future adapters must fit the chosen port.

## Explicit non-goals

- No production authentication implementation.
- No server session, OAuth/OIDC flow, enterprise identity provider, or KMS/HSM.
- No authority derived from MCP initialization, request `_meta`, natural
  language, or possession of a ContextPack.

## Applicable contracts

- [Agent authority](../../architecture/agent-authority.md)
- [Core authority and interface invariants](../../architecture/constitution.md)
- [Threat model](../../architecture/threat-model.md)
- [Local bootstrap identity decision](../../decisions/0009-local-bootstrap-principal.md)
- [Dual-era MCP decision](../../decisions/0010-dual-era-mcp.md)
- [Proposed local Agent authentication decision](../../decisions/0011-local-agent-command-authentication.md)

## Acceptance criteria

- [x] The authenticated subject, requesting Principal, operating Principal,
      Delegation, and runtime/model metadata are distinct typed concepts.
- [x] Untrusted CLI/MCP input cannot select or substitute the authenticated
      subject or operating Principal without cryptographic/adapter proof.
- [x] Issuance, use, anti-replay, rotation, disablement, revocation, recovery,
      and key-compromise behavior are specified.
- [x] Direct-versus-chained Delegation semantics are reconciled with the
      ratified docs, including deny-by-default intersection and cycle behavior.
- [x] Canonical bytes, size/time bounds, errors, and conformance vectors are
      defined for every new contract.
- [x] The strongest rejected design and residual trust boundary are recorded.
- [x] ADR-0011 is explicitly Constitutional, enacts the exact C4 replacement
      text, and records the behavioral compatibility boundary.
- [x] `AuthorityOperationRegistryV1` retains only the three implemented v1
      reads, cross-links all 11 P-0007 v2 input Schemas, and freezes their
      action, closure anchor, resource/budget projections, evidence selectors,
      retry class, consequence, and enablement wave.
- [x] `DelegationV2` and `AuthorizationDecisionV2` use P-0002's exact locale
      grammar; vectors accept lowercase variants and literal aliases and reject
      mixed-case variants.
- [x] The project owner explicitly accepts the decision before this item moves
      from `review` to `done` or any implementation successor becomes `ready`.
- [x] P-0004 and P-0006 are reshaped and promoted only if implementation scope
      is now decision-complete.

## Evidence contract

Record the proposed decision here, link proposed ADRs and threat-model changes,
and stop at `review`. After project-owner acceptance, populate
`accepted_by`/`accepted_at`, ratify the artifacts, and add the one-line result to
the map. Cite prototypes or vectors used to falsify the chosen boundary.

## Completion record

Ready after P-0001 qualified the Release and read-authority baseline at
`1fef16e8d0f9d355957abc6f973b3551a2c922cb`.

Claimed by `codex:/root:p-0003` at `2026-08-17T20:41:57.212Z` from
`11eb4dfb57577e52ddd95822a00fed3001b5164a`. The architecture and conformance
checkpoint is `cf4e57d0ace70e80377d16b57e43b6099129e0d0`; the integrated item-work
commit is `b124b2491dfd787df1a562786f122fb6e62a1497`.

That initial candidate, machine contracts, vectors, downstream shaping, and
independent falsification were complete, but P-0002 subsequently ratified a
localized v2 write-resource closure that required reconciliation before review.

Reclaimed by `codex:/root:p-0003` at `2026-08-20T18:58:18Z` from
`8aede43c1e4ec7f24bc0fd4761aa117a5173bfa8` on
`proof-architecture/p-0003-reconciliation`. The reconciled candidate:

- retains only the three implemented v1 read pairs and binds all 11 P-0007 v2
  pairs to their exact operation Schemas;
- freezes complete-intent and staged released-query resource projections,
  evidence selectors, five budget profiles, retry classes, consequences, and
  enablement wave in `AuthorityOperationRegistryV1`;
- aligns Delegation and decision locale grammar with P-0002; and
- adds a retained cross-profile test plus rejected vectors for registry drift,
  mixed-case variants, superseded v1 writes, and each missing localized grant
  axis.

The refreshed [qualification receipt](../evidence/P-0003/receipt.md) records the
exact candidate and validation results. The item entered `review` at commit
`2d6f87301e75031f5c6f43e90dea525b27f167cf`.

Project owner `smithdak` accepted the bounded decision at
`2026-08-20T19:52:12.756Z`. ADR-0011 and its exact C4 replacement are ratified,
P-0003 is `done`, and P-0004 is promoted to `ready`. Acceptance does not claim
that an authenticated Agent path is implemented.

## Residual risks and next-wave update

Separate local Milestone 2 guarantees from later enterprise identity and key
custody requirements. Do not turn provider selection into a domain invariant.

The selected local profile does not defend an Agent key from another hostile
process under the same Unix UID and does not attest process, executable, model,
or runtime identity. Those are explicit boundaries, not inferred guarantees.
Any process under the bootstrap UID can also use the ambient Human path, so
same-UID Agent execution provides attribution rather than containment. The
Milestone 2 bounded-authority claim requires an Agent outside the bootstrap
UID/private-Workspace boundary, connected only through the authenticated
broker or adapter surface, and must be qualified by P-0006.
It also does not detect rollback to an older valid authority prefix when the
Workspace database and file-backed signer state are restored together; that
claim requires an independently retained authority-head checkpoint or a
stateful external trust service. Idempotent result replay remains subordinate
to fresh authentication and current authorization. Dual-signed root rotation
does not repair predecessor compromise; that requires a pinned pre-compromise
checkpoint and a future explicit trust epoch.
