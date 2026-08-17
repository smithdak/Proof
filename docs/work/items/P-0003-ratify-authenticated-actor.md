---
id: P-0003
title: Ratify authenticated actor and Delegation semantics
status: ready
wave: now
kind: decision
blocked_by: [P-0001]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Ratify authenticated actor and Delegation semantics

[Back to the work map](../map.md)

## Outcome

Proof has a versioned local authentication and delegated-authorization contract
that binds an authenticated workload subject to an Agent Principal without
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

## Acceptance criteria

- [ ] The authenticated subject, requesting Principal, operating Principal,
      Delegation, and runtime/model metadata are distinct typed concepts.
- [ ] Untrusted CLI/MCP input cannot select or substitute the authenticated
      subject or operating Principal without cryptographic/adapter proof.
- [ ] Issuance, use, anti-replay, rotation, disablement, revocation, recovery,
      and key-compromise behavior are specified.
- [ ] Direct-versus-chained Delegation semantics are reconciled with the
      ratified docs, including deny-by-default intersection and cycle behavior.
- [ ] Canonical bytes, size/time bounds, errors, and conformance vectors are
      defined for every new contract.
- [ ] The strongest rejected design and residual trust boundary are recorded.
- [ ] The project owner explicitly accepts the decision before this item moves
      from `review` to `done` or any implementation successor becomes `ready`.
- [ ] P-0004 and P-0006 are reshaped and promoted only if implementation scope
      is now decision-complete.

## Evidence contract

Record the proposed decision here, link proposed ADRs and threat-model changes,
and stop at `review`. After project-owner acceptance, populate
`accepted_by`/`accepted_at`, ratify the artifacts, and add the one-line result to
the map. Cite prototypes or vectors used to falsify the chosen boundary.

## Completion record

Ready after P-0001 qualified the Release and read-authority baseline at
`1fef16e8d0f9d355957abc6f973b3551a2c922cb`.

## Residual risks and next-wave update

Separate local Milestone 2 guarantees from later enterprise identity and key
custody requirements. Do not turn provider selection into a domain invariant.
