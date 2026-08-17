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

## Authorized scope

- Implement the identity port, local adapter, deterministic fake adapter, and
  credential/binding lifecycle selected by P-0003.
- Replace request-declared operating identity with authenticated actor context
  at application boundaries.
- Implement exact action/resource/budget, time, revocation, and direct-or-chain
  Delegation evaluation selected by P-0003.
- Persist canonical authorization decisions and operation evidence without
  secrets.
- Migrate existing workspaces atomically and preserve historical read/Release
  verification.
- Keep CLI and both MCP eras on the same application contracts.

## Explicit non-goals

- No delegated content mutation; that is P-0005.
- No OIDC, HTTP server, enterprise workload provider, or Windows support claim.
- No session-scoped ambient authority.

## Acceptance criteria

- [ ] A request cannot substitute its authenticated subject, requesting
      Principal, or operating Principal. It may present an explicit Delegation,
      but only a grant cryptographically or adapter-verifiably bound to that
      operating Principal may authorize the request.
- [ ] Mismatch, unknown binding, disabled credential, replay, expiry,
      revocation, wrong action/resource, and malformed chain fail closed with
      structured errors. Denial produces no governed content mutation,
      successful idempotency result, projection movement, or external effect. A
      canonical denial/audit record may append only if P-0003 ratifies it, and
      must commit atomically without granting authority.
- [ ] The Unix local Human path remains supported through the same port.
- [ ] A deterministic adapter and portable vectors prove behavior without OS or
      wall-clock dependence.
- [ ] Every storage version supported immediately before this item, enumerated
      in the receipt, migrates atomically and historical Releases reproduce
      exactly.
- [ ] CLI and modern/legacy MCP conformance prove no transport-specific
      authorization semantics.
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
