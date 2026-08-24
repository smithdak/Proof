---
id: P-0014
title: Implement route-complete enrollment with usable credentials
status: claimed
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0014
claimed_at: 2026-08-24T14:21:29.492Z
base_sha: 68ac737e4950fd6b6c8f177024e185b54ae88a1b
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement route-complete enrollment with usable credentials

[Back to the work map](../map.md)

## Outcome

The two pending Destination-4 routes are implemented end to end:
`agent-binding.issue/v1` and `oidc-binding.issue/v1` accept authorized
administrative calls, commit their binding closures through the P-0010 unit of
work, and return usable issued credentials. After this item, an external Human
administrator can enroll an Agent Principal and bind an OIDC subject to a
Human Principal over HTTP without any manual database or file manipulation,
and the enrolled identities complete authenticated operations through the
existing nine-route surface.

## Why now

Milestone 3 is accepted and the project owner ratified the
[strategy ladder](../../product/strategy.md), naming Destination 4 — operable
by strangers — as the active destination. Route-complete enrollment with
usable credentials was recorded as a residual at P-0013 acceptance and is the
first promotion: every later Destination 4 item (SDK, deployment artifact,
quickstart) consumes the credentials this item issues.

## Promotion condition

This item is the first dependency-ready successor named by the ratified
Destination 4 shaping decision. No further ratification is required before
implementation.

## Authorized scope

- Implement `agent-binding.issue/v1`: an `authority.admin` caller supplies the
  required UUIDv7 command identifier, exact authority head, and enrollment
  closure; the server verifies authorization, commits the binding through the
  unit of work with idempotency keyed on the command identifier, appends the
  authority closure evidence, and returns the issued Agent binding material
  exactly once.
- Implement `oidc-binding.issue/v1`: an `identity.admin` caller supplies the
  required UUIDv7 command identifier, exact subject, target Principal, issuer
  configuration reference, and exact authority head; the server validates and
  commits the subject commitment and returns the bound identity state.
- Both operations reuse the existing remote decision successor artifacts,
  frozen operation registry entries, Problem codes, and conformance envelope
  rules already ratified by P-0009 through P-0013. No new wire surface,
  storage schema version, or operation registry entry is introduced.
- Extend the deterministic semantic oracle coverage so local/server trace
  parity includes both new operations where a local counterpart exists, or
  record the precise topology-specific boundary where it does not.
- Add retained conformance vectors for allow, rejection (wrong authority
  head, stale head, non-admin caller, duplicate command identifier, malformed
  closure), and replay outcomes for both routes.
- Update the changelog and any affected reference documentation.

## Explicit non-goals

- Credential rotation, revocation UX beyond the existing
  `agent-binding.revoke/v1` artifact semantics, signing-key lifecycle, and
  Environment configuration update remain fog.
- The PostgreSQL-backed application semantic executor residual is a separate
  successor and is not claimed here.
- No SDK, deployment artifact, documentation site, license selection, push,
  tag, or public release is authorized by this item.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md),
  including the operation registry rows for `agent-binding.issue/v1` and
  `oidc-binding.issue/v1`.
- [Authenticated actor contract](../../architecture/authenticated-actor.md)
  for Agent binding material and authority closure semantics.
- ADR-0013 for the single-Workspace server boundary.

## Acceptance criteria

1. Both routes return issued credential material on the allow path and the
   exact ratified Problem codes on each audited rejection path; no call path
   returns `proof.dependency.unavailable` for either operation.
2. Issued credentials authenticate successfully through the existing dual
   authentication boundary and complete at least one consequential governed
   operation end to end in retained tests.
3. The semantic oracle passes for both operations under the same normalized
   input rules as the retained surface, or the item records the exact
   topology boundary and its justification in the completion record.
4. New conformance vectors pass against the frozen registry hashes and are
   consumed immutably per the testing strategy.
5. The full Linux quality gate passes: fmt, clippy `-D warnings`, workspace
   tests, doc tests, doc links, and work-item validation.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0014/`. The manifest binds
the qualified item-work commit, parent/base SHA, commands, and tool versions
per the [work-control protocol](../README.md).

## Completion record

Populated after acceptance.
