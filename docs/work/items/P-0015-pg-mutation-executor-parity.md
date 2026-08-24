---
id: P-0015
title: Implement the PostgreSQL-backed application semantic executor for full mutation-row trace parity
status: ready
wave: now
kind: implementation
blocked_by: []
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the PostgreSQL-backed application semantic executor for full mutation-row trace parity

[Back to the work map](../map.md)

## Outcome

The deferred P-0010 residual is closed: the PostgreSQL path executes the full
11-row localized `/v2` mutation surface through a PG-backed application
semantic executor, and byte-identical SQLite/PostgreSQL oracle traces cover
every mutation row, not only the retained read subset. Local mode and server
mode produce the same typed application result, governed facts, stable
Problem code, and idempotency/concurrency outcome for equivalent normalized
input at the same authoritative state, row for row.

## Why now

P-0010 shipped PostgreSQL parity for the durable foundation with an explicit
"not yet mirrored" residual on full mutation semantics; P-0013's acceptance
recorded it as a Milestone 3 residual. The project owner ratified the
[strategy ladder](../../product/strategy.md) naming Destination 4, whose exit
requires strangers to drive the north-star localization loop remotely — that
loop is mutation-heavy, so full trace parity is its correctness floor. This
item is the second Destination 4 promotion after accepted P-0014.

## Promotion condition

P-0014 is `done`. This item is the next dependency-ready successor in the
ratified ladder order.

## Authorized scope

- Implement the PG-backed semantic executor for all 11 localized `/v2`
  mutation operations through the P-0010 unit of work, reusing the frozen
  operation registry, artifact catalog, outbox enqueue, and projection-swap
  machinery without schema changes.
- Extend the deterministic semantic oracle so every mutation row produces
  byte-identical normalized traces against both storage adapters, and retain
  those traces as conformance vectors per the testing strategy.
- Preserve exact rejection parity: every audited rejection code reachable
  locally is reachable server-side with the identical stable Problem digest.
- Update the changelog and affected reference documentation.

## Explicit non-goals

- No SDK, deployment artifact, documentation site, or license ADR work; those
  are later ladder promotions.
- No new operation registry rows, storage schema version, or wire surface.
- Enrollment residuals beyond accepted P-0014 are out of scope.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md),
  §"PostgreSQL authoritative unit of work" and the shared-oracle rule.
- [Testing strategy](../../architecture/testing.md) for vector immutability.
- ADR-0007 (modular monolith) and ADR-0013 (single-Workspace boundary).

## Acceptance criteria

1. All 11 localized `/v2` mutation rows execute through the PG executor with
   Success outcomes matching local results byte-for-byte at the oracle layer.
2. Every locally reachable rejection code for those rows reproduces
   server-side with the identical stable Problem digest.
3. Byte-identical SQLite/PostgreSQL traces are retained as consumed-once
   conformance vectors covering every mutation row.
4. The complete remote north-star still reaches verifier Complete after the
   migration of those rows onto the PG executor.
5. The full Linux quality gate passes.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0015/` per the
[work-control protocol](../README.md).

## Completion record

Populated after acceptance.
