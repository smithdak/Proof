---
id: P-0015
title: Implement the PostgreSQL-backed application semantic executor for full mutation-row trace parity
status: claimed
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0015
claimed_at: 2026-08-24T15:44:01.312Z
base_sha: b5ff8f9c42c9b2991979a67a37b521baf514a552
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

## Progress log

- Slice 1 (2026-08-24): the parity importer now carries the localized
  mutation state into PostgreSQL — every `localized_changesets` row as a
  canonical projection fact cross-checked against its imported intent and
  ContextPack evidence, every localized Edit artifact digest-verified under
  `EditV2`, and every validation attempt with its results digest verified —
  so all subsequent executor rows consume imported, re-verified state. The
  accepted-vector inventory grew by the two P-0014 enrollment vectors
  (39 -> 41) and gained the shared `enrollment-vector-v1` Schema. Full Linux
  gate green at this slice.
- Slice 2 (2026-08-24): root-caused the harness thread — localized renditions
  must inherit non-localizable fields verbatim from the source Object
  (`verify_edit_input` reconstructs source-plus-localized-pointers and
  requires exact equality); the fixture now varies only `/legal` and
  `/title`. The import-fidelity test passes unignored. The PostgreSQL
  executor gained its first mirrored row: `changeset.get/v2` reconstructs
  the typed `LocalizedChangeSet` from imported facts with full reference
  semantics (evidence-reference reproduction, contiguous ordinals,
  effective-leaf marking, proposal/effective digest recomputation,
  seal-vs-validation-head, and complete repair-edge verification) and
  serializes through the shared oracle serializers. A retained parity test
  proves byte-identical accepted and not-found traces against SQLite; the
  P-0013 conformance report classification for this row flipped from the
  ratified not-mirrored residual to byte-identical accordingly.

## Completion record

Populated after acceptance.
