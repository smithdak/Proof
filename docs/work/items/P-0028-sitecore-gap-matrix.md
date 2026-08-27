---
id: P-0028
title: Produce the Sitecore-to-Proof capability gap matrix
status: blocked
wave: now
kind: implementation
blocked_by: [P-0026, P-0027]
required_reading: [docs/product/sitecore-pain-points.md]
allowed_paths: [docs/product, docs/work]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Produce the Sitecore-to-Proof capability gap matrix

[Back to the work map](../map.md)

## Outcome

A row-per-capability matrix mapping every ratified canon capability (P-0026) to
its Sitecore counterpart, its current Proof state, its disposition, and its
bounded implementation wave assignment. This is the executable roadmap for
backend completeness.

## Why now

The canon defines what must exist. The gap matrix converts it into wave-scoped
implementation assignments so backend waves are sequenced, bounded, and
directly traceable to competitive evidence and pain elimination.

## Scope

- One row per canon capability: capability name, Sitecore reference behavior,
  Proof disposition, current Proof state, implementation wave, and acceptance
  evidence type.
- Assign every not-yet-implemented capability to a bounded implementation wave
  (W1, W2, W3…) with explicit dependency ordering.
- Wave boundaries must respect `allowed_paths` disjointness so waves can execute
  in parallel where dependencies allow.
- Flag any capability where Sitecore evidence is insufficient to shape a
  bounded item, and name the research needed before that item is ready.

## Non-goals

- No implementation work.
- No UI work.
- No performance benchmark specification (P-0029).
- No architecture change beyond what P-0026 already ratified.

## Acceptance evidence

- A committed gap matrix in `docs/product/` with one row per canon capability.
- Every row names its wave, dependencies, and acceptance evidence type.
- Project-owner acceptance recorded per work-item protocol.

## Completion record

Not started
