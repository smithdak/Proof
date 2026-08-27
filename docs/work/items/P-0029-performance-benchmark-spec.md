---
id: P-0029
title: Ratify the Proof performance benchmark specification
status: ready
wave: now
kind: decision
blocked_by: [P-0026]
required_reading: [docs/product/vision.md, docs/architecture/technology-baseline.md]
allowed_paths: [docs/decisions, docs/product, docs/work]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Ratify the Proof performance benchmark specification

[Back to the work map](../map.md)

## Outcome

A ratified benchmark specification defining the measurable performance and
operability targets Proof must meet to claim superiority over Sitecore-class
systems. Covers latency, throughput, concurrency, bulk operations, publish
cost, evidence cost, and recovery time under realistic enterprise workloads.

## Why now

"Better performance because Rust" is a hypothesis until measured. This
specification converts the performance claim into falsifiable, repeatable
benchmarks that implementation waves must satisfy before the completeness gate
closes.

## Scope

- Define benchmark workloads: single-operation latency, bulk import/export,
  concurrent agent mutation, publish pipeline cost, evidence generation cost,
  rollback/recovery time, and search/filter latency.
- For each workload: name the exact operation sequence, dataset shape, scale,
  concurrency level, and pass/fail threshold.
- Benchmarks must run against the real operation kernel (not mocks) and must
  produce reproducible evidence artifacts.
- Sitecore reference numbers may be directional, not exact, given licensing
  constraints; Proof's own targets are absolute, not relative.

## Non-goals

- No implementation work.
- No UI work.
- No benchmark execution (that belongs to implementation waves).
- No architecture change.

## Acceptance evidence

- A ratified decision document in `docs/decisions/` with complete workload
  definitions, thresholds, and reproducibility requirements.
- Project-owner acceptance recorded per work-item protocol.

## Completion record

Not started
