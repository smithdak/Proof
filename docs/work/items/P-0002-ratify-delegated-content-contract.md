---
id: P-0002
title: Ratify the Milestone 2 delegated content contract
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

# Ratify the Milestone 2 delegated content contract

[Back to the work map](../map.md)

## Outcome

Proof has one ratified, testable definition of the content mutations required
for Milestone 2. The roadmap's two-locale localization scenario, Delegation
resource scopes, validation behavior, and persistence consequences agree.

## Why now

The current edit model creates Schemas and Objects but cannot modify an existing
Object or express locale variants. Implementing an agent write path first would
either produce a create-only demonstration that does not satisfy the ratified
north star or invent content semantics inside an adapter.

## Decision question

What is the smallest content-semantic increment that makes the Milestone 2 exit
scenario true without pulling Milestone 3 or general DXP concerns forward?

The decision must explicitly accept one route or a better evidenced alternative:

1. Add existing-Object revision/update and the minimum locale/variant semantics
   needed for the north-star localization flow.
2. Insert a named content-foundation prerequisite inside Milestone 2 and keep
   the north-star claim unchanged.

A create-only loop may be raised only as a product re-charter requiring explicit
project-owner authorization; it cannot satisfy this item autonomously by
weakening the already-ratified Milestone 2 exit condition.

## Authorized scope

- Inspect product, domain, canonicalization, validation, ChangeSet, Known State,
  Edition, Release, query, and migration consequences.
- Define exact Edit kinds, lifecycle/revision behavior, resource and locale
  scope, conflict behavior, relationships, and compatibility requirements.
- Record the decision in an ADR when it changes or completes architecture.
- Reconcile the vision, roadmap, scope, domain model, CLI reference, and tests.
- Reshape P-0005 and P-0006 from the decision; do not implement them here.

## Explicit non-goals

- No delegated write implementation.
- No collaboration server, visual localization UI, translation provider, model
  integration, or campaign orchestration.
- No generic personalization or variant-selection engine.

## Applicable contracts

- [Vision and north-star scenario](../../product/vision.md)
- [Scope](../../product/scope.md)
- [Roadmap](../../product/roadmap.md)
- [Domain model](../../architecture/domain-model.md)
- [Core invariants](../../architecture/constitution.md)

## Acceptance criteria

- [ ] The decision names the minimum supported user outcome and rejected
      alternative, with mechanism-level rationale.
- [ ] Every required Edit kind and state transition has a canonical input,
      conflict rule, validation rule, and authoritative projection consequence.
- [ ] Delegation scope dimensions are sufficient to constrain the selected
      content behavior without relying on path prefixes or prose alone.
- [ ] Schema, migration, Known State, Edition, Release, query, and proof-format
      compatibility impacts are explicit.
- [ ] The north-star scenario and Milestone 2 exit condition no longer overclaim
      implemented or planned semantics.
- [ ] The project owner explicitly accepts the decision before this item moves
      from `review` to `done` or any implementation successor becomes `ready`.
- [ ] P-0005 and P-0006 are reshaped; any newly sharp prerequisite becomes a
      linked item, while remaining uncertainty stays in map fog.

## Evidence contract

Record the proposed decision and evidence links in this item, link any proposed
ADR, and stop at `review`. After project-owner acceptance, populate
`accepted_by`/`accepted_at`, ratify the decision, add the one-line result to the
map, and promote successors. Prototype code may falsify a design but is not
production implementation for this item.

## Completion record

Ready after P-0001 qualified the Release and read-authority baseline at
`1fef16e8d0f9d355957abc6f973b3551a2c922cb`.

## Residual risks and next-wave update

Record content concerns intentionally deferred beyond the selected Milestone 2
scenario, especially relationship graphs, fallback, migration, and scale.
