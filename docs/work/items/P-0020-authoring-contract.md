---
id: P-0020
title: Ratify the authoring-surface content contract
status: claimed
wave: now
kind: decision
blocked_by: []
claimed_by: ox-alpha:proof:p-0020
claimed_at: 2026-08-26T10:00:59.999Z
base_sha: e53920b6113b67abaff4828ee7ddc4266fe2915a
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Ratify the authoring-surface content contract

[Back to the work map](../map.md)

## Outcome

Proof has a decision-complete contract for the smallest authoring slice in
which Humans and Agents create new Objects and browse Schemas and committed
draft state through the governed operation surface, and the console can build
an Authoring register on frozen artifact shapes without inventing UI-only
semantics. Creation enters through the atomic ChangeSet path like every other
mutation; approval stays Human-only; evidence remains reproducible end to end.

## Why now

Destination 4's shaped ladder is complete through P-0019. The ratified product
thesis claims a CMS, but the implemented v2 vocabulary contains exactly one
edit kind (`object.locale.put`) against pre-existing Objects; creation exists
only in the legacy local v1 loop (`schema.create`, `object.create` via CLI
NDJSON), there is no Schema read surface, no draft-state query, and no template
concept anywhere. Every further destination — stranger-operable authoring,
console depth, agent-authored content — freezes bad approximations unless the
authoring contracts are shaped first. The project owner has directed: full
vertical first, flat content model, blueprints as schema presets.

## Decision questions

- By what mechanism does base-Object creation enter the v2 governed path: a
  new versioned edit kind carried inside `changeset.add/v2` ChangeSets, a
  standalone authenticated operation, or another composition — and how does it
  preserve that direct writes do not exist?
- What minimal Schema read surface (`schema.list`, `schema.get`) reproduces
  stored `schema_versions` faithfully, and which registries carry those rows
  (Agent authority rows, Human HTTP rows, MCP capabilities)?
- What draft-state register read exposes committed-but-unreleased content,
  with which exact-tuple discipline, filters, limits, and result shape, so no
  wildcard or latest-state overclaim re-enters the system?
- Who may read drafts: which Human workspace roles see unreleased state, and
  do Agent reads stay bounded by ContextPack closure and re-authorization?
- What is the content-model stance: confirm the flat model for this
  destination, record subtree authority as deferred-not-decided, name the
  sanctioned structure-as-view escape hatch, and pin the falsifiable trigger
  that reopens hierarchy as a future ratification?
- What do blueprints mean: client-side starting points (Schema pick plus
  optional prefilled field values) composed from existing operations, versus a
  domain entity — and what must never become console-only mutation?
- Which storage, projection, migration, registry-hash, and conformance-vector
  changes does the ratified contract impose on its implementation successor?

## Authorized scope

- Decide the exact creation mechanism and freeze its input/result/Problem
  shapes, validation semantics against Draft 2020-12 Schemas, idempotency,
  concurrency preconditions, and evidence consequences at parity with the
  existing localized path.
- Freeze the Schema read surface and the draft-state register read surface,
  including their registry assignments and capability discovery entries.
- Define draft-read authorization: Human role gating plus any Agent bound-read
  rule, consistent with existing re-authorization requirements.
- Ratify the flat content-model stance with subtree authority explicitly
  deferred-not-decided, the sanctioned escape hatch (Schema-level parent
  self-reference fields inside specific Schemas; projection-side groupings as
  views, never truth), and the reopening trigger: a single Human-resolved
  campaign resource-intent exceeding 100 exact Object IDs, or two consecutive
  qualification runs reporting selection friction as their dominant cost.
- Ratify the blueprint stance: client-side presets (Schema selection plus
  optional initial field values) that compose into ordinary ChangeSets; no new
  domain entity; no governance bypass.
- Enumerate the storage, migration, projection, frozen-hash, and vector
  regeneration plan the implementation successor inherits.
- Name the dependency-ordered successor graph and promote only the first
  implementation successor after owner acceptance.

## Explicit non-goals

- No hierarchy entity, tree storage, closure tables, descendant grants,
  node-move semantics, or URL/page-tree delivery in this destination.
- No Template, content-type, or blueprint domain entity; no locale fallback or
  negotiation; no rendition deletion; no base-Object replacement; no
  relationship localization; no dynamic campaign/subtree selection.
- No implementation code, server routes, SDK changes, console surfaces, or MSW
  handlers while executing this item; those belong to its successors.
- No push, tag, public release, package publication, or license action.

## Applicable contracts

- [Core invariants](../../architecture/constitution.md)
- [Domain model](../../architecture/domain-model.md)
- [Authenticated actor contract](../../architecture/authenticated-actor.md)
- [Agent authority and ContextPacks](../../architecture/agent-authority.md)
- [Proof format and verification](../../architecture/proof-model.md)
- [Testing strategy](../../architecture/testing.md)
- [Roadmap](../../product/roadmap.md)
- [P-0015 completion record](items/P-0015-pg-mutation-executor-parity.md)

## Acceptance criteria

- [ ] One exact authoring north-star names the requesting Human, operating
      Agent, distinct reviewer/approver, created Object and Schema, ChangeSet
      composition, Edition/Release, and independent verifier inputs.
- [ ] The creation mechanism is decided with frozen input, result, Problem,
      validation, idempotency, concurrency, and evidence contracts, and the
      strongest rejected alternative is recorded with kill or pivot triggers.
- [ ] The Schema read surface and draft-state register read are frozen with
      exact-tuple discipline, explicit filters and limits, and no wildcard or
      globally-latest overclaim.
- [ ] Draft-read authorization is exact: which Human roles see unreleased
      state, how Agent reads stay bounded, and why untrusted input cannot
      select authority.
- [ ] The flat stance, deferred subtree-authority record, sanctioned escape
      hatch, and falsifiable reopening trigger appear verbatim in the ratified
      decision artifact.
- [ ] The blueprint stance composes only ratified operations and cannot become
      a console-only mutation path.
- [ ] The storage, migration, projection, frozen-hash, and conformance-vector
      plan is complete enough for the implementation successor to estimate and
      execute without re-deciding scope.
- [ ] A conformance-matrix extension covers accepted and rejected authoring
      operations across local, server, CLI, and MCP surfaces.
- [ ] Only decision-complete successors exist, in dependency order, and none
      is `ready` before the project owner accepts this decision.
- [ ] The project owner accepts the decision candidate before any successor
      promotion.

## Evidence contract

Record the proposed north-star, operation and registry matrices, artifact
shapes, authorization analysis, alternatives with triggers, storage and vector
plan, conformance-matrix extension, and successor graph in
`docs/work/evidence/P-0020/` per the [work-control protocol](../README.md).
Stop at `review` after a qualified decision candidate. Do not implement any
operation, route, SDK, or console change while executing this item.

## Progress log

- 2026-08-26: shaped with the project owner in session. Owner decisions
  recorded: full vertical first (contracts before console); flat content model;
  blueprints as client-side Schema presets; subtree authority deferred with
  recorded reopening conditions rather than promoted into this ratification.
- Slice 1 (2026-08-26): claimed from `e53920b6113b67abaff4828ee7ddc4266fe2915a`.
  Groundwork research executed against the claimed base: registry row anatomy
  (`AuthorityOperationEntry`, `HumanOperationRowV1`, frozen-hash computation),
  the single-edit-kind touchpoint inventory, and draft-state storage reality
  (SQLite content tables, PG facts/projections, read authorization plumbing).
- Slice 2 (2026-08-26): decision candidate authored at
  [contract.md](../evidence/P-0020/contract.md) — D1 creation as a second v2
  edit kind with intra-ChangeSet causality; D2 intent closure extended with
  creation slots (`content-resource-intent/v2`, Agent registry untouched);
  D3 `schema.list/get` Human rows, Agents stay on ContextPack schemas;
  D4 `object.list/v1` committed-state register with release-status pairs;
  D5 flat stance ratified with deferred subtree authority and falsifiable
  reopening trigger; D6 blueprints as client-side presets; D7 storage plan
  (SQLite v15 kind column, PG facts arm, no projection change); D8 frozen-
  artifact impact matrix (Agent hash stable, HTTP/authorization hashes
  recompute). Successor order P-0021→P-0024 recorded. Awaiting project-owner
  review before any promotion.
