---
id: P-0002
title: Ratify the Milestone 2 delegated content contract
status: done
wave: now
kind: decision
blocked_by: [P-0001]
claimed_by: codex:/root:p-0002
claimed_at: 2026-08-18T01:07:37.311Z
base_sha: d6532ffcd9ea00dc18c31005695a40692b1f8cc2
review_gate: project-owner
accepted_by: smithdak
accepted_at: 2026-08-18T12:44:20.977Z
required_reading: []
allowed_paths: []
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

## Proposed resolution

Accept route 1 as the content contract and route 2 as the delivery sequence:
ratify the minimum existing-Object localization semantics now, implement them
through the Human path in P-0007, and only then bind Agent authority in P-0005.
The complete candidate is the
[delegated content contract](../../architecture/delegated-content.md), recorded
by proposed
[ADR-0012](../../decisions/0012-localized-object-renditions.md).

The minimum supported user outcome is exact-locale localization of an existing
Object. Existing `ObjectRevisionV1` content remains the immutable,
locale-neutral source. `proof.dev/edit/v2` adds one mutation kind,
`object.locale.put`, which creates or revises a separate append-only
`ObjectLocaleRevisionV1` identified by the stable Object ID and one restricted
canonical locale. The Edit carries the complete proposed localized content and
exact source/target preconditions. It cannot mutate the source Object, Schema,
relationships, lifecycle, or another locale.

Schema metadata declares a sorted, non-overlapping set of localizable JSON
Pointer leaves. Localized content must remain equal to the source at every
other location and must validate against the same exact Schema. A missing
target precondition creates revision 1; an exact prior target revision and
digest creates revision N+1. Full replacement was selected instead of JSON
Patch so canonical bytes, conflict behavior, and effective validation do not
depend on patch ordering or path-alias rules.

Repair is append-only. A new Edit may supersede only the current effective head
for the same ChangeSet, Object, and locale. Forks, cycles, cross-target edges,
and superseding an already superseded attempt fail. Every attempt remains
evidence and counts toward the edit budget; effective heads alone drive diff,
validation, and commit. Under ChangeSet v2, a deterministic validation failure
persists its findings and leaves the proposal editable. A successful
validation seals the complete lineage and effective digest for submission and
approval. Existing v1 terminal-rejection semantics do not change.

One direct `DelegationV2` is sufficient. Campaign and content-subtree selection
must resolve through an authenticated Human-issued immutable resource-intent
control artifact before Agent execution. It is effect-bound operational
evidence, not an authoritative content fact, and does not advance Known State
or the content sequence. The grant contains one Environment and exact
Object, derived Schema, and target-locale sets;
ChangeSet, Edit, Edition, and Release IDs are generated selectors and evidence,
not authority dimensions. The base Object is readable by exact Object/Schema
scope but is not a locale rendition and no delegated v2 Edit can mutate it.
Consequently, including target locales does not create source-write authority.
The grant's dimension product is only an upper bound; every operation must use
the complete stored intent tuple set, which the Agent cannot create, narrow, or
widen. That record also prevents arbitrary non-rectangular Object/locale
combinations from being selected by the Agent.
If a later product decision makes the source itself a locale-scoped rendition,
requires field/path or dynamic-subtree authority, or requires another variant
axis, this decision fails closed and P-0003 must version `DelegationV2` before
owner acceptance.

The consequence path is causally closed. The ChangeSet binds the Human-issued
resource-intent digest and the ContextPack built from it, including the baseline
Environment Release and Edition, base Known State, and exact
Object/Schema/target-locale tuples. Edition creation must select the exact
authorized commit result, not ambient current state. Release creation must
atomically recheck the unchanged baseline Environment pointer and prove that
the baseline-to-candidate delta is exactly that committed localized closure.
An unrelated or intervening same-resource commit cannot hitchhike. Milestone 2
requires a pre-existing baseline preview Release.

The new behavior uses versioned ChangeSet, validation, ContextPack, Known
State, Edition, Release, Proof-predicate, and released-query contracts. Every
base reference includes its exact API version. The first v2 commit is a
predecessor-bound transition from one clean v1 baseline; later v1 mutations
fail rather than discard rendition state, while historical v1 verification
remains supported. All existing v1 authoritative and portable bytes remain
reproducible; migrations fabricate no locale facts. Exact-locale delivery has
no fallback. Generic
variants, fallback, deletion, base-Object replacement, relationship/lifecycle
mutation, migration Edits, campaign entities, and subtree traversal remain
deferred.

The strongest alternative is a generic JSON Patch operation with field/path
authority. It is rejected because Proof has no stable Field identity, JSON
Pointer authority is Schema-version fragile, and patch ordering adds semantic
ambiguity without improving the selected whole-rendition outcome. Modeling one
Object per locale is also rejected because it duplicates logical identity,
relationships, and authorization closure.

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

- [x] The decision names the minimum supported user outcome and rejected
      alternative, with mechanism-level rationale.
- [x] Every required Edit kind and state transition has a canonical input,
      conflict rule, validation rule, and authoritative projection consequence.
- [x] Delegation scope dimensions are sufficient to constrain the selected
      content behavior without relying on path prefixes or prose alone.
- [x] Schema, migration, Known State, Edition, Release, query, and proof-format
      compatibility impacts are explicit.
- [x] The north-star scenario and Milestone 2 exit condition no longer overclaim
      implemented or planned semantics.
- [x] The project owner explicitly accepts the decision before this item moves
      from `review` to `done` or any implementation successor becomes `ready`.
- [x] P-0005 and P-0006 are reshaped; any newly sharp prerequisite becomes a
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

Claimed by `codex:/root:p-0002` at `2026-08-18T01:07:37.311Z` from
`d6532ffcd9ea00dc18c31005695a40692b1f8cc2`. The proposal is complete when the
linked architecture, ADR, product/reference reconciliation, successor shape,
evidence receipt, and independent falsification are committed. It then stops
at `review`; nothing in this item constitutes project-owner acceptance or an
implemented content capability.

The substantive candidate is committed at
`694b723f2ef5e7c6b8a74d0bb5c6af6497fe0cc3`. Independent falsification found
no remaining owner-review blocker after the validation-history, locale,
v1-to-v2 bridge, resource-intent state, and P-0003/P-0007 dependency defects
were closed. The item entered `review` at `2026-08-18T02:38:58.5989701Z`.

Project owner `smithdak` accepted the bounded decision at
`2026-08-18T12:44:20.977Z`. ADR-0012 and the delegated localized-content
contract are ratified. P-0003 and P-0007 are promoted to `ready`; this
acceptance does not claim either successor or implement localized behavior.
See the [candidate decision receipt](../evidence/P-0002/receipt.md).

## Residual risks and next-wave update

P-0007 implements the Human-path content foundation before P-0005 adds Agent
authority. P-0003 must reconcile its reserved v1 operation registry with the
selected v2 operations and prove the exact action/resource closure against
P-0002's normative identifiers and fields before owner review; it does not
depend on P-0007's not-yet-produced Schema digests. P-0005 later binds the
registered P-0007 Schemas to that authority registry. If the P-0003
reconciliation exposes an authority dimension absent from `DelegationV2`,
P-0003 must version rather than mutate v2 meaning.

Relationship localization, fallback and negotiation, deletion, generic
variants, base-Object updates, dynamic campaign/subtree selection, migration
Edits, and higher-cardinality scale are intentionally deferred. The local
profile is volatile at the operation/artifact-version boundary until P-0007
golden fixtures exist; its semantic invariants and v1 non-reinterpretation are
not optional implementation details.
