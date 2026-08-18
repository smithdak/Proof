# ADR-0012: Represent localization as subordinate Object renditions

**Status:** Proposed

**Constitutional:** No

**Date:** 2026-08-17

## Context

The Milestone 2 north-star requires an Agent to translate existing campaign
content into two locales, validate a legal claim, repair a finding in the same
ChangeSet, and release the result to preview under bounded authority. The
implemented domain currently supports only Schema and Object creation. Its v1
ChangeSet lifecycle treats invalid validation as terminal, and its Object,
ContextPack, Edition, Release, Proof, and released-query artifacts have no
localized rendition contract.

`DelegationV2` already has exact Environment, Object, Schema, and locale scope
dimensions and reserved actions for the ChangeSet, Edition, and Release
lifecycle. The missing decision is how localized content relates to Object
identity, how repair remains append-only, and how a Release proves that it
contains exactly the authorized work rather than unrelated same-scope state.

Adding these semantics directly inside P-0005 would combine a new content
model, migration, validation state machine, release causality, authenticated
Agent transport, and authority evidence in one implementation gate. That makes
content correctness and authorization failures difficult to distinguish.

## Decision

Adopt the [delegated localized-content contract](../architecture/delegated-content.md)
as the proposed Milestone 2 content profile.

- A committed `ObjectRevisionV1` is the locale-neutral source for one task.
  Localization does not mutate or reinterpret it.
- `ObjectLocaleRevisionV1` is a subordinate append-only rendition keyed by
  exact `(object_id, locale)` within a Workspace. It retains the Object's stable
  identity and records the exact source revision and Schema.
- `EditV2` introduces one Agent-writable content kind,
  `object.locale.put`. It carries a complete canonical target object, exact
  source precondition, and either an exact target-rendition precondition or
  `null` to assert target absence.
- The governing Schema declares sorted RFC 6901 string-leaf pointers through
  `x-proof-localizable`. Source and target canonical content must be equal
  outside those leaves. Generic patch, base-Object replacement, relationship,
  lifecycle, tombstone, and Schema mutation are outside the profile.
- Invalid `ChangeSetV2` validation persists findings and returns to `Draft`.
  Repair appends an Edit whose `supersedes_edit_id` names the current active
  Edit for the same target and whose repair reference names the latest invalid
  validation-result digest. Validation results form a contiguous predecessor-
  digest chain; approval commits its head and therefore the complete lineage,
  including invalid superseded attempts.
- An authenticated Human first issues an immutable
  `ContentResourceIntentV1` binding an exact current Environment Release,
  Edition, Known State, and finite sorted target tuples. ContextPack and
  ChangeSet records bind its digest. The Agent cannot create, narrow, or widen
  it. It is a persisted, effect-bound control artifact rather than an
  authoritative content fact, so issuance does not change Known State,
  authoritative content sequence, Edition delta, or Environment state.
  Campaign or subtree selection is pre-resolved by trusted policy; no
  prefix, hierarchy, query, or relationship expands authority after issuance.
- The existing `DelegationV2` dimensions are sufficient. Every lifecycle
  operation evaluates the complete target closure against the Environment,
  Object, Schema, and locale exact sets. The locale applies to the rendition
  write; the locale-neutral source read uses Object and Schema scope. No new
  Delegation dimension or action is added.
- `EditionV2` must be the exact state produced by one committed ChangeSet with
  no intervening authoritative commit. `ReleaseV2` advances the unchanged
  Environment baseline only if its Edition delta is exactly that ChangeSet's
  localized rendition set and contains no unrelated state.
- Existing artifact bytes and meanings remain unchanged. New semantics use
  versioned ChangeSet, validation, ContextPack, Known State, Edition, Release,
  Proof-predicate, query, and operation contracts. Migration creates no
  inferred rendition or locale.
- Every base reference names its exact Release, Edition, and Known State API
  version. The first localized commit verifies one clean v1 baseline and
  produces a predecessor-bound `KnownStateV2`; thereafter v1 mutation commands
  fail rather than discard rendition state. Historical v1 reads and proofs
  remain valid. Human rollback may select an exact v1 Edition through a new
  `ReleaseV2`, but it does not reverse Workspace authoring state.
- Create P-0007 as a human-operated localized-content foundation prerequisite.
  P-0005 binds authenticated Agent authority only after P-0007 proves the
  content and release path. P-0003 is reopened after this decision to reconcile
  its closed operation registry with the proposed v2 operation/resource
  closure before P-0004 proceeds.

## Consequences

- Stable Object identity, relationship identity, and lifecycle are shared
  across locales without duplicating Objects.
- Agent mutation is narrower than the general domain-model direction: it can
  write only exact localized string leaves for exact existing Objects and
  locales.
- A full target document is slightly larger than a patch but makes the
  invariant check and resulting bytes directly reproducible.
- Locale-aware reads are explicit and have no fallback. Callers must handle a
  missing rendition rather than receiving source or another locale silently.
- Repair provenance remains observable, deterministic, and budgeted; it also
  requires a new nonterminal invalid-validation path rather than changing v1.
- Workspace-wide Edition publication is safe only from a clean released
  baseline. Unreleased backlog or an intervening commit blocks the delegated
  profile instead of being swept into the Release.
- P-0007 adds implementation work, but separates content/migration defects from
  authenticated-actor and authority-evidence defects. Its human path becomes a
  behavioral oracle for P-0005.
- The source-locale question is deliberately closed by this profile. If the
  source must become a locale rendition, source-read and target-write authority
  need two grants or a later action-qualified Delegation version.
- P-0003's proposed v1 write-operation registry cannot be accepted unchanged;
  its resource closure and operation versions must be reconciled after owner
  acceptance of this ADR. That reconciliation binds P-0002's normative
  operation identifiers, fields, actions, and resource projections; P-0007
  later publishes the exact content Schema identifiers/digests for P-0005 to
  bind without reopening the authority decision.
- P-0002's LocaleId grammar requires lowercase variant subtags and treats
  registry aliases as distinct literal identifiers. P-0003's broader
  unaccepted `DelegationV2` locale pattern must be tightened and its vectors
  regenerated during that reconciliation.

## Alternatives considered

### Generic JSON Patch with field- or pointer-scoped Delegation

This is the strongest alternative. It can express arbitrary existing-Object
updates and smaller wire payloads. It also adds pointer authorization, patch
normalization, operation ordering, array-index behavior, move/copy semantics,
and equivalence proof between authorized operations and resulting content.
None is required for the two-locale scenario. Full target content plus
Schema-declared string-leaf invariants is smaller, easier to falsify, and does
not widen `DelegationV2`.

### One independent Object per locale

This reuses `object.create`, but duplicates stable identity, relationships,
lifecycle, and authority scope and leaves cross-locale consistency to naming
convention. Rejected because a translation is a rendition of one governed
Object, not another logical Object.

### Mutable locale map inside ObjectRevisionV1

This makes every translation a source-Object replacement, conflicts unrelated
locales, expands delegated write authority, and would either reinterpret v1
bytes or require a new base Object representation. Rejected.

### Add localization directly to P-0005

This has the fewest work-item transitions. It makes one gate responsible for
content semantics, migration, validation repair, Agent authentication,
Delegation, transport parity, Edition/Release causality, and evidence. A defect
would have too many plausible causes, and no human-path oracle would exist.
Rejected in favor of P-0007.

### Dynamic campaign or subtree scope

This matches editorial vocabulary but makes authority depend on mutable query
or hierarchy membership and can include future Objects without a new grant.
Rejected for Milestone 2; exact identifiers are resolved before authorization.

### Keep validation failure terminal

This preserves the v1 state machine but cannot demonstrate repair within the
same ChangeSet and would discard or fragment the requested provenance. Rejected
for v2 while preserving v1 behavior.

## Verification

- P-0007 publishes strict Schemas and golden vectors for rendition digests,
  canonical locales, localizable pointers, full-content invariant comparison,
  exact preconditions, linear supersession, validation results, target intent,
  ContextPack, Edition, Release, and query contracts.
- Negative tests attempt every out-of-pointer source, Schema, relationship,
  lifecycle, Object, and locale mutation; partial disclosure; target-set
  widening; cross-target repair; base and Environment races; and unrelated
  same-scope Edition piggyback.
- Migration tests reproduce every prior v1 canonical byte sequence and digest
  before and after migration and prove that no locale rendition is inferred.
- P-0007 demonstrates the complete path under an authenticated Human before
  P-0005 demonstrates parity under an authenticated Agent.
- P-0006 independently verifies that the Release Proof binds the exact
  ChangeSet lineage, rendition artifacts, authority decision, Edition delta,
  Environment transition, and caller-supplied trust roots.

## Reopen conditions

Reopen this ADR if the required source is locale-specific; field-level grants,
dynamic scope, structural localization, fallback negotiation, multi-ChangeSet
publication, or partitioned Edition semantics enter Milestone 2. Each changes a
load-bearing invariant rather than an implementation detail.
