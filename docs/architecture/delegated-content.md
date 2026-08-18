# Delegated localized-content contract

**Status:** Proposed by P-0002; not ratified

**Version:** 0.1

**As of:** August 17, 2026

**Review gate:** Project owner

This contract defines the smallest complete content-mutation profile required
for the Milestone 2 north-star scenario. It is a proposal until
[ADR-0012](../decisions/0012-localized-object-renditions.md) is accepted. It
does not describe implemented behavior. The current implementation supports
only `schema.create` and `object.create`, uses v1 ChangeSet and release
artifacts, and treats failed validation as terminal rejection.

P-0007 implements and proves the human-operated content foundation defined
here. P-0005 may bind authenticated Agent authority to it only after that
foundation exists. P-0003 must be reopened after P-0002 acceptance because its
closed operation registry currently names v1 write operations without this
content and release resource closure.

## Decision

Milestone 2 represents a translation as an append-only localized rendition of
an existing Object. The existing committed `ObjectRevisionV1` remains the
locale-neutral source. An `object.locale.put` Edit creates or replaces one
`ObjectLocaleRevisionV1`, keyed within the Workspace by exact
`(object_id, locale)`.

The rendition contains a complete canonical content object governed by the
same Schema version as its source. It may differ from the source only at
Schema-declared localizable string leaves. The Edit never changes the source
Object revision, Schema, relationships, lifecycle, or another locale.

Milestone 2 intentionally does not expose generic Object replacement, JSON
Patch, field-level Delegation, locale fallback, relationship mutation,
lifecycle transitions, tombstones, or Schema mutation to an Agent. Campaign
and subtree language is task intent only: a trusted caller resolves it to a
finite canonical set of exact Object, Schema, and locale targets before a
ContextPack or ChangeSet is created.

## Crux and bounded guarantee

The crux is whether the source itself must carry a locale identity. It does not
in this profile. Treating the committed Object revision as locale-neutral
source content lets an Agent read that exact Object under the existing Object
and Schema scope while the Delegation locale dimension constrains only the
rendition being written. The write cannot alter the source through
`object.locale.put`.

The proposed guarantee is:

> For an exact pre-existing Environment baseline and finite target set, Proof
> can show that one authorized ChangeSet added only the permitted localized
> string values, repaired any recorded invalid attempts through append-only
> supersession, and released exactly that ChangeSet to the named Environment.

This does not establish translation quality, legal correctness, cultural
fitness, or factual truth unless a named validator or approval explicitly
attests to that property. It does not grant authority over a campaign,
hierarchy, path prefix, inferred related Object, or future Object.

## Invariants

The following requirements are normative if ADR-0012 is accepted.

- **L1 — Stable logical identity.** Localization MUST NOT mint a second Object.
  `ObjectLocaleRevisionV1` is subordinate to the existing Object and is keyed
  by exact `(workspace_id, object_id, locale)`.
- **L2 — Locale-neutral source.** The source is one immutable committed
  `ObjectRevisionV1`. `object.locale.put` MUST NOT change its revision, content,
  Schema, relationships, lifecycle, or digest.
- **L3 — Exact restricted locale.** A locale MUST match P-0002's restricted
  casing and syntax profile, be at most 64 characters, and be compared
  case-sensitively as stored. Language and variant subtags are lowercase,
  script is title case, and alpha region is uppercase. Proof performs no
  registry alias or likely-subtag normalization. `fr-CA` and `fr-ca` are not
  equivalent; the latter fails. A registry alias such as `iw` is accepted only
  as its literal syntactically valid identifier and remains distinct from
  `he`. P-0003 MUST tighten its still-Proposed `DelegationV2` locale pattern to
  the same grammar before owner review.
- **L4 — Full target content.** Every Edit supplies a complete JSON object, not
  a patch. The target validates against the exact source Schema identifier and
  version and reproduces its RFC 8785 canonical bytes deterministically.
- **L5 — Localizable leaves only.** Source and target content MUST be identical
  outside the Schema's exact localizable pointers. Every changed value MUST be
  a JSON string leaf named by one of those pointers.
- **L6 — Exact optimistic preconditions.** The Edit binds the exact source
  revision and digest and either exact target rendition revision and digest or
  `null` to assert target absence. Any mismatch is a conflict; it is never
  interpreted as an upsert against unknown state.
- **L7 — Append-only repair.** Failed attempts and findings remain durable.
  Repair appends a new Edit that linearly supersedes the active prior Edit for
  the same target. It does not mutate or delete the earlier attempt.
- **L8 — One effective leaf.** Within one ChangeSet, every target has exactly
  one active unsuperseded Edit. Supersession cannot cross a target or
  ChangeSet, fork, cycle, or skip the current active leaf.
- **L9 — Invalid remains repairable.** Invalid `ChangeSetV2` validation returns
  the ChangeSet to `Draft` with immutable results. Only a valid result advances
  it to `Ready`. No Edit may be appended after `Ready`.
- **L10 — Complete lineage commitment.** The proposal digest binds every Edit
  in ordinal order, including superseded invalid attempts and their repair-to-
  validation references, plus the effective-leaf projection. Validation
  results form a contiguous predecessor-digest chain and each binds its exact
  proposal. The sealed ChangeSet digest, approval, and resulting evidence bind
  the final proposal and chain head, transitively committing every invalid and
  valid attempt without a circular preimage.
- **L11 — Exact Human-issued resource intent.** Before Agent execution, an
  authenticated Human issues one immutable content-addressed control artifact
  binding the
  Workspace, Environment, unchanged current Release, exact base Edition and
  Known State, and a sorted unique finite set of
  `(object_id, schema_id, locale)` targets. ContextPack and ChangeSet records
  bind its identifier and digest. An Agent may select that record but cannot
  create, narrow, replace, or widen it.
- **L12 — Complete-scope authorization.** Every operation checks the entire
  ChangeSet resource closure against one direct `DelegationV2`. Partial
  disclosure, partial validation, partial commit, and partial Release are
  forbidden.
- **L13 — No implicit resources.** Campaigns, subtrees, queries, relationships,
  locale fallback, and generated identifiers are not grant dimensions.
  Dynamic selections MUST be resolved to exact identifiers before authority is
  evaluated.
- **L14 — Exact causal Release.** The base Known State MUST equal the current
  Environment Release's Edition state. The new Edition MUST be the exact state
  produced by this one ChangeSet, and the Release transition MUST contain no
  other state delta.
- **L15 — Legacy byte preservation.** Existing v1 artifacts, rows, canonical
  bytes, digests, queries, and Proof predicates retain their meaning. New
  semantics use new artifact or operation versions; migration MUST NOT
  synthesize locale renditions from old Objects.
- **L16 — Evidence is not authority.** A ContextPack, localized value, model
  output, validator result, ChangeSet identifier, Edition identifier, or
  Release identifier cannot grant authority. Authority comes only from the
  authenticated actor and exact direct Delegation evaluation.

## Schema annotation profile

The root of a Schema that permits Milestone 2 localization carries the Proof
annotation `x-proof-localizable`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "x-proof-localizable": ["/legal/claim", "/summary", "/title"]
}
```

The annotation is a sorted, unique, non-empty array of RFC 6901 JSON Pointers.
For this profile:

- the empty root pointer is forbidden;
- every pointer MUST resolve in both source and target to a JSON string leaf;
- a pointer MUST NOT traverse an array or name an array element;
- no pointer may be an ancestor or descendant of another pointer;
- ordering uses ascending UTF-8 byte order over the canonical pointer strings;
- a malformed, missing, empty, overlapping, unresolved, or noncanonical
  annotation grants no localizable field and makes `object.locale.put` invalid;
  and
- standard JSON Schema validation and Proof's localization-invariant check both
  apply. An unknown custom annotation is not sufficient by itself.

The invariant checker is equivalent to copying the source content, replacing
only the values at the declared pointers with the target strings, and requiring
the result's canonical JSON bytes to equal the supplied target content. This
mechanism prevents a full-content payload from smuggling structural, numeric,
relationship, or lifecycle changes.

## Localized rendition artifact

`ObjectLocaleRevisionV1` is an immutable authoritative artifact. Its conceptual
canonical shape is:

```json
{
  "api_version": "proof.dev/object-locale-revision/v1",
  "workspace_id": "019c...",
  "object_id": "019d...",
  "locale": "fr-CA",
  "revision": 2,
  "previous_revision_digest": "blake3:...",
  "source_object_revision": 1,
  "source_object_digest": "blake3:...",
  "schema_id": "campaign-page",
  "schema_version": 3,
  "content": {"legal": {"claim": "..."}, "summary": "...", "title": "..."},
  "changeset_id": "019e...",
  "edit_id": "019f...",
  "authoritative_sequence": 84
}
```

For revision 1, `previous_revision_digest` is `null`; later revisions name the
immediately preceding rendition digest and increment by exactly one. The
artifact commits the exact existing `ObjectRevisionV1`, whose current canonical
contract fixes `revision` at `1`. Its `rendition_digest` is an external
content-addressed identifier computed over the canonical artifact bytes and is
not a member of its own digest preimage. A future base-Object revision contract
MUST reopen and version this source precondition rather than silently rebasing
an existing rendition.

The derive-key context is versioned separately from Object revisions, for
example `proof:object-locale-revision:v1`. Exact JSON Schemas, limits, and
golden vectors belong to P-0007 and must be fixed before implementation
acceptance.

## Edit contract

`EditV2` is a closed discriminated union for versioned ChangeSet mutation. Its
only Agent-writable content kind in this profile is `object.locale.put`:

```json
{
  "api_version": "proof.dev/edit/v2",
  "kind": "object.locale.put",
  "edit_id": "019f...",
  "object_id": "019d...",
  "locale": "fr-CA",
  "expected_source": {
    "revision": 1,
    "digest": "blake3:...",
    "schema_id": "campaign-page",
    "schema_version": 3
  },
  "expected_target": null,
  "content": {"legal": {"claim": "..."}, "summary": "...", "title": "..."},
  "supersedes_edit_id": null,
  "repair_of_validation_result_digest": null
}
```

`expected_target: null` asserts that no rendition exists at the ChangeSet base.
To replace a rendition it is:

```json
{
  "revision": 1,
  "digest": "blake3:..."
}
```

The target precondition is always against the authoritative ChangeSet base,
not against an earlier uncommitted repair attempt. Every superseding Edit for a
target repeats the same source and target preconditions. Changing a precondition
requires a new ChangeSet and ContextPack.

The actor's normalized `proof.dev/operation/changeset.add/v2` semantic input
omits `edit_id`. After
successful authentication and authorization, Proof assigns the UUIDv7 Edit
identity, persists it in the canonical `EditV2`, and binds it in the operation
effect. An actor may name a prior Proof-assigned `supersedes_edit_id` as a
selector, but neither identifier is semantic authority. Unknown Edit kinds fail
closed. The profile does not interpret JSON Patch, JSON Merge Patch, null
deletion, omitted fields, locale fallback, or Schema coercion.

A superseding repair MUST also name the external digest of the latest invalid
`ValidationResultsV2` in `repair_of_validation_result_digest`. That result MUST
bind the proposal containing the superseded Edit and contain a blocking finding
whose `edit_id` is exactly the named `supersedes_edit_id` and whose target is
that exact Object and locale. The first Edit uses `null` for both repair
selectors. A supersession without the matching latest invalid result is not a
repair and fails.

## Repair and validation state machine

The persisted `ChangeSetV2` lifecycle for content validation is:

```text
Draft --validate--> Validating --valid--> Ready
  ^                      |
  |                      +--invalid--> Draft + immutable ValidationResultsV2
  |
  +--append linear superseding Edit--+

Ready --> Submitted --> Approved --> Committed
  |           |             |
  +-----------+-------------+--> Rejected / Superseded / Expired
```

`Validating` may be an in-transaction state, but the durable outcome is either
`Draft` or `Ready`. Structural malformation, failed authorization, and base
conflict are operation failures, not repairable validation findings and do not
append attacker-controlled content.

For each exact target, the first Edit has `supersedes_edit_id: null`. A later
Edit MUST name the target's current active Edit. The named Edit becomes
superseded and the new Edit becomes active atomically. All Edits count toward
`max_edits_per_changeset`, including invalid and superseded attempts.

`ChangeSetV2` has two explicit commitments. `proposal_digest` covers immutable
metadata, resource intent, every ordered Edit, and the effective-leaf
projection, but no validation-result digest. `ValidationResultsV2` binds that
exact proposal digest, the effective-leaf digest, Schema and policy bundle
digests, validator names and versions, and ordered findings. It also carries
the exact `changeset_id`, a contiguous one-based `attempt`, and
`previous_validation_result_digest`: attempt 1 uses `null`; every later result
names the exact external digest of attempt N-1 for that same ChangeSet. A
cross-ChangeSet predecessor fails integrity. Its own result digest is external
to its canonical preimage. A repair Edit
commits the latest invalid result digest as described above. On valid results,
`sealed_changeset_digest` binds the final proposal digest and final validation-
result digest. That result's predecessor chain transitively commits every prior
invalid result, while the final proposal commits every repair-to-result edge.
This order prevents a digest cycle without permitting prior rejection evidence
to disappear. A finding has at least a stable code, severity, `edit_id`,
object, locale, JSON Pointer when applicable, and validator identifier.

The north-star legal finding uses one deliberately narrow deterministic policy
profile. Its versioned policy bundle contains sorted unique entries of exact
`{locale, pointer, disallowed_values}`. Each `disallowed_values` array is sorted
and unique. The pinned validator reads the active target's JSON string at the
exact pointer and compares its bytes to each exact disallowed value. It performs
no regex matching, Unicode normalization, case folding, tokenization, fuzzy or
semantic comparison, locale fallback, or model call. A match emits stable code
`proof.validation.prohibited_legal_claim` with the active `edit_id`, object,
locale, pointer, validator identifier/version, and policy bundle digest.

The ContextPack carries the exact canonical policy bytes and digest, but that
evidence never grants authority. Humans own the policy entries and the decision
that satisfying this rule is enough for the preview workflow. The validator
proves only exact policy conformance; it does not establish real legal
correctness. A model or actor assertion that a claim is legal is never
validation evidence.

Ready seals the Edit lineage. Any requested repair after Ready starts a new
ChangeSet. Submission and approval bind `sealed_changeset_digest`, not only the
active content. Appending a repair after invalid validation changes
`proposal_digest`; the earlier immutable results remain evidence for their old
proposal and cannot satisfy readiness for the new one.
Every verifier and rebuild path requires the complete contiguous result chain;
deleting, reordering, substituting, or forking an attempt fails digest
reconstruction.

## Exact task and resource intent

`ContentResourceIntentV1` is an immutable content-addressed control artifact
issued through the authenticated Human path before any delegated Agent
operation:

```json
{
  "api_version": "proof.dev/content-resource-intent/v1",
  "intent_id": "0199...",
  "workspace_id": "0198...",
  "issued_by_principal_id": "0197...",
  "issued_at": "2026-08-17T20:00:00Z",
  "environment_id": "preview",
  "base": {
    "release": {
      "api_version": "proof.dev/release/v1",
      "release_id": "019b...",
      "digest": "blake3:..."
    },
    "edition": {
      "api_version": "proof.dev/edition/v1",
      "edition_id": "019c...",
      "digest": "blake3:..."
    },
    "known_state": {
      "api_version": "proof.dev/known-state/v1",
      "digest": "blake3:...",
      "authoritative_sequence": 83
    }
  },
  "targets": [
    {
      "object_id": "019d...",
      "schema_id": "campaign-page",
      "locale": "de-DE"
    },
    {
      "object_id": "019d...",
      "schema_id": "campaign-page",
      "locale": "fr-CA"
    }
  ]
}
```

Issuance is idempotent and effect-bound. Under the proposed local authority
profile, `issued_by_principal_id` MUST equal the independently authenticated
requesting Human and direct Delegation issuer. It is a Human administration
operation, not another Agent action token. The Agent receives only the
persisted intent identifier/digest and cannot submit resource arrays as a
substitute. Changing any target or base creates a new intent.

The canonical resource-intent bytes exclude their external digest and use the
derive-key context `proof:content-resource-intent:v1`. Its Proof-assigned
`intent_id`, issuer, issuance time, Workspace, versioned base, and targets are
all effect-bound. P-0007 owns the exact Schema, size bounds, and golden bytes.
The artifact is operational evidence, not an authoritative content fact: its
issuance does not advance the authoritative sequence, change Known State,
appear in an Edition delta, or move an Environment pointer. It therefore
cannot stale the content baseline it names. Issuance is a control-plane
operation, not a governed content mutation under C1. The later ChangeSet and
Release Proof reference its verified digest; they do not reinterpret it as
content.

Targets are unique and sorted by `(object_id, schema_id, locale)` using the
canonical string bytes. The source Object's actual Schema MUST equal the named
Schema. One Object may have multiple target locales. The finite target count is
bounded by both the operation Schema and the Delegation's `max_objects` and
`max_edits_per_changeset`; repeated repair Edits consume only the Edit budget,
while distinct Object identifiers determine the Object budget.

Campaign or content-subtree selection happens outside the Agent authority path
under trusted Human policy. Its output is this exact finite target list. Proof
does not persist a path prefix as authority, traverse relationships to expand
scope, or let the Agent add a selected Object later.

`ContextPackV2` is then built from that exact intent and commits its complete
canonical bytes and digest. `ChangeSetV2` immutable metadata binds both
`resource_intent_id`/digest and `context_pack_id`/digest and verifies that the
pack embeds the identical intent. The resource intent never contains the
ContextPack identifier or digest, so neither artifact has a circular preimage.
Every later Agent command names the same two selectors and Proof derives the
complete target closure from stored bytes.

## ContextPackV2

`ContextPackV2` carries exactly the information needed for the declared target
set:

- the complete `ContentResourceIntentV1` and its target-ordering basis;
- the exact current Environment Release, Edition, Known State, and their
  digests;
- each target's exact source `ObjectRevisionV1` bytes and digest;
- each target's current `ObjectLocaleRevisionV1` bytes and digest, or an
  authenticated absence statement at the base sequence;
- the exact governing Schema bytes, including `x-proof-localizable`;
- the allowed operation/Edit versions and explicit exclusions;
- validator, policy, terminology, brand, and legal-rule identifiers and
  digests; and
- size, Object, Edit, and retry budgets.

It contains no inferred relationship neighborhood or locale fallback content.
The ContextPack is content-addressed evidence and a freshness precondition, not
authority. A target absent from it cannot be added to the ChangeSet even if the
Delegation independently covers that Object.

## DelegationV2 resource closure

P-0002 requires no new Delegation dimension and no new action token. The
existing exact-set dimensions are sufficient:

| Intent member | Required `DelegationV2` scope |
| --- | --- |
| Workspace | Delegation's exact `workspace_id` |
| `environment_id` | member of `scope.environment_ids` |
| every target `object_id` | member of `scope.object_ids` |
| every target `schema_id` | member of `scope.schema_ids` |
| every target `locale` | member of `scope.locales` |

The current P-0003 candidate's locale item pattern is a syntactic superset
because it permits mixed-case variant subtags. A P-0002 content operation first
requires the stricter P-0002 LocaleId grammar and then exact membership in the
Delegation set. P-0003 must tighten its unaccepted Schema and regenerate its
vectors before review; this changes no resource dimension or accepted stored
artifact. A grant string outside the P-0002 grammar authorizes no content
operation even if the earlier candidate accepts its syntax.

The scope arrays form a dimension-wise permission product. The separately
authenticated Human-issued target tuples narrow that product for this task;
they do not widen it, and the Agent cannot choose a different product subset.
This permits non-rectangular exact target tuples without another Delegation
dimension: every tuple must be inside the grant, while the immutable intent is
the required task closure. Because the source Object is locale-neutral,
reading it requires its Object and Schema scope, while writing the rendition
additionally requires the exact target locale. No source-locale grant is
implied.

The affected application operations use the existing reserved actions:

| Operation version proposed for P-0007/P-0005 | Action | Required closure |
| --- | --- | --- |
| `context.build` / `proof.dev/operation/context.build/v2` | `context:build` | Complete intent and target set |
| `changeset.create` / `proof.dev/operation/changeset.create/v2` | `changeset:create` | Complete immutable intent |
| `changeset.add` / `proof.dev/operation/changeset.add/v2` | `changeset:add` | Complete intent plus exact Edit target |
| `changeset.get` / `proof.dev/operation/changeset.get/v2` | `changeset:get` | Complete intent; no filtered response |
| `changeset.diff` / `proof.dev/operation/changeset.diff/v2` | `changeset:diff` | Complete intent and full lineage |
| `changeset.validate` / `proof.dev/operation/changeset.validate/v2` | `changeset:validate` | Complete intent and effective leaves |
| `changeset.submit` / `proof.dev/operation/changeset.submit/v2` | `changeset:submit` | Complete intent and sealed lineage |
| `changeset.commit` / `proof.dev/operation/changeset.commit/v2` | `changeset:commit` | Complete intent, exact base, effective leaves |
| `edition.create` / `proof.dev/operation/edition.create/v2` | `edition:create` | Exact committed ChangeSet result |
| `release.create` / `proof.dev/operation/release.create/v2` | `release:create` | Exact Environment transition and delta |
| `object.query_released` / `proof.dev/operation/object.query_released/v2` | `object:query_released` | Environment, Objects, Schemas, exact locales |

The canonical operation identifiers use the existing
`proof.dev/operation/<name>/v2` form. P-0003 owns the final closed registry and
must reconcile these v2 pairs before P-0004. Generated ChangeSet, Edit, Edition,
Release, and Proof identifiers are selectors and evidence after creation, not
additional grant axes.

Every operation re-evaluates the complete direct Delegation at its current
authority head. A caller authorized for only a subset receives a denial, never
a filtered ChangeSet, diff, validation report, Edition, or Release. This avoids
turning partial reads into a resource-existence oracle and prevents a broad
ChangeSet from being committed through a narrow grant.

## Commit, Edition, and Release causality

The delegated content path requires a pre-existing baseline Release for the
target Environment. At ContextPack construction and ChangeSet creation:

1. the Environment's current Release MUST be the named base Release;
2. that Release's Edition state MUST reproduce the named Known State; and
3. the Workspace's current authoritative state MUST equal that same Known
   State. Unreleased Workspace backlog therefore blocks this profile.

`proof.dev/operation/changeset.commit/v2` uses compare-and-swap against the exact base sequence and
digest. It appends only the effective locale rendition revisions and produces a
resulting authoritative sequence and state digest bound to that ChangeSet.

`proof.dev/operation/edition.create/v2` names that commit result and is allowed only while the
Workspace's current authoritative state still equals it. It creates a
Workspace-wide `EditionV2` whose creation set is exactly the one ChangeSet. An
intervening commit causes conflict; the implementation cannot snapshot ambient
later state and attribute it to the earlier ChangeSet.

`proof.dev/operation/release.create/v2` atomically verifies that:

- the Environment current Release is still the exact base Release;
- the target Edition is the exact result of the authorized ChangeSet;
- the delta from base Edition to target Edition consists exactly of the active
  target `ObjectLocaleRevisionV1` artifacts produced by that ChangeSet; and
- there is no Schema, source Object, relationship, lifecycle, unrelated Object,
  unrelated locale, or unrelated ChangeSet delta.

It then appends `ReleaseV2`, advances the Environment pointer, and creates its
Proof/outbox consequence in the existing atomic Release boundary. An
environment-pointer race, source/base race, extra delta, missing target, or
different ChangeSet fails without advancing the pointer.

This exact-delta check is stronger than testing that every changed resource is
inside a broad Delegation product. It prevents an authorized Release from
carrying unrelated work that happened to use the same Object, Schema, or locale.

## Delivery semantics

`proof.dev/operation/object.query_released/v2` takes one Environment and sorted unique exact
`(object_id, locale)` requests. It reads only the current Release's Edition and
returns, for each authorized target:

- source Object revision and digest;
- requested locale;
- localized rendition revision and digest;
- exact Schema identifier and version; and
- complete resolved target content.

There is no locale fallback. A missing exact rendition returns a stable
not-found result for the complete authorized request; it does not substitute
the source or another locale. `object.query_released/v1` retains its current
locale-neutral behavior and bytes.

## Compatibility and migration boundary

P-0007 owns a one-way storage and artifact migration after owner acceptance.
The exact storage version is chosen against the then-current repository; this
proposal does not reserve a number. The migration must preserve all existing
v1 authoritative and artifact bytes exactly.

The affected contracts require new versions rather than reinterpretation:

- `ObjectLocaleRevisionV1` and its own digest context;
- `EditV2`, `EditBatchV2`, `ChangeSetV2`, and `ValidationResultsV2`;
- a rendition-aware Object set and `KnownStateV2`;
- `ContextPackV2` and `EditionV2`;
- `ReleaseV2` and a versioned Release Proof predicate;
- the v2 operation registry listed above; and
- `proof.dev/operation/object.query_released/v2` request and response Schemas.

### State-profile bridge

Every `ContentResourceIntentV1.base` uses versioned Release, Edition, and Known
State references. A digest without its exact `api_version` is not a valid base.
`KnownStateV2` has a new canonical manifest and digest context. It carries:

- the Workspace and authoritative sequence;
- the same sorted Schema and source-Object reference shapes used by v1;
- sorted exact locale-rendition references containing Object, locale,
  rendition revision/digest, source-Object digest, and Schema identity; and
- a `previous_state` reference with the predecessor's exact Known State API
  version, sequence, and digest.

The first v2 state points to `proof.dev/known-state/v1`; later v2 states point
to v2. `proof:known-state:v2` is a new digest context. Nothing appends an empty
locale member to v1 canonical bytes or treats a v2 digest as a v1 digest.

Cross-version delta verification first verifies the supplied v1 or v2 Known
State under its own canonical contract. It then decodes an in-memory comparison
view of sorted Schema references, source-Object references, and locale-
rendition references. A verified v1 state contributes an empty rendition set
to that comparison view only; no row, artifact, digest member, or inferred
locale is created. The first localized commit MUST preserve every v1 Schema and
Object reference byte-for-byte in that view and may add only its exact
`ObjectLocaleRevisionV1` results. `EditionV2`, `ReleaseV2`, and their Proof
predicate bind both versioned endpoints and the independently reproduced delta.

The first v2 commit is allowed only when the Workspace current Known State, the
named `EditionV1` state, and the named current `ReleaseV1` state are the same
verified v1 digest and sequence. It atomically creates `KnownStateV2` with that
v1 predecessor. Any unreleased v1 backlog, mismatched version, or different
sequence fails before a v2 fact is written.

The compatibility matrix is closed:

| Operation/artifact combination | Rule after P-0007 |
| --- | --- |
| Historical v1 get, inspect, reproduce, and verify by exact identifier | Always supported under the artifact's v1 contract. |
| Current v1 ChangeSet mutation, commit, Edition creation, or Release creation | Allowed only while the Workspace authoring state and required current Environment artifacts are v1. After the first v2 commit, fail `proof.input.unsupported_version`; never drop rendition state. |
| v2 localized ChangeSet from a v1 baseline | Allowed only for the exact first-transition conditions above; produces `KnownStateV2`, `EditionV2`, and `ReleaseV2`. |
| v2 localized ChangeSet from a v2 baseline | Allowed only when every versioned base reference and the unchanged current Environment pointer match exactly. |
| `object.query_released/v1` against an Environment current pointer | Allowed only when the current Release and Edition are both v1; otherwise fail unsupported version rather than omit locale state. |
| `object.query_released/v2` against a v1 Edition | Verifies the v1 state and returns exact rendition-not-found for every requested locale; it performs no source fallback. |
| `object.query_released/v2` against a v2 Edition | Returns only exact rendition references committed by that Edition. |
| Human rollback after v2 activation | Appends `ReleaseV2` and may target an exact historical `EditionV1` or `EditionV2`; it never rewrites the Edition or Workspace authoring state. Delegated rollback is outside this profile. |
| New localized work while an Environment is rolled back behind Workspace authoring state | Denied by the clean-baseline equality rule until a forward Release restores an exact current-state baseline. |

Storage migration alone does not activate v2. The active authoring profile is
the API version of the current authoritative Known State. The first accepted
v2 content commit is the one-way activation point; an Environment rollback is
a delivery-pointer operation, not a reverse authoring-state migration.

`ReleaseV2` records the exact Edition artifact version. Promotion or rollback
may point to an older `EditionV1` without rewriting it, while retaining the
historical `ReleaseV1`. A transition into the v2 state profile is explicit and
digest-bound; migration does not fabricate locale renditions, infer source
locales, reinterpret `ObjectRevisionV1`, or authorize historical
`DelegationV1` facts.

Old CLI, MCP, query, ChangeSet, Edition, Release, Proof, and verification
contracts remain reproducible under their exact versions. An adapter must
reject an unsupported cross-version combination rather than coerce it.

## Implementation sequence

The selected path is a named foundation prerequisite, not direct expansion of
P-0005:

1. **P-0007 — localized content foundation:** implement versioned rendition,
   Edit, repair, validation, ContextPack, Edition, Release, query, migration,
   and human-operated end-to-end conformance without Agent authority.
2. **P-0003 reopen:** reconcile the authenticated command operation registry
   and exact resource projections with this accepted contract before P-0004.
3. **P-0004:** implement authenticated actor and direct-Delegation enforcement
   only after that reconciliation is accepted.
4. **P-0005:** bind the proven P-0007 operations to authenticated Agent
   authority and demonstrate denial/transport parity.
5. **P-0006:** export and independently verify the combined content, authority,
   Edition, Release, and Proof closure.

P-0007 prevents P-0005 from simultaneously inventing content semantics and
debugging Agent authorization. It also yields a human-path oracle against which
Agent behavior can be compared.

Contract ownership is split without duplication. P-0007 owns the content
operation input/output Schemas, canonical artifact Schemas, state transitions,
and Human-path behavior. Reopened P-0003 owns the closed
operation-version-to-action/resource-projection registry and authority
conformance against P-0002's normative operation identifiers, fields, and
resource projections; it does not bind Schema digests that P-0007 has not yet
produced. P-0004 implements the generic authentication/authorization kernel but
exposes no content write. P-0007 later registers the exact content Schema
identifiers and digests. P-0005 binds those registered Schemas to the accepted
authority registry through adapters and may not redefine either contract.

## Conformance and falsification

P-0007 must provide machine-readable Schemas and independent golden vectors for
at least:

- restricted locale acceptance, invalid-case rejection, and literal alias
  non-normalization;
- localizable pointer ordering, escaping, overlap, array traversal, missing
  paths, non-string leaves, and out-of-pointer mutation;
- create and exact replacement preconditions plus target-absence races;
- source revision, Schema, and digest conflicts;
- linear repair, cross-target supersession, fork, cycle, skipped-leaf, and Edit-
  budget exhaustion;
- durable invalid results followed by valid repair in the same ChangeSet;
- complete-lineage digest and approval mutation tests;
- validation-attempt deletion, substitution, reordering, fork, skipped
  predecessor, and repair-to-wrong-finding tests;
- exact ContextPack and target-set closure with no partial disclosure;
- every missing Environment, Object, Schema, locale, action, and budget grant;
- campaign/subtree input that cannot widen beyond the pre-resolved target set;
- concurrent Workspace commit, Environment pointer race, unrelated Edition
  delta, and same-dimension-but-different-ChangeSet piggyback;
- v1 byte/digest reproduction before and after migration, with zero fabricated
  renditions;
- exact-locale query and deliberate no-fallback behavior; and
- CLI, modern MCP, and legacy MCP normalized-input parity when P-0005 binds the
  Agent path.

The critical falsification case is an authorized Agent attempting to change a
source field, Schema, relationship, lifecycle, another locale, or unrelated
same-scope content and still obtaining a Release. Any such success invalidates
this design.

## Volatility isolation

- Locale syntax is a named restricted Proof profile, not a promise to implement
  the evolving full language-tag registry or locale negotiation.
- JSON Schema validation and Proof annotations are separate; a later annotation
  vocabulary receives a new version rather than changing these bytes.
- Policy engines and legal validators are selected by identifiers and digests
  behind validation ports. Their conclusions do not change authority semantics.
- Campaign systems, hierarchy resolution, translation providers, model APIs,
  and terminology stores are ContextPack producers outside the content
  aggregate.
- CLI, MCP, HTTP, and future collaboration transports adapt the same operation
  Schemas and cannot add mutation semantics.
- Artifact and operation versions isolate the v1 implementation from the new
  profile. Storage-table layout is an implementation decision owned by P-0007.

## Kill and pivot triggers

Reopen or reject this proposal before P-0007 if any Milestone 2 requirement
needs:

- a source that is itself one locale rendition rather than locale-neutral
  Object content;
- source-read and target-write permissions that differ by locale or action;
- per-field or per-pointer Delegation rather than Schema-declared invariants;
- dynamic campaign, path-prefix, hierarchy, query, or relationship expansion
  after authorization;
- localized structural, numeric, array, relationship, Schema, or lifecycle
  differences;
- locale fallback or negotiation as part of the released-content contract;
- one delegated Release to aggregate multiple ChangeSets or unreleased
  Workspace backlog; or
- a partial or partitioned Edition whose delta cannot be independently proven
  equivalent to the exact ChangeSet result.

The first two triggers require two explicit grants or a new Delegation version
with action-qualified source/target scopes. The third requires a field-
authority model and patch semantics. The fourth requires a separately governed
selection artifact and time-of-use closure. The fifth or sixth requires a
versioned rendition model beyond simple localized leaves. The final two require
a different Edition/Release causality contract.

## Alternatives considered

### Generic JSON Patch plus field-level authority

This is the strongest rejected alternative because it can express arbitrary
existing-Object updates and minimize payload size. It also requires a new
pointer-level Delegation dimension, exact patch operation ordering, missing-
path and array-index rules, move/copy authority, patch normalization, and a
proof that the authorized patch and resulting full content are equivalent.
Those mechanisms do not advance the two-locale north-star. Full target content
plus Schema-declared invariant comparison is smaller and more falsifiable.

### One Object per locale

This reuses current `object.create` and avoids a new rendition aggregate. It
duplicates stable logical identity, relationships, lifecycle, and scope; makes
cross-locale consistency an application convention; and lets a translation
silently diverge as an independent Object. It is rejected.

### Mutable locale map inside ObjectRevisionV1

This makes every translation replace the source Object and changes its digest,
causing unrelated locales to conflict and expanding the Agent's write authority
to the base Object. It would also reinterpret existing Object bytes. It is
rejected.

### Create-only Milestone 2

Reframing the scenario around new Objects would avoid revision semantics but
would not demonstrate bounded modification of existing governed content or
same-ChangeSet repair. It fails the stated outcome.

### Dynamic campaign or subtree grants

This is convenient for large campaigns but makes authority depend on mutable
hierarchy or query state and permits later Objects to enter scope without a new
grant. Exact pre-resolved identifiers are the correct Milestone 2 boundary.

## Current-source basis

This proposal was derived from the repository state claimed by P-0002. At that
state, only `schema.create` and `object.create` Edits exist; Object revisions,
Object sets, Known State, ChangeSets, ContextPacks, Editions, Releases, Release
Proofs, and released-object query contracts are v1; validation failure seals a
ChangeSet as rejected; Editions are Workspace-wide; and `DelegationV2` already
contains exact Environment, Object, Schema, and locale dimensions plus the
reserved ChangeSet/Edition/Release action vocabulary.

Those facts make the proposed version boundary and P-0007 prerequisite
necessary. They are not evidence that the new behavior is implemented.
