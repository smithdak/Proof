# Domain model

**Status:** Ratified baseline  
**Baseline:** August 3, 2026

> **Proposed P-0003 profile:** The authenticated-actor and authority-evidence
> additions below are pending project-owner acceptance. Existing records retain
> their current meaning until a versioned migration is implemented.
> The normative proposal is the [authenticated actor contract](authenticated-actor.md).
>
> **Ratified P-0002 profile:** Localized existing-Object mutation is modeled as
> a subordinate append-only rendition, not a second Object or a mutable locale
> map inside `ObjectRevisionV1`. The profile is project-owner accepted; its
> normative contract is
> [delegated localized content](delegated-content.md).

## Aggregate map

```text
Workspace
├── Schemas
├── Objects
├── ChangeSets
├── Editions
├── Environments ── Releases
├── Principals ── Delegations
├── Policies and Validators
├── ContextPacks
└── Proofs
```

This is a conceptual ownership map, not a single in-memory aggregate. Transaction boundaries remain narrow except where the ChangeSet intentionally coordinates multiple Objects.

**Proposed P-0003 profile:** The Workspace also references a separately rooted,
append-only authority log containing Principal bindings, Agent credential
public-key references, Delegation issue/revocation facts, consumed command
presentations, and authorization decisions. It does not place credential
secrets or raw provider subjects in the content aggregate.
Its signed hash chain detects mutation and reordering relative to a trusted
later authority head; a valid older prefix or fork restored with the same local
store and file-backed signer remains an explicit residual unless a verifier
pins an independently retained authority-head checkpoint.

## Workspace

A Workspace is the top-level governance and content boundary.

It owns:

- Stable identity and configuration.
- Schema namespace.
- Object namespace.
- Policy attachment points.
- Principal visibility and Delegations.
- Edition and Release history.
- Cryptographic trust configuration.

Cross-Workspace mutation is not supported in one ChangeSet. Coordination across Workspaces occurs through explicit orchestration and separate Proofs.

## Schema

A Schema is a versioned content contract based on JSON Schema Draft 2020-12 plus Proof-specific annotations.

Proof-specific annotations may describe:

- Relationship targets and cardinality.
- Localizable and invariant fields.
- Sensitivity classification.
- Search and delivery projection hints.
- Required custom validators.
- Workflow or approval implications.

Schema versions are immutable. Compatibility is classified as backward-compatible, forward-compatible, fully compatible, or breaking. A breaking Schema change requires an explicit migration plan before it can govern existing Objects.

## Object

An Object is a uniquely identified instance of structured content.

An Object has:

- UUIDv7 operational identifier.
- Stable logical key when the business domain requires one.
- Schema identifier and version.
- Locale or variant identity where applicable.
- Canonical content body.
- Typed relationships to other Objects.
- Lifecycle state.
- Current accepted revision and digest.

An Object has no public `update` operation. New revisions are proposed as Edits inside a ChangeSet.

**Ratified P-0002 profile:** A committed `ObjectRevisionV1` is locale-neutral
source content for localization. `ObjectLocaleRevisionV1` is a separate
immutable revision stream keyed by exact `(object_id, locale)` and commits the
source Object revision and Schema from which it was produced. A localized
rendition retains the Object's stable identity and cannot change its source
content, relationships, lifecycle, or Schema.

## Edit

An Edit is one proposed mutation. Initial Edit kinds are:

- Create Object.
- Replace or patch Object content.
- Create, replace, or remove a relationship.
- Transition lifecycle state.
- Create a new Schema version.
- Apply an explicit migration.
- Tombstone an Object.

Edits name their target, expected revision, operation, and value. Patch semantics use a single ratified format; mixing JSON Patch and merge-patch behavior inside one interface is forbidden.

Deletion is represented by a tombstone fact. Historical Editions and Proof subjects remain verifiable.

**Ratified P-0002 profile:** Milestone 2 Agent mutation narrows the generic
direction above to `EditV2` kind `object.locale.put`. It supplies complete
target content and may differ from its locale-neutral source only at sorted
Schema-declared `x-proof-localizable` RFC 6901 string leaves. Generic Object
replacement or patch, relationship mutation, lifecycle transition, tombstone,
and Schema mutation remain unavailable through this profile.

## ChangeSet

A ChangeSet is the atomic unit of governed intent.

Required fields:

- `changeset_id`
- `workspace_id`
- `intent`
- `principal_id`
- optional `delegation_id`
- `base_state`
- ordered Edits
- idempotency key
- creation time
- optional ContextPack reference
- required policy and validation profile

**Proposed P-0003 profile:** A new version of every authority-bearing command
and fact records distinct `requesting_principal_id` and
`operating_principal_id`, `binding_id` plus its issuing authority
sequence and record digest, direct
`delegation_id`, semantic `CommandInputV1` digest and authenticated-command
envelope digest,
`authorization_decision_digest`, and authority-log position. The legacy
`principal_id` field is not silently reinterpreted.

Lifecycle:

```text
Draft → Validating → Ready → Submitted → Approved → Committed
  │         │          │         │          │
  └─────────┴──────────┴─────────┴──────────┴→ Rejected / Superseded / Expired
```

Only `Committed` changes authoritative content state. Approval does not guarantee commit: authority, policy, base state, and validation are rechecked at commit time.

**Ratified P-0002 profile:** `ChangeSetV2` preserves invalid validation results
but returns to `Draft` so a repair may append a linear superseding Edit for the
same exact Object and locale. Each repair names the invalid validation-result
digest it addresses; validation results form a contiguous predecessor-digest
chain. `Ready` seals the lineage. The ChangeSet digest and approval bind all
Edit and validation attempts, including superseded invalid attempts, and the
one effective leaf per target. This is a versioned behavior change;
`ChangeSetV1` retains its current terminal rejection semantics.

## Edition

An Edition is an immutable representation of accepted content state.

It contains or references:

- Workspace identity.
- Parent Edition when applicable.
- Included state boundary.
- Schema-set digest.
- Object manifest and digests.
- Creation transaction and ChangeSet set.
- Canonicalization and digest algorithms.
- Edition digest.

An Edition may represent the entire Workspace or a declared partition, provided the partition contract is explicit and verifiable. The MVP uses a Workspace-wide Edition for conceptual simplicity.

**Ratified P-0002 profile:** A delegated `EditionV2` is Workspace-wide and must
equal the exact resulting state of one authorized `ChangeSetV2`. Its creation
fails if another authoritative commit occurs after that ChangeSet result; it
cannot snapshot ambient later state and attribute it to the earlier command.

## Environment

An Environment is a named delivery target with its own release policy. Examples include `preview`, `staging`, `production`, a region, or a channel.

Environment configuration is versioned and includes:

- Required approvals.
- Allowed Edition classifications.
- Delivery adapters.
- Release windows and holds.
- Verification requirements.
- Current Release pointer.

## Release

A Release is an immutable record that makes one Edition current for one Environment.

Promotion and rollback create Releases. They never mutate an existing Release. An Environment's current pointer is a projection of the latest accepted Release fact.

**Ratified P-0002 profile:** `ReleaseV2` requires the Environment current
Release to remain the ContextPack's exact baseline and verifies that the target
Edition delta contains only the localized rendition revisions produced by the
one bound ChangeSet. Any unrelated Schema, source Object, relationship,
lifecycle, Object, locale, or ChangeSet delta fails before the Environment
pointer advances.

## Proof

A Proof is signed evidence bound to immutable subjects. Proof is both a domain concept and a portable artifact. Release Proofs are the primary MVP artifact; ChangeSet and Edition attestations may use the same envelope later.

See [Proof model](proof-model.md).

## Principal

A Principal is an authenticated identity of type:

- Human.
- Service.
- Agent.
- System component with distinct workload identity.

Principal type informs policy but does not change available state transitions.

## Proposed P-0003 profile — authenticated actor types

An `AuthenticatedSubjectV1` is a provider-qualified result from a trusted
identity adapter. It is not a Principal and is never accepted from an
application request.

A `PrincipalBindingV1` is an immutable, Workspace-authority-signed mapping from
a provider-qualified subject and public credential to exactly one Principal.
Rotation creates another binding. Disablement or revocation is a later
authority fact with a causal position; it is not an in-place edit. Portable
evidence uses `requesting_subject_commitment`, a hiding commitment formed with
a 32-byte blind, when the raw provider subject is restricted. It is not a raw
UID checksum. Audit policy controls disclosure of the private subject-plus-blind
opening; exact canonical semantics live in the
[authenticated actor contract](authenticated-actor.md) and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).
Principal disablement is terminal in this profile; recovery creates a new
Principal, binding, and direct Delegation rather than re-enabling old authority.

An `AuthenticatedActorContextV1` is an in-process application value derived by
the adapter. It identifies both authenticated subjects, the Agent binding,
requesting and operating Principals, authentication method,
semantic `CommandInputV1` digest, authenticated-command envelope digest,
`presentation_id`, and
authentication time. It has no public request Schema.
Persisted `actor_context_digest` input uses the public
`requesting_subject_commitment`, never the raw requesting `os/unix` subject or
its blind.

An `AuthenticatedCommandV1` is a bounded, single-use DSSE presentation over one
normalized operation. Its `presentation_id` is the replay identity. Its
consumption is an `AuthorityRecordV1` fact. A new presentation
may reuse an idempotency key only for the same normalized operation input.
Fresh C5 authentication and current C6 authorization precede C4 disclosure of
any prior idempotent result; current revocation, disablement, or policy denial
blocks disclosure without undoing the completed effect.

An `AuthorizationDecisionV2` records allow or deny, authenticated actor-context
commitment, exact command and envelope digests, direct Delegation and revocation
position, requested action/resources/budgets, policy inputs, authority head,
and decision time. It never contains a private credential or bearer secret.
Existing `AuthorizationDecisionV1` retains its legacy read-authority meaning
and is not silently reinterpreted.

## Delegation

A Delegation grants bounded authority from an issuer to a recipient Principal. It is immutable after issue; revocation creates a revocation fact. Evaluation follows the full chain, and no link may grant more than its parent.

### Proposed P-0003 direct profile

Milestone 2 narrows evaluation to one immutable Human-to-Agent `DelegationV2`.
The independently authenticated Human must equal the issuer; the authenticated
Agent binding must resolve the recipient as the operating Principal. Revocation state is derived
from append-only authority facts as of the authorization decision's causal
position. A parent reference, subdelegation permission, non-Human issuer,
multi-link or cyclic path, or absent revocation evidence fails closed. If
accepted, this profile supersedes complete-chain evaluation for Milestone 2;
chaining requires a later versioned profile.

See [Agent authority](agent-authority.md).

## ContextPack

A ContextPack is a content-addressed task context artifact. It contains the minimum state and rules needed to propose work, plus an explicit capability boundary. It is evidence, not authority: possessing one does not grant permission to commit.

### Ratified P-0002 localized-content profile

Before delegated execution, an authenticated Human issues immutable
`ContentResourceIntentV1` with one exact Environment baseline Release, Edition,
Known State, and finite sorted set of `(object_id, schema_id, locale)` targets.
This is a content-addressed control artifact, not an authoritative content fact:
issuance does not advance content sequence or Known State, enter an Edition
delta, or move an Environment pointer. `ContextPackV2` embeds that artifact and
carries the exact source revisions, current target renditions or authenticated
absence, Schemas and localizable pointers,
policies, validators, and budgets required by the set. Campaign and subtree
language is task intent only and must be resolved to exact identifiers before
issuance. The Agent cannot create or replace the intent, and the ContextPack
never expands scope through a query, hierarchy, relationship, or locale
fallback.

`ChangeSetV2` binds both the resource-intent and ContextPack identifiers and
digests. Every
ChangeSet, Edition, Release, and released-query operation evaluates its complete
Environment, Object, Schema, and locale closure; a caller with only a subset is
denied rather than receiving a filtered artifact. The locale-neutral source
requires Object and Schema scope. The rendition write additionally requires
the exact target locale. These requirements fit the existing `DelegationV2`
dimensions and add no new action or grant axis.

Generated ChangeSet, Edit, Edition, Release, and Proof identifiers are outcome
selectors and evidence, not authority. P-0007 implements this content
foundation for a Human path before P-0005 binds it to authenticated Agent
authority. P-0003 must reconcile its closed write-operation registry with the
v2 operation and resource closure following P-0002 owner acceptance.

## Proposed P-0003 profile — portable authority closure

P-0006 will define `AuthorityEvidenceBundleV1`; it is not an implemented bundle
contract in P-0003 or P-0004. The future bundle is rooted in the
separate authority trust domain and carries the exact `binding_id`, binding-issue
authority sequence and record digest, subject commitment, direct `DelegationV2`
and applicable revocation records, consumed
`AuthenticatedCommandV1`, `AuthorizationDecisionV2`, `AuthorityRecordV1`
positions, and required policy identifiers. A Release Proof will refer to the
bundle or its selected authority-closure commitment under the P-0006 contract.
When a verifier must detect prefix truncation or rollback rather than only
validate the supplied prefix internally, the bundle also needs an independently
retained expected authority head or a later checkpoint that commits it.

An independent verifier receives the bundle, referenced canonical artifacts,
and explicit caller-supplied authority trust roots. Withheld protected values
remain commitments and make the authority-evidence verdict incomplete unless
the selected trust policy can validate them without disclosure.

## Known State

Known State is not a mutable singleton. It is a verified statement consisting of:

- Workspace or partition identity.
- Authoritative sequence.
- Edition or state digest.
- Projection versions.
- Verification result.
- Time observed.

A state is “known” when Proof can reproduce its digest from authoritative facts and required algorithms.

## Identifier policy

- Operational entities use UUIDv7.
- Immutable artifacts also have algorithm-qualified content digests.
- User-provided logical keys remain separate from identifiers.
- Identifiers never encode authorization or mutable business meaning.
- External representations use lowercase canonical UUID text and lowercase hexadecimal digests.

## Time policy

- External timestamps use RFC 3339 with UTC `Z` form.
- Internal precision is explicit and never exceeds what storage preserves.
- Causal sequence determines ordering; timestamp ties or skew never resolve conflicts.
- Expiration checks use an injected clock so domain tests remain deterministic.
