# Domain model

**Status:** Ratified baseline  
**Baseline:** August 3, 2026

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

Lifecycle:

```text
Draft → Validating → Ready → Submitted → Approved → Committed
  │         │          │         │          │
  └─────────┴──────────┴─────────┴──────────┴→ Rejected / Superseded / Expired
```

Only `Committed` changes authoritative content state. Approval does not guarantee commit: authority, policy, base state, and validation are rechecked at commit time.

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

## Delegation

A Delegation grants bounded authority from an issuer to a recipient Principal. It is immutable after issue; revocation creates a revocation fact. Evaluation follows the full chain, and no link may grant more than its parent.

See [Agent authority](agent-authority.md).

## ContextPack

A ContextPack is a content-addressed task context artifact. It contains the minimum state and rules needed to propose work, plus an explicit capability boundary. It is evidence, not authority: possessing one does not grant permission to commit.

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
