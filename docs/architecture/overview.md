# Architecture overview

**Status:** Ratified direction  
**Baseline:** August 3, 2026

## Architectural style

Proof uses a modular monolith for the first implementation, with domain-driven boundaries and ports-and-adapters dependency direction. This preserves transactional integrity and iteration speed while keeping extraction boundaries explicit.

It does not begin as microservices. Distribution is introduced only where independently measurable scale, isolation, or deployment requirements justify the operational cost.

## System shape

```text
┌─────────────────────────────────────────────────────────────┐
│ Interfaces                                                  │
│ CLI · HTTP · MCP · Rust SDK · TypeScript SDK · Web console │
└────────────────────────────┬────────────────────────────────┘
                             │ commands / queries
┌────────────────────────────▼────────────────────────────────┐
│ Application services                                        │
│ orchestration · idempotency · transactions · authorization │
└────────────────────────────┬────────────────────────────────┘
                             │ domain operations
┌────────────────────────────▼────────────────────────────────┐
│ Domain core                                                  │
│ Objects · ChangeSets · Policies · Editions · Releases       │
│ Principals · Delegations · ContextPacks · Proof predicates  │
└────────────────────────────┬────────────────────────────────┘
                             │ ports
┌────────────────────────────▼────────────────────────────────┐
│ Adapters                                                     │
│ persistence · identity · policy · keys · events · delivery  │
│ clock · hashing · signing · observability                    │
└─────────────────────────────────────────────────────────────┘
```

Dependencies point inward. The domain core has no dependency on CLI parsing, HTTP frameworks, databases, model SDKs, MCP, cloud services, or telemetry exporters.

## Write path

1. An interface converts input into a versioned application command.
2. The application layer authenticates the Principal and resolves Delegation.
3. After required authentication and current authorization, idempotency is
   checked before performing work or disclosing a stored result.
4. The relevant aggregate state is loaded against an explicit base identifier.
5. The domain evaluates invariants.
6. Authorization, policy, schema, and custom validators produce structured decisions.
7. The transaction appends accepted facts and updates required local projections atomically.
8. An outbox record is committed in the same transaction for asynchronous side effects.
9. The application returns a stable structured result and correlation chain.

No message is published before its authoritative transaction commits. External effects are delivered from the transactional outbox and are idempotent.

### Implemented P-0004 profile — authenticated delegated reads

The three enabled authenticated Agent reads use this ordering. The normative
contract is the [authenticated actor contract](authenticated-actor.md); P-0005
reuses the same kernel when it enables delegated mutation.

1. The adapter bounds and parses untrusted CLI or MCP input and authenticates
   the requesting Human through ADR-0009's Unix binding.
2. It verifies a fresh Ed25519 `AuthenticatedCommandV1` DSSE presentation for
   the operating Agent,
   including canonical payload bytes, audience, Workspace, operation version,
   request digest, `presentation_id`, and time bounds.
3. It resolves the validly issued immutable historical Human and Agent bindings
   and derives `AuthenticatedActorContextV1`; request identities are
   cross-checked only after derivation. Current binding/Principal state remains
   an authorization check in step 5.
4. The application treats request Principal identifiers as expected-value
   cross-checks and resolves the one direct Human-to-Agent Delegation.
5. It evaluates recipient, action, resource, budget, time, binding, revocation,
   and the immutable direct/v1 authority profile, producing canonical
   `AuthorizationDecisionV2` evidence.
6. One local transaction enforces unique `presentation_id`, appends signed
   `AuthorityRecordV1` consumption and decision records, resolves idempotency,
   and commits the governed consequence without a revocation check-then-act
   gap. A valid denial may consume the presentation and record a bounded
   decision but cannot move governed state or projections.
7. A retry uses a fresh presentation with the same idempotency key and
   equivalent normalized input. Fresh C5 authentication and current C6
   authorization must succeed before C4 may return a prior result; revocation
   or disablement blocks disclosure. A future mutable authority-policy profile
   must preserve the same rule.

The CLI broker and both MCP protocol eras enter this same executor. This does
not claim that the 11 localized mutation contracts are Agent-enabled.

## Read path

Queries read purpose-built projections. Projections are caches of authoritative facts, not independent truth. Each projection records the last applied sequence and schema version, allowing rebuild and verification.

Delivery reads immutable Editions or projections derived from a specific Edition. It never reads a partially committed ChangeSet.

## Authoritative records

The authoritative history is an append-only sequence of domain facts grouped by committed transaction. Each fact includes:

- Stable event type and schema version.
- Event and transaction identifiers.
- Workspace and aggregate identifiers.
- Causal parent or expected sequence.
- Principal and exercised Delegation identifiers.
- Canonical command or ChangeSet digest.
- Timestamp for evidence.
- Correlation and causation identifiers.

The local implementation may store these records in relational tables rather than an event-store product. “Event-sourced” describes the authority model, not a vendor dependency.

**Ratified P-0003 profile:** authority-bearing records additionally commit the
requesting and operating Principals, exact `binding_id` plus its issuing
authority sequence/record digest, and public
`requesting_subject_commitment`,
semantic `CommandInputV1` digest, authenticated-command envelope digest, direct
Delegation digest,
authorization-decision digest, and authority-log position. The separate
authority log is append-only,
causally ordered, independently rooted, and exportable as a portable authority
closure; it is not a derived content projection.
The requesting commitment is a hiding commitment formed with a 32-byte blind,
not a raw UID checksum; the actor-context digest contains the public commitment
and never the raw `os/unix` subject or blind. Audit policy controls disclosure
of the private opening. The authority hash chain detects mutation and reordering
only relative to a trusted later head. A local SQLite store plus file-backed
signer does not detect restoration of a valid older prefix or fork; that claim
requires an independently pinned authority-head checkpoint.

## Transaction boundaries

The ChangeSet is the primary business transaction boundary. Its commit includes all accepted domain facts, the idempotency record, and outbox entries required by that transition.

Edition construction is deterministic from a committed state. A Release is a separate transaction because it applies Environment-specific policy and may occur later or more than once.

## Concurrency

Proof uses optimistic concurrency:

- Commands name an expected state or sequence.
- Commit compares that expectation with current authoritative state.
- Mismatch returns a structured conflict.
- Proof does not automatically merge semantic content conflicts.
- A client MAY rebase a proposal by explicitly rebuilding it against a new ContextPack and base state.

## Local and server modes

### Local

- One executable.
- SQLite transactional store.
- Filesystem-backed artifact store.
- Local key provider suitable for development.
- In-process projections and delivery server.

**Ratified P-0003 profile:** the bootstrap Unix UID and private Workspace are
inside the Human/administrator trust boundary. Any process with that access can
use the direct-Human path without Agent authentication. Per-Agent Ed25519 proof
of possession is a containment control only when the Agent workload is outside
that UID/filesystem boundary and calls Proof through a Human-owned broker or
adapter; same-UID execution supplies attribution and integrity only. Milestone 2
must demonstrate a distinct UID, container, or sandbox denying repository, raw
CLI, and private Workspace access. Mutually hostile same-UID isolation requires
a protected broker or workload-identity profile, not this local file-backed one.

### Server

- The same application and domain crates.
- PostgreSQL transactional store.
- Durable object storage for immutable artifacts.
- OIDC and workload-identity adapters.
- Managed key provider.
- Outbox workers and remote delivery adapters.

The same conformance suite must pass in both modes. Storage-specific behavior cannot leak into domain semantics.

## Extension model

Extensions begin outside the process through versioned protocols. In-process Rust plugins have ABI and safety costs and are deferred.

Initial extension points:

- Validator command protocol with strict input/output schemas and resource limits.
- Event and webhook subscriptions.
- Import/export adapters.
- Delivery adapters.
- Identity and key-provider ports.
- MCP and other agent-protocol adapters.

WebAssembly may later provide a portable sandbox for deterministic validators, but it is not required for the first local proof loop.

## Observability

Every consequential operation propagates:

- `operation_id`
- `correlation_id`
- `causation_id`
- `workspace_id`
- `principal_id`
- `changeset_id`, `edition_id`, `release_id`, and `proof_id` when present

Structured events and traces must not contain content bodies, secrets, tokens, private keys, or unredacted ContextPacks by default.

## Architectural fitness functions

CI will enforce architecture through tests and tooling:

- Domain crates cannot depend on interface or infrastructure crates.
- All accepted state transitions have property and conformance tests.
- Unsafe Rust is forbidden in the domain and application crates.
- Projections can be deleted and rebuilt to the same digest.
- Local and server adapters pass the same behavioral contract.
- Public schemas and CLI JSON fixtures are compatibility-tested.
- Proof verification vectors run independently from state mutation tests.
