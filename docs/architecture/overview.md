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
3. Idempotency is checked before performing work.
4. The relevant aggregate state is loaded against an explicit base identifier.
5. The domain evaluates invariants.
6. Authorization, policy, schema, and custom validators produce structured decisions.
7. The transaction appends accepted facts and updates required local projections atomically.
8. An outbox record is committed in the same transaction for asynchronous side effects.
9. The application returns a stable structured result and correlation chain.

No message is published before its authoritative transaction commits. External effects are delivered from the transactional outbox and are idempotent.

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
