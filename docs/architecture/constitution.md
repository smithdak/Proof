# Core invariants

**Status:** Ratified  
**Baseline:** August 3, 2026

These invariants define Proof. An implementation that violates one is not a compatible implementation, even if its interfaces look similar.

## Mutation invariants

### C1. No mutation outside a ChangeSet

Every governed mutation MUST belong to exactly one ChangeSet. Internal maintenance tasks that rebuild projections MAY write derived state but MUST NOT alter authoritative facts.

### C2. ChangeSets are atomic

All Edits in a ChangeSet MUST be accepted together or rejected together. A crash, cancellation, timeout, failed validator, policy denial, or concurrency conflict MUST NOT leave a partial authoritative mutation.

### C3. Intent and base state are explicit

A ChangeSet MUST identify its declared intent and expected base state. An operation against stale state MUST conflict explicitly; it MUST NOT silently overwrite newer accepted work.

### C4. Retries are safe

Every consequential application operation MUST accept or derive an idempotency key. Repeating a completed request with the same key and equivalent input MUST return the original result without duplicating effects. Reusing a key with different input MUST fail.

## Authority invariants

### C5. Every action has a Principal

Every consequential request MUST identify an authenticated Principal. “System,” “anonymous,” or a shared service account MUST NOT obscure the operating identity in authoritative records.

### C6. Authority is evaluated at execution time

Authority MUST be evaluated against the requested action, resource, context, and current policy immediately before commit. Generating a proposal does not reserve authority to commit it later.

### C7. Delegation is bounded

A Delegation MUST identify issuer, recipient, allowed actions, resource scope, validity interval, and revocation state. Delegation MUST NOT expand authority, and sub-delegation is forbidden unless explicitly granted.

### C8. Agents have no bypass

Agent Principals MUST use the same state transitions, policy checks, validation, approvals, and evidence path as human and service Principals.

## Validation invariants

### C9. Deterministic code decides consequence

Probabilistic systems MAY propose or explain work. Authorization, invariant enforcement, schema validation, concurrency control, commit, publication, release, and verification MUST be deterministic.

### C10. Validation is bound to exact input

A validation result MUST identify the canonical ChangeSet digest, applicable policy and validator versions, base state, and relevant ContextPack. A result for one input MUST NOT authorize a different input.

### C11. Failure is structured

Expected failures MUST have stable machine-readable codes, locations, and repair information. Human prose MAY supplement structured data but MUST NOT be the only representation.

## Publication invariants

### C12. Editions are immutable

An Edition MUST be content-addressed and immutable after creation. A correction produces a new Edition.

### C13. Releases are explicit

Making content available to a delivery target MUST occur through a Release. A Release MUST identify its Edition, Environment, authority, policy evaluation, time, and resulting target state.

### C14. Rollback does not rewrite history

Rollback MUST create a new Release that selects an existing or newly created Edition. It MUST NOT delete or mutate prior Releases or Editions.

### C15. Proofs bind evidence to subjects

A Proof MUST bind its claims to immutable subject digests. Verification MUST fail closed when the payload, subject, signature, authority chain, or required evidence cannot be validated.

## State invariants

### C16. Authoritative facts are append-only

Accepted domain facts MUST be retained as an append-only sequence. Projections, indexes, caches, and snapshots are derived and MUST be rebuildable.

### C17. Known State is reproducible

Given the same authoritative facts, schemas, canonicalization rules, and deterministic code version, Proof MUST reproduce the same state digest.

### C18. Time is evidence, not ordering authority

Wall-clock timestamps MUST be recorded, but causal ordering MUST come from explicit sequence, parent, and state identifiers. Clock time alone MUST NOT determine conflict resolution.

## Interface invariants

### C19. No privileged interface

CLI, HTTP, SDK, MCP, and web interfaces MUST invoke the same application operations. No UI-only or MCP-only mutation path may bypass the domain.

### C20. Human output derives from structured output

Every command result MUST have a stable structured representation. Human-readable terminal output MUST be a projection of that representation.

### C21. Protocol adapters are replaceable

Transport protocols and model integrations MUST remain outside the domain core. MCP, HTTP, and future agent protocols MAY evolve without changing Proof's state-transition semantics.

## Security invariants

### C22. Secrets never enter content or Proof payloads

Secrets, bearer tokens, private keys, and raw credentials MUST NOT be serialized into Objects, ContextPacks, logs, Proof predicates, or diagnostic output.

### C23. Untrusted content remains data

Content and agent-produced values MUST NOT be interpreted as commands, policy, templates, filesystem paths, or executable code without an explicit typed boundary and validation.

### C24. Evidence survives redaction

When policy requires sensitive values to be removed, Proof MUST retain enough commitments, metadata, and authorized audit linkage to establish what was redacted and preserve chain integrity.

## Changing the constitution

A change to these invariants requires:

1. A dedicated ADR marked **Constitutional**.
2. Migration and compatibility analysis.
3. Updated conformance tests and fixtures.
4. Explicit approval from the project owner.
5. A versioned compatibility boundary if existing Proofs or Workspaces would change meaning.
