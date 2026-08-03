# ADR-0002: All governed mutation occurs through atomic ChangeSets

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Agents commonly perform multi-step work. Direct object updates can leave partial state after failure and make intent, validation, approval, and rollback difficult to reason about.

## Decision

Every governed mutation is represented as one or more Edits inside exactly one intent-scoped ChangeSet. The ChangeSet is committed atomically against an explicit base state after authority, policy, validation, and required approval checks.

Objects expose read operations but no public direct create, update, or delete operations.

## Consequences

- Multi-Object operations have one transaction and evidence boundary.
- Semantic diffs and approvals can bind to an exact digest.
- Concurrency conflicts are explicit.
- Simple one-field changes still require a ChangeSet, though the CLI may make creation concise.
- Storage adapters must support atomic fact, idempotency, and outbox persistence.

## Alternatives considered

- **Direct CRUD plus audit log:** cannot reliably prove atomic intent or prevent partial work.
- **Git commits as the only transaction:** useful as an adapter but insufficient for runtime authority, workflow, and content semantics.
- **Saga across individual writes:** introduces compensating complexity where one local transaction is possible.

## Verification

- No mutation application operation accepts an Object write outside a ChangeSet.
- Crash and rejection tests demonstrate no partial authoritative facts.
- Idempotency tests demonstrate at-most-one committed result.
