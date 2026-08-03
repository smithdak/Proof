# ADR-0007: Begin as a modular monolith with storage adapters

**Status:** Accepted  
**Date:** 2026-08-03

## Context

The first Proof milestone needs strong transactions, fast domain iteration, and a local single-binary mode. Beginning with distributed services would add failure modes and operational work before scale boundaries are known.

## Decision

Build a modular monolith with ports-and-adapters dependency direction. Use SQLite for local mode and PostgreSQL for server mode through behavioral storage contracts. Use an append-only authoritative fact model with rebuildable projections and a transactional outbox.

Do not adopt a microservice boundary until measured scaling, isolation, ownership, or deployment needs justify extraction.

## Consequences

- Atomic ChangeSet semantics remain straightforward.
- Local and server modes can share domain code.
- Module boundaries must be enforced in CI rather than by network boundaries.
- Storage adapters require shared contract tests.
- Later extraction uses explicit application events and ports already present.

## Alternatives considered

- **Microservices first:** rejected due to transaction, consistency, and operational cost.
- **One database CRUD model without facts:** simpler initially but weak for replay, evidence, and projection rebuild.
- **External event-store product:** unnecessary dependency for the initial semantics.

## Verification

- Architecture dependency tests.
- Projection rebuild and digest comparison.
- Identical behavioral suites for storage adapters.
- Transactional outbox crash and retry tests.
