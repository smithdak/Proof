# ADR-0005: UUIDv7 operational identifiers

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Proof requires globally unique operational identifiers that work offline, sort approximately by creation time, and avoid leaking mutable business meaning. Random UUIDv4 values have poor index locality; sequential database IDs are coordination-bound and enumerable.

## Decision

Use UUIDv7 under RFC 9562 for operational entities such as Workspaces, Principals, ChangeSets, Editions, Releases, Proofs, and operation identifiers.

Immutable artifacts also receive content digests. Logical business keys remain separate.

## Consequences

- IDs can be generated without central coordination.
- Database locality and chronological inspection improve.
- Timestamp bits disclose approximate creation time and must not be treated as secret.
- Causal ordering still requires explicit sequence and parent relationships.

## Alternatives considered

- **UUIDv4:** adequate uniqueness but worse locality and ordering.
- **ULID:** similar properties but UUIDv7 now has an IETF standard and broad library support.
- **Database sequence:** simple but prevents offline creation and exposes cardinality.
- **Content digest only:** unsuitable for mutable operational entities and pre-content workflows.

## Verification

- RFC-conforming parsing and generation vectors.
- Monotonic-generation tests within supported process guarantees.
- Serialization uses canonical lowercase UUID text.
