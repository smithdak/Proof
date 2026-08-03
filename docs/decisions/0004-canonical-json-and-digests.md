# ADR-0004: RFC 8785 canonical JSON and algorithm-qualified digests

**Status:** Accepted  
**Date:** 2026-08-03

## Context

Reproducible Editions, ContextPacks, validation records, and Proof predicates require stable bytes. Ordinary JSON permits insignificant representation differences. Bare digest strings create algorithm ambiguity.

## Decision

Use JSON Schema Draft 2020-12 for JSON contracts and RFC 8785 JCS for canonical JSON artifact bytes. Use algorithm-qualified digest strings. Use BLAKE3-256 with derive-key domain separation for internal content addressing and include SHA-256 co-digests when an external attestation ecosystem requires them.

## Consequences

- Independent implementations can reproduce artifact bytes and identifiers.
- JSON data must conform to JCS and I-JSON constraints; values outside interoperable numeric range use typed strings.
- Unicode strings are preserved exactly rather than normalized silently.
- Algorithm selection is explicit and versioned.
- Golden interoperability vectors are required.

## Alternatives considered

- **Pretty or insertion-ordered JSON:** not reproducible across implementations.
- **Canonical CBOR:** technically strong but less inspectable and less aligned with CMS and agent tool ecosystems for the first version.
- **SHA-256 only:** broadly interoperable but slower for internal large-content addressing; retained as a compatibility co-digest.

## Verification

- Cross-language golden vectors for canonical bytes and digests.
- Negative vectors for duplicate keys, invalid Unicode, unsupported numbers, and algorithm confusion.
- Artifact type domain-separation tests.
