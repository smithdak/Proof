# Proof conformance vectors

This directory contains portable, versioned compatibility contracts. A fixture
under `v1/` is immutable once a public Proof artifact depends on it; a semantic
change requires a new versioned directory.

The initial vectors cover:

- RFC 8785 canonical JSON bytes and fixed-point serialization.
- BLAKE3-256 outputs for each versioned derive-key context.
- Accepted and rejected UUIDv7 operational identifiers.

Digest values are algorithm-qualified and lowercase. Implementations must fail
closed on unknown algorithms, malformed encodings, duplicate JSON properties,
unsafe integer literals, and mismatched canonical bytes.
