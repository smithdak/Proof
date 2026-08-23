# Proof conformance vectors

This directory contains portable, versioned compatibility contracts. A fixture
under `v1/` is immutable once a public Proof artifact depends on it; a semantic
change requires a new versioned directory.

The initial vectors cover:

- RFC 8785 canonical JSON bytes and fixed-point serialization.
- BLAKE3-256 outputs for each versioned derive-key context.
- The empty initial Known State manifest and digest.
- Accepted and rejected UUIDv7 operational identifiers.
- Proposed P-0008 collaboration-server authentication, HTTP registry, causal
  artifact, retained shape, and falsification-requirement contracts under
  `v1/collaboration-server/`; these are decision fixtures, not server-runtime
  qualification.

Digest values are algorithm-qualified and lowercase. Implementations must fail
closed on unknown algorithms, malformed encodings, duplicate JSON properties,
unsafe integer literals, and mismatched canonical bytes.
