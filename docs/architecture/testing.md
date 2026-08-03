# Testing and verification strategy

**Status:** Ratified methodology  
**Baseline:** August 3, 2026

Proof's correctness claim depends on executable evidence. Tests are organized around invariants and state transitions rather than crate coverage percentages alone.

## Test layers

### Domain examples

Focused tests document normal state transitions and rejected operations. Each test names the invariant it protects.

### Property-based tests

Property testing targets conditions that examples cannot cover adequately:

- Canonicalization is deterministic.
- Applying valid Edit sequences preserves Schema invariants.
- ChangeSet rejection leaves authoritative state unchanged.
- Retry with one idempotency key creates at most one effect.
- Projection rebuild produces the same state digest.
- Edition and Proof identifiers change when any committed subject changes.
- Delegation cannot expand authority through chaining.

### State-machine tests

Model-based tests generate command sequences across ChangeSet, Edition, Release, Delegation, and key-rotation lifecycles. The reference model is intentionally simpler than production code.

### Golden vectors

Version-controlled fixtures define compatibility for:

- UUID and timestamp serialization.
- Canonical JSON bytes.
- BLAKE3 domain-separated digests.
- ChangeSet and Edition manifests.
- DSSE pre-authentication encoding.
- Signed Proof envelopes.
- Structured errors and CLI JSON results.

Vectors include valid, malformed, ambiguous, oversized, unsupported-version, and tampered cases. At least one verifier implementation must consume vectors without using the producer's serialization path.

### Adapter contract tests

Persistence, identity, key, policy, and delivery adapters run shared behavioral suites. SQLite and PostgreSQL must demonstrate the same domain-observable semantics.

### End-to-end tests

End-to-end scenarios run the actual CLI through the local proof loop. Server tests run the same scenarios over HTTP. MCP tests invoke the same operations through protocol conformance fixtures.

### Security tests

- Fuzz parsers, canonicalization, patch application, Proof envelopes, and import formats.
- Exercise prompt injection, tool confusion, scope escalation, stale ContextPacks, and malicious content.
- Test denial behavior for revoked, expired, malformed, and cyclic Delegations.
- Test archive traversal, symlink, URL-resolution, and decompression limits.
- Test crash consistency and recovery at transaction boundaries.
- Use concurrency model checking for critical queues, locks, and outbox behavior where applicable.

### Migration tests

Every persistent Schema or event-version migration includes fixtures from the previous supported version, forward migration, verification, and documented rollback behavior.

## Required developer checks

The implementation CI baseline will include:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features
cargo test --doc --workspace
cargo llvm-cov nextest --workspace --all-features
cargo deny check
cargo audit
cargo semver-checks
```

Additional scheduled jobs run fuzz targets, mutation testing, minimum-supported-Rust-version checks when an MSRV policy is declared, and dependency freshness review.

## Coverage policy

Line coverage is diagnostic, not a quality target by itself. The release gate requires:

- Every constitutional invariant mapped to executable tests.
- Every public error type covered by a fixture.
- Every state transition covered by accepted and rejected paths.
- Every Proof format version covered by golden vectors.
- Every security boundary covered by abuse cases.

Coverage trends must not regress materially, but a numeric percentage cannot replace these gates.

## Determinism policy

Tests inject clock, random source, identifier generator, key provider, and external I/O. Golden tests never depend on wall time, locale, filesystem ordering, map iteration order, network access, or platform-specific path formatting.

## Agent evaluations

Agent evaluations measure whether representative agents can discover, propose, repair, and complete tasks through stable contracts. They are separate from correctness tests.

Evaluation dimensions include:

- Task completion within delegated scope.
- Number and type of repair iterations.
- ContextPack sufficiency and unnecessary disclosure.
- Correct handling of conflicts and approval gates.
- Attempts to exceed capabilities.
- Token, latency, and operation budgets.

A strong evaluation score never bypasses deterministic validation or authorization.

## Release evidence

A release candidate is eligible only when it has:

- Passing required checks on supported platforms.
- Locked dependencies and reviewed advisory results.
- SBOM and dependency-license report.
- Signed build artifacts and provenance attestation.
- Reproducibility comparison where the platform permits it.
- Verification of bundled Proof golden vectors using the released binary.
