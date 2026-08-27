# Testing and verification strategy

**Status:** Ratified methodology with completed bounded local Linux Milestone 2 qualification
**Baseline:** August 23, 2026

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
- Portable `AuthorityEvidenceBundleV1` directories, caller trust policies,
  authority-head checkpoints, and canonical Complete, Incomplete, and Invalid
  verifier reports.
- Structured errors and CLI JSON results.

Vectors include valid, malformed, ambiguous, oversized, unsupported-version, and tampered cases. At least one verifier implementation must consume vectors without using the producer's serialization path.

P-0006 satisfies that independence requirement with `proof-verifier`, which
does not depend on producer-side Workspace reconstruction or serialization and
consumes frozen portable fixtures under explicit caller trust.

### Adapter contract tests

Persistence, identity, key, policy, and delivery adapters run shared behavioral suites. SQLite and PostgreSQL must demonstrate the same domain-observable semantics.

### End-to-end tests

End-to-end scenarios run the actual CLI through the local proof loop. The
retained Milestone 2 north star also runs the same semantic lifecycle through
the application contract, CLI, modern MCP, and legacy MCP. Its Agent signer and
clean verifier execute under a distinct Linux UID. The signer receives its
scoped Agent credential but no repository, private Workspace, Workspace
authority/Release key, ambient CLI, or network-resolution access; the verifier
receives no private key. Server tests will run the same scenarios over HTTP
after the Milestone 3 contract is ratified.

### Accepted P-0008 local/server conformance

P-0008 separates three evidence classes: retained local executable evidence,
decision-contract Schemas/vectors validated with the proposal, and future
server executable evidence that remains unrun. “The same suite” means one
shared application/domain oracle plus adapter-specific coverage, not identical
test inventories or comparison of SQLite and PostgreSQL rows.

The retained P8 decision and `RemoteApplicationConsequenceV1` instances are
decoded, canonicalizable, signable candidate payloads, not a retained matching
signed pair. Its three normative Complete/Incomplete/Invalid scenarios are unobserved
requirements. A runtime `RemoteVerificationReportV2` is the general closed
outcome type; the exact three-scenario `conformanceReport` is its narrower
qualification subtype.

The server matrix requires:

- local and HTTP adapters to normalize to the same operation input, result,
  Problem, state digest, and evidence consequence for every accepted and
  rejected row;
- exact registry equality among HTTP path/version, capability discovery,
  application and authority operations, input/result Schemas, idempotency,
  concurrency, Problems, limits, and consequence classes;
- deterministic OIDC issuer/JWKS, session, CSRF, remote-Human binding, dual
  Human-plus-Agent authentication, role, and separation-of-duties vectors;
- PostgreSQL two-writer, revocation, Environment-pointer, same/different-key,
  savepoint, serialization/deadlock retry, ambiguous-commit, migration, and
  projection-generation cases;
- crash points before/after artifact staging, authoritative commit, outbox
  claim/send/acknowledgement, lease expiry, poison/replay, and monotonic preview
  application, including rejection of a leaked signed pre-commit orphan/fork
  and enforcement of one lowest-eligible lease per stream;
- clean remote logical-member-map verification with exact kind-and-digest
  acquisition, first-profile producer hint arrays fixed empty, and separate
  caller `VerificationTrustPolicyV2`, checkpoint, opening, and external-byte
  inputs; and
- immutable keyed export-create replay that always returns the same pending
  result while the no-key lifecycle read independently observes pending or
  ready producer state.

No row is considered passed until its later implementation successor runs the
test. The normative matrix is in the
[collaboration-server contract](collaboration-server.md).

### Security tests

- Fuzz parsers, canonicalization, patch application, Proof envelopes, and import formats.
- Exercise prompt injection, tool confusion, scope escalation, stale ContextPacks, and malicious content.
- Test denial behavior for revoked, expired, malformed, and cyclic Delegations.
- Test logical-map absolute/dot-segment/backslash paths, duplicate normalized
  paths, undeclared or missing entries, wrong-kind digest aliases, and running
  count/byte limits. P8 defines no archive, symlink, compression, or
  decompression input to accept.
- Test crash consistency and recovery at transaction boundaries.
- Tamper or withhold every supplied portable-evidence component and verify
  deterministic Complete, Incomplete, or Invalid classification without
  producer authority.
- Exercise fixed-input broker boundaries, path-shaped arguments, symlinks,
  distinct-UID containment, and clean-directory verification.
- Use concurrency model checking for critical queues, locks, and outbox behavior where applicable.

### Migration tests

Every persistent Schema or event-version migration includes fixtures from the previous supported version, forward migration, verification, and documented rollback behavior.

## Current enforced quality gate

The Ubuntu 24.04 workflow currently enforces:

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --doc --workspace --all-features
node scripts/check-doc-links.mjs
node scripts/check-work-items.mjs
```

The accepted P-0006 candidate passed this complete gate on Ubuntu 24.04: 604
tests across 36 suites with zero failures, strict Clippy with warnings denied,
doc tests, documentation links, and work-control validation. Namespace-capable
execution ran the retained bubblewrap containment tests rather than skipping
them. This remains Linux qualification, not cross-platform or release
eligibility.

This is a quality gate, not release eligibility. The planned release and
tooling baseline remains:

```bash
cargo nextest run --workspace --all-features
cargo llvm-cov nextest --workspace --all-features
cargo deny check
cargo audit
cargo semver-checks
```

Additional scheduled jobs run fuzz targets, mutation testing, minimum-supported-Rust-version checks when an MSRV policy is declared, and dependency freshness review.

## Coverage policy

Line coverage is diagnostic, not a quality target by itself. Release
eligibility requires:

- Every constitutional invariant mapped to executable tests.
- Every public error type covered by a fixture.
- Every state transition covered by accepted and rejected paths.
- Every Proof format version covered by golden vectors.
- Every security boundary covered by abuse cases.

Coverage trends must not regress materially, but a numeric percentage cannot replace these gates.

P-0006 maps C1-C24 to retained accepted and rejected paths. Its closed public
verifier registry contains 163 codes: 30 have direct behavioral assertions and
133 have structural emitted-source/registry equality guards. The structural
classification satisfies P-0006 enumeration but does not claim a dedicated
branch-level test for each code or weaken future release-eligibility coverage.

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

Milestone 2 completion does not satisfy this release gate: signed build
artifacts, an SBOM, provenance, reproducibility comparison, public distribution,
and supported-platform qualification remain future work.
