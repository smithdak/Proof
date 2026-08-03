# Technology baseline

**Status:** Ratified for implementation start  
**As of:** August 3, 2026

This document records the implementation baseline, not a promise to depend on every listed library. Exact dependency versions will be locked in `Cargo.lock`, reviewed by automated update tooling, and changed through normal compatibility and security review.

## Language and workspace

| Item | Baseline | Decision |
| --- | --- | --- |
| Rust toolchain | `1.97.1` | Pin CI and release builds to the current patched stable toolchain. |
| Rust Edition | `2024` | Use current stable language semantics. |
| Cargo resolver | `3` | Use the Edition 2024 dependency resolver. |
| Unsafe policy | Forbidden in domain and application crates | Isolate unavoidable unsafe or FFI in audited adapters. |
| Dependency lock | Commit `Cargo.lock` | Proof is an application and requires reproducible dependency resolution. |

Rust 1.97.1 fixes an LLVM miscompilation affecting 1.97.0, so 1.97.0 is not the baseline.

## Audited dependency candidates

These are current stable candidates verified during the August 2026 documentation pass. A dependency is added only when an implementation requirement exists.

| Concern | Candidate | Current stable candidate |
| --- | --- | ---: |
| CLI parsing | `clap` | `4.6.5` |
| Serialization | `serde` | `1.0.229` |
| Canonical JSON | `serde_json_canonicalizer` | `0.3.2` |
| Workspace configuration | `toml` | `1.1.4` |
| Domain errors | `thiserror` | `2.0.19` |
| Operational IDs | `uuid` | `1.24.0` |
| UTC timestamps | `time` | `0.3.55` |
| Content digest | `blake3` | `1.8.5` |
| Local SQLite | `rusqlite` | `0.40.1` |
| Local OS identity | `rustix` | `1.1.4` |
| JSON Schema validation | `jsonschema` | `0.49.3` |
| Async runtime | `tokio` | `1.53.1` |
| HTTP server | `axum` | `0.8.9` |
| Structured tracing | `tracing` | `0.1.44` |
| Trace collection | `tracing-subscriber` | `0.3.23` |
| Server SQL | `sqlx` | `0.9.0` |

Version policy:

- Do not adopt alpha, beta, or RC dependencies in the stable runtime without a recorded exception.
- Prefer focused crates and disable unnecessary default features.
- Use `rustls`-based TLS where an adapter requires TLS unless platform requirements dictate otherwise.
- Keep cryptographic algorithm selection in domain contracts and implementation providers behind ports.
- Record minimum-supported-Rust-version policy before the first public crate release; until then, the pinned toolchain is authoritative.

## Core architecture

### Domain and application

- Synchronous deterministic core where possible.
- Explicit state machines and newtypes for identifiers and digests.
- No dependency on Tokio, Axum, SQLx, MCP, or model SDKs in domain crates.
- `thiserror` for typed library errors; application boundaries translate them to the shared Problem model.
- `serde` only at explicit serialization boundaries; domain constructors enforce invariants after deserialization.

### Persistence

- SQLite with WAL and foreign keys for the first local mode.
- PostgreSQL for collaborative server mode.
- Append-only authoritative facts plus rebuildable projections.
- Transactional outbox for external events.
- Explicit migrations; no automatic destructive Schema changes at startup.
- Storage adapters pass the same contract suite.

`rusqlite` is preferred for the first synchronous local implementation. SQLx is reserved for the asynchronous PostgreSQL server adapter rather than forcing one abstraction across different operational modes.

### Serialization and identity

- JSON Schema Draft 2020-12 for content Schemas and public contracts.
- RFC 8785 JCS for canonical JSON artifacts.
- UUIDv7 under RFC 9562 for operational identifiers.
- RFC 3339 UTC timestamps.
- Algorithm-qualified digests.
- BLAKE3 derive-key contexts for internal domain separation.

### Proofs and signing

- DSSE envelope semantics.
- in-toto Statement v1 with a versioned Proof predicate.
- Ed25519 initial signature profile.
- Enterprise key provider abstraction supporting KMS and HSM implementations.
- SHA-256 co-digests where external attestation ecosystems require them.

### Interfaces

- `clap`-generated CLI and shell completions.
- Axum/Tower for the server HTTP adapter.
- RFC 9457 Problem Details for HTTP errors.
- OpenAPI 3.2.0 generated or validated from the same operation contracts.
- Stable MCP `2025-11-25` first; protocol negotiation required.
- The July 2026 MCP revision remains gated until its final upstream release and SDK conformance.

### Observability

- `tracing` in Rust code.
- OpenTelemetry export at deployment boundaries.
- Structured logs with denylisted sensitive fields and explicit content redaction.
- Correlation and causation identifiers across commands, facts, outbox delivery, Releases, and Proofs.

## Engineering toolchain

Planned baseline:

- `rustfmt` and Clippy with warnings denied.
- `cargo-nextest` for test execution.
- `cargo-llvm-cov` for diagnostic coverage.
- `cargo-deny` for advisories, licenses, bans, and sources.
- `cargo-audit` as a second advisory signal.
- `cargo-semver-checks` for public crate compatibility.
- `cargo-fuzz` for parser and artifact boundaries.
- `cargo-mutants` for targeted mutation testing.
- `proptest` for domain properties.
- `loom` where concurrent behavior warrants model checking.
- `insta` or explicit fixtures for reviewed snapshots; security and canonicalization vectors remain plain portable files.

## Supply-chain baseline

- Pin GitHub Actions to full commit SHAs.
- Use least-privilege workflow permissions and no write token for untrusted pull-request checks.
- Generate SPDX or CycloneDX SBOMs for releases.
- Produce SLSA v1.2 provenance.
- Sign release artifacts and publish verification instructions.
- Run dependency, license, secret, and scorecard checks.
- Avoid install-time shell pipelines and unverified binary downloads.
- Preserve source, lockfile, compiler, target, and build configuration in release evidence.

## Version maintenance

The baseline is reviewed:

- Before implementation begins.
- At least monthly during active development.
- Immediately for relevant security advisories or compiler correctness releases.
- Before each release candidate.

Updates are grouped by compatibility risk and accompanied by the relevant test and artifact-verification results.

## Primary version sources

- [Rust release announcements](https://blog.rust-lang.org/releases/)
- [clap releases](https://github.com/clap-rs/clap/releases)
- [Serde releases](https://github.com/serde-rs/serde/releases)
- [serde_json_canonicalizer releases](https://github.com/evik42/serde-json-canonicalizer/releases)
- [toml releases](https://github.com/toml-rs/toml/releases)
- [thiserror releases](https://github.com/dtolnay/thiserror/releases)
- [UUID releases](https://github.com/uuid-rs/uuid/releases)
- [Tokio releases](https://github.com/tokio-rs/tokio/releases)
- [Axum releases](https://github.com/tokio-rs/axum/releases)
- [Tracing releases](https://github.com/tokio-rs/tracing/releases)
- [rusqlite releases](https://github.com/rusqlite/rusqlite/releases)
- [rustix releases](https://github.com/bytecodealliance/rustix/releases)
- [jsonschema releases](https://github.com/Stranger6667/jsonschema/releases)
- [time releases](https://github.com/time-rs/time/releases)
- [SQLx changelog](https://github.com/transact-rs/sqlx/blob/main/CHANGELOG.md)
- [BLAKE3 releases](https://github.com/BLAKE3-team/BLAKE3/releases)
- [OpenAPI Specification 3.2.0](https://spec.openapis.org/oas/v3.2.0.html)
- [MCP specification releases](https://github.com/modelcontextprotocol/modelcontextprotocol/releases)
