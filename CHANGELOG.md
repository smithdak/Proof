# Changelog

All notable project changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project will follow Semantic Versioning once versioned software is released.

## [Unreleased]

### Added

- Added the initial Rust 2024 workspace with enforced domain, application, and CLI dependency boundaries.
- Added UUIDv7 operation identifiers, shared result and Problem contracts, and the first `proof status` command.
- Added strict RFC 8785 canonical JSON and artifact-specific BLAKE3-256 content digests.
- Added crash-clean local Workspace initialization with committed TOML configuration and private SQLite state.
- Added verified local Workspace status with migration checks and a reproducible initial Known State digest.
- Ratified the **Proof** product name and tagline, “Every release carries its proof.”
- Defined the product vision, scope, roadmap, and complete local MVP loop.
- Defined constitutional invariants for mutation, authority, validation, publication, state, interfaces, and security.
- Defined the initial domain model: Objects, Schemas, Edits, ChangeSets, Editions, Releases, Proofs, Principals, Delegations, ContextPacks, Environments, and Known State.
- Defined the CLI result, error, idempotency, output, and compatibility contracts.
- Established the August 3, 2026 Rust and dependency baseline.
- Adopted current standards for JSON Schema, UUIDv7, canonical JSON, Problem Details, DSSE, in-toto attestations, SLSA provenance, OAuth security, and MCP integration.
- Added the initial threat model, testing methodology, security policy, contribution policy, and architecture decision records.
