# Changelog

All notable project changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project will follow Semantic Versioning once versioned software is released.

## [Unreleased]

### Added

- Added portable `AuthorityEvidenceBundleV1` export and the independent
  `proof-verifier`, with separate caller-supplied Release and authority trust,
  an optional authority-head checkpoint, frozen golden vectors, and
  deterministic Complete, Incomplete, and Invalid reports.
- Added storage v14 persistence for canonical authenticated-command inputs and
  signed presentation envelopes, with atomic migration from every supported
  v1-v13 Workspace and no fabricated historical presentation bytes.
- Qualified the complete bounded local Linux Milestone 2 north star across the
  application contract, CLI, modern MCP, and legacy MCP, including structured
  repair, Human approval, portable independent verification, and clean
  distinct-UID signer/verifier containment.
- Added a pinned Ubuntu quality gate for formatting, Clippy, workspace tests,
  documentation tests, documentation links, and the repository work-control
  validator.
- Added a repository-local rolling-wave work map with explicit claims,
  dependencies, review gates, completion evidence, and machine-checked state.
- Ratified the exact-locale rendition contract: append-only repair, immutable
  Human-issued resource intent, and causally closed Edition/Release semantics.
- Ratified the bounded local authenticated-actor, direct Human-to-Agent
  Delegation, authority-log, and current-authorization retry contract.
- Implemented the exact-locale Human content foundation with append-only
  repair, immutable intent, versioned Edition/Release evidence, migration, and
  exact released-rendition queries.
- Implemented the bounded authenticated Agent read kernel with per-Agent
  Ed25519 bindings, single-use DSSE commands, direct Delegation evaluation,
  separately rooted canonical authority evidence, and equivalent CLI plus
  modern and legacy MCP broker paths.
- Implemented bounded delegated localized mutation across all 11 registered v2
  operations, with immutable Human-issued intent and ContextPack selection,
  separate Human approval, fresh current-authority evaluation, signed result
  and consequence commitments, Workspace-global successful idempotency, and
  equivalent application, CLI, modern MCP, and legacy MCP behavior.
- Added ordered `object.create` Edits with strict canonical input, Schema validation, atomic mixed ChangeSet commits, and immutable Object revisions.
- Added Object-bearing Known State and Edition commitments while preserving Schema-only canonical digests.
- Added versioned Environments, immutable promotion and rollback history, and portable Ed25519 DSSE/in-toto Release Proofs.
- Added registered Agent Principals, exact expiring and revocable Delegations, released-Object queries, and bounded ContextPacks.
- Added dry-run and atomic projection rebuilds that reproduce derived state from authoritative ChangeSet and Release evidence.
- Added domain-separated operation-effect commitments and transactional legacy
  backfill so retries and evidence consumers reject incomplete provenance
  rewrites across the ChangeSet, Edition, authority, and ContextPack lifecycle.
- Added Environment, Release, authority, ContextPack, projection, and offline
  Proof-envelope signature verification CLI operations plus dual-era MCP
  `2026-07-28` and `2025-11-25` support.
- Added the initial Rust 2024 workspace with enforced domain, application, and CLI dependency boundaries.
- Added UUIDv7 operation identifiers, shared result and Problem contracts, and the first `proof status` command.
- Added strict RFC 8785 canonical JSON and artifact-specific BLAKE3-256 content digests.
- Added crash-clean local Workspace initialization with committed TOML configuration and private SQLite state.
- Added verified local Workspace status with migration checks and a reproducible initial Known State digest.
- Added a Human bootstrap Principal bound to the authenticated Unix user for local Workspace operations.
- Added idempotent local ChangeSet draft creation bound to declared intent, Principal, and exact Known State.
- Added atomic approved ChangeSet commits with optimistic base-state checks, immutable Schema versions, and reproducible Known State advancement.
- Added immutable content-addressed Edition creation over committed Known State, Schema, and ChangeSet manifests.
- Added atomic ordered Schema-create Edit batches with strict NDJSON input and canonical document digests.
- Added authenticated `changeset get` and deterministic `changeset diff` projections with full persisted-evidence verification.
- Ratified the **Proof** product name and tagline, “Every release carries its proof.”
- Defined the product vision, scope, roadmap, and complete local MVP loop.
- Defined constitutional invariants for mutation, authority, validation, publication, state, interfaces, and security.
- Defined the initial domain model: Objects, Schemas, Edits, ChangeSets, Editions, Releases, Proofs, Principals, Delegations, ContextPacks, Environments, and Known State.
- Defined the CLI result, error, idempotency, output, and compatibility contracts.
- Established the August 3, 2026 Rust and dependency baseline.
- Adopted current standards for JSON Schema, UUIDv7, canonical JSON, Problem Details, DSSE, in-toto attestations, SLSA provenance, OAuth security, and MCP integration.
- Added the initial threat model, testing methodology, security policy, contribution policy, and architecture decision records.
