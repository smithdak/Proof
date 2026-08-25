# Changelog

All notable project changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project will follow Semantic Versioning once versioned software is released.

## [Unreleased]

### Added

- Implemented the initial human web console with its design system (P-0016):
  a new `web/` React 19 + Vite + TypeScript console covering Overview,
  ChangeSets (list, lifecycle detail with diff and validation findings,
  approve/commit), Released content, Editions and Releases (six-root
  verification report, deliveries), Proofs and Evidence, and Authority
  (principals, delegations) behind a session-aware shell with a global
  command palette. The notarial-register design system (laid-paper ground,
  iron-gall ink, prussian ruling hairlines, rubber-stamp status marks, one
  reserved consequential ink for irreversible actions) is documented in
  `DESIGN.md` with its primitive contract under `web/src/design-system/`.
  A typed client mirrors the exact nine-route HTTP surface and operation
  registry against contract-faithful MSW mocks with a seeded synthetic
  workspace; live-server wiring and production embedding remain open and
  require their own decision. 45 unit tests, mechanical design-detector
  pass, and 19 viewport captures recorded under `.impeccable/review/`.
- Implemented route-complete enrollment with usable credentials (P-0014):
  `agent-binding.issue/v1` verifies the caller-supplied enrollment closure
  (challenge validity, candidate-key proof of possession, and envelope
  binding) before any transaction and commits the immutable
  `PrincipalBindingV1` fact with single-use challenge consumption through the
  P-0010 unit of work; `oidc-binding.issue/v1` generates the fresh blind
  before the serializable transaction, commits the public commitment-only
  `OidcPrincipalBindingV1` plus its protected opening as paired facts, and
  rejects an unpinned issuer configuration or a duplicate subject at the
  locked snapshot. Issued Agent credentials authenticate end to end through
  the dual Human-session-plus-presentation boundary and complete governed
  operations; issued OIDC pairs resolve their subjects at login.
- Implemented remote evidence and the Milestone 3 qualification wave
  (P-0013): the exact six-root `RemoteEvidenceBundleV2` uncompressed logical
  member map with deterministic artifact paths and a closed Invalid taxonomy,
  keyed immutable `evidence.export/v2` capture with byte-identical replay and
  the separate no-key `evidence.export.get/v1` lifecycle read, exact
  `(export_id, kind, digest)` triple artifact acquisition over its HTTP
  route, `proof-verifier` remote-authority and remote-evidence v2 modes under
  explicit caller trust with inert producer hints, the closed
  `RemoteVerificationReportV2` with its three retained conformance scenarios,
  the complete remote north-star (two Humans, one Agent) end to end over HTTP
  and PostgreSQL reaching verifier Complete, the audited 158-code finding
  registry with exhaustive coverage partitioning, the completed nine-boundary
  crash matrix, and a per-step-classified local/server oracle conformance
  report.
- Implemented the artifact outbox and private preview delivery (P-0012):
  the generation-scoped leased outbox worker with deterministic stream
  claims, counted attempts, bounded exponential backoff, dead-letter and
  per-stream poison management, authorized replay and abandonment with
  `DeliveryManagementFactV1`, the filesystem-backed private preview adapter
  with ready-last manifests and the four exact alias outcomes, and the
  delivery projection and snapshot serving through the PostgreSQL unit of
  work.
- Implemented the HTTP and OIDC server boundary (P-0011): the exact
  nine-route HTTP surface with strict raw and canonical body limits,
  route-qualified registry dispatch, the same-origin confidential OIDC BFF
  with Authorization Code plus PKCE against a deterministic Ed25519 issuer,
  opaque hashed-at-rest sessions with bounded lifetimes and revocation
  convergence, the session-bound CSRF synchronizer with exact `Origin`
  enforcement, dual Human-session plus Agent-command authentication,
  per-row authorization with signed remote decisions and consequences
  through the PostgreSQL unit of work, the exact 41-tuple Problem registry
  with disclosure-neutral mapping, and the retained abuse matrix.
- Implemented the PostgreSQL parity foundation (P-0010): the checksummed
  migration ledger with a singleton migrator, the serializable Workspace
  write-lane authoritative transaction with the twelve-step contract
  algorithm, keyed idempotency with replay/conflict semantics and the
  savepoint rule, bounded retry and ambiguous-commit reconciliation, the
  artifact catalog with atomic PostgreSQL storage of fork-capable signed
  bytes, transactional-outbox enqueue, projection generation swaps, the
  verified SQLite-to-PostgreSQL import, the shared `StorageBackend` oracle
  boundary, byte-identical SQLite/PostgreSQL traces, and CI PostgreSQL
  service wiring.
- Implemented the remote actor and shared-contract conformance foundation
  (P-0009): the closed `RemoteAuthorityRecordV1` payload union with a
  single-signature DSSE envelope and causal chain validation; OIDC subject
  commitment machinery; `AuthenticatedActorContextV2`/`AuthenticatedActorContextEvidenceV2`
  profiles with public redaction; causal `ChangeSetApprovalV1` and
  `EnvironmentConfigV2` closures; the closed 23-row Human registry, 14-pair
  Agent projection, and nine-route surface with the three frozen registry
  SHA-256s recomputed byte-exactly; and the deterministic
  `RemoteSemanticOracle` producing byte-identical shared-operation traces over
  the SQLite reference path.
- Ratified the single-Workspace Milestone 3 collaboration-server decision:
  project owner `smithdak` accepted P-0008 candidate `c461b1b` and Engineering
  evidence `4ac62e9` at `2026-08-23T17:48:11.461Z`, ADR-0013 is Accepted, and
  the first dependency-ordered implementation successor, P-0009 remote actor
  and shared-contract conformance, is promoted.
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
