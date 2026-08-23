# Proof

> Every release carries its proof.

Proof is a Rust, CLI-first enterprise content management system designed for work performed by people and software agents.

It treats content mutation as a governed transaction. Every proposed change has an identity, intent, scope, authority, validation result, and provenance trail. Publishing produces an immutable Edition. Releasing that Edition produces a verifiable Proof of what changed, why it changed, who or what was authorized to change it, which rules passed, and what became available to consumers.

## Project status

**Milestones 1 and 2 complete — local proof loop plus bounded local Linux
Agent authority. P-0008 is project-owner accepted; P-0009 remote actor and
shared-contract conformance is complete, and P-0010 PostgreSQL parity
foundation is the promoted Milestone 3 implementation frontier.**

The implemented local path covers authenticated Workspace initialization,
idempotent ChangeSets, exact-locale Human-path repair and release, deterministic
validation, exact-evidence approval and commit, reproducible Known State,
immutable Editions, versioned Environments, signed Release Proofs, persisted
Release verification, offline verification against explicit caller trust, and
projection rebuild. The authority kernel adds per-Agent Ed25519 bindings,
single-use authenticated commands, direct bounded Delegations, canonical
authorization evidence, ContextPacks, capability discovery, and equivalent CLI
and dual-era MCP broker paths for all 14 enabled authenticated operations. The
11 localized `/v2` operations bind Agent execution to immutable Human-issued
resource intent and ContextPack closure; approval and closure issuance remain
Human-only. Their signed decisions commit the exact application result and
consequence, while storage schema v14 preserves canonical command presentations,
per-presentation evidence, and Workspace-global successful idempotency. A
portable `AuthorityEvidenceBundleV1` export and producer-independent
`proof-verifier` reconstruct the disclosed bounded Agent content, approval,
policy, Release, and authority closure under explicit caller trust and an
optional independent authority-head checkpoint, reporting Complete, Incomplete,
or Invalid without the producing Workspace or private keys. A matching
checkpoint bounds the supplied authority prefix; it does not prove a globally
latest or true immediate same-Environment Release. The accepted Linux
qualification runs the signer and clean verifier under a distinct UID with only
the bounded broker or read-only evidence inputs. Mutually hostile same-UID
isolation, Windows runtime containment, server execution, deployment, and a
public release remain unqualified. P-0008 has an accepted single-Workspace
server boundary for OIDC Human sessions, dual Human-plus-Agent requests,
PostgreSQL parity, causal approval, at-least-once preview delivery, and remote
evidence; it is a ratified decision contract, not an implemented capability.
P-0009 has implemented the remote actor and shared-contract conformance
foundation — remote authority payloads and envelopes, OIDC subject
commitments, actor-context evidence redaction, causal approval and
Environment configuration closures, the closed operation registries with
their frozen hashes, and the deterministic semantic oracle. P-0010 implements
the PostgreSQL parity foundation every later server adapter consumes.

Linux CI is the current quality gate. It does not establish release eligibility,
signed artifacts, an SBOM, provenance, reproducibility, or public distribution.
Local Windows compilation or test execution is not live Windows runtime
qualification or a published Windows support claim.

| Area | Status |
| --- | --- |
| Product definition | Ratified |
| Domain vocabulary | Ratified |
| Core invariants | Ratified |
| Technology baseline | Ratified for implementation start |
| CLI contract | Local proof loop implemented |
| Rust implementation | Milestones 1 and 2 complete for the bounded local Linux profile; Milestone 3 foundation (P-0009) implemented; server not implemented |
| Milestone 3 contract | Ratified (P-0008 accepted by project owner `smithdak` on 2026-08-23); first successor P-0009 promoted |
| Continuous integration | Linux quality gate |
| Public release | Not available |

## Why Proof

Traditional CMS products were designed around humans clicking through administrative interfaces. Their APIs were generally added later as secondary integration surfaces. Adding an AI assistant to that model does not make it agent-native: the underlying system still relies on broad credentials, mutable records, implicit context, opaque workflows, and weak operational evidence.

Agents need a different foundation:

- Complete machine-readable capabilities rather than UI automation.
- Authority that is explicit, narrow, delegable, revocable, and time-bound.
- Bounded task context rather than unrestricted repository access.
- Deterministic validation before consequential mutations are accepted.
- Atomic ChangeSets rather than sequences of partial writes.
- Structured, repairable failures rather than prose-only errors.
- Immutable publication artifacts and independently verifiable receipts.
- A reliable way to identify and reconstruct the current Known State.

Proof is an actual CMS—not an AI wrapper around another CMS and not a digital experience platform. It will provide structured content, schemas, relationships, localization, workflow, permissions, publication, delivery, and auditability. Its agent-first architecture changes how those capabilities are exposed and governed.

## The defining model

```text
Intent
  ↓
ContextPack
  ↓
ChangeSet
  ├── one or more Edits
  ├── initiating Principal
  ├── delegated authority
  ├── declared scope
  └── expected base state
  ↓
Deterministic validation and policy evaluation
  ├── rejected → structured findings and repair guidance
  └── accepted
        ↓
Immutable Edition
        ↓
Release to an Environment
        ↓
Proof
        ↓
Known State
```

An Edition answers, **“What exact content state was accepted?”**

A Release answers, **“Where and under what conditions was that Edition made available?”**

A Proof answers, **“What verifiable evidence supports that state transition?”**

## Non-negotiable principles

1. **The CLI is a complete product surface.** It is not an administrative accessory. Future APIs, SDKs, MCP servers, and web interfaces use the same application contracts.
2. **Agents are Principals, not features.** Humans, services, and agents use the same transaction model and evidence requirements.
3. **Every mutation expresses intent.** Direct writes to governed content do not exist; mutations enter through an atomic ChangeSet.
4. **Deterministic systems govern probabilistic systems.** Models may propose. Deterministic code authorizes, validates, commits, and verifies.
5. **Published state is immutable.** Corrections produce new Editions. History is never silently rewritten.
6. **Proof means operational evidence.** It establishes how a change occurred; it does not claim that content is factually true.
7. **The core is model-neutral.** No model vendor, agent framework, or transport protocol owns the domain.
8. **Local and enterprise modes share semantics.** Deployment topology cannot change the meaning of a state transition.

The complete constitution is in [Core invariants](docs/architecture/constitution.md).

## Canonical vocabulary

| Term | Meaning |
| --- | --- |
| **Object** | A uniquely identified instance of structured content. |
| **Schema** | A versioned contract for an Object's fields, relationships, and constraints. |
| **Edit** | One proposed mutation to governed state. |
| **ChangeSet** | An atomic, intent-scoped collection of Edits. |
| **Edition** | An immutable, content-addressed accepted content state. |
| **Release** | Promotion of an Edition to a named delivery target. |
| **Proof** | A verifiable receipt for a consequential state transition. |
| **Known State** | State that Proof can identify, reproduce, and verify. |
| **Principal** | An authenticated human, service, or agent identity. |
| **Delegation** | A scoped grant allowing one Principal to act under another's authority. |
| **ContextPack** | A bounded package of task-relevant state, rules, and capabilities for an agent. |

See the complete [domain model](docs/architecture/domain-model.md).

## Implemented CLI

The executable is `proof`. Human-readable output is a projection of the same structured result returned to agents.

```bash
proof init
proof auth sign --command - --credential agent-a
proof auth execute --invocation -
proof changeset create --intent "Localize the homepage for fr-CA"
proof changeset add <changeset-id> --file edits.ndjson
proof changeset diff <changeset-id>
proof changeset validate <changeset-id>
proof changeset submit <changeset-id>
proof changeset approve <changeset-id> --approval release
proof changeset commit <changeset-id> --idempotency-key <uuid-v7>
proof edition create
proof environment create preview --required-approval release
proof release create --edition <edition-id> --environment preview --idempotency-key <uuid-v7>
proof object query --environment preview --object-id <object-id>
proof release verify <release-id>
proof evidence export --release-id <release-id> --directory <new-directory>
proof projection rebuild --dry-run
proof projection rebuild
proof verify --file release.dsse.json --trusted-key-id ed25519:<64-hex> --expected-envelope-digest blake3:<64-hex>
proof-verifier verify --bundle <directory> --trust <file> [--checkpoint <file>] [--external-root <path>]...
```

`auth sign` and `auth execute` carry the three retained `/v1` reads and all 11
localized `/v2` operations through one normalized application contract. The
localized path reauthorizes every fresh presentation against current Principal,
binding, Delegation, intent, ContextPack, approval, and state closure before it
returns a prior result or commits a new consequence. `release verify` evaluates
the complete persisted local Release evidence. The `proof verify` command
checks canonical envelope bytes, the expected digest, and an Ed25519 signature
against caller-supplied trust; it does not claim to verify Workspace policy or
persisted evidence. The separate `proof-verifier` consumes an exported portable
closure and independently evaluates its transitive content and authority
evidence. The exact implemented grammar and outcome exits are in the
[CLI reference](docs/reference/cli.md). The broader compatibility target remains
there as well.

## Architecture direction

Proof uses a deterministic domain core surrounded by replaceable adapters:

```text
CLI · HTTP API · MCP · SDKs · Web console
                  │
          Application services
                  │
     Domain model and state transitions
                  │
 Persistence · Identity · Policy · Keys · Events · Delivery
```

The architecture favors explicit state machines, append-only facts, content-addressed artifacts, ports and adapters, and dependency direction toward the domain. Event history is authoritative; indexes and projections are rebuildable.

The initial implementation baseline uses:

- Rust 1.97.1, Rust 2024 Edition, and Cargo resolver 3.
- JSON Schema Draft 2020-12 for content shape.
- UUIDv7 for sortable operational identifiers.
- RFC 8785 JCS for canonical JSON artifacts.
- BLAKE3 with domain separation for internal content addressing.
- DSSE and in-toto Statement v1 concepts for signed Proof envelopes.
- SQLite for the first local transactional store; PostgreSQL is the server target.
- MCP 2026-07-28 as the stateless default, with per-request version and capability metadata, plus initialization-based MCP 2025-11-25 compatibility for legacy clients.

See the [technology baseline](docs/reference/technology-baseline.md) and [standards profile](docs/reference/standards.md).

## Documentation

Start with the [documentation map](docs/README.md).

### Product

- [Vision and product thesis](docs/product/vision.md)
- [Scope and non-goals](docs/product/scope.md)
- [Roadmap and MVP](docs/product/roadmap.md)

### Architecture

- [Core invariants](docs/architecture/constitution.md)
- [System architecture](docs/architecture/overview.md)
- [Single-Workspace collaboration-server architecture](docs/architecture/collaboration-server.md)
- [Domain model](docs/architecture/domain-model.md)
- [Agent authority and ContextPacks](docs/architecture/agent-authority.md)
- [Proof format and verification](docs/architecture/proof-model.md)
- [Threat model](docs/architecture/threat-model.md)
- [Testing strategy](docs/architecture/testing.md)

### Reference

- [CLI contract](docs/reference/cli.md)
- [Error model](docs/reference/errors.md)
- [Technology baseline](docs/reference/technology-baseline.md)
- [Standards profile](docs/reference/standards.md)
- [Architecture decision records](docs/decisions/README.md)

### Execute current work

- [Rolling-wave work map](docs/work/map.md)
- [Work-control protocol](docs/work/README.md)

## North-star first release

The planned first release is one complete local vertical slice:

1. Initialize a Workspace.
2. Define and version a Schema.
3. Create a Principal and scoped Delegation.
4. Build a task-specific ContextPack.
5. Propose multiple Object Edits in a ChangeSet.
6. Diff and validate the ChangeSet deterministically.
7. Commit it atomically against an explicit base state.
8. Create an immutable Edition.
9. Release it to a local Environment.
10. Query the released content.
11. Verify the Release Proof.
12. Reconstruct the same Known State from canonical records.

## Contributing and security

Proof has completed its local proof loop and bounded local Linux Agent-authority
profile, including portable independent verification and distinct-UID broker
containment. Collaboration-server, cross-platform, deployment, and public
release qualification remain. Read [CONTRIBUTING.md](CONTRIBUTING.md)
before proposing a change. Report vulnerabilities according to
[SECURITY.md](SECURITY.md); do not open public security issues.

## License

No open-source license has been selected yet. Until a license is added, the repository remains publicly visible but is not licensed for redistribution or derivative works.
