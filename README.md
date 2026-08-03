# Proof

> Every release carries its proof.

Proof is a Rust, CLI-first enterprise content management system designed for work performed by people and software agents.

It treats content mutation as a governed transaction. Every proposed change has an identity, intent, scope, authority, validation result, and provenance trail. Publishing produces an immutable Edition. Releasing that Edition produces a verifiable Proof of what changed, why it changed, who or what was authorized to change it, which rules passed, and what became available to consumers.

## Project status

**Milestone 0 — implementation foundation.**

The Rust workspace, architectural dependency boundaries, operational identifiers, canonical artifact digests, authenticated local bootstrap Principal, local Workspace initialization and verification, idempotent ChangeSet draft creation, shared result contracts, and initial Known State are implemented. There is no public release yet. The next milestone is the first local end-to-end proof loop.

| Area | Status |
| --- | --- |
| Product definition | Ratified |
| Domain vocabulary | Ratified |
| Core invariants | Ratified |
| Technology baseline | Ratified for implementation start |
| CLI contract | Initial stable design |
| Rust implementation | Foundation in progress |
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

## Intended CLI

The executable is `proof`. Human-readable output is a projection of the same structured result returned to agents.

```bash
proof init
proof schema create --file article.schema.json
proof context build --task localize-homepage --output context.json
proof changeset create --intent "Localize the homepage for fr-CA"
proof changeset add --file edits.ndjson
proof changeset diff
proof changeset validate
proof changeset submit
proof edition create --from <changeset-id>
proof release create --edition <edition-id> --environment preview
proof verify <proof-id>
```

These examples define the intended interface; they are not executable until the first implementation milestone ships. The complete contract is in [CLI reference](docs/reference/cli.md).

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
- Stable MCP 2025-11-25 for the first adapter, with protocol negotiation and a path to the 2026 revision after it becomes final.

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

## MVP

The first release is one complete local vertical slice:

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

Proof is currently establishing its implementation foundation. Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a change. Report vulnerabilities according to [SECURITY.md](SECURITY.md); do not open public security issues.

## License

No open-source license has been selected yet. Until a license is added, the repository remains publicly visible but is not licensed for redistribution or derivative works.
