# Proof documentation

This documentation separates durable product and architectural decisions from changeable implementation details. Milestone 1's local proof loop is implemented; Milestone 2 has begun with bounded read authority, ContextPacks, capability discovery, and a dual-era MCP stdio adapter for current stateless and legacy initialized clients. Delegated reads still accept caller-supplied Agent Principal and Delegation identifiers; only the local Human path is adapter-authenticated. Authenticated Agent bindings, delegated mutations, and the collaboration server are not implemented. P-0002's exact-locale rendition contract and P-0007 content-foundation sequence are Proposed, pending project-owner acceptance, and make no implementation claim.

## Reading paths

### Understand the product

1. [Vision and thesis](product/vision.md)
2. [Scope and non-goals](product/scope.md)
3. [Roadmap and MVP](product/roadmap.md)

### Understand the system

1. [Core invariants](architecture/constitution.md)
2. [Architecture overview](architecture/overview.md)
3. [Domain model](architecture/domain-model.md)
4. [Agent authority](architecture/agent-authority.md)
5. [Proposed delegated content contract](architecture/delegated-content.md)
6. [Proposed authenticated actor contract](architecture/authenticated-actor.md)
7. [Proof model](architecture/proof-model.md)
8. [Threat model](architecture/threat-model.md)
9. [Testing strategy](architecture/testing.md)

### Implement a compatible interface

1. [CLI contract](reference/cli.md)
2. [Error model](reference/errors.md)
3. [Technology baseline](reference/technology-baseline.md)
4. [Standards profile](reference/standards.md)

### Understand why decisions were made

- [Architecture decision records](decisions/README.md)

### Execute current work

- [Rolling-wave work map](work/map.md)
- [Work-control protocol](work/README.md)

## Document status

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are used as requirement terms.

- **Ratified** documents define the current product contract.
- **Proposed** sections identify a direction that still requires an ADR.
- **Illustrative** examples explain intent and are not yet compatibility commitments.

When documents disagree, precedence is:

1. Ratified architecture decision records.
2. Core invariants.
3. Domain and interface reference documents.
4. Roadmap and explanatory product documents.
5. README summaries.

## Documentation method

Documentation changes follow a docs-as-code workflow:

- A product or architecture decision is recorded before implementation relies on it.
- Durable decisions receive an ADR.
- Examples use the same terminology and identifiers as the reference contract.
- External standards are linked from the standards profile rather than copied.
- Version claims include an `as of` date and are reviewed during dependency updates.
- Broken links, terminology drift, and invalid examples are treated as defects.

## Current baseline

**Baseline date:** August 17, 2026

**Product phase:** Milestone 1 complete; Milestone 2 read-authority slice begun

**Documentation version:** 0.1
