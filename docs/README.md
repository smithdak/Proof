# Proof documentation

This documentation separates durable product and architectural decisions from
changeable implementation details. Milestone 1's local proof loop, P-0007's
exact-locale Human content foundation, P-0004's authenticated Agent kernel, and
P-0005's bounded delegated-localization profile are implemented. Per-Agent
Ed25519 bindings, direct bounded Delegations, single-use commands, canonical
authorization decisions, and CLI plus modern and legacy MCP broker paths cover
all 14 enabled operations. The 11 localized `/v2` operations consume immutable
Human-issued intent and ContextPack closure; Agents cannot issue or replace
that closure or approve a ChangeSet. Signed result/effect commitments and the
v13 consequence and global-key ledgers make their local outcomes verifiable.
Portable authority bundles, containment qualification, the collaboration
server, and a public release remain unimplemented.

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
5. [Ratified delegated content contract](architecture/delegated-content.md)
6. [Ratified authenticated actor contract](architecture/authenticated-actor.md)
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

**Baseline date:** August 21, 2026

**Product phase:** Milestone 1 complete; Milestone 2 bounded local authenticated mutation implemented, portable qualification next

**Documentation version:** 0.3
