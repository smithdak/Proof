# Proof documentation

This documentation is the authoritative pre-implementation baseline for Proof. It separates durable product and architectural decisions from changeable implementation details.

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
5. [Proof model](architecture/proof-model.md)
6. [Threat model](architecture/threat-model.md)
7. [Testing strategy](architecture/testing.md)

### Implement a compatible interface

1. [CLI contract](reference/cli.md)
2. [Error model](reference/errors.md)
3. [Technology baseline](reference/technology-baseline.md)
4. [Standards profile](reference/standards.md)

### Understand why decisions were made

- [Architecture decision records](decisions/README.md)

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

**Baseline date:** August 3, 2026  
**Product phase:** Pre-implementation  
**Documentation version:** 0.1
