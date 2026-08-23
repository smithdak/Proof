# Proof documentation

This documentation separates durable product and architectural decisions from
changeable implementation details. Milestone 1's local proof loop, P-0007's
exact-locale Human content foundation, P-0004's authenticated Agent kernel, and
P-0005's bounded delegated-localization profile are implemented. P-0006 closes
the bounded local Linux Milestone 2 profile. Per-Agent
Ed25519 bindings, direct bounded Delegations, single-use commands, canonical
authorization decisions, and CLI plus modern and legacy MCP broker paths cover
all 14 enabled operations. The 11 localized `/v2` operations consume immutable
Human-issued intent and ContextPack closure; Agents cannot issue or replace
that closure or approve a ChangeSet. Signed result/effect commitments and the
v14 presentation, consequence, and global-key ledgers make their local outcomes
verifiable. `AuthorityEvidenceBundleV1`, the independent `proof-verifier`,
frozen portable vectors, and distinct-UID Linux signer/verifier containment are
qualified. P-0008's single-Workspace collaboration-server decision candidate is
project-owner accepted and ADR-0013 is Accepted; P-0009 has implemented the
remote actor and shared-contract conformance foundation, P-0010 PostgreSQL
parity is the promoted successor, and the server itself
remains unimplemented. Same-UID
hostile-process isolation, Windows runtime containment, server execution,
deployment, and a public release remain unimplemented or unqualified.

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
7. [Accepted collaboration-server contract](architecture/collaboration-server.md)
8. [Proof model](architecture/proof-model.md)
9. [Threat model](architecture/threat-model.md)
10. [Testing strategy](architecture/testing.md)

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

**Baseline date:** August 23, 2026

**Product phase:** Milestones 1 and 2 complete for the bounded local Linux profile; P-0008 collaboration-server contract accepted by the project owner; P-0009 complete; P-0010 PostgreSQL parity foundation promoted

**Documentation version:** 0.4
