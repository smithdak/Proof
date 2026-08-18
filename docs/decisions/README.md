# Architecture decision records

Architecture decision records preserve the context and consequences of durable choices. They are immutable after acceptance except for status, links, and clearly labeled factual errata that preserve the original decision text. A materially changed decision receives a new ADR that supersedes the previous one.

## Status values

- **Proposed** — under active review.
- **Accepted** — current architecture.
- **Deprecated** — retained for compatibility but no longer preferred.
- **Superseded** — replaced by another ADR.
- **Rejected** — considered and intentionally not adopted.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-rust-cli-first.md) | Rust core and CLI-first interface | Accepted |
| [0002](0002-changesets-only.md) | All governed mutation occurs through atomic ChangeSets | Accepted |
| [0003](0003-edition-release-proof.md) | Separate Edition, Release, and Proof | Accepted |
| [0004](0004-canonical-json-and-digests.md) | RFC 8785 canonical JSON and algorithm-qualified digests | Accepted |
| [0005](0005-uuidv7-identifiers.md) | UUIDv7 operational identifiers | Accepted |
| [0006](0006-dsse-in-toto-proof-envelope.md) | DSSE and in-toto structure for portable Proofs | Accepted |
| [0007](0007-modular-monolith.md) | Begin as a modular monolith with storage adapters | Accepted |
| [0008](0008-mcp-adapter-version.md) | Target stable MCP 2025-11-25 first | Superseded by 0010 |
| [0009](0009-local-bootstrap-principal.md) | Bind the local bootstrap Principal to the operating-system user | Accepted |
| [0010](0010-dual-era-mcp.md) | Prefer stateless MCP 2026 while retaining legacy initialization | Accepted |
| [0011](0011-local-agent-command-authentication.md) | Authenticate local Agent commands with bound Ed25519 credentials | Proposed |

## Template

```markdown
# ADR-NNNN: Decision title

**Status:** Proposed  
**Date:** YYYY-MM-DD

## Context

What forces and constraints require a decision?

## Decision

What is being decided?

## Consequences

What becomes easier, harder, required, or excluded?

## Alternatives considered

Which credible alternatives were rejected and why?

## Verification

How will the architecture demonstrate continued compliance?
```
