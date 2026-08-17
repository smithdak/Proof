# ADR-0008: Target stable MCP 2025-11-25 first

**Status:** Superseded by [ADR-0010](0010-dual-era-mcp.md)
**Date:** 2026-08-03

**Correction:** The premise below was already factually incorrect on this ADR's date: MCP `2026-07-28` had become a final release on July 28, 2026, not a release candidate. The original text is retained as decision history; ADR-0010 records the corrected baseline.

## Context

MCP is a valuable agent interface, but the July 2026 specification revision is a release candidate as of this decision date. Proof's domain architecture must not depend on draft protocol behavior.

## Decision

The first MCP adapter targets the final `2025-11-25` specification and implements version negotiation. The `2026-07-28` revision is added only after upstream finalization and compatible stable SDK or conformance support.

MCP remains an adapter over application operations. Transport session state, capability discovery mechanics, and protocol-specific metadata do not become domain authority.

## Consequences

- The first implementation uses a stable production contract.
- Proof needs per-version conformance fixtures and negotiation tests.
- The adapter may temporarily support both protocol generations.
- New MCP features cannot silently change Proof operation semantics.

## Alternatives considered

- **Build only against the RC:** maximizes novelty but introduces avoidable compatibility risk.
- **Defer MCP entirely:** loses an important agent surface, though the CLI remains sufficient for the first local milestone.
- **Make MCP the internal operation model:** rejected because protocol evolution would control the domain.

## Verification

- Protocol negotiation and downgrade tests.
- Application-operation conformance shared between CLI and MCP.
- No MCP crate dependency from domain or application contract crates.
