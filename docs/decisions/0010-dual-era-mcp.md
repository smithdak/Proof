# ADR-0010: Prefer stateless MCP 2026 while retaining legacy initialization

**Status:** Accepted
**Date:** 2026-08-16
**Supersedes:** [ADR-0008](0008-mcp-adapter-version.md)

## Context

[MCP `2026-07-28`](https://modelcontextprotocol.io/specification/2026-07-28) became a final specification on July 28, 2026. Its [versioning and compatibility contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning) replaces the protocol handshake and implicit session capability state with self-describing requests, adds mandatory server-side discovery, requires typed result discrimination, and makes deterministic list results explicitly cacheable. MCP `2025-11-25` remains deployed and uses the earlier `initialize` / `notifications/initialized` lifecycle.

Proof must support current clients without converting transport metadata or a legacy session into domain authority. Removing legacy support immediately would create avoidable interoperability failure, while remaining legacy-only would make the first adapter stale at introduction.

## Decision

`proof-mcp` is a dual-era newline-delimited stdio server.

- A request carrying modern `_meta` is handled independently under MCP `2026-07-28`. The metadata must include `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities`; no prior request is consulted.
- The server implements `server/discover`. Discovery and `tools/list` return public `ttlMs` and `cacheScope` hints because the advertised capability registry is deterministic and authority-independent.
- Every modern success result, including an `isError` tool result, includes `resultType: "complete"`. Unsupported versions return code `-32022` with `requested` and `supported` fields.
- An `initialize` request selects the MCP `2025-11-25` compatibility path for that stdio process. Legacy tool calls remain gated on `notifications/initialized`.
- Tool definitions come from the application capability registry. Principal and Delegation identifiers remain explicit tool arguments; neither modern request metadata nor legacy session state conveys Proof authority.
- Each input line is bounded before JSON parsing, stdout contains protocol messages only, and application Problems are JSON text in `isError` tool results without success-only `structuredContent`.

## Consequences

- Current clients receive stateless behavior and can route every request independently.
- Legacy clients continue to work without changing application semantics.
- Protocol-era branching is isolated in the MCP adapter and cannot alter domain state transitions.
- Conformance maintenance covers two distinct lifecycles until legacy support is deliberately retired.

## Alternatives considered

- **Support only MCP 2026-07-28:** simpler, but unnecessarily breaks installed legacy clients.
- **Keep MCP 2025-11-25 as the default:** rejected because it preserves session assumptions removed by the current final specification.
- **Translate modern requests into a hidden initialized session:** rejected because it violates per-request capability semantics and introduces ambient transport state.
- **Make discovery or MCP metadata authoritative:** rejected because protocol self-description is neither identity nor delegated authorization.

## Verification

- Fixtures cover modern discovery, list, call, missing metadata, unsupported version, independent calls, and legacy fallback.
- Every modern successful response is asserted to contain `resultType: "complete"`; discovery and list cache hints are asserted exactly.
- Invalid identifiers, malformed and oversized messages, notification silence, protocol-clean stdout, and domain `isError` results have dedicated tests.
- Domain and application crates have no MCP dependency.
