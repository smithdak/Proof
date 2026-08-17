# Standards profile

**Status:** Ratified baseline  
**As of:** August 16, 2026

Proof uses established standards where they provide stable semantics or interoperability. Referencing a standard does not imply implementing every optional feature.

## Normative profile

| Concern | Standard | Proof use |
| --- | --- | --- |
| Content and contract Schema | [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) | Object Schemas, command inputs, results, errors, ContextPacks, and Proof predicates. |
| JSON data model | [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | JSON interchange. |
| Canonical JSON | [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | Reproducible JSON artifact bytes and digests. |
| Operational identifiers | [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) | UUIDv7 for time-ordered operational IDs. |
| Timestamps | [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) | External UTC timestamps. |
| Data locations | [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) | JSON Pointer in findings and diagnostics. |
| HTTP API description | [OpenAPI Specification 3.2.0](https://spec.openapis.org/oas/v3.2.0.html) | Machine-readable HTTP operations, schemas, security requirements, and examples. |
| HTTP errors | [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) | Problem Details representation. |
| OAuth security | [RFC 9700 / BCP 240](https://www.rfc-editor.org/rfc/rfc9700) | Security baseline for OAuth-based enterprise adapters. |
| Signature envelope | [DSSE v1](https://github.com/secure-systems-lab/dsse) | Authenticate typed Proof payload bytes. |
| Attestation statement | [in-toto Attestation Framework v1.2.0, Statement v1](https://github.com/in-toto/attestation/tree/v1.2.0) | Bind Proof predicates to immutable subjects. |
| Build provenance | [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Release build and source provenance. |
| Agent protocol | [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) and [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Stateless current contract with initialization-based legacy compatibility. |
| Telemetry | [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/) | Trace, metric, and log export. |
| Workload identity | [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/) | Optional enterprise service and agent workload identity. |

## MCP version position

The MCP project released `2026-07-28` as the current final specification on July 28, 2026. It replaces the initialization handshake with a stateless core: every modern request carries its protocol version and client capabilities in `_meta`. The specification explicitly defines `2025-11-25` and earlier as legacy initialization-based versions and permits a dual-era server.

Proof will:

- Prefer stateless `2026-07-28` and retain `2025-11-25` initialization compatibility.
- Implement `server/discover`; modern clients may call it before any other operation but are not required to do so.
- Reject unsupported modern versions with JSON-RPC code `-32022` and exact `requested` and `supported` data.
- Include `resultType: "complete"` on every modern result and public `ttlMs` / `cacheScope` hints on discovery and deterministic list responses.
- Keep MCP transport state outside domain authority.
- Maintain conformance fixtures per supported protocol version.
- Preserve application-operation semantics across protocol versions.

This position supersedes [ADR-0008](../decisions/0008-mcp-adapter-version.md) through [ADR-0010](../decisions/0010-dual-era-mcp.md).

## Proof artifact profile

The initial Release Proof combines:

1. Canonical domain artifacts using RFC 8785.
2. BLAKE3-256 internal content digests with domain separation.
3. An in-toto Statement v1 binding immutable subjects to a Proof predicate.
4. A DSSE envelope authenticating the exact statement payload and type.
5. Ed25519 signatures resolved through a versioned trust policy.

SHA-256 subject digests are added where an external in-toto, SLSA, Sigstore, or OCI integration requires them.

## Security methodology

Proof's threat modeling incorporates:

- Conventional application and API abuse cases.
- Supply-chain threats addressed by SLSA and in-toto.
- Agent-specific threats including prompt injection, tool misuse, excessive agency, identity confusion, memory poisoning, and cascading failures.
- Least privilege, separation of duties, explicit trust boundaries, and fail-closed verification.

The [OWASP GenAI Security Project](https://genai.owasp.org/) is an informative source for agentic threat scenarios. Deterministic domain invariants remain Proof's enforceable controls.

## Compatibility rules

- Standard name and version are stored with every artifact whose interpretation depends on them.
- A verifier rejects unsupported required algorithms or Schema versions.
- Algorithm agility is explicit; silent substitution is forbidden.
- Standards profiles are versioned through ADRs and conformance vectors.
- Draft specifications may be prototyped but are not default production contracts.

## Informative architecture and documentation methods

- [Architecture Decision Records](https://adr.github.io/)
- [C4 model](https://c4model.com/) for system visualization
- [Diátaxis](https://diataxis.fr/) for documentation organization
- [Semantic Versioning 2.0.0](https://semver.org/)
- [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
