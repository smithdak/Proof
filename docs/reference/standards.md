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
| Locale identifier lineage | [RFC 5646 / BCP 47](https://www.rfc-editor.org/rfc/rfc5646) | Informative syntax lineage for Proof's restricted locale casing/profile; not a claim of full BCP 47 acceptance, registry canonicalization, or matching. |
| HTTP API description | [OpenAPI Specification 3.2.0](https://spec.openapis.org/oas/v3.2.0.html) | Machine-readable HTTP operations, schemas, security requirements, and examples. |
| HTTP errors | [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) | Problem Details representation. |
| OAuth security | [RFC 9700 / BCP 240](https://www.rfc-editor.org/rfc/rfc9700) | Security baseline for OAuth-based enterprise adapters. |
| Signature envelope | [DSSE v1](https://github.com/secure-systems-lab/dsse) | Authenticate typed Proof payload bytes. |
| Attestation statement | [in-toto Attestation Framework v1.2.0, Statement v1](https://github.com/in-toto/attestation/tree/v1.2.0) | Bind Proof predicates to immutable subjects. |
| Build provenance | [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Release build and source provenance. |
| Agent protocol | [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) and [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25) | Stateless current contract with initialization-based legacy compatibility. |
| Telemetry | [OpenTelemetry specifications](https://opentelemetry.io/docs/specs/) | Trace, metric, and log export. |
| Workload identity | [SPIFFE specifications](https://spiffe.io/docs/latest/spiffe-specs/) | Optional enterprise service and agent workload identity. |

## Ratified P-0002 restricted locale profile

Accepted but not implemented, P-0002 selects this exact restricted locale
syntax:

```regex
^[a-z]{2,8}(?:-[A-Z][a-z]{3})?(?:-(?:[A-Z]{2}|[0-9]{3}))?(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*$
```

This is a Proof canonical identifier profile, not a complete BCP 47 parser.
It permits a lowercase language, optional title-case script, optional uppercase
alpha or three-digit region, and zero or more lowercase syntactically
restricted variants. It excludes extensions, private-use sequences,
grandfathered forms, registry alias resolution, suppress-script normalization,
and likely-subtag inference. A syntactically valid BCP 47 tag outside this
subset is therefore not a valid Proof locale in this profile.

Stored locale bytes are matched exactly and case-sensitively and sorted by
unsigned UTF-8 byte order where canonical sets require ordering. Proof neither
rewrites nor rejects registry aliases: a syntactically valid alias is a literal
identifier distinct from its modern registry replacement. Proof performs no
language, script, region, or parent-locale fallback. Expanding this profile or
adding registry-aware equivalence or fallback changes content and authorization
semantics and requires a versioned contract.

The reconciled P-0003 candidate applies this exact pattern to both
`DelegationV2.scope.locales` and
`AuthorizationDecisionV2.requested_resources.locales`. Its vectors accept
lowercase variants and literal aliases and reject mixed-case variants. The
decision remains Proposed until project-owner acceptance, but there is no
longer a grammar mismatch between the content and authority Schemas.

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

## Proposed P-0003 profile — local Agent command authentication

Pending project-owner acceptance, local Agent proof of possession composes the
existing standards rather than introducing a bearer-token format. The exact
profile is the [authenticated actor contract](../architecture/authenticated-actor.md):

- `AuthenticatedCommandV1` is a bounded DSSE envelope whose typed payload is
  RFC 8785 canonical JSON.
- DSSE `keyid` is an unsigned lookup hint only. After signature verification it
  MUST equal the expected key resolved from the validly issued immutable
  historical binding, enrollment
  candidate, or Workspace authority state. A root-transition envelope contains
  exactly two distinct verified signatures in predecessor-then-successor order;
  duplicate, permuted, or substituted key IDs fail. Exact cases live under
  [`conformance/v1/authority/`](../../conformance/v1/authority/README.md).
- Canonical command and enrollment payloads are each limited to 4,096 bytes and
  their complete DSSE envelopes to 16,384 bytes. A canonical
  `AuthorityRecordV1` payload is limited to 65,536 bytes; a complete authority
  or root-transition DSSE envelope is limited to 98,304 bytes. The
  `AuthenticatedInvocation` broker frame is limited to 1,048,576 bytes in
  addition to the selected operation's input cap.
- The local Agent signature profile is Ed25519. The corresponding public key is
  referenced by `PrincipalBindingV1`; the private key remains behind a protected
  credential handle.
- `presentation_id` uses UUIDv7 and is the single-use replay identity. External
  issued-at and expiry values use RFC 3339 UTC; causal authority-log sequence,
  not wall-clock order, resolves revocation races.
- `DelegationV2`, `AuthorizationDecisionV2`, and `AuthorityRecordV1` use
  versioned JSON Schemas, JCS canonical bytes, and algorithm-qualified,
  domain-separated digests.
- The complete normative
  [`conformance/v1/authority/` digest registry](../../conformance/v1/authority/README.md)
  defines every context. In particular, policy bundles use
  `proof:policy-bundle:v1`, while authority and root-transition DSSE envelopes
  use `proof:authority-record-envelope:v1`. Implementations do not infer
  contexts by reverse-engineering vectors.
- `requesting_subject_commitment` is a hiding commitment formed with a 32-byte
  blind, not a raw UID checksum. Canonical actor-context evidence commits only
  that public value; raw `os/unix` subject-plus-blind disclosure is controlled
  by audit policy.
- The authority hash chain detects mutation and reordering relative to a trusted
  later authority head. A same-store signed prefix or fork remains internally
  valid unless the verifier pins an independently retained expected authority
  head or a later checkpoint that commits it.
- If the predecessor authority private key is lost before a dual-signed root
  transition, v1 continuity is unrecoverable. Preserving existing history is
  required; a new epoch or re-anchor requires a future ADR and Schema plus
  explicit caller trust.
- The future P-0006 `AuthorityEvidenceBundleV1` authenticates its authority
  closure under an explicit authority trust root separate from the
  Release-signing root. Its exact container and golden vectors remain a P-0006
  contract and are not implemented by P-0003 or P-0004.

OAuth/OIDC, SPIFFE, JOSE access tokens, platform attestation, and KMS/HSM-backed
credentials remain future identity-adapter choices. They do not alter the
application actor-context contract or make transport/session metadata authority.

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
