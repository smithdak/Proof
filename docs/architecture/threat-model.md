# Threat model

**Status:** Initial baseline  
**Baseline:** August 3, 2026

> **Proposed P-0003 profile:** The local authentication, replay, authority-log,
> and portable-authority controls labeled below are pending project-owner
> acceptance and are not implementation claims.
> The normative proposal is the [authenticated actor contract](authenticated-actor.md).

This threat model defines the security boundaries that shape Proof's architecture. It is updated when a new interface, trust relationship, or deployment mode is introduced.

## Security objectives

Proof must preserve:

- **Authorization:** only permitted Principals perform consequential actions.
- **Integrity:** accepted content, history, Editions, Releases, and Proofs cannot be altered undetectably.
- **Atomicity:** failure cannot leave partial authoritative mutation.
- **Accountability:** actions remain attributable to an operating identity and authority chain.
- **Confidentiality:** content, credentials, context, and evidence are disclosed only within policy.
- **Availability:** bounded failures cannot permanently block verification or recovery.
- **Reproducibility:** authoritative history can rebuild the same Known State.

## Protected assets

- Authoritative domain facts.
- Current and historical content.
- Schemas, policies, validators, and approval records.
- Principal identities and Delegations.
- ContextPacks and restricted context.
- Editions, Releases, and Proof artifacts.
- Signing keys and trust configuration.
- Idempotency records and correlation history.
- Audit and security signals.

## Trust boundaries

```text
Untrusted content and requests
          │
          ▼
CLI / HTTP / MCP / import boundary
          │ authentication + Schema + limits
          ▼
Application authorization boundary
          │ policy + Delegation + idempotency
          ▼
Deterministic domain boundary
          │ invariants + validation + transaction
          ▼
Authoritative store and key-provider boundaries
          │
          ▼
Delivery, event, webhook, and external integration boundaries
```

Every boundary validates type, size, identity, authority, and version appropriate to its role.

### Proposed P-0003 profile — local authentication boundary

For an Agent operation, the interface boundary verifies a single-use Ed25519
`AuthenticatedCommandV1` DSSE presentation and resolves a validly issued
immutable historical `PrincipalBindingV1` before it may construct
`AuthenticatedActorContextV1`. Current binding state is evaluated afterward by
the authorization kernel.
The requesting Human is independently resolved from ADR-0009's Unix binding.
CLI and MCP input may name expected Principals and a Delegation, but no
identifier is authentication. The application accepts
actor context only through the identity port; domain commands cannot deserialize
one from untrusted input.

The bootstrap Unix UID and private Workspace are the Human/administrator trust
boundary. A process with either access can invoke the direct-Human path and omit
Agent authentication. Local per-Agent proof of possession provides bounded
authority only when the Agent workload runs outside that UID/filesystem boundary
and reaches Proof through a Human-owned broker or adapter. Same-UID execution
provides attribution and command integrity, not containment.

Authentication and authorization evidence is appended as `AuthorityRecordV1`
entries to a causally ordered authority log with an authority trust root
distinct from the governed content
fact log and Release-signing root. Distinct signing authority prevents governed
content evidence alone from manufacturing a trusted binding or revocation. The
authority hash chain detects mutation, insertion, deletion, and reordering only
relative to a trusted later authority head. A file-backed signer and authority
log in the same mutable Workspace do not detect restoration of a valid older
prefix or fork; that same-store rollback is an explicit local residual unless a
verifier pins an independently retained authority-head checkpoint.

If the predecessor authority private key is lost before its dual-signed root
transition, v1 continuity is unrecoverable. The system preserves history and
fails authority operations as fatal integrity/root-unavailable; re-anchoring or
a new authority epoch requires a future ADR, Schema, and explicit caller trust.
Dual-sign rotation is a planned-transition control only: a compromised
predecessor can authorize an attacker successor or fork. Trust stops at the last
independently pinned pre-compromise checkpoint; recovery needs a future explicit
trust epoch/re-anchor rather than ordinary rotation.

## Adversaries

- Unauthenticated network attacker.
- Authenticated Principal attempting scope escalation.
- Compromised or malicious agent runtime.
- Malicious content author using stored prompt injection.
- Compromised integration, validator, or delivery endpoint.
- Dependency or build-supply-chain attacker.
- Operator with legitimate access attempting to erase evidence.
- Accidental misuse, stale automation, or retry storm.

## Primary threats and controls

### Identity spoofing

**Threats:** stolen tokens, shared accounts, forged Delegations, confused workload identity.

**Controls:** OIDC under current OAuth security BCP, short-lived workload identity, distinct Principal IDs, signature verification, audience and resource binding, no shared “agent” account, revocation checks.

**Proposed P-0003 profile (local Milestone 2):** distinct per-Agent Ed25519
proof-of-possession credentials, protected private-key handles, adapter-derived
subjects, immutable causally positioned Principal bindings, explicit audience
and Workspace
binding, and fail-closed binding disablement. OIDC, SPIFFE, and managed workload
identity are later adapters, not present local controls.

Persisted authority evidence replaces the raw requesting `os/unix` subject with
`requesting_subject_commitment`, a hiding commitment formed with a 32-byte
blind—not a raw UID checksum. The public actor-context digest uses that
commitment and never the raw subject. Audit policy alone controls disclosure of
the private subject-plus-blind opening; canonical semantics and vectors live in
the [authenticated actor contract](authenticated-actor.md) and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).

Public failure disclosure is proof-gated. Structurally malformed input may
return `proof.auth.malformed`. For a well-formed presentation, an unknown
binding/key and an invalid signature before proof of possession both return the
same public `proof.auth.denied`; `proof.auth.binding_not_found` and
`proof.auth.signature_invalid` are trusted audit/offline reasons only. After a
valid signature under a known historical key, public audience, actor, time,
inactive-binding, replay, and authorization detail may be returned. Random
unknown credentials and invalid signatures have equivalent public behavior.

### Authority escalation

**Threats:** overbroad Delegation, sub-delegation expansion, stale approval, agent using service authority for an unauthorized requester.

**Controls:** deny by default, scope intersection, digest-bound approval, execution-time re-evaluation, requester and operator attribution, explicit sub-delegation, separation of duties.

### Prompt and content injection

**Threats:** stored content instructs an agent to invoke tools, reveal secrets, change policy, or exceed task scope.

**Controls:** content remains typed data, capability and authority never derive from natural language, minimal ContextPacks, source labeling, secret handles, typed tool calls, output Schema validation, scope and budget enforcement.

### Transaction tampering

**Threats:** Edit substitution after approval, partial write, stale base overwrite, duplicate commit after timeout.

**Controls:** canonical ChangeSet digest, atomic transaction, optimistic concurrency, approval bound to digest, idempotency record committed with effects, append-only authoritative facts.

### Proposed P-0003 profile — presentation replay and substitution

**Threats:** replaying a captured signed request, substituting a Delegation or
operation beneath a valid signature, reusing an idempotency key with different
bytes, returning a cached result to a currently unauthenticated actor, rolling
back a binding or revocation record, or racing revocation against consequence.

**Controls:** a bounded DSSE envelope with canonical `AuthenticatedCommandV1`
payload covering audience, Workspace, binding, operation version, request
digest, expected requester/operator, Delegation, idempotency key,
`presentation_id`, and time bounds; single-use presentation consumption; fresh
C5 authentication and current C6 authorization before C4 may disclose an
idempotent result; exact-input idempotency comparison; causal authority-log
ordering; and presentation consumption, authorization, idempotency, and
consequence in one transaction. Current revocation, disablement, or policy
denial blocks disclosure of an earlier successful result.

### Evidence tampering

**Threats:** altered Edition, substituted subject, forged Proof, deleted history, algorithm confusion.

**Controls:** immutable artifacts, algorithm-qualified digests, domain separation, DSSE typed envelope, in-toto subjects, explicit trust policy, independent golden-vector verification, retention controls.

**Proposed P-0003 profile:** P-0006 portable verification receives the future
`AuthorityEvidenceBundleV1` and every required binding, `DelegationV2`,
revocation, authenticated-command, and authorization-decision artifact. Trust
comes from caller-supplied authority and
Release roots, never self-described producer keys. Missing protected evidence
returns an explicit incomplete verdict; a raw provider subject or private key is
never exported. A supplied authority-log prefix proves history completeness or
rollback resistance only when the verifier also pins an independently retained
expected authority head or a later checkpoint that commits it.

### Sensitive-data disclosure

**Threats:** ContextPack overcollection, secret in prompt or log, verbose error leaks restricted content, public Proof embeds private values.

**Controls:** context minimization and redaction, secret handles, log field policy, authorization-aware problems, digest references rather than bodies, disclosure-specific evidence artifacts.

### Malicious extension or integration

**Threats:** validator executes arbitrary code, webhook exfiltrates data, import traverses filesystem, URL resolver reaches internal services.

**Controls:** out-of-process typed protocols, sandbox and resource limits, egress allowlists, signed extension distribution, path normalization, archive limits, SSRF protection, no automatic arbitrary-URL resolution.

### Denial of service

**Threats:** enormous ChangeSets, recursive Schemas, relationship cycles, decompression bombs, expensive queries, repair loops, event-delivery storms.

**Controls:** size, depth, complexity, duration, and operation budgets; bounded concurrency; backpressure; pagination; circuit breakers at external adapters; dead-letter handling; rate policy by Principal and Workspace.

### Supply-chain compromise

**Threats:** malicious dependency, compromised CI action, tampered release binary, credential-bearing pull-request workflow.

**Controls:** locked dependencies, `cargo-deny`, advisories, pinned action SHAs, least-privilege workflows, isolated untrusted builds, SBOM, SLSA provenance, signed artifacts, independent verification instructions.

## Agent-specific abuse cases

The conformance and red-team suite includes:

- Content asks the agent to ignore its Delegation.
- Content fabricates a tool result or approval.
- Agent probes unrelated Objects to expand context.
- Agent splits one prohibited ChangeSet into many smaller requests.
- Agent reuses a stale approved digest with modified Edits.
- Agent attempts to exfiltrate secrets through content fields or URLs.
- Agent recursively delegates authority.
- Multiple agents create cascading changes based on uncommitted assumptions.
- Agent retries after a timeout with a new idempotency key.
- Agent treats a cryptographically valid but untrusted Proof as authorized.
- **Proposed P-0003 profile:** Agent presents another Principal's identifier with
  its own credential, replays a consumed presentation, signs one operation and
  requests another, uses a disabled binding, or presents a parent/chain when
  only direct Human-to-Agent Delegation is supported.
- **Proposed P-0003 profile:** Revocation and consequence execute concurrently;
  the authority-log/transaction ordering must make exactly one outcome valid.

## Security review gates

A milestone cannot ship until:

- New trust boundaries are added to this model.
- Abuse cases have executable tests where possible.
- Required secrets, permissions, and network paths are documented.
- Logs and errors are reviewed for information disclosure.
- Recovery and key-revocation behavior is tested.
- Known residual risks have owners and explicit acceptance.

## Deferred areas

Detailed deployment threats for multi-region operation, tenant isolation, browser sessions, plugin sandboxing, and managed key custody are completed before their respective milestones. They are not assumed safe by this initial model.

The **Proposed P-0003 profile** is intentionally local and Unix-qualified. It
does not qualify Windows identity, enterprise OIDC/SPIFFE, remote attestation,
managed KMS/HSM custody, server sessions, or multi-tenant authority storage.
It also does not isolate mutually hostile processes under the same Unix UID;
such a process is inside the Human/admin boundary and may bypass the Agent path,
not merely steal a file-backed Agent key. Milestone 2 qualification therefore
requires a distinct UID, container, or sandbox that denies the Agent repository,
raw CLI, and private Workspace access and exposes only the brokered adapter
channel. A requirement to isolate mutually hostile same-UID processes triggers
a protected-broker or workload-identity redesign.
