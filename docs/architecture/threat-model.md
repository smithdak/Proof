# Threat model

**Status:** Initial baseline  
**Baseline:** August 3, 2026

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

### Authority escalation

**Threats:** overbroad Delegation, sub-delegation expansion, stale approval, agent using service authority for an unauthorized requester.

**Controls:** deny by default, scope intersection, digest-bound approval, execution-time re-evaluation, requester and operator attribution, explicit sub-delegation, separation of duties.

### Prompt and content injection

**Threats:** stored content instructs an agent to invoke tools, reveal secrets, change policy, or exceed task scope.

**Controls:** content remains typed data, capability and authority never derive from natural language, minimal ContextPacks, source labeling, secret handles, typed tool calls, output Schema validation, scope and budget enforcement.

### Transaction tampering

**Threats:** Edit substitution after approval, partial write, stale base overwrite, duplicate commit after timeout.

**Controls:** canonical ChangeSet digest, atomic transaction, optimistic concurrency, approval bound to digest, idempotency record committed with effects, append-only authoritative facts.

### Evidence tampering

**Threats:** altered Edition, substituted subject, forged Proof, deleted history, algorithm confusion.

**Controls:** immutable artifacts, algorithm-qualified digests, domain separation, DSSE typed envelope, in-toto subjects, explicit trust policy, independent golden-vector verification, retention controls.

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
