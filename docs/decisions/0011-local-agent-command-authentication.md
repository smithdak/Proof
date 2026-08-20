# ADR-0011: Authenticate local Agent commands with bound Ed25519 credentials

**Status:** Proposed

**Constitutional:** Yes — proposes replacing C4
**Date:** 2026-08-17
**Last revised:** 2026-08-20 — reconciled with ADR-0012 and P-0007

## Context

ADR-0009 binds the local bootstrap Human Principal to the effective Unix user.
The current delegated read adapter then accepts an Agent Principal identifier
and Delegation identifier from CLI or MCP input. It verifies that the selected
Agent is the grant recipient, but nothing proves that the caller controls that
Agent. Any process under the bootstrap UID that knows the two identifiers can
produce evidence attributed to the Agent.

Proof needs the smallest Milestone 2 boundary that distinguishes requesting
Human, operating Agent, runtime metadata, and transport without introducing the
collaboration server or an enterprise identity plane.

The earlier architecture direction also calls for complete Delegation-chain
intersection. Current code and the Milestone 2 scenario require only one direct
Human-to-Agent grant. Supporting recursive subdelegation now would add issuer
authentication, parent binding, intersection, cycle/depth, revocation, and
evidence-closure semantics without a demonstrated outcome.

## Decision

The proposed local Agent authentication profile is defined by the
[authenticated actor contract](../architecture/authenticated-actor.md).

- ADR-0009 remains the requesting-Human authentication path.
- Each Agent uses a per-Agent Ed25519 credential. A signed canonical command
  proves possession of the public key in a validly issued historical
  `PrincipalBindingV1`; current binding activity is evaluated separately during
  authorization.
- An authentication port derives `AuthenticatedActorContextV1`; command input,
  CLI flags, MCP metadata, and sessions cannot construct it.
- The signed `AuthenticatedCommandV1` binds the exact Workspace audience,
  operation/version, normalized command digest, expected requester and operator,
  binding, direct Delegation, idempotency key, one-use presentation identity,
  and bounded validity interval.
- Binding, Delegation, and revocation facts form an append-only signed Workspace
  authority sequence. The authority key is distinct from Agent command keys and
  Release signing keys.
- Milestone 2 supports only direct Human-to-Agent `DelegationV2`. Parent grants,
  Agent issuers, and subdelegation fail explicitly. A future chain requires a
  new Delegation version and ADR.
- A consumed authentication presentation cannot be reused. A safe application
  retry uses a fresh signed presentation with the same equivalent typed input
  and application idempotency key.
- CLI and MCP may carry a Delegation selector and signed expected identity, but
  Proof independently derives the operating Principal from the verified
  binding. MCP `_meta` is transport, never authority.
- Historical `DelegationV1` remains reproducible but does not silently become
  live v2 authority.
- `DelegationV2` retains exact Workspace, Environment, Object, Schema, and
  locale grant axes. The immutable Human-issued `ContentResourceIntentV1`
  narrows their permission product to exact target tuples; it does not create a
  sixth grant axis and the Agent cannot issue or replace it.
- The closed authority registry retains the three implemented v1 read pairs and
  replaces the nine unimplemented reserved v1 write pairs with P-0007's eleven
  localized v2 pairs. It binds each pair to its action, input Schema, complete
  resource- and budget-projection profiles, evidence selectors, idempotency
  class, and consequence class.
- Locale scope uses ADR-0012's exact restricted casing: language and variant
  subtags are lowercase, script is title case, alpha region is uppercase, and
  registry aliases remain literal without normalization.
- `object.query_released/v2` authorizes the requested Workspace, Environment,
  Object, and locale axes before resolving the current Release/Edition, then
  authorizes every resolved Schema before disclosure. All other localized v2
  operations authorize the complete verified intent, never a filtered subset.
- OIDC, SPIFFE, Windows credentials, KMS/HSM, workload measurement, and the
  final portable evidence bundle remain deferred adapters or later work.

## Proposed constitutional change

The current C4 unconditionally requires an equivalent completed retry to return
its original result. That conflicts with C5/C6 when a binding, Principal,
Delegation, or policy is invalidated after the first effect. This ADR proposes
replacing C4 with:

> Every governed consequential application operation MUST accept or derive an
> idempotency key. After the retry independently authenticates its Principal and
> satisfies current authorization, repeating a completed request with the same
> key and the same Workspace, operation/version, normalized input, derived
> requesting Principal, derived operating Principal, and direct Delegation MUST
> return the original result without duplicating the governed effect. A changed
> member of that semantic tuple under the key MUST fail. Authentication
> presentation identity, signature, time, and binding instance are excluded from
> equivalence so a fresh presentation or same-Principal key rotation can retry.
> Failed current authentication or authorization MUST deny disclosure of the
> original result without changing or duplicating the completed effect. An
> idempotency record is not a bearer capability. Single-use presentation
> consumption and its authorization decision are distinct bounded security
> evidence for each authenticated attempt, not duplicate governed effects; an
> otherwise read-only operation MAY use a null application idempotency key and
> return a newly authorized current result while mutating no governed content or
> projection.

No existing stored artifact or digest changes solely because of this amendment.
It changes the response boundary for a completed retry after authority
invalidation and classifies new P-0004 presentation/decision rows as
per-attempt security evidence. The current authenticated-Agent path is not
implemented, so no accepted Agent Proof changes meaning; existing local Human
operations retain their result-replay behavior while the Human remains
authenticated and authorized. Project-owner acceptance is required before the
ratified constitution is replaced or P-0004 becomes ready.

The exact proposed schemas, bounds, errors, evidence, migration boundary, and
falsification vectors are part of the linked contract and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).

## Consequences

- A Principal identifier is no longer accepted as Agent authentication.
- Current delegated CLI/MCP behavior has a deliberate compatibility break at
  P-0004: existing v1 grants remain historical but cannot authorize new Agent
  calls without enrollment and a v2 direct grant.
- Agents need a protected signing-provider handle and must sign a fresh
  presentation for each attempt.
- Proof gains a replay ledger, credential lifecycle, authority sequence, and a
  second local signing role. Those are necessary to make attribution and
  portable authority evidence falsifiable.
- The local claim remains weaker than process or workload attestation. Same-UID
  key theft is an explicit residual, not an authenticated-runtime claim. Any
  process with the bootstrap UID can also omit Agent authentication and use the
  ambient Human path, so same-UID execution is attribution rather than
  containment.
- Enforced bounded Agent authority requires the Agent workload to lack direct
  access to the bootstrap UID, private Workspace, and unrestricted Human CLI,
  and to reach Proof through a Human-owned broker or adapter channel. P-0006
  must qualify that deployment boundary before the Milestone 2 exit claim.
- A signed authority chain proves ordering and integrity relative to a trusted
  head; the local file-backed profile does not detect restoration of both the
  Workspace and signer state to an older valid prefix. Rollback detection needs
  an independently pinned head or future stateful external checkpoint.
- Dual-signed root transition covers planned rotation, not predecessor-key
  compromise. A compromised root can authorize an attacker successor; trust
  stops at the last independently pinned pre-compromise checkpoint until a
  future explicit authority epoch is established.
- Application idempotency never bypasses current authentication or
  authorization. A retry obtains the original result only after fresh C5/C6
  checks; revocation can deny disclosure without duplicating the prior effect.
- P-0007's explicit UUIDv7 keys remain request-bound. Localized validation
  derives its operation key from the proposal, policy, and validator;
  submission derives it from the ChangeSet while retaining `submitted_at` as
  semantic input. Reads use no application idempotency key. These classes are
  frozen in `AuthorityOperationRegistryV1` rather than inferred by adapters.
- Provider churn is isolated behind authentication and signing ports.
- P-0004 becomes implementation-ready only after project-owner acceptance.
  P-0006 can be reshaped now but stays blocked by P-0005.

## Alternatives considered

- **SPIFFE/mTLS first:** strongest future workload boundary, but requires a
  daemon or secure channel, issuance/rotation infrastructure, and workload
  selectors. It still needs command binding. Deferred as an adapter.
- **OS/PID binding:** cannot identify distinct Agents sharing the Unix user and
  is not durable or portable enough for Agent attribution.
- **Bearer/capability token:** copying the token copies authority; sender
  constraint reintroduces a proof-of-possession key.
- **Full chain now:** matches earlier direction but adds substantial semantics
  with no Milestone 2 use case. Rejected in favor of an explicit direct-only
  version.
- **Tuple-scoped `DelegationV3` now:** directly represents nonrectangular
  localized targets, but duplicates the immutable Human-issued resource intent,
  widens the signed grant and portable evidence, and solves no demonstrated
  scope failure. The exact intent safely narrows the existing v2 product.
- **Add explicit keys to localized validate/submit:** would require new P-0007
  operation versions. Proposal/policy/validator and ChangeSet identity already
  provide stable derived operation keys, while changed semantic input remains
  detectable; adapters are forbidden from choosing another derivation.
- **Reuse the Release key:** smaller but couples authority manufacture to
  outcome attestation and weakens compromise isolation.
- **Replay identical signed presentations:** convenient for transport retries,
  but intentionally makes captured read credentials reusable. Fresh
  presentations compose cleanly with application idempotency.

## Verification

- Portable golden vectors reproduce canonical bytes, DSSE PAE, signatures,
  digests, bindings, authority records, and v2 decisions without a private key.
- Negative vectors cover wrong signer/binding/requester/recipient/audience,
  altered command, expiry, replay, disabled or revoked state, direct-profile
  violations, scope/budget denial, and metadata substitution.
- Registry vectors cross-check all 14 authority pairs with P-0007's 11
  localized operation Schemas, exact projection profiles, retry classes, and
  rejection of mixed-case locale variants and superseded v1 write pairs.
- P-0004 must prove CLI, modern MCP, and legacy MCP parity, denial atomicity,
  fresh-presentation idempotent replay, exact migrations, and no secret or raw
  provider subject disclosure.
- P-0006 must independently verify the transitive authority closure with
  caller-supplied trust roots and separate validity/completeness verdicts.
