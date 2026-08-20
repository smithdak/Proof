# Authenticated actor contract

**Status:** Ratified by P-0003; bounded local read profile implemented by P-0004

**Version:** 1.1

**As of:** August 20, 2026
**Review gate:** Project owner

This document is ratified by
[ADR-0011](../decisions/0011-local-agent-command-authentication.md).
P-0004 implements this contract for the bounded local Human-to-Agent profile and
the three enabled v1 reads. The 11 localized v2 operation contracts remain
disabled for Agents until P-0005, and P-0006 still owns portable authority
bundles and the Milestone 2 containment qualification.

| Revision | Date | Decision state |
| --- | --- | --- |
| 0.1 | 2026-08-17 | Qualified local authentication and direct-Delegation candidate; localized resource closure still blocked on P-0002. |
| 0.2 | 2026-08-20 | Reconciled the closed registry, exact resource projections, retry classes, and locale grammar with P-0007; pending owner acceptance. |
| 1.0 | 2026-08-20 | Ratified by project-owner acceptance; implementation remains owned by P-0004. |
| 1.1 | 2026-08-20 | Implemented the bounded local read profile through P-0004; delegated mutation and portable bundles remain downstream. |

## Decision

Milestone 2 uses two independently authenticated actors for an Agent request:

1. the requesting Human is derived from ADR-0009's Unix subject binding; and
2. the operating Agent proves possession of a per-Agent Ed25519 credential.

The application resolves both authenticated subjects through immutable
Principal bindings. A signed command may assert expected Principal identifiers,
but those assertions are cross-checks: they never select authority.

The local Milestone 2 Delegation profile is exactly one direct Human-to-Agent
grant. Agent-to-Agent delegation, parent grants, and subdelegation are rejected
as unsupported. This deliberately narrows the earlier full-chain direction to
the smallest chain required by the Milestone 2 scenario.

Binding, Delegation, and revocation facts form a separate append-only authority
sequence. A Workspace authority key signs that sequence. Agent command keys,
the Workspace authority key, and Release Proof keys are distinct roles.

## Crux and bounded guarantee

The crux is whether proof of possession by a per-Agent key is enough to
distinguish the operating Agent inside the local Unix trust boundary without a
workload-identity control plane.

The ratified guarantee is:

> Proof authenticated control of an active Agent credential bound to the
> recorded operating Principal, under the local requesting Human and exact
> direct Delegation, for this command.

It is not a claim about the model, executable, container image, process
measurement, or operator behind that credential. A hostile process with the
same Unix user may be able to read or invoke a file-backed key and, more
fundamentally, can omit the Agent presentation and invoke Proof through the
ambient Human path. Every process with the bootstrap UID and private Workspace
access is therefore inside the local Human/admin trust boundary.

The profile enforces bounded Agent authority only when the Agent workload is
outside that UID and filesystem boundary and reaches Proof through a
Human-owned broker or adapter channel carrying the signed presentation. Running
the Agent under the bootstrap UID provides attribution and integrity for a
cooperating caller, not containment. It cannot by itself satisfy the Milestone
2 exit condition. If Proof must contain mutually hostile same-UID processes,
P-0004 must not implement this profile as the final boundary.

## Identity vocabulary

| Concept | Meaning | Trust source |
| --- | --- | --- |
| `AuthenticatedSubjectV1` | Provider-qualified subject verified by an adapter | Adapter evidence, never request JSON |
| Requesting Principal | Human or service whose authority initiates the request | Resolved from the requesting subject |
| Operating Principal | Agent that executes the typed operation | Resolved from a validly issued Agent binding; current activity is checked during authorization |
| `PrincipalBindingV1` | Immutable mapping from provider subject and public credential to one Principal | Signed Workspace authority record |
| `AuthenticatedActorContextV1` | Application-only result containing derived requester, operator, binding, and authentication evidence | Authentication port |
| Runtime/model metadata | Declared implementation and execution observations | Nonauthoritative evidence |
| Transport session | CLI process, stdio peer, MCP era, HTTP connection, or future session | Never domain authority |

Provider subject syntax is adapter-owned. The local Agent profile uses provider
`proof/local-ed25519` and subject
`ed25519:<64-lowercase-public-key-hex>`. Provider claims do not enter domain
authorization except through a verified binding.

Within one Workspace, a local Ed25519 subject/public key appears in at most one
immutable binding history. Reusing it after retirement or revocation, including
for another Principal, is authority integrity failure. Rotation for the same
Principal creates a new binding with a distinct key; overlapping active
bindings are permitted only for distinct keys.
For every binding, the authenticated subject, `ed25519:` plus lowercase hex of
the decoded 32-byte `public_key`, enrollment `candidate_key_id`, and verified
enrollment-envelope signer/key ID MUST all be byte-for-byte equivalent.

## Invariants

The following requirements are normative under ADR-0011.

- **A1 — Derived actors.** Request bodies MUST NOT construct an authenticated
  subject or actor context. The application MUST accept actor context only from
  an authentication port.
- **A2 — Two actors.** Agent operations MUST identify a derived requesting
  Principal and a distinct derived operating Agent Principal.
- **A3 — No identifier authentication.** Principal, binding, Delegation, key,
  and ContextPack identifiers are selectors or signed assertions, never proof
  of identity by themselves.
- **A4 — Exact command.** An Agent signature MUST bind the Workspace audience,
  operation name and version, normalized command digest, binding, expected
  requester and operator, direct Delegation, idempotency key when applicable,
  presentation identity, and validity interval.
- **A5 — One presentation, one use.** A successfully authenticated presentation
  MUST be consumed at most once. A semantic retry MUST use a new presentation
  and retain the same application idempotency key and equivalent input.
- **A5a — Authority precedes replay.** Returning an idempotent result MUST first
  satisfy C5 and C6 with a fresh authenticated presentation and current
  authority. An idempotency record prevents duplicate effects; it is not a
  bearer capability to disclose the original result after binding, Principal,
  or Delegation invalidation. Any future mutable authority-policy profile is
  subject to the same rule.
- **A6 — Atomic consequence.** Presentation consumption, authorization
  decision, idempotency outcome, and governed consequence MUST share one
  transaction. A validly authenticated denial MAY atomically persist a bounded
  denial and presentation-consumption record, but MUST NOT persist governed
  content or a successful idempotency result.
- **A7 — Direct Delegation.** Milestone 2 MUST accept exactly one direct
  Human-to-Agent `DelegationV2`. Parent references, Agent issuers,
  `allow_subdelegation: true`, repeated links, and chain-shaped input are not
  representable in the v2 type and MUST fail structural parsing with
  `proof.auth.malformed`. `proof.delegation.chain_unsupported` remains reserved
  for a future typed chain profile that reaches authorization.
- **A8 — Complete direct evaluation.** The requesting Principal MUST equal the
  Delegation issuer; the operating Principal MUST equal its recipient. Action,
  Workspace, resource, budgets, time, revocation, Principal status, and binding
  status MUST all allow the command at its causal authority position.
- **A9 — Prospective invalidation.** Binding and Delegation revocations and
  Principal disablement MUST be append-only and prospective. Later invalidation
  MUST NOT rewrite an earlier valid decision.
- **A10 — Causal authority.** Authority sequence and predecessor digests, not
  wall-clock time, MUST determine authority ordering. Timestamps remain
  validated evidence.
- **A11 — Key separation.** Agent command, Workspace authority, and Release
  signing keys MUST be logically distinct. Private material MUST stay behind a
  key-provider boundary and MUST NOT enter SQLite, content, ContextPacks,
  command payloads, Proof predicates, logs, or diagnostics.
- **A12 — Exact evidence.** `AuthorizationDecisionV2` MUST bind the exact
  authenticated command and envelope digests, derived actors, binding,
  Delegation and revocation state, authority head, policy, resources, budgets,
  evaluation time, and allow or stable denial reason.
- **A13 — Transport parity.** CLI, both MCP eras, and future HTTP adapters MUST
  produce the same normalized command and application decision. MCP `_meta`
  transports authentication material but does not become authority.
- **A14 — Fail closed.** Unknown, noncanonical, unsupported, incomplete,
  expired, replayed, disabled, revoked, mismatched, or incorrectly signed
  authentication and authority data MUST fail before protected data or an
  idempotent result is disclosed.
- **A15 — No silent legacy elevation.** Existing `DelegationV1` facts remain
  historically reproducible but MUST NOT authorize a new Agent operation after
  the v2 enforcement boundary. They are not automatically upgraded.
- **A16 — Caller trust.** Offline verification MUST require caller-supplied
  authority and Release trust roots. Producer-exported keys establish
  self-consistency only.

## Application boundary

Provider-specific verification terminates behind an application port. The
domain receives opaque, canonical evidence references rather than OS, OIDC,
SPIFFE, or KMS claims.

```text
untrusted command + authentication presentation
                    │
                    ▼
AuthenticationPort.verify
  ├─ requesting adapter → AuthenticatedSubjectV1
  ├─ command verifier   → AuthenticatedSubjectV1
  ├─ issued bindings    → cryptographic requesting + operating identities
  └─ replay reservation → presentation identity
                    │
                    ▼
AuthenticatedActorContextV1 + normalized application command
                    │
                    ▼
AuthorizationKernel.evaluate
  ├─ direct DelegationV2
  ├─ binding/Principal/revocation state at authority head
  ├─ direct/v1 policy + action/resource/budget
  └─ AuthorizationDecisionV2
                    │
                    ▼
existing application operation + one atomic transaction
```

The minimum port shape is conceptual, not a Rust compatibility promise:

```text
verify(invocation, normalized_command, evaluated_at)
  -> AuthenticatedActorContextV1

AuthenticatedActorContextV1 {
  requesting_subject,
  requesting_principal_id,
  operating_subject,
  operating_principal_id,
  binding_id,
  command_digest,
  command_envelope_digest,
  presentation_id,
  authenticated_at,
  authentication_profile
}
```

The adapter MUST derive Principal identifiers from a validly issued immutable
historical binding after cryptographic proof, then compare signed expected
identifiers. Current binding activity is evaluated by the authorization kernel.
Reversing identity derivation and request comparison would recreate the current
impersonation defect.

The local broker process may authenticate its own bootstrap Human through the
Unix adapter while authenticating the remote operating Agent through the signed
presentation. The Agent side of that channel MUST NOT have direct access to the
Workspace files, private Human binding, or an unrestricted Human CLI. This is a
deployment precondition, not a property that Ed25519 or DSSE can create inside
one shared UID.

## Local credential lifecycle

### Issuance

1. The authenticated bootstrap Human creates or selects an enabled Agent
   Principal.
2. The Agent or harness generates an Ed25519 key behind its credential provider.
3. Proof issues a single-use `BindingEnrollmentChallengeV1` bound to the
   Workspace audience, challenge, binding, Principal, candidate key, requesting
   Human, issue time, and expiry.
4. The Agent signs the RFC 8785 challenge in a one-signature DSSE envelope with
   payload type
   `application/vnd.proof.binding-enrollment-challenge.v1+json`. Proof verifies
   possession before accepting the public credential. The unsigned DSSE
   `keyid` MUST exactly equal the candidate key identifier after verification;
   it is never accepted as the source of that identity.
5. `PrincipalBindingV1` commits both enrollment challenge and envelope digests,
   and the Workspace authority key signs the append-only binding-issued record.

Only public key material and canonical evidence are stored. The default local
provider MAY use a permission-restricted file because key theft within the
trusted Agent execution boundary is a ratified residual; a future
protected-key provider fits the same port. File permissions do not isolate an
Agent from the ambient Human path when both share the bootstrap UID.
The challenge is valid for at most 300 seconds and is consumed once. Challenge
and envelope digests use `proof:binding-enrollment-challenge:v1` and
`proof:binding-enrollment-envelope:v1`, respectively.

### Rotation and revocation

- Multiple bindings MAY overlap for controlled rotation.
- Rotation issues a new binding, proves it in use, and appends retirement or
  revocation of the old binding. It never mutates the old record.
- Compromise recovery means revoke and reissue. Proof does not recover or export
  an Agent private key.
- Disabling a Principal invalidates all its bindings and Delegations for later
  actions and is terminal in v1. Recovery after Principal disablement creates a
  new Principal, binding, and grant; it does not reactivate old authority.
- A binding revocation effective at authority sequence `N` invalidates a command
  evaluated at or after `N`; it does not invalidate a decision committed under
  an earlier head.

Binding and Delegation facts require `issued_at <= not_before < expires_at` and
are time-active exactly when `not_before <= evaluated_at < expires_at`.
Principal disablement and revocation become effective at their authority-record
sequence regardless of their recorded wall-clock timestamp; causal sequence
wins.

### Workspace authority root

The Workspace authority key signs canonical authority records for binding
issuance/revocation and Delegation issuance/revocation. Its private material is
held by a provider separate from Release signing. The initial public root is a
local trust decision made by the authenticated bootstrap Human; an offline
verifier accepts it only through explicit caller policy.

Root rotation is accepted only when the transition is signed by both the prior
and successor roots. The envelope contains exactly two distinct signatures in
deterministic order: predecessor first, successor second. Each unsigned `keyid`
MUST equal the corresponding key named by the transition payload after that
signature verifies; duplicate, substituted, or permuted entries fail. Loss of
the prior private root cannot manufacture continuity and is unrecoverable in
v1. A new authority epoch or re-anchor requires a future ADR and Schema with an
explicit caller-trusted discontinuity; it cannot masquerade as genesis.

Dual-signature transition is planned rotation, not compromise recovery. A
compromised predecessor can authorize an attacker-chosen successor and fork, so
v1 cannot cryptographically restore trust from that chain alone. Verification
must stop at the last independently pinned pre-compromise checkpoint; resuming
requires the same future explicit trust-epoch/re-anchor mechanism.

### Authority administration

Version 1 has exactly one authority administrator: the enabled ADR-0009
bootstrap Human Principal derived by the Human-owned broker. Only that actor may
issue an enrollment challenge, enable or terminally disable a Principal, issue,
rotate, or revoke a binding, issue or revoke a Delegation, or activate an
authority-root transition. `issued_by_principal_id`,
`recorded_by_principal_id`, `revoked_by_principal_id`,
`activated_by_principal_id`, and the direct Delegation issuer MUST equal that
derived bootstrap Principal. An Agent credential or Delegation never grants
authority-administration rights. `AuthorizationDecisionV2` is produced by the
deterministic kernel, not by an administrator request.

## Canonical signed command

`AuthenticatedCommandV1` is RFC 8785 canonical JSON inside a DSSE envelope with
payload type
`application/vnd.proof.authenticated-command.v1+json`. The v1 profile requires
exactly one Ed25519 signature and resolves the expected public key from the
validly issued immutable historical `PrincipalBindingV1`; DSSE `keyid` is only a
lookup hint. Current binding time and revocation are authorization checks after
signature proof. After verification, `keyid` MUST exactly equal that binding's
credential key identifier.
A substituted `keyid` fails even when the same signature bytes verify under a
key found by another lookup route.

The canonical payload contains:

```json
{
  "api_version": "proof.dev/authenticated-command/v1",
  "audience": "proof://workspace/019c...",
  "binding_id": "019c...",
  "command_digest": "blake3:...",
  "delegation_id": "019c...",
  "expires_at": "2026-08-17T21:05:00Z",
  "idempotency_key": "019c...",
  "issued_at": "2026-08-17T21:00:00Z",
  "operating_principal_id": "019c...",
  "operation": {
    "name": "changeset.create",
    "version": "proof.dev/operation/changeset.create/v1"
  },
  "presentation_id": "019c...",
  "requesting_principal_id": "019c...",
  "workspace_id": "019c..."
}
```

The command digest uses BLAKE3-256 derive-key context `proof:command:v1` over
the RFC 8785 bytes of strict `CommandInputV1`. That wrapper contains the
Workspace, operation name and version, derived requesting and operating
Principal identifiers, direct Delegation, UUIDv7 idempotency key or `null`, and
the already Schema-validated normalized typed application input. Its duplicate
outer fields MUST exactly equal `AuthenticatedCommandV1` and the derived actor
context. It excludes the authentication envelope, signature, presentation
identity, authentication timestamps, runtime/model metadata, correlation
identifiers, and adapter metadata. The verifier validates the operation input,
constructs the wrapper, and recomputes the digest before disclosing authority
or results.

For governed-content reads whose only persistence is per-attempt authentication
and authorization evidence, `idempotency_key` is `null`; each fresh presentation
is a distinct attempt and returns a newly authorized current result. Those
records make capability safety `evidence_write` but do not duplicate a governed
content/projection effect. Unknown payload members, duplicate JSON names,
non-I-JSON values, noncanonical bytes, unknown algorithms, and mismatched base64
encodings fail closed.

Canonical authority-record digests use `proof:authority-record:v1`; canonical
authenticated-command envelope digests use
`proof:authenticated-command-envelope:v1`.

### Operation and action registry

Dots identify application operations; colons identify Delegation actions. They
are not interchangeable strings. The Milestone 2 authority profile has this
closed mapping:

| Operation and exact version | Required action | Requested resource closure | Application idempotency | Persisted consequence in addition to the authorization decision |
| --- | --- | --- | --- | --- |
| `workspace.status` / `proof.dev/operation/workspace.status/v1` | `workspace:status` | Workspace | `null` | authority evidence only |
| `object.query_released` / `proof.dev/operation/object.query_released/v1` | `object:query_released` | Workspace, one Environment, requested Objects | `null` | authority evidence only |
| `context.build` / `proof.dev/operation/context.build/v1` | `context:build` | Workspace, one Environment, requested Objects | required UUIDv7 | immutable v1 ContextPack and authority evidence |
| `context.build` / `proof.dev/operation/context.build/v2` | `context:build` | Complete verified `ContentResourceIntentV1` | required UUIDv7 | immutable localized ContextPack and authority evidence |
| `changeset.create` / `proof.dev/operation/changeset.create/v2` | `changeset:create` | Complete verified intent selected by the command | required UUIDv7 | draft localized ChangeSet and authority evidence |
| `changeset.add` / `proof.dev/operation/changeset.add/v2` | `changeset:add` | Complete intent bound to the ChangeSet; every Edit target must be a member | required UUIDv7 | localized Edit batch and authority evidence |
| `changeset.get` / `proof.dev/operation/changeset.get/v2` | `changeset:get` | Complete intent bound to the ChangeSet | `null` | authority evidence only; never a filtered ChangeSet |
| `changeset.diff` / `proof.dev/operation/changeset.diff/v2` | `changeset:diff` | Complete intent bound to the ChangeSet | `null` | authority evidence only; never a filtered lineage |
| `changeset.validate` / `proof.dev/operation/changeset.validate/v2` | `changeset:validate` | Complete intent bound to the ChangeSet | derived from proposal, policy, and validator | one validation attempt/lifecycle result and authority evidence |
| `changeset.submit` / `proof.dev/operation/changeset.submit/v2` | `changeset:submit` | Complete intent bound to the ChangeSet | derived from ChangeSet identity; timestamp remains semantic input | submission/lifecycle result and authority evidence |
| `changeset.commit` / `proof.dev/operation/changeset.commit/v2` | `changeset:commit` | Complete intent, exact base, and effective leaves | required UUIDv7 | authoritative rendition facts, projections, and authority evidence |
| `edition.create` / `proof.dev/operation/edition.create/v2` | `edition:create` | Complete intent bound to the exact committed ChangeSet | required UUIDv7 | immutable localized Edition and authority evidence |
| `release.create` / `proof.dev/operation/release.create/v2` | `release:create` | Complete intent resolved through the exact Edition and ChangeSet | required UUIDv7 | localized Release, Environment pointer, Proof/outbox, and authority evidence |
| `object.query_released` / `proof.dev/operation/object.query_released/v2` | `object:query_released` | Workspace, Environment, exact requested Object/locale pairs, and Schemas resolved from the current released Edition | `null` | authority evidence only; never a filtered result |

Every resource array is canonical sorted and unique. Generated result
identifiers are not invented as preauthorization inputs. Unknown operation,
version, action, pair, or incomplete resource closure fails closed before
idempotency lookup or protected disclosure.

The machine-readable
[`AuthorityOperationRegistryV1`](../../conformance/v1/authority/vectors/authority-operation-registry.valid.json)
freezes the operation/action pair, localized input Schema, application
idempotency class, closure anchor, requested-resource projection, evidence
selectors, consequence class, and implementation wave for every row.

Four projection profiles are closed:

1. `workspace-only/v1` derives only the signed command Workspace.
2. `legacy-object-selection/v1` derives the signed Workspace plus Environment
   and exact Objects from the v1 normalized input.
3. `localized-intent-closure/v1` verifies the immutable Human-issued
   `ContentResourceIntentV1` selected directly by the command or transitively
   through the ChangeSet and projects its one Environment and every Object,
   Schema, and locale target. The complete intent is evaluated even when one
   operation touches only one target.
4. `localized-released-selection/v1` first requires the signed Workspace,
   requested Environment, Objects, and locales to be granted, then resolves the
   current Release and Edition internally and requires every resolved Schema to
   be granted before disclosure. A missing released target may yield the stable
   not-found result only after the caller's requested axes and a nonempty Schema
   grant have passed; a resolved-but-ungranted Schema is a disclosure-neutral
   scope denial.

Budget projection is equally closed. `delegation-only` records the grant's
three effective maxima for operations with no narrower request budget;
`requested-object-count` additionally bounds the unique requested Objects;
`normalized-v1-context-limits` intersects the v1 context request's Object/byte
limits with the grant; `normalized-v2-context-limits` intersects the localized
context command's Object/byte/Edit limits with the grant; and
`bound-context-limits` verifies the ChangeSet's persisted ContextPack and
intersects those same three limits for every downstream operation. The
ContextPack's validation-attempt limit remains a bound application-policy
limit because `DelegationV2` has no validation-attempt budget field; it is not
silently projected into another axis.

For the two derived-key rows, signed `CommandInputV1.idempotency_key` is
`null`; the application derives a stable internal operation key only after the
selected ChangeSet, proposal, policy, validator, and lifecycle evidence have
been verified. Validation keys bind Workspace, ChangeSet, proposal, policy,
and validator. Submission keys bind Workspace and ChangeSet while
`submitted_at` remains semantic input, so an exact retry returns the persisted
submission and a changed timestamp fails as key reuse. Adapters cannot invent
their own key or treat a fresh presentation as a new validation/submission.

ChangeSet, Edition, and Release identifiers are recorded as exact evidence
selectors in `AuthorizationDecisionV2`; they are not additional Delegation
axes. Resource-intent and ContextPack identifiers/digests are bound directly
by the normalized command or transitively by the selected ChangeSet. New result
identifiers are preallocated signed inputs where required for deterministic
replay, but never widen the grant.

The Human-issued intent narrows the dimension-wise Delegation product to exact
target tuples. An Agent cannot issue, replace, narrow, or widen it. P-0004 may
implement the generic evaluator and the three existing v1 reads but MUST NOT
expose the localized operations. P-0005 binds those v2 operations to P-0007's
implemented application contracts. Any future requirement for a grant axis
outside Workspace, Environment, Object, Schema, or locale requires a new
Delegation version; transport aliases cannot change this registry.

## Time, replay, and idempotency

The v1 profile has these exact bounds:

| Limit | Value |
| --- | ---: |
| Canonical authentication payload | 4,096 bytes |
| Complete DSSE envelope | 16,384 bytes |
| Canonical authority-record payload | 65,536 bytes |
| Complete authority/root-transition DSSE envelope | 98,304 bytes |
| Complete authenticated-invocation broker frame | 1,048,576 bytes plus the stricter operation-input limit |
| Command validity interval | At most 300 seconds |
| Accepted future `issued_at` skew | At most 30 seconds |
| Signatures | Exactly one Ed25519 signature |

At evaluation, `issued_at` MUST be no later than 30 seconds after the injected
clock, the clock MUST be earlier than `expires_at`, and `expires_at - issued_at`
MUST be positive and at most 300 seconds. Causal authority sequence resolves
revocation races; the clock does not.

`presentation_id` is a canonical UUIDv7 and a single-use replay identity.
Canonical/schema/size validation, expected-key resolution and signature,
audience and actor equality, time, command cross-fields, and the unseen
presentation check MUST all succeed before consumption. Any
authentication failure consumes nothing and appends no
`AuthorizationDecisionV2`. Only then does Proof reserve the presentation in the
same transaction as the authorization allow/deny outcome. Scope, budget,
current binding activity, Principal status, or Delegation denial is consumed
and recorded; a second use returns `proof.auth.replay` without a second record,
even when bytes are identical.

Application idempotency remains separate. After an ambiguous timeout the Agent
signs a fresh presentation with the same semantic input and idempotency key.
The authenticated application operation then returns the original result under
C4 only after the retry independently authenticates under C5 and is authorized
under current C6 state. Authentication timestamps, presentation identity,
signature, and binding rotation are excluded from semantic idempotency
equivalence; derived requester, derived operator, direct Delegation, operation
version, and normalized input are included. Revocation or Principal disablement
prevents disclosure of the prior result without changing or duplicating the
completed effect. A future mutable authority-policy profile MUST apply the same
ordering.

The strongest rejected replay rule would return the original result for an
identical reused presentation. It is operationally convenient but lets a
captured read credential disclose protected results repeatedly during its
window. Fresh signing keeps C4 while making presentation replay unambiguous.

## Direct Delegation profile

`DelegationV2` is an immutable, authority-signed direct grant:

- issuer: enabled authenticated Human requesting Principal;
- recipient: enabled Agent operating Principal with an active binding;
- one exact Workspace;
- canonical sorted unique actions spanning the existing read slice and the
  Milestone 2 `changeset:create`, `changeset:add`, `changeset:get`,
  `changeset:diff`, `changeset:validate`, `changeset:submit`,
  `changeset:commit`, `edition:create`, and `release:create` path;
- canonical sorted unique Environment, Object, Schema, and locale resource
  identifiers; locales use P-0002's exact restricted grammar, including
  lowercase language and variant subtags, title-case script, uppercase alpha
  region, literal registry aliases, and no normalization;
- explicit budgets and time interval;
- no parent field; and
- no subdelegation permission.

Every scope array is an exact set. Empty means no resources are granted in that
dimension, never wildcard or all. An operation that does not use a dimension
ignores its empty set; an operation that requires the dimension denies when the
set is empty. Version 2 has no wildcard syntax.

The evaluator denies by default. It requires issuer/requester and
recipient/operator equality, then intersects the one grant with the immutable
`proof.local/authority/direct/v1` policy profile, requested action/resources,
budgets, Principal state, binding state, and revocation state at the exact
authority head. Direct/v1 admits only the three enabled registry operations and
has no mutable runtime policy-denial state. `proof.authorization.policy_denied`
remains a reserved wire value for a future versioned policy profile; P-0004 does
not fabricate an unreachable provider merely to emit it. The evaluator
re-evaluates immediately before every consequential commit and Release.

The earlier full-chain direction is not implemented under this profile. A
future chain design requires `DelegationV3` and a new ADR covering adjacency,
parent-digest binding, issuer proof at each link, intersection, depth, cycle and
duplicate detection, revocation at every link, and portable closure.

## Authority records and decisions

### Subject hiding and actor-context digests

The public authority decision does not expose the low-entropy Unix subject. On
creation or migration of the private ADR-0009 Human binding, Proof generates a
32-byte random blind and retains the opening only in private local authority
state. It computes `requesting_subject_commitment` with BLAKE3-256 derive-key
context `proof:authenticated-subject-commitment:v1` over the RFC 8785 bytes of:

```json
{
  "api_version": "proof.dev/authenticated-subject-commitment/v1",
  "authenticated_subject": {
    "api_version": "proof.dev/authenticated-subject/v1",
    "provider": "os/unix",
    "subject": "uid:1000"
  },
  "blind": "<base64url-no-pad encoding of exactly 32 bytes>",
  "workspace_id": "019c..."
}
```

This is a hiding commitment, not an unsalted UID checksum. The public bundle
carries only its digest. A separate protected audit disclosure may carry the
subject and blind under explicit caller policy, allowing an `opening_valid`
verdict; private keys are never disclosed. Without that optional opening, a
verifier can establish that the authority root signed the commitment but cannot
recover or independently identify the Unix user. Conformance may publish
clearly marked synthetic test openings.

`actor_context_digest` uses BLAKE3-256 derive-key context
`proof:authenticated-actor-context:v1` over strict
`AuthenticatedActorContextEvidenceV1`. That RFC 8785 object replaces the raw
requesting subject with `requesting_subject_commitment` and includes audience,
Workspace, authentication profile, authenticated operating subject, immutable
binding ID, both derived Principals, direct Delegation, exact operation,
command/envelope digests, presentation ID, and authentication time. It MUST be
an exact projection of the verified `AuthenticatedActorContextV1`; adapters
cannot supply either digest.

`AuthorityRecordV1` is a strict discriminated union of Principal-status,
binding-issuance/revocation, Delegation-issuance/revocation, authority-root
transition, and `AuthorizationDecisionV2` records. Every variant carries a
global per-Workspace `authority_sequence`, the previous authority-record
digest, Workspace, and variant-specific authenticated actor and recorded time.
`api_version` is the record-kind discriminator. The exact record digest is
derived from its canonical bytes. Signer identity comes from the causally active
root and verified DSSE signature, never from unsigned `keyid` alone. Where
`AuthorizationDecisionV2` repeats `authority_key_id`, it MUST equal both that
active root and the verified envelope signer. The first record has sequence `1`
and no predecessor; every later record increments by one and names the prior
digest. Each canonical record is signed by the Workspace authority key, except
a root transition, which is signed by both predecessor and successor keys.

The chain detects mutation, insertion, deletion, and reordering only relative
to a caller-trusted later authority head. A validly signed older prefix is still
a valid prefix; a file-backed authority signer and the authority log in the same
mutable Workspace cannot by themselves distinguish database truncation or a
fork restored from backup. Live P-0004 guarantees therefore remain inside the
local Workspace storage trust boundary. Offline or cross-system verification
of history completeness MUST pin an independently retained expected authority
head or a later checkpoint that commits it. A stateful external signer or
transparency service is a compatible future strengthening, not a P-0003 claim.

`AuthorizationDecisionV2` is deterministic and is itself the signed authority
record that consumes the presentation. Its `evaluated_authority_head` MUST equal
its immediate predecessor sequence and digest. The allow/deny decision and any
consequence commit atomically, so a revocation or root transition that wins the
authority-sequence race necessarily precedes and is visible to evaluation. It
records:

- semantic `CommandInputV1` and authenticated-command envelope digests;
- the requesting-subject commitment and complete actor-context digest without
  disclosing the raw Unix subject;
- presentation and operation identities;
- requesting and operating Principals;
- operating subject provider, binding, and credential key commitments;
- direct Delegation and relevant revocation digests;
- its authority sequence, predecessor/evaluated-head digest, and authority key;
- normalized action; Workspace, Environment, Object, Schema, locale, ChangeSet,
  Edition, and Release resources; effective object/context/edit budgets; and
  policy bundle;
- injected evaluation timestamp; and
- `allow` or a stable denial code.

Runtime/model metadata, prompts, MCP client capabilities, session identity, and
raw local OS subjects are excluded. They may be separate evidence linked by
digest, but changing them cannot change authority.

## CLI and MCP transport

The local profile separates signing from Workspace execution:

1. An Agent-side signer with no Workspace access selects an opaque credential
   handle, validates normalized input, and emits one strict
   `AuthenticatedInvocationV1` containing `CommandInputV1` plus the exact
   canonical DSSE envelope string.
2. A Human-owned broker, running inside the bootstrap UID/private-Workspace
   boundary, alone opens SQLite and authority keys, verifies the invocation, and
   calls the application operation.

The ratified CLI surfaces are `proof auth sign --command - --credential
<handle>` on the Agent side and fixed `proof auth execute --invocation -` as a
one-shot broker. A trusted supervisor connects one size-bounded framed stream or
already-open file descriptor across a distinct UID, container, or equivalent
sandbox; a shell pipeline running both under the same UID is only an attribution
test. No Agent-controlled path or argument may cause the privileged broker to
open a file. Any path mode is Human-only and outside the Agent transport. The
direct ambient Workspace CLI remains a Human/admin interface and is not an Agent
execution path. These spellings are part of the P-0004 ratified grammar, not
implemented commands.

The signer MUST NOT accept `--principal` as an authority selector. A retained
expected-Principal field is only a signed mismatch guard. The direct Delegation
remains explicit because authorization evaluates that exact grant.

Both MCP eras carry the complete Agent authentication presentation in
`params._meta["dev.proof/authentication"]` as a JSON string whose value is the
exact UTF-8 canonical DSSE envelope. It is not a reconstructed `_meta` object.
Modern protocol metadata and legacy initialization remain transport behavior.
The tool input may carry the Delegation selector and optional expected operating
Principal, but the backend MUST derive the operating Principal from the verified
binding and reject a mismatch. Tool discovery never grants authority.

An authenticated Agent read consumes a presentation and appends a signed
authorization decision. Its capability side effect is therefore
`evidence_write`, and MCP MUST NOT advertise `readOnlyHint: true`, even though it
does not mutate governed content or projections. An ambient authenticated-Human
read without an Agent presentation may remain read-only.

An MCP implementation that cannot preserve the exact authentication `_meta`
bytes must use an authenticated adapter wrapper. It MUST NOT fall back to a
caller-supplied Principal identifier.

## Portable authority evidence

P-0004 persists canonical authority facts and decisions. P-0006 defines the
`AuthorityEvidenceBundleV1` transport after the delegated mutation and Release
shape is known. A complete bundle for one consequential Agent action must carry
or resolve:

- the exact signed authenticated command and normalized command input;
- canonical `AuthenticatedActorContextEvidenceV1` bytes reproducing
  `actor_context_digest` without the raw requesting subject;
- requesting and operating Principal status plus binding
  issuance/revocation records;
- the direct Delegation and its revocation record when present;
- the ordered authority-log prefix or a completeness-preserving proof to the
  exact decision head;
- an independently retained expected authority-head checkpoint when the caller
  needs rollback or truncation detection;
- `AuthorizationDecisionV2`;
- Workspace authority public roots and transitions;
- the Release Proof binding the decision digest; and
- explicit caller trust policy and roots.

The independent verifier reports command signature, actor binding, authority
sequence, Delegation, policy/decision, Release signature, and evidence
completeness separately. Missing disclosure yields an incomplete verdict, not a
valid one. The public bundle never carries a raw `os/unix` subject; an optional
protected audit disclosure may carry the subject-plus-blind opening under
caller policy. Private keys are never portable. A signed local timestamp remains
a producer assertion; no third-party civil-time claim is made. Without an
independently pinned later authority head, verification can
establish internal validity of the supplied prefix but MUST NOT claim that the
producer supplied the latest or complete history.

## Error contract

P-0004 must map failures to stable Problems without leaking protected resource
existence before authentication and scope checks.

The public Problem boundary is thresholded. Structurally invalid input returns
`proof.auth.malformed`. Until a signature verifies under a known historical
binding credential, unknown binding, missing key, key mismatch, and invalid
signature all return the same public `proof.auth.denied`; the caller cannot
probe whether a binding exists. Trusted local audit and offline verification may
retain the more precise `proof.auth.binding_not_found` or
`proof.auth.signature_invalid` reason. Only after credential proof succeeds may
the public response disclose audience, actor, validity, inactive-binding,
replay, or authorization detail.

| Code | Meaning | Retry |
| --- | --- | --- |
| `proof.auth.malformed` | Envelope, canonical form, or typed payload invalid | Fix request |
| `proof.auth.denied` | Disclosure-neutral public failure before credential proof | Re-enroll or fix credentials without assuming existence |
| `proof.auth.signature_invalid` | Trusted-audit/offline reason: signature fails against the expected credential | Do not expose publicly before proof |
| `proof.auth.audience_mismatch` | Workspace audience or operation binding differs | Fix request |
| `proof.auth.binding_not_found` | Trusted-audit/offline reason: no binding key can verify the presentation | Do not expose publicly before proof |
| `proof.auth.binding_inactive` | Binding is not yet valid, expired, or revoked | Rotate/recover |
| `proof.auth.actor_mismatch` | Signed expected requester/operator differs from derived actor | Fix request or credential |
| `proof.auth.not_yet_valid` | `issued_at` exceeds the accepted future-skew boundary | Correct clock and sign a fresh presentation |
| `proof.auth.expired` | Command validity window has ended | Sign a fresh presentation |
| `proof.auth.replay` | Presentation identity was already consumed | Sign a fresh presentation |
| `proof.delegation.chain_unsupported` | Reserved for a future typed chain profile; direct/v1 rejects parent or subdelegation fields structurally as `proof.auth.malformed` | Use one direct v2 grant |
| `proof.authorization.denied` | Disclosure-neutral public authorization failure, including a hidden or missing Delegation | Change authority or request without assuming resource existence |
| `proof.authorization.principal_disabled` | Requesting or operating Principal is disabled | Recover with an enabled Principal |
| `proof.authorization.delegation_not_yet_valid` | Direct Delegation has not reached `not_before` | Retry after the bound or replace the grant |
| `proof.authorization.delegation_expired` | Direct Delegation reached its exclusive expiry | Issue a new grant |
| `proof.authorization.delegation_revoked` | Direct Delegation was causally revoked | Issue a new grant if policy permits |
| `proof.authorization.delegation_unavailable` | Trusted-audit reason for an unknown or hidden Delegation; public response remains `proof.authorization.denied` | Do not disclose selector existence |
| `proof.authorization.scope_exceeded` | Authenticated request exceeds the exact granted action or resource set | Narrow the request or change the grant |
| `proof.authorization.budget_exceeded` | Authenticated request exceeds a granted budget | Narrow the request or change the grant |
| `proof.authorization.policy_denied` | Reserved for a future versioned authority-policy profile with mutable denial state; direct/v1 never emits it | Upgrade the policy profile or change policy/request when such a profile exists |
| `proof.authority.integrity` | Authority sequence, signature, digest, or trust transition fails | Repair or investigate |

An invalid signature creates no attacker-controlled persistent row. A validly
authenticated denial may reserve the presentation and append a bounded decision
without content mutation. Errors before authentication use disclosure-neutral
wording.

## Implementation boundary for P-0004

P-0004 is decision-complete and owns:

- domain IDs and types for subjects, bindings, actor context, authority records,
  command presentation, and v2 decisions;
- an authentication port, Unix Human adapter, local Ed25519 Agent adapter, and
  deterministic fake;
- the split Agent-side signer, fixed bounded-stdin one-shot Human broker, and
  MCP stdio broker; no Agent-controlled path or argument reaches privileged
  filesystem access;
- a generic bounded typed-message DSSE verifier reusing current canonicalization
  and Ed25519 primitives without reusing the Release Statement profile;
- separate authority-key provider, enrollment, rotation, revocation, and root
  transition operations;
- v2 direct Delegation and one authorization kernel;
- replay and canonical decision storage in the same transaction as effects;
- canonical persistence of `CommandInputV1`,
  `AuthenticatedActorContextEvidenceV1`, authority records, and their exact
  digest preimages;
- atomic migration that preserves v10 and earlier historical bytes and does not
  elevate `DelegationV1`;
- CLI broker and both MCP-era parity; and
- portable conformance vectors without private keys.

P-0004 does not own delegated content mutation, chained Delegation, OIDC,
SPIFFE, Windows identity, KMS/HSM, a network/collaboration server, or the final
evidence bundle.

## Conformance and falsification

The ratified machine contracts and vectors live under
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md). Acceptance of
P-0004 requires at least:

- exact canonical payload, DSSE PAE, public key, key ID, signature, envelope,
  and digest reproduction by an independent implementation;
- one-byte mutations of actor, audience, operation, command, Delegation,
  idempotency, presentation, and time fields;
- unknown/disabled/revoked/expired binding and Principal cases;
- Agent B signing an assertion for Agent A and presenting A's Delegation;
- replay, fresh-presentation idempotent retry, and changed-input key reuse;
- inclusive validity start, exclusive expiry, and revocation at the exact causal
  authority position;
- direct allow plus Agent issuer, parent, subdelegation, cycle-shaped, widened,
  and over-budget denial cases;
- exact cross-check of all 14 authority operation/version pairs against the 11
  P-0007 localized operation Schemas, including rejection of the superseded v1
  write pairs;
- complete-intent projection for each localized lifecycle operation and staged
  Object/locale-then-resolved-Schema evaluation for released v2 queries;
- valid lowercase locale variants and literal aliases plus mixed-case variant,
  wrong region case, and missing Environment/Object/Schema/locale grant cases;
- authority-root separation and root-transition failure;
- CLI, modern MCP, and legacy MCP producing the same command digest and decision;
- denial atomicity and disclosure-neutral errors; and
- no private key, raw OS subject, bearer credential, prompt, or runtime metadata
  in persisted or ordinary public authority artifacts; only the explicit
  synthetic conformance opening and policy-controlled protected audit
  disclosure may contain a subject-plus-blind opening.

## Volatility isolation

- OIDC, SPIFFE, platform key stores, and KMS are adapters behind the subject and
  signing-provider ports.
- MCP versions and authentication carriage stay in the MCP adapter.
- Ed25519, DSSE, RFC 8785, key identifiers, sizes, and time bounds are a named
  v1 profile; a cryptographic change creates a new profile.
- Direct Delegation is `DelegationV2`; future chaining cannot silently change
  its meaning.
- The final portable bundle is deferred to P-0006 so the Release evidence shape
  is not guessed before P-0005.

## Decision record

| Decision | Accepted by | Accepted at | Consequence |
| --- | --- | --- | --- |
| Bounded local Human-to-Agent profile and ADR-0011's C4 replacement | `smithdak` | `2026-08-20T19:52:12.756Z` | P-0004 is ready; a protected workload identity remains a future adapter or reopen trigger. |

No operation-version, locale, resource-axis, retry-class, or projection question
remains open inside this ratified profile. A newly required source-locale grant,
field/path grant, hostile same-UID containment, or Agent-to-Agent chain is a
reopen trigger, not an implementation choice for P-0004.

## Kill and pivot triggers

Reopen this decision during P-0004 if any of the following becomes a
Milestone 2 requirement:

- mutually hostile processes sharing one Unix UID must be isolated;
- Proof must attest a binary, container, model, or runtime measurement;
- no callable or persistent local Agent secret is permitted;
- the north-star scenario requires Agent-to-Agent delegation;
- a client cannot preserve exact signed authentication metadata; or
- replay reservation cannot be atomic with authorization and consequence.

Database-prefix rollback resistance is not part of the local file-backed
profile. If protection against an attacker who can restore both SQLite and its
local authority state becomes a Milestone 2 requirement, P-0004 must add a
stateful external signer, monotonic checkpoint, or transparency boundary and
reopen this decision.

The first three triggers point to a daemon or SPIFFE-style workload-attestation
boundary with protected keys. The fourth requires a bounded `DelegationV3`.
The fifth requires an authenticated adapter wrapper. The sixth requires a
server-challenge protocol or transaction redesign; replay protection must not be
weakened silently.

P-0006 must run the Milestone 2 north-star with the Agent outside the bootstrap
UID/private-Workspace boundary and prove that it receives only the authenticated
adapter surface. A same-UID demonstration may test canonical attribution, but
it is not evidence that Delegation contains the Agent.

## Alternatives considered

### SPIFFE or mTLS first

This gives the strongest later workload boundary and short-lived credential
rotation, but it requires a daemon or secure channel, issuance plane, trust
bundle lifecycle, and platform/orchestrator selectors. It still needs exact
command and idempotency binding. It is the preferred future adapter, not the
smallest complete local slice.

### OS process credentials only

Unix peer credentials can authenticate UID/GID/PID at a local IPC boundary.
They do not provide a durable Agent identity and cannot distinguish two Agents
under the same UID. Keep them for the requesting Human or as supplemental
evidence, not as the operating Agent credential.

### Bearer or capability token

Copying a bearer token copies authority. Sender constraining it introduces a
proof-of-possession key and returns to the selected design with another layer.
Bearer credentials are rejected for Agent authentication.

### Full Delegation chains in Milestone 2

This preserves the earlier architectural direction, but adds parent binding,
issuer proof for every link, intersection, cycle/depth handling, revocation
closure, and substantially larger offline evidence. No current Milestone 2
scenario needs more than one Human-to-Agent grant. The direct profile is the
strongest alternative that remains complete for the demonstrated outcome.

### Tuple-scoped DelegationV3 for localized targets

Embedding exact `(object_id, schema_id, locale)` tuples directly in a new grant
would represent nonrectangular target sets without a separate intent. It would
also let the Agent-facing authority path select task scope, duplicate
Human-issued editorial intent, require a new signed grant/version and portable
closure, and still need the ContextPack freshness artifact. The accepted
`ContentResourceIntentV1` already supplies the exact immutable tuples and can
only narrow the v2 permission product, so a sixth grant axis has no demonstrated
failure mode in Milestone 2. Reopen only if the Human-issued intent cannot
remain authoritative or source-read and target-write scopes diverge.

### Reuse the Release signing key

One key and provider would be smaller. It lets one compromise manufacture both
authority history and outcome Proofs and couples high-frequency authority
administration to publication. Separate roles are worth the small additional
local key-provider surface.

### Trust identical presentation replay

Returning the original result for the same signed presentation helps naive
network retries. It also makes a captured read presentation intentionally
reusable. Proof instead composes a fresh one-use presentation with the existing
semantic idempotency key.

## Current-source and standards basis

This revision was checked against the P-0007 supported candidate
`47153144b4b834cfffab61b328e4551f09fe50cb` and its completed integration on
`main` at `8aede43c1e4ec7f24bc0fd4761aa117a5173bfa8`. Current Agent registration stores
no credential, current Delegation verification compares the recipient only to a
caller-supplied Principal, and CLI/MCP expose that selector. Existing
`proof-canonical` RFC 8785 parsing/digests and `proof-attestation` Ed25519 key
provider and strict verification primitives can be reused after a generic typed
message API is separated from the Release Statement profile.

Standards grounding as of August 20, 2026:

- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) defines Ed25519.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) defines JSON Canonicalization
  Scheme and its duplicate-free I-JSON preconditions.
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) provides the proof-of-
  possession reference pattern for unique proof identifiers and brief validity
  windows; Proof's exact bounds are profile choices.
- [DSSE v1](https://github.com/secure-systems-lab/dsse) defines typed
  pre-authentication encoding; the signature `keyid` is not independently
  authoritative.
- [MCP 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/schema)
  permits extension metadata in `_meta`; carriage does not confer Proof
  authority.
- [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/)
  is the future workload-provider reference, not an implemented dependency.
- [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)
  grounds the separation of key generation, storage, use, compromise,
  recovery, archival, and destruction.
