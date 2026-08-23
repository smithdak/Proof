# Error model

**Status:** Stable local contract
**Baseline:** August 23, 2026

Proof uses one conceptual error model across CLI, HTTP, SDK, and MCP adapters. HTTP serialization follows RFC 9457 Problem Details.

## Problem shape

```json
{
  "type": "urn:proof:problem:validation-failed",
  "title": "Validation failed",
  "status": 422,
  "detail": "Two blocking findings must be repaired before submission.",
  "instance": "urn:proof:operation:019c...",
  "code": "proof.validation.failed",
  "operation": "changeset.validate",
  "operation_id": "019c...",
  "correlation_id": "019b...",
  "retryable": false,
  "findings": [
    {
      "code": "proof.schema.required",
      "severity": "error",
      "pointer": "/edits/1/value/title",
      "object_id": "019a...",
      "validator": "json-schema/2020-12",
      "message": "Required property `title` is missing.",
      "repair": {
        "kind": "set_value",
        "pointer": "/edits/1/value/title",
        "expected": "non-empty string"
      }
    }
  ]
}
```

The controlled HTTPS problem-type URI is finalized before the first public compatibility release. The pre-domain URN avoids creating a dependency on an unowned domain. The stable `code` is the primary programmatic identifier.

## Required fields

| Field | Purpose |
| --- | --- |
| `type` | Documentation URI for the problem type. |
| `title` | Stable human summary. |
| `code` | Stable machine-readable Proof error code. |
| `operation` | Application operation that failed. |
| `operation_id` | Identifier for this execution. |
| `correlation_id` | Identifier for the larger workflow. |
| `retryable` | Whether retry may succeed without changing input. |

HTTP adds `status`; local interfaces may omit it when no transport status exists. `detail`, `instance`, and extension fields are problem-specific.

## Proposed P-0008 HTTP projection

The proposed collaboration server defines a versioned, disclosure-neutral HTTP
projection. It preserves a stable post-authentication application code as the
public `code` when that code is safe for the exact row, but deliberately
collapses unknown issuer/subject/binding/key, invalid token/signature, disabled
Principal before proof, and other sensitive pre-proof failures to
`proof.auth.denied`. This is an explicit projection, not a claim that every
internal Problem tuple is byte-for-byte identical at the HTTP boundary.

The HTTP Problem carries the exact operation name/version pair, a server UUIDv7
`operation_id`, nullable caller UUIDv7 `correlation_id`, and `retryable`.
Authorized cases may also carry `retry_after_ms`, `current_digest`, or an
accepted typed finding. No Problem exposes a token, raw OIDC subject or
opening, hidden selector, policy internals, SQL, or stack trace.

The final public set is composed machine-readably, never inferred from a global
transport list:

- a transport/session route emits exactly its route `problem_profile`;
- a Human application/data row emits the union of its route profile, row
  transaction profile, and exact `application_problem_codes`;
- an Agent row emits the union of its route profile, row transaction profile,
  exact disclosure projection in `agent_error_profiles`, and exact post-Allow
  `application_problem_codes`.

Thus bodyless GET, callback GET, JSON POST, authenticated data GET, Human, and
Human-plus-Agent routes can advertise different sets. A code's presence in the
global tuple registry does not make it reachable from every route or row.

### P-0008 HTTP Problem registry

The collaboration-server registry contains exactly the following 41
`(code, status, type, title, retryable)` tuples. This table mirrors the
normative
[`http-operation-registry.valid.json`](../../conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json)
machine vector; an adapter cannot substitute a different title, status, type,
or retry flag.

| Code | HTTP | Type | Exact title | Retryable |
| --- | ---: | --- | --- | :---: |
| `proof.auth.csrf_denied` | 403 | `urn:proof:problem:csrf-denied` | CSRF validation denied | false |
| `proof.auth.denied` | 401 | `urn:proof:problem:authentication-denied` | Authentication denied | false |
| `proof.auth.replay` | 401 | `urn:proof:problem:authentication-replay` | Authentication replay denied | false |
| `proof.authority.integrity` | 500 | `urn:proof:problem:authority-integrity` | Authority integrity failure | false |
| `proof.authorization.budget_exceeded` | 403 | `urn:proof:problem:authorization-budget-exceeded` | Authorization budget exceeded | false |
| `proof.authorization.delegation_expired` | 403 | `urn:proof:problem:authorization-delegation-expired` | Authorization delegation expired | false |
| `proof.authorization.delegation_not_yet_valid` | 403 | `urn:proof:problem:authorization-delegation-not-yet-valid` | Authorization delegation not yet valid | false |
| `proof.authorization.delegation_revoked` | 403 | `urn:proof:problem:authorization-delegation-revoked` | Authorization delegation revoked | false |
| `proof.authorization.denied` | 403 | `urn:proof:problem:authorization-denied` | Authorization denied | false |
| `proof.authorization.scope_exceeded` | 403 | `urn:proof:problem:authorization-scope-exceeded` | Authorization scope exceeded | false |
| `proof.changeset.duplicate_target` | 409 | `urn:proof:problem:changeset-duplicate-target` | ChangeSet duplicate target | false |
| `proof.changeset.invalid_supersession` | 409 | `urn:proof:problem:changeset-invalid-supersession` | ChangeSet invalid supersession | false |
| `proof.changeset.not_approved` | 409 | `urn:proof:problem:changeset-not-approved` | ChangeSet not approved | false |
| `proof.changeset.not_draft` | 409 | `urn:proof:problem:changeset-not-draft` | ChangeSet not draft | false |
| `proof.changeset.not_ready` | 409 | `urn:proof:problem:changeset-not-ready` | ChangeSet not ready | false |
| `proof.changeset.not_submitted` | 409 | `urn:proof:problem:changeset-not-submitted` | ChangeSet not submitted | false |
| `proof.delegation.expired` | 403 | `urn:proof:problem:delegation-expired` | Delegation expired | false |
| `proof.dependency.unavailable` | 503 | `urn:proof:problem:dependency-unavailable` | Dependency unavailable | true |
| `proof.digest.mismatch` | 500 | `urn:proof:problem:digest-mismatch` | Digest mismatch | false |
| `proof.evidence.incomplete` | 409 | `urn:proof:problem:evidence-incomplete` | Evidence incomplete | false |
| `proof.idempotency.key_reused` | 409 | `urn:proof:problem:idempotency-key-reused` | Idempotency key reused | false |
| `proof.input.invalid_json` | 400 | `urn:proof:problem:invalid-json` | Invalid JSON | false |
| `proof.input.intent_mismatch` | 409 | `urn:proof:problem:intent-mismatch` | Input intent mismatch | false |
| `proof.input.limit_exceeded` | 413 | `urn:proof:problem:input-limit-exceeded` | Input limit exceeded | false |
| `proof.input.schema_mismatch` | 400 | `urn:proof:problem:schema-mismatch` | Schema mismatch | false |
| `proof.input.too_large` | 413 | `urn:proof:problem:input-too-large` | Input too large | false |
| `proof.input.unsupported_media_type` | 415 | `urn:proof:problem:unsupported-media-type` | Unsupported media type | false |
| `proof.input.unsupported_version` | 400 | `urn:proof:problem:unsupported-version` | Unsupported version | false |
| `proof.integrity.failure` | 500 | `urn:proof:problem:integrity-failure` | Integrity failure | false |
| `proof.internal` | 500 | `urn:proof:problem:internal` | Internal error | false |
| `proof.operation.timeout` | 504 | `urn:proof:problem:operation-timeout` | Operation timed out | true |
| `proof.operation.unknown_outcome` | 504 | `urn:proof:problem:unknown-outcome` | Operation outcome unknown | true |
| `proof.policy.denied` | 403 | `urn:proof:problem:policy-denied` | Policy denied | false |
| `proof.rate_limit.exceeded` | 429 | `urn:proof:problem:rate-limit-exceeded` | Rate limit exceeded | true |
| `proof.resource.not_found` | 404 | `urn:proof:problem:resource-not-found` | Resource not found | false |
| `proof.state.conflict` | 409 | `urn:proof:problem:state-conflict` | State conflict | false |
| `proof.state.source_conflict` | 409 | `urn:proof:problem:source-state-conflict` | Source state conflict | false |
| `proof.state.target_conflict` | 409 | `urn:proof:problem:target-state-conflict` | Target state conflict | false |
| `proof.storage.conflict` | 503 | `urn:proof:problem:storage-conflict` | Storage conflict | true |
| `proof.validation.failed` | 422 | `urn:proof:problem:validation-failed` | Validation failed | false |
| `proof.validation.repair_evidence_invalid` | 422 | `urn:proof:problem:repair-evidence-invalid` | Repair evidence invalid | false |

The exact route-and-row composition above is normative. In particular,
bodyless login/session/capability requests do not advertise JSON Schema
mismatch; authenticated GETs do not advertise CSRF denial; callback and Agent
presentation routes can advertise replay; and JSON POST profiles alone carry
invalid-JSON/media-type/body-size failures. `proof.auth.csrf_denied` is
available only after a Human session is established. A 429 response carries
only the authorized retry delay. Dependency and storage conflicts are
retryable; application state and reused idempotency keys are not.

Every Agent row separately lists the errors that may be committed as an
`application-failure` after an Allow. All 11 localized v2 rows use the exact
17-code `LocalizedOperationFailureV1` set. The retained
`object.query_released/v1` row uses `proof.input.unsupported_version` and
`proof.resource.not_found`; `context.build/v1` uses `proof.auth.denied`,
`proof.delegation.expired`, `proof.input.too_large`, and
`proof.resource.not_found`; `workspace.status/v1` has none. The two legacy
prefixes are application outcomes in that accepted contract, not pre-proof
authentication or authorization decisions. No absent authz-only, transport,
idempotency, or infrastructure code may be signed as that row's application
failure.

Either 504 result can follow a deadline or lost commit acknowledgement.
`proof.operation.timeout` says the server deadline was exhausted;
`proof.operation.unknown_outcome` says the client-visible commit outcome is
ambiguous. A keyed operation reconciles with its original application key and
equivalent input; an Agent also supplies a fresh one-use presentation. A
no-key read has no stored-result replay promise: any permitted retry is a fresh
authenticated and authorized attempt, may append distinct evidence, and may
observe newer state. Its first outcome remains internally auditable but is not
disclosed by treating `null` as a key. OIDC login/callback ambiguity abandons or
expires that attempt/state and starts a fresh login. Logout uses no application
key: a bounded revocation tombstone validates exact session-bound CSRF replay,
always expires the HttpOnly cookie, and converges on `200` with
`logged_out:true` for the exact replay/already-revoked handle.

Before identity or Agent proof, unknown issuer, subject, key, binding, and
invalid token/signature all project to `proof.auth.denied`. Protected audit
evidence may retain the exact reason. This proposed mapping is a decision
contract only; P-0008 implements no HTTP endpoint.

## Findings

Validation and policy problems can contain multiple homogeneous findings.

A finding may contain:

- Stable `code`.
- `severity`: `info`, `warning`, or `error`.
- JSON Pointer or domain path.
- Target Object, Schema, Edit, or policy identifier.
- Validator identifier and version.
- Human message.
- Typed repair suggestion.
- Restricted diagnostic reference.

An error-level finding blocks the current transition. Warnings never conceal blocking conditions.

## Error taxonomy

### Input

- `proof.input.invalid_json`
- `proof.input.schema_mismatch`
- `proof.input.too_large`
- `proof.input.unsupported_media_type` (proposed P-0008 HTTP projection)
- `proof.input.unsupported_version`

### Authentication and authority

- `proof.auth.unauthenticated`
- `proof.auth.denied`
- `proof.auth.csrf_denied` (proposed P-0008 HTTP projection)
- `proof.delegation.expired`
- `proof.delegation.revoked`
- `proof.delegation.scope_exceeded`
- `proof.approval.required`

**Implemented P-0004/P-0005 profile** codes:

The normative definitions are in the
[authenticated actor contract](../architecture/authenticated-actor.md).

- `proof.auth.malformed`
- `proof.auth.signature_invalid`
- `proof.auth.audience_mismatch`
- `proof.auth.binding_not_found`
- `proof.auth.binding_inactive`
- `proof.auth.actor_mismatch`
- `proof.auth.not_yet_valid`
- `proof.auth.expired`
- `proof.auth.replay`
- `proof.delegation.chain_unsupported` (reserved; direct/v1 rejects parent and
  subdelegation fields as `proof.auth.malformed` before authorization)
- `proof.authorization.denied`
- `proof.authorization.principal_disabled`
- `proof.authorization.delegation_not_yet_valid`
- `proof.authorization.delegation_expired`
- `proof.authorization.delegation_revoked`
- `proof.authorization.delegation_unavailable`
- `proof.authorization.scope_exceeded`
- `proof.authorization.budget_exceeded`
- `proof.authorization.policy_denied` (reserved; the fixed direct/v1 profile
  never emits it)
- `proof.authority.integrity`

Except for the explicitly reserved values, these codes are emitted by the
bounded local authenticated-read kernel. `proof.auth.not_yet_valid` means
`issued_at` exceeds the accepted future-skew bound;
`proof.auth.expired` is reserved for `evaluated_at >= expires_at`. Exact bounds
and boundary vectors live in the authenticated actor contract and conformance
corpus linked above.

Public disclosure is proof-gated. Malformed structure may return
`proof.auth.malformed`. Before proof of possession, a well-formed unknown
binding/key and an invalid signature both return public `proof.auth.denied`;
`proof.auth.binding_not_found` and `proof.auth.signature_invalid` are trusted
audit/offline reasons only. After a valid signature under a known historical
key, public audience, actor, time, inactive-binding, replay, and authorization
detail is permitted. These rules do not reveal a hidden Principal, Delegation,
or protected resource.

Loss of a predecessor authority private key before dual-signed root transition
is a fatal `proof.authority.integrity` condition. History is preserved; v1 does
not repair, re-anchor, or claim continuity through the loss.

For a binding or `DelegationV2`, `issued_at <= not_before < expires_at`; it is
active exactly when `not_before <= evaluated_at < expires_at`. Disablement or
revocation is effective at its causal authority-record sequence regardless of
timestamp.

Canonical form, known historical binding/key resolution, valid signature,
audience, actor, command time, and unseen-presentation checks precede
consumption. Failure in that phase writes no consumption or decision. A valid
signature under a known historical binding authenticates credential control;
current binding time/revocation and Principal-enabled state are authorization
checks. Their denial atomically consumes the presentation and appends
`AuthorizationDecisionV2`, as do scope, budget, or Delegation denials. Replay
writes no second record. A future versioned authority policy with mutable denial
state may emit `proof.authorization.policy_denied`; direct/v1 cannot.

Audience or actor mismatch is a pre-consumption authentication failure and
cannot appear in `AuthorizationDecisionV2`. After a valid signature under a
known historical binding, an unknown or hidden Delegation selector is an
authorization denial: consume the presentation and persist protected reason
`proof.authorization.delegation_unavailable`, the bound selector,
`resolution: not_found_or_hidden`, and a null Delegation record digest. The
public Problem remains generic `proof.authorization.denied`.

After credential proof, public authorization Problems may use
`proof.authorization.principal_disabled`,
`proof.authorization.delegation_not_yet_valid`,
`proof.authorization.delegation_expired`,
`proof.authorization.delegation_revoked`,
`proof.authorization.scope_exceeded`, or
`proof.authorization.budget_exceeded`. Those codes describe authority already
proven relevant to the authenticated actor; they must not reveal a hidden
selector or protected resource. The reserved
`proof.authorization.policy_denied` follows the same disclosure rule if a
future policy profile enables it. `proof.authorization.delegation_unavailable`
is a protected audit/decision reason, never the public code for an unresolved
Delegation selector.

Authenticated `status` and released-query reads use `idempotency_key: null`.
Each fresh presentation is a distinct attempt that writes one consumption and
decision before returning a newly authorized current read. The `evidence_write`
does not mutate governed content/projections and is excluded from duplicate
governed effects by the ratified C4 replacement. ContextPack build remains
idempotent.

### Validation and policy

- `proof.validation.failed`
- `proof.validation.evidence_missing`
- `proof.policy.denied`
- `proof.schema.required`
- `proof.schema.type_mismatch`
- `proof.relationship.invalid_target`

#### Implemented localized-content taxonomy

The following codes are implemented by P-0007 for the Human path and exposed
through authenticated Agent `/v2` operations by P-0005. They do not alter v1
Problems.

Operation-level Problems:

- `proof.locale.invalid`: the supplied locale is not in Proof's restricted
  canonical locale profile; no alias normalization is attempted.
- `proof.content.source_conflict`: the locale-neutral source revision, digest,
  Schema, or declared base no longer matches the request.
- `proof.content.rendition_conflict`: expected rendition absence, revision, or
  digest does not match the exact `(object_id, locale)` target.
- `proof.content.rendition_not_found`: an exact-locale query has no committed
  rendition; Proof did not perform source or parent-locale fallback.
- `proof.changeset.supersession_invalid`: an Edit supersession is cross-target,
  missing, forked, cyclic, or does not name the current active Edit.
- `proof.content.intent_mismatch`: an operation's Environment, ContextPack,
  base, baseline Release, or exact Object/Schema/locale target closure differs
  from the immutable ChangeSet resource intent.
- `proof.release.baseline_conflict`: the target Environment no longer selects
  the expected baseline Release.
- `proof.release.causal_conflict`: the proposed Edition is not the exact state
  and authoritative sequence produced by the authorized ChangeSet commit.
- `proof.release.delta_mismatch`: the complete baseline-to-target Edition delta
  is not exactly the committed localized-rendition target set and provenance.

Localized validation uses the normal `proof.validation.failed` Problem and
deterministically ordered findings. P-0002 reserves:

- `proof.localization.annotation_invalid`: the Schema's proposed
  `x-proof-localizable` pointer list is malformed, overlapping, or outside the
  restricted pointer profile.
- `proof.localization.path_not_localizable`: source and localized content
  differ at a JSON Pointer not declared localizable by the exact Schema.
- `proof.validation.prohibited_legal_claim`: the pinned v1 legal-claim policy
  contains the exact locale, JSON Pointer, and JSON-string value in its sorted
  `disallowed_values` entries. It performs no fuzzy, regex, model, case, Unicode,
  or locale normalization.

Each localized finding includes `edit_id`, `object_id`, exact `locale`, and
validator identifier/version and policy digest; field findings also include an
RFC 6901 `pointer`. Schema-validation findings continue to use the existing
detailed Schema codes. A typed repair may propose a replacement localized value
or a superseding same-target Edit, but never a scope expansion, fallback,
source mutation, or policy bypass. Possessing policy or ContextPack evidence
does not grant authority.

For a P-0008 authenticated application failure, the signed consequence result
digest uses BLAKE3-256 derive-key `proof:operation-effect:v1` over RFC 8785 of
exactly
`{api_version:"proof.dev/application-problem-digest-preimage/v1",code,operation}`.
HTTP type, title, status, retryability, findings, detail, instance, correlation,
and private diagnostics do not enter that authority preimage. The selected
registry row must list the code in its exact post-Allow
`application_problem_codes`. The signed Allow means the application operation
was authorized and produced that failure, not that its governed mutation
succeeded; a failure consequence has no application effect and does not
reserve a successful idempotency result.

### State and concurrency

- `proof.resource.not_found`
- `proof.state.conflict`
- `proof.changeset.invalid_state`
- `proof.changeset.not_ready`
- `proof.changeset.not_validatable`
- `proof.changeset.not_submitted`
- `proof.changeset.approval_conflict`
- `proof.changeset.expired`
- `proof.idempotency.key_reused`

### Integrity

- `proof.digest.mismatch`
- `proof.signature.invalid`
- `proof.signature.untrusted_key`
- `proof.evidence.incomplete`
- `proof.artifact.unsupported_algorithm`
- `proof.integrity.failure` (proposed P-0008 disclosure-neutral server stop)

### Availability and internal

- `proof.dependency.unavailable`
- `proof.rate_limit.exceeded` (proposed P-0008 HTTP adapter control)
- `proof.operation.timeout`
- `proof.operation.unknown_outcome` (proposed P-0008 ambiguous commit result)
- `proof.storage.conflict` (proposed P-0008 exhausted serializable retry)
- `proof.operation.cancelled`
- `proof.internal`

The operation and Problem mappings are versioned machine-readable application
contracts and are projected identically by CLI and both MCP protocol eras.

The standalone portable verifier has a separate closed
[`proof.verify.` finding-code registry](../../conformance/v1/verifier-finding-codes.json):
156 structured report findings plus two CLI diagnostics. Thirty codes have
direct behavioral assertions; the remaining 128 have structural
emitted-source/registry equality guards and do not claim dedicated branch-level
tests. Semantic verifier outcomes are Complete, Incomplete, and Invalid;
usage/input failures are separate CLI diagnostics with exit 64 rather than
application Problem responses.

## Retry guidance

`retryable: true` means the caller may follow the exact retry protocol for that
route or operation; it does not guarantee success and does not imply that every
operation has an idempotency key.

Examples:

- Temporary dependency failure: retryable.
- Keyed timeout with unknown result: reconcile with the same application key
  and equivalent input.
- No-key timeout with unknown result: make a fresh authenticated/authorized
  attempt only where the operation is safe; there is no original-result replay
  promise.
- Concurrency conflict: not directly retryable; rebuild against current state.
- Validation failure: not retryable until input changes.
- Authorization denial: not retryable until authority or policy changes.

Under the **Ratified P-0003 profile**, an expired or replayed
`AuthenticatedCommandV1` is not retryable as that presentation. The logical
operation may be attempted with a fresh signed presentation and the same
application key when the selected row is keyed and its normalized input is
unchanged. A no-key row instead uses a fresh authenticated and authorized
attempt and may observe newer state. A disabled binding,
wrong Principal, wrong Delegation endpoint, or unsupported chain requires an
authority/input change and fails before any stored result is disclosed.
Fresh C5 authentication and current C6 authorization always precede C4
idempotent-result disclosure; an idempotency key is not a bearer capability.

## Information disclosure

Problems returned to a caller contain only information the caller is authorized to observe. They never include stack traces, SQL, secret values, tokens, private keys, full policy internals, hidden Object content, or a raw requesting subject and its 32-byte commitment blind. Under the **Ratified P-0003 profile**, disclosure of that private opening is audit-policy controlled and never occurs through ordinary Problems.

Restricted diagnostics are correlated through `operation_id` and available only to authorized operators.

## MCP mapping

The MCP adapter preserves the full Problem object as JSON `TextContent` in a successful JSON-RPC tool result with `isError: true`. It omits `structuredContent` for domain failures because each advertised output Schema describes only that tool's success data. It does not flatten repairable findings into one prose message. Transport-level protocol failures remain distinct from a completed tool invocation that returns a domain Problem.
