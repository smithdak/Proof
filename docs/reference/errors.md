# Error model

**Status:** Stable local contract
**Baseline:** August 21, 2026

Proof uses one conceptual error model across CLI, HTTP, SDK, and MCP adapters. HTTP serialization follows RFC 9457 Problem Details.

## Problem shape

```json
{
  "type": "urn:proof:problem:validation-failed",
  "title": "The ChangeSet did not pass validation",
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
- `proof.input.unsupported_version`

### Authentication and authority

- `proof.auth.unauthenticated`
- `proof.auth.denied`
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

For an authenticated localized application failure, the public Problem is also
the canonical signed result preimage under
`proof.dev/result/localized-operation-problem/v1`. Its stable operation, code,
title, retry class, and findings determine the result digest; transport-only
detail does not. The signed Allow means the application operation was
authorized and produced that failure result, not that content mutation
succeeded. The failure consequence commits atomically but does not reserve a
Workspace-global application idempotency key.

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

### Availability and internal

- `proof.dependency.unavailable`
- `proof.operation.timeout`
- `proof.operation.cancelled`
- `proof.internal`

The operation and Problem mappings are versioned machine-readable application
contracts and are projected identically by CLI and both MCP protocol eras.

## Retry guidance

`retryable: true` means a retry with the same idempotency key may succeed without semantic input changes. It does not guarantee success.

Examples:

- Temporary dependency failure: retryable.
- Timeout with unknown result: retryable with same idempotency key.
- Concurrency conflict: not directly retryable; rebuild against current state.
- Validation failure: not retryable until input changes.
- Authorization denial: not retryable until authority or policy changes.

Under the **Ratified P-0003 profile**, an expired or replayed
`AuthenticatedCommandV1` is not retryable as that presentation. The logical
operation may be attempted with a fresh signed presentation and the same
idempotency key when its normalized input is unchanged. A disabled binding,
wrong Principal, wrong Delegation endpoint, or unsupported chain requires an
authority/input change and fails before any stored result is disclosed.
Fresh C5 authentication and current C6 authorization always precede C4
idempotent-result disclosure; an idempotency key is not a bearer capability.

## Information disclosure

Problems returned to a caller contain only information the caller is authorized to observe. They never include stack traces, SQL, secret values, tokens, private keys, full policy internals, hidden Object content, or a raw requesting subject and its 32-byte commitment blind. Under the **Ratified P-0003 profile**, disclosure of that private opening is audit-policy controlled and never occurs through ordinary Problems.

Restricted diagnostics are correlated through `operation_id` and available only to authorized operators.

## MCP mapping

The MCP adapter preserves the full Problem object as JSON `TextContent` in a successful JSON-RPC tool result with `isError: true`. It omits `structuredContent` for domain failures because each advertised output Schema describes only that tool's success data. It does not flatten repairable findings into one prose message. Transport-level protocol failures remain distinct from a completed tool invocation that returns a domain Problem.
