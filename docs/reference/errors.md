# Error model

**Status:** Initial stable design  
**Baseline:** August 3, 2026

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

### Validation and policy

- `proof.validation.failed`
- `proof.validation.evidence_missing`
- `proof.policy.denied`
- `proof.schema.required`
- `proof.schema.type_mismatch`
- `proof.relationship.invalid_target`

### State and concurrency

- `proof.resource.not_found`
- `proof.state.conflict`
- `proof.changeset.invalid_state`
- `proof.changeset.not_ready`
- `proof.changeset.not_validatable`
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

The final registry lives as versioned machine-readable data once implementation begins.

## Retry guidance

`retryable: true` means a retry with the same idempotency key may succeed without semantic input changes. It does not guarantee success.

Examples:

- Temporary dependency failure: retryable.
- Timeout with unknown result: retryable with same idempotency key.
- Concurrency conflict: not directly retryable; rebuild against current state.
- Validation failure: not retryable until input changes.
- Authorization denial: not retryable until authority or policy changes.

## Information disclosure

Problems returned to a caller contain only information the caller is authorized to observe. They never include stack traces, SQL, secret values, tokens, private keys, full policy internals, or hidden Object content.

Restricted diagnostics are correlated through `operation_id` and available only to authorized operators.

## MCP mapping

The MCP adapter preserves the full Problem object as structured tool error data. It does not flatten repairable findings into one prose message. Transport-level protocol failures remain distinct from successful tool invocation that returns a domain problem.
