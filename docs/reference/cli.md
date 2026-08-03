# CLI contract

**Status:** Initial stable design  
**Baseline:** August 3, 2026

The `proof` executable is the first complete interface to the product. It is designed for interactive human use, shell composition, and reliable agent invocation.

## Interface principles

- Every capability is available non-interactively.
- Structured output is the contract; formatted output is a projection.
- Commands identify their side effects and support dry-run where meaningful.
- Consequential commands are idempotent.
- Input can be provided without unsafe shell interpolation.
- stdout carries requested results; diagnostics go to stderr.
- Prompts occur only in an interactive TTY and only when not disabled.
- Color is automatic but can be disabled with `NO_COLOR` or `--color never`.
- Secrets are read from protected handles, standard input, or platform credential stores, never command-line arguments.

## Global syntax

```text
proof [GLOBAL OPTIONS] <RESOURCE> <ACTION> [OPTIONS]
```

Proposed global options:

```text
--workspace <PATH|ID>     Select a Workspace
--profile <NAME>          Select configuration and credentials
--principal <ID>          Select an operating Principal when policy permits
--delegation <ID|PATH>    Present an explicit Delegation
--output <FORMAT>         table | text | json | ndjson | yaml
--color <WHEN>            auto | always | never
--quiet                   Suppress non-result output
--no-input                Never prompt; fail if input is incomplete
--correlation-id <UUID>   Supply or propagate a correlation identifier
--timeout <DURATION>      Bound the application operation
--trace                   Emit local diagnostic tracing to stderr
```

`--output json` returns one result envelope. `--output ndjson` is reserved for streams. YAML is for human interoperability and is never used for canonical hashing or signatures.

## Resource grammar

```text
proof init
proof status
proof inspect

proof schema create|get|list|diff|validate|history
proof object get|list|query|history
proof changeset create|get|list|add|diff|explain|validate|submit|approve|commit
proof edition create|get|list|diff|verify
proof release create|get|list|promote|rollback|verify
proof principal create|get|list|disable
proof delegation grant|get|list|revoke|verify
proof context build|get|inspect|export|verify
proof receipt get|list|verify
proof audit query|export
proof serve
proof verify <SUBJECT>
```

Objects intentionally have no direct `create`, `update`, or `delete` commands. Object mutations are Edits in a ChangeSet.

## Mutation flow

```bash
proof changeset create \
  --intent "Update the launch article and related CTA" \
  --base-state blake3:...

proof changeset add <changeset-id> --file edits.ndjson
proof changeset diff <changeset-id>
proof changeset validate <changeset-id>
proof changeset submit <changeset-id>
proof changeset approve <changeset-id> --approval editorial
proof changeset commit <changeset-id> --idempotency-key <uuid>
```

The implemented local `changeset create` operation trims and bounds the
declared intent, authenticates the Workspace bootstrap Principal, and binds the
draft to the current verified Known State when `--base-state` is omitted. It
returns a generated UUIDv7 idempotency key unless the caller supplies one.
Retrying the same normalized input with that key returns the original draft;
reusing it with different input fails explicitly.

The implemented `changeset add` operation accepts strict NDJSON records. The
first typed Edit contract creates an immutable Schema version:

```json
{"api_version":"proof.dev/edit/v1","kind":"schema.create","schema_id":"article","schema_version":1,"document":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}}
```

Schema identifiers begin with a lowercase ASCII letter and contain at most 128
bytes using lowercase letters, digits, `.`, `_`, or `-`. A batch contains 1 to
100 records and is bounded to 1 MiB. Proof rejects duplicate JSON properties,
unsupported fields, ambiguous numbers, invalid dialect declarations, duplicate
Schema-version targets, and partial batches. Documents are stored as RFC 8785
canonical JSON with a domain-separated digest. Supplying the same idempotency
key and normalized ordered batch returns the original Edit identities.

Mutation commands accept `--dry-run` where they can calculate a result without committing. `commit`, `release create`, `release promote`, and `release rollback` require an idempotency key; the CLI generates one only when running interactively and shows it before execution.

## Input rules

### Files and stdin

- `--file -` reads from stdin.
- A command reads stdin at most once.
- JSON and NDJSON input is Schema-validated before application logic.
- Input size and item-count limits are reported before partial processing.
- Filesystem paths are resolved without following unsafe traversal outside the permitted root.

### Patches

The MVP will select one content patch format through ADR. Until then, examples use complete Object replacement or typed Edit records rather than implying mixed patch semantics.

### Timestamps and durations

- Timestamps use RFC 3339 UTC.
- Durations use a documented unit-bearing format such as `30s`, `5m`, or `2h`.
- Locale-dependent dates are never accepted.

## Result envelope

Every non-streaming command supports this JSON shape:

```json
{
  "api_version": "proof.dev/result/v1",
  "operation": "changeset.validate",
  "operation_id": "019c...",
  "correlation_id": "019b...",
  "ok": true,
  "data": {},
  "warnings": [],
  "meta": {
    "proof_version": "0.1.0",
    "workspace_id": "019a...",
    "principal_id": "0199..."
  }
}
```

Rules:

- `api_version` versions the envelope, not the command.
- `operation` is stable and independent of display text.
- `operation_id` identifies this execution.
- `correlation_id` connects a larger workflow.
- `ok` is always present.
- `data` follows an operation-specific Schema.
- `warnings` never contain a condition that should have failed the command.
- `meta` contains non-authoritative execution metadata.

## Error envelope

Failed commands return the shared Problem shape documented in [Error model](errors.md). In JSON mode, expected failures never require parsing stderr.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `2` | CLI usage or input syntax error |
| `3` | Validation or policy precondition failed |
| `4` | Authentication or authorization failed |
| `5` | Concurrency or state conflict |
| `6` | Requested resource not found |
| `7` | Dependency or service unavailable |
| `8` | Integrity or verification failed |
| `9` | Operation timed out or was cancelled safely |
| `10` | Internal error |

Exit codes are broad automation categories. Stable problem `code` values carry precise semantics.

## Idempotency

Consequential commands accept:

```text
--idempotency-key <UUID>
```

The key is scoped to Workspace, Principal, and operation. Proof stores a digest of normalized request input and the resulting operation identifier.

- Same key and same input: return the original result.
- Same key and different input: return `proof.idempotency.key_reused`.
- Unknown outcome after transport failure: retry with the same key.

## Explanation

`--explain` returns a bounded decision explanation including:

- Evaluated Principal and Delegation chain.
- Requested action and resources.
- Relevant policy identifiers and versions.
- Allow, deny, or indeterminate result.
- Remediation that does not reveal restricted state.

Explanation is diagnostic evidence, not a bypass or alternate policy evaluator.

## Compatibility

- Command and flag removals require a deprecation period after `1.0`.
- JSON field additions are backward-compatible unless a Schema says otherwise.
- Field removal, type change, or semantic change requires a new `api_version`.
- Scripts should select `--output json` and test `api_version`.
- Human table and prose formatting is not a compatibility surface.
- Shell completions are generated for Bash, Zsh, Fish, PowerShell, and Nushell.

## Configuration precedence

Highest precedence first:

1. Explicit command flags.
2. `PROOF_*` environment variables for non-secret configuration.
3. Selected profile configuration.
4. Workspace `proof.toml`.
5. User configuration.
6. Built-in defaults.

Secrets are excluded from ordinary configuration files and environment variables when a credential provider is available.

## Filesystem conventions

```text
proof.toml        Workspace configuration safe to commit
.proof/           Local derived state and private runtime metadata
.proof/cache/     Rebuildable cache
.proof/state/     Local database and transaction data
.proof/artifacts/ Immutable local artifacts
```

`.proof/` is ignored by version control by default. Portable exports use explicit commands rather than copying internal state.
