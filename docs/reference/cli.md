# CLI contract

**Status:** Milestone 1 implemented; Milestone 2 read-authority slice implemented

**Baseline:** August 16, 2026

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
--principal <ID>          Proposed P-0003 profile: cross-check expected Principal
--delegation <ID>         Proposed P-0003 profile: select; never authenticates
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

The grammar above is the compatibility target. The implemented executable currently exposes:

```text
proof init
proof status
proof changeset create|get|add|diff|validate|submit|approve|commit
proof edition create
proof environment create|get
proof release create|get|rollback|verify
proof object query
proof projection rebuild [--dry-run]
proof principal create-agent
proof delegation grant|get|revoke|verify
proof context build|get|verify
proof capability list
proof verify --file <PATH> --trusted-key-id <ed25519:HEX> --expected-envelope-digest <blake3:HEX>
```

`--principal` and `--delegation` are a required pair for delegated `status`, released-Object query, and ContextPack operations. In this slice they are caller-supplied identifiers, not proof of an authenticated Agent binding. Plain `status` and released-Object query use the authenticated local Human. Explicit authority is rejected on operations that cannot enforce it; it is never silently ignored. This slice accepts a Delegation ID, not a path to a Delegation document.

An Environment is a logical, versioned release target and policy binding; it is not a content package or directory. The local adapter target kind is `proof.local/released-state/v1`. Promotion creates an immutable Release and signed Proof. Rollback creates another immutable Release selecting an earlier Edition and advances the derived Environment pointer; it does not rewrite either Release.

A ContextPack is a bounded, immutable package assembled from exact released Objects under an explicit Agent Principal and Delegation. Object count, canonical byte size, task identity, expiry, and idempotency are part of the operation input and persisted evidence.

The standalone offline verifier checks canonical DSSE/in-toto bytes, a caller-supplied expected envelope digest, and the Ed25519 signature against a caller-supplied trusted key ID. It does not verify Workspace policy or persisted Release evidence. `release verify` is the operation that verifies the persisted local Release, Proof subjects, evidence, and configured trust.

The `proof-mcp` stdio binary implements current MCP `2026-07-28` and legacy MCP `2025-11-25` for capability discovery, delegated Workspace status, delegated released-Object query, and ContextPack build. Modern requests are independent and carry protocol version plus client capabilities in per-request `_meta`; they do not require `initialize`. The server implements `server/discover`, returns `resultType: "complete"` on modern results, and publishes public cache hints for discovery and the deterministic tool registry. Legacy clients retain the `initialize` / `notifications/initialized` path. Every authority-bearing tool call supplies its Principal and Delegation explicitly; MCP session state is not authority. This is a read/evidence slice, not a delegated mutation or collaboration server.

### Proposed P-0003 profile — authenticated Agent invocation

This profile is pending project-owner acceptance and is not implemented by the
current delegated read slice. The normative proposal is the
[authenticated actor contract](../architecture/authenticated-actor.md).

- `--profile` selects a protected local Agent credential handle. The profile
  name and handle are configuration selectors, not authority.
- `--principal` is an optional expected operating-Principal cross-check. The
  identity adapter derives the operating Principal from a validly issued
  immutable historical `PrincipalBindingV1`; a mismatch fails authentication,
  while current binding state is evaluated during authorization.
- `--delegation` selects one `DelegationV2`. The application derives the
  requesting Human from its issuer and requires the authenticated Agent to be
  its recipient.
- The profile reserves the exact application action tokens
  `changeset:create`, `changeset:add`, `changeset:get`, `changeset:diff`,
  `changeset:validate`, `changeset:submit`, `changeset:commit`,
  `edition:create`, and `release:create` for downstream P-0002/P-0005 work.
  P-0004 implements the generic exact-set evaluator but exposes only the current
  status, released-query, and ContextPack operations. The exact 12
  operation-version-to-action entries are normative in the
  [authenticated actor contract](../architecture/authenticated-actor.md) and
  [`conformance/v1/authority/`](../../conformance/v1/authority/README.md); adapters reject
  unknown pairs and never infer punctuation aliases. If downstream write
  resources need scope dimensions absent from `DelegationV2`, P-0003 must
  reopen and version the contract before those operations are exposed.
- The CLI signs a fresh `AuthenticatedCommandV1` DSSE presentation through the
  credential provider. The payload binds the Workspace, adapter audience,
  operation and capability versions, normalized request digest,
  `presentation_id`, Delegation, idempotency key where applicable, and time
  bounds.
- Modern and legacy MCP calls carry the same per-call signed presentation. MCP
  carries it in `params._meta["dev.proof/authentication"]`; initialization,
  stdio process lifetime, protocol metadata, and earlier calls provide no
  identity or ambient authority.
- Principal and Delegation identifiers in CLI or MCP input are cross-checks and
  selectors. Possessing either identifier, a ContextPack, or an idempotency key
  proves nothing about the caller.
- A presentation is consumed once in the separately rooted authority log. A
  logical retry creates a fresh presentation with the same idempotency key and
  equivalent normalized request.
- Persisted and ordinary exported actor evidence exposes the public
  `requesting_subject_commitment`, a hiding commitment formed with a 32-byte
  blind, and never treats it as a raw UID checksum. The actor-context digest
  never includes the raw requesting `os/unix` subject or blind. An audit command
  may disclose the private subject-plus-blind opening only when audit policy
  authorizes it; canonical semantics live in the
  [authenticated actor contract](../architecture/authenticated-actor.md).
- Authenticated Agent `status` and query operations do not mutate governed
  content, but they consume the presentation and append
  `AuthorizationDecisionV2` evidence. Their capability side-effect class is
  `evidence_write`; MCP MUST NOT publish `readOnlyHint: true`. Human ambient
  reads that append no authority evidence may remain read-only.
- Authenticated `status` and released-query calls keep `idempotency_key: null`.
  Each fresh presentation is a distinct attempt, appends exactly one consumption
  plus decision, and returns a newly authorized current read. This bounded
  per-attempt security evidence is not a duplicate governed effect under the
  proposed C4 carve-out: governed content and projections remain unchanged.
  ContextPack build remains idempotent under its existing operation contract.

The authenticated local Human path remains adapter-derived from ADR-0009 and
does not impersonate an Agent merely because both processes share one Unix user.

That shared-UID case is not containment under the **Proposed P-0003 profile**.
A process with the bootstrap UID or private Workspace access is inside the
Human/administrator trust boundary and can invoke the direct-Human CLI path
without an Agent presentation. Bounded Agent authority therefore assumes a
distinct UID, container, or sandbox with no repository, raw CLI, or private
Workspace access; it reaches Proof only through the Human-owned broker or
adapter channel. Same-UID proof of possession provides attribution and command
integrity only.

The minimum contained topology splits an Agent-side signer with no Workspace
access from a Human-owned local broker/verifier that alone opens the private
Workspace and authority keys. The signer emits exact normalized input plus its
`AuthenticatedCommandV1` DSSE. Existing `proof-mcp` stdio is one broker surface.
CLI parity uses the fixed Human-owned `proof auth execute --invocation -`
surface, which reads one bounded framed invocation from stdin or an already-open
file descriptor. The frame is at most 1,048,576 bytes and remains subject to the
operation-specific input cap. No Agent-controlled argv, path, signed field, or
MCP value may cause the privileged broker to open a file. Any path-taking mode
is Human-only and outside the Agent transport. The ambient direct CLI is also
Human-only. This adds no network or collaboration server.

Only the enabled ADR-0009 bootstrap Human derived inside that broker may issue
an enrollment challenge; enable or terminally disable a Principal; issue,
revoke, or rotate a binding; issue or revoke a Delegation; or activate a root
transition. Every administration actor field and `DelegationV2` issuer must
equal the derived bootstrap Principal. No Agent or Delegation administers
authority.

Public authentication errors are proof-gated. Malformed structure may return
`proof.auth.malformed`; a well-formed unknown binding/key and an invalid
signature before proof both return public `proof.auth.denied`. Detailed
`binding_not_found` or `signature_invalid` reasons are restricted to trusted
audit/offline output. After a valid signature under a known historical key,
audience, actor, time, inactive-binding, replay, and authorization detail may be
public.

Linux CI is the current quality gate. It does not establish release
eligibility, signed artifacts, an SBOM, provenance, reproducibility, or public
distribution. Windows builds and local test runs do not constitute live
Windows runtime qualification or published Windows support.

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

The implemented `changeset add` operation accepts strict NDJSON records. One
typed Edit contract creates an immutable Schema version:

```json
{"api_version":"proof.dev/edit/v1","kind":"schema.create","schema_id":"article","schema_version":1,"document":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}}
```

The initial Object mutation contract creates revision 1 under an exact Schema:

```json
{"api_version":"proof.dev/edit/v1","kind":"object.create","object_id":"019c0000-0000-7000-8000-000000000001","schema_id":"article","schema_version":1,"content":{"title":"Launch"}}
```

The caller supplies a canonical lowercase UUIDv7 Object identity so a retried
request cannot silently create a second logical Object. Proof normalizes the
first revision to `1`, lifecycle state to `active`, and relationships to `[]`.
The content root must be a JSON object. Replacement, patch, relationship,
localization, and tombstone Edits remain deliberately outside this initial
profile.

Schema identifiers begin with a lowercase ASCII letter and contain at most 128
bytes using lowercase letters, digits, `.`, `_`, or `-`. A batch contains 1 to
100 records and is bounded to 1 MiB. Proof rejects duplicate JSON properties,
unsupported fields, ambiguous numbers, invalid dialect declarations, duplicate
Schema-version or Object targets, and partial batches. Documents and Object
content are stored as RFC 8785 canonical JSON with domain-separated digests.
Supplying the same idempotency key and normalized ordered batch returns the
original Edit identities.

`changeset get` reconstructs the complete authenticated draft and its Edits in
persisted ordinal order. `changeset diff` projects those same verified records
as proposed effects: a Schema-create Edit has a `null` before-state and an after
state containing the parsed document, canonical JSON, and document digest.
An Object-create Edit similarly projects its Object identity as the target, a
`null` before-state, and a complete after-state containing the exact Schema
reference, normalized revision, lifecycle and empty relationships, parsed and
canonical content, and Object-revision digest. Both operations are read-only and fail integrity verification if
identity, schema migration records, ordinals, canonical bytes, dialect, or
digests do not agree. Human diff output is deterministic for the same persisted
ChangeSet.

`changeset validate` reconstructs that same verified proposal, computes a
domain-separated digest over its manifest and ordered Edits, and validates each
Schema document against the bundled Draft 2020-12 metaschema. Object content is
validated against the referenced immutable Schema from the declared base state
or a valid lower-ordinal `schema.create` in the same ChangeSet. A later Schema
Edit is intentionally not visible to an earlier Object Edit. Validation results
are canonicalized, digested, and persisted against the exact ChangeSet digest,
base-state digest, validation profile, and pinned validator identity. An empty
ChangeSet, invalid Schema, missing Schema, or invalid Object returns
`proof.validation.failed` with deterministically ordered findings and exit code
3 and seals the proposal as `rejected`. Successful validation seals the exact
proposal as `ready`, so no further Edits can invalidate its evidence.
Revalidating the sealed proposal reproduces the same ChangeSet and
validation-results digests.

`changeset submit` accepts only a `ready` proposal with canonical valid evidence
matching its exact ChangeSet digest, base state, validation profile, and pinned
validator. It atomically records the submitted digest, validation-results
digest, Principal, and timestamp while transitioning the proposal to
`submitted`. Retrying returns the original submission record. A draft or
rejected proposal fails without creating a partial submission.

`changeset approve --approval <name>` records one explicit local approval for
the exact submitted ChangeSet and validation-results digests. Approval names
use a bounded lowercase machine identifier profile. The authenticated Human
Principal, name, and canonical approval time are persisted atomically with the
transition to `approved`; an identical retry returns the original record, while
a different approval name conflicts. The initial local policy permits the
bootstrap Human Principal to approve their submitted proposal; stronger
separation-of-duties profiles remain an explicit policy extension.

`changeset commit --idempotency-key <uuid>` rechecks the exact validation,
submission, and approval evidence and compares the proposal's declared base to
the current reproducible Known State. It then writes every immutable Schema
version and Object revision in Edit order, advances one shared contiguous
authoritative sequence, records the commit, updates Known State, and transitions
the ChangeSet to `committed` in one immediate SQLite transaction. A stale base,
existing target, reused key, or storage failure leaves authoritative state
unchanged. Retrying the same ChangeSet and key returns the original commit
result and timestamp.

`edition create` materializes the current non-empty Known State as one
immutable canonical `proof.dev/edition/v1` manifest. The manifest binds the
Workspace, authoritative sequence, Known State digest, ordered Schema set,
optional ordered Object set, their domain-separated submanifest digests, and
committed ChangeSet digests. Empty Object fields are omitted, preserving the
exact canonical bytes and digests of existing Schema-only Editions. Its Edition
digest uses the `proof:edition:v1` domain; operational identity and creation
time remain outside the content address. Repeated creation for unchanged state
returns the same Edition, while reusing an idempotency key after state advances
fails explicitly.

Projection rebuild accepts `--dry-run` to reproduce and compare all derived state without writing repairs. `changeset commit`, `release create`, and `release rollback` require an explicit idempotency key. Edition, Environment, Agent Principal, Delegation, and ContextPack creation accept explicit keys and return the generated key when their command grammar permits omission.

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

**Proposed P-0003 profile:** authority-bearing results add distinct requesting
and operating Principal identifiers, exact `binding_id` plus its issuing
authority sequence and record digest, semantic `CommandInputV1` digest,
authenticated-command envelope digest, `DelegationV2` digest,
`AuthorizationDecisionV2` digest, and `AuthorityRecordV1` position. Model and
runtime metadata remain non-authoritative. Existing result Schemas retain their
current meaning until versioned successors are implemented.

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

**Proposed P-0003 profile:** idempotency is evaluated only after a fresh
`AuthenticatedCommandV1` has been verified, consumed, bound to the operating
Principal, and authorized under current authority. C5 authentication and C6
authorization precede C4 disclosure of a stored result. Retrying an unknown
outcome uses the same idempotency key and normalized request but a new
`presentation_id`. Replaying a consumed presentation fails; revocation,
Principal or binding disablement, or policy denial also blocks the stored result.

## Explanation

`--explain` returns a bounded decision explanation including:

- Evaluated Principal and Delegation chain.
- **Proposed P-0003 profile:** distinct requesting Human, authenticated
  operating Agent, exact binding identifier and issuing authority
  sequence/record digest, direct `DelegationV2`, and
  authority-log position.
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
