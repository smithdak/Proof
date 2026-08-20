# Proposed local authority conformance profile

Status: **P-0003 reconciliation candidate, pending project-owner review**.
These schemas and vectors freeze the smallest Milestone-2 local authentication
and authority profile. The three v1 read operations are implemented; the 11
localized v2 application contracts are implemented only through P-0007's Human
path and remain unavailable to an Agent until P-0005. This profile binds their
authority vocabulary now so P-0004 cannot invent adapter-local semantics.

No file in this directory contains an Agent key, Workspace-authority key, blind,
or other secret. Public keys, exact signatures, canonical payload bytes, DSSE
PAE bytes, and digests are test evidence only. `AuthorityEvidenceBundleV1` is
owned by P-0006 and is intentionally not implemented here.

## Deployment and process boundary

An isolated Agent-side signer has no private Workspace access. It produces one
size-bounded `AuthenticatedInvocationV1` containing exact typed
`CommandInputV1` and the canonical authenticated-command DSSE envelope. It
feeds that frame through standard input or an already-open descriptor to one
fixed Human-owned, one-shot/stdio broker command. Agent-controlled executable
paths or arguments are forbidden. MCP stdio is the same broker boundary: typed
tool parameters plus the exact authentication metadata map to the internal
wrapper, and parameters never become filesystem paths.

Only the broker opens the private Workspace, resolves bindings, authenticates,
authorizes, and appends authority evidence. Ambient direct CLI access is
Human-only. Any process with the bootstrap UID or private Workspace access is
inside Human/administrator trust and can bypass Agent presentation. The profile
is enforcement for Agent workloads isolated outside that boundary; same-UID
Agent execution provides attribution only. No network server is required.

## Contracts

- `AuthenticatedSubjectV1`: strict `os/unix` `uid:<decimal>` requester or
  `proof/local-ed25519` operator subject.
- `PrincipalBindingV1`: immutable Agent Principal-to-key binding proven by a
  one-use `BindingEnrollmentChallengeV1`.
- `AuthenticatedActorContextV1`: private runtime context containing both raw
  requester and operator subjects.
- `AuthenticatedActorContextEvidenceV1`: persisted/exportable evidence-safe
  context containing the requester commitment, never the raw UID.
- `CommandInputV1`, `AuthenticatedCommandV1`, and
  `AuthenticatedInvocationV1`: semantic input, signed assertion, and broker
  frame.
- `DelegationV2`: direct Human-to-Agent grant.
- `AuthorizationDecisionV2`: signed, durable presentation-consumption and
  authorization record.
- `AuthorityOperationRegistryV1`: closed operation/action, localized input,
  resource-projection, selector, idempotency, consequence, and availability
  mapping for the three v1 reads and 11 P-0007 v2 operations.
- `AuthorityRecordV1`: discriminated union of typed log records.
- `WorkspaceAuthorityRootV1` and
  `WorkspaceAuthorityRootTransitionV1`: public root metadata and planned
  dual-signed rotation.

`api_version` is a schema version. A binding instance is identified by its
immutable `binding_id`, `authority_sequence`, and derived record digest;
there is no per-Principal binding version. Rotation creates a new key and
binding linked with `supersedes_binding_id`.

## Canonical commands and signatures

All JSON is RFC 8785/JCS canonical UTF-8 with duplicate properties, unsafe
numbers, unknown properties, and noncanonical encodings rejected. The broker
validates and canonicalizes the registered operation input before wrapping and
hashing it. The following `CommandInputV1` fields must equal the signed
`AuthenticatedCommandV1` fields and the independently derived actors:
`workspace_id`, `operation`, `requesting_principal_id`,
`operating_principal_id`, `delegation_id`, and `idempotency_key`.
`normalized_input` is validated by the registered typed operation schema.

`command_digest` means the `CommandInputV1` semantic digest. There is no
separate authenticated-command payload digest. `command_envelope_digest`
commits the canonical DSSE envelope, including its exact signature array.

Authenticated command and enrollment payloads are at most 4,096 canonical
bytes and their complete DSSE envelopes at most 16,384 canonical bytes.
Authority-record payloads are at most 65,536 canonical bytes and ordinary or
root-transition envelopes at most 98,304 bytes. The broker frame is at most
1,048,576 canonical bytes and remains subject to the operation-specific input
limit.

Command and enrollment envelopes have exactly one standard-base64 Ed25519
signature. A root transition has exactly two distinct signatures in order:
predecessor, successor. Standard base64 must round-trip through decode and
canonical re-encode exactly; nonzero pad bits are invalid.

DSSE `keyid` is an unsigned lookup hint. After verifying against the
independently resolved expected key it must equal that key:

- command envelope: the immutable historical PrincipalBinding credential;
- enrollment envelope: the challenge candidate key;
- ordinary authority envelope: the causally active authority root;
- root transition: exactly the payload predecessor then successor.

Duplicate, missing, permuted, or substituted root-transition key IDs fail
authority integrity.

## Digest registry

Each digest is BLAKE3-256 derive-key mode over the named RFC 8785 canonical
object:

| Context | Exact preimage |
| --- | --- |
| `proof:command:v1` | `CommandInputV1` JCS |
| `proof:authenticated-command-envelope:v1` | authenticated-command DSSE envelope JCS |
| `proof:binding-enrollment-challenge:v1` | enrollment challenge JCS |
| `proof:binding-enrollment-envelope:v1` | enrollment DSSE envelope JCS |
| `proof:authenticated-subject-commitment:v1` | subject-commitment input JCS |
| `proof:authenticated-actor-context:v1` | evidence-safe actor-context JCS |
| `proof:authority-record:v1` | typed authority record JCS |
| `proof:authority-record-envelope:v1` | ordinary or transition authority DSSE envelope JCS, including signature order |
| `proof:policy-bundle:v1` | strict policy-bundle JCS |

The requester commitment preimage is exactly
`{api_version:"proof.dev/authenticated-subject-commitment/v1",workspace_id,authenticated_subject,blind}`.
`blind` is base64url without padding for 32 random bytes, generated per
binding and retained only in private authority state or an explicit audit
disclosure. The evidence-safe actor context contains that commitment, the
authenticated operating subject, authentication profile, binding/Principal
IDs, operation, command and envelope digests, presentation ID, and
`authenticated_at`. P-0004 must persist its canonical bytes and digest.
`authenticated_at` is authentication completion time and need not equal the
decision's `evaluated_at`.

## Enrollment, administration, and binding invariants

The sole v1 administrator is the enabled ADR-0009 bootstrap Human derived by
the Human-owned broker. Every `issued_by_principal_id`,
`recorded_by_principal_id`, `revoked_by_principal_id`,
`activated_by_principal_id`, and Delegation issuer must equal that Principal.
Agents and Delegations cannot administer authority. Authorization decisions
are kernel-produced, not administrator mutations.

Enrollment challenges expire within 300 seconds and are single-use. A binding
is issued only after proof of possession. These cross-field invariants are
mandatory:

1. Within one Workspace, one active `proof/local-ed25519` subject/key maps to
   exactly one Agent Principal. Cross-Principal active key reuse is integrity
   failure. Same-Principal rotation uses a new key and binding; overlap is
   allowed only between distinct keys.
2. `authenticated_subject.subject` equals `ed25519:` plus lowercase hex of
   the decoded 32-byte `public_key`, equals the enrollment
   `candidate_key_id`, and equals the verified enrollment signer/key ID.
3. A Principal disablement is terminal in v1. Recovery creates a new Principal,
   binding, and grant; false-to-true status is invalid.

`issued_at <= not_before < expires_at` for bindings and Delegations. They are
active exactly when `not_before <= evaluated_at < expires_at`. Revocation and
Principal disablement take effect at their authority sequence regardless of
their descriptive timestamp; sequence wins.

## Authentication, consumption, and errors

Authentication checks canonical/schema/size limits, resolves a known immutable
historical binding key, verifies the signature, derives the actor, checks DSSE
key ID and all duplicate-field equalities, checks audience and command time,
and rejects an already-seen presentation. Unknown binding/key or an invalid
signature returns public `proof.auth.denied` and appends nothing; trusted
audit/offline verification may retain `proof.auth.binding_not_found` or
`proof.auth.signature_invalid`. Structural failures are public
`proof.auth.malformed`. Specific audience, actor, time, and replay errors are
available only after cryptographic proof.

Current binding activity is authorization state, not signature-discovery state.
After a historical key verifies, the kernel checks binding time/revocation,
Principal status, Delegation resolution/time/revocation/scope, budgets, and
policy. It atomically reserves the presentation and appends one signed
`AuthorizationDecisionV2`, including denials. Missing or hidden Delegation
uses audit reason `proof.authorization.delegation_unavailable` and public
`proof.authorization.denied`. Replay returns the existing result/error and
never appends a second decision.

`presentation_id` is single-use. Command lifetime is at most 300 seconds;
`issued_at` up to 30 seconds in the future is accepted, 31 seconds is
`proof.auth.not_yet_valid`, and `evaluated_at == expires_at` is expired.
A C4 retry signs a fresh presentation over the same semantic command and
idempotency key. Changing normalized input under the same key is
`proof.idempotency.key_reused`.

Localized validate and submit carry a null signed idempotency field but derive
their internal C4 operation key from verified application state. Validation
binds Workspace, ChangeSet, proposal, policy, and validator; submission binds
Workspace and ChangeSet while `submitted_at` remains semantic input. A fresh
presentation does not create a new logical attempt for the same derived key.

Authenticated reads use `idempotency_key: null`. Every fresh read
presentation is a distinct authenticated attempt and intentionally appends one
consumption/decision record but performs zero governed content or projection
writes. It returns a newly authorized current read, not a cached prior result.
Bounded per-attempt security evidence is outside application idempotency.

## Delegation and registered operations

The profile is direct Human-to-Agent only: no parent Delegation and
`allow_subdelegation` is absent or false. Empty scope arrays grant none in
that dimension, never wildcard. An unused dimension is ignored; an operation
requiring an empty dimension is denied. All arrays are sorted and unique.
An authority record whose set-like arrays are not already sorted is rejected
before signing; verifiers never silently reorder a signed record.
Environment IDs are lowercase ASCII `^[a-z][a-z0-9._-]{0,127}$`.
Locale IDs use the P-0002 grammar: lowercase language and variant subtags,
optional title-case script, optional uppercase-alpha or three-digit region, at
most 64 characters, exact case-sensitive comparison, and no alias
normalization. Literal syntactic aliases such as `iw` remain distinct from
`he`.

| Operation/version | Requested action | Idempotency | Consequence/resource status |
| --- | --- | --- | --- |
| `workspace.status` / `proof.dev/operation/workspace.status/v1` | `workspace:status` | null | Workspace; authority evidence only |
| `object.query_released` / `proof.dev/operation/object.query_released/v1` | `object:query_released` | null | Workspace, Environment, exact Objects; authority evidence only |
| `context.build` / `proof.dev/operation/context.build/v1` | `context:build` | required UUIDv7 | Workspace, Environment, exact Objects; immutable v1 ContextPack |
| `context.build` / `proof.dev/operation/context.build/v2` | `context:build` | required UUIDv7 | Complete verified localized intent; immutable localized ContextPack |
| `changeset.create` / `proof.dev/operation/changeset.create/v2` | `changeset:create` | required UUIDv7 | Complete selected intent; draft ChangeSet |
| `changeset.add` / `proof.dev/operation/changeset.add/v2` | `changeset:add` | required UUIDv7 | Complete bound intent plus member Edit targets; Edit batch |
| `changeset.get` / `proof.dev/operation/changeset.get/v2` | `changeset:get` | null | Complete bound intent; unfiltered read |
| `changeset.diff` / `proof.dev/operation/changeset.diff/v2` | `changeset:diff` | null | Complete bound intent; unfiltered lineage read |
| `changeset.validate` / `proof.dev/operation/changeset.validate/v2` | `changeset:validate` | derived proposal/policy/validator key | Complete bound intent; validation attempt |
| `changeset.submit` / `proof.dev/operation/changeset.submit/v2` | `changeset:submit` | derived ChangeSet key | Complete bound intent; submission lifecycle |
| `changeset.commit` / `proof.dev/operation/changeset.commit/v2` | `changeset:commit` | required UUIDv7 | Complete bound intent and exact effective leaves; rendition commit |
| `edition.create` / `proof.dev/operation/edition.create/v2` | `edition:create` | required UUIDv7 | Complete committed ChangeSet intent; immutable Edition |
| `release.create` / `proof.dev/operation/release.create/v2` | `release:create` | required UUIDv7 | Intent resolved through exact Edition/ChangeSet; Release, pointer, and Proof |
| `object.query_released` / `proof.dev/operation/object.query_released/v2` | `object:query_released` | null | Workspace, Environment, exact Object/locale requests, resolved Schemas; unfiltered read |

The normative
[`authority-operation-registry.valid.json`](vectors/authority-operation-registry.valid.json)
and its [Schema](schemas/authority-operation-registry-v1.schema.json) define four
projection profiles. Localized lifecycle operations resolve the complete
immutable Human-issued intent directly or through their ChangeSet/Edition.
The v2 released query uses staged evaluation: grant-check Workspace,
Environment, requested Objects and locales; resolve the current Release and
Edition internally; then grant-check every resolved Schema before disclosure.
ChangeSet, Edition, and Release IDs are evidence selectors, not grant axes.
Five budget profiles separately freeze whether effective constraints come from
the Delegation alone, requested Object count, normalized v1/v2 context limits,
or a verified bound ContextPack. The v2 ContextPack validation-attempt limit is
application policy, not an invented Delegation constraint.
P-0004 may implement the evaluator and three v1 reads but must not expose the
localized rows; P-0005 performs that wiring without changing the registry.

## Authority log, roots, and offline evidence

Each typed AuthorityRecord carries its own `api_version`,
`authority_sequence`, and `previous_authority_record_digest`; its
type-specific actor and time fields are authoritative. The record digest is
derived. The authority key is established by the causally active root and the
verified envelope key ID, except `AuthorizationDecisionV2.authority_key_id`
also explicitly equals that root and signer. Its
`evaluated_authority_head` equals the immediate predecessor. Presentation
consumption, decision consequence, and signed decision append are atomic.
Runtime/model metadata is never an identity or authority selector.

The initial root and authority-head checkpoint are caller-trusted out of band.
A planned rotation activates only as the next causal record and is signed by
both predecessor and successor roots. It is not compromise recovery. Loss of
the predecessor secret before transition makes continuity unrecoverable.
A compromised predecessor can authorize an attacker successor or fork. V1 must
stop at the last independently pinned pre-compromise checkpoint; a future
authority-epoch/re-anchor design must make the trust discontinuity explicit.

The signed chain detects mutation or reordering relative to a trusted head. It
does not prevent database-prefix rollback or a hidden fork. Truncation/fork
detection requires an independently pinned authority head/checkpoint. This
residual is deliberate; P-0003 does not add a stateful external signer.

## Vector verification

The four `*.dsse-bytes.valid.json` manifests expose exact canonical payload
bytes, DSSE PAE bytes, public key/key ID, signature bytes, and envelope digest
for command, enrollment, ordinary authority record, and dual-root transition.
The Context build pair proves identical `CommandInputV1`, idempotency key, and
command digest with distinct presentations, signatures, and envelope digests.
Rejected manifests define both public code and trusted audit reason plus
whether a durable decision append occurs.

The unsigned registry and localized-scope vectors add no credential material.
They prove the exact 14-pair closed registry, cross-link all 11 P-0007 v2 input
Schemas, retain only the three implemented v1 pairs, reproduce the four
resource-projection profiles, and accept lowercase variants/literal aliases
while rejecting mixed-case variants. The retained Rust conformance test also
mutates the operation set, action mapping, projection source, retry class, and
locale casing so these files cannot pass as unexamined documentation.

Vectors were generated in one in-memory dependency graph. Secret material was
never serialized. The temporary derive-key helper was built outside the tree
with:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'proof-authority-vector-target'
cargo build --manifest-path conformance\v1\authority\vector-helper\Cargo.toml --locked
```

That one-off source is deliberately removed after generation. Reverification
must derive every context from the checked-in canonical preimage, decode and
canonical-base64 re-encode every byte field, verify every Ed25519 signature
from public material only, cross-link every duplicated ID/key/digest, and walk
the complete authority sequence from the independently trusted root/head.
