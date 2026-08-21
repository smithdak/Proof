# Agent authority and ContextPacks

**Status:** Ratified architecture; bounded local authenticated mutation implemented
**Baseline:** August 21, 2026

> **Implemented P-0004/P-0005 profile:** Every section carrying the P-0003
> label is normative architecture. P-0004 implements the bounded local kernel
> and three retained v1 reads; P-0005 enables the 11 localized v2 operations.
> P-0006 owns the portable evidence bundle, containment, and publication
> qualification.
>
> The complete contract is the [authenticated actor contract](authenticated-actor.md);
> this document summarizes its consequences for Agent authority.
>
> **Ratified P-0002 profile:** The localized-content resource closure below is
> project-owner accepted. Its normative definition is the
> [delegated localized-content contract](delegated-content.md). P-0005 composes
> that contract with authenticated Agent authority without changing it.

## Principle

Agents are first-class Principals operating under explicit authority. They do not receive a privileged API, implicit trust, or permissions derived from natural-language instructions.

The authorization question is always:

> May this authenticated Principal perform this typed action on these identified resources, in this context, under this Delegation, now?

## Identity model

An agent execution has at least three distinct identities:

1. **Requesting human or service** — the actor asking for an outcome.
2. **Agent Principal** — the runtime identity invoking Proof operations.
3. **Model and runtime metadata** — evidence about the implementation that produced a proposal.

These identities MUST NOT be collapsed into one shared service account. Model metadata is not itself authority.

## Ratified P-0003 profile — authenticated actor contract

The local Milestone 2 profile separates five typed concepts:

1. **`AuthenticatedSubjectV1`** — a provider-qualified subject produced only by
   a trusted identity adapter after it verifies proof of possession. It cannot
   be constructed from CLI flags, MCP arguments, request `_meta`, a ContextPack,
   or natural-language content.
2. **`PrincipalBindingV1`** — an immutable, append-only binding from an
   authenticated Agent subject and credential public key to one operating
   Principal. One binding instance is identified by `binding_id` plus its
   issuing authority sequence and `AuthorityRecordV1` digest; `api_version`
   names only the Schema. Rotation issues a new
   binding whose `supersedes_binding_id` names the old binding; disablement
   appends an authority fact rather than rewriting history.
3. **Requesting Principal** — the Human resolved independently from ADR-0009's
   authenticated Unix subject. It MUST equal the presented Delegation's Human
   issuer; a caller cannot assert or substitute it.
4. **Operating Principal** — the Agent Principal resolved cryptographically from
   the validly issued immutable historical binding. Current binding
   time/revocation is authorization state. A request-supplied Principal is only an
   expected-value cross-check.
5. **`AuthenticatedActorContextV1`** — the adapter-derived application value
   that commits both authenticated subjects, binding identifier and issuing
   authority sequence/record digest,
   requesting and operating Principal identifiers, authentication method,
   semantic `CommandInputV1` digest and authenticated-command envelope digest,
   presentation identity, and `authenticated_at`. `authenticated_at` is the
   authentication-completion time and is not assumed equal to authorization
   `evaluated_at`. The application accepts this value only from its identity
   port.
6. **`AuthenticatedActorContextEvidenceV1`** — the strict, raw-UID-free
   canonical digest preimage for persisted actor evidence. P-0004 persists it
   with the authority decision; P-0006 carries or resolves it for portable
   verification.

For persisted authority evidence, `requesting_subject_commitment` is a hiding
commitment formed with a 32-byte blind; it is not a checksum of the raw Unix
UID. The public actor-context digest commits that public commitment and never
the raw `os/unix` subject. Disclosure of the private subject-plus-blind opening
is controlled by audit policy. The exact canonical derivation and vectors live
in the [authenticated actor contract](authenticated-actor.md) and
[`conformance/v1/authority/`](../../conformance/v1/authority/README.md).

Model, harness, executable, process, and runtime metadata remain non-authoritative
evidence. They cannot select either Principal.

### Local Agent credential

Each local Agent binding uses a distinct Ed25519 proof-of-possession credential.
The binding contains the public key identifier; the private key is addressed
through a protected credential handle and never appears in command arguments,
configuration committed to the Workspace, logs, ContextPacks, content, or Proof
predicates. The authenticated local Human may issue, rotate, or disable an Agent
credential under explicit local policy. Compromise recovery revokes and
reissues; Proof never recovers or exports an Agent private key. Rotation
overlaps only when policy explicitly permits it. Disablement prevents new
authentication but does not invalidate historically valid actions.

Within one Workspace, an active Agent key/subject maps to exactly one Principal.
Rotation for that Principal uses a distinct new key and binding. The
authenticated-subject key hex, binding `public_key`, enrollment candidate, and
actual signer key MUST all be byte-identical. For both bindings and
Delegations, `issued_at <= not_before < expires_at`; the record is active exactly
when `not_before <= evaluated_at < expires_at`. A causal disable/revoke record is
effective at its authority sequence regardless of its wall-clock timestamp.

The Unix Human bootstrap binding from ADR-0009 remains the local administrative
and direct-Human path. Operating-system identity alone does not authenticate an
Agent Principal, because multiple Agent runtimes may execute beneath one Unix
account.

This distinction is an attribution boundary unless deployment supplies
containment. Any process that can run as the bootstrap Unix UID or read the
private Workspace is inside the Human/administrator trust boundary and can use
the direct-Human path without Agent authentication. Per-Agent proof of possession
enforces bounded authority only when the Agent workload is outside that
UID/filesystem boundary and reaches Proof through a Human-owned broker or
adapter channel. Same-UID Agent execution can establish command attribution and
integrity, but cannot by itself satisfy the Milestone 2 bounded-authority exit.
If mutually hostile same-UID processes must be isolated, the profile must pivot
to a protected broker or workload-identity boundary.

### Authority administration

Only the enabled ADR-0009 bootstrap Human derived inside the Human-owned broker
may issue an enrollment challenge; enable or terminally disable a Principal;
issue, revoke, or rotate a binding; issue or revoke a Delegation; or activate an
authority-root transition. Every authority-administration actor field MUST equal
that derived bootstrap Principal, and every `DelegationV2` issuer MUST equal it.
No Agent Principal, Agent credential, or Delegation can administer authority.

### Single-use command presentation

An Agent authenticates each authority-bearing operation with an
`AuthenticatedCommandV1`: a bounded DSSE presentation whose canonical JSON
payload is signed by the bound Agent key. The authenticated payload includes the
Schema version, `presentation_id` replay identity, Workspace audience, binding,
operation name and version, normalized command digest, direct Delegation,
expected requester and operator, idempotency key where applicable, issued-at
time, and expiry. Any Principal identifier present is an expected-value
cross-check and is not identity evidence.

Authentication is a strict pre-consumption phase: canonical form, a known
historical binding and resolved key, valid signature, audience, actor equality,
command time, and unseen `presentation_id` checks all succeed before any write.
Failure appends neither a consumption nor a decision. Valid signature under a
known historical binding proves credential control; current binding
time/revocation and Principal-enabled state are AuthorizationKernel checks. The
kernel then atomically consumes the presentation and appends
`AuthorizationDecisionV2`; inactive binding/Principal, Delegation, scope, or
budget denial is a persisted authenticated denial. Replay appends no second
record. The fixed direct/v1 authority policy has no mutable denial state;
`proof.authorization.policy_denied` is reserved for a future versioned profile.

The adapter verifies the DSSE envelope, canonical payload, signature, audience,
time bounds, and bindings before deriving `AuthenticatedActorContextV1`.
Presentation consumption, `AuthorizationDecisionV2`, idempotency outcome, and
governed consequence share one transaction. Reusing a consumed presentation is
replay even when the request bytes are identical. A transport retry creates a
fresh presentation over the same normalized request and idempotency key;
fresh C5 authentication and current C6 authorization must succeed before C4
idempotency may disclose the original operation result without repeating the
consequence. Revocation or Principal or binding disablement therefore blocks
that disclosure. A future mutable authority-policy profile must preserve the
same ordering.

Each append is a Workspace-authority-signed `AuthorityRecordV1`. The authority
log has its own causal sequence and trust root, separate from governed content
facts and the Release-signing root. The local adapter MAY share one SQLite
transaction boundary while preserving the independent log and root.
Authentication,
presentation consumption, binding lifecycle, Delegation issue/revocation, and
authorization decisions are recorded there without credential secrets.
The hash chain detects mutation, insertion, deletion, and reordering only
relative to a trusted later authority head. A file-backed authority signer and
the log in the same mutable Workspace do not prevent a valid older prefix or
fork from being restored; detecting that residual requires an independently
pinned authority-head checkpoint.

If the predecessor authority private key is lost before a dual-signed root
transition commits, v1 continuity is unrecoverable. Proof preserves the
verifiable history and fails authority operations with a fatal root-unavailable
integrity result; it does not re-anchor or report recovered continuity. A new
authority epoch or re-anchor requires a future ADR, Schema, and explicit caller
trust.

Dual-signed rotation is planned continuity, not compromise recovery. A
compromised predecessor key can sign an attacker successor or fork; trust stops
at the last independently pinned pre-compromise checkpoint. Recovery requires a
future explicit trust epoch/re-anchor, not ordinary rotation.

Principal disablement is terminal in the v1 profile. Recovery after disabling
a Principal creates a new Principal, binding, and `DelegationV2`; it never
reactivates the disabled Principal or its earlier authority.

### Direct Delegation profile

Milestone 2 accepts exactly one `DelegationV2` from a Human to an Agent. The
independently authenticated requesting Principal MUST equal its issuer, and the
authenticated operating Principal MUST equal its recipient. The requested
action, resource, budget, validity
interval, current revocation state, and applicable policy are intersected with
the operation immediately before consequence.

`DelegationV2` uses canonical sorted actions for the existing read slice and
reserves the Milestone 2 `changeset:create`, `changeset:add`, `changeset:get`,
`changeset:diff`, `changeset:validate`, `changeset:submit`,
`changeset:commit`, `edition:create`, and `release:create` tokens. P-0003 fixes
their exact operation/action identities and, after P-0007, their complete
content, Edit, Edition, and Release resource projections. P-0004 exposes the
status/query/context v1 operations; P-0005 enables the localized v2 rows without
changing their authority meaning. Transport or implementation
aliases never silently change the vocabulary.

Every `DelegationV2` scope array is exact-set semantics: an empty array grants
none, never wildcard. Dimensions unused by an operation are ignored; a required
dimension with an empty grant denies. The binding/Delegation time and causal
revocation predicates above are re-evaluated at the authority head.

Subdelegation is unsupported in this profile. A parent reference, a path with
more than one Delegation, `allow_subdelegation: true`, a non-Human issuer, or a
cyclic/malformed path fails closed with structured
`proof.delegation.chain_unsupported` or
malformed-input Problem. No partial prefix is evaluated. Supporting chained
Delegation later requires a new versioned profile and migration/conformance
decision.

### Ratified P-0002 localized-content closure

The existing `DelegationV2` dimensions are sufficient for the ratified
Milestone 2 localized-content path. One immutable `ContentResourceIntentV1`
binds an exact Environment and sorted unique `(object_id, schema_id, locale)`
targets. Every target Environment, Object, Schema, and locale MUST be a member
of the corresponding exact-set scope. Empty required scope remains deny, never
wildcard.

The independently authenticated requesting Human issues that intent as an
immutable content-addressed control artifact before delegated execution and
MUST equal the direct Delegation issuer. An Agent may select its identifier and
digest but cannot
create, replace, narrow, or widen it. Under the bounded local profile,
`context.build/v2` exactly selects and replays a pre-existing Human-built pack;
it does not create the first pack. `changeset.create/v2` binds both record and
pack digests. Intent issuance does not advance the authoritative content
sequence, change Known State, enter an Edition delta, or move an Environment
pointer.

Those dimension arrays describe a permission product. The Human-issued target
tuples narrow the product to this task and cannot be changed by the Agent. A campaign,
content subtree, path prefix, relationship, query, or future Object is not a
resource axis; a trusted Human-side selector resolves editorial intent to exact
identifiers before ContextPack construction and authorization.

The existing `ObjectRevisionV1` is locale-neutral source content. Its read is
covered by the exact Object and Schema dimensions. `object.locale.put` writes
only a subordinate rendition and additionally requires the target locale. It
does not infer or require a source-locale grant, and it cannot mutate the source
Object. If a later requirement makes the source itself locale-specific or
requires distinct source-read and target-write authority, `DelegationV2` is
insufficient and MUST be versioned or replaced by two explicit grants.

No content-specific action is added. The proposal retains the reserved
`context:build`, `changeset:*`, `edition:create`, `release:create`, and
`object:query_released` tokens while versioning the affected application
operations to `proof.dev/operation/<name>/v2`. Every operation evaluates the
complete immutable intent and effective Edit closure. A caller missing one
target dimension is denied rather than receiving a filtered ContextPack,
ChangeSet, diff, validation result, Edition, or Release.

Generated ChangeSet, Edit, Edition, Release, and Proof identifiers are selected
or recorded after an authorized creation; they are evidence, not new grant
dimensions. Edition and Release authorization additionally proves that the
Environment baseline is unchanged and that the state delta is exactly the one
bound ChangeSet, not merely a subset of the broad Delegation product.

P-0003's reconciled registry retains the three implemented v1 read pairs,
replaces the superseded v1 write reservations with all 11 P-0007 localized v2
pairs, and freezes four exact resource-projection profiles in
[`AuthorityOperationRegistryV1`](../../conformance/v1/authority/vectors/authority-operation-registry.valid.json).
The complete intent is evaluated for every localized lifecycle operation; the
released v2 query authorizes Object/locale selectors before internally
resolving and authorizing Schemas from the current Edition. P-0007 proves the
same content path under an authenticated Human; P-0005 enables that exact path
for an Agent.

## Delegation

A Delegation contains:

```json
{
  "delegation_id": "019c...",
  "issuer_principal_id": "019a...",
  "recipient_principal_id": "019b...",
  "actions": ["object:read", "changeset:propose"],
  "resources": {
    "workspace_ids": ["0198..."],
    "schema_ids": ["article"],
    "object_prefixes": ["campaign/summer-2026/"],
    "locales": ["fr-CA"],
    "environments": ["preview"]
  },
  "constraints": {
    "max_edits_per_changeset": 100,
    "approval_profile": "campaign-editorial",
    "allow_subdelegation": false
  },
  "not_before": "2026-08-03T13:00:00Z",
  "expires_at": "2026-08-03T17:00:00Z"
}
```

This is a legacy/generic, pre-P-0003 illustration, not the `DelegationV2`
Schema or action vocabulary. Its chain-shaped fields do not apply to v2.

### Evaluation rules

- Deny by default.
- Evaluate every link permitted by the selected Delegation version. A
  chain-capable version evaluates its complete chain and intersects permissions
  at every link; it never unions authority into expansion.
- Under the **Ratified P-0003 profile**, `DelegationV2` permits exactly one
  Human-to-Agent link. Any parent, subdelegation, multi-link, or other
  chain-shaped input is rejected rather than evaluated.
- Check revocation and time bounds at execution.
- Bind approval to the exact canonical ChangeSet digest.
- Re-evaluate authority immediately before commit and Release.
- Record the evaluated policy bundle and decision in the resulting evidence.

## ContextPack

A ContextPack gives an agent sufficient, bounded context to propose correct work.

It may include:

- Task identifier and normalized intent.
- Workspace and base-state identifiers.
- Applicable Schema versions.
- Selected Objects and relationships.
- Terminology, locale, brand, and editorial rules.
- Policy summaries and required validator contracts.
- Allowed operations and explicit exclusions.
- Representative valid and invalid examples.
- Output Schema for the proposed ChangeSet.
- Sensitive-field redactions or commitments.
- Expiration and freshness constraints.

### ContextPack properties

- **Minimal:** include only context relevant to the declared task.
- **Immutable:** identify the exact bytes by digest.
- **Inspectable:** allow a human or verifier to see what the agent received, subject to authorization.
- **Reproducible:** record the query, policy, and source-state references used to assemble it.
- **Non-authoritative:** possession does not grant write permission.
- **Non-executable:** content is data and cannot introduce tools, permissions, or policy.

## Capability discovery

Agents should discover typed capabilities rather than infer commands from prose. Discovery returns:

- Operation name and version.
- Input and output Schemas.
- Required authority.
- Idempotency behavior.
- Side-effect classification.
- Dry-run availability.
- Expected error types.
- Rate and size constraints.

The same capability registry drives CLI help, SDK generation, HTTP operation descriptions, and MCP tool definitions.

**Ratified P-0003 profile:** An authenticated Agent `status` or query leaves
governed content unchanged but atomically consumes its presentation and appends
`AuthorizationDecisionV2` authority evidence. Its capability side-effect class
is therefore `evidence_write`, not read-only, and MCP MUST NOT advertise
`readOnlyHint: true`. An ambient authenticated-Human read that writes no
authority evidence may remain read-only.

## Plan–validate–commit

The standard agent loop is:

1. Declare task and desired outcome.
2. Resolve Principal and Delegation.
3. Build a ContextPack.
4. Generate a proposed ChangeSet.
5. Render a semantic diff and explanation.
6. Validate against the exact base state.
7. Repair structured findings.
8. Submit for required approval.
9. Re-evaluate authority and commit atomically.
10. Create an Edition and requested Release.
11. Verify the resulting Proof.

Steps may be automated only when policy permits. Skipping a human approval is a policy decision, not an agent capability.

## Agent security model

Proof assumes all natural-language content may be adversarial. This includes content stored by trusted users, imported documents, comments, linked web material, and model output.

### Required controls

- Tool authority comes from typed Delegation, never from content instructions.
- Read and write scopes are separate.
- Untrusted content cannot alter system prompts, policy, capabilities, or tool definitions.
- Context assembly labels source and sensitivity.
- High-impact actions require explicit, digest-bound confirmation or approval.
- Tool responses are Schema-validated before use.
- External URLs, filesystem paths, and commands cross typed allowlisted adapters.
- Secrets are represented by handles and never placed in prompts or ContextPacks.
- Budgets bound Edit count, object count, payload size, duration, and retries.
- Repeated denials, scope probes, and abnormal repair loops generate security signals.

### Confused-deputy prevention

Proof evaluates authorization against both the requesting actor and operating Principal where available. An agent cannot use its own broader service authority to satisfy a request the initiating actor could not make unless a separately auditable automation policy explicitly permits it.

### Memory and state

Agent memory is not authoritative CMS state. Information enters Proof only through typed commands, validation, and accepted ChangeSets. A future memory integration must preserve source, purpose, retention, and authorization metadata.

## MCP adapter policy

MCP is an adapter over application operations, not the internal architecture.

As of August 16, 2026:

- The preferred adapter contract is final MCP `2026-07-28`: each request carries the protocol version and client capabilities in `_meta` and is handled without an initialization gate.
- `server/discover` is implemented for clients that want versions and capabilities up front; it and deterministic tool-list results include explicit public cache hints.
- Initialization-based MCP `2025-11-25` remains a legacy compatibility path in the same stdio server.
- Every modern result includes `resultType: "complete"`; unsupported modern versions fail with `-32022` and exact requested/supported version data.
- MCP sessions or transport state cannot become authority or domain state. Authority-bearing tools require Principal and Delegation identifiers in every call.
- Every MCP tool has the same input Schema, idempotency behavior, and error semantics as its underlying operation.
- Destructive or consequential tools are annotated and policy-gated.

**Ratified P-0003 profile:** Principal and Delegation tool arguments are
expected-value cross-checks and selectors only. Every authority-bearing modern
or legacy MCP call carries a fresh signed command presentation in
`params._meta["dev.proof/authentication"]`. Neither the stdio process, legacy
initialization state, modern protocol metadata, discovery metadata, nor a prior
call supplies ambient authority.

## Evidence

Agent-generated ChangeSets and resulting Proofs record:

- Requesting and operating Principal identifiers.
- Delegation chain identifiers.
- ContextPack digest.
- Capability and operation versions.
- Model and runtime metadata when available.
- Validation and policy bundle versions.
- Human approvals and their bound digest.

Model prompts and hidden reasoning are not required evidence. Storing them by default creates privacy, security, portability, and reproducibility problems. The evidence model records declared inputs, structured outputs, and consequential decisions.

**Ratified P-0003 profile:** Consequential evidence additionally commits the
exact Principal `binding_id` and issuing authority sequence/record digest,
public `requesting_subject_commitment`, raw-UID-free
`AuthenticatedActorContextEvidenceV1`, semantic `CommandInputV1` digest,
authenticated-command envelope digest,
direct `DelegationV2` digest and as-of revocation position,
`AuthorizationDecisionV2` digest, and authority-log position. Portable closure
is deferred to P-0006 as `AuthorityEvidenceBundleV1`; it must supply those
canonical artifacts under an explicit caller-trusted authority root and, when
history completeness is claimed, an independently pinned expected authority
head. Identifiers or producer self-consistency alone do not establish trust.

For localized v2 Allows, local evidence also includes the signed result kind,
result contract and digest, application-consequence digest, the v13
per-presentation consequence row, and the successful Workspace-global
application-key row when one exists. That local cross-link is an input to
P-0006; it is not itself a portable evidence bundle or containment proof.
