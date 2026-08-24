# Roadmap and MVP

**Status:** Ratified product sequence  
**Baseline:** August 23, 2026

The roadmap is organized around complete capability loops rather than feature count. Each milestone must produce an independently usable and testable system slice.

## Milestone 0 — Constitution and contracts

**Outcome:** Implementation can begin without inventing domain semantics inside individual crates.

- Ratify vocabulary and invariants.
- Record initial ADRs.
- Define the CLI result and error envelopes.
- Define identifiers, canonicalization, digest, and Proof formats.
- Establish the Rust workspace boundaries.
- Create conformance fixtures for canonicalization and identifiers.
- Establish testing, dependency, and supply-chain policies.

**Exit condition:** A contributor can explain every accepted state transition and identify the crate responsible for enforcing it.

## Milestone 1 — Local proof loop

**Outcome:** One person can manage and verify structured content entirely through the local CLI.

1. Initialize a Workspace.
2. Define and version a Schema.
3. Create Objects through a ChangeSet.
4. Inspect and validate a multi-Object ChangeSet.
5. Commit atomically against an explicit base state.
6. Create an immutable Edition.
7. Release it to a local Environment.
8. Query released content.
9. Inspect and verify the Release Proof.
10. Rebuild projections and reproduce the same Known State.

**Required quality:** Deterministic fixtures, crash-safe transactions, structured output, no direct writes, and no mutable published state.

## Milestone 2 — Agent authority

**Outcome:** An agent can safely complete the same loop inside bounded authority.

**Status:** Complete for the accepted bounded local Linux profile through
P-0006 candidate `ea35e093daed50017684f7da53373cbb70af753a` and Engineering
evidence `7df66d98b38155f9c6fec1549dbb1c17ebabdb3c`. Project owner
`smithdak` accepted that candidate, evidence, and the documented residual risks
at `2026-08-23T00:34:50.674Z`; the canonical disposition is in the
[P-0006 completion record](../work/items/P-0006-close-milestone-2.md#completion-record).

- Principal registry and local identities.
- Scoped, expiring Delegations.
- ContextPack construction and redaction.
- Capability discovery.
- Idempotency and resumable application operations.
- Structured repair loops.
- Stable MCP adapter with protocol negotiation.
- Agent-security abuse cases and conformance tests.

**Implemented P-0004/P-0005/P-0006 local profile:** Milestone 2 uses distinct
local per-Agent Ed25519 proof-of-possession credentials, adapter-derived
authenticated actor context, single-use signed command presentations, one direct Human-to-Agent
`DelegationV2`, and a separately rooted append-only authority log. CLI and both
MCP eras treat supplied Principal and Delegation identifiers as cross-checks or
selectors, never authority. P-0006 defines and qualifies the portable
`AuthorityEvidenceBundleV1`, including an independently pinned authority-head
checkpoint when authority-prefix rollback or truncation must be detected. The
local SQLite-plus-file-signer profile does not prevent restoration of a valid
older authority prefix or fork. P-0004 implements this kernel for the three
retained v1 reads; P-0005 composes it with all 11 localized v2 operations. Its
normative definition is the
[authenticated actor contract](../architecture/authenticated-actor.md).

**Ratified P-0003 qualification boundary:** a process with the bootstrap Unix
UID or private Workspace access remains inside Human/admin trust and can omit
Agent authentication. Milestone 2 exit evidence must run the Agent under a
distinct UID, container, or sandbox that denies repository, raw CLI, and private
Workspace access and exposes only the Human-owned broker/adapter channel.
Same-UID proof of possession proves attribution and integrity, not containment,
and cannot satisfy the exit condition. If mutually hostile same-UID isolation
becomes required, pivot to a protected broker or workload identity.

The minimum local topology separates a Workspace-blind Agent-side signer from a
Human-owned broker/verifier that alone opens the private Workspace and authority
keys. `proof-mcp` stdio is one broker surface; CLI parity uses
`proof auth execute --invocation -` with one bounded framed stdin/already-open-FD
invocation. No Agent-controlled path or argv can make the broker open a file,
and the ambient CLI remains Human-only. This adds no network/collaboration
server.

P-0004 implements the generic evaluator for the reconciled 14-row authority
registry—three retained v1 reads and 11 localized v2 pairs—and P-0005 exposes
all 14 through CLI and both MCP eras. P-0007 owns the exact
content/Edit/Edition/Release contracts; P-0003 fixes their complete-intent and
staged released-query projections; P-0005 binds but does not reinterpret either
side.

Authenticated status/query reads use no idempotency key: every fresh
presentation is a distinct attempt that appends one consumption plus decision
and returns a newly authorized current read. Their metadata is
`evidence_write`, while governed content/projections remain unchanged under the
ratified C4 security-evidence rule. ContextPack build remains idempotent.

### Implemented P-0007/P-0005 localized content sequence

This sequence is implemented for the Human content path and bounded
authenticated Agent path. P-0007 remains the named content-foundation
prerequisite, so P-0005 does not introduce separate Agent content semantics.

- P-0007 implements the Human-path localized content foundation; P-0005 enables
  the same lifecycle for authenticated Agents. It covers append-only
  `ObjectLocaleRevisionV1` renditions, repair by Edit supersession, exact-locale queries, versioned
  ChangeSet/Edition/Release artifacts, migration, and causal release checks.
- The existing `ObjectRevisionV1` remains the locale-neutral source.
  `object.locale.put` can create an absent rendition or replace an exact
  revision and digest for one `(object_id, locale)` target. It cannot mutate the
  source Object, Schema, relationships, or lifecycle and cannot invoke fallback
  or general variant selection.
- A ChangeSet carries immutable resource intent for one Environment, one
  ContextPack and digest, one base Known State, one expected baseline Release,
  and a sorted finite set of exact Object/Schema/locale targets. The north-star
  campaign and content subtree are resolved by an authenticated Human into a
  separately persisted intent that the Agent cannot replace or narrow; neither
  is a grant dimension or a runtime hierarchy query.
- The Human builds the initial localized ContextPack and performs approval. An
  Agent may exactly select or replay that pack but cannot create or replace
  closure or approve a ChangeSet.
- Invalid validation remains repairable in the versioned ChangeSet contract.
  A repair appends a same-target superseding Edit, while validation, approval,
  commit, and Proof evidence bind the complete attempt history and final active
  leaves.
- Edition creation binds the exact sequence produced by the authorized commit.
  Release creation requires the expected Environment Release to remain current
  and proves that its full delta is exactly the one committed ChangeSet. An
  ambient current Edition or unrelated committed delta cannot be released under
  the operation's authority.
- Ratified application contracts define `/v2` successors for
  `context.build`, `object.query_released`, all content-capable `changeset.*`
  operations, `edition.create`, and `release.create`. P-0003's ratified profile
  reconciles all 11 with the three retained v1 reads and freezes their exact
  resource projections; P-0005 enables them through the P-0004 kernel.
- Each localized Allow signs the exact application result and consequence.
  Storage schema v14 persists the canonical authenticated-command input and
  signed envelope before the cross-linked per-presentation decision, effect,
  and Workspace-global successful application key. Exact replay still requires
  fresh authentication and current-state authorization.

P-0005 composes P-0007 and P-0004 and supplies bounded local authenticated
Agent mutation and local delegated evidence. P-0006 qualifies the complete
north-star loop across application, CLI, modern MCP, and legacy MCP; portable
clean-directory verification; and distinct-UID Linux broker containment. Its
accepted residuals exclude global-latest Release claims, independent
Environment-creation chronology, exact v2 approval causal heads, hostile
same-UID isolation, Windows runtime containment, server parity, deployment, and
public release.

**Exit condition:** Achieved for the bounded local Linux profile: an Agent
completes the north-star localization scenario without unrestricted repository
access or privileged commands, and the resulting closure verifies independently
under explicit caller trust. See the accepted
[P-0006 work item](../work/items/P-0006-close-milestone-2.md).

## Milestone 3 — Collaboration server

**Outcome:** A team can review, approve, publish, and verify changes remotely while preserving local semantics.

**Status:** [P-0008](../work/items/P-0008-ratify-collaboration-server-contract.md)
is project-owner accepted and ADR-0013 is Accepted. Its boundary requires a
same-origin OIDC Human session plus the
existing Agent signature, one serialized PostgreSQL authority unit, causal
approval/configuration evidence, immutable artifact staging, and an
at-least-once outbox. All five dependency-ordered successors — P-0009
remote actor and shared-contract conformance, P-0010 PostgreSQL parity
foundation, P-0011 HTTP and OIDC server boundary, P-0012 artifact outbox
and private preview delivery, and P-0013 remote evidence and Milestone 3
qualification — are complete and project-owner accepted; **Milestone 3 is
complete (2026-08-24)**. No server deployment, provider, or production
choice is made yet.

The server does not create a second application model. Every operation/version
shared with local mode is evaluated by one retained application-semantic
oracle: equivalent normalized input and authoritative state must produce the
same typed application result, governed facts, stable Problem code, and
idempotency/concurrency outcome. OIDC/session evidence, remote authority
successors, PostgreSQL transactions, artifact persistence, and delivery are
versioned topology-specific envelopes around that oracle; they cannot
reinterpret a local state transition.

- HTTP API and PostgreSQL persistence adapter.
- Collaborative review and approval.
- OIDC identity integration.
- Policy administration.
- Event delivery and transactional outbox.
- Rust and TypeScript SDKs.
- Initial human web console.
- Preview Environment integration.

**Exit condition:** Local and server adapters pass the same retained
application-semantic oracle for every shared operation, plus their respective
topology-specific authentication, persistence, delivery, and evidence
conformance suites.

## Milestone 4 — Enterprise readiness

**Outcome:** Proof can operate as a production enterprise CMS.

- Multiple Workspaces, brands, regions, locales, and Environments.
- High availability, backup, restore, and disaster recovery.
- Enterprise workload identity and key-management integrations.
- Migration framework and compatibility adapters.
- Retention, legal hold, redaction, and evidence export.
- Performance and scale qualification.
- Threat-model closure and external security review.
- Signed release artifacts, SBOMs, provenance, and reproducible-build targets.

Milestone 4 evidence export covers enterprise retention, custody, discovery,
legal-hold, and managed distribution. It does not defer the narrower portable
authority closure required by the **Ratified P-0003 profile** for Milestone 2
independent verification.

## MVP definition

The MVP is Milestones 0 and 1. It is complete only when the entire local proof loop works. A partial collection of CRUD commands is not an MVP.

## Success measures

### Correctness

- Replaying accepted records produces the same state digest.
- Partial ChangeSet effects are impossible after rejection, conflict, crash, or retry.
- Proof verification succeeds without trusting the agent that proposed the work.

### Agent operability

- All consequential operations have stable structured input and output.
- An agent can recover from validation failures using returned findings.
- Delegated work cannot exceed declared authority.

### Human operability

- Every change is explainable as a readable diff.
- An operator can identify intent, authority, source context, validation, approval, and outcome from one correlation chain.
- Rollback selects a prior immutable Edition rather than mutating history.

### Portability

- Core conformance tests are independent of CLI, HTTP, storage, and model providers.
- Local and server modes preserve identical state-transition semantics.

## Deliberate deferrals

The roadmap does not schedule personalization, experimentation, campaign automation, visual page building, or a full DAM. Those capabilities are evaluated only after the CMS core is operational and stable.
