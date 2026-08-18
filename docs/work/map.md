# Rolling-wave work map — Milestone 2 agent authority

## Destination

Milestone 2 is complete when an adapter-authenticated local actor bound to an
Agent Principal can execute Proof's complete content-change and Release loop
under bounded Delegation and a task-specific ContextPack, with human approval,
independently verifiable evidence, structured repair, and no privileged
interface.

The current Release and read-authority implementation must first become a clean,
qualified baseline. Collaboration-server and enterprise deployment work begin
only after the Milestone 2 exit scenario passes.

## Operating notes

- Follow the [work-control protocol](README.md).
- Execute one named item as one large autonomous chunk. Sub-agents may work
  inside that item; they do not claim adjacent items implicitly.
- `ready` is claimable. `blocked` and `proposed` are not.
- Closing an item must update this map and reshape only its newly unblocked
  successors.
- Architecture and product claims follow the precedence rules in the
  [documentation index](../README.md).

## Baseline — August 17, 2026

- Checkout: `D:\github\Proof`; branch `main`; one worktree.
- Starting HEAD: `3373f3768a4e07a0e5680d88cb7fe4b2c2848f0d`.
- Qualified baseline implementation commit:
  `1fef16e8d0f9d355957abc6f973b3551a2c922cb`.
- At P-0001 closure, the local `origin/main` tracking ref was `9f69e80` and
  local `main` was three commits ahead. This was not a live remote verification.
- The Release, attestation, Environment, Principal, Delegation, ContextPack,
  projection-rebuild, CLI, and MCP slice is qualified in the baseline
  implementation commit above. The follow-up control-plane commit binds that
  exact SHA without self-reference.
- Ubuntu 24.04 qualification passed on August 17, 2026: strict Clippy, 197
  workspace tests, doc tests, 103 internal links, six work-item checks, and
  normalized whitespace. Windows is compile-only and remains runtime
  unqualified.
- No push, tag, public release, package publication, or live remote
  verification occurred.

## Existing constraints

- [Core invariants](../architecture/constitution.md) prohibit privileged agent
  paths and require execution-time authority, exact-input validation, immutable
  publication, and reproducible evidence.
- [Agent authority](../architecture/agent-authority.md) requires explicit
  requesting and operating identities, bounded Delegation, ContextPacks,
  repair, human approval, re-authorization, Release, and verification.
- [The roadmap](../product/roadmap.md) requires Milestone 2 before the
  collaboration server.
- Environment is a versioned delivery target and current-Release pointer;
  ContextPack is the bounded package supplied to an agent.

## Now

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Ratify the Milestone 2 delegated content contract](items/P-0002-ratify-delegated-content-contract.md) | `review` | P-0001 | Qualified exact-locale candidate awaits project-owner acceptance. |

## Next

These implementation items remain blocked until their decision dependencies
close. Each must be re-read and reshaped before promotion to `ready`.

The item frontmatter is authoritative; the status and blocker columns below are
derived. Any mismatch blocks claiming until both are repaired together.

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Ratify authenticated actor and Delegation semantics](items/P-0003-ratify-authenticated-actor.md) | `blocked` | P-0001, P-0002 | Qualified candidate awaits the delegated content/write-resource closure before owner review. |
| [Implement the authenticated authorization kernel](items/P-0004-implement-authorization-kernel.md) | `blocked` | P-0003 | Bind authenticated actors to Principals and produce exact delegated decisions. |
| [Implement the localized content foundation](items/P-0007-implement-localized-content-foundation.md) | `blocked` | P-0002 | Prove exact-locale revision, repair, Edition, and Release semantics through the Human path. |
| [Deliver delegated mutation through a verified Release](items/P-0005-deliver-delegated-mutation.md) | `blocked` | P-0004, P-0007 | Bind Agent authority to the proven localized-content path through approval, consequence, and Proof. |
| [Close Milestone 2 with independently verifiable evidence and conformance](items/P-0006-close-milestone-2.md) | `blocked` | P-0005 | Prove repair, abuse resistance, adapter parity, and independent verification. |

## Completed

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Stabilize and qualify the current Release and read-authority baseline](items/P-0001-stabilize-current-baseline.md) | `done` | none | Qualified the Release/read-authority baseline at `1fef16e` and established durable rolling-wave work control. |

## Decisions so far

P-0001 closed baseline qualification; no architecture or product decision item
has closed yet. Existing ratified constraints are linked above; this section
gains one-line results as decision items close.

### Proposed P-0002 profile — awaiting owner review

P-0002 proposes `ObjectLocaleRevisionV1` as a separate append-only rendition of
an existing locale-neutral Object, one `proof.dev/edit/v2`
`object.locale.put` Edit kind, append-only supersession repair, immutable exact
resource intent, and Edition/Release causality tied to the unchanged preview
baseline and exactly one authorized committed ChangeSet. Campaign/subtree
selection resolves to exact Object IDs before grant issuance; no new
`DelegationV2` resource dimension is required. P-0007 would implement and
qualify that foundation through the Human path before P-0005 adds Agent
authority. This is a candidate, not implemented or accepted behavior.

### Proposed P-0003 profile — blocked on P-0002

P-0003 currently proposes local per-Agent Ed25519 proof of possession,
adapter-derived `AuthenticatedActorContextV1`, single-use
`AuthenticatedCommandV1` DSSE presentations, direct Human-to-Agent
`DelegationV2`, `AuthorizationDecisionV2`, a separately rooted authority log of
`AuthorityRecordV1`, and a future P-0006 `AuthorityEvidenceBundleV1`. CLI and
both MCP eras would treat Principal and Delegation identifiers as cross-checks
or selectors rather than authority. This is not a closed decision or an
implementation-status claim; P-0003 is `blocked`, and P-0004/P-0006 remain
blocked.

The candidate is not ready for owner review: P-0002 must first settle the exact
content, Edit, Edition, and Release resource closure. Until then P-0003 is
upstream-blocked, P-0004 exposes no write path, and no item moves to `review`
or `ready`. The qualified candidate is bound by the
[P-0003 receipt](evidence/P-0003/receipt.md).

The controlling proposal is the
[authenticated actor contract](../architecture/authenticated-actor.md); the
project owner has not accepted it.

## Fog — not yet specifiable as implementation

- The collaboration-server decomposition: HTTP surface, PostgreSQL adapter,
  outbox, OIDC, SDKs, and human console. It sharpens only after P-0006.
- Environment configuration update, disablement, and signing-key lifecycle.
- The **Proposed P-0003 profile** names a future
  `AuthorityEvidenceBundleV1`; P-0006 still owns its exact container, supplied
  artifact layout, independent serialization path, disclosure behavior, and
  golden vectors after P-0005.
- Windows identity, protected key storage, crash semantics, and live runtime
  qualification.
- Cross-worktree claim locking, GitHub mirroring, and lifecycle automation
  beyond P-0001's minimal metadata/dependency validator. Add them only when
  concurrent execution demonstrates the need.
- Locale fallback/negotiation, rendition deletion, base-Object replacement,
  relationship localization, generic variants, dynamic campaign/subtree
  selection, migration Edits, and field/path authorization.

## Out of scope for this destination

- Milestone 3 collaboration-server implementation.
- Enterprise OIDC, workload identity, KMS/HSM, high availability, backup, and
  disaster recovery.
- Public release, package publication, push, tag, or license selection.
- Personalization, experimentation, visual page building, DAM transformation,
  and other deliberate product deferrals.

The strongest rejected route is starting Axum, PostgreSQL, or OIDC now. That
would duplicate unresolved authority and evidence semantics in a second adapter
before the local write path satisfies Milestone 2.
