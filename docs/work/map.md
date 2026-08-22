# Rolling-wave work map — Milestone 2 agent authority

## Destination

Milestone 2 is complete when an adapter-authenticated local actor bound to an
Agent Principal can execute Proof's complete content-change and Release loop
under bounded Delegation and a task-specific ContextPack, with human approval,
independently verifiable evidence, structured repair, and no privileged
interface.

P-0005 candidate `c6f6ca8` and Engineering evidence `03fd4ea` are the clean,
qualified delegated-mutation baseline for P-0006 portable verification and
Milestone 2 closure. P-0006 candidate `ea35e09`, bound by Engineering evidence
`7df66d9` (initial packet `029f803`), is engineering-qualified and awaiting
project-owner review. Milestone 2 is not complete. Collaboration-server and
enterprise deployment work begin
only after the project owner accepts the Milestone 2 exit evidence and residual
risks.

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
| [Close Milestone 2 with independently verifiable evidence and conformance](items/P-0006-close-milestone-2.md) | `review` | P-0005 | Review engineering-qualified repair, abuse-resistance, adapter-parity, portable-closure, containment, and independent-verification evidence. |

## Next

No later item is promoted. P-0006 remains the sole active frontier while its
engineering-qualified candidate awaits project-owner disposition. Milestone 3
remains in fog until P-0006 completes the independently verifiable exit and
exposes the next decision boundary.

The item frontmatter is authoritative; the status and blocker columns below are
derived. Any mismatch blocks claiming until both are repaired together.

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| None | n/a | n/a | No successor is promoted while P-0006 is in project-owner review. |

## Completed

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Stabilize and qualify the current Release and read-authority baseline](items/P-0001-stabilize-current-baseline.md) | `done` | none | Qualified the Release/read-authority baseline at `1fef16e` and established durable rolling-wave work control. |
| [Ratify the Milestone 2 delegated content contract](items/P-0002-ratify-delegated-content-contract.md) | `done` | P-0001 | Ratified exact-locale renditions, append-only repair, immutable resource intent, and causally closed Edition/Release semantics. |
| [Ratify authenticated actor and Delegation semantics](items/P-0003-ratify-authenticated-actor.md) | `done` | P-0001, P-0002 | Ratified the bounded local authenticated-actor, direct Delegation, and current-authorization retry contract. |
| [Implement the authenticated authorization kernel](items/P-0004-implement-authorization-kernel.md) | `done` | P-0003 | Bind authenticated actors to Principals and produce exact delegated decisions. |
| [Deliver delegated mutation through a verified Release](items/P-0005-deliver-delegated-mutation.md) | `done` | P-0004, P-0007 | Bind Agent authority to the proven localized-content path through approval, consequence, and Proof. |
| [Implement the localized content foundation](items/P-0007-implement-localized-content-foundation.md) | `done` | P-0002 | Prove exact-locale revision, repair, Edition, and Release semantics through the Human path. |

P-0007 replacement candidate `4715314` passed the independent G1-G14 gate and
is accepted as `done` through Assurance record `29ad9d9`. Historical
unsupported candidates `fede487` and `c4b312d` remain unsupported and are not
relabeled by completion. P-0004 candidate `8788847`, bound through Engineering
evidence `e6843ad`, passed the bounded local authorization-kernel gate and is
`done` under `review_gate: none`. P-0005 candidate `c6f6ca8`, bound through
Engineering evidence `03fd4ea`, passed the bounded delegated-mutation gate and
is `done` under `review_gate: none`; P-0006 candidate `ea35e09`, bound by
Engineering evidence `7df66d9` (initial packet `029f803`), is the Milestone 2
closure frontier awaiting project-owner review.

## Decisions so far

P-0001 closed baseline qualification. P-0002 and P-0003 are closed product and
architecture decisions; later decision results accumulate here.

### Ratified P-0002 profile

P-0002 defines `ObjectLocaleRevisionV1` as a separate append-only rendition of
an existing locale-neutral Object, one `proof.dev/edit/v2`
`object.locale.put` Edit kind, append-only supersession repair, immutable exact
resource intent, and Edition/Release causality tied to the unchanged preview
baseline and exactly one authorized committed ChangeSet. Campaign/subtree
selection resolves to exact Object IDs before grant issuance; no new
`DelegationV2` resource dimension is required. P-0007 implements and qualifies
that foundation through the Human path. P-0004 implements authenticated Agent
reads, P-0005 implements delegated localized mutation, and the P-0006 candidate
under review verifies the portable Milestone 2 closure.

### Ratified P-0003 profile

P-0003 defines local per-Agent Ed25519 proof of possession,
adapter-derived `AuthenticatedActorContextV1`, single-use
`AuthenticatedCommandV1` DSSE presentations, direct Human-to-Agent
`DelegationV2`, `AuthorizationDecisionV2`, a separately rooted authority log of
`AuthorityRecordV1`, and a P-0006-selected `AuthorityEvidenceBundleV1`. CLI and
both MCP eras treat Principal and Delegation identifiers as cross-checks or
selectors rather than authority. This is accepted architecture, not an
implementation-status claim by itself. P-0004 implements its bounded local read
profile, P-0005 implements the 11 localized v2 operations, and P-0006 has an
engineering-qualified candidate under project-owner review.

Candidate `38999d0` was qualified and accepted by project owner `smithdak` at
`2026-08-20T19:52:12.756Z`. It aligns
the exact locale Schema, closes the 14-pair operation registry, freezes the
localized resource and budget projections, and regenerates the affected
conformance vectors. P-0004 later enabled the three authenticated v1 reads;
P-0005 now enables the 11 localized mutation rows. The exact P-0003 candidate,
acceptance, and falsification record are bound by the
[P-0003 receipt](evidence/P-0003/receipt.md).

The controlling contract is the
[authenticated actor contract](../architecture/authenticated-actor.md).

## Fog — not yet specifiable as implementation

- The collaboration-server decomposition: HTTP surface, PostgreSQL adapter,
  outbox, OIDC, SDKs, and human console. It sharpens only after P-0006.
- Environment configuration update, disablement, and signing-key lifecycle.
- The **Ratified P-0003 profile** names an `AuthorityEvidenceBundleV1`; P-0006
  candidate `ea35e09` selects and implements its exact container, supplied
  artifact layout, independent serialization path, disclosure behavior, and
  golden vectors. That selection remains unratified until project-owner
  acceptance.
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
