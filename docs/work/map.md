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
- HEAD: `3373f3768a4e07a0e5680d88cb7fe4b2c2848f0d`.
- The local `origin/main` tracking ref is `9f69e80`; the branch is one commit
  ahead. This is not a live remote verification.
- The Release, attestation, Environment, Principal, Delegation, ContextPack,
  projection-rebuild, CLI, and MCP slice is qualified in the item-work commit
  containing P-0001's review record. The follow-up control-plane commit binds
  its exact SHA without self-reference.
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
| [Stabilize and qualify the current Release and read-authority baseline](items/P-0001-stabilize-current-baseline.md) | `review` | none | Bind the qualified baseline commit in one follow-up control-plane record. |

## Next

These items are durable but not claimable until their blockers close. Each must
be re-read and reshaped before promotion to `ready`.

The item frontmatter is authoritative; the status and blocker columns below are
derived. Any mismatch blocks claiming until both are repaired together.

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Ratify the Milestone 2 delegated content contract](items/P-0002-ratify-delegated-content-contract.md) | `blocked` | P-0001 | Decide the minimum content semantics that make the north-star scenario true. |
| [Ratify authenticated actor and Delegation semantics](items/P-0003-ratify-authenticated-actor.md) | `blocked` | P-0001 | Fix the local credential, subject-binding, Delegation, and anti-replay contract. |
| [Implement the authenticated authorization kernel](items/P-0004-implement-authorization-kernel.md) | `blocked` | P-0003 | Bind authenticated actors to Principals and produce exact delegated decisions. |
| [Deliver delegated mutation through a verified Release](items/P-0005-deliver-delegated-mutation.md) | `blocked` | P-0002, P-0004 | Complete one bounded write path through human approval, consequence, and Proof. |
| [Close Milestone 2 with independently verifiable evidence and conformance](items/P-0006-close-milestone-2.md) | `blocked` | P-0005 | Prove repair, abuse resistance, adapter parity, and independent verification. |

## Decisions so far

No work-map decision has closed yet. Existing ratified constraints are linked
above; this section gains one-line results as decision items close.

## Fog — not yet specifiable as implementation

- The collaboration-server decomposition: HTTP surface, PostgreSQL adapter,
  outbox, OIDC, SDKs, and human console. It sharpens only after P-0006.
- Environment configuration update, disablement, and signing-key lifecycle.
- The offline-verification representation selected after P-0003/P-0005:
  embedded evidence, supplied artifacts, separate signatures, a manifest,
  bundling, or another ratified form.
- Windows identity, protected key storage, crash semantics, and live runtime
  qualification.
- Cross-worktree claim locking, GitHub mirroring, and lifecycle automation
  beyond P-0001's minimal metadata/dependency validator. Add them only when
  concurrent execution demonstrates the need.

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
