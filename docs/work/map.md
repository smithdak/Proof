# Rolling-wave work map — Milestone 3 collaboration server

## Destination

Milestone 3 delivers a single-Workspace collaboration server through which a
team can review, approve, publish, and verify changes remotely while preserving
the accepted local application and domain semantics. Its exit requires the same
conformance suite to pass against local and server modes.

The bounded local Linux Milestone 2 profile is complete. Project owner
`smithdak` accepted P-0006 candidate `ea35e09`, Engineering evidence `7df66d9`
(initial packet `029f803`), and its documented residual risks at
`2026-08-23T00:34:50.674Z`. The accepted result covers portable authority and
content closure, independent clean-directory verification under explicit
caller trust, and distinct-UID broker containment. It does not qualify a
collaboration server, HTTP/PostgreSQL parity, Windows runtime, deployment, or
public release.

Project owner `smithdak` accepted P-0008 candidate `c461b1b`, bound by
decision evidence `4ac62e9`, at `2026-08-23T17:48:11.461Z`. ADR-0013 is
Accepted. P-0009 remote actor and shared-contract conformance is complete
with candidate `3e38f30`, P-0010 PostgreSQL parity foundation is complete
with candidate `4410b46`, and P-0011 HTTP and OIDC server boundary is the
promoted and claimed Milestone 3 implementation frontier. No
collaboration-server
implementation, provider, deployment, or live remote result is claimed yet.
implementation, provider, deployment, or live remote result is claimed yet.

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
- [The roadmap](../product/roadmap.md) requires local/server semantic parity and
  one complete remote collaboration loop for Milestone 3.
- Environment is a versioned delivery target and current-Release pointer;
  ContextPack is the bounded package supplied to an agent.

## Now

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Implement the HTTP and OIDC server boundary](items/P-0011-http-oidc-server-boundary.md) | `claimed` | P-0010 | Implement the exact nine-route HTTP surface with strict limits and route-qualified registry dispatch, the same-origin confidential OIDC BFF against a deterministic issuer, opaque bounded sessions, the session-bound CSRF synchronizer, dual Human-plus-Agent authentication, and the owned identity, role, approval, and Environment configuration Human operations through the P-0010 unit of work, with the retained abuse matrix. |

## Next

Only P-0011 is promoted. The accepted contract names the remaining
successors — artifact/outbox/private preview, and remote evidence and
Milestone 3 qualification — but neither is created or promoted before
P-0011 closes. No worker, SDK, console, provider, or deployment work
becomes claimable before that closure.

The item frontmatter is authoritative; the status and blocker columns below are
derived. Any mismatch blocks claiming until both are repaired together.

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| None | n/a | n/a | P-0011 is the promoted successor; later successors are named by the accepted contract but not yet created. |

## Completed

| Work item | Status | Blocked by | Outcome |
| --- | --- | --- | --- |
| [Stabilize and qualify the current Release and read-authority baseline](items/P-0001-stabilize-current-baseline.md) | `done` | none | Qualified the Release/read-authority baseline at `1fef16e` and established durable rolling-wave work control. |
| [Ratify the Milestone 2 delegated content contract](items/P-0002-ratify-delegated-content-contract.md) | `done` | P-0001 | Ratified exact-locale renditions, append-only repair, immutable resource intent, and causally closed Edition/Release semantics. |
| [Ratify authenticated actor and Delegation semantics](items/P-0003-ratify-authenticated-actor.md) | `done` | P-0001, P-0002 | Ratified the bounded local authenticated-actor, direct Delegation, and current-authorization retry contract. |
| [Implement the authenticated authorization kernel](items/P-0004-implement-authorization-kernel.md) | `done` | P-0003 | Bind authenticated actors to Principals and produce exact delegated decisions. |
| [Deliver delegated mutation through a verified Release](items/P-0005-deliver-delegated-mutation.md) | `done` | P-0004, P-0007 | Bind Agent authority to the proven localized-content path through approval, consequence, and Proof. |
| [Close Milestone 2 with independently verifiable evidence and conformance](items/P-0006-close-milestone-2.md) | `done` | P-0005 | Qualified and accepted the bounded local Linux Agent loop, portable closure, independent verifier, and distinct-UID containment. |
| [Implement the localized content foundation](items/P-0007-implement-localized-content-foundation.md) | `done` | P-0002 | Prove exact-locale revision, repair, Edition, and Release semantics through the Human path. |
| [Ratify the single-Workspace Milestone 3 collaboration-server contract](items/P-0008-ratify-collaboration-server-contract.md) | `done` | P-0006 | Ratified the exact remote identity, HTTP/application parity, PostgreSQL transaction, review, outbox, evidence, and conformance contract; ADR-0013 Accepted; P-0009 promoted. |
| [Implement the remote actor and shared-contract conformance foundation](items/P-0009-remote-actor-shared-contract-conformance.md) | `done` | P-0008 | Implemented the remote authority payloads and envelopes, subject commitments, actor-context evidence redaction, causal approval and Environment configuration closures, the closed registries with frozen hashes, and the deterministic semantic oracle; P-0010 promoted. |
| [Implement the PostgreSQL parity foundation](items/P-0010-postgresql-parity-foundation.md) | `done` | P-0009 | Implemented the checksummed migration ledger, the serializable Workspace write-lane unit of work with keyed idempotency and the savepoint rule, bounded retry and ambiguous-commit reconciliation, the artifact catalog with atomic signed-byte storage, outbox enqueue, projection generation swaps, the verified SQLite-to-PostgreSQL import, and byte-identical SQLite/PostgreSQL oracle traces; P-0011 promoted. |

P-0007 replacement candidate `4715314` passed the independent G1-G14 gate and
is accepted as `done` through Assurance record `29ad9d9`. Historical
unsupported candidates `fede487` and `c4b312d` remain unsupported and are not
relabeled by completion. P-0004 candidate `8788847`, bound through Engineering
evidence `e6843ad`, passed the bounded local authorization-kernel gate and is
`done` under `review_gate: none`. P-0005 candidate `c6f6ca8`, bound through
Engineering evidence `03fd4ea`, passed the bounded delegated-mutation gate and
is `done` under `review_gate: none`. P-0006 candidate `ea35e09`, bound by
Engineering evidence `7df66d9` (initial packet `029f803`), passed the complete
Linux gate and was accepted with its bounded residual risks by project owner
`smithdak` at `2026-08-23T00:34:50.674Z`; Milestone 2 is complete.

## Decisions so far

P-0001 closed baseline qualification. P-0002 and P-0003 are closed product and
architecture decisions. P-0008 candidate `c461b1b`, bound by decision evidence
`4ac62e9`, was accepted by project owner `smithdak` at
`2026-08-23T17:48:11.461Z`; ADR-0013 is Accepted and the first dependency-ordered
implementation successor is promoted. Later accepted decision results
accumulate here.

### Ratified P-0002 profile

P-0002 defines `ObjectLocaleRevisionV1` as a separate append-only rendition of
an existing locale-neutral Object, one `proof.dev/edit/v2`
`object.locale.put` Edit kind, append-only supersession repair, immutable exact
resource intent, and Edition/Release causality tied to the unchanged preview
baseline and exactly one authorized committed ChangeSet. Campaign/subtree
selection resolves to exact Object IDs before grant issuance; no new
`DelegationV2` resource dimension is required. P-0007 implements and qualifies
that foundation through the Human path. P-0004 implements authenticated Agent
reads, P-0005 implements delegated localized mutation, and P-0006 independently
verifies the accepted portable Milestone 2 closure.

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
accepted independent bundle/verifier and containment qualification.

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

### Accepted P-0006 Milestone 2 closure

P-0006 implements `AuthorityEvidenceBundleV1`, storage v14 presentation
persistence, a producer-independent `proof-verifier`, frozen Complete,
Incomplete, and Invalid vectors, application/CLI/modern-MCP/legacy-MCP
north-star parity, and Linux distinct-UID signer/verifier containment. The
accepted checkpoint proves the supplied authority prefix under explicit caller
trust; it does not prove a globally latest or true immediate same-Environment
Release. Environment-creation chronology, v2 approval causal-head ambiguity,
same-UID hostile-process isolation, Windows containment, and server/deployment
claims remain outside the bounded result.

## Fog — not yet specifiable as implementation

- P-0011 owns the HTTP and OIDC server boundary. The accepted contract names
  the remaining successors — artifact/outbox/private preview, and remote
  evidence qualification — but their items, framework, provider, and
  deployment choices remain uncreated until P-0011 closes and the next is
  promoted.
- Environment configuration update, disablement, and signing-key lifecycle.
- P-0006 hardening beyond the accepted claim: global-latest Release
  transparency, chronology-bearing Environment and approval successors,
  complete direct-Human v2 evidence, exhaustive behavioral finding coverage,
  and stronger same-UID or Windows containment.
- Windows identity, protected key storage, crash semantics, and live runtime
  qualification.
- Cross-worktree claim locking, GitHub mirroring, and lifecycle automation
  beyond P-0001's minimal metadata/dependency validator. Add them only when
  concurrent execution demonstrates the need.
- Locale fallback/negotiation, rendition deletion, base-Object replacement,
  relationship localization, generic variants, dynamic campaign/subtree
  selection, migration Edits, and field/path authorization.

## Out of scope for this destination

- Milestone 3 successors beyond the promoted P-0011 before it closes.
- Enterprise federation/provisioning and SCIM, workload identity, KMS/HSM,
  high availability, backup, and disaster recovery.
- Public release, package publication, push, tag, or license selection.
- Personalization, experimentation, visual page building, DAM transformation,
  and other deliberate product deferrals.

The strongest rejected route is starting Axum, SQLx/PostgreSQL, an IdP, or a
web console before P-0009's remote actor and semantic-oracle foundation
closes. That would freeze transport, identity, transaction, and collaboration
implementations before the shared local/server conformance boundary exists.
