---
id: P-0008
title: Ratify the single-Workspace Milestone 3 collaboration-server contract
status: ready
wave: now
kind: decision
blocked_by: [P-0006]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Ratify the single-Workspace Milestone 3 collaboration-server contract

[Back to the work map](../map.md)

## Outcome

Proof has a decision-complete contract for the smallest single-Workspace
server slice in which remote Humans and an Agent can review, approve, release
to preview, export evidence, and verify it independently while preserving the
accepted local application and domain semantics.

## Why now

P-0006 completed the bounded local Linux Agent-authority loop and fixed the
portable authority/content closure under explicit caller trust. Milestone 3 can
now decide the remote trust, transport, persistence, collaboration, delivery,
and conformance boundaries without duplicating unresolved Milestone 2
semantics inside a server adapter.

The roadmap names HTTP, PostgreSQL, OIDC, collaborative review, an outbox,
SDKs, a human console, and preview delivery. It does not yet determine their
normative boundary or implementation order. This item makes only the first
server slice and its immediate successors sharp.

## Decision questions

- What is the smallest single-Workspace server topology that preserves Proof's
  application contracts and keeps every adapter non-privileged?
- How do remote Human identity, Agent command authentication, transport
  sessions, and application authority remain distinct?
- Which HTTP operations are required for one complete collaborative north-star,
  and how do their input, result, error, idempotency, concurrency, versioning,
  discovery, and limit contracts map to existing application operations?
- What review facts and separation-of-duties rules are authoritative rather
  than UI convention?
- What PostgreSQL transaction and isolation boundary reproduces SQLite's
  authoritative facts, decisions, consequences, idempotency, projections,
  Proofs, and crash behavior?
- How do immutable artifact storage and a transactional outbox compose without
  an exactly-once delivery claim?
- Which untrusted trust/checkpoint references may a remote export carry, and
  which independently obtained caller inputs must verification receive without
  overclaiming latest history?
- Which implementation successor is first, and what evidence makes it
  independently reviewable?

## Authorized scope

- Define one server deployment for one Workspace and multiple Principals.
  Multi-Workspace tenancy remains Milestone 4.
- Specify remote Human OIDC authentication, subject-to-Principal binding,
  token/session boundaries, disablement and revocation, and separation from
  Agent command authentication. Resolve the current local-only assumption that
  direct-Human identity is derived inside the repository adapter.
- Inventory the minimum HTTP surface for the remote north-star and map every
  endpoint to an existing or explicitly versioned application operation.
  Freeze normalized input, stable results and Problems, idempotency,
  concurrency preconditions, protocol versioning, capability discovery,
  correlation, pagination, and size/time limits.
- Define collaborative review semantics. Prove that inspection plus the
  existing digest-bound approval is sufficient or introduce a versioned
  authoritative review fact; comments and UI state cannot invent workflow.
- Define bounded remote policy and Environment configuration administration,
  including authenticated administrator identity, separation of duties,
  versioned transitions, disablement, and portable decision evidence.
- Define PostgreSQL isolation, locking, retry, migration, projection rebuild,
  and one atomic unit of work covering authoritative facts, authority
  presentation consumption and decisions, localized consequences,
  application idempotency, Proof records, projections, and outbox enqueue.
- Define immutable artifact durability and transactional-outbox semantics,
  including retry, deduplication, ordering, poison handling, and the explicit
  rejection of exactly-once delivery claims.
- Define server key roles, untrusted exported trust/checkpoint references,
  independently obtained caller trust and checkpoint inputs, evidence export,
  and clean independent verification.
- Define the minimum preview-Environment delivery boundary without selecting a
  presentation framework.
- Update the threat model and local/server conformance plan.
- Produce dependency-ordered implementation successors only after the project
  owner accepts the decision.

## Explicit non-goals

- No server crate, PostgreSQL Schema, IdP connection, worker, SDK, console,
  preview renderer, provider provisioning, deployment, or production mutation.
- No multi-Workspace tenancy, SCIM/federation, workload identity, SPIFFE,
  KMS/HSM, high availability, backup/restore, multi-region operation, or public
  release.
- No broader content semantics, Delegation chaining, or policy-language
  expansion.
- No claim that P-0006's accepted residuals are silently closed.

## Applicable contracts

- [Core invariants](../../architecture/constitution.md)
- [System architecture](../../architecture/overview.md)
- [Authenticated actor contract](../../architecture/authenticated-actor.md)
- [Proof format and verification](../../architecture/proof-model.md)
- [Threat model](../../architecture/threat-model.md)
- [Testing strategy](../../architecture/testing.md)
- [Roadmap](../../product/roadmap.md)
- [P-0006 closure evidence](../evidence/P-0006/receipt.md)

## Acceptance criteria

- [ ] One exact remote north-star identifies the requesting Human, operating
      Agent, distinct reviewer/approver, publisher, transactions, artifacts,
      responses, and independent verifier inputs.
- [ ] Remote subjects, Principals, bindings, tokens or sessions, and transport
      connections are distinct; untrusted input cannot select identity or
      authority.
- [ ] OIDC issuer, audience, time, and subject validation; binding lifecycle;
      public evidence/redaction; session and CSRF boundaries; and
      disclosure-neutral failures are specified.
- [ ] Every required HTTP operation maps to the shared application contract
      with stable Schemas, Problems, idempotency, concurrency, versioning,
      discovery, and no HTTP-only mutation.
- [ ] Review, approval, policy administration, and separation-of-duties
      semantics are exact and cannot be supplied by UI convention.
- [ ] PostgreSQL transaction, isolation, retry, migration, rebuild, and crash
      behavior preserve the same observable state transitions as SQLite.
- [ ] Artifact and outbox boundaries cannot publish or deliver an effect before
      its authoritative transaction commits; delivery is idempotent without an
      exactly-once claim.
- [ ] Remote evidence export keeps untrusted references separate from
      independently obtained caller trust and checkpoint inputs and does not
      overclaim a globally latest or immediate Release.
- [ ] Every P-0006 residual is classified as a retained Milestone 3 nonclaim,
      required Milestone 3 closure, or later fog item, especially direct-Human
      v2 completeness, Environment and approval chronology, and latest-Release
      completeness.
- [ ] A local/server conformance matrix covers accepted and rejected
      operations, concurrency, crash recovery, OIDC abuse, network boundaries,
      outbox replay, artifact substitution, and independent verification.
- [ ] The threat model covers network attackers, confused deputies, session and
      CSRF attacks, token replay, database/operator tamper, SSRF and webhooks,
      and Workspace isolation.
- [ ] The strongest rejected decomposition and its kill or pivot triggers are
      recorded.
- [ ] The project owner accepts the decision before any implementation
      successor becomes `ready`.
- [ ] Only decision-complete successors are created; SDK, console, deployment,
      and other uncertainty remain in fog.

## Evidence contract

Record the proposed topology, operation and trust matrices, transaction/outbox
contract, local/server conformance plan, threat-model changes, alternatives,
and successor graph in `docs/work/evidence/P-0008/`. Stop at `review` after a
qualified decision candidate. Do not implement or provision the server while
executing this item.

## Completion record

Ready at `2026-08-23T00:34:50.674Z` after project owner `smithdak` accepted
P-0006 candidate `ea35e093daed50017684f7da53373cbb70af753a`, Engineering
evidence `7df66d98b38155f9c6fec1549dbb1c17ebabdb3c`, and its bounded residual
risks. No Milestone 3 implementation, provider choice, deployment, or public
release is claimed by this promotion.

## Residual risks and next-wave update

Keep HTTP/server framework choice, PostgreSQL implementation, OIDC provider,
artifact store, worker/outbox, SDKs, console, and deployment topology in fog
until this decision establishes their exact contracts and dependency order.
