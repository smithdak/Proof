---
id: P-0009
title: Implement the remote actor and shared-contract conformance foundation
status: done
wave: now
kind: implementation
blocked_by: [P-0008]
claimed_by: deepseek:proof:p-0009
claimed_at: 2026-08-23T17:52:39.023Z
base_sha: 40b79a50dbff88efca40ee6c64c47e2f4d8d46a4
review_gate: none
accepted_by: null
accepted_at: null
required_reading: []
allowed_paths: []
---

# Implement the remote actor and shared-contract conformance foundation

[Back to the work map](../map.md)

## Outcome

Proof has a deterministic, storage-backed remote actor and shared-contract
conformance foundation. Every versioned remote authority payload, actor context
and public evidence redaction, OIDC subject commitment, causal approval and
Environment configuration closure, Workspace role fact, and remote
authorization decision and application consequence can be constructed,
canonicalized, signed, verified, chain-validated, and replayed against a
deterministic local/server semantic oracle, with frozen executable conformance
vectors — without any HTTP server, OIDC provider, or PostgreSQL dependency.

## Why now

P-0008 is project-owner accepted and names this item as the first
dependency-ordered successor. Every later Milestone 3 adapter (PostgreSQL
parity, HTTP/OIDC boundary, artifact/outbox/preview, remote evidence
qualification) consumes the versioned remote types, registries, and oracle
boundary defined here. Implementing those adapters first would freeze transport
and persistence choices before the shared identity, authority, and conformance
semantics exist.

## Promotion condition

Satisfied by completed P-0008 candidate
`c461b1b60bece277b88c6a5aee55c200658ab327`, bound by Engineering evidence
`4ac62e9e2c42d7a586785095b58f060648975649`, accepted by project owner
`smithdak` at `2026-08-23T17:48:11.461Z`. The accepted
[collaboration-server contract](../../architecture/collaboration-server.md)
and [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
are the implementation authority. The retained P-0008 conformance Schemas and
vectors under `conformance/v1/collaboration-server/` are executable
specifications; their bytes and frozen registry hashes do not change.

## Authorized scope

- Implement the closed `RemoteAuthorityRecordV1` successor payload union and
  its one-signature Ed25519 DSSE envelope: agent-binding issue/revoke,
  delegation issue/revoke, OIDC-binding issue/revoke, Workspace-role
  assignment/revocation, `PrincipalStatusV2` recorded status, causal
  `ChangeSetApprovalV1`, `EnvironmentCreationV1`,
  `EnvironmentConfigProposalV1`, and `EnvironmentConfigActivationV1`. Enforce
  strict RFC 8785 canonical decode, causal sequence/predecessor/head
  coherence, single active Workspace authority-key signer resolution, exact
  `proof:remote-authority-record:v1` and
  `proof:remote-authority-record-envelope:v1` digest contexts, and the
  65,536-byte payload and 98,304-byte envelope maxima.
- Implement `RemoteAuthorizationDecisionV1` and
  `RemoteApplicationConsequenceV1` construction, digest, and validation with
  the exact requested-resources, policy-selection, operation-effect, and
  application-problem digest preimages and contexts from the accepted
  contract. `RemoteApplicationConsequenceV1` copies its decision's Workspace,
  operation, complete operation-registry selector, public input-projection
  digest, evaluated head, and typed application key.
- Implement the OIDC subject commitment machinery: the exact
  `proof.dev/oidc-subject-commitment-input/v1` preimage
  `{api_version, blind, subject, workspace_id}` with a uniformly random
  32-byte blind in base64url-without-padding, the
  `proof:oidc-authenticated-subject-commitment:v1` derive-key context, the
  protected opening and private lookup types, `OidcIssuerConfigurationV1`
  with `proof:oidc-issuer-configuration:v1` and
  `proof:oidc-discovery-metadata:v1` digests, the public commitment-only
  `OidcPrincipalBindingV1`, `RemoteAuthenticationEventV1`, and the protected
  exact normalized-input digest under `proof:remote-normalized-operation-input:v1`
  versus the public projection under `proof:public-operation-input-projection:v1`.
- Implement `AuthenticatedActorContextV2` (protected) and
  `AuthenticatedActorContextEvidenceV2` (public commitment-only redaction)
  for both closed profiles
  `proof.server/authentication/oidc-human/v1` and
  `proof.server/authentication/oidc-human-agent/v1`. Public evidence never
  carries a raw issuer/subject, token, opening, or protected input digest.
- Implement `ChangeSetApprovalV1` with its complete closure binding list and
  the prohibited-approver checks (Agent, disabled/unbound Human, ChangeSet
  requester, contributing Agent, active configuration activator, incomplete
  or stale closure, changed validation head, inactive role).
- Implement `EnvironmentCreationV1`, `EnvironmentConfigProposalV1`, and
  `EnvironmentConfigActivationV1` plus the assembled immutable
  `EnvironmentConfigV2` closure with every cross-check (Workspace/Environment
  agreement, chronology, predecessor, proposal digest equality, copied
  creation fields, distinct proposer and activator) and the
  `proof:environment-config:v2` digests.
- Implement the closed operation registries: the ordered 23-row Human
  registry, the 14-pair Agent projection, the nine-route HTTP surface
  metadata, per-row authorization rules and sorted `roles_any_of` sets,
  route-qualified lookup, effect-digest rules, and consequence-outcome
  classification. Recompute byte-exactly the three frozen commitments from
  the retained registry bytes — accepted Agent authority registry SHA-256
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`,
  non-circular remote authorization projection SHA-256
  `e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b`, and
  complete HTTP operation registry SHA-256
  `e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf` — and
  fail closed on any mismatch.
- Implement the deterministic local/server semantic oracle: a reference
  evaluator that runs the shared application operations (the 14 Agent rows
  and the shared Human rows) against the existing SQLite-backed local
  application path and produces typed, replayable traces binding normalized
  input digest, evaluated authority head, application outcome
  (typed result or stable Problem), and consequence digest. Repeated
  execution of the same trace inputs produces byte-identical traces;
  mutated inputs produce the contracted consequence class. Include
  deterministic identity fixtures (issuer configuration, enrollment
  challenges, bindings) with no live provider.
- Extend `conformance/v1/collaboration-server/` with executable vectors for
  every new construction and rejection mutation exercised by the retained
  test harness; keep every existing vector byte-identical.
- Register new workspace crates or modules through the existing
  `proof-domain`/`proof-application`/`proof-local` boundary discipline; no
  new third-party dependency beyond workspace-pinned primitives.

## Explicit non-goals

- No HTTP server, listener, route handler, session store, cookie, CSRF, or
  BFF implementation.
- No PostgreSQL connection, migration, or adapter code.
- No live OIDC provider interaction, network egress, or real IdP discovery.
- No outbox worker, lease, delivery, artifact-store port implementation, or
  preview materialization.
- No evidence export changes to `AuthorityEvidenceBundleV1` or the
  `proof-verifier`; P-0006 evidence and historical v1/v2 bytes are not
  reinterpreted.
- No new user-facing CLI or MCP surface beyond what the oracle and conformance
  tests require internally.
- No successor promotion: PostgreSQL parity, HTTP/OIDC boundary,
  artifact/outbox/preview, and remote evidence qualification stay fog until
  this item closes.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md)
- [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
- [Core invariants](../../architecture/constitution.md)
- [Authenticated actor contract](../../architecture/authenticated-actor.md)
- [Proof format and verification](../../architecture/proof-model.md)
- [P-0008 acceptance evidence](../evidence/P-0008/receipt.md)

## Acceptance criteria

- [x] The closed `RemoteAuthorityRecordV1` union constructs, canonicalizes,
      signs, verifies, and rejects tamper under the exact v1 digest contexts,
      limits, and strict-JSON rules.
- [x] Causal chain validation enforces sequence, predecessor, head, and
      single-active-key signer coherence and rejects fork or reorder
      mutations.
- [x] OIDC subject commitment machinery reproduces the retained vectors
      byte-exactly; public evidence contains no raw issuer/subject, opening,
      or protected input digest.
- [x] Both `AuthenticatedActorContextV2` profiles and their
      `AuthenticatedActorContextEvidenceV2` redactions construct and reject
      substitution.
- [x] `ChangeSetApprovalV1` binds its complete closure and rejects every
      prohibited approver and stale closure case.
- [x] Environment creation/proposal/activation and the assembled
      `EnvironmentConfigV2` enforce every cross-check, including distinct
      proposer/activator and exact predecessor/proposal digests.
- [x] The three frozen registry SHA-256s recompute identically from committed
      registry bytes; route-qualified lookup, per-row authorization rules,
      and effect-digest rules match the accepted contract row-for-row.
- [x] The deterministic oracle reproduces byte-identical traces for shared
      operations across repeated execution; mutated inputs land in the
      contracted consequence class without executing an HTTP or database
      adapter.
- [x] Conformance vectors and rejection mutations are executable in the
      workspace gate; no server, provider, database, or runtime-parity claim
      is introduced.
- [x] The full Linux quality gate passes and durable Engineering evidence
      (receipt, manifest, traceability) binds the item-work commit.

## Evidence contract

Record the qualified implementation candidate, crate/module inventory, frozen
hash recomputation results, oracle trace examples, rejection coverage, exact
command results, and residual boundaries in `docs/work/evidence/P-0009/`.
Produce `receipt.md`, `manifest.json`, and a criterion-level traceability
matrix binding every acceptance criterion to retained tests and vectors.

## Completion record

Ready at `2026-08-23T17:48:11.461Z` after project owner `smithdak` accepted
P-0008 candidate `c461b1b60bece277b88c6a5aee55c200658ab327`, Engineering
evidence `4ac62e9e2c42d7a586785095b58f060648975649`, and its bounded residual
risks.

Claimed by `deepseek:proof:p-0009` at `2026-08-23T17:52:39.023Z` from
P-0008 acceptance commit `40b79a50dbff88efca40ee6c64c47e2f4d8d46a4`
on `proof-architecture/p-0008-collaboration-server-contract`.

Engineering qualified immutable candidate
`3e38f30b95086162816360e68ca9917cf0d06d9b`, whose parent is the skeleton
commit `b14b22cc9bd898565f5349f0d231d684fdfd26f8`, qualified at
`2026-08-23T19:17:42.097Z`. Engineering evidence commit
`89e74c381c5cd486cbfab3762c85ba0fad258e3f` binds the
[receipt](../evidence/P-0009/receipt.md),
[manifest](../evidence/P-0009/manifest.json), and
[AC1-AC10 traceability matrix](../evidence/P-0009/traceability.md). Moved
from `claimed` to `review` at `2026-08-23T19:19:56.856Z` under
`review_gate: none`, then to `done` at `2026-08-23T19:21:12.000Z` after the
complete Linux gate recorded in the receipt. Successor P-0010 PostgreSQL
parity foundation is promoted to `ready`; no HTTP, OIDC, worker, preview, or
deployment work is claimed by this completion.
