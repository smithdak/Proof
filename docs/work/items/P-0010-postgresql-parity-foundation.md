---
id: P-0010
title: Implement the PostgreSQL parity foundation
status: ready
wave: now
kind: implementation
blocked_by: [P-0009]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the PostgreSQL parity foundation

[Back to the work map](../map.md)

## Outcome

Proof has a durable PostgreSQL adapter that reproduces the accepted SQLite
observable semantics for the shared application operations: an immutable
checksummed migration ledger, the serializable Workspace write-lane
authoritative transaction with the exact twelve-step algorithm, keyed
idempotency with replay and conflict semantics, the savepoint rule,
full-transaction retry and ambiguous-commit reconciliation, projection
generation swaps, an artifact catalog with fork-capable signed bytes stored
atomically in PostgreSQL, one logical outbox enqueue per committed external
effect, and a verified SQLite-to-PostgreSQL import. The P-0009
`RemoteSemanticOracle` runs the same shared operations against both backends
and produces byte-identical traces for accepted, rejected, replay, and
conflict scenarios.

## Why now

P-0009 delivered the remote actor contracts and the deterministic
local/server semantic oracle with the SQLite-backed reference path. The
accepted contract names this item as the second dependency-ordered
successor. The HTTP boundary, outbox worker, and preview delivery consume
this persistence foundation, and building them first would freeze transport
and delivery semantics before the authoritative unit of work exists.

## Promotion condition

Satisfied by completed P-0009 candidate
`3e38f30b95086162816360e68ca9917cf0d06d9b`, bound by Engineering evidence
commit `89e74c381c5cd486cbfab3762c85ba0fad258e3f`, per the accepted
[collaboration-server
contract](../../architecture/collaboration-server.md) successor order.
ADR-0013 remains the implementation authority.

## Authorized scope

- Create a `proof-pg` workspace crate using the synchronous rust-postgres
  driver (selected baseline: blocking semantics match the single-writer
  contract, no async runtime is introduced; the HTTP successor may revisit
  runtime composition without changing storage semantics). No ORM.
- Implement the immutable migration ledger: monotonic version, name, and
  domain-separated BLAKE3-256 digest per exact script bytes; one fixed
  advisory-lock key plus a singleton migration-head row; per-phase status
  (`started`, `verified`, `failed`); expand, backfill, verify, cutover, and
  contract phases; transactional DDL plus resumable nontransactional phases;
  refusal to write outside the compatibility interval, on checksum mismatch,
  dirty phase, or unknown newer version. No request-time auto-migration.
- Implement the authoritative unit of work exactly per the accepted
  contract: `SERIALIZABLE READ WRITE`; lock the single durable
  `workspace_write_head` row with `SELECT ... FOR UPDATE`; allocate
  transaction, authority, content, and Release sequences from the locked row
  (PostgreSQL sequences, `SERIAL`, and `BIGSERIAL` are forbidden); verify
  authentication before idempotency lookup or prior-result disclosure;
  evaluate current authorization at the locked head; keyed same-input replay
  appends the fresh decision and replay record and discloses the prior
  committed result without duplicating the governed fact, key, or outbox
  event; same-key changed input commits a signed decision and
  idempotency-conflict consequence without a governed effect; no-key rows
  skip stored-result lookup; precondition conflicts commit presentation
  consumption plus signed decision and failure consequence; a savepoint
  bounds the governed application consequence; an ordinary authorized
  application failure rolls back to the savepoint and commits only
  presentation consumption, decision, and failure-consequence bodies;
  infrastructure, signing, artifact, storage, or integrity failure rolls
  back the complete transaction; nothing returns before commit success.
  Enforce logged durable tables with `synchronous_commit=on`, `fsync=on`,
  `full_page_writes=on` as documented contract preconditions; no `UNLOGGED`
  authoritative tables.
- Implement bounded retry: full-transaction retry on SQLSTATE `40001` and,
  from the beginning only, `40P01`; `23505` retryable only for a named
  internal allocation constraint; at most three attempts within the
  30-second deadline with bounded jitter; reuse normalized input,
  server-preallocated identifiers, correlation identity, semantic times, and
  the application key only for keyed rows; no external call inside the
  retried transaction. Implement the ambiguous-commit contract: unknown
  outcome returns retryable `proof.operation.unknown_outcome`; reconciliation
  is a separate keyed attempt with equivalent input and fresh
  authentication/authorization.
- Implement the artifact catalog and durability boundary: canonical
  `artifacts/{artifact_kind}/blake3/{digest}` keys; kind, canonical bytes,
  digest, media type, Schema version, and length form the identity;
  `put_if_absent` plus read-after-write for the external storage port with a
  filesystem-backed reference implementation; only authority-neutral blobs
  may be staged before the transaction in an unreachable namespace;
  fork-capable signed authority, decision, consequence, approval,
  configuration, Release Proof, and checkpoint bytes are generated with
  already-loaded process-local keys and inserted into an immutable logged
  PostgreSQL artifact-body table in the same transaction as their catalog
  row and state transition; a committed reference has either a verified
  pre-staged neutral blob or atomically committed PostgreSQL bytes; every
  read revalidates kind, length, and digest.
- Implement transactional-outbox enqueue only: immutable enqueue record with
  event ID, Workspace transaction sequence and ordinal, event type/version,
  stable ordering key and stream sequence, effect identity, canonical
  payload digest or artifact reference, destination/configuration version,
  correlation/causation identities, and committed creation time; uniqueness
  keys `{workspace_id, effect_digest, event_type, event_version,
  destination_configuration_digest}` and `{workspace_id,
  workspace_transaction_sequence, ordinal}`; exactly one enqueue per
  committed consequence and destination. No worker, lease, claim,
  acknowledgement, or delivery state yet.
- Implement projection rebuild: serializable write transaction under the
  Workspace head lock; verify authority/content/Release chains and capture
  exact heads; rebuild derived rows into a new generation; compare
  identities, counts, foreign keys, versions, sequences, and state digest;
  atomically swap one active-generation pointer; no partial generation on
  dry run, crash, or mismatch; facts, authority records, idempotency,
  artifact catalog, outbox events, attempts, and receipts are never
  regenerated or deleted.
- Implement the SQLite-to-PostgreSQL import: consume verified canonical
  facts and artifacts only; reconstruct all chains; rebuild projections;
  compare authority heads and Known State; open network writes only after an
  atomic cutover; copying unverified SQLite rows is not sufficient.
- Generalize the P-0009 `RemoteSemanticOracle` behind a storage-backend
  boundary with two implementations — the retained SQLite reference path and
  the new PostgreSQL path — so one shared conformance runner produces
  byte-identical `OracleTraceV1` results for the 14 shared Agent rows and
  the shared Human rows across accepted, rejected, idempotent-replay, and
  precondition-conflict scenarios.
- Wire CI: add the PostgreSQL service to the Linux gate with an exact
  `PROOF_PG_DSN` environment variable; locally, tests use
  `scripts/dev-pg.sh` plus the same DSN default. A test that cannot connect
  fails with an actionable message, never silently passes.
- Update the conformance plan, threat model notes, and CHANGELOG only for
  what this item actually delivers.

## Explicit non-goals

- No HTTP server, route, session, cookie, CSRF, or BFF code.
- No OIDC provider interaction or network egress.
- No outbox worker, lease, claim, retry backoff, dead-letter, replay, or
  abandonment execution; the enqueue record is delivered, the worker is not.
- No preview materialization or delivery adapter.
- No evidence export changes to `AuthorityEvidenceBundleV1`/`proof-verifier`
  and no remote evidence bundle v2 runtime.
- No high availability, backup/restore, multi-region ordering, KMS/HSM,
  workload identity, or tenancy work.
- No successor promotion: HTTP/OIDC boundary, artifact/outbox/preview, and
  remote evidence qualification stay fog until this item closes.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md):
  PostgreSQL authoritative unit of work, retry and ambiguous commit,
  migration and projection rebuild, immutable artifact boundary,
  transactional outbox, and successor order sections.
- [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
- [Core invariants](../../architecture/constitution.md)
- [P-0009 evidence](../evidence/P-0009/receipt.md)

## Acceptance criteria

- [ ] The migration ledger performs the expand/backfill/verify/cutover
      contract with checksummed immutable scripts, a singleton migrator, and
      fail-closed checksum/version/dirty-phase refusal.
- [ ] The authoritative transaction implements all twelve contract steps
      under `SERIALIZABLE` with the locked write head and row-derived causal
      sequences; no PostgreSQL sequence drives causal order.
- [ ] Keyed idempotency replays the prior result without duplicating the
      governed fact, key, or outbox event; same-key changed input commits a
      conflict consequence; no-key rows are fresh authenticated attempts.
- [ ] The savepoint rule commits exactly presentation consumption, decision,
      and failure-consequence bodies on an authorized application failure,
      and rolls back everything on infrastructure failure.
- [ ] Bounded retry and ambiguous-commit reconciliation match the contract,
      including no external calls inside the retried transaction.
- [ ] Artifact identity, `put_if_absent`, read-after-write, staged-neutral
      invisibility before commit, and atomic PostgreSQL storage of
      fork-capable signed bytes all hold under test.
- [ ] Outbox enqueue records one logical event per committed consequence and
      destination with both uniqueness keys; no delivery behavior is
      claimed.
- [ ] Projection rebuild swaps one verified generation atomically and never
      regenerates facts, idempotency, artifacts, or outbox history.
- [ ] The SQLite-to-PostgreSQL import reconstructs chains from verified
      canonical facts, rebuilds projections, compares authority heads and
      Known State, and cuts over atomically.
- [ ] The shared oracle runner produces byte-identical traces on both
      backends for accepted, rejected, replay, and conflict scenarios, and
      CI plus the local dev instance both execute the PostgreSQL tests.
- [ ] The full Linux quality gate passes and durable Engineering evidence
      (receipt, manifest, traceability) binds the item-work commit.

## Evidence contract

Record the qualified implementation candidate, crate/module inventory,
migration and transaction conformance vectors, oracle parity trace digests,
import results, exact command results, environment (including the PostgreSQL
version used), and residual boundaries in `docs/work/evidence/P-0010/`.
Produce `receipt.md`, `manifest.json`, and a criterion-level traceability
matrix.

## Completion record

Ready at `2026-08-23T19:21:12.000Z` after P-0009 candidate
`3e38f30b95086162816360e68ca9917cf0d06d9b` closed with Engineering evidence
commit `89e74c381c5cd486cbfab3762c85ba0fad258e3f`. Not claimed. No HTTP,
OIDC, worker, preview, or deployment work is claimed by this promotion.
