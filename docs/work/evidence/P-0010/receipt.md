# P-0010 Engineering qualification receipt

## Outcome

Engineering qualification is supported for immutable P-0010 candidate
`4410b46a27687fd8ce04d01d2c872f1ca2ac4ccc`, tree
`c685b79afc8bd054595cc0a9df4d7394cdcbeb29`. The candidate implements the
PostgreSQL parity foundation in the new `proof-pg` crate plus the minimal
additive `StorageBackend` boundary in `proof-remote`, and passed the complete
Linux quality gate including live-PostgreSQL tests against PostgreSQL 16.15.
The item has `review_gate: none`, so this packet makes the item eligible to
move from `review` to `done` under the work-control protocol.

This packet does not implement or claim an HTTP server, an OIDC provider
connection, an outbox worker, preview delivery, evidence export, or runtime
deployment parity. Successor promotion remains blocked until this item
completes.

The machine-readable revision, command, environment, inventory, digest, and
gate data are in `manifest.json`. Criterion-level AC1-AC11 coverage is in
`traceability.md`. These evidence files were created after the immutable
candidate and are intentionally absent from its Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0010 base / claim commit | `ace67ac48fad343f4f213ab3d3d37f785a350ccd` |
| Skeleton commit / candidate parent | `7fe7d67a109ea45aaf84854b06ccda5e85920caf` |
| Candidate | `4410b46a27687fd8ce04d01d2c872f1ca2ac4ccc` |
| Candidate tree | `c685b79afc8bd054595cc0a9df4d7394cdcbeb29` |
| Qualified at | `2026-08-23T21:36:53.801Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 23 paths; 7,997 insertions; 16 deletions |
| Parent-to-candidate delta | 22 paths; 6,197 insertions; 114 deletions |
| Retained P-0010 tests | 32 Rust tests across six `proof-pg` test binaries |
| PostgreSQL under test | 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1), local trust instance and CI service container |
| New third-party packages | postgres 0.19.14, postgres-types 0.2.14 (sync driver; tokio appears only as the driver's internal transitive dependency) |
| Frozen conformance vectors changed | 0 |

## Qualified implementation boundary

### Migration ledger

`MigrationLedger` implements the immutable monotonic version/name/digest
ledger over `migration_head`, a singleton migrator via the fixed advisory
lock, per-phase `started`/`verified`/`failed` states, and the expand,
backfill, verify, cutover, and contract phase order. Script digests are
domain-separated BLAKE3-256 over the exact script bytes. `verify_head`
rejects checksum mismatch, dirty phase, unknown newer versions, and writes
outside the compatibility interval. The schema DDL defines fourteen logged
tables including the singleton `workspace_write_head` carrying the causal
sequences and heads, `artifact_catalog` plus the logged `artifact_body_pg`
separation, `outbox_events` with both contract uniqueness keys as database
constraints, and `projection_generations` with one active pointer. No
`UNLOGGED` authoritative table exists; `synchronous_commit`, `fsync`, and
`full_page_writes` are documented preconditions.

### Authoritative unit of work, idempotency, retry

`WorkspaceTransaction` runs `SERIALIZABLE READ WRITE` and locks the
singleton `workspace_write_head` with `SELECT ... FOR UPDATE`; causal
transaction/authority/content/Release sequences derive only from the locked
row — the crate contains no PostgreSQL sequence, `SERIAL`, or `BIGSERIAL`
use. `run_unit_of_work` implements the twelve contract steps through typed
hooks: authentication before idempotency lookup or prior-result disclosure;
current authorization at the locked head; keyed replay disclosing the prior
result without duplicating the domain fact, key, or outbox event; same-key
changed-input conflict consequences without a governed effect; no-key rows
skipping stored-result lookup; precondition conflicts committing
presentation consumption plus signed decision and failure consequence; a
savepoint around the governed consequence; ordinary authorized application
failure rolling back to the savepoint and committing only presentation
consumption, decision, and failure-consequence bodies; infrastructure
failure rolling back the complete transaction; nothing returned before
commit success. `RetryPolicy` bounds three attempts within the 30-second
deadline with jitter; SQLSTATE `40001` retries fully, `40P01` only from the
beginning, and `23505` only for a named internal allocation constraint; no
external call exists inside the retried transaction. The ambiguous-commit
contract models the retryable `proof.operation.unknown_outcome` result and
reconciliation as a separate keyed attempt. A real two-connection
serialization race is retained as a test.

### Artifact catalog and outbox enqueue

`ArtifactKeyV1` uses the canonical `artifacts/{artifact_kind}/blake3/{digest}`
keys with identity over kind, canonical bytes, digest, media type, Schema
version, and length. `FsStoragePort` implements `put_if_absent` with
existing-key digest/length reproduction and different-bytes integrity
failure, plus read-after-write revalidation; neutral blobs stage in a
private unreachable namespace and cannot be named before `catalog_commit`.
Fork-capable signed bytes insert into the logged `artifact_body_pg` table in
the same transaction as their catalog row. `OutboxEnqueueV1` writes one
logical event per committed consequence and destination with both
uniqueness keys enforced at the database level; no worker, lease, or
delivery state exists.

### Projection rebuild and import

`rebuild_into_new_generation` verifies authority and content/Release chains
under the locked head, rebuilds derived rows into a new generation,
compares identities, counts, foreign keys, versions, sequences, and state
digest, and swaps exactly one active pointer atomically; facts, authority
records, idempotency, artifact catalog, outbox events, attempts, and
receipts are structurally never regenerated or deleted. The
SQLite-to-PostgreSQL importer consumes verified canonical facts, re-verifies
digests and signatures during import, reconstructs chains, rebuilds
projections, compares authority heads and Known State, and opens network
writes only at the atomic cutover; a tampered SQLite artifact fails the
import closed.

### Shared oracle parity

`proof-remote::oracle::StorageBackend` is the minimal additive backend
boundary: the SQLite reference path and the PostgreSQL path both produce
`OracleTraceV1` traces. The `ParityRunner` proves byte-identical traces for
shared operations across accepted, rejected, replay, and conflict
scenarios, and proves divergence when the PostgreSQL consequence is
tampered.

## Conformance and falsification result

The retained frozen collaboration-server Schemas and vectors are unchanged;
the retained P-0008 harness and all P-0009 `proof-remote` tests pass
unmodified. The transaction race, savepoint rollback, replay
non-duplication, artifact substitution, staging invisibility, enqueue
uniqueness, import tamper, and parity-divergence tests reject concrete
mutations. CI now runs the PostgreSQL-backed tests against a pinned
`postgres:16` service with `PROOF_PG_DSN`; a test that cannot connect fails
with an actionable message rather than silently passing.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 696 passed across 51 suites; 0 failed (includes live-PostgreSQL tests) |
| `cargo test --locked --doc --workspace --all-features` | Seven doc-test suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 324 internal documentation links passed |
| `node scripts/check-work-items.mjs` | Ten work items passed metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts |
| `git diff --check` | Passed |

The link check is recorded against the committed candidate tree; an
uncommitted scratch draft with unresolved relative links was parked outside
the repository before the recorded run.

## Residual risks and nonclaims

- P-0010 qualifies the PostgreSQL parity foundation only. No HTTP server,
  session, CSRF, or BFF exists; no OIDC provider was contacted; no outbox
  worker, lease, claim, or delivery state exists; no preview
  materialization or evidence export exists.
- The unit of work is proven against PostgreSQL 16.15 semantics including a
  real serialization race; it is not power-loss, storage-controller, or
  operator-tamper proof, and a fully compromised database and key boundary
  remains outside the guarantee.
- SQLite and PostgreSQL traces are byte-identical for the shared operations
  exercised by the retained scenarios; exhaustive cross-product coverage of
  every registry row on both backends remains Milestone 3 qualification
  successor work.
- No successor promotion, framework choice, provider choice, deployment, or
  production mutation is claimed by this packet.

## Disposition

Engineering recommends moving P-0010 from `review` to `done` under
`review_gate: none` after the complete Linux gate recorded above, then
promoting the accepted contract's third successor, P-0011 HTTP and OIDC
server boundary, to `ready`. This receipt does not execute that disposition.

Evidence paths:

- `docs/work/evidence/P-0010/receipt.md`
- `docs/work/evidence/P-0010/manifest.json`
- `docs/work/evidence/P-0010/traceability.md`
