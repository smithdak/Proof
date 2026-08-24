# P-0012 Engineering qualification receipt

## Outcome

Engineering qualification is supported for immutable P-0012 candidate
`9c282ea66d588250fc6cc8a58a2aacf8320dee45`, tree
`b2b1857fabeda2e9b82b4967a085167619876f4d`. The candidate implements the
artifact outbox and private preview delivery in the new `proof-delivery`
crate plus additive delivery-state migration v3 in `proof-pg`, the
`DeliveryManagementFactV1` type in `proof-remote`, and the delivery
operations in `proof-server`, and passed the complete Linux quality gate
including live-PostgreSQL tests. The item has `review_gate: none`, so this
packet makes the item eligible to move from `review` to `done` under the
work-control protocol.

This packet does not implement or claim evidence export, the remote
verifier extension, the north-star run, deployment, or production
operation. Successor promotion remains blocked until this item completes.

The machine-readable revision, command, environment, inventory, digest, and
gate data are in `manifest.json`. Criterion-level AC1-AC10 coverage is in
`traceability.md`. These evidence files were created after the immutable
candidate and are intentionally absent from its Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0012 base / claim commit | `e38cdc666bd57ca77a32c14dfe429ee34362ee54` |
| Skeleton commit / candidate parent | `543a77c3fd3b9f13a1dba395edb0ad00b8f82e86` |
| Candidate | `9c282ea66d588250fc6cc8a58a2aacf8320dee45` |
| Candidate tree | `b2b1857fabeda2e9b82b4967a085167619876f4d` |
| Qualified at | `2026-08-24T01:19:33.555Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 19 paths; 5,776 insertions; 22 deletions |
| Parent-to-candidate delta | 12 paths; 4,833 insertions; 101 deletions |
| Retained P-0012 tests | 37 Rust tests across four test binaries |
| PostgreSQL under test | 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) |
| New third-party packages | 0 |
| Frozen conformance vectors changed | 0 |

## Qualified implementation boundary

### Outbox worker

`claim_due_work` runs a short `READ COMMITTED` transaction with
`FOR UPDATE SKIP LOCKED`, claims only the lowest nonterminal sequence of a
stream whose prior sequence is terminally delivered or explicitly
abandoned, writes a random 32-byte lease token with a 60-second
`clock_timestamp()` lease, and counts the attempt before committing the
claim. External I/O happens only after claim commit under a 30-second
attempt deadline with no lease renewal. `acknowledge` compares-and-sets on
the exact lease token and generation and rejects stale or superseded
acknowledgements; lease expiry makes the same stable delivery eligible
again. Retry delay uniformly samples the upper half of
`min(5s * 2^(generation_attempt - 1), 1h)` added to database time.
Dead-letter fires at twelve counted attempts in one generation or seven
days from the generation start, whichever comes first, or immediately on an
explicit permanent failure; a poison message blocks only its own stream.
Workspace transaction sequence plus ordinal, never time, defines order.
At-least-once semantics are explicit in code and tests; no exactly-once or
at-most-once claim exists.

### Private preview

The filesystem-backed `PreviewAdapter` writes blobs under unreachable
content-addressed keys, verifies kind/length/digest, and writes the
complete-snapshot manifest and ready marker last; a crash before the marker
exposes nothing and reads resolve only ready manifests. `alias_cas`
implements the four exact outcomes — higher sequence advances, same
sequence plus same Release/manifest digest is a no-op, same sequence plus
different bytes is an integrity failure, and a lower sequence is recorded
superseded without regressing the alias. Delivery failure never rewrites
Release history.

### Delivery operations and serving

`delivery.get/v1` projects the exact mutable delivery state.
`delivery.replay/v1` (`environment.admin`) and `delivery.abandon/v1`
(`environment.activator`) each commit the signed
`RemoteAuthorizationDecisionV1`, one `DeliveryManagementFactV1` digested
under `proof:delivery-management-fact:v1`, and the
`RemoteApplicationConsequenceV1` whose `application_effect_digest` binds the
fact through one P-0010 unit of work. Replay increments the generation,
resets `attempts_in_generation`, and returns `pending` while preserving
event, delivery, and payload identities and the append-only attempt
history; abandonment keeps the generation, records null `to_generation`,
and sets terminal `abandoned`. `serve_preview_object` returns the exact
snapshot projection with the strong ETag and `Cache-Control: private,
no-store`, the stable `proof.dependency.unavailable` Problem while pending,
and never falls back to another Release.

## Conformance and falsification result

The retained frozen collaboration-server Schemas and vectors are unchanged;
all retained P-0008 through P-0011 tests pass unmodified. Claim-crash
attempt consumption, stale-ack rejection, dead-letter timing, poison
blocking, alias outcome matrices, wrong-digest materialization closure, and
replay/abandon identity preservation reject concrete mutations. An
end-to-end test executes enqueue, claim, materialization, acknowledgement,
ready resolution, forced-permanent-failure dead-letter, replay, and
abandonment with re-verified fact digests.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 807 passed across 66 suites; 0 failed (includes live-PostgreSQL tests) |
| `cargo test --locked --doc --workspace --all-features` | Seven doc-test suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 344 internal documentation links passed |
| `node scripts/check-work-items.mjs` | Twelve work items passed metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts |
| `git diff --check` | Passed |

## Residual risks and nonclaims

- No evidence export capture/assembly or remote verifier extension exists;
  that is the final successor's scope.
- The preview serving path in `proof-server` and the `proof-delivery`
  `PreviewAdapter` share the exact contract semantics but not one code
  path; unification is recorded as successor cleanup.
- Delivery is at least once by design; recipient-side deduplication and
  receipt observation are not independent proof of remote application.
- The filesystem preview adapter is a reference implementation; object-store
  selection and retention/garbage-collection remain later work.
- No successor promotion, milestone completion, deployment, or production
  mutation is claimed by this packet.

## Disposition

Engineering recommends moving P-0012 from `review` to `done` under
`review_gate: none` after the complete Linux gate recorded above, then
promoting the accepted contract's fifth and final successor, P-0013 remote
evidence and Milestone 3 qualification, to `ready`. This receipt does not
execute that disposition.

Evidence paths:

- `docs/work/evidence/P-0012/receipt.md`
- `docs/work/evidence/P-0012/manifest.json`
- `docs/work/evidence/P-0012/traceability.md`
