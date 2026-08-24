# P-0012 AC1-AC10 traceability

## Binding and result

This matrix applies only to immutable implementation candidate
`9c282ea66d588250fc6cc8a58a2aacf8320dee45`, tree
`b2b1857fabeda2e9b82b4967a085167619876f4d`, qualified at
`2026-08-24T01:19:33.555Z`. The controlling complete gate is
`cargo test --locked --workspace --all-targets --all-features`: 807 tests
passed across 66 suites with no failure, including the live-PostgreSQL
tests.

All ten acceptance criteria are **Supported** by retained executable
evidence. “Supported” means the criterion is exercised by committed tests
under the complete Linux gate; it does not claim evidence export, the
remote verifier extension, the north-star run, or deployment.

## Evidence legend

| ID | Retained source |
| --- | --- |
| WK | `crates/proof-delivery/src/worker.rs`; tests `crates/proof-delivery/tests/worker_impl.rs` |
| PV | `crates/proof-delivery/src/preview.rs`; tests `crates/proof-delivery/tests/preview_impl.rs` |
| DO | `crates/proof-server/src/operations.rs`, `crates/proof-remote/src/governance.rs`; tests `crates/proof-server/tests/delivery_ops_impl.rs` |
| E2 | `crates/proof-delivery/tests/e2e_delivery_impl.rs` |
| PG | `crates/proof-pg/src/migration.rs` v3 delivery-state DDL |

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Qualification and rejection boundary | Result |
| --- | --- | --- | --- | --- |
| AC1 | The worker claims in deterministic stream order under `FOR UPDATE SKIP LOCKED` with a random 60-second lease and counts the attempt at claim commit; external I/O happens only after claim commit. | WK `claim_order_respects_stream_prefixes`, `skip_locked_parallel_claims_of_distinct_streams`, `claim_crash_consumes_attempt_and_expiry_redelivers` | Stream-prefix ordering, SKIP LOCKED parallelism, and claim-crash attempt consumption are retained; the attempt is counted only at claim commit. | **Supported** |
| AC2 | Acknowledgement is compare-and-set on lease token and generation; stale acks reject; expiry makes the same stable delivery eligible again. | WK `stale_ack_rejection`, `claim_crash_consumes_attempt_and_expiry_redelivers` | Stale or superseded acknowledgements reject; expiry re-eligibility preserves the stable delivery identity. | **Supported** |
| AC3 | Backoff, the twelve-attempt/seven-day dead-letter rule, immediate permanent-failure dead-letter, and per-stream poison blocking all behave exactly; other streams progress independently. | WK `twelve_attempt_dead_letter`, `seven_day_dead_letter`, `permanent_failure_immediate_dead_letter`, `poison_stream_blocks_while_other_stream_succeeds`, `retry_delay_bounds_and_distribution` | Both dead-letter triggers, immediate permanent-failure dead-letter, poison scoping, and upper-half retry-delay distribution are asserted. | **Supported** |
| AC4 | Replay and abandonment append `DeliveryManagementFactV1` with the signed decision and consequence binding; replay resets the generation to `pending`; abandonment is terminal `abandoned`. | DO `delivery_management_fact_digest_matches_conformance_vectors`, `replay_returns_pending_with_new_generation_and_preserved_identities`, `abandon_is_terminal_with_null_to_generation_and_preserved_generation`, `non_dead_letter_replay_and_non_poison_abandon_reject` | Fact digests match the retained vectors; identities are preserved; non-qualifying replay/abandon reject. | **Supported** |
| AC5 | The preview adapter materializes blobs under unreachable keys, writes the ready manifest last, and enforces the four alias outcomes by Release sequence. | PV `staged_blobs_without_a_ready_marker_are_invisible`, `deleting_the_ready_marker_hides_a_complete_snapshot`, `alias_cas_yields_the_four_exact_outcomes_by_sequence` | Partial snapshots are invisible; advance, no-op, integrity failure, and superseded all execute. | **Supported** |
| AC6 | The preview route serves exact immutable Release snapshots with the strong ETag and private no-store cache control, returns the stable pending Problem until ready, and performs no fallback. | DO `serve_preview_object_returns_snapshot_after_ready_and_pending_before`, `serve_preview_object_never_falls_back_to_another_release`, `preview_object_projection_type_surface_is_stable`; PV `etag_and_cache_control_constants_are_exact` | Pending yields the stable Problem; ready yields the exact snapshot; fallback never occurs. | **Supported** |
| AC7 | Release commitment and preview delivery remain observably separate facts; delivery failure never rewrites Release history. | E2; DO `delivery_get_projects_each_status` | Release and delivery states are distinct projections; dead-letter/replay/abandon never mutate Release facts. | **Supported** |
| AC8 | At-least-once semantics are explicit in code and tests; no exactly-once or at-most-once claim exists anywhere. | WK claim-crash/expiry redelivery tests; E2 | Claim crash and send-before-ack are modeled as may-repeat; no exactly-once or at-most-once language or logic exists. | **Supported** |
| AC9 | `delivery.get/v1` projects the exact mutable delivery state. | DO `delivery_get_projects_each_status` | Each of the five delivery statuses projects exactly. | **Supported** |
| AC10 | The full Linux quality gate passes and durable Engineering evidence (receipt, manifest, traceability) binds the item-work commit. | This matrix; `manifest.json` commands and artifact digests; receipt | All seven gate commands pass with recorded exit codes; 15 candidate blobs are bound by Git OID and SHA-256; `item_work_commit` equals the candidate. | **Supported** |

## Exact gate

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 807 passed across 66 suites; 0 failed (live-PostgreSQL tests executed) |
| `cargo test --locked --doc --workspace --all-features` | Seven suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 344 internal links passed |
| `node scripts/check-work-items.mjs` | Twelve work items passed |
| `git diff --check` | Passed |

## Boundary carried to completion

The candidate implements the artifact outbox and private preview delivery
and nothing more. No evidence export, remote verifier extension, north-star
run, deployment, or runtime-parity claim exists in or is implied by this
item. The remaining acceptance boundary — remote evidence plus the
project-owner-accepted Milestone 3 qualification — belongs to the final
successor, not to P-0012.
