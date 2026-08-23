# P-0010 AC1-AC11 traceability

## Binding and result

This matrix applies only to immutable implementation candidate
`4410b46a27687fd8ce04d01d2c872f1ca2ac4ccc`, tree
`c685b79afc8bd054595cc0a9df4d7394cdcbeb29`, qualified at
`2026-08-23T21:36:53.801Z`. The controlling complete gate is
`cargo test --locked --workspace --all-targets --all-features`: 696 tests
passed across 51 suites with no failure, including the live-PostgreSQL
tests against PostgreSQL 16.15.

All eleven acceptance criteria are **Supported** by retained executable
evidence. “Supported” means the criterion is exercised by committed tests
under the complete Linux gate; it does not claim an HTTP server, OIDC
provider, outbox worker, preview materialization, or evidence export.

## Evidence legend

| ID | Retained source |
| --- | --- |
| MG | `crates/proof-pg/src/migration.rs`, `schema.rs`; tests `crates/proof-pg/tests/migration_impl.rs` |
| TX | `crates/proof-pg/src/transaction.rs`, `idempotency.rs`; tests `crates/proof-pg/tests/transaction_impl.rs` |
| AO | `crates/proof-pg/src/artifacts.rs`, `outbox.rs`; tests `crates/proof-pg/tests/artifacts_outbox_impl.rs` |
| PI | `crates/proof-pg/src/projection.rs`, `import.rs`; tests `crates/proof-pg/tests/projection_import_impl.rs` |
| PA | `crates/proof-pg/src/parity.rs`, `crates/proof-remote/src/oracle.rs` (`StorageBackend`); tests `crates/proof-pg/tests/parity_impl.rs` |
| WG | `crates/proof-pg/src/wiring.rs`; tests `crates/proof-pg/tests/wiring_impl.rs` |
| CI | `.github/workflows/ci.yml` PostgreSQL service and `PROOF_PG_DSN` |

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Qualification and rejection boundary | Result |
| --- | --- | --- | --- | --- |
| AC1 | The migration ledger performs the expand/backfill/verify/cutover contract with checksummed immutable scripts, a singleton migrator, and fail-closed checksum/version/dirty-phase refusal. | MG `clean_run_applies_all_scripts_and_verify_head_passes`, `rerun_is_a_no_op`, `tampered_script_triggers_checksum_mismatch`, `dirty_phase_blocks`, `unknown_newer_version_blocks`, `concurrent_migrators_exactly_one_wins`, `script_digest_is_domain_separated_over_exact_bytes` | Tampered bytes, dirty phases, unknown newer versions, and concurrent migrators all resolve to exactly one correct outcome. | **Supported** |
| AC2 | The authoritative transaction implements all twelve contract steps under `SERIALIZABLE` with the locked write head and row-derived causal sequences; no PostgreSQL sequence drives causal order. | TX `clean_success_persists_head_facts_consequence_and_one_outbox_enqueue`, `serializable_race_observes_40001_on_commit`, `retry_recovers_from_serialization_failure_with_consistent_sequences`; WG | `SELECT ... FOR UPDATE` on the singleton head; sequences derive only from the locked row; a real two-connection race yields `40001` and the retry converges consistently. | **Supported** |
| AC3 | Keyed idempotency replays the prior result without duplicating the governed fact, key, or outbox event; same-key changed input commits a conflict consequence; no-key rows are fresh authenticated attempts. | TX `replay_discloses_prior_result_without_duplicating_fact_key_or_outbox`, `changed_input_same_key_commits_conflict_without_governed_effect`, `no_key_rows_execute_fresh_without_consulting_stored_results` | Duplication and cross-input disclosure are impossible in the retained paths; fresh no-key attempts never consult stored results. | **Supported** |
| AC4 | The savepoint rule commits exactly presentation consumption, decision, and failure-consequence bodies on an authorized application failure, and rolls back everything on infrastructure failure. | TX `application_failure_keeps_decision_and_consequence_without_governed_effect`, `infrastructure_failure_rolls_back_everything`, `savepoint_guard_rollback_restores_prior_rows` | Authorized failure leaves no governed fact/key/outbox; infrastructure failure leaves nothing at all. | **Supported** |
| AC5 | Bounded retry and ambiguous-commit reconciliation match the contract, including no external calls inside the retried transaction. | TX `retry_recovers_from_serialization_failure_with_consistent_sequences`, `classify_sqlstate_maps_the_contract_classes` | `40001`/`40P01`/`23505` classification, three attempts, 30-second deadline, jitter, and the retryable `proof.operation.unknown_outcome` model. | **Supported** |
| AC6 | Artifact identity, `put_if_absent`, read-after-write, staged-neutral invisibility before commit, and atomic PostgreSQL storage of fork-capable signed bytes all hold under test. | AO `put_if_absent_create_replay_noop_and_integrity_failure`, `read_after_write_revalidates_and_rejects_truncation`, `staged_neutral_blob_is_invisible_until_catalog_commit`, `catalog_and_body_are_atomic_with_the_transaction` | Different bytes at one key are an integrity failure; truncation rejects; staged blobs are unnameable before commit; catalog and body commit or roll back together. | **Supported** |
| AC7 | Outbox enqueue records one logical event per committed consequence and destination with both uniqueness keys; no delivery behavior is claimed. | AO `outbox_enqueue_rejects_both_uniqueness_keys`, `outbox_enqueue_round_trips_all_fields_exactly` | Both `{workspace_id, effect_digest, event_type, event_version, destination_configuration_digest}` and `{workspace_id, workspace_transaction_sequence, ordinal}` are enforced; the module contains no worker, lease, or delivery code. | **Supported** |
| AC8 | Projection rebuild swaps one verified generation atomically and never regenerates facts, idempotency, artifacts, or outbox history. | PI `projection_rebuild_dry_run_then_swap_flips_exactly_one_pointer`, `rebuild_never_touches_facts_idempotency_or_outbox` | Dry run leaves the active generation unchanged; success flips exactly one pointer; authoritative rows are structurally untouched. | **Supported** |
| AC9 | The SQLite-to-PostgreSQL import reconstructs chains from verified canonical facts, rebuilds projections, compares authority heads and Known State, and cuts over atomically. | PI `import_matches_source_heads_known_state_and_counts`, `tampered_sqlite_artifact_fails_closed` | Heads, Known State, and counts match; a tampered artifact fails the import closed before cutover. | **Supported** |
| AC10 | The shared oracle runner produces byte-identical traces on both backends for accepted, rejected, replay, and conflict scenarios, and CI plus the local dev instance both execute the PostgreSQL tests. | PA `workspace_status_trace_is_byte_identical`, `localized_context_build_replay_trace_is_byte_identical`, `rejected_input_trace_is_byte_identical`, `tampered_postgres_consequence_diverges`; CI | Byte-identical traces across backends; tamper produces divergence; the CI service container plus `PROOF_PG_DSN` execute the tests fail-closed. | **Supported** |
| AC11 | The full Linux quality gate passes and durable Engineering evidence (receipt, manifest, traceability) binds the item-work commit. | This matrix; `manifest.json` commands and artifact digests; receipt | All seven gate commands pass with recorded exit codes; 23 candidate blobs are bound by Git OID and SHA-256; `item_work_commit` equals the candidate. | **Supported** |

## Exact gate

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 696 passed across 51 suites; 0 failed (live-PostgreSQL tests executed) |
| `cargo test --locked --doc --workspace --all-features` | Seven suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 324 internal links passed |
| `node scripts/check-work-items.mjs` | Ten work items passed |
| `git diff --check` | Passed |

## Boundary carried to completion

The candidate implements the PostgreSQL parity foundation and nothing more.
No HTTP, OIDC-provider, worker, preview, evidence-export, or runtime-parity
claim exists in or is implied by this item. The remaining acceptance
boundary — the HTTP/OIDC boundary, artifact/outbox/preview delivery, remote
evidence, and owner-level Milestone 3 closure — belongs to the later
successors, not to P-0010.
