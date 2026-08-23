# P-0011 AC1-AC10 traceability

## Binding and result

This matrix applies only to immutable implementation candidate
`ed6a06eb9710ab98792e11f5b7a42d56d2832e65`, tree
`e1f4fe9cc4e1e18ab7386f8437a95175ceb436c5`, qualified at
`2026-08-23T23:18:18.331Z`. The controlling complete gate is
`cargo test --locked --workspace --all-targets --all-features`: 770 tests
passed across 59 suites with no failure, including the live-PostgreSQL
tests.

All ten acceptance criteria are **Supported** by retained executable
evidence. “Supported” means the criterion is exercised by committed tests
under the complete Linux gate; it does not claim a live OIDC provider, an
outbox worker, preview materialization, evidence export, or deployment.

## Evidence legend

| ID | Retained source |
| --- | --- |
| RT | `crates/proof-server/src/routes.rs`; tests `crates/proof-server/tests/routes_impl.rs` |
| BF | `crates/proof-server/src/bff.rs`, `issuer.rs`; tests `crates/proof-server/tests/bff_impl.rs` |
| SS | `crates/proof-server/src/session.rs`; tests `crates/proof-server/tests/session_impl.rs` |
| AO | `crates/proof-server/src/authz.rs`, `operations.rs`; tests `crates/proof-server/tests/authz_operations_impl.rs` |
| DP | `crates/proof-server/src/dispatch.rs`; tests `crates/proof-server/tests/dispatch_impl.rs` |
| E2 | `crates/proof-server/tests/e2e_impl.rs` |
| SM | `crates/proof-server/tests/smoke.rs` |
| PG | `crates/proof-pg/src/migration.rs` session-boundary v2 DDL |

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Qualification and rejection boundary | Result |
| --- | --- | --- | --- | --- |
| AC1 | The nine-route surface and the four transport routes dispatch exactly per the closed registry with route-qualified cross-checks; unknown routes/versions/members fail closed with the route-specific Problem profile. | RT `router_rejects_unknown_routes_and_versions`, `duplicate_json_names_reject_with_400`, `unknown_members_reject_with_400`; SM `every_route_has_a_closed_problem_profile`; DP `dispatch_rejects_cross_check_mismatch_before_execution`, `cross_check_matrix_rejects_every_disagreement` | Unknown routes and every path/body/invocation/capability disagreement reject before application execution with the route profile. | **Supported** |
| AC2 | Raw-body and canonical-request limits are enforced independently; malformed, duplicate-name, non-I-JSON, and oversized requests reject with the exact 400/413/415 Problems. | RT `raw_body_over_limit_rejects_413_before_parsing`, `malformed_json_rejects_with_400`, `non_json_content_type_rejects_415`, `canonical_size_rejects_when_body_expands_past_1mib`; SM `contract_limits_are_exact` | Both 1 MiB bounds reject independently of JSON spelling; malformed and wrong-type requests map exactly. | **Supported** |
| AC3 | The BFF completes the Authorization Code plus PKCE flow against the deterministic issuer with state/nonce/iss/aud/azp/exp/skew checks and rejects every abuse vector in the retained matrix. | BF `happy_path_code_exchange_round_trips`, `pkce_s256_challenge_matches_rfc7636_frozen_vector`, `wrong_issuer_is_rejected`, `wrong_audience_is_rejected`, `multiple_audiences_require_exact_azp`, `wrong_algorithm_none_is_rejected`, `wrong_key_is_rejected`, `expired_token_beyond_skew_is_rejected`, `future_token_beyond_skew_is_rejected`, `not_before_beyond_skew_is_rejected`, `nonce_mismatch_is_rejected`, `issued_code_is_single_use`, `validate_discovery_issuer_requires_exact_equality`, `validate_subject_rejects_empty_and_control_characters` | Every retained abuse vector rejects; codes are single-use; discovery issuer equality and exact subject comparison hold. | **Supported** |
| AC4 | Sessions are opaque, hashed-at-rest, flagged-correctly, bounded, rotated, revocable, and re-resolved per call; logout converges for exact replay and already-revoked handles. | SS `session_id_is_256_bit_opaque_and_unique`, `create_and_resolve_roundtrip`, `rotate_changes_handle_and_preserves_binding`, `idle_expiry_invalidates_and_tombstones`, `absolute_expiry_invalidates_even_when_idle_is_kept_alive`, `revoke_then_replay_converges`, `logout_converges_for_exact_replay_and_unknown_handle_fails`, `cookies_have_exact_flags`; PG | Hashed-at-rest storage, both lifetime bounds, rotation, revocation convergence, and exact cookie flags are asserted. | **Supported** |
| AC5 | The CSRF synchronizer is digest-stored, session-bound, rotated, and required with exact `Origin` on every unsafe authenticated request; CORS is disabled. | SS `csrf_digest_is_stored_not_raw_value`, `csrf_rotation_invalidates_prior_value_and_invalidation_clears`, `logout_invalidates_the_synchronizer`; RT `origin_guard_accepts_same_origin_and_rejects_hostile`, `csrf_guard_accepts_present_and_rejects_missing`; SM `session_cookies_have_exact_flags` | Digest-only storage, rotation, invalidation, exact-Origin enforcement, and CSRF omission rejection hold. | **Supported** |
| AC6 | The Agent route requires both a live requesting-Human session and a fresh single-use verified Agent presentation; neither credential can substitute for the other. | AO `agent_dual_authentication_accepts_and_single_credential_rejects`; E2 | Agent-only and session-only requests fail; the combined path succeeds end to end. | **Supported** |
| AC7 | Every owned Human and Agent row commits its decision, governed fact, and consequence through one P-0010 unit of work with the exact per-row effect digest and timestamp field. | AO `owned_mutation_commits_decision_fact_and_consequence_with_effect_digest`, `idempotent_replay_returns_prior_result_without_duplicating_fact`, `denial_appends_signed_decision_without_governed_effect`, `per_row_role_requirement_is_enforced` | Decision, fact, and consequence commit atomically with the row's effect digest; replay does not duplicate the fact; denial appends only the signed decision. | **Supported** |
| AC8 | The status/Problem mapping matches the accepted registry, including disclosure-neutral 401 and the retryable 504 ambiguous-commit result; no public response leaks raw claims, subjects, tokens, or SQL. | DP `problem_registry_is_exactly_41_frozen_tuples`, `map_server_error_projects_the_contract_table`, `dispatch_returns_429_with_retry_after_when_exhausted`; SS `projection_contains_no_raw_claims`; E2 | All 41 tuples are exact; status mapping including 429 Retry-After and 504 holds; public bodies carry no raw material. | **Supported** |
| AC9 | Rate limiting, the 30-second deadline, and the 4,194,304-byte response bound behave as adapter controls and never as authority. | DP `rate_limiter_exhausts_and_recovers`, `dispatch_returns_429_with_retry_after_when_exhausted`; SM `contract_limits_are_exact` | Exhaustion yields 429 with Retry-After and recovers; the limits are frozen as contract constants distinct from authority records. | **Supported** |
| AC10 | The full Linux quality gate passes and durable Engineering evidence (receipt, manifest, traceability) binds the item-work commit. | This matrix; `manifest.json` commands and artifact digests; receipt | All seven gate commands pass with recorded exit codes; 18 candidate blobs are bound by Git OID and SHA-256; `item_work_commit` equals the candidate. | **Supported** |

## Exact gate

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 770 passed across 59 suites; 0 failed (live-PostgreSQL tests executed) |
| `cargo test --locked --doc --workspace --all-features` | Seven suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 334 internal links passed |
| `node scripts/check-work-items.mjs` | Eleven work items passed |
| `git diff --check` | Passed |

## Boundary carried to completion

The candidate implements the HTTP and OIDC server boundary and nothing more.
No live provider, outbox worker, preview materialization, evidence export,
deployment, or runtime-parity claim exists in or is implied by this item.
The remaining acceptance boundary — artifact/outbox/preview delivery,
remote evidence, and owner-level Milestone 3 closure — belongs to the later
successors, not to P-0011.
