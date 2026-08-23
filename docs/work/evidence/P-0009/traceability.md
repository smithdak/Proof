# P-0009 AC1-AC10 traceability

## Binding and result

This matrix applies only to immutable implementation candidate
`3e38f30b95086162816360e68ca9917cf0d06d9b`, tree
`9e051077699917bdf5289ac1114d7875f5934d81`, qualified at
`2026-08-23T19:17:42.097Z`. The controlling complete gate is
`cargo test --locked --workspace --all-targets --all-features`: 664 tests
passed across 44 suites with no failure.

All ten acceptance criteria are **Supported** by retained executable evidence.
“Supported” means the criterion is exercised by committed tests and vectors
under the complete Linux gate; it does not claim an HTTP server, PostgreSQL
adapter, OIDC provider, outbox worker, or runtime local/server parity.

## Evidence legend

| ID | Retained source |
| --- | --- |
| AU | `crates/proof-remote/src/authority.rs`; tests `crates/proof-remote/tests/authority_impl.rs` |
| ID | `crates/proof-remote/src/identity.rs`; tests `crates/proof-remote/tests/identity_impl.rs` |
| GV | `crates/proof-remote/src/governance.rs`; tests `crates/proof-remote/tests/governance_impl.rs` |
| RG | `crates/proof-remote/src/registry.rs`; tests `crates/proof-remote/tests/registry_impl.rs` |
| OR | `crates/proof-remote/src/oracle.rs`; tests `crates/proof-remote/tests/oracle_impl.rs` |
| SM | `crates/proof-remote/tests/smoke.rs` |
| CV | `conformance/v1/collaboration-server/schemas/*.json` and `vectors/*.json` (frozen) |
| RT | `crates/proof-local/tests/p0008_collaboration_contract.rs` (retained harness, unmodified) |

## Criterion matrix

| Criterion | Required meaning | Primary retained evidence | Qualification and rejection boundary | Result |
| --- | --- | --- | --- | --- |
| AC1 | The closed `RemoteAuthorityRecordV1` union constructs, canonicalizes, signs, verifies, and rejects tamper under the exact v1 digest contexts, limits, and strict-JSON rules. | AU `golden_dsse_vector_matches_frozen_manifest`, `every_variant_round_trips_digest_sign_and_verify`, `signature_and_payload_tamper_are_rejected`, `payload_and_envelope_maxima_are_rejected`; CV | Byte-flip tamper, oversized payload/envelope, and malformed strict JSON all reject; the retained DSSE vector round-trips byte-exactly. | **Supported** |
| AC2 | Causal chain validation enforces sequence, predecessor, head, and single-active-key signer coherence and rejects fork or reorder mutations. | AU `chain_accepts_well_formed_prefix`, `chain_rejects_gap_reorder_predecessor_mismatch_key_switch_and_missing_head` | Gap, reorder, predecessor mismatch, unexpected key switch, and missing initial head each produce a typed rejection. | **Supported** |
| AC3 | OIDC subject commitment machinery reproduces the retained vectors byte-exactly; public evidence contains no raw issuer/subject, opening, or protected input digest. | ID `frozen_identity_digests_are_byte_exact`, `commitment_is_deterministic_and_blinds_are_distinct`, `opening_accepts_exact_preimage_and_rejects_tamper`, `base64url_no_pad_round_trips_without_padding`, `public_evidence_structurally_lacks_raw_subject_material`; CV | Commitments are deterministic per blind, blinds are distinct, openings reject tamper, and the public evidence type structurally lacks raw subject fields. | **Supported** |
| AC4 | Both `AuthenticatedActorContextV2` profiles and their `AuthenticatedActorContextEvidenceV2` redactions construct and reject substitution. | ID `context_redacts_to_exact_public_evidence_for_both_profiles`, `private_binding_validates_against_public_record`, `authentication_event_rejects_reversed_time_boundary` | Both closed profiles redact to exact public evidence; private lookup validates against the public record; time-boundary reversal rejects. | **Supported** |
| AC5 | `ChangeSetApprovalV1` binds its complete closure and rejects every prohibited approver and stale closure case. | GV `retained_changeset_approval_passes_prohibited_approvers`, `prohibited_approver_rejects_*` (requester, contributing Agent, publisher Agent, configuration activator, identity collapse, stale sequence, stale prior head); CV | The retained approval vector passes; each prohibited-approver class and stale-closure case rejects with a distinct outcome. | **Supported** |
| AC6 | Environment creation/proposal/activation and the assembled `EnvironmentConfigV2` enforce every cross-check, including distinct proposer/activator and exact predecessor/proposal digests. | GV `environment_config_v2_digests_match_the_retained_vector`, `assembled_environment_config_v2_validates`, `environment_config_v2_rejects_*` (workspace, chronology, predecessor, proposal digest, creation digest, copied field, self-activation) | Both configuration digests match the retained vector byte-exactly; every cross-check rejection is exercised. | **Supported** |
| AC7 | The three frozen registry SHA-256s recompute identically from committed registry bytes; route-qualified lookup, per-row authorization rules, and effect-digest rules match the accepted contract row-for-row. | RG `frozen_registry_hashes_recompute_byte_exactly`, `registry_lookup_accepts_known_rows_and_rejects_unknown`, `http_route_surface_matches_the_nine_closed_routes`, `route_cross_check_fails_closed_on_any_disagreement`, `digest_preimages_match_the_frozen_vectors`, `effect_timestamp_field_selects_each_authority_payload_member`; CV | The three frozen SHA-256s recompute equal and fail closed on mismatch; unknown rows and path/body disagreements reject; per-row effect timestamp fields select exactly. | **Supported** |
| AC8 | The deterministic oracle reproduces byte-identical traces for shared operations across repeated execution; mutated inputs land in the contracted consequence class without executing an HTTP or database adapter. | OR `repeated_execution_produces_byte_identical_traces`, `workspace_status_produces_a_typed_success_trace`, `rejected_input_produces_a_stable_problem_trace` | Two runs of the same scenario produce byte-identical `OracleTraceV1` traces; success lands in `TypedResult` and rejection in `StableProblem` with the stable code. | **Supported** |
| AC9 | Conformance vectors and rejection mutations are executable in the workspace gate; no server, provider, database, or runtime-parity claim is introduced. | SM public-surface pins; RT; CV frozen-vector inventory | Zero frozen vectors changed; the retained P-0008 harness passes unmodified; the receipt and manifest record explicit nonclaims. | **Supported** |
| AC10 | The full Linux quality gate passes and durable Engineering evidence (receipt, manifest, traceability) binds the item-work commit. | This matrix; `manifest.json` commands and artifact digests; receipt | All eight gate commands pass with recorded exit codes; 15 candidate blobs are bound by Git OID and SHA-256; `item_work_commit` equals the candidate. | **Supported** |

## Exact gate

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 664 passed across 44 suites; 0 failed |
| `cargo test --locked -p proof-remote --all-targets` | 50 passed; 0 failed |
| `cargo test --locked --doc --workspace --all-features` | Seven suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 320 internal links passed |
| `node scripts/check-work-items.mjs` | Nine work items passed at the committed candidate tree |
| `git diff --check` | Passed |

## Boundary carried to completion

The candidate implements the remote actor and shared-contract conformance
foundation and nothing more. No HTTP, PostgreSQL, OIDC-provider, worker,
preview, or runtime-parity claim exists in or is implied by this item. The
remaining acceptance boundary — owner-level Milestone 3 closure — belongs to
the later qualification successor, not to P-0009.
