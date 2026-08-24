# P-0013 traceability matrix

Criterion-level coverage for the P-0013 acceptance criteria at candidate
`1fb53b893b35cf3910f47b4d35ade59ceecfb62a`. Test names are executable
evidence; counts are from the qualified gate run in `manifest.json`.

| # | Acceptance criterion | Status | Evidence |
| --- | --- | --- | --- |
| AC1 | Six-root logical member map exports and re-imports exactly; reserved descriptors, deterministic paths, kind/digest/length checks; every path/limit violation classified Invalid | Supported | `crates/proof-remote/tests/bundle_impl.rs` (26 tests): frozen path identity, `normalize_member_path` taxonomy (absolute/backslash/dot-segment), duplicate/undeclared/missing entries, digest and canonicalization-class mismatches, count/byte limits, external-required roots absent; exercised by producer assembly (`export_impl.rs`, `evidence_e2e_impl.rs`) and verifier membership validation (`remote_impl.rs`) |
| AC2 | Keyed capture returns pending create result; replay byte-identical post-assembly; no-key status read observes ready independently | Supported | `crates/proof-server/tests/export_impl.rs` (5 tests); `evidence_e2e_impl.rs`: keyed replay identity after worker assembly, ready transition with exact reserved digests, second worker run is a no-op |
| AC3 | Artifact acquisition by exact `(export_id, kind, digest)` triple; no cross-kind alias | Supported | `routes.rs` GET route over `evidence_artifact_get_v2`; alias-rejection asserted in `north_star_remote_impl.rs`; revalidated kind/length/digest in `export.rs` |
| AC4 | Verifier remote-authority and remote-evidence modes classify Complete/Incomplete/Invalid exactly under caller trust, including three conformance scenarios | Supported | `crates/proof-verifier/tests/remote_impl.rs` (8); `remote_conformance.rs` (4): `complete-exact-materialization` → Complete; `incomplete-required-opening-withheld` → Incomplete `[missing-disclosure]`; `invalid-content-artifact-byte-tamper` → Invalid `[tampered-artifact]`; report serialization validated against frozen schema constants |
| AC5 | Producer hints inert; no freshness/readiness/latest-history claim in Complete | Supported | Inert-hints assertions in `bundle_impl.rs`/`remote_impl.rs` fixtures; verifier excludes capture integrity, readiness, current-at-snapshot, immediate-predecessor, globally-latest claims (`remote_evidence.rs`, documented in report scope) |
| AC6 | Complete remote north-star (two Humans + one Agent) end to end over HTTP + PostgreSQL with separation-of-duties checks | Supported | `crates/proof-server/tests/north_star_remote_impl.rs`: OIDC sessions ×2, role assignment, delegation + ContextPack, Agent changeset path via signed commands, Human-only approval enforced (Agent approval rejected), distinct-approver commit, Edition/Environment propose+activate split, Release, delivered preview behind ready marker (503→200), export→assemble→verify offline leg asserting **Complete** |
| AC7 | 158-row rejection matrix maps one-to-one to executable tests where applicable; applicable rejections fail closed | Supported | Registry audit: 156 report + 2 CLI codes exact; all 30 direct-behavioral overrides resolve to real passing tests; 128 structural guards frozen by source-to-registry equality; coverage partition now asserted exhaustive/disjoint in `finding_code_registry.rs` |
| AC8 | Crash matrix covers artifact preparation, authoritative transaction boundaries, outbox claim/send/ack, lease expiry, retry, poison handling, replay, preview application | Supported | Nine-boundary mapping table in `.swarm-reports/p0013-crash-matrix.md`; PG-layer windows in `crash_matrix_m3.rs` (10 tests, five new interruption-and-recovery pairs); outbox lease/retry/poison/replay/preview pinned by committed P-0012 worker/delivery suites |
| AC9 | Local/server conformance report proves shared-oracle trace identity in both modes | Supported with explicit classification | `conformance_report_impl.rs`: canonical RFC 8785 report, BLAKE3 `blake3:e55b59da7b492dbc1b019579b9270ceb92fd934271484e9b88e5f7bffd8a0770` (9,290 bytes); A↔B byte-identical on mirrored rows incl. stable not-mirrored error as an exact observable; A↔C byte-identical wherever both modes define typed semantics; remaining steps carry explicit named classifications — full mutation-semantics parity requires the deferred PG-backed executor (residual below) |
| AC10 | Full Linux quality gate passes; durable Engineering evidence binds item-work commit | Supported | Gate: fmt, clippy `-D warnings` (0 warnings), 868/868 tests in 77 binaries, doc tests, 354 doc links, 13-item control-plane validation (commands + exit codes in `manifest.json`); this packet binds candidate `1fb53b8` / tree `cb6fb4a` |
| AC11 | Project owner accepts Milestone 3 exit evidence and residuals before `review` → `done` | Pending gate | `review_gate: project-owner`; acceptance fields intentionally null until project owner `smithdak` records them |

## Residuals carried to the project-owner decision

1. PG-backed application semantic executor (full mutation-row trace parity) —
   ratified P-0010 residual, explicitly classified per step by AC9's report.
2. Route-complete enrollment (`agent-binding.issue/v1`,
   `oidc-binding.issue/v1` usable credentials over HTTP) — fixture-seeded
   bindings in tests today.
3. Unauthenticated producer metadata (capture/manifest/readiness) — retained
   nonclaim by contract.
4. P-0006 same-UID hostile-process isolation and Windows containment —
   unchanged, outside this item.
