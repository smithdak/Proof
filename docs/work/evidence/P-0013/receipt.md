# P-0013 Engineering qualification receipt

## Outcome

Engineering qualification is supported for immutable P-0013 candidate
`1fb53b893b35cf3910f47b4d35ade59ceecfb62a`, tree
`cb6fb4a18cd68d4d232a167ca70363e90c3054e3`. The candidate implements the
remote evidence boundary and completes the Milestone 3 qualification wave:
the six-root uncompressed logical member map with deterministic paths and
closed violation taxonomy, keyed `evidence.export/v2` capture with
byte-identical replay and the separate no-key `evidence.export.get/v1`
lifecycle read, exact-triple artifact acquisition over its HTTP route, the
`proof-verifier/remote-authority/v1` and `proof-verifier/remote-evidence-v2`
modes under explicit caller trust, the closed `RemoteVerificationReportV2`
with its `conformanceReport` subtype and three retained scenarios, the
complete remote north-star (two Humans, one Agent) end to end over the HTTP
server and PostgreSQL reaching verifier `Complete`, the audited 158-row
finding-code rejection matrix, the completed crash matrix across all nine
retained boundaries, and a three-runner local/server conformance report.
The complete Linux quality gate passed at the candidate: rustfmt, clippy
`-D warnings` (zero warnings), 868 workspace tests in 77 binaries,
doc tests, 354 documentation links, and 13-item work-control validation.

This item carries `review_gate: project-owner`. This packet makes the item
eligible to move from `review` to `done` only after project owner `smithdak`
explicitly accepts the Milestone 3 exit evidence and residual boundaries.

The machine-readable revision, command, environment, inventory, digest, and
gate data are in `manifest.json`. Criterion-level AC1–AC11 coverage is in
`traceability.md`. These evidence files were created after the immutable
candidate and are intentionally absent from its Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0013 base / claim commit | `ab3071349162a945e698036070f72a64441e17ba` (claim `eeb9856`) |
| Skeleton commit / candidate parent | `fde6c2814533bd73c0d67553049a8709ac2fbc7f` |
| Candidate | `1fb53b893b35cf3910f47b4d35ade59ceecfb62a` |
| Candidate tree | `cb6fb4a18cd68d4d232a167ca70363e90c3054e3` |
| Qualified at | `2026-08-24T12:58:37.054Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 29 paths; 18,311 insertions; 50 deletions |
| Parent-to-candidate delta | 20 paths; 16,318 insertions; 127 deletions |
| New/extended test binaries | 56 tests across eight binaries named in `manifest.json` |
| Full gate | 868 tests passed, 0 failed, across 77 binaries |
| PostgreSQL under test | 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) via `scripts/dev-pg.sh`, schema-isolated |
| New third-party packages | 0 runtime (`proof-server` gained two dev-dependencies for harness reuse) |
| Frozen conformance vectors changed | 0 |

## Qualified implementation boundary

### Evidence bundle (`proof-remote::bundle`)

The exact uncompressed logical member map is validated against the manifest
and Release closure: two reserved descriptors accounted separately, frozen
root-kind ↔ path identity, deterministic nested artifact paths under
`content/artifacts/<kind>/blake3/<hex>.json`, per-member domain-separated
digest recomputation under RFC 8785 or raw-bytes canonicalization classes,
kind/digest/length agreement, and the closed Invalid taxonomy (absolute
paths, backslashes, dot segments, duplicates, undeclared or missing entries,
count and byte limits, 4,096-body maximum). External-required authority,
actor, and authentication roots are caller obligations, never producer
downloads. 26 tests pin this surface.

### Keyed export capture (`proof-server::export`)

`evidence.export/v2` commits one immutable `EvidenceExportCaptureV2` inside
the P-0010 serializable unit of work at the `pre-export-attempt-locked-heads`
boundary and always returns the exact pending create-result bytes; every
same-key equivalent replay returns those bytes unchanged even after assembly.
A worker assembles outside the transaction; a second transaction verifies the
bytes before pending-to-ready. The no-key `evidence.export.get/v1` performs
fresh authentication/authorization and returns the mutable status with null
digests while pending and the exact reserved digests/counts when ready.
Artifact acquisition is addressed by the exact
`(export_id, artifact_kind, digest)` triple; a digest under another kind is
not an alias. During implementation, integration found and fixed one real
producer defect: closure cross-links were derived from the export caller
(zero command digest) instead of the retained Agent attempt material, which
made verifier `Complete` unreachable; bindings now derive from the stored
`CommandInputV1` bytes, the signed authenticated-command DSSE envelope, and
the Release-closure environment configuration, and the north-star asserts
`Complete` end to end.

### Independent verifier (`proof-verifier`)

`remote-authority/v1` validates a canonical contiguous DSSE suffix from a
caller-pinned initial head through a closed single-active-key resolver;
sequence contiguity, predecessor linkage, head coherence, and signature
verification resolve keys independently of envelope self-assertions.
`remote-evidence-v2` validates membership, closure, companions, and every
Workspace, identity, command, policy, application-key, Release, Proof,
result, effect, decision, consequence, and authority-head link without any
producer database, network, or authenticated base state. Producer hint
arrays are inert; capture/readiness/latest-history claims stay excluded from
`Complete`. The three retained scenarios classify exactly:
complete materialization → `Complete`; required OIDC opening withheld →
`Incomplete [missing-disclosure]`; deterministic
`object_locale_revision_v1` byte tamper → `Invalid [tampered-artifact]`.

### Qualification matrices

The rejection matrix is the frozen registry of 158 finding codes
(156 report + 2 CLI diagnostics): all 30 direct-behavioral override targets
resolve to real passing tests asserting their exact codes; the other 128 are
structural guards frozen by the source-to-registry equality test, whose
coverage partition is now asserted exhaustive and disjoint, including the
remote modules. The crash matrix covers all nine retained boundaries —
artifact preparation and authoritative transaction windows at the PG layer
in `crash_matrix_m3.rs` (10 tests), outbox claim/send/acknowledgement, lease
expiry, retry, poison handling, replay, and preview application pinned by the
P-0012 worker/delivery suites, with five new interruption-and-recovery tests
closing the documented gaps. The conformance report drives one sequence
through the shared oracle on SQLite and PostgreSQL plus the HTTP server,
producing a canonical BLAKE3-digested report
(`blake3:e55b59da7b492dbc1b019579b9270ceb92fd934271484e9b88e5f7bffd8a0770`,
9,290 canonical bytes) whose every step is byte-matched where both modes
define typed semantics or explicitly classified otherwise.

### Architecture boundary amendment

Since Milestone 3 the verifier consumes exactly one shared contract crate:
`proof-remote` (frozen wire types, registries, envelope codecs). The
dependency guard in `crates/proof-cli/tests/architecture.rs` was amended from
"no transitive proof-* dependency" to the M3 boundary: the verifier may reach
the shared contract crate and its inward dependencies but must never link
`proof-server`, `proof-cli`, `proof-mcp`, `proof-pg`, `proof-delivery`, nor
any HTTP server stack or database driver (`rusqlite` is admitted only via the
contract crate's local-evidence reader). Independence semantics are
unchanged: no producer session, database, network, or authenticated base
state exists in the verifier, and caller-supplied trust remains the only
trust root.

## Residual boundaries

Recorded verbatim in `manifest.json.limitations`:

- Byte-identical local/server traces for full mutation semantics require the
  deferred PostgreSQL-backed application semantic executor (the ratified
  P-0010 "not yet mirrored" residual); the conformance report classifies
  every such step explicitly instead of claiming parity.
- Agent enrollment and OIDC Human binding routes commit governed effects but
  usable credential bindings are fixture-seeded in tests; route-complete
  enrollment remains successor work.
- Export metadata (capture, manifest, assembly, readiness) is unauthenticated
  producer metadata by contract.
- No deployment, provider, live OIDC issuer, push, tag, public release, or
  production mutation occurred. Same-UID hostile-process isolation and
  Windows containment residuals from P-0006 are not addressed by this item.

## Post-candidate polish commit

A follow-up correction commit `509c6e05bd84f81744679482689ce6ae7007eba5`
(parent `0078450`) was applied after qualification during integration
self-review: the verifier now narrows to the retained content-tamper
conformance scenario only when a nested content artifact tampers, while a
tampered non-content root stays general `InvalidVerification` (reason code
`TamperedArtifact` unchanged), with a regression test; stale P-0012-era
skeleton doc comments in `proof-delivery` were corrected and the verifier
CLI reference gained the two Milestone 3 remote modes. The complete Linux
quality gate re-passed at this commit: 869 tests in 77 binaries, clippy
`-D warnings` with zero warnings, doc tests, 357 documentation links, and
13-item work-control validation.

## Gate evidence

Exact commands, exit codes, environment versions, inventory counts, and
artifact digests are bound in `manifest.json`. The candidate commit and tree
hashes above are reproducible with `git rev-parse` at the named branch.
