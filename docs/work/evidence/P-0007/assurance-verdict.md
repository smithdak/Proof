---
item_id: P-0007
review_gate: proof-assurance
verdict: unsupported
candidate_sha: c4b312d6f493936e15c2cc658277953ea18777f7
engineering_evidence_commit: 404d427670177f40570916dfa7d32aaae18926a4
reviewed_by: proof-assurance
reviewed_at: 2026-08-20T15:24:51.377Z
---

# P-0007 Assurance verdict

## Verdict

The bounded P-0007 claim is **unsupported** at candidate
`c4b312d6f493936e15c2cc658277953ea18777f7`. G4 and G11 each produced
reproducible, candidate-attributable contrary evidence on the exact candidate.
One unsupported row is dispositive under the ratified gate; the passing rows
cannot average either failure away.

This verdict records the failed candidate before Engineering attempts a new
candidate. It does not relabel historical candidate
`fede487547c3e2bb27f5cb8fb168f5b5312a5f23`, which remains independently
unsupported.

## Bound claim and execution context

| Field | Exact value |
| --- | --- |
| Claim | P-0007 satisfies its authorized localized-content scope and all acceptance criteria at the named SHA |
| Candidate | `c4b312d6f493936e15c2cc658277953ea18777f7` |
| Candidate parent | `2c4335c6ba307523ecbc6965adfeeddc4dcca9f9` |
| Original P-0007 base | `a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566` |
| Engineering revalidation base | `a95ee484b7038358c0d4e30167862dbed85728c0` |
| Engineering evidence commit | `404d427670177f40570916dfa7d32aaae18926a4` |
| Engineering branch | `proof-engineering/p-0007-finalization` |
| Temporary CI ref | `refs/heads/proof-assurance/p-0007-candidate` |
| Exact detached checkout | `D:\github\Proof\target\assurance-p0007-c4b312d` |
| Linux environment | Ubuntu 24.04.4 LTS under WSL2; kernel `5.15.167.4-microsoft-standard-WSL2`; Rust/Cargo 1.97.1; Node v22.23.1 |
| GitHub runner | `ubuntu-24.04` |

The detached candidate and evidence worktrees were clean. Assurance executed
the post-entry checks only after independently matching the candidate, packet,
and evidence-control topology.

## Engineering packet and exact-SHA CI

Evidence commit `404d427...` is a direct child of the candidate and changes
exactly the four P-0007 packet files plus the authorized item/map review-state
pair. Independent packet validation matched 34 of 34 candidate-path Git-blob
hashes, 18 of 18 manifest artifact hashes, all ten candidate-parent delta
paths, and the reported `4091` insertions / `273` deletions.

| Packet artifact | SHA-256 over Git blob bytes |
| --- | --- |
| `receipt.md` | `2d9a559a3ce96322de55841ccc7cebedc37ca10dff6b9d5b8076fa6bfabafba6` |
| `manifest.json` | `f264d6ac7d0d7d550a30ca1126d46a9611bbe59a55e1e05cfa4c5ad7cc9ffe86` |
| `traceability.md` | `59bf2393be5e24588bb5400c0d62aa572992600398ad8165fd20cd95870e9f7c` |
| `candidate-paths.sha256` | `daba75185c41c346da5acaecde9eecbc458807140582d5f13b0f2cabc4ad2f52` |

GitHub Actions run
[`32380862459`](https://github.com/smithdak/Proof/actions/runs/32380862459),
job
[`96463454459`](https://github.com/smithdak/Proof/actions/runs/32380862459/job/96463454459),
completed successfully at exact head SHA `c4b312d...` on
2026-08-20T14:36:06Z. All nine required steps succeeded. That supports G1; it
does not rebut path-specific contrary evidence found after entry.

## G1-G14 results

| Gate | Verdict | Direct evidence |
| --- | --- | --- |
| G1 | supported | Exact-candidate local gate: formatting, strict workspace/all-target/all-feature Clippy, 345 Rust tests, doc tests, 159 links, and seven work items; exact-SHA GitHub run `32380862459` passed. |
| G2 | supported | `localized_conformance_schemas_and_golden_artifacts_are_closed`; `localized_portable_artifacts_and_operation_instances_are_closed`; independent Draft 2020-12 validation plus RFC 8785/BLAKE3 recomputation matched 12 of 12 artifacts, rejected 12 substituted expected digests, and rejected widened/wrong-version Schema instances. |
| G3 | supported | Exact-candidate `localized_` focused run passed 7/7. Resource-operation, Context-operation, and Context-reconstruction matrices produced 128 expected failures, 19 exact-equality checks, and unchanged 13-table snapshots across missing, duplicate, substituted, key-only, digest, cross-link, resource-byte, manifest, row-metadata, and policy mutations. |
| G4 | **unsupported** | The public localized Release verifier stack-aborted on a self-referential v2 predecessor instead of returning a typed Integrity Problem. Eight preceding malformed-record cases rejected without changing the 23-table snapshot. Mechanism is `verify_localized_release` -> `load_localized_release` -> `load_release_selection` -> `verify_v2_release_record` -> `load_localized_release`; the sequence/environment guard occurs only after recursion at `crates/proof-local/src/localized.rs:7612-7619`. |
| G5 | supported | Exact ContextPack closure reconstruction, historical query, `max_bytes`, key-only, cross-link, missing/duplicate, exact-locale, and absent-locale cases passed. The independent lifecycle used exact `es-ES`/`fr-FR` targets and rejected `de-DE` without fallback. |
| G6 | supported | Independent application and Human CLI lifecycles reproduced two locale targets, three retained edits, two effective heads, two validation attempts, two committed renditions, signed Release verification, and exact query results. The external CLI transcript completed 48 commands: 31 successes and 17 expected Problems. |
| G7 | supported | `p0007_g7_separate_context_edit_and_validation_budgets_are_atomic` and `p0007_g7_raw_lineage_deletion_reorder_substitution_and_cycle_are_detected_read_only` passed. Object/byte/Edit/validation limits and deletion/reorder/substitution/cycle mutations returned stable errors with identical before/after domain-separated BLAKE3 snapshots. |
| G8 | supported | Independent exact-delta/pointer reconstruction passed. Missing target, extra same-scope row, wrong ChangeSet, ambient state change, and moved pointer all denied before Release attribution; Release tables and pointer snapshots were unchanged. Exact post-entry delta was `blake3:92ef0293479a2dcb303ca262669ad8be15d5a3d50c00ba0dd9e6ec998999a022`. |
| G9 | supported | Every source storage version v1-v10 rolled back after an injected migration failure, retained the legacy fingerprint, and converged on one retry to `11/11/11` with zero localized rows and one v1 Known-State artifact. Migration-history BLAKE3: `a5646ff029c832c071d24a76aadbffa564578ef4460072e95dd4cd1f97d2e166`. |
| G10 | supported | Four retained `p0007_assurance_g10_*` cases independently reconstructed locale revisions, Known State, and Environment pointer; repeated dry runs were deterministic/no-write, derived repair converged, and authoritative tamper failed closed. |
| G11 | **unsupported** | After create/add/validate/submit/approve/commit, an exact replay of the original `CreateLocalizedChangeSetCommand` returned the current committed aggregate, not the original empty draft required by the operation Schema and G11. Before/after logical-state BLAKE3 remained equal at `943c637ea686ce62eb463f3f338a87894c596a5ab1fb1af923e028660f23afb5`, so denial atomicity held but result equality failed. Source mechanism: replay loads and returns the mutable aggregate at `crates/proof-local/src/localized.rs:3222-3244`; the creation effect hard-codes draft while omitting mutable fields at `3328-3345`. |
| G12 | supported | Independent enumeration invoked all 17 localized trait surfaces through an Agent-mapped bootstrap identity; every surface failed closed before domain action and the logical snapshot remained `0db8c0c9b6b1356132916fa79cc61c6e6a99cadeb84c462ace0bdab3b00f54fa`. Disabled-Human issuance also failed closed with snapshot `731aca643f61a3d484db40fead56d3bcb9387a65438d2389153f6932d9d054d7`. No delegated mutation interface exists in P-0007. |
| G13 | supported | Three retained cases covered pre-write SQLite abort, mid-transaction abort after prior derived writes, and post-commit Release-proof export/replay recovery. Each rollback or retry converged exactly once. Scope is SQLite transaction/export failure, not power loss or SIGKILL. |
| G14 | supported | Independent Git-object reconciliation matched 34/34 candidate paths and the six-path evidence delta, found zero credential-shaped content, and confirmed no runtime database/key path or unrelated candidate-parent path. Checkout-materialization CRLF differences were excluded by the explicit Git-blob byte domain. |

## Commands and quantitative results

The load-bearing commands completed as follows:

```text
cargo fmt --all -- --check
  exit 0
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  exit 0
cargo test --locked --workspace --all-targets --all-features
  exit 0; 345 passed, 0 failed, 0 ignored
cargo test --locked --doc --workspace --all-features
  exit 0; six crate targets, 0 failures
node scripts/check-doc-links.mjs
  exit 0; 159 links
node scripts/check-work-items.mjs
  exit 0; seven items
npm exec --yes --package=markdownlint-cli2@0.23.2 -- markdownlint-cli2
  exit 0; 51 files, 0 issues
cargo test --locked -p proof-local --test initialize localized_ -- --nocapture
  exit 0; 7 passed, 0 failed
```

The disposable exact-candidate G4 harness invoked:

```text
CARGO_TARGET_DIR=.../g4-target CARGO_NET_OFFLINE=true TMPDIR=/tmp \
cargo test --offline --manifest-path .../g4-harness/Cargo.toml \
assurance_g4_localized_verifier_rejects_mutations_without_read_repair \
-- --exact --nocapture
```

The first eight mutations returned errors and unchanged snapshots. The ninth
set both `releases.previous_release_id` and
`localized_release_metadata.base_release_id` to the subject Release. The test
process terminated with `stack overflow`, signal 6 (`SIGABRT`). The transient
harness source SHA-256 was
`445419de61c7cf95370104cf939d1471cbbf4b6710a528080684cca11ebbd5d8`.

The exact-candidate G11 harness invoked:

```text
TMPDIR=/tmp CARGO_TARGET_DIR=.../assurance-g10-g14-c4b \
cargo test --locked --offline \
assurance_g11_create_replay_returns_mutated_aggregate_after_commit \
-- --nocapture --test-threads=1
```

The defect-asserting test passed 1/1 and reported original `draft`, zero edits,
null proposal/seal versus replayed `committed`, one edit, proposal
`blake3:86142afb3ed1cadc6166b65296a17998717baaaa97031c30931d309c559eec62`,
and seal
`blake3:d75916857fec1105034b03bf8383812e60e37b2500fb7c44c156be8dfd7c0d42`.
Its containing transient harness source SHA-256 was
`102676368bdf963b2d35eb8fa58ed280083f57094ead54671683809bab929e9d`.

## Supporting evidence, contrary evidence, and exclusions

Supporting evidence is substantial: the complete quality gate, independent
canonical recomputation, full Human application/CLI lifecycle, budget and raw
lineage matrices, exact delta/pointer denials, every-version migration
rollback/retry, independent derived-family rebuild, Human-only authentication,
SQLite recovery, and complete Git-object provenance all passed.

Contrary evidence is nonetheless decisive:

1. a persisted v2 Release predecessor cycle terminates the verifier process
   before its existing chronology guard can run; and
2. exact ChangeSet-create replay returns later mutable state rather than the
   original operation result.

No Windows product-runtime claim, non-SQLite adapter, network/provider path,
SIGKILL or power-loss durability, delegated Agent authority, locale deletion,
fallback, relationship traversal, or production/customer surface was
exercised or inferred. Repeating six human CLI commands with the same visible
flags also regenerates request-bound IDs/timestamps; this is a CLI retry
usability residual and is not represented as exact normalized-input replay.

## Falsification posture

The strongest counterargument is that operation-created Releases cannot form
the invalid graph and that ChangeSet creation may reasonably return the
resource's current representation. It is rejected. G4 explicitly requires a
fork/cycle verifier challenge, and a public verifier must fail closed on
invalid persisted ancestry rather than abort. G11 explicitly requires the
original result after lifecycle movement, while the ratified create-output
Schema fixes status to `draft`.

The crux is integrity parity on externally reachable reads and replays. Either
one of these paths behaving differently from its ratified contract invalidates
the bounded claim.

Observable falsifiers are exact-candidate reruns in which the same cyclic
Release returns a typed Integrity Problem without process termination and the
same post-commit create replay equals the original empty draft without a write.
Candidate c4 does neither. **Confidence: high**; both full call paths were
located and both failures were dynamically reproduced against exact c4 with
no compensating control.

This verdict applies only to bounded P-0007 at the named SHA. It grants no tag,
release, deployment, production, delegated-authority, customer, or commercial
claim.
