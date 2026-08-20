---
item_id: P-0007
review_gate: proof-assurance
verdict: supported
candidate_sha: 47153144b4b834cfffab61b328e4551f09fe50cb
engineering_evidence_commit: 8308ebfb9090270982fcfb06c8247ab423fcb51d
reviewed_by: proof-assurance
reviewed_at: 2026-08-20T18:40:20.012Z
---

# P-0007 independent Assurance verdict

## Verdict

`supported` for the bounded P-0007 claim at exact candidate
`47153144b4b834cfffab61b328e4551f09fe50cb` in the tested environments. Every
entry condition and G1-G14 row passed after Engineering evidence commit
`8308ebfb9090270982fcfb06c8247ab423fcb51d` entered the candidate into review.

This verdict does not relabel historical unsupported candidates
`fede487547c3e2bb27f5cb8fb168f5b5312a5f23` or
`c4b312d6f493936e15c2cc658277953ea18777f7`. Their findings remain historical
evidence. Candidate `4715314...` was reviewed as a new immutable candidate.

The supported claim is only:

> P-0007 satisfies its authorized scope and acceptance criteria at candidate
> `47153144b4b834cfffab61b328e4551f09fe50cb` in the tested environments.

It grants no tag, release, deployment, production, customer, translation
quality, legal, cultural, delegated Agent-authority, or general Windows-runtime
claim.

## Bound revision and evidence packet

| Field | Exact value |
| --- | --- |
| Original P-0007 base | `a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566` |
| Engineering revalidation base | `a95ee484b7038358c0d4e30167862dbed85728c0` |
| Candidate parent | `cc6f8777dbbec5af819b670662757fda2ae6d191` |
| Candidate | `47153144b4b834cfffab61b328e4551f09fe50cb` |
| Engineering evidence commit | `8308ebfb9090270982fcfb06c8247ab423fcb51d` |
| Branch | `proof-engineering/p-0007-finalization` |
| Temporary CI ref | `refs/heads/proof-assurance/p-0007-candidate` |
| Exact-candidate checkout | `D:\github\Proof\target\assurance-p0007-4715314` |
| GitHub Actions run | [`32391142771`](https://github.com/smithdak/Proof/actions/runs/32391142771) |
| GitHub Actions job | [`96497271205`](https://github.com/smithdak/Proof/actions/runs/32391142771/job/96497271205) |
| Review completed | `2026-08-20T18:40:20.012Z` |

The evidence commit is the candidate's direct child. Its delta is exactly these
six record paths:

- `docs/work/evidence/P-0007/candidate-paths.sha256`;
- `docs/work/evidence/P-0007/manifest.json`;
- `docs/work/evidence/P-0007/receipt.md`;
- `docs/work/evidence/P-0007/traceability.md`;
- `docs/work/items/P-0007-implement-localized-content-foundation.md`; and
- `docs/work/map.md`.

The evidence packet Git-blob SHA-256 values at `8308ebf...` are:

| Path | SHA-256 |
| --- | --- |
| `receipt.md` | `f58f32623658ccbab99b5ae47ecd1f0a9576e2269fcf00d7f2afbb9be38cfd88` |
| `manifest.json` | `d691bbb553e209c979e936463ab54f0c2eb804221335c0e3d67f7e0eeab32f88` |
| `traceability.md` | `71bf2235b5dbd97abb1162b8c662f204b56696cfe7a73fc5843fc95fa83ccd79` |
| `candidate-paths.sha256` | `6cb81e087ac57db4edbd94c33813c69f5d1f38cd9dd25594da05a0623345d7a3` |

Assurance recomputed the 35-path original-base inventory from Git objects:
`35/35` paths and hashes matched. All `18/18` manifest artifact digests matched
candidate Git blobs. The candidate-parent delta is exactly two paths, 419
insertions and 18 deletions. Candidate, evidence, and historical worktrees were
clean at their stated revisions.

## Environments and quality gate

- Ubuntu 24.04.4 LTS under WSL2 kernel
  `5.15.167.4-microsoft-standard-WSL2`;
- GitHub-hosted `ubuntu-24.04`;
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`;
- `cargo 1.97.1 (c980f4866 2026-06-30)`;
- Node `v22.23.1`; and
- Windows Git `2.43.0.windows.1` for topology and binary-safe Git-object
  reconciliation.

The exact-candidate local quality gate passed formatting, strict
workspace/all-target/all-feature Clippy, 353 Rust tests, documentation tests,
159 documentation links, and seven work-control records. The 353 tests were 5
application, 11 attestation, 14 canonical, 1 architecture, 28 CLI, 14 domain,
126 local integration, 1 localized conformance, 133 G10/G13 integration-binary,
3 G6/G7/G9 retained, 9 MCP unit, and 8 MCP protocol tests.

GitHub Actions checked out exact candidate `4715314...`; run `32391142771`, job
`96497271205`, completed at `2026-08-20T16:19:35Z`. Setup, checkout, pinned
toolchain installation and verification, formatting, Clippy, all tests,
documentation tests, documentation links, work-control validation, checkout
cleanup, and job completion all concluded `success`.

For the evidence/control-plane bytes, `git diff --check`, 159-link validation,
seven-item work-control validation, and `markdownlint-cli2 0.23.2` over 52
Markdown files all passed; Markdown lint reported zero issues.

## G1-G14 disposition

| Gate | Verdict | Independent and retained evidence |
| --- | --- | --- |
| G1 | `supported` | Exact candidate passed the complete pinned local Linux gate and exact-SHA GitHub job; the six-path evidence delta passed all record checks. |
| G2 | `supported` | Two Schemas, 14 artifact instances/branches, 11 operation contracts, and 22 operation members validated independently. Twelve canonical artifact digests were independently reconstructed; version and substituted-digest challenges diverged in all 12 cases. |
| G3 | `supported` | Eleven focused local-adapter cases exercised operation/effect uniqueness, reconstructed authority, cross-links, incomplete records, and direct-read parity with no read repair. |
| G4 | `supported` | Four integration tests passed. The external verifier matrix completed all nine focused cases with typed rejection and unchanged snapshots; the former ancestry-cycle process abort did not recur. |
| G5 | `supported` | The 11-case localized subset and one exact immutable-history/query case passed; complete request closure and exact-locale behavior matched independently derived application/CLI results. |
| G6 | `supported` | The Human CLI transcript completed 48 commands: 31 success and 17 expected Problems. Application parity performed six reads, matched four load-bearing digests, returned two exact renditions, and verified the Release with zero findings. |
| G7 | `supported` | Three retained G7/G9 tests passed. Separate Context object/byte, Edit, and validation budgets were atomic; deletion, reorder, substitution, and cycle lineage cases returned stable Problems without changing the challenged state. |
| G8 | `supported` | Five pre-promotion causality scenarios preserved paired Release-table and pointer hashes. All 13 digest-graph checks were true; no scenario attributed a Release or moved the pointer. |
| G9 | `supported` | Every source storage version v1-v10 preserved its source state after an injected migration failure, then converged to `11/11/11` on one retry with zero localized rows and stable legacy hashes. |
| G10 | `supported` | Seven combined G10/G13 tests passed; all three localized derived families rebuilt independently, repeated dry-runs were stable/no-write, and authoritative-history challenges failed closed. |
| G11 | `supported` | Three retained/external replay checks passed. Pointer-advanced replay returned originals; exact ChangeSet-create replay after commit returned the original empty Draft and identical before/after logical-state hashes. |
| G12 | `supported` | The independent all-surface test covered all 17 localized repository surfaces through non-Human and disabled-Human identities; every call failed before domain action and both logical snapshots stayed unchanged. No delegated authority is claimed. |
| G13 | `supported` | Pre-write, mid-transaction-after-prior-writes, and post-commit/pre-export cases followed the documented atomic/durable rule and converged once on retry. No power-loss claim is made. |
| G14 | `supported` | Candidate inventory `35/35`, artifact digests `18/18`, exact two-path candidate delta, exact six-path evidence delta, clean checkouts, packet hashes, scope reconciliation, and credential/personal-path scan all matched. |

## Canonical and Schema reconstruction

The independent Schema harness reported:

```text
schema_meta_valid=2
artifact_instances_valid=14
artifact_branches_covered=14
artifact_wrong_version_rejected=14
artifact_widened_rejected=14
operation_contracts_unique=11
operation_members_valid=22
operation_members_widened_rejected=22
operation_wrong_version_rejected=11
```

JSON Schema is the syntactic layer: it accepts format-valid digest replacement
and one semantically ordered-array reorder. The independent canonical layer
recomputed RFC 8785 bytes with artifact-specific BLAKE3 contexts, compared the
computed digest to the supplied expectation, and rejected substituted
expectations. All 12 version changes changed the digest. Stable digests were:

| Artifact | BLAKE3 digest |
| --- | --- |
| `ContentResourceIntentV1` | `77af41be20404fcc7b90b0b230197f6a3a8ae1610dd8299fc776d58fb5593a6c` |
| `PolicyBundleV1` | `048bbbdd221157876a9a512b4826eac8ee9d89c120ba2e1297f79edc3e21b812` |
| `ContextPackV2` | `b1e223666200760fe60eb28128ba79a5989132e9d47c0209961feb6cf1dbad17` |
| `EditV2` | `9704874cf53605356343835655bcd68f35ea502d05931c8f9fb943eb50b26c9a` |
| `EditBatchV2` | `23b627fc1d93121f393f6902626e71f0269bf5c6692928cf442d42be554b1203` |
| `ChangeSetV2` | `1a0e8a2c33f382c0bec575052f2ee56826d36daa72929261e0d2bb3f781deb91` |
| `ValidationResultsV2` | `1ce591d36859c933fd65708875ec37553a94c3232dc9df7fb01363c44faa0378` |
| `ObjectLocaleRevisionV1` | `292bab632a1a7215ff0ca5e4423dbe39b00032af3e3edfd9dc8b7a8cd2eee449` |
| `ObjectSetV2` | `7af57fbd475ec2c401055e1d9d182c46d76ecc5aa091d423199ce4af70f92cd9` |
| `KnownStateV2` | `818fe03b3a279e17f798c3c3fcdaf1a30a96c7a3b3128a17187feec3c6f253ee` |
| `EditionV2` | `cdd3346f8697a380554ab4bf37fb6969cf24bd9effd9df6c94c144d527736a47` |
| `ReleaseV2` | `80dde63545c7185a6243f9d531025f2186d326e44d5a47b4735841b8ae96713c` |

Restricted locale syntax/casing, literal alias behavior, pointer order and
escaping, overlap, array traversal, missing paths, non-string leaves, and
changes outside declared pointers remain covered by the exact candidate's
canonical and localized conformance suites.

## Direct reads, ContextPack, and verifier evidence

The post-entry exact-candidate localized subset passed `11/11`; the independent
immutable-history/query test passed `1/1`. The matrices cover resource-intent
and Context operation uniqueness/effects, reconstructed ContextPack policy and
resource closure, fixed object/byte limits, Edit-through-Release ancestry,
missing or duplicate operation evidence, key-only changes, row swaps,
cross-links, wrong target/locale/casing, stale source, unrelated scope, absent
locale, and v1/v2 history. Read attempts returned stable domain Problems and
did not repair governed records.

The external Release verifier matrix passed these nine cases, each with typed
rejection and an unchanged 23-table logical snapshot:

1. proof-envelope bytes;
2. matching but incorrect Release delta and digest;
3. incomplete metadata ancestry;
4. wrong proof subject statement;
5. unsupported proof version;
6. stale signing time;
7. mismatched Edition reference;
8. key-only operation-record change; and
9. a one-node v2 predecessor cycle.

The retained candidate tests additionally cover self-v2 rollback-target,
self-v2 predecessor, and two-node-v2 predecessor cycles plus a valid mixed
v1/v2 promotion/rollback chain. Invalid references are rejected before
recursive loading; no stack overflow, signal, or process abort occurred in the
post-entry run. The external G4 log SHA-256 is
`579ea1620d18e654cee79a1942f28c34692aaa1c80445064ffc257d9ffb13770`.

## Human lifecycle, causality, and application parity

The exact-candidate CLI transcript exercised two target locales, three retained
Edits, two effective heads, two validation attempts, two committed renditions,
two exact queried renditions, rollback to v1, and restoration to the exact v2
Release. It completed 48 commands: 31 successful operations and 17 expected
Problem envelopes. The exact-delta SHA-256 was
`2e98b8d757cba17723fe1ef31f7123e01eec46437988914a9674837379eaec8d`.

The independent application adapter performed six reads. Intent, ContextPack,
proposal, and effective-leaf digests matched the CLI values exactly; the
Release verified with zero findings. Five independently prepared G8 scenarios
preserved paired pre/post Release-table and Environment-pointer hashes. All 13
digest-graph checks were true.

Execution artifact SHA-256 values were:

| Artifact | SHA-256 |
| --- | --- |
| CLI summary | `a979a9b76f8d85827ddfd5fb17bb9ee001563536735c21f7dde6194e0400a3ec` |
| CLI transcript | `a5734f7ff453dd4e30100b881c6494543c47aca597aca4429419f2c58cfa31e7` |
| Application parity | `3dce924d94af9403d8e07c49b1de413578ed0043866a16ae2119dc8fde970eb8` |

G11's exact external create replay returned `draft`, zero Edits, no proposal,
and no seal both originally and after the ChangeSet had advanced through
commit. Its logical state was
`b98fa21ae40cea68c08b6afc748179b2b1fdbb4a382b420d61a02b86526f33ce`
before and after replay. The log SHA-256 was
`e24c72e816bf955f5c17be9f66d96a96bea8ceb9e75635195b42df63c49b8c03`.

## Budgets, lineage, migration, rebuild, and recovery

The retained G7/G9 binary passed `3/3`. Context object/byte, Edit-attempt, and
validation-attempt limits each returned the required stable Problem with
identical before/after domain-separated BLAKE3 state fingerprints. The four
lineage-order cases changed the challenged input fingerprint, returned an
integrity Problem on read, and left that challenged fingerprint unchanged.

Each storage source v1-v10 preserved source `user_version`, Schema, migration
history, and legacy fingerprint after its failure point. One retry reached
`11/11/11`, retained zero localized rows and one v1 Known State artifact, and a
second retry was stable. The migration-history BLAKE3 was
`a5646ff029c832c071d24a76aadbffa564578ef4460072e95dd4cd1f97d2e166`.
The G7/G9 execution log SHA-256 was
`341620dbd7fcbda2a989d28d14b12d9113425d0f8fa7e1ad8ec3f0ee03a41541`.

The combined G10/G13 binary passed `7/7`. Locale revision, Known State, and
Environment-pointer projections were checked independently. Repeated dry-runs
were equal and no-write; repair reproduced the independently expected rows and
the second dry-run reported no drift. Authoritative-history cases failed closed
without rewriting it. Pre-write and mid-transaction faults rolled back; the
post-commit/pre-export case retained durable evidence and replay materialized
the export exactly once. The execution log SHA-256 was
`5839a2fea5a0d077e61404fb7647e60815661c27eb9dc288cc7e2cdbdce2da8e`.

G12's all-surface run retained state hashes
`0db8c0c9b6b1356132916fa79cc61c6e6a99cadeb84c462ace0bdab3b00f54fa`
and `731aca643f61a3d484db40fead56d3bcb9387a65438d2389153f6932d9d054d7`
for the non-Human and disabled-Human scenarios respectively. The log SHA-256
was `131bfbe3fafb1e2385e98a86e82f4a33ef920fbc7a7bc38580bd46b1e124e8cb`.

## Contrary evidence, residuals, and falsifier

The strongest counterargument is that retained tests and implementation can
share the same mistaken helper, so a fully green candidate suite may still be
circular evidence. Assurance rejected that shortcut: it independently
validated Schemas and canonical digests, reconstructed application/CLI digest
parity, exercised the public Release verifier through a disposable harness,
checked ChangeSet replay through an external harness, compared direct logical
state hashes, and reconciled Git objects rather than checkout bytes. This
independent layer is what changes the result from Engineering qualification to
a supportable verdict.

No candidate-attributable contrary evidence remained after entry. The two
previous candidate findings were specifically re-exercised: the former Release
cycle now returns a typed error without process termination, and exact
ChangeSet-create replay now returns the original immutable result without a
write.

Residual boundaries remain:

- The local SQLite store has no external cryptographic anchor for a wholly
  self-consistent rewrite of every unsigned row and dependent digest. Partial,
  key-only, swapped, missing, cross-linked, and changed-effect cases are covered;
  total database forgery is not.
- G11 covers identical normalized typed application inputs. Six Human CLI
  operations and Edition creation generate required identities or times that
  are not repeatable from the same visible flags. Same-visible-command CLI
  retry is a UX/API residual and is not claimed.
- Valid v2 Release history remains recursive after the strict-decrease guard.
  The bounded lifecycle and cycle cases are supported; higher-cardinality
  acyclic history has no depth/stack-safety claim and remains outside P-0007.
- The G13 mid-transaction case proves SQLite transactional atomicity after
  earlier writes. It is not a power-loss, kernel-kill, or storage-controller
  qualification.
- Linux is the qualified runtime identity surface. Windows compilation passed
  strict all-target Clippy, but live Windows identity execution was not run.
- The Human path is supported. No Agent credential, DelegationV2 decision, or
  P-0004/P-0005 delegated mutation authority is implemented or inferred.

Observable falsifier: any exact-`4715314...` reproduction that returns success
for an invalid authoritative record, changes governed state on a denial/read,
diverges on identical typed-operation replay, moves a pointer before complete
Release attribution, changes a legacy fingerprint, fabricates localized rows,
fails a required pinned quality step, or contradicts the 35-path Git-object
inventory changes this verdict to `unsupported`. Evidence unavailability or
conflict changes it to `indeterminate`.

Confidence is high. The load-bearing basis is exact-SHA local and remote
quality success, post-entry independent execution of every G1-G14 row, direct
closure of both historical defects, unchanged-state proofs, and exact Git
provenance. The confidence does not extend beyond the residual boundaries
listed above.
