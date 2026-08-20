# P-0007 Engineering qualification receipt

## Outcome

Engineering qualified item-work candidate
`c4b312d6f493936e15c2cc658277953ea18777f7` from a clean detached checkout.
The pinned Ubuntu gate passed locally and in GitHub Actions at that exact SHA.
The local gate comprised formatting, strict workspace/all-target/all-feature
Clippy, 345 Rust tests, documentation tests, 159 internal documentation links,
and all seven work-control records. GitHub Actions run
[`32380862459`](https://github.com/smithdak/Proof/actions/runs/32380862459)
completed every required step successfully; no required step was skipped,
cancelled, neutral, or failing.

This candidate supersedes, but does not relabel, historical candidate
`fede487547c3e2bb27f5cb8fb168f5b5312a5f23`. Assurance found that the historical
candidate did not reconstruct all ContextPack authority and returned mutable
precondition failures instead of original results for three lifecycle-advanced
replays. Candidate `c4b312d...` repairs those defects and retains focused
falsification tests for their failure mechanisms.

This receipt is Engineering evidence, not an Assurance verdict. At this
commit, P-0007 is in `review`, Assurance remains `indeterminate`, and the
bounded claim is not reactivated. No tag, release, deployment, production, or
customer claim follows from qualification.

## Revision topology

| Field | Exact value |
| --- | --- |
| Original P-0007 base | `a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566` |
| Engineering revalidation base | `a95ee484b7038358c0d4e30167862dbed85728c0` |
| Historical unsupported candidate | `fede487547c3e2bb27f5cb8fb168f5b5312a5f23` |
| Candidate parent | `2c4335c6ba307523ecbc6965adfeeddc4dcca9f9` |
| Candidate SHA | `c4b312d6f493936e15c2cc658277953ea18777f7` |
| Engineering branch | `proof-engineering/p-0007-finalization` |
| Temporary CI ref | `refs/heads/proof-assurance/p-0007-candidate` |
| Fresh Assurance checkout | `D:\github\Proof\target\assurance-p0007-c4b312d` |
| Evidence commit | The Git commit containing this packet; bound by the Assurance verdict rather than self-referenced here |
| Main at qualification time | `a95ee484b7038358c0d4e30167862dbed85728c0` |

The candidate is reachable from the reviewed branch and the temporary CI ref.
Its fresh checkout printed the exact SHA before execution and remained clean
after execution. `candidate-paths.sha256` inventories all 34 paths changed from
the original P-0007 base using SHA-256 over Git blob bytes at the candidate.
This byte domain is independent of CRLF/LF checkout materialization. The ten
paths changed from the candidate parent are separately identified in
`manifest.json`.

## Candidate repair scope

The candidate-parent delta contains ten paths:

- `Cargo.lock` and `crates/proof-local/Cargo.toml` add only the existing
  workspace `blake3` and `serde_json_canonicalizer` packages as test-only
  dependencies;
- `conformance/v2/localized-content/schemas/operations.schema.json` fixes the
  canonical artifact Schema reference;
- `operation-instances.valid.json` supplies valid input/output instances for
  all 11 localized operation contracts;
- `portable-artifacts.valid.json` adds independently checked Edition delta and
  Release proof-predicate vectors;
- `crates/proof-local/src/localized.rs` verifies unique, effect-bound resource
  intent and ContextPack operations, reconstructs exact ContextPack closure and
  budget constraints on read, and performs replay lookup before mutable
  lifecycle preconditions;
- `initialize.rs` and `localized_conformance.rs` retain the repaired replay,
  integrity, canonicalization, Schema, and mutation cases; and
- `p0007_assurance_g6_g9.rs` plus `p0007_assurance_g10_g13.rs` retain budget,
  lineage, migration, projection, and recovery matrices.

No Agent credential, delegated authorization, network service, provider,
translation system, UI, locale fallback, rendition deletion, relationship
traversal, or production integration was added.

## Exact qualification

### Environment

- Ubuntu 24.04.4 LTS under WSL2, kernel
  `5.15.167.4-microsoft-standard-WSL2`;
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`;
- `cargo 1.97.1 (c980f4866 2026-06-30)`;
- Node `v22.23.1`; and
- Windows Git `2.43.0.windows.1` for worktree, Git-object, and normalized-diff
  checks.

### Local exact-SHA gate

All commands ran with `--locked`; Rust build output was isolated under
`D:\github\Proof\target\assurance-c4b-build`.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 345 passed, 0 failed, 0 ignored |
| `cargo test --locked --doc --workspace --all-features` | six crate targets, 0 failures |
| `node scripts/check-doc-links.mjs` | 159 links passed |
| `node scripts/check-work-items.mjs` | seven items passed |

The 345 Rust tests comprise 5 application, 11 attestation, 14 canonical, 1
architecture, 28 CLI, 14 domain, 122 local integration, 1 localized
conformance, 129 G10/G13 integration-binary tests, 3 G6/G7/G9 retained tests,
9 MCP unit, and 8 MCP protocol tests. The G10/G13 binary deliberately includes
the 122 local integration cases plus seven focused cases, so 122 cases execute
twice in the workspace total.

### GitHub exact-SHA gate

Run `32380862459`, job `96463454459`, checked out candidate
`c4b312d6f493936e15c2cc658277953ea18777f7` and completed on
2026-08-20 at 14:36:06 UTC. Setup, checkout, pinned-toolchain installation and
verification, formatting, Clippy, all tests, documentation tests,
documentation-link validation, work-control validation, checkout cleanup, and
job completion all concluded `success`.

## Required Engineering evidence matrices

### Canonical and operation contracts

The conformance corpus contains closed artifact and operation Schemas, the
artifact digest vectors, 11 operation registry entries, 22 operation input and
output instances, and portable Edition/Release cases. Retained tests validate
every fixture, recompute RFC 8785 canonical bytes and BLAKE3 digests without
trusting stored expected values, and reject widened or substituted values.
Exact Git-blob SHA-256 values are in `manifest.json` and
`candidate-paths.sha256`.

### Source-to-rendition lifecycle

| Phase | Retained result |
| --- | --- |
| Baseline | Exact v1 Object/Schema/Known State and a Human-authenticated immutable intent for `es-ES` and `fr-FR`. |
| Invalid attempt | A prohibited French claim remains immutable and contributes to the attempt and validation budgets. |
| Repair | A valid superseding Edit forms one acyclic effective head; complete attempt lineage remains bound into validation and approval. |
| Commit and Edition | Exact source and target preconditions produce the expected two-rendition delta without ambient state. |
| Release and query | Promotion uses compare-and-swap pointer semantics; exact `es-ES` and `fr-FR` queries succeed, while absent or mis-cased locales do not fall back. |
| Cross-version | Rollback to v1 hides renditions; restoration to the exact v2 Release reproduces both and verifies. |

The application and CLI lifecycle tests both pass at the exact candidate. The
direct adapter and CLI expose the same identifiers, digests, transitions,
Problems, and normalized result shapes for equivalent operations.

### Denial, lineage, and budget matrix

Retained cases reject stale source and target references, wrong
Object/Schema/locale, non-localizable changes, duplicate active targets,
cross-target supersession, missing or wrong repair evidence, fork, skipped
predecessor, cycle, edits after sealing, and lifecycle operations before their
required prior state. Context object/byte, Edit-attempt, and
validation-attempt budgets return `LimitExceeded` with identical typed BLAKE3
state fingerprints before and after. Raw deletion, reorder, substitution, and
cycle injection returns `Integrity`, leaves the injected database fingerprint
unchanged, and never repairs authoritative history.

### Replay matrix

Exact replay and changed-input/key reuse are retained for all seven
consequential localized operations: issue intent, build ContextPack, create
ChangeSet, add Edits, commit, promote, and rollback. Identical replay returns
the original result after later Environment pointer movement. Changed input,
target, malformed freshness/target values, key aliasing, missing operation
evidence, two-row key swaps, and lifecycle-position reuse fail without
duplicate facts, pointer movement, or overwritten evidence.

### Migration matrix

Every source storage version v1-v10 is faulted independently during v11
migration. Each injected failure preserves the source `user_version`, migration
history, Schema, and a domain-separated BLAKE3 legacy fingerprint. One retry
reaches `11/11/11`, preserves the legacy fingerprint, creates zero localized
rows, and retains exactly one v1 Known State artifact. A second retry is stable.

### Rebuild and recovery matrix

Locale, Known State, and Environment-pointer projections are corrupted one
family at a time. Repeated dry-runs are byte/digest equal and perform no writes;
repair reconstructs independently expected rows and a second dry-run reports
no drift. Authoritative tamper fails closed in both modes. Pre-write and
mid-transaction SQLite aborts leave commit snapshots unchanged and converge on
one retry. A post-commit/pre-export failure retains durable release evidence;
replay repairs the export once and then remains stable.

The mid-transaction injection proves SQLite transactional atomicity after
earlier writes in the same transaction. It is interruption-equivalent evidence
for that boundary, not a power-loss, kernel-kill, or storage-controller test.

## Disposition and residual boundary

Engineering recommends `RESTORE` only if independent Proof Assurance records
every G1-G14 row as `supported` against this exact candidate and binds this
evidence commit. The strongest alternative is `REVISE`: it becomes mandatory
if the independent run finds any candidate-attributable integrity,
atomicity, causality, replay, migration, provenance, or quality-gate failure.

One architectural trust-boundary residual remains: the local SQLite database
has no external cryptographic anchor for an original idempotency key. A simple
key-only mutation, row swap, cross-link, or changed effect is detected. An
omnipotent actor able to rewrite a key and every dependent unsigned row digest
self-consistently is outside the bounded local-store integrity claim. This does
not weaken the tested fail-closed behavior for partial corruption, but the
candidate must not be described as tamper-proof against total database forgery.

The tested runtime identity surface is Linux and the authenticated local Human
adapter. Windows compilation passed through strict all-target Clippy, but live
Windows identity execution was not qualified. No delegated Agent authority is
implemented or claimed.

## Evidence paths

- `docs/work/evidence/P-0007/receipt.md`
- `docs/work/evidence/P-0007/manifest.json`
- `docs/work/evidence/P-0007/traceability.md`
- `docs/work/evidence/P-0007/candidate-paths.sha256`
