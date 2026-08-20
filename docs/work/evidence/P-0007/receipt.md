# P-0007 Engineering qualification receipt

## Outcome

Engineering qualified replacement item-work candidate
`47153144b4b834cfffab61b328e4551f09fe50cb` from a clean detached checkout.
The pinned Ubuntu gate passed locally and in GitHub Actions at that exact SHA.
The local gate comprised formatting, strict workspace/all-target/all-feature
Clippy, 353 Rust tests, documentation tests, 159 internal documentation links,
and all seven work-control records. GitHub Actions run
[`32391142771`](https://github.com/smithdak/Proof/actions/runs/32391142771)
completed every required step successfully; no required step was skipped,
cancelled, neutral, or failing.

Candidates `fede487547c3e2bb27f5cb8fb168f5b5312a5f23` and
`c4b312d6f493936e15c2cc658277953ea18777f7` remain historical unsupported
candidates; this packet does not relabel either one. The retained
`assurance-verdict.md` applies only to `c4b312d...`: its G4 verifier challenge
found recursive v2 ancestry could stack-abort before chronology checks, and
its G11 challenge found exact ChangeSet-create replay returned the later
committed aggregate instead of the original empty Draft result. Replacement
candidate `4715314...` repairs those two mechanisms and retains their focused
regressions.

This receipt is Engineering evidence, not an Assurance verdict. At this
commit, P-0007 is in `review`, Assurance remains `indeterminate`, and the
bounded claim is not reactivated. No tag, release, deployment, production, or
customer claim follows from qualification.

## Revision topology

| Field | Exact value |
| --- | --- |
| Original P-0007 base | `a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566` |
| Engineering revalidation base | `a95ee484b7038358c0d4e30167862dbed85728c0` |
| Historical unsupported candidates | `fede487547c3e2bb27f5cb8fb168f5b5312a5f23`; `c4b312d6f493936e15c2cc658277953ea18777f7` |
| Candidate parent | `cc6f8777dbbec5af819b670662757fda2ae6d191` |
| Candidate SHA | `47153144b4b834cfffab61b328e4551f09fe50cb` |
| Engineering branch | `proof-engineering/p-0007-finalization` |
| Temporary CI ref | `refs/heads/proof-assurance/p-0007-candidate` |
| Fresh exact-candidate checkout | `D:\github\Proof\target\assurance-p0007-4715314` |
| Evidence commit | The Git commit containing this packet; not self-referenced and not bound by the historical c4 verdict |
| Main at qualification time | `a95ee484b7038358c0d4e30167862dbed85728c0` |

The candidate is reachable from the reviewed branch and the temporary CI ref.
Its fresh checkout printed the exact SHA before execution and remained clean
after execution. `candidate-paths.sha256` inventories all 35 paths changed from
the original P-0007 base using SHA-256 over Git blob bytes at the candidate.
This byte domain is independent of CRLF/LF checkout materialization. The two
paths changed from the candidate parent are separately identified in
`manifest.json`.

## Candidate repair scope

The candidate-parent delta contains exactly two paths and 419 insertions / 18
deletions:

- `crates/proof-local/src/localized.rs` reconstructs and effect-checks the
  immutable ChangeSet creation snapshot on exact replay, returning the original
  empty Draft after later lifecycle transitions. It also shallow-checks each v2
  predecessor and rollback target for workspace/Environment identity, strictly
  lower release sequence, and non-later release time before recursion; and
- `crates/proof-local/tests/initialize.rs` retains the post-commit exact-create
  replay/no-write regression, self-v2 predecessor and rollback-target cycle
  denials, a two-node-v2 predecessor-cycle denial, and the valid mixed v1/v2
  chain.

The strict-decrease ancestry contract excludes cycles without an arbitrary
depth cap. The original-base inventory still contains the already-qualified
localized-content implementation, conformance corpus, and test-only `blake3`
and `serde_json_canonicalizer` dependency exposure; this replacement delta adds
no dependency.

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
`D:\github\Proof\target\assurance-4715314-build`.

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | exit 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 353 passed, 0 failed, 0 ignored |
| `cargo test --locked --doc --workspace --all-features` | six crate targets, 0 failures |
| `node scripts/check-doc-links.mjs` | 159 links passed |
| `node scripts/check-work-items.mjs` | seven items passed |

The 353 Rust tests comprise 5 application, 11 attestation, 14 canonical, 1
architecture, 28 CLI, 14 domain, 126 local integration, 1 localized
conformance, 133 G10/G13 integration-binary tests, 3 G6/G7/G9 retained tests,
9 MCP unit, and 8 MCP protocol tests. The G10/G13 binary deliberately includes
the 126 local integration cases plus seven focused cases, so 126 cases execute
twice in the workspace total.

### GitHub exact-SHA gate

Run `32391142771`, job `96497271205`, checked out candidate
`47153144b4b834cfffab61b328e4551f09fe50cb` and completed on
2026-08-20 at 16:19:35 UTC. Setup, checkout, pinned-toolchain installation and
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

Historical verification shallow-checks each v2 predecessor and rollback target
before recursive loading. Self-v2 predecessor and rollback-target references
and a two-node-v2 predecessor cycle now fail closed with unchanged governed
snapshots; the valid mixed v1/v2 chain still verifies.

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
the original result after later lifecycle and Environment pointer movement. In
particular, exact ChangeSet-create replay after commit returns the original
Draft with empty Edits and no proposal or seal, not the current committed
aggregate. Changed input, target, malformed freshness/target values, key
aliasing, missing operation evidence, two-row key swaps, and lifecycle-position
reuse fail without duplicate facts, pointer movement, or overwritten evidence.

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

G11 covers exact replay of the seven typed application operation inputs. The
Human CLI supplies required operation identities and timestamps that are not
repeatable from the same visible flags for six operations and Edition creation;
same-visible-command CLI retry is therefore an adapter UX residual, not a
qualified replay claim.

Valid v2 history verification remains recursive after the new strict-decrease
guard. The bounded lifecycle and cycle cases are qualified, but a
higher-cardinality acyclic Release chain has not been depth-stress-tested and
has no stack-safety claim. Higher-cardinality scale remains outside P-0007.

## Evidence paths

- `docs/work/evidence/P-0007/receipt.md`
- `docs/work/evidence/P-0007/manifest.json`
- `docs/work/evidence/P-0007/traceability.md`
- `docs/work/evidence/P-0007/candidate-paths.sha256`
