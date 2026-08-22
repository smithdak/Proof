# P-0006 Engineering qualification receipt

## Outcome

Engineering qualification is supported for bounded P-0006 candidate
`ea35e093daed50017684f7da53373cbb70af753a`. The immutable candidate passed
the complete Linux gate and retained portable-verifier, Milestone 2
north-star, migration, transport-parity, and distinct-UID containment probes.
It is eligible for project-owner review only: owner acceptance has not
occurred, residual risks have not been accepted on the owner's behalf,
Milestone 2 is not yet complete, and no publication or deployment action was
taken.

The machine-readable candidate inventory, exact command results, conformance
digests, audit dispositions, and limitations are in `manifest.json`. The
criterion-level C1-C24 mapping is in `traceability.md`. Those evidence files
were created after the immutable candidate and are intentionally absent from
its 54-Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-engineering/p-0006-milestone-2-closure` |
| P-0006 base | `0a5becaf9794d81c9a5b1d7118e190b16dd247d2` |
| Claim commit | `4c613972edf290d3ecd2f9e012241da7ee631c02` |
| Candidate parent | `50fef1d5244ddee5aac02a70422f722d37ab1f12` |
| Candidate | `ea35e093daed50017684f7da53373cbb70af753a` |
| Candidate tree | `744884146924b555101f0995827fa3e987776e34` |
| Qualified at | `2026-08-22T22:31:15Z` |
| Base-to-candidate commits | 4 |
| Base-to-candidate inventory | 54 paths; 31,469 insertions; 75 deletions |
| Parent-to-candidate delta | 34 paths; 9,676 insertions; 656 deletions |
| Exact Git-blob inventory | 54 of 54 candidate blobs bound by SHA-256 |

The candidate adds the workspace packages `proof-agent-signer` and
`proof-verifier`. `Cargo.lock` adds only those two internal package records;
it adds no third-party package record. The new crates use already pinned
workspace dependencies, and `proof-cli` exposes its already pinned `rustix`
dependency directly for path-boundary checks.

Nothing in this packet authorizes or records a live remote check, push, tag,
release, publication, deployment, production mutation, or customer proof.

## Qualified implementation boundary

The candidate adds a portable `AuthorityEvidenceBundleV1` export path and a
standalone `proof-verifier`. The verifier does not depend on the producer-side
local Workspace or its Proof reconstruction code. It strictly parses and
canonicalizes supplied bytes, validates domain-separated digests and DSSE
signatures, replays the disclosed authority prefix, evaluates caller trust and
the independent authority-head checkpoint, and independently reconstructs the
Release, policy, approval, Edition, ChangeSet, validation, schema/object, and
localized-consequence closure.

The public result is deterministic and separates `complete`, `incomplete`, and
`invalid`. The CLI freezes semantic exits `0`, `20`, and `21`, and usage/input
exit `64`. Required unavailable evidence yields Incomplete. Conclusive supplied
tamper, contradiction, or semantic falsity yields Invalid; bounded unresolved
or malformed cases are listed under residual risks. A valid Release signature
alone cannot produce a complete authority or content verdict.

The historical v1 path is constructive rather than declarative. It verifies a
canonical omitted-empty genesis, one-based Edits, cumulative ChangeSet
prefixes, exact predecessor/rollback ancestry, producer-exact Known State and
Edition shapes, Human approval identity, Release policy evidence, Draft
2020-12 meta-validation, object-instance validation, and reconstructed state
digests. The v2 path binds the exact delta, intent, ContextPack, approval,
Human/Agent identities, command presentation, signed localized consequence,
canonical result, raw application effect, and Release pointer transition.

The final falsification pass also aligned two subtle producer boundaries. A
signed command may be issued up to 30 seconds after authorization evaluation,
and its maximum 300-second lifetime is compared at nanosecond precision. A
legitimate mapped `context.build/v2` NotFound result may carry
`context: null`; that narrow fallback is reachable only through the exact
signed failure/result/effect companion and still reconstructs the immutable
resource intent, normalized limits, and
`created_at <= evaluated_at < expires_at`. Successful Context builds continue
to require an exact ContextPack.

## Storage v14 and historical compatibility

Storage v14 persists the canonical command input and parsed signed
authenticated-command envelope bytes and digests before the corresponding
signed decision. Presentation persistence, consumption, decision, localized
consequence, result, application effect, and application-key ownership remain
inside the same immediate SQLite transaction.

Every supported source version v1 through v13 migrates atomically to v14. The
migration records an immutable cutover at `MAX(authority_sequence) + 1`, creates
an empty strict presentation table, and fabricates no historical presentation
bytes. A pre-v14 decision whose exact presentation preimages cannot exist is
exported with explicit external commitments. Injected migration failure rolls
back all three version markers and Schema changes; retry converges to stable
v14 and a repeated retry is a no-op.

An independent storage audit found no migration, persistence, transactionality,
or replay blocker. Its one non-blocking test-coverage note is that runtime
checks all seven v14 triggers and directly tests immutable replacement, while
separate direct UPDATE and DELETE trigger probes are not retained.

## Retained Milestone 2 north-star

The north-star starts from a locale-neutral v1 Release, creates a bounded
Human-owned localized intent and ContextPack, and delegates the same typed
operation path to an Agent. A prohibited French claim produces structured
validation findings. A superseding repair retains the invalid attempt and
repair edge, passes deterministic validation, is submitted, receives a
separate enabled-Human approval, commits atomically, creates an immutable v2
Edition and Release, and independently verifies exactly the Spanish and
French renditions without locale fallback or a hitchhiking Object.

Application, the real `proof` CLI, modern MCP, and legacy MCP produce the same
operation, actor, authority, result, and governed-state projections. Text
receipts are asserted field-for-field as projections of the structured JSON
receipt. Prompt-like content remains inert rendition data.

The retained containment test launches the Workspace-blind signer under
bubblewrap UID/GID `65534` with `--unshare-all`. The Agent cannot see the
repository, Workspace, private keys, ambient Human CLI, or an Agent-selected
path or argv. It receives only fixed framed stdin and typed MCP inputs. Path,
file, Workspace, raw-CLI, unknown-tool, and path-shaped MCP substitutions are
rejected before broker storage mutation.

The clean verifier also runs under UID/GID `65534` in a different network
namespace with no `/etc/resolv.conf`. It sees a read-only bundle and a
two-file caller-input directory containing only trust and checkpoint. Producer
`.proof` state and Agent credentials are deleted before verification, and the
test scans every bundle path and byte stream for raw UID, subject blind,
credential, private-key, and host-path canaries.

## Portable conformance

The frozen Complete fixture contains 44 descriptors: 43 included artifacts
and one optional requesting-subject-opening external commitment. It pins
Workspace `019c0000-0000-7000-8000-000000000001`, Release
`019c0000-0000-7000-8000-00000000000f`, and authority head sequence 5. Include
and Withhold modes prove the same public subject commitment; requiring the
withheld opening changes the result to Incomplete, while a supplied
noncanonical blind is Invalid.

| Outcome | Bundle manifest | Trust policy | Canonical report |
| --- | --- | --- | --- |
| Complete | `blake3:3db6b86c7b2d5cd83c3deda353d049f65634ce2518b198d49ae5cb72deae1aaa` | `blake3:4399579437187e55169c87a5f819fe5684c562a6a059018d2e8f8f407e618518` | `blake3:0a8345a9494144d66345c79779fe74a8d0bb781d0e4a9b5f84b5e133901f2c06` |
| Incomplete | Complete bundle | `blake3:9061d60697183b04270351c902fcdf1628fd56975cba6b4f43d71c4e6644f492` | `blake3:53f03ecceb7871fe02fb611418ce6e2fff66aba653ed66f6b15fd51439a61709` |
| Invalid | `blake3:23ab44c867424fe080c9ebae3928c7e43d15023fdf43cff82a8827d3efc3db3a` | Complete trust | `blake3:16c7e5984838546ea90bf058dbff5164efd14a6441c0160795e0c97112a2b9bd` |

The shared checkpoint digest is
`blake3:547bc64adb06fbe51e6cea46178bc9264f25d0351b193634f82bf0cbf49f291d`.
Exact SHA-256 values for every frozen file and every candidate Git blob are in
`manifest.json`.

The closed public registry contains 158 `proof.verify.` codes: 156 structured
report findings and two CLI diagnostics. Thirty are direct-behavioral
classifications that name a retained exact-code assertion. The other 128 are
structural guards covered by exact emitted-source/registry set equality.
Registry membership does not claim an independent branch-level test for each
structural guard.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| Strict workspace/all-target/all-feature Clippy | Passed with warnings denied; no issues |
| Locked workspace/all-target/all-feature tests | 604 passed across 36 suites; 0 failed; 366.90s |
| Locked workspace doc tests | Seven doc-test executables; 0 failures |
| Documentation links | 168 passed |
| Work-control validation | Seven items passed |
| Git diff and status | Diff check passed; worktree clean |
| Candidate identity | HEAD remained `ea35e093daed50017684f7da53373cbb70af753a` |

The complete test command ran with Linux namespace capability so the
bubblewrap tests executed rather than being skipped. Same-content focused runs
before the immutable commit recorded 79 verifier tests, two north-star and
containment tests, 323 authority/migration/assurance tests, and 32
CLI/transport/architecture tests with no failure. The immutable-SHA aggregate,
not those focused counts, is the controlling complete gate.

## Falsification result

Independent producer/verifier parity review repeatedly challenged the bundle
for both false Complete and false Invalid outcomes. Concrete defects found
during that review were repaired before the candidate: conservative
Incomplete verdict contamination, shallow historical v1 replay, omitted exact
policy shapes, approval and Release chronology, 0-based v1 Edit acceptance,
schema/object validation trust, command skew and fractional lifetime mismatch,
and mapped Context NotFound rejection. A separate full-diff audit found no
test weakening, debug artifact, scope overreach, migration blocker, or other
candidate-attributable production defect after those repairs.

The strongest counterargument is that a self-consistent signed bundle can
still overclaim if an independent verifier trusts producer labels, omits a
causal or content cross-link, treats unavailable evidence as valid, or runs
with producer Workspace authority. The candidate answers that argument for
the disclosed bounded closure: the verifier reconstructs the evidence under
explicit caller trust and an independent authority checkpoint, and the clean
distinct-UID run has no producer database, private key, network resolution, or
ambient privileged interface.

## Residual risks and nonclaims

The project owner must explicitly evaluate these boundaries before acceptance:

- The checkpoint pins the supplied authority head. It does not prove that no
  omitted same-Environment signed Release exists, or that the supplied Release
  is globally latest or the true immediate Release history.
- Exported EnvironmentConfig does not contain Environment `created_at`. The
  verifier checks Release chronology against v2 Edition creation, but cannot
  independently prove Release-after-Environment-creation.
- A signed v2 approval carries approver and `approved_at`, but no exact
  authority causal-head reference. The verifier requires an enabled Human by
  that time; backdating and cross-clock causal ambiguity remain bounded.
- Historical direct-Human v2 evidence without the delegated Agent consequence
  companion is conservatively Incomplete, not a Complete claim.
- Missing or unresolved required evidence, unavailable pre-v14 command
  presentations, and some malformed idempotency reconstructions may resolve
  conservatively to Incomplete. Exhaustive Invalid classification is not
  claimed.
- The local path checks retain same-UID time-of-check/time-of-use windows. The
  qualified workload is distinct-UID and read-only where required; mutually
  hostile same-UID isolation is explicitly outside the claim.
- The 128 structural finding codes have source/registry equality coverage,
  not dedicated branch-level behavior tests.
- Legacy EditBatchV1 is redundant producer output and is not replayed as an
  independent authority source; signed ChangeSet Edits and reconstructed state
  carry the v1 semantics.
- The runtime containment result is Linux-specific. Windows identity/runtime
  containment is not qualified.
- No collaboration server, HTTP/PostgreSQL parity, public release, deployment,
  production mutation, or live remote state is included.

## Disposition

Engineering recommends project-owner review of this exact candidate and these
residuals. This receipt does not execute that disposition. The
[P-0006 work item](../../items/P-0006-close-milestone-2.md) must remain short of
`done` until the project owner explicitly accepts the evidence and residual
risks. Milestone 2 status documents and Milestone 3 work promotion must remain
unchanged until that acceptance.

Evidence paths:

- `docs/work/evidence/P-0006/receipt.md`
- `docs/work/evidence/P-0006/manifest.json`
- `docs/work/evidence/P-0006/traceability.md`
