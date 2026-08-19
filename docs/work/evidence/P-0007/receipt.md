# P-0007 Engineering revalidation receipt

## Outcome

Engineering produced and locally qualified item-work candidate
`fede487547c3e2bb27f5cb8fb168f5b5312a5f23`. It repairs every strict-Clippy
failure exposed after the stale `a95ee484b7038358c0d4e30167862dbed85728c0`
candidate and corrects the CLI status test to the implemented v11 storage
schema. The changes preserve behavior except for that stale test expectation.

The complete local Ubuntu gate passed at unchanged candidate HEAD with a clean
tree: formatting, strict workspace/all-target/all-feature Clippy, 208 Rust
tests, documentation tests, 159 internal documentation links, seven work-item
records, and normalized diff validation all passed.

This is Engineering evidence, not an Assurance verdict. P-0007 remains
`claimed`, the prior capability claim remains stale, and the current Assurance
verdict remains `indeterminate`. Exact-SHA GitHub Actions is not available
because the directive prohibits pushing or publication. Assurance entry
condition 4 therefore remains open, and Engineering is not requesting final
Assurance execution from this packet.

## Revision topology

| Field | Exact value |
| --- | --- |
| Original P-0007 base | `a0f1df8d4e7b9b9a4da05681bfd23d1ef619e566` |
| Original claim commit | `12c8e15f37a2e090e84dca6b7d601d7d9cd17a0e` |
| Stale candidate | `a95ee484b7038358c0d4e30167862dbed85728c0` |
| Engineering ownership transfer | `cd6d547` |
| Assurance gate | `a1d695da0ec55868f1aee7539590d601a6ac9adf` |
| Revalidation control plane | `f3e3c2195bdbf983f3322726dccf90985e9a17b3` |
| Candidate parent | `f3e3c2195bdbf983f3322726dccf90985e9a17b3` |
| Candidate SHA | `fede487547c3e2bb27f5cb8fb168f5b5312a5f23` |
| Branch | `proof-engineering/p-0007-revalidation` |
| Checkout | `C:\Users\dakot\.buzz\REPOS\Proof-P0007-Revalidation` |
| Evidence commit | Recorded by Git history and the Assurance verdict; not embedded here, avoiding self-reference |
| Remote publication | Not authorized; not performed |

## Candidate change

The successor candidate changes five files relative to its parent:

- splits long canonical and integration-test helpers without changing the
  covered artifact or lifecycle assertions;
- factors localized projection verification into source, pointer, and content
  checks while preserving fail-closed errors;
- removes stale or unnecessary Clippy constructs and borrows Environment
  identifiers instead of moving them; and
- changes the CLI status expectation from storage schema `10` to `11`.

No dependency, architecture contract, migration SQL, public API, release
configuration, production state, or secret changed in the repair commit.

## Exact local qualification

Environment:

- Ubuntu 24.04.4 LTS under WSL2, kernel
  `5.15.167.4-microsoft-standard-WSL2`;
- `rustc 1.97.1 (8bab26f4f 2026-07-14)`;
- `cargo 1.97.1 (c980f4866 2026-06-30)`;
- Node `v22.23.1`; and
- Windows Git `2.43.0.windows.1` for worktree-aware SHA/clean-tree and
  normalized diff checks.

The exact-SHA harness printed the same full SHA before and after the gate and
an empty post-run porcelain status. Commands and exit codes are recorded in
`manifest.json`. The Rust test count is 208: 5 application, 11 attestation, 14
canonical, 1 architecture, 28 CLI, 14 domain, 118 local integration, 9 MCP
unit, and 8 MCP protocol tests. Documentation tests completed for six crates
with no failures.

WSL Git cannot parse this Windows-created worktree's `.git` file because it
contains a Windows absolute gitdir. The outer PowerShell harness therefore
established clean exact HEAD before and after the Ubuntu commands and ran
`git -c core.autocrlf=true diff --check` through Windows Git. The initial WSL
attempt's final Git command was infrastructure-indeterminate; it did not alter
or weaken the successful Rust, documentation, or work-control results.

## Required evidence matrices

### Migration matrix

| Input storage version | Transition | Retained result |
| --- | --- | --- |
| v1-v9 | Successive atomic migrations through v11 | `every_pre_localization_version_migrates_without_changing_v1_evidence` passed for each input version; legacy snapshots remained byte/digest equal, foreign keys were clean, and zero v11 localized rows were fabricated. |
| v10 | Atomic migration to v11 | The same every-version test passed with operation-effect commitments preserved and zero fabricated localized rows. |
| v9 with injected v10 failure | Remain exactly v9, then retry to current | `version_ten_migration_rolls_back_atomically_after_a_mid_script_failure` passed. |
| v10 with injected v11 failure | Remain exactly v10, then retry to v11 | `version_eleven_migration_rolls_back_atomically_after_an_injected_failure` passed. |

### Source-to-rendition fixture matrix

| Phase | Source / target | Retained result |
| --- | --- | --- |
| Baseline | Object `019c0000-0000-7000-8000-000000000080`, Schema `campaign@1`, locale-neutral revision 1 | Source digest is independently computed by `object_revision_digest`; the first localized commit asserts KnownState v1 to v2. |
| Initial localized commit | Exact `es-ES` and `fr-FR` targets, both absent at base | Two immutable rendition revision-1 records are committed; exact-locale query returns two and `de-DE` returns `NotFound` without fallback. |
| Repair | Invalid French prohibited-claim attempt followed by a valid superseding Edit | Both attempts remain stored; validation attempt 2 passes and the effective French head is the repair. |
| Exact replacement | Existing `fr-FR` revision 1/digest as the expected target | One revision-2 French rendition is committed with `previous_revision_digest` bound to revision 1; Spanish remains revision 1. |
| Cross-version rollback | v2 Release to baseline v1, then v1 back to the exact v2 Release | v1 query exposes no rendition; restored v2 query returns both exact locales and Release verification passes. |

Canonical fixture bytes and portable expected digests are retained in
`conformance/v2/localized-content/vectors/artifact-digests.valid.json`; their
SHA-256 is recorded in `manifest.json`. The runtime scenario reconstructs
content digests rather than storing a disposable database in evidence.

### Denial matrix

| Challenge | Stable result | Atomicity assertion |
| --- | --- | --- |
| Submit before valid validation | `NotReady` | no lifecycle advance |
| Approve before submit | `NotSubmitted` | no approval |
| Commit before approval | `NotApproved` | no commit |
| Locale outside exact intent | `IntentMismatch` | zero localized Edits |
| Stale source digest | `SourceConflict` | zero localized Edits |
| Target claimed present when absent | `TargetConflict` | zero localized Edits |
| Change outside localizable pointers | `InvalidInput` | zero localized Edits |
| Duplicate active target | `DuplicateActiveTarget` | original one Edit remains |
| Unknown supersession predecessor | `InvalidSupersession` | original one Edit remains |
| Missing or wrong repair evidence | `InvalidRepairEvidence` | original one Edit remains |
| Fork after a valid repair | `InvalidSupersession` | two-Edit linear history remains |
| Edit after valid sealing | `NotDraft` | two-Edit history remains |

All rows are retained by `localized_edit_denials_are_specific_and_atomic`.
The independent G3, G7, G8, and G13 database snapshot expansion remains an
Assurance action, not an Engineering pass claim.

### Replay matrix

| Operation family | Retained result | Remaining independent coverage |
| --- | --- | --- |
| ContextPack build | Identical replay returns the original before revalidating candidate time; changed/moved scope rejects without writes. | Localized exact-target cross-link mutation |
| ChangeSet create/add/commit and Edition create | Shared local operation-effect tests return original outputs, reject changed-input/key aliasing, and detect tampered effects. | Per-operation localized-envelope replay matrix |
| Localized rollback | The application scenario replays the identical rollback command and asserts equality with the original Release. | Changed target and lifecycle-position reuse |
| Release promotion/proof export | Release operation-effect tamper/key-swap tests reject; post-commit proof-export retry converges once. | Localized promote changed-input matrix |

These retained results satisfy Engineering's replay evidence obligation but do
not close G11; Assurance must execute every consequential localized operation
with identical and changed inputs.

## Acceptance and gate mapping

`traceability.md` maps every acceptance criterion and G1-G14 row to its public
entry point, source, retained test or command, Engineering result, and remaining
independent action. `candidate-paths.sha256` records SHA-256 for every path
changed from the original P-0007 base through the candidate.

Engineering provides supporting local evidence for all nine acceptance
criteria, with explicit partial states where only Assurance's independent
mutation or reconstruction can resolve the gate. It does not substitute a
broad green suite for integrity-parity testing.

## Disposition

**Preferred disposition after the mandatory gates: RESTORE. No disposition is
currently eligible or executed.** The candidate clears the known
implementation and local Linux failures without changing the ratified scope.
Restoration remains fail-closed on both missing facts: a green GitHub Actions
`Linux quality gate` for the exact candidate SHA, and a `supported` Assurance
verdict binding this candidate and its evidence commit. Until both exist, the
operative state is stale / revalidation in progress / Assurance
`indeterminate`.

The strongest alternative is `REVISE` because several G rows still require
independent adversarial evidence. It is rejected as the current recommendation:
the missing facts concern qualification, not a demonstrated contract or
implementation defect. Any candidate-attributable failure in the authorized
CI or G1-G14 run changes the recommendation to `REVISE`; an invariant that
cannot be met without scope expansion changes it to `RETIRE`.

## Residual risks and explicit exclusions

- Exact-SHA GitHub CI is absent because push/publication is prohibited.
- Assurance has not independently executed G1-G14 on a fresh checkout.
- Engineering's broad suite cannot exclude a shared integrity bug across
  direct reads, verifiers, query, rebuild, repair, and recovery surfaces.
- WSL is local Linux evidence, not GitHub runner, release, production, or
  customer evidence.
- Nothing was pushed, tagged, released, published, deployed, or externally
  communicated. No delegated Agent authority is claimed.

## Evidence paths

- `docs/work/evidence/P-0007/receipt.md`
- `docs/work/evidence/P-0007/manifest.json`
- `docs/work/evidence/P-0007/traceability.md`
- `docs/work/evidence/P-0007/candidate-paths.sha256`
