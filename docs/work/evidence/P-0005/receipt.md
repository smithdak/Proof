# P-0005 Engineering qualification receipt

## Outcome

Engineering qualification is supported for the bounded P-0005 candidate
`c6f6ca899e1a63cf26f858d28b14163ffc270086`. The exact 40-Git-blob
inventory, structured lifecycle transcript, command matrix, and falsification
record are bound in `manifest.json`. An independent exact-candidate acceptance
audit found no candidate-attributable production defect. These gates make the
candidate eligible for review; no owner disposition has been executed and the
candidate is not an accepted or published revision.

The candidate starts from accepted P-0004/P-0007 base
`9c469e219ce5a2c6ec29f06dc6509a346b62cc10` and claim commit
`4ee3af241b8040b86f00dd403febf458948c5b20` on branch
`proof-engineering/p-0005-delegated-mutation`. It enables all 11 registered
localized v2 operations through the existing P-0007 application kernel, adds
storage v13 for signed localized consequences and Workspace-global successful
application-key ownership, and retains Human ownership of resource intent,
ContextPack first-build, approval, and Release policy identity.

Nothing in this packet authorizes or records a push, tag, release, deployment,
publication, production mutation, customer proof, or live-provider operation.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `proof-engineering/p-0005-delegated-mutation` |
| Base | `9c469e219ce5a2c6ec29f06dc6509a346b62cc10` |
| Claim commit | `4ee3af241b8040b86f00dd403febf458948c5b20` |
| Item-work commit | `c6f6ca899e1a63cf26f858d28b14163ffc270086` |
| Qualified at | `2026-08-21T16:03:13Z` |
| Candidate-path count | 40 |
| Candidate numstat | 16,176 insertions; 2,791 deletions |
| Git-blob SHA-256 inventory | 40 of 40 candidate blobs bound |

The manifest derives its path list and numstat from the immutable candidate
commit and records SHA-256 over bytes emitted from each exact Git blob.
Worktree hashes were not substituted.

No package record was added to `Cargo.lock`. The candidate adds one production
direct edge, `proof-application` to `proof-canonical`, and one test-only direct
edge, `proof-mcp` to `jsonschema`.

## Implemented boundary

P-0005 composes P-0004 authority with P-0007 localized content rather than
forking either domain:

- all 14 authenticated operation pairs are enabled: the three retained v1
  reads and the 11 already-registered localized v2 operations;
- the Agent selects the exact persisted Human-issued resource intent and
  Human-built ContextPack, then may create, inspect, add only
  `object.locale.put` v2 Edits, diff, validate, repair, submit, and resume after
  a distinct enabled-Human approval;
- commit, Edition creation, Release creation, and released query execute the
  existing P-0007 contracts with current authorization and closure checks in
  the same SQLite transaction as their authoritative effects;
- application failures map through the authenticated result contract, while a
  savepoint rolls back any partial P-0007 write before the signed consequence
  is recorded; and
- CLI, modern MCP, and legacy MCP expose the same application-generated
  Schemas and authenticated operation behavior.

Every localized Allow carries a typed `LocalizedConsequenceCommitmentV1`
inside signed `AuthorizationDecisionV2`. It binds result kind, result contract,
result digest, and an application consequence digest. That digest closes over
the operation and command, requesting Human, operating Agent, direct
Delegation, selectors, application-key kind and key, semantic timestamp, exact
resource-intent and Context policy/limit/validator/approval closure, result,
and raw P-0007 effect. Storage v13 reconstructs the one-to-one relation among
Allow, consequence, result, application-key owner, actor evidence, selectors,
and P-0007 effect before accepting the projection.

Exact replay is lifecycle-relative. A pre-commit result remains available only
while the selected target and Context base heads still match. A committed
closure may match its exact recorded commit renditions. A Release replay also
requires the existing exact command and Release plus the current Environment
pointer to that Release. A stale selected target, Known State, authority input,
or Environment pointer withholds the old result rather than disclosing it.

`ReleaseV2.principal_id` remains the requesting Human and its
`authorization_decision_digest` remains the P-0007 Human release-policy
decision. P-0005 does not rewrite those meanings. The operating Agent,
Delegation, authenticated decision, result commitment, and raw P-0007 effect
are cross-linked in the separate v13 localized consequence.

## Structured lifecycle transcript

The exact machine-readable transcript is the `qualification_transcript` object
in `manifest.json`, emitted by
`p0005_agent_executes_the_complete_human_owned_localized_lifecycle`. It contains
no credentials, private key material, prompts, or hidden reasoning.

The bound values are from the qualification-time exact-candidate lifecycle run
at the item-work commit. A fresh fixture generates fresh Release-signing
material, so a later ad hoc rerun can legitimately emit different dependent
digests; those later values are not substituted for the retained qualification
transcript.

| Transcript field | Exact value |
| --- | --- |
| API version | `proof.dev/qualification/p0005-lifecycle/v1` |
| Workspace | `019d2000-0000-7000-8000-000000000001` |
| Requesting Human | `019d2000-0000-7000-8000-000000000002` |
| Operating Agent | `019d2000-0000-7000-8000-000000000100` |
| Direct Delegation | `019d2000-0000-7000-8000-000000000200` |
| Successful presentations | 24 |
| Decisions / consumptions / actor evidence | 25 / 25 / 25 |
| Signed localized consequences | 24 |
| Workspace-global successful keys | 10 |
| ChangeSets / Edits / Releases | 1 / 2 / 1 |
| Validation attempts | 2 |
| Final authority head | sequence 30; `blake3:ee25d072c735f1cc8c69cd867ce5898ba8ceda92a8550e0c7db354043f7d93f3` |
| Terminal denial | `release.create/v2`; `proof.authorization.principal_disabled` |

| Artifact | Identifier | Digest |
| --- | --- | --- |
| Resource intent | `019d2000-0000-7000-8000-000000000040` | `blake3:43c420e15fee8a121aa111baca921727760384c53d3b6dbd3ad1377712e9a653` |
| ContextPack | `019d2000-0000-7000-8000-000000000042` | `blake3:e7b8a688535d1afd83fcbe65c6024974170a5e15b66ea04826ae2146e7f2c944` |
| ChangeSet | `019d2000-0000-7000-8000-000000000050` | resulting state `blake3:1b0b18ba5e86943af2414d377d3da6b28d994c3424d34ec1f59f4a2323604a72` |
| Edition | `019d2000-0000-7000-8000-000000000055` | `blake3:f578fa17062546e3d53be36cf6fe0ec2d2abde5f854f25e79a33a2c8e2c5503b` |
| Release | `019d2000-0000-7000-8000-000000000057` | `blake3:af782e47f68a6b6632b7a4cefdc1ae11cee6e36485c1547fbd0f6abdea0fd66b` |
| Proof | `019d2000-0000-7000-8000-000000000058` | envelope `blake3:ab6b2fbbcc1433ea682153923341bad050eafc6c667baaeae72b599229ee80fc` |
| Release Agent decision | n/a | `blake3:93b5482949ab127e5834e3f8195ced2ceae7319bc132cade62a706b86d6801b8` |

The retained operation-call counts are: `context.build/v2` 2,
`changeset.create/v2` 2, `changeset.add/v2` 4, `changeset.get/v2` 1,
`changeset.diff/v2` 1, `changeset.validate/v2` 4,
`changeset.submit/v2` 3, `changeset.commit/v2` 2,
`edition.create/v2` 2, `release.create/v2` 3, and
`object.query_released/v2` 1. The 25th presentation is the retained terminal
Principal-disabled denial; it has no localized consequence.

## Required Engineering evidence matrices

### Delegated lifecycle and Human approval

The lifecycle runs one real local path from exact ContextPack selection through
proposed content, invalid validation, repair, successful validation,
submission, separate Human approval, delegated commit, Edition, delegated
Release, released query, and persisted Release verification. It executes and
exactly replays all 11 localized operations.

The retained approval falsifiers prove that no Agent approval exists, that a
commit without the required approval fails without owning its application key,
that the same key succeeds after Human approval, and that replacing the
approval Principal with the Agent causes authority-integrity failure without
application movement.

The lifecycle target passed 1 test with no failure. Its transcript records 24
successful authenticated presentations, 24 signed localized consequences, and
one terminal Principal-disabled denial.

### Denial, replay, idempotency, and atomicity

The retained matrix covers malformed and actor-mismatched presentations, wrong
action, Environment, Object, Schema, locale, budget, expiry, recipient,
Delegation revocation, Binding revocation, stale Known State, stale selected
Context target, replay mismatch, and approval bypass.

Pre-consumption failures leave zero durable writes. Committed denials append
only the ratified decision, consumption, and actor evidence and do not move
governed content or own an application key. A mapped localized failure can be
corrected under the same key because failure does not reserve it. Successful
key ownership is Workspace-global across Human or Agent identity, operation,
and semantic input, with only the exact Human localized Context-selection
exception required by the existing application contract.

Exact validation replay does not append another validation attempt. Exact
Context replay is withheld after selected-target movement. Exact committed
replay is withheld after stale base state unless the immutable committed
closure still matches its exact recorded renditions. Unrelated resources do
not invalidate an otherwise exact closure.

The matrix target passed 12 tests with no failure, including the shared
lifecycle target. The local-kernel target passed 6 tests with no failure,
including the shared lifecycle target. A two-Edit batch whose second Edit fails
late retained zero partial application write.

### Revocation/consequence serialization

The concurrency test uses two real SQLite connections and a held
`BEGIN IMMEDIATE` writer to exercise both commit orders. If revocation commits
first, the localized consequence is denied. If the consequence commits first,
it completes against the still-current authority state and the later revocation
does not retroactively rewrite it. No check-then-act window permits a
post-revocation consequence.

### Projection and consequence falsification

The public verifier is table-driven against localized consequence rows,
Workspace-global application-key ownership, Context closure, and raw P-0007
effects. Deletion, substitution, digest mutation, selector or actor mismatch,
and result/effect mismatch fail closed. Verifier reads do not create new
authority records.

The strongest projection attack is a valid signed Allow paired with an
attacker-edited unsigned result or application effect. The signed typed
consequence commitment plus v13 one-to-one reconstruction prevents that
substitution. The retained local-kernel target passed all 6 tests.

### Migration matrix

Every supported pre-candidate storage version is explicitly in scope: v1
through v12. The target is v13. For each source version, an injected v13
migration failure retains the source Schema, typed storage fingerprint, and
foreign-key state exactly; retry converges to stable `13/13/13`; a second retry
is a no-op; and migration synthesizes no authenticated v13 row.

The historical migration fixture uses real public application APIs to retain a
signed v10 `ReleaseV1` and Proof, then a v11 mixed v1/v2 localized Release and
rollback chain. It checks exact Release-history and Proof artifact bytes across
the v11/v12/v13 migrations, injected v12 and v13 failures, and keyless
verification after removing the Release signing key. Both migration tests
passed, with 127 unrelated tests filtered out.

### Application and transport parity

Application coverage executes every localized operation through the
application-owned handler and generated Schema path. The real-transport parity
test uses one Local Workspace and three fresh authenticated presentations: a
real `proof` CLI subprocess, modern MCP, and legacy MCP. It compares exact
normalized command, result, localized commitment, resources, constraints,
requesting and operating actors, cryptographically verified Decision
envelopes, one raw P-0007 effect, and one Workspace-global key owner. It also
compares the committed unsupported-version failure with no application
movement. The parity target passed 1 test with no failure.

## Verification

| Surface | Qualification state |
| --- | --- |
| Complete local lifecycle | Windows: 1 passed, 0 failed |
| Delegation, denial, replay, and concurrency matrix | Windows: 12 passed, 0 failed |
| Local kernel and projection falsification | Windows: 6 passed, 0 failed |
| v1-v12 to v13 migration | Ubuntu: 2 passed, 0 failed, 127 filtered |
| CLI and modern/legacy MCP parity | Ubuntu: 1 passed, 0 failed |
| Complete locked immutable-candidate workspace | Ubuntu: 493 passed, 0 failed |
| Ubuntu documentation tests | 6 crate summaries, 0 failures |
| Strict workspace/all-target/all-feature Clippy | Windows and Ubuntu passed with warnings denied |
| Windows workspace check | Passed |
| Rust formatting | Passed |
| Documentation links and work control | 165 links and 7 work items passed |
| Repository Markdown | 53 files, 0 issues |
| JSON, normalized diff, secret and personal-path scans | Passed; 0 scan matches |

Ubuntu qualification used `Ubuntu-24.04` under WSL2 with Cargo 1.97.1 and
Rustc 1.97.1, `TMPDIR=/tmp`, and
`CARGO_TARGET_DIR=/mnt/d/github/Proof/target/p5-wsl`. The exact commands and
exit codes are retained in `manifest.json`.

Windows is qualified for compilation, formatting, strict lint, and focused
deterministic tests only. The Unix bootstrap identity adapter was not exercised
as a Windows runtime, so this packet makes no Windows identity-runtime support
claim.

## Falsification result

The crux was whether an exact signed Allow remained inseparable from the
localized result and P-0007 effect at verification and replay time. It does:
the candidate signs the typed consequence commitment, records the one-to-one
v13 consequence and key owner atomically, reconstructs the complete closure,
and withholds stale replay. Retained probes cover result-digest substitution,
consequence and ledger deletion or mutation, Context and raw-effect tamper,
stale target/base/pointer and authority inputs, late-batch rollback, both
concurrency orders, and transport-specific divergence. None falsified the
bounded local claim.

The strongest rejected alternative was to fold P-0006's portable
clean-directory bundle, independent verifier, independent checkpoint, caller
trust policy, and hostile-workload containment into P-0005. That would combine
local delegated mutation with distribution and deployment trust contracts.
The smaller complete slice retains the exact v13 cross-links P-0006 needs while
leaving those absent properties explicit.

Confidence is high for the bounded local Engineering claim. Evidence that
would reverse the conclusion includes any accepted signed-Decision/result
substitution, stale replay disclosure, partial P-0007 write after mapped
failure, application-key double ownership, post-revocation consequence, byte
drift during migration, or transport-specific authority semantics. The exact
candidate passed each corresponding retained probe plus the complete Ubuntu
workspace gate and an independent acceptance audit with no defect.

## Residual trust boundary and disposition

The final candidate remains bounded by these residuals:

- a process with the bootstrap UID or private Workspace access is inside the
  Human/admin trust boundary; signed Agent presentations provide attribution
  and bounded broker behavior, not hostile same-UID containment;
- P-0006 must carry the v13 signed localized consequence, independent authority
  checkpoint, complete P-0007 Release closure, and explicit caller trust into a
  portable clean-directory bundle and verifier;
- P-0006 or another deployment item must qualify distinct-UID or sandbox
  containment before representing a hostile local workload as contained;
- server, provider, network, PostgreSQL, collaboration, and UI contracts remain
  outside this slice;
- no Windows identity-runtime support is claimed; and
- no live remote, push, tag, release, publication, deployment, production
  mutation, or customer proof is claimed.

Engineering qualification is complete and the candidate is eligible to move
from `claimed` to `review`. No review-to-`done` owner disposition has been
executed by this evidence packet.

## Evidence paths

- `docs/work/evidence/P-0005/receipt.md`
- `docs/work/evidence/P-0005/manifest.json`
