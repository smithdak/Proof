# P-0007 independent verification gate

## Decision boundary

This is the mandatory `proof-assurance` review gate for P-0007 after the
project-owner stale-claim decision recorded in Buzz event
`4fba209ea00d5d985d87873f17915f6ed117ca6e0272a81c100ca3166586f846` on
2026-08-19.

The stale implementation candidate at
`a95ee484b7038358c0d4e30167862dbed85728c0` is prior evidence only. It is not a
current implementation, verification, release, or customer claim. This gate
must bind a successor item-work candidate by full commit SHA and review the
exact product bytes at that revision. A later narrow evidence/control-plane
commit may add only the receipt, manifest, Assurance verdict, item completion
record, and map transition; it does not become a new implementation candidate.

The gate can support only this claim:

> P-0007 satisfies its authorized scope and acceptance criteria at the named
> candidate commit in the tested environments.

A supported verdict does not establish an Agent-authorized path, a public
release, production operation, customer acceptance, translation quality,
legal correctness, cultural fitness, or a business outcome. Assurance has no
release authority.

## Roles and separation

| Role | Required output | Prohibited substitution |
| --- | --- | --- |
| Engineering | Exact candidate commit, changed-path inventory, P-0007 `receipt.md` and `manifest.json`, retained fixtures, and exact-Candidate CI evidence | Engineering's own test assertion cannot substitute for Assurance's reconstruction and negative-path checks. |
| Proof Assurance | Independent test execution, recomputation, contrary evidence, and `assurance-verdict.md` | Assurance cannot repair the implementation, accept residual product risk, transition release state, or authorize publication. |
| Founder | Product and residual-risk decisions, and any separate later release authorization | Founder authorization cannot turn missing or contradictory technical evidence into a supported verification verdict. |

The revision topology is explicit:

1. `candidate_sha` is Engineering's immutable item-work commit. Assurance
   checks out and verifies this revision.
2. `engineering_evidence_commit` is a narrow child that adds the receipt,
   manifest, and review-state work-control records. Those records bind
   `candidate_sha`; they do not claim to verify their own commit hash.
3. `assurance_record_commit` is a narrow child that adds the independent
   verdict. The verdict binds `candidate_sha` and
   `engineering_evidence_commit`; Git history supplies its own commit identity.
4. A later narrow completion commit may record `assurance_record_commit` and
   transition the item and map together.

The implementation candidate is invalidated by any change to product,
conformance, test, workflow, dependency, normative-contract, or
verification-tool bytes after `candidate_sha`. A changed candidate starts a
new gate run; evidence from the prior candidate remains historical and must not
be relabeled. The three later commits do not invalidate `candidate_sha`, but
their diffs must contain only the allowed evidence and work-control paths and
must pass documentation and work-control checks.

## Fail-closed entry conditions

Assurance does not begin a supportable verification run until all entry
conditions are present:

1. The P-0007 work item records Engineering as the current owner under the
   repository claim and handoff rules.
2. The item-work candidate is a full Git commit reachable from the reviewed
   branch, the checkout is clean, and Engineering identifies its parent and
   original P-0007 base SHA.
3. `docs/work/evidence/P-0007/receipt.md` and `manifest.json` exist in the
   review worktree and bind the item-work candidate, commands, tool versions,
   environments, exit codes, fixtures, artifact digests, and residual risks.
   Their planned evidence/control-plane commit and the item-work commit are
   recorded separately to avoid self-referential hashes.
4. GitHub Actions has completed the full Ubuntu 24.04 `Linux quality gate` for
   that exact SHA with no cancelled, skipped, neutral, or failing required
   step.
5. The evidence packet contains no secrets, private runtime database, private
   key, provider credential, or generated text that cannot be checked in.
6. Engineering provides a traceability table mapping every G1-G14 row to its
   ratified requirement, exact public entry point, source location, and test or
   retained command. There is no discretionary `not applicable` during a run;
   an absent or out-of-scope surface requires a recorded gate revision before
   execution.
7. The work-control validator enforces, for P-0007 `done`, the presence of a
   parseable `assurance-verdict.md`, `verdict: supported`, matching
   `candidate_sha` and `engineering_evidence_commit`, `accepted_by:
   proof-assurance`, a valid `accepted_at`, and a completion-record reference
   to `assurance_record_commit`. A prose convention or passing validator that
   does not check these fields is insufficient.

A missing ownership, provenance, entry point, or infrastructure result is
`indeterminate`. A reproducible failure attributable to the exact candidate is
`unsupported`. For example, a candidate-attributable CI failure makes G1
`unsupported`; later steps skipped because of that failure remain
`indeterminate` individually. Neither verdict permits claim reactivation.

## Required verification matrix

Each row is independently blocking. Shared helpers are useful implementation
detail but are not evidence that every externally reachable path enforces the
same integrity rule.

The rows derive from the P-0007 item and the ratified
[delegated localized-content contract](../../architecture/delegated-content.md):

| IDs | Normative coverage |
| --- | --- |
| G1 | P-0007 acceptance criterion 9 and the repository quality gate in `CONTRIBUTING.md`. |
| G2-G4 | Authorized canonical formats, independent golden reconstruction, historical verification, and the contract's conformance/falsification cases. |
| G5 | P-0007 acceptance criterion 6: exact ContextPack and released-query closure with no fallback or traversal. |
| G6 | P-0007 acceptance criteria 1-2 and the required application-contract/Human-CLI boundary. |
| G7 | P-0007 acceptance criteria 3-4: deterministic target preconditions, immutable attempts, repair, and budgets. |
| G8 | P-0007 acceptance criterion 5: commit, Edition, Release, pointer, and exact-delta causality. |
| G9 | P-0007 acceptance criteria 7-8: atomic migration, v1 reproduction, and the closed legacy/v2 matrix. |
| G10-G11 | P-0007 acceptance criterion 9: deterministic rebuild, repair, replay, and denial atomicity. |
| G12 | Human-authenticated issuance and the explicit exclusion of delegated Agent authority. |
| G13 | The atomic-failure and recovery obligations spanning acceptance criteria 3, 5, 7, and 9. |
| G14 | Authorized scope, non-goals, required evidence, and repository claim provenance. |

| ID | Surface | Required adversarial check | Required retained evidence |
| --- | --- | --- | --- |
| G1 | Repository quality | Run the complete pinned Linux gate: formatting, strict Clippy, all workspace tests with all targets and features, doc tests, documentation links, and work-control validation. Run Markdown lint and normalized `git diff --check` for the evidence/control-plane change. | Exact commands, versions, exit codes, test counts, CI run URL and job identity, candidate SHA, and clean-tree proof. |
| G2 | Schemas and canonical artifacts | Independently validate every localized-content operation and artifact fixture against its JSON Schema. Recompute canonical bytes and digests without trusting stored expected digests. Mutate one field, ordering rule, version, and digest per artifact family and require rejection. Exercise restricted locale syntax, invalid casing, literal alias non-normalization, localizable-pointer ordering and escaping, overlap, array traversal, missing paths, non-string leaves, and mutation outside declared pointers. | Schema and vector file digests, independent recomputation output, mutation corpus, and per-case results. |
| G3 | Direct reads | Tamper, omit, substitute, and cross-link authoritative resource intent, ContextPack, Edit, validation, approval, commit, Edition, Release, rendition, and operation-effect records. Direct reads must reject corrupted or incomplete ancestry instead of returning a projection-derived success. | Before/after database snapshots or table hashes, injected mutation description, stable Problem, and proof that no governed state changed. |
| G4 | Verifiers | Supply wrong artifact bytes, matching-but-wrong recomputed digests, incomplete ancestry, a fork or cycle, wrong subject, unsupported version combinations, stale signing time, and mismatched Release/Edition/Known State references. | Verifier inputs, expected and actual Problems, recomputed digests, and immutable source artifact hashes. |
| G5 | ContextPack and exact-locale queries | Build a ContextPack for exact targets and challenge it with an unrelated Object, Schema, locale, relationship, field, stale source, and narrowed or widened target set. Query an exact existing rendition, absent rendition, wrong locale casing, unrelated Object, stale Release, and v1/v2 boundary. Require exact source closure with no fallback, source substitution, partial success, relationship traversal, or disclosure outside the complete request. | ContextPack manifest and source hashes, request and response envelopes, active Release/Edition references, independently derived expected closure, and unchanged-state proof for denials. |
| G6 | Human-path lifecycle and adapter parity | From an exact v1 baseline, issue one immutable Human-authenticated intent for two target locales; build the ContextPack; create a ChangeSet; persist a prohibited-claim attempt; append a valid superseding Edit; validate, submit, approve, commit, create the Edition, promote the Release, query both exact locales, and verify the Release. Exercise the application contracts and Human CLI against equivalent inputs and require equivalent identifiers, digests, state transitions, Problems, and normalized result envelopes. | Complete identifiers and digest graph, application/CLI transcripts, all attempted Edits and validation attempts, effective-head proof, resulting state and delta, Release proof, and final exact-locale results. |
| G7 | Edit semantics and repair lineage | Challenge create and exact-replacement preconditions, wrong Object/Schema/locale, non-localizable changes, cross-target supersession, fork, cycle, skipped predecessor, repair of the wrong finding, deletion/reordering/substitution of failed attempts, and Edit/validation/ContextPack budget exhaustion. The failed attempt must remain immutable, the effective lineage must be unique and acyclic, and approval/evidence must bind the complete attempt history. | Full pre/post lineage, target preconditions, attempt ordinals, validation digests, stable Problems, budget counters, and state/table hashes. |
| G8 | Commit, Edition, and Release causality | Inject stale source and target revisions, duplicate active targets, unrelated concurrent commit, moved Environment pointer, ambient Workspace change, wrong ChangeSet, missing target, and an extra same-scope delta. Every case must fail before pointer movement or attributed Release creation. | Base and candidate sequences/digests, exact delta reconstruction, pointer snapshots, operation-effect rows, and denial atomicity evidence. |
| G9 | Migration and compatibility | Exercise every supported pre-P-0007 storage version through v11. Reproduce legacy v1 bytes and digests before and after migration, prove zero fabricated locale facts, inject failures at each transaction phase, retry, and exercise the closed legacy/v2 command, query, rollback, and verification matrix. | Per-version fixture hashes, `user_version`, row counts, rollback snapshots, retry result, and byte/digest comparisons. |
| G10 | Dry-run rebuild and repair | Corrupt each derived localized projection separately. Dry-run must report deterministic drift and perform zero writes. Repair must converge to independently reconstructed state. Corrupt authoritative history and require both dry-run and repair to fail closed without rewriting it. | Repeated dry-run outputs and digests, database hashes before/after, repair diff, second-run no-drift result, and authoritative-tamper rejection. |
| G11 | Replay and idempotency | Replay every consequential operation with identical input and reuse each key with changed input, changed target, and changed lifecycle position. Identical replay returns the original result; aliasing or stale reuse fails without duplicate facts, pointer movement, or overwritten evidence. | Operation-effect inputs/outputs, key mappings, row counts, original-result equality, stable Problems, and unchanged-state proof. |
| G12 | Authentication and authorization boundary | Prove resource-intent issuance is authenticated as a Human operation, immutable, idempotent, and effect-bound. Attempt issuance and every Human-path mutation without the required local identity or through the unimplemented Agent boundary; require fail-closed behavior. Do not claim P-0004/P-0005 delegated authorization from these results. | Actor and operation metadata without secrets, denial envelopes, absence of side effects, and an explicit scope statement excluding delegated Agent authority. |
| G13 | Failure recovery | Inject storage, proof-export, and interruption failures at pre-write, mid-transaction, post-commit/pre-export, and replay boundaries. Governed state, pointers, projections, evidence, and idempotency records must be atomic or follow a documented durable recovery rule; retry must converge once. | Fault point, transaction/pointer/table snapshots, retained pending evidence, replay output, and convergence proof. |
| G14 | Provenance and inventory | Recompute hashes for every candidate path, schema, vector, command transcript, and retained artifact. Reconcile the Git diff with P-0007 authorized scope and non-goals. Detect untracked, generated, unrelated, or credential-shaped content. Prove the evidence/control-plane follow-up changes only allowed record paths. | Full path inventory, parent/candidate SHA, file hashes, scope classification, evidence-only diff, secret-scan result, and explicit exclusions. |

## Independent execution rules

- Assurance runs against a fresh checkout or worktree of the exact candidate,
  not Engineering's mutable execution directory or runtime database.
- At least one canonical/digest reconstruction and the expected results for
  G5, G8, G9, and G10 must be produced independently of the code path under
  review. Fixtures emitted only by the implementation are circular evidence
  until cross-checked.
- Every negative test captures state before and after the attempt. A stable
  error without unchanged-state proof does not establish denial atomicity.
- Passing a focused test does not replace the complete quality gate. Passing
  the complete suite does not replace the path-specific adversarial checks.
- A repair path may rewrite derived projections only. If it accepts or rewrites
  corrupted authoritative history, the verdict is `unsupported`.
- A missing or skipped result, unsupported runner, tool or infrastructure
  failure, nondeterminism, unavailable retained input, or unresolved evidence
  conflict is `indeterminate`. A failure that reproduces on the exact candidate
  and is attributable to its bytes or behavior is `unsupported`. Neither is
  waived silently.

## Verdict rule

Assurance records one verdict for the bounded P-0007 claim:

- `supported`: every entry condition and G1-G14 row passes on one exact
  candidate, with independently reproducible retained evidence and no
  unresolved acceptance blocker.
- `unsupported`: reproducible, candidate-attributable contrary evidence shows
  that the candidate violates scope, an acceptance criterion, integrity
  parity, denial atomicity, provenance, or a required quality gate.
- `indeterminate`: required evidence is missing, stale, inaccessible, skipped,
  not independently reproducible because of the environment or tooling, or in
  unresolved conflict.

`supported` requires all rows. One `unsupported` row makes the bounded claim
`unsupported`; otherwise any `indeterminate` row makes it `indeterminate`.
Assurance does not average results and does not convert a partial pass into a
conditional support verdict.

## Required Assurance record

Assurance writes `docs/work/evidence/P-0007/assurance-verdict.md` after the
independent run. It begins with machine-readable frontmatter:

```yaml
---
item_id: P-0007
review_gate: proof-assurance
verdict: supported
candidate_sha: <40 lowercase hexadecimal characters>
engineering_evidence_commit: <40 lowercase hexadecimal characters>
reviewed_by: proof-assurance
reviewed_at: <RFC 3339 UTC timestamp>
---
```

An `unsupported` or `indeterminate` result uses that exact value for
`verdict`. The body must contain:

1. the exact claim, candidate SHA, parent/base, branch or ref, checkout, and
   environments;
2. the Engineering evidence packet digests, its commit, and exact GitHub
   Actions run;
3. a G1-G14 table with `supported`, `unsupported`, or `indeterminate` for each
   row and direct evidence locators;
4. commands executed, exit codes, test counts, retained artifact hashes, and
   paths not exercised;
5. supporting and contrary evidence, including every injected failure and
   before/after state proof;
6. the strongest counterargument, residual risks, and observable falsifier;
7. a statement that the verdict applies only to P-0007 at the named SHA and
   grants no release or customer claim.

The P-0007 lifecycle may advance through its repository-defined review step
only when this record says `supported`, the item and map agree, the Engineering
receipt and manifest are complete, and the work-control validator enforces the
record. A later release requires separate Proof evidence and explicit founder
authorization.

## Falsification posture

The strongest counterargument is that G1 plus the broad end-to-end scenario
already exercises the same code, making G2-G14 duplicative. That argument would
be persuasive if every read, verifier, query, rebuild, repair, and recovery
boundary were mechanically identical and independently reconstructed. They are
not equivalent evidence surfaces: several can share the same faulty helper or
trust the same corrupted projection and still pass together.

The crux is integrity parity across externally reachable paths. One path that
accepts evidence another rejects, or one repair path that blesses corrupted
authority, is enough to invalidate the P-0007 proof claim.

This gate design would be falsified if repository inspection shows that a
listed surface is not reachable in P-0007 and no equivalent acceptance claim
depends on it, or that a material P-0007 boundary is absent from G1-G14. In
that case the matrix must be revised before use, with the change recorded
rather than silently narrowing the run.

**Confidence:** high that this is the minimum complete independent gate for the
ratified P-0007 scope. Confidence in any candidate remains unknown until the
gate is executed on its exact bytes.
