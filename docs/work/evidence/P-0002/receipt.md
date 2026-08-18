# P-0002 decision and acceptance receipt

## Outcome

P-0002 produced a complete, falsified candidate for the Milestone 2 delegated
content contract. Project owner `smithdak` accepted that bounded decision at
`2026-08-18T12:44:20.977Z`. The decision and ADR-0012 are ratified; the
localized-content behavior remains unimplemented. The substantive item-work commit is
`694b723f2ef5e7c6b8a74d0bb5c6af6497fe0cc3`; the preceding claim commit is
`a0ea6168bac68be363ab01dad855aeebe44182bc`. This follow-up control commit
binds that immutable work and released the active claim to project-owner
review. Acceptance closes P-0002 and promotes P-0003 and P-0007 to `ready`;
P-0004, P-0005, and P-0006 remain blocked by their direct dependencies.

Nothing was pushed, tagged, released, published, or implemented by the
acceptance transition.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `main` |
| Worktrees | `1` |
| Starting HEAD / claim base | `d6532ffcd9ea00dc18c31005695a40692b1f8cc2` |
| Claim commit | `a0ea6168bac68be363ab01dad855aeebe44182bc` |
| Item-work commit | `694b723f2ef5e7c6b8a74d0bb5c6af6497fe0cc3` |
| Acceptance base | `6abf680a316423cdb7910877a2660d59943db969` |
| Local `origin/main` tracking ref | `d6532ffcd9ea00dc18c31005695a40692b1f8cc2` |
| Live remote verification | Not performed |
| Claim | `codex:/root:p-0002` at `2026-08-18T01:07:37.311Z` |
| Candidate qualified | `2026-08-18T02:38:58.5989701Z` |
| Accepted by | `smithdak` |
| Accepted at | `2026-08-18T12:44:20.977Z` |

The item-work commit changed 18 documentation and work-control paths. It added
one architecture contract, one proposed ADR, and one blocked implementation
prerequisite. No Rust source, migration, runtime database, credential,
portable Proof, or production configuration changed.

## Candidate decision

The proposed content profile:

- retains `ObjectRevisionV1` as the immutable locale-neutral source and adds
  subordinate append-only `ObjectLocaleRevisionV1` renditions keyed by exact
  Object and restricted locale;
- admits only full-content `object.locale.put` edits within exact
  Schema-declared localizable string leaves;
- preserves every repair attempt through linear supersession and a contiguous
  digest-linked validation-result chain sealed by approval and Proof;
- uses a Human-issued, effect-bound `ContentResourceIntentV1` control artifact
  to narrow the Delegation dimension product to exact target tuples without
  advancing authoritative content state;
- requires a clean versioned v1 baseline for the one-way first v2 commit and
  preserves every historical v1 byte and digest; and
- closes Edition and Release causality around exactly one authorized committed
  ChangeSet and an unchanged baseline Environment pointer.

The strongest rejected alternative was generic JSON Patch with field- or
pointer-scoped Delegation. Proof has no stable Field identity, JSON Pointer
prefixes are Schema-version fragile, and patch ordering would make canonical
effect, conflict, and authorization semantics materially larger than the
two-locale milestone requires.

## Verification

All final gates passed on the Windows checkout:

- work-control validation: seven items passed metadata, lifecycle, dependency,
  map-parity, transition, and evidence checks;
- documentation links: 156 internal links resolved;
- Markdown lint: 47 files, zero issues under `markdownlint-cli2` 0.23.2;
- `cargo fmt --all --check`: passed; and
- staged and unstaged diff checks: passed, with only checkout line-ending
  advisories.

The acceptance transition additionally passed seven-item work-control
validation, 157 internal documentation links, Markdown lint over 48 files, and
normalized diff checks. Because this item changes only decision and control
documentation, no new runtime-test result is claimed by the transition.

## Falsification and residuals

Independent falsification found no remaining owner-review blocker. It forced
closure of four load-bearing defects:

- prior invalid validation results are now transitively committed by the final
  seal and cannot be deleted, substituted, reordered, forked, or borrowed from
  another ChangeSet;
- the restricted locale grammar and literal alias behavior are internally
  consistent;
- the v1-to-v2 Known State bridge, query behavior, authoring activation, and
  rollback matrix are explicit; and
- resource-intent issuance is operational evidence outside authoritative
  content state, so it cannot stale the baseline it names.

The P-0003/P-0007 dependency is also closed: reopened P-0003 can bind P-0002's
normative operation, action, field, and resource projections without waiting
for Schema digests that P-0007 has not produced. P-0005 later binds the
registered P-0007 Schemas to that accepted authority registry.

Accepted candidate residuals:

- `ContentResourceIntentV1` has no independent cancellation record; exact base
  checks, ContextPack expiry, current Delegation, and Human approval bound this
  risk for Milestone 2;
- P-0003 must tighten its still-Proposed locale Schema and regenerate authority
  vectors before owner review; and
- general variants, fallback, deletion, base-Object mutation, dynamic subtree
  authority, and higher-cardinality performance remain deferred.

Project-owner acceptance resolves the decision gate. The remaining uncertainty
is implementation risk owned by P-0007 and authority-contract reconciliation
owned by P-0003, not an unresolved P-0002 content decision.

## Evidence paths

- `docs/work/evidence/P-0002/receipt.md`
- `docs/work/evidence/P-0002/manifest.json`
