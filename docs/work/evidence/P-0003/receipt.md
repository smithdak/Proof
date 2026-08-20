# P-0003 reconciliation decision and acceptance receipt

## Outcome

P-0003 produced a qualified reconciliation candidate and project owner
`smithdak` accepted its bounded decision at `2026-08-20T19:52:12.756Z`. The
exact substantive candidate is
`38999d01fdce81015179da3162b90f6c382e3eba`, produced from claim commit
`5d8ac4f4e386f8313e9256da4fbeef0143e1fa9b` and clean `main` base
`8aede43c1e4ec7f24bc0fd4761aa117a5173bfa8`.

The accepted candidate reconciles the previously qualified authenticated-actor profile
with P-0007's supported localized-content candidate
`47153144b4b834cfffab61b328e4551f09fe50cb`. ADR-0011 and its exact C4
replacement are ratified, P-0003 is `done`, and P-0004 is promoted to `ready`.
No authenticated Agent operation is implemented by the acceptance transition.

Nothing was pushed, tagged, released, deployed, or implemented by the
acceptance transition. Live remote state was not queried.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `proof-architecture/p-0003-reconciliation` |
| Worktrees | `1` |
| Base | `8aede43c1e4ec7f24bc0fd4761aa117a5173bfa8` |
| Claim commit | `5d8ac4f4e386f8313e9256da4fbeef0143e1fa9b` |
| Reconciliation candidate | `38999d01fdce81015179da3162b90f6c382e3eba` |
| Candidate parent | `5d8ac4f4e386f8313e9256da4fbeef0143e1fa9b` |
| Acceptance base | `2d6f87301e75031f5c6f43e90dea525b27f167cf` |
| Accepted by | `smithdak` |
| Accepted at | `2026-08-20T19:52:12.756Z` |
| Candidate delta | 23 paths; 1,690 insertions; 148 deletions |
| Qualified at | `2026-08-20T19:39:00.6713118Z` |

The candidate changes nine authority-conformance files, 13 architecture,
decision, reference, product, or work-control documents, and one retained Rust
conformance test. It changes no runtime implementation, migration, database,
private key, credential, production configuration, Release, or Proof.

## Reconciled decision

The reconciliation closes the P-0002/P-0007 dependency without versioning
`DelegationV2`:

- The grant already has the exact Workspace, Environment, Object, Schema, and
  locale axes required by P-0007. Immutable Human-issued
  `ContentResourceIntentV1` tuples narrow that permission product; they do not
  create a new grant axis and an Agent cannot issue or replace them.
- `AuthorityOperationRegistryV1` retains the three implemented v1 read pairs,
  removes the nine unimplemented v1 write reservations, and binds all 11 P-0007
  v2 pairs to their action, localized input Schema, closure anchor, four
  resource-projection profiles, evidence selectors, five budget profiles,
  idempotency class, consequence, and enablement wave.
- Localized lifecycle operations authorize the complete verified intent. A
  subset grant never produces a filtered ChangeSet, diff, validation result,
  Edition, or Release.
- `object.query_released/v2` first checks the requested Workspace,
  Environment, Objects, locales, and a nonempty Schema grant, then internally
  resolves only the requested Objects' Schemas from the current Release and
  Edition and checks those Schemas before disclosure.
- Generated ChangeSet, Edition, and Release identifiers are exact evidence
  selectors, not grant axes. Intent and ContextPack identifiers/digests are
  command-bound directly or transitively through the selected ChangeSet.
- Localized validate and submit use null signed idempotency fields with closed
  derived internal keys; adapters cannot choose a different derivation. Reads
  remain fresh authorized attempts with no application key.
- `DelegationV2.scope.locales` and
  `AuthorizationDecisionV2.requested_resources.locales` now use P-0002's exact
  grammar. Lowercase variants and literal aliases are valid; mixed-case
  variants are not.

The strongest rejected reconciliation alternative was a tuple-scoped
`DelegationV3`. It represents nonrectangular targets directly but duplicates
the already immutable Human intent, expands signed-grant and portable-evidence
closure, and addresses no demonstrated Milestone 2 failure. It becomes valid
only if the intent cannot remain Human-authoritative or source-read and
target-write scopes diverge.

## Falsification result

The strongest counterargument was that exact Schema authorization cannot be
known before a v2 released query resolves current state, making the selected
five-axis profile either incomplete or an existence oracle. The first draft
overreached by naming every Edition target Schema. The falsification pass
narrowed the normative source to only the requested Objects' resolved Schemas,
requires the caller-controlled axes and nonempty Schema grant before internal
resolution, and requires exact Schema membership before disclosure.

The retained test independently parses the authority and localized Schemas and
then proves:

- exact equality among the 14 operation pairs in `OperationV1`,
  `AuthorizationDecisionV2`, and the authority registry;
- exact action equality with all 11 P-0007 localized registry rows and input
  Schema constants;
- canonical registry order, only three v1 pairs, four exact resource profiles,
  closure anchors, selector sources, retry classes, and budget classes;
- Delegation action-set equality with the registry;
- lowercase variant and literal-alias acceptance plus mixed-case rejection in
  both Delegation and decision Schemas; and
- rejected cases for each missing localized grant axis and a superseded v1
  write pair.

Confidence is **high** that the accepted decision is complete for its bounded
local profile. A future requirement that would reopen that judgment is a required
localized grant dimension not expressible by the five axes, an Agent-mutable
resource intent, a P-0007 operation/input mismatch, or a Milestone 2 requirement
for hostile same-UID containment or Agent-to-Agent delegation.

## Verification

| Surface | Result |
| --- | --- |
| Retained P-0003 registry/falsification test | Passed |
| Existing localized portable-conformance control | Passed |
| Strict Clippy for the retained test with `-D warnings` | Passed |
| Complete locked Ubuntu workspace suite | 354 tests; 22 successful suite summaries; zero failures |
| Authority JSON parse | 67 files |
| Documentation links | 163 internal links |
| Work-control validation | 7 items; lifecycle, dependencies, map parity, transitions, and evidence contracts passed |
| Rust formatting and normalized diff checks | Passed |
| Markdown lint, pinned `markdownlint-cli2@0.23.2` | Passed |

The complete Windows workspace attempt reached the CLI integration suite but
20 fixtures failed before domain behavior because the Windows build reports
`proof.auth.unauthenticated`: it provides no local identity adapter for that
platform. Candidate-specific Windows conformance and strict lint passed. The
same complete locked workspace suite then passed on Ubuntu with runtime
temporaries under `/tmp`. The Windows result is an unsupported-surface
qualification, not a candidate-attributable defect or a Windows support claim.

Full logs are retained under ignored `target/p0003-*.log` paths. The manifest
binds checkout-independent Git blob SHA-256 values for all 23 candidate paths;
worktree materialization hashes are deliberately not substituted for Git bytes.

## Historical qualification and residuals

The initial P-0003 profile was qualified at architecture commit
`cf4e57d0ace70e80377d16b57e43b6099129e0d0` and integrated at
`b124b2491dfd787df1a562786f122fb6e62a1497` from base
`11eb4dfb57577e52ddd95822a00fed3001b5164a`. That candidate correctly left its
localized operation/resource closure blocked on P-0002. This receipt supersedes
that blocker while preserving the prior commit lineage.

Accepted candidate residuals remain unchanged:

- same-UID/private-Workspace processes are inside Human/admin trust, so the
  local key proves attribution and integrity, not containment;
- the profile does not attest process, executable, model, or runtime identity;
- valid-prefix rollback or a hidden authority fork needs an independently
  pinned authority head to detect; and
- predecessor-root compromise requires a future explicit trust epoch rather
  than ordinary dual-signed rotation.

## Evidence paths

- `docs/work/evidence/P-0003/receipt.md`
- `docs/work/evidence/P-0003/manifest.json`
