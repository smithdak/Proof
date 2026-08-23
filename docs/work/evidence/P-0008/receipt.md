# P-0008 decision qualification receipt

## Outcome

Decision qualification is supported for immutable P-0008 candidate
`c461b1b60bece277b88c6a5aee55c200658ab327`, with tree
`20385096a71904103ae898bc127eea6c13980cc8`. The candidate fixes a bounded,
single-Workspace collaboration-server contract and passed the complete Linux
quality gate. It is eligible for project-owner review only.

Project-owner acceptance has not occurred. ADR-0013 remains **Proposed**,
`accepted_by` and `accepted_at` remain null, and no implementation successor
exists or is `ready`. This packet does not implement or provision a server,
PostgreSQL database, identity provider, artifact store, worker, preview
renderer, SDK, console, hosting provider, or deployment.

The machine-readable revision, command, environment, inventory, digest,
falsification, and gate data are in `manifest.json`. Criterion-level AC1-AC14
coverage is in `traceability.md`. These evidence files were created after the
immutable candidate and are intentionally absent from its candidate inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0008 base | `bea0075a74237626848e1c2f8bb070248b773863` |
| Claim commit / candidate parent | `87bddefe700433adc844325b6590a875b93f7117` |
| Candidate | `c461b1b60bece277b88c6a5aee55c200658ab327` |
| Candidate tree | `20385096a71904103ae898bc127eea6c13980cc8` |
| Qualified at | `2026-08-23T11:29:42.553Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 75 paths; 28,408 insertions; 33 deletions |
| Parent-to-candidate delta | 73 paths; 28,399 insertions; 28 deletions |
| Collaboration Schemas | 14 closed JSON Schemas |
| Collaboration vectors | 39 JSON vectors |
| Retained P-0008 tests | 10 Rust tests, included in the exact-candidate workspace aggregate |

The base-to-candidate inventory includes the narrow claim mutation. The
parent-to-candidate delta contains the proposed contract, ADR, conformance
Schemas and vectors, retained decision-contract harness, dependency-only test
support, and aligned architecture, product, reference, and threat-model
documentation. It adds no server crate, runtime adapter, migration, provider
configuration, credential, private production key, deployment configuration,
Release, or customer Proof.

## Qualified proposed decision boundary

### Topology, identity, and collaboration

The candidate selects one modular server deployment for one Workspace and
multiple Principals. Remote Human authentication uses a same-origin
confidential backend-for-frontend and an opaque server-side session. Issuer,
subject, token, session, Principal, binding, role, and transport connection are
separate concepts. An Agent request requires both a currently authenticated
requesting Human and a separately verified single-use Agent command; neither a
Delegation nor request-supplied identifier authenticates the requester.

The exact north star names the requesting Human, operating Agent, distinct
reviewer/approver, publisher, authoritative review and configuration facts,
transaction heads, immutable artifacts, private preview result, evidence
capture, and independent verifier inputs. Approval binds the inspected
ChangeSet closure and exact validation, policy, configuration, and authority
state. Role assignments and configuration proposal/activation are append-only
authority facts with explicit separation of duties. Comments and UI state are
never workflow authority.

### HTTP and shared application contract

The closed HTTP registry has nine routes: four transport/session routes and
five application/data routes. Its Human RPC projection is an exact ordered
23-row set; the complete registry has 40 operation rows. Every row binds its
authentication route, shared application operation, strict input and result
Schemas, authorization rule, Problems, idempotency, concurrency, limits, and
effect-digest rule. The adapter cannot introduce an HTTP-only or SQL-only
mutation.

The candidate freezes three distinct commitments rather than allowing a
cross-paired policy registry:

- accepted Agent authority registry SHA-256
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`;
- non-circular remote authorization projection SHA-256
  `e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b`;
  and
- complete HTTP operation registry SHA-256
  `e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf`.

Registry lookup is route-qualified by operation name, version, and
authentication route. Consequence validation covers success, replay,
idempotency conflict, precondition conflict, and mapped application failure,
with exact required and forbidden result, prior-result, effect, and Problem
fields. Authentication, current authorization, and disclosure-neutral failure
precede idempotency lookup and retained-result disclosure.

### PostgreSQL, artifacts, outbox, and preview

The selected persistence contract uses one serializable, Workspace-scoped
write lane. One authoritative transaction covers the locked causal heads,
presentation consumption, signed decision, application facts, consequence,
idempotency ownership, Proof/Release state, projections, artifact catalog, and
outbox enqueue. Complete-transaction retry, ambiguous-commit reconciliation,
migration phases, projection generation swaps, and exact crash outcomes are
specified. The contract does not claim a PostgreSQL implementation or physical
power-loss qualification.

Fork-capable signed bytes must become durable in the authoritative transaction.
Other immutable bytes may be privately and content-addressably staged before
commit, but cannot be externally visible until catalog commit. Outbox delivery
is at least once, generation-scoped, ordered, leased, replayable, and
poison-manageable. Release commit and preview delivery remain separate states;
no exactly-once, synchronous-publication, or immediate-delivery claim is made.
The first preview is private and names one immutable Release and exact locale,
with no fallback or current-at-worker reinterpretation.

### Evidence export and caller trust

Evidence export separates an immutable keyed capture, whose exact replay
remains `pending`, from a fresh no-key mutable status read. A ready export is
an uncompressed logical member map, not an archive. Artifact reads are selected
by exact kind and digest and must match committed length, kind, digest, and
headers.

The remote manifest has exactly six root descriptors. Included roots and
external-required roots have distinct acquisition paths, while nested
Release-closure artifacts remain explicitly enumerated. Export capture,
assembly, readiness, and snapshot metadata are producer statements, not
authenticated freshness claims.

Offline verification receives a separate exact `VerificationTrustPolicyV2`,
caller-pinned head, closed registry resolver, role-separated key bytes,
disclosure requirements, limits, optional checkpoints and openings, and exact
external artifact bytes. Producer hint arrays are empty, untrusted, and cannot
trigger fetching. A valid signature, producer key label, URL, or supplied
checkpoint never creates caller trust or proves globally latest history.

The retained Complete, Incomplete, and Invalid rows are normative successor
scenarios, not observed reports. General reports and the narrower
`conformanceReport` subtype have exact component and first-applicable primary
reason precedence. The retained decision and application consequence are
decoded, canonicalizable, signable payload candidates; no matching signed pair
or server execution is claimed.

## Conformance and falsification result

The retained harness closes and resolves all 14 Schemas, validates all 39 JSON
vectors, recomputes the qualified canonical and raw-byte commitments, verifies
the positive Ed25519 DSSE vector, proves exact registry and authority
projections, checks transaction/delivery and evidence semantics, and applies
semantic rejection mutations. Its ten tests are included in the immutable
candidate's complete workspace gate.

The rejection-requirements manifest contains 158 unique non-executable rows:
88 HTTP-applicable rows with 276 exact route/operation bindings and 70
explicitly non-HTTP rows. Every row reserves one future test identifier. This
is a closed implementation-qualification plan, not evidence that those future
server tests ran.

Falsification found and repaired concrete candidate defects before the
immutable commit, including an Agent-denial ordering mismatch with the
accepted evaluator, operation-only rather than route-qualified consequence
selection, incomplete consequence-outcome coverage, and a report Schema that
could select a later primary reason instead of the required first-applicable
component. The final bounded recheck found no remaining decision-candidate
blocker. That result does not substitute for project-owner acceptance or
future executable server evidence.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `rtk cargo fmt --all -- --check` | Passed |
| `rtk cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `rtk cargo test --locked --workspace --all-targets --all-features` | 614 passed across 37 suites; 0 failed; 383.63s |
| `rtk cargo test --locked --doc --workspace --all-features` | Seven doc-test suites; 0 tests; 0 failures |
| `rtk node scripts/check-doc-links.mjs` | 203 internal documentation links passed |
| `rtk node scripts/check-work-items.mjs` | Eight work items passed metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts |
| `rtk git diff --check` | Passed |

The full workspace aggregate at the immutable candidate is controlling. The
Linux namespace capability required by retained bubblewrap coverage was
available, so the complete suite did not replace containment execution with a
skip.

## Residual risks and nonclaims

Project-owner review must evaluate the following exact boundaries:

- P-0008 qualifies a proposed decision contract, not HTTP, PostgreSQL, OIDC,
  artifact-store, worker, preview, or verifier runtime behavior. Valid-shape
  fixtures, decoded signable payloads, semantic mutations, and the
  non-executable rejection matrix are not relabeled as server observations.
- No materialized remote logical map or actual Complete, Incomplete, or Invalid
  verifier report exists. No matching signed remote decision/consequence pair,
  authenticated capture/readiness fact, globally latest Release proof, or true
  immediate-Release proof is claimed.
- The supplied checkpoint and trust policy validate only the exact disclosed
  closure. They cannot prove that a producer omitted no same-Environment
  Release or later authority history.
- Environment-creation chronology, causal-head-bearing remote approval, and
  complete new direct-Human remote evidence are required successor closures.
  Historical v1/v2 bytes and conservative Incomplete outcomes are not
  reinterpreted or retroactively completed.
- Missing pre-v14 presentations, some malformed historical idempotency
  reconstructions, redundant non-authoritative `EditBatchV1`, and the accepted
  local verifier's structural-only finding-code coverage remain bounded
  historical limitations.
- The accepted local same-UID time-of-check/time-of-use boundary, hostile
  same-UID isolation, and Windows identity/runtime containment remain outside
  this decision. A remote architecture does not retroactively strengthen them.
- Signed evidence and independent checkpoints can detect PostgreSQL or operator
  inconsistency only relative to the supplied closure. Complete database/key
  compromise remains an availability and total-forgery boundary.
- Initial localized Schemas retain known high-cardinality arrays without new
  registry item maxima, and the retained `context.build/v1` producer/verifier
  limit mismatch remains successor parity work. The candidate does not claim
  invented limits or silently change accepted local Schemas.
- High-cardinality recursive Release-history stack safety, power-loss and
  storage-controller durability, backup/restore, garbage collection for
  privately staged orphans, production SLOs, and provider behavior are not
  qualified.
- No browser bearer-token API, public CORS profile, third-party embedding,
  public preview, unattended Agent requester, multi-issuer or just-in-time
  provisioning profile, SCIM/federation, IdP-group authority, approval quorum,
  comment-gated workflow, workload identity, SPIFFE, Delegation chaining, or
  broader policy language is selected.
- No multi-Workspace tenancy, cross-Workspace transaction, tenant row-level
  security, KMS/HSM custody, high availability, backup/restore, disaster
  recovery, multi-region ordering, public release, push, tag, package
  publication, deployment, production mutation, live remote verification, or
  customer proof is included.
- SDK, console, server framework, PostgreSQL adapter, OIDC provider, artifact
  store, worker, preview renderer, key provider, and hosting topology remain in
  map fog. No implementation successor is created or promoted before owner
  acceptance.

The selected modular server must be reopened or replaced before implementation
if it cannot express an accepted operation without adapter privilege, cannot
atomically preserve the authority/application/evidence boundary, requires UI
state for approval, or requires external publication before commit. Later
service extraction requires measured write-head contention, unmet objectives,
independent security isolation, or stable team/deployment ownership rather
than speculative decomposition.

## Disposition

Engineering recommends project-owner review of this exact candidate and these
residual boundaries. This receipt does not execute that disposition. The
[P-0008 work item](../../items/P-0008-ratify-collaboration-server-contract.md)
must remain short of `done`, ADR-0013 must remain Proposed, and no successor may
become `ready` until the project owner explicitly accepts the candidate,
evidence commit, and residuals after presentation.

Evidence paths:

- `docs/work/evidence/P-0008/receipt.md`
- `docs/work/evidence/P-0008/manifest.json`
- `docs/work/evidence/P-0008/traceability.md`
