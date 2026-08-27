---
id: P-0013
title: Implement remote evidence and qualify Milestone 3
status: done
wave: now
kind: qualification
blocked_by: [P-0012]
claimed_by: deepseek:proof:p-0013
claimed_at: 2026-08-24T01:30:26.291Z
base_sha: ab3071349162a945e698036070f72a64441e17ba
review_gate: project-owner
accepted_by: smithdak
accepted_at: 2026-08-24T13:30:25.292Z
required_reading: []
allowed_paths: []
---

# Implement remote evidence and qualify Milestone 3

[Back to the work map](../map.md)

## Outcome

Proof implements the remote evidence boundary and qualifies Milestone 3:
`RemoteEvidenceBundleV2` export over the exact six-root uncompressed logical
member map, immutable keyed export capture with a separate no-key status
read, kind-and-digest artifact acquisition, the `proof-verifier` remote
authority and remote evidence v2 modes under explicit caller
`VerificationTrustPolicyV2` inputs, the closed `RemoteVerificationReportV2`
with its `conformanceReport` subtype, and the complete remote north-star
(two Humans and one Agent) exercised end to end over the HTTP server and
PostgreSQL with the retained rejection, crash, and security matrices — after
which the project owner accepts the Milestone 3 exit evidence and residual
boundaries.

## Why now

P-0009 through P-0012 implemented every predecessor the accepted contract
requires: remote actor contracts and the semantic oracle, the PostgreSQL
parity foundation, the HTTP/OIDC server boundary, and the outbox/private
preview delivery. The accepted contract names this item as the fifth and
final dependency-ordered successor. Milestone 3 cannot claim its exit
condition until remote evidence verifies independently and the complete
north star plus the retained matrices execute against the server.

## Promotion condition

Satisfied by completed P-0012 candidate
`9c282ea66d588250fc6cc8a58a2aacf8320dee45`, bound by Engineering evidence
commit `9ae3cfaadb8b18c94b3f353e827aecf07c4203dd`, per the accepted
[collaboration-server
contract](../../architecture/collaboration-server.md) successor order.
ADR-0013 remains the implementation authority.

## Authorized scope

- Implement `RemoteEvidenceBundleV2`: the exact uncompressed logical member
  map (not tar/zip/compressed) over the six typed roots —
  `release-artifact-closure` (`RemoteReleaseArtifactClosureV1`), one
  canonical `RemoteAuthorityRecordSetV1`, exact
  `AuthenticatedActorContextEvidenceV2` bytes, exact
  `RemoteAuthenticationEventV1` bytes, exact `CommandInputV1` bytes, and the
  exact Agent authenticated-command DSSE envelope. Reserved `bundle.json`
  and `manifest.json` entries; every included root and each unique nested
  artifact at the deterministic path declared by the Release closure;
  external-required roots absent and caller-supplied; absolute or
  dot-segment paths, backslashes, duplicate normalized paths, undeclared or
  missing entries, kind/digest/length mismatches, and any count or byte
  limit violation are Invalid. Maximum 4,096 artifact bodies; the two
  reserved descriptors are accounted separately.
- Implement `evidence.export/v2` (`content.publisher` or
  `evidence.auditor`): one immutable `EvidenceExportCaptureV2` committed in
  a short serializable transaction with the
  `pre-export-attempt-locked-heads` capture boundary (the capture never
  recursively includes its own decision, effect, or consequence); always
  returns the exact keyed `EvidenceExportResultV2` with `status: pending`;
  every same-key equivalent replay returns the same create-result bytes even
  after assembly finishes. A worker builds from the capture outside the
  transaction; a second transaction verifies the bytes before
  pending-to-ready. `evidence.export.get/v1` is the no-key fresh
  authentication/authorization lifecycle read returning the mutable
  `EvidenceExportStatusV1` with null digests/counts while pending or the
  exact reserved digests/counts/bytes when ready; it cannot replace the
  capture or the keyed result. Ready status publishes the exact
  `remote_evidence_bundle_v2` and `remote_evidence_manifest_v2` digests.
- Implement `evidence.artifact.get/v2` acquisition: addressed and authorized
  by the exact `(export_id, artifact_kind, digest)` triple with revalidated
  kind, length, and digest; a digest under another kind is not an alias; an
  external-required root is a caller obligation, never a producer-download
  selector.
- Extend `proof-verifier` with `proof-verifier/remote-authority/v1`
  (validates a canonical contiguous P8 DSSE suffix from a caller-pinned
  initial head) and `proof-verifier/remote-evidence-v2` (validates the
  closure, the Release/artifact closure, and every attempt companion, then
  enforces Workspace, identity, command, policy, application-key, Release,
  Proof, result, effect, decision, consequence, and authority-head links).
  The verifier has no producer database, network, or authenticated base
  state; every binding, Delegation, revocation, Principal/role, Environment,
  approval, decision, and consequence fact consumed for the selected attempt
  must be present in the supplied suffix. P6 `AuthorityEvidenceBundleV1` and
  its verifier remain unchanged historical local evidence and are neither
  embedded nor relabeled.
- Implement `VerificationTrustPolicyV2` caller inputs: usable
  role-separated authority, Release, and historically selected Agent public
  key bytes; the initial remote head; accepted policies and registry
  hashes; a closed built-in hash-to-canonical-registry resolver; disclosure
  policy; and parser, artifact, record, and byte limits. Optional typed
  authority and Environment/Release checkpoints, required OIDC subject
  openings, and exact external-artifact descriptors/bytes cross the same
  separate input boundary. The first-profile `untrusted_hints` object is
  inert: every root, checkpoint, and resolver array exactly empty,
  `trusted: false`, `auto_fetch: false`; a key ID, allowlist label, URL,
  bundle field, or valid signature alone never creates caller trust. A
  required authority checkpoint must equal the included head in Workspace,
  sequence, digest, and active key; a higher sequence without the
  intervening records is not ancestry.
- Implement `RemoteVerificationReportV2` as the general closed observed
  report for every Complete, missing-material Incomplete, and integrity or
  semantic Invalid outcome, binding the exact manifest, verifier input,
  trust policy, optional checkpoint digests, and execution and selecting
  one primary reason consistent with its component results. The narrower
  `conformanceReport` subtype permits exactly the retained three
  qualification scenarios: complete exact materialization, required OIDC
  opening withheld, and deterministic `object_locale_revision_v1` byte
  tamper. Export ID, snapshot label and heads, capture digest, membership
  plan, manifest, assembly, and readiness remain unauthenticated producer
  metadata: the verifier rejects contradictory repetitions but excludes
  capture integrity, readiness, current-at-snapshot,
  immediate-predecessor, and globally latest claims from Complete.
- Execute the Milestone 3 qualification: the complete remote north-star
  (two Humans and one Agent) end to end over the HTTP server and PostgreSQL
  with the exact separation-of-duties sequence; the retained rejection,
  crash, and security matrix (including the 158-row rejection manifest
  translated into executable tests where applicable, with each rejection ID
  mapping one-to-one to a retained test); the local/server conformance
  report proving the shared application oracle produces identical typed
  traces in both modes; and the P-0006 residual disposition status
  (Environment chronology, causal approval heads, and complete direct-Human
  remote evidence are now closed prospectively).
- Record exact crash-boundary tests for artifact preparation, every
  authoritative transaction boundary, outbox claim/send/acknowledgement,
  lease expiry, retry, poison handling, replay, and preview application.

## Explicit non-goals

- No live OIDC provider, deployment, hosting provider, or production
  mutation.
- No SDK, console, or presentation framework.
- No global-latest Release, immediate-predecessor, or authenticated
  snapshot-readiness proof (explicit retained nonclaim).
- No multi-Workspace tenancy, workload identity, KMS/HSM, high availability,
  backup/restore, or public release.
- No claim that this item closes the accepted same-UID hostile-process or
  Windows containment residuals.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md):
  Evidence export and independent verification, exact remote north star,
  conformance and falsification plan, and P-0006 residual disposition.
- [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
- [Core invariants](../../architecture/constitution.md)
- [P-0012 evidence](../evidence/P-0012/receipt.md)

## Acceptance criteria

- [x] The six-root logical member map exports and re-imports exactly with
      reserved descriptors, deterministic paths, kind/digest/length checks,
      and every path/limit violation classified Invalid.
- [x] Keyed export capture always returns the pending create result and
      replays it byte-identically; the no-key status read observes the
      mutable ready transition independently.
- [x] Artifact acquisition is addressed and authorized by the exact
      kind-and-digest triple with no cross-kind alias.
- [x] The remote authority and remote evidence verifier modes reconstruct
      the supplied closure under explicit caller trust and classify
      Complete, Incomplete, and Invalid exactly, including the three
      conformance scenarios.
- [x] Producer hint arrays are inert; no producer metadata can establish
      freshness, readiness, or latest-history claims in Complete.
- [x] The complete remote north-star (two Humans and one Agent) passes end
      to end over HTTP and PostgreSQL with every separation-of-duties
      check.
- [x] The retained rejection matrix (158 rows) maps one-to-one to executable
      tests where applicable; every applicable rejection executes and
      fails closed.
- [x] The crash matrix covers artifact preparation, authoritative
      transaction boundaries, outbox claim/send/acknowledgement, lease
      expiry, retry, poison handling, replay, and preview application.
- [x] The local/server conformance report proves byte-identical shared
      oracle traces in both modes.
- [x] The full Linux quality gate passes and durable Engineering evidence
      (receipt, manifest, traceability) binds the item-work commit.
- [x] The project owner explicitly accepts the Milestone 3 exit evidence
      and residual boundaries before this item moves from `review` to
      `done`.

## Evidence contract

Record the qualified implementation candidate, crate/module inventory, the
north-star trace digest, matrix execution counts, crash-boundary coverage,
exact command results, and residual boundaries in
`docs/work/evidence/P-0013/`. Produce `receipt.md`, `manifest.json`, and a
criterion-level traceability matrix. Milestone 3 completion requires the
project owner's explicit acceptance recorded in this item.

## Completion record

Ready at `2026-08-24T01:28:44.000Z` after P-0012 candidate
`9c282ea66d588250fc6cc8a58a2aacf8320dee45` closed with Engineering evidence
commit `9ae3cfaadb8b18c94b3f353e827aecf07c4203dd`.

Claimed by `deepseek:proof:p-0013` at `2026-08-24T01:30:26.291Z` from
P-0012 completion commit `ab3071349162a945e698036070f72a64441e17ba`
on `proof-architecture/p-0008-collaboration-server-contract`. No
deployment, provider, or production work is claimed by this item.

Engineering qualified immutable candidate
`1fb53b893b35cf3910f47b4d35ade59ceecfb62a`, whose parent is the skeleton
commit `fde6c2814533bd73c0d67553049a8709ac2fbc7f`, qualified at
`2026-08-24T12:58:37.054Z`. Post-candidate polish commit
`509c6e05bd84f81744679482689ce6ae7007eba5` content-scoped the tamper
conformance scenario and refreshed verifier documentation; the complete
Linux gate re-passed there (869 tests, zero clippy warnings). Engineering
evidence commit `97f31fd` binds the [receipt](../evidence/P-0013/receipt.md),
[manifest](../evidence/P-0013/manifest.json), and
[AC1-AC11 traceability matrix](../evidence/P-0013/traceability.md).
Moved from `claimed` to `review` under `review_gate: project-owner`;
Milestone 3 completion additionally requires the project owner's explicit
acceptance of the exit evidence and residual boundaries.

Accepted by project owner `smithdak` at `2026-08-24T13:30:25.292Z`; moved
from `review` to `done`. Milestone 3 is complete: the single-Workspace
collaboration server implements review, approval, publication, delivery,
and independently verifiable remote evidence under the accepted contract.
No SDK, console, provider, deployment, or production work is claimed by
this completion; the next destination awaits a project-owner decision.
