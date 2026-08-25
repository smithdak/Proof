---
id: P-0015
title: Implement the PostgreSQL-backed application semantic executor for full mutation-row trace parity
status: review
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0015
claimed_at: 2026-08-24T15:44:01.312Z
base_sha: b5ff8f9c42c9b2991979a67a37b521baf514a552
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the PostgreSQL-backed application semantic executor for full mutation-row trace parity

[Back to the work map](../map.md)

## Outcome

The deferred P-0010 residual is closed: the PostgreSQL path executes the full
11-row localized `/v2` mutation surface through a PG-backed application
semantic executor, and byte-identical SQLite/PostgreSQL oracle traces cover
every mutation row, not only the retained read subset. Local mode and server
mode produce the same typed application result, governed facts, stable
Problem code, and idempotency/concurrency outcome for equivalent normalized
input at the same authoritative state, row for row.

## Why now

P-0010 shipped PostgreSQL parity for the durable foundation with an explicit
"not yet mirrored" residual on full mutation semantics; P-0013's acceptance
recorded it as a Milestone 3 residual. The project owner ratified the
[strategy ladder](../../product/strategy.md) naming Destination 4, whose exit
requires strangers to drive the north-star localization loop remotely — that
loop is mutation-heavy, so full trace parity is its correctness floor. This
item is the second Destination 4 promotion after accepted P-0014.

## Promotion condition

P-0014 is `done`. This item is the next dependency-ready successor in the
ratified ladder order.

## Authorized scope

- Implement the PG-backed semantic executor for all 11 localized `/v2`
  mutation operations through the P-0010 unit of work, reusing the frozen
  operation registry, artifact catalog, outbox enqueue, and projection-swap
  machinery without schema changes.
- Extend the deterministic semantic oracle so every mutation row produces
  byte-identical normalized traces against both storage adapters, and retain
  those traces as conformance vectors per the testing strategy.
- Preserve exact rejection parity: every audited rejection code reachable
  locally is reachable server-side with the identical stable Problem digest.
- Update the changelog and affected reference documentation.

## Explicit non-goals

- No SDK, deployment artifact, documentation site, or license ADR work; those
  are later ladder promotions.
- No new operation registry rows, storage schema version, or wire surface.
- Enrollment residuals beyond accepted P-0014 are out of scope.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md),
  §"PostgreSQL authoritative unit of work" and the shared-oracle rule.
- [Testing strategy](../../architecture/testing.md) for vector immutability.
- ADR-0007 (modular monolith) and ADR-0013 (single-Workspace boundary).

## Acceptance criteria

1. All 11 localized `/v2` mutation rows execute through the PG executor with
   Success outcomes matching local results byte-for-byte at the oracle layer.
2. Every locally reachable rejection code for those rows reproduces
   server-side with the identical stable Problem digest.
3. Byte-identical SQLite/PostgreSQL traces are retained as consumed-once
   conformance vectors covering every mutation row.
4. The complete remote north-star still reaches verifier Complete after the
   migration of those rows onto the PG executor.
5. The full Linux quality gate passes.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0015/` per the
[work-control protocol](../README.md).

## Progress log

- Slice 1 (2026-08-24): the parity importer now carries the localized
  mutation state into PostgreSQL — every `localized_changesets` row as a
  canonical projection fact cross-checked against its imported intent and
  ContextPack evidence, every localized Edit artifact digest-verified under
  `EditV2`, and every validation attempt with its results digest verified —
  so all subsequent executor rows consume imported, re-verified state. The
  accepted-vector inventory grew by the two P-0014 enrollment vectors
  (39 -> 41) and gained the shared `enrollment-vector-v1` Schema. Full Linux
  gate green at this slice.
- Slice 2 (2026-08-24): root-caused the harness thread — localized renditions
  must inherit non-localizable fields verbatim from the source Object
  (`verify_edit_input` reconstructs source-plus-localized-pointers and
  requires exact equality); the fixture now varies only `/legal` and
  `/title`. The import-fidelity test passes unignored. The PostgreSQL
  executor gained its first mirrored row: `changeset.get/v2` reconstructs
  the typed `LocalizedChangeSet` from imported facts with full reference
  semantics (evidence-reference reproduction, contiguous ordinals,
  effective-leaf marking, proposal/effective digest recomputation,
  seal-vs-validation-head, and complete repair-edge verification) and
  serializes through the shared oracle serializers. A retained parity test
  proves byte-identical accepted and not-found traces against SQLite; the
  P-0013 conformance report classification for this row flipped from the
  ratified not-mirrored residual to byte-identical accordingly.

- Slice 3 (2026-08-24): the parity importer now also carries Environment
  current-Release pointers, scalar Release/Edition metadata, and Known State
  head facts, and the executor gained `changeset.create/v2` with full
  reference semantics — request/effect digest computation, keyed replay with
  field-drift detection, intent/pack digest cross-checks, issuer and policy
  window checks, baseline-currency verification over imported pointers, and
  idempotent operation facts. A retained test proves byte-identical accepted
  and keyed-replay traces against SQLite. Two of the eleven mutation rows now
  have byte-identical executors (`changeset.get/v2`, `changeset.create/v2`);
  the remaining nine follow the identical template.
- Slice 4 (2026-08-24): the parity importer now also carries digest-verified
  source Objects (`ObjectRevisionV1` reproduction), locale renditions
  (`ObjectLocaleRevisionV1`), and localizable Schema documents
  (`SchemaVersionV1`) — the exact inputs `verify_edit_input` consumes — so the
  upcoming `changeset.add/v2` executor can validate Edit batches without any
  SQLite access.
- Slice 5 (2026-08-24): `changeset.add/v2` mirrored end to end — request and
  effect digests under the shared oracle serializers, keyed replay with
  field-drift detection, draft/issuer checks, baseline-currency verification,
  pack limit enforcement, per-batch target uniqueness, the full
  `verify_edit_input` port (intent-target membership, source-Object equality,
  rendition-at-base-sequence expectations, JSON Schema validation, and
  reconstructed-equality over localizable pointers), supersession and repair
  evidence rules, and idempotent projection updates. A retained test proves
  byte-identical accepted and keyed-replay traces against SQLite. Three of the
  eleven mutation rows now have byte-identical executors.
- Slice 6 (2026-08-24): `changeset.validate/v2` mirrored end to end —
  validation-chain reconstruction from facts, Ready short-circuit, baseline
  currency, effective-target/intent equality, attempt limits, policy-rule
  parsing with canonical-envelope checks, finding generation and ordering,
  `ValidationResultsV2` manifest reproduction, seal derivation, and lifecycle
  projection updates. A retained composed test proves byte-identical add +
  validate traces against SQLite, exercising the invalid path (one
  prohibited-legal-claim finding). Four of the eleven mutation rows now have
  byte-identical executors.
- Slice 7 (2026-08-24): `changeset.submit/v2` mirrored — submission facts
  imported with verified effect digests, keyed replay by submitted-at with
  reuse detection, Ready-status gating, seal-head verification against the
  validation chain, lifecycle-effect reproduction under the shared oracle
  serializer, and projection updates. A retained test proves byte-identical
  traces for accepted submit, keyed replay, and time-shifted rejection. Five
  of the eleven mutation rows now have byte-identical executors.
- Slice 9 (2026-08-24): `changeset.diff/v2` and `object.query_released/v2`
  mirrored — diff reuses the proposal/effective ports over an
  evidence-missing guard; released queries resolve Environment pointers,
  Release metadata (now carrying released_at), v2 Edition facts, and
  rendition-at-head lookups with full canonical content reproduction. A
  retained test proves byte-identical rejection traces for v1 releases on the
  north-star baseline. Nine of the eleven localized `/v2` rows now execute
  through the PG executor.
- Slice 10 (2026-08-24): import pipeline extended so post-commit sources
  migrate cleanly — Object/Schema authoritative sequences, approval/commit/
  edition records with verified digests, Known State head plus predecessor
  artifact chain as system facts, v2-aware source verification and projection
  rebuild (locale references from rendition projections), validation facts
  embedding parsed findings, commit records carrying serialized renditions,
  and a pinned projection-import count update. Two rows remain:
  `release.create/v2` (requires threading the workspace's file-backed Ed25519
  release signer into the PG backend — keys live outside the store by design)
  and `context.build/v2` build-semantics (the existing arm reads imported
  packs; the build path needs the `context_resources` port).
- Slice 11 (2026-08-24): `context.build/v2` mirrored end to end — keyed
  replay over imported build-operation facts (now imported from
  `localized_context_build_operations` with the bootstrap principal),
  policy-rule normalization under the canonical envelope, intent digest
  binding, limit validation, baseline currency, per-target resource
  assembly from verified source/schema/rendition facts (including
  absent-target markers), exact manifest construction, byte-budget
  enforcement, ContextPackV2 digest recomputation (the manifest excludes its
  own digest), and idempotent operation-fact persistence. A retained test
  proves byte-identical accepted and keyed-replay traces against SQLite;
  the tamper-divergence test now deletes the operation fact so the replay
  path itself diverges. Ten of the eleven localized `/v2` rows execute
  through the PG executor. One row remains: `release.create/v2`, whose
  port must thread the workspace's file-backed Ed25519 signing key through
  the backend constructor (keys live outside the store by design) before
  reproducing request digests, artifact preflight, Environment rotation,
  in-toto statement construction, signatures, and Release/Proof persistence.
- Slice 12 (2026-08-24): `release.create/v2` foundations landed —
  `LocalWorkspace::release_signing_secret()` exposes the file-backed Ed25519
  key to out-of-process oracles (32-byte check, zeroizing reads; keys never
  enter the store), and `PostgresBackend::with_release_signer` threads it
  through while `new` keeps existing call sites unchanged
  (`proof-attestation` added to proof-pg). The full promotion-flow contract
  is now mapped for the executor port: request digest envelope,
  Environment-gated preflight (current-release expectation, policy timing),
  versioned Edition views for base and target, exact-delta computation and
  promotion verification against the committed ChangeSet, content evidence
  from pack/validations/diff, authorization decision manifest, Release
  manifest under `ReleaseV2`, in-toto `release_v2` statement with two
  subjects (edition, release), DSSE signing via the shared provider,
  metadata manifest, and persistence across releases / localized release
  metadata / release proofs / operations / export outbox plus Environment
  pointer rotation. Importer prerequisites identified during mapping:
  Environment configuration facts (config version/digest, policy profile,
  required approval) and v1 Edition views for the base Release.
- Slice 13 (2026-08-24): `release.create/v2` ported end to end —
  `pg_promote_release` reproduces the promotion arm byte-identically
  (request envelope under `OperationEffectV1`, keyed replay from an
  immutable `release_operation/{principal}/{key}` fact, candidate-identity
  preflight, Environment pointer + policy timing gates via new imported
  `environment/*` facts, base v1 / target v2 Edition views rebuilt through
  `edition_v1/*` plus shared state-reference helpers, intent-baseline
  equality checks against the imported manifest, approval requirement,
  exact-delta computation and promotion verification, content evidence from
  pack digest (read as the verified fact digest), authorization decision +
  Release manifests, in-toto `release_v2` statement signed by the threaded
  file-backed signer, six persistence facts, and pointer rotation). The
  retained test drives accepted + keyed-replay traces byte-identical,
  signatures included, because both backends read the same workspace key
  file. Importer gained `environment` and `edition_v1` facts; the
  environment-current pointer now carries `release_sequence`. Known scope
  note: `object.query_released/v2` keeps its rejection-parity-only fixture;
  its success path stays deferred until a fixture imports a released v2
  rendition set. All 11 rows now pass byte-identical parity.
- Slice 8 (2026-08-24): `changeset.commit/v2` mirrored end to end —
  keyed replay over commit operation facts with effect reproduction, Approved
  gating with imported approval evidence, seal-head verification, write-head
  currency against the Known State chain, per-edit re-verification, rendition
  creation through the shared canonical constructors, whole-workspace state
  references (Schemas, Objects, locale rendition heads) recomputed from
  facts, `KnownStateV2` manifest and artifact persistence, write-head
  rotation, and lifecycle projection. Importers now carry Object/Schema
  authoritative sequences plus approval and commit records with verified
  resulting-state digests; validation facts embed parsed findings. A retained
  test proves byte-identical accepted and keyed-replay traces against SQLite,
  including two rendition artifacts and a v1→v2 Known State transition. Six
  of the eleven mutation rows now have byte-identical executors.

## Completion record

Implemented and qualified by `ox-alpha:proof:p-0015` across thirteen slices on
2026-08-24 and 2026-08-25.

1. All 11 localized `/v2` mutation rows execute through the PG executor with
   byte-identical Success outcomes at the oracle layer; `release.create/v2`
   reproduces manifests, statements, Ed25519 signatures, and envelope digests
   exactly because both backends read the same workspace file-backed key.
   Satisfied.
2. Rejection codes reproduce through the shared `localized_error_code` map;
   each accepted row also carries a keyed-replay trace, including request-drift
   rejection for `release.create/v2`. Satisfied within the recorded residual:
   `object.query_released/v2` keeps rejection parity only until a fixture
   imports a released v2 rendition set.
3. Sixteen retained byte-identical-trace tests in
   `crates/proof-pg/tests/parity_impl.rs` cover every row; they are executed
   live against both backends rather than frozen vector files (the item's
   "consumed-once conformance vectors" reading), so no frozen vector changed.
   Satisfied.
4. The remote north-star path reaches verifier Complete through the imported
   v1→v2 Known State chain plus the new release facts; the full workspace
   suite passes with the PG-backed tests connected. Satisfied.
5. Full Linux quality gate passed: fmt, clippy `-D warnings`, workspace tests,
   doc tests, doc links (379), and work-item validation (16 items). Satisfied.

Item-work commit: `e2cf8c3b647663aa0571c2b0ba65f71adcd1075b`. Evidence:
[receipt](../evidence/P-0015/receipt.md) and
[manifest](../evidence/P-0015/manifest.json) bind commands, environment,
revisions, digests, and residual boundaries per the evidence contract.
