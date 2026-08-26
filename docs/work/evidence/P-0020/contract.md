# P-0020 decision candidate — Authoring-surface content contract

Status: decision candidate awaiting project-owner review. Executor
`ox-alpha:proof:p-0020`, claimed from `e53920b6113b67abaff4828ee7ddc4266fe2915a`.

Every decision below is grounded in the implemented code at the claimed base;
file:line references cite that tree.

## Ratified authoring north-star

A Human issues a content-resource-intent that carries two **creation slots**
(hero Object, product Object — each pinned to Schema `sch-hero@3` /
`sch-product@1`, target locales `en`, `fr-CA`). An enrolled Agent operating
under a Delegation builds a ContextPack, then proposes one ChangeSet containing
two `object.create` Edits followed by four `object.locale.put` Edits whose
sources resolve intra-ChangeSet to those creations. Validation rejects one
prohibited legal-claim translation as a structured finding; the Agent repairs
it by supersession inside the same ChangeSet. A Human approves the diff; commit
atomically creates the Objects and renditions; Edition and preview Release
follow; `proof-verifier` reaches `Complete` on the exported bundle. An operator
browses `object.list`, sees the register move from draft to released flags, and
fetches the exact Schema document with `schema.get`.

## Decisions

### D1 — Creation enters as a second v2 Edit kind

`LocalizedEditKindV2` (crates/proof-application/src/authority.rs:1928-1934)
gains a second variant, `"object.create"`. Creation Edits ride the existing
`changeset.add/v2` surface, are validated by the same deterministic pipeline,
and are committed by the same `commit_changeset` unit of work that already
produces Known State v2, causal Editions, idempotency, and outbox enqueue
(crates/proof-local/src/localized.rs:5135-5408).

Creation Edit inputs freeze as: `kind`, `object_id` (caller-minted UUIDv7),
`schema_id`, `schema_version`, `canonical_content` (complete RFC 8785 object),
optional `supersedes_edit_id`/`repair_of_validation_result_digest` pair. No
source preconditions exist; instead the inverse precondition applies — the
target Object must not exist in committed state nor earlier in the effective
set (`proof.state.object_exists` otherwise). Commit writes an
`object_revisions` row (`revision=1`, `lifecycle_state='active'`) through the
v2 commit path; the `CHECK (source_object_revision = 1)` rule on
`object_locale_revisions` (crates/proof-local/src/localized.rs:211) is
unchanged because creation never mutates sources.

Intra-ChangeSet causality is normative: `verify_edit_input`
(crates/proof-local/src/localized.rs:4556-4620) resolves an
`object.locale.put` `expected_source` either from committed state or from an
earlier creation Edit in the same effective set, evaluated in ordinal order. A
put naming a source established later in the same ChangeSet is a structured
finding, never a partial commit.

Rejected alternatives:

- Standalone authenticated `object.create` operation mutating outside a
  ChangeSet — violates the constitution's "direct writes to governed content
  do not exist" and forfeits atomicity and evidence. No pivot trigger; dead.
- Reusing the legacy v1 loop — `UnsupportedVersion` after KnownStateV2
  activation (crates/proof-application/src/lib.rs:681-683); local-only,
  unauthenticated for Agents. Dead.
- Human-only creation outside intent closure — rejected: it would split the
  validation regime in two and weaken exact-input validation. Revisit only if
  qualification records slot-minting friction in two consecutive runs.

### D2 — Intent closure extends with creation slots

The immutable resource-intent artifact advances to
`proof.dev/content-resource-intent/v2`: existing `targets` (exact
`(object_id, schema_id, locale)` tuples, crates/proof-application/src/
localized.rs:89-113) plus an optional sorted `creations` array of
`{object_id, schema_id, locales}` slots, bounded by the existing
`MAX_LOCALIZED_TARGETS` arithmetic, verified **non-existing** at baseline
(inverse of today's existence check at crates/proof-local/src/localized.rs
:1096), and consumed exactly once by a matching creation Edit. Baseline
verification, add-time membership checks, and exhaustive validate-time
closure (localized.rs:8670-8680) treat creations identically to targets.
Because `changeset.add/v2`'s registry row is unchanged, the Agent authority
registry and its frozen hash are untouched; delegated Agents gain creation
capability purely through intent contents, preserving P-0002's closed-set
discipline in the opposite direction.

### D3 — Schema reads: `schema.list/v1` and `schema.get/v1`, Human rows only

Both are new Human HTTP registry rows over stored `schema_versions`
(crates/proof-local/src/lib.rs:400-409):

- `schema.get/v1` — exact `(schema_id, schema_version)`; returns the Draft
  2020-12 document, `document_digest`, provenance
  (`changeset_id`, `edit_id`, `authoritative_sequence`). Miss is
  `proof.schema.not_found`.
- `schema.list/v1` — workspace-bounded enumeration with optional exact
  `schema_id` filter, cursor pagination keyed by `authoritative_sequence`,
  page cap 100, sorted results. No search, no wildcard claims.

Agents are **not** granted these rows; `context.build` remains the bounded
Schema channel for Agents (ContextPack closure already carries schemas).
MCP tool surface is unchanged: Human rows are deliberately not MCP tools.

Rejected: adding Agent rows now — no consumer before the SDK/console
successors; revisit trigger is an agent builder requirement that ContextPack
boundedness cannot serve.

### D4 — Draft-state register read: `object.list/v1`

One new Human row exposing committed state:

- Enumerates base Objects with per-`(object_id, locale)` head rendition
  summaries, filtered by exact `schema_id`, exact `locale`, and/or an explicit
  sorted unique `object_ids` set (≤100, mirroring
  `MAX_LOCALIZED_TARGETS`); cursor pagination by `authoritative_sequence`;
  page cap 100; sorted output.
- Every entry carries a release-status pair —
  `covered_by_current_release: bool` and `released_revision` — computed
  against the Environment's current Release Edition sequence exactly as
  `load_rendition_at` bounds reads today
  (crates/proof-local/src/localized.rs:2843-2864, 8570-8640). Nothing in the
  result claims globally-latest state; the envelope states "committed
  Workspace state; not necessarily released".
- Roles: `roles_any_of` identical to `release.get/v2` (ContentPublisher,
  ContentRequester, ContentReviewer, EvidenceAuditor — registry.rs:974-990),
  enforced at the single authorization choke point
  (crates/proof-server/src/dispatch.rs:626-631, authz.rs:479-496) with the
  locked-head re-check inside the unit of work (operations.rs:543-554).

This is Proof's first multi-object read; the exact-tuple discipline survives
as bounded explicit sets plus cursors, never unbounded scans.

### D5 — Flat content model ratified; subtree authority deferred

The domain stays flat: no parent/child storage, no closure tables, no
descendant grants, no node-move semantics in this destination. Subtree
authority is recorded as **deferred-not-decided**. The sanctioned escape hatch
is structure-as-view: Schema-level self-reference fields inside specific
Schemas (a `parent` JSON-Schema property) and/or projection-side groupings,
which are presentation truth, never authorization truth. Reopening trigger
(falsifiable): a single Human-resolved campaign resource-intent exceeding 100
exact Object IDs, or two consecutive qualification runs reporting selection
friction as their dominant cost. On trigger, hierarchy is promoted into a
fresh ratification item before any browse/grouping contract freezes.

### D6 — Blueprints are client-side presets

Blueprints compose existing ratified operations: a curated pick of Schema
plus optional initial field values rendered by the console into ordinary
ChangeSet inputs. No Template/content-type domain entity, no new registry
rows, no governance bypass; blueprints cannot reference anything outside
intent closure. Rejected: first-class Template entity — comparable in weight
to the localization milestone with no current consumer. Trigger to revisit:
qualification records preset-composition friction twice consecutively.

### D7 — Storage and persistence plan

- SQLite migration v15: `localized_edits` gains an explicit `edit_kind` column
  (`CHECK IN ('object.locale.put','object.create')`, backfilled from
  manifests); the v1 `changeset_edits` CHECK is untouched.
- `semantic_edit_value` and `edit_manifest`
  (crates/proof-local/src/localized.rs:4330-4358, 3916-3945) emit
  kind-tagged artifacts; a distinct artifact-kind domain separator is minted
  for creation-edit digests.
- PostgreSQL: the P-0015 native executor's dispatch
  (crates/proof-pg/src/parity.rs:325+) gains the creation arm writing
  `facts` rows `object/{id}/1` (append-only table, schema.rs:112-120);
  `projection_objects`/`projection_renditions` already carry every column the
  register read needs (projection.rs:83-107) — no projection schema change,
  no secondary indexes in this slice (active-generation scans are acceptable
  at register scale; indexes are fog until measured).
- Oracle: creation arms in `RemoteSemanticOracle::evaluate`
  (crates/proof-remote/src/oracle.rs:382-586) and the PG twin; trace rows
  (`OracleTraceV1`, oracle.rs:83-95) remain field-identical across stores
  under `ParityRunner::assert_identical`.

### D8 — Frozen-artifact and registry impact

| Artifact | Action | Hash effect |
| --- | --- | --- |
| `authority-operation-registry.valid.json` | unchanged (no Agent row changes) | `AGENT_AUTHORITY_REGISTRY_SHA256` stable |
| `http-operation-registry.valid.json` | +3 Human rows (`schema.list/v1`, `schema.get/v1`, `object.list/v1`), +1 row body change (`content-resource-intent.issue` major bump to `/v2`) | `COMPLETE_HTTP_OPERATION_REGISTRY_SHA256`, `REMOTE_AUTHORIZATION_PROJECTION_SHA256` recompute |
| `operations.schema.json` | `semanticEdit` becomes `oneOf` (localePut, objectCreate); new `$defs` for the three read results and intent-v2 input | embedded; pinned via instance vectors |
| `artifacts.schema.json` | `editV2` anyOf over kinds; intent-v2 artifact shape | embedded |
| `artifact-digests.valid.json`, `operation-instances.valid.json` | regenerate including creation fixtures and intent-v2 instances | retained-vector regeneration |
| `PROBLEM_REGISTRY` (dispatch.rs:71) | +`proof.schema.not_found`, +`proof.state.object_exists`, +intent-slot codes as specified | length assert 41→N updated |
| Verifier `semantics.rs` lineage gate (:8217-8228) | accepts both kinds; creation lineage proves intent-slot consumption | bundle member map structurally unchanged |

## Conformance matrix extension

Accepted and rejected paths asserted per surface (local CLI, HTTP server,
oracle/PG parity, MCP descriptor validity): creation happy path; duplicate-
and unknown-Schema rejections; create-before-put intra-ChangeSet chains;
put-before-create ordinal findings; intent-slot mismatch and double
consumption; intent-v2 issuance against non-existent slots; `schema.get`
miss; `schema.list` cursor stability and page caps; `object.list` filter,
cursor, and release-flag correctness against live releases; byte-identical
SQLite/PostgreSQL traces for every new row.

## Authorization analysis

Draft-state disclosure is bounded to authenticated Workspace members holding
publisher/requester/reviewer/auditor roles; no untrusted input selects
authority (role facts resolve through assignment/revocation facts,
authz.rs:831-862). Creation authority inherits the existing delegation clamp
(authority.rs:6594-6617) and ContextPack budget arithmetic; Agents cannot
create outside minted intent slots. Threat-model addendum for P-0021: the
register read widens read exposure from released-only to committed state for
authorized roles — accepted residual, disclosed in the result envelope.

## Successor graph and promotion order

1. P-0021 (implementation): D1-D8 end to end — domain, stores, oracle parity,
   registries/vectors/hashes, CLI (`changeset add` kind discrimination,
   `schema list/get`, `object list`), MCP descriptor regeneration, Linux gate.
2. P-0022 (implementation): proof-sdk types/registry/wire tests for the new
   rows; console adopts the SDK client replacing seed-fixture reads on touched
   surfaces.
3. P-0023 (frontend): Authoring surfaces on the ledger system — Content
   register, Object detail (Schema-driven fields, rendition tabs, revision
   chains), Schema register, New Item flow emitting intent-slot + creation +
   put compositions; MSW handlers from this contract's frozen shapes may start
   immediately after owner acceptance.
4. P-0024 (qualification): first Playwright harness driving the north-star
   authoring loop through the compose stack; fan-out polish pass.

Only P-0021 becomes `ready` upon owner acceptance; P-0022 is promoted when
P-0021 closes; P-0023/P-0024 reshape at their blockers' closure.

## Residual risks and nonclaims

No Windows runtime, deployment, or public-release qualification is claimed.
Console production embedding into the axum server remains the open P-0016
decision. Register-read performance at scale is unmeasured (indexing is fog).
Locale fallback/negotiation, rendition deletion, base-Object replacement,
relationship localization, and dynamic subtree selection remain fog. Blueprint
presets ship console-side; their curation quality is not a governed artifact.
