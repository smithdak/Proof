---
id: P-0021
title: Implement the authoring operations end to end
status: ready
wave: now
kind: implementation
blocked_by: [P-0020]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the authoring operations end to end

[Back to the work map](../map.md)

## Outcome

The ratified P-0020 authoring contract is implemented and qualified across the
local store, the PostgreSQL server path, the CLI, and MCP: Objects are created
through `object.create` Edits inside ordinary ChangeSets under creation-slot
resource intents, Schemas and committed draft state are readable through
bounded registered reads, frozen registries/vectors/hashes are regenerated
with the Agent registry provably unchanged, and the full Linux quality gate is
green.

## Why now

P-0020 is accepted; D1-D8 freeze the exact mechanisms. Every later surface —
SDK adoption, console registers, e2e qualification — consumes these
operations, so nothing downstream can start on live semantics until this
closes.

## Authorized scope

- D1: the `object.create` v2 edit kind end to end — input/result/Problem
  contracts, inverse existence precondition, intra-ChangeSet causal source
  resolution for subsequent puts in ordinal order, commit writing
  `object_revisions` through the v2 unit of work.
- D2: `proof.dev/content-resource-intent/v2` with sorted, bounded,
  exactly-consumed creation slots verified non-existing at baseline;
  `content-resource-intent.issue` promoted to `/v2` per the contract's
  major-bump plan.
- D3/D4: `schema.list/v1`, `schema.get/v1`, and `object.list/v1` Human rows —
  cursors keyed by `authoritative_sequence`, page cap 100, bounded filters,
  release-status pairs computed against the current Release Edition sequence,
  roles identical to `release.get/v2`.
- D7: SQLite migration v15 (`localized_edits.edit_kind`), kind-tagged edit
  artifacts with a distinct creation digest domain separator, PG facts arm
  for creation, oracle arms in both stores with byte-identical traces.
- D8: regenerate `http-operation-registry.valid.json`,
  `operations.schema.json`, `artifacts.schema.json`, instance/digest vectors;
  recompute `COMPLETE_HTTP_OPERATION_REGISTRY_SHA256` and
  `REMOTE_AUTHORIZATION_PROJECTION_SHA256`; assert
  `AGENT_AUTHORITY_REGISTRY_SHA256` byte-unchanged; extend
  `PROBLEM_REGISTRY`; update verifier lineage acceptance for both kinds.

## Explicit non-goals

- No console surfaces, MSW handlers, or SDK/client changes (P-0022/P-0023).
- No hierarchy, templates-as-entity, locale fallback, rendition deletion,
  base-Object replacement, or relationship localization (contract non-goals).
- No secondary content indexes; active-generation scans remain acceptable
  until measured.
- No Windows, deployment, or public-release claims.

## Applicable contracts

- [P-0020 decision candidate](../evidence/P-0020/contract.md)
- [Core invariants](../../architecture/constitution.md)
- [Authenticated actor contract](../../architecture/authenticated-actor.md)
- [Agent authority and ContextPacks](../../architecture/agent-authority.md)
- [Testing strategy](../../architecture/testing.md)

## Acceptance criteria

1. The extended conformance matrix from P-0020 passes across local CLI, HTTP
   server, SQLite/PostgreSQL oracle parity, and MCP descriptor validity:
   creation happy path; duplicate-object and unknown-Schema rejections;
   create-before-put chains resolving intra-ChangeSet; put-before-create
   ordinal findings; intent-slot mismatch and double consumption; intent-v2
   issuance against non-existent slots.
2. `schema.get` returns the exact stored Draft 2020-12 document with digest
   and provenance; misses are structured problems. `schema.list` honors exact
   filters, cursor stability, and page caps. `object.list` entries carry
   correct `covered_by_current_release`/`released_revision` against live
   releases, and every result envelope states committed-not-released
   semantics.
3. All three new reads enforce the `release.get/v2` role set at the single
   authorization choke point with locked-head re-checks; untrusted input
   cannot select authority.
4. Frozen-artifact impact lands exactly as D8 specifies: two hashes
   recomputed, one asserted unchanged, retained vectors regenerated with
   creation fixtures and intent-v2 instances, problem-registry length asserts
   updated, verifier lineage accepts both kinds.
5. The remote north-star extends to a creation-slot run: a delegated Agent
   executes creates plus locale puts through HTTP+PostgreSQL reaching
   verifier `Complete`, joining the retained suites.
6. CLI parity ships: kind-discriminated `changeset add` input, `schema list`
   /`schema get`, and `object list` commands with outcome exits matching the
   error model.
7. The full Linux gate is green: fmt, clippy `-D warnings`, workspace tests,
   doc tests, work-item validator, doc-link validator.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
frozen-hash before/after values, and residual boundaries in
`docs/work/evidence/P-0021/` per the [work-control protocol](../README.md).
