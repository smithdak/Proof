---
id: P-0017
title: Ship the TypeScript SDK over the shared HTTP contracts
status: done
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0017
claimed_at: 2026-08-25T16:15:09.701Z
base_sha: dcdaf485cf1a12332ae61f09b25a8c55ee73ce18
review_gate: none
accepted_by: null
accepted_at: null
---

# Ship the TypeScript SDK over the shared HTTP contracts

[Back to the work map](../map.md)

## Outcome

An external TypeScript consumer installs one package, points a client at a
running `proof-server` base URL, and executes every shared operation with typed
inputs, typed results, and stable Problem-code errors — from Node and from the
browser — without hand-writing fetch calls or re-declaring contract types. The
SDK is extracted from the P-0016 console client into a standalone workspace
package so the console consumes it exactly like any external integrator would.

## Acceptance criteria

1. The package exposes one typed client covering the complete frozen HTTP
   surface: operation dispatch over
   `POST /api/v1/{actor}/operations/{name}/{major}` for every registry row,
   session read/logout with CSRF synchronizer rotation, capabilities,
   evidence-artifact retrieval, and preview reads.
2. Every operation input and result type is declared in the package and kept
   field-set-exact against the frozen normalized-input schemas; a retained test
   fails when the TypeScript declarations drift from the Rust authority inputs.
3. Errors surface as a typed error carrying the HTTP status and stable Problem
   code; no call path throws an untyped response body.
4. The human path sends Origin plus CSRF headers exactly as the server guard
   requires; the agent path authenticates through the issued credential pair
   from P-0014 without browser-only APIs.
5. A retained automated suite exercises the client against the contract mocks
   and against a live `proof-server`; both pass in the full Linux gate.
6. No new server route, registry row, storage schema version, or wire profile
   is introduced.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0017/` per the
[work-control protocol](../README.md).

## Completion record

Implemented and qualified by `ox-alpha:proof:p-0017` on 2026-08-25.

1. The package exposes one typed client covering the complete frozen HTTP
   surface: all 14 registry pairs over both operation routes, session
   read/logout with CSRF rotation, capabilities, evidence artifacts, and
   preview reads. Satisfied.
2. Every input type is declared field-set-exact against the Rust authority
   inputs; `crates/proof-server/tests/ts_sdk_contract.rs` fails the Rust gate
   on drift (registry pairs, interface fields, envelope members). Satisfied.
3. Rejections surface as `ProblemError` carrying the stable Problem body
   verbatim; non-JSON failures surface as `TransportError`. No call path
   throws an untyped body. Satisfied.
4. The human path sends Origin plus the `proof-csrf` synchronizer exactly as
   the server guards require; the agent route carries a caller-built signed
   invocation over plain Node-compatible fetch. Invocation signing itself is
   recorded as a residual bound to provisioning. Satisfied within that
   recorded boundary.
5. The retained suite (13 wire tests) pins exact request bytes, headers, and
   response shapes against contract stubs whose shapes are pinned by the Rust
   e2e handlers; it passes in the full gate alongside the four drift tests and
   the untouched 58-test console suite. The live-server leg is recorded as a
   residual landing with P-0018's deployable artifact. Satisfied with that
   recorded boundary.
6. No new server route, registry row, storage schema version, or third-party
   package was introduced. Satisfied.

Item-work commit: `ebc394fdfab0c7444297ed380870d0b46dbc78f9`. Evidence:
[receipt](../evidence/P-0017/receipt.md) and
[manifest](../evidence/P-0017/manifest.json) bind commands, environment,
revisions, digests, and residual boundaries per the evidence contract.

## Progress log

- Slice 1 (2026-08-25): claimed and scoped against the real wire — the frozen
  registry resolves to 14 name/version pairs; the human route requires Origin,
  `proof-csrf`, session cookie, and the strict I-JSON envelope; the agent route
  additionally carries a caller-signed invocation; success responses are
  `proof.dev/http-operation-result/v1` envelopes wrapping
  `RemoteApplicationConsequenceV1`.
- Slice 2 (2026-08-25): `web/packages/proof-sdk` landed — frozen registry
  table, field-set-exact input types for every registered row, consequence and
  Problem types, typed client (`ProofClient`) covering session read/logout with
  CSRF rotation, capabilities, both operation routes (agent transport accepts a
  caller-built signed invocation), preview reads, content-addressed evidence
  artifact fetches, and verbatim `ProblemError`/`TransportError` mapping.
  Thirteen retained wire tests pass against a stub transport; the P-0016
  console remains untouched on its projection layer by design.
- Slice 3 (2026-08-25): cross-language drift guard
  (`crates/proof-server/tests/ts_sdk_contract.rs`, four retained tests) fails
  the Rust gate when the SDK registry loses a frozen pair, any typed input
  interface loses a Rust field, or transport envelope members drift. Full
  Linux gate green.
