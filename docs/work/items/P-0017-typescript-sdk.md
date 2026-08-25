---
id: P-0017
title: Ship the TypeScript SDK over the shared HTTP contracts
status: claimed
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

## Progress log

Populated by the claiming executor.
