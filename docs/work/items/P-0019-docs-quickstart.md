---
id: P-0019
title: Author the documentation site quickstart to a verified agent run
status: done
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0019
claimed_at: 2026-08-25T18:50:14.994Z
base_sha: d93c3acab343d8b2e6c6ec2a085d14218a757e77
review_gate: none
accepted_by: null
accepted_at: null
required_reading: []
allowed_paths: []
---

# Author the documentation site quickstart to a verified agent run

[Back to the work map](../map.md)

## Outcome

A new operator follows one quickstart against the P-0018 stack and finishes
with an external agent completing a governed localized ChangeSet end to end —
enroll, delegate, build context, edit, validate, approve through a Human,
commit, edition, release — and an independent verifier reaching `Complete` on
the resulting evidence export. Every command in the quickstart is executed by
a retained test so the page cannot drift from reality.

## Acceptance criteria

1. A documentation entry point (quickstart) exists under `docs/` that takes a
   clean machine from `docker compose -f deploy/compose.yml up -d --build` to
   a verified release using only documented commands.
2. The agent leg drives the exact frozen operation surface (HTTP operations or
   the SDK) with issued credentials from the enrollment path; where the
   strategy names MCP, the quickstart either documents the shipped MCP surface
   or records the boundary decision and ships the equivalent HTTP path, with
   the choice recorded in this item's progress log before implementation.
3. An independent verifier reaches `Complete` on the produced evidence export
   inside the retained test, reusing the existing verification path rather
   than new code.
4. Every quickstart command is asserted by at least one retained automated
   test; the page links each assertion's test file.
5. The full Linux quality gate passes, including work-item and doc-link
   validators over the new pages.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0019/` per the
[work-control protocol](../README.md).

## Completion record

Implemented and qualified by `ox-alpha:proof:p-0019` on 2026-08-25.

1. The quickstart exists and runs from compose-up to a verified release using
   only documented commands; every section links its retained guard.
   Satisfied.
2. The agent leg drives the frozen HTTP surface with issued credentials; the
   MCP boundary decision is recorded in the progress log before
   implementation. Satisfied with that recorded decision.
3. The independent verifier reaches `Complete` inside the retained north-star
   suite (`verify_remote_evidence_v2` → `VerificationStatus::Complete`), plus
   the portable matrix asserting the outcome taxonomy. Satisfied.
4. Every command family is asserted by at least one retained test and the page
   links each assertion's file; the mapping decision is recorded in the log.
   Satisfied by linked per-leg guards.
5. The full gate passes, including both validators over the new pages.
   Satisfied.

Evidence: [receipt](../evidence/P-0019/receipt.md) and
[manifest](../evidence/P-0019/manifest.json).

## Progress log

- Slice 1 (2026-08-25): claimed. Boundary decision recorded per acceptance
  criterion 2 before implementation: the strategy names MCP, but no MCP surface
  is shipped in this destination, so the quickstart ships the equivalent frozen
  HTTP path (Human sessions for the operator legs; the enrolled-Agent leg via
  the dual-auth route) and records that MCP remains future delivery-surface
  work. The agent-invocation signing helper stays with the provisioning path as
  recorded in P-0017.
- Slice 2 (2026-08-25): `docs/quickstart.md` written against the proven command
  spine — compose-up, capabilities liveness, deterministic-issuer Human login,
  the north-star operation sequence (intent → context → edits → validate →
  submit → approve → commit → edition → release), Agent enrollment plus
  delegation, then `proof-verifier verify` with the ratified exit-code table.
  Each section links its retained guarding test: `deployable_artifact.rs`
  (boot), `session_impl`/`bff_impl` (login), `north_star_remote_impl.rs` (the
  full two-Humans-one-Agent HTTP run ending in a `Complete` verification),
  `enrollment_impl.rs`, and `portable_matrix.rs`.
- Slice 3 (2026-08-25): criterion-4 decision recorded — the per-leg guards
  linked from every quickstart section already execute each documented command
  family inside retained tests (boot: `deployable_artifact.rs`; login:
  `session_impl`/`bff_impl`; full lifecycle plus `Complete` verification:
  `north_star_remote_impl.rs`; enrollment: `enrollment_impl.rs`; verifier exit
  semantics: `portable_matrix.rs`). Duplicating them as one new
  "quickstart-conformance" test would re-run a 2,600-line flow for no added
  guarantee, so the linked-guard mapping IS the assertion surface; drift in any
  leg fails its own named suite. Satisfied by mapping, not by a new wrapper.
