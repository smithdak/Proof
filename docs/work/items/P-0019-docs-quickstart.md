---
id: P-0019
title: Author the documentation site quickstart to a verified agent run
status: claimed
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0019
claimed_at: 2026-08-25T18:50:14.994Z
base_sha: d93c3acab343d8b2e6c6ec2a085d14218a757e77
review_gate: none
accepted_by: null
accepted_at: null
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

## Progress log

Populated by the claiming executor.
