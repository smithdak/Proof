---
id: P-0018
title: Produce the deployable server artifact with one-command bring-up
status: claimed
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0018
claimed_at: 2026-08-25T17:22:15.578Z
base_sha: 13bc956d0f7a2fd97a59bed2f4580a0f235f9ab8
review_gate: none
accepted_by: null
accepted_at: null
---

# Produce the deployable server artifact with one-command bring-up

[Back to the work map](../map.md)

## Outcome

An operator runs one command and receives a working single-Workspace stack:
the `proof-server` HTTP boundary, the `proof-worker` delivery worker, and
PostgreSQL — configured through environment variables, healthy without manual
database or file manipulation, and ready for the documentation quickstart to
drive a governed ChangeSet end to end.

## Acceptance criteria

1. A `proof-server` binary target exists: it loads configuration from
   documented environment variables, binds the assembled frozen nine-route
   router on the configured listener, and shuts down gracefully on SIGTERM
   and SIGINT. Liveness is observable through the public capabilities route;
   no new HTTP route is introduced.
2. The existing `proof-worker` binary participates in bring-up against the
   same PostgreSQL deployment, draining its transactional outbox and preview
   snapshots from the shared store.
3. One command brings the full stack up from a clean checkout state (container
   image build plus orchestration file), including schema migration to the
   current storage version on first start; one inverse command tears it down
   cleanly.
4. A retained automated test boots the stack artifact path in-process or via
   the built binaries and proves: capabilities responds 200, an unauthenticated
   session read fails closed with the stable Problem body, and the delivery
   worker drains a seeded outbox row.
5. The full Linux quality gate passes with the binaries built; the SDK's
   live-server leg (P-0017 residual) becomes executable against this artifact
   and is recorded here if exercised.

## Evidence contract

Record exact commands, environment, revisions, exit codes, artifact digests,
and residual boundaries in `docs/work/evidence/P-0018/` per the
[work-control protocol](../README.md).

## Progress log

Populated by the claiming executor.
