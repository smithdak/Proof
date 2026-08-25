---
id: P-0018
title: Produce the deployable server artifact with one-command bring-up
status: review
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

## Completion record

Implemented and qualified by `ox-alpha:proof:p-0018` on 2026-08-25.

1. The `proof-server` binary exists: env-driven `ServerConfig`, listener bind,
   frozen nine-route router, graceful SIGTERM/SIGINT shutdown through
   `serve_until`; liveness rides the public capabilities route and no new route
   was introduced. Satisfied.
2. The existing `proof-worker` binary participates in bring-up against the
   same PostgreSQL deployment, applying the delivery-state migration and
   draining the shared transactional outbox. Satisfied.
3. One command (`docker compose -f deploy/compose.yml up -d --build`) brings
   PostgreSQL, server, and worker up healthy from a clean state with schema
   migration on first start; `down -v` tears it down cleanly. Satisfied.
4. The retained artifact test boots both real binaries against an isolated
   schema and proves capabilities 200 (route_count 9), a cookie-less session
   read failing closed with the stable Problem body, and a seeded outbox row
   reaching `delivered`. Satisfied.
5. The full Linux gate passed; the P-0017 SDK live leg ran green against both
   a locally booted server and the containerized stack (15/15). Satisfied.

Item-work commit: recorded in the evidence manifest. Evidence:
[receipt](../evidence/P-0018/receipt.md) and
[manifest](../evidence/P-0018/manifest.json) bind commands, environment,
revisions, digests, and residual boundaries per the evidence contract.

## Progress log

- Slice 1 (2026-08-25): claimed and studied the assembly surface —
  `AppState::new` + `connect_pg` + `routes::router` + `serve` already compose
  the full stack in-process (the e2e suite drives them), so the binary is an
  environment-to-config adapter rather than new machinery. Found and fixed a
  latent first-start bug while wiring it: `connect_pg` applied migration
  scripts unconditionally, so a fresh database refused its own second runtime
  with "migration head version 3 is newer"; the head is now read once per
  runtime and only missing scripts are applied (`bring_migration_head_to_current`).
- Slice 2 (2026-08-25): the `proof-server` binary landed — env-driven config
  (`PROOF_LISTEN_ADDR`, `PROOF_PG_DSN`, `PROOF_WORKSPACE_ID`,
  hex-encoded `PROOF_SESSION_SECRET`; deterministic in-process issuer by
  default), synchronous migrations before the async runtime starts (the
  retained sync driver must not run inside Tokio), flushed liveness line,
  graceful SIGTERM/SIGINT shutdown through the new `serve_until`.
- Slice 3 (2026-08-25): the retained artifact test boots both real binaries
  against an isolated schema: capabilities answers 200 with route count 9, the
  cookie-less session read fails closed with the stable `proof.auth.denied`
  Problem body, one seeded `preview.release/v1` row reaches `delivered` through
  `proof-worker`. The SDK's live leg (P-0017 residual) ran green against a
  locally booted server: 2 live tests, 15/15 total.
- Slice 4 (2026-08-25): deployment artifact — root `Dockerfile` (release build,
  slim runtime, capabilities-route healthcheck) plus `deploy/compose.yml`
  (PostgreSQL + server + looping worker; server migrates on first start;
  validated with `docker compose config`).
