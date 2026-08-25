# P-0018 execution receipt

[Back to the work item](../../items/P-0018-deployable-server-artifact.md)

## Result

The deployable stack ships. `cargo build --bin proof-server` produces the HTTP
boundary binary: it loads configuration from environment variables, migrates a
fresh PostgreSQL database to the current head on first start, serves the frozen
nine-route router, liveness-answers on the public capabilities route, and shuts
down gracefully on SIGTERM/SIGINT. One command —
`docker compose -f deploy/compose.yml up -d --build` — brings up PostgreSQL,
the server, and the delivery worker; all three reach healthy, capabilities
answers 200 from outside, and the SDK's live leg passes against the
containerized stack. Bringing the stack up also caught and fixed a latent
first-start bug: `connect_pg` refused its own fresh database because migration
scripts were applied unconditionally across its two runtimes.

## Qualified candidate

- Item-work commit: recorded in `manifest.json` (`candidate_commit`)
- Base SHA (claim): `13bc956d0f7a2fd97a59bed2f4580a0f235f9ab8`
- Claim commit: `7abadf108090aa57c3c745c06dd41945a95a8387`

## Commands and exit codes

| Command | Exit |
| --- | --- |
| `cargo test -p proof-server --test deployable_artifact` | 0 (real binaries end to end) |
| `docker compose -f deploy/compose.yml up -d --build` | 0 (all services healthy) |
| `curl http://127.0.0.1:8080/api/v1/capabilities` | 200, route_count 9 |
| `PROOF_SDK_BASE_URL=… pnpm --filter proof-sdk test` | 0 (15 passed incl. live leg) |
| `docker compose -f deploy/compose.yml down -v` | 0 (clean teardown) |
| `cargo fmt --all --check` / clippy `-D warnings` / workspace tests / doc tests | 0 |
| `node scripts/check-work-items.mjs` / `check-doc-links.mjs` | 0 |

## Environment

- Linux (WSL kernel), rustc pinned 1.97.1 via rust-toolchain.toml;
  Docker 29.7.2 with compose v2.
- No push, tag, public release, credential mutation, or external-provider
  change was performed.

## Scope conformance

- No new HTTP route, registry row, wire profile, or storage schema version:
  the binary assembles the existing frozen surface; liveness reuses the public
  capabilities route; first start applies the existing immutable migration
  ledger.
- The retained artifact test spawns the real built binaries (no mocks) against
  an isolated schema; the SDK live leg runs only when `PROOF_SDK_BASE_URL` is
  set, so the standard gate stays hermetic.

## Residual boundaries

- TLS termination and trusted-proxy configuration remain deployment
  prerequisites outside this artifact, per contract.
- The compose worker loops the bounded single-pass reference worker every five
  seconds; a long-poll daemon is a later delivery-surface concern.
- `PROOF_SESSION_SECRET` falls back to a fixed development value when unset;
  production deployments must supply a real secret (compose documents
  generation).
