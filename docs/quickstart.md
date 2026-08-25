# Proof quickstart

[Back to the architecture overview](architecture/overview.md)

This quickstart takes one machine from zero to a verified Release: bring up the
stack, drive the governed localized-content flow over the frozen HTTP surface,
export the evidence, and reach an independent `Complete` verification.

Every command below is asserted by at least one retained test; each section
links its guard.

## 0. Prerequisites

- Rust toolchain (pinned by `rust-toolchain.toml`) and Docker with compose v2
- A running PostgreSQL reachable at the default DSN (`scripts/dev-pg.sh` brings
  one up locally)

## 1. Bring up the stack

```sh
docker compose -f deploy/compose.yml up -d --build
curl -sS http://127.0.0.1:8080/api/v1/capabilities | head -c 120
```

The server applies the immutable migration ledger on first start; all three
services (PostgreSQL, server, worker) must report healthy.

Guarded by `crates/proof-server/tests/deployable_artifact.rs`.

## 2. Sign in as the operator (Human session)

Open `http://127.0.0.1:8080/auth/oidc/login?return_to=/` in a browser. The
first-profile issuer is deterministic and in-process, so the Authorization Code
plus PKCE round-trip completes without an external provider. `GET
/api/v1/session` then returns the session projection and rotates the CSRF
synchronizer used by every mutation below.

Guarded by `crates/proof-server/tests/session_impl.rs` and `bff_impl.rs`.

## 3. Drive the governed localized flow

All application work dispatches through
`POST /api/v1/human/operations/{name}/{major}` with Origin plus `proof-csrf`
headers. The exact sequence — resource intent, context pack, ChangeSet,
localized edits, validation, submission, approval, commit, edition, release —
is exercised end to end by the retained north-star conformance run:

```sh
cargo test -p proof-server --test north_star_remote_impl
```

That suite performs the same calls an integrator makes (two Human sessions and
one Agent presentation over HTTP against PostgreSQL) and produces the evidence
export consumed in step 5.

## 4. Enroll an Agent and delegate

Administrators issue Agent credentials through `agent-binding.issue/v1` and a
delegation through the delegation surface; the enrolled identity completes
authenticated operations through the dual session-plus-presentation boundary.

Guarded by `crates/proof-server/tests/enrollment_impl.rs` and the agent legs of
`north_star_remote_impl.rs`.

## 5. Export evidence and verify independently

```sh
cargo build --release --bin proof-verifier
./target/release/proof-verifier verify \
  --bundle <exported-bundle.json> --trust <trust-root.json>
echo $?
```

Exit code `0` is the ratified `Complete` outcome; `20` is Incomplete and `21`
Invalid. The composed offline leg of the north-star run asserts exactly this
classification on the export it produced.

Guarded by `crates/proof-server/tests/north_star_remote_impl.rs` and
`crates/proof-verifier/tests/portable_matrix.rs`.

## Where to go next

- Operation registry and Problem codes:
  [collaboration-server contract](https://proof.dev/docs/architecture/collaboration-server)
- TypeScript integration: [`web/packages/proof-sdk`](../web/packages/proof-sdk/README.md)
