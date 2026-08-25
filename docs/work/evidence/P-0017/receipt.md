# P-0017 execution receipt

[Back to the work item](../../items/P-0017-typescript-sdk.md)

## Result

The TypeScript SDK ships as `web/packages/proof-sdk`: one typed client over
Proof's frozen collaboration-server HTTP surface. External consumers construct
a `ProofClient` against a base URL, execute every registered operation pair
(14 rows) with field-set-exact inputs, read session/capabilities/preview state,
fetch content-addressed evidence artifacts, and receive rejections as typed
errors carrying the server's stable Problem body verbatim. A cross-language
drift guard fails the Rust gate when the SDK's registry or input types lose a
field their Rust sources require.

## Qualified candidate

- Item-work commit: `ebc394fdfab0c7444297ed380870d0b46dbc78f9`
- Base SHA (claim): `dcdaf485cf1a12332ae61f09b25a8c55ee73ce18`
- Candidate parent (claim commit): `75fe002e4b7a5fbbf2a4ceaddd951933367066c7`

## Commands and exit codes

| Command | Exit |
| --- | --- |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 0 (0 failures) |
| `cargo test -p proof-server --test ts_sdk_contract` | 0 (4 passed) |
| `pnpm --filter proof-sdk test` | 0 (13 passed) |
| `pnpm --filter proof-sdk typecheck` | 0 |
| `pnpm --filter proof-console exec tsc -b` | 0 (console untouched) |
| `pnpm --filter proof-console test` | 0 (58 passed) |
| `cargo test --locked --doc --workspace --all-features` | 0 |
| `node scripts/check-work-items.mjs` | 0 (17 items) |
| `node scripts/check-doc-links.mjs` | 0 (385 links) |

## Environment

- Linux (WSL kernel), rustc pinned 1.97.1 via rust-toolchain.toml; Node v22.23.2
  with pnpm 11.22.0.
- No push, tag, public release, credential mutation, or external-provider
  change was performed.

## Scope conformance

- No new server route, registry row, storage schema version, wire profile, or
  third-party package: the SDK uses only the platform `fetch`, and its dev
  dependencies (`typescript`, `vitest`) already exist in the workspace lockfile
  scope.
- The P-0016 console was not modified; it stays on its deliberate projection
  layer over MSW mocks. Migration onto this wire-exact package is recorded as
  console follow-up under its own review gate.

## Residual boundaries

- Agent invocation signing remains with the caller's provisioning path; the SDK
  carries the dual-auth transport exactly and does not re-implement DSSE
  command envelopes in TypeScript.
- The live-server leg of the client suite lands with P-0018's deployable
  artifact; today's retained suite pins exact request bytes and response
  shapes against a stub transport whose shapes are themselves pinned by the
  Rust e2e handlers plus the cross-language drift guard.
