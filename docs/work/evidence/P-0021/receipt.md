# P-0021 execution receipt

[Back to the work item](../../items/P-0021-authoring-operations.md)

## Result

The P-0020 authoring contract is implemented end to end. `object.create` is a
second v2 Edit kind with intra-ChangeSet source resolution and SQLite v15
persistence; content-resource intents advance to v2 creation slots; Human
`schema.get/v1`, `schema.list/v1`, and `object.list/v1` rows expose bounded
committed-state reads; PostgreSQL parity reproduces the local traces; CLI and
MCP consume the new contracts; frozen schemas and vectors are regenerated.

The PostgreSQL authority path also retains exact Workspace-global keyed replay,
atomic Release delivery creation, bounded retries, SQLSTATE-preserving storage
failures, reconnect support, and ambiguous-commit reconciliation. The remote
north-star executes delegated creation plus locale editing through HTTP and
PostgreSQL, publishes and delivers the Release, and reaches verifier
`Complete`.

## Qualified candidate

- Item-work commit: `75ce593d43fbd12eb74dd40bbc7e8f122c712ea8`
- Candidate tree: `e72b75d9491edaf05dfc8753def1797891e980e3`
- Claim commit/candidate parent: `9ff1bcf573a687dab20c8435655ac4adbe5a957b`
- Claim base: `67e7c874c0ca889b96d687de8d9cf36f4e414db3`

## Contract results

- D1/D2: creation Edits and exactly consumed creation slots are enforced in the
  application, local store, PostgreSQL oracle, CLI, evidence, and verifier.
- D3/D4: Schema and Object register reads retain exact tuple filtering,
  authoritative-sequence cursors, a 100-row cap, provenance, and current
  Release status.
- D5/D6: the flat content model and client-side blueprint boundary remain
  unchanged.
- D7: SQLite migration v15 records the Edit kind and both stores retain
  kind-discriminated artifacts with byte-identical traces.
- D8: the complete HTTP registry hash is
  `6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`;
  the authorization projection hash is
  `d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`;
  the Agent authority registry remains byte-identical at
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`.

## Commands and exit codes

| Command | Exit |
| --- | --- |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 0 (942 passed across 82 suites) |
| `cargo test --locked --doc --workspace --all-features` | 0 |
| `cargo test -p proof-local --test p0021_authoring` | 0 (9 passed) |
| `cargo test -p proof-pg --test parity_impl` | 0 (24 passed) |
| `cargo test -p proof-pg --test transaction_impl` | 0 (14 passed) |
| `cargo test -p proof-pg --test migration_impl` | 0 (10 passed) |
| Exact remote north-star | 0 (1 passed) |
| `node scripts/check-doc-links.mjs` | 0 (439 links) |
| `node scripts/check-work-items.mjs` | 0 (23 items) |
| `npx markdownlint-cli2 --no-globs` over changed work-control Markdown | 0 |

## Environment

- Linux `5.15.167.4-microsoft-standard-WSL2`, x86_64.
- Rust/Cargo 1.97.1; Node v22.23.2; Git 2.43.0.
- PostgreSQL-backed suites connected at the configured Proof test DSN. The
  standalone `psql` client is not installed, so no server-version claim is
  made.
- No push, tag, deployment, package publication, public release, credential
  mutation, or external-provider change was performed.

## Residual boundaries

- No SDK or console implementation is included; P-0022 owns SDK adoption and
  P-0023 owns Authoring UI. P-0025 first resolves the conflicting accepted
  HTTP envelope representations discovered while shaping P-0022.
- Register-read performance at scale is unmeasured; secondary indexes remain
  deferred until measurement justifies them.
- Ambiguous commit is qualified with a deterministic post-commit
  acknowledgement-loss seam plus HTTP Problem mapping; live packet loss after
  a production commit was not induced.
- Windows runtime, deployment, and public-release qualification remain out of
  scope.
