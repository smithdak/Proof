# P-0015 execution receipt

[Back to the work item](../../items/P-0015-pg-mutation-executor-parity.md)

## Result

All eleven localized mutation rows now produce byte-identical SQLite/PostgreSQL
oracle traces. The PostgreSQL parity backend executes the full v2 authority
surface — `changeset.create/add/get/diff/validate/submit/commit`,
`edition.create`, `release.create`, `object.query_released`, and
`context.build` — over imported, digest-verified facts with no SQLite
dependency at operation time. The final row, `release.create/v2`, reproduces
the complete promotion arm including the exact-delta comparison, the in-toto
v2 statement, the Ed25519 DSSE envelope, and keyed replay; signatures match
byte-for-byte because both backends read the same workspace file-backed
signing key.

## Qualified candidate

- Item-work commit: `e2cf8c3b647663aa0571c2b0ba65f71adcd1075b`
- Base SHA (claim): `5d819e6c93ccb29070ad8f9a01a747d1eb1e462a`
- Candidate parent: `4b905b66aa7ce6dd2da0ffaf5a4a8a2f3adc5bf4`

## Commands and exit codes

| Command | Exit |
| --- | --- |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 0 (0 failures across all suites) |
| `cargo test -p proof-pg --test parity_impl` | 0 (16 passed) |
| `cargo test --locked --doc --workspace --all-features` | 0 |
| `node scripts/check-work-items.mjs` | 0 (16 items) |
| `node scripts/check-doc-links.mjs` | 0 (379 links) |

## Environment

- Linux (WSL kernel), rustc pinned 1.97.1 via rust-toolchain.toml.
- PostgreSQL reachable at the proof-pg default DSN `127.0.0.1:55432/prooftest`;
  every PostgreSQL-backed integration test connected and passed.
- No push, tag, public release, credential mutation, or external-provider
  change was performed.

## Scope conformance

- No new wire surface, storage schema version, migration, or operation
  registry entry: every row reuses its frozen registry row, Problem codes, and
  artifact profiles through the shared oracle serializers.
- The retained conformance surface is the sixteen byte-identical-trace tests in
  `crates/proof-pg/tests/parity_impl.rs`; each accepted row also carries a
  keyed-replay trace. Frozen-vector change count: 0.
- Release signing keys stay out of the store by design:
  `LocalWorkspace::release_signing_secret()` exposes the file-backed key for
  out-of-process oracles and no fact ever carries secret material.

## Residual boundaries

- `object.query_released/v2` retains rejection-parity only; the success path is
  deferred until a fixture imports a released v2 rendition set.
- The signer's cross-role authority-key conflict check is out of parity scope;
  authority tables are excluded from import by contract.
- The rollback arm of localized Release creation has no v2 authority input and
  is unreachable from the shared oracle surface; it remains unported.
