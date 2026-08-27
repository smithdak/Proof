# P-0022 implementation qualification receipt

[Back to the work item](../../items/P-0022-sdk-authoring-adoption.md)

## Result

P-0022 candidate `01ff4b0496fe69cf6ed97aa305a5de591a3ec5a6`
implements the P-0025 Schema-authoritative HTTP operation envelope atomically
across the Rust server and unpublished TypeScript SDK. Human and Agent
admission is actor- and route-qualified, successful dispatch returns only the
accepted eight members, row data is validated against the resolved frozen
result Schema, and each accepted result carries a current committed-transaction
anchor over the canonical data digest.

The SDK now exposes actor-qualified generic request/result types, retains all
14 Agent pairs, adds P-0021's four Human pairs, and makes the two Edit v2 kinds
mutually exclusive at compile time. The console constructs one shared SDK
client and uses it only for session and logout. Feature-operation transport,
the existing feature mocks, and all Authoring UI remain P-0023 scope.

Project-owner acceptance has not occurred in this candidate evidence. The item
is in `review`; its later completion record carries the accept-or-rework
verdict without mutating this immutable qualification account.

## Qualified candidate

| Field | Exact value |
| --- | --- |
| Claim base | `c9db396f1a2ecdffe050f9a7208b3c401501ed84` |
| Claim commit / candidate parent | `8d044a4094b50b1fc7d8253b60d39c26a647095e` |
| Item-work candidate | `01ff4b0496fe69cf6ed97aa305a5de591a3ec5a6` |
| Candidate tree | `5c371ab16a2f98ee5f8807671a964b03ff3928d7` |
| Qualified at | `2026-08-27T19:41:57.000Z` |
| Candidate delta | 44 files; 2,781 insertions; 1,010 deletions |

This receipt and `manifest.json` were created after the item-work candidate so
they can bind that immutable commit without self-reference.

## Contract result

- Human requests require exactly `api_version`, `workspace_id`, `operation`,
  `correlation_id`, `idempotency_key`, and `input`. Agent requests require
  exactly `api_version`, `operation`, `correlation_id`, and `invocation`.
  Missing nullable members, unknown members, malformed correlations,
  cross-route members, wrong majors, and route/actor mismatches reject before
  execution.
- Success contains exactly `api_version`, `operation`, `operation_id`,
  `correlation_id`, `replayed`, `result_anchor`, `result_schema`, and `data`.
  The old `result` and `committed_anchor` representation is removed rather
  than accepted as an alias.
- `data` validates against the route-qualified registry row. Its
  `proof:operation-effect:v1` digest is bound to the current committed
  Workspace transaction sequence. A keyed replay returns the prior data and
  digest, a newer replay transaction sequence, and `replayed:true`.
- Fresh authentication and locked-head authorization remain before
  idempotency lookup or stored-result disclosure. Application keys remain
  Workspace-global across actors, routes, and operation pairs.
- The retained Human request, Agent request, and envelope Schema bytes are
  unchanged. One valid result vector is added and checked in both Rust and
  conformance suites.

## SDK and console result

- `proof-sdk` resolves calls by actor plus exact operation URI and exports
  typed `data`, `result_schema`, replay state, and the closed result-anchor
  union.
- The v2 Edit input is a `kind`-discriminated union for `object.create` and
  `object.locale.put`; compile fixtures reject cross-kind fields.
- Exact Human SDK rows cover `content-resource-intent.issue/v2`,
  `schema.get/v1`, `schema.list/v1`, and `object.list/v1`; all 14 frozen Agent
  pairs remain present and route mismatches reject.
- Console session/logout use the centralized SDK client, the `proof-csrf`
  synchronizer, and the exact HTTP 200 logout result. MSW starts only through
  explicit development opt-in. No Authoring component, navigation entry, or
  feature-operation migration is included.
- The React quality pass kept network/session behavior outside render,
  centralized stable SDK configuration, and preserved the existing keyboard,
  responsive, and accessibility behavior without adding UI surface.

## Qualification

| Command | Exit |
| --- | --- |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 0 |
| `cargo test --locked --workspace --all-targets --all-features` | 0 |
| `cargo test --locked --doc --workspace --all-features` | 0 |
| `cargo test --locked -p proof-server --all-targets --all-features` | 0 |
| `cargo test -p proof-pg --test parity_impl` | 0 (24 passed) |
| `pnpm --filter proof-sdk typecheck` from `web/` | 0 |
| `pnpm --filter proof-sdk lint` from `web/` | 0 |
| `pnpm --filter proof-sdk test` from `web/` | 0 (15 passed, 2 skipped) |
| `pnpm typecheck` from `web/` | 0 |
| `pnpm lint` from `web/` | 0 (two retained Fast Refresh warnings) |
| `pnpm test` from `web/` | 0 (60 passed, 2 skipped) |
| `pnpm build` from `web/` | 0 (retained chunk-size warning) |
| `node scripts/check-work-items.mjs` | 0 (24 items) |
| `node scripts/check-doc-links.mjs` | 0 (453 links) |
| `git diff --check` | 0 |
| `npx markdownlint-cli2 --no-globs` over the changed Markdown | 0 |

## Artifact and registry commitments

| Candidate artifact | Git blob | SHA-256 |
| --- | --- | --- |
| `http-operation-result.valid.json` | `fdac909ab96c112cf46ff15c72bffe6115e96f79` | `da0b90036dd3d77332d196d678c32371803d2908701edfbb3d4b2da4d32fc28a` |
| `operation_contract.rs` | `3463a16a804f7d550a85ac3691fa368d9ea43810` | `e37ce90f7c5a7a8d664cc3052b929bb416bb43d980c94b5beae6ebdef37223fd` |
| `proof-sdk/src/client.ts` | `c41938c9ea8a48e7f80c2231363f0b4928de9c55` | `274573433d74d692c7510950eab5b4cbd2ba55c9b5461efa0326a335d96d5d06` |
| `proof-sdk/src/types.ts` | `9543b283207581605e7e46e4ee3c4253700e7438` | `dbe1a3630fe9494c0e9024d0c2e2f904d9730dc084240f0073c7586a18c3c12b` |
| `proof-sdk/src/registry.ts` | `dd17f7062461146ff8192e98a807b9042d2fc2e0` | `62c44dc5b70dbd82e119c5f1fa2d37c7c5655bdec7a1335bc7a1880589dd0ea2` |
| `web/src/api/sdk.ts` | `37f4d4999788c5492932fad9e6e46db560ddfd3d` | `ffab58049ed24f59cbd3544b532c81a607c555b81f1b0e2a2c4d301c790161f0` |

The retained registry commitments remain:

- complete HTTP operation registry:
  `6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`;
- authorization projection:
  `d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`;
  and
- Agent authority registry:
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`.

## Residual boundary and owner gate

- Schema validation deliberately fails closed for a pre-existing producer
  whose result does not satisfy its advertised row. P-0022 does not add new
  backend operation semantics. In particular, the retained Agent
  `context.build/v1` and `object.query_released/v1` pairs still lack native
  PostgreSQL result producers, and Human rows outside P-0022's exercised slice
  may retain earlier generic producers until their owning feature work adds a
  successful row fixture.
- The frozen `changeset.get/v2` result refers to `changeSetV2`, whose edits and
  effective leaves are non-empty; a newly created empty draft therefore has no
  Schema-conformant get result until it receives an Edit. This is an existing
  frozen authoring-contract boundary, not relaxed by the envelope cutover.
- P-0023 must add retained successful fixtures for every Human row it migrates
  before replacing feature transport. P-0024 remains the first full browser
  north-star qualification.
- Console production embedding, Windows runtime, deployment, package
  publication, and public release remain outside this candidate.
- No push, tag, deployment, publication, credential mutation, external
  provider change, or public release occurred.

Because these are explicit residuals rather than hidden compatibility aliases,
the item moves to a project-owner review gate. Acceptance closes P-0022 and
promotes the already-shaped P-0023 frontend item; rework returns P-0022 to
`claimed` and leaves P-0023 blocked.
