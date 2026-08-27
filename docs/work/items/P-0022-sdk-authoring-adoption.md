---
id: P-0022
title: Adopt the authoring contract in the TypeScript SDK and console transport
status: blocked
wave: next
kind: implementation
blocked_by: [P-0021, P-0025]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: none
accepted_by: null
accepted_at: null
---

# Adopt the authoring contract in the TypeScript SDK and console transport

[Back to the work map](../map.md)

## Outcome

`web/packages/proof-sdk` exposes exact actor-qualified TypeScript inputs and
typed results for P-0021's creation Edit, content-resource-intent v2 row, and
Schema/Object register reads. The existing console uses that SDK for session
and logout transport, replacing its duplicate HTTP client without starting the
P-0023 Authoring interface.

## Why now

P-0021 shipped the backend and frozen authoring contracts, but the SDK still
models only `object.locale.put`, treats every successful operation result as an
application consequence, and mirrors only the Agent operation registry. The
console also has a separate direct-fetch client whose session/logout shapes do
not match the server. P-0025 must first select one canonical HTTP request/result
envelope because the retained JSON Schema and accepted Rust implementation use
different field names and requiredness.

## Authorized scope and tasks

1. Consume P-0025's accepted HTTP-envelope contract without adding a second
   compatibility representation.
2. Replace the single-shape localized Edit input in
   `web/packages/proof-sdk/src/types.ts` with an exact `kind`-discriminated v2
   union for `object.locale.put` and `object.create`; mixed-kind fields must be
   impossible to type.
3. Add exact TypeScript types for `ContentResourceIntentV2` and for these four
   Human pairs: `content-resource-intent.issue` at
   `proof.dev/operation/content-resource-intent.issue/v2`, `schema.get` at
   `proof.dev/operation/schema.get/v1`, `schema.list` at
   `proof.dev/operation/schema.list/v1`, and `object.list` at
   `proof.dev/operation/object.list/v1`. Cover their inputs, entries, cursors,
   nullable Release state, provenance, and result envelopes.
4. Make SDK success envelopes and operation results generic and keyed by exact
   operation pair. Remove the unconditional mapping from every operation to
   `ApplicationConsequence` and audit the retained Agent pairs affected by the
   typed-result server path.
5. Split registry resolution and client execution by actor. Retain all 14 Agent
   pairs byte-for-byte, add the four P-0021 Human pairs, and prevent a
   Human-only pair from using the Agent route or an Agent-only pair from using
   the Human route.
6. Extend `crates/proof-server/tests/ts_sdk_contract.rs` so the Rust gate checks
   both Edit variants, all four Human pairs, the unchanged Agent pairs, and
   exact input/result fields and optionality against the retained schemas.
7. Extend `web/packages/proof-sdk/test/wire.spec.ts` with exact request route,
   operation URI, headers, credentials, normalized input, typed success, and
   frozen Problem assertions for every new Human row. Add compile-fail fixtures
   for cross-kind Edit fields.
8. Add `proof-sdk` as a console workspace dependency. Reduce
   `web/src/api/client.ts` to SDK construction/configuration, migrate
   `SessionProvider` and logout to `ProofClient`, and remove the non-contract
   `X-CSRF-Token` and 204-logout assumptions. The authority is
   `crates/proof-server/src/routes.rs`: logout sends `proof-csrf`, requires
   Origin and the session cookie, and returns HTTP 200 with
   `proof.dev/session-logout-result/v1` and `logged_out: true`.
9. Make touched MSW session/logout handlers emit the exact accepted wire
   representation and require explicit development opt-in. Do not migrate a
   feature screen or add an Authoring mock handler in this item.
10. Document the actor-qualified SDK calls and retain Rust, SDK, and console
    typecheck, lint, test, and build gates in CI.

## Acceptance criteria

1. TypeScript accepts exact `object.create` and `object.locale.put` values and
   rejects any value containing fields from both variants.
2. The SDK exports the four exact P-0021 Human pairs and all 14 unchanged Agent
   pairs; actor-qualified resolution rejects every route mismatch.
3. Each new operation key resolves to its exact input and typed result, including
   omitted optional cursors, nullable `released_revision`, and the literal
   committed-state scope.
4. Four hermetic wire tests prove the exact accepted route major, operation URI,
   headers, credentials, request envelope, result envelope, and typed payload.
   They also retain `proof.schema.not_found`, `proof.state.object_exists`, and
   `proof.intent.slot_mismatch` as exact `ProblemError` bodies.
5. Rust drift tests fail on any added, removed, renamed, or re-required Edit,
   input, result, registry, or envelope field covered by this item.
6. Console session and logout production paths use `proof-sdk`; touched
   production files contain no direct `fetch`, no `X-CSRF-Token`, and no seed
   fixture imports. Logout sends `proof-csrf` and accepts only the exact HTTP
   200 `proof.dev/session-logout-result/v1` projection.
7. Touched MSW handlers emit the accepted session/logout representation and are
   enabled only by an explicit development opt-in; the SDK README documents
   the actor-qualified calls and session transport.
8. No Content register, Object detail, Schema register, New Item, blueprint,
   creation, or intent-issuance route/component/navigation entry is added.
9. The locked Rust gate and all `proof-sdk`/console typecheck, lint, test, and
   build commands exit 0; work-item and documentation-link validators pass.

## Explicit non-goals

- No P-0023 Authoring UI, including metadata-only `/objects` migration.
- No new backend operation, read projection, store, registry row, or frozen
  authoring semantic.
- No attempt to support all 26 Human rows; this item adds only P-0021's four
  Human rows and retains the existing 14 Agent rows.
- No Agent command-signing implementation.
- No hierarchy, locale fallback, rendition deletion, base-Object replacement,
  relationship localization, subtree authority, or blueprint governance.
- No Playwright/P-0024, production embedding, deployment, or public release.

## Dependencies and decisions

- P-0021 supplies the implemented and qualified authoring contracts.
- P-0025 must ratify one canonical HTTP request/result envelope before this
  item becomes `ready`.
- Owner scope decision on 2026-08-27: console adoption is limited to SDK
  construction, session, and logout transport; feature fixture replacement
  remains P-0023.
- Open questions: none inside this item after P-0025 is accepted.

## Qualification commands

Run from the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --doc --workspace --all-features
cargo test -p proof-server --test ts_sdk_contract
node scripts/check-work-items.mjs
node scripts/check-doc-links.mjs
```

Run from `web/`:

```sh
pnpm --filter proof-sdk typecheck
pnpm --filter proof-sdk lint
pnpm --filter proof-sdk test
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

## Evidence contract

Record exact Rust, SDK, and console commands, environment and tool versions,
changed paths, generated-contract digests, and residual boundaries in
`docs/work/evidence/P-0022/` per the [work-control protocol](../README.md).
