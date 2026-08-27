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

The Rust server and `web/packages/proof-sdk` emit and consume the exact
Schema-authoritative HTTP operation-envelope v1 accepted in P-0025.
`proof-sdk` also exposes actor-qualified TypeScript inputs and typed results for
P-0021's creation Edit, content-resource-intent v2 row, and Schema/Object
register reads. The existing console adopts the SDK only for session and logout
transport; feature-operation transport remains for P-0023, and this item does
not start the Authoring interface.

## Why now

P-0021 shipped the backend and frozen authoring contracts, but the SDK still
models only `object.locale.put`, treats every successful operation result as an
application consequence, and mirrors only the Agent operation registry. The
console's separate session/logout fetch shapes also differ from the server.
P-0025 recommends the frozen Schema's closed Human request, Agent request, and
`data`/`result_anchor`/`result_schema` success representation; this item stays
blocked until the project owner accepts that exact cutover.

## Authorized scope and tasks

1. Consume P-0025's accepted HTTP-envelope contract without adding a second
   compatibility representation or a new envelope major. Keep the existing
   Schema and two retained request vectors byte-for-byte.
2. Make Rust admission route-specific. Require exactly the six Human members
   `api_version`, `workspace_id`, `operation`, `correlation_id`,
   `idempotency_key`, and `input`; require exactly the four Agent members
   `api_version`, `operation`, `correlation_id`, and `invocation`. Enforce the
   exact version, UUIDv7-or-null correlation, route-qualified operation, Human
   Workspace/key equality guards, and Agent top-level member prohibitions
   before application execution.
3. Emit exactly `api_version`, `operation`, `operation_id`, `correlation_id`,
   `replayed`, `result_anchor`, `result_schema`, and `data` on success. Validate
   `data` against the resolved row result Schema. For every current Human and
   Agent row, emit a `committed-transaction` anchor with the
   `proof:operation-effect:v1` digest of RFC 8785 canonical `data` and the
   current committed Workspace transaction sequence. A keyed replay returns
   the prior data digest, the new replay transaction sequence, and
   `replayed:true`.
4. Preserve fresh authentication and current locked-head authorization before
   any idempotency lookup or prior-result disclosure. Preserve the
   Workspace-global `(workspace_id, application_key)` namespace across Human
   and Agent routes and all operation pairs. A Human top-level key is only a
   duplicate of normalized input; an Agent key remains inside its fresh signed
   invocation.
5. Replace the single-shape localized Edit input in
   `web/packages/proof-sdk/src/types.ts` with an exact `kind`-discriminated v2
   union for `object.locale.put` and `object.create`; mixed-kind fields must be
   impossible to type.
6. Add exact TypeScript types for `ContentResourceIntentV2` and for these four
   Human pairs: `content-resource-intent.issue` at
   `proof.dev/operation/content-resource-intent.issue/v2`, `schema.get` at
   `proof.dev/operation/schema.get/v1`, `schema.list` at
   `proof.dev/operation/schema.list/v1`, and `object.list` at
   `proof.dev/operation/object.list/v1`. Cover their inputs, entries, cursors,
   nullable Release state, provenance, and result envelopes.
7. Make SDK request/result envelopes and operation results generic and keyed by
   exact actor and operation pair. Remove the unconditional mapping from every
   operation to `ApplicationConsequence`; expose typed `data`, exact
   `result_schema`, replay state, and the closed result-anchor union.
8. Split registry resolution and client execution by actor. Retain all 14 Agent
   pairs byte-for-byte, add the four P-0021 Human pairs, and prevent a
   Human-only pair from using the Agent route or an Agent-only pair from using
   the Human route.
9. Add one retained valid operation-result vector and make the Rust
   conformance, route, dispatch, end-to-end, remote north-star, smoke, and SDK
   drift suites enforce all three exact envelope forms, result typing, anchor
   semantics, replay semantics, and route-specific rejection.
10. Extend `web/packages/proof-sdk/test/wire.spec.ts` with exact route,
    operation URI, headers, credentials, normalized request, typed success, and
    frozen Problem assertions for every new Human row. Add compile-fail
    fixtures for cross-kind Edit fields.
11. Add `proof-sdk` as a console workspace dependency and centralize SDK
    construction/configuration. Migrate only `SessionProvider` and logout to
    `ProofClient`, removing the non-contract `X-CSRF-Token` and 204-logout
    assumptions from those paths. The authority is
   `crates/proof-server/src/routes.rs`: logout sends `proof-csrf`, requires
   Origin and the session cookie, and returns HTTP 200 with
   `proof.dev/session-logout-result/v1` and `logged_out: true`.
12. Make only the MSW session/logout handlers emit the exact accepted wire
    representation and require explicit development opt-in. Retain the direct
    console feature `executeOperation` path and existing feature-operation MSW
    handlers for P-0023; do not migrate a feature screen or add an Authoring
    handler here.
13. Document the actor-qualified SDK calls and retain Rust, SDK, and console
    typecheck, lint, test, and build gates in CI. Preserve the complete HTTP,
    authorization-projection, and Agent-authority registry commitments exactly.

## Acceptance criteria

1. Human and Agent operation routes accept only their exact required members,
   version, operation pair, and identity/key guards; unknown, missing nullable,
   malformed, and other-route members fail before application execution.
2. Every current successful Human or Agent operation returns only the accepted
   eight-member envelope with row-typed `data`, exact `result_schema`, replay
   state, and a non-null committed-transaction anchor. Replay binds the prior
   data and current committed replay transaction exactly.
3. Authentication and current authorization precede stored-result lookup and
   disclosure in retained denial/revocation/replay tests. Cross-route,
   cross-actor, and cross-operation reuse remains one Workspace-global
   application-key identity.
4. TypeScript accepts exact `object.create` and `object.locale.put` values and
   rejects any value containing fields from both variants.
5. The SDK exports the four exact P-0021 Human pairs and all 14 unchanged Agent
   pairs; actor-qualified resolution rejects every route mismatch.
6. Each new operation key resolves to its exact input and typed result, including
   omitted optional cursors, nullable `released_revision`, and the literal
   committed-state scope.
7. Hermetic wire tests prove the exact accepted route major, operation URI,
   headers, credentials, request envelope, result envelope, and typed payload.
   They also retain `proof.schema.not_found`, `proof.state.object_exists`, and
   `proof.intent.slot_mismatch` as exact `ProblemError` bodies.
8. Rust and TypeScript drift tests fail on any added, removed, renamed,
   re-required, or loosened request, result, anchor, Edit, registry, input, or
   result-Schema field covered by this item.
9. Console session and logout production paths use `proof-sdk`, send
   `proof-csrf`, and accept only HTTP 200
   `proof.dev/session-logout-result/v1`. Existing feature-operation transport
   and mocks remain behaviorally intact for P-0023.
10. Touched session/logout MSW handlers emit the accepted representation and
    are enabled only by explicit development opt-in; the SDK README documents
    actor-qualified calls and session transport.
11. The envelope Schema and two request vectors are byte-identical, one valid
    result vector is retained, and the complete HTTP, authorization-projection,
    and Agent-authority registry hashes remain respectively
    `6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`,
    `d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`,
    and `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`.
12. No Content register, Object detail, Schema register, New Item, blueprint,
   creation, or intent-issuance route/component/navigation entry is added.
13. The locked Rust gate and all `proof-sdk`/console typecheck, lint, test, and
    build commands exit 0; work-item and documentation-link validators pass.

## Explicit non-goals

- No P-0023 Authoring UI, including metadata-only `/objects` migration.
- No migration or removal of the console feature `executeOperation` transport
  or feature-operation MSW handlers; P-0023 owns that work.
- No new backend operation, read projection, store, registry row, or frozen
  authoring semantic.
- No mutation of `http-envelope-v1.schema.json`, no old-shape aliases or dual
  parser, and no envelope v2 absent P-0025's documented reversal trigger.
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
- The exact pending target is the
  [P-0025 contract candidate](../evidence/P-0025/contract.md): frozen Schema
  authoritative, one atomic v1 cutover, all current rows anchored to the
  current committed Workspace transaction.
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
cargo test -p proof-server --test routes_impl --test dispatch_impl --test ts_sdk_contract
cargo test -p proof-local --test p0008_collaboration_contract
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
