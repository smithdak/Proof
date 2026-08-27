---
id: P-0025
title: Ratify one HTTP operation envelope across schema and runtime
status: ready
wave: now
kind: decision
blocked_by: [P-0021]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Ratify one HTTP operation envelope across schema and runtime

[Back to the work map](../map.md)

## Outcome

One project-owner-accepted contract defines the exact Human request, Agent
request, successful operation result, and committed-result anchor serialized by
the server and consumed by `proof-sdk`. It resolves the conflict between the
retained HTTP JSON Schema and the accepted Rust/TypeScript implementation and
gives P-0022 an unambiguous migration target.

## Why now

`conformance/v1/collaboration-server/schemas/http-envelope-v1.schema.json`
requires Human request cross-check fields and serializes success as
`data`/`result_anchor`/`result_schema`. `crates/proof-server/src/dispatch.rs`,
the router tests, and `web/packages/proof-sdk` instead use optional request
cross-checks and `result`/`committed_anchor`. Both representations have accepted
history, so implementation cannot choose one without changing a public
contract. P-0022 is blocked until one representation and migration rule are
ratified.

## Authorized scope and tasks

1. Inventory every field-name, requiredness, nullability, anchor, and typed
   result difference across the HTTP Schema, Rust request/response types,
   router tests, TypeScript SDK, console mocks, quickstart examples, and
   accepted P-0008/P-0011/P-0017/P-0020 evidence.
2. State the non-negotiable invariants: strict unknown-field rejection;
   server-derived actor authority; exact route/operation/Workspace/key
   cross-checks; nullable validated correlation identity; typed-result schema
   binding; and an unambiguous committed or immutable result anchor.
3. Evaluate at least these genuinely distinct options:
   - Make the frozen JSON Schema representation authoritative and migrate Rust,
     SDK, tests, and mocks.
   - Make the accepted Rust representation authoritative and revise the frozen
     Schema, SDK, tests, and mocks.
   - Introduce a new envelope major with an explicit bounded transition instead
     of silently changing either accepted v1 representation.
4. For each option, enumerate compatibility, security, implementation,
   conformance-vector/hash, SDK, console, documentation, and rollout effects.
5. Ratify exact JSON member names, required versus nullable members, operation
   result typing, result-schema discoverability, anchor variants, and the
   treatment of existing v1 callers and stored evidence.
6. Produce `docs/work/evidence/P-0025/contract.md`, update
   `docs/architecture/collaboration-server.md` and
   `docs/decisions/0013-single-workspace-collaboration-server.md`, and reshape
   P-0022 to consume the accepted contract without a dual-format compatibility
   shim unless the owner explicitly selects a versioned transition.

## Acceptance criteria

1. The candidate contains a field-by-field matrix for all four envelope shapes
   with path-anchored evidence for both conflicting implementations.
2. Exactly one option is recommended, with its strongest counterargument,
   decision crux, reversal trigger, and explicit migration/compatibility rule.
3. Human and Agent request identity/key cross-checks are exact and cannot be
   selected by untrusted input.
4. Successful responses have one exact typed-result and anchor representation;
   every member's requiredness and nullability is specified.
5. The candidate lists every schema, Rust, SDK, test, vector/hash, mock, and
   documentation surface P-0022 must update, plus surfaces guaranteed unchanged.
6. The candidate records the per-option compatibility, security,
   implementation, conformance, SDK, console, documentation, and rollout
   effects required by task 4.
7. The accepted option is reflected in the applicable architecture/decision
   references, and P-0022 is reshaped to name the exact contract it consumes.
8. The project owner records acceptance or returns the item for rework; no
   implementation begins before acceptance.
   Acceptance populates `accepted_by`/`accepted_at` and the completion record
   names the manifest's candidate SHA and owner verdict; no separate verdict
   file is required.
9. Work-item, documentation-link, and changed-document Markdown checks pass.

## Explicit non-goals

- No Rust, SDK, console, mock, schema, or vector implementation change beyond
  the decision artifacts needed to state the accepted contract.
- No new operation, route, authentication method, role, or Problem tuple.
- No P-0022 SDK implementation or P-0023 Authoring UI.
- No deployment, public release, or broad API-versioning policy beyond this
  envelope conflict.

## Dependencies and open questions

- P-0021 exposed the conflict while shaping its SDK successor and must be done
  before this decision is claimed.
- Open questions: none; selecting and ratifying the canonical representation is
  the work of this decision item.

## Qualification commands

Run from the repository root, replacing the contract path only if the final
decision splits supporting appendices into the same evidence directory:

```sh
node scripts/check-work-items.mjs
node scripts/check-doc-links.mjs
npx markdownlint-cli2 --no-globs docs/work/items/P-0022-sdk-authoring-adoption.md docs/work/items/P-0025-ratify-http-operation-envelope.md docs/work/map.md docs/architecture/collaboration-server.md docs/decisions/0013-single-workspace-collaboration-server.md docs/work/evidence/P-0025/contract.md docs/work/evidence/P-0025/receipt.md
```

## Evidence contract

Record the decision candidate, source inventory, option matrix, owner verdict,
exact commands, and artifact digests in `docs/work/evidence/P-0025/` per the
[work-control protocol](../README.md).
