---
id: P-0025
title: Ratify one HTTP operation envelope across schema and runtime
status: review
wave: now
kind: decision
blocked_by: [P-0021]
claimed_by: ox-alpha:proof:p-0025
claimed_at: 2026-08-27T17:15:54.000Z
base_sha: 41364224e4fba87964da8c0974535330eba18195
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
   cross-checks; fresh authentication and current authorization before any
   idempotency lookup or prior-result disclosure; Workspace-global
   application-key identity across actor routes and operation pairs; nullable
   validated correlation identity; typed-result schema binding; and an
   unambiguous committed or immutable result anchor.
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
   treatment of existing v1 callers and stored evidence. Request-envelope
   changes must not make the deployment Workspace caller-selected or narrow
   the existing `(workspace_id, application_key)` replay namespace.
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
4. Fresh authentication and current authorization still precede idempotency
   lookup or prior-result disclosure, and application keys remain
   Workspace-global across actor routes and operation pairs.
5. Successful responses have one exact typed-result and anchor representation;
   every member's requiredness and nullability is specified.
6. The candidate lists every schema, Rust, SDK, test, vector/hash, mock, and
   documentation surface P-0022 must update, plus surfaces guaranteed unchanged.
7. The candidate records the per-option compatibility, security,
   implementation, conformance, SDK, console, documentation, and rollout
   effects required by task 4.
8. The accepted option is reflected in the applicable architecture/decision
   references, and P-0022 is reshaped to name the exact contract it consumes.
9. The project owner records acceptance or returns the item for rework; no
   implementation begins before acceptance.
   Acceptance populates `accepted_by`/`accepted_at` and the completion record
   names the manifest's candidate SHA and owner verdict; no separate verdict
   file is required.
10. Work-item, documentation-link, and changed-document Markdown checks pass.

## Explicit non-goals

- No Rust, SDK, console, mock, schema, or vector implementation change beyond
  the decision artifacts needed to state the accepted contract.
- No new operation, route, authentication method, role, or Problem tuple.
- No change to authentication/authorization ordering, deployment-Workspace
  selection, application-key namespace, or keyed replay semantics.
- No P-0022 SDK implementation or P-0023 Authoring UI.
- No deployment, public release, or broad API-versioning policy beyond this
  envelope conflict.

## Dependencies and open questions

- P-0021 exposed the conflict while shaping its SDK successor and must be done
  before this decision is claimed.
- Open questions: none; selecting and ratifying the canonical representation is
  the work of this decision item.

## Progress log

- Claimed by `ox-alpha:proof:p-0025` at `2026-08-27T17:15:54.000Z` from base
  `41364224e4fba87964da8c0974535330eba18195`; claim commit
  `61cc6886fc4287ae9100256fd0af2fdb67ab3ad6` is the candidate parent.
- Immutable decision candidate
  `1c76c0a26957e4a5f101236a5bb3bcd21ed539e3`, tree
  `85358d68a029a7a8dd9541d23c0b60eccb5ec138`, recommends the frozen Schema as
  authoritative and reshapes P-0022 for one atomic v1 cutover. The
  [contract](../evidence/P-0025/contract.md),
  [receipt](../evidence/P-0025/receipt.md), and
  [manifest](../evidence/P-0025/manifest.json) bind the exact proposal and
  qualification evidence.
- Project-owner verdict is pending. `accepted_by` and `accepted_at` remain
  null, there is no completion record, and P-0022 remains blocked. Acceptance
  must name the manifest's candidate; rework returns this item to `claimed`.

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
