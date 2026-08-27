---
id: P-0023
title: Build the governed Authoring surfaces in the web console
status: blocked
wave: now
kind: implementation
blocked_by: [P-0022, P-0028]
required_reading: [docs/work/items/P-0026-agent-first-cms-capability-canon.md]
allowed_paths: [web, docs/work]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: impeccable-finish-review
accepted_by: null
accepted_at: null
---

# Build the governed Authoring surfaces in the web console

[Back to the work map](../map.md)

## Outcome

An authenticated content operator can use the existing Proof console to browse
the committed Object and Schema registers, inspect one Object's governed state,
and compose a new Object plus locale rendition through the exact Human
operation contracts. The flow exposes the immutable intent, creation slot,
ChangeSet, Edits, validation findings, and operation receipts rather than
introducing a UI-only mutation or bypass.

The work extends the established notarial-register design system. It replaces
the synthetic released-only `/objects` projection on the touched routes with
SDK-backed contract data, migrates every touched feature operation away from
the legacy `executeOperation` transport, and keeps the remaining console
surfaces behaviorally intact. P-0024 owns the compose-stack browser north star
and final cross-surface polish.

## Blocked by owner direction

**Blocked 2026-08-27:** the project owner froze all production UI work until
the backend supports full agent-first CMS operations (P-0026 through P-0029).
This item resumes only after the CMS-completeness gate defined in P-0026 is
satisfied and the project owner explicitly re-opens UI work.

## UX brief

- **Job and audience:** a desktop-first enterprise content operator is
  preparing a governed content addition while supervising the same operation
  contracts available to agents and the CLI. Visitor mode is `Operate`.
- **Outcome and proof:** the operator can find the committed Object or Schema,
  understand release coverage and provenance, then create a draft composition
  whose intent, slot, Object Edit, locale Edit, validation result, operation
  IDs, and result anchors remain inspectable.
- **Selected direction:** preserve the existing notarial register. `/objects`
  becomes the Content register with Object and Schema ledger tabs; Object
  detail is a forward-reading register page; New Item is a staged folio whose
  dominant moment is the exact intent-to-Edit receipt chain. No replacement
  visual world, dashboard card grid, wizard chrome, or nested panel stack.
- **Scope and boundaries:** production-ready console routes and component tests
  under the existing React/Vite app, using the existing six-destination shell.
  The rail keeps one Content destination; Schema is an index tab, not a seventh
  top-level destination. No hierarchy, template entity, blueprint governance,
  or content model expansion.
- **States and ranges:** cover loading, no Schemas, no Objects, single and
  multi-page registers, released and unreleased Objects, no locale renditions,
  long identifiers, Schema miss, permission denial, validation failure,
  idempotent replay, transport failure, and partial multi-step composition.
  Respect the frozen 100-row and 100-Edit limits.
- **Interaction and layout:** keyboard and pointer reach the same actions;
  register rows expose stable deep links; focus returns after overlays; mobile
  uses entry cards and a linear staged flow without horizontal form overflow.
  Consequential ink marks the one creation submission, while replay, retry,
  navigation, and inspection remain ordinary ruled actions.
- **Constraints:** preserve WCAG 2.2 AA, reduced-motion behavior, the three type
  voices, digest-copy affordances, exact domain capitalization, synthetic-data
  disclosure in mock mode, and the current `PRODUCT.md`/`DESIGN.md` authority.

## Authorized scope and tasks

1. Extend `proof-sdk` only with the exact Human registry pairs, inputs, and
   typed results required by the touched existing ChangeSet views and the New
   Item composition. Resolve each pair from the frozen HTTP registry; do not
   clone Agent types under a Human route or invent a generic result escape.
2. Before migrating a Human pair, add a retained successful Rust fixture whose
   `data` validates against that row's advertised result Schema. If the current
   backend producer is generic or otherwise non-conformant, repair its exact
   projection in this item or leave the feature visibly unavailable; never
   weaken P-0022 validation.
3. Replace `web/src/api/client.ts` feature calls on touched surfaces with the
   centralized `ProofClient`. Remove the legacy feature client only after no
   production import remains. Preserve SDK `ProblemError` and transport-error
   distinctions through query and mutation state.
4. Turn `/objects` into the Content register without adding a primary-nav
   destination. Its Object index consumes `object.list/v1`, exposes Schema and
   release-coverage filters, follows opaque cursors, and renders provenance,
   locale/revision summaries, current Release state, and committed-not-released
   scope exactly.
5. Add the Schema register as the sibling ledger tab. It consumes
   `schema.list/v1` and `schema.get/v1`, supports exact ID/version filtering and
   opaque pagination, and renders the stored Draft 2020-12 document, digest,
   and provenance without evaluating or rewriting the Schema in the browser.
6. Add stable Object and Schema detail routes. Object detail combines the
   committed register entry with available released rendition data, presents
   Schema-governed fields, locale tabs, revision lineage, coverage state, and
   provenance, and states when committed content has no released rendition.
   Schema detail supports a direct return to matching Objects.
7. Add a New Item flow that selects one exact Schema and Environment, captures
   locale-neutral Object fields plus one or more exact locale renditions, and
   previews the normalized composition before consequence. Client-side
   blueprints may prefill fields but are neither persisted entities nor grant
   authority.
8. Execute the composition as an explicit receipt-bearing sequence:
   `content-resource-intent.issue/v2` with one creation slot, `context.build/v2`,
   `changeset.create/v2`, then `changeset.add/v2` with an `object.create` Edit
   before every `object.locale.put` that references it. Use fresh UUIDv7
   application keys, preserve Workspace-global key semantics, and make a
   partially completed sequence safely resumable from retained receipts.
9. Run validation after the Edits land and render structured findings with
   exact codes, subjects, and repair guidance. This item may stop at a valid
   draft; approval, commit, Edition, and Release actions remain on their
   existing governed surfaces and are not collapsed into New Item.
10. Replace only the touched MSW handlers with exact closed requests, accepted
    result envelopes, row-typed `data`, and representative Problems. Keep MSW
    behind P-0022's explicit development opt-in and label all demonstration
    records synthetic.
11. Preserve the incumbent ledger system and reusable primitives. Add a new
    primitive only when at least two touched surfaces need the same semantics;
    do not introduce hard-coded colors, boxed inputs, nested ruled panels,
    decorative status ink, or shadowed at-rest surfaces.
12. Cover desktop and mobile composition, keyboard order, accessible names,
    live-region feedback, focus restoration, reduced motion, loading and error
    states, cursor boundaries, replay, and double-submission prevention with
    retained component and transport tests.
13. Finish in two bounded visual passes: one desktop/mobile capture and one
    confirmation after the batched fixes. Run the Impeccable detector once,
    then satisfy the `impeccable-finish-review` disposition with valid
    screenshots and the existing design authority.

## Acceptance criteria

1. No production console code calls the removed legacy feature fetch client;
   every touched pair resolves through actor-qualified `proof-sdk` types and
   exact wire tests.
2. `/objects` displays the committed Object register rather than only released
   seed fixtures, with exact filters, cursors, release coverage, provenance,
   empty/error states, stable detail links, and responsive entry cards.
3. The Schema register and detail surface reproduce exact `schema.list` and
   `schema.get` data, including the stored document and digest, without adding
   a Schema mutation path.
4. Object detail distinguishes committed state from released renditions,
   exposes available locale/revision lineage, and never implies a draft is
   public or substitutes a missing rendition.
5. New Item emits one exact creation slot, one earlier `object.create` Edit,
   and matching later locale puts. Mixed Edit fields, unknown Schemas, slot
   mismatches, duplicate Objects, stale state, permission denial, and
   validation findings surface as exact typed Problems or findings.
6. Multi-step progress is explicit and resumable: successful receipts are not
   hidden after a later failure, retries reuse only the correct application
   identity, and double submission cannot create a second logical Object.
7. No hierarchy, subtree selector, template entity, server-side blueprint,
   locale fallback, rendition deletion, base-Object replacement, or new
   backend operation/registry row is introduced.
8. Component and transport suites cover minimum, typical, 100-row/100-Edit
   boundary, long-content, empty, loading, failure, replay, and mobile states.
   TypeScript rejects every cross-actor or cross-kind value used by the flow.
9. `pnpm typecheck`, `pnpm lint`, `pnpm test`, and `pnpm build` pass. Touched
   Rust/SDK drift suites, documentation links, work-item validation,
   Markdown lint with `--no-globs`, and `git diff --check` pass.
10. Desktop and mobile screenshots are valid, the one detector pass has no
    unresolved mechanical finding, and the finish reviewer returns `ship` or
    scores every requested fix resolved. No Playwright or deployment claim is
    made.

## Explicit non-goals

- No P-0024 compose-stack Playwright north star, cross-surface polish swarm,
  production embedding, deployment, package publication, or public release.
- No replacement of the notarial-register design system, no new top-level
  navigation family, and no broad redesign of Overview, Releases, Proofs, or
  Authority.
- No Agent command-signing UI, autonomous Agent loop, hierarchy, subtree
  authority, locale fallback, generic template entity, or blueprint
  governance.
- No Schema registration/mutation operation, Object deletion, rendition
  deletion, relationship localization, or base-Object replacement.
- No silent compatibility parser for old HTTP envelopes or untyped operation
  result fallback.

## Dependencies and decisions

- P-0020 supplies the accepted content and authoring-surface decisions.
- P-0021 supplies Object creation, creation-slot intent, Schema/Object reads,
  and local/PostgreSQL application semantics.
- P-0022 supplies the accepted envelope, exact result validation,
  actor-qualified SDK foundation, and console SDK/session configuration.
- `PRODUCT.md`, `DESIGN.md`, and the existing design-system contracts are the
  durable product and visual authority. This item is an extension inside that
  established world, not a new direction round.
- P-0024 is shaped only after this item's implementation and finish review
  expose the exact browser qualification surface.
- Open questions: none.

## Qualification commands

Run the touched Rust/SDK suites from the repository root, then the complete web
gate from `web/`:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked -p proof-server --all-targets --all-features
cargo test --locked -p proof-local --test p0008_collaboration_contract
node scripts/check-work-items.mjs
node scripts/check-doc-links.mjs
```

```sh
pnpm --filter proof-sdk typecheck
pnpm --filter proof-sdk lint
pnpm --filter proof-sdk test
pnpm typecheck
pnpm lint
pnpm test
pnpm build
```

Run targeted Markdown lint with `npx markdownlint-cli2 --no-globs`, the
Impeccable detector once over changed UI targets, and the finish-review capture
matrix required above.

## Evidence contract

Record the immutable item-work candidate, exact commands and exits, changed
routes/components, migrated operation pairs, successful row fixtures, desktop
and mobile screenshots, detector output, finish-review disposition, artifact
digests, and residual boundaries under `docs/work/evidence/P-0023/` per the
[work-control protocol](../README.md).
