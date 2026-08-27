---
id: P-0016
title: Initial human web console with notarial-register design system
status: done
wave: now
kind: implementation
blocked_by: []
claimed_by: ox-alpha:proof:p-0016
claimed_at: 2026-08-24T21:30:00.000Z
base_sha: 7e8162e36f5a6a2f11c64cf7059947ca43d161e0
review_gate: impeccable-finish-review
accepted_by: project-owner
accepted_at: 2026-08-25T19:34:23.219Z
required_reading: []
allowed_paths: []
---

# Initial human web console with notarial-register design system

[Back to the work map](../map.md)

## Outcome

The roadmap's "Initial human web console" exists as `web/`: a React 19 +
Vite + TypeScript console covering the six surfaces the frozen operation
registry supports — Overview, ChangeSets (list, detail with lifecycle rail,
diff, validation findings, approve/commit flow), Released content, Editions
and Releases (with six-root verification report and deliveries), Proofs and
Evidence, Authority (principals, delegations) — behind a session-aware shell
with a global command palette, built on a documented design system
(notarial-register world: laid-paper ground, iron-gall ink, prussian ruling
hairlines, rubber-stamp status marks, one reserved consequential ink for
irreversible actions). The console talks to a typed client over the exact
nine-route surface with contract-faithful MSW mocks and a seeded synthetic
workspace; live-server wiring and production embedding remain open.

## Why now

Milestone 3 closed and Destination 4 ("Operable by strangers") is active.
The roadmap names the initial human web console as part of the unshaped
next destination; the project owner requested this build directly on
2026-08-24 and ratified the three execution decisions: direction delegated
to the executor within an agent-native, anti-Sitecore brief; React + Vite
stack; contract-faithful mocks over live wiring for the first build.

## Authorized scope

- `PRODUCT.md` product record and the console surface brief.
- Design direction selection via the impeccable concept-seed roll
  (seed 8fe727c9, operate mode, code-led build path recorded in
  `.impeccable/config.json`).
- `web/` workspace: Vite, React 19, TS strict, Tailwind v4, Radix
  primitives, TanStack Query, react-router, MSW, Vitest, Playwright.
- Design-system primitives under `web/src/design-system/` with a binding
  contract (`CONTRACT.md`, `CONTRACT-primitives.md`).
- App shell, session provider, command palette, six feature surfaces,
  seeded mocks mirroring the nine-route contract and operation registry.
- Screenshot evidence, mechanical design-detector pass, two batched visual
  fix rounds, finish review, and `DESIGN.md` documentation of the built
  world.

## Explicit non-goals

- No changes to any Rust crate, the frozen nine-route surface, or the
  operation registry.
- No production embedding of the console into `proof-server` (requires an
  ADR against the frozen route contract).
- No live OIDC/PostgreSQL wiring; no deployment; no public release.
- No console localization, dark variant, or collaborative presence.

## Acceptance evidence

- `pnpm typecheck`, `pnpm lint` (0 errors), `pnpm test` (45/45), and
  `pnpm build` all green at the item-work commit.
- Mechanical design detector (`detect.mjs --json src`): zero findings.
- 19 viewport captures (9 routes x desktop/mobile + palette) under
  `.impeccable/review/`; two batched fix rounds applied (mobile stacked
  entry cards, consequential-ink discipline, revoked-stamp placement,
  overview density, label contrast, palette capture timing).
- Finish review verdict: **ship** — all seven findings resolved across two
  fix rounds; recorded in `.swarm-reports/p0016-finish-review.md`.
- `DESIGN.md` and its sidecar (`.impeccable/design.json`) recorded from the
  built world by the documenter pass.

## Rework log

- Rework pass 1 executed (2026-08-25): three parallel front-end workers
  audited and polished all six surfaces; 58/58 console tests, tsc, and eslint
  green. Key changes: the Release-detail verdict stamp no longer reads as a
  control (natural scale, meta-line placement — the owner's "Incomplete
  button"); consequential ink reserved for irreversible actions on New
  ChangeSet; Edits tab gained its missing mobile card; real empty states on
  authority surfaces; locale chips unified to one spec; id/digest cells
  truncate with tooltips; sentence-case labels; AA contrast fixes in
  DiffRowView, Stamp token floor (text-2xs replaces hardcoded 11px), and
  sub-4.5:1 meta text raised. SDK live-spec made collection-safe so the shared
  workspace test run stays hermetic (13 pass + 2 skip without a live server;
  live leg re-proven during P-0018). Item returns to the finish-review gate.
- Rework pass 1 (2026-08-25): finish-review returned by the project owner with
  three findings: (1) the Incomplete control on the Releases surface reads as a
  button but does not behave like one — rework its affordance; (2) an overall
  polish pass is required before ship; (3) direction confirmed: good
  foundation, fan out parallel front-end work across all six surfaces.

## Completion record

Item-work commits `adad15c`, `d227bf6`, `be16f49`, `15374d6`, `04de45b`,
`588d74b`, and `86e187e`; see `evidence/P-0016/receipt.md` and
`manifest.json` for the exact command log. The `impeccable-finish-review`
gate returned `ship` on 2026-08-25; the item remains `review` pending
project-owner acceptance, which moves it to `done`.
