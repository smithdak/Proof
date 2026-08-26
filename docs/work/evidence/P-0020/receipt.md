# P-0020 execution receipt

[Back to the work item](../../items/P-0020-authoring-contract.md)

## Result

The authoring-surface contract is decision-complete at
[contract.md](contract.md): creation enters as a second v2 edit kind
(`object.create`) with intra-ChangeSet causality; the resource-intent artifact
advances to `/v2` with exactly-consumed creation slots so delegated Agents
gain creation without any Agent-registry row change; `schema.list/v1`,
`schema.get/v1`, and `object.list/v1` freeze as Human rows with bounded
exact-tuple discipline and release-status pairs; the flat content model is
ratified with subtree authority deferred behind a falsifiable reopening
trigger; blueprints are client-side presets. Storage, frozen-artifact,
problem-registry, verifier, conformance, and successor-graph plans are
enumerated for the implementation successor.

## Method

Groundwork research ran against the claimed base `e53920b`: registry row
anatomy (`AuthorityOperationEntry`, `HumanOperationRowV1`, frozen-hash
computation), the single-edit-kind touchpoint inventory, and draft-state
storage reality (SQLite content tables, PG facts/projections,
authorization plumbing). Decisions cite file:line references from that tree.

## Owner decision inputs

The project owner set scope before shaping: full vertical first, flat model,
blueprints as presets, subtree authority deferred rather than promoted. The
owner accepted the resulting candidate without rework.

## Commands

| Command | Exit |
| --- | --- |
| `node scripts/check-work-items.mjs` | 0 (20 items) |
| `npx markdownlint-cli2` over changed docs | 0 |

No push, tag, public release, or implementation code was produced by this
item; its authorized scope forbids it.

## Residual boundaries

Register-read performance is unmeasured (indexing stays fog); console
embedding into the axum server remains the open P-0016 decision;
locale fallback/negotiation, rendition deletion, base-Object replacement,
relationship localization, and dynamic subtree selection remain fog.
