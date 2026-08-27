---
id: P-0026
title: Ratify the agent-first CMS capability canon
status: done
wave: now
kind: decision
blocked_by: [P-0025]
required_reading: [docs/product/vision.md, docs/product/strategy.md, docs/architecture/domain-model.md, docs/architecture/collaboration-server.md]
allowed_paths: [docs/decisions, docs/product, docs/work]
claimed_by: z-ai:proof:p-0026
claimed_at: 2026-08-27T21:30:00.000Z
base_sha: 2c0faf59875fd479d6599f45e66d9495b4c02555
review_gate: project-owner
accepted_by: smithdak
accepted_at: 2026-08-27T21:45:00.000Z
---

# Ratify the agent-first CMS capability canon

[Back to the work map](../map.md)

## Outcome

Project-owner-accepted decision contract defining "agent-first full CMS
operations" as the product's next destination. The canon enumerates every
capability Proof must support, assigns each Sitecore-class capability a
disposition (adopt, redesign, surpass, or intentionally reject), and establishes
that every operation is available to Agents through the same typed, discoverable,
governed operation surface used by Humans — no UI-only semantics.

## Why now

P-0020 through P-0025 closed the authoring vertical, but its scope was a slice,
not the full operation set. The project owner has directed: UI frozen until
backend CMS completeness is reached; SitecoreAI is the competitive evidence
base; Proof must exceed Sitecore in performance, governance, and agent
operability rather than mirror its architecture. Without a ratified capability
canon, subsequent implementation waves will drift into feature-chasing rather
than bounded, evidence-backed delivery.

## Scope

- Enumerate the complete CMS operation taxonomy: schema/type lifecycle, object
  CRUD and archival, versions/rollback/comparison, relationships/hierarchy,
  localization/fallback/translation, workflow/approval/scheduling, publishing
  targets/scopes/unpublish, assets/DAM, search/bulk/import/export, and
  multi-site/environment governance.
- For each capability: name the agent-facing typed operation, its governance
  profile (Human-only gates vs. agent-executable), and its evidence contract.
- For each Sitecore-class capability: assign exactly one disposition —
  `adopt`, `redesign`, `surpass`, or `reject` — with rationale.
- State explicitly which capabilities are intentionally out of scope for Proof
  (e.g. personalization, marketing automation) so breadth is a choice, not a gap.
- Define the CMS-completeness gate that must be satisfied before any UI work
  resumes.
- Ratified canonical names and operation verbs become frozen vocabulary; later
  waves implement against this canon without renegotiating semantics.

## Non-goals

- No implementation work in this item.
- No UI design or console change.
- No Sitecore feature clone; dispositions are first-principles, not parity.
- No performance benchmark specification (P-0029 owns that).

## Acceptance evidence

- A ratified decision document in `docs/decisions/` with the complete capability
  taxonomy and per-capability disposition.
- Every capability has: operation name, agent-executability profile, evidence
  contract, disposition, and rationale.
- Explicit CMS-completeness gate definition.
- Project-owner acceptance recorded per work-item protocol.

## Completion record

Implemented ADR-0014 (`docs/decisions/0014-agent-first-cms-capability-canon.md`)
with the complete 45-capability CMS taxonomy, per-capability agent operation
class, governance profile, and Sitecore disposition. Defined the
CMS-completeness gate and the intentionally-out-of-scope boundary. Updated
`docs/decisions/README.md` with the ADR index entry.

Evidence: `docs/work/evidence/P-0026/receipt.md`, `manifest.json`.
