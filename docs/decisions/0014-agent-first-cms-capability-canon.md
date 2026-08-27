# ADR-0014: Define the agent-first CMS capability canon and UI-freeze gate

**Status:** Accepted

**Constitutional:** No

**Date:** 2026-08-27

## Context

The authoring vertical (P-0020 through P-0025) delivered end-to-end governed
create, read, mutate, publish, and evidence flows for a bounded slice. The
project owner has directed that no production UI work resumes until the backend
supports full agent-first CMS operations, with SitecoreAI as competitive
evidence rather than a blueprint. Proof must exceed Sitecore in performance,
governance, and agent operability, not mirror its architecture.

The ratified strategy (Destination 5) already names CMS core completeness as a
destination. This ADR defines what that destination means as a bounded,
falsifiable capability canon so implementation waves are evidence-driven rather
than feature-chasing.

## Decision

### Agent-first principle

Every CMS capability must be available to an Agent through the same typed,
discoverable, governed operation surface available to Humans. Agent access is
not a secondary API; it is the primary surface, with Humans and UIs as peers
over the same kernel. Governance (authentication, authority, approval,
idempotency, evidence, audit) applies universally to every actor.

### CMS capability taxonomy

The following capabilities define CMS completeness. Each names the required
agent-facing operation class, its governance profile, and its disposition
relative to Sitecore-class systems.

| # | Capability | Agent operation class | Governance | Disposition |
| --- | --- | --- | --- | --- |
| 1 | Schema create | `schema.create` | Agent-executable | surpass |
| 2 | Schema update (field add/remove/modify) | `schema.field.mutate` | Agent-executable | surpass |
| 3 | Schema version and deprecate | `schema.version` / `schema.deprecate` | Agent-executable | surpass |
| 4 | Schema validation and migration plan | `schema.validate` | Agent-executable | redesign |
| 5 | Object create | `object.create` | Agent-executable | adopted (P-0021) |
| 6 | Object update (all fields, all locales) | `object.locale.put` / `object.update` | Agent-executable | redesign |
| 7 | Object copy | `object.copy` | Agent-executable | adopt |
| 8 | Object move (hierarchy reposition) | `object.move` | Agent-executable | redesign |
| 9 | Object archive | `object.archive` | Agent-executable | redesign |
| 10 | Object restore | `object.restore` | Agent-executable | redesign |
| 11 | Object delete | `object.delete` | Agent-executable | redesign |
| 12 | Version history read | `object.versions` | Agent-executable | surpass |
| 13 | Version rollback | `object.rollback` | Agent-executable | surpass |
| 14 | Version comparison | `object.diff` | Agent-executable | surpass |
| 15 | Optimistic concurrency (revision conflict) | built into mutation envelope | universal | redesign |
| 16 | Relationships (typed, directional) | `relationship.set` / `relationship.remove` | Agent-executable | redesign |
| 17 | Hierarchy and tree management | `tree.reposition` | Agent-executable | redesign |
| 18 | Backlinks and referential integrity | `backlinks.list` | Agent-executable | surpass |
| 19 | Locale fallback and negotiation | query-level (not per-object) | Agent-executable | surpass |
| 20 | Translation job management | `translation.job.create` / `.status` | Agent-executable | redesign |
| 21 | Workflow definition (configurable states/transitions) | `workflow.define` | Human-only (governance) | redesign |
| 22 | Workflow instance execution | `workflow.transition` | Agent-executable | redesign |
| 23 | Assignment and review | `workflow.assign` | Agent-executable | redesign |
| 24 | Comments and annotations | `comment.add` | Agent-executable | adopt |
| 25 | Scheduled publish | `publish.schedule` | Agent-executable | redesign |
| 26 | Publishing targets (scoped) | `publish.execute` with target scope | Agent-executable | redesign |
| 27 | Scoped publish (tree, references, language) | `publish.execute` with scope flag | Agent-executable | surpass |
| 28 | Unpublish | `unpublish.execute` | Agent-executable | redesign |
| 29 | Publish rollback | `publish.rollback` | Agent-executable | surpass |
| 30 | Publish job status and history | `publish.status` / `publish.history` | Agent-executable | adopt |
| 31 | Asset upload | `asset.upload` | Agent-executable | redesign |
| 32 | Asset metadata update | `asset.metadata.put` | Agent-executable | adopt |
| 33 | Asset rendition generation | `asset.rendition` | Agent-executable | redesign |
| 34 | Asset rights and expiry | `asset.rights.put` | Agent-executable | redesign |
| 35 | Asset usage tracking | `asset.usage` | Agent-executable | surpass |
| 36 | Search and filter | `search.query` | Agent-executable | redesign |
| 37 | Facets and aggregation | `search.facet` | Agent-executable | redesign |
| 38 | Bulk operations (batch mutations) | `bulk.execute` | Agent-executable | redesign |
| 39 | Import (content + schema) | `import.execute` | Agent-executable | redesign |
| 40 | Export (content + schema) | `export.execute` | Agent-executable | redesign |
| 41 | Webhooks (event delivery) | `webhook.subscribe` | Agent-executable | redesign |
| 42 | Audit history query | `audit.query` | Agent-executable | surpass |
| 43 | Multi-site management | Workspace-per-site (existing model) | governance decision | redesign |
| 44 | Environment and target governance | existing Environment model | governance decision | adopted |
| 45 | Granular permissions | existing Policy/Delegation model | governance decision | adopted |

### Disposition meanings

- **adopt** — Sitecore's approach is sound; Proof implements equivalent
  semantics with its own contracts.
- **redesign** — Sitecore's approach has known pain; Proof rethinks the
  operation shape to eliminate that pain while preserving the capability.
- **surpass** — Sitecore has no meaningful equivalent, or its equivalent is
  weak; Proof's governance/evidence model creates a category advantage.
- **governance decision** — the capability exists but is a configuration or
  policy concern, not an operation to build; existing governance model covers it.

### CMS-completeness gate

UI work resumes only when all 45 capabilities are implemented and qualified,
and the project owner explicitly re-opens UI work. This gate is not a milestone
number; it is a checklist derived from this table.

### What is intentionally out of scope

Proof is an agent-first CMS, not a marketing suite. The following SitecoreAI
platform areas are intentionally out of scope for CMS completeness: personalization,
marketing automation, campaign management, email, commerce, customer data
management, and audience analytics. These may become future destinations but do
not gate UI work or define CMS completeness.

## Consequences

This ADR freezes the capability vocabulary. Implementation waves (P-0028
output) must cover every row without renegotiating operation names or governance
profiles. New capabilities require a superseding ADR. Performance targets
(P-0029) are absolute and independent of Sitecore's numbers.

The "surpass" rows are Proof's competitive moat: cryptographic evidence for
every operation, agent-native discoverability, and Rust-level performance are
not bolt-ons but structural advantages that Sitecore cannot retrofit without
replacing its architecture.

This ADR supersedes no prior decision. It extends ADR-0013's accepted server
contract with the capability breadth that contract will serve.
