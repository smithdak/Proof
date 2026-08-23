# Scope and non-goals

**Status:** Ratified  
**Baseline:** August 23, 2026

## Product boundary

Proof begins as a headless enterprise CMS. It is not initially a digital experience platform.

The CMS boundary contains the capabilities required to define, govern, publish, and deliver structured content. Adjacent marketing, customer-data, experimentation, and presentation concerns integrate with Proof but do not belong in the first core.

## In scope

### Content foundation

- Versioned JSON-based content Schemas.
- Structured Objects and typed relationships.
- Asset metadata and integrity-preserving asset references.
- Locales, variants, and explicit fallback rules.
- Query and content-delivery contracts.
- Complete history and reproducible state.

**Implemented P-0002/P-0007/P-0005/P-0006 Milestone 2 slice:** Milestone 2 supports
one deliberately narrower localization profile. An
existing locale-neutral Object revision is the source; each target
is an append-only localized rendition keyed by an exact `(object_id, locale)`
pair. The operation permits create or exact-revision replacement of that
rendition and no mutation of the source Object, Schema, relationships, or
lifecycle. Delivery is exact-locale only: a missing rendition is reported as
missing, never resolved through fallback or a general variant engine. The
broader locale, variant, and fallback scope above remains later product scope.

The accepted local Linux slice also exports a portable authority/content
closure and verifies it independently under explicit caller trust, without the
producing Workspace, private keys, or network resolution. That bounded result
does not supply locale fallback, a collaboration server, cross-platform
containment, deployment, or public release.

### Change and publication

- Intent-scoped, atomic ChangeSets.
- Optimistic concurrency against an explicit base state.
- Deterministic validation and policy evaluation.
- Review and approval gates.
- Immutable, content-addressed Editions.
- Environment-specific Releases.
- Promotion and rollback by moving release pointers to existing Editions.
- Verifiable Proofs for consequential operations.

### Identity and governance

- Human, service, and agent Principals.
- Scoped, expiring, revocable Delegations.
- Role- and attribute-aware authorization.
- Separation-of-duties policies.
- Audit queries and evidence export.
- Retention and redaction controls that preserve evidence integrity.

### Agent operation

- Machine-readable capability discovery.
- Task-bounded ContextPacks.
- Dry-run, diff, explanation, and validation flows.
- Structured findings and repair guidance.
- Idempotent consequential commands.
- CLI, API, SDK, and MCP adapters over the same application contracts.

The **Ratified P-0002** sequence uses P-0007 as a named content-foundation
prerequisite. P-0007 implements the localized-rendition, repair, query,
Edition, Release, and migration contracts on the authenticated Human path.
P-0005 composes those proven content semantics with the P-0004 authorization
kernel; it does not invent a separate Agent content model. The composition is
bounded: the Human issues intent and ContextPack closure and approves, while
the Agent executes only the 11 fixed localized v2 operations. P-0006 qualifies
that exact composition through portable verification and distinct-UID Linux
broker containment without broadening its content or authority semantics.

### Enterprise operation

- Multiple Workspaces, brands, locales, and Environments.
- Enterprise identity-provider integration.
- Self-hosted and managed deployment models.
- Import, export, migration, and synchronization tooling.
- Events, webhooks, observability, backup, restore, and disaster recovery.

## Not in the initial product

- Customer data platform functionality.
- Behavioral profiles or audience segmentation.
- Personalization and recommendation engines.
- Experiment design or statistical analysis.
- Campaign and customer-journey orchestration.
- Visual page building.
- Frontend rendering or static-site generation.
- Full digital-asset transformation and creative-production pipelines.
- Model hosting, model routing, or a proprietary general-purpose agent runtime.
- Browser-driving automation for CMS administration.
- Autonomous writes that bypass authority, policy, validation, or approval.

## Boundary rules

### Proof owns content truth, not presentation truth

Proof stores structured content and delivery contracts. A frontend decides how that content appears. Preview adapters may render content for review, but presentation frameworks do not enter the domain core.

### Proof owns operational evidence, not factual truth

A Proof establishes how a state transition happened. Domain-specific factual review can be implemented through validators and approvals, but the name does not imply that every published assertion is true.

### Proof integrates with AI; it does not depend on one AI stack

Models and agents can propose work through stable contracts. No model provider, orchestration framework, or agent protocol becomes the system of record.

### Proof can grow into a platform without becoming a monolith

Personalization, experimentation, DAM, analytics, and delivery accelerators may become optional services or integrations. They must consume explicit contracts and preserve the CMS invariants.

## Scope test

A proposed capability belongs in the CMS core when all three are true:

1. It is required to define, govern, publish, release, or verify structured content.
2. Its semantics must be identical across CLI, API, agent, and human interfaces.
3. Omitting it would force a client to bypass a core invariant.

If any condition is false, the capability should begin as an adapter, integration, or separate product.
