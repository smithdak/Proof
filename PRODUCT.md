# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated and user-confirmed (2026-08-24): Vite + React 19 + TypeScript (strict) + Tailwind CSS v4 + Radix-based primitives + TanStack Router/Query, in `web/`. Backend contact through a typed client mirroring the exact nine-route `proof-server` HTTP contract; MSW contract-faithful mocks during development.

## Users

Primary: platform and content-engineering teams plus enterprise content operators who review, validate, approve, commit, release, and verify governed content changes alongside software agents. Secondary: agent builders who inspect what their agents did, under whose authority, and with what evidence. Situation: focused work sessions at a desktop, often reviewing dense structured data (diffs, validation findings, verification reports); frequently working in dim rooms, late hours, alongside terminals.

## Product Purpose

The Proof web console is the human operating surface of Proof, an agent-first enterprise CMS that treats content mutation as a governed transaction. Every proposed change has identity, intent, scope, authority, validation result, and provenance. Publishing produces immutable Editions; releasing produces verifiable Proofs. Success means a human can supervise agent-proposed work end to end — review a ChangeSet diff, read structured validation findings, approve with exact evidence, commit, release, and independently verify the resulting proof — without ever bypassing governance.

## Positioning

Traditional CMS admin UIs assume humans clicking through administrative screens bolted onto mutable records. Proof's interface hierarchy is inverted: the CLI and machine interfaces are primary, and this console consumes the exact same application contracts (`POST /api/v1/human/operations/{name}/{major}`) with no UI-only capability and no governance bypass. A neighboring CMS could not copy this without rebuilding its write path around atomic ChangeSets, scoped Delegations, and signed evidence.

## Operating Context

- Single-Workspace collaboration server behind same-origin BFF: OIDC Authorization Code + PKCE login, bounded sessions, CSRF-protected mutations.
- Nine-route closed HTTP surface; all application work dispatches as named versioned operations.
- Domain vocabulary is canonical and capitalized: Object, Schema, Edit, ChangeSet, Edition, Release, Proof, Known State, Principal, Delegation, ContextPack.
- Identifiers are operational material: UUIDv7 ids, BLAKE3 content digests, Ed25519 key ids, canonical JSON, DSSE envelopes.
- ChangeSet lifecycle: create → add edits → diff → validate → submit → approve → commit → Edition → Release → Proof.
- Validation failures are structured findings with repair guidance, not prose errors; repair appends superseding Edits inside the same ChangeSet.
- Release verification reports conclude Complete, Incomplete, or Invalid against explicit caller trust.

## Capabilities and Constraints

Implemented operation registry the console may expose: `workspace.status`, `capabilities.discover`, `changeset.create/add/diff/get/validate/submit/approve/commit`, `edition.create`, `release.create/get/verify`, `object.query_released`, `evidence.export`, `delegation.issue/revoke`, `delivery.get/replay/abandon`, `context.build`.

Constraints: approval and closure issuance are Human-only; published state is immutable (corrections produce new Editions); history is never silently rewritten; every mutation expresses intent; local and server modes share semantics. Undecided product facts: production embedding of the built console into the Rust server (frozen route contract requires a decision), information architecture beyond the first release, live collaboration presence.

## Brand Commitments

Name: Proof. Tagline: "Every release carries its proof." Voice: precise, technical, declarative, evidence-forward; short assertive sentences; no hype words, no exclamation marks, no anthropomorphizing of agents. Agents are Principals; proofs are receipts. The word "proof" means operational evidence, never factual truth claims about content.

## Evidence on Hand

Ratified product and architecture documentation under `docs/` (vision, scope, roadmap, constitution, domain model, proof model, CLI reference). Implemented CLI and server code under `crates/`. No logos, marketing imagery, screenshots, testimonials, or customer references exist; none may be fabricated. Demonstration data shown in the console is synthetic and must remain plausible domain data (localization campaign changesets, signed releases), clearly generated rather than presented as customer records.

## Product Principles

1. Evidence over assertion: the interface shows the receipt, the digest, the finding — never a claim without its proof beside it.
2. Intent is data: every mutation displays who initiated it, under whose authority, within what scope.
3. Same semantics everywhere: the console exposes exactly what the CLI exposes, no more, no less.
4. Determinism governs consequence: validation results and verification verdicts are rendered as deterministic facts, styled accordingly.
5. Published state is immutable: history reads forward; corrections are new facts, never edits to old ones.

## Accessibility & Inclusion

Keyboard-first operation is product substance, not garnish: the console supervises machine-driven workflows, so full keyboard reachability, visible focus, and command-palette parity with pointer navigation are required. Target WCAG 2.2 AA. Dense data views must preserve contrast and readable type at realistic density; monospace identifiers must stay legible at small sizes.
