# Strategy and destination ladder

**Status:** Ratified  
**Baseline:** August 24, 2026

This document names the destinations after Milestone 3, the standing loops that
run between them, and the falsifiable criteria that define market leadership.
The [vision](vision.md) states what Proof is; this document states the order in
which Proof becomes impossible to ignore and the triggers that reshape that
order. Project owner `smithdak` ratified it on 2026-08-24.

## Competitive position

Incumbent platforms now market agentic content operations: Kontent.ai brands
itself an Agentic CMS with externally audited AI governance, Contentstack ships
an agent orchestration suite, and Strapi distributes an MCP server. Their
governance models are audit-trail models: a consumer must trust the producing
system's logs, retention, and honesty.

Proof's differentiation is structural and remains unmatched: every governed
transition produces cryptographic evidence that an independent verifier can
reconstruct without the producing Workspace, its private keys, or its vendor.
Strategy therefore requires every destination to deepen verifiable governance,
never trade it for feature parity. A feature that cannot coexist with the
evidence model does not ship.

## Destination ladder

Each destination is a complete capability loop with exit evidence accepted by
the project owner. Destinations are shaped into work items by the
[rolling-wave protocol](../work/README.md) one frontier item at a time.

### Destination 4 — Operable by strangers (private)

**Outcome:** A person outside the project can stand up the server, bind an
agent, and drive the localization north-star end to end using only repository
documentation — while the repository itself remains private.

1. Close the residuals recorded at Milestone 3 acceptance:
   route-complete enrollment (`agent-binding.issue/v1`,
   `oidc-binding.issue/v1`) with usable issued credentials, and the
   PostgreSQL-backed application semantic executor for full mutation-row
   local/server trace parity.
2. Ship a TypeScript SDK over the shared HTTP contracts; expose the Rust
   workspace's application contracts as a consumable SDK surface.
3. Produce a deployable server artifact that brings up `proof-server`, the
   delivery worker, and PostgreSQL with one command.
4. Author the documentation site and a quickstart that ends with an external
   agent completing a governed ChangeSet through MCP and an independent
   verifier reaching Complete.
5. Select a license through an ADR and establish versioning discipline so the
   later public flip is a decision rather than a project.

Exit condition: on a clean machine, a non-author completes the full loop in
under 15 minutes from checkout to verifier Complete. A private pilot cohort
begins providing feedback. The public flip does not occur inside this
destination.

### Destination 5 — CMS core completeness

**Outcome:** Proof satisfies the capability table stakes an enterprise buyer
compares against, without weakening the evidence model.

- Typed relationships and asset references with integrity preservation.
- Locale fallback and negotiation beyond exact-locale delivery.
- Delivery and query API breadth sufficient for real frontends.
- Migration Edits and import/export tooling foundations.
- Generalized event delivery beyond private preview outbox.

The public release flip lands here by default; the owner may pull it earlier
at Destination 4 acceptance.

### Destination 6 — Enterprise readiness

**Outcome:** The roadmap Milestone 4 profile: production operation as an
enterprise CMS. Multiple Workspaces, high availability, backup and restore,
workload identity and KMS integration, retention and legal hold, performance
qualification, threat-model closure with external security review, signed
artifacts, SBOMs, provenance, and reproducible builds. Compliance posture is
expressed against auditable AI-governance frameworks so the existing evidence
chain becomes certified counter-positioning rather than new machinery.

### Destination 7 — Market leadership

**Outcome:** Proof is the reference platform for governed agent content
operations. A human console consumes the same application contracts;
migration tooling imports from incumbent platforms; ecosystem integrations and
published head-to-head benchmarks make the differentiation legible to buyers.

## Standing loops

1. **Wave loop.** Execution follows the rolling-wave protocol: shape one
   frontier item, ratify when it changes a contract, implement autonomously,
   gate, accept, reshape only newly visible successors. Executors run full
   waves and stop only at mandatory acceptance points.
2. **Landscape loop.** Each wave includes a recurring scan of competing
   platforms' agentic and governance capabilities, recorded against this
   document. Findings re-rank the ladder or trigger pivots.
3. **Feedback loop.** From Destination 4 onward, pilot findings feed every
   shaping decision. Post-flip, adoption signals join them.
4. **Quality bar.** Conformance fixtures remain immutable once consumed, the
   Linux CI gate stays enforced, and independent verification reaches
   Complete at every milestone. Coverage, fuzzing, advisory, license, and
   mutation gates join the enforced set entering Destination 6.

## Success criteria

Market leadership is claimed only when all of the following hold:

- An external agent completes the north-star task in under 15 minutes from a
  zero-state machine.
- A published benchmark shows Proof winning head-to-head against Kontent.ai,
  Contentstack, Sanity, and Strapi on verifiable governance and agent
  operability.
- The Destination 6 enterprise checklist is complete and independently
  reviewed.
- Adoption metrics show sustained third-party deployments, SDK usage, and
  contributor activity after the public flip.

## Pivot triggers

A trigger forces reshaping before further implementation:

- An incumbent ships producer-independent verification, eroding the primary
  differentiator.
- A capability gap blocks an entire target segment despite correct sequencing.
- Two consecutive waves produce evidence that a destination's exit condition
  was mis-specified.

Pivots amend this document through the documentation change process and
reshape the work map in the same narrow change.
