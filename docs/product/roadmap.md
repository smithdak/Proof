# Roadmap and MVP

**Status:** Ratified product sequence  
**Baseline:** August 3, 2026

The roadmap is organized around complete capability loops rather than feature count. Each milestone must produce an independently usable and testable system slice.

## Milestone 0 — Constitution and contracts

**Outcome:** Implementation can begin without inventing domain semantics inside individual crates.

- Ratify vocabulary and invariants.
- Record initial ADRs.
- Define the CLI result and error envelopes.
- Define identifiers, canonicalization, digest, and Proof formats.
- Establish the Rust workspace boundaries.
- Create conformance fixtures for canonicalization and identifiers.
- Establish testing, dependency, and supply-chain policies.

**Exit condition:** A contributor can explain every accepted state transition and identify the crate responsible for enforcing it.

## Milestone 1 — Local proof loop

**Outcome:** One person can manage and verify structured content entirely through the local CLI.

1. Initialize a Workspace.
2. Define and version a Schema.
3. Create Objects through a ChangeSet.
4. Inspect and validate a multi-Object ChangeSet.
5. Commit atomically against an explicit base state.
6. Create an immutable Edition.
7. Release it to a local Environment.
8. Query released content.
9. Inspect and verify the Release Proof.
10. Rebuild projections and reproduce the same Known State.

**Required quality:** Deterministic fixtures, crash-safe transactions, structured output, no direct writes, and no mutable published state.

## Milestone 2 — Agent authority

**Outcome:** An agent can safely complete the same loop inside bounded authority.

- Principal registry and local identities.
- Scoped, expiring Delegations.
- ContextPack construction and redaction.
- Capability discovery.
- Idempotency and resumable application operations.
- Structured repair loops.
- Stable MCP adapter with protocol negotiation.
- Agent-security abuse cases and conformance tests.

**Exit condition:** An agent can complete the north-star localization scenario without unrestricted repository access or privileged commands.

## Milestone 3 — Collaboration server

**Outcome:** A team can review, approve, publish, and verify changes remotely while preserving local semantics.

- HTTP API and PostgreSQL persistence adapter.
- Collaborative review and approval.
- OIDC identity integration.
- Policy administration.
- Event delivery and transactional outbox.
- Rust and TypeScript SDKs.
- Initial human web console.
- Preview Environment integration.

**Exit condition:** The same conformance suite passes against local and server modes.

## Milestone 4 — Enterprise readiness

**Outcome:** Proof can operate as a production enterprise CMS.

- Multiple Workspaces, brands, regions, locales, and Environments.
- High availability, backup, restore, and disaster recovery.
- Enterprise workload identity and key-management integrations.
- Migration framework and compatibility adapters.
- Retention, legal hold, redaction, and evidence export.
- Performance and scale qualification.
- Threat-model closure and external security review.
- Signed release artifacts, SBOMs, provenance, and reproducible-build targets.

## MVP definition

The MVP is Milestones 0 and 1. It is complete only when the entire local proof loop works. A partial collection of CRUD commands is not an MVP.

## Success measures

### Correctness

- Replaying accepted records produces the same state digest.
- Partial ChangeSet effects are impossible after rejection, conflict, crash, or retry.
- Proof verification succeeds without trusting the agent that proposed the work.

### Agent operability

- All consequential operations have stable structured input and output.
- An agent can recover from validation failures using returned findings.
- Delegated work cannot exceed declared authority.

### Human operability

- Every change is explainable as a readable diff.
- An operator can identify intent, authority, source context, validation, approval, and outcome from one correlation chain.
- Rollback selects a prior immutable Edition rather than mutating history.

### Portability

- Core conformance tests are independent of CLI, HTTP, storage, and model providers.
- Local and server modes preserve identical state-transition semantics.

## Deliberate deferrals

The roadmap does not schedule personalization, experimentation, campaign automation, visual page building, or a full DAM. Those capabilities are evaluated only after the CMS core is operational and stable.
