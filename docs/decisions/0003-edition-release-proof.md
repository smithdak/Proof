# ADR-0003: Separate Edition, Release, and Proof

**Status:** Accepted  
**Date:** 2026-08-03

## Context

“Publish” often conflates the accepted content state, its promotion to an Environment, and the evidence for that operation. The same content state may be released to multiple targets at different times under different policies.

## Decision

- An **Edition** is an immutable accepted content state.
- A **Release** makes one Edition current for one Environment.
- A **Proof** is portable signed evidence for the state transition.

Promotion and rollback create Releases; they do not mutate Editions or prior Releases.

## Consequences

- One Edition can be released to preview, staging, production, regions, or channels independently.
- Environment policy and approval evidence stays attached to the relevant Release.
- Rollback is an auditable forward operation.
- Product language requires careful consistency across interfaces.

## Alternatives considered

- **One Publish entity:** simpler vocabulary but loses the distinction between content identity and delivery action.
- **Mutable environment snapshots:** operationally common but weakens reproducibility and audit evidence.

## Verification

- Editions reject mutation after creation.
- Release fixtures demonstrate multiple Environments for one Edition.
- Rollback tests preserve all prior artifacts and create a new Release Proof.
