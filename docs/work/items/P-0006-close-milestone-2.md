---
id: P-0006
title: Close Milestone 2 with independently verifiable evidence and conformance
status: blocked
wave: next
kind: qualification
blocked_by: [P-0005]
claimed_by: null
claimed_at: null
base_sha: null
review_gate: project-owner
accepted_by: null
accepted_at: null
---

# Close Milestone 2 with independently verifiable evidence and conformance

[Back to the work map](../map.md)

## Outcome

Proof passes the ratified Milestone 2 north-star scenario through stable
application, CLI, and MCP contracts, and an independent verifier can distinguish
cryptographic validity, complete authority/evidence validity, and incomplete
evidence without trusting the producing Workspace or Agent.

## Promotion condition

Re-shape the exact exit fixture and offline-verification input contract after
P-0005 closes. Do not mark this item `ready` from roadmap prose alone.

## Authorized scope

- Finalize the versioned Release predicate and a versioned
  offline-verification input contract selected after P-0003/P-0005. It may be
  a manifest plus supplied artifacts, a bundle, or another ratified
  representation. Add independently produced golden vectors.
- Export the transitive evidence closure required by P-0002/P-0003: the Release
  and required predecessor or rollback-target Releases; exact Environment
  configuration and policy bundle; Edition subjects and the ChangeSet/Edit
  evidence needed to recompute them; canonical validation results, submission,
  and approval records; authorization inputs and result; Principal-binding
  commitments; Delegation chain and revocations; ContextPack manifest; and
  signing-key validity/revocation evidence plus explicit verifier trust policy.
  Where disclosure is withheld, include commitments and return an explicit
  incomplete verdict.
- Verify the selected representation in a clean directory without the
  Workspace database or any private key and without reusing the producer's
  reconstruction or serialization path.
- Complete structured repair, budget, stale-context, prompt-injection, tool
  confusion, scope-probing, revocation, retry, restart, and tamper cases.
- Run the selected north-star scenario through application contracts, CLI,
  stateless MCP, and legacy MCP without ambient authority.
- Update README, roadmap, work map, threat model, testing strategy, and
  changelog only when every exit criterion is evidenced.

## Explicit non-goals

- No collaboration server, HTTP/PostgreSQL parity claim, public release, or
  enterprise deployment claim.
- No requirement to store prompts or hidden model reasoning.
- No “fully valid” verdict when required evidence is withheld.

## Acceptance criteria

- [ ] The exact Milestone 2 scenario includes bounded context, a prohibited
      change, structured repair, separate Human approval, delegated consequence,
      Release, and independent verification.
- [ ] Clean-directory verification succeeds with explicit caller-supplied
      public trust roots and trust policy, but without the producing Workspace
      database, network resolution, private key, or trust in self-described
      envelope keys. It reports cryptographic, canonical, authority, policy,
      approval, subject, and evidence completeness separately.
- [ ] Signing-key validity and revocation are evaluated at signing time; later
      rotation or revocation does not invalidate historically valid Proofs.
- [ ] Authority validity is evaluated at each recorded consequential action's
      causal position and timestamp. Expiration or revocation effective
      afterward is not retroactive; revocation, disablement, or invalid chain
      state effective before the action makes the authority verdict invalid.
- [ ] A complete authority/trust verdict requires every Principal binding,
      Delegation issuer, policy, and revocation record either to be covered by
      authenticated signed evidence or validated through explicit
      caller-supplied trust roots and policy. Producer-exported
      self-consistency alone never establishes trust.
- [ ] Tampering or withholding each required supplied component fails
      deterministically or yields an explicit incomplete verdict; it never
      overclaims validity.
- [ ] Capability discovery, errors, idempotency, and side-effect semantics match
      across application, CLI, and both MCP eras.
- [ ] A traceability matrix enumerates C1-C24 with executable accepted/rejected
      coverage or a justified `not applicable` result, and covers every public
      error added or materially affected by Milestone 2.
- [ ] Abuse tests and a final falsification review find no open Milestone 2
      blocker; residual risks are explicitly accepted or moved to map fog.
- [ ] The project owner explicitly accepts the exit evidence and residual risks
      before this item moves from `review` to `done`.
- [ ] The full Linux quality gate passes and durable evidence is recorded.
- [ ] Only then are Milestone 2 status claims changed to complete and the first
      Milestone 3 discovery items created.

## Required evidence

Create `docs/work/evidence/P-0006/receipt.md`, `manifest.json`, and reviewed
small golden fixtures when executing. Bind source SHA, toolchain, exact
commands, test/evaluation results, supplied-component digests,
independent-verifier environment, falsification findings, and accepted
residual risk. Large generated artifacts belong in a release/evidence store
once one is ratified, not in Git by default.

## Completion record

Blocked by P-0005.

## Residual risks and next-wave update

If the exit gate passes, chart only the newly visible Milestone 3 route. Do not
bulk-create server, enterprise, or Windows tickets before their contracts are
sharp.
