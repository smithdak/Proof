---
id: P-0006
title: Close Milestone 2 with independently verifiable evidence and conformance
status: ready
wave: now
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

Satisfied by completed P-0005 candidate
`c6f6ca899e1a63cf26f858d28b14163ffc270086` and Engineering evidence commit
`03fd4ea6088f943c708026c42f918f478c115329`. The exact exit fixture and
offline-verification input contract are reshaped below from the retained v13
consequence and Release semantics, not from roadmap prose alone.

## Ratified P-0003 profile reshape

The following P-0003-dependent clauses are ratified and now shape P-0006
qualification. P-0005 has satisfied the implementation dependency. The
controlling contract is the
[authenticated actor contract](../../architecture/authenticated-actor.md).
P-0002 and P-0007 have closed the Human-path write-resource contract, P-0003
is accepted with its exact operation/projection registry, P-0004 implements
the bounded local authenticated read profile, and P-0005 implements the
complete delegated localized-write path. P-0006 is now ready and unclaimed.

## P-0005 consequence and Release reshape

The portable closure and independent verifier must preserve, reconstruct, and
cross-check the exact meanings established by storage v13:

- carry the signed
  `AuthorizationDecisionV2.localized_consequence_commitment`, including the
  canonical result kind, result contract, result digest, and application
  consequence digest;
- carry the exact authenticated localized consequence evidence needed to
  reconstruct command and operation version, requesting Human, operating
  Agent, direct Delegation, selectors, application-key kind and value,
  semantic timestamp, Human-owned intent and Context policy/limits, validator,
  approval, canonical result, and raw P-0007 effect;
- preserve `ReleaseV2.principal_id` as the requesting Human and
  `ReleaseV2.authorization_decision_digest` as the P-0007 Human release-policy
  decision. The separate P-0005 Agent decision, result commitment, and raw
  effect must be verified as a cross-linked authority consequence, never
  substituted into those Release fields;
- treat the v13 Workspace-global application-key ledger as replay and
  projection-integrity evidence, not as a trust root. Recompute its ownership
  from the signed command, decision, consequence, result, and immutable
  application effect; and
- distinguish the stable successful application result and raw effect from the
  fresh signed localized-consequence commitment and cross-linked
  per-presentation consequence evidence for each exact replay. The
  Workspace-global key owner anchors the first successful command, result,
  effect, and application-consequence digest; each later Allow must
  independently reconstruct its current signed composite closure. A Deny
  carries decision, consumption, and actor evidence but no localized
  commitment, result, or consequence. A mapped application failure is an Allow
  with a signed failure-result commitment and cross-linked consequence
  evidence, rolls back partial application writes, and reserves no application
  key.

The clean-directory verifier must validate this closure without the producing
Workspace database or private keys and without reusing the producer's
projection-reconstruction or serialization path.

## Authorized scope

- Finalize the versioned Release predicate and future
  `AuthorityEvidenceBundleV1` selected after P-0003/P-0005. The exact container
  remains a P-0006 decision, but it must carry or resolve a complete portable
  authority closure under explicit caller trust. Add independently produced
  golden vectors.
- Export the transitive evidence closure required by P-0002/P-0003: the Release
  and required predecessor or rollback-target Releases; exact Environment
  configuration and policy bundle; Edition subjects and the ChangeSet/Edit
  evidence needed to recompute them; canonical validation results, submission,
  and approval records; public `requesting_subject_commitment` formed with the
  canonical 32-byte blind;
  `PrincipalBindingV1`; consumed `AuthenticatedCommandV1`; raw-UID-free
  `AuthenticatedActorContextEvidenceV1`; direct
  Human-to-Agent `DelegationV2` and applicable revocation `AuthorityRecordV1`
  entries; `AuthorizationDecisionV2`; ContextPack manifest; and
  signing-key validity/revocation evidence plus explicit verifier trust policy.
  The P-0002 closure includes the exact baseline Environment Release and
  Edition, immutable localized resource intent, source Object and Schema,
  every `ObjectLocaleRevisionV1` predecessor/result, complete superseded Edit
  lineage, the contiguous digest-linked validation-attempt chain and every
  repair-to-finding edge, effective proposal digest, deterministic policy
  bundle and findings, exact committed ChangeSet, resulting state, Edition v2
  delta, and Release v2 pointer transition.
  Where disclosure is withheld, include commitments and return an explicit
  incomplete verdict. Private requesting subject-plus-blind disclosure is
  audit-policy controlled. Include an independently retained expected
  authority-head checkpoint whenever the verifier must detect prefix truncation,
  forks, or rollback rather than only validate a supplied prefix internally.
  For root compromise, stop trust at the last independently pinned
  pre-compromise checkpoint. A dual-signed attacker successor/fork is not
  ordinary-rotation recovery; any new trust epoch/re-anchor is future explicit
  caller trust.
- Verify the selected representation in a clean directory without the
  Workspace database or any private key and without reusing the producer's
  reconstruction or serialization path.
- Complete structured repair, budget, stale-context, prompt-injection, tool
  confusion, scope-probing, revocation, retry, restart, and tamper cases.
- Under the **Ratified P-0003 profile**, add wrong-key, wrong-binding,
  wrong-issuer/recipient, command substitution, expired presentation, consumed
  `presentation_id`, authority-log rollback, unavailable authority root, and
  parent/subdelegation/chain rejection cases.
  Include a compromised-predecessor case that signs an attacker successor/fork
  and proves verification cannot extend trust past the independent
  pre-compromise checkpoint.
- Run the selected north-star scenario through application contracts, CLI,
  stateless MCP, and legacy MCP without ambient authority.
- Under the **Ratified P-0003 profile**, run the Agent workload under a distinct
  UID, container, or sandbox that denies repository, raw CLI, bootstrap-UID, and
  private Workspace access and exposes only the Human-owned broker/adapter
  channel. Same-UID proof of possession is attribution/integrity evidence only
  and cannot qualify bounded authority.
  Launch the Workspace-blind Agent-side signer separately from the Human-owned
  broker/verifier. Prove only the broker can open the Workspace and authority
  keys. Exercise both `proof-mcp` stdio and
  `proof auth execute --invocation -`; the latter receives one bounded framed
  stdin/already-open-FD invocation and never an Agent-selected path or argv.
- Update README, roadmap, work map, threat model, testing strategy, and
  changelog only when every exit criterion is evidenced.

## Explicit non-goals

- No collaboration server, HTTP/PostgreSQL parity claim, public release, or
  enterprise deployment claim.
- No requirement to store prompts or hidden model reasoning.
- No “fully valid” verdict when required evidence is withheld.
- No claim that the local file-backed profile isolates mutually hostile same-UID
  processes. If that becomes required, pivot to a protected broker or workload
  identity rather than treating per-Agent keys as containment.

## Acceptance criteria

- [ ] The exact Milestone 2 scenario includes bounded context, a prohibited
      change, structured repair, separate Human approval, delegated consequence,
      Release, and independent verification.
- [ ] The verifier independently proves that the released Edition differs from
      the unchanged baseline Release by exactly the authorized committed
      localized-rendition closure, with no ambient or same-resource hitchhiking
      commit and no fabricated locale fallback.
- [ ] Clean-directory verification succeeds with explicit caller-supplied
      Release and separate authority public trust roots and trust policy, but
      without the producing Workspace
      database, network resolution, private key, or trust in self-described
      envelope keys. It reports cryptographic, canonical, authority, policy,
      approval, subject, and evidence completeness separately.
- [ ] Signing-key validity and revocation are evaluated at signing time; later
      rotation or revocation does not invalidate historically valid Proofs.
- [ ] Authority validity is evaluated at each recorded consequential action's
      causal position and timestamp. Expiration or revocation effective
      afterward is not retroactive; revocation, disablement, or invalid chain
      state effective before the action makes the authority verdict invalid.
- [ ] Under the **Ratified P-0003 profile**, verification proves the subject
      commitment using the canonical 32-byte-blind hiding-commitment vectors,
      exact immutable `binding_id` plus its issuing authority sequence and
      record digest, single consumption of the signed
      command presentation, direct Human-to-Agent Delegation endpoints, and
      `AuthorizationDecisionV2` at the recorded authority-log position. Any
      chain or subdelegation input is rejected as unsupported. Actor-context
      evidence uses only the public commitment; any private opening is disclosed
      only under audit policy.
- [ ] Portable closure carries or resolves the exact
      `AuthenticatedActorContextEvidenceV1` canonical preimage persisted by
      P-0004 and proves it contains no raw UID. It treats `authenticated_at` as
      authentication completion time, not as authorization `evaluated_at`.
- [ ] A complete authority/trust verdict requires every Principal binding,
      Delegation issuer, policy, and revocation record either to be covered by
      authenticated signed evidence or validated through explicit
      caller-supplied trust roots and policy. Producer-exported
      self-consistency alone never establishes trust.
- [ ] Tampering or withholding each required supplied component fails
      deterministically or yields an explicit incomplete verdict; it never
      overclaims validity.
- [ ] `AuthorityEvidenceBundleV1` verification is implemented independently of
      the producer's authority-log reconstruction and serialization path. A
      valid Release signature without the required authority closure cannot
      yield a complete authority verdict.
- [ ] A verifier without an independently pinned expected authority head reports
      only internal validity of the supplied signed prefix. Rollback,
      truncation, fork, latest-history, or completeness claims require that
      checkpoint and fail closed when it is absent or mismatched.
- [ ] Capability discovery, errors, idempotency, and side-effect semantics match
      across application, CLI, and both MCP eras.
- [ ] C4 idempotent-result disclosure occurs only after fresh C5 authentication
      and current C6 authorization; revocation, Principal/binding disablement,
      or policy denial after the original effect blocks its result on retry.
- [ ] Under the **Ratified P-0003 profile**, authenticated Agent status/query
      capabilities are `evidence_write` and omit MCP `readOnlyHint: true`, while
      conformance independently proves that governed content remains unchanged.
- [ ] The north-star evidence records a distinct-UID/container/sandbox Agent
      denied repository, raw CLI, and private Workspace access and constrained
      to the Human-owned broker/adapter channel. A same-UID run cannot satisfy
      this criterion. It proves the signer cannot open the Workspace, authority
      keys, or ambient Human CLI and cannot induce either broker surface to open
      an Agent-selected path.
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

Ready and unclaimed at `2026-08-21T16:26:07.480Z` after P-0005 completed.
P-0005 Engineering evidence commit
`03fd4ea6088f943c708026c42f918f478c115329` binds the exact v13 inputs and
residual boundaries that this item must carry into portable verification. No
P-0006 implementation or Milestone 2 completion is claimed by this promotion.

## Residual risks and next-wave update

If the exit gate passes, chart only the newly visible Milestone 3 route. Do not
bulk-create server, enterprise, or Windows tickets before their contracts are
sharp.
