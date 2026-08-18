# P-0003 candidate qualification receipt

## Outcome

P-0003 produced a qualified, versioned candidate for local Agent command
authentication and direct delegated authority. It is not an accepted decision.
The candidate is blocked on P-0002 because the final content, Edit, Edition,
Release, and locale resource closure may require `DelegationV2` to reopen or
version before project-owner review.

The architecture and conformance checkpoint is
`cf4e57d0ace70e80377d16b57e43b6099129e0d0`. The integrated item-work commit is
`b124b2491dfd787df1a562786f122fb6e62a1497`. This follow-up control commit binds
those immutable revisions, releases the claim, and records the P-0002 blocker.
Nothing was pushed, tagged, released, published, or accepted.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `main` |
| Worktrees | `1` |
| Starting HEAD / claim base | `11eb4dfb57577e52ddd95822a00fed3001b5164a` |
| Architecture and conformance commit | `cf4e57d0ace70e80377d16b57e43b6099129e0d0` |
| Integrated item-work commit | `b124b2491dfd787df1a562786f122fb6e62a1497` |
| Local `origin/main` tracking ref | `9f69e80cc631385b4f1942b76c584924d756aea9` |
| Live remote verification | Not performed |
| Claim | `codex:/root:p-0003` at `2026-08-17T20:41:57.212Z` |
| Candidate qualified | `2026-08-18T00:25:23.2379066Z` |

The candidate changed 84 paths from the claim base: 65 files under
`conformance/v1/authority/` and 19 architecture, decision, reference, product,
or work-control documents. No Rust source, migration, runtime database, private
key, provider credential, generated Proof, or production configuration changed.
The conformance corpus contains 26 strict Schemas, 38 vector files, and one
local README. The temporary vector generator was removed before commit.

## Candidate decision

The proposed local profile:

- derives requesting and operating Principals behind an authentication port;
- proves Agent credential control with per-command Ed25519 signatures;
- treats same-UID/private-Workspace processes as Human administrator trust and
  requires an isolated Agent-side signer plus Human-owned bounded-stdin broker
  for enforcement;
- supports exactly one direct Human-to-Agent `DelegationV2` and rejects Agent
  issuers, parents, chains, and subdelegation;
- records binding, Principal, Delegation, revocation, presentation-consumption,
  authorization, and planned root-transition facts in a signed causal authority
  sequence; and
- proposes, but does not ratify, a constitutional C4 replacement that makes
  current authentication and authorization precede idempotent result disclosure.

The strongest rejected alternative was starting with SPIFFE/mTLS. It provides a
stronger future workload boundary, but it requires a daemon or secure channel,
issuance and rotation infrastructure, workload selectors, and historical trust
material before resolving exact command binding. The smallest complete local
slice is a provider-neutral authentication port with Ed25519 proof of possession.

## Verification

All final gates passed on the Windows checkout:

- Draft 2020-12 metaschema, reference, and fixture validation: 26 Schemas, 46
  fixture validations, 18 external references, zero missing references.
- Public-byte dependency graph: eight Ed25519 signatures, 21 derived digests,
  four DSSE byte manifests, and a contiguous nine-record authority chain.
- Measured maximum canonical sizes: 6,137-byte `DelegationV2`, 19,128-byte
  `AuthorizationDecisionV2`, and 25,778-byte authority envelope, all below their
  declared 65,536/98,304-byte limits.
- JSON parse: 64 JSON files; provider-mismatch mutation rejected; all required
  authentication, authority, sorting, issuer, and administrator negative cases
  present.
- Documentation: 140 internal links, six work-item contracts, 43 Markdown
  files with zero lint issues, Rust formatting check, normalized diff check,
  and credential-shaped literal scan all passed.

The byte validator used only checked-in payloads, envelopes, signatures, and
public keys plus a temporary BLAKE3 derive-key executable under `%TEMP%`. It
verified existing bytes; no private signing material was serialized or needed.

## Falsification and residuals

Independent falsification found no candidate-preservation blocker beyond
P-0002. It specifically forced closure of public-versus-audit error taxonomy,
historical-key versus current-binding evaluation, Agent-only operating-subject
evidence, direct-only issuer/administrator rules, sorted set-like arrays,
root-transition signer ordering, canonical base64, exact semantic idempotency,
and hidden-Delegation disclosure.

Confidence is high (`0.94`) that no additional P-0003 candidate blocker remains.
Confidence is moderate (`0.70`) that P-0002 will leave the current
`DelegationV2` resource dimensions unchanged, because that question is
deliberately unresolved.

Accepted candidate residuals:

- same-UID or private-Workspace processes remain inside Human/admin trust;
- valid-prefix rollback or a hidden fork requires an independently pinned
  authority head to detect;
- predecessor-root compromise cannot be repaired by ordinary dual-signed
  rotation; a future explicit trust epoch/re-anchor is required; and
- final delegated write-resource sufficiency is unknown until P-0002 closes.

## Evidence paths

- `docs/work/evidence/P-0003/receipt.md`
- `docs/work/evidence/P-0003/manifest.json`
