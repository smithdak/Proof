# P-0004 Engineering qualification receipt

## Outcome

Engineering qualification is supported for the bounded P-0004 candidate
`87888475829cf6f197f6b1ed4b0c0e1a9863ccf7`. The exact Git-blob inventory and
the complete command matrix are bound in `manifest.json`. An independent final
acceptance-criteria audit found no contradiction. These gates make the
candidate eligible for review; no owner disposition has been executed and the
candidate is not an accepted or published revision.

The candidate starts from accepted P-0003 base
`445f56c8737e97d7041ece2971ac755fea5fa05c` and claim commit
`ca9de58c38530fccfe16decf862fedd2cbf8f935` on branch
`proof-engineering/p-0004-authorization-kernel`. It implements the local
authenticated authorization kernel, storage migration v12, retained
conformance and falsification coverage, and CLI/MCP broker parity. It does not
enable delegated content mutation, portable authority bundles, a network
broker, or a Windows runtime-support claim.

Nothing in this packet authorizes or records a push, tag, release, deployment,
publication, production mutation, or live-provider operation.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Checkout | `D:\github\Proof` |
| Branch | `proof-engineering/p-0004-authorization-kernel` |
| Base | `445f56c8737e97d7041ece2971ac755fea5fa05c` |
| Claim commit | `ca9de58c38530fccfe16decf862fedd2cbf8f935` |
| Item-work commit | `87888475829cf6f197f6b1ed4b0c0e1a9863ccf7` |
| Qualified at | `2026-08-21T00:10:35Z` |
| Candidate-path count | 61 |
| Candidate numstat | 21,637 insertions; 768 deletions |
| Git-blob SHA-256 inventory | 61 of 61 candidate blobs bound |

The manifest derives its path list and numstat from the candidate commit and
records SHA-256 over bytes emitted from each exact Git blob. Worktree hashes
were not substituted.

No new package record was added to `Cargo.lock`. Six production direct edges
were added: `proof-application` to `base64`, `proof-application` to
`serde_json` by promotion from dev-only scope, `proof-cli` to `zeroize`,
`proof-local` to `base64` and `getrandom 0.4.3`, and `proof-mcp` to
`proof-attestation`. The `proof-cli` test target added direct edges to `base64`
and `proof-mcp`.

## Implemented boundary

The candidate implements the smallest local vertical slice ratified by P-0003:

- trusted identity adapters for the Unix bootstrap Human, local Ed25519 Agent
  proof of possession, and deterministic test identity and time;
- immutable Principal binding history, single-use enrollment, terminal
  Principal disablement, binding rotation and revocation, direct Human-to-Agent
  `DelegationV2`, and dual-signed Workspace authority-root transition;
- bounded `AuthenticatedCommandV1` verification and internal construction of
  raw-UID-free `AuthenticatedActorContextEvidenceV1` with a blinded requesting
  subject commitment;
- causally ordered, signed authority records and reconstruction of every
  security-relevant projection before authorization;
- atomic presentation consumption, `AuthorizationDecisionV2`, operation
  outcome, authority evidence, and governed consequence at the SQLite
  transaction boundary;
- exact operation-registry enforcement for 14 registered operation pairs,
  while exposing only the three current v1 reads and retaining all 11 P-0007
  localized v2 rows as disabled contracts for P-0005;
- an Agent-side signer separated from Human-owned brokers, with one bounded
  stdin invocation for `proof auth execute --invocation -` and equivalent
  modern and legacy MCP execution; and
- atomic migration of supported storage versions v1 through v11 to v12 while
  preserving historical Release verification and rebuilding ContextPack
  projections without a legacy-only Delegation foreign key.

Authenticated Agent reads are evidence writes: each fresh valid presentation
appends one consumption and one decision but does not move governed content or
content projections. ContextPack build retains application idempotency.

## Required Engineering evidence matrices

### Authentication, binding, and privacy

Retained boundary coverage is designed to establish:

- authentication-time and Binding/Delegation interval edges, including exact
  inclusive `not_before` and exclusive `expires_at` behavior;
- causal disablement and revocation precedence independent of record
  timestamps;
- one immutable Workspace history for each Agent subject and public key,
  distinct-key rotation, and rejection of historical key reuse;
- equality of authenticated subject key hex, binding public key, enrollment
  candidate, and verified signer;
- stable subject opening with no raw UID or blind in ordinary stored authority
  evidence;
- typed maximum-size Decision and Delegation envelopes and rejection above the
  configured payload limits; and
- identical public denial shape and persistence for a well-formed unknown
  binding and an invalid signature, using one canonical candidate-binding
  decode and one Ed25519 verification in either path.

The retained Windows authentication and binding suite passed 10 tests with no
failure. The Ubuntu transport-parity suite passed both denial and allow cases
against the real CLI plus modern and legacy MCP surfaces.

### Authorization, denial, and consequence matrix

The retained matrix separates pre-consumption authentication failure from
committed authorization denial. Malformed input, invalid proof, audience or
actor mismatch, command-digest mismatch, time failure, and replay must disclose
no result and add no decision or consumption. Current binding or Principal
state, direct-Delegation resolution, revocation, action, resource, and budget
denials consume once and persist one canonical denial without governed
consequence.

Successful and unsuccessful released queries persist committed allow outcomes
while leaving governed state unchanged. Workspace-global application
idempotency is checked across Agent identity and changed semantic input.
Parent references, subdelegation, chains, and cycles are rejected rather than
partially interpreted.

`proof.authorization.policy_denied` remains a portable Decision reason and
application error, but it is reserved and unreachable under the fixed
`direct/v1` local policy profile. P-0004 adds no mutable policy source that
could safely manufacture that denial. The qualification therefore must not
claim an executed policy-denial branch; current policy evaluation is the
closed direct profile. A later policy-bearing item must qualify the branch
before relying on it.

### Replay and projection integrity

The ContextPack regression uses a fresh authenticated presentation for logical
retry. Equivalent normalized input returns the exact prior result without a
second application consequence while still recording the fresh authorization
attempt. Changed input under the same application key fails.

Signed authority history is the source of truth. Retained falsification cases
delete, substitute, or mutate derived Principal, Binding, Delegation,
revocation, decision, consumption, actor-evidence, challenge, opening, and
operation-result rows. Reconstruction or cross-checking fails closed before
authorization when those projections no longer match signed history.
Additional retained cases deny an Agent across every closed Human/admin
authority surface and withhold a previously built Context result after
Delegation revocation or Principal disablement. The falsification suite passed
10 tests with no failure.

### Authority-root continuity and custody recovery

Retained continuity evidence covers predecessor-key loss, valid transition,
compromised-predecessor attacker transition, signed-record mutation and
reordering, and a valid older signed prefix evaluated against an independently
pinned later head. Ordinary dual-sign rotation proves continuity only from the
predecessor key; it is not compromise recovery.

The root transition spans SQLite and a file-backed successor signer, which
cannot be one physical atomic commit. Candidate recovery logic is exercised at
the pre-commit publication window: an injected database commit failure restores
retryable staging, and an already-published successor without the matching
database transition is rejected or resumed only through exact verified
metadata. This is bounded crash-window recovery evidence, not a power-loss,
filesystem-durability, storage-controller, or cross-device atomicity claim.

### Migration matrix

Every supported pre-candidate storage version is explicitly in scope:
v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, and v11. The target is v12.
Qualification must prove injected migration failure leaves the source version
and historical artifacts unchanged, one retry reaches stable `12/12/12`, and a
second retry is a no-op. Historical signed v10 Releases and v11 localized and
rollback artifacts must verify byte-exactly before and after migration.

The v12 migration rebuilds ContextPack tables to remove the legacy-only
Delegation foreign-key assumption. Loader and projection checks accept the
closed legacy-or-v2 Delegation relation and reject an unresolved selector.
The two focused Ubuntu migration tests passed with 126 unrelated tests filtered
out.

### CLI and MCP transport parity

The parity test uses a real local Workspace and compares the real CLI process,
modern MCP protocol, and legacy MCP protocol. Equivalent signed status input
must produce the same normalized command, authenticated actor and Delegation,
semantic Decision projection, result, and `evidence_write` classification.
Each fresh transport presentation contributes exactly one decision,
consumption, and actor-evidence record while every other governed and authority
projection remains unchanged.

The broker accepts only the bounded stdin invocation. Agent-controlled paths,
argv fields, signed values, and MCP parameters cannot select a file for the
broker to open. Ambient direct CLI remains a Human path and is not transport
parity evidence for an Agent invocation.

Both parity tests passed. Unknown-binding and invalid-signature presentations
returned the same public Problem across the real CLI, modern MCP, and legacy
MCP paths, with zero decision, consumption, actor-evidence, or governed writes.

### Falsification result

The strongest counterargument was that signed authority records could coexist
with attacker-edited unsigned projections, allowing authorization to trust a
widened Binding, Delegation, Principal status, or cached result. The candidate
therefore reconstructs and cross-checks security-relevant projections from the
signed authority log before use and retains deletion, substitution, mutation,
and reorder tests. The final falsification pass also checked complete
Human/admin-surface denial for an Agent and post-Context revocation or
disablement withholding. All 10 retained falsification tests passed.

The strongest rejected alternative was to introduce a protected network or
enterprise authority service in P-0004. That could narrow same-UID and
private-Workspace administrative trust, but it adds provider, deployment,
credential, and recovery contracts not required for this local milestone. The
Human-owned local broker and bounded stdin/MCP transports are the narrower
complete slice; deployment containment and portable bundle qualification
remain P-0006 concerns.

Confidence is high for the bounded local Engineering claim because the exact
candidate passed the complete Ubuntu gate, the focused Windows suites, strict
lint, transport parity, and an independent acceptance-criteria audit with no
contradiction. Evidence that would falsify qualification includes any
projection mutation that still authorizes, any pre-consumption write, duplicate
governed consequence, migration non-convergence, transport-specific decision
semantics, or authority-root custody state that cannot resume without silently
creating a new trust epoch.

## Verification

| Surface | Qualification state |
| --- | --- |
| P-0004 boundary suite | Windows: 10 passed, 0 failed |
| Authorization matrix | Windows: 7 passed, 0 failed |
| Falsification suite | Windows: 10 passed, 0 failed |
| Authority continuity suite | Windows: 5 passed, 0 failed |
| v1-v11 to v12 migration suite | Ubuntu: 2 passed, 0 failed, 126 filtered |
| CLI and modern/legacy MCP parity | Ubuntu: 2 passed, 0 failed |
| Complete locked Ubuntu workspace | 452 passed, 0 failed |
| Ubuntu documentation tests | 6 crate summaries, 0 doctests, 0 failures |
| Strict workspace/all-target/all-feature Clippy | Windows and Ubuntu passed with warnings denied |
| Documentation links and work control | 163 links and 7 work items passed |
| JSON and Markdown | 68 JSON files parsed; 53 Markdown files, 0 issues |
| Rust formatting, normalized diff, secret/path scan | Passed; 0 scan matches |

Windows may be used for compilation, strict lint, and focused deterministic
tests, but it is not a live identity-runtime qualification surface. The local
Human adapter is Unix-only and P-0004 makes no Windows support claim.

## Residual trust boundary and disposition

The final candidate remains bounded by these residuals:

- a process with the bootstrap UID or private Workspace access is inside the
  Human/admin trust boundary; Ed25519 proves Agent attribution and integrity,
  not containment among hostile same-UID processes;
- the file credential adapter is not KMS, OIDC, workload identity, executable
  attestation, model attestation, or a production credential service;
- a valid older signed prefix or hidden fork is internally valid unless the
  verifier holds an independently pinned later authority head;
- compromise of the predecessor authority root can authorize an attacker
  successor, so ordinary rotation is not recovery and no new epoch is silently
  established;
- SQLite and file publication have a recoverable but not physically atomic
  crash window, with no power-loss or storage-durability qualification;
- the fixed direct policy has no reachable runtime `PolicyDenied` branch;
- P-0005 delegated content mutation remains disabled; and
- P-0006 portable authority evidence and deployment containment remain absent.

Engineering qualification is complete and the candidate is eligible to move
from `claimed` to `review`. No review-to-`done` owner disposition has been
executed. The evidence does not authorize or record a remote push, tag, release,
publication, deployment, production mutation, or customer proof.

## Evidence paths

- `docs/work/evidence/P-0004/receipt.md`
- `docs/work/evidence/P-0004/manifest.json`
