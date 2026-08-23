# P-0009 Engineering qualification receipt

## Outcome

Engineering qualification is supported for immutable P-0009 candidate
`3e38f30b95086162816360e68ca9917cf0d06d9b`, tree
`9e051077699917bdf5289ac1114d7875f5934d81`. The candidate implements the
remote actor and shared-contract conformance foundation in the new
`proof-remote` crate and passed the complete Linux quality gate. The item has
`review_gate: none`, so this packet makes the item eligible to move from
`review` to `done` under the work-control protocol.

This packet does not implement or claim an HTTP server, a PostgreSQL adapter,
an OIDC provider connection, an outbox worker, preview delivery, or runtime
local/server parity. Successor promotion remains blocked until this item
completes.

The machine-readable revision, command, environment, inventory, digest, and
gate data are in `manifest.json`. Criterion-level AC1-AC10 coverage is in
`traceability.md`. These evidence files were created after the immutable
candidate and are intentionally absent from its Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0009 base / claim commit | `c125ba0ee6e284c5f406be74fb1e4f19f51b543d` |
| Skeleton commit / candidate parent | `b14b22cc9bd898565f5349f0d231d684fdfd26f8` |
| Candidate | `3e38f30b95086162816360e68ca9917cf0d06d9b` |
| Candidate tree | `9e051077699917bdf5289ac1114d7875f5934d81` |
| Qualified at | `2026-08-23T19:17:42.097Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 17 paths; 8,293 insertions |
| Parent-to-candidate delta | 15 paths; 5,973 insertions; 80 deletions |
| Retained P-0009 tests | 50 Rust tests across six `proof-remote` test binaries |
| New third-party packages | 0 (sha2 0.11 and all dependencies were already pinned in `Cargo.lock`) |
| Frozen conformance vectors changed | 0 |

## Qualified implementation boundary

### Remote authority records

`RemoteAuthorityRecordV1` is the closed serde-untagged union over the fifteen
accepted variants — four reused local artifacts (`PrincipalBindingV1`,
`PrincipalBindingRevocationV1`, `DelegationV2`, `DelegationRevocationV1`) and
eleven remote successors (OIDC binding issue/revoke, Workspace role
assignment/revocation, principal status v2, causal ChangeSet approval,
Environment creation/proposal/activation, remote authorization decision, and
remote application consequence). Every variant round-trips strict RFC 8785
canonical bytes and digests under `proof:remote-authority-record:v1`. The
envelope is a one-signature Ed25519 DSSE record with payload type
`application/vnd.proof.remote-authority-record.v1+json`, DSSE PAE, the
65,536-byte payload and 98,304-byte envelope maxima enforced before parsing,
and an envelope digest context of `proof:remote-authority-record-envelope:v1`.
Verification accepts only the caller-resolved active Workspace authority key;
the unsigned `keyid` is compared only after signature verification and never
selects trust. `validate_chain` enforces strictly increasing sequences,
predecessor linkage, head coherence, and a single active signer across the
prefix.

### Identity, commitments, and redaction

The OIDC subject commitment machinery generates a uniformly random 32-byte
blind, encodes it base64url-without-padding, commits the exact
`proof.dev/oidc-subject-commitment-input/v1` preimage under
`proof:oidc-authenticated-subject-commitment:v1`, and validates protected
openings. `OidcIssuerConfigurationV1` pins the issuer/endpoints/redirect/
algorithms under `proof:oidc-issuer-configuration:v1` with discovery metadata
under `proof:oidc-discovery-metadata:v1`. `AuthenticatedActorContextV2`
(protected) and `AuthenticatedActorContextEvidenceV2` (public) implement both
closed profiles; the protected context retains the exact normalized-input
digest under `proof:remote-normalized-operation-input:v1` while the public
evidence carries only the operation-specific projection under
`proof:public-operation-input-projection:v1` and structurally lacks any raw
issuer/subject, token, opening, or protected-input field.

### Governance closures

`ChangeSetApprovalV1` binds its complete closure and
`validate_prohibited_approvers` rejects the Agent approver, disabled or
unbound Human, ChangeSet requester, contributing Agent, active configuration
activator, incomplete or stale closure, changed validation head, and inactive
role with a distinct typed outcome. Environment creation, proposal, and
activation assemble into `EnvironmentConfigV2`, whose validation enforces
Workspace/Environment agreement, chronology, expected predecessor, proposal
and creation digest equality, copied creation-field fidelity, and distinct
proposer/activator, with both configuration digests under
`proof:environment-config:v2`.

### Registries and consequences

The closed registries implement the ordered 23-row Human set, the 14-pair
Agent projection, and the nine-route HTTP surface with route-qualified
lookup. The three frozen SHA-256 commitments recompute byte-exactly from the
retained registry vectors and fail closed on mismatch:
`b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`,
`e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b`, and
`e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf`.
`RemoteAuthorizationDecisionV1` and `RemoteApplicationConsequenceV1`
implement the requested-resources, policy-selection, operation-effect, and
application-problem digest preimages with per-row effect timestamp field
selection and the closed consequence-outcome classification across success,
replay, idempotency conflict, precondition conflict, and application failure.

### Deterministic oracle

`RemoteSemanticOracle` runs the shared operations against the SQLite-backed
`proof-local` path and produces `OracleTraceV1` traces binding the
normalized-input digest, evaluated authority head, typed result or stable
Problem outcome, and consequence digest. Repeated execution produces
byte-identical traces; deterministic identity fixtures carry fixed issuer,
enrollment, and binding values with no live provider or network.

## Conformance and falsification result

The retained frozen collaboration-server Schemas and vectors are unchanged;
the retained P-0008 harness in
`crates/proof-local/tests/p0008_collaboration_contract.rs` still passes
unmodified. The registry recomputation, chain validation, redaction, closure
cross-check, and oracle determinism tests reject concrete tamper and
substitution mutations. The complete gate is the candidate's workspace
aggregate.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 664 passed across 44 suites; 0 failed |
| `cargo test --locked -p proof-remote --all-targets` | 50 passed; 0 failed |
| `cargo test --locked --doc --workspace --all-features` | Seven doc-test suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 320 internal documentation links passed |
| `node scripts/check-work-items.mjs` | Nine work items passed metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts at the committed candidate tree |
| `git diff --check` | Passed |

The work-item validator was re-executed against the committed candidate tree
with the uncommitted successor item parked, because the parked P-0010 item
intentionally has no work-map row until promotion.

## Residual risks and nonclaims

- P-0009 qualifies the remote actor and shared-contract conformance
  foundation only. No HTTP listener, session store, CSRF, or BFF exists; no
  PostgreSQL connection, migration, or adapter exists; no OIDC provider was
  contacted; no outbox worker, lease, or delivery state exists.
- The oracle's shared-operation traces run over the SQLite reference path
  only. Local/server trace parity requires the P-0010 PostgreSQL foundation
  and is not claimed here.
- The retained decision and consequence vectors remain signable decoded
  payloads; no matching remote runtime pair or server observation is claimed.
- The frozen registry hashes and retained vectors were not changed; a future
  registry semantic change requires a new versioned profile, not a hash edit.
- No successor promotion, provider choice, deployment, or production mutation
  is claimed by this packet.

## Disposition

Engineering recommends moving P-0009 from `review` to `done` under
`review_gate: none` after the complete Linux gate recorded above, then
promoting the accepted contract's second successor, P-0010 PostgreSQL parity
foundation, to `ready`. This receipt does not execute that disposition.

Evidence paths:

- `docs/work/evidence/P-0009/receipt.md`
- `docs/work/evidence/P-0009/manifest.json`
- `docs/work/evidence/P-0009/traceability.md`
