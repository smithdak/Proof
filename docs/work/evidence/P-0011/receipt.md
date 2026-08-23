# P-0011 Engineering qualification receipt

## Outcome

Engineering qualification is supported for immutable P-0011 candidate
`ed6a06eb9710ab98792e11f5b7a42d56d2832e65`, tree
`e1f4fe9cc4e1e18ab7386f8437a95175ceb436c5`. The candidate implements the
HTTP and OIDC server boundary in the new `proof-server` crate plus the
additive session-boundary migration in `proof-pg`, and passed the complete
Linux quality gate including live-PostgreSQL tests. The item has
`review_gate: none`, so this packet makes the item eligible to move from
`review` to `done` under the work-control protocol.

This packet does not implement or claim a live OIDC provider connection, an
outbox worker, preview materialization, evidence export, deployment, or
production operation. Successor promotion remains blocked until this item
completes.

The machine-readable revision, command, environment, inventory, digest, and
gate data are in `manifest.json`. Criterion-level AC1-AC10 coverage is in
`traceability.md`. These evidence files were created after the immutable
candidate and are intentionally absent from its Git-blob inventory.

## Revision and inventory

| Field | Exact value |
| --- | --- |
| Branch | `proof-architecture/p-0008-collaboration-server-contract` |
| P-0011 base / claim commit | `3780aa5dd524cd3ef9276381bd7d4f35ca6699eb` |
| Skeleton commit / candidate parent | `5248ea2ee43643933fc057dbf6bb3fbca7eece85` |
| Candidate | `ed6a06eb9710ab98792e11f5b7a42d56d2832e65` |
| Candidate tree | `e1f4fe9cc4e1e18ab7386f8437a95175ceb436c5` |
| Qualified at | `2026-08-23T23:18:18.331Z` |
| Base-to-candidate commits | 2 |
| Base-to-candidate inventory | 19 paths; 10,059 insertions |
| Parent-to-candidate delta | 14 paths; 7,279 insertions; 144 deletions |
| Retained P-0011 tests | 74 Rust tests across seven `proof-server` test binaries |
| PostgreSQL under test | 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) |
| New third-party packages | axum 0.8.9, cookie 0.18.2, http 1.5.0, http-body 1.1.0, http-body-util 0.1.5, hyper-util 0.1.20, mime 0.3.17, tower 0.5.3, tower-http 0.6.11, direct tokio 1.53.1 |
| Frozen conformance vectors changed | 0 |

## Qualified implementation boundary

### Routes and strict input

`router` exposes the exact nine routes with their methods and paths and a
404 fallback emitting the route-specific Problem profile. The raw-body limit
layer rejects request bodies over 1,048,576 bytes with 413
`proof.input.too_large` before parsing; the canonical-request guard parses
strict I-JSON (via `proof_canonical::parse_strict`), rejects duplicate and
unknown JSON names, enforces the JSON content type with 415, and
independently rejects RFC 8785 canonical bytes over 1,048,576 bytes. The
Origin guard requires an exact same-origin `Origin` on unsafe authenticated
requests and the CSRF guard requires the session-bound `Proof-CSRF` value.
Session responses carry `Cache-Control: private, no-store`.

### OIDC BFF and deterministic issuer

`DeterministicIssuer` signs Ed25519 ID tokens (no RSA), issues single-use
authorization codes, and exchanges them under `client_secret_basic` against
the `deployment-secret:` reference. The BFF completes Authorization Code
plus PKCE `S256` with one-use `state` and `nonce`, one exact preregistered
redirect URI, the RFC 9207 authorization-response issuer check, exact
discovery-metadata issuer equality, and ID-token validation of the Ed25519
signature, exact `iss`, nonempty `sub`, `aud`, `azp` when multiple
audiences, `exp`/`iat`/optional `nbf` with the frozen 30-second skew, and an
algorithm allowlist that never accepts `none`. Subject comparison is the
exact decoded JSON string with no case folding or Unicode normalization.
Login and callback succeed only by 303; failure paths are
disclosure-neutral with no raw claims in public bodies.

### Sessions and CSRF

`SessionStore` persists only keyed hashes of random 256-bit opaque
identifiers in the proof-pg session-boundary migration, enforces 15-minute
idle and 8-hour absolute limits, rotates on login/reauthentication,
re-resolves per call, and tombstones revocations; logout converges to
`logged_out: true` for exact replay and already-revoked handles without an
application key or prior-result disclosure. Cookies carry the exact
`__Host-` names and flags (`Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, no `Domain`; `SameSite=Lax` only for the callback transaction
cookie). The CSRF synchronizer stores only its digest, rotates with the
session, and is invalidated by logout; the session projection contains no
raw OIDC claims.

### Dual authentication, authorization, and operations

The Agent route requires a currently valid requesting-Human session plus a
fresh single-use `AuthenticatedCommandV1` verified against the pre-bound
Agent key; neither credential substitutes for the other, and
request-carried Principal/Delegation/Workspace identifiers are mismatch
guards only. Per-row authorization rules and sorted `roles_any_of` sets
evaluate at the current authority head. The owned Human rows and the 14
Agent rows execute through one P-0010 unit of work, committing the signed
`RemoteAuthorizationDecisionV1`, the governed fact, and the
`RemoteApplicationConsequenceV1` with the per-row effect digest and
timestamp field; failed authentication returns 401 before idempotency
lookup; proven denial returns 403 with a signed denial decision. The
evidence-export, delivery, and preview rows return the stable
`proof.dependency.unavailable` Problem until their successors implement
them.

### Dispatch, Problems, and limits

The dispatch cross-check requires exact agreement among path terminal
version, body operation, invocation operation, signed operation, capability
row, input Schema, and authority registry row before execution. The Problem
registry carries the exact 41 frozen tuples with RFC 9457 bodies whose
extension members are exactly the allowed set; 429 carries `Retry-After`,
504 is the retryable `proof.operation.unknown_outcome`, and no public body
contains raw claims, subjects, tokens, or SQL. The rate limiter is an
adapter denial control; the 30-second deadline and 4,194,304-byte response
bound are enforced as contract limits.

## Conformance and falsification result

The retained frozen collaboration-server Schemas and vectors are unchanged;
the retained P-0008 harness, all P-0009 `proof-remote` tests, and all
P-0010 `proof-pg` tests pass unmodified. The abuse matrix exercises wrong
issuer/audience/algorithm/key/time, nonce/state reuse and fixation, PKCE
omission, open redirects, hostile Origin, missing CSRF, session expiry and
revocation convergence, idempotent replay non-duplication, and the
disclosure-neutral 401 path. An end-to-end test completes capabilities
discovery, deterministic login, CSRF acquisition, a Human read, and a
dual-auth Agent operation over live PostgreSQL.

## Exact candidate verification

| Check | Exact candidate result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed with warnings denied |
| `cargo test --locked --workspace --all-targets --all-features` | 770 passed across 59 suites; 0 failed (includes live-PostgreSQL tests) |
| `cargo test --locked --doc --workspace --all-features` | Seven doc-test suites; 0 tests; 0 failures |
| `node scripts/check-doc-links.mjs` | 334 internal documentation links passed |
| `node scripts/check-work-items.mjs` | Eleven work items passed metadata, lifecycle, dependencies, map parity, transitions, and evidence contracts |
| `git diff --check` | Passed |

## Residual risks and nonclaims

- No live OIDC provider was contacted; the deterministic issuer is retained
  test infrastructure, and the deployment-secret reference is not resolved
  against a real credential store.
- No outbox worker, lease, delivery state, preview materialization, or
  evidence export exists; the dependent routes return the stable pending
  Problem until their successors implement them.
- TLS termination and trusted-proxy configuration are deployment
  prerequisites and are not implemented or qualified here.
- Rate limits and deadlines are adapter controls; production calibration is
  deployment work.
- No successor promotion, provider choice, deployment, or production
  mutation is claimed by this packet.

## Disposition

Engineering recommends moving P-0011 from `review` to `done` under
`review_gate: none` after the complete Linux gate recorded above, then
promoting the accepted contract's fourth successor, P-0012 artifact outbox
and private preview delivery, to `ready`. This receipt does not execute that
disposition.

Evidence paths:

- `docs/work/evidence/P-0011/receipt.md`
- `docs/work/evidence/P-0011/manifest.json`
- `docs/work/evidence/P-0011/traceability.md`
