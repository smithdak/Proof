---
id: P-0011
title: Implement the HTTP and OIDC server boundary
status: review
wave: now
kind: implementation
blocked_by: [P-0010]
claimed_by: deepseek:proof:p-0011
claimed_at: 2026-08-23T21:39:34.672Z
base_sha: 57c8615c0b9e05e7b408f0bd1fc4e99e176113d7
review_gate: none
accepted_by: null
accepted_at: null
---

# Implement the HTTP and OIDC server boundary

[Back to the work map](../map.md)

## Outcome

Proof has the exact nine-route HTTP server boundary from the accepted
contract: strict versioned RPC dispatch over the P-0009 registries, the
same-origin confidential OIDC Backend for Frontend with Authorization Code
plus PKCE against a deterministic in-process issuer, opaque server-side
sessions with bounded idle/absolute lifetimes and revocation, a
session-bound CSRF synchronizer, dual Human-session plus
`AuthenticatedInvocationV1` Agent authentication, exact envelope/Problem/
status mapping, request and artifact limits, bounded rate limiting, and the
identity, role, approval, and Environment configuration Human operations
implemented over the P-0010 PostgreSQL foundation. No live provider is
contacted; the deterministic issuer is retained test infrastructure.

## Why now

P-0009 fixed the remote actor contracts and registries and P-0010 fixed the
durable PostgreSQL unit of work. The accepted contract names this item as
the third dependency-ordered successor. The HTTP boundary is where remote
identity, sessions, CSRF, and dual authentication become executable; the
artifact/outbox/preview successor and the remote evidence successor consume
this surface.

## Promotion condition

Satisfied by completed P-0010 candidate
`4410b46a27687fd8ce04d01d2c872f1ca2ac4ccc`, bound by its Engineering
evidence, per the accepted [collaboration-server
contract](../../architecture/collaboration-server.md) successor order.
ADR-0013 remains the implementation authority.

## Authorized scope

- Create a `proof-server` workspace crate. Selected baseline: axum over
  tokio (both already in the dependency graph; the sync `postgres` driver is
  invoked behind `tokio::task::spawn_blocking` or an equivalent bounded
  blocking executor — the async runtime never blocks on storage). The choice
  is recorded here as the implementation baseline, not a portable contract.
- Implement the exact nine-route surface:
  `GET /api/v1/capabilities` (`capabilities.discover/v1`),
  `POST /api/v1/human/operations/{name}/{major}`,
  `POST /api/v1/agent/operations/{name}/{major}`,
  `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}`,
  `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}`,
  plus the four transport-session routes
  `GET /auth/oidc/login`, `GET /auth/oidc/callback`,
  `GET /api/v1/session`, and `POST /api/v1/session/logout`.
  Unknown routes, versions, and members fail closed with the route-specific
  Problem profiles from the accepted error registry.
- Implement strict request parsing: raw body and RFC 8785 canonical request
  both bounded to 1,048,576 bytes independently (413
  `proof.input.too_large`), I-JSON values only, duplicate and unknown JSON
  names rejected, `Content-Type: application/json` required for operation
  requests, unsupported media 415.
- Implement route-qualified registry dispatch using the P-0009 registries:
  path terminal `vN` token plus body operation-version identifier must agree
  with the invocation, signed operation, capability row, input Schema, and
  authority registry; a mismatch fails before application execution.
  Success envelopes carry operation/version, server UUIDv7 `operation_id`,
  optional validated caller UUIDv7 `correlation_id`, and the committed
  result anchor. No response is returned from an attempt whose transaction
  did not commit.
- Implement the same-origin confidential BFF over a deterministic
  in-process issuer: public `OidcIssuerConfigurationV1` from trusted
  deployment configuration (digest contexts
  `proof:oidc-issuer-configuration:v1` and
  `proof:oidc-discovery-metadata:v1`); Authorization Code flow with PKCE
  `S256`, one-use `state` and `nonce`, one exact preregistered redirect URI,
  RFC 9207 authorization-response `iss` check, exact discovery-metadata
  issuer equality, TLS-and-algorithm allowlist (never `none`), signature
  verification with keys obtained only from the configured issuer, exact
  `iss`/nonempty `sub`/`aud`/`azp` validation, `exp`/`iat`/optional `nbf`
  with a frozen 30-second skew; `client_secret_basic` exchange with only a
  `deployment-secret:...` credential reference; no redirect, no request-
  selected issuer/Workspace/Principal/redirect; login and callback succeed
  only by 303; egress-allowlist policy documented for the real provider.
- Implement opaque server-side sessions: random 256-bit identifier, only a
  keyed hash stored, cookie `__Host-Http-Proof-Session` with `Secure`,
  `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; 15-minute idle and
  8-hour absolute limits never exceeding upstream token validity; rotation
  on login or reauthentication; every application call re-resolves the
  immutable binding, current Principal status, role/Delegation, and
  authority head; logout retains a bounded revocation tombstone for the
  opaque handle and its session-bound CSRF digest, always expires the
  cookie, and converges to 200 `logged_out: true` for exact replay without
  an application idempotency key or prior-result disclosure. OIDC
  login/callback ambiguity abandons or expires the one-use transaction and
  starts a fresh login.
- Implement the CSRF synchronizer: authenticated same-origin
  `GET /api/v1/session` is the only acquisition route, returns a
  `private, no-store` 200 projection with Principal and bounded session
  timestamps plus an independent uniform random 256-bit base64url
  synchronizer; the server stores only its digest bound to the session,
  rotates it on login/reauthentication, invalidates it with logout; unsafe
  cookie-authenticated requests require exact same-origin `Origin`, JSON
  content type, the current `Proof-CSRF` value, and the current session
  cookie. CORS is disabled. The OIDC callback uses a separate short-lived
  one-use transaction handle cookie `Secure`, `HttpOnly`,
  `Path=/auth/oidc/callback`, `SameSite=Lax`; the strict application cookie
  is never relaxed.
- Implement dual authentication for the Agent route: a currently valid
  requesting-Human session plus a fresh single-use `AuthenticatedCommandV1`
  verified against the pre-bound Agent key; the P-0009
  `AuthenticatedActorContextV2` profiles (`oidc-human/v1`,
  `oidc-human-agent/v1`) derive the actor; request-carried Principal,
  Delegation, and Workspace identifiers are mismatch guards only; a
  Delegation never authenticates either actor.
- Implement the remote decision and consequence persistence through the
  P-0010 unit of work for the operations this item owns: `capabilities.discover/v1`
  (public no-key read), the 14 Agent rows (dispatch over the shared
  application operations), and the Human rows
  `oidc-binding.issue/v1`, `oidc-binding.revoke/v1`,
  `workspace-role.assign/v1`, `workspace-role.revoke/v1`,
  `principal.status.set/v2`, `content-resource-intent.issue/v1`,
  `context.build/v2`, `changeset.get/v2`, `changeset.diff/v2`,
  `changeset.approve/v3`, `delegation.issue/v2`, `delegation.revoke/v1`,
  `release.get/v2`, and `release.verify/v2`. Each mutation commits the
  signed `RemoteAuthorizationDecisionV1`, the governed fact, and the
  `RemoteApplicationConsequenceV1` with the per-row effect digest and
  timestamp field through one P-0010 unit of work.
- Implement the row-specific stable Problem, status, and disclosure mapping
  (400/401/403/404/409/413/415/422/429/500/503/504) with disclosure-neutral
  401 `proof.auth.denied` for pre-proof identity failures and no raw
  subject, token, claim, SQL, or provider diagnostics in any public
  response. 422 carries authorized structured findings; 429 carries
  `Retry-After`; 504 is the retryable ambiguous-commit result.
- Implement bounded rate limiting as an adapter denial control (not
  authority) with exact retry semantics; application idempotency remains in
  typed input and the Agent signature — no normative HTTP `Idempotency-Key`.
- Implement the 30-second application deadline and the 4,194,304-byte
  ordinary response limit; evidence-export and preview routes return the
  stable `proof.dependency.unavailable` Problem until their successors
  implement export capture and preview materialization.
- Implement the deterministic issuer, JWKS, and discovery fixtures plus the
  abuse matrix as retained tests: wrong issuer/audience/algorithm/key/time,
  nonce/state reuse and fixation, revoked binding, Principal disablement,
  hostile `Origin`, missing CSRF, token/claim leakage, oversized bodies,
  unknown routes/versions/members, and dual-authentication failures.
- Add the P-0010 migration for session, authentication-event, CSRF-digest,
  and revocation-tombstone storage; no live provider, no deployment.

## Explicit non-goals

- No live OIDC provider, IdP account, network egress, or provider selection.
- No outbox worker, lease, delivery, preview materialization, or
  artifact-store port execution (P-0011 serves the routes and returns the
  stable pending Problem).
- No evidence export capture/assembly or remote bundle v2 (successor scope).
- No SDK, console, deployment, TLS-termination infrastructure, or public
  preview.
- No multi-issuer, just-in-time provisioning, or unattended Agent requester
  profile.
- No successor promotion: artifact/outbox/private preview and remote
  evidence qualification stay fog until this item closes.

## Applicable contracts

- [Collaboration-server contract](../../architecture/collaboration-server.md):
  HTTP boundary, remote identity vocabulary, OIDC binding and session
  boundary, Human roles and separation of duties, causal approval and
  release recheck, envelopes/Problems/HTTP semantics, and limits.
- [ADR-0013](../../decisions/0013-single-workspace-collaboration-server.md)
- [Core invariants](../../architecture/constitution.md)
- [P-0010 evidence](../evidence/P-0010/receipt.md)

## Acceptance criteria

- [x] The nine-route surface and the four transport routes dispatch exactly
      per the closed registry with route-qualified cross-checks; unknown
      routes/versions/members fail closed with the route-specific Problem
      profile.
- [x] Raw-body and canonical-request limits are enforced independently;
      malformed, duplicate-name, non-I-JSON, and oversized requests reject
      with the exact 400/413/415 Problems.
- [x] The BFF completes the Authorization Code plus PKCE flow against the
      deterministic issuer with state/nonce/iss/aud/azp/exp/skew checks and
      rejects every abuse vector in the retained matrix.
- [x] Sessions are opaque, hashed-at-rest, flagged-correctly, bounded,
      rotated, revocable, and re-resolved per call; logout converges for
      exact replay and already-revoked handles.
- [x] The CSRF synchronizer is digest-stored, session-bound, rotated, and
      required with exact `Origin` on every unsafe authenticated request;
      CORS is disabled.
- [x] The Agent route requires both a live requesting-Human session and a
      fresh single-use verified Agent presentation; neither credential can
      substitute for the other.
- [x] Every owned Human and Agent row commits its decision, governed fact,
      and consequence through one P-0010 unit of work with the exact
      per-row effect digest and timestamp field.
- [x] The status/Problem mapping matches the accepted registry, including
      disclosure-neutral 401 and the retryable 504 ambiguous-commit result;
      no public response leaks raw claims, subjects, tokens, or SQL.
- [x] Rate limiting, the 30-second deadline, and the 4,194,304-byte response
      bound behave as adapter controls and never as authority.
- [x] The full Linux quality gate passes and durable Engineering evidence
      (receipt, manifest, traceability) binds the item-work commit.

## Evidence contract

Record the qualified implementation candidate, crate/module inventory,
route/abuse matrix coverage, deterministic-issuer fixtures, gate command
results, and residual boundaries in `docs/work/evidence/P-0011/`. Produce
`receipt.md`, `manifest.json`, and a criterion-level traceability matrix.

## Completion record

Ready at `2026-08-23T21:38:31.587Z` after P-0010 candidate
`4410b46a27687fd8ce04d01d2c872f1ca2ac4ccc` closed with Engineering evidence
commit `a50fe6a6888614eccdc06b0f1c8b1e631bfb9684`.

Claimed by `deepseek:proof:p-0011` at `2026-08-23T21:39:34.672Z` from
P-0010 completion commit `57c8615c0b9e05e7b408f0bd1fc4e99e176113d7`
on `proof-architecture/p-0008-collaboration-server-contract`.

Engineering qualified immutable candidate
`ed6a06eb9710ab98792e11f5b7a42d56d2832e65`, whose parent is the skeleton
commit `5248ea2ee43643933fc057dbf6bb3fbca7eece85`, qualified at
`2026-08-23T23:18:18.331Z`. Engineering evidence commit
`cddb5355abc3ec5d228bbc511da26e8ed45be6c3` binds the
[receipt](../evidence/P-0011/receipt.md),
[manifest](../evidence/P-0011/manifest.json), and
[AC1-AC10 traceability matrix](../evidence/P-0011/traceability.md). Moved
from `claimed` to `review` at `2026-08-23T23:19:51.900Z` under
`review_gate: none`. No live provider, worker, preview, export, or
deployment work is claimed by this item.
