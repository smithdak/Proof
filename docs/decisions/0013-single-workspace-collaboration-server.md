# ADR-0013: Begin remote collaboration with one Workspace and one server

**Status:** Accepted
**Constitutional:** No
**Date:** 2026-08-23
**Last revised:** 2026-08-26 — P-0021 extended the frozen registry with the ratified bounded reads and intent v2; originally accepted by project owner `smithdak` at `2026-08-23T17:48:11.461Z`

## Context

Milestone 2 completed the bounded local Linux path from a Human-owned resource
intent through authenticated Agent work, approval, Release, portable evidence,
and independent verification. Its accepted residuals are explicit: local Unix
identity is not remote Human identity, approval evidence lacks an exact
authority causal head, exported Environment evidence omits creation chronology,
and a supplied authority checkpoint does not prove that a Release is globally
latest or its Environment's immediate predecessor.

The Milestone 3 roadmap names HTTP, PostgreSQL, OIDC, collaborative review,
policy administration, an outbox, SDKs, a console, and preview delivery. Those
names do not decide which layer owns identity and workflow, which facts are
authoritative, how PostgreSQL reproduces the accepted SQLite behavior, or how
an immutable artifact and an external delivery compose without a distributed
transaction. Implementing those pieces independently would let adapters invent
authority and make a remote result weaker than the accepted local application
contract.

Proof therefore needs one decision-complete remote slice before selecting
frameworks or providers. The slice must support multiple Human Principals, one
operating Agent, distinct review and publication roles, private preview, and
portable verification while remaining a single-Workspace system.

## Decision

Adopt the [single-Workspace collaboration-server
contract](../architecture/collaboration-server.md) and its frozen
[`conformance/v1/collaboration-server/`](../../conformance/v1/collaboration-server/README.md)
profiles as the Milestone 3 server boundary.

### Topology and dependency direction

- Run one modular-monolith server deployment for exactly one configured
  Workspace. Multiple Principals may collaborate in it; request input cannot
  select another Workspace. Multi-Workspace tenancy remains a later decision.
- Reuse the accepted domain and application contracts. HTTP, OIDC, PostgreSQL,
  object storage, keys, outbox workers, and preview are adapters and gain no
  direct mutation or authorization privilege.
- Keep authoritative identity, authority, content, review, configuration,
  Release, Proof, idempotency, and outbox state in one PostgreSQL transactional
  boundary. No service or broker is authoritative merely because it received a
  message.
- Keep key roles distinct: OIDC client/session secrets, Agent command
  credentials, Workspace authority keys, and Release-signing keys are not
  interchangeable. Private key material never enters application commands,
  public Problems, artifacts, or portable bundles.
- Freeze the Human role vocabulary to exactly `authority.admin`,
  `content.publisher`, `content.requester`, `content.reviewer`,
  `environment.activator`, `environment.admin`, `evidence.auditor`, and
  `identity.admin`. OIDC claims grant none of them; active signed Workspace role
  assignments do.

### Human and Agent authentication

- Use a same-origin confidential backend-for-frontend for Human browser
  authentication. It performs OIDC Authorization Code flow with PKCE S256,
  one-use `state` and `nonce`, an exact redirect URI, and the exact public,
  secret-free `OidcIssuerConfigurationV1` loaded from trusted deployment
  configuration. That configuration pins the issuer, client ID, accepted
  discovery-metadata digest, authorization/token/JWKS endpoints, algorithms,
  redirect URI, and no-redirect deployment egress policy. Its digest context is
  `proof:oidc-issuer-configuration:v1`, and accepted discovery metadata uses
  `proof:oidc-discovery-metadata:v1`. Token exchange uses exactly
  `client_secret_basic`; the configuration holds only a
  `deployment-secret:...` client-credential reference, never the secret.
- Validate the provider signature under an algorithm allowlist and validate
  exact `iss`, nonempty `sub`, `aud`, `azp` where required, `exp`, `iat`, and
  `nbf` when present with at most 30 seconds of clock skew. Email, display name,
  groups, roles, and request fields never select a Principal.
  The subject is compared as the exact decoded JSON string without case folding
  or Unicode normalization.
- A public commitment-only `OidcPrincipalBindingV1` is an immutable signed
  authority payload mapping one subject commitment and pinned issuer-config
  digest to one Principal. Outside transient protected request processing,
  exact raw `{iss, sub}` and the opening persist only in matching protected
  `OidcPrincipalBindingPrivateV1` lookup state, which also names the public
  binding-record digest and is excluded from ordinary logs, Problems,
  ContextPacks, exports, and public evidence. There is no
  just-in-time Principal creation. For `oidc-binding.issue/v1`, the
  `identity.admin` caller supplies the protected issuer/subject but cannot
  supply the blind, commitment, or opening: the server generates a fresh
  32-byte random blind and commitment before the transaction and stabilizes
  them across internal retries of that application attempt. The commitment
  context is `proof:oidc-authenticated-subject-commitment:v1`. Disablement and
  replacement are causal authority facts rather than an in-place
  reinterpretation of identity.
- Keep provider tokens server-side. The browser receives only an opaque random
  256-bit session identifier whose stored value is hashed, using the cookie
  `__Host-Http-Proof-Session` with `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, and no `Domain`. A session has a 900-second idle limit, an
  28,800-second absolute limit, and never outlives upstream token validity.
  Rotate it at login or reauthentication and revoke it at logout, binding
  disablement, or Principal disablement. The first profile retains no refresh
  token and requires a new OIDC login after the Proof session expires. Binding,
  Principal, and role state are checked again for every operation.
- Binding revocation or Principal disablement fails current authentication as
  uniform 401 `proof.auth.denied` before idempotency lookup or prior-result
  disclosure and appends no authority record. With the session, bindings, and
  Principals still authentication-valid, loss of a required role, Delegation,
  or current authority is a 403 `proof.authorization.denied` whose signed
  remote denial decision and catalog reference commit.
- State-changing browser requests require JSON, an exact same-origin `Origin`,
  and the current session-bound synchronizer in `Proof-CSRF`. An authenticated
  same-origin `GET /api/v1/session` returns that independent random 256-bit
  base64url value with Principal/session timestamps in a `private, no-store`
  projection. The server stores only its digest, rotates it at login or
  reauthentication, and invalidates it with the session; it is not a bearer
  credential, authority fact, or idempotency key. CORS is disabled by default.
- A remote Human operation derives
  `AuthenticatedActorContextV2` under
  `proof.server/authentication/oidc-human/v1`. An Agent operation derives the
  same requesting Human and additionally verifies the existing single-use,
  exact-operation Agent presentation under
  `proof.server/authentication/oidc-human-agent/v1`. The OIDC session does not
  authenticate the Agent, and an Agent signature does not authenticate or
  choose the requesting Human.
- Protected `AuthenticatedActorContextV2` carries the raw requesting subject
  only across the application identity port. Ordinary persisted/exported actor
  evidence is the commitment-only `AuthenticatedActorContextEvidenceV2`,
  digested under `proof:authenticated-actor-context-evidence:v2`; it binds the
  public binding-record digest, issuer-config digest, Principal, subject
  commitment, authentication event, operation, independently derived public
  operation-input-projection digest, and authority position. Only the protected
  actor context retains the distinct exact normalized-input digest.
  `RemoteAuthorizationDecisionV1` repeats that binding-record digest. Public
  commitment-level verification does not require the protected lookup;
  optional openings are separately authorized caller-controlled audit input.
  `RemoteAuthenticationEventV1` uses
  `proof:remote-authentication-event:v1`; all decoded remote authority payloads
  (including the public binding) and their signed envelopes use
  `proof:remote-authority-record:v1` and
  `proof:remote-authority-record-envelope:v1`, respectively.
- Every operation-registry row carries one exact effect-digest rule, including
  `none` on non-consequence routes. For a successful Human authority mutation,
  the decision, governed authority fact, and application consequence occupy
  three consecutive causal positions in that order; the consequence names the
  intervening effect head. Its registry row also selects the exact persisted
  effect timestamp member used for ordering. Other consequences extend their
  decision directly and use no effect timestamp field.
- Unknown, mismatched, disabled, or unauthorized issuer/subject/binding and a
  pre-proof invalid Agent signature all return the same public 401
  `proof.auth.denied`. RFC 9457 `application/problem+json` responses contain no
  raw subject, token, provider claim, binding existence, Principal status,
  hidden selector, policy internal, or resource-existence oracle. A 403 with
  disclosure-safe authorization detail is permitted only after the Principal
  is authenticated and disclosure policy allows it.

### Versioned HTTP application adapter

- Freeze exactly nine routes. The four transport-session routes are
  `GET /auth/oidc/login`, `GET /auth/oidc/callback`,
  `GET /api/v1/session`, and `POST /api/v1/session/logout`; they are not
  capability operations and cannot mutate application, authority, or content
  evidence. Login and callback accept no request media or application CSRF and
  succeed only by 303 redirect. Session GET is an authenticated no-write 200
  JSON `private, no-store` projection and the CSRF acquisition route. Logout is
  a 200 JSON operation requiring the active Human session or its bounded
  revocation tombstone, exact Origin, and matching session-bound `Proof-CSRF`.
  It always expires the HttpOnly cookie and converges to `logged_out:true` for
  exact replay/already-revoked state without an application key or prior-result
  disclosure. The five other
  routes are `GET /api/v1/capabilities`,
  `POST /api/v1/human/operations/{name}/{major}`,
  `POST /api/v1/agent/operations/{name}/{major}`,
  `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}`,
  and
  `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}`.
- Freeze 26 ordered Human RPC rows, including keyed `evidence.export/v2` and
  no-key `evidence.export.get/v1`, `object.list/v1`, `schema.get/v1`, and
  `schema.list/v1`, and 43 operation rows in total. These rows do
  not add routes; the HTTP surface remains exactly nine routes.
- Expose Human commands at
  `POST /api/v1/human/operations/{name}/{major}` and Agent commands at
  `POST /api/v1/agent/operations/{name}/{major}`. The path carries the terminal
  `vN` token and the body carries the full operation-version identifier. The
  latter route requires both the
  Human BFF context and the Agent presentation.
- Resolve `{name, version}` through a closed, capability-discoverable operation
  registry. Capability discovery embeds that exact registry and its
  RFC 8785/SHA-256 commitment. Every Human row freezes a versioned
  authorization rule and exact any-of role set in addition to the existing or
  explicitly versioned application operation, normalized input Schema, result
  Schema, route-plus-row stable Problem set, idempotency class, concurrency
  preconditions, authority projection, limits, and evidence consequence. An
  unknown or disabled row fails before dispatch.
- Bind each signed remote decision and consequence to both the non-circular
  authorization-projection hash and the complete operation-registry hash. The
  former covers actions, rules, roles, resources, and Agent direct-policy
  mapping; the latter also covers routes, Schemas, idempotency, Problems,
  limits, results, and exact effect-digest rules. Every Agent row separately
  freezes its disclosure-neutral accepted-error projection and exact post-Allow
  `application_problem_codes`; an absent authz-only, transport, idempotency, or
  infrastructure code cannot become an application-failure consequence.
  Resolving the signed full registry hash must yield a registry whose embedded
  authorization hash equals the decision's signed authorization hash; separate
  allowlist membership cannot validate a mismatched pair.
- `RemoteApplicationConsequenceV1` copies the exact decision, full registry
  hash, operation, public input projection, typed application-key kind/value,
  and causal head. Success and replay use `proof:operation-effect:v1` over the
  exact result. Conflict/application-failure outcomes use the same domain over
  RFC 8785 of exactly
  `{api_version:"proof.dev/application-problem-digest-preimage/v1",code,operation}`;
  HTTP presentation and private diagnostics are excluded. The selected row's
  exact effect-digest rule determines whether success binds an authority fact,
  localized effect, content intent, evidence capture, delivery-management
  fact, or null.
- HTTP bounds and parses input and projects application results; it does not
  implement an HTTP-only mutation, cached authority, workflow convention, or
  transport-specific result. Correlation and causation identifiers propagate
  across the transaction and any later delivery.
- Human session identity and Agent identity are adapter-derived values. Any
  Principal, Delegation, Workspace, or role named by untrusted input is only an
  expected-value cross-check after derivation.

### Authoritative review, approval, and configuration

- Introduce one immutable causal approval fact over the exact sealed ChangeSet,
  validation, submission, and Environment-configuration digests. That approval
  is the authoritative review attestation and binds the approver's exact
  subject commitment, context, binding and role, and the immediate authority
  head. A separate “viewed” fact is not workflow authority.
- The approver is an enabled Human with the exact `content.reviewer` role,
  distinct from the requesting Human, operating Agent, and publisher.
  Comments, assignment, page visits, UI state, and token claims are not review
  or approval authority.
- `EnvironmentCreationV1`, `EnvironmentConfigProposalV1`, and
  `EnvironmentConfigActivationV1` are separate immutable decoded
  `RemoteAuthorityRecordV1` payloads persisted in their signed envelopes. The
  proposer has the exact `environment.admin` role; the different activator has
  the exact `environment.activator` role. Proposal and activation bind their
  immediate authority heads, exact predecessor, normalized transition, role
  assignments, and times. Disablement is versioned and cannot rewrite a
  configuration used by an earlier Release.
- `EnvironmentConfigV2` is an immutable assembled closure, not another
  authority payload or mutable row. It embeds the exact creation, proposal, and
  activation payloads plus each payload and envelope digest, and cross-checks
  Workspace/Environment identities, chronology, predecessor, proposal digest,
  copied creation fields, and distinct actors. Its
  `environment_config_digest` and `normalized_configuration_digest` both
  commit the complete normalized configuration under
  `proof:environment-config:v2`. These versioned facts close the corresponding
  P-0006 chronology gaps prospectively; they do not fabricate missing history
  for old artifacts.
- Release creation rechecks current identity, role, approval, configuration,
  policy, base state, and Environment pointer inside its authoritative
  transaction. Prior review or approval is necessary evidence, not a promise
  that a later commit will succeed.

### PostgreSQL transaction and recovery boundary

- Execute every authoritative mutation as `SERIALIZABLE READ WRITE`. Lock one
  durable Workspace write-head row before reading protected state and allocate
  causal sequences from its locked values rather than PostgreSQL sequences.
  This intentionally preserves SQLite's one-writer observable behavior for the
  first server slice.
- Fresh current authentication and authorization precede idempotency lookup or
  disclosure. One transaction covers presentation consumption, authority
  decision, authoritative facts, `RemoteApplicationConsequenceV1` records, successful
  application idempotency, immutable Proof/catalog references, required
  projections, outbox enqueue, and all affected heads.
- A malformed or unproven credential, actor mismatch, or replay writes no new
  authority record. After credential proof, an authorization denial consumes
  an Agent presentation when present and appends the versioned signed remote
  decision body and catalog reference, but writes no application consequence,
  successful application key, or outbox event. For a keyed row, same-key
  equivalent input appends and catalogs the attempt's signed Allow decision and
  replay record; changed input appends and catalogs the signed Allow decision
  and failure consequence. Neither duplicates the prior governed effect. A
  no-key row skips stored-result lookup and executes as a distinct authorized
  attempt.
- Preserve the local savepoint rule: an authorized application failure rolls
  back governed mutation but may commit its consumed presentation, signed
  decision and failure-consequence bodies, and their catalog references. It
  does not reserve the successful application key or enqueue a governed effect.
  Infrastructure or integrity failure rolls back the complete transaction and
  commits none of those records.
- Retry the complete transaction on PostgreSQL serialization failure and, when
  classified as transient, deadlock. Reuse the normalized input, candidate
  identities, correlation, semantic time, and application key only for a keyed
  row; a no-key row does not invent one. Discard every
  attempt-produced reference, signature, and result from an aborted attempt;
  only an authority-neutral unreachable staging orphan may remain. The first profile uses
  already-loaded process-local authority and Release signing keys; network
  KMS/HSM calls while the Workspace transaction is open are deferred. Retries
  are bounded. An uncertain commit first returns retryable 504
  `proof.operation.unknown_outcome` only when the server cannot determine the
  outcome; that response asserts neither commit nor rollback. Reconciliation
  for a keyed row is a separate attempt through the original application key
  with equivalent input. An Agent uses a fresh presentation before any prior
  result is disclosed. A no-key row has no stored-result replay promise: any
  safe retry is a fresh authenticated and authorized attempt that may append
  distinct evidence and observe newer state. OIDC ambiguity abandons or
  expires the one-use login state and begins a fresh login; logout converges
  through its bounded revocation tombstone and cookie expiry, not an
  application key.
- Use logged tables and durable commit settings for authoritative, idempotency,
  artifact-catalog, outbox, attempt, and receipt state. No response, message,
  artifact reference, or delivery becomes visible before commit.
- Persistent migrations are immutable and checksummed. A distinct migration
  role performs expand, backfill, verify, cutover, and contract phases; request
  handling never auto-migrates. Projection rebuild derives a shadow generation
  from verified authoritative facts under the Workspace write lock and swaps
  one active-generation pointer atomically. Facts, idempotency, artifacts, and
  outbox history are never treated as rebuildable projections.

### Immutable artifacts and delivery

- Store canonical artifacts privately at their existing domain-separated
  content address. The storage port performs conditional create and exact
  read-after-write digest and length verification; an existing different value
  is an integrity failure.
- Pre-stage only authority-neutral content bytes known from an exact optimistic
  snapshot, then recheck every state, authority head, and candidate sequence
  used to construct them. Store every fork-capable signed authority, decision,
  consequence, approval, configuration, Release Proof, and checkpoint byte
  atomically in a logged PostgreSQL artifact-body row. Mirror those bytes only
  from a committed outbox event. Thus an abort may leave a neutral unreachable
  orphan but cannot leave a valid signed successor or fork in external storage.
- Insert one immutable logical outbox event for each committed external effect
  in the same authoritative transaction. Stable event and delivery identities,
  transaction sequence plus ordinal, stream order, versioned payload digest,
  destination configuration, and correlation are durable.
- Workers claim only the lowest nonterminal event of each eligible stream, with
  at most one live lease per stream. They record append-only attempts, retry
  with bounded backoff, compare-and-set acknowledgement using the lease token
  and generation, preserve semantic stream order, and dead-letter poison
  messages. The exact delivery states are `pending`, `in-flight`, `delivered`,
  `dead-letter`, and `abandoned`; `attempts_in_generation` counts only claims in
  the current generation while older attempts remain immutable history.
- Replay by `environment.admin` or abandonment by `environment.activator`
  appends a `DeliveryManagementFactV1`, an immutable application fact digested
  under `proof:delivery-management-fact:v1`, not a
  `RemoteAuthorityRecordV1` payload. The signed
  `RemoteAuthorizationDecisionV1` authorizes it, and the successful signed
  `RemoteApplicationConsequenceV1.application_effect_digest` binds its exact
  digest. Replay preserves event/delivery/payload identities, increments the
  generation, resets its bounded attempt window, and returns `pending`;
  abandonment preserves the current generation and returns terminal
  `abandoned`.
- Delivery is explicitly **at least once**. A target may apply an effect before
  the worker records its acknowledgement, so a retry can repeat delivery.
  Stable delivery identity and target-side idempotency make state converge but
  do not create an exactly-once transport or external-effect claim. At-most-once
  delivery is also rejected because it can silently lose a committed effect.

### Evidence and private preview

- Define P8 as an exact uncompressed logical member map, not an archive or
  compressed carrier. Its six roots are the remote Release-artifact closure,
  remote authority record set, public actor evidence, remote authentication
  event, `CommandInputV1`, and authenticated-command DSSE envelope. The
  verifier decodes `AuthenticatedCommandV1` from that envelope; no standalone
  payload root exists. The Release closure enumerates nested artifacts. An
  included root is producer-addressable, while an external-required authority,
  actor, or authentication root is supplied only through caller input.
- Keep P6 `AuthorityEvidenceBundleV1` and its verifier unchanged for historical
  local evidence. It is not embedded, relabeled, or executed as a P8 remote
  authority root. The P8 verifier consumes the full caller-anchored suffix of
  authority facts needed to reconstruct its selected attempt; there is no
  implicit producer database/network lookup or authenticated base-state
  snapshot.
- Independent verification receives one exact caller-obtained
  `VerificationTrustPolicyV2` with usable role-separated authority, Release,
  and historically selected Agent public-key bytes, accepted policy profiles,
  accepted authorization/full-operation-registry hashes, bounded limits, and a
  closed offline hash-to-canonical-registry resolver. Exact typed checkpoints,
  authorized subject openings, and external-artifact descriptors/bytes cross
  the same separate caller boundary. First-profile producer hint arrays are
  exactly empty, with `trusted:false` and `auto_fetch:false`; a key ID,
  allowlist, URL, bundle field, or valid signature cannot establish trust.
  Unsafe or duplicate paths, wrong-kind digest aliases, descriptor
  substitution, and contradictory caller bytes are Invalid.
- The server and verifier continue to distinguish cryptographic validity,
  authority validity, policy validity, content validity, and evidence
  completeness. Missing required disclosure remains Incomplete. A checkpoint
  bounds the supplied authority prefix; it does not prove a globally latest
  Release or the true immediate same-Environment history.
- The first delivery target is a private `preview` Environment. A committed
  Release enqueues a versioned request naming its exact Release, Edition,
  Proof, configuration, and artifact digests. Delivery never resolves ambient
  current content. A content-addressed complete-snapshot manifest/ready marker
  is written last; reads and the alias resolve only ready manifests. The target
  advances monotonically by Release sequence and a duplicate exact delivery is
  a no-op.
- Authoritative Release success and preview delivery are separate states.
  `pending`, `in-flight`, `delivered`, `dead-letter`, and `abandoned` delivery
  remain observable; delivery failure neither rewrites Release history nor
  causes an implicit rollback. Preview access is private and authenticated; it
  is not public release.
- `evidence.export/v2` commits one immutable capture and always returns the
  exact keyed `EvidenceExportResultV2` with `status:pending`; same-key replay
  never changes those result bytes. Build runs deterministically from that
  capture, and a second transaction verifies bytes before pending-to-ready.
  The separate no-key `evidence.export.get/v1` observes the mutable producer
  status. Ready status publishes reserved bundle/manifest digests and exact
  included-member counts; the kind-and-digest artifact route acquires those
  entries, included roots, and nested artifacts.
- Export ID, snapshot label and heads, membership capture, manifest, assembly,
  and readiness are unauthenticated producer metadata. Contradictory repeated
  values fail, but Complete makes no authenticated capture, readiness,
  current-at-snapshot, immediate-predecessor, or globally latest claim.
- `RemoteVerificationReportV2` is the general closed observed runtime outcome
  for Complete, missing-material Incomplete, and integrity or semantic Invalid.
  `conformanceReport` is the exact three-scenario qualification subtype. The
  retained P8 scenarios are unobserved normative requirements, and the
  retained decoded decision and `RemoteApplicationConsequenceV1` payloads are
  signable candidates, not a matching signed pair or execution observation.

## Consequences

- The smallest server keeps the accepted local semantics and adds remote
  identity, collaboration, persistence, and delivery without granting adapters
  a second authority model.
- Browser tokens and provider claims stay out of JavaScript and portable
  evidence, but the BFF becomes a sensitive session and CSRF boundary requiring
  strict same-origin operation and revocation checks.
- Human and Agent attribution remain independent and falsifiable. Agent
  operation now requires both authenticated actors, increasing request setup
  but preventing either credential from impersonating the other.
- Review, approval, and configuration administration require new versioned
  facts and explicit separation of duties. A console may project them but
  cannot define them.
- A single locked Workspace write lane and serializable retries favor
  correctness and parity over maximum write concurrency. Reads, immutable
  artifact access, and independent outbox streams can still proceed in
  parallel.
- Private artifact staging avoids a distributed commit at the cost of bounded
  unreachable orphans. The initial slice makes no garbage-collection or
  retention-deletion claim.
- Release commit can succeed while preview delivery remains `pending` or
  `in-flight`, or later becomes `dead-letter` or `abandoned`. Clients must
  present Release and delivery states separately rather than calling both
  operations “published.”
- A server-produced evidence bundle remains untrusted until evaluated against
  independent caller inputs. Running the producer remotely does not strengthen
  freshness or latest-history claims by itself.
- This decision authorized no implementation successor, provider
  provisioning, deployment, or production mutation before project-owner
  acceptance. Acceptance promoted only the first dependency-ordered successor,
  P-0009 remote actor and shared-contract conformance; later successors are
  created in the accepted order as their blockers close.

## Explicit nonclaims

- No multi-Workspace tenancy, cross-Workspace transaction, tenant row-level
  security, SCIM/federation, workload identity, SPIFFE, or Delegation chaining.
- No browser SPA bearer-token model, public API CORS profile, third-party cookie
  embedding, or public preview.
- No HTTP, PostgreSQL, object-store, OIDC-provider, key-provider, renderer,
  worker, SDK, console, or hosting-framework implementation is selected here.
- No exactly-once delivery, synchronous preview, immediate Release delivery,
  globally latest Release, or true immediate-Release proof.
- No high availability, backup/restore, disaster recovery, multi-region
  ordering, managed KMS/HSM custody, production SLO, or public release.
- No retroactive completion of unavailable pre-v14 presentations,
  direct-Human v2 companion evidence, or historical chronology.

## Alternatives considered

### Split collaboration, authority, content, and delivery services first

This is the strongest rejected decomposition. Independent identity/review,
content, evidence, and delivery services with a broker can scale and isolate
failure domains separately. In the first slice they would replace one accepted
atomic boundary with distributed consistency: presentation consumption,
revocation, idempotency, governed facts, Proof references, and message enqueue
could disagree or require a new cross-service protocol. There is no measured
load or ownership boundary that justifies that cost. Keep explicit ports and
outbox events so later extraction remains possible.

Pivot to a new decomposition ADR only when measured Workspace write-lock
contention, independent scaling or security isolation, failure-domain
requirements, team ownership, or an accepted availability objective cannot be
met by the modular monolith without weakening this transaction contract.

### Browser-held OIDC access tokens

A pure SPA or direct bearer API removes the BFF session. It exposes bearer
credentials to browser JavaScript and makes CSRF/CORS, revocation, token
audience, and public-client storage part of every operation. Rejected for the
same-origin first slice; reconsider only if a demonstrated third-party client
cannot use the BFF and receives a separate OAuth resource-server ADR.

### UI-defined review and mutable configuration

Treating page inspection, comments, role claims, or a mutable Environment row
as workflow would be simpler. It cannot prove which bytes were inspected or
which authority and configuration applied. Rejected in favor of causal,
digest-bound immutable facts.

### Fine-grained `READ COMMITTED` transactions

Per-aggregate locks can increase concurrency. They are easier to apply
inconsistently across authority, content, idempotency, projection, and Release
heads and do not directly reproduce local one-writer behavior. Reconsider only
after conformance traces and contention measurements justify an explicit
partitioning contract.

### Synchronous delivery inside the Release transaction

Calling preview or making an artifact externally reachable while holding the
database transaction would appear immediate but cannot atomically roll back a
successful remote effect and extends critical locks across an unreliable
network. Rejected in favor of neutral pre-staging, atomic PostgreSQL storage for
fork-capable signed bytes, and an at-least-once transactional outbox.

### Trust producer-supplied keys and checkpoints

This makes a bundle self-verifying only by letting the producer choose the
trust used to accept its own claims. Rejected. The first profile fixes every
producer hint array empty, and caller trust stays a separate input.

## Verification

- The decision candidate qualifies frozen collaboration-server Schemas,
  registries, retained decision-candidate valid-shape/cryptographic fixtures,
  and a structurally
  validated non-executable rejection requirements matrix. Each rejection ID
  must later map one-to-one to a retained executable server test; documentation
  does not count as runtime evidence.
- Future shared SQLite/PostgreSQL adapter traces must cover accepted and rejected
  operations, state conflicts, idempotent replay, revocation races, failure
  savepoints, serializable retries, uncertain commits, migrations, projection
  rebuild, and identical authoritative results.
- Future crash tests must interrupt artifact preparation, every authoritative transaction
  boundary, outbox claim/send/acknowledgement, lease expiry, retry, poison
  handling, replay, and preview application. No consumer may observe an event
  before its authoritative commit.
- Future security tests must cover OIDC mix-up and claim substitution, session fixation and
  expiry, CSRF, token replay, invalid Agent proof, disclosure oracles, artifact
  substitution, SSRF, target conflicts, and database/operator tamper.
- Future preview tests must prove exact-Release reads, monotonic application, duplicate
  no-op behavior, no ambient-current substitution, and visible divergence
  between Release and delivery state.
- Future independent verification must run without producer credentials or database state
  and receives caller trust/checkpoint inputs separately from the exported
  bundle.
