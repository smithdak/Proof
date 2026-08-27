# Proposed single-Workspace collaboration-server conformance profile

Status: **P-0008 decision candidate; not implemented or owner-ratified**.

This package freezes the machine-readable boundary for the smallest remote
single-Workspace Proof topology. It does not create a server, PostgreSQL
schema, OIDC connection, browser console, worker, preview renderer, provider
resource, deployment, or public release.

Only metadata from an explicitly configured trusted proxy may affect origin,
scheme, host, client address, or certificate context. A protected request that
arrives from an untrusted peer with authority-affecting `Forwarded`,
`X-Forwarded-*`, `Host`, or conflicting trusted-proxy values is rejected before
actor derivation as uniform 401 `proof.auth.denied`; such values are not merely
accepted and ignored.

The accepted local authority contracts under `conformance/v1/authority/`
remain byte-for-byte and semantically unchanged. In particular,
`AuthenticatedSubjectV1` remains closed to `os/unix` and
`proof/local-ed25519`, and `AuthenticatedActorContextV1` remains the local
Unix Human/Agent profile. Remote operation uses explicit successor types.

## Normative files

- `schemas/remote-auth-v1.schema.json` defines pinned OIDC configuration,
  protected issuer/subject lookup and commitment openings, public-safe binding
  and actor evidence, and `AuthenticatedActorContextV2` for direct Human and
  dual Human/Agent requests.
- `schemas/http-envelope-v1.schema.json` defines strict Human and Agent HTTP
  request envelopes, stable success envelopes, streamed-artifact metadata,
  preview results, and RFC 9457 Problems.
- `schemas/application-operations-v1.schema.json` defines strict proposed
  input/result contracts for new v1/v2/v3 application and transport rows;
  accepted localized-content v2 Schemas are referenced directly where they
  already exist.
- `schemas/collaboration-artifacts-v1.schema.json` defines the persisted signed
  remote-authority envelope, its closed decoded-payload union, and the
  assembled `EnvironmentConfigV2` projection.
- `schemas/http-operation-registry-v1.schema.json` defines the closed route,
  operation, authentication, idempotency, concurrency, Problem, and limit
  registry.
- `schemas/storage-transaction-v1.schema.json` and
  `schemas/artifact-catalog-v1.schema.json` define the serialized authoritative
  transaction and immutable artifact-catalog decision contracts.
- `schemas/outbox-delivery-v1.schema.json` and
  `schemas/preview-delivery-v1.schema.json` define transactional outbox,
  at-least-once delivery, poison management, and private exact-Release preview
  decision contracts.
- `schemas/migration-rebuild-v1.schema.json` defines the migration ledger and
  projection-rebuild decision contract.
- `schemas/remote-evidence-v2.schema.json` defines the future runtime export,
  trust, and verifier types plus an explicitly unmaterialized
  Complete/Incomplete/Invalid decision-contract suite.
- `schemas/remote-authority-dsse-vector-v1.schema.json` freezes the positive
  Ed25519 DSSE byte vector.
- `schemas/storage-delivery-contract-manifest-v1.schema.json` freezes the
  storage/delivery contract inventory and qualification claims.
- `schemas/rejected-case-manifest-v1.schema.json` defines the closed shape of
  the non-executable falsification-requirements matrix.

The current retained inventory contains 39 JSON vectors. Fixture suffixes and
profiles are normative qualifications, not informal labels:

- `vectors/*.valid.json` are retained decision-candidate contract instances for
  this proposed profile. Retention does not claim owner acceptance, a server implementation, or
  runtime qualification; a fixture carrying an explicit `status` or
  `runtime_qualified` field retains that narrower claim.
- `authenticated-actor-context-v2.*.valid.json` is adapter-private runtime
  context and contains the exact raw OIDC subject by design. Its public-safe
  projection is the corresponding
  `authenticated-actor-context-evidence-v2.*.valid.json` fixture.
- `oidc-principal-binding.valid.json` is the commitment-only signed authority
  payload. `oidc-principal-binding.private-test.json` and the two
  `oidc-subject-commitment*.private-test.json` fixtures are protected test-only
  lookup/opening material; they are forbidden from ordinary exports,
  ContextPacks, Problems, and logs.
- `changeset-get-input.private-test.json` and
  `release-create-input.private-test.json` are protected exact normalized-input
  digest preimages. `release-create-result.private-test.json` is the paired
  protected exact server-result/effect preimage. They validate against the
  retained localized-content v2 operation input or result Schema, are excluded
  from public actor evidence and ordinary evidence exports, and are forbidden
  from ContextPacks, Problems, and logs.
- `remote-authority-record.dsse-bytes.valid.json` is a positive canonical-byte,
  PAE, digest, public-key, and signature vector whose profile status remains
  `proposed`; it is not evidence that a deployment key exists.
- `remote-evidence-v2.valid.json` retains an unmaterialized normative suite,
  six independently exact component-vector references, and three conditional
  successor scenarios. It is not a manifest, archive, verifier input, report,
  or claim that exact bundle bytes or runtime observations exist.
- The retained Rust harness recomputes the subject commitment, issuer config,
  public binding, authentication event, public actor evidence, decision,
  consequence, role/approval/revocation, normalized configuration, and
  creation/proposal/activation payload links. Other digest-shaped scenario
  values are schema-valid type/shape examples only. In particular, the three
  `EnvironmentConfigV2` `*_record_envelope_digest` values are syntactic
  placeholders because this package supplies no matching signed envelopes for
  those three records; no cryptographic qualification is claimed for them.
- The retained Agent Allow and successful `release.create/v2`
  `RemoteApplicationConsequenceV1` are exact decoded, canonicalizable, signable
  candidate payloads. They have no retained matching DSSE envelopes and
  therefore are not a signed decision/consequence pair or execution observation. Human payloads,
  denials, replay and idempotency/precondition conflicts, and application
  failures remain successor runtime-vector requirements. P-0008 freezes their
  closed Schemas, registry tables, semantic mutation checks, and rejection
  rows; it does not claim those branches executed.
- `vectors/rejected-cases.json` is structurally validated against
  `rejected-case-manifest-v1.schema.json`, but is non-executable. Every row
  reserves one `future_test_id` and MUST later map 1:1 to one retained
  executable test; its presence does not claim that test is implemented or
  passing. The current closed matrix has 158 rows: 88 HTTP-applicable rows with
  282 exact route/operation bindings and 70 explicitly non-HTTP rows.

Every defined contract object rejects unknown properties. The generic HTTP
`input` and success `data` slots are the only intentionally open objects at the
envelope stage; each is then required to validate against the exact registry
row's closed `input_schema` or `result_schema`. Arrays with set semantics
reject duplicates; order-sensitive arrays retain their frozen contract order.
Validators MUST NOT silently reorder signed input before canonicalization.
Every recomputed cross-document digest uses the repository's RFC 8785 and exact
domain-separated BLAKE3-256 context. No fixture contains an OIDC token, client
secret, browser-session secret, or private signing key. Protected
`.private-test.json` fixtures intentionally contain fixed test subject-opening
material and must never be treated as public or production credentials.

### Signed persistence and raw definitions

The root entrypoint of `collaboration-artifacts-v1.schema.json` accepts only a
persisted `RemoteAuthorityRecordV1` DSSE envelope or an assembled
`EnvironmentConfigV2` projection. Its role, binding, revocation, approval,
configuration, creation, decision, and consequence `$defs` are decoded payload
and typed result contracts. Validating one of those raw definitions never
authorizes storing it unsigned. Persistence verifies canonical decoded bytes,
the closed payload union, causal sequence and predecessor, independently
resolved active Workspace key, one Ed25519 signature, and both payload and
envelope digests before admitting the envelope.

## Topology and actor derivation

The server is one deployment for one Workspace and multiple Principals. A
same-origin confidential Backend for Frontend terminates OIDC. The client
secret is a deployment-adapter secret and is absent from request, domain, and
evidence contracts. ID and access tokens exist only during the server-side code
exchange and validation and are then discarded; no refresh token is retained.
The browser receives only an opaque application-session cookie. Neither that
cookie, the OIDC callback transaction, nor an OIDC token is a Principal, role,
Delegation, application idempotency key, or portable credential.

The exact OIDC identity key is the case-sensitive pair `(issuer, subject)`.
The nonempty subject may contain non-control Unicode and is compared as the
exact decoded JSON string, with no case folding or Unicode normalization.
Email, display name, username, tenant labels, and group claims are attributes,
never Principal identity or Proof authority. The pair is pre-bound through an
immutable `OidcPrincipalBindingV1`; unknown subjects do not create Principals.
One OIDC subject cannot be reassigned after retirement or revocation.

`AuthenticatedActorContextV2` has exactly two profiles:

1. `proof.server/authentication/oidc-human/v1` independently derives one Human
   from an active OIDC subject binding and server session.
2. `proof.server/authentication/oidc-human-agent/v1` independently derives the
   same requesting Human and additionally verifies the existing Agent
   Ed25519 binding, signed command, direct Delegation, and single-use
   presentation.

A request body, path parameter, Principal identifier, role identifier,
Delegation, Agent assertion, cookie value, or OIDC attribute MUST NOT construct
either actor. A Delegation grants authority after authentication; it never
authenticates the requesting Human. A signed expected Principal is only a
cross-check against independently derived identity.

Public context evidence replaces raw OIDC `sub` with a 32-byte-blinded hiding
commitment to the exact issuer/subject tuple. Only protected audit disclosure
may carry an opening. OIDC tokens and raw claims never enter domain artifacts,
portable public evidence, ContextPacks, Problems, or ordinary logs.

The protected actor context binds `normalized_input_digest` to the exact strict
operation input under `proof:remote-normalized-operation-input:v1`. Public
actor evidence instead binds the independently derived, operation-specific
`public_input_projection_digest` under
`proof:public-operation-input-projection:v1`. The two typed preimages and
derive-key domains are distinct; the adapter never renames or copies the
private digest into public evidence.

The adapter-private `AuthenticatedActorContextV2` crosses into the application
only through the identity port; it is never deserialized from an operation
body. Persisted/public actor evidence uses
`AuthenticatedActorContextEvidenceV2`. A `RemoteAuthenticationEventV1` records
the bounded server authentication event but is not IdP non-repudiation or a
bearer credential. Agent authentication remains the separate existing signed
command and one-use presentation proof; a live Human session is independently
required for every Agent HTTP call.

## OIDC and session profile

The first profile has one exact deployment-pinned HTTPS issuer, one client ID,
and `client_secret_basic` token-endpoint authentication. The issuer
configuration comes only from trusted deployment configuration; it is not an
administrator authority fact or HTTP operation. Caller input cannot select or
override issuer, discovery/JWKS/token URLs, algorithm allowlist, audience,
tenant, client credential, or redirect target.

- Authorization Code only, exact pre-registered redirect URI, PKCE `S256`,
  and transaction-specific one-use `state` and `nonce`.
- Discovery `issuer`, authorization-response issuer, and ID-token `iss` equal
  the configured issuer by exact string comparison.
- The adapter verifies an explicitly configured signing-algorithm allowlist,
  signature and key, nonempty `sub`, `aud`, `azp` when required, `exp`, `iat`,
  optional `nbf`, and exact `nonce` before creating a session.
- Clock skew is at most 30 seconds.
- The application session is a uniformly random opaque 256-bit identifier,
  stored server-side only as a digest. It rotates at login or
  reauthentication.
- Cookie profile: `__Host-Http-Proof-Session`, `Secure`, `HttpOnly`,
  `SameSite=Strict`, `Path=/`, and no `Domain`.
- Idle lifetime is 900 seconds and absolute lifetime is 28,800 seconds, never
  beyond upstream credential validity.
- Every operation re-resolves the immutable subject binding and current
  Principal, role, and authority state. A session authenticates a subject; it
  does not cache authority.
- Logout, session expiry, binding revocation, or Principal disablement ends
  further use. Provider-side revocation is bounded by session lifetime unless
  an independently authenticated provider signal is configured later.

Logout retains a bounded revocation tombstone for the opaque session handle
and the digest of its exact session-bound CSRF value. An exact replay or an
already-revoked handle converges to 200 `logged_out: true` and always expires
the `__Host-Http-Proof-Session` cookie. The tombstone is transport state, not
an application idempotency key, and reveals no prior application outcome.

Binding revocation or Principal disablement fails current authentication as
uniform 401 `proof.auth.denied` before idempotency lookup or stored-result
disclosure and appends no authority record. With both identities still valid,
loss of a required role, Delegation, or current authority is instead a 403
authorization denial whose signed remote decision is durably cataloged.

Unsafe cookie-authenticated API requests require an exact allowed `Origin`, a
session-bound synchronizer value in `Proof-CSRF`, and `application/json`.
CORS is disabled. Any later CORS profile must use explicit origins, never
credentialed wildcard or reflected/null origins. Login callback validation of
`state`, issuer, nonce, and PKCE is separate from application CSRF validation.
If a login or callback response is lost while the OIDC transaction outcome is
unknown, the bounded transaction is abandoned or allowed to expire and the
browser begins a fresh login. OIDC state and session convergence never use an
application idempotency key or disclose an earlier callback outcome.

Before identity or Agent proof is established, invalid token/signature and
unknown issuer, subject, key, or binding all return public
`proof.auth.denied`. Protected diagnostics may distinguish them. After proof,
specific current-state denial is disclosed only when it cannot reveal a
hidden Principal, Delegation, role, or resource.

## HTTP and application mapping

The closed registry has exactly nine routes: four transport/session routes and
five application/data routes. Transport/session routes never appear as
capability operations or invoke an application mutation.

| Class | Route ID | Method and path | Authentication / CSRF | Exact boundary |
| --- | --- | --- | --- | --- |
| Transport/session | `oidc-login` | `GET /auth/oidc/login` | public / none | Start the deployment-pinned transaction; accept no Workspace, issuer, redirect, or Principal selector. |
| Transport/session | `oidc-callback` | `GET /auth/oidc/callback` | one-use OIDC transaction / none | Validate and consume the exact callback transaction. |
| Transport/session | `session-get` | `GET /api/v1/session` | OIDC Human / none | Return only the current bounded session projection. |
| Transport/session | `session-logout` | `POST /api/v1/session/logout` | active OIDC Human, or exact bounded revocation-tombstone replay / exact Origin plus session-bound `Proof-CSRF` | Revoke only the ephemeral session and converge an exact replay to `logged_out: true`. |
| Application/data | `public-capabilities` | `GET /api/v1/capabilities` | public / none | Return the exact committed registry plus its RFC 8785/SHA-256 commitment, without Workspace/resource inventory. |
| Application/data | `human-operations` | `POST /api/v1/human/operations/{name}/{major}` | OIDC Human / exact Origin plus session-bound `Proof-CSRF` | Invoke exactly one registered Human application operation. |
| Application/data | `agent-operations` | `POST /api/v1/agent/operations/{name}/{major}` | OIDC Human plus Agent invocation / exact Origin plus session-bound `Proof-CSRF` | Invoke exactly one registered Agent pair with an exact `AuthenticatedInvocationV1`. |
| Application/data | `evidence-export-artifact` | `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}` | reauthorized OIDC Human / none | Stream only the exact kind-and-digest member of the committed export; the same digest text under another kind is not an alias. |
| Application/data | `preview-release-rendition` | `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}` | OIDC Human / none | Return the private immutable exact-Release, exact-locale rendition. |

The route name/version and envelope operation are duplicate cross-checks.
Mismatch, an unsupported pair, or the wrong authentication route fails before
application execution. Agent evidence-writing reads stay on `POST`: consuming
a presentation and appending an authorization decision is not an HTTP-safe
`GET`, even when governed content is unchanged.

The Human route is the exact ordered 26-row set frozen by the registry,
including `delivery.get/v1`, `delivery.replay/v1`, `delivery.abandon/v1`, and
the no-key `evidence.export.get/v1`, `object.list/v1`, `schema.get/v1`, and
`schema.list/v1` reads; `prefixItems` plus `items: false` rejects reordering,
omission, duplication, and additions. With the public capability row and 16
Agent/data rows, the registry contains 43
operation rows in total. Every row names resolvable absolute input and result
Schema references. Replay and abandon append immutable application management
facts; neither fact is a `RemoteAuthorityRecordV1` or extends the closed
remote-authority payload union.
`delivery.get/v1` exposes exactly `pending`, `in-flight`, `delivered`,
`dead-letter`, or `abandoned`, plus `attempts_in_generation`; replay and
abandonment outcomes do not introduce another public delivery-state spelling.

Every public or Human application row also freezes one versioned
`authorization_rule` and its exact `roles_any_of`. A nonempty list means the
current enabled Human MUST hold at least one named role at the transaction's
authority head; satisfying a role does not bypass the rule's resource,
ownership, lifecycle, or separation-of-duties predicate. The only empty list
is public capability discovery. ChangeSet closure reads are limited to
`content.requester`, `content.reviewer`, or `content.publisher`; Release and
preview reads additionally allow `evidence.auditor`; evidence export and
artifact reads allow only `content.publisher` or `evidence.auditor`.

`capabilities.discover/v1` embeds the complete registry object in its strict
result. The accompanying `registry_sha256` is SHA-256 over RFC 8785 canonical
bytes of that embedded value and is frozen here as
`6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`.
The result therefore needs no undisclosed file path or additional HTTP route
to resolve the advertised operation, Schema, authorization, Problem, and
limit rows. It still contains no Workspace, Principal, resource, or deployment
inventory.

The Agent route projects all 14 accepted operation/version pairs through the
exact accepted authority registry file whose SHA-256 is
`b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`.
Each HTTP row preserves `requested_action`, `localized_contract`,
`application_idempotency`, `closure_anchor`, `resource_projection_profile`,
`budget_projection`, `selector_projection`, `consequence`, and `availability`
without reinterpretation. Every Agent row also freezes its exact post-Allow
`application_problem_codes`; the 11 localized v2 rows use the complete
`LocalizedOperationFailureV1` set, while the three retained v1 rows preserve
their distinct accepted sets. These are source-contract outcomes, so the
legacy `context.build/v1` set deliberately includes `proof.auth.denied` and
`proof.delegation.expired`; a code prefix does not reclassify an error that the
accepted application commits after Allow. Authorization-only, transport, and
infrastructure failures absent from a row are forbidden as
application-failure consequences. The HTTP registry does not define a second
authority model. Human and administrative additions name explicit application
contracts; there is no SQL-only or UI-only mutation.

The non-circular authorization commitment is
`d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`:
SHA-256 over RFC 8785 of exactly the Agent authorization projection, resource
projection, rule definitions, and Human authorization projection. The Human
projection binds each operation to its requested action, rule, and sorted role
set. The Agent projection binds each operation to the accepted direct-policy
row and its exact eight `AuthorizationDecisionV2.requested_resources` arrays;
the accepted authority-registry commitment remains separately fixed.
Resolving a decision's signed full operation-registry SHA-256 MUST produce a
registry whose embedded `authorization_registry_sha256` equals that same
decision's signed authorization-registry SHA-256. Independent allowlisting of
two hashes never permits a mismatched pair.

For a Human row, the selected rule resolves only the binding descriptors listed
for that exact operation. Each public-safe typed value is committed as RFC 8785
`{api_version:"proof.dev/authorization-resource-binding/v1",name,value}` under
`proof:authorization-resource-binding:v1`; the outer requested-resource
preimage contains the authorization-registry hash, exact rule, operation,
requested action, and UTF-8-name-sorted `{name,value_digest}` entries under
`proof:requested-authorization-resources:v1`. OIDC issuance commits only the
blinded subject commitment and issuer-configuration digest, never raw issuer or
subject. Agent direct authorization uses the exact eight canonical arrays from
the accepted `AuthorizationDecisionV2.requested_resources` object without
coarsening.

The decision's `policy_bundle_digest` is
`proof:remote-authorization-policy-selection:v1` over RFC 8785 of the
authorization-registry hash, rule, and nullable exact Environment-config and
Environment-policy digests. Both Environment fields are null for a
non-Environment rule; an Environment rule resolves both from the same exact
`EnvironmentConfigV2`. Human decisions bind the active role facts used by the
server rule. Agent decisions use an empty outer role-fact list and carry the
accepted direct authorization, Delegation, binding, requested resources,
constraints, and local policy digest in `agent_authorization`.

Operation requests are strict I-JSON with duplicate names rejected; both the
raw HTTP body and its RFC 8785 canonical form are independently no larger than
1,048,576 bytes. Human HTTP bytes need not already be canonical, while signed
Agent payload bytes must be. Existing Agent bounds remain 4,096 canonical
signed payload bytes, 16,384
envelope bytes, 300 seconds maximum command lifetime, and 100 exact target or
Edit items. Ordinary structured responses, portable manifests, and individual
portable artifacts are each bounded at 4,194,304 bytes; one included export is
bounded at 268,435,456 bytes and 4,096 artifacts; an authority prefix is
bounded at 512 records. Application work has a 30-second deadline, excluding
the streamed export download. Exact closure reads are not paginated. A later
list operation must use a separately versioned application contract, an opaque
snapshot-bound cursor, stable order, default 50, and maximum 100 items; offset
pagination is not part of this profile.

Every typed `request_limits` or `result_limits` entry names an exact RFC 6901
path in that row's input or result Schema and an exact cardinality measure. An
empty list means no additional registry item quota beyond the closed Schema
and canonical-byte ceilings; it does not assert that unbounded values are safe.
The retained localized v2 Schemas still leave ContextPack policy arrays,
ChangeSet diff findings/effective edits, commit renditions, and Edition manifest
arrays without item maxima. P-0008 preserves those accepted Schemas and records
their hardening as successor work rather than advertising fictional caps.
Likewise, the authoritative `context.build/v1` input allows `task_id` through
256 UTF-8 bytes and `intent` through 4,096, while the retained verifier still
enforces legacy 128/500 limits. No server/verifier parity is claimed until a
successor accepts 129/256 and 501/4,096 boundaries and rejects 257/4,097.

A Human envelope carries the deployment Workspace UUID and a nullable
top-level application idempotency key as duplicate cross-checks. Validation is
mandatory in two stages: first the strict envelope, then the exact registry
row's `input_schema`; the Workspace and idempotency values must equal the
normalized input/derived context. A success likewise carries a committed or
immutable `result_anchor`, names the exact row `result_schema`, and validates
`data` against that Schema before serialization.

Application idempotency stays in normalized application input and, for an
Agent, the signed command. An HTTP idempotency header cannot create or replace
it. If accepted by a future adapter, such a header is only an equality
cross-check. For a keyed row, a Human retry keeps the same application key and
equivalent input; an Agent additionally uses a fresh single-use presentation.
Current authentication and authorization always precede stored-result
disclosure. A no-key read has no stored-result replay promise: a retry is a
fresh authenticated and authorized attempt that may append distinct evidence
and observe newer state. `null` is never treated as an idempotency key.

`RemoteApplicationConsequenceV1` copies the exact decision, Workspace,
operation, full operation-registry SHA-256, public input-projection digest,
evaluated head, and the row's typed `application_key_kind` plus nullable
`application_key`. Its success/replay result digest uses the accepted
`proof:operation-effect:v1` preimage over the exact result. Failure outcomes
use that same domain over the closed RFC 8785 preimage
`{api_version:"proof.dev/application-problem-digest-preimage/v1",code,operation}`;
no RFC 9457 presentation or private diagnostic field participates. A
successful Human authority
mutation binds its exact signed `proof:remote-authority-record:v1` payload;
content-intent, evidence-export, and delivery-management rows bind their exact
content-intent, capture, or management-fact digest; evidence-only reads have a
null application effect. Success, replay, idempotency conflict, precondition
conflict, and application failure have distinct required/null result, prior
result, effect, and Problem fields. A 504 on a no-key row remains internally
audit-reconcilable but gives the caller no stored-result lookup: any permitted
retry is a fresh authenticated/authorized attempt and may append new evidence.

Every one of the 43 registry rows carries one closed
`effect_digest_rule`. `none` requires a null effect; otherwise the rule names
the BLAKE3-256 derive-key/RFC 8785 algorithm, exact domain, exact typed preimage
construction, and resolvable source contract. It also fixes
`effect_timestamp_field`: null for non-authority effects and the exact persisted
timestamp member for each authority-record effect, so causal time ordering is
reconstructible without guessing a payload field. Retained `context.build/v1`
hashes the already strict-parsed, byte-for-byte RFC 8785 `manifest_json` bytes
under `proof:context-pack:v1`, not the JSON string wrapper or full result.
Localized validation hashes the exact `ValidationResultsV2` artifact, Release
creation hashes the exact `ReleaseV2` manifest, and the other effect-producing
localized rows use their accepted exact operation-effect wrapper. Read-only
rows use `none`; a coarse consequence label cannot invent an effect digest.
An effect rule does not by itself make a transport, public, or data-projection
row consequence-eligible. For a successful authority-record mutation, the
decision occupies head + 1, the governed authority payload occupies + 2, and
the signed application consequence occupies + 3 while naming that intervening
effect head. All other consequences extend the signed decision directly.

Application exact baselines, artifact digests, expected Release pointers,
authority heads, and configuration predecessors remain the concurrency
contract. `ETag` or `If-Match` may duplicate an existing exact digest but can
never be the sole application precondition or silently reinterpret a local
operation version.

Each attempt has a server-assigned UUIDv7 `operation_id`; an optional caller
UUIDv7 `correlation_id` is propagated but is never authority. Completed
failures use `application/problem+json` and RFC 9457 fields plus stable Proof
extensions. The machine-readable `code`, not `title` or `detail`, is primary.
Problems never carry token material, raw OIDC subject, hidden selectors,
policy internals, SQL, or stack traces.

Each of the exact nine routes names its own closed Problem profile, separating
bodyless GET, JSON POST, OIDC callback, Human-session, and Human-plus-Agent
presentation failures. A transport/session route emits exactly its route
profile. The final Problem set for an application/data operation is exactly
the union of its route profile, transaction profile, and either the Human
row's `application_problem_codes`, or both the Agent row's exact
disclosure-neutral projection of its accepted authenticated errors and its
exact post-Allow `application_problem_codes`.
`problem_definitions` freezes each code's status, RFC 9457 type, title, and
retryability tuple, while `problem_statuses` is an exact redundant status
cross-check; adapters cannot translate a shared application failure to a new
transport-specific code. Problem `detail`, findings, and digest extensions
still require semantic disclosure authorization and redaction. The registry
contains exactly 44 canonical HTTP presentation tuples; their human-readable mirror is the
[P-0008 HTTP Problem registry](../../../docs/reference/errors.md#p-0008-http-problem-registry).
An unresolved commit outcome is retryable 504
`proof.operation.unknown_outcome`, not 503 `proof.dependency.unavailable`, and
asserts neither commit nor rollback. A named preview whose delivery-readiness
marker is absent uses retryable 503 `proof.dependency.unavailable`.

## Review, approval, and separation of duties

Reading a ChangeSet, diff, or validation result and then recording one exact
approval is sufficient. A separate claim that a person cognitively “viewed” a
screen is neither falsifiable nor authoritative. Comments, labels, assignment,
presence, and UI review state cannot satisfy a gate.

`ChangeSetApprovalV1` is a Workspace-authority-signed causal record for the new
`changeset.approve/v3` operation. It binds the exact approver subject
commitment, binding, actor context, reviewer role assignment, submitted and
sealed ChangeSet, validation head, resource intent, ContextPack, active
Environment configuration, and immediate prior authority head. Server time
and sequence are authoritative; caller time cannot backdate it.

For the north star:

- requesting Human, operating Agent, and reviewer/approver are distinct
  Principals;
- approver is an enabled Human with an active `content.reviewer` assignment;
- publisher differs from approver; the retained north star uses the operating
  Agent as publisher under the requesting Human's current direct Delegation;
- any bound proposal, validation, submission, intent, ContextPack, or
  Environment-config mismatch denies approval or publication;
- later Principal disablement does not rewrite an earlier valid fact; approval
  revocation, if required later, needs a new causal record and operation.

OIDC claims and provider groups never confer reviewer, publisher, auditor, or
administrator authority. `WorkspaceRoleAssignmentV1` is a closed,
append-only, Workspace-signed role fact and is rechecked at the transaction's
causal authority head.

The first profile has exactly eight Human-only roles. An Agent may receive a
Delegation for registered content work but can never hold one of these roles.

| Role | Bounded responsibility |
| --- | --- |
| `authority.admin` | Issue/revoke Agent bindings and perform the accepted emergency Delegation revocation. |
| `content.publisher` | Read governed ChangeSet closure, Release, preview, and delivery state and create/read authorized evidence exports; Agent publication still requires its exact Delegation. |
| `content.requester` | Issue the exact resource intent, build the first ContextPack, issue/revoke its direct bounded Agent Delegation, and read its governed ChangeSet closure, Release, and preview. |
| `content.reviewer` | Read the complete submitted closure, Release, and preview and invoke `changeset.approve/v3`. |
| `environment.activator` | Activate an exact configuration proposed by a different Human or abandon an exact poison delivery. |
| `environment.admin` | Propose Environment configuration and inspect or request replay of an exact `dead-letter` delivery. |
| `evidence.auditor` | Read Release, preview, and delivery state and create/read an authorized evidence export without publication or administrative authority. |
| `identity.admin` | Issue/revoke Human bindings and role assignments and record bounded Principal disablement. |

## Environment configuration

Configuration is two causal facts rather than direct mutable state.
`EnvironmentConfigProposalV1` binds the exact predecessor config, complete
policy/target payload, proposing administrator, active role assignment, time,
and authority head. `EnvironmentConfigActivationV1` binds that proposal,
records the next config version, immutable Environment creation chronology,
and a distinct activating administrator and role assignment.

The proposer cannot activate the proposal. Configuration activation and
Release creation are separate transactions. Every Release binds the exact
active config version/digest. Disablement is append-only and prospective: it
blocks new Releases and a mutable current-preview alias but does not erase
historical Releases, immutable Release-specific previews, or evidence.

## Preview and evidence limits

The first preview returns the strictly typed released-rendition JSON for an
immutable named preview Release. It performs no locale fallback, rendering,
arbitrary fetch, redirect, or public signed-link behavior. The response
identifies Release, Edition, and rendition digests and uses a strong digest
ETag. The initial authenticated profile is `Cache-Control: private, no-store`.
A current-Environment alias, if later added, does not prove globally latest
history.

An evidence-artifact read first validates exact export membership, kind,
length, and digest against its typed metadata contract, then streams at most
4,194,304 bytes as `application/octet-stream`; failure is
`application/problem+json`. `Content-Digest`, `Content-Length`, `Content-Type`,
`ETag`, `X-Proof-Artifact-Digest`, and `X-Proof-Artifact-Kind` are mandatory
success headers and must agree with the committed metadata and streamed bytes.

Evidence export separates one immutable keyed capture from mutable producer
readiness. `evidence.export/v2` commits `EvidenceExportCaptureV2` and always
returns the exact immutable `EvidenceExportResultV2` with `status:pending`;
same-key replay returns those same create-result bytes even after assembly.
The no-key `evidence.export.get/v1` performs fresh authentication and
authorization and returns the current `EvidenceExportStatusV1`. Pending status
has null descriptor/manifest digests and zero counts. Ready status publishes
the exact bundle-descriptor and manifest digests plus the count and total bytes
of producer-addressable included roots and nested artifacts. It never changes
the capture or keyed result.

`RemoteEvidenceBundleV2` is the canonical `bundle.json` descriptor for an
uncompressed logical member map, not tar, zip, another archive, or a compressed
carrier. The map has reserved `bundle.json` and `manifest.json` entries, then
exact included roots and deterministic nested artifact paths. Paths are
normalized UTF-8 names and entries stream in bytewise path order; absolute,
dot-segment, backslash, duplicate, missing, undeclared, length-mismatched, or
over-limit members are Invalid. The two reserved entries are retrieved as
`remote_evidence_bundle_v2` and `remote_evidence_manifest_v2`; every HTTP read
selects the exact `(artifact_kind, digest)` pair, so equal digest text under a
different kind is not an alias.

The strict `RemoteEvidenceManifestV2` is the complete
`proof:remote-evidence-manifest:v2` preimage and has exactly six root
descriptors: `release-artifact-closure`, `authority-fact`,
`remote-actor-evidence`, `remote-authentication-event`,
`remote-command-input`, and `remote-authenticated-command-envelope`. The
Release-artifact closure enumerates every nested accepted artifact and its
deterministic kind-and-digest path. An `included` root is available through the
ready export; an `external-required` authority, actor, or authentication root
is absent from the producer map and must arrive through the caller-controlled
verifier input with exact descriptor identity and bytes. The exact
authenticated command payload is decoded from and signature-checked through
the included DSSE envelope; no standalone `AuthenticatedCommandV1` payload
member is defined.

The capture and manifest both freeze
`snapshot_boundary:pre-export-attempt-locked-heads`, before this export
attempt's own decision, capture effect, and
`RemoteApplicationConsequenceV1`. Workspace, export, snapshot, captured heads,
membership plan, capture/manifest digest, assembly, and ready transition remain
unauthenticated producer metadata in this profile. Matching metadata is
cross-checked for contradiction, but a Complete report makes no authenticated
capture, readiness, current-at-snapshot, immediate-predecessor, or globally
latest claim. A later detached receipt would require a new versioned contract.

The accepted P6 `AuthorityEvidenceBundleV1` and
`proof-verifier/authority-evidence-bundle-v1` remain unchanged historical local
evidence only. They are neither a P8 root nor executed or relabeled for a
remote attempt. `proof-verifier/remote-authority/v1` instead validates the
caller-anchored P8 DSSE record suffix and selected decision/consequence. With
no producer database or network access and no authenticated base-state
snapshot, every authority fact or transition consumed to reproduce the
selected attempt must be present in that supplied suffix after the caller's
initial head. `proof-verifier/remote-evidence-v2` independently verifies that
authority closure, the Release/artifact closure, and all attempt companions
before enforcing their cross-links.

Offline verification requires the exact caller-supplied
`VerificationTrustPolicyV2`, including usable and role-separated authority,
Release, and historically selected Agent key bytes; the caller-pinned initial
remote head; accepted policy and registry selectors; bounded disclosure and
parser limits; and the closed built-in registry resolver. Optional typed
authority and Environment/Release checkpoints, required OIDC openings, and
external artifact bytes also cross the caller-controlled input boundary. The
first profile's producer `untrusted_hints` arrays are exactly empty, with
`trusted:false` and `auto_fetch:false`; no root ID, checkpoint ID, URL, or
allowlist label substitutes for bytes or trust.

`RemoteVerificationReportV2` is the general closed runtime report for every
Complete, missing-material Incomplete, and integrity or semantic Invalid
outcome. It binds exact bundle-manifest, verifier-input, trust-policy, optional
checkpoint, and execution identities and selects one primary reason with its
matching component result. `conformanceReport` is the narrower exact
three-scenario subtype: complete materialization, required OIDC opening
withheld, and deterministic `object_locale_revision_v1` byte tamper. The three
rows retained by `remote-evidence-v2.valid.json` are unobserved normative
successor scenarios, not either report type; actual report instances require
materialized bytes and real verifier executions. Delivery evidence remains
`not-requested` because this selected claim contains no outbox, delivery, or
artifact-catalog companion.

## Explicit nonclaims and pivot triggers

- No unattended Agent may call the server using Delegation as requester
  authentication. That requirement needs a new on-behalf-of or workload
  credential profile, likely sender-constrained, and a separately reviewed
  actor-context version.
- No multi-issuer, JIT provisioning, SCIM, IdP-group authority, public preview,
  approval quorum/revocation, or comment-gated workflow is defined.
- No token/session scheme proves XSS immunity, IdP availability, workload
  measurement, or safety after complete server compromise.
- No supplied bundle or preview response proves globally latest state.

## Primary standards

- OpenID Connect Core 1.0, second errata:
  <https://openid.net/specs/openid-connect-core-1_0-errata2.html>
- OpenID Connect Discovery 1.0:
  <https://openid.net/specs/openid-connect-discovery-1_0.html>
- OAuth 2.0 Security Best Current Practice, RFC 9700:
  <https://www.rfc-editor.org/rfc/rfc9700.html>
- OAuth 2.0 for Browser-Based Applications, RFC 10017:
  <https://www.rfc-editor.org/rfc/rfc10017.html>
- OAuth Authorization Server Issuer Identification, RFC 9207:
  <https://www.rfc-editor.org/rfc/rfc9207.html>
- JWT Best Current Practices, RFC 8725:
  <https://www.rfc-editor.org/rfc/rfc8725.html>
- HTTP Semantics, RFC 9110:
  <https://www.rfc-editor.org/rfc/rfc9110.html>
- Problem Details for HTTP APIs, RFC 9457:
  <https://www.rfc-editor.org/rfc/rfc9457.html>
