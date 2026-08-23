# Accepted single-Workspace collaboration-server contract

**Status:** Accepted — ratified for P-0008 by project owner `smithdak` at `2026-08-23T17:48:11.461Z`
**Profile:** `proof.server/single-workspace/v1`
**Date:** 2026-08-23

> This document is a decision contract, not an implementation claim. No server,
> PostgreSQL schema, identity-provider connection, worker, preview host, or
> deployment exists because of this acceptance. The local contracts and accepted
> P-0006 evidence remain authoritative until later implementation items qualify
> this profile.

## Decision and bounded guarantee

Milestone 3 begins as one modular server process, one configured Workspace, one
PostgreSQL authority store, one private immutable-artifact namespace, and one
transactional-outbox worker boundary. HTTP, OIDC, PostgreSQL, artifact,
delivery, and key adapters call the same application and domain operations as
local mode and possess no independent mutation authority.

The first remote Agent profile deliberately requires two independent proofs on
every Agent request:

1. a live server-side session derived from a pre-bound OIDC Human subject; and
2. the accepted single-use `AuthenticatedCommandV1` signed by the operating
   Agent.

The Human session derives the requesting Principal. The Agent presentation
derives the operating Principal. The signed requester and all request-carried
Principal identifiers are mismatch guards only. A Delegation grants authority;
it never authenticates either actor. Unattended Agent execution without a live
requesting-Human session is outside this profile.

The composed verifier may prove the selected inner Release/artifact and remote
authority closures and may require exact caller checkpoints. This profile does
not authenticate the producer's export ID, snapshot label or heads, membership
capture, build, or ready transition, so it makes no current-at-snapshot,
immediate-predecessor, or globally latest claim. The first profile carries no
producer root, checkpoint, or resolver hint values at all.

## Topology and trust boundaries

```text
Human browser or trusted Human client
  │ OIDC Authorization Code + PKCE; opaque same-origin session
  │
  ├── direct Human request ───────────────────────────────┐
  │                                                       │
  └── Agent request + signed AuthenticatedInvocationV1 ───┤
                                                          ▼
                                               HTTP/BFF adapter
                                      strict Schema · CSRF · limits
                                                          │
                                      derived actor context only
                                                          ▼
                                          shared application services
                          authz · idempotency · policy · domain transitions
                                                          │
                         ┌────────────────────────────────┼───────────────┐
                         ▼                                ▼               ▼
                PostgreSQL adapter             artifact-store port   key ports
            facts + evidence + outbox          immutable private     distinct roles
                         │
                         ▼ after commit only
                    outbox worker ──► private preview adapter / allowlisted sink

Exported bundle ──► clean verifier
                    ▲             ▲
                    │             │
          caller trust policy   caller checkpoint
          (never from bundle)   (never from bundle)
```

The logical artifact namespace has two durability classes: fork-capable signed
bytes live atomically in logged PostgreSQL and are mirrored only after commit;
authority-neutral content blobs may use the private external content-addressed
store before commit. Both resolve through the same catalog and digest checks.

The deployment configuration fixes the one Workspace before the server accepts
traffic. A path, query, header, body, OIDC claim, database row, or forwarded
host value cannot select another Workspace. Any different Workspace identifier
fails before authentication detail, resource existence, or application state
is disclosed. This is a single-Workspace boundary, not evidence of tenant
isolation.

TLS termination and trusted-proxy configuration are deployment prerequisites.
Only metadata from an explicitly configured trusted proxy may affect host,
scheme, address, or client-certificate context. On a protected request,
authority-affecting `Forwarded`, `X-Forwarded-*`, or `Host` values from an
untrusted peer—or conflicting values from a trusted proxy—fail closed as
disclosure-neutral 401 `proof.auth.denied` before actor derivation. Neither a
TCP connection nor TLS session is an application Principal.

## Exact remote north star

The first qualified content trace uses exactly two Humans and one Agent. Its
Environment and active configuration are pre-existing verified inputs. A
separate configuration-administration trace uses two distinct administrator
Humans; those roles are not silently folded into the two-Human content trace.

| Symbol | Required identity | Authoritative responsibility |
| --- | --- | --- |
| `H-requester` | enabled OIDC-bound Human Principal with active `content.requester` role | Issues the exact content resource intent, builds the first ContextPack, issues the direct Delegation to a pre-bound Agent, and supplies the live Human session for each Agent call. |
| `A-operator` | enabled Ed25519-bound Agent Principal | Replays the Human-built ContextPack; creates, edits, inspects, validates, repairs, submits, commits, creates the Edition, releases preview, and queries it under the existing 11 localized operations. |
| `H-approver` | separately authenticated enabled OIDC-bound Human Principal with active `content.reviewer` role | Reads the complete ChangeSet, diff, validation chain, and configuration closure, then records one causal digest-bound approval. |
| `H-config-proposer` | enabled OIDC-bound Human with active `environment.admin` role | Proposes the preview Environment/configuration policy version when configuration changes are exercised. |
| `H-config-activator` | distinct enabled OIDC-bound Human with active `environment.activator` role | Activates the exact proposal and must differ from its proposer. |
| Independent verifier | no producer session, credential, private key, or network | Verifies the export with an exact caller-supplied `VerificationTrustPolicyV2`, typed authority/Environment-Release checkpoints, exact external bytes, and authorized subject openings. |

For the content trace:

- `H-requester != H-approver`;
- `A-operator != H-requester` and `A-operator != H-approver` by Principal type;
- `A-operator` is the publisher for `release.create/v2`, so the publisher is
  necessarily distinct from the Human approver;
- the approver cannot be the ChangeSet's initiating Human, any operating Agent
  that contributed an accepted consequence, or the Principal that activated
  the bound configuration version; and
- a configuration activator cannot activate its own proposal.

The sequence is exact:

1. A pre-existing private preview Environment has a verified versioned baseline
   Release, immutable creation fact, and active `EnvironmentConfigV2`.
2. `H-requester` authenticates through OIDC, issues the exact
   `ContentResourceIntentV1`, builds `ContextPackV2`, resolves the already
   active binding for `A-operator`, and issues one direct `DelegationV2`.
3. Each Agent HTTP call carries the live `H-requester` session and a fresh
   `AuthenticatedInvocationV1`. The existing v2 application input and result
   remain unchanged.
4. `A-operator` creates a localized ChangeSet, appends an invalid attempt,
   receives deterministic findings, appends a repair, validates successfully,
   and submits the sealed lineage.
5. `H-approver` reads the complete unfiltered ChangeSet, diff, and validation
   chain and invokes `changeset.approve/v3`. One transaction appends a
   `ChangeSetApprovalV1` at an exact authority head.
6. Fresh dual authentication lets `A-operator` commit the exact approved
   ChangeSet, create its exact Edition, and invoke the existing
   `release.create/v2`. Release authorization rechecks the causal approval,
   current Delegation, active configuration, exact Edition/ChangeSet delta, and
   expected Environment Release.
7. The Release transaction commits facts, decisions, consequences,
   idempotency, projections, immutable artifact references, Proof metadata, and
   `preview.release/v1` outbox enqueue together. Only then can the HTTP result
   report `release_committed`.
8. An at-least-once worker delivers the exact Release snapshot to private
   preview. Delivery status is separately `pending`, `in-flight`, `delivered`,
   `dead-letter`, or `abandoned`, with `attempts_in_generation` counting claims
   in only the current generation; delivery cannot change the committed
   Release fact.
9. A Human with `evidence.auditor` or `content.publisher` requests
   `evidence.export/v2`. The export commits immutable pre-attempt producer
   capture metadata and returns the immutable keyed pending result; it carries
   no trust or checkpoint hint values.
10. After the no-key lifecycle read reports ready, a clean verifier without
    producer state or network consumes the exact logical member map, separate
    `VerificationTrustPolicyV2`, and any caller checkpoints/openings/external
    bytes, then returns a general Complete, Incomplete, or Invalid report
    without treating snapshot or readiness metadata as authenticated.

Each numbered state-changing step has its own PostgreSQL transaction.
Authority-neutral content blobs may use the unreachable staging rules below.
Authority-bearing signed records and Proofs are generated and stored in logged
PostgreSQL bytes inside the transaction so an abort cannot leave a valid signed
fork. External delivery never occurs inside a domain transaction.

## Remote identity vocabulary

The accepted local v1 actor types do not change meaning. The remote profile
adds the following versioned types:

| Type | Meaning | Never means |
| --- | --- | --- |
| `OidcAuthenticatedSubjectV1` | Exact, case-sensitive configured `{issuer, subject}` tuple after OIDC validation; the non-control Unicode subject is compared without case folding or Unicode normalization. | Email, username, display name, tenant label, group, Principal, or authority. |
| `OidcPrincipalBindingV1` | Public commitment-only immutable Workspace authority payload binding one subject commitment and pinned issuer-configuration digest to one Human Principal. | A raw issuer/subject lookup, opening, live login, or role grant. |
| `OidcPrincipalBindingPrivateV1` | Protected adapter lookup that carries the exact issuer/subject, commitment opening, public binding-record digest, and matching identities needed to authenticate. | An ordinary log, Problem, ContextPack, portable public artifact, or authority payload. |
| `RemoteAuthenticationEventV1` | Server record that one configured issuer authenticated the committed subject for a bounded session. | IdP non-repudiation, MFA proof, or portable bearer credential. |
| `AuthenticatedActorContextV2` | Protected adapter-derived Human-only or Human-plus-Agent context delivered through an application identity port; it contains the exact requesting subject used for this execution. | Deserializable request input or public portable evidence. |
| `AuthenticatedActorContextEvidenceV2` | Public commitment-only redaction of that actor context, digested under `proof:authenticated-actor-context-evidence:v2`. | A subject opening, protected lookup record, or bearer credential. |
| `WorkspaceRoleAssignmentV1` | Append-only assignment of one closed role to an enabled Human Principal. | OIDC group mapping or Agent Delegation. |
| Browser session | Opaque transport handle to server-side authentication state. | Principal, role, Delegation, or application idempotency. |
| HTTP connection | Bounded transport channel. | Identity, Workspace selection, or authority. |

`AuthenticatedActorContextV2` and its public
`AuthenticatedActorContextEvidenceV2` redaction have two closed profiles:

- `proof.server/authentication/oidc-human/v1`; and
- `proof.server/authentication/oidc-human-agent/v1`.

The public `OidcPrincipalBindingV1`, `RemoteAuthenticationEventV1`, and
`AuthenticatedActorContextEvidenceV2` closure binds the configured Workspace
audience, pinned issuer-configuration digest, public binding ID and signed
binding-record digest, a domain-separated hiding commitment to the exact
canonical OIDC `{issuer, subject}` plus a uniformly random 32-byte blind, Human
Principal, authentication-event identity and time, application
operation/version and independently derived public operation-input-projection
digest, and exact evaluated authority head. The protected actor context alone
retains the distinct exact normalized-input digest. When present, public
evidence also binds the Agent subject, binding, Principal,
authenticated-command envelope digest, and single-use presentation identity.
The `RemoteAuthorizationDecisionV1` repeats the requesting binding-record
digest so authorization cannot substitute another commitment-only binding.
None of this public evidence includes an ID token, access token, refresh token,
session secret, raw issuer/subject, email, groups, arbitrary claims, or a
commitment opening.

The `RemoteAuthenticationEventV1` digest uses
`proof:remote-authentication-event:v1`; public actor-context evidence uses
`proof:authenticated-actor-context-evidence:v2`. The public binding itself is a
decoded `RemoteAuthorityRecordV1` payload and therefore uses the remote
authority payload and envelope contexts specified below, rather than a private
lookup-specific digest context.

The protected `OidcPrincipalBindingPrivateV1` is the only ordinary runtime
lookup from an exact raw issuer/subject to the public binding fact. It must
match the public Workspace, binding, Principal, issuer-configuration digest,
subject commitment, and binding-record digest. It is excluded from ordinary
logs, Problems, ContextPacks, exports, and public evidence. A complete public
closure can verify the commitment-level binding without this protected record;
an opening is a separately authorized audit disclosure and is supplied to a
verifier through the caller-controlled input boundary, never smuggled into the
ordinary bundle.

The private commitment preimage is exactly
`{api_version:"proof.dev/oidc-subject-commitment-input/v1",blind,subject,workspace_id}`
in RFC 8785 form, with `blind` base64url-without-padding for 32 random bytes;
its BLAKE3-256 derive-key context is
`proof:oidc-authenticated-subject-commitment:v1`. A protected opening carries
that exact preimage and claimed digest. Public evidence carries only the digest.
The protected exact operation-input commitment likewise uses
`proof:remote-normalized-operation-input:v1`; public evidence uses the
operation-specific disclosure projection under
`proof:public-operation-input-projection:v1`. These are different typed
preimages and derive-key domains, never a field rename or copied digest.
For `oidc-binding.issue/v1`, the `identity.admin` caller supplies the exact
protected issuer/subject and pinned issuer-configuration digest, but cannot
select the blind, commitment, or opening. Before the serializable transaction,
the server generates a fresh uniformly random 32-byte blind, computes the
commitment, and reuses that same candidate blind and commitment across internal
retries of the one application attempt.

Because `AuthenticatedActorContextV1`, `AuthorizationDecisionV2`, and their
authority records close over the local Unix requester profile, remote execution
uses versioned successor actor-context, authorization-decision, consequence,
and authority-record variants. It does not silently deserialize remote values
as local v1/v2 bytes. Existing `AuthenticatedCommandV1`, its Workspace audience,
five-minute maximum validity, 30-second future-skew allowance, signature,
single-use presentation, and fresh-presentation retry semantics remain intact.

Remote authority payloads use the closed `RemoteAuthorityRecordV1` successor
union and a one-signature Ed25519 DSSE envelope. The payload type is exactly
`application/vnd.proof.remote-authority-record.v1+json`; payload and envelope
digest contexts are `proof:remote-authority-record:v1` and
`proof:remote-authority-record-envelope:v1`. The decoded payload must already
be strict RFC 8785 canonical JSON, its sequence/predecessor/head fields must be
causally coherent, and its only signer must be the independently resolved
active Workspace authority key. The accepted 65,536-byte payload and
98,304-byte envelope maxima remain unchanged.

## OIDC binding and session boundary

The first profile has one public, secret-free `OidcIssuerConfigurationV1` from
trusted deployment configuration. It pins one HTTPS issuer, client ID, exact
authorization/token/JWKS endpoints, exact preregistered redirect URI, accepted
ID-token algorithms, and the accepted discovery metadata. Its RFC 8785 and
BLAKE3-256 digest context is `proof:oidc-issuer-configuration:v1`; the exact
accepted discovery document is separately committed under
`proof:oidc-discovery-metadata:v1`. Endpoint egress is deployment-allowlisted
with redirects forbidden, and the authorization-response issuer parameter is
required. The confidential client uses exactly `client_secret_basic` and the
configuration carries only a `deployment-secret:...` credential reference,
never the secret. Runtime sessions, authentication events, bindings, and actor
evidence bind the pinned issuer-configuration digest. Caller input cannot
select or override any of these values.

The same-origin Backend for Frontend follows the Authorization Code flow as a
confidential client and requires:

- PKCE `S256`, a transaction-specific one-use `state`, and a transaction-
  specific one-use OpenID Connect `nonce`;
- one exact preregistered redirect URI and no open redirect;
- exact discovery-metadata issuer equality with the configured issuer;
- TLS and an explicit asymmetric signature-algorithm allowlist, never `none`;
- signature verification using keys obtained only from the configured issuer;
- exact `iss`, nonempty stable `sub`, `aud`, and `azp` validation when multiple
  audiences require it;
- `exp`, `iat`, optional `nbf`, and a frozen maximum 30-second clock-skew
  allowance; and
- protected `OidcPrincipalBindingPrivateV1` resolution to its pre-existing
  public `OidcPrincipalBindingV1` record. There is no just-in-time Principal
  creation in this slice.

The exact issuer/subject pair is never rebound to a different Principal after
revocation or retirement. Replacement creates a new binding only for a new
subject or for the same Principal under an explicitly linked successor; it
cannot reinterpret historical authentication evidence.

After token validation, tokens stay server-side only for the exchange and are
discarded. The first profile retains no refresh token and requests a new login
after the Proof session expires. The browser receives a random 256-bit opaque
identifier; only a keyed hash of it is stored. The cookie is named
`__Host-Http-Proof-Session` and is `Secure`, `HttpOnly`, `SameSite=Strict`,
`Path=/`, with no `Domain`. The session has a 15-minute idle limit and an
eight-hour absolute limit, never extends beyond the upstream authentication
validity, and rotates on login or reauthentication.

Every application call re-resolves the immutable binding, current Principal
status, current role or Delegation, and authority head. Logout, session expiry,
binding revocation, or Principal disablement invalidates the session before the
next result is disclosed. Upstream IdP logout or revocation is not claimed to be
instantaneous.

Logout retains a bounded tombstone for the opaque session handle and the digest
of its exact session-bound CSRF value. An exact retry, including an
already-revoked handle, expires the application cookie and converges to 200
`logged_out: true`; it uses no application idempotency key and discloses no
prior application result. If OIDC login/callback outcome is unknown, the
one-use transaction is abandoned or expires and the browser starts a fresh
login rather than replaying an application key.

Binding revocation or Principal disablement therefore fails current
authentication as uniform 401 `proof.auth.denied`, before idempotency lookup or
stored-result disclosure, with no new durable authority record. When the
session, bindings, and Principals remain authentication-valid, loss of a
required role, Delegation, or current authority instead reaches authorization,
returns 403 `proof.authorization.denied`, and appends and catalogs the signed
remote denial decision.

Unsafe cookie-authenticated requests require all of:

- an exact same-origin `Origin`;
- `Content-Type: application/json` for operation requests;
- a session-bound synchronizer value in `Proof-CSRF`; and
- the current session cookie.

An authenticated same-origin `GET /api/v1/session` is the only first-profile
acquisition route for the current `Proof-CSRF` value. Its 200 JSON response is
`private, no-store` and returns the Principal and bounded session timestamps
plus an independent uniformly random 256-bit base64url synchronizer. The server
stores only the synchronizer digest, binds it to that session, rotates it on
login or reauthentication, and invalidates it with logout or any session
invalidation. The synchronizer is not a bearer credential, Principal,
authority fact, or application idempotency key, and the projection contains no
raw OIDC claims or provider tokens.

GET and HEAD have no application or evidence-write effects. Logout is POST.
CORS is disabled. Enabling it requires a later exact-origin profile; wildcard,
reflected, or `null` origins with credentials are forbidden. The OIDC callback
uses a separate short-lived, one-use transaction handle whose cookie is
`Secure`, `HttpOnly`, `Path=/auth/oidc/callback`, and `SameSite=Lax` so a
top-level authorization response can return. It validates state, nonce, PKCE,
and the RFC 9207 authorization-response issuer before that handle is consumed.
The `SameSite=Strict` application-session cookie is not relaxed for the
callback.

Unknown issuer, subject, binding, key, and invalid token/signature failures are
publicly disclosure-neutral. Restricted audit diagnostics can distinguish them
by correlation identity. Raw claims and provider error bodies never enter an
ordinary Problem, log, ContextPack, or public evidence artifact.

## Human roles and separation of duties

OIDC claims do not grant Proof roles. `WorkspaceRoleAssignmentV1` and its
revocation are Workspace-signed, append-only authority facts evaluated at the
same authority head as the attempted consequence. The closed first-profile
roles are:

| Role | Permitted application actions |
| --- | --- |
| `content.requester` | Issue the exact resource intent and first ContextPack, issue/revoke its direct bounded Delegation to a pre-bound Agent, and read its governed ChangeSet closure, Release, and preview. |
| `content.reviewer` | Read the complete submitted closure, Release, and preview and invoke `changeset.approve/v3`. |
| `content.publisher` | Read governed ChangeSet closure, Release, preview, and delivery state and create/read authorized evidence exports. Agent publication still requires the exact direct Delegation action. |
| `identity.admin` | Issue/revoke Human bindings and role assignments and record Principal disablement as bounded below. |
| `authority.admin` | Issue/revoke Agent bindings and perform emergency Delegation revocation under the accepted authority contract. |
| `environment.admin` | Propose an Environment configuration, including exact policy-bundle and delivery-target digests, and inspect or request replay of a `dead-letter` delivery. |
| `environment.activator` | Activate an exact Environment configuration—including a disabled version—proposed by another Principal, or explicitly abandon a poison delivery. |
| `evidence.auditor` | Read Release, preview, and delivery state and create/read an authorized evidence export without gaining publication or administrative authority. |

Environment configuration, including its complete policy payload, uses
proposal plus activation facts with an exact expected predecessor
version/digest and idempotency key. Proposer and activator must be different
enabled Humans, and the proposal cannot activate itself. Human/Agent bindings,
role assignments, Delegations, revocations, and Principal disablement remain
append-only signed authority facts under their exact administrator roles; they
are never OIDC-claim or mutable-row shortcuts. An Agent cannot hold an
administrative role.

Emergency revocation or disablement may be a one-Human operation because delay
can extend compromise, but it cannot leave fewer than two enabled
`identity.admin` Humans. If that invariant is already lost, the online profile
fails closed; it has no one-person recovery bypass. Re-anchoring authority is a
separately qualified offline recovery/import problem, not an implicit role.

Comments, labels, review queues, assignment, page views, and console state are
non-authoritative. They may reference immutable evidence but cannot advance a
ChangeSet, satisfy approval, change policy, or publish a Release.

## Causal approval and release recheck

The current local approval bytes remain historical. Remote approval is the new
application operation `changeset.approve/v3`, whose result is
`ChangeSetApprovalV1`. A separate assertion that a person “viewed” a page would not
prove cognition and is unnecessary. The approval itself attests to one exact
review closure and binds:

- approval identity/name and normalized-input digest;
- approving Human Principal, remote binding, OIDC subject commitment, and
  actor-context digest;
- ChangeSet identity, sealed ChangeSet digest, complete proposal/effective-leaf
  digest, validation-results head, and submission fact/digest;
- resource-intent and ContextPack identities/digests;
- active Environment and policy configuration versions/digests;
- the active reviewer-role assignment record;
- the exact immediate prior authority head;
- server-recorded approval time, new authority sequence/record digest, and
  Workspace-authority signature; and
- one UUIDv7 application idempotency key.

The approval transaction denies an Agent, a disabled or unbound Human, the
ChangeSet requester, a contributing Agent, the active configuration activator,
an incomplete or stale closure, a changed validation head, or a role assignment
not active at the transaction head. Approval time is evidence; the authority
sequence supplies order.

Commit and Release independently recheck current authentication,
authorization, separation of duties, exact approval bytes, role assignment,
configuration, Delegation, base state, and expected Release. A later Principal
disablement does not rewrite historical approval but blocks a new operation
when current policy requires the actor. Approval revocation, quorum, and
multi-stage rejection require a later version.

## Environment and policy administration

`EnvironmentCreationV1`, `EnvironmentConfigProposalV1`, and
`EnvironmentConfigActivationV1` are three separate immutable decoded
`RemoteAuthorityRecordV1` payloads. Each is persisted only in its signed DSSE
envelope. Creation establishes the Environment actor, actor-context digest,
time, authority sequence, predecessor, and key. A Human with the exact
`environment.admin` role proposes a normalized transition at an expected
configuration predecessor; a different enabled Human with the exact
`environment.activator` role activates that exact proposal at the still-current
predecessor.

`EnvironmentConfigV2` is the immutable assembled configuration closure, not a
fourth authority payload, mutable configuration row, or independently signed
fact. It embeds the exact decoded creation, proposal, and activation records
and the payload and envelope digest for each. It also carries Workspace and
Environment identity, positive configuration version and predecessor
version/digest, and the complete normalized configuration: enabled state,
private `preview` target, exact policy-bundle and validation-policy digests,
required approval and separation-of-duties policy, and the versioned delivery
destination rather than a request URL. The closure is valid only when all
three records agree on Workspace, Environment, chronology, predecessor, and
normalized transition; the proposal payload digest equals the activation's
`proposal_digest`; the creation payload digest is the activation's creation
digest and all copied creation fields match; and proposer and activator differ.
Both `environment_config_digest` and `normalized_configuration_digest` are the
RFC 8785/BLAKE3-256 digest of the normalized configuration under
`proof:environment-config:v2`.

Proposal and activation are separate transactions. Activation compares the
exact current predecessor and signed proposal; configuration and Release
publication cannot be combined. Disablement appends a prospective version,
blocks new Releases and movement of the preview alias, and retains every prior
Release, artifact, attempt, and receipt. The current Release pointer remains a
projection of Release facts and is never edited by configuration administration.

The normalized proposal contains the complete policy-bundle and validation
policy digests, so the distinct activation is also the policy-administration
gate. New policy cannot reinterpret a recorded validation, approval, or
Release; a new consequence must bind the exact configuration and policy
versions it actually evaluated.

## HTTP boundary

The HTTP adapter is versioned RPC over exact application operations. It does not
invent resource mutations or query database tables directly.

| Method and path | Authentication | Exact mapping |
| --- | --- | --- |
| `GET /api/v1/capabilities` | none | `capabilities.discover/v1`; the exact committed registry value plus its RFC 8785/SHA-256 commitment, with no Workspace/resource inventory. |
| `POST /api/v1/human/operations/{name}/{major}` | Human session + CSRF | Exactly one registered direct-Human application operation. |
| `POST /api/v1/agent/operations/{name}/{major}` | Human session + CSRF + Agent invocation | Exactly one pair from the accepted 14-row Agent registry. |
| `GET /api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}` | re-authorized Human | `evidence.artifact.get/v2`; exact kind-and-digest membership, length, and byte verification. The same digest text under another kind is not an alias. |
| `GET /preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}` | Human session | `preview.object.get/v1`, a private immutable exact-locale projection over the same released-object query semantics; no fallback or renderer. |

`GET /auth/oidc/login`, `GET /auth/oidc/callback`,
`GET /api/v1/session`, and
`POST /api/v1/session/logout` are a separate closed transport-session surface.
They may create or destroy ephemeral login/session records but cannot invoke an
application mutation, write authority/content evidence, or appear as a
capability operation. Login start and callback never accept a Workspace,
issuer, redirect, or Principal selector; neither GET accepts request media or
requires application CSRF, and each succeeds only with a 303 redirect. The
authenticated `GET /api/v1/session` requires no CSRF, succeeds with the 200
private/no-store session and synchronizer projection described above, and has
no write effect. Logout is a JSON POST requiring either the active Human
session or an exact bounded revocation-tombstone replay, exact same-origin
`Origin`, and the corresponding session-bound `Proof-CSRF`; its 200 result
invalidates both session and synchronizer and expires the cookie. These four
transport routes plus the five registered application or data routes above are
the exact nine-route first-profile HTTP surface.

The Human RPC route contains exactly 23 ordered operation rows, including the
no-key `evidence.export.get/v1` lifecycle read. Together with the public and
Agent/data rows, the complete registry contains exactly 40 operation rows; the
HTTP surface remains nine routes.

Agent operations with an evidence-write consequence remain POST even when they
read governed content. No Agent operation is advertised as HTTP-safe.

### Human and control operation registry

These rows require explicit strict input/result Schemas before implementation.
`Reused` means the application content semantics are unchanged; authentication
and remote evidence are still versioned. `Successor` means the operation is new
or closes a known evidence boundary.

| Operation/version | Status | Authentication | Idempotency | Concurrency anchor |
| --- | --- | --- | --- | --- |
| `capabilities.discover/v1` | Successor | public | none | one committed capability-registry digest |
| `agent-binding.issue/v1` | Reused artifact, remote decision successor | `authority.admin` | required UUIDv7 | exact authority head and enrollment closure |
| `agent-binding.revoke/v1` | Reused artifact, remote decision successor | `authority.admin` | required UUIDv7 | exact active binding and authority head |
| `content-resource-intent.issue/v1` | Reused | `content.requester` | required UUIDv7 | exact baseline Release/Edition/Known State |
| `context.build/v2` | Reused | `content.requester` for first build | required UUIDv7 | exact intent/base/config digests |
| `changeset.get/v2` | Reused | `content.requester`, `content.reviewer`, or `content.publisher` under the contextual closure-read rule | none | complete current ChangeSet digest |
| `changeset.diff/v2` | Reused | `content.requester`, `content.reviewer`, or `content.publisher` under the contextual closure-read rule | none | complete proposal/lineage digest |
| `changeset.approve/v3` | Successor | distinct `content.reviewer` | required UUIDv7 | sealed proposal, validation head, submission, config, authority head |
| `delegation.issue/v2` | Reused artifact, remote decision successor | `content.requester` owning the exact intent | required UUIDv7 | exact Agent, intent, scope, time, budget, and authority head |
| `delegation.revoke/v1` | Reused artifact, remote decision successor | issuing `content.requester` or `authority.admin` | required UUIDv7 | exact active Delegation and authority head |
| `delivery.get/v1` | Successor transport projection | `content.publisher`, `evidence.auditor`, or `environment.admin` | none | exact event, delivery ID, and generation |
| `delivery.replay/v1` | Successor immutable application fact | `environment.admin` | required UUIDv7 | exact `dead-letter` delivery and generation |
| `delivery.abandon/v1` | Successor immutable application fact | `environment.activator` | required UUIDv7 | exact poison delivery and generation |
| `environment-config.propose/v2` | Successor | `environment.admin` | required UUIDv7 | expected predecessor version/digest |
| `environment-config.activate/v2` | Successor | distinct `environment.activator` | required UUIDv7 | exact proposal and current predecessor |
| `evidence.export/v2` | Successor | `content.publisher` or `evidence.auditor` | required UUIDv7 | exact Release and immutable pre-attempt capture metadata; that metadata is not part of the verified inner claim |
| `evidence.export.get/v1` | Successor lifecycle projection | `content.publisher` or `evidence.auditor` | none | exact export identity and current pending/ready producer state |
| `oidc-binding.issue/v1` | Successor | `identity.admin` | required UUIDv7 | exact subject, Principal, issuer config, and authority head |
| `oidc-binding.revoke/v1` | Successor | `identity.admin` | required UUIDv7 | exact active binding and authority head |
| `principal.status.set/v2` | Successor remote authority fact | `identity.admin` | required UUIDv7 | exact Principal status and authority head |
| `release.get/v2` | Successor transport projection | `content.requester`, `content.reviewer`, `content.publisher`, or `evidence.auditor` | none | immutable Release digest |
| `release.verify/v2` | Successor remote evidence | `content.requester`, `content.reviewer`, `content.publisher`, or `evidence.auditor` | none | immutable Release/Proof digest |
| `workspace-role.assign/v1` | Successor | `identity.admin` | required UUIDv7 | exact Principal, role state, and authority head |
| `workspace-role.revoke/v1` | Successor | `identity.admin` | required UUIDv7 | exact active assignment and authority head |

Every public or Human registry row freezes both a versioned
`authorization_rule` and an exact `roles_any_of` set. Holding one listed role
is necessary but does not bypass the rule's contextual ownership, resource,
lifecycle, or separation-of-duties checks. Capability discovery is the only
row with an empty role set. Evidence artifact reads require
`content.publisher` or `evidence.auditor`; private preview reads require one of
`content.requester`, `content.reviewer`, `content.publisher`, or
`evidence.auditor`. The transaction evaluates the rule and role assignment at
the same current authority head as the operation.

The machine registry closes those rules rather than treating their identifiers
as prose aliases. Its non-circular `authorization_registry_sha256` is
`e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b`,
the SHA-256 over RFC 8785 of exactly the resource projection, closed rule
definitions, Human operation-to-action/rule/sorted-role projection, and Agent
operation-to-accepted-direct-policy projection. Every rule lists its exact
operation-specific binding descriptors; no name prefix or unused descriptor is
implicitly selected. The complete operation registry has a separate frozen
SHA-256 covering routes, Schemas, idempotency, Problems, limits, authorization,
results, and effects. Every `RemoteAuthorizationDecisionV1` and
`RemoteApplicationConsequenceV1` copies that complete registry selector so the
authorization-only hash cannot be used to reinterpret result or consequence
semantics. Resolving that full selector must yield a registry whose embedded
authorization-projection hash equals the decision's signed
`authorization_registry_sha256`; two independently accepted but mismatched
hashes fail verification.

For each selected public-safe resource, the server hashes RFC 8785
`{api_version:"proof.dev/authorization-resource-binding/v1",name,value}` with
derive-key context `proof:authorization-resource-binding:v1`. It then hashes
`{api_version:"proof.dev/requested-authorization-resources/v1",authorization_registry_sha256,authorization_rule,operation,requested_action,bindings}`
under `proof:requested-authorization-resources:v1`, where `bindings` is the
UTF-8-name-sorted exact `{name,value_digest}` array. OIDC-binding issuance uses
only the blinded subject commitment and pinned issuer-configuration digest,
never raw issuer or subject. Agent direct authorization copies all eight
canonical arrays from the accepted `AuthorizationDecisionV2.requested_resources`
and binds the accepted authority-registry row without coarsening.

The outer decision copies the exact `authorization_rule` and registry hash.
Its `policy_bundle_digest` is the derive-key
`proof:remote-authorization-policy-selection:v1` digest of RFC 8785
`{api_version:"proof.dev/remote-authorization-policy-selection/v1",authorization_registry_sha256,authorization_rule,environment_config_digest,environment_policy_bundle_digest}`.
Both Environment values are null for non-Environment rules; otherwise both
resolve from the exact selected `EnvironmentConfigV2`. Human decisions include
the active role-assignment digests actually used. Agent decisions have an empty
outer role list and retain the accepted direct decision's binding, Delegation,
requested resources, constraints, and local policy digest in
`agent_authorization`.

`RemoteApplicationConsequenceV1` copies that decision's Workspace, operation,
full operation-registry selector, public input-projection digest, exact
evaluated head, and typed `application_key_kind`/`application_key`. Success and
replay hash the exact row result under `proof:operation-effect:v1`. An
idempotency conflict, precondition conflict, or application failure uses the
same domain over RFC 8785 of exactly
`{api_version:"proof.dev/application-problem-digest-preimage/v1",code,operation}`.
RFC 9457 presentation fields and private diagnostics are excluded. The exact
registry row selects whether success must bind a remote authority payload,
content-intent, evidence-capture, delivery-management fact, localized effect,
or no application effect; a generic consequence label cannot substitute for
that row-specific digest rule. All 40 rows carry the closed rule, including
`none` for routes that never produce a signed consequence; the rule does not
itself confer consequence eligibility. When a successful Human mutation's
effect is itself a remote authority record, the decision extends the locked
head, the governed fact immediately extends the decision, and the application
consequence immediately extends that fact. Its
`application_effect_authority_head` names the fact. Every other success and
every non-success consequence extends the decision directly and carries a null
effect authority head. The row's closed `effect_timestamp_field` selects the
exact authority-payload time (`issued_at`, `revoked_at`, `approved_at`,
`proposed_at`, `activated_at`, `recorded_at`, or `assigned_at`); it is null for
every non-authority effect.

Initial server bootstrap is an offline, separately qualified import/provisioning
step and is not an HTTP operation. Runtime HTTP can never create an unanchored
Workspace root or first administrator. In this profile
`principal.status.set/v2` accepts only the prospective `disabled` transition
for an enabled Principal; online re-enablement and replacement of a lost
administrator are not hidden inside that generic name.

### Agent registry projection

The Agent route projects, without reinterpretation, the accepted 14 operation
pairs: `workspace.status/v1`, `object.query_released/v1`, `context.build/v1`,
and the 11 localized v2 rows for `context.build`, `changeset.create`,
`changeset.add`, `changeset.get`, `changeset.diff`, `changeset.validate`,
`changeset.submit`, `changeset.commit`, `edition.create`, `release.create`, and
`object.query_released`. The remote north star uses the localized v2 rows. The
three v1 rows remain compatibility capabilities.

Each Agent row also freezes the exact codes that may be committed after Allow
as an application failure. The 11 localized v2 rows use the complete accepted
`LocalizedOperationFailureV1` set; the retained v1 rows preserve their own
distinct source sets. In particular, `context.build/v1` retains the legacy
post-Allow `proof.auth.denied` and `proof.delegation.expired` outcomes. A code
prefix does not override that source-contract classification. Authorization-
only, transport, idempotency, and infrastructure codes absent from the exact
row cannot become application-failure consequences.

The path carries the literal terminal version token (`v1`, `v2`, and so on),
while the body carries the full operation-version identifier. The path
name/major, invocation operation, signed operation, capability row,
input Schema, result Schema, authority registry, idempotency class, consequence
class, and Problem registry must agree exactly. A mismatch fails before
application execution. An endpoint absent from the registry cannot mutate or
read protected state.

### Envelopes, Problems, and HTTP semantics

Human request bodies contain only Workspace cross-check, exact operation,
normalized application input, and the application idempotency key or null.
Agent bodies contain the exact canonical `AuthenticatedInvocationV1`. Neither
body can construct actor context. Unknown or duplicate JSON names, non-I-JSON
values, unsupported media types, and unknown members fail closed.
Before parsing, the adapter independently rejects a raw HTTP request body over
1,048,576 bytes. After strict parsing and RFC 8785 canonicalization, it also
independently rejects canonical request bytes over 1,048,576 bytes; whitespace
or alternate JSON spelling cannot bypass the raw transport bound. Either limit
uses the 413 `proof.input.too_large` Problem.

Successful responses use a versioned structured envelope containing the exact
operation/version, server-generated UUIDv7 `operation_id`, optional validated
caller UUIDv7 `correlation_id`, committed snapshot or immutable-result anchor,
and the unchanged typed application result. No response is returned from an
attempt whose transaction did not commit.

Errors use RFC 9457 `application/problem+json`; the existing stable Proof code
is the primary machine classifier. The extension members are exactly `code`,
`api_version`, exact operation name/version, `operation_id`, nullable
`correlation_id`, `retryable`, optional `retry_after_ms`, optional authorized
`current_digest`, and optional authorized structured `findings`. Titles are
stable and details are non-normative. SQL, stack traces, raw claims, subjects,
tokens, secrets, hidden identifiers, and provider diagnostics are forbidden.

Each of the nine routes names a closed route-specific Problem profile; the
profiles distinguish bodyless GET, JSON POST, OIDC callback, Human-session,
and Human-plus-Agent presentation failures. A transport/session route emits
exactly that profile. A Human application/data operation emits the union of its
route profile, row transaction profile, and exact
`application_problem_codes`. An Agent operation additionally unions its exact
disclosure-neutral accepted-error projection with its exact post-Allow
`application_problem_codes`. There is no global transport-code array and no
code is implicitly added to every operation.

| HTTP status | Stable class |
| ---: | --- |
| 400 | malformed strict JSON, Schema, path/body mismatch, or unsupported value |
| 401 | disclosure-neutral unauthenticated session or presentation |
| 403 | proven, safely disclosable authorization or policy denial |
| 404 | absent or disclosure-hidden resource |
| 409 | application state, causal, concurrency, or idempotency conflict |
| 413 | request, artifact, or expansion limit |
| 415 | unsupported request media type |
| 422 | deterministic validation findings |
| 429 | bounded rate limit with `Retry-After` |
| 500 | disclosure-neutral internal integrity or invariant failure |
| 503 | retryable storage, key, issuer, artifact, or worker dependency failure |
| 504 | server deadline exhausted with unknown client-visible outcome |

Application idempotency remains in typed input and the Agent signature. There
is no normative HTTP `Idempotency-Key` dependency. If a compatibility header is
ever accepted, it must exactly duplicate the application value. HTTP ETag and
`If-Match` may duplicate an existing immutable digest or exact application
precondition, but cannot be the only concurrency rule or alter existing v2
semantics. A strong ETag accompanies immutable representations.

Each route accepts only its exact application version; there is no silent
version negotiation. `capabilities.discover/v1` embeds the complete closed
registry object, including route, operation, input/result Schema identifiers,
authentication and authorization profiles, effect,
idempotency/concurrency class, Problems, and limits. Its `registry_sha256` is
SHA-256 over the RFC 8785 canonical bytes of that embedded registry; the
result Schema freezes the accepted commitment. No additional registry route,
deployment file path, Workspace/resource inventory, or implicit lookup is
required. Unsupported versions fail explicitly.

Exact closure reads are not paginated. A future registered list operation uses
a server-authenticated opaque cursor bound to one snapshot and filter, stable
sort, default 50 and maximum 100 rows, and no offset pagination or UI-only SQL.

The initial limits are:

| Boundary | Maximum |
| --- | ---: |
| Raw HTTP request body | 1,048,576 bytes |
| RFC 8785 canonical operation request | 1,048,576 bytes |
| Canonical Agent authentication payload | 4,096 bytes |
| Agent DSSE envelope | 16,384 bytes |
| Human/Agent ordinary structured response | 4,194,304 bytes |
| Portable evidence manifest | 4,194,304 bytes |
| One portable artifact | 4,194,304 bytes |
| Included export total | 268,435,456 bytes |
| Export artifacts | 4,096 |
| Authority records per v1 prefix | 512 |
| Localized targets / Edit attempts | existing 100 limits |
| Application deadline | 30 seconds, excluding streamed export download |

Rate limits and deadlines are adapter denial controls, not authority. A keyed
operation reconciles a timeout or lost response with the same application key
and equivalent normalized input; an Agent also uses a fresh presentation. A
no-key read has no stored-result replay promise: a permitted retry is a fresh
authenticated and authorized attempt that may append distinct evidence and
observe newer state. `null` is never a key. The adapter never generates a new
semantic ID, timestamp, or application key inside an internal storage retry.

## PostgreSQL authoritative unit of work

Every authoritative mutation, including an Agent read that consumes a
presentation, runs in `SERIALIZABLE READ WRITE`. At the start it selects and
locks the single durable `workspace_write_head` row with `SELECT ... FOR
UPDATE`. This deliberately reproduces SQLite's one-writer behavior for the
first server slice while serializable isolation catches missed predicate
interactions.

The transaction algorithm is:

1. Select the deployment Workspace and verify the compatible migration
   version; never accept a request-selected Workspace.
2. Lock the Workspace write head and read exact authority, content, Release,
   policy, and configuration heads.
3. Derive and advance transaction, authority, content, and Release sequence
   values from the locked row. Any optimistically prepared artifact must name
   those exact next values or the attempt restarts without a catalog reference.
   PostgreSQL sequences, `SERIAL`, and `BIGSERIAL` are forbidden for causal
   order because their increments do not roll back.
4. Verify authentication before idempotency lookup or prior-result disclosure.
   A malformed or unproven Human/Agent credential, actor mismatch, or replay
   rolls back without a new authority record; its public failure is
   disclosure-neutral.
5. Evaluate current authorization at the locked head. A proven Agent denial
   atomically consumes the presentation and appends the remote authorization
   decision, including its signed body and catalog reference, but no
   application consequence, successful application key, or outbox event. A
   proven Human denial appends and catalogs the versioned signed remote
   decision without inventing a governed consequence.
6. After Allow, a keyed row compares the complete idempotency tuple. Same key
   plus equivalent normalized input consumes the fresh Agent presentation when
   present, appends and catalogs this attempt's signed decision and replay
   record, and discloses the prior committed result without duplicating the
   prior domain fact, successful key/result record, or outbox event. Same key
   plus changed input commits and catalogs the signed decision and
   idempotency-conflict consequence but no governed effect. A no-key row skips
   stored-result lookup and executes as a distinct authorized attempt.
7. Compare exact base state, approval, configuration, and concurrency
   preconditions. An authorized conflict commits presentation consumption,
   signed decision and failure consequence bodies, and their catalog
   references, but no successful key or external effect.
8. Establish a savepoint around the governed application consequence.
9. On success, atomically persist presentation consumption, remote actor
   evidence, authority decision, authoritative facts,
   `RemoteApplicationConsequenceV1`,
   successful idempotency/result/effect, immutable artifact catalog references,
   fork-capable signed artifact bodies, Release/Proof, required projections, one
   logical outbox enqueue per external effect, and the new heads.
10. On an ordinary authorized application failure, roll back to the savepoint
   and commit only presentation consumption, the signed decision and failure
   consequence bodies, and their catalog references. It reserves no successful
   application key and enqueues no external effect.
11. On infrastructure, signing, artifact, storage, or
   integrity failure, roll back the entire transaction.
12. Return nothing until commit success.

All authoritative, idempotency, artifact-catalog, outbox, attempt, and receipt
data uses ordinary logged durable tables. The first profile requires
`synchronous_commit=on`, `fsync=on`, and `full_page_writes=on` and forbids
`UNLOGGED` authoritative tables. These are contract preconditions whose runtime
verification belongs to implementation evidence, not proof against a malicious
database operator.

### Retry and ambiguous commit

The adapter retries the complete transaction, including all decision logic, on
SQLSTATE `40001`; it may retry `40P01` only from the beginning. `23505` is
retryable only for a named internal allocation constraint; business uniqueness
and idempotency conflicts remain stable application results. Attempts are
bounded to three within the original 30-second deadline with bounded jitter.
Exhaustion returns a retryable storage-conflict Problem.

Every internal retry reuses normalized input, server-preallocated identifiers,
correlation identity, server-preallocated semantic times, and the application
key only when the selected row is keyed. A no-key row reuses the same internal
attempt context without inventing a key. Each aborted attempt discards its
bytes, signatures, and results. No IdP, resolver, key-service, object-store,
webhook, preview-delivery, or other external call occurs inside the retried
transaction.

The first profile therefore requires already-loaded process-local signing keys
for authority and Release records. A network KMS/HSM call while holding the
Workspace transaction is outside this profile and requires a later protocol
that preserves the same commit and retry semantics.

A connection loss during commit has unknown outcome. If the server cannot
establish the outcome before responding, it returns retryable 504
`proof.operation.unknown_outcome`; that response asserts neither commit nor
rollback. For a keyed row, reconciliation is a separate attempt with the same
application key and equivalent input. An Agent supplies a fresh presentation,
and fresh authentication/authorization precedes stored-result disclosure. A
found committed result follows equivalent-replay rules; a conclusively rolled-
back attempt may execute again under the original key. Same-key changed input
is a non-retryable conflict. A no-key row cannot look up or disclose the first
result: any safe retry is a fresh authenticated/authorized attempt and remains
separately auditable. OIDC login/callback ambiguity abandons or expires that
one-use transaction and starts a fresh login; logout converges through its
bounded session-revocation tombstone and cookie expiry, never an application
key. The server never assumes an ambiguous commit failed or invents a key.

## Migration and projection rebuild

Runtime and migration database roles are separate. Request handling never
auto-migrates. Each migration has an immutable monotonic version, name, and
domain-separated BLAKE3-256 digest of its exact script bytes. One fixed
PostgreSQL advisory-lock key plus a durable
singleton migration-head row admits exactly one migrator across transactional
and nontransactional phases. The append-only ledger records version, name,
digest, phase, status (`started`, `verified`, or `failed`), actor/tool version,
and database-recorded times. The server refuses writes outside its declared
compatibility interval, on checksum mismatch, on a dirty/failed phase, or on an
unknown newer version.

Transactional DDL, backfill, verification, and version advancement occur in
one transaction. Nontransactional work such as concurrent index construction
requires explicit resumable phase state and cannot advance the Schema version
until verified. Migration follows expand, backfill, verify, cutover, and later
contract phases. Historical canonical bytes and digests are never reserialized,
rewritten, or inferred. No destructive down-migration promise exists; an older
binary may run only while the forward Schema is explicitly compatible,
otherwise recovery is a forward repair.

An initial SQLite-to-PostgreSQL import consumes verified canonical facts and
artifacts, reconstructs all chains, rebuilds projections, compares authority
heads and Known State, and opens network writes only after an atomic cutover.
Directly copying unverified SQLite rows is not sufficient.

The first projection rebuild is correctness-first and offline for writes:

1. start a serializable write transaction and lock the Workspace head;
2. verify authority/content/Release chains and capture exact heads;
3. rebuild every derived row into a new generation;
4. compare identities, counts, foreign keys, versions, sequences, and state
   digest;
5. atomically swap one active-generation pointer and commit; and
6. expose no partial generation on dry run, crash, or mismatch.

A read transaction pins one projection generation for its lifetime. A retired
generation remains readable until no transaction can still hold that pin; only
then may a separately qualified garbage collector remove it.

Facts, authority records, idempotency, artifact catalog, outbox events,
attempts, and receipts are not projections and are never regenerated or deleted
by rebuild.

## Immutable artifact boundary

Canonical artifacts use private content-addressed keys of the form
`artifacts/{artifact_kind}/blake3/{digest}`. Kind, canonical bytes,
domain-separated digest, media type, Schema version, and byte length form the
identity.

The external storage port supplies private `put_if_absent` plus verified
read-after-write. An existing key succeeds only when length and digest
reproduce; different bytes at one key are an integrity incident. Only
authority-neutral content blobs may be prepared before the authoritative
transaction in an unreachable namespace. The transaction rechecks every head
and candidate sequence used to construct them. A leaked orphan cannot extend a
signed authority or Release chain because no uncommitted signed record names
it.

Authority records, authorization decisions and consequences, approval and
configuration records, Release Proofs, checkpoints, and every other artifact
whose valid signature could extend or fork portable history are different.
Their canonical bytes and signatures are generated with the already-loaded
process-local key and inserted into an immutable logged PostgreSQL artifact-body
table in the same transaction as their catalog row and state transition. Abort
discards the only durable copy. After commit an outbox event may mirror those
exact bytes to the private external store; the committed PostgreSQL body remains
the source until a mirror passes exact read-back verification. The mirror never
changes artifact identity or authority.

A staged neutral blob cannot be listed, exported, previewed, or named by a
public result before the database commit. A committed reference has either a
verified pre-staged neutral blob or atomically committed PostgreSQL bytes.
Every export or delivery read revalidates kind, length, and digest; absence or
substitution fails closed and never falls back to current content. Referenced
blobs and committed inline bodies are never overwritten or deleted while an
authoritative catalog reference exists. Only unreachable neutral-orphan
garbage collection and any future evidence-retention transition are deferred
rather than guessed.

This is not a distributed transaction. It combines atomic database storage for
fork-capable signed bytes with a visibility protocol for neutral pre-commit
blobs; every external mirror or delivery is driven from a committed outbox row.

## Transactional outbox and delivery

The immutable enqueue record contains event ID, Workspace transaction sequence
and ordinal, event type/version, stable ordering key and stream sequence, exact
effect identity, canonical payload digest or artifact reference,
destination/configuration version, correlation/causation identities, and
committed creation time. The logical-event uniqueness key is
`{workspace_id, effect_digest, event_type, event_version,
destination_configuration_digest}`, where `effect_digest` commits the exact
consequence and its stable semantic identity rather than payload bytes alone.
`{workspace_id, workspace_transaction_sequence, ordinal}` is independently
unique. These constraints permit only one enqueue for that committed
consequence and destination and say nothing about delivery count.

The authoritative transaction preallocates one stable UUIDv7 delivery ID for
the event/destination pair. Mutable state has exactly one of `pending`,
`in-flight`, `delivered`, `dead-letter`, or `abandoned`; database-calculated
next-attempt time; `attempts_in_generation`; a random lease token/expiry;
generation; and terminal receipt reference. `attempts_in_generation` counts
claims consumed in only the current generation, while immutable attempts from
older generations remain in global history. Attempts, `dead-letter`
transitions, replays, and abandonments are append-only records.

A worker claims only the lowest nonterminal sequence for a stream whose prior
sequence is terminally delivered or explicitly abandoned. At most one live
lease exists per stream. Within that rule, a worker:

1. claims due work in deterministic order in a short `READ COMMITTED`
   transaction using `FOR UPDATE SKIP LOCKED`;
2. records a random lease token, a 60-second lease using PostgreSQL
   `clock_timestamp()`, and the counted attempt before committing the claim;
3. performs external I/O only after that commit and enforces a 30-second attempt
   deadline; the first profile does not renew leases;
4. acknowledges in a new transaction by compare-and-set on the exact lease
   token and generation;
5. rejects a stale or superseded acknowledgement; and
6. makes the same stable delivery eligible after lease expiry.

Claim or worker crash consumes its recorded attempt. Retry delay is uniformly
sampled from the upper half of
`min(5 seconds * 2^(generation_attempt - 1), 1 hour)` and is added to database
time. Twelve counted attempts in one generation or seven days from that
generation's start, whichever comes first, produces a dead-letter record; an
explicit permanent failure does so immediately. A poison message blocks its
strict destination/Environment stream until successful replay or authenticated
administrative abandonment. Other independent streams may progress. Workspace
transaction sequence plus ordinal, never time, defines enqueue order.

Manual replay or abandonment requires a current authorized Human and appends
one `DeliveryManagementFactV1`, an immutable application fact whose
RFC 8785/BLAKE3-256 digest context is
`proof:delivery-management-fact:v1`. It is deliberately not a
`RemoteAuthorityRecordV1` payload. Authorization still appends the signed
`RemoteAuthorizationDecisionV1`, and success appends the signed
`RemoteApplicationConsequenceV1` whose `application_effect_digest` is exactly
the management-fact digest; those decision and consequence records provide the
authority binding.

Neither management action changes the event ID, delivery ID, or payload.
Replay increments the generation, resets `attempts_in_generation`, and returns
the new generation in `pending` while preserving the append-only global attempt
history. Abandonment keeps the current generation, records null
`to_generation`, and sets its terminal status to `abandoned` so only the
stream-management cursor may advance; it never mutates or pretends to deliver
the event. A worker cannot mutate authoritative domain facts.

Delivery is **at least once**. A worker can apply an external effect and crash
before acknowledging it, so retry may repeat the effect. Stable event/delivery
IDs, recipient deduplication, and conditional monotonic application support
convergence but are not exactly-once transport. A receipt records only what the
adapter observed; it is not independent proof that a remote system applied an
effect once. At-most-once delivery is rejected because it may silently lose a
committed effect. The private preview target retains delivery-ID deduplication
state for as long as the corresponding event remains replayable; this profile
defines no deletion horizon for either.

General arbitrary webhooks are outside the first preview slice. A later webhook
adapter may use only versioned administrator-configured destinations, strict
HTTPS and egress allowlists, no redirect, resolution and connection to the same
validated non-loopback/non-private/non-link-local address, bounded response
bytes/time, and a signed non-secret payload. A request-carried URL is never a
delivery destination or evidence resolver.

## Preview delivery

Release commitment and preview delivery are separate facts. The Release
transaction advances Proof's authoritative Environment pointer and enqueues
`preview.release/v1` with the exact Release sequence/digest, Edition,
Environment configuration, Proof, and artifact references. It never asks the
worker to resolve “current.”

The private preview adapter materializes every blob under unreachable keys,
verifies them, and writes one content-addressed complete-snapshot manifest and
ready marker last. Release-specific reads and the mutable alias resolve only a
ready manifest, so a crash cannot expose a partial snapshot. The alias compare-
and-set outcomes are exact: a higher Release sequence advances; the same
sequence plus the same Release/manifest digest is a no-op; the same sequence
plus different bytes is an integrity failure; and a lower sequence is recorded
as superseded without regressing the alias. An authenticated abandonment may
leave a delivery gap and let a later ready Release advance. Delivery failure
never rewrites Release history. Recovery is retry, authenticated abandonment,
or a new forward rollback Release.

The release-specific GET route returns exact JSON only after that Release's
ready marker exists; while pending it returns the stable delivery-pending
`proof.dependency.unavailable` Problem and never falls back to another Release. The response identifies
Release ID/digest, Edition digest, and rendition digest, uses a strong ETag and
`Cache-Control: private, no-store`, and performs no locale fallback. There is
no public or anonymous preview, bearer link, renderer, template engine,
arbitrary fetch, or presentation-framework contract.

## Server key roles

Key roles are cryptographically and administratively distinct:

| Role | Use | Forbidden use |
| --- | --- | --- |
| Workspace authority root | Bindings, roles, policies, approvals, remote decisions, authority checkpoints. | Agent commands, Release Proofs, TLS, session cookies, or webhooks. |
| Release signing key | Existing Release Proof envelope. | Authority manufacture or session authentication. |
| Agent command key | Client-side `AuthenticatedCommandV1`. Server stores public binding only. | Human login, approval, authority administration, or Release signing. |
| OIDC client credential | Confidential code exchange with one configured issuer. | Proof authority or portable evidence signature. |
| Session-secret key | Hash/rotate opaque session and CSRF material. | Domain artifact or Proof signature. |
| Delivery signing key | Authenticate a configured preview/event payload when the destination supports it. | Authority, Release, or Human identity. |
| TLS key | Transport endpoint. | Application actor or portable Proof. |

Provider and custody selection remain adapter decisions. KMS/HSM, workload
identity, key escrow, and high availability are outside the first profile. A
key ID is a lookup identifier, never trust by itself.

## Evidence export and independent verification

`RemoteEvidenceBundleV2` is a P8 descriptor over exactly six typed root
members:

1. `release-artifact-closure` — one canonical
   `RemoteReleaseArtifactClosureV1` that enumerates every accepted nested
   artifact;
2. `authority-fact` — one canonical `RemoteAuthorityRecordSetV1`;
3. `remote-actor-evidence` — exact
   `AuthenticatedActorContextEvidenceV2` bytes;
4. `remote-authentication-event` — exact
   `RemoteAuthenticationEventV1` bytes;
5. `remote-command-input` — exact `CommandInputV1` bytes; and
6. `remote-authenticated-command-envelope` — the exact Agent DSSE envelope.

The verifier decodes `AuthenticatedCommandV1` from the envelope payload and
checks its signature and every command cross-link. There is no standalone
authenticated-command payload root. The actor, authentication, command, and
envelope companions are not remote-authority payload variants. The protected
OIDC lookup/opening material is not an ordinary root, and the selected claim
does not request outbox, delivery, or artifact-catalog evidence.

The accepted P6 `AuthorityEvidenceBundleV1` and
`proof-verifier/authority-evidence-bundle-v1` remain unchanged historical local
evidence only. P8 neither embeds a P6 bundle nor relabels or executes its
verifier for a remote attempt. `proof-verifier/remote-authority/v1` instead
validates a canonical contiguous P8 DSSE suffix from a caller-pinned initial
head. Because the verifier has no producer database, network, or authenticated
base-state snapshot, every OIDC/Agent binding, Delegation, revocation,
Principal/role, Environment, approval, decision, and consequence fact consumed
for the selected attempt must be present in the supplied suffix after that
initial head. `proof-verifier/remote-evidence-v2` independently validates this
closure, the accepted Release/artifact closure, and every attempt companion
before enforcing Workspace, identity, command, policy, application-key,
Release, Proof, result, effect, decision, consequence, and authority-head
links.

Export creation and readiness are deliberately different contracts.
`evidence.export/v2` commits one immutable `EvidenceExportCaptureV2` in a short
serializable transaction and always returns the exact keyed
`EvidenceExportResultV2` with `status:pending`. Every same-key equivalent replay
returns those same create-result bytes, even after assembly finishes. A worker
builds from that capture outside the transaction; a second transaction verifies
the bytes before pending-to-ready. The no-key `evidence.export.get/v1` performs
fresh authentication and authorization and returns the current mutable
`EvidenceExportStatusV1`, with null descriptor/manifest digests and zero counts
while pending or exact reserved digests/counts/bytes when ready. It cannot
replace the capture or keyed result.

The capture boundary is `pre-export-attempt-locked-heads`, so the capture does
not recursively include its own decision, effect, or
`RemoteApplicationConsequenceV1`. However, the export ID, snapshot label and
heads, capture digest, membership plan, manifest, assembly, and ready transition
are unauthenticated producer metadata in this profile. The verifier rejects
contradictory repetitions but excludes capture integrity, readiness,
current-at-snapshot, immediate-predecessor, and globally latest claims from
Complete until a future non-circular detached receipt authenticates them.

The portable package is an exact uncompressed logical map from normalized
UTF-8 member path to raw bytes, not tar, zip, another archive, or a compressed
carrier. It contains reserved `bundle.json` and `manifest.json` entries, every
`included` root, and each unique nested artifact at the deterministic path
declared by the Release closure. An `external-required` authority, actor, or
authentication root is absent and must be supplied through the caller input.
Absolute or dot-segment paths, backslashes, duplicate normalized paths,
undeclared or missing entries, kind/digest/length mismatches, and any count or
byte limit violation are Invalid. The maximum 4,096 artifact bodies means the
six roots plus at most 4,090 nested bodies; the two reserved descriptor entries
are accounted separately.

Ready status publishes the exact digests for the reserved
`remote_evidence_bundle_v2` and `remote_evidence_manifest_v2` entries. The
manifest enumerates included root selectors and the fetched Release closure
enumerates nested selectors. Each artifact GET is addressed and authorized by
the exact `(export_id, artifact_kind, digest)` triple. A digest under another
kind is not an alias, and an external-required root is a caller obligation, not
a producer-download selector.

Independent verification receives one exact caller-controlled
`VerificationTrustPolicyV2`. It supplies usable role-separated authority,
Release, and historically selected Agent public-key bytes; the initial remote
head; accepted policies and registry hashes; a closed built-in
hash-to-canonical-registry resolver; disclosure policy; and parser, artifact,
record, and byte limits. Optional typed authority and Environment/Release
checkpoints, required OIDC subject openings, and exact external-artifact
descriptor/bytes values also cross this separate input boundary. The verifier
recomputes the trust-policy, input, checkpoint, manifest, descriptor, and
artifact digests and performs no producer database or network lookup.

The first-profile `untrusted_hints` object is intentionally inert: every root,
checkpoint, and resolver array is exactly empty, `trusted` is false, and
`auto_fetch` is false. A key ID, allowlist label, URL, bundle field, or valid
signature alone never creates caller trust. A required authority checkpoint
must equal the included head in Workspace, sequence, digest, and active key; a
higher sequence without the intervening records is not ancestry.

`RemoteVerificationReportV2` is the general closed observed report for every
Complete, missing-material Incomplete, and integrity or semantic Invalid
outcome. It binds the exact manifest, verifier input, trust policy, optional
checkpoint digests, and execution and selects one primary reason consistent
with its component results. The narrower `conformanceReport` subtype permits
exactly the retained three qualification scenarios: complete exact
materialization, required OIDC opening withheld, and deterministic
`object_locale_revision_v1` byte tamper. The three rows in the P-0008 fixture
are unobserved normative successor requirements, not runtime reports. The
retained decision and `RemoteApplicationConsequenceV1` instances are decoded,
canonicalizable, signable candidate payloads, not a retained signed pair or
execution.
Runtime qualification requires materialized logical-map bytes and real
Complete, Incomplete, and Invalid verifier executions. Delivery evidence is
`not-requested` for this claim.

## P-0006 and P-0007 residual disposition

P-0008 cannot close an implementation residual by writing architecture. The
following classification controls later Milestone 3 evidence:

| Prior residual | P-0008 disposition |
| --- | --- |
| No globally latest or provably immediate same-Environment Release | Retained Milestone 3 nonclaim and later external-checkpoint/transparency fog. Producer snapshot metadata remains unauthenticated; caller pins bound only the exact supplied closure. |
| Exported v1 Environment configuration lacks creation chronology | Required Milestone 3 implementation closure through versioned Environment creation/configuration facts; v1 bytes remain unchanged. |
| v2 approval lacks an exact authority causal head | Required Milestone 3 implementation closure through `ChangeSetApprovalV1`; existing approvals are not reinterpreted. |
| Historical direct-Human v2 evidence is Incomplete without the Agent companion | Required closure for new remote Human north-star actions through versioned Human evidence/consequence; historical bundles remain Incomplete. |
| Missing/pre-v14 artifacts and some malformed idempotency reconstructions remain conservatively Incomplete | Retained historical behavior. New server writes retain complete preimages; exhaustive legacy Invalid classification is not claimed. |
| Same-UID TOCTOU and hostile-process isolation | Retained local nonclaim/later protected-broker or workload-identity work. A server does not retroactively change local containment. |
| Verifier registry has 158 codes: 30 direct behavioral and 128 structural source/registry guards | Later release-hardening work. Structural equality is not relabeled branch-level behavior. |
| Redundant `EditBatchV1` is not independently replayed | Retained compatibility nonclaim/later cleanup; it remains non-authoritative. |
| Windows runtime/containment is unqualified | Later fog. |
| No server parity, deployment, production, public release, or live remote verification | P-0008 closes only a decision contract. Each runtime/operational claim requires a later implementation or qualification item. |
| P-0007's localized north star was Human-only at acceptance | The later accepted P-0005/P-0006 Agent path supersedes that bounded workflow gap; P-0008 preserves both evidence sets and makes no remote-runtime claim. |
| A self-consistent SQLite/database rewrite is not prevented cryptographically | Retained local SQLite total-forgery nonclaim. PostgreSQL/operator tamper is likewise detectable only relative to signed evidence and independent checkpoints and remains an availability risk. |
| Six Human CLI operations and Edition creation do not promise same-visible-command retry | HTTP receives an exact versioned idempotency contract; local CLI UX is not relabeled. |
| High-cardinality recursive v2 Release-history stack safety | Retained scalability nonclaim and later qualification. |
| Existing crash injection is not power-loss/storage-controller qualification | Retained operational nonclaim; database durability configuration is necessary but not power-loss proof. |

## Conformance and falsification plan

Three evidence classes stay separate:

1. retained local P-0006 executable evidence;
2. P-0008 decision-contract Schemas, registries, retained decision-candidate
   valid-shape/cryptographic fixtures, and a structurally validated but
   non-executable rejection requirements matrix qualified with the decision
   candidate; and
3. future server executable evidence that does not pass merely because this
   document exists.

The retained decoded, signable candidate decision and consequence payloads
model one Agent Allow and successful `release.create/v2` path, but no matching
signed envelopes or runtime pair are retained. P-0008 also mechanically
validates the closed Schemas, registry effect/failure tables, precedence-aware denial
mutations, and non-executable rejection requirements, but it does not relabel
those checks as executed Human decisions, denials, replay, idempotency or
precondition conflicts, or application failures. A server implementation
candidate must retain exact recomputed vectors for every such consequence
branch and representative Human authority/content/evidence operations before
claiming runtime parity.

“The same conformance suite” means a shared semantic oracle plus adapter-
specific cases, not identical test inventories or database-row comparison.

| Boundary | Required future accepted evidence | Required rejection/crash evidence |
| --- | --- | --- |
| Actor parity | Local and HTTP normalize to the same application input/result; remote Human and Agent are independently derived. | Request-selected Workspace/Principal, Delegation-as-authentication, Agent-only requester, body/context substitution. |
| OIDC/session | Deterministic issuer/JWKS, valid code+PKCE+state+nonce, active binding, rotation and logout. | Wrong issuer/audience/algorithm/key/time/nonce/state, fixation, revoked binding, hostile Origin, CSRF omission, token/claim leakage. |
| Operation registry | Exact equality among HTTP, application, authority, Schema, capability, Problem, idempotency, and consequence rows. | Unknown route/version/member, HTTP-only write, stale precondition, changed-input key reuse, oversized request. |
| Review/SOD | Complete approval closure, exact head/config, distinct reviewer, recheck at commit/Release. | Self/Agent approval, stale validation/config, comment/UI state, disabled role, approval substitution. |
| PostgreSQL | Identical accepted/rejected observable traces, two-writer Release and revocation races, full retries. | Check-then-act gap, partial fact/evidence/projection/outbox, ambiguous-commit duplicate, migration fabrication. |
| Artifact/outbox | No reference or worker visibility before commit; signed bytes atomic with state; read-back integrity; stable at-least-once delivery. | Signed pre-commit orphan/fork, neutral-orphan exposure, missing/substituted committed blob, duplicate changed payload, stale lease ack, out-of-order regression, exactly-once claim. |
| Preview | Exact immutable Release snapshot and monotonic alias. | Current-at-worker lookup, partial snapshot, lower-sequence overwrite, delivery reported as Release commit. |
| Export/verifier | Clean offline verification of the exact logical member map with separate `VerificationTrustPolicyV2`, checkpoints, and external bytes. | Nonempty producer hints, archive/container reinterpretation, arbitrary URL fetch, unauthenticated snapshot/readiness reported verified, wrong-kind digest alias, session treated as Proof trust. |
| Rebuild/migration | Exact chain/state digest, atomic generation swap, retryable phase recovery. | Partial generation, checksum mismatch, unknown Schema, historical byte rewrite. |

The server threat suite additionally covers hostile forwarded headers, OIDC
mix-up and JWKS SSRF, session and token replay, database/operator rollback,
outbox injection, artifact substitution, webhook/event replay and SSRF,
resource enumeration, bounded denial of service, and alternate-Workspace
spoofing. A server adapter, worker, UI, or delivery adapter fails the profile if
it can write authoritative state without an application operation.

## Strongest rejected decomposition

The strongest alternative splits identity, workflow, publication, evidence,
and delivery into independently deployed services joined by an event bus. A
thinner variant puts a generic HTTP/ORM façade over PostgreSQL and treats UI
review state as workflow truth.

Both provide early team autonomy and independent scaling. They are rejected for
the first single-Workspace slice because the accepted authority presentation,
decision, content consequence, successful idempotency, Release/Proof,
projection, and outbox enqueue form one atomic boundary. Distributed
choreography would require compensation or a cross-service transaction before
scale or ownership evidence justifies either. A generic façade would create an
HTTP-only mutation path and make database/UI state privileged.

The selected modular server is killed or pivoted before implementation if its
contracts cannot express a current operation without adapter privilege, cannot
atomically preserve the P-0004/P-0005 evidence boundary, require UI state to
satisfy approval, or require external publication before database commit. A
later extraction ADR becomes justified by measured write-head contention,
unmet latency/throughput objectives, independently required security isolation,
or stable team/deployment ownership—not speculation.

## Successor order after owner acceptance

No implementation successor existed or became ready while P-0008 was in
review. After owner acceptance, create only decision-complete items in
this dependency order, promoting one at a time:

1. **Remote actor and shared contract conformance:** implement the remote Human
   binding/context, causal approval/configuration contracts, registries, and a
   deterministic identity/application oracle without a live provider.
2. **PostgreSQL parity foundation:** implement migration/import, durable
   authoritative transaction, idempotency, projection, artifact catalog, and
   enqueue adapters against the shared oracle.
3. **HTTP/OIDC server boundary:** implement strict routes, same-origin BFF,
   sessions, dual Human-plus-Agent authentication, and abuse cases against a
   deterministic issuer before a provider integration.
4. **Artifact/outbox/private preview:** implement staging, worker leases,
   at-least-once preview delivery, poison management, and private exact-locale
   reads.
5. **Remote evidence and Milestone 3 qualification:** implement bundle v2 and
   independent verification, then run the complete local/server north star and
   security/crash matrix.

Only the first dependency-ready item is promoted after acceptance. SDKs,
console, provider selection/provisioning, deployment, public preview,
workload identity, KMS/HSM, backup/restore, HA, multi-region operation,
multi-Workspace tenancy, and public release remain fog.

## Standards basis

The identity and browser rules are based on
[OpenID Connect Core 1.0, second errata](https://openid.net/specs/openid-connect-core-1_0-errata2.html),
[OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html),
[OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700),
and the [OAuth browser-application BFF profile](https://www.rfc-editor.org/rfc/rfc10017.html).
HTTP conditionals and Problems follow
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) and
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457).

The storage contract relies on PostgreSQL's documented
[Serializable isolation](https://www.postgresql.org/docs/18/transaction-iso.html),
[complete-transaction retry rules](https://www.postgresql.org/docs/18/mvcc-serialization-failure-handling.html),
[explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html), and
[`SELECT ... SKIP LOCKED`](https://www.postgresql.org/docs/18/sql-select.html)
semantics. The non-rollback sequence prohibition, lease clock, migration lock,
durability preconditions, and nontransactional index phase are grounded in
[sequence behavior](https://www.postgresql.org/docs/18/functions-sequence.html),
[date/time functions](https://www.postgresql.org/docs/18/functions-datetime.html),
[advisory locks](https://www.postgresql.org/docs/18/explicit-locking.html#ADVISORY-LOCKS),
[WAL settings](https://www.postgresql.org/docs/18/runtime-config-wal.html), and
[`CREATE INDEX CONCURRENTLY`](https://www.postgresql.org/docs/18/sql-createindex.html#SQL-CREATEINDEX-CONCURRENTLY).
These references constrain the adapter; they do not make a provider or
PostgreSQL major version an accepted implementation choice.

## Decision record and reopen conditions

The accepted durable decision is [ADR-0013](../decisions/0013-single-workspace-collaboration-server.md).
Reopen it before implementation if the first remote Agent must run unattended,
more than one issuer or Workspace is required, public/anonymous preview enters
scope, approval needs quorum/revocation/multiple stages, arbitrary webhook
destinations are required, object-store staging cannot provide the stated
durability contract, or the single Workspace write lane cannot satisfy an
accepted measured objective.
