# P-0025 HTTP operation-envelope decision candidate

Status: **candidate — project-owner acceptance required**.

This candidate is grounded in repository state at claim base
`41364224e4fba87964da8c0974535330eba18195`. File-and-line references name
that tree unless the referenced file is this candidate.

## Recommendation

Make the already-frozen
`conformance/v1/collaboration-server/schemas/http-envelope-v1.schema.json`
representation authoritative for `proof.dev/http-*-operation-request/v1` and
`proof.dev/http-operation-result/v1`. P-0022 should repair the Rust server and
`proof-sdk` atomically to that representation. It should not accept both wire
shapes and should not introduce an envelope v2.

The current Rust/SDK representation is an internal implementation defect, not
a second compatibility profile. The server is undeployed, `proof-sdk` is
unpublished, the repository is private, and the two retained request vectors
already use the Schema-authoritative form. Existing committed authority,
application-result, idempotency, and evidence bytes contain no HTTP success
envelope and require no migration.

## Decision basis and source inventory

The documentation precedence rule puts accepted ADRs first. ADR-0013 adopts
the frozen collaboration-server profile as the server boundary
(`docs/README.md:69-78` and
`docs/decisions/0013-single-workspace-collaboration-server.md:32-37`). The
profile explicitly freezes the two-stage Human request cross-check and the
`data`/`result_anchor`/`result_schema` success form
(`conformance/v1/collaboration-server/README.md:391-405`). Its retained Human
and Agent examples conform to that shape:

- `conformance/v1/collaboration-server/vectors/http-human-operation.valid.json`
  carries all six required Human members and duplicates the application key;
- `conformance/v1/collaboration-server/vectors/http-agent-operation.valid.json`
  carries only the four Agent members and keeps Workspace/key/input inside the
  signed invocation; and
- `conformance/v1/collaboration-server/schemas/http-envelope-v1.schema.json:57-132`
  closes the exact requests, result, and anchor.

The accepted implementation history diverged without changing those frozen
artifacts. P-0011 reported zero frozen-vector changes while claiming strict
input (`docs/work/evidence/P-0011/receipt.md:40-54,115-125`). P-0017 then
described the SDK as wire-exact and pinned to Rust handler shapes
(`docs/work/evidence/P-0017/receipt.md:45-63`). The executable surfaces instead
show the following:

- `crates/proof-server/src/routes.rs:53-64,459-604` uses one union allowlist for
  both routes, treats several required members as optional, and does not check
  the envelope `api_version` or Human top-level application key;
- `crates/proof-server/src/dispatch.rs:394-426,622-734,842-851` serializes
  `result`/`committed_anchor`, omits `replayed` and `result_schema`, and uses an
  authority-head/result-digest object instead of the closed anchor union;
- `web/packages/proof-sdk/src/types.ts:221-285` makes request members optional,
  admits `workspace_id` on Agent requests, and models the runtime success form;
  and
- `web/packages/proof-sdk/src/client.ts:121-178` emits and consumes that SDK
  form. Its result type still assumes an application consequence even though
  P-0021 split several exact typed results from persisted consequence evidence.

The retained tests faithfully exercise the divergent implementation rather
than reconciling it: `crates/proof-server/tests/dispatch_impl.rs:625-668`,
`crates/proof-server/tests/ts_sdk_contract.rs:180-205`, and
`web/packages/proof-sdk/test/wire.spec.ts:9-43`.

The remaining required inventory does not establish a third accepted wire
shape:

- P-0008 created and qualified the closed envelope Schema and both request
  vectors as part of its 14-Schema/39-vector decision candidate
  (`docs/work/evidence/P-0008/receipt.md:36-49,59-81`). Its implementation
  rejection plan did not qualify emitted server bytes.
- P-0020 changes operation inputs, results, and registry rows but never changes
  or interprets the HTTP envelope (`docs/work/evidence/P-0020/contract.md:168-181`).
- `docs/quickstart.md:40-54` names the Human route and Origin/CSRF requirements
  but serializes no request or success body, so it needs no compatibility
  migration.
- `web/packages/proof-sdk/README.md:1-50` explicitly follows Rust rather than
  the frozen envelope Schema and returns a consequence-shaped value; P-0022
  must correct that documentation with the SDK.
- `web/src/api/client.ts:84-124` sends raw operation input and reads
  `payload.result`. `web/src/mocks/handlers.ts:21-39` uses a console-only
  `{outcome:"committed",result}` feature projection and a 204 logout. P-0022
  corrects session/logout transport only; P-0023 retains ownership of feature
  transport and feature mock migration.

## Field-by-field conflict matrix

### Human request

| Member or rule | Frozen v1 Schema | Current Rust/SDK | Decision |
| --- | --- | --- | --- |
| `api_version` | Required exact Human v1 tag | SDK emits it; Rust does not require or compare it | Required and exact |
| `workspace_id` | Required UUIDv7 | Rust cross-checks only a supplied string; SDK option may omit it | Required expected-value cross-check against the deployment/session Workspace; never a selector |
| `operation` | Required closed name/version object | Required and route-cross-checked | Required; route, path, registry row, and body pair must agree |
| `correlation_id` | Required UUIDv7 or `null` | Omission and non-string values collapse to absence; SDK omits by default | Required member; exact UUIDv7 or `null`; response echoes it |
| `idempotency_key` | Required UUIDv7 or `null` | Accepted by the union allowlist but ignored; SDK cannot emit it | Required; exact `input.idempotency_key` for `required-uuidv7`, otherwise `null` |
| `input` | Required object, then exact row-Schema validation | Missing becomes JSON null; SDK requires a generic typed value | Required object; validate against the exact route-qualified row |
| Unknown/other-route members | Rejected by `additionalProperties:false` | Shared allowlist admits ignored `invocation` and other Agent members | Reject before application execution |

There are currently only `required-uuidv7` and `none` Human rows. A future
derived Human application-key class needs a separately ratified envelope rule;
it cannot overload the v1 UUID-or-null member.

### Agent request

| Member or rule | Frozen v1 Schema | Current Rust/SDK | Decision |
| --- | --- | --- | --- |
| `api_version` | Required exact Agent v1 tag | SDK emits it; Rust does not require or compare it | Required and exact |
| `operation` | Required closed name/version object | Required; Rust cross-checks route, invocation, signature, and registry | Preserve all equality checks |
| `correlation_id` | Required UUIDv7 or `null` | Optional; non-string values collapse to absence | Required member; exact UUIDv7 or `null`; response echoes it |
| `invocation` | Required exact `AuthenticatedInvocationV1` | Required and deserialized | Required; signed command remains the only Agent Workspace/key/input carrier |
| `workspace_id` | Forbidden | Shared Rust allowlist ignores it; SDK explicitly permits it | Forbidden |
| `idempotency_key` / `input` | Forbidden | Shared Rust allowlist can ignore them | Forbidden; the signed invocation is authoritative |
| Unknown/other-route members | Rejected by `additionalProperties:false` | Shared allowlist is wider than this route | Reject before application execution |

### Successful operation result

| Member | Frozen v1 Schema | Current Rust/SDK | Decision |
| --- | --- | --- | --- |
| `api_version` | Required exact result v1 tag | Same tag | Preserve |
| `operation` | Required exact pair | Present | Preserve exact route-qualified pair |
| `operation_id` | Required UUIDv7 | Present | New server UUIDv7 for every attempt, including replay |
| `correlation_id` | Required UUIDv7 or `null` | Rust emits nullable; request may omit | Always present and equal to the validated request member |
| `replayed` | Required boolean | Absent | `true` only for a committed idempotent replay; otherwise `false` |
| `result_anchor` | Required closed union | Absent | Required with the exact semantics below |
| `result_schema` | Required Schema URI | Absent | Exact `result_schema` of the resolved route-qualified registry row |
| `data` | Required typed-result object | Named `result`; SDK often mis-types it as consequence evidence | Exact unchanged application result, validated before serialization |
| `committed_anchor` / `result` | Forbidden | Required by runtime/SDK | Remove; do not alias or emit alongside the canonical members |

### Result anchor

| Member or variant | Frozen v1 Schema | Current Rust/SDK | Decision |
| --- | --- | --- | --- |
| `kind` | `committed-transaction` or `immutable-result` | Absent | Required discriminator |
| `digest` | Required BLAKE3 digest | Runtime uses nullable `result_digest` | Exact `proof:operation-effect:v1` digest of RFC 8785 canonical `data`; never null on success |
| `transaction_sequence` | Positive safe integer or `null` by variant | Absent | Current attempt's committed Workspace transaction sequence for `committed-transaction`; `null` only for `immutable-result` |
| Runtime `authority_head` | Absent | Required nested object | Remove from the HTTP anchor; signed consequence/evidence retains authority heads |
| Runtime `result_digest` | Absent | Nullable member | Rename to non-null `digest` with the rule above |

Every currently registered authenticated Human or Agent operation commits at
least its current authorization decision and consequence. It therefore uses
`kind:"committed-transaction"`, including no-key reads and idempotent replay.
For replay, `digest` binds the returned prior `data`, while
`transaction_sequence` names the current attempt that committed the new
decision and replay consequence. `replayed` is `true`.

`kind:"immutable-result"` is reserved for a future registry-qualified result
that performs no authoritative transaction. No current Human or Agent row may
select it. Adding such a row requires an explicit registry and execution rule;
the server may not infer the variant from missing data.

## Non-negotiable invariants

This envelope decision changes presentation plumbing only. P-0022 must retain
all of the following:

1. Strict I-JSON parsing, duplicate-name rejection, route-specific unknown
   member rejection, the raw 1 MiB limit, and the independently applied
   canonical 1 MiB limit.
2. The deployment and authenticated session derive the Workspace and Human;
   the verified invocation derives the Agent. Request members are equality
   guards, never authority selectors.
3. Fresh authentication and current locked-head authorization precede every
   idempotency lookup or prior-result disclosure.
4. A Human top-level key is only a duplicate cross-check. The normalized typed
   input remains the semantic source; an Agent key remains inside its fresh
   signed invocation.
5. Application keys remain unique in the Workspace-global
   `(workspace_id, application_key)` namespace across Human/Agent routes and
   operation pairs. No route, actor, or operation prefix narrows that key.
6. The exact route-qualified registry row selects the input Schema, result
   Schema, authorization, idempotency class, Problems, and effect rule.
7. `data` is the typed application result, not the signed
   `RemoteApplicationConsequenceV1`. Evidence persists the consequence
   separately and continues to bind the same result digest.
8. No success leaves the server before the authoritative attempt commits.

## Options and effects

| Effect | A — Frozen Schema authoritative | B — Rust wire authoritative | C — New major and transition |
| --- | --- | --- | --- |
| Compatibility | Breaks only the private, unpublished internal runtime shape; restores accepted v1 | Preserves current internal callers but silently rewrites accepted v1 | Preserves both shapes during a bounded window |
| Security | Restores route-specific closure and mandatory Workspace/key equality guards | Can be hardened, but optional/omitted cross-checks and implicit replay remain the baseline | Can be strict, but dual parsing adds downgrade and ambiguity surface |
| Implementation | Moderate server metadata plumbing plus SDK/test migration | Smallest runtime change; larger contract/evidence rewrite | Largest: new tags, negotiation/routing, dual tests, removal plan |
| Conformance/vector | Existing Schema and two request vectors stay byte-identical; add one valid result vector | Mutates a consumed frozen Schema and invalidates its recorded artifact digest | Adds a parallel Schema/vector family and transition fixtures |
| Hashes | All three registry commitments stay unchanged | Registry hashes may misleadingly stay unchanged because rows reference the same mutated Schema URI | Complete HTTP registry hash likely changes; authorization and Agent hashes must remain stable |
| SDK | One exact v1 migration; generic typed `data` | Minimal member churn but retains weak discoverability/replay typing | Version selection, compatibility types, and deprecation surface |
| Console | Session/logout adoption remains bounded; feature mocks wait for P-0023 | Same | Must choose a version and carry transition configuration |
| Documentation | Clarifies the already-adopted ADR/profile | Rewrites the ADR/profile around implementation drift | Documents support window, downgrade behavior, and removal date |
| Rollout | One atomic repository migration; no shim | One atomic Schema/evidence mutation | Multi-phase rollout despite no installed base |

## Decision crux, counterargument, and reversal trigger

The decision crux is whether an installed base justifies overriding the
accepted machine-readable contract. It does not: no deployment, published SDK,
package release, or public API exists, while the accepted ADR, closed Schema,
and retained request vectors all agree. Option A therefore repairs drift at
the cheapest point in the product lifecycle and keeps one v1 meaning.

The strongest counterargument is that the Rust server and SDK have much more
runtime test coverage than the unexercised success Schema. Option A must plumb
the actual Workspace transaction sequence through several executors and could
introduce an anchor bug merely to honor a contract that no client has used.
That cost is real, but it is bounded and directly testable; allowing
implementation coverage to rewrite frozen contracts would make conformance
evidence non-authoritative.

Reopen this decision before P-0022 lands only if either:

- evidence identifies a deployed or published v1 consumer whose coordinated
  migration is impossible; or
- implementation proves the current committed Workspace transaction sequence
  cannot be exposed without changing persisted transaction semantics.

Either trigger selects Option C for explicit versioning. It never authorizes a
silent mutation of v1 or a permanent dual-shape v1 parser.

## Compatibility and migration rule

P-0022 performs one atomic cutover:

1. Keep the envelope Schema and retained Human/Agent request vectors
   byte-for-byte.
2. Add one retained valid operation-result vector and validate all three
   envelope forms through the existing conformance harness.
3. Make Rust admission route-specific and enforce all required, nullable, and
   forbidden members plus Human Workspace/key cross-checks before execution.
4. Serialize only the Schema-authoritative success members and validate `data`
   against the resolved row `result_schema` before returning it.
5. Update `proof-sdk`, Rust tests, SDK wire tests, and documentation in the same
   candidate. Reject the old shape; emit no aliases.
6. Preserve historical commits and evidence as historical observations. Do
   not relabel their runtime envelope as conforming and do not rewrite stored
   consequences or application-result bytes.

There is no support window because there is no released consumer. If that
premise changes before implementation, the reversal trigger applies.

## P-0022 implementation surface

P-0022 must update:

- server admission and serialization in `crates/proof-server/src/routes.rs`,
  `crates/proof-server/src/dispatch.rs`, and the minimum execution plumbing in
  `crates/proof-server/src/operations.rs` needed to return replay state, result
  digest, result Schema, and committed transaction sequence;
- exact server tests in `routes_impl.rs`, `dispatch_impl.rs`, `e2e_impl.rs`,
  `authz_operations_impl.rs`, `conformance_report_impl.rs`,
  `north_star_remote_impl.rs`, and `smoke.rs`;
- the cross-language gate in `crates/proof-server/tests/ts_sdk_contract.rs`;
- `web/packages/proof-sdk/src/types.ts`, `client.ts`, `registry.ts`, exports,
  `test/wire.spec.ts`, compile-fail fixtures, and its README;
- one new retained valid result vector, the collaboration-profile inventory,
  and `crates/proof-local/tests/p0008_collaboration_contract.rs`; and
- console SDK configuration, session/logout consumers, and only the
  session/logout MSW handlers and tests authorized by P-0022.

P-0025 itself updates this contract candidate,
`docs/architecture/collaboration-server.md`, ADR-0013, and the P-0022 work item.
After owner acceptance those references become normative; P-0022 updates the
SDK README and any examples it directly invalidates.

P-0022 must leave unchanged:

- `http-envelope-v1.schema.json`, both existing request vectors, all operation
  input/result Schemas, the nine routes, status codes, and Problem tuples;
- all 14 Agent authority pairs and all 43 complete HTTP registry rows;
- `COMPLETE_HTTP_OPERATION_REGISTRY_SHA256`
  `6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`,
  `REMOTE_AUTHORIZATION_PROJECTION_SHA256`
  `d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`,
  and `AGENT_AUTHORITY_REGISTRY_SHA256`
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`;
- PostgreSQL/SQLite schema, Workspace-global idempotency records, signed
  decisions/consequences, application results, CLI, and MCP semantics; and
- `docs/quickstart.md`, which contains route/authentication guidance but no
  serialized operation envelope; and
- existing console feature screens, feature-operation transport, and feature
  MSW handlers. Their migration belongs to P-0023; P-0022 owns session/logout
  transport only.

Any required change to an item in the unchanged list is a reshape trigger, not
implicit P-0022 scope.

## Owner verdict gate

No Rust, SDK, console, mock, Schema, or vector implementation begins from this
candidate. Project-owner acceptance makes Option A authoritative and permits
P-0022 to move from `blocked` to `ready` with this exact migration contract.
Rework keeps P-0022 blocked.
