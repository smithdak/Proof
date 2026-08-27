# P-0025 decision qualification receipt

[Back to the work item](../../items/P-0025-ratify-http-operation-envelope.md)

## Result

P-0025 candidate `1c76c0a26957e4a5f101236a5bb3bcd21ed539e3`
is decision-complete and eligible for project-owner review. It recommends
making the already-frozen HTTP envelope Schema authoritative and repairing the
private Rust server and unpublished TypeScript SDK atomically in P-0022. It
rejects a dual-format v1 parser and does not introduce an envelope v2.

Project-owner acceptance has not occurred. The architecture and ADR additions
are explicitly marked as a non-effective review candidate, P-0025 remains in
`review`, and P-0022 remains `blocked`. No Rust, SDK, console, mock, Schema, or
vector implementation is included in this candidate.

## Qualified candidate

| Field | Exact value |
| --- | --- |
| Claim base | `41364224e4fba87964da8c0974535330eba18195` |
| Claim commit / candidate parent | `61cc6886fc4287ae9100256fd0af2fdb67ab3ad6` |
| Item-work candidate | `1c76c0a26957e4a5f101236a5bb3bcd21ed539e3` |
| Candidate tree | `85358d68a029a7a8dd9541d23c0b60eccb5ec138` |
| Qualified at | `2026-08-27T17:27:56.000Z` |
| Candidate delta | 4 files; 479 insertions; 51 deletions |

The candidate contains the complete field/source/option analysis in
[contract.md](contract.md), explicitly pending architecture/ADR text, and the
exact P-0022 implementation shape. This receipt and `manifest.json` were
created afterward so the manifest can bind the immutable item-work candidate
without self-reference.

## Recommended contract

- Human requests have exactly the six required members `api_version`,
  `workspace_id`, `operation`, `correlation_id`, `idempotency_key`, and `input`.
  Correlation and key members are present and nullable; Workspace and key are
  expected-value guards after trusted derivation.
- Agent requests have exactly the four required members `api_version`,
  `operation`, `correlation_id`, and `invocation`. Top-level Workspace, key, and
  input are forbidden; the fresh signed invocation carries them.
- Success has exactly `api_version`, `operation`, `operation_id`,
  `correlation_id`, `replayed`, `result_anchor`, `result_schema`, and typed
  `data`. The old `result` and `committed_anchor` members are forbidden.
- Every current authenticated operation uses a `committed-transaction` anchor.
  Its digest is the `proof:operation-effect:v1` digest of RFC 8785 canonical
  `data`, and its positive safe-integer sequence names the current committed
  Workspace attempt. Replay binds prior data, names the new replay transaction,
  and sets `replayed:true`.
- `immutable-result` stays reserved for a future explicitly qualified
  no-transaction registry rule. No current row infers it.

Fresh authentication and current locked-head authorization continue to precede
idempotency lookup or prior-result disclosure. Application keys remain unique
in the Workspace-global `(workspace_id, application_key)` namespace across
Human/Agent routes and operation pairs.

## Option and compatibility result

The candidate evaluates all three required choices across compatibility,
security, implementation, conformance/hash, SDK, console, documentation, and
rollout effects. Option A is recommended because the accepted ADR, closed
Schema, and retained request vectors agree, while no deployed, published, or
public consumer depends on the internal runtime shape.

The strongest counterargument is the runtime shape's greater executable test
coverage and the additional transaction-sequence plumbing Option A requires.
The reversal trigger is concrete: evidence of a consumer that cannot be
coordinated, or proof that exposing the current sequence would change persisted
transaction semantics, reopens the decision in favor of an explicit new major.
Neither trigger permits silent v1 mutation or a permanent dual-shape parser.

Existing idempotency result bodies, consequences, evidence, and database rows
contain no HTTP success envelope, so no stored-data migration is required.
P-0022 performs the single atomic repository cutover after acceptance.

## Qualification

| Command | Exit |
| --- | --- |
| `node scripts/check-work-items.mjs` | 0 (23 items) |
| `node scripts/check-doc-links.mjs` | 0 (447 links after the review transition; 442 at the immutable candidate) |
| `git diff --check` | 0 |
| `npx markdownlint-cli2 --no-globs` over the seven P-0025 changed documents | 0 |

This is a documentation/decision item, so Rust, SDK, browser, and persistence
tests are intentionally deferred to P-0022's accepted implementation contract.

## Artifact and registry commitments

| Candidate artifact | Git blob | SHA-256 |
| --- | --- | --- |
| `docs/work/evidence/P-0025/contract.md` | `b7dcc9a9f33a5fd25b11e00ed0d096ff2da05da6` | `1396d78e622c856eabdef9e776901a5d78dfb4387ada8b88eb747e4a47b09984` |
| `docs/architecture/collaboration-server.md` | `ebabecb362b86609571596491aaabc7a87e2ed13` | `ec576b3b7f28bd8bcb4d735b050959ce635098733561f10bb59faf10e1bc9e96` |
| `docs/decisions/0013-single-workspace-collaboration-server.md` | `1172841ebeb51b4f35842dc2ec22f85b5488b394` | `7eb4c3f9b35e49c9cb47d2626653e8c908638c1f356ac5bbc654732964a36e55` |
| `docs/work/items/P-0022-sdk-authoring-adoption.md` | `03bdb35c50008e140964e37a1cf11edba29ecc78` | `cc09fd99cbf3e82cac718935f3230bd4527233a8d9dbaad60b328a542030e15e` |

The candidate changes no registry or frozen conformance bytes. The retained
commitments are:

- complete HTTP registry:
  `6f24ba1cb34e6c024070034c57cabb0dcc3db288a5ae8666fa1dcce0b6fc28ca`;
- authorization projection:
  `d440f8e787099fb8f4a8c1da2ce0f07bbcc51c2ad636ed4dc597bb381a79f171`;
  and
- Agent authority registry:
  `b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7`.

## Residual boundary and owner gate

- The runtime and SDK still implement the conflicting shape. That is expected
  until the project owner accepts this decision and P-0022 becomes `ready`.
- Console feature-operation transport and feature mocks remain P-0023 scope;
  P-0022 owns console session/logout transport only.
- The no-installed-base premise is documented and guarded by the reversal
  trigger rather than treated as permanent fact.
- No push, tag, deployment, package publication, public release, credential
  mutation, or external-provider action occurred.

The required next action is an explicit project-owner accept-or-rework verdict
on candidate `1c76c0a26957e4a5f101236a5bb3bcd21ed539e3`.
