# proof-sdk

Typed TypeScript client over Proof's frozen collaboration-server HTTP surface
(the exact nine routes plus the four transport-session routes). The wire shapes
mirror the Rust sources field-for-field:

- Operation registry and inputs mirror
  `crates/proof-application/src/authority.rs`.
- Request/response envelopes, consequences, and Problem bodies mirror
  `crates/proof-server/src/{routes,dispatch}.rs` and
  `crates/proof-remote/src/registry.rs`.

`crates/proof-server/tests/ts_sdk_contract.rs` fails the Rust gate when either
side drifts.

## Usage

```ts
import { ProofClient } from "proof-sdk";

const client = new ProofClient({
  baseUrl: "https://proof.example.test",
  csrfToken: () => currentCsrfToken,
});

const session = await client.getSession();
const consequence = await client.execute("workspace.status:v1", {});
await client.execute("release.create:v2", {
  api_version: "proof.dev/operation/release.create/v2",
  edition_id: "...",
  environment_id: "preview",
  expected_base_release_id: "...",
  idempotency_key: "...",
  proof_id: "...",
  release_id: "...",
  released_at: "2026-08-25T00:00:00Z",
});
```

Every rejection surfaces as a `ProblemError` carrying the server's stable
Problem body verbatim (`code`, `status`, `retryable`, `retry_after_ms`);
failures before a Problem body can be read surface as `TransportError`.

Agent operations are dual-authenticated (session plus fresh signed invocation).
The client carries that transport exactly — `executeAgent(name, major,
{ invocation })` — while invocation signing itself stays with the caller's
provisioning path.

## Development

```sh
pnpm install
pnpm --filter proof-sdk test        # wire-contract suite against stub transport
pnpm --filter proof-sdk typecheck
```
