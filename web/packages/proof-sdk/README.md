# proof-sdk

Typed TypeScript client over Proof's frozen collaboration-server HTTP surface
(the exact nine routes plus the four transport-session routes). The wire shapes
mirror the Rust sources field-for-field:

- The actor-qualified registries retain all 14 Agent pairs and expose the four
  P-0021 direct-Human authoring/read pairs.
- Request/result envelopes and Problem bodies mirror
  `crates/proof-server/src/{routes,dispatch}.rs` and
  the frozen collaboration-server Schemas.

`crates/proof-server/tests/ts_sdk_contract.rs` fails the Rust gate when either
side drifts.

## Usage

```ts
import { ProofClient } from "proof-sdk";

const client = new ProofClient({
  baseUrl: "https://proof.example.test",
  workspaceId: "019e0000-0000-7000-8000-000000000001",
  csrfToken: () => currentCsrfToken,
});

const session = await client.getSession();
const schemas = await client.executeHuman("schema.list:v1", {
  api_version: "proof.dev/operation/schema.list/v1",
  page_size: 25,
});
console.log(schemas.data.entries, schemas.result_schema, schemas.replayed);

const status = await client.executeAgent(
  "workspace.status:v1",
  freshSignedInvocation,
);
console.log(status.data.storage_schema_version);

await client.logout(); // proof-csrf + Origin; exact HTTP 200 JSON result
```

Every rejection surfaces as a `ProblemError` carrying the server's stable
Problem body verbatim (`code`, `status`, `retryable`, `retry_after_ms`);
failures before a Problem body can be read surface as `TransportError`.

Human and Agent calls are intentionally separate: a Human-only key cannot use
`executeAgent`, and an Agent-only key cannot use `executeHuman`. Agent
operations remain dual-authenticated (session plus a fresh signed invocation);
invocation signing itself stays with the caller's provisioning path. Every
operation call returns the accepted eight-member envelope with typed `data`,
the exact registry `result_schema`, replay state, and a closed result anchor.

## Development

```sh
pnpm install
pnpm --filter proof-sdk test        # wire-contract suite against stub transport
pnpm --filter proof-sdk typecheck
```
