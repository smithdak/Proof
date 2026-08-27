import { describe, expect, it, vi } from "vitest";
import { ProofClient } from "../src/client";
import { ProblemError, TransportError } from "../src/errors";
import {
  resolveAgentOperation,
  resolveHumanOperation,
  type OperationPair,
} from "../src/registry";
import type {
  AgentOperationKey,
  ContentResourceIntentIssueInputV2,
  ContentResourceIntentV2,
  HumanOperationInputByPair,
  HumanOperationKey,
  HumanOperationResultByPair,
  ObjectListResultV1,
  ProblemBody,
  SchemaGetResultV1,
  SchemaListResultV1,
  SessionInfo,
  SuccessEnvelope,
  WorkspaceStatusResultV1,
} from "../src/types";

interface RecordedRequest {
  url: string;
  init: RequestInit;
}

function stubFetch(responseBodies: Array<{ status: number; body?: unknown }>) {
  const requests: RecordedRequest[] = [];
  let call = 0;
  const fetchImpl = vi.fn(
    async (input: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(input), init: init ?? {} });
      const next = responseBodies[Math.min(call, responseBodies.length - 1)];
      call += 1;
      if (!next) {
        throw new Error("stub fetch exhausted");
      }
      return new Response(
        next.body === undefined ? undefined : JSON.stringify(next.body),
        {
          status: next.status,
          headers: { "Content-Type": "application/json" },
        },
      );
    },
  );
  return { fetchImpl, requests };
}

const BASE = "https://proof.example.test";
const WORKSPACE_ID = "019e0000-0000-7000-8000-000000000001";
const CORRELATION_ID = "019e0000-0000-7000-8000-000000000002";

function successEnvelope<T>(
  pair: OperationPair,
  data: T,
  replayed = false,
): SuccessEnvelope<T> {
  return {
    api_version: "proof.dev/http-operation-result/v1",
    operation: { name: pair.name, version: pair.version },
    operation_id: "019e0000-0000-7000-8000-000000000003",
    correlation_id: CORRELATION_ID,
    replayed,
    result_anchor: {
      kind: "committed-transaction",
      digest: "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      transaction_sequence: replayed ? 12 : 11,
    },
    result_schema: pair.resultSchema,
    data,
  };
}

function client(fetchImpl: typeof fetch) {
  return new ProofClient({
    baseUrl: BASE,
    fetchImpl,
    origin: "https://console.example.test",
    csrfToken: () => "sync-token",
    workspaceId: WORKSPACE_ID,
  });
}

describe("ProofClient session routes", () => {
  it("reads the exact session representation with credentials", async () => {
    const session: SessionInfo = {
      api_version: "proof.dev/session-get-result/v1",
      cache_control: "private, no-store",
      csrf_token: "csrf-value",
      principal_id: "019e0000-0000-7000-8000-000000000010",
      authenticated_at: "2026-08-27T12:00:00Z",
      idle_expires_at: "2026-08-27T13:00:00Z",
      expires_at: "2026-08-28T12:00:00Z",
    };
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: session }]);
    await expect(client(fetchImpl).getSession()).resolves.toEqual(session);
    expect(requests[0]).toMatchObject({
      url: `${BASE}/api/v1/session`,
      init: { credentials: "include" },
    });
  });

  it("posts logout with Origin, proof-csrf, and the exact HTTP 200 result", async () => {
    const result = {
      api_version: "proof.dev/session-logout-result/v1",
      logged_out: true,
    } as const;
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: result }]);
    await expect(client(fetchImpl).logout()).resolves.toEqual(result);
    expect(requests[0]?.url).toBe(`${BASE}/api/v1/session/logout`);
    expect(requests[0]?.init).toMatchObject({
      method: "POST",
      credentials: "include",
      body: "{}",
    });
    expect(requests[0]?.init.headers).toEqual({
      "Content-Type": "application/json",
      Accept: "application/json",
      Origin: "https://console.example.test",
      "proof-csrf": "sync-token",
    });
  });

  it("rejects the retired 204 logout assumption", async () => {
    const { fetchImpl } = stubFetch([{ status: 204 }]);
    await expect(client(fetchImpl).logout()).rejects.toBeInstanceOf(TransportError);
  });

  it("builds the OIDC login URL with a return path", () => {
    const proof = new ProofClient({ baseUrl: BASE, fetchImpl: globalThis.fetch });
    expect(proof.loginUrl("/changesets")).toBe(
      `${BASE}/auth/oidc/login?return_to=%2Fchangesets`,
    );
  });
});

const intentInput: ContentResourceIntentIssueInputV2 = {
  api_version: "proof.dev/operation/content-resource-intent.issue/v2",
  environment_id: "preview",
  idempotency_key: "019e0000-0000-7000-8000-000000000020",
  intent_id: "019e0000-0000-7000-8000-000000000021",
  issued_at: "2026-08-27T12:00:00Z",
  targets: [
    {
      locale: "en-US",
      object_id: "019e0000-0000-7000-8000-000000000022",
      schema_id: "article",
    },
  ],
  creations: [
    {
      locales: ["en-US"],
      object_id: "019e0000-0000-7000-8000-000000000023",
      schema_id: "article",
    },
  ],
};

const intentResult: ContentResourceIntentV2 = {
  api_version: "proof.dev/content-resource-intent/v2",
  workspace_id: WORKSPACE_ID,
  environment_id: "preview",
  intent_id: intentInput.intent_id,
  issued_at: intentInput.issued_at,
  issued_by_principal_id: "019e0000-0000-7000-8000-000000000024",
  targets: intentInput.targets,
  creations: intentInput.creations!,
  base: {
    edition: {
      api_version: "proof.dev/edition/v2",
      digest: "blake3:edition",
      edition_id: "019e0000-0000-7000-8000-000000000025",
    },
    known_state: {
      api_version: "proof.dev/known-state/v2",
      authoritative_sequence: 8,
      digest: "blake3:state",
    },
    release: {
      api_version: "proof.dev/release/v2",
      digest: "blake3:release",
      release_id: "019e0000-0000-7000-8000-000000000026",
    },
  },
};

const schemaGetResult: SchemaGetResultV1 = {
  schema_id: "article",
  schema_version: 1,
  document: { type: "object" },
  document_digest: "blake3:schema",
  provenance: {
    authoritative_sequence: 9,
    changeset_id: "019e0000-0000-7000-8000-000000000030",
    edit_id: "019e0000-0000-7000-8000-000000000031",
  },
};

const schemaListResult: SchemaListResultV1 = {
  entries: [
    {
      schema_id: schemaGetResult.schema_id,
      schema_version: schemaGetResult.schema_version,
      document_digest: schemaGetResult.document_digest,
      provenance: schemaGetResult.provenance,
    },
  ],
};

const objectListResult: ObjectListResultV1 = {
  state_scope: "committed-workspace-state-not-necessarily-released",
  entries: [
    {
      object_id: "019e0000-0000-7000-8000-000000000040",
      schema_id: "article",
      schema_version: 1,
      released_revision: null,
      covered_by_current_release: false,
      head_renditions: [
        { locale: "en-US", rendition_digest: "blake3:rendition", revision: 1 },
      ],
    },
  ],
};

const humanCases: Array<{
  key: HumanOperationKey;
  input: HumanOperationInputByPair[HumanOperationKey];
  data: HumanOperationResultByPair[HumanOperationKey];
  topLevelKey: string | null;
}> = [
  {
    key: "content-resource-intent.issue:v2",
    input: intentInput,
    data: intentResult,
    topLevelKey: intentInput.idempotency_key,
  },
  {
    key: "schema.get:v1",
    input: {
      api_version: "proof.dev/operation/schema.get/v1",
      schema_id: "article",
      schema_version: 1,
    },
    data: schemaGetResult,
    topLevelKey: null,
  },
  {
    key: "schema.list:v1",
    input: { api_version: "proof.dev/operation/schema.list/v1", page_size: 25 },
    data: schemaListResult,
    topLevelKey: null,
  },
  {
    key: "object.list:v1",
    input: {
      api_version: "proof.dev/operation/object.list/v1",
      environment_id: "preview",
    },
    data: objectListResult,
    topLevelKey: null,
  },
];

describe("ProofClient actor-qualified operations", () => {
  for (const row of humanCases) {
    it(`dispatches ${row.key} through the exact Human wire contract`, async () => {
      const pair = resolveHumanOperation(row.key);
      expect(pair).toBeDefined();
      if (!pair) return;
      const envelope = successEnvelope(pair, row.data);
      const { fetchImpl, requests } = stubFetch([{ status: 200, body: envelope }]);
      const result = await client(fetchImpl).executeHuman(
        row.key,
        row.input as never,
        { correlationId: CORRELATION_ID },
      );
      expect(result).toEqual(envelope);
      expect(result.result_schema).toBe(pair.resultSchema);
      expect(requests[0]?.url).toBe(
        `${BASE}/api/v1/human/operations/${pair.name}/v${pair.major}`,
      );
      expect(requests[0]?.init.credentials).toBe("include");
      expect(requests[0]?.init.headers).toEqual({
        "Content-Type": "application/json",
        Accept: "application/json",
        Origin: "https://console.example.test",
        "proof-csrf": "sync-token",
      });
      expect(JSON.parse(requests[0]?.init.body as string)).toEqual({
        api_version: "proof.dev/http-human-operation-request/v1",
        workspace_id: WORKSPACE_ID,
        operation: { name: pair.name, version: pair.version },
        correlation_id: CORRELATION_ID,
        idempotency_key: row.topLevelKey,
        input: row.input,
      });
    });
  }

  it("keeps the Agent route invocation-only at top level", async () => {
    const key: AgentOperationKey = "workspace.status:v1";
    const pair = resolveAgentOperation(key);
    expect(pair).toBeDefined();
    if (!pair) return;
    const data: WorkspaceStatusResultV1 = {
      workspace_id: WORKSPACE_ID,
      requesting_principal_id: "019e0000-0000-7000-8000-000000000050",
      operating_principal_id: "019e0000-0000-7000-8000-000000000051",
      delegation_id: "019e0000-0000-7000-8000-000000000052",
      storage_schema_version: 15,
      authoritative_sequence: 41,
      state_digest: "blake3:state",
      authorization_decision_digest: "blake3:decision",
    };
    const { fetchImpl, requests } = stubFetch([
      { status: 200, body: successEnvelope(pair, data) },
    ]);
    const invocation = { api_version: "proof.dev/authenticated-invocation/v1" };
    const result = await client(fetchImpl).executeAgent(key, invocation);
    expect(result.data.storage_schema_version).toBe(15);
    expect(requests[0]?.url).toBe(
      `${BASE}/api/v1/agent/operations/workspace.status/v1`,
    );
    expect(JSON.parse(requests[0]?.init.body as string)).toEqual({
      api_version: "proof.dev/http-agent-operation-request/v1",
      operation: { name: pair.name, version: pair.version },
      correlation_id: null,
      invocation,
    });
  });

  it("rejects a malformed success envelope instead of accepting an alias", async () => {
    const pair = resolveHumanOperation("schema.list:v1");
    if (!pair) throw new Error("missing pair");
    const malformed = {
      ...successEnvelope(pair, schemaListResult),
      committed_anchor: { digest: "blake3:old" },
    };
    const { fetchImpl } = stubFetch([{ status: 200, body: malformed }]);
    await expect(
      client(fetchImpl).executeHuman("schema.list:v1", {
        api_version: "proof.dev/operation/schema.list/v1",
      }),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("rejects an unregistered actor/pair before making a request", async () => {
    const { fetchImpl } = stubFetch([]);
    await expect(
      client(fetchImpl).executeHuman(
        // @ts-expect-error workspace.status is Agent-only.
        "workspace.status:v1",
        {},
      ),
    ).rejects.toThrow(/unregistered Human operation pair/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

function problem(code: string, operation: OperationPair): ProblemBody {
  return {
    api_version: "proof.dev/http-problem/v1",
    type: `urn:proof:problem:${code}`,
    title: code,
    status: 409,
    code,
    operation: { name: operation.name, version: operation.version },
    operation_id: "019e0000-0000-7000-8000-000000000060",
    correlation_id: null,
    retryable: false,
    instance: "urn:proof:operation:019e0000-0000-7000-8000-000000000060",
  };
}

describe("ProofClient frozen Problems", () => {
  for (const code of [
    "proof.schema.not_found",
    "proof.state.object_exists",
    "proof.intent.slot_mismatch",
  ]) {
    it(`preserves ${code} verbatim`, async () => {
      const pair = resolveHumanOperation("content-resource-intent.issue:v2");
      if (!pair) throw new Error("missing pair");
      const body = problem(code, pair);
      const { fetchImpl } = stubFetch([{ status: body.status, body }]);
      try {
        await client(fetchImpl).executeHuman(
          "content-resource-intent.issue:v2",
          intentInput,
        );
        throw new Error("expected a ProblemError");
      } catch (error) {
        expect(error).toBeInstanceOf(ProblemError);
        expect((error as ProblemError).problem).toEqual(body);
      }
    });
  }
});

describe("ProofClient delivery routes", () => {
  it("fetches a preview object through its exact route", async () => {
    const preview = {
      release_id: "019e0000-0000-7000-8000-000000000070",
      release_digest: "blake3:release",
      edition_digest: "blake3:edition",
      rendition_digest: "blake3:rendition",
      body: { title: "Summer campaign" },
    };
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: preview }]);
    const result = await client(fetchImpl).getPreviewObject(
      "preview",
      "r1",
      "o1",
      "fr-FR",
    );
    expect(result.rendition_digest).toBe("blake3:rendition");
    expect(requests[0]?.url).toBe(
      `${BASE}/preview/preview/releases/r1/objects/o1/locales/fr-FR`,
    );
  });
});
