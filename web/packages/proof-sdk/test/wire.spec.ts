import { afterEach, describe, expect, it, vi } from "vitest";
import { ProofClient } from "../src/client";
import { ProblemError, TransportError } from "../src/errors";
import type {
  ApplicationConsequence,
  SessionInfo,
  SuccessEnvelope,
} from "../src/types";

function consequenceEnvelope(): SuccessEnvelope {
  const consequence: ApplicationConsequence = {
    api_version: "proof.dev/application-consequence/v1",
    workspace_id: "019d0000000000000000000000000001",
    consequence_id: "019d0000000000000000000000000002",
    decision_id: "019d0000000000000000000000000003",
    decision_digest: "blake3:aa",
    public_input_projection_digest: "blake3:bb",
    operation: { name: "workspace.status", version: "proof.dev/operation/workspace.status/v1" },
    operation_registry_sha256: "sha256-registry",
    outcome: "Success",
    application_key_kind: "none",
    application_key: null,
    result_digest: null,
    prior_result_digest: null,
    application_effect_digest: null,
    application_effect_authority_head: null,
    problem_code: null,
    recorded_at: "2026-08-25T00:00:00Z",
    evaluated_authority_head: { sequence: 7, record_digest: "blake3:cc" },
    authority_sequence: 8,
    previous_authority_record_digest: "blake3:dd",
    authority_key_id: "ed25519:ee",
  };
  return {
    api_version: "proof.dev/http-operation-result/v1",
    operation: consequence.operation,
    operation_id: "019d0000000000000000000000000004",
    correlation_id: null,
    committed_anchor: { authority_head: consequence.evaluated_authority_head },
    result: consequence,
  };
}

interface RecordedRequest {
  url: string;
  init: RequestInit;
}

function stubFetch(responseBodies: Array<{ status: number; body?: unknown }>) {
  const requests: RecordedRequest[] = [];
  let call = 0;
  const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
    requests.push({ url: String(input), init: init ?? {} });
    const next = responseBodies[Math.min(call, responseBodies.length - 1)];
    call += 1;
    if (!next) {
      throw new Error("stub fetch exhausted");
    }
    return new Response(next.body === undefined ? undefined : JSON.stringify(next.body), {
      status: next.status,
      headers: { "Content-Type": "application/json" },
    });
  });
  return { fetchImpl, requests };
}

const BASE = "https://proof.example.test";

describe("ProofClient session routes", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reads the session and rotates the CSRF synchronizer", async () => {
    const session: SessionInfo = {
      api_version: "proof.dev/session-get-result/v1",
      cache_control: "private, no-store",
      csrf_token: "csrf-value",
      principal_id: "019d0000000000000000000000000010",
      authenticated_at: "2026-08-25T00:00:00Z",
      idle_expires_at: "2026-08-25T01:00:00Z",
      expires_at: "2026-08-26T00:00:00Z",
    };
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: session }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl });
    await expect(client.getSession()).resolves.toEqual(session);
    expect(requests[0]?.url).toBe(`${BASE}/api/v1/session`);
    expect((requests[0]?.init.credentials as string) === "include").toBe(true);
  });

  it("posts logout with Origin and proof-csrf headers", async () => {
    const { fetchImpl, requests } = stubFetch([
      { status: 200, body: { api_version: "proof.dev/session-logout-result/v1", logged_out: true } },
    ]);
    const client = new ProofClient({
      baseUrl: BASE,
      fetchImpl,
      origin: "https://console.example.test",
      csrfToken: () => "sync-1",
    });
    await expect(client.logout()).resolves.toHaveProperty("logged_out", true);
    const headers = requests[0]?.init.headers as Record<string, string>;
    expect(headers.Origin).toBe("https://console.example.test");
    expect(headers["proof-csrf"]).toBe("sync-1");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("builds the OIDC login URL with a return path", () => {
    const client = new ProofClient({ baseUrl: BASE, fetchImpl: globalThis.fetch });
    expect(client.loginUrl("/changesets")).toBe(
      `${BASE}/auth/oidc/login?return_to=%2Fchangesets`,
    );
  });

  it("discovers capabilities", async () => {
    const { fetchImpl } = stubFetch([
      {
        status: 200,
        body: {
          api_version: "proof.dev/capabilities-discover-result/v1",
          profile: "proof.server/single-workspace/v1",
          registry: {},
          registry_canonicalization: "RFC8785",
          registry_digest_algorithm: "sha-256",
          registry_schema: "schema",
          registry_sha256: "digest",
          route_count: 9,
          human_operation_count: 23,
          agent_operation_count: 14,
        },
      },
    ]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl });
    const capabilities = await client.getCapabilities();
    expect(capabilities.route_count).toBe(9);
    expect(capabilities.profile).toBe("proof.server/single-workspace/v1");
  });
});

describe("ProofClient operations", () => {
  it("dispatches a human operation with the exact envelope and CSRF header", async () => {
    const envelope = consequenceEnvelope();
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: envelope }]);
    const client = new ProofClient({
      baseUrl: BASE,
      fetchImpl,
      origin: "https://console.example.test",
      csrfToken: () => "sync-9",
    });
    const consequence = await client.execute("workspace.status:v1", {});
    expect(consequence.outcome).toBe("Success");
    expect(requests[0]?.url).toBe(`${BASE}/api/v1/human/operations/workspace.status/1`);
    expect(JSON.parse(requests[0]?.init.body as string)).toEqual({
      api_version: "proof.dev/http-human-operation-request/v1",
      operation: {
        name: "workspace.status",
        version: "proof.dev/operation/workspace.status/v1",
      },
      input: {},
    });
    const headers = requests[0]?.init.headers as Record<string, string>;
    expect(headers["proof-csrf"]).toBe("sync-9");
    expect(headers.Accept).toBe("application/json");
  });

  it("uses the exact v2 major for release.create", async () => {
    const envelope = consequenceEnvelope();
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: envelope }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    await client.execute("release.create:v2", {
      api_version: "proof.dev/operation/release.create/v2",
      edition_id: "019d0000000000000000000000000020",
      environment_id: "preview",
      expected_base_release_id: "019d0000000000000000000000000021",
      idempotency_key: "019d0000000000000000000000000022",
      proof_id: "019d0000000000000000000000000023",
      release_id: "019d0000000000000000000000000024",
      released_at: "2026-08-25T00:00:00Z",
    });
    expect(requests[0]?.url).toBe(`${BASE}/api/v1/human/operations/release.create/2`);
    const body = JSON.parse(requests[0]?.init.body as string);
    expect(Object.keys(body.input).sort()).toEqual([
      "api_version",
      "edition_id",
      "environment_id",
      "expected_base_release_id",
      "idempotency_key",
      "proof_id",
      "release_id",
      "released_at",
    ]);
  });

  it("carries correlation and workspace cross-check identifiers when given", async () => {
    const envelope = consequenceEnvelope();
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: envelope }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    await client.execute(
      "changeset.get:v2",
      {
        api_version: "proof.dev/operation/changeset.get/v2",
        changeset_id: "019d0000000000000000000000000030",
      },
      {
        correlationId: "019d0000000000000000000000000031",
        workspaceId: "019d0000000000000000000000000032",
      },
    );
    const body = JSON.parse(requests[0]?.init.body as string);
    expect(body.correlation_id).toBe("019d0000000000000000000000000031");
    expect(body.workspace_id).toBe("019d0000000000000000000000000032");
  });

  it("maps a Problem body to ProblemError verbatim", async () => {
    const problem = {
      api_version: "proof.dev/problem/v1",
      type: "https://proof.dev/problems/policy-denied",
      title: "Policy denied",
      status: 403,
      code: "proof.policy.denied",
      operation: { name: "release.create", version: "proof.dev/operation/release.create/v2" },
      operation_id: "019d0000000000000000000000000040",
      correlation_id: null,
      retryable: false,
      instance: "urn:proof:operation:019d0000000000000000000000000040",
    };
    const { fetchImpl } = stubFetch([{ status: 403, body: problem }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    await expect(client.execute("release.create:v2", {
      api_version: "proof.dev/operation/release.create/v2",
      edition_id: "e",
      environment_id: "preview",
      expected_base_release_id: "b",
      idempotency_key: "k",
      proof_id: "p",
      release_id: "r",
      released_at: "2026-08-25T00:00:00Z",
    })).rejects.toMatchObject({
      code: "proof.policy.denied",
      status: 403,
    });
    await expect(client.execute("release.create:v2", {
      api_version: "proof.dev/operation/release.create/v2",
      edition_id: "e",
      environment_id: "preview",
      expected_base_release_id: "b",
      idempotency_key: "k",
      proof_id: "p",
      release_id: "r",
      released_at: "2026-08-25T00:00:00Z",
    })).rejects.toBeInstanceOf(ProblemError);
  });

  it("maps a non-JSON failure to TransportError", async () => {
    const { fetchImpl } = stubFetch([{ status: 502 }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    await expect(
      client.execute("workspace.status:v1", {}),
    ).rejects.toBeInstanceOf(TransportError);
  });

  it("carries a caller-built invocation over the agent route", async () => {
    const envelope = consequenceEnvelope();
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: envelope }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    const invocation = { api_version: "proof.dev/authenticated-invocation/v1" };
    await client.executeAgent("workspace.status", 1, {
      invocation,
    });
    expect(requests[0]?.url).toBe(`${BASE}/api/v1/agent/operations/workspace.status/1`);
    const body = JSON.parse(requests[0]?.init.body as string);
    expect(body.api_version).toBe("proof.dev/http-agent-operation-request/v1");
    expect(body.operation.name).toBe("workspace.status");
    expect(body.invocation).toEqual(invocation);
  });
});

describe("ProofClient delivery routes", () => {
  it("fetches a preview object through its exact route shape", async () => {
    const preview = {
      release_id: "019d0000000000000000000000000050",
      release_digest: "blake3:aa",
      edition_digest: "blake3:bb",
      rendition_digest: "blake3:cc",
      body: { title: "Summer campaign" },
    };
    const { fetchImpl, requests } = stubFetch([{ status: 200, body: preview }]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl });
    const result = await client.getPreviewObject("preview", "r1", "o1", "fr-FR");
    expect(result.rendition_digest).toBe("blake3:cc");
    expect(requests[0]?.url).toBe(`${BASE}/preview/preview/releases/r1/objects/o1/locales/fr-FR`);
  });

  it("builds evidence artifact URLs content-addressed", () => {
    const client = new ProofClient({ baseUrl: BASE, fetchImpl: globalThis.fetch });
    expect(client.evidenceArtifactUrl("x", "rendition_manifest_v2", "blake3:zz")).toBe(
      `${BASE}/api/v1/evidence-exports/x/artifacts/rendition_manifest_v2/blake3%3Azz`,
    );
  });

  it("rejects unregistered operation pairs before any network call", async () => {
    const { fetchImpl } = stubFetch([]);
    const client = new ProofClient({ baseUrl: BASE, fetchImpl, csrfToken: () => "s" });
    await expect(
      // @ts-expect-error -- unknown keys are rejected at compile time; this
      // guards the runtime boundary too.
      client.execute("release.verify:1", {}),
    ).rejects.toThrow(/unregistered operation pair/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
