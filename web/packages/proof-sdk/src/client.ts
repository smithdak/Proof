import { ProblemError, TransportError } from "./errors";
import {
  resolveAgentOperation,
  resolveHumanOperation,
  type OperationPair,
} from "./registry";
import type {
  AgentOperationEnvelope,
  AgentOperationKey,
  AgentOperationRequest,
  CapabilitiesDiscoverResult,
  HumanOperationEnvelope,
  HumanOperationInputByPair,
  HumanOperationKey,
  HumanOperationRequest,
  PreviewObjectResult,
  ProblemBody,
  SessionInfo,
  SessionLogoutResult,
  SuccessEnvelope,
  Uuid,
} from "./types";

export interface ProofClientOptions {
  /** Server origin, e.g. `https://proof.example.test`; empty means same-origin. */
  baseUrl: string;
  fetchImpl?: typeof fetch;
  csrfToken?: (() => string | undefined) | undefined;
  origin?: string | undefined;
  /** Deployment Workspace equality guard used by direct-Human operations. */
  workspaceId?: Uuid | undefined;
}

export interface HumanExecutionOptions {
  correlationId?: Uuid | undefined;
  workspaceId?: Uuid | undefined;
}

export interface AgentExecutionOptions {
  correlationId?: Uuid | undefined;
}

/** Typed client over the exact nine-route proof-server HTTP surface. */
export class ProofClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly csrfToken: (() => string | undefined) | undefined;
  private readonly origin: string | undefined;
  private readonly workspaceId: Uuid | undefined;

  constructor(options: ProofClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.csrfToken = options.csrfToken;
    this.origin = options.origin;
    this.workspaceId = options.workspaceId;
  }

  /** `GET /api/v1/session`; also rotates the CSRF synchronizer server-side. */
  async getSession(): Promise<SessionInfo> {
    const response = await this.fetchImpl(`${this.baseUrl}/api/v1/session`, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    await this.requireStatus(response, 200);
    const value: unknown = await response.json();
    if (!isSessionInfo(value)) {
      throw new TransportError(200, "proof-server returned an invalid session result");
    }
    return value;
  }

  /** Builds the OIDC login entry URL. */
  loginUrl(returnTo = "/"): string {
    const params = new URLSearchParams({ return_to: returnTo });
    return `${this.baseUrl}/auth/oidc/login?${params.toString()}`;
  }

  /** `POST /api/v1/session/logout`; accepts only the exact HTTP 200 result. */
  async logout(): Promise<SessionLogoutResult> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/session/logout`,
      {
        method: "POST",
        credentials: "include",
        headers: this.humanHeaders(this.csrfToken?.()),
        body: "{}",
      },
    );
    await this.requireStatus(response, 200);
    const value: unknown = await response.json();
    if (!isSessionLogoutResult(value)) {
      throw new TransportError(200, "proof-server returned an invalid logout result");
    }
    return value;
  }

  /** `GET /api/v1/capabilities`; public registry discovery. */
  async getCapabilities(): Promise<CapabilitiesDiscoverResult> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/capabilities`,
      { headers: { Accept: "application/json" } },
    );
    await this.requireStatus(response, 200);
    return (await response.json()) as CapabilitiesDiscoverResult;
  }

  /** Executes one of the four actor-qualified direct-Human pairs. */
  async executeHuman<K extends HumanOperationKey>(
    key: K,
    input: HumanOperationInputByPair[K],
    options: HumanExecutionOptions = {},
  ): Promise<HumanOperationEnvelope<K>> {
    const pair = resolveHumanOperation(key);
    if (!pair) {
      throw new Error(`unregistered Human operation pair ${key}`);
    }
    const workspaceId = options.workspaceId ?? this.workspaceId;
    if (!workspaceId) {
      throw new Error(`Human operation ${key} requires a Workspace equality guard`);
    }
    const idempotencyKey = humanIdempotencyKey(pair, input);
    const body: HumanOperationRequest<HumanOperationInputByPair[K]> = {
      api_version: "proof.dev/http-human-operation-request/v1",
      workspace_id: workspaceId,
      operation: { name: pair.name, version: pair.version },
      correlation_id: options.correlationId ?? null,
      idempotency_key: idempotencyKey,
      input,
    };
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/human/operations/${pair.name}/v${pair.major}`,
      {
        method: "POST",
        credentials: "include",
        headers: this.humanHeaders(this.csrfToken?.()),
        body: JSON.stringify(body),
      },
    );
    await this.requireStatus(response, 200);
    return this.readOperationEnvelope<HumanOperationEnvelope<K>>(response, pair);
  }

  /** Executes one of the fourteen retained Agent pairs with a fresh invocation. */
  async executeAgent<K extends AgentOperationKey>(
    key: K,
    invocation: Record<string, unknown>,
    options: AgentExecutionOptions = {},
  ): Promise<AgentOperationEnvelope<K>> {
    const pair = resolveAgentOperation(key);
    if (!pair) {
      throw new Error(`unregistered Agent operation pair ${key}`);
    }
    const body: AgentOperationRequest = {
      api_version: "proof.dev/http-agent-operation-request/v1",
      operation: { name: pair.name, version: pair.version },
      correlation_id: options.correlationId ?? null,
      invocation,
    };
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/agent/operations/${pair.name}/v${pair.major}`,
      {
        method: "POST",
        credentials: "include",
        headers: this.humanHeaders(this.csrfToken?.()),
        body: JSON.stringify(body),
      },
    );
    await this.requireStatus(response, 200);
    return this.readOperationEnvelope<AgentOperationEnvelope<K>>(response, pair);
  }

  /** `GET /preview/{environment}/releases/{release}/objects/{object}/{locale}`. */
  async getPreviewObject(
    environment: string,
    releaseId: string,
    objectId: string,
    locale: string,
  ): Promise<PreviewObjectResult> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/preview/${encodeURIComponent(environment)}/releases/${encodeURIComponent(releaseId)}/objects/${encodeURIComponent(objectId)}/locales/${encodeURIComponent(locale)}`,
      { credentials: "include", headers: { Accept: "application/json" } },
    );
    if (!response.ok) {
      throw await this.toError(response);
    }
    return (await response.json()) as PreviewObjectResult;
  }

  evidenceArtifactUrl(
    exportId: string,
    artifactKind: string,
    digest: string,
  ): string {
    return `${this.baseUrl}/api/v1/evidence-exports/${encodeURIComponent(exportId)}/artifacts/${encodeURIComponent(artifactKind)}/${encodeURIComponent(digest)}`;
  }

  async fetchEvidenceArtifact(
    exportId: string,
    artifactKind: string,
    digest: string,
  ): Promise<ArrayBuffer> {
    const response = await this.fetchImpl(
      this.evidenceArtifactUrl(exportId, artifactKind, digest),
      { headers: { Accept: "application/octet-stream" } },
    );
    if (!response.ok) {
      throw await this.toError(response);
    }
    return response.arrayBuffer();
  }

  private async readOperationEnvelope<TEnvelope>(
    response: Response,
    pair: OperationPair,
  ): Promise<TEnvelope> {
    const value: unknown = await response.json();
    if (!isSuccessEnvelope(value, pair)) {
      throw new TransportError(
        200,
        `proof-server returned an invalid success envelope for ${String(pair.key)}`,
      );
    }
    return value as TEnvelope;
  }

  private humanHeaders(csrf?: string): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.origin) {
      headers.Origin = this.origin;
    }
    if (csrf !== undefined) {
      headers["proof-csrf"] = csrf;
    }
    return headers;
  }

  private async requireStatus(response: Response, expected: number): Promise<void> {
    if (response.status === expected) {
      return;
    }
    if (!response.ok) {
      throw await this.toError(response);
    }
    throw new TransportError(
      response.status,
      `proof-server returned HTTP ${response.status}; expected ${expected}`,
    );
  }

  private async toError(response: Response): Promise<never> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (isRecord(body) && "code" in body && "status" in body) {
      throw new ProblemError(body as unknown as ProblemBody);
    }
    throw new TransportError(
      response.status,
      `proof-server returned ${response.status} without a Problem body`,
    );
  }
}

function humanIdempotencyKey(
  pair: OperationPair,
  input: unknown,
): Uuid | null {
  if (pair.applicationIdempotency === "none") {
    return null;
  }
  if (
    pair.applicationIdempotency === "required-uuidv7" &&
    isRecord(input) &&
    typeof input.idempotency_key === "string"
  ) {
    return input.idempotency_key;
  }
  throw new Error(`Human operation ${String(pair.key)} lacks its required idempotency key`);
}

const SUCCESS_MEMBERS = [
  "api_version",
  "correlation_id",
  "data",
  "operation",
  "operation_id",
  "replayed",
  "result_anchor",
  "result_schema",
] as const;

function isSuccessEnvelope(value: unknown, pair: OperationPair): value is SuccessEnvelope {
  if (!hasExactMembers(value, SUCCESS_MEMBERS)) {
    return false;
  }
  const operation = value.operation;
  const anchor = value.result_anchor;
  return (
    value.api_version === "proof.dev/http-operation-result/v1" &&
    typeof value.operation_id === "string" &&
    (value.correlation_id === null || typeof value.correlation_id === "string") &&
    typeof value.replayed === "boolean" &&
    value.result_schema === pair.resultSchema &&
    isRecord(value.data) &&
    hasExactMembers(operation, ["name", "version"] as const) &&
    operation.name === pair.name &&
    operation.version === pair.version &&
    hasExactMembers(anchor, ["digest", "kind", "transaction_sequence"] as const) &&
    typeof anchor.digest === "string" &&
    ((anchor.kind === "committed-transaction" &&
      typeof anchor.transaction_sequence === "number") ||
      (anchor.kind === "immutable-result" && anchor.transaction_sequence === null))
  );
}

function isSessionInfo(value: unknown): value is SessionInfo {
  return (
    hasExactMembers(value, [
      "api_version",
      "authenticated_at",
      "cache_control",
      "csrf_token",
      "expires_at",
      "idle_expires_at",
      "principal_id",
    ] as const) &&
    value.api_version === "proof.dev/session-get-result/v1" &&
    value.cache_control === "private, no-store" &&
    typeof value.csrf_token === "string" &&
    typeof value.principal_id === "string" &&
    typeof value.authenticated_at === "string" &&
    typeof value.idle_expires_at === "string" &&
    typeof value.expires_at === "string"
  );
}

function isSessionLogoutResult(value: unknown): value is SessionLogoutResult {
  return (
    hasExactMembers(value, ["api_version", "logged_out"] as const) &&
    value.api_version === "proof.dev/session-logout-result/v1" &&
    value.logged_out === true
  );
}

function hasExactMembers<const K extends readonly string[]>(
  value: unknown,
  members: K,
): value is Record<K[number], unknown> {
  if (!isRecord(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...members].sort();
  return (
    actual.length === expected.length &&
    actual.every((member, index) => member === expected[index])
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
