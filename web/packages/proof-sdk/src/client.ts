import { ProblemError, TransportError } from "./errors";
import { resolveOperation } from "./registry";
import type {
  AgentOperationRequest,
  CapabilitiesDiscoverResult,
  HumanOperationRequest,
  OperationInputByPair,
  OperationKey,
  PreviewObjectResult,
  ProblemBody,
  SessionInfo,
  SessionLogoutResult,
  SuccessEnvelope,
} from "./types";

export interface ProofClientOptions {
  /** Server origin, e.g. `https://proof.example.test`. */
  baseUrl: string;
  /**
   * Transport override for tests and non-fetch runtimes; defaults to
   * the platform `fetch` (Node >= 18, browsers, workers).
   */
  fetchImpl?: typeof fetch;
  /**
   * Supplies the current session-bound CSRF synchronizer value. The value
   * rotates on every session read; keep it updated from
   * {@link ProofClient.getSession}. Optional for read-only usage.
   */
  csrfToken?: (() => string | undefined) | undefined;
  /**
   * Origin header value. Browsers forbid setting `Origin` manually; when
   * omitted under a browser runtime the browser supplies it automatically.
   */
  origin?: string | undefined;
}

/**
 * Typed client over the exact nine-route proof-server HTTP surface
 * (contract "HTTP boundary").
 *
 * Application work dispatches through
 * `POST /api/v1/{actor}/operations/{name}/{major}` with a JSON body carrying
 * the frozen operation pair and its strict normalized input. Human calls
 * require the session cookie plus the `proof-csrf` synchronizer and an Origin
 * header; agent calls additionally carry a caller-built signed invocation.
 */
export class ProofClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly csrfToken: (() => string | undefined) | undefined;
  private readonly origin: string | undefined;

  constructor(options: ProofClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
    this.csrfToken = options.csrfToken ?? undefined;
    this.origin = options.origin ?? undefined;
  }

  // -- session boundary -----------------------------------------------------

  /** `GET /api/v1/session`; also rotates the CSRF synchronizer server-side. */
  async getSession(): Promise<SessionInfo> {
    const response = await this.fetchImpl(`${this.baseUrl}/api/v1/session`, {
      credentials: "include",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw await this.toError(response);
    }
    return (await response.json()) as SessionInfo;
  }

  /** Builds the OIDC login entry URL. */
  loginUrl(returnTo = "/"): string {
    const params = new URLSearchParams({ return_to: returnTo });
    return `${this.baseUrl}/auth/oidc/login?${params.toString()}`;
  }

  /** `POST /api/v1/session/logout`; converges to `logged_out: true`. */
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
    if (!response.ok) {
      throw await this.toError(response);
    }
    return (await response.json()) as SessionLogoutResult;
  }

  /** `GET /api/v1/capabilities`; public registry discovery. */
  async getCapabilities(): Promise<CapabilitiesDiscoverResult> {
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/capabilities`,
      { headers: { Accept: "application/json" } },
    );
    if (!response.ok) {
      throw await this.toError(response);
    }
    return (await response.json()) as CapabilitiesDiscoverResult;
  }

  // -- operations -----------------------------------------------------------

  /**
   * Executes one registered operation over the direct-Human route.
   *
   * @param key Registry key of the exact operation pair (`name:major`).
   * @param input The strict normalized input, field-set-exact per contract.
   */
  async execute<K extends OperationKey>(
    key: K,
    input: OperationInputByPair[K],
    options: { correlationId?: string; workspaceId?: string } = {},
  ): Promise<ApplicationConsequenceOf<K>> {
    const [name, majorText] = splitKey(key);
    const major = Number(majorText.slice(1));
    const pair = resolveOperation(name, major);
    if (!pair) {
      throw new Error(`unregistered operation pair ${key}`);
    }
    const body: HumanOperationRequest<OperationInputByPair[K]> = {
      api_version: "proof.dev/http-human-operation-request/v1",
      operation: { name: pair.name, version: pair.version },
      input,
      ...(options.correlationId ? { correlation_id: options.correlationId } : {}),
      ...(options.workspaceId ? { workspace_id: options.workspaceId } : {}),
    };
    const envelope = await this.postHuman(pair.name, pair.major, body);
    return envelope.result as ApplicationConsequenceOf<K>;
  }

  /**
   * Executes one registered operation over the dual-auth Agent route.
   *
   * The caller supplies the fresh signed invocation (`AuthenticatedInvocationV1`)
   * built through its provisioning path; the SDK carries the transport exactly.
   */
  async executeAgent(
    name: string,
    major: number,
    request: Omit<AgentOperationRequest, "api_version" | "operation">,
    options: { correlationId?: string; workspaceId?: string } = {},
  ): Promise<ApplicationConsequence> {
    const pair = resolveOperation(name, major);
    if (!pair) {
      throw new Error(`unregistered operation pair ${name}/v${major}`);
    }
    const body: AgentOperationRequest = {
      api_version: "proof.dev/http-agent-operation-request/v1",
      operation: { name: pair.name, version: pair.version },
      ...request,
      ...(options.correlationId ? { correlation_id: options.correlationId } : {}),
    };
    const token = this.csrfToken?.();
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/agent/operations/${pair.name}/${pair.major}`,
      {
        method: "POST",
        credentials: "include",
        headers: this.humanHeaders(token),
        body: JSON.stringify(body),
      },
    );
    if (!response.ok) {
      throw await this.toError(response);
    }
    const envelope = (await response.json()) as SuccessEnvelope;
    return envelope.result;
  }

  private async postHuman(
    name: string,
    major: number,
    body: unknown,
  ): Promise<SuccessEnvelope> {
    const token = this.csrfToken?.();
    const response = await this.fetchImpl(
      `${this.baseUrl}/api/v1/human/operations/${name}/${major}`,
      {
        method: "POST",
        credentials: "include",
        headers: this.humanHeaders(token),
        body: JSON.stringify(body),
      },
    );
    if (!response.ok) {
      throw await this.toError(response);
    }
    return (await response.json()) as SuccessEnvelope;
  }

  // -- delivery / preview ---------------------------------------------------

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

  /**
   * Builds the URL for an evidence artifact read; the bytes are returned
   * content-addressed and are intended for independent verification.
   */
  evidenceArtifactUrl(
    exportId: string,
    artifactKind: string,
    digest: string,
  ): string {
    return `${this.baseUrl}/api/v1/evidence-exports/${encodeURIComponent(exportId)}/artifacts/${encodeURIComponent(artifactKind)}/${encodeURIComponent(digest)}`;
  }

  /** Fetches one evidence artifact's exact revalidated bytes. */
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

  // -- plumbing -------------------------------------------------------------

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

  private async toError(response: Response): Promise<never> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (
      body !== null &&
      typeof body === "object" &&
      "code" in body &&
      "status" in body
    ) {
      throw new ProblemError(body as ProblemBody);
    }
    throw new TransportError(
      response.status,
      `proof-server returned ${response.status} without a Problem body`,
    );
  }
}

/**
 * The typed application result carried by one row's consequence. Rows whose
 * typed outcome embeds a projection surface it here; rows whose effect rule is
 * digest-only surface the consequence itself.
 */
export type ApplicationConsequenceOf<K extends OperationKey> =
  import("./types").ApplicationConsequence;
import type { ApplicationConsequence } from "./types";

function splitKey(key: OperationKey): [string, string] {
  const index = key.lastIndexOf(":");
  return [key.slice(0, index), key.slice(index + 1)];
}
