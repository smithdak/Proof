import {
  OPERATION_MAJOR,
  type OperationName,
  type OperationResult,
} from "./types";

/**
 * Typed client over the exact nine-route proof-server HTTP surface.
 *
 * All application work dispatches through
 * `POST /api/v1/human/operations/{name}/{major}` with Origin + CSRF headers;
 * session state is read from `GET /api/v1/session`, which also rotates the
 * CSRF synchronizer. Mutations are CSRF-protected JSON POSTs.
 */

export class OperationError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = "OperationError";
  }
}

function originHeader(): string {
  return globalThis.location?.origin ?? "http://localhost:5173";
}

let csrfProvider: (() => string | undefined) | undefined;

/** Installs the provider the shell keeps updated from session reads. */
export function setCsrfProvider(provider: () => string | undefined): void {
  csrfProvider = provider;
}

export interface OperationRequest {
  name: OperationName;
  input: Record<string, unknown>;
}

export async function executeOperation<T>(
  name: OperationName,
  input: Record<string, unknown>,
): Promise<T> {
  const major = OPERATION_MAJOR[name];
  const token = csrfProvider?.();
  const response = await fetch(`/api/v1/human/operations/${name}/${major}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      Origin: originHeader(),
      ...(token ? { "X-CSRF-Token": token } : {}),
    },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    let code = "operation.rejected";
    let message = `Operation ${name} was rejected`;
    let details: unknown;
    try {
      const problem = (await response.json()) as {
        code?: string;
        detail?: string;
        [key: string]: unknown;
      };
      code = problem.code ?? code;
      message = problem.detail ?? message;
      details = problem;
    } catch {
      // non-JSON Problem body; keep defaults
    }
    throw new OperationError(response.status, code, message, details);
  }

  const payload = (await response.json()) as OperationResult<T>;
  return payload.result;
}
