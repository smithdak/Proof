import type { ProblemBody } from "./types";

/**
 * Typed rejection carrying the server's stable Problem body verbatim.
 *
 * Every non-2xx response from any route maps to this error; no SDK call path
 * ever throws an untyped response body.
 */
export class ProblemError extends Error {
  constructor(readonly problem: ProblemBody) {
    super(`${problem.code}: ${problem.title}`);
    this.name = "ProblemError";
  }

  /** Stable machine-readable Proof code, e.g. `proof.policy.denied`. */
  get code(): string {
    return this.problem.code;
  }

  /** Exact HTTP status. */
  get status(): number {
    return this.problem.status;
  }

  /** Authorized retry delay in milliseconds (429 only). */
  get retryAfterMs(): number | undefined {
    return this.problem.retry_after_ms;
  }
}

/** Transport-level failure before a Problem body could be read. */
export class TransportError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "TransportError";
  }
}
