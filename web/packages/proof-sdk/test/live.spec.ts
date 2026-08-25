import { describe, expect, it } from "vitest";
import { ProofClient } from "../src/client";
import { ProblemError } from "../src/errors";

/**
 * Live-server leg: runs only when PROOF_SDK_BASE_URL points at a running
 * proof-server (the deployable artifact boots one). Skipped silently
 * otherwise so the standard gate stays hermetic.
 */
const BASE_URL = process.env.PROOF_SDK_BASE_URL;

describe.skipIf(!BASE_URL)("ProofClient against a live proof-server", () => {
  // Constructed lazily: describe bodies execute during collection even when
  // every contained test is skipped.
  const client = () => new ProofClient({ baseUrl: BASE_URL as string });

  it("discovers capabilities from the deployed router", async () => {
    const capabilities = await client().getCapabilities();
    expect(capabilities.api_version).toBe(
      "proof.dev/capabilities-discover-result/v1",
    );
    expect(capabilities.route_count).toBe(9);
    expect(capabilities.profile).toBe("proof.server/single-workspace/v1");
  });

  it("maps an unauthenticated session read to its stable Problem", async () => {
    const failure = await client().getSession().then(
      () => null,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(ProblemError);
    const problem = failure as ProblemError;
    expect(problem.status).toBe(401);
    expect(problem.code).toBe("proof.auth.denied");
    expect(problem.problem.retryable).toBe(false);
    expect(problem.problem.instance.startsWith("urn:proof:operation:")).toBe(true);
  });
});
