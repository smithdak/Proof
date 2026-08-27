import { ProofClient, type SessionInfo } from "proof-sdk";
import { setCsrfProvider } from "./client";

let csrfToken: string | undefined;

/** One same-origin SDK instance owns console session/logout transport. */
export const proofClient = new ProofClient({
  baseUrl: "",
  csrfToken: () => csrfToken,
});

// P-0023 still owns feature-operation transport, so keep its provider pointed
// at the same rotating synchronizer without moving any feature call to the SDK.
setCsrfProvider(() => csrfToken);

export async function getConsoleSession(): Promise<SessionInfo> {
  const session = await proofClient.getSession();
  csrfToken = session.csrf_token;
  return session;
}

export async function logoutConsoleSession(): Promise<void> {
  await proofClient.logout();
  csrfToken = undefined;
}
