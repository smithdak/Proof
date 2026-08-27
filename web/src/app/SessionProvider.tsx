import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "react-router";
import type { SessionInfo } from "proof-sdk";
import { getConsoleSession, proofClient } from "@/api/sdk";
import { RegisterPanel, Skeleton } from "@/design-system";

const SessionContext = createContext<SessionInfo | undefined>(undefined);

function SessionSkeleton() {
  return (
    <div
      className="flex min-h-svh items-center justify-center bg-paper-50 px-6"
      role="status"
      aria-label="Reading session"
    >
      <div className="w-full max-w-sm space-y-4">
        <Skeleton className="h-3 w-28" />
        <Skeleton className="h-7 w-full" />
        <Skeleton className="h-16 w-full" />
      </div>
    </div>
  );
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const location = useLocation();
  const { data, isPending, isError } = useQuery({
    queryKey: ["session"],
    queryFn: getConsoleSession,
    staleTime: Infinity,
    retry: 1,
  });

  if (isPending) {
    return <SessionSkeleton />;
  }

  if (isError || !data) {
    return (
      <main className="flex min-h-svh items-center justify-center bg-paper-50 px-6">
        <RegisterPanel title="Registry counter" className="w-full max-w-md">
          <p className="text-2xs uppercase tracking-[0.14em] text-ink-500">
            Proof Console
          </p>
          <h1 className="mt-2 text-xl font-semibold tracking-tight text-ink-900">
            Present credentials to open the register.
          </h1>
          <p className="mt-2 max-w-prose text-sm leading-relaxed text-ink-600">
            Every entry in this workspace is signed and witnessed. Sign in
            through your identity provider to read or propose entries.
          </p>
          <div className="mt-5 border-t border-ruling-200 pt-4">
            <a
              href={proofClient.loginUrl(
                `${location.pathname}${location.search}`,
              )}
              className="inline-flex h-9 items-center rounded border border-ruling-300 px-3.5 text-sm font-medium text-ruling-700 transition-colors duration-150 hover:bg-paper-100 motion-reduce:transition-none"
            >
              Sign in
            </a>
          </div>
        </RegisterPanel>
      </main>
    );
  }

  return (
    <SessionContext.Provider value={data}>{children}</SessionContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useSession(): SessionInfo {
  const session = useContext(SessionContext);
  if (!session) {
    throw new Error("useSession is only valid inside an authenticated session");
  }
  return session;
}
