import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Outlet } from "react-router";
import { Search } from "lucide-react";
import { executeOperation, loginUrl, logout } from "@/api/client";
import type { WorkspaceStatus } from "@/api/types";
import {
  DigestText,
  IconButton,
  Kbd,
  Skeleton,
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/design-system";
import { CommandPalette } from "./CommandPalette";
import { NAV_DESTINATIONS } from "./nav";
import { useSession } from "./SessionProvider";

function initialsOf(displayName: string): string {
  const parts = displayName.trim().split(/\s+/);
  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

function useWorkspaceStatus() {
  return useQuery({
    queryKey: ["workspace", "status"],
    queryFn: () => executeOperation<WorkspaceStatus>("workspace.status", {}),
  });
}

function WorkspaceIdentity() {
  const { data, isPending, isError } = useWorkspaceStatus();
  if (isPending) {
    return <Skeleton className="h-4 w-36" />;
  }
  if (isError || !data) {
    return (
      <span className="font-mono text-sm text-ink-400" role="status">
        —
      </span>
    );
  }
  return (
    <div className="flex min-w-0 items-baseline gap-3">
      <span className="truncate text-sm font-semibold tracking-tight text-ink-900">
        {data.name}
      </span>
      <span className="hidden font-mono text-2xs text-ink-400 xl:inline">
        {data.workspace_id}
      </span>
    </div>
  );
}

function KnownStateDigest() {
  const { data } = useWorkspaceStatus();
  if (!data) {
    return <Skeleton className="h-4 w-40" />;
  }
  return <DigestText value={data.known_state_digest} />;
}

function PrincipalMenu() {
  const session = useSession();
  const principal = session.principal;
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    function onPointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("pointerdown", onPointerDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("pointerdown", onPointerDown);
    };
  }, [open]);

  async function signOut() {
    setSigningOut(true);
    try {
      if (session.csrf_token) {
        await logout(session.csrf_token);
      }
    } finally {
      window.location.assign(loginUrl());
    }
  }

  if (!principal) return null;

  return (
    <div ref={rootRef} className="relative">
      <button
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Signed in as ${principal.display_name}`}
        onClick={() => setOpen((value) => !value)}
        className="flex size-8 items-center justify-center rounded-full border border-ruling-300 bg-paper-100 font-mono text-2xs font-semibold text-ruling-700 transition-colors duration-150 hover:bg-paper-150 motion-reduce:transition-none"
      >
        {initialsOf(principal.display_name)}
      </button>
      {open && (
        <div
          role="menu"
          aria-label="Session"
          className="absolute right-0 top-10 z-50 w-64 rounded-md border border-ruling-200 bg-paper-25 py-1 shadow-lg"
        >
          <div className="border-b border-ruling-200 px-3 pb-2 pt-2">
            <p className="truncate text-sm font-medium text-ink-900">
              {principal.display_name}
            </p>
            <p className="mt-0.5 truncate font-mono text-2xs text-ink-500">
              {principal.subject}
            </p>
          </div>
          <button
            type="button"
            role="menuitem"
            disabled={signingOut}
            onClick={() => void signOut()}
            className="mt-1 flex w-full items-center justify-between px-3 py-2 text-left text-sm text-ink-700 transition-colors duration-150 hover:bg-paper-100 hover:text-ink-900 disabled:opacity-60 motion-reduce:transition-none"
          >
            Sign out
            <Kbd aria-hidden="true">⏎</Kbd>
          </button>
        </div>
      )}
    </div>
  );
}

export function AppShell() {
  const [paletteOpen, setPaletteOpen] = useState(false);

  return (
    <TooltipProvider delayDuration={250}>
      <div className="flex min-h-svh">
        <nav
          aria-label="Register sections"
          className="sticky top-0 z-40 flex h-svh w-14 shrink-0 flex-col border-r border-ruling-200 bg-paper-50 lg:w-64"
        >
          <a
            href="/overview"
            className="flex h-14 items-center gap-2.5 border-b border-ruling-200 px-3 lg:px-5"
          >
            <svg
              viewBox="0 0 32 32"
              className="size-6 shrink-0"
              aria-hidden="true"
            >
              <rect
                width="32"
                height="32"
                rx="6"
                className="[fill:var(--color-ink-900)]"
              />
              <path
                d="M9 22V10h7a4 4 0 0 1 0 8h-7"
                stroke="var(--color-ruling-100)"
                strokeWidth="2.5"
                fill="none"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <circle
                cx="22"
                cy="22"
                r="3"
                className="[fill:var(--color-seal-600)]"
              />
            </svg>
            <span className="hidden text-sm font-semibold tracking-tight text-ink-900 lg:inline">
              Proof Console
            </span>
          </a>
          <ul className="flex-1 space-y-0.5 overflow-y-auto py-3">
            {NAV_DESTINATIONS.map((destination) => (
              <li key={destination.path}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <NavLink
                      to={destination.path}
                      aria-label={destination.label}
                      className={({ isActive }) =>
                        [
                          "relative flex h-11 items-center gap-3 px-3 text-sm transition-colors duration-150 motion-reduce:transition-none",
                          "justify-center lg:justify-start",
                          isActive
                            ? "bg-paper-100 font-medium text-ink-900 shadow-[inset_2px_0_0_0_var(--color-ruling-600)]"
                            : "text-ink-600 hover:bg-paper-100 hover:text-ink-900",
                        ].join(" ")
                      }
                    >
                      <destination.icon
                        size={17}
                        strokeWidth={1.75}
                        className="shrink-0"
                        aria-hidden="true"
                      />
                      <span className="hidden lg:inline">
                        {destination.label}
                      </span>
                    </NavLink>
                  </TooltipTrigger>
                  <TooltipContent side="right">
                    {destination.label}
                  </TooltipContent>
                </Tooltip>
              </li>
            ))}
          </ul>
          <p className="hidden border-t border-ruling-200 px-5 py-3 font-mono text-2xs leading-relaxed text-ink-400 lg:block">
            Entries are entered once and never rewritten.
          </p>
        </nav>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 flex h-14 items-center gap-x-5 border-b border-ruling-200 bg-paper-50/95 px-4 backdrop-blur-sm lg:px-8">
            <div className="min-w-0">
              <p className="text-2xs uppercase tracking-[0.14em] text-ink-500">
                Workspace
              </p>
              <WorkspaceIdentity />
            </div>
            <div className="ml-auto hidden md:block">
              <p className="mb-0.5 text-2xs uppercase tracking-[0.14em] text-ink-500">
                Known State
              </p>
              <KnownStateDigest />
            </div>
            <div className="ml-auto flex items-center gap-2 md:ml-4">
              <Tooltip>
                <TooltipTrigger asChild>
                  <IconButton
                    aria-label="Open command palette"
                    onClick={() => setPaletteOpen(true)}
                  >
                    <Search aria-hidden="true" />
                  </IconButton>
                </TooltipTrigger>
                <TooltipContent>Command palette</TooltipContent>
              </Tooltip>
              <span className="hidden items-center gap-1 sm:flex">
                <Kbd>⌘</Kbd>
                <Kbd>K</Kbd>
              </span>
              <PrincipalMenu />
            </div>
          </header>
          <main className="flex-1 px-4 py-6 lg:px-8 lg:py-8">
            <Outlet />
          </main>
          <footer className="border-t border-ruling-200 px-4 py-3 lg:px-8">
            <p className="font-mono text-2xs text-ink-400">
              Proof Console · every release carries its proof
            </p>
          </footer>
        </div>

        <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
      </div>
    </TooltipProvider>
  );
}
