import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { useNavigate } from "react-router";
import {
  FilePenLine,
  Layers,
  Plus,
  type LucideIcon,
} from "lucide-react";
import { EmptyState, Kbd } from "@/design-system";
import { NAV_DESTINATIONS } from "./nav";

interface PaletteEntry {
  id: string;
  section: "Destinations" | "Actions";
  label: string;
  detail: string;
  to: string;
  icon: LucideIcon;
}

const QUICK_ACTIONS: PaletteEntry[] = [
  {
    id: "action-new-changeset",
    section: "Actions",
    label: "New ChangeSet",
    detail: "Open the ChangeSets desk",
    to: "/changesets",
    icon: Plus,
  },
  {
    id: "action-validate-changeset",
    section: "Actions",
    label: "Validate a ChangeSet",
    detail: "Run deterministic rulesets",
    to: "/changesets",
    icon: FilePenLine,
  },
  {
    id: "action-cut-edition",
    section: "Actions",
    label: "Cut an edition",
    detail: "Freeze content into an edition",
    to: "/releases",
    icon: Layers,
  },
];

const ENTRIES: PaletteEntry[] = [
  ...NAV_DESTINATIONS.map((destination) => ({
    id: destination.path,
    section: "Destinations" as const,
    label: destination.label,
    detail: destination.description,
    to: destination.path,
    icon: destination.icon,
  })),
  ...QUICK_ACTIONS,
];

function fuzzyScore(query: string, text: string): number | null {
  if (query.length === 0) return 0;
  const haystack = text.toLowerCase();
  let cursor = 0;
  let streak = 0;
  let score = 0;
  for (const char of query.toLowerCase()) {
    const found = haystack.indexOf(char, cursor);
    if (found === -1) return null;
    streak = found === cursor ? streak + 1 : 0;
    score +=
      1 +
      streak * 2 +
      (found === 0 || /\s/.test(haystack[found - 1] ?? " ") ? 3 : 0);
    cursor = found + 1;
  }
  return score - haystack.length * 0.01;
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    function onGlobalKeyDown(event: KeyboardEvent) {
      if (
        event.key.toLowerCase() === "k" &&
        (event.metaKey || event.ctrlKey)
      ) {
        event.preventDefault();
        onOpenChange(!open);
      }
    }
    window.addEventListener("keydown", onGlobalKeyDown);
    return () => window.removeEventListener("keydown", onGlobalKeyDown);
  }, [open, onOpenChange]);

  useEffect(() => {
    if (!open) return;
    restoreFocusRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    setQuery("");
    setActiveIndex(0);
    const frame = requestAnimationFrame(() => inputRef.current?.focus());
    return () => {
      cancelAnimationFrame(frame);
      restoreFocusRef.current?.focus();
    };
  }, [open]);

  const results = useMemo(() => {
    const matches = (entry: PaletteEntry) =>
      fuzzyScore(query.trim(), `${entry.label} ${entry.detail} ${entry.section}`);
    const groups: PaletteEntry[][] = [
      ENTRIES.filter((e) => e.section === "Destinations" && matches(e) !== null),
      ENTRIES.filter((e) => e.section === "Actions" && matches(e) !== null),
    ];
    return groups.flat();
  }, [query]);

  const active = Math.min(activeIndex, Math.max(results.length - 1, 0));
  const activeId = results[active]
    ? `command-option-${results[active]!.id}`
    : undefined;

  useEffect(() => {
    listRef.current?.children[active]?.scrollIntoView({ block: "nearest" });
  }, [active]);

  function choose(entry: PaletteEntry) {
    onOpenChange(false);
    navigate(entry.to);
  }

  function onKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => (results.length ? (index + 1) % results.length : 0));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) =>
        results.length ? (index - 1 + results.length) % results.length : 0,
      );
    } else if (event.key === "Enter") {
      event.preventDefault();
      const entry = results[active];
      if (entry) choose(entry);
    } else if (event.key === "Escape") {
      event.preventDefault();
      onOpenChange(false);
    }
  }

  if (!open) return null;

  let lastSection: string | null = null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center px-4 pt-[12vh]">
      <button
        type="button"
        aria-hidden="true"
        tabIndex={-1}
        onClick={() => onOpenChange(false)}
        className="absolute inset-0 cursor-default bg-ink-950/40"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="relative w-full max-w-xl overflow-hidden rounded-md border border-ruling-200 bg-paper-25 shadow-lg"
      >
        <div className="border-b border-ruling-200">
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={onKeyDown}
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-list"
            aria-activedescendant={activeId}
            aria-autocomplete="list"
            placeholder="Search the register…"
            spellCheck={false}
            autoComplete="off"
            className="h-12 w-full bg-transparent px-4 font-mono text-sm text-ink-900 outline-none placeholder:text-ink-400"
          />
        </div>
        <ul
          id="command-palette-list"
          ref={listRef}
          role="listbox"
          aria-label="Commands"
          className="max-h-[30rem] overflow-y-auto py-1"
        >
          {results.map((entry, index) => {
            const header =
              entry.section !== lastSection ? entry.section : null;
            lastSection = entry.section;
            return (
              <li key={entry.id} role="presentation">
                {header && (
                  <div
                    role="presentation"
                    className="scroll-mt-2 px-4 pb-1 pt-3 text-2xs uppercase tracking-[0.14em] text-ink-500"
                  >
                    {header}
                  </div>
                )}
                <div
                  id={`command-option-${entry.id}`}
                  role="option"
                  aria-selected={index === active}
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => choose(entry)}
                  className={
                    index === active
                      ? "flex cursor-pointer items-center gap-3 px-4 py-2.5 text-ink-900 shadow-[inset_2px_0_0_0_var(--color-ruling-600)] [background:var(--color-paper-100)] transition-colors duration-150 motion-reduce:transition-none"
                      : "flex cursor-pointer items-center gap-3 px-4 py-2.5 text-ink-700 transition-colors duration-150 hover:bg-paper-100 motion-reduce:transition-none"
                  }
                >
                  <entry.icon
                    size={16}
                    strokeWidth={1.75}
                    className="shrink-0 text-ruling-600"
                    aria-hidden="true"
                  />
                  <span className="min-w-0 flex-1 truncate text-sm">
                    {entry.label}
                    <span className="ml-2 hidden text-ink-500 sm:inline">
                      {entry.detail}
                    </span>
                  </span>
                  <span className="hidden font-mono text-2xs text-ink-400 md:block">
                    {entry.to}
                  </span>
                </div>
              </li>
            );
          })}
          {results.length === 0 && (
            <li role="presentation" className="px-4 py-6">
              <EmptyState title="No entries match" />
            </li>
          )}
        </ul>
        <footer className="flex items-center gap-x-4 gap-y-1 border-t border-ruling-200 bg-paper-50 px-4 py-2">
          <span className="flex items-center gap-1.5">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd>
            <span className="text-2xs uppercase tracking-[0.14em] text-ink-500">
              Move
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>↵</Kbd>
            <span className="text-2xs uppercase tracking-[0.14em] text-ink-500">
              Open
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <Kbd>Esc</Kbd>
            <span className="text-2xs uppercase tracking-[0.14em] text-ink-500">
              Close
            </span>
          </span>
        </footer>
      </div>
    </div>
  );
}
