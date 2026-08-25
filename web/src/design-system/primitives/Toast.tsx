import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { X } from "lucide-react";
import { cx } from "../cx";
import { Stamp, type StampTone } from "./Stamp";

export type ToastTone = StampTone;

export interface ToastOptions {
  title: string;
  description?: string;
  tone?: ToastTone;
}

interface ToastEntry {
  id: number;
  title: string;
  description?: string;
  tone: ToastTone;
}

const AUTO_DISMISS_MS = 5000;
const MAX_VISIBLE = 4;

const TONE_STAMP_LABEL: Record<ToastTone, string> = {
  seal: "Recorded",
  vermilion: "Fault",
  amber: "Pending",
  ruling: "Note",
};

interface ToastContextValue {
  toast: (options: ToastOptions) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const nextIdRef = useRef(0);
  const timersRef = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  useEffect(() => {
    const timers = timersRef.current;
    return () => timers.forEach((timer) => clearTimeout(timer));
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((entry) => entry.id !== id));
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const toast = useCallback(
    (options: ToastOptions) => {
      const id = ++nextIdRef.current;
      setToasts((current) => [
        ...current.slice(-(MAX_VISIBLE - 1)),
        { id, title: options.title, description: options.description, tone: options.tone ?? "ruling" },
      ]);
      timersRef.current.set(
        id,
        setTimeout(() => dismiss(id), AUTO_DISMISS_MS),
      );
    },
    [dismiss],
  );

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        aria-label="Notifications"
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2"
      >
        {toasts.map((entry) => (
          <div
            key={entry.id}
            role="status"
            className="pointer-events-auto flex items-start gap-3 rounded-sm border border-ruling-200 bg-paper-25 p-3"
          >
            <Stamp tone={entry.tone} className="mt-0.5 shrink-0">
              {TONE_STAMP_LABEL[entry.tone]}
            </Stamp>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium leading-5 text-ink-900">{entry.title}</p>
              {entry.description ? (
                <p className="mt-0.5 text-sm leading-5 text-ink-600">{entry.description}</p>
              ) : null}
            </div>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => dismiss(entry.id)}
              className={cx(
                "-m-1 inline-flex size-7 items-center justify-center rounded-sm text-ink-400 transition-colors duration-150 ease-out hover:bg-paper-100 hover:text-ink-700 motion-reduce:transition-none",
              )}
            >
              <X className="size-3.5" aria-hidden />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return context;
}
