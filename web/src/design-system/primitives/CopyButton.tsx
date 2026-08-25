import { forwardRef, useEffect, useRef, useState } from "react";
import type { ButtonHTMLAttributes } from "react";
import { Check, Copy } from "lucide-react";
import { cx } from "../cx";

const COPIED_RESET_MS = 1500;

export interface CopyButtonProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "value" | "children"> {
  value: string;
  label?: string;
  compact?: boolean;
}

export const CopyButton = forwardRef<HTMLButtonElement, CopyButtonProps>(
  ({ value, label = "Copy", compact = false, className, onClick, ...props }, ref) => {
    const [copied, setCopied] = useState(false);
    const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

    useEffect(() => () => {
      if (resetTimer.current) clearTimeout(resetTimer.current);
    }, []);

    const handleCopy = (event: React.MouseEvent<HTMLButtonElement>) => {
      onClick?.(event);
      navigator.clipboard?.writeText(value).then(
        () => {
          setCopied(true);
          if (resetTimer.current) clearTimeout(resetTimer.current);
          resetTimer.current = setTimeout(() => setCopied(false), COPIED_RESET_MS);
        },
        () => {},
      );
    };

    return (
      <button
        ref={ref}
        type="button"
        aria-label={label}
        onClick={handleCopy}
        className={cx(
          "inline-flex h-7 items-center justify-center gap-1 rounded-sm px-1.5 font-mono text-2xs uppercase tracking-[0.12em] text-ink-500 transition-colors duration-150 ease-out hover:bg-paper-100 hover:text-ink-900 motion-reduce:transition-none",
          className,
        )}
        {...props}
      >
        {copied ? (
          <Check className="size-3.5" aria-hidden />
        ) : (
          <Copy className="size-3.5" aria-hidden />
        )}
        {!compact ? (
          <span>{copied ? "Copied" : label}</span>
        ) : copied ? (
          <span className="sr-only">Copied</span>
        ) : null}
      </button>
    );
  },
);

CopyButton.displayName = "CopyButton";
