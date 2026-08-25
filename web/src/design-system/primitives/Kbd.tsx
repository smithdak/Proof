import { forwardRef } from "react";
import type { HTMLAttributes } from "react";
import { cx } from "../cx";

export type KbdProps = HTMLAttributes<HTMLElement>;

export const Kbd = forwardRef<HTMLElement, KbdProps>(({ className, ...props }, ref) => (
  <kbd
    ref={ref}
    className={cx(
      "inline-flex h-5 min-w-5 items-center justify-center rounded-[3px] border border-ruling-200 bg-paper-25 px-1 font-mono text-[10px] leading-none text-ink-700 shadow-[inset_0_-1px_0_0_var(--color-ink-200)]",
      className,
    )}
    {...props}
  />
));

Kbd.displayName = "Kbd";
