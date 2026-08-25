import { forwardRef } from "react";
import type { HTMLAttributes } from "react";
import { cx } from "../cx";

export type StampTone = "seal" | "vermilion" | "amber" | "ruling";

const TONES: Record<StampTone, string> = {
  seal: "border-seal-700 bg-seal-50 text-seal-700",
  vermilion: "border-vermilion-700 bg-vermilion-50 text-vermilion-700",
  amber: "border-amber-screen-700 bg-amber-screen-50 text-amber-screen-700",
  ruling: "border-ruling-700 bg-ruling-50 text-ruling-700",
};

export interface StampProps extends HTMLAttributes<HTMLSpanElement> {
  tone: StampTone;
}

export const Stamp = forwardRef<HTMLSpanElement, StampProps>(
  ({ tone, className, children, ...props }, ref) => (
    <span
      ref={ref}
      className={cx(
        "relative inline-flex -rotate-1 items-center rounded-full border-[1.5px] px-2.5 py-px font-mono text-2xs font-medium uppercase leading-[1.375rem] tracking-[0.12em]",
        TONES[tone],
        className,
      )}
      {...props}
    >
      <span
        aria-hidden
        className="pointer-events-none absolute inset-[2.5px] rounded-full border border-current"
      />
      {children}
    </span>
  ),
);

Stamp.displayName = "Stamp";

const STATUS_TONES: Record<string, StampTone> = {
  approved: "seal",
  committed: "seal",
  delivered: "seal",
  passed: "seal",
  validated: "seal",
  complete: "seal",
  draft: "ruling",
  abandoned: "ruling",
  not_evaluated: "ruling",
  info: "ruling",
  informational: "ruling",
  pending: "amber",
  running: "amber",
  submitted: "amber",
  incomplete: "amber",
  warning: "amber",
  rejected: "vermilion",
  failed: "vermilion",
  error: "vermilion",
  invalid: "vermilion",
};

export function stampToneForStatus(status: string): StampTone {
  return STATUS_TONES[status.toLowerCase()] ?? "ruling";
}
