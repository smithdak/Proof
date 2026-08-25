import { forwardRef } from "react";
import type { HTMLAttributes } from "react";
import { cx } from "../cx";
import { CopyButton } from "./CopyButton";

export interface DigestTextProps extends HTMLAttributes<HTMLSpanElement> {
  value: string;
  copyLabel?: string;
}

function truncateDigest(value: string): string {
  if (value.length <= 24) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

export const DigestText = forwardRef<HTMLSpanElement, DigestTextProps>(
  ({ value, copyLabel = "Copy digest", className, ...props }, ref) => (
    <span
      ref={ref}
      className={cx("inline-flex max-w-full items-center gap-0.5 font-mono text-xs text-ink-800", className)}
      {...props}
    >
      <span title={value} className="truncate">
        {truncateDigest(value)}
      </span>
      <CopyButton value={value} label={copyLabel} compact />
    </span>
  ),
);

DigestText.displayName = "DigestText";
