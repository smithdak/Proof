import { forwardRef } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../cx";

export interface EmptyStateProps extends HTMLAttributes<HTMLDivElement> {
  title: string;
  explanation?: ReactNode;
  action?: ReactNode;
}

export const EmptyState = forwardRef<HTMLDivElement, EmptyStateProps>(
  ({ title, explanation, action, className, ...props }, ref) => (
    <div
      ref={ref}
      className={cx(
        "flex flex-col items-center justify-center gap-1.5 px-6 py-12 text-center",
        className,
      )}
      {...props}
    >
      <p className="text-2xs font-medium uppercase tracking-[0.14em] text-ink-500">{title}</p>
      {explanation ? (
        <p className="max-w-prose text-sm leading-6 text-ink-500">{explanation}</p>
      ) : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  ),
);

EmptyState.displayName = "EmptyState";
