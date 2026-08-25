import { forwardRef } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../cx";

export interface PageHeaderProps extends Omit<HTMLAttributes<HTMLElement>, "title"> {
  kicker?: ReactNode;
  title: ReactNode;
  meta?: ReactNode;
  actions?: ReactNode;
}

export const PageHeader = forwardRef<HTMLElement, PageHeaderProps>(
  ({ kicker, title, meta, actions, className, ...props }, ref) => (
    <header
      ref={ref}
      className={cx(
        "flex flex-wrap items-end justify-between gap-x-6 gap-y-4 border-b border-ruling-200 pb-5",
        className,
      )}
      {...props}
    >
      <div className="min-w-0">
        {kicker ? (
          <p className="text-2xs font-medium uppercase tracking-[0.14em] text-ink-500">{kicker}</p>
        ) : null}
        <h1
          className={cx("text-2xl font-semibold tracking-tight text-ink-900", kicker ? "mt-1.5" : "")}
        >
          {title}
        </h1>
        {meta ? <p className="mt-1.5 truncate font-mono text-xs text-ink-500">{meta}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </header>
  ),
);

PageHeader.displayName = "PageHeader";
