import { forwardRef } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../cx";

export interface SectionHeadingProps extends HTMLAttributes<HTMLHeadingElement> {
  children: ReactNode;
}

export const SectionHeading = forwardRef<HTMLHeadingElement, SectionHeadingProps>(
  ({ className, children, ...props }, ref) => (
    <h2
      ref={ref}
      className={cx(
        "flex items-center gap-4 text-2xs font-medium uppercase tracking-[0.14em] text-ink-600",
        className,
      )}
      {...props}
    >
      <span className="whitespace-nowrap">{children}</span>
      <span aria-hidden className="h-px min-w-8 flex-1 bg-ruling-200" />
    </h2>
  ),
);

SectionHeading.displayName = "SectionHeading";
