import { forwardRef } from "react";
import type { HTMLAttributes, ReactNode } from "react";
import { cx } from "../cx";

export interface RegisterPanelProps extends Omit<HTMLAttributes<HTMLElement>, "title"> {
  title?: ReactNode;
}

export const RegisterPanel = forwardRef<HTMLElement, RegisterPanelProps>(
  ({ title, className, children, ...props }, ref) => (
    <section
      ref={ref}
      className={cx("rounded border border-ruling-200 bg-paper-25", className)}
      {...props}
    >
      {title ? (
        <header className="border-b border-ruling-200 px-4 py-2.5">
          <h2 className="text-2xs font-medium uppercase tracking-[0.14em] text-ink-600">
            {title}
          </h2>
        </header>
      ) : null}
      <div className="p-4">{children}</div>
    </section>
  ),
);

RegisterPanel.displayName = "RegisterPanel";
