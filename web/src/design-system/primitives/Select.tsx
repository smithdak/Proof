import { forwardRef } from "react";
import type { SelectHTMLAttributes } from "react";
import { cx } from "../cx";

export type SelectProps = SelectHTMLAttributes<HTMLSelectElement>;

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      className={cx(
        "w-full appearance-none border-b border-ruling-300 bg-transparent px-0.5 py-2 pr-6 text-sm text-ink-900 transition-colors duration-150 ease-out focus:border-ruling-600 focus:outline-none motion-reduce:transition-none disabled:opacity-60",
        className,
      )}
      {...props}
    >
      {children}
    </select>
  ),
);

Select.displayName = "Select";
