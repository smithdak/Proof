import { forwardRef } from "react";
import type { InputHTMLAttributes } from "react";
import { cx } from "../cx";

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cx(
        "w-full border-b border-ruling-300 bg-transparent px-0.5 py-2 text-sm text-ink-900 transition-colors duration-150 ease-out placeholder:text-ink-500 focus:border-ruling-600 focus:outline-none motion-reduce:transition-none disabled:opacity-60",
        className,
      )}
      {...props}
    />
  ),
);

Input.displayName = "Input";
