import { forwardRef } from "react";
import type { TextareaHTMLAttributes } from "react";
import { cx } from "../cx";

export type TextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, rows = 4, ...props }, ref) => (
    <textarea
      ref={ref}
      rows={rows}
      className={cx(
        "w-full resize-y border-b border-ruling-300 bg-transparent px-0.5 py-2 text-sm leading-6 text-ink-900 transition-colors duration-150 ease-out placeholder:text-ink-500 focus:border-ruling-600 focus:outline-none motion-reduce:transition-none disabled:opacity-60",
        className,
      )}
      {...props}
    />
  ),
);

Textarea.displayName = "Textarea";
