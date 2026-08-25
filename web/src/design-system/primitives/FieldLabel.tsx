import { forwardRef } from "react";
import type { LabelHTMLAttributes } from "react";
import { cx } from "../cx";

export type FieldLabelProps = LabelHTMLAttributes<HTMLLabelElement>;

export const FieldLabel = forwardRef<HTMLLabelElement, FieldLabelProps>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cx(
        "block text-2xs font-medium uppercase tracking-[0.14em] text-ink-500",
        className,
      )}
      {...props}
    />
  ),
);

FieldLabel.displayName = "FieldLabel";
