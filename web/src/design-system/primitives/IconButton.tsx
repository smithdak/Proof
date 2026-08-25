import { forwardRef } from "react";
import type { ButtonHTMLAttributes } from "react";
import { cx } from "../cx";

export type IconButtonProps = Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> & {
  "aria-label": string;
};

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ className, type = "button", children, ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cx(
        "inline-flex size-8 items-center justify-center rounded-sm text-ink-600 transition-colors duration-150 ease-out hover:bg-paper-100 hover:text-ink-900 active:bg-paper-150 [&_svg]:size-4",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  ),
);

IconButton.displayName = "IconButton";
