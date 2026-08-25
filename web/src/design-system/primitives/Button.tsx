import { forwardRef } from "react";
import type { ButtonHTMLAttributes } from "react";
import { cx } from "../cx";

export type ButtonVariant = "default" | "consequential" | "ghost" | "danger";
export type ButtonSize = "sm" | "md";

const BASE =
  "inline-flex items-center justify-center gap-1.5 rounded-sm font-medium transition-colors duration-150 ease-out motion-reduce:transition-none disabled:pointer-events-none disabled:opacity-50";

const VARIANTS: Record<ButtonVariant, string> = {
  default:
    "border border-ruling-300 bg-paper-25 text-ink-800 hover:border-ruling-500 hover:bg-paper-50 active:bg-paper-100",
  consequential:
    "bg-consequential-600 text-paper-25 hover:bg-consequential-700 active:bg-consequential-700",
  ghost: "text-ink-700 hover:bg-paper-100 hover:text-ink-900 active:bg-paper-150",
  danger:
    "border border-vermilion-500 bg-paper-25 text-vermilion-700 hover:border-vermilion-600 hover:bg-vermilion-50",
};

const SIZES: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs",
  md: "h-10 px-4 text-sm",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "default", size = "md", className, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cx(BASE, VARIANTS[variant], SIZES[size], className)}
      {...props}
    />
  ),
);

Button.displayName = "Button";
