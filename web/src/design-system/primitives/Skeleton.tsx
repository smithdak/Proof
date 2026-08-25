import { forwardRef } from "react";
import type { HTMLAttributes } from "react";
import { cx } from "../cx";

export type SkeletonProps = HTMLAttributes<HTMLDivElement>;

export const Skeleton = forwardRef<HTMLDivElement, SkeletonProps>(
  ({ className, ...props }, ref) => (
    <div
      ref={ref}
      aria-hidden
      className={cx("animate-pulse rounded-sm bg-paper-150 motion-reduce:animate-none", className)}
      {...props}
    />
  ),
);

Skeleton.displayName = "Skeleton";
