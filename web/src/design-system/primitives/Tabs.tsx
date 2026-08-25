import * as TabsPrimitive from "@radix-ui/react-tabs";
import { forwardRef } from "react";
import type { ComponentPropsWithoutRef, ComponentRef } from "react";
import { cx } from "../cx";

export const Tabs = TabsPrimitive.Root;

export function TabsList({ className, ...props }: ComponentPropsWithoutRef<typeof TabsPrimitive.List>) {
  return (
    <TabsPrimitive.List
      className={cx("flex items-end gap-5 border-b border-ruling-200", className)}
      {...props}
    />
  );
}

const TRIGGER_BASE =
  "-mb-px border-b-2 border-transparent pb-2 pt-1.5 text-2xs font-medium uppercase tracking-[0.14em] text-ink-500 transition-colors duration-150 ease-out hover:text-ink-700 motion-reduce:transition-none data-[state=active]:border-ruling-700 data-[state=active]:text-ink-900 data-[state=inactive]:text-ink-500";

export const TabsTrigger = forwardRef<
  ComponentRef<typeof TabsPrimitive.Trigger>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger ref={ref} className={cx(TRIGGER_BASE, className)} {...props} />
));

TabsTrigger.displayName = "TabsTrigger";

export function TabsContent({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cx("pt-4", className)} {...props} />;
}
