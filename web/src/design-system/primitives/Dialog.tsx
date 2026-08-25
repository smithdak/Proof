import * as DialogPrimitive from "@radix-ui/react-dialog";
import { forwardRef } from "react";
import type { ComponentPropsWithoutRef, ComponentRef, ReactNode } from "react";
import { X } from "lucide-react";
import { cx } from "../cx";

export const DialogRoot = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;

export interface DialogContentProps
  extends Omit<ComponentPropsWithoutRef<typeof DialogPrimitive.Content>, "title"> {
  title: ReactNode;
  description?: ReactNode;
}

export const DialogContent = forwardRef<
  ComponentRef<typeof DialogPrimitive.Content>,
  DialogContentProps
>(({ title, description, children, className, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-ink-950/40" />
    <DialogPrimitive.Content
      ref={ref}
      className={cx(
        "fixed left-1/2 top-1/2 z-50 w-[calc(100vw-3rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-md border border-ruling-200 bg-paper-25 p-6 shadow-lg",
        className,
      )}
      {...props}
      aria-describedby={description ? props["aria-describedby"] : undefined}
    >
      <DialogPrimitive.Title className="text-lg font-semibold tracking-tight text-ink-900">
        {title}
      </DialogPrimitive.Title>
      {description ? (
        <DialogPrimitive.Description className="mt-1.5 max-w-prose text-sm leading-6 text-ink-600">
          {description}
        </DialogPrimitive.Description>
      ) : null}
      <div className="mt-5">{children}</div>
      <DialogPrimitive.Close asChild>
        <button
          type="button"
          aria-label="Close dialog"
          className="absolute right-3 top-3 inline-flex size-8 items-center justify-center rounded-sm text-ink-500 transition-colors duration-150 ease-out hover:bg-paper-100 hover:text-ink-900 motion-reduce:transition-none"
        >
          <X className="size-4" aria-hidden />
        </button>
      </DialogPrimitive.Close>
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));

DialogContent.displayName = "DialogContent";
