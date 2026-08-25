import type { HTMLAttributes } from "react";
import type { DiffRow } from "@/api/types";
import { cx } from "../cx";

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  const json = JSON.stringify(value);
  return json ?? "";
}

export interface DiffRowViewProps extends HTMLAttributes<HTMLElement> {
  row: DiffRow;
  supersededBy?: string;
}

export function DiffRowView({ row, supersededBy, className, ...props }: DiffRowViewProps) {
  return (
    <article className={cx("font-mono text-xs leading-5", className)} {...props}>
      <header className="flex flex-wrap items-baseline gap-x-2 border-b border-ruling-200 pb-1.5">
        <span className="text-ink-900">{row.object_id}</span>
        <span className="text-ink-500">{row.field_path}</span>
        {row.locale ? <span className="text-ink-400">{row.locale}</span> : null}
      </header>
      <div className="divide-y divide-ruling-100">
        <div className="flex gap-3 py-1.5">
          <span aria-hidden className="select-none text-ink-500">
            -
          </span>
          <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-ink-700">
            {formatValue(row.before)}
          </span>
        </div>
        <div className="flex gap-3 py-1.5">
          <span aria-hidden className="select-none text-ruling-600">
            +
          </span>
          <span className="min-w-0 flex-1 whitespace-pre-wrap break-words text-ink-900">
            {formatValue(row.after)}
          </span>
        </div>
      </div>
      {supersededBy ? (
        <p className="text-2xs uppercase tracking-[0.14em] text-amber-screen-700">
          Superseded by <span className="font-mono normal-case tracking-normal">{supersededBy}</span>
        </p>
      ) : null}
    </article>
  );
}
