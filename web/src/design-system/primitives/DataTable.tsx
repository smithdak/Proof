import type { HTMLAttributes, KeyboardEvent, ReactNode } from "react";
import { cx } from "../cx";
import { EmptyState } from "./EmptyState";

export interface DataTableColumn<T> {
  key: string;
  header: ReactNode;
  render?: (row: T) => ReactNode;
  align?: "left" | "center" | "right";
  width?: string;
}

export interface DataTableProps<T> extends Omit<HTMLAttributes<HTMLTableElement>, "columns"> {
  columns: Array<DataTableColumn<T>>;
  rows: T[];
  rowKey: (row: T) => string;
  selectedKey?: string | null;
  onRowClick?: (row: T) => void;
  emptyState?: ReactNode;
  renderMobileCard?: (row: T) => ReactNode;
}

const ALIGN: Record<NonNullable<DataTableColumn<unknown>["align"]>, string> = {
  left: "text-left",
  center: "text-center",
  right: "text-right",
};

function cellValue(row: unknown, key: string): string {
  const value = (row as Record<string, unknown>)[key];
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  selectedKey = null,
  onRowClick,
  emptyState,
  renderMobileCard,
  className,
  ...props
}: DataTableProps<T>) {
  const interactive = Boolean(onRowClick);

  const handleRowKeyDown =
    interactive
      ? (event: KeyboardEvent<HTMLTableRowElement>, row: T) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onRowClick?.(row);
          }
        }
      : undefined;

  const empty = emptyState ?? (
    <EmptyState title="No entries" explanation="Nothing has been filed here yet." />
  );

  const table = (
    <table
      className={cx(
        "w-full min-w-[640px] border-separate border-spacing-0 text-sm tabular-nums",
        className,
      )}
      {...props}
    >
      <thead>
        {/* tr box-shadow draws the second hairline of the double rule under the header */}
        <tr className="[box-shadow:0_2px_0_0_var(--color-ruling-200)]">
          {columns.map((column) => (
            <th
              key={column.key}
              scope="col"
              style={column.width ? { width: column.width } : undefined}
              className={cx(
                "border-b border-ruling-200 px-3 py-2 text-2xs font-medium uppercase tracking-[0.14em] text-ink-600",
                ALIGN[column.align ?? "left"],
              )}
            >
              {column.header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => {
          const key = rowKey(row);
          const selected = selectedKey != null && key === selectedKey;
          return (
            <tr
              key={key}
              tabIndex={interactive ? 0 : undefined}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              onKeyDown={handleRowKeyDown ? (event) => handleRowKeyDown(event, row) : undefined}
              data-state={selected ? "selected" : "idle"}
              className={cx(
                "transition-colors duration-150 ease-out motion-reduce:transition-none",
                selected && "bg-paper-100",
                !selected && onRowClick && "hover:bg-paper-100",
                onRowClick && "cursor-pointer",
              )}
            >
              {columns.map((column, index) => (
                <td
                  key={column.key}
                  style={column.width ? { width: column.width } : undefined}
                  className={cx(
                    "h-11 border-b border-ruling-200 px-3 align-middle",
                    ALIGN[column.align ?? "left"],
                    selected &&
                      index === 0 &&
                      "[box-shadow:inset_2px_0_0_0_var(--color-ruling-600)]",
                  )}
                >
                  {column.render ? column.render(row) : cellValue(row, column.key)}
                </td>
              ))}
            </tr>
          );
        })}
        {rows.length === 0 ? (
          <tr>
            <td colSpan={columns.length}>{empty}</td>
          </tr>
        ) : null}
      </tbody>
    </table>
  );

  if (!renderMobileCard) {
    return <div className="w-full overflow-x-auto">{table}</div>;
  }

  return (
    <div className="w-full">
      <ul className="sm:hidden">
        {rows.map((row) => (
          <li key={rowKey(row)} className="border-b border-ruling-200 py-4">
            {renderMobileCard(row)}
          </li>
        ))}
        {rows.length === 0 ? <li>{empty}</li> : null}
      </ul>
      <div className="hidden w-full overflow-x-auto sm:block">{table}</div>
    </div>
  );
}
