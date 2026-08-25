import { X } from "lucide-react";
import type { ChangeSetStatus } from "@/api/types";
import { cx } from "../cx";

const STATIONS: ChangeSetStatus[] = [
  "draft",
  "validated",
  "submitted",
  "approved",
  "committed",
];

function titleCase(status: ChangeSetStatus): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

export interface LifecycleRailProps {
  status: ChangeSetStatus;
  className?: string;
}

export function LifecycleRail({ status, className }: LifecycleRailProps) {
  const isRejected = status === "rejected";
  const currentIndex = STATIONS.indexOf(status);
  const visibleStations = isRejected ? STATIONS.slice(0, 3) : STATIONS;

  return (
    <ol aria-label="ChangeSet lifecycle stations" className={cx("flex items-start", className)}>
      {visibleStations.map((station, index) => {
        const reached = isRejected || currentIndex >= 0;
        const passed = reached && (isRejected ? index < 2 : index < currentIndex);
        const active = !isRejected && index === currentIndex;
        const touched = isRejected && index === 2;
        const dotClass = passed
          ? "bg-seal-600"
          : active
            ? "bg-amber-screen-600"
            : touched
              ? "bg-ink-300"
              : "border border-ruling-400 bg-paper-25";
        const labelClass = active
          ? "text-ink-900 font-medium"
          : passed
            ? "text-ink-700"
            : touched
              ? "text-ink-700"
              : "text-ink-500";
        return (
          <li key={station} className="relative flex items-start" aria-current={active ? "step" : undefined}>
            {index > 0 ? (
              <span
                aria-hidden
                className={cx(
                  "mt-[5px] h-px w-8 shrink-0",
                  isRejected && index === 2 ? "bg-vermilion-500" : "bg-ruling-200",
                )}
              />
            ) : null}
            <div className="flex flex-col items-center gap-1.5 px-2">
              <span aria-hidden className={cx("size-2.5 rounded-full", dotClass)} />
              <span className={cx("whitespace-nowrap text-2xs uppercase tracking-[0.14em]", labelClass)}>
                {titleCase(station)}
              </span>
            </div>
          </li>
        );
      })}
      {isRejected ? (
        <li className="relative flex items-start" aria-current="step">
          <span
            aria-hidden
            className="mt-[5px] h-px w-7 shrink-0 origin-left rotate-[24deg] bg-vermilion-500"
          />
          <div className="ml-3 flex flex-col items-center gap-1.5 pt-3">
            <X className="size-3.5 text-vermilion-700" strokeWidth={3} aria-hidden />
            <span className="text-2xs font-medium uppercase tracking-[0.14em] text-vermilion-700">
              Rejected
            </span>
          </div>
        </li>
      ) : null}
    </ol>
  );
}
