import type { HTMLAttributes } from "react";
import type { ValidationFinding } from "@/api/types";
import { cx } from "../cx";
import { DigestText } from "./DigestText";
import { Stamp, type StampTone } from "./Stamp";

const SEVERITY_TONE: Record<ValidationFinding["severity"], StampTone> = {
  error: "vermilion",
  warning: "amber",
  info: "ruling",
};

export interface FindingCardProps extends HTMLAttributes<HTMLElement> {
  finding: ValidationFinding;
}

export function FindingCard({ finding, className, ...props }: FindingCardProps) {
  const subjectIds = [
    ...new Set(
      [finding.subject.edit_id, finding.subject.object_id].filter(
        (id): id is string => Boolean(id),
      ),
    ),
  ];

  return (
    <article
      className={cx("rounded border border-ruling-200 bg-paper-25 p-4", className)}
      {...props}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Stamp tone={SEVERITY_TONE[finding.severity]}>{finding.severity}</Stamp>
        <span className="rounded-sm border border-ruling-200 bg-paper-50 px-1.5 py-0.5 font-mono text-2xs text-ink-700">
          {finding.code}
        </span>
        {finding.subject.field_path ? (
          <span className="font-mono text-2xs text-ink-500">{finding.subject.field_path}</span>
        ) : null}
      </div>
      <p className="mt-2 max-w-prose text-sm leading-6 text-ink-800">{finding.message}</p>
      {finding.repair_guidance ? (
        <div className="mt-3 border-l-2 border-ruling-200 pl-3">
          <p className="text-2xs font-medium uppercase tracking-[0.14em] text-ink-500">Repair</p>
          <p className="mt-1 max-w-prose text-sm leading-6 text-ink-700">{finding.repair_guidance}</p>
        </div>
      ) : null}
      {subjectIds.length > 0 ? (
        <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1">
          {subjectIds.map((id) => (
            <DigestText key={id} value={id} copyLabel={`Copy ${finding.code} subject`} />
          ))}
        </div>
      ) : null}
    </article>
  );
}
