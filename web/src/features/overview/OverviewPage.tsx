import { useNavigate } from "react-router";
import {
  Button,
  DataTable,
  DigestText,
  EmptyState,
  PageHeader,
  RegisterPanel,
  Stamp,
  stampToneForStatus,
} from "@/design-system";
import type { ChangeSet } from "@/api/types";
import { changesets, workspaceStatus } from "@/mocks/seed-core";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate(),
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}Z`;
}

const columns = [
  {
    key: "changeset_id",
    header: "Entry",
    width: "13rem",
    render: (row: ChangeSet) => (
      <span className="font-mono text-xs text-ink-700">{row.changeset_id}</span>
    ),
  },
  {
    key: "intent",
    header: "Intent",
    render: (row: ChangeSet) => (
      <span className="block max-w-md truncate text-sm text-ink-900">
        {row.intent}
      </span>
    ),
  },
  {
    key: "status",
    header: "Status",
    width: "9rem",
    render: (row: ChangeSet) => (
      <Stamp tone={stampToneForStatus(row.status)}>{row.status}</Stamp>
    ),
  },
  {
    key: "created_by",
    header: "Initiated by",
    width: "11rem",
    render: (row: ChangeSet) => (
      <span className="text-sm text-ink-700">{row.created_by.display_name}</span>
    ),
  },
  {
    key: "edit_count",
    header: "Edits",
    align: "right" as const,
    width: "5rem",
    render: (row: ChangeSet) => (
      <span className="font-mono text-sm text-ink-900">{row.edit_count}</span>
    ),
  },
  {
    key: "updated_at",
    header: "Entered",
    align: "right" as const,
    width: "12rem",
    render: (row: ChangeSet) => (
      <span className="font-mono text-xs text-ink-500">
        {formatTimestamp(row.updated_at)}
      </span>
    ),
  },
];

const openChangeSets = [...changesets].sort((a, b) =>
  b.updated_at.localeCompare(a.updated_at),
);

export default function OverviewPage() {
  const navigate = useNavigate();

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Workspace register"
        title="Overview"
        meta={
          <span>
            {openChangeSets.length} open entries ·{" "}
            {workspaceStatus.environments.map((env) => env.name).join(" · ")}
          </span>
        }
        actions={
          <Button
            variant="consequential"
            size="sm"
            onClick={() => navigate("/changesets")}
          >
            New ChangeSet
          </Button>
        }
      />
      <RegisterPanel title={`Open ChangeSets — ${openChangeSets.length}`} className="mt-6">
        <DataTable
          columns={columns}
          rows={openChangeSets}
          rowKey={(row: ChangeSet) => row.changeset_id}
          onRowClick={(row: ChangeSet) =>
            void navigate(`/changesets/${row.changeset_id}`)
          }
          emptyState={<EmptyState title="No open entries" />}
        />
      </RegisterPanel>
      <p className="mt-3 flex items-center gap-1.5 text-2xs uppercase tracking-[0.14em] text-ink-400">
        Known State
        <DigestText value={workspaceStatus.known_state_digest} copyLabel="Copy Known State digest" />
      </p>
    </div>
  );
}
