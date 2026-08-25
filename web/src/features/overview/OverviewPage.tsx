import { useNavigate } from "react-router";
import {
  Button,
  DataTable,
  DigestText,
  EmptyState,
  LifecycleRail,
  PageHeader,
  RegisterPanel,
  SectionHeading,
  Stamp,
  stampToneForStatus,
} from "@/design-system";
import type { ChangeSet } from "@/api/types";
import { changesets, workspaceStatus } from "@/mocks/seed-core";
import { releases, verificationReports } from "@/mocks/seed-content";

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
      <span className="whitespace-nowrap text-sm text-ink-700">
        {row.created_by.display_name}
      </span>
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
      <span className="whitespace-nowrap font-mono text-xs text-ink-500">
        {formatTimestamp(row.updated_at)}
      </span>
    ),
  },
];

function renderChangesetMobileCard(row: ChangeSet) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.changeset_id}
        >
          {row.changeset_id}
        </span>
        <Stamp tone={stampToneForStatus(row.status)}>{row.status}</Stamp>
      </div>
      <p className="mt-1.5 line-clamp-2 text-sm leading-5 text-ink-900">
        {row.intent}
      </p>
      <p className="mt-1.5 font-mono text-xs text-ink-500">
        by {row.created_by.display_name} · {row.edit_count} edits
      </p>
      <p className="mt-1 font-mono text-2xs text-ink-400">
        {formatTimestamp(row.updated_at)}
      </p>
    </div>
  );
}

const openChangeSets = [...changesets].sort((a, b) =>
  b.updated_at.localeCompare(a.updated_at),
);

const STATUS_ADVANCEMENT: Record<ChangeSet["status"], number> = {
  draft: 0,
  validated: 1,
  submitted: 2,
  approved: 3,
  committed: 4,
  rejected: -1,
};

const leadingEntry = [...openChangeSets]
  .filter((cs) => cs.status !== "committed" && cs.status !== "rejected")
  .sort(
    (a, b) =>
      STATUS_ADVANCEMENT[b.status] - STATUS_ADVANCEMENT[a.status] ||
      b.updated_at.localeCompare(a.updated_at),
  )[0];

const latestReleases = Object.values(releases).sort((a, b) =>
  b.created_at.localeCompare(a.created_at),
);

const lastReleaseByEnvironment: Record<string, string> = {};
for (const release of Object.values(releases)) {
  const known = lastReleaseByEnvironment[release.environment];
  if (!known || release.created_at > known) {
    lastReleaseByEnvironment[release.environment] = release.created_at;
  }
}

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
          <Button size="sm" variant="consequential" onClick={() => navigate("/changesets")}>
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
          renderMobileCard={renderChangesetMobileCard}
          emptyState={<EmptyState title="No open entries" />}
        />
      </RegisterPanel>
      <p className="mt-3 flex items-center gap-1.5 text-2xs uppercase tracking-[0.14em] text-ink-400">
        Known State
        <DigestText value={workspaceStatus.known_state_digest} copyLabel="Copy Known State digest" />
      </p>
      {leadingEntry ? (
        <section className="mt-10">
          <SectionHeading>Leading entry</SectionHeading>
          <button
            type="button"
            onClick={() => void navigate(`/changesets/${leadingEntry.changeset_id}`)}
            className="mt-1 block w-full border-b border-ruling-200 py-4 text-left transition-colors duration-150 hover:bg-paper-100"
          >
            <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2">
              <span className="font-mono text-xs text-ink-700">
                {leadingEntry.changeset_id}
              </span>
              <Stamp tone={stampToneForStatus(leadingEntry.status)}>
                {leadingEntry.status}
              </Stamp>
            </div>
            <p className="mt-1.5 max-w-prose text-sm text-ink-900">
              {leadingEntry.intent}
            </p>
            <LifecycleRail
              status={leadingEntry.status}
              className="mt-4"
            />
          </button>
        </section>
      ) : null}
      <section className="mt-10">
        <SectionHeading>Latest releases</SectionHeading>
        <ul className="mt-1 divide-y divide-ruling-200">
          {latestReleases.map((release) => {
            const verdict = verificationReports[release.release_id]?.verdict;
            return (
              <li key={release.release_id}>
                <button
                  type="button"
                  onClick={() => void navigate(`/releases/${release.release_id}`)}
                  className="flex w-full flex-wrap items-center gap-x-4 gap-y-1 py-2.5 text-left transition-colors duration-150 ease-out hover:bg-paper-100 motion-reduce:transition-none"
                >
                  <span className="font-mono text-xs text-ink-700">
                    {release.release_id}
                  </span>
                  <span className="text-sm text-ink-800">{release.environment}</span>
                  <span className="text-sm text-ink-600">
                    released by {release.created_by.display_name}
                  </span>
                  <span className="ml-auto whitespace-nowrap font-mono text-xs text-ink-500">
                    {formatTimestamp(release.created_at)}
                  </span>
                  {verdict ? (
                    <Stamp tone={stampToneForStatus(verdict)}>{verdict}</Stamp>
                  ) : (
                    <span className="text-sm text-ink-300">—</span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </section>
      <section className="mt-8">
        <SectionHeading>Environments</SectionHeading>
        <ul className="mt-1 divide-y divide-ruling-200">
          {workspaceStatus.environments.map((environment) => {
            const lastReleaseAt = lastReleaseByEnvironment[environment.name];
            return (
              <li
                key={environment.name}
                className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2.5"
              >
                <span className="text-sm font-medium text-ink-900">
                  {environment.name}
                </span>
                <span className="text-sm text-ink-600">
                  requires {environment.required_approval ?? "no"} approval
                </span>
                <span className="ml-auto whitespace-nowrap font-mono text-xs text-ink-500">
                  {lastReleaseAt
                    ? `last release ${formatTimestamp(lastReleaseAt)}`
                    : "no releases on file"}
                </span>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}
