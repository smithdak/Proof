import { useNavigate } from "react-router";
import {
  DataTable,
  DigestText,
  EmptyState,
  PageHeader,
  RegisterPanel,
  Stamp,
  stampToneForStatus,
} from "@/design-system";
import type { DataTableColumn } from "@/design-system";
import type { Edition, Release } from "@/api/types";
import { editions, releases, verificationReports } from "@/mocks/seed-content";
import { formatTimestamp } from "./format";

const editionRows = Object.values(editions).sort((a, b) =>
  b.created_at.localeCompare(a.created_at),
);

const releaseRows = Object.values(releases).sort((a, b) =>
  b.created_at.localeCompare(a.created_at),
);

const editionColumns: Array<DataTableColumn<Edition>> = [
  {
    key: "edition_id",
    header: "Edition",
    width: "14rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.edition_id}</span>
    ),
  },
  {
    key: "content_digest",
    header: "Content digest",
    render: (row) => (
      <DigestText
        value={row.content_digest}
        copyLabel={`Copy content digest for ${row.edition_id}`}
      />
    ),
  },
  {
    key: "object_count",
    header: "Objects",
    align: "right",
    width: "6rem",
    render: (row) => (
      <span className="font-mono text-sm text-ink-900">{row.object_count}</span>
    ),
  },
  {
    key: "locales",
    header: "Locales",
    width: "10rem",
    render: (row) => (
      <span className="flex flex-wrap gap-1">
        {row.locales.map((locale) => (
          <span
            key={locale}
            className="inline-block rounded-full border border-ruling-200 bg-paper-50 px-2 py-0.5 font-mono text-2xs leading-4 text-ink-600"
          >
            {locale}
          </span>
        ))}
      </span>
    ),
  },
  {
    key: "created_at",
    header: "Created",
    align: "right",
    width: "12rem",
    render: (row) => (
      <span className="whitespace-nowrap font-mono text-xs text-ink-500">
        {formatTimestamp(row.created_at)}
      </span>
    ),
  },
];

const releaseColumns: Array<DataTableColumn<Release>> = [
  {
    key: "release_id",
    header: "Release",
    width: "14rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.release_id}</span>
    ),
  },
  {
    key: "environment",
    header: "Environment",
    width: "8rem",
    render: (row) => (
      <span className="text-sm text-ink-800">{row.environment}</span>
    ),
  },
  {
    key: "edition_id",
    header: "Edition",
    width: "13rem",
    render: (row) => (
      <DigestText
        value={row.edition_id}
        copyLabel={`Copy edition id for ${row.release_id}`}
      />
    ),
  },
  {
    key: "created_by",
    header: "Released by",
    width: "11rem",
    render: (row) => (
      <span className="text-sm text-ink-700">{row.created_by.display_name}</span>
    ),
  },
  {
    key: "envelope_digest",
    header: "Envelope digest",
    render: (row) => (
      <DigestText
        value={row.envelope_digest}
        copyLabel={`Copy envelope digest for ${row.release_id}`}
      />
    ),
  },
  {
    key: "latest_verification",
    header: "Verdict",
    width: "9rem",
    render: (row) => {
      const verdict = verificationReports[row.release_id]?.verdict;
      return verdict ? (
        <Stamp tone={stampToneForStatus(verdict)}>{verdict}</Stamp>
      ) : (
        <span className="text-sm text-ink-300">—</span>
      );
    },
  },
];

function renderEditionMobileCard(row: Edition) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.edition_id}
        >
          {row.edition_id}
        </span>
        <span className="whitespace-nowrap font-mono text-xs text-ink-500">
          {formatTimestamp(row.created_at)}
        </span>
      </div>
      <div className="mt-1.5">
        <DigestText
          value={row.content_digest}
          copyLabel={`Copy content digest for ${row.edition_id}`}
        />
      </div>
    </div>
  );
}

function renderReleaseMobileCard(row: Release) {
  const verdict = verificationReports[row.release_id]?.verdict;
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.release_id}
        >
          {row.release_id}
        </span>
        {verdict ? (
          <Stamp tone={stampToneForStatus(verdict)}>{verdict}</Stamp>
        ) : (
          <span className="text-sm text-ink-300">—</span>
        )}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span className="text-sm text-ink-800">{row.environment}</span>
        <DigestText
          value={row.envelope_digest}
          copyLabel={`Copy envelope digest for ${row.release_id}`}
        />
      </div>
      <p className="mt-1 font-mono text-2xs text-ink-500">
        {formatTimestamp(row.created_at)}
      </p>
    </div>
  );
}

export default function ReleasesPage() {
  const navigate = useNavigate();

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Register"
        title="Editions and Releases"
        meta={
          <span>
            {editionRows.length} editions · {releaseRows.length} releases
          </span>
        }
      />
      <RegisterPanel
        title={`Editions — ${editionRows.length}`}
        className="mt-6"
      >
        <DataTable
          columns={editionColumns}
          rows={editionRows}
          rowKey={(row) => row.edition_id}
          renderMobileCard={renderEditionMobileCard}
          emptyState={
            <EmptyState
              title="No editions on file"
              explanation="Committing a ChangeSet cuts an edition of the workspace state."
            />
          }
        />
      </RegisterPanel>
      <RegisterPanel
        title={`Releases — ${releaseRows.length}`}
        className="mt-4"
      >
        <DataTable
          columns={releaseColumns}
          rows={releaseRows}
          rowKey={(row) => row.release_id}
          onRowClick={(row) => void navigate(`/releases/${row.release_id}`)}
          renderMobileCard={renderReleaseMobileCard}
          emptyState={
            <EmptyState
              title="No releases on file"
              explanation="Releasing signs an edition envelope and files its proof."
            />
          }
        />
      </RegisterPanel>
    </div>
  );
}
