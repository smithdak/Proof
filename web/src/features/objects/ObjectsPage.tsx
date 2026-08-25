import { useMemo, useState } from "react";
import {
  DataTable,
  DigestText,
  EmptyState,
  FieldLabel,
  PageHeader,
  RegisterPanel,
  Select,
} from "@/design-system";
import type { DataTableColumn } from "@/design-system";
import type { ReleasedObject } from "@/api/types";
import { releasedObjects, releases } from "@/mocks/seed-content";
import { workspaceStatus } from "@/mocks/seed-core";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate(),
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}Z`;
}

const ENVIRONMENTS = workspaceStatus.environments.map((env) => env.name);

const ENVIRONMENT_BY_RELEASE = new Map(
  Object.values(releases).map((release) => [
    release.release_id,
    release.environment,
  ]),
);

function LocaleChip({ locale }: { locale: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-ruling-200 bg-paper-50 px-1.5 font-mono text-2xs leading-4 text-ink-600">
      {locale}
    </span>
  );
}

function FieldValue({ value }: { value: unknown }) {
  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return <p className="max-w-prose text-sm leading-6 text-ink-800">{String(value)}</p>;
  }
  return (
    <pre className="max-w-prose overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-5 text-ink-800">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function FieldsRecord({ object }: { object: ReleasedObject }) {
  const entries = Object.entries(object.fields);
  return (
    <section
      aria-label={`Fields record for ${object.object_id}`}
      className="mt-4 border-t border-ruling-200 pt-4"
    >
      <dl className="divide-y divide-ruling-200">
        {entries.map(([key, value]) => (
          <div
            key={key}
            className="grid gap-x-4 gap-y-1 py-3 first:pt-0 last:pb-0 sm:grid-cols-[10rem_1fr]"
          >
            <dt className="pt-0.5 font-mono text-2xs uppercase tracking-[0.14em] text-ink-500">
              {key}
            </dt>
            <dd>
              <FieldValue value={value} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

const columns: Array<DataTableColumn<ReleasedObject>> = [
  {
    key: "object_id",
    header: "Object",
    width: "13rem",
    render: (row) => (
      <span
        className="block truncate font-mono text-xs text-ink-700"
        title={row.object_id}
      >
        {row.object_id}
      </span>
    ),
  },
  {
    key: "schema_id",
    header: "Schema",
    width: "10rem",
    render: (row) => (
      <span
        className="block truncate font-mono text-xs text-ink-700"
        title={row.schema_id}
      >
        {row.schema_id}
      </span>
    ),
  },
  {
    key: "locale",
    header: "Locale",
    width: "8rem",
    render: (row) => <LocaleChip locale={row.locale} />,
  },
  {
    key: "edition_id",
    header: "Edition",
    render: (row) => (
      <DigestText
        value={row.edition_id}
        copyLabel={`Copy edition id ${row.edition_id}`}
      />
    ),
  },
  {
    key: "released_at",
    header: "Released",
    align: "right",
    width: "12rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-500">
        {formatTimestamp(row.released_at)}
      </span>
    ),
  },
];

function renderObjectMobileCard(row: ReleasedObject) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.object_id}
        >
          {row.object_id}
        </span>
        <span className="whitespace-nowrap font-mono text-xs text-ink-500">
          {formatTimestamp(row.released_at)}
        </span>
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.schema_id}
        >
          {row.schema_id}
        </span>
        <LocaleChip locale={row.locale} />
      </div>
    </div>
  );
}

export default function ObjectsPage() {
  const [environment, setEnvironment] = useState(ENVIRONMENTS[0] ?? "preview");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const visibleObjects = useMemo(
    () =>
      releasedObjects.filter(
        (object) =>
          ENVIRONMENT_BY_RELEASE.get(object.release_id) === environment,
      ),
    [environment],
  );

  const selected =
    visibleObjects.find((object) => object.object_id === selectedId) ?? null;

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Register"
        title="Released content"
        meta={
          <span>
            {visibleObjects.length} object
            {visibleObjects.length === 1 ? "" : "s"} live in {environment}
          </span>
        }
      />
      <div className="mt-6 flex items-baseline gap-3">
        <FieldLabel htmlFor="released-environment">Environment</FieldLabel>
        <Select
          id="released-environment"
          className="w-44"
          value={environment}
          onChange={(event) => {
            setEnvironment(event.target.value);
            setSelectedId(null);
          }}
        >
          {ENVIRONMENTS.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </Select>
      </div>
      <RegisterPanel title={`Release ledger — ${environment}`} className="mt-4">
        <DataTable
          columns={columns}
          rows={visibleObjects}
          rowKey={(row) => row.object_id}
          selectedKey={selectedId}
          onRowClick={(row) =>
            setSelectedId((current) =>
              current === row.object_id ? null : row.object_id,
            )
          }
          renderMobileCard={renderObjectMobileCard}
          emptyState={
            <EmptyState
              title={`Nothing released in ${environment}`}
              explanation="Objects enter this ledger when an edition carrying them is released to this environment."
            />
          }
        />
        {selected ? <FieldsRecord object={selected} /> : null}
      </RegisterPanel>
    </div>
  );
}
