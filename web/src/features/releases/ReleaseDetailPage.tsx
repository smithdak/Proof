import { ArrowLeft, Ban, RotateCcw } from "lucide-react";
import { useNavigate, useParams } from "react-router";
import {
  Button,
  DataTable,
  DigestText,
  EmptyState,
  IconButton,
  PageHeader,
  RegisterPanel,
  Stamp,
  ToastProvider,
  stampToneForStatus,
  useToast,
} from "@/design-system";
import type { DataTableColumn } from "@/design-system";
import type { DeliveryRecord } from "@/api/types";
import {
  deliveries,
  releases,
  verificationReports,
} from "@/mocks/seed-content";
import { formatTimestamp } from "./format";

function RootChecklist() {
  const { releaseId } = useParams();
  const report = releaseId ? verificationReports[releaseId] : undefined;
  if (!report) return null;

  return (
    <>
      <div className="flex flex-wrap items-start justify-between gap-x-8 gap-y-4">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <Stamp
            tone={stampToneForStatus(report.verdict)}
            className="scale-[1.35]"
          >
            {report.verdict}
          </Stamp>
          <p className="text-xs text-ink-500">
            Checked{" "}
            <span className="font-mono text-ink-600">
              {formatTimestamp(report.checked_at)}
            </span>
          </p>
        </div>
        <div className="min-w-0 max-w-md text-right">
          <p className="text-2xs font-medium uppercase tracking-[0.14em] text-ink-500">
            Trust basis
          </p>
          <p className="mt-0.5 text-sm leading-5 text-ink-700">
            {report.trust_basis}
          </p>
        </div>
      </div>
      <ul className="mt-6 divide-y divide-ruling-200 border-t border-ruling-200">
        {report.roots.map((check) => (
          <li key={check.root} className="py-3.5 first:pt-3.5 last:pb-0">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
              <span className="w-20 font-mono text-2xs uppercase tracking-[0.14em] text-ink-500">
                {check.root}
              </span>
              <span className="text-sm font-medium text-ink-900">
                {check.label}
              </span>
              <Stamp tone={stampToneForStatus(check.status)} className="ml-auto">
                {check.status}
              </Stamp>
            </div>
            {check.detail ? (
              <p className="mt-1.5 pl-[6.25rem] text-sm leading-6 text-ink-600">
                {check.detail}
              </p>
            ) : null}
          </li>
        ))}
      </ul>
    </>
  );
}

const canAct = (state: DeliveryRecord["state"]) =>
  state === "pending" || state === "failed";

const deliveryColumns: Array<DataTableColumn<DeliveryRecord>> = [
  {
    key: "delivery_id",
    header: "Delivery",
    width: "14rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.delivery_id}</span>
    ),
  },
  {
    key: "subscriber",
    header: "Subscriber",
    width: "12rem",
    render: (row) => (
      <span className="text-sm text-ink-800">{row.subscriber}</span>
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
    key: "attempts",
    header: "Attempts",
    align: "right",
    width: "6rem",
    render: (row) => (
      <span className="font-mono text-sm text-ink-900">{row.attempts}</span>
    ),
  },
  {
    key: "activity",
    header: "Activity",
    width: "13rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-500">
        {row.last_attempt_at
          ? formatTimestamp(row.last_attempt_at)
          : row.next_attempt_at
            ? `due ${formatTimestamp(row.next_attempt_at)}`
            : "—"}
      </span>
    ),
  },
  {
    key: "state",
    header: "State",
    width: "9rem",
    render: (row) => (
      <Stamp tone={stampToneForStatus(row.state)}>{row.state}</Stamp>
    ),
  },
];

function DeliveriesSection() {
  const { toast } = useToast();

  const actionColumn: DataTableColumn<DeliveryRecord> = {
    key: "actions",
    header: "",
    align: "right",
    width: "6rem",
    render: (row) => (
      <div className="flex items-center justify-end gap-1">
        <IconButton
          aria-label={`Replay delivery ${row.delivery_id}`}
          title="Replay delivery"
          disabled={!canAct(row.state)}
          className="disabled:pointer-events-none disabled:opacity-40"
          onClick={() =>
            toast({
              title: "Replay queued",
              description: `${row.delivery_id} will be offered to ${row.subscriber} again.`,
              tone: "amber",
            })
          }
        >
          <RotateCcw aria-hidden />
        </IconButton>
        <IconButton
          aria-label={`Abandon delivery ${row.delivery_id}`}
          title="Abandon delivery"
          disabled={!canAct(row.state)}
          className="disabled:pointer-events-none disabled:opacity-40 hover:bg-vermilion-50 hover:text-vermilion-700"
          onClick={() =>
            toast({
              title: "Delivery abandoned",
              description: `${row.delivery_id} will not be retried.`,
              tone: "vermilion",
            })
          }
        >
          <Ban aria-hidden />
        </IconButton>
      </div>
    ),
  };

  return (
    <RegisterPanel title={`Deliveries — ${deliveries.length}`} className="mt-4">
      <DataTable
        columns={[...deliveryColumns, actionColumn]}
        rows={deliveries}
        rowKey={(row) => row.delivery_id}
        emptyState={
          <EmptyState
            title="No deliveries on file"
            explanation="Subscribers appear here once the signed envelope is offered."
          />
        }
      />
    </RegisterPanel>
  );
}

function ReleaseDetailView() {
  const { releaseId } = useParams();
  const navigate = useNavigate();
  const release = releaseId ? releases[releaseId] : undefined;

  if (!release) {
    return (
      <div className="mx-auto max-w-3xl">
        <PageHeader
          kicker="Release"
          title="Entry not found"
          meta={<span>{releaseId}</span>}
        />
        <RegisterPanel className="mt-6">
          <EmptyState
            title="No such entry"
            explanation={`Nothing is filed under ${releaseId ?? "this id"} in this register.`}
            action={
              <Button size="sm" onClick={() => navigate("/releases")}>
                <ArrowLeft className="size-3.5" aria-hidden />
                Back to register
              </Button>
            }
          />
        </RegisterPanel>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Release"
        title={<span className="font-mono">{release.release_id}</span>}
        meta={
          <span>
            {release.environment} · released by{" "}
            {release.created_by.display_name} ·{" "}
            {formatTimestamp(release.created_at)}
          </span>
        }
      />
      <p className="mt-3 flex flex-wrap items-center gap-x-1.5 gap-y-1 text-2xs uppercase tracking-[0.14em] text-ink-400">
        Signature Key
        <DigestText
          value={release.signature_key_id}
          copyLabel="Copy signature key id"
        />
        <span aria-hidden className="px-1">
          ·
        </span>
        Envelope
        <DigestText
          value={release.envelope_digest}
          copyLabel="Copy envelope digest"
        />
      </p>
      <RegisterPanel
        title={
          verificationReports[release.release_id]
            ? "Verification report"
            : "Verification report — none on file"
        }
        className="mt-7"
      >
        {verificationReports[release.release_id] ? (
          <RootChecklist />
        ) : (
          <EmptyState
            title="Not yet verified"
            explanation="The six roots are evaluated when the release is checked against its trust set."
          />
        )}
      </RegisterPanel>
      <DeliveriesSection />
    </div>
  );
}

export default function ReleaseDetailPage() {
  return (
    <ToastProvider>
      <ReleaseDetailView />
    </ToastProvider>
  );
}
