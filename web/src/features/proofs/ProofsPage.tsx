import { useState } from "react";
import {
  Button,
  DataTable,
  DialogContent,
  DialogRoot,
  EmptyState,
  FieldLabel,
  PageHeader,
  RegisterPanel,
  Select,
  Stamp,
  ToastProvider,
  stampToneForStatus,
  useToast,
} from "@/design-system";
import type { DataTableColumn } from "@/design-system";
import type { EvidenceExportSummary } from "@/api/types";
import { evidenceExports, releases } from "@/mocks/seed-content";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate(),
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}Z`;
}

const exportRows = [...evidenceExports].sort((a, b) =>
  b.created_at.localeCompare(a.created_at),
);

const releaseOptions = Object.values(releases).sort((a, b) =>
  b.created_at.localeCompare(a.created_at),
);

const ROOT_PROSE: Array<{ root: string; text: string }> = [
  {
    root: "Content",
    text: "every object named in the edition is present in the released set and matches the edition's content digest byte for byte.",
  },
  {
    root: "Authority",
    text: "each edit in the underlying ChangeSet traces to a delegation that was valid when the edit was made, ending at a human principal.",
  },
  {
    root: "Validation",
    text: "deterministic validation ran against a recorded ruleset digest, and no error-severity finding remains open.",
  },
  {
    root: "Approval",
    text: "a human principal approved the ChangeSet on their own authority; delegated agent work alone does not confer approval.",
  },
  {
    root: "Policy",
    text: "policy evaluation closed over the full change surface, anchored to an authority-head checkpoint supplied with the check.",
  },
  {
    root: "Release",
    text: "the signed envelope binds edition, approvals, and evidence together, and its signature verifies against the caller's trust set.",
  },
];

const exportColumns: Array<DataTableColumn<EvidenceExportSummary>> = [
  {
    key: "export_id",
    header: "Export",
    width: "14rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.export_id}</span>
    ),
  },
  {
    key: "release_id",
    header: "Release",
    width: "14rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.release_id}</span>
    ),
  },
  {
    key: "bundle_format",
    header: "Bundle format",
    render: (row) => (
      <span className="inline-block rounded-full border border-ruling-200 bg-paper-50 px-2 py-0.5 font-mono text-2xs leading-4 text-ink-600">
        {row.bundle_format}
      </span>
    ),
  },
  {
    key: "artifact_count",
    header: "Artifacts",
    align: "right",
    width: "7rem",
    render: (row) => (
      <span className="font-mono text-sm text-ink-900">
        {row.artifact_count}
      </span>
    ),
  },
  {
    key: "verifier_conclusion",
    header: "Conclusion",
    width: "9rem",
    render: (row) =>
      row.verifier_conclusion ? (
        <Stamp tone={stampToneForStatus(row.verifier_conclusion)}>
          {row.verifier_conclusion}
        </Stamp>
      ) : (
        <span className="text-sm text-ink-300">—</span>
      ),
  },
  {
    key: "created_at",
    header: "Created",
    align: "right",
    width: "12rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-500">
        {formatTimestamp(row.created_at)}
      </span>
    ),
  },
];

function renderExportMobileCard(row: EvidenceExportSummary) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <span
          className="block max-w-[60%] truncate font-mono text-xs text-ink-700"
          title={row.export_id}
        >
          {row.export_id}
        </span>
        {row.verifier_conclusion ? (
          <Stamp tone={stampToneForStatus(row.verifier_conclusion)}>
            {row.verifier_conclusion}
          </Stamp>
        ) : (
          <span className="text-sm text-ink-300">—</span>
        )}
      </div>
      <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1">
        <span
          className="block max-w-full truncate font-mono text-xs text-ink-500"
          title={row.release_id}
        >
          {row.release_id}
        </span>
        <span className="inline-block rounded-full border border-ruling-200 bg-paper-50 px-2 py-0.5 font-mono text-2xs leading-4 text-ink-600">
          {row.bundle_format}
        </span>
      </div>
      <p className="mt-1 font-mono text-2xs text-ink-400">
        {row.artifact_count} {row.artifact_count === 1 ? "artifact" : "artifacts"}{" "}
        · {formatTimestamp(row.created_at)}
      </p>
    </div>
  );
}

function ExportEvidenceDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { toast } = useToast();
  const [releaseId, setReleaseId] = useState("");

  function handleSubmit() {
    if (!releaseId) return;
    const environment =
      releases[releaseId]?.environment ?? "the selected environment";
    onOpenChange(false);
    setReleaseId("");
    toast({
      title: "Evidence export recorded",
      description: `A RemoteEvidenceBundleV2 bundle for ${releaseId} (${environment}) has been filed.`,
      tone: "seal",
    });
  }

  return (
    <DialogRoot open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="Export evidence"
        description="Assemble the verification artifacts for a release into a verifier-addressed bundle."
      >
        <form
          onSubmit={(event) => {
            event.preventDefault();
            handleSubmit();
          }}
        >
          <div className="space-y-1.5">
            <FieldLabel htmlFor="export-release">Release</FieldLabel>
            <Select
              id="export-release"
              value={releaseId}
              onChange={(event) => setReleaseId(event.target.value)}
            >
              <option value="">Choose a release…</option>
              {releaseOptions.map((release) => (
                <option key={release.release_id} value={release.release_id}>
                  {`${release.release_id} · ${release.environment}`}
                </option>
              ))}
            </Select>
          </div>
          <div className="mt-6 flex items-center justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={!releaseId}>
              Export bundle
            </Button>
          </div>
        </form>
      </DialogContent>
    </DialogRoot>
  );
}

function ProofsSurface() {
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Register"
        title="Proofs and Evidence"
        meta={
          <span>
            {exportRows.length} {exportRows.length === 1 ? "bundle" : "bundles"}{" "}
            on file
          </span>
        }
        actions={
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            Export Evidence
          </Button>
        }
      />
      <p className="mt-6 max-w-prose text-sm leading-6 text-ink-600">
        Proof is filed beside the release it vouches for, not assembled after
        the fact. “Every release carries its proof” is a property of this
        register: while a release exists, so does the evidence a verifier needs
        to check it — addressed, digested, and signed.
      </p>
      <RegisterPanel
        title={`Evidence exports — ${exportRows.length}`}
        className="mt-6"
      >
        <DataTable
          columns={exportColumns}
          rows={exportRows}
          rowKey={(row) => row.export_id}
          renderMobileCard={renderExportMobileCard}
          emptyState={
            <EmptyState
              title="No exports on file"
              explanation="Exporting a release files a verifier-addressed evidence bundle here."
              action={
                <Button size="sm" onClick={() => setDialogOpen(true)}>
                  Export Evidence
                </Button>
              }
            />
          }
        />
      </RegisterPanel>
      <RegisterPanel title="How verification works" className="mt-4">
        <div className="max-w-prose space-y-4 text-sm leading-6 text-ink-600">
          <p>
            A release is not pronounced complete by assertion. When a release
            is checked, the verifier walks six roots and records what each one
            showed:
          </p>
          {ROOT_PROSE.map(({ root, text }) => (
            <p key={root}>
              <span className="mr-1.5 text-2xs font-medium uppercase tracking-[0.14em] text-ink-500">
                {root}
              </span>
              {text}
            </p>
          ))}
          <p>
            A verdict of Complete means all six roots passed. Incomplete means
            at least one root could not be evaluated with the material at hand.
            Invalid means a root was evaluated and failed.
          </p>
        </div>
      </RegisterPanel>
      <ExportEvidenceDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  );
}

export default function ProofsPage() {
  return (
    <ToastProvider>
      <ProofsSurface />
    </ToastProvider>
  );
}
