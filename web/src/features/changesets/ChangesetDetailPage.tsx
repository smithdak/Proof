import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { useNavigate, useParams } from "react-router";
import { executeOperation } from "@/api/client";
import type { ChangeSet } from "@/api/types";
import {
  Button,
  DataTable,
  DialogContent,
  DialogRoot,
  DiffRowView,
  DigestText,
  EmptyState,
  FindingCard,
  LifecycleRail,
  PageHeader,
  RegisterPanel,
  Skeleton,
  Stamp,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  ToastProvider,
  stampToneForStatus,
  useToast,
} from "@/design-system";
import type { DataTableColumn, ToastTone } from "@/design-system";
import type { ChangeSetEdit, ValidationFinding } from "@/api/types";
import { diffs, validationResults } from "@/mocks/seed-content";
import { edits as editsByChangeset, supersessions } from "@/mocks/seed-edits";
import { formatTimestamp } from "./format";
import { operations, readChangeset } from "./store";

const SEVERITY_ORDER: Record<ValidationFinding["severity"], number> = {
  error: 0,
  warning: 1,
  info: 2,
};

function renderValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "string") return value;
  return JSON.stringify(value) ?? "—";
}

function DiffTab({ changesetId }: { changesetId: string }) {
  const diff = diffs[changesetId];
  if (!diff || diff.rows.length === 0) {
    return (
      <EmptyState
        title="No diff on file"
        explanation="A rendered diff arrives once edits are appended and the entry is read against its base state."
      />
    );
  }
  return (
    <div className="max-w-3xl space-y-5">
      {diff.rows.map((row) => {
        const firstEdit = row.edit_ids[0];
        return (
          <DiffRowView
            key={firstEdit ?? `${row.object_id}:${row.field_path}`}
            row={row}
            supersededBy={firstEdit ? supersessions[firstEdit] : undefined}
          />
        );
      })}
    </div>
  );
}

function FindingsTab({ changesetId }: { changesetId: string }) {
  const result = validationResults[changesetId];
  if (!result) {
    return (
      <EmptyState
        title="No findings on file"
        explanation="Run Validate to evaluate this entry against the active ruleset."
      />
    );
  }
  const ordered = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  return (
    <div className="max-w-3xl space-y-4">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-ink-500">
        <span>Verdict</span>
        <Stamp tone={stampToneForStatus(result.verdict)}>
          {result.verdict}
        </Stamp>
        <span aria-hidden>·</span>
        <span>Ruleset</span>
        <DigestText value={result.ruleset_digest} copyLabel="Copy ruleset digest" />
        <span aria-hidden>·</span>
        <span className="font-mono">
          Evaluated {formatTimestamp(result.validated_at)}
        </span>
      </p>
      {ordered.map((finding) => (
        <FindingCard
          key={`${finding.code}:${finding.subject.edit_id ?? finding.subject.object_id ?? ""}`}
          finding={finding}
        />
      ))}
    </div>
  );
}

const editColumns: Array<DataTableColumn<ChangeSetEdit>> = [
  {
    key: "edit_id",
    header: "Edit",
    width: "13rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.edit_id}</span>
    ),
  },
  {
    key: "object_id",
    header: "Object",
    width: "11rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.object_id}</span>
    ),
  },
  {
    key: "op",
    header: "Op",
    width: "5rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-600">{row.op}</span>
    ),
  },
  {
    key: "field_path",
    header: "Field",
    width: "11rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-900">{row.field_path}</span>
    ),
  },
  {
    key: "before",
    header: "Before",
    width: "16rem",
    render: (row) => (
      <span className="block max-w-[15rem] truncate font-mono text-xs text-ink-500">
        {renderValue(row.before)}
      </span>
    ),
  },
  {
    key: "after",
    header: "After",
    width: "16rem",
    render: (row) => (
      <span className="block max-w-[15rem] truncate font-mono text-xs text-ink-900">
        {renderValue(row.after)}
      </span>
    ),
  },
  {
    key: "note",
    header: "Note",
    render: (row) => {
      const supersession = supersessions[row.edit_id];
      if (supersession) {
        return (
          <span className="block max-w-xs text-xs leading-5 text-amber-screen-700">
            <span className="mr-1.5 text-2xs font-medium uppercase tracking-[0.14em]">
              Superseded
            </span>
            {supersession}
          </span>
        );
      }
      if (row.rationale) {
        return (
          <span className="block max-w-xs text-xs leading-5 text-ink-600">
            {row.rationale}
          </span>
        );
      }
      return <span className="text-xs text-ink-300">—</span>;
    },
  },
];

function EditsTab({ changesetId }: { changesetId: string }) {
  const rows = editsByChangeset[changesetId] ?? [];
  return (
    <RegisterPanel title={`Raw edits — ${rows.length}`}>
      <DataTable
        columns={editColumns}
        rows={rows}
        rowKey={(row) => row.edit_id}
        className="-mx-1"
        emptyState={
          <EmptyState
            title="No edits appended"
            explanation="Edits appear here as they are appended to the entry."
          />
        }
      />
    </RegisterPanel>
  );
}

const ACTION_LABELS: Record<string, string> = {
  validate: "Validate",
  submit: "Submit",
  approve: "Approve",
  commit: "Commit",
};

function ChangesetDetailView() {
  const { changesetId } = useParams();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [pendingKey, setPendingKey] = useState<string | null>(null);
  const [confirmAction, setConfirmAction] = useState<
    "approve" | "commit" | null
  >(null);

  const { data: fetched, isPending, isError } = useQuery({
    queryKey: ["changeset", changesetId],
    enabled: Boolean(changesetId),
    retry: false,
    queryFn: async () => {
      if (!changesetId) throw new Error("No ChangeSet id in route");
      return executeOperation<ChangeSet>("changeset.get", {
        changeset_id: changesetId,
      });
    },
  });

  if (isPending) {
    return (
      <div
        className="mx-auto max-w-6xl"
        role="status"
        aria-label="Reading ChangeSet entry"
      >
        <Skeleton className="h-3 w-24" />
        <Skeleton className="mt-4 h-8 max-w-xl" />
        <Skeleton className="mt-3 h-4 w-80" />
        <Skeleton className="mt-8 h-12 max-w-md" />
        <Skeleton className="mt-10 h-44" />
      </div>
    );
  }

  if (isError || !fetched) {
    return (
      <div className="mx-auto max-w-3xl">
        <PageHeader
          kicker="ChangeSet"
          title="Entry not found"
          meta={<span>{changesetId}</span>}
        />
        <RegisterPanel className="mt-6">
          <EmptyState
            title="No such entry"
            explanation={`Nothing is filed under ${changesetId ?? "this id"} in this register.`}
            action={
              <Button size="sm" onClick={() => navigate("/changesets")}>
                <ArrowLeft className="size-3.5" aria-hidden />
                Back to register
              </Button>
            }
          />
        </RegisterPanel>
      </div>
    );
  }

  const live = readChangeset(fetched.changeset_id);
  const entry = live ?? fetched;

  async function runOperation(
    key: string,
    apply: () => void,
    confirmation: { title: string; description?: string; tone: ToastTone },
  ) {
    if (pendingKey) return;
    setPendingKey(key);
    try {
      await Promise.resolve();
      apply();
      toast(confirmation);
    } catch {
      toast({
        title: `${ACTION_LABELS[key]} refused`,
        description:
          "The operation did not record; review the entry and try again.",
        tone: "vermilion",
      });
    } finally {
      setPendingKey(null);
    }
  }

  const rejection =
    entry.status === "rejected"
      ? validationResults[entry.changeset_id]
      : undefined;
  const rejectionError = rejection?.findings.find(
    (finding) => finding.severity === "error",
  );

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="ChangeSet"
        title={entry.intent}
        meta={
          <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>Filed by {entry.created_by.display_name}</span>
            {entry.delegation ? (
              <>
                <span aria-hidden>·</span>
                <span>Delegation</span>
                <DigestText
                  value={entry.delegation.delegation_id}
                  copyLabel="Copy delegation id"
                />
              </>
            ) : null}
            <span aria-hidden>·</span>
            <span>Base state</span>
            <DigestText
              value={entry.base_state_digest}
              copyLabel="Copy base state digest"
            />
          </span>
        }
        actions={
          <>
            {entry.status === "draft" ? (
              <Button
                size="sm"
                disabled={pendingKey !== null}
                onClick={() =>
                  void runOperation(
                    "validate",
                    () => operations.validate(entry.changeset_id),
                    {
                      title: "Validation recorded",
                      description: `No findings recorded against ${entry.changeset_id}.`,
                      tone: "seal",
                    },
                  )
                }
              >
                Validate
              </Button>
            ) : null}
            {entry.status === "draft" || entry.status === "validated" ? (
              <Button
                size="sm"
                disabled={pendingKey !== null}
                onClick={() =>
                  void runOperation(
                    "submit",
                    () => operations.submit(entry.changeset_id),
                    {
                      title: "Submitted for approval",
                      description: `${entry.changeset_id} awaits a human decision.`,
                      tone: "amber",
                    },
                  )
                }
              >
                Submit
              </Button>
            ) : null}
            {entry.status === "submitted" ? (
              <Button
                variant="consequential"
                size="sm"
                disabled={pendingKey !== null}
                onClick={() => setConfirmAction("approve")}
              >
                Approve
              </Button>
            ) : null}
            {entry.status === "approved" ? (
              <Button
                variant="consequential"
                size="sm"
                disabled={pendingKey !== null}
                onClick={() => setConfirmAction("commit")}
              >
                Commit
              </Button>
            ) : null}
          </>
        }
      />
      {entry.status === "rejected" ? (
        <div
          role="alert"
          className="mt-6 rounded border border-vermilion-500 bg-vermilion-50 px-4 py-3.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Stamp tone="vermilion">Rejected</Stamp>
            <span className="rounded-sm border border-vermilion-600 px-1.5 py-0.5 font-mono text-2xs text-vermilion-700">
              {rejectionError?.code ?? "VAL-000"}
            </span>
            <span className="text-sm font-medium text-vermilion-700">
              This entry was refused by deterministic validation.
            </span>
          </div>
          <p className="mt-2 max-w-prose text-sm leading-6 text-vermilion-700">
            {rejectionError?.repair_guidance ??
              "Resolve the recorded findings with a superseding Edit, then resubmit the entry for validation."}
          </p>
        </div>
      ) : null}
      <LifecycleRail status={entry.status} className="mt-7" />
      <Tabs defaultValue="diff" className="mt-8">
        <TabsList aria-label="ChangeSet entry sections">
          <TabsTrigger value="diff">Diff</TabsTrigger>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="edits">Edits</TabsTrigger>
        </TabsList>
        <TabsContent value="diff">
          <DiffTab changesetId={entry.changeset_id} />
        </TabsContent>
        <TabsContent value="findings">
          <FindingsTab changesetId={entry.changeset_id} />
        </TabsContent>
        <TabsContent value="edits">
          <EditsTab changesetId={entry.changeset_id} />
        </TabsContent>
      </Tabs>
      <DialogRoot
        open={confirmAction !== null}
        onOpenChange={(open) => {
          if (!open) setConfirmAction(null);
        }}
      >
        <DialogContent
          title={
            confirmAction === "commit"
              ? "Commit this ChangeSet?"
              : "Approve this ChangeSet?"
          }
          description={
            confirmAction === "commit"
              ? "Committing materializes the approved entry into workspace state under the recorded delegation. A commit cannot be undone."
              : "Approval records your decision in the authority chain. An approval cannot be withdrawn."
          }
        >
          <p className="font-mono text-xs text-ink-600">
            {entry.changeset_id}
          </p>
          <div className="mt-6 flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setConfirmAction(null)}
            >
              Cancel
            </Button>
            <Button
              variant="consequential"
              size="sm"
              disabled={pendingKey !== null}
              onClick={() => {
                const which = confirmAction;
                setConfirmAction(null);
                if (which === "approve") {
                  void runOperation(
                    "approve",
                    () => operations.approve(entry.changeset_id),
                    {
                      title: "Approval recorded",
                      description: `${entry.changeset_id} may now be committed.`,
                      tone: "seal",
                    },
                  );
                }
                if (which === "commit") {
                  void runOperation(
                    "commit",
                    () => operations.commit(entry.changeset_id),
                    {
                      title: "ChangeSet committed",
                      description: `${entry.changeset_id} materialized into workspace state.`,
                      tone: "seal",
                    },
                  );
                }
              }}
            >
              {confirmAction === "commit"
                ? "Commit irreversibly"
                : "Approve entry"}
            </Button>
          </div>
        </DialogContent>
      </DialogRoot>
    </div>
  );
}

export default function ChangesetDetailPage() {
  return (
    <ToastProvider>
      <ChangesetDetailView />
    </ToastProvider>
  );
}
