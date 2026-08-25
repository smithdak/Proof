import { useState } from "react";
import type { FormEvent } from "react";
import { useNavigate } from "react-router";
import {
  Button,
  DataTable,
  DialogContent,
  DialogRoot,
  EmptyState,
  FieldLabel,
  Input,
  PageHeader,
  RegisterPanel,
  Stamp,
  ToastProvider,
  stampToneForStatus,
  useToast,
} from "@/design-system";
import type { DataTableColumn } from "@/design-system";
import type { ChangeSet } from "@/api/types";
import { formatTimestamp } from "./format";
import { createDraft, useChangesets } from "./store";

const columns: Array<DataTableColumn<ChangeSet>> = [
  {
    key: "changeset_id",
    header: "Entry",
    width: "13rem",
    render: (row) => (
      <span className="font-mono text-xs text-ink-700">{row.changeset_id}</span>
    ),
  },
  {
    key: "intent",
    header: "Intent",
    render: (row) => (
      <span className="block max-w-md truncate text-sm text-ink-900">
        {row.intent}
      </span>
    ),
  },
  {
    key: "status",
    header: "Status",
    width: "9rem",
    render: (row) => (
      <Stamp tone={stampToneForStatus(row.status)}>{row.status}</Stamp>
    ),
  },
  {
    key: "created_by",
    header: "Initiated by",
    width: "11rem",
    render: (row) => (
      <span className="text-sm text-ink-700">
        {row.created_by.display_name}
      </span>
    ),
  },
  {
    key: "locale_scope",
    header: "Locales",
    width: "10rem",
    render: (row) =>
      row.locale_scope.length === 0 ? (
        <span className="font-mono text-xs text-ink-300">—</span>
      ) : (
        <span className="flex flex-wrap gap-1">
          {row.locale_scope.map((locale) => (
            <span
              key={locale}
              className="rounded-full border border-ruling-200 bg-paper-50 px-1.5 font-mono text-2xs leading-4 text-ink-600"
            >
              {locale}
            </span>
          ))}
        </span>
      ),
  },
  {
    key: "edit_count",
    header: "Edits",
    align: "right",
    width: "5rem",
    render: (row) => (
      <span className="font-mono text-sm text-ink-900">{row.edit_count}</span>
    ),
  },
  {
    key: "updated_at",
    header: "Updated",
    align: "right",
    width: "12rem",
    render: (row) => (
      <span className="whitespace-nowrap font-mono text-xs text-ink-500">
        {formatTimestamp(row.updated_at)}
      </span>
    ),
  },
];

function NewChangeSetDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (entry: ChangeSet) => void;
}) {
  const { toast } = useToast();
  const [intent, setIntent] = useState("");

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const created = createDraft({ intent });
      setIntent("");
      onOpenChange(false);
      onCreated(created);
      toast({
        title: "ChangeSet opened",
        description: `${created.changeset_id} entered in draft.`,
        tone: "seal",
      });
    } catch {
      toast({
        title: "Entry refused",
        description: "The ChangeSet needs an intent before it can be filed.",
        tone: "vermilion",
      });
    }
  }

  return (
    <DialogRoot open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title="Open a ChangeSet"
        description="Name the change intent. Edits are appended once the entry exists."
      >
        <form onSubmit={handleSubmit}>
          <div className="space-y-1.5">
            <FieldLabel htmlFor="new-changeset-intent">Intent</FieldLabel>
            <Input
              id="new-changeset-intent"
              value={intent}
              maxLength={200}
              autoComplete="off"
              placeholder="What this entry accomplishes"
              onChange={(event) => setIntent(event.target.value)}
            />
          </div>
          <div className="mt-6 flex items-center justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={!intent.trim()}>
              Open entry
            </Button>
          </div>
        </form>
      </DialogContent>
    </DialogRoot>
  );
}

function ChangesetsRegister() {
  const navigate = useNavigate();
  const entries = useChangesets();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Register"
        title="ChangeSets"
        meta={<span>{entries.length} entries on file</span>}
        actions={
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            New ChangeSet
          </Button>
        }
      />
      <RegisterPanel title={`Entries — ${entries.length}`} className="mt-6">
        <DataTable
          columns={columns}
          rows={entries}
          rowKey={(row) => row.changeset_id}
          selectedKey={selectedId}
          onRowClick={(row) => {
            void navigate(`/changesets/${row.changeset_id}`);
          }}
          emptyState={
            <EmptyState
              title="No entries"
              explanation="Open a ChangeSet to begin a governed change."
              action={
                <Button size="sm" onClick={() => setDialogOpen(true)}>
                  New ChangeSet
                </Button>
              }
            />
          }
        />
      </RegisterPanel>
      <NewChangeSetDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        onCreated={(entry) => setSelectedId(entry.changeset_id)}
      />
    </div>
  );
}

export default function ChangesetsPage() {
  return (
    <ToastProvider>
      <ChangesetsRegister />
    </ToastProvider>
  );
}
