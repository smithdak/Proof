import { useState } from "react";
import {
  Button,
  DataTable,
  DialogContent,
  DialogRoot,
  DigestText,
  EmptyState,
  FieldLabel,
  PageHeader,
  RegisterPanel,
  Select,
  Stamp,
  Textarea,
  ToastProvider,
  useToast,
} from "@/design-system";
import type { StampTone } from "@/design-system";
import type { DelegationRef, Principal, PrincipalKind } from "@/api/types";
import type { DataTableColumn } from "@/design-system";
import { delegations as seededDelegations, principals } from "@/mocks/seed-core";

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate(),
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}Z`;
}

const PRINCIPAL_LIST: Principal[] = Object.values(principals);

const KIND_TONES: Record<PrincipalKind, StampTone> = {
  human: "ruling",
  agent: "amber",
  service: "seal",
};

function principalName(principalId: string): string {
  return principals[principalId]?.display_name ?? principalId;
}

function principalOptionLabel(principal: Principal): string {
  return `${principal.display_name} · ${principal.kind}`;
}

function DelegationParties({
  issuedBy,
  grantedTo,
}: {
  issuedBy: string;
  grantedTo: string;
}) {
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
      <span className="text-sm font-medium text-ink-900">
        {principalName(issuedBy)}
      </span>
      <span aria-hidden className="relative inline-flex h-3 w-9 shrink-0">
        <span className="absolute left-0 right-[5px] top-1/2 h-px -translate-y-1/2 bg-ruling-400" />
        <svg
          className="absolute right-0 top-1/2 -translate-y-1/2 text-ruling-500"
          width="6"
          height="8"
          viewBox="0 0 6 8"
          fill="none"
        >
          <path
            d="M1 1l4 3-4 3"
            stroke="currentColor"
            strokeWidth="1.25"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </span>
      <span className="text-sm font-medium text-ink-900">
        {principalName(grantedTo)}
      </span>
    </span>
  );
}

function ExpiryLine({ expiresAt }: { expiresAt: string | null }) {
  return (
    <span className="font-mono text-xs text-ink-500">
      {expiresAt ? `expires ${formatTimestamp(expiresAt)}` : "no expiry"}
    </span>
  );
}

const principalColumns: Array<DataTableColumn<Principal>> = [
  {
    key: "kind",
    header: "Kind",
    width: "8rem",
    render: (row) => (
      <Stamp tone={KIND_TONES[row.kind]}>{row.kind}</Stamp>
    ),
  },
  {
    key: "display_name",
    header: "Name",
    render: (row) => (
      <span className="text-sm font-medium text-ink-900">
        {row.display_name}
      </span>
    ),
  },
  {
    key: "principal_id",
    header: "Principal",
    width: "15rem",
    render: (row) => (
      <span
        className="block truncate font-mono text-xs text-ink-700"
        title={row.principal_id}
      >
        {row.principal_id}
      </span>
    ),
  },
  {
    key: "key_id",
    header: "Key id",
    width: "14rem",
    render: (row) =>
      row.key_id ? (
        <DigestText
          value={row.key_id}
          copyLabel={`Copy key id for ${row.display_name}`}
        />
      ) : (
        <span className="text-sm text-ink-300">—</span>
      ),
  },
];

function renderPrincipalMobileCard(row: Principal) {
  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Stamp tone={KIND_TONES[row.kind]}>{row.kind}</Stamp>
        <span className="text-sm font-medium text-ink-900">
          {row.display_name}
        </span>
      </div>
      <p
        className="mt-1.5 truncate font-mono text-xs text-ink-700"
        title={row.principal_id}
      >
        {row.principal_id}
      </p>
    </div>
  );
}

function AuthoritySurface() {
  const { toast } = useToast();
  const [locallyRevoked, setLocallyRevoked] = useState<Set<string>>(new Set());
  const [revokeTarget, setRevokeTarget] = useState<DelegationRef | null>(null);
  const [issueOpen, setIssueOpen] = useState(false);
  const [granteeId, setGranteeId] = useState("");
  const [scope, setScope] = useState("");

  const isRevoked = (delegation: DelegationRef) =>
    delegation.revoked || locallyRevoked.has(delegation.delegation_id);

  const revokedCount = seededDelegations.filter(isRevoked).length;
  const activeCount = seededDelegations.length - revokedCount;

  function handleRevokeConfirm() {
    if (!revokeTarget) return;
    setLocallyRevoked((current) => {
      const next = new Set(current);
      next.add(revokeTarget.delegation_id);
      return next;
    });
    toast({
      title: "Delegation revoked",
      description: `${revokeTarget.delegation_id} can no longer confer authority.`,
      tone: "seal",
    });
    setRevokeTarget(null);
  }

  function handleIssueSubmit() {
    if (!granteeId || !scope.trim()) return;
    toast({
      title: "Delegation issued",
      description: `Stub submission for ${principalName(granteeId)} — nothing has been written to the register yet.`,
      tone: "seal",
    });
    setIssueOpen(false);
    setGranteeId("");
    setScope("");
  }

  return (
    <div className="mx-auto max-w-6xl">
      <PageHeader
        kicker="Register"
        title="Authority"
        meta={
          <span>
            {PRINCIPAL_LIST.length} principals · {activeCount} active /{" "}
            {revokedCount} revoked delegations
          </span>
        }
        actions={
          <Button size="sm" onClick={() => setIssueOpen(true)}>
            Issue delegation
          </Button>
        }
      />

      <RegisterPanel
        title={`Principals — ${PRINCIPAL_LIST.length}`}
        className="mt-6"
      >
        <DataTable
          columns={principalColumns}
          rows={PRINCIPAL_LIST}
          rowKey={(row) => row.principal_id}
          renderMobileCard={renderPrincipalMobileCard}
          emptyState={
            <EmptyState
              title="No principals on file"
              explanation="Principals appear here once they are provisioned in the workspace."
            />
          }
        />
      </RegisterPanel>

      <RegisterPanel title={`Delegations — ${seededDelegations.length}`} className="mt-4">
        {seededDelegations.length === 0 ? (
          <EmptyState
            title="No delegations on file"
            explanation="Issue a delegation to give a principal standing to act within a stated scope."
          />
        ) : (
          <ul className="divide-y divide-ruling-200">
            {seededDelegations.map((delegation) => {
              const revoked = isRevoked(delegation);
              return (
                <li
                  key={delegation.delegation_id}
                  className="relative py-4 first:pt-0 last:pb-0"
                >
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                    <DelegationParties
                      issuedBy={delegation.issued_by}
                      grantedTo={delegation.granted_to}
                    />
                    {revoked ? (
                      <Stamp tone="vermilion" className="select-none">
                        REVOKED
                      </Stamp>
                    ) : null}
                    <div className="ml-auto flex items-center gap-4">
                      <ExpiryLine expiresAt={delegation.expires_at} />
                      {!revoked ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-vermilion-700 hover:bg-vermilion-50 hover:text-vermilion-700"
                          onClick={() => setRevokeTarget(delegation)}
                        >
                          Revoke
                        </Button>
                      ) : null}
                    </div>
                  </div>
                  <p
                    className={`mt-1.5 max-w-prose text-sm leading-6 ${
                      revoked ? "text-ink-500" : "text-ink-600"
                    }`}
                  >
                    {delegation.scope_summary}
                  </p>
                  <p className="mt-1 font-mono text-2xs text-ink-500">
                    {delegation.delegation_id}
                  </p>
                </li>
              );
            })}
          </ul>
        )}
      </RegisterPanel>

      <DialogRoot open={revokeTarget != null} onOpenChange={(open) => { if (!open) setRevokeTarget(null); }}>
        <DialogContent
          title="Revoke this delegation?"
          description={
            revokeTarget
              ? `${principalName(revokeTarget.issued_by)} → ${principalName(revokeTarget.granted_to)}: ${revokeTarget.scope_summary}`
              : undefined
          }
        >
          <p className="max-w-prose text-sm leading-6 text-ink-700">
            Revocation is irreversible and takes effect immediately. Entries
            already made under this delegation stand; nothing new may be done
            with it.
          </p>
          <div className="mt-6 flex justify-end gap-2">
            <Button size="sm" onClick={() => setRevokeTarget(null)}>
              Cancel
            </Button>
            <Button size="sm" variant="consequential" onClick={handleRevokeConfirm}>
              Revoke delegation
            </Button>
          </div>
        </DialogContent>
      </DialogRoot>

      <DialogRoot open={issueOpen} onOpenChange={setIssueOpen}>
        <DialogContent
          title="Issue a delegation"
          description="Grant a principal standing to act within a stated scope."
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              handleIssueSubmit();
            }}
          >
            <div className="space-y-5">
              <div>
                <FieldLabel htmlFor="issue-grantee">Grantee</FieldLabel>
                <Select
                  id="issue-grantee"
                  className="mt-1"
                  value={granteeId}
                  onChange={(event) => setGranteeId(event.target.value)}
                >
                  <option value="">Choose a principal…</option>
                  {PRINCIPAL_LIST.map((principal) => (
                    <option key={principal.principal_id} value={principal.principal_id}>
                      {principalOptionLabel(principal)}
                    </option>
                  ))}
                </Select>
              </div>
              <div>
                <FieldLabel htmlFor="issue-scope">Scope</FieldLabel>
                <Textarea
                  id="issue-scope"
                  className="mt-1"
                  placeholder="What may the grantee do, against which objects or locales?"
                  value={scope}
                  onChange={(event) => setScope(event.target.value)}
                />
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <Button size="sm" type="button" onClick={() => setIssueOpen(false)}>
                Cancel
              </Button>
              <Button size="sm" type="submit" disabled={!granteeId || !scope.trim()}>
                Record delegation
              </Button>
            </div>
          </form>
        </DialogContent>
      </DialogRoot>
    </div>
  );
}

export default function AuthorityPage() {
  return (
    <ToastProvider>
      <AuthoritySurface />
    </ToastProvider>
  );
}
