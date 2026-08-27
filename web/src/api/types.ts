/**
 * Domain projections of Proof's frozen operation registry.
 *
 * These shapes mirror the canonical vocabulary (Object, Schema, Edit,
 * ChangeSet, Edition, Release, Proof, Principal, Delegation, ContextPack).
 * They are console-side projections used by the typed client and the MSW
 * contract mocks; byte-level parity with proof-remote payloads is a tracked
 * follow-up, not a claim made here.
 */

export type PrincipalKind = "human" | "agent" | "service";

export interface Principal {
  principal_id: string;
  kind: PrincipalKind;
  display_name: string;
  /** Ed25519 key id when the principal holds bindings (`ed25519:<64-hex>`). */
  key_id?: string;
}

export interface DelegationRef {
  delegation_id: string;
  issued_by: string;
  granted_to: string;
  scope_summary: string;
  expires_at: string | null;
  revoked: boolean;
}

export type EditOperation = "set" | "replace" | "append" | "remove";

export interface ChangeSetEdit {
  edit_id: string;
  object_id: string;
  schema_id: string;
  locale?: string;
  op: EditOperation;
  field_path: string;
  before?: unknown;
  after?: unknown;
  rationale?: string;
  superseded_by?: string;
}

export type ChangeSetStatus =
  | "draft"
  | "validated"
  | "submitted"
  | "approved"
  | "committed"
  | "rejected";

export interface ChangeSet {
  changeset_id: string;
  intent: string;
  status: ChangeSetStatus;
  created_at: string;
  created_by: Principal;
  delegation?: Pick<DelegationRef, "delegation_id" | "granted_to"> & {
    issued_by: string;
  };
  base_state_digest: string;
  locale_scope: string[];
  environment_scope?: string;
  edit_count: number;
  updated_at: string;
}

export interface ValidationFindingSubject {
  edit_id?: string;
  object_id?: string;
  field_path?: string;
}

export interface ValidationFinding {
  code: string;
  severity: "error" | "warning" | "info";
  message: string;
  repair_guidance?: string;
  subject: ValidationFindingSubject;
}

export interface ValidationResult {
  changeset_id: string;
  verdict: "accepted" | "rejected";
  findings: ValidationFinding[];
  ruleset_digest: string;
  validated_at: string;
}

export interface DiffRow {
  object_id: string;
  schema_id: string;
  locale?: string;
  field_path: string;
  before: unknown;
  after: unknown;
  edit_ids: string[];
}

export interface ChangesetDiff {
  changeset_id: string;
  rows: DiffRow[];
}

export interface Edition {
  edition_id: string;
  changeset_id: string;
  created_at: string;
  content_digest: string;
  object_count: number;
  locales: string[];
}

export interface Environment {
  name: string;
  required_approval?: string;
}

export type ReleaseVerificationVerdict = "Complete" | "Incomplete" | "Invalid";

export interface VerificationRootCheck {
  root: string;
  label: string;
  status: "passed" | "failed" | "not_evaluated";
  detail?: string;
}

export interface VerificationReport {
  release_id: string;
  verdict: ReleaseVerificationVerdict;
  checked_at: string;
  trust_basis: string;
  roots: VerificationRootCheck[];
}

export interface Release {
  release_id: string;
  edition_id: string;
  environment: string;
  created_at: string;
  created_by: Principal;
  envelope_digest: string;
  signature_key_id: string;
  latest_verification?: VerificationReport;
}

export interface ReleasedObject {
  object_id: string;
  schema_id: string;
  locale: string;
  fields: Record<string, unknown>;
  edition_id: string;
  release_id: string;
  released_at: string;
}

export interface DeliveryRecord {
  delivery_id: string;
  environment: string;
  subscriber: string;
  state: "pending" | "delivered" | "failed" | "abandoned";
  attempts: number;
  last_attempt_at?: string;
  next_attempt_at?: string;
}

export interface EvidenceExportSummary {
  export_id: string;
  release_id: string;
  created_at: string;
  artifact_count: number;
  bundle_format: "RemoteEvidenceBundleV2";
  verifier_conclusion?: ReleaseVerificationVerdict;
}

export interface WorkspaceStatus {
  workspace_id: string;
  name: string;
  known_state_digest: string;
  environments: Environment[];
  principal_count: number;
  open_changesets: number;
  last_release?: {
    release_id: string;
    environment: string;
    created_at: string;
  };
}

export interface OperationResult<T> {
  outcome: "committed" | "returned";
  result: T;
}

export type OperationName =
  | "workspace.status"  | "capabilities.discover"
  | "changeset.create"
  | "changeset.add"
  | "changeset.diff"
  | "changeset.get"
  | "changeset.validate"
  | "changeset.submit"
  | "changeset.approve"
  | "changeset.commit"
  | "edition.create"
  | "release.create"
  | "release.get"
  | "release.verify"
  | "object.query_released"
  | "evidence.export"
  | "delegation.issue"
  | "delegation.revoke"
  | "delivery.get"
  | "delivery.replay"
  | "delivery.abandon"
  | "context.build";

export const OPERATION_MAJOR: Record<OperationName, number> = {
  "workspace.status": 1,
  "capabilities.discover": 1,
  "changeset.create": 1,
  "changeset.add": 1,
  "changeset.diff": 1,
  "changeset.get": 1,
  "changeset.validate": 1,
  "changeset.submit": 1,
  "changeset.approve": 1,
  "changeset.commit": 1,
  "edition.create": 1,
  "release.create": 1,
  "release.get": 1,
  "release.verify": 1,
  "object.query_released": 1,
  "evidence.export": 1,
  "delegation.issue": 1,
  "delegation.revoke": 1,
  "delivery.get": 1,
  "delivery.replay": 1,
  "delivery.abandon": 1,
  "context.build": 1,
};
