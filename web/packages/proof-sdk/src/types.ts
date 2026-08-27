/** Exact wire types for Proof's frozen collaboration-server HTTP surface. */

export type Timestamp = string;
export type ContentDigest = string;
export type Uuid = string;
export type OperationVersionUri = `proof.dev/operation/${string}/v${number}`;
export type JsonObject = Record<string, unknown>;

export interface LocalizedContextLimitsInput {
  max_bytes: number;
  max_edits: number;
  max_objects: number;
  max_validation_attempts: number;
}

export interface LocalizedPolicyRuleInput {
  disallowed_values: string[];
  locale: string;
  pointer: string;
}

export interface LocalizedExpectedSourceInput {
  digest: ContentDigest;
  revision: 1;
  schema_id: string;
  schema_version: number;
}

export interface LocalizedExpectedTargetInput {
  digest: ContentDigest;
  revision: number;
}

interface LocalizedEditCommon {
  api_version: "proof.dev/edit/v2";
  content: JsonObject;
  object_id: Uuid;
  repair_of_validation_result_digest: ContentDigest | null;
  supersedes_edit_id: Uuid | null;
}

/** Existing-object locale mutation. Creation-only members are forbidden. */
export interface LocalizedObjectLocalePutEditInput extends LocalizedEditCommon {
  kind: "object.locale.put";
  expected_source: LocalizedExpectedSourceInput;
  expected_target: LocalizedExpectedTargetInput | null;
  locale: string;
  schema_id?: never;
  schema_version?: never;
}

export interface LocalizedObjectCreateEditCommon extends LocalizedEditCommon {
  kind: "object.create";
  schema_id: string;
  schema_version: number;
  expected_source?: never;
  expected_target?: never;
  locale?: never;
}

export type LocalizedObjectCreateEditInput =
  | (LocalizedObjectCreateEditCommon & {
      supersedes_edit_id: null;
      repair_of_validation_result_digest: null;
    })
  | (LocalizedObjectCreateEditCommon & {
      supersedes_edit_id: Uuid;
      repair_of_validation_result_digest: ContentDigest;
    });

export type LocalizedSemanticEditInput =
  | LocalizedObjectLocalePutEditInput
  | LocalizedObjectCreateEditInput;
export type LocalizedEditKind = LocalizedSemanticEditInput["kind"];

export interface StateReference {
  api_version: "proof.dev/known-state/v1" | "proof.dev/known-state/v2";
  authoritative_sequence: number;
  digest: ContentDigest;
}

export interface EditionReference {
  api_version: "proof.dev/edition/v1" | "proof.dev/edition/v2";
  digest: ContentDigest;
  edition_id: Uuid;
}

export interface ReleaseReference {
  api_version: "proof.dev/release/v1" | "proof.dev/release/v2";
  digest: ContentDigest;
  release_id: Uuid;
}

export interface ContentResourceTarget {
  locale: string;
  object_id: Uuid;
  schema_id: string;
}

export interface ContentResourceCreationSlotV2 {
  locales: string[];
  object_id: Uuid;
  schema_id: string;
}

export interface ContentResourceBaseline {
  edition: EditionReference;
  known_state: StateReference;
  release: ReleaseReference;
}

export interface ContentResourceIntentV2 {
  api_version: "proof.dev/content-resource-intent/v2";
  base: ContentResourceBaseline;
  creations?: ContentResourceCreationSlotV2[];
  environment_id: string;
  intent_id: Uuid;
  issued_at: Timestamp;
  issued_by_principal_id: Uuid;
  targets: ContentResourceTarget[];
  workspace_id: Uuid;
}

export interface ReadProvenance {
  authoritative_sequence: number;
  changeset_id: Uuid;
  edit_id: Uuid;
}

// Four direct-Human pairs adopted from P-0021.

export interface ContentResourceIntentIssueInputV2 {
  api_version: "proof.dev/operation/content-resource-intent.issue/v2";
  creations?: ContentResourceCreationSlotV2[];
  environment_id: string;
  idempotency_key: Uuid;
  intent_id: Uuid;
  issued_at: Timestamp;
  targets: ContentResourceTarget[];
}

export interface SchemaGetInputV1 {
  api_version: "proof.dev/operation/schema.get/v1";
  schema_id: string;
  schema_version: number;
}

export interface SchemaGetResultV1 {
  document: JsonObject;
  document_digest: ContentDigest;
  provenance: ReadProvenance;
  schema_id: string;
  schema_version: number;
}

export interface SchemaListInputV1 {
  api_version: "proof.dev/operation/schema.list/v1";
  cursor?: string;
  page_size?: number;
  schema_id?: string;
}

export interface SchemaListEntryV1 {
  document_digest: ContentDigest;
  provenance: ReadProvenance;
  schema_id: string;
  schema_version: number;
}

export interface SchemaListResultV1 {
  entries: SchemaListEntryV1[];
  next_cursor?: string;
}

export interface ObjectListInputV1 {
  api_version: "proof.dev/operation/object.list/v1";
  cursor?: string;
  environment_id: string;
  locale?: string;
  object_ids?: Uuid[];
  page_size?: number;
  schema_id?: string;
}

export interface ObjectHeadRenditionV1 {
  locale: string;
  rendition_digest: ContentDigest;
  revision: number;
}

export interface ObjectListEntryV1 {
  covered_by_current_release: boolean;
  head_renditions: ObjectHeadRenditionV1[];
  object_id: Uuid;
  released_revision: number | null;
  schema_id: string;
  schema_version: number;
}

export interface ObjectListResultV1 {
  entries: ObjectListEntryV1[];
  next_cursor?: string;
  state_scope: "committed-workspace-state-not-necessarily-released";
}

export interface HumanOperationInputByPair {
  "content-resource-intent.issue:v2": ContentResourceIntentIssueInputV2;
  "schema.get:v1": SchemaGetInputV1;
  "schema.list:v1": SchemaListInputV1;
  "object.list:v1": ObjectListInputV1;
}

export interface HumanOperationResultByPair {
  "content-resource-intent.issue:v2": ContentResourceIntentV2;
  "schema.get:v1": SchemaGetResultV1;
  "schema.list:v1": SchemaListResultV1;
  "object.list:v1": ObjectListResultV1;
}

export interface HumanOperationResultSchemaByPair {
  "content-resource-intent.issue:v2": "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/contentResourceIntentV2";
  "schema.get:v1": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/schemaGetResult";
  "schema.list:v1": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/schemaListResult";
  "object.list:v1": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/objectListResult";
}

export type HumanOperationKey = keyof HumanOperationInputByPair;

// Fourteen retained Agent pairs.

export interface ContextBuildInputV1 {
  operating_principal_id: Uuid;
  delegation_id: Uuid;
  task_id: string;
  intent: string;
  environment_id: string;
  object_ids: Uuid[];
  max_objects: number;
  max_bytes: number;
  idempotency_key: Uuid;
  expires_at: Timestamp;
}

export interface LocalizedContextBuildInputV2 {
  api_version: "proof.dev/operation/context.build/v2";
  context_pack_id: Uuid;
  created_at: Timestamp;
  expires_at: Timestamp;
  idempotency_key: Uuid;
  limits: LocalizedContextLimitsInput;
  policy_rules: LocalizedPolicyRuleInput[];
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
}

export interface LocalizedChangeSetCreateInputV2 {
  api_version: "proof.dev/operation/changeset.create/v2";
  changeset_id: Uuid;
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  created_at: Timestamp;
  idempotency_key: Uuid;
  intent: string;
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
}

export interface LocalizedChangeSetAddInputV2 {
  api_version: "proof.dev/operation/changeset.add/v2";
  changeset_id: Uuid;
  edits: LocalizedSemanticEditInput[];
  idempotency_key: Uuid;
}

export interface ChangesetGetInputV2 {
  api_version: "proof.dev/operation/changeset.get/v2";
  changeset_id: Uuid;
}

export interface ChangesetDiffInputV2 {
  api_version: "proof.dev/operation/changeset.diff/v2";
  changeset_id: Uuid;
}

export interface ChangesetValidateInputV2 {
  api_version: "proof.dev/operation/changeset.validate/v2";
  changeset_id: Uuid;
}

export interface ChangesetSubmitInputV2 {
  api_version: "proof.dev/operation/changeset.submit/v2";
  changeset_id: Uuid;
  submitted_at: Timestamp;
}

export interface ChangesetCommitInputV2 {
  api_version: "proof.dev/operation/changeset.commit/v2";
  changeset_id: Uuid;
  committed_at: Timestamp;
  idempotency_key: Uuid;
}

export interface EditionCreateInputV2 {
  api_version: "proof.dev/operation/edition.create/v2";
  changeset_id: Uuid;
  created_at: Timestamp;
  edition_id: Uuid;
  idempotency_key: Uuid;
  resulting_state_digest: ContentDigest;
}

export interface ReleaseCreateInputV2 {
  api_version: "proof.dev/operation/release.create/v2";
  edition_id: Uuid;
  environment_id: string;
  expected_base_release_id: Uuid;
  idempotency_key: Uuid;
  proof_id: Uuid;
  release_id: Uuid;
  released_at: Timestamp;
}

export interface ReleasedTargetInput {
  locale: string;
  object_id: Uuid;
}

export interface ObjectQueryReleasedInputV2 {
  api_version: "proof.dev/operation/object.query_released/v2";
  environment_id: string;
  evaluated_at: Timestamp;
  targets: ReleasedTargetInput[];
}

export interface ObjectQueryReleasedInputV1 {
  operating_principal_id: Uuid;
  delegation_id: Uuid;
  environment_id: string;
  object_ids: Uuid[];
}

export type WorkspaceStatusInputV1 = Record<string, never>;

export interface AgentOperationInputByPair {
  "changeset.add:v2": LocalizedChangeSetAddInputV2;
  "changeset.commit:v2": ChangesetCommitInputV2;
  "changeset.create:v2": LocalizedChangeSetCreateInputV2;
  "changeset.diff:v2": ChangesetDiffInputV2;
  "changeset.get:v2": ChangesetGetInputV2;
  "changeset.submit:v2": ChangesetSubmitInputV2;
  "changeset.validate:v2": ChangesetValidateInputV2;
  "context.build:v1": ContextBuildInputV1;
  "context.build:v2": LocalizedContextBuildInputV2;
  "edition.create:v2": EditionCreateInputV2;
  "object.query_released:v1": ObjectQueryReleasedInputV1;
  "object.query_released:v2": ObjectQueryReleasedInputV2;
  "release.create:v2": ReleaseCreateInputV2;
  "workspace.status:v1": WorkspaceStatusInputV1;
}

export interface ChangeSetAddResultV2 {
  changeset_id: Uuid;
  edit_ids: Uuid[];
  first_ordinal: number;
  total_edit_count: number;
}

export interface ChangeSetCreateResultV2 {
  base_state: StateReference;
  changeset_id: Uuid;
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
  status: "draft";
}

export interface ChangeSetV2 {
  api_version: "proof.dev/changeset/v2";
  base_state: StateReference;
  changeset_id: Uuid;
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  created_at: Timestamp;
  edits: JsonObject[];
  effective_leaf_digest: ContentDigest;
  effective_leaves: JsonObject[];
  intent: string;
  principal_id: Uuid;
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
  workspace_id: Uuid;
}

export interface ChangeSetDiffResultV2 {
  changeset_id: Uuid;
  effective_edits: JsonObject[];
  effective_leaf_digest: ContentDigest;
  proposal_digest: ContentDigest;
}

export interface ValidationFindingV2 {
  code: "proof.validation.prohibited_legal_claim";
  edit_id: Uuid;
  locale: string;
  object_id: Uuid;
  pointer: string | null;
  policy_digest: ContentDigest;
  severity: "info" | "warning" | "error";
  validator: "proof/localized-content/1";
}

export interface ChangeSetValidateResultV2 {
  attempt: number;
  changeset_id: Uuid;
  effective_leaf_digest: ContentDigest;
  findings: ValidationFindingV2[];
  previous_validation_result_digest: ContentDigest | null;
  proposal_digest: ContentDigest;
  sealed_changeset_digest: ContentDigest | null;
  status: "draft" | "ready";
  valid: boolean;
  validation_results_digest: ContentDigest;
}

export interface ChangeSetSubmitResultV2 {
  changeset_id: Uuid;
  sealed_changeset_digest: ContentDigest;
  status: "submitted";
  submitted_at: Timestamp;
  validation_results_digest: ContentDigest;
}

export interface ObjectLocaleRevisionV1 extends JsonObject {
  api_version: "proof.dev/object-locale-revision/v1";
  authoritative_sequence: number;
  changeset_id: Uuid;
  content: JsonObject;
  edit_id: Uuid;
  locale: string;
  object_id: Uuid;
  previous_revision_digest: ContentDigest | null;
  revision: number;
  schema_id: string;
  schema_version: number;
  source_object_digest: ContentDigest;
  source_object_revision: 1;
  workspace_id: Uuid;
}

export interface ChangeSetCommitResultV2 {
  changeset_id: Uuid;
  committed_at: Timestamp;
  previous_state: StateReference;
  renditions: ObjectLocaleRevisionV1[];
  resulting_state: StateReference;
  sealed_changeset_digest: ContentDigest;
  status: "committed";
  validation_results_digest: ContentDigest;
}

export interface ContextBuildResultV1 {
  base_state: ContentDigest;
  built_at: Timestamp;
  capabilities: OperationVersionUri[];
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  delegation_id: Uuid;
  edition_id: Uuid;
  environment_id: string;
  expires_at: Timestamp;
  intent: string;
  limits: { max_bytes: number; max_objects: number };
  manifest_json: string;
  object_ids: Uuid[];
  operating_principal_id: Uuid;
  release_id: Uuid;
  requesting_principal_id: Uuid;
  task_id: string;
  workspace_id: Uuid;
}

export interface ContextBuildResultV2 {
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  manifest: JsonObject;
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
}

export interface EditionCreateResultV2 {
  edition_digest: ContentDigest;
  edition_id: Uuid;
  manifest: JsonObject;
  state: StateReference;
}

export interface ObjectQueryReleasedResultV1 {
  authorization_decision_digest: ContentDigest;
  delegation_id: Uuid;
  edition_id: Uuid;
  environment_id: string;
  objects: JsonObject[];
  principal_id: Uuid;
  release_id: Uuid;
  workspace_id: Uuid;
}

export interface ReleasedRenditionV2 {
  content: JsonObject;
  locale: string;
  object_id: Uuid;
  rendition_digest: ContentDigest;
  rendition_revision: number;
  schema_id: string;
  schema_version: number;
  source_digest: ContentDigest;
  source_revision: 1;
}

export interface ObjectQueryReleasedResultV2 {
  edition: EditionReference;
  environment_id: string;
  release_id: Uuid;
  renditions: ReleasedRenditionV2[];
  workspace_id: Uuid;
}

export interface ReleaseCreateResultV2 {
  proof_envelope_digest: ContentDigest;
  proof_id: Uuid;
  release_digest: ContentDigest;
  release_id: Uuid;
  release_manifest: JsonObject;
}

export interface WorkspaceStatusResultV1 {
  authoritative_sequence: number;
  authorization_decision_digest: ContentDigest;
  delegation_id: Uuid;
  operating_principal_id: Uuid;
  requesting_principal_id: Uuid;
  state_digest: ContentDigest;
  storage_schema_version: number;
  workspace_id: Uuid;
}

export interface AgentOperationResultByPair {
  "changeset.add:v2": ChangeSetAddResultV2;
  "changeset.commit:v2": ChangeSetCommitResultV2;
  "changeset.create:v2": ChangeSetCreateResultV2;
  "changeset.diff:v2": ChangeSetDiffResultV2;
  "changeset.get:v2": ChangeSetV2;
  "changeset.submit:v2": ChangeSetSubmitResultV2;
  "changeset.validate:v2": ChangeSetValidateResultV2;
  "context.build:v1": ContextBuildResultV1;
  "context.build:v2": ContextBuildResultV2;
  "edition.create:v2": EditionCreateResultV2;
  "object.query_released:v1": ObjectQueryReleasedResultV1;
  "object.query_released:v2": ObjectQueryReleasedResultV2;
  "release.create:v2": ReleaseCreateResultV2;
  "workspace.status:v1": WorkspaceStatusResultV1;
}

export interface AgentOperationResultSchemaByPair {
  "changeset.add:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetAddOutput";
  "changeset.commit:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetCommitOutput";
  "changeset.create:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetCreateOutput";
  "changeset.diff:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetDiffOutput";
  "changeset.get:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetGetOutput";
  "changeset.submit:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetSubmitOutput";
  "changeset.validate:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetValidateOutput";
  "context.build:v1": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/contextBuildResultV1";
  "context.build:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/contextBuildOutput";
  "edition.create:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/editionCreateOutput";
  "object.query_released:v1": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/objectQueryReleasedResultV1";
  "object.query_released:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/objectQueryReleasedOutput";
  "release.create:v2": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/releaseCreateOutput";
  "workspace.status:v1": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/workspaceStatusResultV1";
}

export type AgentOperationKey = keyof AgentOperationInputByPair;
export type OperationKey = HumanOperationKey | AgentOperationKey;

export interface RemoteOperation {
  name: string;
  version: OperationVersionUri;
}

export interface HumanOperationRequest<TInput> {
  api_version: "proof.dev/http-human-operation-request/v1";
  workspace_id: Uuid;
  operation: RemoteOperation;
  correlation_id: Uuid | null;
  idempotency_key: Uuid | null;
  input: TInput;
}

export interface AgentOperationRequest {
  api_version: "proof.dev/http-agent-operation-request/v1";
  operation: RemoteOperation;
  correlation_id: Uuid | null;
  invocation: Record<string, unknown>;
}

export interface CommittedTransactionAnchor {
  kind: "committed-transaction";
  digest: ContentDigest;
  transaction_sequence: number;
}

export interface ImmutableResultAnchor {
  kind: "immutable-result";
  digest: ContentDigest;
  transaction_sequence: null;
}

export type ResultAnchor = CommittedTransactionAnchor | ImmutableResultAnchor;
export type CommittedAnchor = ResultAnchor;

export interface SuccessEnvelope<TData = unknown, TResultSchema extends string = string> {
  api_version: "proof.dev/http-operation-result/v1";
  operation: RemoteOperation;
  operation_id: Uuid;
  correlation_id: Uuid | null;
  replayed: boolean;
  result_anchor: ResultAnchor;
  result_schema: TResultSchema;
  data: TData;
}

export type HumanOperationEnvelope<K extends HumanOperationKey> = SuccessEnvelope<
  HumanOperationResultByPair[K],
  HumanOperationResultSchemaByPair[K]
>;

export type AgentOperationEnvelope<K extends AgentOperationKey> = SuccessEnvelope<
  AgentOperationResultByPair[K],
  AgentOperationResultSchemaByPair[K]
>;

export interface ProblemBody {
  api_version: "proof.dev/http-problem/v1";
  type: string;
  title: string;
  status: number;
  code: string;
  operation: RemoteOperation | null;
  operation_id: Uuid;
  correlation_id: Uuid | null;
  retryable: boolean;
  instance: string;
  retry_after_ms?: number;
}

export interface SessionInfo {
  api_version: "proof.dev/session-get-result/v1";
  cache_control: "private, no-store";
  csrf_token: string;
  principal_id: Uuid;
  authenticated_at: Timestamp;
  idle_expires_at: Timestamp;
  expires_at: Timestamp;
}

export interface SessionLogoutResult {
  api_version: "proof.dev/session-logout-result/v1";
  logged_out: true;
}

export interface CapabilitiesDiscoverResult {
  api_version: "proof.dev/capabilities-discover-result/v1";
  profile: string;
  registry: unknown;
  registry_canonicalization: "RFC8785";
  registry_digest_algorithm: "sha-256";
  registry_schema: string;
  registry_sha256: string;
  route_count: number;
  human_operation_count: number;
  agent_operation_count: number;
}

export interface PreviewObjectResult {
  release_id: Uuid;
  release_digest: ContentDigest;
  edition_digest: ContentDigest;
  rendition_digest: ContentDigest;
  body: JsonObject;
}
