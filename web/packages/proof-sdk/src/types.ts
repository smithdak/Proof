/**
 * Exact wire shapes over Proof's frozen collaboration-server HTTP surface.
 *
 * Input interfaces mirror the strict normalized Rust inputs in
 * `crates/proof-application/src/authority.rs` field-for-field; result and
 * envelope shapes mirror `crates/proof-server` handlers and
 * `crates/proof-remote/src/registry.rs`. The retained cross-language contract
 * test (`crates/proof-server/tests/ts_sdk_contract.rs`) fails when these
 * declarations drift from the Rust sources.
 */

/** RFC 3339 UTC timestamp as serialized on the wire (display-string form). */
export type Timestamp = string;

/** Content digest in display form, e.g. `blake3:<64 hex>`. */
export type ContentDigest = string;

/** UUIDv7 identity in display form. */
export type Uuid = string;

/** Exact version URIs carried by normalized operation inputs. */
export type OperationVersionUri = string;

// ---------------------------------------------------------------------------
// context.build
// ---------------------------------------------------------------------------

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
  api_version: OperationVersionUri;
  context_pack_id: Uuid;
  created_at: Timestamp;
  expires_at: Timestamp;
  idempotency_key: Uuid;
  limits: LocalizedContextLimitsInput;
  policy_rules: LocalizedPolicyRuleInput[];
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
}

// ---------------------------------------------------------------------------
// changeset.create / changeset.add
// ---------------------------------------------------------------------------

export interface LocalizedChangeSetCreateInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
  context_pack_digest: ContentDigest;
  context_pack_id: Uuid;
  created_at: Timestamp;
  idempotency_key: Uuid;
  intent: string;
  resource_intent_digest: ContentDigest;
  resource_intent_id: Uuid;
}

export interface LocalizedExpectedSourceInput {
  digest: ContentDigest;
  revision: number;
  schema_id: string;
  schema_version: number;
}

export interface LocalizedExpectedTargetInput {
  digest: ContentDigest;
  revision: number;
}

export type LocalizedEditKind = "object.locale.put";

export interface LocalizedSemanticEditInput {
  api_version: OperationVersionUri;
  content: Record<string, unknown>;
  expected_source: LocalizedExpectedSourceInput;
  expected_target: LocalizedExpectedTargetInput | null;
  kind: LocalizedEditKind;
  locale: string;
  object_id: Uuid;
  repair_of_validation_result_digest: ContentDigest | null;
  supersedes_edit_id: Uuid | null;
}

export interface LocalizedChangeSetAddInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
  edits: LocalizedSemanticEditInput[];
  idempotency_key: Uuid;
}

// ---------------------------------------------------------------------------
// selector / lifecycle rows
// ---------------------------------------------------------------------------

export interface ChangesetGetInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
}

export interface ChangesetDiffInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
}

export interface ChangesetValidateInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
}

export interface ChangesetSubmitInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
  submitted_at: Timestamp;
}

export interface ChangesetCommitInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
  committed_at: Timestamp;
  idempotency_key: Uuid;
}

export interface EditionCreateInputV2 {
  api_version: OperationVersionUri;
  changeset_id: Uuid;
  created_at: Timestamp;
  edition_id: Uuid;
  idempotency_key: Uuid;
  resulting_state_digest: ContentDigest;
}

export interface ReleaseCreateInputV2 {
  api_version: OperationVersionUri;
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
  api_version: OperationVersionUri;
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

export interface WorkspaceStatusInputV1 {}

/**
 * Maps every registered operation pair to its exact typed input.
 * Keyed by `${name}` with a per-major narrowing union where two majors exist.
 */
export interface OperationInputByPair {
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

/** Registry keys of every registered operation pair, `name:major`. */
export type OperationKey = keyof OperationInputByPair;

// ---------------------------------------------------------------------------
// transport envelopes
// ---------------------------------------------------------------------------

export interface RemoteOperation {
  name: string;
  version: string;
}

export interface HumanOperationRequest<TInput> {
  api_version: "proof.dev/http-human-operation-request/v1";
  operation: RemoteOperation;
  input: TInput;
  correlation_id?: Uuid;
  workspace_id?: Uuid;
}

export interface AgentOperationRequest {
  api_version: "proof.dev/http-agent-operation-request/v1";
  operation: RemoteOperation;
  /** Caller-built signed invocation (`AuthenticatedInvocationV1`). */
  invocation: Record<string, unknown>;
  correlation_id?: Uuid;
  workspace_id?: Uuid;
}

export interface AuthorityHead {
  sequence: number;
  record_digest: ContentDigest;
}

export type ApplicationConsequenceOutcome =
  | "Success"
  | "IdempotentReplay"
  | "IdempotencyConflict"
  | "PreconditionConflict"
  | "ApplicationFailure";

export interface ApplicationConsequence {
  api_version: OperationVersionUri;
  workspace_id: Uuid;
  consequence_id: Uuid;
  decision_id: Uuid;
  decision_digest: ContentDigest;
  public_input_projection_digest: ContentDigest;
  operation: RemoteOperation;
  operation_registry_sha256: string;
  outcome: ApplicationConsequenceOutcome;
  application_key_kind: string;
  application_key: Uuid | null;
  result_digest: ContentDigest | null;
  prior_result_digest: ContentDigest | null;
  application_effect_digest: ContentDigest | null;
  application_effect_authority_head: AuthorityHead | null;
  problem_code: string | null;
  recorded_at: Timestamp;
  evaluated_authority_head: AuthorityHead;
  authority_sequence: number;
  previous_authority_record_digest: ContentDigest;
  authority_key_id: string;
}

export interface CommittedAnchor {
  [member: string]: unknown;
}

export interface SuccessEnvelope {
  api_version: "proof.dev/http-operation-result/v1";
  operation: RemoteOperation;
  operation_id: Uuid;
  correlation_id: Uuid | null;
  committed_anchor: CommittedAnchor;
  result: ApplicationConsequence;
}

export interface ProblemBody {
  api_version: string;
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

// ---------------------------------------------------------------------------
// session / capabilities / preview routes
// ---------------------------------------------------------------------------

export interface SessionInfo {
  api_version: "proof.dev/session-get-result/v1";
  cache_control: string;
  csrf_token: string;
  principal_id: Uuid;
  authenticated_at: Timestamp;
  idle_expires_at: Timestamp;
  expires_at: Timestamp;
}

export interface SessionLogoutResult {
  api_version: "proof.dev/session-logout-result/v1";
  logged_out: boolean;
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
  body: Record<string, unknown>;
}
