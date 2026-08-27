import type {
  AgentOperationKey,
  HumanOperationKey,
  OperationKey,
  OperationVersionUri,
} from "./types";

export type OperationActor = "human" | "agent";
export type ApplicationIdempotency =
  | "required-uuidv7"
  | "derived-changeset"
  | "derived-proposal-policy-validator"
  | "none";

export interface OperationPair<K extends OperationKey = OperationKey> {
  readonly actor: OperationActor;
  readonly key: K;
  readonly name: string;
  readonly version: OperationVersionUri;
  readonly major: number;
  readonly resultSchema: string;
  readonly applicationIdempotency: ApplicationIdempotency;
}

function pair<const K extends OperationKey>(
  actor: OperationActor,
  key: K,
  version: OperationVersionUri,
  resultSchema: string,
  applicationIdempotency: ApplicationIdempotency,
): OperationPair<K> {
  const separator = key.lastIndexOf(":");
  const name = key.slice(0, separator);
  const majorText = key.slice(separator + 1);
  const major = Number(majorText.slice(1));
  if (!name || !Number.isSafeInteger(major) || major < 1) {
    throw new Error(`unparseable operation key ${key}`);
  }
  return {
    actor,
    key,
    name,
    version,
    major,
    resultSchema,
    applicationIdempotency,
  };
}

const LOCALIZED_OPERATIONS =
  "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/";
const LOCALIZED_ARTIFACTS =
  "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/";
const COLLABORATION_OPERATIONS =
  "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/";

export const HUMAN_OPERATION_REGISTRY = [
  pair(
    "human",
    "content-resource-intent.issue:v2",
    "proof.dev/operation/content-resource-intent.issue/v2",
    `${LOCALIZED_ARTIFACTS}contentResourceIntentV2`,
    "required-uuidv7",
  ),
  pair(
    "human",
    "schema.get:v1",
    "proof.dev/operation/schema.get/v1",
    `${LOCALIZED_OPERATIONS}schemaGetResult`,
    "none",
  ),
  pair(
    "human",
    "schema.list:v1",
    "proof.dev/operation/schema.list/v1",
    `${LOCALIZED_OPERATIONS}schemaListResult`,
    "none",
  ),
  pair(
    "human",
    "object.list:v1",
    "proof.dev/operation/object.list/v1",
    `${LOCALIZED_OPERATIONS}objectListResult`,
    "none",
  ),
] as const;

export const AGENT_OPERATION_REGISTRY = [
  pair("agent", "changeset.add:v2", "proof.dev/operation/changeset.add/v2", `${LOCALIZED_OPERATIONS}changeSetAddOutput`, "required-uuidv7"),
  pair("agent", "changeset.commit:v2", "proof.dev/operation/changeset.commit/v2", `${LOCALIZED_OPERATIONS}changeSetCommitOutput`, "required-uuidv7"),
  pair("agent", "changeset.create:v2", "proof.dev/operation/changeset.create/v2", `${LOCALIZED_OPERATIONS}changeSetCreateOutput`, "required-uuidv7"),
  pair("agent", "changeset.diff:v2", "proof.dev/operation/changeset.diff/v2", `${LOCALIZED_OPERATIONS}changeSetDiffOutput`, "none"),
  pair("agent", "changeset.get:v2", "proof.dev/operation/changeset.get/v2", `${LOCALIZED_OPERATIONS}changeSetGetOutput`, "none"),
  pair("agent", "changeset.submit:v2", "proof.dev/operation/changeset.submit/v2", `${LOCALIZED_OPERATIONS}changeSetSubmitOutput`, "derived-changeset"),
  pair("agent", "changeset.validate:v2", "proof.dev/operation/changeset.validate/v2", `${LOCALIZED_OPERATIONS}changeSetValidateOutput`, "derived-proposal-policy-validator"),
  pair("agent", "context.build:v1", "proof.dev/operation/context.build/v1", `${COLLABORATION_OPERATIONS}contextBuildResultV1`, "required-uuidv7"),
  pair("agent", "context.build:v2", "proof.dev/operation/context.build/v2", `${LOCALIZED_OPERATIONS}contextBuildOutput`, "required-uuidv7"),
  pair("agent", "edition.create:v2", "proof.dev/operation/edition.create/v2", `${LOCALIZED_OPERATIONS}editionCreateOutput`, "required-uuidv7"),
  pair("agent", "object.query_released:v1", "proof.dev/operation/object.query_released/v1", `${COLLABORATION_OPERATIONS}objectQueryReleasedResultV1`, "none"),
  pair("agent", "object.query_released:v2", "proof.dev/operation/object.query_released/v2", `${LOCALIZED_OPERATIONS}objectQueryReleasedOutput`, "none"),
  pair("agent", "release.create:v2", "proof.dev/operation/release.create/v2", `${LOCALIZED_OPERATIONS}releaseCreateOutput`, "required-uuidv7"),
  pair("agent", "workspace.status:v1", "proof.dev/operation/workspace.status/v1", `${COLLABORATION_OPERATIONS}workspaceStatusResultV1`, "none"),
] as const;

export const OPERATION_REGISTRY: readonly OperationPair[] = [
  ...HUMAN_OPERATION_REGISTRY,
  ...AGENT_OPERATION_REGISTRY,
];

export function resolveHumanOperation<K extends HumanOperationKey>(
  key: K,
): OperationPair<K> | undefined {
  return HUMAN_OPERATION_REGISTRY.find((candidate) => candidate.key === key) as
    | OperationPair<K>
    | undefined;
}

export function resolveAgentOperation<K extends AgentOperationKey>(
  key: K,
): OperationPair<K> | undefined {
  return AGENT_OPERATION_REGISTRY.find((candidate) => candidate.key === key) as
    | OperationPair<K>
    | undefined;
}

export function resolveOperation(
  actor: OperationActor,
  key: OperationKey,
): OperationPair | undefined {
  return OPERATION_REGISTRY.find(
    (candidate) => candidate.actor === actor && candidate.key === key,
  );
}
