/**
 * Proof's frozen operation registry, mirrored from
 * `AUTHORITY_OPERATION_REGISTRY_V1` (crates/proof-application/src/authority.rs).
 *
 * `crates/proof-server/tests/ts_sdk_contract.rs` fails the Rust gate when this
 * table drifts from the Rust registry or when any typed input interface loses a
 * field its Rust counterpart requires.
 */

export interface OperationPair {
  readonly name: string;
  /** Exact version URI, e.g. `proof.dev/operation/changeset.add/v2`. */
  readonly version: string;
  /** Path major parsed from the version URI (`v2` -> 2). */
  readonly major: number;
}

function pair(name: string, version: string): OperationPair {
  const match = /\/v(\d+)$/.exec(version);
  if (!match) {
    throw new Error(`unparseable operation version ${version}`);
  }
  return { name, version, major: Number(match[1]) };
}

export const OPERATION_REGISTRY: readonly OperationPair[] = [
  pair("changeset.add", "proof.dev/operation/changeset.add/v2"),
  pair("changeset.commit", "proof.dev/operation/changeset.commit/v2"),
  pair("changeset.create", "proof.dev/operation/changeset.create/v2"),
  pair("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
  pair("changeset.get", "proof.dev/operation/changeset.get/v2"),
  pair("changeset.submit", "proof.dev/operation/changeset.submit/v2"),
  pair("changeset.validate", "proof.dev/operation/changeset.validate/v2"),
  pair("context.build", "proof.dev/operation/context.build/v1"),
  pair("context.build", "proof.dev/operation/context.build/v2"),
  pair("edition.create", "proof.dev/operation/edition.create/v2"),
  pair("object.query_released", "proof.dev/operation/object.query_released/v1"),
  pair("object.query_released", "proof.dev/operation/object.query_released/v2"),
  pair("release.create", "proof.dev/operation/release.create/v2"),
  pair("workspace.status", "proof.dev/operation/workspace.status/v1"),
];

export function resolveOperation(
  name: string,
  major?: number,
): OperationPair | undefined {
  return OPERATION_REGISTRY.find(
    (candidate) =>
      candidate.name === name && (major === undefined || candidate.major === major),
  );
}
