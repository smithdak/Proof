//! Shared storage-backend parity boundary and the parity runner (contract
//! §"Conformance and falsification plan").
//!
//! The [`StorageBackend`] trait itself lives in [`proof_remote::oracle`] so the
//! shared conformance runner can produce byte-identical [`OracleTraceV1`]
//! records from either the retained SQLite reference path or the PostgreSQL
//! path without a `proof-remote -> proof-pg` dependency. This module supplies
//! the PostgreSQL implementation ([`PostgresBackend`]), the parity
//! scenario/runner, and the SQLite-to-PostgreSQL parity import that persists
//! the localized content facts the wave-1 importer did not.

use proof_application::Timestamp;
use proof_application::authority::{
    AuthorityOperation, LocalizedChangeSetCreateInputV2, LocalizedChangeSetGetInputV2,
    LocalizedContextBuildInputV2, WorkspaceStatusInputV1,
};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest};
use proof_remote::{
    AuthenticatedActorContextV2, AuthorityHeadV1, OracleConsequence, OracleOutcome, OracleTraceV1,
    RemoteError, RemoteOperationV1, StableProblem, StorageBackend,
    application_problem_digest_preimage, derive_key_digest, normalized_operation_input_digest,
    operation_effect_digest,
};
use serde_json::Value;

use crate::{PgError, import::SqliteToPostgresImporter, wiring::PgRuntime};

/// The stable problem code selected when a normalized input cannot be decoded
/// into the operation's strict typed shape (mirrors the closed oracle code).
const INPUT_SCHEMA_MISMATCH_CODE: &str = "proof.input.schema_mismatch";

/// Domain-separated BLAKE3-256 derive-key context for the canonical trace JSON
/// digest compared by [`ParityRunner::assert_identical`].
const TRACE_DIGEST_CONTEXT: &str = "proof:oracle-trace:v1";

/// Fact kind marker for the imported Workspace metadata (bootstrap principal
/// plus storage Schema version) persisted into the `facts` table.
const FACT_KIND_WORKSPACE_METADATA: &str = "workspace_metadata";
/// Fact kind marker for an imported localized content resource intent.
const FACT_KIND_RESOURCE_INTENT: &str = "resource_intent";
/// Fact kind marker for an imported localized `ContextPack`.
const FACT_KIND_CONTEXT_PACK: &str = "context_pack";
/// Fact kind marker for an imported localized `ChangeSet` row projection.
const FACT_KIND_LOCALIZED_CHANGESET: &str = "localized_changeset";
/// Fact kind marker for one imported localized Edit artifact.
const FACT_KIND_LOCALIZED_EDIT: &str = "localized_edit";
/// Fact kind marker for one imported localized validation attempt.
const FACT_KIND_LOCALIZED_VALIDATION: &str = "localized_validation";

/// The PostgreSQL parity backend: it evaluates a shared operation against the
/// imported, verified PostgreSQL state (contract §"Conformance and
/// falsification plan").
pub struct PostgresBackend<'a> {
    runtime: &'a mut PgRuntime,
}

impl<'a> PostgresBackend<'a> {
    /// Binds the PostgreSQL backend to a runtime whose schema has already been
    /// migrated and populated by [`prepare_parity_backend`].
    #[must_use]
    pub fn new(runtime: &'a mut PgRuntime) -> Self {
        Self { runtime }
    }
}

impl StorageBackend for PostgresBackend<'_> {
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError> {
        run_postgres_operation(self.runtime, normalized_input, actor_context)
            .map_err(|error| RemoteError::Oracle(error.to_string()))
    }
}

/// Prepares a PostgreSQL runtime for parity by importing the SQLite reference
/// Workspace through the verified wave-1 importer, then persisting the
/// localized content facts and Workspace metadata the parity mirror needs to
/// reproduce byte-identical traces.
///
/// # Errors
///
/// Returns [`PgError::Import`] or [`PgError::Integrity`] when the import or the
/// parity-fact verification fails closed.
pub fn prepare_parity_backend(
    source: &proof_local::LocalWorkspace,
    runtime: &mut PgRuntime,
) -> Result<(), PgError> {
    SqliteToPostgresImporter::new().import(source, runtime)?;
    import_parity_facts(source, runtime)
}

/// One normalized shared-operation input plus the exact actor context it is
/// evaluated under.
#[derive(Clone, Debug)]
pub struct ParityOperation {
    /// Normalized shared-operation input, in execution order.
    pub normalized_input: Value,
    /// The closed actor context carrying the operation/version pair.
    pub actor_context: AuthenticatedActorContextV2,
}

/// One parity scenario: a name, its shared operations, and the expected
/// byte-identical trace digests (contract §"Conformance and falsification
/// plan").
#[derive(Clone, Debug)]
pub struct ParityScenario {
    /// Stable scenario name.
    pub name: String,
    /// Normalized shared-operation inputs plus actor contexts, in order.
    pub operations: Vec<ParityOperation>,
    /// Expected [`OracleTraceV1`] digests in the same order.
    pub expected_trace_digests: Vec<ContentDigest>,
}

/// Runs one scenario against both backends and asserts byte-identical traces
/// (contract §"Conformance and falsification plan").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParityRunner;

impl ParityRunner {
    /// Constructs the runner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Runs the scenario against the SQLite reference backend.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a trace cannot be produced.
    pub fn run_sqlite(
        &self,
        scenario: &ParityScenario,
        backend: &mut proof_remote::SqliteReferenceBackend<'_>,
    ) -> Result<Vec<OracleTraceV1>, PgError> {
        scenario
            .operations
            .iter()
            .map(|operation| {
                backend
                    .run(&operation.normalized_input, &operation.actor_context)
                    .map_err(|error| PgError::Integrity(error.to_string()))
            })
            .collect()
    }

    /// Runs the scenario against the PostgreSQL backend.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] when a trace cannot be produced.
    pub fn run_postgres(
        &self,
        scenario: &ParityScenario,
        backend: &mut PostgresBackend<'_>,
    ) -> Result<Vec<OracleTraceV1>, PgError> {
        scenario
            .operations
            .iter()
            .map(|operation| {
                backend
                    .run(&operation.normalized_input, &operation.actor_context)
                    .map_err(|error| PgError::Integrity(error.to_string()))
            })
            .collect()
    }

    /// Asserts that the two backends produced byte-identical traces: exact
    /// field equality plus equality of the canonical trace JSON digest.
    ///
    /// # Errors
    ///
    /// Returns [`PgError::Integrity`] on any trace mismatch.
    pub fn assert_identical(
        &self,
        sqlite: &[OracleTraceV1],
        postgres: &[OracleTraceV1],
    ) -> Result<(), PgError> {
        if sqlite.len() != postgres.len() {
            return Err(PgError::Integrity(format!(
                "trace count mismatch: SQLite produced {}, PostgreSQL produced {}",
                sqlite.len(),
                postgres.len()
            )));
        }
        for (index, (reference, candidate)) in sqlite.iter().zip(postgres).enumerate() {
            if reference != candidate {
                return Err(PgError::Integrity(format!(
                    "trace {index} field mismatch: SQLite {reference:?} vs PostgreSQL {candidate:?}"
                )));
            }
            let reference_digest = trace_digest(reference)?;
            let candidate_digest = trace_digest(candidate)?;
            if reference_digest != candidate_digest {
                return Err(PgError::Integrity(format!(
                    "trace {index} canonical digest mismatch: {reference_digest} vs {candidate_digest}"
                )));
            }
        }
        Ok(())
    }
}

/// Computes the canonical JSON digest of one trace under
/// `proof:oracle-trace:v1`.
fn trace_digest(trace: &OracleTraceV1) -> Result<ContentDigest, PgError> {
    let value = serde_json::to_value(trace)
        .map_err(|error| PgError::Integrity(format!("trace serialization failed: {error}")))?;
    let canonical = canonicalize(&value)
        .map_err(|error| PgError::Integrity(format!("trace canonicalization failed: {error}")))?;
    Ok(derive_key_digest(
        TRACE_DIGEST_CONTEXT,
        canonical.as_bytes(),
    ))
}

/// Extracts the exact operation/version pair and evaluated authority head from
/// a closed actor context (mirrors [`proof_remote::RemoteSemanticOracle::run`]).
fn actor_operation(
    actor_context: &AuthenticatedActorContextV2,
) -> (RemoteOperationV1, AuthorityHeadV1) {
    match actor_context {
        AuthenticatedActorContextV2::Human(context) => {
            (context.operation.clone(), context.evaluated_authority_head)
        }
        AuthenticatedActorContextV2::HumanAgent(context) => {
            (context.operation.clone(), context.evaluated_authority_head)
        }
    }
}

/// Builds a stable-problem trace without any storage access.
fn stable_problem_trace(
    operation: &RemoteOperationV1,
    input: &Value,
    evaluated_authority_head: AuthorityHeadV1,
    code: &str,
) -> Result<OracleTraceV1, PgError> {
    let normalized_input_digest = normalized_operation_input_digest(input, operation)
        .map_err(|error| PgError::Integrity(error.to_string()))?;
    let consequence = application_problem_digest_preimage(code, operation)
        .map_err(|error| PgError::Integrity(error.to_string()))?;
    Ok(OracleTraceV1 {
        normalized_input_digest,
        evaluated_authority_head,
        outcome: OracleOutcome::StableProblem(StableProblem {
            code: code.to_owned(),
            operation: operation.clone(),
        }),
        consequence: OracleConsequence::ConsequenceDigest(consequence),
    })
}

/// Builds a typed success trace.
fn success_trace(
    operation: &RemoteOperationV1,
    input: &Value,
    evaluated_authority_head: AuthorityHeadV1,
    result: Value,
    effect: Option<ContentDigest>,
) -> Result<OracleTraceV1, PgError> {
    let normalized_input_digest = normalized_operation_input_digest(input, operation)
        .map_err(|error| PgError::Integrity(error.to_string()))?;
    Ok(OracleTraceV1 {
        normalized_input_digest,
        evaluated_authority_head,
        outcome: OracleOutcome::TypedResult(result),
        consequence: effect.map_or(
            OracleConsequence::Null,
            OracleConsequence::ConsequenceDigest,
        ),
    })
}

/// Dispatches one resolved operation against the PostgreSQL state.
#[allow(clippy::too_many_lines)]
fn run_postgres_operation(
    runtime: &mut PgRuntime,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
) -> Result<OracleTraceV1, PgError> {
    let (operation, evaluated_authority_head) = actor_operation(actor_context);
    let resolved =
        AuthorityOperation::from_pair(&operation.name, &operation.version).ok_or_else(|| {
            PgError::Integrity(format!(
                "unregistered remote operation `{}` at `{}`",
                operation.name, operation.version
            ))
        })?;

    match resolved {
        AuthorityOperation::WorkspaceStatusV1 => {
            if parse_input::<WorkspaceStatusInputV1>(normalized_input).is_err() {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            }
            let result = read_workspace_status(runtime)?;
            success_trace(
                &operation,
                normalized_input,
                evaluated_authority_head,
                result,
                None,
            )
        }
        AuthorityOperation::ContextBuildV2 => {
            let Ok(input) = parse_input::<LocalizedContextBuildInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            let result = read_localized_context_pack(
                runtime,
                &command.context_pack_id.to_string(),
                &command.resource_intent_id.to_string(),
                &command.resource_intent_digest.to_string(),
            )?;
            let effect = operation_effect_digest(&result)
                .map_err(|error| PgError::Integrity(error.to_string()))?;
            success_trace(
                &operation,
                normalized_input,
                evaluated_authority_head,
                result,
                Some(effect),
            )
        }
        AuthorityOperation::ChangesetGetV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetGetInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            match load_pg_localized_changeset(runtime, &input.changeset_id.to_string()) {
                Ok(changeset) => success_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    proof_remote::oracle::serialize_localized_changeset(&changeset),
                    None,
                ),
                Err(code) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &code,
                ),
            }
        }
        AuthorityOperation::ChangesetCreateV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetCreateInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            match pg_create_changeset(runtime, &command) {
                Ok(changeset) => {
                    let result = proof_remote::oracle::serialize_localized_changeset(&changeset);
                    let effect = operation_effect_digest(&result)
                        .map_err(|error| PgError::Integrity(error.to_string()))?;
                    success_trace(
                        &operation,
                        normalized_input,
                        evaluated_authority_head,
                        result,
                        Some(effect),
                    )
                }
                Err(code) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &code,
                ),
            }
        }
        other => Err(PgError::Integrity(format!(
            "operation `{}` is not yet mirrored on the PostgreSQL parity backend",
            other.name()
        ))),
    }
}

/// Parses one normalized operation input into its strict typed shape.
fn parse_input<T: for<'de> serde::Deserialize<'de>>(input: &Value) -> Result<T, ()> {
    serde_json::from_value(input.clone()).map_err(|_| ())
}

/// Reads the imported Workspace status from PostgreSQL and serializes it exactly
/// as the SQLite oracle does for `workspace.status/v1`.
fn read_workspace_status(runtime: &mut PgRuntime) -> Result<Value, PgError> {
    let head = runtime
        .client_mut()
        .query_one(
            "SELECT workspace_id, content_sequence, content_head_digest
             FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| PgError::Integrity(error.to_string()))?;
    let workspace_id: String = head.get(0);
    let authoritative_sequence: i64 = head.get(1);
    let content_head: Option<String> = head.get(2);
    let content_head = content_head.ok_or_else(|| {
        PgError::Integrity("the imported Workspace has no content head".to_owned())
    })?;

    let metadata = runtime
        .client_mut()
        .query_one(
            "SELECT body FROM facts WHERE fact_id = 'workspace/metadata'",
            &[],
        )
        .map_err(|error| PgError::Integrity(error.to_string()))?;
    let body: Vec<u8> = metadata.get(0);
    let metadata: Value = serde_json::from_slice(&body)
        .map_err(|error| PgError::Integrity(format!("invalid Workspace metadata: {error}")))?;
    let principal_id = metadata
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Integrity("Workspace metadata lacks principal_id".to_owned()))?;
    let storage_schema_version = metadata
        .get("storage_schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            PgError::Integrity("Workspace metadata lacks storage_schema_version".to_owned())
        })?;

    Ok(serde_json::json!({
        "status": "initialized",
        "workspace_id": workspace_id,
        "principal_id": principal_id,
        "storage_schema_version": storage_schema_version,
        "authoritative_sequence": u64::try_from(authoritative_sequence)
            .map_err(|_| PgError::Integrity("content sequence is negative".to_owned()))?,
        "state_digest": content_head,
    }))
}

/// Reads an imported localized `ContextPack` and serializes it exactly as the
/// SQLite oracle does for `context.build/v2`.
fn read_localized_context_pack(
    runtime: &mut PgRuntime,
    context_pack_id: &str,
    resource_intent_id: &str,
    resource_intent_digest: &str,
) -> Result<Value, PgError> {
    let fact_id = format!("context_pack/{context_pack_id}");
    let row = runtime
        .client_mut()
        .query_opt(
            "SELECT fact_digest, body FROM facts WHERE fact_id = $1",
            &[&fact_id],
        )
        .map_err(|error| PgError::Integrity(error.to_string()))?
        .ok_or_else(|| {
            PgError::Integrity(format!("localized ContextPack fact `{fact_id}` is absent"))
        })?;
    let fact_digest: String = row.get(0);
    let body: Vec<u8> = row.get(1);
    let manifest: Value = serde_json::from_slice(&body)
        .map_err(|error| PgError::Integrity(format!("invalid localized ContextPack: {error}")))?;

    let manifest_context_pack_id = manifest
        .get("context_pack_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Integrity("ContextPack manifest lacks context_pack_id".to_owned())
        })?;
    if manifest_context_pack_id != context_pack_id {
        return Err(PgError::Integrity(
            "ContextPack manifest identity disagrees with the request".to_owned(),
        ));
    }
    let manifest_resource_intent_id = manifest
        .get("resource_intent")
        .and_then(|intent| intent.get("intent_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Integrity("ContextPack manifest lacks resource intent identity".to_owned())
        })?;
    if manifest_resource_intent_id != resource_intent_id {
        return Err(PgError::Integrity(
            "ContextPack resource intent disagrees with the request".to_owned(),
        ));
    }
    let manifest_resource_intent_digest = manifest
        .get("resource_intent_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Integrity("ContextPack manifest lacks resource intent digest".to_owned())
        })?;
    if manifest_resource_intent_digest != resource_intent_digest {
        return Err(PgError::Integrity(
            "ContextPack resource intent digest disagrees with the request".to_owned(),
        ));
    }

    Ok(serde_json::json!({
        "context_pack_id": manifest_context_pack_id,
        "context_pack_digest": fact_digest,
        "manifest": manifest,
        "resource_intent_id": manifest_resource_intent_id,
        "resource_intent_digest": manifest_resource_intent_digest,
    }))
}

/// Imports the localized content facts and Workspace metadata the parity mirror
/// needs, re-verifying each canonical digest on the way in.
fn import_parity_facts(
    source: &proof_local::LocalWorkspace,
    runtime: &mut PgRuntime,
) -> Result<(), PgError> {
    let connection = source
        .open_database()
        .map_err(|error| PgError::Import(format!("open source database: {error}")))?;
    let workspace_id = runtime.config().workspace_id.to_string();

    import_workspace_metadata(runtime, &connection, &workspace_id)?;
    import_resource_intents(runtime, &connection, &workspace_id)?;
    import_context_packs(runtime, &connection, &workspace_id)?;
    import_localized_changesets(runtime, &connection, &workspace_id)?;
    import_localized_edits(runtime, &connection, &workspace_id)?;
    import_localized_validations(runtime, &connection, &workspace_id)?;
    import_resource_intent_meta(runtime, &connection, &workspace_id)?;
    import_known_state_head(runtime, &connection, &workspace_id)?;
    import_environment_current_releases(runtime, &connection, &workspace_id)?;
    import_release_metadata(runtime, &connection, &workspace_id)?;
    import_edition_metadata(runtime, &connection, &workspace_id)?;
    Ok(())
}

/// Persists the bootstrap principal and storage Schema version needed to
/// reproduce `workspace.status/v1`.
fn import_workspace_metadata(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let principal_id: String = connection
        .query_row(
            "SELECT bootstrap_principal_id FROM workspace_metadata WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let storage_schema_version: u32 = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get(0)
        })
        .map_err(|error| PgError::Import(error.to_string()))?;

    let body = serde_json::json!({
        "api_version": "proof.dev/parity/workspace-metadata/v1",
        "workspace_id": workspace_id,
        "principal_id": principal_id,
        "storage_schema_version": storage_schema_version,
    });
    let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
    let fact_digest = derive_key_digest("proof:parity:workspace-metadata:v1", canonical.as_bytes());

    insert_fact(
        runtime,
        "workspace/metadata",
        workspace_id,
        FACT_KIND_WORKSPACE_METADATA,
        &fact_digest,
        canonical.as_bytes(),
    )
}

/// Persists every localized content resource intent with its digest verified.
fn import_resource_intents(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare("SELECT intent_id, manifest_json, intent_digest FROM content_resource_intents")
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (intent_id, manifest_json, intent_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let intent_digest = intent_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical = verified_manifest_bytes(
            &manifest_json,
            ArtifactKind::ContentResourceIntentV1,
            intent_digest,
            &format!("resource intent `{intent_id}`"),
        )?;
        let fact_id = format!("resource_intent/{intent_id}");
        insert_fact(
            runtime,
            &fact_id,
            workspace_id,
            FACT_KIND_RESOURCE_INTENT,
            &intent_digest,
            &canonical,
        )?;
    }
    Ok(())
}

/// Persists every localized `ContextPack` with its digest verified.
fn import_context_packs(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare("SELECT context_pack_id, manifest_json, context_pack_digest FROM localized_context_packs")
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (context_pack_id, manifest_json, context_pack_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let context_pack_digest = context_pack_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical = verified_manifest_bytes(
            &manifest_json,
            ArtifactKind::ContextPackV2,
            context_pack_digest,
            &format!("ContextPack `{context_pack_id}`"),
        )?;
        let fact_id = format!("context_pack/{context_pack_id}");
        insert_fact(
            runtime,
            &fact_id,
            workspace_id,
            FACT_KIND_CONTEXT_PACK,
            &context_pack_digest,
            &canonical,
        )?;
    }
    Ok(())
}

/// Verifies that a persisted canonical manifest reproduces its recorded digest
/// and returns the canonical bytes.
fn verified_manifest_bytes(
    manifest_json: &str,
    kind: ArtifactKind,
    expected: ContentDigest,
    label: &str,
) -> Result<Vec<u8>, PgError> {
    let value: Value = serde_json::from_str(manifest_json)
        .map_err(|error| PgError::Import(format!("{label}: invalid JSON: {error}")))?;
    let canonical = canonicalize(&value)
        .map_err(|error| PgError::Import(format!("{label}: canonicalization failed: {error}")))?;
    if canonical.as_bytes() != manifest_json.as_bytes() {
        return Err(PgError::Import(format!(
            "{label}: bytes are not canonical JSON"
        )));
    }
    let recomputed = digest(kind, &canonical);
    if recomputed != expected {
        return Err(PgError::Import(format!(
            "{label}: digest mismatch (expected {expected}, reproduced {recomputed})"
        )));
    }
    Ok(canonical.as_bytes().to_vec())
}

/// Inserts one parity fact into the imported `facts` table.
fn insert_fact(
    runtime: &mut PgRuntime,
    fact_id: &str,
    workspace_id: &str,
    fact_kind: &str,
    fact_digest: &ContentDigest,
    body: &[u8],
) -> Result<(), PgError> {
    runtime
        .client_mut()
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest,
                 body, committed_at
             ) VALUES ($1, $2, $3, 0, $4, $5, now())",
            &[
                &fact_id,
                &workspace_id,
                &fact_kind,
                &fact_digest.to_string(),
                &body,
            ],
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    Ok(())
}

/// Persists every localized `ChangeSet` row as a canonical projection fact.
///
/// The row is not itself a single digest-addressed artifact, so the fact body
/// records the exact scalar columns and the fact digest is derived over those
/// canonical bytes under a parity-specific domain. Edit artifacts carry their
/// own immutable digests and are verified exactly.
#[allow(clippy::too_many_lines)]
fn import_localized_changesets(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, principal_id, intent, resource_intent_id,
                    resource_intent_digest, context_pack_id, context_pack_digest,
                    base_state_api_version, base_authoritative_sequence, base_state_digest,
                    created_at, lifecycle_status, proposal_digest, effective_leaf_digest,
                    sealed_changeset_digest, idempotency_key, effect_digest
             FROM localized_changesets ORDER BY changeset_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
                row.get::<_, Option<String>>(14)?,
                row.get::<_, String>(15)?,
                row.get::<_, String>(16)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            changeset_id,
            principal_id,
            intent,
            resource_intent_id,
            resource_intent_digest,
            context_pack_id,
            context_pack_digest,
            base_state_api_version,
            base_authoritative_sequence,
            base_state_digest,
            created_at,
            lifecycle_status,
            proposal_digest,
            effective_leaf_digest,
            sealed_changeset_digest,
            idempotency_key,
            effect_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let _ = effect_digest;
        let base_sequence = u64::try_from(base_authoritative_sequence).map_err(|_| {
            PgError::Import("imported base authoritative sequence is negative".to_owned())
        })?;
        // Cross-check the referenced evidence facts before persisting.
        let resource_fact_id = format!("resource_intent/{resource_intent_id}");
        let pack_fact_id = format!("context_pack/{context_pack_id}");
        for (fact_id, expected_digest) in [
            (&resource_fact_id, &resource_intent_digest),
            (&pack_fact_id, &context_pack_digest),
        ] {
            let stored: Option<String> = {
                let client = runtime.client_mut();
                client
                    .query_opt(
                        "SELECT fact_digest FROM facts WHERE fact_id = $1",
                        &[&fact_id],
                    )
                    .map_err(|error| PgError::Import(error.to_string()))?
                    .map(|row| row.get(0))
            };
            if stored.as_deref() != Some(expected_digest.as_str()) {
                return Err(PgError::Import(format!(
                    "changeset `{changeset_id}` references `{fact_id}` which is absent or disagrees"
                )));
            }
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-changeset/v1",
            "changeset_id": changeset_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "intent": intent,
            "resource_intent_id": resource_intent_id,
            "resource_intent_digest": resource_intent_digest,
            "context_pack_id": context_pack_id,
            "context_pack_digest": context_pack_digest,
            "base_state_api_version": base_state_api_version,
            "base_authoritative_sequence": base_sequence,
            "base_state_digest": base_state_digest,
            "created_at": created_at,
            "idempotency_key": idempotency_key,
            "lifecycle_status": lifecycle_status,
            "proposal_digest": proposal_digest,
            "effective_leaf_digest": effective_leaf_digest,
            "sealed_changeset_digest": sealed_changeset_digest,
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest =
            derive_key_digest("proof:parity:localized-changeset:v1", canonical.as_bytes());
        insert_fact(
            runtime,
            &format!("localized_changeset/{changeset_id}"),
            workspace_id,
            FACT_KIND_LOCALIZED_CHANGESET,
            &fact_digest,
            canonical.as_bytes(),
        )?;
    }
    Ok(())
}

/// Persists every localized Edit artifact with its exact digest re-verified
/// from the stored canonical manifest bytes.
fn import_localized_edits(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, ordinal, edit_json, edit_digest
             FROM localized_edits ORDER BY changeset_id, ordinal",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (changeset_id, ordinal, edit_json, edit_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let edit_digest = edit_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical = verified_manifest_bytes(
            &edit_json,
            ArtifactKind::EditV2,
            edit_digest,
            &format!("localized Edit `{changeset_id}`#{ordinal}"),
        )?;
        insert_fact(
            runtime,
            &format!("localized_edit/{changeset_id}/{ordinal:020}"),
            workspace_id,
            FACT_KIND_LOCALIZED_EDIT,
            &edit_digest,
            &canonical,
        )?;
    }
    Ok(())
}

/// Persists every localized validation attempt with its results digest
/// re-verified from the stored canonical results bytes.
fn import_localized_validations(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, attempt, results_json, results_digest, valid,
                    sealed_changeset_digest, proposal_digest, findings_json
             FROM localized_validations ORDER BY changeset_id, attempt",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            changeset_id,
            attempt,
            results_json,
            results_digest,
            valid,
            sealed,
            proposal_digest,
            findings,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let results_digest = results_digest
            .parse::<ContentDigest>()
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical = verified_manifest_bytes(
            &results_json,
            ArtifactKind::ValidationResultsV2,
            results_digest,
            &format!("validation `{changeset_id}`#{attempt}"),
        )
        .map_err(|error| {
            if error.to_string().contains("digest mismatch") {
                PgError::Import(format!(
                    "validation `{changeset_id}`#{attempt}: results digest mismatch"
                ))
            } else {
                error
            }
        })?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-validation/v1",
            "changeset_id": changeset_id,
            "attempt": attempt,
            "valid": valid != 0,
            "proposal_digest": proposal_digest,
            "results_digest": results_digest.to_string(),
            "sealed_changeset_digest": sealed,
            "findings": findings,
        });
        let canonical_body =
            canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest = derive_key_digest(
            "proof:parity:localized-validation:v1",
            canonical_body.as_bytes(),
        );
        let _ = canonical;
        insert_fact(
            runtime,
            &format!("localized_validation/{changeset_id}/{attempt:020}"),
            workspace_id,
            FACT_KIND_LOCALIZED_VALIDATION,
            &fact_digest,
            canonical_body.as_bytes(),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P-0015 slice 2: the PostgreSQL localized read executor. Reconstructs the
// typed application result from imported, digest-verified parity facts and
// serializes it through the shared oracle serializers, so traces are
// byte-identical to the SQLite reference path by construction.
// ---------------------------------------------------------------------------

use proof_application::{
    ChangeSetIntent, ChangeSetStatus, EditId, ExpectedLocalizedSource, ExpectedLocalizedTarget,
    KnownStateArtifactReference, LocaleId, LocaleRevision, LocalizedChangeSet, LocalizedEdit,
    ObjectId, ObjectLocalePutInput, ObjectRevision, SchemaId, SchemaVersion,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maps an internal reconstruction failure onto the exact stable problem code
/// the SQLite path selects for integrity failures.
fn integrity_code(_context: &str) -> String {
    "proof.digest.mismatch".to_owned()
}

/// Parses one imported localized Edit manifest back into its typed input.
#[allow(clippy::too_many_lines)]
fn edit_input_from_manifest(
    ordinal: u32,
    edit_id: EditId,
    manifest: &Value,
    canonical_json: &str,
    edit_digest: ContentDigest,
) -> Result<LocalizedEdit, String> {
    let content = manifest
        .get("content")
        .ok_or_else(|| integrity_code("edit manifest lacks content"))?;
    let canonical_content = proof_canonical::canonicalize(content)
        .map_err(|error| integrity_code(&error.to_string()))?
        .as_str()
        .to_owned();
    let source = manifest
        .get("expected_source")
        .ok_or_else(|| integrity_code("edit manifest lacks expected_source"))?;
    let expected_target = match manifest.get("expected_target") {
        None | Some(Value::Null) => None,
        Some(target) => Some(ExpectedLocalizedTarget {
            revision: LocaleRevision::new(
                u32::try_from(
                    target
                        .get("revision")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| integrity_code("target revision"))?,
                )
                .map_err(|_| integrity_code("target revision range"))?,
            )
            .map_err(|_| integrity_code("target revision"))?,
            digest: target
                .get("digest")
                .and_then(Value::as_str)
                .ok_or_else(|| integrity_code("target digest"))?
                .parse()
                .map_err(|_| integrity_code("target digest"))?,
        }),
    };
    Ok(LocalizedEdit {
        ordinal,
        edit_id,
        input: ObjectLocalePutInput {
            object_id: manifest
                .get("object_id")
                .and_then(Value::as_str)
                .ok_or_else(|| integrity_code("edit object_id"))?
                .parse()
                .map_err(|_| integrity_code("edit object_id"))?,
            locale: LocaleId::new(
                manifest
                    .get("locale")
                    .and_then(Value::as_str)
                    .ok_or_else(|| integrity_code("edit locale"))?
                    .to_owned(),
            )
            .map_err(|_| integrity_code("edit locale"))?,
            expected_source: ExpectedLocalizedSource {
                revision: ObjectRevision::new(
                    u32::try_from(
                        source
                            .get("revision")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("source revision"))?,
                    )
                    .map_err(|_| integrity_code("source revision range"))?,
                )
                .map_err(|_| integrity_code("source revision"))?,
                digest: source
                    .get("digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| integrity_code("source digest"))?
                    .parse()
                    .map_err(|_| integrity_code("source digest"))?,
                schema_id: SchemaId::new(
                    source
                        .get("schema_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| integrity_code("source schema_id"))?
                        .to_owned(),
                )
                .map_err(|_| integrity_code("source schema_id"))?,
                schema_version: SchemaVersion::new(
                    u32::try_from(
                        source
                            .get("schema_version")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("source schema_version"))?,
                    )
                    .map_err(|_| integrity_code("schema version range"))?,
                )
                .map_err(|_| integrity_code("source schema_version"))?,
            },
            expected_target,
            canonical_content,
            supersedes_edit_id: match manifest.get("supersedes_edit_id") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| integrity_code("supersedes_edit_id"))?
                        .parse()
                        .map_err(|_| integrity_code("supersedes_edit_id"))?,
                ),
            },
            repair_of_validation_result_digest: match manifest
                .get("repair_of_validation_result_digest")
            {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    value
                        .as_str()
                        .ok_or_else(|| integrity_code("repair digest"))?
                        .parse()
                        .map_err(|_| integrity_code("repair digest"))?,
                ),
            },
        },
        effective: false,
        canonical_json: canonical_json.to_owned(),
        edit_digest,
    })
}

/// Ports the reference effective-leaf marking: linear supersession chains per
/// `(object_id, locale)`; the last edit of each chain is effective.
fn mark_effective_edits(edits: &mut [LocalizedEdit]) -> Result<(), String> {
    let mut active = BTreeMap::<(ObjectId, LocaleId), EditId>::new();
    let mut seen_ids = BTreeSet::new();
    for edit in edits.iter() {
        if !seen_ids.insert(edit.edit_id) {
            return Err(integrity_code("duplicate localized Edit identity"));
        }
        let target = (edit.input.object_id, edit.input.locale.clone());
        match active.get(&target).copied() {
            None => {
                if edit.input.supersedes_edit_id.is_some()
                    || edit.input.repair_of_validation_result_digest.is_some()
                {
                    return Err(integrity_code(
                        "first localized Edit has a supersession edge",
                    ));
                }
            }
            Some(active_edit_id) => {
                if edit.input.supersedes_edit_id != Some(active_edit_id)
                    || edit.input.repair_of_validation_result_digest.is_none()
                {
                    return Err(integrity_code("localized Edit lineage forks or skips"));
                }
            }
        }
        active.insert(target, edit.edit_id);
    }
    for edit in edits.iter_mut() {
        edit.effective = active
            .get(&(edit.input.object_id, edit.input.locale.clone()))
            .is_some_and(|edit_id| *edit_id == edit.edit_id);
    }
    Ok(())
}

/// Ports the reference ChangeSet proposal digest computation.
fn proposal_digests(
    changeset: &LocalizedChangeSet,
) -> Result<(ContentDigest, ContentDigest), String> {
    let mut effective = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .cloned()
        .collect::<Vec<_>>();
    effective.sort_by(|left, right| {
        (left.input.object_id, &left.input.locale)
            .cmp(&(right.input.object_id, &right.input.locale))
    });
    let effective_manifest = proof_canonical::canonicalize(&serde_json::json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": effective
            .iter()
            .map(|edit| parse_canonical_value(&edit.canonical_json))
            .collect::<Result<Vec<_>, _>>()?,
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let effective_digest = digest(proof_domain::ArtifactKind::EditBatchV2, &effective_manifest);
    let manifest = proof_canonical::canonicalize(&serde_json::json!({
        "api_version": proof_application::LOCALIZED_CHANGESET_API_VERSION,
        "base_state": {
            "api_version": changeset.base_state.api_version,
            "authoritative_sequence": changeset.base_state.authoritative_sequence,
            "digest": changeset.base_state.digest.to_string(),
        },
        "changeset_id": changeset.changeset_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "created_at": changeset.created_at.to_string(),
        "edits": changeset
            .edits
            .iter()
            .map(|edit| parse_canonical_value(&edit.canonical_json))
            .collect::<Result<Vec<_>, _>>()?,
        "effective_leaf_digest": effective_digest.to_string(),
        "effective_leaves": effective.iter().map(|edit| serde_json::json!({
            "edit_digest": edit.edit_digest.to_string(),
            "edit_id": edit.edit_id.to_string(),
            "locale": edit.input.locale.as_str(),
            "object_id": edit.input.object_id.to_string(),
        })).collect::<Vec<_>>(),
        "intent": changeset.intent.as_str(),
        "principal_id": changeset.principal_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "workspace_id": changeset.workspace_id.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok((
        digest(proof_domain::ArtifactKind::ChangeSetV2, &manifest),
        effective_digest,
    ))
}

/// Parses stored canonical bytes into a strict JSON value.
/// Reads one fact's recorded digest.
fn fact_digest_of(runtime: &mut PgRuntime, fact_id: &str) -> Result<ContentDigest, String> {
    let row = {
        let client = runtime.client_mut();
        client
            .query_opt(
                "SELECT fact_digest FROM facts WHERE fact_id = $1",
                &[&fact_id],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    row.map(|row| {
        let raw: String = row.get(0);
        raw
    })
    .ok_or_else(|| "proof.resource.not_found".to_owned())?
    .parse()
    .map_err(|_| integrity_code("stored digest"))
}

fn parse_canonical_value(canonical_json: &str) -> Result<Value, String> {
    proof_canonical::parse_strict(canonical_json.as_bytes())
        .map_err(|error| integrity_code(&error.to_string()))
}

/// Reconstructs one localized `ChangeSet` from imported parity facts with the
/// exact reference verification semantics, returning the stable problem code
/// on every rejection the SQLite path would produce.
#[allow(clippy::too_many_lines)]
fn load_pg_localized_changeset(
    runtime: &mut PgRuntime,
    changeset_id: &str,
) -> Result<LocalizedChangeSet, String> {
    let row = {
        let client = runtime.client_mut();
        client
            .query_opt(
                "SELECT fact_id, body FROM facts WHERE fact_kind = 'localized_changeset' AND fact_id = $1",
                &[&format!("localized_changeset/{changeset_id}")],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    let Some(row) = row else {
        return Err("proof.resource.not_found".to_owned());
    };
    let body: Vec<u8> = row.get(1);
    let record: Value =
        serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
    let field = |name: &str| -> Result<String, String> {
        record
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| integrity_code(name))
    };
    let optional_field = |name: &str| -> Result<Option<ContentDigest>, String> {
        match record.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_str()
                .and_then(|raw| raw.parse().ok())
                .map(Some)
                .ok_or_else(|| integrity_code(name)),
        }
    };
    let workspace_id: proof_domain::WorkspaceId = field("workspace_id")?
        .parse()
        .map_err(|_| integrity_code("workspace identity"))?;
    let resource_intent_id = field("resource_intent_id")?;
    let context_pack_id = field("context_pack_id")?;
    // Evidence references must reproduce against their imported facts.
    for (fact_id, expected) in [
        (
            format!("resource_intent/{resource_intent_id}"),
            field("resource_intent_digest")?,
        ),
        (
            format!("context_pack/{context_pack_id}"),
            field("context_pack_digest")?,
        ),
    ] {
        let stored: Option<String> = {
            let client = runtime.client_mut();
            client
                .query_opt(
                    "SELECT fact_digest FROM facts WHERE fact_id = $1",
                    &[&fact_id],
                )
                .map_err(|error| integrity_code(&error.to_string()))?
                .map(|row| row.get(0))
        };
        if stored.as_deref() != Some(expected.as_str()) {
            return Err(integrity_code("evidence reference does not reproduce"));
        }
    }

    // Edits, in contiguous ordinal order.
    let edit_rows = {
        let client = runtime.client_mut();
        client
            .query(
                "SELECT fact_id, fact_digest, body FROM facts
                 WHERE fact_kind = 'localized_edit' AND fact_id LIKE $1
                 ORDER BY fact_id",
                &[&format!("localized_edit/{changeset_id}/%")],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    let mut edits = Vec::with_capacity(edit_rows.len());
    for (index, row) in edit_rows.iter().enumerate() {
        let fact_id: String = row.get(0);
        let stored_digest: String = row.get(1);
        let body: Vec<u8> = row.get(2);
        let ordinal_suffix = fact_id
            .rsplit('/')
            .next()
            .ok_or_else(|| integrity_code("edit fact identity"))?;
        let ordinal_value: usize = ordinal_suffix
            .parse()
            .map_err(|_| integrity_code("edit ordinal"))?;
        if ordinal_value != index + 1 {
            return Err(integrity_code("edit ordinals are not contiguous"));
        }
        let manifest: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let edit_id = manifest
            .get("edit_id")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("edit identity"))?
            .parse()
            .map_err(|_| integrity_code("edit identity"))?;
        let edit = edit_input_from_manifest(
            u32::try_from(ordinal_value).map_err(|_| integrity_code("ordinal range"))?,
            edit_id,
            &manifest,
            std::str::from_utf8(&body).map_err(|_| integrity_code("edit bytes"))?,
            stored_digest
                .parse()
                .map_err(|_| integrity_code("edit digest"))?,
        )?;
        edits.push(edit);
    }
    mark_effective_edits(&mut edits)?;

    let mut changeset = LocalizedChangeSet {
        changeset_id: changeset_id
            .parse()
            .map_err(|_| integrity_code("changeset identity"))?,
        workspace_id,
        principal_id: field("principal_id")?
            .parse()
            .map_err(|_| integrity_code("principal identity"))?,
        intent: ChangeSetIntent::new(field("intent")?).map_err(|_| integrity_code("intent"))?,
        resource_intent_id: resource_intent_id
            .parse()
            .map_err(|_| integrity_code("intent identity"))?,
        resource_intent_digest: field("resource_intent_digest")?
            .parse()
            .map_err(|_| integrity_code("intent digest"))?,
        context_pack_id: context_pack_id
            .parse()
            .map_err(|_| integrity_code("pack identity"))?,
        context_pack_digest: field("context_pack_digest")?
            .parse()
            .map_err(|_| integrity_code("pack digest"))?,
        base_state: KnownStateArtifactReference {
            api_version: field("base_state_api_version")?,
            authoritative_sequence: record
                .get("base_authoritative_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("base sequence"))?,
            digest: field("base_state_digest")?
                .parse()
                .map_err(|_| integrity_code("base digest"))?,
        },
        created_at: field("created_at")?
            .parse()
            .map_err(|_| integrity_code("created_at"))?,
        status: match field("lifecycle_status")?.as_str() {
            "draft" => ChangeSetStatus::Draft,
            "ready" => ChangeSetStatus::Ready,
            "submitted" => ChangeSetStatus::Submitted,
            "approved" => ChangeSetStatus::Approved,
            "committed" => ChangeSetStatus::Committed,
            _ => return Err(integrity_code("lifecycle status")),
        },
        edits,
        proposal_digest: optional_field("proposal_digest")?,
        sealed_changeset_digest: optional_field("sealed_changeset_digest")?,
    };

    if changeset.edits.is_empty() {
        if changeset.proposal_digest.is_some()
            || record
                .get("effective_leaf_digest")
                .and_then(Value::as_str)
                .is_some()
            || changeset.sealed_changeset_digest.is_some()
        {
            return Err(integrity_code("empty ChangeSet carries evidence"));
        }
    } else {
        let (proposal_digest, effective_digest) = proposal_digests(&changeset)?;
        let persisted_effective = field("effective_leaf_digest")?;
        if changeset.proposal_digest != Some(proposal_digest)
            || persisted_effective != effective_digest.to_string()
        {
            return Err(integrity_code("proposal does not reproduce"));
        }
        if let Some(sealed) = changeset.sealed_changeset_digest {
            let latest = latest_validation_fact(runtime, changeset_id)?
                .ok_or_else(|| integrity_code("seal lacks validation"))?;
            if !latest.valid || latest.sealed.as_deref() != Some(sealed.to_string().as_str()) {
                return Err(integrity_code("seal does not match validation head"));
            }
        }
    }
    mark_effective_edits(&mut changeset.edits)?;
    verify_all_repair_edges_pg(runtime, &changeset)?;
    Ok(changeset)
}

/// One imported validation attempt reduced to the fields the reconstruction
/// checks consume.
struct PgValidationFact {
    attempt: i64,
    valid: bool,
    proposal_digest: String,
    results_digest: String,
    sealed: Option<String>,
    findings: Vec<Value>,
}

fn read_validation_facts(
    runtime: &mut PgRuntime,
    changeset_id: &str,
) -> Result<Vec<PgValidationFact>, String> {
    let rows = {
        let client = runtime.client_mut();
        client
            .query(
                "SELECT body FROM facts
                 WHERE fact_kind = 'localized_validation' AND fact_id LIKE $1
                 ORDER BY fact_id",
                &[&format!("localized_validation/{changeset_id}/%")],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    rows.iter()
        .map(|row| {
            let body: Vec<u8> = row.get(0);
            let record: Value = serde_json::from_slice(&body)
                .map_err(|error| integrity_code(&error.to_string()))?;
            Ok(PgValidationFact {
                attempt: record
                    .get("attempt")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| integrity_code("validation attempt"))?,
                valid: record
                    .get("valid")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| integrity_code("validation validity"))?,
                proposal_digest: record
                    .get("proposal_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| integrity_code("validation proposal"))?
                    .to_owned(),
                results_digest: record
                    .get("results_digest")
                    .and_then(Value::as_str)
                    .ok_or_else(|| integrity_code("validation results digest"))?
                    .to_owned(),
                sealed: record
                    .get("sealed_changeset_digest")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                findings: record
                    .get("findings")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn latest_validation_fact(
    runtime: &mut PgRuntime,
    changeset_id: &str,
) -> Result<Option<PgValidationFact>, String> {
    Ok(read_validation_facts(runtime, changeset_id)?.pop())
}

/// Ports the reference repair-edge verification over imported facts.
fn verify_all_repair_edges_pg(
    runtime: &mut PgRuntime,
    changeset: &LocalizedChangeSet,
) -> Result<(), String> {
    let validations = read_validation_facts(runtime, &changeset.changeset_id.to_string())?;
    for (index, edit) in changeset.edits.iter().enumerate() {
        let (Some(superseded), Some(result_digest)) = (
            edit.input.supersedes_edit_id,
            edit.input.repair_of_validation_result_digest,
        ) else {
            continue;
        };
        let mut prefix = changeset.clone();
        prefix.edits.truncate(index);
        prefix.proposal_digest = None;
        prefix.sealed_changeset_digest = None;
        mark_effective_edits(&mut prefix.edits)?;
        let (prefix_proposal, _) = proposal_digests(&prefix)?;
        let matching = validations
            .iter()
            .find(|fact| fact.results_digest == result_digest.to_string())
            .ok_or_else(|| "proof.validation.repair_evidence_invalid".to_owned())?;
        if matching.valid || matching.proposal_digest != prefix_proposal.to_string() {
            return Err("proof.validation.repair_evidence_invalid".to_owned());
        }
        let latest_for_proposal = validations
            .iter()
            .filter(|fact| fact.proposal_digest == prefix_proposal.to_string())
            .map(|fact| fact.attempt)
            .max()
            .ok_or_else(|| "proof.validation.repair_evidence_invalid".to_owned())?;
        if latest_for_proposal != matching.attempt {
            return Err("proof.validation.repair_evidence_invalid".to_owned());
        }
        let superseded_str = superseded.to_string();
        let object_str = edit.input.object_id.to_string();
        let matches = matching.findings.iter().any(|finding| {
            finding.get("edit_id").and_then(Value::as_str) == Some(superseded_str.as_str())
                && finding.get("object_id").and_then(Value::as_str) == Some(object_str.as_str())
                && finding.get("locale").and_then(Value::as_str) == Some(edit.input.locale.as_str())
                && finding.get("severity").and_then(Value::as_str) == Some("error")
        });
        if !matches {
            return Err("proof.validation.repair_evidence_invalid".to_owned());
        }
    }
    Ok(())
}

/// Persists every current-Release Environment pointer.
fn import_environment_current_releases(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT current.environment_id, current.release_id
             FROM environment_current_releases AS current
             JOIN environments AS env ON env.environment_id = current.environment_id
             WHERE env.workspace_id = ?1 ORDER BY current.environment_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([workspace_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (environment_id, release_id) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/environment-current/v1",
            "environment_id": environment_id,
            "release_id": release_id,
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest =
            derive_key_digest("proof:parity:environment-current:v1", canonical.as_bytes());
        insert_fact(
            runtime,
            &format!("environment_current/{environment_id}"),
            workspace_id,
            "environment_current",
            &fact_digest,
            canonical.as_bytes(),
        )?;
    }
    Ok(())
}

/// Persists the scalar Release metadata the baseline reconstruction needs,
/// alongside the wave-1 importer's verified canonical manifest facts.
fn import_release_metadata(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT release_id, api_version, edition_id, edition_digest,
                    release_digest
             FROM releases ORDER BY release_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (release_id, api_version, edition_id, edition_digest, release_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/release-metadata/v1",
            "release_id": release_id,
            "release_api_version": api_version,
            "release_digest": release_digest,
            "edition_id": edition_id,
            "edition_digest": edition_digest,
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest =
            derive_key_digest("proof:parity:release-metadata:v1", canonical.as_bytes());
        insert_fact(
            runtime,
            &format!("release_meta/{release_id}"),
            workspace_id,
            "release_meta",
            &fact_digest,
            canonical.as_bytes(),
        )?;
    }
    Ok(())
}

/// Persists the scalar Edition metadata the baseline reconstruction needs.
fn import_edition_metadata(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT edition_id, api_version, edition_digest, state_digest,
                    authoritative_sequence
             FROM editions ORDER BY edition_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (edition_id, api_version, edition_digest, state_digest, authoritative_sequence) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/edition-metadata/v1",
            "edition_id": edition_id,
            "edition_api_version": api_version,
            "edition_digest": edition_digest,
            "state_digest": state_digest,
            "authoritative_sequence": authoritative_sequence,
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest =
            derive_key_digest("proof:parity:edition-metadata:v1", canonical.as_bytes());
        insert_fact(
            runtime,
            &format!("edition_meta/{edition_id}"),
            workspace_id,
            "edition_meta",
            &fact_digest,
            canonical.as_bytes(),
        )?;
    }
    Ok(())
}

/// Persists the Known State singleton reference the baseline port consumes.
fn import_known_state_head(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let (api_version, sequence, state_digest): (String, i64, String) = connection
        .query_row(
            "SELECT api_version, authoritative_sequence, state_digest
             FROM known_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/known-state-head/v1",
        "known_state_api_version": api_version,
        "authoritative_sequence": u64::try_from(sequence)
            .map_err(|_| PgError::Import("negative Known State sequence".to_owned()))?,
        "state_digest": state_digest,
    });
    let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
    let fact_digest = derive_key_digest("proof:parity:known-state-head:v1", canonical.as_bytes());
    insert_fact(
        runtime,
        "known_state/head",
        workspace_id,
        "known_state_head",
        &fact_digest,
        canonical.as_bytes(),
    )
}

// ---------------------------------------------------------------------------
// P-0015 slice 3: the changeset.create/v2 executor over imported facts.
// ---------------------------------------------------------------------------

use proof_application::{
    CreateLocalizedChangeSetCommand, EditionArtifactReference, LocalizedContentBaseline,
    PrincipalId, ReleaseArtifactReference,
};

fn fact_json(runtime: &mut PgRuntime, fact_id: &str) -> Result<Option<Value>, String> {
    let row = {
        let client = runtime.client_mut();
        client
            .query_opt("SELECT body FROM facts WHERE fact_id = $1", &[&fact_id])
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    match row {
        None => Ok(None),
        Some(row) => {
            let body: Vec<u8> = row.get(0);
            serde_json::from_slice(&body)
                .map(Some)
                .map_err(|error| integrity_code(&error.to_string()))
        }
    }
}

fn require_fact_json(
    runtime: &mut PgRuntime,
    fact_id: &str,
    missing: &str,
) -> Result<Value, String> {
    fact_json(runtime, fact_id)?.ok_or_else(|| missing.to_owned())
}

/// Resolves the acting principal exactly as the SQLite path does: from the
/// imported Workspace identity, never from request-carried identifiers.
fn parity_principal(runtime: &mut PgRuntime) -> Result<PrincipalId, String> {
    let metadata = require_fact_json(runtime, "workspace/metadata", "proof.resource.not_found")?;
    metadata
        .get("principal_id")
        .and_then(Value::as_str)
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| integrity_code("workspace principal"))
}

/// Ports `current_baseline` over the imported pointer, release, edition, and
/// Known State facts.
#[allow(clippy::too_many_lines)]
fn pg_current_baseline(
    runtime: &mut PgRuntime,
    environment_id: &str,
) -> Result<LocalizedContentBaseline, String> {
    let pointer = require_fact_json(
        runtime,
        &format!("environment_current/{environment_id}"),
        "proof.resource.not_found",
    )?;
    let release_id = pointer
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("pointer release"))?;
    let release_meta = require_fact_json(
        runtime,
        &format!("release_meta/{release_id}"),
        "proof.resource.not_found",
    )?;
    let release_api_version = release_meta
        .get("release_api_version")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("release version"))?
        .to_owned();
    let edition_id = release_meta
        .get("edition_id")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("release edition"))?
        .to_owned();
    let release_edition_digest = release_meta
        .get("edition_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("release edition digest"))?
        .to_owned();
    let edition_meta = require_fact_json(
        runtime,
        &format!("edition_meta/{edition_id}"),
        "proof.resource.not_found",
    )?;
    let edition_api_version = edition_meta
        .get("edition_api_version")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("edition version"))?
        .to_owned();
    let edition_digest: ContentDigest = edition_meta
        .get("edition_digest")
        .and_then(Value::as_str)
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| integrity_code("edition digest"))?;
    if release_edition_digest != edition_digest.to_string() {
        return Err(integrity_code("Release and Edition digests differ"));
    }
    let state_digest: ContentDigest = edition_meta
        .get("state_digest")
        .and_then(Value::as_str)
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| integrity_code("edition state"))?;
    let state_sequence = edition_meta
        .get("authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_code("edition sequence"))?;

    let head = require_fact_json(runtime, "known_state/head", "proof.resource.not_found")?;
    let head_api_version = head
        .get("known_state_api_version")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("state version"))?
        .to_owned();
    let head_digest: ContentDigest = head
        .get("state_digest")
        .and_then(Value::as_str)
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| integrity_code("state digest"))?;
    let head_sequence = head
        .get("authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_code("state sequence"))?;
    if head_digest != state_digest || head_sequence != state_sequence {
        return Err("proof.state.conflict".to_owned());
    }
    if release_api_version.ends_with("/v1") != edition_api_version.ends_with("/v1") {
        return Err(integrity_code("Release/Edition version pair"));
    }
    Ok(LocalizedContentBaseline {
        release: ReleaseArtifactReference {
            api_version: release_api_version,
            release_id: release_id
                .parse()
                .map_err(|_| integrity_code("release identity"))?,
            digest: release_meta
                .get("release_digest")
                .and_then(Value::as_str)
                .and_then(|raw| raw.parse().ok())
                .ok_or_else(|| integrity_code("release digest"))?,
        },
        edition: EditionArtifactReference {
            api_version: edition_api_version,
            edition_id: edition_id
                .parse()
                .map_err(|_| integrity_code("edition identity"))?,
            digest: edition_digest,
        },
        known_state: KnownStateArtifactReference {
            api_version: head_api_version,
            authoritative_sequence: head_sequence,
            digest: head_digest,
        },
    })
}

/// Fetches one imported canonical manifest as raw JSON.
fn pg_manifest(runtime: &mut PgRuntime, prefix: &str, identity: &str) -> Result<Value, String> {
    require_fact_json(
        runtime,
        &format!("{prefix}/{identity}"),
        "proof.resource.not_found",
    )
}

fn json_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code(key))
}

/// Parses the imported intent manifest's baseline triple.
fn parse_baseline(value: &Value) -> Result<LocalizedContentBaseline, String> {
    let base = value
        .get("base")
        .ok_or_else(|| integrity_code("intent base"))?;
    let known = base
        .get("known_state")
        .ok_or_else(|| integrity_code("intent base state"))?;
    Ok(LocalizedContentBaseline {
        release: ReleaseArtifactReference {
            api_version: json_str(
                base.get("release")
                    .ok_or_else(|| integrity_code("intent base release"))?,
                "api_version",
            )?
            .to_owned(),
            release_id: json_str(
                base.get("release")
                    .ok_or_else(|| integrity_code("intent base release"))?,
                "release_id",
            )?
            .parse()
            .map_err(|_| integrity_code("release id"))?,
            digest: json_str(
                base.get("release")
                    .ok_or_else(|| integrity_code("intent base release"))?,
                "digest",
            )?
            .parse()
            .map_err(|_| integrity_code("release digest"))?,
        },
        edition: EditionArtifactReference {
            api_version: json_str(
                base.get("edition")
                    .ok_or_else(|| integrity_code("intent base edition"))?,
                "api_version",
            )?
            .to_owned(),
            edition_id: json_str(
                base.get("edition")
                    .ok_or_else(|| integrity_code("intent base edition"))?,
                "edition_id",
            )?
            .parse()
            .map_err(|_| integrity_code("edition id"))?,
            digest: json_str(
                base.get("edition")
                    .ok_or_else(|| integrity_code("intent base edition"))?,
                "digest",
            )?
            .parse()
            .map_err(|_| integrity_code("edition digest"))?,
        },
        known_state: KnownStateArtifactReference {
            api_version: json_str(known, "api_version")?.to_owned(),
            authoritative_sequence: known
                .get("authoritative_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("state sequence"))?,
            digest: json_str(known, "digest")?
                .parse()
                .map_err(|_| integrity_code("state digest"))?,
        },
    })
}

/// Ports the reference `changeset.create/v2` operation over imported facts.
#[allow(clippy::too_many_lines)]
fn pg_create_changeset(
    runtime: &mut PgRuntime,
    command: &CreateLocalizedChangeSetCommand,
) -> Result<LocalizedChangeSet, String> {
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation/changeset.create/v2",
        "changeset_id": command.changeset_id.to_string(),
        "context_pack_digest": command.context_pack_digest.to_string(),
        "context_pack_id": command.context_pack_id.to_string(),
        "created_at": command.created_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "intent": command.intent.as_str(),
        "resource_intent_digest": command.resource_intent_digest.to_string(),
        "resource_intent_id": command.resource_intent_id.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let request_digest = digest(proof_domain::ArtifactKind::OperationEffectV1, &request);

    let principal = parity_principal(runtime)?;
    let op_fact_id = format!(
        "op_changeset_create/{principal}/{key}",
        key = command.idempotency_key
    );
    if let Some(prior) = fact_json(runtime, &op_fact_id)? {
        let stored_effect = prior
            .get("effect_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op effect"))?;
        let prior_changeset = prior
            .get("changeset_id")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op changeset"))?;
        let current = load_pg_localized_changeset(runtime, prior_changeset)?;
        let original = LocalizedChangeSet {
            changeset_id: command.changeset_id,
            workspace_id: current.workspace_id,
            principal_id: current.principal_id,
            intent: command.intent.clone(),
            resource_intent_id: command.resource_intent_id,
            resource_intent_digest: command.resource_intent_digest,
            context_pack_id: command.context_pack_id,
            context_pack_digest: command.context_pack_digest,
            base_state: current.base_state.clone(),
            created_at: command.created_at,
            status: ChangeSetStatus::Draft,
            edits: Vec::new(),
            proposal_digest: None,
            sealed_changeset_digest: None,
        };
        let expected = creation_effect(request_digest, &original)?;
        if stored_effect != expected.to_string() {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        if current.changeset_id != original.changeset_id
            || current.workspace_id != original.workspace_id
            || current.principal_id != original.principal_id
            || current.intent != original.intent
            || current.resource_intent_id != original.resource_intent_id
            || current.resource_intent_digest != original.resource_intent_digest
            || current.context_pack_id != original.context_pack_id
            || current.context_pack_digest != original.context_pack_digest
            || current.base_state != original.base_state
            || current.created_at != original.created_at
        {
            return Err(integrity_code(
                "localized ChangeSet creation fields differ from the operation effect",
            ));
        }
        return Ok(current);
    }

    let intent_value = pg_manifest(
        runtime,
        "resource_intent",
        &command.resource_intent_id.to_string(),
    )?;
    let intent_meta = require_fact_json(
        runtime,
        &format!("resource_intent_meta/{}", command.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let context_fact_id = format!("context_pack/{}", command.context_pack_id);
    let context_value = require_fact_json(runtime, &context_fact_id, "proof.resource.not_found")?;
    // The pack manifest excludes its own digest; recompute it from the
    // imported canonical bytes.
    let stored_pack_digest = fact_digest_of(runtime, &context_fact_id)?;
    let stored_intent_digest: ContentDigest = json_str(&intent_meta, "intent_digest")?
        .parse()
        .map_err(|_| integrity_code("intent digest"))?;
    let pack_intent_id = context_value
        .get("resource_intent")
        .and_then(|intent| intent.get("intent_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("pack intent reference"))?
        .to_owned();
    if stored_intent_digest != command.resource_intent_digest
        || pack_intent_id != command.resource_intent_id.to_string()
        || json_str(&context_value, "resource_intent_digest")?
            != command.resource_intent_digest.to_string()
        || stored_pack_digest != command.context_pack_digest
    {
        return Err("proof.input.intent_mismatch".to_owned());
    }
    if json_str(&intent_meta, "issued_by_principal_id")? != principal.to_string() {
        return Err("proof.resource.not_found".to_owned());
    }
    let context_created: Timestamp = json_str(&context_value, "created_at")?
        .parse()
        .map_err(|_| integrity_code("pack created_at"))?;
    let context_expires: Timestamp = json_str(&context_value, "expires_at")?
        .parse()
        .map_err(|_| integrity_code("pack expires_at"))?;
    if command.created_at < context_created || command.created_at >= context_expires {
        return Err("proof.policy.denied".to_owned());
    }
    let environment_id = json_str(&intent_meta, "environment_id")?.to_owned();
    let intent_issued_by = json_str(&intent_meta, "issued_by_principal_id")?.to_owned();
    let _ = intent_issued_by;
    let current_baseline = pg_current_baseline(runtime, &environment_id)?;
    if current_baseline != parse_baseline(&intent_value)? {
        return Err("proof.state.conflict".to_owned());
    }
    let candidate_exists = fact_json(
        runtime,
        &format!("localized_changeset/{}", command.changeset_id),
    )?
    .is_some();
    if candidate_exists {
        return Err(integrity_code(
            "candidate ChangeSet identity already exists",
        ));
    }

    let workspace_id = workspace_id_of(runtime)?;
    let draft = LocalizedChangeSet {
        changeset_id: command.changeset_id,
        workspace_id: parse_workspace(&workspace_id)?,
        principal_id: principal,
        intent: command.intent.clone(),
        resource_intent_id: command.resource_intent_id,
        resource_intent_digest: command.resource_intent_digest,
        context_pack_id: command.context_pack_id,
        context_pack_digest: command.context_pack_digest,
        base_state: current_baseline.known_state.clone(),
        created_at: command.created_at,
        status: ChangeSetStatus::Draft,
        edits: Vec::new(),
        proposal_digest: None,
        sealed_changeset_digest: None,
    };
    let effect_digest = creation_effect(request_digest, &draft)?;

    // Persist the working-state projection and its idempotent operation fact.
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/localized-changeset/v1",
        "changeset_id": draft.changeset_id.to_string(),
        "workspace_id": draft.workspace_id.to_string(),
        "principal_id": draft.principal_id.to_string(),
        "intent": draft.intent.as_str(),
        "resource_intent_id": draft.resource_intent_id.to_string(),
        "resource_intent_digest": draft.resource_intent_digest.to_string(),
        "context_pack_id": draft.context_pack_id.to_string(),
        "context_pack_digest": draft.context_pack_digest.to_string(),
        "base_state_api_version": draft.base_state.api_version,
        "base_authoritative_sequence": draft.base_state.authoritative_sequence,
        "base_state_digest": draft.base_state.digest.to_string(),
        "created_at": draft.created_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "lifecycle_status": "draft",
        "proposal_digest": Value::Null,
        "effective_leaf_digest": Value::Null,
        "sealed_changeset_digest": Value::Null,
    });
    let workspace_id = workspace_id_of(runtime)?;
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_changeset/{}", draft.changeset_id),
        "localized_changeset",
        &body,
        "proof:parity:localized-changeset:v1",
    )?;
    let op_body = serde_json::json!({
        "api_version": "proof.dev/parity/changeset-create-operation/v1",
        "principal_id": principal.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "changeset_id": draft.changeset_id.to_string(),
        "effect_digest": effect_digest.to_string(),
    });
    insert_parity_op_fact(runtime, &op_fact_id, &op_body)?;

    load_pg_localized_changeset(runtime, &command.changeset_id.to_string())
}

fn workspace_id_of(runtime: &mut PgRuntime) -> Result<String, String> {
    let metadata = require_fact_json(runtime, "workspace/metadata", "proof.resource.not_found")?;
    metadata
        .get("workspace_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| integrity_code("workspace identity"))
}

fn parse_workspace(raw: &str) -> Result<proof_domain::WorkspaceId, String> {
    raw.parse()
        .map_err(|_| integrity_code("workspace identity"))
}

/// Ports `changeset_creation_effect`.
fn creation_effect(
    request_digest: ContentDigest,
    changeset: &LocalizedChangeSet,
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.create/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "base_state": {
                "api_version": changeset.base_state.api_version,
                "authoritative_sequence": changeset.base_state.authoritative_sequence,
                "digest": changeset.base_state.digest.to_string(),
            },
            "changeset_id": changeset.changeset_id.to_string(),
            "context_pack_digest": changeset.context_pack_digest.to_string(),
            "context_pack_id": changeset.context_pack_id.to_string(),
            "resource_intent_digest": changeset.resource_intent_digest.to_string(),
            "resource_intent_id": changeset.resource_intent_id.to_string(),
            "status": "draft",
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(
        proof_domain::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

/// Inserts or replaces one mutable parity working-state projection fact.
fn upsert_parity_fact(
    runtime: &mut PgRuntime,
    workspace_id: &str,
    fact_id: &str,
    kind: &str,
    body: &Value,
    digest_context: &str,
) -> Result<(), String> {
    let canonical = canonicalize(body).map_err(|error| integrity_code(&error.to_string()))?;
    let fact_digest = derive_key_digest(digest_context, canonical.as_bytes());
    let client = runtime.client_mut();
    client
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, $3, 0, $4, $5, now())
             ON CONFLICT (fact_id) DO UPDATE SET
                 fact_digest = EXCLUDED.fact_digest,
                 body = EXCLUDED.body,
                 committed_at = now()",
            &[
                &fact_id,
                &workspace_id,
                &kind,
                &fact_digest.to_string(),
                &canonical.as_bytes().to_vec(),
            ],
        )
        .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(())
}

/// Inserts one immutable idempotent-operation fact; a conflicting identity is
/// an integrity failure exactly like the reference storage.
fn insert_parity_op_fact(
    runtime: &mut PgRuntime,
    fact_id: &str,
    body: &Value,
) -> Result<(), String> {
    let canonical = canonicalize(body).map_err(|error| integrity_code(&error.to_string()))?;
    let fact_digest = derive_key_digest(
        "proof:parity:changeset-create-operation:v1",
        canonical.as_bytes(),
    );
    let workspace_id = workspace_id_of(runtime)?;
    let inserted = {
        let client = runtime.client_mut();
        client
            .execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
                 ) VALUES ($1, $2, 'changeset_create_operation', 0, $3, $4, now())
                 ON CONFLICT (fact_id) DO NOTHING",
                &[
                    &fact_id,
                    &workspace_id,
                    &fact_digest.to_string(),
                    &canonical.as_bytes().to_vec(),
                ],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
    };
    if inserted == 0 {
        return Err(integrity_code("operation fact identity already exists"));
    }
    Ok(())
}

/// Persists the scalar resource-intent metadata (the canonical manifest
/// intentionally excludes its own digest).
fn import_resource_intent_meta(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT intent_id, issued_by_principal_id, environment_id, intent_digest
             FROM content_resource_intents ORDER BY intent_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (intent_id, issued_by, environment_id, intent_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/resource-intent-metadata/v1",
            "intent_id": intent_id,
            "issued_by_principal_id": issued_by,
            "environment_id": environment_id,
            "intent_digest": intent_digest,
        });
        let canonical = canonicalize(&body).map_err(|error| PgError::Import(error.to_string()))?;
        let fact_digest = derive_key_digest(
            "proof:parity:resource-intent-metadata:v1",
            canonical.as_bytes(),
        );
        insert_fact(
            runtime,
            &format!("resource_intent_meta/{intent_id}"),
            workspace_id,
            "resource_intent_meta",
            &fact_digest,
            canonical.as_bytes(),
        )?;
    }
    Ok(())
}
