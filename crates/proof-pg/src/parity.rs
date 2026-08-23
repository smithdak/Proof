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

use proof_application::authority::{
    AuthorityOperation, LocalizedChangeSetGetInputV2, LocalizedContextBuildInputV2,
    WorkspaceStatusInputV1,
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
            if parse_input::<LocalizedChangeSetGetInputV2>(normalized_input).is_err() {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            }
            Err(PgError::Integrity(format!(
                "operation `{}` is not yet mirrored on the PostgreSQL parity backend",
                operation.name
            )))
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
