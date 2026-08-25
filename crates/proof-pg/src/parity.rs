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
    AuthorityOperation, LocalizedChangeSetAddInputV2, LocalizedChangeSetCommitInputV2,
    LocalizedChangeSetCreateInputV2, LocalizedChangeSetDiffInputV2, LocalizedChangeSetGetInputV2,
    LocalizedChangeSetSubmitInputV2, LocalizedChangeSetValidateInputV2,
    LocalizedContextBuildInputV2, LocalizedEditionCreateInputV2,
    LocalizedObjectQueryReleasedInputV2, LocalizedReleaseCreateInputV2, WorkspaceStatusInputV1,
};
use proof_application::{
    AddLocalizedEditsCommand, AddedLocalizedEdits, BuildLocalizedContextCommand,
    CommitLocalizedChangeSetCommand, CommittedLocalizedChangeSet, CreateLocalizedEditionCommand,
    KNOWN_STATE_V1_API_VERSION, KNOWN_STATE_V2_API_VERSION, LocalizedChangeSetDiff,
    LocalizedContextPack, LocalizedEdition, LocalizedRelease, LocalizedValidation,
    ObjectLocalePutInput, PromoteLocalizedReleaseCommand, QueryReleasedRenditionsCommand,
    ReleasedRenditionQuery, SubmittedLocalizedChangeSet,
};
use proof_attestation::sign_release_statement;
use proof_attestation::{Ed25519SigningProvider, InTotoStatement, InTotoSubject};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest};
use proof_remote::{
    AuthenticatedActorContextV2, AuthorityHeadV1, OracleConsequence, OracleOutcome, OracleTraceV1,
    RemoteError, RemoteOperationV1, StableProblem, StorageBackend,
    application_problem_digest_preimage, derive_key_digest, normalized_operation_input_digest,
    operation_effect_digest,
};
use rusqlite::OptionalExtension as _;
use serde_json::Value;
use std::str::FromStr as _;

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
const FACT_KIND_CONTEXT_BUILD_OPERATION: &str = "context_build_operation";
/// Fact kind marker for an imported localized `ChangeSet` row projection.
const FACT_KIND_LOCALIZED_CHANGESET: &str = "localized_changeset";
/// Fact kind marker for one imported localized Edit artifact.
const FACT_KIND_LOCALIZED_EDIT: &str = "localized_edit";
/// Fact kind marker for one imported localized validation attempt.
const FACT_KIND_LOCALIZED_VALIDATION: &str = "localized_validation";
const FACT_KIND_LOCALIZED_SUBMISSION: &str = "localized_submission";
const FACT_KIND_LOCALIZED_APPROVAL: &str = "localized_approval";
const FACT_KIND_LOCALIZED_COMMIT: &str = "localized_commit";
const FACT_KIND_LOCALIZED_EDITION: &str = "localized_edition";
const FACT_KIND_LOCALIZED_EDITION_META: &str = "localized_edition_meta";

/// The PostgreSQL parity backend: it evaluates a shared operation against the
/// imported, verified PostgreSQL state (contract §"Conformance and
/// falsification plan").
pub struct PostgresBackend<'a> {
    runtime: &'a mut PgRuntime,
    release_signer: Option<Ed25519SigningProvider>,
}

impl<'a> PostgresBackend<'a> {
    /// Binds the PostgreSQL backend to a runtime whose schema has already been
    /// migrated and populated by [`prepare_parity_backend`].
    #[must_use]
    pub fn new(runtime: &'a mut PgRuntime) -> Self {
        Self {
            runtime,
            release_signer: None,
        }
    }

    /// Binds the backend with the Workspace's file-backed Release signer so
    /// `release.create/v2` can reproduce signatures byte-identically. Keys
    /// live outside the store by design and are never imported as facts.
    #[must_use]
    pub fn with_release_signer(
        runtime: &'a mut PgRuntime,
        release_signer: Ed25519SigningProvider,
    ) -> Self {
        Self {
            runtime,
            release_signer: Some(release_signer),
        }
    }
}

impl StorageBackend for PostgresBackend<'_> {
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError> {
        run_postgres_operation(
            self.runtime,
            self.release_signer.as_ref(),
            normalized_input,
            actor_context,
        )
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
    release_signer: Option<&Ed25519SigningProvider>,
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
            match pg_build_context(runtime, &command) {
                Ok(context) => {
                    let result = proof_remote::oracle::serialize_localized_context_pack(&context);
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
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ChangesetAddV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetAddInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let Ok(command) = proof_remote::oracle::build_add_edits_command(input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            match pg_add_edits(runtime, &command) {
                Ok(added) => {
                    let result = proof_remote::oracle::serialize_added_localized_edits(&added);
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
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ChangesetValidateV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetValidateInputV2>(normalized_input)
            else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            match pg_validate_changeset(runtime, input.changeset_id) {
                Ok(validation) => {
                    let result = proof_remote::oracle::serialize_localized_validation(&validation);
                    success_trace(
                        &operation,
                        normalized_input,
                        evaluated_authority_head,
                        result,
                        Some(validation.validation_results_digest),
                    )
                }
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ChangesetSubmitV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetSubmitInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            match pg_submit_changeset(runtime, input.changeset_id, input.submitted_at) {
                Ok(submitted) => {
                    let result =
                        proof_remote::oracle::serialize_submitted_localized_changeset(&submitted);
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
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ChangesetCommitV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetCommitInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            match pg_commit_changeset(runtime, &command) {
                Ok(committed) => {
                    let result =
                        proof_remote::oracle::serialize_committed_localized_changeset(&committed);
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
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::EditionCreateV2 => {
            let Ok(input) = parse_input::<LocalizedEditionCreateInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            match pg_create_edition(runtime, &command) {
                Ok(edition) => {
                    let result = proof_remote::oracle::serialize_localized_edition(&edition);
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
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ChangesetDiffV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetDiffInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            match pg_diff_changeset(runtime, input.changeset_id) {
                Ok(diff) => success_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    proof_remote::oracle::serialize_localized_change_set_diff(&diff),
                    None,
                ),
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ObjectQueryReleasedV2 => {
            let Ok(input) = parse_input::<LocalizedObjectQueryReleasedInputV2>(normalized_input)
            else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            match pg_query_released(runtime, &command) {
                Ok(query) => success_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    proof_remote::oracle::serialize_released_rendition_query(&query),
                    None,
                ),
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
        }
        AuthorityOperation::ReleaseCreateV2 => {
            let Ok(input) = parse_input::<LocalizedReleaseCreateInputV2>(normalized_input) else {
                return stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    INPUT_SCHEMA_MISMATCH_CODE,
                );
            };
            let command = input.into_application_command();
            match pg_promote_release(runtime, release_signer, &command) {
                Ok((result, release_digest)) => success_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    result,
                    Some(release_digest),
                ),
                Err(error) => stable_problem_trace(
                    &operation,
                    normalized_input,
                    evaluated_authority_head,
                    &error,
                ),
            }
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
    import_source_objects(runtime, &connection, &workspace_id)?;
    import_localized_submissions(runtime, &connection, &workspace_id)?;
    import_localized_approvals(runtime, &connection, &workspace_id)?;
    import_localized_commits(runtime, &connection, &workspace_id)?;
    import_localized_editions(runtime, &connection, &workspace_id)?;
    import_renditions(runtime, &connection, &workspace_id)?;
    import_localizable_schemas(runtime, &connection, &workspace_id)?;
    import_environment_configs(runtime, &connection, &workspace_id)?;
    import_editions_v1(runtime, &connection, &workspace_id)?;
    import_environment_current_releases(runtime, &connection, &workspace_id)?;
    import_context_build_operations(runtime, &connection, &workspace_id)?;
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
                    sealed_changeset_digest, proposal_digest, findings_json,
                    previous_result_digest, effective_leaf_digest, policy_digest,
                    validator
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
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
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
            previous,
            effective_leaf,
            policy,
            validator_text,
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
            "attempt": attempt,
            "changeset_id": changeset_id,
            "effective_leaf_digest": effective_leaf,
            "policy_digest": policy,
            "previous_result_digest": previous,
            "proposal_digest": proposal_digest,
            "results": serde_json::from_str::<Value>(&results_json)
                .map_err(|error| PgError::Import(error.to_string()))?,
            "results_digest": results_digest.to_string(),
            "sealed_changeset_digest": sealed,
            "findings": serde_json::from_str::<Value>(&findings)
                .map_err(|error| PgError::Import(error.to_string()))?,
            "valid": valid != 0,
            "validator": validator_text,
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
    ObjectId, ObjectRevision, SchemaId, SchemaVersion,
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
        let release_sequence: i64 = connection
            .query_row(
                "SELECT release_sequence FROM releases WHERE release_id = ?1",
                [&release_id],
                |row| row.get(0),
            )
            .map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/environment-current/v1",
            "environment_id": environment_id,
            "release_id": release_id,
            "release_sequence": u64::try_from(release_sequence)
                .map_err(|_| PgError::Import("negative Release sequence".to_owned()))?,
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
                    release_digest, released_at
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
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (release_id, api_version, edition_id, edition_digest, release_digest, released_at) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/release-metadata/v1",
            "edition_digest": edition_digest,
            "edition_id": edition_id,
            "release_api_version": api_version,
            "release_digest": release_digest,
            "release_id": release_id,
            "released_at": released_at,
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

/// Persists source Objects with digest-verified canonical content so the
/// executor can reproduce `verify_edit_input` source checks.
fn import_source_objects(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, schema_id, schema_version, content_json, object_digest,
                    authoritative_sequence
             FROM object_revisions WHERE revision = 1 AND lifecycle_state = 'active'
             ORDER BY object_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (object_id, schema_id, schema_version, content_json, object_digest, sequence) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let value: Value = serde_json::from_str(&content_json)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let parsed_schema_id = proof_domain::SchemaId::new(schema_id.clone())
            .map_err(|error| PgError::Import(error.to_string()))?;
        let parsed_version = proof_domain::SchemaVersion::new(
            u32::try_from(schema_version)
                .map_err(|_| PgError::Import("invalid schema version".to_owned()))?,
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
        let parsed_object_id = object_id
            .parse::<proof_domain::ObjectId>()
            .map_err(|error| PgError::Import(error.to_string()))?;
        let reproduced = proof_canonical::object_revision_digest(
            parsed_object_id,
            &parsed_schema_id,
            parsed_version,
            &value,
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
        if reproduced.to_string() != object_digest {
            return Err(PgError::Import(
                "source Object digest does not reproduce".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/source-object/v1",
            "authoritative_sequence": u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative Object sequence".to_owned()))?,
            "object_id": object_id,
            "schema_id": schema_id,
            "schema_version": schema_version,
            "canonical_content": content_json,
            "object_digest": object_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("source_object/{object_id}"),
            "proof:parity:source-object:v1",
            "source_object",
            &body,
        )?;
    }
    Ok(())
}

/// Persists locale renditions with verified `ObjectLocaleRevisionV1` digests.
fn import_renditions(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT object_id, locale, revision, authoritative_sequence, manifest_json,
                    rendition_digest, changeset_id
             FROM object_locale_revisions ORDER BY object_id, locale, revision",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (object_id, locale, _revision, sequence, manifest_json, rendition_digest, changeset_id) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let canonical_value: Value = serde_json::from_str(&manifest_json)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical =
            canonicalize(&canonical_value).map_err(|error| PgError::Import(error.to_string()))?;
        let reproduced = digest(ArtifactKind::ObjectLocaleRevisionV1, &canonical);
        if reproduced.to_string() != rendition_digest {
            return Err(PgError::Import(
                "locale rendition digest does not reproduce".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/locale-rendition/v1",
            "authoritative_sequence": sequence,
            "changeset_id": changeset_id,
            "manifest": canonical_value,
            "rendition_digest": rendition_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!(
                "locale_rendition/{object_id}/{locale}/{sequence:020}/{revision:020}",
                revision = canonical_value
                    .get("revision")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| PgError::Import("locale rendition lacks revision".to_owned()))?,
            ),
            "proof:parity:locale-rendition:v1",
            "locale_rendition",
            &body,
        )?;
    }
    Ok(())
}

/// Persists localizable Schema documents with verified `SchemaVersionV1` digests.
fn import_localizable_schemas(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_json, document_digest,
                    authoritative_sequence
             FROM schema_versions ORDER BY schema_id, schema_version",
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
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (schema_id, schema_version, document_json, document_digest, sequence) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let value: Value = serde_json::from_str(&document_json)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical = canonicalize(&value).map_err(|error| PgError::Import(error.to_string()))?;
        let reproduced = digest(ArtifactKind::SchemaVersionV1, &canonical);
        if reproduced.to_string() != document_digest {
            return Err(PgError::Import(
                "Schema digest does not reproduce".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localizable-schema/v1",
            "authoritative_sequence": u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative Schema sequence".to_owned()))?,
            "document": value,
            "document_digest": document_digest,
            "schema_id": schema_id,
            "schema_version": schema_version,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("localizable_schema/{schema_id}/{schema_version}"),
            "proof:parity:localizable-schema:v1",
            "localizable_schema",
            &body,
        )?;
    }
    Ok(())
}

/// Canonicalizes a fact body, derives its domain-separated digest under
/// `digest_context`, and inserts the verified row.
fn store_verified_fact(
    runtime: &mut PgRuntime,
    workspace_id: &str,
    fact_id: &str,
    digest_context: &str,
    kind: &str,
    body: &Value,
) -> Result<(), PgError> {
    let canonical = canonicalize(body).map_err(|error| PgError::Import(error.to_string()))?;
    let fact_digest = derive_key_digest(digest_context, canonical.as_bytes());
    insert_fact(
        runtime,
        fact_id,
        "",
        kind,
        &fact_digest,
        canonical.as_bytes(),
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn pg_add_edits(
    runtime: &mut PgRuntime,
    command: &AddLocalizedEditsCommand,
) -> Result<AddedLocalizedEdits, String> {
    use proof_application::{
        ChangeSetIntent, ChangeSetStatus, EditId, ExpectedLocalizedSource, LocaleId,
        LocalizedContentRepository, LocalizedEdit, MAX_LOCALIZED_EDITS, ObjectLocalePutInput,
    };
    if command.edits.is_empty()
        || command.edits.len() != command.assigned_edit_ids.len()
        || command.edits.len() > usize::try_from(MAX_LOCALIZED_EDITS).unwrap_or(usize::MAX)
        || command
            .assigned_edit_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != command.assigned_edit_ids.len()
    {
        return Err("proof.input.schema_mismatch".to_owned());
    }
    let semantic_values = command
        .edits
        .iter()
        .map(semantic_edit_value)
        .collect::<Result<Vec<_>, _>>()?;
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation/changeset.add/v2",
        "changeset_id": command.changeset_id.to_string(),
        "edits": semantic_values,
        "idempotency_key": command.idempotency_key.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let request_digest = digest(proof_domain::ArtifactKind::OperationEffectV1, &request);

    let principal = parity_principal(runtime)?;
    let op_fact_id = format!(
        "op_changeset_add/{principal}/{key}",
        key = command.idempotency_key
    );
    if let Some(prior) = fact_json(runtime, &op_fact_id)? {
        let stored_request: ContentDigest = prior
            .get("request_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op request"))?
            .parse()
            .map_err(|_| integrity_code("op request"))?;
        if stored_request != request_digest {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        let first_ordinal = prior
            .get("first_ordinal")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("op ordinal"))?;
        let added_count = prior
            .get("added_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("op count"))?;
        let total_edit_count = prior
            .get("total_edit_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("op total"))?;
        let first_ordinal =
            u32::try_from(first_ordinal).map_err(|_| integrity_code("op ordinal"))?;
        let added_count = u32::try_from(added_count).map_err(|_| integrity_code("op count"))?;
        let total_edit_count =
            u32::try_from(total_edit_count).map_err(|_| integrity_code("op total"))?;
        let edit_ids = pg_operation_edit_ids(
            runtime,
            &command.changeset_id.to_string(),
            first_ordinal,
            added_count,
        )?;
        let effect = add_effect(
            request_digest,
            command.changeset_id,
            first_ordinal,
            total_edit_count,
            &edit_ids,
        )?;
        let stored_effect: ContentDigest = prior
            .get("effect_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op effect"))?
            .parse()
            .map_err(|_| integrity_code("op effect"))?;
        if effect != stored_effect {
            return Err(integrity_code("add operation effect"));
        }
        return Ok(AddedLocalizedEdits {
            changeset_id: command.changeset_id,
            edit_ids,
            first_ordinal,
            total_edit_count,
        });
    }

    let mut changeset = load_pg_localized_changeset(runtime, &command.changeset_id.to_string())?;
    if changeset.principal_id != principal {
        return Err("proof.resource.not_found".to_owned());
    }
    if changeset.status != proof_application::ChangeSetStatus::Draft {
        return Err("proof.changeset.not_draft".to_owned());
    }
    let intent_manifest = require_fact_json(
        runtime,
        &format!("resource_intent/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let environment_id = json_str(&intent_manifest, "environment_id")?;
    let current_baseline = pg_current_baseline(runtime, environment_id)?;
    if current_baseline.known_state.authoritative_sequence
        != changeset.base_state.authoritative_sequence
        || current_baseline.known_state.digest != changeset.base_state.digest
    {
        return Err("proof.state.conflict".to_owned());
    }
    let context_manifest = require_fact_json(
        runtime,
        &format!("context_pack/{}", changeset.context_pack_id),
        "proof.resource.not_found",
    )?;
    let max_edits = context_manifest
        .get("limits")
        .and_then(|limits| limits.get("max_edits"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| integrity_code("pack limits"))?;
    let added_count =
        u32::try_from(command.edits.len()).map_err(|_| "proof.input.limit_exceeded".to_owned())?;
    let existing_count = u32::try_from(changeset.edits.len())
        .map_err(|_| "proof.input.limit_exceeded".to_owned())?;
    let total_edit_count = existing_count
        .checked_add(added_count)
        .ok_or_else(|| "proof.input.limit_exceeded".to_owned())?;
    if total_edit_count > max_edits {
        return Err("proof.input.limit_exceeded".to_owned());
    }
    let first_ordinal = existing_count
        .checked_add(1)
        .ok_or_else(|| "proof.input.limit_exceeded".to_owned())?;
    let batch_targets = command
        .edits
        .iter()
        .map(|edit| (edit.object_id, &edit.locale))
        .collect::<std::collections::BTreeSet<_>>();
    if batch_targets.len() != command.edits.len() {
        return Err("proof.changeset.duplicate_target".to_owned());
    }
    let active = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .map(|edit| {
            (
                (edit.input.object_id, edit.input.locale.clone()),
                edit.edit_id,
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let base_sequence = changeset.base_state.authoritative_sequence;
    for (index, (input, edit_id)) in command
        .edits
        .iter()
        .zip(&command.assigned_edit_ids)
        .enumerate()
    {
        if pg_edit_exists(runtime, *edit_id)? {
            return Err(integrity_code(
                "Proof-assigned Edit identity already exists",
            ));
        }
        verify_edit_input_pg(runtime, &intent_manifest, input, base_sequence)?;
        let target = (input.object_id, input.locale.clone());
        match active.get(&target).copied() {
            None => {
                if input.supersedes_edit_id.is_some()
                    || input.repair_of_validation_result_digest.is_some()
                {
                    return Err("proof.changeset.invalid_supersession".to_owned());
                }
            }
            Some(active_edit_id) => {
                if input.supersedes_edit_id.is_none() {
                    return Err("proof.changeset.duplicate_target".to_owned());
                }
                if input.supersedes_edit_id != Some(active_edit_id) {
                    return Err("proof.changeset.invalid_supersession".to_owned());
                }
                let Some(result_digest) = input.repair_of_validation_result_digest else {
                    return Err("proof.validation.repair_evidence_invalid".to_owned());
                };
                verify_repair_evidence_pg(
                    runtime,
                    &command.changeset_id.to_string(),
                    active_edit_id,
                    input.object_id,
                    &input.locale,
                    result_digest,
                    changeset
                        .proposal_digest
                        .ok_or_else(|| integrity_code("repair target has no proposal digest"))?,
                )?;
            }
        }
        let ordinal = first_ordinal
            .checked_add(u32::try_from(index).map_err(|_| "proof.input.limit_exceeded".to_owned())?)
            .ok_or_else(|| "proof.input.limit_exceeded".to_owned())?;
        persist_pg_edit(
            runtime,
            &command.changeset_id.to_string(),
            ordinal,
            *edit_id,
            input,
        )?;
        let manifest = semantic_edit_manifest(*edit_id, input)?;
        changeset.edits.push(LocalizedEdit {
            ordinal,
            edit_id: *edit_id,
            input: input.clone(),
            effective: false,
            canonical_json: manifest.as_str().to_owned(),
            edit_digest: digest(proof_domain::ArtifactKind::EditV2, &manifest),
        });
    }
    mark_effective_edits(&mut changeset.edits)?;
    let (proposal_digest, effective_leaf_digest) = proposal_digests(&changeset)?;

    // Refresh the working-state projection; the create key stays authoritative.
    let prior_body = require_fact_json(
        runtime,
        &format!("localized_changeset/{}", changeset.changeset_id),
        "proof.resource.not_found",
    )?;
    let body = serde_json::json!({
        "api_version": prior_body["api_version"],
        "changeset_id": prior_body["changeset_id"],
        "workspace_id": prior_body["workspace_id"],
        "principal_id": prior_body["principal_id"],
        "intent": prior_body["intent"],
        "resource_intent_id": prior_body["resource_intent_id"],
        "resource_intent_digest": prior_body["resource_intent_digest"],
        "context_pack_id": prior_body["context_pack_id"],
        "context_pack_digest": prior_body["context_pack_digest"],
        "base_state_api_version": prior_body["base_state_api_version"],
        "base_authoritative_sequence": prior_body["base_authoritative_sequence"],
        "base_state_digest": prior_body["base_state_digest"],
        "created_at": prior_body["created_at"],
        "idempotency_key": prior_body["idempotency_key"],
        "lifecycle_status": "draft",
        "proposal_digest": proposal_digest.to_string(),
        "effective_leaf_digest": effective_leaf_digest.to_string(),
        "sealed_changeset_digest": Value::Null,
    });
    let workspace_id = workspace_id_of(runtime)?;
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_changeset/{}", changeset.changeset_id),
        FACT_KIND_LOCALIZED_CHANGESET,
        &body,
        "proof:parity:localized-changeset:v1",
    )?;

    let edit_ids = command.assigned_edit_ids.clone();
    let effect_digest = add_effect(
        request_digest,
        command.changeset_id,
        first_ordinal,
        total_edit_count,
        &edit_ids,
    )?;
    let op_body = serde_json::json!({
        "api_version": "proof.dev/parity/changeset-add-operation/v1",
        "principal_id": principal.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "changeset_id": command.changeset_id.to_string(),
        "request_digest": request_digest.to_string(),
        "effect_digest": effect_digest.to_string(),
        "first_ordinal": first_ordinal,
        "added_count": added_count,
        "total_edit_count": total_edit_count,
    });
    insert_parity_op_fact(runtime, &op_fact_id, &op_body)?;

    Ok(AddedLocalizedEdits {
        changeset_id: command.changeset_id,
        edit_ids,
        first_ordinal,
        total_edit_count,
    })
}

/// Ports `semantic_edit_value`: canonical semantic shape of one Edit.
fn semantic_edit_value(input: &ObjectLocalePutInput) -> Result<Value, String> {
    use proof_application::LOCALIZED_EDIT_API_VERSION;
    let content: Value = serde_json::from_str(input.canonical_content.as_str())
        .map_err(|_| "proof.input.schema_mismatch".to_owned())?;
    let canonical = canonicalize(&content).map_err(|_| "proof.input.schema_mismatch".to_owned())?;
    if canonical.as_str() != input.canonical_content {
        return Err("proof.input.schema_mismatch".to_owned());
    }
    Ok(serde_json::json!({
        "api_version": LOCALIZED_EDIT_API_VERSION,
        "content": content,
        "expected_source": {
            "digest": input.expected_source.digest.to_string(),
            "revision": input.expected_source.revision.get(),
            "schema_id": input.expected_source.schema_id.as_str(),
            "schema_version": input.expected_source.schema_version.get(),
        },
        "expected_target": input.expected_target.as_ref().map(|target| serde_json::json!({
            "digest": target.digest.to_string(),
            "revision": target.revision.get(),
        })),
        "kind": "object.locale.put",
        "locale": input.locale.as_str(),
        "object_id": input.object_id.to_string(),
        "repair_of_validation_result_digest": input
            .repair_of_validation_result_digest
            .map(|value| value.to_string()),
        "supersedes_edit_id": input.supersedes_edit_id.map(|value| value.to_string()),
    }))
}

/// Ports `edit_manifest`: the persisted Edit artifact adds its identity.
fn semantic_edit_manifest(
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) -> Result<proof_canonical::CanonicalJson, String> {
    let mut value = semantic_edit_value(input)?;
    value["edit_id"] = Value::String(edit_id.to_string());
    canonicalize(&value).map_err(|error| integrity_code(&error.to_string()))
}

/// Ports `add_effect`.
fn add_effect(
    request_digest: ContentDigest,
    changeset_id: proof_application::ChangeSetId,
    first_ordinal: u32,
    total_edit_count: u32,
    edit_ids: &[proof_application::EditId],
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.add/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": changeset_id.to_string(),
            "edit_ids": edit_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "first_ordinal": first_ordinal,
            "total_edit_count": total_edit_count,
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(
        proof_domain::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

/// Ports `operation_edit_ids` over localized-Edit facts.
fn pg_operation_edit_ids(
    runtime: &mut PgRuntime,
    changeset_id: &str,
    first_ordinal: u32,
    added_count: u32,
) -> Result<Vec<proof_application::EditId>, String> {
    let final_ordinal = first_ordinal
        .checked_add(added_count)
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| integrity_code("invalid Edit operation range"))?;
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT fact_id, body FROM facts
             WHERE fact_kind = $1 AND fact_id LIKE $2 ORDER BY fact_id",
            &[
                &FACT_KIND_LOCALIZED_EDIT,
                &format!("localized_edit/{changeset_id}/%"),
            ],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut values = Vec::with_capacity(rows.len());
    for row in rows {
        let fact_id: String = row.get(0);
        let body: Vec<u8> = row.get(1);
        let suffix = fact_id
            .rsplit('/')
            .next()
            .ok_or_else(|| integrity_code("edit ordinal"))?;
        let ordinal: u32 = suffix.parse().map_err(|_| integrity_code("edit ordinal"))?;
        if ordinal < first_ordinal || ordinal > final_ordinal {
            continue;
        }
        let manifest: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let edit_id = manifest
            .get("edit_id")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("edit identity"))?
            .parse()
            .map_err(|_| integrity_code("edit identity"))?;
        values.push(edit_id);
    }
    if values.len() != usize::try_from(added_count).unwrap_or(usize::MAX) {
        return Err(integrity_code(
            "localized Edit operation range is incomplete",
        ));
    }
    Ok(values)
}

/// Reports whether an assigned Edit identity already exists anywhere.
fn pg_edit_exists(
    runtime: &mut PgRuntime,
    edit_id: proof_application::EditId,
) -> Result<bool, String> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT body FROM facts WHERE fact_kind = $1",
            &[&FACT_KIND_LOCALIZED_EDIT],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let manifest: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        if manifest.get("edit_id").and_then(Value::as_str) == Some(edit_id.to_string().as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Persists one new Edit as a verified localized-Edit fact.
fn persist_pg_edit(
    runtime: &mut PgRuntime,
    changeset_id: &str,
    ordinal: u32,
    edit_id: proof_application::EditId,
    input: &ObjectLocalePutInput,
) -> Result<(), String> {
    let manifest = semantic_edit_manifest(edit_id, input)?;
    let edit_digest = digest(proof_domain::ArtifactKind::EditV2, &manifest);
    let workspace_id = workspace_id_of(runtime)?;
    let canonical_bytes = manifest.as_bytes().to_vec();
    insert_fact(
        runtime,
        &format!("localized_edit/{changeset_id}/{ordinal:020}"),
        &workspace_id,
        FACT_KIND_LOCALIZED_EDIT,
        &edit_digest,
        &canonical_bytes,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(())
}

/// Ports `verify_repair_evidence` over imported validation facts.
fn verify_repair_evidence_pg(
    runtime: &mut PgRuntime,
    changeset_id: &str,
    superseded_edit_id: proof_application::EditId,
    object_id: proof_domain::ObjectId,
    locale: &proof_application::LocaleId,
    expected_result_digest: ContentDigest,
    expected_proposal_digest: ContentDigest,
) -> Result<(), String> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT fact_id, body FROM facts
             WHERE fact_kind = $1 AND fact_id LIKE $2 ORDER BY fact_id",
            &[
                &"localized_validation",
                &format!("localized_validation/{changeset_id}/%"),
            ],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut matched_attempt: Option<i64> = None;
    let mut latest_attempt: i64 = i64::MIN;
    for row in rows {
        let fact_id: String = row.get(0);
        let body: Vec<u8> = row.get(1);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let attempt = value
            .get("attempt")
            .and_then(Value::as_i64)
            .ok_or_else(|| integrity_code("validation attempt"))?;
        if attempt > latest_attempt {
            let proposal_matches = value.get("proposal_digest").and_then(Value::as_str)
                == Some(expected_proposal_digest.to_string().as_str());
            if proposal_matches {
                latest_attempt = attempt;
            }
        }
        let result_digest = value
            .get("results_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("validation results digest"))?;
        if result_digest != expected_result_digest.to_string() {
            continue;
        }
        if value.get("valid").and_then(Value::as_bool) != Some(false)
            || value.get("proposal_digest").and_then(Value::as_str)
                != Some(expected_proposal_digest.to_string().as_str())
        {
            return Err("proof.validation.repair_evidence_invalid".to_owned());
        }
        matched_attempt = Some(attempt);
        let findings = value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or_else(|| integrity_code("validation findings"))?;
        let matches = findings.iter().any(|finding| {
            finding.get("edit_id").and_then(Value::as_str)
                == Some(superseded_edit_id.to_string().as_str())
                && finding.get("object_id").and_then(Value::as_str)
                    == Some(object_id.to_string().as_str())
                && finding.get("locale").and_then(Value::as_str) == Some(locale.as_str())
                && finding.get("severity").and_then(Value::as_str) == Some("error")
        });
        if !matches {
            return Err("proof.validation.repair_evidence_invalid".to_owned());
        }
    }
    match matched_attempt {
        Some(attempt) if attempt == latest_attempt => Ok(()),
        _ => Err("proof.validation.repair_evidence_invalid".to_owned()),
    }
}

/// Ports `verify_edit_input`: target membership, source/rendition/schema
/// checks, JSON Schema validation, and reconstructed-equality.
fn verify_edit_input_pg(
    runtime: &mut PgRuntime,
    intent_manifest: &Value,
    input: &ObjectLocalePutInput,
    base_sequence: u64,
) -> Result<(), String> {
    const INVALID: &str = "proof.input.schema_mismatch";
    let targets = intent_manifest
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity_code("intent targets"))?;
    let member = targets.iter().any(|target| {
        target.get("object_id").and_then(Value::as_str)
            == Some(input.object_id.to_string().as_str())
            && target.get("schema_id").and_then(Value::as_str)
                == Some(input.expected_source.schema_id.as_str())
            && target.get("locale").and_then(Value::as_str) == Some(input.locale.as_str())
    });
    if !member {
        return Err("proof.input.intent_mismatch".to_owned());
    }
    let source = require_fact_json(
        runtime,
        &format!("source_object/{}", input.object_id),
        "proof.resource.not_found",
    )?;
    if input.expected_source.revision != proof_application::ObjectRevision::INITIAL
        || source.get("object_digest").and_then(Value::as_str)
            != Some(input.expected_source.digest.to_string().as_str())
        || source.get("schema_id").and_then(Value::as_str)
            != Some(input.expected_source.schema_id.as_str())
        || source.get("schema_version").and_then(Value::as_u64)
            != Some(u64::from(input.expected_source.schema_version.get()))
    {
        return Err("proof.state.source_conflict".to_owned());
    }
    let persisted_target = pg_rendition_at(
        runtime,
        &input.object_id.to_string(),
        &input.locale.to_string(),
        base_sequence,
    )?;
    let expected_matches = match (&input.expected_target, &persisted_target) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            expected.revision.get() == actual.revision
                && expected.digest.to_string() == actual.digest
        }
        _ => false,
    };
    if !expected_matches {
        return Err("proof.state.target_conflict".to_owned());
    }
    let schema = require_fact_json(
        runtime,
        &format!(
            "localizable_schema/{}/{}",
            input.expected_source.schema_id.as_str(),
            input.expected_source.schema_version.get()
        ),
        INVALID,
    )?;
    let source_value: Value = serde_json::from_str(
        source
            .get("canonical_content")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("source content"))?,
    )
    .map_err(|_| INVALID.to_owned())?;
    let target_value: Value =
        serde_json::from_str(input.canonical_content.as_str()).map_err(|_| INVALID.to_owned())?;
    let target_canonical = canonicalize(&target_value).map_err(|_| INVALID.to_owned())?;
    if target_canonical.as_str() != input.canonical_content || !target_value.is_object() {
        return Err(INVALID.to_owned());
    }
    let schema_value = schema
        .get("document")
        .cloned()
        .ok_or_else(|| integrity_code("schema document"))?;
    let validator = jsonschema::draft202012::new(&schema_value)
        .map_err(|error| integrity_code(&error.to_string()))?;
    if validator.iter_errors(&target_value).next().is_some() {
        return Err(INVALID.to_owned());
    }
    let pointers = localizable_pointers(&schema_value)?;
    let mut reconstructed = source_value;
    for segments in &pointers {
        let target_string = string_at_pointer(&target_value, segments)?.to_owned();
        set_string_at_pointer(&mut reconstructed, segments, target_string)?;
    }
    let reconstructed = canonicalize(&reconstructed).map_err(|_| INVALID.to_owned())?;
    if reconstructed.as_str() != input.canonical_content {
        return Err(INVALID.to_owned());
    }
    Ok(())
}

struct PgRenditionAt {
    revision: u32,
    digest: String,
}

/// Ports `load_rendition_at` over locale-rendition facts.
fn pg_rendition_at(
    runtime: &mut PgRuntime,
    object_id: &str,
    locale: &str,
    sequence: u64,
) -> Result<Option<PgRenditionAt>, String> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT fact_id, body FROM facts
             WHERE fact_kind = $1 AND fact_id LIKE $2 ORDER BY fact_id DESC",
            &[
                &"locale_rendition",
                &format!("locale_rendition/{object_id}/{locale}/%"),
            ],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    for row in rows {
        let fact_id: String = row.get(0);
        let body: Vec<u8> = row.get(1);
        let sequence_text = fact_id
            .split('/')
            .nth(3)
            .ok_or_else(|| integrity_code("rendition identity"))?;
        let rendition_sequence: u64 = sequence_text
            .parse()
            .map_err(|_| integrity_code("rendition sequence"))?;
        if rendition_sequence > sequence {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let revision = value
            .get("manifest")
            .and_then(|manifest| manifest.get("revision"))
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("rendition revision"))?;
        return Ok(Some(PgRenditionAt {
            revision: u32::try_from(revision).map_err(|_| integrity_code("revision range"))?,
            digest: value
                .get("rendition_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| integrity_code("rendition digest"))?
                .to_owned(),
        }));
    }
    Ok(None)
}

/// Extracts `x-proof-localizable` JSON pointers from a Schema document.
fn localizable_pointers(schema_value: &Value) -> Result<Vec<Vec<String>>, String> {
    const INVALID: &str = "proof.input.schema_mismatch";
    let pointers = schema_value
        .get("x-proof-localizable")
        .and_then(Value::as_array)
        .ok_or_else(|| INVALID.to_owned())?;
    if pointers.is_empty() {
        return Err(INVALID.to_owned());
    }
    let mut parsed = Vec::with_capacity(pointers.len());
    for pointer in pointers {
        let pointer = pointer.as_str().ok_or_else(|| INVALID.to_owned())?;
        parsed.push(parse_pointer(pointer)?);
    }
    Ok(parsed)
}

/// Splits an RFC 6901 JSON pointer into decoded segments.
fn parse_pointer(pointer: &str) -> Result<Vec<String>, String> {
    const INVALID: &str = "proof.input.schema_mismatch";
    if pointer.is_empty() || !pointer.starts_with('/') {
        return Err(INVALID.to_owned());
    }
    let mut segments = Vec::new();
    for raw in pointer[1..].split('/') {
        let mut decoded = String::new();
        let mut chars = raw.chars();
        while let Some(character) = chars.next() {
            if character == '~' {
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => return Err(INVALID.to_owned()),
                }
            } else {
                decoded.push(character);
            }
        }
        segments.push(decoded);
    }
    Ok(segments)
}

/// Reads the string at a decoded pointer path.
fn string_at_pointer<'a>(value: &'a Value, segments: &[String]) -> Result<&'a str, String> {
    const INVALID: &str = "proof.input.schema_mismatch";
    let mut current = value;
    for segment in segments {
        current = current
            .as_object()
            .and_then(|object| object.get(segment))
            .ok_or_else(|| INVALID.to_owned())?;
    }
    current.as_str().ok_or_else(|| INVALID.to_owned())
}

/// Replaces the string at a decoded pointer path.
fn set_string_at_pointer(
    value: &mut Value,
    segments: &[String],
    replacement: String,
) -> Result<(), String> {
    use serde_json::map::Entry;
    const INVALID: &str = "proof.input.schema_mismatch";
    let Some((last, parents)) = segments.split_last() else {
        return Err(INVALID.to_owned());
    };
    let mut current = value;
    for segment in parents {
        current = current
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .ok_or_else(|| INVALID.to_owned())?;
    }
    let slot = current
        .as_object_mut()
        .and_then(|object| object.get_mut(last))
        .ok_or_else(|| INVALID.to_owned())?;
    if !slot.is_string() {
        return Err(INVALID.to_owned());
    }
    *slot = Value::String(replacement);
    let _ = Entry::Vacant;
    Ok(())
}

/// Ports `validate_changeset` over imported parity facts.
#[allow(clippy::too_many_lines)]
fn pg_validate_changeset(
    runtime: &mut PgRuntime,
    changeset_id: proof_application::ChangeSetId,
) -> Result<LocalizedValidation, String> {
    use proof_application::{
        ChangeSetStatus, LOCALIZED_CONTENT_VALIDATOR, LocalizedContentTarget,
        PROHIBITED_LEGAL_CLAIM_CODE, Severity,
    };
    const INVALID: &str = "proof.input.schema_mismatch";
    let mut changeset = load_pg_localized_changeset(runtime, &changeset_id.to_string())?;
    let principal = parity_principal(runtime)?;
    if changeset.principal_id != principal {
        return Err("proof.resource.not_found".to_owned());
    }
    let chain = pg_validation_chain(runtime, &changeset_id.to_string())?;
    if changeset.status == ChangeSetStatus::Ready {
        return chain
            .last()
            .cloned()
            .ok_or_else(|| integrity_code("Ready ChangeSet lacks validation"));
    }
    if changeset.status != ChangeSetStatus::Draft || changeset.edits.is_empty() {
        return Err(INVALID.to_owned());
    }
    let intent_manifest = require_fact_json(
        runtime,
        &format!("resource_intent/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let environment_id = json_str(&intent_manifest, "environment_id")?;
    let current_baseline = pg_current_baseline(runtime, environment_id)?;
    if current_baseline.known_state.authoritative_sequence
        != changeset.base_state.authoritative_sequence
        || current_baseline.known_state.digest != changeset.base_state.digest
    {
        return Err("proof.state.conflict".to_owned());
    }
    let (proposal_digest, effective_leaf_digest, effective_edits) = pg_proposal(&changeset)?;
    let effective_targets = effective_edits
        .iter()
        .map(|edit| LocalizedContentTarget {
            object_id: edit.input.object_id,
            schema_id: edit.input.expected_source.schema_id.clone(),
            locale: edit.input.locale.clone(),
        })
        .collect::<Vec<_>>();
    let intent_targets = intent_manifest
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity_code("intent targets"))?
        .iter()
        .map(|target| {
            Ok(LocalizedContentTarget {
                object_id: json_str(target, "object_id")?
                    .parse()
                    .map_err(|_| INVALID)?,
                schema_id: proof_domain::SchemaId::new(json_str(target, "schema_id")?)
                    .map_err(|_| INVALID)?,
                locale: json_str(target, "locale")?.parse().map_err(|_| INVALID)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if effective_targets != intent_targets {
        return Err(INVALID.to_owned());
    }
    let context_fact_id = format!("context_pack/{}", changeset.context_pack_id);
    let context_manifest =
        require_fact_json(runtime, &context_fact_id, "proof.resource.not_found")?;
    let context_pack_digest: ContentDigest = fact_digest_of(runtime, &context_fact_id)?;
    let max_attempts = context_manifest
        .get("limits")
        .and_then(|limits| limits.get("max_validation_attempts"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| integrity_code("pack limits"))?;
    let attempt = u32::try_from(chain.len())
        .map_err(|_| "proof.input.limit_exceeded".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "proof.input.limit_exceeded".to_owned())?;
    if attempt > max_attempts {
        return Err("proof.input.limit_exceeded".to_owned());
    }
    let previous = chain.last().map(|result| result.validation_results_digest);
    let rules = pg_policy_rules(
        context_manifest
            .get("policy")
            .ok_or_else(|| integrity_code("pack policy"))?,
    )?;
    let policy_digest: ContentDigest = json_str(&context_manifest, "policy_digest")?
        .parse()
        .map_err(|_| integrity_code("policy digest"))?;
    let mut findings = Vec::new();
    for edit in &effective_edits {
        let localized_value: Value = serde_json::from_str(edit.input.canonical_content.as_str())
            .map_err(|error| integrity_code(&error.to_string()))?;
        for rule in rules.iter().filter(|rule| rule.locale == edit.input.locale) {
            let segments = parse_pointer(&rule.pointer)?;
            let value = string_at_pointer(&localized_value, &segments)?;
            if rule
                .disallowed_values
                .binary_search_by(|candidate| candidate.as_str().cmp(value))
                .is_ok()
            {
                findings.push(proof_application::LocalizedFinding {
                    code: PROHIBITED_LEGAL_CLAIM_CODE.to_owned(),
                    severity: Severity::Error,
                    edit_id: edit.edit_id,
                    object_id: edit.input.object_id,
                    locale: edit.input.locale.clone(),
                    pointer: Some(rule.pointer.clone()),
                    validator: LOCALIZED_CONTENT_VALIDATOR.to_owned(),
                    policy_digest,
                });
            }
        }
    }
    findings.sort_by(|left, right| {
        (
            left.object_id,
            &left.locale,
            left.pointer.as_deref().unwrap_or_default(),
            left.edit_id,
        )
            .cmp(&(
                right.object_id,
                &right.locale,
                right.pointer.as_deref().unwrap_or_default(),
                right.edit_id,
            ))
    });
    let valid = findings.is_empty();
    let schema_digests = pg_context_schema_digests(&context_manifest)?;
    let manifest_value = validation_manifest_value(
        changeset_id,
        attempt,
        previous,
        proposal_digest,
        effective_leaf_digest,
        context_pack_digest,
        policy_digest,
        &schema_digests,
        &findings,
    );
    let manifest =
        canonicalize(&manifest_value).map_err(|error| integrity_code(&error.to_string()))?;
    let validation_results_digest =
        digest(proof_domain::ArtifactKind::ValidationResultsV2, &manifest);
    let sealed_changeset_digest = valid
        .then(|| seal_digest(proposal_digest, validation_results_digest))
        .transpose()?;
    let workspace_id = workspace_id_of(runtime)?;
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/localized-validation/v1",
        "attempt": attempt,
        "changeset_id": changeset.changeset_id.to_string(),
        "effective_leaf_digest": effective_leaf_digest.to_string(),
        "findings": findings_value(&findings),
        "policy_digest": policy_digest.to_string(),
        "previous_result_digest": previous.map(|value| value.to_string()),
        "proposal_digest": proposal_digest.to_string(),
        "results": manifest_value,
        "results_digest": validation_results_digest.to_string(),
        "sealed_changeset_digest": sealed_changeset_digest.map(|value| value.to_string()),
        "valid": valid,
        "validator": LOCALIZED_CONTENT_VALIDATOR,
    });
    insert_fact(
        runtime,
        &format!(
            "localized_validation/{}/{}",
            changeset.changeset_id, attempt
        ),
        &workspace_id,
        FACT_KIND_LOCALIZED_VALIDATION,
        &derive_key_digest(
            "proof:parity:localized-validation:v1",
            body.to_string().as_bytes(),
        ),
        &serde_json::to_vec(&body).map_err(|e| integrity_code(&e.to_string()))?,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    let prior_body = require_fact_json(
        runtime,
        &format!("localized_changeset/{}", changeset.changeset_id),
        "proof.resource.not_found",
    )?;
    let mut updated = prior_body.clone();
    updated["lifecycle_status"] = Value::String(if valid { "ready" } else { "draft" }.into());
    updated["sealed_changeset_digest"] = sealed_changeset_digest
        .as_ref()
        .map_or(Value::Null, |value| Value::String(value.to_string()));
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_changeset/{}", changeset.changeset_id),
        FACT_KIND_LOCALIZED_CHANGESET,
        &updated,
        "proof:parity:localized-changeset:v1",
    )?;
    changeset.status = if valid {
        ChangeSetStatus::Ready
    } else {
        ChangeSetStatus::Draft
    };
    Ok(LocalizedValidation {
        changeset_id: changeset.changeset_id,
        attempt,
        previous_validation_result_digest: previous,
        proposal_digest,
        effective_leaf_digest,
        valid,
        findings,
        validation_results_digest,
        sealed_changeset_digest,
        status: changeset.status,
    })
}

/// Ports `load_validation_chain` over validation facts.
fn pg_validation_chain(
    runtime: &mut PgRuntime,
    changeset_id: &str,
) -> Result<Vec<LocalizedValidation>, String> {
    use proof_application::{ChangeSetStatus, Severity};
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT body FROM facts WHERE fact_kind = $1 AND fact_id LIKE $2 ORDER BY fact_id",
            &[
                &FACT_KIND_LOCALIZED_VALIDATION,
                &format!("localized_validation/{changeset_id}/%"),
            ],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut chain = Vec::with_capacity(rows.len());
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let findings = value
            .get("findings")
            .and_then(Value::as_array)
            .ok_or_else(|| integrity_code("validation findings"))?
            .iter()
            .map(|finding| {
                Ok(proof_application::LocalizedFinding {
                    code: json_str(finding, "code")?.to_owned(),
                    severity: match json_str(finding, "severity")? {
                        "info" => Severity::Info,
                        "warning" => Severity::Warning,
                        _ => Severity::Error,
                    },
                    edit_id: json_str(finding, "edit_id")?
                        .parse()
                        .map_err(|_| integrity_code("finding edit identity"))?,
                    object_id: json_str(finding, "object_id")?
                        .parse()
                        .map_err(|_| integrity_code("finding object identity"))?,
                    locale: json_str(finding, "locale")?
                        .parse()
                        .map_err(|_| integrity_code("finding locale"))?,
                    pointer: finding
                        .get("pointer")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    validator: json_str(finding, "validator")?.to_owned(),
                    policy_digest: json_str(finding, "policy_digest")?
                        .parse()
                        .map_err(|_| integrity_code("finding policy digest"))?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        chain.push(LocalizedValidation {
            changeset_id: json_str(&value, "changeset_id")?
                .parse()
                .map_err(|_| integrity_code("validation identity"))?,
            attempt: u32::try_from(
                value
                    .get("attempt")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| integrity_code("validation attempt"))?,
            )
            .map_err(|_| integrity_code("attempt range"))?,
            previous_validation_result_digest: value
                .get("previous_result_digest")
                .and_then(Value::as_str)
                .map(str::parse)
                .transpose()
                .map_err(|_| integrity_code("previous digest"))?,
            proposal_digest: json_str(&value, "proposal_digest")?
                .parse()
                .map_err(|_| integrity_code("proposal digest"))?,
            effective_leaf_digest: json_str(&value, "effective_leaf_digest")?
                .parse()
                .map_err(|_| integrity_code("leaf digest"))?,
            valid: value
                .get("valid")
                .and_then(Value::as_bool)
                .ok_or_else(|| integrity_code("validation verdict"))?,
            findings,
            validation_results_digest: json_str(&value, "results_digest")?
                .parse()
                .map_err(|_| integrity_code("results digest"))?,
            sealed_changeset_digest: value
                .get("sealed_changeset_digest")
                .and_then(Value::as_str)
                .map(str::parse)
                .transpose()
                .map_err(|_| integrity_code("seal digest"))?,
            status: if value
                .get("valid")
                .and_then(Value::as_bool)
                .unwrap_or_default()
            {
                ChangeSetStatus::Ready
            } else {
                ChangeSetStatus::Draft
            },
        });
    }
    Ok(chain)
}

/// Ports `proposal`: digests plus the ordered effective Edit set.
fn pg_proposal(
    changeset: &LocalizedChangeSet,
) -> Result<(ContentDigest, ContentDigest, Vec<LocalizedEdit>), String> {
    let mut effective = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .cloned()
        .collect::<Vec<_>>();
    effective.sort_by(|left, right| {
        (&left.input.object_id, &left.input.locale)
            .cmp(&(&right.input.object_id, &right.input.locale))
    });
    let pair = proposal_digests(changeset)?;
    Ok((pair.0, pair.1, effective))
}

/// Ports `normalized_policy_rules` + strict policy-envelope parsing.
fn pg_policy_rules(policy: &Value) -> Result<Vec<proof_application::LocalizedPolicyRule>, String> {
    use proof_application::LocalizedPolicyRule;
    const INTEGRITY_FAIL: &str = "proof.digest.mismatch";
    let object = policy
        .as_object()
        .ok_or_else(|| INTEGRITY_FAIL.to_owned())?;
    if object.len() != 2
        || object.get("api_version").and_then(Value::as_str)
            != Some("proof.dev/localized-content-policy/v1")
    {
        return Err(INTEGRITY_FAIL.to_owned());
    }
    let rules = policy
        .get("rules")
        .and_then(Value::as_array)
        .ok_or_else(|| INTEGRITY_FAIL.to_owned())?;
    let mut parsed = Vec::with_capacity(rules.len());
    for rule in rules {
        let rule = rule.as_object().ok_or_else(|| INTEGRITY_FAIL.to_owned())?;
        if rule.len() != 3 {
            return Err(INTEGRITY_FAIL.to_owned());
        }
        let values = rule
            .get("disallowed_values")
            .and_then(Value::as_array)
            .ok_or_else(|| INTEGRITY_FAIL.to_owned())?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| INTEGRITY_FAIL.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rule_value = Value::Object(rule.clone());
        parsed.push(LocalizedPolicyRule {
            locale: json_str(&rule_value, "locale")?
                .parse()
                .map_err(|_| INTEGRITY_FAIL.to_owned())?,
            pointer: json_str(&rule_value, "pointer")?.to_owned(),
            disallowed_values: values,
        });
    }
    for rule in &parsed {
        parse_pointer(&rule.pointer)?;
        if rule.disallowed_values.is_empty() {
            return Err(INTEGRITY_FAIL.to_owned());
        }
        let mut sorted = rule.disallowed_values.clone();
        sorted.sort();
        if sorted.windows(2).any(|pair| pair[0] == pair[1]) || sorted != rule.disallowed_values {
            return Err(INTEGRITY_FAIL.to_owned());
        }
    }
    Ok(parsed)
}

/// Ports `context_schema_digests`.
fn pg_context_schema_digests(context_manifest: &Value) -> Result<Vec<Value>, String> {
    let resources = context_manifest
        .get("resources")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity_code("pack resources"))?;
    let mut schemas = std::collections::BTreeMap::<(String, u32), String>::new();
    for resource in resources {
        let schema = resource
            .get("schema")
            .and_then(Value::as_object)
            .ok_or_else(|| integrity_code("pack schema"))?;
        let schema_id = schema
            .get("schema_id")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("pack schema identity"))?
            .to_owned();
        let version = schema
            .get("schema_version")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| integrity_code("pack schema version"))?;
        let digest_text = schema
            .get("document_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("pack schema digest"))?
            .to_owned();
        if let Some(existing) = schemas.insert((schema_id, version), digest_text.clone())
            && existing != digest_text
        {
            return Err(integrity_code(
                "ContextPack repeats one Schema with different bytes",
            ));
        }
    }
    Ok(schemas
        .into_iter()
        .map(|((schema_id, schema_version), document_digest)| {
            serde_json::json!({
                "document_digest": document_digest,
                "schema_id": schema_id,
                "schema_version": schema_version,
            })
        })
        .collect())
}

/// Ports `findings_value`.
fn findings_value(findings: &[proof_application::LocalizedFinding]) -> Vec<Value> {
    use proof_application::Severity;
    findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "code": finding.code,
                "edit_id": finding.edit_id.to_string(),
                "locale": finding.locale.as_str(),
                "object_id": finding.object_id.to_string(),
                "pointer": finding.pointer,
                "policy_digest": finding.policy_digest.to_string(),
                "severity": match finding.severity {
                    Severity::Info => "info",
                    Severity::Warning => "warning",
                    Severity::Error => "error",
                },
                "validator": finding.validator,
            })
        })
        .collect()
}

/// Ports `validation_manifest` as a JSON value.
#[allow(clippy::too_many_arguments)]
fn validation_manifest_value(
    changeset_id: proof_application::ChangeSetId,
    attempt: u32,
    previous: Option<ContentDigest>,
    proposal_digest: ContentDigest,
    effective_leaf_digest: ContentDigest,
    context_pack_digest: ContentDigest,
    policy_digest: ContentDigest,
    schema_digests: &[Value],
    findings: &[proof_application::LocalizedFinding],
) -> Value {
    use proof_application::LOCALIZED_CONTENT_VALIDATOR;
    serde_json::json!({
        "api_version": "proof.dev/validation-results/v2",
        "attempt": attempt,
        "changeset_id": changeset_id.to_string(),
        "context_pack_digest": context_pack_digest.to_string(),
        "effective_leaf_digest": effective_leaf_digest.to_string(),
        "findings": findings_value(findings),
        "policy_digest": policy_digest.to_string(),
        "previous_validation_result_digest": previous.map(|value| value.to_string()),
        "proposal_digest": proposal_digest.to_string(),
        "schema_digests": schema_digests,
        "valid": findings.is_empty(),
        "validator": LOCALIZED_CONTENT_VALIDATOR,
    })
}

/// Ports `seal_digest`.
fn seal_digest(
    proposal_digest: ContentDigest,
    validation_results_digest: ContentDigest,
) -> Result<ContentDigest, String> {
    let seal = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": proposal_digest.to_string(),
        "validation_results_digest": validation_results_digest.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(proof_domain::ArtifactKind::ChangeSetV2, &seal))
}

/// Persists localized submissions as verified parity facts.
fn import_localized_submissions(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, sealed_changeset_digest, validation_results_digest,
                    principal_id, submitted_at, effect_digest
             FROM localized_submissions ORDER BY changeset_id",
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
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            changeset_id,
            sealed,
            validation_results_digest,
            principal_id,
            submitted_at,
            effect_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-submission/v1",
            "changeset_id": changeset_id,
            "effect_digest": effect_digest,
            "principal_id": principal_id,
            "sealed_changeset_digest": sealed,
            "submitted_at": submitted_at,
            "validation_results_digest": validation_results_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("localized_submission/{changeset_id}"),
            "proof:parity:localized-submission:v1",
            FACT_KIND_LOCALIZED_SUBMISSION,
            &body,
        )?;
    }
    Ok(())
}

/// Ports `submit_changeset` over imported parity facts.
fn pg_submit_changeset(
    runtime: &mut PgRuntime,
    changeset_id: proof_application::ChangeSetId,
    submitted_at: Timestamp,
) -> Result<SubmittedLocalizedChangeSet, String> {
    use proof_application::ChangeSetStatus;
    let changeset = load_pg_localized_changeset(runtime, &changeset_id.to_string())?;
    let principal = parity_principal(runtime)?;
    if changeset.principal_id != principal {
        return Err("proof.resource.not_found".to_owned());
    }
    let submission_fact_id = format!("localized_submission/{changeset_id}");
    if let Some(existing) = fact_json(runtime, &submission_fact_id)? {
        let stored_at: Timestamp = json_str(&existing, "submitted_at")?
            .parse()
            .map_err(|_| integrity_code("submission timestamp"))?;
        if stored_at != submitted_at {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        return Ok(SubmittedLocalizedChangeSet {
            changeset_id,
            sealed_changeset_digest: json_str(&existing, "sealed_changeset_digest")?
                .parse()
                .map_err(|_| integrity_code("seal digest"))?,
            validation_results_digest: json_str(&existing, "validation_results_digest")?
                .parse()
                .map_err(|_| integrity_code("results digest"))?,
            submitted_at: stored_at,
            status: ChangeSetStatus::Submitted,
        });
    }
    if changeset.status != ChangeSetStatus::Ready {
        return Err("proof.changeset.not_ready".to_owned());
    }
    if submitted_at < changeset.created_at {
        return Err("proof.input.schema_mismatch".to_owned());
    }
    let chain = pg_validation_chain(runtime, &changeset_id.to_string())?;
    let validation = chain
        .last()
        .ok_or_else(|| integrity_code("localized ChangeSet has no validation evidence"))?;
    let sealed = validation
        .sealed_changeset_digest
        .ok_or_else(|| integrity_code("valid localized validation lacks a seal"))?;
    let changeset_sealed =
        load_pg_localized_changeset(runtime, &changeset_id.to_string())?.sealed_changeset_digest;
    if !validation.valid
        || validation.sealed_changeset_digest != Some(sealed)
        || changeset_sealed.as_ref() != Some(&sealed)
        || validation.proposal_digest
            != changeset
                .proposal_digest
                .ok_or_else(|| integrity_code("sealed localized ChangeSet lacks proposal digest"))?
    {
        return Err(integrity_code(
            "localized ChangeSet seal is not the valid validation head",
        ));
    }
    let effect = localized_lifecycle_effect(
        "changeset.submit/v2",
        changeset_id,
        sealed,
        validation.validation_results_digest,
        Some(submitted_at),
        None,
        principal,
    )?;
    let workspace_id = workspace_id_of(runtime)?;
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/localized-submission/v1",
        "changeset_id": changeset_id.to_string(),
        "effect_digest": effect.to_string(),
        "principal_id": principal.to_string(),
        "sealed_changeset_digest": sealed.to_string(),
        "submitted_at": submitted_at.to_string(),
        "validation_results_digest": validation.validation_results_digest.to_string(),
    });
    insert_parity_op_fact(runtime, &submission_fact_id, &body)?;
    let prior_body = require_fact_json(
        runtime,
        &format!("localized_changeset/{changeset_id}"),
        "proof.resource.not_found",
    )?;
    let mut updated = prior_body.clone();
    updated["lifecycle_status"] = Value::String("submitted".into());
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_changeset/{changeset_id}"),
        FACT_KIND_LOCALIZED_CHANGESET,
        &updated,
        "proof:parity:localized-changeset:v1",
    )?;
    Ok(SubmittedLocalizedChangeSet {
        changeset_id,
        sealed_changeset_digest: sealed,
        validation_results_digest: validation.validation_results_digest,
        submitted_at,
        status: ChangeSetStatus::Submitted,
    })
}

/// Ports `localized_lifecycle_effect`.
fn localized_lifecycle_effect(
    operation_kind: &str,
    changeset_id: proof_application::ChangeSetId,
    sealed_changeset_digest: ContentDigest,
    validation_results_digest: ContentDigest,
    occurred_at: Option<Timestamp>,
    approval: Option<&str>,
    principal_id: proof_domain::PrincipalId,
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": operation_kind,
        "result": {
            "approval": approval,
            "changeset_id": changeset_id.to_string(),
            "occurred_at": occurred_at.map(|value| value.to_string()),
            "principal_id": principal_id.to_string(),
            "sealed_changeset_digest": sealed_changeset_digest.to_string(),
            "validation_results_digest": validation_results_digest.to_string(),
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(
        proof_domain::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

/// Persists localized approvals as verified parity facts.
fn import_localized_approvals(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, approval_name, sealed_changeset_digest,
                    validation_results_digest, principal_id, approved_at, effect_digest
             FROM localized_approvals ORDER BY changeset_id",
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
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            changeset_id,
            approval_name,
            sealed,
            validation_results_digest,
            principal_id,
            approved_at,
            effect_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-approval/v1",
            "approval_name": approval_name,
            "approved_at": approved_at,
            "changeset_id": changeset_id,
            "effect_digest": effect_digest,
            "principal_id": principal_id,
            "sealed_changeset_digest": sealed,
            "validation_results_digest": validation_results_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("localized_approval/{changeset_id}"),
            "proof:parity:localized-approval:v1",
            FACT_KIND_LOCALIZED_APPROVAL,
            &body,
        )?;
    }
    Ok(())
}

/// Persists one Environment configuration fact per Workspace Environment so
/// the release executor can evaluate policy without re-deriving configuration
/// from manifests.
fn import_environment_configs(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT env.environment_id, env.created_by_principal_id, env.created_at,
                    v.config_version, v.target_kind, v.policy_profile, v.required_approval,
                    v.config_digest
             FROM environments AS env
             JOIN environment_versions AS v ON v.environment_id = env.environment_id
             WHERE env.workspace_id = ?1
                   AND v.config_version = (
                       SELECT MAX(inner_v.config_version)
                       FROM environment_versions AS inner_v
                       WHERE inner_v.environment_id = env.environment_id
                   )
             ORDER BY env.environment_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([workspace_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            environment_id,
            principal_id,
            created_at,
            config_version,
            target_kind,
            policy_profile,
            required_approval,
            config_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/environment/v1",
            "config_digest": config_digest,
            "config_version": u32::try_from(config_version)
                .map_err(|_| PgError::Import("negative Environment version".to_owned()))?,
            "created_at": created_at,
            "policy_profile": policy_profile,
            "principal_id": principal_id,
            "required_approval": required_approval,
            "target_kind": target_kind,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("environment/{environment_id}"),
            "proof:parity:environment:v1",
            "environment",
            &body,
        )?;
    }
    Ok(())
}

/// Persists v1 Edition rows so the base-Release Edition view can be rebuilt
/// (v2 localized Editions arrive through [`import_localized_editions`]).
fn import_editions_v1(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT edition_id, authoritative_sequence, state_digest, edition_digest, created_at
             FROM editions
             WHERE workspace_id = ?1 AND api_version = 'proof.dev/edition/v1'
             ORDER BY authoritative_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([workspace_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (edition_id, authoritative_sequence, state_digest, edition_digest, created_at) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/edition-v1/v1",
            "authoritative_sequence": u64::try_from(authoritative_sequence)
                .map_err(|_| PgError::Import("negative Edition sequence".to_owned()))?,
            "created_at": created_at,
            "edition_digest": edition_digest,
            "state_digest": state_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("edition_v1/{edition_id}"),
            "proof:parity:edition-v1:v1",
            "edition_v1",
            &body,
        )?;
    }
    Ok(())
}

/// Persists localized commits with their exact resulting-state references.
fn import_localized_commits(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT changeset_id, idempotency_key, sealed_changeset_digest,
                    validation_results_digest, previous_state_api_version,
                    previous_authoritative_sequence, previous_state_digest,
                    resulting_authoritative_sequence, resulting_state_digest,
                    resulting_state_json, committed_at, effect_digest
             FROM localized_commits ORDER BY changeset_id",
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
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            changeset_id,
            idempotency_key,
            sealed,
            validation_results_digest,
            previous_api_version,
            previous_sequence,
            previous_digest,
            resulting_sequence,
            resulting_digest,
            resulting_state_json,
            committed_at,
            effect_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let renditions = commit_rendition_values(connection, &changeset_id)?;
        let resulting_manifest: Value = serde_json::from_str(&resulting_state_json)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let reproduced = digest(ArtifactKind::KnownStateV2, &{
            canonicalize(&resulting_manifest).map_err(|error| PgError::Import(error.to_string()))?
        });
        if reproduced.to_string() != resulting_digest {
            return Err(PgError::Import(
                "resulting Known State digest does not reproduce".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-commit/v1",
            "changeset_id": changeset_id,
            "committed_at": committed_at,
            "effect_digest": effect_digest,
            "idempotency_key": idempotency_key,
            "renditions": renditions,
            "previous_state_api_version": previous_api_version,
            "previous_state_digest": previous_digest,
            "previous_state_sequence": u64::try_from(previous_sequence)
                .map_err(|_| PgError::Import("negative sequence".to_owned()))?,
            "resulting_state_digest": resulting_digest,
            "resulting_state_sequence": u64::try_from(resulting_sequence)
                .map_err(|_| PgError::Import("negative sequence".to_owned()))?,
            "resulting_state_manifest": resulting_manifest,
            "sealed_changeset_digest": sealed,
            "validation_results_digest": validation_results_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("localized_commit/{changeset_id}"),
            "proof:parity:localized-commit:v1",
            FACT_KIND_LOCALIZED_COMMIT,
            &body,
        )?;
    }
    Ok(())
}

/// Ports `commit_changeset` over imported parity facts.
#[allow(clippy::too_many_lines)]
fn pg_commit_changeset(
    runtime: &mut PgRuntime,
    command: &CommitLocalizedChangeSetCommand,
) -> Result<CommittedLocalizedChangeSet, String> {
    use proof_application::{ChangeSetStatus, LocaleRevision};
    const INVALID: &str = "proof.input.schema_mismatch";
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": command.changeset_id.to_string(),
        "committed_at": command.committed_at.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let request_digest = digest(proof_domain::ArtifactKind::OperationEffectV1, &request);

    let principal = parity_principal(runtime)?;
    let op_fact_id = format!(
        "op_changeset_commit/{principal}/{key}",
        key = command.idempotency_key
    );
    if let Some(prior) = fact_json(runtime, &op_fact_id)? {
        let stored_effect: ContentDigest = prior
            .get("effect_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op effect"))?
            .parse()
            .map_err(|_| integrity_code("op effect"))?;
        let persisted_id = json_str(&prior, "changeset_id")?
            .parse()
            .map_err(|_| integrity_code("commit identity"))?;
        let result = pg_load_commit(runtime, persisted_id)?;
        let expected_effect = localized_commit_effect(request_digest, &result)?;
        if persisted_id != command.changeset_id || stored_effect != expected_effect {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        return Ok(result);
    }

    let changeset = load_pg_localized_changeset(runtime, &command.changeset_id.to_string())?;
    if changeset.principal_id != principal {
        return Err("proof.resource.not_found".to_owned());
    }
    if changeset.status != ChangeSetStatus::Approved {
        return Err("proof.changeset.not_approved".to_owned());
    }
    let chain = pg_validation_chain(runtime, &command.changeset_id.to_string())?;
    let validation = chain
        .last()
        .ok_or_else(|| integrity_code("localized ChangeSet has no validation evidence"))?;
    let sealed = validation
        .sealed_changeset_digest
        .ok_or_else(|| integrity_code("valid localized validation lacks a seal"))?;
    let approval = require_fact_json(
        runtime,
        &format!("localized_approval/{}", command.changeset_id),
        "proof.evidence.incomplete",
    )?;
    let approved_at: Timestamp = json_str(&approval, "approved_at")?
        .parse()
        .map_err(|_| integrity_code("approval timestamp"))?;
    if command.committed_at < approved_at {
        return Err(INVALID.to_owned());
    }
    if !validation.valid || changeset.sealed_changeset_digest.as_ref() != Some(&sealed) {
        return Err(integrity_code(
            "localized ChangeSet seal is not the valid validation head",
        ));
    }
    let intent_manifest = require_fact_json(
        runtime,
        &format!("resource_intent/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let environment_id = json_str(&intent_manifest, "environment_id")?;
    let current_baseline = pg_current_baseline(runtime, environment_id)?;
    if current_baseline.known_state.authoritative_sequence
        != changeset.base_state.authoritative_sequence
        || current_baseline.known_state.digest != changeset.base_state.digest
    {
        return Err("proof.state.conflict".to_owned());
    }
    let head = require_fact_json(runtime, "known_state/head", "proof.state.conflict")?;
    let previous_state = KnownStateArtifactReference {
        api_version: json_str(&head, "known_state_api_version")?.to_owned(),
        authoritative_sequence: head
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("head sequence"))?,
        digest: json_str(&head, "state_digest")?
            .parse()
            .map_err(|_| integrity_code("head digest"))?,
    };
    if previous_state.authoritative_sequence != changeset.base_state.authoritative_sequence
        || previous_state.digest != changeset.base_state.digest
    {
        return Err("proof.state.conflict".to_owned());
    }
    ensure_known_state_artifact_pg(runtime, &previous_state)?;
    let (_, _, effective_edits) = pg_proposal(&changeset)?;
    if effective_edits.is_empty() {
        return Err(INVALID.to_owned());
    }
    let workspace_typed = workspace_id_of(runtime)?
        .parse()
        .map_err(|_| integrity_code("workspace identity"))?;
    let mut renditions = Vec::with_capacity(effective_edits.len());
    let mut next_sequence = previous_state.authoritative_sequence;
    for edit in &effective_edits {
        verify_edit_input_pg(
            runtime,
            &intent_manifest,
            &edit.input,
            previous_state.authoritative_sequence,
        )?;
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or_else(|| integrity_code("authoritative sequence overflow"))?;
        let previous = pg_rendition_at(
            runtime,
            &edit.input.object_id.to_string(),
            &edit.input.locale.to_string(),
            previous_state.authoritative_sequence,
        )?;
        let revision = LocaleRevision::new(
            previous
                .as_ref()
                .map_or(1, |value| value.revision.saturating_add(1)),
        )
        .map_err(|error| integrity_code(&error.to_string()))?;
        let previous_revision_digest = previous.as_ref().map(|value: &PgRenditionAt| {
            value
                .digest
                .parse::<ContentDigest>()
                .map_err(|_| integrity_code("rendition digest"))
        });
        let previous_revision_digest = match previous_revision_digest {
            Some(value) => Some(value?),
            None => None,
        };
        let content: Value = serde_json::from_str(edit.input.canonical_content.as_str())
            .map_err(|error| integrity_code(&error.to_string()))?;
        let (manifest, rendition_digest) =
            proof_canonical::object_locale_revision(&proof_canonical::ObjectLocaleRevisionInput {
                workspace_id: workspace_typed,
                object_id: edit.input.object_id,
                locale: &edit.input.locale,
                revision,
                previous_revision_digest,
                source_object_revision: edit.input.expected_source.revision,
                source_object_digest: edit.input.expected_source.digest,
                schema_id: &edit.input.expected_source.schema_id,
                schema_version: edit.input.expected_source.schema_version,
                content: &content,
                changeset_id: changeset.changeset_id,
                edit_id: edit.edit_id,
                authoritative_sequence: next_sequence,
            })
            .map_err(|error| integrity_code(&error.to_string()))?;
        let workspace_id = workspace_id_of(runtime)?;
        persist_committed_rendition(runtime, &workspace_id, &manifest, rendition_digest)?;
        renditions.push(proof_application::ObjectLocaleRevision {
            workspace_id: workspace_typed,
            object_id: edit.input.object_id,
            locale: edit.input.locale.clone(),
            revision,
            previous_revision_digest,
            source_object_revision: edit.input.expected_source.revision,
            source_object_digest: edit.input.expected_source.digest,
            schema_id: edit.input.expected_source.schema_id.clone(),
            schema_version: edit.input.expected_source.schema_version,
            canonical_content: edit.input.canonical_content.clone(),
            changeset_id: changeset.changeset_id,
            edit_id: edit.edit_id,
            authoritative_sequence: next_sequence,
            manifest_json: manifest.as_str().to_owned(),
            rendition_digest,
        });
    }
    let schemas = pg_schema_state_references(runtime, next_sequence)?;
    let objects = pg_object_state_references(runtime, next_sequence)?;
    let locale_references = pg_locale_state_references(runtime, next_sequence)?;
    let previous_reference = proof_canonical::PreviousKnownStateReference {
        api_version: previous_state.api_version.clone(),
        authoritative_sequence: previous_state.authoritative_sequence,
        digest: previous_state.digest,
    };
    let state_manifest = proof_canonical::known_state_v2_manifest(
        workspace_typed,
        next_sequence,
        &schemas,
        &objects,
        &locale_references,
        &previous_reference,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    let state_digest = digest(proof_domain::ArtifactKind::KnownStateV2, &state_manifest);
    let resulting_state = KnownStateArtifactReference {
        api_version: KNOWN_STATE_V2_API_VERSION.to_owned(),
        authoritative_sequence: next_sequence,
        digest: state_digest,
    };
    let result = CommittedLocalizedChangeSet {
        changeset_id: changeset.changeset_id,
        sealed_changeset_digest: validation
            .sealed_changeset_digest
            .ok_or_else(|| integrity_code("valid localized validation lacks seal"))?,
        validation_results_digest: validation.validation_results_digest,
        previous_state: previous_state.clone(),
        resulting_state: resulting_state.clone(),
        renditions,
        committed_at: command.committed_at,
        status: ChangeSetStatus::Committed,
    };
    let effect_digest = localized_commit_effect(request_digest, &result)?;
    let workspace_id = workspace_id_of(runtime)?;
    // Known State artifact fact.
    let artifact_body = serde_json::json!({
        "api_version": KNOWN_STATE_V2_API_VERSION,
        "authoritative_sequence": next_sequence,
        "state_digest": state_digest.to_string(),
        "manifest": serde_json::from_str::<Value>(state_manifest.as_str())
            .map_err(|error| integrity_code(&error.to_string()))?,
    });
    store_verified_fact(
        runtime,
        &workspace_id,
        &format!(
            "known_state_artifact/{}",
            format_args!("{next_sequence:020}")
        ),
        "proof:parity:known-state-artifact:v1",
        "known_state_artifact",
        &artifact_body,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    // Commit record fact.
    let commit_body = serde_json::json!({
        "api_version": "proof.dev/parity/localized-commit/v1",
        "changeset_id": changeset.changeset_id.to_string(),
        "committed_at": command.committed_at.to_string(),
        "effect_digest": effect_digest.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "renditions": result.renditions.iter().map(serialize_commit_rendition).collect::<Vec<_>>(),
        "resulting_state_digest": state_digest.to_string(),
        "resulting_state_manifest": serde_json::from_str::<Value>(state_manifest.as_str())
            .map_err(|error| integrity_code(&error.to_string()))?,
        "resulting_state_sequence": next_sequence,
        "sealed_changeset_digest": result.sealed_changeset_digest.to_string(),
        "validation_results_digest": result.validation_results_digest.to_string(),
        "previous_state_api_version": previous_state.api_version,
        "previous_state_digest": previous_state.digest.to_string(),
        "previous_state_sequence": previous_state.authoritative_sequence,
    });
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_commit/{}", changeset.changeset_id),
        FACT_KIND_LOCALIZED_COMMIT,
        &commit_body,
        "proof:parity:localized-commit:v1",
    )?;
    // Advance the write head.
    let head_body = serde_json::json!({
        "api_version": "proof.dev/parity/known-state-head/v1",
        "authoritative_sequence": next_sequence,
        "known_state_api_version": KNOWN_STATE_V2_API_VERSION,
        "state_digest": state_digest.to_string(),
    });
    upsert_parity_fact(
        runtime,
        &workspace_id,
        "known_state/head",
        "known_state_head",
        &head_body,
        "proof:parity:known-state-head:v1",
    )?;
    // Lifecycle projection.
    let prior_body = require_fact_json(
        runtime,
        &format!("localized_changeset/{}", changeset.changeset_id),
        "proof.resource.not_found",
    )?;
    let mut updated = prior_body.clone();
    updated["lifecycle_status"] = Value::String("committed".into());
    upsert_parity_fact(
        runtime,
        &workspace_id,
        &format!("localized_changeset/{}", changeset.changeset_id),
        FACT_KIND_LOCALIZED_CHANGESET,
        &updated,
        "proof:parity:localized-changeset:v1",
    )?;
    insert_parity_op_fact(
        runtime,
        &op_fact_id,
        &serde_json::json!({
            "api_version": "proof.dev/parity/changeset-commit-operation/v1",
            "principal_id": principal.to_string(),
            "idempotency_key": command.idempotency_key.to_string(),
            "changeset_id": command.changeset_id.to_string(),
            "request_digest": request_digest.to_string(),
            "effect_digest": effect_digest.to_string(),
        }),
    )?;
    Ok(result)
}

/// Rebuilds a committed ChangeSet result from its fact.
#[allow(clippy::too_many_lines)]
fn pg_load_commit(
    runtime: &mut PgRuntime,
    changeset_id: proof_application::ChangeSetId,
) -> Result<CommittedLocalizedChangeSet, String> {
    use proof_application::{ChangeSetStatus, LocaleRevision};
    let _ = runtime;
    let body = require_fact_json(
        runtime,
        &format!("localized_commit/{changeset_id}"),
        "proof.resource.not_found",
    )?;
    let previous_state = KnownStateArtifactReference {
        api_version: json_str(&body, "previous_state_api_version")?.to_owned(),
        authoritative_sequence: body
            .get("previous_state_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("previous sequence"))?,
        digest: json_str(&body, "previous_state_digest")?
            .parse()
            .map_err(|_| integrity_code("previous digest"))?,
    };
    let resulting_state = KnownStateArtifactReference {
        api_version: KNOWN_STATE_V2_API_VERSION.to_owned(),
        authoritative_sequence: body
            .get("resulting_state_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("resulting sequence"))?,
        digest: json_str(&body, "resulting_state_digest")?
            .parse()
            .map_err(|_| integrity_code("resulting digest"))?,
    };
    let renditions = body
        .get("renditions")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity_code("commit renditions"))?
        .iter()
        .map(|stored| {
            Ok(proof_application::ObjectLocaleRevision {
                workspace_id: parse_workspace(json_str(stored, "workspace_id")?)?,
                object_id: json_str(stored, "object_id")?
                    .parse()
                    .map_err(|_| integrity_code("rendition object"))?,
                locale: json_str(stored, "locale")?
                    .parse()
                    .map_err(|_| integrity_code("rendition locale"))?,
                revision: LocaleRevision::new(
                    u32::try_from(
                        stored
                            .get("revision")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("rendition revision"))?,
                    )
                    .map_err(|_| integrity_code("revision range"))?,
                )
                .map_err(|error| integrity_code(&error.to_string()))?,
                previous_revision_digest: stored
                    .get("previous_revision_digest")
                    .and_then(Value::as_str)
                    .map(str::parse)
                    .transpose()
                    .map_err(|_| integrity_code("rendition previous digest"))?,
                source_object_revision: proof_application::ObjectRevision::new(
                    u32::try_from(
                        stored
                            .get("source_object_revision")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("source revision"))?,
                    )
                    .map_err(|_| integrity_code("source revision range"))?,
                )
                .map_err(|error| integrity_code(&error.to_string()))?,
                source_object_digest: json_str(stored, "source_object_digest")?
                    .parse()
                    .map_err(|_| integrity_code("rendition source digest"))?,
                schema_id: proof_domain::SchemaId::new(json_str(stored, "schema_id")?)
                    .map_err(|error| integrity_code(&error.to_string()))?,
                schema_version: proof_domain::SchemaVersion::new(
                    u32::try_from(
                        stored
                            .get("schema_version")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("schema version"))?,
                    )
                    .map_err(|_| integrity_code("schema version range"))?,
                )
                .map_err(|error| integrity_code(&error.to_string()))?,
                canonical_content: json_str(stored, "canonical_content")?.to_owned(),
                changeset_id: json_str(stored, "changeset_id")?
                    .parse()
                    .map_err(|_| integrity_code("rendition changeset"))?,
                edit_id: json_str(stored, "edit_id")?
                    .parse()
                    .map_err(|_| integrity_code("rendition edit"))?,
                authoritative_sequence: stored
                    .get("authoritative_sequence")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| integrity_code("rendition sequence"))?,
                manifest_json: json_str(stored, "manifest_json")?.to_owned(),
                rendition_digest: json_str(stored, "rendition_digest")?
                    .parse()
                    .map_err(|_| integrity_code("rendition digest"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(CommittedLocalizedChangeSet {
        changeset_id,
        sealed_changeset_digest: json_str(&body, "sealed_changeset_digest")?
            .parse()
            .map_err(|_| integrity_code("seal digest"))?,
        validation_results_digest: json_str(&body, "validation_results_digest")?
            .parse()
            .map_err(|_| integrity_code("results digest"))?,
        previous_state,
        resulting_state,
        renditions,
        committed_at: json_str(&body, "committed_at")?
            .parse()
            .map_err(|_| integrity_code("commit timestamp"))?,
        status: ChangeSetStatus::Committed,
    })
}

/// Serializes one rendition for the commit record fact.
fn serialize_commit_rendition(rendition: &proof_application::ObjectLocaleRevision) -> Value {
    serde_json::json!({
        "authoritative_sequence": rendition.authoritative_sequence,
        "canonical_content": rendition.canonical_content,
        "changeset_id": rendition.changeset_id.to_string(),
        "edit_id": rendition.edit_id.to_string(),
        "locale": rendition.locale.as_str(),
        "manifest_json": rendition.manifest_json,
        "object_id": rendition.object_id.to_string(),
        "previous_revision_digest": rendition.previous_revision_digest.map(|value| value.to_string()),
        "rendition_digest": rendition.rendition_digest.to_string(),
        "revision": rendition.revision.get(),
        "schema_id": rendition.schema_id.as_str(),
        "schema_version": rendition.schema_version.get(),
        "source_object_digest": rendition.source_object_digest.to_string(),
        "source_object_revision": rendition.source_object_revision.get(),
        "workspace_id": rendition.workspace_id.to_string(),
    })
}

/// Persists one newly committed rendition fact.
fn persist_committed_rendition(
    runtime: &mut PgRuntime,
    workspace_id: &str,
    manifest: &proof_canonical::CanonicalJson,
    rendition_digest: ContentDigest,
) -> Result<(), String> {
    let parsed: Value =
        serde_json::from_str(manifest.as_str()).map_err(|e| integrity_code(&e.to_string()))?;
    let object_id = parsed
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("rendition identity"))?;
    let locale = parsed
        .get("locale")
        .and_then(Value::as_str)
        .ok_or_else(|| integrity_code("rendition identity"))?;
    let sequence = parsed
        .get("authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_code("rendition identity"))?;
    let revision = parsed
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_code("rendition identity"))?;
    let value: Value =
        serde_json::from_str(manifest.as_str()).map_err(|e| integrity_code(&e.to_string()))?;
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/locale-rendition/v1",
        "authoritative_sequence": sequence,
        "changeset_id": value
            .get("changeset_id")
            .cloned()
            .ok_or_else(|| integrity_code("rendition identity"))?,
        "manifest": value,
        "rendition_digest": rendition_digest.to_string(),
    });
    let canonical = canonicalize(&body).map_err(|e| integrity_code(&e.to_string()))?;
    let fact_digest = derive_key_digest("proof:parity:locale-rendition:v1", canonical.as_bytes());
    insert_fact(
        runtime,
        &format!("locale_rendition/{object_id}/{locale}/{sequence:020}/{revision:020}"),
        workspace_id,
        "locale_rendition",
        &fact_digest,
        canonical.as_bytes(),
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(())
}

/// Ports `ensure_known_state_artifact`.
fn ensure_known_state_artifact_pg(
    runtime: &mut PgRuntime,
    state: &KnownStateArtifactReference,
) -> Result<(), String> {
    if state.api_version == KNOWN_STATE_V1_API_VERSION {
        return Ok(());
    }
    let fact_id = format!(
        "known_state_artifact/{}",
        format_args!("{:020}", state.authoritative_sequence)
    );
    if fact_json(runtime, &fact_id)?.is_some() {
        return Ok(());
    }
    Err(integrity_code("Known State artifact is missing"))
}

/// Ports `schema_state_references`.
fn pg_schema_state_references(
    runtime: &mut PgRuntime,
    sequence: u64,
) -> Result<
    Vec<(
        proof_domain::SchemaId,
        proof_domain::SchemaVersion,
        ContentDigest,
    )>,
    String,
> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT fact_id, body FROM facts WHERE fact_kind = $1 ORDER BY fact_id",
            &[&"localizable_schema"],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut schemas = Vec::new();
    for row in rows {
        let body: Vec<u8> = row.get(1);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let item_sequence = value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("schema sequence"))?;
        if item_sequence > sequence {
            continue;
        }
        let document = value
            .get("document")
            .cloned()
            .ok_or_else(|| integrity_code("schema document"))?;
        let canonical = canonicalize(&document).map_err(|e| integrity_code(&e.to_string()))?;
        let digest_value: ContentDigest = json_str(&value, "document_digest")?
            .parse()
            .map_err(|_| integrity_code("schema digest"))?;
        if digest(proof_domain::ArtifactKind::SchemaVersionV1, &canonical) != digest_value {
            return Err(integrity_code("Schema state reference does not reproduce"));
        }
        schemas.push((
            proof_domain::SchemaId::new(json_str(&value, "schema_id")?)
                .map_err(|error| integrity_code(&error.to_string()))?,
            proof_domain::SchemaVersion::new(
                u32::try_from(
                    value
                        .get("schema_version")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| integrity_code("schema version"))?,
                )
                .map_err(|_| integrity_code("schema version range"))?,
            )
            .map_err(|error| integrity_code(&error.to_string()))?,
            digest_value,
        ));
    }
    Ok(schemas)
}

/// Ports `object_state_references`.
fn pg_object_state_references(
    runtime: &mut PgRuntime,
    sequence: u64,
) -> Result<Vec<proof_canonical::ObjectStateReference>, String> {
    use proof_application::ObjectLifecycleState;
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT body FROM facts WHERE fact_kind = $1 ORDER BY fact_id",
            &[&"source_object"],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut objects = Vec::new();
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let item_sequence = value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("object sequence"))?;
        if item_sequence > sequence {
            continue;
        }
        objects.push(proof_canonical::ObjectStateReference {
            object_id: json_str(&value, "object_id")?
                .parse()
                .map_err(|_| integrity_code("object identity"))?,
            revision: proof_application::ObjectRevision::INITIAL,
            schema_id: proof_domain::SchemaId::new(json_str(&value, "schema_id")?)
                .map_err(|error| integrity_code(&error.to_string()))?,
            schema_version: proof_domain::SchemaVersion::new(
                u32::try_from(
                    value
                        .get("schema_version")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| integrity_code("object schema version"))?,
                )
                .map_err(|_| integrity_code("schema version range"))?,
            )
            .map_err(|error| integrity_code(&error.to_string()))?,
            lifecycle_state: ObjectLifecycleState::Active,
            object_digest: json_str(&value, "object_digest")?
                .parse()
                .map_err(|_| integrity_code("object digest"))?,
        });
    }
    Ok(objects)
}

/// Ports `locale_state_references` over rendition facts.
fn pg_locale_state_references(
    runtime: &mut PgRuntime,
    sequence: u64,
) -> Result<Vec<proof_canonical::LocaleStateReference>, String> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT fact_id, body FROM facts WHERE fact_kind = $1 ORDER BY fact_id",
            &[&"locale_rendition"],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    let mut heads =
        std::collections::BTreeMap::<(String, String), proof_canonical::LocaleStateReference>::new(
        );
    for row in rows {
        let body: Vec<u8> = row.get(1);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let item_sequence = value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("rendition sequence"))?;
        if item_sequence > sequence {
            continue;
        }
        let manifest = value
            .get("manifest")
            .cloned()
            .ok_or_else(|| integrity_code("rendition manifest"))?;
        let key = (
            json_str(&manifest, "object_id")?.to_owned(),
            json_str(&manifest, "locale")?.to_owned(),
        );
        heads.insert(
            key,
            proof_canonical::LocaleStateReference {
                object_id: json_str(&manifest, "object_id")?
                    .parse()
                    .map_err(|_| integrity_code("rendition object"))?,
                locale: json_str(&manifest, "locale")?
                    .parse()
                    .map_err(|_| integrity_code("rendition locale"))?,
                revision: proof_application::LocaleRevision::new(
                    u32::try_from(
                        manifest
                            .get("revision")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("rendition revision"))?,
                    )
                    .map_err(|_| integrity_code("revision range"))?,
                )
                .map_err(|error| integrity_code(&error.to_string()))?,
                rendition_digest: json_str(&value, "rendition_digest")?
                    .parse()
                    .map_err(|_| integrity_code("rendition digest"))?,
                source_object_digest: json_str(&manifest, "source_object_digest")?
                    .parse()
                    .map_err(|_| integrity_code("rendition source digest"))?,
                schema_id: proof_domain::SchemaId::new(json_str(&manifest, "schema_id")?)
                    .map_err(|error| integrity_code(&error.to_string()))?,
                schema_version: proof_domain::SchemaVersion::new(
                    u32::try_from(
                        manifest
                            .get("schema_version")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| integrity_code("rendition schema version"))?,
                    )
                    .map_err(|_| integrity_code("schema version range"))?,
                )
                .map_err(|error| integrity_code(&error.to_string()))?,
            },
        );
    }
    Ok(heads.into_values().collect())
}

/// Ports `localized_commit_effect`.
fn localized_commit_effect(
    request_digest: ContentDigest,
    result: &CommittedLocalizedChangeSet,
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.commit/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": result.changeset_id.to_string(),
            "committed_at": result.committed_at.to_string(),
            "previous_state": {
                "api_version": result.previous_state.api_version,
                "authoritative_sequence": result.previous_state.authoritative_sequence,
                "digest": result.previous_state.digest.to_string(),
            },
            "renditions": result.renditions.iter().map(|rendition| serde_json::json!({
                "digest": rendition.rendition_digest.to_string(),
                "edit_id": rendition.edit_id.to_string(),
                "locale": rendition.locale.as_str(),
                "object_id": rendition.object_id.to_string(),
                "revision": rendition.revision.get(),
            })).collect::<Vec<_>>(),
            "resulting_state": {
                "api_version": result.resulting_state.api_version,
                "authoritative_sequence": result.resulting_state.authoritative_sequence,
                "digest": result.resulting_state.digest.to_string(),
            },
            "sealed_changeset_digest": result.sealed_changeset_digest.to_string(),
            "validation_results_digest": result.validation_results_digest.to_string(),
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(
        proof_domain::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

/// Persists localized Editions as verified parity facts.
fn import_localized_editions(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let mut statement = connection
        .prepare(
            "SELECT editions.edition_id, editions.principal_id, editions.authoritative_sequence,
                    editions.state_digest, editions.schema_set_digest, editions.object_set_digest,
                    editions.edition_digest, editions.manifest_json, editions.created_at,
                    editions.api_version, metadata.changeset_id,
                    metadata.base_edition_api_version, metadata.base_edition_id,
                    metadata.base_edition_digest, metadata.state_api_version
             FROM editions
             JOIN localized_edition_metadata AS metadata
               ON metadata.edition_id = editions.edition_id
             ORDER BY editions.edition_id",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (
            edition_id,
            principal_id,
            sequence,
            state_digest,
            schema_set_digest,
            object_set_digest,
            edition_digest,
            manifest_json,
            created_at,
            api_version,
            changeset_id,
            base_api_version,
            base_edition_id,
            base_digest,
            state_api_version,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        let manifest: Value = serde_json::from_str(&manifest_json)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let canonical: proof_canonical::CanonicalJson =
            canonicalize(&manifest).map_err(|error| PgError::Import(error.to_string()))?;
        let parsed_digest = ContentDigest::from_str(&edition_digest)
            .map_err(|error| PgError::Import(error.to_string()))?;
        let reproduced: ContentDigest = digest(ArtifactKind::EditionV2, &canonical);
        if reproduced != parsed_digest {
            return Err(PgError::Import(
                "Edition digest does not reproduce".to_owned(),
            ));
        }
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/localized-edition/v1",
            "authoritative_sequence": u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative sequence".to_owned()))?,
            "base_edition_api_version": base_api_version,
            "base_edition_digest": base_digest,
            "base_edition_id": base_edition_id,
            "changeset_id": changeset_id,
            "created_at": created_at,
            "edition_api_version": api_version,
            "edition_digest": edition_digest,
            "edition_id": edition_id,
            "manifest": manifest,
            "object_set_digest": object_set_digest,
            "principal_id": principal_id,
            "schema_set_digest": schema_set_digest,
            "state_api_version": state_api_version,
            "state_digest": state_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("localized_edition/{edition_id}"),
            "proof:parity:localized-edition:v1",
            FACT_KIND_LOCALIZED_EDITION,
            &body,
        )?;
    }
    Ok(())
}

/// Ports `create_localized_edition` over imported parity facts.
#[allow(clippy::too_many_lines)]
fn pg_create_edition(
    runtime: &mut PgRuntime,
    command: &CreateLocalizedEditionCommand,
) -> Result<LocalizedEdition, String> {
    use proof_application::{EditionArtifactReference, LOCALIZED_EDITION_API_VERSION};
    const INVALID: &str = "proof.input.schema_mismatch";
    let request = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation/edition.create/v2",
        "changeset_id": command.changeset_id.to_string(),
        "created_at": command.created_at.to_string(),
        "edition_id": command.edition_id.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "resulting_state_digest": command.resulting_state_digest.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let request_digest = digest(proof_domain::ArtifactKind::OperationEffectV1, &request);
    let principal = parity_principal(runtime)?;
    let op_fact_id = format!(
        "op_edition_create/{principal}/{key}",
        key = command.idempotency_key
    );
    if let Some(prior) = fact_json(runtime, &op_fact_id)? {
        let persisted_request: ContentDigest = prior
            .get("request_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op request"))?
            .parse()
            .map_err(|_| integrity_code("op request"))?;
        let edition_id = json_str(&prior, "edition_id")?
            .parse()
            .map_err(|_| integrity_code("edition identity"))?;
        let edition = pg_load_edition(runtime, edition_id)?;
        let expected_effect = localized_edition_effect(request_digest, &edition)?;
        if persisted_request != request_digest
            || edition_id != command.edition_id
            || prior.get("effect_digest").and_then(Value::as_str)
                != Some(expected_effect.to_string().as_str())
        {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        return Ok(edition);
    }
    if fact_json(
        runtime,
        &format!("localized_edition/{}", command.edition_id),
    )?
    .is_some()
    {
        return Err(integrity_code("candidate Edition identity already exists"));
    }
    let commit = pg_load_commit(runtime, command.changeset_id)?;
    if commit.resulting_state.digest != command.resulting_state_digest
        || commit.committed_at > command.created_at
    {
        return Err(INVALID.to_owned());
    }
    let head = require_fact_json(runtime, "known_state/head", "proof.state.conflict")?;
    if json_str(&head, "state_digest")? != commit.resulting_state.digest.to_string()
        || head.get("authoritative_sequence").and_then(Value::as_u64)
            != Some(commit.resulting_state.authoritative_sequence)
    {
        return Err("proof.state.conflict".to_owned());
    }
    let changeset = load_pg_localized_changeset(runtime, &command.changeset_id.to_string())?;
    let intent_manifest = require_fact_json(
        runtime,
        &format!("resource_intent/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let base_edition_value = intent_manifest
        .get("base")
        .and_then(|base| base.get("edition"))
        .cloned()
        .ok_or_else(|| integrity_code("intent base edition"))?;
    let base_edition = EditionArtifactReference {
        api_version: json_str(&base_edition_value, "api_version")?.to_owned(),
        digest: json_str(&base_edition_value, "digest")?
            .parse()
            .map_err(|_| integrity_code("base edition digest"))?,
        edition_id: json_str(&base_edition_value, "edition_id")?
            .parse()
            .map_err(|_| integrity_code("base edition identity"))?,
    };
    let schemas =
        pg_schema_state_references(runtime, commit.resulting_state.authoritative_sequence)?;
    let objects =
        pg_object_state_references(runtime, commit.resulting_state.authoritative_sequence)?;
    let renditions =
        pg_locale_state_references(runtime, commit.resulting_state.authoritative_sequence)?;
    let schema_set_digest = localized_schema_set_digest(&schemas)?;
    let object_set_digest = proof_canonical::object_set_v2_digest(&objects, &renditions)
        .map_err(|error| integrity_code(&error.to_string()))?;
    let (_, effective_leaf_digest) = proposal_digests(&changeset)?;
    let manifest_value = serde_json::json!({
        "api_version": LOCALIZED_EDITION_API_VERSION,
        "authoritative_sequence": commit.resulting_state.authoritative_sequence,
        "base_edition": edition_reference_value(&base_edition),
        "changeset": {
            "changeset_id": changeset.changeset_id.to_string(),
            "context_pack_digest": changeset.context_pack_digest.to_string(),
            "effective_leaf_digest": effective_leaf_digest.to_string(),
            "proposal_digest": changeset
                .proposal_digest
                .ok_or_else(|| integrity_code("committed ChangeSet lacks proposal"))?
                .to_string(),
            "resource_intent_digest": changeset.resource_intent_digest.to_string(),
            "sealed_changeset_digest": commit.sealed_changeset_digest.to_string(),
            "validation_results_digest": commit.validation_results_digest.to_string(),
        },
        "created_at": command.created_at.to_string(),
        "edition_id": command.edition_id.to_string(),
        "object_set_digest": object_set_digest.to_string(),
        "objects": objects.iter().map(object_reference_value).collect::<Vec<_>>(),
        "principal_id": principal.to_string(),
        "renditions": renditions.iter().map(locale_reference_value).collect::<Vec<_>>(),
        "schema_set_digest": schema_set_digest.to_string(),
        "schemas": schemas.iter().map(|(schema_id, schema_version, document_digest)| serde_json::json!({
            "document_digest": document_digest.to_string(),
            "schema_id": schema_id.as_str(),
            "schema_version": schema_version.get(),
        })).collect::<Vec<_>>(),
        "state": state_reference_value(&commit.resulting_state),
        "workspace_id": workspace_id_of(runtime)?,
    });
    let manifest =
        canonicalize(&manifest_value).map_err(|error| integrity_code(&error.to_string()))?;
    let edition_digest = digest(proof_domain::ArtifactKind::EditionV2, &manifest);
    let metadata = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/localized-edition-metadata/v1",
        "base_edition": edition_reference_value(&base_edition),
        "changeset_id": command.changeset_id.to_string(),
        "edition_id": command.edition_id.to_string(),
        "state": state_reference_value(&commit.resulting_state),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let edition = LocalizedEdition {
        edition_id: command.edition_id,
        workspace_id: parse_workspace(&workspace_id_of(runtime)?)?,
        principal_id: principal,
        changeset_id: command.changeset_id,
        base_edition,
        state: commit.resulting_state.clone(),
        schema_set_digest,
        object_set_digest,
        manifest_json: manifest.as_str().to_owned(),
        edition_digest,
        created_at: command.created_at,
    };
    let effect_digest = localized_edition_effect(request_digest, &edition)?;
    let workspace_id = workspace_id_of(runtime)?;
    let body = serde_json::json!({
        "api_version": "proof.dev/parity/localized-edition/v1",
        "authoritative_sequence": commit.resulting_state.authoritative_sequence,
        "base_edition_api_version": edition.base_edition.api_version,
        "base_edition_digest": edition.base_edition.digest.to_string(),
        "base_edition_id": edition.base_edition.edition_id.to_string(),
        "changeset_id": command.changeset_id.to_string(),
        "created_at": command.created_at.to_string(),
        "edition_api_version": LOCALIZED_EDITION_API_VERSION,
        "edition_digest": edition_digest.to_string(),
        "edition_id": command.edition_id.to_string(),
        "manifest": manifest_value,
        "object_set_digest": object_set_digest.to_string(),
        "principal_id": principal.to_string(),
        "schema_set_digest": schema_set_digest.to_string(),
        "state_api_version": commit.resulting_state.api_version,
        "state_digest": commit.resulting_state.digest.to_string(),
    });
    store_verified_fact(
        runtime,
        &workspace_id,
        &format!("localized_edition/{}", command.edition_id),
        "proof:parity:localized-edition:v1",
        FACT_KIND_LOCALIZED_EDITION,
        &body,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    insert_parity_op_fact(
        runtime,
        &op_fact_id,
        &serde_json::json!({
            "api_version": "proof.dev/parity/edition-create-operation/v1",
            "principal_id": principal.to_string(),
            "idempotency_key": command.idempotency_key.to_string(),
            "edition_id": command.edition_id.to_string(),
            "request_digest": request_digest.to_string(),
            "effect_digest": effect_digest.to_string(),
        }),
    )?;
    Ok(edition)
}

/// Rebuilds an Edition from its wrapper fact.
fn pg_load_edition(
    runtime: &mut PgRuntime,
    edition_id: proof_application::EditionId,
) -> Result<LocalizedEdition, String> {
    use proof_application::{EditionArtifactReference, KnownStateArtifactReference};
    let body = require_fact_json(
        runtime,
        &format!("localized_edition/{edition_id}"),
        "proof.resource.not_found",
    )?;
    let manifest_value = body
        .get("manifest")
        .cloned()
        .ok_or_else(|| integrity_code("edition manifest"))?;
    let manifest =
        canonicalize(&manifest_value).map_err(|error| integrity_code(&error.to_string()))?;
    Ok(LocalizedEdition {
        edition_id: json_str(&body, "edition_id")?
            .parse()
            .map_err(|_| integrity_code("edition identity"))?,
        workspace_id: parse_workspace(&workspace_id_of(runtime)?)?,
        principal_id: json_str(&body, "principal_id")?
            .parse()
            .map_err(|_| integrity_code("principal identity"))?,
        changeset_id: json_str(&body, "changeset_id")?
            .parse()
            .map_err(|_| integrity_code("changeset identity"))?,
        base_edition: EditionArtifactReference {
            api_version: json_str(&body, "base_edition_api_version")?.to_owned(),
            digest: json_str(&body, "base_edition_digest")?
                .parse()
                .map_err(|_| integrity_code("base edition digest"))?,
            edition_id: json_str(&body, "base_edition_id")?
                .parse()
                .map_err(|_| integrity_code("base edition identity"))?,
        },
        state: KnownStateArtifactReference {
            api_version: json_str(&body, "state_api_version")?.to_owned(),
            authoritative_sequence: body
                .get("authoritative_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("edition sequence"))?,
            digest: json_str(&body, "state_digest")?
                .parse()
                .map_err(|_| integrity_code("state digest"))?,
        },
        schema_set_digest: json_str(&body, "schema_set_digest")?
            .parse()
            .map_err(|_| integrity_code("schema set digest"))?,
        object_set_digest: body
            .get("object_set_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("object set digest"))?
            .parse()
            .map_err(|_| integrity_code("object set digest"))?,
        manifest_json: manifest.as_str().to_owned(),
        edition_digest: json_str(&body, "edition_digest")?
            .parse()
            .map_err(|_| integrity_code("edition digest"))?,
        created_at: json_str(&body, "created_at")?
            .parse()
            .map_err(|_| integrity_code("edition timestamp"))?,
    })
}

/// Ports `localized_schema_set_digest`.
fn localized_schema_set_digest(
    schemas: &[(
        proof_domain::SchemaId,
        proof_domain::SchemaVersion,
        ContentDigest,
    )],
) -> Result<ContentDigest, String> {
    let manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": schemas.iter().map(|(schema_id, schema_version, document_digest)| serde_json::json!({
            "document_digest": document_digest.to_string(),
            "schema_id": schema_id.as_str(),
            "schema_version": schema_version.get(),
        })).collect::<Vec<_>>(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(proof_domain::ArtifactKind::SchemaSetV1, &manifest))
}

/// Ports `edition_reference_value`.
fn edition_reference_value(reference: &proof_application::EditionArtifactReference) -> Value {
    serde_json::json!({
        "api_version": reference.api_version,
        "digest": reference.digest.to_string(),
        "edition_id": reference.edition_id.to_string(),
    })
}

/// Ports `state_reference_value`.
fn state_reference_value(state: &KnownStateArtifactReference) -> Value {
    serde_json::json!({
        "api_version": state.api_version,
        "authoritative_sequence": state.authoritative_sequence,
        "digest": state.digest.to_string(),
    })
}

/// Ports `object_reference_value`.
fn object_reference_value(reference: &proof_canonical::ObjectStateReference) -> Value {
    serde_json::json!({
        "lifecycle_state": reference.lifecycle_state.to_string(),
        "object_digest": reference.object_digest.to_string(),
        "object_id": reference.object_id.to_string(),
        "revision": reference.revision.get(),
        "schema_id": reference.schema_id.as_str(),
        "schema_version": reference.schema_version.get(),
    })
}

/// Ports `locale_reference_value`.
fn locale_reference_value(reference: &proof_canonical::LocaleStateReference) -> Value {
    serde_json::json!({
        "locale": reference.locale.as_str(),
        "object_id": reference.object_id.to_string(),
        "rendition_digest": reference.rendition_digest.to_string(),
        "revision": reference.revision.get(),
        "schema_id": reference.schema_id.as_str(),
        "schema_version": reference.schema_version.get(),
        "source_object_digest": reference.source_object_digest.to_string(),
    })
}

/// Ports `localized_edition_effect`.
fn localized_edition_effect(
    request_digest: ContentDigest,
    edition: &LocalizedEdition,
) -> Result<ContentDigest, String> {
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "edition.create/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": edition.changeset_id.to_string(),
            "edition_digest": edition.edition_digest.to_string(),
            "edition_id": edition.edition_id.to_string(),
            "state": state_reference_value(&edition.state),
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(digest(
        proof_domain::ArtifactKind::OperationEffectV1,
        &effect,
    ))
}

/// Persists Known State artifacts as parity facts for projection rebuilds.
fn import_known_state_artifacts(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master WHERE type='table'
                 AND name='known_state_artifacts'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    if !exists {
        return Ok(());
    }
    let mut statement = connection
        .prepare(
            "SELECT api_version, authoritative_sequence, state_digest
             FROM known_state_artifacts ORDER BY authoritative_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    for row in rows {
        let (api_version, sequence, state_digest) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/known-state-artifact/v1",
            "artifact_api_version": api_version,
            "authoritative_sequence": u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative sequence".to_owned()))?,
            "state_digest": state_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!(
                "known_state_artifact/{}",
                format_args!("{:020}", u64::try_from(sequence).unwrap_or(u64::MAX))
            ),
            "proof:parity:known-state-artifact:v1",
            "known_state_artifact",
            &body,
        )?;
    }
    Ok(())
}

/// Builds serialized rendition records for one committed ChangeSet.
fn commit_rendition_values(
    connection: &rusqlite::Connection,
    changeset_id: &str,
) -> Result<Vec<Value>, PgError> {
    let mut statement = connection
        .prepare(
            "SELECT workspace_id, object_id, locale, revision, previous_revision_digest,
                    source_object_revision, source_object_digest, schema_id, schema_version,
                    content_json, edit_id, authoritative_sequence, manifest_json,
                    rendition_digest
             FROM object_locale_revisions WHERE changeset_id = ?1
             ORDER BY authoritative_sequence",
        )
        .map_err(|error| PgError::Import(error.to_string()))?;
    let rows = statement
        .query_map([changeset_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
            ))
        })
        .map_err(|error| PgError::Import(error.to_string()))?;
    let mut values = Vec::new();
    for row in rows {
        let (
            workspace_id,
            object_id,
            locale,
            revision,
            previous_revision_digest,
            source_object_revision,
            source_object_digest,
            schema_id,
            schema_version,
            content_json,
            edit_id,
            sequence,
            manifest_json,
            rendition_digest,
        ) = row.map_err(|error| PgError::Import(error.to_string()))?;
        values.push(serde_json::json!({
            "authoritative_sequence": u64::try_from(sequence)
                .map_err(|_| PgError::Import("negative sequence".to_owned()))?,
            "canonical_content": content_json,
            "changeset_id": changeset_id,
            "edit_id": edit_id,
            "locale": locale,
            "manifest_json": manifest_json,
            "object_id": object_id,
            "previous_revision_digest": previous_revision_digest,
            "rendition_digest": rendition_digest,
            "revision": u32::try_from(revision)
                .map_err(|_| PgError::Import("revision overflow".to_owned()))?,
            "schema_id": schema_id,
            "schema_version": u32::try_from(schema_version)
                .map_err(|_| PgError::Import("schema version overflow".to_owned()))?,
            "source_object_digest": source_object_digest,
            "source_object_revision": u32::try_from(source_object_revision)
                .map_err(|_| PgError::Import("source revision overflow".to_owned()))?,
            "workspace_id": workspace_id,
        }));
    }
    Ok(values)
}

/// Ports `changeset_diff` over parity facts.
fn pg_diff_changeset(
    runtime: &mut PgRuntime,
    changeset_id: proof_application::ChangeSetId,
) -> Result<LocalizedChangeSetDiff, String> {
    let _ = runtime;
    let changeset = load_pg_localized_changeset(runtime, &changeset_id.to_string())?;
    let (proposal_digest, effective_leaf_digest, effective_edits) = pg_proposal(&changeset)?;
    if effective_edits.is_empty() {
        return Err("proof.evidence.incomplete".to_owned());
    }
    Ok(LocalizedChangeSetDiff {
        changeset_id: changeset.changeset_id,
        proposal_digest,
        effective_leaf_digest,
        effective_edits,
    })
}

/// Ports `query_released_renditions` over parity facts.
#[allow(clippy::too_many_lines)]
fn pg_query_released(
    runtime: &mut PgRuntime,
    command: &QueryReleasedRenditionsCommand,
) -> Result<ReleasedRenditionQuery, String> {
    use proof_application::{
        LOCALIZED_EDITION_API_VERSION, LOCALIZED_RELEASE_API_VERSION, LocaleRevision,
        MAX_LOCALIZED_TARGETS,
    };
    const INVALID: &str = "proof.input.schema_mismatch";
    if command.targets.is_empty()
        || command.targets.len() > MAX_LOCALIZED_TARGETS
        || !command.targets.is_sorted()
        || command.targets.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(INVALID.to_owned());
    }
    let pointer = require_fact_json(
        runtime,
        &format!("environment_current/{}", command.environment_id),
        "proof.resource.not_found",
    )?;
    let release_id = json_str(&pointer, "release_id")?
        .parse()
        .map_err(|_| integrity_code("release identity"))?;
    let release_meta = require_fact_json(
        runtime,
        &format!("release_meta/{release_id}"),
        "proof.resource.not_found",
    )?;
    if json_str(&release_meta, "release_api_version")? != LOCALIZED_RELEASE_API_VERSION {
        return Err("proof.resource.not_found".to_owned());
    }
    let released_at: Timestamp = json_str(&release_meta, "released_at")?
        .parse()
        .map_err(|_| integrity_code("release timestamp"))?;
    if command.evaluated_at < released_at {
        return Err(INVALID.to_owned());
    }
    let edition_ref = proof_application::EditionArtifactReference {
        api_version: LOCALIZED_EDITION_API_VERSION.to_owned(),
        digest: json_str(&release_meta, "edition_digest")?
            .parse()
            .map_err(|_| integrity_code("edition digest"))?,
        edition_id: json_str(&release_meta, "edition_id")?
            .parse()
            .map_err(|_| integrity_code("edition identity"))?,
    };
    let edition = pg_load_edition(runtime, edition_ref.edition_id)?;
    let mut renditions = Vec::with_capacity(command.targets.len());
    for target in &command.targets {
        let selected = pg_rendition_at(
            runtime,
            &target.object_id.to_string(),
            &target.locale.to_string(),
            edition.state.authoritative_sequence,
        )?
        .ok_or_else(|| "proof.resource.not_found".to_owned())?;
        let revision = LocaleRevision::new(selected.revision)
            .map_err(|error| integrity_code(&error.to_string()))?;
        let fact = require_fact_json(
            runtime,
            &format!(
                "locale_rendition/{}/{}/{}",
                target.object_id,
                target.locale,
                format_args!("{:020}", edition.state.authoritative_sequence)
            ),
            "proof.resource.not_found",
        )?;
        let manifest = fact
            .get("manifest")
            .cloned()
            .ok_or_else(|| integrity_code("rendition manifest"))?;
        renditions.push(proof_application::ReleasedRendition {
            object_id: target.object_id,
            locale: target.locale.clone(),
            source_revision: proof_application::ObjectRevision::new(
                u32::try_from(
                    manifest
                        .get("source_object_revision")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| integrity_code("rendition source revision"))?,
                )
                .map_err(|_| integrity_code("revision range"))?,
            )
            .map_err(|error| integrity_code(&error.to_string()))?,
            source_digest: json_str(&manifest, "source_object_digest")?
                .parse()
                .map_err(|_| integrity_code("rendition source digest"))?,
            rendition_revision: revision,
            rendition_digest: json_str(&fact, "rendition_digest")?
                .parse()
                .map_err(|_| integrity_code("rendition digest"))?,
            schema_id: proof_domain::SchemaId::new(json_str(&manifest, "schema_id")?)
                .map_err(|error| integrity_code(&error.to_string()))?,
            schema_version: proof_domain::SchemaVersion::new(
                u32::try_from(
                    manifest
                        .get("schema_version")
                        .and_then(Value::as_u64)
                        .ok_or_else(|| integrity_code("rendition schema version"))?,
                )
                .map_err(|_| integrity_code("schema version range"))?,
            )
            .map_err(|error| integrity_code(&error.to_string()))?,
            canonical_content: serde_json::to_string(
                manifest
                    .get("content")
                    .ok_or_else(|| integrity_code("rendition content"))?,
            )
            .map_err(|error| integrity_code(&error.to_string()))?,
        });
    }
    Ok(ReleasedRenditionQuery {
        workspace_id: parse_workspace(&workspace_id_of(runtime)?)?,
        environment_id: command.environment_id.clone(),
        release_id,
        edition: edition_ref,
        renditions,
    })
}

/// Ports `build_context` over parity facts.
#[allow(clippy::too_many_lines)]
fn pg_build_context(
    runtime: &mut PgRuntime,
    command: &BuildLocalizedContextCommand,
) -> Result<LocalizedContextPack, String> {
    use proof_application::{LOCALIZED_CONTENT_VALIDATOR, LOCALIZED_CONTEXT_API_VERSION};
    const INVALID: &str = "proof.input.schema_mismatch";
    const LIMIT_EXCEEDED: &str = "proof.input.limit_exceeded";
    let principal = parity_principal(runtime)?;
    // Keyed replay: recompute the request digest under normalized inputs.
    let mut normalized_rules = command.policy_rules.clone();
    for rule in &mut normalized_rules {
        parse_pointer(&rule.pointer)?;
        rule.disallowed_values.sort();
    }
    for rule in &normalized_rules {
        if rule.disallowed_values.is_empty()
            || rule
                .disallowed_values
                .windows(2)
                .any(|pair| pair[0] == pair[1])
        {
            return Err(INVALID.to_owned());
        }
    }
    let request_digest = |policy_digest: ContentDigest| -> Result<ContentDigest, String> {
        let request = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/operation/context.build/v2",
            "context_pack_id": command.context_pack_id.to_string(),
            "created_at": command.created_at.to_string(),
            "expires_at": command.expires_at.to_string(),
            "idempotency_key": command.idempotency_key.to_string(),
            "limits": {
                "max_bytes": command.limits.max_bytes,
                "max_edits": command.limits.max_edits,
                "max_objects": command.limits.max_objects,
                "max_validation_attempts": command.limits.max_validation_attempts,
            },
            "policy_digest": policy_digest.to_string(),
            "resource_intent_digest": command.resource_intent_digest.to_string(),
            "resource_intent_id": command.resource_intent_id.to_string(),
        }))
        .map_err(|error| integrity_code(&error.to_string()))?;
        Ok(digest(
            proof_domain::ArtifactKind::OperationEffectV1,
            &request,
        ))
    };
    let op_fact_id = format!(
        "op_context_build/{principal}/{key}",
        key = command.idempotency_key
    );
    if let Some(prior) = fact_json(runtime, &op_fact_id)? {
        let stored_request: ContentDigest = prior
            .get("request_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("op request"))?
            .parse()
            .map_err(|_| integrity_code("op request"))?;
        let pack_id = json_str(&prior, "context_pack_id")?
            .parse()
            .map_err(|_| integrity_code("pack identity"))?;
        let pack = pg_load_context(runtime, pack_id)?;
        let policy = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/localized-content-policy/v1",
            "rules": normalized_rules.iter().map(|rule| serde_json::json!({
                "disallowed_values": rule.disallowed_values,
                "locale": rule.locale.as_str(),
                "pointer": rule.pointer,
            })).collect::<Vec<_>>(),
        }))
        .map_err(|error| integrity_code(&error.to_string()))?;
        let replay_policy_digest = digest(proof_domain::ArtifactKind::PolicyBundleV1, &policy);
        if stored_request != request_digest(replay_policy_digest)?
            || pack_id != command.context_pack_id
        {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        return Ok(pack);
    }
    if command.expires_at <= command.created_at {
        return Err(INVALID.to_owned());
    }
    let policy = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/localized-content-policy/v1",
        "rules": normalized_rules.iter().map(|rule| serde_json::json!({
            "disallowed_values": rule.disallowed_values,
            "locale": rule.locale.as_str(),
            "pointer": rule.pointer,
        })).collect::<Vec<_>>(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let policy_digest = digest(proof_domain::ArtifactKind::PolicyBundleV1, &policy);
    let request_digest = request_digest(policy_digest)?;
    let intent_manifest = require_fact_json(
        runtime,
        &format!("resource_intent/{}", command.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let intent_meta = require_fact_json(
        runtime,
        &format!("resource_intent_meta/{}", command.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let stored_intent_digest: ContentDigest = json_str(&intent_meta, "intent_digest")?
        .parse()
        .map_err(|_| integrity_code("intent digest"))?;
    if stored_intent_digest != command.resource_intent_digest {
        return Err(INVALID.to_owned());
    }
    let targets = intent_manifest
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity_code("intent targets"))?
        .iter()
        .map(|target| {
            Ok((
                json_str(target, "object_id")?.to_owned(),
                json_str(target, "schema_id")?.to_owned(),
                json_str(target, "locale")?.to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    {
        use std::collections::BTreeSet;
        let object_count = u32::try_from(
            targets
                .iter()
                .map(|(id, _, _)| id)
                .collect::<BTreeSet<_>>()
                .len(),
        )
        .map_err(|_| LIMIT_EXCEEDED.to_owned())?;
        let target_count = u32::try_from(targets.len()).map_err(|_| LIMIT_EXCEEDED.to_owned())?;
        if command.limits.max_objects < object_count
            || command.limits.max_objects == 0
            || command.limits.max_objects
                > u32::try_from(proof_application::MAX_LOCALIZED_TARGETS).unwrap_or(u32::MAX)
            || command.limits.max_edits < target_count
            || command.limits.max_edits > proof_application::MAX_LOCALIZED_EDITS
            || command.limits.max_validation_attempts == 0
            || command.limits.max_validation_attempts
                > proof_application::MAX_LOCALIZED_VALIDATION_ATTEMPTS
            || command.limits.max_bytes == 0
            || command.limits.max_bytes > proof_application::MAX_LOCALIZED_CONTEXT_BYTES
        {
            return Err(LIMIT_EXCEEDED.to_owned());
        }
    }
    let environment_id = json_str(&intent_manifest, "environment_id")?;
    let current_baseline = pg_current_baseline(runtime, environment_id)?;
    let base_state_value = intent_manifest
        .get("base")
        .and_then(|base| base.get("known_state"))
        .cloned()
        .ok_or_else(|| integrity_code("intent base state"))?;
    if current_baseline.known_state.authoritative_sequence
        != base_state_value
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .unwrap_or_default()
        || current_baseline.known_state.digest.to_string() != json_str(&base_state_value, "digest")?
    {
        return Err("proof.state.conflict".to_owned());
    }
    if fact_json(
        runtime,
        &format!("context_pack/{}", command.context_pack_id),
    )?
    .is_some()
    {
        return Err(integrity_code(
            "candidate localized ContextPack identity already exists",
        ));
    }
    let base_sequence = current_baseline.known_state.authoritative_sequence;
    let mut resources = Vec::with_capacity(targets.len());
    for (object_id, schema_id_text, locale_text) in &targets {
        let source = require_fact_json(
            runtime,
            &format!("source_object/{object_id}"),
            "proof.resource.not_found",
        )?;
        if json_str(&source, "schema_id")? != schema_id_text {
            return Err(INVALID.to_owned());
        }
        let schema_version = source
            .get("schema_version")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("source schema version"))?;
        let schema = require_fact_json(
            runtime,
            &format!("localizable_schema/{schema_id_text}/{schema_version}"),
            INVALID,
        )?;
        let document = schema
            .get("document")
            .cloned()
            .ok_or_else(|| integrity_code("schema document"))?;
        let pointers: Vec<String> = document
            .get("x-proof-localizable")
            .and_then(Value::as_array)
            .ok_or_else(|| INVALID.to_owned())?
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        for rule in normalized_rules
            .iter()
            .filter(|rule| rule.locale.as_str() == locale_text.as_str())
        {
            if !pointers.contains(&rule.pointer) {
                return Err(INVALID.to_owned());
            }
        }
        let target_value = match pg_rendition_at(runtime, object_id, locale_text, base_sequence)? {
            None => serde_json::json!({
                "absent": true,
                "api_version": "proof.dev/object-locale-absence/v1",
                "authoritative_sequence": base_sequence,
            }),
            Some(state) => serde_json::json!({
                "absent": false,
                "api_version": "proof.dev/object-locale-revision/v1",
                "digest": state.digest,
                "manifest": pg_rendition_manifest(
                    runtime,
                    object_id,
                    locale_text,
                    state.revision,
                )?,
                "revision": state.revision,
            }),
        };
        let content: Value = serde_json::from_str(
            source
                .get("canonical_content")
                .and_then(Value::as_str)
                .ok_or_else(|| integrity_code("source content"))?,
        )
        .map_err(|error| integrity_code(&error.to_string()))?;
        resources.push(serde_json::json!({
            "locale": locale_text,
            "object_id": object_id,
            "schema": {
                "document": document,
                "document_digest": json_str(&schema, "document_digest")?,
                "localizable_pointers": pointers,
                "schema_id": schema_id_text,
                "schema_version": schema_version,
            },
            "source": {
                "api_version": "proof.dev/object-revision/v1",
                "content": content,
                "digest": json_str(&source, "object_digest")?,
                "revision": 1,
            },
            "target": target_value,
        }));
    }
    for rule in &normalized_rules {
        if !targets
            .iter()
            .any(|(_, _, locale)| locale == rule.locale.as_str())
        {
            return Err(INVALID.to_owned());
        }
    }
    let manifest_value = serde_json::json!({
        "allowed_operations": [
            "proof.dev/operation/changeset.create/v2",
            "proof.dev/operation/changeset.add/v2",
            "proof.dev/operation/changeset.get/v2",
            "proof.dev/operation/changeset.diff/v2",
            "proof.dev/operation/changeset.validate/v2",
            "proof.dev/operation/changeset.submit/v2",
            "proof.dev/operation/changeset.commit/v2",
            "proof.dev/operation/edition.create/v2",
            "proof.dev/operation/release.create/v2",
            "proof.dev/operation/object.query_released/v2"
        ],
        "api_version": LOCALIZED_CONTEXT_API_VERSION,
        "context_pack_id": command.context_pack_id.to_string(),
        "created_at": command.created_at.to_string(),
        "explicit_exclusions": [
            "agent-authority",
            "campaign-expansion",
            "deletion",
            "fallback",
            "generic-object-replacement",
            "relationship-mutation",
            "schema-mutation"
        ],
        "expires_at": command.expires_at.to_string(),
        "limits": {
            "max_bytes": command.limits.max_bytes,
            "max_edits": command.limits.max_edits,
            "max_objects": command.limits.max_objects,
            "max_validation_attempts": command.limits.max_validation_attempts,
        },
        "policy": serde_json::from_str::<Value>(policy.as_str())
            .map_err(|e| integrity_code(&e.to_string()))?,
        "policy_digest": policy_digest.to_string(),
        "principal_id": principal.to_string(),
        "resource_intent": intent_manifest,
        "resource_intent_digest": command.resource_intent_digest.to_string(),
        "resources": resources,
        "target_ordering": "object_id,schema_id,locale:utf8-ascending",
        "validator": LOCALIZED_CONTENT_VALIDATOR,
        "workspace_id": workspace_id_of(runtime)?,
    });
    let manifest =
        canonicalize(&manifest_value).map_err(|error| integrity_code(&error.to_string()))?;
    if u64::try_from(manifest.as_bytes().len()).unwrap_or(u64::MAX) > command.limits.max_bytes {
        return Err(LIMIT_EXCEEDED.to_owned());
    }
    let context_pack_digest = digest(proof_domain::ArtifactKind::ContextPackV2, &manifest);
    let workspace_id = workspace_id_of(runtime)?;
    store_verified_fact(
        runtime,
        &workspace_id,
        &format!("context_pack/{}", command.context_pack_id),
        "proof:parity:context-pack:v1",
        FACT_KIND_CONTEXT_PACK,
        &manifest_value,
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    let effect = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "context.build/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "context_pack_digest": context_pack_digest.to_string(),
            "context_pack_id": command.context_pack_id.to_string(),
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let effect_digest = digest(proof_domain::ArtifactKind::OperationEffectV1, &effect);
    insert_parity_op_fact(
        runtime,
        &op_fact_id,
        &serde_json::json!({
            "api_version": "proof.dev/parity/context-build-operation/v1",
            "principal_id": principal.to_string(),
            "idempotency_key": command.idempotency_key.to_string(),
            "context_pack_id": command.context_pack_id.to_string(),
            "request_digest": request_digest.to_string(),
            "effect_digest": effect_digest.to_string(),
        }),
    )?;
    pg_load_context(runtime, command.context_pack_id)
}

/// Reads one rendition manifest by exact revision.
fn pg_rendition_manifest(
    runtime: &mut PgRuntime,
    object_id: &str,
    locale: &str,
    revision: u32,
) -> Result<Value, String> {
    let rows = {
        let client = runtime.client_mut();
        client.query(
            "SELECT body FROM facts WHERE fact_kind = $1 AND fact_id LIKE $2",
            &[
                &"locale_rendition",
                &format!("locale_rendition/{object_id}/{locale}/%"),
            ],
        )
    }
    .map_err(|error| integrity_code(&error.to_string()))?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value: Value =
            serde_json::from_slice(&body).map_err(|error| integrity_code(&error.to_string()))?;
        let manifest = value
            .get("manifest")
            .cloned()
            .ok_or_else(|| integrity_code("rendition manifest"))?;
        if manifest.get("revision").and_then(Value::as_u64) == Some(u64::from(revision)) {
            return Ok(manifest);
        }
    }
    Err(integrity_code("rendition fact is absent"))
}

/// Rebuilds a ContextPack from its wrapper fact.
#[allow(clippy::too_many_lines)]
fn pg_load_context(
    runtime: &mut PgRuntime,
    context_pack_id: proof_application::ContextPackId,
) -> Result<LocalizedContextPack, String> {
    use proof_application::{LocalizedContentBaseline, LocalizedContextLimits};
    let _ = runtime;
    let body = require_fact_json(
        runtime,
        &format!("context_pack/{context_pack_id}"),
        "proof.resource.not_found",
    )?;
    let manifest_json = canonicalize(&body)
        .map_err(|error| integrity_code(&error.to_string()))?
        .as_str()
        .to_owned();
    let base_value = body
        .get("resource_intent")
        .and_then(|intent| intent.get("base"))
        .cloned()
        .ok_or_else(|| integrity_code("pack base"))?;
    let limits_value = body
        .get("limits")
        .cloned()
        .ok_or_else(|| integrity_code("pack limits"))?;
    let release_value = base_value
        .get("release")
        .cloned()
        .ok_or_else(|| integrity_code("pack base release"))?;
    let edition_value = base_value
        .get("edition")
        .cloned()
        .ok_or_else(|| integrity_code("pack base edition"))?;
    let known_state_value = base_value
        .get("known_state")
        .cloned()
        .ok_or_else(|| integrity_code("pack base state"))?;
    Ok(LocalizedContextPack {
        context_pack_id: json_str(&body, "context_pack_id")?
            .parse()
            .map_err(|_| integrity_code("pack identity"))?,
        workspace_id: parse_workspace(json_str(&body, "workspace_id")?)?,
        principal_id: json_str(&body, "principal_id")?
            .parse()
            .map_err(|_| integrity_code("pack principal"))?,
        resource_intent_id: body
            .get("resource_intent")
            .and_then(|intent| intent.get("intent_id"))
            .and_then(Value::as_str)
            .ok_or_else(|| integrity_code("pack intent reference"))?
            .parse()
            .map_err(|_| integrity_code("pack intent identity"))?,
        resource_intent_digest: json_str(&body, "resource_intent_digest")?
            .parse()
            .map_err(|_| integrity_code("pack intent digest"))?,
        base: LocalizedContentBaseline {
            release: proof_application::ReleaseArtifactReference {
                api_version: json_str(&release_value, "api_version")?.to_owned(),
                digest: json_str(&release_value, "digest")?
                    .parse()
                    .map_err(|_| integrity_code("pack release digest"))?,
                release_id: json_str(&release_value, "release_id")?
                    .parse()
                    .map_err(|_| integrity_code("pack release identity"))?,
            },
            edition: proof_application::EditionArtifactReference {
                api_version: json_str(&edition_value, "api_version")?.to_owned(),
                digest: json_str(&edition_value, "digest")?
                    .parse()
                    .map_err(|_| integrity_code("pack edition digest"))?,
                edition_id: json_str(&edition_value, "edition_id")?
                    .parse()
                    .map_err(|_| integrity_code("pack edition identity"))?,
            },
            known_state: KnownStateArtifactReference {
                api_version: json_str(&known_state_value, "api_version")?.to_owned(),
                authoritative_sequence: known_state_value
                    .get("authoritative_sequence")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| integrity_code("pack sequence"))?,
                digest: json_str(&known_state_value, "digest")?
                    .parse()
                    .map_err(|_| integrity_code("pack state digest"))?,
            },
        },
        policy_digest: json_str(&body, "policy_digest")?
            .parse()
            .map_err(|_| integrity_code("policy digest"))?,
        limits: LocalizedContextLimits {
            max_objects: u32::try_from(
                limits_value
                    .get("max_objects")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0),
            max_edits: u32::try_from(
                limits_value
                    .get("max_edits")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0),
            max_validation_attempts: u32::try_from(
                limits_value
                    .get("max_validation_attempts")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .unwrap_or(0),
            max_bytes: limits_value
                .get("max_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        },
        created_at: json_str(&body, "created_at")?
            .parse()
            .map_err(|_| integrity_code("pack timestamp"))?,
        expires_at: json_str(&body, "expires_at")?
            .parse()
            .map_err(|_| integrity_code("pack expiry"))?,
        // The pack manifest excludes its own digest; recompute it from the
        // imported canonical bytes.
        context_pack_digest: digest(
            proof_domain::ArtifactKind::ContextPackV2,
            &canonicalize(&body).map_err(|error| integrity_code(&error.to_string()))?,
        ),
        manifest_json,
    })
}

/// Persists ContextPack build operations as idempotent operation facts.
fn import_context_build_operations(
    runtime: &mut PgRuntime,
    connection: &rusqlite::Connection,
    workspace_id: &str,
) -> Result<(), PgError> {
    let principal = {
        let metadata: String = connection
            .query_row(
                "SELECT bootstrap_principal_id FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| PgError::Import(error.to_string()))?
            .ok_or_else(|| PgError::Import("workspace principal is absent".to_owned()))?;
        metadata
    };
    let mut statement = connection
        .prepare(
            "SELECT idempotency_key, request_digest, effect_digest, context_pack_id
             FROM localized_context_build_operations ORDER BY context_pack_id",
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
        let (idempotency_key, request_digest, effect_digest, context_pack_id) =
            row.map_err(|error| PgError::Import(error.to_string()))?;
        let body = serde_json::json!({
            "api_version": "proof.dev/parity/context-build-operation/v1",
            "context_pack_id": context_pack_id,
            "effect_digest": effect_digest,
            "idempotency_key": idempotency_key,
            "principal_id": principal,
            "request_digest": request_digest,
        });
        store_verified_fact(
            runtime,
            workspace_id,
            &format!("op_context_build/{principal}/{idempotency_key}"),
            "proof:parity:context-build-operation:v1",
            FACT_KIND_CONTEXT_BUILD_OPERATION,
            &body,
        )?;
    }
    Ok(())
}
// ---------------------------------------------------------------------------
// P-0015 slice 12: the release.create/v2 executor over imported facts.
// ---------------------------------------------------------------------------

/// One versioned Edition projection rebuilt from parity facts, mirroring the
/// reference `VersionedEditionView` shape.
struct PgVersionedEditionView {
    reference: proof_application::EditionArtifactReference,
    state: KnownStateArtifactReference,
    schemas: Vec<(
        proof_domain::SchemaId,
        proof_domain::SchemaVersion,
        ContentDigest,
    )>,
    objects: Vec<proof_canonical::ObjectStateReference>,
    renditions: Vec<proof_canonical::LocaleStateReference>,
    created_at: Timestamp,
}

/// The exact base-Release selection used by the promotion preflight.
struct PgReleaseSelection {
    reference: proof_application::ReleaseArtifactReference,
    environment_id: proof_application::EnvironmentId,
    edition: proof_application::EditionArtifactReference,
    release_sequence: u64,
    released_at: Timestamp,
}

/// The Environment configuration fields the release flow reads.
struct PgEnvironment {
    config_version: u32,
    config_digest: ContentDigest,
    policy_profile: String,
    required_approval: String,
    created_at: Timestamp,
}

/// The exact Edition delta compared and signed at Release time.
struct PgExactEditionDelta {
    canonical: String,
    digest: ContentDigest,
    schema_changed: bool,
    object_changed: bool,
    rendition_changes: Vec<PgRenditionChange>,
}

/// One before/after rendition comparison in the exact Edition delta.
type PgRenditionChange = (
    (proof_application::ObjectId, LocaleId),
    Option<proof_canonical::LocaleStateReference>,
    Option<proof_canonical::LocaleStateReference>,
);

fn pg_release_reference_value(reference: &proof_application::ReleaseArtifactReference) -> Value {
    serde_json::json!({
        "api_version": reference.api_version,
        "digest": reference.digest.to_string(),
        "release_id": reference.release_id.to_string(),
    })
}

/// Rebuilds one versioned Edition view (v1 or v2) from parity facts.
fn pg_versioned_edition_view(
    runtime: &mut PgRuntime,
    edition_id: proof_application::EditionId,
) -> Result<PgVersionedEditionView, String> {
    use proof_application::{EditionArtifactReference, KnownStateArtifactReference};
    if let Some(body) = fact_json(runtime, &format!("localized_edition/{edition_id}"))? {
        let state = KnownStateArtifactReference {
            api_version: json_str(&body, "state_api_version")?.to_owned(),
            authoritative_sequence: body
                .get("authoritative_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("edition sequence"))?,
            digest: json_str(&body, "state_digest")?
                .parse()
                .map_err(|_| integrity_code("state digest"))?,
        };
        let created_at: Timestamp = json_str(&body, "created_at")?
            .parse()
            .map_err(|_| integrity_code("edition timestamp"))?;
        let schemas = pg_schema_state_references(runtime, state.authoritative_sequence)?;
        let objects = pg_object_state_references(runtime, state.authoritative_sequence)?;
        let renditions = pg_locale_state_references(runtime, state.authoritative_sequence)?;
        return Ok(PgVersionedEditionView {
            reference: EditionArtifactReference {
                api_version: "proof.dev/edition/v2".to_owned(),
                edition_id,
                digest: json_str(&body, "edition_digest")?
                    .parse()
                    .map_err(|_| integrity_code("edition digest"))?,
            },
            state,
            schemas,
            objects,
            renditions,
            created_at,
        });
    }
    let body = require_fact_json(
        runtime,
        &format!("edition_v1/{edition_id}"),
        "proof.resource.not_found",
    )?;
    let sequence = body
        .get("authoritative_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity_code("v1 edition sequence"))?;
    let schemas = pg_schema_state_references(runtime, sequence)?;
    let objects = pg_object_state_references(runtime, sequence)?;
    Ok(PgVersionedEditionView {
        reference: EditionArtifactReference {
            api_version: "proof.dev/edition/v1".to_owned(),
            edition_id,
            digest: json_str(&body, "edition_digest")?
                .parse()
                .map_err(|_| integrity_code("v1 edition digest"))?,
        },
        state: KnownStateArtifactReference {
            api_version: KNOWN_STATE_V1_API_VERSION.to_owned(),
            authoritative_sequence: sequence,
            digest: json_str(&body, "state_digest")?
                .parse()
                .map_err(|_| integrity_code("v1 state digest"))?,
        },
        schemas,
        objects,
        renditions: Vec::new(),
        created_at: json_str(&body, "created_at")?
            .parse()
            .map_err(|_| integrity_code("v1 edition timestamp"))?,
    })
}

/// Ports `load_release_selection` over release metadata plus manifest facts.
fn pg_load_release_selection(
    runtime: &mut PgRuntime,
    release_id: proof_application::ReleaseId,
) -> Result<PgReleaseSelection, String> {
    use proof_application::{EditionArtifactReference, ReleaseArtifactReference};
    let meta = require_fact_json(
        runtime,
        &format!("release_meta/{release_id}"),
        "proof.resource.not_found",
    )?;
    let manifest = require_fact_json(
        runtime,
        &format!("release/{release_id}"),
        "proof.resource.not_found",
    )?;
    let view = pg_versioned_edition_view(
        runtime,
        json_str(&meta, "edition_id")?
            .parse()
            .map_err(|_| integrity_code("release edition identity"))?,
    )?;
    if json_str(&meta, "edition_digest")? != view.reference.digest.to_string() {
        return Err(integrity_code("Release Edition digest does not reproduce"));
    }
    Ok(PgReleaseSelection {
        reference: ReleaseArtifactReference {
            api_version: json_str(&meta, "release_api_version")?.to_owned(),
            release_id,
            digest: json_str(&meta, "release_digest")?
                .parse()
                .map_err(|_| integrity_code("release digest"))?,
        },
        environment_id: json_str(&manifest, "environment_id")?
            .parse()
            .map_err(|_| integrity_code("release environment"))?,
        edition: view.reference,
        release_sequence: manifest
            .get("release_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("release sequence"))?,
        released_at: json_str(&meta, "released_at")?
            .parse()
            .map_err(|_| integrity_code("release timestamp"))?,
    })
}

fn pg_load_environment(
    runtime: &mut PgRuntime,
    environment_id: &proof_application::EnvironmentId,
) -> Result<PgEnvironment, String> {
    let body = require_fact_json(
        runtime,
        &format!("environment/{environment_id}"),
        "proof.resource.not_found",
    )?;
    Ok(PgEnvironment {
        config_version: u32::try_from(
            body.get("config_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("environment version"))?,
        )
        .map_err(|_| integrity_code("environment version range"))?,
        config_digest: json_str(&body, "config_digest")?
            .parse()
            .map_err(|_| integrity_code("environment digest"))?,
        policy_profile: json_str(&body, "policy_profile")?.to_owned(),
        required_approval: json_str(&body, "required_approval")?.to_owned(),
        created_at: json_str(&body, "created_at")?
            .parse()
            .map_err(|_| integrity_code("environment timestamp"))?,
    })
}

/// Ports `exact_edition_delta` across all three versioned dimensions.
#[allow(clippy::too_many_lines)]
fn pg_exact_edition_delta(
    base: &PgVersionedEditionView,
    target: &PgVersionedEditionView,
) -> Result<PgExactEditionDelta, String> {
    let base_schemas = base
        .schemas
        .iter()
        .map(|(id, version, digest)| ((id.clone(), *version), *digest))
        .collect::<BTreeMap<_, _>>();
    let target_schemas = target
        .schemas
        .iter()
        .map(|(id, version, digest)| ((id.clone(), *version), *digest))
        .collect::<BTreeMap<_, _>>();
    let base_objects = base
        .objects
        .iter()
        .map(|object| (object.object_id, object.clone()))
        .collect::<BTreeMap<_, _>>();
    let target_objects = target
        .objects
        .iter()
        .map(|object| (object.object_id, object.clone()))
        .collect::<BTreeMap<_, _>>();
    let base_renditions = base
        .renditions
        .iter()
        .map(|rendition| {
            (
                (rendition.object_id, rendition.locale.clone()),
                rendition.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let target_renditions = target
        .renditions
        .iter()
        .map(|rendition| {
            (
                (rendition.object_id, rendition.locale.clone()),
                rendition.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let schema_keys = base_schemas
        .keys()
        .chain(target_schemas.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let object_keys = base_objects
        .keys()
        .chain(target_objects.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let rendition_keys = base_renditions
        .keys()
        .chain(target_renditions.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let schema_changes = schema_keys
        .iter()
        .filter_map(|key| {
            let before = base_schemas.get(key).copied();
            let after = target_schemas.get(key).copied();
            (before != after).then(|| {
                serde_json::json!({
                    "after": after.map(|value| value.to_string()),
                    "before": before.map(|value| value.to_string()),
                    "schema_id": key.0.as_str(),
                    "schema_version": key.1.get(),
                })
            })
        })
        .collect::<Vec<_>>();
    let object_changes = object_keys
        .iter()
        .filter_map(|key| {
            let before = base_objects.get(key);
            let after = target_objects.get(key);
            (before != after).then(|| {
                serde_json::json!({
                    "after": after.map(object_reference_value),
                    "before": before.map(object_reference_value),
                    "object_id": key.to_string(),
                })
            })
        })
        .collect::<Vec<_>>();
    let rendition_changes = rendition_keys
        .iter()
        .filter_map(|key| {
            let before = base_renditions.get(key).cloned();
            let after = target_renditions.get(key).cloned();
            (before != after).then(|| (key.clone(), before, after))
        })
        .collect::<Vec<_>>();
    let canonical = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/edition-delta/v2",
        "base": {
            "edition": edition_reference_value(&base.reference),
            "state": state_reference_value(&base.state),
        },
        "objects": object_changes,
        "renditions": rendition_changes.iter().map(|(key, before, after)| serde_json::json!({
            "after": after.as_ref().map(locale_reference_value),
            "before": before.as_ref().map(locale_reference_value),
            "locale": key.1.as_str(),
            "object_id": key.0.to_string(),
        })).collect::<Vec<_>>(),
        "schemas": schema_changes,
        "target": {
            "edition": edition_reference_value(&target.reference),
            "state": state_reference_value(&target.state),
        },
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(PgExactEditionDelta {
        digest: digest(ArtifactKind::ReleaseV2, &canonical),
        canonical: canonical.as_str().to_owned(),
        schema_changed: base_schemas != target_schemas,
        object_changed: base_objects != target_objects,
        rendition_changes,
    })
}

/// Ports `verify_promotion_delta` against the committed ChangeSet evidence.
fn pg_verify_promotion_delta(
    delta: &PgExactEditionDelta,
    commit: &CommittedLocalizedChangeSet,
    effective_edits: &[proof_application::LocalizedEdit],
) -> Result<(), String> {
    if delta.schema_changed || delta.object_changed {
        return Err("proof.policy.denied".to_owned());
    }
    if delta.rendition_changes.len() != commit.renditions.len()
        || commit.renditions.len() != effective_edits.len()
    {
        return Err("proof.policy.denied".to_owned());
    }
    for ((key, before, after), (rendition, edit)) in delta
        .rendition_changes
        .iter()
        .zip(commit.renditions.iter().zip(effective_edits.iter()))
    {
        let Some(after) = after else {
            return Err("proof.policy.denied".to_owned());
        };
        let expected_before = edit.input.expected_target.as_ref();
        if key != &(rendition.object_id, rendition.locale.clone())
            || key != &(edit.input.object_id, edit.input.locale.clone())
            || after.rendition_digest != rendition.rendition_digest
            || after.revision != rendition.revision
            || after.source_object_digest != rendition.source_object_digest
            || before
                .as_ref()
                .map(|value| (value.revision, value.rendition_digest))
                != expected_before.map(|value| (value.revision, value.digest))
        {
            return Err("proof.policy.denied".to_owned());
        }
    }
    Ok(())
}

/// Ports `localized_release_content_evidence` over parity facts.
fn pg_content_evidence(
    runtime: &mut PgRuntime,
    intent_body: &Value,
    changeset: &proof_application::LocalizedChangeSet,
    commit: &CommittedLocalizedChangeSet,
) -> Result<Value, String> {
    let context_pack_digest = fact_digest_of(
        runtime,
        &format!("context_pack/{}", changeset.context_pack_id),
    )?
    .to_string();
    let meta = require_fact_json(
        runtime,
        &format!("resource_intent_meta/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let validations = pg_validation_chain(runtime, &changeset.changeset_id.to_string())?;
    let (proposal_digest, effective_leaf_digest, _) = pg_proposal(changeset)?;
    Ok(serde_json::json!({
        "base": intent_body.get("base").cloned().unwrap_or(Value::Null),
        "changeset": {
            "changeset_id": changeset.changeset_id.to_string(),
            "effective_leaf_digest": effective_leaf_digest.to_string(),
            "proposal_digest": proposal_digest.to_string(),
            "sealed_changeset_digest": commit.sealed_changeset_digest.to_string(),
        },
        "context_pack_digest": context_pack_digest,
        "renditions": commit.renditions.iter().map(|rendition| serde_json::json!({
            "edit_id": rendition.edit_id.to_string(),
            "locale": rendition.locale.as_str(),
            "object_id": rendition.object_id.to_string(),
            "rendition_digest": rendition.rendition_digest.to_string(),
            "schema_id": rendition.schema_id.as_str(),
            "schema_version": rendition.schema_version.get(),
            "source_object_digest": rendition.source_object_digest.to_string(),
        })).collect::<Vec<_>>(),
        "resource_intent": {
            "digest": json_str(&meta, "intent_digest")?,
            "intent_id": changeset.resource_intent_id.to_string(),
            "targets": intent_body.get("targets").cloned().unwrap_or(Value::Array(Vec::new())),
        },
        "resulting_state": state_reference_value(&commit.resulting_state),
        "validations": validations.iter().map(|validation| serde_json::json!({
            "attempt": validation.attempt,
            "previous_validation_result_digest": validation.previous_validation_result_digest.map(|value| value.to_string()),
            "proposal_digest": validation.proposal_digest.to_string(),
            "results_digest": validation.validation_results_digest.to_string(),
            "valid": validation.valid,
        })).collect::<Vec<_>>(),
    }))
}

/// Inserts one immutable release-operation fact for exact keyed replay.
fn insert_release_op_fact(
    runtime: &mut PgRuntime,
    fact_id: &str,
    body: &Value,
) -> Result<(), String> {
    let canonical = canonicalize(body).map_err(|error| integrity_code(&error.to_string()))?;
    let fact_digest = derive_key_digest("proof:parity:release-operation:v1", canonical.as_bytes());
    let workspace_id = workspace_id_of(runtime)?;
    let inserted = {
        let client = runtime.client_mut();
        client
            .execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
                 ) VALUES ($1, $2, 'release_operation', 0, $3, $4, now())
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

fn pg_localized_digest_hex(digest: ContentDigest) -> String {
    digest
        .to_string()
        .strip_prefix("blake3:")
        .map_or_else(|| digest.to_string(), str::to_owned)
}

/// Ports `create_localized_release` (promotion arm) over parity facts with an
/// externally supplied Release signer.
#[allow(clippy::too_many_lines)]
fn pg_promote_release(
    runtime: &mut PgRuntime,
    signer: Option<&Ed25519SigningProvider>,
    command: &PromoteLocalizedReleaseCommand,
) -> Result<(Value, ContentDigest), String> {
    use proof_application::{ArtifactKind as AppKind, KnownStateArtifactReference};
    let principal = parity_principal(runtime)?;
    let workspace_id = parse_workspace(&workspace_id_of(runtime)?)?;

    // Request digest envelope (mirrors `localized_release_request_digest`).
    let request_canonical = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/operation/release.create/v2",
        "edition_id": Some(command.edition_id.to_string()),
        "environment_id": command.environment_id.as_str(),
        "expected_current_release_id": command.expected_base_release_id.to_string(),
        "idempotency_key": command.idempotency_key.to_string(),
        "kind": "promotion",
        "principal_id": principal.to_string(),
        "proof_id": command.proof_id.to_string(),
        "release_id": command.release_id.to_string(),
        "released_at": command.released_at.to_string(),
        "rollback_target_release_id": Option::<String>::None,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let request_digest = digest(AppKind::OperationEffectV1, &request_canonical);

    // Keyed replay against the immutable operation fact.
    let op_fact_id = format!("release_operation/{principal}/{}", command.idempotency_key);
    if let Some(stored) = fact_json(runtime, &op_fact_id)? {
        let stored_request = json_str(&stored, "request_digest")?.to_owned();
        let stored_release = json_str(&stored, "release_id")?
            .parse::<proof_application::ReleaseId>()
            .map_err(|_| integrity_code("stored release identity"))?;
        let stored_proof = json_str(&stored, "proof_id")?
            .parse::<proof_application::ProofId>()
            .map_err(|_| integrity_code("stored proof identity"))?;
        if stored_request != request_digest.to_string()
            || stored_release != command.release_id
            || stored_proof != command.proof_id
        {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        let release_manifest = require_fact_json(
            runtime,
            &format!("release/{}", command.release_id),
            "proof.resource.not_found",
        )?;
        if json_str(&release_manifest, "proof_id")? != command.proof_id.to_string() {
            return Err("proof.idempotency.key_reused".to_owned());
        }
        let result = stored
            .get("result")
            .cloned()
            .ok_or_else(|| integrity_code("stored release result"))?;
        let release_digest = json_str(&stored, "release_digest")?
            .parse::<ContentDigest>()
            .map_err(|_| integrity_code("stored release digest"))?;
        return Ok((result, release_digest));
    }

    // Candidate identity preflight.
    let candidate_exists = fact_json(runtime, &format!("release/{}", command.release_id))?
        .is_some()
        || fact_json(runtime, &format!("release_proof/{}", command.proof_id))?.is_some();
    if candidate_exists {
        return Err(integrity_code(
            "candidate Release or Proof identity already exists",
        ));
    }

    // Environment pointer and base-Release preflight.
    let environment = pg_load_environment(runtime, &command.environment_id)?;
    let pointer = require_fact_json(
        runtime,
        &format!("environment_current/{}", command.environment_id),
        "proof.resource.not_found",
    )?;
    if json_str(&pointer, "release_id")? != command.expected_base_release_id.to_string() {
        return Err("proof.state.conflict".to_owned());
    }
    let base_release = pg_load_release_selection(runtime, command.expected_base_release_id)?;
    if base_release.environment_id != command.environment_id
        || command.released_at < base_release.released_at
        || command.released_at < environment.created_at
    {
        return Err("proof.policy.denied".to_owned());
    }
    let base_view = pg_versioned_edition_view(runtime, base_release.edition.edition_id)?;

    // Promotion-specific verification.
    let target_view = pg_versioned_edition_view(runtime, command.edition_id)?;
    if target_view.reference.api_version != "proof.dev/edition/v2" {
        return Err("proof.input.schema_mismatch".to_owned());
    }
    let edition = pg_load_edition(runtime, command.edition_id)?;
    let changeset = load_pg_localized_changeset(runtime, &edition.changeset_id.to_string())?;
    let commit = pg_load_commit(runtime, edition.changeset_id)?;
    let intent_body = require_fact_json(
        runtime,
        &format!("resource_intent/{}", changeset.resource_intent_id),
        "proof.resource.not_found",
    )?;
    let intent_base = intent_base_values(&intent_base_json(&intent_body)?)?;
    if intent_base.release != base_release.reference
        || intent_base.edition != base_release.edition
        || intent_base.state != base_view.state
        || edition.base_edition != base_release.edition
        || edition.state != commit.resulting_state
        || pg_current_state_reference(runtime)? != edition.state
    {
        return Err("proof.state.conflict".to_owned());
    }
    let approval = require_fact_json(
        runtime,
        &format!("localized_approval/{}", changeset.changeset_id),
        "proof.digest.mismatch",
    )
    .map_err(|_| integrity_code("Release lacks localized approval"))?;
    let approval_name = json_str(&approval, "approval_name")?.to_owned();
    let approved_at: Timestamp = json_str(&approval, "approved_at")?
        .parse()
        .map_err(|_| integrity_code("approval timestamp"))?;
    if approval_name != environment.required_approval
        || command.released_at < approved_at
        || command.released_at < commit.committed_at
        || command.released_at < edition.created_at
    {
        return Err("proof.policy.denied".to_owned());
    }
    let delta = pg_exact_edition_delta(&base_view, &target_view)?;
    let (_, _, effective_edits) = pg_proposal(&changeset)?;
    pg_verify_promotion_delta(&delta, &commit, &effective_edits)?;
    let content_evidence = pg_content_evidence(runtime, &intent_body, &changeset, &commit)?;

    // Signing.
    let signer = signer.ok_or_else(|| "proof.dependency.unavailable".to_owned())?;
    let metadata =
        <Ed25519SigningProvider as proof_attestation::ProofSigningProvider>::metadata(signer)
            .map_err(|error| "proof.dependency.unavailable".to_owned())?;
    if metadata.public_key.len() != 32
        || !metadata.key_id.starts_with("ed25519:")
        || metadata.key_id.len() != 72
    {
        return Err("proof.dependency.unavailable".to_owned());
    }
    {
        let public_key = metadata.public_key.iter().fold(
            String::with_capacity(metadata.public_key.len() * 2),
            |mut out, byte| {
                use std::fmt::Write as _;
                let _ = write!(&mut out, "{byte:02x}");
                out
            },
        );
        if metadata.key_id != format!("ed25519:{public_key}") {
            return Err("proof.dependency.unavailable".to_owned());
        }
        upsert_parity_fact(
            runtime,
            &workspace_id.to_string(),
            &format!("release_signing_key/{}", metadata.key_id),
            "release_signing_key",
            &serde_json::json!({
                "api_version": "proof.dev/parity/release-signing-key/v1",
                "algorithm": "Ed25519",
                "key_id": metadata.key_id,
                "not_before": command.released_at.to_string(),
                "public_key": public_key,
            }),
            "proof:parity:release-signing-key:v1",
        )?;
    }
    let release_sequence = {
        let client = runtime.client_mut();
        client
            .query_one(
                "SELECT COALESCE(MAX(authority_sequence), 0) + 1 AS next_seq FROM facts
                 WHERE fact_kind IN ('release', 'release_v2')",
                &[],
            )
            .map_err(|error| integrity_code(&error.to_string()))?
            .get::<_, i64>("next_seq")
    };
    let release_sequence = u64::try_from(release_sequence)
        .map_err(|_| integrity_code("invalid next Release sequence"))?;

    // Authorization decision, manifest, statement, signature.
    let policy_decision = canonicalize(&serde_json::json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": pg_release_reference_value(&base_release.reference),
        "changeset_id": Some(changeset.changeset_id.to_string()),
        "edition": edition_reference_value(&target_view.reference),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": command.environment_id.as_str(),
        "evaluated_at": command.released_at.to_string(),
        "exact_delta_digest": delta.digest.to_string(),
        "kind": "promotion",
        "operating_principal_id": principal.to_string(),
        "policy_profile": environment.policy_profile,
        "required_approval": environment.required_approval,
        "resource_intent_id": Some(changeset.resource_intent_id.to_string()),
        "rollback_target_release_id": Option::<String>::None,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let policy_decision_digest = digest(AppKind::AuthorizationDecisionV1, &policy_decision);
    let manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/release/v2",
        "authorization_decision_digest": policy_decision_digest.to_string(),
        "base_release": pg_release_reference_value(&base_release.reference),
        "changeset_id": changeset.changeset_id.to_string(),
        "edition": edition_reference_value(&target_view.reference),
        "environment_config_digest": environment.config_digest.to_string(),
        "environment_config_version": environment.config_version,
        "environment_id": command.environment_id.as_str(),
        "exact_delta_digest": delta.digest.to_string(),
        "key_id": metadata.key_id,
        "kind": "promotion",
        "principal_id": principal.to_string(),
        "proof_id": command.proof_id.to_string(),
        "release_id": command.release_id.to_string(),
        "release_sequence": release_sequence,
        "released_at": command.released_at.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "rollback_target_release_id": Option::<String>::None,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let release_digest = digest(AppKind::ReleaseV2, &manifest);
    let statement = InTotoStatement::release_v2(
        vec![
            InTotoSubject {
                name: format!("proof:edition:{}", target_view.reference.edition_id),
                digest: std::collections::BTreeMap::from([(
                    "blake3".to_owned(),
                    pg_localized_digest_hex(target_view.reference.digest),
                )]),
            },
            InTotoSubject {
                name: format!("proof:release:{}", command.release_id),
                digest: std::collections::BTreeMap::from([(
                    "blake3".to_owned(),
                    pg_localized_digest_hex(release_digest),
                )]),
            },
        ],
        serde_json::json!({
            "api_version": "proof.dev/release-proof-predicate/v2",
            "authority": {
                "authorization_decision_digest": policy_decision_digest.to_string(),
                "human_principal_id": principal.to_string(),
                "policy_profile": environment.policy_profile,
            },
            "content_evidence": content_evidence,
            "exact_delta": proof_canonical::parse_strict(delta.canonical.as_bytes())
                .map_err(|error| integrity_code(&error.to_string()))?,
            "exact_delta_digest": delta.digest.to_string(),
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": target_view.state.api_version,
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "release": {
                "base_release": pg_release_reference_value(&base_release.reference),
                "changeset_id": changeset.changeset_id.to_string(),
                "edition": edition_reference_value(&target_view.reference),
                "environment_id": command.environment_id.as_str(),
                "key_id": metadata.key_id,
                "kind": "promotion",
                "release_digest": release_digest.to_string(),
                "release_id": command.release_id.to_string(),
                "release_sequence": release_sequence,
                "released_at": command.released_at.to_string(),
                "resource_intent_id": changeset.resource_intent_id.to_string(),
                "rollback_target_release_id": Option::<String>::None,
            },
            "state": state_reference_value(&target_view.state),
            "workspace_id": workspace_id.to_string(),
        }),
    );
    let signed_proof = sign_release_statement(&statement, signer)
        .map_err(|error| "proof.dependency.unavailable".to_owned())?;
    if signed_proof.key_id != metadata.key_id {
        return Err("proof.dependency.unavailable".to_owned());
    }
    let metadata_manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/localized-release-metadata/v1",
        "base_release": pg_release_reference_value(&base_release.reference),
        "changeset_id": changeset.changeset_id.to_string(),
        "edition": edition_reference_value(&target_view.reference),
        "exact_delta_digest": delta.digest.to_string(),
        "kind": "promotion",
        "release_id": command.release_id.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "rollback_target_release_id": Option::<String>::None,
    }))
    .map_err(|error| integrity_code(&error.to_string()))?;
    let metadata_digest = digest(AppKind::ReleaseV2, &metadata_manifest);

    // Persistence.
    insert_release_fact(runtime, &manifest, &release_digest, release_sequence)?;
    store_verified_fact(
        runtime,
        &workspace_id.to_string(),
        &format!("release_metadata/{}", command.release_id),
        "proof:parity:release-metadata:v1",
        "release_metadata",
        &serde_json::json!({
            "api_version": "proof.dev/parity/release-metadata-record/v1",
            "base_release_id": base_release.reference.release_id.to_string(),
            "changeset_id": changeset.changeset_id.to_string(),
            "exact_delta": proof_canonical::parse_strict(delta.canonical.as_bytes())
                .map_err(|error| integrity_code(&error.to_string()))?,
            "exact_delta_digest": delta.digest.to_string(),
            "metadata": proof_canonical::parse_strict(metadata_manifest.as_bytes())
                .map_err(|error| integrity_code(&error.to_string()))?,
            "metadata_digest": metadata_digest.to_string(),
            "resource_intent_id": changeset.resource_intent_id.to_string(),
        }),
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    store_verified_fact(
        runtime,
        &workspace_id.to_string(),
        &format!("release_proof/{}", command.proof_id),
        "proof:parity:release-proof:v1",
        "release_proof",
        &serde_json::json!({
            "api_version": "proof.dev/parity/release-proof/v1",
            "created_at": command.released_at.to_string(),
            "envelope_digest": signed_proof.envelope_digest.to_string(),
            "envelope_json": signed_proof.envelope_json,
            "key_id": metadata.key_id,
            "payload_type": signed_proof.envelope.payload_type.clone(),
            "predicate_type": statement.predicate_type,
            "release_id": command.release_id.to_string(),
            "statement_payload": signed_proof.payload_json,
        }),
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    store_verified_fact(
        runtime,
        &workspace_id.to_string(),
        &format!("release_export/{}", command.proof_id),
        "proof:parity:release-export:v1",
        "release_export",
        &serde_json::json!({
            "api_version": "proof.dev/parity/release-export-outbox/v1",
            "created_at": command.released_at.to_string(),
            "proof_id": command.proof_id.to_string(),
            "release_id": command.release_id.to_string(),
        }),
    )
    .map_err(|error| integrity_code(&error.to_string()))?;
    let release = LocalizedRelease {
        release_id: command.release_id,
        workspace_id,
        environment_id: command.environment_id.clone(),
        edition: target_view.reference.clone(),
        kind: proof_application::ReleaseKind::Promotion,
        release_sequence,
        previous_release_id: Some(base_release.reference.release_id),
        rollback_target_release_id: None,
        changeset_id: Some(changeset.changeset_id),
        resource_intent_id: Some(changeset.resource_intent_id),
        manifest_json: manifest.as_str().to_owned(),
        release_digest,
        proof_id: command.proof_id,
        proof_envelope_digest: signed_proof.envelope_digest,
        key_id: signed_proof.key_id.clone(),
        proof_envelope_json: signed_proof.envelope_json.clone(),
        released_at: command.released_at,
    };
    let result = proof_remote::oracle::serialize_localized_release(&release);
    // Rotate the Environment pointer exactly like the reference UPDATE.
    upsert_parity_fact(
        runtime,
        &workspace_id.to_string(),
        &format!("environment_current/{}", command.environment_id),
        "environment_current",
        &serde_json::json!({
            "api_version": "proof.dev/parity/environment-current/v1",
            "environment_id": command.environment_id.as_str(),
            "release_id": command.release_id.to_string(),
            "release_sequence": release_sequence,
        }),
        "proof:parity:environment-current:v1",
    )?;
    insert_release_op_fact(
        runtime,
        &op_fact_id,
        &serde_json::json!({
            "api_version": "proof.dev/parity/release-operation/v1",
            "idempotency_key": command.idempotency_key.to_string(),
            "operation_kind": "release.promote.v2",
            "principal_id": principal.to_string(),
            "proof_id": command.proof_id.to_string(),
            "release_digest": release_digest.to_string(),
            "release_id": command.release_id.to_string(),
            "request_digest": request_digest.to_string(),
            "result": result,
        }),
    )?;
    Ok((result, release_digest))
}

/// Extracts the three baseline references from an imported intent manifest.
fn intent_base_values(base: &Value) -> Result<IntentBaseRefs, String> {
    let parse_ref = |value: &Value,
                     digest_key: &str,
                     id_key: &str|
     -> Result<(String, ContentDigest, String), String> {
        Ok((
            json_str(value, "api_version")?.to_owned(),
            json_str(value, digest_key)?
                .parse()
                .map_err(|_| integrity_code("baseline digest"))?,
            json_str(value, id_key)?.to_owned(),
        ))
    };
    let (release_api, release_digest, release_id) = parse_ref(
        base.get("release")
            .ok_or_else(|| integrity_code("baseline release"))?,
        "digest",
        "release_id",
    )?;
    let (edition_api, edition_digest, edition_id) = parse_ref(
        base.get("edition")
            .ok_or_else(|| integrity_code("baseline edition"))?,
        "digest",
        "edition_id",
    )?;
    let state = base
        .get("known_state")
        .ok_or_else(|| integrity_code("baseline state"))?;
    Ok(IntentBaseRefs {
        release: proof_application::ReleaseArtifactReference {
            api_version: release_api,
            digest: release_digest,
            release_id: release_id
                .parse()
                .map_err(|_| integrity_code("baseline release identity"))?,
        },
        edition: proof_application::EditionArtifactReference {
            api_version: edition_api,
            digest: edition_digest,
            edition_id: edition_id
                .parse()
                .map_err(|_| integrity_code("baseline edition identity"))?,
        },
        state: KnownStateArtifactReference {
            api_version: json_str(state, "api_version")?.to_owned(),
            authoritative_sequence: state
                .get("authoritative_sequence")
                .and_then(Value::as_u64)
                .ok_or_else(|| integrity_code("baseline sequence"))?,
            digest: json_str(state, "digest")?
                .parse()
                .map_err(|_| integrity_code("baseline state digest"))?,
        },
    })
}

struct IntentBaseRefs {
    release: proof_application::ReleaseArtifactReference,
    edition: proof_application::EditionArtifactReference,
    state: KnownStateArtifactReference,
}

fn intent_base_json(intent_body: &Value) -> Result<Value, String> {
    intent_body
        .get("base")
        .cloned()
        .ok_or_else(|| integrity_code("intent baseline"))
}

fn pg_current_state_reference(
    runtime: &mut PgRuntime,
) -> Result<KnownStateArtifactReference, String> {
    let head = require_fact_json(runtime, "known_state/head", "proof.resource.not_found")?;
    Ok(KnownStateArtifactReference {
        api_version: json_str(&head, "known_state_api_version")?.to_owned(),
        authoritative_sequence: head
            .get("authoritative_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| integrity_code("head sequence"))?,
        digest: json_str(&head, "state_digest")?
            .parse()
            .map_err(|_| integrity_code("head digest"))?,
    })
}

/// Inserts the immutable v2 Release manifest fact with its real artifact digest
/// and workspace-global sequence.
fn insert_release_fact(
    runtime: &mut PgRuntime,
    manifest: &proof_canonical::CanonicalJson,
    release_digest: &ContentDigest,
    release_sequence: u64,
) -> Result<(), String> {
    let release_id = {
        let value: Value = proof_canonical::parse_strict(manifest.as_bytes())
            .map_err(|error| integrity_code(&error.to_string()))?;
        json_str(&value, "release_id")?.to_owned()
    };
    let workspace_id = workspace_id_of(runtime)?;
    let client = runtime.client_mut();
    client
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, 'release_v2', $3, $4, $5, now())",
            &[
                &format!("release/{release_id}"),
                &workspace_id,
                &(i64::try_from(release_sequence).map_err(|_| integrity_code("sequence range"))?),
                &release_digest.to_string(),
                &manifest.as_bytes().to_vec(),
            ],
        )
        .map_err(|error| integrity_code(&error.to_string()))?;
    Ok(())
}
