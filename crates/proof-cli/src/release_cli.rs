use std::{env, path::PathBuf};

use clap::Subcommand;
use proof_application::{
    ApprovalName, CreateEnvironmentCommand, Environment, EnvironmentError, IdempotencyKey,
    LocalizedContentError, LocalizedContentRepository, ObjectListCommand, PrincipalId, Problem,
    ProjectionRebuild, QueryReleasedObjectsCommand, QueryReleasedObjectsError,
    RebuildProjectionsCommand, RebuildProjectionsError, Release, ReleaseError, ReleaseVerification,
    ResultEnvelope, RollbackReleaseCommand, SchemaGetCommand, SchemaListCommand,
    VerifyReleaseCommand, create_environment, get_environment, get_release, promote_release,
    query_released_objects, rebuild_projections, rollback_release, verify_release,
};
use proof_local::LocalWorkspace;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    AuthoritySelection, ExecutionContext, ExitCode, OutputFormat, current_timestamp,
    generated_idempotency_key, write_json,
};

#[derive(Debug, Subcommand)]
pub(super) enum EnvironmentAction {
    /// Create one versioned local release target.
    Create {
        /// Stable lowercase Environment identity.
        environment_id: String,
        /// Versioned local target adapter.
        #[arg(long, default_value = "proof.local/released-state/v1")]
        target_kind: String,
        /// Versioned local release policy.
        #[arg(long, default_value = "proof.local/release-policy/v1")]
        policy_profile: String,
        /// Exact approval name required on every included `ChangeSet`.
        #[arg(long)]
        required_approval: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Return one verified Environment and its current Release pointer.
    Get {
        /// Stable Environment identity.
        environment_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum ReleaseAction {
    /// Promote one immutable Edition to an Environment.
    Create {
        /// Immutable Edition `UUIDv7`.
        #[arg(long)]
        edition: String,
        /// Target Environment identity.
        #[arg(long)]
        environment: String,
        /// Supply the consequential `UUIDv7` retry key.
        #[arg(long)]
        idempotency_key: String,
    },
    /// Return one immutable Release and its Proof envelope.
    Get {
        /// Release `UUIDv7`.
        release_id: String,
    },
    /// Select the Edition from an earlier Release without rewriting history.
    Rollback {
        /// Target Environment identity.
        #[arg(long)]
        environment: String,
        /// Earlier Release whose Edition will become current.
        #[arg(long)]
        to_release: String,
        /// Supply the consequential `UUIDv7` retry key.
        #[arg(long)]
        idempotency_key: String,
    },
    /// Verify one persisted Release, Proof, subjects, evidence, and trust.
    Verify {
        /// Release `UUIDv7`.
        release_id: String,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum ObjectAction {
    /// Query exact Objects from the immutable Edition current in an Environment.
    Query {
        /// Released Environment identity.
        #[arg(long)]
        environment: String,
        /// Exact Object `UUIDv7`; repeat for multiple Objects.
        #[arg(long)]
        object_id: Vec<String>,
    },
    /// List committed base Objects and exact-locale rendition heads.
    List {
        /// Environment whose current Release defines release coverage.
        #[arg(long)]
        environment: String,
        /// Optional exact Schema identity.
        #[arg(long)]
        schema_id: Option<String>,
        /// Optional exact locale.
        #[arg(long)]
        locale: Option<String>,
        /// Exact Object `UUIDv7`; repeat for a bounded explicit set.
        #[arg(long)]
        object_id: Vec<String>,
        /// Exclusive decimal authoritative-sequence cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Number of entries to return, from 1 through 100.
        #[arg(long)]
        page_size: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum SchemaAction {
    /// Get one exact committed Schema version.
    Get {
        /// Exact Schema identity.
        schema_id: String,
        /// Exact immutable Schema version.
        schema_version: u32,
    },
    /// List committed Schema versions without document bodies.
    List {
        /// Optional exact Schema identity.
        #[arg(long)]
        schema_id: Option<String>,
        /// Exclusive decimal authoritative-sequence cursor.
        #[arg(long)]
        cursor: Option<String>,
        /// Number of entries to return, from 1 through 100.
        #[arg(long)]
        page_size: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Subcommand)]
pub(super) enum ProjectionAction {
    /// Reproduce every derived projection from authoritative facts.
    Rebuild {
        /// Report drift without writing repaired projections.
        #[arg(long)]
        dry_run: bool,
    },
}

pub(super) fn run_environment(
    action: EnvironmentAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let operation = match &action {
        EnvironmentAction::Create { .. } => "environment.create",
        EnvironmentAction::Get { .. } => "environment.get",
    };
    let repository = local_workspace(selected_workspace, operation, context)?;
    match action {
        EnvironmentAction::Create {
            environment_id,
            target_kind,
            policy_profile,
            required_approval,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let environment = create_environment(
                &repository,
                CreateEnvironmentCommand {
                    environment_id: parse(&environment_id, "environment-id", operation, context)?,
                    target_kind,
                    policy_profile,
                    required_approval: ApprovalName::new(required_approval)
                        .map_err(|error| input_problem(operation, context, error.to_string()))?,
                    idempotency_key,
                    created_at: now(operation, context)?,
                },
            )
            .map_err(|error| environment_problem(&error, operation, context))?;
            render_environment(
                output,
                context,
                operation,
                &environment,
                Some(idempotency_key),
            );
        }
        EnvironmentAction::Get { environment_id } => {
            let environment = get_environment(
                &repository,
                parse(&environment_id, "environment-id", operation, context)?,
            )
            .map_err(|error| environment_problem(&error, operation, context))?;
            render_environment(output, context, operation, &environment, None);
        }
    }
    Ok(ExitCode::Success)
}

pub(super) fn run_release(
    action: ReleaseAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let operation = match &action {
        ReleaseAction::Create { .. } => "release.create",
        ReleaseAction::Get { .. } => "release.get",
        ReleaseAction::Rollback { .. } => "release.rollback",
        ReleaseAction::Verify { .. } => "release.verify",
    };
    let repository = local_workspace(selected_workspace, operation, context)?;
    match action {
        ReleaseAction::Create {
            edition,
            environment,
            idempotency_key,
        } => {
            let release = promote_release(
                &repository,
                proof_application::PromoteReleaseCommand {
                    release_id: generated_operational_id(),
                    proof_id: generated_operational_id(),
                    environment_id: parse(&environment, "environment", operation, context)?,
                    edition_id: parse(&edition, "edition", operation, context)?,
                    idempotency_key: parse(
                        &idempotency_key,
                        "idempotency-key",
                        operation,
                        context,
                    )?,
                    released_at: now(operation, context)?,
                },
            )
            .map_err(|error| release_problem(&error, operation, context))?;
            render_release(output, context, operation, &release);
        }
        ReleaseAction::Get { release_id } => {
            let release = get_release(
                &repository,
                parse(&release_id, "release-id", operation, context)?,
            )
            .map_err(|error| release_problem(&error, operation, context))?;
            render_release(output, context, operation, &release);
        }
        ReleaseAction::Rollback {
            environment,
            to_release,
            idempotency_key,
        } => {
            let release = rollback_release(
                &repository,
                RollbackReleaseCommand {
                    release_id: generated_operational_id(),
                    proof_id: generated_operational_id(),
                    environment_id: parse(&environment, "environment", operation, context)?,
                    rollback_target_release_id: parse(
                        &to_release,
                        "to-release",
                        operation,
                        context,
                    )?,
                    idempotency_key: parse(
                        &idempotency_key,
                        "idempotency-key",
                        operation,
                        context,
                    )?,
                    released_at: now(operation, context)?,
                },
            )
            .map_err(|error| release_problem(&error, operation, context))?;
            render_release(output, context, operation, &release);
        }
        ReleaseAction::Verify { release_id } => {
            let verified = verify_release(
                &repository,
                VerifyReleaseCommand {
                    release_id: parse(&release_id, "release-id", operation, context)?,
                    verified_at: now(operation, context)?,
                },
            )
            .map_err(|error| release_problem(&error, operation, context))?;
            render_release_verification(output, context, operation, &verified);
        }
    }
    Ok(ExitCode::Success)
}

pub(super) fn run_schema(
    action: SchemaAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let operation = match action {
        SchemaAction::Get { .. } => "schema.get",
        SchemaAction::List { .. } => "schema.list",
    };
    let repository = local_workspace(selected_workspace, operation, context)?;
    match action {
        SchemaAction::Get {
            schema_id,
            schema_version,
        } => {
            let result = repository
                .get_schema(SchemaGetCommand {
                    schema_id: parse(&schema_id, "schema-id", operation, context)?,
                    schema_version: proof_application::SchemaVersion::new(schema_version)
                        .map_err(|error| input_problem(operation, context, error.to_string()))?,
                })
                .map_err(|error| content_read_problem(&error, operation, context))?;
            let data = json!({
                "document": result.document,
                "document_digest": result.document_digest.to_string(),
                "provenance": schema_provenance_value(result.provenance),
                "schema_id": result.schema_id.as_str(),
                "schema_version": result.schema_version.get(),
            });
            render_value(output, context, operation, data, |data| {
                println!("Schema {}@{}", data["schema_id"], data["schema_version"]);
                println!("digest: {}", data["document_digest"]);
                println!(
                    "authoritative sequence: {}",
                    data["provenance"]["authoritative_sequence"]
                );
                println!("{}", data["document"]);
            });
        }
        SchemaAction::List {
            schema_id,
            cursor,
            page_size,
        } => {
            let result = repository
                .list_schemas(SchemaListCommand {
                    schema_id: schema_id
                        .map(|value| parse(&value, "schema-id", operation, context))
                        .transpose()?,
                    cursor,
                    page_size,
                })
                .map_err(|error| content_read_problem(&error, operation, context))?;
            let mut data = json!({
                "entries": result.entries.iter().map(|entry| json!({
                    "document_digest": entry.document_digest.to_string(),
                    "provenance": schema_provenance_value(entry.provenance),
                    "schema_id": entry.schema_id.as_str(),
                    "schema_version": entry.schema_version.get(),
                })).collect::<Vec<_>>(),
            });
            if let Some(cursor) = result.next_cursor {
                data.as_object_mut()
                    .expect("Schema list data is an object")
                    .insert("next_cursor".to_owned(), Value::String(cursor));
            }
            render_value(output, context, operation, data, |data| {
                for entry in data["entries"].as_array().into_iter().flatten() {
                    println!(
                        "{}@{} {}",
                        entry["schema_id"], entry["schema_version"], entry["document_digest"]
                    );
                }
                if let Some(cursor) = data.get("next_cursor") {
                    println!("next cursor: {cursor}");
                }
            });
        }
    }
    Ok(ExitCode::Success)
}

#[allow(clippy::too_many_lines)]
pub(super) fn run_object(
    action: ObjectAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    authority: &AuthoritySelection,
) -> Result<ExitCode, Box<Problem>> {
    match action {
        ObjectAction::Query {
            environment,
            object_id,
        } => {
            let operation = "object.query_released";
            let (operating_principal_id, delegation_id) =
                optional_authority(authority, operation, context)?;
            let repository = local_workspace(selected_workspace, operation, context)?;
            let query = query_released_objects(
                &repository,
                QueryReleasedObjectsCommand {
                    operating_principal_id,
                    delegation_id,
                    environment_id: parse(&environment, "environment", operation, context)?,
                    object_ids: parse_many(&object_id, "object-id", operation, context)?,
                    evaluated_at: now(operation, context)?,
                },
            )
            .map_err(|error| query_problem(&error, operation, context))?;
            let objects = query
                .objects
                .iter()
                .map(|object| {
                    json!({
                        "object_id": object.object_id.to_string(),
                        "revision": object.revision.get(),
                        "schema_id": object.schema_id.to_string(),
                        "schema_version": object.schema_version.get(),
                        "lifecycle_state": object.lifecycle_state.to_string(),
                        "content": serde_json::from_str::<Value>(&object.canonical_content).unwrap_or(Value::Null),
                        "canonical_content": object.canonical_content,
                        "object_digest": object.object_digest.to_string(),
                    })
                })
                .collect::<Vec<_>>();
            let data = json!({
                "workspace_id": query.workspace_id.to_string(),
                "environment_id": query.environment_id.to_string(),
                "release_id": query.release_id.to_string(),
                "edition_id": query.edition_id.to_string(),
                "principal_id": query.principal_id.to_string(),
                "delegation_id": query.delegation_id.map(|id| id.to_string()),
                "authorization_decision_digest": query.authorization_decision_digest.to_string(),
                "objects": objects,
            });
            render_value(output, context, operation, data, |data| {
                println!("Released Objects from {}", data["environment_id"]);
                println!("release: {}", data["release_id"]);
                println!("edition: {}", data["edition_id"]);
                for object in data["objects"].as_array().into_iter().flatten() {
                    println!("{} revision {}", object["object_id"], object["revision"]);
                    println!(
                        "  schema: {}@{}",
                        object["schema_id"], object["schema_version"]
                    );
                    println!("  digest: {}", object["object_digest"]);
                }
            });
        }
        ObjectAction::List {
            environment,
            schema_id,
            locale,
            object_id,
            cursor,
            page_size,
        } => {
            let operation = "object.list";
            if authority.is_explicit() {
                return Err(mapped_problem(
                    "urn:proof:problem:authority-denied",
                    "The committed Object register is Human-only",
                    "proof.auth.denied",
                    operation,
                    context,
                    false,
                ));
            }
            let repository = local_workspace(selected_workspace, operation, context)?;
            let object_ids = if object_id.is_empty() {
                None
            } else {
                let mut parsed = parse_many(&object_id, "object-id", operation, context)?;
                parsed.sort_unstable();
                if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
                    return Err(input_problem(
                        operation,
                        context,
                        "object-id values must be unique".to_owned(),
                    ));
                }
                Some(parsed)
            };
            let result = repository
                .list_objects(ObjectListCommand {
                    environment_id: parse(&environment, "environment", operation, context)?,
                    schema_id: schema_id
                        .map(|value| parse(&value, "schema-id", operation, context))
                        .transpose()?,
                    locale: locale
                        .map(|value| parse(&value, "locale", operation, context))
                        .transpose()?,
                    object_ids,
                    cursor,
                    page_size,
                })
                .map_err(|error| content_read_problem(&error, operation, context))?;
            let mut data = json!({
                "entries": result.entries.iter().map(|entry| json!({
                    "covered_by_current_release": entry.covered_by_current_release,
                    "head_renditions": entry.head_renditions.iter().map(|rendition| json!({
                        "locale": rendition.locale.as_str(),
                        "rendition_digest": rendition.rendition_digest.to_string(),
                        "revision": rendition.revision.get(),
                    })).collect::<Vec<_>>(),
                    "object_id": entry.object_id.to_string(),
                    "released_revision": entry.released_revision.map(proof_application::ObjectRevision::get),
                    "schema_id": entry.schema_id.as_str(),
                    "schema_version": entry.schema_version.get(),
                })).collect::<Vec<_>>(),
                "state_scope": result.state_scope,
            });
            if let Some(cursor) = result.next_cursor {
                data.as_object_mut()
                    .expect("Object list data is an object")
                    .insert("next_cursor".to_owned(), Value::String(cursor));
            }
            render_value(output, context, operation, data, |data| {
                println!("state scope: {}", data["state_scope"]);
                for entry in data["entries"].as_array().into_iter().flatten() {
                    println!(
                        "{} {}@{} released revision {}",
                        entry["object_id"],
                        entry["schema_id"],
                        entry["schema_version"],
                        entry["released_revision"]
                    );
                }
                if let Some(cursor) = data.get("next_cursor") {
                    println!("next cursor: {cursor}");
                }
            });
        }
    }
    Ok(ExitCode::Success)
}

pub(super) fn run_projection(
    action: ProjectionAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    match action {
        ProjectionAction::Rebuild { dry_run } => {
            let operation = "projection.rebuild";
            let repository = local_workspace(selected_workspace, operation, context)?;
            let rebuilt = rebuild_projections(&repository, RebuildProjectionsCommand { dry_run })
                .map_err(|error| rebuild_problem(&error, operation, context))?;
            render_projection(output, context, operation, rebuilt);
        }
    }
    Ok(ExitCode::Success)
}

fn schema_provenance_value(provenance: proof_application::SchemaReadProvenance) -> Value {
    json!({
        "authoritative_sequence": provenance.authoritative_sequence,
        "changeset_id": provenance.changeset_id.to_string(),
        "edit_id": provenance.edit_id.to_string(),
    })
}

fn render_environment(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    environment: &Environment,
    idempotency_key: Option<IdempotencyKey>,
) {
    let data = json!({
        "environment_id": environment.environment_id.to_string(),
        "workspace_id": environment.workspace_id.to_string(),
        "config_version": environment.config_version,
        "target_kind": environment.target_kind,
        "policy_profile": environment.policy_profile,
        "required_approval": environment.required_approval.to_string(),
        "config_manifest": serde_json::from_str::<Value>(&environment.config_manifest_json).unwrap_or(Value::Null),
        "config_manifest_json": environment.config_manifest_json,
        "config_digest": environment.config_digest.to_string(),
        "current_release_id": environment.current_release_id.map(|id| id.to_string()),
        "principal_id": environment.principal_id.to_string(),
        "created_at": environment.created_at.to_string(),
        "idempotency_key": idempotency_key.map(|key| key.to_string()),
    });
    render_value(output, context, operation, data, |data| {
        println!("Environment {}", data["environment_id"]);
        println!("target: {}", data["target_kind"]);
        println!("policy: {}", data["policy_profile"]);
        println!("required approval: {}", data["required_approval"]);
        println!("config digest: {}", data["config_digest"]);
        println!("current release: {}", data["current_release_id"]);
    });
}

fn render_release(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    release: &Release,
) {
    let data = json!({
        "release_id": release.release_id.to_string(),
        "workspace_id": release.workspace_id.to_string(),
        "environment_id": release.environment_id.to_string(),
        "edition_id": release.edition_id.to_string(),
        "kind": release.kind.to_string(),
        "release_sequence": release.release_sequence,
        "previous_release_id": release.previous_release_id.map(|id| id.to_string()),
        "rollback_target_release_id": release.rollback_target_release_id.map(|id| id.to_string()),
        "principal_id": release.principal_id.to_string(),
        "delegation_id": release.delegation_id.map(|id| id.to_string()),
        "released_at": release.released_at.to_string(),
        "release_digest": release.release_digest.to_string(),
        "edition_digest": release.edition_digest.to_string(),
        "environment_config_digest": release.environment_config_digest.to_string(),
        "authorization_decision_digest": release.authorization_decision_digest.to_string(),
        "proof_id": release.proof_id.to_string(),
        "proof_envelope_digest": release.proof_envelope_digest.to_string(),
        "key_id": release.key_id,
        "proof_envelope": serde_json::from_str::<Value>(&release.proof_envelope_json).unwrap_or(Value::Null),
        "proof_envelope_json": release.proof_envelope_json,
    });
    render_value(output, context, operation, data, |data| {
        println!("Release {}", data["release_id"]);
        println!("environment: {}", data["environment_id"]);
        println!("edition: {}", data["edition_id"]);
        println!("kind: {}", data["kind"]);
        println!("sequence: {}", data["release_sequence"]);
        println!("proof: {}", data["proof_id"]);
        println!("key id: {}", data["key_id"]);
        println!("proof envelope digest: {}", data["proof_envelope_digest"]);
    });
}

fn render_release_verification(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    verified: &ReleaseVerification,
) {
    let data = json!({
        "release_id": verified.release_id.to_string(),
        "proof_id": verified.proof_id.to_string(),
        "key_id": verified.key_id,
        "signature_valid": verified.signature_valid,
        "subjects_valid": verified.subjects_valid,
        "evidence_complete": verified.evidence_complete,
        "trusted": verified.trusted,
        "valid": verified.valid,
        "findings": verified.findings,
        "verified_at": verified.verified_at.to_string(),
    });
    render_value(output, context, operation, data, |data| {
        println!("Release {} verification", data["release_id"]);
        println!("valid: {}", data["valid"]);
        println!("signature valid: {}", data["signature_valid"]);
        println!("subjects valid: {}", data["subjects_valid"]);
        println!("evidence complete: {}", data["evidence_complete"]);
        println!("trusted: {}", data["trusted"]);
    });
}

fn render_projection(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    rebuilt: ProjectionRebuild,
) {
    let data = json!({
        "dry_run": rebuilt.dry_run,
        "changed": rebuilt.changed,
        "authoritative_sequence": rebuilt.authoritative_sequence,
        "state_digest": rebuilt.state_digest.to_string(),
        "schema_count": rebuilt.schema_count,
        "object_count": rebuilt.object_count,
        "environment_pointer_count": rebuilt.environment_pointer_count,
    });
    render_value(output, context, operation, data, |data| {
        println!("Projection rebuild");
        println!("dry run: {}", data["dry_run"]);
        println!("changed: {}", data["changed"]);
        println!("authoritative sequence: {}", data["authoritative_sequence"]);
        println!("state digest: {}", data["state_digest"]);
        println!("Schemas: {}", data["schema_count"]);
        println!("Objects: {}", data["object_count"]);
        println!(
            "Environment pointers: {}",
            data["environment_pointer_count"]
        );
    });
}

fn render_value(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    data: Value,
    text: impl FnOnce(&Value),
) {
    let result = ResultEnvelope::success(
        operation,
        context.operation_id,
        context.correlation_id,
        data,
    );
    match output {
        OutputFormat::Json => write_json(&result),
        OutputFormat::Text => text(&result.data),
    }
}

fn local_workspace(
    selected_workspace: Option<String>,
    operation: &str,
    context: ExecutionContext,
) -> Result<LocalWorkspace, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| root_problem(operation, context))?,
    };
    LocalWorkspace::new(root).map_err(|_| root_problem(operation, context))
}

fn optional_authority(
    authority: &AuthoritySelection,
    operation: &str,
    context: ExecutionContext,
) -> Result<(Option<PrincipalId>, Option<proof_application::DelegationId>), Box<Problem>> {
    match (&authority.principal, &authority.delegation) {
        (None, None) => Ok((None, None)),
        (Some(principal), Some(delegation)) => Ok((
            Some(parse(principal, "principal", operation, context)?),
            Some(parse(delegation, "delegation", operation, context)?),
        )),
        _ => Err(input_problem(
            operation,
            context,
            "--principal and --delegation must be supplied together".to_owned(),
        )),
    }
}

fn parse<T: std::str::FromStr>(
    value: &str,
    field: &str,
    operation: &str,
    context: ExecutionContext,
) -> Result<T, Box<Problem>>
where
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|error: T::Err| {
        input_problem(operation, context, format!("invalid {field}: {error}"))
    })
}

fn parse_many<T: std::str::FromStr>(
    values: &[String],
    field: &str,
    operation: &str,
    context: ExecutionContext,
) -> Result<Vec<T>, Box<Problem>>
where
    T::Err: std::fmt::Display,
{
    values
        .iter()
        .map(|value| parse(value, field, operation, context))
        .collect()
}

fn optional_id(
    value: Option<String>,
    operation: &str,
    context: ExecutionContext,
) -> Result<IdempotencyKey, Box<Problem>> {
    value.map_or_else(
        || Ok(generated_idempotency_key()),
        |value| parse(&value, "idempotency-key", operation, context),
    )
}

fn generated_operational_id<T: std::str::FromStr>() -> T
where
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7()
        .to_string()
        .parse()
        .expect("generated UUIDv7 must satisfy operational identity")
}

fn now(
    operation: &str,
    context: ExecutionContext,
) -> Result<proof_application::Timestamp, Box<Problem>> {
    current_timestamp().map_err(|_| internal_problem(operation, context))
}

fn root_problem(operation: &str, context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        operation,
        context,
        false,
    )
}

fn input_problem(operation: &str, context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The supplied command input is invalid",
        "proof.input.schema_mismatch",
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn internal_problem(operation: &str, context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:internal",
        "The operation could not be completed",
        "proof.internal",
        operation,
        context,
        false,
    )
}

fn environment_problem(
    error: &EnvironmentError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        EnvironmentError::Unauthenticated => auth_mapping(),
        EnvironmentError::NotFound => not_found_mapping("Environment"),
        EnvironmentError::AlreadyExists => (
            "urn:proof:problem:state-conflict",
            "The Environment already exists with different configuration",
            "proof.state.conflict",
            false,
        ),
        EnvironmentError::InvalidConfiguration => validation_mapping("Environment configuration"),
        EnvironmentError::IdempotencyKeyReused => idempotency_mapping(),
        EnvironmentError::Integrity(_) => integrity_mapping("Environment"),
        EnvironmentError::Storage(_) => storage_mapping("Environment"),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

fn release_problem(
    error: &ReleaseError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        ReleaseError::Unauthenticated => auth_mapping(),
        ReleaseError::UnsupportedVersion => unsupported_version_mapping(),
        ReleaseError::NotFound => not_found_mapping("Release"),
        ReleaseError::PolicyDenied => (
            "urn:proof:problem:policy-denied",
            "Release policy denied the requested operation",
            "proof.policy.denied",
            false,
        ),
        ReleaseError::InvalidRollbackTarget => validation_mapping("rollback target"),
        ReleaseError::StateConflict => (
            "urn:proof:problem:state-conflict",
            "The Environment release pointer changed concurrently",
            "proof.state.conflict",
            false,
        ),
        ReleaseError::IdempotencyKeyReused => idempotency_mapping(),
        ReleaseError::Signing(_) | ReleaseError::Storage(_) => storage_mapping("Release"),
        ReleaseError::Integrity(_) => integrity_mapping("Release"),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

fn query_problem(
    error: &QueryReleasedObjectsError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        QueryReleasedObjectsError::Unauthenticated => auth_mapping(),
        QueryReleasedObjectsError::UnsupportedVersion => unsupported_version_mapping(),
        QueryReleasedObjectsError::Denied => (
            "urn:proof:problem:authority-denied",
            "The released Object query is outside delegated authority",
            "proof.auth.denied",
            false,
        ),
        QueryReleasedObjectsError::InvalidQuery => validation_mapping("released Object query"),
        QueryReleasedObjectsError::NotFound => not_found_mapping("released Object"),
        QueryReleasedObjectsError::Integrity(_) => integrity_mapping("released Object"),
        QueryReleasedObjectsError::Storage(_) => storage_mapping("released Object"),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

fn content_read_problem(
    error: &LocalizedContentError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let mapping = match error {
        LocalizedContentError::Unauthenticated => auth_mapping(),
        LocalizedContentError::UnsupportedVersion => unsupported_version_mapping(),
        LocalizedContentError::NotFound if operation == "schema.get" => (
            "urn:proof:problem:schema-not-found",
            "The exact Schema version was not found",
            "proof.schema.not_found",
            false,
        ),
        LocalizedContentError::SchemaNotFound => (
            "urn:proof:problem:schema-not-found",
            "Schema not found",
            "proof.schema.not_found",
            false,
        ),
        LocalizedContentError::NotFound => not_found_mapping("Environment or released Object"),
        LocalizedContentError::InvalidInput | LocalizedContentError::LimitExceeded => {
            return input_problem(operation, context, error.to_string());
        }
        LocalizedContentError::Integrity(_) => integrity_mapping("content register"),
        LocalizedContentError::Storage(_) => storage_mapping("content register"),
        _ => return internal_problem(operation, context),
    };
    mapped_problem(
        mapping.0, mapping.1, mapping.2, operation, context, mapping.3,
    )
}

fn rebuild_problem(
    error: &RebuildProjectionsError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        RebuildProjectionsError::Unauthenticated => auth_mapping(),
        RebuildProjectionsError::Integrity(_) => integrity_mapping("projection rebuild"),
        RebuildProjectionsError::Storage(_) => storage_mapping("projection rebuild"),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

const fn auth_mapping() -> (&'static str, &'static str, &'static str, bool) {
    (
        "urn:proof:problem:authentication-required",
        "The current identity is not authenticated",
        "proof.auth.unauthenticated",
        false,
    )
}

const fn unsupported_version_mapping() -> (&'static str, &'static str, &'static str, bool) {
    (
        "urn:proof:problem:unsupported-version",
        "The v1 operation is unsupported for the current artifact version",
        "proof.input.unsupported_version",
        false,
    )
}

fn not_found_mapping(resource: &str) -> (&'static str, &'static str, &'static str, bool) {
    match resource {
        "Environment" => (
            "urn:proof:problem:resource-not-found",
            "The requested Environment was not found",
            "proof.resource.not_found",
            false,
        ),
        "Release" => (
            "urn:proof:problem:resource-not-found",
            "The requested Release resource was not found",
            "proof.resource.not_found",
            false,
        ),
        _ => (
            "urn:proof:problem:resource-not-found",
            "A requested released Object resource was not found",
            "proof.resource.not_found",
            false,
        ),
    }
}

fn validation_mapping(resource: &str) -> (&'static str, &'static str, &'static str, bool) {
    match resource {
        "Environment configuration" => (
            "urn:proof:problem:validation-failed",
            "The Environment configuration is invalid",
            "proof.validation.failed",
            false,
        ),
        "rollback target" => (
            "urn:proof:problem:validation-failed",
            "The rollback target is invalid for this Environment",
            "proof.validation.failed",
            false,
        ),
        _ => (
            "urn:proof:problem:validation-failed",
            "The released Object query is invalid",
            "proof.validation.failed",
            false,
        ),
    }
}

const fn idempotency_mapping() -> (&'static str, &'static str, &'static str, bool) {
    (
        "urn:proof:problem:idempotency-key-reused",
        "The idempotency key was reused with different input",
        "proof.idempotency.key_reused",
        false,
    )
}

fn integrity_mapping(resource: &str) -> (&'static str, &'static str, &'static str, bool) {
    match resource {
        "Release" => (
            "urn:proof:problem:evidence-incomplete",
            "Release evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        "projection rebuild" => (
            "urn:proof:problem:evidence-incomplete",
            "Projection rebuild evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        _ => (
            "urn:proof:problem:evidence-incomplete",
            "Persisted evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
    }
}

fn storage_mapping(resource: &str) -> (&'static str, &'static str, &'static str, bool) {
    match resource {
        "Release" => (
            "urn:proof:problem:dependency-unavailable",
            "Release storage or signing is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
        "projection rebuild" => (
            "urn:proof:problem:dependency-unavailable",
            "Projection storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
        _ => (
            "urn:proof:problem:dependency-unavailable",
            "Local Workspace storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    }
}

fn mapped_problem(
    problem_type: &str,
    title: &str,
    code: &str,
    operation: &str,
    context: ExecutionContext,
    retryable: bool,
) -> Box<Problem> {
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.retryable = retryable;
    Box::new(problem)
}
