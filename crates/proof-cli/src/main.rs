#![forbid(unsafe_code)]

use std::{
    env, fs,
    io::{self, Read},
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand, ValueEnum};
use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, AddedChangeSetEdits, ArtifactKind,
    ChangeSetId, ChangeSetIntent, ContentDigest, CorrelationId, CreateChangeSetCommand,
    CreateChangeSetError, DraftChangeSet, EditId, ExitCode, IdempotencyKey,
    InitializeWorkspaceCommand, OperationId, PrincipalId, Problem, ResultEnvelope,
    SchemaCreateEdit, SchemaId, SchemaVersion, StatusData, Timestamp, WorkspaceId,
    WorkspaceInitializationError, WorkspaceStatus, WorkspaceStatusError, add_changeset_edits,
    create_changeset, initialize_workspace, workspace_status,
};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_local::LocalWorkspace;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "proof",
    version,
    about = "Governed, verifiable structured content",
    long_about = None
)]
struct Cli {
    /// Select a Workspace by path or identifier.
    #[arg(long, global = true, value_name = "PATH|ID")]
    workspace: Option<String>,

    /// Select a configuration and credential profile.
    #[arg(long, global = true)]
    profile: Option<String>,

    /// Select an operating Principal when policy permits.
    #[arg(long, global = true)]
    principal: Option<String>,

    /// Present an explicit Delegation by identifier or path.
    #[arg(long, global = true, value_name = "ID|PATH")]
    delegation: Option<PathBuf>,

    /// Select the result projection.
    #[arg(long, global = true, value_enum, default_value_t)]
    output: OutputFormat,

    /// Control terminal color output.
    #[arg(long, global = true, value_enum, default_value_t)]
    color: ColorChoice,

    /// Suppress non-result output.
    #[arg(long, global = true)]
    quiet: bool,

    /// Never prompt for missing input.
    #[arg(long, global = true)]
    no_input: bool,

    /// Supply or propagate a `UUIDv7` correlation identifier.
    #[arg(long, global = true)]
    correlation_id: Option<String>,

    /// Bound the application operation with a unit-bearing duration.
    #[arg(long, global = true)]
    timeout: Option<String>,

    /// Emit local diagnostic tracing to stderr.
    #[arg(long, global = true)]
    trace: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a local Workspace in the selected directory.
    Init,
    /// Report the current implementation and Workspace status.
    Status,
    /// Work with atomic, intent-scoped governed proposals.
    Changeset {
        #[command(subcommand)]
        action: ChangeSetAction,
    },
}

#[derive(Debug, Subcommand)]
enum ChangeSetAction {
    /// Create an empty draft bound to an exact base state.
    Create {
        /// Declare why this governed proposal exists.
        #[arg(long)]
        intent: String,
        /// Require an exact Known State digest; defaults to current state.
        #[arg(long)]
        base_state: Option<String>,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Atomically append typed Edits from an NDJSON file or stdin.
    Add {
        /// Target draft `ChangeSet` `UUIDv7`.
        changeset_id: String,
        /// Read typed Edit records from this file, or `-` for stdin.
        #[arg(long)]
        file: PathBuf,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

impl Command {
    const fn operation(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Status => "status",
            Self::Changeset {
                action: ChangeSetAction::Create { .. },
            } => "changeset.create",
            Self::Changeset {
                action: ChangeSetAction::Add { .. },
            } => "changeset.add",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum OutputFormat {
    /// Human-oriented text.
    #[default]
    Text,
    /// One stable JSON result envelope.
    Json,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum ColorChoice {
    /// Enable color for an interactive terminal.
    #[default]
    Auto,
    /// Always enable color.
    Always,
    /// Never enable color.
    Never,
}

#[derive(Clone, Copy)]
struct ExecutionContext {
    operation_id: OperationId,
    correlation_id: CorrelationId,
}

fn main() {
    let cli = Cli::parse();
    let output = cli.output;
    let exit_code = match run(cli) {
        Ok(exit_code) => exit_code,
        Err(problem) => render_problem(output, &problem),
    };
    process::exit(exit_code as i32);
}

fn run(cli: Cli) -> Result<ExitCode, Box<Problem>> {
    let Cli {
        workspace,
        correlation_id,
        output,
        command,
        ..
    } = cli;
    let operation = command.operation();
    let operation_id = generated_operation_id();
    let correlation_id = match correlation_id {
        Some(value) => value.parse::<CorrelationId>().map_err(|error| {
            let generated_correlation_id = generated_correlation_id();
            let mut problem = Problem::new(
                "urn:proof:problem:input-schema-mismatch",
                "The supplied correlation identifier is invalid",
                "proof.input.schema_mismatch",
                operation,
                operation_id,
                generated_correlation_id,
            );
            problem.detail = Some(error.to_string());
            Box::new(problem)
        })?,
        None => generated_correlation_id(),
    };
    let context = ExecutionContext {
        operation_id,
        correlation_id,
    };

    let exit_code = match command {
        Command::Init => initialize_local_workspace(output, context, workspace)?,
        Command::Status => inspect_local_workspace(output, context, workspace)?,
        Command::Changeset {
            action:
                ChangeSetAction::Create {
                    intent,
                    base_state,
                    idempotency_key,
                },
        } => create_local_changeset(
            output,
            context,
            workspace,
            intent,
            base_state,
            idempotency_key,
        )?,
        Command::Changeset {
            action:
                ChangeSetAction::Add {
                    changeset_id,
                    file,
                    idempotency_key,
                },
        } => add_local_changeset_edits(
            output,
            context,
            workspace,
            &changeset_id,
            &file,
            idempotency_key,
        )?,
    };
    Ok(exit_code)
}

fn render_status(output: OutputFormat, context: ExecutionContext, data: StatusData) -> ExitCode {
    let mut result =
        ResultEnvelope::success("status", context.operation_id, context.correlation_id, data);
    result
        .meta
        .workspace_id
        .clone_from(&result.data.workspace_id);
    result
        .meta
        .principal_id
        .clone_from(&result.data.principal_id);

    match output {
        OutputFormat::Text => {
            println!("Proof {}", result.meta.proof_version);
            println!("implementation: {}", result.data.implementation_stage);
            println!("workspace selected: {}", result.data.workspace_selected);
            println!(
                "workspace initialized: {}",
                result.data.workspace_initialized
            );
            if let Some(workspace_id) = &result.data.workspace_id {
                println!("workspace id: {workspace_id}");
            }
            if let Some(principal_id) = &result.data.principal_id {
                println!("principal id: {principal_id}");
            }
            if let Some(sequence) = result.data.authoritative_sequence {
                println!("authoritative sequence: {sequence}");
            }
            if let Some(state_digest) = &result.data.state_digest {
                println!("state digest: {state_digest}");
            }
        }
        OutputFormat::Json => write_json(&result),
    }

    ExitCode::Success
}

fn inspect_local_workspace(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let explicitly_selected = selected_workspace.is_some();
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| status_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| status_root_problem(context))?;
    let status =
        workspace_status(&repository).map_err(|error| workspace_status_problem(&error, context))?;
    let workspace_selected =
        explicitly_selected || matches!(status, WorkspaceStatus::Initialized(_));
    let data = StatusData::from_workspace(workspace_selected, status);
    Ok(render_status(output, context, data))
}

fn status_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "status",
        context.operation_id,
        context.correlation_id,
    ))
}

fn workspace_status_problem(
    error: &WorkspaceStatusError,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        WorkspaceStatusError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        WorkspaceStatusError::Incomplete | WorkspaceStatusError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The selected Workspace could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        WorkspaceStatusError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local Workspace storage could not be inspected",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "status",
        context.operation_id,
        context.correlation_id,
    );
    problem.retryable = retryable;
    Box::new(problem)
}

fn initialize_local_workspace(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| {
            workspace_problem(
                WorkspaceInitializationError::RootUnavailable(
                    "the current directory is unavailable".to_owned(),
                ),
                context,
            )
        })?,
    };
    let repository =
        LocalWorkspace::new(&root).map_err(|error| workspace_problem(error, context))?;
    let workspace_id = generated_workspace_id();
    let bootstrap_principal_id = generated_principal_id();
    let initialized = initialize_workspace(
        &repository,
        InitializeWorkspaceCommand {
            workspace_id,
            bootstrap_principal_id,
        },
    )
    .map_err(|error| workspace_problem(error, context))?;
    let data = InitializedWorkspaceData {
        workspace_id: initialized.workspace_id.to_string(),
        principal_id: initialized.principal_id.to_string(),
        workspace_root: repository.root().display().to_string(),
        config_path: repository.config_path().display().to_string(),
        database_path: repository.database_path().display().to_string(),
    };
    let mut result =
        ResultEnvelope::success("init", context.operation_id, context.correlation_id, data);
    result.meta.workspace_id = Some(initialized.workspace_id.to_string());
    result.meta.principal_id = Some(initialized.principal_id.to_string());

    match output {
        OutputFormat::Text => {
            println!("Initialized Proof Workspace {}", result.data.workspace_id);
            println!("principal: {}", result.data.principal_id);
            println!("root: {}", result.data.workspace_root);
            println!("configuration: {}", result.data.config_path);
            println!("database: {}", result.data.database_path);
        }
        OutputFormat::Json => write_json(&result),
    }
    Ok(ExitCode::Success)
}

fn workspace_problem(
    error: WorkspaceInitializationError,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, detail, retryable) = match error {
        WorkspaceInitializationError::AlreadyExists => (
            "urn:proof:problem:state-conflict",
            "A Workspace is already initialized at the selected location",
            "proof.state.conflict",
            None,
            false,
        ),
        WorkspaceInitializationError::RootUnavailable(detail) => (
            "urn:proof:problem:resource-not-found",
            "The selected Workspace root is unavailable",
            "proof.resource.not_found",
            Some(detail),
            false,
        ),
        WorkspaceInitializationError::IdentityUnavailable(detail) => (
            "urn:proof:problem:authentication-required",
            "The local operating-system identity could not be authenticated",
            "proof.auth.unauthenticated",
            Some(detail),
            false,
        ),
        WorkspaceInitializationError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local Workspace storage could not be initialized",
            "proof.dependency.unavailable",
            None,
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "init",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = detail;
    problem.retryable = retryable;
    Box::new(problem)
}

fn create_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    intent: String,
    requested_base_state: Option<String>,
    idempotency_key: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| changeset_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| changeset_root_problem(context))?;
    let intent = ChangeSetIntent::new(intent)
        .map_err(|error| changeset_input_problem(context, error.to_string()))?;
    let requested_base_state = requested_base_state
        .map(|value| {
            value
                .parse::<ContentDigest>()
                .map_err(|error| changeset_input_problem(context, error.to_string()))
        })
        .transpose()?;
    let idempotency_key = idempotency_key
        .map(|value| {
            value
                .parse::<IdempotencyKey>()
                .map_err(|error| changeset_input_problem(context, error.to_string()))
        })
        .transpose()?
        .unwrap_or_else(generated_idempotency_key);
    let command = CreateChangeSetCommand {
        changeset_id: generated_changeset_id(),
        intent,
        requested_base_state,
        idempotency_key,
        created_at: current_timestamp()
            .map_err(|detail| internal_problem("changeset.create", context, detail))?,
    };
    let draft = create_changeset(&repository, command)
        .map_err(|error| changeset_problem(&error, context))?;
    render_created_changeset(output, context, &draft);
    Ok(ExitCode::Success)
}

fn render_created_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    draft: &DraftChangeSet,
) {
    let data = CreatedChangeSetData::from(draft);
    let mut result = ResultEnvelope::success(
        "changeset.create",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(draft.workspace_id.to_string());
    result.meta.principal_id = Some(draft.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("Created ChangeSet {}", result.data.changeset_id);
            println!("status: {}", result.data.status);
            println!("intent: {}", result.data.intent);
            println!("base state: {}", result.data.base_state);
            println!("idempotency key: {}", result.data.idempotency_key);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn changeset_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.create",
        context.operation_id,
        context.correlation_id,
    ))
}

fn changeset_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet creation input is invalid",
        "proof.input.schema_mismatch",
        "changeset.create",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn changeset_problem(error: &CreateChangeSetError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        CreateChangeSetError::WorkspaceUninitialized => (
            "urn:proof:problem:resource-not-found",
            "The selected location is not an initialized Workspace",
            "proof.resource.not_found",
            false,
        ),
        CreateChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        CreateChangeSetError::BaseStateConflict => (
            "urn:proof:problem:state-conflict",
            "The requested base state is not current",
            "proof.state.conflict",
            false,
        ),
        CreateChangeSetError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        CreateChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The selected Workspace could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        CreateChangeSetError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.create",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, CreateChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

fn internal_problem(operation: &str, context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:internal",
        "Proof could not construct the operation safely",
        "proof.internal.error",
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn add_local_changeset_edits(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
    file: &std::path::Path,
    idempotency_key: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| edit_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| edit_root_problem(context))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| edit_input_problem(context, error.to_string()))?;
    let idempotency_key = idempotency_key
        .map(|value| {
            value
                .parse::<IdempotencyKey>()
                .map_err(|error| edit_input_problem(context, error.to_string()))
        })
        .transpose()?
        .unwrap_or_else(generated_idempotency_key);
    let bytes = read_edit_source(file).map_err(|error| edit_input_problem(context, error))?;
    let edits = parse_edit_records(&bytes).map_err(|error| edit_input_problem(context, error))?;
    let result = add_changeset_edits(
        &repository,
        AddChangeSetEditsCommand {
            changeset_id,
            edits,
            idempotency_key,
        },
    )
    .map_err(|error| edit_problem(&error, context))?;
    render_added_edits(output, context, &result, idempotency_key);
    Ok(ExitCode::Success)
}

fn render_added_edits(
    output: OutputFormat,
    context: ExecutionContext,
    added: &AddedChangeSetEdits,
    idempotency_key: IdempotencyKey,
) {
    let data = AddedEditsData {
        changeset_id: added.changeset_id.to_string(),
        first_ordinal: added.first_ordinal,
        edit_ids: added.edit_ids.iter().map(ToString::to_string).collect(),
        added_count: added.edit_ids.len(),
        total_edit_count: added.total_edit_count,
        idempotency_key: idempotency_key.to_string(),
    };
    let mut result = ResultEnvelope::success(
        "changeset.add",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(added.workspace_id.to_string());
    result.meta.principal_id = Some(added.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!(
                "Added {} Edit(s) to ChangeSet {}",
                result.data.added_count, result.data.changeset_id
            );
            println!("first ordinal: {}", result.data.first_ordinal);
            println!("total edits: {}", result.data.total_edit_count);
            println!("idempotency key: {}", result.data.idempotency_key);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn edit_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.add",
        context.operation_id,
        context.correlation_id,
    ))
}

fn edit_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The Edit input is invalid",
        "proof.input.schema_mismatch",
        "changeset.add",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn edit_problem(error: &AddChangeSetEditsError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        AddChangeSetEditsError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        AddChangeSetEditsError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        AddChangeSetEditsError::NotDraft => (
            "urn:proof:problem:changeset-not-draft",
            "Edits can only be appended to a draft ChangeSet",
            "proof.changeset.not_draft",
            false,
        ),
        AddChangeSetEditsError::InvalidBatchSize => (
            "urn:proof:problem:input-schema-mismatch",
            "The Edit batch size is invalid",
            "proof.input.schema_mismatch",
            false,
        ),
        AddChangeSetEditsError::DuplicateTarget => (
            "urn:proof:problem:changeset-duplicate-target",
            "The draft already contains the requested Schema version",
            "proof.changeset.duplicate_target",
            false,
        ),
        AddChangeSetEditsError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        AddChangeSetEditsError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The Edit batch or Workspace could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        AddChangeSetEditsError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.add",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, AddChangeSetEditsError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

const MAX_EDIT_INPUT_BYTES: u64 = 1_048_576;

fn read_edit_source(path: &std::path::Path) -> Result<Vec<u8>, String> {
    if path.as_os_str() == "-" {
        read_limited(io::stdin().lock())
    } else {
        let file = fs::File::open(path)
            .map_err(|error| format!("could not open Edit input `{}`: {error}", path.display()))?;
        read_limited(file)
    }
}

fn read_limited(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_EDIT_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read Edit input: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_EDIT_INPUT_BYTES {
        return Err(format!(
            "Edit input must not exceed {MAX_EDIT_INPUT_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

fn parse_edit_records(bytes: &[u8]) -> Result<Vec<SchemaCreateEdit>, String> {
    let mut edits = Vec::new();
    let mut lines = bytes.split(|byte| *byte == b'\n').peekable();
    let mut index = 0_usize;
    while let Some(raw_line) = lines.next() {
        index += 1;
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            if lines.peek().is_none() {
                continue;
            }
            return Err(format!("Edit record line {index} is empty"));
        }
        let value =
            parse_strict(line).map_err(|error| format!("Edit record line {index}: {error}"))?;
        let input: SchemaCreateEditInput = serde_json::from_value(value)
            .map_err(|error| format!("Edit record line {index}: {error}"))?;
        edits.push(input.into_edit(index)?);
        if edits.len() > proof_application::MAX_EDITS_PER_BATCH {
            return Err(format!(
                "Edit batch must not exceed {} records",
                proof_application::MAX_EDITS_PER_BATCH
            ));
        }
    }
    if edits.is_empty() {
        return Err("Edit input must contain at least one record".to_owned());
    }
    Ok(edits)
}

fn render_problem(output: OutputFormat, problem: &Problem) -> ExitCode {
    let exit_code = problem.exit_code();
    match output {
        OutputFormat::Json => write_json(problem),
        OutputFormat::Text => {
            eprintln!("error: {}", problem.title);
            if let Some(detail) = &problem.detail {
                eprintln!("{detail}");
            }
            eprintln!("code: {}", problem.code);
        }
    }
    exit_code
}

#[derive(Serialize)]
struct InitializedWorkspaceData {
    workspace_id: String,
    principal_id: String,
    workspace_root: String,
    config_path: String,
    database_path: String,
}

#[derive(Serialize)]
struct CreatedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    intent: String,
    base_authoritative_sequence: u64,
    base_state: String,
    idempotency_key: String,
    created_at: String,
    status: String,
    policy_profile: String,
    validation_profile: String,
    edit_count: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaCreateEditInput {
    api_version: String,
    kind: String,
    schema_id: String,
    schema_version: u32,
    document: serde_json::Value,
}

impl SchemaCreateEditInput {
    fn into_edit(self, line: usize) -> Result<SchemaCreateEdit, String> {
        if self.api_version != "proof.dev/edit/v1" {
            return Err(format!(
                "Edit record line {line}: unsupported api_version `{}`",
                self.api_version
            ));
        }
        if self.kind != "schema.create" {
            return Err(format!(
                "Edit record line {line}: unsupported kind `{}`",
                self.kind
            ));
        }
        let schema_id = SchemaId::new(self.schema_id)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        let schema_version = SchemaVersion::new(self.schema_version)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        let Some(document) = self.document.as_object() else {
            return Err(format!(
                "Edit record line {line}: Schema document root must be a JSON object"
            ));
        };
        if document.get("$schema").and_then(serde_json::Value::as_str)
            != Some("https://json-schema.org/draft/2020-12/schema")
        {
            return Err(format!(
                "Edit record line {line}: Schema document must declare JSON Schema Draft 2020-12"
            ));
        }
        let canonical = canonicalize(&self.document)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        let document_digest = digest(ArtifactKind::SchemaVersionV1, &canonical);
        Ok(SchemaCreateEdit {
            edit_id: generated_edit_id(),
            schema_id,
            schema_version,
            canonical_document: canonical.as_str().to_owned(),
            document_digest,
        })
    }
}

#[derive(Serialize)]
struct AddedEditsData {
    changeset_id: String,
    first_ordinal: u32,
    edit_ids: Vec<String>,
    added_count: usize,
    total_edit_count: u32,
    idempotency_key: String,
}

impl From<&DraftChangeSet> for CreatedChangeSetData {
    fn from(draft: &DraftChangeSet) -> Self {
        Self {
            changeset_id: draft.changeset_id.to_string(),
            workspace_id: draft.workspace_id.to_string(),
            principal_id: draft.principal_id.to_string(),
            intent: draft.intent.to_string(),
            base_authoritative_sequence: draft.base_authoritative_sequence,
            base_state: draft.base_state.to_string(),
            idempotency_key: draft.idempotency_key.to_string(),
            created_at: draft.created_at.to_string(),
            status: draft.status.to_string(),
            policy_profile: draft.policy_profile.clone(),
            validation_profile: draft.validation_profile.clone(),
            edit_count: draft.edit_count,
        }
    }
}

fn write_json(value: &impl Serialize) {
    write_json_to(io::stdout().lock(), value);
}

fn write_json_to(mut writer: impl io::Write, value: &impl Serialize) {
    if serde_json::to_writer(&mut writer, value).is_ok() {
        let _ = writeln!(writer);
    }
}

fn generated_operation_id() -> OperationId {
    OperationId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_correlation_id() -> CorrelationId {
    CorrelationId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_principal_id() -> PrincipalId {
    PrincipalId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_changeset_id() -> ChangeSetId {
    ChangeSetId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_edit_id() -> EditId {
    EditId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn generated_idempotency_key() -> IdempotencyKey {
    IdempotencyKey::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
}

fn current_timestamp() -> Result<Timestamp, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock precedes Unix epoch: {error}"))?;
    let nanoseconds = i128::try_from(duration.as_nanos())
        .map_err(|_| "system clock exceeds timestamp range".to_owned())?;
    Timestamp::from_unix_timestamp_nanos(nanoseconds).map_err(|error| error.to_string())
}
