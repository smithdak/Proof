#![forbid(unsafe_code)]

use std::{env, io, path::PathBuf, process};

use clap::{Parser, Subcommand, ValueEnum};
use proof_application::{
    CorrelationId, ExitCode, InitializeWorkspaceCommand, OperationId, PrincipalId, Problem,
    ResultEnvelope, StatusData, WorkspaceId, WorkspaceInitializationError, WorkspaceStatus,
    WorkspaceStatusError, initialize_workspace, workspace_status,
};
use proof_local::LocalWorkspace;
use serde::Serialize;
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
}

impl Command {
    const fn operation(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Status => "status",
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
