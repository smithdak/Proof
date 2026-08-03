#![forbid(unsafe_code)]

use std::{io, path::PathBuf, process};

use clap::{Parser, Subcommand, ValueEnum};
use proof_application::{
    CorrelationId, ExitCode, OperationId, Problem, ResultEnvelope, StatusData,
};
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
    /// Report the current implementation and Workspace status.
    Status,
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
    let exit_code = match run(cli) {
        Ok(exit_code) => exit_code,
        Err(problem) => render_problem(&problem),
    };
    process::exit(exit_code as i32);
}

fn run(cli: Cli) -> Result<ExitCode, Box<Problem>> {
    let Cli {
        correlation_id,
        output,
        command,
        ..
    } = cli;
    let operation_id = generated_operation_id();
    let correlation_id = match correlation_id {
        Some(value) => value.parse::<CorrelationId>().map_err(|error| {
            let generated_correlation_id = generated_correlation_id();
            let mut problem = Problem::new(
                "urn:proof:problem:input-schema-mismatch",
                "The supplied correlation identifier is invalid",
                "proof.input.schema_mismatch",
                "status",
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
        Command::Status => render_status(output, context),
    };
    Ok(exit_code)
}

fn render_status(output: OutputFormat, context: ExecutionContext) -> ExitCode {
    let result = ResultEnvelope::success(
        "status",
        context.operation_id,
        context.correlation_id,
        StatusData::foundation(),
    );

    match output {
        OutputFormat::Text => {
            println!("Proof {}", result.meta.proof_version);
            println!("implementation: {}", result.data.implementation_stage);
            println!("workspace selected: {}", result.data.workspace_selected);
        }
        OutputFormat::Json => write_json(&result),
    }

    ExitCode::Success
}

fn render_problem(problem: &Problem) -> ExitCode {
    let exit_code = problem.exit_code();
    write_json_to(io::stderr().lock(), &problem);
    exit_code
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
