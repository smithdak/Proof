#![forbid(unsafe_code)]

mod auth_cli;
mod authority_cli;
mod evidence_cli;
mod localized_cli;
mod release_cli;

use std::{
    env, fs,
    io::{self, Read},
    path::PathBuf,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand, ValueEnum};
use proof_application::{
    AddChangeSetEditsCommand, AddChangeSetEditsError, AddedChangeSetEdits, ApprovalName,
    ApproveChangeSetCommand, ApproveChangeSetError, ApprovedChangeSet, ArtifactKind, ChangeSetEdit,
    ChangeSetId, ChangeSetIntent, CommitChangeSetCommand, CommitChangeSetError, CommittedChangeSet,
    ContentDigest, CorrelationId, CreateChangeSetCommand, CreateChangeSetError,
    CreateEditionCommand, CreateEditionError, DelegatedWorkspaceStatusCommand,
    DelegatedWorkspaceStatusError, DraftChangeSet, EditId, Edition, EditionId, ExitCode,
    IdempotencyKey, InitializeWorkspaceCommand, InspectChangeSetError, InspectedChangeSet,
    InspectedChangeSetEdit, ObjectCreateEdit, ObjectId, ObjectLifecycleState, ObjectRevision,
    OperationId, PrincipalId, Problem, ResultEnvelope, SchemaCreateEdit, SchemaId, SchemaVersion,
    StatusData, SubmitChangeSetCommand, SubmitChangeSetError, SubmittedChangeSet, Timestamp,
    ValidateChangeSetError, ValidatedChangeSet, WorkspaceId, WorkspaceInitializationError,
    WorkspaceStatus, WorkspaceStatusError, add_changeset_edits, approve_changeset,
    commit_changeset, create_changeset, create_edition, delegated_workspace_status,
    initialize_workspace, inspect_changeset, submit_changeset, validate_changeset,
    workspace_status,
};
use proof_attestation::{
    AttestationError, MAX_ENVELOPE_BYTES, parse_ed25519_key_id, verify_release_envelope,
};
use proof_canonical::{canonicalize, digest, object_revision_digest, parse_strict};
use proof_local::LocalWorkspace;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use auth_cli::AuthAction;
use authority_cli::{CapabilityAction, ContextAction, DelegationAction, PrincipalAction};
use evidence_cli::EvidenceAction;
use localized_cli::LocalizedAction;
use release_cli::{EnvironmentAction, ObjectAction, ProjectionAction, ReleaseAction};

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

    /// Present an explicit Delegation identifier.
    #[arg(long, global = true, value_name = "ID")]
    delegation: Option<String>,

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
    /// Sign or execute one bounded authenticated Agent invocation.
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Work with atomic, intent-scoped governed proposals.
    Changeset {
        #[command(subcommand)]
        action: ChangeSetAction,
    },
    /// Work with immutable accepted-state Editions.
    Edition {
        #[command(subcommand)]
        action: EditionAction,
    },
    /// Manage local human and Agent identities.
    Principal {
        #[command(subcommand)]
        action: PrincipalAction,
    },
    /// Manage bounded, expiring Agent authority.
    Delegation {
        #[command(subcommand)]
        action: DelegationAction,
    },
    /// Build and verify bounded agent `ContextPacks`.
    Context {
        #[command(subcommand)]
        action: ContextAction,
    },
    /// Discover stable application capabilities.
    Capability {
        #[command(subcommand)]
        action: CapabilityAction,
    },
    /// Manage versioned local release targets.
    Environment {
        #[command(subcommand)]
        action: EnvironmentAction,
    },
    /// Promote, inspect, roll back, and verify immutable Releases.
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// Export portable Release and authority-evidence closures.
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    /// Query immutable released content.
    Object {
        #[command(subcommand)]
        action: ObjectAction,
    },
    /// Inspect and rebuild derived state.
    Projection {
        #[command(subcommand)]
        action: ProjectionAction,
    },
    /// Operate the Human-only exact-locale content foundation.
    Localized {
        #[command(subcommand)]
        action: LocalizedAction,
    },
    /// Verify one canonical signed Proof envelope against caller-supplied trust.
    Verify {
        /// Canonical DSSE envelope file.
        #[arg(long)]
        file: PathBuf,
        /// Explicit trusted key identity (`ed25519:` followed by 64 lowercase hex characters).
        #[arg(long)]
        trusted_key_id: String,
        /// Expected domain-separated digest of the complete canonical envelope.
        #[arg(long)]
        expected_envelope_digest: String,
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
    /// Return the complete verified `ChangeSet` read model.
    Get {
        /// Target `ChangeSet` `UUIDv7`.
        changeset_id: String,
    },
    /// Return a deterministic projection of proposed effects.
    Diff {
        /// Target `ChangeSet` `UUIDv7`.
        changeset_id: String,
    },
    /// Validate the exact current proposal and persist deterministic evidence.
    Validate {
        /// Target `ChangeSet` `UUIDv7`.
        changeset_id: String,
    },
    /// Submit a validation-sealed proposal for governed review.
    Submit {
        /// Target ready `ChangeSet` `UUIDv7`.
        changeset_id: String,
    },
    /// Record explicit approval for an exact submitted proposal.
    Approve {
        /// Target submitted `ChangeSet` `UUIDv7`.
        changeset_id: String,
        /// Named approval requirement being satisfied.
        #[arg(long)]
        approval: String,
    },
    /// Atomically apply an approved proposal to authoritative state.
    Commit {
        /// Target approved `ChangeSet` `UUIDv7`.
        changeset_id: String,
        /// Supply the required `UUIDv7` retry key.
        #[arg(long)]
        idempotency_key: String,
    },
}

#[derive(Debug, Subcommand)]
enum EditionAction {
    /// Materialize current committed Known State as an immutable Edition.
    Create {
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
            Self::Auth {
                action: AuthAction::Sign { .. },
            } => "auth.sign",
            Self::Auth {
                action: AuthAction::Execute { .. },
            } => "auth.execute",
            Self::Changeset {
                action: ChangeSetAction::Create { .. },
            } => "changeset.create",
            Self::Changeset {
                action: ChangeSetAction::Add { .. },
            } => "changeset.add",
            Self::Changeset {
                action: ChangeSetAction::Get { .. },
            } => "changeset.get",
            Self::Changeset {
                action: ChangeSetAction::Diff { .. },
            } => "changeset.diff",
            Self::Changeset {
                action: ChangeSetAction::Validate { .. },
            } => "changeset.validate",
            Self::Changeset {
                action: ChangeSetAction::Submit { .. },
            } => "changeset.submit",
            Self::Changeset {
                action: ChangeSetAction::Approve { .. },
            } => "changeset.approve",
            Self::Changeset {
                action: ChangeSetAction::Commit { .. },
            } => "changeset.commit",
            Self::Edition {
                action: EditionAction::Create { .. },
            } => "edition.create",
            Self::Principal {
                action: PrincipalAction::CreateAgent { .. },
            } => "principal.create_agent",
            Self::Delegation {
                action: DelegationAction::Grant { .. },
            } => "delegation.grant",
            Self::Delegation {
                action: DelegationAction::Get { .. },
            } => "delegation.get",
            Self::Delegation {
                action: DelegationAction::Revoke { .. },
            } => "delegation.revoke",
            Self::Delegation {
                action: DelegationAction::Verify { .. },
            } => "delegation.verify",
            Self::Context {
                action: ContextAction::Build { .. },
            } => "context.build",
            Self::Context {
                action: ContextAction::Get { .. },
            } => "context.get",
            Self::Context {
                action: ContextAction::Verify { .. },
            } => "context.verify",
            Self::Capability {
                action: CapabilityAction::List,
            } => "capability.list",
            Self::Environment {
                action: EnvironmentAction::Create { .. },
            } => "environment.create",
            Self::Environment {
                action: EnvironmentAction::Get { .. },
            } => "environment.get",
            Self::Release {
                action: ReleaseAction::Create { .. },
            } => "release.create",
            Self::Release {
                action: ReleaseAction::Get { .. },
            } => "release.get",
            Self::Release {
                action: ReleaseAction::Rollback { .. },
            } => "release.rollback",
            Self::Release {
                action: ReleaseAction::Verify { .. },
            } => "release.verify",
            Self::Evidence {
                action: EvidenceAction::Export { .. },
            } => "evidence.export",
            Self::Object {
                action: ObjectAction::Query { .. },
            } => "object.query_released",
            Self::Projection {
                action: ProjectionAction::Rebuild { .. },
            } => "projection.rebuild",
            Self::Localized { action } => action.operation(),
            Self::Verify { .. } => "proof.verify",
        }
    }

    const fn accepts_explicit_authority(&self) -> bool {
        matches!(
            self,
            Self::Status | Self::Context { .. } | Self::Object { .. }
        )
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

#[derive(Debug)]
struct AuthoritySelection {
    principal: Option<String>,
    delegation: Option<String>,
}

impl AuthoritySelection {
    const fn is_explicit(&self) -> bool {
        self.principal.is_some() || self.delegation.is_some()
    }
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
        principal,
        delegation,
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

    let authority = AuthoritySelection {
        principal,
        delegation,
    };
    run_command(command, output, context, workspace, &authority)
}

#[expect(
    clippy::too_many_lines,
    reason = "the top-level exhaustive dispatch makes unsupported authority impossible to ignore"
)]
fn run_command(
    command: Command,
    output: OutputFormat,
    context: ExecutionContext,
    workspace: Option<String>,
    authority: &AuthoritySelection,
) -> Result<ExitCode, Box<Problem>> {
    if authority.is_explicit() && !command.accepts_explicit_authority() {
        return Err(explicit_authority_problem(command.operation(), context));
    }
    let exit_code = match command {
        Command::Init => initialize_local_workspace(output, context, workspace)?,
        Command::Status => inspect_local_workspace(output, context, workspace, authority)?,
        Command::Auth { action } => {
            auth_cli::run_auth(action, output, context, workspace.as_deref())?
        }
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
        Command::Changeset {
            action: ChangeSetAction::Get { changeset_id },
        } => inspect_local_changeset(
            output,
            context,
            workspace,
            &changeset_id,
            ChangeSetProjection::Get,
        )?,
        Command::Changeset {
            action: ChangeSetAction::Diff { changeset_id },
        } => inspect_local_changeset(
            output,
            context,
            workspace,
            &changeset_id,
            ChangeSetProjection::Diff,
        )?,
        Command::Changeset {
            action: ChangeSetAction::Validate { changeset_id },
        } => validate_local_changeset(output, context, workspace, &changeset_id)?,
        Command::Changeset {
            action: ChangeSetAction::Submit { changeset_id },
        } => submit_local_changeset(output, context, workspace, &changeset_id)?,
        Command::Changeset {
            action:
                ChangeSetAction::Approve {
                    changeset_id,
                    approval,
                },
        } => approve_local_changeset(output, context, workspace, &changeset_id, approval)?,
        Command::Changeset {
            action:
                ChangeSetAction::Commit {
                    changeset_id,
                    idempotency_key,
                },
        } => commit_local_changeset(output, context, workspace, &changeset_id, &idempotency_key)?,
        Command::Edition {
            action: EditionAction::Create { idempotency_key },
        } => create_local_edition(output, context, workspace, idempotency_key)?,
        Command::Principal { action } => {
            authority_cli::run_principal(action, output, context, workspace)?
        }
        Command::Delegation { action } => {
            authority_cli::run_delegation(action, output, context, workspace)?
        }
        Command::Context { action } => {
            authority_cli::run_context(action, output, context, workspace, authority)?
        }
        Command::Capability { action } => authority_cli::run_capability(action, output, context),
        Command::Environment { action } => {
            release_cli::run_environment(action, output, context, workspace)?
        }
        Command::Release { action } => {
            release_cli::run_release(action, output, context, workspace)?
        }
        Command::Evidence { action } => {
            evidence_cli::run_evidence(action, output, context, workspace)?
        }
        Command::Object { action } => {
            release_cli::run_object(action, output, context, workspace, authority)?
        }
        Command::Projection { action } => {
            release_cli::run_projection(action, output, context, workspace)?
        }
        Command::Localized { action } => {
            localized_cli::run_localized(action, output, context, workspace)?
        }
        Command::Verify {
            file,
            trusted_key_id,
            expected_envelope_digest,
        } => verify_offline_envelope(
            output,
            context,
            &file,
            &trusted_key_id,
            &expected_envelope_digest,
        )?,
    };
    Ok(exit_code)
}

fn verify_offline_envelope(
    output: OutputFormat,
    context: ExecutionContext,
    file: &std::path::Path,
    trusted_key_id: &str,
    expected_envelope_digest: &str,
) -> Result<ExitCode, Box<Problem>> {
    let bytes = read_envelope_file(file).map_err(|detail| {
        offline_verify_problem(
            "urn:proof:problem:input-schema-mismatch",
            "The Proof envelope could not be read",
            "proof.input.schema_mismatch",
            detail,
            context,
        )
    })?;
    let expected_digest = expected_envelope_digest
        .parse::<ContentDigest>()
        .map_err(|error| {
            offline_verify_problem(
                "urn:proof:problem:input-schema-mismatch",
                "The expected envelope digest is invalid",
                "proof.input.schema_mismatch",
                error.to_string(),
                context,
            )
        })?;
    parse_ed25519_key_id(trusted_key_id).map_err(|error| {
        offline_verify_problem(
            "urn:proof:problem:input-schema-mismatch",
            "The caller-supplied trusted key identifier is invalid",
            "proof.input.schema_mismatch",
            error.to_string(),
            context,
        )
    })?;
    let verified = verify_release_envelope(&bytes, expected_digest, trusted_key_id)
        .map_err(|error| map_attestation_problem(&error, context))?;
    let subjects = verified
        .parsed
        .statement
        .subject
        .iter()
        .map(|subject| {
            serde_json::json!({
                "name": subject.name,
                "digest": subject.digest,
            })
        })
        .collect::<Vec<_>>();
    let data = serde_json::json!({
        "envelope_digest": verified.parsed.envelope_digest.to_string(),
        "key_id": verified.key_id,
        "payload_type": verified.parsed.envelope.payload_type,
        "statement_type": verified.parsed.statement.statement_type,
        "predicate_type": verified.parsed.statement.predicate_type,
        "subjects": subjects,
        "canonical_envelope": true,
        "digest_valid": true,
        "signature_valid": true,
        "workspace_evidence_verified": false,
        "workspace_policy_verified": false,
    });
    let result = ResultEnvelope::success(
        "proof.verify",
        context.operation_id,
        context.correlation_id,
        data,
    );
    match output {
        OutputFormat::Json => write_json(&result),
        OutputFormat::Text => {
            println!("offline envelope verified: true");
            println!("envelope digest: {}", verified.parsed.envelope_digest);
            println!("trusted key id: {}", verified.key_id);
            println!("subjects: {}", verified.parsed.statement.subject.len());
            println!("workspace evidence verified: false");
            println!("workspace policy verified: false");
        }
    }
    Ok(ExitCode::Success)
}

fn read_envelope_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|error| {
        format!(
            "could not open Proof envelope `{}`: {error}",
            path.display()
        )
    })?;
    let max = u64::try_from(MAX_ENVELOPE_BYTES).expect("envelope bound fits u64");
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read Proof envelope: {error}"))?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(format!(
            "Proof envelope must not exceed {MAX_ENVELOPE_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

fn map_attestation_problem(error: &AttestationError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code) = match error {
        AttestationError::EnvelopeDigestMismatch => (
            "urn:proof:problem:digest-mismatch",
            "The Proof envelope digest does not match the expected digest",
            "proof.digest.mismatch",
        ),
        AttestationError::KeyIdMismatch
        | AttestationError::InvalidPublicKey
        | AttestationError::InvalidPublicKeyLength
        | AttestationError::InvalidSignatureLength
        | AttestationError::SignatureInvalid => (
            "urn:proof:problem:signature-invalid",
            "The Proof envelope signature could not be verified against caller-supplied trust",
            "proof.signature.invalid",
        ),
        AttestationError::EnvelopeTooLarge | AttestationError::PayloadTooLarge => (
            "urn:proof:problem:input-too-large",
            "The Proof envelope exceeds a bounded profile limit",
            "proof.input.too_large",
        ),
        _ => (
            "urn:proof:problem:artifact-invalid",
            "The Proof envelope violates the supported artifact profile",
            "proof.artifact.invalid",
        ),
    };
    offline_verify_problem(problem_type, title, code, error.to_string(), context)
}

fn offline_verify_problem(
    problem_type: &str,
    title: &str,
    code: &str,
    detail: String,
    context: ExecutionContext,
) -> Box<Problem> {
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "proof.verify",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn explicit_authority_problem(operation: &str, context: ExecutionContext) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:authority-denied",
        "Explicit Principal or Delegation selection is not supported for this operation",
        "proof.auth.denied",
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(
        "No operation was performed; remove --principal and --delegation or use a delegated read operation"
            .to_owned(),
    );
    Box::new(problem)
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
    authority: &AuthoritySelection,
) -> Result<ExitCode, Box<Problem>> {
    let explicitly_selected = selected_workspace.is_some();
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| status_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| status_root_problem(context))?;
    if authority.is_explicit() {
        let principal = authority.principal.as_deref().ok_or_else(|| {
            status_authority_input_problem(
                context,
                "--principal and --delegation must be supplied together".to_owned(),
            )
        })?;
        let delegation = authority.delegation.as_deref().ok_or_else(|| {
            status_authority_input_problem(
                context,
                "--principal and --delegation must be supplied together".to_owned(),
            )
        })?;
        let operating_principal_id = principal.parse::<PrincipalId>().map_err(|error| {
            status_authority_input_problem(context, format!("invalid principal: {error}"))
        })?;
        let delegation_id = delegation
            .parse::<proof_application::DelegationId>()
            .map_err(|error| {
                status_authority_input_problem(context, format!("invalid delegation: {error}"))
            })?;
        let evaluated_at = current_timestamp()
            .map_err(|detail| status_authority_input_problem(context, detail))?;
        let status = delegated_workspace_status(
            &repository,
            DelegatedWorkspaceStatusCommand {
                operating_principal_id,
                delegation_id,
                evaluated_at,
            },
        )
        .map_err(|error| delegated_status_problem(&error, context))?;
        let data = serde_json::json!({
            "workspace_id": status.workspace_id.to_string(),
            "principal_id": status.principal_id.to_string(),
            "delegation_id": status.delegation_id.to_string(),
            "storage_schema_version": status.storage_schema_version,
            "authoritative_sequence": status.authoritative_sequence,
            "state_digest": status.state_digest.to_string(),
            "authorization_decision_digest": status.authorization_decision_digest.to_string(),
        });
        let result =
            ResultEnvelope::success("status", context.operation_id, context.correlation_id, data);
        match output {
            OutputFormat::Json => write_json(&result),
            OutputFormat::Text => {
                println!("Workspace {}", status.workspace_id);
                println!("principal: {}", status.principal_id);
                println!("delegation: {}", status.delegation_id);
                println!("storage schema: {}", status.storage_schema_version);
                println!("authoritative sequence: {}", status.authoritative_sequence);
                println!("state digest: {}", status.state_digest);
                println!(
                    "authorization decision: {}",
                    status.authorization_decision_digest
                );
            }
        }
        return Ok(ExitCode::Success);
    }
    let status =
        workspace_status(&repository).map_err(|error| workspace_status_problem(&error, context))?;
    let workspace_selected =
        explicitly_selected || matches!(status, WorkspaceStatus::Initialized(_));
    let data = StatusData::from_workspace(workspace_selected, status);
    Ok(render_status(output, context, data))
}

fn status_authority_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The delegated status authority selection is invalid",
        "proof.input.schema_mismatch",
        "status",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn delegated_status_problem(
    error: &DelegatedWorkspaceStatusError,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        DelegatedWorkspaceStatusError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        DelegatedWorkspaceStatusError::Denied => (
            "urn:proof:problem:authority-denied",
            "Workspace status is outside delegated authority",
            "proof.auth.denied",
            false,
        ),
        DelegatedWorkspaceStatusError::Integrity(_) => (
            "urn:proof:problem:digest-mismatch",
            "The selected Workspace could not be verified",
            "proof.digest.mismatch",
            false,
        ),
        DelegatedWorkspaceStatusError::Storage(_) => (
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
    if matches!(error, DelegatedWorkspaceStatusError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
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
        CreateChangeSetError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 ChangeSet operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
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
        AddChangeSetEditsError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 Edit operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
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

fn parse_edit_records(bytes: &[u8]) -> Result<Vec<ChangeSetEdit>, String> {
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
        let is_object_create = value
            .as_object()
            .and_then(|record| record.get("kind"))
            .and_then(serde_json::Value::as_str)
            == Some("object.create");
        let edit = if is_object_create {
            let input: ObjectCreateEditInput = serde_json::from_value(value)
                .map_err(|error| format!("Edit record line {index}: {error}"))?;
            ChangeSetEdit::ObjectCreate(input.into_edit(index)?)
        } else {
            let input: SchemaCreateEditInput = serde_json::from_value(value)
                .map_err(|error| format!("Edit record line {index}: {error}"))?;
            ChangeSetEdit::SchemaCreate(input.into_edit(index)?)
        };
        edits.push(edit);
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

fn validate_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| validation_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| validation_root_problem(context))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| validation_input_problem(context, error.to_string()))?;
    let validated = validate_changeset(&repository, changeset_id)
        .map_err(|error| validation_problem(&error, context))?;
    if !validated.valid {
        return Err(validation_failed_problem(&validated, context));
    }
    render_validated_changeset(output, context, &validated);
    Ok(ExitCode::Success)
}

fn render_validated_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    validated: &ValidatedChangeSet,
) {
    let data = ValidatedChangeSetData::from(validated);
    let mut result = ResultEnvelope::success(
        "changeset.validate",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(validated.workspace_id.to_string());
    result.meta.principal_id = Some(validated.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {} is valid", result.data.changeset_id);
            println!("ChangeSet digest: {}", result.data.changeset_digest);
            println!(
                "validation results: {}",
                result.data.validation_results_digest
            );
            println!("edits: {}", result.data.edit_count);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn validation_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.validate",
        context.operation_id,
        context.correlation_id,
    ))
}

fn validation_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet identifier is invalid",
        "proof.input.schema_mismatch",
        "changeset.validate",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn validation_problem(error: &ValidateChangeSetError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        ValidateChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        ValidateChangeSetError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 validation operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
            false,
        ),
        ValidateChangeSetError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        ValidateChangeSetError::NotValidatable => (
            "urn:proof:problem:changeset-not-validatable",
            "The ChangeSet is no longer in a validatable lifecycle state",
            "proof.changeset.not_validatable",
            false,
        ),
        ValidateChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The requested ChangeSet could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        ValidateChangeSetError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet validation storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.validate",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, ValidateChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

fn validation_failed_problem(
    validated: &ValidatedChangeSet,
    context: ExecutionContext,
) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:validation-failed",
        "The ChangeSet failed validation",
        "proof.validation.failed",
        "changeset.validate",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(format!(
        "validation evidence {} covers ChangeSet {}",
        validated.validation_results_digest, validated.changeset_digest
    ));
    problem.findings.clone_from(&validated.findings);
    Box::new(problem)
}

fn submit_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| submission_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| submission_root_problem(context))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| submission_input_problem(context, error.to_string()))?;
    let submitted_at = current_timestamp()
        .map_err(|error| internal_problem("changeset.submit", context, error))?;
    let submitted = submit_changeset(
        &repository,
        SubmitChangeSetCommand {
            changeset_id,
            submitted_at,
        },
    )
    .map_err(|error| submission_problem(&error, context))?;
    render_submitted_changeset(output, context, &submitted);
    Ok(ExitCode::Success)
}

fn render_submitted_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    submitted: &SubmittedChangeSet,
) {
    let data = SubmittedChangeSetData::from(submitted);
    let mut result = ResultEnvelope::success(
        "changeset.submit",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(submitted.workspace_id.to_string());
    result.meta.principal_id = Some(submitted.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {} submitted", result.data.changeset_id);
            println!("ChangeSet digest: {}", result.data.changeset_digest);
            println!(
                "validation results: {}",
                result.data.validation_results_digest
            );
            println!("submitted at: {}", result.data.submitted_at);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn submission_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.submit",
        context.operation_id,
        context.correlation_id,
    ))
}

fn submission_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet identifier is invalid",
        "proof.input.schema_mismatch",
        "changeset.submit",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn submission_problem(error: &SubmitChangeSetError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        SubmitChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        SubmitChangeSetError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 submission operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
            false,
        ),
        SubmitChangeSetError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        SubmitChangeSetError::NotReady => (
            "urn:proof:problem:changeset-not-ready",
            "Only a ready ChangeSet can be submitted",
            "proof.changeset.not_ready",
            false,
        ),
        SubmitChangeSetError::ValidationEvidenceMissing => (
            "urn:proof:problem:validation-evidence-missing",
            "Exact valid ChangeSet evidence is required before submission",
            "proof.validation.evidence_missing",
            false,
        ),
        SubmitChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The ChangeSet submission could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        SubmitChangeSetError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet submission storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.submit",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, SubmitChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

fn approve_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
    approval: String,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| approval_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| approval_root_problem(context))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| approval_input_problem(context, error.to_string()))?;
    let approval = ApprovalName::new(approval)
        .map_err(|error| approval_input_problem(context, error.to_string()))?;
    let approved_at = current_timestamp()
        .map_err(|error| internal_problem("changeset.approve", context, error))?;
    let approved = approve_changeset(
        &repository,
        ApproveChangeSetCommand {
            changeset_id,
            approval,
            approved_at,
        },
    )
    .map_err(|error| approval_problem(&error, context))?;
    render_approved_changeset(output, context, &approved);
    Ok(ExitCode::Success)
}

fn render_approved_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    approved: &ApprovedChangeSet,
) {
    let data = ApprovedChangeSetData::from(approved);
    let mut result = ResultEnvelope::success(
        "changeset.approve",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(approved.workspace_id.to_string());
    result.meta.principal_id = Some(approved.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {} approved", result.data.changeset_id);
            println!("approval: {}", result.data.approval);
            println!("ChangeSet digest: {}", result.data.changeset_digest);
            println!("approved at: {}", result.data.approved_at);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn approval_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.approve",
        context.operation_id,
        context.correlation_id,
    ))
}

fn approval_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet approval input is invalid",
        "proof.input.schema_mismatch",
        "changeset.approve",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn approval_problem(error: &ApproveChangeSetError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        ApproveChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        ApproveChangeSetError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 approval operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
            false,
        ),
        ApproveChangeSetError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        ApproveChangeSetError::NotSubmitted => (
            "urn:proof:problem:changeset-not-submitted",
            "Only a submitted ChangeSet can be approved",
            "proof.changeset.not_submitted",
            false,
        ),
        ApproveChangeSetError::EvidenceMissing => (
            "urn:proof:problem:evidence-incomplete",
            "Exact submitted ChangeSet evidence is required before approval",
            "proof.evidence.incomplete",
            false,
        ),
        ApproveChangeSetError::ApprovalConflict => (
            "urn:proof:problem:approval-conflict",
            "A different named approval was already recorded",
            "proof.changeset.approval_conflict",
            false,
        ),
        ApproveChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The ChangeSet approval could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        ApproveChangeSetError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet approval storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.approve",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, ApproveChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

fn commit_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
    idempotency_key: &str,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| commit_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| commit_root_problem(context))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| commit_input_problem(context, error.to_string()))?;
    let idempotency_key = idempotency_key
        .parse::<IdempotencyKey>()
        .map_err(|error| commit_input_problem(context, error.to_string()))?;
    let committed_at = current_timestamp()
        .map_err(|error| internal_problem("changeset.commit", context, error))?;
    let committed = commit_changeset(
        &repository,
        CommitChangeSetCommand {
            changeset_id,
            idempotency_key,
            committed_at,
        },
    )
    .map_err(|error| commit_problem(&error, context))?;
    render_committed_changeset(output, context, &committed);
    Ok(ExitCode::Success)
}

fn render_committed_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    committed: &CommittedChangeSet,
) {
    let data = CommittedChangeSetData::from(committed);
    let mut result = ResultEnvelope::success(
        "changeset.commit",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(committed.workspace_id.to_string());
    result.meta.principal_id = Some(committed.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {} committed", result.data.changeset_id);
            println!(
                "authoritative sequence: {}",
                result.data.authoritative_sequence
            );
            println!("Known State: {}", result.data.resulting_state);
            println!("committed at: {}", result.data.committed_at);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn commit_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "changeset.commit",
        context.operation_id,
        context.correlation_id,
    ))
}

fn commit_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet commit input is invalid",
        "proof.input.schema_mismatch",
        "changeset.commit",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn commit_problem(error: &CommitChangeSetError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        CommitChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        CommitChangeSetError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 commit operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
            false,
        ),
        CommitChangeSetError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        CommitChangeSetError::NotApproved => (
            "urn:proof:problem:changeset-not-approved",
            "Only an approved ChangeSet can be committed",
            "proof.changeset.not_approved",
            false,
        ),
        CommitChangeSetError::EvidenceMissing => (
            "urn:proof:problem:evidence-incomplete",
            "Exact approved ChangeSet evidence is required before commit",
            "proof.evidence.incomplete",
            false,
        ),
        CommitChangeSetError::BaseStateConflict => (
            "urn:proof:problem:state-conflict",
            "The current Known State no longer matches the ChangeSet base",
            "proof.state.conflict",
            false,
        ),
        CommitChangeSetError::TargetConflict => (
            "urn:proof:problem:target-conflict",
            "A ChangeSet target already exists in authoritative state",
            "proof.changeset.target_conflict",
            false,
        ),
        CommitChangeSetError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        CommitChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The ChangeSet commit could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        CommitChangeSetError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local ChangeSet commit storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "changeset.commit",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, CommitChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

fn create_local_edition(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    idempotency_key: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| edition_root_problem(context))?,
    };
    let repository = LocalWorkspace::new(root).map_err(|_| edition_root_problem(context))?;
    let idempotency_key = idempotency_key
        .map(|value| value.parse::<IdempotencyKey>())
        .transpose()
        .map_err(|error| edition_input_problem(context, error.to_string()))?
        .unwrap_or_else(generated_idempotency_key);
    let created_at =
        current_timestamp().map_err(|error| internal_problem("edition.create", context, error))?;
    let edition = create_edition(
        &repository,
        CreateEditionCommand {
            edition_id: generated_edition_id(),
            idempotency_key,
            created_at,
        },
    )
    .map_err(|error| edition_problem(&error, context))?;
    render_created_edition(output, context, &edition, idempotency_key);
    Ok(ExitCode::Success)
}

fn render_created_edition(
    output: OutputFormat,
    context: ExecutionContext,
    edition: &Edition,
    idempotency_key: IdempotencyKey,
) {
    let data = CreatedEditionData::from_edition(edition, idempotency_key);
    let mut result = ResultEnvelope::success(
        "edition.create",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(edition.workspace_id.to_string());
    result.meta.principal_id = Some(edition.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("Edition {} created", result.data.edition_id);
            println!("Edition digest: {}", result.data.edition_digest);
            println!("Known State: {}", result.data.state_digest);
            if let Some(object_set_digest) = &result.data.object_set_digest {
                println!("Object set: {object_set_digest}");
            }
            println!("objects: {}", result.data.object_count);
            println!("idempotency key: {}", result.data.idempotency_key);
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn edition_root_problem(context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        "edition.create",
        context.operation_id,
        context.correlation_id,
    ))
}

fn edition_input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The Edition creation input is invalid",
        "proof.input.schema_mismatch",
        "edition.create",
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn edition_problem(error: &CreateEditionError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        CreateEditionError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        CreateEditionError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 Edition operation is unsupported after KnownStateV2 activation",
            "proof.input.unsupported_version",
            false,
        ),
        CreateEditionError::EmptyState => (
            "urn:proof:problem:empty-authoritative-state",
            "An Edition requires committed authoritative state",
            "proof.validation.empty_state",
            false,
        ),
        CreateEditionError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        CreateEditionError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The Edition could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        CreateEditionError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Local Edition storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        "edition.create",
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, CreateEditionError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

#[derive(Clone, Copy)]
enum ChangeSetProjection {
    Get,
    Diff,
}

impl ChangeSetProjection {
    const fn operation(self) -> &'static str {
        match self {
            Self::Get => "changeset.get",
            Self::Diff => "changeset.diff",
        }
    }
}

fn inspect_local_changeset(
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    changeset_id: &str,
    projection: ChangeSetProjection,
) -> Result<ExitCode, Box<Problem>> {
    let root = match selected_workspace {
        Some(path) => PathBuf::from(path),
        None => env::current_dir().map_err(|_| inspection_root_problem(context, projection))?,
    };
    let repository =
        LocalWorkspace::new(root).map_err(|_| inspection_root_problem(context, projection))?;
    let changeset_id = changeset_id
        .parse::<ChangeSetId>()
        .map_err(|error| inspection_input_problem(context, projection, error.to_string()))?;
    let inspected = inspect_changeset(&repository, changeset_id)
        .map_err(|error| inspection_problem(&error, context, projection))?;
    match projection {
        ChangeSetProjection::Get => render_changeset_get(output, context, &inspected),
        ChangeSetProjection::Diff => render_changeset_diff(output, context, &inspected),
    }
    Ok(ExitCode::Success)
}

fn render_changeset_get(
    output: OutputFormat,
    context: ExecutionContext,
    inspected: &InspectedChangeSet,
) {
    let data = InspectedChangeSetData::from(inspected);
    let mut result = ResultEnvelope::success(
        "changeset.get",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(inspected.workspace_id.to_string());
    result.meta.principal_id = Some(inspected.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {}", result.data.changeset_id);
            println!("status: {}", result.data.status);
            println!("intent: {}", result.data.intent);
            println!("base state: {}", result.data.base_state);
            println!("edits: {}", result.data.edits.len());
            for edit in &result.data.edits {
                match edit {
                    InspectedEditData::SchemaCreate(edit) => println!(
                        "{}. {} {}@{} ({})",
                        edit.ordinal,
                        edit.kind,
                        edit.schema_id,
                        edit.schema_version,
                        edit.document_digest
                    ),
                    InspectedEditData::ObjectCreate(edit) => println!(
                        "{}. {} {}@{} {}@{} {} ({})",
                        edit.ordinal,
                        edit.kind,
                        edit.object_id,
                        edit.revision,
                        edit.schema_id,
                        edit.schema_version,
                        edit.lifecycle_state,
                        edit.object_digest
                    ),
                }
            }
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn render_changeset_diff(
    output: OutputFormat,
    context: ExecutionContext,
    inspected: &InspectedChangeSet,
) {
    let data = ChangeSetDiffData::from(inspected);
    let mut result = ResultEnvelope::success(
        "changeset.diff",
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(inspected.workspace_id.to_string());
    result.meta.principal_id = Some(inspected.principal_id.to_string());
    match output {
        OutputFormat::Text => {
            println!("ChangeSet {}", result.data.changeset_id);
            println!("base state: {}", result.data.base_state);
            for edit in &result.data.edits {
                match edit {
                    ChangeSetDiffEditData::SchemaCreate(edit) => {
                        println!(
                            "@@ {} {} {}@{} {} @@",
                            edit.ordinal,
                            edit.operation,
                            edit.schema_id,
                            edit.schema_version,
                            edit.edit_id
                        );
                        println!("+ {}", edit.after.document_canonical);
                    }
                    ChangeSetDiffEditData::ObjectCreate(edit) => {
                        println!(
                            "@@ {} {} {}@{} {}@{} {} @@",
                            edit.ordinal,
                            edit.operation,
                            edit.object_id,
                            edit.after.revision,
                            edit.after.schema_id,
                            edit.after.schema_version,
                            edit.edit_id
                        );
                        println!("+ {}", edit.after.content_canonical);
                    }
                }
            }
        }
        OutputFormat::Json => write_json(&result),
    }
}

fn inspection_root_problem(
    context: ExecutionContext,
    projection: ChangeSetProjection,
) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        projection.operation(),
        context.operation_id,
        context.correlation_id,
    ))
}

fn inspection_input_problem(
    context: ExecutionContext,
    projection: ChangeSetProjection,
    detail: String,
) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The ChangeSet identifier is invalid",
        "proof.input.schema_mismatch",
        projection.operation(),
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn inspection_problem(
    error: &InspectChangeSetError,
    context: ExecutionContext,
    projection: ChangeSetProjection,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        InspectChangeSetError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current operating-system identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        InspectChangeSetError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ChangeSet was not found",
            "proof.resource.not_found",
            false,
        ),
        InspectChangeSetError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The requested ChangeSet could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        InspectChangeSetError::Storage(_) => (
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
        projection.operation(),
        context.operation_id,
        context.correlation_id,
    );
    if matches!(error, InspectChangeSetError::Integrity(_)) {
        problem.detail = Some(error.to_string());
    }
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
            for finding in &problem.findings {
                let pointer = finding.pointer.as_deref().unwrap_or("/");
                eprintln!("{} at {pointer}: {}", finding.code, finding.message);
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectCreateEditInput {
    api_version: String,
    kind: String,
    object_id: String,
    schema_id: String,
    schema_version: u32,
    content: serde_json::Value,
}

impl ObjectCreateEditInput {
    fn into_edit(self, line: usize) -> Result<ObjectCreateEdit, String> {
        if self.api_version != "proof.dev/edit/v1" {
            return Err(format!(
                "Edit record line {line}: unsupported api_version `{}`",
                self.api_version
            ));
        }
        if self.kind != "object.create" {
            return Err(format!(
                "Edit record line {line}: unsupported kind `{}`",
                self.kind
            ));
        }
        let object_id = self
            .object_id
            .parse::<ObjectId>()
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        if object_id.to_string() != self.object_id {
            return Err(format!(
                "Edit record line {line}: Object identifier must be a canonical UUIDv7"
            ));
        }
        let schema_id = SchemaId::new(self.schema_id)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        let schema_version = SchemaVersion::new(self.schema_version)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        if !self.content.is_object() {
            return Err(format!(
                "Edit record line {line}: Object content root must be a JSON object"
            ));
        }
        let canonical = canonicalize(&self.content)
            .map_err(|error| format!("Edit record line {line}: {error}"))?;
        let object_digest =
            object_revision_digest(object_id, &schema_id, schema_version, &self.content)
                .map_err(|error| format!("Edit record line {line}: {error}"))?;
        Ok(ObjectCreateEdit {
            edit_id: generated_edit_id(),
            object_id,
            schema_id,
            schema_version,
            canonical_content: canonical.as_str().to_owned(),
            object_digest,
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

#[derive(Serialize)]
struct ValidatedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    changeset_digest: String,
    base_state: String,
    validation_profile: String,
    validator: String,
    valid: bool,
    findings: Vec<proof_application::Finding>,
    validation_results_digest: String,
    edit_count: u32,
    status: String,
}

impl From<&ValidatedChangeSet> for ValidatedChangeSetData {
    fn from(validated: &ValidatedChangeSet) -> Self {
        Self {
            changeset_id: validated.changeset_id.to_string(),
            workspace_id: validated.workspace_id.to_string(),
            principal_id: validated.principal_id.to_string(),
            changeset_digest: validated.changeset_digest.to_string(),
            base_state: validated.base_state.to_string(),
            validation_profile: validated.validation_profile.clone(),
            validator: validated.validator.clone(),
            valid: validated.valid,
            findings: validated.findings.clone(),
            validation_results_digest: validated.validation_results_digest.to_string(),
            edit_count: validated.edit_count,
            status: validated.status.to_string(),
        }
    }
}

#[derive(Serialize)]
struct SubmittedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    changeset_digest: String,
    validation_results_digest: String,
    base_state: String,
    submitted_at: String,
    status: String,
    edit_count: u32,
}

impl From<&SubmittedChangeSet> for SubmittedChangeSetData {
    fn from(submitted: &SubmittedChangeSet) -> Self {
        Self {
            changeset_id: submitted.changeset_id.to_string(),
            workspace_id: submitted.workspace_id.to_string(),
            principal_id: submitted.principal_id.to_string(),
            changeset_digest: submitted.changeset_digest.to_string(),
            validation_results_digest: submitted.validation_results_digest.to_string(),
            base_state: submitted.base_state.to_string(),
            submitted_at: submitted.submitted_at.to_string(),
            status: submitted.status.to_string(),
            edit_count: submitted.edit_count,
        }
    }
}

#[derive(Serialize)]
struct ApprovedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    approval: String,
    changeset_digest: String,
    validation_results_digest: String,
    approved_at: String,
    status: String,
}

impl From<&ApprovedChangeSet> for ApprovedChangeSetData {
    fn from(approved: &ApprovedChangeSet) -> Self {
        Self {
            changeset_id: approved.changeset_id.to_string(),
            workspace_id: approved.workspace_id.to_string(),
            principal_id: approved.principal_id.to_string(),
            approval: approved.approval.to_string(),
            changeset_digest: approved.changeset_digest.to_string(),
            validation_results_digest: approved.validation_results_digest.to_string(),
            approved_at: approved.approved_at.to_string(),
            status: approved.status.to_string(),
        }
    }
}

#[derive(Serialize)]
struct CommittedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    changeset_digest: String,
    validation_results_digest: String,
    previous_state: String,
    resulting_state: String,
    authoritative_sequence: u64,
    committed_at: String,
    status: String,
    edit_count: u32,
}

impl From<&CommittedChangeSet> for CommittedChangeSetData {
    fn from(committed: &CommittedChangeSet) -> Self {
        Self {
            changeset_id: committed.changeset_id.to_string(),
            workspace_id: committed.workspace_id.to_string(),
            principal_id: committed.principal_id.to_string(),
            changeset_digest: committed.changeset_digest.to_string(),
            validation_results_digest: committed.validation_results_digest.to_string(),
            previous_state: committed.previous_state.to_string(),
            resulting_state: committed.resulting_state.to_string(),
            authoritative_sequence: committed.authoritative_sequence,
            committed_at: committed.committed_at.to_string(),
            status: committed.status.to_string(),
            edit_count: committed.edit_count,
        }
    }
}

#[derive(Serialize)]
struct CreatedEditionData {
    edition_id: String,
    workspace_id: String,
    principal_id: String,
    authoritative_sequence: u64,
    state_digest: String,
    schema_set_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    object_set_digest: Option<String>,
    edition_digest: String,
    manifest: serde_json::Value,
    created_at: String,
    schema_count: usize,
    object_count: usize,
    changeset_count: usize,
    idempotency_key: String,
}

impl CreatedEditionData {
    fn from_edition(edition: &Edition, idempotency_key: IdempotencyKey) -> Self {
        let manifest = parse_strict(edition.manifest_json.as_bytes())
            .expect("verified Edition manifest must remain strict JSON");
        Self {
            edition_id: edition.edition_id.to_string(),
            workspace_id: edition.workspace_id.to_string(),
            principal_id: edition.principal_id.to_string(),
            authoritative_sequence: edition.authoritative_sequence,
            state_digest: edition.state_digest.to_string(),
            schema_set_digest: edition.schema_set_digest.to_string(),
            object_set_digest: edition.object_set_digest.map(|digest| digest.to_string()),
            edition_digest: edition.edition_digest.to_string(),
            manifest,
            created_at: edition.created_at.to_string(),
            schema_count: edition.schemas.len(),
            object_count: edition.objects.len(),
            changeset_count: edition.changesets.len(),
            idempotency_key: idempotency_key.to_string(),
        }
    }
}

#[derive(Serialize)]
struct InspectedChangeSetData {
    changeset_id: String,
    workspace_id: String,
    principal_id: String,
    intent: String,
    base_authoritative_sequence: u64,
    base_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_base_state: Option<String>,
    idempotency_key: String,
    created_at: String,
    status: String,
    policy_profile: String,
    validation_profile: String,
    edits: Vec<InspectedEditData>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum InspectedEditData {
    SchemaCreate(InspectedSchemaCreateEditData),
    ObjectCreate(InspectedObjectCreateEditData),
}

#[derive(Serialize)]
struct InspectedSchemaCreateEditData {
    ordinal: u32,
    edit_id: String,
    kind: &'static str,
    schema_id: String,
    schema_version: u32,
    document: serde_json::Value,
    document_canonical: String,
    document_digest: String,
}

#[derive(Serialize)]
struct InspectedObjectCreateEditData {
    ordinal: u32,
    edit_id: String,
    kind: &'static str,
    object_id: String,
    revision: u32,
    schema_id: String,
    schema_version: u32,
    lifecycle_state: String,
    relationships: Vec<serde_json::Value>,
    content: serde_json::Value,
    content_canonical: String,
    object_digest: String,
}

impl From<&InspectedChangeSet> for InspectedChangeSetData {
    fn from(changeset: &InspectedChangeSet) -> Self {
        Self {
            changeset_id: changeset.changeset_id.to_string(),
            workspace_id: changeset.workspace_id.to_string(),
            principal_id: changeset.principal_id.to_string(),
            intent: changeset.intent.to_string(),
            base_authoritative_sequence: changeset.base_authoritative_sequence,
            base_state: changeset.base_state.to_string(),
            requested_base_state: changeset
                .requested_base_state
                .map(|value| value.to_string()),
            idempotency_key: changeset.idempotency_key.to_string(),
            created_at: changeset.created_at.to_string(),
            status: changeset.status.to_string(),
            policy_profile: changeset.policy_profile.clone(),
            validation_profile: changeset.validation_profile.clone(),
            edits: changeset
                .edits
                .iter()
                .map(|edit| match edit {
                    InspectedChangeSetEdit::SchemaCreate(edit) => {
                        InspectedEditData::SchemaCreate(InspectedSchemaCreateEditData {
                            ordinal: edit.ordinal,
                            edit_id: edit.edit_id.to_string(),
                            kind: "schema.create",
                            schema_id: edit.schema_id.to_string(),
                            schema_version: edit.schema_version.get(),
                            document: serde_json::from_str(&edit.canonical_document)
                                .expect("verified canonical JSON must deserialize"),
                            document_canonical: edit.canonical_document.clone(),
                            document_digest: edit.document_digest.to_string(),
                        })
                    }
                    InspectedChangeSetEdit::ObjectCreate(edit) => {
                        InspectedEditData::ObjectCreate(InspectedObjectCreateEditData {
                            ordinal: edit.ordinal,
                            edit_id: edit.edit_id.to_string(),
                            kind: "object.create",
                            object_id: edit.object_id.to_string(),
                            revision: ObjectRevision::INITIAL.get(),
                            schema_id: edit.schema_id.to_string(),
                            schema_version: edit.schema_version.get(),
                            lifecycle_state: ObjectLifecycleState::Active.to_string(),
                            relationships: Vec::new(),
                            content: serde_json::from_str(&edit.canonical_content)
                                .expect("verified canonical JSON must deserialize"),
                            content_canonical: edit.canonical_content.clone(),
                            object_digest: edit.object_digest.to_string(),
                        })
                    }
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct ChangeSetDiffData {
    changeset_id: String,
    base_authoritative_sequence: u64,
    base_state: String,
    edits: Vec<ChangeSetDiffEditData>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ChangeSetDiffEditData {
    SchemaCreate(SchemaCreateDiffData),
    ObjectCreate(ObjectCreateDiffData),
}

#[derive(Serialize)]
struct SchemaCreateDiffData {
    ordinal: u32,
    edit_id: String,
    operation: &'static str,
    schema_id: String,
    schema_version: u32,
    before: Option<SchemaDiffState>,
    after: SchemaDiffState,
}

#[derive(Serialize)]
struct SchemaDiffState {
    document: serde_json::Value,
    document_canonical: String,
    document_digest: String,
}

#[derive(Serialize)]
struct ObjectCreateDiffData {
    ordinal: u32,
    edit_id: String,
    operation: &'static str,
    object_id: String,
    before: Option<ObjectDiffState>,
    after: ObjectDiffState,
}

#[derive(Serialize)]
struct ObjectDiffState {
    revision: u32,
    schema_id: String,
    schema_version: u32,
    lifecycle_state: String,
    relationships: Vec<serde_json::Value>,
    content: serde_json::Value,
    content_canonical: String,
    object_digest: String,
}

impl From<&InspectedChangeSet> for ChangeSetDiffData {
    fn from(changeset: &InspectedChangeSet) -> Self {
        Self {
            changeset_id: changeset.changeset_id.to_string(),
            base_authoritative_sequence: changeset.base_authoritative_sequence,
            base_state: changeset.base_state.to_string(),
            edits: changeset
                .edits
                .iter()
                .map(|edit| match edit {
                    InspectedChangeSetEdit::SchemaCreate(edit) => {
                        ChangeSetDiffEditData::SchemaCreate(SchemaCreateDiffData {
                            ordinal: edit.ordinal,
                            edit_id: edit.edit_id.to_string(),
                            operation: "schema.create",
                            schema_id: edit.schema_id.to_string(),
                            schema_version: edit.schema_version.get(),
                            before: None,
                            after: SchemaDiffState {
                                document: serde_json::from_str(&edit.canonical_document)
                                    .expect("verified canonical JSON must deserialize"),
                                document_canonical: edit.canonical_document.clone(),
                                document_digest: edit.document_digest.to_string(),
                            },
                        })
                    }
                    InspectedChangeSetEdit::ObjectCreate(edit) => {
                        ChangeSetDiffEditData::ObjectCreate(ObjectCreateDiffData {
                            ordinal: edit.ordinal,
                            edit_id: edit.edit_id.to_string(),
                            operation: "object.create",
                            object_id: edit.object_id.to_string(),
                            before: None,
                            after: ObjectDiffState {
                                revision: ObjectRevision::INITIAL.get(),
                                schema_id: edit.schema_id.to_string(),
                                schema_version: edit.schema_version.get(),
                                lifecycle_state: ObjectLifecycleState::Active.to_string(),
                                relationships: Vec::new(),
                                content: serde_json::from_str(&edit.canonical_content)
                                    .expect("verified canonical JSON must deserialize"),
                                content_canonical: edit.canonical_content.clone(),
                                object_digest: edit.object_digest.to_string(),
                            },
                        })
                    }
                })
                .collect(),
        }
    }
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

fn generated_edition_id() -> EditionId {
    EditionId::from_uuid(Uuid::now_v7()).expect("UUIDv7 generation must produce version 7")
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
