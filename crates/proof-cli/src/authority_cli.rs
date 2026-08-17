use std::{env, path::PathBuf};

use clap::Subcommand;
use proof_application::{
    AgentPrincipal, BuildContextPackCommand, ContextPack, ContextPackError, ContextPackLimits,
    ContextPackVerification, CreateAgentPrincipalCommand, Delegation, DelegationConstraints,
    DelegationError, DelegationId, DelegationScope, DelegationVerification, GetContextPackCommand,
    IdempotencyKey, PrincipalError, PrincipalId, ResultEnvelope, RevokeDelegationCommand,
    Timestamp, VerifyContextPackCommand, VerifyDelegationCommand, build_context_pack, capabilities,
    create_agent_principal, get_context_pack, get_delegation, grant_delegation, revoke_delegation,
    verify_context_pack, verify_delegation,
};
use proof_local::LocalWorkspace;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    AuthoritySelection, ExecutionContext, ExitCode, OutputFormat, Problem, current_timestamp,
    generated_idempotency_key, generated_principal_id, write_json,
};

#[derive(Debug, Subcommand)]
pub(super) enum PrincipalAction {
    /// Register one local Agent Principal.
    CreateAgent {
        /// Stable caller-facing Agent label.
        #[arg(long)]
        display_name: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum DelegationAction {
    /// Grant bounded, expiring read authority to an Agent Principal.
    Grant {
        /// Agent Principal receiving the grant.
        #[arg(long)]
        recipient: String,
        /// Allowed action; repeat for multiple actions.
        #[arg(long, required = true)]
        action: Vec<String>,
        /// Exact visible Environment; repeat to extend the scope.
        #[arg(long)]
        environment: Vec<String>,
        /// Exact visible Object; repeat to extend the scope.
        #[arg(long)]
        object_id: Vec<String>,
        /// Maximum Objects in one authorized result.
        #[arg(long)]
        max_objects: u32,
        /// Maximum canonical `ContextPack` bytes.
        #[arg(long)]
        max_context_bytes: u64,
        /// Inclusive canonical UTC validity start.
        #[arg(long)]
        not_before: String,
        /// Exclusive canonical UTC validity end.
        #[arg(long)]
        expires_at: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Return one verified Delegation and revocation state.
    Get {
        /// Delegation `UUIDv7`.
        delegation_id: String,
    },
    /// Append a revocation fact for one Delegation.
    Revoke {
        /// Delegation `UUIDv7`.
        delegation_id: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Evaluate a Delegation against an exact proposed read.
    Verify {
        /// Delegation `UUIDv7`.
        delegation_id: String,
        /// Agent Principal presenting the Delegation.
        #[arg(long)]
        operating_principal: String,
        /// Exact action being requested.
        #[arg(long)]
        action: String,
        /// Exact target Environment, when applicable.
        #[arg(long)]
        environment: Option<String>,
        /// Exact target Object; repeat for multiple Objects.
        #[arg(long)]
        object_id: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum ContextAction {
    /// Build one immutable bounded `ContextPack` under delegated authority.
    Build {
        /// Stable caller task identity.
        #[arg(long)]
        task_id: String,
        /// Normalized statement of task intent.
        #[arg(long)]
        intent: String,
        /// Released Environment supplying content.
        #[arg(long)]
        environment: String,
        /// Exact requested Object; repeat for multiple Objects.
        #[arg(long, required = true)]
        object_id: Vec<String>,
        /// Maximum Object count requested from the Delegation.
        #[arg(long, default_value_t = 100)]
        max_objects: u32,
        /// Maximum canonical `ContextPack` bytes requested from the Delegation.
        #[arg(long, default_value_t = 1_048_576)]
        max_bytes: u64,
        /// Exclusive canonical UTC freshness bound.
        #[arg(long)]
        expires_at: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Return one authorized immutable `ContextPack`.
    Get {
        /// `ContextPack` `UUIDv7`.
        context_pack_id: String,
    },
    /// Verify one `ContextPack`'s canonical bytes, sources, authority, and freshness.
    Verify {
        /// `ContextPack` `UUIDv7`.
        context_pack_id: String,
    },
}

#[derive(Clone, Copy, Debug, Subcommand)]
pub(super) enum CapabilityAction {
    /// List the stable agent-visible application operations.
    List,
}

pub(super) fn run_principal(
    action: PrincipalAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    match action {
        PrincipalAction::CreateAgent {
            display_name,
            idempotency_key,
        } => {
            let operation = "principal.create_agent";
            let repository = local_workspace(selected_workspace, operation, context)?;
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let principal = create_agent_principal(
                &repository,
                CreateAgentPrincipalCommand {
                    principal_id: generated_principal_id(),
                    display_name,
                    idempotency_key,
                    created_at: now(operation, context)?,
                },
            )
            .map_err(|error| principal_problem(&error, operation, context))?;
            render_agent_principal(output, context, operation, &principal, idempotency_key);
            Ok(ExitCode::Success)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive CLI projection keeps each Delegation action explicit"
)]
pub(super) fn run_delegation(
    action: DelegationAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let operation = match &action {
        DelegationAction::Grant { .. } => "delegation.grant",
        DelegationAction::Get { .. } => "delegation.get",
        DelegationAction::Revoke { .. } => "delegation.revoke",
        DelegationAction::Verify { .. } => "delegation.verify",
    };
    let repository = local_workspace(selected_workspace, operation, context)?;
    match action {
        DelegationAction::Grant {
            recipient,
            action,
            environment,
            object_id,
            max_objects,
            max_context_bytes,
            not_before,
            expires_at,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let delegation = grant_delegation(
                &repository,
                proof_application::GrantDelegationCommand {
                    delegation_id: generated_operational_id(),
                    recipient_principal_id: parse(&recipient, "recipient", operation, context)?,
                    actions: parse_many(&action, "action", operation, context)?,
                    scope: DelegationScope {
                        workspace_id: workspace_id(&repository, operation, context)?,
                        environment_ids: parse_many(
                            &environment,
                            "environment",
                            operation,
                            context,
                        )?,
                        object_ids: parse_many(&object_id, "object-id", operation, context)?,
                    },
                    constraints: DelegationConstraints {
                        max_objects,
                        max_context_bytes,
                        allow_subdelegation: false,
                    },
                    not_before: parse(&not_before, "not-before", operation, context)?,
                    expires_at: parse(&expires_at, "expires-at", operation, context)?,
                    idempotency_key,
                    issued_at: now(operation, context)?,
                },
            )
            .map_err(|error| delegation_problem(&error, operation, context))?;
            render_delegation(
                output,
                context,
                operation,
                &delegation,
                Some(idempotency_key),
            );
        }
        DelegationAction::Get { delegation_id } => {
            let delegation = get_delegation(
                &repository,
                parse(&delegation_id, "delegation-id", operation, context)?,
            )
            .map_err(|error| delegation_problem(&error, operation, context))?;
            render_delegation(output, context, operation, &delegation, None);
        }
        DelegationAction::Revoke {
            delegation_id,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let delegation = revoke_delegation(
                &repository,
                RevokeDelegationCommand {
                    delegation_id: parse(&delegation_id, "delegation-id", operation, context)?,
                    idempotency_key,
                    revoked_at: now(operation, context)?,
                },
            )
            .map_err(|error| delegation_problem(&error, operation, context))?;
            render_delegation(
                output,
                context,
                operation,
                &delegation,
                Some(idempotency_key),
            );
        }
        DelegationAction::Verify {
            delegation_id,
            operating_principal,
            action,
            environment,
            object_id,
        } => {
            let verified = verify_delegation(
                &repository,
                VerifyDelegationCommand {
                    delegation_id: parse(&delegation_id, "delegation-id", operation, context)?,
                    operating_principal_id: parse(
                        &operating_principal,
                        "operating-principal",
                        operation,
                        context,
                    )?,
                    action: parse(&action, "action", operation, context)?,
                    environment_id: environment
                        .as_deref()
                        .map(|value| parse(value, "environment", operation, context))
                        .transpose()?,
                    object_ids: parse_many(&object_id, "object-id", operation, context)?,
                    evaluated_at: now(operation, context)?,
                },
            )
            .map_err(|error| delegation_problem(&error, operation, context))?;
            render_delegation_verification(output, context, operation, &verified);
        }
    }
    Ok(ExitCode::Success)
}

pub(super) fn run_context(
    action: ContextAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
    authority: &AuthoritySelection,
) -> Result<ExitCode, Box<Problem>> {
    let operation = match &action {
        ContextAction::Build { .. } => "context.build",
        ContextAction::Get { .. } => "context.get",
        ContextAction::Verify { .. } => "context.verify",
    };
    let (operating_principal_id, delegation_id) =
        selected_authority(authority, operation, context)?;
    let repository = local_workspace(selected_workspace, operation, context)?;
    match action {
        ContextAction::Build {
            task_id,
            intent,
            environment,
            object_id,
            max_objects,
            max_bytes,
            expires_at,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let pack = build_context_pack(
                &repository,
                BuildContextPackCommand {
                    context_pack_id: generated_operational_id(),
                    operating_principal_id,
                    delegation_id,
                    task_id,
                    intent: proof_application::ChangeSetIntent::new(intent)
                        .map_err(|error| input_problem(operation, context, error.to_string()))?,
                    environment_id: parse(&environment, "environment", operation, context)?,
                    object_ids: parse_many(&object_id, "object-id", operation, context)?,
                    limits: ContextPackLimits {
                        max_objects,
                        max_bytes,
                    },
                    idempotency_key,
                    built_at: now(operation, context)?,
                    expires_at: parse(&expires_at, "expires-at", operation, context)?,
                },
            )
            .map_err(|error| context_problem(&error, operation, context))?;
            render_context_pack(output, context, operation, &pack, Some(idempotency_key));
        }
        ContextAction::Get { context_pack_id } => {
            let pack = get_context_pack(
                &repository,
                GetContextPackCommand {
                    context_pack_id: parse(
                        &context_pack_id,
                        "context-pack-id",
                        operation,
                        context,
                    )?,
                    operating_principal_id,
                    delegation_id,
                    observed_at: now(operation, context)?,
                },
            )
            .map_err(|error| context_problem(&error, operation, context))?;
            render_context_pack(output, context, operation, &pack, None);
        }
        ContextAction::Verify { context_pack_id } => {
            let verified = verify_context_pack(
                &repository,
                VerifyContextPackCommand {
                    context_pack_id: parse(
                        &context_pack_id,
                        "context-pack-id",
                        operation,
                        context,
                    )?,
                    operating_principal_id,
                    delegation_id,
                    verified_at: now(operation, context)?,
                },
            )
            .map_err(|error| context_problem(&error, operation, context))?;
            render_context_verification(output, context, operation, &verified);
        }
    }
    Ok(ExitCode::Success)
}

pub(super) fn run_capability(
    action: CapabilityAction,
    output: OutputFormat,
    context: ExecutionContext,
) -> ExitCode {
    match action {
        CapabilityAction::List => {
            let data = json!({ "capabilities": capabilities() });
            let result = ResultEnvelope::success(
                "capability.list",
                context.operation_id,
                context.correlation_id,
                data,
            );
            match output {
                OutputFormat::Json => write_json(&result),
                OutputFormat::Text => {
                    for capability in capabilities() {
                        println!("{} {}", capability.operation, capability.version);
                        println!("  {}", capability.description);
                        println!("  side effect: {:?}", capability.side_effect);
                        println!("  required action: {}", capability.required_action);
                    }
                }
            }
        }
    }
    ExitCode::Success
}

fn render_agent_principal(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    principal: &AgentPrincipal,
    idempotency_key: IdempotencyKey,
) {
    let data = json!({
        "principal_id": principal.principal_id.to_string(),
        "workspace_id": principal.workspace_id.to_string(),
        "principal_type": "agent",
        "display_name": principal.display_name,
        "created_by_principal_id": principal.created_by_principal_id.to_string(),
        "created_at": principal.created_at.to_string(),
        "enabled": principal.enabled,
        "idempotency_key": idempotency_key.to_string(),
    });
    render_value(output, context, operation, data, |data| {
        println!("Created Agent Principal {}", data["principal_id"]);
        println!("display name: {}", data["display_name"]);
        println!("created by: {}", data["created_by_principal_id"]);
        println!("created at: {}", data["created_at"]);
    });
}

fn delegation_value(delegation: &Delegation, idempotency_key: Option<IdempotencyKey>) -> Value {
    json!({
        "delegation_id": delegation.delegation_id.to_string(),
        "workspace_id": delegation.workspace_id.to_string(),
        "issuer_principal_id": delegation.issuer_principal_id.to_string(),
        "recipient_principal_id": delegation.recipient_principal_id.to_string(),
        "actions": delegation.actions.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "scope": {
            "workspace_id": delegation.scope.workspace_id.to_string(),
            "environment_ids": delegation.scope.environment_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "object_ids": delegation.scope.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        },
        "constraints": {
            "max_objects": delegation.constraints.max_objects,
            "max_context_bytes": delegation.constraints.max_context_bytes,
            "allow_subdelegation": delegation.constraints.allow_subdelegation,
        },
        "not_before": delegation.not_before.to_string(),
        "expires_at": delegation.expires_at.to_string(),
        "issued_at": delegation.issued_at.to_string(),
        "delegation_digest": delegation.delegation_digest.to_string(),
        "revoked_by_principal_id": delegation.revoked_by_principal_id.map(|id| id.to_string()),
        "revoked_at": delegation.revoked_at.map(|time| time.to_string()),
        "idempotency_key": idempotency_key.map(|key| key.to_string()),
    })
}

fn render_delegation(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    delegation: &Delegation,
    idempotency_key: Option<IdempotencyKey>,
) {
    render_value(
        output,
        context,
        operation,
        delegation_value(delegation, idempotency_key),
        |data| {
            println!("Delegation {}", data["delegation_id"]);
            println!("issuer: {}", data["issuer_principal_id"]);
            println!("recipient: {}", data["recipient_principal_id"]);
            println!("digest: {}", data["delegation_digest"]);
            println!("expires at: {}", data["expires_at"]);
            println!("revoked: {}", !data["revoked_at"].is_null());
        },
    );
}

fn render_delegation_verification(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    verified: &DelegationVerification,
) {
    let data = json!({
        "delegation_id": verified.delegation_id.to_string(),
        "operating_principal_id": verified.operating_principal_id.to_string(),
        "action": verified.action.to_string(),
        "authorized": verified.authorized,
        "denial_code": verified.denial_code,
        "policy_profile": verified.policy_profile,
        "decision_digest": verified.decision_digest.to_string(),
        "evaluated_at": verified.evaluated_at.to_string(),
    });
    render_value(output, context, operation, data, |data| {
        println!("Delegation {} verification", data["delegation_id"]);
        println!("authorized: {}", data["authorized"]);
        println!("action: {}", data["action"]);
        println!("decision digest: {}", data["decision_digest"]);
    });
}

fn context_value(pack: &ContextPack, idempotency_key: Option<IdempotencyKey>) -> Value {
    json!({
        "context_pack_id": pack.context_pack_id.to_string(),
        "workspace_id": pack.workspace_id.to_string(),
        "requesting_principal_id": pack.requesting_principal_id.to_string(),
        "operating_principal_id": pack.operating_principal_id.to_string(),
        "delegation_id": pack.delegation_id.to_string(),
        "task_id": pack.task_id,
        "intent": pack.intent.to_string(),
        "environment_id": pack.environment_id.to_string(),
        "release_id": pack.release_id.to_string(),
        "edition_id": pack.edition_id.to_string(),
        "base_state": pack.base_state.to_string(),
        "object_ids": pack.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "limits": { "max_objects": pack.limits.max_objects, "max_bytes": pack.limits.max_bytes },
        "built_at": pack.built_at.to_string(),
        "expires_at": pack.expires_at.to_string(),
        "capabilities": pack.capabilities,
        "manifest": serde_json::from_str::<Value>(&pack.manifest_json).unwrap_or(Value::Null),
        "manifest_json": pack.manifest_json,
        "context_pack_digest": pack.context_pack_digest.to_string(),
        "idempotency_key": idempotency_key.map(|key| key.to_string()),
    })
}

fn render_context_pack(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    pack: &ContextPack,
    idempotency_key: Option<IdempotencyKey>,
) {
    render_value(
        output,
        context,
        operation,
        context_value(pack, idempotency_key),
        |data| {
            println!("ContextPack {}", data["context_pack_id"]);
            println!("environment: {}", data["environment_id"]);
            println!("release: {}", data["release_id"]);
            println!(
                "objects: {}",
                data["object_ids"].as_array().map_or(0, Vec::len)
            );
            println!("digest: {}", data["context_pack_digest"]);
            println!("expires at: {}", data["expires_at"]);
        },
    );
}

fn render_context_verification(
    output: OutputFormat,
    context: ExecutionContext,
    operation: &str,
    verified: &ContextPackVerification,
) {
    let data = json!({
        "context_pack_id": verified.context_pack_id.to_string(),
        "context_pack_digest": verified.context_pack_digest.to_string(),
        "digest_valid": verified.digest_valid,
        "sources_valid": verified.sources_valid,
        "fresh": verified.fresh,
        "valid": verified.valid,
        "findings": verified.findings,
        "verified_at": verified.verified_at.to_string(),
    });
    render_value(output, context, operation, data, |data| {
        println!("ContextPack {} verification", data["context_pack_id"]);
        println!("valid: {}", data["valid"]);
        println!("digest valid: {}", data["digest_valid"]);
        println!("sources valid: {}", data["sources_valid"]);
        println!("fresh: {}", data["fresh"]);
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

fn workspace_id(
    repository: &LocalWorkspace,
    operation: &str,
    context: ExecutionContext,
) -> Result<proof_application::WorkspaceId, Box<Problem>> {
    repository
        .read_config()
        .map_err(|_| root_problem(operation, context))?
        .workspace_id
        .parse()
        .map_err(|error: proof_application::IdentifierError| {
            integrity_problem(operation, context, error.to_string())
        })
}

fn selected_authority(
    authority: &AuthoritySelection,
    operation: &str,
    context: ExecutionContext,
) -> Result<(PrincipalId, DelegationId), Box<Problem>> {
    let principal = authority.principal.as_deref().ok_or_else(|| {
        input_problem(
            operation,
            context,
            "--principal is required for delegated ContextPack operations".to_owned(),
        )
    })?;
    let delegation = authority.delegation.as_deref().ok_or_else(|| {
        input_problem(
            operation,
            context,
            "--delegation is required for delegated ContextPack operations".to_owned(),
        )
    })?;
    Ok((
        parse(principal, "principal", operation, context)?,
        parse(delegation, "delegation", operation, context)?,
    ))
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

fn now(operation: &str, context: ExecutionContext) -> Result<Timestamp, Box<Problem>> {
    current_timestamp().map_err(|detail| internal_problem(operation, context, detail))
}

fn root_problem(operation: &str, context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        operation,
        context.operation_id,
        context.correlation_id,
    ))
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

fn integrity_problem(operation: &str, context: ExecutionContext, _detail: String) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:evidence-incomplete",
        "Persisted authority or ContextPack evidence could not be verified",
        "proof.evidence.incomplete",
        operation,
        context.operation_id,
        context.correlation_id,
    ))
}

fn internal_problem(operation: &str, context: ExecutionContext, _detail: String) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:internal",
        "The operation could not be completed",
        "proof.internal",
        operation,
        context.operation_id,
        context.correlation_id,
    ))
}

fn principal_problem(
    error: &PrincipalError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        PrincipalError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current identity is not authenticated",
            "proof.auth.unauthenticated",
            false,
        ),
        PrincipalError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested Agent Principal was not found",
            "proof.resource.not_found",
            false,
        ),
        PrincipalError::Disabled => (
            "urn:proof:problem:authority-denied",
            "The requested Agent Principal is disabled",
            "proof.auth.denied",
            false,
        ),
        PrincipalError::InvalidDisplayName => (
            "urn:proof:problem:input-schema-mismatch",
            "The Agent display name is invalid",
            "proof.input.schema_mismatch",
            false,
        ),
        PrincipalError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was reused with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        PrincipalError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "Principal registry evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        PrincipalError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Principal registry storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

fn delegation_problem(
    error: &DelegationError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        DelegationError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current identity is not authenticated",
            "proof.auth.unauthenticated",
            false,
        ),
        DelegationError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested Delegation resource was not found",
            "proof.resource.not_found",
            false,
        ),
        DelegationError::InvalidRecipient | DelegationError::InvalidGrant => (
            "urn:proof:problem:validation-failed",
            "The Delegation grant is invalid",
            "proof.validation.failed",
            false,
        ),
        DelegationError::NotYetValid => (
            "urn:proof:problem:delegation-not-yet-valid",
            "The Delegation is not yet valid",
            "proof.delegation.not_yet_valid",
            false,
        ),
        DelegationError::Expired => (
            "urn:proof:problem:delegation-expired",
            "The Delegation has expired",
            "proof.delegation.expired",
            false,
        ),
        DelegationError::Revoked => (
            "urn:proof:problem:delegation-revoked",
            "The Delegation has been revoked",
            "proof.delegation.revoked",
            false,
        ),
        DelegationError::ScopeExceeded => (
            "urn:proof:problem:delegation-scope-exceeded",
            "The request exceeds Delegation scope",
            "proof.delegation.scope_exceeded",
            false,
        ),
        DelegationError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was reused with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        DelegationError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "Delegation evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        DelegationError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Delegation storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
}

fn context_problem(
    error: &ContextPackError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        ContextPackError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The current identity is not authenticated",
            "proof.auth.unauthenticated",
            false,
        ),
        ContextPackError::Denied => (
            "urn:proof:problem:authority-denied",
            "The ContextPack operation is outside delegated authority",
            "proof.auth.denied",
            false,
        ),
        ContextPackError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested ContextPack resource was not found",
            "proof.resource.not_found",
            false,
        ),
        ContextPackError::LimitExceeded => (
            "urn:proof:problem:input-too-large",
            "The ContextPack request exceeds its bounded constraints",
            "proof.input.too_large",
            false,
        ),
        ContextPackError::Expired => (
            "urn:proof:problem:delegation-expired",
            "The ContextPack has expired",
            "proof.delegation.expired",
            false,
        ),
        ContextPackError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was reused with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        ContextPackError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "ContextPack evidence could not be verified",
            "proof.evidence.incomplete",
            false,
        ),
        ContextPackError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "ContextPack storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    mapped_problem(problem_type, title, code, operation, context, retryable)
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
