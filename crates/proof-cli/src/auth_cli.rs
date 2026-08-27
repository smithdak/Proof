use std::{
    env, fs,
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use proof_application::{
    ArtifactKind, BindingId, ExitCode, PresentationId, Problem, ResultEnvelope, Timestamp,
    authority::{
        AuthenticatedAuthorityExecutor, AuthenticatedCommandApiVersion,
        AuthenticatedCommandEnvelopeJson, AuthenticatedCommandSigner, AuthenticatedCommandV1,
        AuthenticatedExecutionV1, AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationFailureV1, AuthenticatedOperationResultV1, AuthorityAudience,
        AuthorityError, CommandInputV1, MAX_AUTHENTICATED_INVOCATION_BYTES,
        MAX_COMMAND_LIFETIME_SECONDS, SignAuthenticatedCommandV1,
    },
};
use proof_attestation::{
    Ed25519SigningProvider, ProofSigningProvider as _,
    authority::{AuthorityPayloadProfile, sign_authority_payload},
};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_local::LocalWorkspace;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroize as _;

use super::{ExecutionContext, OutputFormat, current_timestamp, write_json};

const CREDENTIAL_API_VERSION: &str = "proof.dev/local-agent-credential/v1";
const MAX_CREDENTIAL_BYTES: usize = 4_096;

#[derive(Debug, Subcommand)]
pub(super) enum AuthAction {
    /// Sign one exact semantic command without opening a Workspace.
    Sign {
        /// Read the semantic `CommandInputV1` from stdin; only `-` is accepted.
        #[arg(long, value_parser = stdin_only)]
        command: String,
        /// Select a separator-free handle under the fixed per-user credential directory.
        #[arg(long)]
        credential: String,
    },
    /// Execute one canonical authenticated invocation from bounded stdin.
    Execute {
        /// Read the `AuthenticatedInvocationV1` frame from stdin; only `-` is accepted.
        #[arg(long, value_parser = stdin_only)]
        invocation: String,
    },
}

pub(super) fn run_auth(
    action: AuthAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<&str>,
) -> Result<ExitCode, Box<Problem>> {
    match action {
        AuthAction::Sign {
            command,
            credential,
        } => run_sign(&command, &credential, context, selected_workspace),
        AuthAction::Execute { invocation } => {
            run_execute(&invocation, output, context, selected_workspace)
        }
    }
}

fn run_sign(
    command_source: &str,
    credential_handle: &str,
    context: ExecutionContext,
    selected_workspace: Option<&str>,
) -> Result<ExitCode, Box<Problem>> {
    require_fixed_stdin(command_source, "command", context)?;
    reject_workspace_argument(selected_workspace, "auth.sign", context)?;
    validate_credential_handle(credential_handle)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let bytes = read_bounded(io::stdin().lock(), MAX_AUTHENTICATED_INVOCATION_BYTES)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let command_input = normalized_command_input(&bytes)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let signer = FileCredentialSigner::load(credential_handle)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let issued_at = current_timestamp().map_err(|_| {
        authority_problem(
            &AuthorityError::Signing("signer clock is unavailable".to_owned()),
            "auth.sign",
            context,
        )
    })?;
    let expires_at = command_expiry(issued_at)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let invocation = signer
        .sign_authenticated_command(SignAuthenticatedCommandV1 {
            command_input,
            binding_id: signer.binding_id,
            presentation_id: generated_presentation_id(),
            issued_at,
            expires_at,
        })
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    let frame = canonical_invocation(&invocation)
        .map_err(|error| authority_problem(&error, "auth.sign", context))?;
    io::stdout()
        .lock()
        .write_all(frame.as_bytes())
        .map_err(|_| {
            authority_problem(
                &AuthorityError::Storage("stdout is unavailable".to_owned()),
                "auth.sign",
                context,
            )
        })?;
    Ok(ExitCode::Success)
}

fn run_execute(
    invocation_source: &str,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<&str>,
) -> Result<ExitCode, Box<Problem>> {
    require_fixed_stdin(invocation_source, "invocation", context)?;
    reject_workspace_argument(selected_workspace, "auth.execute", context)?;
    let bytes = read_bounded(io::stdin().lock(), MAX_AUTHENTICATED_INVOCATION_BYTES)
        .map_err(|error| authority_problem(&error, "auth.execute", context))?;
    let invocation = parse_canonical_invocation(&bytes)
        .map_err(|error| authority_problem(&error, "auth.execute", context))?;

    // The supervisor establishes the broker's working directory. The invocation
    // cannot name a credential, path, or file for this privileged process to open.
    let root = env::current_dir().map_err(|_| {
        authority_problem(
            &AuthorityError::Storage("broker working directory is unavailable".to_owned()),
            "auth.execute",
            context,
        )
    })?;
    let repository = LocalWorkspace::new(root).map_err(|_| {
        authority_problem(
            &AuthorityError::Storage("broker Workspace is unavailable".to_owned()),
            "auth.execute",
            context,
        )
    })?;
    let evaluated_at = current_timestamp().map_err(|_| {
        authority_problem(
            &AuthorityError::Storage("broker clock is unavailable".to_owned()),
            "auth.execute",
            context,
        )
    })?;
    let execution = repository
        .execute_authenticated(invocation, evaluated_at)
        .map_err(|error| authority_problem(&error, "auth.execute", context))?;
    match &execution.result {
        AuthenticatedOperationResultV1::Failure(failure) => {
            return Err(operation_failure_problem(*failure, &execution, context));
        }
        AuthenticatedOperationResultV1::LocalizedFailure(failure) => {
            return Err(localized_operation_failure_problem(
                *failure,
                execution.decision_record_digest,
                context,
            ));
        }
        AuthenticatedOperationResultV1::WorkspaceStatus(_)
        | AuthenticatedOperationResultV1::ReleasedObjectQuery(_)
        | AuthenticatedOperationResultV1::ContextPack(_)
        | AuthenticatedOperationResultV1::LocalizedSuccess(_) => {}
    }
    render_execution(output, context, &execution)?;
    Ok(ExitCode::Success)
}

fn stdin_only(value: &str) -> Result<String, String> {
    if value == "-" {
        Ok(value.to_owned())
    } else {
        Err("only `-` is accepted; authenticated Agent transport is stdin-only".to_owned())
    }
}

fn require_fixed_stdin(
    value: &str,
    field: &str,
    context: ExecutionContext,
) -> Result<(), Box<Problem>> {
    if value == "-" {
        Ok(())
    } else {
        let mut problem = Problem::new(
            "urn:proof:problem:authenticated-invocation-malformed",
            "Authenticated Agent transport is stdin-only",
            "proof.auth.malformed",
            if field == "command" {
                "auth.sign"
            } else {
                "auth.execute"
            },
            context.operation_id,
            context.correlation_id,
        );
        problem.detail = Some(format!("--{field} must be exactly `-`"));
        Err(Box::new(problem))
    }
}

fn reject_workspace_argument(
    selected_workspace: Option<&str>,
    operation: &str,
    context: ExecutionContext,
) -> Result<(), Box<Problem>> {
    if selected_workspace.is_none() {
        return Ok(());
    }
    let mut problem = Problem::new(
        "urn:proof:problem:authenticated-invocation-malformed",
        "The authenticated Agent transport has a fixed filesystem boundary",
        "proof.auth.malformed",
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(
        "--workspace is not accepted: the signer is Workspace-blind and the broker uses its supervisor-established working directory"
            .to_owned(),
    );
    Err(Box::new(problem))
}

fn read_bounded(reader: impl io::Read, maximum: usize) -> Result<Vec<u8>, AuthorityError> {
    let maximum_u64 = u64::try_from(maximum).expect("authenticated input bound fits u64");
    let mut bytes = Vec::new();
    reader
        .take(maximum_u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthorityError::AuthMalformed)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(AuthorityError::AuthMalformed);
    }
    Ok(bytes)
}

fn normalized_command_input(bytes: &[u8]) -> Result<CommandInputV1, AuthorityError> {
    let value = parse_strict(bytes).map_err(|_| AuthorityError::AuthMalformed)?;
    let mut command_input: CommandInputV1 =
        serde_json::from_value(value).map_err(|_| AuthorityError::AuthMalformed)?;
    command_input
        .normalize_for_authenticated_execution()
        .map_err(|_| AuthorityError::AuthMalformed)?;
    Ok(command_input)
}

fn parse_canonical_invocation(bytes: &[u8]) -> Result<AuthenticatedInvocationV1, AuthorityError> {
    if bytes.len() > MAX_AUTHENTICATED_INVOCATION_BYTES {
        return Err(AuthorityError::AuthMalformed);
    }
    let value = parse_strict(bytes).map_err(|_| AuthorityError::AuthMalformed)?;
    let canonical = canonicalize(&value).map_err(|_| AuthorityError::AuthMalformed)?;
    if canonical.as_bytes() != bytes {
        return Err(AuthorityError::AuthMalformed);
    }
    let invocation: AuthenticatedInvocationV1 =
        serde_json::from_value(value).map_err(|_| AuthorityError::AuthMalformed)?;
    validate_normalized_input(&invocation.command_input)?;
    Ok(invocation)
}

fn canonical_invocation(invocation: &AuthenticatedInvocationV1) -> Result<String, AuthorityError> {
    let value = serde_json::to_value(invocation).map_err(|_| AuthorityError::AuthMalformed)?;
    let canonical = canonicalize(&value).map_err(|_| AuthorityError::AuthMalformed)?;
    if canonical.as_str().len() > MAX_AUTHENTICATED_INVOCATION_BYTES {
        Err(AuthorityError::AuthMalformed)
    } else {
        Ok(canonical.as_str().to_owned())
    }
}

fn validate_normalized_input(command: &CommandInputV1) -> Result<(), AuthorityError> {
    command
        .validate_for_authenticated_execution()
        .map(|_| ())
        .map_err(|_| AuthorityError::AuthMalformed)
}

fn command_expiry(issued_at: Timestamp) -> Result<Timestamp, AuthorityError> {
    let lifetime = i128::from(MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000;
    let expires_at = issued_at
        .unix_timestamp_nanos()
        .checked_add(lifetime)
        .ok_or_else(|| {
            AuthorityError::Signing("signer clock exceeds timestamp range".to_owned())
        })?;
    Timestamp::from_unix_timestamp_nanos(expires_at)
        .map_err(|_| AuthorityError::Signing("signer clock exceeds timestamp range".to_owned()))
}

fn generated_presentation_id() -> PresentationId {
    PresentationId::from_uuid(Uuid::now_v7())
        .expect("UUIDv7 generation must produce a Presentation identifier")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCredentialV1 {
    api_version: String,
    binding_id: String,
    key_id: String,
    secret_key_hex: String,
}

struct FileCredentialSigner {
    binding_id: BindingId,
    provider: Ed25519SigningProvider,
}

impl FileCredentialSigner {
    fn load(handle: &str) -> Result<Self, AuthorityError> {
        let directory = credential_directory()?;
        Self::load_from_directory(&directory, handle)
    }

    fn load_from_directory(directory: &Path, handle: &str) -> Result<Self, AuthorityError> {
        validate_credential_handle(handle)?;
        validate_credential_directory(directory)?;
        let path = directory.join(format!("{handle}.json"));
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| AuthorityError::Signing("credential is unavailable".to_owned()))?;
        validate_credential_metadata(&metadata)?;
        let file = fs::File::open(&path)
            .map_err(|_| AuthorityError::Signing("credential is unavailable".to_owned()))?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_CREDENTIAL_BYTES).expect("credential bound fits u64") + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityError::Signing("credential is unavailable".to_owned()))?;
        if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL_BYTES {
            bytes.zeroize();
            return Err(AuthorityError::Signing(
                "credential has an invalid size".to_owned(),
            ));
        }
        let parsed = serde_json::from_slice::<FileCredentialV1>(&bytes);
        bytes.zeroize();
        let mut credential =
            parsed.map_err(|_| AuthorityError::Signing("credential is malformed".to_owned()))?;
        if credential.api_version != CREDENTIAL_API_VERSION {
            credential.secret_key_hex.zeroize();
            return Err(AuthorityError::Signing(
                "credential version is unsupported".to_owned(),
            ));
        }
        let binding_id = credential.binding_id.parse::<BindingId>().map_err(|_| {
            credential.secret_key_hex.zeroize();
            AuthorityError::Signing("credential binding is malformed".to_owned())
        })?;
        let secret = decode_secret_hex(&mut credential.secret_key_hex)?;
        let mut secret = secret;
        let provider = Ed25519SigningProvider::from_secret_bytes(&secret);
        secret.zeroize();
        let metadata = provider.metadata().map_err(|_| {
            AuthorityError::Signing("credential metadata is unavailable".to_owned())
        })?;
        if metadata.key_id != credential.key_id {
            return Err(AuthorityError::Signing(
                "credential key identity does not match its secret".to_owned(),
            ));
        }
        Ok(Self {
            binding_id,
            provider,
        })
    }
}

impl AuthenticatedCommandSigner for FileCredentialSigner {
    fn sign_authenticated_command(
        &self,
        command: SignAuthenticatedCommandV1,
    ) -> Result<AuthenticatedInvocationV1, AuthorityError> {
        command
            .validate()
            .map_err(|_| AuthorityError::AuthMalformed)?;
        if command.binding_id != self.binding_id {
            return Err(AuthorityError::AuthMalformed);
        }
        validate_normalized_input(&command.command_input)?;
        let command_value = serde_json::to_value(&command.command_input)
            .map_err(|_| AuthorityError::AuthMalformed)?;
        let canonical_command =
            canonicalize(&command_value).map_err(|_| AuthorityError::AuthMalformed)?;
        let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);
        let payload = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(command.command_input.workspace_id),
            workspace_id: command.command_input.workspace_id,
            operation: command.command_input.operation,
            binding_id: command.binding_id,
            requesting_principal_id: command.command_input.requesting_principal_id,
            operating_principal_id: command.command_input.operating_principal_id,
            delegation_id: command.command_input.delegation_id,
            command_digest,
            idempotency_key: command.command_input.idempotency_key,
            presentation_id: command.presentation_id,
            issued_at: command.issued_at,
            expires_at: command.expires_at,
        };
        let signed = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &payload,
            &[&self.provider],
        )
        .map_err(|error| AuthorityError::Signing(error.to_string()))?;
        let authentication = AuthenticatedCommandEnvelopeJson::new(signed.envelope_json)
            .map_err(|_| AuthorityError::AuthMalformed)?;
        let invocation = AuthenticatedInvocationV1 {
            api_version: AuthenticatedInvocationApiVersion::V1,
            command_input: command.command_input,
            authentication,
        };
        canonical_invocation(&invocation)?;
        Ok(invocation)
    }
}

fn validate_credential_handle(handle: &str) -> Result<(), AuthorityError> {
    let valid = !handle.is_empty()
        && handle.len() <= 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(AuthorityError::AuthMalformed)
    }
}

fn credential_directory() -> Result<PathBuf, AuthorityError> {
    #[cfg(unix)]
    {
        if let Some(root) = absolute_environment_path("XDG_DATA_HOME") {
            return Ok(root.join("proof").join("credentials"));
        }
        if let Some(root) = absolute_environment_path("HOME") {
            return Ok(root
                .join(".local")
                .join("share")
                .join("proof")
                .join("credentials"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(root) = absolute_environment_path("LOCALAPPDATA") {
            return Ok(root.join("Proof").join("credentials"));
        }
    }
    Err(AuthorityError::Signing(
        "per-user credential directory is unavailable".to_owned(),
    ))
}

fn absolute_environment_path(name: &str) -> Option<PathBuf> {
    let value = PathBuf::from(env::var_os(name)?);
    value.is_absolute().then_some(value)
}

fn validate_credential_directory(directory: &Path) -> Result<(), AuthorityError> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| AuthorityError::Signing("credential directory is unavailable".to_owned()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AuthorityError::Signing(
            "credential directory is not a regular directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(AuthorityError::Signing(
                "credential directory permissions must be 0700".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_credential_metadata(metadata: &fs::Metadata) -> Result<(), AuthorityError> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AuthorityError::Signing(
            "credential is not a regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(AuthorityError::Signing(
                "credential permissions must be 0600".to_owned(),
            ));
        }
    }
    Ok(())
}

fn decode_secret_hex(value: &mut String) -> Result<[u8; 32], AuthorityError> {
    if value.len() != 64 {
        value.zeroize();
        return Err(AuthorityError::Signing(
            "credential secret has an invalid encoding".to_owned(),
        ));
    }
    let mut encoded = [0_u8; 64];
    encoded.copy_from_slice(value.as_bytes());
    value.zeroize();
    let mut secret = [0_u8; 32];
    for (index, pair) in encoded.chunks_exact(2).enumerate() {
        let high = decode_lower_hex(pair[0]);
        let low = decode_lower_hex(pair[1]);
        let (Some(high), Some(low)) = (high, low) else {
            secret.zeroize();
            encoded.zeroize();
            return Err(AuthorityError::Signing(
                "credential secret has an invalid encoding".to_owned(),
            ));
        };
        secret[index] = (high << 4) | low;
    }
    encoded.zeroize();
    Ok(secret)
}

const fn decode_lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn render_execution(
    output: OutputFormat,
    context: ExecutionContext,
    execution: &AuthenticatedExecutionV1,
) -> Result<(), Box<Problem>> {
    let operation = execution.command_input.operation.name();
    let mut data = operation_result_value(execution, context)?;
    let authority = json!({
        "requesting_principal_id": execution.actor_context_evidence.requesting_principal_id.to_string(),
        "operating_principal_id": execution.actor_context_evidence.operating_principal_id.to_string(),
        "binding_id": execution.actor_context_evidence.binding_id.to_string(),
        "binding_authority_sequence": execution.decision.binding.authority_sequence.get(),
        "binding_record_digest": execution.decision.binding.record_digest.to_string(),
        "delegation_id": execution.actor_context_evidence.delegation_id.to_string(),
        "delegation_record_digest": execution.decision.delegation.record_digest.map(|value| value.to_string()),
        "command_digest": execution.actor_context_evidence.command_digest.to_string(),
        "command_envelope_digest": execution.actor_context_evidence.command_envelope_digest.to_string(),
        "presentation_id": execution.actor_context_evidence.presentation_id.to_string(),
        "actor_context_digest": execution.actor_context_digest.to_string(),
        "authorization_decision_digest": execution.decision_record_digest.to_string(),
        "authorization_decision_envelope_digest": execution.decision_envelope_digest.to_string(),
        "authority_sequence": execution.decision.authority_sequence.get(),
        "authority_key_id": execution.decision.authority_key_id.to_string(),
        "decision": execution.decision.decision,
    });
    if !matches!(
        &execution.result,
        AuthenticatedOperationResultV1::LocalizedSuccess(_)
    ) && let Value::Object(object) = &mut data
    {
        object.insert("authority".to_owned(), authority);
    }
    let mut result = ResultEnvelope::success(
        operation,
        context.operation_id,
        context.correlation_id,
        data,
    );
    result.meta.workspace_id = Some(execution.command_input.workspace_id.to_string());
    result.meta.principal_id = Some(execution.command_input.operating_principal_id.to_string());
    match output {
        OutputFormat::Json => write_json(&result),
        OutputFormat::Text => {
            match &execution.result {
                AuthenticatedOperationResultV1::WorkspaceStatus(status) => {
                    println!("Workspace {}", status.workspace_id);
                }
                AuthenticatedOperationResultV1::ReleasedObjectQuery(query) => println!(
                    "Released Objects from {}: {}",
                    query.environment_id,
                    query.objects.len()
                ),
                AuthenticatedOperationResultV1::ContextPack(pack) => {
                    println!("ContextPack {}", pack.context_pack_id);
                }
                AuthenticatedOperationResultV1::Failure(failure) => {
                    println!("{} failed: {}", failure.operation().name(), failure.code());
                }
                AuthenticatedOperationResultV1::LocalizedSuccess(success) => {
                    println!("{} completed", success.operation().name());
                }
                AuthenticatedOperationResultV1::LocalizedFailure(failure) => {
                    println!("{} failed: {}", failure.operation.name(), failure.code());
                }
            }
            println!(
                "authorization decision: {}",
                execution.decision_record_digest
            );
        }
    }
    Ok(())
}

fn operation_result_value(
    execution: &AuthenticatedExecutionV1,
    context: ExecutionContext,
) -> Result<Value, Box<Problem>> {
    match &execution.result {
        AuthenticatedOperationResultV1::WorkspaceStatus(status) => Ok(json!({
            "workspace_id": status.workspace_id.to_string(),
            "requesting_principal_id": status.requesting_principal_id.to_string(),
            "operating_principal_id": status.operating_principal_id.to_string(),
            "delegation_id": status.delegation_id.to_string(),
            "storage_schema_version": status.storage_schema_version,
            "authoritative_sequence": status.authoritative_sequence,
            "state_digest": status.state_digest.to_string(),
            "authorization_decision_digest": status.authorization_decision_digest.to_string(),
        })),
        AuthenticatedOperationResultV1::ReleasedObjectQuery(query) => Ok(query_value(query)),
        AuthenticatedOperationResultV1::ContextPack(pack) => Ok(json!({
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
            "idempotency_key": execution.command_input.idempotency_key.map(|value| value.to_string()),
        })),
        AuthenticatedOperationResultV1::Failure(failure) => Ok(json!({
            "failure": {
                "code": failure.code(),
            }
        })),
        AuthenticatedOperationResultV1::LocalizedSuccess(success) => success
            .output_value()
            .map_err(|_| invalid_operation_result_problem(success.operation().name(), context)),
        AuthenticatedOperationResultV1::LocalizedFailure(failure) => Ok(json!({
            "failure": {
                "code": failure.code(),
            }
        })),
    }
}

fn operation_failure_problem(
    failure: AuthenticatedOperationFailureV1,
    execution: &AuthenticatedExecutionV1,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title) = match failure {
        AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound
        | AuthenticatedOperationFailureV1::ContextBuildNotFound => (
            "urn:proof:problem:resource-not-found",
            "The authorized operation could not find a required resource",
        ),
        AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The authorized operation encountered an unsupported resource version",
        ),
        AuthenticatedOperationFailureV1::ContextBuildLimitExceeded => (
            "urn:proof:problem:input-too-large",
            "The authorized Context build exceeded its bounded limit",
        ),
        AuthenticatedOperationFailureV1::ContextBuildExpired => (
            "urn:proof:problem:delegation-expired",
            "The authorized Context build input has expired",
        ),
        AuthenticatedOperationFailureV1::ContextBuildDenied => (
            "urn:proof:problem:authority-denied",
            "The authorized Context build was denied by current application state",
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        failure.code(),
        failure.operation().name(),
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(format!(
        "authorization allow decision recorded as {}",
        execution.decision_record_digest
    ));
    Box::new(problem)
}

fn localized_operation_failure_problem(
    failure: proof_application::authority::LocalizedOperationFailureV1,
    decision_record_digest: proof_application::ContentDigest,
    context: ExecutionContext,
) -> Box<Problem> {
    let public = failure.public_problem();
    let mut problem = Problem::new(
        public.problem_type,
        public.title,
        public.code,
        failure.operation.name(),
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(format!(
        "authorization allow decision recorded as {decision_record_digest}"
    ));
    problem.retryable = public.retryable;
    Box::new(problem)
}

fn invalid_operation_result_problem(operation: &str, context: ExecutionContext) -> Box<Problem> {
    Box::new(Problem::new(
        "urn:proof:problem:internal",
        "The authenticated operation result is invalid",
        "proof.internal",
        operation,
        context.operation_id,
        context.correlation_id,
    ))
}

fn query_value(query: &proof_application::ReleasedObjectQuery) -> Value {
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
    json!({
        "workspace_id": query.workspace_id.to_string(),
        "environment_id": query.environment_id.to_string(),
        "release_id": query.release_id.to_string(),
        "edition_id": query.edition_id.to_string(),
        "principal_id": query.principal_id.to_string(),
        "delegation_id": query.delegation_id.map(|value| value.to_string()),
        "authorization_decision_digest": query.authorization_decision_digest.to_string(),
        "objects": objects,
    })
}

fn authority_problem(
    error: &AuthorityError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let public = error.public_problem();
    let mut problem = Problem::new(
        public.problem_type,
        public.title,
        public.code,
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = public.detail.map(str::to_owned);
    problem.retryable = public.retryable;
    Box::new(problem)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Cursor},
    };

    use clap::Parser as _;
    use proof_application::{
        BindingId, ContentDigest, PresentationId, Timestamp,
        authority::{
            ApplicationIdempotency, AuthenticatedCommandSigner as _, CommandInputV1,
            LocalizedOperationFailureKindV1, LocalizedOperationFailureV1,
            SignAuthenticatedCommandV1, authority_operation_entry,
        },
    };
    use proof_attestation::{
        Ed25519SigningProvider, ProofSigningProvider as _,
        authority::{AuthorityPayloadProfile, verify_authority_envelope},
    };

    use super::{
        FileCredentialSigner, MAX_AUTHENTICATED_INVOCATION_BYTES, canonical_invocation,
        localized_operation_failure_problem, normalized_command_input, parse_canonical_invocation,
        read_bounded, stdin_only, validate_credential_handle,
    };
    use crate::{Cli, ExecutionContext, run};

    const STATUS_COMMAND: &str =
        include_str!("../../../conformance/v1/authority/vectors/semantic-command.valid.json");
    const LOCALIZED_OPERATION_INSTANCES: &str = include_str!(
        "../../../conformance/v2/localized-content/vectors/operation-instances.valid.json"
    );

    #[test]
    fn clap_rejects_every_non_stdin_auth_source() {
        assert!(stdin_only("-").is_ok());
        assert!(stdin_only("command.json").is_err());
        assert!(
            Cli::try_parse_from([
                "proof",
                "auth",
                "sign",
                "--command",
                "command.json",
                "--credential",
                "agent-a",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "proof",
                "auth",
                "execute",
                "--invocation",
                "invocation.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn signer_rejects_explicit_authority_and_workspace_selection() {
        let principal = Cli::try_parse_from([
            "proof",
            "--principal",
            "019c0000-0000-7000-8000-000000000003",
            "auth",
            "sign",
            "--command",
            "-",
            "--credential",
            "agent-a",
        ])
        .unwrap();
        let problem = run(principal).unwrap_err();
        assert_eq!(problem.code, "proof.auth.denied");
        assert_eq!(problem.operation, "auth.sign");

        let workspace = Cli::try_parse_from([
            "proof",
            "--workspace",
            "caller-selected-path",
            "auth",
            "sign",
            "--command",
            "-",
            "--credential",
            "agent-a",
        ])
        .unwrap();
        let problem = run(workspace).unwrap_err();
        assert_eq!(problem.code, "proof.auth.malformed");
        assert_eq!(problem.operation, "auth.sign");
    }

    #[test]
    fn broker_frame_bound_is_exact() {
        let exact = vec![b'x'; MAX_AUTHENTICATED_INVOCATION_BYTES];
        assert_eq!(
            read_bounded(Cursor::new(exact), MAX_AUTHENTICATED_INVOCATION_BYTES)
                .unwrap()
                .len(),
            MAX_AUTHENTICATED_INVOCATION_BYTES
        );
        let excessive = vec![b'x'; MAX_AUTHENTICATED_INVOCATION_BYTES + 1];
        assert!(read_bounded(Cursor::new(excessive), MAX_AUTHENTICATED_INVOCATION_BYTES).is_err());
        assert!(read_bounded(io::empty(), 16).is_err());
    }

    #[test]
    fn credential_handle_cannot_escape_the_fixed_directory() {
        for valid in ["agent-a", "agent_01", "A9"] {
            assert!(validate_credential_handle(valid).is_ok(), "{valid}");
        }
        for invalid in ["", ".", "../agent", "agent/key", "agent\\key", "agent.json"] {
            assert!(validate_credential_handle(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn credential_handle_resolves_only_inside_the_supplied_fixed_directory() {
        let suffix = uuid::Uuid::now_v7();
        let directory = std::env::temp_dir().join(format!("proof-cli-credential-{suffix}"));
        fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let provider = Ed25519SigningProvider::from_secret_bytes(&[37_u8; 32]);
        let key_id = provider.metadata().unwrap().key_id;
        let path = directory.join("agent-a.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "api_version": "proof.dev/local-agent-credential/v1",
                "binding_id": "019c0000-0000-7000-8000-000000000004",
                "key_id": key_id,
                "secret_key_hex": "25".repeat(32),
            }))
            .unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = FileCredentialSigner::load_from_directory(&directory, "agent-a").unwrap();
        assert_eq!(loaded.provider.metadata().unwrap().key_id, key_id);

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn credential_loader_rejects_symlinked_file_and_directory() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let suffix = uuid::Uuid::now_v7();
        let parent = std::env::temp_dir().join(format!("proof-cli-symlink-{suffix}"));
        let directory = parent.join("credentials");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let target = parent.join("credential-target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let credential_link = directory.join("agent-a.json");
        symlink(&target, &credential_link).unwrap();
        assert!(FileCredentialSigner::load_from_directory(&directory, "agent-a").is_err());

        let directory_link = parent.join("credentials-link");
        symlink(&directory, &directory_link).unwrap();
        assert!(FileCredentialSigner::load_from_directory(&directory_link, "agent-a").is_err());

        fs::remove_file(directory_link).unwrap();
        fs::remove_file(credential_link).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(directory).unwrap();
        fs::remove_dir(parent).unwrap();
    }

    #[test]
    fn signer_emits_one_canonical_strict_invocation() {
        let input: CommandInputV1 = serde_json::from_str(STATUS_COMMAND).unwrap();
        let signer = FileCredentialSigner {
            binding_id: "019c0000-0000-7000-8000-000000000004"
                .parse::<BindingId>()
                .unwrap(),
            provider: Ed25519SigningProvider::from_secret_bytes(&[29_u8; 32]),
        };
        let invocation = signer
            .sign_authenticated_command(SignAuthenticatedCommandV1 {
                command_input: input,
                binding_id: signer.binding_id,
                presentation_id: "019c0000-0000-7000-8000-000000000006"
                    .parse::<PresentationId>()
                    .unwrap(),
                issued_at: "2026-08-17T20:02:00Z".parse::<Timestamp>().unwrap(),
                expires_at: "2026-08-17T20:07:00Z".parse::<Timestamp>().unwrap(),
            })
            .unwrap();
        let frame = canonical_invocation(&invocation).unwrap();
        let reparsed = parse_canonical_invocation(frame.as_bytes()).unwrap();
        assert_eq!(reparsed, invocation);
        let metadata = signer.provider.metadata().unwrap();
        let verified = verify_authority_envelope::<serde_json::Value>(
            invocation.authentication.as_str().as_bytes(),
            AuthorityPayloadProfile::AuthenticatedCommand,
            &[metadata.key_id.as_str()],
        )
        .unwrap();
        assert_eq!(
            verified.parsed.payload["binding_id"],
            "019c0000-0000-7000-8000-000000000004"
        );
    }

    #[test]
    fn signer_normalizes_transport_input_before_hashing_and_signing() {
        let mut input = serde_json::from_str::<serde_json::Value>(include_str!(
            "../../../conformance/v1/authority/vectors/context-build.command-input.valid.json"
        ))
        .unwrap();
        input["normalized_input"]["object_ids"] = serde_json::json!([
            "019c0000-0000-7000-8000-000000000021",
            "019c0000-0000-7000-8000-000000000020"
        ]);
        input["normalized_input"]["max_objects"] = serde_json::json!(2);
        let signer = FileCredentialSigner {
            binding_id: "019c0000-0000-7000-8000-000000000004"
                .parse::<BindingId>()
                .unwrap(),
            provider: Ed25519SigningProvider::from_secret_bytes(&[41_u8; 32]),
        };
        let command_input = normalized_command_input(&serde_json::to_vec(&input).unwrap()).unwrap();
        let invocation = signer
            .sign_authenticated_command(SignAuthenticatedCommandV1 {
                command_input,
                binding_id: signer.binding_id,
                presentation_id: "019c0000-0000-7000-8000-000000000006"
                    .parse::<PresentationId>()
                    .unwrap(),
                issued_at: "2026-08-17T20:02:00Z".parse::<Timestamp>().unwrap(),
                expires_at: "2026-08-17T20:07:00Z".parse::<Timestamp>().unwrap(),
            })
            .unwrap();

        assert_eq!(
            invocation.command_input.normalized_input["object_ids"],
            serde_json::json!([
                "019c0000-0000-7000-8000-000000000020",
                "019c0000-0000-7000-8000-000000000021"
            ])
        );
        assert!(canonical_invocation(&invocation).is_ok());
    }

    #[test]
    fn signer_normalizes_all_eleven_localized_v2_commands_through_the_application_contract() {
        let vectors: serde_json::Value =
            serde_json::from_str(LOCALIZED_OPERATION_INSTANCES).unwrap();
        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 11);

        for case in cases {
            let version = case["operation_id"].as_str().unwrap();
            let descriptor = proof_application::capabilities()
                .iter()
                .find(|descriptor| descriptor.version == version)
                .unwrap_or_else(|| panic!("missing capability {version}"));
            let operation = descriptor.authority_operation().unwrap();
            let idempotency_key = match authority_operation_entry(operation).application_idempotency
            {
                ApplicationIdempotency::RequiredUuidV7 => case["input"]["idempotency_key"].clone(),
                ApplicationIdempotency::None
                | ApplicationIdempotency::DerivedChangeset
                | ApplicationIdempotency::DerivedProposalPolicyValidator => serde_json::Value::Null,
            };
            let command = serde_json::json!({
                "api_version": "proof.dev/command-input/v1",
                "workspace_id": "019c0000-0000-7000-8000-000000000001",
                "operation": {
                    "name": descriptor.operation,
                    "version": descriptor.version,
                },
                "delegation_id": "019c0000-0000-7000-8000-000000000005",
                "idempotency_key": idempotency_key,
                "normalized_input": case["input"],
                "requesting_principal_id": "019c0000-0000-7000-8000-000000000002",
                "operating_principal_id": "019c0000-0000-7000-8000-000000000003",
            });

            let normalized = normalized_command_input(&serde_json::to_vec(&command).unwrap())
                .unwrap_or_else(|error| panic!("{version} failed: {error:?}"));
            assert_eq!(normalized.operation, operation);
            assert_eq!(
                normalized.normalized_input,
                case["input"].as_object().unwrap().clone(),
                "{version}"
            );
        }
    }

    #[test]
    fn localized_failures_use_the_same_public_projection_as_the_application_contract() {
        let context = ExecutionContext {
            operation_id: "019c0000-0000-7000-8000-000000000011".parse().unwrap(),
            correlation_id: "019c0000-0000-7000-8000-000000000012".parse().unwrap(),
        };
        let decision_record_digest: ContentDigest =
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap();
        let kinds = [
            LocalizedOperationFailureKindV1::NotFound,
            LocalizedOperationFailureKindV1::UnsupportedVersion,
            LocalizedOperationFailureKindV1::InvalidInput,
            LocalizedOperationFailureKindV1::IntentMismatch,
            LocalizedOperationFailureKindV1::IntentSlotMismatch,
            LocalizedOperationFailureKindV1::SchemaNotFound,
            LocalizedOperationFailureKindV1::SourceConflict,
            LocalizedOperationFailureKindV1::TargetConflict,
            LocalizedOperationFailureKindV1::StateConflict,
            LocalizedOperationFailureKindV1::ObjectExists,
            LocalizedOperationFailureKindV1::DuplicateActiveTarget,
            LocalizedOperationFailureKindV1::InvalidSupersession,
            LocalizedOperationFailureKindV1::InvalidRepairEvidence,
            LocalizedOperationFailureKindV1::NotDraft,
            LocalizedOperationFailureKindV1::NotReady,
            LocalizedOperationFailureKindV1::NotSubmitted,
            LocalizedOperationFailureKindV1::NotApproved,
            LocalizedOperationFailureKindV1::EvidenceMissing,
            LocalizedOperationFailureKindV1::LimitExceeded,
            LocalizedOperationFailureKindV1::PolicyDenied,
        ];

        for kind in kinds {
            let failure = LocalizedOperationFailureV1::new(
                proof_application::authority::AuthorityOperation::ChangesetAddV2,
                kind,
            )
            .unwrap();
            let expected = kind.public_problem();
            let problem =
                localized_operation_failure_problem(failure, decision_record_digest, context);
            assert_eq!(problem.problem_type, expected.problem_type);
            assert_eq!(problem.title, expected.title);
            assert_eq!(problem.code, expected.code);
            assert_eq!(problem.retryable, expected.retryable);
            assert_eq!(
                problem.detail.as_deref(),
                Some(
                    "authorization allow decision recorded as blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            );
        }
    }

    #[test]
    fn broker_rejects_noncanonical_invocation_before_execution() {
        let input: CommandInputV1 = serde_json::from_str(STATUS_COMMAND).unwrap();
        let signer = FileCredentialSigner {
            binding_id: "019c0000-0000-7000-8000-000000000004"
                .parse::<BindingId>()
                .unwrap(),
            provider: Ed25519SigningProvider::from_secret_bytes(&[31_u8; 32]),
        };
        let invocation = signer
            .sign_authenticated_command(SignAuthenticatedCommandV1 {
                command_input: input,
                binding_id: signer.binding_id,
                presentation_id: "019c0000-0000-7000-8000-000000000006"
                    .parse::<PresentationId>()
                    .unwrap(),
                issued_at: "2026-08-17T20:02:00Z".parse::<Timestamp>().unwrap(),
                expires_at: "2026-08-17T20:07:00Z".parse::<Timestamp>().unwrap(),
            })
            .unwrap();
        let frame = canonical_invocation(&invocation).unwrap();
        let mut with_newline = frame.into_bytes();
        with_newline.push(b'\n');
        assert!(parse_canonical_invocation(&with_newline).is_err());
    }
}
