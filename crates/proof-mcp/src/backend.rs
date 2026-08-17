//! Concrete local application adapter for MCP tools.

#![expect(
    clippy::result_large_err,
    reason = "the application Problem is the structured adapter error contract"
)]

use std::{
    collections::BTreeSet,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use proof_application::{
    BuildContextPackCommand, CapabilityIdempotency, CapabilitySideEffect, ChangeSetIntent,
    ContextPack, ContextPackError, ContextPackLimits, CorrelationId,
    DelegatedWorkspaceStatusCommand, DelegatedWorkspaceStatusError, OperationId, Problem,
    QueryReleasedObjectsCommand, QueryReleasedObjectsError, ReleasedObjectQuery, Timestamp,
    build_context_pack, capabilities, delegated_workspace_status, query_released_objects,
};
use proof_local::LocalWorkspace;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::ToolBackend;

const CAPABILITIES_TOOL: &str = "proof.capabilities.list";

/// MCP backend over one explicitly selected local Workspace.
pub struct LocalBackend {
    workspace: LocalWorkspace,
}

impl LocalBackend {
    /// Selects a local Workspace root without performing a protocol write.
    ///
    /// # Errors
    ///
    /// Returns a caller-safe description when the root cannot be selected.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        LocalWorkspace::new(root)
            .map(|workspace| Self { workspace })
            .map_err(|error| error.to_string())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one exhaustive dispatch keeps registry names visibly bound to application operations"
    )]
    fn invoke(&self, name: &str, arguments: &Map<String, Value>) -> Result<Value, Problem> {
        let context = InvocationContext::new();
        match name {
            CAPABILITIES_TOOL => {
                ensure_keys(arguments, &[], "capabilities.list", context)?;
                let descriptors = serde_json::to_value(capabilities()).map_err(|_| {
                    internal_problem(
                        "capabilities.list",
                        context,
                        "capability serialization failed",
                    )
                })?;
                Ok(json!({ "capabilities": descriptors }))
            }
            "proof.workspace.status" => {
                let operation = "workspace.status";
                ensure_keys(
                    arguments,
                    &["operating_principal_id", "delegation_id"],
                    operation,
                    context,
                )?;
                let status = delegated_workspace_status(
                    &self.workspace,
                    DelegatedWorkspaceStatusCommand {
                        operating_principal_id: parse_required(
                            arguments,
                            "operating_principal_id",
                            operation,
                            context,
                        )?,
                        delegation_id: parse_required(
                            arguments,
                            "delegation_id",
                            operation,
                            context,
                        )?,
                        evaluated_at: now(operation, context)?,
                    },
                )
                .map_err(|error| delegated_status_problem(&error, operation, context))?;
                Ok(json!({
                    "workspace_id": status.workspace_id.to_string(),
                    "principal_id": status.principal_id.to_string(),
                    "delegation_id": status.delegation_id.to_string(),
                    "storage_schema_version": status.storage_schema_version,
                    "authoritative_sequence": status.authoritative_sequence,
                    "state_digest": status.state_digest.to_string(),
                    "authorization_decision_digest": status.authorization_decision_digest.to_string(),
                }))
            }
            "proof.object.query_released" => {
                let operation = "object.query_released";
                ensure_keys(
                    arguments,
                    &[
                        "operating_principal_id",
                        "delegation_id",
                        "environment_id",
                        "object_ids",
                    ],
                    operation,
                    context,
                )?;
                let query = query_released_objects(
                    &self.workspace,
                    QueryReleasedObjectsCommand {
                        operating_principal_id: Some(parse_required(
                            arguments,
                            "operating_principal_id",
                            operation,
                            context,
                        )?),
                        delegation_id: Some(parse_required(
                            arguments,
                            "delegation_id",
                            operation,
                            context,
                        )?),
                        environment_id: parse_required(
                            arguments,
                            "environment_id",
                            operation,
                            context,
                        )?,
                        object_ids: parse_required_array(
                            arguments,
                            "object_ids",
                            operation,
                            context,
                        )?,
                        evaluated_at: now(operation, context)?,
                    },
                )
                .map_err(|error| query_problem(&error, operation, context))?;
                Ok(released_query_value(&query))
            }
            "proof.context.build" => {
                let operation = "context.build";
                ensure_keys(
                    arguments,
                    &[
                        "operating_principal_id",
                        "delegation_id",
                        "task_id",
                        "intent",
                        "environment_id",
                        "object_ids",
                        "max_objects",
                        "max_bytes",
                        "idempotency_key",
                        "expires_at",
                    ],
                    operation,
                    context,
                )?;
                let intent = required_string(arguments, "intent", operation, context)?;
                let pack = build_context_pack(
                    &self.workspace,
                    BuildContextPackCommand {
                        context_pack_id: generated_id(),
                        operating_principal_id: parse_required(
                            arguments,
                            "operating_principal_id",
                            operation,
                            context,
                        )?,
                        delegation_id: parse_required(
                            arguments,
                            "delegation_id",
                            operation,
                            context,
                        )?,
                        task_id: required_string(arguments, "task_id", operation, context)?
                            .to_owned(),
                        intent: ChangeSetIntent::new(intent.to_owned()).map_err(|error| {
                            input_problem(operation, context, error.to_string())
                        })?,
                        environment_id: parse_required(
                            arguments,
                            "environment_id",
                            operation,
                            context,
                        )?,
                        object_ids: parse_required_array(
                            arguments,
                            "object_ids",
                            operation,
                            context,
                        )?,
                        limits: ContextPackLimits {
                            max_objects: required_u32(
                                arguments,
                                "max_objects",
                                operation,
                                context,
                            )?,
                            max_bytes: required_u64(arguments, "max_bytes", operation, context)?,
                        },
                        idempotency_key: parse_required(
                            arguments,
                            "idempotency_key",
                            operation,
                            context,
                        )?,
                        built_at: now(operation, context)?,
                        expires_at: parse_required(arguments, "expires_at", operation, context)?,
                    },
                )
                .map_err(|error| context_problem(&error, operation, context))?;
                Ok(context_pack_value(&pack))
            }
            _ => Err(input_problem(
                name,
                context,
                "the requested MCP tool is not registered".to_owned(),
            )),
        }
    }
}

impl ToolBackend for LocalBackend {
    fn tools(&self) -> Vec<Value> {
        let mut tools = vec![json!({
            "name": CAPABILITIES_TOOL,
            "description": "List the exact application capabilities exposed by this server.",
            "inputSchema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": false
            },
            "outputSchema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "additionalProperties": false,
                "properties": { "capabilities": { "type": "array", "items": { "type": "object" } } },
                "required": ["capabilities"]
            },
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        })];
        tools.extend(capabilities().iter().map(|descriptor| {
            let input_schema: Value = serde_json::from_str(descriptor.input_schema_json)
                .expect("static capability input Schema must remain valid JSON");
            let output_schema: Value = serde_json::from_str(descriptor.output_schema_json)
                .expect("static capability output Schema must remain valid JSON");
            json!({
                "name": format!("proof.{}", descriptor.operation),
                "description": descriptor.description,
                "inputSchema": input_schema,
                "outputSchema": output_schema,
                "annotations": {
                    "readOnlyHint": descriptor.side_effect == CapabilitySideEffect::ReadOnly,
                    "destructiveHint": false,
                    "idempotentHint": descriptor.idempotency != CapabilityIdempotency::Required
                        || descriptor.side_effect == CapabilitySideEffect::EvidenceWrite,
                    "openWorldHint": false
                }
            })
        }));
        tools
    }

    fn call(&self, name: &str, arguments: &Map<String, Value>) -> Result<Value, Value> {
        self.invoke(name, arguments)
            .map_err(|problem| serde_json::to_value(problem).expect("Problem must serialize"))
    }
}

#[derive(Clone, Copy)]
struct InvocationContext {
    operation_id: OperationId,
    correlation_id: CorrelationId,
}

impl InvocationContext {
    fn new() -> Self {
        Self {
            operation_id: generated_id(),
            correlation_id: generated_id(),
        }
    }
}

fn generated_id<T>() -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7()
        .to_string()
        .parse()
        .expect("UUIDv7 must parse as an operational identifier")
}

fn now(operation: &str, context: InvocationContext) -> Result<Timestamp, Problem> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| input_problem(operation, context, error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos())
        .map_err(|error| input_problem(operation, context, error.to_string()))?;
    Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| input_problem(operation, context, error.to_string()))
}

fn ensure_keys(
    arguments: &Map<String, Value>,
    expected: &[&str],
    operation: &str,
    context: InvocationContext,
) -> Result<(), Problem> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if arguments.keys().any(|key| !expected.contains(key.as_str())) {
        return Err(input_problem(
            operation,
            context,
            "tool arguments contain an unknown property".to_owned(),
        ));
    }
    Ok(())
}

fn required_string<'a>(
    arguments: &'a Map<String, Value>,
    name: &str,
    operation: &str,
    context: InvocationContext,
) -> Result<&'a str, Problem> {
    arguments.get(name).and_then(Value::as_str).ok_or_else(|| {
        input_problem(
            operation,
            context,
            format!("`{name}` is required and must be a string"),
        )
    })
}

fn parse_required<T>(
    arguments: &Map<String, Value>,
    name: &str,
    operation: &str,
    context: InvocationContext,
) -> Result<T, Problem>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    required_string(arguments, name, operation, context)?
        .parse()
        .map_err(|error: T::Err| {
            input_problem(operation, context, format!("invalid `{name}`: {error}"))
        })
}

fn parse_required_array<T>(
    arguments: &Map<String, Value>,
    name: &str,
    operation: &str,
    context: InvocationContext,
) -> Result<Vec<T>, Problem>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let values = arguments
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            input_problem(
                operation,
                context,
                format!("`{name}` is required and must be an array"),
            )
        })?;
    values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or_else(|| {
                input_problem(
                    operation,
                    context,
                    format!("every `{name}` entry must be a string"),
                )
            })?;
            value.parse().map_err(|error: T::Err| {
                input_problem(
                    operation,
                    context,
                    format!("invalid `{name}` entry: {error}"),
                )
            })
        })
        .collect()
}

fn required_u64(
    arguments: &Map<String, Value>,
    name: &str,
    operation: &str,
    context: InvocationContext,
) -> Result<u64, Problem> {
    arguments.get(name).and_then(Value::as_u64).ok_or_else(|| {
        input_problem(
            operation,
            context,
            format!("`{name}` is required and must be a non-negative integer"),
        )
    })
}

fn required_u32(
    arguments: &Map<String, Value>,
    name: &str,
    operation: &str,
    context: InvocationContext,
) -> Result<u32, Problem> {
    u32::try_from(required_u64(arguments, name, operation, context)?)
        .map_err(|error| input_problem(operation, context, format!("invalid `{name}`: {error}")))
}

fn released_query_value(query: &ReleasedObjectQuery) -> Value {
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

fn context_pack_value(pack: &ContextPack) -> Value {
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
        "limits": {
            "max_objects": pack.limits.max_objects,
            "max_bytes": pack.limits.max_bytes,
        },
        "built_at": pack.built_at.to_string(),
        "expires_at": pack.expires_at.to_string(),
        "capabilities": pack.capabilities,
        "manifest_json": pack.manifest_json,
        "context_pack_digest": pack.context_pack_digest.to_string(),
    })
}

fn input_problem(operation: &str, context: InvocationContext, detail: String) -> Problem {
    mapped_problem(
        "urn:proof:problem:input-schema-mismatch",
        "The MCP tool arguments do not satisfy the operation contract",
        "proof.input.schema_mismatch",
        operation,
        context,
        Some(detail),
        false,
    )
}

fn internal_problem(operation: &str, context: InvocationContext, detail: &str) -> Problem {
    mapped_problem(
        "urn:proof:problem:internal",
        "The MCP operation could not produce a result",
        "proof.internal",
        operation,
        context,
        Some(detail.to_owned()),
        false,
    )
}

fn delegated_status_problem(
    error: &DelegatedWorkspaceStatusError,
    operation: &str,
    context: InvocationContext,
) -> Problem {
    let (problem_type, title, code, retryable) = match error {
        DelegatedWorkspaceStatusError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The local identity is not authenticated for this Workspace",
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
            "Workspace status failed deterministic verification",
            "proof.digest.mismatch",
            false,
        ),
        DelegatedWorkspaceStatusError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Workspace status storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    mapped_problem(
        problem_type,
        title,
        code,
        operation,
        context,
        matches!(error, DelegatedWorkspaceStatusError::Integrity(_)).then(|| error.to_string()),
        retryable,
    )
}

fn query_problem(
    error: &QueryReleasedObjectsError,
    operation: &str,
    context: InvocationContext,
) -> Problem {
    let (problem_type, title, code, retryable) = match error {
        QueryReleasedObjectsError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The local identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        QueryReleasedObjectsError::Denied => (
            "urn:proof:problem:authority-denied",
            "The released Object query is outside delegated authority",
            "proof.auth.denied",
            false,
        ),
        QueryReleasedObjectsError::InvalidQuery => (
            "urn:proof:problem:input-schema-mismatch",
            "The released Object query is invalid",
            "proof.input.schema_mismatch",
            false,
        ),
        QueryReleasedObjectsError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "A requested released Object resource was not found",
            "proof.resource.not_found",
            false,
        ),
        QueryReleasedObjectsError::Integrity(_) => (
            "urn:proof:problem:digest-mismatch",
            "Released Object integrity verification failed",
            "proof.digest.mismatch",
            false,
        ),
        QueryReleasedObjectsError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Released Object storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let detail = matches!(
        error,
        QueryReleasedObjectsError::Integrity(_) | QueryReleasedObjectsError::Storage(_)
    )
    .then(|| error.to_string());
    mapped_problem(
        problem_type,
        title,
        code,
        operation,
        context,
        detail,
        retryable,
    )
}

fn context_problem(
    error: &ContextPackError,
    operation: &str,
    context: InvocationContext,
) -> Problem {
    let (problem_type, title, code, retryable) = match error {
        ContextPackError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The local identity is not authenticated for this Workspace",
            "proof.auth.unauthenticated",
            false,
        ),
        ContextPackError::Denied => (
            "urn:proof:problem:authority-denied",
            "ContextPack assembly is outside delegated authority",
            "proof.auth.denied",
            false,
        ),
        ContextPackError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "A requested ContextPack source was not found",
            "proof.resource.not_found",
            false,
        ),
        ContextPackError::LimitExceeded => (
            "urn:proof:problem:input-too-large",
            "The ContextPack request exceeds a bounded constraint",
            "proof.input.too_large",
            false,
        ),
        ContextPackError::Expired => (
            "urn:proof:problem:delegation-expired",
            "The ContextPack authority or artifact has expired",
            "proof.delegation.expired",
            false,
        ),
        ContextPackError::IdempotencyKeyReused => (
            "urn:proof:problem:idempotency-key-reused",
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
            false,
        ),
        ContextPackError::Integrity(_) => (
            "urn:proof:problem:digest-mismatch",
            "ContextPack integrity verification failed",
            "proof.digest.mismatch",
            false,
        ),
        ContextPackError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "ContextPack storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    let detail = matches!(
        error,
        ContextPackError::Integrity(_) | ContextPackError::Storage(_)
    )
    .then(|| error.to_string());
    mapped_problem(
        problem_type,
        title,
        code,
        operation,
        context,
        detail,
        retryable,
    )
}

fn mapped_problem(
    problem_type: &str,
    title: &str,
    code: &str,
    operation: &str,
    context: InvocationContext,
    detail: Option<String>,
    retryable: bool,
) -> Problem {
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = detail;
    problem.retryable = retryable;
    problem
}

#[cfg(test)]
mod tests {
    use super::{CAPABILITIES_TOOL, LocalBackend};
    use crate::ToolBackend;

    #[test]
    fn tool_registry_comes_from_application_capabilities() {
        let backend = LocalBackend::new(".").unwrap();
        let tools = backend.tools();

        assert_eq!(tools.len(), proof_application::capabilities().len() + 1);
        assert_eq!(tools[0]["name"], CAPABILITIES_TOOL);
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "proof.capabilities.list",
                "proof.workspace.status",
                "proof.object.query_released",
                "proof.context.build",
            ]
        );
        for descriptor in proof_application::capabilities() {
            let name = format!("proof.{}", descriptor.operation);
            let tool = tools
                .iter()
                .find(|candidate| candidate["name"] == name)
                .unwrap();
            assert_eq!(
                tool["inputSchema"],
                serde_json::from_str::<serde_json::Value>(descriptor.input_schema_json).unwrap()
            );
            assert_eq!(
                tool["outputSchema"],
                serde_json::from_str::<serde_json::Value>(descriptor.output_schema_json).unwrap()
            );
            let required = tool["inputSchema"]["required"].as_array().unwrap();
            assert!(
                required
                    .iter()
                    .any(|field| field == "operating_principal_id")
            );
            assert!(required.iter().any(|field| field == "delegation_id"));
        }
    }
}
