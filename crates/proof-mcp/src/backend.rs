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
    CapabilityIdempotency, CapabilitySideEffect, ContextPack, CorrelationId, OperationId, Problem,
    ReleasedObjectQuery, Timestamp,
    authority::{
        AuthenticatedAuthorityExecutor, AuthenticatedCommandEnvelopeJson, AuthenticatedCommandV1,
        AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1,
        AuthenticatedOperationFailureV1, AuthenticatedOperationResultV1, AuthorityError,
        AuthorityOperation, CommandInputApiVersion, CommandInputV1,
    },
    capabilities,
};
use proof_attestation::authority::{AuthorityPayloadProfile, parse_authority_envelope};
use proof_local::LocalWorkspace;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{AuthenticationMetadata, ToolBackend};

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

    fn invoke(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        authentication: AuthenticationMetadata<'_>,
    ) -> Result<Value, Problem> {
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
                let invocation = authenticated_invocation(
                    arguments,
                    authentication,
                    AuthorityOperation::WorkspaceStatusV1,
                    Map::new(),
                    operation,
                    context,
                )?;
                self.execute(invocation, operation, context)
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
                let invocation = authenticated_invocation(
                    arguments,
                    authentication,
                    AuthorityOperation::ObjectQueryReleasedV1,
                    arguments.clone(),
                    operation,
                    context,
                )?;
                self.execute(invocation, operation, context)
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
                let invocation = authenticated_invocation(
                    arguments,
                    authentication,
                    AuthorityOperation::ContextBuildV1,
                    arguments.clone(),
                    operation,
                    context,
                )?;
                self.execute(invocation, operation, context)
            }
            _ => Err(input_problem(
                name,
                context,
                "the requested MCP tool is not registered".to_owned(),
            )),
        }
    }

    fn execute(
        &self,
        invocation: AuthenticatedInvocationV1,
        operation: &str,
        context: InvocationContext,
    ) -> Result<Value, Problem> {
        let execution = self
            .workspace
            .execute_authenticated(invocation, now(operation, context)?)
            .map_err(|error| authority_problem(&error, operation, context))?;
        match execution.result {
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
            AuthenticatedOperationResultV1::ReleasedObjectQuery(query) => Ok(released_query_value(
                &query,
                execution.decision_record_digest,
            )),
            AuthenticatedOperationResultV1::ContextPack(pack) => Ok(context_pack_value(&pack)),
            AuthenticatedOperationResultV1::Failure(failure) => Err(operation_failure_problem(
                failure,
                execution.decision_record_digest,
                operation,
                context,
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

    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        authentication: AuthenticationMetadata<'_>,
    ) -> Result<Value, Value> {
        self.invoke(name, arguments, authentication)
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

fn authenticated_invocation(
    arguments: &Map<String, Value>,
    authentication: AuthenticationMetadata<'_>,
    operation: AuthorityOperation,
    normalized_input: Map<String, Value>,
    operation_name: &str,
    context: InvocationContext,
) -> Result<AuthenticatedInvocationV1, Problem> {
    let envelope = match authentication {
        AuthenticationMetadata::Envelope(envelope) => envelope,
        AuthenticationMetadata::Missing | AuthenticationMetadata::InvalidType => {
            return Err(authority_problem(
                &AuthorityError::AuthMalformed,
                operation_name,
                context,
            ));
        }
    };
    let parsed = parse_authority_envelope::<AuthenticatedCommandV1>(
        envelope.as_bytes(),
        AuthorityPayloadProfile::AuthenticatedCommand,
    )
    .map_err(|_| authority_problem(&AuthorityError::AuthMalformed, operation_name, context))?;
    let operating_principal_id =
        parse_required(arguments, "operating_principal_id", operation_name, context)?;
    let delegation_id = parse_required(arguments, "delegation_id", operation_name, context)?;
    let idempotency_key = match operation {
        AuthorityOperation::ContextBuildV1 => Some(parse_required(
            arguments,
            "idempotency_key",
            operation_name,
            context,
        )?),
        AuthorityOperation::WorkspaceStatusV1 | AuthorityOperation::ObjectQueryReleasedV1 => None,
        _ => {
            return Err(authority_problem(
                &AuthorityError::AuthMalformed,
                operation_name,
                context,
            ));
        }
    };
    let authentication = AuthenticatedCommandEnvelopeJson::new(envelope.to_owned())
        .map_err(|_| authority_problem(&AuthorityError::AuthMalformed, operation_name, context))?;
    let mut command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: parsed.payload.workspace_id,
        operation,
        requesting_principal_id: parsed.payload.requesting_principal_id,
        operating_principal_id,
        delegation_id,
        idempotency_key,
        normalized_input,
    };
    command_input
        .normalize_for_authenticated_execution()
        .map_err(|_| authority_problem(&AuthorityError::AuthMalformed, operation_name, context))?;
    command_input
        .validate_for_authenticated_execution()
        .map_err(|_| authority_problem(&AuthorityError::AuthMalformed, operation_name, context))?;
    Ok(AuthenticatedInvocationV1 {
        api_version: AuthenticatedInvocationApiVersion::V1,
        command_input,
        authentication,
    })
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

fn released_query_value(
    query: &ReleasedObjectQuery,
    authorization_decision_digest: proof_application::ContentDigest,
) -> Value {
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
        "authorization_decision_digest": authorization_decision_digest.to_string(),
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

fn authority_problem(
    error: &AuthorityError,
    operation: &str,
    context: InvocationContext,
) -> Problem {
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
    problem
}

fn operation_failure_problem(
    failure: AuthenticatedOperationFailureV1,
    decision_record_digest: proof_application::ContentDigest,
    operation: &str,
    context: InvocationContext,
) -> Problem {
    let (problem_type, title) = match failure {
        AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound => (
            "urn:proof:problem:resource-not-found",
            "A requested released Object resource was not found",
        ),
        AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The v1 query is unsupported for the current Release version",
        ),
        AuthenticatedOperationFailureV1::ContextBuildNotFound => (
            "urn:proof:problem:resource-not-found",
            "A requested ContextPack source was not found",
        ),
        AuthenticatedOperationFailureV1::ContextBuildLimitExceeded => (
            "urn:proof:problem:input-too-large",
            "The ContextPack request exceeds a bounded constraint",
        ),
        AuthenticatedOperationFailureV1::ContextBuildExpired => (
            "urn:proof:problem:delegation-expired",
            "The ContextPack authority or artifact has expired",
        ),
        AuthenticatedOperationFailureV1::ContextBuildDenied => (
            "urn:proof:problem:authority-denied",
            "ContextPack assembly is outside delegated authority",
        ),
    };
    mapped_problem(
        problem_type,
        title,
        failure.code(),
        operation,
        context,
        Some(format!(
            "authorization allow decision recorded as {decision_record_digest}"
        )),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CAPABILITIES_TOOL, InvocationContext, LocalBackend, authenticated_invocation,
        operation_failure_problem,
    };
    use crate::{
        AuthenticationMetadata, LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, ToolBackend,
        serve,
    };
    use proof_application::{
        CapabilitySideEffect, ContentDigest,
        authority::{AuthenticatedOperationFailureV1, AuthorityOperation, CommandInputV1},
    };
    use serde_json::{Map, Value, json};
    use std::io::Cursor;

    const AUTHENTICATED_INVOCATION_VECTOR: &str = include_str!(
        "../../../conformance/v1/authority/vectors/authenticated-invocation.valid.json"
    );
    const CONTEXT_COMMAND_INPUT_VECTOR: &str = include_str!(
        "../../../conformance/v1/authority/vectors/context-build.command-input.valid.json"
    );
    const CONTEXT_ENVELOPE_VECTOR: &str = include_str!(
        "../../../conformance/v1/authority/vectors/context-build.presentation-1.envelope.valid.json"
    );

    struct MappingBackend;

    impl ToolBackend for MappingBackend {
        fn tools(&self) -> Vec<Value> {
            vec![json!({ "name": "proof.workspace.status" })]
        }

        fn call(
            &self,
            name: &str,
            arguments: &Map<String, Value>,
            authentication: AuthenticationMetadata<'_>,
        ) -> Result<Value, Value> {
            let invocation = authenticated_invocation(
                arguments,
                authentication,
                AuthorityOperation::WorkspaceStatusV1,
                Map::new(),
                name.strip_prefix("proof.").unwrap(),
                InvocationContext::new(),
            )
            .map_err(|problem| serde_json::to_value(problem).unwrap())?;
            serde_json::to_value(invocation.command_input).map_err(|error| json!(error.to_string()))
        }
    }

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
            assert_eq!(descriptor.side_effect, CapabilitySideEffect::EvidenceWrite);
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
            assert_eq!(tool["annotations"]["readOnlyHint"], false);
        }
    }

    #[test]
    fn status_mapping_preserves_the_envelope_and_binds_exact_selectors() {
        let vector: Value = serde_json::from_str(AUTHENTICATED_INVOCATION_VECTOR).unwrap();
        let authentication = vector["authentication"].as_str().unwrap();
        let arguments = Map::from_iter([
            (
                "operating_principal_id".to_owned(),
                json!("019c0000-0000-7000-8000-000000000003"),
            ),
            (
                "delegation_id".to_owned(),
                json!("019c0000-0000-7000-8000-000000000005"),
            ),
        ]);

        let invocation = authenticated_invocation(
            &arguments,
            AuthenticationMetadata::Envelope(authentication),
            AuthorityOperation::WorkspaceStatusV1,
            Map::new(),
            "workspace.status",
            InvocationContext::new(),
        )
        .unwrap();

        assert_eq!(invocation.authentication.as_str(), authentication);
        assert_eq!(
            invocation.command_input.operating_principal_id.to_string(),
            "019c0000-0000-7000-8000-000000000003"
        );
        assert_eq!(
            invocation.command_input.delegation_id.to_string(),
            "019c0000-0000-7000-8000-000000000005"
        );
        assert!(invocation.command_input.normalized_input.is_empty());

        let mut substituted = arguments;
        substituted.insert(
            "operating_principal_id".to_owned(),
            json!("019c0000-0000-7000-8000-000000000007"),
        );
        let substituted = authenticated_invocation(
            &substituted,
            AuthenticationMetadata::Envelope(authentication),
            AuthorityOperation::WorkspaceStatusV1,
            Map::new(),
            "workspace.status",
            InvocationContext::new(),
        )
        .unwrap();
        assert_eq!(substituted.authentication.as_str(), authentication);
        assert_ne!(substituted.command_input, invocation.command_input);
    }

    #[test]
    fn missing_non_string_and_noncanonical_authentication_are_malformed() {
        for authentication in [
            AuthenticationMetadata::Missing,
            AuthenticationMetadata::InvalidType,
            AuthenticationMetadata::Envelope("{}"),
        ] {
            let error = authenticated_invocation(
                &Map::new(),
                authentication,
                AuthorityOperation::WorkspaceStatusV1,
                Map::new(),
                "workspace.status",
                InvocationContext::new(),
            )
            .unwrap_err();
            assert_eq!(error.code, "proof.auth.malformed");
        }
    }

    #[test]
    fn context_mapping_matches_the_ratified_command_input_exactly() {
        let expected: CommandInputV1 = serde_json::from_str(CONTEXT_COMMAND_INPUT_VECTOR).unwrap();
        let envelope_value: Value = serde_json::from_str(CONTEXT_ENVELOPE_VECTOR).unwrap();
        let envelope = serde_json::to_string(&envelope_value).unwrap();
        let invocation = authenticated_invocation(
            &expected.normalized_input,
            AuthenticationMetadata::Envelope(&envelope),
            AuthorityOperation::ContextBuildV1,
            expected.normalized_input.clone(),
            "context.build",
            InvocationContext::new(),
        )
        .unwrap();

        assert_eq!(invocation.command_input, expected);
        assert_eq!(invocation.authentication.as_str(), envelope);
    }

    #[test]
    fn query_mapping_uses_shared_sorting_and_duplicate_rejection() {
        let vector: Value = serde_json::from_str(AUTHENTICATED_INVOCATION_VECTOR).unwrap();
        let authentication = vector["authentication"].as_str().unwrap();
        let mut arguments = Map::from_iter([
            (
                "operating_principal_id".to_owned(),
                json!("019c0000-0000-7000-8000-000000000003"),
            ),
            (
                "delegation_id".to_owned(),
                json!("019c0000-0000-7000-8000-000000000005"),
            ),
            ("environment_id".to_owned(), json!("production")),
            (
                "object_ids".to_owned(),
                json!([
                    "019c0000-0000-7000-8000-000000000021",
                    "019c0000-0000-7000-8000-000000000020"
                ]),
            ),
        ]);
        let invocation = authenticated_invocation(
            &arguments,
            AuthenticationMetadata::Envelope(authentication),
            AuthorityOperation::ObjectQueryReleasedV1,
            arguments.clone(),
            "object.query_released",
            InvocationContext::new(),
        )
        .unwrap();
        assert_eq!(
            invocation.command_input.normalized_input["object_ids"],
            json!([
                "019c0000-0000-7000-8000-000000000020",
                "019c0000-0000-7000-8000-000000000021"
            ])
        );

        arguments.insert(
            "object_ids".to_owned(),
            json!([
                "019c0000-0000-7000-8000-000000000020",
                "019c0000-0000-7000-8000-000000000020"
            ]),
        );
        let error = authenticated_invocation(
            &arguments,
            AuthenticationMetadata::Envelope(authentication),
            AuthorityOperation::ObjectQueryReleasedV1,
            arguments.clone(),
            "object.query_released",
            InvocationContext::new(),
        )
        .unwrap_err();
        assert_eq!(error.code, "proof.auth.malformed");
    }

    #[test]
    fn authorized_operation_failures_report_the_committed_allow_decision() {
        let decision_record_digest: ContentDigest =
            "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .unwrap();
        let cases = [
            (
                AuthenticatedOperationFailureV1::ReleasedObjectQueryNotFound,
                "proof.resource.not_found",
            ),
            (
                AuthenticatedOperationFailureV1::ReleasedObjectQueryUnsupportedVersion,
                "proof.input.unsupported_version",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildNotFound,
                "proof.resource.not_found",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildLimitExceeded,
                "proof.input.too_large",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildExpired,
                "proof.delegation.expired",
            ),
            (
                AuthenticatedOperationFailureV1::ContextBuildDenied,
                "proof.auth.denied",
            ),
        ];

        for (failure, expected_code) in cases {
            let problem = operation_failure_problem(
                failure,
                decision_record_digest,
                "authenticated.operation",
                InvocationContext::new(),
            );
            assert_eq!(problem.code, expected_code);
            assert_eq!(
                problem.detail.as_deref(),
                Some(
                    "authorization allow decision recorded as blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                )
            );
            assert!(!problem.retryable);
        }
    }

    #[test]
    fn both_protocol_eras_reach_the_same_exact_command_mapper() {
        let vector: Value = serde_json::from_str(AUTHENTICATED_INVOCATION_VECTOR).unwrap();
        let authentication = vector["authentication"].as_str().unwrap();
        let arguments = json!({
            "operating_principal_id": "019c0000-0000-7000-8000-000000000003",
            "delegation_id": "019c0000-0000-7000-8000-000000000005"
        });
        let messages = [
            json!({
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": LEGACY_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "test", "version": "1" }
                }
            }),
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            json!({
                "jsonrpc": "2.0",
                "id": "legacy",
                "method": "tools/call",
                "params": {
                    "_meta": { "dev.proof/authentication": authentication },
                    "name": "proof.workspace.status",
                    "arguments": arguments
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "modern",
                "method": "tools/call",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "dev.proof/authentication": authentication
                    },
                    "name": "proof.workspace.status",
                    "arguments": arguments
                }
            }),
        ];
        let input = messages
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &MappingBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let responses = responses
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 3);
        for response in &responses[1..] {
            assert_eq!(
                response["result"]["structuredContent"],
                vector["command_input"]
            );
        }
    }
}
