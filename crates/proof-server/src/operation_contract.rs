//! Runtime validation against the frozen HTTP operation registry and Schema
//! graph (contract §"HTTP boundary").

use std::sync::OnceLock;

use jsonschema::Registry;
use proof_remote::{HttpRouteV1, RemoteOperationV1};
use serde_json::{Value, json};

use crate::ServerError;

const HTTP_REGISTRY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json"
));

const SCHEMAS: &[&[u8]] = &[
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/application-operations-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/artifact-catalog-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/collaboration-artifacts-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/enrollment-vector-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/http-envelope-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/http-operation-registry-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/migration-rebuild-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/outbox-delivery-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/preview-delivery-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/rejected-case-manifest-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/remote-auth-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/remote-authority-dsse-vector-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/remote-evidence-v2.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/storage-delivery-contract-manifest-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/collaboration-server/schemas/storage-transaction-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authenticated-invocation-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authenticated-subject-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/command-input-v1.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/delegation-revocation-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/delegation-v2.schema.json"),
    include_bytes!("../../../conformance/v1/authority/schemas/operation-v1.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authority-operation-registry-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authorization-decision-v2.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/principal-binding-revocation-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/principal-binding-v1.schema.json"),
    include_bytes!("../../../conformance/v2/localized-content/schemas/artifacts.schema.json"),
    include_bytes!("../../../conformance/v2/localized-content/schemas/operations.schema.json"),
];

const HUMAN_REQUEST_SCHEMA: &str = concat!(
    "https://proof.dev/schema/collaboration-server/http-envelope/v1",
    "#/$defs/humanOperationRequestV1"
);
const AGENT_REQUEST_SCHEMA: &str = concat!(
    "https://proof.dev/schema/collaboration-server/http-envelope/v1",
    "#/$defs/agentOperationRequestV1"
);
const RESULT_ENVELOPE_SCHEMA: &str = concat!(
    "https://proof.dev/schema/collaboration-server/http-envelope/v1",
    "#/$defs/operationResultV1"
);

/// One route-qualified operation row from the frozen HTTP registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationContract {
    pub(crate) route: HttpRouteV1,
    pub(crate) operation: RemoteOperationV1,
    pub(crate) input_schema: String,
    pub(crate) result_schema: String,
    pub(crate) application_idempotency: String,
}

pub(crate) fn validate_human_request(value: &Value) -> Result<(), ServerError> {
    validate_input_schema(HUMAN_REQUEST_SCHEMA, value)
}

pub(crate) fn validate_agent_request(value: &Value) -> Result<(), ServerError> {
    validate_input_schema(AGENT_REQUEST_SCHEMA, value)
}

pub(crate) fn validate_operation_input(
    contract: &OperationContract,
    value: &Value,
) -> Result<(), ServerError> {
    validate_input_schema(&contract.input_schema, value)
}

pub(crate) fn validate_operation_result(
    contract: &OperationContract,
    value: &Value,
) -> Result<(), ServerError> {
    validate_schema(&contract.result_schema, value).map_err(|error| {
        ServerError::Internal(format!(
            "operation result failed its frozen Schema `{}`: {error}",
            contract.result_schema
        ))
    })
}

pub(crate) fn validate_result_envelope(value: &Value) -> Result<(), ServerError> {
    validate_schema(RESULT_ENVELOPE_SCHEMA, value).map_err(|error| {
        ServerError::Internal(format!(
            "HTTP operation result failed its frozen envelope Schema: {error}"
        ))
    })
}

pub(crate) fn resolve_operation(
    route: HttpRouteV1,
    operation: &RemoteOperationV1,
) -> Result<&'static OperationContract, ServerError> {
    operation_contracts()
        .iter()
        .find(|contract| contract.route == route && contract.operation == *operation)
        .ok_or_else(|| {
            ServerError::Dispatch(format!(
                "operation `{}/{}` is absent from route `{}`",
                operation.name,
                operation.version,
                route.path()
            ))
        })
}

fn validate_input_schema(reference: &str, value: &Value) -> Result<(), ServerError> {
    validate_schema(reference, value).map_err(|_| {
        ServerError::Dispatch(format!(
            "request value failed its frozen Schema `{reference}`"
        ))
    })
}

fn validate_schema(reference: &str, value: &Value) -> Result<(), String> {
    let validator = jsonschema::options()
        .with_registry(schema_registry())
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": reference,
        }))
        .map_err(|error| error.to_string())?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err(validator.iter_errors(value).next().map_or_else(
            || "Schema validation failed".to_owned(),
            |error| error.to_string(),
        ))
    }
}

fn schema_registry() -> &'static Registry<'static> {
    static REGISTRY: OnceLock<Registry<'static>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = Registry::new();
        for bytes in SCHEMAS {
            let schema = proof_canonical::parse_strict(bytes)
                .expect("checked-in collaboration Schema must strict-parse");
            let identifier = schema
                .get("$id")
                .and_then(Value::as_str)
                .expect("checked-in collaboration Schema must declare $id")
                .to_owned();
            registry = registry
                .add(identifier, schema)
                .expect("checked-in collaboration Schema must be a resource");
        }
        registry
            .prepare()
            .expect("complete collaboration Schema graph must resolve")
    })
}

fn operation_contracts() -> &'static [OperationContract] {
    static CONTRACTS: OnceLock<Vec<OperationContract>> = OnceLock::new();
    CONTRACTS.get_or_init(|| {
        let registry = proof_canonical::parse_strict(HTTP_REGISTRY)
            .expect("checked-in HTTP registry must strict-parse");
        let routes = registry
            .get("routes")
            .and_then(Value::as_array)
            .expect("checked-in HTTP registry must carry routes");
        let mut contracts = Vec::new();
        for route in routes {
            let route_id = route
                .get("route_id")
                .and_then(Value::as_str)
                .expect("registry route must carry route_id");
            let route_kind = match route_id {
                "human-operations" => HttpRouteV1::HumanOperations,
                "agent-operations" => HttpRouteV1::AgentOperations,
                _ => continue,
            };
            for row in route
                .get("operations")
                .and_then(Value::as_array)
                .expect("operation route must carry operations")
            {
                contracts.push(OperationContract {
                    route: route_kind,
                    operation: serde_json::from_value(
                        row.get("operation")
                            .cloned()
                            .expect("registry row must carry operation"),
                    )
                    .expect("registry operation must deserialize"),
                    input_schema: required_string(row, "input_schema"),
                    result_schema: required_string(row, "result_schema"),
                    application_idempotency: required_string(row, "application_idempotency"),
                });
            }
        }
        contracts
    })
}

fn required_string(value: &Value, member: &str) -> String {
    value
        .get(member)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("registry row must carry string `{member}`"))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUMAN_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/http-human-operation.valid.json"
    ));
    const AGENT_VECTOR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/http-agent-operation.valid.json"
    ));

    fn vector(bytes: &[u8]) -> Value {
        proof_canonical::parse_strict(bytes).expect("retained HTTP vector must strict-parse")
    }

    #[test]
    fn retained_requests_validate_with_their_exact_closed_members() {
        let human = vector(HUMAN_VECTOR);
        validate_human_request(&human).expect("retained Human request");
        let agent = vector(AGENT_VECTOR);
        validate_agent_request(&agent).expect("retained Agent request");

        let mut nullable = human;
        nullable["correlation_id"] = Value::Null;
        validate_human_request(&nullable).expect("the required Human correlation may be null");
    }

    #[test]
    fn request_schemas_reject_missing_unknown_and_cross_route_members() {
        let human = vector(HUMAN_VECTOR);
        for member in [
            "api_version",
            "workspace_id",
            "operation",
            "correlation_id",
            "idempotency_key",
            "input",
        ] {
            let mut candidate = human.clone();
            candidate
                .as_object_mut()
                .expect("Human vector is an object")
                .remove(member);
            assert!(
                validate_human_request(&candidate).is_err(),
                "missing Human member `{member}` must reject"
            );
        }
        for (member, value) in [("invocation", json!({})), ("unexpected", json!(true))] {
            let mut candidate = human.clone();
            candidate[member] = value;
            assert!(
                validate_human_request(&candidate).is_err(),
                "Human cross-route/unknown member `{member}` must reject"
            );
        }
        let mut malformed_correlation = human;
        malformed_correlation["correlation_id"] = json!("not-a-uuidv7");
        assert!(validate_human_request(&malformed_correlation).is_err());

        let agent = vector(AGENT_VECTOR);
        for member in ["api_version", "operation", "correlation_id", "invocation"] {
            let mut candidate = agent.clone();
            candidate
                .as_object_mut()
                .expect("Agent vector is an object")
                .remove(member);
            assert!(
                validate_agent_request(&candidate).is_err(),
                "missing Agent member `{member}` must reject"
            );
        }
        for (member, value) in [
            (
                "workspace_id",
                json!("019e0000-0000-7000-8000-000000000001"),
            ),
            ("idempotency_key", Value::Null),
            ("input", json!({})),
        ] {
            let mut candidate = agent.clone();
            candidate[member] = value;
            assert!(
                validate_agent_request(&candidate).is_err(),
                "Agent Human-only member `{member}` must reject"
            );
        }
    }

    #[test]
    fn operation_resolution_is_actor_and_route_qualified() {
        let human: RemoteOperationV1 = serde_json::from_value(
            vector(HUMAN_VECTOR)
                .get("operation")
                .cloned()
                .expect("Human vector operation"),
        )
        .expect("Human operation");
        let agent: RemoteOperationV1 = serde_json::from_value(
            vector(AGENT_VECTOR)
                .get("operation")
                .cloned()
                .expect("Agent vector operation"),
        )
        .expect("Agent operation");

        resolve_operation(HttpRouteV1::HumanOperations, &human)
            .expect("Human pair resolves only on the Human route");
        assert!(resolve_operation(HttpRouteV1::AgentOperations, &human).is_err());
        resolve_operation(HttpRouteV1::AgentOperations, &agent)
            .expect("Agent pair resolves only on the Agent route");
        assert!(resolve_operation(HttpRouteV1::HumanOperations, &agent).is_err());

        let wrong_major = RemoteOperationV1 {
            name: agent.name,
            version: "proof.dev/operation/workspace.status/v2".to_owned(),
        };
        assert!(resolve_operation(HttpRouteV1::AgentOperations, &wrong_major).is_err());
    }
}
