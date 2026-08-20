use std::{
    io::{Cursor, Write},
    process::{Command, Stdio},
};

use proof_mcp::{
    AuthenticationMetadata, LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, REGISTRY_TTL_MS,
    SUPPORTED_PROTOCOL_VERSIONS, ToolBackend, serve,
};
use serde_json::{Map, Value, json};

struct FixtureBackend;

impl ToolBackend for FixtureBackend {
    fn tools(&self) -> Vec<Value> {
        vec![json!({
            "name": "proof.capabilities.list",
            "description": "List the operations available to this caller.",
            "inputSchema": { "type": "object", "additionalProperties": false },
            "outputSchema": {
                "type": "object",
                "properties": { "capabilities": { "type": "array" } },
                "required": ["capabilities"]
            },
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            }
        })]
    }

    fn call(
        &self,
        name: &str,
        _arguments: &Map<String, Value>,
        authentication: AuthenticationMetadata<'_>,
    ) -> Result<Value, Value> {
        assert_eq!(name, "proof.capabilities.list");
        assert_eq!(authentication, AuthenticationMetadata::Missing);
        Ok(json!({ "capabilities": [] }))
    }
}

struct ErrorBackend;

impl ToolBackend for ErrorBackend {
    fn tools(&self) -> Vec<Value> {
        FixtureBackend.tools()
    }

    fn call(
        &self,
        _name: &str,
        _arguments: &Map<String, Value>,
        _authentication: AuthenticationMetadata<'_>,
    ) -> Result<Value, Value> {
        Err(json!({
            "type": "urn:proof:problem:authority-denied",
            "title": "The operation is outside delegated authority",
            "code": "proof.auth.denied",
            "operation": "capabilities.list",
            "operation_id": "019c0000-0000-7000-8000-000000000001",
            "correlation_id": "019c0000-0000-7000-8000-000000000002",
            "retryable": false
        }))
    }
}

#[test]
fn legacy_fixture_falls_back_to_initialize_and_lists_tools() {
    let input = include_bytes!("fixtures/initialize-and-list.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let responses = String::from_utf8(output).unwrap();
    let lines = responses.lines().collect::<Vec<_>>();

    assert_eq!(
        lines.len(),
        2,
        "the initialized notification has no response"
    );
    let initialized: Value = serde_json::from_str(lines[0]).unwrap();
    let tools: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(initialized["id"], "initialize");
    assert_eq!(
        initialized["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    assert!(initialized["result"].get("resultType").is_none());
    assert_eq!(tools["id"], "tools");
    assert_eq!(
        tools["result"]["tools"][0]["name"],
        "proof.capabilities.list"
    );
    assert!(tools["result"].get("resultType").is_none());
}

#[test]
fn modern_fixture_discovers_lists_and_calls_without_initialize() {
    let input = include_bytes!("fixtures/modern-discover-list-call.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let responses = String::from_utf8(output).unwrap();
    let lines = responses.lines().collect::<Vec<_>>();

    assert_eq!(lines.len(), 3);
    let discover: Value = serde_json::from_str(lines[0]).unwrap();
    let tools: Value = serde_json::from_str(lines[1]).unwrap();
    let call: Value = serde_json::from_str(lines[2]).unwrap();
    for response in [&discover, &tools, &call] {
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(
            response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "proof-mcp"
        );
    }
    assert_eq!(
        discover["result"]["supportedVersions"],
        json!(SUPPORTED_PROTOCOL_VERSIONS)
    );
    assert_eq!(
        discover["result"]["supportedVersions"][0],
        MODERN_PROTOCOL_VERSION
    );
    assert_eq!(discover["result"]["ttlMs"], REGISTRY_TTL_MS);
    assert_eq!(discover["result"]["cacheScope"], "public");
    assert_eq!(tools["result"]["ttlMs"], REGISTRY_TTL_MS);
    assert_eq!(tools["result"]["cacheScope"], "public");
    assert_eq!(
        tools["result"]["tools"][0]["name"],
        "proof.capabilities.list"
    );
    assert_eq!(call["result"]["isError"], false);
    assert_eq!(
        call["result"]["structuredContent"]["capabilities"],
        json!([])
    );
}

#[test]
fn modern_fixture_rejects_missing_request_metadata() {
    let input = include_bytes!("fixtures/modern-missing-meta.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(response["error"]["code"], -32_602);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("_meta")
    );
}

#[test]
fn modern_fixture_returns_the_standard_unsupported_version_error() {
    let input = include_bytes!("fixtures/modern-unsupported-version.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(response["error"]["code"], -32_022);
    assert_eq!(response["error"]["data"]["requested"], "2099-01-01");
    assert_eq!(
        response["error"]["data"]["supported"],
        json!(SUPPORTED_PROTOCOL_VERSIONS)
    );
}

#[test]
fn modern_fixture_handles_each_request_independently() {
    let input = include_bytes!("fixtures/modern-stateless.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let responses = String::from_utf8(output).unwrap();
    let lines = responses.lines().collect::<Vec<_>>();

    assert_eq!(lines.len(), 2);
    for (line, expected_id) in lines.into_iter().zip(["first", "second"]) {
        let response: Value = serde_json::from_str(line).unwrap();
        assert_eq!(response["id"], expected_id);
        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(response["result"]["tools"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn invalid_id_fixture_returns_invalid_request_without_echoing_the_value() {
    let input = include_bytes!("fixtures/invalid-id.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &FixtureBackend).unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["error"]["code"], -32_600);
}

#[test]
fn domain_problem_fixture_is_json_text_without_success_structured_content() {
    let input = include_bytes!("fixtures/tool-error.ndjson");
    let mut output = Vec::new();
    serve(Cursor::new(input), &mut output, &ErrorBackend).unwrap();
    let response: Value = serde_json::from_slice(&output).unwrap();

    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"].get("structuredContent").is_none());
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    let problem: Value = serde_json::from_str(text).unwrap();
    assert_eq!(problem["code"], "proof.auth.denied");
}

#[test]
fn stdio_binary_keeps_stdout_protocol_clean() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_proof-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(include_bytes!("fixtures/modern-discover-list-call.ndjson"))
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let lines = String::from_utf8(output.stdout).unwrap();
    assert_eq!(lines.lines().count(), 3);
    for line in lines.lines() {
        let message: Value = serde_json::from_str(line).unwrap();
        assert_eq!(message["jsonrpc"], "2.0");
        assert_eq!(message["result"]["resultType"], "complete");
    }
}
