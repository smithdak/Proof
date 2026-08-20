#![forbid(unsafe_code)]

//! Protocol-clean stdio adapter for the Model Context Protocol.

mod backend;

use std::io::{self, BufRead, Write};

use serde_json::{Map, Value, json};

pub use backend::LocalBackend;

/// The current stateless MCP protocol revision implemented by this server.
pub const MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// The initialization-based MCP protocol revision retained for compatibility.
pub const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

/// The preferred MCP protocol revision.
pub const PROTOCOL_VERSION: &str = MODERN_PROTOCOL_VERSION;

/// Every protocol revision this dual-era server implements, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] =
    [MODERN_PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION];

/// Lifetime advertised for process-version-static discovery and tool metadata.
pub const REGISTRY_TTL_MS: u64 = 3_600_000;

/// Maximum size of one newline-delimited JSON-RPC message.
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// Exact authentication metadata carried by one MCP tool call.
///
/// The envelope variant borrows the JSON string value without parsing or
/// reconstructing it. This keeps the signed canonical DSSE bytes independent
/// from both modern protocol metadata and legacy session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationMetadata<'a> {
    /// The call did not carry `dev.proof/authentication`.
    Missing,
    /// The metadata key was present but its value was not a JSON string.
    InvalidType,
    /// The exact UTF-8 DSSE envelope string supplied by the caller.
    Envelope(&'a str),
}

/// Executes the application operations exposed as MCP tools.
pub trait ToolBackend {
    /// Returns the complete deterministic MCP tool registry.
    fn tools(&self) -> Vec<Value>;

    /// Invokes a known tool and returns structured content or a domain Problem.
    ///
    /// # Errors
    ///
    /// Returns the complete structured domain Problem when the application
    /// operation rejects or cannot complete the request.
    fn call(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
        authentication: AuthenticationMetadata<'_>,
    ) -> Result<Value, Value>;
}

/// Runs one newline-delimited JSON-RPC session.
///
/// # Errors
///
/// Returns an I/O error if stdin cannot be read or stdout cannot be written.
pub fn serve(
    mut reader: impl BufRead,
    mut writer: impl Write,
    backend: &impl ToolBackend,
) -> io::Result<()> {
    let mut session = Session::default();
    let mut message = Vec::new();
    while let Some(read) = read_message(&mut reader, &mut message)? {
        let response = match read {
            MessageRead::Complete if message.is_empty() => Some(error_response(
                Value::Null,
                -32_600,
                "Invalid Request",
                None,
            )),
            MessageRead::Complete => match serde_json::from_slice::<Value>(&message) {
                Ok(request) => session.handle(&request, backend),
                Err(_) => Some(error_response(Value::Null, -32_700, "Parse error", None)),
            },
            MessageRead::Oversized => Some(error_response(
                Value::Null,
                -32_600,
                "Request exceeds the 1048576-byte limit",
                None,
            )),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut writer, &response)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
    }
    Ok(())
}

enum MessageRead {
    Complete,
    Oversized,
}

fn read_message(
    reader: &mut impl BufRead,
    message: &mut Vec<u8>,
) -> io::Result<Option<MessageRead>> {
    message.clear();
    let mut saw_bytes = false;
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if saw_bytes {
                Ok(Some(if oversized {
                    MessageRead::Oversized
                } else {
                    MessageRead::Complete
                }))
            } else {
                Ok(None)
            };
        }
        saw_bytes = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |position| position + 1);
        let payload = newline.map_or(available, |position| &available[..position]);
        if !oversized {
            if message.len().saturating_add(payload.len()) > MAX_MESSAGE_BYTES {
                oversized = true;
                message.clear();
            } else {
                message.extend_from_slice(payload);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(if oversized {
                MessageRead::Oversized
            } else {
                MessageRead::Complete
            }));
        }
    }
}

#[derive(Default)]
struct Session {
    initialize_completed: bool,
    initialized: bool,
}

impl Session {
    fn handle(&mut self, request: &Value, backend: &impl ToolBackend) -> Option<Value> {
        let Some(object) = request.as_object() else {
            return Some(error_response(
                Value::Null,
                -32_600,
                "Invalid Request",
                None,
            ));
        };
        let id = object.get("id").cloned();
        let is_notification = id.is_none();
        if id
            .as_ref()
            .is_some_and(|id| !id.is_string() && !id.is_number())
        {
            return Some(error_response(
                Value::Null,
                -32_600,
                "Request id must be a string or number",
                None,
            ));
        }
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return (!is_notification).then(|| {
                error_response(id.unwrap_or(Value::Null), -32_600, "Invalid Request", None)
            });
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return (!is_notification).then(|| {
                error_response(id.unwrap_or(Value::Null), -32_600, "Invalid Request", None)
            });
        };

        if is_notification {
            if method == "notifications/initialized" && self.initialize_completed {
                self.initialized = true;
            }
            return None;
        }

        let id = id.unwrap_or(Value::Null);
        if method == "initialize" {
            return Some(self.initialize(id, object.get("params")));
        }

        let params = object.get("params");
        let declares_modern_protocol = params
            .and_then(Value::as_object)
            .and_then(|params| params.get("_meta"))
            .and_then(Value::as_object)
            .is_some_and(|meta| meta.contains_key("io.modelcontextprotocol/protocolVersion"));
        if method == "server/discover"
            || declares_modern_protocol
            || ((!self.initialize_completed) && matches!(method, "tools/list" | "tools/call"))
        {
            return Some(Self::handle_modern(id, method, params, backend));
        }

        Some(self.handle_legacy(id, method, params, backend))
    }

    fn initialize(&mut self, id: Value, params: Option<&Value>) -> Value {
        if self.initialize_completed {
            return error_response(id, -32_600, "Initialize may only be requested once", None);
        }
        let Some(params) = params.and_then(Value::as_object) else {
            return error_response(id, -32_602, "Invalid initialize parameters", None);
        };
        if params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .is_none()
            || !params.get("capabilities").is_some_and(Value::is_object)
            || !params.get("clientInfo").is_some_and(Value::is_object)
        {
            return error_response(id, -32_602, "Invalid initialize parameters", None);
        }
        self.initialize_completed = true;
        success_response(
            id,
            json!({
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "proof-mcp",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Authenticated authority MCP adapter for Proof"
                },
                "instructions": "Authority-bearing tools require a fresh exact DSSE presentation in params._meta[\"dev.proof/authentication\"]. Principal and Delegation fields are mismatch guards and selectors, never authority."
            }),
        )
    }

    fn handle_legacy(
        &self,
        id: Value,
        method: &str,
        params: Option<&Value>,
        backend: &impl ToolBackend,
    ) -> Value {
        match method {
            "ping" => success_response(id, json!({})),
            "tools/list" if self.initialized => {
                success_response(id, json!({ "tools": backend.tools() }))
            }
            "tools/call" if self.initialized => Self::call_tool(id, params, backend, false),
            "tools/list" | "tools/call" => {
                error_response(id, -32_002, "Server is not initialized", None)
            }
            _ => error_response(id, -32_601, "Method not found", None),
        }
    }

    fn handle_modern(
        id: Value,
        method: &str,
        params: Option<&Value>,
        backend: &impl ToolBackend,
    ) -> Value {
        if let Err(error) = validate_modern_request_meta(id.clone(), params) {
            return error;
        }

        match method {
            "server/discover" => success_response(
                id,
                modern_result(json!({
                    "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                    "capabilities": { "tools": {} },
                    "instructions": "Authority-bearing tools require a fresh exact DSSE presentation in params._meta[\"dev.proof/authentication\"]. Principal and Delegation fields are mismatch guards and selectors, never authority.",
                    "ttlMs": REGISTRY_TTL_MS,
                    "cacheScope": "public"
                })),
            ),
            "tools/list" => {
                if params
                    .and_then(Value::as_object)
                    .and_then(|params| params.get("cursor"))
                    .is_some_and(|cursor| !cursor.is_string())
                {
                    return error_response(id, -32_602, "Tool list cursor must be a string", None);
                }
                success_response(
                    id,
                    modern_result(json!({
                        "tools": backend.tools(),
                        "ttlMs": REGISTRY_TTL_MS,
                        "cacheScope": "public"
                    })),
                )
            }
            "tools/call" => Self::call_tool(id, params, backend, true),
            _ => error_response(id, -32_601, "Method not found", None),
        }
    }

    fn call_tool(
        id: Value,
        params: Option<&Value>,
        backend: &impl ToolBackend,
        modern: bool,
    ) -> Value {
        let Some(params) = params.and_then(Value::as_object) else {
            return error_response(id, -32_602, "Invalid tools/call parameters", None);
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return error_response(id, -32_602, "Invalid tools/call parameters", None);
        };
        let empty = Map::new();
        let Some(arguments) = params
            .get("arguments")
            .map_or(Some(&empty), Value::as_object)
        else {
            return error_response(id, -32_602, "Tool arguments must be an object", None);
        };
        if !backend
            .tools()
            .iter()
            .any(|tool| tool.get("name").and_then(Value::as_str) == Some(name))
        {
            return error_response(id, -32_602, &format!("Unknown tool: {name}"), None);
        }
        let authentication = params
            .get("_meta")
            .and_then(Value::as_object)
            .and_then(|meta| meta.get("dev.proof/authentication"))
            .map_or(AuthenticationMetadata::Missing, |value| {
                value.as_str().map_or(
                    AuthenticationMetadata::InvalidType,
                    AuthenticationMetadata::Envelope,
                )
            });
        let mut result = match backend.call(name, arguments, authentication) {
            Ok(value) => tool_result(value, false),
            Err(problem) => tool_result(problem, true),
        };
        if modern {
            result = modern_result(result);
        }
        success_response(id, result)
    }
}

fn validate_modern_request_meta(id: Value, params: Option<&Value>) -> Result<(), Value> {
    let Some(params) = params.and_then(Value::as_object) else {
        return Err(error_response(
            id,
            -32_602,
            "Modern requests require object parameters with _meta",
            None,
        ));
    };
    let Some(meta) = params.get("_meta").and_then(Value::as_object) else {
        return Err(error_response(
            id,
            -32_602,
            "Modern requests require object _meta",
            None,
        ));
    };
    let Some(requested) = meta
        .get("io.modelcontextprotocol/protocolVersion")
        .and_then(Value::as_str)
    else {
        return Err(error_response(
            id,
            -32_602,
            "Modern requests require io.modelcontextprotocol/protocolVersion",
            None,
        ));
    };
    if requested != MODERN_PROTOCOL_VERSION {
        return Err(error_response(
            id,
            -32_022,
            "Unsupported protocol version",
            Some(json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": requested
            })),
        ));
    }
    if !meta
        .get("io.modelcontextprotocol/clientCapabilities")
        .is_some_and(Value::is_object)
    {
        return Err(error_response(
            id,
            -32_602,
            "Modern requests require io.modelcontextprotocol/clientCapabilities",
            None,
        ));
    }
    if meta
        .get("io.modelcontextprotocol/clientInfo")
        .is_some_and(|client_info| !client_info.is_object())
    {
        return Err(error_response(
            id,
            -32_602,
            "io.modelcontextprotocol/clientInfo must be an object",
            None,
        ));
    }
    Ok(())
}

fn modern_result(mut result: Value) -> Value {
    if let Some(result) = result.as_object_mut() {
        result.insert(
            "resultType".to_owned(),
            Value::String("complete".to_owned()),
        );
        result.insert(
            "_meta".to_owned(),
            json!({
                "io.modelcontextprotocol/serverInfo": {
                    "name": "proof-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        );
    }
    result
}

fn tool_result(structured: Value, is_error: bool) -> Value {
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".to_owned());
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    });
    // Advertised output schemas describe successful application data. Domain
    // Problems remain machine-readable JSON TextContent without claiming to
    // satisfy those success schemas.
    if !is_error {
        result["structuredContent"] = structured;
    }
    result
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "response construction takes ownership of one-shot JSON-RPC values"
)]
fn success_response(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "response construction takes ownership of the one-shot JSON-RPC identifier"
)]
fn error_response(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticationMetadata, LEGACY_PROTOCOL_VERSION, MAX_MESSAGE_BYTES,
        MODERN_PROTOCOL_VERSION, REGISTRY_TTL_MS, SUPPORTED_PROTOCOL_VERSIONS, ToolBackend, serve,
    };
    use serde_json::{Map, Value, json};
    use std::io::Cursor;

    struct StubBackend;

    impl ToolBackend for StubBackend {
        fn tools(&self) -> Vec<Value> {
            vec![json!({
                "name": "proof.capabilities.list",
                "description": "List capabilities",
                "inputSchema": { "type": "object", "additionalProperties": false }
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

    struct AuthenticationEchoBackend;

    impl ToolBackend for AuthenticationEchoBackend {
        fn tools(&self) -> Vec<Value> {
            vec![json!({
                "name": "proof.workspace.status",
                "description": "Authenticated status",
                "inputSchema": { "type": "object", "additionalProperties": false }
            })]
        }

        fn call(
            &self,
            name: &str,
            _arguments: &Map<String, Value>,
            authentication: AuthenticationMetadata<'_>,
        ) -> Result<Value, Value> {
            assert_eq!(name, "proof.workspace.status");
            match authentication {
                AuthenticationMetadata::Envelope(envelope) => {
                    Ok(json!({ "authentication": envelope }))
                }
                AuthenticationMetadata::Missing => Err(json!({
                    "code": "proof.auth.malformed",
                    "detail": "authentication metadata is required"
                })),
                AuthenticationMetadata::InvalidType => Err(json!({
                    "code": "proof.auth.malformed",
                    "detail": "authentication metadata must be a string"
                })),
            }
        }
    }

    #[test]
    fn initialize_negotiates_the_legacy_revision() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n".to_owned();
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(
            response["result"]["protocolVersion"],
            LEGACY_PROTOCOL_VERSION
        );
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
    }

    #[test]
    fn tools_require_initialized_notification_and_return_structured_content() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"test\",\"version\":\"1\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"proof.capabilities.list\",\"arguments\":{}}}\n"
        );
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let lines = responses.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2, "notifications must not receive responses");
        let response: Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(response["result"]["isError"], false);
        assert_eq!(
            response["result"]["structuredContent"]["capabilities"],
            json!([])
        );
        assert!(response["result"].get("resultType").is_none());
    }

    #[test]
    fn modern_discovery_is_stateless_and_self_describing() {
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":\"discover\",\"method\":\"server/discover\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"{MODERN_PROTOCOL_VERSION}\",\"io.modelcontextprotocol/clientCapabilities\":{{}}}}}}}}\n"
        );
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();

        assert_eq!(response["result"]["resultType"], "complete");
        assert_eq!(
            response["result"]["supportedVersions"],
            json!(SUPPORTED_PROTOCOL_VERSIONS)
        );
        assert_eq!(response["result"]["capabilities"], json!({ "tools": {} }));
        assert_eq!(response["result"]["ttlMs"], REGISTRY_TTL_MS);
        assert_eq!(response["result"]["cacheScope"], "public");
        assert_eq!(
            response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "proof-mcp"
        );
    }

    #[test]
    fn modern_calls_do_not_depend_on_prior_messages() {
        let request = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"{MODERN_PROTOCOL_VERSION}\",\"io.modelcontextprotocol/clientCapabilities\":{{}}}},\"name\":\"proof.capabilities.list\",\"arguments\":{{}}}}}}\n"
        );
        let input = format!("{request}{request}");
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let lines = responses.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        for line in lines {
            let response: Value = serde_json::from_str(line).unwrap();
            assert_eq!(response["result"]["resultType"], "complete");
            assert_eq!(response["result"]["isError"], false);
        }
    }

    #[test]
    fn modern_and_legacy_calls_preserve_the_exact_authentication_string() {
        let authentication =
            r#"{"payload":"YWJj","payloadType":"application/example+json","signatures": []}"#;
        let legacy_messages = [
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
                    "arguments": {}
                }
            }),
        ];
        let modern_message = json!({
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
                "arguments": {}
            }
        });
        let mut input = legacy_messages
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        input.push('\n');
        input.push_str(&modern_message.to_string());
        input.push('\n');

        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &AuthenticationEchoBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let responses = responses
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 3);
        assert_eq!(
            responses[1]["result"]["structuredContent"]["authentication"],
            authentication
        );
        assert!(responses[1]["result"].get("resultType").is_none());
        assert_eq!(
            responses[2]["result"]["structuredContent"]["authentication"],
            authentication
        );
        assert_eq!(responses[2]["result"]["resultType"], "complete");
    }

    #[test]
    fn modern_authenticated_tools_reject_missing_and_non_string_metadata() {
        let requests = [Value::Null, json!({ "payload": "not-a-string" })]
            .into_iter()
            .enumerate()
            .map(|(index, authentication)| {
                let mut meta = json!({
                    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientCapabilities": {}
                });
                if !authentication.is_null() {
                    meta["dev.proof/authentication"] = authentication;
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {
                        "_meta": meta,
                        "name": "proof.workspace.status",
                        "arguments": {}
                    }
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let mut output = Vec::new();
        serve(
            Cursor::new(requests),
            &mut output,
            &AuthenticationEchoBackend,
        )
        .unwrap();

        for line in String::from_utf8(output).unwrap().lines() {
            let response: Value = serde_json::from_str(line).unwrap();
            assert_eq!(response["result"]["isError"], true);
            let problem: Value =
                serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(problem["code"], "proof.auth.malformed");
        }
    }

    #[test]
    fn legacy_authenticated_tools_reject_missing_and_non_string_metadata() {
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
                "id": "missing",
                "method": "tools/call",
                "params": { "name": "proof.workspace.status", "arguments": {} }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "invalid",
                "method": "tools/call",
                "params": {
                    "_meta": { "dev.proof/authentication": {} },
                    "name": "proof.workspace.status",
                    "arguments": {}
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
        serve(Cursor::new(input), &mut output, &AuthenticationEchoBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let responses = responses
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(responses.len(), 3);
        for response in &responses[1..] {
            assert_eq!(response["result"]["isError"], true);
            assert!(response["result"].get("resultType").is_none());
            let problem: Value =
                serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                    .unwrap();
            assert_eq!(problem["code"], "proof.auth.malformed");
        }
    }

    #[test]
    fn modern_requests_require_metadata_and_report_unsupported_versions() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2099-01-01\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n"
        );
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let lines = responses.lines().collect::<Vec<_>>();
        let missing: Value = serde_json::from_str(lines[0]).unwrap();
        let unsupported: Value = serde_json::from_str(lines[1]).unwrap();

        assert_eq!(missing["error"]["code"], -32_602);
        assert_eq!(unsupported["error"]["code"], -32_022);
        assert_eq!(unsupported["error"]["data"]["requested"], "2099-01-01");
        assert_eq!(
            unsupported["error"]["data"]["supported"],
            json!(SUPPORTED_PROTOCOL_VERSIONS)
        );
    }

    #[test]
    fn malformed_and_oversized_messages_return_bounded_protocol_errors() {
        let mut oversized = vec![b' '; MAX_MESSAGE_BYTES + 1];
        oversized.push(b'\n');
        let mut input = b"not-json\n".to_vec();
        input.extend(oversized);
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
        let responses = String::from_utf8(output).unwrap();
        let lines = responses.lines().collect::<Vec<_>>();

        assert_eq!(lines.len(), 2);
        let malformed: Value = serde_json::from_str(lines[0]).unwrap();
        let oversized: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(malformed["error"]["code"], -32_700);
        assert_eq!(oversized["error"]["code"], -32_600);
    }

    #[test]
    fn notifications_never_write_a_json_rpc_response() {
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"unknown\"}\n"
        );
        let mut output = Vec::new();
        serve(Cursor::new(input), &mut output, &StubBackend).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn request_ids_are_limited_to_strings_and_numbers() {
        for invalid_id in [json!(true), json!([]), json!({}), Value::Null] {
            let request = json!({
                "jsonrpc": "2.0",
                "id": invalid_id,
                "method": "ping"
            });
            let mut input = serde_json::to_vec(&request).unwrap();
            input.push(b'\n');
            let mut output = Vec::new();
            serve(Cursor::new(input), &mut output, &StubBackend).unwrap();
            let response: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(response["error"]["code"], -32_600);
            assert_eq!(response["id"], Value::Null);
        }

        let mut output = Vec::new();
        serve(
            Cursor::new("{\"jsonrpc\":\"2.0\",\"id\":1.5,\"method\":\"ping\"}\n"),
            &mut output,
            &StubBackend,
        )
        .unwrap();
        let response: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(response["id"], json!(1.5));
        assert!(response.get("result").is_some());
    }
}
