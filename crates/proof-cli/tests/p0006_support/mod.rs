use std::{
    io::{Cursor, Write as _},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use proof_application::authority::{AuthenticatedInvocationV1, CommandInputV1};
use proof_canonical::{canonicalize, parse_strict};
use proof_mcp::{LEGACY_PROTOCOL_VERSION, LocalBackend, MODERN_PROTOCOL_VERSION, serve};
use serde_json::{Value, json};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerOutcome {
    Success(Value),
    Problem(Value),
}

pub fn execute_cli_broker(root: &Path, invocation: &AuthenticatedInvocationV1) -> BrokerOutcome {
    let frame = canonical_frame(invocation);
    let mut child = Command::new(env!("CARGO_BIN_EXE_proof"))
        .current_dir(root)
        .args(["--output", "json", "auth", "execute", "--invocation", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(frame.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    if output.status.success() {
        BrokerOutcome::Success(value["data"].clone())
    } else {
        BrokerOutcome::Problem(value)
    }
}

pub fn execute_modern_mcp_broker(
    root: &Path,
    invocation: &AuthenticatedInvocationV1,
) -> BrokerOutcome {
    let request = modern_request(invocation, "p0006-modern");
    let responses = serve_mcp(root, &[request]);
    assert_eq!(responses.len(), 1);
    mcp_outcome(&responses[0])
}

pub fn execute_legacy_mcp_broker(
    root: &Path,
    invocation: &AuthenticatedInvocationV1,
) -> BrokerOutcome {
    let requests = legacy_requests(invocation, "p0006-legacy");
    let responses = serve_mcp(root, &requests);
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    mcp_outcome(&responses[1])
}

#[allow(
    dead_code,
    reason = "the shared P-0006 helper is exercised by the separate containment target"
)]
pub fn execute_modern_mcp_process(
    root: &Path,
    invocation: &AuthenticatedInvocationV1,
) -> BrokerOutcome {
    let responses = serve_mcp_process(root, &[modern_request(invocation, "p0006-modern-process")]);
    assert_eq!(responses.len(), 1);
    mcp_outcome(&responses[0])
}

#[allow(
    dead_code,
    reason = "the shared P-0006 helper is exercised by the separate containment target"
)]
pub fn execute_legacy_mcp_process(
    root: &Path,
    invocation: &AuthenticatedInvocationV1,
) -> BrokerOutcome {
    let responses = serve_mcp_process(root, &legacy_requests(invocation, "p0006-legacy-process"));
    assert_eq!(responses.len(), 2);
    assert_eq!(
        responses[0]["result"]["protocolVersion"],
        LEGACY_PROTOCOL_VERSION
    );
    mcp_outcome(&responses[1])
}

fn modern_request(invocation: &AuthenticatedInvocationV1, id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
                "dev.proof/authentication": invocation.authentication.as_str(),
            },
            "name": tool_name(invocation),
            "arguments": tool_arguments(invocation),
        },
    })
}

fn legacy_requests(invocation: &AuthenticatedInvocationV1, id: &str) -> [Value; 3] {
    [
        json!({
            "jsonrpc": "2.0",
            "id": format!("{id}-initialize"),
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "p0006-containment", "version": "1" },
            },
        }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({
            "jsonrpc": "2.0",
                "id": id,
            "method": "tools/call",
            "params": {
                "_meta": { "dev.proof/authentication": invocation.authentication.as_str() },
                "name": tool_name(invocation),
                "arguments": tool_arguments(invocation),
            },
        }),
    ]
}

pub fn canonical_frame(invocation: &AuthenticatedInvocationV1) -> String {
    canonicalize(&serde_json::to_value(invocation).unwrap())
        .unwrap()
        .as_str()
        .to_owned()
}

fn tool_name(invocation: &AuthenticatedInvocationV1) -> String {
    proof_application::capabilities()
        .iter()
        .find(|descriptor| {
            descriptor.authority_operation() == Some(invocation.command_input.operation)
        })
        .unwrap_or_else(|| {
            panic!(
                "missing capability for {:?}",
                invocation.command_input.operation
            )
        })
        .mcp_tool_name()
}

fn tool_arguments(invocation: &AuthenticatedInvocationV1) -> Value {
    let mut arguments = invocation.command_input.normalized_input.clone();
    arguments.insert(
        "operating_principal_id".to_owned(),
        Value::String(invocation.command_input.operating_principal_id.to_string()),
    );
    arguments.insert(
        "delegation_id".to_owned(),
        Value::String(invocation.command_input.delegation_id.to_string()),
    );
    Value::Object(arguments)
}

fn serve_mcp(root: &Path, requests: &[Value]) -> Vec<Value> {
    let input = request_frames(requests);
    let backend = LocalBackend::new(root).unwrap();
    let mut output = Vec::new();
    serve(Cursor::new(input.as_bytes()), &mut output, &backend).unwrap();
    String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[allow(
    dead_code,
    reason = "the shared P-0006 helper is exercised by the separate containment target"
)]
fn serve_mcp_process(root: &Path, requests: &[Value]) -> Vec<Value> {
    let input = request_frames(requests);
    let binary = mcp_binary();
    assert!(binary.is_file(), "build proof-mcp first");
    let mut child = Command::new(binary)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn request_frames(requests: &[Value]) -> String {
    requests
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

#[allow(
    dead_code,
    reason = "the shared P-0006 helper is exercised by the separate containment target"
)]
fn mcp_binary() -> PathBuf {
    let proof = PathBuf::from(env!("CARGO_BIN_EXE_proof"));
    proof
        .parent()
        .expect("proof binary has a parent")
        .join("proof-mcp")
}

fn mcp_outcome(response: &Value) -> BrokerOutcome {
    if response["result"]["isError"] == false {
        BrokerOutcome::Success(response["result"]["structuredContent"].clone())
    } else {
        BrokerOutcome::Problem(
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap(),
        )
    }
}

#[allow(dead_code)]
pub fn assert_contained_agent_signer_available() {
    let signer = agent_signer_binary();
    assert!(signer.is_file(), "build proof-agent-signer first");
    let output = Command::new("bwrap")
        .arg("--version")
        .output()
        .expect("P-0006 qualification requires bubblewrap");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("id").arg("-u").output().unwrap();
    assert!(output.status.success());
    assert_ne!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "65534",
        "the retained fixture must bootstrap under a different host UID"
    );
}

#[allow(dead_code)]
pub fn assert_contained_agent_signer_boundary(credentials: &Path) {
    let mut command = contained_agent_command(credentials);
    command.args([
        "/usr/bin/sh",
        "-ceu",
        concat!(
            "test \"$(id -u)\" = 65534; ",
            "test \"$(id -g)\" = 65534; ",
            "test \"$(stat -c %u /run/proof-agent/credentials)\" = 65534; ",
            "test \"$(stat -c %g /run/proof-agent/credentials)\" = 65534; ",
            "test \"$(stat -c %a /run/proof-agent/credentials)\" = 700; ",
            "test \"$(stat -c %u /run/proof-agent/credentials/agent-a.json)\" = 65534; ",
            "test \"$(stat -c %g /run/proof-agent/credentials/agent-a.json)\" = 65534; ",
            "test \"$(stat -c %a /run/proof-agent/credentials/agent-a.json)\" = 600; ",
            "test -r /run/proof-agent/credentials/agent-a.json; ",
            "test \"$(find /run/proof-agent/credentials -maxdepth 1 -type f | wc -l)\" = 1; ",
            "test ! -e /mnt/d/github/Proof; ",
            "test ! -e /workspace; ",
            "test ! -e /.proof; ",
            "! command -v proof; ",
            "test ! -e /run/proof-agent/credentials/workspace-authority-key.json; ",
            "test ! -e /run/proof-agent/credentials/release-signing-key.json"
        ),
    ]);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[allow(dead_code)]
pub fn execute_contained_agent_signer(
    credentials: &Path,
    command_input: &CommandInputV1,
) -> AuthenticatedInvocationV1 {
    let command_frame = canonicalize(&serde_json::to_value(command_input).unwrap()).unwrap();
    let mut command = contained_agent_command(credentials);
    command
        .args([
            "/proof-agent-signer",
            "--command",
            "-",
            "--credential",
            "agent-a",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(command_frame.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_ne!(output.stdout.last(), Some(&b'\n'));
    let value = parse_strict(&output.stdout).unwrap();
    let canonical = canonicalize(&value).unwrap();
    assert_eq!(canonical.as_bytes(), output.stdout);
    let invocation: AuthenticatedInvocationV1 = serde_json::from_value(value).unwrap();
    assert_eq!(&invocation.command_input, command_input);
    invocation
}

fn contained_agent_command(credentials: &Path) -> Command {
    let signer = agent_signer_binary();
    let mut command = Command::new("bwrap");
    command
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin",
            "--setenv",
            "HOME",
            "/nonexistent",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/run",
            "--dir",
            "/run/proof-agent",
            "--ro-bind",
        ])
        .arg(credentials)
        .arg("/run/proof-agent/credentials")
        .arg("--ro-bind")
        .arg(signer)
        .arg("/proof-agent-signer")
        .args(["--chdir", "/"]);
    command
}

fn agent_signer_binary() -> PathBuf {
    let proof = PathBuf::from(env!("CARGO_BIN_EXE_proof"));
    let name = if cfg!(windows) {
        "proof-agent-signer.exe"
    } else {
        "proof-agent-signer"
    };
    proof
        .parent()
        .expect("proof binary has a parent")
        .join(name)
}
