//! Retained artifact test for the deployable stack (work item P-0018).
//!
//! Boots the real `proof-server` binary against an isolated PostgreSQL schema,
//! proves liveness through capabilities, proves the unauthenticated session
//! boundary fails closed with a stable Problem body, then seeds one
//! `preview.release/v1` outbox row and runs the real `proof-worker` binary to
//! prove it drains.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proof_pg::outbox::{OutboxEnqueueV1, enqueue};
use proof_domain::{ContentDigest, Timestamp, WorkspaceId};
use proof_pg::wiring::PgRuntime;
use uuid::Uuid;

const WORKSPACE: &str = "019c0000-0000-7000-8000-000000000010";

fn dsn() -> String {
    std::env::var(proof_pg::DSN_ENV).unwrap_or_else(|_| proof_pg::DEFAULT_DSN.to_owned())
}

fn now_timestamp() -> Timestamp {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    Timestamp::from_unix_timestamp_nanos(i128::try_from(nanos).expect("nanos fit in i128"))
        .expect("timestamp is representable")
}

/// Locates a sibling workspace binary next to this test binary.
fn workspace_bin(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_proof-server"));
    assert!(path.pop(), "binary parent directory");
    path.push(name);
    assert!(
        path.is_file(),
        "expected the {name} binary at {}; run `cargo build --workspace --bins`",
        path.display()
    );
    path
}

/// A DSN pinned to one isolated schema via the connection `options` parameter.
fn schema_scoped_dsn(base_dsn: &str, schema: &str) -> String {
    let separator = if base_dsn.contains('?') { '&' } else { '?' };
    format!("{base_dsn}{separator}options=-c%20search_path%3D{schema}")
}

struct Stack {
    schema: String,
    cleanup_runtime: PgRuntime,
    child: Option<std::process::Child>,
    base_url: String,
    scoped_dsn: String,
    preview_root: PathBuf,
}

impl Drop for Stack {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = self
            .cleanup_runtime
            .client_mut()
            .batch_execute(&format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE", self.schema));
        let _ = std::fs::remove_dir_all(&self.preview_root);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn deployed_stack_serves_and_the_worker_drains() {
    let schema = format!("p0018_artifact_{}", Uuid::now_v7().simple());
    let preview_root =
        std::env::temp_dir().join(format!("proof-artifact-preview-{}", Uuid::now_v7().simple()));
    let _ = std::fs::remove_dir_all(&preview_root);
    std::fs::create_dir_all(&preview_root).expect("create preview root");

    let workspace_id: WorkspaceId = WORKSPACE.parse().expect("valid Workspace UUIDv7");
    let mut cleanup_runtime = PgRuntime::connect(proof_pg::PgConfig::new(
        dsn(),
        workspace_id,
        Duration::from_secs(30),
    ))
    .expect("connect to PostgreSQL; run scripts/dev-pg.sh");
    cleanup_runtime
        .client_mut()
        .batch_execute(&format!(
            "CREATE SCHEMA \"{schema}\"; SET search_path TO \"{schema}\""
        ))
        .expect("create isolated schema");

    let scoped_dsn = schema_scoped_dsn(&dsn(), &schema);

    // Boot the real server binary; it applies the full migration ledger itself.
    let mut envs = HashMap::new();
    envs.insert("PROOF_LISTEN_ADDR".to_owned(), "127.0.0.1:0".to_owned());
    envs.insert("PROOF_PG_DSN".to_owned(), scoped_dsn.clone());
    envs.insert(
        "PROOF_WORKSPACE_ID".to_owned(),
        WORKSPACE.to_owned(),
    );
    envs.insert(
        "PROOF_SESSION_SECRET".to_owned(),
        format!("{:02x}", 0x5a_u8).repeat(32),
    );
    let mut child = Command::new(workspace_bin("proof-server"))
        .env_clear()
        .envs(envs)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn the proof-server binary");

    let mut stdout = std::io::BufReader::new(
        child
            .stdout
            .take()
            .expect("the server pipes its listening line"),
    );
    let mut listening_line = String::new();
    std::io::BufRead::read_line(&mut stdout, &mut listening_line)
        .expect("read the listening line");
    let bound_addr = listening_line
        .trim()
        .strip_prefix("proof-server listening on ")
        .unwrap_or_else(|| panic!("unexpected first output line: {listening_line}"))
        .to_owned();
    let base_url = format!("http://{bound_addr}");

    // Liveness: public capabilities discovery answers on the deployed router.
    let response = http_get(&format!("{base_url}/api/v1/capabilities"));
    assert_eq!(response.status, 200, "capabilities must answer 200");
    assert_eq!(
        response.body["api_version"],
        "proof.dev/capabilities-discover-result/v1"
    );
    assert_eq!(response.body["route_count"], 9);

    // Session boundary: without a session cookie the read fails closed with
    // the stable Problem body.
    let response = http_get(&format!("{base_url}/api/v1/session"));
    assert_eq!(response.status, 401);
    assert_eq!(response.body["code"], "proof.auth.denied");
    assert_eq!(response.body["retryable"], false);
    assert!(
        response.body["instance"]
            .as_str()
            .is_some_and(|value| value.starts_with("urn:proof:operation:")),
        "Problem bodies carry the operation instance URN"
    );

    // Delivery drain: enqueue one preview.release/v1 event, run the real
    // worker binary once over the same isolated schema, and require the row
    // to reach a terminal delivered state.
    let effect_digest = ContentDigest::blake3([0xab_u8; 32]);
    let event = OutboxEnqueueV1 {
        event_id: Uuid::now_v7().to_string(),
        workspace_id,
        workspace_transaction_sequence: 1,
        ordinal: 1,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: format!("release/{WORKSPACE}"),
        stream_sequence: 1,
        effect_digest,
        payload_digest: Some(ContentDigest::blake3([0x33_u8; 32])),
        artifact_reference: None,
        destination_configuration_version: 1,
        destination_configuration_digest: ContentDigest::blake3([0x44_u8; 32]),
        correlation_id: None,
        causation_id: None,
        committed_creation_time: now_timestamp(),
    };
    let delivery_id = Uuid::now_v7().to_string();
    let mut transaction = cleanup_runtime
        .client_mut()
        .transaction()
        .expect("begin enqueue transaction");
    enqueue(&mut transaction, &event).expect("enqueue outbox event");
    let params: &[&(dyn postgres::types::ToSql + Sync)] =
        &[&event.event_id, &delivery_id];
    transaction
        .execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             ) VALUES ($1, $2, 1, 'pending', NULL, 0, NULL, NULL, NULL,
                       clock_timestamp(), clock_timestamp())",
            params,
        )
        .expect("preallocate delivery state");
    transaction.commit().expect("commit enqueue");

    let worker_envs = HashMap::from([
        ("PROOF_PG_DSN".to_owned(), scoped_dsn.clone()),
        ("PROOF_WORKSPACE_ID".to_owned(), WORKSPACE.to_owned()),
        (
            "PROOF_PREVIEW_ROOT".to_owned(),
            preview_root.to_string_lossy().to_string(),
        ),
    ]);
    let worker_output: Output = Command::new(workspace_bin("proof-worker"))
        .env_clear()
        .envs(worker_envs)
        .output()
        .expect("run the proof-worker binary");
    assert!(
        worker_output.status.success(),
        "the worker must succeed: {}",
        String::from_utf8_lossy(&worker_output.stderr)
    );

    let drained: i64 = cleanup_runtime
        .client_mut()
        .query_one(
            "SELECT COUNT(*) FROM delivery_state WHERE status = 'delivered'",
            &[],
        )
        .expect("query delivery state")
        .get(0);
    assert_eq!(drained, 1, "the seeded outbox row must be delivered");

    drop(Stack {
        schema,
        cleanup_runtime,
        child: Some(child),
        base_url,
        scoped_dsn,
        preview_root,
    });
}

struct HttpResponse {
    status: u16,
    body: serde_json::Value,
}

fn http_get(url: &str) -> HttpResponse {
    let output = Command::new("curl")
        .args(["-sS", "-o", "-", "-w", "\n%{http_code}", url])
        .output()
        .expect("curl must exist for the retained artifact probe");
    let text = String::from_utf8_lossy(&output.stdout);
    let (body, code) = text
        .rsplit_once('\n')
        .expect("curl appends the status code");
    HttpResponse {
        status: code.trim().parse::<u16>().expect("HTTP status code"),
        body: serde_json::from_str(body).expect("JSON body"),
    }
}
