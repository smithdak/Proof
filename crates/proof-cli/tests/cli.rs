use std::process::Command;

const CORRELATION_ID: &str = "019c0000-0000-7000-8000-000000000002";

#[test]
fn status_emits_the_stable_json_envelope() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args([
            "--output",
            "json",
            "--correlation-id",
            CORRELATION_ID,
            "status",
        ])
        .output()
        .expect("proof executable should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["api_version"], "proof.dev/result/v1");
    assert_eq!(value["operation"], "status");
    assert_eq!(value["correlation_id"], CORRELATION_ID);
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["implementation_stage"], "foundation");
    assert_eq!(value["data"]["workspace_selected"], false);
}

#[test]
fn invalid_correlation_id_is_a_structured_input_problem() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .args([
            "--output",
            "json",
            "--correlation-id",
            "not-a-uuid",
            "status",
        ])
        .output()
        .expect("proof executable should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    let value: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["code"], "proof.input.schema_mismatch");
    assert_eq!(value["operation"], "status");
    assert_eq!(value["retryable"], false);
}

#[test]
fn status_human_output_is_a_projection_of_status_data() {
    let output = Command::new(env!("CARGO_BIN_EXE_proof"))
        .arg("status")
        .output()
        .expect("proof executable should run");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Proof 0.1.0"));
    assert!(stdout.contains("implementation: foundation"));
    assert!(stdout.contains("workspace selected: false"));
}
