mod support;

use std::process::{Command, Output};

use serde_json::Value;

use support::{OpeningMode, SignatureMode, canonical, generate};

fn run(fixture: &support::GeneratedFixture, trust: &[u8], checkpoint: &[u8]) -> Output {
    let trust_path = fixture.write_input("trust.json", trust);
    let checkpoint_path = fixture.write_input("checkpoint.json", checkpoint);
    Command::new(env!("CARGO_BIN_EXE_proof-verifier"))
        .args([
            "verify",
            "--bundle",
            fixture.root().to_str().unwrap(),
            "--trust",
            trust_path.to_str().unwrap(),
            "--checkpoint",
            checkpoint_path.to_str().unwrap(),
        ])
        .output()
        .unwrap()
}

fn assert_semantic_result(output: &Output, exit: i32, report: &[u8]) {
    assert_eq!(output.status.code(), Some(exit));
    assert_eq!(output.stdout, report);
    assert!(output.stderr.is_empty());
}

#[test]
fn public_cli_freezes_complete_incomplete_and_invalid_results() {
    let complete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let output = run(&complete, &complete.trust_json, &complete.checkpoint_json);
    assert_semantic_result(
        &output,
        0,
        include_bytes!("../../../conformance/v1/portable-proof/report.complete.json"),
    );

    let incomplete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut required_trust: Value = serde_json::from_slice(&incomplete.trust_json).unwrap();
    required_trust["disclosure"]["requesting_subject_opening"] =
        Value::String("required".to_owned());
    let output = run(
        &incomplete,
        &canonical(&required_trust),
        &incomplete.checkpoint_json,
    );
    assert_semantic_result(
        &output,
        20,
        include_bytes!("../../../conformance/v1/portable-proof/report.incomplete.json"),
    );

    let invalid = generate(
        OpeningMode::Withhold,
        SignatureMode::CorruptAuthorityDecision,
    );
    let output = run(&invalid, &invalid.trust_json, &invalid.checkpoint_json);
    assert_semantic_result(
        &output,
        21,
        include_bytes!("../../../conformance/v1/portable-proof/report.invalid.json"),
    );
}

#[test]
fn public_cli_freezes_usage_and_input_failures() {
    let usage = Command::new(env!("CARGO_BIN_EXE_proof-verifier"))
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(64));
    assert!(usage.stdout.is_empty());
    assert_eq!(usage.stderr, b"proof-verifier: proof.verify.usage\n");

    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let missing = fixture.root().join("missing-trust.json");
    let input = Command::new(env!("CARGO_BIN_EXE_proof-verifier"))
        .args([
            "verify",
            "--bundle",
            fixture.root().to_str().unwrap(),
            "--trust",
            missing.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(input.status.code(), Some(64));
    assert!(input.stdout.is_empty());
    assert_eq!(input.stderr, b"proof-verifier: proof.verify.input\n");
}
