mod support;

use std::{fs, path::Path};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use proof_verifier::{
    VerificationRequest,
    model::{ArtifactRef, DimensionStatus, EvidenceRole, Outcome},
    verify_bundle_directory,
};
use serde_json::Value;

use support::{OpeningMode, SignatureMode, canonical, digest, generate};

fn verify(fixture: &support::GeneratedFixture) -> proof_verifier::model::Report {
    verify_bundle_directory(VerificationRequest {
        bundle_root: fixture.root(),
        trust_policy_json: &fixture.trust_json,
        checkpoint_json: Some(&fixture.checkpoint_json),
        external_roots: &[],
    })
}

fn finding_codes(report: &proof_verifier::model::Report) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

fn corrupt_first_signature(envelope: &mut Value) {
    let signature = envelope["signatures"][0]["sig"].as_str().unwrap();
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    envelope["signatures"][0]["sig"] = Value::String(format!("{replacement}{}", &signature[1..]));
}

fn readdress_included_artifact(
    fixture: &support::GeneratedFixture,
    bundle: &mut Value,
    role: EvidenceRole,
    old_reference: ArtifactRef,
    bytes: &[u8],
) -> ArtifactRef {
    let new_reference = ArtifactRef {
        artifact_kind: old_reference.artifact_kind,
        digest: digest(old_reference.artifact_kind, bytes),
    };
    let new_path = fixture.artifact_path(new_reference);
    fs::create_dir_all(new_path.parent().unwrap()).unwrap();
    fs::write(new_path, bytes).unwrap();
    fs::remove_file(fixture.artifact_path(old_reference)).unwrap();

    let old_digest = old_reference.digest.to_string();
    let descriptor = bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| {
            descriptor["role"] == role.wire_name() && descriptor["artifact"]["digest"] == old_digest
        })
        .unwrap();
    descriptor["artifact"] = serde_json::to_value(new_reference).unwrap();
    descriptor["availability"]["byte_length"] = Value::from(bytes.len() as u64);
    bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|descriptor| {
            (
                descriptor["role"].as_str().unwrap().to_owned(),
                descriptor["artifact"]["artifact_kind"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                descriptor["artifact"]["digest"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        });
    new_reference
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}

fn read_bundle_files(root: &Path) -> Vec<Vec<u8>> {
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                files.push(fs::read(entry.path()).unwrap());
            }
        }
    }
    files
}

#[test]
fn readdressed_corrupt_release_signature_reaches_release_verification() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = fixture.bundle_value();
    let old_reference: ArtifactRef =
        serde_json::from_value(bundle["entrypoints"]["target_release_proof_envelope"].clone())
            .unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(fixture.artifact_path(old_reference)).unwrap()).unwrap();
    corrupt_first_signature(&mut envelope);
    let bytes = canonical(&envelope);
    let new_reference = readdress_included_artifact(
        &fixture,
        &mut bundle,
        EvidenceRole::ReleaseProofEnvelope,
        old_reference,
        &bytes,
    );
    bundle["entrypoints"]["target_release_proof_envelope"] =
        serde_json::to_value(new_reference).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture);
    let codes = finding_codes(&report);
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        codes.contains(&"proof.verify.release.signature"),
        "{report:#?}"
    );
    assert!(!codes.contains(&"proof.verify.artifact.digest"));
    assert_eq!(report.dimensions["container"], DimensionStatus::Valid);
}

#[test]
fn readdressed_corrupt_command_signature_reaches_command_verification() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = fixture.bundle_value();
    let decision_index = bundle["authority_prefix"]
        .as_array()
        .unwrap()
        .iter()
        .position(|entry| !entry["decision_companion"].is_null())
        .unwrap();
    let old_reference: ArtifactRef = serde_json::from_value(
        bundle["authority_prefix"][decision_index]["decision_companion"]
            ["authenticated_command_envelope"]
            .clone(),
    )
    .unwrap();
    let mut envelope: Value =
        serde_json::from_slice(&fs::read(fixture.artifact_path(old_reference)).unwrap()).unwrap();
    corrupt_first_signature(&mut envelope);
    let bytes = canonical(&envelope);
    let new_reference = readdress_included_artifact(
        &fixture,
        &mut bundle,
        EvidenceRole::AuthenticatedCommandEnvelope,
        old_reference,
        &bytes,
    );
    bundle["authority_prefix"][decision_index]["decision_companion"]["authenticated_command_envelope"] =
        serde_json::to_value(new_reference).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture);
    let codes = finding_codes(&report);
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        codes.contains(&"proof.verify.command.signature"),
        "{report:#?}"
    );
    assert!(!codes.contains(&"proof.verify.artifact.digest"));
    assert_eq!(report.dimensions["container"], DimensionStatus::Valid);
}

#[test]
fn withheld_bundle_excludes_private_keys_credentials_uid_and_blind() {
    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let files = read_bundle_files(fixture.root());
    let mut forbidden = vec![
        b"uid:1000".to_vec(),
        fixture.subject_blind.as_bytes().to_vec(),
        b"-----BEGIN PRIVATE KEY-----".to_vec(),
        b"AKIA0123456789ABCDEF".to_vec(),
        b"ghp_0123456789abcdefghijklmnopqrstuvwxyzAB".to_vec(),
        b"sk-proj-proof-portable-evidence-canary".to_vec(),
        b"Bearer proof-portable-evidence-canary".to_vec(),
        b"\"private_key\"".to_vec(),
        b"\"private_key_seed\"".to_vec(),
        b"\"secret_key\"".to_vec(),
        b"\"access_token\"".to_vec(),
        b"\"refresh_token\"".to_vec(),
    ];
    for seed in [[0x11; 32], [0x22; 32], [0x33; 32]] {
        forbidden.push(seed.to_vec());
        forbidden.push(hex(&seed).into_bytes());
        forbidden.push(BASE64.encode(seed).into_bytes());
        forbidden.push(URL_SAFE_NO_PAD.encode(seed).into_bytes());
    }

    for needle in forbidden {
        assert!(
            files.iter().all(|bytes| !contains(bytes, &needle)),
            "portable bundle leaked forbidden material: {}",
            String::from_utf8_lossy(&needle)
        );
    }
}

#[cfg(unix)]
#[test]
fn included_artifact_symlink_substitution_fails_at_container_boundary() {
    use std::os::unix::fs::symlink;

    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let artifact_path = fixture.artifact_path(fixture.command_input);
    let substitute = fixture.write_input(
        "substituted-command.json",
        &fs::read(&artifact_path).unwrap(),
    );
    fs::remove_file(&artifact_path).unwrap();
    symlink(substitute, artifact_path).unwrap();

    let report = verify(&fixture);
    let codes = finding_codes(&report);
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert_eq!(report.dimensions["container"], DimensionStatus::Invalid);
    assert!(
        codes.contains(&"proof.verify.bundle.inventory"),
        "{report:#?}"
    );
}
