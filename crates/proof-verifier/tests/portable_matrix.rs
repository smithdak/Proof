mod support;

use std::{fs, path::Path};

use proof_verifier::{
    VerificationRequest, canonical_report,
    model::{ArtifactRef, Digest, DimensionStatus, HistoryScope, OpeningRequirement, Outcome},
    parse_checkpoint, parse_trust_policy, verify_bundle_directory,
};
use serde_json::Value;

use support::{OpeningMode, SignatureMode, canonical, digest, generate};

fn verify(
    fixture: &support::GeneratedFixture,
    checkpoint_json: Option<&[u8]>,
) -> proof_verifier::model::Report {
    verify_bundle_directory(VerificationRequest {
        bundle_root: fixture.root(),
        trust_policy_json: &fixture.trust_json,
        checkpoint_json,
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

fn all_files(root: &Path) -> Vec<Vec<u8>> {
    let mut pending = vec![root.to_owned()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
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
fn independently_generated_complete_include_and_withhold_are_equivalent() {
    let withheld = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let included = generate(OpeningMode::Include, SignatureMode::Valid);

    let withheld_report = verify(&withheld, Some(&withheld.checkpoint_json));
    let included_report = verify(&included, Some(&included.checkpoint_json));

    assert_eq!(
        withheld_report.outcome,
        Outcome::Complete,
        "{withheld_report:#?}"
    );
    assert_eq!(
        included_report.outcome,
        Outcome::Complete,
        "{included_report:#?}"
    );
    assert_eq!(withheld.subject_opening, included.subject_opening);
    assert_eq!(withheld_report.history_scope, HistoryScope::PinnedHead);
    assert_eq!(included_report.history_scope, HistoryScope::PinnedHead);
    assert_eq!(
        withheld_report.dimensions["subject_opening"],
        DimensionStatus::NotRequired
    );
    assert_eq!(
        included_report.dimensions["subject_opening"],
        DimensionStatus::Valid
    );
    assert!(withheld_report.findings.is_empty());
    assert!(included_report.findings.is_empty());
}

#[test]
fn required_withheld_opening_and_missing_checkpoint_are_incomplete() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = fixture.trust_value();
    trust["disclosure"]["requesting_subject_opening"] =
        serde_json::to_value(OpeningRequirement::Required).unwrap();
    fixture.replace_trust(&trust);

    let required_report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(
        required_report.outcome,
        Outcome::Incomplete,
        "{required_report:#?}"
    );
    assert_eq!(
        required_report.dimensions["evidence_completeness"],
        DimensionStatus::Incomplete
    );
    assert_eq!(
        required_report.dimensions["subject_opening"],
        DimensionStatus::Incomplete
    );
    assert!(finding_codes(&required_report).contains(&"proof.verify.external.missing"));
    assert!(finding_codes(&required_report).contains(&"proof.verify.subject.opening_required"));

    let checkpoint_report = verify(&fixture, None);
    assert_eq!(checkpoint_report.outcome, Outcome::Incomplete);
    assert_eq!(
        checkpoint_report.history_scope,
        HistoryScope::InternalPrefix
    );
    assert!(finding_codes(&checkpoint_report).contains(&"proof.verify.checkpoint.required"));
}

#[test]
fn corrupt_authority_signature_is_invalid_and_emits_no_verified_claims() {
    let fixture = generate(
        OpeningMode::Withhold,
        SignatureMode::CorruptAuthorityDecision,
    );
    let report = verify(&fixture, Some(&fixture.checkpoint_json));

    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.authority.signature"));
    assert_eq!(report.verified_claims.workspace_id, None);
    assert_eq!(report.verified_claims.release_id, None);
    assert_eq!(report.verified_claims.release_digest, None);
    assert_eq!(report.verified_claims.authorization_decision_digest, None);
    assert_eq!(report.verified_claims.authority_head, None);
}

#[test]
fn canonical_byte_and_digest_tampering_have_stable_container_codes() {
    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let command_path = fixture.artifact_path(fixture.command_input);
    let mut bytes = fs::read(&command_path).unwrap();
    bytes.push(b' ');
    fs::write(&command_path, bytes).unwrap();
    let noncanonical = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(noncanonical.outcome, Outcome::Invalid);
    assert!(finding_codes(&noncanonical).contains(&"proof.verify.artifact.length"));

    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let command_path = fixture.artifact_path(fixture.command_input);
    let mut value: Value = serde_json::from_slice(&fs::read(&command_path).unwrap()).unwrap();
    value["workspace_id"] = Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    let replacement = canonical(&value);
    assert_eq!(
        replacement.len(),
        usize::try_from(fs::metadata(&command_path).unwrap().len()).unwrap()
    );
    fs::write(&command_path, replacement).unwrap();
    let digest = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(digest.outcome, Outcome::Invalid);
    assert!(finding_codes(&digest).contains(&"proof.verify.artifact.digest"));
}

#[test]
fn checkpoint_mismatch_and_compromise_cutoff_never_claim_a_pinned_head() {
    let mut mismatch = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut checkpoint: Value = serde_json::from_slice(&mismatch.checkpoint_json).unwrap();
    checkpoint["authority_sequence"] = Value::from(4);
    mismatch.checkpoint_json = canonical(&checkpoint);
    let report = verify(&mismatch, Some(&mismatch.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid);
    assert_eq!(report.history_scope, HistoryScope::InternalPrefix);
    assert!(finding_codes(&report).contains(&"proof.verify.checkpoint.mismatch"));
    assert_eq!(report.verified_claims.authority_head, None);

    let mut cutoff = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let bundle = cutoff.bundle_value();
    let record_digest = bundle["authority_prefix"][3]["record_digest"].clone();
    let mut trust = cutoff.trust_value();
    trust["authority"]["compromise_cutoff"] = serde_json::json!({
        "record_digest": record_digest,
        "sequence": 4,
    });
    cutoff.replace_trust(&trust);
    let report = verify(&cutoff, Some(&cutoff.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid);
    assert_eq!(report.history_scope, HistoryScope::InternalPrefix);
    assert!(finding_codes(&report).contains(&"proof.verify.authority.beyond_compromise_cutoff"));
}

#[test]
fn authority_truncation_and_fork_substitution_are_invalid() {
    let mut truncated = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = truncated.bundle_value();
    bundle["authority_prefix"].as_array_mut().unwrap().pop();
    let new_head = bundle["authority_prefix"][3]["record_digest"].clone();
    bundle["included_authority_head"] = serde_json::json!({
        "record_digest": new_head,
        "sequence": 4,
    });
    truncated.replace_bundle(&bundle);
    let report = verify(&truncated, Some(&truncated.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid);
    assert!(finding_codes(&report).contains(&"proof.verify.bundle.entrypoint"));

    let mut forked = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = forked.bundle_value();
    bundle["authority_prefix"][3]["record_digest"] = Value::String(Digest([0x44; 32]).to_string());
    forked.replace_bundle(&bundle);
    let report = verify(&forked, Some(&forked.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.authority.chain"));
}

#[test]
fn required_external_preimage_is_incomplete_without_producer_reconstruction() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = fixture.bundle_value();
    let command_digest = fixture.command_input.digest.to_string();
    let descriptor = bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| {
            descriptor["role"] == "command_input"
                && descriptor["artifact"]["digest"] == command_digest
        })
        .unwrap();
    descriptor["availability"] = serde_json::json!({"state": "external_commitment"});
    let command_path = fixture.artifact_path(fixture.command_input);
    fs::remove_file(&command_path).unwrap();
    let digest_directory = command_path.parent().unwrap();
    let kind_directory = digest_directory.parent().unwrap();
    fs::remove_dir(digest_directory).unwrap();
    fs::remove_dir(kind_directory).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Incomplete, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.external.missing"));
    assert!(finding_codes(&report).contains(&"proof.verify.command.input_missing"));
    assert!(finding_codes(&report).contains(&"proof.verify.consequence.artifact_missing"));
    assert_eq!(
        report.dimensions["localized_consequence"],
        DimensionStatus::Incomplete
    );
    assert!(
        report
            .dimensions
            .values()
            .all(|status| *status != DimensionStatus::Invalid),
        "{report:#?}"
    );
}

#[test]
fn invalid_included_preimage_remains_invalid() {
    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let command_path = fixture.artifact_path(fixture.command_input);
    let mut command: Value = serde_json::from_slice(&fs::read(&command_path).unwrap()).unwrap();
    command["workspace_id"] = Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    fs::write(&command_path, canonical(&command)).unwrap();

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.artifact.digest"));
    assert!(!finding_codes(&report).contains(&"proof.verify.external.missing"));
    assert_eq!(
        report.dimensions["command_authentication"],
        DimensionStatus::Invalid
    );
    assert_eq!(
        report.dimensions["localized_consequence"],
        DimensionStatus::Invalid
    );
}

#[test]
fn required_external_release_policy_is_incomplete_without_semantic_cascade() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = fixture.bundle_value();
    let descriptor = bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| descriptor["role"] == "release_policy_decision")
        .unwrap();
    let policy_reference: ArtifactRef =
        serde_json::from_value(descriptor["artifact"].clone()).unwrap();
    descriptor["availability"] = serde_json::json!({"state": "external_commitment"});
    let policy_path = fixture.artifact_path(policy_reference);
    fs::remove_file(&policy_path).unwrap();
    let digest_directory = policy_path.parent().unwrap();
    let kind_directory = digest_directory.parent().unwrap();
    fs::remove_dir(digest_directory).unwrap();
    fs::remove_dir(kind_directory).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Incomplete, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.external.missing"));
    assert!(finding_codes(&report).contains(&"proof.verify.release.policy_missing"));
    assert_eq!(report.dimensions["policy"], DimensionStatus::Incomplete);
    assert!(
        report
            .dimensions
            .values()
            .all(|status| *status != DimensionStatus::Invalid),
        "{report:#?}"
    );
}

#[test]
fn readdressed_command_substitution_reaches_and_fails_semantic_cross_links() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let old_reference = fixture.command_input;
    let old_path = fixture.artifact_path(old_reference);
    let mut command: Value = serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
    command["workspace_id"] = Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    let bytes = canonical(&command);
    let new_reference = ArtifactRef {
        artifact_kind: old_reference.artifact_kind,
        digest: digest(old_reference.artifact_kind, &bytes),
    };
    let new_path = fixture.artifact_path(new_reference);
    fs::create_dir_all(new_path.parent().unwrap()).unwrap();
    fs::write(&new_path, &bytes).unwrap();
    fs::remove_file(old_path).unwrap();

    let mut bundle = fixture.bundle_value();
    let old_digest = old_reference.digest.to_string();
    let descriptor = bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| {
            descriptor["role"] == "command_input" && descriptor["artifact"]["digest"] == old_digest
        })
        .unwrap();
    descriptor["artifact"] = serde_json::to_value(new_reference).unwrap();
    descriptor["availability"]["byte_length"] = Value::from(bytes.len() as u64);
    bundle["authority_prefix"][4]["decision_companion"]["command_input"] =
        serde_json::to_value(new_reference).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.command.cross_link"));
    assert!(!finding_codes(&report).contains(&"proof.verify.artifact.digest"));
}

#[test]
fn signed_binding_sequence_substitution_fails_the_causal_decision_link() {
    let fixture = generate(
        OpeningMode::Withhold,
        SignatureMode::SubstituteBindingSequence,
    );
    let report = verify(&fixture, Some(&fixture.checkpoint_json));

    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.binding.inactive"));
    assert!(!finding_codes(&report).contains(&"proof.verify.authority.signature"));
}

#[test]
fn release_entrypoint_splice_and_revoked_signer_are_invalid() {
    let mut spliced = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = spliced.bundle_value();
    let target = bundle["entrypoints"]["target_release_manifest"]["digest"].clone();
    let replacement = bundle["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|descriptor| {
            descriptor["role"] == "release_manifest"
                && descriptor["artifact"]["artifact_kind"] == "release_v2"
                && descriptor["artifact"]["digest"] != target
        })
        .unwrap()["artifact"]
        .clone();
    bundle["entrypoints"]["target_release_manifest"] = replacement;
    spliced.replace_bundle(&bundle);
    let report = verify(&spliced, Some(&spliced.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.release.subject"));

    let mut revoked = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = revoked.trust_value();
    trust["release"]["trusted_signers"][0]["revoked_at"] =
        Value::String("2026-08-21T10:09:00Z".to_owned());
    revoked.replace_trust(&trust);
    let report = verify(&revoked, Some(&revoked.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.release.key_time"));
}

#[test]
fn withheld_bundle_contains_neither_raw_uid_nor_subject_blind() {
    let fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let files = all_files(fixture.root());
    let blind = fixture.subject_blind.as_bytes();

    assert!(
        files
            .iter()
            .all(|bytes| !bytes.windows(8).any(|window| window == b"uid:1000"))
    );
    assert!(
        files
            .iter()
            .all(|bytes| !bytes.windows(blind.len()).any(|window| window == blind))
    );
}

#[test]
fn included_opening_rejects_a_noncanonical_32_byte_blind_substitution() {
    let mut fixture = generate(OpeningMode::Include, SignatureMode::Valid);
    let old_reference = fixture.subject_opening;
    let old_path = fixture.artifact_path(old_reference);
    let mut opening: Value = serde_json::from_slice(&fs::read(&old_path).unwrap()).unwrap();
    opening["blind"] = Value::String("AA".to_owned());
    opening["commitment_input"]["blind"] = Value::String("AA".to_owned());
    let bytes = canonical(&opening);
    let new_reference = ArtifactRef {
        artifact_kind: old_reference.artifact_kind,
        digest: digest(old_reference.artifact_kind, &bytes),
    };
    let new_path = fixture.artifact_path(new_reference);
    fs::write(&new_path, &bytes).unwrap();
    fs::remove_file(old_path).unwrap();

    let mut bundle = fixture.bundle_value();
    let old_digest = old_reference.digest.to_string();
    let descriptor = bundle["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|descriptor| {
            descriptor["role"] == "subject_opening"
                && descriptor["artifact"]["digest"] == old_digest
        })
        .unwrap();
    descriptor["artifact"] = serde_json::to_value(new_reference).unwrap();
    descriptor["availability"]["byte_length"] = Value::from(bytes.len() as u64);
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.subject.opening_invalid"));
}

#[test]
fn complete_report_bytes_and_digest_are_deterministic() {
    let fixture_a = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let fixture_b = generate(OpeningMode::Withhold, SignatureMode::Valid);
    assert_eq!(
        fixture_a.bundle_manifest_digest,
        fixture_b.bundle_manifest_digest
    );

    let report_a = verify(&fixture_a, Some(&fixture_a.checkpoint_json));
    let report_b = verify(&fixture_b, Some(&fixture_b.checkpoint_json));
    let canonical_a = canonical_report(&report_a).unwrap();
    let canonical_b = canonical_report(&report_b).unwrap();
    assert_eq!(canonical_a, canonical_b);
}

#[test]
fn generated_outcomes_match_frozen_conformance_hashes() {
    fn identifiers(
        fixture: &support::GeneratedFixture,
        report: &proof_verifier::model::Report,
    ) -> Value {
        serde_json::json!({
            "bundle_manifest_digest": fixture.bundle_manifest_digest,
            "checkpoint_digest": parse_checkpoint(&fixture.checkpoint_json).unwrap().digest,
            "report_digest": canonical_report(report).unwrap().1,
            "trust_policy_digest": parse_trust_policy(&fixture.trust_json).unwrap().digest,
        })
    }

    let complete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let complete_report = verify(&complete, Some(&complete.checkpoint_json));

    let mut incomplete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = incomplete.trust_value();
    trust["disclosure"]["requesting_subject_opening"] = Value::String("required".to_owned());
    incomplete.replace_trust(&trust);
    let incomplete_report = verify(&incomplete, Some(&incomplete.checkpoint_json));

    let invalid = generate(
        OpeningMode::Withhold,
        SignatureMode::CorruptAuthorityDecision,
    );
    let invalid_report = verify(&invalid, Some(&invalid.checkpoint_json));

    let hashes = serde_json::json!({
        "api_version": "proof.dev/portable-proof-conformance-hashes/v1",
        "complete": identifiers(&complete, &complete_report),
        "incomplete": identifiers(&incomplete, &incomplete_report),
        "invalid": identifiers(&invalid, &invalid_report),
    });
    let frozen: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v1/portable-proof/hashes.json"
    ))
    .unwrap();
    assert_eq!(hashes, frozen);
}

#[test]
fn generated_inputs_and_reports_match_canonical_wire_fixtures() {
    fn line(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.push(b'\n');
        bytes
    }

    let complete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let complete_report = verify(&complete, Some(&complete.checkpoint_json));

    let mut incomplete = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut required_trust = incomplete.trust_value();
    required_trust["disclosure"]["requesting_subject_opening"] =
        Value::String("required".to_owned());
    incomplete.replace_trust(&required_trust);
    let incomplete_report = verify(&incomplete, Some(&incomplete.checkpoint_json));

    let invalid = generate(
        OpeningMode::Withhold,
        SignatureMode::CorruptAuthorityDecision,
    );
    let invalid_report = verify(&invalid, Some(&invalid.checkpoint_json));

    assert_eq!(
        line(fs::read(complete.root().join("bundle.json")).unwrap()),
        include_bytes!("../../../conformance/v1/portable-proof/bundle.json")
    );
    assert_eq!(
        line(complete.checkpoint_json.clone()),
        include_bytes!("../../../conformance/v1/portable-proof/checkpoint.json")
    );
    assert_eq!(
        line(canonical_report(&complete_report).unwrap().0),
        include_bytes!("../../../conformance/v1/portable-proof/report.complete.json")
    );
    assert_eq!(
        line(canonical_report(&incomplete_report).unwrap().0),
        include_bytes!("../../../conformance/v1/portable-proof/report.incomplete.json")
    );
    assert_eq!(
        line(canonical_report(&invalid_report).unwrap().0),
        include_bytes!("../../../conformance/v1/portable-proof/report.invalid.json")
    );
    assert_eq!(
        line(complete.trust_json.clone()),
        include_bytes!("../../../conformance/v1/portable-proof/trust.complete.json")
    );
    assert_eq!(
        line(canonical(&required_trust)),
        include_bytes!("../../../conformance/v1/portable-proof/trust.required-opening.json")
    );
}
