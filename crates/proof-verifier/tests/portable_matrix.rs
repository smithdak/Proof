mod support;

use std::{collections::BTreeSet, fs, path::Path};

use proof_verifier::{
    VerificationRequest, canonical_report,
    model::{
        ArtifactKind, ArtifactRef, Digest, DimensionStatus, EvidenceRole, HistoryScope,
        OpeningRequirement, Outcome,
    },
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

fn artifact_value(fixture: &support::GeneratedFixture, reference: ArtifactRef) -> Value {
    serde_json::from_slice(&fs::read(fixture.artifact_path(reference)).unwrap()).unwrap()
}

fn decision_companion_for_effect(
    fixture: &support::GeneratedFixture,
    effect: ArtifactRef,
) -> Option<Value> {
    let expected = serde_json::to_value(effect).unwrap();
    fixture.bundle_value()["authority_prefix"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry.get("decision_companion"))
        .find(|companion| companion.get("application_effect") == Some(&expected))
        .cloned()
}

fn release_key_id(fixture: &support::GeneratedFixture, reference: ArtifactRef) -> String {
    artifact_value(fixture, reference)["key_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn trusted_signer_mut<'a>(trust: &'a mut Value, key_id: &str) -> &'a mut Value {
    trust["release"]["trusted_signers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["key_id"] == key_id)
        .unwrap()
}

fn release_key_evidence_ref(fixture: &support::GeneratedFixture, key_id: &str) -> ArtifactRef {
    fixture.bundle_value()["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|descriptor| descriptor["role"] == "release_signing_key")
        .map(|descriptor| {
            serde_json::from_value::<ArtifactRef>(descriptor["artifact"].clone()).unwrap()
        })
        .find(|reference| artifact_value(fixture, *reference)["key_id"] == key_id)
        .unwrap()
}

fn add_included_artifact(
    fixture: &support::GeneratedFixture,
    bundle: &mut Value,
    role: EvidenceRole,
    kind: ArtifactKind,
    value: &Value,
) -> ArtifactRef {
    let bytes = canonical(value);
    let reference = ArtifactRef {
        artifact_kind: kind,
        digest: digest(kind, &bytes),
    };
    let path = fixture.artifact_path(reference);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, &bytes).unwrap();
    let descriptors = bundle["artifacts"].as_array_mut().unwrap();
    descriptors.push(serde_json::json!({
        "artifact": reference,
        "availability": {
            "byte_length": bytes.len(),
            "state": "included",
        },
        "role": role.wire_name(),
    }));
    descriptors.sort_by_key(|descriptor| {
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
    reference
}

fn withhold_artifact(
    fixture: &mut support::GeneratedFixture,
    role: EvidenceRole,
    reference: ArtifactRef,
) {
    let mut bundle = fixture.bundle_value();
    let expected = serde_json::to_value(reference).unwrap();
    let descriptors = bundle["artifacts"].as_array_mut().unwrap();
    let descriptor = descriptors
        .iter_mut()
        .find(|descriptor| {
            descriptor["role"] == role.wire_name() && descriptor["artifact"] == expected
        })
        .unwrap();
    descriptor["availability"] = serde_json::json!({"state": "external_commitment"});
    let path = fixture.artifact_path(reference);
    fs::remove_file(&path).unwrap();
    let _ = fs::remove_dir(path.parent().unwrap());
    let _ = fs::remove_dir(path.parent().unwrap().parent().unwrap());
    fixture.replace_bundle(&bundle);
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
fn localized_creation_requires_candidate_and_causal_closure() {
    for mode in [
        SignatureMode::LocalizedCreationConstructive,
        SignatureMode::LocalizedCreationRepaired,
    ] {
        let constructive = generate(OpeningMode::Withhold, mode);
        let report = verify(&constructive, Some(&constructive.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Complete, "{mode:?}: {report:#?}");
        assert!(report.findings.is_empty(), "{mode:?}: {report:#?}");
    }

    for (mode, expected_code) in [
        (
            SignatureMode::LocalizedCreationCandidateOmitted,
            "proof.verify.content.context_resources",
        ),
        (
            SignatureMode::LocalizedCreationCausalityViolation,
            "proof.verify.content.edit_causality",
        ),
        (
            SignatureMode::LocalizedCreationRepairEvidenceMissing,
            "proof.verify.content.repair_evidence",
        ),
        (
            SignatureMode::LocalizedCreationRepairPairMissing,
            "proof.verify.content.edit_lineage",
        ),
        (
            SignatureMode::LocalizedCreationRepairSupersedesMismatch,
            "proof.verify.content.edit_lineage",
        ),
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert_eq!(
            report.dimensions["content_delta"],
            DimensionStatus::Invalid,
            "{mode:?}: {report:#?}"
        );
        assert!(
            finding_codes(&report).contains(&expected_code),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn localized_v2_creation_slots_are_optional_closed_and_bounded() {
    for mode in [
        SignatureMode::LocalizedV2CreationsOmitted,
        SignatureMode::LocalizedV2CreationsEmpty,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Complete, "{mode:?}: {report:#?}");
        assert!(report.findings.is_empty(), "{mode:?}: {report:#?}");
    }

    for (mode, schema_invalid) in [
        (SignatureMode::LocalizedV2CreationsMalformed, true),
        (SignatureMode::LocalizedV2CreationsUnsorted, false),
        (SignatureMode::LocalizedV2CreationsOverLimit, true),
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert_eq!(
            report.dimensions["content_delta"],
            DimensionStatus::Invalid,
            "{mode:?}: {report:#?}"
        );
        assert!(
            finding_codes(&report).contains(&"proof.verify.content.intent_targets"),
            "{mode:?}: {report:#?}"
        );
        assert_eq!(
            finding_codes(&report).contains(&"proof.verify.artifact.schema"),
            schema_invalid,
            "{mode:?}: {report:#?}"
        );
    }
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
    assert!(
        finding_codes(&noncanonical).contains(&"proof.verify.artifact.length"),
        "{noncanonical:#?}"
    );

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
fn causally_exact_checkpoint_accepts_an_earlier_observer_clock() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut checkpoint: Value = serde_json::from_slice(&fixture.checkpoint_json).unwrap();
    checkpoint["observed_at"] = Value::String("2026-08-21T09:00:00Z".to_owned());
    fixture.checkpoint_json = canonical(&checkpoint);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert_eq!(report.history_scope, HistoryScope::PinnedHead);
    assert!(report.findings.is_empty(), "{report:#?}");
}

#[test]
fn causal_prefix_position_wins_over_status_and_revocation_clock_skew() {
    for mode in [
        SignatureMode::FutureCausalStatus,
        SignatureMode::LaterCausalRevocation,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Complete, "{mode:?}: {report:#?}");
        assert_eq!(report.history_scope, HistoryScope::PinnedHead);
        assert!(report.findings.is_empty(), "{mode:?}: {report:#?}");
    }
}

#[test]
fn dual_signed_root_rotation_is_complete_and_cutoff_or_wrong_checkpoint_stops_it() {
    let rotated = generate(OpeningMode::Withhold, SignatureMode::RootRotation);
    let report = verify(&rotated, Some(&rotated.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert_eq!(report.history_scope, HistoryScope::PinnedHead);
    assert_eq!(report.verified_claims.authority_head.unwrap().sequence, 6);

    let mut cutoff = generate(OpeningMode::Withhold, SignatureMode::RootRotation);
    let bundle = cutoff.bundle_value();
    let mut trust = cutoff.trust_value();
    trust["authority"]["compromise_cutoff"] = serde_json::json!({
        "record_digest": bundle["authority_prefix"][4]["record_digest"],
        "sequence": 5,
    });
    cutoff.replace_trust(&trust);
    let report = verify(&cutoff, Some(&cutoff.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.authority.beyond_compromise_cutoff"));

    let mut wrong_checkpoint = generate(OpeningMode::Withhold, SignatureMode::RootRotation);
    let mut checkpoint: Value = serde_json::from_slice(&wrong_checkpoint.checkpoint_json).unwrap();
    checkpoint["active_authority_key_id"] =
        wrong_checkpoint.trust_value()["authority"]["initial_root"]["key_id"].clone();
    wrong_checkpoint.checkpoint_json = canonical(&checkpoint);
    let report = verify(&wrong_checkpoint, Some(&wrong_checkpoint.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.checkpoint.mismatch"));
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
fn every_supplied_artifact_tamper_is_invalid_and_required_withholding_is_incomplete() {
    let inventory = generate(OpeningMode::Include, SignatureMode::Valid);
    let supplied = inventory.bundle_value()["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|descriptor| descriptor["availability"]["state"] == "included")
        .map(|descriptor| serde_json::from_value(descriptor["artifact"].clone()).unwrap())
        .collect::<BTreeSet<ArtifactRef>>();
    assert!(supplied.len() > 20, "descriptor matrix unexpectedly shrank");

    for reference in supplied {
        let fixture = generate(OpeningMode::Include, SignatureMode::Valid);
        let path = fixture.artifact_path(reference);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b' ');
        fs::write(&path, bytes).unwrap();
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(
            report.outcome,
            Outcome::Invalid,
            "tampered {reference:?}: {report:#?}"
        );
        assert!(
            finding_codes(&report).contains(&"proof.verify.artifact.length"),
            "tampered {reference:?}: {report:#?}"
        );

        let mut fixture = generate(OpeningMode::Include, SignatureMode::Valid);
        let mut trust = fixture.trust_value();
        trust["disclosure"]["requesting_subject_opening"] =
            serde_json::to_value(OpeningRequirement::Required).unwrap();
        fixture.replace_trust(&trust);
        let mut bundle = fixture.bundle_value();
        let expected = serde_json::to_value(reference).unwrap();
        let mut changed = 0_usize;
        for descriptor in bundle["artifacts"].as_array_mut().unwrap() {
            if descriptor["artifact"] == expected {
                descriptor["availability"] = serde_json::json!({"state": "external_commitment"});
                changed += 1;
            }
        }
        assert!(changed > 0, "missing descriptor for {reference:?}");
        let path = fixture.artifact_path(reference);
        fs::remove_file(&path).unwrap();
        let digest_directory = path.parent().unwrap();
        let kind_directory = digest_directory.parent().unwrap();
        let _ = fs::remove_dir(digest_directory);
        let _ = fs::remove_dir(kind_directory);
        fixture.replace_bundle(&bundle);

        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(
            report.outcome,
            Outcome::Incomplete,
            "withheld {reference:?}: {report:#?}"
        );
        assert!(
            finding_codes(&report).contains(&"proof.verify.external.missing"),
            "withheld {reference:?}: {report:#?}"
        );
        assert!(
            report
                .dimensions
                .values()
                .all(|status| *status != DimensionStatus::Invalid),
            "withheld {reference:?}: {report:#?}"
        );
    }
}

#[test]
fn required_external_release_policy_is_incomplete_without_semantic_cascade() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let manifest = artifact_value(&fixture, fixture.target_release_manifest);
    let policy_digest = manifest["authorization_decision_digest"].as_str().unwrap();
    let policy_reference = fixture.bundle_value()["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|descriptor| {
            descriptor["role"] == "release_policy_decision"
                && descriptor["artifact"]["digest"] == policy_digest
        })
        .map(|descriptor| serde_json::from_value(descriptor["artifact"].clone()).unwrap())
        .unwrap();
    withhold_artifact(
        &mut fixture,
        EvidenceRole::ReleasePolicyDecision,
        policy_reference,
    );

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
fn signed_subdelegation_record_is_rejected_by_the_closed_authority_contract() {
    let fixture = generate(OpeningMode::Withhold, SignatureMode::SubdelegationRecord);
    let report = verify(&fixture, Some(&fixture.checkpoint_json));

    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.authority.record_schema"));
    assert!(!finding_codes(&report).contains(&"proof.verify.authority.signature"));
}

#[test]
fn wrong_delegation_issuer_and_recipient_are_rejected() {
    for mode in [
        SignatureMode::WrongDelegationIssuer,
        SignatureMode::WrongDelegationRecipient,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));

        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.authority.causal_state"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.authority.signature"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn bootstrap_only_admin_and_active_binding_requirements_are_enforced() {
    for mode in [
        SignatureMode::SecondHumanAdmin,
        SignatureMode::DelegationWithoutActiveBinding,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.authority.causal_state"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn binding_rotation_requires_exact_supersession_and_disables_the_old_binding() {
    for mode in [
        SignatureMode::BindingRotationMissingSupersedes,
        SignatureMode::BindingRotationWrongSupersedes,
        SignatureMode::BindingRotationSelfSupersedes,
        SignatureMode::SupersededBindingDecision,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.authority.causal_state")
                || finding_codes(&report).contains(&"proof.verify.authority.record_schema"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn authority_binding_and_release_signing_keys_are_role_separated() {
    for mode in [
        SignatureMode::AuthoritySuccessorReusesBindingKey,
        SignatureMode::BindingReusesAuthorityRootKey,
        SignatureMode::ReleaseSignerReusesAuthorityRootKey,
        SignatureMode::ReleaseSignerReusesBindingKey,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.authority.causal_state")
                || finding_codes(&report).contains(&"proof.verify.trust.invalid"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn reconstructible_signed_denials_are_complete_and_have_no_effects() {
    for mode in [
        SignatureMode::DenialScopeExceeded,
        SignatureMode::DenialBudgetExceeded,
        SignatureMode::DenialActionExceeded,
        SignatureMode::DenialDelegationUnavailable,
        SignatureMode::DenialPrincipalDisabled,
        SignatureMode::DenialBindingInactive,
        SignatureMode::DenialDelegationExpired,
        SignatureMode::DenialDelegationNotYetValid,
        SignatureMode::DenialRevokedRetry,
        SignatureMode::DenialIdempotencyKeyReused,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Complete, "{mode:?}: {report:#?}");
        assert!(report.findings.is_empty(), "{mode:?}: {report:#?}");

        let bundle = fixture.bundle_value();
        let denial_companion = &bundle["authority_prefix"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["decision_companion"];
        for field in ["result", "localized_consequence", "application_effect"] {
            assert!(
                denial_companion[field].is_null(),
                "{mode:?} denial unexpectedly carries {field}: {denial_companion:#?}"
            );
        }
    }
}

#[test]
fn fail_safe_or_effectful_denials_are_invalid() {
    for mode in [
        SignatureMode::DenialPolicyDenied,
        SignatureMode::DenialChainUnsupported,
        SignatureMode::DenialWithEffect,
        SignatureMode::DenialIdempotencyExactReplay,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        if mode == SignatureMode::DenialWithEffect {
            assert!(
                finding_codes(&report).contains(&"proof.verify.consequence.deny_has_effect"),
                "{report:#?}"
            );
        }
    }
}

#[test]
fn idempotency_reuse_denial_requires_a_reconstructible_prior_owner() {
    let fresh = generate(
        OpeningMode::Withhold,
        SignatureMode::DenialIdempotencyFreshKey,
    );
    let report = verify(&fresh, Some(&fresh.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Incomplete, "{report:#?}");
    assert!(
        report
            .dimensions
            .values()
            .all(|status| *status != DimensionStatus::Invalid),
        "{report:#?}"
    );

    let mut withheld = generate(
        OpeningMode::Withhold,
        SignatureMode::DenialIdempotencyKeyReused,
    );
    let target_consequence: ArtifactRef = serde_json::from_value(
        withheld.bundle_value()["entrypoints"]["target_localized_consequence"].clone(),
    )
    .unwrap();
    withhold_artifact(
        &mut withheld,
        EvidenceRole::LocalizedConsequence,
        target_consequence,
    );
    let report = verify(&withheld, Some(&withheld.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Incomplete, "{report:#?}");
    assert!(
        report
            .dimensions
            .values()
            .all(|status| *status != DimensionStatus::Invalid),
        "{report:#?}"
    );
}

#[test]
fn signed_actor_presentation_substitution_fails_the_command_cross_link() {
    let fixture = generate(
        OpeningMode::Withhold,
        SignatureMode::SubstituteActorPresentation,
    );
    let report = verify(&fixture, Some(&fixture.checkpoint_json));

    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.command.cross_link"));
    assert!(!finding_codes(&report).contains(&"proof.verify.authority.signature"));
    assert!(!finding_codes(&report).contains(&"proof.verify.artifact.digest"));
}

#[test]
fn unrelated_required_withholding_does_not_mask_an_included_semantic_invalidity() {
    let mut fixture = generate(
        OpeningMode::Withhold,
        SignatureMode::SubstituteActorPresentation,
    );
    let mut trust = fixture.trust_value();
    trust["disclosure"]["requesting_subject_opening"] =
        serde_json::to_value(OpeningRequirement::Required).unwrap();
    fixture.replace_trust(&trust);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert_eq!(
        report.dimensions["evidence_completeness"],
        DimensionStatus::Incomplete
    );
    assert_eq!(
        report.dimensions["command_authentication"],
        DimensionStatus::Invalid
    );
    assert!(finding_codes(&report).contains(&"proof.verify.external.missing"));
    assert!(finding_codes(&report).contains(&"proof.verify.command.cross_link"));
}

#[test]
fn release_entrypoint_splice_and_revoked_signer_are_invalid() {
    let mut spliced = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = spliced.bundle_value();
    let target: ArtifactRef =
        serde_json::from_value(bundle["entrypoints"]["target_release_manifest"].clone()).unwrap();
    let mut alternate: Value =
        serde_json::from_slice(&fs::read(spliced.artifact_path(target)).unwrap()).unwrap();
    alternate["release_id"] = Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    let alternate_bytes = canonical(&alternate);
    let replacement = ArtifactRef {
        artifact_kind: ArtifactKind::ReleaseV2,
        digest: digest(ArtifactKind::ReleaseV2, &alternate_bytes),
    };
    let replacement_path = spliced.artifact_path(replacement);
    fs::create_dir_all(replacement_path.parent().unwrap()).unwrap();
    fs::write(replacement_path, &alternate_bytes).unwrap();
    let descriptors = bundle["artifacts"].as_array_mut().unwrap();
    descriptors.push(serde_json::json!({
        "artifact": replacement,
        "availability": {
            "byte_length": alternate_bytes.len(),
            "state": "included",
        },
        "role": "release_manifest",
    }));
    descriptors.sort_by_key(|descriptor| {
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
    bundle["entrypoints"]["target_release_manifest"] = serde_json::to_value(replacement).unwrap();
    spliced.replace_bundle(&bundle);
    let report = verify(&spliced, Some(&spliced.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.release.subject"),
        "{report:#?}"
    );

    let mut revoked = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = revoked.trust_value();
    let target_key_id = release_key_id(&revoked, revoked.target_release_manifest);
    trusted_signer_mut(&mut trust, &target_key_id)["revoked_at"] =
        Value::String("2026-08-21T10:09:00Z".to_owned());
    revoked.replace_trust(&trust);
    let report = verify(&revoked, Some(&revoked.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.release.key_time"));
}

#[test]
fn release_signing_time_boundaries_and_later_revocation_are_enforced() {
    let cases = [
        ("not_before", "2026-08-21T10:10:00Z", Outcome::Complete),
        ("not_before", "2026-08-21T10:11:00Z", Outcome::Invalid),
        ("not_after", "2026-08-21T10:10:00Z", Outcome::Invalid),
        ("not_after", "2026-08-21T10:11:00Z", Outcome::Complete),
        ("revoked_at", "2026-08-21T10:10:00Z", Outcome::Invalid),
        ("revoked_at", "2026-08-21T10:11:00Z", Outcome::Complete),
    ];
    for (field, timestamp, expected) in cases {
        let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
        let mut trust = fixture.trust_value();
        let target_key_id = release_key_id(&fixture, fixture.target_release_manifest);
        trusted_signer_mut(&mut trust, &target_key_id)[field] = Value::String(timestamp.to_owned());
        fixture.replace_trust(&trust);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, expected, "{field}={timestamp}: {report:#?}");
        if expected == Outcome::Invalid {
            assert!(
                finding_codes(&report).contains(&"proof.verify.release.key_time"),
                "{field}={timestamp}: {report:#?}"
            );
        }
    }

    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = fixture.trust_value();
    let key_id = release_key_id(&fixture, fixture.target_release_manifest);
    let revoked_at = "2026-08-21T10:11:00Z";
    trusted_signer_mut(&mut trust, &key_id)["revoked_at"] = Value::String(revoked_at.to_owned());
    fixture.replace_trust(&trust);
    let native_revocation = serde_json::json!({
        "api_version": "proof.dev/signing-key-revocation/v1",
        "key_id": key_id,
        "reason": "rotation",
        "revoked_at": revoked_at,
    });
    let native_revocation_digest =
        digest(ArtifactKind::PolicyBundleV1, &canonical(&native_revocation));
    let revocation = serde_json::json!({
        "api_version": "proof.dev/release-signing-key-revocation/v1",
        "key_id": key_id,
        "native_revocation": native_revocation,
        "native_revocation_digest": native_revocation_digest,
        "reason": "rotation",
        "revoked_at": revoked_at,
        "workspace_id": trust["workspace_id"],
    });
    let mut bundle = fixture.bundle_value();
    add_included_artifact(
        &fixture,
        &mut bundle,
        EvidenceRole::ReleaseSigningKeyRevocation,
        ArtifactKind::ReleaseSigningKeyRevocationV1,
        &revocation,
    );
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");
}

#[test]
fn external_root_restores_the_exact_committed_subject_opening() {
    let withheld = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let external = generate(OpeningMode::Include, SignatureMode::Valid);

    let report = verify_bundle_directory(VerificationRequest {
        bundle_root: withheld.root(),
        trust_policy_json: &withheld.trust_json,
        checkpoint_json: Some(&withheld.checkpoint_json),
        external_roots: &[external.root().to_path_buf()],
    });

    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert_eq!(report.dimensions["subject_opening"], DimensionStatus::Valid);
    assert!(report.findings.is_empty(), "{report:#?}");
}

#[test]
fn wrong_localized_consequence_endpoint_is_rejected() {
    let mut fixture = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut bundle = fixture.bundle_value();
    let target: ArtifactRef =
        serde_json::from_value(bundle["entrypoints"]["target_localized_consequence"].clone())
            .unwrap();
    let mut alternate: Value =
        serde_json::from_slice(&fs::read(fixture.artifact_path(target)).unwrap()).unwrap();
    alternate["presentation_id"] = Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    let replacement = add_included_artifact(
        &fixture,
        &mut bundle,
        EvidenceRole::LocalizedConsequence,
        ArtifactKind::AuthenticatedLocalizedConsequenceV1,
        &alternate,
    );
    bundle["entrypoints"]["target_localized_consequence"] =
        serde_json::to_value(replacement).unwrap();
    fixture.replace_bundle(&bundle);

    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.consequence.cross_link"),
        "{report:#?}"
    );
}

#[test]
fn complete_rollback_bundle_requires_an_unbroken_predecessor_chain() {
    let complete = generate(OpeningMode::Withhold, SignatureMode::RollbackRelease);
    let report = verify(&complete, Some(&complete.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert_eq!(report.history_scope, HistoryScope::PinnedHead);
    assert!(report.findings.is_empty(), "{report:#?}");

    let broken = generate(OpeningMode::Withhold, SignatureMode::RollbackBrokenAncestry);
    let report = verify(&broken, Some(&broken.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.content.rollback_ancestry"),
        "{report:#?}"
    );
}

#[test]
fn signed_release_kind_and_rollback_target_shape_tampering_is_invalid() {
    for mode in [
        SignatureMode::PromotionWithRollbackTarget,
        SignatureMode::RollbackWithNullTarget,
        SignatureMode::RollbackSelectsDifferentEdition,
        SignatureMode::RollbackPromotionWorkspaceTamper,
        SignatureMode::V2PredicateUnknownField,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "the internally re-signed history mutation must fail semantically: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn historical_v2_content_evidence_rejects_unknown_nested_fields_after_resigning() {
    let control = generate(OpeningMode::Withhold, SignatureMode::RollbackRelease);
    let control_report = verify(&control, Some(&control.checkpoint_json));
    assert_eq!(
        control_report.outcome,
        Outcome::Complete,
        "{control_report:#?}"
    );
    assert!(control_report.findings.is_empty(), "{control_report:#?}");

    for mode in [
        SignatureMode::HistoricalV2ContentEvidenceUnknownField,
        SignatureMode::HistoricalV2ContentBaseUnknownField,
        SignatureMode::HistoricalV2ContentChangesetUnknownField,
        SignatureMode::HistoricalV2ContentResourceIntentUnknownField,
        SignatureMode::HistoricalV2ContentValidationUnknownField,
        SignatureMode::HistoricalV2ContentRenditionUnknownField,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        assert_ne!(
            fixture.promotion_release_proof,
            fixture.target_release_proof
        );
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        let codes = finding_codes(&report);
        assert!(
            codes.contains(&"proof.verify.content.evidence"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !codes.contains(&"proof.verify.artifact.digest")
                && !codes.contains(&"proof.verify.release.signature"),
            "the historical v2 predicate was re-signed and readdressed: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn predicate_uri_must_match_the_predicate_and_release_versions() {
    for control in [SignatureMode::Valid, SignatureMode::RollbackRelease] {
        let fixture = generate(OpeningMode::Withhold, control);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(
            report.outcome,
            Outcome::Complete,
            "{control:?}: {report:#?}"
        );
        assert!(report.findings.is_empty(), "{control:?}: {report:#?}");
    }

    for mode in [
        SignatureMode::HistoricalV1PredicateTypeV2,
        SignatureMode::HistoricalV2PredicateTypeV1,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let accepted = fixture.trust_value()["release"]["accepted_predicate_types"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(accepted.len(), 2, "the mismatch URI must remain trusted");
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        let codes = finding_codes(&report);
        assert!(
            codes.contains(&"proof.verify.release.statement_profile"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !codes.contains(&"proof.verify.artifact.digest")
                && !codes.contains(&"proof.verify.release.signature"),
            "the mismatched statement was re-signed and readdressed: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn uncompanioned_historical_v2_approval_evidence_never_authorizes_a_release() {
    let direct = generate(
        OpeningMode::Withhold,
        SignatureMode::HistoricalV2DirectHumanNoCompanion,
    );
    let direct_manifest = artifact_value(&direct, direct.promotion_release_manifest);
    assert_eq!(
        direct_manifest["api_version"],
        Value::String("proof.dev/release/v2".to_owned())
    );
    let direct_policy = artifact_value(
        &direct,
        ArtifactRef {
            artifact_kind: ArtifactKind::AuthorizationDecisionV1,
            digest: serde_json::from_value(
                direct_manifest["authorization_decision_digest"].clone(),
            )
            .unwrap(),
        },
    );
    assert_eq!(
        direct_manifest["principal_id"], direct_policy["operating_principal_id"],
        "the historical v2 release is governed directly by its Human producer"
    );
    assert!(
        decision_companion_for_effect(&direct, direct.promotion_release_manifest).is_none(),
        "the historical direct-Human release must not fabricate a newer authority companion"
    );
    let report = verify(&direct, Some(&direct.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Incomplete, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.content.approval"),
        "{report:#?}"
    );
    assert!(
        report
            .dimensions
            .values()
            .all(|status| *status != DimensionStatus::Invalid),
        "absence of Agent-governed P5 evidence is unsupported, not contradictory: {report:#?}"
    );

    let fixture = generate(
        OpeningMode::Withhold,
        SignatureMode::OrphanHistoricalV2ApprovalEvidence,
    );
    let bundle = fixture.bundle_value();
    let promotion_effect = serde_json::to_value(fixture.promotion_release_manifest).unwrap();
    assert!(
        bundle["authority_prefix"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.get("decision_companion"))
            .all(|companion| companion.get("application_effect") != Some(&promotion_effect)),
        "the historical promotion must not have a signed Allow companion"
    );
    let descriptors = bundle["artifacts"].as_array().unwrap();
    let orphan_consequences = descriptors
        .iter()
        .filter(|descriptor| descriptor["role"] == "localized_consequence")
        .filter(|descriptor| {
            let reference: ArtifactRef =
                serde_json::from_value(descriptor["artifact"].clone()).unwrap();
            let consequence: Value =
                serde_json::from_slice(&fs::read(fixture.artifact_path(reference)).unwrap())
                    .unwrap();
            consequence["application_effect_digest"]
                == serde_json::to_value(fixture.promotion_release_manifest.digest).unwrap()
        })
        .count();
    assert_eq!(orphan_consequences, 1);
    assert!(
        descriptors
            .iter()
            .any(|descriptor| descriptor["role"] == "submission")
            && descriptors
                .iter()
                .any(|descriptor| descriptor["role"] == "approval")
    );
    let report = verify(&fixture, Some(&fixture.checkpoint_json));
    assert_ne!(report.outcome, Outcome::Complete, "{report:#?}");
    let codes = finding_codes(&report);
    match report.outcome {
        Outcome::Invalid => assert!(
            codes.contains(&"proof.verify.content.approval"),
            "{report:#?}"
        ),
        Outcome::Incomplete => assert!(
            report
                .dimensions
                .values()
                .all(|status| *status != DimensionStatus::Invalid),
            "{report:#?}"
        ),
        Outcome::Complete => unreachable!(),
    }
    assert!(
        !codes.contains(&"proof.verify.artifact.digest")
            && !codes.contains(&"proof.verify.release.signature"),
        "the canonical orphan artifacts must reach the signed-companion semantic check: {report:#?}"
    );
}

#[test]
fn historical_v2_release_result_proof_metadata_is_cross_linked() {
    let control = generate(OpeningMode::Withhold, SignatureMode::RollbackRelease);
    let report = verify(&control, Some(&control.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");

    for mode in [
        SignatureMode::HistoricalV2ResultProofMetadataMismatch,
        SignatureMode::HistoricalV2ResultProofIdMismatch,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        assert_ne!(
            fixture.promotion_release_proof, fixture.target_release_proof,
            "the mutation must target a historical v2 release"
        );
        let manifest = artifact_value(&fixture, fixture.promotion_release_manifest);
        let companion = decision_companion_for_effect(&fixture, fixture.promotion_release_manifest)
            .expect("the historical v2 release must retain its signed companion");
        let result_ref: ArtifactRef = serde_json::from_value(companion["result"].clone()).unwrap();
        let result = artifact_value(&fixture, result_ref);
        let proof_digest_matches = result["proof_envelope_digest"]
            == serde_json::to_value(fixture.promotion_release_proof.digest).unwrap();
        let proof_id_matches = result["proof_id"] == manifest["proof_id"];
        match mode {
            SignatureMode::HistoricalV2ResultProofMetadataMismatch => {
                assert!(!proof_digest_matches && proof_id_matches);
            }
            SignatureMode::HistoricalV2ResultProofIdMismatch => {
                assert!(proof_digest_matches && !proof_id_matches);
            }
            _ => unreachable!(),
        }

        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        let codes = finding_codes(&report);
        assert!(
            codes.contains(&"proof.verify.content.approval"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !codes.contains(&"proof.verify.artifact.digest")
                && !codes.contains(&"proof.verify.release.signature"),
            "the canonical companion must reach result-metadata verification: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn release_and_authorization_timestamps_follow_their_distinct_contracts() {
    let distinct = generate(
        OpeningMode::Withhold,
        SignatureMode::HistoricalV2DistinctAuthorizationTime,
    );
    let manifest = artifact_value(&distinct, distinct.promotion_release_manifest);
    let authorization = distinct
        .authority_payload_for_effect(distinct.promotion_release_manifest)
        .unwrap();
    assert_ne!(authorization["evaluated_at"], manifest["released_at"]);
    let report = verify(&distinct, Some(&distinct.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");

    let early = generate(
        OpeningMode::Withhold,
        SignatureMode::V2ReleaseBeforeEditionCreatedAt,
    );
    let manifest = artifact_value(&early, early.target_release_manifest);
    let edition_ref = ArtifactRef {
        artifact_kind: ArtifactKind::EditionV2,
        digest: serde_json::from_value(manifest["edition"]["digest"].clone()).unwrap(),
    };
    let edition = artifact_value(&early, edition_ref);
    assert!(manifest["released_at"].as_str() < edition["created_at"].as_str());
    let report = verify(&early, Some(&early.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.content.reference_artifacts"),
        "{report:#?}"
    );
    assert!(
        !finding_codes(&report).contains(&"proof.verify.artifact.digest")
            && !finding_codes(&report).contains(&"proof.verify.release.signature"),
        "the re-signed chronology mutation must reach semantic verification: {report:#?}"
    );
}

#[test]
fn approval_may_come_from_a_distinct_enabled_human_but_not_an_inactive_or_non_human() {
    let distinct = generate(OpeningMode::Withhold, SignatureMode::DistinctHumanApprover);
    let manifest = artifact_value(&distinct, distinct.target_release_manifest);
    let companion = decision_companion_for_effect(&distinct, distinct.target_release_manifest)
        .expect("the target release must have a signed authority companion");
    let consequence_ref: ArtifactRef =
        serde_json::from_value(companion["localized_consequence"].clone()).unwrap();
    let consequence = artifact_value(&distinct, consequence_ref);
    assert_ne!(
        manifest["principal_id"], consequence["closure"]["approval"]["principal_id"],
        "the control must exercise a genuinely separate Human approval identity"
    );
    let approval_principal = consequence["closure"]["approval"]["principal_id"]
        .as_str()
        .unwrap();
    let approval_status = distinct
        .authority_payloads()
        .into_iter()
        .filter(|payload| {
            payload["api_version"] == "proof.dev/principal-status/v1"
                && payload["principal_id"] == approval_principal
        })
        .max_by_key(|payload| payload["authority_sequence"].as_u64().unwrap())
        .unwrap();
    assert_eq!(approval_status["enabled"], Value::Bool(true));
    assert_eq!(approval_status["principal_type"], "human");
    assert!(
        approval_status["recorded_at"].as_str().unwrap()
            <= consequence["closure"]["approval"]["approved_at"]
                .as_str()
                .unwrap()
    );
    let report = verify(&distinct, Some(&distinct.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");

    for mode in [
        SignatureMode::DisabledHumanApprover,
        SignatureMode::LateEnabledHumanApprover,
        SignatureMode::NonHumanApprover,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.content.approval"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn non_genesis_v1_history_requires_constructive_transition_evidence() {
    let root = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let origin = artifact_value(&root, root.base_release_origin_state);
    assert_eq!(origin["authoritative_sequence"], Value::from(0));
    assert!(origin.get("objects").is_none() && origin.get("schemas").is_none());
    let root_manifest = artifact_value(&root, root.base_release_manifest);
    let root_policy = artifact_value(
        &root,
        ArtifactRef {
            artifact_kind: ArtifactKind::AuthorizationDecisionV1,
            digest: serde_json::from_value(root_manifest["authorization_decision_digest"].clone())
                .unwrap(),
        },
    );
    let root_changeset = artifact_value(
        &root,
        ArtifactRef {
            artifact_kind: ArtifactKind::ChangeSetV1,
            digest: serde_json::from_value(root_policy["evidence"][0]["changeset_digest"].clone())
                .unwrap(),
        },
    );
    assert_eq!(root_manifest["release_sequence"], Value::from(1));
    assert_eq!(root_changeset["edits"][0]["ordinal"], Value::from(1));
    assert_eq!(root_changeset["edits"][1]["ordinal"], Value::from(2));
    assert_eq!(
        root_changeset["principal_id"], root_policy["evidence"][0]["approval"]["principal_id"],
        "legacy v1 approval identity must equal the ChangeSet principal"
    );
    let report = verify(&root, Some(&root.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");

    let constructive = generate(
        OpeningMode::Withhold,
        SignatureMode::NonGenesisV1Constructive,
    );
    let manifest: Value = serde_json::from_slice(
        &fs::read(constructive.artifact_path(constructive.base_release_manifest)).unwrap(),
    )
    .unwrap();
    let decision_digest: Digest =
        serde_json::from_value(manifest["authorization_decision_digest"].clone()).unwrap();
    let decision_ref = ArtifactRef {
        artifact_kind: ArtifactKind::AuthorizationDecisionV1,
        digest: decision_digest,
    };
    let policy: Value =
        serde_json::from_slice(&fs::read(constructive.artifact_path(decision_ref)).unwrap())
            .unwrap();
    assert_eq!(manifest["release_sequence"], Value::from(2));
    assert_eq!(
        policy["evidence"][0]["authoritative_sequence"],
        Value::from(2)
    );
    assert_eq!(
        policy["operating_principal_id"], policy["evidence"][0]["approval"]["principal_id"],
        "the compact fixture uses one legacy Human across ChangeSet, approval, and Release"
    );
    let report = verify(&constructive, Some(&constructive.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Complete, "{report:#?}");
    assert!(report.findings.is_empty(), "{report:#?}");

    let fabricated = generate(
        OpeningMode::Withhold,
        SignatureMode::NonGenesisV1FabricatedEvidence,
    );
    let report = verify(&fabricated, Some(&fabricated.checkpoint_json));
    assert_ne!(
        report.outcome,
        Outcome::Complete,
        "fabricated signed strings and an arbitrary base state must never authorize history: {report:#?}"
    );
    let codes = finding_codes(&report);
    assert!(
        codes.contains(&"proof.verify.content.references"),
        "{report:#?}"
    );
    assert!(
        !codes.contains(&"proof.verify.artifact.digest")
            && !codes.contains(&"proof.verify.release.signature"),
        "the internally re-signed v1 predicate must fail constructively: {report:#?}"
    );

    for mode in [
        SignatureMode::NonGenesisV1SequenceGap,
        SignatureMode::NonGenesisV1ApprovalPrincipalMismatch,
        SignatureMode::NonGenesisV1ZeroBasedOrdinals,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.content.references"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "the signed v1 incompatibility must reach constructive verification: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn v1_edition_shape_and_independent_validation_are_enforced() {
    for mode in [
        SignatureMode::V1EditionUnknownField,
        SignatureMode::V1EditionMissingSchemas,
        SignatureMode::V1EditionMissingObjectSetDigest,
        SignatureMode::V1EditionEmptyObjectsWithDigest,
        SignatureMode::V1InvalidSchemaDocument,
        SignatureMode::V1ObjectSchemaMismatch,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.content.references"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "the readdressed v1 producer artifacts must reach semantic verification: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn release_policy_environment_and_policy_bundle_shapes_are_closed() {
    for mode in [
        SignatureMode::V1PolicyDecisionUnknownField,
        SignatureMode::V2PolicyDecisionUnknownField,
        SignatureMode::EnvironmentUnknownField,
        SignatureMode::EnvironmentPolicyUnknownField,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "the readdressed policy mutation must reach semantic verification: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn recursive_release_closure_has_one_proof_for_every_reachable_release() {
    for (mode, expected_releases) in [
        (SignatureMode::Valid, 2_usize),
        (SignatureMode::RollbackRelease, 3_usize),
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let bundle = fixture.bundle_value();
        let descriptors = bundle["artifacts"].as_array().unwrap();
        let manifests = descriptors
            .iter()
            .filter(|descriptor| descriptor["role"] == "release_manifest")
            .map(|descriptor| {
                serde_json::from_value::<ArtifactRef>(descriptor["artifact"].clone()).unwrap()
            })
            .collect::<BTreeSet<_>>();
        let proofs = descriptors
            .iter()
            .filter(|descriptor| descriptor["role"] == "release_proof_envelope")
            .map(|descriptor| {
                serde_json::from_value::<ArtifactRef>(descriptor["artifact"].clone()).unwrap()
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(manifests.len(), expected_releases, "{mode:?}");
        assert_eq!(proofs.len(), expected_releases, "{mode:?}");
        assert!(manifests.contains(&fixture.base_release_manifest));
        assert!(proofs.contains(&fixture.base_release_proof));
        assert!(manifests.contains(&fixture.promotion_release_manifest));
        assert!(proofs.contains(&fixture.promotion_release_proof));
        assert!(manifests.contains(&fixture.target_release_manifest));
        assert!(proofs.contains(&fixture.target_release_proof));

        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Complete, "{mode:?}: {report:#?}");
        assert!(report.findings.is_empty(), "{mode:?}: {report:#?}");
    }
}

#[test]
fn corrupt_or_subject_substituted_historical_proof_is_semantically_invalid() {
    let cases = [
        (
            SignatureMode::CorruptBaseReleaseProof,
            "proof.verify.release.signature",
        ),
        (
            SignatureMode::SubstituteBaseReleaseProofSubject,
            "proof.verify.release.subject",
        ),
        (
            SignatureMode::RollbackCorruptTargetProof,
            "proof.verify.release.signature",
        ),
        (
            SignatureMode::RollbackSubstituteTargetProofSubject,
            "proof.verify.release.subject",
        ),
    ];
    for (mode, expected_code) in cases {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&expected_code),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest"),
            "the corrupt envelope was readdressed and reached semantic verification: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn missing_required_historical_proof_is_incomplete_not_invalid() {
    for mode in [SignatureMode::Valid, SignatureMode::RollbackRelease] {
        let mut fixture = generate(OpeningMode::Withhold, mode);
        let base_proof = fixture.base_release_proof;
        withhold_artifact(&mut fixture, EvidenceRole::ReleaseProofEnvelope, base_proof);

        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Incomplete, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.external.missing"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            report
                .dimensions
                .values()
                .all(|status| *status != DimensionStatus::Invalid),
            "{mode:?}: {report:#?}"
        );
    }

    for mode in [SignatureMode::Valid, SignatureMode::RollbackRelease] {
        let mut predecessor = generate(OpeningMode::Withhold, mode);
        let base_release = predecessor.base_release_manifest;
        withhold_artifact(
            &mut predecessor,
            EvidenceRole::ReleaseManifest,
            base_release,
        );
        let report = verify(&predecessor, Some(&predecessor.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Incomplete, "{mode:?}: {report:#?}");
        assert!(
            report
                .dimensions
                .values()
                .all(|status| *status != DimensionStatus::Invalid),
            "missing predecessor: {mode:?}: {report:#?}"
        );

        let mut key = generate(OpeningMode::Withhold, mode);
        let key_id = release_key_id(&key, key.base_release_manifest);
        let key_reference = release_key_evidence_ref(&key, &key_id);
        withhold_artifact(&mut key, EvidenceRole::ReleaseSigningKey, key_reference);
        let report = verify(&key, Some(&key.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Incomplete, "{mode:?}: {report:#?}");
        assert!(
            report
                .dimensions
                .values()
                .all(|status| *status != DimensionStatus::Invalid),
            "missing historical producer key: {mode:?}: {report:#?}"
        );
    }
}

#[test]
fn duplicate_and_orphan_historical_proof_mappings_are_invalid() {
    for mode in [
        SignatureMode::DuplicateBaseReleaseProof,
        SignatureMode::OrphanReleaseProof,
    ] {
        let fixture = generate(OpeningMode::Withhold, mode);
        let report = verify(&fixture, Some(&fixture.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            finding_codes(&report).contains(&"proof.verify.release.signature")
                || finding_codes(&report).contains(&"proof.verify.release.subject"),
            "{mode:?}: {report:#?}"
        );
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest"),
            "{mode:?}: {report:#?}"
        );
    }
}

#[test]
fn historical_policy_key_time_and_signed_v2_delta_tampering_are_invalid() {
    for mode in [
        SignatureMode::BasePredicateOriginStateTamper,
        SignatureMode::BasePredicateWorkspaceTamper,
    ] {
        let origin = generate(OpeningMode::Withhold, mode);
        let report = verify(&origin, Some(&origin.checkpoint_json));
        assert_eq!(report.outcome, Outcome::Invalid, "{mode:?}: {report:#?}");
        assert!(
            !finding_codes(&report).contains(&"proof.verify.artifact.digest")
                && !finding_codes(&report).contains(&"proof.verify.release.signature"),
            "the historical predicate was re-signed and must reach semantic verification: {mode:?}: {report:#?}"
        );
    }

    let policy = generate(OpeningMode::Withhold, SignatureMode::BasePolicyDenied);
    let report = verify(&policy, Some(&policy.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.release.policy"));

    let mut key_time = generate(OpeningMode::Withhold, SignatureMode::Valid);
    let mut trust = key_time.trust_value();
    let base_manifest: Value = serde_json::from_slice(
        &fs::read(key_time.artifact_path(key_time.base_release_manifest)).unwrap(),
    )
    .unwrap();
    let historical_key_id = base_manifest["key_id"].clone();
    let historical = trust["release"]["trusted_signers"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|key| key["key_id"] == historical_key_id)
        .unwrap();
    historical["revoked_at"] = Value::String("2026-08-21T10:00:00Z".to_owned());
    key_time.replace_trust(&trust);
    let report = verify(&key_time, Some(&key_time.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(finding_codes(&report).contains(&"proof.verify.release.key_time"));

    let delta = generate(
        OpeningMode::Withhold,
        SignatureMode::PromotionDeltaHitchhike,
    );
    let report = verify(&delta, Some(&delta.checkpoint_json));
    assert_eq!(report.outcome, Outcome::Invalid, "{report:#?}");
    assert!(
        finding_codes(&report).contains(&"proof.verify.content.delta_state_mismatch"),
        "{report:#?}"
    );
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
