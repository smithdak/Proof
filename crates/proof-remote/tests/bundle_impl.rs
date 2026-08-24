//! Integration tests for the `proof-remote` bundle module.
//!
//! These exercise the deterministic member-path normalization, the exact
//! uncompressed logical member-map validation (six roots, reserved descriptors,
//! nested artifacts, kind/digest/length equality, and every count/byte limit),
//! included-vs-external selector enumeration, the inert first-profile hints,
//! authority-checkpoint equality/ancestry helpers, and the closed verifier
//! report/primary-reason and conformance-scenario helpers.

use proof_canonical::canonicalize;
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_remote::bundle::{ARTIFACT_ROOT_PREFIX, NestedArtifactSelectorV1, nested_artifact_path};
use proof_remote::{
    AcceptedArtifactAvailabilityV1, AcceptedArtifactDescriptorV1, AcceptedArtifactRefV1,
    AuthorityCheckpointApiVersion, AuthorityCheckpointV1, AuthorityHeadV1, AuthorityTrustV2,
    BUNDLE_DESCRIPTOR_PATH, BundleValidationError, CheckpointRequirement, ConformanceScenario,
    DisclosurePolicyV2, EvidenceHeadsV1, MANIFEST_MEMBER_PATH, MAX_ARTIFACT_BYTES,
    MAX_BUNDLE_DESCRIPTOR_BYTES, MAX_MANIFEST_BYTES, MAX_NESTED_ARTIFACT_BODIES,
    RegistryResolutionFailure, RegistryResolutionV1, ReleaseTrustV2,
    RemoteAuthorityRecordSetApiVersion, RemoteAuthorityRecordSetV1,
    RemoteEvidenceArtifactClosureBindingV1, RemoteEvidenceAttemptCompanionsBindingV1,
    RemoteEvidenceAuthorityBindingV1, RemoteEvidenceCanonicalization,
    RemoteEvidenceClosureBindingsApiVersion, RemoteEvidenceClosureBindingsV1,
    RemoteEvidenceComponentBindingV1, RemoteEvidenceCrossLinksV1, RemoteEvidenceDelivery,
    RemoteEvidenceDisclosureKind, RemoteEvidenceDisclosureProfile,
    RemoteEvidenceDisclosureRequirementV1, RemoteEvidenceManifestApiVersion,
    RemoteEvidenceManifestType, RemoteEvidenceManifestV2, RemoteEvidenceMemberMap,
    RemoteEvidenceMemberV1, RemoteEvidenceRootKind, RemoteIdentityTrustV2, RemoteOperationV1,
    RemoteReleaseArtifactClosureApiVersion, RemoteReleaseArtifactClosureEntrypointsV1,
    RemoteReleaseArtifactClosureV1, RemoteVerificationConformanceReportV2,
    RemoteVerificationReportV2, RemoteVerifierInputApiVersion, RemoteVerifierInputType,
    RemoteVerifierInputV2, RequestingSubjectOpeningPolicy, TrustedKeyV2, UntrustedHintsV1,
    VerificationComponentResult, VerificationComponentResultsV2, VerificationLimitsV2,
    VerificationReasonCode, VerificationScenario, VerificationStatus,
    VerificationTrustPolicyApiVersion, VerificationTrustPolicyV2, derive_key_digest,
    normalize_member_path, validate_bundle_members,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Fixture helpers.
// ---------------------------------------------------------------------------

fn cd(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

/// Distinct digest derived from a `usize` seed (for large descriptor sets).
fn digest_from(seed: usize) -> ContentDigest {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&(seed as u64).to_be_bytes());
    ContentDigest::blake3(bytes)
}

fn ts() -> Timestamp {
    "2026-08-23T01:00:00Z".parse().unwrap()
}

fn canonical_body(value: &serde_json::Value) -> Vec<u8> {
    canonicalize(value).unwrap().as_bytes().to_vec()
}

/// The frozen BLAKE3-256 derive-key context for each root kind.
fn root_context(kind: RemoteEvidenceRootKind) -> &'static str {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => {
            "proof:remote-release-artifact-closure:v1"
        }
        RemoteEvidenceRootKind::AuthorityFact => "proof:remote-authority-record-set:v1",
        RemoteEvidenceRootKind::RemoteActorEvidence => {
            "proof:authenticated-actor-context-evidence:v2"
        }
        RemoteEvidenceRootKind::RemoteAuthenticationEvent => "proof:remote-authentication-event:v1",
        RemoteEvidenceRootKind::RemoteCommandInput => "proof:command:v1",
        RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope => {
            "proof:authenticated-command-envelope:v1"
        }
    }
}

/// The frozen digest context for a nested accepted artifact kind.
fn nested_context(artifact_kind: &str) -> &'static str {
    if artifact_kind == "environment_config_v2_projection" {
        "proof:environment-config:v2"
    } else {
        ArtifactKind::from_wire_name(artifact_kind)
            .expect("known accepted artifact kind")
            .derive_key_context()
    }
}

fn root_member(
    kind: RemoteEvidenceRootKind,
    delivery: RemoteEvidenceDelivery,
    body: &[u8],
    disclosure_id: Option<String>,
) -> RemoteEvidenceMemberV1 {
    let context = root_context(kind);
    RemoteEvidenceMemberV1 {
        member_path: kind.member_path().to_owned(),
        artifact_kind: kind,
        schema_id: "proof.remote-evidence-member/v1".to_owned(),
        schema_version: 1,
        media_type: "application/json".to_owned(),
        canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
        digest_context: context.to_owned(),
        byte_length: body.len() as u64,
        content_digest: derive_key_digest(context, body),
        delivery,
        disclosure_id,
    }
}

fn nested_descriptor(
    artifact_kind: &str,
    digest: ContentDigest,
    byte_length: u64,
) -> AcceptedArtifactDescriptorV1 {
    AcceptedArtifactDescriptorV1 {
        artifact: AcceptedArtifactRefV1 {
            artifact_kind: artifact_kind.to_owned(),
            digest,
        },
        availability: AcceptedArtifactAvailabilityV1 {
            state: "included".to_owned(),
            byte_length,
        },
    }
}

fn component_binding(member_path: &str) -> RemoteEvidenceComponentBindingV1 {
    RemoteEvidenceComponentBindingV1 {
        member_path: member_path.to_owned(),
        record_digest: cd(0x10),
        digest_context: "proof:command:v1".to_owned(),
        schema_id: "proof.command-input/v1".to_owned(),
        schema_version: 1,
    }
}

fn closure_bindings() -> RemoteEvidenceClosureBindingsV1 {
    RemoteEvidenceClosureBindingsV1 {
        api_version: RemoteEvidenceClosureBindingsApiVersion::Tag,
        artifact_closure: RemoteEvidenceArtifactClosureBindingV1 {
            api_version: "proof.dev/remote-release-artifact-closure/v1".to_owned(),
            manifest_member_path: "content/release-closure.json".to_owned(),
            manifest_digest: cd(0x20),
            digest_context: "proof:remote-release-artifact-closure:v1".to_owned(),
            artifact_root_prefix: "content/artifacts/".to_owned(),
            verification_profile: "proof-verifier/accepted-release-artifact-semantics-v1"
                .to_owned(),
            authority_entrypoint:
                "none; remote authority is verified only through closure_bindings.remote_authority"
                    .to_owned(),
        },
        cross_links: RemoteEvidenceCrossLinksV1 {
            workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
            requesting_principal_id: "019e0000-0000-7000-8000-000000000002".to_owned(),
            operating_principal_id: "019e0000-0000-7000-8000-000000000003".to_owned(),
            delegation_id: "019e0000-0000-7000-8000-000000000004".to_owned(),
            presentation_id: "019e0000-0000-7000-8000-000000000005".to_owned(),
            command_digest: cd(0x30),
            authenticated_command_envelope_digest: cd(0x31),
            public_input_projection_digest: cd(0x32),
            operation: RemoteOperationV1 {
                name: "release.create".to_owned(),
                version: "proof.dev/operation/release.create/v2".to_owned(),
            },
            application_key_kind: "required-uuidv7".to_owned(),
            application_key: "019e0000-0000-7000-8000-000000000006".to_owned(),
            environment_config_digest: cd(0x33),
            environment_config_version: 2,
            release_id: "019e0000-0000-7000-8000-000000000007".to_owned(),
            release_digest: cd(0x34),
            release_policy_decision_digest: cd(0x35),
            release_proof_envelope_digest: cd(0x36),
            result_digest: cd(0x37),
            application_effect_digest: cd(0x38),
        },
        remote_authority: RemoteEvidenceAuthorityBindingV1 {
            record_set_member_path: "authority/facts.json".to_owned(),
            record_set_digest: cd(0x40),
            digest_context: "proof:remote-authority-record-set:v1".to_owned(),
            head: AuthorityHeadV1 {
                sequence: 1,
                record_digest: cd(0x41),
            },
            target_decision_digest: cd(0x42),
            target_consequence_digest: cd(0x43),
            verifier_profile: "proof-verifier/remote-authority/v1".to_owned(),
        },
        remote_attempt_companions: RemoteEvidenceAttemptCompanionsBindingV1 {
            profile: "agent-release-create-v2-success".to_owned(),
            actor_context_evidence: component_binding("actor/context-evidence.json"),
            authentication_event: component_binding("authentication/event.json"),
            command_input: component_binding("attempt/command-input.json"),
            authenticated_command_envelope: component_binding(
                "attempt/authenticated-command-envelope.json",
            ),
            public_input_projection_rule: "reconstruct public projection".to_owned(),
            result_rule: "reconstruct result".to_owned(),
            application_effect_rule: "application effect equals target ReleaseV2".to_owned(),
        },
    }
}

fn manifest(
    membership: Vec<RemoteEvidenceMemberV1>,
    disclosures: Vec<RemoteEvidenceDisclosureRequirementV1>,
    profile: RemoteEvidenceDisclosureProfile,
) -> RemoteEvidenceManifestV2 {
    RemoteEvidenceManifestV2 {
        r#type: RemoteEvidenceManifestType::Tag,
        api_version: RemoteEvidenceManifestApiVersion::Tag,
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        export_id: "019e0000-0000-7000-8000-000000000009".to_owned(),
        snapshot_id: "snapshot_00000000000000000000000000000000".to_owned(),
        snapshot_boundary: "pre-export-attempt-locked-heads".to_owned(),
        capture_digest: cd(0x50),
        release_id: "019e0000-0000-7000-8000-000000000007".to_owned(),
        release_digest: cd(0x34),
        closure_bindings: closure_bindings(),
        disclosure_profile: profile,
        heads: EvidenceHeadsV1 {
            authority: cd(0x51),
            content: cd(0x52),
            release: cd(0x53),
            environment: cd(0x54),
            outbox: cd(0x55),
        },
        membership_order: "member_path UTF-8 bytewise ascending".to_owned(),
        membership,
        disclosure_order: "disclosure_id UTF-8 bytewise ascending".to_owned(),
        disclosures,
    }
}

fn closure(artifacts: Vec<AcceptedArtifactDescriptorV1>) -> RemoteReleaseArtifactClosureV1 {
    RemoteReleaseArtifactClosureV1 {
        api_version: RemoteReleaseArtifactClosureApiVersion::Tag,
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        artifact_order: "artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        artifacts,
        role_binding_order: "role, artifact_kind, digest UTF-8 bytewise ascending".to_owned(),
        role_bindings: Vec::new(),
        entrypoints: RemoteReleaseArtifactClosureEntrypointsV1 {
            target_release_manifest: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: cd(0x60),
            },
            target_release_proof_envelope: AcceptedArtifactRefV1 {
                artifact_kind: "proof_envelope_v1".to_owned(),
                digest: cd(0x61),
            },
            target_environment_config: AcceptedArtifactRefV1 {
                artifact_kind: "environment_config_v2_projection".to_owned(),
                digest: cd(0x62),
            },
            application_effect: AcceptedArtifactRefV1 {
                artifact_kind: "release_v2".to_owned(),
                digest: cd(0x60),
            },
            result_derivation:
                "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest"
                    .to_owned(),
        },
    }
}

/// The six root kinds in stable declaration order.
const ROOT_KINDS: [RemoteEvidenceRootKind; 6] = [
    RemoteEvidenceRootKind::ReleaseArtifactClosure,
    RemoteEvidenceRootKind::AuthorityFact,
    RemoteEvidenceRootKind::RemoteActorEvidence,
    RemoteEvidenceRootKind::RemoteAuthenticationEvent,
    RemoteEvidenceRootKind::RemoteCommandInput,
    RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope,
];

/// Builds a complete-portable fixture: all six roots included, two nested
/// `object_locale_revision_v1` artifacts, and the reserved descriptors.
fn complete_portable() -> (
    RemoteEvidenceMemberMap,
    RemoteEvidenceManifestV2,
    RemoteReleaseArtifactClosureV1,
) {
    let mut members = RemoteEvidenceMemberMap::new();
    let mut membership = Vec::new();

    members.insert(BUNDLE_DESCRIPTOR_PATH.to_owned(), b"{}".to_vec());
    members.insert(MANIFEST_MEMBER_PATH.to_owned(), b"{}".to_vec());

    for (index, kind) in ROOT_KINDS.iter().copied().enumerate() {
        let body = canonical_body(&json!({ "root": index }));
        membership.push(root_member(
            kind,
            RemoteEvidenceDelivery::Included,
            &body,
            None,
        ));
        members.insert(kind.member_path().to_owned(), body);
    }

    let nested_kind = "object_locale_revision_v1";
    let nested1 = canonical_body(&json!({ "nested": 1 }));
    let nested2 = canonical_body(&json!({ "nested": 2 }));
    let digest1 = derive_key_digest(nested_context(nested_kind), &nested1);
    let digest2 = derive_key_digest(nested_context(nested_kind), &nested2);
    let artifacts = vec![
        nested_descriptor(nested_kind, digest1, nested1.len() as u64),
        nested_descriptor(nested_kind, digest2, nested2.len() as u64),
    ];
    members.insert(nested_artifact_path(nested_kind, &digest1), nested1);
    members.insert(nested_artifact_path(nested_kind, &digest2), nested2);

    let manifest = manifest(
        membership,
        Vec::new(),
        RemoteEvidenceDisclosureProfile::CompletePortable,
    );
    let closure = closure(artifacts);

    (members, manifest, closure)
}

/// Builds an explicit-external-artifacts fixture: the authority, actor, and
/// authentication roots are external-required (absent) while the closure,
/// command, and envelope roots are included.
fn external_required() -> (
    RemoteEvidenceMemberMap,
    RemoteEvidenceManifestV2,
    RemoteReleaseArtifactClosureV1,
) {
    let mut members = RemoteEvidenceMemberMap::new();
    let mut membership = Vec::new();
    let mut disclosures = Vec::new();

    members.insert(BUNDLE_DESCRIPTOR_PATH.to_owned(), b"{}".to_vec());
    members.insert(MANIFEST_MEMBER_PATH.to_owned(), b"{}".to_vec());

    for (index, kind) in ROOT_KINDS.iter().copied().enumerate() {
        if kind.can_be_external_required() {
            let disclosure_id = format!("disclosure:{index}");
            let body = canonical_body(&json!({ "external": index }));
            membership.push(root_member(
                kind,
                RemoteEvidenceDelivery::ExternalRequired,
                &body,
                Some(disclosure_id.clone()),
            ));
            disclosures.push(RemoteEvidenceDisclosureRequirementV1 {
                disclosure_id,
                kind: RemoteEvidenceDisclosureKind::ArtifactBytes,
                commitment_digest: derive_key_digest(root_context(kind), &body),
            });
        } else {
            let body = canonical_body(&json!({ "root": index }));
            membership.push(root_member(
                kind,
                RemoteEvidenceDelivery::Included,
                &body,
                None,
            ));
            members.insert(kind.member_path().to_owned(), body);
        }
    }

    let manifest = manifest(
        membership,
        disclosures,
        RemoteEvidenceDisclosureProfile::ExplicitExternalArtifacts,
    );
    let closure = closure(Vec::new());

    (members, manifest, closure)
}

// ---------------------------------------------------------------------------
// Path normalization.
// ---------------------------------------------------------------------------

#[test]
fn normalize_rejects_absolute_dot_segment_and_backslash() {
    assert_eq!(
        normalize_member_path("/absolute/path.json"),
        Err(BundleValidationError::AbsolutePath(
            "/absolute/path.json".to_owned()
        ))
    );
    assert_eq!(
        normalize_member_path("a\\b.json"),
        Err(BundleValidationError::Backslash("a\\b.json".to_owned()))
    );
    for dot in ["..", ".", "a/../b.json", "a/./b.json", "a/..", "a/."] {
        assert_eq!(
            normalize_member_path(dot),
            Err(BundleValidationError::DotSegment(dot.to_owned())),
            "dot-segment path `{dot}` must be rejected"
        );
    }
}

#[test]
fn normalize_accepts_deterministic_utf8_paths() {
    assert_eq!(normalize_member_path("bundle.json").unwrap(), "bundle.json");
    assert_eq!(
        normalize_member_path("content/release-closure.json").unwrap(),
        "content/release-closure.json"
    );
    assert_eq!(
        normalize_member_path("content/artifacts/object_locale_revision_v1/blake3/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.json").unwrap(),
        "content/artifacts/object_locale_revision_v1/blake3/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.json"
    );
}

// ---------------------------------------------------------------------------
// Valid member maps.
// ---------------------------------------------------------------------------

#[test]
fn validate_accepts_complete_portable_map() {
    let (members, manifest, closure) = complete_portable();
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Ok(())
    );
}

#[test]
fn validate_accepts_external_required_map() {
    let (members, manifest, closure) = external_required();
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Ok(())
    );

    // The three external-required roots are absent from the map while the three
    // included roots are present.
    for member in &manifest.membership {
        let present = members.contains_key(&member.member_path);
        assert_eq!(
            present,
            member.delivery == RemoteEvidenceDelivery::Included,
            "root `{}` presence must follow its delivery",
            member.member_path
        );
    }
}

// ---------------------------------------------------------------------------
// Rejection classes.
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_absolute_declared_path() {
    let (members, mut manifest, closure) = complete_portable();
    let body = canonical_body(&json!({ "root": 0 }));
    let mut bad = root_member(
        RemoteEvidenceRootKind::AuthorityFact,
        RemoteEvidenceDelivery::Included,
        &body,
        None,
    );
    bad.member_path = "/authority/facts.json".to_owned();
    manifest.membership[1] = bad;
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::AbsolutePath(
            "/authority/facts.json".to_owned()
        ))
    );
}

#[test]
fn validate_rejects_duplicate_normalized_path() {
    // Two nested descriptors with the same kind and digest map to one path.
    let (members, manifest, _) = complete_portable();
    let kind = "object_locale_revision_v1";
    let digest = digest_from(7);
    let artifacts = vec![
        nested_descriptor(kind, digest, 1),
        nested_descriptor(kind, digest, 2),
    ];
    let dup = closure(artifacts);
    let path = nested_artifact_path(kind, &digest);
    assert_eq!(
        validate_bundle_members(&members, &manifest, &dup),
        Err(BundleValidationError::DuplicatePath(path))
    );
}

#[test]
fn validate_rejects_undeclared_entry() {
    let (mut members, manifest, closure) = complete_portable();
    members.insert("extra/undeclared.json".to_owned(), b"{}".to_vec());
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::UndeclaredEntry(
            "extra/undeclared.json".to_owned()
        ))
    );
}

#[test]
fn validate_rejects_missing_entry() {
    let (mut members, manifest, closure) = complete_portable();
    members.remove(RemoteEvidenceRootKind::AuthorityFact.member_path());
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::MissingEntry(
            "authority/facts.json".to_owned()
        ))
    );
}

#[test]
fn validate_rejects_kind_mismatch() {
    let (members, mut manifest, closure) = complete_portable();
    let body = canonical_body(&json!({ "root": 0 }));
    let mut bad = root_member(
        RemoteEvidenceRootKind::RemoteActorEvidence,
        RemoteEvidenceDelivery::Included,
        &body,
        None,
    );
    // Declared kind is remote-actor-evidence but the path is the frozen
    // authority-fact path.
    bad.member_path = "authority/facts.json".to_owned();
    manifest.membership[1] = bad;
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::KindMismatch(
            "authority/facts.json".to_owned()
        ))
    );
}

#[test]
fn validate_rejects_digest_mismatch() {
    let (members, mut manifest, closure) = complete_portable();
    // Corrupt the declared digest of the command-input root while keeping its
    // declared length correct.
    let index = manifest
        .membership
        .iter()
        .position(|m| m.artifact_kind == RemoteEvidenceRootKind::RemoteCommandInput)
        .unwrap();
    manifest.membership[index].content_digest = cd(0xFF);
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::DigestMismatch(
            "attempt/command-input.json".to_owned()
        ))
    );
}

#[test]
fn validate_rejects_length_mismatch() {
    let (members, mut manifest, closure) = complete_portable();
    let index = manifest
        .membership
        .iter()
        .position(|m| m.artifact_kind == RemoteEvidenceRootKind::RemoteCommandInput)
        .unwrap();
    manifest.membership[index].byte_length += 1;
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::LengthMismatch(
            "attempt/command-input.json".to_owned()
        ))
    );
}

// ---------------------------------------------------------------------------
// Count and byte limits.
// ---------------------------------------------------------------------------

#[test]
fn validate_rejects_4097th_artifact() {
    // 4,091 nested descriptors (the 4,097th body counting the six roots).
    let (_, manifest, _) = complete_portable();
    let artifacts = (0..=MAX_NESTED_ARTIFACT_BODIES)
        .map(|seed| nested_descriptor("object_locale_revision_v1", digest_from(seed), 1))
        .collect();
    let over = closure(artifacts);
    assert_eq!(
        validate_bundle_members(&RemoteEvidenceMemberMap::new(), &manifest, &over),
        Err(BundleValidationError::CountViolation)
    );
}

#[test]
fn validate_rejects_oversized_manifest() {
    let (mut members, manifest, closure) = complete_portable();
    members.insert(
        MANIFEST_MEMBER_PATH.to_owned(),
        vec![b'x'; MAX_MANIFEST_BYTES + 1],
    );
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::ByteViolation)
    );
}

#[test]
fn validate_rejects_oversized_artifact() {
    let (mut members, manifest, closure) = complete_portable();
    members.insert(
        RemoteEvidenceRootKind::AuthorityFact
            .member_path()
            .to_owned(),
        vec![b'x'; MAX_ARTIFACT_BYTES + 1],
    );
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::ByteViolation)
    );
}

#[test]
fn validate_rejects_oversized_descriptor() {
    let (mut members, manifest, closure) = complete_portable();
    members.insert(
        BUNDLE_DESCRIPTOR_PATH.to_owned(),
        vec![b'{'; MAX_BUNDLE_DESCRIPTOR_BYTES + 1],
    );
    assert_eq!(
        validate_bundle_members(&members, &manifest, &closure),
        Err(BundleValidationError::ByteViolation)
    );
}

#[test]
fn validate_rejects_oversized_total() {
    // 65 nested bodies at the exact per-body ceiling exceed the total ceiling.
    let nested_kind = "object_locale_revision_v1";
    let mut members = RemoteEvidenceMemberMap::new();
    let mut artifacts = Vec::new();

    members.insert(BUNDLE_DESCRIPTOR_PATH.to_owned(), b"{}".to_vec());
    members.insert(MANIFEST_MEMBER_PATH.to_owned(), b"{}".to_vec());

    let body = vec![0_u8; MAX_ARTIFACT_BYTES];
    for seed in 0..65_usize {
        let digest = digest_from(seed);
        artifacts.push(nested_descriptor(nested_kind, digest, body.len() as u64));
        members.insert(nested_artifact_path(nested_kind, &digest), body.clone());
    }

    let (_, manifest, _) = complete_portable();
    let over = closure(artifacts);
    assert_eq!(
        validate_bundle_members(&members, &manifest, &over),
        Err(BundleValidationError::ByteViolation)
    );
    // 64 * MAX_ARTIFACT_BYTES == MAX_TOTAL_BYTES exactly, so 65 bodies exceed it.
}

// ---------------------------------------------------------------------------
// Selector enumeration.
// ---------------------------------------------------------------------------

#[test]
fn manifest_enumerates_included_and_external_root_selectors() {
    let (_, manifest, _) = external_required();

    let included: Vec<_> = manifest.included_root_members().collect();
    let external: Vec<_> = manifest.external_required_root_members().collect();

    assert_eq!(included.len(), 3);
    assert_eq!(external.len(), 3);
    assert!(
        included
            .iter()
            .all(|m| m.delivery == RemoteEvidenceDelivery::Included)
    );
    assert!(
        external
            .iter()
            .all(|m| m.delivery == RemoteEvidenceDelivery::ExternalRequired)
    );
    for member in &external {
        assert!(member.artifact_kind.can_be_external_required());
    }
    assert!(
        !external
            .iter()
            .any(|m| m.artifact_kind == RemoteEvidenceRootKind::ReleaseArtifactClosure)
    );
}

#[test]
fn closure_enumerates_deterministic_nested_selectors() {
    let kind = "object_locale_revision_v1";
    let digest = digest_from(9);
    let byte_length = 41;
    let artifacts = vec![nested_descriptor(kind, digest, byte_length)];
    let closure = closure(artifacts);

    let selectors: Vec<NestedArtifactSelectorV1> = closure.nested_selectors();
    assert_eq!(selectors.len(), 1);
    let selector = &selectors[0];
    assert_eq!(selector.member_path, nested_artifact_path(kind, &digest));
    assert_eq!(selector.artifact_kind, kind);
    assert_eq!(selector.digest, digest);
    assert_eq!(selector.byte_length, byte_length);
    assert!(selector.member_path.starts_with(ARTIFACT_ROOT_PREFIX));
}

// ---------------------------------------------------------------------------
// Authority checkpoint helpers.
// ---------------------------------------------------------------------------

fn record_set(
    workspace_id: &str,
    sequence: u64,
    digest: ContentDigest,
) -> RemoteAuthorityRecordSetV1 {
    RemoteAuthorityRecordSetV1 {
        api_version: RemoteAuthorityRecordSetApiVersion::Tag,
        workspace_id: workspace_id.to_owned(),
        base_head: AuthorityHeadV1 {
            sequence: sequence - 1,
            record_digest: cd(0xAB),
        },
        record_order: "decoded authority_sequence ascending and contiguous".to_owned(),
        records: Vec::new(),
        included_head: AuthorityHeadV1 {
            sequence,
            record_digest: digest,
        },
    }
}

fn checkpoint(
    workspace_id: &str,
    sequence: u64,
    digest: ContentDigest,
    key_id: &str,
) -> AuthorityCheckpointV1 {
    AuthorityCheckpointV1 {
        api_version: AuthorityCheckpointApiVersion::Tag,
        workspace_id: workspace_id.to_owned(),
        authority_sequence: sequence,
        authority_record_digest: digest,
        active_authority_key_id: key_id.to_owned(),
        observed_at: ts(),
    }
}

#[test]
fn checkpoint_equality_and_higher_sequence_not_ancestry() {
    let set = record_set("019e0000-0000-7000-8000-000000000001", 5, cd(0xE5));
    let key_id = "ed25519:34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746";

    // Exact equality in Workspace, sequence, digest, and active key.
    let exact = checkpoint("019e0000-0000-7000-8000-000000000001", 5, cd(0xE5), key_id);
    assert!(exact.matches_included_head(&set, key_id));
    assert!(!exact.exceeds_included_head(&set));

    // Any single-field mismatch breaks equality.
    let wrong_workspace = checkpoint("019e0000-0000-7000-8000-0000000000FF", 5, cd(0xE5), key_id);
    assert!(!wrong_workspace.matches_included_head(&set, key_id));
    let wrong_sequence = checkpoint("019e0000-0000-7000-8000-000000000001", 4, cd(0xE5), key_id);
    assert!(!wrong_sequence.matches_included_head(&set, key_id));
    let wrong_digest = checkpoint("019e0000-0000-7000-8000-000000000001", 5, cd(0xE6), key_id);
    assert!(!wrong_digest.matches_included_head(&set, key_id));
    let wrong_key = checkpoint(
        "019e0000-0000-7000-8000-000000000001",
        5,
        cd(0xE5),
        "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    assert!(!wrong_key.matches_included_head(&set, key_id));

    // A higher sequence without the intervening records is not ancestry.
    let higher = checkpoint("019e0000-0000-7000-8000-000000000001", 6, cd(0xE6), key_id);
    assert!(higher.exceeds_included_head(&set));
    assert!(!higher.matches_included_head(&set, key_id));
}

fn trust_policy(key_id: &str) -> VerificationTrustPolicyV2 {
    VerificationTrustPolicyV2 {
        api_version: VerificationTrustPolicyApiVersion::Tag,
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        registry_resolution: RegistryResolutionV1 {
            profile: "proof.verifier/collaboration-registry/v1".to_owned(),
            source: "verifier-built-in-closed-hash-to-rfc8785-document-table".to_owned(),
            unknown_hash_result: RegistryResolutionFailure::Invalid,
            hash_mismatch_result: RegistryResolutionFailure::Invalid,
        },
        authority: AuthorityTrustV2 {
            initial_root: TrustedKeyV2 {
                key_id: key_id.to_owned(),
                public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
                not_before: ts(),
                not_after: None,
                revoked_at: None,
            },
            initial_head: AuthorityHeadV1 {
                sequence: 0,
                record_digest: cd(0x00),
            },
            accepted_authorization_registry_hashes: vec!["00".repeat(32)],
            accepted_operation_registry_hashes: vec!["11".repeat(32)],
            accepted_policy_bundles: Vec::new(),
            checkpoint_requirement: CheckpointRequirement::Required,
            compromise_cutoff: None,
        },
        release: ReleaseTrustV2 {
            trusted_signers: Vec::new(),
            accepted_predicate_types: Vec::new(),
            accepted_policy_profiles: Vec::new(),
        },
        remote_identity: RemoteIdentityTrustV2 {
            accepted_oidc_issuer_configuration_digests: Vec::new(),
        },
        disclosure: DisclosurePolicyV2 {
            requesting_subject_opening: RequestingSubjectOpeningPolicy::Required,
        },
        limits: VerificationLimitsV2::contract(),
    }
}

fn verifier_input(
    key_id: &str,
    checkpoint: Option<AuthorityCheckpointV1>,
) -> RemoteVerifierInputV2 {
    RemoteVerifierInputV2 {
        r#type: RemoteVerifierInputType::Tag,
        api_version: RemoteVerifierInputApiVersion::Tag,
        verification_trust_policy: trust_policy(key_id),
        trust_policy_digest: cd(0x70),
        subject_openings: Vec::new(),
        authority_checkpoint: checkpoint,
        environment_release_checkpoint: None,
        external_artifacts: Vec::new(),
        bundle_hints_are_authority: false,
        network_access: false,
        database_access: false,
        session_access: false,
        private_key_count: 0,
        credential_count: 0,
    }
}

#[test]
fn required_authority_checkpoint_helper_matches_only_exact_head() {
    let set = record_set("019e0000-0000-7000-8000-000000000001", 5, cd(0xE5));
    let key_id = "ed25519:34b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a746";

    let with_exact = verifier_input(
        key_id,
        Some(checkpoint(
            "019e0000-0000-7000-8000-000000000001",
            5,
            cd(0xE5),
            key_id,
        )),
    );
    assert!(with_exact.required_authority_checkpoint_satisfied(&set));

    // A missing checkpoint fails a required policy.
    let without = verifier_input(key_id, None);
    assert!(!without.required_authority_checkpoint_satisfied(&set));

    // A mismatched checkpoint fails.
    let mismatched = verifier_input(
        key_id,
        Some(checkpoint(
            "019e0000-0000-7000-8000-000000000001",
            6,
            cd(0xE6),
            key_id,
        )),
    );
    assert!(!mismatched.required_authority_checkpoint_satisfied(&set));
}

// ---------------------------------------------------------------------------
// Inert first-profile hints.
// ---------------------------------------------------------------------------

#[test]
fn untrusted_hints_are_structurally_inert() {
    let hints = UntrustedHintsV1::inert();
    assert!(hints.authority_root_ids.is_empty());
    assert!(hints.release_root_ids.is_empty());
    assert!(hints.checkpoint_ids.is_empty());
    assert!(hints.resolver_urls.is_empty());
    assert!(!hints.trusted);
    assert!(!hints.auto_fetch);
    // No fetch material exists: the resolver arrays are empty and auto_fetch
    // is false, so nothing can be fetched from a producer hint.
}

// ---------------------------------------------------------------------------
// Primary reason and conformance scenarios.
// ---------------------------------------------------------------------------

fn components() -> VerificationComponentResultsV2 {
    VerificationComponentResultsV2 {
        signature: VerificationComponentResult::Verified,
        actor: VerificationComponentResult::Verified,
        authority: VerificationComponentResult::Verified,
        role_separation: VerificationComponentResult::Verified,
        approval: VerificationComponentResult::Verified,
        policy: VerificationComponentResult::Verified,
        content: VerificationComponentResult::Verified,
        environment: VerificationComponentResult::Verified,
        release: VerificationComponentResult::Verified,
        delivery_evidence: VerificationComponentResult::NotRequested,
        completeness: VerificationComponentResult::Verified,
    }
}

#[test]
fn primary_reason_selects_first_applicable_invalid_component() {
    // Complete selects verified.
    let verified = components();
    assert_eq!(
        verified.primary_reason(
            VerificationStatus::Complete,
            VerificationScenario::CompleteExactMaterialization
        ),
        VerificationReasonCode::Verified
    );

    // First-applicable precedence: an earlier invalid component wins.
    let mut two = components();
    two.signature = VerificationComponentResult::Invalid;
    two.release = VerificationComponentResult::Invalid;
    assert_eq!(
        two.primary_reason(
            VerificationStatus::Invalid,
            VerificationScenario::InvalidVerification
        ),
        VerificationReasonCode::InvalidSignature
    );

    let mut authority = components();
    authority.authority = VerificationComponentResult::Invalid;
    assert_eq!(
        authority.primary_reason(
            VerificationStatus::Invalid,
            VerificationScenario::InvalidVerification
        ),
        VerificationReasonCode::InvalidAuthority
    );

    let mut release = components();
    release.release = VerificationComponentResult::Invalid;
    assert_eq!(
        release.primary_reason(
            VerificationStatus::Invalid,
            VerificationScenario::InvalidVerification
        ),
        VerificationReasonCode::InvalidRelease
    );

    // The content-only conformance tamper selects tampered-artifact.
    let mut tampered = components();
    tampered.content = VerificationComponentResult::Invalid;
    assert_eq!(
        tampered.primary_reason(
            VerificationStatus::Invalid,
            VerificationScenario::InvalidContentArtifactByteTamper
        ),
        VerificationReasonCode::TamperedArtifact
    );
}

#[test]
fn primary_reason_maps_incomplete_scenarios() {
    let verified = components();
    assert_eq!(
        verified.primary_reason(
            VerificationStatus::Incomplete,
            VerificationScenario::IncompleteRequiredOpeningWithheld
        ),
        VerificationReasonCode::MissingDisclosure
    );
    assert_eq!(
        verified.primary_reason(
            VerificationStatus::Incomplete,
            VerificationScenario::IncompleteRequiredArtifactWithheld
        ),
        VerificationReasonCode::MissingArtifact
    );
    assert_eq!(
        verified.primary_reason(
            VerificationStatus::Incomplete,
            VerificationScenario::IncompleteRequiredAuthorityCheckpointWithheld
        ),
        VerificationReasonCode::MissingCheckpoint
    );
}

#[test]
fn report_primary_reason_delegates_to_components() {
    let mut report = RemoteVerificationReportV2 {
        r#type: proof_remote::RemoteVerificationReportType::Tag,
        api_version: proof_remote::RemoteVerificationReportApiVersion::Tag,
        claim_kind: "observed-verifier-outcome".to_owned(),
        runtime_observed: true,
        execution_id: "execution_0000000000000000".to_owned(),
        observed_at: ts(),
        verifier_profile: "proof-verifier/remote-evidence-v2".to_owned(),
        report_id: "report_0000000000000000".to_owned(),
        scenario: VerificationScenario::InvalidVerification,
        status: VerificationStatus::Invalid,
        snapshot_scope:
            "verified-inner-claim-only; producer export and snapshot metadata unauthenticated"
                .to_owned(),
        raw_verifier_input_digest: cd(0x80),
        raw_bundle_descriptor_digest: None,
        raw_bundle_manifest_digest: None,
        bundle_manifest_digest: None,
        verifier_input_digest: None,
        trust_policy_digest: None,
        authority_checkpoint_digest: None,
        environment_release_checkpoint_digest: None,
        components: components(),
        reason_codes: Vec::new(),
    };
    report.components.authority = VerificationComponentResult::Invalid;
    assert_eq!(
        report.primary_reason(),
        VerificationReasonCode::InvalidAuthority
    );
}

#[test]
fn conformance_scenario_rejects_a_fourth_scenario() {
    // Exactly three retained scenarios narrow successfully.
    assert_eq!(
        ConformanceScenario::from_verification_scenario(
            VerificationScenario::CompleteExactMaterialization
        ),
        Some(ConformanceScenario::CompleteExactMaterialization)
    );
    assert_eq!(
        ConformanceScenario::from_verification_scenario(
            VerificationScenario::IncompleteRequiredOpeningWithheld
        ),
        Some(ConformanceScenario::IncompleteRequiredOpeningWithheld)
    );
    assert_eq!(
        ConformanceScenario::from_verification_scenario(
            VerificationScenario::InvalidContentArtifactByteTamper
        ),
        Some(ConformanceScenario::InvalidContentArtifactByteTamper)
    );

    // The three non-retained scenarios are rejected.
    assert_eq!(
        ConformanceScenario::from_verification_scenario(
            VerificationScenario::IncompleteRequiredArtifactWithheld
        ),
        None
    );
    assert_eq!(
        ConformanceScenario::from_verification_scenario(
            VerificationScenario::IncompleteRequiredAuthorityCheckpointWithheld
        ),
        None
    );
    assert_eq!(
        ConformanceScenario::from_verification_scenario(VerificationScenario::InvalidVerification),
        None
    );
}

#[test]
fn conformance_report_consistency_checks_scenario_narrowing() {
    let base = RemoteVerificationReportV2 {
        r#type: proof_remote::RemoteVerificationReportType::Tag,
        api_version: proof_remote::RemoteVerificationReportApiVersion::Tag,
        claim_kind: "observed-verifier-outcome".to_owned(),
        runtime_observed: true,
        execution_id: "execution_0000000000000000".to_owned(),
        observed_at: ts(),
        verifier_profile: "proof-verifier/remote-evidence-v2".to_owned(),
        report_id: "report_0000000000000000".to_owned(),
        scenario: VerificationScenario::CompleteExactMaterialization,
        status: VerificationStatus::Complete,
        snapshot_scope:
            "verified-inner-claim-only; producer export and snapshot metadata unauthenticated"
                .to_owned(),
        raw_verifier_input_digest: cd(0x80),
        raw_bundle_descriptor_digest: None,
        raw_bundle_manifest_digest: None,
        bundle_manifest_digest: None,
        verifier_input_digest: None,
        trust_policy_digest: None,
        authority_checkpoint_digest: None,
        environment_release_checkpoint_digest: None,
        components: components(),
        reason_codes: vec![VerificationReasonCode::Verified],
    };

    let consistent = RemoteVerificationConformanceReportV2 {
        report: base.clone(),
        scenario: ConformanceScenario::CompleteExactMaterialization,
    };
    assert!(consistent.is_consistent());

    // A conformance scenario that does not match the inner general scenario is
    // inconsistent.
    let inconsistent = RemoteVerificationConformanceReportV2 {
        report: base,
        scenario: ConformanceScenario::InvalidContentArtifactByteTamper,
    };
    assert!(!inconsistent.is_consistent());
}
