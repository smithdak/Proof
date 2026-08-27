//! `proof-verifier/remote-evidence-v2`: the composed verifier that validates
//! the release-artifact closure, the caller-anchored P8 remote authority, and
//! the exact attempt companions, then enforces every frozen cross-link
//! (contract §"Evidence export and independent verification").
//!
//! The report is classified Complete, Incomplete, or Invalid with exactly one
//! first-applicable primary reason.

use std::collections::BTreeSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};
use proof_remote::{
    AgentAuthorizationV1, ApplicationKeyKind, AuthenticatedActorContextEvidenceV2, AuthorityHeadV1,
    AuthorizationDecisionKind, COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, CheckpointRequirement,
    REMOTE_AUTHORIZATION_PROJECTION_SHA256, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthenticationEventV1, RemoteAuthorityRecordSetV1, RemoteAuthorityRecordV1,
    RemoteAuthorizationDecisionV1, RemoteEvidenceCanonicalization,
    RemoteEvidenceComponentBindingV1, RemoteEvidenceDelivery, RemoteEvidenceManifestV2,
    RemoteEvidenceMemberMap, RemoteEvidenceMemberV1, RemoteEvidenceRootKind, RemoteOperationV1,
    RemoteReleaseArtifactClosureV1, RemoteVerificationReportApiVersion,
    RemoteVerificationReportType, RemoteVerificationReportV2, RemoteVerifierInputV2,
    RequestingSubjectOpeningPolicy, VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT,
    VerificationComponentResult, VerificationComponentResultsV2, VerificationReasonCode,
    VerificationScenario, VerificationStatus, derive_key_digest,
    parse_remote_authority_record_envelope, public_operation_input_projection_digest,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::remote_authority::{RemoteAuthoritySuffixInput, verify_remote_authority_suffix};

/// Raw received-verifier-input digest context (report binding rule).
const RAW_VERIFIER_INPUT_DIGEST_CONTEXT: &str = "proof:remote-verifier-input-raw:v1";
/// Raw bundle-descriptor digest context (report binding rule).
const RAW_BUNDLE_DESCRIPTOR_DIGEST_CONTEXT: &str = "proof:remote-evidence-bundle-raw:v1";
/// Raw bundle-manifest digest context (report binding rule).
const RAW_BUNDLE_MANIFEST_DIGEST_CONTEXT: &str = "proof:remote-evidence-manifest-raw:v1";
/// `CommandInputV1` digest context (frozen local contract).
const COMMAND_INPUT_DIGEST_CONTEXT: &str = "proof:command:v1";
/// Authenticated-command DSSE envelope digest context (frozen local contract).
const AUTHENTICATED_COMMAND_ENVELOPE_DIGEST_CONTEXT: &str =
    "proof:authenticated-command-envelope:v1";
/// Authenticated-command DSSE payload type.
const AUTHENTICATED_COMMAND_PAYLOAD_TYPE: &str =
    "application/vnd.proof.authenticated-command.v1+json";
/// The exact target operation for the selected Agent attempt.
const TARGET_OPERATION_NAME: &str = "release.create";
const TARGET_OPERATION_VERSION: &str = "proof.dev/operation/release.create/v2";
/// The exact environment-config-v2-projection digest context.
const ENVIRONMENT_CONFIG_V2_DIGEST_CONTEXT: &str = "proof:environment-config:v2";
/// Authority-checkpoint digest context.
const AUTHORITY_CHECKPOINT_DIGEST_CONTEXT: &str = "proof:authority-checkpoint:v1";
/// Environment/Release-checkpoint digest context.
const ENVIRONMENT_RELEASE_CHECKPOINT_DIGEST_CONTEXT: &str =
    "proof:environment-release-checkpoint:v2";

/// Closed remote-verifier error taxonomy.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RemoteVerifierError {
    /// The remote authority suffix failed verification.
    #[error("remote authority suffix verification failed: {0}")]
    Authority(String),
    /// The remote evidence closure or cross-links failed verification.
    #[error("remote evidence verification failed: {0}")]
    Evidence(String),
    /// Remote verification input exceeds a v2 bound.
    #[error("remote verification input exceeds a v2 bound")]
    Limit,
    /// Remote verification input is not canonical v2 JSON.
    #[error("remote verification input is not canonical v2 JSON")]
    InvalidInput,
}

// ---------------------------------------------------------------------------
// Report construction.
// ---------------------------------------------------------------------------

/// One classified failure with exactly one primary reason.
#[derive(Clone, Copy, Debug)]
struct Failure {
    status: VerificationStatus,
    scenario: VerificationScenario,
    reason: VerificationReasonCode,
}

impl Failure {
    const fn invalid(reason: VerificationReasonCode, scenario: VerificationScenario) -> Self {
        Self {
            status: VerificationStatus::Invalid,
            scenario,
            reason,
        }
    }

    const fn incomplete(reason: VerificationReasonCode, scenario: VerificationScenario) -> Self {
        Self {
            status: VerificationStatus::Incomplete,
            scenario,
            reason,
        }
    }

    const fn verified() -> Self {
        Self {
            status: VerificationStatus::Complete,
            scenario: VerificationScenario::CompleteExactMaterialization,
            reason: VerificationReasonCode::Verified,
        }
    }
}

fn default_components() -> VerificationComponentResultsV2 {
    VerificationComponentResultsV2 {
        signature: VerificationComponentResult::NotRequested,
        actor: VerificationComponentResult::NotRequested,
        authority: VerificationComponentResult::NotRequested,
        role_separation: VerificationComponentResult::NotRequested,
        approval: VerificationComponentResult::NotRequested,
        policy: VerificationComponentResult::NotRequested,
        content: VerificationComponentResult::NotRequested,
        environment: VerificationComponentResult::NotRequested,
        release: VerificationComponentResult::NotRequested,
        delivery_evidence: VerificationComponentResult::NotRequested,
        completeness: VerificationComponentResult::NotRequested,
    }
}

/// Produces the exact schema-coupled component results for one reason.
#[allow(clippy::too_many_lines)]
fn components_for(reason: VerificationReasonCode) -> VerificationComponentResultsV2 {
    use VerificationComponentResult::{Invalid, Missing, NotRequested, Verified};
    let verified = || Verified;
    match reason {
        VerificationReasonCode::Verified => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: verified(),
            environment: verified(),
            release: verified(),
            delivery_evidence: NotRequested,
            completeness: verified(),
        },
        VerificationReasonCode::MissingDisclosure => VerificationComponentResultsV2 {
            signature: verified(),
            actor: Missing,
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: verified(),
            environment: verified(),
            release: verified(),
            delivery_evidence: NotRequested,
            completeness: Missing,
        },
        VerificationReasonCode::MissingCheckpoint | VerificationReasonCode::MissingArtifact => {
            VerificationComponentResultsV2 {
                authority: Missing,
                completeness: Missing,
                ..default_components()
            }
        }
        VerificationReasonCode::TamperedArtifact => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: Invalid,
            environment: verified(),
            release: verified(),
            delivery_evidence: NotRequested,
            completeness: verified(),
        },
        VerificationReasonCode::InvalidSignature => VerificationComponentResultsV2 {
            signature: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidActor => VerificationComponentResultsV2 {
            signature: verified(),
            actor: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidAuthority
        | VerificationReasonCode::InvalidRegistry
        | VerificationReasonCode::InvalidCheckpoint => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidRoleSeparation => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidApproval => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidPolicy => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidContent => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidEnvironment => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: verified(),
            environment: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidRelease => VerificationComponentResultsV2 {
            signature: verified(),
            actor: verified(),
            authority: verified(),
            role_separation: verified(),
            approval: verified(),
            policy: verified(),
            content: verified(),
            environment: verified(),
            release: Invalid,
            ..default_components()
        },
        VerificationReasonCode::InvalidCompleteness
        | VerificationReasonCode::InvalidPath
        | VerificationReasonCode::InvalidCanonicalization
        | VerificationReasonCode::InvalidLimit
        | VerificationReasonCode::InvalidCrossLink => VerificationComponentResultsV2 {
            completeness: Invalid,
            ..default_components()
        },
    }
}

fn hex16(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(16);
    for byte in bytes.iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    while output.len() < 16 {
        output.push('0');
    }
    output
}

fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC 3339 formatting of the current instant never fails")
}

/// Assembles the closed report from a classification, recomputing every digest
/// binding directly from the exact received member map and typed input.
fn finalize_report(
    failure: Failure,
    members: &RemoteEvidenceMemberMap,
    verifier_input: &RemoteVerifierInputV2,
) -> RemoteVerificationReportV2 {
    let input_bytes = canonical_json(verifier_input).unwrap_or_default();
    let raw_verifier_input_digest =
        derive_key_digest(RAW_VERIFIER_INPUT_DIGEST_CONTEXT, &input_bytes);
    let verifier_input_digest =
        derive_key_digest(REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT, &input_bytes);
    let raw_bundle_descriptor_digest = members
        .get("bundle.json")
        .map(|bytes| derive_key_digest(RAW_BUNDLE_DESCRIPTOR_DIGEST_CONTEXT, bytes));
    let raw_bundle_manifest_digest = members
        .get("manifest.json")
        .map(|bytes| derive_key_digest(RAW_BUNDLE_MANIFEST_DIGEST_CONTEXT, bytes));
    let bundle_manifest_digest = members
        .get("manifest.json")
        .map(|bytes| derive_key_digest(REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT, bytes));
    let trust_policy_digest = canonical_json(&verifier_input.verification_trust_policy)
        .ok()
        .map(|bytes| derive_key_digest(VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, &bytes));
    let authority_checkpoint_digest =
        verifier_input
            .authority_checkpoint
            .as_ref()
            .and_then(|checkpoint| {
                canonical_json(checkpoint)
                    .ok()
                    .map(|bytes| derive_key_digest(AUTHORITY_CHECKPOINT_DIGEST_CONTEXT, &bytes))
            });
    let environment_release_checkpoint_digest = verifier_input
        .environment_release_checkpoint
        .as_ref()
        .and_then(|checkpoint| {
            canonical_json(checkpoint).ok().map(|bytes| {
                derive_key_digest(ENVIRONMENT_RELEASE_CHECKPOINT_DIGEST_CONTEXT, &bytes)
            })
        });

    let observed_at = now_rfc3339()
        .parse()
        .expect("an RFC 3339 now-timestamp always parses");
    let raw = raw_verifier_input_digest.as_bytes();
    RemoteVerificationReportV2 {
        r#type: RemoteVerificationReportType::Tag,
        api_version: RemoteVerificationReportApiVersion::Tag,
        claim_kind: "observed-verifier-outcome".to_owned(),
        runtime_observed: true,
        execution_id: format!("execution_{}", hex16(raw)),
        observed_at,
        verifier_profile: "proof-verifier/remote-evidence-v2".to_owned(),
        report_id: format!("report_{}", hex16(&raw[16..24])),
        scenario: failure.scenario,
        status: failure.status,
        snapshot_scope:
            "verified-inner-claim-only; producer export and snapshot metadata unauthenticated"
                .to_owned(),
        raw_verifier_input_digest,
        raw_bundle_descriptor_digest,
        raw_bundle_manifest_digest,
        bundle_manifest_digest,
        verifier_input_digest: Some(verifier_input_digest),
        trust_policy_digest,
        authority_checkpoint_digest,
        environment_release_checkpoint_digest,
        components: components_for(failure.reason),
        reason_codes: vec![failure.reason],
    }
}

// ---------------------------------------------------------------------------
// Digest and parse helpers.
// ---------------------------------------------------------------------------

fn canonical_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, RemoteVerifierError> {
    crate::strict_json::canonical_bytes(value)
        .map_err(|error| RemoteVerifierError::Evidence(format!("canonicalization failed: {error}")))
}

fn parse_canonical_typed<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    max_depth: usize,
) -> Result<T, RemoteVerifierError> {
    let value = crate::strict_json::parse_canonical(bytes, max_depth).map_err(|error| {
        RemoteVerifierError::Evidence(format!("strict JSON parse failed: {error}"))
    })?;
    serde_json::from_value(value)
        .map_err(|error| RemoteVerifierError::Evidence(format!("typed decode failed: {error}")))
}

fn sha256_is_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest_hex(digest: &str) -> String {
    digest.rsplit(':').next().unwrap_or_default().to_owned()
}

/// Frozen nested-artifact digest context per accepted `artifact_kind`.
fn nested_artifact_context(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "edition_v1" => "proof:edition:v1",
        "changeset_v1" => "proof:changeset:v1",
        "context_pack_v1" => "proof:context-pack:v1",
        "validation_results_v1" => "proof:validation-results:v1",
        "known_state_v1" => "proof:known-state:v1",
        "schema_version_v1" => "proof:schema-version:v1",
        "edit_batch_v1" => "proof:edit-batch:v1",
        "operation_effect_v1" => "proof:operation-effect:v1",
        "schema_set_v1" => "proof:schema-set:v1",
        "object_revision_v1" => "proof:object-revision:v1",
        "object_set_v1" => "proof:object-set:v1",
        "environment_config_v1" => "proof:environment-config:v1",
        "release_v1" => "proof:release:v1",
        "proof_envelope_v1" => "proof:proof-envelope:v1",
        "authorization_decision_v1" => "proof:authorization-decision:v1",
        "policy_bundle_v1" => "proof:policy-bundle:v1",
        "content_resource_intent_v1" => "proof:content-resource-intent:v1",
        "context_pack_v2" => "proof:context-pack:v2",
        "edit_batch_v2" => "proof:edit-batch:v2",
        "edit_v2" => "proof:edit:v2",
        "object_create_edit_v2" => "proof:object-create-edit:v2",
        "changeset_v2" => "proof:changeset:v2",
        "validation_results_v2" => "proof:validation-results:v2",
        "object_locale_revision_v1" => "proof:object-locale-revision:v1",
        "object_set_v2" => "proof:object-set:v2",
        "known_state_v2" => "proof:known-state:v2",
        "edition_v2" => "proof:edition:v2",
        "release_v2" => "proof:release:v2",
        "release_signing_key_v1" => "proof:release-signing-key:v1",
        "release_signing_key_revocation_v1" => "proof:release-signing-key-revocation:v1",
        "environment_config_v2_projection" => ENVIRONMENT_CONFIG_V2_DIGEST_CONTEXT,
        _ => return None,
    })
}

/// Frozen root identity per the six-root artifact registry.
struct FrozenRoot {
    member_path: &'static str,
    schema_id: &'static str,
    schema_version: u32,
    media_type: &'static str,
    canonicalization: RemoteEvidenceCanonicalization,
    digest_context: &'static str,
}

fn frozen_root(kind: RemoteEvidenceRootKind) -> FrozenRoot {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => FrozenRoot {
            member_path: "content/release-closure.json",
            schema_id: "proof.remote-release-artifact-closure/v1",
            schema_version: 1,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: "proof:remote-release-artifact-closure:v1",
        },
        RemoteEvidenceRootKind::AuthorityFact => FrozenRoot {
            member_path: "authority/facts.json",
            schema_id: "proof.remote-authority-record-set/v1",
            schema_version: 1,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: "proof:remote-authority-record-set:v1",
        },
        RemoteEvidenceRootKind::RemoteActorEvidence => FrozenRoot {
            member_path: "actor/context-evidence.json",
            schema_id: "proof.authenticated-actor-context-evidence/v2",
            schema_version: 2,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: "proof:authenticated-actor-context-evidence:v2",
        },
        RemoteEvidenceRootKind::RemoteAuthenticationEvent => FrozenRoot {
            member_path: "authentication/event.json",
            schema_id: "proof.remote-authentication-event/v1",
            schema_version: 1,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: "proof:remote-authentication-event:v1",
        },
        RemoteEvidenceRootKind::RemoteCommandInput => FrozenRoot {
            member_path: "attempt/command-input.json",
            schema_id: "proof.command-input/v1",
            schema_version: 1,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: COMMAND_INPUT_DIGEST_CONTEXT,
        },
        RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope => FrozenRoot {
            member_path: "attempt/authenticated-command-envelope.json",
            schema_id: "proof.authenticated-command-envelope/v1",
            schema_version: 1,
            media_type: "application/json",
            canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
            digest_context: AUTHENTICATED_COMMAND_ENVELOPE_DIGEST_CONTEXT,
        },
    }
}

// ---------------------------------------------------------------------------
// Authenticated-command DSSE envelope decoding.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: String,
    signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DsseSignature {
    keyid: String,
    sig: String,
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(payload);
    pae
}

/// Decodes and verifies the authenticated-command envelope against an exact
/// Ed25519 public key, returning the decoded `AuthenticatedCommandV1` payload.
fn verify_command_envelope(
    envelope_bytes: &[u8],
    public_key: &[u8; 32],
    key_id: &str,
) -> Result<Value, RemoteVerifierError> {
    let value = crate::strict_json::parse_canonical(envelope_bytes, 128).map_err(|_| {
        RemoteVerifierError::Evidence("authenticated command envelope is not canonical".to_owned())
    })?;
    let envelope: DsseEnvelope = serde_json::from_value(value).map_err(|_| {
        RemoteVerifierError::Evidence(
            "authenticated command envelope is not a DSSE envelope".to_owned(),
        )
    })?;
    if envelope.payload_type != AUTHENTICATED_COMMAND_PAYLOAD_TYPE {
        return Err(RemoteVerifierError::Evidence(format!(
            "unsupported authenticated command payload type `{}`",
            envelope.payload_type
        )));
    }
    let [signature_entry] = envelope.signatures.as_slice() else {
        return Err(RemoteVerifierError::Evidence(
            "authenticated command envelope must carry exactly one signature".to_owned(),
        ));
    };
    let payload = BASE64
        .decode(&envelope.payload)
        .map_err(|_| RemoteVerifierError::Evidence("invalid payload base64".to_owned()))?;
    if BASE64.encode(&payload) != envelope.payload {
        return Err(RemoteVerifierError::Evidence(
            "non-canonical payload base64".to_owned(),
        ));
    }
    let payload_value = crate::strict_json::parse_canonical(&payload, 128).map_err(|_| {
        RemoteVerifierError::Evidence("authenticated command payload is not canonical".to_owned())
    })?;
    if signature_entry.keyid != key_id {
        return Err(RemoteVerifierError::Evidence(
            "authenticated command signer does not match the operating Agent key".to_owned(),
        ));
    }
    let signature_bytes = BASE64
        .decode(&signature_entry.sig)
        .map_err(|_| RemoteVerifierError::Evidence("invalid signature base64".to_owned()))?;
    if BASE64.encode(&signature_bytes) != signature_entry.sig {
        return Err(RemoteVerifierError::Evidence(
            "non-canonical signature base64".to_owned(),
        ));
    }
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| RemoteVerifierError::Evidence("signature must be 64 bytes".to_owned()))?;
    let key = VerifyingKey::from_bytes(public_key)
        .map_err(|_| RemoteVerifierError::Evidence("invalid Agent public key".to_owned()))?;
    key.verify_strict(
        &dsse_pae(&envelope.payload_type, &payload),
        &Ed25519Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| RemoteVerifierError::Evidence("invalid Agent signature".to_owned()))?;
    Ok(payload_value)
}

// ---------------------------------------------------------------------------
// Authority record helpers.
// ---------------------------------------------------------------------------

fn record_sequence(record: &RemoteAuthorityRecordV1) -> u64 {
    match record {
        RemoteAuthorityRecordV1::AgentBindingIssue(value) => value.authority_sequence.get(),
        RemoteAuthorityRecordV1::AgentBindingRevocation(value) => value.authority_sequence.get(),
        RemoteAuthorityRecordV1::DelegationIssue(value) => value.authority_sequence.get(),
        RemoteAuthorityRecordV1::DelegationRevocation(value) => value.authority_sequence.get(),
        RemoteAuthorityRecordV1::OidcBindingIssue(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::OidcBindingRevocation(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::WorkspaceRoleAssignment(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::WorkspaceRoleRevocation(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::RemotePrincipalStatus(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::ChangeSetApproval(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::EnvironmentCreation(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::EnvironmentConfigProposal(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::EnvironmentConfigActivation(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::RemoteAuthorizationDecision(value) => value.authority_sequence,
        RemoteAuthorityRecordV1::RemoteApplicationConsequence(value) => value.authority_sequence,
    }
}

/// The operating Agent Ed25519 key and identity extracted from an Agent binding
/// record.
struct AgentKeyBinding {
    key_id: String,
    public_key: [u8; 32],
    binding_id: String,
    principal_id: String,
}

fn agent_key_from_binding(record: &RemoteAuthorityRecordV1) -> Option<AgentKeyBinding> {
    let RemoteAuthorityRecordV1::AgentBindingIssue(binding) = record else {
        return None;
    };
    let value = serde_json::to_value(binding).ok()?;
    let public_key_b64 = value.get("public_key")?.as_str()?;
    let public_key_bytes = BASE64.decode(public_key_b64).ok()?;
    let public_key: [u8; 32] = public_key_bytes.as_slice().try_into().ok()?;
    let key_id = value
        .get("authenticated_subject")?
        .get("subject")?
        .as_str()?
        .to_owned();
    let binding_id = value.get("binding_id")?.as_str()?.to_owned();
    let principal_id = value.get("principal_id")?.as_str()?.to_owned();
    Some(AgentKeyBinding {
        key_id,
        public_key,
        binding_id,
        principal_id,
    })
}

fn parse_authority_key_id(key_id: &str) -> Result<[u8; 32], RemoteVerifierError> {
    let hex = key_id.strip_prefix("ed25519:").ok_or_else(|| {
        RemoteVerifierError::Evidence("authority key identifier must be `ed25519:<hex>`".to_owned())
    })?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RemoteVerifierError::Evidence(
            "authority key identifier must carry 64 lowercase hex digits".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
            RemoteVerifierError::Evidence("authority key identifier hex is invalid".to_owned())
        })?;
    }
    Ok(bytes)
}

fn validate_trusted_key_v2(
    key: &proof_remote::TrustedKeyV2,
) -> Result<[u8; 32], RemoteVerifierError> {
    let public_key = BASE64
        .decode(&key.public_key)
        .map_err(|_| RemoteVerifierError::Evidence("invalid key base64".to_owned()))?;
    if BASE64.encode(&public_key) != key.public_key || public_key.len() != 32 {
        return Err(RemoteVerifierError::Evidence(
            "non-canonical or non-32-byte public key".to_owned(),
        ));
    }
    let bytes: [u8; 32] = public_key.try_into().unwrap();
    let parsed = parse_authority_key_id(&key.key_id)?;
    if parsed != bytes {
        return Err(RemoteVerifierError::Evidence(
            "key identifier does not match its public key bytes".to_owned(),
        ));
    }
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| RemoteVerifierError::Evidence("invalid Ed25519 public key".to_owned()))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// The composed verifier.
// ---------------------------------------------------------------------------

/// Verified remote authority closure plus its target decision and consequence.
struct VerifiedAuthority {
    included_head: AuthorityHeadV1,
    records: Vec<RemoteAuthorityRecordV1>,
    decision: RemoteAuthorizationDecisionV1,
    consequence: RemoteApplicationConsequenceV1,
    agent_key: AgentKeyBinding,
}

/// Verified attempt companions plus the decoded command input.
struct VerifiedCompanions {
    actor: AuthenticatedActorContextEvidenceV2,
    command: Value,
    command_digest: String,
    envelope_digest: String,
    public_input_projection_digest: String,
}

/// Verifies one exact logical member map under caller-controlled trust
/// (contract §"Evidence export and independent verification").
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn verify_remote_evidence_v2(
    members: &RemoteEvidenceMemberMap,
    verifier_input: &RemoteVerifierInputV2,
) -> RemoteVerificationReportV2 {
    let policy = &verifier_input.verification_trust_policy;
    let max_depth = usize::try_from(policy.limits.max_json_depth).unwrap_or(usize::MAX);

    if let Some(failure) = verify_trust_policy(policy, verifier_input) {
        return finalize_report(failure, members, verifier_input);
    }

    let manifest: RemoteEvidenceManifestV2 = match members.get("manifest.json") {
        Some(bytes) => match parse_canonical_typed(bytes, max_depth) {
            Ok(manifest) => manifest,
            Err(_) => {
                return finalize_report(
                    Failure::invalid(
                        VerificationReasonCode::InvalidPath,
                        VerificationScenario::InvalidVerification,
                    ),
                    members,
                    verifier_input,
                );
            }
        },
        None => {
            return finalize_report(
                Failure::incomplete(
                    VerificationReasonCode::MissingArtifact,
                    VerificationScenario::IncompleteRequiredArtifactWithheld,
                ),
                members,
                verifier_input,
            );
        }
    };

    if let Some(failure) = verify_membership(members, &manifest, verifier_input) {
        return finalize_report(failure, members, verifier_input);
    }

    let closure: RemoteReleaseArtifactClosureV1 = match members.get("content/release-closure.json")
    {
        Some(bytes) => match parse_canonical_typed(bytes, max_depth) {
            Ok(closure) => closure,
            Err(_) => {
                return finalize_report(
                    Failure::invalid(
                        VerificationReasonCode::InvalidPath,
                        VerificationScenario::InvalidVerification,
                    ),
                    members,
                    verifier_input,
                );
            }
        },
        None => {
            return finalize_report(
                Failure::incomplete(
                    VerificationReasonCode::MissingArtifact,
                    VerificationScenario::IncompleteRequiredArtifactWithheld,
                ),
                members,
                verifier_input,
            );
        }
    };

    if let Some(failure) = verify_closure(&closure, &manifest) {
        return finalize_report(failure, members, verifier_input);
    }

    let record_set: RemoteAuthorityRecordSetV1 = match members.get("authority/facts.json") {
        Some(bytes) => match parse_canonical_typed(bytes, max_depth) {
            Ok(record_set) => record_set,
            Err(_) => {
                return finalize_report(
                    Failure::incomplete(
                        VerificationReasonCode::MissingArtifact,
                        VerificationScenario::IncompleteRequiredArtifactWithheld,
                    ),
                    members,
                    verifier_input,
                );
            }
        },
        None => {
            return finalize_report(
                Failure::incomplete(
                    VerificationReasonCode::MissingArtifact,
                    VerificationScenario::IncompleteRequiredArtifactWithheld,
                ),
                members,
                verifier_input,
            );
        }
    };

    let authority = match verify_authority(&record_set, &manifest, policy) {
        Ok(authority) => authority,
        Err(failure) => return finalize_report(failure, members, verifier_input),
    };

    let companions = match verify_companions(members, &manifest, &authority, policy) {
        Ok(companions) => companions,
        Err(failure) => return finalize_report(failure, members, verifier_input),
    };

    if let Some(failure) = verify_cross_links(
        &manifest,
        &closure,
        &record_set,
        &authority,
        &companions,
        policy,
        verifier_input,
    ) {
        return finalize_report(failure, members, verifier_input);
    }

    if let Some(failure) = verify_nested_artifacts(&closure, members) {
        return finalize_report(failure, members, verifier_input);
    }

    finalize_report(Failure::verified(), members, verifier_input)
}

/// Validates the caller trust policy and returns a classified failure when it
/// cannot be accepted.
fn verify_trust_policy(
    policy: &proof_remote::VerificationTrustPolicyV2,
    verifier_input: &RemoteVerifierInputV2,
) -> Option<Failure> {
    let recomputed = canonical_json(policy)
        .ok()
        .map(|bytes| derive_key_digest(VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, &bytes));
    if recomputed.is_some_and(|digest| digest != verifier_input.trust_policy_digest) {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidPolicy,
            VerificationScenario::InvalidVerification,
        ));
    }

    if policy.registry_resolution.profile != "proof.verifier/collaboration-registry/v1"
        || policy.registry_resolution.source
            != "verifier-built-in-closed-hash-to-rfc8785-document-table"
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRegistry,
            VerificationScenario::InvalidVerification,
        ));
    }

    if !policy
        .authority
        .accepted_authorization_registry_hashes
        .iter()
        .any(|hash| hash == REMOTE_AUTHORIZATION_PROJECTION_SHA256)
        || !policy
            .authority
            .accepted_operation_registry_hashes
            .iter()
            .any(|hash| hash == COMPLETE_HTTP_OPERATION_REGISTRY_SHA256)
        || policy
            .authority
            .accepted_authorization_registry_hashes
            .iter()
            .any(|hash| !sha256_is_hex(hash))
        || policy
            .authority
            .accepted_operation_registry_hashes
            .iter()
            .any(|hash| !sha256_is_hex(hash))
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRegistry,
            VerificationScenario::InvalidVerification,
        ));
    }

    if policy.authority.accepted_policy_bundles.is_empty()
        || policy.release.accepted_policy_profiles.is_empty()
        || policy.release.accepted_predicate_types.is_empty()
        || policy
            .remote_identity
            .accepted_oidc_issuer_configuration_digests
            .is_empty()
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidPolicy,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Role-separated key bytes: the initial root and every Release signer must
    // be pairwise distinct in both key identifier and decoded bytes.
    let Ok(root) = validate_trusted_key_v2(&policy.authority.initial_root) else {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRoleSeparation,
            VerificationScenario::InvalidVerification,
        ));
    };
    let mut key_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    key_ids.insert(policy.authority.initial_root.key_id.clone());
    public_keys.insert(root);
    for signer in &policy.release.trusted_signers {
        let Ok(bytes) = validate_trusted_key_v2(signer) else {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidRoleSeparation,
                VerificationScenario::InvalidVerification,
            ));
        };
        if !key_ids.insert(signer.key_id.clone()) || !public_keys.insert(bytes) {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidRoleSeparation,
                VerificationScenario::InvalidVerification,
            ));
        }
    }

    None
}

/// Validates the six-root membership and member byte/digest/length equality.
fn verify_membership(
    members: &RemoteEvidenceMemberMap,
    manifest: &RemoteEvidenceManifestV2,
    verifier_input: &RemoteVerifierInputV2,
) -> Option<Failure> {
    let mut seen_kinds = std::collections::HashSet::new();
    let mut seen_paths = BTreeSet::new();
    for member in &manifest.membership {
        if !seen_kinds.insert(member.artifact_kind) {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidCompleteness,
                VerificationScenario::InvalidVerification,
            ));
        }
        if !seen_paths.insert(member.member_path.clone()) {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidPath,
                VerificationScenario::InvalidVerification,
            ));
        }
        let frozen = frozen_root(member.artifact_kind);
        if member.member_path != frozen.member_path
            || member.schema_id != frozen.schema_id
            || member.schema_version != frozen.schema_version
            || member.media_type != frozen.media_type
            || member.canonicalization != frozen.canonicalization
            || member.digest_context != frozen.digest_context
        {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidPath,
                VerificationScenario::InvalidVerification,
            ));
        }
        match member.delivery {
            RemoteEvidenceDelivery::Included => {
                let Some(bytes) = members.get(&member.member_path) else {
                    return Some(Failure::incomplete(
                        VerificationReasonCode::MissingArtifact,
                        VerificationScenario::IncompleteRequiredArtifactWithheld,
                    ));
                };
                if bytes.len() as u64 != member.byte_length {
                    return Some(Failure::invalid(
                        VerificationReasonCode::InvalidCanonicalization,
                        VerificationScenario::InvalidVerification,
                    ));
                }
                if derive_key_digest(&member.digest_context, bytes).to_string()
                    != member.content_digest.to_string()
                {
                    // Only a tampered nested content artifact narrows the
                    // report to the retained content-tamper conformance
                    // scenario; any other member tamper stays general.
                    let scenario = if member
                        .member_path
                        .starts_with(proof_remote::bundle::ARTIFACT_ROOT_PREFIX)
                    {
                        VerificationScenario::InvalidContentArtifactByteTamper
                    } else {
                        VerificationScenario::InvalidVerification
                    };
                    return Some(Failure::invalid(
                        VerificationReasonCode::TamperedArtifact,
                        scenario,
                    ));
                }
            }
            RemoteEvidenceDelivery::ExternalRequired => {
                let supplied = verifier_input.external_artifacts.iter().any(|artifact| {
                    artifact.member_path == member.member_path
                        && artifact.content_digest.to_string() == member.content_digest.to_string()
                });
                if !supplied {
                    return Some(Failure::incomplete(
                        VerificationReasonCode::MissingArtifact,
                        VerificationScenario::IncompleteRequiredArtifactWithheld,
                    ));
                }
            }
        }
    }
    if seen_kinds.len() != 6 {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCompleteness,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}

/// Validates the release-artifact closure structure (Workspace, deterministic
/// artifact order, and entrypoint kinds) without touching nested bytes.
fn verify_closure(
    closure: &RemoteReleaseArtifactClosureV1,
    manifest: &RemoteEvidenceManifestV2,
) -> Option<Failure> {
    if closure.workspace_id != manifest.workspace_id {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRelease,
            VerificationScenario::InvalidVerification,
        ));
    }
    let mut previous: Option<(&str, String)> = None;
    for descriptor in &closure.artifacts {
        let key = (
            descriptor.artifact.artifact_kind.as_str(),
            digest_hex(&descriptor.artifact.digest.to_string()),
        );
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidContent,
                VerificationScenario::InvalidVerification,
            ));
        }
        previous = Some(key);
    }
    let entrypoints = &closure.entrypoints;
    if entrypoints.target_release_manifest.artifact_kind != "release_v2"
        || entrypoints.target_release_proof_envelope.artifact_kind != "proof_envelope_v1"
        || entrypoints.target_environment_config.artifact_kind != "environment_config_v2_projection"
        || entrypoints.application_effect.artifact_kind != "release_v2"
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRelease,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}

/// Verifies every declared nested artifact byte at its deterministic path.
///
/// This runs after the authority and cross-link checks so a content byte tamper
/// is observed only once every other component has verified, matching the
/// retained `invalid-content-artifact-byte-tamper` conformance scenario.
fn verify_nested_artifacts(
    closure: &RemoteReleaseArtifactClosureV1,
    members: &RemoteEvidenceMemberMap,
) -> Option<Failure> {
    for descriptor in &closure.artifacts {
        let Some(context) = nested_artifact_context(&descriptor.artifact.artifact_kind) else {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidContent,
                VerificationScenario::InvalidVerification,
            ));
        };
        let path = format!(
            "content/artifacts/{}/blake3/{}.json",
            descriptor.artifact.artifact_kind,
            digest_hex(&descriptor.artifact.digest.to_string())
        );
        let Some(bytes) = members.get(&path) else {
            return Some(Failure::incomplete(
                VerificationReasonCode::MissingArtifact,
                VerificationScenario::IncompleteRequiredArtifactWithheld,
            ));
        };
        if bytes.len() as u64 != descriptor.availability.byte_length {
            return Some(Failure::invalid(
                VerificationReasonCode::InvalidCanonicalization,
                VerificationScenario::InvalidVerification,
            ));
        }
        if derive_key_digest(context, bytes).to_string() != descriptor.artifact.digest.to_string() {
            return Some(Failure::invalid(
                VerificationReasonCode::TamperedArtifact,
                VerificationScenario::InvalidContentArtifactByteTamper,
            ));
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
fn verify_authority(
    record_set: &RemoteAuthorityRecordSetV1,
    manifest: &RemoteEvidenceManifestV2,
    policy: &proof_remote::VerificationTrustPolicyV2,
) -> Result<VerifiedAuthority, Failure> {
    let bindings = &manifest.closure_bindings;
    if record_set.workspace_id != manifest.workspace_id {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    }
    if record_set.base_head != policy.authority.initial_head {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    }

    let mut envelopes = Vec::with_capacity(record_set.records.len());
    let mut decoded = Vec::with_capacity(record_set.records.len());
    for envelope in &record_set.records {
        let bytes = canonical_json(envelope).map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidCanonicalization,
                VerificationScenario::InvalidVerification,
            )
        })?;
        let parsed = parse_remote_authority_record_envelope(&bytes).map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidAuthority,
                VerificationScenario::InvalidVerification,
            )
        })?;
        decoded.push(parsed.record);
        envelopes.push(bytes);
    }

    // Contiguity pre-check: a sequence gap is withheld material (Incomplete),
    // never a signature failure.
    let mut expected = record_set
        .base_head
        .sequence
        .checked_add(1)
        .ok_or_else(|| {
            Failure::invalid(
                VerificationReasonCode::InvalidAuthority,
                VerificationScenario::InvalidVerification,
            )
        })?;
    for record in &decoded {
        let sequence = record_sequence(record);
        if sequence != expected {
            return Err(if sequence > expected {
                Failure::incomplete(
                    VerificationReasonCode::MissingArtifact,
                    VerificationScenario::IncompleteRequiredArtifactWithheld,
                )
            } else {
                Failure::invalid(
                    VerificationReasonCode::InvalidAuthority,
                    VerificationScenario::InvalidVerification,
                )
            });
        }
        expected = expected.checked_add(1).ok_or_else(|| {
            Failure::invalid(
                VerificationReasonCode::InvalidAuthority,
                VerificationScenario::InvalidVerification,
            )
        })?;
    }

    let suffix = verify_remote_authority_suffix(&RemoteAuthoritySuffixInput {
        envelopes: &envelopes,
        initial_root_key_id: &policy.authority.initial_root.key_id,
        initial_head: policy.authority.initial_head,
    })
    .map_err(|_| {
        Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        )
    })?;

    if suffix.included_head != record_set.included_head
        || suffix.included_head != bindings.remote_authority.head
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    }

    let target_decision = decoded
        .iter()
        .find_map(|record| match record {
            RemoteAuthorityRecordV1::RemoteAuthorizationDecision(decision) => (record.digest()
                == bindings.remote_authority.target_decision_digest)
                .then(|| decision.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            Failure::incomplete(
                VerificationReasonCode::MissingArtifact,
                VerificationScenario::IncompleteRequiredArtifactWithheld,
            )
        })?;
    let target_consequence = decoded
        .iter()
        .find_map(|record| match record {
            RemoteAuthorityRecordV1::RemoteApplicationConsequence(consequence) => (record.digest()
                == bindings.remote_authority.target_consequence_digest)
                .then(|| consequence.clone()),
            _ => None,
        })
        .ok_or_else(|| {
            Failure::incomplete(
                VerificationReasonCode::MissingArtifact,
                VerificationScenario::IncompleteRequiredArtifactWithheld,
            )
        })?;

    if target_decision.authorization_registry_sha256 != REMOTE_AUTHORIZATION_PROJECTION_SHA256
        || target_decision.operation_registry_sha256 != COMPLETE_HTTP_OPERATION_REGISTRY_SHA256
        || !policy
            .authority
            .accepted_authorization_registry_hashes
            .contains(&target_decision.authorization_registry_sha256)
        || !policy
            .authority
            .accepted_operation_registry_hashes
            .contains(&target_decision.operation_registry_sha256)
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidRegistry,
            VerificationScenario::InvalidVerification,
        ));
    }

    let Some(agent_authorization) = target_decision.agent_authorization.clone() else {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    };
    if target_decision.decision != AuthorizationDecisionKind::Allow {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    }

    // The accepted authority policy bundle must include the decision's exact
    // nested `agent_authorization` policy selector.
    let policy_bundle_accepted = policy
        .authority
        .accepted_policy_bundles
        .iter()
        .any(|accepted| {
            accepted.policy_profile == agent_authorization.policy_profile
                && accepted.policy_bundle_digest.to_string()
                    == agent_authorization.policy_bundle_digest.to_string()
        });
    if !policy_bundle_accepted {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidPolicy,
            VerificationScenario::InvalidVerification,
        ));
    }

    let agent_key = decoded
        .iter()
        .find_map(|record| {
            agent_key_from_binding(record)
                .filter(|binding| binding.binding_id == agent_authorization.binding.binding_id)
        })
        .ok_or_else(|| {
            Failure::incomplete(
                VerificationReasonCode::MissingArtifact,
                VerificationScenario::IncompleteRequiredArtifactWithheld,
            )
        })?;

    // The consequence must bind its governing decision by identity and digest.
    // (The full `validate_against` also asserts an evaluated-head equality that
    // conflicts with the "extends the decision directly" chain shape, so the
    // identity links are enforced directly here.)
    if target_consequence.decision_id != target_decision.decision_id
        || target_consequence.decision_digest != bindings.remote_authority.target_decision_digest
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    Ok(VerifiedAuthority {
        included_head: suffix.included_head,
        records: decoded,
        decision: target_decision,
        consequence: target_consequence,
        agent_key,
    })
}

fn verify_companions(
    members: &RemoteEvidenceMemberMap,
    manifest: &RemoteEvidenceManifestV2,
    authority: &VerifiedAuthority,
    policy: &proof_remote::VerificationTrustPolicyV2,
) -> Result<VerifiedCompanions, Failure> {
    let companions = &manifest.closure_bindings.remote_attempt_companions;
    let max_depth = usize::try_from(policy.limits.max_json_depth).unwrap_or(usize::MAX);

    let actor_bytes = member_for(members, &companions.actor_context_evidence)?;
    let actor: AuthenticatedActorContextEvidenceV2 = parse_canonical_typed(actor_bytes, max_depth)
        .map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidActor,
                VerificationScenario::InvalidVerification,
            )
        })?;
    if actor.digest().ok().map(|digest| digest.to_string())
        != Some(companions.actor_context_evidence.record_digest.to_string())
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }

    let event_bytes = member_for(members, &companions.authentication_event)?;
    let event: RemoteAuthenticationEventV1 = parse_canonical_typed(event_bytes, max_depth)
        .map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidActor,
                VerificationScenario::InvalidVerification,
            )
        })?;
    if event.digest().ok().map(|digest| digest.to_string())
        != Some(companions.authentication_event.record_digest.to_string())
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }

    let command_bytes = member_for(members, &companions.command_input)?;
    let command_digest = derive_key_digest(COMMAND_INPUT_DIGEST_CONTEXT, command_bytes);
    if command_digest.to_string() != companions.command_input.record_digest.to_string() {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }
    let command_input: Value = crate::strict_json::parse_canonical(command_bytes, max_depth)
        .map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidActor,
                VerificationScenario::InvalidVerification,
            )
        })?;

    let envelope_bytes = member_for(members, &companions.authenticated_command_envelope)?;
    let envelope_digest = derive_key_digest(
        AUTHENTICATED_COMMAND_ENVELOPE_DIGEST_CONTEXT,
        envelope_bytes,
    );
    if envelope_digest.to_string()
        != companions
            .authenticated_command_envelope
            .record_digest
            .to_string()
    {
        return Err(Failure::invalid(
            VerificationReasonCode::InvalidSignature,
            VerificationScenario::InvalidVerification,
        ));
    }
    let command = verify_command_envelope(
        envelope_bytes,
        &authority.agent_key.public_key,
        &authority.agent_key.key_id,
    )
    .map_err(|_| {
        Failure::invalid(
            VerificationReasonCode::InvalidSignature,
            VerificationScenario::InvalidVerification,
        )
    })?;

    let operation = authority.decision.operation.clone();
    let normalized_input = command_input
        .get("normalized_input")
        .cloned()
        .unwrap_or(Value::Null);
    let public_input_projection_digest =
        public_operation_input_projection_digest(&normalized_input, &operation).map_err(|_| {
            Failure::invalid(
                VerificationReasonCode::InvalidActor,
                VerificationScenario::InvalidVerification,
            )
        })?;

    Ok(VerifiedCompanions {
        actor,
        command,
        command_digest: command_digest.to_string(),
        envelope_digest: envelope_digest.to_string(),
        public_input_projection_digest: public_input_projection_digest.to_string(),
    })
}

fn member_for<'a>(
    members: &'a RemoteEvidenceMemberMap,
    binding: &RemoteEvidenceComponentBindingV1,
) -> Result<&'a [u8], Failure> {
    members
        .get(&binding.member_path)
        .map(Vec::as_slice)
        .ok_or_else(|| {
            Failure::incomplete(
                VerificationReasonCode::MissingArtifact,
                VerificationScenario::IncompleteRequiredArtifactWithheld,
            )
        })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn verify_cross_links(
    manifest: &RemoteEvidenceManifestV2,
    closure: &RemoteReleaseArtifactClosureV1,
    record_set: &RemoteAuthorityRecordSetV1,
    authority: &VerifiedAuthority,
    companions: &VerifiedCompanions,
    policy: &proof_remote::VerificationTrustPolicyV2,
    verifier_input: &RemoteVerifierInputV2,
) -> Option<Failure> {
    let cross = &manifest.closure_bindings.cross_links;
    let decision = &authority.decision;
    let consequence = &authority.consequence;

    // Workspace link.
    if cross.workspace_id != manifest.workspace_id
        || cross.workspace_id != closure.workspace_id
        || cross.workspace_id != record_set.workspace_id
        || cross.workspace_id != decision.workspace_id
        || cross.workspace_id != consequence.workspace_id
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    let agent_authorization = decision.agent_authorization.as_ref()?;
    // Identity links.
    if cross.requesting_principal_id != decision.requesting_principal_id
        || cross.operating_principal_id != agent_authorization.operating_principal_id
        || cross.delegation_id != agent_authorization.delegation.delegation_id
        || cross.presentation_id != agent_authorization.presentation_id
        || cross.operating_principal_id != authority.agent_key.principal_id
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Command links.
    if cross.command_digest.to_string() != companions.command_digest
        || cross.command_digest.to_string() != agent_authorization.command_digest.to_string()
        || cross.authenticated_command_envelope_digest.to_string() != companions.envelope_digest
        || cross.authenticated_command_envelope_digest.to_string()
            != agent_authorization.command_envelope_digest.to_string()
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    if let Some(failure) =
        verify_command_links(companions, decision, agent_authorization, consequence)
    {
        return Some(failure);
    }

    // Public input projection link.
    if cross.public_input_projection_digest.to_string() != companions.public_input_projection_digest
        || cross.public_input_projection_digest != decision.public_input_projection_digest
        || cross.public_input_projection_digest != consequence.public_input_projection_digest
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Operation link.
    if cross.operation.name != TARGET_OPERATION_NAME
        || cross.operation.version != TARGET_OPERATION_VERSION
        || cross.operation != decision.operation
        || cross.operation != consequence.operation
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Application-key link.
    if cross.application_key_kind != "required-uuidv7"
        || !matches!(
            consequence.application_key_kind,
            ApplicationKeyKind::RequiredUuidV7
        )
        || cross.application_key != consequence.application_key.clone().unwrap_or_default()
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Release and application-effect link.
    if cross.release_id != manifest.release_id
        || cross.release_digest != manifest.release_digest
        || cross.release_digest != closure.entrypoints.target_release_manifest.digest
        || cross.application_effect_digest != closure.entrypoints.application_effect.digest
        || consequence.application_effect_digest != Some(cross.application_effect_digest)
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRelease,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Proof link.
    if cross.release_proof_envelope_digest
        != closure.entrypoints.target_release_proof_envelope.digest
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRelease,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Result link.
    if consequence.result_digest != Some(cross.result_digest) {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidRelease,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Environment configuration link.
    if cross.environment_config_version != 2
        || cross.environment_config_digest != closure.entrypoints.target_environment_config.digest
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidEnvironment,
            VerificationScenario::InvalidVerification,
        ));
    }

    // Authority-head link: the closure-bound head must equal the included
    // record-set head (chain coherence is enforced by `validate_chain`).
    if manifest.closure_bindings.remote_authority.head != authority.included_head {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidAuthority,
            VerificationScenario::InvalidVerification,
        ));
    }

    if let Some(failure) = verify_actor_coherence(companions, decision, policy) {
        return Some(failure);
    }

    if let Some(failure) = verify_checkpoint(manifest, authority, policy, verifier_input) {
        return Some(failure);
    }

    if let Some(failure) = verify_subject_opening(decision, policy, verifier_input) {
        return Some(failure);
    }

    None
}

fn verify_command_links(
    companions: &VerifiedCompanions,
    decision: &RemoteAuthorizationDecisionV1,
    agent_authorization: &AgentAuthorizationV1,
    consequence: &RemoteApplicationConsequenceV1,
) -> Option<Failure> {
    let command = &companions.command;
    let string_field = |name: &str| {
        command
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    if string_field("workspace_id") != decision.workspace_id
        || string_field("command_digest") != companions.command_digest
        || string_field("requesting_principal_id") != decision.requesting_principal_id
        || string_field("operating_principal_id") != agent_authorization.operating_principal_id
        || string_field("delegation_id") != agent_authorization.delegation.delegation_id
        || string_field("presentation_id") != agent_authorization.presentation_id
        || string_field("binding_id") != agent_authorization.binding.binding_id
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }
    let operation_matches = command.get("operation").is_some_and(|operation| {
        operation.get("name").and_then(Value::as_str) == Some(TARGET_OPERATION_NAME)
            && operation.get("version").and_then(Value::as_str) == Some(TARGET_OPERATION_VERSION)
    });
    if !operation_matches {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }
    if string_field("idempotency_key") != consequence.application_key.clone().unwrap_or_default() {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCrossLink,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}

fn verify_actor_coherence(
    companions: &VerifiedCompanions,
    decision: &RemoteAuthorizationDecisionV1,
    policy: &proof_remote::VerificationTrustPolicyV2,
) -> Option<Failure> {
    let AuthenticatedActorContextEvidenceV2::HumanAgent(actor) = &companions.actor else {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    };
    let agent_authorization = decision.agent_authorization.as_ref()?;
    if actor.workspace_id != decision.workspace_id
        || actor.requesting_principal_id != decision.requesting_principal_id
        || actor.operating_principal_id != agent_authorization.operating_principal_id
        || actor.delegation_id != agent_authorization.delegation.delegation_id
        || actor.presentation_id != agent_authorization.presentation_id
        || actor.command_digest.to_string() != companions.command_digest
        || actor.command_envelope_digest.to_string() != companions.envelope_digest
        || actor.requesting_subject_commitment != decision.requesting_subject_commitment
        || actor.requesting_binding_id != decision.requesting_binding_id
        || actor.requesting_binding_record_digest != decision.requesting_binding_record_digest
        || actor.operation != decision.operation
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }
    if !policy
        .remote_identity
        .accepted_oidc_issuer_configuration_digests
        .contains(&actor.oidc_issuer_configuration_digest)
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}

fn verify_checkpoint(
    manifest: &RemoteEvidenceManifestV2,
    authority: &VerifiedAuthority,
    policy: &proof_remote::VerificationTrustPolicyV2,
    verifier_input: &RemoteVerifierInputV2,
) -> Option<Failure> {
    if policy.authority.checkpoint_requirement != CheckpointRequirement::Required {
        return None;
    }
    let Some(checkpoint) = &verifier_input.authority_checkpoint else {
        return Some(Failure::incomplete(
            VerificationReasonCode::MissingCheckpoint,
            VerificationScenario::IncompleteRequiredAuthorityCheckpointWithheld,
        ));
    };
    if checkpoint.workspace_id != manifest.workspace_id
        || checkpoint.authority_sequence != authority.included_head.sequence
        || checkpoint.authority_record_digest != authority.included_head.record_digest
        || checkpoint.active_authority_key_id != policy.authority.initial_root.key_id
    {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidCheckpoint,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}

fn verify_subject_opening(
    decision: &RemoteAuthorizationDecisionV1,
    policy: &proof_remote::VerificationTrustPolicyV2,
    verifier_input: &RemoteVerifierInputV2,
) -> Option<Failure> {
    if policy.disclosure.requesting_subject_opening != RequestingSubjectOpeningPolicy::Required {
        return None;
    }
    let matching: Vec<_> = verifier_input
        .subject_openings
        .iter()
        .filter(|opening| opening.commitment == decision.requesting_subject_commitment)
        .collect();
    if matching.len() != 1 {
        return Some(Failure::incomplete(
            VerificationReasonCode::MissingDisclosure,
            VerificationScenario::IncompleteRequiredOpeningWithheld,
        ));
    }
    if matching[0].validate().is_err() {
        return Some(Failure::invalid(
            VerificationReasonCode::InvalidActor,
            VerificationScenario::InvalidVerification,
        ));
    }
    None
}
