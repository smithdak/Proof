//! Immutable keyed evidence-export capture, no-key lifecycle status read,
//! kind-and-digest artifact acquisition, and the out-of-transaction assembly
//! worker (contract §"Evidence export and independent verification").
//!
//! This module implements the complete P-0013 export boundary:
//! [`evidence_export_v2`] commits one immutable [`EvidenceExportCaptureV2`] in
//! a short serializable transaction with the
//! [`CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS`] boundary and always
//! returns the keyed pending [`EvidenceExportResultV2`]; [`ExportWorker`] builds
//! the logical member map outside the transaction and performs a separate
//! pending-to-ready transaction; [`evidence_export_get_v1`] reads the mutable
//! [`EvidenceExportStatusV1`]; [`evidence_artifact_get_v2`] acquires one body by
//! its exact `(export_id, artifact_kind, digest)` triple.
//!
//! # Producer storage contract
//!
//! The export boundary reuses the existing `facts` and `artifact_body_pg`
//! tables rather than introducing new schema (the P-0010 schema is frozen and
//! owned by the PostgreSQL foundation):
//!
//! * `facts` row `evidence_export_capture/{export_id}` (kind
//!   `evidence_export_capture`) holds the canonical capture bytes;
//! * `facts` row `evidence_export_result/{idempotency_key}` (kind
//!   `evidence_export_result`) holds the exact keyed create-result bytes so a
//!   same-key replay returns byte-identical bytes;
//! * `facts` row `evidence_export_ready/{export_id}` (kind
//!   `evidence_export_ready`) holds the immutable ready projection
//!   ([`EvidenceExportStatusV1`] with `status: Ready`), written by the worker
//!   as a separate serializable transaction;
//! * `facts` row `release_export_material/{release_id}` (kind
//!   `release_export_material`) carries the pre-materialized aggregate-root and
//!   attempt-companion digests selected by the capture;
//! * `artifact_body_pg` holds the six root member bytes (kinds
//!   `release-artifact-closure`, `authority-fact`, `remote-actor-evidence`,
//!   `remote-authentication-event`, `remote-command-input`,
//!   `remote-authenticated-command-envelope`), the reserved descriptor bytes
//!   (kinds `bundle` and `manifest`), and every nested accepted-artifact body.
//!
//! The five captured heads are projected from the locked Workspace head row:
//! `authority` <- `authority_head_digest`, `content` <- `content_head_digest`,
//! `release` <- `release_head_digest`, `environment` <-
//! `configuration_head_digest`, and `outbox` <- `policy_head_digest`. These
//! heads remain unauthenticated producer metadata (contract §"Evidence export
//! and independent verification").

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use proof_application::authority::{AuthenticatedCommandV1, CommandInputV1};
use proof_attestation::authority::{AuthorityPayloadProfile, parse_authority_envelope};
use proof_canonical::canonicalize;
use proof_domain::{ContentDigest, Timestamp};
use proof_pg::{
    PgError,
    idempotency::{IdempotencyOutcome, IdempotencyTupleV1, SavepointGuard, replay_or_conflict},
    transaction::{UnitOfWorkHooks, UnitOfWorkOutcome, WorkspaceHeadSnapshot, run_unit_of_work},
};
use proof_remote::{
    AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT, AuthorityHeadV1, BUNDLE_DESCRIPTOR_PATH,
    CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS, ENVIRONMENT_CONFIG_DIGEST_CONTEXT,
    EVIDENCE_EXPORT_CAPTURE_DIGEST_CONTEXT, EvidenceExportCaptureApiVersion,
    EvidenceExportCaptureType, EvidenceExportCaptureV2, EvidenceExportResultApiVersion,
    EvidenceExportResultV2, EvidenceExportStatusApiVersion, EvidenceExportStatusKind,
    EvidenceExportStatusV1, EvidenceHeadsV1, MANIFEST_MEMBER_PATH, MAX_ARTIFACT_BYTES,
    MAX_EXPORT_ARTIFACT_BODIES, MAX_NESTED_ARTIFACT_BODIES, MAX_TOTAL_BYTES,
    REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT, REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
    REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, RemoteApplicationConsequenceV1,
    RemoteAuthorityRecordSetV1, RemoteAuthorizationDecisionV1,
    RemoteEvidenceArtifactClosureBindingV1, RemoteEvidenceAttemptCompanionsBindingV1,
    RemoteEvidenceAuthorityBindingV1, RemoteEvidenceBundleApiVersion, RemoteEvidenceBundleType,
    RemoteEvidenceBundleV2, RemoteEvidenceCanonicalization,
    RemoteEvidenceClosureBindingsApiVersion, RemoteEvidenceClosureBindingsV1,
    RemoteEvidenceComponentBindingV1, RemoteEvidenceCrossLinksV1, RemoteEvidenceDelivery,
    RemoteEvidenceDisclosureKind, RemoteEvidenceDisclosureProfile,
    RemoteEvidenceDisclosureRequirementV1, RemoteEvidenceManifestApiVersion,
    RemoteEvidenceManifestType, RemoteEvidenceManifestV2, RemoteEvidenceMemberMap,
    RemoteEvidenceMemberV1, RemoteEvidencePortablePayloadContractV1, RemoteEvidenceRootKind,
    RemoteOperationV1, RemoteReleaseArtifactClosureV1, UntrustedHintsV1,
    authority::RemoteAuthorityRecordV1,
    identity::{AuthenticatedActorContextV2, public_operation_input_projection_digest},
    registry::{
        ApplicationConsequenceOutcome, ApplicationKeyKind, AuthorizationDecisionKind,
        RemoteApplicationConsequenceApiVersion, application_problem_digest_preimage,
        operation_effect_digest,
    },
};
use serde_json::Value;

use crate::{AppState, ServerError};

/// The exact `(export_id, artifact_kind, digest)` triple that addresses and
/// authorizes one artifact acquisition (contract §"Evidence export and
/// independent verification").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceArtifactSelector {
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// Exact artifact kind; a digest under another kind is not an alias.
    pub artifact_kind: String,
    /// Domain-separated digest of the exact canonical bytes.
    pub digest: ContentDigest,
}

/// `facts.fact_kind` for one immutable export capture.
const CAPTURE_FACT_KIND: &str = "evidence_export_capture";
/// `facts.fact_kind` for one keyed create-result byte preimage.
const RESULT_FACT_KIND: &str = "evidence_export_result";
/// `facts.fact_kind` for one immutable ready projection.
const READY_FACT_KIND: &str = "evidence_export_ready";
/// `facts.fact_kind` for one pre-materialized release export selection.
const MATERIAL_FACT_KIND: &str = "release_export_material";

/// Reserved artifact kind selecting the `bundle.json` descriptor body.
const RESERVED_BUNDLE_KIND: &str = "bundle";
/// Reserved artifact kind selecting the `manifest.json` descriptor body.
const RESERVED_MANIFEST_KIND: &str = "manifest";

/// Exact `remote_attempt_companions` profile for the exported Agent attempt.
const ATTEMPT_COMPANIONS_PROFILE: &str = "agent-release-create-v2-success";
/// Exact exported Agent operation identity.
const RELEASE_CREATE_VERSION: &str = "proof.dev/operation/release.create/v2";

/// Exact `disclosure_id` for the always-present OIDC subject-opening
/// requirement (contract §"Evidence export and independent verification").
const SUBJECT_OPENING_DISCLOSURE_ID: &str = "disclosure:subject-opening";

/// Stable missing-capture/export Problem classification.
const PROBLEM_RESOURCE_NOT_FOUND: &str = "proof.resource.not_found";

// ---------------------------------------------------------------------------
// Canonicalization and digest helpers.
// ---------------------------------------------------------------------------

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, ServerError> {
    canonicalize(value)
        .map(|canonical| canonical.as_bytes().to_vec())
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn typed_digest<T: serde::Serialize>(
    context: &str,
    value: &T,
) -> Result<ContentDigest, ServerError> {
    let json =
        serde_json::to_value(value).map_err(|error| ServerError::Internal(error.to_string()))?;
    let bytes = canonical_bytes(&json)?;
    Ok(proof_remote::derive_key_digest(context, &bytes))
}

fn raw_digest(context: &str, bytes: &[u8]) -> ContentDigest {
    proof_remote::derive_key_digest(context, bytes)
}

fn capture_digest(capture: &EvidenceExportCaptureV2) -> Result<ContentDigest, ServerError> {
    typed_digest(EVIDENCE_EXPORT_CAPTURE_DIGEST_CONTEXT, capture)
}

fn manifest_digest(manifest: &RemoteEvidenceManifestV2) -> Result<ContentDigest, ServerError> {
    typed_digest(REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT, manifest)
}

fn bundle_descriptor_digest(bundle: &RemoteEvidenceBundleV2) -> Result<ContentDigest, ServerError> {
    typed_digest(REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT, bundle)
}

fn closure_digest(closure: &RemoteReleaseArtifactClosureV1) -> Result<ContentDigest, ServerError> {
    typed_digest(REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, closure)
}

fn record_set_digest(
    record_set: &RemoteAuthorityRecordSetV1,
) -> Result<ContentDigest, ServerError> {
    typed_digest(REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT, record_set)
}

fn unique_fact_digest(bytes: &[u8]) -> ContentDigest {
    ContentDigest::blake3(*blake3::hash(bytes).as_bytes())
}

fn now_timestamp() -> Result<Timestamp, ServerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_| {
        ServerError::Internal("system clock exceeds the timestamp range".to_owned())
    })?;
    Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn zero_digest() -> ContentDigest {
    ContentDigest::blake3([0_u8; 32])
}

fn digest_hex(digest: &ContentDigest) -> String {
    let encoded = digest.to_string();
    encoded
        .strip_prefix("blake3:")
        .unwrap_or(encoded.as_str())
        .to_owned()
}

// ---------------------------------------------------------------------------
// Member path and artifact-kind resolution.
// ---------------------------------------------------------------------------

fn normalize_member_path(path: &str) -> Result<String, ServerError> {
    if path.starts_with('/') {
        return Err(ServerError::Internal(
            "absolute member path is not permitted".to_owned(),
        ));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(ServerError::Internal(
            "dot-segment member path is not permitted".to_owned(),
        ));
    }
    if path.contains('\\') {
        return Err(ServerError::Internal(
            "backslash member path is not permitted".to_owned(),
        ));
    }
    Ok(path.to_owned())
}

fn root_digest_context(kind: RemoteEvidenceRootKind) -> &'static str {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => {
            REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT
        }
        RemoteEvidenceRootKind::AuthorityFact => REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
        RemoteEvidenceRootKind::RemoteActorEvidence => {
            AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT
        }
        RemoteEvidenceRootKind::RemoteAuthenticationEvent => {
            REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT
        }
        RemoteEvidenceRootKind::RemoteCommandInput => "proof:command:v1",
        RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope => {
            "proof:authenticated-command-envelope:v1"
        }
    }
}

fn root_member_spec(kind: RemoteEvidenceRootKind) -> (&'static str, &'static str, u32) {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => (
            "content/release-closure.json",
            "proof.remote-release-artifact-closure/v1",
            1,
        ),
        RemoteEvidenceRootKind::AuthorityFact => (
            "authority/facts.json",
            "proof.remote-authority-record-set/v1",
            1,
        ),
        RemoteEvidenceRootKind::RemoteActorEvidence => (
            "actor/context-evidence.json",
            "proof.authenticated-actor-context-evidence/v2",
            2,
        ),
        RemoteEvidenceRootKind::RemoteAuthenticationEvent => (
            "authentication/event.json",
            "proof.remote-authentication-event/v1",
            1,
        ),
        RemoteEvidenceRootKind::RemoteCommandInput => {
            ("attempt/command-input.json", "proof.command-input/v1", 1)
        }
        RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope => (
            "attempt/authenticated-command-envelope.json",
            "proof.authenticated-command-envelope/v1",
            1,
        ),
    }
}

fn root_kind_wire(kind: RemoteEvidenceRootKind) -> &'static str {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => "release-artifact-closure",
        RemoteEvidenceRootKind::AuthorityFact => "authority-fact",
        RemoteEvidenceRootKind::RemoteActorEvidence => "remote-actor-evidence",
        RemoteEvidenceRootKind::RemoteAuthenticationEvent => "remote-authentication-event",
        RemoteEvidenceRootKind::RemoteCommandInput => "remote-command-input",
        RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope => {
            "remote-authenticated-command-envelope"
        }
    }
}

fn parse_root_kind(kind: &str) -> Result<RemoteEvidenceRootKind, ServerError> {
    match kind {
        "release-artifact-closure" => Ok(RemoteEvidenceRootKind::ReleaseArtifactClosure),
        "authority-fact" => Ok(RemoteEvidenceRootKind::AuthorityFact),
        "remote-actor-evidence" => Ok(RemoteEvidenceRootKind::RemoteActorEvidence),
        "remote-authentication-event" => Ok(RemoteEvidenceRootKind::RemoteAuthenticationEvent),
        "remote-command-input" => Ok(RemoteEvidenceRootKind::RemoteCommandInput),
        "remote-authenticated-command-envelope" => {
            Ok(RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope)
        }
        _ => Err(ServerError::Internal(format!(
            "unknown root artifact kind `{kind}`"
        ))),
    }
}

fn nested_artifact_digest_context(kind: &str) -> Option<&'static str> {
    if kind == "environment_config_v2_projection" {
        return Some(ENVIRONMENT_CONFIG_DIGEST_CONTEXT);
    }
    proof_domain::ArtifactKind::from_wire_name(kind)
        .map(proof_domain::ArtifactKind::derive_key_context)
}

fn nested_artifact_path(kind: &str, digest: &ContentDigest) -> String {
    format!(
        "content/artifacts/{kind}/blake3/{}.json",
        digest_hex(digest)
    )
}

fn project_heads(head: &WorkspaceHeadSnapshot) -> EvidenceHeadsV1 {
    EvidenceHeadsV1 {
        authority: head
            .authority_head
            .map_or_else(zero_digest, |h| h.record_digest),
        content: head.content_head.unwrap_or_else(zero_digest),
        release: head.release_head.unwrap_or_else(zero_digest),
        environment: head.configuration_head.unwrap_or_else(zero_digest),
        outbox: head.policy_head.unwrap_or_else(zero_digest),
    }
}

// ---------------------------------------------------------------------------
// Captured descriptor construction.
// ---------------------------------------------------------------------------

fn build_root_member(
    kind: RemoteEvidenceRootKind,
    content_digest: ContentDigest,
    byte_length: u64,
    delivery: RemoteEvidenceDelivery,
    disclosure_id: Option<String>,
) -> RemoteEvidenceMemberV1 {
    let (member_path, schema_id, schema_version) = root_member_spec(kind);
    RemoteEvidenceMemberV1 {
        member_path: member_path.to_owned(),
        artifact_kind: kind,
        schema_id: schema_id.to_owned(),
        schema_version,
        media_type: "application/json".to_owned(),
        canonicalization: RemoteEvidenceCanonicalization::Rfc8785,
        digest_context: root_digest_context(kind).to_owned(),
        byte_length,
        content_digest,
        delivery,
        disclosure_id,
    }
}

fn component_binding(
    member_path: &str,
    record_digest: ContentDigest,
    digest_context: &str,
    schema_id: &str,
    schema_version: u32,
) -> RemoteEvidenceComponentBindingV1 {
    RemoteEvidenceComponentBindingV1 {
        member_path: member_path.to_owned(),
        record_digest,
        digest_context: digest_context.to_owned(),
        schema_id: schema_id.to_owned(),
        schema_version,
    }
}

// ---------------------------------------------------------------------------
// Bundle descriptor and manifest projection.
// ---------------------------------------------------------------------------

/// Builds the reserved `bundle.json` descriptor from one immutable capture.
pub fn build_bundle_descriptor(
    capture: &EvidenceExportCaptureV2,
) -> Result<RemoteEvidenceBundleV2, ServerError> {
    let manifest = build_manifest(capture)?;
    let manifest_digest = manifest_digest(&manifest)?;
    let artifact_closure = &capture.closure_bindings.artifact_closure;
    let remote_authority = &capture.closure_bindings.remote_authority;

    Ok(RemoteEvidenceBundleV2 {
        r#type: RemoteEvidenceBundleType::Tag,
        api_version: RemoteEvidenceBundleApiVersion::Tag,
        bundle_descriptor_path: BUNDLE_DESCRIPTOR_PATH.to_owned(),
        manifest_member_path: MANIFEST_MEMBER_PATH.to_owned(),
        workspace_id: capture.workspace_id.clone(),
        export_id: capture.export_id.clone(),
        snapshot_id: capture.snapshot_id.clone(),
        snapshot_claim: "unauthenticated producer snapshot label; no current, latest, capture-integrity, or readiness claim"
            .to_owned(),
        snapshot_heads: capture.heads.clone(),
        manifest_digest,
        portable_payload_contract: RemoteEvidencePortablePayloadContractV1 {
            artifact_closure_api_version: artifact_closure.api_version.clone(),
            artifact_closure_member_path: artifact_closure.manifest_member_path.clone(),
            artifact_closure_digest: artifact_closure.manifest_digest,
            artifact_verifier_profile: artifact_closure.verification_profile.clone(),
            remote_record_set_member_path: remote_authority.record_set_member_path.clone(),
            remote_record_set_digest: remote_authority.record_set_digest,
            remote_verifier_profile: remote_authority.verifier_profile.clone(),
            composed_verifier_profile: "proof-verifier/remote-evidence-v2".to_owned(),
            composition: "verify-accepted-artifact-release-closure-p8-remote-authority-and-attempt-companions-then-enforce-cross-links"
                .to_owned(),
            included_bytes_rule: "retain the exact outer manifest, release-artifact closure manifest and every selected accepted artifact, P8 record set and every remote-authority envelope, and all selected actor, authentication, CommandInputV1, and authenticated-command-envelope companion bytes"
                .to_owned(),
            p6_compatibility: "historical AuthorityEvidenceBundleV1 and its verifier remain unchanged and are not relabeled or executed for the remote attempt"
                .to_owned(),
        },
        untrusted_hints: UntrustedHintsV1::inert(),
    })
}

/// Builds the reserved `manifest.json` value from one immutable capture.
pub fn build_manifest(
    capture: &EvidenceExportCaptureV2,
) -> Result<RemoteEvidenceManifestV2, ServerError> {
    Ok(RemoteEvidenceManifestV2 {
        r#type: RemoteEvidenceManifestType::Tag,
        api_version: RemoteEvidenceManifestApiVersion::Tag,
        workspace_id: capture.workspace_id.clone(),
        export_id: capture.export_id.clone(),
        snapshot_id: capture.snapshot_id.clone(),
        snapshot_boundary: capture.snapshot_boundary.clone(),
        capture_digest: capture_digest(capture)?,
        release_id: capture.release_id.clone(),
        release_digest: capture.release_digest,
        closure_bindings: capture.closure_bindings.clone(),
        disclosure_profile: capture.disclosure_profile,
        heads: capture.heads.clone(),
        membership_order: "member_path UTF-8 bytewise ascending".to_owned(),
        membership: capture.membership.clone(),
        disclosure_order: "disclosure_id UTF-8 bytewise ascending".to_owned(),
        disclosures: capture.disclosures.clone(),
    })
}

/// Builds the complete closure bindings from the capture inputs.
///
/// Every verifier-enforced attempt link — identity, command, envelope, public
/// input projection, application key, and environment configuration — is bound
/// from the retained attempt material (the pre-materialized selection plus the
/// stored CommandInputV1/authenticated-command-envelope bytes and the closure
/// entrypoints). The export-caller context appears only in unauthenticated
/// capture metadata (`disclosures`, snapshot heads).
#[allow(clippy::too_many_arguments)]
fn build_closure_bindings(
    workspace_id: &str,
    attempt: &AttemptBindings,
    release_id: &str,
    release_digest: ContentDigest,
    closure_digest: ContentDigest,
    record_set_digest: ContentDigest,
    record_set: &RemoteAuthorityRecordSetV1,
    actor_evidence_digest: ContentDigest,
    authentication_event_digest: ContentDigest,
    command_input_digest: ContentDigest,
    envelope_digest: ContentDigest,
    target_decision_digest: ContentDigest,
    target_consequence_digest: ContentDigest,
    result_digest: ContentDigest,
    release_policy_decision_digest: ContentDigest,
    release_proof_envelope_digest: ContentDigest,
    application_effect_digest: ContentDigest,
    environment_config_digest: ContentDigest,
) -> RemoteEvidenceClosureBindingsV1 {
    RemoteEvidenceClosureBindingsV1 {
        api_version: RemoteEvidenceClosureBindingsApiVersion::Tag,
        artifact_closure: RemoteEvidenceArtifactClosureBindingV1 {
            api_version: "proof.dev/remote-release-artifact-closure/v1".to_owned(),
            manifest_member_path: "content/release-closure.json".to_owned(),
            manifest_digest: closure_digest,
            digest_context: REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT.to_owned(),
            artifact_root_prefix: "content/artifacts/".to_owned(),
            verification_profile: "proof-verifier/accepted-release-artifact-semantics-v1".to_owned(),
            authority_entrypoint:
                "none; remote authority is verified only through closure_bindings.remote_authority"
                    .to_owned(),
        },
        cross_links: RemoteEvidenceCrossLinksV1 {
            workspace_id: workspace_id.to_owned(),
            requesting_principal_id: attempt.requesting_principal_id.clone(),
            operating_principal_id: attempt.operating_principal_id.clone(),
            delegation_id: attempt.delegation_id.clone(),
            presentation_id: attempt.presentation_id.clone(),
            command_digest: command_input_digest,
            authenticated_command_envelope_digest: envelope_digest,
            public_input_projection_digest: attempt.public_input_projection_digest,
            operation: RemoteOperationV1 {
                name: "release.create".to_owned(),
                version: RELEASE_CREATE_VERSION.to_owned(),
            },
            application_key_kind: "required-uuidv7".to_owned(),
            application_key: attempt.application_key.clone(),
            environment_config_digest,
            environment_config_version: 2,
            release_id: release_id.to_owned(),
            release_digest,
            release_policy_decision_digest,
            release_proof_envelope_digest,
            result_digest,
            application_effect_digest,
        },
        remote_authority: RemoteEvidenceAuthorityBindingV1 {
            record_set_member_path: "authority/facts.json".to_owned(),
            record_set_digest,
            digest_context: REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT.to_owned(),
            head: record_set.included_head,
            target_decision_digest,
            target_consequence_digest,
            verifier_profile: "proof-verifier/remote-authority/v1".to_owned(),
        },
        remote_attempt_companions: RemoteEvidenceAttemptCompanionsBindingV1 {
            profile: ATTEMPT_COMPANIONS_PROFILE.to_owned(),
            actor_context_evidence: component_binding(
                "actor/context-evidence.json",
                actor_evidence_digest,
                AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
                "proof.authenticated-actor-context-evidence/v2",
                2,
            ),
            authentication_event: component_binding(
                "authentication/event.json",
                authentication_event_digest,
                REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
                "proof.remote-authentication-event/v1",
                1,
            ),
            command_input: component_binding(
                "attempt/command-input.json",
                command_input_digest,
                "proof:command:v1",
                "proof.command-input/v1",
                1,
            ),
            authenticated_command_envelope: component_binding(
                "attempt/authenticated-command-envelope.json",
                envelope_digest,
                "proof:authenticated-command-envelope:v1",
                "proof.authenticated-command-envelope/v1",
                1,
            ),
            public_input_projection_rule:
                "reconstruct proof.dev/public-operation-input-projection/v1 from exact CommandInputV1.normalized_input and release.create/v2 operation, then recompute proof:public-operation-input-projection:v1"
                    .to_owned(),
            result_rule:
                "reconstruct exact ReleaseCreateOutputV2 from the artifact closure target ReleaseV2 and target Release Proof envelope digest, then recompute proof:operation-effect:v1"
                    .to_owned(),
            application_effect_rule:
                "application_effect_digest equals the artifact closure target ReleaseV2 digest under proof:release:v2"
                    .to_owned(),
        },
    }
}

// ---------------------------------------------------------------------------
// Pre-materialized selection and capture assembly.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct ExportMaterial {
    release_id: String,
    release_digest: ContentDigest,
    closure_digest: ContentDigest,
    record_set_digest: ContentDigest,
    actor_evidence_digest: ContentDigest,
    authentication_event_digest: ContentDigest,
    command_input_digest: ContentDigest,
    envelope_digest: ContentDigest,
    target_decision_digest: ContentDigest,
    target_consequence_digest: ContentDigest,
    result_digest: ContentDigest,
    release_policy_decision_digest: ContentDigest,
}

impl ExportMaterial {
    fn parse(value: &Value) -> Result<Self, ServerError> {
        let field = |name: &str| -> Result<String, ServerError> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    ServerError::Internal(format!("export material is missing `{name}`"))
                })
        };
        let digest = |name: &str| -> Result<ContentDigest, ServerError> {
            field(name)?.parse().map_err(|error| {
                ServerError::Internal(format!("export material `{name}` is not a digest: {error}"))
            })
        };
        Ok(Self {
            release_id: field("release_id")?,
            release_digest: digest("release_digest")?,
            closure_digest: digest("release_artifact_closure_digest")?,
            record_set_digest: digest("authority_record_set_digest")?,
            actor_evidence_digest: digest("actor_context_evidence_digest")?,
            authentication_event_digest: digest("authentication_event_digest")?,
            command_input_digest: digest("command_input_digest")?,
            envelope_digest: digest("authenticated_command_envelope_digest")?,
            target_decision_digest: digest("target_decision_digest")?,
            target_consequence_digest: digest("target_consequence_digest")?,
            result_digest: digest("result_digest")?,
            release_policy_decision_digest: digest("release_policy_decision_digest")?,
        })
    }
}

/// Attempt-binding fields of `cross_links`, derived from the retained attempt
/// companions rather than the export caller (contract §"Evidence export and
/// independent verification": identity, command, projection, and
/// application-key links bind the exported attempt).
#[derive(Clone, Debug)]
struct AttemptBindings {
    requesting_principal_id: String,
    operating_principal_id: String,
    delegation_id: String,
    presentation_id: String,
    application_key: String,
    public_input_projection_digest: ContentDigest,
}

/// Derives the attempt bindings from the stored CommandInputV1 bytes and the
/// signed authenticated-command DSSE envelope bytes addressed by the capture's
/// pre-materialized selection. No trust decision is made here; the independent
/// verifier re-derives and enforces every link against the embedded bytes.
fn attempt_bindings(
    command_input_bytes: &[u8],
    envelope_bytes: &[u8],
) -> Result<AttemptBindings, ServerError> {
    let command_input: CommandInputV1 = serde_json::from_slice(command_input_bytes)
        .map_err(|error| ServerError::Internal(format!("invalid stored command input: {error}")))?;
    let envelope = parse_authority_envelope::<AuthenticatedCommandV1>(
        envelope_bytes,
        AuthorityPayloadProfile::AuthenticatedCommand,
    )
    .map_err(|error| ServerError::Internal(format!("invalid stored command envelope: {error}")))?;

    let operation = RemoteOperationV1 {
        name: command_input.operation.name().to_owned(),
        version: command_input.operation.version().to_owned(),
    };
    let normalized_input = Value::Object(command_input.normalized_input.clone());
    let public_input_projection_digest =
        public_operation_input_projection_digest(&normalized_input, &operation)
            .map_err(|error| ServerError::Internal(error.to_string()))?;
    let application_key = command_input
        .idempotency_key
        .as_ref()
        .map(ToString::to_string)
        .ok_or_else(|| {
            ServerError::Internal(
                "stored command input lacks the required UUIDv7 application key".to_owned(),
            )
        })?;

    Ok(AttemptBindings {
        requesting_principal_id: command_input.requesting_principal_id.to_string(),
        operating_principal_id: command_input.operating_principal_id.to_string(),
        delegation_id: command_input.delegation_id.to_string(),
        presentation_id: envelope.payload.presentation_id.to_string(),
        application_key,
        public_input_projection_digest,
    })
}

fn build_complete_membership(
    closure: &RemoteReleaseArtifactClosureV1,
    record_set: &RemoteAuthorityRecordSetV1,
    closure_bytes_len: u64,
    record_set_bytes_len: u64,
    actor_len: u64,
    auth_len: u64,
    command_len: u64,
    envelope_len: u64,
    material: &ExportMaterial,
) -> Result<Vec<RemoteEvidenceMemberV1>, ServerError> {
    let closure_digest = closure_digest(closure)?;
    let record_set_digest = record_set_digest(record_set)?;
    let mut members = vec![
        build_root_member(
            RemoteEvidenceRootKind::ReleaseArtifactClosure,
            closure_digest,
            closure_bytes_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
        build_root_member(
            RemoteEvidenceRootKind::AuthorityFact,
            record_set_digest,
            record_set_bytes_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
        build_root_member(
            RemoteEvidenceRootKind::RemoteActorEvidence,
            material.actor_evidence_digest,
            actor_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
        build_root_member(
            RemoteEvidenceRootKind::RemoteAuthenticationEvent,
            material.authentication_event_digest,
            auth_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
        build_root_member(
            RemoteEvidenceRootKind::RemoteCommandInput,
            material.command_input_digest,
            command_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
        build_root_member(
            RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope,
            material.envelope_digest,
            envelope_len,
            RemoteEvidenceDelivery::Included,
            None,
        ),
    ];
    members.sort_by(|a, b| a.member_path.cmp(&b.member_path));
    Ok(members)
}

fn build_disclosures(
    decision: &RemoteAuthorizationDecisionV1,
) -> Vec<RemoteEvidenceDisclosureRequirementV1> {
    vec![RemoteEvidenceDisclosureRequirementV1 {
        disclosure_id: SUBJECT_OPENING_DISCLOSURE_ID.to_owned(),
        kind: RemoteEvidenceDisclosureKind::OidcSubjectOpening,
        commitment_digest: decision.requesting_subject_commitment,
    }]
}

#[allow(clippy::too_many_arguments)]
fn build_capture(
    decision: &RemoteAuthorizationDecisionV1,
    idempotency_key: &str,
    release_id: &str,
    release_digest: ContentDigest,
    head: &WorkspaceHeadSnapshot,
    material: &ExportMaterial,
    attempt: &AttemptBindings,
    closure: &RemoteReleaseArtifactClosureV1,
    record_set: &RemoteAuthorityRecordSetV1,
    closure_bytes_len: u64,
    record_set_bytes_len: u64,
    actor_len: u64,
    auth_len: u64,
    command_len: u64,
    envelope_len: u64,
) -> Result<EvidenceExportCaptureV2, ServerError> {
    let export_id = uuid::Uuid::now_v7();
    let snapshot_id = format!("snapshot_{}", export_id.simple());
    let closure_digest = closure_digest(closure)?;
    let record_set_digest = record_set_digest(record_set)?;
    let release_proof_envelope_digest = closure.entrypoints.target_release_proof_envelope.digest;
    let application_effect_digest = closure.entrypoints.application_effect.digest;
    let environment_config_digest = closure.entrypoints.target_environment_config.digest;
    let closure_bindings = build_closure_bindings(
        &decision.workspace_id,
        attempt,
        release_id,
        release_digest,
        closure_digest,
        record_set_digest,
        record_set,
        material.actor_evidence_digest,
        material.authentication_event_digest,
        material.command_input_digest,
        material.envelope_digest,
        material.target_decision_digest,
        material.target_consequence_digest,
        material.result_digest,
        material.release_policy_decision_digest,
        release_proof_envelope_digest,
        application_effect_digest,
        environment_config_digest,
    );
    let membership = build_complete_membership(
        closure,
        record_set,
        closure_bytes_len,
        record_set_bytes_len,
        actor_len,
        auth_len,
        command_len,
        envelope_len,
        material,
    )?;
    let disclosures = build_disclosures(decision);

    Ok(EvidenceExportCaptureV2 {
        r#type: EvidenceExportCaptureType::Tag,
        api_version: EvidenceExportCaptureApiVersion::Tag,
        workspace_id: decision.workspace_id.clone(),
        export_id: export_id.to_string(),
        idempotency_key: idempotency_key.to_owned(),
        release_id: release_id.to_owned(),
        release_digest,
        closure_bindings,
        disclosure_profile: RemoteEvidenceDisclosureProfile::CompletePortable,
        transaction_isolation: "SERIALIZABLE READ WRITE".to_owned(),
        captured_at: now_timestamp()?,
        snapshot_id,
        snapshot_boundary: CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS.to_owned(),
        heads: project_heads(head),
        membership_order: "member_path UTF-8 bytewise ascending".to_owned(),
        membership,
        disclosure_order: "disclosure_id UTF-8 bytewise ascending".to_owned(),
        disclosures,
        build_event_count: 1,
        state_after_commit: "pending".to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Transaction persistence macros. `postgres::Transaction` cannot be named in
// this crate, so the SQL bodies expand inline at each use site.
// ---------------------------------------------------------------------------

macro_rules! read_auth_sequence_in_tx {
    ($tx:expr) => {{
        let value: i64 = $tx
            .query_one(
                "SELECT authority_sequence FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?
            .get(0);
        u64::try_from(value)
            .map_err(|_| PgError::Integrity("authority sequence is negative".to_owned()))
    }};
}

macro_rules! persist_decision_in_tx {
    ($tx:expr, $decision:expr) => {{
        let value =
            serde_json::to_value($decision).map_err(|e| PgError::Integrity(e.to_string()))?;
        let body = proof_canonical::canonicalize(&value)
            .map(|c| c.as_bytes().to_vec())
            .map_err(|e| PgError::Integrity(e.to_string()))?;
        let seq = i64::try_from($decision.authority_sequence)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "INSERT INTO authorization_decisions (
                 authority_sequence, workspace_id, decision_digest, operation, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, now())",
            &[
                &seq,
                &$decision.workspace_id,
                &decision_digest($decision).to_string(),
                &$decision.operation.name,
                &body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_fact_in_tx {
    ($tx:expr, $fact_id:expr, $fact_kind:expr, $workspace_id:expr, $auth_seq:expr, $fact_digest:expr, $body:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, now())",
            &[
                &$fact_id,
                &$workspace_id,
                &$fact_kind,
                &seq,
                &$fact_digest.to_string(),
                &$body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_consequence_in_tx {
    ($tx:expr, $consequence:expr, $auth_seq:expr) => {{
        let value =
            serde_json::to_value($consequence).map_err(|e| PgError::Integrity(e.to_string()))?;
        let body = proof_canonical::canonicalize(&value)
            .map(|c| c.as_bytes().to_vec())
            .map_err(|e| PgError::Integrity(e.to_string()))?;
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        let effect = $consequence
            .application_effect_digest
            .map(|d| d.to_string());
        $tx.execute(
            "INSERT INTO application_consequences (
                 authority_sequence, workspace_id, consequence_digest, operation,
                 application_effect_digest, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, now())",
            &[
                &seq,
                &$consequence.workspace_id,
                &consequence_digest($consequence).to_string(),
                &$consequence.operation.name,
                &effect,
                &body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_idempotency_in_tx {
    ($tx:expr, $candidate:expr, $key_kind:expr, $result_digest:expr) => {{
        $tx.execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, key_kind,
                 result_digest, replay_count, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, now())",
            &[
                &$candidate.workspace_id.to_string(),
                &$candidate.operation.name,
                &$candidate.operation.version,
                &$candidate.normalized_input_digest.to_string(),
                &$candidate.requesting_principal.to_string(),
                &$candidate.operating_principal.to_string(),
                &$candidate.delegation.map(|d| d.to_string()),
                &key_kind_label($key_kind),
                &$result_digest.to_string(),
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! advance_authority_head_in_tx {
    ($tx:expr, $digest:expr, $auth_seq:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "UPDATE workspace_write_head
             SET authority_head_digest = $1, authority_head_sequence = $2
             WHERE singleton = 1",
            &[&$digest.to_string(), &seq],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! read_status_in_tx {
    ($tx:expr, $export_id:expr) => {{
        let capture = $tx
            .query_opt(
                "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'evidence_export_capture'",
                &[&format!("evidence_export_capture/{}", $export_id)],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
        if capture.is_none() {
            None
        } else {
            let ready = $tx
                .query_opt(
                    "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'evidence_export_ready'",
                    &[&format!("evidence_export_ready/{}", $export_id)],
                )
                .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
            match ready {
                None => Some(EvidenceExportStatusV1 {
                    api_version: EvidenceExportStatusApiVersion::Tag,
                    export_id: $export_id.to_owned(),
                    status: EvidenceExportStatusKind::Pending,
                    bundle_descriptor_digest: None,
                    manifest_digest: None,
                    artifact_count: 0,
                    total_included_bytes: 0,
                }),
                Some(row) => {
                    let bytes: Vec<u8> = row.get(0);
                    Some(serde_json::from_slice(&bytes).map_err(|error| {
                        PgError::Integrity(format!("invalid stored ready status: {error}"))
                    })?)
                }
            }
        }
    }};
}

macro_rules! commit_export_failure_in_tx {
    ($tx:expr, $decision:expr, $operation:expr, $problem_code:expr, $auth_seq:expr, $built:expr) => {{
        let failure = failure_consequence($decision, $operation, $problem_code, $auth_seq)
            .map_err(|error| PgError::Idempotency(error.to_string()))?;
        persist_decision_in_tx!($tx, $decision);
        persist_consequence_in_tx!($tx, &failure, $auth_seq);
        advance_authority_head_in_tx!($tx, &consequence_digest(&failure), $auth_seq);
        *$built.borrow_mut() = Some(failure);
        return Err(PgError::Idempotency($problem_code.to_owned()));
    }};
}

// ---------------------------------------------------------------------------
// Pure helpers.
// ---------------------------------------------------------------------------

fn decision_digest(decision: &RemoteAuthorizationDecisionV1) -> ContentDigest {
    RemoteAuthorityRecordV1::authorization_decision(decision.clone()).digest()
}

fn consequence_digest(consequence: &RemoteApplicationConsequenceV1) -> ContentDigest {
    RemoteAuthorityRecordV1::application_consequence(consequence.clone()).digest()
}

fn key_kind_label(kind: ApplicationKeyKind) -> &'static str {
    match kind {
        ApplicationKeyKind::RequiredUuidV7 => "required-uuidv7",
        ApplicationKeyKind::None => "none",
        ApplicationKeyKind::DerivedChangeset
        | ApplicationKeyKind::DerivedProposalPolicyValidator => "derived",
    }
}

fn actor_principals(context: &AuthenticatedActorContextV2) -> (String, String, Option<String>) {
    match context {
        AuthenticatedActorContextV2::Human(human) => (
            human.requesting_principal_id.clone(),
            human.requesting_principal_id.clone(),
            None,
        ),
        AuthenticatedActorContextV2::HumanAgent(agent) => (
            agent.requesting_principal_id.clone(),
            agent.operating_principal_id.clone(),
            Some(agent.delegation_id.clone()),
        ),
    }
}

fn parse_workspace_id(value: &str) -> Result<proof_domain::WorkspaceId, ServerError> {
    value
        .parse()
        .map_err(|_| ServerError::Authorization("invalid Workspace identity".to_owned()))
}

fn parse_principal_id(value: &str) -> Result<proof_domain::PrincipalId, ServerError> {
    value
        .parse()
        .map_err(|_| ServerError::Authorization("invalid Principal identity".to_owned()))
}

fn required_input_str<'a>(input: &'a Value, field: &str) -> Result<&'a str, ServerError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Dispatch(format!("normalized input is missing `{field}`")))
}

fn lock_pg(
    state: &AppState,
) -> Result<std::sync::MutexGuard<'_, Option<proof_pg::wiring::PgRuntime>>, ServerError> {
    state
        .pg
        .lock()
        .map_err(|_| ServerError::Internal("PostgreSQL runtime lock is poisoned".to_owned()))
}

fn runtime_mut<'a>(
    guard: &'a mut std::sync::MutexGuard<'_, Option<proof_pg::wiring::PgRuntime>>,
) -> Result<&'a mut proof_pg::wiring::PgRuntime, ServerError> {
    guard.as_mut().ok_or_else(|| {
        ServerError::Storage(PgError::Connect(
            "PostgreSQL runtime is not connected".to_owned(),
        ))
    })
}

fn read_idempotency_prior(
    runtime: &mut proof_pg::wiring::PgRuntime,
    candidate: &IdempotencyTupleV1,
) -> Result<(Option<IdempotencyTupleV1>, Option<ContentDigest>), ServerError> {
    let row = runtime
        .client_mut()
        .query_opt(
            "SELECT normalized_input_digest, delegation_id, result_digest
             FROM idempotency_keys
             WHERE workspace_id = $1 AND operation = $2 AND operation_version = $3
               AND requesting_principal = $4 AND operating_principal = $5
             ORDER BY committed_at DESC
             LIMIT 1",
            &[
                &candidate.workspace_id.to_string(),
                &candidate.operation.name,
                &candidate.operation.version,
                &candidate.requesting_principal.to_string(),
                &candidate.operating_principal.to_string(),
            ],
        )
        .map_err(|error| {
            ServerError::Storage(PgError::Idempotency(format!(
                "idempotency lookup failed: {error}"
            )))
        })?;
    let Some(row) = row else {
        return Ok((None, None));
    };
    let normalized_input_digest: String = row.get(0);
    let delegation: Option<String> = row.get(1);
    let result_digest: String = row.get(2);
    let prior = IdempotencyTupleV1 {
        workspace_id: candidate.workspace_id,
        operation: candidate.operation.clone(),
        normalized_input_digest: normalized_input_digest.parse().map_err(|error| {
            ServerError::Internal(format!("invalid stored input digest: {error}"))
        })?,
        requesting_principal: candidate.requesting_principal,
        operating_principal: candidate.operating_principal,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Internal("invalid stored Delegation identity".to_owned()))?,
    };
    let prior_result_digest = result_digest
        .parse()
        .map_err(|error| ServerError::Internal(format!("invalid stored result digest: {error}")))?;
    Ok((Some(prior), Some(prior_result_digest)))
}

#[allow(clippy::too_many_arguments)]
fn success_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    application_key: Option<String>,
    key_kind: ApplicationKeyKind,
    result: &Value,
    application_effect_digest: Option<ContentDigest>,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let result_digest = operation_effect_digest(result)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::Success,
        key_kind,
        application_key,
        Some(result_digest),
        None,
        application_effect_digest,
        None,
        None,
        auth_seq,
        decision_digest(decision),
    ))
}

/// Builds one authorized application-failure consequence.
fn failure_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    problem_code: &str,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let problem_digest = application_problem_digest_preimage(problem_code, operation)
        .map_err(|error| ServerError::Dispatch(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::ApplicationFailure,
        ApplicationKeyKind::None,
        None,
        Some(problem_digest),
        None,
        None,
        None,
        Some(problem_code.to_owned()),
        auth_seq,
        decision_digest(decision),
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    outcome: ApplicationConsequenceOutcome,
    key_kind: ApplicationKeyKind,
    application_key: Option<String>,
    result_digest: Option<ContentDigest>,
    prior_result_digest: Option<ContentDigest>,
    application_effect_digest: Option<ContentDigest>,
    application_effect_authority_head: Option<AuthorityHeadV1>,
    problem_code: Option<String>,
    authority_sequence: u64,
    previous_authority_record_digest: ContentDigest,
) -> RemoteApplicationConsequenceV1 {
    let mut consequence = RemoteApplicationConsequenceV1 {
        api_version: RemoteApplicationConsequenceApiVersion::V1,
        workspace_id: decision.workspace_id.clone(),
        consequence_id: uuid::Uuid::now_v7().to_string(),
        decision_id: decision.decision_id.clone(),
        decision_digest: decision_digest(decision),
        public_input_projection_digest: decision.public_input_projection_digest,
        operation: operation.clone(),
        operation_registry_sha256: decision.operation_registry_sha256.clone(),
        outcome,
        application_key_kind: key_kind,
        application_key,
        result_digest,
        prior_result_digest,
        application_effect_digest,
        application_effect_authority_head,
        problem_code,
        recorded_at: now_timestamp().expect("the system clock always produces a timestamp"),
        evaluated_authority_head: decision.evaluated_authority_head,
        authority_sequence,
        previous_authority_record_digest,
        authority_key_id: decision.authority_key_id.clone(),
    };
    consequence.copy_decision_binding(decision);
    consequence
}

fn replay_consequence(
    decision: RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    prior_result_digest: Option<ContentDigest>,
) -> RemoteApplicationConsequenceV1 {
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotentReplay,
        ApplicationKeyKind::None,
        None,
        prior_result_digest,
        prior_result_digest,
        None,
        None,
        None,
        decision.authority_sequence,
        decision.previous_authority_record_digest,
    )
}

fn conflict_consequence(
    decision: RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    prior_result_digest: Option<ContentDigest>,
) -> RemoteApplicationConsequenceV1 {
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotencyConflict,
        ApplicationKeyKind::None,
        None,
        prior_result_digest,
        prior_result_digest,
        None,
        None,
        Some("proof.idempotency.key_reused".to_owned()),
        decision.authority_sequence,
        decision.previous_authority_record_digest,
    )
}

/// Reads one `facts` body by exact `fact_id` and `fact_kind`.
fn read_fact(
    runtime: &mut proof_pg::wiring::PgRuntime,
    fact_id: &str,
    fact_kind: &str,
) -> Result<Option<Vec<u8>>, ServerError> {
    let row = runtime
        .client_mut()
        .query_opt(
            "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = $2",
            &[&fact_id, &fact_kind],
        )
        .map_err(|error| {
            ServerError::Storage(PgError::Integrity(format!("fact lookup failed: {error}")))
        })?;
    Ok(row.map(|row| row.get::<_, Vec<u8>>(0)))
}

/// Reads one artifact body by exact `(kind, digest)`.
fn read_artifact_body(
    runtime: &mut proof_pg::wiring::PgRuntime,
    kind: &str,
    digest: &ContentDigest,
) -> Result<Option<Vec<u8>>, ServerError> {
    let row = runtime
        .client_mut()
        .query_opt(
            "SELECT body FROM artifact_body_pg WHERE kind = $1 AND digest = $2",
            &[&kind, &digest.to_string()],
        )
        .map_err(|error| {
            ServerError::Storage(PgError::Artifact(format!(
                "artifact lookup failed: {error}"
            )))
        })?;
    Ok(row.map(|row| row.get::<_, Vec<u8>>(0)))
}

fn read_material(
    runtime: &mut proof_pg::wiring::PgRuntime,
    release_id: &str,
) -> Result<ExportMaterial, ServerError> {
    let fact_id = format!("release_export_material/{release_id}");
    let bytes = read_fact(runtime, &fact_id, MATERIAL_FACT_KIND)?
        .ok_or_else(|| ServerError::Internal("release export material is absent".to_owned()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ServerError::Internal(format!("malformed export material: {error}")))?;
    ExportMaterial::parse(&value)
}

fn read_closure(
    runtime: &mut proof_pg::wiring::PgRuntime,
    material: &ExportMaterial,
) -> Result<(RemoteReleaseArtifactClosureV1, Vec<u8>), ServerError> {
    let bytes = read_artifact_body(
        runtime,
        "release-artifact-closure",
        &material.closure_digest,
    )?
    .ok_or_else(|| ServerError::Internal("release-artifact closure bytes are absent".to_owned()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ServerError::Internal(format!("malformed release closure: {error}")))?;
    let closure: RemoteReleaseArtifactClosureV1 = serde_json::from_value(value)
        .map_err(|error| ServerError::Internal(format!("invalid release closure: {error}")))?;
    let canonical = canonical_bytes(
        &serde_json::to_value(&closure)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    if raw_digest(REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, &canonical)
        != material.closure_digest
    {
        return Err(ServerError::Internal(
            "release-artifact closure digest mismatch".to_owned(),
        ));
    }
    Ok((closure, canonical))
}

fn read_record_set(
    runtime: &mut proof_pg::wiring::PgRuntime,
    material: &ExportMaterial,
) -> Result<(RemoteAuthorityRecordSetV1, Vec<u8>), ServerError> {
    let bytes = read_artifact_body(runtime, "authority-fact", &material.record_set_digest)?
        .ok_or_else(|| ServerError::Internal("authority record-set bytes are absent".to_owned()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ServerError::Internal(format!("malformed record set: {error}")))?;
    let record_set: RemoteAuthorityRecordSetV1 = serde_json::from_value(value)
        .map_err(|error| ServerError::Internal(format!("invalid record set: {error}")))?;
    let canonical = canonical_bytes(
        &serde_json::to_value(&record_set)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    if raw_digest(REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT, &canonical)
        != material.record_set_digest
    {
        return Err(ServerError::Internal(
            "authority record-set digest mismatch".to_owned(),
        ));
    }
    Ok((record_set, canonical))
}

fn read_companion_bytes(
    runtime: &mut proof_pg::wiring::PgRuntime,
    kind: &str,
    digest: &ContentDigest,
) -> Result<Vec<u8>, ServerError> {
    read_artifact_body(runtime, kind, digest)?
        .ok_or_else(|| ServerError::Internal(format!("companion `{kind}` bytes are absent")))
}

fn companion_len(bytes: &[u8]) -> Result<u64, ServerError> {
    u64::try_from(bytes.len())
        .map_err(|_| ServerError::Internal("companion byte length exceeds u64".to_owned()))
}

fn read_result_preimage(
    runtime: &mut proof_pg::wiring::PgRuntime,
    idempotency_key: &str,
) -> Result<Option<Vec<u8>>, ServerError> {
    read_fact(
        runtime,
        &format!("evidence_export_result/{idempotency_key}"),
        RESULT_FACT_KIND,
    )
}

fn read_status(
    runtime: &mut proof_pg::wiring::PgRuntime,
    export_id: &str,
) -> Result<EvidenceExportStatusV1, ServerError> {
    let capture = read_fact(
        runtime,
        &format!("evidence_export_capture/{export_id}"),
        CAPTURE_FACT_KIND,
    )?;
    if capture.is_none() {
        return Err(ServerError::Dispatch(format!(
            "{PROBLEM_RESOURCE_NOT_FOUND}: unknown export"
        )));
    }
    let ready = read_fact(
        runtime,
        &format!("evidence_export_ready/{export_id}"),
        READY_FACT_KIND,
    )?;
    let Some(ready) = ready else {
        return Ok(EvidenceExportStatusV1 {
            api_version: EvidenceExportStatusApiVersion::Tag,
            export_id: export_id.to_owned(),
            status: EvidenceExportStatusKind::Pending,
            bundle_descriptor_digest: None,
            manifest_digest: None,
            artifact_count: 0,
            total_included_bytes: 0,
        });
    };
    serde_json::from_slice(&ready)
        .map_err(|error| ServerError::Internal(format!("invalid stored ready status: {error}")))
}

// ---------------------------------------------------------------------------
// `evidence.export/v2` — immutable keyed capture.
// ---------------------------------------------------------------------------

fn execute_export_create(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(EvidenceExportResultV2, RemoteApplicationConsequenceV1), ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial(state, decision)?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }

    let idempotency_key = required_input_str(normalized_input, "idempotency_key")?.to_owned();
    let release_id = required_input_str(normalized_input, "release_id")?.to_owned();
    let release_digest: ContentDigest = required_input_str(normalized_input, "release_digest")?
        .parse()
        .map_err(|error| ServerError::Dispatch(format!("invalid release_digest: {error}")))?;

    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    // Pre-materialize the aggregate-root and companion bytes outside the
    // serializable transaction (they are immutable and content-addressed); the
    // capture heads are selected inside the locked transaction.
    let material = read_material(runtime, &release_id)?;
    let (closure, closure_bytes) = read_closure(runtime, &material)?;
    let (record_set, record_set_bytes) = read_record_set(runtime, &material)?;
    let closure_bytes_len = u64::try_from(closure_bytes.len())
        .map_err(|_| ServerError::Internal("closure too large".to_owned()))?;
    let record_set_bytes_len = u64::try_from(record_set_bytes.len())
        .map_err(|_| ServerError::Internal("record set too large".to_owned()))?;
    let actor_bytes = read_companion_bytes(
        runtime,
        "remote-actor-evidence",
        &material.actor_evidence_digest,
    )?;
    let auth_bytes = read_companion_bytes(
        runtime,
        "remote-authentication-event",
        &material.authentication_event_digest,
    )?;
    let command_input_bytes = read_companion_bytes(
        runtime,
        "remote-command-input",
        &material.command_input_digest,
    )?;
    let envelope_bytes = read_companion_bytes(
        runtime,
        "remote-authenticated-command-envelope",
        &material.envelope_digest,
    )?;
    let actor_len = companion_len(&actor_bytes)?;
    let auth_len = companion_len(&auth_bytes)?;
    let command_len = companion_len(&command_input_bytes)?;
    let envelope_len = companion_len(&envelope_bytes)?;

    // The exported attempt identities, projection digest, and application key
    // derive from the retained attempt companions before any transaction work.
    let attempt = attempt_bindings(&command_input_bytes, &envelope_bytes)?;

    let (requesting_principal, operating_principal, delegation) = actor_principals(actor_context);
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(normalized_input, operation)
            .map_err(|error| ServerError::Internal(error.to_string()))?;
    let candidate = IdempotencyTupleV1 {
        workspace_id: parse_workspace_id(&decision.workspace_id)?,
        operation: operation.clone(),
        normalized_input_digest,
        requesting_principal: parse_principal_id(&requesting_principal)?,
        operating_principal: parse_principal_id(&operating_principal)?,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Authorization("invalid Delegation identity".to_owned()))?,
    };
    let (prior, prior_result_digest) = read_idempotency_prior(runtime, &candidate)?;

    let decision_owned = decision.clone();
    let operation_owned = operation.clone();
    let idempotency_key_owned = idempotency_key.clone();
    let release_id_owned = release_id;

    let head_snapshot: Rc<RefCell<Option<WorkspaceHeadSnapshot>>> = Rc::new(RefCell::new(None));
    let head_for_hook = Rc::clone(&head_snapshot);
    let built_result: Rc<RefCell<Option<EvidenceExportResultV2>>> = Rc::new(RefCell::new(None));
    let built_result_for_hook = Rc::clone(&built_result);
    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let decision_for_hook = decision_owned.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision_owned.evaluated_authority_head;
            Box::new(move |head: &WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    *head_for_hook.borrow_mut() = Some(head.clone());
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: {
            let candidate_for_hook = candidate.clone();
            let prior_for_hook = prior.clone();
            Box::new(move |_head| {
                Ok(replay_or_conflict(
                    &candidate_for_hook,
                    prior_for_hook.as_ref(),
                ))
            })
        },
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let head = head_snapshot.borrow().clone().ok_or_else(|| {
                PgError::Integrity("locked head snapshot was not captured".to_owned())
            })?;

            let capture = build_capture(
                &decision_for_hook,
                &idempotency_key_owned,
                &release_id_owned,
                release_digest,
                &head,
                &material,
                &attempt,
                &closure,
                &record_set,
                closure_bytes_len,
                record_set_bytes_len,
                actor_len,
                auth_len,
                command_len,
                envelope_len,
            )
            .map_err(|error| PgError::Integrity(error.to_string()))?;
            let capture_bytes = serde_json::to_value(&capture)
                .map_err(|e| PgError::Integrity(e.to_string()))
                .and_then(|value| {
                    proof_canonical::canonicalize(&value)
                        .map(|c| c.as_bytes().to_vec())
                        .map_err(|e| PgError::Integrity(e.to_string()))
                })?;
            let capture_digest =
                capture_digest(&capture).map_err(|error| PgError::Integrity(error.to_string()))?;

            let result = EvidenceExportResultV2 {
                api_version: EvidenceExportResultApiVersion::Tag,
                export_id: capture.export_id.clone(),
                application_key: idempotency_key_owned.clone(),
                capture_digest,
                status: EvidenceExportStatusKind::Pending,
            };
            let result_value =
                serde_json::to_value(&result).map_err(|e| PgError::Integrity(e.to_string()))?;
            let result_bytes = proof_canonical::canonicalize(&result_value)
                .map(|c| c.as_bytes().to_vec())
                .map_err(|e| PgError::Integrity(e.to_string()))?;
            let consequence = success_consequence(
                &decision_for_hook,
                &operation_owned,
                Some(idempotency_key_owned.clone()),
                ApplicationKeyKind::RequiredUuidV7,
                &result_value,
                Some(capture_digest),
                auth_seq,
            )
            .map_err(|error| PgError::Idempotency(error.to_string()))?;

            let workspace_id = capture.workspace_id.clone();
            let result_digest = consequence
                .result_digest
                .expect("a success consequence always carries a result digest");

            persist_decision_in_tx!(tx, &decision_for_hook);
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_fact_in_tx!(
                    sp,
                    format!("evidence_export_capture/{}", capture.export_id),
                    CAPTURE_FACT_KIND,
                    workspace_id,
                    auth_seq,
                    capture_digest,
                    capture_bytes
                );
                persist_fact_in_tx!(
                    sp,
                    format!("evidence_export_result/{idempotency_key_owned}"),
                    RESULT_FACT_KIND,
                    capture.workspace_id,
                    auth_seq,
                    unique_fact_digest(&result_bytes),
                    result_bytes
                );
                persist_consequence_in_tx!(sp, &consequence, auth_seq);
                persist_idempotency_in_tx!(
                    sp,
                    &candidate,
                    ApplicationKeyKind::RequiredUuidV7,
                    &result_digest
                );
                advance_authority_head_in_tx!(sp, &consequence_digest(&consequence), auth_seq);
            }
            savepoint.release()?;
            *built_result_for_hook.borrow_mut() = Some(result);
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let outcome =
        run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;

    match outcome {
        UnitOfWorkOutcome::Committed | UnitOfWorkOutcome::ApplicationFailureCommitted => {
            let consequence = built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))?;
            let result = built_result.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("create-result was not produced".to_owned())
            })?;
            Ok((result, consequence))
        }
        UnitOfWorkOutcome::Replayed => {
            let result_bytes =
                read_result_preimage(runtime, &idempotency_key)?.ok_or_else(|| {
                    ServerError::Internal("create-result preimage is absent".to_owned())
                })?;
            let result: EvidenceExportResultV2 =
                serde_json::from_slice(&result_bytes).map_err(|error| {
                    ServerError::Internal(format!("invalid stored result: {error}"))
                })?;
            let consequence = replay_consequence(decision_owned, operation, prior_result_digest);
            Ok((result, consequence))
        }
        UnitOfWorkOutcome::ConflictCommitted => {
            let _consequence = conflict_consequence(decision_owned, operation, prior_result_digest);
            Err(ServerError::Dispatch(
                "idempotency key reused with changed input".to_owned(),
            ))
        }
    }
}

/// `evidence.export/v2`: commits one immutable [`EvidenceExportCaptureV2`] in a
/// short serializable transaction with the `pre-export-attempt-locked-heads`
/// capture boundary and always returns the keyed pending result (contract
/// §"Evidence export and independent verification").
///
/// Every same-key equivalent replay returns the same create-result bytes, even
/// after assembly finishes.
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// consequence failure.
pub fn evidence_export_v2(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<EvidenceExportResultV2, ServerError> {
    execute_export_create(state, operation, normalized_input, actor_context, decision)
        .map(|(result, _consequence)| result)
}

/// Consequence-returning entrypoint for `evidence.export/v2`, used by the
/// dispatch executor (the HTTP success envelope carries the consequence whose
/// `result_digest` binds the exact [`EvidenceExportResultV2`]).
pub fn evidence_export_v2_execute(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    execute_export_create(state, operation, normalized_input, actor_context, decision)
        .map(|(_result, consequence)| consequence)
}

/// Commits a signed denial decision alone (mirrors `crate::operations`).
fn commit_denial(
    state: &AppState,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let decision = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(move |head: &WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: Box::new(|_head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            persist_decision_in_tx!(tx, &decision);
            advance_authority_head_in_tx!(tx, &decision_digest(&decision), auth_seq);
            Ok(())
        }),
    };

    run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `evidence.export.get/v1` — no-key lifecycle status read.
// ---------------------------------------------------------------------------

fn execute_export_get(
    state: &AppState,
    operation: &RemoteOperationV1,
    export_id: &str,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(EvidenceExportStatusV1, RemoteApplicationConsequenceV1), ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial(state, decision)?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }
    let _ = actor_context;

    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let decision_owned = decision.clone();
    let operation_owned = operation.clone();
    let export_id_owned = export_id.to_owned();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let decision_for_hook = decision_owned.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision_owned.evaluated_authority_head;
            Box::new(move |head: &WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: Box::new(|_head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let Some(status) = read_status_in_tx!(tx, export_id_owned) else {
                commit_export_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_RESOURCE_NOT_FOUND,
                    auth_seq,
                    &built_for_hook
                );
            };
            let result_value =
                serde_json::to_value(&status).map_err(|e| PgError::Integrity(e.to_string()))?;
            let consequence = success_consequence(
                &decision_for_hook,
                &operation_owned,
                None,
                ApplicationKeyKind::None,
                &result_value,
                None,
                auth_seq,
            )
            .map_err(|error| PgError::Idempotency(error.to_string()))?;

            persist_decision_in_tx!(tx, &decision_for_hook);
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_consequence_in_tx!(sp, &consequence, auth_seq);
                advance_authority_head_in_tx!(sp, &consequence_digest(&consequence), auth_seq);
            }
            savepoint.release()?;
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let outcome =
        run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;

    match outcome {
        UnitOfWorkOutcome::Committed | UnitOfWorkOutcome::ApplicationFailureCommitted => {
            let consequence = built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))?;
            let status = read_status(runtime, export_id)?;
            Ok((status, consequence))
        }
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "a no-key read produced an unexpected idempotency outcome".to_owned(),
            ))
        }
    }
}

/// `evidence.export.get/v1`: the no-key fresh authentication/authorization
/// lifecycle read returning the mutable [`EvidenceExportStatusV1`] (contract
/// §"Evidence export and independent verification").
///
/// It cannot replace the capture or the keyed result; it publishes null
/// descriptor/manifest digests and zero counts while pending and the exact
/// reserved digests/counts/bytes when ready.
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, or storage
/// failure.
pub fn evidence_export_get_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<EvidenceExportStatusV1, ServerError> {
    let export_id = required_input_str(normalized_input, "export_id")?;
    execute_export_get(state, operation, export_id, actor_context, decision)
        .map(|(status, _consequence)| status)
}

/// Consequence-returning entrypoint for `evidence.export.get/v1`.
pub fn evidence_export_get_v1_execute(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let export_id = required_input_str(normalized_input, "export_id")?;
    execute_export_get(state, operation, export_id, actor_context, decision)
        .map(|(_status, consequence)| consequence)
}

// ---------------------------------------------------------------------------
// `evidence.artifact.get/v2` — exact kind-and-digest acquisition.
// ---------------------------------------------------------------------------

/// `evidence.artifact.get/v2`: acquires one artifact body addressed and
/// authorized by its exact `(export_id, artifact_kind, digest)` triple, with
/// kind, length, and digest revalidated (contract §"Evidence export and
/// independent verification").
///
/// # Errors
///
/// Returns [`ServerError`] when the triple does not resolve, the kind does not
/// match, or length/digest revalidation fails.
pub fn evidence_artifact_get_v2(
    state: &AppState,
    selector: &EvidenceArtifactSelector,
) -> Result<Vec<u8>, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let capture_bytes = read_fact(
        runtime,
        &format!("evidence_export_capture/{}", selector.export_id),
        CAPTURE_FACT_KIND,
    )?
    .ok_or_else(|| {
        ServerError::Dispatch(format!("{PROBLEM_RESOURCE_NOT_FOUND}: unknown export"))
    })?;
    let capture: EvidenceExportCaptureV2 = serde_json::from_slice(&capture_bytes)
        .map_err(|error| ServerError::Internal(format!("invalid stored capture: {error}")))?;

    let (resolved_kind, resolved_digest, digest_context) =
        resolve_selector(runtime, &capture, selector)?;

    if is_external_required_root(&capture, &resolved_kind) {
        return Err(ServerError::Dispatch(
            "external-required roots are never producer-download selectors".to_owned(),
        ));
    }

    let bytes =
        read_artifact_body(runtime, &resolved_kind, &resolved_digest)?.ok_or_else(|| {
            ServerError::Dispatch(format!("{PROBLEM_RESOURCE_NOT_FOUND}: unknown artifact"))
        })?;

    revalidate_artifact(&resolved_kind, &resolved_digest, digest_context, &bytes)?;
    Ok(bytes)
}

fn resolve_selector(
    runtime: &mut proof_pg::wiring::PgRuntime,
    capture: &EvidenceExportCaptureV2,
    selector: &EvidenceArtifactSelector,
) -> Result<(String, ContentDigest, &'static str), ServerError> {
    if selector.artifact_kind == RESERVED_BUNDLE_KIND
        || selector.artifact_kind == RESERVED_MANIFEST_KIND
    {
        let ready = read_fact(
            runtime,
            &format!("evidence_export_ready/{}", capture.export_id),
            READY_FACT_KIND,
        )?;
        let Some(ready) = ready else {
            return Err(ServerError::Dispatch(
                "reserved descriptors are not acquirable while pending".to_owned(),
            ));
        };
        let status: EvidenceExportStatusV1 = serde_json::from_slice(&ready).map_err(|error| {
            ServerError::Internal(format!("invalid stored ready status: {error}"))
        })?;
        if selector.artifact_kind == RESERVED_BUNDLE_KIND {
            let digest = status.bundle_descriptor_digest.ok_or_else(|| {
                ServerError::Internal("ready status has no bundle digest".to_owned())
            })?;
            if digest != selector.digest {
                return Err(ServerError::Dispatch(
                    "bundle descriptor digest mismatch".to_owned(),
                ));
            }
            return Ok((
                RESERVED_BUNDLE_KIND.to_owned(),
                digest,
                REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT,
            ));
        }
        let digest = status.manifest_digest.ok_or_else(|| {
            ServerError::Internal("ready status has no manifest digest".to_owned())
        })?;
        if digest != selector.digest {
            return Err(ServerError::Dispatch("manifest digest mismatch".to_owned()));
        }
        return Ok((
            RESERVED_MANIFEST_KIND.to_owned(),
            digest,
            REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
        ));
    }

    if let Ok(kind) = parse_root_kind(&selector.artifact_kind) {
        let member = capture
            .membership
            .iter()
            .find(|member| member.artifact_kind == kind)
            .ok_or_else(|| {
                ServerError::Dispatch("root member is not in the captured membership".to_owned())
            })?;
        if member.content_digest != selector.digest {
            return Err(ServerError::Dispatch(
                "root member digest mismatch".to_owned(),
            ));
        }
        return Ok((
            selector.artifact_kind.clone(),
            selector.digest,
            root_digest_context(kind),
        ));
    }

    let closure = read_closure_for_export(runtime, capture)?;
    let declared = closure
        .artifacts
        .iter()
        .find(|descriptor| {
            descriptor.artifact.artifact_kind == selector.artifact_kind
                && descriptor.artifact.digest == selector.digest
        })
        .ok_or_else(|| {
            ServerError::Dispatch("nested artifact is not in the captured closure".to_owned())
        })?;
    let context = nested_artifact_digest_context(&declared.artifact.artifact_kind)
        .ok_or_else(|| ServerError::Dispatch("unknown nested artifact kind".to_owned()))?;
    Ok((selector.artifact_kind.clone(), selector.digest, context))
}

fn is_external_required_root(capture: &EvidenceExportCaptureV2, kind: &str) -> bool {
    capture.membership.iter().any(|member| {
        root_kind_wire(member.artifact_kind) == kind
            && member.delivery == RemoteEvidenceDelivery::ExternalRequired
    })
}

fn read_closure_for_export(
    runtime: &mut proof_pg::wiring::PgRuntime,
    capture: &EvidenceExportCaptureV2,
) -> Result<RemoteReleaseArtifactClosureV1, ServerError> {
    let digest = capture.closure_bindings.artifact_closure.manifest_digest;
    let bytes =
        read_artifact_body(runtime, "release-artifact-closure", &digest)?.ok_or_else(|| {
            ServerError::Internal("release-artifact closure bytes are absent".to_owned())
        })?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| ServerError::Internal(format!("malformed release closure: {error}")))?;
    let closure: RemoteReleaseArtifactClosureV1 = serde_json::from_value(value)
        .map_err(|error| ServerError::Internal(format!("invalid release closure: {error}")))?;
    let canonical = canonical_bytes(
        &serde_json::to_value(&closure)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    if raw_digest(REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT, &canonical) != digest {
        return Err(ServerError::Internal(
            "release-artifact closure digest mismatch".to_owned(),
        ));
    }
    Ok(closure)
}

fn revalidate_artifact(
    kind: &str,
    expected_digest: &ContentDigest,
    digest_context: &str,
    bytes: &[u8],
) -> Result<(), ServerError> {
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES as u64 {
        return Err(ServerError::Internal(
            "artifact byte limit violated".to_owned(),
        ));
    }
    let recomputed = raw_digest(digest_context, bytes);
    if &recomputed != expected_digest {
        return Err(ServerError::Internal(format!(
            "artifact `{kind}` digest mismatch: expected {expected_digest}, recomputed {recomputed}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Logical member map assembly.
// ---------------------------------------------------------------------------

/// Builds the exact uncompressed logical member map from one immutable capture,
/// outside any transaction (contract §"Evidence export and independent
/// verification").
///
/// This function materializes the members derivable from the typed inputs — the
/// reserved `bundle.json` and `manifest.json` descriptors plus the
/// `release-artifact-closure` and `authority-fact` root bytes — and verifies
/// their digests against the capture's closure bindings. The attempt-companion
/// roots and nested artifacts are materialized by [`assemble_export`], which
/// reads their exact bytes from immutable storage and merges them into the
/// returned map.
///
/// # Errors
///
/// Returns [`ServerError`] when the capture's closure bytes are absent,
/// malformed, or fail kind/length/digest revalidation.
pub fn build_logical_member_map(
    capture: &EvidenceExportCaptureV2,
    closure: &RemoteReleaseArtifactClosureV1,
    record_set: &RemoteAuthorityRecordSetV1,
) -> Result<RemoteEvidenceMemberMap, ServerError> {
    let bundle = build_bundle_descriptor(capture)?;
    let bundle_bytes = canonical_bytes(
        &serde_json::to_value(&bundle).map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;

    let manifest = build_manifest(capture)?;
    let manifest_bytes = canonical_bytes(
        &serde_json::to_value(&manifest)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;

    let closure_bytes = canonical_bytes(
        &serde_json::to_value(closure).map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    let recomputed_closure_digest = raw_digest(
        REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT,
        &closure_bytes,
    );
    if recomputed_closure_digest != capture.closure_bindings.artifact_closure.manifest_digest {
        return Err(ServerError::Internal(
            "release-artifact closure digest does not match the captured binding".to_owned(),
        ));
    }

    let record_set_bytes = canonical_bytes(
        &serde_json::to_value(record_set)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    let recomputed_record_set_digest = raw_digest(
        REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
        &record_set_bytes,
    );
    if recomputed_record_set_digest != capture.closure_bindings.remote_authority.record_set_digest {
        return Err(ServerError::Internal(
            "authority record-set digest does not match the captured binding".to_owned(),
        ));
    }

    let mut members = RemoteEvidenceMemberMap::new();
    members.insert(BUNDLE_DESCRIPTOR_PATH.to_owned(), bundle_bytes);
    members.insert(MANIFEST_MEMBER_PATH.to_owned(), manifest_bytes);
    members.insert(
        normalize_member_path(
            &capture
                .closure_bindings
                .artifact_closure
                .manifest_member_path,
        )?,
        closure_bytes,
    );
    members.insert(
        normalize_member_path(
            &capture
                .closure_bindings
                .remote_authority
                .record_set_member_path,
        )?,
        record_set_bytes,
    );
    Ok(members)
}

/// `assemble_export`: the worker entrypoint that builds the logical member map
/// from the capture outside the transaction, verifies the bytes, and performs
/// the separate pending-to-ready transaction (contract §"Evidence export and
/// independent verification").
///
/// # Errors
///
/// Returns [`ServerError`] when verification fails or the ready transition
/// cannot commit.
pub fn assemble_export(
    state: &AppState,
    capture: &EvidenceExportCaptureV2,
) -> Result<EvidenceExportStatusV1, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let (members, bundle, manifest, bundle_digest, manifest_digest, artifact_count, total_bytes) =
        materialize_members(runtime, capture)?;

    validate_member_map(capture, &members)?;

    commit_ready(
        runtime,
        capture,
        &bundle,
        &manifest,
        bundle_digest,
        manifest_digest,
        artifact_count,
        total_bytes,
    )?;

    Ok(EvidenceExportStatusV1 {
        api_version: EvidenceExportStatusApiVersion::Tag,
        export_id: capture.export_id.clone(),
        status: EvidenceExportStatusKind::Ready,
        bundle_descriptor_digest: Some(bundle_digest),
        manifest_digest: Some(manifest_digest),
        artifact_count,
        total_included_bytes: total_bytes,
    })
}

#[allow(clippy::type_complexity)]
fn materialize_members(
    runtime: &mut proof_pg::wiring::PgRuntime,
    capture: &EvidenceExportCaptureV2,
) -> Result<
    (
        RemoteEvidenceMemberMap,
        RemoteEvidenceBundleV2,
        RemoteEvidenceManifestV2,
        ContentDigest,
        ContentDigest,
        u64,
        u64,
    ),
    ServerError,
> {
    let material = read_material(runtime, &capture.release_id)?;
    let (closure, _closure_bytes) = read_closure(runtime, &material)?;
    let (record_set, _record_set_bytes) = read_record_set(runtime, &material)?;

    let mut members = build_logical_member_map(capture, &closure, &record_set)?;

    let companion_specs = [
        (
            RemoteEvidenceRootKind::RemoteActorEvidence,
            "remote-actor-evidence",
            material.actor_evidence_digest,
            AUTHENTICATED_ACTOR_CONTEXT_EVIDENCE_DIGEST_CONTEXT,
        ),
        (
            RemoteEvidenceRootKind::RemoteAuthenticationEvent,
            "remote-authentication-event",
            material.authentication_event_digest,
            REMOTE_AUTHENTICATION_EVENT_DIGEST_CONTEXT,
        ),
        (
            RemoteEvidenceRootKind::RemoteCommandInput,
            "remote-command-input",
            material.command_input_digest,
            "proof:command:v1",
        ),
        (
            RemoteEvidenceRootKind::RemoteAuthenticatedCommandEnvelope,
            "remote-authenticated-command-envelope",
            material.envelope_digest,
            "proof:authenticated-command-envelope:v1",
        ),
    ];
    for (kind, storage_kind, digest, context) in companion_specs {
        let (member_path, _schema_id, _version) = root_member_spec(kind);
        let member = capture
            .membership
            .iter()
            .find(|m| m.artifact_kind == kind)
            .ok_or_else(|| {
                ServerError::Internal("companion root is not in the membership".to_owned())
            })?;
        if member.delivery == RemoteEvidenceDelivery::ExternalRequired {
            continue;
        }
        let bytes = read_artifact_body(runtime, storage_kind, &digest)?.ok_or_else(|| {
            ServerError::Internal(format!("companion `{storage_kind}` bytes are absent"))
        })?;
        revalidate_artifact(storage_kind, &digest, context, &bytes)?;
        if bytes.len() as u64 != member.byte_length {
            return Err(ServerError::Internal(format!(
                "companion `{member_path}` length {} does not match declared {}",
                bytes.len(),
                member.byte_length
            )));
        }
        members.insert(normalize_member_path(member_path)?, bytes);
    }

    for descriptor in &closure.artifacts {
        let kind = &descriptor.artifact.artifact_kind;
        let digest = descriptor.artifact.digest;
        let context = nested_artifact_digest_context(kind).ok_or_else(|| {
            ServerError::Internal(format!("unknown nested artifact kind `{kind}`"))
        })?;
        let bytes = read_artifact_body(runtime, kind, &digest)?.ok_or_else(|| {
            ServerError::Internal(format!("nested artifact `{kind}` bytes are absent"))
        })?;
        revalidate_artifact(kind, &digest, context, &bytes)?;
        if bytes.len() as u64 != descriptor.availability.byte_length {
            return Err(ServerError::Internal(format!(
                "nested artifact `{kind}` length {} does not match declared {}",
                bytes.len(),
                descriptor.availability.byte_length
            )));
        }
        members.insert(
            normalize_member_path(&nested_artifact_path(kind, &digest))?,
            bytes,
        );
    }

    let artifact_count = u64::try_from(capture.membership.len()).unwrap_or(0)
        + u64::try_from(closure.artifacts.len()).unwrap_or(0);
    let total_bytes = members
        .iter()
        .filter(|(path, _)| *path != BUNDLE_DESCRIPTOR_PATH && *path != MANIFEST_MEMBER_PATH)
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();

    let bundle = build_bundle_descriptor(capture)?;
    let manifest = build_manifest(capture)?;
    let bundle_digest = bundle_descriptor_digest(&bundle)?;
    let manifest_digest = manifest_digest(&manifest)?;

    Ok((
        members,
        bundle,
        manifest,
        bundle_digest,
        manifest_digest,
        artifact_count,
        total_bytes,
    ))
}

fn validate_member_map(
    capture: &EvidenceExportCaptureV2,
    members: &RemoteEvidenceMemberMap,
) -> Result<(), ServerError> {
    if members.len() > MAX_EXPORT_ARTIFACT_BODIES + 2 {
        return Err(ServerError::Internal(
            "member count exceeds the 4,096-artifact limit plus two reserved entries".to_owned(),
        ));
    }
    let nested_len = members
        .keys()
        .filter(|path| path.starts_with("content/artifacts/"))
        .count();
    if nested_len > MAX_NESTED_ARTIFACT_BODIES {
        return Err(ServerError::Internal(
            "nested artifact count exceeds the 4,090 limit".to_owned(),
        ));
    }
    let total: u64 = members.values().map(|bytes| bytes.len() as u64).sum();
    if total > MAX_TOTAL_BYTES as u64 {
        return Err(ServerError::Internal(
            "total member bytes exceed the limit".to_owned(),
        ));
    }

    for member in &capture.membership {
        if member.delivery == RemoteEvidenceDelivery::ExternalRequired {
            continue;
        }
        let Some(bytes) = members.get(&member.member_path) else {
            return Err(ServerError::Internal(format!(
                "included root member `{}` is absent",
                member.member_path
            )));
        };
        if bytes.len() as u64 != member.byte_length {
            return Err(ServerError::Internal(format!(
                "root member `{}` length mismatch",
                member.member_path
            )));
        }
        let context = root_digest_context(member.artifact_kind);
        if raw_digest(context, bytes) != member.content_digest {
            return Err(ServerError::Internal(format!(
                "root member `{}` digest mismatch",
                member.member_path
            )));
        }
    }

    if !members.contains_key(BUNDLE_DESCRIPTOR_PATH) || !members.contains_key(MANIFEST_MEMBER_PATH)
    {
        return Err(ServerError::Internal(
            "reserved bundle.json/manifest.json descriptors are absent".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_ready(
    runtime: &mut proof_pg::wiring::PgRuntime,
    capture: &EvidenceExportCaptureV2,
    bundle: &RemoteEvidenceBundleV2,
    manifest: &RemoteEvidenceManifestV2,
    bundle_digest: ContentDigest,
    manifest_digest: ContentDigest,
    artifact_count: u64,
    total_bytes: u64,
) -> Result<(), ServerError> {
    let bundle_bytes = canonical_bytes(
        &serde_json::to_value(bundle).map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;
    let manifest_bytes = canonical_bytes(
        &serde_json::to_value(manifest)
            .map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;

    let status = EvidenceExportStatusV1 {
        api_version: EvidenceExportStatusApiVersion::Tag,
        export_id: capture.export_id.clone(),
        status: EvidenceExportStatusKind::Ready,
        bundle_descriptor_digest: Some(bundle_digest),
        manifest_digest: Some(manifest_digest),
        artifact_count,
        total_included_bytes: total_bytes,
    };
    let status_bytes = canonical_bytes(
        &serde_json::to_value(&status).map_err(|error| ServerError::Internal(error.to_string()))?,
    )?;

    let client = runtime.client_mut();
    let mut tx = client
        .transaction()
        .map_err(|error| ServerError::Storage(PgError::Transaction(error.to_string())))?;
    tx.batch_execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE")
        .map_err(|error| ServerError::Storage(PgError::Transaction(error.to_string())))?;

    tx.execute(
        "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
         VALUES ($1, $2, $3, clock_timestamp())
         ON CONFLICT (kind, digest) DO NOTHING",
        &[
            &RESERVED_BUNDLE_KIND,
            &bundle_digest.to_string(),
            &bundle_bytes,
        ],
    )
    .map_err(|error| ServerError::Storage(PgError::Artifact(error.to_string())))?;
    tx.execute(
        "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
         VALUES ($1, $2, $3, clock_timestamp())
         ON CONFLICT (kind, digest) DO NOTHING",
        &[
            &RESERVED_MANIFEST_KIND,
            &manifest_digest.to_string(),
            &manifest_bytes,
        ],
    )
    .map_err(|error| ServerError::Storage(PgError::Artifact(error.to_string())))?;

    let seq: i64 = tx
        .query_one(
            "SELECT authority_sequence FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| ServerError::Storage(PgError::Transaction(error.to_string())))?
        .get(0);
    tx.execute(
        "INSERT INTO facts (
             fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
         ) VALUES ($1, $2, $3, $4, $5, $6, now())
         ON CONFLICT (fact_id) DO NOTHING",
        &[
            &format!("evidence_export_ready/{}", capture.export_id),
            &capture.workspace_id,
            &READY_FACT_KIND,
            &seq,
            &unique_fact_digest(&status_bytes).to_string(),
            &status_bytes,
        ],
    )
    .map_err(|error| ServerError::Storage(PgError::Integrity(error.to_string())))?;

    tx.commit()
        .map_err(|error| ServerError::Storage(PgError::Transaction(error.to_string())))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Export worker.
// ---------------------------------------------------------------------------

/// The bounded assembly worker that materializes captured exports into their
/// ready logical member maps (contract §"Evidence export and independent
/// verification").
#[derive(Clone, Debug, Default)]
pub struct ExportWorker;

impl ExportWorker {
    /// Constructs the assembly worker.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Assembles one captured export and transitions it pending-to-ready.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any build, verification, or transition
    /// failure.
    pub fn assemble(
        &self,
        state: &AppState,
        capture: &EvidenceExportCaptureV2,
    ) -> Result<EvidenceExportStatusV1, ServerError> {
        assemble_export(state, capture)
    }

    /// Claims and assembles one due pending export; returns the number of
    /// exports advanced (0 or 1).
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on storage or assembly failure.
    pub fn run_once(&self, state: &AppState) -> Result<usize, ServerError> {
        let capture = {
            let mut guard = lock_pg(state)?;
            let runtime = runtime_mut(&mut guard)?;
            let row = runtime
                .client_mut()
                .query_opt(
                    "SELECT f.fact_id FROM facts f
                     WHERE f.fact_kind = $1
                       AND NOT EXISTS (
                           SELECT 1 FROM facts ready
                           WHERE ready.fact_kind = $2
                             AND ready.fact_id = replace(f.fact_id, 'evidence_export_capture/', 'evidence_export_ready/')
                       )
                     ORDER BY f.fact_id
                     LIMIT 1",
                    &[&CAPTURE_FACT_KIND, &READY_FACT_KIND],
                )
                .map_err(|error| {
                    ServerError::Storage(PgError::Integrity(error.to_string()))
                })?;
            let Some(row) = row else {
                return Ok(0);
            };
            let fact_id: String = row.get(0);
            let bytes = read_fact(runtime, &fact_id, CAPTURE_FACT_KIND)?
                .ok_or_else(|| ServerError::Internal("capture fact body is absent".to_owned()))?;
            serde_json::from_slice::<EvidenceExportCaptureV2>(&bytes).map_err(|error| {
                ServerError::Internal(format!("invalid stored capture: {error}"))
            })?
        };

        // Assemble outside the runtime lock/transaction boundary.
        assemble_export(state, &capture)?;
        Ok(1)
    }
}
