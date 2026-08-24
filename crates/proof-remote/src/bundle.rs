//! `RemoteEvidenceBundleV2` export descriptor, manifest, capture/status types,
//! caller `VerificationTrustPolicyV2`, and closed verifier report types.
//!
//! This module is the complete public type surface for the Milestone 3 remote
//! evidence boundary (contract §"Evidence export and independent verification").
//! The type shapes, frozen constants, validation/assembly functions, selector
//! enumeration, checkpoint, and closed report helpers are implemented and
//! exercised by `tests/bundle_impl.rs`. The closed Schemas live under
//! `conformance/v1/collaboration-server/schemas/
//! remote-evidence-v2.schema.json`.

use std::collections::BTreeMap;

use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AuthorityHeadV1, RemoteOperationV1, authority::RemoteAuthorityRecordEnvelopeV1,
    identity::OidcSubjectCommitmentOpeningV1,
};

/// Generates a closed single-value wire tag enum (for `api_version` and `type`
/// discriminators that admit exactly one accepted string).
macro_rules! wire_tag {
    ($name:ident, $wire:literal) => {
        #[doc = concat!("Exact closed wire tag `", $wire, "`.")]
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        pub enum $name {
            /// The sole accepted value.
            #[serde(rename = $wire)]
            Tag,
        }
    };
}

// ---------------------------------------------------------------------------
// Frozen wire tags and digest contexts.
// ---------------------------------------------------------------------------

wire_tag!(RemoteEvidenceBundleType, "RemoteEvidenceBundleV2");
wire_tag!(
    RemoteEvidenceBundleApiVersion,
    "proof.dev/remote-evidence-bundle/v2"
);
wire_tag!(RemoteEvidenceManifestType, "RemoteEvidenceManifestV2");
wire_tag!(
    RemoteEvidenceManifestApiVersion,
    "proof.dev/remote-evidence-manifest/v2"
);
wire_tag!(EvidenceExportCaptureType, "EvidenceExportCaptureV2");
wire_tag!(
    EvidenceExportCaptureApiVersion,
    "proof.dev/evidence-export-capture/v2"
);
wire_tag!(
    EvidenceExportResultApiVersion,
    "proof.dev/evidence-export-result/v2"
);
wire_tag!(
    EvidenceExportStatusApiVersion,
    "proof.dev/evidence-export-status/v1"
);
wire_tag!(
    VerificationTrustPolicyApiVersion,
    "proof.dev/verification-trust-policy/v2"
);
wire_tag!(RemoteVerificationReportType, "RemoteVerificationReportV2");
wire_tag!(
    RemoteVerificationReportApiVersion,
    "proof.dev/remote-verification-report/v2"
);
wire_tag!(
    RemoteReleaseArtifactClosureApiVersion,
    "proof.dev/remote-release-artifact-closure/v1"
);
wire_tag!(
    RemoteAuthorityRecordSetApiVersion,
    "proof.dev/remote-authority-record-set/v1"
);
wire_tag!(
    RemoteEvidenceClosureBindingsApiVersion,
    "proof.dev/remote-evidence-closure-bindings/v1"
);
wire_tag!(
    AuthorityCheckpointApiVersion,
    "proof.dev/authority-checkpoint/v1"
);
wire_tag!(
    EnvironmentReleaseCheckpointApiVersion,
    "proof.dev/environment-release-checkpoint/v2"
);
wire_tag!(RemoteVerifierInputType, "RemoteVerifierInputV2");
wire_tag!(
    RemoteVerifierInputApiVersion,
    "proof.dev/remote-verifier-input/v2"
);

/// Exact `api_version`/`type` wire strings for the remote evidence boundary.
pub const REMOTE_EVIDENCE_BUNDLE_API_VERSION: &str = "proof.dev/remote-evidence-bundle/v2";
/// Exact `api_version` for [`RemoteEvidenceManifestV2`].
pub const REMOTE_EVIDENCE_MANIFEST_API_VERSION: &str = "proof.dev/remote-evidence-manifest/v2";
/// Exact `api_version` for [`EvidenceExportCaptureV2`].
pub const EVIDENCE_EXPORT_CAPTURE_API_VERSION: &str = "proof.dev/evidence-export-capture/v2";
/// Exact `api_version` for [`EvidenceExportResultV2`].
pub const EVIDENCE_EXPORT_RESULT_API_VERSION: &str = "proof.dev/evidence-export-result/v2";
/// Exact `api_version` for [`EvidenceExportStatusV1`].
pub const EVIDENCE_EXPORT_STATUS_API_VERSION: &str = "proof.dev/evidence-export-status/v1";
/// Exact `api_version` for [`VerificationTrustPolicyV2`].
pub const VERIFICATION_TRUST_POLICY_API_VERSION: &str = "proof.dev/verification-trust-policy/v2";
/// Exact `api_version` for [`RemoteVerificationReportV2`].
pub const REMOTE_VERIFICATION_REPORT_API_VERSION: &str = "proof.dev/remote-verification-report/v2";

/// Exact capture boundary: the capture locks heads before the export attempt
/// appends its own decision, effect, or consequence (contract §"Evidence export
/// and independent verification").
pub const CAPTURE_BOUNDARY_PRE_EXPORT_ATTEMPT_LOCKED_HEADS: &str =
    "pre-export-attempt-locked-heads";

/// Reserved bundle descriptor member path (accounted separately from the 4,096
/// artifact bodies).
pub const BUNDLE_DESCRIPTOR_PATH: &str = "bundle.json";
/// Reserved manifest member path (accounted separately from the 4,096 artifact
/// bodies).
pub const MANIFEST_MEMBER_PATH: &str = "manifest.json";

/// Maximum total artifact bodies: six roots plus at most 4,090 nested bodies
/// (contract §"Evidence export and independent verification", limits table).
pub const MAX_EXPORT_ARTIFACT_BODIES: usize = 4_096;
/// Maximum nested artifact bodies under the release-artifact closure.
pub const MAX_NESTED_ARTIFACT_BODIES: usize = 4_090;
/// Maximum canonical manifest bytes.
pub const MAX_MANIFEST_BYTES: usize = 4_194_304;
/// Maximum canonical bytes for one artifact body.
pub const MAX_ARTIFACT_BYTES: usize = 4_194_304;
/// Maximum included export total bytes.
pub const MAX_TOTAL_BYTES: usize = 268_435_456;
/// Maximum canonical `RemoteEvidenceBundleV2` descriptor bytes.
pub const MAX_BUNDLE_DESCRIPTOR_BYTES: usize = 65_536;
/// Maximum decoded remote authority envelopes per record set.
pub const MAX_AUTHORITY_RECORDS: usize = 512;
/// Maximum raw `RemoteVerifierInputV2` bytes.
pub const MAX_VERIFIER_INPUT_BYTES: usize = 268_435_456;

/// BLAKE3-256 derive-key context for the `RemoteEvidenceBundleV2` descriptor.
pub const REMOTE_EVIDENCE_BUNDLE_DIGEST_CONTEXT: &str = "proof:remote-evidence-bundle:v2";
/// BLAKE3-256 derive-key context for [`RemoteEvidenceManifestV2`].
pub const REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT: &str = "proof:remote-evidence-manifest:v2";
/// BLAKE3-256 derive-key context for [`EvidenceExportCaptureV2`].
pub const EVIDENCE_EXPORT_CAPTURE_DIGEST_CONTEXT: &str = "proof:evidence-export-capture:v2";
/// BLAKE3-256 derive-key context for [`VerificationTrustPolicyV2`].
pub const VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT: &str = "proof:verification-trust-policy:v2";
/// BLAKE3-256 derive-key context for [`RemoteReleaseArtifactClosureV1`].
pub const REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT: &str =
    "proof:remote-release-artifact-closure:v1";
/// BLAKE3-256 derive-key context for [`RemoteAuthorityRecordSetV1`].
pub const REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT: &str = "proof:remote-authority-record-set:v1";
/// BLAKE3-256 derive-key context for [`RemoteVerifierInputV2`].
pub const REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT: &str = "proof:remote-verifier-input:v2";
/// BLAKE3-256 derive-key context for [`AuthorityCheckpointV1`].
pub const AUTHORITY_CHECKPOINT_DIGEST_CONTEXT: &str = "proof:authority-checkpoint:v1";
/// BLAKE3-256 derive-key context for [`EnvironmentReleaseCheckpointV2`].
pub const ENVIRONMENT_RELEASE_CHECKPOINT_DIGEST_CONTEXT: &str =
    "proof:environment-release-checkpoint:v2";

// ---------------------------------------------------------------------------
// Small closed enums.
// ---------------------------------------------------------------------------

/// The exact six typed roots of a `RemoteEvidenceBundleV2` (contract §"Evidence
/// export and independent verification").
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteEvidenceRootKind {
    /// `release-artifact-closure` — one canonical `RemoteReleaseArtifactClosureV1`.
    ReleaseArtifactClosure,
    /// `authority-fact` — one canonical `RemoteAuthorityRecordSetV1`.
    AuthorityFact,
    /// `remote-actor-evidence` — exact `AuthenticatedActorContextEvidenceV2` bytes.
    RemoteActorEvidence,
    /// `remote-authentication-event` — exact `RemoteAuthenticationEventV1` bytes.
    RemoteAuthenticationEvent,
    /// `remote-command-input` — exact `CommandInputV1` bytes.
    RemoteCommandInput,
    /// `remote-authenticated-command-envelope` — the exact Agent DSSE envelope.
    RemoteAuthenticatedCommandEnvelope,
}

impl RemoteEvidenceRootKind {
    /// The frozen deterministic member path for each root kind (contract
    /// §"Evidence export and independent verification", frozen
    /// `artifactDescriptorIdentity`).
    #[must_use]
    pub const fn member_path(self) -> &'static str {
        match self {
            Self::ReleaseArtifactClosure => "content/release-closure.json",
            Self::AuthorityFact => "authority/facts.json",
            Self::RemoteActorEvidence => "actor/context-evidence.json",
            Self::RemoteAuthenticationEvent => "authentication/event.json",
            Self::RemoteCommandInput => "attempt/command-input.json",
            Self::RemoteAuthenticatedCommandEnvelope => {
                "attempt/authenticated-command-envelope.json"
            }
        }
    }

    /// The three roots that may be `external-required` (caller-supplied):
    /// authority, actor, and authentication. The release-artifact closure,
    /// command input, and authenticated-command envelope are always included.
    #[must_use]
    pub const fn can_be_external_required(self) -> bool {
        matches!(
            self,
            Self::AuthorityFact | Self::RemoteActorEvidence | Self::RemoteAuthenticationEvent
        )
    }
}

/// Whether one captured root is producer-included or caller-supplied.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteEvidenceDelivery {
    /// Present in the producer logical member map.
    Included,
    /// Absent from the bundle and supplied through caller input only.
    ExternalRequired,
}

/// Canonicalization class of one member body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RemoteEvidenceCanonicalization {
    /// Strict RFC 8785 canonical JSON.
    #[serde(rename = "RFC8785")]
    Rfc8785,
    /// Exact decoded bytes hashed directly.
    #[serde(rename = "raw-bytes")]
    RawBytes,
}

/// Typed disclosure requirement kind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteEvidenceDisclosureKind {
    /// Exact external artifact bytes.
    ArtifactBytes,
    /// Authorized OIDC subject-commitment opening.
    OidcSubjectOpening,
}

/// Closed export disclosure profile.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteEvidenceDisclosureProfile {
    /// Every root member is producer-included.
    CompletePortable,
    /// At least one authority/actor/authentication root is external-required.
    ExplicitExternalArtifacts,
}

/// Observed verification outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Every required byte, signature, semantic, and cross-link verified.
    Complete,
    /// Required material is missing without contradiction.
    Incomplete,
    /// Integrity or semantic failure.
    Invalid,
}

/// The closed general report scenario vocabulary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationScenario {
    /// Complete exact materialization.
    CompleteExactMaterialization,
    /// Required OIDC opening withheld.
    IncompleteRequiredOpeningWithheld,
    /// Required artifact withheld.
    IncompleteRequiredArtifactWithheld,
    /// Required authority checkpoint withheld.
    IncompleteRequiredAuthorityCheckpointWithheld,
    /// Deterministic `object_locale_revision_v1` byte tamper.
    InvalidContentArtifactByteTamper,
    /// Any other integrity or semantic Invalid outcome.
    InvalidVerification,
}

/// The exact three retained P-0008 qualification scenarios.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConformanceScenario {
    /// Complete exact materialization.
    CompleteExactMaterialization,
    /// Required OIDC opening withheld.
    IncompleteRequiredOpeningWithheld,
    /// Deterministic `object_locale_revision_v1` byte tamper.
    InvalidContentArtifactByteTamper,
}

/// One closed report reason code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationReasonCode {
    /// All components verified.
    Verified,
    /// Required disclosure (subject opening) withheld.
    MissingDisclosure,
    /// Required artifact withheld.
    MissingArtifact,
    /// Required checkpoint withheld.
    MissingCheckpoint,
    /// Deterministic content byte tamper.
    TamperedArtifact,
    /// Invalid signature.
    InvalidSignature,
    /// Invalid actor.
    InvalidActor,
    /// Invalid authority.
    InvalidAuthority,
    /// Invalid role separation.
    InvalidRoleSeparation,
    /// Invalid approval.
    InvalidApproval,
    /// Invalid policy.
    InvalidPolicy,
    /// Invalid content.
    InvalidContent,
    /// Invalid environment.
    InvalidEnvironment,
    /// Invalid release.
    InvalidRelease,
    /// Invalid completeness.
    InvalidCompleteness,
    /// Invalid member path.
    InvalidPath,
    /// Invalid canonicalization.
    InvalidCanonicalization,
    /// Invalid limit.
    InvalidLimit,
    /// Invalid registry.
    InvalidRegistry,
    /// Invalid checkpoint.
    InvalidCheckpoint,
    /// Invalid cross-link.
    InvalidCrossLink,
}

/// One per-component observed result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationComponentResult {
    /// The component verified.
    Verified,
    /// The component was missing required material.
    Missing,
    /// The component failed integrity or semantics.
    Invalid,
    /// The component was not requested (delivery evidence only).
    NotRequested,
}

/// Authority checkpoint requirement policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointRequirement {
    /// Internal caller-pinned prefix only; no freshness claim.
    InternalPrefixOnly,
    /// The authority checkpoint is required and must match the included head.
    Required,
}

/// Requesting-subject-opening disclosure policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestingSubjectOpeningPolicy {
    /// The opening is optional; verification may proceed without it.
    Optional,
    /// The opening is required; withholding it is Incomplete.
    Required,
}

/// Registry resolver failure result (always `Invalid`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RegistryResolutionFailure {
    /// An unknown or mismatched registry hash is Invalid.
    #[serde(rename = "Invalid")]
    Invalid,
}

/// Export lifecycle status shared by result and status projections.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceExportStatusKind {
    /// The immutable capture committed; assembly has not published ready.
    Pending,
    /// The worker verified the manifest and exact bytes.
    Ready,
}

// ---------------------------------------------------------------------------
// Logical member map and validation.
// ---------------------------------------------------------------------------

/// The exact uncompressed logical member map: normalized UTF-8 member path to
/// raw member bytes (contract §"Evidence export and independent verification").
pub type RemoteEvidenceMemberMap = BTreeMap<String, Vec<u8>>;

/// Validation failure for the `RemoteEvidenceBundleV2` logical member map.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BundleValidationError {
    /// An absolute member path is not permitted.
    #[error("absolute member path is not permitted: {0}")]
    AbsolutePath(String),
    /// A dot-segment member path is not permitted.
    #[error("dot-segment member path is not permitted: {0}")]
    DotSegment(String),
    /// A backslash in a member path is not permitted.
    #[error("backslash in member path is not permitted: {0}")]
    Backslash(String),
    /// The same normalized path appears more than once.
    #[error("duplicate normalized member path: {0}")]
    DuplicatePath(String),
    /// A member is not declared by the manifest or release closure.
    #[error("undeclared member entry: {0}")]
    UndeclaredEntry(String),
    /// A declared included member is absent.
    #[error("missing included member entry: {0}")]
    MissingEntry(String),
    /// A member's kind does not match its declared descriptor.
    #[error("artifact kind mismatch for member {0}")]
    KindMismatch(String),
    /// A member's content digest does not match its declared digest.
    #[error("content digest mismatch for member {0}")]
    DigestMismatch(String),
    /// A member's byte length does not match its declared length.
    #[error("byte length mismatch for member {0}")]
    LengthMismatch(String),
    /// The artifact-body count exceeds the 4,096 limit.
    #[error("artifact body count exceeds {MAX_EXPORT_ARTIFACT_BODIES}")]
    CountViolation,
    /// A manifest, artifact, or total byte limit was exceeded.
    #[error("byte limit violation")]
    ByteViolation,
}

/// Normalizes one member path to its deterministic UTF-8 form, rejecting
/// absolute, dot-segment, and backslash paths (contract §"Evidence export and
/// independent verification").
///
/// # Errors
///
/// Returns [`BundleValidationError`] for any unsafe path spelling.
pub fn normalize_member_path(path: &str) -> Result<String, BundleValidationError> {
    if path.starts_with('/') {
        return Err(BundleValidationError::AbsolutePath(path.to_owned()));
    }
    if path.contains('\\') {
        return Err(BundleValidationError::Backslash(path.to_owned()));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(BundleValidationError::DotSegment(path.to_owned()));
    }
    Ok(path.to_owned())
}

/// The deterministic nested artifact member path prefix (contract §"Evidence
/// export and independent verification").
pub const ARTIFACT_ROOT_PREFIX: &str = "content/artifacts/";

/// Renders the lowercase 64-hex digest suffix used in nested member paths.
fn digest_hex(digest: &ContentDigest) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in digest.as_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Computes the deterministic nested artifact member path for one
/// `(artifact_kind, digest)` pair (contract §"Evidence export and independent
/// verification"): `content/artifacts/<artifact_kind>/blake3/<digest-hex>.json`.
#[must_use]
pub fn nested_artifact_path(artifact_kind: &str, digest: &ContentDigest) -> String {
    format!(
        "{ARTIFACT_ROOT_PREFIX}{artifact_kind}/blake3/{}.json",
        digest_hex(digest)
    )
}

/// The frozen BLAKE3-256 derive-key context for each root kind.
fn root_digest_context(kind: RemoteEvidenceRootKind) -> &'static str {
    match kind {
        RemoteEvidenceRootKind::ReleaseArtifactClosure => {
            REMOTE_RELEASE_ARTIFACT_CLOSURE_DIGEST_CONTEXT
        }
        RemoteEvidenceRootKind::AuthorityFact => REMOTE_AUTHORITY_RECORD_SET_DIGEST_CONTEXT,
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

/// Resolves the frozen digest context for one nested accepted artifact kind,
/// special-casing the `environment_config_v2_projection` projection.
fn nested_digest_context(artifact_kind: &str) -> Option<&'static str> {
    if artifact_kind == "environment_config_v2_projection" {
        return Some("proof:environment-config:v2");
    }
    ArtifactKind::from_wire_name(artifact_kind).map(ArtifactKind::derive_key_context)
}

/// Recomputes one member body's domain-separated digest under its
/// canonicalization class and compares it to the declared digest.
fn digest_matches(
    canonicalization: RemoteEvidenceCanonicalization,
    digest_context: &str,
    body: &[u8],
    declared: ContentDigest,
) -> bool {
    match canonicalization {
        RemoteEvidenceCanonicalization::Rfc8785 => proof_canonical::parse_strict(body)
            .and_then(|value| proof_canonical::canonicalize(&value))
            .is_ok_and(|canonical| {
                crate::derive_key_digest(digest_context, canonical.as_bytes()) == declared
            }),
        RemoteEvidenceCanonicalization::RawBytes => {
            crate::derive_key_digest(digest_context, body) == declared
        }
    }
}

/// Validates the exact uncompressed logical member map against the manifest and
/// release-artifact closure (contract §"Evidence export and independent
/// verification").
///
/// Enforces the six-root membership, reserved descriptor entries, deterministic
/// normalized paths, declared/included bijection, kind/digest/length equality,
/// and the 4,096-artifact and byte limits.
///
/// # Errors
///
/// Returns [`BundleValidationError`] for any path, membership, kind, digest,
/// length, count, or byte violation.
#[allow(clippy::too_many_lines)]
pub fn validate_bundle_members(
    members: &RemoteEvidenceMemberMap,
    manifest: &RemoteEvidenceManifestV2,
    closure: &RemoteReleaseArtifactClosureV1,
) -> Result<(), BundleValidationError> {
    /// One declared included entry's expected identity.
    enum ExpectedEntry {
        /// A reserved descriptor (`bundle.json` / `manifest.json`).
        Reserved,
        /// One of the six typed roots.
        Root {
            kind: RemoteEvidenceRootKind,
            digest: ContentDigest,
            byte_length: u64,
        },
        /// One unique nested accepted artifact.
        Nested {
            artifact_kind: String,
            digest: ContentDigest,
            byte_length: u64,
        },
    }

    let mut expected: BTreeMap<String, ExpectedEntry> = BTreeMap::new();

    let mut insert = |path: String, entry: ExpectedEntry| -> Result<(), BundleValidationError> {
        if expected.insert(path.clone(), entry).is_none() {
            Ok(())
        } else {
            Err(BundleValidationError::DuplicatePath(path))
        }
    };

    // Reserved descriptor entries are accounted separately from artifact bodies.
    insert(BUNDLE_DESCRIPTOR_PATH.to_owned(), ExpectedEntry::Reserved)?;
    insert(MANIFEST_MEMBER_PATH.to_owned(), ExpectedEntry::Reserved)?;

    // The six typed roots. An included root must live at its frozen path;
    // an external-required root is caller-supplied and must be absent.
    for member in &manifest.membership {
        let path = normalize_member_path(&member.member_path)?;
        if member.delivery == RemoteEvidenceDelivery::Included {
            if path != member.artifact_kind.member_path() {
                return Err(BundleValidationError::KindMismatch(
                    member.member_path.clone(),
                ));
            }
            insert(
                path,
                ExpectedEntry::Root {
                    kind: member.artifact_kind,
                    digest: member.content_digest,
                    byte_length: member.byte_length,
                },
            )?;
        }
    }

    // Each unique nested accepted artifact at its deterministic path.
    for descriptor in &closure.artifacts {
        let path = nested_artifact_path(
            &descriptor.artifact.artifact_kind,
            &descriptor.artifact.digest,
        );
        insert(
            path,
            ExpectedEntry::Nested {
                artifact_kind: descriptor.artifact.artifact_kind.clone(),
                digest: descriptor.artifact.digest,
                byte_length: descriptor.availability.byte_length,
            },
        )?;
    }

    // Count limits: six roots plus at most 4,090 nested bodies.
    let included_roots = manifest
        .membership
        .iter()
        .filter(|member| member.delivery == RemoteEvidenceDelivery::Included)
        .count();
    let nested = closure.artifacts.len();
    if nested > MAX_NESTED_ARTIFACT_BODIES || included_roots + nested > MAX_EXPORT_ARTIFACT_BODIES {
        return Err(BundleValidationError::CountViolation);
    }

    // Byte limits: per-body, reserved-descriptor, and running total.
    let mut total_bytes: usize = 0;
    for (path, body) in members {
        total_bytes = total_bytes.saturating_add(body.len());
        if path == BUNDLE_DESCRIPTOR_PATH {
            if body.len() > MAX_BUNDLE_DESCRIPTOR_BYTES {
                return Err(BundleValidationError::ByteViolation);
            }
        } else if path == MANIFEST_MEMBER_PATH {
            if body.len() > MAX_MANIFEST_BYTES {
                return Err(BundleValidationError::ByteViolation);
            }
        } else if body.len() > MAX_ARTIFACT_BYTES {
            return Err(BundleValidationError::ByteViolation);
        }
    }
    if total_bytes > MAX_TOTAL_BYTES {
        return Err(BundleValidationError::ByteViolation);
    }

    // Every map key must itself be a safe normalized path.
    for path in members.keys() {
        normalize_member_path(path)?;
    }

    // Every declared included entry must be present with matching
    // kind/length/digest identity.
    for (path, entry) in &expected {
        match entry {
            ExpectedEntry::Reserved => {
                if !members.contains_key(path) {
                    return Err(BundleValidationError::MissingEntry(path.clone()));
                }
            }
            ExpectedEntry::Root {
                kind,
                digest,
                byte_length,
            } => {
                let body = members
                    .get(path)
                    .ok_or_else(|| BundleValidationError::MissingEntry(path.clone()))?;
                if body.len() as u64 != *byte_length {
                    return Err(BundleValidationError::LengthMismatch(path.clone()));
                }
                if !digest_matches(
                    RemoteEvidenceCanonicalization::Rfc8785,
                    root_digest_context(*kind),
                    body,
                    *digest,
                ) {
                    return Err(BundleValidationError::DigestMismatch(path.clone()));
                }
            }
            ExpectedEntry::Nested {
                artifact_kind,
                digest,
                byte_length,
            } => {
                let body = members
                    .get(path)
                    .ok_or_else(|| BundleValidationError::MissingEntry(path.clone()))?;
                if body.len() as u64 != *byte_length {
                    return Err(BundleValidationError::LengthMismatch(path.clone()));
                }
                let context = nested_digest_context(artifact_kind)
                    .ok_or_else(|| BundleValidationError::KindMismatch(path.clone()))?;
                if !digest_matches(
                    RemoteEvidenceCanonicalization::Rfc8785,
                    context,
                    body,
                    *digest,
                ) {
                    return Err(BundleValidationError::DigestMismatch(path.clone()));
                }
            }
        }
    }

    // Every map entry must be declared (undeclared entries are rejected).
    for path in members.keys() {
        if !expected.contains_key(path) {
            return Err(BundleValidationError::UndeclaredEntry(path.clone()));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Bundle descriptor and portable payload contract.
// ---------------------------------------------------------------------------

/// Inert first-profile producer hint namespace (contract §"Evidence export and
/// independent verification").
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UntrustedHintsV1 {
    /// Always empty in the first profile.
    #[serde(default)]
    pub authority_root_ids: Vec<String>,
    /// Always empty in the first profile.
    #[serde(default)]
    pub release_root_ids: Vec<String>,
    /// Always empty in the first profile.
    #[serde(default)]
    pub checkpoint_ids: Vec<String>,
    /// Always empty in the first profile.
    #[serde(default)]
    pub resolver_urls: Vec<String>,
    /// Always false; producer hints never create caller trust.
    #[serde(default)]
    pub trusted: bool,
    /// Always false; the verifier never fetches hinted material.
    #[serde(default)]
    pub auto_fetch: bool,
}

impl UntrustedHintsV1 {
    /// The exact inert first-profile hint object: every array empty,
    /// `trusted: false`, `auto_fetch: false`.
    #[must_use]
    pub fn inert() -> Self {
        Self::default()
    }
}

/// Exact five-head snapshot projection shared by capture, manifest, and bundle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceHeadsV1 {
    /// Authority head record digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub authority: ContentDigest,
    /// Content head digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub content: ContentDigest,
    /// Release head digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release: ContentDigest,
    /// Environment head digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub environment: ContentDigest,
    /// Outbox head digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub outbox: ContentDigest,
}

/// The `portable_payload_contract` object of the bundle descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidencePortablePayloadContractV1 {
    /// `proof.dev/remote-release-artifact-closure/v1`.
    pub artifact_closure_api_version: String,
    /// `content/release-closure.json`.
    pub artifact_closure_member_path: String,
    /// Digest of the release-artifact closure member.
    #[serde(with = "crate::serde_support::display_string")]
    pub artifact_closure_digest: ContentDigest,
    /// `proof-verifier/accepted-release-artifact-semantics-v1`.
    pub artifact_verifier_profile: String,
    /// `authority/facts.json`.
    pub remote_record_set_member_path: String,
    /// Digest of the remote authority record set member.
    #[serde(with = "crate::serde_support::display_string")]
    pub remote_record_set_digest: ContentDigest,
    /// `proof-verifier/remote-authority/v1`.
    pub remote_verifier_profile: String,
    /// `proof-verifier/remote-evidence-v2`.
    pub composed_verifier_profile: String,
    /// The exact composition rule.
    pub composition: String,
    /// The exact included-bytes retention rule.
    pub included_bytes_rule: String,
    /// The P6 compatibility rule (historical bundle verifier unchanged).
    pub p6_compatibility: String,
}

/// The canonical `bundle.json` descriptor for one uncompressed logical member
/// set (schema `bundle`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceBundleV2 {
    /// `RemoteEvidenceBundleV2`.
    pub r#type: RemoteEvidenceBundleType,
    /// `proof.dev/remote-evidence-bundle/v2`.
    pub api_version: RemoteEvidenceBundleApiVersion,
    /// `bundle.json`.
    pub bundle_descriptor_path: String,
    /// `manifest.json`.
    pub manifest_member_path: String,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// `snapshot_<hex32>` producer label.
    pub snapshot_id: String,
    /// The exact snapshot-claim nonclaim statement.
    pub snapshot_claim: String,
    /// The five captured heads.
    pub snapshot_heads: EvidenceHeadsV1,
    /// `proof:remote-evidence-manifest:v2` digest of the manifest member.
    #[serde(with = "crate::serde_support::display_string")]
    pub manifest_digest: ContentDigest,
    /// The portable payload contract.
    pub portable_payload_contract: RemoteEvidencePortablePayloadContractV1,
    /// Inert first-profile producer hints.
    pub untrusted_hints: UntrustedHintsV1,
}

// ---------------------------------------------------------------------------
// Accepted artifact closure and remote authority record set.
// ---------------------------------------------------------------------------

/// One accepted-artifact reference (kind + digest).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedArtifactRefV1 {
    /// Frozen artifact kind (closed verifier-owned registry).
    pub artifact_kind: String,
    /// Domain-separated BLAKE3-256 digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub digest: ContentDigest,
}

/// Included availability for one accepted artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedArtifactAvailabilityV1 {
    /// Always `included` in the first remote profile.
    pub state: String,
    /// Declared exact byte length.
    pub byte_length: u64,
}

/// One accepted-artifact descriptor (artifact + availability).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedArtifactDescriptorV1 {
    /// The exact artifact reference.
    pub artifact: AcceptedArtifactRefV1,
    /// Its availability and byte length.
    pub availability: AcceptedArtifactAvailabilityV1,
}

/// One role-to-artifact binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedArtifactRoleBindingV1 {
    /// The exact bound artifact reference.
    pub artifact: AcceptedArtifactRefV1,
    /// The accepted role vocabulary label.
    pub role: String,
}

/// Exact accepted-artifact closure entrypoints (schema
/// `remoteReleaseArtifactClosureV1.entrypoints`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteReleaseArtifactClosureEntrypointsV1 {
    /// `release_v2` target release manifest.
    pub target_release_manifest: AcceptedArtifactRefV1,
    /// `proof_envelope_v1` target release proof envelope.
    pub target_release_proof_envelope: AcceptedArtifactRefV1,
    /// `environment_config_v2_projection` target environment configuration.
    pub target_environment_config: AcceptedArtifactRefV1,
    /// `release_v2` application effect.
    pub application_effect: AcceptedArtifactRefV1,
    /// `proof.dev/release-create-output/v2 ...` result derivation rule.
    pub result_derivation: String,
}

/// Authority-neutral manifest for one exact accepted artifact, `ReleaseV2`, and
/// Release Proof closure (schema `remoteReleaseArtifactClosureV1`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteReleaseArtifactClosureV1 {
    /// `proof.dev/remote-release-artifact-closure/v1`.
    pub api_version: RemoteReleaseArtifactClosureApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// `artifact_kind, digest UTF-8 bytewise ascending`.
    pub artifact_order: String,
    /// At most 4,090 unique accepted-artifact descriptors.
    pub artifacts: Vec<AcceptedArtifactDescriptorV1>,
    /// `role, artifact_kind, digest UTF-8 bytewise ascending`.
    pub role_binding_order: String,
    /// At most 4,096 unique role bindings.
    pub role_bindings: Vec<AcceptedArtifactRoleBindingV1>,
    /// The exact entrypoints.
    pub entrypoints: RemoteReleaseArtifactClosureEntrypointsV1,
}

/// Exact canonical bounded suffix of the P8 remote authority chain (schema
/// `remoteAuthorityRecordSetV1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAuthorityRecordSetV1 {
    /// `proof.dev/remote-authority-record-set/v1`.
    pub api_version: RemoteAuthorityRecordSetApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// The caller-pinned initial predecessor head.
    pub base_head: AuthorityHeadV1,
    /// `decoded authority_sequence ascending and contiguous`.
    pub record_order: String,
    /// At most 512 canonical remote authority envelopes.
    pub records: Vec<RemoteAuthorityRecordEnvelopeV1>,
    /// The included head (equals the last record's head).
    pub included_head: AuthorityHeadV1,
}

// ---------------------------------------------------------------------------
// Attempt companions and closure bindings.
// ---------------------------------------------------------------------------

/// Digest-addressed non-authority companion binding (schema
/// `componentBindingBase`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceComponentBindingV1 {
    /// Exact member path.
    pub member_path: String,
    /// Domain-separated digest of the exact member bytes.
    #[serde(with = "crate::serde_support::display_string")]
    pub record_digest: ContentDigest,
    /// `proof:...:vN` digest context.
    pub digest_context: String,
    /// `proof.<name>/vN` schema identifier.
    pub schema_id: String,
    /// Exact schema version.
    pub schema_version: u32,
}

/// The exact non-authority byte and deterministic-preimage closure for the
/// selected Agent `release.create/v2` success attempt (schema
/// `remoteAttemptCompanionsV1`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAttemptCompanionsV1 {
    /// `agent-release-create-v2-success`.
    pub profile: String,
    /// `actor/context-evidence.json`.
    pub actor_context_evidence: RemoteEvidenceComponentBindingV1,
    /// `authentication/event.json`.
    pub authentication_event: RemoteEvidenceComponentBindingV1,
    /// `attempt/command-input.json`.
    pub command_input: RemoteEvidenceComponentBindingV1,
    /// `attempt/authenticated-command-envelope.json`.
    pub authenticated_command_envelope: RemoteEvidenceComponentBindingV1,
}

/// Exact cross-links the composed verifier must enforce.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceCrossLinksV1 {
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Requesting Human Principal identity (UUIDv7).
    pub requesting_principal_id: String,
    /// Operating Agent Principal identity (UUIDv7).
    pub operating_principal_id: String,
    /// Delegation identity (UUIDv7).
    pub delegation_id: String,
    /// Presentation identity (UUIDv7).
    pub presentation_id: String,
    /// `proof:command:v1` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub command_digest: ContentDigest,
    /// `proof:authenticated-command-envelope:v1` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub authenticated_command_envelope_digest: ContentDigest,
    /// `proof:public-operation-input-projection:v1` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub public_input_projection_digest: ContentDigest,
    /// `release.create/v2` operation identity.
    pub operation: RemoteOperationV1,
    /// `required-uuidv7`.
    pub application_key_kind: String,
    /// The exact application idempotency key (UUIDv7).
    pub application_key: String,
    /// `proof:environment-config:v2` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    /// Always `2`.
    pub environment_config_version: u32,
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// `proof:release:v2` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_digest: ContentDigest,
    /// Release policy decision digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_policy_decision_digest: ContentDigest,
    /// Release Proof envelope digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_proof_envelope_digest: ContentDigest,
    /// `proof:operation-effect:v1` result digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub result_digest: ContentDigest,
    /// `proof:release:v2` application effect digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub application_effect_digest: ContentDigest,
}

/// Artifact-closure binding within [`RemoteEvidenceClosureBindingsV1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceArtifactClosureBindingV1 {
    /// `proof.dev/remote-release-artifact-closure/v1`.
    pub api_version: String,
    /// `content/release-closure.json`.
    pub manifest_member_path: String,
    /// Digest of the release-artifact closure member.
    #[serde(with = "crate::serde_support::display_string")]
    pub manifest_digest: ContentDigest,
    /// `proof:remote-release-artifact-closure:v1`.
    pub digest_context: String,
    /// `content/artifacts/`.
    pub artifact_root_prefix: String,
    /// `proof-verifier/accepted-release-artifact-semantics-v1`.
    pub verification_profile: String,
    /// `none; remote authority is verified only through closure_bindings.remote_authority`.
    pub authority_entrypoint: String,
}

/// Remote-authority binding within [`RemoteEvidenceClosureBindingsV1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceAuthorityBindingV1 {
    /// `authority/facts.json`.
    pub record_set_member_path: String,
    /// Digest of the record set member.
    #[serde(with = "crate::serde_support::display_string")]
    pub record_set_digest: ContentDigest,
    /// `proof:remote-authority-record-set:v1`.
    pub digest_context: String,
    /// The record-set included head.
    pub head: AuthorityHeadV1,
    /// Target decision digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub target_decision_digest: ContentDigest,
    /// Target consequence digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub target_consequence_digest: ContentDigest,
    /// `proof-verifier/remote-authority/v1`.
    pub verifier_profile: String,
}

/// Attempt-companion binding within [`RemoteEvidenceClosureBindingsV1`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceAttemptCompanionsBindingV1 {
    /// `agent-release-create-v2-success`.
    pub profile: String,
    /// `actor/context-evidence.json`.
    pub actor_context_evidence: RemoteEvidenceComponentBindingV1,
    /// `authentication/event.json`.
    pub authentication_event: RemoteEvidenceComponentBindingV1,
    /// `attempt/command-input.json`.
    pub command_input: RemoteEvidenceComponentBindingV1,
    /// `attempt/authenticated-command-envelope.json`.
    pub authenticated_command_envelope: RemoteEvidenceComponentBindingV1,
    /// The exact public-input-projection reconstruction rule.
    pub public_input_projection_rule: String,
    /// The exact result reconstruction rule.
    pub result_rule: String,
    /// The exact application-effect reconstruction rule.
    pub application_effect_rule: String,
}

/// Exact composition boundary between accepted artifact/Release-proof semantics
/// and the successor P8 remote-authority verifier (schema `closureBindings`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceClosureBindingsV1 {
    /// `proof.dev/remote-evidence-closure-bindings/v1`.
    pub api_version: RemoteEvidenceClosureBindingsApiVersion,
    /// The accepted-artifact closure binding.
    pub artifact_closure: RemoteEvidenceArtifactClosureBindingV1,
    /// The cross-links the composed verifier enforces.
    pub cross_links: RemoteEvidenceCrossLinksV1,
    /// The remote-authority closure binding.
    pub remote_authority: RemoteEvidenceAuthorityBindingV1,
    /// The attempt-companion binding.
    pub remote_attempt_companions: RemoteEvidenceAttemptCompanionsBindingV1,
}

// ---------------------------------------------------------------------------
// Member, manifest, capture, result, and status.
// ---------------------------------------------------------------------------

/// One captured root member descriptor (schema `member`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceMemberV1 {
    /// Normalized UTF-8 member path.
    pub member_path: String,
    /// One of the six root kinds.
    pub artifact_kind: RemoteEvidenceRootKind,
    /// `proof.<name>/vN` schema identifier.
    pub schema_id: String,
    /// Exact schema version.
    pub schema_version: u32,
    /// Exact media type.
    pub media_type: String,
    /// Canonicalization class.
    pub canonicalization: RemoteEvidenceCanonicalization,
    /// `proof:...:vN` digest context.
    pub digest_context: String,
    /// Declared exact byte length.
    pub byte_length: u64,
    /// Domain-separated digest of the exact member bytes.
    #[serde(with = "crate::serde_support::display_string")]
    pub content_digest: ContentDigest,
    /// `included` or `external-required`.
    pub delivery: RemoteEvidenceDelivery,
    /// `disclosure:<id>` when external-required, otherwise null.
    pub disclosure_id: Option<String>,
}

/// One typed disclosure requirement (schema `disclosureRequirement`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceDisclosureRequirementV1 {
    /// `disclosure:<id>` identifier.
    pub disclosure_id: String,
    /// `artifact-bytes` or `oidc-subject-opening`.
    pub kind: RemoteEvidenceDisclosureKind,
    /// The committed digest the disclosure must open or supply.
    #[serde(with = "crate::serde_support::display_string")]
    pub commitment_digest: ContentDigest,
}

/// The exact portable bundle manifest and complete manifest-digest preimage
/// (schema `evidenceManifestV2`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteEvidenceManifestV2 {
    /// `RemoteEvidenceManifestV2`.
    pub r#type: RemoteEvidenceManifestType,
    /// `proof.dev/remote-evidence-manifest/v2`.
    pub api_version: RemoteEvidenceManifestApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// `snapshot_<hex32>` producer label.
    pub snapshot_id: String,
    /// `pre-export-attempt-locked-heads`.
    pub snapshot_boundary: String,
    /// `proof:evidence-export-capture:v2` digest of the capture.
    #[serde(with = "crate::serde_support::display_string")]
    pub capture_digest: ContentDigest,
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// `proof:release:v2` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_digest: ContentDigest,
    /// The exact closure bindings.
    pub closure_bindings: RemoteEvidenceClosureBindingsV1,
    /// `complete-portable` or `explicit-external-artifacts`.
    pub disclosure_profile: RemoteEvidenceDisclosureProfile,
    /// The five captured heads.
    pub heads: EvidenceHeadsV1,
    /// `member_path UTF-8 bytewise ascending`.
    pub membership_order: String,
    /// The exact six-root membership.
    pub membership: Vec<RemoteEvidenceMemberV1>,
    /// `disclosure_id UTF-8 bytewise ascending`.
    pub disclosure_order: String,
    /// The exact typed disclosure requirements.
    pub disclosures: Vec<RemoteEvidenceDisclosureRequirementV1>,
}

impl RemoteEvidenceManifestV2 {
    /// Enumerates the included (producer-supplied) root member descriptors in
    /// declared `membership_order`.
    pub fn included_root_members(&self) -> impl Iterator<Item = &RemoteEvidenceMemberV1> {
        self.membership
            .iter()
            .filter(|member| member.delivery == RemoteEvidenceDelivery::Included)
    }

    /// Enumerates the external-required (caller-supplied) root member
    /// descriptors, which are absent from the logical member map.
    pub fn external_required_root_members(&self) -> impl Iterator<Item = &RemoteEvidenceMemberV1> {
        self.membership
            .iter()
            .filter(|member| member.delivery == RemoteEvidenceDelivery::ExternalRequired)
    }
}

/// One deterministic nested artifact selector derived from the release closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NestedArtifactSelectorV1 {
    /// `content/artifacts/<artifact_kind>/blake3/<digest-hex>.json`.
    pub member_path: String,
    /// The accepted artifact kind.
    pub artifact_kind: String,
    /// Domain-separated digest of the exact member bytes.
    pub digest: ContentDigest,
    /// Declared exact byte length.
    pub byte_length: u64,
}

impl RemoteReleaseArtifactClosureV1 {
    /// Enumerates each unique nested artifact's deterministic selector
    /// (`member_path`, `artifact_kind`, `digest`, `byte_length`).
    #[must_use]
    pub fn nested_selectors(&self) -> Vec<NestedArtifactSelectorV1> {
        self.artifacts
            .iter()
            .map(|descriptor| NestedArtifactSelectorV1 {
                member_path: nested_artifact_path(
                    &descriptor.artifact.artifact_kind,
                    &descriptor.artifact.digest,
                ),
                artifact_kind: descriptor.artifact.artifact_kind.clone(),
                digest: descriptor.artifact.digest,
                byte_length: descriptor.availability.byte_length,
            })
            .collect()
    }
}

/// The complete immutable export-capture digest preimage (schema
/// `evidenceExportCaptureV2`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportCaptureV2 {
    /// `EvidenceExportCaptureV2`.
    pub r#type: EvidenceExportCaptureType,
    /// `proof.dev/evidence-export-capture/v2`.
    pub api_version: EvidenceExportCaptureApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// The exact `evidence.export/v2` application idempotency key (UUIDv7).
    pub idempotency_key: String,
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// `proof:release:v2` digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_digest: ContentDigest,
    /// The exact closure bindings.
    pub closure_bindings: RemoteEvidenceClosureBindingsV1,
    /// `complete-portable` or `explicit-external-artifacts`.
    pub disclosure_profile: RemoteEvidenceDisclosureProfile,
    /// `SERIALIZABLE READ WRITE`.
    pub transaction_isolation: String,
    /// Server-recorded capture time.
    #[serde(with = "crate::serde_support::display_string")]
    pub captured_at: Timestamp,
    /// `snapshot_<hex32>` producer label.
    pub snapshot_id: String,
    /// `pre-export-attempt-locked-heads`.
    pub snapshot_boundary: String,
    /// The five locked heads.
    pub heads: EvidenceHeadsV1,
    /// `member_path UTF-8 bytewise ascending`.
    pub membership_order: String,
    /// The exact six-root membership.
    pub membership: Vec<RemoteEvidenceMemberV1>,
    /// `disclosure_id UTF-8 bytewise ascending`.
    pub disclosure_order: String,
    /// The exact typed disclosure requirements.
    pub disclosures: Vec<RemoteEvidenceDisclosureRequirementV1>,
    /// Always `1`.
    pub build_event_count: u32,
    /// Always `pending`.
    pub state_after_commit: String,
}

/// The exact keyed `evidence.export/v2` create result; always `status: pending`
/// (contract §"Evidence export and independent verification").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportResultV2 {
    /// `proof.dev/evidence-export-result/v2`.
    pub api_version: EvidenceExportResultApiVersion,
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// The exact application idempotency key (UUIDv7).
    pub application_key: String,
    /// `proof:evidence-export-capture:v2` digest of the immutable capture.
    #[serde(with = "crate::serde_support::display_string")]
    pub capture_digest: ContentDigest,
    /// Always `pending` at creation and on every same-key replay.
    pub status: EvidenceExportStatusKind,
}

/// The mutable readiness projection returned by the no-key
/// `evidence.export.get/v1` lifecycle read (contract §"Evidence export and
/// independent verification").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceExportStatusV1 {
    /// `proof.dev/evidence-export-status/v1`.
    pub api_version: EvidenceExportStatusApiVersion,
    /// Export identity (UUIDv7).
    pub export_id: String,
    /// `pending` or `ready`.
    pub status: EvidenceExportStatusKind,
    /// `proof:remote-evidence-bundle:v2` reserved descriptor digest; null while
    /// pending.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub bundle_descriptor_digest: Option<ContentDigest>,
    /// `proof:remote-evidence-manifest:v2` reserved manifest digest; null while
    /// pending.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub manifest_digest: Option<ContentDigest>,
    /// Exact included artifact count; zero while pending.
    pub artifact_count: u64,
    /// Exact total included bytes; zero while pending.
    pub total_included_bytes: u64,
}

// ---------------------------------------------------------------------------
// Caller trust policy, checkpoints, and verifier input.
// ---------------------------------------------------------------------------

/// Independently supplied Ed25519 verifier key and validity window (schema
/// `trustedKey`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKeyV2 {
    /// `ed25519:<64 lowercase hex>` key identifier.
    pub key_id: String,
    /// Standard base64 of the exact decoded 32-byte public key.
    pub public_key: String,
    /// Validity window start.
    #[serde(with = "crate::serde_support::display_string")]
    pub not_before: Timestamp,
    /// Validity window end; null means unbounded.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub not_after: Option<Timestamp>,
    /// Revocation time; null means not revoked.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub revoked_at: Option<Timestamp>,
}

/// One accepted authority policy bundle selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPolicyBundleV1 {
    /// `proof.local/authority/direct/v1`.
    pub policy_profile: String,
    /// Accepted policy-bundle digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub policy_bundle_digest: ContentDigest,
}

/// One accepted release policy profile selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedReleasePolicyProfileV1 {
    /// Accepted Environment configuration digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    /// `proof.local/release-policy/v1`.
    pub policy_profile: String,
}

/// Authority trust inputs of [`VerificationTrustPolicyV2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTrustV2 {
    /// Independently supplied active Workspace authority key.
    pub initial_root: TrustedKeyV2,
    /// Caller-pinned initial remote authority head.
    pub initial_head: AuthorityHeadV1,
    /// Accepted authorization-projection SHA-256 values.
    pub accepted_authorization_registry_hashes: Vec<String>,
    /// Accepted complete operation-registry SHA-256 values.
    pub accepted_operation_registry_hashes: Vec<String>,
    /// Accepted authority policy bundles.
    pub accepted_policy_bundles: Vec<AcceptedPolicyBundleV1>,
    /// Authority checkpoint requirement.
    pub checkpoint_requirement: CheckpointRequirement,
    /// Optional compromise cutoff head.
    pub compromise_cutoff: Option<AuthorityHeadV1>,
}

/// Release trust inputs of [`VerificationTrustPolicyV2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustV2 {
    /// Caller-supplied closed Release signer set.
    pub trusted_signers: Vec<TrustedKeyV2>,
    /// Accepted Release attestation predicate types.
    pub accepted_predicate_types: Vec<String>,
    /// Accepted release policy profiles.
    pub accepted_policy_profiles: Vec<AcceptedReleasePolicyProfileV1>,
}

/// Remote identity trust inputs of [`VerificationTrustPolicyV2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteIdentityTrustV2 {
    /// Accepted OIDC issuer configuration digests.
    #[serde(with = "crate::serde_support::display_string_vec")]
    pub accepted_oidc_issuer_configuration_digests: Vec<ContentDigest>,
}

/// Disclosure policy of [`VerificationTrustPolicyV2`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicyV2 {
    /// Whether the selected requesting-subject opening is required.
    pub requesting_subject_opening: RequestingSubjectOpeningPolicy,
}

/// Parser/artifact/record/byte limits of [`VerificationTrustPolicyV2`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationLimitsV2 {
    /// Caller-selected raw verifier-input byte ceiling.
    pub max_verifier_input_bytes: u64,
    /// Maximum outer manifest bytes.
    pub max_manifest_bytes: u64,
    /// Maximum artifact bodies.
    pub max_artifacts: u64,
    /// Maximum authority records.
    pub max_authority_records: u64,
    /// Maximum bytes for one artifact body.
    pub max_artifact_bytes: u64,
    /// Maximum total bytes.
    pub max_total_bytes: u64,
    /// Maximum strict JSON depth.
    pub max_json_depth: u64,
}

impl VerificationLimitsV2 {
    /// The exact fixed contract limits (contract §"Evidence export and
    /// independent verification", limits table).
    #[must_use]
    pub const fn contract() -> Self {
        Self {
            max_verifier_input_bytes: MAX_VERIFIER_INPUT_BYTES as u64,
            max_manifest_bytes: MAX_MANIFEST_BYTES as u64,
            max_artifacts: MAX_EXPORT_ARTIFACT_BODIES as u64,
            max_authority_records: MAX_AUTHORITY_RECORDS as u64,
            max_artifact_bytes: MAX_ARTIFACT_BYTES as u64,
            max_total_bytes: MAX_TOTAL_BYTES as u64,
            max_json_depth: 128,
        }
    }
}

/// Closed offline hash-to-canonical-registry resolver descriptor (schema
/// `verificationTrustPolicy.registry_resolution`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryResolutionV1 {
    /// `proof.verifier/collaboration-registry/v1`.
    pub profile: String,
    /// `verifier-built-in-closed-hash-to-rfc8785-document-table`.
    pub source: String,
    /// Always `Invalid`.
    pub unknown_hash_result: RegistryResolutionFailure,
    /// Always `Invalid`.
    pub hash_mismatch_result: RegistryResolutionFailure,
}

/// The exact caller-controlled trust input for remote verification (schema
/// `verificationTrustPolicy`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationTrustPolicyV2 {
    /// `proof.dev/verification-trust-policy/v2`.
    pub api_version: VerificationTrustPolicyApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// The closed offline registry resolver descriptor.
    pub registry_resolution: RegistryResolutionV1,
    /// Role-separated authority trust.
    pub authority: AuthorityTrustV2,
    /// Role-separated Release trust.
    pub release: ReleaseTrustV2,
    /// Accepted remote identity (OIDC issuer configuration) digests.
    pub remote_identity: RemoteIdentityTrustV2,
    /// Disclosure policy.
    pub disclosure: DisclosurePolicyV2,
    /// Parser/artifact/record/byte limits.
    pub limits: VerificationLimitsV2,
}

/// Independently obtained authority checkpoint (schema `authorityCheckpoint`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpointV1 {
    /// `proof.dev/authority-checkpoint/v1`.
    pub api_version: AuthorityCheckpointApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Checked authority sequence.
    pub authority_sequence: u64,
    /// Checked authority record digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub authority_record_digest: ContentDigest,
    /// Active authority key identifier at the checkpoint.
    pub active_authority_key_id: String,
    /// Observation time.
    #[serde(with = "crate::serde_support::display_string")]
    pub observed_at: Timestamp,
}

impl AuthorityCheckpointV1 {
    /// A required authority checkpoint must equal the included head in
    /// Workspace, sequence, digest, and active key (contract §"Evidence export
    /// and independent verification").
    #[must_use]
    pub fn matches_included_head(
        &self,
        record_set: &RemoteAuthorityRecordSetV1,
        initial_root_key_id: &str,
    ) -> bool {
        self.workspace_id == record_set.workspace_id
            && self.authority_sequence == record_set.included_head.sequence
            && self.authority_record_digest == record_set.included_head.record_digest
            && self.active_authority_key_id == initial_root_key_id
    }

    /// A checkpoint whose sequence exceeds the included head is not ancestry:
    /// the intervening records are not supplied in the caller-anchored suffix.
    #[must_use]
    pub fn exceeds_included_head(&self, record_set: &RemoteAuthorityRecordSetV1) -> bool {
        self.authority_sequence > record_set.included_head.sequence
    }
}

/// Independently obtained Environment/Release expectation (schema
/// `environmentReleaseCheckpoint`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentReleaseCheckpointV2 {
    /// `proof.dev/environment-release-checkpoint/v2`.
    pub api_version: EnvironmentReleaseCheckpointApiVersion,
    /// Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Environment identity.
    pub environment_id: String,
    /// Environment configuration digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub environment_config_digest: ContentDigest,
    /// Always `2`.
    pub environment_config_version: u32,
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// Release digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub release_digest: ContentDigest,
    /// Observation time.
    #[serde(with = "crate::serde_support::display_string")]
    pub observed_at: Timestamp,
}

/// Exact caller-supplied bytes for one external-required root (schema
/// `externalArtifact`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalArtifactV2 {
    /// Exact member path.
    pub member_path: String,
    /// One of the three external-required root kinds.
    pub artifact_kind: RemoteEvidenceRootKind,
    /// Always `external-required`.
    pub delivery: RemoteEvidenceDelivery,
    /// `disclosure:<id>` identifier.
    pub disclosure_id: String,
    /// `proof.<name>/vN` schema identifier.
    pub schema_id: String,
    /// Exact schema version.
    pub schema_version: u32,
    /// Canonicalization class.
    pub canonicalization: RemoteEvidenceCanonicalization,
    /// `proof:...:vN` digest context.
    pub digest_context: String,
    /// Declared content digest.
    #[serde(with = "crate::serde_support::display_string")]
    pub content_digest: ContentDigest,
    /// Exact media type.
    pub media_type: String,
    /// Declared exact decoded byte length.
    pub byte_length: u64,
    /// Standard base64 of the exact decoded bytes.
    pub bytes_base64: String,
}

/// Complete caller-controlled input for the composed verifier (schema
/// `verifierInput`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RemoteVerifierInputV2 {
    /// `RemoteVerifierInputV2`.
    pub r#type: RemoteVerifierInputType,
    /// `proof.dev/remote-verifier-input/v2`.
    pub api_version: RemoteVerifierInputApiVersion,
    /// The exact accepted caller trust policy.
    pub verification_trust_policy: VerificationTrustPolicyV2,
    /// `proof:verification-trust-policy:v2` digest of the trust policy.
    #[serde(with = "crate::serde_support::display_string")]
    pub trust_policy_digest: ContentDigest,
    /// Authorized OIDC subject-commitment openings.
    pub subject_openings: Vec<OidcSubjectCommitmentOpeningV1>,
    /// Optional authority checkpoint.
    pub authority_checkpoint: Option<AuthorityCheckpointV1>,
    /// Optional Environment/Release checkpoint.
    pub environment_release_checkpoint: Option<EnvironmentReleaseCheckpointV2>,
    /// Exact caller-supplied external-artifact bytes.
    pub external_artifacts: Vec<ExternalArtifactV2>,
    /// Always false; bundle hints are never authority.
    pub bundle_hints_are_authority: bool,
    /// Always false; the verifier never opens the network.
    pub network_access: bool,
    /// Always false; the verifier never opens a producer database.
    pub database_access: bool,
    /// Always false; the verifier has no producer session.
    pub session_access: bool,
    /// Always `0`.
    pub private_key_count: u64,
    /// Always `0`.
    pub credential_count: u64,
}

impl RemoteVerifierInputV2 {
    /// True when the caller's required authority checkpoint is supplied and
    /// equals the record set's included head in Workspace, sequence, digest,
    /// and active key (contract §"Evidence export and independent
    /// verification"). A missing checkpoint fails a `required` policy.
    #[must_use]
    pub fn required_authority_checkpoint_satisfied(
        &self,
        record_set: &RemoteAuthorityRecordSetV1,
    ) -> bool {
        match &self.authority_checkpoint {
            Some(checkpoint) => checkpoint.matches_included_head(
                record_set,
                &self.verification_trust_policy.authority.initial_root.key_id,
            ),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Closed verifier report types.
// ---------------------------------------------------------------------------

/// Per-component observed results (schema `componentResults`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationComponentResultsV2 {
    /// Signature component.
    pub signature: VerificationComponentResult,
    /// Actor component.
    pub actor: VerificationComponentResult,
    /// Authority component.
    pub authority: VerificationComponentResult,
    /// Role-separation component.
    pub role_separation: VerificationComponentResult,
    /// Approval component.
    pub approval: VerificationComponentResult,
    /// Policy component.
    pub policy: VerificationComponentResult,
    /// Content component.
    pub content: VerificationComponentResult,
    /// Environment component.
    pub environment: VerificationComponentResult,
    /// Release component.
    pub release: VerificationComponentResult,
    /// Delivery evidence (always `not-requested` in this claim).
    pub delivery_evidence: VerificationComponentResult,
    /// Completeness component.
    pub completeness: VerificationComponentResult,
}

impl VerificationComponentResultsV2 {
    /// Derives the first-applicable primary reason code consistent with the
    /// component results, status, and scenario (contract §"Evidence export and
    /// independent verification", `x-proof-primary-reason-rule`).
    #[must_use]
    pub fn primary_reason(
        &self,
        status: VerificationStatus,
        scenario: VerificationScenario,
    ) -> VerificationReasonCode {
        match status {
            VerificationStatus::Complete => VerificationReasonCode::Verified,
            VerificationStatus::Incomplete => match scenario {
                VerificationScenario::IncompleteRequiredOpeningWithheld => {
                    VerificationReasonCode::MissingDisclosure
                }
                VerificationScenario::IncompleteRequiredArtifactWithheld => {
                    VerificationReasonCode::MissingArtifact
                }
                VerificationScenario::IncompleteRequiredAuthorityCheckpointWithheld => {
                    VerificationReasonCode::MissingCheckpoint
                }
                _ => VerificationReasonCode::MissingArtifact,
            },
            VerificationStatus::Invalid => {
                // The content-only conformance scenario selects `tampered-artifact`.
                if scenario == VerificationScenario::InvalidContentArtifactByteTamper {
                    return VerificationReasonCode::TamperedArtifact;
                }
                // First-applicable Invalid class in the frozen precedence order.
                if self.signature == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidSignature
                } else if self.actor == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidActor
                } else if self.authority == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidAuthority
                } else if self.role_separation == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidRoleSeparation
                } else if self.approval == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidApproval
                } else if self.policy == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidPolicy
                } else if self.content == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidContent
                } else if self.environment == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidEnvironment
                } else if self.release == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidRelease
                } else if self.completeness == VerificationComponentResult::Invalid {
                    VerificationReasonCode::InvalidCompleteness
                } else {
                    VerificationReasonCode::InvalidContent
                }
            }
        }
    }
}

/// The general closed observed report for every Complete, Incomplete, and
/// Invalid outcome (schema `report`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVerificationReportV2 {
    /// `RemoteVerificationReportV2`.
    pub r#type: RemoteVerificationReportType,
    /// `proof.dev/remote-verification-report/v2`.
    pub api_version: RemoteVerificationReportApiVersion,
    /// `observed-verifier-outcome`.
    pub claim_kind: String,
    /// Always true.
    pub runtime_observed: bool,
    /// `execution_<hex16>`.
    pub execution_id: String,
    /// Report observation time.
    #[serde(with = "crate::serde_support::display_string")]
    pub observed_at: Timestamp,
    /// `proof-verifier/remote-evidence-v2`.
    pub verifier_profile: String,
    /// `report_<hex16>`.
    pub report_id: String,
    /// The observed scenario.
    pub scenario: VerificationScenario,
    /// The observed status.
    pub status: VerificationStatus,
    /// The exact snapshot-scope nonclaim statement.
    pub snapshot_scope: String,
    /// `proof:remote-verifier-input-raw:v1` digest of the exact input bytes.
    #[serde(with = "crate::serde_support::display_string")]
    pub raw_verifier_input_digest: ContentDigest,
    /// Raw bundle descriptor digest; null when absent.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub raw_bundle_descriptor_digest: Option<ContentDigest>,
    /// Raw bundle manifest digest; null when absent.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub raw_bundle_manifest_digest: Option<ContentDigest>,
    /// Typed manifest digest; null when no strict manifest parsed.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub bundle_manifest_digest: Option<ContentDigest>,
    /// Typed verifier-input digest; null when no strict input parsed.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub verifier_input_digest: Option<ContentDigest>,
    /// Typed trust-policy digest; null when no strict trust parsed.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub trust_policy_digest: Option<ContentDigest>,
    /// Authority checkpoint digest; null when no checkpoint supplied.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub authority_checkpoint_digest: Option<ContentDigest>,
    /// Environment/Release checkpoint digest; null when no checkpoint supplied.
    #[serde(default, with = "crate::serde_support::optional_display_string")]
    pub environment_release_checkpoint_digest: Option<ContentDigest>,
    /// Per-component observed results.
    pub components: VerificationComponentResultsV2,
    /// Exactly one primary reason code.
    pub reason_codes: Vec<VerificationReasonCode>,
}

impl RemoteVerificationReportV2 {
    /// Derives the first-applicable primary reason code from the report's own
    /// status, scenario, and component results.
    #[must_use]
    pub fn primary_reason(&self) -> VerificationReasonCode {
        self.components.primary_reason(self.status, self.scenario)
    }
}

impl ConformanceScenario {
    /// Narrows a general [`VerificationScenario`] to the exact three retained
    /// P-0008 qualification scenarios, rejecting the non-retained scenarios
    /// (`incomplete-required-artifact-withheld`,
    /// `incomplete-required-authority-checkpoint-withheld`, and
    /// `invalid-verification`).
    #[must_use]
    pub fn from_verification_scenario(scenario: VerificationScenario) -> Option<Self> {
        match scenario {
            VerificationScenario::CompleteExactMaterialization => {
                Some(Self::CompleteExactMaterialization)
            }
            VerificationScenario::IncompleteRequiredOpeningWithheld => {
                Some(Self::IncompleteRequiredOpeningWithheld)
            }
            VerificationScenario::InvalidContentArtifactByteTamper => {
                Some(Self::InvalidContentArtifactByteTamper)
            }
            VerificationScenario::IncompleteRequiredArtifactWithheld
            | VerificationScenario::IncompleteRequiredAuthorityCheckpointWithheld
            | VerificationScenario::InvalidVerification => None,
        }
    }
}

/// The exact three-scenario qualification subtype (schema `conformanceReport`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVerificationConformanceReportV2 {
    /// The general observed report (status/component/reason already narrowed).
    pub report: RemoteVerificationReportV2,
    /// The exact retained P-0008 qualification scenario.
    pub scenario: ConformanceScenario,
}

impl RemoteVerificationConformanceReportV2 {
    /// True when the conformance report's narrowed scenario is consistent with
    /// its inner general report's scenario (i.e. the general scenario is one of
    /// the exactly three retained qualification scenarios and narrows to
    /// `self.scenario`).
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        ConformanceScenario::from_verification_scenario(self.report.scenario) == Some(self.scenario)
    }
}
