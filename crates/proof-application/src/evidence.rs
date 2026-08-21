//! Producer-side contracts for portable P-0006 evidence export.

use std::collections::BTreeSet;

use proof_canonical::{canonicalize, digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ArtifactKind, ContentDigest, ReleaseId, WorkspaceId, authority::AuthorityHeadV1};

/// Exact wire version for the portable evidence index.
pub const AUTHORITY_EVIDENCE_BUNDLE_API_VERSION: &str = "proof.dev/authority-evidence-bundle/v1";
/// Maximum canonical bundle-manifest length.
pub const MAX_AUTHORITY_EVIDENCE_MANIFEST_BYTES: usize = 4 * 1_048_576;
/// Maximum number of described artifacts.
pub const MAX_AUTHORITY_EVIDENCE_ARTIFACTS: usize = 4_096;
/// Maximum authority records in one v1 prefix.
pub const MAX_AUTHORITY_EVIDENCE_RECORDS: usize = 512;
/// Maximum canonical bytes in any one portable artifact.
pub const MAX_AUTHORITY_EVIDENCE_ARTIFACT_BYTES: usize = 4 * 1_048_576;
/// Maximum cumulative included artifact bytes.
pub const MAX_AUTHORITY_EVIDENCE_TOTAL_BYTES: u64 = 256 * 1_048_576;

/// Stable semantic role of one portable artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRoleV1 {
    ReleaseManifest,
    ReleaseProofEnvelope,
    ReleasePolicyDecision,
    ReleaseSigningKey,
    ReleaseSigningKeyRevocation,
    EnvironmentConfig,
    EnvironmentPolicyBundle,
    Edition,
    KnownState,
    EditionDelta,
    ChangeSet,
    Edit,
    ValidationAttempt,
    Submission,
    Approval,
    ContextPack,
    ContextPolicyBundle,
    ResourceIntent,
    Object,
    Schema,
    LocaleRevision,
    AuthorityRecordEnvelope,
    AuthenticatedCommandEnvelope,
    CommandInput,
    ActorContextEvidence,
    LocalizedResult,
    LocalizedConsequence,
    ApplicationEffect,
    SubjectOpening,
}

impl EvidenceRoleV1 {
    /// Returns the stable lowercase wire name used for canonical ordering.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ReleaseManifest => "release_manifest",
            Self::ReleaseProofEnvelope => "release_proof_envelope",
            Self::ReleasePolicyDecision => "release_policy_decision",
            Self::ReleaseSigningKey => "release_signing_key",
            Self::ReleaseSigningKeyRevocation => "release_signing_key_revocation",
            Self::EnvironmentConfig => "environment_config",
            Self::EnvironmentPolicyBundle => "environment_policy_bundle",
            Self::Edition => "edition",
            Self::KnownState => "known_state",
            Self::EditionDelta => "edition_delta",
            Self::ChangeSet => "change_set",
            Self::Edit => "edit",
            Self::ValidationAttempt => "validation_attempt",
            Self::Submission => "submission",
            Self::Approval => "approval",
            Self::ContextPack => "context_pack",
            Self::ContextPolicyBundle => "context_policy_bundle",
            Self::ResourceIntent => "resource_intent",
            Self::Object => "object",
            Self::Schema => "schema",
            Self::LocaleRevision => "locale_revision",
            Self::AuthorityRecordEnvelope => "authority_record_envelope",
            Self::AuthenticatedCommandEnvelope => "authenticated_command_envelope",
            Self::CommandInput => "command_input",
            Self::ActorContextEvidence => "actor_context_evidence",
            Self::LocalizedResult => "localized_result",
            Self::LocalizedConsequence => "localized_consequence",
            Self::ApplicationEffect => "application_effect",
            Self::SubjectOpening => "subject_opening",
        }
    }
}

/// Domain-separated reference to one canonical artifact.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactRefV1 {
    #[serde(with = "artifact_kind_wire")]
    pub artifact_kind: ArtifactKind,
    #[serde(with = "display_string")]
    pub digest: ContentDigest,
}

impl EvidenceArtifactRefV1 {
    /// Returns the only permitted relative path for this reference.
    #[must_use]
    pub fn relative_path(self) -> String {
        let digest = self.digest.to_string();
        let encoded = digest.strip_prefix("blake3:").unwrap_or(digest.as_str());
        format!(
            "artifacts/{}/blake3/{encoded}.json",
            self.artifact_kind.wire_name()
        )
    }
}

/// Whether artifact bytes are in the bundle or must be disclosed separately.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvidenceAvailabilityV1 {
    Included { byte_length: u64 },
    ExternalCommitment,
}

/// One strict inventory entry in the portable bundle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifactDescriptorV1 {
    pub role: EvidenceRoleV1,
    pub artifact: EvidenceArtifactRefV1,
    pub availability: EvidenceAvailabilityV1,
}

/// Required companion evidence for a signed authorization decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCompanionV1 {
    pub command_input: EvidenceArtifactRefV1,
    pub authenticated_command_envelope: EvidenceArtifactRefV1,
    pub actor_context_evidence: EvidenceArtifactRefV1,
    pub result: Option<EvidenceArtifactRefV1>,
    pub localized_consequence: Option<EvidenceArtifactRefV1>,
    pub application_effect: Option<EvidenceArtifactRefV1>,
}

/// One position in the complete signed authority prefix.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPrefixEntryV1 {
    pub sequence: u64,
    #[serde(with = "display_string")]
    pub record_digest: ContentDigest,
    pub authority_envelope: EvidenceArtifactRefV1,
    pub decision_companion: Option<DecisionCompanionV1>,
}

/// Trusted-claim entrypoints whose complete closure the verifier derives.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidenceBundleEntrypointsV1 {
    pub target_release_manifest: EvidenceArtifactRefV1,
    pub target_release_proof_envelope: EvidenceArtifactRefV1,
    #[serde(with = "display_string")]
    pub target_authorization_record_digest: ContentDigest,
    pub target_localized_consequence: EvidenceArtifactRefV1,
}

/// Strict portable index over one Release and its complete authority closure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvidenceBundleV1 {
    pub api_version: String,
    #[serde(with = "display_string")]
    pub workspace_id: WorkspaceId,
    pub entrypoints: AuthorityEvidenceBundleEntrypointsV1,
    pub included_authority_head: AuthorityHeadV1,
    pub authority_prefix: Vec<AuthorityPrefixEntryV1>,
    pub artifacts: Vec<EvidenceArtifactDescriptorV1>,
}

impl AuthorityEvidenceBundleV1 {
    /// Constructs the exact v1 wire version.
    #[must_use]
    pub fn new(
        workspace_id: WorkspaceId,
        entrypoints: AuthorityEvidenceBundleEntrypointsV1,
        included_authority_head: AuthorityHeadV1,
        authority_prefix: Vec<AuthorityPrefixEntryV1>,
        artifacts: Vec<EvidenceArtifactDescriptorV1>,
    ) -> Self {
        Self {
            api_version: AUTHORITY_EVIDENCE_BUNDLE_API_VERSION.to_owned(),
            workspace_id,
            entrypoints,
            included_authority_head,
            authority_prefix,
            artifacts,
        }
    }

    /// Checks closed-version, order, uniqueness, and bounded-container invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityEvidenceExportError::InvalidBundle`] for a structural
    /// contract violation and [`AuthorityEvidenceExportError::LimitExceeded`]
    /// when a v1 size or count bound is exceeded.
    pub fn validate(&self) -> Result<(), AuthorityEvidenceExportError> {
        if self.api_version != AUTHORITY_EVIDENCE_BUNDLE_API_VERSION {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "unsupported bundle version".to_owned(),
            ));
        }
        if self.authority_prefix.is_empty()
            || self.authority_prefix.len() > MAX_AUTHORITY_EVIDENCE_RECORDS
            || self.artifacts.is_empty()
            || self.artifacts.len() > MAX_AUTHORITY_EVIDENCE_ARTIFACTS
        {
            return Err(AuthorityEvidenceExportError::LimitExceeded);
        }
        for (index, entry) in self.authority_prefix.iter().enumerate() {
            let expected = u64::try_from(index + 1)
                .map_err(|_| AuthorityEvidenceExportError::LimitExceeded)?;
            if entry.sequence != expected {
                return Err(AuthorityEvidenceExportError::InvalidBundle(
                    "authority prefix is not contiguous from sequence 1".to_owned(),
                ));
            }
        }
        let Some(last) = self.authority_prefix.last() else {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "authority prefix is empty".to_owned(),
            ));
        };
        if last.sequence != self.included_authority_head.sequence.get()
            || last.record_digest != self.included_authority_head.record_digest
            || !self.authority_prefix.iter().any(|entry| {
                entry.record_digest == self.entrypoints.target_authorization_record_digest
                    && entry.decision_companion.is_some()
            })
        {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "entrypoints or included authority head do not match the prefix".to_owned(),
            ));
        }
        let keys = self
            .artifacts
            .iter()
            .map(|descriptor| {
                (
                    descriptor.role,
                    descriptor.artifact.artifact_kind.wire_name(),
                    descriptor.artifact.digest.to_string(),
                )
            })
            .collect::<BTreeSet<_>>();
        if keys.len() != self.artifacts.len() {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "artifact descriptors are not unique".to_owned(),
            ));
        }
        if !self.artifacts.windows(2).all(|pair| {
            let left = (
                pair[0].role.wire_name(),
                pair[0].artifact.artifact_kind.wire_name(),
                pair[0].artifact.digest.to_string(),
            );
            let right = (
                pair[1].role.wire_name(),
                pair[1].artifact.artifact_kind.wire_name(),
                pair[1].artifact.digest.to_string(),
            );
            left < right
        }) {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "artifact descriptors are not in canonical order".to_owned(),
            ));
        }
        let mut total = 0_u64;
        for descriptor in &self.artifacts {
            if let EvidenceAvailabilityV1::Included { byte_length } = descriptor.availability {
                if byte_length == 0 || byte_length > MAX_AUTHORITY_EVIDENCE_ARTIFACT_BYTES as u64 {
                    return Err(AuthorityEvidenceExportError::LimitExceeded);
                }
                total = total
                    .checked_add(byte_length)
                    .ok_or(AuthorityEvidenceExportError::LimitExceeded)?;
            }
        }
        if total > MAX_AUTHORITY_EVIDENCE_TOTAL_BYTES {
            return Err(AuthorityEvidenceExportError::LimitExceeded);
        }
        Ok(())
    }

    /// Returns exact canonical manifest JSON and its domain-separated digest.
    ///
    /// # Errors
    ///
    /// Returns an export error when the bundle is invalid, exceeds a v1 bound,
    /// or cannot be serialized canonically.
    pub fn canonical_manifest(
        &self,
    ) -> Result<(String, ContentDigest), AuthorityEvidenceExportError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|error| AuthorityEvidenceExportError::InvalidBundle(error.to_string()))?;
        let canonical = canonicalize(&value)
            .map_err(|error| AuthorityEvidenceExportError::InvalidBundle(error.to_string()))?;
        if canonical.as_bytes().len() > MAX_AUTHORITY_EVIDENCE_MANIFEST_BYTES {
            return Err(AuthorityEvidenceExportError::LimitExceeded);
        }
        let manifest_digest = digest(ArtifactKind::AuthorityEvidenceBundleV1, &canonical);
        Ok((canonical.as_str().to_owned(), manifest_digest))
    }
}

/// One materialized canonical artifact returned by the producer port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalEvidenceArtifactV1 {
    pub artifact: EvidenceArtifactRefV1,
    pub canonical_json: String,
}

/// Complete bounded producer output before filesystem materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityEvidenceBundleExportV1 {
    pub bundle: AuthorityEvidenceBundleV1,
    pub canonical_manifest_json: String,
    pub manifest_digest: ContentDigest,
    pub artifacts: Vec<CanonicalEvidenceArtifactV1>,
}

/// Input selecting one immutable Release closure for export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExportAuthorityEvidenceBundleV1Command {
    pub release_id: ReleaseId,
    pub subject_opening: SubjectOpeningDisclosureV1,
}

/// Caller-selected disclosure posture for the protected subject opening.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SubjectOpeningDisclosureV1 {
    /// Export only the public commitment; this is the safe default.
    #[default]
    Withhold,
    /// Include an opening only when audit policy and storage permit it.
    Include,
}

/// Path-neutral receipt returned after producing one complete bundle graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityEvidenceBundleReceiptV1 {
    pub release_id: ReleaseId,
    pub manifest_digest: ContentDigest,
    pub included_authority_head: AuthorityHeadV1,
    pub descriptor_count: u32,
    pub included_artifact_count: u32,
    pub included_bytes: u64,
}

/// Producer port that extracts one complete bounded portable evidence graph.
pub trait AuthorityEvidenceExportRepository {
    /// Returns canonical manifest and artifact bytes without selecting a path.
    ///
    /// # Errors
    ///
    /// Returns an export error when authentication, extraction, closure, or
    /// canonical validation fails.
    fn export_authority_evidence_bundle(
        &self,
        command: ExportAuthorityEvidenceBundleV1Command,
    ) -> Result<AuthorityEvidenceBundleExportV1, AuthorityEvidenceExportError>;
}

/// Exports one portable authority-evidence closure through its producer port.
///
/// # Errors
///
/// Returns the producer port's exact export failure.
pub fn export_authority_evidence_bundle(
    repository: &impl AuthorityEvidenceExportRepository,
    command: ExportAuthorityEvidenceBundleV1Command,
) -> Result<AuthorityEvidenceBundleExportV1, AuthorityEvidenceExportError> {
    repository.export_authority_evidence_bundle(command)
}

/// Portable evidence export failed before a complete bundle was returned.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AuthorityEvidenceExportError {
    #[error("the current caller is not authenticated to export Workspace evidence")]
    AccessDenied,
    #[error("the requested Release was not found")]
    NotFound,
    #[error("the portable evidence closure is incomplete: {0}")]
    Incomplete(String),
    #[error("the portable evidence closure violates its contract: {0}")]
    InvalidBundle(String),
    #[error("the portable evidence closure exceeds a v1 bound")]
    LimitExceeded,
    #[error("portable evidence storage is unavailable: {0}")]
    Storage(String),
}

mod display_string {
    use std::{fmt::Display, str::FromStr};

    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<T: Display, S: Serializer>(
        value: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

mod artifact_kind_wire {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    use crate::ArtifactKind;

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(
        value: &ArtifactKind,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.wire_name())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ArtifactKind, D::Error> {
        let value = String::deserialize(deserializer)?;
        ArtifactKind::from_wire_name(&value)
            .ok_or_else(|| D::Error::custom("unknown artifact kind"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::AuthoritySequence;

    #[test]
    fn content_addressed_path_is_closed_and_algorithm_qualified() {
        let reference = EvidenceArtifactRefV1 {
            artifact_kind: ArtifactKind::ReleaseV2,
            digest: ContentDigest::blake3([0xab; 32]),
        };
        assert_eq!(
            reference.relative_path(),
            format!("artifacts/release_v2/blake3/{}.json", "ab".repeat(32))
        );
    }

    #[test]
    fn artifact_kind_wire_registry_round_trips() {
        for kind in proof_domain::ALL_ARTIFACT_KINDS {
            let reference = EvidenceArtifactRefV1 {
                artifact_kind: kind,
                digest: ContentDigest::blake3([0x11; 32]),
            };
            let value = serde_json::to_value(reference).unwrap();
            assert_eq!(value["artifact_kind"], kind.wire_name());
            assert_eq!(
                serde_json::from_value::<EvidenceArtifactRefV1>(value)
                    .unwrap()
                    .artifact_kind,
                kind
            );
        }
    }

    #[test]
    fn authority_record_bound_accepts_512_and_rejects_513() {
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let reference = EvidenceArtifactRefV1 {
            artifact_kind: ArtifactKind::AuthorityRecordEnvelopeV1,
            digest: ContentDigest::blake3([0x22; 32]),
        };
        let companion = DecisionCompanionV1 {
            command_input: reference,
            authenticated_command_envelope: reference,
            actor_context_evidence: reference,
            result: None,
            localized_consequence: None,
            application_effect: None,
        };
        let prefix = (1..=MAX_AUTHORITY_EVIDENCE_RECORDS)
            .map(|sequence| AuthorityPrefixEntryV1 {
                sequence: sequence as u64,
                record_digest: ContentDigest::blake3([0x33; 32]),
                authority_envelope: reference,
                decision_companion: (sequence == MAX_AUTHORITY_EVIDENCE_RECORDS)
                    .then_some(companion),
            })
            .collect::<Vec<_>>();
        let head = AuthorityHeadV1 {
            sequence: AuthoritySequence::new(MAX_AUTHORITY_EVIDENCE_RECORDS as u64).unwrap(),
            record_digest: ContentDigest::blake3([0x33; 32]),
        };
        let entrypoints = AuthorityEvidenceBundleEntrypointsV1 {
            target_release_manifest: reference,
            target_release_proof_envelope: reference,
            target_authorization_record_digest: head.record_digest,
            target_localized_consequence: reference,
        };
        let descriptors = vec![EvidenceArtifactDescriptorV1 {
            role: EvidenceRoleV1::AuthorityRecordEnvelope,
            artifact: reference,
            availability: EvidenceAvailabilityV1::Included { byte_length: 1 },
        }];
        let accepted = AuthorityEvidenceBundleV1::new(
            workspace_id,
            entrypoints,
            head,
            prefix.clone(),
            descriptors.clone(),
        );
        assert_eq!(accepted.validate(), Ok(()));

        let mut exceeded_prefix = prefix;
        exceeded_prefix.push(AuthorityPrefixEntryV1 {
            sequence: 513,
            record_digest: ContentDigest::blake3([0x44; 32]),
            authority_envelope: reference,
            decision_companion: None,
        });
        let exceeded = AuthorityEvidenceBundleV1::new(
            workspace_id,
            entrypoints,
            AuthorityHeadV1 {
                sequence: AuthoritySequence::new(513).unwrap(),
                record_digest: ContentDigest::blake3([0x44; 32]),
            },
            exceeded_prefix,
            descriptors,
        );
        assert_eq!(
            exceeded.validate(),
            Err(AuthorityEvidenceExportError::LimitExceeded)
        );
    }
}
