use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

pub const BUNDLE_API_VERSION: &str = "proof.dev/authority-evidence-bundle/v1";
pub const TRUST_POLICY_API_VERSION: &str = "proof.dev/verification-trust-policy/v1";
pub const CHECKPOINT_API_VERSION: &str = "proof.dev/authority-checkpoint/v1";
pub const REPORT_API_VERSION: &str = "proof.dev/verification-report/v1";
pub const MAX_MANIFEST_BYTES: usize = 4 * 1_048_576;
pub const MAX_ARTIFACTS: usize = 4_096;
pub const MAX_AUTHORITY_RECORDS: usize = 512;
pub const MAX_ARTIFACT_BYTES: usize = 4 * 1_048_576;
pub const MAX_TOTAL_BYTES: u64 = 256 * 1_048_576;
pub const MAX_EXTERNAL_ROOTS: usize = 8;
pub const MAX_JSON_DEPTH: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let encoded = value.strip_prefix("blake3:")?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(Self(bytes))
    }

    #[must_use]
    pub fn hex(self) -> String {
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            use fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("blake3:")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).ok_or_else(|| D::Error::custom("invalid BLAKE3 digest"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    EditionV1,
    #[serde(rename = "changeset_v1")]
    ChangeSetV1,
    ContextPackV1,
    ValidationResultsV1,
    KnownStateV1,
    SchemaVersionV1,
    EditBatchV1,
    OperationEffectV1,
    SchemaSetV1,
    ObjectRevisionV1,
    ObjectSetV1,
    EnvironmentConfigV1,
    ReleaseV1,
    ProofEnvelopeV1,
    DelegationV1,
    PrincipalRegistrationV1,
    AuthorizationDecisionV1,
    PolicyBundleV1,
    CommandV1,
    AuthenticatedCommandEnvelopeV1,
    BindingEnrollmentChallengeV1,
    BindingEnrollmentEnvelopeV1,
    AuthenticatedSubjectCommitmentV1,
    AuthenticatedActorContextV1,
    AuthorityRecordV1,
    AuthorityRecordEnvelopeV1,
    ContentResourceIntentV1,
    ContextPackV2,
    EditBatchV2,
    EditV2,
    #[serde(rename = "changeset_v2")]
    ChangeSetV2,
    ValidationResultsV2,
    ObjectLocaleRevisionV1,
    ObjectSetV2,
    KnownStateV2,
    EditionV2,
    ReleaseV2,
    AuthorityEvidenceBundleV1,
    AuthenticatedLocalizedConsequenceV1,
    AuthenticatedSubjectOpeningV1,
    AuthorityCheckpointV1,
    VerificationTrustPolicyV1,
    VerificationReportV1,
    ReleaseSigningKeyV1,
    ReleaseSigningKeyRevocationV1,
}

impl ArtifactKind {
    #[must_use]
    pub const fn context(self) -> &'static str {
        match self {
            Self::EditionV1 => "proof:edition:v1",
            Self::ChangeSetV1 => "proof:changeset:v1",
            Self::ContextPackV1 => "proof:context-pack:v1",
            Self::ValidationResultsV1 => "proof:validation-results:v1",
            Self::KnownStateV1 => "proof:known-state:v1",
            Self::SchemaVersionV1 => "proof:schema-version:v1",
            Self::EditBatchV1 => "proof:edit-batch:v1",
            Self::OperationEffectV1 => "proof:operation-effect:v1",
            Self::SchemaSetV1 => "proof:schema-set:v1",
            Self::ObjectRevisionV1 => "proof:object-revision:v1",
            Self::ObjectSetV1 => "proof:object-set:v1",
            Self::EnvironmentConfigV1 => "proof:environment-config:v1",
            Self::ReleaseV1 => "proof:release:v1",
            Self::ProofEnvelopeV1 => "proof:proof-envelope:v1",
            Self::DelegationV1 => "proof:delegation:v1",
            Self::PrincipalRegistrationV1 => "proof:principal-registration:v1",
            Self::AuthorizationDecisionV1 => "proof:authorization-decision:v1",
            Self::PolicyBundleV1 => "proof:policy-bundle:v1",
            Self::CommandV1 => "proof:command:v1",
            Self::AuthenticatedCommandEnvelopeV1 => "proof:authenticated-command-envelope:v1",
            Self::BindingEnrollmentChallengeV1 => "proof:binding-enrollment-challenge:v1",
            Self::BindingEnrollmentEnvelopeV1 => "proof:binding-enrollment-envelope:v1",
            Self::AuthenticatedSubjectCommitmentV1 => "proof:authenticated-subject-commitment:v1",
            Self::AuthenticatedActorContextV1 => "proof:authenticated-actor-context:v1",
            Self::AuthorityRecordV1 => "proof:authority-record:v1",
            Self::AuthorityRecordEnvelopeV1 => "proof:authority-record-envelope:v1",
            Self::ContentResourceIntentV1 => "proof:content-resource-intent:v1",
            Self::ContextPackV2 => "proof:context-pack:v2",
            Self::EditBatchV2 => "proof:edit-batch:v2",
            Self::EditV2 => "proof:edit:v2",
            Self::ChangeSetV2 => "proof:changeset:v2",
            Self::ValidationResultsV2 => "proof:validation-results:v2",
            Self::ObjectLocaleRevisionV1 => "proof:object-locale-revision:v1",
            Self::ObjectSetV2 => "proof:object-set:v2",
            Self::KnownStateV2 => "proof:known-state:v2",
            Self::EditionV2 => "proof:edition:v2",
            Self::ReleaseV2 => "proof:release:v2",
            Self::AuthorityEvidenceBundleV1 => "proof:authority-evidence-bundle:v1",
            Self::AuthenticatedLocalizedConsequenceV1 => {
                "proof:authenticated-localized-consequence:v1"
            }
            Self::AuthenticatedSubjectOpeningV1 => "proof:authenticated-subject-opening:v1",
            Self::AuthorityCheckpointV1 => "proof:authority-checkpoint:v1",
            Self::VerificationTrustPolicyV1 => "proof:verification-trust-policy:v1",
            Self::VerificationReportV1 => "proof:verification-report:v1",
            Self::ReleaseSigningKeyV1 => "proof:release-signing-key:v1",
            Self::ReleaseSigningKeyRevocationV1 => "proof:release-signing-key-revocation:v1",
        }
    }

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EditionV1 => "edition_v1",
            Self::ChangeSetV1 => "changeset_v1",
            Self::ContextPackV1 => "context_pack_v1",
            Self::ValidationResultsV1 => "validation_results_v1",
            Self::KnownStateV1 => "known_state_v1",
            Self::SchemaVersionV1 => "schema_version_v1",
            Self::EditBatchV1 => "edit_batch_v1",
            Self::OperationEffectV1 => "operation_effect_v1",
            Self::SchemaSetV1 => "schema_set_v1",
            Self::ObjectRevisionV1 => "object_revision_v1",
            Self::ObjectSetV1 => "object_set_v1",
            Self::EnvironmentConfigV1 => "environment_config_v1",
            Self::ReleaseV1 => "release_v1",
            Self::ProofEnvelopeV1 => "proof_envelope_v1",
            Self::DelegationV1 => "delegation_v1",
            Self::PrincipalRegistrationV1 => "principal_registration_v1",
            Self::AuthorizationDecisionV1 => "authorization_decision_v1",
            Self::PolicyBundleV1 => "policy_bundle_v1",
            Self::CommandV1 => "command_v1",
            Self::AuthenticatedCommandEnvelopeV1 => "authenticated_command_envelope_v1",
            Self::BindingEnrollmentChallengeV1 => "binding_enrollment_challenge_v1",
            Self::BindingEnrollmentEnvelopeV1 => "binding_enrollment_envelope_v1",
            Self::AuthenticatedSubjectCommitmentV1 => "authenticated_subject_commitment_v1",
            Self::AuthenticatedActorContextV1 => "authenticated_actor_context_v1",
            Self::AuthorityRecordV1 => "authority_record_v1",
            Self::AuthorityRecordEnvelopeV1 => "authority_record_envelope_v1",
            Self::ContentResourceIntentV1 => "content_resource_intent_v1",
            Self::ContextPackV2 => "context_pack_v2",
            Self::EditBatchV2 => "edit_batch_v2",
            Self::EditV2 => "edit_v2",
            Self::ChangeSetV2 => "changeset_v2",
            Self::ValidationResultsV2 => "validation_results_v2",
            Self::ObjectLocaleRevisionV1 => "object_locale_revision_v1",
            Self::ObjectSetV2 => "object_set_v2",
            Self::KnownStateV2 => "known_state_v2",
            Self::EditionV2 => "edition_v2",
            Self::ReleaseV2 => "release_v2",
            Self::AuthorityEvidenceBundleV1 => "authority_evidence_bundle_v1",
            Self::AuthenticatedLocalizedConsequenceV1 => "authenticated_localized_consequence_v1",
            Self::AuthenticatedSubjectOpeningV1 => "authenticated_subject_opening_v1",
            Self::AuthorityCheckpointV1 => "authority_checkpoint_v1",
            Self::VerificationTrustPolicyV1 => "verification_trust_policy_v1",
            Self::VerificationReportV1 => "verification_report_v1",
            Self::ReleaseSigningKeyV1 => "release_signing_key_v1",
            Self::ReleaseSigningKeyRevocationV1 => "release_signing_key_revocation_v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
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

impl EvidenceRole {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub artifact_kind: ArtifactKind,
    pub digest: Digest,
}

impl ArtifactRef {
    #[must_use]
    pub fn relative_path(self) -> String {
        format!(
            "artifacts/{}/blake3/{}.json",
            self.artifact_kind.wire_name(),
            self.digest.hex()
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Availability {
    Included { byte_length: u64 },
    ExternalCommitment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    pub role: EvidenceRole,
    pub artifact: ArtifactRef,
    pub availability: Availability,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionCompanion {
    pub command_input: ArtifactRef,
    pub authenticated_command_envelope: ArtifactRef,
    pub actor_context_evidence: ArtifactRef,
    pub result: Option<ArtifactRef>,
    pub localized_consequence: Option<ArtifactRef>,
    pub application_effect: Option<ArtifactRef>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityPrefixEntry {
    pub sequence: u64,
    pub record_digest: Digest,
    pub authority_envelope: ArtifactRef,
    pub decision_companion: Option<DecisionCompanion>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHead {
    pub sequence: u64,
    pub record_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entrypoints {
    pub target_release_manifest: ArtifactRef,
    pub target_release_proof_envelope: ArtifactRef,
    pub target_authorization_record_digest: Digest,
    pub target_localized_consequence: ArtifactRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub api_version: String,
    pub workspace_id: String,
    pub entrypoints: Entrypoints,
    pub included_authority_head: AuthorityHead,
    pub authority_prefix: Vec<AuthorityPrefixEntry>,
    pub artifacts: Vec<ArtifactDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: String,
    pub not_before: String,
    pub not_after: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedReleasePolicy {
    pub policy_profile: String,
    pub environment_config_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrust {
    pub trusted_signers: Vec<TrustedKey>,
    pub accepted_predicate_types: Vec<String>,
    pub accepted_policy_profiles: Vec<AcceptedReleasePolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedAuthorityPolicy {
    pub policy_profile: String,
    pub policy_bundle_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointRequirement {
    Required,
    InternalPrefixOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTrust {
    pub initial_root: TrustedKey,
    pub accepted_policy_bundles: Vec<AcceptedAuthorityPolicy>,
    pub checkpoint_requirement: CheckpointRequirement,
    pub compromise_cutoff: Option<AuthorityHead>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OpeningRequirement {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosurePolicy {
    pub requesting_subject_opening: OpeningRequirement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationLimits {
    pub max_manifest_bytes: u64,
    pub max_artifacts: u32,
    pub max_authority_records: u32,
    pub max_artifact_bytes: u64,
    pub max_total_bytes: u64,
    pub max_json_depth: u32,
}

impl VerificationLimits {
    #[must_use]
    pub const fn hard() -> Self {
        Self {
            max_manifest_bytes: MAX_MANIFEST_BYTES as u64,
            max_artifacts: 4_096,
            max_authority_records: 512,
            max_artifact_bytes: MAX_ARTIFACT_BYTES as u64,
            max_total_bytes: MAX_TOTAL_BYTES,
            max_json_depth: 128,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPolicy {
    pub api_version: String,
    pub workspace_id: String,
    pub release: ReleaseTrust,
    pub authority: AuthorityTrust,
    pub disclosure: DisclosurePolicy,
    pub limits: VerificationLimits,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub api_version: String,
    pub workspace_id: String,
    pub authority_sequence: u64,
    pub authority_record_digest: Digest,
    pub active_authority_key_id: String,
    pub observed_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Complete,
    Incomplete,
    Invalid,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionStatus {
    Valid,
    Incomplete,
    Invalid,
    NotRequired,
}

impl DimensionStatus {
    const fn severity(self) -> u8 {
        match self {
            Self::NotRequired | Self::Valid => 0,
            Self::Incomplete => 1,
            Self::Invalid => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryScope {
    PinnedHead,
    InternalPrefix,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub dimension: String,
    pub artifact_digest: Option<Digest>,
    pub authority_sequence: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedClaims {
    pub workspace_id: Option<String>,
    pub release_id: Option<String>,
    pub release_digest: Option<Digest>,
    pub authorization_decision_digest: Option<Digest>,
    pub authority_head: Option<AuthorityHead>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub api_version: String,
    pub bundle_manifest_digest: Option<Digest>,
    pub trust_policy_digest: Digest,
    pub checkpoint_digest: Option<Digest>,
    pub outcome: Outcome,
    pub history_scope: HistoryScope,
    pub dimensions: BTreeMap<String, DimensionStatus>,
    pub findings: Vec<Finding>,
    pub verified_claims: VerifiedClaims,
}

impl Report {
    #[must_use]
    pub fn new(trust_policy_digest: Digest, checkpoint_digest: Option<Digest>) -> Self {
        let dimensions = [
            "trust_policy",
            "container",
            "canonical",
            "artifact_integrity",
            "release_signature",
            "release_key_trust",
            "release_subjects",
            "content_delta",
            "authority_signatures",
            "authority_sequence",
            "authority_checkpoint",
            "command_authentication",
            "principal_binding",
            "delegation",
            "policy",
            "approval",
            "subject_commitment",
            "subject_opening",
            "localized_consequence",
            "application_key_history",
            "evidence_completeness",
        ]
        .into_iter()
        .map(|dimension| (dimension.to_owned(), DimensionStatus::Incomplete))
        .collect();
        Self {
            api_version: REPORT_API_VERSION.to_owned(),
            bundle_manifest_digest: None,
            trust_policy_digest,
            checkpoint_digest,
            outcome: Outcome::Incomplete,
            history_scope: HistoryScope::InternalPrefix,
            dimensions,
            findings: Vec::new(),
            verified_claims: VerifiedClaims {
                workspace_id: None,
                release_id: None,
                release_digest: None,
                authorization_decision_digest: None,
                authority_head: None,
            },
        }
    }

    pub fn finding(
        &mut self,
        dimension: &str,
        status: DimensionStatus,
        code: &str,
        artifact_digest: Option<Digest>,
        authority_sequence: Option<u64>,
    ) {
        let current = self
            .dimensions
            .get(dimension)
            .copied()
            .unwrap_or(DimensionStatus::Incomplete);
        if status.severity() > current.severity() {
            self.dimensions.insert(dimension.to_owned(), status);
        }
        self.findings.push(Finding {
            code: code.to_owned(),
            dimension: dimension.to_owned(),
            artifact_digest,
            authority_sequence,
        });
        self.outcome = aggregate(self.dimensions.values().copied());
    }

    pub fn valid(&mut self, dimension: &str) {
        if self.dimensions.get(dimension) == Some(&DimensionStatus::Incomplete)
            && !self
                .findings
                .iter()
                .any(|finding| finding.dimension == dimension)
        {
            self.dimensions
                .insert(dimension.to_owned(), DimensionStatus::Valid);
        }
        self.outcome = aggregate(self.dimensions.values().copied());
    }

    pub fn not_required(&mut self, dimension: &str) {
        if self.dimensions.get(dimension) == Some(&DimensionStatus::Incomplete)
            && !self
                .findings
                .iter()
                .any(|finding| finding.dimension == dimension)
        {
            self.dimensions
                .insert(dimension.to_owned(), DimensionStatus::NotRequired);
        }
        self.outcome = aggregate(self.dimensions.values().copied());
    }

    pub fn finalize(&mut self) {
        self.findings.sort_by(|left, right| {
            (
                left.dimension.as_str(),
                left.code.as_str(),
                left.artifact_digest,
                left.authority_sequence,
            )
                .cmp(&(
                    right.dimension.as_str(),
                    right.code.as_str(),
                    right.artifact_digest,
                    right.authority_sequence,
                ))
        });
        self.findings.dedup_by(|left, right| {
            left.dimension == right.dimension
                && left.code == right.code
                && left.artifact_digest == right.artifact_digest
                && left.authority_sequence == right.authority_sequence
        });
        self.outcome = aggregate(self.dimensions.values().copied());
        if self.outcome == Outcome::Invalid {
            self.verified_claims = VerifiedClaims {
                workspace_id: None,
                release_id: None,
                release_digest: None,
                authorization_decision_digest: None,
                authority_head: None,
            };
        }
    }
}

fn aggregate(statuses: impl Iterator<Item = DimensionStatus>) -> Outcome {
    let mut incomplete = false;
    for status in statuses {
        match status {
            DimensionStatus::Invalid => return Outcome::Invalid,
            DimensionStatus::Incomplete => incomplete = true,
            DimensionStatus::Valid | DimensionStatus::NotRequired => {}
        }
    }
    if incomplete {
        Outcome::Incomplete
    } else {
        Outcome::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_dimensions_default_incomplete() {
        let report = Report::new(Digest([1; 32]), None);
        assert_eq!(report.outcome, Outcome::Incomplete);
        assert_eq!(report.history_scope, HistoryScope::InternalPrefix);
        assert!(
            report
                .dimensions
                .values()
                .all(|status| *status == DimensionStatus::Incomplete)
        );
    }

    #[test]
    fn invalid_report_never_serializes_unverified_claims() {
        let mut report = Report::new(Digest([0x21; 32]), None);
        report.verified_claims.workspace_id = Some("unverified-workspace".to_owned());
        report.verified_claims.release_id = Some("unverified-release".to_owned());
        report.verified_claims.release_digest = Some(Digest([0x22; 32]));
        report.verified_claims.authorization_decision_digest = Some(Digest([0x23; 32]));
        report.verified_claims.authority_head = Some(AuthorityHead {
            sequence: 9,
            record_digest: Digest([0x24; 32]),
        });
        report.finding(
            "release_signature",
            DimensionStatus::Invalid,
            "proof.verify.release.signature",
            None,
            None,
        );
        report.finalize();
        assert_eq!(report.outcome, Outcome::Invalid);
        assert!(report.verified_claims.workspace_id.is_none());
        assert!(report.verified_claims.release_id.is_none());
        assert!(report.verified_claims.release_digest.is_none());
        assert!(
            report
                .verified_claims
                .authorization_decision_digest
                .is_none()
        );
        assert!(report.verified_claims.authority_head.is_none());
    }

    #[test]
    fn dimension_updates_are_monotonic_and_order_independent() {
        let mut first = Report::new(Digest([1; 32]), None);
        first.finding("policy", DimensionStatus::Invalid, "z", None, None);
        first.finding("policy", DimensionStatus::Incomplete, "a", None, None);
        first.valid("policy");
        let mut second = Report::new(Digest([1; 32]), None);
        second.finding("policy", DimensionStatus::Incomplete, "a", None, None);
        second.finding("policy", DimensionStatus::Invalid, "z", None, None);
        second.valid("policy");
        first.finalize();
        second.finalize();
        assert_eq!(first.dimensions["policy"], DimensionStatus::Invalid);
        assert_eq!(first.dimensions, second.dimensions);
        assert_eq!(first.findings, second.findings);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the independent wire registry is intentionally exhaustive in one test"
    )]
    fn independent_artifact_wire_registry_is_exact() {
        let cases = [
            (ArtifactKind::EditionV1, "edition_v1"),
            (ArtifactKind::ChangeSetV1, "changeset_v1"),
            (ArtifactKind::ContextPackV1, "context_pack_v1"),
            (ArtifactKind::ValidationResultsV1, "validation_results_v1"),
            (ArtifactKind::KnownStateV1, "known_state_v1"),
            (ArtifactKind::SchemaVersionV1, "schema_version_v1"),
            (ArtifactKind::EditBatchV1, "edit_batch_v1"),
            (ArtifactKind::OperationEffectV1, "operation_effect_v1"),
            (ArtifactKind::SchemaSetV1, "schema_set_v1"),
            (ArtifactKind::ObjectRevisionV1, "object_revision_v1"),
            (ArtifactKind::ObjectSetV1, "object_set_v1"),
            (ArtifactKind::EnvironmentConfigV1, "environment_config_v1"),
            (ArtifactKind::ReleaseV1, "release_v1"),
            (ArtifactKind::ProofEnvelopeV1, "proof_envelope_v1"),
            (ArtifactKind::DelegationV1, "delegation_v1"),
            (
                ArtifactKind::PrincipalRegistrationV1,
                "principal_registration_v1",
            ),
            (
                ArtifactKind::AuthorizationDecisionV1,
                "authorization_decision_v1",
            ),
            (ArtifactKind::PolicyBundleV1, "policy_bundle_v1"),
            (ArtifactKind::CommandV1, "command_v1"),
            (
                ArtifactKind::AuthenticatedCommandEnvelopeV1,
                "authenticated_command_envelope_v1",
            ),
            (
                ArtifactKind::BindingEnrollmentChallengeV1,
                "binding_enrollment_challenge_v1",
            ),
            (
                ArtifactKind::BindingEnrollmentEnvelopeV1,
                "binding_enrollment_envelope_v1",
            ),
            (
                ArtifactKind::AuthenticatedSubjectCommitmentV1,
                "authenticated_subject_commitment_v1",
            ),
            (
                ArtifactKind::AuthenticatedActorContextV1,
                "authenticated_actor_context_v1",
            ),
            (ArtifactKind::AuthorityRecordV1, "authority_record_v1"),
            (
                ArtifactKind::AuthorityRecordEnvelopeV1,
                "authority_record_envelope_v1",
            ),
            (
                ArtifactKind::ContentResourceIntentV1,
                "content_resource_intent_v1",
            ),
            (ArtifactKind::ContextPackV2, "context_pack_v2"),
            (ArtifactKind::EditBatchV2, "edit_batch_v2"),
            (ArtifactKind::EditV2, "edit_v2"),
            (ArtifactKind::ChangeSetV2, "changeset_v2"),
            (ArtifactKind::ValidationResultsV2, "validation_results_v2"),
            (
                ArtifactKind::ObjectLocaleRevisionV1,
                "object_locale_revision_v1",
            ),
            (ArtifactKind::ObjectSetV2, "object_set_v2"),
            (ArtifactKind::KnownStateV2, "known_state_v2"),
            (ArtifactKind::EditionV2, "edition_v2"),
            (ArtifactKind::ReleaseV2, "release_v2"),
            (
                ArtifactKind::AuthorityEvidenceBundleV1,
                "authority_evidence_bundle_v1",
            ),
            (
                ArtifactKind::AuthenticatedLocalizedConsequenceV1,
                "authenticated_localized_consequence_v1",
            ),
            (
                ArtifactKind::AuthenticatedSubjectOpeningV1,
                "authenticated_subject_opening_v1",
            ),
            (
                ArtifactKind::AuthorityCheckpointV1,
                "authority_checkpoint_v1",
            ),
            (
                ArtifactKind::VerificationTrustPolicyV1,
                "verification_trust_policy_v1",
            ),
            (ArtifactKind::VerificationReportV1, "verification_report_v1"),
            (ArtifactKind::ReleaseSigningKeyV1, "release_signing_key_v1"),
            (
                ArtifactKind::ReleaseSigningKeyRevocationV1,
                "release_signing_key_revocation_v1",
            ),
        ];
        assert_eq!(cases.len(), 45);
        for (kind, wire) in cases {
            assert_eq!(kind.wire_name(), wire);
            assert_eq!(serde_json::to_value(kind).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<ArtifactKind>(serde_json::Value::String(wire.to_owned()))
                    .unwrap(),
                kind
            );
        }
    }
}
