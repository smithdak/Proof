#![forbid(unsafe_code)]

//! Independent, bounded verifier for portable Proof authority evidence.

mod container;
mod crypto;
pub mod model;
mod operation;
mod schema;
mod semantics;
mod strict_json;

use std::path::{Path, PathBuf};

use model::{
    ArtifactKind, CHECKPOINT_API_VERSION, Checkpoint, DimensionStatus, REPORT_API_VERSION, Report,
    TrustPolicy,
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::{
    container::load_bundle,
    crypto::domain_digest,
    strict_json::{canonical_bytes, parse_canonical},
};

/// Immutable inputs for one clean-directory verification.
#[derive(Clone, Copy, Debug)]
pub struct VerificationRequest<'a> {
    /// Directory containing exactly `bundle.json` and declared included artifacts.
    pub bundle_root: &'a Path,
    /// Canonical caller-controlled trust-policy bytes.
    pub trust_policy_json: &'a [u8],
    /// Optional canonical caller-controlled checkpoint bytes.
    pub checkpoint_json: Option<&'a [u8]>,
    /// Optional read-only content-addressed roots for externally disclosed artifacts.
    pub external_roots: &'a [PathBuf],
}

/// A bounded verifier input could not be represented as its strict wire type.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InputError {
    /// Input exceeds a fixed v1 byte, count, or depth limit.
    #[error("verification input exceeds a v1 bound")]
    Limit,
    /// Input is ambiguous, noncanonical, or violates its closed schema.
    #[error("verification input is not canonical v1 JSON")]
    Invalid,
}

/// Parsed trust policy paired with its domain-separated identity.
#[derive(Clone, Debug)]
pub struct ParsedTrustPolicy {
    /// Strict caller-controlled policy.
    pub policy: TrustPolicy,
    /// Digest over the exact canonical policy bytes.
    pub digest: model::Digest,
}

/// Parsed authority checkpoint paired with its domain-separated identity.
#[derive(Clone, Debug)]
pub struct ParsedCheckpoint {
    /// Strict caller-controlled checkpoint.
    pub checkpoint: Checkpoint,
    /// Digest over the exact canonical checkpoint bytes.
    pub digest: model::Digest,
}

/// Parses and validates canonical caller trust without consulting a producer.
///
/// # Errors
///
/// Returns [`InputError::Limit`] when bytes or declared limits exceed v1 hard
/// bounds, and [`InputError::Invalid`] for noncanonical or invalid policy data.
pub fn parse_trust_policy(input: &[u8]) -> Result<ParsedTrustPolicy, InputError> {
    if input.len() > model::MAX_MANIFEST_BYTES {
        return Err(InputError::Limit);
    }
    let policy: TrustPolicy = parse_typed(input)?;
    validate_trust_policy(&policy)?;
    Ok(ParsedTrustPolicy {
        policy,
        digest: domain_digest(ArtifactKind::VerificationTrustPolicyV1, input),
    })
}

/// Parses and validates a canonical caller checkpoint.
///
/// # Errors
///
/// Returns [`InputError::Limit`] when bytes exceed the v1 bound, and
/// [`InputError::Invalid`] for noncanonical or invalid checkpoint data.
pub fn parse_checkpoint(input: &[u8]) -> Result<ParsedCheckpoint, InputError> {
    if input.len() > model::MAX_ARTIFACT_BYTES {
        return Err(InputError::Limit);
    }
    let checkpoint: Checkpoint = parse_typed(input)?;
    if checkpoint.api_version != CHECKPOINT_API_VERSION
        || !operation::uuid_v7(&checkpoint.workspace_id)
        || checkpoint.authority_sequence == 0
        || semantics::parse_timestamp(&checkpoint.observed_at).is_none()
        || checkpoint.active_authority_key_id.is_empty()
    {
        return Err(InputError::Invalid);
    }
    Ok(ParsedCheckpoint {
        checkpoint,
        digest: domain_digest(ArtifactKind::AuthorityCheckpointV1, input),
    })
}

/// Verifies one bundle using only supplied public inputs and artifact bytes.
///
/// The function never opens a producer database, reconstructs producer state,
/// or accesses private signing material. Findings contain stable codes only.
#[must_use]
pub fn verify_bundle_directory(request: VerificationRequest<'_>) -> Report {
    let trust_digest = domain_digest(
        ArtifactKind::VerificationTrustPolicyV1,
        request.trust_policy_json,
    );
    let checkpoint_digest = request
        .checkpoint_json
        .map(|bytes| domain_digest(ArtifactKind::AuthorityCheckpointV1, bytes));
    let mut report = Report::new(trust_digest, checkpoint_digest);

    let trust = match parse_trust_policy(request.trust_policy_json) {
        Ok(value) => {
            report.valid("trust_policy");
            value
        }
        Err(InputError::Limit) => {
            report.finding(
                "trust_policy",
                DimensionStatus::Invalid,
                "proof.verify.trust.limit",
                None,
                None,
            );
            report.finalize();
            return report;
        }
        Err(InputError::Invalid) => {
            report.finding(
                "trust_policy",
                DimensionStatus::Invalid,
                "proof.verify.trust.invalid",
                None,
                None,
            );
            report.finalize();
            return report;
        }
    };

    let checkpoint = match request.checkpoint_json {
        Some(bytes) => match parse_checkpoint(bytes) {
            Ok(value) => Some(value),
            Err(error) => {
                let code = match error {
                    InputError::Limit => "proof.verify.checkpoint.limit",
                    InputError::Invalid => "proof.verify.checkpoint.invalid",
                };
                report.finding(
                    "authority_checkpoint",
                    DimensionStatus::Invalid,
                    code,
                    None,
                    None,
                );
                None
            }
        },
        None => None,
    };

    let Some(loaded) = load_bundle(
        request.bundle_root,
        &trust.policy,
        request.external_roots,
        &mut report,
    ) else {
        report.finalize();
        return report;
    };
    report.bundle_manifest_digest = Some(loaded.manifest_digest);
    report.verified_claims.workspace_id = Some(loaded.bundle.workspace_id.clone());
    semantics::verify_semantics(&loaded, &trust.policy, checkpoint.as_ref(), &mut report);
    report.finalize();
    report
}

/// Serializes a finalized report canonically and returns its v1 digest.
///
/// # Errors
///
/// Returns [`InputError::Invalid`] only when report serialization fails.
pub fn canonical_report(report: &Report) -> Result<(Vec<u8>, model::Digest), InputError> {
    let mut normalized = report.clone();
    REPORT_API_VERSION.clone_into(&mut normalized.api_version);
    normalized.finalize();
    let bytes = canonical_bytes(&normalized).map_err(|_| InputError::Invalid)?;
    let digest = domain_digest(ArtifactKind::VerificationReportV1, &bytes);
    Ok((bytes, digest))
}

fn parse_typed<T: DeserializeOwned>(input: &[u8]) -> Result<T, InputError> {
    let value = parse_canonical(input, model::MAX_JSON_DEPTH).map_err(|_| InputError::Invalid)?;
    serde_json::from_value(value).map_err(|_| InputError::Invalid)
}

fn validate_trust_policy(policy: &TrustPolicy) -> Result<(), InputError> {
    let hard = model::VerificationLimits::hard();
    let limits = policy.limits;
    if limits.max_manifest_bytes > hard.max_manifest_bytes
        || limits.max_artifacts > hard.max_artifacts
        || limits.max_authority_records > hard.max_authority_records
        || limits.max_artifact_bytes > hard.max_artifact_bytes
        || limits.max_total_bytes > hard.max_total_bytes
        || limits.max_json_depth > hard.max_json_depth
        || policy.release.trusted_signers.len() > 32
        || policy.release.accepted_predicate_types.len() > 32
        || policy.release.accepted_policy_profiles.len() > 128
        || policy.authority.accepted_policy_bundles.len() > 128
    {
        return Err(InputError::Limit);
    }
    if policy.api_version != model::TRUST_POLICY_API_VERSION
        || !operation::uuid_v7(&policy.workspace_id)
        || limits.max_manifest_bytes == 0
        || limits.max_artifacts == 0
        || limits.max_authority_records == 0
        || limits.max_artifact_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_json_depth == 0
        || policy.release.trusted_signers.is_empty()
        || policy.release.accepted_predicate_types.is_empty()
        || policy.release.accepted_policy_profiles.is_empty()
        || policy.authority.accepted_policy_bundles.is_empty()
        || policy
            .release
            .accepted_predicate_types
            .iter()
            .any(String::is_empty)
        || policy
            .release
            .accepted_predicate_types
            .iter()
            .any(|value| value.len() > 512)
        || policy
            .release
            .accepted_policy_profiles
            .iter()
            .any(|accepted| {
                accepted.policy_profile.is_empty() || accepted.policy_profile.len() > 256
            })
        || policy
            .authority
            .accepted_policy_bundles
            .iter()
            .any(|accepted| {
                accepted.policy_profile.is_empty() || accepted.policy_profile.len() > 256
            })
    {
        return Err(InputError::Invalid);
    }
    if !strictly_sorted_unique(
        policy
            .release
            .accepted_predicate_types
            .iter()
            .map(String::as_str),
    ) || !strictly_sorted_unique(policy.release.accepted_policy_profiles.iter().map(
        |accepted| {
            (
                accepted.policy_profile.as_str(),
                accepted.environment_config_digest,
            )
        },
    )) || !strictly_sorted_unique(policy.authority.accepted_policy_bundles.iter().map(
        |accepted| {
            (
                accepted.policy_profile.as_str(),
                accepted.policy_bundle_digest,
            )
        },
    )) {
        return Err(InputError::Invalid);
    }
    let root = &policy.authority.initial_root;
    let root_signer = crypto::parse_public_signer(&root.key_id, &root.public_key)
        .map_err(|_| InputError::Invalid)?;
    validate_trusted_key(root)?;
    let mut key_ids = std::collections::BTreeSet::new();
    let mut public_keys = std::collections::BTreeSet::new();
    key_ids.insert(root_signer.key_id);
    public_keys.insert(root_signer.public_key);
    for key in &policy.release.trusted_signers {
        validate_trusted_key(key)?;
        let signer = crypto::parse_public_signer(&key.key_id, &key.public_key)
            .map_err(|_| InputError::Invalid)?;
        if !key_ids.insert(signer.key_id) || !public_keys.insert(signer.public_key) {
            return Err(InputError::Invalid);
        }
    }
    Ok(())
}

fn strictly_sorted_unique<T: Ord>(values: impl Iterator<Item = T>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.as_ref().is_some_and(|previous| previous >= &value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn validate_trusted_key(key: &model::TrustedKey) -> Result<(), InputError> {
    let not_before = semantics::parse_timestamp(&key.not_before).ok_or(InputError::Invalid)?;
    let not_after = match key.not_after.as_deref() {
        Some(value) => Some(semantics::parse_timestamp(value).ok_or(InputError::Invalid)?),
        None => None,
    };
    let revoked = match key.revoked_at.as_deref() {
        Some(value) => Some(semantics::parse_timestamp(value).ok_or(InputError::Invalid)?),
        None => None,
    };
    if key.key_id.len() > 256
        || key.public_key.len() > 128
        || not_after.is_some_and(|value| value <= not_before)
        || revoked.is_some_and(|value| value < not_before)
    {
        return Err(InputError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};

    use super::*;

    fn trusted_key(seed: u8) -> Value {
        let public_key = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        json!({
            "key_id": format!("ed25519:{}", hex(public_key)),
            "not_after": null,
            "not_before": "2026-08-21T00:00:00Z",
            "public_key": BASE64.encode(public_key),
            "revoked_at": null,
        })
    }

    fn valid_trust_value() -> Value {
        json!({
            "api_version": model::TRUST_POLICY_API_VERSION,
            "authority": {
                "accepted_policy_bundles": [{
                    "policy_bundle_digest": model::Digest([0x33; 32]),
                    "policy_profile": "proof.local/authority/direct/v1",
                }],
                "checkpoint_requirement": "required",
                "compromise_cutoff": null,
                "initial_root": trusted_key(1),
            },
            "disclosure": { "requesting_subject_opening": "optional" },
            "limits": model::VerificationLimits::hard(),
            "release": {
                "accepted_policy_profiles": [{
                    "environment_config_digest": model::Digest([0x44; 32]),
                    "policy_profile": "proof.local/release/v1",
                }],
                "accepted_predicate_types": ["https://proof.dev/attestation/release/v2"],
                "trusted_signers": [trusted_key(2)],
            },
            "workspace_id": "019c0000-0000-7000-8000-000000000001",
        })
    }

    fn canonical(value: &Value) -> Vec<u8> {
        strict_json::canonical_bytes(value).unwrap()
    }

    fn hex(bytes: [u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    #[test]
    fn trust_semantics_and_limits_have_distinct_stable_codes() {
        let valid = valid_trust_value();
        assert!(parse_trust_policy(&canonical(&valid)).is_ok());

        let mut invalid = valid.clone();
        invalid["api_version"] = Value::String("proof.dev/wrong/v1".to_owned());
        let invalid_bytes = canonical(&invalid);
        assert!(matches!(
            parse_trust_policy(&invalid_bytes),
            Err(InputError::Invalid)
        ));
        let invalid_report = verify_bundle_directory(VerificationRequest {
            bundle_root: Path::new("not-read-for-invalid-trust"),
            trust_policy_json: &invalid_bytes,
            checkpoint_json: None,
            external_roots: &[],
        });
        assert_eq!(
            invalid_report.history_scope,
            model::HistoryScope::InternalPrefix
        );
        assert_eq!(
            invalid_report.findings[0].code,
            "proof.verify.trust.invalid"
        );
        assert!(invalid_report.verified_claims.workspace_id.is_none());

        let mut limit = valid;
        limit["limits"]["max_authority_records"] =
            Value::from(u64::try_from(model::MAX_AUTHORITY_RECORDS).unwrap() + 1);
        let limit_bytes = canonical(&limit);
        assert!(matches!(
            parse_trust_policy(&limit_bytes),
            Err(InputError::Limit)
        ));
        let limit_report = verify_bundle_directory(VerificationRequest {
            bundle_root: Path::new("not-read-for-limit-trust"),
            trust_policy_json: &limit_bytes,
            checkpoint_json: None,
            external_roots: &[],
        });
        assert_eq!(limit_report.findings[0].code, "proof.verify.trust.limit");
        assert_eq!(
            limit_report.history_scope,
            model::HistoryScope::InternalPrefix
        );
    }

    #[test]
    fn invalid_checkpoint_never_implies_a_pinned_history_scope() {
        let trust = canonical(&valid_trust_value());
        let invalid_checkpoint = canonical(&json!({
            "active_authority_key_id": "",
            "api_version": model::CHECKPOINT_API_VERSION,
            "authority_record_digest": model::Digest([0x55; 32]),
            "authority_sequence": 1,
            "observed_at": "2026-08-21T00:00:00Z",
            "workspace_id": "019c0000-0000-7000-8000-000000000001",
        }));
        let report = verify_bundle_directory(VerificationRequest {
            bundle_root: Path::new("missing-bundle"),
            trust_policy_json: &trust,
            checkpoint_json: Some(&invalid_checkpoint),
            external_roots: &[],
        });
        assert_eq!(report.history_scope, model::HistoryScope::InternalPrefix);
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.code == "proof.verify.checkpoint.invalid")
        );
        assert!(report.verified_claims.workspace_id.is_none());
    }
}
