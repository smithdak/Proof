#![allow(
    clippy::manual_let_else,
    clippy::single_match_else,
    clippy::too_many_lines,
    reason = "the bounded container pass keeps each fail-closed branch next to its stable finding"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read as _},
    path::{Component, Path, PathBuf},
};

use serde_json::Value;

use crate::{
    crypto::domain_digest,
    model::{
        ArtifactKind, ArtifactRef, Availability, BUNDLE_API_VERSION, Bundle, DimensionStatus,
        EvidenceRole, Report, TrustPolicy,
    },
    strict_json::parse_canonical,
};

pub(crate) struct LoadedArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) value: Value,
}

pub(crate) struct LoadedBundle {
    pub(crate) bundle: Bundle,
    pub(crate) manifest_digest: crate::model::Digest,
    pub(crate) artifacts: BTreeMap<ArtifactRef, LoadedArtifact>,
    pub(crate) missing_external: BTreeSet<ArtifactRef>,
    pub(crate) required_external_missing: bool,
}

/// Availability of a declared artifact needed by a later semantic check.
///
/// Keeping an externally withheld dependency distinct from an artifact that
/// failed container validation prevents an `Incomplete` disclosure from being
/// reinterpreted as an `Invalid` semantic contradiction.
pub(crate) enum RequiredArtifact<'a> {
    Available(&'a LoadedArtifact),
    MissingRequiredExternal,
    InvalidOrAbsent,
}

impl LoadedBundle {
    pub(crate) fn required_artifact(&self, reference: &ArtifactRef) -> RequiredArtifact<'_> {
        if let Some(artifact) = self.artifacts.get(reference) {
            RequiredArtifact::Available(artifact)
        } else if self.missing_external.contains(reference) {
            RequiredArtifact::MissingRequiredExternal
        } else {
            RequiredArtifact::InvalidOrAbsent
        }
    }

    pub(crate) fn required_role_artifact(
        &self,
        role: EvidenceRole,
        digest: crate::model::Digest,
    ) -> RequiredArtifact<'_> {
        let mut matches =
            self.bundle.artifacts.iter().filter(|descriptor| {
                descriptor.role == role && descriptor.artifact.digest == digest
            });
        let Some(descriptor) = matches.next() else {
            return RequiredArtifact::InvalidOrAbsent;
        };
        if matches.next().is_some() {
            return RequiredArtifact::InvalidOrAbsent;
        }
        self.required_artifact(&descriptor.artifact)
    }
}

pub(crate) fn load_bundle(
    root: &Path,
    trust: &TrustPolicy,
    external_roots: &[PathBuf],
    report: &mut Report,
) -> Option<LoadedBundle> {
    if external_roots.len() > crate::model::MAX_EXTERNAL_ROOTS {
        invalid(
            report,
            "container",
            "proof.verify.external_roots.limit",
            None,
        );
        return None;
    }
    let manifest_limit = usize::try_from(trust.limits.max_manifest_bytes).ok()?;
    let manifest = match safe_read(root, "bundle.json", manifest_limit) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            incomplete(report, "container", "proof.verify.bundle.missing", None);
            return None;
        }
        Err(ReadFailure::Limit) => {
            invalid(report, "container", "proof.verify.bundle.limit", None);
            return None;
        }
        Err(ReadFailure::Unsafe | ReadFailure::Io) => {
            invalid(report, "container", "proof.verify.bundle.path", None);
            return None;
        }
    };
    let value = match parse_canonical(&manifest, trust.limits.max_json_depth as usize) {
        Ok(value) => value,
        Err(_) => {
            invalid(
                report,
                "canonical",
                "proof.verify.bundle.noncanonical",
                None,
            );
            return None;
        }
    };
    let bundle: Bundle = match serde_json::from_value(value) {
        Ok(bundle) => bundle,
        Err(_) => {
            invalid(report, "container", "proof.verify.bundle.schema", None);
            return None;
        }
    };
    let manifest_digest = domain_digest(ArtifactKind::AuthorityEvidenceBundleV1, &manifest);
    if !validate_manifest(&bundle, trust, report) {
        return None;
    }
    report.valid("container");

    let mut declarations = BTreeMap::<ArtifactRef, Availability>::new();
    let mut included_paths = BTreeSet::new();
    for descriptor in &bundle.artifacts {
        match declarations.get(&descriptor.artifact) {
            Some(existing) if *existing != descriptor.availability => {
                invalid(
                    report,
                    "container",
                    "proof.verify.artifact.availability_conflict",
                    Some(descriptor.artifact.digest),
                );
            }
            Some(_) => {}
            None => {
                declarations.insert(descriptor.artifact, descriptor.availability);
            }
        }
        if matches!(descriptor.availability, Availability::Included { .. }) {
            included_paths.insert(descriptor.artifact.relative_path());
        }
    }
    if report.dimensions["container"] == DimensionStatus::Invalid {
        return None;
    }
    if !inventory_is_exact(root, &included_paths) {
        invalid(report, "container", "proof.verify.bundle.inventory", None);
        return None;
    }

    let mut artifacts = BTreeMap::new();
    let mut missing_external = BTreeSet::new();
    let artifact_limit = usize::try_from(trust.limits.max_artifact_bytes).ok()?;
    let mut actual_total = 0_u64;
    for (artifact, availability) in declarations {
        let path = artifact.relative_path();
        let bytes = match availability {
            Availability::Included { byte_length } => {
                match safe_read(root, &path, artifact_limit) {
                    Ok(Some(bytes)) if bytes.len() as u64 == byte_length => bytes,
                    Ok(Some(_)) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.length",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                    Ok(None) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.missing_included",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                    Err(ReadFailure::Limit) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.limit",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                    Err(ReadFailure::Unsafe | ReadFailure::Io) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.path",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                }
            }
            Availability::ExternalCommitment => {
                match resolve_external(external_roots, &path, artifact_limit) {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => {
                        missing_external.insert(artifact);
                        continue;
                    }
                    Err(ReadFailure::Limit) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.limit",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                    Err(ReadFailure::Unsafe | ReadFailure::Io) => {
                        invalid(
                            report,
                            "artifact_integrity",
                            "proof.verify.artifact.external_conflict",
                            Some(artifact.digest),
                        );
                        continue;
                    }
                }
            }
        };
        actual_total = match actual_total.checked_add(bytes.len() as u64) {
            Some(value) if value <= trust.limits.max_total_bytes => value,
            _ => {
                invalid(
                    report,
                    "artifact_integrity",
                    "proof.verify.total.limit",
                    None,
                );
                break;
            }
        };
        let value = match parse_canonical(&bytes, trust.limits.max_json_depth as usize) {
            Ok(value) => value,
            Err(_) => {
                invalid(
                    report,
                    "canonical",
                    "proof.verify.artifact.noncanonical",
                    Some(artifact.digest),
                );
                continue;
            }
        };
        if domain_digest(artifact.artifact_kind, &bytes) != artifact.digest {
            invalid(
                report,
                "artifact_integrity",
                "proof.verify.artifact.digest",
                Some(artifact.digest),
            );
            continue;
        }
        artifacts.insert(artifact, LoadedArtifact { bytes, value });
    }
    if report.dimensions["canonical"] != DimensionStatus::Invalid {
        report.valid("canonical");
    }
    if report.dimensions["artifact_integrity"] != DimensionStatus::Invalid {
        report.valid("artifact_integrity");
    }
    let mut required_external_missing = false;
    if !missing_external.is_empty() {
        for artifact in &missing_external {
            if missing_external_is_required(
                &bundle.artifacts,
                *artifact,
                trust.disclosure.requesting_subject_opening,
            ) {
                required_external_missing = true;
                incomplete(
                    report,
                    "evidence_completeness",
                    "proof.verify.external.missing",
                    Some(artifact.digest),
                );
            }
        }
    }
    if !required_external_missing {
        report.valid("evidence_completeness");
    }
    Some(LoadedBundle {
        bundle,
        manifest_digest,
        artifacts,
        missing_external,
        required_external_missing,
    })
}

fn missing_external_is_required(
    descriptors: &[crate::model::ArtifactDescriptor],
    artifact: ArtifactRef,
    requirement: crate::model::OpeningRequirement,
) -> bool {
    requirement != crate::model::OpeningRequirement::Optional
        || !descriptors.iter().any(|descriptor| {
            descriptor.artifact == artifact && descriptor.role == EvidenceRole::SubjectOpening
        })
}

fn validate_manifest(bundle: &Bundle, trust: &TrustPolicy, report: &mut Report) -> bool {
    if bundle.api_version != BUNDLE_API_VERSION || bundle.workspace_id != trust.workspace_id {
        invalid(report, "container", "proof.verify.bundle.identity", None);
        return false;
    }
    if bundle.artifacts.is_empty()
        || bundle.artifacts.len() > trust.limits.max_artifacts as usize
        || bundle.authority_prefix.is_empty()
        || bundle.authority_prefix.len() > trust.limits.max_authority_records as usize
        || bundle.included_authority_head.sequence != bundle.authority_prefix.len() as u64
    {
        invalid(report, "container", "proof.verify.bundle.count", None);
        return false;
    }
    for (index, entry) in bundle.authority_prefix.iter().enumerate() {
        if entry.sequence != index as u64 + 1 {
            invalid(
                report,
                "container",
                "proof.verify.authority_prefix.sequence",
                Some(entry.record_digest),
            );
            return false;
        }
    }
    let Some(last) = bundle.authority_prefix.last() else {
        return false;
    };
    if last.record_digest != bundle.included_authority_head.record_digest
        || !bundle.authority_prefix.iter().any(|entry| {
            entry.record_digest == bundle.entrypoints.target_authorization_record_digest
                && entry.decision_companion.is_some()
        })
    {
        invalid(report, "container", "proof.verify.bundle.entrypoint", None);
        return false;
    }
    let mut descriptor_keys = BTreeSet::new();
    let mut prior = None;
    let mut total = 0_u64;
    for descriptor in &bundle.artifacts {
        let key = (
            descriptor.role.wire_name(),
            descriptor.artifact.artifact_kind.wire_name(),
            descriptor.artifact.digest,
        );
        if prior.is_some_and(|previous| previous >= key)
            || !descriptor_keys.insert((descriptor.role, descriptor.artifact))
            || !role_accepts_kind(descriptor.role, descriptor.artifact.artifact_kind)
        {
            invalid(report, "container", "proof.verify.bundle.descriptor", None);
            return false;
        }
        prior = Some(key);
        if let Availability::Included { byte_length } = descriptor.availability {
            if byte_length == 0 || byte_length > trust.limits.max_artifact_bytes {
                invalid(report, "container", "proof.verify.artifact.limit", None);
                return false;
            }
            total = match total.checked_add(byte_length) {
                Some(value) => value,
                None => {
                    invalid(report, "container", "proof.verify.total.limit", None);
                    return false;
                }
            };
        }
    }
    if total > trust.limits.max_total_bytes
        || !has_descriptor(
            bundle,
            EvidenceRole::ReleaseManifest,
            bundle.entrypoints.target_release_manifest,
        )
        || !has_descriptor(
            bundle,
            EvidenceRole::ReleaseProofEnvelope,
            bundle.entrypoints.target_release_proof_envelope,
        )
        || !has_descriptor(
            bundle,
            EvidenceRole::LocalizedConsequence,
            bundle.entrypoints.target_localized_consequence,
        )
        || bundle.authority_prefix.iter().any(|entry| {
            !has_descriptor(
                bundle,
                EvidenceRole::AuthorityRecordEnvelope,
                entry.authority_envelope,
            ) || entry.decision_companion.is_some_and(|companion| {
                !has_descriptor(bundle, EvidenceRole::CommandInput, companion.command_input)
                    || !has_descriptor(
                        bundle,
                        EvidenceRole::AuthenticatedCommandEnvelope,
                        companion.authenticated_command_envelope,
                    )
                    || !has_descriptor(
                        bundle,
                        EvidenceRole::ActorContextEvidence,
                        companion.actor_context_evidence,
                    )
            })
        })
    {
        invalid(report, "container", "proof.verify.bundle.closure", None);
        return false;
    }
    true
}

fn has_descriptor(bundle: &Bundle, role: EvidenceRole, artifact: ArtifactRef) -> bool {
    bundle
        .artifacts
        .iter()
        .any(|descriptor| descriptor.role == role && descriptor.artifact == artifact)
}

#[allow(clippy::match_same_arms)]
const fn role_accepts_kind(role: EvidenceRole, kind: ArtifactKind) -> bool {
    match role {
        EvidenceRole::ReleaseManifest => {
            matches!(kind, ArtifactKind::ReleaseV1 | ArtifactKind::ReleaseV2)
        }
        EvidenceRole::ReleaseProofEnvelope => matches!(kind, ArtifactKind::ProofEnvelopeV1),
        EvidenceRole::ReleasePolicyDecision => {
            matches!(kind, ArtifactKind::AuthorizationDecisionV1)
        }
        EvidenceRole::ReleaseSigningKey => matches!(kind, ArtifactKind::ReleaseSigningKeyV1),
        EvidenceRole::ReleaseSigningKeyRevocation => {
            matches!(kind, ArtifactKind::ReleaseSigningKeyRevocationV1)
        }
        EvidenceRole::EnvironmentConfig => matches!(kind, ArtifactKind::EnvironmentConfigV1),
        EvidenceRole::EnvironmentPolicyBundle => matches!(kind, ArtifactKind::PolicyBundleV1),
        EvidenceRole::Edition => matches!(kind, ArtifactKind::EditionV1 | ArtifactKind::EditionV2),
        EvidenceRole::KnownState => matches!(
            kind,
            ArtifactKind::KnownStateV1 | ArtifactKind::KnownStateV2
        ),
        EvidenceRole::EditionDelta => matches!(kind, ArtifactKind::ReleaseV2),
        EvidenceRole::ChangeSet => {
            matches!(kind, ArtifactKind::ChangeSetV1 | ArtifactKind::ChangeSetV2)
        }
        EvidenceRole::Edit => matches!(
            kind,
            ArtifactKind::EditBatchV1
                | ArtifactKind::EditBatchV2
                | ArtifactKind::EditV2
                | ArtifactKind::ObjectCreateEditV2
        ),
        EvidenceRole::ValidationAttempt => matches!(
            kind,
            ArtifactKind::ValidationResultsV1 | ArtifactKind::ValidationResultsV2
        ),
        EvidenceRole::Submission | EvidenceRole::Approval | EvidenceRole::LocalizedResult => {
            matches!(kind, ArtifactKind::OperationEffectV1)
        }
        EvidenceRole::ApplicationEffect => matches!(
            kind,
            ArtifactKind::OperationEffectV1
                | ArtifactKind::ValidationResultsV2
                | ArtifactKind::ReleaseV2
        ),
        EvidenceRole::ContextPack => matches!(
            kind,
            ArtifactKind::ContextPackV1 | ArtifactKind::ContextPackV2
        ),
        EvidenceRole::ContextPolicyBundle => matches!(kind, ArtifactKind::PolicyBundleV1),
        EvidenceRole::ResourceIntent => matches!(kind, ArtifactKind::ContentResourceIntentV1),
        EvidenceRole::Object => matches!(kind, ArtifactKind::ObjectRevisionV1),
        EvidenceRole::Schema => matches!(kind, ArtifactKind::SchemaVersionV1),
        EvidenceRole::LocaleRevision => matches!(kind, ArtifactKind::ObjectLocaleRevisionV1),
        EvidenceRole::AuthorityRecordEnvelope => {
            matches!(kind, ArtifactKind::AuthorityRecordEnvelopeV1)
        }
        EvidenceRole::AuthenticatedCommandEnvelope => {
            matches!(kind, ArtifactKind::AuthenticatedCommandEnvelopeV1)
        }
        EvidenceRole::CommandInput => matches!(kind, ArtifactKind::CommandV1),
        EvidenceRole::ActorContextEvidence => {
            matches!(kind, ArtifactKind::AuthenticatedActorContextV1)
        }
        EvidenceRole::LocalizedConsequence => {
            matches!(kind, ArtifactKind::AuthenticatedLocalizedConsequenceV1)
        }
        EvidenceRole::SubjectOpening => matches!(kind, ArtifactKind::AuthenticatedSubjectOpeningV1),
    }
}

fn resolve_external(
    roots: &[PathBuf],
    relative: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, ReadFailure> {
    let mut selected: Option<Vec<u8>> = None;
    for root in roots {
        if let Some(bytes) = safe_read(root, relative, limit)? {
            if selected.as_ref().is_some_and(|existing| *existing != bytes) {
                return Err(ReadFailure::Unsafe);
            }
            selected = Some(bytes);
        }
    }
    Ok(selected)
}

fn inventory_is_exact(root: &Path, included: &BTreeSet<String>) -> bool {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return false;
    };
    if !safe_directory(&metadata) {
        return false;
    }
    let mut pending = vec![(root.to_path_buf(), String::new(), 0_usize)];
    let mut actual = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    let mut allowed_directories = BTreeSet::new();
    for path in included {
        let mut prefix = String::new();
        let components = path.split('/').collect::<Vec<_>>();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            allowed_directories.insert(prefix.clone());
        }
    }
    let mut entries = 0_usize;
    while let Some((directory, prefix, depth)) = pending.pop() {
        if depth > 8 {
            return false;
        }
        let Ok(children) = fs::read_dir(&directory) else {
            return false;
        };
        for child in children {
            let Ok(child) = child else {
                return false;
            };
            entries += 1;
            if entries > included.len().saturating_mul(6).saturating_add(16) {
                return false;
            }
            let Some(name) = child.file_name().to_str().map(str::to_owned) else {
                return false;
            };
            if name == "." || name == ".." || name.contains(['/', '\\']) {
                return false;
            }
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(metadata) = fs::symlink_metadata(child.path()) else {
                return false;
            };
            if safe_directory(&metadata) {
                actual_directories.insert(relative.clone());
                pending.push((child.path(), relative, depth + 1));
            } else if safe_file(&metadata) {
                actual.insert(relative);
            } else {
                return false;
            }
        }
    }
    let mut expected = included.clone();
    expected.insert("bundle.json".to_owned());
    actual == expected && actual_directories == allowed_directories
}

#[derive(Clone, Copy)]
enum ReadFailure {
    Limit,
    Unsafe,
    Io,
}

fn safe_read(root: &Path, relative: &str, limit: usize) -> Result<Option<Vec<u8>>, ReadFailure> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ReadFailure::Unsafe);
    }
    let root_metadata = match fs::symlink_metadata(root) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(ReadFailure::Io),
    };
    if !safe_directory(&root_metadata) {
        return Err(ReadFailure::Unsafe);
    }
    let mut current = root.to_path_buf();
    let components = relative_path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(ReadFailure::Unsafe);
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ReadFailure::Io),
        };
        let last = index + 1 == components.len();
        if (last && !safe_file(&metadata)) || (!last && !safe_directory(&metadata)) {
            return Err(ReadFailure::Unsafe);
        }
        if last {
            if metadata.len() > limit as u64 {
                return Err(ReadFailure::Limit);
            }
            let file = fs::File::open(&current).map_err(|_| ReadFailure::Io)?;
            let mut bytes = Vec::new();
            file.take(limit as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ReadFailure::Io)?;
            if bytes.len() > limit {
                return Err(ReadFailure::Limit);
            }
            return Ok(Some(bytes));
        }
    }
    Err(ReadFailure::Unsafe)
}

fn safe_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink() && !is_reparse(metadata)
}

fn safe_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse(metadata)
}

#[cfg(windows)]
fn is_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
const fn is_reparse(_: &fs::Metadata) -> bool {
    false
}

fn invalid(report: &mut Report, dimension: &str, code: &str, digest: Option<crate::model::Digest>) {
    report.finding(dimension, DimensionStatus::Invalid, code, digest, None);
}

fn incomplete(
    report: &mut Report,
    dimension: &str,
    code: &str,
    digest: Option<crate::model::Digest>,
) {
    report.finding(dimension, DimensionStatus::Incomplete, code, digest, None);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "proof-verifier-container-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn inventory_rejects_an_undeclared_empty_directory() {
        let directory = TestDirectory::new();
        fs::write(directory.0.join("bundle.json"), b"{}").unwrap();
        assert!(inventory_is_exact(&directory.0, &BTreeSet::new()));
        fs::create_dir(directory.0.join("undeclared")).unwrap();
        assert!(!inventory_is_exact(&directory.0, &BTreeSet::new()));
    }

    #[test]
    fn subject_opening_and_application_effect_kinds_are_closed() {
        assert!(role_accepts_kind(
            EvidenceRole::SubjectOpening,
            ArtifactKind::AuthenticatedSubjectOpeningV1
        ));
        assert!(!role_accepts_kind(
            EvidenceRole::SubjectOpening,
            ArtifactKind::AuthenticatedSubjectCommitmentV1
        ));
        for kind in [
            ArtifactKind::OperationEffectV1,
            ArtifactKind::ValidationResultsV2,
            ArtifactKind::ReleaseV2,
        ] {
            assert!(role_accepts_kind(EvidenceRole::ApplicationEffect, kind));
        }
        assert!(!role_accepts_kind(
            EvidenceRole::ApplicationEffect,
            ArtifactKind::ReleaseV1
        ));
    }

    #[test]
    fn optional_withheld_opening_is_not_required_but_required_is_incomplete() {
        let artifact = ArtifactRef {
            artifact_kind: ArtifactKind::AuthenticatedSubjectOpeningV1,
            digest: crate::model::Digest([0x55; 32]),
        };
        let descriptors = [crate::model::ArtifactDescriptor {
            role: EvidenceRole::SubjectOpening,
            artifact,
            availability: crate::model::Availability::ExternalCommitment,
        }];
        assert!(!missing_external_is_required(
            &descriptors,
            artifact,
            crate::model::OpeningRequirement::Optional
        ));
        assert!(missing_external_is_required(
            &descriptors,
            artifact,
            crate::model::OpeningRequirement::Required
        ));
    }
}
