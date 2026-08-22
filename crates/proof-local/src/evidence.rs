//! Content-addressed P-0006 evidence extraction for the local `SQLite` adapter.

use std::collections::{BTreeMap, BTreeSet};

use proof_application::{
    ArtifactKind, ContentDigest, ReleaseId, WorkspaceId,
    authority::{AuthorityHeadV1, AuthorityRecordV1, AuthoritySequence},
    evidence::{
        AuthorityEvidenceBundleEntrypointsV1, AuthorityEvidenceBundleExportV1,
        AuthorityEvidenceBundleV1, AuthorityEvidenceExportError, AuthorityEvidenceExportRepository,
        AuthorityPrefixEntryV1, CanonicalEvidenceArtifactV1, DecisionCompanionV1,
        EvidenceArtifactDescriptorV1, EvidenceArtifactRefV1, EvidenceAvailabilityV1,
        EvidenceRoleV1, ExportAuthorityEvidenceBundleV1Command, SubjectOpeningDisclosureV1,
    },
};
use proof_canonical::{canonicalize, digest, parse_strict};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior};
use serde_json::{Value, json};

use super::{LocalWorkspace, authority, ensure_latest_schema};

type ExportResult<T> = Result<T, AuthorityEvidenceExportError>;

#[derive(Default)]
struct ArtifactCollector {
    descriptors: BTreeMap<(&'static str, &'static str, String), EvidenceArtifactDescriptorV1>,
    materialized: BTreeMap<(&'static str, String), CanonicalEvidenceArtifactV1>,
    references_by_digest: BTreeMap<String, EvidenceArtifactRefV1>,
}

impl ArtifactCollector {
    fn include(
        &mut self,
        role: EvidenceRoleV1,
        artifact_kind: ArtifactKind,
        canonical_json: String,
        expected_digest: Option<ContentDigest>,
    ) -> ExportResult<EvidenceArtifactRefV1> {
        let value = parse_strict(canonical_json.as_bytes()).map_err(|error| {
            invalid(format!(
                "invalid {} JSON: {error}",
                artifact_kind.wire_name()
            ))
        })?;
        let canonical = canonicalize(&value).map_err(|error| invalid(error.to_string()))?;
        if canonical.as_str() != canonical_json {
            return Err(invalid(format!(
                "{} bytes are not canonical JSON",
                artifact_kind.wire_name()
            )));
        }
        let actual_digest = digest(artifact_kind, &canonical);
        if expected_digest.is_some_and(|expected| expected != actual_digest) {
            return Err(invalid(format!(
                "{} bytes disagree with their stored digest",
                artifact_kind.wire_name()
            )));
        }
        let artifact = EvidenceArtifactRefV1 {
            artifact_kind,
            digest: actual_digest,
        };
        let byte_length = u64::try_from(canonical_json.len())
            .map_err(|_| AuthorityEvidenceExportError::LimitExceeded)?;
        let descriptor = EvidenceArtifactDescriptorV1 {
            role,
            artifact,
            availability: EvidenceAvailabilityV1::Included { byte_length },
        };
        let key = (
            role.wire_name(),
            artifact_kind.wire_name(),
            actual_digest.to_string(),
        );
        self.descriptors.insert(key.clone(), descriptor);
        self.materialized.insert(
            (artifact_kind.wire_name(), actual_digest.to_string()),
            CanonicalEvidenceArtifactV1 {
                artifact,
                canonical_json,
            },
        );
        self.references_by_digest
            .entry(actual_digest.to_string())
            .or_insert(artifact);
        Ok(artifact)
    }

    fn include_expected(
        &mut self,
        role: EvidenceRoleV1,
        artifact_kind: ArtifactKind,
        canonical_json: String,
        expected_digest: &str,
    ) -> ExportResult<EvidenceArtifactRefV1> {
        let expected = parse_digest(expected_digest)?;
        self.include(role, artifact_kind, canonical_json, Some(expected))
    }

    fn external(
        &mut self,
        role: EvidenceRoleV1,
        artifact_kind: ArtifactKind,
        digest: ContentDigest,
    ) -> EvidenceArtifactRefV1 {
        let artifact = EvidenceArtifactRefV1 {
            artifact_kind,
            digest,
        };
        let key = (
            role.wire_name(),
            artifact_kind.wire_name(),
            digest.to_string(),
        );
        self.descriptors.insert(
            key,
            EvidenceArtifactDescriptorV1 {
                role,
                artifact,
                availability: EvidenceAvailabilityV1::ExternalCommitment,
            },
        );
        artifact
    }

    fn reference_for_digest(&self, raw_digest: &str) -> Option<EvidenceArtifactRefV1> {
        self.references_by_digest.get(raw_digest).copied()
    }

    fn alias_for_digest(
        &mut self,
        role: EvidenceRoleV1,
        raw_digest: &str,
    ) -> ExportResult<Option<EvidenceArtifactRefV1>> {
        let Some(reference) = self.reference_for_digest(raw_digest) else {
            return Ok(None);
        };
        let key = (
            reference.artifact_kind.wire_name(),
            reference.digest.to_string(),
        );
        let canonical_json = self
            .materialized
            .get(&key)
            .ok_or_else(|| invalid("included artifact reference has no canonical bytes"))?
            .canonical_json
            .clone();
        self.include(
            role,
            reference.artifact_kind,
            canonical_json,
            Some(reference.digest),
        )
        .map(Some)
    }

    fn finish(
        self,
    ) -> (
        Vec<EvidenceArtifactDescriptorV1>,
        Vec<CanonicalEvidenceArtifactV1>,
    ) {
        (
            self.descriptors.into_values().collect(),
            self.materialized.into_values().collect(),
        )
    }
}

#[derive(Clone)]
struct ReleaseClosureEntry {
    release_id: String,
    api_version: String,
    previous_release_id: Option<String>,
    rollback_target_release_id: Option<String>,
    edition_id: String,
    manifest_ref: EvidenceArtifactRefV1,
    proof_ref: EvidenceArtifactRefV1,
}

struct ReleaseClosure {
    entries: BTreeMap<String, ReleaseClosureEntry>,
    target_manifest: EvidenceArtifactRefV1,
    target_proof: EvidenceArtifactRefV1,
}

impl AuthorityEvidenceExportRepository for LocalWorkspace {
    #[expect(
        clippy::too_many_lines,
        reason = "export authentication, migration, integrity, closure, and manifest assembly remain visibly ordered"
    )]
    fn export_authority_evidence_bundle(
        &self,
        command: ExportAuthorityEvidenceBundleV1Command,
    ) -> ExportResult<AuthorityEvidenceBundleExportV1> {
        let config = self
            .read_config()
            .map_err(|error| AuthorityEvidenceExportError::Storage(error.to_string()))?;
        let configured_workspace_id = config
            .workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| invalid(error.to_string()))?;
        let local_identity = self
            .resolved_local_identity()
            .map_err(|_| AuthorityEvidenceExportError::AccessDenied)?;
        let mut connection = self
            .open_database()
            .map_err(|error| AuthorityEvidenceExportError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let (raw_workspace_id, bootstrap_principal_id, schema_version): (String, String, u32) =
            transaction
                .query_row(
                    "SELECT workspace_id, bootstrap_principal_id, schema_version
                 FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(storage)?;
        let workspace_id = raw_workspace_id
            .parse::<WorkspaceId>()
            .map_err(|error| invalid(error.to_string()))?;
        if workspace_id != configured_workspace_id {
            return Err(invalid(
                "configuration and database Workspace identities differ",
            ));
        }
        super::authenticated_principal(&transaction, &bootstrap_principal_id, &local_identity)
            .map_err(|_| AuthorityEvidenceExportError::AccessDenied)?;
        ensure_latest_schema(&transaction, schema_version).map_err(|error| match error {
            super::LatestSchemaError::Integrity(detail) => invalid(detail),
            super::LatestSchemaError::Storage(detail) => {
                AuthorityEvidenceExportError::Storage(detail)
            }
        })?;
        authority::verify_authority_log(&transaction, workspace_id)
            .map_err(|error| invalid(error.to_string()))?;

        let mut collector = ArtifactCollector::default();
        let release_closure = collect_release_closure(
            &transaction,
            workspace_id,
            command.release_id,
            &mut collector,
        )?;
        collect_content_closure(&transaction, workspace_id, &release_closure, &mut collector)?;
        let target_sequence =
            target_authority_sequence(&transaction, workspace_id, command.release_id)?;
        let (included_head_sequence, included_head_digest): (i64, String) = transaction
            .query_row(
                "SELECT authority_sequence, record_digest FROM authority_records
                 WHERE workspace_id = ?1 ORDER BY authority_sequence DESC LIMIT 1",
                [workspace_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        let included_head_sequence = u64::try_from(included_head_sequence)
            .map_err(|_| invalid("authority head sequence is out of range"))?;
        let (authority_prefix, target_record_digest, target_consequence) =
            collect_authority_prefix(
                &transaction,
                workspace_id,
                included_head_sequence,
                target_sequence,
                &mut collector,
            )?;
        collect_subject_opening(
            &transaction,
            workspace_id,
            target_sequence,
            command.subject_opening,
            &mut collector,
        )?;

        let included_authority_head = AuthorityHeadV1 {
            sequence: AuthoritySequence::new(included_head_sequence)
                .map_err(|error| invalid(error.to_string()))?,
            record_digest: parse_digest(&included_head_digest)?,
        };
        let entrypoints = AuthorityEvidenceBundleEntrypointsV1 {
            target_release_manifest: release_closure.target_manifest,
            target_release_proof_envelope: release_closure.target_proof,
            target_authorization_record_digest: target_record_digest,
            target_localized_consequence: target_consequence,
        };
        let (descriptors, artifacts) = collector.finish();
        let bundle = AuthorityEvidenceBundleV1::new(
            workspace_id,
            entrypoints,
            included_authority_head,
            authority_prefix,
            descriptors,
        );
        let (canonical_manifest_json, manifest_digest) = bundle.canonical_manifest()?;
        transaction.commit().map_err(storage)?;
        Ok(AuthorityEvidenceBundleExportV1 {
            bundle,
            canonical_manifest_json,
            manifest_digest,
            artifacts,
        })
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "rusqlite Result::map_err supplies an owned error"
)]
fn storage(error: rusqlite::Error) -> AuthorityEvidenceExportError {
    AuthorityEvidenceExportError::Storage(error.to_string())
}

fn invalid(detail: impl Into<String>) -> AuthorityEvidenceExportError {
    AuthorityEvidenceExportError::InvalidBundle(detail.into())
}

fn incomplete(detail: impl Into<String>) -> AuthorityEvidenceExportError {
    AuthorityEvidenceExportError::Incomplete(detail.into())
}

fn parse_digest(raw: &str) -> ExportResult<ContentDigest> {
    raw.parse::<ContentDigest>()
        .map_err(|error| invalid(error.to_string()))
}

#[derive(Debug)]
struct StoredRelease {
    release_id: String,
    api_version: String,
    previous_release_id: Option<String>,
    rollback_target_release_id: Option<String>,
    edition_id: String,
    environment_id: String,
    environment_config_version: i64,
    policy_decision_digest: String,
    manifest_json: String,
    release_digest: String,
}

fn load_stored_release(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: &str,
) -> ExportResult<Option<StoredRelease>> {
    connection
        .query_row(
            "SELECT release_id, api_version, previous_release_id,
                    rollback_target_release_id, edition_id, environment_id,
                    environment_config_version, policy_decision_digest,
                    manifest_json, release_digest
             FROM releases WHERE workspace_id = ?1 AND release_id = ?2",
            (workspace_id.to_string(), release_id),
            |row| {
                Ok(StoredRelease {
                    release_id: row.get(0)?,
                    api_version: row.get(1)?,
                    previous_release_id: row.get(2)?,
                    rollback_target_release_id: row.get(3)?,
                    edition_id: row.get(4)?,
                    environment_id: row.get(5)?,
                    environment_config_version: row.get(6)?,
                    policy_decision_digest: row.get(7)?,
                    manifest_json: row.get(8)?,
                    release_digest: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(storage)
}

fn release_kind(api_version: &str) -> ExportResult<ArtifactKind> {
    match api_version {
        "proof.dev/release/v1" => Ok(ArtifactKind::ReleaseV1),
        "proof.dev/release/v2" => Ok(ArtifactKind::ReleaseV2),
        _ => Err(invalid(format!(
            "Release has unsupported API version {api_version}"
        ))),
    }
}

fn edition_kind(api_version: &str) -> ExportResult<ArtifactKind> {
    match api_version {
        "proof.dev/edition/v1" => Ok(ArtifactKind::EditionV1),
        "proof.dev/edition/v2" => Ok(ArtifactKind::EditionV2),
        _ => Err(invalid(format!(
            "Edition has unsupported API version {api_version}"
        ))),
    }
}

fn known_state_kind(api_version: &str) -> ExportResult<ArtifactKind> {
    match api_version {
        "proof.dev/known-state/v1" => Ok(ArtifactKind::KnownStateV1),
        "proof.dev/known-state/v2" => Ok(ArtifactKind::KnownStateV2),
        _ => Err(invalid(format!(
            "Known State has unsupported API version {api_version}"
        ))),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "Release prefix, predecessor, rollback, Proof, policy, key, and delta closure are one fail-closed traversal"
)]
fn collect_release_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    target_release_id: ReleaseId,
    collector: &mut ArtifactCollector,
) -> ExportResult<ReleaseClosure> {
    let target_id = target_release_id.to_string();
    let target_exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM releases
             WHERE workspace_id = ?1 AND release_id = ?2)",
            (workspace_id.to_string(), target_id.as_str()),
            |row| row.get(0),
        )
        .map_err(storage)?;
    if !target_exists {
        return Err(AuthorityEvidenceExportError::NotFound);
    }
    let mut pending = vec![target_id.clone()];
    let mut entries = BTreeMap::new();
    while let Some(release_id) = pending.pop() {
        if entries.contains_key(&release_id) {
            continue;
        }
        let release =
            load_stored_release(connection, workspace_id, &release_id)?.ok_or_else(|| {
                if release_id == target_id {
                    AuthorityEvidenceExportError::NotFound
                } else {
                    incomplete(format!("Release predecessor {release_id} is absent"))
                }
            })?;
        let manifest_ref = collector.include_expected(
            EvidenceRoleV1::ReleaseManifest,
            release_kind(&release.api_version)?,
            release.manifest_json.clone(),
            &release.release_digest,
        )?;
        let (proof_envelope, proof_digest, key_id): (String, String, String) = connection
            .query_row(
                "SELECT envelope_json, proof_digest, key_id
                 FROM release_proofs WHERE release_id = ?1",
                [release.release_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| incomplete(format!("Release {} lacks its Proof", release.release_id)))?;
        let proof_ref = collector.include_expected(
            EvidenceRoleV1::ReleaseProofEnvelope,
            ArtifactKind::ProofEnvelopeV1,
            proof_envelope,
            &proof_digest,
        )?;
        collect_release_policy_and_environment(connection, &release, collector)?;
        collect_release_signing_key(connection, workspace_id, &key_id, collector)?;
        if release.api_version == "proof.dev/release/v2" {
            let (delta_json, delta_digest): (String, String) = connection
                .query_row(
                    "SELECT exact_delta_json, exact_delta_digest
                     FROM localized_release_metadata WHERE release_id = ?1",
                    [release.release_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| {
                    incomplete(format!(
                        "v2 Release {} lacks localized metadata",
                        release.release_id
                    ))
                })?;
            collector.include_expected(
                EvidenceRoleV1::EditionDelta,
                ArtifactKind::ReleaseV2,
                delta_json,
                &delta_digest,
            )?;
        }
        if let Some(previous) = &release.previous_release_id {
            pending.push(previous.clone());
        }
        if let Some(rollback) = &release.rollback_target_release_id {
            pending.push(rollback.clone());
        }
        entries.insert(
            release.release_id.clone(),
            ReleaseClosureEntry {
                release_id: release.release_id,
                api_version: release.api_version,
                previous_release_id: release.previous_release_id,
                rollback_target_release_id: release.rollback_target_release_id,
                edition_id: release.edition_id,
                manifest_ref,
                proof_ref,
            },
        );
    }

    for entry in entries.values() {
        let Some(rollback_target) = entry.rollback_target_release_id.as_deref() else {
            continue;
        };
        let mut cursor = entry.previous_release_id.as_deref();
        let mut found = false;
        let mut visited = BTreeSet::new();
        while let Some(release_id) = cursor {
            if !visited.insert(release_id.to_owned()) {
                return Err(invalid("Release predecessor chain contains a cycle"));
            }
            if release_id == rollback_target {
                found = true;
                break;
            }
            cursor = entries
                .get(release_id)
                .ok_or_else(|| incomplete("Release predecessor closure is incomplete"))?
                .previous_release_id
                .as_deref();
        }
        if !found {
            return Err(invalid(format!(
                "rollback target {rollback_target} is not on Release {} predecessor chain",
                entry.release_id
            )));
        }
    }

    let target = entries
        .get(&target_id)
        .ok_or(AuthorityEvidenceExportError::NotFound)?;
    Ok(ReleaseClosure {
        target_manifest: target.manifest_ref,
        target_proof: target.proof_ref,
        entries,
    })
}

fn collect_release_policy_and_environment(
    connection: &Connection,
    release: &StoredRelease,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let decision_json: String = connection
        .query_row(
            "SELECT decision_json FROM release_policy_decisions
             WHERE decision_digest = ?1 AND environment_id = ?2
                   AND environment_config_version = ?3",
            (
                release.policy_decision_digest.as_str(),
                release.environment_id.as_str(),
                release.environment_config_version,
            ),
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete("Release policy decision is absent"))?;
    collector.include_expected(
        EvidenceRoleV1::ReleasePolicyDecision,
        ArtifactKind::AuthorizationDecisionV1,
        decision_json,
        &release.policy_decision_digest,
    )?;
    let (manifest_json, config_digest, policy_json, policy_digest): (
        String,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT manifest_json, config_digest, policy_json, policy_digest
                 FROM environment_versions
                 WHERE environment_id = ?1 AND config_version = ?2",
            (
                release.environment_id.as_str(),
                release.environment_config_version,
            ),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete("Release Environment version is absent"))?;
    collector.include_expected(
        EvidenceRoleV1::EnvironmentConfig,
        ArtifactKind::EnvironmentConfigV1,
        manifest_json,
        &config_digest,
    )?;
    collector.include_expected(
        EvidenceRoleV1::EnvironmentPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        policy_json,
        &policy_digest,
    )?;
    Ok(())
}

fn collect_release_signing_key(
    connection: &Connection,
    workspace_id: WorkspaceId,
    key_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let (algorithm, public_key, trust_profile, not_before, metadata_json, metadata_digest): (
        String,
        String,
        String,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT algorithm, public_key, trust_profile, not_before,
                    metadata_json, metadata_digest
             FROM signing_keys WHERE key_id = ?1",
            [key_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete(format!("Release signing key {key_id} is absent")))?;
    let metadata =
        parse_strict(metadata_json.as_bytes()).map_err(|error| invalid(error.to_string()))?;
    let portable = portable_release_signing_key(
        workspace_id,
        key_id,
        &algorithm,
        &public_key,
        &trust_profile,
        &not_before,
        &metadata,
        &metadata_digest,
    )?;
    collector.include(
        EvidenceRoleV1::ReleaseSigningKey,
        ArtifactKind::ReleaseSigningKeyV1,
        portable.as_str().to_owned(),
        None,
    )?;

    let revocation: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT revoked_at, reason, revocation_json, revocation_digest
             FROM signing_key_revocations WHERE key_id = ?1",
            [key_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((revoked_at, reason, revocation_json, revocation_digest)) = revocation {
        let native =
            parse_strict(revocation_json.as_bytes()).map_err(|error| invalid(error.to_string()))?;
        let portable = portable_release_signing_key_revocation(
            workspace_id,
            key_id,
            &revoked_at,
            &reason,
            &native,
            &revocation_digest,
        )?;
        collector.include(
            EvidenceRoleV1::ReleaseSigningKeyRevocation,
            ArtifactKind::ReleaseSigningKeyRevocationV1,
            portable.as_str().to_owned(),
            None,
        )?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the portable wrapper makes every native public-key field explicit"
)]
fn portable_release_signing_key(
    workspace_id: WorkspaceId,
    key_id: &str,
    algorithm: &str,
    public_key: &str,
    trust_profile: &str,
    not_before: &str,
    metadata: &Value,
    metadata_digest: &str,
) -> ExportResult<proof_canonical::CanonicalJson> {
    canonicalize(&json!({
        "algorithm": algorithm,
        "api_version": "proof.dev/release-signing-key/v1",
        "key_id": key_id,
        "metadata": metadata,
        "native_metadata_digest": metadata_digest,
        "not_before": not_before,
        "public_key": public_key,
        "trust_profile": trust_profile,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| invalid(error.to_string()))
}

fn portable_release_signing_key_revocation(
    workspace_id: WorkspaceId,
    key_id: &str,
    revoked_at: &str,
    reason: &str,
    native: &Value,
    native_digest: &str,
) -> ExportResult<proof_canonical::CanonicalJson> {
    canonicalize(&json!({
        "api_version": "proof.dev/release-signing-key-revocation/v1",
        "key_id": key_id,
        "native_revocation": native,
        "native_revocation_digest": native_digest,
        "reason": reason,
        "revoked_at": revoked_at,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| invalid(error.to_string()))
}

fn collect_content_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    releases: &ReleaseClosure,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let pending_editions = releases
        .entries
        .values()
        .map(|entry| entry.edition_id.clone())
        .collect::<Vec<_>>();
    let pending_states = collect_v1_release_origin_states(connection, releases)?;
    collect_edition_content_closure(
        connection,
        workspace_id,
        pending_editions,
        pending_states,
        collector,
    )
}

fn collect_v1_release_origin_states(
    connection: &Connection,
    releases: &ReleaseClosure,
) -> ExportResult<Vec<(String, i64, String)>> {
    let mut states = BTreeSet::new();
    for entry in releases
        .entries
        .values()
        .filter(|entry| entry.api_version == "proof.dev/release/v1")
    {
        let (statement_json, envelope_json): (String, String) = connection
            .query_row(
                "SELECT statement_json, envelope_json FROM release_proofs WHERE release_id = ?1",
                [entry.release_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| incomplete(format!("Release {} lacks its Proof", entry.release_id)))?;
        let parsed = proof_attestation::parse_release_envelope(envelope_json.as_bytes()).map_err(
            |error| {
                invalid(format!(
                    "Release {} Proof is invalid: {error}",
                    entry.release_id
                ))
            },
        )?;
        if parsed.payload_json != statement_json
            || parsed.statement.predicate_type != proof_attestation::RELEASE_PREDICATE_TYPE
        {
            return Err(invalid(format!(
                "Release {} stored Statement differs from its signed v1 Proof",
                entry.release_id
            )));
        }
        for field in ["base_state", "edition_state"] {
            let state_digest = parsed
                .statement
                .predicate
                .pointer(&format!("/origin/{field}"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    invalid(format!(
                        "Release {} v1 Proof has no origin {field}",
                        entry.release_id
                    ))
                })?;
            parse_digest(state_digest)?;
            let sequence = connection
                .query_row(
                    "SELECT authoritative_sequence FROM known_state_artifacts
                     WHERE api_version = 'proof.dev/known-state/v1' AND state_digest = ?1",
                    [state_digest],
                    |row| row.get::<_, i64>(0),
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| {
                    incomplete(format!(
                        "Release {} v1 Proof origin {field} Known State is absent",
                        entry.release_id
                    ))
                })?;
            states.insert((
                "proof.dev/known-state/v1".to_owned(),
                sequence,
                state_digest.to_owned(),
            ));
        }
    }
    Ok(states.into_iter().collect())
}

#[expect(
    clippy::too_many_lines,
    reason = "Edition, Known State, fact, and ChangeSet recursion share one visited-set traversal"
)]
fn collect_edition_content_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    mut pending_editions: Vec<String>,
    mut pending_states: Vec<(String, i64, String)>,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let mut visited_editions = BTreeSet::new();
    let mut localized_changesets = BTreeSet::new();

    while let Some(edition_id) = pending_editions.pop() {
        if !visited_editions.insert(edition_id.clone()) {
            continue;
        }
        let (api_version, sequence, state_digest, manifest_json, edition_digest): (
            String,
            i64,
            String,
            String,
            String,
        ) = connection
            .query_row(
                "SELECT api_version, authoritative_sequence, state_digest,
                        manifest_json, edition_digest
                 FROM editions WHERE workspace_id = ?1 AND edition_id = ?2",
                (workspace_id.to_string(), edition_id.as_str()),
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| incomplete(format!("Edition {edition_id} is absent")))?;
        collector.include_expected(
            EvidenceRoleV1::Edition,
            edition_kind(&api_version)?,
            manifest_json.clone(),
            &edition_digest,
        )?;
        let state_api_version = if api_version == "proof.dev/edition/v2" {
            let metadata: (String, String, String) = connection
                .query_row(
                    "SELECT base_edition_id, state_api_version, changeset_id
                     FROM localized_edition_metadata WHERE edition_id = ?1",
                    [edition_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| incomplete(format!("v2 Edition {edition_id} lacks metadata")))?;
            pending_editions.push(metadata.0);
            localized_changesets.insert(metadata.2);
            metadata.1
        } else {
            let manifest = parse_strict(manifest_json.as_bytes())
                .map_err(|error| invalid(error.to_string()))?;
            if let Some(changesets) = manifest.get("changesets").and_then(Value::as_array) {
                for value in changesets {
                    if let Some(changeset_id) = value.get("changeset_id").and_then(Value::as_str) {
                        collect_v1_changeset(connection, changeset_id, collector)?;
                    }
                }
            }
            "proof.dev/known-state/v1".to_owned()
        };
        pending_states.push((state_api_version, sequence, state_digest));
    }

    let mut visited_states = BTreeSet::new();
    let mut maximum_sequence = 0_i64;
    while let Some((api_version, sequence, state_digest)) = pending_states.pop() {
        if !visited_states.insert((api_version.clone(), state_digest.clone())) {
            continue;
        }
        if sequence < 0 {
            return Err(invalid("Known State sequence is negative"));
        }
        maximum_sequence = maximum_sequence.max(sequence);
        let manifest: Option<Option<String>> = connection
            .query_row(
                "SELECT manifest_json FROM known_state_artifacts
                 WHERE api_version = ?1 AND authoritative_sequence = ?2
                       AND state_digest = ?3",
                (api_version.as_str(), sequence, state_digest.as_str()),
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        let manifest = manifest.ok_or_else(|| {
            incomplete(format!(
                "Known State {api_version} {state_digest} is absent"
            ))
        })?;
        let canonical_json = if api_version == "proof.dev/known-state/v1" {
            if manifest.is_some() {
                return Err(invalid("v1 Known State unexpectedly stores v2 bytes"));
            }
            reproduce_v1_known_state(connection, workspace_id, sequence)?
        } else {
            manifest.ok_or_else(|| incomplete("v2 Known State bytes are absent"))?
        };
        collector.include_expected(
            EvidenceRoleV1::KnownState,
            known_state_kind(&api_version)?,
            canonical_json,
            &state_digest,
        )?;
        if api_version == "proof.dev/known-state/v2" {
            let predecessor: (String, i64, String, String) = connection
                .query_row(
                    "SELECT localized_commit.previous_state_api_version,
                            localized_commit.previous_authoritative_sequence,
                            localized_commit.previous_state_digest, localized_commit.changeset_id
                     FROM known_state_artifacts AS state
                     JOIN localized_commits AS localized_commit
                       ON localized_commit.changeset_id = state.changeset_id
                     WHERE state.api_version = ?1 AND state.state_digest = ?2",
                    (api_version.as_str(), state_digest.as_str()),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| incomplete("v2 Known State producing commit is absent"))?;
            pending_states.push((predecessor.0, predecessor.1, predecessor.2));
            localized_changesets.insert(predecessor.3);
        }
    }

    localized_changesets.extend(collect_authoritative_facts(
        connection,
        workspace_id,
        maximum_sequence,
        collector,
    )?);
    for changeset_id in localized_changesets {
        collect_localized_changeset(connection, workspace_id, &changeset_id, collector)?;
    }
    Ok(())
}

fn reproduce_v1_known_state(
    connection: &Connection,
    workspace_id: WorkspaceId,
    sequence: i64,
) -> ExportResult<String> {
    let mut schema_statement = connection
        .prepare(
            "SELECT schema_id, schema_version, document_digest FROM schema_versions
             WHERE authoritative_sequence <= ?1 ORDER BY schema_id, schema_version",
        )
        .map_err(storage)?;
    let schemas = schema_statement
        .query_map([sequence], |row| {
            Ok(json!({
                "document_digest": row.get::<_, String>(2)?,
                "schema_id": row.get::<_, String>(0)?,
                "schema_version": row.get::<_, i64>(1)?,
            }))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    drop(schema_statement);
    let mut object_statement = connection
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version,
                    lifecycle_state, object_digest FROM object_revisions
             WHERE authoritative_sequence <= ?1 ORDER BY object_id, revision",
        )
        .map_err(storage)?;
    let objects = object_statement
        .query_map([sequence], |row| {
            Ok(json!({
                "lifecycle_state": row.get::<_, String>(4)?,
                "object_digest": row.get::<_, String>(5)?,
                "object_id": row.get::<_, String>(0)?,
                "revision": row.get::<_, i64>(1)?,
                "schema_id": row.get::<_, String>(2)?,
                "schema_version": row.get::<_, i64>(3)?,
            }))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    let mut manifest = json!({
        "api_version": "proof.dev/known-state/v1",
        "authoritative_sequence": sequence,
        "workspace_id": workspace_id.to_string(),
    });
    if !schemas.is_empty() {
        manifest["schemas"] = Value::Array(schemas);
    }
    if !objects.is_empty() {
        manifest["objects"] = Value::Array(objects);
    }
    canonicalize(&manifest)
        .map(|canonical| canonical.as_str().to_owned())
        .map_err(|error| invalid(error.to_string()))
}

fn collect_authoritative_facts(
    connection: &Connection,
    workspace_id: WorkspaceId,
    maximum_sequence: i64,
    collector: &mut ArtifactCollector,
) -> ExportResult<BTreeSet<String>> {
    let mut schemas = connection
        .prepare(
            "SELECT document_json, document_digest FROM schema_versions
             WHERE authoritative_sequence <= ?1 ORDER BY authoritative_sequence",
        )
        .map_err(storage)?;
    let rows = schemas
        .query_map([maximum_sequence], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    for (document, document_digest) in rows {
        collector.include_expected(
            EvidenceRoleV1::Schema,
            ArtifactKind::SchemaVersionV1,
            document,
            &document_digest,
        )?;
    }

    let mut objects = connection
        .prepare(
            "SELECT object_id, revision, schema_id, schema_version,
                    lifecycle_state, content_json, object_digest
             FROM object_revisions WHERE authoritative_sequence <= ?1
             ORDER BY authoritative_sequence",
        )
        .map_err(storage)?;
    let rows = objects
        .query_map([maximum_sequence], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    for (object_id, revision, schema_id, schema_version, lifecycle, content, object_digest) in rows
    {
        let content =
            parse_strict(content.as_bytes()).map_err(|error| invalid(error.to_string()))?;
        let manifest = canonicalize(&json!({
            "api_version": "proof.dev/object-revision/v1",
            "content": content,
            "lifecycle_state": lifecycle,
            "object_id": object_id,
            "relationships": [],
            "revision": revision,
            "schema_id": schema_id,
            "schema_version": schema_version,
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::Object,
            ArtifactKind::ObjectRevisionV1,
            manifest.as_str().to_owned(),
            &object_digest,
        )?;
    }

    let mut changesets = BTreeSet::new();
    let mut renditions = connection
        .prepare(
            "SELECT manifest_json, rendition_digest, changeset_id, workspace_id
             FROM object_locale_revisions WHERE authoritative_sequence <= ?1
             ORDER BY authoritative_sequence",
        )
        .map_err(storage)?;
    let rows = renditions
        .query_map([maximum_sequence], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    for (manifest, rendition_digest, changeset_id, stored_workspace) in rows {
        if stored_workspace != workspace_id.to_string() {
            return Err(invalid("rendition closure crosses Workspace boundary"));
        }
        collector.include_expected(
            EvidenceRoleV1::LocaleRevision,
            ArtifactKind::ObjectLocaleRevisionV1,
            manifest,
            &rendition_digest,
        )?;
        changesets.insert(changeset_id);
    }
    Ok(changesets)
}

fn target_authority_sequence(
    connection: &Connection,
    workspace_id: WorkspaceId,
    release_id: ReleaseId,
) -> ExportResult<u64> {
    let mut statement = connection
        .prepare(
            "SELECT idempotency_key FROM localized_release_operations
             WHERE workspace_id = ?1 AND release_id = ?2
             ORDER BY idempotency_key",
        )
        .map_err(storage)?;
    let keys = statement
        .query_map((workspace_id.to_string(), release_id.to_string()), |row| {
            row.get::<_, String>(0)
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    if keys.len() != 1 {
        return Err(incomplete(
            "target Release lacks one unambiguous localized operation key",
        ));
    }
    let sequence: i64 = connection
        .query_row(
            "SELECT first_decision_authority_sequence
             FROM authenticated_application_idempotency_v1
             WHERE workspace_id = ?1 AND idempotency_key = ?2
                   AND operation_name = 'release.create'",
            (workspace_id.to_string(), keys[0].as_str()),
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete("target Release lacks its authenticated global-key anchor"))?;
    u64::try_from(sequence).map_err(|_| invalid("target authority sequence is out of range"))
}

#[derive(Debug)]
struct StoredConsequence {
    result_kind: String,
    application_idempotency_key: Option<String>,
    result_json: String,
    result_digest: String,
    application_effect_digest: String,
    evidence_json: String,
}

fn load_consequence(
    connection: &Connection,
    sequence: u64,
) -> ExportResult<Option<StoredConsequence>> {
    let sequence =
        i64::try_from(sequence).map_err(|_| invalid("authority sequence exceeds SQLite range"))?;
    connection
        .query_row(
            "SELECT result_kind, application_idempotency_key, result_json, result_digest,
                    application_effect_digest, evidence_json
             FROM authenticated_localized_consequences_v1
             WHERE decision_authority_sequence = ?1",
            [sequence],
            |row| {
                Ok(StoredConsequence {
                    result_kind: row.get(0)?,
                    application_idempotency_key: row.get(1)?,
                    result_json: row.get(2)?,
                    result_digest: row.get(3)?,
                    application_effect_digest: row.get(4)?,
                    evidence_json: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(storage)
}

#[expect(
    clippy::too_many_lines,
    reason = "each signed decision companion is assembled adjacent to its contiguous authority record"
)]
fn collect_authority_prefix(
    connection: &Connection,
    workspace_id: WorkspaceId,
    included_head_sequence: u64,
    target_sequence: u64,
    collector: &mut ArtifactCollector,
) -> ExportResult<(
    Vec<AuthorityPrefixEntryV1>,
    ContentDigest,
    EvidenceArtifactRefV1,
)> {
    let mut statement = connection
        .prepare(
            "SELECT authority_sequence, record_json, record_digest,
                    envelope_json, envelope_digest
             FROM authority_records WHERE workspace_id = ?1
                   AND authority_sequence <= ?2
             ORDER BY authority_sequence",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(
            (
                workspace_id.to_string(),
                i64::try_from(included_head_sequence)
                    .map_err(|_| invalid("authority head exceeds SQLite range"))?,
            ),
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    drop(statement);

    let mut prefix = Vec::with_capacity(rows.len());
    let mut target_record_digest = None;
    let mut target_consequence = None;
    for (raw_sequence, record_json, record_digest, envelope_json, envelope_digest) in rows {
        let sequence = u64::try_from(raw_sequence)
            .map_err(|_| invalid("authority sequence is out of range"))?;
        let authority_envelope = collector.include_expected(
            EvidenceRoleV1::AuthorityRecordEnvelope,
            ArtifactKind::AuthorityRecordEnvelopeV1,
            envelope_json,
            &envelope_digest,
        )?;
        let record = serde_json::from_str::<AuthorityRecordV1>(&record_json)
            .map_err(|error| invalid(format!("invalid authority record: {error}")))?;
        let decision_companion = if let AuthorityRecordV1::AuthorizationDecision(decision) = record
        {
            let presentation: Option<(String, String, String, String)> = connection
                .query_row(
                    "SELECT command_input_json, command_digest,
                            command_envelope_json, command_envelope_digest
                     FROM authenticated_command_presentations_v1
                     WHERE decision_authority_sequence = ?1
                           AND workspace_id = ?2 AND presentation_id = ?3",
                    (
                        raw_sequence,
                        workspace_id.to_string(),
                        decision.presentation_id.to_string(),
                    ),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(storage)?;
            let (command_input, authenticated_command_envelope) = match presentation {
                Some(presentation) => (
                    collector.include_expected(
                        EvidenceRoleV1::CommandInput,
                        ArtifactKind::CommandV1,
                        presentation.0,
                        &presentation.1,
                    )?,
                    collector.include_expected(
                        EvidenceRoleV1::AuthenticatedCommandEnvelope,
                        ArtifactKind::AuthenticatedCommandEnvelopeV1,
                        presentation.2,
                        &presentation.3,
                    )?,
                ),
                None => (
                    collector.external(
                        EvidenceRoleV1::CommandInput,
                        ArtifactKind::CommandV1,
                        decision.command_digest,
                    ),
                    collector.external(
                        EvidenceRoleV1::AuthenticatedCommandEnvelope,
                        ArtifactKind::AuthenticatedCommandEnvelopeV1,
                        decision.command_envelope_digest,
                    ),
                ),
            };
            let actor: Option<(String, String)> = connection
                .query_row(
                    "SELECT evidence_json, actor_context_digest
                     FROM authenticated_actor_context_evidence_v1
                     WHERE workspace_id = ?1 AND presentation_id = ?2",
                    (
                        workspace_id.to_string(),
                        decision.presentation_id.to_string(),
                    ),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(storage)?;
            let actor_context_evidence = match actor {
                Some((actor_json, actor_digest)) => collector.include_expected(
                    EvidenceRoleV1::ActorContextEvidence,
                    ArtifactKind::AuthenticatedActorContextV1,
                    actor_json,
                    &actor_digest,
                )?,
                None => collector.external(
                    EvidenceRoleV1::ActorContextEvidence,
                    ArtifactKind::AuthenticatedActorContextV1,
                    decision.actor_context_digest,
                ),
            };
            let consequence = load_consequence(connection, sequence)?;
            let (result, localized_consequence, application_effect) =
                if let Some(consequence) = consequence {
                    let result = collector.include_expected(
                        EvidenceRoleV1::LocalizedResult,
                        ArtifactKind::OperationEffectV1,
                        consequence.result_json.clone(),
                        &consequence.result_digest,
                    )?;
                    let localized_consequence = collector.include(
                        EvidenceRoleV1::LocalizedConsequence,
                        ArtifactKind::AuthenticatedLocalizedConsequenceV1,
                        consequence.evidence_json.clone(),
                        None,
                    )?;
                    let application_effect = collect_application_effect(
                        connection,
                        sequence,
                        &decision,
                        &consequence,
                        result,
                        collector,
                    )?;
                    collect_decision_application_closure(
                        connection,
                        workspace_id,
                        &decision,
                        &consequence,
                        collector,
                    )?;
                    if sequence == target_sequence {
                        target_consequence = Some(localized_consequence);
                    }
                    (
                        Some(result),
                        Some(localized_consequence),
                        Some(application_effect),
                    )
                } else {
                    (None, None, None)
                };
            Some(DecisionCompanionV1 {
                command_input,
                authenticated_command_envelope,
                actor_context_evidence,
                result,
                localized_consequence,
                application_effect,
            })
        } else {
            None
        };
        let record_digest = parse_digest(&record_digest)?;
        if sequence == target_sequence {
            target_record_digest = Some(record_digest);
        }
        prefix.push(AuthorityPrefixEntryV1 {
            sequence,
            record_digest,
            authority_envelope,
            decision_companion,
        });
    }
    if prefix.len() != usize::try_from(included_head_sequence).unwrap_or(usize::MAX) {
        return Err(invalid(
            "authority prefix is not complete through its included head",
        ));
    }
    Ok((
        prefix,
        target_record_digest
            .ok_or_else(|| incomplete("target authorization decision is absent from prefix"))?,
        target_consequence
            .ok_or_else(|| incomplete("target Release has no localized consequence"))?,
    ))
}

fn collect_decision_application_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    decision: &proof_application::authority::AuthorizationDecisionV2,
    consequence: &StoredConsequence,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    use proof_application::authority::AuthorityOperation;

    collect_signed_consequence_closure(connection, workspace_id, consequence, collector)?;
    if consequence.result_kind == "failure" {
        return Ok(());
    }
    let result = parse_strict(consequence.result_json.as_bytes())
        .map_err(|error| invalid(error.to_string()))?;
    match decision.operation {
        AuthorityOperation::ChangesetAddV2
        | AuthorityOperation::ChangesetCommitV2
        | AuthorityOperation::ChangesetCreateV2
        | AuthorityOperation::ChangesetDiffV2
        | AuthorityOperation::ChangesetGetV2
        | AuthorityOperation::ChangesetSubmitV2
        | AuthorityOperation::ChangesetValidateV2 => {
            if let Some(changeset_id) = result.get("changeset_id").and_then(Value::as_str) {
                collect_localized_changeset(connection, workspace_id, changeset_id, collector)?;
            }
        }
        AuthorityOperation::ContextBuildV2 => {
            let context_id = required_string(&result, "context_pack_id")?;
            collect_localized_context(connection, workspace_id, context_id, collector)?;
        }
        AuthorityOperation::EditionCreateV2 => {
            let edition_id = required_string(&result, "edition_id")?;
            collect_edition_content_closure(
                connection,
                workspace_id,
                vec![edition_id.to_owned()],
                Vec::new(),
                collector,
            )?;
        }
        AuthorityOperation::ReleaseCreateV2 => {
            let release_id = required_string(&result, "release_id")?
                .parse::<ReleaseId>()
                .map_err(|error| invalid(error.to_string()))?;
            let releases =
                collect_release_closure(connection, workspace_id, release_id, collector)?;
            collect_content_closure(connection, workspace_id, &releases, collector)?;
        }
        AuthorityOperation::ObjectQueryReleasedV2 => {
            let release_id = object_query_release_closure_root(&result)?;
            let releases =
                collect_release_closure(connection, workspace_id, release_id, collector)?;
            collect_content_closure(connection, workspace_id, &releases, collector)?;
        }
        AuthorityOperation::ContextBuildV1
        | AuthorityOperation::ObjectQueryReleasedV1
        | AuthorityOperation::WorkspaceStatusV1 => {}
    }
    Ok(())
}

fn collect_signed_consequence_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    consequence: &StoredConsequence,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let evidence = parse_strict(consequence.evidence_json.as_bytes())
        .map_err(|error| invalid(error.to_string()))?;
    let closure = evidence
        .get("closure")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("localized consequence has no object closure"))?;
    if closure.contains_key("resource_intent") {
        collect_signed_intent_closure(connection, workspace_id, closure, collector)
    } else {
        collect_signed_released_closure(connection, workspace_id, closure, collector)
    }
}

fn collect_signed_intent_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    closure: &serde_json::Map<String, Value>,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let intent = closure
        .get("resource_intent")
        .ok_or_else(|| invalid("localized closure has no resource Intent"))?;
    let intent_id = required_string(intent, "intent_id")?;
    collect_resource_intent(connection, workspace_id, intent_id, collector)?;

    if let Some(context) = optional_closure_object(closure, "context")? {
        let context_id = required_string(context, "context_pack_id")?;
        collect_localized_context(connection, workspace_id, context_id, collector)?;
    }

    let changeset_id = if let Some(changeset) = optional_closure_object(closure, "changeset")? {
        let changeset_id = required_string(changeset, "changeset_id")?;
        collect_localized_changeset(connection, workspace_id, changeset_id, collector)?;
        Some(changeset_id)
    } else {
        None
    };
    if closure
        .get("approval")
        .is_some_and(|value| !value.is_null())
        && changeset_id.is_none()
    {
        return Err(invalid(
            "localized approval closure has no ChangeSet preimage anchor",
        ));
    }
    Ok(())
}

fn collect_signed_released_closure(
    connection: &Connection,
    workspace_id: WorkspaceId,
    closure: &serde_json::Map<String, Value>,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let release_id = optional_closure_string(closure, "release_id")?
        .map(|value| {
            value
                .parse::<ReleaseId>()
                .map_err(|error| invalid(error.to_string()))
        })
        .transpose()?;
    let edition_id = optional_closure_string(closure, "edition_id")?;
    let schema_ids = closure
        .get("schema_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("localized released closure has no Schema identities"))?;
    if schema_ids.iter().any(|value| !value.is_string()) {
        return Err(invalid(
            "localized released closure has a malformed Schema identity",
        ));
    }
    if !schema_ids.is_empty() && edition_id.is_none() {
        return Err(invalid(
            "localized released closure has Schemas without an Edition anchor",
        ));
    }

    if let Some(release_id) = release_id {
        let releases = collect_release_closure(connection, workspace_id, release_id, collector)?;
        collect_content_closure(connection, workspace_id, &releases, collector)?;
    }
    if let Some(edition_id) = edition_id {
        collect_edition_content_closure(
            connection,
            workspace_id,
            vec![edition_id.to_owned()],
            Vec::new(),
            collector,
        )?;
    }
    Ok(())
}

fn optional_closure_object<'a>(
    closure: &'a serde_json::Map<String, Value>,
    field: &str,
) -> ExportResult<Option<&'a Value>> {
    match closure.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value @ Value::Object(_)) => Ok(Some(value)),
        Some(_) => Err(invalid(format!(
            "localized closure field {field} is not an object"
        ))),
    }
}

fn optional_closure_string<'a>(
    closure: &'a serde_json::Map<String, Value>,
    field: &str,
) -> ExportResult<Option<&'a str>> {
    match closure.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(invalid(format!(
            "localized closure field {field} is not a string"
        ))),
    }
}

fn object_query_release_closure_root(result: &Value) -> ExportResult<ReleaseId> {
    required_string(result, "release_id")?
        .parse::<ReleaseId>()
        .map_err(|error| invalid(error.to_string()))
}

#[expect(
    clippy::too_many_lines,
    reason = "the closed AuthorityOperation registry is exhaustively reconstructed in one match"
)]
fn collect_application_effect(
    connection: &Connection,
    sequence: u64,
    decision: &proof_application::authority::AuthorizationDecisionV2,
    consequence: &StoredConsequence,
    _result_ref: EvidenceArtifactRefV1,
    collector: &mut ArtifactCollector,
) -> ExportResult<EvidenceArtifactRefV1> {
    use proof_application::authority::AuthorityOperation;

    if consequence.result_kind == "failure"
        || matches!(
            decision.operation,
            AuthorityOperation::ChangesetGetV2
                | AuthorityOperation::ChangesetDiffV2
                | AuthorityOperation::ObjectQueryReleasedV2
        )
    {
        return collector.include_expected(
            EvidenceRoleV1::ApplicationEffect,
            ArtifactKind::OperationEffectV1,
            consequence.result_json.clone(),
            &consequence.application_effect_digest,
        );
    }
    if let Some(reference) = collector.alias_for_digest(
        EvidenceRoleV1::ApplicationEffect,
        &consequence.application_effect_digest,
    )? {
        return Ok(reference);
    }
    let result = parse_strict(consequence.result_json.as_bytes())
        .map_err(|error| invalid(error.to_string()))?;
    let key = consequence.application_idempotency_key.as_deref();
    let effect = match decision.operation {
        AuthorityOperation::ContextBuildV2 => {
            let context_id = required_string(&result, "context_pack_id")?;
            let context_digest = required_string(&result, "context_pack_digest")?;
            let (request_digest, stored_effect): (String, String) = connection
                .query_row(
                    "SELECT request_digest, effect_digest
                     FROM localized_context_build_operations
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3
                           AND context_pack_id = ?4",
                    (
                        decision.workspace_id.to_string(),
                        decision.requesting_principal_id.to_string(),
                        required_key(key, sequence)?,
                        context_id,
                    ),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(storage)?;
            if stored_effect != consequence.application_effect_digest {
                return Err(invalid(
                    "Context effect digest differs from global consequence",
                ));
            }
            canonicalize(&json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "context.build/v2",
                "request_digest": request_digest,
                "result": {
                    "context_pack_digest": context_digest,
                    "context_pack_id": context_id,
                },
            }))
            .map_err(|error| invalid(error.to_string()))?
        }
        AuthorityOperation::ChangesetCreateV2 => {
            let changeset_id = required_string(&result, "changeset_id")?;
            let row: (
                String,
                String,
                String,
                String,
                String,
                String,
                String,
                String,
            ) = connection
                .query_row(
                    "SELECT context_pack_digest, context_pack_id, created_at,
                            idempotency_key, intent, resource_intent_digest,
                            resource_intent_id, effect_digest
                     FROM localized_changesets WHERE changeset_id = ?1",
                    [changeset_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .map_err(storage)?;
            if row.7 != consequence.application_effect_digest {
                return Err(invalid("ChangeSet-create effect differs from consequence"));
            }
            let request = canonicalize(&json!({
                "api_version": "proof.dev/operation/changeset.create/v2",
                "changeset_id": changeset_id,
                "context_pack_digest": row.0,
                "context_pack_id": row.1,
                "created_at": row.2,
                "idempotency_key": row.3,
                "intent": row.4,
                "resource_intent_digest": row.5,
                "resource_intent_id": row.6,
            }))
            .map_err(|error| invalid(error.to_string()))?;
            let request_digest = digest(ArtifactKind::OperationEffectV1, &request);
            canonicalize(&json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.create/v2",
                "request_digest": request_digest.to_string(),
                "result": result,
            }))
            .map_err(|error| invalid(error.to_string()))?
        }
        AuthorityOperation::ChangesetAddV2 => {
            let (request_digest, stored_effect): (String, String) = connection
                .query_row(
                    "SELECT request_digest, effect_digest FROM localized_add_operations
                     WHERE workspace_id = ?1 AND principal_id = ?2 AND idempotency_key = ?3",
                    (
                        decision.workspace_id.to_string(),
                        decision.requesting_principal_id.to_string(),
                        required_key(key, sequence)?,
                    ),
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(storage)?;
            if stored_effect != consequence.application_effect_digest {
                return Err(invalid("ChangeSet-add effect differs from consequence"));
            }
            canonicalize(&json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.add/v2",
                "request_digest": request_digest,
                "result": result,
            }))
            .map_err(|error| invalid(error.to_string()))?
        }
        AuthorityOperation::ChangesetValidateV2 => {
            let validation_digest = required_string(&result, "validation_results_digest")?;
            let results_json: String = connection
                .query_row(
                    "SELECT results_json FROM localized_validations WHERE results_digest = ?1",
                    [validation_digest],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            return collector.include_expected(
                EvidenceRoleV1::ApplicationEffect,
                ArtifactKind::ValidationResultsV2,
                results_json,
                &consequence.application_effect_digest,
            );
        }
        AuthorityOperation::ChangesetSubmitV2 => {
            let changeset_id = required_string(&result, "changeset_id")?;
            let row: (String, String, String, String, String) = connection
                .query_row(
                    "SELECT sealed_changeset_digest, validation_results_digest,
                            principal_id, submitted_at, effect_digest
                     FROM localized_submissions WHERE changeset_id = ?1",
                    [changeset_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .map_err(storage)?;
            if row.4 != consequence.application_effect_digest {
                return Err(invalid("ChangeSet-submit effect differs from consequence"));
            }
            canonicalize(&json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.submit/v2",
                "result": {
                    "approval": null,
                    "changeset_id": changeset_id,
                    "occurred_at": row.3,
                    "principal_id": row.2,
                    "sealed_changeset_digest": row.0,
                    "validation_results_digest": row.1,
                },
            }))
            .map_err(|error| invalid(error.to_string()))?
        }
        AuthorityOperation::ChangesetCommitV2 => {
            let changeset_id = required_string(&result, "changeset_id")?;
            reproduce_commit_effect(connection, changeset_id, consequence)?
        }
        AuthorityOperation::EditionCreateV2 => {
            let edition_id = required_string(&result, "edition_id")?;
            let (request_digest, stored_effect, changeset_id): (String, String, String) =
                connection
                    .query_row(
                        "SELECT operation.request_digest, operation.effect_digest,
                            metadata.changeset_id
                     FROM localized_edition_operations AS operation
                     JOIN localized_edition_metadata AS metadata
                       ON metadata.edition_id = operation.edition_id
                     WHERE operation.workspace_id = ?1 AND operation.principal_id = ?2
                           AND operation.idempotency_key = ?3 AND operation.edition_id = ?4",
                        (
                            decision.workspace_id.to_string(),
                            decision.requesting_principal_id.to_string(),
                            required_key(key, sequence)?,
                            edition_id,
                        ),
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .map_err(storage)?;
            if stored_effect != consequence.application_effect_digest {
                return Err(invalid("Edition effect differs from consequence"));
            }
            canonicalize(&json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "edition.create/v2",
                "request_digest": request_digest,
                "result": {
                    "changeset_id": changeset_id,
                    "edition_digest": required_string(&result, "edition_digest")?,
                    "edition_id": edition_id,
                    "state": result.get("state").cloned().ok_or_else(|| invalid("Edition result lacks state"))?,
                },
            }))
            .map_err(|error| invalid(error.to_string()))?
        }
        AuthorityOperation::ReleaseCreateV2 => {
            let release_id = required_string(&result, "release_id")?;
            let (api_version, manifest_json, release_digest): (String, String, String) = connection
                .query_row(
                    "SELECT api_version, manifest_json, release_digest
                     FROM releases WHERE workspace_id = ?1 AND release_id = ?2",
                    (decision.workspace_id.to_string(), release_id),
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .map_err(storage)?;
            if release_digest != consequence.application_effect_digest {
                return Err(invalid("Release effect differs from consequence"));
            }
            return collector.include_expected(
                EvidenceRoleV1::ApplicationEffect,
                release_kind(&api_version)?,
                manifest_json,
                &release_digest,
            );
        }
        AuthorityOperation::ChangesetGetV2
        | AuthorityOperation::ChangesetDiffV2
        | AuthorityOperation::ObjectQueryReleasedV2 => unreachable!("read effects returned above"),
        AuthorityOperation::ContextBuildV1
        | AuthorityOperation::ObjectQueryReleasedV1
        | AuthorityOperation::WorkspaceStatusV1 => {
            return Err(invalid("legacy operation has a localized consequence"));
        }
    };
    collector.include_expected(
        EvidenceRoleV1::ApplicationEffect,
        ArtifactKind::OperationEffectV1,
        effect.as_str().to_owned(),
        &consequence.application_effect_digest,
    )
}

fn required_string<'a>(value: &'a Value, field: &str) -> ExportResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("localized result lacks {field}")))
}

fn required_key(key: Option<&str>, sequence: u64) -> ExportResult<&str> {
    key.ok_or_else(|| {
        incomplete(format!(
            "localized decision {sequence} lacks its global key"
        ))
    })
}

fn reproduce_commit_effect(
    connection: &Connection,
    changeset_id: &str,
    consequence: &StoredConsequence,
) -> ExportResult<proof_canonical::CanonicalJson> {
    let row: (
        String,
        String,
        String,
        i64,
        String,
        i64,
        String,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT idempotency_key, sealed_changeset_digest,
                    previous_state_api_version, previous_authoritative_sequence,
                    previous_state_digest, resulting_authoritative_sequence,
                    resulting_state_digest, validation_results_digest,
                    committed_at, effect_digest
             FROM localized_commits WHERE changeset_id = ?1",
            [changeset_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .map_err(storage)?;
    if row.9 != consequence.application_effect_digest {
        return Err(invalid("ChangeSet-commit effect differs from consequence"));
    }
    let request = canonicalize(&json!({
        "api_version": "proof.dev/operation/changeset.commit/v2",
        "changeset_id": changeset_id,
        "committed_at": row.8,
        "idempotency_key": row.0,
    }))
    .map_err(|error| invalid(error.to_string()))?;
    let request_digest = digest(ArtifactKind::OperationEffectV1, &request);
    let mut statement = connection
        .prepare(
            "SELECT rendition_digest, edit_id, locale, object_id, revision
             FROM object_locale_revisions WHERE changeset_id = ?1
             ORDER BY authoritative_sequence",
        )
        .map_err(storage)?;
    let renditions = statement
        .query_map([changeset_id], |rendition| {
            Ok(json!({
                "digest": rendition.get::<_, String>(0)?,
                "edit_id": rendition.get::<_, String>(1)?,
                "locale": rendition.get::<_, String>(2)?,
                "object_id": rendition.get::<_, String>(3)?,
                "revision": rendition.get::<_, i64>(4)?,
            }))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    canonicalize(&json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.commit/v2",
        "request_digest": request_digest.to_string(),
        "result": {
            "changeset_id": changeset_id,
            "committed_at": row.8,
            "previous_state": {
                "api_version": row.2,
                "authoritative_sequence": row.3,
                "digest": row.4,
            },
            "renditions": renditions,
            "resulting_state": {
                "api_version": "proof.dev/known-state/v2",
                "authoritative_sequence": row.5,
                "digest": row.6,
            },
            "sealed_changeset_digest": row.1,
            "validation_results_digest": row.7,
        },
    }))
    .map_err(|error| invalid(error.to_string()))
}

fn collect_subject_opening(
    connection: &Connection,
    workspace_id: WorkspaceId,
    target_sequence: u64,
    disclosure: SubjectOpeningDisclosureV1,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let decision_json: String = connection
        .query_row(
            "SELECT decision_json FROM authorization_decisions_v2
             WHERE authority_sequence = ?1 AND workspace_id = ?2",
            (
                i64::try_from(target_sequence)
                    .map_err(|_| invalid("target sequence exceeds SQLite range"))?,
                workspace_id.to_string(),
            ),
            |row| row.get(0),
        )
        .map_err(storage)?;
    let decision = serde_json::from_str::<proof_application::authority::AuthorizationDecisionV2>(
        &decision_json,
    )
    .map_err(|error| invalid(error.to_string()))?;
    let row: (String, String, String, String, String) = connection
        .query_row(
            "SELECT requesting_subject_provider, requesting_subject, blind,
                    commitment_input_json, requesting_subject_commitment
             FROM authenticated_subject_commitment_openings_v1
             WHERE workspace_id = ?1 AND requesting_principal_id = ?2",
            (
                workspace_id.to_string(),
                decision.requesting_principal_id.to_string(),
            ),
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete("authenticated subject opening is absent"))?;
    if row.4 != decision.requesting_subject_commitment.to_string() {
        return Err(invalid("subject opening differs from signed commitment"));
    }
    let commitment_input =
        parse_strict(row.3.as_bytes()).map_err(|error| invalid(error.to_string()))?;
    let canonical_input =
        canonicalize(&commitment_input).map_err(|error| invalid(error.to_string()))?;
    if canonical_input.as_str() != row.3
        || digest(
            ArtifactKind::AuthenticatedSubjectCommitmentV1,
            &canonical_input,
        ) != decision.requesting_subject_commitment
    {
        return Err(invalid("subject opening does not reproduce its commitment"));
    }
    let opening = canonicalize(&json!({
        "api_version": "proof.dev/authenticated-subject-opening/v1",
        "blind": row.2,
        "commitment_input": commitment_input,
        "requesting_subject": {
            "provider": row.0,
            "subject": row.1,
        },
        "requesting_subject_commitment": row.4,
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| invalid(error.to_string()))?;
    let opening_digest = digest(ArtifactKind::AuthenticatedSubjectOpeningV1, &opening);
    match disclosure {
        SubjectOpeningDisclosureV1::Withhold => {
            collector.external(
                EvidenceRoleV1::SubjectOpening,
                ArtifactKind::AuthenticatedSubjectOpeningV1,
                opening_digest,
            );
        }
        SubjectOpeningDisclosureV1::Include => {
            collector.include(
                EvidenceRoleV1::SubjectOpening,
                ArtifactKind::AuthenticatedSubjectOpeningV1,
                opening.as_str().to_owned(),
                Some(opening_digest),
            )?;
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "localized lifecycle closure retains its exact typed SQLite projection and causal checks together"
)]
fn collect_localized_changeset(
    connection: &Connection,
    workspace_id: WorkspaceId,
    changeset_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: Option<(
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = connection
        .query_row(
            "SELECT resource_intent_id, resource_intent_digest,
                    context_pack_id, context_pack_digest, workspace_id, principal_id,
                    intent, base_state_api_version, base_authoritative_sequence,
                    base_state_digest, created_at, proposal_digest,
                    effective_leaf_digest, sealed_changeset_digest
             FROM localized_changesets WHERE changeset_id = ?1",
            [changeset_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some((
        intent_id,
        intent_digest,
        context_id,
        context_digest,
        stored_workspace,
        principal_id,
        intent,
        base_api_version,
        base_sequence,
        base_digest,
        created_at,
        proposal_digest,
        effective_leaf_digest,
        sealed_digest,
    )) = row
    else {
        return Err(incomplete(format!(
            "localized ChangeSet {changeset_id} is absent"
        )));
    };
    if stored_workspace != workspace_id.to_string() {
        return Err(invalid("localized ChangeSet crosses Workspace boundary"));
    }

    let mut edits = connection
        .prepare(
            "SELECT edit_json, edit_digest, edit_id, object_id, locale
             FROM localized_edits
             WHERE changeset_id = ?1 ORDER BY ordinal",
        )
        .map_err(storage)?;
    let edit_rows = edits
        .query_map([changeset_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    let mut all_edits = Vec::with_capacity(edit_rows.len());
    let mut effective = BTreeMap::<(String, String), (Value, String, String)>::new();
    for (edit_json, edit_digest, edit_id, object_id, locale) in edit_rows {
        let edit_value = parse_strict(edit_json.as_bytes())
            .map_err(|error| invalid(format!("localized Edit is invalid: {error}")))?;
        collector.include_expected(
            EvidenceRoleV1::Edit,
            ArtifactKind::EditV2,
            edit_json,
            &edit_digest,
        )?;
        all_edits.push(edit_value.clone());
        effective.insert((object_id, locale), (edit_value, edit_digest, edit_id));
    }
    if let Some(proposal_digest) = proposal_digest.as_deref() {
        let expected_effective_digest = effective_leaf_digest.as_deref().ok_or_else(|| {
            incomplete("localized ChangeSet proposal lacks effective Edit digest")
        })?;
        let effective_edits = effective
            .values()
            .map(|(edit, _, _)| edit.clone())
            .collect::<Vec<_>>();
        let effective_batch = canonicalize(&json!({
            "api_version": "proof.dev/edit-batch/v2",
            "edits": effective_edits,
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::Edit,
            ArtifactKind::EditBatchV2,
            effective_batch.as_str().to_owned(),
            expected_effective_digest,
        )?;
        let effective_leaves = effective
            .iter()
            .map(|((object_id, locale), (_, edit_digest, edit_id))| {
                json!({
                    "edit_digest": edit_digest,
                    "edit_id": edit_id,
                    "locale": locale,
                    "object_id": object_id,
                })
            })
            .collect::<Vec<_>>();
        let proposal = canonicalize(&json!({
            "api_version": "proof.dev/changeset/v2",
            "base_state": {
                "api_version": base_api_version,
                "authoritative_sequence": base_sequence,
                "digest": base_digest,
            },
            "changeset_id": changeset_id,
            "context_pack_digest": context_digest,
            "context_pack_id": context_id,
            "created_at": created_at,
            "edits": all_edits,
            "effective_leaf_digest": expected_effective_digest,
            "effective_leaves": effective_leaves,
            "intent": intent,
            "principal_id": principal_id,
            "resource_intent_digest": intent_digest,
            "resource_intent_id": intent_id,
            "workspace_id": stored_workspace,
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::ChangeSet,
            ArtifactKind::ChangeSetV2,
            proposal.as_str().to_owned(),
            proposal_digest,
        )?;
    }

    let mut validations = connection
        .prepare(
            "SELECT proposal_digest, results_json, results_digest,
                    sealed_changeset_digest
             FROM localized_validations WHERE changeset_id = ?1 ORDER BY attempt",
        )
        .map_err(storage)?;
    let validation_rows = validations
        .query_map([changeset_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    let mut sealed_source = None;
    for (validation_proposal, results_json, results_digest, validation_seal) in validation_rows {
        collector.include_expected(
            EvidenceRoleV1::ValidationAttempt,
            ArtifactKind::ValidationResultsV2,
            results_json,
            &results_digest,
        )?;
        if validation_seal.as_deref() == sealed_digest.as_deref() {
            sealed_source = Some((validation_proposal, results_digest));
        }
    }
    if let Some(sealed_digest) = sealed_digest.as_deref() {
        let (validation_proposal, results_digest) = sealed_source
            .ok_or_else(|| incomplete("localized ChangeSet seal has no validation source"))?;
        if proposal_digest.as_deref() != Some(validation_proposal.as_str()) {
            return Err(invalid(
                "localized ChangeSet proposal and seal source differ",
            ));
        }
        let seal = canonicalize(&json!({
            "api_version": "proof.dev/changeset-seal/v2",
            "proposal_digest": validation_proposal,
            "validation_results_digest": results_digest,
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::ChangeSet,
            ArtifactKind::ChangeSetV2,
            seal.as_str().to_owned(),
            sealed_digest,
        )?;
    }

    collect_localized_submission(connection, changeset_id, collector)?;
    collect_localized_approval(connection, changeset_id, collector)?;
    collect_resource_intent(connection, workspace_id, &intent_id, collector)?;
    collect_localized_context(connection, workspace_id, &context_id, collector)?;
    Ok(())
}

fn collect_resource_intent(
    connection: &Connection,
    workspace_id: WorkspaceId,
    intent_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: (String, String, String) = connection
        .query_row(
            "SELECT workspace_id, manifest_json, intent_digest
             FROM content_resource_intents WHERE intent_id = ?1",
            [intent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete(format!("resource Intent {intent_id} is absent")))?;
    if row.0 != workspace_id.to_string() {
        return Err(invalid("resource Intent crosses Workspace boundary"));
    }
    collector.include_expected(
        EvidenceRoleV1::ResourceIntent,
        ArtifactKind::ContentResourceIntentV1,
        row.1,
        &row.2,
    )?;
    Ok(())
}

fn collect_localized_context(
    connection: &Connection,
    workspace_id: WorkspaceId,
    context_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: (String, String, String, String, String) = connection
        .query_row(
            "SELECT workspace_id, manifest_json, context_pack_digest,
                    policy_json, policy_digest
             FROM localized_context_packs WHERE context_pack_id = ?1",
            [context_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?
        .ok_or_else(|| incomplete(format!("localized ContextPack {context_id} is absent")))?;
    if row.0 != workspace_id.to_string() {
        return Err(invalid("localized ContextPack crosses Workspace boundary"));
    }
    collector.include_expected(
        EvidenceRoleV1::ContextPack,
        ArtifactKind::ContextPackV2,
        row.1,
        &row.2,
    )?;
    collector.include_expected(
        EvidenceRoleV1::ContextPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        row.3,
        &row.4,
    )?;
    Ok(())
}

fn collect_localized_submission(
    connection: &Connection,
    changeset_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: Option<(String, String, String, String, String)> = connection
        .query_row(
            "SELECT sealed_changeset_digest, validation_results_digest,
                    principal_id, submitted_at, effect_digest
             FROM localized_submissions WHERE changeset_id = ?1",
            [changeset_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    if let Some((sealed, validation, principal, submitted_at, effect_digest)) = row {
        let effect = canonicalize(&json!({
            "api_version": "proof.dev/operation-effect/v1",
            "operation_kind": "changeset.submit/v2",
            "result": {
                "approval": null,
                "changeset_id": changeset_id,
                "occurred_at": submitted_at,
                "principal_id": principal,
                "sealed_changeset_digest": sealed,
                "validation_results_digest": validation,
            },
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::Submission,
            ArtifactKind::OperationEffectV1,
            effect.as_str().to_owned(),
            &effect_digest,
        )?;
    }
    Ok(())
}

fn collect_localized_approval(
    connection: &Connection,
    changeset_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: Option<(String, String, String, String, String, String)> = connection
        .query_row(
            "SELECT approval_name, sealed_changeset_digest,
                    validation_results_digest, principal_id, approved_at, effect_digest
             FROM localized_approvals WHERE changeset_id = ?1",
            [changeset_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    if let Some((approval, sealed, validation, principal, approved_at, effect_digest)) = row {
        let effect = canonicalize(&json!({
            "api_version": "proof.dev/operation-effect/v1",
            "operation_kind": "changeset.approve/v2",
            "result": {
                "approval": approval,
                "changeset_id": changeset_id,
                "occurred_at": approved_at,
                "principal_id": principal,
                "sealed_changeset_digest": sealed,
                "validation_results_digest": validation,
            },
        }))
        .map_err(|error| invalid(error.to_string()))?;
        collector.include_expected(
            EvidenceRoleV1::Approval,
            ArtifactKind::OperationEffectV1,
            effect.as_str().to_owned(),
            &effect_digest,
        )?;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    clippy::type_complexity,
    reason = "legacy ChangeSet reconstruction keeps every historical field and validation byte visible"
)]
fn collect_v1_changeset(
    connection: &Connection,
    changeset_id: &str,
    collector: &mut ArtifactCollector,
) -> ExportResult<()> {
    let row: Option<(
        String,
        String,
        String,
        Option<String>,
        i64,
        String,
        String,
        String,
        String,
        String,
    )> = connection
        .query_row(
            "SELECT workspace_id, principal_id, intent, requested_base_state,
                    base_authoritative_sequence, base_state, idempotency_key,
                    created_at, policy_profile, validation_profile
             FROM changesets WHERE changeset_id = ?1",
            [changeset_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Err(incomplete(format!("v1 ChangeSet {changeset_id} is absent")));
    };
    let mut statement = connection
        .prepare(
            "SELECT edit.ordinal, edit.edit_id, edit.edit_kind, edit.schema_id,
                    edit.schema_version, edit.object_id, edit.document_json,
                    edit.document_digest, object.object_digest
             FROM changeset_edits AS edit
             LEFT JOIN object_revisions AS object ON object.edit_id = edit.edit_id
             WHERE edit.changeset_id = ?1 ORDER BY edit.ordinal",
        )
        .map_err(storage)?;
    let edit_rows = statement
        .query_map([changeset_id], |entry| {
            Ok((
                entry.get::<_, i64>(0)?,
                entry.get::<_, String>(1)?,
                entry.get::<_, String>(2)?,
                entry.get::<_, String>(3)?,
                entry.get::<_, i64>(4)?,
                entry.get::<_, Option<String>>(5)?,
                entry.get::<_, String>(6)?,
                entry.get::<_, String>(7)?,
                entry.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    let mut edits = Vec::with_capacity(edit_rows.len());
    let mut edit_batch_entries = Vec::with_capacity(edit_rows.len());
    for entry in edit_rows {
        let semantic = if entry.2 == "schema.create" {
            edit_batch_entries.push(json!({
                "document_digest": entry.7,
                "kind": entry.2,
                "schema_id": entry.3,
                "schema_version": entry.4,
            }));
            json!({
                "document_digest": entry.7,
                "edit_id": entry.1,
                "kind": entry.2,
                "ordinal": entry.0,
                "schema_id": entry.3,
                "schema_version": entry.4,
            })
        } else {
            let object_digest = entry
                .8
                .ok_or_else(|| incomplete("v1 Object Edit lacks projection"))?;
            let object_id = entry
                .5
                .ok_or_else(|| incomplete("v1 Object Edit lacks Object identity"))?;
            edit_batch_entries.push(json!({
                "kind": entry.2,
                "object_digest": object_digest,
                "object_id": object_id,
                "schema_id": entry.3,
                "schema_version": entry.4,
            }));
            json!({
                "edit_id": entry.1,
                "kind": entry.2,
                "object_digest": object_digest,
                "object_id": object_id,
                "ordinal": entry.0,
                "schema_id": entry.3,
                "schema_version": entry.4,
            })
        };
        edits.push(semantic);
    }
    let edit_batch = canonicalize(&json!({
        "api_version": "proof.dev/edit-batch/v1",
        "edits": edit_batch_entries,
    }))
    .map_err(|error| invalid(error.to_string()))?;
    collector.include(
        EvidenceRoleV1::Edit,
        ArtifactKind::EditBatchV1,
        edit_batch.as_str().to_owned(),
        None,
    )?;
    let manifest = canonicalize(&json!({
        "api_version": "proof.dev/changeset/v1",
        "base_authoritative_sequence": row.4,
        "base_state": row.5,
        "changeset_id": changeset_id,
        "created_at": row.7,
        "edits": edits,
        "idempotency_key": row.6,
        "intent": row.2,
        "policy_profile": row.8,
        "principal_id": row.1,
        "requested_base_state": row.3,
        "validation_profile": row.9,
        "workspace_id": row.0,
    }))
    .map_err(|error| invalid(error.to_string()))?;
    let expected_digest: Option<String> = connection
        .query_row(
            "SELECT changeset_digest FROM changeset_validations
             WHERE changeset_id = ?1 ORDER BY validator LIMIT 1",
            [changeset_id],
            |entry| entry.get(0),
        )
        .optional()
        .map_err(storage)?;
    collector.include(
        EvidenceRoleV1::ChangeSet,
        ArtifactKind::ChangeSetV1,
        manifest.as_str().to_owned(),
        expected_digest.as_deref().map(parse_digest).transpose()?,
    )?;

    let mut validations = connection
        .prepare(
            "SELECT results_json, results_digest FROM changeset_validations
             WHERE changeset_id = ?1 ORDER BY validator",
        )
        .map_err(storage)?;
    let rows = validations
        .query_map([changeset_id], |entry| {
            Ok((entry.get::<_, String>(0)?, entry.get::<_, String>(1)?))
        })
        .map_err(storage)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage)?;
    for (results_json, results_digest) in rows {
        collector.include_expected(
            EvidenceRoleV1::ValidationAttempt,
            ArtifactKind::ValidationResultsV1,
            results_json,
            &results_digest,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use proof_application::{
        AddChangeSetEditsCommand, AddLocalizedEditsCommand, ApprovalName, ApproveChangeSetCommand,
        ArtifactKind, BuildLocalizedContextCommand, ChangeSetEdit, ChangeSetIntent,
        CommitChangeSetCommand, CommitLocalizedChangeSetCommand, CreateAgentPrincipalCommand,
        CreateChangeSetCommand, CreateEditionCommand, CreateEnvironmentCommand,
        CreateLocalizedChangeSetCommand, CreateLocalizedEditionCommand, ExpectedLocalizedSource,
        IdempotencyKey, InitializeWorkspaceCommand, IssueContentResourceIntentCommand, LocaleId,
        LocalizedContentRepository, LocalizedContentTarget, LocalizedContextLimits,
        ObjectCreateEdit, ObjectId, ObjectLocalePutInput, ObjectRevision, PrincipalId,
        PromoteReleaseCommand, ProofId, ReleaseId, SchemaCreateEdit, SchemaId, SchemaVersion,
        SubmitChangeSetCommand, Timestamp, WorkspaceId, add_changeset_edits, approve_changeset,
        authority::{
            AgentPrincipalType, AuthenticatedAuthorityExecutor, AuthenticatedCommandApiVersion,
            AuthenticatedCommandEnvelopeJson, AuthenticatedCommandKeyUsage, AuthenticatedCommandV1,
            AuthenticatedInvocationApiVersion, AuthenticatedInvocationV1, AuthorityAction,
            AuthorityAdministrator, AuthorityAudience, AuthorityOperation, AuthorityPrincipalType,
            AuthorityRepository, AuthoritySequence, BindingEnrollmentChallengeV1,
            CommandInputApiVersion, CommandInputV1, DelegationActionsV2, DelegationApiVersion,
            DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
            DelegationObjectIdsV2, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
            DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
            EnrollmentChallengeApiVersion, LocalEd25519AuthenticatedSubjectV1, MaxContextBytes,
            MaxEditsPerChangeSet, MaxObjects, PrincipalBindingApiVersion, PrincipalBindingV1,
            PrincipalStatusApiVersion, PrincipalStatusV1, SubdelegationDisabled,
        },
        commit_changeset, create_agent_principal, create_changeset, create_edition,
        create_environment,
        evidence::{
            AuthorityEvidenceExportError, AuthorityEvidenceExportRepository,
            EvidenceAvailabilityV1, EvidenceRoleV1, ExportAuthorityEvidenceBundleV1Command,
            SubjectOpeningDisclosureV1,
        },
        initialize_workspace, promote_release, submit_changeset, validate_changeset,
    };
    use proof_attestation::{
        Ed25519SigningProvider, ProofSigningProvider as _,
        authority::{AuthorityPayloadProfile, sign_authority_payload},
    };
    use proof_canonical::{
        canonicalize, digest as canonical_digest, object_revision_digest, parse_strict,
    };
    use rusqlite::{Connection, params, types::ValueRef};
    use serde_json::Value;

    use super::{
        ArtifactCollector, LocalWorkspace, StoredConsequence, collect_release_closure,
        collect_signed_consequence_closure, object_query_release_closure_root,
        portable_release_signing_key, portable_release_signing_key_revocation,
    };
    use crate::DeterministicLocalAuthorityAdapter;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "proof-p0006-evidence-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn deterministic_adapter(unix_uid: u64) -> DeterministicLocalAuthorityAdapter {
        DeterministicLocalAuthorityAdapter::new(
            unix_uid,
            "2026-08-21T12:00:00Z".parse::<Timestamp>().unwrap(),
            [0x4d; 32],
        )
    }

    #[test]
    fn portable_release_key_wrappers_are_workspace_scoped() {
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let metadata = serde_json::json!({
            "algorithm": "ed25519",
            "api_version": "proof.dev/signing-key-metadata/v1",
            "key_id": format!("ed25519:{}", "11".repeat(32)),
            "not_before": "2026-08-21T12:00:00Z",
            "public_key": "11".repeat(32),
            "trust_profile": "proof.local/release-proof/v1",
        });
        let key = portable_release_signing_key(
            workspace_id,
            metadata["key_id"].as_str().unwrap(),
            "ed25519",
            metadata["public_key"].as_str().unwrap(),
            "proof.local/release-proof/v1",
            "2026-08-21T12:00:00Z",
            &metadata,
            &format!("blake3:{}", "22".repeat(32)),
        )
        .unwrap();
        let revocation = portable_release_signing_key_revocation(
            workspace_id,
            metadata["key_id"].as_str().unwrap(),
            "2026-08-22T12:00:00Z",
            "rotation",
            &serde_json::json!({
                "api_version": "proof.dev/signing-key-revocation/v1",
                "key_id": metadata["key_id"],
                "reason": "rotation",
                "revoked_at": "2026-08-22T12:00:00Z",
            }),
            &format!("blake3:{}", "33".repeat(32)),
        )
        .unwrap();
        let key: serde_json::Value = serde_json::from_str(key.as_str()).unwrap();
        let revocation: serde_json::Value = serde_json::from_str(revocation.as_str()).unwrap();
        assert_eq!(key["workspace_id"], workspace_id.to_string());
        assert_eq!(revocation["workspace_id"], workspace_id.to_string());
    }

    #[test]
    fn object_query_closure_ignores_nested_release_id_content() {
        let selected = "019c0000-0000-7000-8000-000000000021"
            .parse::<ReleaseId>()
            .unwrap();
        let other = "019c0000-0000-7000-8000-000000000022";
        let result = serde_json::json!({
            "release_id": selected.to_string(),
            "objects": [
                {
                    "canonical_content": {
                        "release_id": "not-a-release-id",
                        "nested": {"release_id": other}
                    }
                },
                {"release_id": other}
            ]
        });

        assert_eq!(
            object_query_release_closure_root(&result).unwrap(),
            selected
        );

        let nested_only = serde_json::json!({
            "objects": [{"release_id": other}]
        });
        assert!(matches!(
            object_query_release_closure_root(&nested_only),
            Err(AuthorityEvidenceExportError::InvalidBundle(detail))
                if detail == "localized result lacks release_id"
        ));
    }

    fn evidence_fixture_id(value: u64) -> String {
        format!("019e0000-0000-7000-8000-{value:012x}")
    }

    fn evidence_fixture_key(value: u64) -> IdempotencyKey {
        evidence_fixture_id(value).parse().unwrap()
    }

    fn add_test_seconds(timestamp: Timestamp, seconds: i64) -> Timestamp {
        Timestamp::from_unix_timestamp_nanos(
            timestamp.unix_timestamp_nanos() + i128::from(seconds) * 1_000_000_000,
        )
        .unwrap()
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the v1 baseline keeps the real source-to-Release prerequisites explicit"
    )]
    fn prepare_external_commitment_baseline(
        repository: &LocalWorkspace,
        object_id: ObjectId,
        schema_id: &SchemaId,
    ) -> (ReleaseId, proof_application::ContentDigest) {
        let source = serde_json::json!({
            "legal": "Standard terms apply",
            "slug": "summer-campaign",
            "title": "Summer campaign",
        });
        let changeset_id = evidence_fixture_id(0x20).parse().unwrap();
        create_changeset(
            repository,
            CreateChangeSetCommand {
                changeset_id,
                intent: ChangeSetIntent::new("Create the pre-v14 export source").unwrap(),
                requested_base_state: None,
                idempotency_key: evidence_fixture_key(0x21),
                created_at: "2026-08-20T10:00:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        let schema_version = SchemaVersion::new(1).unwrap();
        let schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "additionalProperties": false,
            "properties": {
                "legal": {"type": "string"},
                "slug": {"type": "string"},
                "title": {"type": "string"},
            },
            "required": ["legal", "slug", "title"],
            "type": "object",
            "x-proof-localizable": ["/legal", "/title"],
        });
        let canonical_schema = canonicalize(&schema).unwrap();
        let canonical_source = canonicalize(&source).unwrap();
        let source_digest =
            object_revision_digest(object_id, schema_id, schema_version, &source).unwrap();
        add_changeset_edits(
            repository,
            AddChangeSetEditsCommand {
                changeset_id,
                edits: vec![
                    ChangeSetEdit::SchemaCreate(SchemaCreateEdit {
                        edit_id: evidence_fixture_id(0x22).parse().unwrap(),
                        schema_id: schema_id.clone(),
                        schema_version,
                        canonical_document: canonical_schema.as_str().to_owned(),
                        document_digest: canonical_digest(
                            ArtifactKind::SchemaVersionV1,
                            &canonical_schema,
                        ),
                    }),
                    ChangeSetEdit::ObjectCreate(ObjectCreateEdit {
                        edit_id: evidence_fixture_id(0x23).parse().unwrap(),
                        object_id,
                        schema_id: schema_id.clone(),
                        schema_version,
                        canonical_content: canonical_source.as_str().to_owned(),
                        object_digest: source_digest,
                    }),
                ],
                idempotency_key: evidence_fixture_key(0x24),
            },
        )
        .unwrap();
        assert!(validate_changeset(repository, changeset_id).unwrap().valid);
        submit_changeset(
            repository,
            SubmitChangeSetCommand {
                changeset_id,
                submitted_at: "2026-08-20T10:01:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        approve_changeset(
            repository,
            ApproveChangeSetCommand {
                changeset_id,
                approval: ApprovalName::new("editorial").unwrap(),
                approved_at: "2026-08-20T10:02:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        commit_changeset(
            repository,
            CommitChangeSetCommand {
                changeset_id,
                idempotency_key: evidence_fixture_key(0x25),
                committed_at: "2026-08-20T10:03:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        let edition_id = evidence_fixture_id(0x26).parse().unwrap();
        create_edition(
            repository,
            CreateEditionCommand {
                edition_id,
                idempotency_key: evidence_fixture_key(0x27),
                created_at: "2026-08-20T10:04:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        create_environment(
            repository,
            CreateEnvironmentCommand {
                environment_id: "preview".parse().unwrap(),
                target_kind: "proof.local/released-state/v1".to_owned(),
                policy_profile: "proof.local/release-policy/v1".to_owned(),
                required_approval: ApprovalName::new("editorial").unwrap(),
                idempotency_key: evidence_fixture_key(0x28),
                created_at: "2026-08-20T10:05:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        let release_id = evidence_fixture_id(0x29).parse::<ReleaseId>().unwrap();
        promote_release(
            repository,
            PromoteReleaseCommand {
                release_id,
                proof_id: evidence_fixture_id(0x2a).parse::<ProofId>().unwrap(),
                environment_id: "preview".parse().unwrap(),
                edition_id,
                idempotency_key: evidence_fixture_key(0x2b),
                released_at: "2026-08-20T10:06:00Z".parse().unwrap(),
            },
        )
        .unwrap();
        (release_id, source_digest)
    }

    struct EvidenceAgent {
        principal_id: PrincipalId,
        binding_id: proof_application::BindingId,
        signer: Ed25519SigningProvider,
    }

    fn enroll_external_commitment_agent(
        repository: &LocalWorkspace,
        workspace_id: WorkspaceId,
        human_principal_id: PrincipalId,
        base_time: Timestamp,
    ) -> EvidenceAgent {
        let principal_id = evidence_fixture_id(0x80).parse().unwrap();
        let binding_id = evidence_fixture_id(0x81).parse().unwrap();
        create_agent_principal(
            repository,
            CreateAgentPrincipalCommand {
                principal_id,
                display_name: "pre-v14-export-agent".to_owned(),
                idempotency_key: evidence_fixture_key(0x82),
                created_at: add_test_seconds(base_time, 1),
            },
        )
        .unwrap();
        let signer = Ed25519SigningProvider::from_secret_bytes(&[0x42; 32]);
        let metadata = signer.metadata().unwrap();
        let key_id = Ed25519KeyId::new(metadata.key_id).unwrap();
        let challenge = BindingEnrollmentChallengeV1 {
            api_version: EnrollmentChallengeApiVersion::V1,
            challenge_id: evidence_fixture_id(0x83).parse().unwrap(),
            audience: AuthorityAudience::for_workspace(workspace_id),
            workspace_id,
            binding_id,
            principal_id,
            candidate_key_id: key_id.clone(),
            issued_by_principal_id: human_principal_id,
            issued_at: add_test_seconds(base_time, 20),
            expires_at: add_test_seconds(base_time, 320),
        };
        let recorded = repository
            .create_binding_enrollment_challenge(challenge.clone())
            .unwrap();
        let enrollment = sign_authority_payload(
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            &challenge,
            &[&signer],
        )
        .unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .issue_principal_binding(
                PrincipalBindingV1 {
                    api_version: PrincipalBindingApiVersion::V1,
                    authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                    previous_authority_record_digest: Some(head.record_digest),
                    workspace_id,
                    binding_id,
                    principal_id,
                    principal_type: AgentPrincipalType::Agent,
                    authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&key_id),
                    algorithm: Ed25519Algorithm::Ed25519,
                    public_key: Ed25519PublicKey::new(BASE64.encode(metadata.public_key)).unwrap(),
                    key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                    audience: AuthorityAudience::for_workspace(workspace_id),
                    enrollment_challenge_digest: recorded.challenge_digest,
                    enrollment_envelope_digest: enrollment.envelope_digest,
                    issued_by_principal_id: human_principal_id,
                    issued_at: add_test_seconds(base_time, 21),
                    not_before: add_test_seconds(base_time, 21),
                    expires_at: add_test_seconds(base_time, 3_600),
                    supersedes_binding_id: None,
                },
                enrollment.envelope_json,
            )
            .unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .set_principal_status(PrincipalStatusV1 {
                api_version: PrincipalStatusApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                workspace_id,
                principal_id,
                principal_type: AuthorityPrincipalType::Agent,
                enabled: true,
                recorded_by_principal_id: human_principal_id,
                recorded_at: add_test_seconds(base_time, 22),
            })
            .unwrap();
        EvidenceAgent {
            principal_id,
            binding_id,
            signer,
        }
    }

    struct PreV14ExportFixture {
        _directory: TestDirectory,
        repository: LocalWorkspace,
        release_id: ReleaseId,
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the fixture creates one real localized Release then authenticates its exact replay"
    )]
    fn prepare_pre_v14_export_fixture() -> PreV14ExportFixture {
        let directory = TestDirectory::new();
        let base_time = "2026-08-21T12:00:00Z".parse::<Timestamp>().unwrap();
        let repository = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            DeterministicLocalAuthorityAdapter::new(
                2_006,
                add_test_seconds(base_time, 30),
                [0x76; 32],
            ),
        )
        .unwrap();
        let workspace_id = evidence_fixture_id(1).parse::<WorkspaceId>().unwrap();
        let human_principal_id = evidence_fixture_id(2).parse::<PrincipalId>().unwrap();
        initialize_workspace(
            &repository,
            InitializeWorkspaceCommand {
                workspace_id,
                bootstrap_principal_id: human_principal_id,
            },
        )
        .unwrap();
        let object_id = evidence_fixture_id(0x30).parse::<ObjectId>().unwrap();
        let schema_id = SchemaId::new("campaign").unwrap();
        let schema_version = SchemaVersion::new(1).unwrap();
        let (base_release_id, source_digest) =
            prepare_external_commitment_baseline(&repository, object_id, &schema_id);
        let intent = repository
            .issue_content_resource_intent(IssueContentResourceIntentCommand {
                intent_id: evidence_fixture_id(0x40).parse().unwrap(),
                environment_id: "preview".parse().unwrap(),
                targets: vec![LocalizedContentTarget {
                    object_id,
                    schema_id: schema_id.clone(),
                    locale: "fr-FR".parse::<LocaleId>().unwrap(),
                }],
                idempotency_key: evidence_fixture_key(0x41),
                issued_at: add_test_seconds(base_time, 8),
            })
            .unwrap();
        let context = repository
            .build_localized_context(BuildLocalizedContextCommand {
                context_pack_id: evidence_fixture_id(0x42).parse().unwrap(),
                resource_intent_id: intent.intent_id,
                resource_intent_digest: intent.intent_digest,
                policy_rules: Vec::new(),
                limits: LocalizedContextLimits {
                    max_objects: 1,
                    max_edits: 1,
                    max_validation_attempts: 1,
                    max_bytes: 65_536,
                },
                idempotency_key: evidence_fixture_key(0x43),
                created_at: add_test_seconds(base_time, 10),
                expires_at: add_test_seconds(base_time, 3_600),
            })
            .unwrap();
        let agent = enroll_external_commitment_agent(
            &repository,
            workspace_id,
            human_principal_id,
            base_time,
        );
        let delegation_id = evidence_fixture_id(0x84).parse().unwrap();
        let head = repository.authority_head(workspace_id).unwrap().unwrap();
        repository
            .issue_delegation(DelegationV2 {
                api_version: DelegationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(head.sequence.get() + 1).unwrap(),
                previous_authority_record_digest: Some(head.record_digest),
                delegation_id,
                workspace_id,
                delegation_profile: DirectAuthorityProfileV1::Direct,
                issuer_principal_id: human_principal_id,
                recipient_principal_id: agent.principal_id,
                actions: DelegationActionsV2::new(vec![AuthorityAction::ReleaseCreate]).unwrap(),
                scope: DelegationScopeV2 {
                    environment_ids: DelegationEnvironmentIdsV2::new(vec![
                        "preview".parse().unwrap(),
                    ])
                    .unwrap(),
                    object_ids: DelegationObjectIdsV2::new(vec![object_id]).unwrap(),
                    schema_ids: DelegationSchemaIdsV2::new(vec![schema_id.clone()]).unwrap(),
                    locales: DelegationLocalesV2::new(vec!["fr-FR".parse().unwrap()]).unwrap(),
                },
                constraints: DelegationConstraintsV2 {
                    max_objects: MaxObjects::new(1).unwrap(),
                    max_context_bytes: MaxContextBytes::new(65_536).unwrap(),
                    max_edits_per_changeset: MaxEditsPerChangeSet::new(1).unwrap(),
                    allow_subdelegation: SubdelegationDisabled,
                },
                not_before: add_test_seconds(base_time, 23),
                expires_at: add_test_seconds(base_time, 3_600),
                issued_at: add_test_seconds(base_time, 23),
            })
            .unwrap();

        let localized_changeset_id = evidence_fixture_id(0x50).parse().unwrap();
        let changeset = repository
            .create_localized_changeset(CreateLocalizedChangeSetCommand {
                changeset_id: localized_changeset_id,
                intent: ChangeSetIntent::new("Create one French rendition").unwrap(),
                resource_intent_id: intent.intent_id,
                resource_intent_digest: intent.intent_digest,
                context_pack_id: context.context_pack_id,
                context_pack_digest: context.context_pack_digest,
                idempotency_key: evidence_fixture_key(0x51),
                created_at: add_test_seconds(base_time, 40),
            })
            .unwrap();
        let localized = canonicalize(&serde_json::json!({
            "legal": "Des conditions standard s’appliquent",
            "slug": "summer-campaign",
            "title": "Campagne d’été",
        }))
        .unwrap();
        repository
            .add_localized_edits(AddLocalizedEditsCommand {
                changeset_id: changeset.changeset_id,
                edits: vec![ObjectLocalePutInput {
                    object_id,
                    locale: "fr-FR".parse().unwrap(),
                    expected_source: ExpectedLocalizedSource {
                        revision: ObjectRevision::INITIAL,
                        digest: source_digest,
                        schema_id: schema_id.clone(),
                        schema_version,
                    },
                    expected_target: None,
                    canonical_content: localized.as_str().to_owned(),
                    supersedes_edit_id: None,
                    repair_of_validation_result_digest: None,
                }],
                assigned_edit_ids: vec![evidence_fixture_id(0x52).parse().unwrap()],
                idempotency_key: evidence_fixture_key(0x53),
            })
            .unwrap();
        assert!(
            repository
                .validate_localized_changeset(changeset.changeset_id)
                .unwrap()
                .valid
        );
        repository
            .submit_localized_changeset(changeset.changeset_id, add_test_seconds(base_time, 60))
            .unwrap();
        repository
            .approve_localized_changeset(
                changeset.changeset_id,
                ApprovalName::new("editorial").unwrap(),
                add_test_seconds(base_time, 70),
            )
            .unwrap();
        let committed = repository
            .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                changeset_id: changeset.changeset_id,
                idempotency_key: evidence_fixture_key(0x54),
                committed_at: add_test_seconds(base_time, 80),
            })
            .unwrap();
        let edition_id = evidence_fixture_id(0x55).parse().unwrap();
        repository
            .create_localized_edition(CreateLocalizedEditionCommand {
                edition_id,
                changeset_id: changeset.changeset_id,
                resulting_state_digest: committed.resulting_state.digest,
                idempotency_key: evidence_fixture_key(0x56),
                created_at: add_test_seconds(base_time, 90),
            })
            .unwrap();
        let release_id = evidence_fixture_id(0x57).parse::<ReleaseId>().unwrap();
        let proof_id = evidence_fixture_id(0x58).parse::<ProofId>().unwrap();
        let release_key = evidence_fixture_key(0x59);
        let normalized_input = serde_json::json!({
            "api_version": "proof.dev/operation/release.create/v2",
            "edition_id": edition_id.to_string(),
            "environment_id": "preview",
            "expected_base_release_id": base_release_id.to_string(),
            "idempotency_key": release_key.to_string(),
            "proof_id": proof_id.to_string(),
            "release_id": release_id.to_string(),
            "released_at": add_test_seconds(base_time, 100).to_string(),
        });
        let mut command_input = CommandInputV1 {
            api_version: CommandInputApiVersion::V1,
            workspace_id,
            operation: AuthorityOperation::ReleaseCreateV2,
            requesting_principal_id: human_principal_id,
            operating_principal_id: agent.principal_id,
            delegation_id,
            idempotency_key: Some(release_key),
            normalized_input: normalized_input.as_object().unwrap().clone(),
        };
        command_input
            .normalize_for_authenticated_execution()
            .unwrap();
        let command_json = canonicalize(&serde_json::to_value(&command_input).unwrap()).unwrap();
        let command = AuthenticatedCommandV1 {
            api_version: AuthenticatedCommandApiVersion::V1,
            audience: AuthorityAudience::for_workspace(workspace_id),
            workspace_id,
            operation: AuthorityOperation::ReleaseCreateV2,
            binding_id: agent.binding_id,
            requesting_principal_id: human_principal_id,
            operating_principal_id: agent.principal_id,
            delegation_id,
            command_digest: canonical_digest(ArtifactKind::CommandV1, &command_json),
            idempotency_key: Some(release_key),
            presentation_id: evidence_fixture_id(0x90).parse().unwrap(),
            issued_at: add_test_seconds(base_time, 115),
            expires_at: add_test_seconds(base_time, 240),
        };
        let envelope = sign_authority_payload(
            AuthorityPayloadProfile::AuthenticatedCommand,
            &command,
            &[&agent.signer],
        )
        .unwrap();
        let execution = repository
            .execute_authenticated(
                AuthenticatedInvocationV1 {
                    api_version: AuthenticatedInvocationApiVersion::V1,
                    command_input,
                    authentication: AuthenticatedCommandEnvelopeJson::new(envelope.envelope_json)
                        .unwrap(),
                },
                add_test_seconds(base_time, 120),
            )
            .unwrap();
        execution.validate().unwrap();
        assert_eq!(
            execution.decision.operation,
            AuthorityOperation::ReleaseCreateV2
        );
        PreV14ExportFixture {
            _directory: directory,
            repository,
            release_id,
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the retained downgrade fixture keeps migration and exported-evidence assertions together"
    )]
    fn pre_v14_export_marks_missing_historical_presentations_external() {
        let fixture = prepare_pre_v14_export_fixture();
        let connection = fixture.repository.open_database().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM authenticated_command_presentations_v1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let v1_statement: String = connection
            .query_row(
                "SELECT proof.statement_json
                 FROM release_proofs AS proof
                 JOIN releases AS release ON release.release_id = proof.release_id
                 WHERE release.api_version = 'proof.dev/release/v1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let v1_statement = parse_strict(v1_statement.as_bytes()).unwrap();
        let v1_base_state = v1_statement
            .pointer("/predicate/origin/base_state")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        connection
            .execute_batch(
                "DROP TRIGGER authorization_decision_requires_command_presentation;
                 DROP TABLE authenticated_command_presentations_v1;
                 DROP TABLE authenticated_command_presentation_cutover_v1;
                 DELETE FROM schema_migrations WHERE version = 14;
                 UPDATE workspace_metadata SET schema_version = 13 WHERE singleton = 1;
                 PRAGMA user_version = 13;",
            )
            .unwrap();
        drop(connection);

        let exported = fixture
            .repository
            .export_authority_evidence_bundle(ExportAuthorityEvidenceBundleV1Command {
                release_id: fixture.release_id,
                subject_opening: SubjectOpeningDisclosureV1::Withhold,
            })
            .unwrap();

        let v1_base_state_descriptor = exported
            .bundle
            .artifacts
            .iter()
            .find(|descriptor| {
                descriptor.role == EvidenceRoleV1::KnownState
                    && descriptor.artifact.artifact_kind == ArtifactKind::KnownStateV1
                    && descriptor.artifact.digest.to_string() == v1_base_state
            })
            .expect("the signed v1 Proof origin base Known State must be exported");
        assert!(matches!(
            v1_base_state_descriptor.availability,
            EvidenceAvailabilityV1::Included { .. }
        ));
        assert!(
            exported
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact == v1_base_state_descriptor.artifact)
        );

        let presentation_descriptors = exported
            .bundle
            .artifacts
            .iter()
            .filter(|descriptor| {
                matches!(
                    descriptor.role,
                    EvidenceRoleV1::CommandInput | EvidenceRoleV1::AuthenticatedCommandEnvelope
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(presentation_descriptors.len(), 2);
        assert!(
            [
                EvidenceRoleV1::CommandInput,
                EvidenceRoleV1::AuthenticatedCommandEnvelope,
            ]
            .into_iter()
            .all(|role| presentation_descriptors
                .iter()
                .any(|descriptor| descriptor.role == role))
        );
        assert!(presentation_descriptors.iter().all(|descriptor| matches!(
            descriptor.availability,
            EvidenceAvailabilityV1::ExternalCommitment
        )));
        assert!(presentation_descriptors.iter().all(|descriptor| {
            !exported
                .artifacts
                .iter()
                .any(|artifact| artifact.artifact == descriptor.artifact)
        }));
        let migrated = fixture.repository.open_database().unwrap();
        assert_eq!(
            migrated
                .query_row(
                    "SELECT schema_version FROM workspace_metadata WHERE singleton = 1",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT COUNT(*) FROM authenticated_command_presentations_v1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0,
            "v13-to-v14 migration must not fabricate historical presentation bytes"
        );
    }

    fn canonical_fixture(kind: ArtifactKind, value: &serde_json::Value) -> (String, String) {
        let canonical = canonicalize(value).unwrap();
        let digest = canonical_digest(kind, &canonical).to_string();
        (canonical.as_str().to_owned(), digest)
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the hostile closure fixture keeps all signed preimages visible in one regression"
    )]
    fn failure_consequence_collects_context_build_signed_closure_preimages() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE content_resource_intents (
                     intent_id TEXT PRIMARY KEY,
                     workspace_id TEXT NOT NULL,
                     manifest_json TEXT NOT NULL,
                     intent_digest TEXT NOT NULL
                 );
                 CREATE TABLE localized_context_packs (
                     context_pack_id TEXT PRIMARY KEY,
                     workspace_id TEXT NOT NULL,
                     manifest_json TEXT NOT NULL,
                     context_pack_digest TEXT NOT NULL,
                     policy_json TEXT NOT NULL,
                     policy_digest TEXT NOT NULL
                 );",
            )
            .unwrap();
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let intent_id = "019c0000-0000-7000-8000-000000000031";
        let context_id = "019c0000-0000-7000-8000-000000000032";
        let (intent_json, intent_digest) = canonical_fixture(
            ArtifactKind::ContentResourceIntentV1,
            &serde_json::json!({
                "api_version": "proof.dev/content-resource-intent/v1",
                "fixture": "signed failure resource Intent",
                "intent_id": intent_id,
                "workspace_id": workspace_id.to_string(),
            }),
        );
        let (context_json, context_digest) = canonical_fixture(
            ArtifactKind::ContextPackV2,
            &serde_json::json!({
                "api_version": "proof.dev/context-pack/v2",
                "context_pack_id": context_id,
                "fixture": "signed failure ContextPack",
                "workspace_id": workspace_id.to_string(),
            }),
        );
        let (policy_json, policy_digest) = canonical_fixture(
            ArtifactKind::PolicyBundleV1,
            &serde_json::json!({
                "api_version": "proof.dev/policy-bundle/v1",
                "fixture": "signed failure context policy",
            }),
        );
        connection
            .execute(
                "INSERT INTO content_resource_intents
                 (intent_id, workspace_id, manifest_json, intent_digest)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    intent_id,
                    workspace_id.to_string(),
                    intent_json,
                    intent_digest,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO localized_context_packs
                 (context_pack_id, workspace_id, manifest_json, context_pack_digest,
                  policy_json, policy_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    context_id,
                    workspace_id.to_string(),
                    context_json,
                    context_digest,
                    policy_json,
                    policy_digest,
                ],
            )
            .unwrap();
        let evidence = canonicalize(&serde_json::json!({
            "closure": {
                "approval": null,
                "changeset": null,
                "context": {
                    "context_pack_digest": context_digest,
                    "context_pack_id": context_id,
                    "limits": {
                        "max_bytes": 1024,
                        "max_edits": 1,
                        "max_objects": 1,
                        "max_validation_attempts": 1,
                    },
                    "policy_digest": policy_digest,
                },
                "context_fresh": true,
                "resource_intent": {
                    "intent_digest": intent_digest,
                    "intent_id": intent_id,
                    "issued_by_principal_id": "019c0000-0000-7000-8000-000000000002",
                },
                "validator": proof_application::LOCALIZED_CONTENT_VALIDATOR,
            }
        }))
        .unwrap();
        let consequence = StoredConsequence {
            result_kind: "failure".to_owned(),
            application_idempotency_key: None,
            result_json: r#"{"error":"dependency_unavailable"}"#.to_owned(),
            result_digest: "unused-result-digest".to_owned(),
            application_effect_digest: "unused-effect-digest".to_owned(),
            evidence_json: evidence.as_str().to_owned(),
        };
        let mut collector = ArtifactCollector::default();

        collect_signed_consequence_closure(&connection, workspace_id, &consequence, &mut collector)
            .unwrap();

        let (descriptors, artifacts) = collector.finish();
        let roles = descriptors
            .into_iter()
            .map(|descriptor| descriptor.role)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            roles,
            BTreeSet::from([
                EvidenceRoleV1::ContextPack,
                EvidenceRoleV1::ContextPolicyBundle,
                EvidenceRoleV1::ResourceIntent,
            ])
        );
        let bytes = artifacts
            .into_iter()
            .map(|artifact| artifact.canonical_json)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(bytes.contains("signed failure resource Intent"));
        assert!(bytes.contains("signed failure ContextPack"));
        assert!(bytes.contains("signed failure context policy"));
    }

    fn create_release_closure_fixture_schema(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE releases (
                     release_id TEXT PRIMARY KEY,
                     release_sequence INTEGER NOT NULL,
                     workspace_id TEXT NOT NULL,
                     api_version TEXT NOT NULL,
                     previous_release_id TEXT,
                     rollback_target_release_id TEXT,
                     edition_id TEXT NOT NULL,
                     environment_id TEXT NOT NULL,
                     environment_config_version INTEGER NOT NULL,
                     policy_decision_digest TEXT NOT NULL,
                     manifest_json TEXT NOT NULL,
                     release_digest TEXT NOT NULL
                 );
                 CREATE TABLE release_proofs (
                     release_id TEXT PRIMARY KEY,
                     envelope_json TEXT NOT NULL,
                     proof_digest TEXT NOT NULL,
                     key_id TEXT NOT NULL
                 );
                 CREATE TABLE release_policy_decisions (
                     decision_digest TEXT PRIMARY KEY,
                     environment_id TEXT NOT NULL,
                     environment_config_version INTEGER NOT NULL,
                     decision_json TEXT NOT NULL
                 );
                 CREATE TABLE environment_versions (
                     environment_id TEXT NOT NULL,
                     config_version INTEGER NOT NULL,
                     manifest_json TEXT NOT NULL,
                     config_digest TEXT NOT NULL,
                     policy_json TEXT NOT NULL,
                     policy_digest TEXT NOT NULL,
                     PRIMARY KEY (environment_id, config_version)
                 );
                 CREATE TABLE signing_keys (
                     key_id TEXT PRIMARY KEY,
                     algorithm TEXT NOT NULL,
                     public_key TEXT NOT NULL,
                     trust_profile TEXT NOT NULL,
                     not_before TEXT NOT NULL,
                     metadata_json TEXT NOT NULL,
                     metadata_digest TEXT NOT NULL
                 );
                 CREATE TABLE signing_key_revocations (
                     key_id TEXT PRIMARY KEY,
                     revoked_at TEXT NOT NULL,
                     reason TEXT NOT NULL,
                     revocation_json TEXT NOT NULL,
                     revocation_digest TEXT NOT NULL
                 );",
            )
            .unwrap();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the bounded Release graph fixture makes every exporter preimage explicit"
    )]
    fn insert_v1_release_closure_fixture(
        connection: &Connection,
        workspace_id: WorkspaceId,
        release_id: &str,
        sequence: i64,
        previous_release_id: Option<&str>,
        environment_id: &str,
    ) {
        let edition_id = format!("edition-{release_id}");
        let key_id = format!("key-{release_id}");
        let (manifest_json, release_digest) = canonical_fixture(
            ArtifactKind::ReleaseV1,
            &serde_json::json!({
                "api_version": "proof.dev/release/v1",
                "environment_id": environment_id,
                "release_id": release_id,
            }),
        );
        let (proof_json, proof_digest) = canonical_fixture(
            ArtifactKind::ProofEnvelopeV1,
            &serde_json::json!({
                "api_version": "proof.dev/proof-envelope/v1",
                "release_id": release_id,
            }),
        );
        let (decision_json, decision_digest) = canonical_fixture(
            ArtifactKind::AuthorizationDecisionV1,
            &serde_json::json!({
                "allowed": true,
                "api_version": "proof.dev/release-authorization-decision/v1",
                "environment_id": environment_id,
                "release_id": release_id,
            }),
        );
        let (environment_json, environment_digest) = canonical_fixture(
            ArtifactKind::EnvironmentConfigV1,
            &serde_json::json!({
                "api_version": "proof.dev/environment-config/v1",
                "environment_id": environment_id,
                "release_fixture": release_id,
            }),
        );
        let (policy_json, policy_digest) = canonical_fixture(
            ArtifactKind::PolicyBundleV1,
            &serde_json::json!({
                "api_version": "proof.dev/policy-bundle/v1",
                "environment_id": environment_id,
            }),
        );
        let metadata_json = canonicalize(&serde_json::json!({
            "api_version": "proof.dev/signing-key-metadata/v1",
            "key_id": key_id,
        }))
        .unwrap();
        connection
            .execute(
                "INSERT INTO releases
                 (release_id, release_sequence, workspace_id, api_version,
                  previous_release_id, rollback_target_release_id, edition_id,
                  environment_id, environment_config_version, policy_decision_digest,
                  manifest_json, release_digest)
                 VALUES (?1, ?2, ?3, 'proof.dev/release/v1', ?4, NULL, ?5, ?6, ?7,
                         ?8, ?9, ?10)",
                params![
                    release_id,
                    sequence,
                    workspace_id.to_string(),
                    previous_release_id,
                    edition_id,
                    environment_id,
                    sequence,
                    decision_digest,
                    manifest_json,
                    release_digest,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO release_proofs
                 (release_id, envelope_json, proof_digest, key_id)
                 VALUES (?1, ?2, ?3, ?4)",
                params![release_id, proof_json, proof_digest, key_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO release_policy_decisions
                 (decision_digest, environment_id, environment_config_version, decision_json)
                 VALUES (?1, ?2, ?3, ?4)",
                params![decision_digest, environment_id, sequence, decision_json],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO environment_versions
                 (environment_id, config_version, manifest_json, config_digest,
                  policy_json, policy_digest)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    environment_id,
                    sequence,
                    environment_json,
                    environment_digest,
                    policy_json,
                    policy_digest,
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO signing_keys
                 (key_id, algorithm, public_key, trust_profile, not_before,
                  metadata_json, metadata_digest)
                 VALUES (?1, 'ed25519', ?2, 'proof.local/release-proof/v1',
                         '2026-08-21T12:00:00Z', ?3, ?4)",
                params![
                    key_id,
                    "11".repeat(32),
                    metadata_json.as_str(),
                    format!("blake3:{}", "22".repeat(32)),
                ],
            )
            .unwrap();
    }

    #[test]
    fn target_release_closure_excludes_earlier_unrelated_environment() {
        let connection = Connection::open_in_memory().unwrap();
        create_release_closure_fixture_schema(&connection);
        let workspace_id = "019c0000-0000-7000-8000-000000000001"
            .parse::<WorkspaceId>()
            .unwrap();
        let ancestor = "019c0000-0000-7000-8000-000000000041";
        let unrelated = "019c0000-0000-7000-8000-000000000042";
        let target = "019c0000-0000-7000-8000-000000000043";
        insert_v1_release_closure_fixture(
            &connection,
            workspace_id,
            ancestor,
            1,
            None,
            "target-environment",
        );
        insert_v1_release_closure_fixture(
            &connection,
            workspace_id,
            unrelated,
            2,
            None,
            "unrelated-environment",
        );
        insert_v1_release_closure_fixture(
            &connection,
            workspace_id,
            target,
            3,
            Some(ancestor),
            "target-environment",
        );
        let mut collector = ArtifactCollector::default();

        let closure = collect_release_closure(
            &connection,
            workspace_id,
            target.parse::<ReleaseId>().unwrap(),
            &mut collector,
        )
        .unwrap();

        assert_eq!(
            closure
                .entries
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![ancestor, target]
        );
        let materialized = collector
            .finish()
            .1
            .into_iter()
            .map(|artifact| artifact.canonical_json)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!materialized.contains(unrelated));
        assert!(!materialized.contains("unrelated-environment"));
    }

    fn hash_query(connection: &Connection, sql: &str, hasher: &mut blake3::Hasher) {
        let mut statement = connection.prepare(sql).unwrap();
        let column_count = statement.column_count();
        let mut rows = statement.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            hasher.update(b"row");
            for index in 0..column_count {
                match row.get_ref(index).unwrap() {
                    ValueRef::Null => {
                        hasher.update(b"null");
                    }
                    ValueRef::Integer(value) => {
                        hasher.update(b"integer");
                        hasher.update(&value.to_le_bytes());
                    }
                    ValueRef::Real(value) => {
                        hasher.update(b"real");
                        hasher.update(&value.to_bits().to_le_bytes());
                    }
                    ValueRef::Text(value) => {
                        hasher.update(b"text");
                        hasher.update(&(value.len() as u64).to_le_bytes());
                        hasher.update(value);
                    }
                    ValueRef::Blob(value) => {
                        hasher.update(b"blob");
                        hasher.update(&(value.len() as u64).to_le_bytes());
                        hasher.update(value);
                    }
                }
            }
        }
    }

    fn full_database_fingerprint(workspace: &LocalWorkspace) -> blake3::Hash {
        let connection = workspace.open_database().unwrap();
        let mut hasher = blake3::Hasher::new_derive_key("proof:p0006:no-write-auth:v1");
        hash_query(
            &connection,
            "SELECT type, name, tbl_name, rootpage, sql
             FROM sqlite_schema ORDER BY type, name",
            &mut hasher,
        );
        hash_query(
            &connection,
            "SELECT user_version FROM pragma_user_version",
            &mut hasher,
        );
        let table_names = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        for table in table_names {
            hasher.update(table.as_bytes());
            let identifier = table.replace('"', "\"\"");
            hash_query(
                &connection,
                &format!("SELECT * FROM \"{identifier}\" ORDER BY rowid"),
                &mut hasher,
            );
            let literal = table.replace('\'', "''");
            hash_query(
                &connection,
                &format!("SELECT * FROM pragma_foreign_key_list('{literal}') ORDER BY id, seq"),
                &mut hasher,
            );
        }
        hash_query(&connection, "PRAGMA foreign_key_check", &mut hasher);
        hasher.finalize()
    }

    #[test]
    fn wrong_uid_is_denied_before_v13_migration_and_cannot_disclose_subject_opening() {
        let directory = TestDirectory::new();
        let authorized = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            deterministic_adapter(1000),
        )
        .unwrap();
        initialize_workspace(
            &authorized,
            InitializeWorkspaceCommand {
                workspace_id: "019c0000-0000-7000-8000-000000000001"
                    .parse::<WorkspaceId>()
                    .unwrap(),
                bootstrap_principal_id: "019c0000-0000-7000-8000-000000000002"
                    .parse::<PrincipalId>()
                    .unwrap(),
            },
        )
        .unwrap();
        authorized
            .open_database()
            .unwrap()
            .execute_batch(
                "DROP TRIGGER authorization_decision_requires_command_presentation;
                 DROP TABLE authenticated_command_presentations_v1;
                 DROP TABLE authenticated_command_presentation_cutover_v1;
                 DELETE FROM schema_migrations WHERE version = 14;
                 UPDATE workspace_metadata SET schema_version = 13 WHERE singleton = 1;
                 PRAGMA user_version = 13;",
            )
            .unwrap();
        let before = full_database_fingerprint(&authorized);
        let unauthorized = LocalWorkspace::with_deterministic_authority_adapter(
            directory.path(),
            deterministic_adapter(2000),
        )
        .unwrap();

        let result =
            unauthorized.export_authority_evidence_bundle(ExportAuthorityEvidenceBundleV1Command {
                release_id: "019c0000-0000-7000-8000-000000000099"
                    .parse::<ReleaseId>()
                    .unwrap(),
                subject_opening: SubjectOpeningDisclosureV1::Include,
            });

        assert_eq!(
            result.unwrap_err(),
            AuthorityEvidenceExportError::AccessDenied
        );
        assert_eq!(full_database_fingerprint(&authorized), before);
        let versions: (u32, u32, u32) = authorized
            .open_database()
            .unwrap()
            .query_row(
                "SELECT schema_version, (SELECT MAX(version) FROM schema_migrations),
                        (SELECT user_version FROM pragma_user_version)
                 FROM workspace_metadata WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(versions, (13, 13, 13));
    }
}
