#![allow(
    clippy::too_many_lines,
    reason = "the independent fixture keeps every signed and content-addressed preimage explicit"
)]
#![allow(
    dead_code,
    reason = "the shared fixture exposes mutations used by separate integration-test binaries"
)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer as _, SigningKey};
use proof_verifier::model::{
    ArtifactDescriptor, ArtifactKind, ArtifactRef, AuthorityHead, AuthorityPrefixEntry,
    Availability, Bundle, DecisionCompanion, Digest, Entrypoints, EvidenceRole, VerificationLimits,
};
use serde::Serialize;
use serde_json::{Value, json};

const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000001";
const HUMAN_ID: &str = "019c0000-0000-7000-8000-000000000002";
const AGENT_ID: &str = "019c0000-0000-7000-8000-000000000003";
const BINDING_ID: &str = "019c0000-0000-7000-8000-000000000004";
const DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000005";
const PRESENTATION_ID: &str = "019c0000-0000-7000-8000-000000000006";
const IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000007";
const CHANGESET_ID: &str = "019c0000-0000-7000-8000-000000000008";
const EDIT_ID: &str = "019c0000-0000-7000-8000-000000000009";
const INTENT_ID: &str = "019c0000-0000-7000-8000-00000000000a";
const CONTEXT_ID: &str = "019c0000-0000-7000-8000-00000000000b";
const BASE_EDITION_ID: &str = "019c0000-0000-7000-8000-00000000000c";
const TARGET_EDITION_ID: &str = "019c0000-0000-7000-8000-00000000000d";
const BASE_RELEASE_ID: &str = "019c0000-0000-7000-8000-00000000000e";
const TARGET_RELEASE_ID: &str = "019c0000-0000-7000-8000-00000000000f";
const PROOF_ID: &str = "019c0000-0000-7000-8000-000000000011";
const BASE_PROOF_ID: &str = "019c0000-0000-7000-8000-000000000012";
const ROLLBACK_RELEASE_ID: &str = "019c0000-0000-7000-8000-000000000013";
const ROLLBACK_PROOF_ID: &str = "019c0000-0000-7000-8000-000000000014";
const ROLLBACK_PRESENTATION_ID: &str = "019c0000-0000-7000-8000-000000000015";
const ROLLBACK_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000016";
const DENIAL_DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000080";
const DENIAL_PRESENTATION_ID: &str = "019c0000-0000-7000-8000-000000000081";
const DENIAL_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000082";
const ROTATED_BINDING_ID: &str = "019c0000-0000-7000-8000-000000000083";
const SECOND_HUMAN_ID: &str = "019c0000-0000-7000-8000-000000000084";
const SECOND_HUMAN_DELEGATION_ID: &str = "019c0000-0000-7000-8000-000000000085";
const DENIAL_RELEASE_ID: &str = "019c0000-0000-7000-8000-000000000086";
const DENIAL_PROOF_ID: &str = "019c0000-0000-7000-8000-000000000087";
const DENIAL_REVOCATION_ID: &str = "019c0000-0000-7000-8000-000000000088";
const V1_GENESIS_EDITION_ID: &str = "019c0000-0000-7000-8000-000000000089";
const V1_GENESIS_RELEASE_ID: &str = "019c0000-0000-7000-8000-00000000008a";
const V1_GENESIS_PROOF_ID: &str = "019c0000-0000-7000-8000-00000000008b";
const V1_CHANGESET_ID: &str = "019c0000-0000-7000-8000-00000000008c";
const V1_SCHEMA_EDIT_ID: &str = "019c0000-0000-7000-8000-00000000008d";
const V1_OBJECT_EDIT_ID: &str = "019c0000-0000-7000-8000-00000000008e";
const V1_IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-00000000008f";
const OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000010";
const SCHEMA_ID: &str = "campaign";
const LOCALE: &str = "es-ES";
const ENVIRONMENT_ID: &str = "preview";
const POLICY_PROFILE: &str = "proof.local/authority/direct/v1";
const RELEASE_POLICY_PROFILE: &str = "proof.local/release-policy/v1";
const PREDICATE_TYPE_V1: &str = "urn:proof:attestation:release:v1";
const PREDICATE_TYPE_V2: &str = "urn:proof:attestation:release:v2";
const RELEASE_RESULT_CONTRACT: &str = concat!(
    "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
    "releaseCreateOutput"
);
const T0: &str = "2026-08-21T10:00:00Z";
const V1_CHANGESET_CREATED_AT: &str = "2026-08-21T10:01:00Z";
const V1_SUBMITTED_AT: &str = "2026-08-21T10:02:00Z";
const V1_APPROVED_AT: &str = "2026-08-21T10:03:00Z";
const V1_COMMITTED_AT: &str = "2026-08-21T10:04:00Z";
const V1_RELEASED_AT: &str = "2026-08-21T10:04:00Z";
const SUBMITTED_AT: &str = "2026-08-21T10:05:00Z";
const APPROVED_AT: &str = "2026-08-21T10:06:00Z";
const EVALUATED_AT: &str = "2026-08-21T10:10:00Z";
const AUTHENTICATED_AT: &str = "2026-08-21T10:11:00Z";
const EXPIRES_AT: &str = "2026-08-21T10:15:00Z";
const COMMAND_ISSUED_AT: &str = "2026-08-21T10:10:00Z";
const OBSERVED_AT: &str = "2026-08-21T10:20:00Z";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpeningMode {
    Withhold,
    Include,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureMode {
    Valid,
    CorruptAuthorityDecision,
    CorruptBaseReleaseProof,
    SubstituteBaseReleaseProofSubject,
    RollbackCorruptTargetProof,
    RollbackSubstituteTargetProofSubject,
    PromotionWithRollbackTarget,
    RollbackWithNullTarget,
    RollbackSelectsDifferentEdition,
    RollbackPromotionWorkspaceTamper,
    BasePredicateOriginStateTamper,
    BasePredicateWorkspaceTamper,
    V2PredicateUnknownField,
    HistoricalV2ContentEvidenceUnknownField,
    HistoricalV2ContentBaseUnknownField,
    HistoricalV2ContentChangesetUnknownField,
    HistoricalV2ContentResourceIntentUnknownField,
    HistoricalV2ContentValidationUnknownField,
    HistoricalV2ContentRenditionUnknownField,
    HistoricalV2PredicateTypeV1,
    HistoricalV1PredicateTypeV2,
    OrphanHistoricalV2ApprovalEvidence,
    HistoricalV2DirectHumanNoCompanion,
    NonGenesisV1Constructive,
    NonGenesisV1FabricatedEvidence,
    NonGenesisV1SequenceGap,
    NonGenesisV1ApprovalPrincipalMismatch,
    NonGenesisV1ZeroBasedOrdinals,
    V1InvalidSchemaDocument,
    V1ObjectSchemaMismatch,
    V1EditionUnknownField,
    V1EditionMissingSchemas,
    V1EditionMissingObjectSetDigest,
    V1EditionEmptyObjectsWithDigest,
    V1PolicyDecisionUnknownField,
    V2PolicyDecisionUnknownField,
    EnvironmentUnknownField,
    EnvironmentPolicyUnknownField,
    DistinctHumanApprover,
    DisabledHumanApprover,
    LateEnabledHumanApprover,
    NonHumanApprover,
    DuplicateBaseReleaseProof,
    OrphanReleaseProof,
    BasePolicyDenied,
    PromotionDeltaHitchhike,
    SubstituteBindingSequence,
    SubstituteActorPresentation,
    FutureCausalStatus,
    LaterCausalRevocation,
    RootRotation,
    SubdelegationRecord,
    RollbackRelease,
    RollbackBrokenAncestry,
    WrongDelegationIssuer,
    WrongDelegationRecipient,
    SecondHumanAdmin,
    BindingRotationMissingSupersedes,
    BindingRotationWrongSupersedes,
    BindingRotationSelfSupersedes,
    SupersededBindingDecision,
    DelegationWithoutActiveBinding,
    AuthoritySuccessorReusesBindingKey,
    BindingReusesAuthorityRootKey,
    ReleaseSignerReusesAuthorityRootKey,
    ReleaseSignerReusesBindingKey,
    V2ReleaseBeforeEditionCreatedAt,
    HistoricalV2DistinctAuthorizationTime,
    HistoricalV2ResultProofMetadataMismatch,
    HistoricalV2ResultProofIdMismatch,
    DenialScopeExceeded,
    DenialBudgetExceeded,
    DenialActionExceeded,
    DenialDelegationUnavailable,
    DenialPrincipalDisabled,
    DenialBindingInactive,
    DenialDelegationExpired,
    DenialDelegationNotYetValid,
    DenialRevokedRetry,
    DenialIdempotencyKeyReused,
    DenialIdempotencyExactReplay,
    DenialIdempotencyFreshKey,
    DenialPolicyDenied,
    DenialChainUnsupported,
    DenialWithEffect,
}

fn historical_v2_shape_attack(signature: SignatureMode) -> bool {
    matches!(
        signature,
        SignatureMode::HistoricalV2ContentEvidenceUnknownField
            | SignatureMode::HistoricalV2ContentBaseUnknownField
            | SignatureMode::HistoricalV2ContentChangesetUnknownField
            | SignatureMode::HistoricalV2ContentResourceIntentUnknownField
            | SignatureMode::HistoricalV2ContentValidationUnknownField
            | SignatureMode::HistoricalV2ContentRenditionUnknownField
            | SignatureMode::HistoricalV2PredicateTypeV1
    )
}

fn non_genesis_v1_mode(signature: SignatureMode) -> bool {
    matches!(
        signature,
        SignatureMode::NonGenesisV1Constructive
            | SignatureMode::NonGenesisV1FabricatedEvidence
            | SignatureMode::NonGenesisV1SequenceGap
            | SignatureMode::NonGenesisV1ApprovalPrincipalMismatch
            | SignatureMode::NonGenesisV1ZeroBasedOrdinals
    )
}

fn second_human_approval_mode(signature: SignatureMode) -> bool {
    matches!(
        signature,
        SignatureMode::DistinctHumanApprover
            | SignatureMode::DisabledHumanApprover
            | SignatureMode::LateEnabledHumanApprover
    )
}

fn requires_second_human_status(signature: SignatureMode) -> bool {
    signature == SignatureMode::SecondHumanAdmin
        || second_human_approval_mode(signature)
        || signature == SignatureMode::NonGenesisV1ApprovalPrincipalMismatch
}

pub struct GeneratedFixture {
    directory: TestDirectory,
    pub trust_json: Vec<u8>,
    pub checkpoint_json: Vec<u8>,
    pub bundle_manifest_digest: Digest,
    pub subject_opening: ArtifactRef,
    pub subject_blind: String,
    pub command_input: ArtifactRef,
    pub base_release_origin_state: ArtifactRef,
    pub base_release_manifest: ArtifactRef,
    pub base_release_proof: ArtifactRef,
    pub promotion_release_manifest: ArtifactRef,
    pub promotion_release_proof: ArtifactRef,
    pub target_release_manifest: ArtifactRef,
    pub target_release_proof: ArtifactRef,
}

impl GeneratedFixture {
    pub fn root(&self) -> &Path {
        &self.directory.bundle
    }

    pub fn trust_value(&self) -> Value {
        serde_json::from_slice(&self.trust_json).unwrap()
    }

    pub fn replace_trust(&mut self, value: &Value) {
        self.trust_json = canonical(value);
    }

    pub fn artifact_path(&self, reference: ArtifactRef) -> PathBuf {
        self.root().join(reference.relative_path())
    }

    pub fn bundle_value(&self) -> Value {
        serde_json::from_slice(&fs::read(self.root().join("bundle.json")).unwrap()).unwrap()
    }

    pub fn authority_payload_for_effect(&self, effect: ArtifactRef) -> Option<Value> {
        let expected = serde_json::to_value(effect).unwrap();
        let bundle = self.bundle_value();
        let entry = bundle["authority_prefix"]
            .as_array()?
            .iter()
            .find(|entry| {
                entry
                    .get("decision_companion")
                    .and_then(|companion| companion.get("application_effect"))
                    == Some(&expected)
            })?;
        let envelope_ref: ArtifactRef =
            serde_json::from_value(entry["authority_envelope"].clone()).ok()?;
        let envelope: Value =
            serde_json::from_slice(&fs::read(self.artifact_path(envelope_ref)).ok()?).ok()?;
        let payload = BASE64.decode(envelope["payload"].as_str()?).ok()?;
        serde_json::from_slice(&payload).ok()
    }

    pub fn authority_payloads(&self) -> Vec<Value> {
        self.bundle_value()["authority_prefix"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let envelope_ref: ArtifactRef =
                    serde_json::from_value(entry["authority_envelope"].clone()).unwrap();
                let envelope: Value =
                    serde_json::from_slice(&fs::read(self.artifact_path(envelope_ref)).unwrap())
                        .unwrap();
                let payload = BASE64
                    .decode(envelope["payload"].as_str().unwrap())
                    .unwrap();
                serde_json::from_slice(&payload).unwrap()
            })
            .collect()
    }

    pub fn replace_bundle(&mut self, value: &Value) {
        let bytes = canonical(value);
        self.bundle_manifest_digest = digest(ArtifactKind::AuthorityEvidenceBundleV1, &bytes);
        fs::write(self.root().join("bundle.json"), bytes).unwrap();
    }

    pub fn write_input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let inputs = self.directory.base.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        let path = inputs.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

struct TestDirectory {
    base: PathBuf,
    bundle: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let suffix = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "proof-verifier-portable-fixture-{}-{suffix}",
            std::process::id()
        ));
        let bundle = path.join("bundle");
        fs::create_dir_all(&bundle).unwrap();
        Self { base: path, bundle }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[derive(Default)]
struct ArtifactStore {
    artifacts: BTreeMap<ArtifactRef, Vec<u8>>,
    descriptors: Vec<ArtifactDescriptor>,
}

impl ArtifactStore {
    fn add(&mut self, role: EvidenceRole, kind: ArtifactKind, value: &Value) -> ArtifactRef {
        let bytes = canonical(value);
        self.add_bytes(role, kind, &bytes)
    }

    fn add_bytes(&mut self, role: EvidenceRole, kind: ArtifactKind, bytes: &[u8]) -> ArtifactRef {
        let reference = ArtifactRef {
            artifact_kind: kind,
            digest: digest(kind, bytes),
        };
        let existing = self.artifacts.insert(reference, bytes.to_owned());
        assert!(existing.as_deref().is_none_or(|existing| existing == bytes));
        self.descriptors.push(ArtifactDescriptor {
            role,
            artifact: reference,
            availability: Availability::Included {
                byte_length: u64::try_from(bytes.len()).unwrap(),
            },
        });
        reference
    }

    fn add_role(&mut self, role: EvidenceRole, reference: ArtifactRef) {
        let bytes = self.artifacts.get(&reference).unwrap();
        self.descriptors.push(ArtifactDescriptor {
            role,
            artifact: reference,
            availability: Availability::Included {
                byte_length: u64::try_from(bytes.len()).unwrap(),
            },
        });
    }

    fn external(&mut self, role: EvidenceRole, kind: ArtifactKind, value: &Value) -> ArtifactRef {
        let bytes = canonical(value);
        let reference = ArtifactRef {
            artifact_kind: kind,
            digest: digest(kind, &bytes),
        };
        self.descriptors.push(ArtifactDescriptor {
            role,
            artifact: reference,
            availability: Availability::ExternalCommitment,
        });
        reference
    }

    fn sort_descriptors(&mut self) {
        self.descriptors.sort_by_key(|descriptor| {
            (
                descriptor.role.wire_name(),
                descriptor.artifact.artifact_kind.wire_name(),
                descriptor.artifact.digest,
            )
        });
    }
}

#[derive(Clone, Copy)]
struct CommandAttemptArtifacts {
    command_input: ArtifactRef,
    command_envelope: ArtifactRef,
    actor_context: ArtifactRef,
}

fn add_release_command_input(
    store: &mut ArtifactStore,
    delegation_id: &str,
    idempotency_key: &str,
    release_id: &str,
    proof_id: &str,
) -> ArtifactRef {
    store.add(
        EvidenceRole::CommandInput,
        ArtifactKind::CommandV1,
        &json!({
            "api_version": "proof.dev/command-input/v1",
            "delegation_id": delegation_id,
            "idempotency_key": idempotency_key,
            "normalized_input": {
                "api_version": "proof.dev/operation/release.create/v2",
                "edition_id": TARGET_EDITION_ID,
                "environment_id": ENVIRONMENT_ID,
                "expected_base_release_id": BASE_RELEASE_ID,
                "idempotency_key": idempotency_key,
                "proof_id": proof_id,
                "release_id": release_id,
                "released_at": EVALUATED_AT,
            },
            "operating_principal_id": AGENT_ID,
            "operation": {
                "name": "release.create",
                "version": "proof.dev/operation/release.create/v2",
            },
            "requesting_principal_id": HUMAN_ID,
            "workspace_id": WORKSPACE_ID,
        }),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "a fresh authenticated denial presentation binds every actor and command identity"
)]
fn add_command_presentation(
    store: &mut ArtifactStore,
    signing_key: &SigningKey,
    binding_id: &str,
    delegation_id: &str,
    presentation_id: &str,
    idempotency_key: &str,
    subject_commitment: Digest,
    command_input: ArtifactRef,
) -> CommandAttemptArtifacts {
    let (key_id, _, _) = key_material(signing_key);
    let operation = json!({
        "name": "release.create",
        "version": "proof.dev/operation/release.create/v2",
    });
    let command = json!({
        "api_version": "proof.dev/authenticated-command/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "binding_id": binding_id,
        "command_digest": command_input.digest,
        "delegation_id": delegation_id,
        "expires_at": EXPIRES_AT,
        "idempotency_key": idempotency_key,
        "issued_at": COMMAND_ISSUED_AT,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "presentation_id": presentation_id,
        "requesting_principal_id": HUMAN_ID,
        "workspace_id": WORKSPACE_ID,
    });
    let envelope = dsse_value(
        "application/vnd.proof.authenticated-command.v1+json",
        &command,
        &[signing_key],
    );
    let command_envelope = store.add(
        EvidenceRole::AuthenticatedCommandEnvelope,
        ArtifactKind::AuthenticatedCommandEnvelopeV1,
        &envelope,
    );
    let actor = json!({
        "api_version": "proof.dev/authenticated-actor-context-evidence/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "authenticated_at": AUTHENTICATED_AT,
        "authentication_profile": "proof.local/authentication/human-agent/v1",
        "binding_id": binding_id,
        "command_digest": command_input.digest,
        "command_envelope_digest": command_envelope.digest,
        "delegation_id": delegation_id,
        "operating_principal_id": AGENT_ID,
        "operating_subject": {
            "api_version": "proof.dev/authenticated-subject/v1",
            "provider": "proof/local-ed25519",
            "subject": key_id,
        },
        "operation": operation,
        "presentation_id": presentation_id,
        "requesting_principal_id": HUMAN_ID,
        "requesting_subject_commitment": subject_commitment,
        "workspace_id": WORKSPACE_ID,
    });
    let actor_context = store.add(
        EvidenceRole::ActorContextEvidence,
        ArtifactKind::AuthenticatedActorContextV1,
        &actor,
    );
    CommandAttemptArtifacts {
        command_input,
        command_envelope,
        actor_context,
    }
}

struct AuthorityRecordBuilder<'a> {
    root_key: &'a SigningKey,
    store: &'a mut ArtifactStore,
    previous: Option<Digest>,
    prefix: Vec<AuthorityPrefixEntry>,
}

impl<'a> AuthorityRecordBuilder<'a> {
    fn new(root_key: &'a SigningKey, store: &'a mut ArtifactStore) -> Self {
        Self {
            root_key,
            store,
            previous: None,
            prefix: Vec::new(),
        }
    }

    fn append(
        &mut self,
        mut payload: Value,
        companion: Option<DecisionCompanion>,
        signature_mode: SignatureMode,
    ) -> Digest {
        let sequence = u64::try_from(self.prefix.len() + 1).unwrap();
        payload["authority_sequence"] = Value::from(sequence);
        payload["previous_authority_record_digest"] = serde_json::to_value(self.previous).unwrap();
        let payload_bytes = canonical(&payload);
        let record_digest = digest(ArtifactKind::AuthorityRecordV1, &payload_bytes);
        let mut envelope = dsse_value(
            "application/vnd.proof.authority-record.v1+json",
            &payload,
            &[self.root_key],
        );
        if signature_mode == SignatureMode::CorruptAuthorityDecision
            && payload["api_version"] == "proof.dev/authorization-decision/v2"
        {
            let signature = envelope["signatures"][0]["sig"].as_str().unwrap();
            let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
            envelope["signatures"][0]["sig"] =
                Value::String(format!("{replacement}{}", &signature[1..]));
        }
        let envelope_reference = self.store.add(
            EvidenceRole::AuthorityRecordEnvelope,
            ArtifactKind::AuthorityRecordEnvelopeV1,
            &envelope,
        );
        self.prefix.push(AuthorityPrefixEntry {
            sequence,
            record_digest,
            authority_envelope: envelope_reference,
            decision_companion: companion,
        });
        self.previous = Some(record_digest);
        record_digest
    }

    fn append_root_transition(&mut self, mut payload: Value, successor_key: &SigningKey) -> Digest {
        let sequence = u64::try_from(self.prefix.len() + 1).unwrap();
        payload["authority_sequence"] = Value::from(sequence);
        payload["previous_authority_record_digest"] = serde_json::to_value(self.previous).unwrap();
        let payload_bytes = canonical(&payload);
        let record_digest = digest(ArtifactKind::AuthorityRecordV1, &payload_bytes);
        let envelope = dsse_value(
            "application/vnd.proof.workspace-authority-root-transition.v1+json",
            &payload,
            &[self.root_key, successor_key],
        );
        let envelope_reference = self.store.add(
            EvidenceRole::AuthorityRecordEnvelope,
            ArtifactKind::AuthorityRecordEnvelopeV1,
            &envelope,
        );
        self.prefix.push(AuthorityPrefixEntry {
            sequence,
            record_digest,
            authority_envelope: envelope_reference,
            decision_companion: None,
        });
        self.previous = Some(record_digest);
        record_digest
    }
}

pub fn generate(opening: OpeningMode, signature: SignatureMode) -> GeneratedFixture {
    let directory = TestDirectory::new();
    let root_key = SigningKey::from_bytes(&[0x11; 32]);
    let agent_key = SigningKey::from_bytes(&[0x22; 32]);
    let release_key = SigningKey::from_bytes(&match signature {
        SignatureMode::ReleaseSignerReusesAuthorityRootKey => [0x11; 32],
        SignatureMode::ReleaseSignerReusesBindingKey => [0x22; 32],
        _ => [0x33; 32],
    });
    let historical_release_key = SigningKey::from_bytes(&[0x35; 32]);
    let successor_key = SigningKey::from_bytes(&[0x44; 32]);
    let rotated_binding_key = SigningKey::from_bytes(&[0x55; 32]);
    let (root_key_id, root_public_base64, _) = key_material(&root_key);
    let (agent_key_id, agent_public_base64, _) = key_material(&agent_key);
    let (release_key_id, release_public_base64, release_public_hex) = key_material(&release_key);
    let (
        historical_release_key_id,
        historical_release_public_base64,
        historical_release_public_hex,
    ) = key_material(&historical_release_key);
    let (successor_key_id, successor_public_base64, _) = key_material(&successor_key);
    let (rotated_binding_key_id, rotated_binding_public_base64, _) =
        key_material(&rotated_binding_key);
    let (binding_signing_key, binding_key_id, binding_public_base64) =
        if signature == SignatureMode::BindingReusesAuthorityRootKey {
            (&root_key, root_key_id.as_str(), root_public_base64.as_str())
        } else {
            (
                &agent_key,
                agent_key_id.as_str(),
                agent_public_base64.as_str(),
            )
        };
    let mut store = ArtifactStore::default();
    let non_genesis_v1 = non_genesis_v1_mode(signature);

    let mut environment_policy = json!({
        "api_version": "proof.dev/release-policy/v1",
        "profile": RELEASE_POLICY_PROFILE,
        "require_approved_changesets": true,
        "require_signed_proof": true,
        "required_approval": "editorial",
    });
    if signature == SignatureMode::EnvironmentPolicyUnknownField {
        environment_policy["unexpected"] = Value::Bool(true);
    }
    let release_policy_ref = store.add(
        EvidenceRole::EnvironmentPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        &environment_policy,
    );
    let authority_policy = json!({
        "api_version": "proof.dev/policy-bundle/v1",
        "profile": POLICY_PROFILE,
        "rules": [{"effect": "allow", "operation": "release.create"}],
    });
    let policy_ref = store.add(
        EvidenceRole::EnvironmentPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        &authority_policy,
    );
    let mut environment = json!({
        "api_version": "proof.dev/environment/v1",
        "config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "policy_digest": release_policy_ref.digest,
        "policy_profile": RELEASE_POLICY_PROFILE,
        "required_approval": "editorial",
        "target_kind": "proof.local/released-state/v1",
        "workspace_id": WORKSPACE_ID,
    });
    if signature == SignatureMode::EnvironmentUnknownField {
        environment["unexpected"] = Value::Bool(true);
    }
    let environment_ref = store.add(
        EvidenceRole::EnvironmentConfig,
        ArtifactKind::EnvironmentConfigV1,
        &environment,
    );
    let localized_policy = json!({
        "api_version": "proof.dev/localized-content-policy/v1",
        "rules": [{
            "disallowed_values": ["Guaranteed approval"],
            "locale": LOCALE,
            "pointer": "/title",
        }],
    });
    let localized_policy_ref = store.add(
        EvidenceRole::ContextPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        &localized_policy,
    );

    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "properties": {"title": {"type": "string"}},
        "required": ["title"],
        "type": "object",
        "x-proof-localizable": ["/title"],
    });
    if signature == SignatureMode::V1InvalidSchemaDocument {
        schema["type"] = Value::String("not-a-json-schema-type".to_owned());
    }
    let schema_ref = store.add(EvidenceRole::Schema, ArtifactKind::SchemaVersionV1, &schema);
    let mut source = json!({
        "api_version": "proof.dev/object-revision/v1",
        "content": {"title": "Canonical source"},
        "lifecycle_state": "active",
        "object_id": OBJECT_ID,
        "relationships": [],
        "revision": 1,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
    });
    if signature == SignatureMode::V1ObjectSchemaMismatch {
        source["content"]["title"] = Value::from(42);
    }
    let source_ref = store.add(
        EvidenceRole::Object,
        ArtifactKind::ObjectRevisionV1,
        &source,
    );
    let schema_state = json!({
        "document_digest": schema_ref.digest,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
    });
    let object_state = json!({
        "lifecycle_state": "active",
        "object_digest": source_ref.digest,
        "object_id": OBJECT_ID,
        "revision": 1,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
    });
    let v1_origin_state = json!({
        "api_version": "proof.dev/known-state/v1",
        "authoritative_sequence": 0,
        "workspace_id": WORKSPACE_ID,
    });
    let v1_origin_state_ref = store.add(
        EvidenceRole::KnownState,
        ArtifactKind::KnownStateV1,
        &v1_origin_state,
    );
    let _v1_predecessor = non_genesis_v1.then(|| {
        let empty_schema_set = json!({
            "api_version": "proof.dev/schema-set/v1",
            "schemas": [],
        });
        let empty_schema_set_digest =
            digest(ArtifactKind::SchemaSetV1, &canonical(&empty_schema_set));
        let predecessor_edition = json!({
            "api_version": "proof.dev/edition/v1",
            "authoritative_sequence": 0,
            "changesets": [],
            "schema_set_digest": empty_schema_set_digest,
            "schemas": [],
            "state_digest": v1_origin_state_ref.digest,
            "workspace_id": WORKSPACE_ID,
        });
        let predecessor_edition_ref = store.add(
            EvidenceRole::Edition,
            ArtifactKind::EditionV1,
            &predecessor_edition,
        );
        let predecessor_policy = json!({
            "action": "release.promote",
            "allowed": true,
            "api_version": "proof.dev/release-authorization-decision/v1",
            "delegation_chain": [],
            "edition_digest": predecessor_edition_ref.digest,
            "edition_id": V1_GENESIS_EDITION_ID,
            "environment_config_digest": environment_ref.digest,
            "environment_config_version": 1,
            "environment_id": ENVIRONMENT_ID,
            "evaluated_at": T0,
            "evidence": [],
            "operating_principal_id": HUMAN_ID,
            "policy_profile": RELEASE_POLICY_PROFILE,
            "previous_release_id": null,
            "required_approval": "editorial",
            "rollback_target_release_id": null,
            "workspace_id": WORKSPACE_ID,
        });
        let predecessor_policy_ref = store.add(
            EvidenceRole::ReleasePolicyDecision,
            ArtifactKind::AuthorizationDecisionV1,
            &predecessor_policy,
        );
        let predecessor_release = json!({
            "api_version": "proof.dev/release/v1",
            "authorization_decision_digest": predecessor_policy_ref.digest,
            "delegation_id": null,
            "edition_digest": predecessor_edition_ref.digest,
            "edition_id": V1_GENESIS_EDITION_ID,
            "environment_config_digest": environment_ref.digest,
            "environment_config_version": 1,
            "environment_id": ENVIRONMENT_ID,
            "key_id": historical_release_key_id,
            "kind": "promotion",
            "previous_release_id": null,
            "principal_id": HUMAN_ID,
            "proof_id": V1_GENESIS_PROOF_ID,
            "release_id": V1_GENESIS_RELEASE_ID,
            "release_sequence": 1,
            "released_at": T0,
            "rollback_target_release_id": null,
            "workspace_id": WORKSPACE_ID,
        });
        let predecessor_release_ref = store.add(
            EvidenceRole::ReleaseManifest,
            ArtifactKind::ReleaseV1,
            &predecessor_release,
        );
        let predecessor_statement = json!({
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
                "api_version": "proof.dev/release-proof-predicate/v1",
                "authority": {
                    "authorization_decision_digest": predecessor_policy_ref.digest,
                    "delegation_chain": [],
                    "human_principal_id": HUMAN_ID,
                    "policy_profile": RELEASE_POLICY_PROFILE,
                },
                "evidence": [],
                "implementation": {
                    "canonical_json": "RFC 8785",
                    "digest": "BLAKE3-256 domain-separated",
                    "dsse": "DSSE v1 PAE",
                    "known_state": "proof.dev/known-state/v1",
                    "signature": "Ed25519",
                    "statement": "in-toto Statement v1",
                },
                "origin": {
                    "authoritative_sequence": 0,
                    "base_state": v1_origin_state_ref.digest,
                    "changesets": [],
                    "edition_state": v1_origin_state_ref.digest,
                    "workspace_id": WORKSPACE_ID,
                },
                "policy": {
                    "decision": "allow",
                    "environment_config_digest": environment_ref.digest,
                    "environment_config_version": 1,
                    "required_approval": "editorial",
                },
                "release": {
                    "edition_digest": predecessor_edition_ref.digest,
                    "edition_id": V1_GENESIS_EDITION_ID,
                    "environment_id": ENVIRONMENT_ID,
                    "key_id": historical_release_key_id,
                    "kind": "promotion",
                    "previous_release_id": null,
                    "release_digest": predecessor_release_ref.digest,
                    "release_id": V1_GENESIS_RELEASE_ID,
                    "release_sequence": 1,
                    "released_at": T0,
                    "rollback_target_release_id": null,
                },
            },
            "predicateType": PREDICATE_TYPE_V1,
            "subject": [
                {
                    "digest": {"blake3": predecessor_edition_ref.digest.hex()},
                    "name": format!("proof:edition:{V1_GENESIS_EDITION_ID}"),
                },
                {
                    "digest": {"blake3": predecessor_release_ref.digest.hex()},
                    "name": format!("proof:release:{V1_GENESIS_RELEASE_ID}"),
                },
            ],
        });
        let predecessor_envelope = dsse_value(
            "application/vnd.in-toto+json",
            &predecessor_statement,
            &[&historical_release_key],
        );
        let predecessor_proof_ref = store.add(
            EvidenceRole::ReleaseProofEnvelope,
            ArtifactKind::ProofEnvelopeV1,
            &predecessor_envelope,
        );
        (
            v1_origin_state_ref,
            predecessor_edition_ref,
            predecessor_release_ref,
            predecessor_proof_ref,
        )
    });

    let v1_transition = {
        let predecessor_state_ref = v1_origin_state_ref;
        let first_ordinal = u64::from(signature != SignatureMode::NonGenesisV1ZeroBasedOrdinals);
        let changeset = json!({
            "api_version": "proof.dev/changeset/v1",
            "base_authoritative_sequence": 0,
            "base_state": predecessor_state_ref.digest,
            "changeset_id": V1_CHANGESET_ID,
            "created_at": V1_CHANGESET_CREATED_AT,
            "edits": [
                {
                    "document_digest": schema_ref.digest,
                    "edit_id": V1_SCHEMA_EDIT_ID,
                    "kind": "schema.create",
                        "ordinal": first_ordinal,
                    "schema_id": SCHEMA_ID,
                    "schema_version": 1,
                },
                {
                    "edit_id": V1_OBJECT_EDIT_ID,
                    "kind": "object.create",
                    "object_digest": source_ref.digest,
                    "object_id": OBJECT_ID,
                        "ordinal": first_ordinal + 1,
                    "schema_id": SCHEMA_ID,
                    "schema_version": 1,
                },
            ],
            "idempotency_key": V1_IDEMPOTENCY_KEY,
            "intent": "Create the canonical source object",
            "policy_profile": "proof.local/policy/default/v1",
            "principal_id": HUMAN_ID,
            "requested_base_state": predecessor_state_ref.digest,
            "validation_profile": "proof.local/validation/default/v1",
            "workspace_id": WORKSPACE_ID,
        });
        let changeset_ref = store.add(
            EvidenceRole::ChangeSet,
            ArtifactKind::ChangeSetV1,
            &changeset,
        );
        let validation = json!({
            "api_version": "proof.dev/validation-results/v1",
            "base_state": predecessor_state_ref.digest,
            "changeset_digest": changeset_ref.digest,
            "changeset_id": V1_CHANGESET_ID,
            "findings": [],
            "valid": true,
            "validation_profile": "proof.local/validation/default/v1",
            "validator": "proof/object-create/draft-2020-12/1+jsonschema/0.49.3",
        });
        let validation_ref = store.add(
            EvidenceRole::ValidationAttempt,
            ArtifactKind::ValidationResultsV1,
            &validation,
        );
        let evidence = json!({
            "approval": {
                "approved_at": V1_APPROVED_AT,
                "approval_name": "editorial",
                "principal_id": if signature == SignatureMode::NonGenesisV1ApprovalPrincipalMismatch {
                    SECOND_HUMAN_ID
                } else {
                    HUMAN_ID
                },
            },
            "authoritative_sequence": 2,
            "changeset_digest": changeset_ref.digest,
            "changeset_id": V1_CHANGESET_ID,
            "committed_at": V1_COMMITTED_AT,
            "created_at": V1_CHANGESET_CREATED_AT,
            "submission": {
                "submitted_at": V1_SUBMITTED_AT,
            },
            "validation": {
                "results_digest": validation_ref.digest,
                "validation_profile": "proof.local/validation/default/v1",
                "validator": "proof/object-create/draft-2020-12/1+jsonschema/0.49.3",
            },
        });
        (changeset_ref, validation_ref, evidence)
    };
    let schema_set = json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": [schema_state],
    });
    let schema_set_digest = digest(ArtifactKind::SchemaSetV1, &canonical(&schema_set));
    let base_object_set = json!({
        "api_version": "proof.dev/object-set/v1",
        "objects": [object_state],
    });
    let base_object_set_digest = digest(ArtifactKind::ObjectSetV1, &canonical(&base_object_set));
    let base_authoritative_sequence = 2;
    let base_state = json!({
        "api_version": "proof.dev/known-state/v1",
        "authoritative_sequence": base_authoritative_sequence,
        "objects": [object_state],
        "schemas": [schema_state],
        "workspace_id": WORKSPACE_ID,
    });
    let base_state_ref = store.add(
        EvidenceRole::KnownState,
        ArtifactKind::KnownStateV1,
        &base_state,
    );
    let base_state_reference = state_reference(
        base_state_ref,
        "proof.dev/known-state/v1",
        base_authoritative_sequence,
    );
    let base_changesets = vec![json!({
        "changeset_digest": v1_transition.0.digest,
        "changeset_id": V1_CHANGESET_ID,
    })];
    let mut base_edition = json!({
        "api_version": "proof.dev/edition/v1",
        "authoritative_sequence": base_authoritative_sequence,
        "changesets": base_changesets,
        "object_set_digest": base_object_set_digest,
        "objects": [object_state],
        "schema_set_digest": schema_set_digest,
        "schemas": [schema_state],
        "state_digest": base_state_ref.digest,
        "workspace_id": WORKSPACE_ID,
    });
    match signature {
        SignatureMode::V1EditionUnknownField => {
            base_edition["unexpected"] = Value::Bool(true);
        }
        SignatureMode::V1EditionMissingSchemas => {
            base_edition.as_object_mut().unwrap().remove("schemas");
        }
        SignatureMode::V1EditionMissingObjectSetDigest => {
            base_edition
                .as_object_mut()
                .unwrap()
                .remove("object_set_digest");
        }
        SignatureMode::V1EditionEmptyObjectsWithDigest => {
            base_edition["objects"] = json!([]);
        }
        _ => {}
    }
    let base_edition_ref = store.add(
        EvidenceRole::Edition,
        ArtifactKind::EditionV1,
        &base_edition,
    );
    let base_edition_reference =
        edition_reference(base_edition_ref, "proof.dev/edition/v1", BASE_EDITION_ID);
    let base_previous_release_id = if non_genesis_v1 {
        Value::String(V1_GENESIS_RELEASE_ID.to_owned())
    } else {
        Value::Null
    };
    let base_release_sequence = if non_genesis_v1 { 2 } else { 1 };
    let base_released_at = V1_RELEASED_AT;
    let mut base_signed_evidence = vec![v1_transition.2.clone()];
    if signature == SignatureMode::NonGenesisV1FabricatedEvidence {
        base_signed_evidence[0]["approval"]["approval_name"] =
            Value::String("attacker-self-approved".to_owned());
        base_signed_evidence[0]["validation"]["validation_profile"] =
            Value::String("attacker/validation/always-valid".to_owned());
        base_signed_evidence[0]["validation"]["validator"] =
            Value::String("attacker/validator/always-valid".to_owned());
    }
    if signature == SignatureMode::NonGenesisV1SequenceGap {
        base_signed_evidence[0]["authoritative_sequence"] = Value::from(3);
    }
    let mut base_policy_decision = json!({
        "action": "release.promote",
        "allowed": signature != SignatureMode::BasePolicyDenied,
        "api_version": "proof.dev/release-authorization-decision/v1",
        "delegation_chain": [],
        "edition_digest": base_edition_ref.digest,
        "edition_id": BASE_EDITION_ID,
        "environment_config_digest": environment_ref.digest,
        "environment_config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "evaluated_at": base_released_at,
        "evidence": base_signed_evidence.clone(),
        "operating_principal_id": HUMAN_ID,
        "policy_profile": RELEASE_POLICY_PROFILE,
        "previous_release_id": base_previous_release_id.clone(),
        "required_approval": "editorial",
        "rollback_target_release_id": null,
        "workspace_id": WORKSPACE_ID,
    });
    if signature == SignatureMode::V1PolicyDecisionUnknownField {
        base_policy_decision["unexpected"] = Value::Bool(true);
    }
    let base_policy_decision_ref = store.add(
        EvidenceRole::ReleasePolicyDecision,
        ArtifactKind::AuthorizationDecisionV1,
        &base_policy_decision,
    );
    let base_release = json!({
        "api_version": "proof.dev/release/v1",
        "authorization_decision_digest": base_policy_decision_ref.digest,
        "delegation_id": null,
        "edition_digest": base_edition_ref.digest,
        "edition_id": BASE_EDITION_ID,
        "environment_config_digest": environment_ref.digest,
        "environment_config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "key_id": historical_release_key_id,
        "kind": "promotion",
        "previous_release_id": base_previous_release_id.clone(),
        "principal_id": HUMAN_ID,
        "proof_id": BASE_PROOF_ID,
        "release_id": BASE_RELEASE_ID,
        "release_sequence": base_release_sequence,
        "released_at": base_released_at,
        "rollback_target_release_id": null,
        "workspace_id": WORKSPACE_ID,
    });
    let base_release_ref = store.add(
        EvidenceRole::ReleaseManifest,
        ArtifactKind::ReleaseV1,
        &base_release,
    );
    let mut base_statement = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "api_version": "proof.dev/release-proof-predicate/v1",
            "authority": {
                "authorization_decision_digest": base_policy_decision_ref.digest,
                "delegation_chain": [],
                "human_principal_id": HUMAN_ID,
                "policy_profile": RELEASE_POLICY_PROFILE,
            },
            "evidence": base_signed_evidence,
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": "proof.dev/known-state/v1",
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "origin": {
                "authoritative_sequence": base_authoritative_sequence,
                "base_state": if signature == SignatureMode::NonGenesisV1FabricatedEvidence {
                    base_state_ref.digest
                } else {
                    v1_origin_state_ref.digest
                },
                "changesets": base_changesets,
                "edition_state": base_state_ref.digest,
                "workspace_id": WORKSPACE_ID,
            },
            "policy": {
                "decision": "allow",
                "environment_config_digest": environment_ref.digest,
                "environment_config_version": 1,
                "required_approval": "editorial",
            },
            "release": {
                "edition_digest": base_edition_ref.digest,
                "edition_id": BASE_EDITION_ID,
                "environment_id": ENVIRONMENT_ID,
                "key_id": historical_release_key_id,
                "kind": "promotion",
                "previous_release_id": base_previous_release_id,
                "release_digest": base_release_ref.digest,
                "release_id": BASE_RELEASE_ID,
                "release_sequence": base_release_sequence,
                "released_at": base_released_at,
                "rollback_target_release_id": null,
            },
        },
        "predicateType": PREDICATE_TYPE_V1,
        "subject": [
            {
                "digest": {"blake3": base_edition_ref.digest.hex()},
                "name": format!("proof:edition:{BASE_EDITION_ID}"),
            },
            {
                "digest": {"blake3": base_release_ref.digest.hex()},
                "name": format!("proof:release:{BASE_RELEASE_ID}"),
            },
        ],
    });
    if matches!(
        signature,
        SignatureMode::SubstituteBaseReleaseProofSubject
            | SignatureMode::RollbackSubstituteTargetProofSubject
    ) {
        base_statement["subject"][1]["digest"]["blake3"] = Digest([0x91; 32]).hex().into();
    }
    if signature == SignatureMode::BasePredicateOriginStateTamper {
        base_statement["predicate"]["origin"]["edition_state"] =
            serde_json::to_value(Digest([0x93; 32])).unwrap();
    }
    if signature == SignatureMode::BasePredicateWorkspaceTamper {
        base_statement["predicate"]["origin"]["workspace_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    }
    if signature == SignatureMode::HistoricalV1PredicateTypeV2 {
        base_statement["predicateType"] = Value::String(PREDICATE_TYPE_V2.to_owned());
    }
    let mut base_release_envelope = dsse_value(
        "application/vnd.in-toto+json",
        &base_statement,
        &[&historical_release_key],
    );
    if matches!(
        signature,
        SignatureMode::CorruptBaseReleaseProof | SignatureMode::RollbackCorruptTargetProof
    ) {
        corrupt_first_signature(&mut base_release_envelope);
    }
    let base_release_proof_ref = store.add(
        EvidenceRole::ReleaseProofEnvelope,
        ArtifactKind::ProofEnvelopeV1,
        &base_release_envelope,
    );
    if signature == SignatureMode::DuplicateBaseReleaseProof {
        let mut duplicate_statement = base_statement.clone();
        duplicate_statement["implementation"]["statement"] =
            Value::String("in-toto Statement v1 duplicate mapping".to_owned());
        let duplicate_envelope = dsse_value(
            "application/vnd.in-toto+json",
            &duplicate_statement,
            &[&historical_release_key],
        );
        store.add(
            EvidenceRole::ReleaseProofEnvelope,
            ArtifactKind::ProofEnvelopeV1,
            &duplicate_envelope,
        );
    }
    if signature == SignatureMode::OrphanReleaseProof {
        let mut orphan_statement = base_statement.clone();
        let orphan_release_id = "019c0000-0000-7000-8000-000000000097";
        let orphan_digest = Digest([0x92; 32]);
        orphan_statement["predicate"]["release"]["release_id"] =
            Value::String(orphan_release_id.to_owned());
        orphan_statement["predicate"]["release"]["release_digest"] =
            serde_json::to_value(orphan_digest).unwrap();
        orphan_statement["subject"][1]["name"] =
            Value::String(format!("proof:release:{orphan_release_id}"));
        orphan_statement["subject"][1]["digest"]["blake3"] = orphan_digest.hex().into();
        let orphan_envelope = dsse_value(
            "application/vnd.in-toto+json",
            &orphan_statement,
            &[&historical_release_key],
        );
        store.add(
            EvidenceRole::ReleaseProofEnvelope,
            ArtifactKind::ProofEnvelopeV1,
            &orphan_envelope,
        );
    }
    let base_release_reference = release_reference_v1(base_release_ref, BASE_RELEASE_ID);

    let targets = json!([{
        "locale": LOCALE,
        "object_id": OBJECT_ID,
        "schema_id": SCHEMA_ID,
    }]);
    let base_closure = json!({
        "edition": base_edition_reference,
        "known_state": base_state_reference,
        "release": base_release_reference,
    });
    let content_created_at = if non_genesis_v1 { V1_RELEASED_AT } else { T0 };
    let intent = json!({
        "api_version": "proof.dev/content-resource-intent/v1",
        "base": base_closure,
        "environment_id": ENVIRONMENT_ID,
        "intent_id": INTENT_ID,
        "issued_at": content_created_at,
        "issued_by_principal_id": HUMAN_ID,
        "targets": targets,
        "workspace_id": WORKSPACE_ID,
    });
    let intent_ref = store.add(
        EvidenceRole::ResourceIntent,
        ArtifactKind::ContentResourceIntentV1,
        &intent,
    );
    let context_pack = json!({
        "allowed_operations": [
            "proof.dev/operation/changeset.create/v2",
            "proof.dev/operation/changeset.add/v2",
            "proof.dev/operation/changeset.get/v2",
            "proof.dev/operation/changeset.diff/v2",
            "proof.dev/operation/changeset.validate/v2",
            "proof.dev/operation/changeset.submit/v2",
            "proof.dev/operation/changeset.commit/v2",
            "proof.dev/operation/edition.create/v2",
            "proof.dev/operation/release.create/v2",
            "proof.dev/operation/object.query_released/v2",
        ],
        "api_version": "proof.dev/context-pack/v2",
        "context_pack_id": CONTEXT_ID,
        "created_at": content_created_at,
        "explicit_exclusions": [
            "agent-authority",
            "campaign-expansion",
            "deletion",
            "fallback",
            "generic-object-replacement",
            "relationship-mutation",
            "schema-mutation",
        ],
        "expires_at": "2027-08-21T10:00:00Z",
        "limits": {
            "max_bytes": 4096,
            "max_edits": 1,
            "max_objects": 1,
            "max_validation_attempts": 1,
        },
        "policy": localized_policy,
        "policy_digest": localized_policy_ref.digest,
        "principal_id": HUMAN_ID,
        "resource_intent": intent,
        "resource_intent_digest": intent_ref.digest,
        "resources": [{
            "locale": LOCALE,
            "object_id": OBJECT_ID,
            "schema": {
                "document": schema,
                "document_digest": schema_ref.digest,
                "localizable_pointers": ["/title"],
                "schema_id": SCHEMA_ID,
                "schema_version": 1,
            },
            "source": {
                "api_version": "proof.dev/object-revision/v1",
                "content": source["content"],
                "digest": source_ref.digest,
                "revision": 1,
            },
            "target": {
                "absent": true,
                "api_version": "proof.dev/object-locale-absence/v1",
                "authoritative_sequence": base_authoritative_sequence,
            },
        }],
        "target_ordering": "object_id,schema_id,locale:utf8-ascending",
        "validator": "proof/localized-content/1",
        "workspace_id": WORKSPACE_ID,
    });
    let context_ref = store.add(
        EvidenceRole::ContextPack,
        ArtifactKind::ContextPackV2,
        &context_pack,
    );
    let edit = json!({
        "api_version": "proof.dev/edit/v2",
        "content": {"title": "Versión aprobada"},
        "edit_id": EDIT_ID,
        "expected_source": {
            "digest": source_ref.digest,
            "revision": 1,
            "schema_id": SCHEMA_ID,
            "schema_version": 1,
        },
        "expected_target": null,
        "kind": "object.locale.put",
        "locale": LOCALE,
        "object_id": OBJECT_ID,
        "repair_of_validation_result_digest": null,
        "supersedes_edit_id": null,
    });
    let edit_ref = store.add(EvidenceRole::Edit, ArtifactKind::EditV2, &edit);
    let effective_batch = json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": [edit],
    });
    let effective_ref = store.add(
        EvidenceRole::Edit,
        ArtifactKind::EditBatchV2,
        &effective_batch,
    );
    let effective_leaves = json!([{
        "edit_digest": edit_ref.digest,
        "edit_id": EDIT_ID,
        "locale": LOCALE,
        "object_id": OBJECT_ID,
    }]);
    let proposal = json!({
        "api_version": "proof.dev/changeset/v2",
        "base_state": base_state_reference,
        "changeset_id": CHANGESET_ID,
        "context_pack_digest": context_ref.digest,
        "context_pack_id": CONTEXT_ID,
        "created_at": content_created_at,
        "edits": [edit],
        "effective_leaf_digest": effective_ref.digest,
        "effective_leaves": effective_leaves,
        "intent": "Create an approved Spanish rendition",
        "principal_id": HUMAN_ID,
        "resource_intent_digest": intent_ref.digest,
        "resource_intent_id": INTENT_ID,
        "workspace_id": WORKSPACE_ID,
    });
    let proposal_ref = store.add(
        EvidenceRole::ChangeSet,
        ArtifactKind::ChangeSetV2,
        &proposal,
    );
    let validation = json!({
        "api_version": "proof.dev/validation-results/v2",
        "attempt": 1,
        "changeset_id": CHANGESET_ID,
        "context_pack_digest": context_ref.digest,
        "effective_leaf_digest": effective_ref.digest,
        "findings": [],
        "policy_digest": localized_policy_ref.digest,
        "previous_validation_result_digest": null,
        "proposal_digest": proposal_ref.digest,
        "schema_digests": [schema_state],
        "valid": true,
        "validator": "proof/localized-content/1",
    });
    let validation_ref = store.add(
        EvidenceRole::ValidationAttempt,
        ArtifactKind::ValidationResultsV2,
        &validation,
    );
    let seal = json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": proposal_ref.digest,
        "validation_results_digest": validation_ref.digest,
    });
    let seal_ref = store.add(EvidenceRole::ChangeSet, ArtifactKind::ChangeSetV2, &seal);
    let rendition = json!({
        "api_version": "proof.dev/object-locale-revision/v1",
        "authoritative_sequence": base_authoritative_sequence + 1,
        "changeset_id": CHANGESET_ID,
        "content": {"title": "Versión aprobada"},
        "edit_id": EDIT_ID,
        "locale": LOCALE,
        "object_id": OBJECT_ID,
        "previous_revision_digest": null,
        "revision": 1,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": source_ref.digest,
        "source_object_revision": 1,
        "workspace_id": WORKSPACE_ID,
    });
    let rendition_ref = store.add(
        EvidenceRole::LocaleRevision,
        ArtifactKind::ObjectLocaleRevisionV1,
        &rendition,
    );
    let rendition_state = json!({
        "locale": LOCALE,
        "object_id": OBJECT_ID,
        "rendition_digest": rendition_ref.digest,
        "revision": 1,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
        "source_object_digest": source_ref.digest,
    });
    let target_state = json!({
        "api_version": "proof.dev/known-state/v2",
        "authoritative_sequence": base_authoritative_sequence + 1,
        "objects": [object_state],
        "previous_state": base_state_reference,
        "renditions": [rendition_state],
        "schemas": [schema_state],
        "workspace_id": WORKSPACE_ID,
    });
    let target_state_ref = store.add(
        EvidenceRole::KnownState,
        ArtifactKind::KnownStateV2,
        &target_state,
    );
    let target_state_reference = state_reference(
        target_state_ref,
        "proof.dev/known-state/v2",
        base_authoritative_sequence + 1,
    );
    let changeset_evidence = json!({
        "changeset_id": CHANGESET_ID,
        "context_pack_digest": context_ref.digest,
        "effective_leaf_digest": effective_ref.digest,
        "proposal_digest": proposal_ref.digest,
        "resource_intent_digest": intent_ref.digest,
        "sealed_changeset_digest": seal_ref.digest,
        "validation_results_digest": validation_ref.digest,
    });
    let release_changeset_evidence = json!({
        "changeset_id": CHANGESET_ID,
        "effective_leaf_digest": effective_ref.digest,
        "proposal_digest": proposal_ref.digest,
        "sealed_changeset_digest": seal_ref.digest,
    });
    let target_object_set = json!({
        "api_version": "proof.dev/object-set/v2",
        "objects": [object_state],
        "renditions": [rendition_state],
    });
    let target_object_set_digest =
        digest(ArtifactKind::ObjectSetV2, &canonical(&target_object_set));
    let target_edition = json!({
        "api_version": "proof.dev/edition/v2",
        "authoritative_sequence": base_authoritative_sequence + 1,
        "base_edition": base_edition_reference,
        "changeset": changeset_evidence,
        "created_at": if signature == SignatureMode::V2ReleaseBeforeEditionCreatedAt {
            "2026-08-21T10:11:00Z"
        } else {
            EVALUATED_AT
        },
        "edition_id": TARGET_EDITION_ID,
        "object_set_digest": target_object_set_digest,
        "objects": [object_state],
        "principal_id": HUMAN_ID,
        "renditions": [rendition_state],
        "schema_set_digest": schema_set_digest,
        "schemas": [schema_state],
        "state": target_state_reference,
        "workspace_id": WORKSPACE_ID,
    });
    let target_edition_ref = store.add(
        EvidenceRole::Edition,
        ArtifactKind::EditionV2,
        &target_edition,
    );
    let target_edition_reference = edition_reference(
        target_edition_ref,
        "proof.dev/edition/v2",
        TARGET_EDITION_ID,
    );
    let mut delta = json!({
        "api_version": "proof.dev/edition-delta/v2",
        "base": {"edition": base_edition_reference, "state": base_state_reference},
        "objects": [],
        "renditions": [{
            "after": rendition_state,
            "before": null,
            "locale": LOCALE,
            "object_id": OBJECT_ID,
        }],
        "schemas": [],
        "target": {"edition": target_edition_reference, "state": target_state_reference},
    });
    if signature == SignatureMode::PromotionDeltaHitchhike {
        delta["objects"] = json!([{
            "after": object_state,
            "before": object_state,
            "object_id": OBJECT_ID,
        }]);
    }
    let delta_ref = store.add(EvidenceRole::EditionDelta, ArtifactKind::ReleaseV2, &delta);
    let submission = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.submit/v2",
        "result": {
            "approval": null,
            "changeset_id": CHANGESET_ID,
            "occurred_at": SUBMITTED_AT,
            "principal_id": HUMAN_ID,
            "sealed_changeset_digest": seal_ref.digest,
            "validation_results_digest": validation_ref.digest,
        },
    });
    let _submission_ref = store.add(
        EvidenceRole::Submission,
        ArtifactKind::OperationEffectV1,
        &submission,
    );
    let approval_principal_id = if second_human_approval_mode(signature) {
        SECOND_HUMAN_ID
    } else if signature == SignatureMode::NonHumanApprover {
        AGENT_ID
    } else {
        HUMAN_ID
    };
    let approval = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.approve/v2",
        "result": {
            "approval": "editorial",
            "changeset_id": CHANGESET_ID,
            "occurred_at": APPROVED_AT,
            "principal_id": approval_principal_id,
            "sealed_changeset_digest": seal_ref.digest,
            "validation_results_digest": validation_ref.digest,
        },
    });
    let approval_ref = store.add(
        EvidenceRole::Approval,
        ArtifactKind::OperationEffectV1,
        &approval,
    );
    let broken_predecessor = release_reference_v1(
        ArtifactRef {
            artifact_kind: ArtifactKind::ReleaseV1,
            digest: Digest([0xee; 32]),
        },
        BASE_RELEASE_ID,
    );
    let promotion_base_release = if signature == SignatureMode::RollbackBrokenAncestry {
        broken_predecessor
    } else {
        base_release_reference.clone()
    };
    let mut policy_decision = json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": promotion_base_release,
        "changeset_id": CHANGESET_ID,
        "edition": target_edition_reference,
        "environment_config_digest": environment_ref.digest,
        "environment_config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "evaluated_at": EVALUATED_AT,
        "exact_delta_digest": delta_ref.digest,
        "kind": "promotion",
        "operating_principal_id": HUMAN_ID,
        "policy_profile": RELEASE_POLICY_PROFILE,
        "required_approval": "editorial",
        "resource_intent_id": INTENT_ID,
        "rollback_target_release_id": if signature == SignatureMode::PromotionWithRollbackTarget {
            Value::String(BASE_RELEASE_ID.to_owned())
        } else {
            Value::Null
        },
        "workspace_id": WORKSPACE_ID,
    });
    if signature == SignatureMode::V2PolicyDecisionUnknownField {
        policy_decision["unexpected"] = Value::Bool(true);
    }
    let policy_decision_ref = store.add(
        EvidenceRole::ReleasePolicyDecision,
        ArtifactKind::AuthorizationDecisionV1,
        &policy_decision,
    );
    let promotion_manifest = json!({
        "api_version": "proof.dev/release/v2",
        "authorization_decision_digest": policy_decision_ref.digest,
        "base_release": promotion_base_release,
        "changeset_id": CHANGESET_ID,
        "edition": target_edition_reference,
        "environment_config_digest": environment_ref.digest,
        "environment_config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "exact_delta_digest": delta_ref.digest,
        "key_id": release_key_id,
        "kind": "promotion",
        "principal_id": HUMAN_ID,
        "proof_id": PROOF_ID,
        "release_id": TARGET_RELEASE_ID,
        "release_sequence": base_release_sequence + 1,
        "released_at": EVALUATED_AT,
        "resource_intent_id": INTENT_ID,
        "rollback_target_release_id": if signature == SignatureMode::PromotionWithRollbackTarget {
            Value::String(BASE_RELEASE_ID.to_owned())
        } else {
            Value::Null
        },
        "workspace_id": WORKSPACE_ID,
    });
    let promotion_manifest_ref = store.add(
        EvidenceRole::ReleaseManifest,
        ArtifactKind::ReleaseV2,
        &promotion_manifest,
    );
    let mut content_evidence = json!({
        "base": base_closure,
        "changeset": release_changeset_evidence,
        "context_pack_digest": context_ref.digest,
        "renditions": [{
            "edit_id": EDIT_ID,
            "locale": LOCALE,
            "object_id": OBJECT_ID,
            "rendition_digest": rendition_ref.digest,
            "schema_id": SCHEMA_ID,
            "schema_version": 1,
            "source_object_digest": source_ref.digest,
        }],
        "resource_intent": {
            "digest": intent_ref.digest,
            "intent_id": INTENT_ID,
            "targets": targets,
        },
        "resulting_state": target_state_reference,
        "validations": [{
            "attempt": 1,
            "previous_validation_result_digest": null,
            "proposal_digest": proposal_ref.digest,
            "results_digest": validation_ref.digest,
            "valid": true,
        }],
    });
    match signature {
        SignatureMode::HistoricalV2ContentEvidenceUnknownField => {
            content_evidence["unexpected"] = Value::Bool(true);
        }
        SignatureMode::HistoricalV2ContentBaseUnknownField => {
            content_evidence["base"]["unexpected"] = Value::Bool(true);
        }
        SignatureMode::HistoricalV2ContentChangesetUnknownField => {
            content_evidence["changeset"]["unexpected"] = Value::Bool(true);
        }
        SignatureMode::HistoricalV2ContentResourceIntentUnknownField => {
            content_evidence["resource_intent"]["unexpected"] = Value::Bool(true);
        }
        SignatureMode::HistoricalV2ContentValidationUnknownField => {
            content_evidence["validations"][0]["unexpected"] = Value::Bool(true);
        }
        SignatureMode::HistoricalV2ContentRenditionUnknownField => {
            content_evidence["renditions"][0]["unexpected"] = Value::Bool(true);
        }
        _ => {}
    }
    let mut promotion_statement = release_v2_statement(
        &promotion_manifest,
        promotion_manifest_ref,
        policy_decision_ref,
        &delta,
        delta_ref,
        &content_evidence,
        &target_state_reference,
        target_edition_ref,
        TARGET_EDITION_ID,
        TARGET_RELEASE_ID,
    );
    if signature == SignatureMode::RollbackPromotionWorkspaceTamper {
        promotion_statement["predicate"]["workspace_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    }
    if signature == SignatureMode::V2PredicateUnknownField {
        promotion_statement["predicate"]["unexpected"] = Value::Bool(true);
    }
    if signature == SignatureMode::HistoricalV2PredicateTypeV1 {
        promotion_statement["predicateType"] = Value::String(PREDICATE_TYPE_V1.to_owned());
    }
    let promotion_envelope = dsse_value(
        "application/vnd.in-toto+json",
        &promotion_statement,
        &[&release_key],
    );
    let promotion_proof_ref = store.add(
        EvidenceRole::ReleaseProofEnvelope,
        ArtifactKind::ProofEnvelopeV1,
        &promotion_envelope,
    );
    let rollback_mode = historical_v2_shape_attack(signature)
        || matches!(
            signature,
            SignatureMode::OrphanHistoricalV2ApprovalEvidence
                | SignatureMode::HistoricalV2DirectHumanNoCompanion
                | SignatureMode::HistoricalV2DistinctAuthorizationTime
                | SignatureMode::HistoricalV2ResultProofMetadataMismatch
                | SignatureMode::HistoricalV2ResultProofIdMismatch
        )
        || matches!(
            signature,
            SignatureMode::RollbackRelease
                | SignatureMode::RollbackBrokenAncestry
                | SignatureMode::RollbackCorruptTargetProof
                | SignatureMode::RollbackSubstituteTargetProofSubject
                | SignatureMode::RollbackWithNullTarget
                | SignatureMode::RollbackSelectsDifferentEdition
                | SignatureMode::RollbackPromotionWorkspaceTamper
        );
    let (
        release_manifest,
        release_manifest_ref,
        release_proof_ref,
        selected_release_id,
        selected_proof_id,
    ) = if rollback_mode {
        let current_release_reference =
            release_reference(promotion_manifest_ref, TARGET_RELEASE_ID);
        let rollback_delta = json!({
            "api_version": "proof.dev/edition-delta/v2",
            "base": {"edition": target_edition_reference, "state": target_state_reference},
            "objects": [],
            "renditions": [{
                "after": null,
                "before": rendition_state,
                "locale": LOCALE,
                "object_id": OBJECT_ID,
            }],
            "schemas": [],
            "target": {"edition": base_edition_reference, "state": base_state_reference},
        });
        let rollback_delta_ref = store.add(
            EvidenceRole::EditionDelta,
            ArtifactKind::ReleaseV2,
            &rollback_delta,
        );
        let rollback_target = if signature == SignatureMode::RollbackWithNullTarget {
            Value::Null
        } else {
            Value::String(BASE_RELEASE_ID.to_owned())
        };
        let rollback_edition = if signature == SignatureMode::RollbackSelectsDifferentEdition {
            target_edition_reference.clone()
        } else {
            base_edition_reference.clone()
        };
        let rollback_policy = json!({
            "action": "release.create",
            "allowed": true,
            "api_version": "proof.dev/release-authorization-decision/v2",
            "base_release": current_release_reference,
            "changeset_id": null,
            "edition": rollback_edition,
            "environment_config_digest": environment_ref.digest,
            "environment_config_version": 1,
            "environment_id": ENVIRONMENT_ID,
            "evaluated_at": EVALUATED_AT,
            "exact_delta_digest": rollback_delta_ref.digest,
            "kind": "rollback",
            "operating_principal_id": HUMAN_ID,
            "policy_profile": RELEASE_POLICY_PROFILE,
            "required_approval": "editorial",
            "resource_intent_id": null,
            "rollback_target_release_id": rollback_target,
            "workspace_id": WORKSPACE_ID,
        });
        let rollback_policy_ref = store.add(
            EvidenceRole::ReleasePolicyDecision,
            ArtifactKind::AuthorizationDecisionV1,
            &rollback_policy,
        );
        let rollback_manifest = json!({
            "api_version": "proof.dev/release/v2",
            "authorization_decision_digest": rollback_policy_ref.digest,
            "base_release": current_release_reference,
            "changeset_id": null,
            "edition": rollback_edition,
            "environment_config_digest": environment_ref.digest,
            "environment_config_version": 1,
            "environment_id": ENVIRONMENT_ID,
            "exact_delta_digest": rollback_delta_ref.digest,
            "key_id": release_key_id,
            "kind": "rollback",
            "principal_id": HUMAN_ID,
            "proof_id": ROLLBACK_PROOF_ID,
            "release_id": ROLLBACK_RELEASE_ID,
            "release_sequence": base_release_sequence + 2,
            "released_at": EVALUATED_AT,
            "resource_intent_id": null,
            "rollback_target_release_id": rollback_target,
            "workspace_id": WORKSPACE_ID,
        });
        let rollback_manifest_ref = store.add(
            EvidenceRole::ReleaseManifest,
            ArtifactKind::ReleaseV2,
            &rollback_manifest,
        );
        let (rollback_state, rollback_edition_ref, rollback_edition_id) =
            if signature == SignatureMode::RollbackSelectsDifferentEdition {
                (
                    &target_state_reference,
                    target_edition_ref,
                    TARGET_EDITION_ID,
                )
            } else {
                (&base_state_reference, base_edition_ref, BASE_EDITION_ID)
            };
        let rollback_statement = release_v2_statement(
            &rollback_manifest,
            rollback_manifest_ref,
            rollback_policy_ref,
            &rollback_delta,
            rollback_delta_ref,
            &Value::Null,
            rollback_state,
            rollback_edition_ref,
            rollback_edition_id,
            ROLLBACK_RELEASE_ID,
        );
        let rollback_envelope = dsse_value(
            "application/vnd.in-toto+json",
            &rollback_statement,
            &[&release_key],
        );
        let rollback_proof_ref = store.add(
            EvidenceRole::ReleaseProofEnvelope,
            ArtifactKind::ProofEnvelopeV1,
            &rollback_envelope,
        );
        (
            rollback_manifest,
            rollback_manifest_ref,
            rollback_proof_ref,
            ROLLBACK_RELEASE_ID,
            ROLLBACK_PROOF_ID,
        )
    } else {
        (
            promotion_manifest.clone(),
            promotion_manifest_ref,
            promotion_proof_ref,
            TARGET_RELEASE_ID,
            PROOF_ID,
        )
    };
    store.add_role(EvidenceRole::ApplicationEffect, release_manifest_ref);
    if rollback_mode {
        store.add_role(EvidenceRole::ApplicationEffect, promotion_manifest_ref);
    }
    let localized_result = json!({
        "proof_envelope_digest": release_proof_ref.digest,
        "proof_id": selected_proof_id,
        "release_digest": release_manifest_ref.digest,
        "release_id": selected_release_id,
        "release_manifest": release_manifest,
    });
    let localized_result_ref = store.add(
        EvidenceRole::LocalizedResult,
        ArtifactKind::OperationEffectV1,
        &localized_result,
    );
    let promotion_localized_result_ref = rollback_mode.then(|| {
        let mut result = json!({
            "proof_envelope_digest": promotion_proof_ref.digest,
            "proof_id": PROOF_ID,
            "release_digest": promotion_manifest_ref.digest,
            "release_id": TARGET_RELEASE_ID,
            "release_manifest": promotion_manifest,
        });
        if signature == SignatureMode::HistoricalV2ResultProofMetadataMismatch {
            result["proof_envelope_digest"] =
                serde_json::to_value(release_proof_ref.digest).unwrap();
        }
        if signature == SignatureMode::HistoricalV2ResultProofIdMismatch {
            result["proof_id"] = Value::String(ROLLBACK_PROOF_ID.to_owned());
        }
        store.add(
            EvidenceRole::LocalizedResult,
            ArtifactKind::OperationEffectV1,
            &result,
        )
    });
    let operation = json!({
        "name": "release.create",
        "version": "proof.dev/operation/release.create/v2",
    });
    let selectors = json!({
        "changeset_ids": [CHANGESET_ID],
        "edition_ids": [TARGET_EDITION_ID],
        "release_ids": [BASE_RELEASE_ID, TARGET_RELEASE_ID],
    });
    let consequence_result = json!({
        "contract": RELEASE_RESULT_CONTRACT,
        "digest": localized_result_ref.digest,
        "kind": "success",
    });
    let consequence_closure = json!({
        "approval": {
            "approval_name": "editorial",
            "approved_at": APPROVED_AT,
            "effect_digest": approval_ref.digest,
            "principal_id": approval_principal_id,
        },
        "changeset": {
            "changeset_id": CHANGESET_ID,
            "context_pack_digest": context_ref.digest,
            "context_pack_id": CONTEXT_ID,
            "resource_intent_digest": intent_ref.digest,
            "resource_intent_id": INTENT_ID,
        },
        "context": {
            "context_pack_digest": context_ref.digest,
            "context_pack_id": CONTEXT_ID,
            "limits": context_pack["limits"],
            "policy_digest": localized_policy_ref.digest,
        },
        "context_fresh": true,
        "resource_intent": {
            "intent_digest": intent_ref.digest,
            "intent_id": INTENT_ID,
            "issued_by_principal_id": HUMAN_ID,
        },
        "validator": "proof/localized-content/1",
    });
    let target_idempotency_key = if rollback_mode {
        ROLLBACK_IDEMPOTENCY_KEY
    } else {
        IDEMPOTENCY_KEY
    };
    let target_presentation_id = if rollback_mode {
        ROLLBACK_PRESENTATION_ID
    } else {
        PRESENTATION_ID
    };
    let application_idempotency = json!({"key": target_idempotency_key, "kind": "required"});
    let composite = json!({
        "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
        "application_effect_digest": release_manifest_ref.digest,
        "application_idempotency": application_idempotency,
        "closure": consequence_closure,
        "command_digest": Value::Null,
        "delegation_id": DELEGATION_ID,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "requesting_principal_id": HUMAN_ID,
        "result": consequence_result,
        "selectors": selectors,
        "semantic_timestamp": EVALUATED_AT,
        "workspace_id": WORKSPACE_ID,
    });

    let commitment_input = json!({
        "api_version": "proof.dev/authenticated-subject-commitment/v1",
        "authenticated_subject": {
            "api_version": "proof.dev/authenticated-subject/v1",
            "provider": "os/unix",
            "subject": "uid:1000",
        },
        "blind": URL_SAFE_NO_PAD.encode([0x44; 32]),
        "workspace_id": WORKSPACE_ID,
    });
    let subject_commitment = digest(
        ArtifactKind::AuthenticatedSubjectCommitmentV1,
        &canonical(&commitment_input),
    );
    let subject_blind = commitment_input["blind"].as_str().unwrap().to_owned();
    let subject_opening_value = json!({
        "api_version": "proof.dev/authenticated-subject-opening/v1",
        "blind": subject_blind,
        "commitment_input": commitment_input,
        "requesting_subject": {"provider": "os/unix", "subject": "uid:1000"},
        "requesting_subject_commitment": subject_commitment,
        "workspace_id": WORKSPACE_ID,
    });

    let promotion_attempt = (rollback_mode
        && signature != SignatureMode::HistoricalV2DirectHumanNoCompanion)
        .then(|| {
            let command_input = add_release_command_input(
                &mut store,
                DELEGATION_ID,
                IDEMPOTENCY_KEY,
                TARGET_RELEASE_ID,
                PROOF_ID,
            );
            add_command_presentation(
                &mut store,
                binding_signing_key,
                BINDING_ID,
                DELEGATION_ID,
                PRESENTATION_ID,
                IDEMPOTENCY_KEY,
                subject_commitment,
                command_input,
            )
        });

    let command_input_value = json!({
        "api_version": "proof.dev/command-input/v1",
        "delegation_id": DELEGATION_ID,
        "idempotency_key": target_idempotency_key,
        "normalized_input": {
            "api_version": "proof.dev/operation/release.create/v2",
            "edition_id": TARGET_EDITION_ID,
            "environment_id": ENVIRONMENT_ID,
            "expected_base_release_id": BASE_RELEASE_ID,
            "idempotency_key": target_idempotency_key,
            "proof_id": PROOF_ID,
            "release_id": TARGET_RELEASE_ID,
            "released_at": EVALUATED_AT,
        },
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "requesting_principal_id": HUMAN_ID,
        "workspace_id": WORKSPACE_ID,
    });
    let command_input_ref = store.add(
        EvidenceRole::CommandInput,
        ArtifactKind::CommandV1,
        &command_input_value,
    );
    let authenticated_command = json!({
        "api_version": "proof.dev/authenticated-command/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "binding_id": BINDING_ID,
        "command_digest": command_input_ref.digest,
        "delegation_id": DELEGATION_ID,
        "expires_at": EXPIRES_AT,
        "idempotency_key": target_idempotency_key,
        "issued_at": COMMAND_ISSUED_AT,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "presentation_id": target_presentation_id,
        "requesting_principal_id": HUMAN_ID,
        "workspace_id": WORKSPACE_ID,
    });
    let command_envelope = dsse_value(
        "application/vnd.proof.authenticated-command.v1+json",
        &authenticated_command,
        &[binding_signing_key],
    );
    let command_envelope_ref = store.add(
        EvidenceRole::AuthenticatedCommandEnvelope,
        ArtifactKind::AuthenticatedCommandEnvelopeV1,
        &command_envelope,
    );
    let operating_subject = json!({
        "api_version": "proof.dev/authenticated-subject/v1",
        "provider": "proof/local-ed25519",
        "subject": binding_key_id,
    });
    let actor_presentation = if signature == SignatureMode::SubstituteActorPresentation {
        "019c0000-0000-7000-8000-000000000099"
    } else {
        target_presentation_id
    };
    let actor = json!({
        "api_version": "proof.dev/authenticated-actor-context-evidence/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "authenticated_at": AUTHENTICATED_AT,
        "authentication_profile": "proof.local/authentication/human-agent/v1",
        "binding_id": BINDING_ID,
        "command_digest": command_input_ref.digest,
        "command_envelope_digest": command_envelope_ref.digest,
        "delegation_id": DELEGATION_ID,
        "operating_principal_id": AGENT_ID,
        "operating_subject": operating_subject,
        "operation": operation,
        "presentation_id": actor_presentation,
        "requesting_principal_id": HUMAN_ID,
        "requesting_subject_commitment": subject_commitment,
        "workspace_id": WORKSPACE_ID,
    });
    let actor_ref = store.add(
        EvidenceRole::ActorContextEvidence,
        ArtifactKind::AuthenticatedActorContextV1,
        &actor,
    );
    let mut composite_with_command = composite;
    composite_with_command["command_digest"] =
        serde_json::to_value(command_input_ref.digest).unwrap();
    let application_consequence_digest = digest(
        ArtifactKind::OperationEffectV1,
        &canonical(&composite_with_command),
    );
    let localized_commitment = json!({
        "application_consequence_digest": application_consequence_digest,
        "result_contract": RELEASE_RESULT_CONTRACT,
        "result_digest": localized_result_ref.digest,
        "result_kind": "success",
    });
    let promotion_consequence = promotion_attempt
        .as_ref()
        .zip(promotion_localized_result_ref)
        .map(|(attempt, result_ref)| {
            let result = json!({
                "contract": RELEASE_RESULT_CONTRACT,
                "digest": result_ref.digest,
                "kind": "success",
            });
            let application_idempotency = json!({"key": IDEMPOTENCY_KEY, "kind": "required"});
            let composite = json!({
                "api_version": "proof.dev/authenticated-localized-consequence-commitment/v1",
                "application_effect_digest": promotion_manifest_ref.digest,
                "application_idempotency": application_idempotency,
                "closure": consequence_closure,
                "command_digest": attempt.command_input.digest,
                "delegation_id": DELEGATION_ID,
                "operating_principal_id": AGENT_ID,
                "operation": operation,
                "requesting_principal_id": HUMAN_ID,
                "result": result,
                "selectors": selectors,
                "semantic_timestamp": EVALUATED_AT,
                "workspace_id": WORKSPACE_ID,
            });
            let application_consequence_digest =
                digest(ArtifactKind::OperationEffectV1, &canonical(&composite));
            let commitment = json!({
                "application_consequence_digest": application_consequence_digest,
                "result_contract": RELEASE_RESULT_CONTRACT,
                "result_digest": result_ref.digest,
                "result_kind": "success",
            });
            (
                result,
                application_idempotency,
                application_consequence_digest,
                commitment,
            )
        });

    let mut authority = AuthorityRecordBuilder::new(&root_key, &mut store);
    authority.append(
        json!({
            "api_version": "proof.dev/principal-status/v1",
            "enabled": true,
            "principal_id": HUMAN_ID,
            "principal_type": "human",
            "recorded_at": T0,
            "recorded_by_principal_id": HUMAN_ID,
            "workspace_id": WORKSPACE_ID,
        }),
        None,
        SignatureMode::Valid,
    );
    authority.append(
        json!({
            "api_version": "proof.dev/principal-status/v1",
            "enabled": true,
            "principal_id": AGENT_ID,
            "principal_type": "agent",
            "recorded_at": if signature == SignatureMode::FutureCausalStatus {
                "2026-08-21T10:12:00Z"
            } else {
                T0
            },
            "recorded_by_principal_id": HUMAN_ID,
            "workspace_id": WORKSPACE_ID,
        }),
        None,
        SignatureMode::Valid,
    );
    let binding_digest = authority.append(
        json!({
            "algorithm": "ed25519",
            "api_version": "proof.dev/principal-binding/v1",
            "audience": format!("proof://workspace/{WORKSPACE_ID}"),
            "authenticated_subject": operating_subject,
            "binding_id": BINDING_ID,
            "enrollment_challenge_digest": Digest([0x71; 32]),
            "enrollment_envelope_digest": Digest([0x72; 32]),
            "expires_at": if signature == SignatureMode::DelegationWithoutActiveBinding {
                "2026-08-21T09:30:00Z"
            } else {
                "2027-08-21T10:00:00Z"
            },
            "issued_at": if signature == SignatureMode::DelegationWithoutActiveBinding {
                "2026-08-21T09:00:00Z"
            } else {
                T0
            },
            "issued_by_principal_id": HUMAN_ID,
            "key_usage": "authenticated-command",
            "not_before": if signature == SignatureMode::DelegationWithoutActiveBinding {
                "2026-08-21T09:00:00Z"
            } else {
                T0
            },
            "principal_id": AGENT_ID,
            "principal_type": "agent",
            "public_key": binding_public_base64,
            "supersedes_binding_id": null,
            "workspace_id": WORKSPACE_ID,
        }),
        None,
        SignatureMode::Valid,
    );
    if matches!(
        signature,
        SignatureMode::BindingRotationMissingSupersedes
            | SignatureMode::BindingRotationWrongSupersedes
            | SignatureMode::BindingRotationSelfSupersedes
            | SignatureMode::SupersededBindingDecision
    ) {
        let supersedes = match signature {
            SignatureMode::BindingRotationWrongSupersedes => {
                Value::String("019c0000-0000-7000-8000-000000000099".to_owned())
            }
            SignatureMode::BindingRotationSelfSupersedes => {
                Value::String(ROTATED_BINDING_ID.to_owned())
            }
            _ => Value::String(BINDING_ID.to_owned()),
        };
        let mut rotated_binding = json!({
            "algorithm": "ed25519",
            "api_version": "proof.dev/principal-binding/v1",
            "audience": format!("proof://workspace/{WORKSPACE_ID}"),
            "authenticated_subject": {
                "api_version": "proof.dev/authenticated-subject/v1",
                "provider": "proof/local-ed25519",
                "subject": rotated_binding_key_id,
            },
            "binding_id": ROTATED_BINDING_ID,
            "enrollment_challenge_digest": Digest([0x73; 32]),
            "enrollment_envelope_digest": Digest([0x74; 32]),
            "expires_at": "2027-08-21T10:00:00Z",
            "issued_at": T0,
            "issued_by_principal_id": HUMAN_ID,
            "key_usage": "authenticated-command",
            "not_before": T0,
            "principal_id": AGENT_ID,
            "principal_type": "agent",
            "public_key": rotated_binding_public_base64,
            "supersedes_binding_id": supersedes,
            "workspace_id": WORKSPACE_ID,
        });
        if signature == SignatureMode::BindingRotationMissingSupersedes {
            rotated_binding
                .as_object_mut()
                .unwrap()
                .remove("supersedes_binding_id");
        }
        authority.append(rotated_binding, None, SignatureMode::Valid);
    }
    if requires_second_human_status(signature) {
        authority.append(
            json!({
                "api_version": "proof.dev/principal-status/v1",
                "enabled": true,
                "principal_id": SECOND_HUMAN_ID,
                "principal_type": "human",
                "recorded_at": if signature == SignatureMode::LateEnabledHumanApprover {
                    "2026-08-21T10:07:00Z"
                } else {
                    T0
                },
                "recorded_by_principal_id": HUMAN_ID,
                "workspace_id": WORKSPACE_ID,
            }),
            None,
            SignatureMode::Valid,
        );
    }
    if signature == SignatureMode::DisabledHumanApprover {
        authority.append(
            json!({
                "api_version": "proof.dev/principal-status/v1",
                "enabled": false,
                "principal_id": SECOND_HUMAN_ID,
                "principal_type": "human",
                "recorded_at": V1_SUBMITTED_AT,
                "recorded_by_principal_id": HUMAN_ID,
                "workspace_id": WORKSPACE_ID,
            }),
            None,
            SignatureMode::Valid,
        );
    }
    if signature == SignatureMode::SecondHumanAdmin {
        authority.append(
            json!({
                "actions": ["release:create"],
                "api_version": "proof.dev/delegation/v2",
                "constraints": {
                    "allow_subdelegation": false,
                    "max_context_bytes": 4096,
                    "max_edits_per_changeset": 1,
                    "max_objects": 1,
                },
                "delegation_id": SECOND_HUMAN_DELEGATION_ID,
                "delegation_profile": POLICY_PROFILE,
                "expires_at": "2027-08-21T10:00:00Z",
                "issued_at": T0,
                "issuer_principal_id": SECOND_HUMAN_ID,
                "not_before": T0,
                "recipient_principal_id": AGENT_ID,
                "scope": {
                    "environment_ids": [ENVIRONMENT_ID],
                    "locales": [LOCALE],
                    "object_ids": [OBJECT_ID],
                    "schema_ids": [SCHEMA_ID],
                },
                "workspace_id": WORKSPACE_ID,
            }),
            None,
            SignatureMode::Valid,
        );
    }
    let mut delegation_record = json!({
        "actions": ["release:create"],
        "api_version": "proof.dev/delegation/v2",
        "constraints": {
            "allow_subdelegation": false,
            "max_context_bytes": 4096,
            "max_edits_per_changeset": 1,
            "max_objects": 1,
        },
        "delegation_id": DELEGATION_ID,
        "delegation_profile": POLICY_PROFILE,
        "expires_at": "2027-08-21T10:00:00Z",
        "issued_at": T0,
        "issuer_principal_id": HUMAN_ID,
        "not_before": T0,
        "recipient_principal_id": AGENT_ID,
        "scope": {
            "environment_ids": [ENVIRONMENT_ID],
            "locales": [LOCALE],
            "object_ids": [OBJECT_ID],
            "schema_ids": [SCHEMA_ID],
        },
        "workspace_id": WORKSPACE_ID,
    });
    if signature == SignatureMode::SubdelegationRecord {
        delegation_record["parent_delegation_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    }
    if signature == SignatureMode::WrongDelegationIssuer {
        delegation_record["issuer_principal_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    }
    if signature == SignatureMode::WrongDelegationRecipient {
        delegation_record["recipient_principal_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
    }
    let delegation_digest = authority.append(delegation_record, None, SignatureMode::Valid);
    let requested_resources = json!({
        "changeset_ids": [CHANGESET_ID],
        "edition_ids": [TARGET_EDITION_ID],
        "environment_ids": [ENVIRONMENT_ID],
        "locales": [LOCALE],
        "object_ids": [OBJECT_ID],
        "release_ids": [BASE_RELEASE_ID, TARGET_RELEASE_ID],
        "schema_ids": [SCHEMA_ID],
        "workspace_ids": [WORKSPACE_ID],
    });
    if let (
        Some(attempt),
        Some((result, application_idempotency, consequence_digest, commitment)),
    ) = (promotion_attempt, promotion_consequence)
    {
        let promotion_previous_head = AuthorityHead {
            sequence: u64::try_from(authority.prefix.len()).unwrap(),
            record_digest: authority.previous.unwrap_or(delegation_digest),
        };
        let promotion_decision = json!({
            "actor_context_digest": attempt.actor_context.digest,
            "api_version": "proof.dev/authorization-decision/v2",
            "audience": format!("proof://workspace/{WORKSPACE_ID}"),
            "authority_key_id": root_key_id,
            "binding": {
                "authority_sequence": 3,
                "binding_id": BINDING_ID,
                "record_digest": binding_digest,
                "revocation_record_digest": null,
            },
            "command_digest": attempt.command_input.digest,
            "command_envelope_digest": attempt.command_envelope.digest,
            "decision": "allow",
            "delegation": {
                "delegation_id": DELEGATION_ID,
                "record_digest": delegation_digest,
                "resolution": "resolved",
                "revocation_record_digest": null,
            },
            "effective_constraints": {
                "max_context_bytes": 4096,
                "max_edits_per_changeset": 1,
                "max_objects": 1,
            },
            "evaluated_at": if signature == SignatureMode::HistoricalV2DistinctAuthorizationTime {
                "2026-08-21T10:12:00Z"
            } else {
                EVALUATED_AT
            },
            "evaluated_authority_head": promotion_previous_head,
            "localized_consequence_commitment": commitment,
            "operating_principal_id": AGENT_ID,
            "operation": operation,
            "policy_bundle_digest": policy_ref.digest,
            "policy_profile": POLICY_PROFILE,
            "presentation_consumed": true,
            "presentation_id": PRESENTATION_ID,
            "principal_state": {
                "operating_principal_enabled": true,
                "requesting_principal_enabled": true,
            },
            "reason_code": null,
            "requested_action": "release:create",
            "requested_resources": requested_resources,
            "requesting_principal_id": HUMAN_ID,
            "requesting_subject_commitment": subject_commitment,
            "workspace_id": WORKSPACE_ID,
        });
        let orphan = signature == SignatureMode::OrphanHistoricalV2ApprovalEvidence;
        let promotion_decision_digest = if orphan {
            Digest([0xa5; 32])
        } else {
            let companion = DecisionCompanion {
                command_input: attempt.command_input,
                authenticated_command_envelope: attempt.command_envelope,
                actor_context_evidence: attempt.actor_context,
                result: promotion_localized_result_ref,
                localized_consequence: None,
                application_effect: Some(promotion_manifest_ref),
            };
            authority.append(promotion_decision, Some(companion), SignatureMode::Valid)
        };
        let localized_consequence = json!({
            "api_version": "proof.dev/authenticated-localized-consequence/v1",
            "application_consequence_digest": consequence_digest,
            "application_effect_digest": promotion_manifest_ref.digest,
            "application_idempotency": application_idempotency,
            "authorization_decision_digest": promotion_decision_digest,
            "closure": consequence_closure,
            "command_digest": attempt.command_input.digest,
            "delegation_id": DELEGATION_ID,
            "operating_principal_id": AGENT_ID,
            "operation": operation,
            "operation_output_schema": RELEASE_RESULT_CONTRACT,
            "presentation_id": PRESENTATION_ID,
            "requesting_principal_id": HUMAN_ID,
            "result": result,
            "selectors": selectors,
            "semantic_timestamp": EVALUATED_AT,
            "workspace_id": WORKSPACE_ID,
        });
        let consequence_ref = authority.store.add(
            EvidenceRole::LocalizedConsequence,
            ArtifactKind::AuthenticatedLocalizedConsequenceV1,
            &localized_consequence,
        );
        if !orphan {
            authority
                .prefix
                .last_mut()
                .unwrap()
                .decision_companion
                .as_mut()
                .unwrap()
                .localized_consequence = Some(consequence_ref);
        }
    }
    let previous_head = AuthorityHead {
        sequence: u64::try_from(authority.prefix.len()).unwrap(),
        record_digest: authority.previous.unwrap_or(delegation_digest),
    };
    let mut decision = json!({
        "actor_context_digest": actor_ref.digest,
        "api_version": "proof.dev/authorization-decision/v2",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "authority_key_id": root_key_id,
        "binding": {
            "authority_sequence": 3,
            "binding_id": BINDING_ID,
            "record_digest": binding_digest,
            "revocation_record_digest": null,
        },
        "command_digest": command_input_ref.digest,
        "command_envelope_digest": command_envelope_ref.digest,
        "decision": "allow",
        "delegation": {
            "delegation_id": DELEGATION_ID,
            "record_digest": delegation_digest,
            "resolution": "resolved",
            "revocation_record_digest": null,
        },
        "effective_constraints": {
            "max_context_bytes": 4096,
            "max_edits_per_changeset": 1,
            "max_objects": 1,
        },
        "evaluated_at": EVALUATED_AT,
        "evaluated_authority_head": previous_head,
        "localized_consequence_commitment": localized_commitment,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "policy_bundle_digest": policy_ref.digest,
        "policy_profile": POLICY_PROFILE,
        "presentation_consumed": true,
        "presentation_id": target_presentation_id,
        "principal_state": {
            "operating_principal_enabled": true,
            "requesting_principal_enabled": true,
        },
        "reason_code": null,
        "requested_action": "release:create",
        "requested_resources": requested_resources,
        "requesting_principal_id": HUMAN_ID,
        "requesting_subject_commitment": subject_commitment,
        "workspace_id": WORKSPACE_ID,
    });
    if signature == SignatureMode::SubstituteBindingSequence {
        decision["binding"]["authority_sequence"] = Value::from(2);
    }
    let companion = DecisionCompanion {
        command_input: command_input_ref,
        authenticated_command_envelope: command_envelope_ref,
        actor_context_evidence: actor_ref,
        result: Some(localized_result_ref),
        localized_consequence: None,
        application_effect: Some(release_manifest_ref),
    };
    let decision_digest = authority.append(decision.clone(), Some(companion), signature);
    let localized_consequence = json!({
        "api_version": "proof.dev/authenticated-localized-consequence/v1",
        "application_consequence_digest": application_consequence_digest,
        "application_effect_digest": release_manifest_ref.digest,
        "application_idempotency": application_idempotency,
        "authorization_decision_digest": decision_digest,
        "closure": consequence_closure,
        "command_digest": command_input_ref.digest,
        "delegation_id": DELEGATION_ID,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "operation_output_schema": RELEASE_RESULT_CONTRACT,
        "presentation_id": target_presentation_id,
        "requesting_principal_id": HUMAN_ID,
        "result": consequence_result,
        "selectors": selectors,
        "semantic_timestamp": EVALUATED_AT,
        "workspace_id": WORKSPACE_ID,
    });
    let consequence_ref = authority.store.add(
        EvidenceRole::LocalizedConsequence,
        ArtifactKind::AuthenticatedLocalizedConsequenceV1,
        &localized_consequence,
    );
    let last = authority.prefix.last_mut().unwrap();
    last.decision_companion
        .as_mut()
        .unwrap()
        .localized_consequence = Some(consequence_ref);
    let mut authority_head_digest = decision_digest;
    let mut active_authority_key_id = root_key_id.as_str();
    let denial_reason = match signature {
        SignatureMode::DenialScopeExceeded | SignatureMode::DenialActionExceeded => {
            Some("proof.authorization.scope_exceeded")
        }
        SignatureMode::DenialBudgetExceeded => Some("proof.authorization.budget_exceeded"),
        SignatureMode::DenialDelegationUnavailable => {
            Some("proof.authorization.delegation_unavailable")
        }
        SignatureMode::DenialPrincipalDisabled => Some("proof.authorization.principal_disabled"),
        SignatureMode::DenialBindingInactive => Some("proof.auth.binding_inactive"),
        SignatureMode::DenialDelegationExpired => Some("proof.authorization.delegation_expired"),
        SignatureMode::DenialDelegationNotYetValid => {
            Some("proof.authorization.delegation_not_yet_valid")
        }
        SignatureMode::DenialRevokedRetry => Some("proof.authorization.delegation_revoked"),
        SignatureMode::DenialIdempotencyKeyReused
        | SignatureMode::DenialIdempotencyExactReplay
        | SignatureMode::DenialIdempotencyFreshKey
        | SignatureMode::DenialWithEffect => Some("proof.idempotency.key_reused"),
        SignatureMode::DenialPolicyDenied => Some("proof.authorization.policy_denied"),
        SignatureMode::DenialChainUnsupported => Some("proof.delegation.chain_unsupported"),
        _ => None,
    };
    if let Some(reason) = denial_reason {
        let mut denial_delegation_id = DELEGATION_ID;
        let mut denial_delegation_digest = delegation_digest;
        let mut delegation_revocation = None;
        let mut binding_revocation = None;
        let mut operating_enabled = true;
        if signature == SignatureMode::DenialDelegationUnavailable {
            denial_delegation_id = DENIAL_DELEGATION_ID;
        } else if matches!(
            signature,
            SignatureMode::DenialScopeExceeded
                | SignatureMode::DenialBudgetExceeded
                | SignatureMode::DenialActionExceeded
                | SignatureMode::DenialDelegationExpired
                | SignatureMode::DenialDelegationNotYetValid
        ) {
            let mut actions = json!(["release:create"]);
            let mut scope = json!({
                "environment_ids": [ENVIRONMENT_ID],
                "locales": [LOCALE],
                "object_ids": [OBJECT_ID],
                "schema_ids": [SCHEMA_ID],
            });
            let mut constraints = json!({
                "allow_subdelegation": false,
                "max_context_bytes": 4096,
                "max_edits_per_changeset": 1,
                "max_objects": 1,
            });
            let mut not_before = T0;
            let mut expires_at = "2027-08-21T10:00:00Z";
            match signature {
                SignatureMode::DenialScopeExceeded => scope["object_ids"] = json!([]),
                SignatureMode::DenialBudgetExceeded => {
                    constraints["max_context_bytes"] = Value::from(2048);
                }
                SignatureMode::DenialActionExceeded => actions = json!(["context:build"]),
                SignatureMode::DenialDelegationExpired => expires_at = "2026-08-21T10:05:00Z",
                SignatureMode::DenialDelegationNotYetValid => not_before = "2026-08-21T10:11:00Z",
                _ => {}
            }
            denial_delegation_digest = authority.append(
                json!({
                    "actions": actions,
                    "api_version": "proof.dev/delegation/v2",
                    "constraints": constraints,
                    "delegation_id": DENIAL_DELEGATION_ID,
                    "delegation_profile": POLICY_PROFILE,
                    "expires_at": expires_at,
                    "issued_at": T0,
                    "issuer_principal_id": HUMAN_ID,
                    "not_before": not_before,
                    "recipient_principal_id": AGENT_ID,
                    "scope": scope,
                    "workspace_id": WORKSPACE_ID,
                }),
                None,
                SignatureMode::Valid,
            );
            denial_delegation_id = DENIAL_DELEGATION_ID;
        } else if signature == SignatureMode::DenialRevokedRetry {
            let digest = authority.append(
                json!({
                    "api_version": "proof.dev/delegation-revocation/v1",
                    "delegation_id": DELEGATION_ID,
                    "reason": "issuer_request",
                    "revocation_id": DENIAL_REVOCATION_ID,
                    "revoked_at": "2026-08-21T10:05:00Z",
                    "revoked_by_principal_id": HUMAN_ID,
                    "workspace_id": WORKSPACE_ID,
                }),
                None,
                SignatureMode::Valid,
            );
            delegation_revocation = Some(digest);
        } else if signature == SignatureMode::DenialBindingInactive {
            let digest = authority.append(
                json!({
                    "api_version": "proof.dev/principal-binding-revocation/v1",
                    "binding_id": BINDING_ID,
                    "reason": "rotation",
                    "revocation_id": DENIAL_REVOCATION_ID,
                    "revoked_at": "2026-08-21T10:05:00Z",
                    "revoked_by_principal_id": HUMAN_ID,
                    "workspace_id": WORKSPACE_ID,
                }),
                None,
                SignatureMode::Valid,
            );
            binding_revocation = Some(digest);
        } else if signature == SignatureMode::DenialPrincipalDisabled {
            authority.append(
                json!({
                    "api_version": "proof.dev/principal-status/v1",
                    "enabled": false,
                    "principal_id": AGENT_ID,
                    "principal_type": "agent",
                    "recorded_at": "2026-08-21T10:05:00Z",
                    "recorded_by_principal_id": HUMAN_ID,
                    "workspace_id": WORKSPACE_ID,
                }),
                None,
                SignatureMode::Valid,
            );
            operating_enabled = false;
        }

        let (denial_input, denial_idempotency, denial_release_id) = if matches!(
            signature,
            SignatureMode::DenialRevokedRetry
                | SignatureMode::DenialBindingInactive
                | SignatureMode::DenialPrincipalDisabled
                | SignatureMode::DenialIdempotencyExactReplay
        ) {
            (command_input_ref, IDEMPOTENCY_KEY, TARGET_RELEASE_ID)
        } else if matches!(
            signature,
            SignatureMode::DenialIdempotencyKeyReused | SignatureMode::DenialWithEffect
        ) {
            (
                add_release_command_input(
                    authority.store,
                    denial_delegation_id,
                    IDEMPOTENCY_KEY,
                    DENIAL_RELEASE_ID,
                    DENIAL_PROOF_ID,
                ),
                IDEMPOTENCY_KEY,
                DENIAL_RELEASE_ID,
            )
        } else if signature == SignatureMode::DenialIdempotencyFreshKey {
            (
                add_release_command_input(
                    authority.store,
                    denial_delegation_id,
                    DENIAL_IDEMPOTENCY_KEY,
                    DENIAL_RELEASE_ID,
                    DENIAL_PROOF_ID,
                ),
                DENIAL_IDEMPOTENCY_KEY,
                DENIAL_RELEASE_ID,
            )
        } else {
            (
                add_release_command_input(
                    authority.store,
                    denial_delegation_id,
                    DENIAL_IDEMPOTENCY_KEY,
                    TARGET_RELEASE_ID,
                    PROOF_ID,
                ),
                DENIAL_IDEMPOTENCY_KEY,
                TARGET_RELEASE_ID,
            )
        };
        let attempt = add_command_presentation(
            authority.store,
            binding_signing_key,
            BINDING_ID,
            denial_delegation_id,
            DENIAL_PRESENTATION_ID,
            denial_idempotency,
            subject_commitment,
            denial_input,
        );
        let mut denial = decision.clone();
        denial
            .as_object_mut()
            .unwrap()
            .remove("localized_consequence_commitment");
        denial["actor_context_digest"] =
            serde_json::to_value(attempt.actor_context.digest).unwrap();
        denial["command_digest"] = serde_json::to_value(attempt.command_input.digest).unwrap();
        denial["command_envelope_digest"] =
            serde_json::to_value(attempt.command_envelope.digest).unwrap();
        denial["decision"] = Value::String("deny".to_owned());
        denial["reason_code"] = Value::String(reason.to_owned());
        denial["presentation_id"] = Value::String(DENIAL_PRESENTATION_ID.to_owned());
        if matches!(
            signature,
            SignatureMode::DenialActionExceeded
                | SignatureMode::DenialDelegationUnavailable
                | SignatureMode::DenialPrincipalDisabled
                | SignatureMode::DenialBindingInactive
                | SignatureMode::DenialDelegationExpired
                | SignatureMode::DenialDelegationNotYetValid
                | SignatureMode::DenialRevokedRetry
        ) {
            denial["requested_resources"] = json!({
                "changeset_ids": [],
                "edition_ids": [],
                "environment_ids": [],
                "locales": [],
                "object_ids": [],
                "release_ids": [],
                "schema_ids": [],
                "workspace_ids": [WORKSPACE_ID],
            });
            denial["effective_constraints"] = json!({
                "max_context_bytes": 1,
                "max_edits_per_changeset": 1,
                "max_objects": 1,
            });
        }
        denial["principal_state"]["operating_principal_enabled"] = Value::Bool(operating_enabled);
        denial["binding"]["revocation_record_digest"] =
            serde_json::to_value(binding_revocation).unwrap();
        denial["evaluated_authority_head"] = serde_json::to_value(AuthorityHead {
            sequence: u64::try_from(authority.prefix.len()).unwrap(),
            record_digest: authority.previous.unwrap_or(decision_digest),
        })
        .unwrap();
        if signature == SignatureMode::DenialDelegationUnavailable {
            denial["delegation"] = json!({
                "delegation_id": DENIAL_DELEGATION_ID,
                "record_digest": null,
                "resolution": "not_found_or_hidden",
                "revocation_record_digest": null,
            });
        } else {
            denial["delegation"] = json!({
                "delegation_id": denial_delegation_id,
                "record_digest": denial_delegation_digest,
                "resolution": "resolved",
                "revocation_record_digest": delegation_revocation,
            });
        }
        if denial_release_id != TARGET_RELEASE_ID {
            denial["requested_resources"]["release_ids"] =
                json!([BASE_RELEASE_ID, denial_release_id]);
        }
        let effectful = signature == SignatureMode::DenialWithEffect;
        let denial_companion = DecisionCompanion {
            command_input: attempt.command_input,
            authenticated_command_envelope: attempt.command_envelope,
            actor_context_evidence: attempt.actor_context,
            result: effectful.then_some(localized_result_ref),
            localized_consequence: effectful.then_some(consequence_ref),
            application_effect: effectful.then_some(release_manifest_ref),
        };
        authority_head_digest =
            authority.append(denial, Some(denial_companion), SignatureMode::Valid);
    } else if signature == SignatureMode::LaterCausalRevocation {
        authority_head_digest = authority.append(
            json!({
                "api_version": "proof.dev/delegation-revocation/v1",
                "delegation_id": DELEGATION_ID,
                "reason": "issuer_request",
                "revocation_id": "019c0000-0000-7000-8000-000000000099",
                "revoked_at": "2026-08-21T10:05:00Z",
                "revoked_by_principal_id": HUMAN_ID,
                "workspace_id": WORKSPACE_ID,
            }),
            None,
            SignatureMode::Valid,
        );
    } else if matches!(
        signature,
        SignatureMode::RootRotation | SignatureMode::AuthoritySuccessorReusesBindingKey
    ) {
        let (rotation_key, rotation_key_id, rotation_public_key) =
            if signature == SignatureMode::AuthoritySuccessorReusesBindingKey {
                (binding_signing_key, binding_key_id, binding_public_base64)
            } else {
                (
                    &successor_key,
                    successor_key_id.as_str(),
                    successor_public_base64.as_str(),
                )
            };
        authority_head_digest = authority.append_root_transition(
            json!({
                "activated_at": "2026-08-21T10:12:00Z",
                "activated_by_principal_id": HUMAN_ID,
                "algorithm": "ed25519",
                "api_version": "proof.dev/workspace-authority-root-transition/v1",
                "predecessor_authority_key_id": root_key_id,
                "successor_authority_key_id": rotation_key_id,
                "successor_public_key": rotation_public_key,
                "transition_id": "019c0000-0000-7000-8000-000000000098",
                "workspace_id": WORKSPACE_ID,
            }),
            rotation_key,
        );
        active_authority_key_id = rotation_key_id;
    }
    let authority_head_sequence = u64::try_from(authority.prefix.len()).unwrap();
    let prefix = std::mem::take(&mut authority.prefix);
    drop(authority);

    let opening_ref = match opening {
        OpeningMode::Withhold => store.external(
            EvidenceRole::SubjectOpening,
            ArtifactKind::AuthenticatedSubjectOpeningV1,
            &subject_opening_value,
        ),
        OpeningMode::Include => store.add(
            EvidenceRole::SubjectOpening,
            ArtifactKind::AuthenticatedSubjectOpeningV1,
            &subject_opening_value,
        ),
    };
    let release_metadata = json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/signing-key-metadata/v1",
        "key_id": release_key_id,
        "not_before": T0,
        "public_key": release_public_hex,
        "trust_profile": "proof.local/release-proof/v1",
    });
    let metadata_digest = digest(ArtifactKind::PolicyBundleV1, &canonical(&release_metadata));
    let release_key_wrapper = json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/release-signing-key/v1",
        "key_id": release_key_id,
        "metadata": release_metadata,
        "native_metadata_digest": metadata_digest,
        "not_before": T0,
        "public_key": release_public_hex,
        "trust_profile": "proof.local/release-proof/v1",
        "workspace_id": WORKSPACE_ID,
    });
    store.add(
        EvidenceRole::ReleaseSigningKey,
        ArtifactKind::ReleaseSigningKeyV1,
        &release_key_wrapper,
    );
    let historical_release_metadata = json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/signing-key-metadata/v1",
        "key_id": historical_release_key_id,
        "not_before": T0,
        "public_key": historical_release_public_hex,
        "trust_profile": "proof.local/release-proof/v1",
    });
    let historical_metadata_digest = digest(
        ArtifactKind::PolicyBundleV1,
        &canonical(&historical_release_metadata),
    );
    let historical_release_key_wrapper = json!({
        "algorithm": "ed25519",
        "api_version": "proof.dev/release-signing-key/v1",
        "key_id": historical_release_key_id,
        "metadata": historical_release_metadata,
        "native_metadata_digest": historical_metadata_digest,
        "not_before": T0,
        "public_key": historical_release_public_hex,
        "trust_profile": "proof.local/release-proof/v1",
        "workspace_id": WORKSPACE_ID,
    });
    store.add(
        EvidenceRole::ReleaseSigningKey,
        ArtifactKind::ReleaseSigningKeyV1,
        &historical_release_key_wrapper,
    );
    store.sort_descriptors();
    let included_head = AuthorityHead {
        sequence: authority_head_sequence,
        record_digest: authority_head_digest,
    };
    let bundle = Bundle {
        api_version: proof_verifier::model::BUNDLE_API_VERSION.to_owned(),
        workspace_id: WORKSPACE_ID.to_owned(),
        entrypoints: Entrypoints {
            target_release_manifest: release_manifest_ref,
            target_release_proof_envelope: release_proof_ref,
            target_authorization_record_digest: decision_digest,
            target_localized_consequence: consequence_ref,
        },
        included_authority_head: included_head,
        authority_prefix: prefix,
        artifacts: store.descriptors,
    };
    let bundle_json = canonical_serialize(&bundle);
    let bundle_manifest_digest = digest(ArtifactKind::AuthorityEvidenceBundleV1, &bundle_json);
    fs::write(directory.bundle.join("bundle.json"), &bundle_json).unwrap();
    for (reference, bytes) in store.artifacts {
        let path = directory.bundle.join(reference.relative_path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    let trust = json!({
        "api_version": proof_verifier::model::TRUST_POLICY_API_VERSION,
        "authority": {
            "accepted_policy_bundles": [{
                "policy_bundle_digest": policy_ref.digest,
                "policy_profile": POLICY_PROFILE,
            }],
            "checkpoint_requirement": "required",
            "compromise_cutoff": null,
            "initial_root": {
                "key_id": root_key_id,
                "not_after": null,
                "not_before": T0,
                "public_key": root_public_base64,
                "revoked_at": null,
            },
        },
        "disclosure": {"requesting_subject_opening": "optional"},
        "limits": VerificationLimits::hard(),
        "release": {
            "accepted_policy_profiles": [{
                "environment_config_digest": environment_ref.digest,
                "policy_profile": RELEASE_POLICY_PROFILE,
            }],
            "accepted_predicate_types": [PREDICATE_TYPE_V1, PREDICATE_TYPE_V2],
            "trusted_signers": [
                {
                    "key_id": historical_release_key_id,
                    "not_after": null,
                    "not_before": T0,
                    "public_key": historical_release_public_base64,
                    "revoked_at": null,
                },
                {
                    "key_id": release_key_id,
                    "not_after": null,
                    "not_before": T0,
                    "public_key": release_public_base64,
                    "revoked_at": null,
                },
            ],
        },
        "workspace_id": WORKSPACE_ID,
    });
    let checkpoint = json!({
        "active_authority_key_id": active_authority_key_id,
        "api_version": proof_verifier::model::CHECKPOINT_API_VERSION,
        "authority_record_digest": authority_head_digest,
        "authority_sequence": authority_head_sequence,
        "observed_at": OBSERVED_AT,
        "workspace_id": WORKSPACE_ID,
    });
    GeneratedFixture {
        directory,
        trust_json: canonical(&trust),
        checkpoint_json: canonical(&checkpoint),
        bundle_manifest_digest,
        subject_opening: opening_ref,
        subject_blind,
        command_input: command_input_ref,
        base_release_origin_state: v1_origin_state_ref,
        base_release_manifest: base_release_ref,
        base_release_proof: base_release_proof_ref,
        promotion_release_manifest: promotion_manifest_ref,
        promotion_release_proof: promotion_proof_ref,
        target_release_manifest: release_manifest_ref,
        target_release_proof: release_proof_ref,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the recursive fixture makes every signed v2 Release subject and predicate link explicit"
)]
fn release_v2_statement(
    manifest: &Value,
    manifest_ref: ArtifactRef,
    policy_decision_ref: ArtifactRef,
    delta: &Value,
    delta_ref: ArtifactRef,
    content_evidence: &Value,
    state_reference: &Value,
    edition_ref: ArtifactRef,
    edition_id: &str,
    release_id: &str,
) -> Value {
    let release = json!({
        "base_release": manifest["base_release"],
        "changeset_id": manifest["changeset_id"],
        "edition": manifest["edition"],
        "environment_id": manifest["environment_id"],
        "key_id": manifest["key_id"],
        "kind": manifest["kind"],
        "release_digest": manifest_ref.digest,
        "release_id": manifest["release_id"],
        "release_sequence": manifest["release_sequence"],
        "released_at": manifest["released_at"],
        "resource_intent_id": manifest["resource_intent_id"],
        "rollback_target_release_id": manifest["rollback_target_release_id"],
    });
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "api_version": "proof.dev/release-proof-predicate/v2",
            "authority": {
                "authorization_decision_digest": policy_decision_ref.digest,
                "human_principal_id": HUMAN_ID,
                "policy_profile": RELEASE_POLICY_PROFILE,
            },
            "content_evidence": content_evidence,
            "exact_delta": delta,
            "exact_delta_digest": delta_ref.digest,
            "implementation": {
                "canonical_json": "RFC 8785",
                "digest": "BLAKE3-256 domain-separated",
                "dsse": "DSSE v1 PAE",
                "known_state": state_reference["api_version"],
                "signature": "Ed25519",
                "statement": "in-toto Statement v1",
            },
            "release": release,
            "state": state_reference,
            "workspace_id": WORKSPACE_ID,
        },
        "predicateType": PREDICATE_TYPE_V2,
        "subject": [
            {
                "digest": {"blake3": edition_ref.digest.hex()},
                "name": format!("proof:edition:{edition_id}"),
            },
            {
                "digest": {"blake3": manifest_ref.digest.hex()},
                "name": format!("proof:release:{release_id}"),
            },
        ],
    })
}

fn key_material(key: &SigningKey) -> (String, String, String) {
    let public = key.verifying_key().to_bytes();
    let hex = hex(public);
    (format!("ed25519:{hex}"), BASE64.encode(public), hex)
}

fn dsse_value(payload_type: &str, payload: &Value, keys: &[&SigningKey]) -> Value {
    let payload_bytes = canonical(payload);
    let pae = dsse_pae(payload_type, &payload_bytes);
    json!({
        "payload": BASE64.encode(&payload_bytes),
        "payloadType": payload_type,
        "signatures": keys.iter().map(|key| {
            let (key_id, _, _) = key_material(key);
            json!({
                "keyid": key_id,
                "sig": BASE64.encode(key.sign(&pae).to_bytes()),
            })
        }).collect::<Vec<_>>(),
    })
}

fn corrupt_first_signature(envelope: &mut Value) {
    let signature = envelope["signatures"][0]["sig"].as_str().unwrap();
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    envelope["signatures"][0]["sig"] = Value::String(format!("{replacement}{}", &signature[1..]));
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let prefix = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = Vec::with_capacity(prefix.len() + payload.len());
    pae.extend_from_slice(prefix.as_bytes());
    pae.extend_from_slice(payload);
    pae
}

fn state_reference(reference: ArtifactRef, api_version: &str, sequence: u64) -> Value {
    json!({
        "api_version": api_version,
        "authoritative_sequence": sequence,
        "digest": reference.digest,
    })
}

fn edition_reference(reference: ArtifactRef, api_version: &str, edition_id: &str) -> Value {
    json!({
        "api_version": api_version,
        "digest": reference.digest,
        "edition_id": edition_id,
    })
}

fn release_reference(reference: ArtifactRef, release_id: &str) -> Value {
    json!({
        "api_version": "proof.dev/release/v2",
        "digest": reference.digest,
        "release_id": release_id,
    })
}

fn release_reference_v1(reference: ArtifactRef, release_id: &str) -> Value {
    json!({
        "api_version": "proof.dev/release/v1",
        "digest": reference.digest,
        "release_id": release_id,
    })
}

pub fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

fn canonical_serialize(value: &impl Serialize) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).unwrap()
}

pub fn digest(kind: ArtifactKind, bytes: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new_derive_key(kind.context());
    hasher.update(bytes);
    Digest(*hasher.finalize().as_bytes())
}

fn hex(bytes: [u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
