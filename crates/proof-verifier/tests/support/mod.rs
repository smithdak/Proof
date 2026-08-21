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
const OBJECT_ID: &str = "019c0000-0000-7000-8000-000000000010";
const SCHEMA_ID: &str = "campaign";
const LOCALE: &str = "es-ES";
const ENVIRONMENT_ID: &str = "preview";
const POLICY_PROFILE: &str = "proof.local/authority/direct/v1";
const RELEASE_POLICY_PROFILE: &str = "proof.local/release/v1";
const PREDICATE_TYPE: &str = "https://proof.dev/attestation/release/v2";
const RELEASE_RESULT_CONTRACT: &str = concat!(
    "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/",
    "releaseCreateOutput"
);
const T0: &str = "2026-08-21T10:00:00Z";
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
    SubstituteBindingSequence,
}

pub struct GeneratedFixture {
    directory: TestDirectory,
    pub trust_json: Vec<u8>,
    pub checkpoint_json: Vec<u8>,
    pub bundle_manifest_digest: Digest,
    pub subject_opening: ArtifactRef,
    pub subject_blind: String,
    pub command_input: ArtifactRef,
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
}

pub fn generate(opening: OpeningMode, signature: SignatureMode) -> GeneratedFixture {
    let directory = TestDirectory::new();
    let root_key = SigningKey::from_bytes(&[0x11; 32]);
    let agent_key = SigningKey::from_bytes(&[0x22; 32]);
    let release_key = SigningKey::from_bytes(&[0x33; 32]);
    let (root_key_id, root_public_base64, _) = key_material(&root_key);
    let (agent_key_id, agent_public_base64, _) = key_material(&agent_key);
    let (release_key_id, release_public_base64, release_public_hex) = key_material(&release_key);
    let mut store = ArtifactStore::default();

    let environment_policy = json!({
        "api_version": "proof.dev/policy-bundle/v1",
        "profile": POLICY_PROFILE,
        "rules": [{"effect": "allow", "operation": "release.create"}],
    });
    let policy_ref = store.add(
        EvidenceRole::EnvironmentPolicyBundle,
        ArtifactKind::PolicyBundleV1,
        &environment_policy,
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

    let schema = json!({
        "properties": {"title": {"type": "string"}},
        "required": ["title"],
        "type": "object",
        "x-proof-localizable": ["/title"],
    });
    let schema_ref = store.add(EvidenceRole::Schema, ArtifactKind::SchemaVersionV1, &schema);
    let source = json!({
        "api_version": "proof.dev/object-revision/v1",
        "content": {"title": "Canonical source"},
        "lifecycle_state": "active",
        "object_id": OBJECT_ID,
        "relationships": [],
        "revision": 1,
        "schema_id": SCHEMA_ID,
        "schema_version": 1,
    });
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
    let base_state = json!({
        "api_version": "proof.dev/known-state/v1",
        "authoritative_sequence": 0,
        "objects": [object_state],
        "schemas": [schema_state],
        "workspace_id": WORKSPACE_ID,
    });
    let base_state_ref = store.add(
        EvidenceRole::KnownState,
        ArtifactKind::KnownStateV1,
        &base_state,
    );
    let base_state_reference = state_reference(base_state_ref, "proof.dev/known-state/v1", 0);
    let base_edition = json!({
        "api_version": "proof.dev/edition/v1",
        "authoritative_sequence": 0,
        "changesets": [],
        "object_set_digest": base_object_set_digest,
        "objects": [object_state],
        "schema_set_digest": schema_set_digest,
        "schemas": [schema_state],
        "state_digest": base_state_ref.digest,
        "workspace_id": WORKSPACE_ID,
    });
    let base_edition_ref = store.add(
        EvidenceRole::Edition,
        ArtifactKind::EditionV1,
        &base_edition,
    );
    let base_edition_reference =
        edition_reference(base_edition_ref, "proof.dev/edition/v1", BASE_EDITION_ID);
    let base_release = json!({
        "api_version": "proof.dev/release/v1",
        "authorization_decision_digest": Digest([0x01; 32]),
        "delegation_id": null,
        "edition_digest": base_edition_ref.digest,
        "edition_id": BASE_EDITION_ID,
        "environment_config_digest": Digest([0x02; 32]),
        "environment_config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "key_id": release_key_id,
        "kind": "promotion",
        "previous_release_id": null,
        "principal_id": HUMAN_ID,
        "proof_id": "019c0000-0000-7000-8000-000000000012",
        "release_id": BASE_RELEASE_ID,
        "release_sequence": 1,
        "released_at": T0,
        "rollback_target_release_id": null,
        "workspace_id": WORKSPACE_ID,
    });
    let base_release_ref = store.add(
        EvidenceRole::ReleaseManifest,
        ArtifactKind::ReleaseV1,
        &base_release,
    );
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
    let intent = json!({
        "api_version": "proof.dev/content-resource-intent/v1",
        "base": base_closure,
        "environment_id": ENVIRONMENT_ID,
        "intent_id": INTENT_ID,
        "issued_at": T0,
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
        "created_at": T0,
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
                "authoritative_sequence": 0,
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
        "created_at": T0,
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
        "authoritative_sequence": 1,
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
        "authoritative_sequence": 1,
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
    let target_state_reference = state_reference(target_state_ref, "proof.dev/known-state/v2", 1);
    let changeset_evidence = json!({
        "changeset_id": CHANGESET_ID,
        "context_pack_digest": context_ref.digest,
        "effective_leaf_digest": effective_ref.digest,
        "proposal_digest": proposal_ref.digest,
        "resource_intent_digest": intent_ref.digest,
        "sealed_changeset_digest": seal_ref.digest,
        "validation_results_digest": validation_ref.digest,
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
        "authoritative_sequence": 1,
        "base_edition": base_edition_reference,
        "changeset": changeset_evidence,
        "created_at": EVALUATED_AT,
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
    let delta = json!({
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
    let submission_ref = store.add(
        EvidenceRole::Submission,
        ArtifactKind::OperationEffectV1,
        &submission,
    );
    let approval = json!({
        "api_version": "proof.dev/operation-effect/v1",
        "operation_kind": "changeset.approve/v2",
        "result": {
            "approval": "editorial",
            "changeset_id": CHANGESET_ID,
            "occurred_at": APPROVED_AT,
            "principal_id": HUMAN_ID,
            "sealed_changeset_digest": seal_ref.digest,
            "validation_results_digest": validation_ref.digest,
        },
    });
    let approval_ref = store.add(
        EvidenceRole::Approval,
        ArtifactKind::OperationEffectV1,
        &approval,
    );
    let environment = json!({
        "api_version": "proof.dev/environment/v1",
        "config_version": 1,
        "environment_id": ENVIRONMENT_ID,
        "policy_digest": policy_ref.digest,
        "policy_profile": RELEASE_POLICY_PROFILE,
        "required_approval": "editorial",
        "workspace_id": WORKSPACE_ID,
    });
    let environment_ref = store.add(
        EvidenceRole::EnvironmentConfig,
        ArtifactKind::EnvironmentConfigV1,
        &environment,
    );
    let policy_decision = json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": base_release_reference,
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
        "rollback_target_release_id": null,
        "workspace_id": WORKSPACE_ID,
    });
    let policy_decision_ref = store.add(
        EvidenceRole::ReleasePolicyDecision,
        ArtifactKind::AuthorizationDecisionV1,
        &policy_decision,
    );
    let release_manifest = json!({
        "api_version": "proof.dev/release/v2",
        "authorization_decision_digest": policy_decision_ref.digest,
        "base_release": base_release_reference,
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
        "release_sequence": 2,
        "released_at": EVALUATED_AT,
        "resource_intent_id": INTENT_ID,
        "rollback_target_release_id": null,
        "workspace_id": WORKSPACE_ID,
    });
    let release_manifest_ref = store.add(
        EvidenceRole::ReleaseManifest,
        ArtifactKind::ReleaseV2,
        &release_manifest,
    );
    store.add_role(EvidenceRole::ApplicationEffect, release_manifest_ref);
    let content_evidence = json!({
        "base": base_closure,
        "changeset": changeset_evidence,
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
    let mut release_statement_value = release_manifest.clone();
    release_statement_value["release_digest"] =
        serde_json::to_value(release_manifest_ref.digest).unwrap();
    let release_statement = json!({
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
                "name": "proof-verifier-independent-fixture",
                "version": "1",
            },
            "release": release_statement_value,
            "state": target_state_reference,
            "workspace_id": WORKSPACE_ID,
        },
        "predicateType": PREDICATE_TYPE,
        "subject": [
            {
                "digest": {"blake3": release_manifest_ref.digest.hex()},
                "name": format!("proof:release:{TARGET_RELEASE_ID}"),
            },
            {
                "digest": {"blake3": target_edition_ref.digest.hex()},
                "name": format!("proof:edition:{TARGET_EDITION_ID}"),
            },
        ],
    });
    let release_envelope = dsse_value(
        "application/vnd.in-toto+json",
        &release_statement,
        &[&release_key],
    );
    let release_proof_ref = store.add(
        EvidenceRole::ReleaseProofEnvelope,
        ArtifactKind::ProofEnvelopeV1,
        &release_envelope,
    );
    let localized_result = json!({
        "proof_envelope_digest": release_proof_ref.digest,
        "proof_id": PROOF_ID,
        "release_digest": release_manifest_ref.digest,
        "release_id": TARGET_RELEASE_ID,
        "release_manifest": release_manifest,
    });
    let localized_result_ref = store.add(
        EvidenceRole::LocalizedResult,
        ArtifactKind::OperationEffectV1,
        &localized_result,
    );
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
            "principal_id": HUMAN_ID,
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
    let application_idempotency = json!({"key": IDEMPOTENCY_KEY, "kind": "required"});
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

    let command_input_value = json!({
        "api_version": "proof.dev/command-input/v1",
        "delegation_id": DELEGATION_ID,
        "idempotency_key": IDEMPOTENCY_KEY,
        "normalized_input": {
            "api_version": "proof.dev/operation/release.create/v2",
            "edition_id": TARGET_EDITION_ID,
            "environment_id": ENVIRONMENT_ID,
            "expected_base_release_id": BASE_RELEASE_ID,
            "idempotency_key": IDEMPOTENCY_KEY,
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
        "idempotency_key": IDEMPOTENCY_KEY,
        "issued_at": COMMAND_ISSUED_AT,
        "operating_principal_id": AGENT_ID,
        "operation": operation,
        "presentation_id": PRESENTATION_ID,
        "requesting_principal_id": HUMAN_ID,
        "workspace_id": WORKSPACE_ID,
    });
    let command_envelope = dsse_value(
        "application/vnd.proof.authenticated-command.v1+json",
        &authenticated_command,
        &[&agent_key],
    );
    let command_envelope_ref = store.add(
        EvidenceRole::AuthenticatedCommandEnvelope,
        ArtifactKind::AuthenticatedCommandEnvelopeV1,
        &command_envelope,
    );
    let operating_subject = json!({
        "api_version": "proof.dev/authenticated-subject/v1",
        "provider": "proof/local-ed25519",
        "subject": agent_key_id,
    });
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
        "presentation_id": PRESENTATION_ID,
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
            "recorded_at": T0,
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
            "expires_at": "2027-08-21T10:00:00Z",
            "issued_at": T0,
            "issued_by_principal_id": HUMAN_ID,
            "key_usage": "authenticated-command",
            "not_before": T0,
            "principal_id": AGENT_ID,
            "principal_type": "agent",
            "public_key": agent_public_base64,
            "supersedes_binding_id": null,
            "workspace_id": WORKSPACE_ID,
        }),
        None,
        SignatureMode::Valid,
    );
    let delegation_digest = authority.append(
        json!({
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
        }),
        None,
        SignatureMode::Valid,
    );
    let previous_head = AuthorityHead {
        sequence: 4,
        record_digest: delegation_digest,
    };
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
    let decision_digest = authority.append(decision, Some(companion), signature);
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
        "presentation_id": PRESENTATION_ID,
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
    store.sort_descriptors();
    let included_head = AuthorityHead {
        sequence: 5,
        record_digest: decision_digest,
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
            "accepted_predicate_types": [PREDICATE_TYPE],
            "trusted_signers": [{
                "key_id": release_key_id,
                "not_after": null,
                "not_before": T0,
                "public_key": release_public_base64,
                "revoked_at": null,
            }],
        },
        "workspace_id": WORKSPACE_ID,
    });
    let checkpoint = json!({
        "active_authority_key_id": root_key_id,
        "api_version": proof_verifier::model::CHECKPOINT_API_VERSION,
        "authority_record_digest": decision_digest,
        "authority_sequence": 5,
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
    }
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
