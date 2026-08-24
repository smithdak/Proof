//! P-0013 Milestone 3 retained `conformanceReport` qualification scenarios as
//! executable Rust integration tests over the live
//! `proof-verifier/remote-evidence-v2` implementation:
//!
//! 1. complete exact materialization classifies `Complete`;
//! 2. required OIDC opening withheld classifies `Incomplete` (never `Invalid`,
//!    never `Complete`);
//! 3. deterministic `object_locale_revision_v1` body-byte tamper classifies
//!    `Invalid` with the exact integrity reason while every declared digest
//!    stays unchanged.
//!
//! Every produced report is serialized and validated against the frozen
//! `report` and `conformanceReport` definitions of
//! `conformance/v1/collaboration-server/schemas/remote-evidence-v2.schema.json`.
//!
//! The retained machine vector `vectors/remote-evidence-v2.valid.json` is
//! executed to the extent its shape allows: it is a normative decision
//! contract with `execution_status: normative-requirements-only` and no
//! materialized bytes, so the vector test maps its three normative scenario
//! rows onto these executed scenarios and structurally validates the produced
//! bundle descriptor, manifest, and verifier input against the Schema's frozen
//! constants (digest contexts, api versions, type strings) rather than
//! replaying retained fixture bytes.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer as _, SigningKey};
use jsonschema::{Registry, Validator};
use proof_remote::{
    COMPLETE_HTTP_OPERATION_REGISTRY_SHA256, ConformanceScenario,
    REMOTE_AUTHORIZATION_PROJECTION_SHA256, REMOTE_EVIDENCE_BUNDLE_API_VERSION,
    REMOTE_EVIDENCE_MANIFEST_API_VERSION, REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT,
    REMOTE_VERIFICATION_REPORT_API_VERSION, REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT,
    RemoteOperationV1, RemoteVerificationConformanceReportV2, RemoteVerificationReportV2,
    RemoteVerifierInputV2, VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, VerificationComponentResult,
    VerificationReasonCode, VerificationScenario, VerificationStatus, derive_key_digest,
    public_operation_input_projection_digest,
};
use proof_verifier::verify_remote_evidence_v2;
use serde_json::{Value, json};

const AUTHORITY_PAYLOAD_TYPE: &str = "application/vnd.proof.remote-authority-record.v1+json";
const COMMAND_PAYLOAD_TYPE: &str = "application/vnd.proof.authenticated-command.v1+json";
const AUTHORITY_RECORD_DIGEST_CONTEXT: &str = "proof:remote-authority-record:v1";
const RELEASE_V2_CONTEXT: &str = "proof:release:v2";
const PROOF_ENVELOPE_V1_CONTEXT: &str = "proof:proof-envelope:v1";
const ENV_CONFIG_V2_CONTEXT: &str = "proof:environment-config:v2";
const OBJECT_LOCALE_V1_CONTEXT: &str = "proof:object-locale-revision:v1";
const COMMAND_INPUT_CONTEXT: &str = "proof:command:v1";
const ENVELOPE_CONTEXT: &str = "proof:authenticated-command-envelope:v1";
const ACTOR_CONTEXT: &str = "proof:authenticated-actor-context-evidence:v2";
const AUTH_EVENT_CONTEXT: &str = "proof:remote-authentication-event:v1";
const CLOSURE_CONTEXT: &str = "proof:remote-release-artifact-closure:v1";
const RECORD_SET_CONTEXT: &str = "proof:remote-authority-record-set:v1";

/// Raw received-bytes digest contexts (frozen Schema report binding rule).
const RAW_BUNDLE_DESCRIPTOR_DIGEST_CONTEXT: &str = "proof:remote-evidence-bundle-raw:v1";
const RAW_BUNDLE_MANIFEST_DIGEST_CONTEXT: &str = "proof:remote-evidence-manifest-raw:v1";

const WORKSPACE_ID: &str = "019e0000-0000-7000-8000-000000000001";
const REQUESTING_PRINCIPAL: &str = "019e0000-0000-7000-8000-000000000002";
const OPERATING_PRINCIPAL: &str = "019e0000-0000-7000-8000-000000000003";
const REQUESTING_BINDING: &str = "019e0000-0000-7000-8000-000000000011";
const AUTH_EVENT_ID: &str = "019e0000-0000-7000-8000-000000000012";
const DELEGATION_ID: &str = "019e0000-0000-7000-8000-000000000013";
const AGENT_BINDING_ID: &str = "019e0000-0000-7000-8000-000000000014";
const PRESENTATION_ID: &str = "019e0000-0000-7000-8000-000000000015";
const DECISION_ID: &str = "019e0000-0000-7000-8000-000000000021";
const CONSEQUENCE_ID: &str = "019e0000-0000-7000-8000-000000000022";
const RELEASE_ID: &str = "019e0000-0000-7000-8000-000000000031";
const APP_KEY: &str = "019e0000-0000-7000-8000-000000000041";

const OIDC_ISSUER_DIGEST: &str =
    "blake3:abababababababababababababababababababababababababababababababab";
const SUBJECT_COMMITMENT: &str =
    "blake3:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const REQUESTING_BINDING_RECORD_DIGEST: &str =
    "blake3:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
const POLICY_BUNDLE_DIGEST: &str =
    "blake3:1111111111111111111111111111111111111111111111111111111111111111";
const ACTOR_CONTEXT_DIGEST: &str =
    "blake3:2222222222222222222222222222222222222222222222222222222222222222";
const RELEASE_POLICY_DECISION_DIGEST: &str =
    "blake3:3333333333333333333333333333333333333333333333333333333333333333";
const ZERO_DIGEST: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

const REMOTE_EVIDENCE_SCHEMA_ID: &str =
    "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2";

// ---------------------------------------------------------------------------
// Fixture helpers (copied from tests/remote_impl.rs).
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn key_id(bytes: &[u8; 32]) -> String {
    format!("ed25519:{}", hex(bytes))
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn canonical(value: &Value) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(value).expect("value always canonicalizes")
}

fn digest_str(context: &str, bytes: &[u8]) -> String {
    derive_key_digest(context, bytes).to_string()
}

fn digest_hex_of(digest: &str) -> String {
    digest.rsplit(':').next().unwrap_or_default().to_owned()
}

fn sign_dsse(payload: &[u8], payload_type: &str, key: &SigningKey, signer_id: &str) -> Vec<u8> {
    let pae = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    );
    let mut pae = pae.into_bytes();
    pae.extend_from_slice(payload);
    let signature = key.sign(&pae).to_bytes();
    let envelope = json!({
        "payloadType": payload_type,
        "payload": b64(payload),
        "signatures": [{"keyid": signer_id, "sig": b64(&signature)}],
    });
    canonical(&envelope)
}

struct Keys {
    authority: SigningKey,
    authority_key_id: String,
    authority_public_b64: String,
    release_key_id: String,
    release_public_b64: String,
    agent: SigningKey,
    agent_key_id: String,
    agent_public_b64: String,
}

fn make_keys() -> Keys {
    let authority = SigningKey::from_bytes(&[0x11; 32]);
    let authority_public = authority.verifying_key().to_bytes();
    let release = SigningKey::from_bytes(&[0x22; 32]);
    let release_public = release.verifying_key().to_bytes();
    let agent = SigningKey::from_bytes(&[0x33; 32]);
    let agent_public = agent.verifying_key().to_bytes();
    Keys {
        authority_key_id: key_id(&authority_public),
        authority_public_b64: b64(&authority_public),
        release_key_id: key_id(&release_public),
        release_public_b64: b64(&release_public),
        agent_key_id: key_id(&agent_public),
        agent_public_b64: b64(&agent_public),
        authority,
        agent,
    }
}

fn trusted_key(key_id: &str, public_b64: &str) -> Value {
    json!({
        "key_id": key_id,
        "public_key": public_b64,
        "not_before": "2026-08-01T00:00:00Z",
        "not_after": null,
        "revoked_at": null,
    })
}

fn head(sequence: u64, digest: &str) -> Value {
    json!({ "sequence": sequence, "record_digest": digest })
}

/// The exact `release.create/v2` operation selector.
fn operation() -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: "release.create".to_owned(),
        version: "proof.dev/operation/release.create/v2".to_owned(),
    }
}

/// Builds the three authority record payloads (Agent binding, decision,
/// consequence) and returns them along with their chain digests.
struct Records {
    agent_binding: Value,
    decision: Value,
    consequence: Value,
    decision_digest: String,
    consequence_digest: String,
}

#[allow(clippy::too_many_lines)]
fn build_records(
    keys: &Keys,
    command_digest: &str,
    envelope_digest: &str,
    projection_digest: &str,
) -> Records {
    let agent_binding = json!({
        "api_version": "proof.dev/principal-binding/v1",
        "authority_sequence": 2,
        "previous_authority_record_digest": ZERO_DIGEST,
        "workspace_id": WORKSPACE_ID,
        "binding_id": AGENT_BINDING_ID,
        "principal_id": OPERATING_PRINCIPAL,
        "principal_type": "agent",
        "authenticated_subject": {
            "api_version": "proof.dev/authenticated-subject/v1",
            "provider": "proof/local-ed25519",
            "subject": keys.agent_key_id,
        },
        "algorithm": "ed25519",
        "public_key": keys.agent_public_b64,
        "key_usage": "authenticated-command",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "enrollment_challenge_digest": ZERO_DIGEST,
        "enrollment_envelope_digest": ZERO_DIGEST,
        "issued_by_principal_id": REQUESTING_PRINCIPAL,
        "issued_at": "2026-08-23T00:00:00Z",
        "not_before": "2026-08-23T00:00:00Z",
        "expires_at": "2026-08-24T00:00:00Z",
        "supersedes_binding_id": null,
    });
    let agent_binding_digest =
        digest_str(AUTHORITY_RECORD_DIGEST_CONTEXT, &canonical(&agent_binding));

    let decision = json!({
        "api_version": "proof.dev/remote-authorization-decision/v1",
        "authentication_profile": "proof.server/authentication/oidc-human-agent/v1",
        "authorization_registry_sha256": REMOTE_AUTHORIZATION_PROJECTION_SHA256,
        "operation_registry_sha256": COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "authorization_rule": "proof.local/authority/direct/v1",
        "workspace_id": WORKSPACE_ID,
        "decision_id": DECISION_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "requested_action": "release:create",
        "public_input_projection_digest": projection_digest,
        "actor_context_digest": ACTOR_CONTEXT_DIGEST,
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "requesting_binding_id": REQUESTING_BINDING,
        "requesting_binding_record_digest": REQUESTING_BINDING_RECORD_DIGEST,
        "requesting_subject_commitment": SUBJECT_COMMITMENT,
        "agent_authorization": {
            "command_digest": command_digest,
            "command_envelope_digest": envelope_digest,
            "presentation_id": PRESENTATION_ID,
            "presentation_consumed": false,
            "operating_principal_id": OPERATING_PRINCIPAL,
            "principal_state": {"requesting_principal_enabled": true, "operating_principal_enabled": true},
            "binding": {
                "active": true,
                "binding_id": AGENT_BINDING_ID,
                "authority_sequence": 2,
                "record_digest": agent_binding_digest,
                "revocation_record_digest": null
            },
            "delegation": {
                "delegation_id": DELEGATION_ID,
                "record_digest": ZERO_DIGEST,
                "revocation_record_digest": null,
                "resolution": "resolved"
            },
            "policy_profile": "proof.local/authority/direct/v1",
            "policy_bundle_digest": POLICY_BUNDLE_DIGEST,
            "requested_resources": {
                "workspace_ids": [], "environment_ids": [], "object_ids": [],
                "schema_ids": [], "locales": [], "changeset_ids": [],
                "edition_ids": [], "release_ids": []
            },
            "effective_constraints": {
                "max_objects": 100, "max_context_bytes": 1_048_576, "max_edits_per_changeset": 100
            }
        },
        "role_assignment_digests": [],
        "requested_resources_digest": ZERO_DIGEST,
        "policy_bundle_digest": ZERO_DIGEST,
        "environment_config_digest": null,
        "decision": "allow",
        "public_code": null,
        "reason_code": "proof.authorization.allowed",
        "evaluated_at": "2026-08-23T02:00:00Z",
        "evaluated_authority_head": head(2, &agent_binding_digest),
        "authority_sequence": 3,
        "previous_authority_record_digest": agent_binding_digest,
        "authority_key_id": keys.authority_key_id,
    });
    let decision_digest = digest_str(AUTHORITY_RECORD_DIGEST_CONTEXT, &canonical(&decision));

    let release_v2_digest = digest_str(RELEASE_V2_CONTEXT, &canonical(&json!({"kind": "release"})));
    let consequence = json!({
        "api_version": "proof.dev/remote-application-consequence/v1",
        "workspace_id": WORKSPACE_ID,
        "consequence_id": CONSEQUENCE_ID,
        "decision_id": DECISION_ID,
        "decision_digest": decision_digest,
        "public_input_projection_digest": projection_digest,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "operation_registry_sha256": COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "outcome": "success",
        "application_key_kind": "required-uuidv7",
        "application_key": APP_KEY,
        "result_digest": ZERO_DIGEST,
        "prior_result_digest": null,
        "application_effect_digest": release_v2_digest,
        "application_effect_authority_head": null,
        "problem_code": null,
        "recorded_at": "2026-08-23T02:00:01Z",
        "evaluated_authority_head": head(3, &decision_digest),
        "authority_sequence": 4,
        "previous_authority_record_digest": decision_digest,
        "authority_key_id": keys.authority_key_id,
    });
    let consequence_digest = digest_str(AUTHORITY_RECORD_DIGEST_CONTEXT, &canonical(&consequence));

    Records {
        agent_binding,
        decision,
        consequence,
        decision_digest,
        consequence_digest,
    }
}

/// Signs a set of record payloads into a `RemoteAuthorityRecordSetV1` value.
fn record_set_value(keys: &Keys, payloads: &[&Value], included_head: &Value) -> Value {
    let records: Vec<Value> = payloads
        .iter()
        .map(|payload| {
            let bytes = canonical(payload);
            serde_json::from_slice(&sign_dsse(
                &bytes,
                AUTHORITY_PAYLOAD_TYPE,
                &keys.authority,
                &keys.authority_key_id,
            ))
            .expect("envelope is valid JSON")
        })
        .collect();
    json!({
        "api_version": "proof.dev/remote-authority-record-set/v1",
        "workspace_id": WORKSPACE_ID,
        "base_head": head(1, ZERO_DIGEST),
        "record_order": "decoded authority_sequence ascending and contiguous",
        "records": records,
        "included_head": included_head,
    })
}

/// Builds a nested artifact body and returns `(bytes, digest)`.
fn nested_artifact(content: &Value, digest_context: &str) -> (Vec<u8>, String) {
    let bytes = canonical(content);
    let digest = digest_str(digest_context, &bytes);
    (bytes, digest)
}

/// Assembles the complete logical member map and verifier input.
struct Fixture {
    members: BTreeMap<String, Vec<u8>>,
    input: RemoteVerifierInputV2,
}

#[allow(clippy::too_many_lines)]
fn assemble(
    keys: &Keys,
    record_payloads: &[&Value],
    included_head: &Value,
    decision_digest: &str,
    consequence_digest: &str,
    policy_value: &Value,
    trust_policy_digest: &str,
) -> Fixture {
    // Nested artifacts.
    let (release_bytes, release_digest) =
        nested_artifact(&json!({"kind": "release"}), RELEASE_V2_CONTEXT);
    let (proof_bytes, proof_digest) =
        nested_artifact(&json!({"kind": "proof"}), PROOF_ENVELOPE_V1_CONTEXT);
    let (env_bytes, env_digest) = nested_artifact(&json!({"kind": "env"}), ENV_CONFIG_V2_CONTEXT);
    let (locale_bytes, locale_digest) =
        nested_artifact(&json!({"kind": "locale"}), OBJECT_LOCALE_V1_CONTEXT);

    let operation = operation();
    let normalized_input = json!({"release_name": "preview"});
    let projection_digest = public_operation_input_projection_digest(&normalized_input, &operation)
        .expect("projection digests")
        .to_string();

    // Command input and authenticated command.
    let command_input = json!({
        "api_version": "proof.dev/command-input/v1",
        "workspace_id": WORKSPACE_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "operating_principal_id": OPERATING_PRINCIPAL,
        "delegation_id": DELEGATION_ID,
        "idempotency_key": APP_KEY,
        "normalized_input": normalized_input,
    });
    let command_input_bytes = canonical(&command_input);
    let command_digest = digest_str(COMMAND_INPUT_CONTEXT, &command_input_bytes);

    let command = json!({
        "api_version": "proof.dev/authenticated-command/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "workspace_id": WORKSPACE_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "binding_id": AGENT_BINDING_ID,
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "operating_principal_id": OPERATING_PRINCIPAL,
        "delegation_id": DELEGATION_ID,
        "command_digest": command_digest,
        "idempotency_key": APP_KEY,
        "presentation_id": PRESENTATION_ID,
        "issued_at": "2026-08-23T01:59:00Z",
        "expires_at": "2026-08-23T02:05:00Z",
    });
    let command_payload = canonical(&command);
    let envelope_bytes = sign_dsse(
        &command_payload,
        COMMAND_PAYLOAD_TYPE,
        &keys.agent,
        &keys.agent_key_id,
    );
    let envelope_digest = digest_str(ENVELOPE_CONTEXT, &envelope_bytes);

    // Authentication event and actor evidence.
    let auth_event = json!({
        "api_version": "proof.dev/remote-authentication-event/v1",
        "workspace_id": WORKSPACE_ID,
        "authentication_event_id": AUTH_EVENT_ID,
        "authentication_method": "oidc-authorization-code-pkce-s256",
        "oidc_issuer_configuration_digest": OIDC_ISSUER_DIGEST,
        "requesting_subject_commitment": SUBJECT_COMMITMENT,
        "requesting_binding_id": REQUESTING_BINDING,
        "requesting_binding_record_digest": REQUESTING_BINDING_RECORD_DIGEST,
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "authenticated_at": "2026-08-23T02:00:00Z",
        "expires_at": "2026-08-23T08:00:00Z",
    });
    let auth_event_bytes = canonical(&auth_event);
    let auth_event_digest = digest_str(AUTH_EVENT_CONTEXT, &auth_event_bytes);

    let actor_evidence = json!({
        "api_version": "proof.dev/authenticated-actor-context-evidence/v2",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "authentication_profile": "proof.server/authentication/oidc-human-agent/v1",
        "oidc_issuer_configuration_digest": OIDC_ISSUER_DIGEST,
        "public_input_projection_digest": projection_digest,
        "requesting_subject_commitment": SUBJECT_COMMITMENT,
        "requesting_binding_id": REQUESTING_BINDING,
        "requesting_binding_record_digest": REQUESTING_BINDING_RECORD_DIGEST,
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "authentication_event_id": AUTH_EVENT_ID,
        "authentication_event_digest": auth_event_digest,
        "operating_subject": {
            "api_version": "proof.dev/authenticated-subject/v1",
            "provider": "proof/local-ed25519",
            "subject": keys.agent_key_id,
        },
        "operating_binding": {
            "authority_sequence": 2,
            "binding_id": AGENT_BINDING_ID,
            "record_digest": ZERO_DIGEST,
        },
        "operating_principal_id": OPERATING_PRINCIPAL,
        "delegation_id": DELEGATION_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "command_digest": command_digest,
        "command_envelope_digest": envelope_digest,
        "presentation_id": PRESENTATION_ID,
        "authenticated_at": "2026-08-23T02:00:00Z",
        "evaluated_authority_head": head(2, ZERO_DIGEST),
        "workspace_id": WORKSPACE_ID,
    });
    let actor_bytes = canonical(&actor_evidence);
    let actor_digest = digest_str(ACTOR_CONTEXT, &actor_bytes);

    // Release-artifact closure.
    let closure = json!({
        "api_version": "proof.dev/remote-release-artifact-closure/v1",
        "workspace_id": WORKSPACE_ID,
        "artifact_order": "artifact_kind, digest UTF-8 bytewise ascending",
        "artifacts": [
            {
                "artifact": {"artifact_kind": "environment_config_v2_projection", "digest": env_digest},
                "availability": {"state": "included", "byte_length": env_bytes.len() as u64}
            },
            {
                "artifact": {"artifact_kind": "object_locale_revision_v1", "digest": locale_digest},
                "availability": {"state": "included", "byte_length": locale_bytes.len() as u64}
            },
            {
                "artifact": {"artifact_kind": "proof_envelope_v1", "digest": proof_digest},
                "availability": {"state": "included", "byte_length": proof_bytes.len() as u64}
            },
            {
                "artifact": {"artifact_kind": "release_v2", "digest": release_digest},
                "availability": {"state": "included", "byte_length": release_bytes.len() as u64}
            }
        ],
        "role_binding_order": "role, artifact_kind, digest UTF-8 bytewise ascending",
        "role_bindings": [
            {"artifact": {"artifact_kind": "release_v2", "digest": release_digest}, "role": "application_effect"},
            {"artifact": {"artifact_kind": "environment_config_v2_projection", "digest": env_digest}, "role": "environment_config"},
            {"artifact": {"artifact_kind": "release_v2", "digest": release_digest}, "role": "release_manifest"},
            {"artifact": {"artifact_kind": "proof_envelope_v1", "digest": proof_digest}, "role": "release_proof_envelope"}
        ],
        "entrypoints": {
            "target_release_manifest": {"artifact_kind": "release_v2", "digest": release_digest},
            "target_release_proof_envelope": {"artifact_kind": "proof_envelope_v1", "digest": proof_digest},
            "target_environment_config": {"artifact_kind": "environment_config_v2_projection", "digest": env_digest},
            "application_effect": {"artifact_kind": "release_v2", "digest": release_digest},
            "result_derivation": "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest"
        }
    });
    let closure_bytes = canonical(&closure);
    let closure_digest = digest_str(CLOSURE_CONTEXT, &closure_bytes);

    // Authority record set.
    let record_set = record_set_value(keys, record_payloads, included_head);
    let record_set_bytes = canonical(&record_set);
    let record_set_digest = digest_str(RECORD_SET_CONTEXT, &record_set_bytes);

    // Closure bindings.
    let closure_bindings = json!({
        "api_version": "proof.dev/remote-evidence-closure-bindings/v1",
        "artifact_closure": {
            "api_version": "proof.dev/remote-release-artifact-closure/v1",
            "manifest_member_path": "content/release-closure.json",
            "manifest_digest": closure_digest,
            "digest_context": CLOSURE_CONTEXT,
            "artifact_root_prefix": "content/artifacts/",
            "verification_profile": "proof-verifier/accepted-release-artifact-semantics-v1",
            "authority_entrypoint": "none; remote authority is verified only through closure_bindings.remote_authority"
        },
        "cross_links": {
            "workspace_id": WORKSPACE_ID,
            "requesting_principal_id": REQUESTING_PRINCIPAL,
            "operating_principal_id": OPERATING_PRINCIPAL,
            "delegation_id": DELEGATION_ID,
            "presentation_id": PRESENTATION_ID,
            "command_digest": command_digest,
            "authenticated_command_envelope_digest": envelope_digest,
            "public_input_projection_digest": projection_digest,
            "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
            "application_key_kind": "required-uuidv7",
            "application_key": APP_KEY,
            "environment_config_digest": env_digest,
            "environment_config_version": 2,
            "release_id": RELEASE_ID,
            "release_digest": release_digest,
            "release_policy_decision_digest": RELEASE_POLICY_DECISION_DIGEST,
            "release_proof_envelope_digest": proof_digest,
            "result_digest": ZERO_DIGEST,
            "application_effect_digest": release_digest
        },
        "remote_authority": {
            "record_set_member_path": "authority/facts.json",
            "record_set_digest": record_set_digest,
            "digest_context": RECORD_SET_CONTEXT,
            "head": included_head,
            "target_decision_digest": decision_digest,
            "target_consequence_digest": consequence_digest,
            "verifier_profile": "proof-verifier/remote-authority/v1"
        },
        "remote_attempt_companions": {
            "profile": "agent-release-create-v2-success",
            "actor_context_evidence": {
                "member_path": "actor/context-evidence.json",
                "record_digest": actor_digest,
                "digest_context": ACTOR_CONTEXT,
                "schema_id": "proof.authenticated-actor-context-evidence/v2",
                "schema_version": 2
            },
            "authentication_event": {
                "member_path": "authentication/event.json",
                "record_digest": auth_event_digest,
                "digest_context": AUTH_EVENT_CONTEXT,
                "schema_id": "proof.remote-authentication-event/v1",
                "schema_version": 1
            },
            "command_input": {
                "member_path": "attempt/command-input.json",
                "record_digest": command_digest,
                "digest_context": COMMAND_INPUT_CONTEXT,
                "schema_id": "proof.command-input/v1",
                "schema_version": 1
            },
            "authenticated_command_envelope": {
                "member_path": "attempt/authenticated-command-envelope.json",
                "record_digest": envelope_digest,
                "digest_context": ENVELOPE_CONTEXT,
                "schema_id": "proof.authenticated-command-envelope/v1",
                "schema_version": 1
            },
            "public_input_projection_rule": "reconstruct proof.dev/public-operation-input-projection/v1 from exact CommandInputV1.normalized_input and release.create/v2 operation, then recompute proof:public-operation-input-projection:v1",
            "result_rule": "reconstruct exact ReleaseCreateOutputV2 from the artifact closure target ReleaseV2 and target Release Proof envelope digest, then recompute proof:operation-effect:v1",
            "application_effect_rule": "application_effect_digest equals the artifact closure target ReleaseV2 digest under proof:release:v2"
        }
    });

    // Manifest.
    let manifest = json!({
        "type": "RemoteEvidenceManifestV2",
        "api_version": "proof.dev/remote-evidence-manifest/v2",
        "workspace_id": WORKSPACE_ID,
        "export_id": "019e0000-0000-7000-8000-000000000051",
        "snapshot_id": "snapshot_0102030405060708090a0b0c0d0e0f10",
        "snapshot_boundary": "pre-export-attempt-locked-heads",
        "capture_digest": ZERO_DIGEST,
        "release_id": RELEASE_ID,
        "release_digest": release_digest,
        "closure_bindings": closure_bindings,
        "disclosure_profile": "complete-portable",
        "heads": {
            "authority": included_head["record_digest"].clone(),
            "content": ZERO_DIGEST,
            "release": release_digest,
            "environment": env_digest,
            "outbox": ZERO_DIGEST
        },
        "membership_order": "member_path UTF-8 bytewise ascending",
        "membership": [
            {
                "member_path": "actor/context-evidence.json",
                "artifact_kind": "remote-actor-evidence",
                "schema_id": "proof.authenticated-actor-context-evidence/v2",
                "schema_version": 2,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": ACTOR_CONTEXT,
                "byte_length": actor_bytes.len() as u64,
                "content_digest": actor_digest,
                "delivery": "included",
                "disclosure_id": null
            },
            {
                "member_path": "attempt/authenticated-command-envelope.json",
                "artifact_kind": "remote-authenticated-command-envelope",
                "schema_id": "proof.authenticated-command-envelope/v1",
                "schema_version": 1,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": ENVELOPE_CONTEXT,
                "byte_length": envelope_bytes.len() as u64,
                "content_digest": envelope_digest,
                "delivery": "included",
                "disclosure_id": null
            },
            {
                "member_path": "attempt/command-input.json",
                "artifact_kind": "remote-command-input",
                "schema_id": "proof.command-input/v1",
                "schema_version": 1,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": COMMAND_INPUT_CONTEXT,
                "byte_length": command_input_bytes.len() as u64,
                "content_digest": command_digest,
                "delivery": "included",
                "disclosure_id": null
            },
            {
                "member_path": "authentication/event.json",
                "artifact_kind": "remote-authentication-event",
                "schema_id": "proof.remote-authentication-event/v1",
                "schema_version": 1,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": AUTH_EVENT_CONTEXT,
                "byte_length": auth_event_bytes.len() as u64,
                "content_digest": auth_event_digest,
                "delivery": "included",
                "disclosure_id": null
            },
            {
                "member_path": "authority/facts.json",
                "artifact_kind": "authority-fact",
                "schema_id": "proof.remote-authority-record-set/v1",
                "schema_version": 1,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": RECORD_SET_CONTEXT,
                "byte_length": record_set_bytes.len() as u64,
                "content_digest": record_set_digest,
                "delivery": "included",
                "disclosure_id": null
            },
            {
                "member_path": "content/release-closure.json",
                "artifact_kind": "release-artifact-closure",
                "schema_id": "proof.remote-release-artifact-closure/v1",
                "schema_version": 1,
                "media_type": "application/json",
                "canonicalization": "RFC8785",
                "digest_context": CLOSURE_CONTEXT,
                "byte_length": closure_bytes.len() as u64,
                "content_digest": closure_digest,
                "delivery": "included",
                "disclosure_id": null
            }
        ],
        "disclosure_order": "disclosure_id UTF-8 bytewise ascending",
        "disclosures": [
            {
                "disclosure_id": "disclosure:subject-opening",
                "kind": "oidc-subject-opening",
                "commitment_digest": SUBJECT_COMMITMENT
            }
        ]
    });
    let manifest_bytes = canonical(&manifest);

    // Bundle descriptor.
    let bundle = json!({
        "type": "RemoteEvidenceBundleV2",
        "api_version": "proof.dev/remote-evidence-bundle/v2",
        "bundle_descriptor_path": "bundle.json",
        "manifest_member_path": "manifest.json",
        "workspace_id": WORKSPACE_ID,
        "export_id": "019e0000-0000-7000-8000-000000000051",
        "snapshot_id": "snapshot_0102030405060708090a0b0c0d0e0f10",
        "snapshot_claim": "unauthenticated producer snapshot label; no current, latest, capture-integrity, or readiness claim",
        "snapshot_heads": {
            "authority": included_head["record_digest"].clone(),
            "content": ZERO_DIGEST,
            "release": release_digest,
            "environment": env_digest,
            "outbox": ZERO_DIGEST
        },
        "manifest_digest": digest_str("proof:remote-evidence-manifest:v2", &manifest_bytes),
        "portable_payload_contract": {
            "artifact_closure_api_version": "proof.dev/remote-release-artifact-closure/v1",
            "artifact_closure_member_path": "content/release-closure.json",
            "artifact_closure_digest": closure_digest,
            "artifact_verifier_profile": "proof-verifier/accepted-release-artifact-semantics-v1",
            "remote_record_set_member_path": "authority/facts.json",
            "remote_record_set_digest": record_set_digest,
            "remote_verifier_profile": "proof-verifier/remote-authority/v1",
            "composed_verifier_profile": "proof-verifier/remote-evidence-v2",
            "composition": "verify-accepted-artifact-release-closure-p8-remote-authority-and-attempt-companions-then-enforce-cross-links",
            "included_bytes_rule": "retain the exact outer manifest, release-artifact closure manifest and every selected accepted artifact, P8 record set and every remote-authority envelope, and all selected actor, authentication, CommandInputV1, and authenticated-command-envelope companion bytes",
            "p6_compatibility": "historical AuthorityEvidenceBundleV1 and its verifier remain unchanged and are not relabeled or executed for the remote attempt"
        },
        "untrusted_hints": {
            "authority_root_ids": [],
            "release_root_ids": [],
            "checkpoint_ids": [],
            "resolver_urls": [],
            "trusted": false,
            "auto_fetch": false
        }
    });

    let mut members = BTreeMap::new();
    members.insert("bundle.json".to_owned(), canonical(&bundle));
    members.insert("manifest.json".to_owned(), manifest_bytes);
    members.insert("content/release-closure.json".to_owned(), closure_bytes);
    members.insert("authority/facts.json".to_owned(), record_set_bytes);
    members.insert("actor/context-evidence.json".to_owned(), actor_bytes);
    members.insert("authentication/event.json".to_owned(), auth_event_bytes);
    members.insert("attempt/command-input.json".to_owned(), command_input_bytes);
    members.insert(
        "attempt/authenticated-command-envelope.json".to_owned(),
        envelope_bytes,
    );
    members.insert(
        format!(
            "content/artifacts/release_v2/blake3/{}.json",
            digest_hex_of(&release_digest)
        ),
        release_bytes,
    );
    members.insert(
        format!(
            "content/artifacts/proof_envelope_v1/blake3/{}.json",
            digest_hex_of(&proof_digest)
        ),
        proof_bytes,
    );
    members.insert(
        format!(
            "content/artifacts/environment_config_v2_projection/blake3/{}.json",
            digest_hex_of(&env_digest)
        ),
        env_bytes,
    );
    members.insert(
        format!(
            "content/artifacts/object_locale_revision_v1/blake3/{}.json",
            digest_hex_of(&locale_digest)
        ),
        locale_bytes,
    );

    let input_json = json!({
        "type": "RemoteVerifierInputV2",
        "api_version": "proof.dev/remote-verifier-input/v2",
        "verification_trust_policy": policy_value,
        "trust_policy_digest": trust_policy_digest,
        "subject_openings": [],
        "authority_checkpoint": null,
        "environment_release_checkpoint": null,
        "external_artifacts": [],
        "bundle_hints_are_authority": false,
        "network_access": false,
        "database_access": false,
        "session_access": false,
        "private_key_count": 0,
        "credential_count": 0
    });
    let input: RemoteVerifierInputV2 = serde_json::from_value(input_json).expect("valid input");

    Fixture { members, input }
}

fn build_policy(
    keys: &Keys,
    authorization_registry_hashes: &[&str],
    operation_registry_hashes: &[&str],
    disclosure_required: bool,
) -> (Value, String) {
    let policy = json!({
        "api_version": "proof.dev/verification-trust-policy/v2",
        "workspace_id": WORKSPACE_ID,
        "registry_resolution": {
            "profile": "proof.verifier/collaboration-registry/v1",
            "source": "verifier-built-in-closed-hash-to-rfc8785-document-table",
            "unknown_hash_result": "Invalid",
            "hash_mismatch_result": "Invalid"
        },
        "authority": {
            "initial_root": trusted_key(&keys.authority_key_id, &keys.authority_public_b64),
            "initial_head": head(1, ZERO_DIGEST),
            "accepted_authorization_registry_hashes": authorization_registry_hashes,
            "accepted_operation_registry_hashes": operation_registry_hashes,
            "accepted_policy_bundles": [
                {"policy_profile": "proof.local/authority/direct/v1", "policy_bundle_digest": POLICY_BUNDLE_DIGEST}
            ],
            "checkpoint_requirement": "internal_prefix_only",
            "compromise_cutoff": null
        },
        "release": {
            "trusted_signers": [trusted_key(&keys.release_key_id, &keys.release_public_b64)],
            "accepted_predicate_types": ["urn:proof:attestation:release:v2"],
            "accepted_policy_profiles": [
                {"policy_profile": "proof.local/release-policy/v1", "environment_config_digest": ZERO_DIGEST}
            ]
        },
        "remote_identity": {
            "accepted_oidc_issuer_configuration_digests": [OIDC_ISSUER_DIGEST]
        },
        "disclosure": {
            "requesting_subject_opening": if disclosure_required { "required" } else { "optional" }
        },
        "limits": {
            "max_verifier_input_bytes": 268_435_456,
            "max_manifest_bytes": 4_194_304,
            "max_artifacts": 4096,
            "max_authority_records": 512,
            "max_artifact_bytes": 4_194_304,
            "max_total_bytes": 268_435_456,
            "max_json_depth": 128
        }
    });
    let bytes = canonical(&policy);
    let digest = derive_key_digest(VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, &bytes).to_string();
    (policy, digest)
}

/// Builds a complete, well-formed fixture with the standard three records.
fn build_standard(disclosure_required: bool) -> (Keys, Fixture, Records, Value) {
    let keys = make_keys();
    let (policy, policy_digest) = build_policy(
        &keys,
        &[REMOTE_AUTHORIZATION_PROJECTION_SHA256],
        &[COMPLETE_HTTP_OPERATION_REGISTRY_SHA256],
        disclosure_required,
    );
    let projection_digest = {
        let normalized_input = json!({"release_name": "preview"});
        public_operation_input_projection_digest(&normalized_input, &operation())
            .expect("projection")
            .to_string()
    };
    let command_input = json!({
        "api_version": "proof.dev/command-input/v1",
        "workspace_id": WORKSPACE_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "operating_principal_id": OPERATING_PRINCIPAL,
        "delegation_id": DELEGATION_ID,
        "idempotency_key": APP_KEY,
        "normalized_input": {"release_name": "preview"},
    });
    let command_digest = digest_str(COMMAND_INPUT_CONTEXT, &canonical(&command_input));
    let command = json!({
        "api_version": "proof.dev/authenticated-command/v1",
        "audience": format!("proof://workspace/{WORKSPACE_ID}"),
        "workspace_id": WORKSPACE_ID,
        "operation": {"name": "release.create", "version": "proof.dev/operation/release.create/v2"},
        "binding_id": AGENT_BINDING_ID,
        "requesting_principal_id": REQUESTING_PRINCIPAL,
        "operating_principal_id": OPERATING_PRINCIPAL,
        "delegation_id": DELEGATION_ID,
        "command_digest": command_digest,
        "idempotency_key": APP_KEY,
        "presentation_id": PRESENTATION_ID,
        "issued_at": "2026-08-23T01:59:00Z",
        "expires_at": "2026-08-23T02:05:00Z",
    });
    let envelope_bytes = sign_dsse(
        &canonical(&command),
        COMMAND_PAYLOAD_TYPE,
        &keys.agent,
        &keys.agent_key_id,
    );
    let envelope_digest = digest_str(ENVELOPE_CONTEXT, &envelope_bytes);

    let records = build_records(&keys, &command_digest, &envelope_digest, &projection_digest);
    let payloads: Vec<&Value> = vec![
        &records.agent_binding,
        &records.decision,
        &records.consequence,
    ];
    let included_head = head(4, &records.consequence_digest);
    let fixture = assemble(
        &keys,
        &payloads,
        &included_head,
        &records.decision_digest,
        &records.consequence_digest,
        &policy,
        &policy_digest,
    );
    (keys, fixture, records, policy)
}

// ---------------------------------------------------------------------------
// Scenario executions.
// ---------------------------------------------------------------------------

/// Executes Scenario 1: full exact materialization, all caller trust inputs
/// supplied, disclosure policy optional.
fn execute_complete() -> (RemoteVerificationReportV2, Fixture) {
    let (_keys, fixture, _records, _policy) = build_standard(false);
    let report = verify_remote_evidence_v2(&fixture.members, &fixture.input);
    (report, fixture)
}

/// Executes Scenario 2: identical materialization under a caller disclosure
/// policy requiring the requesting-subject opening, which is withheld.
fn execute_incomplete_withheld_opening() -> RemoteVerificationReportV2 {
    let (_keys, fixture, _records, _policy) = build_standard(true);
    verify_remote_evidence_v2(&fixture.members, &fixture.input)
}

/// Executes Scenario 3: flips one byte inside the assembled
/// `object_locale_revision_v1` member body after assembly while every declared
/// digest stays unchanged. Returns the report plus the tampered deterministic
/// path and the original body bytes.
fn execute_locale_byte_tamper() -> (RemoteVerificationReportV2, String, Vec<u8>) {
    let (_keys, mut fixture, _records, _policy) = build_standard(false);
    let path = fixture
        .members
        .keys()
        .find(|path| path.starts_with("content/artifacts/object_locale_revision_v1/"))
        .cloned()
        .expect("nested object_locale_revision_v1 member present");
    let mut bytes = fixture.members.get(&path).expect("member body").clone();
    let original = bytes.clone();

    // The declared closure descriptor commits exactly the assembled body.
    let closure_before = fixture
        .members
        .get("content/release-closure.json")
        .expect("closure member")
        .clone();
    let closure_value: Value =
        serde_json::from_slice(&closure_before).expect("closure parses as JSON");
    let declared = closure_value["artifacts"]
        .as_array()
        .expect("closure artifacts")
        .iter()
        .find(|descriptor| descriptor["artifact"]["artifact_kind"] == "object_locale_revision_v1")
        .expect("declared object_locale_revision_v1 descriptor")
        .clone();
    assert_eq!(
        declared["artifact"]["digest"].as_str(),
        Some(digest_str(OBJECT_LOCALE_V1_CONTEXT, &original).as_str()),
        "the descriptor must commit the pre-tamper body digest"
    );

    // Flip one body byte after assembly; declared digests stay unchanged.
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    assert_ne!(bytes, original, "the flip must change the body byte");
    fixture.members.insert(path.clone(), bytes);
    assert_eq!(
        fixture.members.get("content/release-closure.json"),
        Some(&closure_before),
        "the closure bytes committing the declared digests must stay unchanged"
    );
    assert_eq!(
        declared["availability"]["byte_length"].as_u64(),
        Some(original.len() as u64),
        "the declared byte length must remain unchanged"
    );

    let report = verify_remote_evidence_v2(&fixture.members, &fixture.input);
    (report, path, original)
}

// ---------------------------------------------------------------------------
// Schema validation helpers (pattern of
// crates/proof-local/tests/p0008_collaboration_contract.rs).
// ---------------------------------------------------------------------------

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Registry over the full collaboration Schema graph (the remote-evidence
/// Schema's external `$ref` targets resolve transitively into the authority
/// and localized-content Schema directories).
fn evidence_schema_registry() -> Registry<'static> {
    let root = repository_root();
    let mut schema_paths: Vec<PathBuf> = [
        "remote-evidence-v2.schema.json",
        "collaboration-artifacts-v1.schema.json",
        "remote-auth-v1.schema.json",
    ]
    .into_iter()
    .map(|name| {
        root.join("conformance/v1/collaboration-server/schemas")
            .join(name)
    })
    .collect();
    for path in [
        "conformance/v1/authority/schemas/authenticated-invocation-v1.schema.json",
        "conformance/v1/authority/schemas/authenticated-subject-v1.schema.json",
        "conformance/v1/authority/schemas/command-input-v1.schema.json",
        "conformance/v1/authority/schemas/delegation-revocation-v1.schema.json",
        "conformance/v1/authority/schemas/delegation-v2.schema.json",
        "conformance/v1/authority/schemas/operation-v1.schema.json",
        "conformance/v1/authority/schemas/authority-operation-registry-v1.schema.json",
        "conformance/v1/authority/schemas/authorization-decision-v2.schema.json",
        "conformance/v1/authority/schemas/principal-binding-revocation-v1.schema.json",
        "conformance/v1/authority/schemas/principal-binding-v1.schema.json",
        "conformance/v2/localized-content/schemas/artifacts.schema.json",
        "conformance/v2/localized-content/schemas/operations.schema.json",
    ] {
        schema_paths.push(root.join(path));
    }

    let mut registry = Registry::new();
    for path in schema_paths {
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let schema: Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let id = schema["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} must declare $id", path.display()))
            .to_owned();
        registry = registry
            .add(id, schema)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    }
    registry
        .prepare()
        .expect("the remote-evidence Schema graph must resolve")
}

fn def_validator(registry: &Registry<'_>, def: &str) -> Validator {
    jsonschema::options()
        .with_registry(registry)
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": format!("{REMOTE_EVIDENCE_SCHEMA_ID}#/$defs/{def}"),
        }))
        .unwrap_or_else(|error| panic!("$defs/{def}: {error}"))
}

fn assert_schema_valid(validator: &Validator, label: &str, value: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "{label} violates the frozen Schema: {errors:?}"
    );
}

/// Narrows a general report to the retained three-scenario subtype and asserts
/// the narrowing is consistent with the inner general scenario.
fn narrow_to_conformance(
    report: &RemoteVerificationReportV2,
) -> RemoteVerificationConformanceReportV2 {
    let scenario =
        ConformanceScenario::from_verification_scenario(report.scenario).unwrap_or_else(|| {
            panic!(
                "{:?} must narrow to a retained conformance scenario",
                report.scenario
            )
        });
    let conformance = RemoteVerificationConformanceReportV2 {
        report: report.clone(),
        scenario,
    };
    assert!(conformance.is_consistent());
    conformance
}

/// Serializes one produced report, checks its frozen wire tags, and validates
/// it against both the general closed `report` definition and the narrower
/// three-scenario `conformanceReport` subtype.
fn assert_report_matches_conformance_subtype(
    registry: &Registry<'_>,
    report: &RemoteVerificationReportV2,
) {
    let value = serde_json::to_value(report).expect("report serializes");
    assert_eq!(value["type"], "RemoteVerificationReportV2");
    assert_eq!(value["api_version"], REMOTE_VERIFICATION_REPORT_API_VERSION);
    assert_eq!(
        value["verifier_profile"],
        "proof-verifier/remote-evidence-v2"
    );
    assert_eq!(value["claim_kind"], "observed-verifier-outcome");
    let general = def_validator(registry, "report");
    let narrowed = def_validator(registry, "conformanceReport");
    assert_schema_valid(&general, "general report", &value);
    assert_schema_valid(&narrowed, "conformanceReport subtype", &value);
}

// ---------------------------------------------------------------------------
// Scenario 1: complete exact materialization.
// ---------------------------------------------------------------------------

#[test]
fn scenario_complete_exact_materialization_classifies_complete_and_conforms() {
    let (report, _fixture) = execute_complete();

    // Exact classification.
    assert_eq!(report.status, VerificationStatus::Complete);
    assert_eq!(
        report.scenario,
        VerificationScenario::CompleteExactMaterialization
    );
    assert_eq!(report.reason_codes, vec![VerificationReasonCode::Verified]);
    assert!(report.runtime_observed);

    // Component results: every requested component verified; delivery
    // evidence is not-requested for this claim.
    let c = &report.components;
    for (name, result) in [
        ("signature", c.signature),
        ("actor", c.actor),
        ("authority", c.authority),
        ("role_separation", c.role_separation),
        ("approval", c.approval),
        ("policy", c.policy),
        ("content", c.content),
        ("environment", c.environment),
        ("release", c.release),
        ("completeness", c.completeness),
    ] {
        assert_eq!(
            result,
            VerificationComponentResult::Verified,
            "component {name} must be verified in the Complete report"
        );
    }
    assert_eq!(
        c.delivery_evidence,
        VerificationComponentResult::NotRequested
    );
    assert_eq!(report.primary_reason(), VerificationReasonCode::Verified);

    // The report narrows to the retained conformance subtype and serializes
    // consistently with the Schema rules.
    let registry = evidence_schema_registry();
    narrow_to_conformance(&report);
    assert_report_matches_conformance_subtype(&registry, &report);
}

// ---------------------------------------------------------------------------
// Scenario 2: required opening withheld.
// ---------------------------------------------------------------------------

#[test]
fn scenario_incomplete_required_opening_withheld_is_exact_and_never_invalid_or_complete() {
    let (_keys, fixture, _records, policy) = build_standard(true);

    // Caller trust requires the opening; caller input withholds it.
    assert_eq!(
        policy["disclosure"]["requesting_subject_opening"],
        "required"
    );
    assert!(fixture.input.subject_openings.is_empty());

    let report = verify_remote_evidence_v2(&fixture.members, &fixture.input);

    // Never Invalid, never Complete.
    assert_ne!(report.status, VerificationStatus::Invalid);
    assert_ne!(report.status, VerificationStatus::Complete);
    assert_eq!(report.status, VerificationStatus::Incomplete);
    assert_eq!(
        report.scenario,
        VerificationScenario::IncompleteRequiredOpeningWithheld
    );
    assert_eq!(
        report.reason_codes,
        vec![VerificationReasonCode::MissingDisclosure]
    );
    assert_eq!(
        report.primary_reason(),
        VerificationReasonCode::MissingDisclosure
    );

    // Exact component results required by the conformanceReport branch:
    // signature verified, actor missing, completeness missing, every other
    // component verified except delivery evidence.
    let c = &report.components;
    assert_eq!(c.signature, VerificationComponentResult::Verified);
    assert_eq!(c.actor, VerificationComponentResult::Missing);
    assert_eq!(c.authority, VerificationComponentResult::Verified);
    assert_eq!(c.role_separation, VerificationComponentResult::Verified);
    assert_eq!(c.approval, VerificationComponentResult::Verified);
    assert_eq!(c.policy, VerificationComponentResult::Verified);
    assert_eq!(c.content, VerificationComponentResult::Verified);
    assert_eq!(c.environment, VerificationComponentResult::Verified);
    assert_eq!(c.release, VerificationComponentResult::Verified);
    assert_eq!(
        c.delivery_evidence,
        VerificationComponentResult::NotRequested
    );
    assert_eq!(c.completeness, VerificationComponentResult::Missing);

    let registry = evidence_schema_registry();
    narrow_to_conformance(&report);
    assert_report_matches_conformance_subtype(&registry, &report);
}

// ---------------------------------------------------------------------------
// Scenario 3: deterministic nested artifact byte tamper.
// ---------------------------------------------------------------------------

#[test]
fn scenario_invalid_content_artifact_byte_tamper_classifies_invalid_with_integrity_reason() {
    let (report, path, _original) = execute_locale_byte_tamper();

    // Exact integrity classification.
    assert_eq!(report.status, VerificationStatus::Invalid);
    assert_ne!(report.status, VerificationStatus::Incomplete);
    assert_ne!(report.status, VerificationStatus::Complete);
    assert_eq!(
        report.scenario,
        VerificationScenario::InvalidContentArtifactByteTamper
    );
    assert_eq!(
        report.reason_codes,
        vec![VerificationReasonCode::TamperedArtifact]
    );
    assert_eq!(
        report.primary_reason(),
        VerificationReasonCode::TamperedArtifact
    );

    // Exact component results: only content failed; delivery evidence stayed
    // not-requested.
    let c = &report.components;
    assert_eq!(c.signature, VerificationComponentResult::Verified);
    assert_eq!(c.actor, VerificationComponentResult::Verified);
    assert_eq!(c.authority, VerificationComponentResult::Verified);
    assert_eq!(c.role_separation, VerificationComponentResult::Verified);
    assert_eq!(c.approval, VerificationComponentResult::Verified);
    assert_eq!(c.policy, VerificationComponentResult::Verified);
    assert_eq!(c.content, VerificationComponentResult::Invalid);
    assert_eq!(c.environment, VerificationComponentResult::Verified);
    assert_eq!(c.release, VerificationComponentResult::Verified);
    assert_eq!(
        c.delivery_evidence,
        VerificationComponentResult::NotRequested
    );
    assert_eq!(c.completeness, VerificationComponentResult::Verified);

    // The failure is attributed to the committed deterministic nested path.
    let file = path
        .strip_prefix("content/artifacts/object_locale_revision_v1/blake3/")
        .expect("deterministic nested prefix");
    let hex_part = file.strip_suffix(".json").expect(".json member name");
    assert_eq!(hex_part.len(), 64);
    assert!(hex_part.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let registry = evidence_schema_registry();
    narrow_to_conformance(&report);
    assert_report_matches_conformance_subtype(&registry, &report);
}

// ---------------------------------------------------------------------------
// Retained machine vector execution and structural validation.
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn machine_vector_executes_retained_scenarios_and_produced_structures_validate() {
    // -- Inspect the retained machine vector ---------------------------------
    let vector_path = repository_root()
        .join("conformance/v1/collaboration-server/vectors")
        .join("remote-evidence-v2.valid.json");
    let bytes =
        fs::read(&vector_path).unwrap_or_else(|error| panic!("{}: {error}", vector_path.display()));
    let vector: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("{}: {error}", vector_path.display()));

    // The vector is a normative decision contract, not a materialized
    // executable fixture: it retains no bundle bytes and no observed reports,
    // so nothing can be replayed byte-for-byte.
    assert_eq!(vector["api_version"], "proof.dev/remote-evidence-suite/v2");
    assert_eq!(vector["evidence_class"], "decision-contract");
    assert_eq!(vector["execution_status"], "normative-requirements-only");
    assert!(
        !vector["runtime_qualified"]
            .as_bool()
            .expect("runtime_qualified bool"),
        "the decision-contract fixture must not claim runtime qualification"
    );
    let materialization = &vector["materialization"];
    assert_eq!(materialization["status"], "unmaterialized-runtime-contract");
    assert!(
        !materialization["exact_bundle_bytes_retained"]
            .as_bool()
            .expect("exact_bundle_bytes_retained bool")
    );
    assert!(
        !materialization["observed_reports_retained"]
            .as_bool()
            .expect("observed_reports_retained bool")
    );
    for forbidden_materialized_field in [
        "bundle_descriptor",
        "bundle_manifest",
        "export_lifecycle",
        "reports",
        "verifier_input",
    ] {
        assert!(
            vector.get(forbidden_materialized_field).is_none(),
            "the decision-contract fixture must not invent {forbidden_materialized_field}"
        );
    }
    assert_eq!(
        vector["composition"]["profile"], "proof-verifier/remote-evidence-v2",
        "the composition profile names exactly the implementation executed here"
    );
    assert_eq!(
        vector["contract"]["missing_disclosure_result"], "Incomplete",
        "the contract pins the withheld-opening outcome executed below"
    );
    assert_eq!(
        vector["contract"]["tamper_contradiction_or_falsity_result"], "Invalid",
        "the contract pins the tamper outcome executed below"
    );

    // -- Execute the three normative scenario rows against the implementation
    let (complete_report, fixture) = execute_complete();
    let incomplete_report = execute_incomplete_withheld_opening();
    let (tamper_report, _tamper_path, _original) = execute_locale_byte_tamper();

    let rows = vector["normative_scenarios"]
        .as_array()
        .expect("normative_scenarios array");
    assert_eq!(rows.len(), 3);
    let observed = [
        (
            &complete_report,
            ConformanceScenario::CompleteExactMaterialization,
            "Complete",
        ),
        (
            &incomplete_report,
            ConformanceScenario::IncompleteRequiredOpeningWithheld,
            "Incomplete",
        ),
        (
            &tamper_report,
            ConformanceScenario::InvalidContentArtifactByteTamper,
            "Invalid",
        ),
    ];
    for (row, (report, scenario, expected_status)) in rows.iter().zip(observed) {
        assert_eq!(row["claim_kind"], "normative-successor-requirement");
        assert!(
            !row["runtime_observed"]
                .as_bool()
                .expect("runtime_observed bool"),
            "normative rows are unobserved successor requirements"
        );
        assert_eq!(row["delivery_evidence"], "not-requested");
        assert_eq!(
            row["scenario"],
            serde_json::to_value(scenario).expect("scenario wire string")
        );
        assert_eq!(row["expected_status"], expected_status);
        assert_eq!(
            report.status,
            match expected_status {
                "Complete" => VerificationStatus::Complete,
                "Incomplete" => VerificationStatus::Incomplete,
                _ => VerificationStatus::Invalid,
            },
            "the executed outcome must match the normative expectation"
        );
    }

    // -- Structural validation of the produced structures --------------------
    // Executed above: three verifier runs over fully materialized logical
    // member maps. Validated structurally here: the produced bundle
    // descriptor, manifest, and verifier input against the Schema's frozen
    // constants (digest contexts, api versions, type strings).
    let registry = evidence_schema_registry();

    let bundle_bytes = fixture
        .members
        .get("bundle.json")
        .expect("reserved bundle.json");
    let bundle_value: Value = serde_json::from_slice(bundle_bytes).expect("bundle.json parses");
    assert_eq!(bundle_value["type"], "RemoteEvidenceBundleV2");
    assert_eq!(
        bundle_value["api_version"],
        REMOTE_EVIDENCE_BUNDLE_API_VERSION
    );
    assert_eq!(bundle_value["bundle_descriptor_path"], "bundle.json");
    assert_eq!(bundle_value["manifest_member_path"], "manifest.json");
    assert_schema_valid(
        &def_validator(&registry, "bundle"),
        "bundle.json",
        &bundle_value,
    );

    let manifest_bytes = fixture
        .members
        .get("manifest.json")
        .expect("reserved manifest.json");
    let manifest_value: Value =
        serde_json::from_slice(manifest_bytes).expect("manifest.json parses");
    assert_eq!(manifest_value["type"], "RemoteEvidenceManifestV2");
    assert_eq!(
        manifest_value["api_version"],
        REMOTE_EVIDENCE_MANIFEST_API_VERSION
    );
    assert_schema_valid(
        &def_validator(&registry, "evidenceManifestV2"),
        "manifest.json",
        &manifest_value,
    );

    // Digest-context bindings across descriptor, manifest, and reports.
    let declared_manifest_digest = bundle_value["manifest_digest"].as_str().expect("digest");
    assert_eq!(
        declared_manifest_digest,
        derive_key_digest(REMOTE_EVIDENCE_MANIFEST_DIGEST_CONTEXT, manifest_bytes).to_string(),
        "descriptor manifest_digest must recompute under the frozen manifest context"
    );

    let input_value = serde_json::to_value(&fixture.input).expect("verifier input serializes");
    assert_eq!(input_value["type"], "RemoteVerifierInputV2");
    assert_schema_valid(
        &def_validator(&registry, "verifierInput"),
        "verifier input",
        &input_value,
    );

    for report in [&complete_report, &incomplete_report, &tamper_report] {
        assert_report_matches_conformance_subtype(&registry, report);
    }

    // Report binding rule: raw reserved-entry digests recompute under their
    // frozen raw contexts; the typed manifest/input/policy digests recompute
    // under their frozen typed contexts.
    assert_eq!(
        complete_report
            .raw_bundle_descriptor_digest
            .expect("descriptor bytes present")
            .to_string(),
        derive_key_digest(RAW_BUNDLE_DESCRIPTOR_DIGEST_CONTEXT, bundle_bytes).to_string()
    );
    assert_eq!(
        complete_report
            .raw_bundle_manifest_digest
            .expect("manifest bytes present")
            .to_string(),
        derive_key_digest(RAW_BUNDLE_MANIFEST_DIGEST_CONTEXT, manifest_bytes).to_string()
    );
    assert_eq!(
        complete_report
            .bundle_manifest_digest
            .expect("strict manifest parsed")
            .to_string(),
        declared_manifest_digest
    );
    let input_bytes = canonical(&input_value);
    assert_eq!(
        complete_report
            .verifier_input_digest
            .expect("strict input parsed")
            .to_string(),
        derive_key_digest(REMOTE_VERIFIER_INPUT_DIGEST_CONTEXT, &input_bytes).to_string()
    );
    let policy_value = input_value["verification_trust_policy"].clone();
    assert_eq!(
        complete_report
            .trust_policy_digest
            .expect("strict policy parsed")
            .to_string(),
        derive_key_digest(
            VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT,
            &canonical(&policy_value)
        )
        .to_string()
    );
}
