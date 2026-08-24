#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::unreadable_literal
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use jsonschema::{Registry, Validator};
use proof_application::CAPABILITY_REGISTRY;
use proof_canonical::parse_strict;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const APPLICATION_SCHEMA_ID: &str =
    "https://proof.dev/schema/collaboration-server/application-operations/v1";
const ARTIFACT_SCHEMA_ID: &str =
    "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1";
const HTTP_SCHEMA_ID: &str = "https://proof.dev/schema/collaboration-server/http-envelope/v1";
const REMOTE_AUTH_SCHEMA_ID: &str = "https://proof.dev/schema/collaboration-server/remote-auth/v1";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collaboration_path(relative: &str) -> PathBuf {
    repository_root()
        .join("conformance/v1/collaboration-server")
        .join(relative)
}

fn parse_file(path: &Path) -> Value {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    parse_strict(&bytes).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn parse_instant(value: &Value) -> OffsetDateTime {
    OffsetDateTime::parse(
        value.as_str().expect("timestamp must be a string"),
        &Rfc3339,
    )
    .expect("timestamp must be valid RFC 3339")
}

fn effect_digest_rule(digest_context: &str, preimage_source: &str, source_contract: &str) -> Value {
    let effect_timestamp_field = match preimage_source {
        "agent-binding-issue-v1-remote-authority-record"
        | "delegation-issue-v2-remote-authority-record"
        | "oidc-binding-issue-v1-remote-authority-record" => json!("issued_at"),
        "agent-binding-revoke-v1-remote-authority-record"
        | "delegation-revoke-v1-remote-authority-record"
        | "oidc-binding-revoke-v1-remote-authority-record"
        | "workspace-role-revocation-v1-remote-authority-record" => json!("revoked_at"),
        "changeset-approval-v1-remote-authority-record" => json!("approved_at"),
        "environment-config-activation-v1-remote-authority-record" => json!("activated_at"),
        "environment-config-proposal-v1-remote-authority-record" => json!("proposed_at"),
        "principal-status-v2-remote-authority-record" => json!("recorded_at"),
        "workspace-role-assignment-v1-remote-authority-record" => json!("assigned_at"),
        _ => Value::Null,
    };
    json!({
        "digest_context": digest_context,
        "effect_timestamp_field": effect_timestamp_field,
        "mode": "blake3-256-derive-key-rfc8785",
        "preimage_source": preimage_source,
        "source_contract": source_contract,
    })
}

fn sorted_json_files(directory: &Path) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            entry
                .expect("conformance directory entry must be readable")
                .path()
        })
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn external_schema_paths() -> Vec<PathBuf> {
    let root = repository_root();
    [
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
    ]
    .into_iter()
    .map(|path| root.join(path))
    .collect()
}

fn schema_registry() -> (BTreeMap<String, Value>, Registry<'static>) {
    let schema_paths = sorted_json_files(&collaboration_path("schemas"));
    let meta = jsonschema::draft202012::meta::validator();
    let mut schemas = BTreeMap::new();
    let mut registry = Registry::new();

    for path in schema_paths.into_iter().chain(external_schema_paths()) {
        let schema = parse_file(&path);
        assert!(
            meta.is_valid(&schema),
            "{} is not a valid Draft 2020-12 Schema: {:?}",
            path.display(),
            meta.iter_errors(&schema).collect::<Vec<_>>()
        );
        let identifier = schema["$id"]
            .as_str()
            .unwrap_or_else(|| panic!("{} must declare $id", path.display()))
            .to_owned();
        registry = registry
            .add(identifier.clone(), schema.clone())
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(schemas.insert(identifier, schema).is_none());
    }

    let registry = registry
        .prepare()
        .expect("the complete collaboration Schema graph must resolve");
    (schemas, registry)
}

fn validator(registry: &Registry<'_>, reference: &str) -> Validator {
    jsonschema::options()
        .with_registry(registry)
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": reference,
        }))
        .unwrap_or_else(|error| panic!("{reference}: {error}"))
}

fn vector_schema_reference(file_name: &str, value: &Value) -> &'static str {
    if file_name == "remote-authority-record-envelope.valid.json" {
        return ARTIFACT_SCHEMA_ID;
    }
    if file_name == "release-create-result.private-test.json" {
        return concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json",
            "#/$defs/releaseCreateOutput"
        );
    }

    match value["api_version"].as_str().unwrap_or_else(|| {
        panic!("{file_name} must carry api_version or have an explicit file mapping")
    }) {
        "proof.dev/artifact-catalog-suite/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/artifact-catalog/v1"
        }
        "proof.dev/authenticated-actor-context-evidence/v2"
        | "proof.dev/authenticated-actor-context/v2"
        | "proof.dev/oidc-authenticated-subject/v1"
        | "proof.dev/oidc-issuer-configuration/v1"
        | "proof.dev/oidc-principal-binding-revocation/v1"
        | "proof.dev/oidc-principal-binding-private/v1"
        | "proof.dev/oidc-principal-binding/v1"
        | "proof.dev/oidc-subject-commitment-input/v1"
        | "proof.dev/oidc-subject-commitment-opening/v1"
        | "proof.dev/remote-authentication-event/v1" => REMOTE_AUTH_SCHEMA_ID,
        "proof.dev/changeset-approval/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/changeSetApprovalV1"
        ),
        "proof.dev/environment-config-activation/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/environmentConfigActivationV1"
        ),
        "proof.dev/environment-config-proposal/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/environmentConfigProposalV1"
        ),
        "proof.dev/environment-config/v2" => ARTIFACT_SCHEMA_ID,
        "proof.dev/environment-creation/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/environmentCreationV1"
        ),
        "proof.dev/remote-application-consequence/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/remoteApplicationConsequenceV1"
        ),
        "proof.dev/remote-authorization-decision/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/remoteAuthorizationDecisionV1"
        ),
        "proof.dev/remote-principal-status/v2" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/remotePrincipalStatusV2"
        ),
        "proof.dev/workspace-role-assignment/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/workspaceRoleAssignmentV1"
        ),
        "proof.dev/workspace-role-revocation/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1",
            "#/$defs/workspaceRoleRevocationV1"
        ),
        "proof.dev/http-agent-operation-request/v1"
        | "proof.dev/http-human-operation-request/v1"
        | "proof.dev/http-problem/v1" => HTTP_SCHEMA_ID,
        "proof.dev/conformance/enrollment-agent-binding/v1"
        | "proof.dev/conformance/enrollment-oidc-binding/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/enrollment-vector/v1"
        }
        "proof.dev/http-operation-registry/v1" => {
            "https://proof.dev/schema/collaboration-server/http-operation-registry/v1"
        }
        "proof.dev/operation/changeset.get/v2" => concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json",
            "#/$defs/changeSetGetInput"
        ),
        "proof.dev/operation/release.create/v2" => concat!(
            "https://proof.dev/schemas/localized-content/operations-v2.schema.json",
            "#/$defs/releaseCreateInput"
        ),
        "proof.dev/delivery-management-fact/v1" => concat!(
            "https://proof.dev/schema/collaboration-server/application-operations/v1",
            "#/$defs/deliveryManagementFactV1"
        ),
        "proof.dev/conformance/collaboration-server-rejected-requirements/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/rejected-requirements/v1"
        }
        "proof.dev/conformance/remote-authority-dsse-vector/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/remote-authority-dsse-vector/v1"
        }
        "proof.dev/authoritative-transaction-trace-suite/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/storage-transaction/v1"
        }
        "proof.dev/migration-rebuild-suite/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/migration-rebuild/v1"
        }
        "proof.dev/outbox-delivery-suite/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/outbox-delivery/v1"
        }
        "proof.dev/preview-delivery-suite/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/preview-delivery/v1"
        }
        "proof.dev/remote-evidence-suite/v2" => {
            "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2"
        }
        "proof.dev/storage-delivery-contract-manifest/v1" => {
            "https://proof.dev/schema/conformance/collaboration-server/storage-delivery-contract-manifest/v1"
        }
        version => panic!("{file_name} has no validator mapping for {version}"),
    }
}

fn canonical_digest(context: &str, value: &Value) -> String {
    let canonical = serde_json_canonicalizer::to_vec(value)
        .expect("checked-in portable JSON must canonicalize under RFC 8785");
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&canonical);
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn raw_digest(context: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(bytes);
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn sha256(input: &[u8]) -> [u8; 32] {
    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64)
        .checked_mul(8)
        .expect("SHA-256 input length must fit u64 bits");
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for block in padded.chunks_exact(64) {
        let mut schedule = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(big_s1)
                .wrapping_add(choose)
                .wrapping_add(ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = big_s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    let mut digest = [0u8; 32];
    for (chunk, word) in digest.chunks_exact_mut(4).zip(state) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn canonical_sha256(value: &Value) -> String {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .expect("the decision-contract value must canonicalize under RFC 8785");
    hex_lower(&sha256(&bytes))
}

fn resolve_schema_reference(
    schemas: &BTreeMap<String, Value>,
    current_schema_id: Option<&str>,
    reference: &str,
) -> (String, Value) {
    let absolute = if reference.starts_with('#') {
        format!(
            "{}{}",
            current_schema_id.expect("a local Schema reference needs a document identifier"),
            reference
        )
    } else {
        reference.to_owned()
    };
    let (schema_id, fragment) = absolute
        .split_once('#')
        .map_or((absolute.as_str(), ""), |(schema_id, fragment)| {
            (schema_id, fragment)
        });
    let schema = schemas
        .get(schema_id)
        .unwrap_or_else(|| panic!("unregistered Schema document {schema_id}"));
    let value = if fragment.is_empty() {
        schema
    } else {
        schema
            .pointer(fragment)
            .unwrap_or_else(|| panic!("{absolute} does not resolve"))
    };
    (schema_id.to_owned(), value.clone())
}

fn instance_path_exists_in_schema(
    schemas: &BTreeMap<String, Value>,
    reference: &str,
    instance_path: &str,
) -> bool {
    let (mut schema_id, mut node) = resolve_schema_reference(schemas, None, reference);
    for encoded_segment in instance_path
        .strip_prefix('/')
        .unwrap_or(instance_path)
        .split('/')
        .filter(|segment| !segment.is_empty())
    {
        while let Some(next_reference) = node.get("$ref").and_then(Value::as_str).map(str::to_owned)
        {
            (schema_id, node) =
                resolve_schema_reference(schemas, Some(&schema_id), &next_reference);
        }
        let segment = encoded_segment.replace("~1", "/").replace("~0", "~");
        let Some(next) = node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(&segment))
        else {
            return false;
        };
        node = next.clone();
    }
    true
}

fn assert_fields_equal(left: &Value, right: &Value, fields: &[&str], label: &str) {
    for field in fields {
        assert_eq!(left[*field], right[*field], "{label} differs at {field}");
    }
}

fn operation_pairs(route: &Value) -> Vec<(&str, &str)> {
    route["operations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["operation"]["name"].as_str().unwrap(),
                row["operation"]["version"].as_str().unwrap(),
            )
        })
        .collect()
}

fn route_qualified_operation_row<'a>(registry: &'a Value, decision: &Value) -> Option<&'a Value> {
    let routes = registry["routes"].as_array()?;
    let mut selected = None;
    for route in routes {
        if route["authentication"] != decision["authentication_profile"] {
            continue;
        }
        for row in route["operations"].as_array().into_iter().flatten() {
            if row["operation"] == decision["operation"] {
                if selected.is_some() {
                    return None;
                }
                selected = Some(row);
            }
        }
    }
    selected
}

fn operation_row_authorization_projection_is_consistent(
    registry: &Value,
    decision: &Value,
    row: &Value,
) -> bool {
    let Some(version) = decision["operation"]["version"].as_str() else {
        return false;
    };
    match decision["authentication_profile"].as_str() {
        Some("proof.server/authentication/oidc-human/v1") => {
            let projection = &registry["human_authorization_projection"]["operations"][version];
            row["authorization"]["authorization_rule"] == decision["authorization_rule"]
                && projection["authorization_rule"] == decision["authorization_rule"]
                && projection["requested_action"] == decision["requested_action"]
                && projection["roles_any_of"] == row["authorization"]["roles_any_of"]
        }
        Some("proof.server/authentication/oidc-human-agent/v1") => {
            let projection = &registry["agent_authorization_projection"]["operations"][version];
            decision["authorization_rule"] == "proof.local/authority/direct/v1"
                && projection["requested_action"] == decision["requested_action"]
                && projection["requested_action"] == row["requested_action"]
                && projection["consequence"] == row["consequence"]
        }
        _ => false,
    }
}

fn application_problem_digest(operation: &Value, code: &Value) -> String {
    canonical_digest(
        "proof:operation-effect:v1",
        &json!({
            "api_version": "proof.dev/application-problem-digest-preimage/v1",
            "code": code,
            "operation": operation,
        }),
    )
}

fn stored_success_matches(
    current_decision: &Value,
    consequence: &Value,
    stored_decision: &Value,
    stored_consequence: &Value,
) -> bool {
    stored_consequence["outcome"] == "success"
        && stored_decision["authentication_profile"] == current_decision["authentication_profile"]
        && stored_consequence["decision_digest"]
            == canonical_digest("proof:remote-authority-record:v1", stored_decision)
        && stored_consequence["workspace_id"] == consequence["workspace_id"]
        && stored_consequence["operation"] == consequence["operation"]
        && stored_consequence["operation_registry_sha256"]
            == consequence["operation_registry_sha256"]
        && stored_consequence["application_key_kind"] == consequence["application_key_kind"]
        && stored_consequence["application_key"] == consequence["application_key"]
        && stored_consequence["result_digest"] == consequence["prior_result_digest"]
}

fn consequence_semantics_are_valid(
    registry: &Value,
    decision: &Value,
    consequence: &Value,
    expected_application_key: &Value,
    successful_result: &Value,
    expected_success_effect_digest: &Value,
    stored_success: Option<(&Value, &Value)>,
) -> bool {
    let Some(row) = route_qualified_operation_row(registry, decision) else {
        return false;
    };
    if !operation_row_authorization_projection_is_consistent(registry, decision, row)
        || decision["decision"] != "allow"
        || consequence["decision_id"] != decision["decision_id"]
        || consequence["decision_digest"]
            != canonical_digest("proof:remote-authority-record:v1", decision)
        || consequence["workspace_id"] != decision["workspace_id"]
        || consequence["operation"] != decision["operation"]
        || consequence["operation_registry_sha256"] != decision["operation_registry_sha256"]
        || consequence["public_input_projection_digest"]
            != decision["public_input_projection_digest"]
        || consequence["application_key_kind"] != row["application_idempotency"]
        || consequence["application_key"] != *expected_application_key
        || parse_instant(&consequence["recorded_at"]) < parse_instant(&decision["evaluated_at"])
    {
        return false;
    }

    let Some(decision_sequence) = decision["authority_sequence"].as_u64() else {
        return false;
    };
    let decision_digest = consequence["decision_digest"].clone();
    let outcome = consequence["outcome"].as_str().unwrap_or_default();
    let authority_effect_success = outcome == "success"
        && row["effect_digest_rule"]["digest_context"] == "proof:remote-authority-record:v1";
    let causal_link_is_valid = if authority_effect_success {
        consequence["application_effect_digest"].is_string()
            && consequence["application_effect_authority_head"]
                == json!({
                    "record_digest": consequence["application_effect_digest"].clone(),
                    "sequence": decision_sequence + 1,
                })
            && consequence["evaluated_authority_head"]
                == consequence["application_effect_authority_head"]
            && consequence["previous_authority_record_digest"]
                == consequence["application_effect_digest"]
            && consequence["authority_sequence"] == decision_sequence + 2
    } else {
        consequence["application_effect_authority_head"].is_null()
            && consequence["evaluated_authority_head"]
                == json!({
                    "record_digest": decision_digest,
                    "sequence": decision_sequence,
                })
            && consequence["previous_authority_record_digest"] == consequence["decision_digest"]
            && consequence["authority_sequence"] == decision_sequence + 1
    };
    if !causal_link_is_valid {
        return false;
    }

    let successful_result_digest = canonical_digest("proof:operation-effect:v1", successful_result);
    match outcome {
        "success" => {
            consequence["result_digest"] == successful_result_digest
                && consequence["prior_result_digest"].is_null()
                && consequence["problem_code"].is_null()
                && consequence["application_effect_digest"] == *expected_success_effect_digest
        }
        "idempotent-replay" => {
            consequence["result_digest"] == successful_result_digest
                && consequence["prior_result_digest"] == consequence["result_digest"]
                && consequence["problem_code"].is_null()
                && consequence["application_effect_digest"].is_null()
                && stored_success.is_some_and(|(stored_decision, stored_consequence)| {
                    stored_success_matches(
                        decision,
                        consequence,
                        stored_decision,
                        stored_consequence,
                    )
                })
        }
        "idempotency-conflict" => {
            consequence["problem_code"] == "proof.idempotency.key_reused"
                && consequence["result_digest"]
                    == application_problem_digest(
                        &consequence["operation"],
                        &consequence["problem_code"],
                    )
                && consequence["application_effect_digest"].is_null()
                && stored_success.is_some_and(|(stored_decision, stored_consequence)| {
                    stored_success_matches(
                        decision,
                        consequence,
                        stored_decision,
                        stored_consequence,
                    )
                })
        }
        "precondition-conflict" => {
            consequence["problem_code"] == "proof.state.conflict"
                && consequence["result_digest"]
                    == application_problem_digest(
                        &consequence["operation"],
                        &consequence["problem_code"],
                    )
                && consequence["prior_result_digest"].is_null()
                && consequence["application_effect_digest"].is_null()
        }
        "application-failure" => {
            row["application_problem_codes"]
                .as_array()
                .is_some_and(|codes| codes.contains(&consequence["problem_code"]))
                && consequence["result_digest"]
                    == application_problem_digest(
                        &consequence["operation"],
                        &consequence["problem_code"],
                    )
                && consequence["prior_result_digest"].is_null()
                && consequence["application_effect_digest"].is_null()
        }
        _ => false,
    }
}

fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut pae = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    pae.extend_from_slice(payload);
    pae
}

fn assert_causal_record(value: &Value) {
    assert_eq!(
        value["authority_sequence"].as_u64(),
        value["evaluated_authority_head"]["sequence"]
            .as_u64()
            .map(|sequence| sequence + 1)
    );
    assert_eq!(
        value["previous_authority_record_digest"],
        value["evaluated_authority_head"]["record_digest"]
    );
}

#[test]
fn collaboration_schemas_resolve_and_every_checked_in_vector_is_closed() {
    let (schemas, registry) = schema_registry();

    for identifier in schemas.keys() {
        validator(&registry, identifier);
    }

    let vector_paths = sorted_json_files(&collaboration_path("vectors"));
    assert_eq!(
        vector_paths.len(),
        41,
        "the accepted-vector inventory changed"
    );
    for path in vector_paths {
        let value = parse_file(&path);
        let file_name = path.file_name().unwrap().to_str().unwrap();
        let reference = vector_schema_reference(file_name, &value);
        let vector_validator = validator(&registry, reference);
        assert!(
            vector_validator.is_valid(&value),
            "{file_name} does not satisfy {reference}: {:?}",
            vector_validator.iter_errors(&value).collect::<Vec<_>>()
        );

        let mut widened = value.clone();
        widened
            .as_object_mut()
            .expect("every accepted vector is an object")
            .insert("unexpected".to_owned(), Value::Bool(true));
        assert!(
            !vector_validator.is_valid(&widened),
            "{file_name} accepted an unknown top-level property"
        );
    }

    assert!(schemas.contains_key(APPLICATION_SCHEMA_ID));
}

#[test]
fn private_oidc_subject_opening_matches_every_public_commitment() {
    let (_, contract_registry) = schema_registry();
    let issuer_configuration = parse_file(&collaboration_path(
        "vectors/oidc-issuer-configuration.valid.json",
    ));
    let input = parse_file(&collaboration_path(
        "vectors/oidc-subject-commitment.input.private-test.json",
    ));
    let opening = parse_file(&collaboration_path(
        "vectors/oidc-subject-commitment-opening.private-test.json",
    ));
    let private_binding = parse_file(&collaboration_path(
        "vectors/oidc-principal-binding.private-test.json",
    ));
    let public_binding = parse_file(&collaboration_path(
        "vectors/oidc-principal-binding.valid.json",
    ));
    let binding_revocation = parse_file(&collaboration_path(
        "vectors/oidc-principal-binding-revocation.valid.json",
    ));
    let authentication_event = parse_file(&collaboration_path(
        "vectors/remote-authentication-event.valid.json",
    ));
    let commitment = canonical_digest("proof:oidc-authenticated-subject-commitment:v1", &input);
    let issuer_configuration_digest =
        canonical_digest("proof:oidc-issuer-configuration:v1", &issuer_configuration);
    let binding_record_digest =
        canonical_digest("proof:remote-authority-record:v1", &public_binding);
    let authentication_event_digest = canonical_digest(
        "proof:remote-authentication-event:v1",
        &authentication_event,
    );

    assert_eq!(opening["input"], input);
    assert_eq!(opening["commitment"], commitment);
    assert_eq!(private_binding["opening"], opening);
    assert_eq!(private_binding["subject"], input["subject"]);
    assert_eq!(private_binding["subject_commitment"], commitment);
    assert_eq!(
        private_binding["binding_record_digest"],
        binding_record_digest
    );
    assert_eq!(public_binding["subject_commitment"], commitment);
    assert_eq!(
        public_binding["oidc_issuer_configuration_digest"],
        issuer_configuration_digest
    );
    assert_fields_equal(
        &private_binding,
        &public_binding,
        &[
            "workspace_id",
            "binding_id",
            "principal_id",
            "subject_commitment",
            "oidc_issuer_configuration_digest",
        ],
        "protected/public OIDC binding",
    );

    assert_fields_equal(
        &binding_revocation,
        &public_binding,
        &[
            "workspace_id",
            "binding_id",
            "principal_id",
            "subject_commitment",
            "authority_key_id",
        ],
        "OIDC binding revocation",
    );
    assert_eq!(
        binding_revocation["binding_record_digest"],
        binding_record_digest
    );
    assert_eq!(
        canonical_digest("proof:remote-authority-record:v1", &binding_revocation),
        "blake3:5a504b341f53eeb18c857b2463b36cec7db787471ea6d00138d8148576eb5435"
    );

    assert_eq!(
        authentication_event["oidc_issuer_configuration_digest"],
        issuer_configuration_digest
    );
    assert_eq!(
        authentication_event["requesting_binding_record_digest"],
        binding_record_digest
    );
    assert_eq!(
        authentication_event["workspace_id"],
        public_binding["workspace_id"]
    );
    assert_eq!(
        authentication_event["requesting_binding_id"],
        public_binding["binding_id"]
    );
    assert_eq!(
        authentication_event["requesting_principal_id"],
        public_binding["principal_id"]
    );
    assert_eq!(
        authentication_event["requesting_subject_commitment"],
        public_binding["subject_commitment"]
    );

    for (context_file, evidence_file, input_file) in [
        (
            "authenticated-actor-context-v2.human.valid.json",
            "authenticated-actor-context-evidence-v2.human.valid.json",
            "changeset-get-input.private-test.json",
        ),
        (
            "authenticated-actor-context-v2.human-agent.valid.json",
            "authenticated-actor-context-evidence-v2.human-agent.valid.json",
            "release-create-input.private-test.json",
        ),
    ] {
        let context = parse_file(&collaboration_path(&format!("vectors/{context_file}")));
        let evidence = parse_file(&collaboration_path(&format!("vectors/{evidence_file}")));
        let normalized_input = parse_file(&collaboration_path(&format!("vectors/{input_file}")));
        let normalized_input_preimage = json!({
            "api_version": "proof.dev/remote-normalized-operation-input/v1",
            "input": normalized_input.clone(),
            "operation": context["operation"].clone(),
        });
        let public_input_preimage = json!({
            "api_version": "proof.dev/public-operation-input-projection/v1",
            "input": normalized_input,
            "operation": context["operation"].clone(),
        });
        let normalized_input_digest = canonical_digest(
            "proof:remote-normalized-operation-input:v1",
            &normalized_input_preimage,
        );
        let public_input_projection_digest = canonical_digest(
            "proof:public-operation-input-projection:v1",
            &public_input_preimage,
        );
        assert_eq!(context["normalized_input_digest"], normalized_input_digest);
        assert_eq!(
            evidence["public_input_projection_digest"],
            public_input_projection_digest
        );
        assert_ne!(
            normalized_input_digest, public_input_projection_digest,
            "private and public input commitments use distinct typed preimages and domains"
        );
        let mut expected_evidence = context.clone();
        let expected_object = expected_evidence.as_object_mut().unwrap();
        expected_object.remove("requesting_subject");
        expected_object
            .remove("normalized_input_digest")
            .expect("private actor context must bind its exact normalized input");
        expected_object.insert(
            "public_input_projection_digest".to_owned(),
            Value::String(public_input_projection_digest),
        );
        expected_object.insert(
            "api_version".to_owned(),
            Value::String("proof.dev/authenticated-actor-context-evidence/v2".to_owned()),
        );
        assert_eq!(
            expected_evidence, evidence,
            "{evidence_file} is not the exact public redaction of {context_file}"
        );
        assert_eq!(context["requesting_subject"], input["subject"]);
        assert_eq!(context["requesting_subject_commitment"], commitment);
        assert_eq!(
            context["oidc_issuer_configuration_digest"],
            issuer_configuration_digest
        );
        assert_eq!(
            context["authentication_event_digest"],
            authentication_event_digest
        );
        assert_fields_equal(
            &context,
            &authentication_event,
            &[
                "workspace_id",
                "authentication_event_id",
                "authenticated_at",
                "requesting_binding_id",
                "requesting_binding_record_digest",
                "requesting_principal_id",
                "requesting_subject_commitment",
                "oidc_issuer_configuration_digest",
            ],
            context_file,
        );
    }

    let human_evidence = parse_file(&collaboration_path(
        "vectors/authenticated-actor-context-evidence-v2.human.valid.json",
    ));
    assert_eq!(
        canonical_digest(
            "proof:authenticated-actor-context-evidence:v2",
            &human_evidence,
        ),
        "blake3:9b208791427c5d25c5d56a0f7487d3ed206ff1de80f4d442feb4859c7abe6c7d"
    );

    let agent_evidence = parse_file(&collaboration_path(
        "vectors/authenticated-actor-context-evidence-v2.human-agent.valid.json",
    ));
    let decision = parse_file(&collaboration_path(
        "vectors/remote-authorization-decision.valid.json",
    ));
    let consequence = parse_file(&collaboration_path(
        "vectors/remote-application-consequence.valid.json",
    ));
    let decision_validator = validator(
        &contract_registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/remoteAuthorizationDecisionV1"),
    );
    let consequence_validator = validator(
        &contract_registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/remoteApplicationConsequenceV1"),
    );
    assert!(decision_validator.is_valid(&decision));
    assert!(consequence_validator.is_valid(&consequence));

    // RemoteAuthorizationDecisionV1 carries the resolved Delegation digest, not a
    // second copy of its immutable issuer/recipient/scope bytes. Reproduce the
    // accepted direct evaluator's relevant ordering against those referenced bytes.
    let accepted_scope_or_revocation_denial =
        |candidate: &Value, delegation: &Value| -> Option<&'static str> {
            let actor_mismatch = delegation["issuer_principal_id"]
                != candidate["requesting_principal_id"]
                || delegation["recipient_principal_id"]
                    != candidate["agent_authorization"]["operating_principal_id"];
            if actor_mismatch {
                return Some("proof.authorization.scope_exceeded");
            }
            if candidate
                .pointer("/agent_authorization/delegation/revocation_record_digest")
                .is_some_and(|digest| !digest.is_null())
            {
                return Some("proof.authorization.delegation_revoked");
            }

            let action_allowed = delegation["actions"].as_array().is_some_and(|actions| {
                actions
                    .iter()
                    .any(|action| action == &candidate["requested_action"])
            });
            let requested = &candidate["agent_authorization"]["requested_resources"];
            let delegated_scope = &delegation["scope"];
            let resources_allowed = ["environment_ids", "locales", "object_ids", "schema_ids"]
                .into_iter()
                .all(|field| {
                    requested[field].as_array().is_some_and(|requested_values| {
                        delegated_scope[field]
                            .as_array()
                            .is_some_and(|delegated_values| {
                                requested_values
                                    .iter()
                                    .all(|value| delegated_values.contains(value))
                            })
                    })
                });
            (!action_allowed || !resources_allowed).then_some("proof.authorization.scope_exceeded")
        };
    let mut matching_delegation = parse_file(
        &repository_root().join("conformance/v1/authority/vectors/delegation-v2.valid.json"),
    );
    matching_delegation["issuer_principal_id"] = decision["requesting_principal_id"].clone();
    matching_delegation["recipient_principal_id"] =
        decision["agent_authorization"]["operating_principal_id"].clone();
    matching_delegation["actions"] = json!([decision["requested_action"].clone()]);
    for field in ["environment_ids", "locales", "object_ids", "schema_ids"] {
        matching_delegation["scope"][field] =
            decision["agent_authorization"]["requested_resources"][field].clone();
    }
    assert_eq!(
        accepted_scope_or_revocation_denial(&decision, &matching_delegation),
        None,
        "the positive fixture must pass the evaluator gates covered by these denial tests"
    );

    let mut unavailable_denial = decision.clone();
    unavailable_denial["decision"] = json!("deny");
    unavailable_denial["public_code"] = json!("proof.auth.denied");
    unavailable_denial["reason_code"] = json!("proof.authorization.delegation_unavailable");
    unavailable_denial["agent_authorization"]["delegation"]["resolution"] =
        json!("not_found_or_hidden");
    unavailable_denial["agent_authorization"]["delegation"]["record_digest"] = Value::Null;
    unavailable_denial["agent_authorization"]["delegation"]["revocation_record_digest"] =
        Value::Null;
    assert!(decision_validator.is_valid(&unavailable_denial));
    let mut unavailable_with_resolved_delegation = unavailable_denial.clone();
    unavailable_with_resolved_delegation["agent_authorization"]["delegation"] =
        decision["agent_authorization"]["delegation"].clone();
    assert!(
        !decision_validator.is_valid(&unavailable_with_resolved_delegation),
        "delegation_unavailable cannot coexist with a resolved Delegation"
    );

    let mut inactive_binding_denial = decision.clone();
    inactive_binding_denial["decision"] = json!("deny");
    inactive_binding_denial["public_code"] = json!("proof.auth.denied");
    inactive_binding_denial["reason_code"] = json!("proof.auth.binding_inactive");
    inactive_binding_denial["agent_authorization"]["binding"]["active"] = json!(false);
    assert!(decision_validator.is_valid(&inactive_binding_denial));
    let mut inactive_reason_with_active_binding = inactive_binding_denial.clone();
    inactive_reason_with_active_binding["agent_authorization"]["binding"]["active"] = json!(true);
    assert!(
        !decision_validator.is_valid(&inactive_reason_with_active_binding),
        "binding_inactive cannot coexist with binding.active=true"
    );
    let mut inactive_binding_with_wrong_reason = inactive_binding_denial.clone();
    inactive_binding_with_wrong_reason["public_code"] = json!("proof.authorization.denied");
    inactive_binding_with_wrong_reason["reason_code"] = json!("proof.authorization.policy_denied");
    assert!(
        !decision_validator.is_valid(&inactive_binding_with_wrong_reason),
        "binding.active=false must select the exact binding_inactive denial"
    );

    let mut disabled_principal_denial = decision.clone();
    disabled_principal_denial["decision"] = json!("deny");
    disabled_principal_denial["public_code"] = json!("proof.auth.denied");
    disabled_principal_denial["reason_code"] = json!("proof.authorization.principal_disabled");
    disabled_principal_denial["agent_authorization"]["principal_state"]["operating_principal_enabled"] =
        json!(false);
    assert!(decision_validator.is_valid(&disabled_principal_denial));
    let mut disabled_reason_with_enabled_principal = disabled_principal_denial.clone();
    disabled_reason_with_enabled_principal["agent_authorization"]["principal_state"]["operating_principal_enabled"] =
        json!(true);
    assert!(
        !decision_validator.is_valid(&disabled_reason_with_enabled_principal),
        "principal_disabled cannot coexist with an enabled operating Principal"
    );
    let mut disabled_principal_with_wrong_reason = disabled_principal_denial.clone();
    disabled_principal_with_wrong_reason["public_code"] = json!("proof.authorization.denied");
    disabled_principal_with_wrong_reason["reason_code"] =
        json!("proof.authorization.policy_denied");
    assert!(
        !decision_validator.is_valid(&disabled_principal_with_wrong_reason),
        "operating_principal_enabled=false must select the exact principal_disabled denial"
    );
    let mut requesting_principal_disabled = decision.clone();
    requesting_principal_disabled["decision"] = json!("deny");
    requesting_principal_disabled["public_code"] = json!("proof.auth.denied");
    requesting_principal_disabled["reason_code"] = json!("proof.authorization.principal_disabled");
    requesting_principal_disabled["agent_authorization"]["principal_state"]["requesting_principal_enabled"] =
        json!(false);
    assert!(
        decision_validator.is_valid(&requesting_principal_disabled),
        "the accepted direct evaluator can deny an Agent attempt when its requesting Human is disabled"
    );
    let mut requesting_disabled_with_wrong_reason = requesting_principal_disabled.clone();
    requesting_disabled_with_wrong_reason["public_code"] = json!("proof.authorization.denied");
    requesting_disabled_with_wrong_reason["reason_code"] =
        json!("proof.authorization.policy_denied");
    assert!(
        !decision_validator.is_valid(&requesting_disabled_with_wrong_reason),
        "requesting_principal_enabled=false must select the exact principal_disabled denial"
    );
    let mut requesting_disabled_before_other_failures = requesting_principal_disabled.clone();
    requesting_disabled_before_other_failures["agent_authorization"]["binding"]["active"] =
        json!(false);
    requesting_disabled_before_other_failures["agent_authorization"]["delegation"]["revocation_record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        decision_validator.is_valid(&requesting_disabled_before_other_failures),
        "Principal disablement precedes binding inactivity and Delegation revocation"
    );

    let mut revoked_delegation_denial = decision.clone();
    revoked_delegation_denial["decision"] = json!("deny");
    revoked_delegation_denial["public_code"] = json!("proof.authorization.delegation_revoked");
    revoked_delegation_denial["reason_code"] = json!("proof.authorization.delegation_revoked");
    revoked_delegation_denial["agent_authorization"]["delegation"]["revocation_record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(decision_validator.is_valid(&revoked_delegation_denial));
    let mut revoked_reason_without_revocation = revoked_delegation_denial.clone();
    revoked_reason_without_revocation["agent_authorization"]["delegation"]["revocation_record_digest"] =
        Value::Null;
    assert!(
        !decision_validator.is_valid(&revoked_reason_without_revocation),
        "delegation_revoked requires a resolved revocation record"
    );
    let mut revoked_delegation_with_wrong_reason = revoked_delegation_denial.clone();
    revoked_delegation_with_wrong_reason["public_code"] = json!("proof.authorization.denied");
    revoked_delegation_with_wrong_reason["reason_code"] =
        json!("proof.authorization.policy_denied");
    assert!(
        !decision_validator.is_valid(&revoked_delegation_with_wrong_reason),
        "a non-null Delegation revocation must select the exact delegation_revoked denial"
    );

    assert_eq!(
        accepted_scope_or_revocation_denial(&revoked_delegation_denial, &matching_delegation),
        Some("proof.authorization.delegation_revoked"),
        "a matching revoked Delegation must remain delegation_revoked"
    );
    let mut identity_mismatch_with_revocation = revoked_delegation_denial.clone();
    identity_mismatch_with_revocation["public_code"] = json!("proof.authorization.scope_exceeded");
    identity_mismatch_with_revocation["reason_code"] = json!("proof.authorization.scope_exceeded");
    assert!(
        decision_validator.is_valid(&identity_mismatch_with_revocation),
        "the structural decision must admit the accepted pre-revocation identity-scope branch"
    );
    for (field, wrong_principal) in [
        (
            "issuer_principal_id",
            "019e0000-0000-7000-8000-0000000000e1",
        ),
        (
            "recipient_principal_id",
            "019e0000-0000-7000-8000-0000000000e2",
        ),
    ] {
        let mut mismatched_delegation = matching_delegation.clone();
        mismatched_delegation[field] = json!(wrong_principal);
        assert_eq!(
            accepted_scope_or_revocation_denial(
                &identity_mismatch_with_revocation,
                &mismatched_delegation,
            ),
            Some("proof.authorization.scope_exceeded"),
            "{field} mismatch must precede the resolved Delegation revocation"
        );
    }
    assert_ne!(
        identity_mismatch_with_revocation["reason_code"],
        json!(accepted_scope_or_revocation_denial(
            &identity_mismatch_with_revocation,
            &matching_delegation,
        )),
        "matching issuer/recipient bytes cannot claim the identity-mismatch scope branch"
    );

    let mut later_scope_denial = decision.clone();
    later_scope_denial["decision"] = json!("deny");
    later_scope_denial["public_code"] = json!("proof.authorization.scope_exceeded");
    later_scope_denial["reason_code"] = json!("proof.authorization.scope_exceeded");
    for (label, later_scope_failure) in [
        ("action", {
            let mut delegation = matching_delegation.clone();
            delegation["actions"] = json!([]);
            delegation
        }),
        ("resource", {
            let mut delegation = matching_delegation.clone();
            delegation["scope"]["object_ids"] = json!([]);
            delegation
        }),
    ] {
        assert!(decision_validator.is_valid(&later_scope_denial));
        assert_eq!(
            accepted_scope_or_revocation_denial(&later_scope_denial, &later_scope_failure),
            Some("proof.authorization.scope_exceeded"),
            "an unrevoked matching Delegation may reach the later {label}-scope check"
        );
        let mut revoked_before_later_scope = later_scope_denial.clone();
        revoked_before_later_scope["agent_authorization"]["delegation"]["revocation_record_digest"] =
            json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            accepted_scope_or_revocation_denial(&revoked_before_later_scope, &later_scope_failure,),
            Some("proof.authorization.delegation_revoked"),
            "Delegation revocation must prevent the later {label}-scope check"
        );
        assert_ne!(
            revoked_before_later_scope["reason_code"],
            json!(accepted_scope_or_revocation_denial(
                &revoked_before_later_scope,
                &later_scope_failure,
            )),
            "a revoked matching Delegation cannot claim a later {label}-scope denial"
        );
    }

    let mut generic_agent_denial = decision.clone();
    generic_agent_denial["decision"] = json!("deny");
    generic_agent_denial["public_code"] = json!("proof.authorization.denied");
    generic_agent_denial["reason_code"] = json!("proof.authorization.denied");
    assert!(
        !decision_validator.is_valid(&generic_agent_denial),
        "proof.authorization.denied is not an accepted direct-Agent source reason"
    );
    let mut generic_human_denial = generic_agent_denial.clone();
    generic_human_denial["authentication_profile"] =
        json!("proof.server/authentication/oidc-human/v1");
    generic_human_denial["agent_authorization"] = Value::Null;
    generic_human_denial["authorization_rule"] =
        json!("proof.server/authorization/workspace-reader/v1");
    assert!(
        decision_validator.is_valid(&generic_human_denial),
        "the disclosure-safe generic Human denial remains part of the signed union vocabulary"
    );
    let mut human_with_agent_source_reason = generic_human_denial;
    human_with_agent_source_reason["reason_code"] = json!("proof.authorization.policy_denied");
    assert!(
        !decision_validator.is_valid(&human_with_agent_source_reason),
        "the generic Human denial branch cannot substitute an Agent-direct source reason"
    );

    for (later_reason, public_code) in [
        (
            "proof.authorization.budget_exceeded",
            "proof.authorization.budget_exceeded",
        ),
        (
            "proof.authorization.delegation_expired",
            "proof.authorization.delegation_expired",
        ),
        (
            "proof.authorization.delegation_not_yet_valid",
            "proof.authorization.delegation_not_yet_valid",
        ),
        (
            "proof.authorization.policy_denied",
            "proof.authorization.denied",
        ),
        (
            "proof.delegation.chain_unsupported",
            "proof.authorization.denied",
        ),
    ] {
        let mut later_denial = decision.clone();
        later_denial["decision"] = json!("deny");
        later_denial["public_code"] = json!(public_code);
        later_denial["reason_code"] = json!(later_reason);
        assert!(
            decision_validator.is_valid(&later_denial),
            "{later_reason} must remain expressible after the earlier denial gates pass"
        );

        let mut disabled_before_later_check = later_denial.clone();
        disabled_before_later_check["agent_authorization"]["principal_state"]["operating_principal_enabled"] =
            json!(false);
        assert!(
            !decision_validator.is_valid(&disabled_before_later_check),
            "principal disablement must take precedence over {later_reason}"
        );

        let mut requesting_disabled_before_later_check = later_denial.clone();
        requesting_disabled_before_later_check["agent_authorization"]["principal_state"]["requesting_principal_enabled"] =
            json!(false);
        assert!(
            !decision_validator.is_valid(&requesting_disabled_before_later_check),
            "requesting-Principal disablement must take precedence over {later_reason}"
        );

        let mut inactive_before_later_check = later_denial.clone();
        inactive_before_later_check["agent_authorization"]["binding"]["active"] = json!(false);
        assert!(
            !decision_validator.is_valid(&inactive_before_later_check),
            "binding inactivity must take precedence over {later_reason}"
        );

        let mut revoked_before_later_check = later_denial.clone();
        revoked_before_later_check["agent_authorization"]["delegation"]["revocation_record_digest"] =
            json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(
            !decision_validator.is_valid(&revoked_before_later_check),
            "Delegation revocation must take precedence over {later_reason}"
        );

        let mut unavailable_before_later_check = later_denial;
        unavailable_before_later_check["agent_authorization"]["delegation"]["resolution"] =
            json!("not_found_or_hidden");
        unavailable_before_later_check["agent_authorization"]["delegation"]["record_digest"] =
            Value::Null;
        assert!(
            !decision_validator.is_valid(&unavailable_before_later_check),
            "Delegation unavailability must take precedence over {later_reason}"
        );
    }

    let agent_evidence_digest = canonical_digest(
        "proof:authenticated-actor-context-evidence:v2",
        &agent_evidence,
    );
    assert_eq!(decision["actor_context_digest"], agent_evidence_digest);
    let http_registry = parse_file(&collaboration_path(
        "vectors/http-operation-registry.valid.json",
    ));
    let operation_registry_sha256 = hex_lower(&sha256(
        &serde_json_canonicalizer::to_vec(&http_registry)
            .expect("the HTTP operation registry must RFC 8785 canonicalize"),
    ));
    assert_eq!(
        operation_registry_sha256,
        "e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf"
    );
    assert_eq!(
        decision["operation_registry_sha256"],
        operation_registry_sha256
    );
    assert_eq!(
        consequence["operation_registry_sha256"],
        operation_registry_sha256
    );
    assert_eq!(
        decision["authorization_registry_sha256"],
        http_registry["authorization_registry_commitment"]["authorization_registry_sha256"]
    );
    let mut mismatched_registry_pair = decision.clone();
    mismatched_registry_pair["authorization_registry_sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(decision_validator.is_valid(&mismatched_registry_pair));
    assert_ne!(
        mismatched_registry_pair["authorization_registry_sha256"],
        http_registry["authorization_registry_commitment"]["authorization_registry_sha256"],
        "the semantic verifier must reject independently allowlisted registry hashes that are not the committed full-registry/auth-projection pair"
    );
    let resource_projection = &http_registry["authorization_resource_projection"];
    let requested_resource_fields =
        resource_projection["agent_direct_requested_resources"]["fields"]
            .as_array()
            .unwrap();
    assert_eq!(requested_resource_fields.len(), 8);
    let nested_requested_resources = &decision["agent_authorization"]["requested_resources"];
    assert_eq!(
        requested_resource_fields
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        nested_requested_resources
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );
    let requested_resource_arrays_are_canonical = |resources: &Value| {
        resources.as_object().is_some_and(|fields| {
            fields.values().all(|value| {
                value.as_array().is_some_and(|items| {
                    items
                        .windows(2)
                        .all(|pair| pair[0].as_str().unwrap() < pair[1].as_str().unwrap())
                })
            })
        })
    };
    assert!(requested_resource_arrays_are_canonical(
        nested_requested_resources
    ));
    let mut unsorted_requested_resources = decision.clone();
    unsorted_requested_resources["agent_authorization"]["requested_resources"]["object_ids"] =
        json!([
            "019e1234-5678-7abc-8def-000000000082",
            "019e1234-5678-7abc-8def-000000000081",
        ]);
    assert!(decision_validator.is_valid(&unsorted_requested_resources));
    assert!(
        !requested_resource_arrays_are_canonical(
            &unsorted_requested_resources["agent_authorization"]["requested_resources"],
        ),
        "schema-valid resource arrays are rejected before evaluation when not UTF-8 sorted"
    );
    let requested_resource_bindings = nested_requested_resources
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| {
            let binding_preimage = json!({
                "api_version": "proof.dev/authorization-resource-binding/v1",
                "name": name,
                "value": value,
            });
            json!({
                "name": name,
                "value_digest": canonical_digest(
                    "proof:authorization-resource-binding:v1",
                    &binding_preimage,
                ),
            })
        })
        .collect::<Vec<_>>();
    let requested_resources_preimage = json!({
        "api_version": "proof.dev/requested-authorization-resources/v1",
        "authorization_registry_sha256": decision["authorization_registry_sha256"].clone(),
        "authorization_rule": decision["authorization_rule"].clone(),
        "operation": decision["operation"].clone(),
        "requested_action": decision["requested_action"].clone(),
        "bindings": requested_resource_bindings,
    });
    assert_eq!(
        decision["requested_resources_digest"],
        canonical_digest(
            "proof:requested-authorization-resources:v1",
            &requested_resources_preimage,
        )
    );
    assert_eq!(
        decision["requested_resources_digest"],
        "blake3:4fbc4c2df1351f3aa3c316102605d07501ecb029064fa661a9516fe05dba3251"
    );
    let environment_config = parse_file(&collaboration_path(
        "vectors/environment-config-v2.valid.json",
    ));
    assert_eq!(
        decision["environment_config_digest"],
        environment_config["environment_config_digest"]
    );
    let policy_selection_preimage = json!({
        "api_version": "proof.dev/remote-authorization-policy-selection/v1",
        "authorization_registry_sha256": decision["authorization_registry_sha256"].clone(),
        "authorization_rule": decision["authorization_rule"].clone(),
        "environment_config_digest": decision["environment_config_digest"].clone(),
        "environment_policy_bundle_digest": environment_config["normalized_configuration"]["policy_bundle_digest"].clone(),
    });
    assert_eq!(
        decision["policy_bundle_digest"],
        canonical_digest(
            "proof:remote-authorization-policy-selection:v1",
            &policy_selection_preimage,
        )
    );
    assert_eq!(
        decision["policy_bundle_digest"],
        "blake3:f1a941b4d67907001f74ea5d01fb38f51900ff36fee114fb7fb79dc5ff3e2712"
    );
    let release_result = parse_file(&collaboration_path(
        "vectors/release-create-result.private-test.json",
    ));
    let release_manifest = &release_result["release_manifest"];
    let release_policy_preimage = json!({
        "action": "release.create",
        "allowed": true,
        "api_version": "proof.dev/release-authorization-decision/v2",
        "base_release": release_manifest["base_release"].clone(),
        "changeset_id": release_manifest["changeset_id"].clone(),
        "edition": release_manifest["edition"].clone(),
        "environment_config_digest": release_manifest["environment_config_digest"].clone(),
        "environment_config_version": release_manifest["environment_config_version"].clone(),
        "environment_id": release_manifest["environment_id"].clone(),
        "evaluated_at": release_manifest["released_at"].clone(),
        "exact_delta_digest": release_manifest["exact_delta_digest"].clone(),
        "kind": release_manifest["kind"].clone(),
        "operating_principal_id": decision["requesting_principal_id"].clone(),
        "policy_profile": "proof.local/release-policy/v1",
        "required_approval": environment_config["normalized_configuration"]["approval_name"].clone(),
        "resource_intent_id": release_manifest["resource_intent_id"].clone(),
        "rollback_target_release_id": release_manifest["rollback_target_release_id"].clone(),
        "workspace_id": release_manifest["workspace_id"].clone(),
    });
    let release_policy_digest =
        canonical_digest("proof:authorization-decision:v1", &release_policy_preimage);
    assert_eq!(
        release_policy_digest,
        "blake3:61f16158b4515f1ddd753dc27ee952b9cdf461b73e5694ec2374b18fb3a444a6"
    );
    assert_eq!(
        release_manifest["authorization_decision_digest"],
        release_policy_digest
    );
    assert_eq!(
        release_manifest["principal_id"],
        decision["requesting_principal_id"]
    );
    assert_ne!(
        release_manifest["principal_id"],
        decision["agent_authorization"]["operating_principal_id"]
    );
    assert_eq!(
        canonical_digest("proof:release:v2", release_manifest),
        "blake3:cfa65f376f46fa29d5dc723102197442be2d9c84708251edb3153936a77632a1"
    );
    assert_eq!(
        release_result["release_digest"],
        canonical_digest("proof:release:v2", release_manifest)
    );
    let release_result_digest = canonical_digest("proof:operation-effect:v1", &release_result);
    assert_eq!(
        release_result_digest,
        "blake3:31523caf536aa25719fba4395176700b56d7316ce594fe18be1263a62fe781f4"
    );
    assert_fields_equal(
        &decision,
        &agent_evidence,
        &[
            "workspace_id",
            "operation",
            "public_input_projection_digest",
            "requesting_principal_id",
            "requesting_binding_id",
            "requesting_binding_record_digest",
            "requesting_subject_commitment",
        ],
        "actor evidence/authorization decision",
    );
    let agent_authorization = &decision["agent_authorization"];
    assert_fields_equal(
        agent_authorization,
        &agent_evidence,
        &[
            "command_digest",
            "command_envelope_digest",
            "operating_principal_id",
            "presentation_id",
        ],
        "Agent evidence/direct authorization",
    );
    assert_eq!(
        agent_authorization["delegation"]["delegation_id"],
        agent_evidence["delegation_id"]
    );
    assert_fields_equal(
        &agent_authorization["binding"],
        &agent_evidence["operating_binding"],
        &["authority_sequence", "binding_id", "record_digest"],
        "Agent binding evidence/direct authorization",
    );
    assert_eq!(decision["role_assignment_digests"], json!([]));

    let decision_digest = canonical_digest("proof:remote-authority-record:v1", &decision);
    assert_eq!(
        decision_digest,
        "blake3:72388b45610cdee98f362b58ba7ffcee0b5f2c93278b0b39841fb6c92c10d2b1"
    );
    assert_ne!(release_policy_digest, decision_digest);
    assert_eq!(consequence["decision_id"], decision["decision_id"]);
    assert_eq!(consequence["decision_digest"], decision_digest);
    assert_eq!(
        consequence["evaluated_authority_head"]["record_digest"],
        decision_digest
    );
    assert_eq!(
        consequence["evaluated_authority_head"]["sequence"],
        decision["authority_sequence"]
    );
    assert_eq!(
        consequence["authority_sequence"].as_u64(),
        decision["authority_sequence"]
            .as_u64()
            .map(|value| value + 1)
    );
    assert_fields_equal(
        &consequence,
        &decision,
        &[
            "workspace_id",
            "operation",
            "public_input_projection_digest",
            "authority_key_id",
        ],
        "authorization decision/application consequence",
    );
    assert_eq!(consequence["application_key_kind"], "required-uuidv7");
    assert!(
        validator(
            &contract_registry,
            &format!("{APPLICATION_SCHEMA_ID}#/$defs/uuidv7"),
        )
        .is_valid(&consequence["application_key"])
    );
    let release_create_input = parse_file(&collaboration_path(
        "vectors/release-create-input.private-test.json",
    ));
    assert_eq!(
        consequence["application_key"], release_create_input["idempotency_key"],
        "the application consequence binds the exact normalized release.create/v2 key"
    );
    let mut wrong_release_application_key = consequence.clone();
    wrong_release_application_key["application_key"] =
        json!("019e1234-5678-7abc-8def-000000000099");
    assert!(consequence_validator.is_valid(&wrong_release_application_key));
    assert_ne!(
        wrong_release_application_key["application_key"], release_create_input["idempotency_key"],
        "a schema-valid UUIDv7 substitution remains a semantic key-binding failure"
    );
    assert_eq!(consequence["outcome"], "success");
    assert_eq!(consequence["result_digest"], release_result_digest);
    assert_eq!(
        consequence["application_effect_digest"],
        release_result["release_digest"]
    );
    assert!(consequence["prior_result_digest"].is_null());
    assert!(consequence["problem_code"].is_null());
    assert!(consequence["application_effect_authority_head"].is_null());
    assert_eq!(
        consequence["previous_authority_record_digest"],
        decision_digest
    );

    let selected_release_row = route_qualified_operation_row(&http_registry, &decision)
        .expect("the Agent release operation must resolve to one route-qualified row");
    assert_eq!(selected_release_row["operation"], decision["operation"]);
    assert!(operation_row_authorization_projection_is_consistent(
        &http_registry,
        &decision,
        selected_release_row,
    ));
    let expected_application_key = consequence["application_key"].clone();
    assert!(consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &consequence,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut replay = consequence.clone();
    replay["outcome"] = json!("idempotent-replay");
    replay["application_effect_digest"] = Value::Null;
    replay["prior_result_digest"] = consequence["result_digest"].clone();
    assert!(consequence_validator.is_valid(&replay));

    let mut idempotency_conflict = replay.clone();
    idempotency_conflict["outcome"] = json!("idempotency-conflict");
    idempotency_conflict["problem_code"] = json!("proof.idempotency.key_reused");
    idempotency_conflict["result_digest"] = json!(application_problem_digest(
        &idempotency_conflict["operation"],
        &idempotency_conflict["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&idempotency_conflict));

    let mut precondition_conflict = idempotency_conflict.clone();
    precondition_conflict["outcome"] = json!("precondition-conflict");
    precondition_conflict["prior_result_digest"] = Value::Null;
    precondition_conflict["problem_code"] = json!("proof.state.conflict");
    precondition_conflict["result_digest"] = json!(application_problem_digest(
        &precondition_conflict["operation"],
        &precondition_conflict["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&precondition_conflict));

    let application_failure_code = selected_release_row["application_problem_codes"]
        .as_array()
        .and_then(|codes| codes.first())
        .expect("the Agent release row must declare a post-Allow failure code")
        .clone();
    let mut application_failure = precondition_conflict.clone();
    application_failure["outcome"] = json!("application-failure");
    application_failure["problem_code"] = application_failure_code;
    application_failure["result_digest"] = json!(application_problem_digest(
        &application_failure["operation"],
        &application_failure["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&application_failure));

    for (label, candidate, needs_stored_success) in [
        ("success", &consequence, false),
        ("idempotent-replay", &replay, true),
        ("idempotency-conflict", &idempotency_conflict, true),
        ("precondition-conflict", &precondition_conflict, false),
        ("application-failure", &application_failure, false),
    ] {
        let stored_success = needs_stored_success.then_some((&decision, &consequence));
        assert!(
            consequence_semantics_are_valid(
                &http_registry,
                &decision,
                candidate,
                &expected_application_key,
                &release_result,
                &release_result["release_digest"],
                stored_success,
            ),
            "the {label} consequence must satisfy its exact row-qualified branch"
        );
        if label != "success" {
            assert!(candidate["application_effect_digest"].is_null());
            assert!(candidate["application_effect_authority_head"].is_null());
            assert_eq!(
                candidate["evaluated_authority_head"],
                json!({
                    "record_digest": decision_digest.clone(),
                    "sequence": decision["authority_sequence"].clone(),
                })
            );
            assert_eq!(
                candidate["authority_sequence"].as_u64(),
                decision["authority_sequence"]
                    .as_u64()
                    .map(|sequence| sequence + 1)
            );
            assert!(
                parse_instant(&candidate["recorded_at"])
                    >= parse_instant(&decision["evaluated_at"])
            );
        }
    }

    let mut wrong_failure_preimage = application_failure.clone();
    wrong_failure_preimage["result_digest"] = json!(canonical_digest(
        "proof:operation-effect:v1",
        &json!({
            "api_version": "proof.dev/application-problem-digest-preimage/v1",
            "code": wrong_failure_preimage["problem_code"].clone(),
            "detail": "transport-only detail must not enter the digest",
            "operation": wrong_failure_preimage["operation"].clone(),
        }),
    ));
    assert!(consequence_validator.is_valid(&wrong_failure_preimage));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &wrong_failure_preimage,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut replay_with_wrong_prior = replay.clone();
    replay_with_wrong_prior["prior_result_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(consequence_validator.is_valid(&replay_with_wrong_prior));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &replay_with_wrong_prior,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        Some((&decision, &consequence)),
    ));

    let mut conflict_with_wrong_prior = idempotency_conflict.clone();
    conflict_with_wrong_prior["prior_result_digest"] =
        json!("blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(consequence_validator.is_valid(&conflict_with_wrong_prior));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &conflict_with_wrong_prior,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        Some((&decision, &consequence)),
    ));

    let mut wrong_row_code = application_failure.clone();
    wrong_row_code["problem_code"] = json!("proof.delegation.expired");
    wrong_row_code["result_digest"] = json!(application_problem_digest(
        &wrong_row_code["operation"],
        &wrong_row_code["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&wrong_row_code));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &wrong_row_code,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut wrong_key_kind = precondition_conflict.clone();
    wrong_key_kind["application_key_kind"] = json!("none");
    wrong_key_kind["application_key"] = Value::Null;
    assert!(consequence_validator.is_valid(&wrong_key_kind));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &wrong_key_kind,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut wrong_key_linkage = precondition_conflict.clone();
    wrong_key_linkage["application_key"] = json!("019e1234-5678-7abc-8def-000000000099");
    assert!(consequence_validator.is_valid(&wrong_key_linkage));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &wrong_key_linkage,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut wrong_head_linkage = precondition_conflict.clone();
    wrong_head_linkage["evaluated_authority_head"]["record_digest"] =
        json!("blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    assert!(consequence_validator.is_valid(&wrong_head_linkage));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &wrong_head_linkage,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut consequence_before_decision = precondition_conflict.clone();
    consequence_before_decision["recorded_at"] = json!("2026-08-23T03:09:59Z");
    assert!(consequence_validator.is_valid(&consequence_before_decision));
    assert!(!consequence_semantics_are_valid(
        &http_registry,
        &decision,
        &consequence_before_decision,
        &expected_application_key,
        &release_result,
        &release_result["release_digest"],
        None,
    ));

    let mut human_decision = decision.clone();
    human_decision["authentication_profile"] = json!("proof.server/authentication/oidc-human/v1");
    human_decision["agent_authorization"] = Value::Null;
    human_decision["authorization_rule"] =
        json!("proof.server/authorization/workspace-role-admin/v1");
    human_decision["operation"] = json!({
        "name": "workspace-role.assign",
        "version": "proof.dev/operation/workspace-role.assign/v1",
    });
    human_decision["requested_action"] = json!("workspace_role:assign");
    human_decision["role_assignment_digests"] =
        json!(["blake3:3030303030303030303030303030303030303030303030303030303030303030"]);
    human_decision["environment_config_digest"] = Value::Null;
    human_decision["policy_bundle_digest"] = json!(canonical_digest(
        "proof:remote-authorization-policy-selection:v1",
        &json!({
            "api_version": "proof.dev/remote-authorization-policy-selection/v1",
            "authorization_registry_sha256": human_decision["authorization_registry_sha256"].clone(),
            "authorization_rule": human_decision["authorization_rule"].clone(),
            "environment_config_digest": null,
            "environment_policy_bundle_digest": null,
        }),
    ));
    assert!(decision_validator.is_valid(&human_decision));

    let mut human_context_decision = human_decision.clone();
    human_context_decision["authorization_rule"] =
        json!("proof.server/authorization/initial-context-requester/v1");
    human_context_decision["operation"] = json!({
        "name": "context.build",
        "version": "proof.dev/operation/context.build/v2",
    });
    human_context_decision["requested_action"] = json!("context:build");
    human_context_decision["policy_bundle_digest"] = json!(canonical_digest(
        "proof:remote-authorization-policy-selection:v1",
        &json!({
            "api_version": "proof.dev/remote-authorization-policy-selection/v1",
            "authorization_registry_sha256": human_context_decision["authorization_registry_sha256"].clone(),
            "authorization_rule": human_context_decision["authorization_rule"].clone(),
            "environment_config_digest": null,
            "environment_policy_bundle_digest": null,
        }),
    ));
    assert!(decision_validator.is_valid(&human_context_decision));

    let mut agent_context_decision = decision.clone();
    agent_context_decision["operation"] = human_context_decision["operation"].clone();
    agent_context_decision["requested_action"] = human_context_decision["requested_action"].clone();
    assert!(decision_validator.is_valid(&agent_context_decision));

    let human_context_row = route_qualified_operation_row(&http_registry, &human_context_decision)
        .expect("Human context.build/v2 must select exactly its Human route row");
    let agent_context_row = route_qualified_operation_row(&http_registry, &agent_context_decision)
        .expect("Agent context.build/v2 must select exactly its Agent route row");
    assert_eq!(
        human_context_row["operation"],
        agent_context_row["operation"]
    );
    assert_ne!(
        human_context_row, agent_context_row,
        "the duplicate operation pair has profile-specific committed semantics"
    );
    assert!(operation_row_authorization_projection_is_consistent(
        &http_registry,
        &human_context_decision,
        human_context_row,
    ));
    assert!(operation_row_authorization_projection_is_consistent(
        &http_registry,
        &agent_context_decision,
        agent_context_row,
    ));
    assert!(!operation_row_authorization_projection_is_consistent(
        &http_registry,
        &human_context_decision,
        agent_context_row,
    ));
    assert!(!operation_row_authorization_projection_is_consistent(
        &http_registry,
        &agent_context_decision,
        human_context_row,
    ));

    let mut wrong_human_authorization_projection = human_context_decision.clone();
    wrong_human_authorization_projection["authorization_rule"] =
        json!("proof.server/authorization/workspace-role-admin/v1");
    wrong_human_authorization_projection["policy_bundle_digest"] = json!(canonical_digest(
        "proof:remote-authorization-policy-selection:v1",
        &json!({
            "api_version": "proof.dev/remote-authorization-policy-selection/v1",
            "authorization_registry_sha256": wrong_human_authorization_projection["authorization_registry_sha256"].clone(),
            "authorization_rule": wrong_human_authorization_projection["authorization_rule"].clone(),
            "environment_config_digest": null,
            "environment_policy_bundle_digest": null,
        }),
    ));
    assert!(decision_validator.is_valid(&wrong_human_authorization_projection));
    assert!(!operation_row_authorization_projection_is_consistent(
        &http_registry,
        &wrong_human_authorization_projection,
        human_context_row,
    ));
    let mut wrong_agent_authorization_projection = agent_context_decision.clone();
    wrong_agent_authorization_projection["requested_action"] = json!("release:create");
    assert!(decision_validator.is_valid(&wrong_agent_authorization_projection));
    assert!(!operation_row_authorization_projection_is_consistent(
        &http_registry,
        &wrong_agent_authorization_projection,
        agent_context_row,
    ));

    let agent_only_code = json!("proof.validation.repair_evidence_invalid");
    assert!(
        agent_context_row["application_problem_codes"]
            .as_array()
            .is_some_and(|codes| codes.contains(&agent_only_code))
    );
    assert!(
        human_context_row["application_problem_codes"]
            .as_array()
            .is_some_and(|codes| !codes.contains(&agent_only_code))
    );
    let human_context_decision_digest =
        canonical_digest("proof:remote-authority-record:v1", &human_context_decision);
    let mut human_context_failure = application_failure.clone();
    human_context_failure["decision_id"] = human_context_decision["decision_id"].clone();
    human_context_failure["decision_digest"] = json!(human_context_decision_digest.clone());
    human_context_failure["operation"] = human_context_decision["operation"].clone();
    human_context_failure["public_input_projection_digest"] =
        human_context_decision["public_input_projection_digest"].clone();
    human_context_failure["evaluated_authority_head"] = json!({
        "record_digest": human_context_decision_digest.clone(),
        "sequence": human_context_decision["authority_sequence"].clone(),
    });
    human_context_failure["previous_authority_record_digest"] =
        json!(human_context_decision_digest);
    human_context_failure["authority_sequence"] = json!(
        human_context_decision["authority_sequence"]
            .as_u64()
            .unwrap()
            + 1
    );
    let human_application_code = human_context_row["application_problem_codes"]
        .as_array()
        .and_then(|codes| codes.first())
        .expect("Human context.build/v2 must declare an application failure")
        .clone();
    human_context_failure["problem_code"] = human_application_code;
    human_context_failure["result_digest"] = json!(application_problem_digest(
        &human_context_failure["operation"],
        &human_context_failure["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&human_context_failure));
    assert!(consequence_semantics_are_valid(
        &http_registry,
        &human_context_decision,
        &human_context_failure,
        &expected_application_key,
        &release_result,
        &Value::Null,
        None,
    ));

    let mut agent_only_code_on_human_row = human_context_failure.clone();
    agent_only_code_on_human_row["problem_code"] = agent_only_code;
    agent_only_code_on_human_row["result_digest"] = json!(application_problem_digest(
        &agent_only_code_on_human_row["operation"],
        &agent_only_code_on_human_row["problem_code"],
    ));
    assert!(consequence_validator.is_valid(&agent_only_code_on_human_row));
    assert!(
        !consequence_semantics_are_valid(
            &http_registry,
            &human_context_decision,
            &agent_only_code_on_human_row,
            &expected_application_key,
            &release_result,
            &Value::Null,
            None,
        ),
        "an Agent-only application code cannot be imported into the duplicate Human context.build/v2 row"
    );

    let digests_are_canonical = |digests: &Value| {
        digests.as_array().is_some_and(|items| {
            items
                .windows(2)
                .all(|pair| pair[0].as_str().unwrap() < pair[1].as_str().unwrap())
        })
    };
    assert!(digests_are_canonical(
        &human_decision["role_assignment_digests"]
    ));
    let mut unsorted_role_assignments = human_decision.clone();
    unsorted_role_assignments["role_assignment_digests"] = json!([
        "blake3:4040404040404040404040404040404040404040404040404040404040404040",
        "blake3:3030303030303030303030303030303030303030303030303030303030303030",
    ]);
    assert!(decision_validator.is_valid(&unsorted_role_assignments));
    assert!(
        !digests_are_canonical(&unsorted_role_assignments["role_assignment_digests"]),
        "schema-valid role digests are rejected before decision acceptance when not UTF-8 sorted"
    );
    let human_decision_digest =
        canonical_digest("proof:remote-authority-record:v1", &human_decision);

    let mut human_authority_effect = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    human_authority_effect["assigned_at"] = json!("2026-08-23T03:10:01Z");
    human_authority_effect["assigned_by_actor_context_digest"] =
        human_decision["actor_context_digest"].clone();
    human_authority_effect["assigned_by_principal_id"] =
        human_decision["requesting_principal_id"].clone();
    human_authority_effect["evaluated_authority_head"] = json!({
        "sequence": human_decision["authority_sequence"].clone(),
        "record_digest": human_decision_digest.clone(),
    });
    human_authority_effect["previous_authority_record_digest"] =
        json!(human_decision_digest.clone());
    human_authority_effect["authority_sequence"] =
        json!(human_decision["authority_sequence"].as_u64().unwrap() + 1);
    assert!(
        validator(
            &contract_registry,
            &format!("{ARTIFACT_SCHEMA_ID}#/$defs/workspaceRoleAssignmentV1"),
        )
        .is_valid(&human_authority_effect)
    );
    let human_effect_digest =
        canonical_digest("proof:remote-authority-record:v1", &human_authority_effect);

    let mut human_consequence = consequence.clone();
    human_consequence["decision_id"] = human_decision["decision_id"].clone();
    human_consequence["decision_digest"] = json!(human_decision_digest.clone());
    human_consequence["operation"] = human_decision["operation"].clone();
    human_consequence["public_input_projection_digest"] =
        human_decision["public_input_projection_digest"].clone();
    human_consequence["application_effect_digest"] = json!(human_effect_digest.clone());
    human_consequence["application_effect_authority_head"] = json!({
        "sequence": human_authority_effect["authority_sequence"].clone(),
        "record_digest": human_effect_digest.clone(),
    });
    human_consequence["evaluated_authority_head"] =
        human_consequence["application_effect_authority_head"].clone();
    human_consequence["previous_authority_record_digest"] = json!(human_effect_digest.clone());
    human_consequence["authority_sequence"] = json!(
        human_authority_effect["authority_sequence"]
            .as_u64()
            .unwrap()
            + 1
    );
    human_consequence["recorded_at"] = json!("2026-08-23T03:10:02Z");
    human_consequence["result_digest"] = json!(canonical_digest(
        "proof:operation-effect:v1",
        &human_authority_effect,
    ));
    assert!(consequence_validator.is_valid(&human_consequence));
    assert_eq!(
        human_authority_effect["authority_sequence"].as_u64(),
        human_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 1)
    );
    assert_eq!(
        human_consequence["authority_sequence"].as_u64(),
        human_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 2)
    );
    assert_eq!(
        human_consequence["application_effect_authority_head"]["record_digest"],
        human_consequence["application_effect_digest"]
    );
    assert_eq!(
        human_authority_effect["evaluated_authority_head"],
        json!({
            "sequence": human_decision["authority_sequence"].clone(),
            "record_digest": human_decision_digest.clone(),
        })
    );
    let successor_timestamp_field = http_registry["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|route| route["operations"].as_array())
        .flatten()
        .find(|row| row["operation"]["version"] == "proof.dev/operation/workspace-role.assign/v1")
        .unwrap()["effect_digest_rule"]["effect_timestamp_field"]
        .as_str()
        .unwrap();
    assert_eq!(successor_timestamp_field, "assigned_at");
    let authority_effect_time_is_ordered =
        |decision: &Value, effect: &Value, timestamp_field: &str, consequence: &Value| {
            parse_instant(&decision["evaluated_at"]) <= parse_instant(&effect[timestamp_field])
                && parse_instant(&effect[timestamp_field])
                    <= parse_instant(&consequence["recorded_at"])
        };
    assert!(
        authority_effect_time_is_ordered(
            &human_decision,
            &human_authority_effect,
            successor_timestamp_field,
            &human_consequence,
        ),
        "the successor authority effect's registry-selected time must fall between decision and consequence"
    );
    let mut effect_before_decision = human_authority_effect.clone();
    effect_before_decision[successor_timestamp_field] = json!("2026-08-23T03:09:59Z");
    assert!(
        validator(
            &contract_registry,
            &format!("{ARTIFACT_SCHEMA_ID}#/$defs/workspaceRoleAssignmentV1"),
        )
        .is_valid(&effect_before_decision),
        "the effect payload remains structurally valid so the cross-record semantic check is necessary"
    );
    assert!(
        !authority_effect_time_is_ordered(
            &human_decision,
            &effect_before_decision,
            successor_timestamp_field,
            &human_consequence,
        ),
        "an authority effect cannot predate its authorizing decision"
    );
    let mut fractional_effect_after_decision = human_authority_effect.clone();
    fractional_effect_after_decision[successor_timestamp_field] = json!("2026-08-23T03:10:00.1Z");
    assert!(authority_effect_time_is_ordered(
        &human_decision,
        &fractional_effect_after_decision,
        successor_timestamp_field,
        &human_consequence,
    ));
    let mut fractional_effect_after_consequence = human_authority_effect.clone();
    fractional_effect_after_consequence[successor_timestamp_field] =
        json!("2026-08-23T03:10:02.1Z");
    assert!(
        !authority_effect_time_is_ordered(
            &human_decision,
            &fractional_effect_after_consequence,
            successor_timestamp_field,
            &human_consequence,
        ),
        "fractional RFC3339 instants are compared chronologically rather than lexicographically"
    );

    let mut legacy_decision = human_decision.clone();
    legacy_decision["authorization_rule"] =
        json!("proof.server/authorization/agent-binding-admin/v1");
    legacy_decision["operation"] = json!({
        "name": "agent-binding.issue",
        "version": "proof.dev/operation/agent-binding.issue/v1",
    });
    legacy_decision["requested_action"] = json!("agent_binding:issue");
    legacy_decision["policy_bundle_digest"] = json!(canonical_digest(
        "proof:remote-authorization-policy-selection:v1",
        &json!({
            "api_version": "proof.dev/remote-authorization-policy-selection/v1",
            "authorization_registry_sha256": legacy_decision["authorization_registry_sha256"].clone(),
            "authorization_rule": legacy_decision["authorization_rule"].clone(),
            "environment_config_digest": null,
            "environment_policy_bundle_digest": null,
        }),
    ));
    assert!(decision_validator.is_valid(&legacy_decision));
    let legacy_decision_digest =
        canonical_digest("proof:remote-authority-record:v1", &legacy_decision);

    let mut legacy_authority_effect = parse_file(
        &repository_root().join("conformance/v1/authority/vectors/principal-binding.valid.json"),
    );
    legacy_authority_effect["workspace_id"] = legacy_decision["workspace_id"].clone();
    legacy_authority_effect["audience"] = json!(format!(
        "proof://workspace/{}",
        legacy_decision["workspace_id"].as_str().unwrap()
    ));
    legacy_authority_effect["issued_by_principal_id"] =
        legacy_decision["requesting_principal_id"].clone();
    legacy_authority_effect["issued_at"] = json!("2026-08-23T03:10:01Z");
    legacy_authority_effect["previous_authority_record_digest"] =
        json!(legacy_decision_digest.clone());
    legacy_authority_effect["authority_sequence"] =
        json!(legacy_decision["authority_sequence"].as_u64().unwrap() + 1);
    let legacy_effect_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/authority/principal-binding/v1",
    );
    assert!(legacy_effect_validator.is_valid(&legacy_authority_effect));
    assert!(
        legacy_authority_effect
            .as_object()
            .is_some_and(|effect| !effect.contains_key("evaluated_authority_head")),
        "accepted legacy PrincipalBindingV1 bytes do not carry a successor-only evaluated head"
    );
    let mut legacy_effect_with_successor_head = legacy_authority_effect.clone();
    legacy_effect_with_successor_head["evaluated_authority_head"] = json!({
        "sequence": legacy_decision["authority_sequence"].clone(),
        "record_digest": legacy_decision_digest.clone(),
    });
    assert!(
        !legacy_effect_validator.is_valid(&legacy_effect_with_successor_head),
        "the legacy payload must not be extended with successor authority-head bytes"
    );
    assert_eq!(
        legacy_authority_effect["authority_sequence"].as_u64(),
        legacy_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 1)
    );
    assert_eq!(
        legacy_authority_effect["previous_authority_record_digest"],
        legacy_decision_digest
    );
    let legacy_effect_digest =
        canonical_digest("proof:remote-authority-record:v1", &legacy_authority_effect);

    let mut legacy_consequence = human_consequence.clone();
    legacy_consequence["decision_id"] = legacy_decision["decision_id"].clone();
    legacy_consequence["decision_digest"] = json!(legacy_decision_digest.clone());
    legacy_consequence["operation"] = legacy_decision["operation"].clone();
    legacy_consequence["public_input_projection_digest"] =
        legacy_decision["public_input_projection_digest"].clone();
    legacy_consequence["application_effect_digest"] = json!(legacy_effect_digest.clone());
    legacy_consequence["application_effect_authority_head"] = json!({
        "sequence": legacy_authority_effect["authority_sequence"].clone(),
        "record_digest": legacy_effect_digest.clone(),
    });
    legacy_consequence["evaluated_authority_head"] =
        legacy_consequence["application_effect_authority_head"].clone();
    legacy_consequence["previous_authority_record_digest"] = json!(legacy_effect_digest.clone());
    legacy_consequence["authority_sequence"] =
        json!(legacy_decision["authority_sequence"].as_u64().unwrap() + 2);
    legacy_consequence["recorded_at"] = json!("2026-08-23T03:10:02Z");
    legacy_consequence["result_digest"] = json!(canonical_digest(
        "proof:operation-effect:v1",
        &legacy_authority_effect,
    ));
    assert!(consequence_validator.is_valid(&legacy_consequence));
    assert_eq!(
        legacy_consequence["application_effect_authority_head"]["record_digest"],
        legacy_consequence["application_effect_digest"]
    );
    assert_eq!(
        legacy_consequence["authority_sequence"].as_u64(),
        legacy_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 2)
    );
    let legacy_timestamp_field = http_registry["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|route| route["operations"].as_array())
        .flatten()
        .find(|row| row["operation"]["version"] == "proof.dev/operation/agent-binding.issue/v1")
        .unwrap()["effect_digest_rule"]["effect_timestamp_field"]
        .as_str()
        .unwrap();
    assert_eq!(legacy_timestamp_field, "issued_at");
    assert!(
        authority_effect_time_is_ordered(
            &legacy_decision,
            &legacy_authority_effect,
            legacy_timestamp_field,
            &legacy_consequence,
        ),
        "the legacy authority effect's registry-selected time must fall between decision and consequence"
    );

    let mut authority_head_on_failure = consequence.clone();
    authority_head_on_failure["outcome"] = json!("application-failure");
    authority_head_on_failure["application_effect_digest"] = Value::Null;
    authority_head_on_failure["application_effect_authority_head"] =
        human_consequence["application_effect_authority_head"].clone();
    authority_head_on_failure["problem_code"] = json!("proof.state.conflict");
    assert!(
        !consequence_validator.is_valid(&authority_head_on_failure),
        "a failed application attempt cannot claim an appended effect authority head"
    );
    let mut authority_head_with_null_effect = consequence.clone();
    authority_head_with_null_effect["application_effect_digest"] = Value::Null;
    authority_head_with_null_effect["application_effect_authority_head"] =
        human_consequence["application_effect_authority_head"].clone();
    assert!(
        !consequence_validator.is_valid(&authority_head_with_null_effect),
        "a non-null effect authority head requires a non-null application effect digest"
    );
    let mut wrong_human_adjacency = human_consequence.clone();
    wrong_human_adjacency["authority_sequence"] =
        json!(human_decision["authority_sequence"].as_u64().unwrap() + 1);
    assert!(consequence_validator.is_valid(&wrong_human_adjacency));
    assert_ne!(
        wrong_human_adjacency["authority_sequence"].as_u64(),
        human_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 2),
        "the semantic validator must reject a consequence that collides with its intervening authority effect"
    );
    let mut wrong_human_effect_head = human_consequence.clone();
    wrong_human_effect_head["application_effect_authority_head"]["record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(consequence_validator.is_valid(&wrong_human_effect_head));
    assert_ne!(
        wrong_human_effect_head["application_effect_authority_head"]["record_digest"],
        human_effect_digest,
        "the semantic validator must reject an authority-effect head that does not name the exact persisted effect"
    );
    assert!(
        parse_instant(&authentication_event["authenticated_at"])
            <= parse_instant(&decision["evaluated_at"])
    );
    assert!(
        parse_instant(&decision["evaluated_at"])
            < parse_instant(&authentication_event["expires_at"])
    );
    assert!(
        binding_revocation["authority_sequence"].as_u64()
            > consequence["authority_sequence"].as_u64()
    );
    assert!(
        parse_instant(&binding_revocation["revoked_at"])
            > parse_instant(&consequence["recorded_at"])
    );
    assert_eq!(
        canonical_digest("proof:remote-authority-record:v1", &consequence),
        "blake3:e4c349626423fa88dcf844ee026da2cb6e0db2334bb99b6588c55450e19da119"
    );
}

#[test]
fn causal_authority_vectors_use_the_immediate_locked_head() {
    for file_name in [
        "changeset-approval.valid.json",
        "environment-config-activation.valid.json",
        "environment-config-proposal.valid.json",
        "oidc-principal-binding-revocation.valid.json",
        "oidc-principal-binding.valid.json",
        "remote-application-consequence.valid.json",
        "remote-authorization-decision.valid.json",
        "remote-principal-status.valid.json",
        "workspace-role-assignment.valid.json",
        "workspace-role-revocation.valid.json",
    ] {
        assert_causal_record(&parse_file(&collaboration_path(&format!(
            "vectors/{file_name}"
        ))));
    }

    let role_assignment = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    let approval = parse_file(&collaboration_path("vectors/changeset-approval.valid.json"));
    let role_revocation = parse_file(&collaboration_path(
        "vectors/workspace-role-revocation.valid.json",
    ));
    let authority_envelope = parse_file(&collaboration_path(
        "vectors/remote-authority-record-envelope.valid.json",
    ));
    let role_assignment_digest =
        canonical_digest("proof:remote-authority-record:v1", &role_assignment);
    let approval_digest = canonical_digest("proof:remote-authority-record:v1", &approval);
    assert_eq!(
        approval["reviewer_role_assignment_digest"],
        role_assignment_digest
    );
    assert_eq!(
        role_revocation["assignment_record_digest"],
        role_assignment_digest
    );
    assert_eq!(
        role_revocation["evaluated_authority_head"]["record_digest"],
        approval_digest
    );
    assert_eq!(
        role_revocation["evaluated_authority_head"]["sequence"],
        approval["authority_sequence"]
    );
    assert!(
        parse_instant(&role_revocation["revoked_at"]) > parse_instant(&approval["approved_at"])
    );
    assert_fields_equal(
        &role_revocation,
        &role_assignment,
        &[
            "workspace_id",
            "assignment_id",
            "principal_id",
            "role",
            "authority_key_id",
        ],
        "role assignment/revocation",
    );
    assert_eq!(approval["workspace_id"], role_assignment["workspace_id"]);
    assert_eq!(
        approval["approver_principal_id"],
        role_assignment["principal_id"]
    );
    assert_eq!(role_assignment["role"], "content.reviewer");
    assert_eq!(
        approval["authority_key_id"],
        role_assignment["authority_key_id"]
    );
    assert_eq!(
        authority_envelope["signatures"][0]["keyid"],
        role_assignment["authority_key_id"]
    );
    assert_eq!(
        canonical_digest("proof:remote-authority-record:v1", &role_revocation),
        "blake3:d748011804b459a0beb5f0be54e166ad34aaa8c2fa507978a8bea56de21297b0"
    );

    let config = parse_file(&collaboration_path(
        "vectors/environment-config-v2.valid.json",
    ));
    let environment_creation = parse_file(&collaboration_path(
        "vectors/environment-creation.valid.json",
    ));
    let config_proposal = parse_file(&collaboration_path(
        "vectors/environment-config-proposal.valid.json",
    ));
    let config_activation = parse_file(&collaboration_path(
        "vectors/environment-config-activation.valid.json",
    ));
    assert_eq!(config["environment_creation"], environment_creation);
    assert_eq!(config["proposal"], config_proposal);
    assert_eq!(config["activation"], config_activation);
    assert_causal_record(&config["proposal"]);
    assert_causal_record(&config["activation"]);
    assert_eq!(config["workspace_id"], config["proposal"]["workspace_id"]);
    assert_eq!(config["workspace_id"], config["activation"]["workspace_id"]);
    assert_eq!(
        config["environment_id"],
        config["proposal"]["environment_id"]
    );
    assert_eq!(
        config["environment_id"],
        config["activation"]["environment_id"]
    );
    assert_eq!(
        config["predecessor_config_version"],
        config["proposal"]["expected_predecessor_config_version"]
    );
    assert_eq!(
        config["predecessor_config_version"],
        config["activation"]["predecessor_config_version"]
    );
    assert_eq!(
        config["predecessor_config_digest"],
        config["proposal"]["expected_predecessor_config_digest"]
    );
    assert_eq!(
        config["predecessor_config_digest"],
        config["activation"]["predecessor_config_digest"]
    );
    assert_eq!(
        config["normalized_configuration"],
        config["proposal"]["normalized_configuration"]
    );
    assert_eq!(
        config["normalized_configuration_digest"],
        config["proposal"]["normalized_configuration_digest"]
    );
    assert_eq!(
        config["normalized_configuration_digest"],
        config["activation"]["normalized_configuration_digest"]
    );
    assert_eq!(
        config["environment_config_version"],
        config["activation"]["environment_config_version"]
    );
    assert_eq!(
        config["environment_config_digest"],
        config["activation"]["environment_config_digest"]
    );
    assert_eq!(
        config["proposal_record_digest"],
        config["activation"]["proposal_digest"]
    );
    let normalized_configuration_digest = canonical_digest(
        "proof:environment-config:v2",
        &config["normalized_configuration"],
    );
    let environment_creation_record_digest =
        canonical_digest("proof:remote-authority-record:v1", &environment_creation);
    let proposal_record_digest =
        canonical_digest("proof:remote-authority-record:v1", &config_proposal);
    let activation_record_digest =
        canonical_digest("proof:remote-authority-record:v1", &config_activation);
    assert_eq!(
        config["normalized_configuration_digest"],
        normalized_configuration_digest
    );
    assert_eq!(
        config["environment_config_digest"],
        normalized_configuration_digest
    );
    assert_eq!(
        config["environment_creation_record_digest"],
        environment_creation_record_digest
    );
    assert_eq!(
        config_activation["environment_creation_record_digest"],
        environment_creation_record_digest
    );
    assert_eq!(config["proposal_record_digest"], proposal_record_digest);
    assert_eq!(config_activation["proposal_digest"], proposal_record_digest);
    assert_eq!(
        config_activation["evaluated_authority_head"]["record_digest"],
        proposal_record_digest
    );
    assert_eq!(
        config_activation["evaluated_authority_head"]["sequence"],
        config_proposal["authority_sequence"]
    );
    assert_eq!(config["activation_record_digest"], activation_record_digest);
    assert_eq!(
        config_activation["environment_created_at"],
        environment_creation["created_at"]
    );
    assert_eq!(
        config_activation["environment_created_by_principal_id"],
        environment_creation["created_by_principal_id"]
    );
    assert_eq!(
        config_activation["environment_created_by_actor_context_digest"],
        environment_creation["created_by_actor_context_digest"]
    );
    assert_eq!(
        config_activation["environment_creation_authority_sequence"],
        environment_creation["authority_sequence"]
    );
    assert_fields_equal(
        &config_proposal,
        &config_activation,
        &["workspace_id", "environment_id", "authority_key_id"],
        "configuration proposal/activation",
    );
    assert_eq!(
        environment_creation["authority_key_id"],
        config_proposal["authority_key_id"]
    );
    assert_ne!(
        config["proposal"]["proposed_by_principal_id"],
        config["activation"]["activated_by_principal_id"]
    );
}

#[test]
fn artifact_root_requires_signed_authority_while_exact_payload_fragments_remain_usable() {
    let (_, registry) = schema_registry();
    let root = validator(&registry, ARTIFACT_SCHEMA_ID);
    let authority_union = validator(
        &registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/remoteAuthorityRecordV1"),
    );
    let raw_authority_vectors = [
        (
            "oidc-principal-binding.valid.json",
            "https://proof.dev/schema/collaboration-server/remote-auth/v1#/$defs/oidcPrincipalBindingV1",
        ),
        (
            "oidc-principal-binding-revocation.valid.json",
            "https://proof.dev/schema/collaboration-server/remote-auth/v1#/$defs/oidcPrincipalBindingRevocationV1",
        ),
        (
            "workspace-role-assignment.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/workspaceRoleAssignmentV1",
        ),
        (
            "workspace-role-revocation.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/workspaceRoleRevocationV1",
        ),
        (
            "changeset-approval.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/changeSetApprovalV1",
        ),
        (
            "environment-creation.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/environmentCreationV1",
        ),
        (
            "environment-config-proposal.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/environmentConfigProposalV1",
        ),
        (
            "environment-config-activation.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/environmentConfigActivationV1",
        ),
        (
            "remote-principal-status.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/remotePrincipalStatusV2",
        ),
        (
            "remote-authorization-decision.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/remoteAuthorizationDecisionV1",
        ),
        (
            "remote-application-consequence.valid.json",
            "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/remoteApplicationConsequenceV1",
        ),
    ];

    for (file_name, fragment) in raw_authority_vectors {
        let value = parse_file(&collaboration_path(&format!("vectors/{file_name}")));
        assert!(
            validator(&registry, fragment).is_valid(&value),
            "{file_name} must remain valid at its exact decoded-payload fragment"
        );
        assert!(
            authority_union.is_valid(&value),
            "{file_name} must remain a member of the closed authority union"
        );
        assert!(
            !root.is_valid(&value),
            "{file_name} must not be accepted as an unsigned persisted root artifact"
        );
    }

    let envelope = parse_file(&collaboration_path(
        "vectors/remote-authority-record-envelope.valid.json",
    ));
    assert!(root.is_valid(&envelope));
    let decoded_payload = BASE64
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    let decoded_payload: Value = serde_json::from_slice(&decoded_payload).unwrap();
    assert!(authority_union.is_valid(&decoded_payload));
    assert!(!root.is_valid(&decoded_payload));
    assert!(
        validator(
            &registry,
            &format!("{ARTIFACT_SCHEMA_ID}#/$defs/workspaceRoleAssignmentV1"),
        )
        .is_valid(&decoded_payload)
    );
}

#[test]
fn remote_authority_dsse_bytes_are_canonical_digest_bound_and_signature_valid() {
    let (_, registry) = schema_registry();
    let envelope_validator = validator(
        &registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/remoteAuthorityRecordEnvelopeV1"),
    );
    let vector = parse_file(&collaboration_path(
        "vectors/remote-authority-record.dsse-bytes.valid.json",
    ));
    let payload = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    let envelope = parse_file(&collaboration_path(
        "vectors/remote-authority-record-envelope.valid.json",
    ));

    let mut exact_limit_shape = envelope.clone();
    exact_limit_shape["payload"] = Value::String(format!("{}==", "A".repeat(87_382)));
    assert!(envelope_validator.is_valid(&exact_limit_shape));
    assert_eq!(
        BASE64
            .decode(exact_limit_shape["payload"].as_str().unwrap())
            .unwrap()
            .len(),
        65_536
    );
    let mut over_decoded_limit_shape = envelope.clone();
    over_decoded_limit_shape["payload"] = Value::String("A".repeat(87_384));
    assert!(
        !envelope_validator.is_valid(&over_decoded_limit_shape),
        "a maximum-length unpadded Base64 string decodes above 65,536 bytes"
    );

    let payload_bytes = serde_json_canonicalizer::to_vec(&payload).unwrap();
    let vector_payload_bytes = BASE64
        .decode(vector["payload_utf8_base64"].as_str().unwrap())
        .unwrap();
    let envelope_payload_bytes = BASE64
        .decode(envelope["payload"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        vector["payload_file"],
        "workspace-role-assignment.valid.json"
    );
    assert_eq!(
        vector["envelope_file"],
        "remote-authority-record-envelope.valid.json"
    );
    assert_eq!(vector_payload_bytes, payload_bytes);
    assert_eq!(envelope_payload_bytes, payload_bytes);
    assert_eq!(
        BASE64.encode(&payload_bytes),
        vector["payload_utf8_base64"].as_str().unwrap()
    );
    assert_eq!(
        BASE64.encode(&payload_bytes),
        envelope["payload"].as_str().unwrap()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&payload_bytes).unwrap(),
        payload
    );
    assert_eq!(
        serde_json_canonicalizer::to_vec(&serde_json::from_slice::<Value>(&payload_bytes).unwrap())
            .unwrap(),
        payload_bytes
    );
    assert!(payload_bytes.len() <= 65_536);
    assert!(serde_json_canonicalizer::to_vec(&envelope).unwrap().len() <= 98_304);
    assert_eq!(envelope["signatures"].as_array().unwrap().len(), 1);
    assert_eq!(
        vector["payload_digest_context"],
        "proof:remote-authority-record:v1"
    );
    assert_eq!(
        vector["envelope_digest_context"],
        "proof:remote-authority-record-envelope:v1"
    );
    assert_eq!(
        vector["payload_digest"],
        canonical_digest("proof:remote-authority-record:v1", &payload)
    );
    assert_eq!(
        vector["envelope_digest"],
        canonical_digest("proof:remote-authority-record-envelope:v1", &envelope)
    );

    let payload_type = vector["payload_type"].as_str().unwrap();
    assert_eq!(envelope["payloadType"], payload_type);
    let pae = dsse_pae(payload_type, &payload_bytes);
    let encoded_pae = vector["pae_utf8_base64"].as_str().unwrap();
    assert_eq!(BASE64.decode(encoded_pae).unwrap(), pae);
    assert_eq!(BASE64.encode(&pae), encoded_pae);

    let public_key: [u8; 32] = BASE64
        .decode(vector["signer"]["public_key_base64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
    let signature_bytes: [u8; 64] = BASE64
        .decode(vector["signer"]["signature_base64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key.verify(&pae, &signature).unwrap();
    assert_eq!(vector["signer"]["public_key_hex"], hex_lower(&public_key));
    assert_eq!(
        vector["signer"]["signature_hex"],
        hex_lower(&signature_bytes)
    );
    assert_eq!(
        BASE64.encode(signature_bytes),
        vector["signer"]["signature_base64"]
    );

    let key_id = format!(
        "ed25519:{}",
        vector["signer"]["public_key_hex"].as_str().unwrap()
    );
    assert_eq!(vector["signer"]["key_id"], key_id);
    assert_eq!(envelope["signatures"][0]["keyid"], key_id);
    assert_eq!(
        payload["authority_key_id"], key_id,
        "a payload that carries authority_key_id must name the exact causally active Workspace key used by its sole DSSE signature"
    );
    assert_eq!(
        envelope["signatures"][0]["sig"],
        vector["signer"]["signature_base64"]
    );
    let mut wrong_signer_identity = envelope.clone();
    wrong_signer_identity["signatures"][0]["keyid"] =
        json!("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(envelope_validator.is_valid(&wrong_signer_identity));
    assert_ne!(
        wrong_signer_identity["signatures"][0]["keyid"], payload["authority_key_id"],
        "the semantic remote-chain verifier must reject a schema-valid envelope whose signer key ID differs from the decoded payload authority key"
    );
}

#[test]
fn http_registry_is_exact_resolvable_and_bound_to_the_accepted_agent_registry() {
    let (schemas, schema_registry) = schema_registry();
    let registry_path = collaboration_path("vectors/http-operation-registry.valid.json");
    let registry_bytes = fs::read(&registry_path)
        .unwrap_or_else(|error| panic!("{}: {error}", registry_path.display()));
    let registry = parse_strict(&registry_bytes)
        .unwrap_or_else(|error| panic!("{}: {error}", registry_path.display()));
    let registry_canonical_bytes = serde_json_canonicalizer::to_vec(&registry)
        .expect("the HTTP registry must canonicalize under RFC 8785");
    let registry_sha256 = hex_lower(&sha256(&registry_canonical_bytes));
    assert_eq!(
        registry_sha256, "e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf",
        "the exact reviewed canonical HTTP registry changed"
    );
    let routes = registry["routes"].as_array().unwrap();
    assert_eq!(routes.len(), 9);
    assert_eq!(
        routes
            .iter()
            .map(|route| route["route_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "oidc-login",
            "oidc-callback",
            "session-get",
            "session-logout",
            "public-capabilities",
            "human-operations",
            "agent-operations",
            "evidence-export-artifact",
            "preview-release-rendition",
        ]
    );
    assert_eq!(
        routes
            .iter()
            .map(|route| route["problem_profile"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "route_oidc_login_get",
            "route_oidc_callback_get",
            "route_session_get",
            "route_session_logout_json_post",
            "route_capabilities_get",
            "route_human_json_post",
            "route_agent_json_post",
            "route_evidence_artifact_get",
            "route_preview_get",
        ]
    );
    for index in [0usize, 1, 2, 4, 7, 8] {
        let profile = routes[index]["problem_profile"].as_str().unwrap();
        assert!(
            !registry["problem_profiles"][profile]
                .as_array()
                .unwrap()
                .iter()
                .any(|code| code == "proof.auth.csrf_denied"),
            "GET route {} must not advertise CSRF denial",
            routes[index]["route_id"]
        );
    }
    assert!(
        registry["problem_profiles"]["route_oidc_callback_get"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == "proof.auth.replay")
    );
    assert!(
        registry["problem_profiles"]["route_agent_json_post"]
            .as_array()
            .unwrap()
            .iter()
            .any(|code| code == "proof.auth.replay")
    );
    for profile in [
        "route_oidc_login_get",
        "route_session_get",
        "route_session_logout_json_post",
        "route_capabilities_get",
        "route_human_json_post",
        "route_evidence_artifact_get",
        "route_preview_get",
    ] {
        assert!(
            !registry["problem_profiles"][profile]
                .as_array()
                .unwrap()
                .iter()
                .any(|code| code == "proof.auth.replay"),
            "{profile} must not advertise presentation replay"
        );
    }

    assert_eq!(
        operation_pairs(&routes[5]),
        [
            (
                "agent-binding.issue",
                "proof.dev/operation/agent-binding.issue/v1"
            ),
            (
                "agent-binding.revoke",
                "proof.dev/operation/agent-binding.revoke/v1"
            ),
            (
                "content-resource-intent.issue",
                "proof.dev/operation/content-resource-intent.issue/v1",
            ),
            ("context.build", "proof.dev/operation/context.build/v2"),
            ("changeset.get", "proof.dev/operation/changeset.get/v2"),
            ("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
            (
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v3",
            ),
            (
                "delegation.issue",
                "proof.dev/operation/delegation.issue/v2"
            ),
            (
                "delegation.revoke",
                "proof.dev/operation/delegation.revoke/v1"
            ),
            ("delivery.get", "proof.dev/operation/delivery.get/v1"),
            ("delivery.replay", "proof.dev/operation/delivery.replay/v1"),
            (
                "delivery.abandon",
                "proof.dev/operation/delivery.abandon/v1",
            ),
            (
                "environment-config.propose",
                "proof.dev/operation/environment-config.propose/v2",
            ),
            (
                "environment-config.activate",
                "proof.dev/operation/environment-config.activate/v2",
            ),
            ("evidence.export", "proof.dev/operation/evidence.export/v2"),
            (
                "evidence.export.get",
                "proof.dev/operation/evidence.export.get/v1",
            ),
            (
                "oidc-binding.issue",
                "proof.dev/operation/oidc-binding.issue/v1",
            ),
            (
                "oidc-binding.revoke",
                "proof.dev/operation/oidc-binding.revoke/v1",
            ),
            (
                "principal.status.set",
                "proof.dev/operation/principal.status.set/v2",
            ),
            ("release.get", "proof.dev/operation/release.get/v2"),
            ("release.verify", "proof.dev/operation/release.verify/v2"),
            (
                "workspace-role.assign",
                "proof.dev/operation/workspace-role.assign/v1",
            ),
            (
                "workspace-role.revoke",
                "proof.dev/operation/workspace-role.revoke/v1",
            ),
        ]
    );
    assert_eq!(
        operation_pairs(&routes[6]),
        [
            ("changeset.add", "proof.dev/operation/changeset.add/v2"),
            (
                "changeset.commit",
                "proof.dev/operation/changeset.commit/v2",
            ),
            (
                "changeset.create",
                "proof.dev/operation/changeset.create/v2",
            ),
            ("changeset.diff", "proof.dev/operation/changeset.diff/v2"),
            ("changeset.get", "proof.dev/operation/changeset.get/v2"),
            (
                "changeset.submit",
                "proof.dev/operation/changeset.submit/v2",
            ),
            (
                "changeset.validate",
                "proof.dev/operation/changeset.validate/v2",
            ),
            ("context.build", "proof.dev/operation/context.build/v1"),
            ("context.build", "proof.dev/operation/context.build/v2"),
            ("edition.create", "proof.dev/operation/edition.create/v2"),
            (
                "object.query_released",
                "proof.dev/operation/object.query_released/v1",
            ),
            (
                "object.query_released",
                "proof.dev/operation/object.query_released/v2",
            ),
            ("release.create", "proof.dev/operation/release.create/v2"),
            (
                "workspace.status",
                "proof.dev/operation/workspace.status/v1"
            ),
        ]
    );

    let expected_human_authorizations = vec![
        json!({ "authorization_rule": "proof.server/authorization/agent-binding-admin/v1", "roles_any_of": ["authority.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/agent-binding-admin/v1", "roles_any_of": ["authority.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/resource-intent-requester/v1", "roles_any_of": ["content.requester"] }),
        json!({ "authorization_rule": "proof.server/authorization/initial-context-requester/v1", "roles_any_of": ["content.requester"] }),
        json!({ "authorization_rule": "proof.server/authorization/changeset-closure-reader/v1", "roles_any_of": ["content.publisher", "content.requester", "content.reviewer"] }),
        json!({ "authorization_rule": "proof.server/authorization/changeset-closure-reader/v1", "roles_any_of": ["content.publisher", "content.requester", "content.reviewer"] }),
        json!({ "authorization_rule": "proof.server/authorization/changeset-distinct-reviewer/v1", "roles_any_of": ["content.reviewer"] }),
        json!({ "authorization_rule": "proof.server/authorization/delegation-requester/v1", "roles_any_of": ["content.requester"] }),
        json!({ "authorization_rule": "proof.server/authorization/delegation-issuer-or-authority-admin/v1", "roles_any_of": ["authority.admin", "content.requester"] }),
        json!({ "authorization_rule": "proof.server/authorization/delivery-reader/v1", "roles_any_of": ["content.publisher", "environment.admin", "evidence.auditor"] }),
        json!({ "authorization_rule": "proof.server/authorization/delivery-dead-letter-replay-admin/v1", "roles_any_of": ["environment.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/delivery-poison-abandon-activator/v1", "roles_any_of": ["environment.activator"] }),
        json!({ "authorization_rule": "proof.server/authorization/environment-config-proposer/v1", "roles_any_of": ["environment.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/environment-config-distinct-activator/v1", "roles_any_of": ["environment.activator"] }),
        json!({ "authorization_rule": "proof.server/authorization/evidence-export-reader/v1", "roles_any_of": ["content.publisher", "evidence.auditor"] }),
        json!({ "authorization_rule": "proof.server/authorization/evidence-export-reader/v1", "roles_any_of": ["content.publisher", "evidence.auditor"] }),
        json!({ "authorization_rule": "proof.server/authorization/oidc-binding-admin/v1", "roles_any_of": ["identity.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/oidc-binding-admin/v1", "roles_any_of": ["identity.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/principal-disable-admin/v1", "roles_any_of": ["identity.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/release-reader/v1", "roles_any_of": ["content.publisher", "content.requester", "content.reviewer", "evidence.auditor"] }),
        json!({ "authorization_rule": "proof.server/authorization/release-reader/v1", "roles_any_of": ["content.publisher", "content.requester", "content.reviewer", "evidence.auditor"] }),
        json!({ "authorization_rule": "proof.server/authorization/workspace-role-admin/v1", "roles_any_of": ["identity.admin"] }),
        json!({ "authorization_rule": "proof.server/authorization/workspace-role-admin/v1", "roles_any_of": ["identity.admin"] }),
    ];
    assert_eq!(
        routes[5]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["authorization"].clone())
            .collect::<Vec<_>>(),
        expected_human_authorizations
    );
    assert_eq!(
        routes[4]["operations"][0]["authorization"],
        json!({ "authorization_rule": "proof.server/authorization/public-capability-discovery/v1", "roles_any_of": [] })
    );
    assert_eq!(
        routes[7]["operations"][0]["authorization"],
        json!({ "authorization_rule": "proof.server/authorization/export-artifact-reader/v1", "roles_any_of": ["content.publisher", "evidence.auditor"] })
    );
    assert_eq!(
        routes[8]["operations"][0]["authorization"],
        json!({ "authorization_rule": "proof.server/authorization/preview-reader/v1", "roles_any_of": ["content.publisher", "content.requester", "content.reviewer", "evidence.auditor"] })
    );

    let human_projection = registry["human_authorization_projection"]["operations"]
        .as_object()
        .unwrap();
    let human_rows = routes
        .iter()
        .flat_map(|route| route["operations"].as_array().into_iter().flatten())
        .filter(|row| row.get("authorization").is_some())
        .collect::<Vec<_>>();
    assert_eq!(human_rows.len(), 26);
    assert_eq!(human_projection.len(), human_rows.len());
    let mut human_input_schemas = BTreeMap::new();
    let mut referenced_rules = BTreeSet::new();
    for row in &human_rows {
        let operation = row["operation"]["version"].as_str().unwrap();
        let projected = human_projection
            .get(operation)
            .unwrap_or_else(|| panic!("{operation} lacks a Human authorization projection"));
        assert_eq!(
            projected["authorization_rule"],
            row["authorization"]["authorization_rule"]
        );
        assert_eq!(
            projected["roles_any_of"],
            row["authorization"]["roles_any_of"]
        );
        assert!(
            projected["requested_action"]
                .as_str()
                .is_some_and(|action| action.contains(':'))
        );
        referenced_rules.insert(projected["authorization_rule"].as_str().unwrap());
        let prior = human_input_schemas.insert(
            operation,
            row["input_schema"]
                .as_str()
                .expect("Human row input Schema"),
        );
        assert!(prior.is_none(), "duplicate Human operation {operation}");
    }

    let rule_definitions = registry["authorization_rule_definitions"]
        .as_object()
        .unwrap();
    assert_eq!(referenced_rules.len(), rule_definitions.len());
    assert_eq!(
        referenced_rules,
        rule_definitions.keys().map(String::as_str).collect()
    );
    for (rule_id, definition) in rule_definitions {
        let operation_versions = definition["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|operation| operation["version"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        let operation_bindings = definition["operation_resource_bindings"]
            .as_object()
            .unwrap();
        assert_eq!(
            operation_versions,
            operation_bindings.keys().map(String::as_str).collect(),
            "{rule_id} operation applicability is incomplete"
        );
        let descriptors = definition["resource_input_bindings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|binding| (binding["binding_name"].as_str().unwrap(), binding))
            .collect::<BTreeMap<_, _>>();
        let mut selected_bindings = BTreeSet::new();
        for (operation, selected) in operation_bindings {
            assert_eq!(
                human_projection[operation]["authorization_rule"],
                rule_id.as_str(),
                "{operation} selects a different rule than {rule_id}"
            );
            for binding_name in selected.as_array().unwrap() {
                let binding_name = binding_name.as_str().unwrap();
                selected_bindings.insert(binding_name);
                let descriptor = descriptors.get(binding_name).unwrap_or_else(|| {
                    panic!("{rule_id}/{operation} selects unknown binding {binding_name}")
                });
                if descriptor["source_kind"] == "input-field" {
                    let source_path = descriptor["source_path"].as_str().unwrap();
                    let instance_path = format!(
                        "/{}",
                        source_path
                            .strip_prefix("input.")
                            .unwrap_or_else(|| panic!(
                                "{rule_id} has fake input path {source_path}"
                            ))
                            .replace('.', "/")
                    );
                    assert!(
                        instance_path_exists_in_schema(
                            &schemas,
                            human_input_schemas[operation.as_str()],
                            &instance_path,
                        ),
                        "{rule_id}/{operation} binding {binding_name} does not resolve at {instance_path}"
                    );
                }
            }
        }
        assert_eq!(
            selected_bindings,
            descriptors.keys().copied().collect(),
            "{rule_id} contains unused or multiply selected bindings"
        );
    }
    assert!(
        !instance_path_exists_in_schema(
            &schemas,
            human_input_schemas["proof.dev/operation/changeset.approve/v3"],
            "/nonexistent_authorization_selector",
        ),
        "authorization binding path checking must reject invented selectors"
    );

    let agent_projection = &registry["agent_authorization_projection"];
    let agent_route = &routes[6];
    validator(
        &schema_registry,
        registry["authorization_resource_projection"]["agent_direct_requested_resources"]
            ["source_contract"]
            .as_str()
            .expect("Agent requested-resources source contract"),
    );
    for field in [
        "authority_registry_contract",
        "authority_registry_file",
        "authority_registry_sha256",
    ] {
        assert_eq!(agent_projection[field], agent_route[field]);
    }
    let projected_agent_operations = agent_projection["operations"].as_object().unwrap();
    assert_eq!(projected_agent_operations.len(), 14);
    for row in agent_route["operations"].as_array().unwrap() {
        let operation = row["operation"]["version"].as_str().unwrap();
        let projected = &projected_agent_operations[operation];
        assert_fields_equal(
            projected,
            row,
            &[
                "requested_action",
                "closure_anchor",
                "resource_projection_profile",
                "budget_projection",
                "selector_projection",
                "consequence",
                "availability",
            ],
            "Agent authorization projection/HTTP row",
        );
    }

    let projection_fields = registry["authorization_registry_commitment"]["projection_fields"]
        .as_array()
        .unwrap();
    let authorization_projection = Value::Object(
        projection_fields
            .iter()
            .map(|field| {
                let field = field.as_str().unwrap();
                (field.to_owned(), registry[field].clone())
            })
            .collect(),
    );
    assert_eq!(
        canonical_sha256(&authorization_projection),
        registry["authorization_registry_commitment"]["authorization_registry_sha256"]
    );
    let mut drifted_human_projection = authorization_projection.clone();
    drifted_human_projection["human_authorization_projection"]["operations"]["proof.dev/operation/changeset.approve/v3"]
        ["roles_any_of"] = json!(["content.publisher"]);
    assert_ne!(
        canonical_sha256(&drifted_human_projection),
        registry["authorization_registry_commitment"]["authorization_registry_sha256"],
        "a role/rule/action reassignment must change the authorization commitment"
    );

    assert_eq!(
        registry["typed_limit_semantics"]["empty_array_meaning"],
        "no-additional-registry-item-quota;closed-schema-and-canonical-byte-limits-still-apply"
    );
    let mut request_limits_by_schema = BTreeMap::<&str, &Value>::new();
    let mut result_limits_by_schema = BTreeMap::<&str, &Value>::new();
    for route in routes {
        for row in route["operations"].as_array().into_iter().flatten() {
            for (schema_field, limits_field, seen) in [
                (
                    "input_schema",
                    "request_limits",
                    &mut request_limits_by_schema,
                ),
                (
                    "result_schema",
                    "result_limits",
                    &mut result_limits_by_schema,
                ),
            ] {
                let schema = row[schema_field].as_str().unwrap();
                let limits = &row[limits_field];
                if let Some(prior) = seen.insert(schema, limits) {
                    assert_eq!(
                        prior, limits,
                        "the same {schema_field} advertises different {limits_field}"
                    );
                }
                for limit in limits.as_array().unwrap() {
                    assert!(
                        instance_path_exists_in_schema(
                            &schemas,
                            schema,
                            limit["schema_path"].as_str().unwrap(),
                        ),
                        "{} {} does not resolve in {}",
                        row["operation"],
                        limit["schema_path"],
                        schema
                    );
                }
            }
        }
    }
    for operation in [
        "proof.dev/operation/changeset.diff/v2",
        "proof.dev/operation/changeset.validate/v2",
        "proof.dev/operation/changeset.commit/v2",
        "proof.dev/operation/edition.create/v2",
    ] {
        for row in routes
            .iter()
            .flat_map(|route| route["operations"].as_array().into_iter().flatten())
            .filter(|row| row["operation"]["version"] == operation)
        {
            assert_eq!(
                row["result_limits"],
                json!([]),
                "{operation} must not claim an item cap absent from its accepted result Schema"
            );
        }
    }

    let capability_result = json!({
        "agent_operation_count": 14,
        "api_version": "proof.dev/capabilities-discover-result/v1",
        "human_operation_count": 23,
        "profile": "proof.server/single-workspace/v1",
        "registry": registry.clone(),
        "registry_canonicalization": "RFC8785",
        "registry_digest_algorithm": "sha-256",
        "registry_schema": "https://proof.dev/schema/collaboration-server/http-operation-registry/v1",
        "registry_sha256": registry_sha256,
        "route_count": 9
    });
    let capability_result_validator = validator(
        &schema_registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/capabilitiesDiscoverResultV1"),
    );
    assert!(
        capability_result_validator.is_valid(&capability_result),
        "capability discovery must return the exact committed registry: {:?}",
        capability_result_validator
            .iter_errors(&capability_result)
            .collect::<Vec<_>>()
    );
    assert_eq!(capability_result["registry"], registry);

    let mut schema_references = BTreeSet::new();
    for route in routes {
        for field in ["input_schema", "result_schema"] {
            if let Some(reference) = route[field].as_str() {
                schema_references.insert(reference);
            }
        }
        for row in route["operations"].as_array().into_iter().flatten() {
            for field in ["input_schema", "result_schema"] {
                let reference = row[field]
                    .as_str()
                    .unwrap_or_else(|| panic!("{} lacks {field}", row["operation"]));
                schema_references.insert(reference);
            }
            if let Some(reference) = row["localized_contract"].as_str() {
                schema_references.insert(reference);
            }
            if let Some(reference) = row["effect_digest_rule"]["source_contract"].as_str() {
                schema_references.insert(reference);
            }
        }
    }
    for reference in schema_references {
        assert!(reference.starts_with("https://proof.dev/"));
        validator(&schema_registry, reference);
    }
    let mut authority_effect_timestamp_fields = BTreeMap::<&str, usize>::new();
    for row in routes
        .iter()
        .flat_map(|route| route["operations"].as_array().into_iter().flatten())
    {
        let effect_rule = &row["effect_digest_rule"];
        if effect_rule["digest_context"] == "proof:remote-authority-record:v1" {
            let field = effect_rule["effect_timestamp_field"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "{} authority effect lacks its exact timestamp member",
                        row["operation"]
                    )
                });
            *authority_effect_timestamp_fields.entry(field).or_default() += 1;
            assert!(
                instance_path_exists_in_schema(
                    &schemas,
                    effect_rule["source_contract"].as_str().unwrap(),
                    &format!("/{field}"),
                ),
                "{} selects missing effect timestamp {}#/{field}",
                row["operation"],
                effect_rule["source_contract"]
            );
        } else {
            assert!(
                effect_rule["effect_timestamp_field"].is_null(),
                "{} must not invent an authority timestamp for a non-authority effect",
                row["operation"]
            );
        }
    }
    assert_eq!(
        authority_effect_timestamp_fields,
        BTreeMap::from([
            ("activated_at", 1),
            ("approved_at", 1),
            ("assigned_at", 1),
            ("issued_at", 3),
            ("proposed_at", 1),
            ("recorded_at", 1),
            ("revoked_at", 4),
        ])
    );

    let expected_problem_statuses = BTreeMap::from([
        ("proof.auth.csrf_denied", 403u64),
        ("proof.auth.denied", 401),
        ("proof.auth.replay", 401),
        ("proof.authority.integrity", 500),
        ("proof.authorization.budget_exceeded", 403),
        ("proof.authorization.delegation_expired", 403),
        ("proof.authorization.delegation_not_yet_valid", 403),
        ("proof.authorization.delegation_revoked", 403),
        ("proof.authorization.denied", 403),
        ("proof.authorization.scope_exceeded", 403),
        ("proof.changeset.duplicate_target", 409),
        ("proof.changeset.invalid_supersession", 409),
        ("proof.changeset.not_approved", 409),
        ("proof.changeset.not_draft", 409),
        ("proof.changeset.not_ready", 409),
        ("proof.changeset.not_submitted", 409),
        ("proof.delegation.expired", 403),
        ("proof.dependency.unavailable", 503),
        ("proof.digest.mismatch", 500),
        ("proof.evidence.incomplete", 409),
        ("proof.idempotency.key_reused", 409),
        ("proof.input.invalid_json", 400),
        ("proof.input.intent_mismatch", 409),
        ("proof.input.limit_exceeded", 413),
        ("proof.input.schema_mismatch", 400),
        ("proof.input.too_large", 413),
        ("proof.input.unsupported_media_type", 415),
        ("proof.input.unsupported_version", 400),
        ("proof.integrity.failure", 500),
        ("proof.internal", 500),
        ("proof.operation.timeout", 504),
        ("proof.operation.unknown_outcome", 504),
        ("proof.policy.denied", 403),
        ("proof.rate_limit.exceeded", 429),
        ("proof.resource.not_found", 404),
        ("proof.state.conflict", 409),
        ("proof.state.source_conflict", 409),
        ("proof.state.target_conflict", 409),
        ("proof.storage.conflict", 503),
        ("proof.validation.failed", 422),
        ("proof.validation.repair_evidence_invalid", 422),
    ]);
    let definitions = registry["problem_definitions"].as_array().unwrap();
    let statuses = registry["problem_statuses"].as_object().unwrap();
    assert_eq!(definitions.len(), 41);
    assert_eq!(statuses.len(), 41);
    assert_eq!(
        definitions
            .iter()
            .map(|definition| definition["code"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_problem_statuses
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    let problem_validator = validator(
        &schema_registry,
        &format!("{HTTP_SCHEMA_ID}#/$defs/problemV1"),
    );
    for definition in definitions {
        let code = definition["code"].as_str().unwrap();
        assert_eq!(
            definition["status"].as_u64(),
            expected_problem_statuses.get(code).copied()
        );
        assert_eq!(statuses[code], definition["status"]);
        let problem = json!({
            "api_version": "proof.dev/http-problem/v1",
            "code": definition["code"].clone(),
            "correlation_id": null,
            "instance": "urn:proof:operation:019e0000-0000-7000-8000-000000000090",
            "operation": {
                "name": "workspace.status",
                "version": "proof.dev/operation/workspace.status/v1"
            },
            "operation_id": "019e0000-0000-7000-8000-000000000090",
            "retryable": definition["retryable"].clone(),
            "status": definition["status"].clone(),
            "title": definition["title"].clone(),
            "type": definition["type"].clone()
        });
        assert!(
            problem_validator.is_valid(&problem),
            "invalid tuple for {code}"
        );
        let mut wrong_status = problem;
        wrong_status["status"] = json!(418);
        assert!(
            !problem_validator.is_valid(&wrong_status),
            "{code} accepted a non-registry status"
        );
    }
    let authentication_denied = definitions
        .iter()
        .find(|definition| definition["code"] == "proof.auth.denied")
        .unwrap();
    let transport_problem = json!({
        "api_version": "proof.dev/http-problem/v1",
        "code": authentication_denied["code"].clone(),
        "correlation_id": null,
        "instance": "urn:proof:operation:019e0000-0000-7000-8000-000000000091",
        "operation": {
            "name": "session.get",
            "version": "proof.dev/transport/session.get/v1"
        },
        "operation_id": "019e0000-0000-7000-8000-000000000091",
        "retryable": authentication_denied["retryable"].clone(),
        "status": authentication_denied["status"].clone(),
        "title": authentication_denied["title"].clone(),
        "type": authentication_denied["type"].clone()
    });
    assert!(
        problem_validator.is_valid(&transport_problem),
        "transport/session failures must carry their exact transport operation"
    );
    let mut unnamespaced_problem = transport_problem;
    unnamespaced_problem["operation"]["version"] = json!("proof.dev/session/session.get/v1");
    assert!(
        !problem_validator.is_valid(&unnamespaced_problem),
        "Problems must reject operation versions outside the closed operation/transport namespaces"
    );
    let mut used_problem_codes = BTreeSet::new();
    for profile in registry["problem_profiles"].as_object().unwrap().values() {
        used_problem_codes.extend(
            profile
                .as_array()
                .unwrap()
                .iter()
                .map(|code| code.as_str().unwrap()),
        );
    }
    for route in routes {
        for row in route["operations"].as_array().into_iter().flatten() {
            used_problem_codes.extend(
                row["application_problem_codes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|code| code.as_str().unwrap()),
            );
            if let Some(profile) = row["application_error_profile"].as_str() {
                used_problem_codes.extend(
                    registry["agent_error_profiles"][profile]["public_problem_codes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|code| code.as_str().unwrap()),
                );
            }
        }
    }
    assert_eq!(
        used_problem_codes,
        expected_problem_statuses.keys().copied().collect()
    );

    assert_eq!(
        hex_lower(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let authority_registry_path = repository_root()
        .join("conformance/v1/authority/vectors/authority-operation-registry.valid.json");
    let authority_registry_bytes = fs::read(&authority_registry_path).unwrap();
    let authority_registry = parse_file(&authority_registry_path);
    let authority_registry_sha256 = hex_lower(&sha256(&authority_registry_bytes));
    let agent_route = &routes[6];
    assert_eq!(
        agent_route["authority_registry_contract"],
        "https://proof.dev/schema/authority/operation-registry/v1"
    );
    assert_eq!(
        agent_route["authority_registry_file"],
        "conformance/v1/authority/vectors/authority-operation-registry.valid.json"
    );
    assert_eq!(
        authority_registry_sha256,
        "b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7"
    );
    assert_eq!(
        agent_route["authority_registry_sha256"],
        authority_registry_sha256
    );
    assert!(
        validator(
            &schema_registry,
            "https://proof.dev/schema/authority/operation-registry/v1",
        )
        .is_valid(&authority_registry)
    );
    let agent_operations = agent_route["operations"].as_array().unwrap();
    let authority_operations = authority_registry["operations"].as_array().unwrap();
    assert_eq!(agent_operations.len(), 14);
    assert_eq!(agent_operations.len(), authority_operations.len());
    for (agent, authority) in agent_operations.iter().zip(authority_operations) {
        assert_fields_equal(
            agent,
            authority,
            &[
                "operation",
                "requested_action",
                "localized_contract",
                "application_idempotency",
                "closure_anchor",
                "resource_projection_profile",
                "budget_projection",
                "selector_projection",
                "consequence",
                "availability",
            ],
            "HTTP/authority Agent registry",
        );
    }

    let localized_v2_application_problem_codes = json!([
        "proof.changeset.duplicate_target",
        "proof.changeset.invalid_supersession",
        "proof.changeset.not_approved",
        "proof.changeset.not_draft",
        "proof.changeset.not_ready",
        "proof.changeset.not_submitted",
        "proof.evidence.incomplete",
        "proof.input.intent_mismatch",
        "proof.input.limit_exceeded",
        "proof.input.schema_mismatch",
        "proof.input.unsupported_version",
        "proof.policy.denied",
        "proof.resource.not_found",
        "proof.state.conflict",
        "proof.state.source_conflict",
        "proof.state.target_conflict",
        "proof.validation.repair_evidence_invalid",
    ]);
    let legacy_context_application_problem_codes = json!([
        "proof.auth.denied",
        "proof.delegation.expired",
        "proof.input.too_large",
        "proof.resource.not_found",
    ]);
    let legacy_object_query_application_problem_codes = json!([
        "proof.input.unsupported_version",
        "proof.resource.not_found",
    ]);
    let no_application_problem_codes = json!([]);
    let forbidden_post_allow_application_codes = BTreeSet::from([
        "proof.auth.csrf_denied",
        "proof.auth.replay",
        "proof.authority.integrity",
        "proof.authorization.budget_exceeded",
        "proof.authorization.delegation_expired",
        "proof.authorization.delegation_not_yet_valid",
        "proof.authorization.delegation_revoked",
        "proof.authorization.denied",
        "proof.authorization.scope_exceeded",
        "proof.dependency.unavailable",
        "proof.digest.mismatch",
        "proof.idempotency.key_reused",
        "proof.input.invalid_json",
        "proof.input.unsupported_media_type",
        "proof.integrity.failure",
        "proof.internal",
        "proof.operation.timeout",
        "proof.operation.unknown_outcome",
        "proof.rate_limit.exceeded",
        "proof.storage.conflict",
    ]);
    let none_effect = json!({
        "digest_context": null,
        "effect_timestamp_field": null,
        "mode": "none",
        "preimage_source": "none",
        "source_contract": null,
    });
    let expected_agent_effect_rules = BTreeMap::from([
        (
            "proof.dev/operation/changeset.add/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-changeset-add-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedChangeSetAddOperationEffectV1",
            }),
        ),
        (
            "proof.dev/operation/changeset.commit/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-changeset-commit-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedChangeSetCommitOperationEffectV1",
            }),
        ),
        (
            "proof.dev/operation/changeset.create/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-changeset-create-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedChangeSetCreateOperationEffectV1",
            }),
        ),
        ("proof.dev/operation/changeset.diff/v2", none_effect.clone()),
        ("proof.dev/operation/changeset.get/v2", none_effect.clone()),
        (
            "proof.dev/operation/changeset.submit/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-changeset-submit-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedChangeSetSubmitOperationEffectV1",
            }),
        ),
        (
            "proof.dev/operation/changeset.validate/v2",
            json!({
                "digest_context": "proof:validation-results:v2",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-validation-results-v2-artifact",
                "source_contract": "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/validationResultsV2",
            }),
        ),
        (
            "proof.dev/operation/context.build/v1",
            json!({
                "digest_context": "proof:context-pack:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "retained-context-pack-v1-manifest-json",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/contextPackManifestV1",
            }),
        ),
        (
            "proof.dev/operation/context.build/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-context-build-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedContextBuildOperationEffectV1",
            }),
        ),
        (
            "proof.dev/operation/edition.create/v2",
            json!({
                "digest_context": "proof:operation-effect:v1",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-edition-create-v2-operation-effect-v1",
                "source_contract": "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedEditionCreateOperationEffectV1",
            }),
        ),
        (
            "proof.dev/operation/object.query_released/v1",
            none_effect.clone(),
        ),
        (
            "proof.dev/operation/object.query_released/v2",
            none_effect.clone(),
        ),
        (
            "proof.dev/operation/release.create/v2",
            json!({
                "digest_context": "proof:release:v2",
                "effect_timestamp_field": null,
                "mode": "blake3-256-derive-key-rfc8785",
                "preimage_source": "localized-release-v2-manifest",
                "source_contract": "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/releaseV2",
            }),
        ),
        ("proof.dev/operation/workspace.status/v1", none_effect),
    ]);
    let none_human_effect = json!({
        "digest_context": null,
        "effect_timestamp_field": null,
        "mode": "none",
        "preimage_source": "none",
        "source_contract": null,
    });
    let expected_human_effect_rules = BTreeMap::from([
        (
            "proof.dev/operation/agent-binding.issue/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "agent-binding-issue-v1-remote-authority-record",
                "https://proof.dev/schema/authority/principal-binding/v1",
            ),
        ),
        (
            "proof.dev/operation/agent-binding.revoke/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "agent-binding-revoke-v1-remote-authority-record",
                "https://proof.dev/schema/authority/principal-binding-revocation/v1",
            ),
        ),
        (
            "proof.dev/operation/capabilities.discover/v1",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/changeset.approve/v3",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "changeset-approval-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/changeSetApprovalV1",
            ),
        ),
        (
            "proof.dev/operation/changeset.diff/v2",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/changeset.get/v2",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/content-resource-intent.issue/v1",
            effect_digest_rule(
                "proof:content-resource-intent:v1",
                "content-resource-intent-v1-artifact",
                "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json#/$defs/contentResourceIntentV1",
            ),
        ),
        (
            "proof.dev/operation/context.build/v2",
            effect_digest_rule(
                "proof:operation-effect:v1",
                "localized-context-build-v2-operation-effect-v1",
                "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/localizedContextBuildOperationEffectV1",
            ),
        ),
        (
            "proof.dev/operation/delegation.issue/v2",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "delegation-issue-v2-remote-authority-record",
                "https://proof.dev/schema/authority/delegation/v2",
            ),
        ),
        (
            "proof.dev/operation/delegation.revoke/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "delegation-revoke-v1-remote-authority-record",
                "https://proof.dev/schema/authority/delegation-revocation/v1",
            ),
        ),
        (
            "proof.dev/operation/delivery.abandon/v1",
            effect_digest_rule(
                "proof:delivery-management-fact:v1",
                "delivery-abandon-v1-management-fact",
                "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/deliveryManagementFactV1",
            ),
        ),
        (
            "proof.dev/operation/delivery.get/v1",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/delivery.replay/v1",
            effect_digest_rule(
                "proof:delivery-management-fact:v1",
                "delivery-replay-v1-management-fact",
                "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/deliveryManagementFactV1",
            ),
        ),
        (
            "proof.dev/operation/environment-config.activate/v2",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "environment-config-activation-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/environmentConfigActivationV1",
            ),
        ),
        (
            "proof.dev/operation/environment-config.propose/v2",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "environment-config-proposal-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/environmentConfigProposalV1",
            ),
        ),
        (
            "proof.dev/operation/evidence.artifact.get/v2",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/evidence.export/v2",
            effect_digest_rule(
                "proof:evidence-export-capture:v2",
                "evidence-export-capture-v2-artifact",
                "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2#/$defs/evidenceExportCaptureV2",
            ),
        ),
        (
            "proof.dev/operation/evidence.export.get/v1",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/oidc-binding.issue/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "oidc-binding-issue-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/remote-auth/v1#/$defs/oidcPrincipalBindingV1",
            ),
        ),
        (
            "proof.dev/operation/oidc-binding.revoke/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "oidc-binding-revoke-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/remote-auth/v1#/$defs/oidcPrincipalBindingRevocationV1",
            ),
        ),
        (
            "proof.dev/operation/preview.object.get/v1",
            none_human_effect.clone(),
        ),
        (
            "proof.dev/operation/principal.status.set/v2",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "principal-status-v2-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/remotePrincipalStatusV2",
            ),
        ),
        (
            "proof.dev/operation/release.get/v2",
            none_human_effect.clone(),
        ),
        ("proof.dev/operation/release.verify/v2", none_human_effect),
        (
            "proof.dev/operation/workspace-role.assign/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "workspace-role-assignment-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/workspaceRoleAssignmentV1",
            ),
        ),
        (
            "proof.dev/operation/workspace-role.revoke/v1",
            effect_digest_rule(
                "proof:remote-authority-record:v1",
                "workspace-role-revocation-v1-remote-authority-record",
                "https://proof.dev/schema/collaboration-server/collaboration-artifacts/v1#/$defs/workspaceRoleRevocationV1",
            ),
        ),
    ]);
    assert_eq!(expected_human_effect_rules.len(), 26);
    for (route_index, route) in routes.iter().enumerate() {
        if route_index == 6 {
            continue;
        }
        for row in route["operations"].as_array().into_iter().flatten() {
            let version = row["operation"]["version"].as_str().unwrap();
            assert_eq!(
                row["effect_digest_rule"], expected_human_effect_rules[version],
                "{version} Human/public/data effect contract drifted"
            );
            assert_eq!(
                row["effect_digest_rule"]["mode"] == "none",
                matches!(
                    row["consequence"].as_str().unwrap(),
                    "authority-evidence-only"
                        | "none"
                        | "private-release-rendition"
                        | "transport-projection"
                ),
                "{version} effect nullability contradicts its consequence class"
            );
        }
    }

    let localized_instances = parse_file(
        &repository_root()
            .join("conformance/v2/localized-content/vectors/operation-instances.valid.json"),
    );
    let localized_cases = localized_instances["cases"].as_array().unwrap();
    let localized_case = |version: &str| {
        localized_cases
            .iter()
            .find(|case| case["operation_id"] == version)
            .unwrap_or_else(|| panic!("missing localized operation instance {version}"))
    };
    let create_case = localized_case("proof.dev/operation/changeset.create/v2");
    let add_case = localized_case("proof.dev/operation/changeset.add/v2");
    let context_case = localized_case("proof.dev/operation/context.build/v2");
    let submit_case = localized_case("proof.dev/operation/changeset.submit/v2");
    let commit_case = localized_case("proof.dev/operation/changeset.commit/v2");
    let edition_case = localized_case("proof.dev/operation/edition.create/v2");
    let changeset_case = localized_case("proof.dev/operation/changeset.get/v2");

    let context_policy_preimage = json!({
        "api_version": "proof.dev/localized-content-policy/v1",
        "rules": context_case["input"]["policy_rules"].clone(),
    });
    let context_request_preimage = json!({
        "api_version": context_case["input"]["api_version"].clone(),
        "context_pack_id": context_case["input"]["context_pack_id"].clone(),
        "created_at": context_case["input"]["created_at"].clone(),
        "expires_at": context_case["input"]["expires_at"].clone(),
        "idempotency_key": context_case["input"]["idempotency_key"].clone(),
        "limits": context_case["input"]["limits"].clone(),
        "policy_digest": canonical_digest("proof:policy-bundle:v1", &context_policy_preimage),
        "resource_intent_digest": context_case["input"]["resource_intent_digest"].clone(),
        "resource_intent_id": context_case["input"]["resource_intent_id"].clone(),
    });
    let context_request_validator = validator(
        &schema_registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/localizedContextBuildOperationEffectRequestV1"),
    );
    assert!(context_request_validator.is_valid(&context_request_preimage));

    let commit_renditions = commit_case["output"]["renditions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rendition| {
            json!({
                "digest": canonical_digest("proof:object-locale-revision:v1", rendition),
                "edit_id": rendition["edit_id"].clone(),
                "locale": rendition["locale"].clone(),
                "object_id": rendition["object_id"].clone(),
                "revision": rendition["revision"].clone(),
            })
        })
        .collect::<Vec<_>>();
    let effect_preimages = BTreeMap::from([
        (
            "proof.dev/operation/changeset.add/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.add/v2",
                "request_digest": canonical_digest("proof:operation-effect:v1", &add_case["input"]),
                "result": add_case["output"].clone(),
            }),
        ),
        (
            "proof.dev/operation/changeset.commit/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.commit/v2",
                "request_digest": canonical_digest("proof:operation-effect:v1", &commit_case["input"]),
                "result": {
                    "changeset_id": commit_case["output"]["changeset_id"].clone(),
                    "committed_at": commit_case["output"]["committed_at"].clone(),
                    "previous_state": commit_case["output"]["previous_state"].clone(),
                    "renditions": commit_renditions,
                    "resulting_state": commit_case["output"]["resulting_state"].clone(),
                    "sealed_changeset_digest": commit_case["output"]["sealed_changeset_digest"].clone(),
                    "validation_results_digest": commit_case["output"]["validation_results_digest"].clone(),
                },
            }),
        ),
        (
            "proof.dev/operation/changeset.create/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.create/v2",
                "request_digest": canonical_digest("proof:operation-effect:v1", &create_case["input"]),
                "result": create_case["output"].clone(),
            }),
        ),
        (
            "proof.dev/operation/changeset.submit/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "changeset.submit/v2",
                "result": {
                    "approval": null,
                    "changeset_id": submit_case["output"]["changeset_id"].clone(),
                    "occurred_at": submit_case["output"]["submitted_at"].clone(),
                    "principal_id": changeset_case["output"]["principal_id"].clone(),
                    "sealed_changeset_digest": submit_case["output"]["sealed_changeset_digest"].clone(),
                    "validation_results_digest": submit_case["output"]["validation_results_digest"].clone(),
                },
            }),
        ),
        (
            "proof.dev/operation/context.build/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "context.build/v2",
                "request_digest": canonical_digest("proof:operation-effect:v1", &context_request_preimage),
                "result": {
                    "context_pack_digest": context_case["output"]["context_pack_digest"].clone(),
                    "context_pack_id": context_case["output"]["context_pack_id"].clone(),
                },
            }),
        ),
        (
            "proof.dev/operation/edition.create/v2",
            json!({
                "api_version": "proof.dev/operation-effect/v1",
                "operation_kind": "edition.create/v2",
                "request_digest": canonical_digest("proof:operation-effect:v1", &edition_case["input"]),
                "result": {
                    "changeset_id": edition_case["input"]["changeset_id"].clone(),
                    "edition_digest": edition_case["output"]["edition_digest"].clone(),
                    "edition_id": edition_case["output"]["edition_id"].clone(),
                    "state": edition_case["output"]["state"].clone(),
                },
            }),
        ),
    ]);
    let mut effect_digests = BTreeSet::new();
    for (version, preimage) in &effect_preimages {
        let contract = expected_agent_effect_rules[version]["source_contract"]
            .as_str()
            .unwrap();
        let effect_validator = validator(&schema_registry, contract);
        assert!(
            effect_validator.is_valid(preimage),
            "{version} effect preimage is not reconstructible from its exact closed contract: {:?}",
            effect_validator.iter_errors(preimage).collect::<Vec<_>>()
        );
        assert!(effect_digests.insert(canonical_digest("proof:operation-effect:v1", preimage)));

        let mut extra_field = preimage.clone();
        extra_field["unexpected"] = json!(true);
        assert!(
            !effect_validator.is_valid(&extra_field),
            "{version} effect preimage admitted an uncommitted member"
        );
        assert_ne!(
            canonical_digest("proof:operation-effect:v1", preimage),
            canonical_digest("proof:operation-effect:v1", &extra_field)
        );
    }
    assert_eq!(effect_digests.len(), effect_preimages.len());
    for (version, full_output) in [
        (
            "proof.dev/operation/context.build/v2",
            &context_case["output"],
        ),
        (
            "proof.dev/operation/changeset.commit/v2",
            &commit_case["output"],
        ),
        (
            "proof.dev/operation/edition.create/v2",
            &edition_case["output"],
        ),
    ] {
        let mut wrong_projection = effect_preimages[version].clone();
        wrong_projection["result"] = full_output.clone();
        assert!(
            !validator(
                &schema_registry,
                expected_agent_effect_rules[version]["source_contract"]
                    .as_str()
                    .unwrap(),
            )
            .is_valid(&wrong_projection),
            "{version} must not substitute its full output for the committed reduced effect projection"
        );
    }
    let mut submit_with_request_digest =
        effect_preimages["proof.dev/operation/changeset.submit/v2"].clone();
    submit_with_request_digest["request_digest"] = json!(canonical_digest(
        "proof:operation-effect:v1",
        &submit_case["input"],
    ));
    assert!(
        !validator(
            &schema_registry,
            expected_agent_effect_rules["proof.dev/operation/changeset.submit/v2"]
                ["source_contract"]
                .as_str()
                .unwrap(),
        )
        .is_valid(&submit_with_request_digest),
        "changeset.submit/v2 must retain its accepted derived-lifecycle preimage without request_digest"
    );
    for row in agent_operations {
        let version = row["operation"]["version"].as_str().unwrap();
        let expected = match version {
            "proof.dev/operation/context.build/v1" => &legacy_context_application_problem_codes,
            "proof.dev/operation/object.query_released/v1" => {
                &legacy_object_query_application_problem_codes
            }
            "proof.dev/operation/workspace.status/v1" => &no_application_problem_codes,
            _ => &localized_v2_application_problem_codes,
        };
        assert_eq!(
            &row["application_problem_codes"], expected,
            "{version} post-Allow application failures drifted from its source contract"
        );
        assert_eq!(
            row["effect_digest_rule"], expected_agent_effect_rules[version],
            "{version} application-effect digest contract drifted"
        );
        for code in row["application_problem_codes"].as_array().unwrap() {
            assert!(
                !forbidden_post_allow_application_codes.contains(code.as_str().unwrap()),
                "{version} permits a pre-proof, authorization-only, transport, or infrastructure code as an application failure: {code}"
            );
        }
    }
    let application_problem_code_validator = validator(
        &schema_registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/applicationProblemCode"),
    );
    for row in routes
        .iter()
        .flat_map(|route| route["operations"].as_array().into_iter().flatten())
    {
        for code in row["application_problem_codes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            assert!(
                application_problem_code_validator.is_valid(code),
                "{} advertises application failure {code} outside RemoteApplicationConsequenceV1",
                row["operation"]
            );
        }
    }
    let registry_validator = validator(
        &schema_registry,
        "https://proof.dev/schema/collaboration-server/http-operation-registry/v1",
    );
    let mut substituted_human_effect = registry.clone();
    substituted_human_effect["routes"][5]["operations"][6]["effect_digest_rule"] = json!({
        "digest_context": "proof:remote-authority-record:v1",
        "effect_timestamp_field": "issued_at",
        "mode": "blake3-256-derive-key-rfc8785",
        "preimage_source": "agent-binding-issue-v1-remote-authority-record",
        "source_contract": "https://proof.dev/schema/authority/principal-binding/v1",
    });
    assert!(registry_validator.is_valid(&substituted_human_effect));
    assert_ne!(
        substituted_human_effect["routes"][5]["operations"][6]["effect_digest_rule"],
        expected_human_effect_rules["proof.dev/operation/changeset.approve/v3"],
        "the mandatory semantic registry validator must reject a schema-valid cross-operation effect substitution"
    );
    let mut incoherent_effect_tuple = registry.clone();
    incoherent_effect_tuple["routes"][5]["operations"][6]["effect_digest_rule"]["source_contract"] =
        json!("https://proof.dev/schema/authority/principal-binding/v1");
    assert!(
        !registry_validator.is_valid(&incoherent_effect_tuple),
        "the registry Schema must reject a token/source tuple that is internally incoherent"
    );
    let mut wrong_authority_timestamp = registry.clone();
    wrong_authority_timestamp["routes"][5]["operations"][6]["effect_digest_rule"]["effect_timestamp_field"] =
        json!("revoked_at");
    assert!(
        !registry_validator.is_valid(&wrong_authority_timestamp),
        "an authority effect cannot select a timestamp member from another payload type"
    );
    let mut invented_non_authority_timestamp = registry.clone();
    invented_non_authority_timestamp["routes"][5]["operations"][3]["effect_digest_rule"]["effect_timestamp_field"] =
        json!("approved_at");
    assert!(
        !registry_validator.is_valid(&invented_non_authority_timestamp),
        "a non-authority effect must keep effect_timestamp_field null"
    );
    let mut infrastructure_as_application_failure = registry.clone();
    infrastructure_as_application_failure["routes"][6]["operations"][13]["application_problem_codes"] =
        json!(["proof.internal"]);
    assert!(
        !registry_validator.is_valid(&infrastructure_as_application_failure),
        "the registry Schema must reject infrastructure codes as post-Allow application failures"
    );

    let application_failure_preimage = json!({
        "api_version": "proof.dev/application-problem-digest-preimage/v1",
        "code": "proof.state.conflict",
        "operation": {
            "name": "release.create",
            "version": "proof.dev/operation/release.create/v2"
        }
    });
    assert!(
        validator(
            &schema_registry,
            &format!("{ARTIFACT_SCHEMA_ID}#/$defs/applicationProblemDigestPreimageV1"),
        )
        .is_valid(&application_failure_preimage)
    );
    let application_failure_digest =
        canonical_digest("proof:operation-effect:v1", &application_failure_preimage);
    let mut different_failure_code = application_failure_preimage.clone();
    different_failure_code["code"] = json!("proof.resource.not_found");
    assert_ne!(
        application_failure_digest,
        canonical_digest("proof:operation-effect:v1", &different_failure_code),
        "an application failure digest must commit the exact public code"
    );
    let mut different_failure_operation = application_failure_preimage;
    different_failure_operation["operation"]["name"] = json!("edition.create");
    different_failure_operation["operation"]["version"] =
        json!("proof.dev/operation/edition.create/v2");
    assert_ne!(
        application_failure_digest,
        canonical_digest("proof:operation-effect:v1", &different_failure_operation),
        "an application failure digest must commit the exact operation pair"
    );

    let release_create_result = parse_file(&collaboration_path(
        "vectors/release-create-result.private-test.json",
    ));
    assert_eq!(
        release_create_result["release_digest"],
        canonical_digest(
            "proof:release:v2",
            &release_create_result["release_manifest"]
        ),
        "release.create/v2 application effect must be the exact ReleaseV2 manifest digest"
    );
    let release_consequence = parse_file(&collaboration_path(
        "vectors/remote-application-consequence.valid.json",
    ));
    assert_eq!(
        release_consequence["application_effect_digest"],
        release_create_result["release_digest"]
    );
    let mut substituted_release_manifest = release_create_result["release_manifest"].clone();
    substituted_release_manifest["release_sequence"] = json!(3);
    assert_ne!(
        release_create_result["release_digest"],
        canonical_digest("proof:release:v2", &substituted_release_manifest),
        "the effect digest must reject a schema-valid Release manifest substitution"
    );

    let source_projection = registry["source_problem_projection"]["rules"]
        .as_object()
        .unwrap();
    for row in agent_operations {
        let operation = row["operation"]["name"].as_str().unwrap();
        let version = row["operation"]["version"].as_str().unwrap();
        let capability = CAPABILITY_REGISTRY
            .iter()
            .find(|capability| capability.operation == operation && capability.version == version)
            .unwrap_or_else(|| panic!("HTTP Agent row {operation}/{version} is not accepted"));
        assert_eq!(row["requested_action"], capability.required_action.as_str());
        let profile_name = row["application_error_profile"].as_str().unwrap();
        let profile = &registry["agent_error_profiles"][profile_name];
        assert_eq!(
            profile["error_codes"],
            json!(capability.error_codes),
            "{version} source error set drifted"
        );
        assert_eq!(
            profile["ambient_error_codes"],
            json!(capability.ambient_error_codes),
            "{version} ambient error set drifted"
        );
        assert_eq!(
            profile["authenticated_error_codes"],
            json!(capability.authenticated_error_codes),
            "{version} authenticated error set drifted"
        );
        let unreachable = profile["unreachable_error_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        let expected_public = capability
            .authenticated_error_codes
            .iter()
            .filter(|code| !unreachable.contains(**code))
            .map(|code| {
                source_projection[*code]
                    .as_str()
                    .unwrap_or_else(|| panic!("{code} lacks a public disclosure projection"))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            profile["public_problem_codes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|code| code.as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            expected_public,
            "{version} public Problem projection is not exact"
        );
        if row["application_idempotency"] == "none" {
            if capability
                .authenticated_error_codes
                .contains(&"proof.idempotency.key_reused")
            {
                assert!(unreachable.contains("proof.idempotency.key_reused"));
            }
            assert!(!expected_public.contains("proof.idempotency.key_reused"));
        }
        if let Some(maximum) = capability.max_objects {
            assert!(
                row["request_limits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|limit| limit["maximum"].as_u64() == Some(u64::from(maximum))),
                "{version} does not expose its accepted capability item ceiling"
            );
        }
    }

    let http_agent_request = parse_file(&collaboration_path(
        "vectors/http-agent-operation.valid.json",
    ));
    let command_input = &http_agent_request["invocation"]["command_input"];
    assert_eq!(command_input["normalized_input"], json!({}));
    let effective_workspace_input = json!({
        "operating_principal_id": command_input["operating_principal_id"].clone(),
        "delegation_id": command_input["delegation_id"].clone(),
    });
    let workspace_capability = CAPABILITY_REGISTRY
        .iter()
        .find(|capability| capability.version == "proof.dev/operation/workspace.status/v1")
        .unwrap();
    let workspace_capability_schema =
        parse_strict(workspace_capability.input_schema_json.as_bytes())
            .expect("accepted workspace.status/v1 input Schema must strict-parse");
    let workspace_capability_validator = jsonschema::draft202012::options()
        .build(&workspace_capability_schema)
        .expect("accepted workspace.status/v1 input Schema must compile");
    assert!(workspace_capability_validator.is_valid(&effective_workspace_input));
    assert!(
        validator(
            &schema_registry,
            "https://proof.dev/schema/collaboration-server/application-operations/v1#/$defs/workspaceStatusInputV1",
        )
        .is_valid(&command_input["normalized_input"]),
        "the HTTP row validates the signed normalized semantic input, then reconstructs the accepted capability input from outer actor fields"
    );
    let mut mismatched_effective_input = effective_workspace_input;
    mismatched_effective_input["delegation_id"] = json!("019e0000-0000-7000-8000-000000000099");
    assert!(workspace_capability_validator.is_valid(&mismatched_effective_input));
    assert_ne!(
        mismatched_effective_input["delegation_id"], command_input["delegation_id"],
        "Schema validity alone cannot replace the mandatory outer-field equality check"
    );
}

#[test]
fn storage_delivery_decision_fixtures_are_semantically_self_consistent() {
    let (_, contract_registry) = schema_registry();
    let manifest = parse_file(&collaboration_path(
        "vectors/storage-delivery-contract-manifest.valid.json",
    ));
    assert_eq!(
        manifest["api_version"],
        "proof.dev/storage-delivery-contract-manifest/v1"
    );
    assert_eq!(manifest["evidence_class"], "decision-contract-inventory");
    assert_eq!(manifest["runtime_qualified"].as_bool(), Some(false));
    assert!(
        manifest["validation_scope"]
            .as_str()
            .unwrap()
            .contains("not runtime implementation evidence")
    );

    let expected_inventory = [
        (
            "authoritative-transaction",
            "schemas/storage-transaction-v1.schema.json",
            "vectors/storage-transaction-traces.valid.json",
        ),
        (
            "artifact-catalog",
            "schemas/artifact-catalog-v1.schema.json",
            "vectors/artifact-catalog.valid.json",
        ),
        (
            "outbox-delivery",
            "schemas/outbox-delivery-v1.schema.json",
            "vectors/outbox-delivery.valid.json",
        ),
        (
            "migration-rebuild",
            "schemas/migration-rebuild-v1.schema.json",
            "vectors/migration-rebuild.valid.json",
        ),
        (
            "preview-delivery",
            "schemas/preview-delivery-v1.schema.json",
            "vectors/preview-delivery.valid.json",
        ),
        (
            "remote-evidence",
            "schemas/remote-evidence-v2.schema.json",
            "vectors/remote-evidence-v2.valid.json",
        ),
    ];
    let inventory = manifest["fixtures"].as_array().unwrap();
    assert_eq!(inventory.len(), expected_inventory.len());
    for (entry, &(contract, schema_path, vector_path)) in
        inventory.iter().zip(expected_inventory.iter())
    {
        assert_eq!(entry["contract"], contract);
        assert_eq!(entry["schema_path"], schema_path);
        assert_eq!(entry["accepted_vector_path"], vector_path);

        let schema_path = collaboration_path(schema_path);
        let vector_path = collaboration_path(vector_path);
        assert!(
            schema_path.is_file(),
            "{} is missing",
            schema_path.display()
        );
        assert!(
            vector_path.is_file(),
            "{} is missing",
            vector_path.display()
        );
        let vector = parse_file(&vector_path);
        assert_eq!(vector["evidence_class"], "decision-contract");
        assert_eq!(
            vector["runtime_qualified"].as_bool(),
            Some(false),
            "{} must remain explicitly non-runtime evidence",
            vector_path.display()
        );
    }
    assert_eq!(
        inventory
            .iter()
            .map(|entry| entry["contract"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_inventory
            .iter()
            .map(|(contract, _, _)| *contract)
            .collect()
    );
    assert_eq!(
        inventory
            .iter()
            .map(|entry| entry["schema_path"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_inventory
            .iter()
            .map(|(_, schema, _)| *schema)
            .collect()
    );
    assert_eq!(
        inventory
            .iter()
            .map(|entry| entry["accepted_vector_path"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        expected_inventory
            .iter()
            .map(|(_, _, vector)| *vector)
            .collect()
    );

    let transactions = parse_file(&collaboration_path(
        "vectors/storage-transaction-traces.valid.json",
    ));
    assert_eq!(
        transactions["contract"]["exactly_once_claim"].as_bool(),
        Some(false)
    );
    assert_eq!(
        transactions["contract"]["response_before_commit_success"].as_bool(),
        Some(false)
    );
    let traces = transactions["traces"].as_array().unwrap();
    assert_eq!(
        traces
            .iter()
            .map(|trace| trace["trace_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "tx-pre-proof-denial",
            "tx-proven-denial",
            "tx-equivalent-replay",
            "tx-changed-input-conflict",
            "tx-precondition-conflict",
            "tx-success",
            "tx-authorized-application-failure",
            "tx-infrastructure-rollback",
        ]
    );
    for trace in traces {
        assert_eq!(trace["operation"], "release.create/v2");
        let outcome = trace["outcome"].as_str().unwrap();
        let committed = trace["transaction_outcome"] == "committed";
        let rolled_back = trace["transaction_outcome"] == "rolled-back";
        assert_ne!(committed, rolled_back);
        let effects = trace["durable_effects"].as_object().unwrap();

        if rolled_back {
            for (field, value) in effects {
                if field == "outbox_event_count" {
                    assert_eq!(value.as_u64(), Some(0), "{outcome}: {field}");
                } else {
                    assert_eq!(value.as_bool(), Some(false), "{outcome}: {field}");
                }
            }
        } else {
            assert_eq!(trace["authentication_proven"].as_bool(), Some(true));
            for field in [
                "presentation_consumed",
                "authorization_decision_appended",
                "fork_capable_signed_bodies_appended",
                "artifact_catalog_references_appended",
                "workspace_heads_advanced",
            ] {
                assert_eq!(effects[field].as_bool(), Some(true), "{outcome}: {field}");
            }
        }

        let is_success = outcome == "success";
        for field in [
            "governed_domain_facts_appended",
            "successful_idempotency_record_created",
            "result_record_created",
            "projections_updated",
        ] {
            assert_eq!(
                effects[field].as_bool(),
                Some(is_success),
                "{outcome}: {field}"
            );
        }
        assert_eq!(
            effects["outbox_event_count"].as_u64(),
            Some(u64::from(is_success)),
            "{outcome}: outbox effects"
        );
        assert_eq!(
            effects["replay_record_appended"].as_bool(),
            Some(outcome == "equivalent-replay")
        );
        assert_eq!(
            effects["failure_consequence_appended"].as_bool(),
            Some(matches!(
                outcome,
                "changed-input-conflict"
                    | "precondition-conflict"
                    | "authorized-application-failure"
            ))
        );
        assert_eq!(
            trace["retryable"].as_bool(),
            Some(outcome == "infrastructure-rollback")
        );
    }
    let replay = &traces[2];
    assert_eq!(replay["response_source"], "prior-committed-result");
    assert_eq!(replay["idempotency_outcome"], "equivalent-replay");
    assert_eq!(
        replay["durable_effects"]["successful_idempotency_record_created"].as_bool(),
        Some(false)
    );
    let success = &traces[5];
    assert_eq!(success["response_source"], "new-committed-result");
    assert_eq!(success["savepoint_outcome"], "released");

    let artifacts = parse_file(&collaboration_path("vectors/artifact-catalog.valid.json"));
    assert_eq!(
        artifacts["contract"]["distributed_transaction_claim"].as_bool(),
        Some(false)
    );
    let entries = artifacts["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let mut artifact_ids = BTreeSet::new();
    let mut artifact_digests = BTreeSet::new();
    let mut object_keys = BTreeSet::new();
    for entry in entries {
        assert!(artifact_ids.insert(entry["artifact_id"].as_str().unwrap()));
        let content_digest = entry["content_digest"].as_str().unwrap();
        assert!(artifact_digests.insert(content_digest));
        assert_eq!(entry["catalog_state"], "committed");
        assert_eq!(entry["immutable"].as_bool(), Some(true));
        assert_eq!(
            entry["abort_leaves_durable_signed_fork"].as_bool(),
            Some(false)
        );

        match entry["storage_class"].as_str().unwrap() {
            "authority-neutral-external" => {
                assert_eq!(entry["authority_neutral"].as_bool(), Some(true));
                assert_eq!(entry["fork_capable"].as_bool(), Some(false));
                assert_eq!(entry["precommit_staging"], "private-unreachable-permitted");
                let expected_key = format!(
                    "artifacts/{}/blake3/{}",
                    entry["artifact_kind"].as_str().unwrap(),
                    content_digest.strip_prefix("blake3:").unwrap()
                );
                assert_eq!(
                    entry["external"]["object_key"].as_str(),
                    Some(expected_key.as_str())
                );
                assert!(object_keys.insert(expected_key));
                assert_eq!(entry["external"]["put_if_absent"].as_bool(), Some(true));
                assert_eq!(
                    entry["external"]["exact_readback_verified"].as_bool(),
                    Some(true)
                );
                assert_eq!(
                    entry["external"]["publicly_reachable_before_commit"].as_bool(),
                    Some(false)
                );
                assert!(entry["postgresql_body"]["body_digest"].is_null());
                assert_eq!(
                    entry["postgresql_body"]["logged_table"].as_bool(),
                    Some(false)
                );
                assert_eq!(entry["mirror_policy"], "not-applicable");
            }
            "fork-capable-postgresql" => {
                assert_eq!(entry["authority_neutral"].as_bool(), Some(false));
                assert_eq!(entry["fork_capable"].as_bool(), Some(true));
                assert_eq!(entry["precommit_staging"], "forbidden");
                assert!(entry["external"]["object_key"].is_null());
                assert_eq!(
                    entry["postgresql_body"]["body_digest"],
                    entry["content_digest"]
                );
                assert_eq!(
                    entry["postgresql_body"]["logged_table"].as_bool(),
                    Some(true)
                );
                assert_eq!(
                    entry["postgresql_body"]["inserted_with_catalog_and_authority_state"].as_bool(),
                    Some(true)
                );
                assert_eq!(entry["mirror_policy"], "post-commit-outbox-only");
            }
            storage_class => panic!("unexpected artifact storage class {storage_class}"),
        }
    }
    assert_eq!(artifact_ids.len(), entries.len());
    assert_eq!(artifact_digests.len(), entries.len());

    let outbox = parse_file(&collaboration_path("vectors/outbox-delivery.valid.json"));
    assert_eq!(outbox["contract"]["delivery_semantics"], "at-least-once");
    assert_eq!(
        outbox["contract"]["exactly_once_claim"].as_bool(),
        Some(false)
    );
    let scenarios = outbox["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 2);
    let mut event_ids = BTreeSet::new();
    let mut delivery_ids = BTreeSet::new();
    let mut ordered_facts = Vec::new();
    for scenario in scenarios {
        let event = &scenario["event"];
        let state = &scenario["delivery_state"];
        let delivery_id = state["delivery_id"].as_str().unwrap();
        assert!(event_ids.insert(event["event_id"].as_str().unwrap()));
        assert!(delivery_ids.insert(delivery_id));
        assert_eq!(event["event_id"], state["event_id"]);
        assert_eq!(
            event["workspace_id"],
            event["uniqueness_inputs"]["workspace_id"]
        );
        assert_eq!(
            event["effect_identity"]["effect_digest"],
            event["uniqueness_inputs"]["effect_digest"]
        );
        assert_eq!(
            event["event_type"],
            event["uniqueness_inputs"]["event_type"]
        );
        assert_eq!(
            event["event_version"],
            event["uniqueness_inputs"]["event_version"]
        );
        assert_eq!(
            event["destination_configuration_digest"],
            event["uniqueness_inputs"]["destination_configuration_digest"]
        );
        assert!(
            event["created_at"].as_str().unwrap()
                < state["generation_started_at"].as_str().unwrap()
        );

        let attempts = scenario["attempt_facts"].as_array().unwrap();
        let receipts = scenario["receipt_facts"].as_array().unwrap();
        let management = scenario["management_facts"].as_array().unwrap();
        let mut attempts_by_generation = BTreeMap::<u64, Vec<u64>>::new();
        for attempt in attempts {
            assert_eq!(attempt["delivery_id"], state["delivery_id"]);
            assert_eq!(
                attempt["lease_seconds"],
                outbox["contract"]["lease_seconds"]
            );
            assert_eq!(
                attempt["attempt_deadline_seconds"],
                outbox["contract"]["attempt_deadline_seconds"]
            );
            let generation = attempt["generation"].as_u64().unwrap();
            assert!(generation <= state["generation"].as_u64().unwrap());
            attempts_by_generation
                .entry(generation)
                .or_default()
                .push(attempt["attempt_number"].as_u64().unwrap());
            ordered_facts.push((
                attempt["fact_sequence"].as_u64().unwrap(),
                attempt["claimed_at"].as_str().unwrap(),
            ));
        }
        for numbers in attempts_by_generation.values_mut() {
            numbers.sort_unstable();
            assert_eq!(
                *numbers,
                (1..=numbers.len() as u64).collect::<Vec<_>>(),
                "attempt numbers must restart at one and remain contiguous"
            );
        }
        let current_generation = state["generation"].as_u64().unwrap();
        assert_eq!(
            state["attempts_in_generation"].as_u64(),
            Some(
                attempts
                    .iter()
                    .filter(|attempt| attempt["generation"].as_u64() == Some(current_generation))
                    .count() as u64
            )
        );

        for receipt in receipts {
            assert_eq!(receipt["delivery_id"], state["delivery_id"]);
            assert_eq!(receipt["receipt_id"], state["receipt_id"]);
            assert_eq!(receipt["remote_side_effect_proven"].as_bool(), Some(false));
            let accepted_attempt = attempts
                .iter()
                .find(|attempt| {
                    attempt["generation"] == receipt["generation"]
                        && attempt["attempt_number"] == receipt["attempt_number"]
                })
                .expect("receipt must reference a recorded attempt");
            assert_eq!(accepted_attempt["ack_cas_result"], "accepted");
            assert!(
                accepted_attempt["claimed_at"].as_str().unwrap()
                    < receipt["observed_at"].as_str().unwrap()
            );
            ordered_facts.push((
                receipt["fact_sequence"].as_u64().unwrap(),
                receipt["observed_at"].as_str().unwrap(),
            ));
        }
        assert_eq!(state["receipt_id"].is_null(), receipts.is_empty());

        for fact in management {
            let application_fact = &fact["application_fact"];
            assert_eq!(
                application_fact["api_version"],
                "proof.dev/delivery-management-fact/v1"
            );
            assert_eq!(application_fact["workspace_id"], event["workspace_id"]);
            assert_eq!(application_fact["event_id"], event["event_id"]);
            assert_eq!(application_fact["delivery_id"], state["delivery_id"]);
            assert!(
                application_fact["workspace_transaction_sequence"]
                    .as_u64()
                    .unwrap()
                    > event["workspace_transaction_sequence"].as_u64().unwrap()
            );
            assert_eq!(fact["immutable_identity_preserved"].as_bool(), Some(true));
            let created_at = application_fact["recorded_at"].as_str().unwrap();
            match application_fact["action"].as_str().unwrap() {
                "replay" => {
                    let from_generation = application_fact["from_generation"].as_u64().unwrap();
                    let to_generation = application_fact["to_generation"].as_u64().unwrap();
                    assert_eq!(to_generation, from_generation + 1);
                    assert_eq!(fact["management_cursor_advanced"].as_bool(), Some(false));
                    assert!(
                        created_at
                            < attempts
                                .iter()
                                .filter(|attempt| {
                                    attempt["generation"].as_u64() == Some(to_generation)
                                })
                                .map(|attempt| attempt["claimed_at"].as_str().unwrap())
                                .min()
                                .expect("replayed generation must contain an attempt")
                    );
                    if to_generation == current_generation {
                        assert!(created_at < state["generation_started_at"].as_str().unwrap());
                    }
                }
                "abandon" => {
                    assert_eq!(
                        application_fact["from_generation"].as_u64(),
                        Some(current_generation)
                    );
                    assert!(application_fact["to_generation"].is_null());
                    assert_eq!(fact["management_cursor_advanced"].as_bool(), Some(true));
                    assert_eq!(state["status"], "abandoned");
                    assert!(
                        created_at
                            > attempts
                                .iter()
                                .map(|attempt| attempt["claimed_at"].as_str().unwrap())
                                .max()
                                .expect("abandonment follows at least one attempt")
                    );
                }
                action => panic!("unexpected delivery management action {action}"),
            }
            ordered_facts.push((fact["fact_sequence"].as_u64().unwrap(), created_at));
        }

        match scenario["scenario"].as_str().unwrap() {
            "lost-ack-redelivery" => {
                assert_eq!(state["status"], "delivered");
                assert_eq!(state["generation"].as_u64(), Some(1));
                assert_eq!(attempts.len(), 2);
                assert_eq!(receipts.len(), 1);
                assert!(management.is_empty());
                assert_eq!(attempts[0]["outcome"], "remote-accepted-ack-lost");
                assert_eq!(attempts[0]["ack_cas_result"], "not-observed");
                assert_eq!(attempts[1]["outcome"], "recipient-duplicate-no-op");
                assert_eq!(attempts[1]["ack_cas_result"], "accepted");
            }
            "poison-abandonment" => {
                assert_eq!(state["status"], "abandoned");
                assert_eq!(state["generation"].as_u64(), Some(2));
                assert!(receipts.is_empty());
                assert_eq!(management.len(), 2);
                assert_eq!(management[0]["application_fact"]["action"], "replay");
                assert_eq!(management[1]["application_fact"]["action"], "abandon");
            }
            name => panic!("unexpected outbox scenario {name}"),
        }
    }
    assert_eq!(event_ids.len(), scenarios.len());
    assert_eq!(delivery_ids.len(), scenarios.len());
    ordered_facts.sort_unstable_by_key(|(sequence, _)| *sequence);
    assert_eq!(
        ordered_facts
            .iter()
            .map(|(sequence, _)| *sequence)
            .collect::<Vec<_>>(),
        (1..=7).collect::<Vec<_>>()
    );
    for adjacent in ordered_facts.windows(2) {
        assert!(adjacent[0].1 < adjacent[1].1);
    }
    let outbox_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/outbox-delivery/v1",
    );
    assert!(outbox_validator.is_valid(&outbox));
    let mut legacy_workspace_outbox = outbox.clone();
    legacy_workspace_outbox["scenarios"][0]["event"]["workspace_id"] = json!("ws_1111111111111111");
    assert!(
        !outbox_validator.is_valid(&legacy_workspace_outbox),
        "outbox events must use the domain UUIDv7 WorkspaceId"
    );
    let mut unsafe_integer_outbox = outbox.clone();
    unsafe_integer_outbox["scenarios"][0]["event"]["stream_sequence"] =
        json!(9_007_199_254_742_016_u64);
    assert!(
        !outbox_validator.is_valid(&unsafe_integer_outbox),
        "outbox sequences must stay inside the I-JSON exact-integer range"
    );

    let migration = parse_file(&collaboration_path("vectors/migration-rebuild.valid.json"));
    let phases = migration["contract"]["phases"].as_array().unwrap();
    let phase_positions = phases
        .iter()
        .enumerate()
        .map(|(index, phase)| (phase.as_str().unwrap(), index))
        .collect::<BTreeMap<_, _>>();
    let ledger = migration["migration_ledger"].as_array().unwrap();
    assert_eq!(ledger.len(), 3);
    assert_eq!(
        ledger
            .iter()
            .map(|record| {
                (
                    record["phase"].as_str().unwrap(),
                    record["status"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("backfill", "started"),
            ("verify", "verified"),
            ("contract", "failed")
        ]
    );
    assert_eq!(
        ledger
            .iter()
            .map(|record| record["migration_name"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        ledger.len()
    );
    assert_eq!(
        ledger
            .iter()
            .map(|record| record["script_digest"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        ledger.len()
    );
    for adjacent in ledger.windows(2) {
        assert_eq!(
            adjacent[1]["ledger_sequence"].as_u64().unwrap(),
            adjacent[0]["ledger_sequence"].as_u64().unwrap() + 1
        );
        assert!(
            adjacent[0]["database_time"].as_str().unwrap()
                < adjacent[1]["database_time"].as_str().unwrap()
        );
        assert!(
            adjacent[0]["migration_version"].as_u64().unwrap()
                <= adjacent[1]["migration_version"].as_u64().unwrap()
        );
        assert!(
            phase_positions[adjacent[0]["phase"].as_str().unwrap()]
                < phase_positions[adjacent[1]["phase"].as_str().unwrap()]
        );
    }
    let rebuild = &migration["projection_rebuild"];
    assert_eq!(
        rebuild["candidate_generation"].as_u64().unwrap(),
        rebuild["old_generation"].as_u64().unwrap() + 1
    );
    assert_eq!(rebuild["source_chains_verified"].as_bool(), Some(true));
    assert_eq!(
        rebuild["comparisons"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "counts",
            "foreign_keys",
            "identities",
            "sequences",
            "state_digest",
            "versions",
        ])
    );
    assert!(
        rebuild["comparisons"]
            .as_object()
            .unwrap()
            .values()
            .all(|comparison| comparison == "matched")
    );
    assert_eq!(rebuild["atomic_pointer_swap"].as_bool(), Some(true));
    assert_eq!(rebuild["partial_candidate_exposed"].as_bool(), Some(false));
    assert_eq!(rebuild["reader_generation_pinned"].as_bool(), Some(true));
    assert_eq!(
        rebuild["retired_generation_retained_until_no_readers"].as_bool(),
        Some(true)
    );
    for scenario in scenarios {
        assert_eq!(
            scenario["event"]["workspace_id"], rebuild["workspace_id"],
            "outbox and rebuild fixtures must use one exact WorkspaceId grammar and identity"
        );
    }
    let migration_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/migration-rebuild/v1",
    );
    assert!(migration_validator.is_valid(&migration));
    let mut legacy_workspace_rebuild = migration.clone();
    legacy_workspace_rebuild["projection_rebuild"]["workspace_id"] = json!("ws_1111111111111111");
    assert!(
        !migration_validator.is_valid(&legacy_workspace_rebuild),
        "projection rebuilds must use the domain UUIDv7 WorkspaceId"
    );
    let mut unsafe_integer_migration = migration.clone();
    unsafe_integer_migration["migration_ledger"][0]["ledger_sequence"] =
        json!(9_007_199_254_740_992_u64);
    assert!(
        !migration_validator.is_valid(&unsafe_integer_migration),
        "migration sequences must stay inside the I-JSON exact-integer range"
    );

    let preview = parse_file(&collaboration_path("vectors/preview-delivery.valid.json"));
    let delivery = &preview["delivery"];
    let event_payload = &delivery["event_payload"];
    let ready = &delivery["ready_response"];
    assert_eq!(
        delivery["stream_sequence"],
        event_payload["release_sequence"]
    );
    assert_eq!(delivery["environment_id"], ready["environment_id"]);
    assert_eq!(delivery["release_id"], ready["release_id"]);
    assert_eq!(event_payload["release_digest"], ready["release_digest"]);
    assert_eq!(event_payload["edition_digest"], ready["edition_digest"]);
    assert_eq!(delivery["materialized_private"].as_bool(), Some(true));
    assert_eq!(delivery["ready_state"], "ready");
    assert_eq!(delivery["ready_marker_order"], "last");
    assert_eq!(delivery["publicly_reachable"].as_bool(), Some(false));
    assert_eq!(ready["body_source"], "ready-manifest-exact-bytes");
    assert_eq!(ready["cache_control"], preview["contract"]["cache_control"]);
    assert_eq!(
        ready["etag"].as_str().unwrap(),
        format!("\"{}\"", ready["rendition_digest"].as_str().unwrap())
    );
    assert_eq!(ready["locale_fallback"].as_bool(), Some(false));

    let preview_manifest = delivery["manifest"].as_array().unwrap();
    assert_eq!(
        preview_manifest.len(),
        event_payload["artifact_refs"].as_array().unwrap().len()
    );
    let mut preview_paths = BTreeSet::new();
    let mut preview_artifact_refs = BTreeSet::new();
    let mut preview_digests = BTreeSet::new();
    let mut preview_object_keys = BTreeSet::new();
    let mut rendition_members = Vec::new();
    for member in preview_manifest {
        assert!(preview_paths.insert(member["path"].as_str().unwrap()));
        assert!(preview_artifact_refs.insert(member["artifact_ref"].as_str().unwrap()));
        let digest = member["content_digest"].as_str().unwrap();
        assert!(preview_digests.insert(digest));
        let expected_key = format!(
            "preview/private/blake3/{}",
            digest.strip_prefix("blake3:").unwrap()
        );
        assert_eq!(member["object_key"].as_str(), Some(expected_key.as_str()));
        assert!(preview_object_keys.insert(expected_key));
        if member["artifact_kind"] == "release-json" {
            assert_eq!(member["content_digest"], event_payload["release_digest"]);
        }
        if member["artifact_kind"] == "release-proof" {
            assert_eq!(member["content_digest"], event_payload["proof_digest"]);
        }
        if member["artifact_kind"] == "rendition-json" {
            rendition_members.push(member);
        }
    }
    assert_eq!(preview_paths.len(), preview_manifest.len());
    assert_eq!(preview_digests.len(), preview_manifest.len());
    assert_eq!(preview_object_keys.len(), preview_manifest.len());
    assert_eq!(
        preview_artifact_refs,
        event_payload["artifact_refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|artifact_ref| artifact_ref.as_str().unwrap())
            .collect()
    );
    assert_eq!(rendition_members.len(), 1);
    let rendition = rendition_members[0];
    assert_eq!(rendition["artifact_ref"], ready["rendition_artifact_ref"]);
    assert_eq!(rendition["content_digest"], ready["rendition_digest"]);
    assert_eq!(rendition["object_id"], ready["object_id"]);
    assert_eq!(rendition["locale"], ready["locale"]);

    let cas_outcomes = preview["cas_outcomes"].as_array().unwrap();
    assert_eq!(cas_outcomes.len(), 4);
    for cas in cas_outcomes {
        assert_eq!(cas["alias_regressed"].as_bool(), Some(false));
        let current = cas["current_stream_sequence"].as_u64().unwrap();
        let candidate = cas["candidate_stream_sequence"].as_u64().unwrap();
        match cas["sequence_relation"].as_str().unwrap() {
            "higher" => {
                assert!(candidate > current);
                assert_eq!(candidate, delivery["stream_sequence"].as_u64().unwrap());
                assert_eq!(cas["candidate_release_id"], delivery["release_id"]);
                assert_eq!(
                    cas["candidate_manifest_digest"],
                    delivery["manifest_digest"]
                );
                assert_eq!(cas["outcome"], "advanced");
            }
            "equal-same-bytes" => {
                assert_eq!(candidate, current);
                assert_eq!(current, delivery["stream_sequence"].as_u64().unwrap());
                assert_eq!(cas["current_release_id"], cas["candidate_release_id"]);
                assert_eq!(cas["current_release_id"], delivery["release_id"]);
                assert_eq!(
                    cas["current_manifest_digest"],
                    cas["candidate_manifest_digest"]
                );
                assert_eq!(cas["current_manifest_digest"], delivery["manifest_digest"]);
                assert_eq!(cas["outcome"], "no-op");
            }
            "equal-different-bytes" => {
                assert_eq!(candidate, current);
                assert_eq!(current, delivery["stream_sequence"].as_u64().unwrap());
                assert_eq!(cas["current_release_id"], delivery["release_id"]);
                assert_eq!(cas["current_manifest_digest"], delivery["manifest_digest"]);
                assert!(
                    cas["current_release_id"] != cas["candidate_release_id"]
                        || cas["current_manifest_digest"] != cas["candidate_manifest_digest"]
                );
                assert_eq!(cas["outcome"], "integrity-failure");
            }
            "lower" => {
                assert!(candidate < current);
                assert_eq!(current, delivery["stream_sequence"].as_u64().unwrap());
                assert_eq!(cas["current_release_id"], delivery["release_id"]);
                assert_eq!(cas["current_manifest_digest"], delivery["manifest_digest"]);
                assert_eq!(cas["outcome"], "superseded");
            }
            relation => panic!("unexpected preview CAS relation {relation}"),
        }
    }
    let preview_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/preview-delivery/v1",
    );
    assert!(preview_validator.is_valid(&preview));
    let mut legacy_release_preview = preview.clone();
    legacy_release_preview["delivery"]["release_id"] = json!("rel_3333333333333333");
    assert!(
        !preview_validator.is_valid(&legacy_release_preview),
        "preview delivery must use the domain UUIDv7 ReleaseId"
    );
    let mut unsafe_integer_preview = preview.clone();
    unsafe_integer_preview["delivery"]["stream_sequence"] = json!(9_007_199_254_742_016_u64);
    assert!(
        !preview_validator.is_valid(&unsafe_integer_preview),
        "preview sequences must stay inside the I-JSON exact-integer range"
    );

    let evidence = parse_file(&collaboration_path("vectors/remote-evidence-v2.valid.json"));
    let evidence_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2",
    );
    assert!(evidence_validator.is_valid(&evidence));
    assert_eq!(evidence["execution_status"], "normative-requirements-only");
    assert_eq!(evidence["runtime_qualified"].as_bool(), Some(false));

    let materialization = &evidence["materialization"];
    assert_eq!(materialization["status"], "unmaterialized-runtime-contract");
    assert_eq!(
        materialization["exact_bundle_bytes_retained"].as_bool(),
        Some(false)
    );
    assert_eq!(
        materialization["observed_reports_retained"].as_bool(),
        Some(false)
    );
    for forbidden_materialized_field in [
        "bundle_descriptor",
        "bundle_manifest",
        "export_lifecycle",
        "reports",
        "verifier_input",
    ] {
        assert!(
            evidence.get(forbidden_materialized_field).is_none(),
            "the decision-contract fixture must not invent {forbidden_materialized_field}"
        );
    }

    let composition = &evidence["composition"];
    assert_eq!(
        composition["p6_compatibility"],
        "AuthorityEvidenceBundleV1 and proof-verifier/authority-evidence-bundle-v1 remain unchanged for historical local evidence and are neither required nor relabeled for a remote attempt"
    );
    assert_eq!(
        composition["authority_entrypoint"],
        "P8 remote actor, decision, consequence, and authority chain only"
    );
    for (field, expected_fragment) in [
        ("artifact_closure", "#/$defs/remoteReleaseArtifactClosureV1"),
        (
            "remote_authority_closure",
            "#/$defs/remoteAuthorityRecordSetV1",
        ),
        (
            "remote_attempt_companions",
            "#/$defs/remoteAttemptCompanionsV1",
        ),
        ("verifier_input", "#/$defs/verifierInput"),
        ("verifier_report", "#/$defs/report"),
        ("conformance_report", "#/$defs/conformanceReport"),
    ] {
        assert_eq!(composition[field], expected_fragment);
        let reference = format!(
            "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2{expected_fragment}"
        );
        let _resolved_entrypoint = validator(&contract_registry, &reference);
    }

    let retained_components = evidence["retained_components"].as_array().unwrap();
    assert_eq!(retained_components.len(), 6);
    let retained_by_role = retained_components
        .iter()
        .map(|component| {
            (
                component["role"].as_str().unwrap(),
                component["path"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        retained_by_role,
        BTreeMap::from([
            (
                "actor-context-evidence",
                "conformance/v1/collaboration-server/vectors/authenticated-actor-context-evidence-v2.human-agent.valid.json",
            ),
            (
                "application-consequence",
                "conformance/v1/collaboration-server/vectors/remote-application-consequence.valid.json",
            ),
            (
                "authentication-event",
                "conformance/v1/collaboration-server/vectors/remote-authentication-event.valid.json",
            ),
            (
                "authorization-decision",
                "conformance/v1/collaboration-server/vectors/remote-authorization-decision.valid.json",
            ),
            (
                "operation-registry",
                "conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json",
            ),
            (
                "release-result-preimage",
                "conformance/v1/collaboration-server/vectors/release-create-result.private-test.json",
            ),
        ])
    );
    assert_eq!(
        retained_components
            .iter()
            .map(|component| component["path"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        retained_components.len()
    );
    for component in retained_components {
        assert_eq!(
            component["qualification"],
            "retained-exact-component-vector-not-a-materialized-bundle"
        );
        let retained_path = repository_root().join(component["path"].as_str().unwrap());
        assert!(
            retained_path.is_file(),
            "retained exact component must exist: {}",
            retained_path.display()
        );
        assert!(parse_file(&retained_path).is_object());
    }

    let contract = &evidence["contract"];
    assert_eq!(contract["event_contract"], "evidence.export/v2");
    assert_eq!(contract["bundle_hints_trusted"].as_bool(), Some(false));
    assert_eq!(contract["bundle_hints_auto_fetched"].as_bool(), Some(false));
    assert_eq!(contract["caller_trust_is_separate"].as_bool(), Some(true));
    for denied_access in [
        "verifier_database_access",
        "verifier_session_access",
        "verifier_private_key_access",
        "verifier_credential_access",
        "verifier_network_access",
    ] {
        assert_eq!(contract[denied_access].as_bool(), Some(false));
    }
    assert_eq!(contract["missing_disclosure_result"], "Incomplete");
    assert_eq!(
        contract["tamper_contradiction_or_falsity_result"],
        "Invalid"
    );
    assert!(
        contract["runtime_qualification_gate"]
            .as_str()
            .unwrap()
            .contains("this unmaterialized contract or any descriptor-only fixture cannot produce an observed Complete report")
    );

    let scenarios = evidence["normative_scenarios"].as_array().unwrap();
    assert_eq!(
        scenarios
            .iter()
            .map(|scenario| {
                (
                    scenario["scenario"].as_str().unwrap(),
                    scenario["expected_status"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("complete-exact-materialization", "Complete"),
            ("incomplete-required-opening-withheld", "Incomplete",),
            ("invalid-content-artifact-byte-tamper", "Invalid"),
        ]
    );
    assert!(scenarios.iter().all(|scenario| {
        scenario["claim_kind"] == "normative-successor-requirement"
            && scenario["delivery_evidence"] == "not-requested"
            && scenario["runtime_observed"].as_bool() == Some(false)
    }));

    let mut falsely_qualified = evidence.clone();
    falsely_qualified["runtime_qualified"] = json!(true);
    assert!(
        !evidence_validator.is_valid(&falsely_qualified),
        "an unmaterialized contract cannot claim runtime qualification"
    );
    let mut invented_materialization = evidence.clone();
    invented_materialization["materialization"]["exact_bundle_bytes_retained"] = json!(true);
    assert!(
        !evidence_validator.is_valid(&invented_materialization),
        "the decision contract cannot claim exact unretained bundle bytes"
    );
    let mut invented_bundle = evidence.clone();
    invented_bundle["bundle_manifest"] = json!({});
    assert!(
        !evidence_validator.is_valid(&invented_bundle),
        "materialized bundle fields are forbidden until exact runtime bytes exist"
    );
    let mut observed_normative_scenario = evidence.clone();
    observed_normative_scenario["normative_scenarios"][0]["runtime_observed"] = json!(true);
    assert!(
        !evidence_validator.is_valid(&observed_normative_scenario),
        "a normative successor scenario is not an observed verifier report"
    );
    let mut reordered_scenarios = evidence.clone();
    reordered_scenarios["normative_scenarios"]
        .as_array_mut()
        .unwrap()
        .swap(0, 2);
    assert!(
        !evidence_validator.is_valid(&reordered_scenarios),
        "the three closed conditional scenarios have a canonical order"
    );
    let mut incomplete_retained_set = evidence.clone();
    incomplete_retained_set["retained_components"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(
        !evidence_validator.is_valid(&incomplete_retained_set),
        "all six exact component fixtures are required"
    );

    let authority_record_envelope = parse_file(&collaboration_path(
        "vectors/remote-authority-record-envelope.valid.json",
    ));
    let authority_record_payload = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    let authority_record_set = json!({
        "api_version": "proof.dev/remote-authority-record-set/v1",
        "workspace_id": authority_record_payload["workspace_id"].clone(),
        "base_head": authority_record_payload["evaluated_authority_head"].clone(),
        "record_order": "decoded authority_sequence ascending and contiguous",
        "records": [authority_record_envelope],
        "included_head": {
            "sequence": authority_record_payload["authority_sequence"].clone(),
            "record_digest": canonical_digest(
                "proof:remote-authority-record:v1",
                &authority_record_payload,
            ),
        },
    });
    let authority_record_set_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2#/$defs/remoteAuthorityRecordSetV1",
    );
    assert!(authority_record_set_validator.is_valid(&authority_record_set));
    assert_eq!(
        authority_record_set["base_head"]["sequence"]
            .as_u64()
            .map(|sequence| sequence + 1),
        authority_record_set["included_head"]["sequence"].as_u64()
    );
    assert_eq!(
        authority_record_set["base_head"]["record_digest"],
        authority_record_payload["previous_authority_record_digest"]
    );
    let mut empty_authority_record_set = authority_record_set.clone();
    empty_authority_record_set["records"] = json!([]);
    assert!(
        !authority_record_set_validator.is_valid(&empty_authority_record_set),
        "a remote authority suffix must carry at least one exact signed envelope"
    );
    let mut substituted_base_head = authority_record_set.clone();
    substituted_base_head["base_head"]["record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(authority_record_set_validator.is_valid(&substituted_base_head));
    assert_ne!(
        substituted_base_head["base_head"]["record_digest"],
        authority_record_payload["previous_authority_record_digest"],
        "the semantic verifier must reject a producer-selected suffix anchor"
    );

    let remote_decision = parse_file(&collaboration_path(
        "vectors/remote-authorization-decision.valid.json",
    ));
    let remote_consequence = parse_file(&collaboration_path(
        "vectors/remote-application-consequence.valid.json",
    ));
    let remote_decision_digest =
        canonical_digest("proof:remote-authority-record:v1", &remote_decision);
    let remote_consequence_digest =
        canonical_digest("proof:remote-authority-record:v1", &remote_consequence);
    assert_eq!(
        remote_consequence["decision_digest"],
        remote_decision_digest
    );
    assert_eq!(
        remote_consequence["evaluated_authority_head"],
        json!({
            "sequence": remote_decision["authority_sequence"].clone(),
            "record_digest": remote_decision_digest.clone(),
        })
    );
    assert_eq!(
        remote_consequence["authority_sequence"].as_u64(),
        remote_decision["authority_sequence"]
            .as_u64()
            .map(|sequence| sequence + 1)
    );
    let remote_chain_heads = [
        remote_decision["evaluated_authority_head"].clone(),
        json!({
            "sequence": remote_decision["authority_sequence"].clone(),
            "record_digest": remote_decision_digest.clone(),
        }),
        json!({
            "sequence": remote_consequence["authority_sequence"].clone(),
            "record_digest": remote_consequence_digest.clone(),
        }),
    ];
    let included_remote_head = remote_chain_heads.last().unwrap();
    let closure_remote_head = included_remote_head.clone();
    let captured_authority_digest = included_remote_head["record_digest"].clone();
    assert_eq!(closure_remote_head, *included_remote_head);
    assert_eq!(
        captured_authority_digest,
        included_remote_head["record_digest"]
    );
    let mut same_digest_wrong_sequence = closure_remote_head.clone();
    same_digest_wrong_sequence["sequence"] =
        json!(included_remote_head["sequence"].as_u64().unwrap() - 1);
    assert_eq!(
        same_digest_wrong_sequence["record_digest"],
        included_remote_head["record_digest"]
    );
    assert_ne!(
        same_digest_wrong_sequence, *included_remote_head,
        "closure head equality checks sequence and digest even though capture heads.authority carries only the digest"
    );

    let authority_checkpoint = json!({
        "api_version": "proof.dev/authority-checkpoint/v1",
        "workspace_id": remote_consequence["workspace_id"].clone(),
        "authority_sequence": included_remote_head["sequence"].clone(),
        "authority_record_digest": included_remote_head["record_digest"].clone(),
        "active_authority_key_id": remote_consequence["authority_key_id"].clone(),
        "observed_at": "2026-08-23T03:10:02Z",
    });
    let authority_checkpoint_validator = validator(
        &contract_registry,
        "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2#/$defs/authorityCheckpoint",
    );
    assert!(authority_checkpoint_validator.is_valid(&authority_checkpoint));
    assert_eq!(
        (
            &authority_checkpoint["workspace_id"],
            &authority_checkpoint["authority_sequence"],
            &authority_checkpoint["authority_record_digest"],
            &authority_checkpoint["active_authority_key_id"],
        ),
        (
            &remote_consequence["workspace_id"],
            &included_remote_head["sequence"],
            &included_remote_head["record_digest"],
            &remote_consequence["authority_key_id"],
        ),
        "a required caller checkpoint must exactly equal the included head and active key"
    );

    let mut unsupported_later_checkpoint = authority_checkpoint.clone();
    unsupported_later_checkpoint["authority_sequence"] =
        json!(authority_checkpoint["authority_sequence"].as_u64().unwrap() + 1);
    unsupported_later_checkpoint["authority_record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        authority_checkpoint_validator.is_valid(&unsupported_later_checkpoint),
        "the checkpoint shape alone cannot prove omitted intervening records"
    );
    assert_ne!(
        (
            &unsupported_later_checkpoint["authority_sequence"],
            &unsupported_later_checkpoint["authority_record_digest"],
        ),
        (
            &included_remote_head["sequence"],
            &included_remote_head["record_digest"],
        ),
        "a higher checkpoint is not ancestry without every intervening verified record"
    );
    let mut wrong_checkpoint_key = authority_checkpoint.clone();
    wrong_checkpoint_key["active_authority_key_id"] =
        json!("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(authority_checkpoint_validator.is_valid(&wrong_checkpoint_key));
    assert_ne!(
        wrong_checkpoint_key["active_authority_key_id"], remote_consequence["authority_key_id"],
        "the caller checkpoint must name the exact causally active authority key"
    );

    let cutoff_accepts_selected_attempt = |cutoff: &Value, included_head: &Value| {
        let cutoff_sequence = cutoff["sequence"].as_u64().unwrap();
        remote_chain_heads.iter().any(|head| head == cutoff)
            && included_head["sequence"].as_u64().unwrap() <= cutoff_sequence
            && remote_decision["authority_sequence"].as_u64().unwrap() <= cutoff_sequence
            && remote_consequence["authority_sequence"].as_u64().unwrap() <= cutoff_sequence
    };
    let consequence_head_cutoff = included_remote_head.clone();
    assert!(cutoff_accepts_selected_attempt(
        &consequence_head_cutoff,
        included_remote_head,
    ));
    assert_eq!(
        consequence_head_cutoff, *included_remote_head,
        "a disclosed cutoff in this bounded profile must be the included head"
    );
    let decision_head_cutoff = remote_chain_heads[1].clone();
    assert!(
        !cutoff_accepts_selected_attempt(&decision_head_cutoff, included_remote_head),
        "a cutoff at the decision rejects its later selected consequence"
    );
    let extended_included_head = json!({
        "sequence": included_remote_head["sequence"].as_u64().unwrap() + 1,
        "record_digest": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    });
    assert!(
        !cutoff_accepts_selected_attempt(&consequence_head_cutoff, &extended_included_head),
        "the bounded record set must reject an included head after the compromise cutoff even when the selected decision and consequence precede it"
    );
    let mut same_sequence_wrong_digest_cutoff = consequence_head_cutoff.clone();
    same_sequence_wrong_digest_cutoff["record_digest"] =
        json!("blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(
        !cutoff_accepts_selected_attempt(&same_sequence_wrong_digest_cutoff, included_remote_head,),
        "a compromise cutoff must equal one exact recomputed chain head, not only its sequence"
    );
}

#[test]
fn evidence_export_create_replay_and_ready_member_acquisition_are_unambiguous() {
    let (_, registry) = schema_registry();
    let create_input_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceExportInputV2"),
    );
    let create_result_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceExportResultV2"),
    );
    let get_input_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceExportGetInputV1"),
    );
    let status_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceExportStatusV1"),
    );
    let member_input_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceArtifactGetInputV2"),
    );
    let member_metadata_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceArtifactMetadataV2"),
    );

    let create_input = json!({
        "export_id": "019e1234-5678-7abc-8def-000000000081",
        "release_id": "019e1234-5678-7abc-8def-000000000082",
        "release_digest": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "disclosure_profile": "complete-portable",
        "idempotency_key": "019e1234-5678-7abc-8def-000000000083",
    });
    assert!(create_input_validator.is_valid(&create_input));
    let immutable_create_result = json!({
        "api_version": "proof.dev/evidence-export-result/v2",
        "export_id": create_input["export_id"].clone(),
        "status": "pending",
        "capture_digest": "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    });
    assert!(create_result_validator.is_valid(&immutable_create_result));
    let stored_create_digest =
        canonical_digest("proof:operation-effect:v1", &immutable_create_result);
    let mut illegal_ready_create_result = immutable_create_result.clone();
    illegal_ready_create_result["status"] = json!("ready");
    assert!(
        !create_result_validator.is_valid(&illegal_ready_create_result),
        "the keyed create result cannot mutate when producer readiness changes"
    );

    let get_input = json!({ "export_id": create_input["export_id"].clone() });
    assert!(get_input_validator.is_valid(&get_input));
    let mut keyed_get_input = get_input.clone();
    keyed_get_input["idempotency_key"] = create_input["idempotency_key"].clone();
    assert!(
        !get_input_validator.is_valid(&keyed_get_input),
        "the lifecycle read cannot consult or reserve an application key"
    );
    let pending_status = json!({
        "api_version": "proof.dev/evidence-export-status/v1",
        "export_id": create_input["export_id"].clone(),
        "status": "pending",
        "capture_digest": immutable_create_result["capture_digest"].clone(),
        "bundle_descriptor_digest": null,
        "manifest_digest": null,
        "artifact_count": 0,
        "total_included_bytes": 0,
    });
    assert!(status_validator.is_valid(&pending_status));
    let ready_status = json!({
        "api_version": "proof.dev/evidence-export-status/v1",
        "export_id": create_input["export_id"].clone(),
        "status": "ready",
        "capture_digest": immutable_create_result["capture_digest"].clone(),
        "bundle_descriptor_digest": "blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "manifest_digest": "blake3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "artifact_count": 9,
        "total_included_bytes": 12_345,
    });
    assert!(status_validator.is_valid(&ready_status));
    assert_ne!(
        canonical_digest("proof:operation-effect:v1", &pending_status),
        canonical_digest("proof:operation-effect:v1", &ready_status),
        "fresh no-key status projections may observe a later producer state"
    );
    assert_eq!(
        canonical_digest("proof:operation-effect:v1", &immutable_create_result),
        stored_create_digest,
        "the original keyed create replay remains byte-identical after readiness"
    );

    let reserved_bundle_selector = json!({
        "export_id": ready_status["export_id"].clone(),
        "artifact_kind": "remote_evidence_bundle_v2",
        "artifact_digest": ready_status["bundle_descriptor_digest"].clone(),
    });
    let reserved_manifest_selector = json!({
        "export_id": ready_status["export_id"].clone(),
        "artifact_kind": "remote_evidence_manifest_v2",
        "artifact_digest": ready_status["manifest_digest"].clone(),
    });
    assert!(member_input_validator.is_valid(&reserved_bundle_selector));
    assert!(member_input_validator.is_valid(&reserved_manifest_selector));
    assert_eq!(
        ready_status["artifact_count"].as_u64().unwrap() + 2,
        11,
        "the two reserved descriptor members are addressable in addition to the six-root-plus-nested artifact count"
    );
    let same_digest_other_kind = json!({
        "export_id": ready_status["export_id"].clone(),
        "artifact_kind": "remote_evidence_manifest_v2",
        "artifact_digest": ready_status["bundle_descriptor_digest"].clone(),
    });
    assert!(member_input_validator.is_valid(&same_digest_other_kind));
    assert_ne!(
        reserved_bundle_selector, same_digest_other_kind,
        "same digest text under another artifact kind is a distinct, non-aliasing selector"
    );

    let raw_digest = [0x11_u8; 32];
    let artifact_digest = format!("blake3:{}", hex_lower(&raw_digest));
    let artifact_metadata = json!({
        "export_id": ready_status["export_id"].clone(),
        "artifact_digest": artifact_digest,
        "artifact_kind": "remote_evidence_manifest_v2",
        "artifact_media_type": "application/json",
        "byte_length": 1024,
        "content_digest": format!("blake3=:{}:", BASE64.encode(raw_digest)),
        "content_length": 1024,
        "content_type": "application/octet-stream",
        "etag": format!("\"{artifact_digest}\""),
        "x_proof_artifact_digest": artifact_digest,
        "x_proof_artifact_kind": "remote_evidence_manifest_v2",
    });
    assert!(member_metadata_validator.is_valid(&artifact_metadata));
    let headers_match = |metadata: &Value| {
        let digest_hex = metadata["artifact_digest"]
            .as_str()
            .unwrap()
            .strip_prefix("blake3:")
            .unwrap();
        let digest_bytes = (0..digest_hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&digest_hex[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        metadata["content_digest"] == json!(format!("blake3=:{}:", BASE64.encode(digest_bytes)))
            && metadata["content_length"] == metadata["byte_length"]
            && metadata["x_proof_artifact_digest"] == metadata["artifact_digest"]
            && metadata["x_proof_artifact_kind"] == metadata["artifact_kind"]
            && metadata["etag"]
                == json!(format!(
                    "\"{}\"",
                    metadata["artifact_digest"].as_str().unwrap()
                ))
    };
    assert!(headers_match(&artifact_metadata));
    let mut mismatched_header_projection = artifact_metadata.clone();
    mismatched_header_projection["x_proof_artifact_kind"] = json!("remote_evidence_bundle_v2");
    assert!(member_metadata_validator.is_valid(&mismatched_header_projection));
    assert!(
        !headers_match(&mismatched_header_projection),
        "a syntactically valid required-header substitution is rejected semantically"
    );
    let mut mismatched_content_digest = artifact_metadata.clone();
    mismatched_content_digest["content_digest"] =
        json!("blake3=:IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=:");
    assert!(member_metadata_validator.is_valid(&mismatched_content_digest));
    assert!(
        !headers_match(&mismatched_content_digest),
        "Content-Digest must encode the same raw digest bytes selected by artifact_digest"
    );

    let http_registry = parse_file(&collaboration_path(
        "vectors/http-operation-registry.valid.json",
    ));
    let artifact_route = http_registry["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|route| route["route_id"] == "evidence-export-artifact")
        .unwrap();
    assert_eq!(
        artifact_route["path_template"],
        "/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}"
    );
    assert_eq!(
        http_registry["authorization_rule_definitions"]["proof.server/authorization/export-artifact-reader/v1"]
            ["operation_resource_bindings"]["proof.dev/operation/evidence.artifact.get/v2"],
        json!(["artifact_digest", "artifact_kind", "export_id"])
    );
}

#[test]
fn remote_evidence_direct_types_close_trust_artifact_and_observed_report_semantics() {
    let (_, registry) = schema_registry();
    let evidence_schema_id =
        "https://proof.dev/schema/conformance/collaboration-server/remote-evidence/v2";
    let trust_limits_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/verificationTrustPolicy/properties/limits"),
    );
    let trust_limits = json!({
        "max_verifier_input_bytes": 67_108_864,
        "max_manifest_bytes": 4_194_304,
        "max_artifacts": 4096,
        "max_authority_records": 512,
        "max_artifact_bytes": 4_194_304,
        "max_total_bytes": 268_435_456,
        "max_json_depth": 128,
    });
    assert!(trust_limits_validator.is_valid(&trust_limits));
    let evidence_schema = parse_file(&collaboration_path(
        "schemas/remote-evidence-v2.schema.json",
    ));
    let max_nested_artifacts = evidence_schema
        .pointer("/$defs/remoteReleaseArtifactClosureV1/properties/artifacts/maxItems")
        .and_then(Value::as_u64)
        .unwrap();
    assert_eq!(max_nested_artifacts, 4090);
    let inventory_fits_global_limit = |nested_artifacts: u64| {
        nested_artifacts <= max_nested_artifacts
            && 6 + nested_artifacts <= trust_limits["max_artifacts"].as_u64().unwrap()
    };
    assert!(inventory_fits_global_limit(4090));
    assert!(
        !inventory_fits_global_limit(4091),
        "4091 nested bodies plus six mandatory roots cannot exceed the global 4096-artifact bound"
    );
    let mut missing_raw_input_limit = trust_limits.clone();
    missing_raw_input_limit
        .as_object_mut()
        .unwrap()
        .remove("max_verifier_input_bytes");
    assert!(
        !trust_limits_validator.is_valid(&missing_raw_input_limit),
        "decoded-body limits cannot substitute for a raw verifier-input parser bound"
    );
    let mut oversized_raw_input_limit = trust_limits.clone();
    oversized_raw_input_limit["max_verifier_input_bytes"] = json!(268_435_457);
    assert!(
        !trust_limits_validator.is_valid(&oversized_raw_input_limit),
        "caller policy cannot raise the fixed 256 MiB pre-parse ceiling"
    );
    let raw_input_is_accepted =
        |raw_bytes: u64, caller_limit: u64| raw_bytes <= 268_435_456 && raw_bytes <= caller_limit;
    assert!(raw_input_is_accepted(67_108_864, 67_108_864));
    assert!(!raw_input_is_accepted(67_108_865, 67_108_864));
    assert!(!raw_input_is_accepted(268_435_457, 536_870_912));
    let authority_union = validator(
        &registry,
        &format!("{ARTIFACT_SCHEMA_ID}#/$defs/remoteAuthorityRecordV1"),
    );
    let timestamp_field_by_api = BTreeMap::from([
        ("proof.dev/principal-binding/v1", "issued_at"),
        ("proof.dev/principal-binding-revocation/v1", "revoked_at"),
        ("proof.dev/delegation/v2", "issued_at"),
        ("proof.dev/delegation-revocation/v1", "revoked_at"),
        ("proof.dev/oidc-principal-binding/v1", "issued_at"),
        (
            "proof.dev/oidc-principal-binding-revocation/v1",
            "revoked_at",
        ),
        ("proof.dev/workspace-role-assignment/v1", "assigned_at"),
        ("proof.dev/workspace-role-revocation/v1", "revoked_at"),
        ("proof.dev/changeset-approval/v1", "approved_at"),
        ("proof.dev/environment-config-proposal/v1", "proposed_at"),
        ("proof.dev/environment-config-activation/v1", "activated_at"),
        ("proof.dev/environment-creation/v1", "created_at"),
        ("proof.dev/remote-principal-status/v2", "recorded_at"),
        ("proof.dev/remote-authorization-decision/v1", "evaluated_at"),
        ("proof.dev/remote-application-consequence/v1", "recorded_at"),
    ]);
    let authority_payload_paths = [
        "conformance/v1/authority/vectors/principal-binding.valid.json",
        "conformance/v1/authority/vectors/principal-binding-revocation.valid.json",
        "conformance/v1/authority/vectors/delegation-v2.valid.json",
        "conformance/v1/authority/vectors/delegation-revocation.valid.json",
        "conformance/v1/collaboration-server/vectors/oidc-principal-binding.valid.json",
        "conformance/v1/collaboration-server/vectors/oidc-principal-binding-revocation.valid.json",
        "conformance/v1/collaboration-server/vectors/workspace-role-assignment.valid.json",
        "conformance/v1/collaboration-server/vectors/workspace-role-revocation.valid.json",
        "conformance/v1/collaboration-server/vectors/changeset-approval.valid.json",
        "conformance/v1/collaboration-server/vectors/environment-config-proposal.valid.json",
        "conformance/v1/collaboration-server/vectors/environment-config-activation.valid.json",
        "conformance/v1/collaboration-server/vectors/environment-creation.valid.json",
        "conformance/v1/collaboration-server/vectors/remote-principal-status.valid.json",
        "conformance/v1/collaboration-server/vectors/remote-authorization-decision.valid.json",
        "conformance/v1/collaboration-server/vectors/remote-application-consequence.valid.json",
    ];
    assert_eq!(authority_payload_paths.len(), timestamp_field_by_api.len());

    let dsse = parse_file(&collaboration_path(
        "vectors/remote-authority-record.dsse-bytes.valid.json",
    ));
    let initial_root = json!({
        "key_id": dsse["signer"]["key_id"].clone(),
        "public_key": dsse["signer"]["public_key_base64"].clone(),
        "not_before": "2026-08-17T20:00:00Z",
        "not_after": "2026-08-24T00:00:00Z",
        "revoked_at": null,
    });
    let trusted_key_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/trustedKey"),
    );
    assert!(trusted_key_validator.is_valid(&initial_root));
    let decoded_initial_root = BASE64
        .decode(initial_root["public_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded_initial_root.len(), 32);
    assert_eq!(
        initial_root["key_id"],
        format!("ed25519:{}", hex_lower(&decoded_initial_root)),
        "trusted key identifiers are the lowercase hex of exact decoded key bytes"
    );
    let mut noncanonical_public_key = initial_root.clone();
    let mut noncanonical_base64 = initial_root["public_key"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    noncanonical_base64[42] = b'B';
    noncanonical_public_key["public_key"] = json!(String::from_utf8(noncanonical_base64).unwrap());
    assert!(
        !trusted_key_validator.is_valid(&noncanonical_public_key),
        "a 32-byte Ed25519 key rejects non-zero final Base64 pad bits"
    );
    let mut mismatched_key_id = initial_root.clone();
    mismatched_key_id["key_id"] =
        json!("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(trusted_key_validator.is_valid(&mismatched_key_id));
    assert_ne!(
        mismatched_key_id["key_id"],
        format!("ed25519:{}", hex_lower(&decoded_initial_root)),
        "a syntactically valid but byte-mismatched key identifier is a semantic failure"
    );
    let root_allows_timestamp = |root: &Value, timestamp: &str| {
        let timestamp = OffsetDateTime::parse(timestamp, &Rfc3339).unwrap();
        let not_before = parse_instant(&root["not_before"]);
        let not_after = root["not_after"].as_str().map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).expect("valid trusted-key not_after")
        });
        let revoked_at = root["revoked_at"].as_str().map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).expect("valid trusted-key revoked_at")
        });
        timestamp >= not_before
            && not_after.is_none_or(|bound| timestamp < bound)
            && revoked_at.is_none_or(|bound| timestamp < bound)
    };

    let semantic_timestamp_names = BTreeSet::from([
        "activated_at",
        "approved_at",
        "assigned_at",
        "created_at",
        "evaluated_at",
        "issued_at",
        "proposed_at",
        "recorded_at",
        "revoked_at",
    ]);
    let mut seen_apis = BTreeSet::new();
    for relative_path in authority_payload_paths {
        let payload = parse_file(&repository_root().join(relative_path));
        assert!(authority_union.is_valid(&payload), "{relative_path}");
        let api_version = payload["api_version"].as_str().unwrap();
        assert!(seen_apis.insert(api_version.to_owned()));
        let timestamp_field = timestamp_field_by_api[api_version];
        let timestamp = payload[timestamp_field].as_str().unwrap_or_else(|| {
            panic!("{api_version} must select semantic timestamp {timestamp_field}")
        });
        assert_eq!(
            semantic_timestamp_names
                .iter()
                .filter(|field| payload.get(**field).is_some())
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([timestamp_field]),
            "{api_version} must have one unambiguous authority-root evaluation timestamp"
        );
        assert!(
            root_allows_timestamp(&initial_root, timestamp),
            "the sole initial root must be valid at {api_version}.{timestamp_field}"
        );
    }
    assert_eq!(
        seen_apis,
        timestamp_field_by_api
            .keys()
            .map(|api_version| (*api_version).to_owned())
            .collect()
    );

    let assignment = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    let assignment_timestamp = assignment["assigned_at"].as_str().unwrap();
    let envelope = parse_file(&collaboration_path(
        "vectors/remote-authority-record-envelope.valid.json",
    ));
    assert_eq!(envelope["signatures"].as_array().unwrap().len(), 1);
    assert_eq!(envelope["signatures"][0]["keyid"], initial_root["key_id"]);
    assert_eq!(assignment["authority_key_id"], initial_root["key_id"]);
    let mut unsupported_rotation = envelope.clone();
    unsupported_rotation["signatures"][0]["keyid"] =
        json!("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_ne!(
        unsupported_rotation["signatures"][0]["keyid"], initial_root["key_id"],
        "the first remote profile rejects authority-key rotation rather than selecting a new envelope key"
    );

    let mut not_yet_valid_root = initial_root.clone();
    not_yet_valid_root["not_before"] = json!("2026-08-23T01:30:01Z");
    assert!(trusted_key_validator.is_valid(&not_yet_valid_root));
    assert!(!root_allows_timestamp(
        &not_yet_valid_root,
        assignment_timestamp,
    ));
    let mut expired_root = initial_root.clone();
    expired_root["not_after"] = json!("2026-08-23T01:29:59Z");
    assert!(trusted_key_validator.is_valid(&expired_root));
    assert!(!root_allows_timestamp(&expired_root, assignment_timestamp));
    let mut expires_at_payload_time = initial_root.clone();
    expires_at_payload_time["not_after"] = json!(assignment_timestamp);
    assert!(trusted_key_validator.is_valid(&expires_at_payload_time));
    assert!(
        !root_allows_timestamp(&expires_at_payload_time, assignment_timestamp),
        "authority payload time must be strictly before root expiry"
    );
    let mut revoked_at_payload_time = initial_root.clone();
    revoked_at_payload_time["revoked_at"] = json!(assignment_timestamp);
    assert!(trusted_key_validator.is_valid(&revoked_at_payload_time));
    assert!(
        !root_allows_timestamp(&revoked_at_payload_time, assignment_timestamp),
        "authority payload time must be strictly before root revocation"
    );
    let mut fractional_not_before = initial_root.clone();
    fractional_not_before["not_before"] = json!("2026-08-23T01:30:00.1Z");
    assert!(trusted_key_validator.is_valid(&fractional_not_before));
    assert!(
        !root_allows_timestamp(&fractional_not_before, assignment_timestamp),
        "a whole-second payload instant precedes a same-second fractional not_before bound"
    );
    let mut fractional_not_after = initial_root.clone();
    fractional_not_after["not_after"] = json!("2026-08-23T01:30:00.1Z");
    assert!(trusted_key_validator.is_valid(&fractional_not_after));
    assert!(
        root_allows_timestamp(&fractional_not_after, assignment_timestamp),
        "a whole-second payload instant remains strictly before a same-second fractional expiry"
    );

    let agent_binding = parse_file(
        &repository_root().join("conformance/v1/authority/vectors/principal-binding.valid.json"),
    );
    let release_key_bytes = [0x2a_u8; 32];
    let release_key_id = format!("ed25519:{}", hex_lower(&release_key_bytes));
    let command_key_bytes = [0x15_u8; 32];
    let command_key_id = format!("ed25519:{}", hex_lower(&command_key_bytes));
    let trusted_release_key = json!({
        "key_id": release_key_id.clone(),
        "public_key": BASE64.encode(release_key_bytes),
        "not_before": "2026-08-17T20:00:00Z",
        "not_after": "2026-08-24T00:00:00Z",
        "revoked_at": null,
    });
    assert!(trusted_key_validator.is_valid(&trusted_release_key));
    let role_keys = [
        (
            initial_root["key_id"].as_str().unwrap().to_owned(),
            BASE64
                .decode(initial_root["public_key"].as_str().unwrap())
                .unwrap(),
        ),
        (release_key_id.clone(), release_key_bytes.to_vec()),
        (command_key_id.clone(), command_key_bytes.to_vec()),
    ];
    let role_keys_are_separated = |keys: &[(String, Vec<u8>)]| {
        keys.iter()
            .map(|(key_id, _)| key_id)
            .collect::<BTreeSet<_>>()
            .len()
            == keys.len()
            && keys
                .iter()
                .map(|(_, public_key)| public_key)
                .collect::<BTreeSet<_>>()
                .len()
                == keys.len()
    };
    assert!(role_keys_are_separated(&role_keys));
    let mut duplicate_role_id = role_keys.clone();
    let authority_role_id = duplicate_role_id[0].0.clone();
    duplicate_role_id[1].0 = authority_role_id;
    assert!(
        !role_keys_are_separated(&duplicate_role_id),
        "authority, Release, and Agent command roles require distinct key identifiers"
    );
    let mut duplicate_role_bytes = role_keys.clone();
    let authority_role_bytes = duplicate_role_bytes[0].1.clone();
    duplicate_role_bytes[1].1 = authority_role_bytes;
    assert!(
        !role_keys_are_separated(&duplicate_role_bytes),
        "key-role separation compares exact decoded public-key bytes as well as identifiers"
    );

    let release_result = parse_file(&collaboration_path(
        "vectors/release-create-result.private-test.json",
    ));
    assert_eq!(
        release_result["release_manifest"]["key_id"], trusted_release_key["key_id"],
        "the target ReleaseV2 signer must resolve to the exact caller-trusted release key"
    );
    let decoded_release_key = BASE64
        .decode(trusted_release_key["public_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded_release_key, release_key_bytes);
    assert_eq!(
        trusted_release_key["key_id"],
        format!("ed25519:{}", hex_lower(&decoded_release_key)),
        "the Release signer key identifier must equal its exact decoded Ed25519 bytes"
    );
    let trusted_signers_are_unambiguous = |keys: &[Value]| {
        let mut key_ids = BTreeSet::new();
        let mut public_keys = BTreeSet::new();
        keys.iter().all(|key| {
            let Ok(decoded) = BASE64.decode(key["public_key"].as_str().unwrap()) else {
                return false;
            };
            decoded.len() == 32
                && key["key_id"] == format!("ed25519:{}", hex_lower(&decoded))
                && key_ids.insert(key["key_id"].as_str().unwrap().to_owned())
                && public_keys.insert(decoded)
        })
    };
    let release_signer_resolves = |keys: &[Value], release: &Value| {
        trusted_signers_are_unambiguous(keys)
            && keys
                .iter()
                .filter(|key| {
                    key["key_id"] == release["release_manifest"]["key_id"]
                        && root_allows_timestamp(
                            key,
                            release["release_manifest"]["released_at"].as_str().unwrap(),
                        )
                })
                .count()
                == 1
    };
    let trusted_release_signers = vec![trusted_release_key.clone()];
    assert!(release_signer_resolves(
        &trusted_release_signers,
        &release_result,
    ));
    let mut same_id_different_bytes = trusted_release_key.clone();
    same_id_different_bytes["public_key"] = json!(BASE64.encode([0x2b_u8; 32]));
    assert!(
        !trusted_signers_are_unambiguous(&[trusted_release_key.clone(), same_id_different_bytes,]),
        "one signer identifier cannot denote two decoded public keys"
    );
    let mut different_id_same_bytes = trusted_release_key.clone();
    different_id_same_bytes["key_id"] = json!(format!("ed25519:{}", hex_lower(&[0x2b_u8; 32])));
    assert!(
        !trusted_signers_are_unambiguous(&[trusted_release_key.clone(), different_id_same_bytes,]),
        "one decoded public key cannot be relabeled as a second signer"
    );
    let mut untrusted_release = release_result.clone();
    untrusted_release["release_manifest"]["key_id"] =
        json!("ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        !release_signer_resolves(&trusted_release_signers, &untrusted_release),
        "an untrusted but well-formed Release signer cannot produce Complete"
    );
    let mut expired_release_key = trusted_release_key.clone();
    expired_release_key["not_after"] = release_result["release_manifest"]["released_at"].clone();
    assert!(trusted_key_validator.is_valid(&expired_release_key));
    assert!(
        !release_signer_resolves(&[expired_release_key], &release_result),
        "the Release instant is excluded at the exact signer expiry boundary"
    );
    let mut revoked_release_key = trusted_release_key.clone();
    revoked_release_key["revoked_at"] = release_result["release_manifest"]["released_at"].clone();
    assert!(trusted_key_validator.is_valid(&revoked_release_key));
    assert!(
        !release_signer_resolves(&[revoked_release_key], &release_result),
        "the Release instant is excluded at the exact signer revocation boundary"
    );
    let mut mismatched_release_key_bytes = trusted_release_key.clone();
    mismatched_release_key_bytes["public_key"] = json!(BASE64.encode([0x2b_u8; 32]));
    assert!(trusted_key_validator.is_valid(&mismatched_release_key_bytes));
    assert_ne!(
        mismatched_release_key_bytes["key_id"],
        format!(
            "ed25519:{}",
            hex_lower(
                &BASE64
                    .decode(mismatched_release_key_bytes["public_key"].as_str().unwrap())
                    .unwrap()
            )
        ),
        "matching signer labels cannot substitute different decoded public-key bytes"
    );
    let remote_decision = parse_file(&collaboration_path(
        "vectors/remote-authorization-decision.valid.json",
    ));
    let remote_consequence = parse_file(&collaboration_path(
        "vectors/remote-application-consequence.valid.json",
    ));

    let principal_binding_validator = validator(
        &registry,
        "https://proof.dev/schema/authority/principal-binding/v1",
    );
    let principal_binding_revocation_validator = validator(
        &registry,
        "https://proof.dev/schema/authority/principal-binding-revocation/v1",
    );
    let mut historical_agent_binding = agent_binding.clone();
    historical_agent_binding["authority_sequence"] =
        remote_decision["agent_authorization"]["binding"]["authority_sequence"].clone();
    historical_agent_binding["previous_authority_record_digest"] =
        json!("blake3:3838383838383838383838383838383838383838383838383838383838383838");
    historical_agent_binding["workspace_id"] = remote_decision["workspace_id"].clone();
    historical_agent_binding["binding_id"] =
        remote_decision["agent_authorization"]["binding"]["binding_id"].clone();
    historical_agent_binding["principal_id"] =
        remote_decision["agent_authorization"]["operating_principal_id"].clone();
    historical_agent_binding["authenticated_subject"] = json!({
        "api_version": "proof.dev/authenticated-subject/v1",
        "provider": "proof/local-ed25519",
        "subject": command_key_id.clone(),
    });
    historical_agent_binding["public_key"] = json!(BASE64.encode(command_key_bytes));
    historical_agent_binding["audience"] = json!(format!(
        "proof://workspace/{}",
        remote_decision["workspace_id"].as_str().unwrap()
    ));
    historical_agent_binding["issued_by_principal_id"] =
        remote_decision["requesting_principal_id"].clone();
    historical_agent_binding["issued_at"] = json!("2026-08-23T01:30:00Z");
    historical_agent_binding["not_before"] = json!("2026-08-23T01:30:00Z");
    historical_agent_binding["expires_at"] = json!("2026-08-24T01:30:00Z");
    assert!(principal_binding_validator.is_valid(&historical_agent_binding));
    assert!(authority_union.is_valid(&historical_agent_binding));
    let historical_binding_digest = canonical_digest(
        "proof:remote-authority-record:v1",
        &historical_agent_binding,
    );
    let mut historically_bound_decision = remote_decision.clone();
    historically_bound_decision["agent_authorization"]["binding"]["record_digest"] =
        json!(historical_binding_digest.clone());
    let selected_actor_evidence = parse_file(&collaboration_path(
        "vectors/authenticated-actor-context-evidence-v2.human-agent.valid.json",
    ));
    let mut historically_bound_actor = selected_actor_evidence;
    historically_bound_actor["operating_binding"]["record_digest"] =
        json!(historical_binding_digest.clone());
    historically_bound_actor["operating_subject"] =
        historical_agent_binding["authenticated_subject"].clone();
    assert_eq!(
        historically_bound_decision["agent_authorization"]["binding"],
        json!({
            "active": true,
            "authority_sequence": historical_agent_binding["authority_sequence"].clone(),
            "binding_id": historical_agent_binding["binding_id"].clone(),
            "record_digest": historical_binding_digest.clone(),
            "revocation_record_digest": null,
        })
    );
    assert_fields_equal(
        &historically_bound_decision["agent_authorization"]["binding"],
        &historically_bound_actor["operating_binding"],
        &["authority_sequence", "binding_id", "record_digest"],
        "historically selected Agent binding",
    );
    assert_eq!(
        historically_bound_actor["operating_subject"],
        historical_agent_binding["authenticated_subject"]
    );

    let mut later_agent_binding_revocation = parse_file(
        &repository_root()
            .join("conformance/v1/authority/vectors/principal-binding-revocation.valid.json"),
    );
    later_agent_binding_revocation["authority_sequence"] = json!(73);
    later_agent_binding_revocation["previous_authority_record_digest"] = json!(canonical_digest(
        "proof:remote-authority-record:v1",
        &remote_consequence
    ));
    later_agent_binding_revocation["workspace_id"] = remote_decision["workspace_id"].clone();
    later_agent_binding_revocation["revocation_id"] = json!("019e0000-0000-7000-8000-000000000075");
    later_agent_binding_revocation["binding_id"] = historical_agent_binding["binding_id"].clone();
    later_agent_binding_revocation["revoked_by_principal_id"] =
        remote_decision["requesting_principal_id"].clone();
    later_agent_binding_revocation["revoked_at"] = json!("2026-08-23T03:10:02Z");
    assert!(principal_binding_revocation_validator.is_valid(&later_agent_binding_revocation));
    assert!(authority_union.is_valid(&later_agent_binding_revocation));
    assert!(
        remote_consequence["authority_sequence"].as_u64().unwrap()
            < later_agent_binding_revocation["authority_sequence"]
                .as_u64()
                .unwrap()
    );

    let binding_is_active_at = |binding: &Value,
                                decision: &Value,
                                actor: &Value,
                                revocations: &[Value],
                                head_sequence: u64,
                                evaluated_at: &Value| {
        let decoded_key = BASE64
            .decode(binding["public_key"].as_str().unwrap())
            .unwrap();
        let selected = &decision["agent_authorization"]["binding"];
        canonical_digest("proof:remote-authority-record:v1", binding) == selected["record_digest"]
            && binding["binding_id"] == selected["binding_id"]
            && binding["authority_sequence"] == selected["authority_sequence"]
            && binding["binding_id"] == actor["operating_binding"]["binding_id"]
            && selected["record_digest"] == actor["operating_binding"]["record_digest"]
            && binding["authenticated_subject"] == actor["operating_subject"]
            && binding["authenticated_subject"]["subject"]
                == format!("ed25519:{}", hex_lower(&decoded_key))
            && binding["authority_sequence"].as_u64().unwrap() <= head_sequence
            && parse_instant(&binding["not_before"]) <= parse_instant(evaluated_at)
            && parse_instant(evaluated_at) < parse_instant(&binding["expires_at"])
            && !revocations.iter().any(|revocation| {
                revocation["binding_id"] == binding["binding_id"]
                    && revocation["authority_sequence"].as_u64().unwrap() <= head_sequence
                    && parse_instant(&revocation["revoked_at"]) <= parse_instant(evaluated_at)
            })
    };
    let target_decision_head = historically_bound_decision["evaluated_authority_head"]["sequence"]
        .as_u64()
        .unwrap();
    assert!(binding_is_active_at(
        &historical_agent_binding,
        &historically_bound_decision,
        &historically_bound_actor,
        std::slice::from_ref(&later_agent_binding_revocation),
        target_decision_head,
        &historically_bound_decision["evaluated_at"],
    ));
    assert!(
        !binding_is_active_at(
            &historical_agent_binding,
            &historically_bound_decision,
            &historically_bound_actor,
            std::slice::from_ref(&later_agent_binding_revocation),
            later_agent_binding_revocation["authority_sequence"]
                .as_u64()
                .unwrap(),
            &later_agent_binding_revocation["revoked_at"],
        ),
        "the binding is no longer current at the later included head"
    );
    let mut revocation_before_target = later_agent_binding_revocation.clone();
    revocation_before_target["authority_sequence"] = json!(70);
    revocation_before_target["revoked_at"] = json!("2026-08-23T03:09:59Z");
    assert!(principal_binding_revocation_validator.is_valid(&revocation_before_target));
    assert!(
        !binding_is_active_at(
            &historical_agent_binding,
            &historically_bound_decision,
            &historically_bound_actor,
            std::slice::from_ref(&revocation_before_target),
            target_decision_head,
            &historically_bound_decision["evaluated_at"],
        ),
        "a revocation at or before the target decision head invalidates historical selection"
    );
    let mut wrong_historical_binding_digest = historically_bound_decision.clone();
    wrong_historical_binding_digest["agent_authorization"]["binding"]["record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        !binding_is_active_at(
            &historical_agent_binding,
            &wrong_historical_binding_digest,
            &historically_bound_actor,
            &[],
            target_decision_head,
            &historically_bound_decision["evaluated_at"],
        ),
        "a same-ID binding with the wrong exact record digest cannot supply the command key"
    );

    let decision_record_digest = canonical_digest(
        "proof:remote-authority-record:v1",
        &historically_bound_decision,
    );
    let consequence_record_digest =
        canonical_digest("proof:remote-authority-record:v1", &remote_consequence);
    let required_authority_facts = BTreeMap::from([
        (
            historical_agent_binding["authority_sequence"]
                .as_u64()
                .unwrap(),
            historical_binding_digest.clone(),
        ),
        (
            historically_bound_decision["authority_sequence"]
                .as_u64()
                .unwrap(),
            decision_record_digest,
        ),
        (
            remote_consequence["authority_sequence"].as_u64().unwrap(),
            consequence_record_digest,
        ),
    ]);
    let authority_state_is_reconstructible =
        |base_sequence: u64, records: &BTreeMap<u64, String>, required: &BTreeMap<u64, String>| {
            let Some((&first_sequence, _)) = records.first_key_value() else {
                return false;
            };
            let Some((&last_sequence, _)) = records.last_key_value() else {
                return false;
            };
            let Some((&earliest_required_sequence, _)) = required.first_key_value() else {
                return false;
            };
            base_sequence < earliest_required_sequence
                && first_sequence == base_sequence + 1
                && records.len() == usize::try_from(last_sequence - base_sequence).unwrap()
                && records.keys().copied().eq(first_sequence..=last_sequence)
                && required
                    .iter()
                    .all(|(sequence, digest)| records.get(sequence) == Some(digest))
        };
    let complete_authority_records = (38_u64 + 1..=73)
        .map(|sequence| (sequence, format!("blake3:{sequence:064x}")))
        .collect::<BTreeMap<_, _>>();
    let mut complete_authority_records = complete_authority_records;
    for (sequence, digest) in &required_authority_facts {
        complete_authority_records.insert(*sequence, digest.clone());
    }
    assert!(authority_state_is_reconstructible(
        38,
        &complete_authority_records,
        &required_authority_facts,
    ));
    let decision_consequence_suffix = complete_authority_records
        .range(71..=73)
        .map(|(sequence, digest)| (*sequence, digest.clone()))
        .collect::<BTreeMap<_, _>>();
    assert!(
        !authority_state_is_reconstructible(
            70,
            &decision_consequence_suffix,
            &required_authority_facts,
        ),
        "a contiguous decision/consequence suffix cannot reconstruct an Agent binding issued before its digest-only base head"
    );
    let mut missing_intermediate_transition = complete_authority_records.clone();
    missing_intermediate_transition.remove(&40);
    assert!(
        !authority_state_is_reconstructible(
            38,
            &missing_intermediate_transition,
            &required_authority_facts,
        ),
        "every relevant transition from the caller anchor through the attempt must remain contiguous"
    );
    let mut substituted_required_fact = complete_authority_records.clone();
    substituted_required_fact.insert(
        39,
        "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
    );
    assert!(
        !authority_state_is_reconstructible(
            38,
            &substituted_required_fact,
            &required_authority_facts,
        ),
        "a sequence-complete chain with the wrong exact required fact is Invalid"
    );
    let release_ref = json!({
        "artifact_kind": "release_v2",
        "digest": release_result["release_digest"].clone(),
    });
    let proof_ref = json!({
        "artifact_kind": "proof_envelope_v1",
        "digest": release_result["proof_envelope_digest"].clone(),
    });
    let environment_ref = json!({
        "artifact_kind": "environment_config_v2_projection",
        "digest": remote_decision["environment_config_digest"].clone(),
    });
    let release_artifact_closure = json!({
        "api_version": "proof.dev/remote-release-artifact-closure/v1",
        "workspace_id": release_result["release_manifest"]["workspace_id"].clone(),
        "artifact_order": "artifact_kind, digest UTF-8 bytewise ascending",
        "artifacts": [
            {"artifact": environment_ref.clone(), "availability": {"state": "included", "byte_length": 1}},
            {"artifact": proof_ref.clone(), "availability": {"state": "included", "byte_length": 1}},
            {"artifact": release_ref.clone(), "availability": {"state": "included", "byte_length": 1}},
        ],
        "role_binding_order": "role, artifact_kind, digest UTF-8 bytewise ascending",
        "role_bindings": [
            {"artifact": release_ref.clone(), "role": "application_effect"},
            {"artifact": environment_ref.clone(), "role": "environment_config"},
            {"artifact": release_ref.clone(), "role": "release_manifest"},
            {"artifact": proof_ref.clone(), "role": "release_proof_envelope"},
        ],
        "entrypoints": {
            "application_effect": release_ref.clone(),
            "result_derivation": "proof.dev/release-create-output/v2 from target ReleaseV2 plus target Release Proof envelope digest",
            "target_environment_config": environment_ref.clone(),
            "target_release_manifest": release_ref.clone(),
            "target_release_proof_envelope": proof_ref.clone(),
        },
    });
    let release_artifact_closure_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/remoteReleaseArtifactClosureV1"),
    );
    assert!(release_artifact_closure_validator.is_valid(&release_artifact_closure));
    let release_closure_is_unambiguous = |closure: &Value| {
        let Some(artifacts) = closure["artifacts"].as_array() else {
            return false;
        };
        let Some(role_bindings) = closure["role_bindings"].as_array() else {
            return false;
        };
        let ref_key = |artifact: &Value| {
            (
                artifact["artifact_kind"].as_str().unwrap().to_owned(),
                artifact["digest"].as_str().unwrap().to_owned(),
            )
        };
        let mut descriptors = BTreeMap::new();
        for descriptor in artifacts {
            if descriptors
                .insert(ref_key(&descriptor["artifact"]), descriptor)
                .is_some()
            {
                return false;
            }
        }
        let mut roles = BTreeMap::new();
        let mut selected_refs = BTreeSet::new();
        for binding in role_bindings {
            let key = ref_key(&binding["artifact"]);
            if !descriptors.contains_key(&key)
                || roles
                    .insert(binding["role"].as_str().unwrap(), &binding["artifact"])
                    .is_some()
            {
                return false;
            }
            selected_refs.insert(key);
        }
        if selected_refs != descriptors.keys().cloned().collect() {
            return false;
        }
        let entrypoints = &closure["entrypoints"];
        roles
            .get("release_manifest")
            .is_some_and(|artifact| **artifact == entrypoints["target_release_manifest"])
            && roles
                .get("release_proof_envelope")
                .is_some_and(|artifact| **artifact == entrypoints["target_release_proof_envelope"])
            && roles
                .get("environment_config")
                .is_some_and(|artifact| **artifact == entrypoints["target_environment_config"])
            && roles
                .get("application_effect")
                .is_some_and(|artifact| **artifact == entrypoints["application_effect"])
            && entrypoints["target_release_manifest"] == entrypoints["application_effect"]
    };
    assert!(release_closure_is_unambiguous(&release_artifact_closure));
    let mut duplicate_artifact_ref = release_artifact_closure.clone();
    let mut same_ref_different_length = duplicate_artifact_ref["artifacts"][0].clone();
    same_ref_different_length["availability"]["byte_length"] = json!(2);
    duplicate_artifact_ref
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .unwrap()
        .push(same_ref_different_length);
    assert!(release_artifact_closure_validator.is_valid(&duplicate_artifact_ref));
    assert!(
        !release_closure_is_unambiguous(&duplicate_artifact_ref),
        "one ArtifactRef cannot select two descriptors or byte lengths"
    );
    let mut duplicate_role_binding = release_artifact_closure.clone();
    let alternate_release_ref_for_role = json!({
        "artifact_kind": "release_v2",
        "digest": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    duplicate_role_binding
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .unwrap()
        .push(json!({
            "artifact": alternate_release_ref_for_role.clone(),
            "availability": {"state": "included", "byte_length": 1},
        }));
    duplicate_role_binding
        .get_mut("role_bindings")
        .and_then(Value::as_array_mut)
        .unwrap()
        .push(json!({
            "artifact": alternate_release_ref_for_role,
            "role": "release_manifest",
        }));
    assert!(release_artifact_closure_validator.is_valid(&duplicate_role_binding));
    assert!(
        !release_closure_is_unambiguous(&duplicate_role_binding),
        "each required role resolves exactly one declared ArtifactRef"
    );
    let outer_root_identity_matches = |workspace_id: &Value,
                                       release_id: &Value,
                                       release_digest: &Value,
                                       closure: &Value,
                                       decision: &Value,
                                       release: &Value| {
        workspace_id == &closure["workspace_id"]
            && workspace_id == &decision["workspace_id"]
            && release_id == &release["release_id"]
            && release_digest == &release["release_digest"]
            && release_digest == &closure["entrypoints"]["target_release_manifest"]["digest"]
    };
    assert!(outer_root_identity_matches(
        &release_result["release_manifest"]["workspace_id"],
        &release_result["release_id"],
        &release_result["release_digest"],
        &release_artifact_closure,
        &remote_decision,
        &release_result,
    ));
    let wrong_outer_release_digest =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        !outer_root_identity_matches(
            &release_result["release_manifest"]["workspace_id"],
            &release_result["release_id"],
            &wrong_outer_release_digest,
            &release_artifact_closure,
            &remote_decision,
            &release_result,
        ),
        "contradictory unauthenticated outer Release metadata is Invalid rather than substituted into the inner claim"
    );
    assert_eq!(
        release_artifact_closure["entrypoints"]["target_release_manifest"],
        release_artifact_closure["entrypoints"]["application_effect"]
    );

    let mut wrong_entrypoint_kind = release_artifact_closure.clone();
    wrong_entrypoint_kind["entrypoints"]["target_release_manifest"] = proof_ref.clone();
    assert!(
        !release_artifact_closure_validator.is_valid(&wrong_entrypoint_kind),
        "the Release-manifest entrypoint cannot resolve a Proof-envelope artifact kind"
    );
    let mut unequal_release_effect = release_artifact_closure.clone();
    let alternate_release_ref = json!({
        "artifact_kind": "release_v2",
        "digest": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
    unequal_release_effect["artifacts"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "artifact": alternate_release_ref.clone(),
            "availability": {"state": "included", "byte_length": 1},
        }));
    unequal_release_effect["entrypoints"]["application_effect"] = alternate_release_ref.clone();
    let effect_binding = unequal_release_effect["role_bindings"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|binding| binding["role"] == "application_effect")
        .unwrap();
    effect_binding["artifact"] = alternate_release_ref;
    assert!(release_artifact_closure_validator.is_valid(&unequal_release_effect));
    assert_ne!(
        unequal_release_effect["entrypoints"]["target_release_manifest"],
        unequal_release_effect["entrypoints"]["application_effect"],
        "a schema-valid second ReleaseV2 digest must be rejected for release.create/v2 application effect"
    );

    let actor_evidence = parse_file(&collaboration_path(
        "vectors/authenticated-actor-context-evidence-v2.human-agent.valid.json",
    ));
    let authentication_event = parse_file(&collaboration_path(
        "vectors/remote-authentication-event.valid.json",
    ));
    let actor_evidence_digest = canonical_digest(
        "proof:authenticated-actor-context-evidence:v2",
        &actor_evidence,
    );
    let authentication_event_digest = canonical_digest(
        "proof:remote-authentication-event:v1",
        &authentication_event,
    );
    let oidc_binding = parse_file(&collaboration_path(
        "vectors/oidc-principal-binding.valid.json",
    ));
    let oidc_issuer_configuration = parse_file(&collaboration_path(
        "vectors/oidc-issuer-configuration.valid.json",
    ));
    let oidc_issuer_configuration_digest = canonical_digest(
        "proof:oidc-issuer-configuration:v1",
        &oidc_issuer_configuration,
    );
    assert_eq!(
        oidc_issuer_configuration_digest,
        actor_evidence["oidc_issuer_configuration_digest"]
    );
    assert_eq!(
        oidc_issuer_configuration_digest,
        authentication_event["oidc_issuer_configuration_digest"]
    );
    assert_eq!(
        oidc_issuer_configuration_digest,
        oidc_binding["oidc_issuer_configuration_digest"]
    );
    let remote_authentication_event_validator = validator(
        &registry,
        &format!("{REMOTE_AUTH_SCHEMA_ID}#/$defs/remoteAuthenticationEventV1"),
    );
    let actor_lifetime_is_valid = |event: &Value, actor: &Value, decision: &Value| {
        event["authenticated_at"] == actor["authenticated_at"]
            && parse_instant(&event["authenticated_at"]) <= parse_instant(&decision["evaluated_at"])
            && parse_instant(&decision["evaluated_at"]) < parse_instant(&event["expires_at"])
    };
    assert!(actor_lifetime_is_valid(
        &authentication_event,
        &actor_evidence,
        &remote_decision,
    ));
    let mut zero_lifetime_event = authentication_event.clone();
    zero_lifetime_event["expires_at"] = zero_lifetime_event["authenticated_at"].clone();
    assert!(remote_authentication_event_validator.is_valid(&zero_lifetime_event));
    assert!(
        !actor_lifetime_is_valid(&zero_lifetime_event, &actor_evidence, &remote_decision),
        "expires_at equal to authenticated_at is not a usable authority-attested session"
    );
    let mut decision_at_expiry = remote_decision.clone();
    decision_at_expiry["evaluated_at"] = authentication_event["expires_at"].clone();
    assert!(authority_union.is_valid(&decision_at_expiry));
    assert!(
        !actor_lifetime_is_valid(&authentication_event, &actor_evidence, &decision_at_expiry),
        "authorization at the exact authentication expiry boundary is Invalid"
    );
    let mut mismatched_actor_time = actor_evidence.clone();
    mismatched_actor_time["authenticated_at"] = json!("2026-08-23T03:09:59Z");
    assert!(
        !actor_lifetime_is_valid(
            &authentication_event,
            &mismatched_actor_time,
            &remote_decision
        ),
        "actor and authentication event times must be byte-identical"
    );
    let accepted_oidc_configurations = BTreeSet::from([oidc_issuer_configuration_digest.clone()]);
    assert!(
        accepted_oidc_configurations.contains(
            actor_evidence["oidc_issuer_configuration_digest"]
                .as_str()
                .unwrap()
        )
    );
    assert!(
        !accepted_oidc_configurations
            .contains("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "a repeated producer-selected issuer-configuration digest is not caller trust"
    );

    let accepted_agent_policies = BTreeSet::from([(
        "proof.local/authority/direct/v1".to_owned(),
        remote_decision["agent_authorization"]["policy_bundle_digest"]
            .as_str()
            .unwrap()
            .to_owned(),
    )]);
    let selected_agent_policy = (
        remote_decision["agent_authorization"]["policy_profile"]
            .as_str()
            .unwrap()
            .to_owned(),
        remote_decision["agent_authorization"]["policy_bundle_digest"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    assert!(accepted_agent_policies.contains(&selected_agent_policy));
    assert_ne!(
        remote_decision["policy_bundle_digest"],
        remote_decision["agent_authorization"]["policy_bundle_digest"],
        "the outer remote policy-selection digest is not the nested accepted direct-policy digest"
    );
    let mut unaccepted_nested_policy = remote_decision.clone();
    unaccepted_nested_policy["agent_authorization"]["policy_bundle_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(authority_union.is_valid(&unaccepted_nested_policy));
    assert_eq!(
        unaccepted_nested_policy["policy_bundle_digest"], remote_decision["policy_bundle_digest"],
        "the independently recomputed outer selection can remain correct while the nested policy is unaccepted"
    );
    assert!(
        !accepted_agent_policies.contains(&(
            unaccepted_nested_policy["agent_authorization"]["policy_profile"]
                .as_str()
                .unwrap()
                .to_owned(),
            unaccepted_nested_policy["agent_authorization"]["policy_bundle_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        ))
    );

    let http_registry = parse_file(&collaboration_path(
        "vectors/http-operation-registry.valid.json",
    ));
    let operation_registry_bytes = serde_json_canonicalizer::to_vec(&http_registry).unwrap();
    let operation_registry_hash = hex_lower(&sha256(&operation_registry_bytes));
    let projection_fields = http_registry["authorization_registry_commitment"]["projection_fields"]
        .as_array()
        .unwrap();
    let authorization_registry = Value::Object(
        projection_fields
            .iter()
            .map(|field| {
                let field = field.as_str().unwrap();
                (field.to_owned(), http_registry[field].clone())
            })
            .collect(),
    );
    let authorization_registry_bytes =
        serde_json_canonicalizer::to_vec(&authorization_registry).unwrap();
    let authorization_registry_hash = hex_lower(&sha256(&authorization_registry_bytes));
    assert_eq!(
        http_registry["authorization_registry_commitment"]["authorization_registry_sha256"],
        authorization_registry_hash,
    );
    assert_eq!(
        remote_decision["authorization_registry_sha256"],
        authorization_registry_hash,
    );
    assert_eq!(
        remote_decision["operation_registry_sha256"],
        operation_registry_hash,
    );

    let initial_head_source = parse_file(&collaboration_path(
        "vectors/workspace-role-assignment.valid.json",
    ));
    let caller_authority_checkpoint = json!({
        "api_version": "proof.dev/authority-checkpoint/v1",
        "workspace_id": remote_consequence["workspace_id"].clone(),
        "authority_sequence": later_agent_binding_revocation["authority_sequence"].clone(),
        "authority_record_digest": canonical_digest(
            "proof:remote-authority-record:v1",
            &later_agent_binding_revocation,
        ),
        "active_authority_key_id": remote_consequence["authority_key_id"].clone(),
        "observed_at": "2026-08-23T03:10:02Z",
    });
    assert!(
        validator(
            &registry,
            &format!("{evidence_schema_id}#/$defs/authorityCheckpoint"),
        )
        .is_valid(&caller_authority_checkpoint)
    );
    let verification_trust_policy = json!({
        "api_version": "proof.dev/verification-trust-policy/v2",
        "workspace_id": remote_decision["workspace_id"].clone(),
        "registry_resolution": {
            "profile": "proof.verifier/collaboration-registry/v1",
            "source": "verifier-built-in-closed-hash-to-rfc8785-document-table",
            "unknown_hash_result": "Invalid",
            "hash_mismatch_result": "Invalid",
        },
        "authority": {
            "initial_root": initial_root.clone(),
            "initial_head": initial_head_source["evaluated_authority_head"].clone(),
            "accepted_authorization_registry_hashes": [authorization_registry_hash.clone()],
            "accepted_operation_registry_hashes": [operation_registry_hash.clone()],
            "accepted_policy_bundles": [{
                "policy_profile": remote_decision["agent_authorization"]["policy_profile"].clone(),
                "policy_bundle_digest": remote_decision["agent_authorization"]["policy_bundle_digest"].clone(),
            }],
            "checkpoint_requirement": "required",
            "compromise_cutoff": null,
        },
        "release": {
            "trusted_signers": trusted_release_signers.clone(),
            "accepted_predicate_types": ["urn:proof:attestation:release:v2"],
            "accepted_policy_profiles": [{
                "policy_profile": "proof.local/release-policy/v1",
                "environment_config_digest": release_result["release_manifest"]["environment_config_digest"].clone(),
            }],
        },
        "remote_identity": {
            "accepted_oidc_issuer_configuration_digests": [oidc_issuer_configuration_digest.clone()],
        },
        "disclosure": {
            "requesting_subject_opening": "required",
        },
        "limits": trust_limits.clone(),
    });
    let trust_policy_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/verificationTrustPolicy"),
    );
    assert!(trust_policy_validator.is_valid(&verification_trust_policy));
    let trust_selectors_accept_target = |policy: &Value| {
        policy["workspace_id"] == remote_decision["workspace_id"]
            && policy["workspace_id"] == release_result["release_manifest"]["workspace_id"]
            && policy["authority"]["initial_root"] == initial_root
            && policy["authority"]["initial_head"]
                == initial_head_source["evaluated_authority_head"]
            && policy["authority"]["accepted_policy_bundles"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "policy_profile": remote_decision["agent_authorization"]["policy_profile"].clone(),
                    "policy_bundle_digest": remote_decision["agent_authorization"]["policy_bundle_digest"].clone(),
                }))
            && policy["release"]["accepted_predicate_types"]
                .as_array()
                .unwrap()
                .contains(&json!("urn:proof:attestation:release:v2"))
            && policy["release"]["accepted_policy_profiles"]
                .as_array()
                .unwrap()
                .contains(&json!({
                    "policy_profile": "proof.local/release-policy/v1",
                    "environment_config_digest": release_result["release_manifest"]["environment_config_digest"].clone(),
                }))
            && release_signer_resolves(
                policy["release"]["trusted_signers"].as_array().unwrap(),
                &release_result,
            )
            && policy["remote_identity"]["accepted_oidc_issuer_configuration_digests"]
                .as_array()
                .unwrap()
                .contains(&json!(oidc_issuer_configuration_digest.clone()))
            && policy["disclosure"]["requesting_subject_opening"] == "required"
            && policy["limits"] == trust_limits
    };
    assert!(trust_selectors_accept_target(&verification_trust_policy));
    let mut substituted_initial_head = verification_trust_policy.clone();
    substituted_initial_head["authority"]["initial_head"]["record_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(trust_policy_validator.is_valid(&substituted_initial_head));
    assert!(!trust_selectors_accept_target(&substituted_initial_head));
    let mut substituted_nested_policy = verification_trust_policy.clone();
    substituted_nested_policy["authority"]["accepted_policy_bundles"][0]["policy_bundle_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(trust_policy_validator.is_valid(&substituted_nested_policy));
    assert!(!trust_selectors_accept_target(&substituted_nested_policy));
    let mut substituted_oidc_trust = verification_trust_policy.clone();
    substituted_oidc_trust["remote_identity"]["accepted_oidc_issuer_configuration_digests"][0] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(trust_policy_validator.is_valid(&substituted_oidc_trust));
    assert!(!trust_selectors_accept_target(&substituted_oidc_trust));

    let closed_registry_resolver = BTreeMap::from([
        (
            authorization_registry_hash.clone(),
            authorization_registry_bytes.clone(),
        ),
        (
            operation_registry_hash.clone(),
            operation_registry_bytes.clone(),
        ),
    ]);
    let registry_pair_resolves =
        |policy: &Value, selected_decision: &Value, resolver: &BTreeMap<String, Vec<u8>>| {
            let authorization_hash = selected_decision["authorization_registry_sha256"]
                .as_str()
                .unwrap();
            let operation_hash = selected_decision["operation_registry_sha256"]
                .as_str()
                .unwrap();
            let accepted_authorization =
                policy["authority"]["accepted_authorization_registry_hashes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|hash| hash == authorization_hash);
            let accepted_operation = policy["authority"]["accepted_operation_registry_hashes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|hash| hash == operation_hash);
            let (Some(authorization_bytes), Some(operation_bytes)) = (
                resolver.get(authorization_hash),
                resolver.get(operation_hash),
            ) else {
                return false;
            };
            if !accepted_authorization
                || !accepted_operation
                || hex_lower(&sha256(authorization_bytes)) != authorization_hash
                || hex_lower(&sha256(operation_bytes)) != operation_hash
            {
                return false;
            }
            let Ok(resolved_authorization) = parse_strict(authorization_bytes) else {
                return false;
            };
            let Ok(resolved_operation) = parse_strict(operation_bytes) else {
                return false;
            };
            if serde_json_canonicalizer::to_vec(&resolved_authorization)
                .ok()
                .as_ref()
                != Some(authorization_bytes)
                || serde_json_canonicalizer::to_vec(&resolved_operation)
                    .ok()
                    .as_ref()
                    != Some(operation_bytes)
                || resolved_operation["authorization_registry_commitment"]["authorization_registry_sha256"]
                    != authorization_hash
            {
                return false;
            }
            let Some(fields) =
                resolved_operation["authorization_registry_commitment"]["projection_fields"]
                    .as_array()
            else {
                return false;
            };
            let reconstructed_authorization = Value::Object(
                fields
                    .iter()
                    .map(|field| {
                        let field = field.as_str().unwrap();
                        (field.to_owned(), resolved_operation[field].clone())
                    })
                    .collect(),
            );
            reconstructed_authorization == resolved_authorization
        };
    assert!(registry_pair_resolves(
        &verification_trust_policy,
        &remote_decision,
        &closed_registry_resolver,
    ));
    let mut unknown_authorization = remote_decision.clone();
    unknown_authorization["authorization_registry_sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(!registry_pair_resolves(
        &verification_trust_policy,
        &unknown_authorization,
        &closed_registry_resolver,
    ));
    let mut unknown_operation = remote_decision.clone();
    unknown_operation["operation_registry_sha256"] =
        json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(!registry_pair_resolves(
        &verification_trust_policy,
        &unknown_operation,
        &closed_registry_resolver,
    ));
    let mut crossed_registry_document = http_registry.clone();
    crossed_registry_document["authorization_registry_commitment"]["authorization_registry_sha256"] =
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let crossed_registry_bytes =
        serde_json_canonicalizer::to_vec(&crossed_registry_document).unwrap();
    let crossed_registry_hash = hex_lower(&sha256(&crossed_registry_bytes));
    let mut cross_allowlisted_policy = verification_trust_policy.clone();
    cross_allowlisted_policy["authority"]["accepted_operation_registry_hashes"]
        .as_array_mut()
        .unwrap()
        .push(json!(crossed_registry_hash.clone()));
    cross_allowlisted_policy["authority"]["accepted_authorization_registry_hashes"]
        .as_array_mut()
        .unwrap()
        .push(json!(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    let mut crossed_resolver = closed_registry_resolver.clone();
    crossed_resolver.insert(crossed_registry_hash.clone(), crossed_registry_bytes);
    let mut crossed_decision = remote_decision.clone();
    crossed_decision["operation_registry_sha256"] = json!(crossed_registry_hash);
    assert!(trust_policy_validator.is_valid(&cross_allowlisted_policy));
    assert!(
        !registry_pair_resolves(
            &cross_allowlisted_policy,
            &crossed_decision,
            &crossed_resolver,
        ),
        "independently allowlisted registry hashes cannot be paired across versions"
    );
    let mut producer_substitution = closed_registry_resolver.clone();
    let mut producer_registry = http_registry.clone();
    producer_registry["api_version"] = json!("proof.dev/http-operation-registry/v2");
    producer_substitution.insert(
        operation_registry_hash.clone(),
        serde_json_canonicalizer::to_vec(&producer_registry).unwrap(),
    );
    assert!(
        !registry_pair_resolves(
            &verification_trust_policy,
            &remote_decision,
            &producer_substitution,
        ),
        "producer bytes cannot replace the verifier-owned document under an accepted hash label"
    );

    let subject_opening = parse_file(&collaboration_path(
        "vectors/oidc-subject-commitment-opening.private-test.json",
    ));
    assert_eq!(
        subject_opening["commitment"],
        remote_decision["requesting_subject_commitment"]
    );
    let verification_trust_policy_digest = canonical_digest(
        "proof:verification-trust-policy:v2",
        &verification_trust_policy,
    );
    let remote_verifier_input = json!({
        "type": "RemoteVerifierInputV2",
        "api_version": "proof.dev/remote-verifier-input/v2",
        "verification_trust_policy": verification_trust_policy.clone(),
        "trust_policy_digest": verification_trust_policy_digest.clone(),
        "subject_openings": [subject_opening],
        "authority_checkpoint": caller_authority_checkpoint,
        "environment_release_checkpoint": null,
        "external_artifacts": [],
        "bundle_hints_are_authority": false,
        "network_access": false,
        "database_access": false,
        "session_access": false,
        "private_key_count": 0,
        "credential_count": 0,
    });
    let verifier_input_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/verifierInput"),
    );
    assert!(verifier_input_validator.is_valid(&remote_verifier_input));
    let remote_verifier_input_digest =
        canonical_digest("proof:remote-verifier-input:v2", &remote_verifier_input);
    let remote_verifier_input_bytes =
        serde_json_canonicalizer::to_vec(&remote_verifier_input).unwrap();
    let raw_remote_verifier_input_digest = raw_digest(
        "proof:remote-verifier-input-raw:v1",
        &remote_verifier_input_bytes,
    );
    let remote_attempt_companions = json!({
        "profile": "agent-release-create-v2-success",
        "actor_context_evidence": {
            "member_path": "actor/context-evidence.json",
            "record_digest": actor_evidence_digest,
            "digest_context": "proof:authenticated-actor-context-evidence:v2",
            "schema_id": "proof.authenticated-actor-context-evidence/v2",
            "schema_version": 2,
        },
        "authentication_event": {
            "member_path": "authentication/event.json",
            "record_digest": authentication_event_digest,
            "digest_context": "proof:remote-authentication-event:v1",
            "schema_id": "proof.remote-authentication-event/v1",
            "schema_version": 1,
        },
        "command_input": {
            "member_path": "attempt/command-input.json",
            "record_digest": remote_decision["agent_authorization"]["command_digest"].clone(),
            "digest_context": "proof:command:v1",
            "schema_id": "proof.command-input/v1",
            "schema_version": 1,
        },
        "authenticated_command_envelope": {
            "member_path": "attempt/authenticated-command-envelope.json",
            "record_digest": remote_decision["agent_authorization"]["command_envelope_digest"].clone(),
            "digest_context": "proof:authenticated-command-envelope:v1",
            "schema_id": "proof.authenticated-command-envelope/v1",
            "schema_version": 1,
        },
    });
    let remote_attempt_companions_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/remoteAttemptCompanionsV1"),
    );
    assert!(remote_attempt_companions_validator.is_valid(&remote_attempt_companions));
    assert_eq!(
        remote_attempt_companions["actor_context_evidence"]["record_digest"],
        remote_decision["actor_context_digest"]
    );
    assert_eq!(
        remote_attempt_companions["authentication_event"]["record_digest"],
        actor_evidence["authentication_event_digest"]
    );
    assert_eq!(
        remote_attempt_companions["command_input"]["record_digest"],
        remote_decision["agent_authorization"]["command_digest"],
        "the cross-link command_digest binds exact CommandInputV1 bytes"
    );
    assert_ne!(
        remote_attempt_companions["command_input"]["record_digest"],
        remote_attempt_companions["authenticated_command_envelope"]["record_digest"],
        "the command preimage digest is not the DSSE envelope digest"
    );

    let mut invented_command_payload_binding = remote_attempt_companions.clone();
    invented_command_payload_binding["command_input"]["digest_context"] =
        json!("proof:authenticated-command:v1");
    assert!(
        !remote_attempt_companions_validator.is_valid(&invented_command_payload_binding),
        "the attempt companion must bind CommandInputV1 under proof:command:v1, not an invented standalone AuthenticatedCommandV1 digest"
    );

    let member_validator = validator(&registry, &format!("{evidence_schema_id}#/$defs/member"));
    let command_input_member = json!({
        "member_path": "attempt/command-input.json",
        "artifact_kind": "remote-command-input",
        "schema_id": "proof.command-input/v1",
        "schema_version": 1,
        "media_type": "application/json",
        "canonicalization": "RFC8785",
        "digest_context": "proof:command:v1",
        "byte_length": 1,
        "content_digest": remote_attempt_companions["command_input"]["record_digest"].clone(),
        "delivery": "included",
        "disclosure_id": null,
    });
    assert!(member_validator.is_valid(&command_input_member));
    let mut invented_standalone_payload_member = command_input_member.clone();
    invented_standalone_payload_member["artifact_kind"] =
        json!("remote-authenticated-command-payload");
    invented_standalone_payload_member["schema_id"] = json!("proof.authenticated-command/v1");
    invented_standalone_payload_member["digest_context"] = json!("proof:authenticated-command:v1");
    assert!(
        !member_validator.is_valid(&invented_standalone_payload_member),
        "the outer inventory cannot add a standalone authenticated-command payload member"
    );

    let included_member = |member_path: &str,
                           artifact_kind: &str,
                           schema_id: &str,
                           schema_version: u64,
                           digest_context: &str,
                           content_digest: Value| {
        json!({
            "member_path": member_path,
            "artifact_kind": artifact_kind,
            "schema_id": schema_id,
            "schema_version": schema_version,
            "media_type": "application/json",
            "canonicalization": "RFC8785",
            "digest_context": digest_context,
            "byte_length": 1,
            "content_digest": content_digest,
            "delivery": "included",
            "disclosure_id": null,
        })
    };
    let root_membership = json!([
        included_member(
            "actor/context-evidence.json",
            "remote-actor-evidence",
            "proof.authenticated-actor-context-evidence/v2",
            2,
            "proof:authenticated-actor-context-evidence:v2",
            remote_attempt_companions["actor_context_evidence"]["record_digest"].clone(),
        ),
        included_member(
            "attempt/authenticated-command-envelope.json",
            "remote-authenticated-command-envelope",
            "proof.authenticated-command-envelope/v1",
            1,
            "proof:authenticated-command-envelope:v1",
            remote_attempt_companions["authenticated_command_envelope"]["record_digest"].clone(),
        ),
        command_input_member.clone(),
        included_member(
            "authentication/event.json",
            "remote-authentication-event",
            "proof.remote-authentication-event/v1",
            1,
            "proof:remote-authentication-event:v1",
            remote_attempt_companions["authentication_event"]["record_digest"].clone(),
        ),
        included_member(
            "authority/facts.json",
            "authority-fact",
            "proof.remote-authority-record-set/v1",
            1,
            "proof:remote-authority-record-set:v1",
            json!("blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ),
        included_member(
            "content/release-closure.json",
            "release-artifact-closure",
            "proof.remote-release-artifact-closure/v1",
            1,
            "proof:remote-release-artifact-closure:v1",
            json!("blake3:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        ),
    ]);
    let root_membership_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/rootMembership"),
    );
    assert!(root_membership_validator.is_valid(&root_membership));
    assert!(
        root_membership
            .as_array()
            .unwrap()
            .windows(2)
            .all(|pair| pair[0]["member_path"].as_str() < pair[1]["member_path"].as_str())
    );
    let mut missing_root = root_membership.clone();
    missing_root.as_array_mut().unwrap().pop();
    assert!(!root_membership_validator.is_valid(&missing_root));
    let mut extra_root = root_membership.clone();
    extra_root
        .as_array_mut()
        .unwrap()
        .push(root_membership[0].clone());
    assert!(!root_membership_validator.is_valid(&extra_root));
    let mut duplicate_kind = root_membership.clone();
    duplicate_kind[5] = duplicate_kind[4].clone();
    assert!(!root_membership_validator.is_valid(&duplicate_kind));
    let mut wrong_fixed_path = root_membership.clone();
    wrong_fixed_path[0]["member_path"] = json!("actor/alternate.json");
    assert!(!root_membership_validator.is_valid(&wrong_fixed_path));

    let mut mixed_root_membership = root_membership.clone();
    mixed_root_membership[0]["delivery"] = json!("external-required");
    mixed_root_membership[0]["disclosure_id"] = json!("disclosure:actor-context");
    assert!(
        root_membership_validator.is_valid(&mixed_root_membership),
        "the explicit-external profile may withhold an allowed root while retaining its descriptor"
    );

    let disclosure_requirement_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/disclosureRequirement"),
    );
    let captured_disclosures = json!([
        {
            "disclosure_id": "disclosure:actor-context",
            "kind": "artifact-bytes",
            "commitment_digest": mixed_root_membership[0]["content_digest"].clone(),
        },
        {
            "disclosure_id": "disclosure:oidc-subject-opening",
            "kind": "oidc-subject-opening",
            "commitment_digest": remote_decision["requesting_subject_commitment"].clone(),
        },
    ]);
    assert!(
        captured_disclosures
            .as_array()
            .unwrap()
            .iter()
            .all(|requirement| disclosure_requirement_validator.is_valid(requirement))
    );
    let disclosure_plan_is_closed =
        |membership: &Value, disclosures: &Value, target_commitment: &Value| {
            let Some(members) = membership.as_array() else {
                return false;
            };
            let Some(requirements) = disclosures.as_array() else {
                return false;
            };
            let ids = requirements
                .iter()
                .filter_map(|requirement| requirement["disclosure_id"].as_str())
                .collect::<Vec<_>>();
            if ids.len() != requirements.len()
                || ids.windows(2).any(|pair| pair[0] >= pair[1])
                || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len()
            {
                return false;
            }

            let oidc_requirements = requirements
                .iter()
                .filter(|requirement| requirement["kind"] == "oidc-subject-opening")
                .collect::<Vec<_>>();
            if oidc_requirements.len() != 1
                || oidc_requirements[0]["commitment_digest"] != *target_commitment
            {
                return false;
            }

            let external_members = members
                .iter()
                .filter(|member| member["delivery"] == "external-required")
                .collect::<Vec<_>>();
            external_members.iter().all(|member| {
                requirements
                    .iter()
                    .filter(|requirement| {
                        requirement["kind"] == "artifact-bytes"
                            && requirement["disclosure_id"] == member["disclosure_id"]
                            && requirement["commitment_digest"] == member["content_digest"]
                    })
                    .count()
                    == 1
            }) && requirements
                .iter()
                .filter(|requirement| requirement["kind"] == "artifact-bytes")
                .all(|requirement| {
                    external_members
                        .iter()
                        .filter(|member| {
                            member["disclosure_id"] == requirement["disclosure_id"]
                                && member["content_digest"] == requirement["commitment_digest"]
                        })
                        .count()
                        == 1
                })
        };
    let manifest_disclosures = captured_disclosures.clone();
    for (projection, disclosures) in [
        ("capture", &captured_disclosures),
        ("manifest", &manifest_disclosures),
    ] {
        assert!(
            disclosure_plan_is_closed(
                &mixed_root_membership,
                disclosures,
                &remote_decision["requesting_subject_commitment"],
            ),
            "the {projection} projection closes the external-root bijection and target opening"
        );
    }
    let mut omitted_oidc = captured_disclosures.clone();
    omitted_oidc.as_array_mut().unwrap().pop();
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &omitted_oidc,
        &remote_decision["requesting_subject_commitment"],
    ));
    let mut duplicate_oidc = captured_disclosures.clone();
    duplicate_oidc.as_array_mut().unwrap().push(json!({
        "disclosure_id": "disclosure:oidc-subject-opening-two",
        "kind": "oidc-subject-opening",
        "commitment_digest": remote_decision["requesting_subject_commitment"].clone(),
    }));
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &duplicate_oidc,
        &remote_decision["requesting_subject_commitment"],
    ));
    let mut wrong_disclosure_kind = captured_disclosures.clone();
    wrong_disclosure_kind[0]["kind"] = json!("oidc-subject-opening");
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &wrong_disclosure_kind,
        &remote_decision["requesting_subject_commitment"],
    ));
    let mut wrong_opening_commitment = captured_disclosures.clone();
    wrong_opening_commitment[1]["commitment_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &wrong_opening_commitment,
        &remote_decision["requesting_subject_commitment"],
    ));
    let mut unselected_artifact_disclosure = captured_disclosures.clone();
    unselected_artifact_disclosure
        .as_array_mut()
        .unwrap()
        .push(json!({
            "disclosure_id": "disclosure:extra-artifact",
            "kind": "artifact-bytes",
            "commitment_digest": "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }));
    unselected_artifact_disclosure
        .as_array_mut()
        .unwrap()
        .sort_by(|left, right| {
            left["disclosure_id"]
                .as_str()
                .cmp(&right["disclosure_id"].as_str())
        });
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &unselected_artifact_disclosure,
        &remote_decision["requesting_subject_commitment"],
    ));
    let mut omitted_external_disclosure = captured_disclosures.clone();
    omitted_external_disclosure
        .as_array_mut()
        .unwrap()
        .remove(0);
    assert!(!disclosure_plan_is_closed(
        &mixed_root_membership,
        &omitted_external_disclosure,
        &remote_decision["requesting_subject_commitment"],
    ));

    let nested_members = release_artifact_closure["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|descriptor| {
            let artifact = &descriptor["artifact"];
            assert_eq!(descriptor["availability"]["state"], "included");
            (
                artifact["artifact_kind"].as_str().unwrap().to_owned(),
                artifact["digest"].as_str().unwrap().to_owned(),
                format!(
                    "content/artifacts/{}/blake3/{}.json",
                    artifact["artifact_kind"].as_str().unwrap(),
                    artifact["digest"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("blake3:")
                        .unwrap()
                ),
                descriptor["availability"]["byte_length"].as_u64().unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let bundle_digest = "blake3:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let manifest_digest = "blake3:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let mut acquisition_graph = BTreeMap::<(String, String), (String, u64)>::new();
    assert!(
        acquisition_graph
            .insert(
                (
                    "remote_evidence_bundle_v2".to_owned(),
                    bundle_digest.to_owned(),
                ),
                ("bundle.json".to_owned(), 1),
            )
            .is_none()
    );
    assert!(
        acquisition_graph
            .insert(
                (
                    "remote_evidence_manifest_v2".to_owned(),
                    manifest_digest.to_owned(),
                ),
                ("manifest.json".to_owned(), 1),
            )
            .is_none()
    );
    for member in mixed_root_membership
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["delivery"] == "included")
    {
        assert!(
            acquisition_graph
                .insert(
                    (
                        member["artifact_kind"].as_str().unwrap().to_owned(),
                        member["content_digest"].as_str().unwrap().to_owned(),
                    ),
                    (
                        member["member_path"].as_str().unwrap().to_owned(),
                        member["byte_length"].as_u64().unwrap(),
                    ),
                )
                .is_none(),
            "an included root selector must be unique"
        );
    }
    for (artifact_kind, digest, member_path, byte_length) in &nested_members {
        assert!(
            acquisition_graph
                .insert(
                    (artifact_kind.clone(), digest.clone()),
                    (member_path.clone(), *byte_length),
                )
                .is_none(),
            "a nested ArtifactRef selector must be unique"
        );
    }

    let external_root = &mixed_root_membership[0];
    let external_selector = (
        external_root["artifact_kind"].as_str().unwrap().to_owned(),
        external_root["content_digest"].as_str().unwrap().to_owned(),
    );
    assert!(
        !acquisition_graph.contains_key(&external_selector),
        "an external-required root remains a caller-input obligation and never resolves through producer GET"
    );
    assert!(
        !acquisition_graph.contains_key(&(
            "remote_evidence_manifest_v2".to_owned(),
            bundle_digest.to_owned(),
        )),
        "the same digest under the wrong kind is not an acquisition alias"
    );
    assert!(
        !acquisition_graph.contains_key(&(
            "release_v2".to_owned(),
            "blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned(),
        )),
        "an unlisted selector never resolves"
    );

    let artifact_count = acquisition_graph.len() - 2;
    let included_root_count = mixed_root_membership
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["delivery"] == "included")
        .count();
    assert_eq!(artifact_count, included_root_count + nested_members.len());
    assert_eq!(artifact_count, 8);
    assert_eq!(acquisition_graph.len(), artifact_count + 2);
    let total_included_bytes = acquisition_graph
        .values()
        .map(|(_, byte_length)| *byte_length)
        .sum::<u64>();
    let mixed_ready_status = json!({
        "api_version": "proof.dev/evidence-export-status/v1",
        "export_id": "019e1234-5678-7abc-8def-000000000091",
        "status": "ready",
        "capture_digest": "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bundle_descriptor_digest": bundle_digest,
        "manifest_digest": manifest_digest,
        "artifact_count": artifact_count,
        "total_included_bytes": total_included_bytes,
    });
    let status_validator = validator(
        &registry,
        &format!("{APPLICATION_SCHEMA_ID}#/$defs/evidenceExportStatusV1"),
    );
    assert!(status_validator.is_valid(&mixed_ready_status));

    let untrusted_hints_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/bundle/properties/untrusted_hints"),
    );
    let frozen_untrusted_hints = json!({
        "authority_root_ids": [],
        "release_root_ids": [],
        "checkpoint_ids": [],
        "resolver_urls": [],
        "trusted": false,
        "auto_fetch": false,
    });
    assert!(untrusted_hints_validator.is_valid(&frozen_untrusted_hints));
    let mut drifted_descriptor_hints = frozen_untrusted_hints.clone();
    drifted_descriptor_hints["authority_root_ids"] =
        json!([format!("key:{}", initial_root["key_id"].as_str().unwrap())]);
    assert!(
        !untrusted_hints_validator.is_valid(&drifted_descriptor_hints),
        "the first v2 profile has one deterministic const-empty producer-hint projection"
    );

    let lifecycle_build_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/exportLifecycle/properties/build"),
    );
    let lifecycle_ready_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/exportLifecycle/properties/ready"),
    );
    let lifecycle_build = json!({
        "runs_outside_capture_transaction": true,
        "input_scope": "captured-membership-only",
        "deterministic": true,
        "bundle_descriptor_digest": mixed_ready_status["bundle_descriptor_digest"].clone(),
        "manifest_digest": mixed_ready_status["manifest_digest"].clone(),
        "artifact_count": mixed_ready_status["artifact_count"].clone(),
        "total_included_bytes": mixed_ready_status["total_included_bytes"].clone(),
        "built_at": "2026-08-23T03:30:00.100Z",
        "state_after_build": "pending",
    });
    let lifecycle_ready = json!({
        "transaction_isolation": "SERIALIZABLE READ WRITE",
        "manifest_verified": true,
        "exact_bytes_verified": true,
        "captured_membership_only": true,
        "bundle_descriptor_digest": mixed_ready_status["bundle_descriptor_digest"].clone(),
        "manifest_digest": mixed_ready_status["manifest_digest"].clone(),
        "artifact_count": mixed_ready_status["artifact_count"].clone(),
        "total_included_bytes": mixed_ready_status["total_included_bytes"].clone(),
        "transition": "pending-to-ready",
        "ready_at": "2026-08-23T03:30:00.200Z",
    });
    assert!(lifecycle_build_validator.is_valid(&lifecycle_build));
    assert!(lifecycle_ready_validator.is_valid(&lifecycle_ready));
    let lifecycle_outputs_match =
        |captured_at: &str, build: &Value, ready: &Value, status: &Value| {
            let captured_at = OffsetDateTime::parse(captured_at, &Rfc3339).unwrap();
            let built_at = parse_instant(&build["built_at"]);
            let ready_at = parse_instant(&ready["ready_at"]);
            captured_at <= built_at
                && built_at <= ready_at
                && status["status"] == "ready"
                && [
                    "bundle_descriptor_digest",
                    "manifest_digest",
                    "artifact_count",
                    "total_included_bytes",
                ]
                .into_iter()
                .all(|field| build[field] == ready[field] && ready[field] == status[field])
        };
    assert!(lifecycle_outputs_match(
        "2026-08-23T03:30:00Z",
        &lifecycle_build,
        &lifecycle_ready,
        &mixed_ready_status,
    ));
    let mut stale_ready_digest = lifecycle_ready.clone();
    stale_ready_digest["bundle_descriptor_digest"] =
        json!("blake3:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert!(lifecycle_ready_validator.is_valid(&stale_ready_digest));
    assert!(
        !lifecycle_outputs_match(
            "2026-08-23T03:30:00Z",
            &lifecycle_build,
            &stale_ready_digest,
            &mixed_ready_status,
        ),
        "ready cannot publish a stale or substituted build output"
    );
    let mut reversed_ready_time = lifecycle_ready.clone();
    reversed_ready_time["ready_at"] = json!("2026-08-23T03:29:59.999Z");
    assert!(lifecycle_ready_validator.is_valid(&reversed_ready_time));
    assert!(
        !lifecycle_outputs_match(
            "2026-08-23T03:30:00Z",
            &lifecycle_build,
            &reversed_ready_time,
            &mixed_ready_status,
        ),
        "capture, build, and readiness timestamps are compared as instants in causal order"
    );

    let expected_logical_paths = acquisition_graph
        .values()
        .map(|(path, _)| path.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        expected_logical_paths.len(),
        artifact_count + 2,
        "the status count plus two reserved entries equals the exact producer-addressable member graph"
    );
    assert_eq!(
        expected_logical_paths.len(),
        acquisition_graph.len(),
        "every eligible selector resolves exactly one unique logical member path"
    );
    let mut logical_entries = acquisition_graph
        .values()
        .map(|(path, byte_length)| (path.clone(), *byte_length, *byte_length))
        .collect::<Vec<_>>();
    logical_entries.sort_by(|left, right| left.0.cmp(&right.0));
    let logical_member_set_is_accepted =
        |entries: &[(String, u64, u64)], max_artifact_bytes: u64, max_total_bytes: u64| {
            if entries.len() != expected_logical_paths.len() || entries.len() > 4098 {
                return false;
            }
            let mut seen = BTreeSet::new();
            let mut total = 0_u64;
            let mut prior_path: Option<&str> = None;
            for (path, declared_length, observed_length) in entries {
                let safe_path = !path.is_empty()
                    && !path.starts_with('/')
                    && !path.contains('\\')
                    && path
                        .split('/')
                        .all(|segment| !segment.is_empty() && segment != "." && segment != "..");
                if !safe_path
                    || prior_path.is_some_and(|prior| prior >= path.as_str())
                    || declared_length != observed_length
                    || *declared_length > max_artifact_bytes
                    || !expected_logical_paths.contains(path)
                    || !seen.insert(path.clone())
                {
                    return false;
                }
                let Some(next_total) = total.checked_add(*observed_length) else {
                    return false;
                };
                if next_total > max_total_bytes {
                    return false;
                }
                total = next_total;
                prior_path = Some(path);
            }
            seen == expected_logical_paths
        };
    let logical_total = logical_entries
        .iter()
        .map(|(_, _, observed_length)| *observed_length)
        .sum::<u64>();
    assert_eq!(logical_total, total_included_bytes);
    assert_eq!(
        mixed_ready_status["total_included_bytes"].as_u64(),
        Some(logical_total)
    );
    assert!(logical_member_set_is_accepted(
        &logical_entries,
        4_194_304,
        logical_total,
    ));
    let mut duplicate_logical_path = logical_entries.clone();
    duplicate_logical_path.push(logical_entries[0].clone());
    duplicate_logical_path.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!logical_member_set_is_accepted(
        &duplicate_logical_path,
        4_194_304,
        u64::MAX,
    ));
    let mut unsafe_logical_path = logical_entries.clone();
    unsafe_logical_path[0].0 = "../bundle.json".to_owned();
    unsafe_logical_path.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!logical_member_set_is_accepted(
        &unsafe_logical_path,
        4_194_304,
        u64::MAX,
    ));
    let mut undeclared_logical_path = logical_entries.clone();
    undeclared_logical_path[0].0 = "extra.json".to_owned();
    undeclared_logical_path.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(!logical_member_set_is_accepted(
        &undeclared_logical_path,
        4_194_304,
        u64::MAX,
    ));
    let mut missing_logical_path = logical_entries.clone();
    missing_logical_path.pop();
    assert!(!logical_member_set_is_accepted(
        &missing_logical_path,
        4_194_304,
        u64::MAX,
    ));
    let mut length_mismatch = logical_entries.clone();
    length_mismatch[0].2 = 2;
    assert!(!logical_member_set_is_accepted(
        &length_mismatch,
        4_194_304,
        u64::MAX,
    ));
    let mut oversized_member = logical_entries.clone();
    oversized_member[0].1 = 4_194_305;
    oversized_member[0].2 = 4_194_305;
    assert!(!logical_member_set_is_accepted(
        &oversized_member,
        4_194_304,
        u64::MAX,
    ));
    assert!(!logical_member_set_is_accepted(
        &logical_entries,
        4_194_304,
        logical_total - 1,
    ));

    let report_validator = validator(&registry, &format!("{evidence_schema_id}#/$defs/report"));
    let conformance_report_validator = validator(
        &registry,
        &format!("{evidence_schema_id}#/$defs/conformanceReport"),
    );
    let verified_components = json!({
        "signature": "verified",
        "actor": "verified",
        "authority": "verified",
        "role_separation": "verified",
        "approval": "verified",
        "policy": "verified",
        "content": "verified",
        "environment": "verified",
        "release": "verified",
        "delivery_evidence": "not-requested",
        "completeness": "verified",
    });
    let report_base = json!({
        "type": "RemoteVerificationReportV2",
        "api_version": "proof.dev/remote-verification-report/v2",
        "claim_kind": "observed-verifier-outcome",
        "runtime_observed": true,
        "execution_id": "execution_0000000000000001",
        "observed_at": "2026-08-23T04:00:00Z",
        "verifier_profile": "proof-verifier/remote-evidence-v2",
        "report_id": "report_0000000000000001",
        "scenario": "complete-exact-materialization",
        "status": "Complete",
        "snapshot_scope": "verified-inner-claim-only; producer export and snapshot metadata unauthenticated",
        "raw_verifier_input_digest": raw_remote_verifier_input_digest.clone(),
        "raw_bundle_descriptor_digest": "blake3:0202020202020202020202020202020202020202020202020202020202020202",
        "raw_bundle_manifest_digest": "blake3:0303030303030303030303030303030303030303030303030303030303030303",
        "bundle_manifest_digest": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
        "verifier_input_digest": remote_verifier_input_digest.clone(),
        "trust_policy_digest": verification_trust_policy_digest.clone(),
        "authority_checkpoint_digest": canonical_digest(
            "proof:authority-checkpoint:v1",
            &caller_authority_checkpoint,
        ),
        "environment_release_checkpoint_digest": null,
        "components": verified_components.clone(),
        "reason_codes": ["verified"],
    });
    assert_eq!(
        evidence_schema
            .pointer("/$defs/authorityCheckpoint/x-proof-digest-context")
            .and_then(Value::as_str),
        Some("proof:authority-checkpoint:v1")
    );
    assert_eq!(
        evidence_schema
            .pointer("/$defs/environmentReleaseCheckpoint/x-proof-digest-context")
            .and_then(Value::as_str),
        Some("proof:environment-release-checkpoint:v2")
    );
    let authority_checkpoint = caller_authority_checkpoint.clone();
    let environment_release_checkpoint = json!({
        "api_version": "proof.dev/environment-release-checkpoint/v2",
        "workspace_id": release_result["release_manifest"]["workspace_id"].clone(),
        "environment_id": release_result["release_manifest"]["environment_id"].clone(),
        "environment_config_digest": release_result["release_manifest"]["environment_config_digest"].clone(),
        "environment_config_version": release_result["release_manifest"]["environment_config_version"].clone(),
        "release_id": release_result["release_id"].clone(),
        "release_digest": release_result["release_digest"].clone(),
        "observed_at": "2026-08-23T03:10:02Z",
    });
    assert!(
        validator(
            &registry,
            &format!("{evidence_schema_id}#/$defs/authorityCheckpoint"),
        )
        .is_valid(&authority_checkpoint)
    );
    assert!(
        validator(
            &registry,
            &format!("{evidence_schema_id}#/$defs/environmentReleaseCheckpoint"),
        )
        .is_valid(&environment_release_checkpoint)
    );
    let report_checkpoints_match = |exact_input: &Value, report: &Value| {
        let authority_digest = if exact_input["authority_checkpoint"].is_null() {
            Value::Null
        } else {
            json!(canonical_digest(
                "proof:authority-checkpoint:v1",
                &exact_input["authority_checkpoint"],
            ))
        };
        let environment_digest = if exact_input["environment_release_checkpoint"].is_null() {
            Value::Null
        } else {
            json!(canonical_digest(
                "proof:environment-release-checkpoint:v2",
                &exact_input["environment_release_checkpoint"],
            ))
        };
        report["authority_checkpoint_digest"] == authority_digest
            && report["environment_release_checkpoint_digest"] == environment_digest
    };
    let null_checkpoint_input = json!({
        "authority_checkpoint": null,
        "environment_release_checkpoint": null,
    });
    let mut null_checkpoint_report = report_base.clone();
    null_checkpoint_report["authority_checkpoint_digest"] = Value::Null;
    assert!(report_checkpoints_match(
        &null_checkpoint_input,
        &null_checkpoint_report,
    ));
    let exact_checkpoint_input = json!({
        "authority_checkpoint": authority_checkpoint.clone(),
        "environment_release_checkpoint": environment_release_checkpoint.clone(),
    });
    let mut checkpoint_bound_report = report_base.clone();
    checkpoint_bound_report["authority_checkpoint_digest"] = json!(canonical_digest(
        "proof:authority-checkpoint:v1",
        &authority_checkpoint,
    ));
    checkpoint_bound_report["environment_release_checkpoint_digest"] = json!(canonical_digest(
        "proof:environment-release-checkpoint:v2",
        &environment_release_checkpoint,
    ));
    assert!(report_validator.is_valid(&checkpoint_bound_report));
    assert!(report_checkpoints_match(
        &exact_checkpoint_input,
        &checkpoint_bound_report,
    ));
    assert!(
        !report_checkpoints_match(&exact_checkpoint_input, &null_checkpoint_report),
        "nonnull exact checkpoints cannot be reported as null"
    );
    assert!(
        !report_checkpoints_match(&null_checkpoint_input, &checkpoint_bound_report),
        "a report cannot invent checkpoint digests for null exact inputs"
    );
    let mut changed_authority_checkpoint_input = exact_checkpoint_input.clone();
    changed_authority_checkpoint_input["authority_checkpoint"]["observed_at"] =
        json!("2026-08-23T03:10:03Z");
    assert!(
        !report_checkpoints_match(
            &changed_authority_checkpoint_input,
            &checkpoint_bound_report,
        ),
        "changing exact authority checkpoint bytes invalidates a stale report digest"
    );
    let mut changed_environment_checkpoint_input = exact_checkpoint_input.clone();
    changed_environment_checkpoint_input["environment_release_checkpoint"]["release_digest"] =
        json!("blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(
        !report_checkpoints_match(
            &changed_environment_checkpoint_input,
            &checkpoint_bound_report,
        ),
        "changing exact Environment checkpoint bytes invalidates a stale report digest"
    );
    let mut wrong_environment_domain_report = checkpoint_bound_report.clone();
    wrong_environment_domain_report["environment_release_checkpoint_digest"] =
        json!(canonical_digest(
            "proof:environment-release-checkpoint:v1",
            &environment_release_checkpoint,
        ));
    assert!(
        !report_checkpoints_match(&exact_checkpoint_input, &wrong_environment_domain_report,),
        "the Environment checkpoint cannot be substituted under the v1 digest domain"
    );
    let complete_report = report_base.clone();
    let mut incomplete_report = report_base.clone();
    incomplete_report["execution_id"] = json!("execution_0000000000000002");
    incomplete_report["report_id"] = json!("report_0000000000000002");
    incomplete_report["scenario"] = json!("incomplete-required-opening-withheld");
    incomplete_report["status"] = json!("Incomplete");
    incomplete_report["components"]["actor"] = json!("missing");
    incomplete_report["components"]["completeness"] = json!("missing");
    incomplete_report["reason_codes"] = json!(["missing-disclosure"]);
    let mut invalid_report = report_base.clone();
    invalid_report["execution_id"] = json!("execution_0000000000000003");
    invalid_report["report_id"] = json!("report_0000000000000003");
    invalid_report["scenario"] = json!("invalid-content-artifact-byte-tamper");
    invalid_report["status"] = json!("Invalid");
    invalid_report["components"]["content"] = json!("invalid");
    invalid_report["reason_codes"] = json!(["tampered-artifact"]);
    let observed_reports = [complete_report, incomplete_report, invalid_report];
    assert!(
        observed_reports
            .iter()
            .all(|report| report_validator.is_valid(report))
    );
    assert!(
        observed_reports
            .iter()
            .all(|report| conformance_report_validator.is_valid(report))
    );
    assert_eq!(
        observed_reports
            .iter()
            .map(|report| {
                (
                    report["scenario"].as_str().unwrap(),
                    report["status"].as_str().unwrap(),
                )
            })
            .collect::<Vec<_>>(),
        [
            ("complete-exact-materialization", "Complete"),
            ("incomplete-required-opening-withheld", "Incomplete"),
            ("invalid-content-artifact-byte-tamper", "Invalid"),
        ]
    );
    assert!(observed_reports.iter().all(|report| {
        report["claim_kind"] == "observed-verifier-outcome"
            && report["runtime_observed"].as_bool() == Some(true)
    }));
    let mut normative_report = observed_reports[0].clone();
    normative_report["claim_kind"] = json!("normative-successor-requirement");
    normative_report["runtime_observed"] = json!(false);
    assert!(!report_validator.is_valid(&normative_report));
    let mut mismatched_report_scenario = observed_reports[0].clone();
    mismatched_report_scenario["scenario"] = json!("invalid-verification");
    assert!(!report_validator.is_valid(&mismatched_report_scenario));
    let mut delivery_overclaim = observed_reports[0].clone();
    delivery_overclaim["components"]["delivery_evidence"] = json!("verified");
    assert!(!report_validator.is_valid(&delivery_overclaim));
    let mut misleading_incomplete_reason = observed_reports[1].clone();
    misleading_incomplete_reason["reason_codes"] = json!(["missing-artifact"]);
    assert!(!report_validator.is_valid(&misleading_incomplete_reason));
    let mut misleading_invalid_reason = observed_reports[2].clone();
    misleading_invalid_reason["reason_codes"] = json!(["invalid-signature"]);
    assert!(!report_validator.is_valid(&misleading_invalid_reason));
    let mut opening_without_typed_identity = observed_reports[1].clone();
    opening_without_typed_identity["verifier_input_digest"] = Value::Null;
    assert!(
        !report_validator.is_valid(&opening_without_typed_identity),
        "a post-parse opening outcome must retain every applicable typed identity"
    );
    let mut tamper_without_raw_identity = observed_reports[2].clone();
    tamper_without_raw_identity["raw_bundle_manifest_digest"] = Value::Null;
    assert!(
        !report_validator.is_valid(&tamper_without_raw_identity),
        "the content-tamper scenario must identify the exact received manifest bytes"
    );

    let oversized_raw_input = vec![0x41_u8; 64];
    let mut preparse_limit_report = report_base.clone();
    preparse_limit_report["execution_id"] = json!("execution_0000000000000005");
    preparse_limit_report["report_id"] = json!("report_0000000000000005");
    preparse_limit_report["scenario"] = json!("invalid-verification");
    preparse_limit_report["status"] = json!("Invalid");
    preparse_limit_report["raw_verifier_input_digest"] = json!(raw_digest(
        "proof:remote-verifier-input-raw:v1",
        &oversized_raw_input,
    ));
    preparse_limit_report["raw_bundle_descriptor_digest"] = Value::Null;
    preparse_limit_report["raw_bundle_manifest_digest"] = Value::Null;
    preparse_limit_report["bundle_manifest_digest"] = Value::Null;
    preparse_limit_report["verifier_input_digest"] = Value::Null;
    preparse_limit_report["trust_policy_digest"] = Value::Null;
    preparse_limit_report["components"]["completeness"] = json!("invalid");
    preparse_limit_report["reason_codes"] = json!(["invalid-limit"]);
    assert!(
        report_validator.is_valid(&preparse_limit_report),
        "an oversized raw input remains reportable without inventing typed canonical digests"
    );
    assert_eq!(
        preparse_limit_report["raw_verifier_input_digest"],
        raw_digest("proof:remote-verifier-input-raw:v1", &oversized_raw_input,)
    );

    let malformed_manifest_bytes = br#"{"type":"RemoteEvidenceManifestV2","type":"duplicate"}"#;
    let mut malformed_manifest_report = report_base.clone();
    malformed_manifest_report["execution_id"] = json!("execution_0000000000000006");
    malformed_manifest_report["report_id"] = json!("report_0000000000000006");
    malformed_manifest_report["scenario"] = json!("invalid-verification");
    malformed_manifest_report["status"] = json!("Invalid");
    malformed_manifest_report["raw_bundle_manifest_digest"] = json!(raw_digest(
        "proof:remote-evidence-manifest-raw:v1",
        malformed_manifest_bytes,
    ));
    malformed_manifest_report["bundle_manifest_digest"] = Value::Null;
    malformed_manifest_report["components"]["completeness"] = json!("invalid");
    malformed_manifest_report["reason_codes"] = json!(["invalid-canonicalization"]);
    assert!(
        report_validator.is_valid(&malformed_manifest_report),
        "duplicate-key manifest bytes retain raw identity without a fabricated typed manifest digest"
    );

    let mut missing_manifest_report = report_base.clone();
    missing_manifest_report["execution_id"] = json!("execution_0000000000000007");
    missing_manifest_report["report_id"] = json!("report_0000000000000007");
    missing_manifest_report["scenario"] = json!("incomplete-required-artifact-withheld");
    missing_manifest_report["status"] = json!("Incomplete");
    missing_manifest_report["raw_bundle_manifest_digest"] = Value::Null;
    missing_manifest_report["bundle_manifest_digest"] = Value::Null;
    missing_manifest_report["components"]["content"] = json!("missing");
    missing_manifest_report["components"]["completeness"] = json!("missing");
    missing_manifest_report["reason_codes"] = json!(["missing-artifact"]);
    assert!(
        report_validator.is_valid(&missing_manifest_report),
        "a withheld manifest is Incomplete and carries null raw/typed manifest identities"
    );

    let invalid_reason_precedence = [
        "invalid-signature",
        "invalid-actor",
        "invalid-authority",
        "invalid-role-separation",
        "invalid-approval",
        "invalid-policy",
        "invalid-content",
        "invalid-environment",
        "invalid-release",
        "invalid-path",
        "invalid-canonicalization",
        "invalid-limit",
        "invalid-registry",
        "invalid-checkpoint",
        "invalid-cross-link",
        "invalid-completeness",
    ];
    let select_primary_invalid_reason = |applicable: &BTreeSet<&str>| {
        invalid_reason_precedence
            .iter()
            .find(|reason| applicable.contains(**reason))
            .copied()
    };
    for (index, reason) in invalid_reason_precedence.iter().enumerate() {
        assert_eq!(
            select_primary_invalid_reason(&BTreeSet::from([*reason])),
            Some(*reason),
        );
        if let Some(later) = invalid_reason_precedence.get(index + 1) {
            assert_eq!(
                select_primary_invalid_reason(&BTreeSet::from([*reason, *later])),
                Some(*reason),
                "{reason} must precede simultaneously applicable {later}",
            );
        }
    }
    let distinguishable_component_precedence = [
        ("signature", "invalid-signature"),
        ("actor", "invalid-actor"),
        ("authority", "invalid-authority"),
        ("role_separation", "invalid-role-separation"),
        ("approval", "invalid-approval"),
        ("policy", "invalid-policy"),
        ("content", "invalid-content"),
        ("environment", "invalid-environment"),
        ("release", "invalid-release"),
        ("completeness", "invalid-completeness"),
    ];
    for (earlier_index, (earlier_component, earlier_reason)) in
        distinguishable_component_precedence.iter().enumerate()
    {
        for (later_component, later_reason) in distinguishable_component_precedence
            .iter()
            .skip(earlier_index + 1)
        {
            let mut correctly_ranked = report_base.clone();
            correctly_ranked["execution_id"] = json!("execution_0000000000000008");
            correctly_ranked["report_id"] = json!("report_0000000000000008");
            correctly_ranked["scenario"] = json!("invalid-verification");
            correctly_ranked["status"] = json!("Invalid");
            correctly_ranked["components"][*earlier_component] = json!("invalid");
            correctly_ranked["components"][*later_component] = json!("invalid");
            correctly_ranked["reason_codes"] = json!([earlier_reason]);
            assert!(
                report_validator.is_valid(&correctly_ranked),
                "{earlier_reason} must represent the first distinguishable invalid component"
            );
            let mut lower_priority_reason = correctly_ranked;
            lower_priority_reason["reason_codes"] = json!([later_reason]);
            assert!(
                !report_validator.is_valid(&lower_priority_reason),
                "{later_reason} cannot skip earlier invalid component {earlier_component}"
            );
        }
    }

    let mut authority_tamper_report = observed_reports[2].clone();
    authority_tamper_report["execution_id"] = json!("execution_0000000000000004");
    authority_tamper_report["report_id"] = json!("report_0000000000000004");
    authority_tamper_report["scenario"] = json!("invalid-verification");
    authority_tamper_report["components"]["content"] = json!("verified");
    authority_tamper_report["components"]["authority"] = json!("invalid");
    authority_tamper_report["reason_codes"] = json!(["invalid-authority"]);
    assert!(report_validator.is_valid(&authority_tamper_report));
    let mut parsed_failure_without_manifest_identity = authority_tamper_report.clone();
    parsed_failure_without_manifest_identity["raw_bundle_manifest_digest"] = Value::Null;
    parsed_failure_without_manifest_identity["bundle_manifest_digest"] = Value::Null;
    assert!(
        !report_validator.is_valid(&parsed_failure_without_manifest_identity),
        "a post-manifest semantic failure cannot erase its raw or typed manifest identity"
    );
    assert!(
        !conformance_report_validator.is_valid(&authority_tamper_report),
        "general runtime authority failures remain representable but cannot masquerade as the content-only conformance scenario"
    );
    let mut mislabeled_authority_tamper = authority_tamper_report.clone();
    mislabeled_authority_tamper["scenario"] = json!("invalid-content-artifact-byte-tamper");
    assert!(!report_validator.is_valid(&mislabeled_authority_tamper));
    let mut reason_component_mismatch = authority_tamper_report.clone();
    reason_component_mismatch["reason_codes"] = json!(["invalid-signature"]);
    assert!(
        !report_validator.is_valid(&reason_component_mismatch),
        "the primary invalid reason must match an invalid component"
    );
    let mut wrong_precedence = authority_tamper_report.clone();
    wrong_precedence["components"]["authority"] = json!("verified");
    wrong_precedence["components"]["signature"] = json!("invalid");
    wrong_precedence["components"]["actor"] = json!("invalid");
    wrong_precedence["reason_codes"] = json!(["invalid-actor"]);
    assert!(
        !report_validator.is_valid(&wrong_precedence),
        "signature failure precedes a simultaneously observable actor failure"
    );
    wrong_precedence["reason_codes"] = json!(["invalid-signature"]);
    assert!(report_validator.is_valid(&wrong_precedence));

    let mut invalid_environment_checkpoint = authority_tamper_report;
    invalid_environment_checkpoint["components"]["authority"] = json!("verified");
    invalid_environment_checkpoint["components"]["environment"] = json!("invalid");
    invalid_environment_checkpoint["reason_codes"] = json!(["invalid-checkpoint"]);
    assert!(
        report_validator.is_valid(&invalid_environment_checkpoint),
        "an exact Environment release-checkpoint contradiction is representable without mislabeling authority"
    );
}

#[test]
fn rejection_requirements_are_unique_layered_and_problem_consistent() {
    let matrix = parse_file(&collaboration_path("vectors/rejected-cases.json"));
    let cases = matrix["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 158);

    assert_eq!(
        matrix["api_version"],
        "proof.dev/conformance/collaboration-server-rejected-requirements/v1"
    );
    assert_eq!(matrix["status"], "proposed");
    assert_eq!(matrix["execution_status"], "normative-requirements-only");

    let case_ids = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let future_test_ids = cases
        .iter()
        .map(|case| case["future_test_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(case_ids.len(), cases.len());
    assert_eq!(future_test_ids.len(), cases.len());
    for case in cases {
        assert_eq!(case["test_status"], "required-not-yet-implemented");
        assert_eq!(
            case["future_test_id"].as_str().unwrap(),
            format!("p0008.{}", case["id"].as_str().unwrap())
        );

        let authority = case["effects"]["authority"].as_str().unwrap();
        let artifacts = case["effects"]["artifacts"].as_str().unwrap();
        if authority.starts_with("append-") {
            assert!(
                artifacts.starts_with("catalog-new-signed-authority-records")
                    || (authority == "append-one-allow-decision"
                        && artifacts == "catalog-once-after-verification"),
                "{} commits {authority} without its signed body/catalog effect",
                case["id"]
            );
        }
    }
    let layers = cases
        .iter()
        .map(|case| case["layer"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        layers,
        BTreeSet::from([
            "authentication",
            "authorization",
            "configuration",
            "csrf",
            "disclosure",
            "export",
            "http",
            "idempotency",
            "migration",
            "outbox",
            "preview",
            "rebuild",
            "review",
            "schema",
            "storage",
            "transaction",
        ])
    );

    let registry = parse_file(&collaboration_path(
        "vectors/http-operation-registry.valid.json",
    ));
    let statuses = registry["problem_statuses"].as_object().unwrap();
    let http_cases = cases
        .iter()
        .filter(|case| case["applicability"]["kind"] == "http")
        .collect::<Vec<_>>();
    let non_http_cases = cases
        .iter()
        .filter(|case| case["applicability"]["kind"] == "non-http")
        .collect::<Vec<_>>();
    assert_eq!(http_cases.len(), 88);
    assert_eq!(non_http_cases.len(), 70);
    assert_eq!(http_cases.len() + non_http_cases.len(), cases.len());
    assert_eq!(
        http_cases
            .iter()
            .map(|case| { case["applicability"]["bindings"].as_array().unwrap().len() })
            .sum::<usize>(),
        276
    );

    let routes = registry["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|route| (route["route_id"].as_str().unwrap(), route))
        .collect::<BTreeMap<_, _>>();
    for case in &http_cases {
        let public_code = case["public_code"]
            .as_str()
            .expect("an HTTP rejected requirement must have a public Problem code");
        for binding in case["applicability"]["bindings"].as_array().unwrap() {
            let route_id = binding["route_id"].as_str().unwrap();
            let route = routes
                .get(route_id)
                .unwrap_or_else(|| panic!("{} binds unknown route {route_id}", case["id"]));
            let mut applicable_codes = registry["problem_profiles"]
                [route["problem_profile"].as_str().unwrap()]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect::<BTreeSet<_>>();

            if binding["operation"].is_object() {
                let operation = &binding["operation"];
                let row = route["operations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row.get("operation") == Some(operation))
                    .unwrap_or_else(|| {
                        panic!(
                            "{} binds {:?} to the wrong route {route_id}",
                            case["id"], operation
                        )
                    });
                applicable_codes.extend(
                    registry["problem_profiles"][row["problem_profile"].as_str().unwrap()]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|code| code.as_str().unwrap()),
                );
                applicable_codes.extend(
                    row["application_problem_codes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|code| code.as_str().unwrap()),
                );
                if let Some(profile) = row["application_error_profile"].as_str() {
                    applicable_codes.extend(
                        registry["agent_error_profiles"][profile]["public_problem_codes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|code| code.as_str().unwrap()),
                    );
                }
            }
            assert!(
                applicable_codes.contains(public_code),
                "{} exposes {public_code} outside exact route/operation closure {route_id}/{:?}",
                case["id"],
                binding["operation"]
            );
        }
    }
    for case in cases {
        if let Some(code) = case["public_code"].as_str() {
            assert_eq!(
                statuses.get(code),
                case.get("public_status"),
                "{} has a Problem/status pair outside the registry",
                case["future_test_id"]
            );
        } else {
            assert!(case["public_status"].is_null());
            match case["public_disclosure"].as_str() {
                Some("not-applicable-report") => assert!(matches!(
                    case["report_status"].as_str(),
                    Some("Complete" | "Incomplete" | "Invalid")
                )),
                Some("not-applicable-internal") => {
                    assert!(case.get("report_status").is_none());
                }
                disclosure => panic!(
                    "{} has null public outcome with {disclosure:?}",
                    case["future_test_id"]
                ),
            }
        }
    }

    let case_by_id = |id: &str| {
        cases
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("missing rejected requirement {id}"))
    };
    for id in [
        "artifact-catalog-before-verification",
        "artifact-existing-address-different-bytes",
        "artifact-read-after-write-mismatch",
    ] {
        assert_eq!(
            case_by_id(id)["effects"],
            json!({
                "authority": "rollback-attempt",
                "presentation": "rollback-attempt",
                "application": "rollback-governed-mutation",
                "idempotency": "rollback-attempt",
                "artifacts": "unreachable-staged-orphan-only",
                "outbox": "rollback-attempt"
            }),
            "{id} must roll back the complete authoritative attempt"
        );
    }
    assert_eq!(
        case_by_id("idempotency-key-different-input")["effects"],
        json!({
            "authority": "append-allow-decision-and-failure-consequence",
            "presentation": "consume-once",
            "application": "none",
            "idempotency": "conflict-no-result-disclosure",
            "artifacts": "catalog-new-signed-authority-records-once",
            "outbox": "none"
        })
    );
    assert_eq!(
        case_by_id("transaction-authorized-application-failure")["effects"],
        json!({
            "authority": "append-allow-decision-and-failure-consequence",
            "presentation": "consume-once",
            "application": "rollback-governed-mutation",
            "idempotency": "not-reserved",
            "artifacts": "catalog-new-signed-authority-records-once",
            "outbox": "none"
        })
    );

    let preview_pending = case_by_id("preview-ready-marker-missing");
    assert_eq!(
        preview_pending["public_code"],
        "proof.dependency.unavailable"
    );
    assert_eq!(preview_pending["public_status"], 503);

    let uncertain = case_by_id("transaction-uncertain-commit");
    assert_eq!(uncertain["public_code"], "proof.operation.unknown_outcome");
    assert_eq!(uncertain["public_status"], 504);
    assert!(
        uncertain["effects"]
            .as_object()
            .unwrap()
            .values()
            .all(|effect| effect == "outcome-unknown")
    );
    let reconciled = case_by_id("transaction-uncertain-commit-reconciled-as-replay");
    assert_eq!(
        reconciled["effects"]["authority"],
        "append-allow-decision-and-replay-record"
    );
    assert_eq!(
        reconciled["effects"]["idempotency"],
        "return-equivalent-stored-result"
    );
    assert_eq!(reconciled["effects"]["outbox"], "preserve-committed");

    assert_eq!(
        case_by_id("outbox-abandon-management-recovery")["effects"]["outbox"],
        "abandon-after-committed-management-fact"
    );
    assert_eq!(
        case_by_id("outbox-replay-management-recovery")["effects"]["outbox"],
        "replay-after-committed-management-fact"
    );
}
