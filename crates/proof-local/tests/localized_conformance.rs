use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

const ARTIFACT_SCHEMA_ID: &str =
    "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json";

fn independent_artifact_digest(context: &str, artifact: &Value) -> String {
    let canonical = serde_json_canonicalizer::to_string(artifact)
        .expect("portable artifact must satisfy RFC 8785 serialization");
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(canonical.as_bytes());
    format!("blake3:{}", hasher.finalize().to_hex())
}

fn expected_derive_key_context(artifact_kind: &str) -> &'static str {
    match artifact_kind {
        "ContentResourceIntentV1" => "proof:content-resource-intent:v1",
        "PolicyBundleV1" => "proof:policy-bundle:v1",
        "ContextPackV2" => "proof:context-pack:v2",
        "EditV2" => "proof:edit:v2",
        "ObjectCreateEditV2" => "proof:object-create-edit:v2",
        "EditBatchV2" => "proof:edit-batch:v2",
        "ChangeSetV2" => "proof:changeset:v2",
        "ValidationResultsV2" => "proof:validation-results:v2",
        "ObjectLocaleRevisionV1" => "proof:object-locale-revision:v1",
        "ObjectSetV2" => "proof:object-set:v2",
        "KnownStateV2" => "proof:known-state:v2",
        "EditionV2" => "proof:edition:v2",
        "ReleaseV2" => "proof:release:v2",
        other => panic!("{other} has no retained derive-key context"),
    }
}

fn case_by_id<'a>(cases: &'a [Value], case_id: &str) -> &'a Value {
    cases
        .iter()
        .find(|case| case["case_id"] == case_id)
        .unwrap_or_else(|| panic!("missing retained case {case_id}"))
}

fn rewrite_schema_refs(value: &mut Value, namespace: &str) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref") {
                if let Some(fragment) = reference.strip_prefix("#/$defs/") {
                    *reference = format!("#/$defs/{namespace}/{fragment}");
                } else if let Some(fragment) = reference
                    .strip_prefix(ARTIFACT_SCHEMA_ID)
                    .and_then(|reference| reference.strip_prefix("#/$defs/"))
                {
                    *reference = format!("#/$defs/artifacts/{fragment}");
                }
            }
            for child in object.values_mut() {
                rewrite_schema_refs(child, namespace);
            }
        }
        Value::Array(array) => {
            for child in array {
                rewrite_schema_refs(child, namespace);
            }
        }
        _ => {}
    }
}

fn operation_validator(
    artifact_schema: &Value,
    operation_schema: &Value,
    selector: &str,
) -> jsonschema::Validator {
    let definition = selector
        .strip_prefix("#/$defs/")
        .expect("operation selector must be a local definition");
    let mut artifact_definitions = artifact_schema["$defs"].clone();
    rewrite_schema_refs(&mut artifact_definitions, "artifacts");
    let mut operation_definitions = operation_schema["$defs"].clone();
    rewrite_schema_refs(&mut operation_definitions, "operations");
    let bundled = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/$defs/operations/{definition}"),
        "$defs": {
            "artifacts": artifact_definitions,
            "operations": operation_definitions,
        },
    });
    jsonschema::draft202012::new(&bundled).expect("bundled operation Schema must compile")
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one closed conformance matrix binds every artifact and operation family"
)]
fn localized_portable_artifacts_and_operation_instances_are_closed() {
    let artifact_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/schemas/artifacts.schema.json"
    ))
    .unwrap();
    let operation_schema: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/schemas/operations.schema.json"
    ))
    .unwrap();
    assert_eq!(artifact_schema["$id"], ARTIFACT_SCHEMA_ID);
    let meta = jsonschema::draft202012::meta::validator();
    assert!(meta.is_valid(&artifact_schema));
    assert!(meta.is_valid(&operation_schema));

    let artifact_validator = jsonschema::draft202012::new(&artifact_schema).unwrap();
    let digest_vectors: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/artifact-digests.valid.json"
    ))
    .unwrap();
    let portable_vectors: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/portable-artifacts.valid.json"
    ))
    .unwrap();
    let digest_cases = digest_vectors["cases"].as_array().unwrap();
    assert_eq!(digest_cases.len(), 15);
    assert_eq!(
        digest_cases
            .iter()
            .map(|case| case["case_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>()
            .len(),
        digest_cases.len()
    );
    for case in digest_cases {
        let case_id = case["case_id"].as_str().unwrap();
        let kind = case["artifact_kind"].as_str().unwrap();
        let context = case["derive_key_context"].as_str().unwrap();
        let expected = case["expected_digest"].as_str().unwrap();
        assert_eq!(context, expected_derive_key_context(kind));
        assert_eq!(
            independent_artifact_digest(context, &case["artifact"]),
            expected,
            "{case_id} independent RFC 8785/BLAKE3 digest mismatch"
        );

        let mut changed_version = case["artifact"].clone();
        changed_version["api_version"] = json!("proof.dev/unsupported/v999");
        assert_ne!(
            independent_artifact_digest(context, &changed_version),
            expected,
            "{case_id} digest did not bind the mutated version"
        );
        assert_ne!(
            independent_artifact_digest(context, &case["artifact"]),
            "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            "{case_id} accepted a substituted expected digest"
        );
    }

    let artifact_cases = digest_cases
        .iter()
        .chain(portable_vectors["cases"].as_array().unwrap())
        .collect::<Vec<_>>();
    let artifact_kinds = artifact_cases
        .iter()
        .map(|case| case["artifact_kind"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(artifact_schema["oneOf"].as_array().unwrap().len(), 15);
    assert_eq!(artifact_cases.len(), 17);
    assert_eq!(artifact_kinds.len(), 15);
    for case in artifact_cases {
        let artifact = &case["artifact"];
        let errors = artifact_validator
            .iter_errors(artifact)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(
            errors.is_empty(),
            "{} failed its artifact Schema: {errors:?}",
            case["artifact_kind"].as_str().unwrap()
        );
        let mut wrong_version = artifact.clone();
        wrong_version["api_version"] = json!("proof.dev/unsupported/v999");
        assert!(!artifact_validator.is_valid(&wrong_version));
        let mut widened = artifact.clone();
        widened["unexpected"] = json!(true);
        assert!(!artifact_validator.is_valid(&widened));
    }

    let legacy_intent = case_by_id(digest_cases, "content-resource-intent-v1");
    let creation_intent = case_by_id(digest_cases, "content-resource-intent-v2");
    assert_eq!(
        legacy_intent["artifact"]["api_version"],
        "proof.dev/content-resource-intent/v1"
    );
    assert_eq!(
        creation_intent["artifact"]["api_version"],
        "proof.dev/content-resource-intent/v2"
    );
    let creation_slot = &creation_intent["artifact"]["creations"][0];
    let creation_target = &creation_intent["artifact"]["targets"][0];
    assert_eq!(
        creation_intent["artifact"]["creations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(creation_slot["locales"], json!(["fr-FR"]));
    assert_eq!(creation_slot["object_id"], creation_target["object_id"]);
    assert_eq!(creation_slot["schema_id"], creation_target["schema_id"]);
    assert_eq!(creation_slot["locales"][0], creation_target["locale"]);
    let mut mismatched_slot = creation_intent["artifact"].clone();
    mismatched_slot["creations"][0]["schema_id"] = json!("other-campaign");
    assert!(
        artifact_validator.is_valid(&mismatched_slot),
        "intent-slot matching is semantic, not a JSON Schema ordering constraint"
    );
    assert_ne!(
        independent_artifact_digest("proof:content-resource-intent:v1", &mismatched_slot),
        creation_intent["expected_digest"]
    );
    let mut missing_creations = creation_intent["artifact"].clone();
    missing_creations
        .as_object_mut()
        .unwrap()
        .remove("creations");
    assert!(artifact_validator.is_valid(&missing_creations));
    let mut empty_creations = creation_intent["artifact"].clone();
    empty_creations["creations"] = json!([]);
    assert!(artifact_validator.is_valid(&empty_creations));
    assert_eq!(
        artifact_schema["$defs"]["contentResourceIntentV2"]["x-proof-aggregate-limit"],
        "targets.length + (creations.length when present, otherwise 0) <= 100; excess is proof.input.limit_exceeded"
    );
    assert!(artifact_schema["$defs"]["contentResourceIntentV2"]["properties"]["creations"]
        ["x-proof-set-order"]
        .as_str()
        .unwrap()
        .contains("strictly sorted"));
    let oversized_locales = (0..101)
        .map(|index| Value::String(format!("aa-{index:03}")))
        .collect::<Vec<_>>();
    let mut oversized_artifact_slot = creation_intent["artifact"].clone();
    oversized_artifact_slot["creations"][0]["locales"] = Value::Array(oversized_locales.clone());
    assert!(!artifact_validator.is_valid(&oversized_artifact_slot));

    let issue_validator = operation_validator(
        &artifact_schema,
        &operation_schema,
        "#/$defs/contentResourceIntentIssueInputV2",
    );
    let issue_input = json!({
        "api_version": "proof.dev/operation/content-resource-intent.issue/v2",
        "creations": creation_intent["artifact"]["creations"],
        "environment_id": creation_intent["artifact"]["environment_id"],
        "idempotency_key": "019c0000-0000-7000-8000-000000000080",
        "intent_id": creation_intent["artifact"]["intent_id"],
        "issued_at": creation_intent["artifact"]["issued_at"],
        "targets": creation_intent["artifact"]["targets"],
    });
    assert!(issue_validator.is_valid(&issue_input));
    let mut oversized_operation_slot = issue_input;
    oversized_operation_slot["creations"][0]["locales"] = Value::Array(oversized_locales);
    assert!(!issue_validator.is_valid(&oversized_operation_slot));

    let create_case = case_by_id(digest_cases, "edit-v2-object-create");
    let create_artifact = &create_case["artifact"];
    assert_eq!(create_artifact["api_version"], "proof.dev/edit/v2");
    assert_eq!(create_artifact["kind"], "object.create");
    assert!(create_artifact["supersedes_edit_id"].is_null());
    assert!(create_artifact["repair_of_validation_result_digest"].is_null());
    for (pointer, replacement) in [
        ("/content/title", json!("Different title")),
        ("/object_id", json!("019c0000-0000-7000-8000-000000000082")),
        ("/schema_version", json!(2)),
    ] {
        let mut mutated = create_artifact.clone();
        *mutated.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(
            independent_artifact_digest("proof:object-create-edit:v2", &mutated),
            create_case["expected_digest"],
            "ObjectCreateEditV2 did not bind {pointer}"
        );
    }
    let mut missing_schema = create_artifact.clone();
    missing_schema.as_object_mut().unwrap().remove("schema_id");
    assert!(!artifact_validator.is_valid(&missing_schema));
    let mut create_with_locale = create_artifact.clone();
    create_with_locale["locale"] = json!("fr-FR");
    assert!(!artifact_validator.is_valid(&create_with_locale));

    let existing_context = case_by_id(digest_cases, "context-pack-v2-existing-source");
    let existing_resource = &existing_context["artifact"]["resources"][0];
    assert!(existing_resource.get("schema").is_some());
    assert!(existing_resource.get("schema_candidates").is_none());
    assert_eq!(
        existing_resource["source"]["api_version"],
        "proof.dev/object-revision/v1"
    );
    let creation_context = case_by_id(digest_cases, "context-pack-v2-creation");
    let creation_resource = &creation_context["artifact"]["resources"][0];
    assert!(creation_resource.get("schema").is_none());
    assert_eq!(
        creation_resource["schema_candidates"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        creation_resource["source"],
        json!({
            "absent": true,
            "api_version": "proof.dev/object-revision-absence/v1",
            "authoritative_sequence": 2,
        })
    );
    assert_eq!(
        creation_resource["target"],
        json!({
            "absent": true,
            "api_version": "proof.dev/object-locale-absence/v1",
            "authoritative_sequence": 2,
        })
    );
    let candidate = &creation_resource["schema_candidates"][0];
    assert_eq!(
        independent_artifact_digest("proof:schema-version:v1", &candidate["document"]),
        candidate["document_digest"],
        "creation candidate must close over the exact Schema document"
    );
    let mut missing_candidates = creation_context["artifact"].clone();
    missing_candidates["resources"][0]
        .as_object_mut()
        .unwrap()
        .remove("schema_candidates");
    assert!(!artifact_validator.is_valid(&missing_candidates));
    let mut partial_candidate = creation_context["artifact"].clone();
    partial_candidate["resources"][0]["schema_candidates"][0]
        .as_object_mut()
        .unwrap()
        .remove("document_digest");
    assert!(!artifact_validator.is_valid(&partial_candidate));
    let mut present_source = creation_context["artifact"].clone();
    present_source["resources"][0]["source"]["absent"] = json!(false);
    assert!(!artifact_validator.is_valid(&present_source));
    let mut present_target = creation_context["artifact"].clone();
    present_target["resources"][0]["target"]["absent"] = json!(false);
    assert!(!artifact_validator.is_valid(&present_target));
    let mut mixed_closures = creation_context["artifact"].clone();
    mixed_closures["resources"][0]["schema"] =
        mixed_closures["resources"][0]["schema_candidates"][0].clone();
    assert!(!artifact_validator.is_valid(&mixed_closures));

    let registry: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/operation-registry.valid.json"
    ))
    .unwrap();
    let instances: Value = serde_json::from_slice(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/operation-instances.valid.json"
    ))
    .unwrap();
    let contracts = registry["contracts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|contract| (contract["operation_id"].as_str().unwrap(), contract))
        .collect::<BTreeMap<_, _>>();
    let instance_cases = instances["cases"].as_array().unwrap();
    let operation_cases = instance_cases
        .iter()
        .map(|case| (case["operation_id"].as_str().unwrap(), case))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(contracts.len(), 11);
    assert_eq!(instance_cases.len(), 11);
    assert_eq!(operation_cases.len(), 11);
    assert_eq!(
        operation_cases.keys().copied().collect::<BTreeSet<_>>(),
        contracts.keys().copied().collect()
    );
    assert!(!contracts.contains_key("proof.dev/operation/content-resource-intent.issue/v2"));

    for case in instance_cases {
        let operation_id = case["operation_id"].as_str().unwrap();
        let contract = contracts[operation_id];
        for (member, selector) in [("input", "input_schema"), ("output", "output_schema")] {
            let validator = operation_validator(
                &artifact_schema,
                &operation_schema,
                contract[selector].as_str().unwrap(),
            );
            let errors = validator
                .iter_errors(&case[member])
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "{operation_id} {member} failed its registered Schema: {errors:?}"
            );
            let mut widened = case[member].clone();
            widened["unexpected"] = json!(true);
            assert!(
                !validator.is_valid(&widened),
                "{operation_id} {member} accepted an unknown member"
            );
        }
        let mut wrong_version = case["input"].clone();
        wrong_version["api_version"] = json!("proof.dev/operation/unsupported/v999");
        let input_validator = operation_validator(
            &artifact_schema,
            &operation_schema,
            contract["input_schema"].as_str().unwrap(),
        );
        assert!(
            !input_validator.is_valid(&wrong_version),
            "{operation_id} accepted a mismatched input api_version"
        );
    }

    let context_operation = operation_cases["proof.dev/operation/context.build/v2"];
    assert_eq!(
        context_operation["output"]["manifest"],
        creation_context["artifact"]
    );
    assert_eq!(
        context_operation["output"]["context_pack_digest"],
        creation_context["expected_digest"]
    );
    assert_eq!(
        context_operation["output"]["manifest"]["resource_intent"],
        creation_intent["artifact"]
    );
    assert_eq!(
        independent_artifact_digest(
            "proof:content-resource-intent:v1",
            &context_operation["output"]["manifest"]["resource_intent"],
        ),
        context_operation["input"]["resource_intent_digest"]
    );
    assert_eq!(
        independent_artifact_digest(
            "proof:policy-bundle:v1",
            &context_operation["output"]["manifest"]["policy"],
        ),
        context_operation["output"]["manifest"]["policy_digest"]
    );

    let add = operation_cases["proof.dev/operation/changeset.add/v2"];
    assert_eq!(
        add["input"]["edits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edit| edit["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["object.create", "object.locale.put"]
    );
    assert_eq!(
        add["output"]["edit_ids"],
        json!([
            "019c0000-0000-7000-8000-000000000213",
            "019c0000-0000-7000-8000-000000000214",
        ])
    );
    assert_eq!(add["output"]["total_edit_count"], 2);
    let add_validator = operation_validator(
        &artifact_schema,
        &operation_schema,
        contracts["proof.dev/operation/changeset.add/v2"]["input_schema"]
            .as_str()
            .unwrap(),
    );
    let mut put_before_create = add["input"].clone();
    put_before_create["edits"].as_array_mut().unwrap().reverse();
    assert!(
        add_validator.is_valid(&put_before_create),
        "JSON Schema must not pretend to enforce create-before-put causality"
    );
    // p0021_authoring::put_before_create_is_a_deterministic_validation_finding_without_commit
    // locks the corresponding semantic finding and commit exclusion.
    let create_index = put_before_create["edits"]
        .as_array()
        .unwrap()
        .iter()
        .position(|edit| edit["kind"] == "object.create")
        .unwrap();
    put_before_create["edits"][create_index]
        .as_object_mut()
        .unwrap()
        .remove("schema_id");
    assert!(!add_validator.is_valid(&put_before_create));

    let get = operation_cases["proof.dev/operation/changeset.get/v2"];
    let diff = operation_cases["proof.dev/operation/changeset.diff/v2"];
    assert_eq!(get["output"]["edits"], diff["output"]["effective_edits"]);
    assert_eq!(
        get["output"]["edits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edit| edit["edit_id"].clone())
            .collect::<Vec<_>>(),
        add["output"]["edit_ids"].as_array().unwrap().clone()
    );
    assert_eq!(get["output"]["edits"][0], create_case["artifact"]);
    assert_eq!(
        get["output"]["edits"][1],
        case_by_id(digest_cases, "edit-v2-locale-put")["artifact"]
    );
    let created_object_revision = json!({
        "api_version": "proof.dev/object-revision/v1",
        "content": create_case["artifact"]["content"].clone(),
        "lifecycle_state": "active",
        "object_id": create_case["artifact"]["object_id"].clone(),
        "relationships": [],
        "revision": 1,
        "schema_id": create_case["artifact"]["schema_id"].clone(),
        "schema_version": create_case["artifact"]["schema_version"].clone(),
    });
    assert_eq!(
        independent_artifact_digest("proof:object-revision:v1", &created_object_revision),
        get["output"]["edits"][1]["expected_source"]["digest"]
    );
    assert!(get["output"]["effective_leaves"][0].get("locale").is_none());
    assert_eq!(get["output"]["effective_leaves"][1]["locale"], "fr-FR");
    let effective_batch = json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": diff["output"]["effective_edits"].clone(),
    });
    assert_eq!(
        independent_artifact_digest("proof:edit-batch:v2", &effective_batch),
        diff["output"]["effective_leaf_digest"]
    );
    assert_eq!(
        independent_artifact_digest("proof:changeset:v2", &get["output"]),
        diff["output"]["proposal_digest"]
    );
    assert_eq!(
        get["output"],
        case_by_id(digest_cases, "changeset-v2-create-put")["artifact"]
    );

    let validation_case = case_by_id(digest_cases, "validation-results-v2");
    let selected_schema = json!({
        "document_digest": candidate["document_digest"].clone(),
        "schema_id": candidate["schema_id"].clone(),
        "schema_version": candidate["schema_version"].clone(),
    });
    assert!(
        validation_case["artifact"]["schema_digests"]
            .as_array()
            .unwrap()
            .contains(&selected_schema)
    );
    let schema_keys = validation_case["artifact"]["schema_digests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|schema| {
            (
                schema["schema_id"].as_str().unwrap(),
                schema["schema_version"].as_u64().unwrap(),
                schema["document_digest"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut sorted_unique_schema_keys = schema_keys.clone();
    sorted_unique_schema_keys.sort_unstable();
    sorted_unique_schema_keys.dedup();
    assert_eq!(schema_keys, sorted_unique_schema_keys);
    let validate = operation_cases["proof.dev/operation/changeset.validate/v2"];
    assert_eq!(
        validate["output"]["validation_results_digest"],
        validation_case["expected_digest"]
    );
    assert_eq!(
        validate["output"]["proposal_digest"],
        validation_case["artifact"]["proposal_digest"]
    );
    assert_eq!(
        validate["output"]["effective_leaf_digest"],
        validation_case["artifact"]["effective_leaf_digest"]
    );
    let seal = json!({
        "api_version": "proof.dev/changeset-seal/v2",
        "proposal_digest": validate["output"]["proposal_digest"].clone(),
        "validation_results_digest": validate["output"]["validation_results_digest"].clone(),
    });
    assert_eq!(
        independent_artifact_digest("proof:changeset:v2", &seal),
        validate["output"]["sealed_changeset_digest"]
    );

    let commit = operation_cases["proof.dev/operation/changeset.commit/v2"];
    assert_eq!(
        commit["output"]["previous_state"]["authoritative_sequence"],
        2
    );
    assert_eq!(
        commit["output"]["resulting_state"]["authoritative_sequence"],
        4
    );
    assert_eq!(
        commit["output"]["renditions"][0],
        case_by_id(digest_cases, "object-locale-revision-v1")["artifact"]
    );
    let known_state = case_by_id(digest_cases, "known-state-v2");
    assert_eq!(
        commit["output"]["resulting_state"]["digest"],
        known_state["expected_digest"]
    );
    assert_eq!(known_state["artifact"]["authoritative_sequence"], 4);
    assert_eq!(
        known_state["artifact"]["objects"].as_array().unwrap().len(),
        2
    );
    let base_state = json!({
        "api_version": "proof.dev/known-state/v1",
        "authoritative_sequence": 2,
        "objects": [known_state["artifact"]["objects"][0].clone()],
        "schemas": known_state["artifact"]["schemas"].clone(),
        "workspace_id": known_state["artifact"]["workspace_id"].clone(),
    });
    assert_eq!(
        independent_artifact_digest("proof:known-state:v1", &base_state),
        commit["output"]["previous_state"]["digest"]
    );
    let edition_operation = operation_cases["proof.dev/operation/edition.create/v2"];
    assert_eq!(
        edition_operation["output"]["manifest"],
        case_by_id(digest_cases, "edition-v2")["artifact"]
    );
    assert_eq!(
        edition_operation["output"]["edition_digest"],
        case_by_id(digest_cases, "edition-v2")["expected_digest"]
    );
    let schema_set = json!({
        "api_version": "proof.dev/schema-set/v1",
        "schemas": edition_operation["output"]["manifest"]["schemas"].clone(),
    });
    assert_eq!(
        independent_artifact_digest("proof:schema-set:v1", &schema_set),
        edition_operation["output"]["manifest"]["schema_set_digest"]
    );
    let release_operation = operation_cases["proof.dev/operation/release.create/v2"];
    let release_case = case_by_id(digest_cases, "release-v2");
    assert_eq!(
        release_operation["output"]["release_manifest"],
        release_case["artifact"]
    );
    assert_eq!(
        release_operation["output"]["release_digest"],
        release_case["expected_digest"]
    );

    let portable_cases = portable_vectors["cases"].as_array().unwrap();
    let delta = case_by_id(portable_cases, "edition-delta-v2-create-put");
    let created_reference = known_state["artifact"]["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["object_id"] == creation_slot["object_id"])
        .unwrap();
    assert!(delta["artifact"]["objects"][0]["before"].is_null());
    assert_eq!(delta["artifact"]["objects"][0]["after"], *created_reference);
    assert_eq!(
        delta["artifact"]["base"]["state"]["authoritative_sequence"],
        2
    );
    assert_eq!(
        delta["artifact"]["target"]["state"]["authoritative_sequence"],
        4
    );
    assert_eq!(
        independent_artifact_digest("proof:release:v2", &delta["artifact"]),
        release_case["artifact"]["exact_delta_digest"]
    );
    let predicate = case_by_id(portable_cases, "release-proof-predicate-v2-create-put");
    assert_eq!(predicate["artifact"]["exact_delta"], delta["artifact"]);
    assert_eq!(
        predicate["artifact"]["exact_delta_digest"],
        release_case["artifact"]["exact_delta_digest"]
    );
}
