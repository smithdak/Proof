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

fn independent_artifact_digest_matches(context: &str, artifact: &Value, expected: &str) -> bool {
    independent_artifact_digest(context, artifact) == expected
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
    let digest_contexts = BTreeMap::from([
        (
            "ContentResourceIntentV1",
            "proof:content-resource-intent:v1",
        ),
        ("PolicyBundleV1", "proof:policy-bundle:v1"),
        ("ContextPackV2", "proof:context-pack:v2"),
        ("EditV2", "proof:edit:v2"),
        ("EditBatchV2", "proof:edit-batch:v2"),
        ("ChangeSetV2", "proof:changeset:v2"),
        ("ValidationResultsV2", "proof:validation-results:v2"),
        ("ObjectLocaleRevisionV1", "proof:object-locale-revision:v1"),
        ("ObjectSetV2", "proof:object-set:v2"),
        ("KnownStateV2", "proof:known-state:v2"),
        ("EditionV2", "proof:edition:v2"),
        ("ReleaseV2", "proof:release:v2"),
    ]);
    let digest_cases = digest_vectors["cases"].as_array().unwrap();
    assert_eq!(digest_cases.len(), digest_contexts.len());
    for case in digest_cases {
        let kind = case["artifact_kind"].as_str().unwrap();
        let expected = case["expected_digest"].as_str().unwrap();
        assert!(
            independent_artifact_digest_matches(digest_contexts[kind], &case["artifact"], expected,),
            "{kind} independent digest mismatch"
        );

        let mut changed_version = case["artifact"].clone();
        changed_version["api_version"] = json!("proof.dev/unsupported/v999");
        assert_ne!(
            independent_artifact_digest(digest_contexts[kind], &changed_version),
            expected,
            "{kind} digest did not bind the mutated version"
        );
        assert!(
            !independent_artifact_digest_matches(
                digest_contexts[kind],
                &case["artifact"],
                "blake3:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            "{kind} accepted a syntactically valid substituted expected digest"
        );
    }
    let artifact_cases = digest_vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .chain(portable_vectors["cases"].as_array().unwrap())
        .collect::<Vec<_>>();
    let artifact_kinds = artifact_cases
        .iter()
        .map(|case| case["artifact_kind"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(artifact_schema["oneOf"].as_array().unwrap().len(), 14);
    assert_eq!(artifact_cases.len(), 14);
    assert_eq!(artifact_kinds.len(), 14);
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
    let instance_ids = instance_cases
        .iter()
        .map(|case| case["operation_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(contracts.len(), 11);
    assert_eq!(instance_cases.len(), 11);
    assert_eq!(instance_ids.len(), 11);
    assert_eq!(instance_ids, contracts.keys().copied().collect());

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
}
