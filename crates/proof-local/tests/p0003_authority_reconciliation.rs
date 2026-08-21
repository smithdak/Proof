use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

const OPERATION_SCHEMA_ID: &str = "https://proof.dev/schema/authority/operation/v1";
const LOCALIZED_OPERATION_SCHEMA_ID: &str =
    "https://proof.dev/schemas/localized-content/operations-v2.schema.json";

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("checked-in conformance JSON must parse")
}

fn rewrite_external_operation_ref(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if object.get("$ref").and_then(Value::as_str) == Some(OPERATION_SCHEMA_ID) {
                object.insert(
                    "$ref".to_owned(),
                    Value::String("#/$defs/registeredOperation".to_owned()),
                );
            }
            for child in object.values_mut() {
                rewrite_external_operation_ref(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                rewrite_external_operation_ref(child);
            }
        }
        _ => {}
    }
}

fn operation_bundled_validator(schema: &Value, operation_schema: &Value) -> jsonschema::Validator {
    let mut bundled = schema.clone();
    rewrite_external_operation_ref(&mut bundled);
    bundled["$defs"]["registeredOperation"] = operation_schema.clone();
    jsonschema::draft202012::new(&bundled).expect("bundled authority Schema must compile")
}

fn operation_pair(value: &Value) -> (String, String) {
    (
        value["operation"]["name"].as_str().unwrap().to_owned(),
        value["operation"]["version"].as_str().unwrap().to_owned(),
    )
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one closed matrix cross-checks the complete P-0003/P-0007 registry and projection boundary"
)]
fn authority_registry_reconciles_the_localized_contract_without_widening_delegation() {
    let operation_schema = parse(include_bytes!(
        "../../../conformance/v1/authority/schemas/operation-v1.schema.json"
    ));
    let delegation_schema = parse(include_bytes!(
        "../../../conformance/v1/authority/schemas/delegation-v2.schema.json"
    ));
    let decision_schema = parse(include_bytes!(
        "../../../conformance/v1/authority/schemas/authorization-decision-v2.schema.json"
    ));
    let registry_schema = parse(include_bytes!(
        "../../../conformance/v1/authority/schemas/authority-operation-registry-v1.schema.json"
    ));
    let rejected_case_schema = parse(include_bytes!(
        "../../../conformance/v1/authority/schemas/rejected-case-manifest-v1.schema.json"
    ));
    let meta = jsonschema::draft202012::meta::validator();
    for schema in [
        &operation_schema,
        &delegation_schema,
        &decision_schema,
        &registry_schema,
        &rejected_case_schema,
    ] {
        assert!(
            meta.is_valid(schema),
            "authority Schema is not Draft 2020-12"
        );
    }

    let registry = parse(include_bytes!(
        "../../../conformance/v1/authority/vectors/authority-operation-registry.valid.json"
    ));
    let registry_validator = operation_bundled_validator(&registry_schema, &operation_schema);
    assert!(registry_validator.is_valid(&registry));

    let operations = registry["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 14);
    let operation_pairs = operations.iter().map(operation_pair).collect::<Vec<_>>();
    let mut sorted_pairs = operation_pairs.clone();
    sorted_pairs.sort();
    assert_eq!(
        operation_pairs, sorted_pairs,
        "registry order must be canonical"
    );
    assert_eq!(
        operation_pairs.iter().collect::<BTreeSet<_>>().len(),
        operation_pairs.len()
    );

    let schema_pairs = operation_schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["properties"]["name"]["const"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                entry["properties"]["version"]["const"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(schema_pairs, operation_pairs.iter().cloned().collect());

    let registry_mapping = operations
        .iter()
        .map(|entry| {
            (
                operation_pair(entry),
                entry["requested_action"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let decision_mapping = decision_schema["allOf"].as_array().unwrap().last().unwrap()["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                (
                    entry["properties"]["operation"]["properties"]["name"]["const"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                    entry["properties"]["operation"]["properties"]["version"]["const"]
                        .as_str()
                        .unwrap()
                        .to_owned(),
                ),
                entry["properties"]["requested_action"]["const"]
                    .as_str()
                    .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(decision_mapping, registry_mapping);
    let delegation_actions = delegation_schema["properties"]["actions"]["items"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        delegation_actions,
        registry_mapping.values().copied().collect::<BTreeSet<_>>()
    );
    assert_eq!(
        operation_pairs
            .iter()
            .filter(|(_, version)| version.ends_with("/v1"))
            .cloned()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "context.build".to_owned(),
                "proof.dev/operation/context.build/v1".to_owned(),
            ),
            (
                "object.query_released".to_owned(),
                "proof.dev/operation/object.query_released/v1".to_owned(),
            ),
            (
                "workspace.status".to_owned(),
                "proof.dev/operation/workspace.status/v1".to_owned(),
            ),
        ])
    );

    let localized_registry = parse(include_bytes!(
        "../../../conformance/v2/localized-content/vectors/operation-registry.valid.json"
    ));
    let localized_operation_schema = parse(include_bytes!(
        "../../../conformance/v2/localized-content/schemas/operations.schema.json"
    ));
    let authority_by_version = operations
        .iter()
        .map(|entry| (entry["operation"]["version"].as_str().unwrap(), entry))
        .collect::<BTreeMap<_, _>>();
    let localized_contracts = localized_registry["contracts"].as_array().unwrap();
    assert_eq!(localized_contracts.len(), 11);
    for contract in localized_contracts {
        let operation_id = contract["operation_id"].as_str().unwrap();
        let authority = authority_by_version[operation_id];
        assert_eq!(authority["requested_action"], contract["action"]);
        assert_eq!(
            authority["localized_contract"],
            format!(
                "{}{}",
                LOCALIZED_OPERATION_SCHEMA_ID,
                contract["input_schema"].as_str().unwrap()
            )
        );
        let selector = contract["input_schema"]
            .as_str()
            .unwrap()
            .strip_prefix("#/$defs/")
            .unwrap();
        assert!(localized_operation_schema["$defs"].get(selector).is_some());
        assert_eq!(
            localized_operation_schema["$defs"][selector]["properties"]["api_version"]["const"],
            operation_id
        );
    }

    assert_eq!(
        registry["resource_projection_profiles"],
        json!([
            {
                "profile": "legacy-object-selection/v1",
                "grant_axes": ["environment_ids", "object_ids", "workspace_ids"],
                "evaluation": "single-stage",
                "sources": {
                    "workspace_ids": "command.workspace_id",
                    "environment_ids": "normalized_input.environment_id",
                    "object_ids": "normalized_input.object_ids",
                    "schema_ids": "none",
                    "locales": "none"
                }
            },
            {
                "profile": "localized-intent-closure/v1",
                "grant_axes": [
                    "environment_ids", "locales", "object_ids", "schema_ids", "workspace_ids"
                ],
                "evaluation": "single-stage",
                "sources": {
                    "workspace_ids": "command.workspace_id",
                    "environment_ids": "verified_content_resource_intent.environment_id",
                    "object_ids": "verified_content_resource_intent.targets.object_id",
                    "schema_ids": "verified_content_resource_intent.targets.schema_id",
                    "locales": "verified_content_resource_intent.targets.locale"
                }
            },
            {
                "profile": "localized-released-selection/v1",
                "grant_axes": [
                    "environment_ids", "locales", "object_ids", "schema_ids", "workspace_ids"
                ],
                "evaluation": "staged-object-locale-then-resolved-schema",
                "sources": {
                    "workspace_ids": "command.workspace_id",
                    "environment_ids": "normalized_input.environment_id",
                    "object_ids": "normalized_input.targets.object_id",
                    "schema_ids": "resolved_current_release.edition.requested_objects.schema_id",
                    "locales": "normalized_input.targets.locale"
                }
            },
            {
                "profile": "workspace-only/v1",
                "grant_axes": ["workspace_ids"],
                "evaluation": "single-stage",
                "sources": {
                    "workspace_ids": "command.workspace_id",
                    "environment_ids": "none",
                    "object_ids": "none",
                    "schema_ids": "none",
                    "locales": "none"
                }
            }
        ])
    );

    let closure_profiles = operations
        .iter()
        .map(|entry| {
            (
                entry["operation"]["version"].as_str().unwrap(),
                (
                    entry["closure_anchor"].as_str().unwrap(),
                    entry["resource_projection_profile"].as_str().unwrap(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected_closure_profiles = BTreeMap::from([
        (
            "proof.dev/operation/workspace.status/v1",
            ("command", "workspace-only/v1"),
        ),
        (
            "proof.dev/operation/object.query_released/v1",
            ("command", "legacy-object-selection/v1"),
        ),
        (
            "proof.dev/operation/context.build/v1",
            ("command", "legacy-object-selection/v1"),
        ),
        (
            "proof.dev/operation/context.build/v2",
            (
                "normalized-input-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.create/v2",
            (
                "normalized-input-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.add/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.get/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.diff/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.validate/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.submit/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/changeset.commit/v2",
            (
                "verified-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/edition.create/v2",
            (
                "verified-committed-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/release.create/v2",
            (
                "verified-edition-changeset-resource-intent",
                "localized-intent-closure/v1",
            ),
        ),
        (
            "proof.dev/operation/object.query_released/v2",
            (
                "resolved-current-release",
                "localized-released-selection/v1",
            ),
        ),
    ]);
    assert_eq!(closure_profiles, expected_closure_profiles);

    for entry in operations.iter().filter(|entry| {
        entry["operation"]["name"]
            .as_str()
            .unwrap()
            .starts_with("changeset.")
    }) {
        assert_eq!(
            entry["selector_projection"],
            json!({
                "changeset_ids": "normalized_input.changeset_id",
                "edition_ids": "none",
                "release_ids": "none"
            })
        );
    }
    assert_eq!(
        authority_by_version["proof.dev/operation/edition.create/v2"]["selector_projection"],
        json!({
            "changeset_ids": "normalized_input.changeset_id",
            "edition_ids": "normalized_input.edition_id",
            "release_ids": "none"
        })
    );
    assert_eq!(
        authority_by_version["proof.dev/operation/release.create/v2"]["selector_projection"],
        json!({
            "changeset_ids": "resolved_edition.changeset_id",
            "edition_ids": "normalized_input.edition_id",
            "release_ids": "canonical-sorted(normalized_input.expected_base_release_id,normalized_input.release_id)"
        })
    );
    for version in [
        "proof.dev/operation/object.query_released/v1",
        "proof.dev/operation/object.query_released/v2",
    ] {
        assert_eq!(
            authority_by_version[version]["selector_projection"],
            json!({
                "changeset_ids": "none",
                "edition_ids": "resolved_current_release.edition_id",
                "release_ids": "resolved_current_release.release_id"
            })
        );
    }

    let idempotency = operations
        .iter()
        .map(|entry| {
            (
                entry["operation"]["version"].as_str().unwrap(),
                entry["application_idempotency"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        idempotency["proof.dev/operation/changeset.validate/v2"],
        "derived-proposal-policy-validator"
    );
    assert_eq!(
        idempotency["proof.dev/operation/changeset.submit/v2"],
        "derived-changeset"
    );
    for operation in [
        "proof.dev/operation/changeset.diff/v2",
        "proof.dev/operation/changeset.get/v2",
        "proof.dev/operation/object.query_released/v1",
        "proof.dev/operation/object.query_released/v2",
        "proof.dev/operation/workspace.status/v1",
    ] {
        assert_eq!(idempotency[operation], "none");
    }
    let budget_projection = operations
        .iter()
        .map(|entry| {
            (
                entry["operation"]["version"].as_str().unwrap(),
                entry["budget_projection"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        budget_projection["proof.dev/operation/context.build/v1"],
        "normalized-v1-context-limits"
    );
    assert_eq!(
        budget_projection["proof.dev/operation/context.build/v2"],
        "normalized-v2-context-limits"
    );
    assert_eq!(
        budget_projection["proof.dev/operation/object.query_released/v2"],
        "requested-object-count"
    );
    assert_eq!(
        budget_projection["proof.dev/operation/release.create/v2"],
        "bound-context-limits"
    );

    let localized_delegation = parse(include_bytes!(
        "../../../conformance/v1/authority/vectors/delegation-v2.localized-scope.valid.json"
    ));
    let delegation_validator = jsonschema::draft202012::new(&delegation_schema).unwrap();
    assert!(delegation_validator.is_valid(&localized_delegation));
    assert_eq!(
        localized_delegation["scope"]["locales"],
        json!(["fr-FR", "iw", "sl-rozaj"])
    );
    let mut uppercase_variant = localized_delegation;
    uppercase_variant["scope"]["locales"][2] = json!("sl-ROZAJ");
    assert!(!delegation_validator.is_valid(&uppercase_variant));

    let decision_validator = operation_bundled_validator(&decision_schema, &operation_schema);
    let mut decision = parse(include_bytes!(
        "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
    ));
    decision["requested_resources"]["locales"] = json!(["sl-rozaj"]);
    assert!(decision_validator.is_valid(&decision));
    decision["requested_resources"]["locales"] = json!(["sl-ROZAJ"]);
    assert!(!decision_validator.is_valid(&decision));

    let legacy_decision = parse(include_bytes!(
        "../../../conformance/v1/authority/vectors/authorization-decision-v2.valid.json"
    ));
    assert!(decision_validator.is_valid(&legacy_decision));
    let mut p4_with_commitment = legacy_decision.clone();
    p4_with_commitment["localized_consequence_commitment"] = json!({
        "application_consequence_digest": format!("blake3:{}", "b".repeat(64)),
        "result_contract": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/contextBuildOutput",
        "result_digest": format!("blake3:{}", "a".repeat(64)),
        "result_kind": "success"
    });
    assert!(!decision_validator.is_valid(&p4_with_commitment));

    let mut localized_allow = legacy_decision.clone();
    localized_allow["operation"] = json!({
        "name": "context.build",
        "version": "proof.dev/operation/context.build/v2"
    });
    localized_allow["requested_action"] = json!("context:build");
    assert!(!decision_validator.is_valid(&localized_allow));
    localized_allow["localized_consequence_commitment"] = json!({
        "application_consequence_digest": format!("blake3:{}", "b".repeat(64)),
        "result_contract": "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/contextBuildOutput",
        "result_digest": format!("blake3:{}", "a".repeat(64)),
        "result_kind": "success"
    });
    assert!(decision_validator.is_valid(&localized_allow));
    localized_allow["localized_consequence_commitment"]["result_contract"] = json!(
        "https://proof.dev/schemas/localized-content/operations-v2.schema.json#/$defs/changeSetCreateOutput"
    );
    assert!(!decision_validator.is_valid(&localized_allow));
    localized_allow["localized_consequence_commitment"]["result_kind"] = json!("failure");
    localized_allow["localized_consequence_commitment"]["result_contract"] =
        json!("proof.dev/result/localized-operation-problem/v1");
    assert!(decision_validator.is_valid(&localized_allow));
    localized_allow["decision"] = json!("deny");
    localized_allow["reason_code"] = json!("proof.authorization.policy_denied");
    assert!(!decision_validator.is_valid(&localized_allow));

    let rejected_cases = parse(include_bytes!(
        "../../../conformance/v1/authority/vectors/rejected-authorization-cases.json"
    ));
    let rejected_validator = jsonschema::draft202012::new(&rejected_case_schema).unwrap();
    assert!(rejected_validator.is_valid(&rejected_cases));
    let locale_case = rejected_cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "uppercase-locale-variant")
        .unwrap();
    assert_eq!(locale_case["mutation"]["value"], "sl-ROZAJ");
    assert_eq!(locale_case["expected_decision_append"], false);
    let rejected_ids = rejected_cases["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(
        BTreeSet::from([
            "localized-environment-scope-missing",
            "localized-locale-scope-missing",
            "localized-object-scope-missing",
            "localized-schema-scope-missing",
            "superseded-v1-write-operation",
            "uppercase-locale-variant",
        ])
        .is_subset(&rejected_ids)
    );
}
