//! Independent validation against the checked-in public wire contracts.
//!
//! The verifier compiles these schemas itself. It neither calls a producer
//! parser nor links any `proof-*` crate, so a producer value is accepted only
//! when it independently satisfies the portable public contract.

use std::{collections::BTreeMap, sync::OnceLock};

use jsonschema::{Registry, Validator};
use serde_json::{Value, json};

const AUTHORITY_RECORD_ID: &str = "https://proof.dev/schema/authority/authority-record/v1";
const COMMAND_INPUT_ID: &str = "https://proof.dev/schema/authority/command-input/v1";
const AUTHENTICATED_COMMAND_ID: &str =
    "https://proof.dev/schema/authority/authenticated-command/v1";
const ACTOR_EVIDENCE_ID: &str =
    "https://proof.dev/schema/authority/authenticated-actor-context-evidence/v1";
const LOCALIZED_ARTIFACT_ID: &str =
    "https://proof.dev/schemas/localized-content/artifacts-v2.schema.json";
const LOCALIZED_OPERATION_ID: &str =
    "https://proof.dev/schemas/localized-content/operations-v2.schema.json";

const AUTHORITY_SCHEMAS: &[&[u8]] = &[
    include_bytes!("../../../conformance/v1/authority/schemas/authority-record-v1.schema.json"),
    include_bytes!("../../../conformance/v1/authority/schemas/principal-status-v1.schema.json"),
    include_bytes!("../../../conformance/v1/authority/schemas/principal-binding-v1.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/principal-binding-revocation-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/delegation-v2.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/delegation-revocation-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authorization-decision-v2.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/workspace-authority-root-transition-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/operation-v1.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authenticated-subject-v1.schema.json"
    ),
    include_bytes!("../../../conformance/v1/authority/schemas/command-input-v1.schema.json"),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authenticated-command-v1.schema.json"
    ),
    include_bytes!(
        "../../../conformance/v1/authority/schemas/authenticated-actor-context-evidence-v1.schema.json"
    ),
];

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("checked-in public schema must parse")
}

fn registry(values: &[Value]) -> Registry<'_> {
    let mut registry = Registry::new();
    for value in values {
        let identifier = value
            .get("$id")
            .and_then(Value::as_str)
            .expect("checked-in public schema must have an identifier");
        registry = registry
            .add(identifier, value)
            .expect("checked-in public schema must be a resource");
    }
    registry
        .prepare()
        .expect("checked-in public schema registry must resolve")
}

fn authority_validator(identifier: &'static str) -> Validator {
    let values = AUTHORITY_SCHEMAS
        .iter()
        .map(|bytes| parse(bytes))
        .collect::<Vec<_>>();
    let registry = registry(&values);
    jsonschema::options()
        .with_registry(&registry)
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": identifier,
        }))
        .expect("checked-in authority schemas must compile")
}

fn localized_validator(reference: &str) -> Validator {
    let values = vec![
        parse(include_bytes!(
            "../../../conformance/v2/localized-content/schemas/artifacts.schema.json"
        )),
        parse(include_bytes!(
            "../../../conformance/v2/localized-content/schemas/operations.schema.json"
        )),
    ];
    let registry = registry(&values);
    jsonschema::options()
        .with_registry(&registry)
        .build(&json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": reference,
        }))
        .expect("checked-in localized schemas must compile")
}

pub(crate) fn authority_record(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| authority_validator(AUTHORITY_RECORD_ID))
        .is_valid(value)
}

pub(crate) fn command_input(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| authority_validator(COMMAND_INPUT_ID))
        .is_valid(value)
}

pub(crate) fn authenticated_command(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| authority_validator(AUTHENTICATED_COMMAND_ID))
        .is_valid(value)
}

pub(crate) fn actor_evidence(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| authority_validator(ACTOR_EVIDENCE_ID))
        .is_valid(value)
}

pub(crate) fn localized_artifact(value: &Value) -> bool {
    static VALIDATOR: OnceLock<Validator> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| localized_validator(LOCALIZED_ARTIFACT_ID))
        .is_valid(value)
}

fn operation_validators() -> &'static BTreeMap<&'static str, Validator> {
    static VALIDATORS: OnceLock<BTreeMap<&'static str, Validator>> = OnceLock::new();
    VALIDATORS.get_or_init(|| {
        [
            "contextBuildInput",
            "contextBuildOutput",
            "changeSetCreateInput",
            "changeSetCreateOutput",
            "changeSetAddInput",
            "changeSetAddOutput",
            "changeSetGetInput",
            "changeSetGetOutput",
            "changeSetDiffInput",
            "changeSetDiffOutput",
            "changeSetValidateInput",
            "changeSetValidateOutput",
            "changeSetSubmitInput",
            "changeSetSubmitOutput",
            "changeSetCommitInput",
            "changeSetCommitOutput",
            "editionCreateInput",
            "editionCreateOutput",
            "releaseCreateInput",
            "releaseCreateOutput",
            "objectQueryReleasedInput",
            "objectQueryReleasedOutput",
        ]
        .into_iter()
        .map(|definition| {
            (
                definition,
                localized_validator(&format!("{LOCALIZED_OPERATION_ID}#/$defs/{definition}")),
            )
        })
        .collect()
    })
}

pub(crate) fn localized_operation(definition: &str, value: &Value) -> bool {
    operation_validators()
        .get(definition)
        .is_some_and(|validator| validator.is_valid(value))
}

pub(crate) fn document_accepts(document: &Value, instance: &Value) -> bool {
    jsonschema::validator_for(document).is_ok_and(|validator| validator.is_valid(instance))
}

pub(crate) fn draft_2020_12_document(value: &Value) -> bool {
    value.is_object()
        && value.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema")
        && jsonschema::draft202012::meta::validator().is_valid(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_schemas_compile_and_reject_open_objects() {
        assert!(!localized_operation(
            "releaseCreateInput",
            &json!({"api_version": "proof.dev/operation/release.create/v2"})
        ));
        assert!(!authority_record(&json!({
            "api_version": "proof.dev/principal-status/v1",
            "unknown": true,
        })));
    }
}
