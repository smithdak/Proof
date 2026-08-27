//! Cross-language contract drift guard: the TypeScript SDK's frozen registry
//! and typed operation inputs must stay field-set-exact against the Rust
//! authority inputs (`web/packages/proof-sdk`).
//!
//! These tests fail the Rust gate when either side drifts, satisfying the
//! P-0017 acceptance criterion that a retained test catches TypeScript
//! declaration drift from the Rust sources.

use std::path::{Path, PathBuf};

fn sdk_source(name: &str) -> String {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir
        .join("../../web/packages/proof-sdk/src")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn interface_block<'a>(ts_source: &'a str, interface_name: &str) -> Option<&'a str> {
    let marker = format!("export interface {interface_name}");
    let start = ts_source.find(&marker)?;
    let body_start = ts_source[start..].find('{')? + start;
    let mut depth = 0usize;
    for (offset, character) in ts_source[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&ts_source[body_start..=body_start + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

fn rust_struct_fields(source: &str, struct_name: &str) -> Vec<String> {
    let marker = format!("pub struct {struct_name}");
    let Some(start) = source.find(&marker) else {
        panic!("Rust struct {struct_name} not found");
    };
    let body_start = source[start..].find('{').expect("struct body") + start;
    let body_end = source[body_start..].find('}').expect("struct end") + body_start;
    let body = &source[body_start..body_end];
    let mut fields = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub ")
            && let Some(name) = rest.split(':').next()
        {
            fields.push(name.trim().to_owned());
        }
    }
    fields
}

fn assert_interface_covers<'a>(
    ts_source: &str,
    interface_name: &str,
    rust_fields: impl IntoIterator<Item = &'a String>,
) {
    let block = interface_block(ts_source, interface_name)
        .unwrap_or_else(|| panic!("TypeScript interface {interface_name} not found"));
    for field in rust_fields {
        assert!(
            block.contains(&format!("{field}:")),
            "TypeScript interface {interface_name} is missing field `{field}`"
        );
    }
}

#[test]
fn ts_registry_matches_the_frozen_authority_operation_pairs() {
    use proof_application::authority::AuthorityOperation;
    let registry_ts = sdk_source("registry.ts");
    let all = [
        AuthorityOperation::ChangesetAddV2,
        AuthorityOperation::ChangesetCommitV2,
        AuthorityOperation::ChangesetCreateV2,
        AuthorityOperation::ChangesetDiffV2,
        AuthorityOperation::ChangesetGetV2,
        AuthorityOperation::ChangesetSubmitV2,
        AuthorityOperation::ChangesetValidateV2,
        AuthorityOperation::ContextBuildV1,
        AuthorityOperation::ContextBuildV2,
        AuthorityOperation::EditionCreateV2,
        AuthorityOperation::ObjectQueryReleasedV1,
        AuthorityOperation::ObjectQueryReleasedV2,
        AuthorityOperation::ReleaseCreateV2,
        AuthorityOperation::WorkspaceStatusV1,
    ];
    assert_eq!(
        all.len(),
        proof_application::authority::AUTHORITY_OPERATION_REGISTRY_V1.len()
    );
    assert_eq!(registry_ts.matches("pair(\"agent\"").count(), 14);
    for operation in all {
        let key = format!(
            "\"{}:{}\"",
            operation.name(),
            operation.version().rsplit('/').next().unwrap()
        );
        assert!(
            registry_ts.contains(&key) && registry_ts.contains(operation.version()),
            "TypeScript SDK Agent registry is missing `{key}` at `{}`",
            operation.version()
        );
    }

    for (key, version) in [
        (
            "content-resource-intent.issue:v2",
            "proof.dev/operation/content-resource-intent.issue/v2",
        ),
        ("schema.get:v1", "proof.dev/operation/schema.get/v1"),
        ("schema.list:v1", "proof.dev/operation/schema.list/v1"),
        ("object.list:v1", "proof.dev/operation/object.list/v1"),
    ] {
        assert!(
            registry_ts.contains(&format!("\"{key}\"")) && registry_ts.contains(version),
            "TypeScript SDK Human registry is missing `{key}` at `{version}`"
        );
    }
}

#[test]
fn ts_input_types_stay_field_set_exact_against_rust_inputs() {
    let types_ts = sdk_source("types.ts");
    let authority = include_str!("../../proof-application/src/authority.rs");

    let cases: &[(&str, &str)] = &[
        (
            "LocalizedContextLimitsInput",
            "LocalizedContextLimitsInputV2",
        ),
        ("LocalizedPolicyRuleInput", "LocalizedPolicyRuleInputV2"),
        ("ContextBuildInputV1", "ContextBuildInputV1"),
        (
            "LocalizedContextBuildInputV2",
            "LocalizedContextBuildInputV2",
        ),
        (
            "LocalizedChangeSetCreateInputV2",
            "LocalizedChangeSetCreateInputV2",
        ),
        (
            "LocalizedExpectedSourceInput",
            "LocalizedExpectedSourceInputV2",
        ),
        (
            "LocalizedExpectedTargetInput",
            "LocalizedExpectedTargetInputV2",
        ),
        (
            "LocalizedChangeSetAddInputV2",
            "LocalizedChangeSetAddInputV2",
        ),
        ("ChangesetSubmitInputV2", "LocalizedChangeSetSubmitInputV2"),
        ("ChangesetCommitInputV2", "LocalizedChangeSetCommitInputV2"),
        ("EditionCreateInputV2", "LocalizedEditionCreateInputV2"),
        ("ReleaseCreateInputV2", "LocalizedReleaseCreateInputV2"),
        ("ReleasedTargetInput", "LocalizedReleasedTargetInputV2"),
        (
            "ObjectQueryReleasedInputV2",
            "LocalizedObjectQueryReleasedInputV2",
        ),
    ];
    // The three selector rows are generated by
    // `localized_changeset_selector_input!`; their field set is fixed by the
    // macro and cannot be extracted textually.
    let selector_fields = ["api_version".to_owned(), "changeset_id".to_owned()];
    for ts_name in [
        "ChangesetGetInputV2",
        "ChangesetDiffInputV2",
        "ChangesetValidateInputV2",
    ] {
        assert_interface_covers(&types_ts, ts_name, &selector_fields);
    }
    for (ts_name, rust_name) in cases {
        if *ts_name == "ChangesetGetInputV2"
            || *ts_name == "ChangesetDiffInputV2"
            || *ts_name == "ChangesetValidateInputV2"
        {
            continue;
        }
        let fields = rust_struct_fields(authority, rust_name);
        assert!(!fields.is_empty(), "{rust_name} produced no fields");
        assert_interface_covers(&types_ts, ts_name, &fields);
    }

    for rust_name in [
        "LocalizedObjectLocalePutEditInputV2",
        "LocalizedObjectCreateEditInputV2",
    ] {
        for field in rust_struct_fields(authority, rust_name) {
            assert!(
                types_ts.contains(&format!("{field}:")),
                "TypeScript Edit union is missing `{field}` from {rust_name}"
            );
        }
    }
}

#[test]
fn ts_transport_envelopes_match_the_server_handlers() {
    let types_ts = sdk_source("types.ts");
    let human = interface_block(&types_ts, "HumanOperationRequest").unwrap();
    for member in [
        "api_version:",
        "workspace_id:",
        "operation:",
        "correlation_id:",
        "idempotency_key:",
        "input:",
    ] {
        assert!(
            human.contains(member),
            "Human envelope is missing `{member}`"
        );
    }
    assert!(!human.contains("invocation:"));

    let agent = interface_block(&types_ts, "AgentOperationRequest").unwrap();
    for member in [
        "api_version:",
        "operation:",
        "correlation_id:",
        "invocation:",
    ] {
        assert!(
            agent.contains(member),
            "Agent envelope is missing `{member}`"
        );
    }
    for forbidden in ["workspace_id:", "idempotency_key:", "input:"] {
        assert!(
            !agent.contains(forbidden),
            "Agent envelope admits `{forbidden}`"
        );
    }

    let success = interface_block(&types_ts, "SuccessEnvelope").unwrap();
    for member in [
        "api_version:",
        "operation:",
        "operation_id:",
        "correlation_id:",
        "replayed:",
        "result_anchor:",
        "result_schema:",
        "data:",
    ] {
        assert!(
            success.contains(member),
            "TypeScript success envelope is missing `{member}`"
        );
    }
    for retired in ["committed_anchor:", "result:"] {
        assert!(
            !success.contains(retired),
            "retired success member `{retired}` remains"
        );
    }

    assert!(types_ts.contains("kind: \"committed-transaction\""));
    assert!(types_ts.contains("kind: \"immutable-result\""));
    assert!(types_ts.contains("transaction_sequence: number"));
    assert!(types_ts.contains("transaction_sequence: null"));

    assert!(types_ts.contains("kind: \"object.locale.put\""));
    assert!(types_ts.contains("kind: \"object.create\""));
    assert!(types_ts.contains("schema_id?: never"));
    assert!(types_ts.contains("locale?: never"));

    // Problem body members as written by `ProblemResponse::into_response`.
    for member in ["retryable", "instance", "retry_after_ms"] {
        assert!(
            types_ts.contains(member),
            "TypeScript problem type is missing `{member}`"
        );
    }
}

#[test]
fn sdk_sources_exist_in_the_expected_layout() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for relative in [
        "../../web/packages/proof-sdk/package.json",
        "../../web/packages/proof-sdk/src/index.ts",
        "../../web/packages/proof-sdk/test/wire.spec.ts",
    ] {
        let path = manifest_dir.join(relative);
        assert!(
            Path::new(&path).is_file(),
            "expected SDK artifact at {}",
            path.display()
        );
    }
}
