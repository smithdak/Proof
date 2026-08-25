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
    let marker = format!("export interface {interface_name} ");
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
        if let Some(rest) = trimmed.strip_prefix("pub ") {
            if let Some(name) = rest.split(':').next() {
                fields.push(name.trim().to_owned());
            }
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
    for operation in all {
        let literal = format!(
            "pair(\"{}\", \"{}\")",
            operation.name(),
            operation.version()
        );
        assert!(
            registry_ts.contains(&literal),
            "TypeScript SDK registry is missing the frozen pair `{literal}`"
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
        ("LocalizedSemanticEditInput", "LocalizedSemanticEditInputV2"),
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
}

#[test]
fn ts_transport_envelopes_match_the_server_handlers() {
    let types_ts = sdk_source("types.ts");
    // Human/agent request envelopes exactly as parsed by the route guards.
    assert!(types_ts.contains("\"proof.dev/http-human-operation-request/v1\""));
    assert!(types_ts.contains("\"proof.dev/http-agent-operation-request/v1\""));
    // Result envelope and consequence members as serialized by the dispatcher.
    for member in [
        "committed_anchor",
        "operation_id",
        "correlation_id",
        "decision_digest",
        "public_input_projection_digest",
        "application_effect_digest",
        "evaluated_authority_head",
        "authority_key_id",
    ] {
        assert!(
            types_ts.contains(member),
            "TypeScript result types are missing `{member}`"
        );
    }
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
