use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

const REGISTRY_JSON: &str = include_str!("../../../conformance/v1/verifier-finding-codes.json");
const REPORT_SOURCES: &[(&str, &str)] = &[
    ("container.rs", include_str!("../src/container.rs")),
    ("crypto.rs", include_str!("../src/crypto.rs")),
    ("lib.rs", include_str!("../src/lib.rs")),
    ("model.rs", include_str!("../src/model.rs")),
    ("operation.rs", include_str!("../src/operation.rs")),
    ("schema.rs", include_str!("../src/schema.rs")),
    ("semantics.rs", include_str!("../src/semantics.rs")),
    ("strict_json.rs", include_str!("../src/strict_json.rs")),
];
const CLI_SOURCES: &[(&str, &str)] = &[("main.rs", include_str!("../src/main.rs"))];
const BEHAVIORAL_TEST_SOURCES: &[(&str, &str)] = &[
    ("portable_matrix", include_str!("portable_matrix.rs")),
    ("public_cli", include_str!("public_cli.rs")),
    ("security_matrix", include_str!("security_matrix.rs")),
];
const API_VERSION: &str = "proof.dev/verifier-finding-code-registry/v1";
const NAMESPACE: &str = "proof.verify.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    api_version: String,
    namespace: String,
    report_findings: Surface,
    cli_diagnostics: Surface,
    coverage: Coverage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Surface {
    code_count: usize,
    families: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coverage {
    default: CoverageClaim,
    overrides: Vec<CoverageOverride>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageOverride {
    code: String,
    classification: CoverageClassification,
    evidence_target: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CoverageClassification {
    DirectBehavioral,
    FamilyMatrix,
    StructuralGuard,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CoverageClaim {
    classification: CoverageClassification,
    evidence_target: String,
    reason: String,
}

#[test]
fn public_finding_code_registry_matches_every_emitted_literal() {
    let registry: Registry =
        serde_json::from_str(REGISTRY_JSON).expect("finding-code registry must be valid JSON");
    assert_eq!(registry.api_version, API_VERSION);
    assert_eq!(registry.namespace, NAMESPACE);

    let registered_report = validate_surface("report_findings", &registry.report_findings, false);
    let registered_cli = validate_surface("cli_diagnostics", &registry.cli_diagnostics, true);
    assert!(
        registered_report.is_disjoint(&registered_cli),
        "a code cannot be both a structured finding and a CLI diagnostic"
    );
    let registered = registered_report
        .union(&registered_cli)
        .cloned()
        .collect::<BTreeSet<_>>();
    validate_coverage(&registry.coverage, &registered);

    let emitted_report = emitted_codes(REPORT_SOURCES);
    let emitted_cli = emitted_codes(CLI_SOURCES);
    assert_eq!(
        registered_report, emitted_report,
        "structured finding-code drift: update verifier code and the conformance registry together"
    );
    assert_eq!(
        registered_cli, emitted_cli,
        "CLI diagnostic-code drift: update verifier code and the conformance registry together"
    );
}

fn validate_coverage(coverage: &Coverage, registered: &BTreeSet<String>) {
    validate_claim(
        coverage.default.classification,
        &coverage.default.evidence_target,
        &coverage.default.reason,
    );
    assert_eq!(
        coverage.default.classification,
        CoverageClassification::StructuralGuard,
        "unlisted codes must conservatively default to structural_guard"
    );
    assert_eq!(
        coverage.default.evidence_target,
        "finding_code_registry::public_finding_code_registry_matches_every_emitted_literal"
    );
    assert!(
        coverage
            .overrides
            .windows(2)
            .all(|pair| pair[0].code < pair[1].code),
        "coverage overrides must be strictly sorted and duplicate-free"
    );

    let mut overridden = BTreeSet::new();
    for entry in &coverage.overrides {
        assert!(
            registered.contains(&entry.code),
            "coverage override names an unregistered or stale code: {:?}",
            entry.code
        );
        assert!(
            overridden.insert(entry.code.clone()),
            "coverage override duplicates {:?}",
            entry.code
        );
        validate_claim(entry.classification, &entry.evidence_target, &entry.reason);
        match entry.classification {
            CoverageClassification::DirectBehavioral => {
                assert_named_behavioral_assertion(&entry.evidence_target, &entry.code);
            }
            CoverageClassification::FamilyMatrix => {
                assert_named_test_exists(&entry.evidence_target, Some(&entry.code));
            }
            CoverageClassification::StructuralGuard => panic!(
                "structural_guard is the closed default; {:?} must not redundantly override it",
                entry.code
            ),
        }
    }

    for code in registered {
        let classifications =
            usize::from(overridden.contains(code)) + usize::from(!overridden.contains(code));
        assert_eq!(
            classifications, 1,
            "registered code must receive exactly one coverage classification: {code:?}"
        );
    }
}

fn validate_claim(_classification: CoverageClassification, evidence_target: &str, reason: &str) {
    assert!(
        !evidence_target.trim().is_empty(),
        "coverage evidence_target must not be empty"
    );
    assert!(
        !reason.trim().is_empty(),
        "coverage reason must not be empty"
    );
}

fn assert_named_behavioral_assertion(evidence_target: &str, code: &str) {
    let body = assert_named_test_exists(evidence_target, Some(code));
    let finding_assertion = format!("contains(&\"{code}\")");
    let cli_assertion = format!("{code}\\n");
    assert!(
        body.contains(&finding_assertion) || body.contains(&cli_assertion),
        "direct_behavioral target {evidence_target:?} must assert exact code {code:?}"
    );
}

fn assert_named_test_exists(evidence_target: &str, expected_code: Option<&str>) -> &'static str {
    let (suite, test) = evidence_target
        .split_once("::")
        .unwrap_or_else(|| panic!("evidence target must be suite::test: {evidence_target:?}"));
    let source = BEHAVIORAL_TEST_SOURCES
        .iter()
        .find_map(|(name, source)| (*name == suite).then_some(*source))
        .unwrap_or_else(|| panic!("unknown behavioral test suite: {suite:?}"));
    let marker = format!("fn {test}(");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("missing retained test target: {evidence_target:?}"));
    assert!(
        source[..start].trim_end().ends_with("#[test]"),
        "coverage target is not a retained #[test]: {evidence_target:?}"
    );
    let remainder = &source[start..];
    let end = remainder.find("\n#[test]").unwrap_or(remainder.len());
    let body = &remainder[..end];
    if let Some(code) = expected_code {
        assert!(
            body.contains(code),
            "coverage target {evidence_target:?} does not name {code:?}"
        );
    }
    body
}

fn validate_surface(
    name: &str,
    surface: &Surface,
    allows_family_only_code: bool,
) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    for (family, family_codes) in &surface.families {
        assert!(
            valid_segment(family),
            "{name} has invalid family {family:?}"
        );
        assert!(
            !family_codes.is_empty(),
            "{name} family {family:?} must not be empty"
        );
        assert!(
            family_codes.windows(2).all(|pair| pair[0] < pair[1]),
            "{name} family {family:?} must be strictly sorted and duplicate-free"
        );
        for code in family_codes {
            validate_code(name, family, code, allows_family_only_code);
            assert!(codes.insert(code.clone()), "{name} duplicates {code:?}");
        }
    }
    assert_eq!(
        surface.code_count,
        codes.len(),
        "{name}.code_count must match its closed code set"
    );
    codes
}

fn validate_code(surface: &str, family: &str, code: &str, allows_family_only_code: bool) {
    let suffix = code
        .strip_prefix(NAMESPACE)
        .unwrap_or_else(|| panic!("{surface} code is outside {NAMESPACE:?}: {code:?}"));
    let mut segments = suffix.split('.');
    assert_eq!(
        segments.next(),
        Some(family),
        "{surface} code is filed under the wrong family: {code:?}"
    );
    let remaining = segments.collect::<Vec<_>>();
    assert!(
        (allows_family_only_code || !remaining.is_empty())
            && remaining.iter().all(|segment| valid_segment(segment)),
        "{surface} code has an invalid or missing leaf: {code:?}"
    );
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn emitted_codes(sources: &[(&str, &str)]) -> BTreeSet<String> {
    let mut codes = BTreeSet::new();
    for (_, source) in sources {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for literal in rust_string_literals(production) {
            for code in codes_in_literal(&literal) {
                codes.insert(code);
            }
        }
    }
    codes
}

fn codes_in_literal(literal: &str) -> Vec<String> {
    let mut codes = Vec::new();
    let mut remainder = literal;
    while let Some(start) = remainder.find(NAMESPACE) {
        let candidate = &remainder[start..];
        let end = candidate
            .find(|character: char| {
                !(character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || matches!(character, '.' | '_'))
            })
            .unwrap_or(candidate.len());
        codes.push(candidate[..end].to_owned());
        remainder = &candidate[end..];
    }
    codes
}

fn rust_string_literals(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index..] {
            [b'/', b'/', ..] => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            [b'/', b'*', ..] => index = skip_block_comment(bytes, index + 2),
            [b'\'', b'"', b'\'', ..] => index += 3,
            [b'\'', b'\\', b'"', b'\'', ..] => index += 4,
            [b'r', ..] if raw_string_hashes(bytes, index).is_some() => {
                let hashes = raw_string_hashes(bytes, index).expect("raw-string start was checked");
                let content_start = index + hashes + 2;
                let (literal, end) = take_raw_string(source, content_start, hashes);
                literals.push(literal.to_owned());
                index = end;
            }
            [b'"', ..] => {
                let (literal, end) = take_quoted_string(source, index + 1);
                literals.push(literal.to_owned());
                index = end;
            }
            _ => index += 1,
        }
    }
    literals
}

fn skip_block_comment(bytes: &[u8], mut index: usize) -> usize {
    let mut depth = 1_usize;
    while index < bytes.len() && depth > 0 {
        match bytes[index..] {
            [b'/', b'*', ..] => {
                depth += 1;
                index += 2;
            }
            [b'*', b'/', ..] => {
                depth -= 1;
                index += 2;
            }
            _ => index += 1,
        }
    }
    index
}

fn raw_string_hashes(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start.checked_add(1)?;
    while bytes.get(index) == Some(&b'#') {
        index += 1;
    }
    (bytes.get(index) == Some(&b'"')).then_some(index - start - 1)
}

fn take_raw_string(source: &str, content_start: usize, hashes: usize) -> (&str, usize) {
    let terminator = format!("\"{}", "#".repeat(hashes));
    let relative_end = source[content_start..]
        .find(&terminator)
        .expect("source must contain a complete raw string literal");
    let content_end = content_start + relative_end;
    (
        &source[content_start..content_end],
        content_end + terminator.len(),
    )
}

fn take_quoted_string(source: &str, content_start: usize) -> (&str, usize) {
    let bytes = source.as_bytes();
    let mut index = content_start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => return (&source[content_start..index], index + 1),
            _ => index += 1,
        }
    }
    panic!("source must contain a complete string literal");
}
