use std::{collections::BTreeSet, path::Path, process::Command};

use serde_json::Value;

#[test]
fn inward_dependency_boundaries_are_enforced() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace)
        .output()
        .expect("cargo metadata should run");
    assert!(output.status.success());

    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    let domain = normal_dependencies(packages, "proof-domain");
    let application = normal_dependencies(packages, "proof-application");
    let canonical = normal_dependencies(packages, "proof-canonical");

    assert_eq!(
        domain,
        BTreeSet::from(["thiserror".to_owned(), "uuid".to_owned()])
    );
    assert_eq!(
        application,
        BTreeSet::from(["proof-domain".to_owned(), "serde".to_owned()]),
        "application contracts may depend inward, never on interface or adapter crates"
    );
    assert_eq!(
        canonical,
        BTreeSet::from([
            "blake3".to_owned(),
            "proof-domain".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "serde_json_canonicalizer".to_owned(),
            "thiserror".to_owned(),
        ]),
        "canonicalization may use deterministic codecs and hashing, never interfaces or storage"
    );
}

fn normal_dependencies(packages: &[Value], package_name: &str) -> BTreeSet<String> {
    let package = packages
        .iter()
        .find(|package| package["name"] == package_name)
        .unwrap_or_else(|| panic!("missing package {package_name}"));

    package["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|dependency| dependency["kind"].is_null())
        .map(|dependency| dependency["name"].as_str().unwrap().to_owned())
        .collect()
}
