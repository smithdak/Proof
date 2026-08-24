use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    process::Command,
};

use serde_json::Value;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the exact dependency sets keep every workspace layer visible in one architecture guard"
)]
fn inward_dependency_boundaries_are_enforced() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(&workspace)
        .output()
        .expect("cargo metadata should run");
    assert!(output.status.success());

    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    let domain = normal_dependencies(packages, "proof-domain");
    let application = normal_dependencies(packages, "proof-application");
    let attestation = normal_dependencies(packages, "proof-attestation");
    let canonical = normal_dependencies(packages, "proof-canonical");
    let local = normal_dependencies(packages, "proof-local");
    let cli = normal_dependencies(packages, "proof-cli");
    let mcp = normal_dependencies(packages, "proof-mcp");
    let signer = normal_dependencies(packages, "proof-agent-signer");
    let verifier = normal_dependencies(packages, "proof-verifier");

    assert_eq!(
        domain,
        BTreeSet::from(["thiserror".to_owned(), "time".to_owned(), "uuid".to_owned(),])
    );
    assert_eq!(
        application,
        BTreeSet::from([
            "base64".to_owned(),
            "proof-canonical".to_owned(),
            "proof-domain".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "thiserror".to_owned(),
        ]),
        "application contracts may depend inward, never on interface or adapter crates"
    );
    assert_eq!(
        attestation,
        BTreeSet::from([
            "base64".to_owned(),
            "ed25519-dalek".to_owned(),
            "getrandom".to_owned(),
            "proof-canonical".to_owned(),
            "proof-domain".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "thiserror".to_owned(),
            "zeroize".to_owned(),
        ]),
        "attestation may depend on deterministic codecs, cryptography, and inward domain contracts"
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
    assert_eq!(
        local,
        BTreeSet::from([
            "base64".to_owned(),
            "getrandom".to_owned(),
            "jsonschema".to_owned(),
            "proof-application".to_owned(),
            "proof-attestation".to_owned(),
            "proof-canonical".to_owned(),
            "rusqlite".to_owned(),
            "rustix".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "thiserror".to_owned(),
            "toml".to_owned(),
            "zeroize".to_owned(),
        ]),
        "local storage is an adapter and may only depend inward plus infrastructure libraries"
    );
    assert_eq!(
        cli,
        BTreeSet::from([
            "clap".to_owned(),
            "proof-application".to_owned(),
            "proof-attestation".to_owned(),
            "proof-canonical".to_owned(),
            "proof-local".to_owned(),
            "rustix".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "uuid".to_owned(),
            "zeroize".to_owned(),
        ]),
        "the CLI may compose application contracts and adapters but owns no domain behavior"
    );
    assert_eq!(
        mcp,
        BTreeSet::from([
            "clap".to_owned(),
            "proof-application".to_owned(),
            "proof-attestation".to_owned(),
            "proof-local".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "uuid".to_owned(),
        ]),
        "the MCP interface may compose application contracts and adapters but owns no domain behavior"
    );
    assert_eq!(
        signer,
        BTreeSet::from([
            "clap".to_owned(),
            "proof-application".to_owned(),
            "proof-attestation".to_owned(),
            "proof-canonical".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "uuid".to_owned(),
            "zeroize".to_owned(),
        ]),
        "the Agent signer may depend on signing/application contracts but never the Workspace adapter or SQLite"
    );
    assert_eq!(
        verifier,
        BTreeSet::from([
            "base64".to_owned(),
            "blake3".to_owned(),
            "ed25519-dalek".to_owned(),
            "jsonschema".to_owned(),
            "proof-remote".to_owned(),
            "serde".to_owned(),
            "serde_json".to_owned(),
            "serde_json_canonicalizer".to_owned(),
            "thiserror".to_owned(),
            "time".to_owned(),
        ]),
        "the independent verifier owns its strict wire, canonicalization, digest, and signature \
         path; since Milestone 3 it consumes exactly one shared contract crate (proof-remote) for \
         frozen wire types and registries"
    );
    assert_no_reachable_dependencies(
        &workspace,
        "proof-agent-signer",
        &["proof-cli", "proof-local", "proof-mcp", "rusqlite"],
    );
    assert_no_reachable_dependencies(
        &workspace,
        "proof-verifier",
        &[
            // Producer, interface, and delivery crates: the verifier verifies
            // exported evidence and never links the systems that produce it.
            "proof-server",
            "proof-cli",
            "proof-mcp",
            "proof-pg",
            "proof-delivery",
            // No HTTP server stack or database driver may enter the offline
            // verifier process; `rusqlite` is admitted only through the shared
            // proof-remote contract crate's local-evidence reader.
            "axum",
            "hyper",
            "hyper-util",
            "tokio",
            "postgres",
        ],
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

fn assert_no_reachable_dependencies(workspace: &Path, package_name: &str, forbidden: &[&str]) {
    let dependencies = resolved_dependency_names(workspace, package_name);
    for forbidden_name in forbidden {
        assert!(
            !dependencies.contains(*forbidden_name),
            "{package_name} reaches forbidden dependency {forbidden_name}"
        );
    }
}

fn resolved_dependency_names(workspace: &Path, package_name: &str) -> BTreeSet<String> {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(workspace)
        .output()
        .expect("resolved cargo metadata should run");
    assert!(output.status.success());
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let packages = metadata["packages"].as_array().unwrap();
    let package_names = packages
        .iter()
        .map(|package| {
            (
                package["id"].as_str().unwrap().to_owned(),
                package["name"].as_str().unwrap().to_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let package_id = packages
        .iter()
        .find(|package| package["name"] == package_name)
        .unwrap_or_else(|| panic!("missing package {package_name}"))["id"]
        .as_str()
        .unwrap();
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| (node["id"].as_str().unwrap().to_owned(), node))
        .collect::<BTreeMap<_, _>>();
    let mut pending = vec![package_id.to_owned()];
    let mut visited = BTreeSet::new();
    let mut dependency_names = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let node = nodes
            .get(&current)
            .unwrap_or_else(|| panic!("missing resolve node {current}"));
        for dependency in node["deps"].as_array().unwrap() {
            let dependency_id = dependency["pkg"].as_str().unwrap();
            dependency_names.insert(package_names[dependency_id].clone());
            pending.push(dependency_id.to_owned());
        }
    }
    dependency_names
}
