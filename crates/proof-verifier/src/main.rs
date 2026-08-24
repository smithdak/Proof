#![forbid(unsafe_code)]

use std::{
    env, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process,
};

use proof_remote::{
    RemoteVerifierInputApiVersion, RemoteVerifierInputType, RemoteVerifierInputV2,
    VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT, VerificationTrustPolicyV2, derive_key_digest,
};
use proof_verifier::{
    VerificationRequest, canonical_report, model::Outcome,
    remote_authority::RemoteAuthoritySuffixInput, remote_authority::verify_remote_authority_suffix,
    remote_evidence::verify_remote_evidence_v2, verify_bundle_directory,
};

const EXIT_COMPLETE: i32 = 0;
const EXIT_INCOMPLETE: i32 = 20;
const EXIT_INVALID: i32 = 21;
const EXIT_USAGE: i32 = 64;

struct Cli {
    bundle: PathBuf,
    trust: PathBuf,
    checkpoint: Option<PathBuf>,
    external_roots: Vec<PathBuf>,
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(subcommand) = args.first().map(String::as_str) else {
        eprintln!("proof-verifier: proof.verify.usage");
        process::exit(EXIT_USAGE);
    };
    match subcommand {
        "verify" => run_verify(&args),
        "remote-authority" => run_remote_authority(&args[1..]),
        "remote-evidence" => run_remote_evidence(&args[1..]),
        _ => {
            eprintln!("proof-verifier: proof.verify.usage");
            process::exit(EXIT_USAGE);
        }
    }
}

fn run_verify(args: &[String]) {
    let Ok(cli) = parse_cli(args.iter().cloned()) else {
        eprintln!("proof-verifier: proof.verify.usage");
        process::exit(EXIT_USAGE);
    };
    let Ok(trust) = read_input(&cli.trust, proof_verifier::model::MAX_MANIFEST_BYTES) else {
        eprintln!("proof-verifier: proof.verify.input");
        process::exit(EXIT_USAGE);
    };
    let Ok(checkpoint) = cli
        .checkpoint
        .as_deref()
        .map(|path| read_input(path, proof_verifier::model::MAX_ARTIFACT_BYTES))
        .transpose()
    else {
        eprintln!("proof-verifier: proof.verify.input");
        process::exit(EXIT_USAGE);
    };
    let report = verify_bundle_directory(VerificationRequest {
        bundle_root: &cli.bundle,
        trust_policy_json: &trust,
        checkpoint_json: checkpoint.as_deref(),
        external_roots: &cli.external_roots,
    });
    let (bytes, _) = canonical_report(&report)
        .expect("the typed verification report must always have a canonical representation");
    let mut stdout = io::stdout().lock();
    if stdout.write_all(&bytes).is_err() || stdout.write_all(b"\n").is_err() {
        process::exit(EXIT_USAGE);
    }
    let exit = match report.outcome {
        Outcome::Complete => EXIT_COMPLETE,
        Outcome::Incomplete => EXIT_INCOMPLETE,
        Outcome::Invalid => EXIT_INVALID,
    };
    process::exit(exit);
}

/// CLI plumbing stub for `proof-verifier/remote-authority/v1` (contract
/// §"Evidence export and independent verification").
fn run_remote_authority(args: &[String]) {
    let mut trust = None;
    let mut records = Vec::new();
    let mut arguments = args.iter();
    while let Some(flag) = arguments.next() {
        let Some(value) = arguments.next() else {
            eprintln!("proof-verifier: proof.verify.usage");
            process::exit(EXIT_USAGE);
        };
        match flag.as_str() {
            "--trust" if trust.is_none() => trust = Some(value.clone()),
            "--records" => records.push(value.clone()),
            _ => {
                eprintln!("proof-verifier: proof.verify.usage");
                process::exit(EXIT_USAGE);
            }
        }
    }
    let Some(trust_path) = trust else {
        eprintln!("proof-verifier: proof.verify.usage");
        process::exit(EXIT_USAGE);
    };
    let trust_bytes = read_input(Path::new(&trust_path), proof_remote::MAX_MANIFEST_BYTES)
        .unwrap_or_else(|()| {
            eprintln!("proof-verifier: proof.verify.input");
            process::exit(EXIT_USAGE);
        });
    let policy: VerificationTrustPolicyV2 =
        serde_json::from_slice(&trust_bytes).unwrap_or_else(|error| {
            eprintln!("proof-verifier: proof.verify.input: {error}");
            process::exit(EXIT_USAGE);
        });
    let envelopes: Vec<Vec<u8>> = records
        .iter()
        .map(|path| {
            read_input(
                Path::new(path),
                proof_remote::MAX_AUTHORITY_RECORDS * 98_304,
            )
            .unwrap_or_else(|()| {
                eprintln!("proof-verifier: proof.verify.input");
                process::exit(EXIT_USAGE);
            })
        })
        .collect();
    let input = RemoteAuthoritySuffixInput {
        envelopes: &envelopes,
        initial_root_key_id: &policy.authority.initial_root.key_id,
        initial_head: policy.authority.initial_head,
    };
    match verify_remote_authority_suffix(&input) {
        Ok(output) => {
            emit_json(&output.included_head);
        }
        Err(_) => process::exit(EXIT_INVALID),
    }
}

/// CLI plumbing stub for `proof-verifier/remote-evidence-v2` (contract
/// §"Evidence export and independent verification").
fn run_remote_evidence(args: &[String]) {
    let mut bundle = None;
    let mut trust = None;
    let mut checkpoint = None;
    let mut external_roots = Vec::new();
    let mut arguments = args.iter();
    while let Some(flag) = arguments.next() {
        let Some(value) = arguments.next() else {
            eprintln!("proof-verifier: proof.verify.usage");
            process::exit(EXIT_USAGE);
        };
        match flag.as_str() {
            "--bundle" if bundle.is_none() => bundle = Some(value.clone()),
            "--trust" if trust.is_none() => trust = Some(value.clone()),
            "--checkpoint" if checkpoint.is_none() => checkpoint = Some(value.clone()),
            "--external-root" => external_roots.push(value.clone()),
            _ => {
                eprintln!("proof-verifier: proof.verify.usage");
                process::exit(EXIT_USAGE);
            }
        }
    }
    let (Some(bundle_path), Some(trust_path)) = (bundle, trust) else {
        eprintln!("proof-verifier: proof.verify.usage");
        process::exit(EXIT_USAGE);
    };
    let bundle_root = PathBuf::from(bundle_path);
    let _checkpoint = checkpoint.map(PathBuf::from);
    let _external_roots: Vec<PathBuf> = external_roots.into_iter().map(PathBuf::from).collect();
    let trust_bytes = read_input(Path::new(&trust_path), proof_remote::MAX_MANIFEST_BYTES)
        .unwrap_or_else(|()| {
            eprintln!("proof-verifier: proof.verify.input");
            process::exit(EXIT_USAGE);
        });
    let policy: VerificationTrustPolicyV2 =
        serde_json::from_slice(&trust_bytes).unwrap_or_else(|error| {
            eprintln!("proof-verifier: proof.verify.input: {error}");
            process::exit(EXIT_USAGE);
        });
    let verifier_input = RemoteVerifierInputV2 {
        r#type: RemoteVerifierInputType::Tag,
        api_version: RemoteVerifierInputApiVersion::Tag,
        trust_policy_digest: derive_key_digest(
            VERIFICATION_TRUST_POLICY_DIGEST_CONTEXT,
            &trust_bytes,
        ),
        verification_trust_policy: policy,
        subject_openings: Vec::new(),
        authority_checkpoint: None,
        environment_release_checkpoint: None,
        external_artifacts: Vec::new(),
        bundle_hints_are_authority: false,
        network_access: false,
        database_access: false,
        session_access: false,
        private_key_count: 0,
        credential_count: 0,
    };
    let members = read_member_map(&bundle_root);
    let report = verify_remote_evidence_v2(&members, &verifier_input);
    emit_json(&report);
}

fn read_member_map(bundle_root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let _ = bundle_root;
    todo!("read the logical member map from the bundle directory")
}

fn emit_json(value: &impl serde::Serialize) {
    let bytes = serde_json::to_string(value).expect("the report always serializes");
    let mut stdout = io::stdout().lock();
    if stdout.write_all(bytes.as_bytes()).is_err() || stdout.write_all(b"\n").is_err() {
        process::exit(EXIT_USAGE);
    }
}

fn parse_cli(arguments: impl Iterator<Item = String>) -> Result<Cli, ()> {
    let mut arguments = arguments;
    if arguments.next().as_deref() != Some("verify") {
        return Err(());
    }
    let mut bundle = None;
    let mut trust = None;
    let mut checkpoint = None;
    let mut external_roots = Vec::new();
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(())?;
        match flag.as_str() {
            "--bundle" if bundle.is_none() => bundle = Some(PathBuf::from(value)),
            "--trust" if trust.is_none() => trust = Some(PathBuf::from(value)),
            "--checkpoint" if checkpoint.is_none() => checkpoint = Some(PathBuf::from(value)),
            "--external-root"
                if external_roots.len() < proof_verifier::model::MAX_EXTERNAL_ROOTS =>
            {
                external_roots.push(PathBuf::from(value));
            }
            _ => return Err(()),
        }
    }
    Ok(Cli {
        bundle: bundle.ok_or(())?,
        trust: trust.ok_or(())?,
        checkpoint,
        external_roots,
    })
}

fn read_input(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit as u64 {
        return Err(());
    }
    let bytes = fs::read(path).map_err(|_| ())?;
    if bytes.len() > limit {
        return Err(());
    }
    Ok(bytes)
}
