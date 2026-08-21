#![forbid(unsafe_code)]

use std::{
    env, fs,
    io::{self, Write as _},
    path::PathBuf,
    process,
};

use proof_verifier::{
    VerificationRequest, canonical_report, model::Outcome, verify_bundle_directory,
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
    let Ok(cli) = parse_cli(env::args().skip(1)) else {
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
    let Ok((bytes, _)) = canonical_report(&report) else {
        eprintln!("proof-verifier: proof.verify.report");
        process::exit(EXIT_INVALID);
    };
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
