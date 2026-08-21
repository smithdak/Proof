use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use proof_application::{
    ExitCode, Problem, ReleaseId, ResultEnvelope,
    evidence::{
        AuthorityEvidenceBundleExportV1, AuthorityEvidenceBundleReceiptV1,
        AuthorityEvidenceExportError, EvidenceAvailabilityV1,
        ExportAuthorityEvidenceBundleV1Command, SubjectOpeningDisclosureV1,
        export_authority_evidence_bundle,
    },
};
use proof_canonical::{canonicalize, digest, parse_strict};
use proof_local::LocalWorkspace;
use serde_json::{Value, json};

use super::{ExecutionContext, OutputFormat, write_json};

const OPERATION: &str = "evidence.export";
const MANIFEST_FILENAME: &str = "bundle.json";

#[derive(Debug, Subcommand)]
pub(super) enum EvidenceAction {
    /// Export one complete portable Release and authority-evidence closure.
    Export {
        /// Release `UUIDv7` whose transitive closure will be exported.
        #[arg(long)]
        release_id: String,

        /// New destination directory; an existing path is never overwritten.
        #[arg(long, value_name = "DIRECTORY")]
        directory: PathBuf,

        /// Include the protected requesting-subject opening for an authorized audit.
        #[arg(long)]
        include_subject_opening: bool,
    },
}

pub(super) fn run_evidence(
    action: EvidenceAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    match action {
        EvidenceAction::Export {
            release_id,
            directory,
            include_subject_opening,
        } => {
            let release_id = release_id
                .parse::<ReleaseId>()
                .map_err(|error| input_problem(context, format!("invalid release-id: {error}")))?;
            let root = selected_workspace.map_or_else(
                || env::current_dir().map_err(|_| workspace_problem(context)),
                |path| Ok(PathBuf::from(path)),
            )?;
            let repository = LocalWorkspace::new(root).map_err(|_| workspace_problem(context))?;
            let subject_opening = if include_subject_opening {
                SubjectOpeningDisclosureV1::Include
            } else {
                SubjectOpeningDisclosureV1::Withhold
            };
            let export = export_authority_evidence_bundle(
                &repository,
                ExportAuthorityEvidenceBundleV1Command {
                    release_id,
                    subject_opening,
                },
            )
            .map_err(|error| export_problem(&error, context))?;
            let plan =
                materialization_plan(&export).map_err(|error| export_problem(&error, context))?;
            let materialized_directory = materialize(&directory, &plan, context)?;
            let receipt = AuthorityEvidenceBundleReceiptV1 {
                release_id,
                manifest_digest: export.manifest_digest,
                included_authority_head: export.bundle.included_authority_head,
                descriptor_count: u32::try_from(export.bundle.artifacts.len()).map_err(|_| {
                    export_problem(&AuthorityEvidenceExportError::LimitExceeded, context)
                })?,
                included_artifact_count: u32::try_from(plan.artifacts.len()).map_err(|_| {
                    export_problem(&AuthorityEvidenceExportError::LimitExceeded, context)
                })?,
                included_bytes: plan.included_bytes,
            };
            render_receipt(
                output,
                context,
                &receipt,
                &materialized_directory,
                include_subject_opening,
            );
        }
    }
    Ok(ExitCode::Success)
}

struct MaterializationPlan {
    manifest: String,
    artifacts: BTreeMap<String, String>,
    included_bytes: u64,
}

fn materialization_plan(
    export: &AuthorityEvidenceBundleExportV1,
) -> Result<MaterializationPlan, AuthorityEvidenceExportError> {
    export.bundle.validate()?;
    let (manifest, manifest_digest) = export.bundle.canonical_manifest()?;
    if manifest != export.canonical_manifest_json || manifest_digest != export.manifest_digest {
        return Err(AuthorityEvidenceExportError::InvalidBundle(
            "producer manifest does not reproduce".to_owned(),
        ));
    }

    let mut included = BTreeMap::new();
    for descriptor in &export.bundle.artifacts {
        let EvidenceAvailabilityV1::Included { byte_length } = descriptor.availability else {
            continue;
        };
        let relative_path = descriptor.artifact.relative_path();
        if let Some((existing, existing_length)) =
            included.insert(relative_path, (descriptor.artifact, byte_length))
            && (existing != descriptor.artifact || existing_length != byte_length)
        {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "one included artifact ref has inconsistent descriptors".to_owned(),
            ));
        }
    }

    let mut artifacts = BTreeMap::<String, String>::new();
    for artifact in &export.artifacts {
        let relative_path = artifact.artifact.relative_path();
        let Some((expected_ref, byte_length)) = included.get(&relative_path) else {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "materialized artifact is absent from the included manifest refs".to_owned(),
            ));
        };
        if artifact.artifact != *expected_ref {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "materialized artifact disagrees with its manifest ref".to_owned(),
            ));
        }
        let parsed = parse_strict(artifact.canonical_json.as_bytes())
            .map_err(|error| AuthorityEvidenceExportError::InvalidBundle(error.to_string()))?;
        let canonical = canonicalize(&parsed)
            .map_err(|error| AuthorityEvidenceExportError::InvalidBundle(error.to_string()))?;
        if canonical.as_str() != artifact.canonical_json
            || u64::try_from(canonical.as_bytes().len())
                .map_err(|_| AuthorityEvidenceExportError::LimitExceeded)?
                != *byte_length
            || digest(artifact.artifact.artifact_kind, &canonical) != artifact.artifact.digest
        {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "materialized artifact does not reproduce its descriptor".to_owned(),
            ));
        }
        if artifacts
            .insert(relative_path, artifact.canonical_json.clone())
            .is_some()
        {
            return Err(AuthorityEvidenceExportError::InvalidBundle(
                "one content-addressed artifact ref was materialized more than once".to_owned(),
            ));
        }
    }

    if included
        .keys()
        .any(|relative_path| !artifacts.contains_key(relative_path))
    {
        return Err(AuthorityEvidenceExportError::Incomplete(
            "an included artifact ref was not materialized".to_owned(),
        ));
    }

    let included_bytes = artifacts.values().try_fold(0_u64, |total, artifact| {
        let length = u64::try_from(artifact.len())
            .map_err(|_| AuthorityEvidenceExportError::LimitExceeded)?;
        total
            .checked_add(length)
            .ok_or(AuthorityEvidenceExportError::LimitExceeded)
    })?;
    Ok(MaterializationPlan {
        manifest,
        artifacts,
        included_bytes,
    })
}

fn materialize(
    destination: &Path,
    plan: &MaterializationPlan,
    context: ExecutionContext,
) -> Result<PathBuf, Box<Problem>> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err(destination_conflict_problem(context));
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    let parent = match parent {
        Some(parent) => parent.to_path_buf(),
        None => env::current_dir().map_err(|_| storage_problem(context))?,
    };
    let metadata = fs::symlink_metadata(&parent).map_err(|_| storage_problem(context))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(storage_problem(context));
    }
    let staging = parent.join(format!(".proof-evidence-{}.staging", context.operation_id));
    create_private_directory(&staging).map_err(|_| storage_problem(context))?;
    if write_materialization(&staging, plan).is_err() {
        cleanup_staging(&staging).map_err(|_| storage_problem(context))?;
        return Err(storage_problem(context));
    }
    if let Err(error) = publish_without_replacement(&staging, destination) {
        let conflict = fs::symlink_metadata(destination).is_ok();
        cleanup_staging(&staging).map_err(|_| storage_problem(context))?;
        return Err(if error.kind() == io::ErrorKind::Unsupported {
            platform_unavailable_problem(context)
        } else if conflict {
            destination_conflict_problem(context)
        } else {
            storage_problem(context)
        });
    }
    sync_directory(&parent).map_err(|_| storage_problem(context))?;
    fs::canonicalize(destination).map_err(|_| storage_problem(context))
}

fn cleanup_staging(staging: &Path) -> io::Result<()> {
    match fs::remove_dir_all(staging) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_materialization(directory: &Path, plan: &MaterializationPlan) -> io::Result<()> {
    write_new_file(&directory.join(MANIFEST_FILENAME), plan.manifest.as_bytes())?;
    for (relative_path, canonical_json) in &plan.artifacts {
        let path = directory.join(relative_path);
        let parent = path
            .parent()
            .expect("content-addressed artifact path always has a parent");
        fs::create_dir_all(parent)?;
        write_new_file(&path, canonical_json.as_bytes())?;
    }
    sync_materialization_directories(directory)
}

#[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
fn publish_without_replacement(staging: &Path, destination: &Path) -> io::Result<()> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging,
        rustix::fs::CWD,
        destination,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
}

#[cfg(windows)]
fn publish_without_replacement(_staging: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace evidence publication is not implemented on Windows",
    ))
}

#[cfg(not(any(
    target_vendor = "apple",
    target_os = "linux",
    target_os = "redox",
    windows
)))]
fn publish_without_replacement(_staging: &Path, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no atomic no-replace directory publication primitive",
    ))
}

#[cfg(unix)]
fn sync_materialization_directories(root: &Path) -> io::Result<()> {
    use std::cmp::Reverse;

    let mut directories = vec![root.to_path_buf()];
    let mut index = 0_usize;
    while index < directories.len() {
        for entry in fs::read_dir(&directories[index])? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
        index += 1;
    }
    directories.sort_by_key(|path| Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "all platform materializers share one fallible durability contract"
)]
fn sync_materialization_directories(_root: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "all platform materializers share one fallible durability contract"
)]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

fn render_receipt(
    output: OutputFormat,
    context: ExecutionContext,
    receipt: &AuthorityEvidenceBundleReceiptV1,
    directory: &Path,
    subject_opening_included: bool,
) {
    let data = json!({
        "release_id": receipt.release_id.to_string(),
        "manifest_digest": receipt.manifest_digest.to_string(),
        "included_authority_head": {
            "sequence": receipt.included_authority_head.sequence.get(),
            "record_digest": receipt.included_authority_head.record_digest.to_string(),
        },
        "descriptor_count": receipt.descriptor_count,
        "included_artifact_count": receipt.included_artifact_count,
        "included_bytes": receipt.included_bytes,
        "directory": directory.display().to_string(),
        "subject_opening_included": subject_opening_included,
    });
    let result = ResultEnvelope::success(
        OPERATION,
        context.operation_id,
        context.correlation_id,
        data,
    );
    match output {
        OutputFormat::Json => write_json(&result),
        OutputFormat::Text => {
            print!("{}", text_receipt(&result.data));
        }
    }
}

fn text_receipt(data: &Value) -> String {
    format!(
        concat!(
            "Evidence bundle for Release {}\n",
            "directory: {}\n",
            "manifest digest: {}\n",
            "authority head sequence: {}\n",
            "authority head record digest: {}\n",
            "descriptors: {}\n",
            "included artifacts: {}\n",
            "included bytes: {}\n",
            "subject opening included: {}\n",
        ),
        data["release_id"],
        data["directory"],
        data["manifest_digest"],
        data["included_authority_head"]["sequence"],
        data["included_authority_head"]["record_digest"],
        data["descriptor_count"],
        data["included_artifact_count"],
        data["included_bytes"],
        data["subject_opening_included"],
    )
}

fn input_problem(context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The supplied evidence export input is invalid",
        "proof.input.schema_mismatch",
        OPERATION,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

fn workspace_problem(context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:resource-not-found",
        "The selected Workspace root is unavailable",
        "proof.resource.not_found",
        context,
        false,
    )
}

fn destination_conflict_problem(context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:state-conflict",
        "The evidence destination already exists",
        "proof.state.conflict",
        context,
        false,
    )
}

fn storage_problem(context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:dependency-unavailable",
        "Portable evidence storage is unavailable",
        "proof.dependency.unavailable",
        context,
        true,
    )
}

fn platform_unavailable_problem(context: ExecutionContext) -> Box<Problem> {
    mapped_problem(
        "urn:proof:problem:dependency-unavailable",
        "Portable evidence publication is unavailable on this platform",
        "proof.dependency.unavailable",
        context,
        false,
    )
}

fn export_problem(error: &AuthorityEvidenceExportError, context: ExecutionContext) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        AuthorityEvidenceExportError::AccessDenied => (
            "urn:proof:problem:authority-denied",
            "Portable evidence export requires the authenticated bootstrap Human",
            "proof.auth.denied",
            false,
        ),
        AuthorityEvidenceExportError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The requested Release resource was not found",
            "proof.resource.not_found",
            false,
        ),
        AuthorityEvidenceExportError::Incomplete(_) => (
            "urn:proof:problem:evidence-incomplete",
            "The portable authority-evidence closure is incomplete",
            "proof.evidence.incomplete",
            false,
        ),
        AuthorityEvidenceExportError::InvalidBundle(_) => (
            "urn:proof:problem:evidence-invalid",
            "The portable authority-evidence closure is invalid",
            "proof.evidence.invalid",
            false,
        ),
        AuthorityEvidenceExportError::LimitExceeded => (
            "urn:proof:problem:evidence-limit-exceeded",
            "The portable authority-evidence closure exceeds a v1 bound",
            "proof.evidence.limit_exceeded",
            false,
        ),
        AuthorityEvidenceExportError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Portable evidence storage is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
    };
    mapped_problem(problem_type, title, code, context, retryable)
}

fn mapped_problem(
    problem_type: &str,
    title: &str,
    code: &str,
    context: ExecutionContext,
    retryable: bool,
) -> Box<Problem> {
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        OPERATION,
        context.operation_id,
        context.correlation_id,
    );
    problem.retryable = retryable;
    Box::new(problem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn export_errors_have_exhaustive_caller_safe_problem_projections() {
        const PRIVATE_DETAIL: &str = "private repository evidence detail";
        let cases = [
            AuthorityEvidenceExportError::AccessDenied,
            AuthorityEvidenceExportError::NotFound,
            AuthorityEvidenceExportError::Incomplete(PRIVATE_DETAIL.to_owned()),
            AuthorityEvidenceExportError::InvalidBundle(PRIVATE_DETAIL.to_owned()),
            AuthorityEvidenceExportError::LimitExceeded,
            AuthorityEvidenceExportError::Storage(PRIVATE_DETAIL.to_owned()),
        ];

        for error in cases {
            let (problem_type, title, code, retryable) = expected_export_problem(&error);
            let problem = export_problem(&error, execution_context());
            assert_eq!(problem.problem_type, problem_type);
            assert_eq!(problem.title, title);
            assert_eq!(problem.code, code);
            assert_eq!(problem.retryable, retryable);
            assert_eq!(problem.operation, OPERATION);
            assert!(problem.detail.is_none());
            let public_projection = serde_json::to_value(&problem).unwrap();
            assert!(public_projection.get("detail").is_none());
            assert!(!public_projection.to_string().contains(PRIVATE_DETAIL));
        }
    }

    #[test]
    fn materialization_errors_have_exact_caller_safe_problem_projections() {
        let context = execution_context();
        let cases = [
            (
                destination_conflict_problem(context),
                "urn:proof:problem:state-conflict",
                "The evidence destination already exists",
                "proof.state.conflict",
                false,
            ),
            (
                storage_problem(context),
                "urn:proof:problem:dependency-unavailable",
                "Portable evidence storage is unavailable",
                "proof.dependency.unavailable",
                true,
            ),
            (
                platform_unavailable_problem(context),
                "urn:proof:problem:dependency-unavailable",
                "Portable evidence publication is unavailable on this platform",
                "proof.dependency.unavailable",
                false,
            ),
        ];

        for (problem, problem_type, title, code, retryable) in cases {
            assert_eq!(problem.problem_type, problem_type);
            assert_eq!(problem.title, title);
            assert_eq!(problem.code, code);
            assert_eq!(problem.retryable, retryable);
            assert_eq!(problem.operation, OPERATION);
            assert!(problem.detail.is_none());
            assert!(
                serde_json::to_value(&problem)
                    .unwrap()
                    .get("detail")
                    .is_none()
            );
        }
    }

    #[test]
    fn evidence_command_input_and_workspace_problems_have_exact_projections() {
        let context = execution_context();
        let detail = "invalid release-id: not a UUIDv7";
        let input = input_problem(context, detail.to_owned());
        assert_eq!(
            (
                input.problem_type.as_str(),
                input.title.as_str(),
                input.code.as_str(),
                input.retryable,
                input.detail.as_deref(),
            ),
            (
                "urn:proof:problem:input-schema-mismatch",
                "The supplied evidence export input is invalid",
                "proof.input.schema_mismatch",
                false,
                Some(detail),
            )
        );

        let workspace = workspace_problem(context);
        assert_eq!(
            (
                workspace.problem_type.as_str(),
                workspace.title.as_str(),
                workspace.code.as_str(),
                workspace.retryable,
            ),
            (
                "urn:proof:problem:resource-not-found",
                "The selected Workspace root is unavailable",
                "proof.resource.not_found",
                false,
            )
        );
        assert!(workspace.detail.is_none());
    }

    #[test]
    fn text_receipt_is_an_exact_projection_of_json_receipt_data() {
        let data = json!({
            "release_id": "019d2000-0000-7000-8000-000000000057",
            "manifest_digest": format!("blake3:{}", "1".repeat(64)),
            "included_authority_head": {
                "sequence": 42,
                "record_digest": format!("blake3:{}", "2".repeat(64)),
            },
            "descriptor_count": 17,
            "included_artifact_count": 13,
            "included_bytes": 4096,
            "directory": "/tmp/portable-evidence",
            "subject_opening_included": false,
        });
        let expected = format!(
            concat!(
                "Evidence bundle for Release \"019d2000-0000-7000-8000-000000000057\"\n",
                "directory: \"/tmp/portable-evidence\"\n",
                "manifest digest: \"blake3:{}\"\n",
                "authority head sequence: 42\n",
                "authority head record digest: \"blake3:{}\"\n",
                "descriptors: 17\n",
                "included artifacts: 13\n",
                "included bytes: 4096\n",
                "subject opening included: false\n",
            ),
            "1".repeat(64),
            "2".repeat(64),
        );
        assert_eq!(text_receipt(&data), expected);
    }

    fn expected_export_problem(
        error: &AuthorityEvidenceExportError,
    ) -> (&'static str, &'static str, &'static str, bool) {
        match error {
            AuthorityEvidenceExportError::AccessDenied => (
                "urn:proof:problem:authority-denied",
                "Portable evidence export requires the authenticated bootstrap Human",
                "proof.auth.denied",
                false,
            ),
            AuthorityEvidenceExportError::NotFound => (
                "urn:proof:problem:resource-not-found",
                "The requested Release resource was not found",
                "proof.resource.not_found",
                false,
            ),
            AuthorityEvidenceExportError::Incomplete(_) => (
                "urn:proof:problem:evidence-incomplete",
                "The portable authority-evidence closure is incomplete",
                "proof.evidence.incomplete",
                false,
            ),
            AuthorityEvidenceExportError::InvalidBundle(_) => (
                "urn:proof:problem:evidence-invalid",
                "The portable authority-evidence closure is invalid",
                "proof.evidence.invalid",
                false,
            ),
            AuthorityEvidenceExportError::LimitExceeded => (
                "urn:proof:problem:evidence-limit-exceeded",
                "The portable authority-evidence closure exceeds a v1 bound",
                "proof.evidence.limit_exceeded",
                false,
            ),
            AuthorityEvidenceExportError::Storage(_) => (
                "urn:proof:problem:dependency-unavailable",
                "Portable evidence storage is unavailable",
                "proof.dependency.unavailable",
                true,
            ),
        }
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
    #[test]
    fn materializer_writes_exact_layout_without_overwriting() {
        let directory = TestDirectory::new();
        let destination = directory.path().join("bundle");
        let plan = MaterializationPlan {
            manifest: r#"{"api_version":"proof.dev/authority-evidence-bundle/v1"}"#.to_owned(),
            artifacts: BTreeMap::from([(
                "artifacts/command-v1/blake3/abcd.json".to_owned(),
                r#"{"command":"status"}"#.to_owned(),
            )]),
            included_bytes: 20,
        };
        let materialized = materialize(&destination, &plan, execution_context()).unwrap();
        assert_eq!(materialized, fs::canonicalize(&destination).unwrap());
        assert_eq!(
            fs::read_to_string(destination.join(MANIFEST_FILENAME)).unwrap(),
            plan.manifest
        );
        assert_eq!(
            fs::read_to_string(destination.join("artifacts/command-v1/blake3/abcd.json")).unwrap(),
            plan.artifacts["artifacts/command-v1/blake3/abcd.json"]
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o077,
                0
            );
            assert_eq!(
                fs::metadata(destination.join(MANIFEST_FILENAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
        }

        let marker = destination.join("human-owned-marker");
        fs::write(&marker, b"preserve").unwrap();
        let problem = materialize(&destination, &plan, execution_context()).unwrap_err();
        assert_eq!(problem.code, "proof.state.conflict");
        assert_eq!(fs::read(marker).unwrap(), b"preserve");
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
    #[test]
    fn publication_race_never_replaces_an_existing_empty_destination() {
        let directory = TestDirectory::new();
        let staging = directory.path().join("staging");
        let destination = directory.path().join("bundle");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("payload"), b"staged").unwrap();
        fs::create_dir(&destination).unwrap();

        assert!(publish_without_replacement(&staging, &destination).is_err());
        assert!(staging.join("payload").is_file());
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
    }

    #[cfg(any(target_vendor = "apple", target_os = "linux", target_os = "redox"))]
    #[test]
    fn publication_race_never_replaces_a_destination_symlink() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        let staging = directory.path().join("staging");
        let victim = directory.path().join("victim");
        let destination = directory.path().join("bundle");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("payload"), b"staged").unwrap();
        fs::create_dir(&victim).unwrap();
        fs::write(victim.join("human-owned-marker"), b"preserve").unwrap();
        symlink(&victim, &destination).unwrap();

        assert!(publish_without_replacement(&staging, &destination).is_err());
        assert!(staging.join("payload").is_file());
        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read(destination.join("human-owned-marker")).unwrap(),
            b"preserve"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_publication_fails_closed_without_destination_or_staging() {
        let directory = TestDirectory::new();
        let destination = directory.path().join("bundle");
        let plan = MaterializationPlan {
            manifest: r#"{"api_version":"proof.dev/authority-evidence-bundle/v1"}"#.to_owned(),
            artifacts: BTreeMap::new(),
            included_bytes: 0,
        };
        let context = execution_context();

        let problem = materialize(&destination, &plan, context).unwrap_err();
        assert_eq!(problem.code, "proof.dependency.unavailable");
        assert!(!problem.retryable);
        assert!(!destination.exists());
        assert!(
            !directory
                .path()
                .join(format!(".proof-evidence-{}.staging", context.operation_id))
                .exists()
        );
    }

    fn execution_context() -> ExecutionContext {
        ExecutionContext {
            operation_id: "019d2000-0000-7000-8000-000000000001".parse().unwrap(),
            correlation_id: "019d2000-0000-7000-8000-000000000002".parse().unwrap(),
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "proof-p0006-evidence-materializer-{}",
                Uuid::now_v7()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
