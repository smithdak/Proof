use std::{
    env, fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use clap::Subcommand;
use proof_application::{
    AddLocalizedEditsCommand, AddedLocalizedEdits, ApprovalName, ApprovedLocalizedChangeSet,
    BuildLocalizedContextCommand, ChangeSetIntent, CommitLocalizedChangeSetCommand,
    CommittedLocalizedChangeSet, ContentResourceIntent, CreateLocalizedChangeSetCommand,
    CreateLocalizedEditionCommand, EditionArtifactReference, ExpectedLocalizedSource,
    ExpectedLocalizedTarget, IdempotencyKey, IssueContentResourceIntentCommand, LocaleId,
    LocaleRevision, LocalizedChangeSet, LocalizedChangeSetDiff, LocalizedContentBaseline,
    LocalizedContentError, LocalizedContentRepository, LocalizedContentTarget,
    LocalizedContextLimits, LocalizedContextPack, LocalizedEdit, LocalizedEdition,
    LocalizedFinding, LocalizedPolicyRule, LocalizedRelease, LocalizedReleaseVerification,
    LocalizedValidation, ObjectLocalePutInput, ObjectLocaleRevision, ObjectRevision,
    PromoteLocalizedReleaseCommand, QueryReleasedRenditionsCommand, ReleaseArtifactReference,
    ReleasedLocaleTarget, ReleasedRendition, ReleasedRenditionQuery, ResultEnvelope,
    RollbackLocalizedReleaseCommand, SchemaId, SchemaVersion, SubmittedLocalizedChangeSet,
    VerifyLocalizedReleaseCommand,
};
use proof_canonical::canonicalize;
use proof_local::LocalWorkspace;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    ExecutionContext, ExitCode, OutputFormat, Problem, current_timestamp,
    generated_idempotency_key, write_json,
};

const MAX_LOCALIZED_INPUT_BYTES: u64 = 1_048_576;

#[derive(Debug, Subcommand)]
pub(super) enum LocalizedAction {
    /// Issue one immutable Human-owned exact target intent.
    IntentIssue {
        /// Environment whose current Release becomes the exact baseline.
        #[arg(long)]
        environment: String,
        /// Exact `OBJECT_ID:SCHEMA_ID:LOCALE` tuple; repeat for every target.
        #[arg(long, required = true)]
        target: Vec<String>,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Get one verified immutable resource intent.
    IntentGet {
        /// Content resource intent `UUIDv7`.
        intent_id: String,
    },
    /// Build one exact `ContextPackV2` from a persisted resource intent.
    ContextBuild {
        /// Content resource intent `UUIDv7`.
        #[arg(long)]
        resource_intent: String,
        /// Exact persisted intent digest.
        #[arg(long)]
        resource_intent_digest: String,
        /// JSON file containing policy rules, limits, and `expires_at`; `-` reads stdin.
        #[arg(long)]
        file: PathBuf,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Get one verified localized `ContextPackV2`.
    ContextGet {
        /// `ContextPack` `UUIDv7`.
        context_pack_id: String,
    },
    /// Create one repairable `ChangeSetV2` bound to exact intent and context artifacts.
    ChangesetCreate {
        /// Human-declared reason for the proposal.
        #[arg(long)]
        intent: String,
        /// Exact content resource intent `UUIDv7`.
        #[arg(long)]
        resource_intent: String,
        /// Exact content resource intent digest.
        #[arg(long)]
        resource_intent_digest: String,
        /// Exact `ContextPack` `UUIDv7`.
        #[arg(long)]
        context_pack: String,
        /// Exact `ContextPack` digest.
        #[arg(long)]
        context_pack_digest: String,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Atomically append `object.locale.put` attempts from NDJSON.
    ChangesetAdd {
        /// Target localized `ChangeSet` `UUIDv7`.
        changeset_id: String,
        /// NDJSON file containing semantic Edit inputs; `-` reads stdin.
        #[arg(long)]
        file: PathBuf,
        /// Supply a `UUIDv7` retry key; one is generated when omitted.
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Get the complete immutable Edit and validation-facing `ChangeSetV2` view.
    ChangesetGet { changeset_id: String },
    /// Get the effective-leaf diff while verifying complete attempt lineage.
    ChangesetDiff { changeset_id: String },
    /// Persist one deterministic `ValidationResultsV2` attempt.
    ChangesetValidate { changeset_id: String },
    /// Submit one exact validation-sealed `ChangeSetV2`.
    ChangesetSubmit { changeset_id: String },
    /// Record one exact Human approval.
    ChangesetApprove {
        changeset_id: String,
        #[arg(long)]
        approval: String,
    },
    /// Atomically commit the effective rendition leaves.
    ChangesetCommit {
        changeset_id: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Create the exact `EditionV2` produced by one localized commit.
    EditionCreate {
        #[arg(long)]
        changeset: String,
        #[arg(long)]
        resulting_state_digest: String,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Promote one exact `EditionV2` as a signed `ReleaseV2`.
    ReleasePromote {
        #[arg(long)]
        environment: String,
        #[arg(long)]
        edition: String,
        #[arg(long)]
        expected_base_release: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Append a Human rollback as `ReleaseV2` without changing authoring state.
    ReleaseRollback {
        #[arg(long)]
        environment: String,
        #[arg(long)]
        expected_current_release: String,
        #[arg(long)]
        to_release: String,
        #[arg(long)]
        idempotency_key: String,
    },
    /// Query exact `(object_id, locale)` renditions with no fallback.
    Query {
        #[arg(long)]
        environment: String,
        /// Exact `OBJECT_ID:LOCALE` tuple; repeat for every target.
        #[arg(long, required = true)]
        target: Vec<String>,
    },
    /// Reconstruct and verify one persisted `ReleaseV2` and its signed Proof.
    ReleaseVerify { release_id: String },
}

impl LocalizedAction {
    pub(super) const fn operation(&self) -> &'static str {
        match self {
            Self::IntentIssue { .. } => "content-resource-intent.issue",
            Self::IntentGet { .. } => "content-resource-intent.get",
            Self::ContextBuild { .. } => "context.build",
            Self::ContextGet { .. } => "context.get",
            Self::ChangesetCreate { .. } => "changeset.create",
            Self::ChangesetAdd { .. } => "changeset.add",
            Self::ChangesetGet { .. } => "changeset.get",
            Self::ChangesetDiff { .. } => "changeset.diff",
            Self::ChangesetValidate { .. } => "changeset.validate",
            Self::ChangesetSubmit { .. } => "changeset.submit",
            Self::ChangesetApprove { .. } => "changeset.approve",
            Self::ChangesetCommit { .. } => "changeset.commit",
            Self::EditionCreate { .. } => "edition.create",
            Self::ReleasePromote { .. } => "release.create",
            Self::ReleaseRollback { .. } => "release.rollback",
            Self::Query { .. } => "object.query_released",
            Self::ReleaseVerify { .. } => "release.verify",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextFile {
    policy_rules: Vec<PolicyRuleInput>,
    limits: ContextLimitsInput,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRuleInput {
    locale: String,
    pointer: String,
    disallowed_values: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_field_names,
    reason = "the input fields intentionally mirror the committed max_* budget contract"
)]
struct ContextLimitsInput {
    max_objects: u32,
    max_edits: u32,
    max_validation_attempts: u32,
    max_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditInput {
    object_id: String,
    locale: String,
    expected_source: SourceInput,
    expected_target: Option<TargetInput>,
    content: Value,
    supersedes_edit_id: Option<String>,
    repair_of_validation_result_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    revision: u32,
    digest: String,
    schema_id: String,
    schema_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetInput {
    revision: u32,
    digest: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive Human CLI dispatch keeps every localized operation and version boundary explicit"
)]
pub(super) fn run_localized(
    action: LocalizedAction,
    output: OutputFormat,
    context: ExecutionContext,
    selected_workspace: Option<String>,
) -> Result<ExitCode, Box<Problem>> {
    let operation = action.operation();
    let repository = local_workspace(selected_workspace, operation, context)?;
    let data = match action {
        LocalizedAction::IntentIssue {
            environment,
            target,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let intent = repository
                .issue_content_resource_intent(IssueContentResourceIntentCommand {
                    intent_id: generated_id(),
                    environment_id: parse(&environment, "environment", operation, context)?,
                    targets: target
                        .iter()
                        .map(|value| parse_content_target(value, operation, context))
                        .collect::<Result<Vec<_>, _>>()?,
                    idempotency_key,
                    issued_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            content_intent_value(&intent, Some(idempotency_key))
        }
        LocalizedAction::IntentGet { intent_id } => {
            let intent = repository
                .get_content_resource_intent(parse(&intent_id, "intent-id", operation, context)?)
                .map_err(|error| localized_problem(&error, operation, context))?;
            content_intent_value(&intent, None)
        }
        LocalizedAction::ContextBuild {
            resource_intent,
            resource_intent_digest,
            file,
            idempotency_key,
        } => {
            let input: ContextFile = read_json(&file, operation, context)?;
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let pack = repository
                .build_localized_context(BuildLocalizedContextCommand {
                    context_pack_id: generated_id(),
                    resource_intent_id: parse(
                        &resource_intent,
                        "resource-intent",
                        operation,
                        context,
                    )?,
                    resource_intent_digest: parse(
                        &resource_intent_digest,
                        "resource-intent-digest",
                        operation,
                        context,
                    )?,
                    policy_rules: input
                        .policy_rules
                        .into_iter()
                        .map(|rule| {
                            Ok(LocalizedPolicyRule {
                                locale: parse(&rule.locale, "policy locale", operation, context)?,
                                pointer: rule.pointer,
                                disallowed_values: rule.disallowed_values,
                            })
                        })
                        .collect::<Result<Vec<_>, Box<Problem>>>()?,
                    limits: LocalizedContextLimits {
                        max_objects: input.limits.max_objects,
                        max_edits: input.limits.max_edits,
                        max_validation_attempts: input.limits.max_validation_attempts,
                        max_bytes: input.limits.max_bytes,
                    },
                    idempotency_key,
                    created_at: now(operation, context)?,
                    expires_at: parse(&input.expires_at, "expires-at", operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            context_pack_value(&pack, Some(idempotency_key))
        }
        LocalizedAction::ContextGet { context_pack_id } => {
            let pack = repository
                .get_localized_context(parse(
                    &context_pack_id,
                    "context-pack-id",
                    operation,
                    context,
                )?)
                .map_err(|error| localized_problem(&error, operation, context))?;
            context_pack_value(&pack, None)
        }
        LocalizedAction::ChangesetCreate {
            intent,
            resource_intent,
            resource_intent_digest,
            context_pack,
            context_pack_digest,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let changeset = repository
                .create_localized_changeset(CreateLocalizedChangeSetCommand {
                    changeset_id: generated_id(),
                    intent: ChangeSetIntent::new(intent)
                        .map_err(|error| input_problem(operation, context, error.to_string()))?,
                    resource_intent_id: parse(
                        &resource_intent,
                        "resource-intent",
                        operation,
                        context,
                    )?,
                    resource_intent_digest: parse(
                        &resource_intent_digest,
                        "resource-intent-digest",
                        operation,
                        context,
                    )?,
                    context_pack_id: parse(&context_pack, "context-pack", operation, context)?,
                    context_pack_digest: parse(
                        &context_pack_digest,
                        "context-pack-digest",
                        operation,
                        context,
                    )?,
                    idempotency_key,
                    created_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            localized_changeset_value(&changeset, Some(idempotency_key))
        }
        LocalizedAction::ChangesetAdd {
            changeset_id,
            file,
            idempotency_key,
        } => {
            let edits = read_edits(&file, operation, context)?;
            let assigned_edit_ids = (0..edits.len()).map(|_| generated_id()).collect();
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let added = repository
                .add_localized_edits(AddLocalizedEditsCommand {
                    changeset_id: parse(&changeset_id, "changeset-id", operation, context)?,
                    edits,
                    assigned_edit_ids,
                    idempotency_key,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            added_edits_value(&added, idempotency_key)
        }
        LocalizedAction::ChangesetGet { changeset_id } => {
            let changeset = repository
                .inspect_localized_changeset(parse(
                    &changeset_id,
                    "changeset-id",
                    operation,
                    context,
                )?)
                .map_err(|error| localized_problem(&error, operation, context))?;
            localized_changeset_value(&changeset, None)
        }
        LocalizedAction::ChangesetDiff { changeset_id } => {
            let diff = repository
                .diff_localized_changeset(parse(&changeset_id, "changeset-id", operation, context)?)
                .map_err(|error| localized_problem(&error, operation, context))?;
            changeset_diff_value(&diff)
        }
        LocalizedAction::ChangesetValidate { changeset_id } => {
            let validation = repository
                .validate_localized_changeset(parse(
                    &changeset_id,
                    "changeset-id",
                    operation,
                    context,
                )?)
                .map_err(|error| localized_problem(&error, operation, context))?;
            validation_value(&validation)
        }
        LocalizedAction::ChangesetSubmit { changeset_id } => {
            let submitted = repository
                .submit_localized_changeset(
                    parse(&changeset_id, "changeset-id", operation, context)?,
                    now(operation, context)?,
                )
                .map_err(|error| localized_problem(&error, operation, context))?;
            submission_value(&submitted)
        }
        LocalizedAction::ChangesetApprove {
            changeset_id,
            approval,
        } => {
            let approved = repository
                .approve_localized_changeset(
                    parse(&changeset_id, "changeset-id", operation, context)?,
                    ApprovalName::new(approval)
                        .map_err(|error| input_problem(operation, context, error.to_string()))?,
                    now(operation, context)?,
                )
                .map_err(|error| localized_problem(&error, operation, context))?;
            approval_value(&approved)
        }
        LocalizedAction::ChangesetCommit {
            changeset_id,
            idempotency_key,
        } => {
            let committed = repository
                .commit_localized_changeset(CommitLocalizedChangeSetCommand {
                    changeset_id: parse(&changeset_id, "changeset-id", operation, context)?,
                    idempotency_key: parse(
                        &idempotency_key,
                        "idempotency-key",
                        operation,
                        context,
                    )?,
                    committed_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            committed_value(&committed)
        }
        LocalizedAction::EditionCreate {
            changeset,
            resulting_state_digest,
            idempotency_key,
        } => {
            let idempotency_key = optional_id(idempotency_key, operation, context)?;
            let edition = repository
                .create_localized_edition(CreateLocalizedEditionCommand {
                    edition_id: generated_id(),
                    changeset_id: parse(&changeset, "changeset", operation, context)?,
                    resulting_state_digest: parse(
                        &resulting_state_digest,
                        "resulting-state-digest",
                        operation,
                        context,
                    )?,
                    idempotency_key,
                    created_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            edition_value(&edition, idempotency_key)
        }
        LocalizedAction::ReleasePromote {
            environment,
            edition,
            expected_base_release,
            idempotency_key,
        } => {
            let release = repository
                .promote_localized_release(PromoteLocalizedReleaseCommand {
                    release_id: generated_id(),
                    proof_id: generated_id(),
                    environment_id: parse(&environment, "environment", operation, context)?,
                    edition_id: parse(&edition, "edition", operation, context)?,
                    expected_base_release_id: parse(
                        &expected_base_release,
                        "expected-base-release",
                        operation,
                        context,
                    )?,
                    idempotency_key: parse(
                        &idempotency_key,
                        "idempotency-key",
                        operation,
                        context,
                    )?,
                    released_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            release_value(&release)
        }
        LocalizedAction::ReleaseRollback {
            environment,
            expected_current_release,
            to_release,
            idempotency_key,
        } => {
            let release = repository
                .rollback_localized_release(RollbackLocalizedReleaseCommand {
                    release_id: generated_id(),
                    proof_id: generated_id(),
                    environment_id: parse(&environment, "environment", operation, context)?,
                    expected_current_release_id: parse(
                        &expected_current_release,
                        "expected-current-release",
                        operation,
                        context,
                    )?,
                    rollback_target_release_id: parse(
                        &to_release,
                        "to-release",
                        operation,
                        context,
                    )?,
                    idempotency_key: parse(
                        &idempotency_key,
                        "idempotency-key",
                        operation,
                        context,
                    )?,
                    released_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            release_value(&release)
        }
        LocalizedAction::Query {
            environment,
            target,
        } => {
            let query = repository
                .query_released_renditions(QueryReleasedRenditionsCommand {
                    environment_id: parse(&environment, "environment", operation, context)?,
                    targets: target
                        .iter()
                        .map(|value| parse_locale_target(value, operation, context))
                        .collect::<Result<Vec<_>, _>>()?,
                    evaluated_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            query_value(&query)
        }
        LocalizedAction::ReleaseVerify { release_id } => {
            let verification = repository
                .verify_localized_release(VerifyLocalizedReleaseCommand {
                    release_id: parse(&release_id, "release-id", operation, context)?,
                    verified_at: now(operation, context)?,
                })
                .map_err(|error| localized_problem(&error, operation, context))?;
            verification_value(&verification)
        }
    };
    render(output, context, operation, data);
    Ok(ExitCode::Success)
}

fn parse_content_target(
    value: &str,
    operation: &str,
    context: ExecutionContext,
) -> Result<LocalizedContentTarget, Box<Problem>> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(input_problem(
            operation,
            context,
            "target must use OBJECT_ID:SCHEMA_ID:LOCALE".to_owned(),
        ));
    }
    Ok(LocalizedContentTarget {
        object_id: parse(parts[0], "target object-id", operation, context)?,
        schema_id: SchemaId::new(parts[1]).map_err(|error| {
            input_problem(
                operation,
                context,
                format!("invalid target schema-id: {error}"),
            )
        })?,
        locale: LocaleId::new(parts[2]).map_err(|error| {
            input_problem(
                operation,
                context,
                format!("invalid target locale: {error}"),
            )
        })?,
    })
}

fn parse_locale_target(
    value: &str,
    operation: &str,
    context: ExecutionContext,
) -> Result<ReleasedLocaleTarget, Box<Problem>> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(input_problem(
            operation,
            context,
            "target must use OBJECT_ID:LOCALE".to_owned(),
        ));
    }
    Ok(ReleasedLocaleTarget {
        object_id: parse(parts[0], "target object-id", operation, context)?,
        locale: LocaleId::new(parts[1]).map_err(|error| {
            input_problem(
                operation,
                context,
                format!("invalid target locale: {error}"),
            )
        })?,
    })
}

fn read_edits(
    path: &Path,
    operation: &str,
    context: ExecutionContext,
) -> Result<Vec<ObjectLocalePutInput>, Box<Problem>> {
    let bytes = read_input(path).map_err(|detail| input_problem(operation, context, detail))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| input_problem(operation, context, error.to_string()))?;
    let mut edits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let input: EditInput = serde_json::from_str(line).map_err(|error| {
            input_problem(
                operation,
                context,
                format!("invalid NDJSON record {}: {error}", index + 1),
            )
        })?;
        let canonical_content = canonicalize(&input.content)
            .map_err(|error| input_problem(operation, context, error.to_string()))?;
        edits.push(ObjectLocalePutInput {
            object_id: parse(&input.object_id, "object-id", operation, context)?,
            locale: parse(&input.locale, "locale", operation, context)?,
            expected_source: ExpectedLocalizedSource {
                revision: ObjectRevision::new(input.expected_source.revision)
                    .map_err(|error| input_problem(operation, context, error.to_string()))?,
                digest: parse(
                    &input.expected_source.digest,
                    "source digest",
                    operation,
                    context,
                )?,
                schema_id: SchemaId::new(input.expected_source.schema_id)
                    .map_err(|error| input_problem(operation, context, error.to_string()))?,
                schema_version: SchemaVersion::new(input.expected_source.schema_version)
                    .map_err(|error| input_problem(operation, context, error.to_string()))?,
            },
            expected_target: input
                .expected_target
                .map(|target| {
                    Ok::<ExpectedLocalizedTarget, Box<Problem>>(ExpectedLocalizedTarget {
                        revision: LocaleRevision::new(target.revision).map_err(|error| {
                            input_problem(operation, context, error.to_string())
                        })?,
                        digest: parse(&target.digest, "target digest", operation, context)?,
                    })
                })
                .transpose()?,
            canonical_content: canonical_content.as_str().to_owned(),
            supersedes_edit_id: input
                .supersedes_edit_id
                .map(|value| parse(&value, "supersedes-edit-id", operation, context))
                .transpose()?,
            repair_of_validation_result_digest: input
                .repair_of_validation_result_digest
                .map(|value| parse(&value, "repair validation digest", operation, context))
                .transpose()?,
        });
    }
    Ok(edits)
}

fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    operation: &str,
    context: ExecutionContext,
) -> Result<T, Box<Problem>> {
    let bytes = read_input(path).map_err(|detail| input_problem(operation, context, detail))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| input_problem(operation, context, error.to_string()))
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    if path == Path::new("-") {
        io::stdin()
            .take(MAX_LOCALIZED_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    } else {
        let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
        if metadata.len() > MAX_LOCALIZED_INPUT_BYTES {
            return Err("localized input exceeds the 1 MiB CLI limit".to_owned());
        }
        fs::File::open(path)
            .map_err(|error| error.to_string())?
            .take(MAX_LOCALIZED_INPUT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
    }
    if bytes.len() as u64 > MAX_LOCALIZED_INPUT_BYTES {
        return Err("localized input exceeds the 1 MiB CLI limit".to_owned());
    }
    Ok(bytes)
}

fn parse<T: std::str::FromStr>(
    value: &str,
    field: &str,
    operation: &str,
    context: ExecutionContext,
) -> Result<T, Box<Problem>>
where
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|error: T::Err| {
        input_problem(operation, context, format!("invalid {field}: {error}"))
    })
}

fn optional_id(
    value: Option<String>,
    operation: &str,
    context: ExecutionContext,
) -> Result<IdempotencyKey, Box<Problem>> {
    value.map_or_else(
        || Ok(generated_idempotency_key()),
        |value| parse(&value, "idempotency-key", operation, context),
    )
}

fn generated_id<T: std::str::FromStr>() -> T
where
    T::Err: std::fmt::Debug,
{
    Uuid::now_v7()
        .to_string()
        .parse()
        .expect("generated UUIDv7 must satisfy operational identity")
}

fn now(
    operation: &str,
    context: ExecutionContext,
) -> Result<proof_application::Timestamp, Box<Problem>> {
    current_timestamp().map_err(|detail| input_problem(operation, context, detail))
}

fn local_workspace(
    selected_workspace: Option<String>,
    operation: &str,
    context: ExecutionContext,
) -> Result<LocalWorkspace, Box<Problem>> {
    let root = selected_workspace
        .map_or_else(env::current_dir, |path| Ok(PathBuf::from(path)))
        .map_err(|error| input_problem(operation, context, error.to_string()))?;
    LocalWorkspace::new(root).map_err(|error| input_problem(operation, context, error.to_string()))
}

fn input_problem(operation: &str, context: ExecutionContext, detail: String) -> Box<Problem> {
    let mut problem = Problem::new(
        "urn:proof:problem:input-schema-mismatch",
        "The localized-content command input is invalid",
        "proof.input.schema_mismatch",
        operation,
        context.operation_id,
        context.correlation_id,
    );
    problem.detail = Some(detail);
    Box::new(problem)
}

#[expect(
    clippy::too_many_lines,
    reason = "the stable Problem taxonomy maps every localized application error explicitly"
)]
fn localized_problem(
    error: &LocalizedContentError,
    operation: &str,
    context: ExecutionContext,
) -> Box<Problem> {
    let (problem_type, title, code, retryable) = match error {
        LocalizedContentError::Unauthenticated => (
            "urn:proof:problem:authentication-required",
            "The local identity is not an authenticated Human",
            "proof.auth.unauthenticated",
            false,
        ),
        LocalizedContentError::NotFound => (
            "urn:proof:problem:resource-not-found",
            "The exact localized-content resource was not found",
            "proof.resource.not_found",
            false,
        ),
        LocalizedContentError::UnsupportedVersion => (
            "urn:proof:problem:unsupported-version",
            "The operation is unsupported for the current artifact version",
            "proof.input.unsupported_version",
            false,
        ),
        LocalizedContentError::InvalidInput => (
            "urn:proof:problem:input-schema-mismatch",
            "The localized-content input violates its closed contract",
            "proof.input.schema_mismatch",
            false,
        ),
        LocalizedContentError::IntentMismatch => (
            "urn:proof:problem:intent-mismatch",
            "The operation differs from the immutable resource intent",
            "proof.input.intent_mismatch",
            false,
        ),
        LocalizedContentError::SourceConflict => conflict_mapping(
            "The locale-neutral source precondition changed",
            "proof.state.source_conflict",
        ),
        LocalizedContentError::TargetConflict => conflict_mapping(
            "The exact target rendition precondition changed",
            "proof.state.target_conflict",
        ),
        LocalizedContentError::StateConflict => conflict_mapping(
            "The localized-content baseline changed concurrently",
            "proof.state.conflict",
        ),
        LocalizedContentError::DuplicateActiveTarget => conflict_mapping(
            "The ChangeSet already has an active Edit for this target",
            "proof.changeset.duplicate_target",
        ),
        LocalizedContentError::InvalidSupersession => conflict_mapping(
            "The requested Edit supersession edge is invalid",
            "proof.changeset.invalid_supersession",
        ),
        LocalizedContentError::InvalidRepairEvidence => (
            "urn:proof:problem:repair-evidence-invalid",
            "The repair evidence does not match the latest invalid result",
            "proof.validation.repair_evidence_invalid",
            false,
        ),
        LocalizedContentError::NotDraft => lifecycle_mapping(
            "Localized Edits require a Draft ChangeSet",
            "proof.changeset.not_draft",
        ),
        LocalizedContentError::NotReady => lifecycle_mapping(
            "The localized ChangeSet is not Ready",
            "proof.changeset.not_ready",
        ),
        LocalizedContentError::NotSubmitted => lifecycle_mapping(
            "The localized ChangeSet is not Submitted",
            "proof.changeset.not_submitted",
        ),
        LocalizedContentError::NotApproved => lifecycle_mapping(
            "The localized ChangeSet is not Approved",
            "proof.changeset.not_approved",
        ),
        LocalizedContentError::EvidenceMissing => (
            "urn:proof:problem:evidence-incomplete",
            "Localized-content evidence is incomplete",
            "proof.evidence.incomplete",
            false,
        ),
        LocalizedContentError::LimitExceeded => (
            "urn:proof:problem:input-limit-exceeded",
            "The localized-content operation exceeds its committed budget",
            "proof.input.limit_exceeded",
            false,
        ),
        LocalizedContentError::IdempotencyKeyReused => conflict_mapping(
            "The idempotency key was already used with different input",
            "proof.idempotency.key_reused",
        ),
        LocalizedContentError::PolicyDenied => (
            "urn:proof:problem:policy-denied",
            "Policy denied the exact localized-content operation",
            "proof.policy.denied",
            false,
        ),
        LocalizedContentError::Signing(_) | LocalizedContentError::Storage(_) => (
            "urn:proof:problem:dependency-unavailable",
            "Localized-content persistence or signing is unavailable",
            "proof.dependency.unavailable",
            true,
        ),
        LocalizedContentError::Integrity(_) => (
            "urn:proof:problem:evidence-incomplete",
            "Localized-content evidence failed deterministic reconstruction",
            "proof.evidence.incomplete",
            false,
        ),
    };
    let mut problem = Problem::new(
        problem_type,
        title,
        code,
        operation,
        context.operation_id,
        context.correlation_id,
    );
    if matches!(
        error,
        LocalizedContentError::Integrity(_)
            | LocalizedContentError::Storage(_)
            | LocalizedContentError::Signing(_)
    ) {
        problem.detail = Some(error.to_string());
    }
    problem.retryable = retryable;
    Box::new(problem)
}

const fn conflict_mapping(
    title: &'static str,
    code: &'static str,
) -> (&'static str, &'static str, &'static str, bool) {
    ("urn:proof:problem:state-conflict", title, code, false)
}

const fn lifecycle_mapping(
    title: &'static str,
    code: &'static str,
) -> (&'static str, &'static str, &'static str, bool) {
    ("urn:proof:problem:changeset-lifecycle", title, code, false)
}

fn render(output: OutputFormat, context: ExecutionContext, operation: &str, data: Value) {
    let result = ResultEnvelope::success(
        operation,
        context.operation_id,
        context.correlation_id,
        data,
    );
    match output {
        OutputFormat::Json => write_json(&result),
        OutputFormat::Text => {
            println!("{operation}");
            println!(
                "{}",
                serde_json::to_string_pretty(&result.data)
                    .expect("localized result data must serialize")
            );
        }
    }
}

fn state_value(state: &proof_application::KnownStateArtifactReference) -> Value {
    json!({
        "api_version": state.api_version,
        "authoritative_sequence": state.authoritative_sequence,
        "digest": state.digest.to_string(),
    })
}

fn edition_reference_value(reference: &EditionArtifactReference) -> Value {
    json!({
        "api_version": reference.api_version,
        "edition_id": reference.edition_id.to_string(),
        "digest": reference.digest.to_string(),
    })
}

fn release_reference_value(reference: &ReleaseArtifactReference) -> Value {
    json!({
        "api_version": reference.api_version,
        "release_id": reference.release_id.to_string(),
        "digest": reference.digest.to_string(),
    })
}

fn baseline_value(baseline: &LocalizedContentBaseline) -> Value {
    json!({
        "release": release_reference_value(&baseline.release),
        "edition": edition_reference_value(&baseline.edition),
        "known_state": state_value(&baseline.known_state),
    })
}

fn target_value(target: &LocalizedContentTarget) -> Value {
    json!({
        "object_id": target.object_id.to_string(),
        "schema_id": target.schema_id.as_str(),
        "locale": target.locale.as_str(),
    })
}

fn content_intent_value(
    intent: &ContentResourceIntent,
    idempotency_key: Option<IdempotencyKey>,
) -> Value {
    json!({
        "api_version": proof_application::CONTENT_RESOURCE_INTENT_API_VERSION,
        "intent_id": intent.intent_id.to_string(),
        "workspace_id": intent.workspace_id.to_string(),
        "issued_by_principal_id": intent.issued_by_principal_id.to_string(),
        "issued_at": intent.issued_at.to_string(),
        "environment_id": intent.environment_id.as_str(),
        "base": baseline_value(&intent.base),
        "targets": intent.targets.iter().map(target_value).collect::<Vec<_>>(),
        "canonical": serde_json::from_str::<Value>(&intent.canonical_json).unwrap_or(Value::Null),
        "canonical_json": intent.canonical_json,
        "intent_digest": intent.intent_digest.to_string(),
        "idempotency_key": idempotency_key.map(|value| value.to_string()),
    })
}

fn context_pack_value(
    pack: &LocalizedContextPack,
    idempotency_key: Option<IdempotencyKey>,
) -> Value {
    json!({
        "api_version": proof_application::LOCALIZED_CONTEXT_API_VERSION,
        "context_pack_id": pack.context_pack_id.to_string(),
        "workspace_id": pack.workspace_id.to_string(),
        "principal_id": pack.principal_id.to_string(),
        "resource_intent_id": pack.resource_intent_id.to_string(),
        "resource_intent_digest": pack.resource_intent_digest.to_string(),
        "base": baseline_value(&pack.base),
        "policy_digest": pack.policy_digest.to_string(),
        "limits": {
            "max_objects": pack.limits.max_objects,
            "max_edits": pack.limits.max_edits,
            "max_validation_attempts": pack.limits.max_validation_attempts,
            "max_bytes": pack.limits.max_bytes,
        },
        "created_at": pack.created_at.to_string(),
        "expires_at": pack.expires_at.to_string(),
        "manifest": serde_json::from_str::<Value>(&pack.manifest_json).unwrap_or(Value::Null),
        "manifest_json": pack.manifest_json,
        "context_pack_digest": pack.context_pack_digest.to_string(),
        "idempotency_key": idempotency_key.map(|value| value.to_string()),
    })
}

fn edit_value(edit: &LocalizedEdit) -> Value {
    json!({
        "ordinal": edit.ordinal,
        "edit_id": edit.edit_id.to_string(),
        "effective": edit.effective,
        "object_id": edit.input.object_id.to_string(),
        "locale": edit.input.locale.as_str(),
        "expected_source": {
            "revision": edit.input.expected_source.revision.get(),
            "digest": edit.input.expected_source.digest.to_string(),
            "schema_id": edit.input.expected_source.schema_id.as_str(),
            "schema_version": edit.input.expected_source.schema_version.get(),
        },
        "expected_target": edit.input.expected_target.as_ref().map(|target| json!({
            "revision": target.revision.get(),
            "digest": target.digest.to_string(),
        })),
        "content": serde_json::from_str::<Value>(&edit.input.canonical_content).unwrap_or(Value::Null),
        "canonical_content": edit.input.canonical_content,
        "supersedes_edit_id": edit.input.supersedes_edit_id.map(|value| value.to_string()),
        "repair_of_validation_result_digest": edit.input.repair_of_validation_result_digest.map(|value| value.to_string()),
        "canonical": serde_json::from_str::<Value>(&edit.canonical_json).unwrap_or(Value::Null),
        "canonical_json": edit.canonical_json,
        "edit_digest": edit.edit_digest.to_string(),
    })
}

fn localized_changeset_value(
    changeset: &LocalizedChangeSet,
    idempotency_key: Option<IdempotencyKey>,
) -> Value {
    json!({
        "api_version": proof_application::LOCALIZED_CHANGESET_API_VERSION,
        "changeset_id": changeset.changeset_id.to_string(),
        "workspace_id": changeset.workspace_id.to_string(),
        "principal_id": changeset.principal_id.to_string(),
        "intent": changeset.intent.as_str(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "base_state": state_value(&changeset.base_state),
        "created_at": changeset.created_at.to_string(),
        "status": changeset.status.to_string(),
        "edits": changeset.edits.iter().map(edit_value).collect::<Vec<_>>(),
        "proposal_digest": changeset.proposal_digest.map(|value| value.to_string()),
        "sealed_changeset_digest": changeset.sealed_changeset_digest.map(|value| value.to_string()),
        "idempotency_key": idempotency_key.map(|value| value.to_string()),
    })
}

fn added_edits_value(added: &AddedLocalizedEdits, idempotency_key: IdempotencyKey) -> Value {
    json!({
        "changeset_id": added.changeset_id.to_string(),
        "edit_ids": added.edit_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "first_ordinal": added.first_ordinal,
        "total_edit_count": added.total_edit_count,
        "idempotency_key": idempotency_key.to_string(),
    })
}

fn changeset_diff_value(diff: &LocalizedChangeSetDiff) -> Value {
    json!({
        "changeset_id": diff.changeset_id.to_string(),
        "proposal_digest": diff.proposal_digest.to_string(),
        "effective_leaf_digest": diff.effective_leaf_digest.to_string(),
        "effective_edits": diff.effective_edits.iter().map(edit_value).collect::<Vec<_>>(),
    })
}

fn finding_value(finding: &LocalizedFinding) -> Value {
    json!({
        "code": finding.code,
        "severity": finding.severity,
        "edit_id": finding.edit_id.to_string(),
        "object_id": finding.object_id.to_string(),
        "locale": finding.locale.as_str(),
        "pointer": finding.pointer,
        "validator": finding.validator,
        "policy_digest": finding.policy_digest.to_string(),
    })
}

fn validation_value(validation: &LocalizedValidation) -> Value {
    json!({
        "changeset_id": validation.changeset_id.to_string(),
        "attempt": validation.attempt,
        "previous_validation_result_digest": validation.previous_validation_result_digest.map(|value| value.to_string()),
        "proposal_digest": validation.proposal_digest.to_string(),
        "effective_leaf_digest": validation.effective_leaf_digest.to_string(),
        "valid": validation.valid,
        "findings": validation.findings.iter().map(finding_value).collect::<Vec<_>>(),
        "validation_results_digest": validation.validation_results_digest.to_string(),
        "sealed_changeset_digest": validation.sealed_changeset_digest.map(|value| value.to_string()),
        "status": validation.status.to_string(),
    })
}

fn submission_value(submitted: &SubmittedLocalizedChangeSet) -> Value {
    json!({
        "changeset_id": submitted.changeset_id.to_string(),
        "sealed_changeset_digest": submitted.sealed_changeset_digest.to_string(),
        "validation_results_digest": submitted.validation_results_digest.to_string(),
        "submitted_at": submitted.submitted_at.to_string(),
        "status": submitted.status.to_string(),
    })
}

fn approval_value(approved: &ApprovedLocalizedChangeSet) -> Value {
    json!({
        "changeset_id": approved.changeset_id.to_string(),
        "approval": approved.approval.as_str(),
        "sealed_changeset_digest": approved.sealed_changeset_digest.to_string(),
        "validation_results_digest": approved.validation_results_digest.to_string(),
        "approved_at": approved.approved_at.to_string(),
        "status": approved.status.to_string(),
    })
}

fn rendition_revision_value(rendition: &ObjectLocaleRevision) -> Value {
    json!({
        "workspace_id": rendition.workspace_id.to_string(),
        "object_id": rendition.object_id.to_string(),
        "locale": rendition.locale.as_str(),
        "revision": rendition.revision.get(),
        "previous_revision_digest": rendition.previous_revision_digest.map(|value| value.to_string()),
        "source_object_revision": rendition.source_object_revision.get(),
        "source_object_digest": rendition.source_object_digest.to_string(),
        "schema_id": rendition.schema_id.as_str(),
        "schema_version": rendition.schema_version.get(),
        "content": serde_json::from_str::<Value>(&rendition.canonical_content).unwrap_or(Value::Null),
        "canonical_content": rendition.canonical_content,
        "changeset_id": rendition.changeset_id.to_string(),
        "edit_id": rendition.edit_id.to_string(),
        "authoritative_sequence": rendition.authoritative_sequence,
        "manifest": serde_json::from_str::<Value>(&rendition.manifest_json).unwrap_or(Value::Null),
        "manifest_json": rendition.manifest_json,
        "rendition_digest": rendition.rendition_digest.to_string(),
    })
}

fn committed_value(committed: &CommittedLocalizedChangeSet) -> Value {
    json!({
        "changeset_id": committed.changeset_id.to_string(),
        "sealed_changeset_digest": committed.sealed_changeset_digest.to_string(),
        "validation_results_digest": committed.validation_results_digest.to_string(),
        "previous_state": state_value(&committed.previous_state),
        "resulting_state": state_value(&committed.resulting_state),
        "renditions": committed.renditions.iter().map(rendition_revision_value).collect::<Vec<_>>(),
        "committed_at": committed.committed_at.to_string(),
        "status": committed.status.to_string(),
    })
}

fn edition_value(edition: &LocalizedEdition, idempotency_key: IdempotencyKey) -> Value {
    json!({
        "api_version": proof_application::LOCALIZED_EDITION_API_VERSION,
        "edition_id": edition.edition_id.to_string(),
        "workspace_id": edition.workspace_id.to_string(),
        "principal_id": edition.principal_id.to_string(),
        "changeset_id": edition.changeset_id.to_string(),
        "base_edition": edition_reference_value(&edition.base_edition),
        "state": state_value(&edition.state),
        "schema_set_digest": edition.schema_set_digest.to_string(),
        "object_set_digest": edition.object_set_digest.to_string(),
        "manifest": serde_json::from_str::<Value>(&edition.manifest_json).unwrap_or(Value::Null),
        "manifest_json": edition.manifest_json,
        "edition_digest": edition.edition_digest.to_string(),
        "created_at": edition.created_at.to_string(),
        "idempotency_key": idempotency_key.to_string(),
    })
}

fn release_value(release: &LocalizedRelease) -> Value {
    json!({
        "api_version": proof_application::LOCALIZED_RELEASE_API_VERSION,
        "release_id": release.release_id.to_string(),
        "workspace_id": release.workspace_id.to_string(),
        "environment_id": release.environment_id.as_str(),
        "edition": edition_reference_value(&release.edition),
        "kind": release.kind.to_string(),
        "release_sequence": release.release_sequence,
        "previous_release_id": release.previous_release_id.map(|value| value.to_string()),
        "rollback_target_release_id": release.rollback_target_release_id.map(|value| value.to_string()),
        "changeset_id": release.changeset_id.map(|value| value.to_string()),
        "resource_intent_id": release.resource_intent_id.map(|value| value.to_string()),
        "manifest": serde_json::from_str::<Value>(&release.manifest_json).unwrap_or(Value::Null),
        "manifest_json": release.manifest_json,
        "release_digest": release.release_digest.to_string(),
        "proof_id": release.proof_id.to_string(),
        "proof_envelope_digest": release.proof_envelope_digest.to_string(),
        "key_id": release.key_id,
        "proof_envelope": serde_json::from_str::<Value>(&release.proof_envelope_json).unwrap_or(Value::Null),
        "proof_envelope_json": release.proof_envelope_json,
        "released_at": release.released_at.to_string(),
    })
}

fn released_rendition_value(rendition: &ReleasedRendition) -> Value {
    json!({
        "object_id": rendition.object_id.to_string(),
        "locale": rendition.locale.as_str(),
        "source_revision": rendition.source_revision.get(),
        "source_digest": rendition.source_digest.to_string(),
        "rendition_revision": rendition.rendition_revision.get(),
        "rendition_digest": rendition.rendition_digest.to_string(),
        "schema_id": rendition.schema_id.as_str(),
        "schema_version": rendition.schema_version.get(),
        "content": serde_json::from_str::<Value>(&rendition.canonical_content).unwrap_or(Value::Null),
        "canonical_content": rendition.canonical_content,
    })
}

fn query_value(query: &ReleasedRenditionQuery) -> Value {
    json!({
        "workspace_id": query.workspace_id.to_string(),
        "environment_id": query.environment_id.as_str(),
        "release_id": query.release_id.to_string(),
        "edition": edition_reference_value(&query.edition),
        "renditions": query.renditions.iter().map(released_rendition_value).collect::<Vec<_>>(),
    })
}

fn verification_value(verification: &LocalizedReleaseVerification) -> Value {
    json!({
        "release_id": verification.release_id.to_string(),
        "proof_id": verification.proof_id.to_string(),
        "valid": verification.valid,
        "findings": verification.findings,
        "verified_at": verification.verified_at.to_string(),
    })
}
