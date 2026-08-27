//! Deterministic local/server semantic oracle over the SQLite-backed local
//! application path.
//!
//! The oracle replays the shared application operations (the 14 Agent rows and
//! the shared Human rows) against `proof-local` and produces byte-identical,
//! replayable [`OracleTraceV1`] records. It also carries deterministic
//! [`IdentityFixtureV1`] test identity data with no live provider or network
//! (contract §"Conformance and falsification plan",
//! §"PostgreSQL authoritative unit of work").

use proof_application::authority::{
    AuthorityOperation, ContextBuildInputV1, LocalizedChangeSetAddInputV2,
    LocalizedChangeSetCommitInputV2, LocalizedChangeSetCreateInputV2,
    LocalizedChangeSetDiffInputV2, LocalizedChangeSetGetInputV2, LocalizedChangeSetSubmitInputV2,
    LocalizedChangeSetValidateInputV2, LocalizedContextBuildInputV2, LocalizedEditionCreateInputV2,
    LocalizedObjectQueryReleasedInputV2, LocalizedReleaseCreateInputV2, ObjectQueryReleasedInputV1,
    WorkspaceStatusInputV1,
};
use proof_application::{
    AddLocalizedEditsCommand, AddedLocalizedEdits, BuildContextPackCommand,
    CommittedLocalizedChangeSet, ContextPack, ContextPackLimits, ContextPackRepository, EditId,
    EditionArtifactReference, KnownStateArtifactReference, LocalizedChangeSet,
    LocalizedChangeSetDiff, LocalizedContentRepository, LocalizedEdit, LocalizedEdition,
    LocalizedFinding, LocalizedRelease, LocalizedValidation, ObjectLocaleRevision,
    QueryReleasedObjectsCommand, ReleasedObject, ReleasedObjectQuery, ReleasedObjectRepository,
    ReleasedRendition, ReleasedRenditionQuery, Severity, SubmittedLocalizedChangeSet, Timestamp,
    WorkspaceStatus, WorkspaceStatusRepository,
};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AuthorityHeadV1, RemoteError, RemoteOperationV1, derive_key_digest,
    identity::{
        AuthenticatedActorContextV2, OidcIssuerConfigurationApiVersion, OidcIssuerConfigurationV1,
        OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1,
        REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT,
    },
};

/// BLAKE3-256 derive-key context for operation effects and application problems.
///
/// This is the closed `proof:operation-effect:v1` context shared by the remote
/// consequence and problem digests (contract §"Human and control operation
/// registry"). It is duplicated here rather than imported from the sibling
/// registry module so the oracle stays self-contained while the registry is
/// implemented in parallel.
const OPERATION_EFFECT_DIGEST_CONTEXT: &str = "proof:operation-effect:v1";
/// The stable problem code selected when a normalized input cannot be decoded
/// into the operation's strict typed shape.
const INPUT_SCHEMA_MISMATCH_CODE: &str = "proof.input.schema_mismatch";

/// A stable application problem projected into a trace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StableProblem {
    /// Stable machine-readable problem code.
    pub code: String,
    /// Exact operation/version that produced the problem.
    pub operation: RemoteOperationV1,
}

/// The typed outcome of one oracle evaluation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub enum OracleOutcome {
    /// A successful typed application result.
    TypedResult(Value),
    /// A stable application problem.
    StableProblem(StableProblem),
}

/// The consequence bound to one oracle evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum OracleConsequence {
    /// Exact domain-separated consequence digest.
    ConsequenceDigest(#[serde(with = "crate::serde_support::display_string")] ContentDigest),
    /// No signed consequence was produced.
    Null,
}

/// One deterministic, replayable oracle trace.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OracleTraceV1 {
    /// `proof:remote-normalized-operation-input:v1` digest of the exact input.
    #[serde(with = "crate::serde_support::display_string")]
    pub normalized_input_digest: ContentDigest,
    /// Exact authority head evaluated by the trace.
    pub evaluated_authority_head: AuthorityHeadV1,
    /// Typed application outcome.
    pub outcome: OracleOutcome,
    /// Consequence digest or null.
    pub consequence: OracleConsequence,
}

/// Deterministic test identity data: an issuer configuration, an enrollment
/// challenge, and binding fixtures. This fixture never performs network I/O or
/// contacts a live OIDC provider.
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityFixtureV1 {
    /// Pinned public issuer configuration.
    pub issuer_configuration: OidcIssuerConfigurationV1,
    /// One-use enrollment challenge (state, nonce, PKCE verifier).
    pub enrollment_challenge: OidcEnrollmentChallengeV1,
    /// Public OIDC Principal bindings.
    pub oidc_bindings: Vec<OidcPrincipalBindingV1>,
    /// Protected OIDC Principal binding lookups.
    pub oidc_bindings_private: Vec<OidcPrincipalBindingPrivateV1>,
}

/// One deterministic OIDC enrollment challenge. This is local fixture data
/// only; it never performs network I/O.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcEnrollmentChallengeV1 {
    /// Exact fixture api version.
    pub api_version: String,
    /// One-use `state` value.
    pub state: String,
    /// One-use OIDC `nonce` value.
    pub nonce: String,
    /// PKCE `S256` code verifier.
    pub code_verifier: String,
}

impl OidcEnrollmentChallengeV1 {
    /// Returns a deterministic one-use enrollment challenge with fixed values.
    ///
    /// The values are closed fixture data only: they carry no live provider
    /// state and are reproducible across process restarts.
    #[must_use]
    pub fn deterministic() -> Self {
        Self {
            api_version: "proof.dev/oidc-enrollment-challenge/v1".to_owned(),
            state: "019e0000-0000-7000-8000-0000000000a1".to_owned(),
            nonce: "019e0000-0000-7000-8000-0000000000a2".to_owned(),
            code_verifier: "deterministic-pkce-verifier-0000000000000000000000000000000000000000"
                .to_owned(),
        }
    }
}

impl IdentityFixtureV1 {
    /// Returns deterministic test identity data with no live provider.
    ///
    /// The issuer configuration mirrors the retained
    /// `oidc-issuer-configuration.valid.json` vector byte-for-byte; bindings are
    /// left empty so callers seed exactly the commitment material they need.
    #[must_use]
    pub fn deterministic() -> Self {
        Self {
            issuer_configuration: deterministic_issuer_configuration(),
            enrollment_challenge: OidcEnrollmentChallengeV1::deterministic(),
            oidc_bindings: Vec::new(),
            oidc_bindings_private: Vec::new(),
        }
    }
}

/// Constructs the closed, secret-free issuer configuration mirrored from the
/// retained conformance vector.
fn deterministic_issuer_configuration() -> OidcIssuerConfigurationV1 {
    OidcIssuerConfigurationV1 {
        api_version: OidcIssuerConfigurationApiVersion::V1,
        configuration_id: "019e0000-0000-7000-8000-000000000010".to_owned(),
        configuration_source: "trusted-deployment-configuration".to_owned(),
        issuer: "https://identity.example.test".to_owned(),
        discovery_uri: "https://identity.example.test/.well-known/openid-configuration".to_owned(),
        authorization_endpoint: "https://identity.example.test/oauth2/authorize".to_owned(),
        token_endpoint: "https://identity.example.test/oauth2/token".to_owned(),
        jwks_uri: "https://identity.example.test/oauth2/jwks".to_owned(),
        client_id: "proof-collaboration-server".to_owned(),
        redirect_uri: "https://proof.example.test/auth/oidc/callback".to_owned(),
        discovery_metadata_digest:
            "blake3:1010101010101010101010101010101010101010101010101010101010101010"
                .parse()
                .expect("the pinned issuer discovery-metadata digest is a valid ContentDigest"),
        endpoint_egress_policy: "deployment-allowlist-no-redirect".to_owned(),
        accepted_id_token_algorithms: vec!["EdDSA".to_owned(), "ES256".to_owned()],
        authorization_code_flow: true,
        pkce_method: "S256".to_owned(),
        response_issuer_parameter_required: true,
        token_endpoint_auth_method: "client_secret_basic".to_owned(),
        client_credential_reference: "deployment-secret:proof-oidc-client".to_owned(),
        tokens_retained: false,
        clock_skew_seconds: 30,
        session_cookie_name: "__Host-Http-Proof-Session".to_owned(),
        session_idle_seconds: 900,
        session_absolute_seconds: 28_800,
    }
}

/// Deterministic trace runner over the SQLite-backed local application path.
///
/// Repeated execution of the same trace inputs produces byte-identical
/// [`OracleTraceV1`] records; mutated inputs land in the contracted consequence
/// class without executing an HTTP or PostgreSQL adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteSemanticOracle;

impl RemoteSemanticOracle {
    /// Constructs the deterministic oracle.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluates one normalized operation input plus actor context against the
    /// supplied local Workspace and returns a deterministic trace.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Oracle`] when the operation cannot be dispatched
    /// or evaluated deterministically.
    pub fn run(
        &self,
        workspace: &proof_local::LocalWorkspace,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError> {
        let (operation, evaluated_authority_head, authenticated_at, presentation_id) =
            match actor_context {
                AuthenticatedActorContextV2::Human(context) => (
                    context.operation.clone(),
                    context.evaluated_authority_head,
                    context.authenticated_at,
                    None,
                ),
                AuthenticatedActorContextV2::HumanAgent(context) => (
                    context.operation.clone(),
                    context.evaluated_authority_head,
                    context.authenticated_at,
                    Some(context.presentation_id.as_str()),
                ),
            };

        let normalized_input_digest = normalized_input_digest(&operation, normalized_input)?;
        let resolved = AuthorityOperation::from_pair(&operation.name, &operation.version)
            .ok_or_else(|| {
                RemoteError::Oracle(format!(
                    "unregistered remote operation `{}` at `{}`",
                    operation.name, operation.version
                ))
            })?;

        let (outcome, consequence) = evaluate(
            workspace,
            resolved,
            normalized_input,
            authenticated_at,
            presentation_id,
            &operation,
        )?;

        Ok(OracleTraceV1 {
            normalized_input_digest,
            evaluated_authority_head,
            outcome,
            consequence,
        })
    }
}

/// The shared oracle boundary between the retained SQLite reference path and
/// the new PostgreSQL path (contract §"Conformance and falsification plan").
///
/// This trait lives in `proof-remote` so one shared conformance runner can
/// produce byte-identical [`OracleTraceV1`] records from either backend without
/// introducing a `proof-remote -> proof-pg` dependency. The SQLite
/// implementation ([`SqliteReferenceBackend`]) delegates to
/// [`RemoteSemanticOracle`]; the PostgreSQL implementation lives in `proof-pg`
/// and consumes the same shared operation, input, and actor-context vocabulary.
pub trait StorageBackend {
    /// Evaluates one normalized operation input plus actor context against the
    /// backend and returns a deterministic trace.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteError::Oracle`] when the operation cannot be dispatched
    /// or evaluated deterministically.
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError>;
}

/// The retained SQLite reference backend, delegating to [`proof_local`] through
/// [`RemoteSemanticOracle`] (contract §"Conformance and falsification plan").
pub struct SqliteReferenceBackend<'a> {
    workspace: &'a proof_local::LocalWorkspace,
}

impl<'a> SqliteReferenceBackend<'a> {
    /// Binds the reference backend to a local Workspace.
    #[must_use]
    pub const fn new(workspace: &'a proof_local::LocalWorkspace) -> Self {
        Self { workspace }
    }
}

impl StorageBackend for SqliteReferenceBackend<'_> {
    fn run(
        &mut self,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
    ) -> Result<OracleTraceV1, RemoteError> {
        RemoteSemanticOracle::new().run(self.workspace, normalized_input, actor_context)
    }
}

/// Computes the protected exact normalized-input digest under
/// `proof:remote-normalized-operation-input:v1`.
fn normalized_input_digest(
    operation: &RemoteOperationV1,
    input: &Value,
) -> Result<ContentDigest, RemoteError> {
    let preimage = serde_json::json!({
        "api_version": "proof.dev/remote-normalized-operation-input/v1",
        "input": input,
        "operation": operation,
    });
    canonical_digest(REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT, &preimage)
}

/// Computes a domain-separated BLAKE3-256 digest over RFC 8785 canonical bytes.
fn canonical_digest(context: &str, value: &Value) -> Result<ContentDigest, RemoteError> {
    let canonical =
        canonicalize(value).map_err(|error| RemoteError::Canonical(error.to_string()))?;
    Ok(derive_key_digest(context, canonical.as_bytes()))
}

/// Computes the `proof:operation-effect:v1` digest of an exact row result.
fn operation_effect_digest(result: &Value) -> Result<ContentDigest, RemoteError> {
    canonical_digest(OPERATION_EFFECT_DIGEST_CONTEXT, result)
}

/// Computes the stable application-problem digest under `proof:operation-effect:v1`.
fn application_problem_digest(
    code: &str,
    operation: &RemoteOperationV1,
) -> Result<ContentDigest, RemoteError> {
    let preimage = serde_json::json!({
        "api_version": "proof.dev/application-problem-digest-preimage/v1",
        "code": code,
        "operation": operation,
    });
    canonical_digest(OPERATION_EFFECT_DIGEST_CONTEXT, &preimage)
}

/// Builds a stable-problem outcome plus its domain-separated consequence digest.
fn stable_problem(
    code: &str,
    operation: &RemoteOperationV1,
) -> Result<(OracleOutcome, OracleConsequence), RemoteError> {
    let consequence = application_problem_digest(code, operation)?;
    Ok((
        OracleOutcome::StableProblem(StableProblem {
            code: code.to_owned(),
            operation: operation.clone(),
        }),
        OracleConsequence::ConsequenceDigest(consequence),
    ))
}

/// Builds a typed success outcome. `effect` is the row-selected signed
/// consequence digest, or [`None`] for rows whose effect rule is `none`.
fn success(result: Value, effect: Option<ContentDigest>) -> (OracleOutcome, OracleConsequence) {
    (
        OracleOutcome::TypedResult(result),
        effect.map_or(
            OracleConsequence::Null,
            OracleConsequence::ConsequenceDigest,
        ),
    )
}

/// Dispatches one resolved operation against the local application path and
/// returns its typed outcome plus consequence.
#[allow(clippy::too_many_lines)]
fn evaluate(
    workspace: &proof_local::LocalWorkspace,
    operation: AuthorityOperation,
    normalized_input: &Value,
    injected_at: Timestamp,
    presentation_id: Option<&str>,
    remote_operation: &RemoteOperationV1,
) -> Result<(OracleOutcome, OracleConsequence), RemoteError> {
    match operation {
        AuthorityOperation::WorkspaceStatusV1 => {
            if parse_input::<WorkspaceStatusInputV1>(normalized_input).is_err() {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            }
            match workspace.status() {
                Ok(status) => Ok(success(serialize_workspace_status(&status), None)),
                Err(error) => stable_problem(workspace_status_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ObjectQueryReleasedV1 => {
            let Ok(input) = parse_input::<ObjectQueryReleasedInputV1>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = QueryReleasedObjectsCommand {
                operating_principal_id: Some(input.operating_principal_id),
                delegation_id: Some(input.delegation_id),
                environment_id: input.environment_id,
                object_ids: input.object_ids.into_vec(),
                evaluated_at: injected_at,
            };
            match workspace.query_released_objects(command) {
                Ok(query) => Ok(success(serialize_released_object_query(&query), None)),
                Err(error) => stable_problem(query_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ContextBuildV1 => {
            let Ok(input) = parse_input::<ContextBuildInputV1>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let context_pack_id = resolve_context_pack_id(presentation_id)?;
            let command = BuildContextPackCommand {
                context_pack_id,
                operating_principal_id: input.operating_principal_id,
                delegation_id: input.delegation_id,
                task_id: input.task_id.as_str().to_owned(),
                intent: input.intent,
                environment_id: input.environment_id,
                object_ids: input.object_ids.as_slice().to_vec(),
                limits: ContextPackLimits {
                    max_objects: input.max_objects.get(),
                    max_bytes: u64::from(input.max_bytes.get()),
                },
                idempotency_key: input.idempotency_key,
                built_at: injected_at,
                expires_at: input.expires_at,
            };
            match workspace.build_context_pack(command) {
                Ok(context_pack) => {
                    let result = serialize_context_pack(&context_pack);
                    Ok(success(result, Some(context_pack.context_pack_digest)))
                }
                Err(error) => stable_problem(context_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ContextBuildV2 => {
            let Ok(input) = parse_input::<LocalizedContextBuildInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.build_localized_context(command) {
                Ok(context_pack) => {
                    let result = serialize_localized_context_pack(&context_pack);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetCreateV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetCreateInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.create_localized_changeset(command) {
                Ok(changeset) => {
                    let result = serialize_created_localized_changeset(&changeset);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetAddV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetAddInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let Ok(command) = build_add_edits_command(input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            match workspace.add_localized_edits(command) {
                Ok(added) => {
                    let result = serialize_added_localized_edits(&added);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetGetV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetGetInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            match workspace.inspect_localized_changeset(input.changeset_id) {
                Ok(changeset) => Ok(success(serialize_localized_changeset(&changeset), None)),
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetDiffV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetDiffInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            match workspace.diff_localized_changeset(input.changeset_id) {
                Ok(diff) => Ok(success(serialize_localized_change_set_diff(&diff), None)),
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetValidateV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetValidateInputV2>(normalized_input)
            else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            match workspace.validate_localized_changeset(input.changeset_id) {
                Ok(validation) => {
                    let result = serialize_localized_validation(&validation);
                    Ok(success(result, Some(validation.validation_results_digest)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetSubmitV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetSubmitInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            match workspace.submit_localized_changeset(input.changeset_id, input.submitted_at) {
                Ok(submitted) => {
                    let result = serialize_submitted_localized_changeset(&submitted);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ChangesetCommitV2 => {
            let Ok(input) = parse_input::<LocalizedChangeSetCommitInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.commit_localized_changeset(command) {
                Ok(committed) => {
                    let result = serialize_committed_localized_changeset(&committed);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::EditionCreateV2 => {
            let Ok(input) = parse_input::<LocalizedEditionCreateInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.create_localized_edition(command) {
                Ok(edition) => {
                    let result = serialize_localized_edition(&edition);
                    let effect = operation_effect_digest(&result)?;
                    Ok(success(result, Some(effect)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ReleaseCreateV2 => {
            let Ok(input) = parse_input::<LocalizedReleaseCreateInputV2>(normalized_input) else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.promote_localized_release(command) {
                Ok(release) => {
                    let result = serialize_localized_release(&release);
                    Ok(success(result, Some(release.release_digest)))
                }
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
        AuthorityOperation::ObjectQueryReleasedV2 => {
            let Ok(input) = parse_input::<LocalizedObjectQueryReleasedInputV2>(normalized_input)
            else {
                return stable_problem(INPUT_SCHEMA_MISMATCH_CODE, remote_operation);
            };
            let command = input.into_application_command();
            match workspace.query_released_renditions(command) {
                Ok(query) => Ok(success(serialize_released_rendition_query(&query), None)),
                Err(error) => stable_problem(localized_error_code(&error), remote_operation),
            }
        }
    }
}

/// Parses one normalized operation input into its strict typed shape.
fn parse_input<T: for<'de> Deserialize<'de>>(input: &Value) -> Result<T, ()> {
    serde_json::from_value(input.clone()).map_err(|_| ())
}

/// Converts a `WorkspaceStatusError` into its stable problem code.
fn workspace_status_error_code(error: &proof_application::WorkspaceStatusError) -> &'static str {
    use proof_application::WorkspaceStatusError;
    match error {
        WorkspaceStatusError::Incomplete => "proof.state.incomplete",
        WorkspaceStatusError::Unauthenticated => "proof.auth.denied",
        WorkspaceStatusError::Integrity(_) => "proof.digest.mismatch",
        WorkspaceStatusError::Storage(_) => "proof.dependency.unavailable",
    }
}

/// Converts a `QueryReleasedObjectsError` into its stable problem code.
fn query_error_code(error: &proof_application::QueryReleasedObjectsError) -> &'static str {
    use proof_application::QueryReleasedObjectsError;
    match error {
        QueryReleasedObjectsError::Unauthenticated => "proof.auth.denied",
        QueryReleasedObjectsError::UnsupportedVersion => "proof.input.unsupported_version",
        QueryReleasedObjectsError::Denied => "proof.authorization.denied",
        QueryReleasedObjectsError::InvalidQuery => "proof.input.schema_mismatch",
        QueryReleasedObjectsError::NotFound => "proof.resource.not_found",
        QueryReleasedObjectsError::Integrity(_) => "proof.digest.mismatch",
        QueryReleasedObjectsError::Storage(_) => "proof.dependency.unavailable",
    }
}

/// Converts a `ContextPackError` into its stable problem code.
fn context_error_code(error: &proof_application::ContextPackError) -> &'static str {
    use proof_application::ContextPackError;
    match error {
        ContextPackError::Unauthenticated => "proof.auth.denied",
        ContextPackError::Denied => "proof.authorization.denied",
        ContextPackError::NotFound => "proof.resource.not_found",
        ContextPackError::LimitExceeded => "proof.input.limit_exceeded",
        ContextPackError::Expired => "proof.delegation.expired",
        ContextPackError::IdempotencyKeyReused => "proof.idempotency.key_reused",
        ContextPackError::Integrity(_) => "proof.digest.mismatch",
        ContextPackError::Storage(_) => "proof.dependency.unavailable",
    }
}

/// Converts a `LocalizedContentError` into its stable problem code.
#[must_use]
pub fn localized_error_code(error: &proof_application::LocalizedContentError) -> &'static str {
    use proof_application::LocalizedContentError;
    match error {
        LocalizedContentError::Unauthenticated => "proof.auth.denied",
        LocalizedContentError::NotFound => "proof.resource.not_found",
        LocalizedContentError::UnsupportedVersion => "proof.input.unsupported_version",
        LocalizedContentError::InvalidInput => "proof.input.schema_mismatch",
        LocalizedContentError::IntentMismatch => "proof.input.intent_mismatch",
        LocalizedContentError::IntentSlotMismatch => "proof.intent.slot_mismatch",
        LocalizedContentError::SchemaNotFound => "proof.schema.not_found",
        LocalizedContentError::SourceConflict => "proof.state.source_conflict",
        LocalizedContentError::TargetConflict => "proof.state.target_conflict",
        LocalizedContentError::StateConflict => "proof.state.conflict",
        LocalizedContentError::ObjectExists => "proof.state.object_exists",
        LocalizedContentError::DuplicateActiveTarget => "proof.changeset.duplicate_target",
        LocalizedContentError::InvalidSupersession => "proof.changeset.invalid_supersession",
        LocalizedContentError::InvalidRepairEvidence => "proof.validation.repair_evidence_invalid",
        LocalizedContentError::NotDraft => "proof.changeset.not_draft",
        LocalizedContentError::NotReady => "proof.changeset.not_ready",
        LocalizedContentError::NotSubmitted => "proof.changeset.not_submitted",
        LocalizedContentError::NotApproved => "proof.changeset.not_approved",
        LocalizedContentError::EvidenceMissing => "proof.evidence.incomplete",
        LocalizedContentError::LimitExceeded => "proof.input.limit_exceeded",
        LocalizedContentError::IdempotencyKeyReused => "proof.idempotency.key_reused",
        LocalizedContentError::PolicyDenied => "proof.policy.denied",
        LocalizedContentError::Signing(_) | LocalizedContentError::Storage(_) => {
            "proof.dependency.unavailable"
        }
        LocalizedContentError::Integrity(_) => "proof.digest.mismatch",
    }
}

/// Resolves the deterministic `ContextPack` identity for a v1 context build,
/// mirroring the real authority path that derives it from the presentation ID.
fn resolve_context_pack_id(
    presentation_id: Option<&str>,
) -> Result<proof_application::ContextPackId, RemoteError> {
    let value = presentation_id.map_or_else(
        || "019c0000-0000-7000-8000-0000000002ff".to_owned(),
        str::to_owned,
    );
    value
        .parse::<proof_application::ContextPackId>()
        .map_err(|error| RemoteError::Oracle(format!("invalid context-pack identity: {error}")))
}

/// Builds the localized add command with deterministic, Proof-assigned Edit
/// identities derived from the exact batch identity.
/// Builds the application Add command from a normalized authority input.
///
/// # Errors
///
/// Returns unit error when canonicalization or input mapping fails.
#[allow(clippy::result_unit_err)]
pub fn build_add_edits_command(
    input: LocalizedChangeSetAddInputV2,
) -> Result<AddLocalizedEditsCommand, ()> {
    let mut edits = Vec::with_capacity(input.edits.len());
    let mut assigned_edit_ids = Vec::with_capacity(input.edits.len());
    for (index, edit) in input.edits.into_iter().enumerate() {
        let content = Value::Object(edit.content().clone());
        let canonical = canonicalize(&content).map_err(|_| ())?;
        let application_input = edit
            .into_application_input(canonical.as_str().to_owned())
            .map_err(|_| ())?;
        let seed = format!("{}:{}", input.changeset_id, input.idempotency_key);
        let edit_id = deterministic_edit_id(&seed, index)?;
        edits.push(application_input);
        assigned_edit_ids.push(edit_id);
    }
    Ok(AddLocalizedEditsCommand {
        changeset_id: input.changeset_id,
        edits,
        assigned_edit_ids,
        idempotency_key: input.idempotency_key,
    })
}

/// Derives a deterministic UUIDv7 [`EditId`] from a stable seed and ordinal.
///
/// # Errors
///
/// Returns unit error when the derived identity cannot be parsed.
#[allow(clippy::result_unit_err)]
pub fn deterministic_edit_id(seed: &str, ordinal: usize) -> Result<EditId, ()> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"proof:oracle:edit-id:v1");
    hasher.update(seed.as_bytes());
    hasher.update(&(ordinal as u64).to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70; // UUID version 7
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    let text = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    text.parse::<EditId>().map_err(|_| ())
}

fn serialize_workspace_status(status: &WorkspaceStatus) -> Value {
    match status {
        WorkspaceStatus::Uninitialized => serde_json::json!({ "status": "uninitialized" }),
        WorkspaceStatus::Initialized(initialized) => serde_json::json!({
            "status": "initialized",
            "workspace_id": initialized.workspace_id.to_string(),
            "principal_id": initialized.principal_id.to_string(),
            "storage_schema_version": initialized.storage_schema_version,
            "authoritative_sequence": initialized.authoritative_sequence,
            "state_digest": initialized.state_digest.to_string(),
        }),
    }
}

fn serialize_released_object_query(query: &ReleasedObjectQuery) -> Value {
    serde_json::json!({
        "workspace_id": query.workspace_id.to_string(),
        "environment_id": query.environment_id.to_string(),
        "release_id": query.release_id.to_string(),
        "edition_id": query.edition_id.to_string(),
        "principal_id": query.principal_id.to_string(),
        "delegation_id": query.delegation_id.map(|value| value.to_string()),
        "authorization_decision_digest": query.authorization_decision_digest.to_string(),
        "objects": query.objects.iter().map(serialize_released_object).collect::<Vec<_>>(),
    })
}

fn serialize_released_object(object: &ReleasedObject) -> Value {
    serde_json::json!({
        "object_id": object.object_id.to_string(),
        "revision": object.revision.get(),
        "schema_id": object.schema_id.to_string(),
        "schema_version": object.schema_version.get(),
        "lifecycle_state": object.lifecycle_state.to_string(),
        "content": parse_json(&object.canonical_content),
        "object_digest": object.object_digest.to_string(),
    })
}

fn serialize_context_pack(context_pack: &ContextPack) -> Value {
    serde_json::json!({
        "context_pack_id": context_pack.context_pack_id.to_string(),
        "workspace_id": context_pack.workspace_id.to_string(),
        "requesting_principal_id": context_pack.requesting_principal_id.to_string(),
        "operating_principal_id": context_pack.operating_principal_id.to_string(),
        "delegation_id": context_pack.delegation_id.to_string(),
        "task_id": context_pack.task_id,
        "intent": context_pack.intent.to_string(),
        "environment_id": context_pack.environment_id.to_string(),
        "release_id": context_pack.release_id.to_string(),
        "edition_id": context_pack.edition_id.to_string(),
        "base_state": context_pack.base_state.to_string(),
        "object_ids": context_pack.object_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "limits": {
            "max_objects": context_pack.limits.max_objects,
            "max_bytes": context_pack.limits.max_bytes,
        },
        "built_at": context_pack.built_at.to_string(),
        "expires_at": context_pack.expires_at.to_string(),
        "capabilities": context_pack.capabilities,
        "manifest": parse_json(&context_pack.manifest_json),
        "context_pack_digest": context_pack.context_pack_digest.to_string(),
    })
}

#[must_use]
pub fn serialize_localized_context_pack(
    context_pack: &proof_application::LocalizedContextPack,
) -> Value {
    serde_json::json!({
        "context_pack_id": context_pack.context_pack_id.to_string(),
        "context_pack_digest": context_pack.context_pack_digest.to_string(),
        "manifest": parse_json(&context_pack.manifest_json),
        "resource_intent_id": context_pack.resource_intent_id.to_string(),
        "resource_intent_digest": context_pack.resource_intent_digest.to_string(),
    })
}

fn serialize_known_state_reference(state: &KnownStateArtifactReference) -> Value {
    serde_json::json!({
        "api_version": state.api_version,
        "authoritative_sequence": state.authoritative_sequence,
        "digest": state.digest.to_string(),
    })
}

fn serialize_edition_reference(edition: &EditionArtifactReference) -> Value {
    serde_json::json!({
        "api_version": edition.api_version,
        "edition_id": edition.edition_id.to_string(),
        "digest": edition.digest.to_string(),
    })
}

#[must_use]
pub fn serialize_created_localized_changeset(changeset: &LocalizedChangeSet) -> Value {
    serde_json::json!({
        "base_state": serialize_known_state_reference(&changeset.base_state),
        "changeset_id": changeset.changeset_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "status": "draft",
    })
}

#[must_use]
/// Serializes the complete localized ChangeSet artifact used by get/diff
/// result contracts.
///
/// # Panics
///
/// Panics only if the already validated localized Edit values cannot be
/// canonicalized as JSON while deriving their effective-leaf digest.
pub fn serialize_localized_changeset(changeset: &LocalizedChangeSet) -> Value {
    let mut effective = changeset
        .edits
        .iter()
        .filter(|edit| edit.effective)
        .collect::<Vec<_>>();
    effective.sort_by(|left, right| {
        let key = |edit: &LocalizedEdit| match &edit.input {
            proof_application::LocalizedEditAttempt::LocalePut(input) => {
                (1_u8, input.object_id, Some(input.locale.clone()))
            }
            proof_application::LocalizedEditAttempt::ObjectCreate(input) => {
                (0_u8, input.object_id, None)
            }
        };
        key(left).cmp(&key(right))
    });
    let effective_edits = effective
        .iter()
        .map(|edit| parse_json(&edit.canonical_json))
        .collect::<Vec<_>>();
    let effective_manifest = canonicalize(&serde_json::json!({
        "api_version": "proof.dev/edit-batch/v2",
        "edits": effective_edits,
    }))
    .expect("validated localized edits must canonicalize");
    let effective_leaf_digest = digest(ArtifactKind::EditBatchV2, &effective_manifest);
    serde_json::json!({
        "api_version": proof_application::LOCALIZED_CHANGESET_API_VERSION,
        "base_state": serialize_known_state_reference(&changeset.base_state),
        "changeset_id": changeset.changeset_id.to_string(),
        "context_pack_digest": changeset.context_pack_digest.to_string(),
        "context_pack_id": changeset.context_pack_id.to_string(),
        "created_at": changeset.created_at.to_string(),
        "edits": changeset.edits.iter().map(serialize_localized_edit).collect::<Vec<_>>(),
        "effective_leaf_digest": effective_leaf_digest.to_string(),
        "effective_leaves": effective.iter().map(|edit| {
            let mut leaf = serde_json::Map::new();
            leaf.insert("edit_digest".to_owned(), serde_json::json!(edit.edit_digest.to_string()));
            leaf.insert("edit_id".to_owned(), serde_json::json!(edit.edit_id.to_string()));
            if let Some(locale) = edit.input.locale() {
                leaf.insert("locale".to_owned(), serde_json::json!(locale.as_str()));
            }
            leaf.insert(
                "object_id".to_owned(),
                serde_json::json!(edit.input.object_id().to_string()),
            );
            Value::Object(leaf)
        }).collect::<Vec<_>>(),
        "intent": changeset.intent.to_string(),
        "principal_id": changeset.principal_id.to_string(),
        "resource_intent_digest": changeset.resource_intent_digest.to_string(),
        "resource_intent_id": changeset.resource_intent_id.to_string(),
        "workspace_id": changeset.workspace_id.to_string(),
    })
}

fn serialize_localized_edit(edit: &LocalizedEdit) -> Value {
    parse_json(&edit.canonical_json)
}

#[must_use]
pub fn serialize_added_localized_edits(added: &AddedLocalizedEdits) -> Value {
    serde_json::json!({
        "changeset_id": added.changeset_id.to_string(),
        "edit_ids": added.edit_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "first_ordinal": added.first_ordinal,
        "total_edit_count": added.total_edit_count,
    })
}

#[must_use]
pub fn serialize_localized_change_set_diff(diff: &LocalizedChangeSetDiff) -> Value {
    serde_json::json!({
        "changeset_id": diff.changeset_id.to_string(),
        "proposal_digest": diff.proposal_digest.to_string(),
        "effective_leaf_digest": diff.effective_leaf_digest.to_string(),
        "effective_edits": diff.effective_edits.iter().map(serialize_localized_edit).collect::<Vec<_>>(),
    })
}

#[must_use]
pub fn serialize_localized_validation(validation: &LocalizedValidation) -> Value {
    serde_json::json!({
        "changeset_id": validation.changeset_id.to_string(),
        "attempt": validation.attempt,
        "previous_validation_result_digest": validation.previous_validation_result_digest.map(|value| value.to_string()),
        "proposal_digest": validation.proposal_digest.to_string(),
        "effective_leaf_digest": validation.effective_leaf_digest.to_string(),
        "valid": validation.valid,
        "findings": validation.findings.iter().map(serialize_localized_finding).collect::<Vec<_>>(),
        "validation_results_digest": validation.validation_results_digest.to_string(),
        "sealed_changeset_digest": validation.sealed_changeset_digest.map(|value| value.to_string()),
        "status": validation.status.to_string(),
    })
}

fn serialize_localized_finding(finding: &LocalizedFinding) -> Value {
    serde_json::json!({
        "code": finding.code,
        "severity": severity_str(finding.severity),
        "edit_id": finding.edit_id.to_string(),
        "object_id": finding.object_id.to_string(),
        "locale": finding.locale.to_string(),
        "pointer": finding.pointer,
        "validator": finding.validator,
        "policy_digest": finding.policy_digest.to_string(),
    })
}

#[must_use]
pub fn serialize_submitted_localized_changeset(submitted: &SubmittedLocalizedChangeSet) -> Value {
    serde_json::json!({
        "changeset_id": submitted.changeset_id.to_string(),
        "sealed_changeset_digest": submitted.sealed_changeset_digest.to_string(),
        "validation_results_digest": submitted.validation_results_digest.to_string(),
        "submitted_at": submitted.submitted_at.to_string(),
        "status": submitted.status.to_string(),
    })
}

#[must_use]
pub fn serialize_committed_localized_changeset(committed: &CommittedLocalizedChangeSet) -> Value {
    serde_json::json!({
        "changeset_id": committed.changeset_id.to_string(),
        "sealed_changeset_digest": committed.sealed_changeset_digest.to_string(),
        "validation_results_digest": committed.validation_results_digest.to_string(),
        "previous_state": serialize_known_state_reference(&committed.previous_state),
        "resulting_state": serialize_known_state_reference(&committed.resulting_state),
        "renditions": committed.renditions.iter().map(serialize_object_locale_revision).collect::<Vec<_>>(),
        "committed_at": committed.committed_at.to_string(),
        "status": committed.status.to_string(),
    })
}

fn serialize_object_locale_revision(rendition: &ObjectLocaleRevision) -> Value {
    serde_json::json!({
        "api_version": "proof.dev/object-locale-revision/v1",
        "workspace_id": rendition.workspace_id.to_string(),
        "object_id": rendition.object_id.to_string(),
        "locale": rendition.locale.to_string(),
        "revision": rendition.revision.get(),
        "previous_revision_digest": rendition.previous_revision_digest.map(|value| value.to_string()),
        "source_object_revision": rendition.source_object_revision.get(),
        "source_object_digest": rendition.source_object_digest.to_string(),
        "schema_id": rendition.schema_id.to_string(),
        "schema_version": rendition.schema_version.get(),
        "changeset_id": rendition.changeset_id.to_string(),
        "edit_id": rendition.edit_id.to_string(),
        "authoritative_sequence": rendition.authoritative_sequence,
        "content": parse_json(&rendition.canonical_content),
    })
}

#[must_use]
pub fn serialize_localized_edition(edition: &LocalizedEdition) -> Value {
    serde_json::json!({
        "edition_id": edition.edition_id.to_string(),
        "edition_digest": edition.edition_digest.to_string(),
        "manifest": parse_json(&edition.manifest_json),
        "state": serialize_known_state_reference(&edition.state),
    })
}

#[must_use]
pub fn serialize_localized_release(release: &LocalizedRelease) -> Value {
    serde_json::json!({
        "release_id": release.release_id.to_string(),
        "release_digest": release.release_digest.to_string(),
        "proof_id": release.proof_id.to_string(),
        "proof_envelope_digest": release.proof_envelope_digest.to_string(),
        "release_manifest": parse_json(&release.manifest_json),
    })
}

#[must_use]
pub fn serialize_released_rendition_query(query: &ReleasedRenditionQuery) -> Value {
    serde_json::json!({
        "workspace_id": query.workspace_id.to_string(),
        "environment_id": query.environment_id.to_string(),
        "release_id": query.release_id.to_string(),
        "edition": serialize_edition_reference(&query.edition),
        "renditions": query.renditions.iter().map(serialize_released_rendition).collect::<Vec<_>>(),
    })
}

fn serialize_released_rendition(rendition: &ReleasedRendition) -> Value {
    serde_json::json!({
        "object_id": rendition.object_id.to_string(),
        "locale": rendition.locale.to_string(),
        "source_revision": rendition.source_revision.get(),
        "source_digest": rendition.source_digest.to_string(),
        "rendition_revision": rendition.rendition_revision.get(),
        "rendition_digest": rendition.rendition_digest.to_string(),
        "schema_id": rendition.schema_id.to_string(),
        "schema_version": rendition.schema_version.get(),
        "content": parse_json(&rendition.canonical_content),
    })
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// Parses a canonical JSON string, falling back to the raw string when the
/// artifact content is not itself a JSON document.
fn parse_json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::localized_error_code;
    use proof_application::LocalizedContentError;

    #[test]
    fn creation_errors_keep_their_registered_remote_codes() {
        assert_eq!(
            localized_error_code(&LocalizedContentError::IntentSlotMismatch),
            "proof.intent.slot_mismatch"
        );
        assert_eq!(
            localized_error_code(&LocalizedContentError::SchemaNotFound),
            "proof.schema.not_found"
        );
        assert_eq!(
            localized_error_code(&LocalizedContentError::ObjectExists),
            "proof.state.object_exists"
        );
    }
}
