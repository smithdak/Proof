//! Dual Human-session plus Agent-presentation authentication and the
//! per-row authorization rule evaluation (contract §"Remote identity
//! vocabulary", §"Human roles and separation of duties", §"HTTP boundary").

use std::time::{SystemTime, UNIX_EPOCH};

use proof_application::authority::{
    AuthenticatedCommandApiVersion, AuthenticatedInvocationV1, CommandInputV1, PrincipalBindingV1,
};
use proof_attestation::authority::{AuthorityPayloadProfile, verify_authority_envelope};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_remote::{
    AuthorityHeadV1, RemoteOperationV1,
    authority::{
        RemotePrincipalStatusV2, RemotePrincipalType, WorkspaceRole, WorkspaceRoleAssignmentV1,
        WorkspaceRoleRevocationV1,
    },
    derive_key_digest,
    identity::{
        AgentSubjectApiVersion, AgentSubjectV1, AuthenticatedActorContextApiVersion,
        AuthenticatedActorContextHumanAgentV2, AuthenticatedActorContextHumanV2,
        AuthenticatedActorContextV2, OidcAuthenticatedSubjectV1,
        OidcHumanAgentAuthenticationProfile, OidcHumanAuthenticationProfile,
        OidcPrincipalBindingPrivateV1, OidcPrincipalBindingV1, OperatingBindingReferenceV1,
        REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT, RemoteAuthenticationEventApiVersion,
        RemoteAuthenticationEventV1, normalized_operation_input_digest,
    },
    registry::{
        AgentOperationProjectionV1, AuthorizationDecisionKind, DelegationEvaluationV1,
        DelegationResolutionV1, EffectiveConstraintsV1, HumanOperationRegistryV1,
        OperatingBindingEvaluationV1, PrincipalStateV1, RemoteAuthorizationDecisionApiVersion,
        RemoteAuthorizationDecisionV1, RequestedResourcesV1,
    },
};
use serde_json::Value;

use crate::{AppState, ServerError};

/// Direct Human OIDC authentication profile (contract §"Remote identity
/// vocabulary").
pub const OIDC_HUMAN_PROFILE: &str = "proof.server/authentication/oidc-human/v1";

/// Human-plus-Agent authentication profile (contract §"Remote identity
/// vocabulary").
pub const OIDC_HUMAN_AGENT_PROFILE: &str = "proof.server/authentication/oidc-human-agent/v1";

/// Fallback active Workspace authority key identifier used only when the
/// `workspace_authority_root` fact has not been seeded. It is a syntactically
/// valid Ed25519 key identifier (64 lowercase hex digits).
const FALLBACK_AUTHORITY_KEY_ID: &str =
    "ed25519:0000000000000000000000000000000000000000000000000000000000000000";

/// The frozen direct-authority policy profile selected by every Agent row.
const AGENT_DIRECT_AUTHORIZATION_RULE: &str = "proof.local/authority/direct/v1";

/// A live session-resolved requesting Human actor, before Agent presentation
/// proof (contract §"Remote identity vocabulary").
#[derive(Clone, Debug)]
pub struct RequestingHuman {
    /// Requesting Principal identity (UUIDv7).
    pub principal_id: String,
    /// Requesting binding identity (UUIDv7).
    pub binding_id: String,
    /// Requesting binding record digest.
    pub binding_record_digest: ContentDigest,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
}

/// Authenticates a live requesting-Human session to
/// `proof.server/authentication/oidc-human/v1` (contract §"Remote identity
/// vocabulary").
///
/// The returned context re-resolves the immutable binding, the current
/// Principal status, and the exact authority head per call. Because this
/// function has no request-scoped operation or normalized input, its
/// `operation` and `normalized_input_digest` fields are unbound placeholders:
/// the dispatch layer must overwrite both from the parsed request before
/// evaluation. Every authentication failure is disclosure-neutral and maps to
/// a uniform 401 `proof.auth.denied` with no binding-existence oracle.
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] when the session, binding, or
/// Principal is not currently authentication-valid. Returns
/// [`ServerError::Storage`] when the authority store is unavailable.
pub fn authenticate_human_session(
    state: &AppState,
    session: &crate::session::SessionRecord,
) -> Result<AuthenticatedActorContextV2, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let head = read_authority_head(runtime)?
        .ok_or_else(|| auth_denied("the Workspace has no authority head"))?;

    let public = read_public_binding(runtime, &session.binding_id)?;
    let private = read_private_binding(runtime, &session.binding_id)?;
    private
        .validate_against(&public)
        .map_err(|_| auth_denied("binding is not authentication-valid"))?;

    // Cross-check the session-bound identities against the immutable binding.
    if public.principal_id != session.principal_id
        || public.workspace_id != session.workspace_id
        || public.binding_id != session.binding_id
    {
        return Err(auth_denied("session does not match the immutable binding"));
    }
    let binding_record_digest = public
        .binding_record_digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    let principal_enabled = resolve_principal_enabled(runtime, &session.principal_id)?;
    if !principal_enabled {
        return Err(auth_denied("requesting Principal is not enabled"));
    }

    let issuer_configuration_digest = state
        .config
        .issuer
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    let authenticated_at = system_time_to_timestamp(session.created_at)?;
    let expires_at = system_time_to_timestamp(session.absolute_expiry)?;

    let authentication_event = RemoteAuthenticationEventV1 {
        api_version: RemoteAuthenticationEventApiVersion::V1,
        workspace_id: session.workspace_id.clone(),
        authentication_event_id: session.authentication_event_id.clone(),
        authentication_method: "oidc-authorization-code-pkce-s256".to_owned(),
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        requesting_subject_commitment: private.subject_commitment,
        requesting_binding_id: session.binding_id.clone(),
        requesting_binding_record_digest: binding_record_digest,
        requesting_principal_id: session.principal_id.clone(),
        authenticated_at,
        expires_at,
    };
    let authentication_event_digest = authentication_event
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    // Unbound request-scoped placeholders: the dispatch layer replaces these
    // from the parsed operation request before authorization evaluation.
    let operation = RemoteOperationV1 {
        name: String::new(),
        version: String::new(),
    };
    let normalized_input_digest = normalized_operation_input_digest(&Value::Null, &operation)
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    let context = AuthenticatedActorContextHumanV2 {
        api_version: AuthenticatedActorContextApiVersion::V1,
        audience: workspace_audience(&session.workspace_id),
        authentication_profile: OidcHumanAuthenticationProfile::V1,
        oidc_issuer_configuration_digest: issuer_configuration_digest,
        normalized_input_digest,
        requesting_subject: private.subject.clone(),
        requesting_subject_commitment: private.subject_commitment,
        requesting_binding_id: session.binding_id.clone(),
        requesting_binding_record_digest: binding_record_digest,
        requesting_principal_id: session.principal_id.clone(),
        authentication_event_id: session.authentication_event_id.clone(),
        authentication_event_digest,
        operation,
        authenticated_at,
        evaluated_authority_head: head,
        workspace_id: session.workspace_id.clone(),
    };
    Ok(AuthenticatedActorContextV2::Human(context))
}

/// A live requesting-Human binding resolved from an authenticated OIDC subject
/// during login/callback (contract §"OIDC binding and session boundary").
#[derive(Clone, Debug)]
pub struct ResolvedOidcBinding {
    /// Owning Workspace identity (UUIDv7).
    pub workspace_id: String,
    /// Bound Human Principal identity (UUIDv7).
    pub principal_id: String,
    /// Binding identity (UUIDv7).
    pub binding_id: String,
}

/// Resolves the single active protected OIDC Principal binding for an
/// authenticated `{issuer, subject}` tuple (contract §"OIDC binding and session
/// boundary").
///
/// Every candidate protected binding is re-validated against its public
/// commitment-only record and the highest-authority-sequence survivor whose
/// Principal is enabled is returned. An unknown, superseded, mismatched, or
/// disabled subject fails closed with the same disclosure-neutral
/// [`ServerError::Authorization`] as every other identity failure — no
/// binding-existence oracle.
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] when no authentication-valid binding
/// matches the subject, or [`ServerError::Storage`] when the authority store is
/// unavailable.
pub fn resolve_oidc_binding_by_subject(
    state: &AppState,
    subject: &OidcAuthenticatedSubjectV1,
) -> Result<ResolvedOidcBinding, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let mut best: Option<(OidcPrincipalBindingV1, OidcPrincipalBindingPrivateV1)> = None;
    for body in read_facts_by_kind(runtime, "oidc_private_binding")? {
        let Ok(private) = serde_json::from_slice::<OidcPrincipalBindingPrivateV1>(&body) else {
            continue;
        };
        if private.subject != *subject {
            continue;
        }
        let Ok(public) = read_public_binding(runtime, &private.binding_id) else {
            continue;
        };
        if private.validate_against(&public).is_err() {
            continue;
        }
        let is_newer = best
            .as_ref()
            .is_none_or(|(current, _)| public.authority_sequence > current.authority_sequence);
        if is_newer {
            best = Some((public, private));
        }
    }

    let Some((public, _private)) = best else {
        return Err(auth_denied("no binding matches the authenticated subject"));
    };
    if !resolve_principal_enabled(runtime, &public.principal_id)? {
        return Err(auth_denied("requesting Principal is not enabled"));
    }

    Ok(ResolvedOidcBinding {
        workspace_id: public.workspace_id,
        principal_id: public.principal_id,
        binding_id: public.binding_id,
    })
}

/// Verifies a fresh single-use `AuthenticatedCommandV1` against the pre-bound
/// Agent key and composes the Human-plus-Agent context under
/// `proof.server/authentication/oidc-human-agent/v1` (contract §"Remote
/// identity vocabulary", §"HTTP boundary").
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] for an invalid, replayed, or
/// mismatched Agent presentation.
pub fn authenticate_agent_presentation(
    state: &AppState,
    session: &crate::session::SessionRecord,
    invocation: &AuthenticatedInvocationV1,
) -> Result<AuthenticatedActorContextV2, ServerError> {
    // The requesting-Human half must already be authentication-valid.
    let human = match authenticate_human_session(state, session)? {
        AuthenticatedActorContextV2::Human(human) => human,
        AuthenticatedActorContextV2::HumanAgent(_) => {
            return Err(auth_denied("expected a direct Human session"));
        }
    };

    let envelope = invocation.authentication.as_str().as_bytes();
    // Parse first (without trust) to learn the operating binding identity.
    let parsed = proof_attestation::authority::parse_authority_envelope::<
        proof_application::authority::AuthenticatedCommandV1,
    >(envelope, AuthorityPayloadProfile::AuthenticatedCommand)
    .map_err(|_| auth_denied("Agent presentation is malformed"))?;
    let command = &parsed.payload;

    let binding = read_agent_binding(state, &command.binding_id.to_string())?;
    let key_id = binding
        .authenticated_subject
        .as_subject()
        .subject()
        .to_owned();

    let verified =
        verify_authority_envelope::<proof_application::authority::AuthenticatedCommandV1>(
            envelope,
            AuthorityPayloadProfile::AuthenticatedCommand,
            &[&key_id],
        )
        .map_err(|_| auth_denied("Agent presentation signature is invalid"))?;
    let command = &verified.parsed.payload;

    let command_input = &invocation.command_input;
    let workspace_id = parse_workspace_id(&session.workspace_id)?;
    if command.audience
        != proof_application::authority::AuthorityAudience::for_workspace(workspace_id)
        || command.workspace_id != workspace_id
        || command_input.workspace_id != workspace_id
    {
        return Err(auth_denied("Agent presentation audience does not match"));
    }
    if command.operation != command_input.operation {
        return Err(auth_denied("Agent presentation operation does not match"));
    }

    // The signed command digest must reproduce from the exact command input.
    let command_input_value = serde_json::to_value(command_input)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let canonical_command = canonicalize(&command_input_value)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let command_digest = digest(ArtifactKind::CommandV1, &canonical_command);
    if command.command_digest != command_digest {
        return Err(auth_denied(
            "Agent presentation command digest does not match",
        ));
    }

    let requesting_principal_id = parse_principal_id(&session.principal_id)?;
    command_input
        .validate_authenticated_command(command, requesting_principal_id, binding.principal_id)
        .map_err(|_| auth_denied("Agent presentation actor cross-checks failed"))?;
    if binding.workspace_id != workspace_id
        || binding.principal_id != command.operating_principal_id
        || command.requesting_principal_id != requesting_principal_id
    {
        return Err(auth_denied("Agent presentation actor mismatch"));
    }
    if !binding.is_time_active(now_timestamp()?) {
        return Err(auth_denied("Agent binding is not currently active"));
    }

    // Bounded command lifetime plus future-skew allowance.
    let issued_at = command.issued_at.unix_timestamp_nanos();
    let expires_at = command.expires_at.unix_timestamp_nanos();
    let evaluated = now_timestamp()?.unix_timestamp_nanos();
    let lifetime = expires_at - issued_at;
    if lifetime <= 0
        || lifetime
            > i128::from(proof_application::authority::MAX_COMMAND_LIFETIME_SECONDS) * 1_000_000_000
    {
        return Err(auth_denied("Agent presentation lifetime is invalid"));
    }
    if issued_at - evaluated
        > i128::from(proof_application::authority::MAX_COMMAND_FUTURE_SKEW_SECONDS) * 1_000_000_000
    {
        return Err(auth_denied("Agent presentation is not yet valid"));
    }
    if evaluated >= expires_at {
        return Err(auth_denied("Agent presentation has expired"));
    }

    // Fresh single-use presentation: reject an already-consumed presentation.
    if presentation_consumed(state, &command.presentation_id.to_string())? {
        return Err(auth_denied("Agent presentation was already consumed"));
    }

    let binding_record_digest =
        proof_remote::authority::RemoteAuthorityRecordV1::agent_binding_issue(binding.clone())
            .digest();

    let operating_subject = AgentSubjectV1 {
        api_version: AgentSubjectApiVersion::V1,
        provider: "proof/local-ed25519".to_owned(),
        subject: key_id,
    };
    let operating_binding = OperatingBindingReferenceV1 {
        authority_sequence: binding.authority_sequence.get(),
        binding_id: binding.binding_id.to_string(),
        record_digest: binding_record_digest,
    };

    let operation = RemoteOperationV1 {
        name: command_input.operation.name().to_owned(),
        version: command_input.operation.version().to_owned(),
    };
    let normalized_input_digest = normalized_operation_input_digest(
        &Value::Object(command_input.normalized_input.clone()),
        &operation,
    )
    .map_err(|error| ServerError::Internal(error.to_string()))?;

    let context = AuthenticatedActorContextHumanAgentV2 {
        api_version: AuthenticatedActorContextApiVersion::V1,
        audience: human.audience.clone(),
        authentication_profile: OidcHumanAgentAuthenticationProfile::V1,
        oidc_issuer_configuration_digest: human.oidc_issuer_configuration_digest,
        normalized_input_digest,
        requesting_subject: human.requesting_subject.clone(),
        requesting_subject_commitment: human.requesting_subject_commitment,
        requesting_binding_id: human.requesting_binding_id.clone(),
        requesting_binding_record_digest: human.requesting_binding_record_digest,
        requesting_principal_id: human.requesting_principal_id.clone(),
        authentication_event_id: human.authentication_event_id.clone(),
        authentication_event_digest: human.authentication_event_digest,
        operating_subject,
        operating_binding,
        operating_principal_id: binding.principal_id.to_string(),
        delegation_id: command.delegation_id.to_string(),
        operation,
        command_digest: command.command_digest,
        command_envelope_digest: verified.parsed.envelope_digest,
        presentation_id: command.presentation_id.to_string(),
        authenticated_at: now_timestamp()?,
        evaluated_authority_head: human.evaluated_authority_head,
        workspace_id: human.workspace_id.clone(),
    };
    Ok(AuthenticatedActorContextV2::HumanAgent(context))
}

/// Returns the closed authentication profile of one actor context.
#[must_use]
pub fn actor_profile(
    context: &AuthenticatedActorContextV2,
) -> proof_remote::identity::AuthenticationProfile {
    context.profile()
}

/// Evaluates the per-row authorization rule plus `roles_any_of` at the exact
/// locked authority head, producing the signed
/// [`RemoteAuthorizationDecisionV1`] (contract §"Human roles and separation of
/// duties", §"HTTP boundary").
///
/// The returned decision carries `decision: Allow` or `decision: Deny`. The
/// caller (the operation executor) commits the decision — a denial commits the
/// decision alone and surfaces 403 `proof.authorization.denied`.
///
/// # Errors
///
/// Returns [`ServerError::Storage`] when the authority store is unavailable.
pub fn evaluate_authorization(
    state: &AppState,
    actor_context: &AuthenticatedActorContextV2,
    normalized_input: &Value,
) -> Result<RemoteAuthorizationDecisionV1, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let head = read_authority_head(runtime)?.ok_or_else(|| {
        ServerError::Authorization("the Workspace has no authority head".to_owned())
    })?;
    let authority_key_id =
        read_authority_key_id(runtime)?.unwrap_or_else(|| FALLBACK_AUTHORITY_KEY_ID.to_owned());

    let (
        profile,
        workspace_id,
        operation,
        requesting_principal_id,
        requesting_binding_id,
        requesting_binding_record_digest,
        requesting_subject_commitment,
    ) = actor_identity(actor_context);

    let public_input_projection_digest =
        proof_remote::identity::public_operation_input_projection_digest(
            normalized_input,
            &operation,
        )
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let actor_context_digest =
        actor_evidence_digest(actor_context, public_input_projection_digest)?;

    let (
        authorization_rule,
        requested_action,
        role_assignment_digests,
        agent_authorization,
        denied_reason,
    ) = match actor_context {
        AuthenticatedActorContextV2::Human(_) => {
            let row = HumanOperationRegistryV1
                .lookup(&operation.name, &operation.version)
                .ok_or_else(|| {
                    ServerError::Dispatch(format!(
                        "unregistered Human operation `{}` at `{}`",
                        operation.name, operation.version
                    ))
                })?;
            let (roles, role_digests) = resolve_active_roles(runtime, &requesting_principal_id)?;
            if roles_any_of(&roles, &row.roles_any_of) {
                (
                    row.authorization_rule.clone(),
                    human_requested_action(&operation.name),
                    role_digests,
                    None,
                    None,
                )
            } else {
                (
                    row.authorization_rule.clone(),
                    human_requested_action(&operation.name),
                    role_digests,
                    None,
                    Some("required_role_missing"),
                )
            }
        }
        AuthenticatedActorContextV2::HumanAgent(context) => {
            let row = AgentOperationProjectionV1
                .lookup(&operation.name, &operation.version)
                .ok_or_else(|| {
                    ServerError::Dispatch(format!(
                        "unregistered Agent operation `{}` at `{}`",
                        operation.name, operation.version
                    ))
                })?;
            (
                row.authorization_rule.clone(),
                row.requested_action.clone(),
                Vec::new(),
                Some(build_agent_authorization(context)?),
                None,
            )
        }
    };

    let requested_resources_digest =
        proof_remote::registry::requested_authorization_resources_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            &authorization_rule,
            &operation,
            &requested_action,
            &[],
        )
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let policy_bundle_digest =
        proof_remote::registry::remote_authorization_policy_selection_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            &authorization_rule,
            None,
            None,
        )
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    let (decision, public_code, reason_code) = match denied_reason {
        Some(reason) => (
            AuthorizationDecisionKind::Deny,
            Some("proof.authorization.denied".to_owned()),
            reason.to_owned(),
        ),
        None => (AuthorizationDecisionKind::Allow, None, String::new()),
    };

    let mut built = RemoteAuthorizationDecisionV1 {
        api_version: RemoteAuthorizationDecisionApiVersion::V1,
        authentication_profile: profile.to_owned(),
        authorization_registry_sha256: String::new(),
        operation_registry_sha256: String::new(),
        authorization_rule,
        workspace_id,
        decision_id: uuid::Uuid::now_v7().to_string(),
        operation,
        requested_action,
        public_input_projection_digest,
        actor_context_digest,
        requesting_principal_id,
        requesting_binding_id,
        requesting_binding_record_digest,
        requesting_subject_commitment,
        agent_authorization,
        role_assignment_digests,
        requested_resources_digest,
        policy_bundle_digest,
        environment_config_digest: None,
        decision,
        public_code,
        reason_code,
        evaluated_at: now_timestamp()?,
        evaluated_authority_head: head,
        authority_sequence: head.sequence.saturating_add(1),
        previous_authority_record_digest: head.record_digest,
        authority_key_id,
    };
    built.bind_registry_hashes();
    Ok(built)
}

/// Checks whether any assigned role satisfies the exact `roles_any_of` set
/// (contract §"Human roles and separation of duties"). Holding one listed role
/// is necessary but never bypasses the rule's contextual checks.
#[must_use]
pub fn roles_any_of(assigned: &[WorkspaceRole], required: &[WorkspaceRole]) -> bool {
    required
        .iter()
        .any(|required_role| assigned.contains(required_role))
}

/// Resolves the exact `roles_any_of` set for one Human operation row (contract
/// §"Human and control operation registry").
#[must_use]
pub fn required_roles_for(operation: &RemoteOperationV1) -> Vec<WorkspaceRole> {
    HumanOperationRegistryV1
        .lookup(&operation.name, &operation.version)
        .map(|row| row.roles_any_of.clone())
        .unwrap_or_default()
}

/// Mismatch guard: a request-carried Principal, Delegation, or Workspace
/// identifier is an expected-value cross-check only — it never selects or
/// authenticates an actor (contract §"HTTP boundary").
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] when a request-carried identifier
/// diverges from the derived value.
pub fn guard_request_carried_identity(
    expected: &str,
    supplied: Option<&str>,
    label: &str,
) -> Result<(), ServerError> {
    match supplied {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(ServerError::Authorization(format!(
            "request-carried {label} `{value}` does not match the derived `{expected}`"
        ))),
        None => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn lock_pg(
    state: &AppState,
) -> Result<std::sync::MutexGuard<'_, Option<proof_pg::wiring::PgRuntime>>, ServerError> {
    state
        .pg
        .lock()
        .map_err(|_| ServerError::Internal("PostgreSQL runtime lock is poisoned".to_owned()))
}

fn runtime_mut<'a>(
    guard: &'a mut std::sync::MutexGuard<'_, Option<proof_pg::wiring::PgRuntime>>,
) -> Result<&'a mut proof_pg::wiring::PgRuntime, ServerError> {
    guard.as_mut().ok_or_else(|| {
        ServerError::Storage(proof_pg::PgError::Connect(
            "PostgreSQL runtime is not connected".to_owned(),
        ))
    })
}

fn auth_denied(_detail: &str) -> ServerError {
    // Disclosure-neutral pre-proof identity failure: no binding-existence or
    // Principal-status oracle, and it must project to 401 `proof.auth.denied`
    // (never the 403 authorization-denied code reserved for a proven denial).
    ServerError::Authentication("authentication denied".to_owned())
}

fn storage_error(message: impl Into<String>) -> ServerError {
    ServerError::Storage(proof_pg::PgError::Transaction(message.into()))
}

fn now_timestamp() -> Result<Timestamp, ServerError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_| {
        ServerError::Internal("system clock exceeds the timestamp range".to_owned())
    })?;
    Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn system_time_to_timestamp(value: SystemTime) -> Result<Timestamp, ServerError> {
    let duration = value
        .duration_since(UNIX_EPOCH)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_| {
        ServerError::Internal("system clock exceeds the timestamp range".to_owned())
    })?;
    Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn parse_workspace_id(value: &str) -> Result<proof_domain::WorkspaceId, ServerError> {
    value
        .parse()
        .map_err(|_| ServerError::Authorization("invalid Workspace identity".to_owned()))
}

fn parse_principal_id(value: &str) -> Result<proof_domain::PrincipalId, ServerError> {
    value
        .parse()
        .map_err(|_| ServerError::Authorization("invalid Principal identity".to_owned()))
}

fn workspace_audience(workspace_id: &str) -> String {
    format!("proof://workspace/{workspace_id}")
}

fn read_authority_head(
    runtime: &mut proof_pg::wiring::PgRuntime,
) -> Result<Option<AuthorityHeadV1>, ServerError> {
    let client = runtime.client_mut();
    let row = client
        .query_opt(
            "SELECT authority_head_digest, authority_head_sequence
             FROM workspace_write_head WHERE singleton = 1",
            &[],
        )
        .map_err(|error| storage_error(format!("read authority head: {error}")))?;
    let Some(row) = row else {
        return Err(storage_error(
            "the Workspace write head singleton is absent",
        ));
    };
    let digest: Option<String> = row.get(0);
    let sequence: Option<i64> = row.get(1);
    match (digest, sequence) {
        (None, None) => Ok(None),
        (Some(digest), Some(sequence)) => {
            let record_digest = digest.parse::<ContentDigest>().map_err(|error| {
                storage_error(format!("invalid authority head digest: {error}"))
            })?;
            let sequence = u64::try_from(sequence)
                .map_err(|_| storage_error("authority head sequence is negative"))?;
            Ok(Some(AuthorityHeadV1 {
                sequence,
                record_digest,
            }))
        }
        _ => Err(storage_error(
            "authority head digest and sequence are not both present",
        )),
    }
}

fn read_authority_key_id(
    runtime: &mut proof_pg::wiring::PgRuntime,
) -> Result<Option<String>, ServerError> {
    let client = runtime.client_mut();
    let row = client
        .query_opt(
            "SELECT body FROM facts WHERE fact_id = 'workspace_authority_root'",
            &[],
        )
        .map_err(|error| storage_error(format!("read authority root: {error}")))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let body: Vec<u8> = row.get(0);
    let value: Value = serde_json::from_slice(&body)
        .map_err(|error| storage_error(format!("invalid authority root body: {error}")))?;
    Ok(value
        .get("authority_key_id")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

fn read_fact_body(
    runtime: &mut proof_pg::wiring::PgRuntime,
    fact_id: &str,
) -> Result<Option<Vec<u8>>, ServerError> {
    let row = runtime
        .client_mut()
        .query_opt("SELECT body FROM facts WHERE fact_id = $1", &[&fact_id])
        .map_err(|error| storage_error(format!("read fact {fact_id}: {error}")))?;
    Ok(row.map(|row| row.get::<_, Vec<u8>>(0)))
}

fn read_facts_by_kind(
    runtime: &mut proof_pg::wiring::PgRuntime,
    kind: &str,
) -> Result<Vec<Vec<u8>>, ServerError> {
    let rows = runtime
        .client_mut()
        .query(
            "SELECT body FROM facts WHERE fact_kind = $1 ORDER BY authority_sequence",
            &[&kind],
        )
        .map_err(|error| storage_error(format!("read facts of kind {kind}: {error}")))?;
    Ok(rows.iter().map(|row| row.get::<_, Vec<u8>>(0)).collect())
}

fn read_public_binding(
    runtime: &mut proof_pg::wiring::PgRuntime,
    binding_id: &str,
) -> Result<OidcPrincipalBindingV1, ServerError> {
    let body = read_fact_body(runtime, &format!("oidc_binding/{binding_id}"))?
        .ok_or_else(|| auth_denied("binding is unknown"))?;
    serde_json::from_slice(&body).map_err(|_| auth_denied("binding is not authentication-valid"))
}

fn read_private_binding(
    runtime: &mut proof_pg::wiring::PgRuntime,
    binding_id: &str,
) -> Result<OidcPrincipalBindingPrivateV1, ServerError> {
    let body = read_fact_body(runtime, &format!("oidc_private_binding/{binding_id}"))?
        .ok_or_else(|| auth_denied("binding is unknown"))?;
    serde_json::from_slice(&body).map_err(|_| auth_denied("binding is not authentication-valid"))
}

fn read_agent_binding(
    state: &AppState,
    binding_id: &str,
) -> Result<PrincipalBindingV1, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let body = read_fact_body(runtime, &format!("agent_binding/{binding_id}"))?
        .ok_or_else(|| auth_denied("Agent binding is unknown"))?;
    serde_json::from_slice(&body)
        .map_err(|_| auth_denied("Agent binding is not authentication-valid"))
}

fn resolve_principal_enabled(
    runtime: &mut proof_pg::wiring::PgRuntime,
    principal_id: &str,
) -> Result<bool, ServerError> {
    let bodies = read_facts_by_kind(runtime, "principal_status")?;
    let mut latest: Option<RemotePrincipalStatusV2> = None;
    for body in bodies {
        let Ok(status) = serde_json::from_slice::<RemotePrincipalStatusV2>(&body) else {
            continue;
        };
        if status.principal_id != principal_id {
            continue;
        }
        if latest
            .as_ref()
            .is_none_or(|current: &RemotePrincipalStatusV2| {
                status.authority_sequence >= current.authority_sequence
            })
        {
            latest = Some(status);
        }
    }
    Ok(latest.is_none_or(|status| status.enabled))
}

fn resolve_active_roles(
    runtime: &mut proof_pg::wiring::PgRuntime,
    principal_id: &str,
) -> Result<(Vec<WorkspaceRole>, Vec<ContentDigest>), ServerError> {
    let mut revoked: Vec<String> = Vec::new();
    for body in read_facts_by_kind(runtime, "workspace_role_revocation")? {
        if let Ok(revocation) = serde_json::from_slice::<WorkspaceRoleRevocationV1>(&body)
            && revocation.principal_id == principal_id
        {
            revoked.push(revocation.assignment_id);
        }
    }

    let mut roles = Vec::new();
    let mut digests = Vec::new();
    for body in read_facts_by_kind(runtime, "workspace_role_assignment")? {
        let Ok(assignment) = serde_json::from_slice::<WorkspaceRoleAssignmentV1>(&body) else {
            continue;
        };
        if assignment.principal_id != principal_id || revoked.contains(&assignment.assignment_id) {
            continue;
        }
        digests.push(
            proof_remote::authority::RemoteAuthorityRecordV1::workspace_role_assignment(
                assignment.clone(),
            )
            .digest(),
        );
        roles.push(assignment.role);
    }
    Ok((roles, digests))
}

fn presentation_consumed(state: &AppState, presentation_id: &str) -> Result<bool, ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    Ok(read_fact_body(
        runtime,
        &format!("presentation_consumption/{presentation_id}"),
    )?
    .is_some())
}

/// The seven actor-identity fields extracted from a context for decision
/// building.
type ActorIdentity = (
    &'static str,
    String,
    RemoteOperationV1,
    String,
    String,
    ContentDigest,
    ContentDigest,
);

fn actor_identity(context: &AuthenticatedActorContextV2) -> ActorIdentity {
    match context {
        AuthenticatedActorContextV2::Human(human) => (
            OIDC_HUMAN_PROFILE,
            human.workspace_id.clone(),
            human.operation.clone(),
            human.requesting_principal_id.clone(),
            human.requesting_binding_id.clone(),
            human.requesting_binding_record_digest,
            human.requesting_subject_commitment,
        ),
        AuthenticatedActorContextV2::HumanAgent(agent) => (
            OIDC_HUMAN_AGENT_PROFILE,
            agent.workspace_id.clone(),
            agent.operation.clone(),
            agent.requesting_principal_id.clone(),
            agent.requesting_binding_id.clone(),
            agent.requesting_binding_record_digest,
            agent.requesting_subject_commitment,
        ),
    }
}

fn actor_evidence_digest(
    context: &AuthenticatedActorContextV2,
    public_input_projection_digest: ContentDigest,
) -> Result<ContentDigest, ServerError> {
    context
        .redact(public_input_projection_digest)
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn build_agent_authorization(
    context: &AuthenticatedActorContextHumanAgentV2,
) -> Result<proof_remote::registry::AgentAuthorizationV1, ServerError> {
    let requested_action = AgentOperationProjectionV1
        .lookup(&context.operation.name, &context.operation.version)
        .map_or_else(
            || context.operation.name.replace('.', ":"),
            |row| row.requested_action.clone(),
        );
    let policy_bundle_digest =
        proof_remote::registry::remote_authorization_policy_selection_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            AGENT_DIRECT_AUTHORIZATION_RULE,
            None,
            None,
        )
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let _ = requested_action;
    Ok(proof_remote::registry::AgentAuthorizationV1 {
        command_digest: context.command_digest,
        command_envelope_digest: context.command_envelope_digest,
        presentation_id: context.presentation_id.clone(),
        presentation_consumed: false,
        operating_principal_id: context.operating_principal_id.clone(),
        principal_state: PrincipalStateV1 {
            requesting_principal_enabled: true,
            operating_principal_enabled: true,
        },
        binding: OperatingBindingEvaluationV1 {
            active: true,
            binding_id: context.operating_binding.binding_id.clone(),
            authority_sequence: context.operating_binding.authority_sequence,
            record_digest: context.operating_binding.record_digest,
            revocation_record_digest: None,
        },
        delegation: DelegationEvaluationV1 {
            delegation_id: context.delegation_id.clone(),
            record_digest: None,
            revocation_record_digest: None,
            resolution: DelegationResolutionV1::NotFoundOrHidden,
        },
        policy_profile: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
        policy_bundle_digest,
        requested_resources: RequestedResourcesV1 {
            workspace_ids: Vec::new(),
            environment_ids: Vec::new(),
            object_ids: Vec::new(),
            schema_ids: Vec::new(),
            locales: Vec::new(),
            changeset_ids: Vec::new(),
            edition_ids: Vec::new(),
            release_ids: Vec::new(),
        },
        effective_constraints: EffectiveConstraintsV1 {
            max_objects: 100,
            max_context_bytes: 1_048_576,
            max_edits_per_changeset: 100,
        },
    })
}

/// Maps a Human operation name to its frozen `requested_action` selector
/// (mirrors `http-operation-registry.valid.json`).
#[must_use]
fn human_requested_action(name: &str) -> String {
    let action = match name {
        "agent-binding.issue" => "agent_binding:issue",
        "agent-binding.revoke" => "agent_binding:revoke",
        "changeset.approve" => "changeset:approve",
        "changeset.diff" => "changeset:diff",
        "changeset.get" => "changeset:get",
        "content-resource-intent.issue" => "content_resource_intent:issue",
        "context.build" => "context:build",
        "delegation.issue" => "delegation:issue",
        "delegation.revoke" => "delegation:revoke",
        "delivery.abandon" => "delivery:abandon",
        "delivery.get" => "delivery:get",
        "delivery.replay" => "delivery:replay",
        "environment-config.activate" => "environment_config:activate",
        "environment-config.propose" => "environment_config:propose",
        "evidence.export" => "evidence:export",
        "evidence.export.get" => "evidence:read",
        "oidc-binding.issue" => "oidc_binding:issue",
        "oidc-binding.revoke" => "oidc_binding:revoke",
        "principal.status.set" => "principal:disable",
        "release.get" => "release:get",
        "release.verify" => "release:verify",
        "workspace-role.assign" => "workspace_role:assign",
        "workspace-role.revoke" => "workspace_role:revoke",
        _ => return name.replace('.', ":"),
    };
    action.to_owned()
}
