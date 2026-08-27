//! Dual Human-session plus Agent-presentation authentication and the
//! per-row authorization rule evaluation (contract §"Remote identity
//! vocabulary", §"Human roles and separation of duties", §"HTTP boundary").

use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use proof_application::authority::{
    AuthenticatedCommandApiVersion, AuthenticatedInvocationV1, AuthorityOperation,
    CommandInputApiVersion, CommandInputV1, DelegationRevocationV1, DelegationV2,
    PrincipalBindingRevocationV1, PrincipalBindingV1,
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
        OidcPrincipalBindingPrivateV1, OidcPrincipalBindingRevocationV1, OidcPrincipalBindingV1,
        OperatingBindingReferenceV1, REMOTE_NORMALIZED_OPERATION_INPUT_DIGEST_CONTEXT,
        RemoteAuthenticationEventApiVersion, RemoteAuthenticationEventV1,
        normalized_operation_input_digest, public_operation_input_projection_digest,
    },
    registry::{
        AgentOperationProjectionV1, AuthorizationDecisionKind, DelegationEvaluationV1,
        DelegationResolutionV1, EffectiveConstraintsV1, HumanOperationRegistryV1,
        OperatingBindingEvaluationV1, PrincipalStateV1, RemoteAuthorizationDecisionApiVersion,
        RemoteAuthorizationDecisionV1, RequestedAuthorizationResourceBindingV1,
        RequestedResourcesV1,
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

/// One exact authenticated-attempt artifact prepared before the authoritative
/// transaction. Preparation verifies bytes and digests but never persists
/// them; the operation unit of work commits the complete set atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAttemptArtifact {
    /// Closed remote evidence artifact kind.
    pub kind: &'static str,
    /// Domain-separated digest of `body`.
    pub digest: ContentDigest,
    /// Exact canonical body or signed envelope bytes.
    pub body: Vec<u8>,
}

/// Verified Agent request material that is safe to carry to the locked unit of
/// work but has not yet consumed its presentation or written storage.
#[derive(Clone, Debug)]
pub struct PreparedAgentAttempt {
    /// Adapter-derived protected actor context.
    pub actor_context: AuthenticatedActorContextV2,
    /// Exact attempt artifacts committed with the decision.
    pub artifacts: Vec<PreparedAttemptArtifact>,
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
    if oidc_binding_is_revoked(runtime, &session.binding_id)? {
        return Err(auth_denied("binding is not authentication-valid"));
    }
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
        operation: operation.clone(),
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
        if oidc_binding_is_revoked(runtime, &public.binding_id)? {
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
    prepare_agent_attempt(state, session, invocation).map(|attempt| attempt.actor_context)
}

/// Verifies one Agent presentation and prepares its exact evidence bytes
/// without writing storage. The returned material must be passed to the
/// authoritative operation transaction, which claims the presentation and
/// persists all artifacts atomically.
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] for an invalid, replayed, or
/// mismatched Agent presentation.
pub fn prepare_agent_attempt(
    state: &AppState,
    session: &crate::session::SessionRecord,
    invocation: &AuthenticatedInvocationV1,
) -> Result<PreparedAgentAttempt, ServerError> {
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
        operation: operation.clone(),
        command_digest: command.command_digest,
        command_envelope_digest: verified.parsed.envelope_digest,
        presentation_id: command.presentation_id.to_string(),
        authenticated_at: now_timestamp()?,
        evaluated_authority_head: human.evaluated_authority_head,
        workspace_id: human.workspace_id.clone(),
    };
    let actor_context = AuthenticatedActorContextV2::HumanAgent(context);

    let authentication_event = RemoteAuthenticationEventV1 {
        api_version: RemoteAuthenticationEventApiVersion::V1,
        workspace_id: session.workspace_id.clone(),
        authentication_event_id: session.authentication_event_id.clone(),
        authentication_method: "oidc-authorization-code-pkce-s256".to_owned(),
        oidc_issuer_configuration_digest: human.oidc_issuer_configuration_digest,
        requesting_subject_commitment: human.requesting_subject_commitment,
        requesting_binding_id: human.requesting_binding_id.clone(),
        requesting_binding_record_digest: human.requesting_binding_record_digest,
        requesting_principal_id: human.requesting_principal_id.clone(),
        authenticated_at: system_time_to_timestamp(session.created_at)?,
        expires_at: system_time_to_timestamp(session.absolute_expiry)?,
    };
    let authentication_event_value = serde_json::to_value(&authentication_event)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let authentication_event_bytes = canonicalize(&authentication_event_value)
        .map_err(|error| ServerError::Internal(error.to_string()))?
        .as_bytes()
        .to_vec();
    let authentication_event_digest = authentication_event
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    if authentication_event_digest != human.authentication_event_digest {
        return Err(ServerError::Internal(
            "reconstructed authentication event digest differs from the session context".to_owned(),
        ));
    }

    let public_input_projection_digest = public_operation_input_projection_digest(
        &Value::Object(command_input.normalized_input.clone()),
        &operation,
    )
    .map_err(|error| ServerError::Internal(error.to_string()))?;
    let actor_evidence = actor_context.redact(public_input_projection_digest);
    let actor_evidence_value = serde_json::to_value(&actor_evidence)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let actor_evidence_bytes = canonicalize(&actor_evidence_value)
        .map_err(|error| ServerError::Internal(error.to_string()))?
        .as_bytes()
        .to_vec();
    let actor_evidence_digest = actor_evidence
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;

    Ok(PreparedAgentAttempt {
        actor_context,
        artifacts: vec![
            PreparedAttemptArtifact {
                kind: "remote-authentication-event",
                digest: authentication_event_digest,
                body: authentication_event_bytes,
            },
            PreparedAttemptArtifact {
                kind: "remote-actor-evidence",
                digest: actor_evidence_digest,
                body: actor_evidence_bytes,
            },
            PreparedAttemptArtifact {
                kind: "remote-command-input",
                digest: command_digest,
                body: canonical_command.as_bytes().to_vec(),
            },
            PreparedAttemptArtifact {
                kind: "remote-authenticated-command-envelope",
                digest: verified.parsed.envelope_digest,
                body: envelope.to_vec(),
            },
        ],
    })
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

    let evaluated_at = now_timestamp()?;
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
                    Some("proof.authorization.denied".to_owned()),
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
            let assessment = build_agent_authorization(
                runtime.client_mut(),
                context,
                normalized_input,
                evaluated_at,
            )?;
            (
                row.authorization_rule.clone(),
                row.requested_action.clone(),
                Vec::new(),
                Some(assessment.authorization),
                assessment.denied_reason,
            )
        }
    };

    let requested_resource_bindings =
        authorization_resource_bindings(&authorization_rule, &operation, normalized_input)?;
    let requested_resources_digest =
        proof_remote::registry::requested_authorization_resources_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            &authorization_rule,
            &operation,
            &requested_action,
            &requested_resource_bindings,
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
            Some(authorization_public_code(&reason).to_owned()),
            reason,
        ),
        None => (
            AuthorizationDecisionKind::Allow,
            None,
            "proof.authorization.allowed".to_owned(),
        ),
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
        evaluated_at,
        evaluated_authority_head: head,
        authority_sequence: head.sequence.saturating_add(1),
        previous_authority_record_digest: head.record_digest,
        authority_key_id,
    };
    built.bind_registry_hashes();
    Ok(built)
}

/// Re-evaluates the complete Agent CAP closure against the transaction's
/// locked snapshot. No stored-result lookup or governed mutation may run until
/// this exact comparison succeeds.
pub(crate) fn revalidate_agent_authorization_in_transaction(
    transaction: &mut postgres::Transaction<'_>,
    actor_context: &AuthenticatedActorContextV2,
    normalized_input: &Value,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), proof_pg::PgError> {
    let AuthenticatedActorContextV2::HumanAgent(context) = actor_context else {
        return Ok(());
    };
    let consumed: bool = transaction
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM facts WHERE fact_id = $1)",
            &[&format!(
                "presentation_consumption/{}",
                context.presentation_id
            )],
        )
        .map_err(|error| proof_pg::transaction::transaction_error(&error))?
        .get(0);
    if consumed {
        return Err(proof_pg::PgError::Idempotency(
            "proof.auth.replay".to_owned(),
        ));
    }
    let current = build_agent_authorization(
        transaction,
        context,
        normalized_input,
        decision.evaluated_at,
    )
    .map_err(server_error_to_pg)?;
    let expected_decision = if current.denied_reason.is_some() {
        AuthorizationDecisionKind::Deny
    } else {
        AuthorizationDecisionKind::Allow
    };
    let expected_reason = current
        .denied_reason
        .as_deref()
        .unwrap_or("proof.authorization.allowed");
    let expected_public = current
        .denied_reason
        .as_deref()
        .map(authorization_public_code);
    if decision.agent_authorization.as_ref() != Some(&current.authorization)
        || decision.decision != expected_decision
        || decision.reason_code != expected_reason
        || decision.public_code.as_deref() != expected_public
    {
        return Err(proof_pg::PgError::Integrity(
            "Agent authorization changed before the locked evaluation".to_owned(),
        ));
    }
    Ok(())
}

/// Claims a fresh Agent presentation and persists every prepared attempt body
/// and catalog row in the caller's authoritative transaction.
pub(crate) fn persist_agent_attempt_in_transaction(
    transaction: &mut postgres::Transaction<'_>,
    attempt: &PreparedAgentAttempt,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), proof_pg::PgError> {
    if &attempt.actor_context != actor_context {
        return Err(proof_pg::PgError::Integrity(
            "prepared Agent attempt does not match its actor context".to_owned(),
        ));
    }
    let AuthenticatedActorContextV2::HumanAgent(context) = actor_context else {
        return Err(proof_pg::PgError::Integrity(
            "prepared Agent attempt was supplied for a Human request".to_owned(),
        ));
    };
    for artifact in &attempt.artifacts {
        let inserted = transaction
            .execute(
                "INSERT INTO artifact_body_pg (kind, digest, body, committed_at)
                 VALUES ($1, $2, $3, clock_timestamp())
                 ON CONFLICT (kind, digest) DO NOTHING",
                &[&artifact.kind, &artifact.digest.to_string(), &artifact.body],
            )
            .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
        if inserted == 0 {
            let existing: Vec<u8> = transaction
                .query_one(
                    "SELECT body FROM artifact_body_pg WHERE kind = $1 AND digest = $2",
                    &[&artifact.kind, &artifact.digest.to_string()],
                )
                .map_err(|error| proof_pg::transaction::transaction_error(&error))?
                .get(0);
            if existing != artifact.body {
                return Err(proof_pg::PgError::Integrity(
                    "authenticated attempt artifact digest collision".to_owned(),
                ));
            }
        }
        let length = i64::try_from(artifact.body.len()).map_err(|_| {
            proof_pg::PgError::Artifact("attempt artifact length exceeds BIGINT".to_owned())
        })?;
        transaction
            .execute(
                "INSERT INTO artifact_catalog (
                     kind, digest, media_type, schema_version, length, stored_inline, committed_at
                 ) VALUES ($1, $2, $3, 1, $4, TRUE, clock_timestamp())
                 ON CONFLICT (kind, digest) DO NOTHING",
                &[
                    &artifact.kind,
                    &artifact.digest.to_string(),
                    &"application/json",
                    &length,
                ],
            )
            .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
    }

    let consumption = serde_json::json!({
        "api_version": "proof.dev/presentation-consumption/v1",
        "consumed_at": decision.evaluated_at.to_string(),
        "decision_id": decision.decision_id,
        "presentation_id": context.presentation_id,
        "workspace_id": decision.workspace_id,
    });
    let canonical = canonicalize(&consumption)
        .map_err(|error| proof_pg::PgError::Integrity(error.to_string()))?;
    let consumption_digest =
        proof_remote::derive_key_digest("proof:presentation-consumption:v1", canonical.as_bytes());
    let authority_sequence = i64::try_from(decision.authority_sequence)
        .map_err(|_| proof_pg::PgError::Integrity("authority sequence out of range".to_owned()))?;
    transaction
        .execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, 'presentation_consumption', $3, $4, $5, clock_timestamp())",
            &[
                &format!("presentation_consumption/{}", context.presentation_id),
                &decision.workspace_id,
                &authority_sequence,
                &consumption_digest.to_string(),
                &canonical.as_bytes(),
            ],
        )
        .map_err(|error| {
            if error.code() == Some(&postgres::error::SqlState::UNIQUE_VIOLATION) {
                proof_pg::PgError::Idempotency("proof.auth.replay".to_owned())
            } else {
                proof_pg::transaction::transaction_error(&error)
            }
        })?;
    Ok(())
}

fn server_error_to_pg(error: ServerError) -> proof_pg::PgError {
    match error {
        ServerError::Storage(error) => error,
        ServerError::Dispatch(detail) | ServerError::Authorization(detail) => {
            proof_pg::PgError::Integrity(detail)
        }
        error => proof_pg::PgError::Integrity(error.to_string()),
    }
}

fn authorization_resource_bindings(
    authorization_rule: &str,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
) -> Result<Vec<RequestedAuthorizationResourceBindingV1>, ServerError> {
    if authorization_rule != "proof.server/authorization/schema-reader/v1" {
        return Ok(Vec::new());
    }
    let names: &[&str] = match operation.name.as_str() {
        "object.list" => &["object_ids", "schema_id"],
        "schema.get" => &["schema_id", "schema_version"],
        "schema.list" => &["schema_id"],
        _ => &[],
    };
    names
        .iter()
        .map(|name| {
            let value = normalized_input.get(name).unwrap_or(&Value::Null);
            let value_digest = proof_remote::authorization_resource_binding_digest(name, value)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            Ok(RequestedAuthorizationResourceBindingV1 {
                name: (*name).to_owned(),
                value_digest,
            })
        })
        .collect()
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
    let runtime = guard.as_mut().ok_or_else(|| {
        ServerError::Storage(proof_pg::PgError::Connect(
            "PostgreSQL runtime is not connected".to_owned(),
        ))
    })?;
    runtime.ensure_connected().map_err(ServerError::Storage)?;
    Ok(runtime)
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

fn oidc_binding_is_revoked(
    runtime: &mut proof_pg::wiring::PgRuntime,
    binding_id: &str,
) -> Result<bool, ServerError> {
    for body in read_facts_by_kind(runtime, "oidc_binding_revocation")? {
        if let Ok(revocation) = serde_json::from_slice::<OidcPrincipalBindingRevocationV1>(&body)
            && revocation.binding_id == binding_id
        {
            return Ok(true);
        }
    }
    Ok(false)
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

struct AgentAuthorizationAssessment {
    authorization: proof_remote::registry::AgentAuthorizationV1,
    denied_reason: Option<String>,
}

struct AgentResourceAssessment {
    requested: RequestedResourcesV1,
    effective_constraints: EffectiveConstraintsV1,
    closure_resolved: bool,
    context_expires_at: Option<Timestamp>,
}

struct StoredFact {
    value: Value,
    digest: ContentDigest,
}

fn build_agent_authorization(
    client: &mut impl postgres::GenericClient,
    context: &AuthenticatedActorContextHumanAgentV2,
    normalized_input: &Value,
    evaluated_at: Timestamp,
) -> Result<AgentAuthorizationAssessment, ServerError> {
    let row = AgentOperationProjectionV1
        .lookup(&context.operation.name, &context.operation.version)
        .ok_or_else(|| {
            ServerError::Dispatch(format!(
                "unregistered Agent operation `{}` at `{}`",
                context.operation.name, context.operation.version
            ))
        })?;
    let authority_operation =
        AuthorityOperation::from_pair(&context.operation.name, &context.operation.version)
            .ok_or_else(|| {
                ServerError::Dispatch("Agent operation is not authority-enabled".to_owned())
            })?;
    let normalized_map = normalized_input.as_object().cloned().ok_or_else(|| {
        ServerError::Dispatch("normalized Agent input is not an object".to_owned())
    })?;
    let command_input = CommandInputV1 {
        api_version: CommandInputApiVersion::V1,
        workspace_id: parse_workspace_id(&context.workspace_id)?,
        operation: authority_operation,
        requesting_principal_id: parse_principal_id(&context.requesting_principal_id)?,
        operating_principal_id: parse_principal_id(&context.operating_principal_id)?,
        delegation_id: context
            .delegation_id
            .parse()
            .map_err(|_| ServerError::Authorization("invalid Delegation identity".to_owned()))?,
        idempotency_key: normalized_input
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Dispatch("invalid application key".to_owned()))?,
        normalized_input: normalized_map,
    };
    command_input.normalized_operation_input().map_err(|_| {
        ServerError::Dispatch("Agent input violates its operation contract".to_owned())
    })?;

    let requesting_enabled = principal_enabled_at_head(client, &context.requesting_principal_id)?;
    let operating_enabled = principal_enabled_at_head(client, &context.operating_principal_id)?;

    let binding_fact = read_stored_fact(
        client,
        &format!("agent_binding/{}", context.operating_binding.binding_id),
    )?;
    let binding = binding_fact
        .as_ref()
        .and_then(|fact| serde_json::from_value::<PrincipalBindingV1>(fact.value.clone()).ok());
    let binding_revocation =
        binding_revocation_digest(client, &context.operating_binding.binding_id)?;
    let binding_record_digest = binding_fact
        .as_ref()
        .map_or(context.operating_binding.record_digest, |fact| fact.digest);
    let binding_active = binding.as_ref().is_some_and(|binding| {
        binding.workspace_id.to_string() == context.workspace_id
            && binding.binding_id.to_string() == context.operating_binding.binding_id
            && binding.principal_id.to_string() == context.operating_principal_id
            && binding_record_digest == context.operating_binding.record_digest
            && binding_revocation.is_none()
            && binding.is_time_active(evaluated_at)
    });

    let delegation_fact =
        read_stored_fact(client, &format!("delegation/{}", context.delegation_id))?;
    let delegation = delegation_fact
        .as_ref()
        .and_then(|fact| serde_json::from_value::<DelegationV2>(fact.value.clone()).ok())
        .filter(|delegation| delegation.validate().is_ok());
    let delegation_revocation = delegation_revocation_digest(client, &context.delegation_id)?;
    let resources = project_agent_resources(
        client,
        &context.workspace_id,
        &context.requesting_principal_id,
        authority_operation,
        normalized_input,
    )?;

    let mut denied_reason = if !requesting_enabled || !operating_enabled {
        Some("proof.authorization.principal_disabled".to_owned())
    } else if !binding_active {
        Some("proof.auth.binding_inactive".to_owned())
    } else if delegation.is_none() {
        Some("proof.authorization.delegation_unavailable".to_owned())
    } else {
        None
    };
    if denied_reason.is_none() {
        let delegation = delegation
            .as_ref()
            .expect("the preceding branch proves the Delegation is present");
        denied_reason = if delegation.workspace_id.to_string() != context.workspace_id
            || delegation.issuer_principal_id.to_string() != context.requesting_principal_id
            || delegation.recipient_principal_id.to_string() != context.operating_principal_id
        {
            Some("proof.authorization.scope_exceeded".to_owned())
        } else if delegation_revocation.is_some() {
            Some("proof.authorization.delegation_revoked".to_owned())
        } else if evaluated_at < delegation.not_before {
            Some("proof.authorization.delegation_not_yet_valid".to_owned())
        } else if evaluated_at >= delegation.expires_at {
            Some("proof.authorization.delegation_expired".to_owned())
        } else if !delegation
            .actions
            .as_slice()
            .iter()
            .any(|action| action.to_string() == row.requested_action)
            || !resources.closure_resolved
            || !delegation_covers_resources(delegation, &resources.requested)
        {
            Some("proof.authorization.scope_exceeded".to_owned())
        } else if resources.effective_constraints.max_objects
            > delegation.constraints.max_objects.get()
            || resources.effective_constraints.max_context_bytes
                > delegation.constraints.max_context_bytes.get()
            || resources.effective_constraints.max_edits_per_changeset
                > delegation.constraints.max_edits_per_changeset.get()
            || resources
                .context_expires_at
                .is_some_and(|expires_at| expires_at > delegation.expires_at)
        {
            Some("proof.authorization.budget_exceeded".to_owned())
        } else {
            None
        };
    }

    let policy_bundle_digest =
        proof_remote::registry::remote_authorization_policy_selection_digest(
            proof_remote::registry::REMOTE_AUTHORIZATION_PROJECTION_SHA256,
            AGENT_DIRECT_AUTHORIZATION_RULE,
            None,
            None,
        )
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let delegation_evaluation = match (&delegation_fact, &delegation) {
        (Some(fact), Some(_)) => DelegationEvaluationV1 {
            delegation_id: context.delegation_id.clone(),
            record_digest: Some(fact.digest),
            revocation_record_digest: delegation_revocation,
            resolution: DelegationResolutionV1::Resolved,
        },
        _ => DelegationEvaluationV1 {
            delegation_id: context.delegation_id.clone(),
            record_digest: None,
            revocation_record_digest: None,
            resolution: DelegationResolutionV1::NotFoundOrHidden,
        },
    };
    Ok(AgentAuthorizationAssessment {
        authorization: proof_remote::registry::AgentAuthorizationV1 {
            command_digest: context.command_digest,
            command_envelope_digest: context.command_envelope_digest,
            presentation_id: context.presentation_id.clone(),
            presentation_consumed: true,
            operating_principal_id: context.operating_principal_id.clone(),
            principal_state: PrincipalStateV1 {
                requesting_principal_enabled: requesting_enabled,
                operating_principal_enabled: operating_enabled,
            },
            binding: OperatingBindingEvaluationV1 {
                active: binding_active,
                binding_id: context.operating_binding.binding_id.clone(),
                authority_sequence: binding
                    .as_ref()
                    .map_or(context.operating_binding.authority_sequence, |value| {
                        value.authority_sequence.get()
                    }),
                record_digest: binding_record_digest,
                revocation_record_digest: binding_revocation,
            },
            delegation: delegation_evaluation,
            policy_profile: AGENT_DIRECT_AUTHORIZATION_RULE.to_owned(),
            policy_bundle_digest,
            requested_resources: resources.requested,
            effective_constraints: resources.effective_constraints,
        },
        denied_reason,
    })
}

fn authorization_public_code(reason: &str) -> &'static str {
    match reason {
        "proof.auth.binding_inactive"
        | "proof.authorization.delegation_unavailable"
        | "proof.authorization.principal_disabled" => "proof.auth.denied",
        "proof.authorization.budget_exceeded" => "proof.authorization.budget_exceeded",
        "proof.authorization.delegation_expired" => "proof.authorization.delegation_expired",
        "proof.authorization.delegation_not_yet_valid" => {
            "proof.authorization.delegation_not_yet_valid"
        }
        "proof.authorization.delegation_revoked" => "proof.authorization.delegation_revoked",
        "proof.authorization.scope_exceeded" => "proof.authorization.scope_exceeded",
        _ => "proof.authorization.denied",
    }
}

fn read_stored_fact(
    client: &mut impl postgres::GenericClient,
    fact_id: &str,
) -> Result<Option<StoredFact>, ServerError> {
    let row = client
        .query_opt(
            "SELECT fact_digest, body FROM facts WHERE fact_id = $1",
            &[&fact_id],
        )
        .map_err(|error| storage_error(format!("read fact {fact_id}: {error}")))?;
    row.map(|row| {
        let digest = row
            .get::<_, String>(0)
            .parse()
            .map_err(|error| storage_error(format!("invalid fact digest: {error}")))?;
        let body: Vec<u8> = row.get(1);
        let value = serde_json::from_slice(&body)
            .map_err(|error| storage_error(format!("invalid fact body: {error}")))?;
        Ok(StoredFact { value, digest })
    })
    .transpose()
}

fn principal_enabled_at_head(
    client: &mut impl postgres::GenericClient,
    principal_id: &str,
) -> Result<bool, ServerError> {
    let rows = client
        .query(
            "SELECT body FROM facts WHERE fact_kind = 'principal_status'
             ORDER BY authority_sequence DESC",
            &[],
        )
        .map_err(|error| storage_error(format!("read Principal status: {error}")))?;
    Ok(rows
        .into_iter()
        .find_map(|row| {
            serde_json::from_slice::<RemotePrincipalStatusV2>(&row.get::<_, Vec<u8>>(0))
                .ok()
                .filter(|status| status.principal_id == principal_id)
                .map(|status| status.enabled)
        })
        .unwrap_or(false))
}

fn binding_revocation_digest(
    client: &mut impl postgres::GenericClient,
    binding_id: &str,
) -> Result<Option<ContentDigest>, ServerError> {
    let rows = client
        .query(
            "SELECT fact_digest, body FROM facts
             WHERE fact_kind = 'agent_binding_revocation'
             ORDER BY authority_sequence DESC",
            &[],
        )
        .map_err(|error| storage_error(format!("read Agent binding revocations: {error}")))?;
    rows.into_iter()
        .find_map(|row| {
            let body: Vec<u8> = row.get(1);
            serde_json::from_slice::<PrincipalBindingRevocationV1>(&body)
                .ok()
                .filter(|revocation| revocation.binding_id.to_string() == binding_id)
                .map(|_| row.get::<_, String>(0))
        })
        .map(|digest| {
            digest.parse().map_err(|error| {
                storage_error(format!("invalid binding revocation digest: {error}"))
            })
        })
        .transpose()
}

fn delegation_revocation_digest(
    client: &mut impl postgres::GenericClient,
    delegation_id: &str,
) -> Result<Option<ContentDigest>, ServerError> {
    let rows = client
        .query(
            "SELECT fact_digest, body FROM facts
             WHERE fact_kind = 'delegation_revocation'
             ORDER BY authority_sequence DESC",
            &[],
        )
        .map_err(|error| storage_error(format!("read Delegation revocations: {error}")))?;
    rows.into_iter()
        .find_map(|row| {
            let body: Vec<u8> = row.get(1);
            serde_json::from_slice::<DelegationRevocationV1>(&body)
                .ok()
                .filter(|revocation| revocation.delegation_id.to_string() == delegation_id)
                .map(|_| row.get::<_, String>(0))
        })
        .map(|digest| {
            digest.parse().map_err(|error| {
                storage_error(format!("invalid Delegation revocation digest: {error}"))
            })
        })
        .transpose()
}

fn project_agent_resources(
    client: &mut impl postgres::GenericClient,
    workspace_id: &str,
    requesting_principal_id: &str,
    operation: AuthorityOperation,
    input: &Value,
) -> Result<AgentResourceAssessment, ServerError> {
    let mut requested = RequestedResourcesV1 {
        workspace_ids: vec![workspace_id.to_owned()],
        environment_ids: Vec::new(),
        object_ids: Vec::new(),
        schema_ids: Vec::new(),
        locales: Vec::new(),
        changeset_ids: Vec::new(),
        edition_ids: Vec::new(),
        release_ids: Vec::new(),
    };
    let mut constraints = EffectiveConstraintsV1 {
        max_objects: 1,
        max_context_bytes: 1,
        max_edits_per_changeset: 1,
    };
    let mut closure_resolved = true;
    let mut context_expires_at = None;

    match operation {
        AuthorityOperation::WorkspaceStatusV1 => {}
        AuthorityOperation::ContextBuildV1 => {
            requested.environment_ids = input_string(input, "environment_id").into_iter().collect();
            requested.object_ids = input_string_array(input, "object_ids");
            constraints.max_objects = input_u32(input, "max_objects").unwrap_or(1);
            constraints.max_context_bytes = input_u32(input, "max_bytes").unwrap_or(1);
            context_expires_at = input_timestamp(input, "expires_at");
        }
        AuthorityOperation::ObjectQueryReleasedV1 => {
            requested.environment_ids = input_string(input, "environment_id").into_iter().collect();
            requested.object_ids = input_string_array(input, "object_ids");
            constraints.max_objects = u32::try_from(requested.object_ids.len())
                .unwrap_or(u32::MAX)
                .max(1);
        }
        AuthorityOperation::ObjectQueryReleasedV2 => {
            requested.environment_ids = input_string(input, "environment_id").into_iter().collect();
            if let Some(targets) = input.get("targets").and_then(Value::as_array) {
                for target in targets {
                    if let Some(object_id) = input_string(target, "object_id") {
                        requested.object_ids.push(object_id.clone());
                        if let Some(source) =
                            read_stored_fact(client, &format!("source_object/{object_id}"))?
                            && let Some(schema_id) = input_string(&source.value, "schema_id")
                        {
                            requested.schema_ids.push(schema_id);
                        }
                    }
                    if let Some(locale) = input_string(target, "locale") {
                        requested.locales.push(locale);
                    }
                }
            }
            constraints.max_objects =
                u32::try_from(requested.object_ids.iter().collect::<BTreeSet<_>>().len())
                    .unwrap_or(u32::MAX)
                    .max(1);
        }
        _ => {
            let closure =
                resolve_localized_intent_fact(client, operation, input, requesting_principal_id)?;
            closure_resolved = closure.is_some();
            if let Some(closure) = closure {
                requested.environment_ids = input_string(&closure.intent.value, "environment_id")
                    .into_iter()
                    .collect();
                if let Some(targets) = closure
                    .intent
                    .value
                    .get("targets")
                    .and_then(Value::as_array)
                {
                    for target in targets {
                        if let Some(value) = input_string(target, "object_id") {
                            requested.object_ids.push(value);
                        }
                        if let Some(value) = input_string(target, "schema_id") {
                            requested.schema_ids.push(value);
                        }
                        if let Some(value) = input_string(target, "locale") {
                            requested.locales.push(value);
                        }
                    }
                }
                requested.changeset_ids.extend(closure.changeset_id);
                requested.edition_ids.extend(closure.edition_id);
                requested.release_ids.extend(closure.release_ids);
                if let Some(limits) = closure.limits.as_ref() {
                    constraints.max_objects = input_u32(limits, "max_objects").unwrap_or(1);
                    constraints.max_context_bytes = limits
                        .get("max_bytes")
                        .and_then(Value::as_u64)
                        .and_then(|value| u32::try_from(value).ok())
                        .unwrap_or(1);
                    constraints.max_edits_per_changeset =
                        input_u32(limits, "max_edits").unwrap_or(1);
                }
                context_expires_at = closure.context_expires_at;
            }
        }
    }

    sort_dedup(&mut requested.environment_ids);
    sort_dedup(&mut requested.object_ids);
    sort_dedup(&mut requested.schema_ids);
    sort_dedup(&mut requested.locales);
    sort_dedup(&mut requested.changeset_ids);
    sort_dedup(&mut requested.edition_ids);
    sort_dedup(&mut requested.release_ids);
    Ok(AgentResourceAssessment {
        requested,
        effective_constraints: constraints,
        closure_resolved,
        context_expires_at,
    })
}

struct LocalizedIntentClosure {
    intent: StoredFact,
    changeset_id: Option<String>,
    edition_id: Option<String>,
    release_ids: Vec<String>,
    limits: Option<Value>,
    context_expires_at: Option<Timestamp>,
}

fn resolve_localized_intent_fact(
    client: &mut impl postgres::GenericClient,
    operation: AuthorityOperation,
    input: &Value,
    requesting_principal_id: &str,
) -> Result<Option<LocalizedIntentClosure>, ServerError> {
    let mut changeset_id = input_string(input, "changeset_id");
    let mut edition_id = input_string(input, "edition_id");
    if matches!(operation, AuthorityOperation::ReleaseCreateV2) {
        let Some(id) = edition_id.as_deref() else {
            return Ok(None);
        };
        let Some(edition) = read_stored_fact(client, &format!("localized_edition/{id}"))? else {
            return Ok(None);
        };
        changeset_id = input_string(&edition.value, "changeset_id");
    }
    let changeset = if let Some(id) = changeset_id.as_deref() {
        read_stored_fact(client, &format!("localized_changeset/{id}"))?
    } else {
        None
    };
    if changeset.as_ref().is_some_and(|fact| {
        input_string(&fact.value, "principal_id").as_deref() != Some(requesting_principal_id)
    }) {
        return Ok(None);
    }

    let intent_id = input_string(input, "resource_intent_id").or_else(|| {
        changeset
            .as_ref()
            .and_then(|fact| input_string(&fact.value, "resource_intent_id"))
    });
    let Some(intent_id) = intent_id else {
        return Ok(None);
    };
    let Some(intent) = read_stored_fact(client, &format!("resource_intent/{intent_id}"))? else {
        return Ok(None);
    };
    if input_string(&intent.value, "issued_by_principal_id").as_deref()
        != Some(requesting_principal_id)
    {
        return Ok(None);
    }
    let expected_digest = input_string(input, "resource_intent_digest").or_else(|| {
        changeset
            .as_ref()
            .and_then(|fact| input_string(&fact.value, "resource_intent_digest"))
    });
    if expected_digest
        .as_deref()
        .is_some_and(|expected| expected != intent.digest.to_string())
    {
        return Ok(None);
    }

    let context_id = input_string(input, "context_pack_id").or_else(|| {
        changeset
            .as_ref()
            .and_then(|fact| input_string(&fact.value, "context_pack_id"))
    });
    let context = context_id
        .as_deref()
        .map(|id| read_stored_fact(client, &format!("context_pack/{id}")))
        .transpose()?
        .flatten();
    let limits = if matches!(operation, AuthorityOperation::ContextBuildV2) {
        input.get("limits").cloned()
    } else {
        context
            .as_ref()
            .and_then(|fact| fact.value.get("limits").cloned())
    };
    let context_expires_at = if matches!(operation, AuthorityOperation::ContextBuildV2) {
        input_timestamp(input, "expires_at")
    } else {
        context
            .as_ref()
            .and_then(|fact| input_timestamp(&fact.value, "expires_at"))
    };
    if !matches!(operation, AuthorityOperation::ContextBuildV2) && context.is_none() {
        return Ok(None);
    }
    if matches!(operation, AuthorityOperation::EditionCreateV2) {
        edition_id = input_string(input, "edition_id");
    }
    let release_ids = if matches!(operation, AuthorityOperation::ReleaseCreateV2) {
        [
            input_string(input, "expected_base_release_id"),
            input_string(input, "release_id"),
        ]
        .into_iter()
        .flatten()
        .collect()
    } else {
        Vec::new()
    };
    Ok(Some(LocalizedIntentClosure {
        intent,
        changeset_id,
        edition_id,
        release_ids,
        limits,
        context_expires_at,
    }))
}

fn delegation_covers_resources(
    delegation: &DelegationV2,
    requested: &RequestedResourcesV1,
) -> bool {
    requested.workspace_ids == [delegation.workspace_id.to_string()]
        && requested.environment_ids.iter().all(|requested| {
            delegation
                .scope
                .environment_ids
                .as_slice()
                .iter()
                .any(|granted| granted.to_string() == *requested)
        })
        && requested.object_ids.iter().all(|requested| {
            delegation
                .scope
                .object_ids
                .as_slice()
                .iter()
                .any(|granted| granted.to_string() == *requested)
        })
        && requested.schema_ids.iter().all(|requested| {
            delegation
                .scope
                .schema_ids
                .as_slice()
                .iter()
                .any(|granted| granted.to_string() == *requested)
        })
        && requested.locales.iter().all(|requested| {
            delegation
                .scope
                .locales
                .as_slice()
                .iter()
                .any(|granted| granted.to_string() == *requested)
        })
}

fn input_string(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn input_string_array(value: &Value, field: &str) -> Vec<String> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn input_u32(value: &Value, field: &str) -> Option<u32> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn input_timestamp(value: &Value, field: &str) -> Option<Timestamp> {
    value.get(field).and_then(Value::as_str)?.parse().ok()
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
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
        "object.list" => "object:list",
        "oidc-binding.issue" => "oidc_binding:issue",
        "oidc-binding.revoke" => "oidc_binding:revoke",
        "principal.status.set" => "principal:disable",
        "release.get" => "release:get",
        "release.verify" => "release:verify",
        "schema.get" => "schema:get",
        "schema.list" => "schema:list",
        "workspace-role.assign" => "workspace_role:assign",
        "workspace-role.revoke" => "workspace_role:revoke",
        _ => return name.replace('.', ":"),
    };
    action.to_owned()
}
