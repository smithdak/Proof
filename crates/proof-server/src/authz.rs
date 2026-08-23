//! Dual Human-session plus Agent-presentation authentication and the
//! per-row authorization rule evaluation (contract §"Remote identity
//! vocabulary", §"Human roles and separation of duties", §"HTTP boundary").

use proof_application::authority::AuthenticatedInvocationV1;
use proof_remote::{
    authority::WorkspaceRole,
    identity::{AuthenticatedActorContextV2, AuthenticationProfile},
    registry::{HumanOperationRegistryV1, RemoteAuthorizationDecisionV1},
};
use serde_json::Value;

use crate::{AppState, ServerError};

/// Direct Human OIDC authentication profile (contract §"Remote identity
/// vocabulary").
pub const OIDC_HUMAN_PROFILE: &str = "proof.server/authentication/oidc-human/v1";

/// Human-plus-Agent authentication profile (contract §"Remote identity
/// vocabulary").
pub const OIDC_HUMAN_AGENT_PROFILE: &str = "proof.server/authentication/oidc-human-agent/v1";

/// A live session-resolved requesting Human actor, before Agent presentation
/// proof (contract §"Remote identity vocabulary").
#[derive(Clone, Debug)]
pub struct RequestingHuman {
    /// Requesting Principal identity (UUIDv7).
    pub principal_id: String,
    /// Requesting binding identity (UUIDv7).
    pub binding_id: String,
    /// Requesting binding record digest.
    pub binding_record_digest: proof_domain::ContentDigest,
    /// Authentication event identity (UUIDv7).
    pub authentication_event_id: String,
}

/// Authenticates a live requesting-Human session to
/// `proof.server/authentication/oidc-human/v1` (contract §"Remote identity
/// vocabulary").
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] when the session, binding, or
/// Principal is not currently authentication-valid.
pub fn authenticate_human_session(
    _state: &AppState,
    _session: &crate::session::SessionRecord,
) -> Result<AuthenticatedActorContextV2, ServerError> {
    todo!("derive the oidc-human/v1 protected actor context")
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
    _state: &AppState,
    _session: &crate::session::SessionRecord,
    _invocation: &AuthenticatedInvocationV1,
) -> Result<AuthenticatedActorContextV2, ServerError> {
    todo!("verify command signature, single-use presentation, and compose the context")
}

/// Returns the closed authentication profile of one actor context.
#[must_use]
pub fn actor_profile(context: &AuthenticatedActorContextV2) -> AuthenticationProfile {
    context.profile()
}

/// Evaluates the per-row authorization rule plus `roles_any_of` at the exact
/// locked authority head, producing the signed
/// [`RemoteAuthorizationDecisionV1`] (contract §"Human roles and separation of
/// duties", §"HTTP boundary").
///
/// # Errors
///
/// Returns [`ServerError::Authorization`] on a denial; the caller commits the
/// signed denial decision.
pub fn evaluate_authorization(
    _state: &AppState,
    _actor_context: &AuthenticatedActorContextV2,
    _normalized_input: &Value,
) -> Result<RemoteAuthorizationDecisionV1, ServerError> {
    todo!("resolve row, roles, and authority head; build the decision")
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
pub fn required_roles_for(operation: &proof_remote::RemoteOperationV1) -> Vec<WorkspaceRole> {
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
