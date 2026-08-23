//! Owned Human and Agent operation executors over the P-0010 unit of work
//! (contract §"PostgreSQL authoritative unit of work", §"HTTP boundary").

use proof_remote::{
    RemoteOperationV1,
    identity::AuthenticatedActorContextV2,
    registry::{RemoteApplicationConsequenceV1, RemoteAuthorizationDecisionV1},
};
use serde_json::Value;

use crate::{AppState, ServerError};

/// Stable pending Problem code returned for dependency successor scope
/// (evidence export capture/assembly, delivery, and preview materialization)
/// until S4/S5 (contract §"HTTP boundary").
pub const DEPENDENCY_UNAVAILABLE_CODE: &str = "proof.dependency.unavailable";

/// Human operation executor: maps one normalized input to an application
/// operation through the P-0010 [`StorageBackend`] unit of work, committing
/// the decision, governed fact, and consequence with the exact per-row effect
/// digest and timestamp field (contract §"Human and control operation
/// registry").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HumanOperationExecutor;

impl HumanOperationExecutor {
    /// Executes one owned Human operation (contract §"Human and control
    /// operation registry").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any authentication, authorization, storage,
    /// deadline, or consequence failure.
    pub fn execute(
        _state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<RemoteApplicationConsequenceV1, ServerError> {
        match operation.name.as_str() {
            "evidence.export"
            | "evidence.export.get"
            | "delivery.replay"
            | "delivery.abandon"
            | "delivery.get" => dependency_unavailable_consequence(
                operation,
                normalized_input,
                actor_context,
                decision,
            ),
            _ => todo!("run the owned Human operation through one unit of work"),
        }
    }
}

/// Agent operation executor: dispatches the accepted 14-row projection through
/// the shared application operations (contract §"Agent registry projection").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AgentOperationExecutor;

impl AgentOperationExecutor {
    /// Executes one owned Agent operation (contract §"Agent registry
    /// projection").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any failure.
    pub fn execute(
        _state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<RemoteApplicationConsequenceV1, ServerError> {
        todo!("dispatch the accepted Agent row through the shared application operation")
    }
}

/// Returns the stable `proof.dependency.unavailable` pending consequence for
/// dependency successor scope (contract §"HTTP boundary").
///
/// # Errors
///
/// Returns [`ServerError::Dispatch`] when the consequence cannot be built.
#[allow(clippy::unused_self)]
pub fn dependency_unavailable_consequence(
    _operation: &RemoteOperationV1,
    _normalized_input: &Value,
    _actor_context: &AuthenticatedActorContextV2,
    _decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    todo!("build the signed pending consequence with proof.dependency.unavailable")
}

/// The owned Human rows implemented over the P-0010 unit of work (contract
/// §"Human and control operation registry").
pub const OWNED_HUMAN_OPERATION_NAMES: [&str; 15] = [
    "oidc-binding.issue",
    "oidc-binding.revoke",
    "workspace-role.assign",
    "workspace-role.revoke",
    "principal.status.set",
    "content-resource-intent.issue",
    "context.build",
    "changeset.get",
    "changeset.diff",
    "changeset.approve",
    "delegation.issue",
    "delegation.revoke",
    "release.get",
    "release.verify",
    "capabilities.discover",
];

/// The owned pending-dependency Human rows (contract §"HTTP boundary").
pub const PENDING_DEPENDENCY_OPERATION_NAMES: [&str; 5] = [
    "evidence.export",
    "evidence.export.get",
    "delivery.get",
    "delivery.replay",
    "delivery.abandon",
];
