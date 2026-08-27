//! Owned Human and Agent operation executors over the P-0010 unit of work
//! (contract §"PostgreSQL authoritative unit of work", §"HTTP boundary").

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use proof_application::authority::{
    AgentPrincipalType, AuthenticatedCommandKeyUsage, AuthorityAction, AuthorityAudience,
    AuthorityOperation, AuthoritySequence, BindingEnrollmentChallengeV1, DelegationActionsV2,
    DelegationApiVersion, DelegationConstraintsV2, DelegationEnvironmentIdsV2, DelegationLocalesV2,
    DelegationObjectIdsV2, DelegationRevocationApiVersion, DelegationRevocationReasonV1,
    DelegationRevocationV1, DelegationSchemaIdsV2, DelegationScopeV2, DelegationV2,
    DirectAuthorityProfileV1, Ed25519Algorithm, Ed25519KeyId, Ed25519PublicKey,
    LocalEd25519AuthenticatedSubjectV1, PrincipalBindingApiVersion,
    PrincipalBindingRevocationApiVersion, PrincipalBindingRevocationReason,
    PrincipalBindingRevocationV1, PrincipalBindingV1, SubdelegationDisabled,
};
use proof_attestation::authority::{AuthorityPayloadProfile, verify_authority_envelope};
use proof_canonical::{canonicalize, digest};
use proof_domain::{ArtifactKind, ContentDigest, Timestamp};
use proof_pg::{
    PgError,
    artifacts::ArtifactKeyV1,
    idempotency::{
        IdempotencyOutcome, IdempotencyTupleV1, SavepointGuard, read_stored_in_transaction,
        record_replay_in_transaction, replay_or_conflict,
    },
    outbox::{OutboxEnqueueV1, enqueue_initial_delivery},
    transaction::{
        CausalSequencePolicy, RetryPolicy, UnitOfWorkHooks, UnitOfWorkOutcome,
        run_unit_of_work_with_retry_and_sequence_policy,
        run_unit_of_work_with_retry_and_sequence_policy_commit,
    },
};
use proof_remote::{
    AuthorityHeadV1, DeliveryManagementAction, DeliveryManagementFactV1, OracleConsequence,
    OracleOutcome, RemoteOperationV1,
    authority::{
        RemoteAuthorityRecordV1, RemotePrincipalStatusApiVersion, RemotePrincipalStatusV2,
        RemotePrincipalType, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
        WorkspaceRoleAssignmentV1, WorkspaceRoleRevocationApiVersion, WorkspaceRoleRevocationV1,
    },
    identity::{
        AuthenticatedActorContextV2, OidcAuthenticatedSubjectV1, OidcPrincipalBindingApiVersion,
        OidcPrincipalBindingPrivateApiVersion, OidcPrincipalBindingPrivateV1,
        OidcPrincipalBindingRevocationApiVersion, OidcPrincipalBindingRevocationV1,
        OidcPrincipalBindingV1, OidcSubjectCommitmentInputApiVersion, OidcSubjectCommitmentInputV1,
        OidcSubjectCommitmentOpeningApiVersion, OidcSubjectCommitmentOpeningV1, encode_blind,
        subject_commitment_digest,
    },
    registry::{
        AgentOperationProjectionV1, ApplicationConsequenceOutcome, ApplicationKeyKind,
        AuthorizationDecisionKind, EffectDigestRule, HumanOperationRegistryV1,
        RemoteApplicationConsequenceApiVersion, RemoteApplicationConsequenceV1,
        RemoteAuthorizationDecisionV1, application_problem_digest_preimage,
        operation_effect_digest,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{AppState, ServerError};

/// Stable pending Problem code returned for dependency successor scope
/// (evidence export capture/assembly and not-yet-ready preview materialization)
/// (contract §"HTTP boundary").
pub const DEPENDENCY_UNAVAILABLE_CODE: &str = "proof.dependency.unavailable";

/// Human operation executor: maps one normalized input to an application
/// operation through the P-0010 [`proof_pg::transaction::run_unit_of_work`]
/// unit of work, committing the decision, governed fact, and consequence with
/// the exact per-row effect digest and timestamp field (contract §"Human and
/// control operation registry").
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HumanOperationExecutor;

/// One committed Human execution plus the exact application result exposed by
/// the HTTP success envelope.
#[derive(Debug)]
pub struct HumanOperationExecution {
    /// Signed application consequence retained as authority evidence.
    pub consequence: RemoteApplicationConsequenceV1,
    /// Exact typed application result.
    pub result: Value,
    /// Exact Workspace transaction sequence committed for this attempt.
    pub transaction_sequence: u64,
}

impl HumanOperationExecutor {
    /// Executes one owned Human operation (contract §"Human and control
    /// operation registry").
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any authentication, authorization, storage,
    /// deadline, or consequence failure.
    pub fn execute(
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<RemoteApplicationConsequenceV1, ServerError> {
        Self::execute_for_dispatch(state, operation, normalized_input, actor_context, decision)
            .map(|execution| execution.consequence)
    }

    /// Executes one Human operation while retaining its exact typed result for
    /// the HTTP success envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any authentication, authorization, storage,
    /// deadline, application, or consequence failure.
    pub fn execute_for_dispatch(
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<HumanOperationExecution, ServerError> {
        match operation.name.as_str() {
            "content-resource-intent.issue"
            | "context.build"
            | "changeset.get"
            | "changeset.diff"
            | "changeset.approve" => execute_native_agent(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                None,
                None,
            ),
            "schema.get" | "schema.list" | "object.list" => {
                execute_content_read(state, operation, normalized_input, actor_context, decision)
            }
            "evidence.export" => crate::export::evidence_export_v2_for_dispatch(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
            ),
            "evidence.export.get" => crate::export::evidence_export_get_v1_for_dispatch(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
            ),
            "delivery.get" => {
                execute_delivery_get(state, operation, normalized_input, actor_context, decision)
            }
            "delivery.replay" => execute_delivery_management(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                DeliveryManagementAction::Replay,
            ),
            "delivery.abandon" => execute_delivery_management(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                DeliveryManagementAction::Abandon,
            ),
            "workspace-role.assign" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::RoleAssignment,
                None,
                None,
            ),
            "workspace-role.revoke" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::RoleRevocation,
                None,
                None,
            ),
            "agent-binding.revoke" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::AgentBindingRevocation,
                None,
                None,
            ),
            "oidc-binding.revoke" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::OidcBindingRevocation,
                None,
                None,
            ),
            "principal.status.set" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::PrincipalStatus,
                None,
                None,
            ),
            "delegation.issue" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::DelegationIssue,
                None,
                None,
            ),
            "delegation.revoke" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::DelegationRevocation,
                None,
                None,
            ),
            "agent-binding.issue" | "oidc-binding.issue" => execute_enrollment_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
            ),
            _ => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::Generic,
                None,
                None,
            ),
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
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<RemoteApplicationConsequenceV1, ServerError> {
        Self::execute_for_dispatch(state, operation, normalized_input, actor_context, decision)
            .map(|execution| execution.consequence)
    }

    /// Executes one Agent operation while retaining its native typed result for
    /// the HTTP success envelope.
    pub fn execute_for_dispatch(
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
    ) -> Result<HumanOperationExecution, ServerError> {
        Self::execute_for_dispatch_with_attempt(
            state,
            operation,
            normalized_input,
            actor_context,
            decision,
            None,
        )
    }

    /// Executes one Agent operation with the verified attempt material that
    /// must be persisted by the same authoritative transaction.
    pub fn execute_for_dispatch_with_attempt(
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
        agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
    ) -> Result<HumanOperationExecution, ServerError> {
        Self::execute_for_dispatch_with_attempt_and_correlation(
            state,
            operation,
            normalized_input,
            actor_context,
            decision,
            agent_attempt,
            None,
        )
    }

    /// Executes one Agent operation with atomic authentication-attempt
    /// persistence and the validated HTTP correlation identity.
    ///
    /// # Errors
    ///
    /// Returns [`ServerError`] on any execution or persistence failure.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_for_dispatch_with_attempt_and_correlation(
        state: &AppState,
        operation: &RemoteOperationV1,
        normalized_input: &Value,
        actor_context: &AuthenticatedActorContextV2,
        decision: &RemoteAuthorizationDecisionV1,
        agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
        correlation_id: Option<&str>,
    ) -> Result<HumanOperationExecution, ServerError> {
        if AgentOperationProjectionV1
            .lookup(&operation.name, &operation.version)
            .is_none()
        {
            return Err(ServerError::Dispatch(format!(
                "unregistered Agent operation `{}` at `{}`",
                operation.name, operation.version
            )));
        }
        if native_localized_agent_operation(operation) {
            execute_native_agent(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                agent_attempt,
                correlation_id,
            )
        } else {
            execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::Generic,
                None,
                agent_attempt,
            )
        }
    }
}

fn native_localized_agent_operation(operation: &RemoteOperationV1) -> bool {
    matches!(
        AuthorityOperation::from_pair(&operation.name, &operation.version),
        Some(
            AuthorityOperation::ContextBuildV2
                | AuthorityOperation::ChangesetAddV2
                | AuthorityOperation::ChangesetCommitV2
                | AuthorityOperation::ChangesetCreateV2
                | AuthorityOperation::ChangesetDiffV2
                | AuthorityOperation::ChangesetGetV2
                | AuthorityOperation::ChangesetSubmitV2
                | AuthorityOperation::ChangesetValidateV2
                | AuthorityOperation::EditionCreateV2
                | AuthorityOperation::ObjectQueryReleasedV2
                | AuthorityOperation::ReleaseCreateV2
                | AuthorityOperation::WorkspaceStatusV1
        )
    )
}

fn native_operation_refreshes_projection(operation: &RemoteOperationV1) -> bool {
    matches!(
        operation.name.as_str(),
        "changeset.commit" | "release.create"
    )
}

// These transaction bodies expand where the savepoint's concrete PostgreSQL
// type is inferred; proof-server intentionally does not name that type.
macro_rules! read_auth_sequence_in_tx {
    ($tx:expr) => {{
        let value: i64 = $tx
            .query_one(
                "SELECT authority_sequence FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?
            .get(0);
        u64::try_from(value)
            .map_err(|_| PgError::Integrity("authority sequence is negative".to_owned()))
    }};
}

macro_rules! persist_decision_in_tx {
    ($tx:expr, $decision:expr) => {{
        let value =
            serde_json::to_value($decision).map_err(|e| PgError::Integrity(e.to_string()))?;
        let body = canonical_bytes_pg(&value)?;
        let seq = i64::try_from($decision.authority_sequence)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "INSERT INTO authorization_decisions (
                 authority_sequence, workspace_id, decision_digest, operation, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, now())",
            &[
                &seq,
                &$decision.workspace_id,
                &decision_digest($decision).to_string(),
                &$decision.operation.name,
                &body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_consequence_in_tx {
    ($tx:expr, $consequence:expr, $auth_seq:expr) => {{
        let value =
            serde_json::to_value($consequence).map_err(|e| PgError::Integrity(e.to_string()))?;
        let body = canonical_bytes_pg(&value)?;
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        let effect = $consequence
            .application_effect_digest
            .map(|d| d.to_string());
        $tx.execute(
            "INSERT INTO application_consequences (
                 authority_sequence, workspace_id, consequence_digest, operation,
                 application_effect_digest, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, now())",
            &[
                &seq,
                &$consequence.workspace_id,
                &consequence_digest($consequence).to_string(),
                &$consequence.operation.name,
                &effect,
                &body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_remote_record_in_tx {
    ($tx:expr, $record:expr, $workspace_id:expr, $sequence:expr, $predecessor:expr, $signer:expr) => {{
        if let Some(signer) = $signer.as_ref() {
            let signed = proof_remote::sign_remote_authority_record(&$record, signer.as_ref())
                .map_err(|error| PgError::Integrity(error.to_string()))?;
            let sequence = i64::try_from($sequence)
                .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
            let envelope = signed.envelope_json.as_bytes().to_vec();
            $tx.execute(
                "INSERT INTO remote_authority_records (
                     authority_sequence, workspace_id, record_digest, envelope_digest,
                     payload_type, envelope, predecessor_digest, committed_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, now())",
                &[
                    &sequence,
                    &$workspace_id,
                    &signed.payload_digest.to_string(),
                    &signed.envelope_digest.to_string(),
                    &proof_remote::REMOTE_AUTHORITY_RECORD_PAYLOAD_TYPE,
                    &envelope,
                    &$predecessor.to_string(),
                ],
            )
            .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
        }
    }};
}

macro_rules! persist_idempotency_in_tx {
    ($tx:expr, $candidate:expr, $application_key:expr, $key_kind:expr, $consequence:expr, $result:expr) => {{
        if let Some(application_key) = $application_key.as_deref() {
            let result_digest = $consequence
                .result_digest
                .map(|d| d.to_string())
                .unwrap_or_else(|| consequence_digest($consequence).to_string());
            let result_body = canonical_bytes_pg($result)?;
            $tx.execute(
                "INSERT INTO idempotency_keys (
                     workspace_id, operation, operation_version, normalized_input_digest,
                     requesting_principal, operating_principal, delegation_id, application_key,
                     key_kind, result_digest, result_body, replay_count, committed_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 0, now())",
                &[
                    &$candidate.workspace_id.to_string(),
                    &$candidate.operation.name,
                    &$candidate.operation.version,
                    &$candidate.normalized_input_digest.to_string(),
                    &$candidate.requesting_principal.to_string(),
                    &$candidate.operating_principal.to_string(),
                    &$candidate.delegation.map(|d| d.to_string()),
                    &application_key,
                    &key_kind_label($key_kind),
                    &result_digest,
                    &result_body,
                ],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
        }
    }};
}

macro_rules! advance_authority_head_in_tx {
    ($tx:expr, $digest:expr, $auth_seq:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "UPDATE workspace_write_head
             SET authority_sequence = $2,
                 authority_head_digest = $1, authority_head_sequence = $2
             WHERE singleton = 1",
            &[&$digest.to_string(), &seq],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! read_idempotency_prior_in_tx {
    ($tx:expr, $candidate:expr, $application_key:expr) => {{
        let result: Result<IdempotencyPrior, PgError> = (|| {
            let Some(application_key) = $application_key.as_deref() else {
                return Ok(IdempotencyPrior {
                    prior: None,
                    prior_result_digest: None,
                    prior_result_body: None,
                });
            };
            let row = $tx
                .query_opt(
                    "SELECT operation, operation_version, normalized_input_digest,
                            requesting_principal, operating_principal, delegation_id,
                            result_digest, result_body
                     FROM idempotency_keys
                     WHERE workspace_id = $1 AND application_key = $2",
                    &[&$candidate.workspace_id.to_string(), &application_key],
                )
                .map_err(|error| {
                    PgError::Idempotency(format!("idempotency lookup failed: {error}"))
                })?;
            let Some(row) = row else {
                return Ok(IdempotencyPrior {
                    prior: None,
                    prior_result_digest: None,
                    prior_result_body: None,
                });
            };
            let operation_name: String = row.get(0);
            let operation_version: String = row.get(1);
            let normalized_input_digest: String = row.get(2);
            let requesting_principal: String = row.get(3);
            let operating_principal: String = row.get(4);
            let delegation: Option<String> = row.get(5);
            let result_digest: String = row.get(6);
            let result_body: Option<Vec<u8>> = row.get(7);
            Ok(IdempotencyPrior {
                prior: Some(IdempotencyTupleV1 {
                    workspace_id: $candidate.workspace_id,
                    operation: RemoteOperationV1 {
                        name: operation_name,
                        version: operation_version,
                    },
                    normalized_input_digest: normalized_input_digest.parse().map_err(|error| {
                        PgError::Integrity(format!("invalid stored input digest: {error}"))
                    })?,
                    requesting_principal: requesting_principal.parse().map_err(|_| {
                        PgError::Integrity("invalid stored requesting Principal".to_owned())
                    })?,
                    operating_principal: operating_principal.parse().map_err(|_| {
                        PgError::Integrity("invalid stored operating Principal".to_owned())
                    })?,
                    delegation: delegation.as_deref().map(str::parse).transpose().map_err(
                        |_| PgError::Integrity("invalid stored Delegation identity".to_owned()),
                    )?,
                }),
                prior_result_digest: Some(result_digest.parse().map_err(|error| {
                    PgError::Integrity(format!("invalid stored result digest: {error}"))
                })?),
                prior_result_body: result_body,
            })
        })();
        result
    }};
}

macro_rules! read_release_delivery_destination_in_tx {
    ($tx:expr, $fields:expr) => {{
        let result: Result<ReleaseDeliveryDestination, PgError> = (|| {
            let fact_id = format!("environment/{}", $fields.environment_id);
            let row = $tx
                .query_opt(
                    "SELECT body FROM facts WHERE fact_id = $1 AND fact_kind = 'environment'",
                    &[&fact_id],
                )
                .map_err(|error| proof_pg::transaction::transaction_error(&error))?
                .ok_or_else(|| {
                    PgError::Integrity(
                        "Release delivery lacks its active Environment configuration".to_owned(),
                    )
                })?;
            let body: Vec<u8> = row.get(0);
            let environment: Value = serde_json::from_slice(&body).map_err(|error| {
                PgError::Integrity(format!("invalid active Environment fact: {error}"))
            })?;
            let config_version = environment
                .get("config_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    PgError::Integrity("active Environment lacks config_version".to_owned())
                })?;
            let config_digest: ContentDigest = environment
                .get("config_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PgError::Integrity("active Environment lacks config_digest".to_owned())
                })?
                .parse()
                .map_err(|error| {
                    PgError::Integrity(format!("invalid active Environment digest: {error}"))
                })?;
            if config_version != $fields.environment_config_version
                || config_digest != $fields.environment_config_digest
            {
                return Err(PgError::Integrity(
                    "Release delivery Environment configuration disagrees with the Release"
                        .to_owned(),
                ));
            }
            if environment.get("target_kind").and_then(Value::as_str) != Some("preview") {
                return Err(PgError::Integrity(
                    "Release delivery target is not preview".to_owned(),
                ));
            }

            let Some(delivery) = environment.get("delivery") else {
                return Ok(ReleaseDeliveryDestination {
                    version: config_version,
                    digest: config_digest,
                });
            };
            let version = delivery
                .get("destination_configuration_version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    PgError::Integrity(
                        "active Environment delivery lacks destination configuration version"
                            .to_owned(),
                    )
                })?;
            let digest = delivery
                .get("destination_configuration_digest")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PgError::Integrity(
                        "active Environment delivery lacks destination configuration digest"
                            .to_owned(),
                    )
                })?
                .parse()
                .map_err(|error| {
                    PgError::Integrity(format!("invalid destination configuration digest: {error}"))
                })?;
            Ok(ReleaseDeliveryDestination { version, digest })
        })();
        result
    }};
}

macro_rules! read_workspace_transaction_sequence_in_tx {
    ($tx:expr) => {{
        let value: i64 = $tx
            .query_one(
                "SELECT transaction_sequence FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .map_err(|error| proof_pg::transaction::transaction_error(&error))?
            .get(0);
        u64::try_from(value)
            .map_err(|_| PgError::Integrity("transaction sequence is negative".to_owned()))
    }};
}

#[allow(clippy::too_many_lines)]
fn execute_native_agent(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
    agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
    correlation_id: Option<&str>,
) -> Result<HumanOperationExecution, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_agent_denial_with_policy(
            state,
            decision,
            actor_context,
            normalized_input,
            agent_attempt,
            CausalSequencePolicy::AuthorityOnly,
        )?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }

    let prepared_release_delivery = if operation.name == "release.create" {
        Some(PreparedReleaseDelivery {
            event_id: uuid::Uuid::now_v7().to_string(),
            delivery_id: uuid::Uuid::now_v7().to_string(),
            created_at: now_timestamp()?,
            correlation_id: correlation_id.map(str::parse).transpose().map_err(|_| {
                ServerError::Internal("validated correlation ID became invalid".into())
            })?,
        })
    } else {
        None
    };
    let prepared_consequence = PreparedConsequence {
        consequence_id: uuid::Uuid::now_v7().to_string(),
        recorded_at: now_timestamp()?,
    };

    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let (requesting_principal, operating_principal, delegation) = actor_principals(actor_context);
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(normalized_input, operation)
            .map_err(|error| ServerError::Internal(error.to_string()))?;
    let candidate = IdempotencyTupleV1 {
        workspace_id: parse_workspace_id(&decision.workspace_id)?,
        operation: operation.clone(),
        normalized_input_digest,
        requesting_principal: parse_principal_id(&requesting_principal)?,
        operating_principal: parse_principal_id(&operating_principal)?,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Authorization("invalid Delegation identity".to_owned()))?,
    };
    let key_kind = idempotency_kind(operation);
    let provided_application_key = normalized_input
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if key_kind == ApplicationKeyKind::RequiredUuidV7 && provided_application_key.is_none() {
        return Err(ServerError::Dispatch(
            "normalized keyed Agent input lacks idempotency_key".to_owned(),
        ));
    }

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let input_owned = normalized_input.clone();
    let actor_owned = actor_context.clone();
    let release_signer = state.config.release_signer.clone();
    let authority_signer = state.config.authority_signer.clone();
    let portable_authority = authority_signer.is_some();
    let candidate_for_hook = candidate.clone();
    let provided_key_for_hook = provided_application_key;
    let authorization_actor = actor_context.clone();
    let authorization_input = normalized_input.clone();
    let authorization_attempt = agent_attempt.cloned();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let consequence_for_hook = Rc::clone(&built_consequence);
    let built_result: Rc<RefCell<Option<Value>>> = Rc::new(RefCell::new(None));
    let result_for_hook = Rc::clone(&built_result);
    let application_problem: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let problem_for_hook = Rc::clone(&application_problem);
    let decision_for_hook = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            let decision_for_authorization = decision.clone();
            Box::new(
                move |tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    revalidate_and_claim_agent_attempt(
                        tx,
                        head,
                        expected_head,
                        &authorization_actor,
                        &authorization_input,
                        &decision_for_authorization,
                        authorization_attempt.as_ref(),
                    )
                },
            )
        },
        // Replay/conflict evidence is committed by the consequence hook so it
        // shares the same locked transaction and authority record as success.
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let application_key = match key_kind {
                ApplicationKeyKind::RequiredUuidV7 => provided_key_for_hook.clone(),
                ApplicationKeyKind::None => None,
                ApplicationKeyKind::DerivedChangeset => Some(derived_changeset_application_key(
                    candidate_for_hook.workspace_id,
                    &input_owned,
                )?),
                ApplicationKeyKind::DerivedProposalPolicyValidator => {
                    proof_pg::parity::derive_validation_application_key_in_transaction(
                        tx,
                        candidate_for_hook.workspace_id,
                        &input_owned,
                    )?
                }
            };
            let prior = read_idempotency_prior_in_tx!(tx, candidate_for_hook, application_key)?;
            let idempotency_outcome = replay_or_conflict(&candidate_for_hook, prior.prior.as_ref());
            match idempotency_outcome {
                IdempotencyOutcome::Replayed => {
                    let prior_result_body =
                        prior.prior_result_body.as_deref().ok_or_else(|| {
                            PgError::Integrity(
                                "stored idempotency result bytes are absent".to_owned(),
                            )
                        })?;
                    let prior_result: Value =
                        serde_json::from_slice(prior_result_body).map_err(|error| {
                            PgError::Integrity(format!("invalid stored result bytes: {error}"))
                        })?;
                    let stored_result_digest = prior.prior_result_digest.ok_or_else(|| {
                        PgError::Integrity("stored idempotency result digest is absent".to_owned())
                    })?;
                    let recomputed_result_digest = operation_effect_digest(&prior_result)
                        .map_err(|error| PgError::Integrity(error.to_string()))?;
                    if recomputed_result_digest != stored_result_digest {
                        return Err(PgError::Integrity(
                            "stored idempotency result bytes do not match their digest".to_owned(),
                        ));
                    }
                    let consequence = bind_native_authority_chain(
                        apply_prepared_consequence(
                            replay_consequence(
                                decision_for_hook.clone(),
                                &operation_owned,
                                prior.prior_result_digest,
                                key_kind,
                                application_key.clone(),
                            ),
                            &prepared_consequence,
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    tx.execute(
                        "UPDATE idempotency_keys
                         SET replay_count = replay_count + 1
                         WHERE workspace_id = $1 AND application_key = $2",
                        &[
                            &candidate_for_hook.workspace_id.to_string(),
                            &application_key,
                        ],
                    )
                    .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
                    *result_for_hook.borrow_mut() = Some(prior_result);
                    *consequence_for_hook.borrow_mut() = Some(consequence);
                    return Ok(());
                }
                IdempotencyOutcome::Conflict => {
                    let consequence = bind_native_authority_chain(
                        apply_prepared_consequence(
                            conflict_consequence(
                                decision_for_hook.clone(),
                                &operation_owned,
                                prior.prior_result_digest,
                                key_kind,
                                application_key.clone(),
                            ),
                            &prepared_consequence,
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    *consequence_for_hook.borrow_mut() = Some(consequence);
                    *problem_for_hook.borrow_mut() =
                        Some("proof.idempotency.key_reused".to_owned());
                    return Err(PgError::ApplicationFailure(
                        "proof.idempotency.key_reused".to_owned(),
                    ));
                }
                IdempotencyOutcome::Fresh => {}
            }

            persist_decision_in_tx!(tx, &decision_for_hook);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                decision_for_hook.workspace_id,
                decision_for_hook.authority_sequence,
                decision_for_hook.previous_authority_record_digest,
                authority_signer
            );
            let mut savepoint = SavepointGuard::establish(tx)?;
            let trace = if operation_owned.name == "content-resource-intent.issue" {
                proof_pg::parity::issue_resource_intent_in_transaction(
                    savepoint.transaction(),
                    candidate_for_hook.workspace_id,
                    &input_owned,
                    &actor_owned,
                )
            } else if operation_owned.name == "changeset.approve" {
                proof_pg::parity::approve_changeset_in_transaction(
                    savepoint.transaction(),
                    candidate_for_hook.workspace_id,
                    &input_owned,
                    &actor_owned,
                    decision_for_hook.evaluated_at,
                )
            } else {
                proof_pg::parity::execute_operation_in_transaction(
                    savepoint.transaction(),
                    candidate_for_hook.workspace_id,
                    release_signer.as_deref(),
                    &input_owned,
                    &actor_owned,
                )
            };
            let trace = match trace {
                Ok(trace) => trace,
                Err(error) => {
                    savepoint.rollback()?;
                    return Err(error);
                }
            };
            match trace.outcome {
                OracleOutcome::TypedResult(result) => {
                    let result = project_native_result_for_registry(
                        savepoint.transaction(),
                        &operation_owned,
                        &input_owned,
                        result,
                        &actor_owned,
                        &decision_for_hook,
                    )?;
                    let effect_digest = match trace.consequence {
                        OracleConsequence::Null => None,
                        OracleConsequence::ConsequenceDigest(digest) => Some(digest),
                    };
                    let result_digest = operation_effect_digest(&result)
                        .map_err(|error| PgError::Integrity(error.to_string()))?;
                    let consequence = bind_native_authority_chain(
                        apply_prepared_consequence(
                            build_consequence(
                                &decision_for_hook,
                                &operation_owned,
                                ApplicationConsequenceOutcome::Success,
                                key_kind,
                                application_key.clone(),
                                Some(result_digest),
                                None,
                                effect_digest,
                                effect_digest.map(|record_digest| AuthorityHeadV1 {
                                    sequence: auth_seq,
                                    record_digest,
                                }),
                                None,
                                auth_seq,
                                decision_digest(&decision_for_hook),
                            ),
                            &prepared_consequence,
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    {
                        let sp = savepoint.transaction();
                        persist_consequence_in_tx!(
                            sp,
                            &consequence,
                            consequence.authority_sequence
                        );
                        persist_remote_record_in_tx!(
                            sp,
                            RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                            consequence.workspace_id,
                            consequence.authority_sequence,
                            consequence.previous_authority_record_digest,
                            authority_signer
                        );
                        persist_idempotency_in_tx!(
                            sp,
                            &candidate_for_hook,
                            &application_key,
                            key_kind,
                            &consequence,
                            &result
                        );
                        if let Some(prepared) = prepared_release_delivery.as_ref() {
                            let release_effect = effect_digest.ok_or_else(|| {
                                PgError::Integrity(
                                    "Release success lacks its effect digest".to_owned(),
                                )
                            })?;
                            let fields = release_delivery_fields(
                                &result,
                                release_effect,
                                candidate_for_hook.workspace_id,
                            )?;
                            let destination = read_release_delivery_destination_in_tx!(sp, fields)?;
                            let event = release_delivery_event(
                                prepared,
                                &fields,
                                &destination,
                                candidate_for_hook.workspace_id,
                                read_workspace_transaction_sequence_in_tx!(sp)?,
                            );
                            enqueue_initial_delivery(sp, &event, &prepared.delivery_id)?;
                        }
                        advance_authority_head_in_tx!(
                            sp,
                            &consequence_digest(&consequence),
                            consequence.authority_sequence
                        );
                        if native_operation_refreshes_projection(&operation_owned) {
                            proof_pg::projection::rebuild_content_and_swap_in_transaction(sp)?;
                        }
                    }
                    savepoint.release()?;
                    *result_for_hook.borrow_mut() = Some(result);
                    *consequence_for_hook.borrow_mut() = Some(consequence);
                    Ok(())
                }
                OracleOutcome::StableProblem(problem) => {
                    savepoint.rollback()?;
                    let consequence = bind_native_authority_chain(
                        apply_prepared_consequence(
                            native_failure_consequence(
                                &decision_for_hook,
                                &operation_owned,
                                &problem.code,
                                application_key,
                                key_kind,
                                auth_seq,
                            )
                            .map_err(|error| PgError::Integrity(error.to_string()))?,
                            &prepared_consequence,
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    *consequence_for_hook.borrow_mut() = Some(consequence);
                    *problem_for_hook.borrow_mut() = Some(problem.code.clone());
                    Err(PgError::ApplicationFailure(problem.code))
                }
            }
        }),
    };

    let commit = run_unit_of_work_with_retry_and_sequence_policy_commit(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        CausalSequencePolicy::AuthorityOnly,
    )
    .map_err(map_agent_uow_error)?;
    match commit.outcome {
        UnitOfWorkOutcome::Committed => Ok(HumanOperationExecution {
            consequence: built_consequence.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("native consequence was not produced".into())
            })?,
            result: built_result
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("native result was not produced".into()))?,
            transaction_sequence: commit.transaction_sequence,
        }),
        UnitOfWorkOutcome::ApplicationFailureCommitted => Err(ServerError::ApplicationProblem(
            application_problem
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("native Problem was not produced".into()))?,
        )),
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "native idempotency escaped the locked consequence hook".to_owned(),
            ))
        }
    }
}

fn project_native_result_for_registry(
    transaction: &mut postgres::Transaction<'_>,
    operation: &RemoteOperationV1,
    input: &Value,
    result: Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<Value, PgError> {
    if operation.name == "changeset.approve" {
        return project_changeset_approval_result(
            transaction,
            input,
            &result,
            actor_context,
            decision,
        );
    }
    if operation.name != "workspace.status" {
        return Ok(result);
    }
    let (requesting_principal_id, operating_principal_id, delegation_id) =
        actor_principals(actor_context);
    let delegation_id = delegation_id.ok_or_else(|| {
        PgError::Integrity("workspace.status Agent result lacks a Delegation identity".to_owned())
    })?;
    Ok(json!({
        "workspace_id": required_result_member(&result, "workspace_id")?,
        "requesting_principal_id": requesting_principal_id,
        "operating_principal_id": operating_principal_id,
        "delegation_id": delegation_id,
        "storage_schema_version": required_result_member(&result, "storage_schema_version")?,
        "authoritative_sequence": required_result_member(&result, "authoritative_sequence")?,
        "state_digest": required_result_member(&result, "state_digest")?,
        "authorization_decision_digest": decision_digest(decision).to_string(),
    }))
}

fn project_changeset_approval_result(
    transaction: &mut postgres::Transaction<'_>,
    input: &Value,
    approval: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<Value, PgError> {
    let AuthenticatedActorContextV2::Human(approver) = actor_context else {
        return Err(PgError::Integrity(
            "changeset.approve result requires a Human actor context".to_owned(),
        ));
    };
    let changeset_id = required_result_str(input, "changeset_id")?;
    let changeset = read_projection_fact(
        transaction,
        &format!("localized_changeset/{changeset_id}"),
        "localized_changeset",
    )?;
    let submission = read_projection_fact(
        transaction,
        &format!("localized_submission/{changeset_id}"),
        "localized_submission",
    )?;
    let resource_intent_id = required_result_str(&changeset, "resource_intent_id")?;
    let resource_intent = read_projection_fact(
        transaction,
        &format!("resource_intent/{resource_intent_id}"),
        "resource_intent",
    )?;
    let context_pack_id = required_result_str(&changeset, "context_pack_id")?;
    let context_pack = read_projection_fact(
        transaction,
        &format!("context_pack/{context_pack_id}"),
        "context_pack",
    )?;
    let environment_id = required_result_str(&resource_intent, "environment_id")?;
    let environment = read_projection_fact(
        transaction,
        &format!("environment/{environment_id}"),
        "environment",
    )?;
    let requesting_principal_id = required_result_str(&changeset, "principal_id")?;
    let requesting_subject_commitment =
        read_subject_commitment(transaction, requesting_principal_id)?;
    let reviewer_role_assignment_digest = decision
        .role_assignment_digests
        .first()
        .ok_or_else(|| {
            PgError::Integrity(
                "changeset.approve decision lacks its reviewer role assignment".to_owned(),
            )
        })?
        .to_string();
    let effect_evaluated_head = AuthorityHeadV1 {
        sequence: decision.authority_sequence,
        record_digest: decision_digest(decision),
    };
    let authority_sequence = effect_evaluated_head
        .sequence
        .checked_add(1)
        .ok_or_else(|| PgError::Integrity("approval authority sequence overflow".to_owned()))?;

    Ok(json!({
        "api_version": "proof.dev/changeset-approval/v1",
        "workspace_id": decision.workspace_id,
        "approval_id": required_result_member(input, "approval_id")?,
        "approval_name": required_result_member(approval, "approval_name")?,
        "changeset_id": changeset_id,
        "approval_decision": "approved",
        "requesting_principal_id": requesting_principal_id,
        "requesting_subject_commitment": requesting_subject_commitment,
        "operating_principal_id": required_result_member(&context_pack, "principal_id")?,
        "approver_principal_id": approver.requesting_principal_id,
        "approver_subject_commitment": approver.requesting_subject_commitment.to_string(),
        "approver_binding_id": approver.requesting_binding_id,
        "approver_actor_context_digest": decision.actor_context_digest.to_string(),
        "reviewer_role_assignment_digest": reviewer_role_assignment_digest,
        "publisher_principal_id": required_result_member(&context_pack, "principal_id")?,
        "sealed_changeset_digest": required_result_member(&changeset, "sealed_changeset_digest")?,
        "proposal_digest": required_result_member(&changeset, "proposal_digest")?,
        "effective_leaves_digest": required_result_member(&changeset, "effective_leaf_digest")?,
        "validation_results_digest": required_result_member(&submission, "validation_results_digest")?,
        "submission_id": submission.get("submission_id").cloned().unwrap_or_else(|| json!(changeset_id)),
        "submission_digest": required_result_member(&submission, "effect_digest")?,
        "resource_intent_id": resource_intent_id,
        "resource_intent_digest": required_result_member(&changeset, "resource_intent_digest")?,
        "context_pack_id": context_pack_id,
        "context_pack_digest": required_result_member(&changeset, "context_pack_digest")?,
        "environment_id": environment_id,
        "environment_config_version": required_result_member(&environment, "config_version")?,
        "environment_config_digest": required_result_member(&environment, "config_digest")?,
        "environment_activated_by_principal_id": required_result_member(&environment, "principal_id")?,
        "policy_bundle_digest": decision.policy_bundle_digest.to_string(),
        "validation_policy_digest": required_result_member(&context_pack, "policy_digest")?,
        "idempotency_key": required_result_member(input, "idempotency_key")?,
        "normalized_input_digest": approver.normalized_input_digest.to_string(),
        "evaluated_authority_head": effect_evaluated_head,
        "approved_at": required_result_member(approval, "approved_at")?,
        "authority_sequence": authority_sequence,
        "previous_authority_record_digest": decision_digest(decision).to_string(),
        "authority_key_id": decision.authority_key_id,
    }))
}

fn read_projection_fact(
    transaction: &mut postgres::Transaction<'_>,
    fact_id: &str,
    fact_kind: &str,
) -> Result<Value, PgError> {
    let row = transaction
        .query_opt("SELECT body FROM facts WHERE fact_id = $1", &[&fact_id])
        .map_err(|error| proof_pg::transaction::transaction_error(&error))?
        .ok_or_else(|| {
            PgError::Integrity(format!(
                "changeset.approve projection lacks `{fact_kind}` fact `{fact_id}`"
            ))
        })?;
    serde_json::from_slice(&row.get::<_, Vec<u8>>(0)).map_err(|error| {
        PgError::Integrity(format!(
            "changeset.approve projection has invalid `{fact_kind}` bytes: {error}"
        ))
    })
}

fn read_subject_commitment(
    transaction: &mut postgres::Transaction<'_>,
    principal_id: &str,
) -> Result<Value, PgError> {
    let rows = transaction
        .query(
            "SELECT body FROM facts WHERE fact_id LIKE 'oidc_binding/%' ORDER BY authority_sequence DESC",
            &[],
        )
        .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
    for row in rows {
        let binding: Value = serde_json::from_slice(&row.get::<_, Vec<u8>>(0))
            .map_err(|error| PgError::Integrity(format!("invalid OIDC binding fact: {error}")))?;
        if binding.get("principal_id").and_then(Value::as_str) == Some(principal_id) {
            return required_result_member(&binding, "subject_commitment");
        }
    }
    Err(PgError::Integrity(format!(
        "changeset.approve projection lacks an OIDC binding for `{principal_id}`"
    )))
}

fn required_result_str<'a>(result: &'a Value, member: &str) -> Result<&'a str, PgError> {
    result.get(member).and_then(Value::as_str).ok_or_else(|| {
        PgError::Integrity(format!(
            "native operation result lacks required string member `{member}`"
        ))
    })
}

fn required_result_member(result: &Value, member: &str) -> Result<Value, PgError> {
    result.get(member).cloned().ok_or_else(|| {
        PgError::Integrity(format!(
            "native operation result lacks required member `{member}`"
        ))
    })
}

/// Returns the stable `proof.dependency.unavailable` pending consequence for
/// dependency successor scope (contract §"HTTP boundary").
///
/// # Errors
///
/// Returns [`ServerError::Dispatch`] when the consequence cannot be built.
#[allow(clippy::unused_self)]
pub fn dependency_unavailable_consequence(
    operation: &RemoteOperationV1,
    _normalized_input: &Value,
    _actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let problem_digest =
        application_problem_digest_preimage(DEPENDENCY_UNAVAILABLE_CODE, operation)
            .map_err(|error| ServerError::Dispatch(error.to_string()))?;
    let mut consequence = RemoteApplicationConsequenceV1 {
        api_version: RemoteApplicationConsequenceApiVersion::V1,
        workspace_id: decision.workspace_id.clone(),
        consequence_id: uuid::Uuid::now_v7().to_string(),
        decision_id: decision.decision_id.clone(),
        decision_digest: decision_digest(decision),
        public_input_projection_digest: decision.public_input_projection_digest,
        operation: operation.clone(),
        operation_registry_sha256: decision.operation_registry_sha256.clone(),
        outcome: ApplicationConsequenceOutcome::ApplicationFailure,
        application_key_kind: ApplicationKeyKind::None,
        application_key: None,
        result_digest: Some(problem_digest),
        prior_result_digest: None,
        application_effect_digest: None,
        application_effect_authority_head: None,
        problem_code: Some(DEPENDENCY_UNAVAILABLE_CODE.to_owned()),
        recorded_at: now_timestamp()?,
        evaluated_authority_head: decision.evaluated_authority_head,
        authority_sequence: decision.authority_sequence,
        previous_authority_record_digest: decision.previous_authority_record_digest,
        authority_key_id: decision.authority_key_id.clone(),
    };
    consequence.copy_decision_binding(decision);
    Ok(consequence)
}

/// The owned Human rows implemented over the P-0010 unit of work (contract
/// §"Human and control operation registry").
pub const OWNED_HUMAN_OPERATION_NAMES: [&str; 18] = [
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
    "schema.get",
    "schema.list",
    "object.list",
];

/// The owned pending-dependency Human rows (contract §"HTTP boundary").
pub const PENDING_DEPENDENCY_OPERATION_NAMES: [&str; 2] =
    ["evidence.export", "evidence.export.get"];

// ---------------------------------------------------------------------------
// Internal execution machinery
// ---------------------------------------------------------------------------

/// Which governed-fact shape one owned mutation produces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FactPlan {
    RoleAssignment,
    RoleRevocation,
    AgentBindingIssue,
    AgentBindingRevocation,
    OidcBindingIssue,
    OidcBindingRevocation,
    PrincipalStatus,
    DelegationIssue,
    DelegationRevocation,
    Generic,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingRevocationInputV1 {
    binding_id: String,
    reason: PrincipalBindingRevocationReason,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcBindingRevocationInputV1 {
    binding_id: String,
    reason: String,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalStatusSetInputV2 {
    principal_id: String,
    expected_status: String,
    new_status: String,
    reason: String,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleRevocationInputV1 {
    assignment_id: String,
    reason: String,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationIssueInputV2 {
    delegation_id: String,
    operating_principal_id: String,
    resource_intent_id: String,
    resource_intent_digest: String,
    actions: DelegationActionsV2,
    scope: DelegationScopeV2,
    constraints: DelegationConstraintsV2,
    not_before: String,
    expires_at: String,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationRevokeInputV1 {
    delegation_id: String,
    reason: DelegationRevocationReasonV1,
    #[serde(rename = "idempotency_key")]
    _idempotency_key: String,
}

/// One governed fact prepared for a fresh success attempt.
struct GovernedFact {
    fact_id: String,
    fact_kind: String,
    workspace_id: String,
    fact_digest: ContentDigest,
    body: Vec<u8>,
    effect_authority_head: Option<AuthorityHeadV1>,
    remote_record: Option<RemoteAuthorityRecordV1>,
    result: Value,
    auxiliary: Vec<AuxiliaryFact>,
}

/// The pre-transaction idempotency lookup result.
struct IdempotencyPrior {
    prior: Option<IdempotencyTupleV1>,
    prior_result_digest: Option<ContentDigest>,
    prior_result_body: Option<Vec<u8>>,
}

#[derive(Clone)]
struct PreparedReleaseDelivery {
    event_id: String,
    delivery_id: String,
    created_at: Timestamp,
    correlation_id: Option<proof_domain::CorrelationId>,
}

#[derive(Clone)]
struct PreparedConsequence {
    consequence_id: String,
    recorded_at: Timestamp,
}

struct ReleaseDeliveryFields {
    release_id: String,
    release_digest: ContentDigest,
    edition_digest: ContentDigest,
    environment_id: String,
    environment_config_version: u64,
    environment_config_digest: ContentDigest,
    release_sequence: u64,
}

struct ReleaseDeliveryDestination {
    version: u64,
    digest: ContentDigest,
}

// ---------------------------------------------------------------------------
// Transaction persistence macros. `postgres::Transaction` cannot be named in
// this crate, so the SQL bodies expand inline at each `apply_consequence`
// closure where the transaction type is inferred.
// ---------------------------------------------------------------------------

macro_rules! persist_fact_in_tx {
    ($tx:expr, $fact:expr, $auth_seq:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "INSERT INTO facts (
                 fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, now())",
            &[
                &$fact.fact_id,
                &$fact.workspace_id,
                &$fact.fact_kind,
                &seq,
                &$fact.fact_digest.to_string(),
                &$fact.body,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! persist_auxiliaries_in_tx {
    ($tx:expr, $fact:expr, $auth_seq:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        for auxiliary in &$fact.auxiliary {
            $tx.execute(
                "INSERT INTO facts (
                     fact_id, workspace_id, fact_kind, authority_sequence, fact_digest, body, committed_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, now())",
                &[
                    &auxiliary.fact_id,
                    &$fact.workspace_id,
                    &auxiliary.kind,
                    &seq,
                    &auxiliary.digest.to_string(),
                    &auxiliary.body,
                ],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
        }
    }};
}

macro_rules! enrollment_precondition_in_tx {
    ($tx:expr, $plan:expr, $prepared:expr) => {{
        let problem: Option<&'static str> = match ($plan, $prepared) {
            (FactPlan::AgentBindingIssue, Some(PreparedEnrollment::Agent(p))) => {
                let consumed = $tx
                    .query_opt(
                        "SELECT 1 FROM facts WHERE fact_id = $1",
                        &[&p.consumption_fact_id],
                    )
                    .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
                let now = now_timestamp().map_err(|error| PgError::Integrity(error.to_string()))?;
                if consumed.is_some()
                    || now < p.challenge.issued_at
                    || now >= p.challenge.expires_at
                {
                    Some("proof.state.conflict")
                } else {
                    None
                }
            }
            (FactPlan::OidcBindingIssue, Some(PreparedEnrollment::Oidc(p))) => {
                let rows = $tx
                    .query(
                        "SELECT body FROM facts WHERE fact_kind = $1",
                        &[&OIDC_PRIVATE_BINDING_KIND],
                    )
                    .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
                let duplicate = rows.iter().any(|row| {
                    let body: Vec<u8> = row.get(0);
                    serde_json::from_slice::<OidcPrincipalBindingPrivateV1>(&body)
                        .is_ok_and(|existing| existing.subject == p.subject)
                });
                if duplicate {
                    Some("proof.state.conflict")
                } else {
                    None
                }
            }
            _ => None,
        };
        problem
    }};
}

fn missing_field(field: &str) -> ServerError {
    ServerError::Dispatch(format!("normalized input is missing `{field}`"))
}

#[derive(Clone)]
enum ContentReadCommand {
    SchemaGet(proof_application::SchemaGetCommand),
    SchemaList(proof_application::SchemaListCommand),
    ObjectList(proof_application::ObjectListCommand),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaGetInput {
    api_version: String,
    schema_id: String,
    schema_version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaListInput {
    api_version: String,
    schema_id: Option<String>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectListInput {
    api_version: String,
    environment_id: String,
    schema_id: Option<String>,
    locale: Option<String>,
    object_ids: Option<Vec<String>>,
    cursor: Option<String>,
    page_size: Option<u32>,
}

fn execute_content_read(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<HumanOperationExecution, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial_with_policy(state, decision, CausalSequencePolicy::AuthorityOnly)?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }
    let command = parse_content_read_command(operation, normalized_input)?;
    let schema_get = matches!(command, ContentReadCommand::SchemaGet(_));
    let _ = actor_context;
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let workspace_id = state.config.workspace_id;
    let decision = decision.clone();
    let operation = operation.clone();
    let authority_signer = state.config.authority_signer.clone();
    let portable_authority = authority_signer.is_some();
    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let built_result: Rc<RefCell<Option<Value>>> = Rc::new(RefCell::new(None));
    let result_for_hook = Rc::clone(&built_result);
    let application_problem: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let problem_for_hook = Rc::clone(&application_problem);
    let decision_for_hook = decision.clone();
    let operation_for_hook = operation.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(
                move |_tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    if head.authority_head == Some(expected_head) {
                        Ok(())
                    } else {
                        Err(PgError::Transaction(
                            "authority head advanced between evaluation and lock".to_owned(),
                        ))
                    }
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let result = match &command {
                ContentReadCommand::SchemaGet(command) => {
                    proof_pg::projection::get_schema(tx, workspace_id, command)
                        .map(|result| schema_get_result_value(&result))
                }
                ContentReadCommand::SchemaList(command) => {
                    proof_pg::projection::list_schemas(tx, workspace_id, command)
                        .map(|result| schema_list_result_value(&result))
                }
                ContentReadCommand::ObjectList(command) => {
                    proof_pg::projection::list_objects(tx, workspace_id, command)
                        .map(|result| object_list_result_value(&result))
                }
            };
            let result = match result {
                Ok(result) => result,
                Err(proof_application::LocalizedContentError::NotFound) => {
                    let code = if schema_get {
                        "proof.schema.not_found"
                    } else {
                        PROBLEM_RESOURCE_NOT_FOUND
                    };
                    let failure = bind_native_authority_chain(
                        delivery_failure_consequence(
                            &decision_for_hook,
                            &operation_for_hook,
                            code,
                            auth_seq,
                        )
                        .map_err(|error| PgError::Integrity(error.to_string()))?,
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &failure, failure.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(failure.clone()),
                        failure.workspace_id,
                        failure.authority_sequence,
                        failure.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&failure),
                        failure.authority_sequence
                    );
                    *built_for_hook.borrow_mut() = Some(failure);
                    *problem_for_hook.borrow_mut() = Some(code.to_owned());
                    return Err(PgError::ApplicationFailure(code.to_owned()));
                }
                Err(proof_application::LocalizedContentError::Storage(detail)) => {
                    return Err(PgError::Transaction(detail));
                }
                Err(proof_application::LocalizedContentError::Integrity(detail)) => {
                    return Err(PgError::Integrity(detail));
                }
                Err(error) => {
                    return Err(PgError::Integrity(format!(
                        "validated content read failed unexpectedly: {error}"
                    )));
                }
            };
            let consequence = bind_native_authority_chain(
                delivery_get_success_consequence(
                    &decision_for_hook,
                    &operation_for_hook,
                    &result,
                    auth_seq,
                )
                .map_err(|error| PgError::Integrity(error.to_string()))?,
                &decision_for_hook,
                auth_seq,
                portable_authority,
            )?;
            persist_decision_in_tx!(tx, &decision_for_hook);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                decision_for_hook.workspace_id,
                decision_for_hook.authority_sequence,
                decision_for_hook.previous_authority_record_digest,
                authority_signer
            );
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_consequence_in_tx!(sp, &consequence, consequence.authority_sequence);
                persist_remote_record_in_tx!(
                    sp,
                    RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                    consequence.workspace_id,
                    consequence.authority_sequence,
                    consequence.previous_authority_record_digest,
                    authority_signer
                );
                advance_authority_head_in_tx!(
                    sp,
                    &consequence_digest(&consequence),
                    consequence.authority_sequence
                );
            }
            savepoint.release()?;
            *result_for_hook.borrow_mut() = Some(result);
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };
    let commit = run_unit_of_work_with_retry_and_sequence_policy_commit(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        CausalSequencePolicy::AuthorityOnly,
    )
    .map_err(ServerError::Storage)?;
    match commit.outcome {
        UnitOfWorkOutcome::Committed => Ok(HumanOperationExecution {
            consequence: built_consequence.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("read consequence was not produced".to_owned())
            })?,
            result: built_result
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("read result was not produced".to_owned()))?,
            transaction_sequence: commit.transaction_sequence,
        }),
        UnitOfWorkOutcome::ApplicationFailureCommitted => Err(ServerError::ApplicationProblem(
            application_problem
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("read Problem was not produced".to_owned()))?,
        )),
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "a no-key read produced an unexpected idempotency outcome".to_owned(),
            ))
        }
    }
}

fn parse_content_read_command(
    operation: &RemoteOperationV1,
    normalized_input: &Value,
) -> Result<ContentReadCommand, ServerError> {
    match operation.name.as_str() {
        "schema.get" => {
            let input: SchemaGetInput = strict_read_input(normalized_input)?;
            require_read_version(
                &input.api_version,
                proof_application::SCHEMA_GET_OPERATION_API_VERSION,
            )?;
            let schema_id = proof_application::SchemaId::new(input.schema_id)
                .map_err(|error| ServerError::Dispatch(error.to_string()))?;
            let schema_version = proof_application::SchemaVersion::new(input.schema_version)
                .map_err(|error| ServerError::Dispatch(error.to_string()))?;
            Ok(ContentReadCommand::SchemaGet(
                proof_application::SchemaGetCommand {
                    schema_id,
                    schema_version,
                },
            ))
        }
        "schema.list" => {
            let input: SchemaListInput = strict_read_input(normalized_input)?;
            require_read_version(
                &input.api_version,
                proof_application::SCHEMA_LIST_OPERATION_API_VERSION,
            )?;
            let command = proof_application::SchemaListCommand {
                schema_id: input
                    .schema_id
                    .map(proof_application::SchemaId::new)
                    .transpose()
                    .map_err(|error| ServerError::Dispatch(error.to_string()))?,
                cursor: input.cursor,
                page_size: input.page_size,
            };
            command
                .validated_bounds()
                .map_err(|error| ServerError::Dispatch(error.to_string()))?;
            Ok(ContentReadCommand::SchemaList(command))
        }
        "object.list" => {
            let input: ObjectListInput = strict_read_input(normalized_input)?;
            require_read_version(
                &input.api_version,
                proof_application::OBJECT_LIST_OPERATION_API_VERSION,
            )?;
            let command = proof_application::ObjectListCommand {
                environment_id: proof_application::EnvironmentId::new(input.environment_id)
                    .map_err(|error| ServerError::Dispatch(error.to_string()))?,
                schema_id: input
                    .schema_id
                    .map(proof_application::SchemaId::new)
                    .transpose()
                    .map_err(|error| ServerError::Dispatch(error.to_string()))?,
                locale: input
                    .locale
                    .map(proof_application::LocaleId::new)
                    .transpose()
                    .map_err(|error| ServerError::Dispatch(error.to_string()))?,
                object_ids: input
                    .object_ids
                    .map(|ids| {
                        ids.into_iter()
                            .map(|id| id.parse::<proof_application::ObjectId>())
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()
                    .map_err(|error| ServerError::Dispatch(error.to_string()))?,
                cursor: input.cursor,
                page_size: input.page_size,
            };
            command
                .validated_bounds()
                .map_err(|error| ServerError::Dispatch(error.to_string()))?;
            Ok(ContentReadCommand::ObjectList(command))
        }
        _ => Err(ServerError::Dispatch(format!(
            "unsupported content read `{}`",
            operation.name
        ))),
    }
}

fn strict_read_input<T: for<'de> Deserialize<'de>>(input: &Value) -> Result<T, ServerError> {
    serde_json::from_value(input.clone()).map_err(|error| ServerError::Dispatch(error.to_string()))
}

fn require_read_version(actual: &str, expected: &str) -> Result<(), ServerError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ServerError::ApplicationProblem(
            "proof.input.unsupported_version".to_owned(),
        ))
    }
}

fn schema_provenance_value(provenance: proof_application::SchemaReadProvenance) -> Value {
    json!({
        "authoritative_sequence": provenance.authoritative_sequence,
        "changeset_id": provenance.changeset_id.to_string(),
        "edit_id": provenance.edit_id.to_string(),
    })
}

fn schema_get_result_value(result: &proof_application::SchemaGetResult) -> Value {
    json!({
        "document": result.document,
        "document_digest": result.document_digest.to_string(),
        "provenance": schema_provenance_value(result.provenance),
        "schema_id": result.schema_id.as_str(),
        "schema_version": result.schema_version.get(),
    })
}

fn schema_list_result_value(result: &proof_application::SchemaListResult) -> Value {
    let mut value = json!({
        "entries": result.entries.iter().map(|entry| json!({
            "document_digest": entry.document_digest.to_string(),
            "provenance": schema_provenance_value(entry.provenance),
            "schema_id": entry.schema_id.as_str(),
            "schema_version": entry.schema_version.get(),
        })).collect::<Vec<_>>(),
    });
    if let Some(cursor) = &result.next_cursor {
        value
            .as_object_mut()
            .expect("Schema list result is an object")
            .insert("next_cursor".to_owned(), Value::String(cursor.clone()));
    }
    value
}

fn object_list_result_value(result: &proof_application::ObjectListResult) -> Value {
    let mut value = json!({
        "entries": result.entries.iter().map(|entry| json!({
            "covered_by_current_release": entry.covered_by_current_release,
            "head_renditions": entry.head_renditions.iter().map(|rendition| json!({
                "locale": rendition.locale.as_str(),
                "rendition_digest": rendition.rendition_digest.to_string(),
                "revision": rendition.revision.get(),
            })).collect::<Vec<_>>(),
            "object_id": entry.object_id.to_string(),
            "released_revision": entry.released_revision.map(proof_application::ObjectRevision::get),
            "schema_id": entry.schema_id.as_str(),
            "schema_version": entry.schema_version.get(),
        })).collect::<Vec<_>>(),
        "state_scope": result.state_scope,
    });
    if let Some(cursor) = &result.next_cursor {
        value
            .as_object_mut()
            .expect("Object list result is an object")
            .insert("next_cursor".to_owned(), Value::String(cursor.clone()));
    }
    value
}

/// Runs one owned mutation through the P-0010 unit of work.
#[allow(clippy::too_many_lines)]
fn execute_owned(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
    plan: FactPlan,
    prepared: Option<&PreparedEnrollment>,
    agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
) -> Result<HumanOperationExecution, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        if matches!(actor_context, AuthenticatedActorContextV2::HumanAgent(_)) {
            commit_agent_denial_with_policy(
                state,
                decision,
                actor_context,
                normalized_input,
                agent_attempt,
                CausalSequencePolicy::AuthorityOnly,
            )?;
        } else {
            commit_denial_with_policy(state, decision, CausalSequencePolicy::AuthorityOnly)?;
        }
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }

    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let (requesting_principal, operating_principal, delegation) = actor_principals(actor_context);
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(normalized_input, operation)
            .map_err(|error| ServerError::Internal(error.to_string()))?;

    let candidate = IdempotencyTupleV1 {
        workspace_id: parse_workspace_id(&decision.workspace_id)?,
        operation: operation.clone(),
        normalized_input_digest,
        requesting_principal: parse_principal_id(&requesting_principal)?,
        operating_principal: parse_principal_id(&operating_principal)?,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Authorization("invalid Delegation identity".to_owned()))?,
    };
    let key_kind = idempotency_kind(operation);
    let application_key = normalized_input
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if key_kind == ApplicationKeyKind::RequiredUuidV7 && application_key.is_none() {
        return Err(ServerError::Dispatch(
            "normalized keyed input lacks idempotency_key".to_owned(),
        ));
    }

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let input_owned = normalized_input.clone();
    let actor_owned = actor_context.clone();
    let authority_signer = state.config.authority_signer.clone();
    let portable_authority = authority_signer.is_some();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let built_result: Rc<RefCell<Option<Value>>> = Rc::new(RefCell::new(None));
    let result_for_hook = Rc::clone(&built_result);
    let application_problem: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let problem_for_hook = Rc::clone(&application_problem);
    let decision_for_hook = decision.clone();
    let input_for_hook = input_owned.clone();
    let operation_for_hook = operation_owned.clone();
    let actor_for_hook = actor_owned.clone();
    let application_key_for_hook = application_key.clone();
    let candidate_for_hook = candidate.clone();
    let authorization_actor = actor_context.clone();
    let authorization_input = normalized_input.clone();
    let authorization_attempt = agent_attempt.cloned();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            let decision_for_authorization = decision.clone();
            Box::new(
                move |tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    revalidate_and_claim_agent_attempt(
                        tx,
                        head,
                        expected_head,
                        &authorization_actor,
                        &authorization_input,
                        &decision_for_authorization,
                        authorization_attempt.as_ref(),
                    )
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let decision_sequence = read_auth_sequence_in_tx!(tx)?;
            let prior =
                read_idempotency_prior_in_tx!(tx, candidate_for_hook, application_key_for_hook)?;
            match replay_or_conflict(&candidate_for_hook, prior.prior.as_ref()) {
                IdempotencyOutcome::Replayed => {
                    let prior_result_body =
                        prior.prior_result_body.as_deref().ok_or_else(|| {
                            PgError::Integrity(
                                "stored idempotency result bytes are absent".to_owned(),
                            )
                        })?;
                    let prior_result: Value =
                        serde_json::from_slice(prior_result_body).map_err(|error| {
                            PgError::Integrity(format!("invalid stored result bytes: {error}"))
                        })?;
                    let stored_result_digest = prior.prior_result_digest.ok_or_else(|| {
                        PgError::Integrity("stored idempotency result digest is absent".to_owned())
                    })?;
                    if operation_effect_digest(&prior_result)
                        .map_err(|error| PgError::Integrity(error.to_string()))?
                        != stored_result_digest
                    {
                        return Err(PgError::Integrity(
                            "stored idempotency result bytes do not match their digest".to_owned(),
                        ));
                    }
                    let consequence = bind_native_authority_chain(
                        replay_consequence(
                            decision_for_hook.clone(),
                            &operation_for_hook,
                            prior.prior_result_digest,
                            key_kind,
                            application_key_for_hook.clone(),
                        ),
                        &decision_for_hook,
                        decision_sequence,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    tx.execute(
                        "UPDATE idempotency_keys
                         SET replay_count = replay_count + 1
                         WHERE workspace_id = $1 AND application_key = $2",
                        &[
                            &candidate_for_hook.workspace_id.to_string(),
                            &application_key_for_hook,
                        ],
                    )
                    .map_err(|error| proof_pg::transaction::transaction_error(&error))?;
                    *result_for_hook.borrow_mut() = Some(prior_result);
                    *built_for_hook.borrow_mut() = Some(consequence);
                    return Ok(());
                }
                IdempotencyOutcome::Conflict => {
                    let consequence = bind_native_authority_chain(
                        conflict_consequence(
                            decision_for_hook.clone(),
                            &operation_for_hook,
                            prior.prior_result_digest,
                            key_kind,
                            application_key_for_hook.clone(),
                        ),
                        &decision_for_hook,
                        decision_sequence,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    *built_for_hook.borrow_mut() = Some(consequence);
                    *problem_for_hook.borrow_mut() =
                        Some("proof.idempotency.key_reused".to_owned());
                    return Err(PgError::ApplicationFailure(
                        "proof.idempotency.key_reused".to_owned(),
                    ));
                }
                IdempotencyOutcome::Fresh => {}
            }
            let decision_record_digest = decision_digest(&decision_for_hook);
            let decision_head = AuthorityHeadV1 {
                sequence: decision_sequence,
                record_digest: decision_record_digest,
            };
            let authority_effect =
                effect_rule(&operation_for_hook) == EffectDigestRule::RemoteAuthorityRecord;
            let fact_sequence = decision_sequence
                .checked_add(u64::from(authority_effect))
                .ok_or_else(|| PgError::Integrity("authority sequence overflow".to_owned()))?;

            // P-0014: state-dependent enrollment preconditions resolve at the
            // locked snapshot; an authorized failure commits the decision and
            // a failure consequence without a governed effect.
            if let Some(problem_code) = enrollment_precondition_in_tx!(tx, plan, prepared) {
                let failure = delivery_failure_consequence(
                    &decision_for_hook,
                    &operation_for_hook,
                    problem_code,
                    decision_sequence,
                )
                .map_err(|error| PgError::Integrity(error.to_string()))?;
                let failure = bind_consequence_to_head(failure, decision_head)?;
                persist_decision_in_tx!(tx, &decision_for_hook);
                persist_remote_record_in_tx!(
                    tx,
                    RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                    decision_for_hook.workspace_id,
                    decision_sequence,
                    decision_for_hook.previous_authority_record_digest,
                    authority_signer
                );
                persist_consequence_in_tx!(tx, &failure, failure.authority_sequence);
                persist_remote_record_in_tx!(
                    tx,
                    RemoteAuthorityRecordV1::application_consequence(failure.clone()),
                    failure.workspace_id,
                    failure.authority_sequence,
                    failure.previous_authority_record_digest,
                    authority_signer
                );
                advance_authority_head_in_tx!(
                    tx,
                    &consequence_digest(&failure),
                    failure.authority_sequence
                );
                *built_for_hook.borrow_mut() = Some(failure);
                *problem_for_hook.borrow_mut() = Some(problem_code.to_owned());
                return Err(PgError::ApplicationFailure(problem_code.to_owned()));
            }

            let fact = match build_governed_fact(
                tx,
                plan,
                prepared,
                &input_for_hook,
                &actor_for_hook,
                &decision_for_hook,
                &operation_for_hook,
                fact_sequence,
                decision_record_digest,
            ) {
                Ok(fact) => fact,
                Err(ServerError::ApplicationProblem(problem_code)) => {
                    let failure = delivery_failure_consequence(
                        &decision_for_hook,
                        &operation_for_hook,
                        &problem_code,
                        decision_sequence,
                    )
                    .map_err(|error| PgError::Integrity(error.to_string()))?;
                    let failure = bind_consequence_to_head(failure, decision_head)?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &failure, failure.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(failure.clone()),
                        failure.workspace_id,
                        failure.authority_sequence,
                        failure.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&failure),
                        failure.authority_sequence
                    );
                    *built_for_hook.borrow_mut() = Some(failure);
                    *problem_for_hook.borrow_mut() = Some(problem_code.clone());
                    return Err(PgError::ApplicationFailure(problem_code));
                }
                Err(ServerError::Storage(error)) => return Err(error),
                Err(error) => return Err(PgError::Integrity(error.to_string())),
            };
            if authority_effect && fact.remote_record.is_none() {
                return Err(PgError::Integrity(
                    "effectful authority operation lacks its typed remote record".to_owned(),
                ));
            }
            let consequence_predecessor = if authority_effect {
                fact.effect_authority_head.ok_or_else(|| {
                    PgError::Integrity("authority effect lacks its causal head".to_owned())
                })?
            } else {
                decision_head
            };
            let consequence_sequence = consequence_predecessor
                .sequence
                .checked_add(1)
                .ok_or_else(|| PgError::Integrity("authority sequence overflow".to_owned()))?;
            let consequence = success_consequence(
                &decision_for_hook,
                &operation_for_hook,
                application_key_for_hook.clone(),
                key_kind,
                &fact,
                consequence_sequence,
                consequence_predecessor.record_digest,
            )
            .map_err(|error| PgError::Integrity(error.to_string()))?;
            let consequence = bind_consequence_to_head(consequence, consequence_predecessor)?;

            // The decision persists outside the savepoint so an authorized
            // application failure still retains the signed decision.
            persist_decision_in_tx!(tx, &decision_for_hook);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                decision_for_hook.workspace_id,
                decision_sequence,
                decision_for_hook.previous_authority_record_digest,
                authority_signer
            );
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                if effect_rule(&operation_for_hook) != EffectDigestRule::None {
                    persist_fact_in_tx!(sp, &fact, fact_sequence);
                    persist_auxiliaries_in_tx!(sp, &fact, fact_sequence);
                }
                if let Some(remote_record) = fact.remote_record.clone() {
                    persist_remote_record_in_tx!(
                        sp,
                        remote_record,
                        fact.workspace_id,
                        fact_sequence,
                        decision_record_digest,
                        authority_signer
                    );
                }
                persist_consequence_in_tx!(sp, &consequence, consequence.authority_sequence);
                persist_remote_record_in_tx!(
                    sp,
                    RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                    consequence.workspace_id,
                    consequence.authority_sequence,
                    consequence.previous_authority_record_digest,
                    authority_signer
                );
                persist_idempotency_in_tx!(
                    sp,
                    &candidate,
                    &application_key_for_hook,
                    key_kind,
                    &consequence,
                    &fact.result
                );
                advance_authority_head_in_tx!(
                    sp,
                    &consequence_digest(&consequence),
                    consequence.authority_sequence
                );
            }
            savepoint.release()?;
            *result_for_hook.borrow_mut() = Some(fact.result.clone());
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let commit = run_unit_of_work_with_retry_and_sequence_policy_commit(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        CausalSequencePolicy::AuthorityOnly,
    )
    .map_err(|error| {
        if matches!(actor_context, AuthenticatedActorContextV2::HumanAgent(_)) {
            map_agent_uow_error(error)
        } else {
            ServerError::Storage(error)
        }
    })?;

    match commit.outcome {
        UnitOfWorkOutcome::Committed => Ok(HumanOperationExecution {
            consequence: built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))?,
            result: built_result.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("operation result was not produced".to_owned())
            })?,
            transaction_sequence: commit.transaction_sequence,
        }),
        UnitOfWorkOutcome::ApplicationFailureCommitted => Err(ServerError::ApplicationProblem(
            application_problem.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("application Problem was not produced".to_owned())
            })?,
        )),
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => Err(
            ServerError::Internal("idempotency escaped the locked consequence hook".to_owned()),
        ),
    }
}

/// Commits a signed denial decision alone (no governed fact or consequence).
fn commit_denial(
    state: &AppState,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), ServerError> {
    commit_denial_with_policy(state, decision, CausalSequencePolicy::All)
}

fn commit_denial_with_policy(
    state: &AppState,
    decision: &RemoteAuthorizationDecisionV1,
    sequence_policy: CausalSequencePolicy,
) -> Result<(), ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let decision = decision.clone();
    let authority_signer = state.config.authority_signer.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(
                move |_tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    if head.authority_head == Some(expected_head) {
                        Ok(())
                    } else {
                        Err(PgError::Transaction(
                            "authority head advanced between evaluation and lock".to_owned(),
                        ))
                    }
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            persist_decision_in_tx!(tx, &decision);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision.clone()),
                decision.workspace_id,
                decision.authority_sequence,
                decision.previous_authority_record_digest,
                authority_signer
            );
            advance_authority_head_in_tx!(tx, &decision_digest(&decision), auth_seq);
            Ok(())
        }),
    };

    run_unit_of_work_with_retry_and_sequence_policy(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        sequence_policy,
    )
    .map_err(ServerError::Storage)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn commit_agent_denial_with_policy(
    state: &AppState,
    decision: &RemoteAuthorizationDecisionV1,
    actor_context: &AuthenticatedActorContextV2,
    normalized_input: &Value,
    agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
    sequence_policy: CausalSequencePolicy,
) -> Result<(), ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let decision = decision.clone();
    let actor = actor_context.clone();
    let input = normalized_input.clone();
    let attempt = agent_attempt.cloned();
    let authority_signer = state.config.authority_signer.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            let decision_for_authorization = decision.clone();
            Box::new(
                move |tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    revalidate_and_claim_agent_attempt(
                        tx,
                        head,
                        expected_head,
                        &actor,
                        &input,
                        &decision_for_authorization,
                        attempt.as_ref(),
                    )
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            persist_decision_in_tx!(tx, &decision);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision.clone()),
                decision.workspace_id,
                decision.authority_sequence,
                decision.previous_authority_record_digest,
                authority_signer
            );
            advance_authority_head_in_tx!(tx, &decision_digest(&decision), auth_seq);
            Ok(())
        }),
    };

    run_unit_of_work_with_retry_and_sequence_policy(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        sequence_policy,
    )
    .map_err(map_agent_uow_error)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn revalidate_and_claim_agent_attempt(
    transaction: &mut postgres::Transaction<'_>,
    head: &proof_pg::transaction::WorkspaceHeadSnapshot,
    expected_head: AuthorityHeadV1,
    actor_context: &AuthenticatedActorContextV2,
    normalized_input: &Value,
    decision: &RemoteAuthorizationDecisionV1,
    agent_attempt: Option<&crate::authz::PreparedAgentAttempt>,
) -> Result<(), PgError> {
    if head.authority_head != Some(expected_head) {
        return Err(PgError::Transaction(
            "authority head advanced between evaluation and lock".to_owned(),
        ));
    }
    crate::authz::revalidate_agent_authorization_in_transaction(
        transaction,
        actor_context,
        normalized_input,
        decision,
    )?;
    match (actor_context, agent_attempt) {
        (AuthenticatedActorContextV2::HumanAgent(_), Some(attempt)) => {
            crate::authz::persist_agent_attempt_in_transaction(
                transaction,
                attempt,
                actor_context,
                decision,
            )
        }
        (AuthenticatedActorContextV2::HumanAgent(_), None) => Err(PgError::Integrity(
            "Agent execution lacks its prepared authentication attempt".to_owned(),
        )),
        (AuthenticatedActorContextV2::Human(_), _) => Ok(()),
    }
}

fn map_agent_uow_error(error: PgError) -> ServerError {
    if matches!(&error, PgError::Idempotency(code) if code == "proof.auth.replay") {
        ServerError::Authorization("Agent presentation was already consumed".to_owned())
    } else {
        ServerError::Storage(error)
    }
}

/// Builds the row-governed fact for one fresh attempt.
#[allow(clippy::too_many_lines)]
fn build_governed_fact(
    transaction: &mut postgres::Transaction<'_>,
    plan: FactPlan,
    prepared: Option<&PreparedEnrollment>,
    input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    auth_seq: u64,
    previous_digest: ContentDigest,
) -> Result<GovernedFact, ServerError> {
    let effect_evaluated_head = AuthorityHeadV1 {
        sequence: auth_seq.checked_sub(1).ok_or_else(|| {
            ServerError::Internal("authority effect sequence cannot be zero".to_owned())
        })?,
        record_digest: previous_digest,
    };
    match plan {
        FactPlan::RoleAssignment => {
            let principal_id = required_input_str(input, "principal_id")?;
            let role = parse_role(required_input_str(input, "role")?)?;
            let assignment_id = assignment_id_from_input(input);
            let target_status = read_current_principal_status_in_tx(transaction, principal_id)?;
            if !target_status.enabled
                || transaction
                    .query_opt(
                        "SELECT 1 FROM facts WHERE fact_id = $1",
                        &[&format!("workspace_role_assignment/{assignment_id}")],
                    )
                    .map_err(|error| {
                        ServerError::Storage(proof_pg::transaction::transaction_error(&error))
                    })?
                    .is_some()
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let assignment = WorkspaceRoleAssignmentV1 {
                api_version: WorkspaceRoleAssignmentApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                assignment_id: assignment_id.clone(),
                principal_id: principal_id.to_owned(),
                role,
                assigned_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                assigned_by_actor_context_digest: decision.actor_context_digest,
                assigned_at: now_timestamp()?,
                evaluated_authority_head: effect_evaluated_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            let result = serde_json::to_value(&assignment)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let remote_record =
                RemoteAuthorityRecordV1::workspace_role_assignment(assignment.clone());
            let fact_digest = remote_record.digest();
            Ok(GovernedFact {
                fact_id: format!("workspace_role_assignment/{assignment_id}"),
                fact_kind: "workspace_role_assignment".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest: fact_digest,
                }),
                remote_record: Some(remote_record),
                result,
                auxiliary: Vec::new(),
            })
        }
        FactPlan::RoleRevocation => {
            let input: RoleRevocationInputV1 = strict_read_input(input)?;
            if input.reason.is_empty() || input.reason.len() > 256 {
                return Err(ServerError::Dispatch(
                    "role revocation reason exceeds its UTF-8 byte bound".to_owned(),
                ));
            }
            let (assignment, assignment_record_digest) =
                read_authority_fact_in_tx::<WorkspaceRoleAssignmentV1>(
                    transaction,
                    &format!("workspace_role_assignment/{}", input.assignment_id),
                    "workspace_role_assignment",
                )?;
            if assignment.workspace_id != decision.workspace_id
                || authority_fact_exists_for_target::<WorkspaceRoleRevocationV1>(
                    transaction,
                    "workspace_role_revocation",
                    |revocation| revocation.assignment_id == assignment.assignment_id,
                )?
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let revocation_id = uuid::Uuid::now_v7().to_string();
            let revocation = WorkspaceRoleRevocationV1 {
                api_version: WorkspaceRoleRevocationApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                revocation_id: revocation_id.clone(),
                assignment_id: assignment.assignment_id,
                assignment_record_digest,
                principal_id: assignment.principal_id,
                role: assignment.role,
                reason: input.reason,
                revoked_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                revoked_by_actor_context_digest: decision.actor_context_digest,
                revoked_at: now_timestamp()?,
                evaluated_authority_head: effect_evaluated_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            let result = serde_json::to_value(&revocation)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let remote_record =
                RemoteAuthorityRecordV1::workspace_role_revocation(revocation.clone());
            let fact_digest = remote_record.digest();
            Ok(GovernedFact {
                fact_id: format!("workspace_role_revocation/{revocation_id}"),
                fact_kind: "workspace_role_revocation".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest: fact_digest,
                }),
                remote_record: Some(remote_record),
                result,
                auxiliary: Vec::new(),
            })
        }
        FactPlan::AgentBindingIssue => {
            let Some(PreparedEnrollment::Agent(prepared)) = prepared else {
                return Err(ServerError::Internal(
                    "agent-binding.issue is missing its prepared enrollment closure".to_owned(),
                ));
            };
            let now = now_timestamp()?;
            let expires_at = Timestamp::from_unix_timestamp_nanos(
                now.unix_timestamp_nanos()
                    + i128::from(AGENT_BINDING_VALIDITY_SECS) * 1_000_000_000,
            )
            .map_err(|error| ServerError::Internal(error.to_string()))?;
            let workspace_id = parse_workspace_id(&decision.workspace_id)?;
            let binding = PrincipalBindingV1 {
                api_version: PrincipalBindingApiVersion::V1,
                authority_sequence: AuthoritySequence::new(auth_seq)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
                previous_authority_record_digest: Some(previous_digest),
                workspace_id,
                binding_id: prepared.challenge.binding_id,
                principal_id: prepared.challenge.principal_id,
                principal_type: AgentPrincipalType::Agent,
                authenticated_subject: LocalEd25519AuthenticatedSubjectV1::new(&prepared.key_id),
                algorithm: Ed25519Algorithm::Ed25519,
                public_key: prepared.public_key.clone(),
                key_usage: AuthenticatedCommandKeyUsage::AuthenticatedCommand,
                audience: AuthorityAudience::for_workspace(workspace_id),
                enrollment_challenge_digest: prepared.challenge_digest,
                enrollment_envelope_digest: prepared.envelope_digest,
                issued_by_principal_id: requesting_principal_id(actor_context).parse().map_err(
                    |_| ServerError::Authorization("invalid issuing Principal identity".to_owned()),
                )?,
                issued_at: now,
                not_before: now,
                expires_at,
                supersedes_binding_id: None,
            };
            binding
                .validate()
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let record_digest =
                RemoteAuthorityRecordV1::agent_binding_issue(binding.clone()).digest();
            let result = serde_json::to_value(&binding)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let consumption_body = canonical_bytes(&json!({
                "api_version": "proof.dev/enrollment-challenge-consumption/v1",
                "challenge_digest": prepared.challenge_digest.to_string(),
                "enrollment_envelope_digest": prepared.envelope_digest.to_string(),
                "binding_id": binding.binding_id.to_string(),
                "consumed_by_decision_digest": decision_digest(decision).to_string(),
                "consumed_at": now.to_string(),
            }))?;
            Ok(GovernedFact {
                fact_id: format!("agent_binding/{}", binding.binding_id),
                fact_kind: "agent_binding".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest: record_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest,
                }),
                remote_record: Some(RemoteAuthorityRecordV1::agent_binding_issue(
                    binding.clone(),
                )),
                auxiliary: vec![AuxiliaryFact::new(
                    prepared.consumption_fact_id.clone(),
                    "enrollment_challenge_consumption",
                    prepared.envelope_digest,
                    consumption_body,
                )],
                result,
            })
        }
        FactPlan::AgentBindingRevocation => {
            let input: BindingRevocationInputV1 = strict_read_input(input)?;
            let (binding, _) = read_authority_fact_in_tx::<PrincipalBindingV1>(
                transaction,
                &format!("agent_binding/{}", input.binding_id),
                "agent_binding",
            )?;
            if binding.workspace_id.to_string() != decision.workspace_id
                || authority_fact_exists_for_target::<PrincipalBindingRevocationV1>(
                    transaction,
                    "agent_binding_revocation",
                    |revocation| revocation.binding_id == binding.binding_id,
                )?
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let revocation = PrincipalBindingRevocationV1 {
                api_version: PrincipalBindingRevocationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(auth_seq)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
                previous_authority_record_digest: previous_digest,
                workspace_id: binding.workspace_id,
                revocation_id: uuid::Uuid::now_v7().to_string().parse().map_err(|_| {
                    ServerError::Internal("generated invalid revocation identity".to_owned())
                })?,
                binding_id: binding.binding_id,
                revoked_by_principal_id: parse_principal_id(requesting_principal_id(
                    actor_context,
                ))?,
                revoked_at: now_timestamp()?,
                reason: input.reason,
            };
            authority_governed_fact(
                format!("agent_binding_revocation/{}", revocation.revocation_id),
                "agent_binding_revocation",
                decision,
                auth_seq,
                RemoteAuthorityRecordV1::agent_binding_revocation(revocation.clone()),
                serde_json::to_value(revocation)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
            )
        }
        FactPlan::OidcBindingIssue => {
            let Some(PreparedEnrollment::Oidc(prepared)) = prepared else {
                return Err(ServerError::Internal(
                    "oidc-binding.issue is missing its prepared issuance material".to_owned(),
                ));
            };
            let public = OidcPrincipalBindingV1 {
                api_version: OidcPrincipalBindingApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                binding_id: prepared.binding_id.clone(),
                principal_id: prepared.principal_id.clone(),
                subject_commitment: prepared.commitment,
                oidc_issuer_configuration_digest: prepared.issuer_configuration_digest,
                issued_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                issued_at: now_timestamp()?,
                supersedes_binding_id: None,
                evaluated_authority_head: effect_evaluated_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            let binding_record_digest = public
                .binding_record_digest()
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let private = OidcPrincipalBindingPrivateV1 {
                api_version: OidcPrincipalBindingPrivateApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                binding_id: prepared.binding_id.clone(),
                principal_id: prepared.principal_id.clone(),
                subject: prepared.subject.clone(),
                subject_commitment: prepared.commitment,
                opening: OidcSubjectCommitmentOpeningV1 {
                    api_version: OidcSubjectCommitmentOpeningApiVersion::V1,
                    commitment: prepared.commitment,
                    input: OidcSubjectCommitmentInputV1 {
                        api_version: OidcSubjectCommitmentInputApiVersion::V1,
                        blind: prepared.blind_b64.clone(),
                        subject: prepared.subject.clone(),
                        workspace_id: decision.workspace_id.clone(),
                    },
                },
                oidc_issuer_configuration_digest: prepared.issuer_configuration_digest,
                binding_record_digest,
            };
            let result = serde_json::to_value(&public)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let aux_result = serde_json::to_value(&private)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let aux_body = canonical_bytes(&aux_result)?;
            let aux_digest = operation_effect_digest(&aux_result)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            Ok(GovernedFact {
                fact_id: format!("oidc_binding/{}", prepared.binding_id),
                fact_kind: OIDC_PUBLIC_BINDING_KIND.to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest: binding_record_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest: binding_record_digest,
                }),
                remote_record: Some(RemoteAuthorityRecordV1::oidc_binding_issue(public.clone())),
                auxiliary: vec![AuxiliaryFact::new(
                    format!("oidc_private_binding/{}", prepared.binding_id),
                    OIDC_PRIVATE_BINDING_KIND,
                    aux_digest,
                    aux_body,
                )],
                result,
            })
        }
        FactPlan::OidcBindingRevocation => {
            let input: OidcBindingRevocationInputV1 = strict_read_input(input)?;
            let (binding, binding_digest) = read_authority_fact_in_tx::<OidcPrincipalBindingV1>(
                transaction,
                &format!("oidc_binding/{}", input.binding_id),
                OIDC_PUBLIC_BINDING_KIND,
            )?;
            let protected_exists = transaction
                .query_opt(
                    "SELECT 1 FROM facts WHERE fact_id = $1 AND fact_kind = $2",
                    &[
                        &format!("oidc_private_binding/{}", input.binding_id),
                        &OIDC_PRIVATE_BINDING_KIND,
                    ],
                )
                .map_err(|error| {
                    ServerError::Storage(proof_pg::transaction::transaction_error(&error))
                })?
                .is_some();
            if !protected_exists
                || binding.workspace_id != decision.workspace_id
                || authority_fact_exists_for_target::<OidcPrincipalBindingRevocationV1>(
                    transaction,
                    "oidc_binding_revocation",
                    |revocation| revocation.binding_id == binding.binding_id,
                )?
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let revocation = OidcPrincipalBindingRevocationV1 {
                api_version: OidcPrincipalBindingRevocationApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                revocation_id: uuid::Uuid::now_v7().to_string(),
                binding_id: binding.binding_id,
                binding_record_digest: binding_digest,
                principal_id: binding.principal_id,
                subject_commitment: binding.subject_commitment,
                revoked_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                revoked_by_actor_context_digest: decision.actor_context_digest,
                revoked_at: now_timestamp()?,
                reason: input.reason,
                evaluated_authority_head: effect_evaluated_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            authority_governed_fact(
                format!("oidc_binding_revocation/{}", revocation.revocation_id),
                "oidc_binding_revocation",
                decision,
                auth_seq,
                RemoteAuthorityRecordV1::oidc_binding_revocation(revocation.clone()),
                serde_json::to_value(revocation)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
            )
        }
        FactPlan::PrincipalStatus => {
            let input: PrincipalStatusSetInputV2 = strict_read_input(input)?;
            let current = read_current_principal_status_in_tx(transaction, &input.principal_id)?;
            if input.expected_status != "enabled"
                || input.new_status != "disabled"
                || !current.enabled
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let status = RemotePrincipalStatusV2 {
                api_version: RemotePrincipalStatusApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                principal_id: input.principal_id,
                principal_type: current.principal_type,
                enabled: false,
                reason: input.reason,
                recorded_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                recorded_by_actor_context_digest: decision.actor_context_digest,
                recorded_at: now_timestamp()?,
                evaluated_authority_head: effect_evaluated_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            authority_governed_fact(
                format!(
                    "principal_status/{}/{}",
                    status.principal_id,
                    uuid::Uuid::now_v7()
                ),
                "principal_status",
                decision,
                auth_seq,
                RemoteAuthorityRecordV1::principal_status(status.clone()),
                serde_json::to_value(status)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
            )
        }
        FactPlan::DelegationIssue => {
            let input: DelegationIssueInputV2 = strict_read_input(input)?;
            if transaction
                .query_opt(
                    "SELECT 1 FROM facts WHERE fact_id = $1",
                    &[&format!("delegation/{}", input.delegation_id)],
                )
                .map_err(|error| {
                    ServerError::Storage(proof_pg::transaction::transaction_error(&error))
                })?
                .is_some()
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            validate_delegation_resource_intent_in_tx(transaction, &input, decision)?;
            let recipient_status =
                read_current_principal_status_in_tx(transaction, &input.operating_principal_id)?;
            if !recipient_status.enabled
                || recipient_status.principal_type != RemotePrincipalType::Agent
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.state.conflict".to_owned(),
                ));
            }
            let delegation = DelegationV2 {
                api_version: DelegationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(auth_seq)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
                previous_authority_record_digest: Some(previous_digest),
                delegation_id: input
                    .delegation_id
                    .parse()
                    .map_err(|_| ServerError::Dispatch("invalid Delegation identity".to_owned()))?,
                workspace_id: parse_workspace_id(&decision.workspace_id)?,
                delegation_profile: DirectAuthorityProfileV1::Direct,
                issuer_principal_id: parse_principal_id(requesting_principal_id(actor_context))?,
                recipient_principal_id: parse_principal_id(&input.operating_principal_id)?,
                actions: input.actions,
                scope: input.scope,
                constraints: input.constraints,
                not_before: input
                    .not_before
                    .parse()
                    .map_err(|_| ServerError::Dispatch("invalid not_before".to_owned()))?,
                expires_at: input
                    .expires_at
                    .parse()
                    .map_err(|_| ServerError::Dispatch("invalid expires_at".to_owned()))?,
                issued_at: now_timestamp()?,
            };
            delegation
                .validate()
                .map_err(|_| ServerError::ApplicationProblem("proof.state.conflict".to_owned()))?;
            authority_governed_fact(
                format!("delegation/{}", delegation.delegation_id),
                "delegation",
                decision,
                auth_seq,
                RemoteAuthorityRecordV1::delegation_issue(delegation.clone()),
                serde_json::to_value(delegation)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
            )
        }
        FactPlan::DelegationRevocation => {
            let input: DelegationRevokeInputV1 = strict_read_input(input)?;
            let (delegation, _) = read_authority_fact_in_tx::<DelegationV2>(
                transaction,
                &format!("delegation/{}", input.delegation_id),
                "delegation",
            )?;
            if authority_fact_exists_for_target::<DelegationRevocationV1>(
                transaction,
                "delegation_revocation",
                |revocation| revocation.delegation_id == delegation.delegation_id,
            )? {
                return Err(ServerError::ApplicationProblem(
                    "proof.authorization.delegation_revoked".to_owned(),
                ));
            }
            let requester = requesting_principal_id(actor_context);
            if delegation.issuer_principal_id.to_string() != requester
                && !principal_has_role_in_tx(transaction, requester, WorkspaceRole::AuthorityAdmin)?
            {
                return Err(ServerError::ApplicationProblem(
                    "proof.authorization.denied".to_owned(),
                ));
            }
            let revocation = DelegationRevocationV1 {
                api_version: DelegationRevocationApiVersion::V1,
                authority_sequence: AuthoritySequence::new(auth_seq)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
                previous_authority_record_digest: previous_digest,
                workspace_id: parse_workspace_id(&decision.workspace_id)?,
                revocation_id: uuid::Uuid::now_v7().to_string().parse().map_err(|_| {
                    ServerError::Internal("generated invalid revocation identity".to_owned())
                })?,
                delegation_id: delegation.delegation_id,
                revoked_by_principal_id: parse_principal_id(requester)?,
                revoked_at: now_timestamp()?,
                reason: input.reason,
            };
            authority_governed_fact(
                format!("delegation_revocation/{}", revocation.revocation_id),
                "delegation_revocation",
                decision,
                auth_seq,
                RemoteAuthorityRecordV1::delegation_revocation(revocation.clone()),
                serde_json::to_value(revocation)
                    .map_err(|error| ServerError::Internal(error.to_string()))?,
            )
        }
        FactPlan::Generic => {
            let has_effect = effect_rule(operation) != EffectDigestRule::None;
            let result = json!({
                "api_version": "proof.dev/governed-effect/v1",
                "operation": operation,
                "input": input,
                "decision_digest": decision_digest(decision).to_string(),
            });
            let fact_digest = operation_effect_digest(&result)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            Ok(GovernedFact {
                fact_id: format!(
                    "governed_effect/{}/{}",
                    operation.name,
                    uuid::Uuid::now_v7()
                ),
                fact_kind: "governed_effect".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest,
                body,
                effect_authority_head: if has_effect {
                    Some(AuthorityHeadV1 {
                        sequence: auth_seq,
                        record_digest: fact_digest,
                    })
                } else {
                    None
                },
                remote_record: None,
                result,
                auxiliary: Vec::new(),
            })
        }
    }
}

fn authority_governed_fact(
    fact_id: String,
    fact_kind: &str,
    decision: &RemoteAuthorizationDecisionV1,
    auth_seq: u64,
    record: RemoteAuthorityRecordV1,
    result: Value,
) -> Result<GovernedFact, ServerError> {
    let fact_digest = record.digest();
    let body = canonical_bytes(&result)?;
    Ok(GovernedFact {
        fact_id,
        fact_kind: fact_kind.to_owned(),
        workspace_id: decision.workspace_id.clone(),
        fact_digest,
        body,
        effect_authority_head: Some(AuthorityHeadV1 {
            sequence: auth_seq,
            record_digest: fact_digest,
        }),
        remote_record: Some(record),
        result,
        auxiliary: Vec::new(),
    })
}

fn read_authority_fact_in_tx<T: serde::de::DeserializeOwned>(
    transaction: &mut postgres::Transaction<'_>,
    fact_id: &str,
    expected_kind: &str,
) -> Result<(T, ContentDigest), ServerError> {
    let row = transaction
        .query_opt(
            "SELECT fact_kind, fact_digest, body FROM facts WHERE fact_id = $1",
            &[&fact_id],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?
        .ok_or_else(|| ServerError::ApplicationProblem("proof.resource.not_found".to_owned()))?;
    let kind: String = row.get(0);
    if kind != expected_kind {
        return Err(ServerError::Internal(format!(
            "authority fact `{fact_id}` has kind `{kind}`, expected `{expected_kind}`"
        )));
    }
    let digest = row.get::<_, String>(1).parse().map_err(|error| {
        ServerError::Internal(format!("invalid authority fact digest: {error}"))
    })?;
    let body: Vec<u8> = row.get(2);
    let value = serde_json::from_slice(&body).map_err(|error| {
        ServerError::Internal(format!("invalid `{expected_kind}` authority fact: {error}"))
    })?;
    Ok((value, digest))
}

fn authority_fact_exists_for_target<T: serde::de::DeserializeOwned>(
    transaction: &mut postgres::Transaction<'_>,
    fact_kind: &str,
    matches_target: impl Fn(&T) -> bool,
) -> Result<bool, ServerError> {
    let rows = transaction
        .query(
            "SELECT body FROM facts WHERE fact_kind = $1 ORDER BY authority_sequence DESC",
            &[&fact_kind],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let value = serde_json::from_slice::<T>(&body).map_err(|error| {
            ServerError::Internal(format!("invalid `{fact_kind}` authority fact: {error}"))
        })?;
        if matches_target(&value) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_current_principal_status_in_tx(
    transaction: &mut postgres::Transaction<'_>,
    principal_id: &str,
) -> Result<RemotePrincipalStatusV2, ServerError> {
    let rows = transaction
        .query(
            "SELECT body FROM facts
             WHERE fact_kind = 'principal_status'
             ORDER BY authority_sequence DESC",
            &[],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?;
    for row in rows {
        let body: Vec<u8> = row.get(0);
        let status = serde_json::from_slice::<RemotePrincipalStatusV2>(&body).map_err(|error| {
            ServerError::Internal(format!("invalid Principal status authority fact: {error}"))
        })?;
        if status.principal_id == principal_id {
            return Ok(status);
        }
    }
    Err(ServerError::ApplicationProblem(
        "proof.resource.not_found".to_owned(),
    ))
}

fn principal_has_role_in_tx(
    transaction: &mut postgres::Transaction<'_>,
    principal_id: &str,
    expected_role: WorkspaceRole,
) -> Result<bool, ServerError> {
    let revocation_rows = transaction
        .query(
            "SELECT body FROM facts WHERE fact_kind = 'workspace_role_revocation'",
            &[],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?;
    let mut revoked = BTreeSet::new();
    for row in revocation_rows {
        let body: Vec<u8> = row.get(0);
        let revocation =
            serde_json::from_slice::<WorkspaceRoleRevocationV1>(&body).map_err(|error| {
                ServerError::Internal(format!("invalid role revocation fact: {error}"))
            })?;
        revoked.insert(revocation.assignment_id);
    }
    let assignment_rows = transaction
        .query(
            "SELECT body FROM facts WHERE fact_kind = 'workspace_role_assignment'",
            &[],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?;
    for row in assignment_rows {
        let body: Vec<u8> = row.get(0);
        let assignment =
            serde_json::from_slice::<WorkspaceRoleAssignmentV1>(&body).map_err(|error| {
                ServerError::Internal(format!("invalid role assignment fact: {error}"))
            })?;
        if assignment.principal_id == principal_id
            && assignment.role == expected_role
            && !revoked.contains(&assignment.assignment_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_delegation_resource_intent_in_tx(
    transaction: &mut postgres::Transaction<'_>,
    input: &DelegationIssueInputV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), ServerError> {
    let row = transaction
        .query_opt(
            "SELECT fact_digest, body FROM facts WHERE fact_id = $1 AND fact_kind = 'resource_intent'",
            &[&format!("resource_intent/{}", input.resource_intent_id)],
        )
        .map_err(|error| ServerError::Storage(proof_pg::transaction::transaction_error(&error)))?
        .ok_or_else(|| ServerError::ApplicationProblem("proof.resource.not_found".to_owned()))?;
    let digest: ContentDigest = row.get::<_, String>(0).parse().map_err(|error| {
        ServerError::Internal(format!("invalid resource-intent digest: {error}"))
    })?;
    let body: Vec<u8> = row.get(1);
    let intent: Value = serde_json::from_slice(&body)
        .map_err(|error| ServerError::Internal(format!("invalid resource intent: {error}")))?;
    let expected_digest = input.resource_intent_digest.parse().map_err(|error| {
        ServerError::Dispatch(format!("invalid resource-intent digest: {error}"))
    })?;
    if digest != expected_digest
        || intent.get("workspace_id").and_then(Value::as_str)
            != Some(decision.workspace_id.as_str())
        || intent.get("issued_by_principal_id").and_then(Value::as_str)
            != Some(decision.requesting_principal_id.as_str())
    {
        return Err(ServerError::ApplicationProblem(
            "proof.state.conflict".to_owned(),
        ));
    }

    let environment = intent
        .get("environment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Internal("resource intent lacks environment_id".to_owned()))?;
    let mut object_ids = BTreeSet::new();
    let mut schema_ids = BTreeSet::new();
    let mut locales = BTreeSet::new();
    for target in intent
        .get("targets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(value) = target.get("object_id").and_then(Value::as_str) {
            object_ids.insert(value.to_owned());
        }
        if let Some(value) = target.get("schema_id").and_then(Value::as_str) {
            schema_ids.insert(value.to_owned());
        }
        if let Some(value) = target.get("locale").and_then(Value::as_str) {
            locales.insert(value.to_owned());
        }
    }
    for creation in intent
        .get("creations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(value) = creation.get("object_id").and_then(Value::as_str) {
            object_ids.insert(value.to_owned());
        }
        if let Some(value) = creation.get("schema_id").and_then(Value::as_str) {
            schema_ids.insert(value.to_owned());
        }
        for value in creation
            .get("locales")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            locales.insert(value.to_owned());
        }
    }
    let covered = input
        .scope
        .environment_ids
        .as_slice()
        .iter()
        .all(|value| value.to_string() == environment)
        && input
            .scope
            .object_ids
            .as_slice()
            .iter()
            .all(|value| object_ids.contains(&value.to_string()))
        && input
            .scope
            .schema_ids
            .as_slice()
            .iter()
            .all(|value| schema_ids.contains(&value.to_string()))
        && input
            .scope
            .locales
            .as_slice()
            .iter()
            .all(|value| locales.contains(&value.to_string()));
    if covered {
        Ok(())
    } else {
        Err(ServerError::ApplicationProblem(
            "proof.authorization.scope_exceeded".to_owned(),
        ))
    }
}

fn assignment_id_from_input(input: &Value) -> String {
    input
        .get("assignment_id")
        .and_then(Value::as_str)
        .map_or_else(|| uuid::Uuid::now_v7().to_string(), str::to_owned)
}

/// Builds a fresh success consequence bound to one governed fact.
fn success_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    application_key: Option<String>,
    key_kind: ApplicationKeyKind,
    fact: &GovernedFact,
    auth_seq: u64,
    previous_digest: ContentDigest,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let result_digest = operation_effect_digest(&fact.result)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let application_effect_digest = if effect_rule(operation) == EffectDigestRule::None {
        None
    } else {
        Some(fact.fact_digest)
    };
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::Success,
        key_kind,
        application_key,
        Some(result_digest),
        None,
        application_effect_digest,
        fact.effect_authority_head,
        None,
        auth_seq,
        previous_digest,
    ))
}

fn replay_consequence(
    decision: RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    prior_result_digest: Option<ContentDigest>,
    key_kind: ApplicationKeyKind,
    application_key: Option<String>,
) -> RemoteApplicationConsequenceV1 {
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotentReplay,
        key_kind,
        application_key,
        prior_result_digest,
        prior_result_digest,
        None,
        None,
        None,
        decision.authority_sequence,
        decision.previous_authority_record_digest,
    )
}

fn conflict_consequence(
    decision: RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    prior_result_digest: Option<ContentDigest>,
    key_kind: ApplicationKeyKind,
    application_key: Option<String>,
) -> RemoteApplicationConsequenceV1 {
    let problem_digest =
        application_problem_digest_preimage("proof.idempotency.key_reused", operation)
            .expect("idempotency conflict is a frozen operation Problem");
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotencyConflict,
        key_kind,
        application_key,
        Some(problem_digest),
        prior_result_digest,
        None,
        None,
        Some("proof.idempotency.key_reused".to_owned()),
        decision.authority_sequence,
        decision.previous_authority_record_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    outcome: ApplicationConsequenceOutcome,
    key_kind: ApplicationKeyKind,
    application_key: Option<String>,
    result_digest: Option<ContentDigest>,
    prior_result_digest: Option<ContentDigest>,
    application_effect_digest: Option<ContentDigest>,
    application_effect_authority_head: Option<AuthorityHeadV1>,
    problem_code: Option<String>,
    authority_sequence: u64,
    previous_authority_record_digest: ContentDigest,
) -> RemoteApplicationConsequenceV1 {
    let mut consequence = RemoteApplicationConsequenceV1 {
        api_version: RemoteApplicationConsequenceApiVersion::V1,
        workspace_id: decision.workspace_id.clone(),
        consequence_id: uuid::Uuid::now_v7().to_string(),
        decision_id: decision.decision_id.clone(),
        decision_digest: decision_digest(decision),
        public_input_projection_digest: decision.public_input_projection_digest,
        operation: operation.clone(),
        operation_registry_sha256: decision.operation_registry_sha256.clone(),
        outcome,
        application_key_kind: key_kind,
        application_key,
        result_digest,
        prior_result_digest,
        application_effect_digest,
        application_effect_authority_head,
        problem_code,
        recorded_at: now_timestamp().expect("the system clock always produces a timestamp"),
        evaluated_authority_head: decision.evaluated_authority_head,
        authority_sequence,
        previous_authority_record_digest,
        authority_key_id: decision.authority_key_id.clone(),
    };
    consequence.copy_decision_binding(decision);
    consequence
}

fn apply_prepared_consequence(
    mut consequence: RemoteApplicationConsequenceV1,
    prepared: &PreparedConsequence,
) -> RemoteApplicationConsequenceV1 {
    consequence
        .consequence_id
        .clone_from(&prepared.consequence_id);
    consequence.recorded_at = prepared.recorded_at;
    consequence
}

fn bind_consequence_to_head(
    mut consequence: RemoteApplicationConsequenceV1,
    predecessor: AuthorityHeadV1,
) -> Result<RemoteApplicationConsequenceV1, PgError> {
    consequence.authority_sequence = predecessor
        .sequence
        .checked_add(1)
        .ok_or_else(|| PgError::Integrity("authority sequence overflow".to_owned()))?;
    consequence.previous_authority_record_digest = predecessor.record_digest;
    consequence.evaluated_authority_head = predecessor;
    Ok(consequence)
}

fn bind_native_authority_chain(
    mut consequence: RemoteApplicationConsequenceV1,
    decision: &RemoteAuthorizationDecisionV1,
    decision_sequence: u64,
    portable: bool,
) -> Result<RemoteApplicationConsequenceV1, PgError> {
    if portable {
        if decision.authority_sequence != decision_sequence {
            return Err(PgError::Integrity(
                "native decision sequence disagrees with the locked allocation".to_owned(),
            ));
        }
        let decision_digest = decision_digest(decision);
        consequence.authority_sequence = decision_sequence
            .checked_add(1)
            .ok_or_else(|| PgError::Integrity("authority sequence overflow".to_owned()))?;
        consequence.previous_authority_record_digest = decision_digest;
        consequence.evaluated_authority_head = AuthorityHeadV1 {
            sequence: decision_sequence,
            record_digest: decision_digest,
        };
    }
    Ok(consequence)
}

// ---------------------------------------------------------------------------
// Pure helpers (no transaction parameter).
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

fn decision_digest(decision: &RemoteAuthorizationDecisionV1) -> ContentDigest {
    RemoteAuthorityRecordV1::authorization_decision(decision.clone()).digest()
}

fn consequence_digest(consequence: &RemoteApplicationConsequenceV1) -> ContentDigest {
    RemoteAuthorityRecordV1::application_consequence(consequence.clone()).digest()
}

fn effect_rule(operation: &RemoteOperationV1) -> EffectDigestRule {
    HumanOperationRegistryV1
        .lookup(&operation.name, &operation.version)
        .map(|row| row.effect_digest_rule)
        .or_else(|| {
            AgentOperationProjectionV1
                .lookup(&operation.name, &operation.version)
                .map(|row| row.effect_digest_rule)
        })
        .unwrap_or(EffectDigestRule::None)
}

fn idempotency_kind(operation: &RemoteOperationV1) -> ApplicationKeyKind {
    if let Some(row) = AgentOperationProjectionV1.lookup(&operation.name, &operation.version) {
        return row.application_key_kind;
    }
    match HumanOperationRegistryV1
        .lookup(&operation.name, &operation.version)
        .map(|row| row.idempotency.as_str())
    {
        Some("required-uuidv7") => ApplicationKeyKind::RequiredUuidV7,
        Some("none") | None => ApplicationKeyKind::None,
        Some(_) => ApplicationKeyKind::DerivedChangeset,
    }
}

fn key_kind_label(kind: ApplicationKeyKind) -> &'static str {
    match kind {
        ApplicationKeyKind::RequiredUuidV7 => "required-uuidv7",
        ApplicationKeyKind::None => "none",
        ApplicationKeyKind::DerivedChangeset
        | ApplicationKeyKind::DerivedProposalPolicyValidator => "derived",
    }
}

fn derived_changeset_application_key(
    workspace_id: proof_domain::WorkspaceId,
    input: &Value,
) -> Result<String, PgError> {
    let changeset_id = input
        .get("changeset_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Integrity("derived ChangeSet key input lacks changeset_id".to_owned())
        })?;
    let value = canonicalize(&json!({
        "api_version": "proof.dev/application-idempotency-key/v1",
        "changeset_id": changeset_id,
        "operation": "changeset.submit/v2",
        "workspace_id": workspace_id.to_string(),
    }))
    .map_err(|error| PgError::Integrity(error.to_string()))?;
    Ok(digest(ArtifactKind::OperationEffectV1, &value).to_string())
}

fn actor_principals(context: &AuthenticatedActorContextV2) -> (String, String, Option<String>) {
    match context {
        AuthenticatedActorContextV2::Human(human) => (
            human.requesting_principal_id.clone(),
            human.requesting_principal_id.clone(),
            None,
        ),
        AuthenticatedActorContextV2::HumanAgent(agent) => (
            agent.requesting_principal_id.clone(),
            agent.operating_principal_id.clone(),
            Some(agent.delegation_id.clone()),
        ),
    }
}

fn requesting_principal_id(context: &AuthenticatedActorContextV2) -> &str {
    match context {
        AuthenticatedActorContextV2::Human(human) => &human.requesting_principal_id,
        AuthenticatedActorContextV2::HumanAgent(agent) => &agent.requesting_principal_id,
    }
}

fn required_input_str<'a>(input: &'a Value, field: &str) -> Result<&'a str, ServerError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Dispatch(format!("normalized input is missing `{field}`")))
}

fn parse_role(value: &str) -> Result<WorkspaceRole, ServerError> {
    serde_json::from_value(Value::String(value.to_owned()))
        .map_err(|_| ServerError::Dispatch(format!("invalid Workspace role `{value}`")))
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

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, ServerError> {
    canonicalize(value)
        .map(|canonical| canonical.as_bytes().to_vec())
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn canonical_bytes_pg(value: &Value) -> Result<Vec<u8>, PgError> {
    canonicalize(value)
        .map(|canonical| canonical.as_bytes().to_vec())
        .map_err(|error| PgError::Integrity(error.to_string()))
}

fn release_delivery_fields(
    result: &Value,
    effect_digest: ContentDigest,
    workspace_id: proof_domain::WorkspaceId,
) -> Result<ReleaseDeliveryFields, PgError> {
    let release_id = result
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Integrity("Release result lacks release_id".to_owned()))?
        .to_owned();
    release_id
        .parse::<proof_application::ReleaseId>()
        .map_err(|_| PgError::Integrity("Release result has an invalid release_id".to_owned()))?;
    let release_digest: ContentDigest = result
        .get("release_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Integrity("Release result lacks release_digest".to_owned()))?
        .parse()
        .map_err(|error| PgError::Integrity(format!("invalid Release digest: {error}")))?;
    if release_digest != effect_digest {
        return Err(PgError::Integrity(
            "Release result digest disagrees with its committed effect".to_owned(),
        ));
    }

    let manifest = result
        .get("release_manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| PgError::Integrity("Release result lacks release_manifest".to_owned()))?;
    if manifest.get("release_id").and_then(Value::as_str) != Some(release_id.as_str())
        || manifest.get("workspace_id").and_then(Value::as_str)
            != Some(workspace_id.to_string().as_str())
    {
        return Err(PgError::Integrity(
            "Release manifest identity disagrees with its result".to_owned(),
        ));
    }
    let environment_id = manifest
        .get("environment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Integrity("Release manifest lacks environment_id".to_owned()))?
        .to_owned();
    environment_id
        .parse::<proof_application::EnvironmentId>()
        .map_err(|_| {
            PgError::Integrity("Release manifest has an invalid environment_id".to_owned())
        })?;
    let environment_config_version = manifest
        .get("environment_config_version")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            PgError::Integrity("Release manifest lacks environment_config_version".to_owned())
        })?;
    let environment_config_digest = manifest
        .get("environment_config_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PgError::Integrity("Release manifest lacks environment_config_digest".to_owned())
        })?
        .parse()
        .map_err(|error| {
            PgError::Integrity(format!("invalid Release Environment digest: {error}"))
        })?;
    let release_sequence = manifest
        .get("release_sequence")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| PgError::Integrity("Release manifest lacks release_sequence".to_owned()))?;
    let edition_digest = manifest
        .get("edition")
        .and_then(Value::as_object)
        .and_then(|edition| edition.get("digest"))
        .and_then(Value::as_str)
        .ok_or_else(|| PgError::Integrity("Release manifest lacks Edition digest".to_owned()))?
        .parse()
        .map_err(|error| PgError::Integrity(format!("invalid Edition digest: {error}")))?;

    Ok(ReleaseDeliveryFields {
        release_id,
        release_digest,
        edition_digest,
        environment_id,
        environment_config_version,
        environment_config_digest,
        release_sequence,
    })
}

fn release_delivery_event(
    prepared: &PreparedReleaseDelivery,
    fields: &ReleaseDeliveryFields,
    destination: &ReleaseDeliveryDestination,
    workspace_id: proof_domain::WorkspaceId,
    workspace_transaction_sequence: u64,
) -> OutboxEnqueueV1 {
    OutboxEnqueueV1 {
        event_id: prepared.event_id.clone(),
        workspace_id,
        workspace_transaction_sequence,
        ordinal: 0,
        event_type: "preview.release".to_owned(),
        event_version: "v1".to_owned(),
        ordering_key: format!("preview:{workspace_id}:{}", fields.environment_id),
        stream_sequence: fields.release_sequence,
        effect_digest: fields.release_digest,
        payload_digest: Some(fields.edition_digest),
        artifact_reference: Some(ArtifactKeyV1 {
            kind: ArtifactKind::ReleaseV2,
            blake3_digest: fields.release_digest,
        }),
        destination_configuration_version: destination.version,
        destination_configuration_digest: destination.digest,
        correlation_id: prepared.correlation_id,
        causation_id: None,
        committed_creation_time: prepared.created_at,
    }
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

// ---------------------------------------------------------------------------
// P-0012 delivery and preview executors.
// ---------------------------------------------------------------------------

/// The exact `Cache-Control` value for private preview responses (contract
/// §"Preview delivery").
const PREVIEW_CACHE_CONTROL: &str = "private, no-store";

/// The stable replay reason committed by `delivery.replay/v1` (contract
/// §"Immutable artifacts and delivery").
const REPLAY_REASON: &str = "dead-letter-replay";

/// Missing-delivery problem code (contract §"Human and control operation
/// registry").
const PROBLEM_RESOURCE_NOT_FOUND: &str = "proof.resource.not_found";

/// Stale-generation or wrong-state problem code (contract §"Human and control
/// operation registry").
const PROBLEM_STATE_CONFLICT: &str = "proof.state.conflict";

/// The wire spelling of the `dead-letter` delivery status.
const DELIVERY_STATUS_DEAD_LETTER: &str = "dead-letter";

/// One mutable delivery-state row read at the locked transaction snapshot.
struct DeliveryStateRow {
    status: String,
    attempts_in_generation: i64,
    next_attempt_at: Option<SystemTime>,
    receipt_digest: Option<String>,
}

// ---------------------------------------------------------------------------
// Delivery persistence macros. Like the base transaction macros above,
// `postgres::Transaction` cannot be named in this crate, so the SQL bodies
// expand inline at each closure where the transaction type is inferred.
// ---------------------------------------------------------------------------

macro_rules! read_transaction_sequence_in_tx {
    ($tx:expr) => {{
        let value: i64 = $tx
            .query_one(
                "SELECT transaction_sequence FROM workspace_write_head WHERE singleton = 1",
                &[],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?
            .get(0);
        u64::try_from(value)
            .map_err(|_| PgError::Integrity("transaction sequence is negative".to_owned()))
    }};
}

macro_rules! read_delivery_state_in_tx {
    ($tx:expr, $event_id:expr, $delivery_id:expr, $generation:expr) => {{
        let generation = i64::try_from($generation).map_err(|_| {
            PgError::Integrity("delivery generation exceeds BIGINT range".to_owned())
        })?;
        let row = $tx
            .query_opt(
                "SELECT status, attempts_in_generation, next_attempt_at, receipt_digest
                 FROM delivery_state
                 WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
                &[&$event_id, &$delivery_id, &generation],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
        row.map(|row| DeliveryStateRow {
            status: row.get(0),
            attempts_in_generation: row.get(1),
            next_attempt_at: row.get(2),
            receipt_digest: row.get(3),
        })
    }};
}

macro_rules! read_latest_generation_in_tx {
    ($tx:expr, $event_id:expr, $delivery_id:expr) => {{
        let row = $tx
            .query_opt(
                "SELECT MAX(generation) FROM delivery_state WHERE event_id = $1 AND delivery_id = $2",
                &[&$event_id, &$delivery_id],
            )
            .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
        row.and_then(|row| row.get::<_, Option<i64>>(0))
    }};
}

macro_rules! persist_delivery_fact_in_tx {
    ($tx:expr, $fact:expr, $fact_id:expr) => {{
        let value = serde_json::to_value(&$fact).map_err(|e| PgError::Integrity(e.to_string()))?;
        let body = canonical_bytes_pg(&value)?;
        let digest = $fact
            .digest()
            .map_err(|error| PgError::Integrity(error.to_string()))?;
        let generation = i64::try_from($fact.from_generation).map_err(|_| {
            PgError::Integrity("delivery generation exceeds BIGINT range".to_owned())
        })?;
        let recorded_at = timestamp_to_system_time($fact.recorded_at);
        $tx.execute(
            "INSERT INTO delivery_management_facts (
                 fact_id, workspace_id, event_id, delivery_id, generation, action,
                 fact_digest, payload, recorded_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &$fact_id,
                &$fact.workspace_id,
                &$fact.event_id,
                &$fact.delivery_id,
                &generation,
                &delivery_action_label($fact.action),
                &digest.to_string(),
                &body,
                &recorded_at,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! insert_replayed_generation_in_tx {
    ($tx:expr, $event_id:expr, $delivery_id:expr, $generation:expr) => {{
        let generation = i64::try_from($generation).map_err(|_| {
            PgError::Integrity("delivery generation exceeds BIGINT range".to_owned())
        })?;
        $tx.execute(
            "INSERT INTO delivery_state (
                 event_id, delivery_id, generation, status, next_attempt_at,
                 attempts_in_generation, lease_token_hash, lease_expires_at, receipt_digest,
                 generation_started_at, committed_at
             ) VALUES ($1, $2, $3, 'pending', now(), 0, NULL, NULL, NULL, now(), now())",
            &[&$event_id, &$delivery_id, &generation],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! abandon_delivery_in_tx {
    ($tx:expr, $event_id:expr, $delivery_id:expr, $generation:expr) => {{
        let generation = i64::try_from($generation).map_err(|_| {
            PgError::Integrity("delivery generation exceeds BIGINT range".to_owned())
        })?;
        $tx.execute(
            "UPDATE delivery_state
             SET status = 'abandoned',
                 next_attempt_at = NULL,
                 lease_token_hash = NULL,
                 lease_expires_at = NULL,
                 receipt_digest = NULL
             WHERE event_id = $1 AND delivery_id = $2 AND generation = $3",
            &[&$event_id, &$delivery_id, &generation],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! commit_delivery_failure_in_tx {
    (
        $tx:expr,
        $decision:expr,
        $operation:expr,
        $problem_code:expr,
        $auth_seq:expr,
        $built:expr,
        $problem:expr,
        $application_key:expr,
        $key_kind:expr,
        $portable:expr,
        $authority_signer:expr
    ) => {{
        let failure = native_failure_consequence(
            $decision,
            $operation,
            $problem_code,
            $application_key.clone(),
            $key_kind,
            $auth_seq,
        )
        .map_err(|error| PgError::Integrity(error.to_string()))?;
        let failure = bind_native_authority_chain(failure, $decision, $auth_seq, $portable)?;
        persist_decision_in_tx!($tx, $decision);
        persist_remote_record_in_tx!(
            $tx,
            RemoteAuthorityRecordV1::authorization_decision($decision.clone()),
            $decision.workspace_id,
            $decision.authority_sequence,
            $decision.previous_authority_record_digest,
            $authority_signer
        );
        persist_consequence_in_tx!($tx, &failure, failure.authority_sequence);
        persist_remote_record_in_tx!(
            $tx,
            RemoteAuthorityRecordV1::application_consequence(failure.clone()),
            failure.workspace_id,
            failure.authority_sequence,
            failure.previous_authority_record_digest,
            $authority_signer
        );
        advance_authority_head_in_tx!(
            $tx,
            &consequence_digest(&failure),
            failure.authority_sequence
        );
        *$built.borrow_mut() = Some(failure);
        *$problem.borrow_mut() = Some($problem_code.to_owned());
        return Err(PgError::ApplicationFailure($problem_code.to_owned()));
    }};
}

// ---------------------------------------------------------------------------
// Delivery executor helpers.
// ---------------------------------------------------------------------------

fn delivery_action_label(action: DeliveryManagementAction) -> &'static str {
    match action {
        DeliveryManagementAction::Replay => "replay",
        DeliveryManagementAction::Abandon => "abandon",
    }
}

fn required_input_u64(input: &Value, field: &str) -> Result<u64, ServerError> {
    input
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ServerError::Dispatch(format!("normalized input is missing `{field}`")))
}

fn timestamp_to_system_time(timestamp: Timestamp) -> SystemTime {
    let nanos = timestamp.unix_timestamp_nanos();
    if nanos >= 0 {
        let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
        SystemTime::UNIX_EPOCH + std::time::Duration::from_nanos(nanos)
    } else {
        let nanos = u64::try_from(nanos.unsigned_abs()).unwrap_or(u64::MAX);
        SystemTime::UNIX_EPOCH - std::time::Duration::from_nanos(nanos)
    }
}

fn system_time_to_timestamp(value: SystemTime) -> Result<Timestamp, ServerError> {
    let duration = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    let nanos = i128::try_from(duration.as_nanos()).map_err(|_| {
        ServerError::Internal("system clock exceeds the timestamp range".to_owned())
    })?;
    Timestamp::from_unix_timestamp_nanos(nanos)
        .map_err(|error| ServerError::Internal(error.to_string()))
}

fn build_delivery_fact(
    decision: &RemoteAuthorizationDecisionV1,
    action: DeliveryManagementAction,
    event_id: &str,
    delivery_id: &str,
    generation: u64,
    idempotency_key: &str,
    reason: &str,
    transaction_sequence: u64,
    recorded_at: Timestamp,
) -> DeliveryManagementFactV1 {
    match action {
        DeliveryManagementAction::Replay => DeliveryManagementFactV1::replay(
            decision.workspace_id.clone(),
            event_id,
            delivery_id,
            generation,
            idempotency_key,
            decision.actor_context_digest,
            transaction_sequence,
            recorded_at,
        ),
        DeliveryManagementAction::Abandon => DeliveryManagementFactV1::abandon(
            decision.workspace_id.clone(),
            event_id,
            delivery_id,
            generation,
            idempotency_key,
            reason,
            decision.actor_context_digest,
            transaction_sequence,
            recorded_at,
        ),
    }
}

fn delivery_result(
    action: DeliveryManagementAction,
    event_id: &str,
    delivery_id: &str,
    generation: u64,
    fact_digest: ContentDigest,
) -> Value {
    match action {
        DeliveryManagementAction::Replay => json!({
            "api_version": "proof.dev/delivery-replay-result/v1",
            "event_id": event_id,
            "delivery_id": delivery_id,
            "from_generation": generation,
            "to_generation": generation + 1,
            "status": "pending",
            "management_fact_digest": fact_digest.to_string(),
        }),
        DeliveryManagementAction::Abandon => json!({
            "api_version": "proof.dev/delivery-abandon-result/v1",
            "event_id": event_id,
            "delivery_id": delivery_id,
            "generation": generation,
            "status": "abandoned",
            "management_fact_digest": fact_digest.to_string(),
        }),
    }
}

fn delivery_success_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    result: &Value,
    application_key: Option<String>,
    key_kind: ApplicationKeyKind,
    fact_digest: ContentDigest,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let result_digest = operation_effect_digest(result)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::Success,
        key_kind,
        application_key,
        Some(result_digest),
        None,
        Some(fact_digest),
        None,
        None,
        auth_seq,
        decision_digest(decision),
    ))
}

fn delivery_failure_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    problem_code: &str,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let problem_digest = application_problem_digest_preimage(problem_code, operation)
        .map_err(|error| ServerError::Dispatch(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::ApplicationFailure,
        ApplicationKeyKind::None,
        None,
        Some(problem_digest),
        None,
        None,
        None,
        Some(problem_code.to_owned()),
        auth_seq,
        decision_digest(decision),
    ))
}

fn native_failure_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    problem_code: &str,
    application_key: Option<String>,
    key_kind: ApplicationKeyKind,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let problem_digest = application_problem_digest_preimage(problem_code, operation)
        .map_err(|error| ServerError::Dispatch(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::ApplicationFailure,
        key_kind,
        application_key,
        Some(problem_digest),
        None,
        None,
        None,
        Some(problem_code.to_owned()),
        auth_seq,
        decision_digest(decision),
    ))
}

/// Runs one delivery-management mutation (`replay` or `abandon`) through the
/// P-0010 unit of work.
///
/// The consequence hook resolves the exact locked generation, rejects a
/// missing, stale, or non-`dead-letter` row as an application failure, and on
/// success appends one [`DeliveryManagementFactV1`], binds its digest as
/// `application_effect_digest`, and mutates `delivery_state` (replay inserts
/// the successor generation as `pending`; abandonment updates the row to
/// terminal `abandoned`).
#[allow(clippy::too_many_lines)]
fn execute_delivery_management(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
    action: DeliveryManagementAction,
) -> Result<HumanOperationExecution, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial_with_policy(state, decision, CausalSequencePolicy::AuthorityOnly)?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }

    let event_id = required_input_str(normalized_input, "event_id")?.to_owned();
    let delivery_id = required_input_str(normalized_input, "delivery_id")?.to_owned();
    let generation = required_input_u64(normalized_input, "expected_generation")?;
    let idempotency_key = required_input_str(normalized_input, "idempotency_key")?.to_owned();
    let reason = normalized_input
        .get("reason")
        .and_then(Value::as_str)
        .map_or_else(
            || "operator-confirmed-poison-delivery".to_owned(),
            str::to_owned,
        );
    let fact_id = format!("delivery_management_fact/{}", uuid::Uuid::now_v7());
    let fact_recorded_at = now_timestamp()?;

    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let (requesting_principal, operating_principal, delegation) = actor_principals(actor_context);
    let normalized_input_digest =
        proof_remote::identity::normalized_operation_input_digest(normalized_input, operation)
            .map_err(|error| ServerError::Internal(error.to_string()))?;

    let candidate = IdempotencyTupleV1 {
        workspace_id: parse_workspace_id(&decision.workspace_id)?,
        operation: operation.clone(),
        normalized_input_digest,
        requesting_principal: parse_principal_id(&requesting_principal)?,
        operating_principal: parse_principal_id(&operating_principal)?,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Authorization("invalid Delegation identity".to_owned()))?,
    };
    let key_kind = idempotency_kind(operation);
    let application_key = Some(idempotency_key.clone());

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let event_id_owned = event_id;
    let delivery_id_owned = delivery_id;
    let idempotency_key_owned = idempotency_key;
    let reason_owned = reason;
    let application_key_owned = application_key.clone();
    let authority_signer = state.config.authority_signer.clone();
    let portable_authority = authority_signer.is_some();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let built_result: Rc<RefCell<Option<Value>>> = Rc::new(RefCell::new(None));
    let result_for_hook = Rc::clone(&built_result);
    let application_problem: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let problem_for_hook = Rc::clone(&application_problem);
    let decision_for_hook = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(
                move |_tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    if head.authority_head == Some(expected_head) {
                        Ok(())
                    } else {
                        Err(PgError::Transaction(
                            "authority head advanced between evaluation and lock".to_owned(),
                        ))
                    }
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let transaction_seq = read_transaction_sequence_in_tx!(tx)?;
            let prior =
                read_stored_in_transaction(tx, candidate.workspace_id, &idempotency_key_owned)?;
            match replay_or_conflict(&candidate, prior.as_ref().map(|stored| &stored.tuple)) {
                IdempotencyOutcome::Replayed => {
                    let prior = prior.as_ref().expect("replay requires a stored row");
                    let prior_result_body = prior.result_body.as_deref().ok_or_else(|| {
                        PgError::Integrity("stored idempotency result bytes are absent".to_owned())
                    })?;
                    let prior_result: Value =
                        serde_json::from_slice(prior_result_body).map_err(|error| {
                            PgError::Integrity(format!("invalid stored result bytes: {error}"))
                        })?;
                    let recomputed_result_digest = operation_effect_digest(&prior_result)
                        .map_err(|error| PgError::Integrity(error.to_string()))?;
                    if recomputed_result_digest != prior.result_digest {
                        return Err(PgError::Integrity(
                            "stored idempotency result bytes do not match their digest".to_owned(),
                        ));
                    }
                    let consequence = bind_native_authority_chain(
                        replay_consequence(
                            decision_for_hook.clone(),
                            &operation_owned,
                            Some(prior.result_digest),
                            key_kind,
                            application_key_owned.clone(),
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    record_replay_in_transaction(
                        tx,
                        candidate.workspace_id,
                        &idempotency_key_owned,
                    )?;
                    *result_for_hook.borrow_mut() = Some(prior_result);
                    *built_for_hook.borrow_mut() = Some(consequence);
                    return Ok(());
                }
                IdempotencyOutcome::Conflict => {
                    let consequence = bind_native_authority_chain(
                        conflict_consequence(
                            decision_for_hook.clone(),
                            &operation_owned,
                            prior.as_ref().map(|stored| stored.result_digest),
                            key_kind,
                            application_key_owned.clone(),
                        ),
                        &decision_for_hook,
                        auth_seq,
                        portable_authority,
                    )?;
                    persist_decision_in_tx!(tx, &decision_for_hook);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                        decision_for_hook.workspace_id,
                        decision_for_hook.authority_sequence,
                        decision_for_hook.previous_authority_record_digest,
                        authority_signer
                    );
                    persist_consequence_in_tx!(tx, &consequence, consequence.authority_sequence);
                    persist_remote_record_in_tx!(
                        tx,
                        RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                        consequence.workspace_id,
                        consequence.authority_sequence,
                        consequence.previous_authority_record_digest,
                        authority_signer
                    );
                    advance_authority_head_in_tx!(
                        tx,
                        &consequence_digest(&consequence),
                        consequence.authority_sequence
                    );
                    *built_for_hook.borrow_mut() = Some(consequence);
                    *problem_for_hook.borrow_mut() =
                        Some("proof.idempotency.key_reused".to_owned());
                    return Err(PgError::ApplicationFailure(
                        "proof.idempotency.key_reused".to_owned(),
                    ));
                }
                IdempotencyOutcome::Fresh => {}
            }

            let state_row =
                read_delivery_state_in_tx!(tx, event_id_owned, delivery_id_owned, generation);
            let Some(state_row) = state_row else {
                commit_delivery_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_RESOURCE_NOT_FOUND,
                    auth_seq,
                    &built_for_hook,
                    &problem_for_hook,
                    application_key_owned,
                    key_kind,
                    portable_authority,
                    authority_signer
                );
            };
            let latest = read_latest_generation_in_tx!(tx, event_id_owned, delivery_id_owned);
            if latest != Some(i64::try_from(generation).unwrap_or(i64::MAX))
                || state_row.status != DELIVERY_STATUS_DEAD_LETTER
            {
                commit_delivery_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_STATE_CONFLICT,
                    auth_seq,
                    &built_for_hook,
                    &problem_for_hook,
                    application_key_owned,
                    key_kind,
                    portable_authority,
                    authority_signer
                );
            }

            let fact = build_delivery_fact(
                &decision_for_hook,
                action,
                &event_id_owned,
                &delivery_id_owned,
                generation,
                &idempotency_key_owned,
                &reason_owned,
                transaction_seq,
                fact_recorded_at,
            );
            let fact_digest = fact
                .digest()
                .map_err(|error| PgError::Integrity(error.to_string()))?;
            let result = delivery_result(
                action,
                &event_id_owned,
                &delivery_id_owned,
                generation,
                fact_digest,
            );
            let consequence = delivery_success_consequence(
                &decision_for_hook,
                &operation_owned,
                &result,
                application_key_owned.clone(),
                key_kind,
                fact_digest,
                auth_seq,
            )
            .map_err(|error| PgError::Integrity(error.to_string()))?;
            let consequence = bind_native_authority_chain(
                consequence,
                &decision_for_hook,
                auth_seq,
                portable_authority,
            )?;

            // The decision persists outside the savepoint so an authorized
            // application failure still retains the signed decision.
            persist_decision_in_tx!(tx, &decision_for_hook);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                decision_for_hook.workspace_id,
                decision_for_hook.authority_sequence,
                decision_for_hook.previous_authority_record_digest,
                authority_signer
            );
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_delivery_fact_in_tx!(sp, fact, fact_id);
                persist_consequence_in_tx!(sp, &consequence, consequence.authority_sequence);
                persist_remote_record_in_tx!(
                    sp,
                    RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                    consequence.workspace_id,
                    consequence.authority_sequence,
                    consequence.previous_authority_record_digest,
                    authority_signer
                );
                persist_idempotency_in_tx!(
                    sp,
                    &candidate,
                    &application_key_owned,
                    key_kind,
                    &consequence,
                    &result
                );
                match action {
                    DeliveryManagementAction::Replay => {
                        insert_replayed_generation_in_tx!(
                            sp,
                            event_id_owned,
                            delivery_id_owned,
                            generation + 1
                        );
                    }
                    DeliveryManagementAction::Abandon => {
                        abandon_delivery_in_tx!(sp, event_id_owned, delivery_id_owned, generation);
                    }
                }
                advance_authority_head_in_tx!(
                    sp,
                    &consequence_digest(&consequence),
                    consequence.authority_sequence
                );
            }
            savepoint.release()?;
            *result_for_hook.borrow_mut() = Some(result);
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let commit = run_unit_of_work_with_retry_and_sequence_policy_commit(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        CausalSequencePolicy::AuthorityOnly,
    )
    .map_err(ServerError::Storage)?;

    match commit.outcome {
        UnitOfWorkOutcome::Committed => Ok(HumanOperationExecution {
            consequence: built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))?,
            result: built_result.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("delivery result was not produced".to_owned())
            })?,
            transaction_sequence: commit.transaction_sequence,
        }),
        UnitOfWorkOutcome::ApplicationFailureCommitted => Err(ServerError::ApplicationProblem(
            application_problem.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("delivery application Problem was not produced".to_owned())
            })?,
        )),
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "delivery idempotency escaped the locked consequence hook".to_owned(),
            ))
        }
    }
}

/// `delivery.get/v1` — the typed transport projection of the exact mutable
/// delivery state (contract §"Human and control operation registry",
/// §"Transactional outbox and delivery").
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// projection failure.
fn execute_delivery_get(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<HumanOperationExecution, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial_with_policy(state, decision, CausalSequencePolicy::AuthorityOnly)?;
        return Err(ServerError::Authorization(
            "authorization denied".to_owned(),
        ));
    }

    let event_id = required_input_str(normalized_input, "event_id")?.to_owned();
    let delivery_id = required_input_str(normalized_input, "delivery_id")?.to_owned();
    let generation = required_input_u64(normalized_input, "expected_generation")?;

    // `delivery.get/v1` is a no-key read (idempotency `none`): it skips the
    // stored-result lookup entirely and always executes a fresh projection.
    let _ = actor_context;
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let event_id_owned = event_id;
    let delivery_id_owned = delivery_id;
    let application_key: Option<String> = None;
    let authority_signer = state.config.authority_signer.clone();
    let portable_authority = authority_signer.is_some();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let built_result: Rc<RefCell<Option<Value>>> = Rc::new(RefCell::new(None));
    let result_for_hook = Rc::clone(&built_result);
    let application_problem: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let problem_for_hook = Rc::clone(&application_problem);
    let decision_for_hook = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(
                move |_tx, head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                    if head.authority_head == Some(expected_head) {
                        Ok(())
                    } else {
                        Err(PgError::Transaction(
                            "authority head advanced between evaluation and lock".to_owned(),
                        ))
                    }
                },
            )
        },
        replay_or_conflict: Box::new(|_tx, _head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;

            let state_row =
                read_delivery_state_in_tx!(tx, event_id_owned, delivery_id_owned, generation);
            let Some(state_row) = state_row else {
                commit_delivery_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_RESOURCE_NOT_FOUND,
                    auth_seq,
                    &built_for_hook,
                    &problem_for_hook,
                    application_key,
                    ApplicationKeyKind::None,
                    portable_authority,
                    authority_signer
                );
            };
            let latest = read_latest_generation_in_tx!(tx, event_id_owned, delivery_id_owned);
            if latest != Some(i64::try_from(generation).unwrap_or(i64::MAX)) {
                commit_delivery_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_STATE_CONFLICT,
                    auth_seq,
                    &built_for_hook,
                    &problem_for_hook,
                    application_key,
                    ApplicationKeyKind::None,
                    portable_authority,
                    authority_signer
                );
            }

            let projection = delivery_projection(
                &event_id_owned,
                &delivery_id_owned,
                generation,
                &state_row.status,
                state_row.attempts_in_generation,
                state_row.next_attempt_at,
                state_row.receipt_digest.as_deref(),
            )
            .map_err(|error| PgError::Integrity(error.to_string()))?;
            // A no-key read produces no governed fact: the consequence binds the
            // exact projection digest as its result digest and no application
            // effect (contract §"Human and control operation registry").
            let consequence = delivery_get_success_consequence(
                &decision_for_hook,
                &operation_owned,
                &projection,
                auth_seq,
            )
            .map_err(|error| PgError::Integrity(error.to_string()))?;
            let consequence = bind_native_authority_chain(
                consequence,
                &decision_for_hook,
                auth_seq,
                portable_authority,
            )?;

            persist_decision_in_tx!(tx, &decision_for_hook);
            persist_remote_record_in_tx!(
                tx,
                RemoteAuthorityRecordV1::authorization_decision(decision_for_hook.clone()),
                decision_for_hook.workspace_id,
                decision_for_hook.authority_sequence,
                decision_for_hook.previous_authority_record_digest,
                authority_signer
            );
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_consequence_in_tx!(sp, &consequence, consequence.authority_sequence);
                persist_remote_record_in_tx!(
                    sp,
                    RemoteAuthorityRecordV1::application_consequence(consequence.clone()),
                    consequence.workspace_id,
                    consequence.authority_sequence,
                    consequence.previous_authority_record_digest,
                    authority_signer
                );
                advance_authority_head_in_tx!(
                    sp,
                    &consequence_digest(&consequence),
                    consequence.authority_sequence
                );
            }
            savepoint.release()?;
            *result_for_hook.borrow_mut() = Some(projection);
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let commit = run_unit_of_work_with_retry_and_sequence_policy_commit(
        runtime.client_mut(),
        &mut hooks,
        RetryPolicy::default(),
        CausalSequencePolicy::AuthorityOnly,
    )
    .map_err(ServerError::Storage)?;

    match commit.outcome {
        UnitOfWorkOutcome::Committed => Ok(HumanOperationExecution {
            consequence: built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))?,
            result: built_result.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("delivery result was not produced".to_owned())
            })?,
            transaction_sequence: commit.transaction_sequence,
        }),
        UnitOfWorkOutcome::ApplicationFailureCommitted => Err(ServerError::ApplicationProblem(
            application_problem.borrow_mut().take().ok_or_else(|| {
                ServerError::Internal("delivery application Problem was not produced".to_owned())
            })?,
        )),
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "a no-key read produced an unexpected idempotency outcome".to_owned(),
            ))
        }
    }
}

/// Executes `delivery.get/v1` and returns its committed authority consequence.
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// projection failure.
pub fn delivery_get_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    execute_delivery_get(state, operation, normalized_input, actor_context, decision)
        .map(|execution| execution.consequence)
}

/// `delivery.replay/v1` (`environment.admin`) — increments the generation,
/// resets `attempts_in_generation`, and returns `pending` while preserving
/// event, delivery, and payload identities and the append-only attempt history
/// (contract §"Human and control operation registry", §"Immutable artifacts
/// and delivery").
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// replay failure.
pub fn delivery_replay_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    execute_delivery_management(
        state,
        operation,
        normalized_input,
        actor_context,
        decision,
        DeliveryManagementAction::Replay,
    )
    .map(|execution| execution.consequence)
}

/// `delivery.abandon/v1` (`environment.activator`) — keeps the current
/// generation, records null `to_generation`, and sets terminal `abandoned`
/// (contract §"Human and control operation registry", §"Immutable artifacts
/// and delivery").
///
/// # Errors
///
/// Returns [`ServerError`] on any authentication, authorization, storage, or
/// abandonment failure.
pub fn delivery_abandon_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    execute_delivery_management(
        state,
        operation,
        normalized_input,
        actor_context,
        decision,
        DeliveryManagementAction::Abandon,
    )
    .map(|execution| execution.consequence)
}

/// Builds the exact `deliveryGetResultV1` projection from a locked state row.
fn delivery_projection(
    event_id: &str,
    delivery_id: &str,
    generation: u64,
    status: &str,
    attempts_in_generation: i64,
    next_attempt_at: Option<SystemTime>,
    receipt_digest: Option<&str>,
) -> Result<Value, ServerError> {
    let next_attempt_at = next_attempt_at
        .map(system_time_to_timestamp)
        .transpose()?
        .map(|timestamp| timestamp.to_string());
    Ok(json!({
        "api_version": "proof.dev/delivery-get-result/v1",
        "event_id": event_id,
        "delivery_id": delivery_id,
        "generation": generation,
        "status": status,
        "attempts_in_generation": attempts_in_generation,
        "next_attempt_at": next_attempt_at,
        "receipt_digest": receipt_digest,
    }))
}

fn delivery_get_success_consequence(
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    result: &Value,
    auth_seq: u64,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    let result_digest = operation_effect_digest(result)
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    Ok(build_consequence(
        decision,
        operation,
        ApplicationConsequenceOutcome::Success,
        ApplicationKeyKind::None,
        None,
        Some(result_digest),
        None,
        None,
        None,
        None,
        auth_seq,
        decision_digest(decision),
    ))
}

/// Exact private preview object projection (contract §"Preview delivery").
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreviewObjectResultV1 {
    /// Release identity (UUIDv7).
    pub release_id: String,
    /// Exact Release digest.
    pub release_digest: ContentDigest,
    /// Exact Edition digest.
    pub edition_digest: ContentDigest,
    /// Exact rendition digest.
    pub rendition_digest: ContentDigest,
    /// Strong HTTP ETag over the exact rendition digest.
    pub etag: String,
    /// Exact `private, no-store` cache control.
    pub cache_control: &'static str,
    /// The exact immutable Release snapshot projection body.
    pub body: Value,
}

/// The preview route serving signature: exact JSON only after that Release's
/// ready marker exists, identifying Release ID/digest, Edition digest, and
/// rendition digest, with a strong ETag and `Cache-Control: private,
/// no-store`, no locale fallback, no renderer, no template engine, no
/// arbitrary fetch (contract §"Preview delivery").
///
/// The reference filesystem layout mirrors the `proof-delivery` preview
/// adapter: a `<environment>`-scoped root holds one directory per Release with
/// a `ready` marker (written last), a `manifest.json` complete-snapshot
/// manifest, and the content-addressed rendition bodies. A Release with no
/// `ready` marker returns the stable `proof.dependency.unavailable` condition
/// and never falls back to another Release.
///
/// # Errors
///
/// Returns [`ServerError`] when the ready manifest is absent, the snapshot
/// fails verification, or the projection cannot be built. The absent case
/// carries [`DEPENDENCY_UNAVAILABLE_CODE`] so the route layer maps it to the
/// stable pending Problem.
pub fn serve_preview_object(
    state: &AppState,
    environment: &str,
    release_id: &str,
    object_id: &str,
    locale: &str,
) -> Result<PreviewObjectResultV1, ServerError> {
    let _ = state;
    let root = preview_root(environment).join(release_id);

    let ready_path = root.join("ready");
    if !ready_path.is_file() {
        return Err(ServerError::Internal(format!(
            "{DEPENDENCY_UNAVAILABLE_CODE}: the private preview snapshot for Release `{release_id}` is not ready"
        )));
    }

    let manifest_bytes = std::fs::read(root.join("manifest.json"))
        .map_err(|error| ServerError::Internal(format!("cannot read preview manifest: {error}")))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ServerError::Internal(format!("invalid preview manifest: {error}")))?;

    let manifest_release_id = manifest
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ServerError::Internal("preview manifest is missing `release_id`".to_owned())
        })?;
    if manifest_release_id != release_id {
        return Err(ServerError::Internal(format!(
            "preview manifest names Release `{manifest_release_id}`, not `{release_id}`"
        )));
    }

    let release_digest = parse_preview_digest(&manifest, "release_digest")?;
    let edition_digest = parse_preview_digest(&manifest, "edition_digest")?;

    let objects = manifest
        .get("objects")
        .and_then(Value::as_array)
        .ok_or_else(|| ServerError::Internal("preview manifest is missing `objects`".to_owned()))?;
    let entry = objects
        .iter()
        .find(|entry| {
            entry.get("object_id").and_then(Value::as_str) == Some(object_id)
                && entry.get("locale").and_then(Value::as_str) == Some(locale)
        })
        .ok_or_else(|| {
            ServerError::Dispatch(format!(
                "no preview object `{object_id}` for locale `{locale}` in Release `{release_id}`"
            ))
        })?;

    let rendition_digest = parse_preview_digest(entry, "rendition_digest")?;
    let path = entry
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Internal("preview object is missing `path`".to_owned()))?;
    let body_bytes = std::fs::read(root.join(path)).map_err(|error| {
        ServerError::Internal(format!("cannot read preview object body: {error}"))
    })?;
    let computed_digest = ContentDigest::blake3(*blake3::hash(&body_bytes).as_bytes());
    if computed_digest != rendition_digest {
        return Err(ServerError::Internal(
            "preview object rendition digest mismatch".to_owned(),
        ));
    }
    let body: Value = serde_json::from_slice(&body_bytes)
        .map_err(|error| ServerError::Internal(format!("invalid preview object body: {error}")))?;

    Ok(PreviewObjectResultV1 {
        release_id: release_id.to_owned(),
        release_digest,
        edition_digest,
        rendition_digest,
        etag: strong_etag(&rendition_digest),
        cache_control: PREVIEW_CACHE_CONTROL,
        body,
    })
}

/// Derives the filesystem-backed private preview root for one environment.
fn preview_root(environment: &str) -> PathBuf {
    std::env::temp_dir().join("proof-preview").join(environment)
}

/// Renders a strong HTTP ETag from the exact rendition digest.
fn strong_etag(digest: &ContentDigest) -> String {
    format!("\"{digest}\"")
}

fn parse_preview_digest(value: &Value, field: &str) -> Result<ContentDigest, ServerError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ServerError::Internal(format!("preview manifest is missing `{field}`")))?
        .parse::<ContentDigest>()
        .map_err(|error| ServerError::Internal(format!("invalid `{field}` digest: {error}")))
}

// ---------------------------------------------------------------------------
// P-0014 enrollment: agent-binding.issue/v1 and oidc-binding.issue/v1
// (contract §"Human and control operation registry", §"Remote identity
// vocabulary").
// ---------------------------------------------------------------------------

/// Frozen Agent binding validity: 90 days from issuance.
const AGENT_BINDING_VALIDITY_SECS: i64 = 7_776_000;

/// The governed fact kind of the public OIDC Principal binding row.
const OIDC_PUBLIC_BINDING_KIND: &str = "oidc_public_binding";

/// The governed fact kind of the protected OIDC binding opening row.
const OIDC_PRIVATE_BINDING_KIND: &str = "oidc_private_binding";

/// One extra immutable fact row persisted inside the same savepoint as its
/// governing fact.
struct AuxiliaryFact {
    fact_id: String,
    kind: String,
    digest: ContentDigest,
    body: Vec<u8>,
}

impl AuxiliaryFact {
    fn new(fact_id: String, kind: &str, digest: ContentDigest, body: Vec<u8>) -> Self {
        Self {
            fact_id,
            kind: kind.to_owned(),
            digest,
            body,
        }
    }
}

/// Caller-supplied enrollment closure for `agent-binding.issue/v1`, fully
/// parsed and proof-of-possession verified before any transaction.
struct PreparedAgentEnrollment {
    public_key: Ed25519PublicKey,
    key_id: Ed25519KeyId,
    challenge: proof_application::authority::BindingEnrollmentChallengeV1,
    envelope_digest: ContentDigest,
    challenge_digest: ContentDigest,
    consumption_fact_id: String,
}

/// Server-derived material for one `oidc-binding.issue/v1` application. The
/// blind is generated before the serializable transaction and reused across
/// internal retries of the one application attempt (contract §"Remote identity
/// vocabulary").
struct PreparedOidcIssuance {
    principal_id: String,
    subject: OidcAuthenticatedSubjectV1,
    issuer_configuration_digest: ContentDigest,
    binding_id: String,
    commitment: ContentDigest,
    blind_b64: String,
}

/// Fully prepared enrollment closure carried into the unit of work.
enum PreparedEnrollment {
    Agent(Box<PreparedAgentEnrollment>),
    Oidc(Box<PreparedOidcIssuance>),
}

/// Executes one P-0014 enrollment operation after out-of-band preparation of
/// its closure (contract §"Human and control operation registry").
fn execute_enrollment_owned(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<HumanOperationExecution, ServerError> {
    match operation.name.as_str() {
        "agent-binding.issue" => {
            let prepared = prepare_agent_enrollment(normalized_input, actor_context, decision)?;
            execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::AgentBindingIssue,
                Some(&prepared),
                None,
            )
        }
        "oidc-binding.issue" => {
            let prepared = prepare_oidc_issuance(state, normalized_input)?;
            execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::OidcBindingIssue,
                Some(&prepared),
                None,
            )
        }
        _ => Err(ServerError::Dispatch(format!(
            "operation `{}` carries no enrollment executor",
            operation.name
        ))),
    }
}

/// Parses and proof-of-possession verifies the agent-binding closure. Every
/// structural failure is an input schema mismatch; time and consumption
/// checks resolve inside the locked transaction.
#[allow(clippy::too_many_lines)]
fn prepare_agent_enrollment(
    input: &Value,
    _actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<PreparedEnrollment, ServerError> {
    let principal_id = required_input_str(input, "principal_id")?;
    let public_key_b64 = required_input_str(input, "public_key")?;
    let envelope_json = required_input_str(input, "enrollment_envelope")?;
    let challenge_value = input
        .get("challenge")
        .ok_or_else(|| missing_field("challenge"))?;
    let challenge: proof_application::authority::BindingEnrollmentChallengeV1 =
        serde_json::from_value(challenge_value.clone())
            .map_err(|_| ServerError::Dispatch("malformed enrollment challenge".to_owned()))?;

    if principal_id != challenge.principal_id.to_string() {
        return Err(ServerError::Dispatch(
            "`principal_id` does not match the enrollment challenge".to_owned(),
        ));
    }
    if parse_workspace_id(&decision.workspace_id)? != challenge.workspace_id {
        return Err(ServerError::Dispatch(
            "enrollment challenge is bound to a different Workspace".to_owned(),
        ));
    }
    let candidate_public_key = Ed25519PublicKey::new(public_key_b64.to_owned())
        .map_err(|_| ServerError::Dispatch("malformed candidate public key".to_owned()))?;
    let candidate_key_id = candidate_public_key
        .key_id()
        .map_err(|_| ServerError::Dispatch("candidate public key is unusable".to_owned()))?;
    if challenge.candidate_key_id.as_str() != candidate_key_id.as_str() {
        return Err(ServerError::Dispatch(
            "candidate public key does not match the enrollment challenge".to_owned(),
        ));
    }
    let verified =
        verify_authority_envelope::<proof_application::authority::BindingEnrollmentChallengeV1>(
            envelope_json.as_bytes(),
            AuthorityPayloadProfile::BindingEnrollmentChallenge,
            &[challenge.candidate_key_id.as_str()],
        )
        .map_err(|_| ServerError::Dispatch("enrollment envelope does not verify".to_owned()))?;
    if verified.parsed.payload != challenge {
        return Err(ServerError::Dispatch(
            "enrollment envelope does not carry its challenge".to_owned(),
        ));
    }

    let canonical_challenge =
        canonicalize(challenge_value).map_err(|error| ServerError::Internal(error.to_string()))?;
    let challenge_digest = digest(
        ArtifactKind::BindingEnrollmentChallengeV1,
        &canonical_challenge,
    );
    Ok(PreparedEnrollment::Agent(Box::new(
        PreparedAgentEnrollment {
            consumption_fact_id: format!("enrollment_challenge_consumption/{challenge_digest}"),
            challenge_digest,
            envelope_digest: verified.parsed.envelope_digest,
            key_id: candidate_key_id,
            public_key: candidate_public_key,
            challenge,
        },
    )))
}

/// Prepares the server-derived OIDC binding material. The caller supplies the
/// exact protected subject and pinned issuer-configuration digest but cannot
/// select the blind, commitment, or opening (contract §"Remote identity
/// vocabulary").
fn prepare_oidc_issuance(
    state: &AppState,
    input: &Value,
) -> Result<PreparedEnrollment, ServerError> {
    let principal_id = required_input_str(input, "principal_id")?.to_owned();
    let subject_value = input
        .get("subject")
        .ok_or_else(|| missing_field("subject"))?;
    let subject: OidcAuthenticatedSubjectV1 = serde_json::from_value(subject_value.clone())
        .map_err(|_| ServerError::Dispatch("malformed OIDC subject".to_owned()))?;
    let supplied_issuer_digest = required_input_str(input, "issuer_configuration_digest")?;
    let issuer_configuration_digest: ContentDigest = supplied_issuer_digest
        .parse()
        .map_err(|_| ServerError::Dispatch("malformed issuer configuration digest".to_owned()))?;
    let configured_issuer_digest = state
        .config
        .issuer
        .digest()
        .map_err(|error| ServerError::Internal(error.to_string()))?;
    if issuer_configuration_digest != configured_issuer_digest {
        return Err(ServerError::Dispatch(
            "`issuer_configuration_digest` does not match the deployment issuer".to_owned(),
        ));
    }
    let binding_id = match input.get("binding_id").and_then(Value::as_str) {
        Some(value) => value.to_owned(),
        None => uuid::Uuid::now_v7().to_string(),
    };
    let mut blind = [0_u8; 32];
    getrandom::fill(&mut blind).map_err(|error| ServerError::Internal(error.to_string()))?;
    let blind_b64 = encode_blind(&blind);
    let commitment = subject_commitment_digest(&OidcSubjectCommitmentInputV1 {
        api_version: OidcSubjectCommitmentInputApiVersion::V1,
        blind: blind_b64.clone(),
        subject: subject.clone(),
        workspace_id: state.config.workspace_id.to_string(),
    })
    .map_err(|error| ServerError::Internal(error.to_string()))?;
    Ok(PreparedEnrollment::Oidc(Box::new(PreparedOidcIssuance {
        principal_id,
        subject,
        issuer_configuration_digest,
        binding_id,
        commitment,
        blind_b64,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(name: &str, version: &str) -> RemoteOperationV1 {
        RemoteOperationV1 {
            name: name.to_owned(),
            version: version.to_owned(),
        }
    }

    #[test]
    fn content_read_inputs_reject_unknown_members() {
        let error = parse_content_read_command(
            &operation(
                "schema.get",
                proof_application::SCHEMA_GET_OPERATION_API_VERSION,
            ),
            &json!({
                "api_version": proof_application::SCHEMA_GET_OPERATION_API_VERSION,
                "schema_id": "article",
                "schema_version": 1,
                "unexpected": true,
            }),
        )
        .err()
        .expect("unknown input must fail");
        assert!(matches!(error, ServerError::Dispatch(_)));
    }

    #[test]
    fn content_read_inputs_report_wrong_api_versions() {
        let error = parse_content_read_command(
            &operation(
                "schema.list",
                proof_application::SCHEMA_LIST_OPERATION_API_VERSION,
            ),
            &json!({"api_version": "proof.dev/operation/schema.list/v2"}),
        )
        .err()
        .expect("wrong API version must fail");
        assert!(matches!(
            error,
            ServerError::ApplicationProblem(code)
                if code == "proof.input.unsupported_version"
        ));
    }

    #[test]
    fn object_list_requires_environment_and_bounded_unfiltered_scans() {
        let operation = operation(
            "object.list",
            proof_application::OBJECT_LIST_OPERATION_API_VERSION,
        );
        let missing_environment = parse_content_read_command(
            &operation,
            &json!({
                "api_version": proof_application::OBJECT_LIST_OPERATION_API_VERSION,
                "cursor": "0",
                "page_size": 10,
            }),
        );
        assert!(matches!(missing_environment, Err(ServerError::Dispatch(_))));

        let unbounded = parse_content_read_command(
            &operation,
            &json!({
                "api_version": proof_application::OBJECT_LIST_OPERATION_API_VERSION,
                "environment_id": "preview",
            }),
        );
        assert!(matches!(unbounded, Err(ServerError::Dispatch(_))));
    }
}
