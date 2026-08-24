//! Owned Human and Agent operation executors over the P-0010 unit of work
//! (contract §"PostgreSQL authoritative unit of work", §"HTTP boundary").

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};

use proof_canonical::canonicalize;
use proof_domain::{ContentDigest, Timestamp};
use proof_pg::{
    PgError,
    idempotency::{IdempotencyOutcome, IdempotencyTupleV1, SavepointGuard, replay_or_conflict},
    transaction::{UnitOfWorkHooks, UnitOfWorkOutcome, run_unit_of_work},
};
use proof_remote::{
    AuthorityHeadV1, DeliveryManagementAction, DeliveryManagementFactV1, RemoteOperationV1,
    authority::{
        RemoteAuthorityRecordV1, WorkspaceRole, WorkspaceRoleAssignmentApiVersion,
        WorkspaceRoleAssignmentV1, WorkspaceRoleRevocationApiVersion, WorkspaceRoleRevocationV1,
    },
    identity::AuthenticatedActorContextV2,
    registry::{
        AgentOperationProjectionV1, ApplicationConsequenceOutcome, ApplicationKeyKind,
        AuthorizationDecisionKind, EffectDigestRule, HumanOperationRegistryV1,
        RemoteApplicationConsequenceApiVersion, RemoteApplicationConsequenceV1,
        RemoteAuthorizationDecisionV1, application_problem_digest_preimage,
        operation_effect_digest,
    },
};
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
        match operation.name.as_str() {
            "evidence.export" | "evidence.export.get" => dependency_unavailable_consequence(
                operation,
                normalized_input,
                actor_context,
                decision,
            ),
            "delivery.get" => {
                delivery_get_v1(state, operation, normalized_input, actor_context, decision)
            }
            "delivery.replay" => {
                delivery_replay_v1(state, operation, normalized_input, actor_context, decision)
            }
            "delivery.abandon" => {
                delivery_abandon_v1(state, operation, normalized_input, actor_context, decision)
            }
            "workspace-role.assign" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::RoleAssignment,
            ),
            "workspace-role.revoke" => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::RoleRevocation,
            ),
            _ => execute_owned(
                state,
                operation,
                normalized_input,
                actor_context,
                decision,
                FactPlan::Generic,
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
        if AgentOperationProjectionV1
            .lookup(&operation.name, &operation.version)
            .is_none()
        {
            return Err(ServerError::Dispatch(format!(
                "unregistered Agent operation `{}` at `{}`",
                operation.name, operation.version
            )));
        }
        execute_owned(
            state,
            operation,
            normalized_input,
            actor_context,
            decision,
            FactPlan::Generic,
        )
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
    Generic,
}

/// One governed fact prepared for a fresh success attempt.
struct GovernedFact {
    fact_id: String,
    fact_kind: String,
    workspace_id: String,
    fact_digest: ContentDigest,
    body: Vec<u8>,
    effect_authority_head: Option<AuthorityHeadV1>,
    result: Value,
}

/// The pre-transaction idempotency lookup result.
struct IdempotencyPrior {
    prior: Option<IdempotencyTupleV1>,
    prior_result_digest: Option<ContentDigest>,
}

// ---------------------------------------------------------------------------
// Transaction persistence macros. `postgres::Transaction` cannot be named in
// this crate, so the SQL bodies expand inline at each `apply_consequence`
// closure where the transaction type is inferred.
// ---------------------------------------------------------------------------

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

macro_rules! persist_idempotency_in_tx {
    ($tx:expr, $candidate:expr, $key_kind:expr, $consequence:expr) => {{
        let result = $consequence
            .result_digest
            .map(|d| d.to_string())
            .unwrap_or_else(|| consequence_digest($consequence).to_string());
        $tx.execute(
            "INSERT INTO idempotency_keys (
                 workspace_id, operation, operation_version, normalized_input_digest,
                 requesting_principal, operating_principal, delegation_id, key_kind,
                 result_digest, replay_count, committed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, now())",
            &[
                &$candidate.workspace_id.to_string(),
                &$candidate.operation.name,
                &$candidate.operation.version,
                &$candidate.normalized_input_digest.to_string(),
                &$candidate.requesting_principal.to_string(),
                &$candidate.operating_principal.to_string(),
                &$candidate.delegation.map(|d| d.to_string()),
                &key_kind_label($key_kind),
                &result,
            ],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
}

macro_rules! advance_authority_head_in_tx {
    ($tx:expr, $digest:expr, $auth_seq:expr) => {{
        let seq = i64::try_from($auth_seq)
            .map_err(|_| PgError::Integrity("authority sequence out of range".to_owned()))?;
        $tx.execute(
            "UPDATE workspace_write_head
             SET authority_head_digest = $1, authority_head_sequence = $2
             WHERE singleton = 1",
            &[&$digest.to_string(), &seq],
        )
        .map_err(|e| proof_pg::transaction::transaction_error(&e))?;
    }};
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
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial(state, decision)?;
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
    let prior = read_idempotency_prior(runtime, &candidate)?;

    let key_kind = idempotency_kind(operation);
    let application_key = normalized_input
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let input_owned = normalized_input.clone();
    let actor_owned = actor_context.clone();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let decision_for_hook = decision.clone();
    let input_for_hook = input_owned.clone();
    let operation_for_hook = operation_owned.clone();
    let actor_for_hook = actor_owned.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(move |head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: {
            let candidate_for_hook = candidate.clone();
            let prior_for_hook = prior.prior.clone();
            Box::new(move |_head| {
                Ok(replay_or_conflict(
                    &candidate_for_hook,
                    prior_for_hook.as_ref(),
                ))
            })
        },
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let fact = build_governed_fact(
                plan,
                &input_for_hook,
                &actor_for_hook,
                &decision_for_hook,
                &operation_for_hook,
                auth_seq,
                decision_digest(&decision_for_hook),
            )
            .map_err(|error| PgError::Idempotency(error.to_string()))?;
            let consequence = success_consequence(
                &decision_for_hook,
                &operation_for_hook,
                application_key.clone(),
                key_kind,
                &fact,
                auth_seq,
                decision_digest(&decision_for_hook),
            )
            .map_err(|error| PgError::Idempotency(error.to_string()))?;

            // The decision persists outside the savepoint so an authorized
            // application failure still retains the signed decision.
            persist_decision_in_tx!(tx, &decision_for_hook);
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_fact_in_tx!(sp, &fact, auth_seq);
                persist_consequence_in_tx!(sp, &consequence, auth_seq);
                persist_idempotency_in_tx!(sp, &candidate, key_kind, &consequence);
                advance_authority_head_in_tx!(sp, &consequence_digest(&consequence), auth_seq);
            }
            savepoint.release()?;
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let outcome =
        run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;

    match outcome {
        UnitOfWorkOutcome::Committed | UnitOfWorkOutcome::ApplicationFailureCommitted => {
            built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))
        }
        UnitOfWorkOutcome::Replayed => Ok(replay_consequence(
            decision,
            operation,
            prior.prior_result_digest,
        )),
        UnitOfWorkOutcome::ConflictCommitted => Ok(conflict_consequence(
            decision,
            operation,
            prior.prior_result_digest,
        )),
    }
}

/// Commits a signed denial decision alone (no governed fact or consequence).
fn commit_denial(
    state: &AppState,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<(), ServerError> {
    let mut guard = lock_pg(state)?;
    let runtime = runtime_mut(&mut guard)?;
    let decision = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(move |head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: Box::new(|_head| Ok(IdempotencyOutcome::Fresh)),
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            persist_decision_in_tx!(tx, &decision);
            advance_authority_head_in_tx!(tx, &decision_digest(&decision), auth_seq);
            Ok(())
        }),
    };

    run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;
    Ok(())
}

/// Builds the row-governed fact for one fresh attempt.
#[allow(clippy::too_many_lines)]
fn build_governed_fact(
    plan: FactPlan,
    input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
    operation: &RemoteOperationV1,
    auth_seq: u64,
    previous_digest: ContentDigest,
) -> Result<GovernedFact, ServerError> {
    match plan {
        FactPlan::RoleAssignment => {
            let principal_id = required_input_str(input, "principal_id")?;
            let role = parse_role(required_input_str(input, "role")?)?;
            let assignment_id = assignment_id_from_input(input);
            let assignment = WorkspaceRoleAssignmentV1 {
                api_version: WorkspaceRoleAssignmentApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                assignment_id,
                principal_id: principal_id.to_owned(),
                role,
                assigned_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                assigned_by_actor_context_digest: decision.actor_context_digest,
                assigned_at: now_timestamp()?,
                evaluated_authority_head: decision.evaluated_authority_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            let result = serde_json::to_value(&assignment)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let fact_digest =
                RemoteAuthorityRecordV1::workspace_role_assignment(assignment).digest();
            Ok(GovernedFact {
                fact_id: format!(
                    "workspace_role_assignment/{}",
                    assignment_id_from_input(input)
                ),
                fact_kind: "workspace_role_assignment".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest: fact_digest,
                }),
                result,
            })
        }
        FactPlan::RoleRevocation => {
            let principal_id = required_input_str(input, "principal_id")?;
            let role = parse_role(required_input_str(input, "role")?)?;
            let assignment_id = required_input_str(input, "assignment_id")?.to_owned();
            let reason = input
                .get("reason")
                .and_then(Value::as_str)
                .map_or_else(|| "administrative".to_owned(), str::to_owned);
            let revocation = WorkspaceRoleRevocationV1 {
                api_version: WorkspaceRoleRevocationApiVersion::V1,
                workspace_id: decision.workspace_id.clone(),
                revocation_id: uuid::Uuid::now_v7().to_string(),
                assignment_id,
                assignment_record_digest: decision
                    .role_assignment_digests
                    .first()
                    .copied()
                    .unwrap_or_else(|| ContentDigest::blake3([0_u8; 32])),
                principal_id: principal_id.to_owned(),
                role,
                reason,
                revoked_by_principal_id: requesting_principal_id(actor_context).to_owned(),
                revoked_by_actor_context_digest: decision.actor_context_digest,
                revoked_at: now_timestamp()?,
                evaluated_authority_head: decision.evaluated_authority_head,
                authority_sequence: auth_seq,
                previous_authority_record_digest: previous_digest,
                authority_key_id: decision.authority_key_id.clone(),
            };
            let result = serde_json::to_value(&revocation)
                .map_err(|error| ServerError::Internal(error.to_string()))?;
            let body = canonical_bytes(&result)?;
            let fact_digest =
                RemoteAuthorityRecordV1::workspace_role_revocation(revocation).digest();
            Ok(GovernedFact {
                fact_id: format!("workspace_role_revocation/{}", uuid::Uuid::now_v7()),
                fact_kind: "workspace_role_revocation".to_owned(),
                workspace_id: decision.workspace_id.clone(),
                fact_digest,
                body,
                effect_authority_head: Some(AuthorityHeadV1 {
                    sequence: auth_seq,
                    record_digest: fact_digest,
                }),
                result,
            })
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
                result,
            })
        }
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
) -> RemoteApplicationConsequenceV1 {
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotentReplay,
        ApplicationKeyKind::None,
        None,
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
) -> RemoteApplicationConsequenceV1 {
    build_consequence(
        &decision,
        operation,
        ApplicationConsequenceOutcome::IdempotencyConflict,
        ApplicationKeyKind::None,
        None,
        prior_result_digest,
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
    guard.as_mut().ok_or_else(|| {
        ServerError::Storage(proof_pg::PgError::Connect(
            "PostgreSQL runtime is not connected".to_owned(),
        ))
    })
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

fn read_idempotency_prior(
    runtime: &mut proof_pg::wiring::PgRuntime,
    candidate: &IdempotencyTupleV1,
) -> Result<IdempotencyPrior, ServerError> {
    let row = runtime
        .client_mut()
        .query_opt(
            "SELECT normalized_input_digest, delegation_id, result_digest
             FROM idempotency_keys
             WHERE workspace_id = $1 AND operation = $2 AND operation_version = $3
               AND requesting_principal = $4 AND operating_principal = $5
             ORDER BY committed_at DESC
             LIMIT 1",
            &[
                &candidate.workspace_id.to_string(),
                &candidate.operation.name,
                &candidate.operation.version,
                &candidate.requesting_principal.to_string(),
                &candidate.operating_principal.to_string(),
            ],
        )
        .map_err(|error| {
            ServerError::Storage(PgError::Idempotency(format!(
                "idempotency lookup failed: {error}"
            )))
        })?;
    let Some(row) = row else {
        return Ok(IdempotencyPrior {
            prior: None,
            prior_result_digest: None,
        });
    };
    let normalized_input_digest: String = row.get(0);
    let delegation: Option<String> = row.get(1);
    let result_digest: String = row.get(2);
    let prior = IdempotencyTupleV1 {
        workspace_id: candidate.workspace_id,
        operation: candidate.operation.clone(),
        normalized_input_digest: normalized_input_digest.parse().map_err(|error| {
            ServerError::Internal(format!("invalid stored input digest: {error}"))
        })?,
        requesting_principal: candidate.requesting_principal,
        operating_principal: candidate.operating_principal,
        delegation: delegation
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| ServerError::Internal("invalid stored Delegation identity".to_owned()))?,
    };
    let prior_result_digest = result_digest
        .parse()
        .map_err(|error| ServerError::Internal(format!("invalid stored result digest: {error}")))?;
    Ok(IdempotencyPrior {
        prior: Some(prior),
        prior_result_digest: Some(prior_result_digest),
    })
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
    ($tx:expr, $decision:expr, $operation:expr, $problem_code:expr, $auth_seq:expr, $built:expr) => {{
        let failure = delivery_failure_consequence($decision, $operation, $problem_code, $auth_seq)
            .map_err(|error| PgError::Idempotency(error.to_string()))?;
        persist_decision_in_tx!($tx, $decision);
        persist_consequence_in_tx!($tx, &failure, $auth_seq);
        advance_authority_head_in_tx!($tx, &consequence_digest(&failure), $auth_seq);
        *$built.borrow_mut() = Some(failure);
        return Err(PgError::Idempotency($problem_code.to_owned()));
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
) -> DeliveryManagementFactV1 {
    let recorded_at = now_timestamp().expect("the system clock always produces a timestamp");
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
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial(state, decision)?;
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
    let prior = read_idempotency_prior(runtime, &candidate)?;

    let key_kind = idempotency_kind(operation);
    let application_key = normalized_input
        .get("idempotency_key")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let decision = decision.clone();
    let operation_owned = operation.clone();
    let event_id_owned = event_id;
    let delivery_id_owned = delivery_id;
    let idempotency_key_owned = idempotency_key;
    let reason_owned = reason;
    let application_key_owned = application_key.clone();

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let decision_for_hook = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(move |head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: {
            let candidate_for_hook = candidate.clone();
            let prior_for_hook = prior.prior.clone();
            Box::new(move |_head| {
                Ok(replay_or_conflict(
                    &candidate_for_hook,
                    prior_for_hook.as_ref(),
                ))
            })
        },
        apply_consequence: Box::new(move |tx| {
            let auth_seq = read_auth_sequence_in_tx!(tx)?;
            let transaction_seq = read_transaction_sequence_in_tx!(tx)?;

            let state_row =
                read_delivery_state_in_tx!(tx, event_id_owned, delivery_id_owned, generation);
            let Some(state_row) = state_row else {
                commit_delivery_failure_in_tx!(
                    tx,
                    &decision_for_hook,
                    &operation_owned,
                    PROBLEM_RESOURCE_NOT_FOUND,
                    auth_seq,
                    &built_for_hook
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
                    &built_for_hook
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
            );
            let fact_digest = fact
                .digest()
                .map_err(|error| PgError::Idempotency(error.to_string()))?;
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
            .map_err(|error| PgError::Idempotency(error.to_string()))?;

            // The decision persists outside the savepoint so an authorized
            // application failure still retains the signed decision.
            persist_decision_in_tx!(tx, &decision_for_hook);
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                let fact_id = format!("delivery_management_fact/{}", uuid::Uuid::now_v7());
                persist_delivery_fact_in_tx!(sp, fact, fact_id);
                persist_consequence_in_tx!(sp, &consequence, auth_seq);
                persist_idempotency_in_tx!(sp, &candidate, key_kind, &consequence);
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
                advance_authority_head_in_tx!(sp, &consequence_digest(&consequence), auth_seq);
            }
            savepoint.release()?;
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let outcome =
        run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;

    match outcome {
        UnitOfWorkOutcome::Committed | UnitOfWorkOutcome::ApplicationFailureCommitted => {
            built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))
        }
        UnitOfWorkOutcome::Replayed => Ok(replay_consequence(
            decision,
            operation,
            prior.prior_result_digest,
        )),
        UnitOfWorkOutcome::ConflictCommitted => Ok(conflict_consequence(
            decision,
            operation,
            prior.prior_result_digest,
        )),
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
pub fn delivery_get_v1(
    state: &AppState,
    operation: &RemoteOperationV1,
    normalized_input: &Value,
    actor_context: &AuthenticatedActorContextV2,
    decision: &RemoteAuthorizationDecisionV1,
) -> Result<RemoteApplicationConsequenceV1, ServerError> {
    if decision.decision == AuthorizationDecisionKind::Deny {
        commit_denial(state, decision)?;
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

    let built_consequence: Rc<RefCell<Option<RemoteApplicationConsequenceV1>>> =
        Rc::new(RefCell::new(None));
    let built_for_hook = Rc::clone(&built_consequence);
    let decision_for_hook = decision.clone();

    let mut hooks = UnitOfWorkHooks {
        verify_authentication: Box::new(|| Ok(())),
        evaluate_authorization: {
            let expected_head = decision.evaluated_authority_head;
            Box::new(move |head: &proof_pg::transaction::WorkspaceHeadSnapshot| {
                if head.authority_head == Some(expected_head) {
                    Ok(())
                } else {
                    Err(PgError::Transaction(
                        "authority head advanced between evaluation and lock".to_owned(),
                    ))
                }
            })
        },
        replay_or_conflict: Box::new(|_head| Ok(IdempotencyOutcome::Fresh)),
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
                    &built_for_hook
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
                    &built_for_hook
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
            .map_err(|error| PgError::Idempotency(error.to_string()))?;
            // A no-key read produces no governed fact: the consequence binds the
            // exact projection digest as its result digest and no application
            // effect (contract §"Human and control operation registry").
            let consequence = delivery_get_success_consequence(
                &decision_for_hook,
                &operation_owned,
                &projection,
                auth_seq,
            )
            .map_err(|error| PgError::Idempotency(error.to_string()))?;

            persist_decision_in_tx!(tx, &decision_for_hook);
            let mut savepoint = SavepointGuard::establish(tx)?;
            {
                let sp = savepoint.transaction();
                persist_consequence_in_tx!(sp, &consequence, auth_seq);
                advance_authority_head_in_tx!(sp, &consequence_digest(&consequence), auth_seq);
            }
            savepoint.release()?;
            *built_for_hook.borrow_mut() = Some(consequence);
            Ok(())
        }),
    };

    let outcome =
        run_unit_of_work(runtime.client_mut(), &mut hooks).map_err(ServerError::Storage)?;

    match outcome {
        UnitOfWorkOutcome::Committed | UnitOfWorkOutcome::ApplicationFailureCommitted => {
            built_consequence
                .borrow_mut()
                .take()
                .ok_or_else(|| ServerError::Internal("consequence was not produced".to_owned()))
        }
        UnitOfWorkOutcome::Replayed | UnitOfWorkOutcome::ConflictCommitted => {
            Err(ServerError::Internal(
                "a no-key read produced an unexpected idempotency outcome".to_owned(),
            ))
        }
    }
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
