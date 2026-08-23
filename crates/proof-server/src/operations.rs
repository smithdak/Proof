//! Owned Human and Agent operation executors over the P-0010 unit of work
//! (contract §"PostgreSQL authoritative unit of work", §"HTTP boundary").

use std::cell::RefCell;
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
    AuthorityHeadV1, RemoteOperationV1,
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
/// (evidence export capture/assembly, delivery, and preview materialization)
/// until S4/S5 (contract §"HTTP boundary").
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
pub const PENDING_DEPENDENCY_OPERATION_NAMES: [&str; 5] = [
    "evidence.export",
    "evidence.export.get",
    "delivery.get",
    "delivery.replay",
    "delivery.abandon",
];

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
