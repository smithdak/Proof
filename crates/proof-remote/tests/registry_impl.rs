//! Integration tests for the closed `proof-remote` operation registries, frozen
//! SHA-256 recomputation, digest preimage builders, route cross-check, effect
//! timestamp selection, and consequence-outcome classification.

use proof_domain::ContentDigest;
use proof_remote::registry::{
    RemoteApplicationConsequenceApiVersion, RemoteAuthorizationDecisionApiVersion,
    RequestedAuthorizationResourceBindingV1, classify_consequence_outcome,
    cross_check_route_operation, effect_timestamp_field, operation_major,
    recompute_agent_authority_registry_sha256, recompute_complete_http_operation_registry_sha256,
    recompute_remote_authorization_projection_sha256,
};
use proof_remote::{
    AGENT_AUTHORITY_REGISTRY_SHA256, AgentOperationProjectionV1, ApplicationConsequenceOutcome,
    ApplicationKeyKind, AuthorizationDecisionKind, COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
    EffectDigestRule, EffectTimestampField, HttpRouteV1, HumanOperationRegistryV1,
    REMOTE_AUTHORIZATION_PROJECTION_SHA256, RemoteApplicationConsequenceV1,
    RemoteAuthorizationDecisionV1, RemoteOperationV1, application_problem_digest_preimage,
    authorization_resource_binding_digest, operation_effect_digest,
    remote_authorization_policy_selection_digest, requested_authorization_resources_digest,
};
use serde_json::{Value, json};

fn parse_strict_json(embedded: &str) -> Value {
    proof_canonical::parse_strict(embedded.as_bytes()).expect("retained vector must parse strictly")
}

fn decision_json() -> Value {
    parse_strict_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/remote-authorization-decision.valid.json"
    )))
}

fn release_result_json() -> Value {
    parse_strict_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/release-create-result.private-test.json"
    )))
}

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::blake3([byte; 32])
}

fn operation(name: &str, version: &str) -> RemoteOperationV1 {
    RemoteOperationV1 {
        name: name.to_owned(),
        version: version.to_owned(),
    }
}

fn base_decision() -> RemoteAuthorizationDecisionV1 {
    let mut decision = RemoteAuthorizationDecisionV1 {
        api_version: RemoteAuthorizationDecisionApiVersion::default(),
        authentication_profile: "proof.server/authentication/oidc-human-agent/v1".to_owned(),
        authorization_registry_sha256: String::new(),
        operation_registry_sha256: String::new(),
        authorization_rule: "proof.local/authority/direct/v1".to_owned(),
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        decision_id: "019e0000-0000-7000-8000-000000000071".to_owned(),
        operation: operation("release.create", "proof.dev/operation/release.create/v2"),
        requested_action: "release:create".to_owned(),
        public_input_projection_digest: digest(0x11),
        actor_context_digest: digest(0x22),
        requesting_principal_id: "019e0000-0000-7000-8000-000000000002".to_owned(),
        requesting_binding_id: "019e0000-0000-7000-8000-000000000011".to_owned(),
        requesting_binding_record_digest: digest(0x33),
        requesting_subject_commitment: digest(0x44),
        agent_authorization: None,
        role_assignment_digests: Vec::new(),
        requested_resources_digest: digest(0x55),
        policy_bundle_digest: digest(0x66),
        environment_config_digest: None,
        decision: AuthorizationDecisionKind::Allow,
        public_code: None,
        reason_code: "proof.authorization.allowed".to_owned(),
        evaluated_at: "2026-08-23T03:10:00Z".parse().unwrap(),
        evaluated_authority_head: proof_remote::AuthorityHeadV1 {
            sequence: 70,
            record_digest: digest(0x77),
        },
        authority_sequence: 71,
        previous_authority_record_digest: digest(0x77),
        authority_key_id:
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    };
    decision.bind_registry_hashes();
    decision
}

fn base_consequence() -> RemoteApplicationConsequenceV1 {
    RemoteApplicationConsequenceV1 {
        api_version: RemoteApplicationConsequenceApiVersion::default(),
        workspace_id: "019e0000-0000-7000-8000-000000000001".to_owned(),
        consequence_id: "019e0000-0000-7000-8000-000000000073".to_owned(),
        decision_id: "019e0000-0000-7000-8000-000000000071".to_owned(),
        decision_digest: digest(0xaa),
        public_input_projection_digest: digest(0x11),
        operation: operation("release.create", "proof.dev/operation/release.create/v2"),
        operation_registry_sha256: COMPLETE_HTTP_OPERATION_REGISTRY_SHA256.to_owned(),
        outcome: ApplicationConsequenceOutcome::Success,
        application_key_kind: ApplicationKeyKind::RequiredUuidV7,
        application_key: Some("019e0000-0000-7000-8000-000000000074".to_owned()),
        result_digest: Some(digest(0xbb)),
        prior_result_digest: None,
        application_effect_digest: None,
        application_effect_authority_head: None,
        problem_code: None,
        recorded_at: "2026-08-23T03:10:01Z".parse().unwrap(),
        evaluated_authority_head: proof_remote::AuthorityHeadV1 {
            sequence: 71,
            record_digest: digest(0xaa),
        },
        authority_sequence: 72,
        previous_authority_record_digest: digest(0xaa),
        authority_key_id:
            "ed25519:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
    }
}

#[test]
fn frozen_registry_hashes_recompute_byte_exactly() {
    recompute_agent_authority_registry_sha256()
        .expect("accepted Agent authority registry must recompute byte-exactly");
    recompute_remote_authorization_projection_sha256()
        .expect("remote authorization projection must recompute byte-exactly");
    recompute_complete_http_operation_registry_sha256()
        .expect("complete HTTP operation registry must recompute byte-exactly");

    assert_eq!(
        AGENT_AUTHORITY_REGISTRY_SHA256,
        "b4e67916e0d1cae8e7b73ce681057edcad7f83bc953487ccf127333a3340bca7"
    );
    assert_eq!(
        REMOTE_AUTHORIZATION_PROJECTION_SHA256,
        "e91d966de797f6f66bf15b619bec521e6a758c2775e402b5f8e0bc231125424b"
    );
    assert_eq!(
        COMPLETE_HTTP_OPERATION_REGISTRY_SHA256,
        "e485f67c7eb9e882f2a93f17f628e7078bd877faa116fd22b58895799051f2cf"
    );
}

#[test]
fn registry_lookup_accepts_known_rows_and_rejects_unknown() {
    let human = HumanOperationRegistryV1;
    let agent = AgentOperationProjectionV1;

    assert_eq!(human.rows().len(), 23);
    assert_eq!(agent.rows().len(), 14);

    // Known Human rows resolve; the route-scoped registries reject the other
    // route's rows and unknown (name, version) pairs.
    assert!(
        human
            .lookup(
                "agent-binding.issue",
                "proof.dev/operation/agent-binding.issue/v1"
            )
            .is_some()
    );
    assert!(
        human
            .lookup(
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v3"
            )
            .is_some()
    );
    assert!(
        human
            .lookup("release.create", "proof.dev/operation/release.create/v2")
            .is_none()
    );
    assert!(
        human
            .lookup("release.create", "proof.dev/operation/release.create/v9")
            .is_none()
    );

    assert!(
        agent
            .lookup("release.create", "proof.dev/operation/release.create/v2")
            .is_some()
    );
    assert!(
        agent
            .lookup(
                "workspace.status",
                "proof.dev/operation/workspace.status/v1"
            )
            .is_some()
    );
    assert!(
        agent
            .lookup(
                "agent-binding.issue",
                "proof.dev/operation/agent-binding.issue/v1"
            )
            .is_none()
    );
    assert!(
        agent
            .lookup("changeset.add", "proof.dev/operation/changeset.add/v1")
            .is_none()
    );
}

#[test]
fn http_route_surface_matches_the_nine_closed_routes() {
    assert_eq!(HttpRouteV1::ALL.len(), 9);
    assert_eq!(HttpRouteV1::OidcLogin.method(), "GET");
    assert_eq!(HttpRouteV1::OidcLogin.path(), "/auth/oidc/login");
    assert_eq!(HttpRouteV1::OidcCallback.path(), "/auth/oidc/callback");
    assert_eq!(HttpRouteV1::Session.path(), "/api/v1/session");
    assert_eq!(HttpRouteV1::SessionLogout.method(), "POST");
    assert_eq!(HttpRouteV1::SessionLogout.path(), "/api/v1/session/logout");
    assert_eq!(HttpRouteV1::Capabilities.path(), "/api/v1/capabilities");
    assert_eq!(
        HttpRouteV1::HumanOperations.path(),
        "/api/v1/human/operations/{name}/{major}"
    );
    assert_eq!(
        HttpRouteV1::AgentOperations.path(),
        "/api/v1/agent/operations/{name}/{major}"
    );
    assert_eq!(
        HttpRouteV1::EvidenceArtifact.path(),
        "/api/v1/evidence-exports/{export_id}/artifacts/{artifact_kind}/{digest}"
    );
    assert_eq!(
        HttpRouteV1::PreviewObject.path(),
        "/preview/{environment}/releases/{release_id}/objects/{object_id}/locales/{locale}"
    );
}

#[test]
fn route_cross_check_fails_closed_on_any_disagreement() {
    let release_create = operation("release.create", "proof.dev/operation/release.create/v2");

    // Agreement succeeds on the Agent route.
    cross_check_route_operation(
        HttpRouteV1::AgentOperations,
        "release.create",
        "v2",
        &release_create,
    )
    .unwrap();

    // Wrong name, wrong major, and wrong route all fail closed.
    assert!(
        cross_check_route_operation(
            HttpRouteV1::AgentOperations,
            "release.get",
            "v2",
            &release_create,
        )
        .is_err()
    );
    assert!(
        cross_check_route_operation(
            HttpRouteV1::AgentOperations,
            "release.create",
            "v1",
            &release_create,
        )
        .is_err()
    );
    assert!(
        cross_check_route_operation(
            HttpRouteV1::HumanOperations,
            "release.create",
            "v2",
            &release_create,
        )
        .is_err()
    );

    assert_eq!(
        operation_major("proof.dev/operation/release.create/v2"),
        Some("v2")
    );
    assert_eq!(
        operation_major("proof.dev/operation/changeset.approve/v3"),
        Some("v3")
    );
    assert_eq!(operation_major("proof.dev/operation/foo/"), None);
}

#[test]
fn digest_preimages_match_the_frozen_vectors() {
    let decision = decision_json();

    // requested_resources digest (the eight canonical resource arrays).
    let requested = &decision["agent_authorization"]["requested_resources"];
    let mut bindings: Vec<RequestedAuthorizationResourceBindingV1> = requested
        .as_object()
        .expect("requested_resources must be an object")
        .iter()
        .map(|(name, value)| RequestedAuthorizationResourceBindingV1 {
            name: name.clone(),
            value_digest: authorization_resource_binding_digest(name, value)
                .expect("binding preimage must canonicalize"),
        })
        .collect();
    bindings.sort_by(|left, right| left.name.cmp(&right.name));

    let decision_operation = operation(
        decision["operation"]["name"].as_str().unwrap(),
        decision["operation"]["version"].as_str().unwrap(),
    );
    let requested_digest = requested_authorization_resources_digest(
        decision["authorization_registry_sha256"].as_str().unwrap(),
        decision["authorization_rule"].as_str().unwrap(),
        &decision_operation,
        decision["requested_action"].as_str().unwrap(),
        &bindings,
    )
    .unwrap();
    assert_eq!(
        requested_digest.to_string(),
        "blake3:4fbc4c2df1351f3aa3c316102605d07501ecb029064fa661a9516fe05dba3251"
    );

    // policy_bundle_digest (remote-authorization-policy-selection).
    let policy_digest = remote_authorization_policy_selection_digest(
        decision["authorization_registry_sha256"].as_str().unwrap(),
        decision["authorization_rule"].as_str().unwrap(),
        Some(
            decision["environment_config_digest"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        ),
        Some(
            "blake3:5454545454545454545454545454545454545454545454545454545454545454"
                .parse()
                .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        policy_digest.to_string(),
        "blake3:f1a941b4d67907001f74ea5d01fb38f51900ff36fee114fb7fb79dc5ff3e2712"
    );

    // operation-effect digest over the exact release.create result.
    let release_result = release_result_json();
    let effect = operation_effect_digest(&release_result).unwrap();
    assert_eq!(
        effect.to_string(),
        "blake3:31523caf536aa25719fba4395176700b56d7316ce594fe18be1263a62fe781f4"
    );

    // application-problem preimage matches the documented
    // {api_version, code, operation} shape.
    let problem =
        application_problem_digest_preimage("proof.idempotency.key_reused", &decision_operation)
            .unwrap();
    let expected = canonical_digest(
        "proof:operation-effect:v1",
        &json!({
            "api_version": "proof.dev/application-problem-digest-preimage/v1",
            "code": "proof.idempotency.key_reused",
            "operation": decision["operation"].clone(),
        }),
    );
    assert_eq!(problem.to_string(), expected);
}

fn canonical_digest(context: &str, value: &Value) -> String {
    let canonical = proof_canonical::canonicalize(value).expect("value must canonicalize");
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(canonical.as_bytes());
    format!("blake3:{}", hasher.finalize().to_hex())
}

#[test]
fn effect_timestamp_field_selects_each_authority_payload_member() {
    let cases = [
        (
            (
                "agent-binding.issue",
                "proof.dev/operation/agent-binding.issue/v1",
            ),
            Some(EffectTimestampField::IssuedAt),
        ),
        (
            (
                "agent-binding.revoke",
                "proof.dev/operation/agent-binding.revoke/v1",
            ),
            Some(EffectTimestampField::RevokedAt),
        ),
        (
            (
                "changeset.approve",
                "proof.dev/operation/changeset.approve/v3",
            ),
            Some(EffectTimestampField::ApprovedAt),
        ),
        (
            (
                "environment-config.propose",
                "proof.dev/operation/environment-config.propose/v2",
            ),
            Some(EffectTimestampField::ProposedAt),
        ),
        (
            (
                "environment-config.activate",
                "proof.dev/operation/environment-config.activate/v2",
            ),
            Some(EffectTimestampField::ActivatedAt),
        ),
        (
            (
                "principal.status.set",
                "proof.dev/operation/principal.status.set/v2",
            ),
            Some(EffectTimestampField::RecordedAt),
        ),
        (
            (
                "workspace-role.assign",
                "proof.dev/operation/workspace-role.assign/v1",
            ),
            Some(EffectTimestampField::AssignedAt),
        ),
        (
            (
                "workspace-role.revoke",
                "proof.dev/operation/workspace-role.revoke/v1",
            ),
            Some(EffectTimestampField::RevokedAt),
        ),
    ];
    for ((name, version), expected) in cases {
        let selected = effect_timestamp_field(&operation(name, version));
        assert_eq!(selected, expected, "{name}/{version}");
    }

    // Non-authority effects and unknown rows select null.
    assert_eq!(
        effect_timestamp_field(&operation(
            "changeset.get",
            "proof.dev/operation/changeset.get/v2"
        )),
        None
    );
    assert_eq!(
        effect_timestamp_field(&operation(
            "release.create",
            "proof.dev/operation/release.create/v2"
        )),
        None
    );
    assert_eq!(
        effect_timestamp_field(&operation(
            "unknown.op",
            "proof.dev/operation/unknown.op/v1"
        )),
        None
    );
}

#[test]
fn consequence_outcome_classification_covers_all_five_classes() {
    // success: result present, prior null, problem null.
    let mut consequence = base_consequence();
    assert_eq!(
        classify_consequence_outcome(&consequence).unwrap(),
        ApplicationConsequenceOutcome::Success
    );

    // idempotent-replay: result == prior, no problem, no effect.
    consequence.outcome = ApplicationConsequenceOutcome::IdempotentReplay;
    consequence.prior_result_digest = Some(digest(0xbb));
    assert_eq!(
        classify_consequence_outcome(&consequence).unwrap(),
        ApplicationConsequenceOutcome::IdempotentReplay
    );

    // idempotency-conflict.
    let mut conflict = base_consequence();
    conflict.problem_code = Some("proof.idempotency.key_reused".to_owned());
    conflict.prior_result_digest = Some(digest(0xbb));
    assert_eq!(
        classify_consequence_outcome(&conflict).unwrap(),
        ApplicationConsequenceOutcome::IdempotencyConflict
    );

    // precondition-conflict.
    let mut precondition = base_consequence();
    precondition.problem_code = Some("proof.state.conflict".to_owned());
    assert_eq!(
        classify_consequence_outcome(&precondition).unwrap(),
        ApplicationConsequenceOutcome::PreconditionConflict
    );

    // application-failure.
    let mut failure = base_consequence();
    failure.problem_code = Some("proof.resource.not_found".to_owned());
    assert_eq!(
        classify_consequence_outcome(&failure).unwrap(),
        ApplicationConsequenceOutcome::ApplicationFailure
    );

    // An inconsistent shape (a precondition conflict with an effect) fails closed.
    precondition.application_effect_digest = Some(digest(0xcc));
    assert!(classify_consequence_outcome(&precondition).is_err());
}

#[test]
fn decision_binds_frozen_hashes_and_rejects_mismatch() {
    let mut decision = base_decision();
    assert_eq!(
        decision.authorization_registry_sha256,
        REMOTE_AUTHORIZATION_PROJECTION_SHA256
    );
    assert_eq!(
        decision.operation_registry_sha256,
        COMPLETE_HTTP_OPERATION_REGISTRY_SHA256
    );

    // A mismatched authorization registry hash must fail closed.
    decision.authorization_registry_sha256 = "a".repeat(64);
    assert!(decision.validate().is_err());
    decision.bind_registry_hashes();

    // A mismatched operation registry hash must fail closed.
    decision.operation_registry_sha256 = "b".repeat(64);
    assert!(decision.validate().is_err());
    decision.bind_registry_hashes();
    decision.authentication_profile = "proof.server/authentication/oidc-human-agent/v1".to_owned();

    // An Agent decision without agent_authorization must fail closed.
    decision.agent_authorization = None;
    assert!(decision.validate().is_err());
}

#[test]
fn consequence_copies_and_validates_its_decision_binding() {
    let decision = base_decision();
    let mut consequence = base_consequence();
    consequence.copy_decision_binding(&decision);
    consequence.validate_against(&decision).unwrap();

    // Diverging any copied field fails closed.
    consequence.workspace_id = "019e0000-0000-7000-8000-0000000000ff".to_owned();
    assert!(consequence.validate_against(&decision).is_err());
}

fn role_name(role: proof_remote::WorkspaceRole) -> &'static str {
    match role {
        proof_remote::WorkspaceRole::AuthorityAdmin => "authority.admin",
        proof_remote::WorkspaceRole::ContentPublisher => "content.publisher",
        proof_remote::WorkspaceRole::ContentRequester => "content.requester",
        proof_remote::WorkspaceRole::ContentReviewer => "content.reviewer",
        proof_remote::WorkspaceRole::EnvironmentActivator => "environment.activator",
        proof_remote::WorkspaceRole::EnvironmentAdmin => "environment.admin",
        proof_remote::WorkspaceRole::EvidenceAuditor => "evidence.auditor",
        proof_remote::WorkspaceRole::IdentityAdmin => "identity.admin",
    }
}

fn timestamp_name(field: EffectTimestampField) -> &'static str {
    match field {
        EffectTimestampField::IssuedAt => "issued_at",
        EffectTimestampField::RevokedAt => "revoked_at",
        EffectTimestampField::ApprovedAt => "approved_at",
        EffectTimestampField::ProposedAt => "proposed_at",
        EffectTimestampField::ActivatedAt => "activated_at",
        EffectTimestampField::RecordedAt => "recorded_at",
        EffectTimestampField::AssignedAt => "assigned_at",
    }
}

fn effect_rule_for(context: Option<&str>) -> EffectDigestRule {
    match context {
        None => EffectDigestRule::None,
        Some("proof:remote-authority-record:v1") => EffectDigestRule::RemoteAuthorityRecord,
        Some("proof:content-resource-intent:v1") => EffectDigestRule::ContentResourceIntent,
        Some("proof:evidence-export-capture:v2") => EffectDigestRule::EvidenceCapture,
        Some("proof:delivery-management-fact:v1") => EffectDigestRule::DeliveryManagementFact,
        Some(_) => EffectDigestRule::LocalizedEffect,
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn registry_rows_match_the_retained_vector_field_for_field() {
    let registry = parse_strict_json(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/v1/collaboration-server/vectors/http-operation-registry.valid.json"
    )));
    let routes = registry["routes"]
        .as_array()
        .expect("routes must be an array");

    let human_route = routes
        .iter()
        .find(|route| route["route_id"] == "human-operations")
        .expect("human-operations route must exist");
    let human_rows = human_route["operations"].as_array().unwrap();
    assert_eq!(human_rows.len(), HumanOperationRegistryV1.rows().len());
    for (json_row, row) in human_rows.iter().zip(HumanOperationRegistryV1.rows()) {
        assert_eq!(
            json_row["operation"]["name"].as_str().unwrap(),
            row.operation.name
        );
        assert_eq!(
            json_row["operation"]["version"].as_str().unwrap(),
            row.operation.version
        );
        assert_eq!(
            json_row["application_idempotency"].as_str().unwrap(),
            row.idempotency
        );
        assert_eq!(
            json_row["concurrency"].as_str().unwrap(),
            row.concurrency_anchor
        );
        assert_eq!(
            json_row["authorization"]["authorization_rule"]
                .as_str()
                .unwrap(),
            row.authorization_rule
        );
        let json_roles: Vec<&str> = json_row["authorization"]["roles_any_of"]
            .as_array()
            .unwrap()
            .iter()
            .map(|role| role.as_str().unwrap())
            .collect();
        let my_roles: Vec<&str> = row
            .roles_any_of
            .iter()
            .map(|role| role_name(*role))
            .collect();
        assert_eq!(json_roles, my_roles, "{}", row.operation.name);
        let json_ts = json_row["effect_digest_rule"]["effect_timestamp_field"].as_str();
        let my_ts = row.effect_timestamp_field.map(timestamp_name);
        assert_eq!(json_ts, my_ts, "{}", row.operation.name);
        assert_eq!(
            effect_rule_for(json_row["effect_digest_rule"]["digest_context"].as_str()),
            row.effect_digest_rule,
            "{}",
            row.operation.name
        );
        let json_codes: Vec<&str> = json_row["application_problem_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        let my_codes: Vec<&str> = row
            .application_problem_codes
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(json_codes, my_codes, "{}", row.operation.name);
    }

    let agent_route = routes
        .iter()
        .find(|route| route["route_id"] == "agent-operations")
        .expect("agent-operations route must exist");
    let agent_rows = agent_route["operations"].as_array().unwrap();
    assert_eq!(agent_rows.len(), AgentOperationProjectionV1.rows().len());
    for (json_row, row) in agent_rows.iter().zip(AgentOperationProjectionV1.rows()) {
        assert_eq!(
            json_row["operation"]["name"].as_str().unwrap(),
            row.operation.name
        );
        assert_eq!(
            json_row["operation"]["version"].as_str().unwrap(),
            row.operation.version
        );
        assert_eq!(
            json_row["requested_action"].as_str().unwrap(),
            row.requested_action
        );
        assert_eq!(row.authorization_rule, "proof.local/authority/direct/v1");
        assert_eq!(
            effect_rule_for(json_row["effect_digest_rule"]["digest_context"].as_str()),
            row.effect_digest_rule,
            "{}",
            row.operation.name
        );
        let json_codes: Vec<&str> = json_row["application_problem_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|code| code.as_str().unwrap())
            .collect();
        let my_codes: Vec<&str> = row
            .application_problem_codes
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(json_codes, my_codes, "{}", row.operation.name);
    }
}
