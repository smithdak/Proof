//! Independent copy of the ratified 14-row authority operation registry.
//!
//! This module decodes the exact signed input and derives the decision's
//! resource, selector, budget, and application-idempotency projections from
//! portable artifacts. No producer registry or state store is consulted.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::{
    container::{LoadedArtifact, LoadedBundle},
    model::{Digest, EvidenceRole},
    schema,
    semantics::parse_timestamp,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Idempotency {
    None,
    Required,
    Derived,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Consequence {
    EvidenceOnly,
    Context,
    ChangeSetCreate,
    ChangeSetAdd,
    Validation,
    Submission,
    Commit,
    Edition,
    Release,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OperationSpec {
    pub(crate) name: &'static str,
    pub(crate) version: &'static str,
    pub(crate) action: &'static str,
    pub(crate) input: Option<&'static str>,
    pub(crate) output: Option<&'static str>,
    pub(crate) idempotency: Idempotency,
    pub(crate) consequence: Consequence,
}

const OPERATIONS: [OperationSpec; 14] = [
    spec(
        "changeset.add",
        "proof.dev/operation/changeset.add/v2",
        "changeset:add",
        Some("changeSetAddInput"),
        Some("changeSetAddOutput"),
        Idempotency::Required,
        Consequence::ChangeSetAdd,
    ),
    spec(
        "changeset.commit",
        "proof.dev/operation/changeset.commit/v2",
        "changeset:commit",
        Some("changeSetCommitInput"),
        Some("changeSetCommitOutput"),
        Idempotency::Required,
        Consequence::Commit,
    ),
    spec(
        "changeset.create",
        "proof.dev/operation/changeset.create/v2",
        "changeset:create",
        Some("changeSetCreateInput"),
        Some("changeSetCreateOutput"),
        Idempotency::Required,
        Consequence::ChangeSetCreate,
    ),
    spec(
        "changeset.diff",
        "proof.dev/operation/changeset.diff/v2",
        "changeset:diff",
        Some("changeSetDiffInput"),
        Some("changeSetDiffOutput"),
        Idempotency::None,
        Consequence::EvidenceOnly,
    ),
    spec(
        "changeset.get",
        "proof.dev/operation/changeset.get/v2",
        "changeset:get",
        Some("changeSetGetInput"),
        Some("changeSetGetOutput"),
        Idempotency::None,
        Consequence::EvidenceOnly,
    ),
    spec(
        "changeset.submit",
        "proof.dev/operation/changeset.submit/v2",
        "changeset:submit",
        Some("changeSetSubmitInput"),
        Some("changeSetSubmitOutput"),
        Idempotency::Derived,
        Consequence::Submission,
    ),
    spec(
        "changeset.validate",
        "proof.dev/operation/changeset.validate/v2",
        "changeset:validate",
        Some("changeSetValidateInput"),
        Some("changeSetValidateOutput"),
        Idempotency::Derived,
        Consequence::Validation,
    ),
    spec(
        "context.build",
        "proof.dev/operation/context.build/v1",
        "context:build",
        None,
        None,
        Idempotency::Required,
        Consequence::Context,
    ),
    spec(
        "context.build",
        "proof.dev/operation/context.build/v2",
        "context:build",
        Some("contextBuildInput"),
        Some("contextBuildOutput"),
        Idempotency::Required,
        Consequence::Context,
    ),
    spec(
        "edition.create",
        "proof.dev/operation/edition.create/v2",
        "edition:create",
        Some("editionCreateInput"),
        Some("editionCreateOutput"),
        Idempotency::Required,
        Consequence::Edition,
    ),
    spec(
        "object.query_released",
        "proof.dev/operation/object.query_released/v1",
        "object:query_released",
        None,
        None,
        Idempotency::None,
        Consequence::EvidenceOnly,
    ),
    spec(
        "object.query_released",
        "proof.dev/operation/object.query_released/v2",
        "object:query_released",
        Some("objectQueryReleasedInput"),
        Some("objectQueryReleasedOutput"),
        Idempotency::None,
        Consequence::EvidenceOnly,
    ),
    spec(
        "release.create",
        "proof.dev/operation/release.create/v2",
        "release:create",
        Some("releaseCreateInput"),
        Some("releaseCreateOutput"),
        Idempotency::Required,
        Consequence::Release,
    ),
    spec(
        "workspace.status",
        "proof.dev/operation/workspace.status/v1",
        "workspace:status",
        None,
        None,
        Idempotency::None,
        Consequence::EvidenceOnly,
    ),
];

const fn spec(
    name: &'static str,
    version: &'static str,
    action: &'static str,
    input: Option<&'static str>,
    output: Option<&'static str>,
    idempotency: Idempotency,
    consequence: Consequence,
) -> OperationSpec {
    OperationSpec {
        name,
        version,
        action,
        input,
        output,
        idempotency,
        consequence,
    }
}

pub(crate) fn resolve(operation: &Value) -> Option<&'static OperationSpec> {
    let name = operation.get("name")?.as_str()?;
    let version = operation.get("version")?.as_str()?;
    OPERATIONS
        .iter()
        .find(|entry| entry.name == name && entry.version == version)
}

#[derive(Default)]
struct Projection {
    environment_ids: BTreeSet<String>,
    object_ids: BTreeSet<String>,
    schema_ids: BTreeSet<String>,
    locales: BTreeSet<String>,
    changeset_ids: BTreeSet<String>,
    edition_ids: BTreeSet<String>,
    release_ids: BTreeSet<String>,
    max_objects: u64,
    max_context_bytes: u64,
    max_edits: u64,
}

impl Projection {
    fn requested_value(&self, workspace_id: &str) -> Value {
        json!({
            "changeset_ids": self.changeset_ids,
            "edition_ids": self.edition_ids,
            "environment_ids": self.environment_ids,
            "locales": self.locales,
            "object_ids": self.object_ids,
            "release_ids": self.release_ids,
            "schema_ids": self.schema_ids,
            "workspace_ids": [workspace_id],
        })
    }

    fn constraints_value(&self) -> Value {
        json!({
            "max_context_bytes": self.max_context_bytes,
            "max_edits_per_changeset": self.max_edits,
            "max_objects": self.max_objects,
        })
    }
}

pub(crate) fn validate_command_and_projection(
    loaded: &LoadedBundle,
    input: &Value,
    decision: &Value,
    delegation: &Value,
) -> Option<&'static OperationSpec> {
    validate_command_and_projection_inner(loaded, input, decision, delegation, false)
}

pub(crate) fn validate_command_and_projection_allowing_missing_context_build(
    loaded: &LoadedBundle,
    input: &Value,
    decision: &Value,
    delegation: &Value,
) -> Option<&'static OperationSpec> {
    validate_command_and_projection_inner(loaded, input, decision, delegation, true)
}

fn validate_command_and_projection_inner(
    loaded: &LoadedBundle,
    input: &Value,
    decision: &Value,
    delegation: &Value,
    allow_missing_context_build: bool,
) -> Option<&'static OperationSpec> {
    let spec = validate_command_shape(input, decision)?;
    let normalized = input.get("normalized_input")?;
    let evaluated = decision
        .get("evaluated_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)?;
    let mut projection = derive_projection(
        loaded,
        spec,
        input,
        normalized,
        decision,
        evaluated,
        allow_missing_context_build,
    )?;
    let delegated_constraints = delegation.get("constraints")?;
    match (spec.name, spec.version) {
        ("workspace.status", _) => {
            projection.max_objects = delegated_constraints.get("max_objects")?.as_u64()?;
            projection.max_context_bytes =
                delegated_constraints.get("max_context_bytes")?.as_u64()?;
            projection.max_edits = delegated_constraints
                .get("max_edits_per_changeset")?
                .as_u64()?;
        }
        ("object.query_released", _) => {
            projection.max_context_bytes =
                delegated_constraints.get("max_context_bytes")?.as_u64()?;
            projection.max_edits = delegated_constraints
                .get("max_edits_per_changeset")?
                .as_u64()?;
        }
        _ => {}
    }
    (decision.get("requested_resources")
        == Some(&projection.requested_value(&loaded.bundle.workspace_id))
        && decision.get("effective_constraints") == Some(&projection.constraints_value()))
    .then_some(spec)
}

pub(crate) fn validate_command_initial_projection(
    input: &Value,
    decision: &Value,
) -> Option<&'static OperationSpec> {
    let spec = validate_command_shape(input, decision)?;
    let normalized = input.get("normalized_input")?;
    let mut projection = Projection {
        max_objects: 1,
        max_context_bytes: 1,
        max_edits: 1,
        ..Projection::default()
    };
    match (spec.name, spec.version) {
        ("object.query_released", "proof.dev/operation/object.query_released/v1") => {
            projection
                .environment_ids
                .insert(string_field(normalized, "environment_id")?.to_owned());
            projection
                .object_ids
                .extend(strings(normalized.get("object_ids"))?);
            projection.max_objects = projection.object_ids.len() as u64;
        }
        ("context.build", "proof.dev/operation/context.build/v1") => {
            projection
                .environment_ids
                .insert(string_field(normalized, "environment_id")?.to_owned());
            projection
                .object_ids
                .extend(strings(normalized.get("object_ids"))?);
            projection.max_objects = normalized.get("max_objects")?.as_u64()?;
            projection.max_context_bytes = normalized.get("max_bytes")?.as_u64()?;
        }
        ("context.build", "proof.dev/operation/context.build/v2") => {
            projection.max_objects = normalized.pointer("/limits/max_objects")?.as_u64()?;
            projection.max_context_bytes = normalized.pointer("/limits/max_bytes")?.as_u64()?;
            projection.max_edits = normalized.pointer("/limits/max_edits")?.as_u64()?;
        }
        ("object.query_released", "proof.dev/operation/object.query_released/v2") => {
            projection
                .environment_ids
                .insert(string_field(normalized, "environment_id")?.to_owned());
            for target in normalized.get("targets")?.as_array()? {
                projection
                    .object_ids
                    .insert(string_field(target, "object_id")?.to_owned());
                projection
                    .locales
                    .insert(string_field(target, "locale")?.to_owned());
            }
            projection.max_objects = projection.object_ids.len() as u64;
        }
        _ => {}
    }
    let workspace = string_field(decision, "workspace_id")?;
    (decision.get("requested_resources") == Some(&projection.requested_value(workspace))
        && decision.get("effective_constraints") == Some(&projection.constraints_value()))
    .then_some(spec)
}

pub(crate) fn validate_command_shape(
    input: &Value,
    decision: &Value,
) -> Option<&'static OperationSpec> {
    let operation = input.get("operation")?;
    let spec = resolve(operation)?;
    if decision.get("operation") != Some(operation)
        || decision.get("requested_action") != Some(&Value::String(spec.action.to_owned()))
    {
        return None;
    }
    validate_normalized(spec, input, input.get("normalized_input")?).then_some(spec)
}

pub(crate) fn full_projection_is_resolvable(
    loaded: &LoadedBundle,
    input: &Value,
    decision: &Value,
) -> bool {
    let Some(spec) = validate_command_shape(input, decision) else {
        return false;
    };
    let Some(normalized) = input.get("normalized_input") else {
        return false;
    };
    let Some(evaluated) = decision
        .get("evaluated_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
    else {
        return false;
    };
    derive_projection(loaded, spec, input, normalized, decision, evaluated, false).is_some()
}

fn validate_normalized(spec: &OperationSpec, command: &Value, normalized: &Value) -> bool {
    let outer_key = command.get("idempotency_key");
    let inner_key = normalized.get("idempotency_key");
    let idempotency_valid = match spec.idempotency {
        Idempotency::Required => {
            outer_key.and_then(Value::as_str).is_some_and(uuid_v7) && outer_key == inner_key
        }
        Idempotency::None | Idempotency::Derived => {
            outer_key.is_some_and(Value::is_null) && inner_key.is_none()
        }
    };
    if !idempotency_valid {
        return false;
    }
    if let Some(definition) = spec.input {
        return schema::localized_operation(definition, normalized)
            && normalized_collections_are_canonical(spec, normalized);
    }
    match (spec.name, spec.version) {
        ("workspace.status", "proof.dev/operation/workspace.status/v1") => normalized
            .as_object()
            .is_some_and(serde_json::Map::is_empty),
        ("object.query_released", "proof.dev/operation/object.query_released/v1") => {
            exact_keys(
                normalized,
                &[
                    "delegation_id",
                    "environment_id",
                    "object_ids",
                    "operating_principal_id",
                ],
            ) && normalized.get("delegation_id") == command.get("delegation_id")
                && normalized.get("operating_principal_id") == command.get("operating_principal_id")
                && sorted_unique_strings(normalized.get("object_ids"), 1, 100)
                && logical_id(normalized.get("environment_id").and_then(Value::as_str))
        }
        ("context.build", "proof.dev/operation/context.build/v1") => {
            exact_keys(
                normalized,
                &[
                    "delegation_id",
                    "environment_id",
                    "expires_at",
                    "idempotency_key",
                    "intent",
                    "max_bytes",
                    "max_objects",
                    "object_ids",
                    "operating_principal_id",
                    "task_id",
                ],
            ) && normalized.get("delegation_id") == command.get("delegation_id")
                && normalized.get("operating_principal_id") == command.get("operating_principal_id")
                && normalized.get("idempotency_key") == command.get("idempotency_key")
                && sorted_unique_strings(normalized.get("object_ids"), 1, 100)
                && normalized
                    .get("object_ids")
                    .and_then(Value::as_array)
                    .is_some_and(|values| {
                        normalized
                            .get("max_objects")
                            .and_then(Value::as_u64)
                            .is_some_and(|maximum| {
                                !values.is_empty()
                                    && values.len() as u64 <= maximum
                                    && maximum <= 100
                            })
                    })
                && normalized
                    .get("max_bytes")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| (1..=1_048_576).contains(&value))
                && bounded_string(normalized.get("task_id").and_then(Value::as_str), 1, 128)
                && bounded_string(normalized.get("intent").and_then(Value::as_str), 1, 500)
                && logical_id(normalized.get("environment_id").and_then(Value::as_str))
                && normalized
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .and_then(parse_timestamp)
                    .is_some()
        }
        _ => false,
    }
}

fn normalized_collections_are_canonical(spec: &OperationSpec, value: &Value) -> bool {
    match spec.name {
        "context.build" => sorted_unique_by(value.get("policy_rules"), |rule| {
            Some(format!(
                "{}\0{}",
                rule.get("locale")?.as_str()?,
                rule.get("pointer")?.as_str()?
            ))
        }),
        "changeset.add" => value
            .get("edits")
            .and_then(Value::as_array)
            .is_some_and(|edits| !edits.is_empty() && edits.len() <= 100),
        "object.query_released" => sorted_unique_by(value.get("targets"), |target| {
            Some(format!(
                "{}\0{}",
                target.get("object_id")?.as_str()?,
                target.get("locale")?.as_str()?
            ))
        }),
        _ => true,
    }
}

fn derive_projection(
    loaded: &LoadedBundle,
    spec: &OperationSpec,
    command: &Value,
    input: &Value,
    decision: &Value,
    evaluated: time::OffsetDateTime,
    allow_missing_context_build: bool,
) -> Option<Projection> {
    let mut projection = Projection {
        max_objects: 1,
        max_context_bytes: 1,
        max_edits: 1,
        ..Projection::default()
    };
    match (spec.name, spec.version) {
        ("workspace.status", _) => {}
        ("object.query_released", "proof.dev/operation/object.query_released/v1") => {
            projection
                .environment_ids
                .insert(string_field(input, "environment_id")?.to_owned());
            projection
                .object_ids
                .extend(strings(input.get("object_ids"))?);
            projection.max_objects = projection.object_ids.len() as u64;
        }
        ("context.build", "proof.dev/operation/context.build/v1") => {
            projection
                .environment_ids
                .insert(string_field(input, "environment_id")?.to_owned());
            projection
                .object_ids
                .extend(strings(input.get("object_ids"))?);
            projection.max_objects = input.get("max_objects")?.as_u64()?;
            projection.max_context_bytes = input.get("max_bytes")?.as_u64()?;
        }
        ("object.query_released", "proof.dev/operation/object.query_released/v2") => {
            derive_released_query(loaded, input, &mut projection)?;
        }
        _ => {
            derive_intent_closure(
                loaded,
                spec,
                input,
                decision,
                evaluated,
                allow_missing_context_build,
                &mut projection,
            )?;
        }
    }
    apply_selectors(loaded, spec, input, &mut projection)?;
    let _ = command;
    Some(projection)
}

fn derive_intent_closure(
    loaded: &LoadedBundle,
    spec: &OperationSpec,
    input: &Value,
    decision: &Value,
    evaluated: time::OffsetDateTime,
    allow_missing_context_build: bool,
    projection: &mut Projection,
) -> Option<()> {
    let requesting = string_field(decision, "requesting_principal_id")?;
    let (intent_digest, context_digest, changeset, edition) = match spec.name {
        "context.build" => (
            digest_field(input, "resource_intent_digest")?,
            None,
            None,
            None,
        ),
        "changeset.create" => (
            digest_field(input, "resource_intent_digest")?,
            Some(digest_field(input, "context_pack_digest")?),
            None,
            None,
        ),
        "release.create" => {
            let edition = edition_by_id(loaded, string_field(input, "edition_id")?)?;
            let changeset_id = edition.value.pointer("/changeset/changeset_id")?.as_str()?;
            let changeset = changeset_by_id(loaded, changeset_id)?;
            (
                digest_field(&changeset.value, "resource_intent_digest")?,
                digest_field(&changeset.value, "context_pack_digest"),
                Some(changeset),
                Some(edition),
            )
        }
        _ => {
            let changeset = changeset_by_id(loaded, string_field(input, "changeset_id")?)?;
            (
                digest_field(&changeset.value, "resource_intent_digest")?,
                digest_field(&changeset.value, "context_pack_digest"),
                Some(changeset),
                None,
            )
        }
    };
    let intent = exact_role(loaded, EvidenceRole::ResourceIntent, intent_digest)?;
    if string_field(&intent.value, "workspace_id")? != loaded.bundle.workspace_id
        || string_field(&intent.value, "issued_by_principal_id")? != requesting
    {
        return None;
    }
    if let Some(changeset) = changeset
        && (string_field(&changeset.value, "principal_id")? != requesting
            || digest_field(&changeset.value, "resource_intent_digest")? != intent_digest
            || changeset.value.get("resource_intent_id") != intent.value.get("intent_id"))
    {
        return None;
    }
    if let Some(edition) = edition
        && string_field(&edition.value, "principal_id")? != requesting
    {
        return None;
    }
    let targets = project_intent_resources(&intent.value, projection)?;
    if allow_missing_context_build
        && spec.name == "context.build"
        && spec.version == "proof.dev/operation/context.build/v2"
    {
        if input.get("resource_intent_id") != intent.value.get("intent_id") {
            return None;
        }
        let created = string_field(input, "created_at").and_then(parse_timestamp)?;
        let expires = string_field(input, "expires_at").and_then(parse_timestamp)?;
        if created > evaluated || evaluated >= expires {
            return None;
        }
        projection.max_objects = input.pointer("/limits/max_objects")?.as_u64()?;
        projection.max_context_bytes = input.pointer("/limits/max_bytes")?.as_u64()?;
        projection.max_edits = input.pointer("/limits/max_edits")?.as_u64()?;
        return Some(());
    }
    let context = match context_digest {
        Some(digest) => exact_role(loaded, EvidenceRole::ContextPack, digest)?,
        None => artifacts_for_role(loaded, EvidenceRole::ContextPack).find(|artifact| {
            digest_field(&artifact.value, "resource_intent_digest") == Some(intent_digest)
        })?,
    };
    let created = string_field(&context.value, "created_at").and_then(parse_timestamp)?;
    let expires = string_field(&context.value, "expires_at").and_then(parse_timestamp)?;
    if string_field(&context.value, "principal_id")? != requesting
        || string_field(&context.value, "workspace_id")? != loaded.bundle.workspace_id
        || digest_field(&context.value, "resource_intent_digest")? != intent_digest
        || context.value.get("resource_intent") != Some(&intent.value)
        || created > evaluated
        || evaluated >= expires
    {
        return None;
    }
    projection.max_objects = context.value.pointer("/limits/max_objects")?.as_u64()?;
    projection.max_context_bytes = context.value.pointer("/limits/max_bytes")?.as_u64()?;
    projection.max_edits = context.value.pointer("/limits/max_edits")?.as_u64()?;
    if !intent_limits_are_respected(context, targets, changeset, projection) {
        return None;
    }
    Some(())
}

fn project_intent_resources<'a>(
    intent: &'a Value,
    projection: &mut Projection,
) -> Option<&'a [Value]> {
    let targets = intent.get("targets")?.as_array()?;
    for target in targets {
        projection
            .object_ids
            .insert(string_field(target, "object_id")?.to_owned());
        projection
            .schema_ids
            .insert(string_field(target, "schema_id")?.to_owned());
        projection
            .locales
            .insert(string_field(target, "locale")?.to_owned());
    }
    projection
        .environment_ids
        .insert(string_field(intent, "environment_id")?.to_owned());
    Some(targets)
}

fn intent_limits_are_respected(
    context: &LoadedArtifact,
    targets: &[Value],
    changeset: Option<&LoadedArtifact>,
    projection: &Projection,
) -> bool {
    let Some(resources) = context.value.get("resources").and_then(Value::as_array) else {
        return false;
    };
    let target_object_count = targets
        .iter()
        .filter_map(|target| string_field(target, "object_id"))
        .collect::<BTreeSet<_>>()
        .len() as u64;
    let edit_count = changeset
        .and_then(|changeset| changeset.value.get("edits"))
        .and_then(Value::as_array)
        .map_or(0_u64, |edits| edits.len() as u64);
    resources.len() == targets.len()
        && target_object_count <= projection.max_objects
        && resources.len() as u64 <= projection.max_edits
        && u64::try_from(context.bytes.len())
            .is_ok_and(|bytes| bytes <= projection.max_context_bytes)
        && edit_count <= projection.max_edits
}

fn derive_released_query(
    loaded: &LoadedBundle,
    input: &Value,
    projection: &mut Projection,
) -> Option<()> {
    let environment = string_field(input, "environment_id")?;
    projection.environment_ids.insert(environment.to_owned());
    let targets = input.get("targets")?.as_array()?;
    for target in targets {
        projection
            .object_ids
            .insert(string_field(target, "object_id")?.to_owned());
        projection
            .locales
            .insert(string_field(target, "locale")?.to_owned());
    }
    projection.max_objects = projection.object_ids.len() as u64;
    let current = artifacts_for_role(loaded, EvidenceRole::ReleaseManifest)
        .filter(|artifact| string_field(&artifact.value, "environment_id") == Some(environment))
        .max_by_key(|artifact| {
            artifact
                .value
                .get("release_sequence")
                .and_then(Value::as_u64)
        })?;
    projection
        .release_ids
        .insert(string_field(&current.value, "release_id")?.to_owned());
    let edition_ref = current.value.get("edition")?;
    let edition = exact_role(
        loaded,
        EvidenceRole::Edition,
        digest_field(edition_ref, "digest")?,
    )?;
    projection
        .edition_ids
        .insert(string_field(edition_ref, "edition_id")?.to_owned());
    for object_id in &projection.object_ids {
        let object = edition
            .value
            .get("objects")?
            .as_array()?
            .iter()
            .find(|object| string_field(object, "object_id") == Some(object_id.as_str()))?;
        projection
            .schema_ids
            .insert(string_field(object, "schema_id")?.to_owned());
    }
    Some(())
}

fn apply_selectors(
    loaded: &LoadedBundle,
    spec: &OperationSpec,
    input: &Value,
    projection: &mut Projection,
) -> Option<()> {
    match spec.name {
        "changeset.create" | "changeset.add" | "changeset.get" | "changeset.diff"
        | "changeset.validate" | "changeset.submit" | "changeset.commit" => {
            projection
                .changeset_ids
                .insert(string_field(input, "changeset_id")?.to_owned());
        }
        "edition.create" => {
            projection
                .changeset_ids
                .insert(string_field(input, "changeset_id")?.to_owned());
            projection
                .edition_ids
                .insert(string_field(input, "edition_id")?.to_owned());
        }
        "release.create" => {
            let edition = edition_by_id(loaded, string_field(input, "edition_id")?)?;
            projection.changeset_ids.insert(
                edition
                    .value
                    .pointer("/changeset/changeset_id")?
                    .as_str()?
                    .to_owned(),
            );
            projection
                .edition_ids
                .insert(string_field(input, "edition_id")?.to_owned());
            projection
                .release_ids
                .insert(string_field(input, "expected_base_release_id")?.to_owned());
            projection
                .release_ids
                .insert(string_field(input, "release_id")?.to_owned());
        }
        _ => {}
    }
    Some(())
}

fn changeset_by_id<'a>(loaded: &'a LoadedBundle, id: &str) -> Option<&'a LoadedArtifact> {
    let mut matches = artifacts_for_role(loaded, EvidenceRole::ChangeSet).filter(|artifact| {
        artifact.value.get("api_version").and_then(Value::as_str) == Some("proof.dev/changeset/v2")
            && string_field(&artifact.value, "changeset_id") == Some(id)
    });
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn edition_by_id<'a>(loaded: &'a LoadedBundle, id: &str) -> Option<&'a LoadedArtifact> {
    let mut matches = artifacts_for_role(loaded, EvidenceRole::Edition).filter(|artifact| {
        string_field(&artifact.value, "api_version") == Some("proof.dev/edition/v2")
            && string_field(&artifact.value, "edition_id") == Some(id)
    });
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn exact_role(
    loaded: &LoadedBundle,
    role: EvidenceRole,
    digest: Digest,
) -> Option<&LoadedArtifact> {
    let mut matches = loaded
        .bundle
        .artifacts
        .iter()
        .filter(|descriptor| descriptor.role == role && descriptor.artifact.digest == digest)
        .filter_map(|descriptor| loaded.artifacts.get(&descriptor.artifact));
    let value = matches.next()?;
    matches.next().is_none().then_some(value)
}

fn artifacts_for_role(
    loaded: &LoadedBundle,
    role: EvidenceRole,
) -> impl Iterator<Item = &LoadedArtifact> {
    loaded
        .bundle
        .artifacts
        .iter()
        .filter(move |descriptor| descriptor.role == role)
        .filter_map(|descriptor| loaded.artifacts.get(&descriptor.artifact))
}

fn digest_field(value: &Value, field: &str) -> Option<Digest> {
    value.get(field)?.as_str().and_then(Digest::parse)
}

fn string_field<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field)?.as_str()
}

fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    value?
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn sorted_unique_strings(value: Option<&Value>, minimum: usize, maximum: usize) -> bool {
    sorted_unique_by(value, |value| value.as_str().map(str::to_owned))
        && value
            .and_then(Value::as_array)
            .is_some_and(|values| (minimum..=maximum).contains(&values.len()))
}

fn sorted_unique_by<F>(value: Option<&Value>, key: F) -> bool
where
    F: Fn(&Value) -> Option<String>,
{
    let Some(values) = value.and_then(Value::as_array) else {
        return false;
    };
    let mut previous = None;
    for value in values {
        let Some(key) = key(value) else {
            return false;
        };
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return false;
        }
        previous = Some(key);
    }
    true
}

fn bounded_string(value: Option<&str>, minimum: usize, maximum: usize) -> bool {
    value
        .is_some_and(|value| (minimum..=maximum).contains(&value.len()) && !value.trim().is_empty())
}

fn logical_id(value: Option<&str>) -> bool {
    bounded_string(value, 1, 128)
        && value.is_some_and(|value| {
            let mut bytes = value.bytes();
            bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
                && bytes.all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

pub(crate) fn uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || (b'a'..=b'f').contains(byte)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ArtifactDescriptor, ArtifactKind, ArtifactRef, AuthorityHead, Availability,
        BUNDLE_API_VERSION, Bundle, Entrypoints,
    };

    const WORKSPACE_ID: &str = "019c0000-0000-7000-8000-000000000001";
    const PRINCIPAL_ID: &str = "019c0000-0000-7000-8000-000000000002";
    const INTENT_ID: &str = "019c0000-0000-7000-8000-000000000003";
    const CONTEXT_ID: &str = "019c0000-0000-7000-8000-000000000004";
    const IDEMPOTENCY_KEY: &str = "019c0000-0000-7000-8000-000000000005";

    fn artifact_ref(artifact_kind: ArtifactKind, byte: u8) -> ArtifactRef {
        ArtifactRef {
            artifact_kind,
            digest: Digest([byte; 32]),
        }
    }

    fn loaded_with_intent(intent_ref: ArtifactRef, intent: Value) -> LoadedBundle {
        let release_ref = artifact_ref(ArtifactKind::ReleaseV2, 2);
        let proof_ref = artifact_ref(ArtifactKind::ProofEnvelopeV1, 3);
        let consequence_ref = artifact_ref(ArtifactKind::AuthenticatedLocalizedConsequenceV1, 4);
        LoadedBundle {
            bundle: Bundle {
                api_version: BUNDLE_API_VERSION.to_owned(),
                workspace_id: WORKSPACE_ID.to_owned(),
                entrypoints: Entrypoints {
                    target_release_manifest: release_ref,
                    target_release_proof_envelope: proof_ref,
                    target_authorization_record_digest: Digest([5; 32]),
                    target_localized_consequence: consequence_ref,
                },
                included_authority_head: AuthorityHead {
                    sequence: 0,
                    record_digest: Digest([5; 32]),
                },
                authority_prefix: Vec::new(),
                artifacts: vec![ArtifactDescriptor {
                    role: EvidenceRole::ResourceIntent,
                    artifact: intent_ref,
                    availability: Availability::Included { byte_length: 1 },
                }],
            },
            manifest_digest: Digest([6; 32]),
            artifacts: [(
                intent_ref,
                LoadedArtifact {
                    bytes: vec![0],
                    value: intent,
                },
            )]
            .into_iter()
            .collect(),
            missing_external: BTreeSet::new(),
            required_external_missing: false,
        }
    }

    fn context_build_projection_fixture() -> (LoadedBundle, Value, Value, Value) {
        let intent_ref = artifact_ref(ArtifactKind::ContentResourceIntentV1, 1);
        let intent = json!({
            "environment_id": "production",
            "intent_id": INTENT_ID,
            "issued_by_principal_id": PRINCIPAL_ID,
            "targets": [{
                "locale": "en-US",
                "object_id": "019c0000-0000-7000-8000-000000000006",
                "schema_id": "article",
            }],
            "workspace_id": WORKSPACE_ID,
        });
        let normalized = json!({
            "api_version": "proof.dev/operation/context.build/v2",
            "context_pack_id": CONTEXT_ID,
            "created_at": "2026-08-21T09:00:00Z",
            "expires_at": "2026-08-21T11:00:00Z",
            "idempotency_key": IDEMPOTENCY_KEY,
            "limits": {
                "max_bytes": 4096,
                "max_edits": 2,
                "max_objects": 1,
                "max_validation_attempts": 3,
            },
            "policy_rules": [{
                "disallowed_values": ["forbidden"],
                "locale": "en-US",
                "pointer": "/title",
            }],
            "resource_intent_digest": intent_ref.digest,
            "resource_intent_id": INTENT_ID,
        });
        let input = json!({
            "idempotency_key": IDEMPOTENCY_KEY,
            "normalized_input": normalized,
            "operation": {
                "name": "context.build",
                "version": "proof.dev/operation/context.build/v2",
            },
        });
        let decision = json!({
            "effective_constraints": {
                "max_context_bytes": 4096,
                "max_edits_per_changeset": 2,
                "max_objects": 1,
            },
            "evaluated_at": "2026-08-21T10:00:00Z",
            "operation": input["operation"],
            "requested_action": "context:build",
            "requested_resources": {
                "changeset_ids": [],
                "edition_ids": [],
                "environment_ids": ["production"],
                "locales": ["en-US"],
                "object_ids": ["019c0000-0000-7000-8000-000000000006"],
                "release_ids": [],
                "schema_ids": ["article"],
                "workspace_ids": [WORKSPACE_ID],
            },
            "requesting_principal_id": PRINCIPAL_ID,
            "workspace_id": WORKSPACE_ID,
        });
        let delegation = json!({
            "constraints": {
                "max_context_bytes": 4096,
                "max_edits_per_changeset": 2,
                "max_objects": 1,
            },
        });
        let loaded = loaded_with_intent(intent_ref, intent);
        (loaded, input, decision, delegation)
    }

    fn insert_context_pack(loaded: &mut LoadedBundle) {
        let intent_ref = loaded.bundle.artifacts[0].artifact;
        let intent = loaded.artifacts[&intent_ref].value.clone();
        let context_ref = artifact_ref(ArtifactKind::ContextPackV2, 7);
        loaded.bundle.artifacts.push(ArtifactDescriptor {
            role: EvidenceRole::ContextPack,
            artifact: context_ref,
            availability: Availability::Included { byte_length: 128 },
        });
        loaded.artifacts.insert(
            context_ref,
            LoadedArtifact {
                bytes: vec![0; 128],
                value: json!({
                    "created_at": "2026-08-21T09:00:00Z",
                    "expires_at": "2026-08-21T11:00:00Z",
                    "limits": {
                        "max_bytes": 4096,
                        "max_edits": 2,
                        "max_objects": 1,
                    },
                    "principal_id": PRINCIPAL_ID,
                    "resource_intent": intent,
                    "resource_intent_digest": intent_ref.digest,
                    "resources": [{}],
                    "workspace_id": WORKSPACE_ID,
                }),
            },
        );
    }

    #[test]
    fn registry_is_closed_and_uuid_is_canonical_v7() {
        assert_eq!(OPERATIONS.len(), 14);
        assert!(uuid_v7("019c0000-0000-7000-8000-000000000001"));
        assert!(!uuid_v7("019c0000-0000-6000-8000-000000000001"));
        assert!(
            resolve(
                &json!({"name":"release.create","version":"proof.dev/operation/release.create/v2"})
            )
            .is_some()
        );
        assert!(
            resolve(
                &json!({"name":"release.create","version":"proof.dev/operation/release.create/v3"})
            )
            .is_none()
        );
    }

    #[test]
    fn missing_context_build_projection_requires_the_explicit_fallback() {
        let (loaded, input, decision, delegation) = context_build_projection_fixture();

        assert!(validate_command_and_projection(&loaded, &input, &decision, &delegation).is_none());
        assert!(
            validate_command_and_projection_allowing_missing_context_build(
                &loaded,
                &input,
                &decision,
                &delegation,
            )
            .is_some()
        );

        let mut wrong_intent = input.clone();
        wrong_intent["normalized_input"]["resource_intent_id"] =
            Value::String("019c0000-0000-7000-8000-000000000099".to_owned());
        assert!(
            validate_command_and_projection_allowing_missing_context_build(
                &loaded,
                &wrong_intent,
                &decision,
                &delegation,
            )
            .is_none()
        );
    }

    #[test]
    fn ordinary_context_build_projection_still_requires_a_context_pack() {
        let (mut loaded, input, decision, delegation) = context_build_projection_fixture();
        insert_context_pack(&mut loaded);

        assert!(validate_command_and_projection(&loaded, &input, &decision, &delegation).is_some());
    }

    #[test]
    fn missing_context_build_freshness_matches_the_producer_boundaries() {
        let (loaded, mut input, decision, delegation) = context_build_projection_fixture();
        input["normalized_input"]["created_at"] = decision["evaluated_at"].clone();
        assert!(
            validate_command_and_projection_allowing_missing_context_build(
                &loaded,
                &input,
                &decision,
                &delegation,
            )
            .is_some()
        );

        input["normalized_input"]["created_at"] = Value::String("2026-08-21T09:00:00Z".to_owned());
        input["normalized_input"]["expires_at"] = decision["evaluated_at"].clone();
        assert!(
            validate_command_and_projection_allowing_missing_context_build(
                &loaded,
                &input,
                &decision,
                &delegation,
            )
            .is_none()
        );

        input["normalized_input"]["expires_at"] = Value::String("2026-08-21T11:00:00Z".to_owned());
        input["normalized_input"]["created_at"] = Value::String("2026-08-21T10:00:01Z".to_owned());
        assert!(
            validate_command_and_projection_allowing_missing_context_build(
                &loaded,
                &input,
                &decision,
                &delegation,
            )
            .is_none()
        );
    }
}
